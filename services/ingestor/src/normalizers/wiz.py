from __future__ import annotations
from datetime import datetime
from typing import Any
from shared.schemas.event import (
    HostIndicator, Indicators, NetworkIndicator,
    Severity, SOAREvent,
)
from .base import BaseNormalizer, NormalizationError

_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "INFO":     Severity.INFO,
}

_MITRE_MAP = {
    "PUBLIC_EXPOSURE":       ("TA0001", "T1190"),
    "LATERAL_MOVEMENT":      ("TA0008", "T1021"),
    "DATA_EXFILTRATION":     ("TA0010", "T1537"),
    "PRIVILEGE_ESCALATION":  ("TA0004", "T1068"),
    "DEFENSE_EVASION":       ("TA0005", "T1562"),
    "INITIAL_ACCESS":        ("TA0001", "T1078"),
}

class WizNormalizer(BaseNormalizer):
    SOURCE_ID = "wiz.cloud"

    async def normalize(self, raw: dict[str, Any]) -> SOAREvent:
        try:
            issue = raw.get("issue", raw)
        except Exception as e:
            raise NormalizationError(f"Bad Wiz payload: {e}") from e

        title    = issue.get("name", issue.get("title", "Wiz Cloud Issue"))
        desc     = issue.get("description", "")
        sev_raw  = issue.get("severity", "MEDIUM").upper()
        severity = _SEV_MAP.get(sev_raw, Severity.MEDIUM)

        category = issue.get("type", {}).get("name", "")
        tactic, technique = _MITRE_MAP.get(category, (None, None))

        indicators = self.extract_indicators(issue)
        fingerprint = self._fingerprint(title, indicators)

        return SOAREvent(
            fingerprint=fingerprint,
            source=self.SOURCE_ID,
            source_event_id=issue.get("id", ""),
            title=title,
            description=desc,
            severity=severity,
            mitre_tactic=tactic,
            mitre_technique=technique,
            confidence_score=0.9,
            risk_score=_SEV_MAP.get(sev_raw, Severity.MEDIUM) == Severity.CRITICAL and 0.95 or 0.6,
            event_time=datetime.utcnow(),
            indicators=indicators,
            raw_payload=raw,
        )

    def extract_indicators(self, issue: dict[str, Any]) -> Indicators:
        network, hosts = [], []
        for resource in issue.get("entitySnapshot", {}).get("resourceGroups", []):
            if name := resource.get("name"):
                hosts.append(HostIndicator(
                    hostname=name,
                    cloud_region=resource.get("region"),
                    cloud_instance_id=resource.get("id"),
                ))
        for ip in issue.get("entitySnapshot", {}).get("ipAddresses", []):
            network.append(NetworkIndicator(ip=ip))
        return Indicators(network=network, hosts=hosts)
