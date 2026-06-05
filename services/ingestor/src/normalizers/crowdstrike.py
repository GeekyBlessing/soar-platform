from __future__ import annotations
from datetime import datetime
from typing import Any
from shared.schemas.event import (
    HostIndicator, Indicators, NetworkIndicator,
    Severity, SOAREvent, UserIndicator,
)
from .base import BaseNormalizer, NormalizationError

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "informational": Severity.INFO,
}

_MITRE_MAP = {
    "MaliciousFile":       ("TA0002", "T1204"),
    "NetworkTraffic":      ("TA0011", "T1071"),
    "ProcessCreation":     ("TA0002", "T1059"),
    "PrivilegeEscalation": ("TA0004", "T1068"),
    "LateralMovement":     ("TA0008", "T1021"),
    "CredentialAccess":    ("TA0006", "T1003"),
    "DefenseEvasion":      ("TA0005", "T1055"),
}

class CrowdStrikeNormalizer(BaseNormalizer):
    SOURCE_ID = "crowdstrike.falcon"

    async def normalize(self, raw: dict[str, Any]) -> SOAREvent:
        try:
            event = raw.get("event", raw)
        except Exception as e:
            raise NormalizationError(f"Bad CrowdStrike payload: {e}") from e

        title    = event.get("DetectName", "CrowdStrike Detection")
        desc     = event.get("DetectDescription", "")
        sev_raw  = event.get("SeverityName", "medium").lower()
        severity = _SEV_MAP.get(sev_raw, Severity.MEDIUM)
        behavior = event.get("Behavior", "")
        tactic, technique = _MITRE_MAP.get(behavior, (None, None))
        indicators = self.extract_indicators(event)
        fingerprint = self._fingerprint(title, indicators)

        return SOAREvent(
            fingerprint=fingerprint,
            source=self.SOURCE_ID,
            source_event_id=event.get("DetectionId", ""),
            title=title,
            description=desc,
            severity=severity,
            mitre_tactic=tactic,
            mitre_technique=technique,
            confidence_score=min(event.get("MaxSeverity", 50) / 100, 1.0),
            risk_score=min(event.get("MaxSeverity", 50) / 100, 1.0),
            event_time=datetime.utcnow(),
            indicators=indicators,
            raw_payload=raw,
        )

    def extract_indicators(self, event: dict[str, Any]) -> Indicators:
        network, hosts, users = [], [], []
        device = event.get("DeviceDetails", {})
        if device:
            hosts.append(HostIndicator(
                hostname=device.get("Hostname"),
                ip=device.get("LocalIP"),
                os=device.get("OSVersion"),
            ))
            if ip := device.get("LocalIP"):
                network.append(NetworkIndicator(ip=ip))
            if ext := device.get("ExternalIP"):
                network.append(NetworkIndicator(ip=ext))
        if username := event.get("UserName"):
            users.append(UserIndicator(
                username=username,
                is_privileged="admin" in username.lower() or "root" in username.lower(),
            ))
        return Indicators(network=network, hosts=hosts, users=users)
