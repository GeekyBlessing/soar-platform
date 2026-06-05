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
    "info":     Severity.INFO,
}

class SplunkNormalizer(BaseNormalizer):
    SOURCE_ID = "splunk.es"

    async def normalize(self, raw: dict[str, Any]) -> SOAREvent:
        try:
            result = raw.get("result", raw)
        except Exception as e:
            raise NormalizationError(f"Bad Splunk payload: {e}") from e

        title    = result.get("search_name", result.get("name", "Splunk Alert"))
        desc     = result.get("message", result.get("description", ""))
        sev_raw  = result.get("severity", result.get("urgency", "medium")).lower()
        severity = _SEV_MAP.get(sev_raw, Severity.MEDIUM)
        indicators = self.extract_indicators(result)
        fingerprint = self._fingerprint(title, indicators)

        return SOAREvent(
            fingerprint=fingerprint,
            source=self.SOURCE_ID,
            source_event_id=result.get("event_id", result.get("sid", "")),
            title=title,
            description=desc,
            severity=severity,
            confidence_score=float(result.get("confidence", 0.5)),
            risk_score=float(result.get("risk_score", 0.5)),
            event_time=datetime.utcnow(),
            indicators=indicators,
            raw_payload=raw,
        )

    def extract_indicators(self, result: dict[str, Any]) -> Indicators:
        network, hosts, users = [], [], []
        if src_ip := result.get("src_ip", result.get("src")):
            network.append(NetworkIndicator(ip=src_ip))
        if dst_ip := result.get("dest_ip", result.get("dest")):
            network.append(NetworkIndicator(ip=dst_ip))
        if host := result.get("host", result.get("hostname")):
            hosts.append(HostIndicator(hostname=host))
        if user := result.get("user", result.get("src_user")):
            users.append(UserIndicator(
                username=user,
                is_privileged="admin" in user.lower(),
            ))
        return Indicators(network=network, hosts=hosts, users=users)
