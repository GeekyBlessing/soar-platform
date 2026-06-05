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

class SecurityHubNormalizer(BaseNormalizer):
    SOURCE_ID = "aws.securityhub"

    async def normalize(self, raw: dict[str, Any]) -> SOAREvent:
        try:
            finding = raw.get("detail", {}).get("findings", [raw])[0]
        except (KeyError, IndexError) as e:
            raise NormalizationError(f"Bad payload: {e}") from e

        title    = finding.get("Title", "Unknown Finding")
        desc     = finding.get("Description", "")
        sev_raw  = finding.get("Severity", {}).get("Label", "MEDIUM").lower()
        severity = _SEV_MAP.get(sev_raw, Severity.MEDIUM)
        indicators = self.extract_indicators(finding)
        fingerprint = self._fingerprint(title, indicators)

        return SOAREvent(
            fingerprint=fingerprint,
            source=self.SOURCE_ID,
            source_event_id=finding.get("Id", ""),
            title=title,
            description=desc,
            severity=severity,
            confidence_score=finding.get("Confidence", 50) / 100,
            risk_score=finding.get("Criticality", 50) / 100,
            event_time=datetime.utcnow(),
            indicators=indicators,
            raw_payload=raw,
        )

    def extract_indicators(self, finding: dict[str, Any]) -> Indicators:
        network, hosts, users = [], [], []
        for resource in finding.get("Resources", []):
            rtype = resource.get("Type", "")
            details = resource.get("Details", {})
            if rtype == "AwsEc2Instance":
                ec2 = details.get("AwsEc2Instance", {})
                hosts.append(HostIndicator(
                    ip=ec2.get("IpV4Addresses", [None])[0],
                    hostname=resource.get("Id"),
                    cloud_instance_id=resource.get("Id"),
                    cloud_region=resource.get("Region"),
                ))
                for ip in ec2.get("IpV4Addresses", []):
                    network.append(NetworkIndicator(ip=ip))
            elif rtype == "AwsIamUser":
                iam = details.get("AwsIamUser", {})
                users.append(UserIndicator(username=iam.get("UserName")))
        return Indicators(network=network, hosts=hosts, users=users)
