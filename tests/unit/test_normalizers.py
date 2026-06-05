import pytest
from services.ingestor.src.normalizers.security_hub import SecurityHubNormalizer
from services.ingestor.src.normalizers.crowdstrike import CrowdStrikeNormalizer
from shared.schemas.event import Severity

@pytest.fixture
def sh():
    return SecurityHubNormalizer()

@pytest.fixture
def cs():
    return CrowdStrikeNormalizer()

@pytest.fixture
def guardduty():
    return {"detail":{"findings":[{
        "Id": "test-001",
        "Title": "EC2 communicating with C2",
        "Description": "Test finding",
        "Severity": {"Label": "HIGH"},
        "ProductName": "GuardDuty",
        "Confidence": 85,
        "Criticality": 75,
        "Resources": [{"Type": "AwsEc2Instance","Id": "i-0test",
        "Region": "us-east-1","Details": {"AwsEc2Instance":
        {"IpV4Addresses": ["172.31.0.10"],"ImageId": "ami-test"}}}]
    }]}}

@pytest.fixture
def crowdstrike():
    return {"event": {
        "DetectionId": "cs-001",
        "DetectName": "Malware Detected",
        "DetectDescription": "Malicious file executed",
        "SeverityName": "high",
        "MaxSeverity": 80,
        "Behavior": "MaliciousFile",
        "UserName": "administrator",
        "DeviceDetails": {
            "Hostname": "WORKSTATION-01",
            "LocalIP": "10.0.0.50",
            "ExternalIP": "1.2.3.4",
            "OSVersion": "Windows 10",
        }
    }}

class TestSecurityHubNormalizer:
    @pytest.mark.asyncio
    async def test_severity_mapped(self, sh, guardduty):
        event = await sh.normalize(guardduty)
        assert event.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_source_correct(self, sh, guardduty):
        event = await sh.normalize(guardduty)
        assert event.source == "aws.securityhub"

    @pytest.mark.asyncio
    async def test_ip_extracted(self, sh, guardduty):
        event = await sh.normalize(guardduty)
        ips = [n.ip for n in event.indicators.network]
        assert "172.31.0.10" in ips

    @pytest.mark.asyncio
    async def test_fingerprint_deterministic(self, sh, guardduty):
        e1 = await sh.normalize(guardduty)
        e2 = await sh.normalize(guardduty)
        assert e1.fingerprint == e2.fingerprint

    @pytest.mark.asyncio
    async def test_event_immutable(self, sh, guardduty):
        event = await sh.normalize(guardduty)
        with pytest.raises(Exception):
            event.title = "mutated"

    @pytest.mark.asyncio
    async def test_confidence_in_range(self, sh, guardduty):
        event = await sh.normalize(guardduty)
        assert 0.0 <= event.confidence_score <= 1.0

class TestCrowdStrikeNormalizer:
    @pytest.mark.asyncio
    async def test_severity_mapped(self, cs, crowdstrike):
        event = await cs.normalize(crowdstrike)
        assert event.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_source_correct(self, cs, crowdstrike):
        event = await cs.normalize(crowdstrike)
        assert event.source == "crowdstrike.falcon"

    @pytest.mark.asyncio
    async def test_mitre_tactic_mapped(self, cs, crowdstrike):
        event = await cs.normalize(crowdstrike)
        assert event.mitre_tactic == "TA0002"

    @pytest.mark.asyncio
    async def test_host_extracted(self, cs, crowdstrike):
        event = await cs.normalize(crowdstrike)
        hostnames = [h.hostname for h in event.indicators.hosts]
        assert "WORKSTATION-01" in hostnames

    @pytest.mark.asyncio
    async def test_privileged_user_detected(self, cs, crowdstrike):
        event = await cs.normalize(crowdstrike)
        privileged = [u for u in event.indicators.users if u.is_privileged]
        assert len(privileged) > 0

    @pytest.mark.asyncio
    async def test_external_ip_extracted(self, cs, crowdstrike):
        event = await cs.normalize(crowdstrike)
        ips = [n.ip for n in event.indicators.network]
        assert "1.2.3.4" in ips
