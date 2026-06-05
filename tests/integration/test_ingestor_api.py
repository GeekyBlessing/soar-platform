"""
Integration tests — spins up real FastAPI app and hits the endpoints.
No mocking. Tests the full request/response cycle.
"""
import hashlib
import hmac
import json
import pytest
from fastapi.testclient import TestClient
from services.ingestor.src.main import app

client = TestClient(app)

def _sign(body: str) -> str:
    secret = b"dev-hmac-secret"
    sig = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    return f"sha256={sig}"

def _headers(source: str, body: str) -> dict:
    return {
        "Content-Type": "application/json",
        "X-SOAR-Source": source,
        "X-SOAR-Signature": _sign(body),
    }

GUARDDUTY = json.dumps({"detail":{"findings":[{
    "Id": "integ-test-001",
    "Title": "Integration test finding",
    "Description": "Test",
    "Severity": {"Label": "HIGH"},
    "ProductName": "GuardDuty",
    "Confidence": 85,
    "Criticality": 75,
    "Resources": [{"Type": "AwsEc2Instance", "Id": "i-integ",
    "Region": "us-east-1", "Details": {"AwsEc2Instance":
    {"IpV4Addresses": ["10.0.0.1"], "ImageId": "ami-test"}}}]
}]}})

CROWDSTRIKE = json.dumps({"event": {
    "DetectionId": "integ-cs-001",
    "DetectName": "Integration Test Detection",
    "DetectDescription": "Test",
    "SeverityName": "critical",
    "MaxSeverity": 95,
    "Behavior": "MaliciousFile",
    "UserName": "admin",
    "DeviceDetails": {
        "Hostname": "INTEG-HOST-01",
        "LocalIP": "192.168.1.50",
        "ExternalIP": "5.6.7.8",
        "OSVersion": "Windows 11",
    }
}})

SPLUNK = json.dumps({"result": {
    "search_name": "Integration Test Alert",
    "message": "Test Splunk alert",
    "severity": "high",
    "event_id": "splunk-integ-001",
    "src_ip": "172.16.0.1",
    "dest_ip": "8.8.8.8",
    "host": "splunk-host-01",
    "user": "jsmith",
}})


class TestHealth:
    def test_health_returns_200(self):
        resp = client.get("/v1/ingest/health")
        assert resp.status_code == 200

    def test_health_lists_all_sources(self):
        resp = client.get("/v1/ingest/health")
        data = resp.json()
        assert "aws.securityhub" in data["sources"]
        assert "crowdstrike.falcon" in data["sources"]
        assert "splunk.es" in data["sources"]
        assert "wiz.cloud" in data["sources"]

    def test_root_returns_service_info(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["service"] == "SOAR Platform"

    def test_sources_endpoint(self):
        resp = client.get("/v1/ingest/sources")
        assert resp.status_code == 200
        assert resp.json()["count"] == 4


class TestSecurityHubIngestion:
    def test_accepts_valid_guardduty_alert(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=GUARDDUTY,
            headers=_headers("aws.securityhub", GUARDDUTY),
        )
        assert resp.status_code == 202

    def test_response_has_event_id(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=GUARDDUTY,
            headers=_headers("aws.securityhub", GUARDDUTY),
        )
        data = resp.json()
        assert "event_id" in data
        assert len(data["event_id"]) == 36

    def test_response_has_correct_source(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=GUARDDUTY,
            headers=_headers("aws.securityhub", GUARDDUTY),
        )
        assert resp.json()["source"] == "aws.securityhub"

    def test_response_has_fingerprint(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=GUARDDUTY,
            headers=_headers("aws.securityhub", GUARDDUTY),
        )
        assert "fingerprint" in resp.json()


class TestCrowdStrikeIngestion:
    def test_accepts_crowdstrike_alert(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=CROWDSTRIKE,
            headers=_headers("crowdstrike.falcon", CROWDSTRIKE),
        )
        assert resp.status_code == 202

    def test_crowdstrike_severity_critical(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=CROWDSTRIKE,
            headers=_headers("crowdstrike.falcon", CROWDSTRIKE),
        )
        assert resp.json()["severity"] == "critical"

    def test_crowdstrike_has_mitre_tactic(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=CROWDSTRIKE,
            headers=_headers("crowdstrike.falcon", CROWDSTRIKE),
        )
        assert resp.json()["mitre_tactic"] == "TA0002"


class TestSplunkIngestion:
    def test_accepts_splunk_alert(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=SPLUNK,
            headers=_headers("splunk.es", SPLUNK),
        )
        assert resp.status_code == 202

    def test_splunk_source_correct(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=SPLUNK,
            headers=_headers("splunk.es", SPLUNK),
        )
        assert resp.json()["source"] == "splunk.es"


class TestSecurity:
    def test_bad_signature_rejected(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=GUARDDUTY,
            headers={
                "Content-Type": "application/json",
                "X-SOAR-Source": "aws.securityhub",
                "X-SOAR-Signature": "sha256=badsignature",
            },
        )
        assert resp.status_code == 401

    def test_missing_signature_rejected(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=GUARDDUTY,
            headers={
                "Content-Type": "application/json",
                "X-SOAR-Source": "aws.securityhub",
            },
        )
        assert resp.status_code == 401

    def test_unknown_source_rejected(self):
        resp = client.post(
            "/v1/ingest/webhook",
            content=GUARDDUTY,
            headers=_headers("unknown.source", GUARDDUTY),
        )
        assert resp.status_code == 400

    def test_same_alert_twice_both_accepted(self):
        resp1 = client.post(
            "/v1/ingest/webhook",
            content=GUARDDUTY,
            headers=_headers("aws.securityhub", GUARDDUTY),
        )
        resp2 = client.post(
            "/v1/ingest/webhook",
            content=GUARDDUTY,
            headers=_headers("aws.securityhub", GUARDDUTY),
        )
        assert resp1.status_code == 202
        assert resp2.status_code == 202
