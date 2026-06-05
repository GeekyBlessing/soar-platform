import asyncio
import pytest
from datetime import datetime
from uuid import uuid4
from services.correlator.src.engine.correlator import CorrelationEngine
from shared.schemas.event import (
    AlertStatus, Indicators, NetworkIndicator,
    HostIndicator, SOAREvent, Severity,
)

def _make_event(
    severity=Severity.HIGH,
    ips=None,
    hosts=None,
    title="Test alert",
    fingerprint=None,
):
    indicators = Indicators(
        network=[NetworkIndicator(ip=ip) for ip in (ips or [])],
        hosts=[HostIndicator(hostname=h) for h in (hosts or [])],
    )
    fp = fingerprint or SOAREvent.compute_fingerprint(
        "test.source", title,
        {"ips": sorted(ips or []), "hosts": sorted(hosts or [])},
    )
    return SOAREvent(
        fingerprint=fp,
        source="test.source",
        source_event_id=str(uuid4()),
        title=title,
        description="Test",
        severity=severity,
        event_time=datetime.utcnow(),
        indicators=indicators,
        raw_payload={},
    )

class TestDeduplication:
    @pytest.mark.asyncio
    async def test_same_event_is_duplicate(self):
        engine = CorrelationEngine()
        event = _make_event(ips=["1.2.3.4"])
        _, dup1 = await engine.process(event)
        _, dup2 = await engine.process(event)
        assert dup1 is False
        assert dup2 is True

    @pytest.mark.asyncio
    async def test_different_events_not_duplicate(self):
        engine = CorrelationEngine()
        e1 = _make_event(ips=["1.1.1.1"], fingerprint="fp-aaa")
        e2 = _make_event(ips=["2.2.2.2"], fingerprint="fp-bbb")
        _, d1 = await engine.process(e1)
        _, d2 = await engine.process(e2)
        assert d1 is False
        assert d2 is False

class TestCorrelation:
    @pytest.mark.asyncio
    async def test_shared_ip_correlates_events(self):
        engine = CorrelationEngine()
        e1 = _make_event(ips=["10.0.0.1"], fingerprint="fp-c1")
        e2 = _make_event(ips=["10.0.0.1"], fingerprint="fp-c2")
        r1, _ = await engine.process(e1)
        r2, _ = await engine.process(e2)
        assert r1.id in r2.correlated_event_ids

    @pytest.mark.asyncio
    async def test_shared_host_correlates_events(self):
        engine = CorrelationEngine()
        e1 = _make_event(hosts=["prod-db-01"], fingerprint="fp-h1")
        e2 = _make_event(hosts=["prod-db-01"], fingerprint="fp-h2")
        r1, _ = await engine.process(e1)
        r2, _ = await engine.process(e2)
        assert r1.id in r2.correlated_event_ids

    @pytest.mark.asyncio
    async def test_unrelated_events_not_correlated(self):
        engine = CorrelationEngine()
        e1 = _make_event(ips=["1.1.1.1"], fingerprint="fp-u1")
        e2 = _make_event(ips=["2.2.2.2"], fingerprint="fp-u2")
        r1, _ = await engine.process(e1)
        r2, _ = await engine.process(e2)
        assert r1.correlated_event_ids == []
        assert r2.correlated_event_ids == []

    @pytest.mark.asyncio
    async def test_cluster_severity_escalates(self):
        engine = CorrelationEngine()
        e1 = _make_event(ips=["10.0.0.5"], severity=Severity.LOW, fingerprint="fp-s1")
        e2 = _make_event(ips=["10.0.0.5"], severity=Severity.CRITICAL, fingerprint="fp-s2")
        await engine.process(e1)
        await engine.process(e2)
        cluster = list(engine._clusters.values())[0]
        assert cluster.severity == Severity.CRITICAL

class TestScoring:
    @pytest.mark.asyncio
    async def test_risk_score_boosted_in_cluster(self):
        engine = CorrelationEngine()
        ip = "192.168.1.100"
        results = []
        for i in range(5):
            r, _ = await engine.process(
                _make_event(ips=[ip], fingerprint=f"fp-boost{i}")
            )
            results.append(r)
        assert results[-1].risk_score > 0.5

    @pytest.mark.asyncio
    async def test_risk_score_never_exceeds_1(self):
        engine = CorrelationEngine()
        ip = "10.10.10.10"
        result = None
        for i in range(20):
            result, _ = await engine.process(
                _make_event(ips=[ip], fingerprint=f"fp-cap{i}")
            )
        assert result.risk_score <= 1.0

    @pytest.mark.asyncio
    async def test_status_set_to_triaged(self):
        engine = CorrelationEngine()
        result, _ = await engine.process(
            _make_event(ips=["172.16.0.1"], fingerprint="fp-stat")
        )
        assert result.status == AlertStatus.TRIAGED
