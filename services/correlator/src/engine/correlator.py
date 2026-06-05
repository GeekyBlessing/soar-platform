from __future__ import annotations
import asyncio, logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID, uuid4
from shared.schemas.event import AlertStatus, SOAREvent, Severity

logger = logging.getLogger(__name__)
CORRELATION_WINDOW = timedelta(minutes=30)

_SEV_RANK = {
    Severity.INFO:     0,
    Severity.LOW:      1,
    Severity.MEDIUM:   2,
    Severity.HIGH:     3,
    Severity.CRITICAL: 4,
}

@dataclass
class CorrelationCluster:
    id: UUID
    events: list[SOAREvent] = field(default_factory=list)
    ioc_index: dict[str, list[UUID]] = field(default_factory=lambda: defaultdict(list))
    severity: Severity = Severity.INFO
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def add(self, event: SOAREvent) -> None:
        self.events.append(event)
        self.updated_at = datetime.utcnow()
        self.severity = max(
            (e.severity for e in self.events),
            key=lambda s: _SEV_RANK[s]
        )
        for ip in [n.ip for n in event.indicators.network if n.ip]:
            self.ioc_index[f"ip:{ip}"].append(event.id)
        for h in [h.hostname for h in event.indicators.hosts if h.hostname]:
            self.ioc_index[f"host:{h}"].append(event.id)

    @property
    def is_stale(self) -> bool:
        return (datetime.utcnow() - self.updated_at) > CORRELATION_WINDOW

class CorrelationEngine:
    def __init__(self) -> None:
        self._fingerprint_cache: dict[str, UUID] = {}
        self._ioc_index: dict[str, list[UUID]] = defaultdict(list)
        self._clusters: dict[UUID, CorrelationCluster] = {}
        self._lock = asyncio.Lock()

    async def process(self, event: SOAREvent) -> tuple[SOAREvent, bool]:
        async with self._lock:
            if existing_id := self._fingerprint_cache.get(event.fingerprint):
                logger.info("dedup fingerprint=%s", event.fingerprint)
                return event, True
            self._fingerprint_cache[event.fingerprint] = event.id
            cluster = self._find_cluster(event)
            if cluster:
                cluster.add(event)
            else:
                cluster = CorrelationCluster(id=uuid4())
                cluster.add(event)
                self._clusters[cluster.id] = cluster
                self._update_ioc_index(event, cluster.id)
            adjusted = self._adjust_scores(event, cluster)
            return adjusted, False

    def _find_cluster(self, event: SOAREvent) -> CorrelationCluster | None:
        candidates: set[UUID] = set()
        for ip in [n.ip for n in event.indicators.network if n.ip]:
            for cid in self._ioc_index.get(f"ip:{ip}", []):
                candidates.add(cid)
        for h in [h.hostname for h in event.indicators.hosts if h.hostname]:
            for cid in self._ioc_index.get(f"host:{h}", []):
                candidates.add(cid)
        for cid in candidates:
            c = self._clusters.get(cid)
            if c and not c.is_stale:
                return c
        return None

    def _update_ioc_index(self, event: SOAREvent, cluster_id: UUID) -> None:
        for ip in [n.ip for n in event.indicators.network if n.ip]:
            self._ioc_index[f"ip:{ip}"].append(cluster_id)
        for h in [h.hostname for h in event.indicators.hosts if h.hostname]:
            self._ioc_index[f"host:{h}"].append(cluster_id)

    def _adjust_scores(self, event: SOAREvent, cluster: CorrelationCluster) -> SOAREvent:
        boost = min(0.1 * (len(cluster.events) - 1), 0.3)
        return event.model_copy(update={
            "risk_score": min(event.risk_score + boost, 1.0),
            "correlated_event_ids": [e.id for e in cluster.events if e.id != event.id],
            "status": AlertStatus.TRIAGED,
        })
