from __future__ import annotations
import abc, hashlib, json
from typing import Any
from shared.schemas.event import Indicators, SOAREvent, Severity

class NormalizationError(Exception):
    pass

class BaseNormalizer(abc.ABC):
    SOURCE_ID: str

    @abc.abstractmethod
    async def normalize(self, raw: dict[str, Any]) -> SOAREvent: ...

    @abc.abstractmethod
    def extract_indicators(self, raw: dict[str, Any]) -> Indicators: ...

    def _fingerprint(self, title: str, indicators: Indicators) -> str:
        key = {
            "source": self.SOURCE_ID,
            "title": title,
            "ips": sorted([n.ip for n in indicators.network if n.ip]),
            "hosts": sorted([h.hostname for h in indicators.hosts if h.hostname]),
            "hashes": sorted(indicators.hashes),
        }
        return hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()
