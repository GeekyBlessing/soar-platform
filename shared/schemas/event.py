from __future__ import annotations
import hashlib, json
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

class AlertStatus(StrEnum):
    NEW            = "new"
    ENRICHING      = "enriching"
    TRIAGED        = "triaged"
    IN_PLAYBOOK    = "in_playbook"
    RESPONDED      = "responded"
    CLOSED         = "closed"
    FALSE_POSITIVE = "false_positive"

class NetworkIndicator(BaseModel):
    ip: str | None = None
    domain: str | None = None
    url: str | None = None
    port: int | None = None

class HostIndicator(BaseModel):
    hostname: str | None = None
    ip: str | None = None
    os: str | None = None
    cloud_instance_id: str | None = None
    cloud_region: str | None = None

class UserIndicator(BaseModel):
    username: str | None = None
    email: str | None = None
    is_privileged: bool = False

class FileIndicator(BaseModel):
    name: str | None = None
    sha256: str | None = None

class Indicators(BaseModel):
    network: list[NetworkIndicator] = Field(default_factory=list)
    users: list[UserIndicator] = Field(default_factory=list)
    hosts: list[HostIndicator] = Field(default_factory=list)
    files: list[FileIndicator] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)

class EnrichmentResult(BaseModel):
    provider: str
    enriched_at: datetime
    data: dict[str, Any]
    ttl_seconds: int = 3600

class SOAREvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    version: int = 1
    fingerprint: str
    source: str
    source_event_id: str
    source_count: int = 1
    title: str
    description: str
    severity: Severity
    status: AlertStatus = AlertStatus.NEW
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.5, ge=0.0, le=1.0)
    event_time: datetime = Field(default_factory=datetime.utcnow)
    received_at: datetime = Field(default_factory=datetime.utcnow)
    indicators: Indicators = Field(default_factory=Indicators)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    enrichments: list[EnrichmentResult] = Field(default_factory=list)
    correlated_event_ids: list[UUID] = Field(default_factory=list)
    case_id: UUID | None = None
    tags: list[str] = Field(default_factory=list)

    @classmethod
    def compute_fingerprint(cls, source: str, title: str, indicators: dict) -> str:
        key = json.dumps({"source": source, "title": title, "indicators": indicators}, sort_keys=True)
        return hashlib.sha256(key.encode()).hexdigest()

    class Config:
        frozen = True
