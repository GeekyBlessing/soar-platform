from __future__ import annotations
import hashlib
import hmac
import logging
from typing import Annotated, Any
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from ..normalizers.security_hub import SecurityHubNormalizer
from ..normalizers.crowdstrike import CrowdStrikeNormalizer
from ..normalizers.splunk import SplunkNormalizer
from ..normalizers.wiz import WizNormalizer
from ..normalizers.base import NormalizationError
from .middleware import check_rate_limit, check_body_size

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/ingest", tags=["ingest"])

_REGISTRY = {
    "aws.securityhub":    SecurityHubNormalizer(),
    "crowdstrike.falcon": CrowdStrikeNormalizer(),
    "splunk.es":          SplunkNormalizer(),
    "wiz.cloud":          WizNormalizer(),
}

async def _verify(
    request: Request,
    x_soar_signature: Annotated[str | None, Header()] = None,
    x_soar_source: Annotated[str | None, Header()] = None,
) -> str:
    if not x_soar_source or x_soar_source not in _REGISTRY:
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"Unknown source: {x_soar_source}",
                "registered_sources": list(_REGISTRY.keys()),
            }
        )
    if not x_soar_signature:
        raise HTTPException(401, "X-SOAR-Signature header required")
    body = await request.body()
    if not body:
        raise HTTPException(400, "Empty request body")
    secret = b"dev-hmac-secret"
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_soar_signature):
        raise HTTPException(401, "Signature verification failed")
    check_rate_limit(x_soar_source)
    return x_soar_source

@router.post("/webhook")
async def ingest_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    source: str = Depends(_verify),
) -> JSONResponse:
    await check_body_size(request)
    raw: dict[str, Any] = await request.json()
    normalizer = _REGISTRY[source]
    try:
        event = await normalizer.normalize(raw)
    except NormalizationError as e:
        raise HTTPException(422, str(e)) from e
    logger.info(
        "event_received id=%s source=%s severity=%s fingerprint=%s",
        event.id, event.source, event.severity, event.fingerprint,
    )
    return JSONResponse(
        content={
            "event_id":    str(event.id),
            "source":      event.source,
            "severity":    event.severity,
            "fingerprint": event.fingerprint,
            "mitre_tactic": event.mitre_tactic,
            "risk_score":  event.risk_score,
            "status":      "accepted",
        },
        status_code=202,
    )

@router.post("/webhook/batch")
async def ingest_batch(
    request: Request,
    background_tasks: BackgroundTasks,
    source: str = Depends(_verify),
) -> JSONResponse:
    raw_events: list[dict[str, Any]] = await request.json()
    if not isinstance(raw_events, list):
        raise HTTPException(400, "Batch endpoint expects a JSON array")
    if len(raw_events) > 500:
        raise HTTPException(413, "Batch size exceeds 500 events")
    normalizer = _REGISTRY[source]
    accepted, failed = 0, 0
    for raw in raw_events:
        try:
            await normalizer.normalize(raw)
            accepted += 1
        except NormalizationError:
            failed += 1
    return JSONResponse(
        content={"accepted": accepted, "failed": failed, "status": "processed"},
        status_code=202,
    )

@router.get("/health")
async def health() -> dict:
    return {
        "status":  "healthy",
        "service": "ingestor",
        "version": "1.0.0",
        "sources": list(_REGISTRY.keys()),
    }

@router.get("/sources")
async def list_sources() -> dict:
    return {
        "registered_sources": list(_REGISTRY.keys()),
        "count": len(_REGISTRY),
    }
