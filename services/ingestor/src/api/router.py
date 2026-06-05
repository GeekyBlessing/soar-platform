from __future__ import annotations
import hashlib, hmac, logging
from typing import Annotated, Any
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from ..normalizers.security_hub import SecurityHubNormalizer
from ..normalizers.base import NormalizationError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/ingest", tags=["ingest"])

_REGISTRY = {"aws.securityhub": SecurityHubNormalizer()}

async def _verify(
    request: Request,
    x_soar_signature: Annotated[str | None, Header()] = None,
    x_soar_source: Annotated[str | None, Header()] = None,
) -> str:
    if not x_soar_source or x_soar_source not in _REGISTRY:
        raise HTTPException(400, f"Unknown source: {x_soar_source}")
    if not x_soar_signature:
        raise HTTPException(401, "X-SOAR-Signature required")
    body = await request.body()
    secret = b"dev-hmac-secret"
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_soar_signature):
        raise HTTPException(401, "Bad signature")
    return x_soar_source

@router.post("/webhook")
async def ingest_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    source: str = Depends(_verify),
) -> JSONResponse:
    raw: dict[str, Any] = await request.json()
    normalizer = _REGISTRY[source]
    try:
        event = await normalizer.normalize(raw)
    except NormalizationError as e:
        raise HTTPException(422, str(e)) from e
    logger.info("event_received id=%s severity=%s", event.id, event.severity)
    return JSONResponse(
        content={"event_id": str(event.id), "severity": event.severity, "status": "accepted"},
        status_code=202,
    )

@router.get("/health")
async def health() -> dict:
    return {"status": "healthy", "service": "ingestor"}
