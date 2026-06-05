from __future__ import annotations
import time
import logging
from collections import defaultdict
from typing import Any
from fastapi import Request, HTTPException

logger = logging.getLogger(__name__)

# Token bucket rate limiter — per source
# Each source gets 100 requests per 60 seconds
_buckets: dict[str, dict[str, Any]] = defaultdict(lambda: {
    "tokens": 100,
    "last_refill": time.time(),
})

MAX_TOKENS = 100
REFILL_RATE = 100   # tokens per minute
MAX_BODY_SIZE = 1 * 1024 * 1024  # 1MB max payload


def check_rate_limit(source: str) -> None:
    bucket = _buckets[source]
    now = time.time()
    elapsed = now - bucket["last_refill"]

    # Refill tokens based on elapsed time
    refill = (elapsed / 60.0) * REFILL_RATE
    bucket["tokens"] = min(MAX_TOKENS, bucket["tokens"] + refill)
    bucket["last_refill"] = now

    if bucket["tokens"] < 1:
        logger.warning("rate_limit_exceeded source=%s", source)
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for source {source}. Max {MAX_TOKENS} requests/minute.",
            headers={"Retry-After": "60"},
        )

    bucket["tokens"] -= 1


async def check_body_size(request: Request) -> None:
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Payload too large. Max size is {MAX_BODY_SIZE // 1024}KB.",
        )
