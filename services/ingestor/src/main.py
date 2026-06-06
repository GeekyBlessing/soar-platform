import logging
import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from .api.router import router

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","service":"ingestor","msg":"%(message)s"}'
)
log = logging.getLogger(__name__)

EVENTS_TOTAL = Counter(
    "soar_events_total",
    "Total events received",
    ["source", "severity", "status"]
)
REQUEST_LATENCY = Histogram(
    "soar_request_duration_seconds",
    "Request latency",
    ["method", "endpoint"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
)
ACTIVE_REQUESTS = Counter(
    "soar_requests_total",
    "Total HTTP requests",
    ["method", "status"]
)

app = FastAPI(
    title="SOAR Platform",
    description="Cloud-native Security Orchestration, Automation and Response",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start
    REQUEST_LATENCY.labels(
        method=request.method,
        endpoint=request.url.path,
    ).observe(duration)
    ACTIVE_REQUESTS.labels(
        method=request.method,
        status=response.status_code,
    ).inc()
    log.info("%s %s %s %.3fs", request.method, request.url.path, response.status_code, duration)
    return response


@app.get("/metrics", include_in_schema=False)
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": "SOAR Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "metrics": "/metrics",
        "health": "/v1/ingest/health",
        "github": "https://github.com/GeekyBlessing/soar-platform",
    }


app.include_router(router)
