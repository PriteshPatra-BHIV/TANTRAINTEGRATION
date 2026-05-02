"""
metrics.py — Prometheus metrics for DGIC.
Exposes /metrics endpoint via prometheus_client.
DGIC has ZERO downstream calls — no downstream metrics are defined.
"""

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response

# ── Request metrics ────────────────────────────────────────────────────────────
REQUEST_COUNT = Counter(
    "dgic_requests_total",
    "Total POST /dgic/evaluate requests",
    ["decision", "epistemic_state"],
)

REQUEST_LATENCY = Histogram(
    "dgic_request_latency_ms",
    "Latency of /dgic/evaluate in milliseconds",
    buckets=[5, 10, 25, 50, 100, 250, 500, 1000],
)

REQUEST_ERRORS = Counter(
    "dgic_request_errors_total",
    "Total failed /dgic/evaluate requests",
    ["error_type"],
)

# ── Circuit breaker state ──────────────────────────────────────────────────────
CIRCUIT_STATE = Gauge(
    "dgic_circuit_breaker_open",
    "1 if internal reasoning circuit breaker is open, 0 if closed",
    ["service"],
)


def metrics_endpoint() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
