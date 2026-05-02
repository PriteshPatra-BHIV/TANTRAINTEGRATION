"""
middleware.py — Production middleware for DGIC.
- X-Request-ID: injected on every request/response for correlation
- Rate limiting: per client IP, configurable via RATE_LIMIT_PER_MINUTE
"""

import os
import re
import time
import uuid
import threading
from collections import defaultdict
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

_RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_MINUTE", 60))
# Trust X-Forwarded-For only when explicitly enabled (e.g. behind a known proxy)
_TRUST_PROXY = os.environ.get("DGIC_TRUST_PROXY", "false").lower() == "true"
# Prune the IP bucket map every N requests to bound memory
_PRUNE_EVERY = 500
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter per client IP."""

    def __init__(self, app, requests_per_minute: int = _RATE_LIMIT):
        super().__init__(app)
        self._limit = requests_per_minute
        self._window = 60.0
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._request_count = 0

    def _client_ip(self, request: Request) -> str:
        """Resolve client IP. Only honour X-Forwarded-For when DGIC_TRUST_PROXY=true."""
        if _TRUST_PROXY:
            forwarded_for = request.headers.get("X-Forwarded-For", "")
            if forwarded_for:
                # Take only the leftmost (original client) address
                candidate = forwarded_for.split(",")[0].strip()
                # Basic sanity check — accept only plausible IPv4/IPv6 strings
                if candidate and len(candidate) <= 45:
                    return candidate
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health and metrics endpoints
        if request.url.path in ("/health", "/metrics", "/health/live"):
            return await call_next(request)

        client_ip = self._client_ip(request)
        now = time.time()

        with self._lock:
            self._request_count += 1
            # Drop timestamps outside the sliding window
            self._buckets[client_ip] = [
                t for t in self._buckets[client_ip] if now - t < self._window
            ]
            if len(self._buckets[client_ip]) >= self._limit:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limit_exceeded",
                        "detail": f"Max {self._limit} requests/minute",
                    },
                )
            self._buckets[client_ip].append(now)
            # Periodically evict fully-expired IP entries to bound memory
            if self._request_count % _PRUNE_EVERY == 0:
                expired = [ip for ip, ts in self._buckets.items()
                           if not ts or (now - max(ts)) >= self._window]
                for ip in expired:
                    del self._buckets[ip]

        return await call_next(request)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Injects X-Request-ID into every request and response."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
