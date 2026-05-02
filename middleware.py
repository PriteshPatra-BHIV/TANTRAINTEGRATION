"""
middleware.py — Production middleware for DGIC.
- X-Request-ID: injected on every request/response for correlation
- Rate limiting: per client IP, configurable via RATE_LIMIT_PER_MINUTE
"""

import os
import time
import uuid
import threading
from collections import defaultdict
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

_RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_MINUTE", 60))


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter per client IP."""

    def __init__(self, app, requests_per_minute: int = _RATE_LIMIT):
        super().__init__(app)
        self._limit = requests_per_minute
        self._window = 60.0
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health and metrics endpoints
        if request.url.path in ("/health", "/metrics"):
            return await call_next(request)

        # Honour X-Forwarded-For so rate limiting works correctly behind a
        # reverse proxy or load balancer. Take only the first (client) IP.
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        with self._lock:
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
            # Evict IPs with no recent requests to prevent unbounded growth
            if len(self._buckets[client_ip]) == 1:
                # Just added first entry — prune any fully-expired keys
                expired = [ip for ip, ts in self._buckets.items() if not ts]
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
