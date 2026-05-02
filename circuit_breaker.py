"""
circuit_breaker.py — Per-service circuit breaker.
States: CLOSED (normal) -> OPEN (failing) -> HALF_OPEN (probing recovery).
Thread-safe. Configured via CB_FAILURE_THRESHOLD and CB_RECOVERY_TIMEOUT_S.
"""

import time
import threading
from enum import Enum
from typing import Callable, Any
from logger import get_logger

_log = get_logger("circuit_breaker")


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when a call is attempted while the circuit is open."""


class CircuitBreaker:
    def __init__(self, service: str, failure_threshold: int, recovery_timeout_s: int):
        self.service = service
        self.failure_threshold = failure_threshold
        self.recovery_timeout_s = recovery_timeout_s
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._opened_at: float = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._current_state()

    def _current_state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.time() - self._opened_at >= self.recovery_timeout_s:
                self._state = CircuitState.HALF_OPEN
                _log.info("circuit_half_open service=%s", self.service)
        return self._state

    def call(self, func: Callable, *args, **kwargs) -> Any:
        with self._lock:
            state = self._current_state()
            if state == CircuitState.OPEN:
                _log.warning("circuit_open_rejected service=%s", self.service)
                raise CircuitOpenError(
                    f"Circuit breaker OPEN for {self.service} — call rejected"
                )

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._on_failure(exc)
            raise

    def _on_success(self):
        with self._lock:
            if self._state in (CircuitState.HALF_OPEN, CircuitState.OPEN):
                _log.info("circuit_closed service=%s", self.service)
            self._state = CircuitState.CLOSED
            self._failures = 0

    def _on_failure(self, exc: Exception):
        with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                if self._state != CircuitState.OPEN:
                    self._state = CircuitState.OPEN
                    self._opened_at = time.time()
                    _log.error(
                        "circuit_opened service=%s failures=%d error=%s",
                        self.service, self._failures, exc,
                    )

    def get_status(self) -> dict:
        with self._lock:
            return {
                "service": self.service,
                "state": self._current_state().value,
                "failures": self._failures,
                "threshold": self.failure_threshold,
            }


# ── Registry ───────────────────────────────────────────────────────────────────
# DGIC has ZERO downstream calls. Circuit breakers track only internal
# reasoning health so /health/live reflects DGIC's own state.

import os

_THRESHOLD = int(os.environ.get("CB_FAILURE_THRESHOLD", 5))
_RECOVERY = int(os.environ.get("CB_RECOVERY_TIMEOUT_S", 30))

_breakers: dict[str, CircuitBreaker] = {
    "dgic_reasoning": CircuitBreaker("dgic_reasoning", _THRESHOLD, _RECOVERY),
}


def get_breaker(service: str) -> CircuitBreaker:
    return _breakers[service]


def all_statuses() -> list[dict]:
    return [b.get_status() for b in _breakers.values()]
