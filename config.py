"""
config.py — Centralized configuration loaded from environment variables.
All hardcoded values removed from source code.
"""

import os

# Session settings
SESSION_EXPIRY_MS = int(os.environ.get("DGIC_SESSION_EXPIRY_MS", 300000))       # 5 min
SESSION_MAX_INVOCATIONS = int(os.environ.get("DGIC_MAX_INVOCATIONS", 100))
SARATHI_APPROVAL_TIMEOUT_MS = int(os.environ.get("DGIC_SARATHI_TIMEOUT_MS", 30000))

# Secret key for HMAC token signing — MUST be set in production via environment
TOKEN_SECRET_KEY = os.environ.get("DGIC_TOKEN_SECRET_KEY", "")

# Signal limits
MAX_SIGNALS_PER_REQUEST = int(os.environ.get("DGIC_MAX_SIGNALS", 100))

# Confidence thresholds
CONFIDENCE_THRESHOLD_ALLOW = float(os.environ.get("DGIC_CONF_ALLOW", 0.7))
CONFIDENCE_THRESHOLD_ESCALATE = float(os.environ.get("DGIC_CONF_ESCALATE", 0.5))
CONFIDENCE_THRESHOLD_REDIRECT = float(os.environ.get("DGIC_CONF_REDIRECT", 0.3))

# Logging
LOG_LEVEL = os.environ.get("DGIC_LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"

# ── External service URLs — NOT USED BY DGIC ──────────────────────────────────
# DGIC is a pure reasoning authority with ZERO downstream calls.
# These variables are retained for reference only (other services in RAJYA may
# read this config). dgic_service.py and dgic_adapter.py import NONE of them.
# Sarathi (Layer 1 Governance) — Aakanksha Parab
SARATHI_URL = os.environ.get("SARATHI_URL", "http://localhost:8001")
SARATHI_EVALUATE_PATH = "/sarathi/evaluate"
SARATHI_TIMEOUT_S = int(os.environ.get("SARATHI_TIMEOUT_S", 10))

# Core (Execution Engine) — Raj Prajapati
CORE_URL = os.environ.get("CORE_URL", "http://localhost:8002")
CORE_MAP_DECISION_PATH = "/core/map-decision"
CORE_TIMEOUT_S = int(os.environ.get("CORE_TIMEOUT_S", 10))

# Bucket (Layer 5 Truth) — Siddhesh Narkar
BUCKET_URL = os.environ.get("BUCKET_URL", "http://localhost:8003")
BUCKET_WRITE_PATH = "/bucket/write"
BUCKET_TIMEOUT_S = int(os.environ.get("BUCKET_TIMEOUT_S", 10))
BUCKET_MAX_RETRIES = int(os.environ.get("BUCKET_MAX_RETRIES", 3))
BUCKET_RETRY_DELAY_S = float(os.environ.get("BUCKET_RETRY_DELAY_S", 1.0))

# InsightBridge (Telemetry) — Vijay Dhawan
INSIGHTBRIDGE_URL = os.environ.get("INSIGHTBRIDGE_URL", "http://localhost:8004")
INSIGHTBRIDGE_EMIT_PATH = "/insightbridge/emit"
INSIGHTBRIDGE_TIMEOUT_S = int(os.environ.get("INSIGHTBRIDGE_TIMEOUT_S", 5))
INSIGHTBRIDGE_MAX_RETRIES = int(os.environ.get("INSIGHTBRIDGE_MAX_RETRIES", 2))

# Enforcement (Layer 4 Execution Gate) — Rajaryan Verma
ENFORCEMENT_URL = os.environ.get("ENFORCEMENT_URL", "http://localhost:8005")
ENFORCEMENT_TRIGGER_PATH = "/enforcement/trigger"
ENFORCEMENT_TIMEOUT_S = int(os.environ.get("ENFORCEMENT_TIMEOUT_S", 10))

# DGIC service own port
DGIC_PORT = int(os.environ.get("DGIC_PORT", 8000))

# Minimum secret key length (32 bytes = 64 hex chars)
_MIN_SECRET_LEN = 32


def validate_production_config():
    """Raise if critical production config is missing or insecure."""
    if not TOKEN_SECRET_KEY:
        raise EnvironmentError(
            "DGIC_TOKEN_SECRET_KEY is not set. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    if len(TOKEN_SECRET_KEY) < _MIN_SECRET_LEN:
        raise EnvironmentError(
            f"DGIC_TOKEN_SECRET_KEY is too short ({len(TOKEN_SECRET_KEY)} chars). "
            f"Minimum {_MIN_SECRET_LEN} characters required."
        )
