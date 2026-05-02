"""
Sūtradhāra Compliance Module
Phase 1: Ensure DGIC cannot be invoked outside Sūtradhāra control plane
"""

from typing import Dict, Any, Callable
from functools import wraps
import hmac
import hashlib
import secrets
import threading
import time
import uuid
from enum import Enum
from config import SESSION_EXPIRY_MS, SESSION_MAX_INVOCATIONS, TOKEN_SECRET_KEY
from logger import get_logger

_log = get_logger("sutradhara_compliance")

class InvocationSource(Enum):
    """Valid invocation sources"""
    SUTRADHARA = "sutradhara"
    INVALID = "invalid"

class ComplianceViolation(Exception):
    """Raised when Sūtradhāra compliance is violated"""
    pass

class SutradhaaraCompliance:
    """Enforces Sūtradhāra compliance for DGIC agent"""

    def __init__(self):
        self._lock = threading.Lock()          # thread-safe session access
        self.active_sessions: Dict[str, Any] = {}
        self.strict_mode = True

    def create_sutradhara_session(self, sutradhara_instance_id: str) -> Dict[str, str]:
        """Create a valid Sūtradhāra session (called by Sūtradhāra only)"""
        session_id = f"sutradhara_session_{uuid.uuid4().hex}"
        # Cryptographically secure token
        invocation_token = secrets.token_hex(32)

        # HMAC-based session hash — requires TOKEN_SECRET_KEY
        secret = TOKEN_SECRET_KEY.encode() if TOKEN_SECRET_KEY else secrets.token_bytes(32)
        session_hash = hmac.new(
            secret,
            f"{session_id}:{invocation_token}:{sutradhara_instance_id}".encode(),
            hashlib.sha256
        ).hexdigest()

        now = int(time.time() * 1000)
        session_data = {
            "session_id": session_id,
            "invocation_token": invocation_token,
            "session_hash": session_hash,
            "sutradhara_instance_id": sutradhara_instance_id,
            "created_at": now,
            "expires_at": now + SESSION_EXPIRY_MS,
            "invocation_count": 0,
            "max_invocations": SESSION_MAX_INVOCATIONS,
        }

        with self._lock:
            self.active_sessions[session_id] = session_data

        _log.info("session_created session_id=%s instance=%s", session_id, sutradhara_instance_id)
        return {"session_id": session_id, "invocation_token": invocation_token, "session_hash": session_hash}
    
    def validate_sutradhara_invocation(self, caller_context: Dict[str, Any]) -> bool:
        """Validate that invocation comes from Sūtradhāra with valid session"""
        for field in ("sutradhara_session_id", "agent_invocation_token"):
            if field not in caller_context:
                _log.warning("compliance_violation type=missing_field field=%s", field)
                raise ComplianceViolation(f"Missing required field: {field}")

        session_id = caller_context["sutradhara_session_id"]
        token = caller_context["agent_invocation_token"]

        with self._lock:
            session = self.active_sessions.get(session_id)
            if session is None:
                _log.warning("compliance_violation type=invalid_session session_id=%s", session_id)
                raise ComplianceViolation(f"Invalid or expired session: {session_id}")

            # Constant-time token comparison to prevent timing attacks
            if not secrets.compare_digest(token, session["invocation_token"]):
                _log.warning("compliance_violation type=invalid_token session_id=%s", session_id)
                raise ComplianceViolation("Invalid invocation token")

            now = int(time.time() * 1000)
            if now > session["expires_at"]:
                del self.active_sessions[session_id]
                _log.warning("compliance_violation type=expired_session session_id=%s", session_id)
                raise ComplianceViolation("Session expired")

            if session["invocation_count"] >= session["max_invocations"]:
                _log.warning("compliance_violation type=invocation_limit session_id=%s", session_id)
                raise ComplianceViolation("Session invocation limit exceeded")

            session["invocation_count"] += 1
            session["last_invocation"] = now

        _log.info("valid_invocation session_id=%s count=%d", session_id, session["invocation_count"])
        return True
    
    def get_compliance_status(self) -> Dict[str, Any]:
        """Get current compliance status"""
        now = int(time.time() * 1000)
        with self._lock:
            active = sum(1 for s in self.active_sessions.values() if s["expires_at"] > now)
        return {"strict_mode": self.strict_mode, "active_sessions": active}

    def cleanup_expired_sessions(self) -> int:
        """Remove all expired sessions. Call periodically."""
        now = int(time.time() * 1000)
        with self._lock:
            expired = [sid for sid, s in self.active_sessions.items() if s["expires_at"] <= now]
            for sid in expired:
                del self.active_sessions[sid]
        if expired:
            _log.info("cleanup_expired_sessions count=%d", len(expired))
        return len(expired)

# Global compliance instance
sutradhara_compliance = SutradhaaraCompliance()


def sutradhara_only(func: Callable) -> Callable:
    """Decorator: function can only be called via Sūtradhāra."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        caller_context = kwargs.get("caller_context")
        if not caller_context:
            raise ComplianceViolation("No caller context — DGIC can only be invoked via Sutradhara")
        sutradhara_compliance.validate_sutradhara_invocation(caller_context)
        return func(*args, **{k: v for k, v in kwargs.items() if k != "caller_context"})
    return wrapper


def block_direct_access(func: Callable) -> Callable:
    """Decorator: block any call that lacks a Sūtradhāra context."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "caller_context" not in kwargs:
            raise ComplianceViolation(
                "Direct access to DGIC is forbidden. "
                "DGIC must be invoked through Sutradhara control plane only."
            )
        return func(*args, **kwargs)
    return wrapper


def create_sutradhara_session(sutradhara_instance_id: str) -> Dict[str, str]:
    return sutradhara_compliance.create_sutradhara_session(sutradhara_instance_id)


def validate_invocation(caller_context: Dict[str, Any]) -> bool:
    return sutradhara_compliance.validate_sutradhara_invocation(caller_context)


def get_compliance_status() -> Dict[str, Any]:
    return sutradhara_compliance.get_compliance_status()


def cleanup_sessions() -> int:
    return sutradhara_compliance.cleanup_expired_sessions()

if __name__ == "__main__":
    import os
    import sys
    if not os.environ.get("DGIC_TOKEN_SECRET_KEY"):
        print("ERROR: DGIC_TOKEN_SECRET_KEY must be set before running this module.")
        print("  export DGIC_TOKEN_SECRET_KEY=$(python -c \"import secrets; print(secrets.token_hex(32))\")") 
        sys.exit(1)
    session = create_sutradhara_session("sutradhara_instance_001")
    print(f"Created session: {session['session_id']}")
    caller_context = {
        "sutradhara_session_id": session["session_id"],
        "agent_invocation_token": session["invocation_token"]
    }
    validate_invocation(caller_context)
    print("Valid invocation: ALLOWED")
    try:
        validate_invocation({})
    except ComplianceViolation as e:
        print(f"Invalid invocation: BLOCKED — {e}")