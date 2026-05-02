"""
dgic_contract.py — DGIC Output Contract (Schema-Locked)

Enforces the strict DGIC → Sarathi output schema.
No extra fields. No missing fields. All values deterministic.
"""

import hashlib
import json
from typing import Any, Dict, List

REQUIRED_FIELDS = {
    "execution_id": str,
    "execution_hash": str,
    "decision": str,
    "epistemic_state": dict,
    "confidence": float,
    "reason_trace": list,
    "collapse_trigger": str,
}

VALID_DECISIONS = {"ALLOW", "DENY", "ESCALATE"}


class ContractViolation(Exception):
    """Raised when DGIC output violates the strict contract."""


def _validate_schema(payload: Dict[str, Any]) -> None:
    """Reject if any required field is missing, extra, or wrong type."""
    missing = REQUIRED_FIELDS.keys() - payload.keys()
    if missing:
        raise ContractViolation(f"Missing fields: {sorted(missing)}")

    extra = payload.keys() - REQUIRED_FIELDS.keys()
    if extra:
        raise ContractViolation(f"Extra fields not allowed: {sorted(extra)}")

    for field, expected_type in REQUIRED_FIELDS.items():
        if not isinstance(payload[field], expected_type):
            raise ContractViolation(
                f"Field '{field}' must be {expected_type.__name__}, "
                f"got {type(payload[field]).__name__}"
            )

    if payload["decision"] not in VALID_DECISIONS:
        raise ContractViolation(
            f"decision must be one of {VALID_DECISIONS}, got '{payload['decision']}'"
        )

    if not (0.0 <= payload["confidence"] <= 1.0):
        raise ContractViolation(
            f"confidence must be 0.0–1.0, got {payload['confidence']}"
        )

    if not payload["reason_trace"]:
        raise ContractViolation("reason_trace cannot be empty")

    if not payload["epistemic_state"]:
        raise ContractViolation("epistemic_state cannot be empty — ESCALATE instead")


def _compute_hash(payload: Dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON payload (execution_hash field excluded)."""
    hashable = {k: v for k, v in payload.items() if k != "execution_hash"}
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def build_contract_payload(
    execution_id: str,
    decision: str,
    epistemic_state: Dict[str, Any],
    confidence: float,
    reason_trace: List[str],
    collapse_trigger: str,
) -> Dict[str, Any]:
    """
    Build and lock a DGIC contract payload.

    Raises ContractViolation if execution_id is missing or schema is invalid.
    Returns an immutable-safe dict with execution_hash bound.
    """
    if not execution_id or not isinstance(execution_id, str):
        raise ContractViolation("execution_id is required and must be a non-empty string")

    payload: Dict[str, Any] = {
        "execution_id": execution_id,
        "execution_hash": "",          # placeholder — filled after hash
        "decision": decision,
        "epistemic_state": epistemic_state,
        "confidence": float(confidence),
        "reason_trace": list(reason_trace),
        "collapse_trigger": collapse_trigger,
    }

    # Validate schema before hashing
    _validate_schema({**payload, "execution_hash": "placeholder"})

    # Bind hash (execution_id is part of the hashable payload)
    payload["execution_hash"] = _compute_hash(payload)

    # Final validation with real hash
    _validate_schema(payload)

    return payload


def verify_contract_payload(payload: Dict[str, Any]) -> None:
    """
    Verify a received payload:
    1. Schema is valid
    2. execution_hash matches recomputed hash

    Raises ContractViolation on any failure.
    """
    _validate_schema(payload)

    expected_hash = _compute_hash(payload)
    if payload["execution_hash"] != expected_hash:
        raise ContractViolation(
            f"Hash mismatch: payload has '{payload['execution_hash']}', "
            f"expected '{expected_hash}'"
        )
