"""
hash_validator.py — Execution Hash Integrity Validator

Standalone tamper-detection layer.
Callers validate execution_hash before acting on any DGIC payload.
"""

import hashlib
import json
from typing import Any, Dict


class HashMismatchError(Exception):
    """Raised when the recomputed hash does not match the payload hash."""


class MissingHashError(Exception):
    """Raised when execution_hash or execution_id is absent."""


def _recompute_hash(payload: Dict[str, Any]) -> str:
    """SHA-256 of canonical JSON with execution_hash excluded."""
    hashable = {k: v for k, v in payload.items() if k != "execution_hash"}
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate_payload_hash(payload: Dict[str, Any]) -> str:
    """
    Verify execution_hash in a DGIC payload.

    Returns the verified hash on success.
    Raises MissingHashError or HashMismatchError on failure.
    """
    if "execution_hash" not in payload:
        raise MissingHashError("execution_hash field is absent from payload")

    if "execution_id" not in payload:
        raise MissingHashError("execution_id field is absent from payload")

    expected = _recompute_hash(payload)
    received = payload["execution_hash"]

    if received != expected:
        raise HashMismatchError(
            f"Tamper detected for execution_id='{payload['execution_id']}': "
            f"received={received} expected={expected}"
        )

    return received


def validate_handoff_hash(handoff: Dict[str, Any]) -> None:
    """
    Validate a DGIC output envelope:
    {
        "execution_id": "...",
        "dgic_output": { ... },
        "execution_hash": "...",
        "timestamp": "..."
    }

    Rules:
    - execution_id in envelope must match execution_id inside dgic_output
    - execution_hash in envelope must match execution_hash inside dgic_output
    - dgic_output payload hash must be internally consistent

    Raises MissingHashError or HashMismatchError on any violation.
    """
    for field in ("execution_id", "dgic_output", "execution_hash", "timestamp"):
        if field not in handoff:
            raise MissingHashError(f"Handoff envelope missing field: '{field}'")

    dgic = handoff["dgic_output"]

    # execution_id continuity
    if handoff["execution_id"] != dgic.get("execution_id"):
        raise HashMismatchError(
            f"execution_id mismatch: envelope='{handoff['execution_id']}' "
            f"dgic_output='{dgic.get('execution_id')}'"
        )

    # execution_hash continuity
    if handoff["execution_hash"] != dgic.get("execution_hash"):
        raise HashMismatchError(
            f"execution_hash mismatch: envelope='{handoff['execution_hash']}' "
            f"dgic_output='{dgic.get('execution_hash')}'"
        )

    # Internal payload integrity
    validate_payload_hash(dgic)
