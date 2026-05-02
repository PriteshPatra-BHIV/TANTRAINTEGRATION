"""
dgic_contract_validator.py — DGIC Contract Validator

Single responsibility: validate a DGIC output payload is schema-correct
and cryptographically intact before RAJYA consumes it.

Returns:
    {"status": "VALID", "execution_id": "..."}
    {"status": "INVALID", "reason": "...", "execution_id": "..."}
"""

import hashlib
import json
from typing import Any, Dict

# ── Contract definition ────────────────────────────────────────────────────────

REQUIRED_FIELDS: Dict[str, type] = {
    "execution_id":    str,
    "execution_hash":  str,
    "decision":        str,
    "epistemic_state": str,
    "confidence":      float,
    "reason_trace":    list,
    "collapse_trigger": str,
}

VALID_DECISIONS = {"ALLOW", "DENY", "ESCALATE"}


# ── Hash recomputation ─────────────────────────────────────────────────────────

def _recompute_hash(payload: Dict[str, Any]) -> str:
    """SHA-256(execution_id + canonical JSON of full payload minus execution_hash)."""
    hashable = {k: v for k, v in payload.items() if k != "execution_hash"}
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── Validator ──────────────────────────────────────────────────────────────────

def validate(payload: Dict[str, Any]) -> Dict[str, str]:
    """
    Validate a DGIC output payload.

    Checks (in order):
      1. Payload is a dict
      2. No missing fields
      3. No extra fields
      4. Correct types
      5. decision is one of ALLOW / DENY / ESCALATE
      6. confidence is 0.0–1.0
      7. reason_trace is non-empty
      8. execution_hash matches recomputed hash

    Returns:
        {"status": "VALID",   "execution_id": "..."}
        {"status": "INVALID", "execution_id": "...", "reason": "..."}
    """
    eid = payload.get("execution_id", "<unknown>") if isinstance(payload, dict) else "<unknown>"

    def _invalid(reason: str) -> Dict[str, str]:
        return {"status": "INVALID", "execution_id": eid, "reason": reason}

    if not isinstance(payload, dict):
        return _invalid("Payload must be a dict")

    missing = REQUIRED_FIELDS.keys() - payload.keys()
    if missing:
        return _invalid(f"Missing fields: {sorted(missing)}")

    extra = payload.keys() - REQUIRED_FIELDS.keys()
    if extra:
        return _invalid(f"Extra fields not allowed: {sorted(extra)}")

    for field, expected in REQUIRED_FIELDS.items():
        if not isinstance(payload[field], expected):
            return _invalid(
                f"Field '{field}' must be {expected.__name__}, "
                f"got {type(payload[field]).__name__}"
            )

    if payload["decision"] not in VALID_DECISIONS:
        return _invalid(f"decision must be one of {VALID_DECISIONS}, got '{payload['decision']}'")

    if not (0.0 <= payload["confidence"] <= 1.0):
        return _invalid(f"confidence must be 0.0–1.0, got {payload['confidence']}")

    if not payload["reason_trace"]:
        return _invalid("reason_trace cannot be empty")

    expected_hash = _recompute_hash(payload)
    if payload["execution_hash"] != expected_hash:
        return _invalid(
            f"Hash mismatch — tamper detected: "
            f"stored={payload['execution_hash']} expected={expected_hash}"
        )

    return {"status": "VALID", "execution_id": eid}


# ── Self-test ──────────────────────────────────────────────────────────────────

def _run_tests() -> None:
    import sys, io, logging
    logging.disable(logging.CRITICAL)
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    passed = failed = 0

    def _assert(name: str, cond: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if cond:
            print(f"  PASS  {name}"); passed += 1
        else:
            print(f"  FAIL  {name}" + (f" — {detail}" if detail else "")); failed += 1

    def _make_valid() -> Dict[str, Any]:
        base = {
            "execution_id":    "550e8400-e29b-41d4-a716-446655440001",
            "execution_hash":  "",
            "decision":        "ALLOW",
            "epistemic_state": "CERTAIN",
            "confidence":      0.9,
            "reason_trace":    ["Signal analysis complete"],
            "collapse_trigger": "threshold",
        }
        base["execution_hash"] = _recompute_hash(base)
        return base

    print("=" * 60)
    print("dgic_contract_validator — Test Suite")
    print("=" * 60)

    # 1. Valid payload
    print("\n[1] Valid payload")
    r = validate(_make_valid())
    _assert("status VALID",        r["status"] == "VALID")
    _assert("execution_id echoed", r["execution_id"] == "550e8400-e29b-41d4-a716-446655440001")

    # 2. Hash tampering
    print("\n[2] Hash tampering")
    p = _make_valid(); p["decision"] = "DENY"   # mutate without rehashing
    r = validate(p)
    _assert("status INVALID",      r["status"] == "INVALID")
    _assert("reason mentions hash", "tamper" in r["reason"].lower())

    # 3. Missing field
    print("\n[3] Missing field")
    p = _make_valid(); del p["collapse_trigger"]
    r = validate(p)
    _assert("status INVALID",           r["status"] == "INVALID")
    _assert("reason mentions missing",  "Missing" in r["reason"])

    # 4. Extra field
    print("\n[4] Extra field")
    p = _make_valid(); p["rogue_field"] = "injected"
    r = validate(p)
    _assert("status INVALID",          r["status"] == "INVALID")
    _assert("reason mentions extra",   "Extra" in r["reason"])

    # 5. execution_id mismatch (tampered id, hash not updated)
    print("\n[5] execution_id mismatch")
    p = _make_valid(); p["execution_id"] = "00000000-0000-4000-a000-000000000000"
    r = validate(p)
    _assert("status INVALID",          r["status"] == "INVALID")
    _assert("reason mentions hash",    "tamper" in r["reason"].lower())

    # 6. Invalid decision value
    print("\n[6] Invalid decision value")
    p = _make_valid(); p["decision"] = "MAYBE"; p["execution_hash"] = _recompute_hash(p)
    r = validate(p)
    _assert("status INVALID",          r["status"] == "INVALID")
    _assert("reason mentions decision", "decision" in r["reason"])

    # 7. confidence out of range
    print("\n[7] confidence out of range")
    p = _make_valid(); p["confidence"] = 1.5; p["execution_hash"] = _recompute_hash(p)
    r = validate(p)
    _assert("status INVALID",              r["status"] == "INVALID")
    _assert("reason mentions confidence",  "confidence" in r["reason"])

    # 8. empty reason_trace
    print("\n[8] Empty reason_trace")
    p = _make_valid(); p["reason_trace"] = []; p["execution_hash"] = _recompute_hash(p)
    r = validate(p)
    _assert("status INVALID",                  r["status"] == "INVALID")
    _assert("reason mentions reason_trace",    "reason_trace" in r["reason"])

    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    _run_tests()
