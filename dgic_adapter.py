"""
dgic_adapter.py — DGIC Mandala Authority Adapter

Wraps DGIC reasoning as a plug-and-play Mandala authority node.

Input contract:
{
    "execution_id": "<UUID v4>",
    "signals": [...],
    "context": {}
}

Output contract (strict — no extra, no missing fields):
{
    "execution_id": "<UUID v4>",
    "dgic_reasoning": {
        "decision": "ALLOW | DENY | ESCALATE",
        "confidence": <float 0.0-1.0>,
        "epistemic_state": "<string>",
        "reason_trace": [...],
        "execution_hash": "<sha256>",
        "collapse_trigger": "<string>"
    }
}
"""

import hashlib
import json
import time
import uuid
from typing import Any, Dict, List

from decision_contract_standardization import (
    DecisionContractStandardizer,
    DecisionContractError,
    convert_to_dict as decision_to_dict,
)
from logger import get_logger

_log = get_logger("dgic_adapter")
_standardizer = DecisionContractStandardizer()

# ── Decision mapping ───────────────────────────────────────────────────────────
# Map DecisionContractStandardizer values → Mandala-compatible decisions
_DECISION_MAP = {
    "ESCALATE": "ESCALATE",
    "PROCEED":  "ALLOW",
    "HOLD":     "ESCALATE",          # ambiguous → escalate for safety
    "REQUEST_MORE_DATA": "ESCALATE", # insufficient → escalate
    "ERROR":    "ESCALATE",
}


# ── Contract validation ────────────────────────────────────────────────────────

class AdapterContractError(Exception):
    """Raised when input or output violates the strict adapter contract."""


_REQUIRED_OUTPUT_FIELDS = {
    "decision", "confidence", "epistemic_state",
    "reason_trace", "execution_hash", "collapse_trigger",
}


def _validate_input(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise AdapterContractError("Input must be a dict")
    if "execution_id" not in payload:
        raise AdapterContractError("Missing required field: execution_id")
    eid = payload["execution_id"]
    if not eid or not isinstance(eid, str):
        raise AdapterContractError("execution_id must be a non-empty string")
    try:
        obj = uuid.UUID(eid, version=4)
        if str(obj) != eid:
            raise ValueError
    except ValueError:
        raise AdapterContractError(f"execution_id must be a valid UUID v4, got: {eid}")
    if "signals" not in payload:
        raise AdapterContractError("Missing required field: signals")
    if not isinstance(payload["signals"], list):
        raise AdapterContractError("signals must be a list")


def _validate_output(reasoning: Dict[str, Any]) -> None:
    missing = _REQUIRED_OUTPUT_FIELDS - reasoning.keys()
    if missing:
        raise AdapterContractError(f"Output missing fields: {sorted(missing)}")
    extra = reasoning.keys() - _REQUIRED_OUTPUT_FIELDS
    if extra:
        raise AdapterContractError(f"Output has extra fields not allowed: {sorted(extra)}")


# ── Intelligence builder ───────────────────────────────────────────────────────

def _build_intelligence(signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    threat = [s for s in signals if s.get("type") == "THREAT"]
    safe   = [s for s in signals if s.get("type") == "SAFE"]
    unk    = [s for s in signals if s.get("type") == "UNKNOWN"]

    interpretations = []
    if threat:
        avg = sum(s.get("priority", 0.5) for s in threat) / len(threat)
        interpretations.append({
            "hypothesis": "H-THREAT",
            "description": f"{len(threat)} threat signal(s) detected",
            "confidence_estimate": {"mean": avg, "uncertainty": 0.1},
        })
    if safe:
        avg = sum(s.get("priority", 0.5) for s in safe) / len(safe)
        interpretations.append({
            "hypothesis": "H-SAFE",
            "description": f"{len(safe)} safe signal(s) detected",
            "confidence_estimate": {"mean": 1.0 - avg, "uncertainty": 0.1},
        })

    uncertainty: Dict[str, List] = {"ambiguities": [], "unknowns": []}
    if len(interpretations) > 1:
        uncertainty["ambiguities"].append("Multiple interpretations present")
    if unk:
        uncertainty["unknowns"].append(f"{len(unk)} unknown signal(s)")

    return {
        "signals": [{"signal_id": s.get("id", ""), "type": s.get("type", "")} for s in signals],
        "interpretations": interpretations,
        "uncertainty": uncertainty,
    }


def _get_timestamp(signals: List[Dict[str, Any]]) -> int:
    """Use first signal timestamp if available, else fixed epoch for determinism."""
    for s in signals:
        ts = s.get("timestamp")
        if isinstance(ts, int) and ts > 0:
            return ts
    return 1700000000000


# ── Core adapter function ──────────────────────────────────────────────────────

def run_dgic_adapter(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute DGIC reasoning and return a Mandala-compatible authority response.

    Args:
        payload: {"execution_id": str, "signals": list, "context": dict}

    Returns:
        {"execution_id": str, "dgic_reasoning": {...}}

    Raises:
        AdapterContractError: on input/output contract violation
        DecisionContractError: on internal reasoning failure
    """
    _validate_input(payload)

    execution_id: str = payload["execution_id"]
    signals: List[Dict[str, Any]] = payload["signals"]
    timestamp = _get_timestamp(signals)

    _log.info("adapter_start execution_id=%s signal_count=%d", execution_id, len(signals))

    intelligence = _build_intelligence(signals)

    decision_obj = _standardizer.standardize_decision_output(
        intelligence, execution_id, timestamp
    )
    raw = decision_to_dict(decision_obj)

    # Map to Mandala-compatible decision values
    mandala_decision = _DECISION_MAP.get(raw["decision"], "ESCALATE")

    reasoning: Dict[str, Any] = {
        "decision":        mandala_decision,
        "confidence":      raw["confidence"],
        "epistemic_state": raw["epistemic_state"],
        "reason_trace":    raw["reason_trace"],
        "execution_hash":  raw["execution_hash"],
        "collapse_trigger": raw["collapse_trigger"],
    }

    _validate_output(reasoning)

    result = {
        "execution_id":   execution_id,
        "dgic_reasoning": reasoning,
    }

    _log.info(
        "adapter_complete execution_id=%s decision=%s confidence=%.2f",
        execution_id, mandala_decision, reasoning["confidence"],
    )
    return result


# ── Test cases ─────────────────────────────────────────────────────────────────

def _run_tests() -> None:
    import sys
    import logging
    import io
    logging.disable(logging.CRITICAL)  # suppress log output during tests
    # Force UTF-8 output on Windows
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    passed = 0
    failed = 0

    def _assert(name: str, condition: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if condition:
            print(f"  PASS  {name}")
            passed += 1
        else:
            print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))
            failed += 1

    print("=" * 60)
    print("dgic_adapter — Test Suite")
    print("=" * 60)

    ts = 1700000000000
    valid_eid = str(uuid.uuid4())

    # ── Test 1: Normal reasoning ───────────────────────────────────────────────
    print("\n[1] Normal reasoning")
    payload = {
        "execution_id": valid_eid,
        "signals": [
            {"id": "s1", "type": "SAFE", "priority": 0.2, "timestamp": ts, "source": "sensor_a"},
        ],
        "context": {},
    }
    try:
        result = run_dgic_adapter(payload)
        _assert("execution_id echoed", result["execution_id"] == valid_eid)
        _assert("dgic_reasoning present", "dgic_reasoning" in result)
        r = result["dgic_reasoning"]
        _assert("decision is valid", r["decision"] in {"ALLOW", "DENY", "ESCALATE"})
        _assert("confidence in range", 0.0 <= r["confidence"] <= 1.0)
        _assert("reason_trace non-empty", len(r["reason_trace"]) > 0)
        _assert("execution_hash present", len(r["execution_hash"]) == 64)
        _assert("no extra fields", set(r.keys()) == _REQUIRED_OUTPUT_FIELDS)
    except Exception as exc:
        _assert("normal_reasoning no exception", False, str(exc))

    # ── Test 2: Conflicting signals → ESCALATE ─────────────────────────────────
    print("\n[2] Conflicting signals -> ESCALATE")
    conflict_eid = str(uuid.uuid4())
    payload2 = {
        "execution_id": conflict_eid,
        "signals": [
            {"id": "s1", "type": "THREAT", "priority": 0.9, "timestamp": ts, "source": "sensor_a"},
            {"id": "s2", "type": "SAFE",   "priority": 0.2, "timestamp": ts, "source": "sensor_b"},
        ],
        "context": {},
    }
    try:
        result2 = run_dgic_adapter(payload2)
        r2 = result2["dgic_reasoning"]
        _assert("conflicting → ESCALATE", r2["decision"] == "ESCALATE",
                f"got {r2['decision']}")
        _assert("execution_id echoed", result2["execution_id"] == conflict_eid)
    except Exception as exc:
        _assert("conflicting_signals no exception", False, str(exc))

    # ── Test 3: Missing execution_id → reject ──────────────────────────────────
    print("\n[3] Missing execution_id -> reject")
    try:
        run_dgic_adapter({"signals": [], "context": {}})
        _assert("missing execution_id rejected", False, "no exception raised")
    except AdapterContractError as exc:
        _assert("AdapterContractError raised", True)
        _assert("error mentions execution_id", "execution_id" in str(exc))
    except Exception as exc:
        _assert("missing execution_id rejected", False, f"wrong exception: {exc}")

    # ── Test 4: Invalid execution_id format → reject ───────────────────────────
    print("\n[4] Invalid execution_id format -> reject")
    try:
        run_dgic_adapter({"execution_id": "not-a-uuid", "signals": [], "context": {}})
        _assert("invalid uuid rejected", False, "no exception raised")
    except AdapterContractError as exc:
        _assert("AdapterContractError raised", True)

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    _run_tests()
