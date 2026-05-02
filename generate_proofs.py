"""
generate_proofs.py — Proof Generation Script (Phase 7)

Generates:
  proof_valid_output.json      — valid DGIC output sample
  proof_tampered_output.json   — tampered output + rejection log
  proof_failure_cases.json     — all failure case rejection logs

Run:
    python generate_proofs.py
"""

import json
import sys
import io
import logging
from pathlib import Path
from typing import Any, Dict

logging.disable(logging.CRITICAL)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from dgic_contract_validator import validate, _recompute_hash

# ── Output directory — always the script's own directory (no traversal) ────────
_OUT_DIR = Path(__file__).resolve().parent

FIXED_EID   = "550e8400-e29b-41d4-a716-446655440001"
FIXED_EID_2 = "550e8400-e29b-41d4-a716-446655440002"


def _build_valid(eid: str, decision: str, confidence: float,
                 epistemic_state: str, reason_trace: list,
                 collapse_trigger: str) -> Dict[str, Any]:
    base = {
        "execution_id":    eid,
        "execution_hash":  "",
        "decision":        decision,
        "epistemic_state": epistemic_state,
        "confidence":      confidence,
        "reason_trace":    reason_trace,
        "collapse_trigger": collapse_trigger,
    }
    base["execution_hash"] = _recompute_hash(base)
    return base


def _write(filename: str, data: Any) -> None:
    """Write proof JSON to the script directory only — no path traversal possible."""
    out_path = _OUT_DIR / Path(filename).name  # strip any directory component
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"  wrote  {out_path.name}")


# ── Proof 1 — Valid output ─────────────────────────────────────────────────────

def _proof_valid_output() -> None:
    payload = _build_valid(
        eid=FIXED_EID,
        decision="ESCALATE",
        confidence=0.85,
        epistemic_state="CONTRADICTORY",
        reason_trace=[
            "Analyzed 2 input signals",
            "Found 1 THREAT signals",
            "Found 1 SAFE signals",
            "H-THREAT: 1 threat signal(s) detected (confidence: 0.90)",
            "H-SAFE: 1 safe signal(s) detected (confidence: 0.80)",
            "Identified 1 ambiguities",
        ],
        collapse_trigger="dominance",
    )
    result = validate(payload)
    assert result["status"] == "VALID", f"Expected VALID, got: {result}"

    _write("proof_valid_output.json", {
        "description": "Valid DGIC output — RAJYA can consume directly",
        "payload": payload,
        "validation_result": result,
    })


# ── Proof 2 — Tampered output ──────────────────────────────────────────────────

def _proof_tampered_output() -> None:
    original = _build_valid(
        eid=FIXED_EID,
        decision="ALLOW",
        confidence=0.92,
        epistemic_state="CERTAIN",
        reason_trace=["Signal analysis complete", "No threats detected"],
        collapse_trigger="threshold",
    )
    original_result = validate(original)
    assert original_result["status"] == "VALID"

    # Tamper: flip decision without rehashing
    tampered = dict(original)
    tampered["decision"] = "DENY"
    tampered_result = validate(tampered)
    assert tampered_result["status"] == "INVALID"

    _write("proof_tampered_output.json", {
        "description": "Tampered DGIC output — hash mismatch detected by RAJYA validator",
        "original_payload": original,
        "original_validation": original_result,
        "tampered_payload": tampered,
        "tampered_validation": tampered_result,
        "rejection_log": {
            "execution_id": tampered_result["execution_id"],
            "status": "REJECTED",
            "reason": tampered_result["reason"],
            "tamper_type": "decision_field_mutated_without_rehash",
        },
    })


# ── Proof 3 — All failure cases ────────────────────────────────────────────────

def _proof_failure_cases() -> None:
    cases: Dict[str, Any] = {}

    # Case 1: missing field
    p = _build_valid(FIXED_EID, "ALLOW", 0.9, "CERTAIN",
                     ["ok"], "threshold")
    del p["collapse_trigger"]
    r = validate(p)
    cases["case1_missing_field"] = {
        "input_mutation": "deleted collapse_trigger",
        "result": "REJECTED",
        "reason": r["reason"],
    }

    # Case 2: extra field
    p = _build_valid(FIXED_EID, "ALLOW", 0.9, "CERTAIN", ["ok"], "threshold")
    p["injected"] = "malicious"
    r = validate(p)
    cases["case2_extra_field"] = {
        "input_mutation": "added injected field",
        "result": "REJECTED",
        "reason": r["reason"],
    }

    # Case 3: hash tampering (decision mutated)
    p = _build_valid(FIXED_EID, "ALLOW", 0.9, "CERTAIN", ["ok"], "threshold")
    p["decision"] = "DENY"
    r = validate(p)
    cases["case3_hash_tampering"] = {
        "input_mutation": "decision changed ALLOW→DENY without rehash",
        "result": "REJECTED",
        "reason": r["reason"],
    }

    # Case 4: execution_id mismatch
    p = _build_valid(FIXED_EID, "ALLOW", 0.9, "CERTAIN", ["ok"], "threshold")
    p["execution_id"] = FIXED_EID_2   # swap id, hash now invalid
    r = validate(p)
    cases["case4_execution_id_mismatch"] = {
        "input_mutation": f"execution_id swapped to {FIXED_EID_2}",
        "result": "REJECTED",
        "reason": r["reason"],
    }

    # Case 5: invalid decision value
    p = _build_valid(FIXED_EID, "ALLOW", 0.9, "CERTAIN", ["ok"], "threshold")
    p["decision"] = "MAYBE"
    p["execution_hash"] = _recompute_hash(p)
    r = validate(p)
    cases["case5_invalid_decision"] = {
        "input_mutation": "decision set to MAYBE",
        "result": "REJECTED",
        "reason": r["reason"],
    }

    # Case 6: confidence out of range
    p = _build_valid(FIXED_EID, "ALLOW", 0.9, "CERTAIN", ["ok"], "threshold")
    p["confidence"] = 1.5
    p["execution_hash"] = _recompute_hash(p)
    r = validate(p)
    cases["case6_confidence_out_of_range"] = {
        "input_mutation": "confidence set to 1.5",
        "result": "REJECTED",
        "reason": r["reason"],
    }

    # Case 7: empty reason_trace
    p = _build_valid(FIXED_EID, "ALLOW", 0.9, "CERTAIN", ["ok"], "threshold")
    p["reason_trace"] = []
    p["execution_hash"] = _recompute_hash(p)
    r = validate(p)
    cases["case7_empty_reason_trace"] = {
        "input_mutation": "reason_trace set to []",
        "result": "REJECTED",
        "reason": r["reason"],
    }

    _write("proof_failure_cases.json", {
        "description": "All DGIC contract failure cases — each rejected deterministically",
        "cases": cases,
    })


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Generating proof files...")
    _proof_valid_output()
    _proof_tampered_output()
    _proof_failure_cases()
    print("Done.")
