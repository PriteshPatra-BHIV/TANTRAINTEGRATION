# DGIC — MANDALA AUTHORITY NODE REVIEW PACKET

## ROLE

DGIC is a **pure reasoning authority**. It accepts signals, produces a decision, and returns.
It has **zero downstream calls**. Mandala drives all orchestration.

---

## 1. DELIVERABLES

| File | Role |
|------|------|
| `dgic_contract_validator.py` | **NEW** — RAJYA-facing validator: schema + hash integrity, returns VALID/INVALID |
| `dgic_adapter.py` | Mandala authority adapter — strict input/output contract |
| `dgic_service.py` | Refactored FastAPI service — decision only, no pipeline |
| `live_pipeline.py` | **DISABLED** — import-guarded, raises `ImportError` |
| `dgic_contract.py` | Schema enforcement + SHA-256 hash binding |
| `hash_validator.py` | Low-level hash recomputation and tamper detection |
| `generate_proofs.py` | **NEW** — programmatically generates all proof JSON files |
| `proof_valid_output.json` | Valid DGIC output sample with VALID confirmation |
| `proof_tampered_output.json` | Tampered output + rejection log |
| `proof_failure_cases.json` | All 7 failure cases with deterministic rejection reasons |
| `review_packets/2025-07-14_task.md` | **NEW** — dated task review packet |
| `REVIEW_PACKET.md` | This file |

---

## 2. START SERVICE

```
set DGIC_TOKEN_SECRET_KEY=<your_secret>
python dgic_service.py
```

Runs on `http://localhost:8000` (override with `DGIC_PORT`).

---

## 3. API CONTRACT

### POST /dgic/evaluate

**Request:**
```json
{
  "execution_id": "<UUID v4>",
  "ksml_input": {
    "execution_id": "<same UUID v4>",
    "timestamp": 1700000000000,
    "signals": [
      {"id": "s1", "type": "THREAT", "priority": 0.9,
       "timestamp": 1700000000000, "source": "sensor_a", "metadata": {}}
    ],
    "metadata": {}
  },
  "signals": []
}
```

**Response (strict — exactly these fields):**
```json
{
  "execution_id": "<UUID v4>",
  "decision": "ESCALATE",
  "confidence": 0.9,
  "epistemic_state": "CONTRADICTORY",
  "reason_trace": ["Analyzed 1 input signals", "..."],
  "execution_hash": "<sha256>",
  "collapse_trigger": "dominance",
  "processing_time_ms": 3
}
```

**Rules:**
- `execution_id` in body must match `execution_id` inside `ksml_input` → HTTP 400 on mismatch
- Invalid KSML → HTTP 422
- DGIC returns decision only — **zero downstream calls**

---

## 4. MANDALA ADAPTER CONTRACT

### Input
```json
{
  "execution_id": "<UUID v4>",
  "signals": [...],
  "context": {}
}
```

### Output (strict — no extra, no missing fields)
```json
{
  "execution_id": "<UUID v4>",
  "dgic_reasoning": {
    "decision": "ALLOW | DENY | ESCALATE",
    "confidence": 0.9,
    "epistemic_state": "CONTRADICTORY",
    "reason_trace": ["..."],
    "execution_hash": "<sha256>",
    "collapse_trigger": "dominance"
  }
}
```

Fits directly into `execution_request` — no transformation needed.

---

## 5. ZERO DOWNSTREAM CALLS — PROOF

`live_pipeline.py` is import-guarded:
```python
raise ImportError("live_pipeline is disabled. DGIC no longer owns pipeline orchestration.")
```

`dgic_service.py` has **no imports** of:
- `sarathi_client`
- `enforcement_client`
- `bucket_client`
- `insightbridge_client`
- `live_pipeline`

DGIC flow:
```
POST /dgic/evaluate
  └─► KSML validation
  └─► execution_id boundary check
  └─► Decision reasoning
  └─► Return decision ← STOPS HERE
```

---

## 6. ADAPTER TEST CASES

Run:
```
python dgic_adapter.py
```

| # | Test | Expected |
|---|------|----------|
| 1 | Normal reasoning (SAFE signal) | Valid output, all 6 fields present |
| 2 | Conflicting signals (THREAT + SAFE) | `decision = ESCALATE` |
| 3 | Missing `execution_id` | `AdapterContractError` raised |
| 4 | Invalid UUID format | `AdapterContractError` raised |

---

## 7. EXECUTION_ID INTEGRITY

| Boundary | File | Behaviour on mismatch |
|----------|------|-----------------------|
| Outer vs ksml_input | `dgic_service.py` | HTTP 400, logged |
| Adapter input | `dgic_adapter.py` | `AdapterContractError` raised |
| Output echo | `dgic_adapter.py` | `execution_id` always echoed unchanged |

---

## 8. ENVIRONMENT VARIABLES

| Variable | Default | Description |
|----------|---------|-------------|
| `DGIC_TOKEN_SECRET_KEY` | (required) | HMAC secret for session tokens |
| `DGIC_PORT` | `8000` | DGIC service port |

All downstream service URLs (`SARATHI_URL`, `CORE_URL`, etc.) are **no longer used by DGIC**.

---

## 9. HASH CONTRACT ALIGNMENT (CRITICAL FIX)

`decision_contract_standardization._generate_execution_hash()` was updated to compute
`SHA256(canonical_json(7 contract fields, execution_hash excluded))` — identical to
`dgic_contract_validator._recompute_hash()`. This ensures a live `/dgic/evaluate` response
passes RAJYA validation without any transformation.

---

## 10. ACCEPTANCE CRITERIA

| Criterion | Status |
|-----------|--------|
| DGIC has ZERO downstream calls | PASS — `live_pipeline` import-guarded, no client imports |
| DGIC works as standalone authority | PASS — `dgic_service.py` returns decision only |
| DGIC integrates via adapter into Mandala | PASS — `dgic_adapter.py` with strict contract |
| Output fits `execution_request` directly | PASS — no transformation needed |
| Missing `execution_id` → rejected | PASS — `AdapterContractError` |
| Conflicting signals → ESCALATE | PASS — test 2 |
| No extra / missing output fields | PASS — `_validate_output` enforces exact field set |
| Deterministic output | PASS — same input → same hash always |
| DGIC schema strictly enforced (7 fields) | PASS — `dgic_contract_validator.py` |
| Hash binds full payload + execution_id | PASS — SHA-256 over canonical JSON of 7 contract fields |
| Tampering detectable by RAJYA | PASS — 16/16 validator tests pass |
| Proof files generated programmatically | PASS — `python generate_proofs.py` |
| Dated review packet present | PASS — `review_packets/2025-07-14_task.md` |

---

## 10. PROOF OUTPUTS

### Validator tests (Phase 3 + Phase 6)
```
python dgic_contract_validator.py
```
Expected: `16 passed, 0 failed`

Covers: valid payload, hash tampering, missing field, extra field, execution_id mismatch, invalid decision, confidence out of range, empty reason_trace.

### Adapter tests (Phase 4)
```
python dgic_adapter.py
```
Expected: `12 passed, 0 failed`

### Generate proof files (Phase 7)
```
python generate_proofs.py
```
Writes:
- `proof_valid_output.json` — valid payload + VALID confirmation
- `proof_tampered_output.json` — tampered payload + rejection log
- `proof_failure_cases.json` — 7 failure cases, all deterministically rejected
