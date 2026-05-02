"""
dgic_service.py — DGIC Authority Node (Mandala-compatible)
Exposes:
  POST /dgic/evaluate   — pure reasoning, returns decision only
  GET  /health
  GET  /health/live
  GET  /metrics
  GET  /circuit-breakers
DGIC has ZERO downstream calls. It is a standalone reasoning authority.
"""

import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Request, Header, Depends
from pydantic import BaseModel, field_validator

from circuit_breaker import all_statuses
from config import DGIC_PORT, validate_production_config
from decision_contract_standardization import (
    DecisionContractStandardizer,
    DecisionContractError,
    convert_to_dict as decision_to_dict,
)
from ksml_input_enforcement import KSMLInputEnforcer, InputValidationError
from logger import get_logger
from metrics import (
    REQUEST_COUNT,
    REQUEST_ERRORS,
    REQUEST_LATENCY,
    CIRCUIT_STATE,
    metrics_endpoint,
)
from middleware import RateLimitMiddleware, RequestIDMiddleware
from sutradhara_compliance import ComplianceViolation, validate_invocation
from tracing import setup_tracing, get_tracer

_log = get_logger("dgic_service")
_ksml_enforcer = KSMLInputEnforcer()
_standardizer = DecisionContractStandardizer()


def _safe(value: str) -> str:
    """Strip newlines and carriage returns to prevent log injection."""
    return str(value).replace("\n", "").replace("\r", "")

# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        validate_production_config()
        _log.info("startup_config_ok")
    except EnvironmentError as exc:
        _log.error("startup_config_error error=%s", exc)
        raise
    setup_tracing(app)
    _log.info("startup_complete service=dgic port=%d", DGIC_PORT)
    yield
    _log.info("shutdown_complete service=dgic")


# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="DGIC Intelligence Authority Node",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestIDMiddleware)


# ── Sutradhara auth dependency ─────────────────────────────────────────────────

def _require_sutradhara(
    x_sutradhara_session_id: Optional[str] = Header(None, alias="X-Sutradhara-Session-Id"),
    x_sutradhara_token: Optional[str] = Header(None, alias="X-Sutradhara-Token"),
) -> Dict[str, str]:
    if not x_sutradhara_session_id or not x_sutradhara_token:
        raise HTTPException(
            status_code=401,
            detail="Missing Sutradhara session headers",
        )
    try:
        validate_invocation({
            "sutradhara_session_id": x_sutradhara_session_id,
            "agent_invocation_token": x_sutradhara_token,
        })
    except ComplianceViolation as exc:
        raise HTTPException(status_code=403, detail=f"Sutradhara compliance violation: {exc}")
    return {
        "sutradhara_session_id": x_sutradhara_session_id,
        "agent_invocation_token": x_sutradhara_token,
    }


# ── Request / Response models ──────────────────────────────────────────────────

class EvaluateRequest(BaseModel):
    execution_id: str
    ksml_input: Dict[str, Any]
    signals: List[Dict[str, Any]] = []

    @field_validator("execution_id")
    @classmethod
    def must_be_uuid4(cls, v: str) -> str:
        try:
            obj = uuid.UUID(v, version=4)
            if str(obj) != v:
                raise ValueError
        except ValueError:
            raise ValueError(f"execution_id must be a valid UUID v4, got: {v}")
        return v


class EvaluateResponse(BaseModel):
    """
    Strict DGIC authority output — exactly these fields, no more, no less.
    Compatible with Mandala execution_request directly.
    """
    execution_id: str
    decision: str
    confidence: float
    epistemic_state: str
    reason_trace: List[str]
    execution_hash: str
    collapse_trigger: str
    processing_time_ms: int


# ── Intelligence builder ───────────────────────────────────────────────────────

def _build_intelligence(signals: List[Dict]) -> Dict[str, Any]:
    threat = [s for s in signals if s["type"] == "THREAT"]
    safe   = [s for s in signals if s["type"] == "SAFE"]
    unk    = [s for s in signals if s["type"] == "UNKNOWN"]

    interpretations = []
    if threat:
        avg = sum(s["priority"] for s in threat) / len(threat)
        interpretations.append({
            "hypothesis": "H-THREAT",
            "description": f"{len(threat)} threat signal(s) detected",
            "confidence_estimate": {"mean": avg, "uncertainty": 0.1},
        })
    if safe:
        avg = sum(s["priority"] for s in safe) / len(safe)
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
        "signals": [{"signal_id": s["id"], "type": s["type"]} for s in signals],
        "interpretations": interpretations,
        "uncertainty": uncertainty,
    }


# ── Evaluate endpoint ──────────────────────────────────────────────────────────

@app.post("/dgic/evaluate", response_model=EvaluateResponse)
async def evaluate(
    req: EvaluateRequest,
    request: Request,
    _caller: Dict[str, str] = Depends(_require_sutradhara),
):
    start = time.time()
    execution_id = req.execution_id
    request_id = getattr(request.state, "request_id", "unknown")

    _log.info("evaluate_start execution_id=%s request_id=%s", _safe(execution_id), _safe(request_id))

    tracer = get_tracer()
    with tracer.start_as_current_span("dgic.evaluate") as span:
        span.set_attribute("execution_id", execution_id)

        # 1. Validate KSML input
        try:
            validated = _ksml_enforcer.enforce_input_contract(req.ksml_input)
        except InputValidationError as exc:
            REQUEST_ERRORS.labels(error_type="ksml_validation").inc()
            _log.error("ksml_validation_failed execution_id=%s error=%s", _safe(execution_id), _safe(str(exc)))
            raise HTTPException(status_code=422, detail=str(exc))

        # 2. execution_id boundary check
        if validated.execution_id != execution_id:
            REQUEST_ERRORS.labels(error_type="execution_id_mismatch").inc()
            _log.error("execution_id_mismatch outer=%s ksml=%s", _safe(execution_id), _safe(validated.execution_id))
            raise HTTPException(
                status_code=400,
                detail=f"execution_id mismatch: outer={execution_id} ksml={validated.execution_id}",
            )

        # 3. Build intelligence from validated signals
        signal_dicts = [
            {"id": s.id, "type": s.type.value, "priority": s.priority,
             "timestamp": s.timestamp, "source": s.source}
            for s in validated.signals
        ]
        intelligence = _build_intelligence(signal_dicts)

        # 4. Standardize to decision contract
        try:
            decision_obj = _standardizer.standardize_decision_output(
                intelligence, execution_id, validated.timestamp
            )
        except DecisionContractError as exc:
            REQUEST_ERRORS.labels(error_type="standardization_error").inc()
            _log.error("standardization_failed execution_id=%s error=%s", _safe(execution_id), _safe(str(exc)))
            raise HTTPException(status_code=500, detail=f"Decision standardization failed: {exc}")

        output = decision_to_dict(decision_obj)
        elapsed_ms = int((time.time() - start) * 1000)

        # 5. Metrics
        REQUEST_COUNT.labels(
            decision=output["decision"],
            epistemic_state=output["epistemic_state"],
        ).inc()
        REQUEST_LATENCY.observe(elapsed_ms)

        span.set_attribute("decision", output["decision"])
        span.set_attribute("confidence", output["confidence"])

        _log.info(
            "evaluate_complete execution_id=%s decision=%s confidence=%.2f latency_ms=%d",
            _safe(execution_id), _safe(output["decision"]), output["confidence"], elapsed_ms,
        )

        # 6. Return decision only — DGIC calls NO downstream service
        return EvaluateResponse(
            execution_id=output["execution_id"],
            decision=output["decision"],
            confidence=output["confidence"],
            epistemic_state=output["epistemic_state"],
            reason_trace=output["reason_trace"],
            execution_hash=output["execution_hash"],
            collapse_trigger=output["collapse_trigger"],
            processing_time_ms=elapsed_ms,
        )


# ── Health / Metrics ───────────────────────────────────────────────────────────

@app.post("/demo/create-session")
async def create_demo_session():
    """Demo only — disabled in production (set DGIC_DEMO_ENABLED=true to enable)."""
    import os
    if os.environ.get("DGIC_DEMO_ENABLED", "false").lower() != "true":
        raise HTTPException(status_code=404, detail="Not found")
    from sutradhara_compliance import create_sutradhara_session
    session = create_sutradhara_session("tiwari_demo")
    return {
        "session_id": session["session_id"],
        "invocation_token": session["invocation_token"],
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "dgic", "version": "2.0.0"}


@app.get("/health/live")
async def health_live():
    statuses = all_statuses()
    for s in statuses:
        CIRCUIT_STATE.labels(service=s["service"]).set(1 if s["state"] == "open" else 0)
    return {"status": "ok", "circuit_breakers": statuses}


@app.get("/metrics")
async def metrics():
    return metrics_endpoint()


@app.get("/circuit-breakers")
async def circuit_breakers():
    return {"circuit_breakers": all_statuses()}


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    import uvicorn
    workers = int(os.environ.get("DGIC_WORKERS", 1))
    uvicorn.run("dgic_service:app", host="0.0.0.0", port=DGIC_PORT,
                workers=workers, reload=False, access_log=True)
