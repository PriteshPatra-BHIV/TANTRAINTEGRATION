"""
Phase 3: Decision Contract Standardization
Ensures DGIC returns EXACT output format required by Sovereign Core system
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import hashlib
import time
import json
from logger import get_logger

_log = get_logger("decision_contract")

class DecisionType(Enum):
    """Standard decision types for Sovereign Core"""
    ESCALATE = "ESCALATE"
    PROCEED = "PROCEED"
    HOLD = "HOLD"
    REQUEST_MORE_DATA = "REQUEST_MORE_DATA"
    ERROR = "ERROR"

class EpistemicState(Enum):
    """Standard epistemic states"""
    HIGH_CONFIDENCE = "CERTAIN"
    AMBIGUOUS = "AMBIGUOUS"
    CONTRADICTORY = "CONTRADICTORY"
    INSUFFICIENT = "INSUFFICIENT"

class CollapseTrigger(Enum):
    """Standard collapse triggers"""
    DOMINANCE = "dominance"
    THRESHOLD = "threshold"
    TIMEOUT = "timeout"
    NONE = "none"

class DecisionContractError(Exception):
    """Raised when decision contract is violated"""
    pass

@dataclass
class StandardDecisionOutput:
    """Standard decision output structure for Sovereign Core"""
    execution_id: str           # Same UUID from input
    execution_hash: str         # SHA-256 hex string
    decision: DecisionType      # Standard decision enum
    epistemic_state: EpistemicState  # Epistemic state enum
    confidence: float           # 0.0-1.0
    reason_trace: List[str]     # Decision reasoning steps
    collapse_trigger: CollapseTrigger  # What triggered collapse
    timestamp: int              # Processing timestamp
    processing_time_ms: int     # Processing duration
    
    def __post_init__(self):
        """Validate decision output after creation"""
        if not (0.0 <= self.confidence <= 1.0):
            raise DecisionContractError(f"Confidence must be 0.0-1.0, got {self.confidence}")
        
        if not self.reason_trace:
            raise DecisionContractError("reason_trace cannot be empty")
        
        if self.processing_time_ms < 0:
            raise DecisionContractError(f"processing_time_ms must be non-negative, got {self.processing_time_ms}")

class DecisionContractStandardizer:
    """Standardizes DGIC output to exact Sovereign Core decision contract"""

    def __init__(self):
        self.contract_version = "1.0.0"
        self.decision_mappings = {
            "threat_detected": DecisionType.ESCALATE,
            "safe_confirmed": DecisionType.PROCEED,
            "ambiguous_signals": DecisionType.HOLD,
            "insufficient_data": DecisionType.REQUEST_MORE_DATA,
            "processing_error": DecisionType.ERROR,
        }
    
    def standardize_decision_output(
        self, 
        raw_intelligence: Dict[str, Any], 
        execution_id: str,
        input_timestamp: int
    ) -> StandardDecisionOutput:
        """
        Convert raw intelligence output to standard decision contract
        
        Args:
            raw_intelligence: Raw DGIC intelligence output
            execution_id: Execution ID from input
            input_timestamp: Original input timestamp
            
        Returns:
            Standardized decision output
            
        Raises:
            DecisionContractError: If standardization fails
        """
        start_time = time.time()

        # Let all exceptions propagate — no silent swallow.
        # dgic_service.py catches DecisionContractError and returns HTTP 500.
        decision = self._extract_decision(raw_intelligence)
        epistemic_state = self._extract_epistemic_state(raw_intelligence)
        confidence = self._extract_confidence(raw_intelligence)
        reason_trace = self._generate_reason_trace(raw_intelligence)
        collapse_trigger = self._determine_collapse_trigger(raw_intelligence)
        processing_time_ms = int((time.time() - start_time) * 1000)

        # Build the partial payload (execution_hash placeholder = "") so the
        # hash covers the exact same fields that dgic_contract_validator checks.
        partial: Dict[str, Any] = {
            "execution_id":    execution_id,
            "execution_hash":  "",
            "decision":        decision.value,
            "epistemic_state": epistemic_state.value,
            "confidence":      float(confidence),
            "reason_trace":    reason_trace,
            "collapse_trigger": collapse_trigger.value,
        }
        execution_hash = self._generate_execution_hash(
            execution_id, raw_intelligence, input_timestamp,
            _partial_payload=partial,
        )

        standardized = StandardDecisionOutput(
            execution_id=execution_id,
            execution_hash=execution_hash,
            decision=decision,
            epistemic_state=epistemic_state,
            confidence=confidence,
            reason_trace=reason_trace,
            collapse_trigger=collapse_trigger,
            timestamp=int(time.time() * 1000),
            processing_time_ms=processing_time_ms,
        )

        self._log_standardization_success(execution_id, decision, epistemic_state)
        return standardized
    
    def _extract_decision(self, intelligence: Dict[str, Any]) -> DecisionType:
        """Extract decision from intelligence output"""
        
        # Check for explicit decision
        if "decision" in intelligence:
            decision_str = intelligence["decision"]
            try:
                return DecisionType(decision_str)
            except ValueError:
                pass
        
        # Analyze interpretations to infer decision
        interpretations = intelligence.get("interpretations", [])
        if not interpretations:
            return DecisionType.REQUEST_MORE_DATA
        
        # Get primary interpretation
        primary = interpretations[0] if interpretations else {}
        hypothesis = primary.get("hypothesis", "").upper()
        
        # Map hypothesis to decision
        if "THREAT" in hypothesis or "DANGER" in hypothesis:
            return DecisionType.ESCALATE
        elif "SAFE" in hypothesis or "NORMAL" in hypothesis:
            return DecisionType.PROCEED
        elif "AMBIGUOUS" in hypothesis or "UNCLEAR" in hypothesis:
            return DecisionType.HOLD
        elif "INSUFFICIENT" in hypothesis or "INCOMPLETE" in hypothesis:
            return DecisionType.REQUEST_MORE_DATA
        else:
            # Default based on confidence
            confidence = primary.get("confidence_estimate", {}).get("mean", 0.5)
            if confidence > 0.8:
                return DecisionType.PROCEED
            elif confidence < 0.3:
                return DecisionType.ESCALATE
            else:
                return DecisionType.HOLD
    
    def _extract_epistemic_state(self, intelligence: Dict[str, Any]) -> EpistemicState:
        """Extract epistemic state from intelligence output"""
        
        # Check for explicit epistemic state
        if "epistemic_state" in intelligence:
            state_str = intelligence["epistemic_state"]
            try:
                return EpistemicState(state_str)
            except ValueError:
                pass
        
        # Analyze uncertainty to determine state
        uncertainty = intelligence.get("uncertainty", {})
        interpretations = intelligence.get("interpretations", [])
        
        # Check for contradictions
        if len(interpretations) > 1:
            confidences = [
                interp.get("confidence_estimate", {}).get("mean", 0.5)
                for interp in interpretations
            ]
            if max(confidences) - min(confidences) > 0.5:
                return EpistemicState.CONTRADICTORY
        
        # Check for ambiguity
        ambiguities = uncertainty.get("ambiguities", [])
        if ambiguities:
            return EpistemicState.AMBIGUOUS
        
        # Check for insufficient data
        unknowns = uncertainty.get("unknowns", [])
        if unknowns or len(interpretations) == 0:
            return EpistemicState.INSUFFICIENT
        
        # Default to certain if high confidence
        if interpretations:
            primary_confidence = interpretations[0].get("confidence_estimate", {}).get("mean", 0.5)
            if primary_confidence > 0.8:
                return EpistemicState.HIGH_CONFIDENCE
        
        return EpistemicState.AMBIGUOUS
    
    def _extract_confidence(self, intelligence: Dict[str, Any]) -> float:
        """Extract overall confidence from intelligence output"""
        
        # Check for explicit confidence
        if "confidence" in intelligence:
            conf = intelligence["confidence"]
            if isinstance(conf, (int, float)) and 0.0 <= conf <= 1.0:
                return float(conf)
        
        # Calculate from interpretations
        interpretations = intelligence.get("interpretations", [])
        if interpretations:
            confidences = []
            for interp in interpretations:
                conf_est = interp.get("confidence_estimate", {})
                mean_conf = conf_est.get("mean", 0.5)
                if isinstance(mean_conf, (int, float)):
                    confidences.append(float(mean_conf))
            
            if confidences:
                return sum(confidences) / len(confidences)
        
        # Default confidence
        return 0.5
    
    def _generate_reason_trace(self, intelligence: Dict[str, Any]) -> List[str]:
        """Generate reasoning trace from intelligence output"""
        
        trace = []
        
        # Add signal analysis
        signals = intelligence.get("signals", [])
        if signals:
            trace.append(f"Analyzed {len(signals)} input signals")
            
            # Add signal summary
            signal_types = {}
            for signal in signals:
                sig_type = signal.get("type", "unknown")
                signal_types[sig_type] = signal_types.get(sig_type, 0) + 1
            
            for sig_type, count in signal_types.items():
                trace.append(f"Found {count} {sig_type} signals")
        
        # Add interpretation analysis
        interpretations = intelligence.get("interpretations", [])
        for i, interp in enumerate(interpretations):
            hypothesis = interp.get("hypothesis", f"H-{i}")
            description = interp.get("description", "No description")
            confidence = interp.get("confidence_estimate", {}).get("mean", 0.5)
            trace.append(f"{hypothesis}: {description} (confidence: {confidence:.2f})")
        
        # Add uncertainty analysis
        uncertainty = intelligence.get("uncertainty", {})
        if uncertainty.get("ambiguities"):
            trace.append(f"Identified {len(uncertainty['ambiguities'])} ambiguities")
        if uncertainty.get("unknowns"):
            trace.append(f"Identified {len(uncertainty['unknowns'])} unknowns")
        
        # Ensure trace is not empty
        if not trace:
            trace.append("No detailed reasoning available")
        
        return trace
    
    def _determine_collapse_trigger(self, intelligence: Dict[str, Any]) -> CollapseTrigger:
        """Determine what triggered epistemic collapse"""
        
        interpretations = intelligence.get("interpretations", [])
        
        # Check for dominance (one interpretation much stronger)
        if len(interpretations) > 1:
            confidences = [
                interp.get("confidence_estimate", {}).get("mean", 0.5)
                for interp in interpretations
            ]
            max_conf = max(confidences)
            if max_conf > 0.8 and max_conf - min(confidences) > 0.4:
                return CollapseTrigger.DOMINANCE
        
        # Check for threshold crossing
        if interpretations:
            primary_conf = interpretations[0].get("confidence_estimate", {}).get("mean", 0.5)
            if primary_conf > 0.75 or primary_conf < 0.25:
                return CollapseTrigger.THRESHOLD
        
        # Check for timeout (processing time limit)
        # This would be set by the calling system
        
        # Default to none if no clear trigger
        return CollapseTrigger.NONE
    
    def _generate_execution_hash(
        self,
        execution_id: str,
        intelligence: Dict[str, Any],
        input_timestamp: int,
        *,
        _partial_payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        """SHA-256 over canonical JSON of the full output payload (execution_hash excluded).

        Matches dgic_contract_validator._recompute_hash() exactly so RAJYA can verify.
        """
        # _partial_payload is injected by standardize_decision_output after all
        # fields are known; we fall back to a deterministic summary only when
        # called before the payload is assembled (should not happen in practice).
        if _partial_payload is not None:
            hashable = {k: v for k, v in _partial_payload.items() if k != "execution_hash"}
        else:
            hashable = {
                "execution_id": execution_id,
                "input_timestamp": input_timestamp,
                "intelligence_summary": {
                    "interpretations_count": len(intelligence.get("interpretations", [])),
                    "signals_count": len(intelligence.get("signals", [])),
                    "uncertainty_keys": sorted(intelligence.get("uncertainty", {}).keys()),
                },
            }
        canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    
    def _log_standardization_success(self, execution_id: str, decision: DecisionType, state: EpistemicState):
        _log.info("standardization_success execution_id=%s decision=%s state=%s",
                  execution_id, decision.value, state.value)

    def _log_standardization_failure(self, execution_id: str, error: str):
        _log.error("standardization_failure execution_id=%s error=%s", execution_id, error)

    def get_standardization_stats(self) -> Dict[str, Any]:
        """Kept for interface compatibility."""
        return {"note": "stats available via structured logs"}

    def get_decision_contract_spec(self) -> Dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "required_fields": {
                "execution_id": {"type": "string", "format": "UUID v4"},
                "execution_hash": {"type": "string", "format": "SHA-256 hex"},
                "decision": {"type": "string", "enum": [d.value for d in DecisionType]},
                "epistemic_state": {"type": "string", "enum": [s.value for s in EpistemicState]},
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "reason_trace": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "collapse_trigger": {"type": "string", "enum": [t.value for t in CollapseTrigger]},
                "timestamp": {"type": "integer"},
                "processing_time_ms": {"type": "integer", "minimum": 0},
            },
            "decision_mappings": {
                "ESCALATE": "High threat or contradictory signals",
                "PROCEED": "Safe conditions confirmed",
                "HOLD": "Ambiguous signals require review",
                "REQUEST_MORE_DATA": "Insufficient information",
                "ERROR": "Processing or validation error",
            },
        }

# Global standardizer instance
decision_contract_standardizer = DecisionContractStandardizer()

def standardize_decision_output(
    raw_intelligence: Dict[str, Any], 
    execution_id: str, 
    input_timestamp: int
) -> StandardDecisionOutput:
    """Standardize intelligence output to decision contract"""
    return decision_contract_standardizer.standardize_decision_output(
        raw_intelligence, execution_id, input_timestamp
    )

def get_decision_contract() -> Dict[str, Any]:
    return decision_contract_standardizer.get_decision_contract_spec()


def convert_to_dict(decision_output: StandardDecisionOutput) -> Dict[str, Any]:
    """Convert StandardDecisionOutput to dictionary"""
    return {
        "execution_id": decision_output.execution_id,
        "execution_hash": decision_output.execution_hash,
        "decision": decision_output.decision.value,
        "epistemic_state": decision_output.epistemic_state.value,
        "confidence": decision_output.confidence,
        "reason_trace": decision_output.reason_trace,
        "collapse_trigger": decision_output.collapse_trigger.value,
        "timestamp": decision_output.timestamp,
        "processing_time_ms": decision_output.processing_time_ms
    }

if __name__ == "__main__":
    # Demo decision contract standardization
    print("=== Decision Contract Standardization Demo ===")
    
    # Sample intelligence output
    sample_intelligence = {
        "signals": [
            {"signal_id": "S1", "type": "THREAT", "confidence": 0.8},
            {"signal_id": "S2", "type": "SAFE", "confidence": 0.3}
        ],
        "interpretations": [
            {
                "hypothesis": "H-THREAT",
                "description": "Potential security threat detected",
                "confidence_estimate": {"mean": 0.75, "uncertainty": 0.2}
            }
        ],
        "uncertainty": {
            "ambiguities": ["Signal confidence varies significantly"],
            "unknowns": []
        }
    }
    
    # Standardize output
    execution_id = "550e8400-e29b-41d4-a716-446655440000"
    input_timestamp = int(time.time() * 1000)
    
    standardized = standardize_decision_output(sample_intelligence, execution_id, input_timestamp)
    
    print(f"Execution ID: {standardized.execution_id}")
    print(f"Decision: {standardized.decision.value}")
    print(f"Epistemic State: {standardized.epistemic_state.value}")
    print(f"Confidence: {standardized.confidence}")
    print(f"Reason Trace: {len(standardized.reason_trace)} steps")
    print(f"Collapse Trigger: {standardized.collapse_trigger.value}")
    print(f"Execution Hash: {standardized.execution_hash[:16]}...")
    
    # Show contract specification
    contract = get_decision_contract()
    print(f"Contract Version: {contract['contract_version']}")
    print(f"Required Fields: {len(contract['required_fields'])}")
    print(f"Decision Types: {len(contract['decision_mappings'])}")