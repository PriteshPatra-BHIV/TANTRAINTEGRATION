"""
Phase 2: KSML Input Contract Enforcement
Ensures DGIC accepts ONLY structured input in exact format required by Sovereign Core
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from collections import deque
import uuid
import time
import hashlib
import json

class SignalType(Enum):
    """Valid signal types for DGIC"""
    THREAT = "THREAT"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"

class InputValidationError(Exception):
    """Raised when input validation fails"""
    pass

@dataclass
class KSMLSignal:
    """KSML-compliant signal structure"""
    id: str
    type: SignalType
    priority: float  # 0.0-1.0
    timestamp: int   # Unix epoch ms
    source: str
    metadata: Dict[str, Any]
    
    def __post_init__(self):
        """Validate signal after creation"""
        if not (0.0 <= self.priority <= 1.0):
            raise InputValidationError(f"Signal priority must be 0.0-1.0, got {self.priority}")
        
        if self.timestamp <= 0:
            raise InputValidationError(f"Signal timestamp must be positive, got {self.timestamp}")
        
        if not self.id or not isinstance(self.id, str):
            raise InputValidationError(f"Signal ID must be non-empty string, got {self.id}")
        
        if not self.source or not isinstance(self.source, str):
            raise InputValidationError(f"Signal source must be non-empty string, got {self.source}")

@dataclass
class KSMLInput:
    """KSML-compliant input structure for DGIC"""
    execution_id: str      # UUID v4
    timestamp: int         # Unix epoch ms
    signals: List[KSMLSignal]
    metadata: Dict[str, Any]
    
    def __post_init__(self):
        """Validate input after creation"""
        # Validate execution_id is UUID v4
        try:
            uuid_obj = uuid.UUID(self.execution_id, version=4)
            if str(uuid_obj) != self.execution_id:
                raise ValueError("Not a valid UUID v4")
        except ValueError as e:
            raise InputValidationError(f"execution_id must be valid UUID v4, got {self.execution_id}: {e}")
        
        # Validate timestamp
        if self.timestamp <= 0:
            raise InputValidationError(f"Timestamp must be positive, got {self.timestamp}")
        
        # Validate signals
        if not self.signals:
            raise InputValidationError("At least one signal is required")
        
        if len(self.signals) > 100:  # Reasonable limit
            raise InputValidationError(f"Too many signals (max 100), got {len(self.signals)}")

class KSMLInputValidator:
    """Validates and enforces KSML input contract"""
    
    def __init__(self):
        # Capped deques — prevent unbounded memory growth under sustained load
        self.validation_log: deque = deque(maxlen=1000)
        self.rejected_inputs: deque = deque(maxlen=1000)
        self.accepted_inputs: deque = deque(maxlen=1000)
    
    def validate_raw_input(self, raw_input: Dict[str, Any]) -> KSMLInput:
        """
        Validate raw input dict and convert to KSMLInput
        
        Args:
            raw_input: Raw input dictionary
            
        Returns:
            Validated KSMLInput object
            
        Raises:
            InputValidationError: If input is invalid
        """
        self._log_validation_attempt(raw_input)
        
        # Check required top-level fields
        required_fields = ["execution_id", "timestamp", "signals", "metadata"]
        for field in required_fields:
            if field not in raw_input:
                error = f"Missing required field: {field}"
                self._log_validation_failure(raw_input, error)
                raise InputValidationError(error)
        
        # Validate execution_id
        execution_id = raw_input["execution_id"]
        if not isinstance(execution_id, str):
            error = f"execution_id must be string, got {type(execution_id)}"
            self._log_validation_failure(raw_input, error)
            raise InputValidationError(error)
        
        # Validate timestamp
        timestamp = raw_input["timestamp"]
        if not isinstance(timestamp, int):
            error = f"timestamp must be int, got {type(timestamp)}"
            self._log_validation_failure(raw_input, error)
            raise InputValidationError(error)
        
        # Validate signals array
        signals_raw = raw_input["signals"]
        if not isinstance(signals_raw, list):
            error = f"signals must be list, got {type(signals_raw)}"
            self._log_validation_failure(raw_input, error)
            raise InputValidationError(error)
        
        # Validate metadata
        metadata = raw_input["metadata"]
        if not isinstance(metadata, dict):
            error = f"metadata must be dict, got {type(metadata)}"
            self._log_validation_failure(raw_input, error)
            raise InputValidationError(error)
        
        # Convert and validate signals
        validated_signals = []
        for i, signal_raw in enumerate(signals_raw):
            try:
                validated_signal = self._validate_signal(signal_raw, i)
                validated_signals.append(validated_signal)
            except InputValidationError as e:
                error = f"Signal {i} validation failed: {e}"
                self._log_validation_failure(raw_input, error)
                raise InputValidationError(error)
        
        # Create validated input
        try:
            ksml_input = KSMLInput(
                execution_id=execution_id,
                timestamp=timestamp,
                signals=validated_signals,
                metadata=metadata
            )
            
            self._log_validation_success(raw_input, ksml_input)
            return ksml_input
            
        except InputValidationError as e:
            self._log_validation_failure(raw_input, str(e))
            raise
    
    def _validate_signal(self, signal_raw: Dict[str, Any], index: int) -> KSMLSignal:
        """Validate individual signal"""
        if not isinstance(signal_raw, dict):
            raise InputValidationError(f"Signal must be dict, got {type(signal_raw)}")
        
        # Check required signal fields
        required_fields = ["id", "type", "priority", "timestamp", "source"]
        for field in required_fields:
            if field not in signal_raw:
                raise InputValidationError(f"Signal missing required field: {field}")
        
        # Validate signal type
        signal_type_raw = signal_raw["type"]
        try:
            signal_type = SignalType(signal_type_raw)
        except ValueError:
            valid_types = [t.value for t in SignalType]
            raise InputValidationError(f"Invalid signal type '{signal_type_raw}', must be one of: {valid_types}")
        
        # Validate priority
        priority = signal_raw["priority"]
        if not isinstance(priority, (int, float)):
            raise InputValidationError(f"Signal priority must be number, got {type(priority)}")
        
        # Validate timestamp
        timestamp = signal_raw["timestamp"]
        if not isinstance(timestamp, int):
            raise InputValidationError(f"Signal timestamp must be int, got {type(timestamp)}")
        
        # Validate source
        source = signal_raw["source"]
        if not isinstance(source, str) or not source.strip():
            raise InputValidationError(f"Signal source must be non-empty string, got {source}")
        
        # Get metadata (optional)
        metadata = signal_raw.get("metadata", {})
        if not isinstance(metadata, dict):
            raise InputValidationError(f"Signal metadata must be dict, got {type(metadata)}")
        
        return KSMLSignal(
            id=signal_raw["id"],
            type=signal_type,
            priority=float(priority),
            timestamp=timestamp,
            source=source,
            metadata=metadata
        )
    
    def _log_validation_attempt(self, raw_input: Dict[str, Any]):
        """Log validation attempt"""
        log_entry = {
            "timestamp": int(time.time() * 1000),
            "event": "validation_attempt",
            "input_hash": self._hash_input(raw_input),
            "input_size": len(str(raw_input))
        }
        self.validation_log.append(log_entry)
    
    def _log_validation_success(self, raw_input: Dict[str, Any], ksml_input: KSMLInput):
        """Log successful validation"""
        log_entry = {
            "timestamp": int(time.time() * 1000),
            "event": "validation_success",
            "execution_id": ksml_input.execution_id,
            "signal_count": len(ksml_input.signals),
            "input_hash": self._hash_input(raw_input)
        }
        self.validation_log.append(log_entry)
        self.accepted_inputs.append(ksml_input.execution_id)
    
    def _log_validation_failure(self, raw_input: Dict[str, Any], error: str):
        """Log validation failure"""
        log_entry = {
            "timestamp": int(time.time() * 1000),
            "event": "validation_failure",
            "error": error,
            "input_hash": self._hash_input(raw_input)
        }
        self.validation_log.append(log_entry)
        self.rejected_inputs.append(self._hash_input(raw_input))
    
    def _hash_input(self, raw_input: Dict[str, Any]) -> str:
        """Create hash of input for logging"""
        input_str = json.dumps(raw_input, sort_keys=True, default=str)
        return hashlib.sha256(input_str.encode()).hexdigest()[:16]
    
    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation statistics"""
        total_attempts = len([log for log in self.validation_log if log["event"] == "validation_attempt"])
        successful_validations = len(self.accepted_inputs)
        failed_validations = len(self.rejected_inputs)
        
        return {
            "total_validation_attempts": total_attempts,
            "successful_validations": successful_validations,
            "failed_validations": failed_validations,
            "success_rate": successful_validations / total_attempts if total_attempts > 0 else 0.0,
            "recent_failures": [
                log for log in self.validation_log[-10:] 
                if log["event"] == "validation_failure"
            ]
        }

class KSMLInputEnforcer:
    """Enforces KSML input contract for DGIC"""
    
    def __init__(self):
        self.validator = KSMLInputValidator()
        self.strict_mode = True  # Always enforce strict validation
    
    def enforce_input_contract(self, raw_input: Any) -> KSMLInput:
        """
        Enforce KSML input contract
        
        Args:
            raw_input: Raw input (must be dict)
            
        Returns:
            Validated KSMLInput object
            
        Raises:
            InputValidationError: If input violates contract
        """
        # Reject non-dict inputs immediately
        if not isinstance(raw_input, dict):
            raise InputValidationError(f"Input must be dict, got {type(raw_input)}")
        
        # Reject unstructured inputs
        if not raw_input:
            raise InputValidationError("Empty input not allowed")
        
        # Validate against KSML contract
        return self.validator.validate_raw_input(raw_input)
    
    def create_sample_input(self, execution_id: Optional[str] = None) -> Dict[str, Any]:
        """Create sample KSML-compliant input for testing"""
        if execution_id is None:
            execution_id = str(uuid.uuid4())
        
        current_time = int(time.time() * 1000)
        
        return {
            "execution_id": execution_id,
            "timestamp": current_time,
            "signals": [
                {
                    "id": "signal_001",
                    "type": "THREAT",
                    "priority": 0.8,
                    "timestamp": current_time,
                    "source": "security_sensor",
                    "metadata": {
                        "location": "perimeter",
                        "confidence": 0.85
                    }
                },
                {
                    "id": "signal_002", 
                    "type": "SAFE",
                    "priority": 0.3,
                    "timestamp": current_time - 1000,
                    "source": "status_monitor",
                    "metadata": {
                        "system": "normal",
                        "last_check": current_time - 5000
                    }
                }
            ],
            "metadata": {
                "source_system": "orchestrator",
                "processing_mode": "real_time",
                "priority_level": "high"
            }
        }
    
    def get_input_contract_spec(self) -> Dict[str, Any]:
        """Get KSML input contract specification"""
        return {
            "contract_version": "1.0.0",
            "required_fields": {
                "execution_id": {
                    "type": "string",
                    "format": "UUID v4",
                    "description": "Unique execution identifier"
                },
                "timestamp": {
                    "type": "integer",
                    "format": "Unix epoch milliseconds",
                    "description": "Request timestamp"
                },
                "signals": {
                    "type": "array",
                    "min_items": 1,
                    "max_items": 100,
                    "items": {
                        "type": "object",
                        "required_fields": ["id", "type", "priority", "timestamp", "source"],
                        "properties": {
                            "id": {"type": "string", "description": "Signal identifier"},
                            "type": {"type": "string", "enum": ["THREAT", "SAFE", "UNKNOWN"]},
                            "priority": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                            "timestamp": {"type": "integer", "format": "Unix epoch ms"},
                            "source": {"type": "string", "description": "Signal source"},
                            "metadata": {"type": "object", "description": "Optional metadata"}
                        }
                    }
                },
                "metadata": {
                    "type": "object",
                    "description": "Request metadata"
                }
            },
            "validation_rules": [
                "execution_id must be valid UUID v4",
                "timestamp must be positive integer",
                "signals array must contain 1-100 items",
                "signal priority must be 0.0-1.0",
                "signal type must be THREAT, SAFE, or UNKNOWN",
                "all string fields must be non-empty"
            ]
        }

# Global enforcer instance
ksml_input_enforcer = KSMLInputEnforcer()

def validate_ksml_input(raw_input: Any) -> KSMLInput:
    """Validate input against KSML contract"""
    return ksml_input_enforcer.enforce_input_contract(raw_input)

def get_input_contract() -> Dict[str, Any]:
    """Get KSML input contract specification"""
    return ksml_input_enforcer.get_input_contract_spec()

def create_sample_ksml_input() -> Dict[str, Any]:
    """Create sample KSML input for testing"""
    return ksml_input_enforcer.create_sample_input()

if __name__ == "__main__":
    # Demo KSML input validation
    print("=== KSML Input Contract Enforcement Demo ===")
    
    # Create sample input
    sample_input = create_sample_ksml_input()
    print(f"Sample input execution_id: {sample_input['execution_id']}")
    print(f"Sample input signals: {len(sample_input['signals'])}")
    
    # Test valid input
    try:
        validated = validate_ksml_input(sample_input)
        print(f"✓ Valid input accepted: {validated.execution_id}")
    except Exception as e:
        print(f"✗ Valid input rejected: {e}")
    
    # Test invalid input (missing field)
    try:
        invalid_input = sample_input.copy()
        del invalid_input["execution_id"]
        validate_ksml_input(invalid_input)
        print("✗ Invalid input accepted (ERROR!)")
    except InputValidationError as e:
        print(f"✓ Invalid input rejected: {str(e)[:50]}...")
    
    # Test unstructured input
    try:
        validate_ksml_input("unstructured string")
        print("✗ Unstructured input accepted (ERROR!)")
    except InputValidationError as e:
        print(f"✓ Unstructured input rejected: {str(e)[:50]}...")
    
    # Show validation stats
    stats = ksml_input_enforcer.validator.get_validation_stats()
    print(f"Validation stats: {stats['successful_validations']}/{stats['total_validation_attempts']} success rate: {stats['success_rate']:.2f}")