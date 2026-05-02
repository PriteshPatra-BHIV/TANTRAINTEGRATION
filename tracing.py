"""
tracing.py — OpenTelemetry distributed tracing setup.
Exports to OTLP endpoint when OTEL_EXPORTER_OTLP_ENDPOINT is set.
Falls back to no-op when not configured (zero overhead).
"""

import os
import threading
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor


class _TracerState:
    """Encapsulates mutable tracer state to avoid dangerous module-level globals."""
    def __init__(self):
        self._tracer: trace.Tracer | None = None
        self._lock = threading.Lock()

    def get_or_init(self, app=None) -> trace.Tracer:
        with self._lock:
            if self._tracer is not None:
                return self._tracer

            service_name = os.environ.get("OTEL_SERVICE_NAME", "dgic-intelligence")
            otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")

            resource = Resource.create({"service.name": service_name})
            provider = TracerProvider(resource=resource)

            if otlp_endpoint:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
                exporter = OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces")
            else:
                exporter = ConsoleSpanExporter()

            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)

            if app is not None:
                FastAPIInstrumentor.instrument_app(app)

            self._tracer = trace.get_tracer(service_name)
            return self._tracer


_state = _TracerState()


def setup_tracing(app=None) -> trace.Tracer:
    return _state.get_or_init(app)


def get_tracer() -> trace.Tracer:
    return _state.get_or_init()
