"""
live_pipeline.py — DISABLED

DGIC is now a pure reasoning authority node.
Pipeline orchestration has been removed from DGIC's scope.
Mandala drives all downstream calls via dgic_adapter.py.

This file is import-guarded to prevent accidental use.
"""

raise ImportError(
    "live_pipeline is disabled. DGIC no longer owns pipeline orchestration. "
    "Use dgic_adapter.py to integrate DGIC as a Mandala authority node."
)
