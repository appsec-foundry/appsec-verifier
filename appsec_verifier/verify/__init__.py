"""verify orchestration: selection → preflight → per-finding probe → report.

The probe layer is a typed interface with an (currently empty) registry, and the
HTTP transport is injected, so the whole flow runs and is tested offline. No
probe is implemented yet: dynamically verifiable findings are reported as
`not-attempted` with that reason (VER-024), never as refuted.
"""

from __future__ import annotations

from .probes import Probe, ProbeContext, ProbeRegistry, ProbeResult, default_registry
from .report import build_annotations, merge_reports, write_reports
from .runner import run_verification

__all__ = [
    "Probe", "ProbeContext", "ProbeRegistry", "ProbeResult", "default_registry",
    "run_verification", "write_reports", "build_annotations", "merge_reports",
]
