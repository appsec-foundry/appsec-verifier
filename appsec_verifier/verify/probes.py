"""The probe interface the verification agent drives per finding.

A probe actively confirms or refutes exactly one finding against the running
target (VER-008) and returns a ProbeResult. No probe is implemented yet, so
`default_registry()` is empty and dynamically verifiable findings are reported
`not-attempted` (VER-024). Probes run through the injected, scope-confined HTTP
client and must honour `ProbeContext.safe` (VER-030) and `read_only` (VER-014).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..loader import FindingPlan


@dataclass
class ProbeResult:
    verdict: str  # confirmed | not-reproducible | blocked-by-control | inconclusive | not-attempted
    confidence: str | None = None      # high | medium | low
    rationale: str | None = None
    proof: dict | None = None
    identities_used: list[str] = field(default_factory=list)
    state_changes: list[dict] = field(default_factory=list)
    deviation: str | None = None
    observations: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    target_location: dict | None = None
    limits_hit: str | None = None


@dataclass
class ProbeContext:
    plan: FindingPlan
    scope: dict
    guard: object                      # ScopeGuard
    budget: object                     # RunBudget
    http: object | None                # GuardedHttpClient, or None when no transport is wired
    identities: list[dict]             # role dicts (no secret values)
    callback: dict
    safe: bool = True                  # VER-030: cautious by default
    read_only: bool = True             # VER-014: no state change unless explicitly allowed
    sessions: object | None = None     # SessionManager, or None offline
    source: object | None = None       # SourceReader (read-only target checkout), or None
    target_base: str = ""              # target base URL the agent's requests are joined to
    browser: object | None = None      # ProofBrowser for XSS (VER-009), or None when unavailable
    marker: tuple[str, str] = ("", "")  # per-finding XSS marker parts; only their runtime join counts
    log: object | None = None          # callable(record) for the action log (VER-017), or None
    evidence_dir: object | None = None  # Path of evidence/ for proof records (VER-022), or None offline


@runtime_checkable
class Probe(Protocol):
    cls: str                           # the verification class this probe handles

    def run(self, ctx: ProbeContext) -> ProbeResult: ...


class ProbeRegistry:
    """Maps a verification class to the probe that handles it."""

    def __init__(self, probes: dict[str, Probe] | None = None):
        self._probes: dict[str, Probe] = dict(probes or {})

    def register(self, probe: Probe) -> None:
        self._probes[probe.cls] = probe

    def get(self, cls: str | None) -> Probe | None:
        return self._probes.get(cls or "")

    def classes(self) -> set[str]:
        return set(self._probes)


def default_registry() -> ProbeRegistry:
    """No probes implemented yet — intentionally empty (VER-024)."""
    return ProbeRegistry()
