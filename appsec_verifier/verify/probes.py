"""The probe interface the verification agent drives per finding.

A probe actively confirms or refutes exactly one finding against the running
target (VER-008) and returns a ProbeResult. No probe is implemented yet, so
`default_registry()` is empty and dynamically verifiable findings are reported
`not-attempted` (VER-024). Probes run through the injected, scope-confined HTTP
client and must honour `ProbeContext.safe` (VER-030) and `read_only` (VER-014).
Technical QA state is separate from proof, with correction allowances shared
across a finding's variants (VER-046). `PROOF_FORMS` says what each checked proof
form showed, for the console and the report (VER-013).
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
    poc: dict | None = None            # proof of concept recorded by the code (VER-034, verify/poc.py)
    planning: list[dict] = field(default_factory=list)
    evidence_review: dict | None = None  # presentation quality, never a technical verdict (VER-042)
    technical_review: dict | None = None  # independent technical objections, never proof (VER-046)


# What a checked proof showed, per proof form the check accepts (agent/proof.py, proof_form): a phrase for the
# console and a sentence for the report. One table, so that a new form is described wherever a proof is shown.
PROOF_FORMS = {
    "script-executed": ("script executed in the browser", "The injected script ran in the browser"),
    "listener-hit": ("the target called the Verifier's listener", "The target called the Verifier's listener"),
    "marker-redirect": ("redirect to the marker host", "The target redirected to the Verifier's marker host"),
    "marker-file": ("marker file read", "The response contained the content of the marker file"),
    "archive-marker": ("escaped archive entry read back",
                       "An entry of the uploaded archive escaped its directory and was read back with its marker"),
    "cookie-attribute": ("cookie attribute missing in repeated responses",
                         "The cookie attribute was missing in repeated responses"),
    "predicate": ("response follows fresh controls",
                  "The response followed the Verifier's fresh control values for the declared input"),
    "engine-error": ("engine error only for the syntax break",
                     "A syntax break in the declared input raised a backend engine error that its balanced "
                     "counterpart did not"),
    "returned-marker": ("the Verifier's marker returned for one control only",
                        "The answer returned the Verifier's marker for one control and not for its complement"),
    "computed-expression": ("fresh computed results returned",
                            "Each control's freshly computed result appeared in its own answer"),
    "out-of-band": ("the target sent the control's nonce to the listener",
                    "The target sent the control's nonce to the Verifier's listener, and not the complementary "
                    "control's"),
    "auth-artifact": ("true controls yielded an authenticated artifact",
                      "The true-predicate controls yielded an authenticated artifact; "
                      "the false ones and baseline did not"),
    "auth-resource": ("positive artifacts accessed the protected resource",
                      "Positive-control artifacts accessed the declared protected resource; baseline and negative "
                      "controls did not"),
    "selected-access": ("the declared protected observation matched across identities",
                        "The operator-declared protected field or text marker was accessible to a denied identity"),
    "declared-exposure": ("protected marker exposed in repeated anonymous reads",
                          "Two anonymous reads exposed the declared protected marker; "
                          "the neighbouring control did not"),
    "identity-contrast": ("access differs between identities", "Access differed between the identities"),
    "record-marker": ("another account read the owner's marked record",
                      "Another account read the record the owner created, with its marker"),
    "record-change": ("another account changed the owner's record",
                      "Another account changed the record the owner created"),
    "privileged-comparison": ("normal account got the privileged answer",
                              "A normal account got the same answer as the privileged account"),
    "comparison-without-credentials": ("same answer without credentials, unlike a random path",
                                       "Without credentials the request got the same answer as the signed-in "
                                       "account, unlike a random path next to it"),
}
# The form a result saved without one stands for: its class's usual proof.
DEFAULT_FORMS = {"xss": "script-executed", "ssrf": "listener-hit", "open-redirect": "marker-redirect",
                 "path-traversal": "marker-file", "session": "cookie-attribute", "injection": "predicate",
                 "access-control": "identity-contrast"}


def proof_shown(proof: dict | None, cls: str | None) -> tuple[str, str] | None:
    """What a checked proof showed, as (console phrase, report sentence), by the form the check accepted."""
    return PROOF_FORMS.get((proof or {}).get("form") or DEFAULT_FORMS.get(cls or "", ""))


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
    ask_writes: object | None = None   # VER-052: callable(requests, reason, identity) -> the operator's yes
    sessions: object | None = None     # SessionManager, or None offline
    source: object | None = None       # SourceReader (read-only target checkout), or None
    target_base: str = ""              # target base URL the agent's requests are joined to
    browser: object | None = None      # ProofBrowser for XSS (VER-009), or None when unavailable
    marker: tuple[str, str] = ("", "")  # per-finding marker parts: XSS joins them at runtime, open redirect
    #                                     uses <part0><part1>.invalid as its redirect host (agent/proof.py)
    listener: object | None = None     # CallbackListener for SSRF (VER-012), or None when unavailable
    log: object | None = None          # callable(record) for the action log (VER-017), or None
    evidence_dir: object | None = None  # Path of evidence/ for proof records (VER-022), or None offline
    progress: object | None = None     # RunProgress that shows each step on the console, or None
    responses: dict = field(default_factory=dict)  # bounded redacted responses, private to this finding
    agent_history: list[dict] = field(default_factory=list)  # recorded steps, never supplied by a model
    # step -> experiment as plan_test accepted it, unredacted; outside the history the planner reads (VER-016), for
    # the proof to compare the requests sent with it (VER-011)
    accepted_plans: dict = field(default_factory=dict)
    derived_requests: list[dict] = field(default_factory=list)  # checked provenance for related requests
    technical_review_budget: dict = field(default_factory=dict)  # shared by all variants (VER-046)
    created: set = field(default_factory=set)  # identifiers the owner's creating answers returned (VER-010)
    owned: set = field(default_factory=set)    # of those, the ones the owner's read showed with its marker
    prior_results: list[dict] = field(default_factory=list)
    evidence_test_planner: object | None = None
    evidence_reviewer_factory: object | None = None
    evidence_panels: list[dict] = field(default_factory=list)
    recapture: object | None = None   # another page for an unclear screenshot after a review issue (VER-042)
    represent: object | None = None   # the test agent's revised presentation after a review issue (VER-059)
    # VER-063: every model call of this finding as sent and answered (agent/hosts.py), and why a call failed or its
    # answer was unusable; only the debug file of a failed verification reads them (verify/failure_debug.py)
    model_exchanges: list[dict] = field(default_factory=list)
    model_failure: str | None = None
    # VER-024: the fixed reason of a failed model call that ended this finding, for the report's reason line
    model_call_failed: str | None = None


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
