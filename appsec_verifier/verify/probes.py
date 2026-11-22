"""The probe interface the verification agent drives per finding.

A probe actively confirms or refutes exactly one finding against the running
target (VER-008) and returns a ProbeResult. No probe is implemented yet, so
`default_registry()` is empty and dynamically verifiable findings are reported
`not-attempted` (VER-024). Probes run through the injected, scope-confined HTTP
client and must honour `ProbeContext.safe` (VER-030) and `read_only` (VER-014).
Technical QA state is separate from proof, with correction allowances shared
across a finding's variants (VER-046). `PROOF_FORMS` says what each checked proof
form showed, for the console and the report (VER-013); `BECAUSE`, `WEAKNESS_NAMES`
and `PROOF_RULES` word the sentence that heads a finding's images and report entry
and why its proof holds (VER-035).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..loader import FindingPlan


@dataclass
class ProbeResult:
    # confirmed | shown-without-exploit (VER-066) | not-reproducible | blocked-by-control | inconclusive | not-attempted
    verdict: str
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
    "name-error": ("evaluation error only for the unknown names",
                   "Fresh unknown names in the declared input raised an evaluation error that names the language "
                   "knows did not"),
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
    "named-record": ("another account got the owner's record that names the owner",
                     "Another account got the owner's identical answer for a record that names the owner's user name"),
    "listed-record": ("another account got the record only the owner's list shows",
                      "Another account got the owner's identical answer for a record that only the owner's list of "
                      "the collection shows"),
    "privileged-comparison": ("normal account got the privileged answer",
                              "A normal account got the same answer as the privileged account"),
    "comparison-without-credentials": ("same answer without credentials, unlike a random path",
                                       "Without credentials the request got the same answer as the signed-in "
                                       "account, unlike a random path next to it"),
}
# Why each form's observation is a proof and not only a hint, in one sentence for the images and the report.
PROOF_RULES = {
    "script-executed": "The browser showed a dialog with the Verifier's random marker. Only a script that ran can "
                       "produce it; a payload that is merely reflected in the answer does not count.",
    "listener-hit": "The Verifier's listener received a request with this finding's marker, so the target called "
                    "an address the request chose.",
    "marker-redirect": "The Location of the redirect is a host name the Verifier generated for this finding, so the "
                       "target took the redirect target from the request.",
    "marker-file": "The answer holds the content of the operator's marker file, which the request must not be able "
                   "to read.",
    "archive-marker": "An entry of the uploaded archive was written outside its directory and read back with the "
                      "Verifier's marker.",
    "cookie-attribute": "The target set the session cookie without the attribute in repeated responses.",
    "predicate": "A server that reads the input as a plain value gives a true and a false condition the same "
                 "answer; here the answer followed whether the condition held. A slower answer alone never counts.",
    "engine-error": "Only the syntax break raised a backend engine error, its balanced counterpart did not, so "
                    "the backend parses the input as code.",
    "name-error": "Only the fresh names, which no code can know, raised an error; names the language always knows "
                  "did not, and an input that is only looked up treats all of them alike. So the backend evaluates "
                  "the input as code. No exploit ran, so this shows the weakness without confirming it.",
    "returned-marker": "The answer returned the marker the Verifier generated for one control and not for its "
                       "complement, so the injected statement ran.",
    "computed-expression": "Each answer holds the result of an expression the Verifier generated at random for it, "
                           "so the backend evaluated the input.",
    "out-of-band": "The Verifier's listener received the nonce of one control and not the complementary one's, so "
                   "the injected statement ran on the target.",
    "auth-artifact": "Only the true-predicate controls yielded an authenticated artifact; the false ones and the "
                     "normal input did not, so the input decides the login.",
    "auth-resource": "Only the artifacts of the positive controls reached the declared protected resource; those "
                     "of the normal input and the negative controls did not.",
    "selected-access": "The field or text marker the operator declared as protected reached an identity the "
                       "declaration denies.",
    "declared-exposure": "Two reads without credentials showed the marker the operator declared as protected; the "
                         "neighbouring control did not.",
    "identity-contrast": "The proof check compared the identities' answers on the cited steps and found the access "
                         "the finding describes.",
    "record-marker": "Another account read the record with the marker that only the owner's request had written.",
    "record-change": "The owner's read showed the second marker, which only the other account's write carried.",
    "named-record": "Another account got the owner's identical answer for a record that names the owner's user name "
                    "and not its own, while its own record names its own user name and a request without login did "
                    "not get the record.",
    "listed-record": "Another account got the owner's identical answer for a record that the owner's list of the "
                     "collection shows and its own list does not, while its own record answers differently and a "
                     "request without login did not get the record.",
    "privileged-comparison": "A normal account got the identical answer of the privileged account, while a request "
                             "without login was refused.",
    "comparison-without-credentials": "A request without credentials got the identical answer of the signed-in "
                                      "account, and a random path next to it did not.",
}
# Why a confirmed finding is the weakness, as the end of the sentence that heads its images and its report entry
# (VER-035): "<weakness> through <input>, because …". {input} is the tested input's name, {query} what it reaches.
BECAUSE = {
    "script-executed": "a script sent in the request ran in the browser",
    "listener-hit": "the target called the Verifier's listener at an address the request chose",
    "marker-redirect": "the target redirected to a host the request chose",
    "marker-file": "the answer holds the content of the operator's marker file",
    "archive-marker": "an entry of the uploaded archive was written outside its directory",
    "cookie-attribute": "the target set the session cookie without it in repeated responses",
    "predicate": "a condition added to {input} changes what {query} returns",
    "engine-error": "only a syntax break in {input} makes the backend fail with an engine error",
    "name-error": "only names no code can know make the backend fail when sent in {input}",
    "returned-marker": "a statement added to {input} returned the Verifier's marker",
    "computed-expression": "the answer holds the result of an expression sent in {input}",
    "out-of-band": "a statement added to {input} made the target call the Verifier's listener",
    "auth-artifact": "a true condition in {input} signs in and a false one does not",
    "auth-resource": "a true condition in {input} signs in and reaches the protected resource",
    "selected-access": "the field or text declared as protected reached an identity the declaration denies",
    "declared-exposure": "reads without credentials showed the marker declared as protected",
    "identity-contrast": "the identities' answers show the access the finding describes",
    "record-marker": "another account read the record the owner created",
    "record-change": "another account changed the record the owner created",
    "named-record": "another account read a record that names the owner",
    "listed-record": "another account read a record that only the owner's list shows",
    "privileged-comparison": "a normal account got the privileged account's answer",
    "comparison-without-credentials": "a request without credentials got the signed-in account's answer",
}
# The weakness as a short name for that sentence, per CWE of data/verifiable-cwes.yaml, else per class.
WEAKNESS_NAMES = {
    "CWE-79": "Cross-site scripting", "CWE-639": "Insecure direct object reference",
    "CWE-862": "Missing authorization", "CWE-863": "Incorrect authorization", "CWE-285": "Improper authorization",
    "CWE-306": "Missing authentication", "CWE-200": "Exposure of sensitive information",
    "CWE-497": "Exposure of system information", "CWE-530": "Exposed backup file",
    "CWE-538": "Sensitive information in an accessible file", "CWE-548": "Directory listing",
    "CWE-552": "Files accessible to outsiders", "CWE-89": "SQL injection", "CWE-943": "NoSQL injection",
    "CWE-22": "Path traversal", "CWE-23": "Relative path traversal", "CWE-73": "External control of a file path",
    "CWE-601": "Open redirect", "CWE-918": "Server-side request forgery", "CWE-614": "Session cookie without Secure",
    "CWE-1004": "Session cookie without HttpOnly", "CWE-1275": "Session cookie with improper SameSite",
    "CWE-78": "OS command injection", "CWE-1336": "Template injection", "CWE-94": "Code injection",
    "CWE-95": "Eval injection", "CWE-643": "XPath injection", "CWE-90": "LDAP injection",
}
CLASS_NAMES = {"xss": "Cross-site scripting", "access-control": "Broken access control", "injection": "Injection",
               "path-traversal": "Path traversal", "open-redirect": "Open redirect",
               "ssrf": "Server-side request forgery", "session": "Session cookie weakness"}
# What a condition in the input reaches, per CWE, for the predicate form's sentence; otherwise "the server".
QUERY_NOUNS = {"CWE-89": "the database query", "CWE-943": "the database query", "CWE-643": "the XPath query",
               "CWE-90": "the LDAP query"}
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
    assume_restrictions: bool = False  # VER-010: the restriction a comparison implies counts where none is declared
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
    variant_status: list[dict] = field(default_factory=list)  # bounded coverage summary, never another proof
    created: set = field(default_factory=set)  # identifiers the owner's creating answers returned (VER-010)
    owned: set = field(default_factory=set)    # of those, the ones the owner's read showed with its marker
    prior_results: list[dict] = field(default_factory=list)
    # VER-068: how an earlier run confirmed this finding variant (verify/earlier.py), a hint for the agent, never proof
    earlier_confirmation: dict | None = None
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
