# Requirements for AppSec Verifier

AppSec Verifier takes the findings of a static security assessment and tries to
**prove or disprove each one against the running application**. Where AppSec
Analyzer reasons about source code, the Verifier interacts with a live target:
it reproduces a finding with a safe, marked probe, observes the application's
real behaviour, and records whether the weakness is confirmed, not reproducible,
or blocked by a control that the static view could not see.

It reads a finished `security-assessment.yaml`, verifies one finding at a time
against a target the operator is authorised to test, and writes its own report.
It never re-runs the static analysis, never changes the Analyzer's rating, and
rates after verification only the findings it actively tested (VER-039).

**Non-goals.** The Verifier is not a scanner and not a pentest agent. It does
not crawl for new weaknesses, does not chain exploits for impact, and does not
try to extract real data, escalate privileges for their own sake, or damage the
target. It confirms or refutes the specific findings it is given.

**Authorisation.** Running the Verifier against a system is an active security
test. It acts only against targets for which the operator has supplied an
explicit, confirmed authorisation scope (see *Target the right system*). These
authorisation, scope, secret-handling, and bounded-execution requirements follow
the AI Secure Coding Baseline (aiscb); they are controls on a dual-use tool, not
optional hardening.

---

## Target the right system

- **VER-001: Require an explicit authorisation scope.** Every run names its scope: a scope file, or the target URL alone. A scope file lists the authorised target (base URL, hosts, allowed ports, allowed path prefixes), an authorisation window (from/until), and a responsible owner; it is needed for anything beyond a single host. The URL alone authorises only its scheme, host and port, for that run; write requests follow VER-030. The Verifier contacts only destinations inside the scope. Anything outside it — a different host, port, scheme, or path prefix, or a time outside the window — is refused, not attempted. There is no implicit or default target.

- **VER-002: Confirm before the first request.** Before it sends anything to the
  target, the Verifier prints the resolved scope (target, ports, path prefixes,
  window, owner) and asks for one explicit confirmation. Silence, a timeout, or
  an unrelated answer does not count as confirmation; Enter confirms only in
  the guided run (VER-031), whose prompt shows yes as the default. In
  non-interactive or CI use, a single explicit flag stands in for the prompt
  and is recorded in the report; nothing else suppresses the question.

- **VER-003: Verify the target before testing.** The Verifier first checks that
  the target is reachable and, where possible, that its version or commit matches
  the assessment it is verifying. If they diverge, it records the mismatch and
  continues only after the operator confirms, because a finding verified against
  the wrong build proves nothing. Starting, resetting, or provisioning the target
  application is out of scope; the operator supplies a running URL.

- **VER-004: Keep the operator in control of the target boundary.** The target
  URL, the scope file, and any session credentials come from the operator per
  run. The Verifier does not read them from the assessment, from the target, or
  from the network, and it does not widen the scope on anything the target or a
  model says during a run.

## Read the assessment

- **VER-005: Consume the assessment as untrusted input.** The input is a validated `security-assessment.yaml`. The Verifier reads the fields it needs from each `threats[]` entry — identifier, title, `cwe`, `evidence` file and line, `scenario`, and the finding's `verification` hint — and validates their types and values before use. Invalid assessment structure or field types block the run. Missing exploit instructions do not make a finding untestable. The agent may derive and validate missing test details from relevant source and observed application behaviour; assumptions remain explicit and never supply authorisation. Additional fields the Verifier does not use are ignored.

- **VER-026: Let the operator choose what to verify.** From the referenced
  assessment the operator selects which findings to verify — by weakness class,
  by severity (a floor or an explicit set), by CWE, or by finding id — and the
  Verifier tests only that selection. In interactive mode the selection and the
  resulting count are shown for confirmation before any request; in
  non-interactive mode the selection comes entirely from the invocation. An empty
  selection is reported, not silently treated as "verify everything".
  Findings the Verifier can confirm cheaply, XSS and SQL or NoSQL injection whose request the assessment names and a read can send, form the category `quick`. A severity selection also tests them whatever their severity, marked as added in the test plan; `--strict-severity` leaves them out, and `--category quick` selects them alone.
  Findings are tested most severe first, with prerequisites before the findings that depend on them; within one severity, findings whose request the assessment names and that need no write come first. Within a finding, variants that need no write come before those that do, so a confirmation without a write leaves the others untested (VER-039, VER-052). A run stopped by a limit has spent its budget on the highest-severity findings it could reach.

- **VER-006: Select only verifiable finding classes.** A finding is eligible for
  active verification only when its weakness can be probed against a running
  system and its CWE is on a supported positive list. Static-only findings — a
  weak PRNG choice, a hard-coded secret literal, an insecure practice with no
  runtime effect — are outside dynamic verification. A missing CWE catalog entry
  is reported as unsupported, not as proof that a finding is static-only.
  Unsupported findings have a short reason and are not marked unconfirmed. Version 1 supports:
  - **Cross-site scripting** (CWE-79): reflected, stored, and DOM-based.
  - **Broken access control / IDOR** (CWE-639, CWE-862, CWE-863, CWE-285): missing object- and function-level authorisation.
  - **Injection** (CWE-89 SQL, CWE-943 NoSQL, CWE-78 command, CWE-94 and CWE-95 code evaluation, CWE-1336 template, CWE-643 XPath, CWE-90 LDAP): mechanism-specific harmless controls.
    NoSQL uses JSON operator controls, also as bracket notation in a query parameter (`q[$eq]=…`), or, where the input is spliced into a server-side JavaScript predicate such as `$where`, complementary predicate controls; LDAP uses complementary filter predicates.
  - **Authentication and exposure** (CWE-306, CWE-200, CWE-497, CWE-530, CWE-538, CWE-548, CWE-552): operator-declared harmless protected resources with an independent allowed/denied contrast, or for a read the comparison of VER-057.
  - **Session-cookie attributes** (CWE-614, CWE-1004, CWE-1275): repeated
    observations of an operator-identified session cookie, without cookie values.
  - **Path traversal, open redirect, SSRF** (CWE-22, CWE-23, CWE-73, CWE-601, CWE-918): confirmed through harmless marker files or operator-controlled callbacks.

- **VER-007: Preserve the link to the finding.** Each verification result carries
  the finding's identifier and a cross-run stable key, so a result can be traced
  back to exactly one finding in the source assessment and matched again after
  the assessment is re-generated. The stable key is the one the Analyzer uses for
  its own deltas — `<normalized-file>|<cwe-family>` — which the Verifier
  recomputes from the finding's evidence file and CWE, not the display
  fingerprint `component|cwe|title` that the Analyzer treats as drifting. When a
  finding has several locations, the result also records the `file:line` it
  tested, so two findings that share a key stay distinct.

## Verify findings with evidence

- **VER-008: Verify the finding and its necessary preparation.** The Verifier may investigate the affected function, resource and data flow to establish a finding, including related preparation and observation requests not listed in the assessment. Each derived request must have recorded supporting evidence and pass checks outside the model for its relationship to the finding and the authorised scope. Unrelated weaknesses remain unverified observations and are not pursued. Before contacting the target it shows which findings it will test and with which requests, as far as the assessment names them. With a source checkout, a route that another file registers for a handler of the finding's file can supply the finding's request when the assessment names none; the plan shows where it came from. A finding the run cannot confirm, because its proof needs what the run lacks (VER-009 to VER-012) or every request it names writes in safe mode or needs a login without a test identity, is not tested unless the operator asks; the plan names what is missing, the report the reason. Optional versioned analysis context preserves source-cited input processing, controls, hypotheses and unknowns per variant. Missing capabilities never count as a negative test. Before testing, the operator can distinguish missing information and preparation from unsupported proof methods. For access-control tests, the Verifier considers evidenced requests for creating and reading its own test resources and shows the preparation before execution. Unsupported weaknesses are not automatically classified as static-only; ambiguous resource relationships remain unresolved, and scope, write permission and proof requirements still apply (VER-001, VER-010, VER-030).

- **VER-043: Leave the attack path to the test agent.** Within VER-008, the agent may develop hypotheses and adapt payloads, input representations, request order and supported proof methods to observed behaviour without a prescribed exploit recipe. Assessment variants guide investigation rather than exhaust the permitted approaches; operator-declared restrictions and the evidence requirements of VER-009 to VER-013 remain binding. No test plan is required. A confirmation counts when recorded steps meet the proof of their class (VER-009 to VER-012); the agent declares only what the Verifier needs to generate controls or a marker (VER-010, VER-011). The Verifier tells the agent when the recorded steps already meet the proof. When a proof check fails, the agent is told which step is missing or must be repeated.

- **VER-047: Obtain a finding's prerequisite reads.** Within VER-008, where a finding's own request cannot proceed without a preceding harmless read the assessment does not name — a CSRF token, a CAPTCHA identifier, a nonce the same operation issues — the agent may issue that read as a GET on the target origin and within scope, and use its response only to complete the finding's request. A prerequisite read is never the operation under test and never a proof (VER-009 to VER-013); it stays read-only in any mode (VER-030), is marked and logged (VER-014), counts against the run's budgets with a finite per-finding allowance (VER-036), and a finding whose prerequisite cannot be obtained is reported as untested, not failed. The plan names a prerequisite request where the finding implies one.

- **VER-056: Find the request of a page script by its file path.** Where the assessment names no request and the source declares no route for the finding (VER-008), a finding in a directly served script or page, such as a `.php` or `.jsp` file, can take its request from its file path below the web root: the file itself and up to two directories above it. The test agent may read these candidate pages with a GET as one of the run's identities, at most three per finding and recorded like a prerequisite read (VER-047). A candidate supplies the finding's request when its recorded answer is successful and it is the evidence file itself, or it holds a form or link that points into its own directory and carries an input whose name the evidence file contains as a literal; that form or link then names the request. No other link is followed, and scope, mode and proof rules apply unchanged.

- **VER-050: Locate source files without guessing.** With a source checkout, the agent can search the repository for files whose name or path contains a given substring, before reading one, so it does not spend steps guessing paths. It can also search file contents for a literal string and gets the matching paths and line numbers with the matching line. Both searches are read-only and confined to the repository, exclude credential, key and VCS files and heavy vendor directories, return a bounded answer (VER-016, VER-017), and count against the run's budgets (VER-036).

- **VER-051: Bound what one finding may spend.** A single finding's model spend is capped at a share of the run's cost ceiling, never below a floor, so one finding cannot drain the budget before later findings are reached (VER-015, VER-036). Reaching the cap stops that finding as inconclusive and the run continues with the next; it does not end the run. The share and floor are configurable, and the cap is off when the run has no cost ceiling. It bounds runaway spend and spreads the budget; it does not by itself make a small budget enough to test every finding.

- **VER-009: Require real execution as proof of XSS.** An XSS finding counts as confirmed only when a unique, harmless marker payload actually executes in a real headless browser against the target, proven by the triggered event. The page's requests and responses are recorded with it (VER-034); screenshots are provided under the conditions of VER-035. A payload merely reflected unencoded in an HTTP response is recorded as *indicative, not executed*, never as confirmed, so DOM handling and sanitisers are not mistaken for exploitable output. When the marker does not execute but the browser check finds a part of it in an injected script element or event-handler attribute, not in inert text or a plain attribute value, that is recorded as *indicative: breaks HTML context*, a stronger signal than plain reflection yet still not a confirmation.

- **VER-010: Prove access-control findings by comparison.** An IDOR or missing-authorisation finding is confirmed by showing that identity A can perform or read something that belongs to identity B, or that an unauthenticated caller reaches a protected operation. This requires at least two independent test identities (see VER-016). The result records which identity saw what, with the requests and responses as evidence. A single successful request without the cross-identity contrast is not sufficient. The operator can declare the known harmless resource, expected marker, allowed and denied roles; a declared resource takes precedence. Without one, given two normal accounts and intrusive mode (VER-030), the Verifier creates the resource: the owning account writes a random marker and reads it back, an unauthenticated read must not show it, and the other account's read decides. If the finding's request changes a record, the other account then writes a second random marker to the created resource, addressed by the identifier its creation returned, and the owner's next read decides: the second marker confirms, the first alone after a 403 or 404 gives blocked-by-control. The proofs using a resource created by the Verifier count at medium confidence (VER-013). For a finding that identifies a function as privileged, matching responses for independent normal and privileged accounts, with anonymous access refused, confirm the observed access at medium confidence. The report states that the intended restriction comes from the finding unless an operator-declared test resource establishes it; the response comparison does not establish that restriction independently. Different role labels backed by the same credentials do not establish independent identities.

- **VER-057: Prove access without credentials by comparison.** An access-control finding other than an IDOR (VER-006), whose request is a read and that has no operator-declared resource, is confirmed at medium confidence when the Verifier sends that request as an account of the run, without credentials, and without credentials to a random path next to it, and the request without credentials receives a successful answer identical to the account's while the random path does not. The answers are compared in code; their content reaches neither the model nor the evidence and screenshots. As in VER-010, the report states that the intended restriction comes from the finding. Answers that change between requests leave the finding inconclusive.

- **VER-011: Prove injection without exfiltration.** Injection findings are
  confirmed through controlled, observable behavioural differences — a boolean
  condition flipping a response, or a bounded, clearly-marked timing difference —
  not by dumping database contents. The Verifier never attempts to read, copy, or
  exfiltrate real application data to prove a point. The agent names the input,
  the observation and a template for the injected value; the Verifier generates
  the controls from it, sends a read-only experiment at once and reports whether
  the proof holds. A read plan whose controls the agent chose itself runs the same way; such controls can support a negative result, never a confirmation, and the Verifier tells the agent so. The declaration may also fix values for the request's other
  inputs, such as the password next to a login's user name; every control carries
  the same values, and only the declared input differs. The declaration may carry up to three candidate templates; the
  Verifier uses the first whose controls the target answers without a server
  error. The test agent chooses
  that input — a query parameter or JSON field of a read request the finding
  names, or an evidenced path segment (VER-044) — unless a scope file declares
  it; the report names the input the proof treated as literal data. Injection
  carried only by a write request is proven only in intrusive mode (VER-030).
  There the Verifier sends the declared controls in one step when the agent asks
  for it, each control at most twice, and stops at the first control that fails;
  it never sends them unasked. The agent selects the observation that fits the finding — a
  response field, the presence or emptiness of a result set, a count, or another
  recorded signal — and the method to reach it; the engine fixes what counts as
  proof, not how. A confirmation requires the fresh complementary controls to
  partition the repeated, recorded responses into two stable classes driven only
  by the declared input and not merely reflecting it. A result that only varies
  with the input, without the true/false controls deciding the class, is not such
  a contrast, and the true class need not reproduce an uninjected baseline. Timing needs alternating independent controls with
  identical responses and repeated separations of 2–5 seconds, but timing alone
  remains inconclusive because ordinary computation can cause the same effect.
  SQL confirmation requires fresh complementary predicate controls. NoSQL confirmation in a server-side JavaScript predicate requires fresh complementary predicates joined with AND to an input that finds a record, so the true control repeats the baseline and the false one suppresses it. The NoSQL operator controls may travel as bracket notation in a query parameter where the target builds an object from it. Command,
  code-evaluation, template and XPath confirmation requires fresh computed
  arithmetic results. Injection that surfaces no response difference may instead
  be confirmed by an out-of-band callback (VER-048), and injection whose effect
  is authenticated state by the artifact it yields (VER-049).

- **VER-044: Verify injection through path inputs.** Operators can verify injection in an evidenced path parameter using repeatable, harmless controls and a stable response-field or text contrast (VER-055); scope and input encoding remain enforced.

- **VER-048: Prove blind injection by out-of-band callback.** An injection that surfaces no response difference may be confirmed when a control the agent declares makes the target send a unique nonce to the Verifier's loopback callback listener, correlated to that control and absent for a complementary control (VER-011). Only the nonce returns; no application data is read or exfiltrated. The listener stays loopback-only and is never the Verifier's own target, and an injection payload is steered only at it, like SSRF (VER-012). In a standard run the carrier is a code-evaluation or template injection context, where no response-side proof exists; SQL, NoSQL and XPath keep their response-side forms, and command execution as the carrier is out of scope.

- **VER-049: Prove injection that yields authenticated state.** An injection whose effect is an authentication or authorization change, such as a login-bypass SQL or NoSQL injection, is confirmed when the positive control yields an authenticated artifact, a session or an authenticated identity, that the baseline and negative controls do not, stable across repeats and driven only by the declared input (VER-011). The artifact's presence is the observation; its value is never read, logged, or shown (VER-016). The uniform-status requirement of the response-field form does not apply. Confidence is medium (VER-013).

- **VER-053: Prove injection by a returned marker or a triggering engine error.** An injection may be confirmed when a control the agent declares makes the target return a unique marker the Verifier generates — a constant it chose, never application data — present for that control and absent for a complementary one, or when the Verifier sends a small per-class set of syntax-breaking metacharacters, each paired with a balanced counterpart, and at least one break raises a backend engine error (a SQL, NoSQL, XPath or template-engine parser error) its counterpart does not, stable across repeats and driven only by the declared input (VER-011). The marker form fits where the context returns a chosen value in its results (SQL); the engine-error form covers SQL, XPath, NoSQL, template and code-evaluation injection. LDAP keeps its result-set contrast (VER-011), since a malformed filter usually returns empty rather than an error, and command execution stays out of scope. The Verifier owns the metacharacter set and never injects a payload that selects a real column or row; only its own marker and the engine-error class are matched, in code. The triggering error message, when one occurs, is recorded as owner-only evidence with credential values redacted, to show the operator that the input reached the interpreter; it never reaches the model (VER-016). Metacharacter sets per class are in docs/cli.md. Confidence matches the response-field contrast (VER-013).

- **VER-054: Probe control characters before other injection forms.** For a finding whose class the engine-error form (VER-053) covers, the test agent is directed to run that control-character probe first, before a boolean, returned-marker, arithmetic, operator or auth-artifact proof. A break the target appears to filter may be resent in a harmless alternative representation (VER-014). The probe stays read-only unless the finding's own request writes and adds nothing to the model beyond the per-control engine-error class (VER-016); it is guidance, not a gate, and never blocks another form or a negative verdict.

- **VER-055: Observe injection in text and HTML answers.** Where the target answers with a page or text rather than JSON, the injection forms of VER-011 can read the answer's text instead of a response field, with the same Verifier-generated controls and repeats. An arithmetic proof holds when each control's freshly computed result appears in its own answer as a whole number that neither the request, the baseline answer nor another control's answer contains. A predicate proof holds when a text the agent selects from a recorded answer is present for one class of controls and absent for the other, stable across repeats and not part of any sent value. A negative verdict on such a text also needs the text in every baseline answer and in no control answer, so it shows a result rather than the page (VER-013). Confidence matches the response-field contrast (VER-013).

- **VER-012: Prove traversal, redirect, and SSRF with harmless markers.** Path traversal is confirmed by reading a pre-placed, non-sensitive marker file. Open redirect is confirmed by a redirect response whose Location points to the finding's unique .invalid marker host, without following it. SSRF requires a correlated hit on the Verifier's loopback callback listener and a scope declaration that fetching this destination should be rejected; the automatically provided callback for a loopback target carries that declaration. A hit proves retrieval of that destination only. The Verifier does not read system files, follow redirects to arbitrary hosts, or reach internal or metadata addresses to demonstrate impact. The callback destination is the only place those two probe classes, and an out-of-band injection proof (VER-048), are steered toward.

- **VER-045: Verify archive-upload traversal.** Operators can verify an evidenced archive-upload traversal using a bounded, marked test archive and an explicitly designated test location; confirmation requires proof of the marker escaping the intended extraction directory, with state-change authorization and a recorded cleanup outcome.

- **VER-013: State each verdict and its confidence.** Every tested finding gets
  one verdict — confirmed, not reproducible, blocked by a control, or
  inconclusive — with the concrete evidence behind it and a short, honest reason.
  The Verifier distinguishes "I could not reproduce it" from "it is not
  exploitable" and never reports a weakness as confirmed without the evidence
  class its finding type requires. Negative verdicts also cite completed,
  comparable attempts; for injection, the true and false controls of at least two declared contexts give the same stable answer while the baseline answers with content, and the report names those contexts. A missing prerequisite or an unperformed request is
  not a security control. The code assigns confidence and bounds corrections
  of insufficient proof. Results cover only the cited requests and variants.

- **VER-034: Record a proof of concept for every tested finding.** Every
  finding the Verifier tested carries its proof of concept, whatever the
  verdict. The code records it from what was sent and received; the model's
  own account of its evidence is not taken over. Each request to the target is
  kept with method, URL, headers and body, each response with status, headers
  and body, redacted as in VER-016 and naming the identity by its role. The
  report shows the requests the verdict rests on, each with the decisive part
  of its response, and lists the other requests in one line each; the complete
  record goes to the evidence files (VER-022). For a confirmed verdict these
  are the steps its proof check relied on (VER-009 to VER-012), for SSRF also
  the request that triggered the callback; for any other verdict the steps it
  cites, such as the refused request behind *blocked by a control*.
  Screenshots show it (VER-035).

- **VER-035: Show the successful exploit and its HTTP proof.** For confirmed findings with a visible application effect, an available application screenshot leads the evidence presentation. It identifies the finding, test identity and recorded steps it illustrates. Rendered responses and added visual annotations are labelled. Known credential values are masked before capture where this preserves the decisive observation; otherwise the image is omitted. If no application screenshot is provided, the report states why. Screenshots explain the observed effect; the required technical proof determines the verdict. The test agent may choose test inputs whose effect is visible and, once the proof holds, select a supported application view and explain the image. The Verifier opens that view read-only and labels the agent's explanation. The corresponding recorded HTTP requests and responses always accompany the proof (VER-034), presented in the report as relevant code-block excerpts with the decisive parts marked. HTTP screenshots are saved under `evidence/` for later use and are not embedded in the report. For API-only findings, requests and responses are the primary evidence; no artificial browser view is required. The operator chooses which classes receive screenshots, by default all; this does not require an application view for every class. Additional browser requests obey scope, identity, mode and budget controls; saved exchanges remain unchanged.

- **VER-042: Review evidence clarity.** After each finding with a confirmed variant, a separate evidence reviewer checks whether the evidence presentation is understandable and returns concrete issues to the original test agent for at most two correction rounds shared by all variants of that finding. Technical verdict and presentation quality stay separate. A missing screenshot with a stated reason is not by itself a presentation issue; the reviewer visually judges only images it actually receives. Corrections use recorded evidence and send no new target requests, except that the test agent may replace an unclear application screenshot by choosing another page as in VER-035. Repeated issues without improvement and the existing cost and time limits stop the loop. Issues in what the Verifier renders itself are reported and not returned to the test agent, which cannot change them. The console and report show progress, completion and unresolved issues. The reviewer also sees the application screenshots the report shows and judges whether they show the exploit or its effect clearly. HTTP and other evidence images are never sent, and a screenshot whose checked text still contains a credential value after masking is not sent either. The report states which images a model reviewed.

- **VER-046: Review the technical test approach.** An independent QA agent reviews the finding's hypotheses, recorded attempts, counterexamples and proposed conclusion, may select additional recorded evidence, and may return concrete follow-up questions to the test agent for at most two correction rounds shared by all variants of the finding. Follow-up tests use the same execution controls and remaining budgets without resetting them. QA cannot confirm a finding or waive a proof requirement; unresolved objections remain visible separately from the code-checked verdict. A confirmed verdict whose proof check passed is not reviewed, except an access-control confirmation: QA then judges whether the observed access contradicts the application's intended authorization, and an objection is shown beside the verdict without changing it. Where the objection is that the tested resource is meant to be public while the finding names a protected one, QA may return that question to the test agent once, within the shared correction rounds, to test such a resource. Presentation review remains governed by VER-042.

## Stay safe and in scope

- **VER-014: Use safe, marked, reversible probes.** Probes use unique, identifiable markers so every artefact they create can be found and attributed. State-changing requests are allowed only with those markers and are logged. Created test artifacts are identified in the evidence. Automatic cleanup uses only an explicitly designated cleanup operation for the test's own artifacts and records its outcome; otherwise the artifacts remain for manual cleanup. Deleting other data, bulk or destructive operations and denial-of-service are never performed. Testing whether application input controls can be bypassed with harmless alternative representations is permitted within VER-008. Concealing test activity, tampering with logs or disabling monitoring is not permitted. A probe whose outcome is unknown is reconciled or treated as having had an effect, never blindly retried.

- **VER-030: Safe mode is the default.** Safe mode permits bounded, hypothesis-driven read-only diagnosis and follow-up attempts within VER-015 and VER-036. State-changing probes require the explicit intrusive-mode opt-out, given at the start or for a finding when the agent asks (VER-052), and follow VER-014; wordlist fuzzing, broad parameter sweeps and indiscriminate payload spraying are not performed in either mode. The opt-out is recorded in the report and permits state change only unless the scope explicitly forbids it. A single class can be verified on its own (VER-026), and safe mode applies the same way to that one class.

- **VER-052: Ask for a write the run does not allow.** In an interactive terminal, when the test agent finds during a test that it needs a state-changing request the run's mode does not permit, it can ask for it instead of giving up; a finding whose named requests all write is not asked about and stays untested in safe mode (VER-030). The Verifier asks the operator only if the request would be permitted in intrusive mode (VER-001, VER-014, VER-030), and shows the finding, the request, the identity, what remains on the target and the agent's reason, marked as its claim. The operator allows writes for that finding or for the rest of the run, or declines; Enter, an invalid answer or no answer in time declines, and the agent continues read-only. Nothing is asked without a terminal, with `--read-only` or when the scope forbids state change. The report records each answer for its finding. The question never widens the scope or raises a limit.

- **VER-015: Bound every run.** Limits on total requests, per-finding attempts, retries, request rate, wall-clock time, and model spend are enforced outside the model. Each bound comes from the invocation or a documented default. Reaching a limit stops the affected work rather than pressing on, and the run is cancellable. These bounds protect the target from accidental load, cap the cost of a run, and keep it from drifting beyond the finding under test. When a run would exceed the cost ceiling, it stops with a distinct exit. In an interactive terminal it first asks for a higher total ceiling; it never raises the ceiling on its own, and Enter, an invalid or missing answer, or the end of the run time keeps it. Other limits are not raised this way. The report records each raise.

- **VER-036: Stop unproductive verification.** Before each model call and tool action, the Verifier checks authorisation, remaining budgets and recorded progress outside the model. Tool actions must stay within the finding under test (VER-008). Repeated failed or redundant actions without new evidence stop after documented finite allowances; planned repetitions required for proof remain permitted. Running actions are bounded by the remaining execution time. A stopped finding retains its evidence and reports the reason without claiming a negative result (VER-024).

- **VER-016: Handle test credentials as secrets.** Session credentials for the test identities (bearer tokens, usernames and passwords, client secrets, session cookies) come from environment variables supplied by the operator or, in an interactive run, from hidden input; a user name may also be given on the command line (VER-041); sessions are also obtained at run time (VER-028, VER-040). None is stored, committed or bundled, and none is a default or shared account. Credential and token **values** never appear in logs, in the report, in evidence artefacts, or in any prompt sent to a model; only a role label identifies an identity, and captured requests are redacted of Authorization headers, cookies, and token parameters. Self-registration is used only when the scope explicitly allows it and the target has open registration, and any account it creates is marked and reported.

- **VER-028: Authenticate through the operator's mechanism.** The Verifier obtains sessions the way the target expects: a static bearer token, HTTP basic or form login with a username and password, an SSO/OIDC flow (client-credentials grant, resource-owner password grant, an authorization-code flow with PKCE in the operator's own browser, or a device-code flow), or a login program (VER-040). The Verifier never handles the password of an interactive SSO login. Each identity declares its method and its authentication endpoint, directly or through its issuer's discovery document, inside the scope (VER-029); the Verifier sends the identity's credentials only to that bound endpoint, obtains a token or session, and attaches it to requests to the target. It never sends a credential to an endpoint the identity did not name or, for an account of VER-041, to one other than the endpoint shown before the confirmation, and never re-sends a token across a redirect to a different origin (VER-018). A token is obtained once per identity and reused, renewed before it expires, with a refresh token where one was issued, and re-obtained when a request is rejected as unauthenticated, so a long run stays within its bounds without re-logging in for every finding. Flows that need a person run only in an interactive run and before the first finding; elsewhere such an identity blocks the run before anything is contacted. Later in the run the Verifier never asks, and an identity whose session cannot be renewed is unavailable for the rest of the run.

- **VER-029: Reach the target through a declared proxy.** When the operator
  declares an HTTP/HTTPS proxy, the Verifier routes its target and authentication
  traffic through it, with optional proxy credentials taken from the environment
  under the same secret handling as VER-016. The proxy and the identity-provider
  and token endpoints are named in the authorisation scope as permitted
  destinations; they widen only where the Verifier may connect for transport and
  authentication, separately from the target's attack surface, and the scope
  still refuses every destination not listed (VER-001).

- **VER-040: Obtain a session from the operator's login program.** An identity can name a program the operator provides, which the Verifier runs without a shell and without model credentials to obtain that identity's session and, optionally, its expiry. The program is shown before it first runs and confirmed with VER-002; one from an identities file the guided run found rather than was given needs its own explicit yes, and the model can neither choose nor change it. The Verifier attaches only the headers the identity allows, only to its origin (VER-018), handles every value as in VER-016, and runs the program again only to renew the session (VER-028). The program's own requests are outside the run's scope, limits and safe mode (VER-001, VER-015, VER-030); the documentation and the confirmation say so.

- **VER-041: Sign in accounts named on the command line.** Instead of an identities file, the operator can name test accounts by user name, normal or privileged, with the password entered hidden or read from an environment variable the operator names (VER-016). The Verifier signs each in with a username and password POST that returns a token, at the login URL the operator gives or else at the single login entry point the assessment names for the target, and shows that endpoint before the confirmation (VER-002); if the assessment names none or several, the operator gives the URL. The model only chooses the field names and never sees a value; credentials go only to that endpoint, with at most two attempts per account. A login that returns no token stops the run and points to the identities file (VER-028). The model knows the accounts only by neutral role names. A privileged account only reads (VER-030) and serves as the reference for VER-010.

- **VER-017: Give the agent the least authority it needs.** The verification
  agent is driven through narrow, purpose-built tools — a scoped HTTP client, a
  sandboxed browser, a marker/callback service — not an open shell or arbitrary
  network access. Model-selected actions and their arguments are treated as
  untrusted proposals: each is validated and authorised against the active scope
  before it runs, and any request to act outside the scope is refused and logged,
  not executed.

- **VER-018: Confine the browser and outbound requests.** The headless browser and any outbound request the agent makes are restricted at connection time to the authorised scope plus the explicitly declared proxy and authentication/identity-provider hosts, including after redirects and for IPv6, so a probe cannot be steered to internal, loopback, or metadata endpoints. For direct connections, resolved target addresses are checked at connection time. With a declared proxy, the Verifier still checks target URLs against scope and checks the proxy's connection address; the operator must ensure that the proxy enforces the destination address restrictions when resolving and connecting to the target. A session token or credential is attached only to its intended origin and is dropped, never forwarded, when a redirect leads to a different origin.

- **VER-019: Keep model and tool output from steering the run.** Content from the
  target, from retrieved pages, and from the model is data, not instructions. It
  cannot change the scope, the authorisation, the finding under test, the tool
  set, or the safety limits. Structured output from the model is validated
  against a strict schema before anything acts on it.

## Report the results

- **VER-020: Write a standalone verification report by default.** Unless the operator asks otherwise, each run writes its own `verification.md` for reading and `verification.yaml` for further processing, and leaves the source assessment untouched. Every entry names the finding it tested (identifier and cross-run key), the verdict and its confidence, the evidence (requests, responses, browser events, screenshots, callback hits), the target and build tested, any deviation from the finding, and the authorisation under which the test ran. The report opens with an overview of the selected findings, each linked to its entry, with its verdict and its rating before and after verification (VER-039). A tested entry leads with its verdict, the steps its proof rests on as the code checked them, and its proof of concept (VER-034, VER-035); the test plan, the test agent's own explanation and the evidence review (VER-042) follow in an appendix. Where the Analyzer's report lies next to the assessment, each entry links to the finding there.

- **VER-027: Annotate a copy of the assessment.** On request, a run also writes a copy of the assessment annotated with the verification results; the standalone report (VER-020) is always written. Annotating only adds each tested finding's verdict, confidence, rating after verification (VER-039) and pointers to its proof of concept and screenshots next to the existing finding; it never changes or removes the static result, and it records that the file was annotated and by which run. The added fields follow a published schema, and the copy stays valid against the Analyzer's assessment schema. Annotating works in interactive and in non-interactive runs and never changes the source assessment.

- **VER-038: Write the assessment report with the verification results.** On request, a run also saves a copy of the Analyzer's report in which each tested finding gets a verification section with its verdict, rationale, rating after verification (VER-039), proof of concept and screenshots. A summary of the verification precedes the findings, and the report's changelog gets an entry for the verification run. The original report stays unchanged. A finding the copy cannot place is listed at the end, never left out. The copy can show target data and is marked for review before sharing (VER-022).

- **VER-039: Rate a finding after verification.** For each tested finding the Verifier states a rating after verification next to the Analyzer's rating, which stays visible, with the reason for any change. The rating follows fixed, documented rules applied in code, never the model's judgement, and changes only on a verdict whose proof check passed (VER-013). Impact is never changed. A changed rating is marked at its finding and listed in the summary. Variants of the same finding stop testing after the first one confirms, and a variant whose request another variant already tested is not tested again; the remaining ones end as not-attempted with that reason, and the finding's rating uses the confirmed verdict.

- **VER-037: Update an earlier report.** A run can continue the report of an earlier run against the same assessment and target. It keeps each checked verdict, tests the selected findings that have none, and tests again the findings the operator names, for example after a fix, replacing their earlier result. Each result states when it was tested. A report for another assessment or target is not continued.

- **VER-021: Offer a result for the Analyzer to re-ingest.** The verdicts can
  also be emitted in a form keyed by finding identifier and the cross-run key
  (VER-007), meant for AppSec Analyzer to read back and annotate findings with
  their dynamic-verification status. Reading it is the Analyzer's part, which it
  does not do yet. This export is explicit and additive; it never rewrites or
  re-scores the assessment itself.

- **VER-022: Make evidence self-contained and safe to share.** Evidence
  artefacts are stored next to the report, readable only by the operator, and
  are enough to let a reader confirm a verdict without re-running the test
  (VER-034). They contain no real secrets: captured requests and responses are
  redacted of credentials, cookies and tokens (VER-016). Response bodies,
  capped in size, and screenshots can show target data a proof needs; they are
  marked for review before sharing, and the Analyzer export carries neither
  (VER-021).

## Run and maintain

- **VER-023: Run as a standalone CLI.** The Verifier is a standalone command-line
  tool, usable in CI, that takes an assessment, a scope file, and a target URL,
  and produces the verification report. It resolves its own agent runtime and
  does not depend on a coding assistant being present. The model comes from a
  profile chosen as in AppSec Analyzer: an installed agent CLI (Claude, Codex,
  Copilot) with its login, or an API with a key. Without a profile an
  interactive run uses the Claude CLI; a non-interactive run must name one. An
  API profile keeps CI runs possible without any agent CLI. Every profile only
  plans, without tools of its own (VER-017).

- **VER-031: Start a guided run from the assessment alone.** Called with an
  assessment and no command, the Verifier starts a guided interactive run; the
  `verify` command stays unguided. It reads the assessment offline (VER-005,
  VER-006), shows how many findings it holds, how many are dynamically
  verifiable, and how they split by weakness class and severity, and then sets
  up the run, asking only where no usable default exists:
  - **Selection** (VER-026): findings of severity high and above, with up to eight additional
    declared prerequisites or management-access/exposure findings within other
    explicit filters, unless --strict-severity keeps the floor exact; the run prints the
    floor. If nothing of high or above can be verified dynamically, it asks
    whether to verify the next lower severity that has findings.
  - **Target** (VER-001, VER-004): a scope file given or found next to the
    assessment or in the working directory is used as it is; one that cannot be
    used stops the run. Without one the run asks for the target URL, which has
    no default, and the URL alone is the scope. Neither comes from the
    assessment; the guided run writes no scope and never widens one.
  - **Identities** (VER-016, VER-028): asked when an identities file is found; missing credential values are asked for hidden. Without a file, when findings need two identities (VER-010), the run offers to take each identity's session from a request copied from the operator's browser. Access-control findings that cannot be confirmed for lack of two identities are pointed out.
  - **Model and budget** (VER-023, VER-015): the profile claude and the
    documented run limits, unless options change them; an unavailable profile
    stops the run before any question.
  - **Mode and output** (VER-030, VER-020, VER-027): safe mode and the
    standalone report by default. Intrusive mode is offered only where the scope
    allows state change and needs its own explicit yes. An existing report in
    the output directory is replaced only after its own yes or `--overwrite`;
    a no stops the run before anything is contacted.

  Answers are validated like the matching options and allow nothing an option could not; settings already given as options are not asked again. The guided run asks for secret values only hidden and never stores them (VER-016). Before anything is contacted it shows the resolved settings with the equivalent non-interactive invocation, then asks for the confirmation of VER-002; answering the setup questions is not that confirmation. There Enter confirms. Cancelling at any point contacts nothing.

  An explicit flag turns the guided run off for CI, and it is also off when no
  terminal is attached, so an unattended run never waits for input. All
  settings then come from the invocation and documented defaults; a missing
  scope or URL, profile, or confirmation blocks the run and names what is
  missing.

- **VER-032: Check inputs and access before the first finding.** Before a run tests a finding, it checks the assessment's structure (VER-005), that a source checkout given on the command line is a readable directory, that the target answers through the declared proxy (VER-003, VER-029), that every identity obtains a session and, where it names a check URL, is accepted there, and that no two identities whose tokens name their account are the same account (VER-010, VER-028), that the model profile is usable, for an API profile by one metadata request, and that the model answers one fixed prompt without target data, findings or credentials with a valid step, within the run's limits. A failed check blocks the run and names its cause, never a secret or raw error (VER-016); what a check cannot prove is said. Checks that contact the target follow the confirmation of VER-002. Each configured login is tried once, except for the at most two field-pair attempts per command-line account in VER-041. A separate command runs the same checks without verifying, offline if asked; there the fixed prompt runs only on explicit request and with its own limit, and it shows the test plan of VER-008 and warns when a finding cannot be tested.

- **VER-033: Update its own installation on request.** A separate command
  reinstalls a pipx installation of the Verifier from the source it was
  installed from, only after the operator confirms in an interactive terminal.
  Without a terminal, in CI, or for any other kind of installation it installs
  nothing and says how to update instead. It names the installed version before
  and after, as `--version` does: the engine version with the commit and date of
  the build. The source is shown without credentials.

- **VER-024: Explain what it could and could not do.** When a finding class is
  unsupported, a target is unreachable, a required test identity is missing, or a
  limit was hit, the report says so plainly per finding, so an unverified finding
  is never mistaken for a refuted one.

- **VER-025: Verify its own safety controls.** The Verifier ships with tests that
  prove the scope gate refuses out-of-scope hosts, ports, and paths; that
  destructive actions and credential leakage into logs, reports, and prompts are
  rejected; that execution limits and cancellation stop runaway or duplicate
  side effects; and that missing or invalid authorisation or credentials block a
  run rather than weakening it.
