# AppSec Verifier: command reference

`appsec-verifier` takes a finished `security-assessment.yaml`, an
authorisation scope file and a running target. It tests the selected findings
one at a time against the application and writes a verification report. It
never re-runs or re-scores the static assessment. For installation and a quick
start, see the [README](../README.md).

The requirement IDs (VER-001 to VER-035, [`requirements.md`](../requirements.md))
are cited per command and option.

## Commands

`appsec-verifier` without arguments, or with `--help`, lists the commands with
examples. `appsec-verifier <command> --help` lists the options of one by group,
with example calls; `appsec-verifier ASSESSMENT --help` does the same for the
guided run. A wrong call shows the short usage, the error and where the
examples are. Options count only as written: an abbreviation such as
`--show-cost` is an error that names the option meant (`did you mean
--show-costs?`), and nothing is contacted.

**Act against a target** (makes model calls and network requests)

- `verify` — verify findings of an assessment against a running target.
- `appsec-verifier ASSESSMENT` (no command) — the guided run: asks for the
  `verify` settings that have no usable default, then runs `verify` (VER-031).
- `preflight` — check the assessment, scope, proxy, target, logins and model
  profile without verifying anything; `--offline` contacts nothing (VER-032).

**Inspect without touching the target** (no network, no model calls)

- `scope` — resolve and print a scope file, show what is in and out of scope,
  and validate it against the schema (VER-001).

**Post-processing** (no model calls)

- `export` — re-emit the verdicts of a finished `verification.yaml` in a form
  AppSec Analyzer can read back; no re-verification (VER-021, VER-015).

**Maintain the installation**

- `update` — update a pipx installation of the Verifier after your yes
  (VER-033).

## Guided run — `appsec-verifier ASSESSMENT` (VER-031)

Called with an assessment and no command, the Verifier reads the assessment
offline, shows how many findings it holds, how many can be tested against the
running app and how many are code-only, and their split by class and severity,
then asks only for what has no usable default. What the selected findings need
(a test identity, the proof browser, a marker file, a callback) is shown in the
test plan of `verify`, with how to provide it.

Without options the run tests findings of severity high and above, of every
class present, with the profile `claude` and the limits of `data/limits.yaml`.
`--min-severity`, `--category`, `--profile`, `--cost-limit`, `--max-calls`,
`--max-requests`, `--max-attempts`, `--max-duration` and `--rate` change that.
The run prints the selection, e.g.
`→ 24 findings to verify, severity high and above (--min-severity to change)`,
and shows the floor again in the `Selection` line before the confirmation. If
no finding of severity high or above can be verified dynamically, it asks
whether to verify those of the next lower severity that has any, e.g.
`Verify the 3 of severity medium? [Y/n]`; no ends the run without contact. A
profile that is not available ends the run before any question and names
`--profile`.

Questions come only where there is no usable default. Enter accepts the default
shown in brackets.

| Question | Default | Same as |
| --- | --- | --- |
| Target URL | none; asked only without a scope file (below) | `--url` |
| Identities file | asked only when `identities.yaml` is found next to the scope, the assessment, or in the working directory; `none` for no identities | `--identities` |
| Allow intrusive probes? | no; asked only when the scope has `allow_state_change: true` | `--allow-intrusive` |
| Existing report in the output directory | `There is already a report in ./verification. Overwrite it? [y/N]`; a no stops the run before anything is contacted. Not asked with `--overwrite` or `--resume`, nor without a terminal, where the run stops as `verify` does | `--output`, `--overwrite`, `--resume` |

Each answer goes through the same check as its option and is asked again when
invalid: a URL without http or https, with a user name or password, or with an
ambiguous path, or an identities file with unset variables (named, never their
values). Options given on the command line are used as given and not asked, e.g.
`appsec-verifier ./security-assessment.yaml --target http://localhost:3000`
asks nothing but the confirmation. No question asks for a password, token, or
other secret; credentials stay in environment variables.

A `scope.yaml` next to the assessment, else in the working directory, is used
without a question; the run prints its path. If it cannot be used, for instance
because its window has closed, the run stops with exit 2 and says why. Correct
the file, or move it away to enter a target URL instead.

Without a scope file the run asks for the target URL, which has no default and
is never taken from the assessment. The run then tests only that URL's scheme,
host and port, read-only, as `verify --url` does without `--scope`, and writes
no file.

After the questions the run shows the `verify` settings and the equivalent
non-interactive command line, e.g.

```
appsec-verifier verify --assessment ./security-assessment.yaml \
  --url http://localhost:3000 --output ./verification --min-severity high \
  --profile claude --non-interactive --yes
```

and then asks the one confirmation of VER-002 as `[Y/n]`: Enter starts the run.
Answering the questions does not confirm. Ctrl-C or end of input at any
question stops with exit 2 and contacts nothing.

`--non-interactive` (`--ci`), or standard input that is not a terminal, turns the
questions off: `appsec-verifier ASSESSMENT --ci --scope … --profile … --yes`
behaves like `verify` with the same options. Without `--scope` or `--url`, or
without `--profile`, the run stops with exit 2 and names what is missing; a
missing `--yes` blocks it at the confirmation as in `verify`.

## `verify` — verify findings against a running target

`verify` takes the `security-assessment.yaml` of an AppSec Analyzer run, the
scope and limits of the test, and the selection of findings, and writes its own
report or annotates the assessment.

```
# verify every High+ XSS and access-control finding of an assessment,
# against a local target, capped at USD 5, writing a standalone report
appsec-verifier verify \
  --assessment ./security-assessment.yaml \
  --scope ./scope.yaml \
  --identities ./identities.yaml \
  --url https://localhost:3000 \
  --category xss,access-control \
  --min-severity high \
  --cost-limit 5 \
  --output ./verification
```

Flow: check the assessment's structure, the scope and proxy settings, the
identities file and the model profile (VER-005, VER-032) → resolve the selection
and the scope and, interactively, **print both for one explicit confirmation**
(VER-002, VER-026) → check that the target answers, that every identity logs
in, and that the model answers one fixed prompt, the pre-flight checks of
[`preflight`](#preflight--check-before-a-run-ver-032) (VER-003, VER-032; the
build/version match of VER-003 is *not implemented yet*) → for each selected
finding, run a bounded, scope-confined verification of exactly that finding
(VER-008, VER-015, VER-017) → write the report or annotate the assessment, with
evidence artefacts (VER-020, VER-027, VER-022). Each check prints one line under
`Preflight`. A failed check stops the run before the first finding (exit 2).
Its requests count against `--max-requests`; the model test counts as one model
call against `--max-calls` and `--cost-limit`.

Before the confirmation, `Test plan` lists the findings the run will test, each
with its severity, class, the requests the assessment names for it (for example
`GET /rest/basket/:id (login)`) and its title. The requests come from the
finding's scenario and attack steps and from the assessment's `attack_surface`:
an entry point that matches a named request, or whose handler is at the
finding's location, gives the path template and, with `auth_required: true`, the
`(login)` mark. `page /#/search` is a browser route. The agent gets these
requests and the finding's scenario and attack steps; without `--source` it is
not offered `read_source`.

`Not testable` groups the findings this run cannot confirm by what they need,
with how to provide it: a test identity (an access-control finding, or one whose
named requests all need a login), the proof browser (XSS), a marker file
(path traversal), a callback (SSRF), or intrusive mode (every named request
writes). They are not tested and appear in the report as `not-attempted` with
the reason; `--test-all` tests them anyway. When nothing is left to test, the
run stops with exit 2: nothing is contacted and no report is written.

During the run, `verify` prints one entry per event on standard error, in the
columns `TIME FINDING EVENT PROGRESS ELAPSED LEFT DETAIL`, as AppSec Analyzer
does. A blank line separates the findings. FINDING is the finding under test and
its position among the findings that get a probe. The `start` entry gives its
title, then its severity, class and up to two requests from the test plan.
EVENT is `start` and `done` for a finding, `·` for a request,
browser check or source read of the agent, `↻` for a step the Verifier
refused, and `⚠` for a limit that stopped the finding. A `·` entry gives the
agent's note on what the step checks, then the request with its query and JSON body,
the result, how long the model took to propose the step (`model 14s`) and, when
costs are shown, what the step's model call cost (`$0.04`). The
`done` entry gives the verdict, the steps, the time the finding took, when costs
are shown the finding's model cost and the run's spend (`$0.08 · run $0.42 of
$10.00`), then the agent's rationale; a confirmed verdict also says `proof checked`, because it
stands only when the Verifier found the proof its class requires. In a terminal
these parts stand on rows of their own: the title in bold, the tested request
in its own colour under the note, the rationale under the verdict, and the
amounts highlighted. Without a terminal each entry is one line. Under it an
`img` line names each screenshot the finding produced and where it lies
(`screenshot verification/evidence/T-036-xss-1.png`). The verdict
is green when the finding is confirmed, red when it was not reproduced or a
control blocked it (a likely false positive), and yellow when it stays
inconclusive; the results at the end use the same colours. When a Claude CLI
call fails, the reason names the CLI's error kind where it reports one, for
example `host_error (error_max_turns, exit 1)`. PROGRESS is the share of
findings done, ELAPSED the run time. LEFT is estimated from the findings done so
far and never exceeds what `--max-duration` leaves; before the first finding is done it shows
that remainder (`≤29m`). In a terminal a status line underneath shows a progress
bar, when costs are shown the run's spend so far (`$0.42 of $10.00`), the
running step (the model call or the request) and its age. Without a
terminal, a line with the same follows after two minutes without
output. The summary at the end adds a `Run` row: run time, model calls,
requests and, when costs are shown, the spend against `--cost-limit`. Costs are
shown with API billing (`codex`, `anthropic-api`, and `claude` with
`ANTHROPIC_API_KEY` or a login that bills the API), and with `--show-costs` in
any mode, as in AppSec Analyzer. With a Claude subscription the amount is what
the calls would cost at API prices and is marked `at API prices`; with
`codex-cli` and `copilot-cli` the `Run` row says `cost not reported
(subscription)`. Text from the assessment, the model or the target is shown
without control characters and without credential values.

### Input and target boundary

| Flag | Meaning | Req. |
| --- | --- | --- |
| `--assessment PATH` | `security-assessment.yaml` to verify (the one the Analyzer produced). | VER-005 |
| `--scope PATH` | Authorisation scope file (`schemas/scope.schema.yaml`): the target boundary, the declared proxy and auth hosts, the test window and the owner. Without it, `--url` alone sets the boundary. | VER-001 |
| `--url URL` (alias `--target`) | Start/base URL to test. With `--scope` it must fall inside the scope; a mismatch is refused, and without `--url` the scope's `base_url` is used. Without `--scope` it is required and is the whole boundary: its scheme, host and port, read-only, with no window and no owner. | VER-001/004 |
| `--identities PATH` | Test-identity config (`schemas/identities.schema.yaml`): bearer, basic, form, or OIDC login per role. Secret **values** come from env, never this file. | VER-016/028 |
| `--proxy URL` | *Not implemented yet; set `proxy.url` in the scope file.* Route target and auth traffic through this HTTP/HTTPS proxy, overriding the scope's `proxy.url`. Proxy credentials still come from the env vars the scope names. | VER-029 |

### Select what to verify (VER-026)

All selectors read from the referenced assessment and combine with AND. With no
selector, the run verifies every *dynamically verifiable* finding (VER-006) and
says so before it starts. Prefer categories and severities over CWEs.

| Flag | Meaning |
| --- | --- |
| `--category LIST` | Categories, by class or finer technique: `access-control`, `idor`, `sqli`, `nosqli`, `xss`, `path-traversal`, `open-redirect`, `ssrf`, … So `--category idor` verifies IDOR alone; no CWE is needed. (The guided run names the classes the assessment holds.) |
| `--severity LIST` | Exact severities, e.g. `critical,high`. |
| `--min-severity LEVEL` | Severity floor: `low\|medium\|high\|critical`. |
| `--only ID[,ID]` | Specific finding ids, e.g. `T-037,F-001`. Overrides the other selectors. |
| `--class LIST` | (advanced) weakness classes. |
| `--cwe LIST` | (advanced) specific CWEs, e.g. `CWE-79,CWE-639`. |

### Boundaries — cost and load (VER-015)

| Flag | Meaning |
| --- | --- |
| `--cost-limit USD` | Model-spend ceiling for the run. Default from `data/limits.yaml`. Reaching it stops the run (exit 3), and so does a model call that reports no usable cost. Rejected with `codex-cli` and `copilot-cli`, which report no cost. |
| `--max-requests N` | Hard cap on total requests to the target. Refused requests are not counted. |
| `--max-attempts N` | Cap on agent steps per finding (each step is one planner call: a tool call or the verdict). Default 12. Reaching it ends the finding `inconclusive` with `limits_hit: attempts`. |
| `--max-calls N` | Cap on model calls (planning steps) for the run, for every profile. |
| `--max-duration S` | Wall-clock cap; cancellable mid-run. |
| `--rate RPS` | Max request rate to the target and its login endpoints: every request, redirect hops and the proof browser's included, waits until it is 1/RPS seconds after the previous one. `0` turns the rate limit off. |

Every limit must be greater than 0; only `--rate` accepts 0. A negative or zero
cap blocks the run (exit 2) before anything is contacted, as does a key in
`data/limits.yaml` that the Verifier does not enforce.

Once the cost ceiling, the request cap, the call cap, the run time or the scope
window is reached, the finding under test ends `inconclusive` and the remaining
findings are not tested: they appear as `not-attempted` with the limit in
`limits_hit`, no further model call is made, and the run exits with 3. After
three failed model calls in a row, for example an exhausted quota or a rejected
key, the run makes no further model call and the remaining findings end
`inconclusive` with the reason.

A failed request is not retried; the only resend is one new login after the
target answers 401. When the request is answered 401 again with the new
session, that identity is not logged in again until one of its requests is
accepted. A login the target refuses is not tried again in the run. Each
answer is read for at most 30 seconds and up to 10 MiB after decompression; a
slower or larger answer ends that request with an error the agent sees.

Ctrl-C stops the run: the finding under test ends `inconclusive`, the
remaining ones are `not-attempted`, the report is written with the results so
far and `meta.interrupted: true`, and the run exits with 130.

### Output mode and run mode

| Flag | Meaning | Req. |
| --- | --- | --- |
| `--output DIR` | Report and evidence directory (created, owner-readable). Default `./verification`. | VER-020 |
| `--report` | Write a standalone report, leave the assessment untouched. **Default.** | VER-020 |
| `--print` | List every finding in the results at the end, code-only ones included, with the whole reason. | VER-013 |
| `--show-costs` | Show model costs on the console also with subscription billing; by default only with API billing (see the `Run` row above). Changes no limit and nothing in the report. | VER-015 |
| `--resume` | Continue the report in `--output`: findings with confirmed, not-reproducible or blocked-by-control and a code-checked proof contract 2 keep it; older or unchecked results are tested again; the other selected findings (inconclusive, not attempted, or not in the report) are tested and their results replace the earlier ones. The action log is continued. When every selected finding has a verdict, nothing is contacted (exit 0). Without a report in `--output` the run starts as usual. A report that cannot be read, does not match `schemas/verification.schema.yaml`, or was written for another assessment (by SHA-256) or target blocks the run (exit 2) before anything is contacted. Cannot be combined with `--overwrite`. | VER-027 |
| `--overwrite` | Replace a report already in `--output` (`verification.md` or `verification.yaml`). Without it, and without `--resume`, such a report stops the run (exit 2) before anything is contacted. | VER-027 |
| `--annotate` | Also write `security-assessment.annotated.yaml` to `--output`: a copy of the assessment with the verification status of each finding. Never re-scores or removes a finding. | VER-027 |
| `--in-place` | With `--annotate`, modify the referenced `security-assessment.yaml` itself. Explicit, never a default. The file is replaced in one step, so a write that fails leaves it unchanged. | VER-027 |
| `--non-interactive` / `--ci` | No prompts: selection, scope confirmation, and cost ceiling all come from the invocation. Recorded in the report. | VER-002/026 |
| `--allow-intrusive` | Opt out of safe mode (below) for marked state-changing or more thorough probing. Recorded in the report. | VER-030 |
| `--read-only` | Force read-only even if the scope permits state change; overrides `allow_state_change`. | VER-014 |
| `--dry-run` | Resolve selection + scope and print the plan; send nothing to the target. | VER-008 |
| `--test-all` | Also test findings this run cannot confirm (see the test plan below); by default they are not tested and reported `not-attempted` with the reason. | VER-008 |
| `--headful` | Run the proof browser visibly (local debugging only). | VER-009 |
| `--screenshots CLASSES` | Classes that get screenshots, comma-separated: `xss`, `access-control`, `injection`, `open-redirect`, `path-traversal`, `ssrf`; or `none`. Default: all. Without screenshots an XSS proof still holds. | VER-035 |
| `--profile NAME` | Model profile (below), as in AppSec Analyzer. Default `claude`; required with `--non-interactive`. | VER-023 |
| `--model NAME` | Model for the selected profile; default is the profile's model. | — |

**Model profiles.** The profile decides which agent CLI or API plans each step.
An unavailable profile (CLI missing or too old, not logged in, key missing,
model unknown) stops the run before anything is contacted.

| Profile | Runs | Credentials | Default model | Spend |
| --- | --- | --- | --- | --- |
| `claude` | `claude -p` | Claude login, or `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` | `claude-sonnet-5-5` | reported USD (API-equivalent on a subscription) |
| `codex-cli` | `codex exec`, 0.163.0+ | ChatGPT login only | `gpt-sol` | not reported |
| `copilot-cli` | `copilot`, exactly 1.0.101 | Copilot login | `gpt-5.4` | not reported; soft limit of 30 AI credits per call |
| `codex` | OpenAI Responses API | `OPENAI_API_KEY` | `gpt-sol` | tokens × `data/model-catalog.yaml` prices |
| `anthropic-api` | Anthropic Messages API via the `anthropic` SDK (`[agent]`, 0.87+) | `ANTHROPIC_API_KEY` | `claude-sonnet-5-5` | tokens × `data/anthropic-model-catalog.yaml` prices (Opus 5.5, Sonnet 5.5, Haiku 5.5, Fable 5.1; Haiku 5.5 at its higher rates when a prompt exceeds 100 000 tokens); an unlisted model is refused |

Whatever the profile, the model only proposes the next step as one JSON
object. The Verifier checks it against strict schemas and runs it with the same
scope-guarded tools (VER-017, VER-019). An invalid step ends the finding
`inconclusive` and nothing runs. A step that fails (target not reachable, login
rejected, unknown role) goes back to the model as an error. A finding whose
check fails entirely ends `inconclusive`, and the run goes on.

The CLIs run in an empty temporary directory without built-in tools, MCP
servers, settings, skills, custom instructions or session history. They get
only the environment they need: no identity secrets and no API keys of other
providers. `claude` and `codex-cli` also check each call for tool use; a
session that offers or uses a tool ends the finding `inconclusive` and stops
all later model calls of the run. Copilot CLI prints only the answer, so its
isolation rests on the pinned version and its flags. `codex-cli` and
`copilot-cli` have only offline tests so far.

**Proof per class (VER-009 to VER-013).** A `confirmed` verdict must name the
steps that prove it in `proof_steps` (step numbers as in `agent-log.jsonl`).
The code checks them against what the tools returned (`agent/proof.py`):

- Access control: declare a test with an operator-supplied `test_resources` entry. The same method, path and inputs must return its known harmless marker both for an allowed role and a denied role with independent credentials. Two successful responses alone do not establish unauthorized access.
- Injection: declare the hypothesis, one input to change and the observation before collecting evidence. Repeat a working baseline, a true condition and a false condition at least twice each. All other inputs and the identity stay fixed. A selected JSON field must be stable, reproduce the nonempty baseline for the true condition and differ for the false condition. Reflected input, status changes and generic errors are insufficient. Alternatively, alternate at least two baseline and two delay requests: every delayed answer must be 2–5 seconds slower than every baseline answer, with identical successful response bodies. Repeated citations to one request never count as repetitions.
- XSS: a `browser_check` in which the marker executed (see below).
- Open redirect: a cited request answered 301, 302, 303, 307 or 308 whose
  `Location` leads to `<marker>.invalid`, a host drawn at random per finding.
  `.invalid` never resolves (RFC 6761). Redirects are never followed; a 3xx
  answer comes back with its `Location`, and a next hop is a request of its own.
- Path traversal: a cited request whose response held the content of the
  scope's `marker_file`, recognised in code. The model is told the file's path,
  never its content, which shows as `[marker-file]` in every tool result. A
  request that itself carried the content does not count.
- SSRF: a request with the finding's marker reached the callback listener. No
  `proof_steps` are needed.

When a firm verdict lacks its required evidence, the agent receives the missing checks and may correct its experiment within the remaining step, request and model budgets. At most two correction rounds are allowed. An unresolved claim ends `inconclusive`, with the missing evidence in the report. Confidence is assigned by the checker: medium for injection and checked negative results, high for other confirmed proofs, low for unresolved or unattempted findings. Evidence the
model lists itself is never taken over. When the check passes, the code adds
the record it checked. For access control, injection, open redirect and path
traversal that is `evidence/<finding>-exchanges.json` (owner-only): per cited
step the method, path, parameters, body, identity, status, length and a hash
of the redacted response body. For SSRF it is
`evidence/<finding>-callback-hits.json` with time, method and source address of
each hit.

Negative verdicts also need evidence. Without an answered request the result is `not-attempted`. Injection needs the same repeated controls, either with a stable nonempty observation or a repeatable rejection against a working baseline. Access control needs the declared resource visible to its allowed role and absent for an independent denied role; a 403 or 404 supports `blocked-by-control`. A timeout, scope refusal, missing capability or server error establishes no control. XSS needs a completed browser attempt carrying the marker parts; other marker classes currently retain unsuccessful attempts as `inconclusive`. Every checked result and exported annotation states that it covers only its cited requests and variant.

The assessment’s optional `verification_context` version 1 carries per-variant input locations, query construction, dialect and driver where known, processing and filter order, controls, prerequisites, observations, negative controls, unknowns and sources. The agent reads this context on demand; legacy mechanism traces, scenarios, attack steps and evidence are also retained with explicit size limits. This context supplies hypotheses, never target authorization. A `plan_test` declaration binds its variant to the method and route. Missing header or browser-interaction support is reported before testing when all declared variants require it. Form bodies are supported with POST, PUT and PATCH under the existing intrusive-mode controls.

The agent can use `read_response` to inspect or compare a JSON field or a 1,500-character window from this finding’s recorded, redacted responses, without sending another request. Inspection retains at most 64,000 characters per response and 256,000 per finding; incomplete bodies cannot support field comparisons. Context and result fields stay structured, so long text does not remove measured durations or statuses.

**Proof of concept (VER-034).** Every finding the agent tested gets a proof of
concept, whatever the verdict, also when a limit stopped it. The code records
each request an agent step sent to the target and the response to it:
`http_request` one exchange (two when it renewed a session after a 401),
`browser_check` every request of the page that the guarded client answered,
with bodies only for documents, XHR and fetch. They are written to
`evidence/<finding>-poc.har` (HTTP Archive 1.2, owner-only), which Burp, ZAP or
a browser's developer tools can import. Each entry names its step (`_step`),
and `_decisive` marks the steps the verdict rests on: for a confirmed verdict
the steps its proof check used, for XSS also the `browser_check` in which the
marker executed and for SSRF the request that reached the listener; for any
other verdict the steps it cites in `proof_steps`. The report lists every step
in one line and shows the decisive ones as raw HTTP with the time of the
answer: the request in full, and of the response the status, the headers and
1,500 characters of the body around
the part that decides (the marker file's content, the XSS marker, the first
difference between two injection answers, otherwise the start). The model sees
none of this beyond its own tool results.

Before an exchange is recorded, headers the identity added read
`[identity <role>]`. The values of `Authorization`, `Cookie` and `Set-Cookie`
(cookie names and attributes stay), of other headers whose name contains
`token`, `secret`, `passw`, `api-key`, `session`, `credential` or the word
`auth`, of query parameters named that way, every credential value the run
knows and every JWT read `[redacted]`. Bodies are kept up to 256 KiB each after
redaction and up to 4 MiB for all bodies of a finding, binary bodies only with
type, length and hash. Other data the
target returned stays, because the proof needs it: the report says to review
the evidence before sharing it, and `export` never references the HAR file.

**Markers for path traversal and SSRF (VER-012).** These probes are aimed only
at harmless markers. In a path-traversal probe, a parameter or body value that
names a file (it contains `..` or a NUL, or starts with `/`, `\`, `~` or a
drive letter) must name the marker file; without `marker_file` in the scope no
such value is sent. The traversal goes in a parameter or the body, because the
guard refuses dot segments and encoded separators in the URL path. In an SSRF
probe, a value that holds a URL (`://` or a leading `//`) must point at the
callback listener's origin. Values are percent-decoded up to three times
before the check; other encodings a target may accept are not decoded, and the
agent is told the same rule. The listener (`tools/callback.py`) binds only to a
loopback `callback.host`. A target on another machine reaches it through a
TLS-terminating proxy or tunnel the operator runs, named in
`callback.base_url`, which must then be https. The listener answers every
request with an empty 204, keeps only time, method and source address of
requests that carry a marker, and is never a target of the Verifier itself.
If it cannot bind, the run goes on and SSRF findings stay unconfirmed.

**XSS proof browser (VER-009, VER-018, VER-022).** For XSS findings the agent
gets one more tool, `browser_check`, which loads a target page in headless
Google Chrome (Playwright, `appsec-verifier[browser]`; `--headful` shows it).
Chrome opens no connection itself: every request of the page is intercepted and
sent through the same scope guard, budget and safe mode as the agent's HTTP
requests, identity headers are added only for the identity's origin, redirects
go back to the browser so each hop is checked, and anything else is aborted,
service workers included. WebSockets are never connected to a server. Chrome
itself is started inside a network namespace of its own
(`unshare --user --net --map-current-user`) that
has no interface but loopback, so traffic the interception never sees, such as
WebRTC/UDP, cannot leave the machine either. This needs Linux, `unshare` from
util-linux and unprivileged user namespaces. Chrome runs with its own sandbox.
Where the namespace or the sandbox is unavailable (other systems, some
containers), the browser does not start and XSS findings cannot be confirmed.
If Chrome fails during the run, that check ends with an error the agent sees,
and the next check starts a new Chrome. A check takes at most about 45
seconds: 30 for loading the page, then the wait the agent asked for (at most
5), and 5 each for marking the page and taking its screenshot. A request of
the page other than a document gets at most 5 seconds, so a long poll the
server holds open does not hold up the check; a page that does not answer in
time keeps its proof of execution but gets no screenshot.

Each finding gets a random two-part marker; the payload must call
`alert('<part1>'+'<part2>')`, and only a dialog
showing the joined value counts, so a page that merely echoes the payload text
is not mistaken for execution. If any request of the probe carried the joined
value itself (also percent-encoded), the dialog does not count either: a page
that shows a parameter through `alert()` by design would display it without
any injected script. A `confirmed` XSS verdict without such an
executed marker is downgraded to `inconclusive` ("indicative, not executed"),
whatever the model says. On execution the browser draws a banner and saves a
JSON event record under `evidence/` (owner-only) and, unless `--screenshots`
leaves out `xss`, a screenshot. Its caption names the finding, the URL as
requested, the identity, the time and the element that carries the payload,
which is outlined in red, with a red tag and arrow pointing at it; the page is
moved clear of banner and caption. The banner stands at the top of the page
also when the payload ran in a frame. Whatever of the page covers the payload
element, such as a dialog and its backdrop, is hidden for the screenshot and
named in the caption and in the event record. The
proof does not depend on the screenshot. Screenshots can show target data; the
report marks them for review before sharing, and the Analyzer export never
references them. Without Playwright or Chrome the `Browser` line in the run
settings says so and XSS findings cannot be confirmed. The line also names the
classes that get screenshots.

**Access-control screenshots (VER-035).** For a confirmed access-control
finding, each decisive response that is an HTML page is rendered in the proof
browser from the recorded, redacted response. Only the page itself is answered;
images, styles and scripts are aborted and scripts are off, so nothing is sent
to the target and the page may look unstyled. The exchange screenshot below is
taken as well. The caption names finding, step, request,
identity, status and time. Up to three values the model names in `highlight`,
such as the other identity's email, are marked in yellow when they occur in
the response.

**Exchange screenshots (VER-035).** Every tested finding whose verdict
rests on steps (see proof of concept above) gets
`evidence/<finding>-exchange-<n>.png` when `--screenshots` includes its class,
also beside the page screenshot of an executed XSS or an access-control page.
It shows the decisive
steps, request and response side by side as recorded and redacted, built as a
page without scripts and rendered in the proof browser without a new request.
Marked is what the code can locate, each kind with a red label that says what
it is (`payload`, `input`, `answer differs`): the identity, the XSS or SSRF marker, the
redirect host and the `Location` header, the marker file's name and content,
the input and the part of the answer that differ between two injection
requests (the input also decoded), a different status, and the answer times
when they differ by 2 s or more. For SSRF the image also says whether the
listener received the marker, for XSS which page the browser opened (with the
payload, also when it sits in the `#` fragment that never reaches the server)
and whether the marker executed. The proof browser
starts for screenshots only when a finding of an included class is selected;
without Playwright or Chrome no screenshot is taken and the verdicts stand.

**Safe mode (default, VER-030).** Without `--allow-intrusive` the run stays
read-only, even when the scope permits state change. It sends the most harmless
payload that can still decide a verdict, keeps request count and rate low, and
does no wordlist fuzzing, broad parameter sweeps or long series of payload
variants. Writing to the target, needed for stored XSS and some IDOR cases,
happens only with `--allow-intrusive`, `allow_state_change: true` in the scope
and without `--read-only`; such requests use unique markers and are logged
(VER-014). The Verifier does not clean up what they wrote, so reset the target
after the run. The HTTP client enforces the methods for every caller: safe mode
sends only GET, HEAD and OPTIONS, intrusive mode adds POST, PUT and PATCH, and
DELETE and every other method are refused. A POST can still change or remove
data, so use intrusive mode only against a disposable test instance.

### Interactive and non-interactive

- Interactive (default, with a terminal): the run prints its settings and
  waits for one confirmation before the first request (VER-002). The guided run
  (above) asks for the settings first.
- Non-interactive (`--non-interactive` / `--ci`, or no terminal): no prompts.
  Selection, profile and confirmation (`--yes`) come from the command line; a
  missing confirmation stops the run.

### Console output

The console is laid out like AppSec Analyzer's, with a red logo and red
accents instead of its turquoise. Before the first request `verify` prints its
settings as `Key : value` lines: the assessment, the target, the scope and its
owner (or `no scope file`), the selection with its severity floor, the profile
and model, the limits and the mode. For selected classes that need a
preparation and have it, one more line names it: `Identities` (roles only),
`Browser`, `Callback` and `Marker file` (its path only). Then follows the test
plan described above, and the question `Proceed against this target? [y/N]`, or
`[Y/n]` in the guided run.

The `Report` line names where the report goes, `verification.md` (Markdown)
and `verification.yaml` (YAML, for tools, `--resume` and `export`), and says
`replaces` when `--overwrite` replaces a report already there.

At the end `Results` lists each finding testable against the app: a mark
(`✓` confirmed, `✗` not reproducible, `⊘` blocked by a control, `?`
inconclusive, `·` not tested), id, severity, class, result and title, and under
it the reason in one line. A finding this run could not test shows what it
needs as its result (`needs test identity`). Confirmed findings come first.
`--print` lists every finding, code-only ones included, with the whole reason.
`Done` then gives the paths of the report, its data, the evidence and the action
log, the run's usage and the count per result.

When a run cannot start or go on, `verify` says so on standard error in one
form: a line marked `✗` with what is wrong, the details under it, a line marked
`→` with what to do, and `Nothing was contacted.` when that is so.

On a terminal the output is in colour and starts with the logo: a confirmed
finding is green, not reproducible or blocked red, inconclusive yellow, and
severities and pre-flight results have their own colours. `NO_COLOR` (any
value) turns colour off, `FORCE_COLOR=1` turns it on without a terminal, and
`COLORTERM=truecolor` selects the 24-bit palette. Without a terminal, for
example in CI or when redirected to a file, the output is plain text.

**Exit codes.**

| Code | Meaning |
| --- | --- |
| `0` | All selected findings were tested, whatever the verdict. A confirmed weakness is a successful run. |
| `2` | The run was blocked before testing: malformed assessment, unreadable, invalid or expired scope, unset proxy or identity variable, unusable model profile, missing confirmation, unreachable target, rejected login, failed model test, empty selection, no selected finding testable in this run, a report already in `--output` without `--overwrite` or `--resume`, or a `--resume` report that cannot be continued. |
| `3` | A limit was reached for at least one finding, for example the cost ceiling, the request cap, the steps per finding, or the end of the scope window. |
| `130` | Interrupted with Ctrl-C. A `verify` run that had started testing writes its report with the results so far. |

## `preflight` — check before a run (VER-032)

```
appsec-verifier preflight --assessment ./security-assessment.yaml --scope ./scope.yaml \
  [--url URL] [--identities ./identities.yaml] [--profile P] [--model M] \
  [--offline] [--json] [--yes] [--non-interactive] \
  [--test-model (--cost-limit USD | --max-calls 1) [--show-costs]]
```

Runs the checks `verify` runs before its first finding, and verifies nothing.
Each check prints one line: `✓` passed, `⚠` works with a caveat, `✗` failed,
`·` not checked or not applicable.

| Check | What it does | Contacts |
| --- | --- | --- |
| Assessment | Checks the fields the Verifier reads against `schemas/assessment.schema.yaml` and that finding ids are unique. Shows project, date, and how many findings are dynamic, static-only, input-incomplete. Messages name the place and the rule; only a repeated id is quoted, escaped. | nothing |
| Scope | Schema, window, URL inside the scope. | nothing |
| Proxy | The proxy URL is http(s) without inline credentials, and `username_env`/`password_env` are both set. | nothing |
| Identities | Schema, every `*_env` variable set, endpoints and `check_url` inside the scope. | nothing |
| Test plan | The test plan `verify` shows, for every finding and in safe mode: which findings a run tests, and which it cannot test because they need what the run lacks, grouped by that need with what to add. Warns when a finding cannot be tested, never fails. Only when the checks above passed. | nothing |
| Model | The profile resolves (CLI present and logged in, or key set; model known and priced). For `codex` and `anthropic-api` one metadata request shows the key is accepted and the model offered; it generates nothing and proves no quota. | the provider (not with `--offline`) |
| Target | One GET to the URL through the scope gate and the declared proxy. A redirect is not followed. Any HTTP answer counts as reachable; 5xx warns. A failure names its cause: name resolution, refused connection, timeout, TLS certificate or handshake, proxy refusal or proxy authentication (407), or an address the scope refuses. | the target |
| per role | One login for `form` and OIDC identities, never retried. With `auth.check_url`, one GET there with the identity's credentials: 2xx accepted, 401/403 rejected, anything else unclear. `bearer` and `basic` without `check_url` are reported as not checked against the target. | target, login endpoints |
| Model test | Only with `--test-model` (`verify` always runs it, within its own limits): one fixed prompt without target data, findings or credentials. Passes when the host stays confined and replies with exactly the requested step. | the provider |

The offline checks run first. If one fails, nothing is contacted. The target and
login checks run only after one explicit confirmation (VER-002): at the prompt,
or with `--yes`. `--non-interactive` without `--yes` contacts nothing and fails.
A failed target check skips the logins. The test plan itself is printed after
the checks, before the result.

`--test-model` needs its own limit: `--cost-limit` of at least USD 0.01 for
`claude`, `codex` and `anthropic-api`, `--max-calls 1` for `codex-cli` and
`copilot-cli`. It cannot be combined with `--offline` and runs only when all other
checks passed. Its line names the call's cost with API billing, and with
`--show-costs` in any mode, as `verify` does.

`--json` prints `{"kind": "preflight", "ok": …, "verification": "not_run",
"checks": [{"check", "status", "message"}]}` on stdout and the progress lines and
the test plan on stderr. It never prompts, so contacting the target needs `--yes`.

Messages never contain a secret, a token, a response body or a raw error text,
which can hold proxy credentials (VER-016). Exit code `0` when no check failed,
`2` otherwise.

## `scope` — resolve and check a scope file

```
appsec-verifier scope --scope ./scope.yaml [--target URL]
```

Validates the scope against `schemas/scope.schema.yaml`, prints the resolved
boundary (host, ports, path prefixes, window, owner), and, with `--target`,
reports whether that URL is inside it. Contacts nothing (VER-001).

## `export` — hand verdicts back to the Analyzer

```
appsec-verifier export --verification ./verification/verification.yaml \
  --output ./verification/analyzer-verification.json [--format json|yaml]
```

Converts a finished `verification.yaml` into a set of verdicts keyed by finding
id and the cross-run `match_key` (VER-007), which AppSec Analyzer reads to mark
findings with their verification status. It never changes or re-scores the
assessment (VER-021), contacts nothing and makes no model calls. Default output:
`analyzer-verification.json` in the working directory, JSON format. A file that
cannot be read or does not match `schemas/verification.schema.yaml` stops it
with exit 2.

## `update` — update the installed Verifier (VER-033)

```
appsec-verifier update
```

- Reinstalls the Verifier from the source pipx recorded at install time, such
  as GitHub or a local checkout. Credentials in a recorded URL are not shown.
- Shows the installed version and the source, then asks `[Y/n]`. Enter or `y`
  confirms; anything else, or closed input, installs nothing.
- Runs `pipx upgrade --pip-args=--force-reinstall appsec-verifier`, which you
  can also run yourself. `--force-reinstall` reinstalls even when the version
  number is unchanged, as is usual between GitHub commits. Like a new
  `pipx install`, it takes the newest dependency versions `setup.py` allows, not
  the pins of `requirements.lock`; packages added with `pipx inject` stay.
- Hides the pipx output and shows it only when the update fails (exit 2).
- Afterwards shows the new version as `appsec-verifier --version` prints it,
  read from the new installation: the engine version with commit and date of
  the build, e.g. `0.1.0a1 (a26a8e10, 2026-11-07)`. `(unchanged)` means the
  source had nothing newer.
- Needs an interactive terminal outside CI (`CI` set); no option skips the
  question. Otherwise it exits 2 and names the pipx command to run yourself.
- An installation without pipx (a venv from `requirements.lock`, an editable
  checkout) is not changed; update it the way you installed it.

To switch the source, run `pipx install --force` with the new source. A
checkout installed with `pipx install --force .` stays the source: change it,
for example with `git pull`, and run `update`.

`--version` names the build. `setup.py` stamps commit, date and local changes
into the package (`build-info.json`); a checkout without a stamp is read from
Git; a build without either shows `(commit unknown)`.

## Configuration files

### Scope file — `scope.yaml` (authorisation, VER-001)

The scope file states what the Verifier may contact, during which window, and
who is responsible. Schema: `schemas/scope.schema.yaml`; examples in
`examples/`. A minimal scope needs `schema_version`, `base_url`, `window` and
`owner`; the README's quick start shows one.

Without a scope file, `--url` alone is the scope: the URL's scheme, host and
port, the whole host, read-only, for that run. You need a scope file for
anything more: several hosts or ports, path prefixes, `deny_paths`, a host name
that resolves to a private address (`networks`), a proxy, login hosts, the SSRF
callback, the marker file, write requests, or a test window and owner on
record.

| Key | Meaning |
| --- | --- |
| `base_url` | Absolute http(s) URL of the target. Hosts and ports default to those of this URL. |
| `hosts`, `ports`, `schemes`, `path_prefixes` | What may be contacted. `schemes` defaults to the scheme of `base_url`, so plain http is allowed only when `base_url` or `schemes` names it. |
| `deny_paths` | Paths that are never contacted, compared regardless of case and percent-encoding. |
| `networks` | CIDR ranges of private or loopback addresses that may be contacted (see below). |
| `window` | Authorised test period (`from`, `until`, ISO 8601 UTC). |
| `owner` | The person or party responsible for the test. |
| `allow_state_change` | `true` allows writing requests together with `--allow-intrusive` (VER-030). |
| `auth_hosts` | SSO, OIDC and token endpoints that may be contacted only to log in, never tested. |
| `proxy` | HTTP(S) proxy for target and login traffic; credentials are named as environment variables (`username_env`, `password_env`), never in the URL. `no_proxy` lists hosts reached directly. |
| `callback` | Listener for SSRF proofs (see above). |
| `marker_file` | Path and token of the marker file for path-traversal proofs. |
| `test_resources` | Known harmless resources for access-control checks, bound to a finding, concrete request, allowed and denied roles, and expected response marker. |

For access-control checks, create a harmless resource in the test application and declare its ownership. This example states that `customer-b` may read `/rest/basket/2` and `customer-a` must not receive its marker:

```yaml
test_resources:
  - id: basket-b
    finding_id: T-001
    path: /rest/basket/2
    method: GET
    allowed_roles: [customer-b]
    denied_roles: [customer-a]
    pointer: /test_marker
    value: verifier-owned-basket
```

Use the actual finding ID, path, roles and a non-sensitive marker from your test setup. `pointer` selects a JSON response field using JSON Pointer syntax. An empty pointer checks a literal text marker instead; that marker must not occur in the request. `anonymous` names a caller without credentials. Optional `params`, `json` or `form` bind fixed inputs; choose one body format. Role lists must be disjoint, and the resource must be inside the target scope. These entries establish expected access, not additional request permissions.

Anything outside the scope, whether target, login host or proxy, is refused
and not attempted. A path that a server could resolve to another resource (a
`.` or `..` segment, `//`, `\`, `;`, or `%2e`, `%2f`, `%5c`, `%3b`, `%25`,
`%00`) is always refused. Proxy variables in the environment (`HTTPS_PROXY` and
the like) are ignored; only the scope's `proxy` is used.

Addresses are checked when the connection is made (VER-018). Each host name is
resolved once, every address it resolves to is checked, and the connection goes
to a checked address, so a DNS answer that changes later cannot redirect a
request. Public addresses are allowed. Loopback, private and other non-public
addresses need `networks`, unless the host is written as that address or as
`localhost`. Link-local addresses (including cloud metadata at
169.254.169.254), other known metadata addresses, multicast, unspecified and
reserved addresses are never contacted. If any address of a host is refused,
the request is refused. Through a proxy only the proxy's address is checked;
hosts in `proxy.no_proxy` are checked as without a proxy.

The `window` is checked before every request and every planning step. Once it
has closed, the current finding ends `inconclusive` with `limits_hit: window`,
no further request is sent, and the run exits with 3.

### Identities file — `identities.yaml` (sessions, VER-016/028)

Lists the test identities by role name and, per identity, the login `method`
and the environment variables that hold its credentials. The file holds no
secret values. Schema: `schemas/identities.schema.yaml`. Methods: `bearer`
(static token), `basic`, `form`, `oidc-password`, `oidc-client-credentials`,
and `none` (anonymous). `oidc-authorization-code` is in the schema but not
implemented yet; the pre-flight check refuses it. Examples:
`examples/juice-shop/` (form login) and `examples/sso-proxy/` (OIDC and proxy).

```yaml
identities:
  - role: user-a                       # OIDC password grant against the SSO server
    method: oidc-password
    auth:
      token_url: https://sso.example.com/realms/app/protocol/openid-connect/token
      client_id: verifier-cli
      client_secret_env: VERIFIER_OIDC_CLIENT_SECRET
      username_env: VERIFIER_USER_A_NAME
      password_env: VERIFIER_USER_A_PASS
  - role: service                      # pre-issued bearer token
    method: bearer
    auth: { token_env: VERIFIER_SVC_TOKEN }
  - role: anonymous
    method: none
```

Each identity sends its credentials only to the endpoint it names, which must be
the target or a scope `auth_hosts` entry (VER-028). The session it obtains is
attached only to its own origin, `auth.target_origin`, by default the target
base URL; a request as that role to any other origin is refused (VER-018). The
HTTP client keeps no cookies, so a session never travels in a cookie the target
set for another identity.

Before the first request `verify` checks the file against the schema, checks
that every `*_env` variable it names is set, and that login endpoints and
`target_origin` lie inside the scope. A failure stops the run with exit 2 and
names the variable, never its value. After the confirmation and before the
first model call, every `form` and OIDC identity logs in once; a rejected login
stops the run (VER-032). A `bearer` or `basic` identity is checked against the
target only when it names `auth.check_url`, a URL on the origin its credentials
are sent to, which the pre-flight check requests once.

Credential and token values are read from the environment at run time and used
only to obtain a session. They are never written to logs, the report, evidence
files or a model prompt; only the role name is passed on, and recorded requests
are stripped of Authorization headers, cookies and token parameters (VER-016,
VER-022). If the target echoes a credential, every value the run knows (each
`*_env` value and each token obtained, also JSON-escaped and URL-encoded) is
replaced by `[redacted]` in tool results, the report and the proof of
concept. Values shorter than 4 characters are not replaced, and XSS screenshots
are not redacted.

### Limits — `data/limits.yaml`

Default limits of a run: model cost, model calls, requests, steps per finding,
run time and request rate. The options `--cost-limit`, `--max-calls`,
`--max-requests`, `--max-attempts`, `--max-duration` and `--rate` override them
per run (VER-015).

## Outputs

Written to `--output` (default `./verification`):

- `verification.md` — the report: one section per finding with verdict,
  evidence and its proof of concept, and the authorisation context.
- `verification.yaml` — the same results as data
  (`schemas/verification.schema.yaml`), each entry linked to its finding by id
  and `match_key` (VER-007, VER-020).
- `agent-log.jsonl` — written when the target is contacted: one JSON object per
  agent step of every finding, with `time`, `finding`, `step` and either the
  tool call (`tool`, `args`, `result` with status, body length, error or the
  browser's blocked requests), a step that was refused (`refused`, `proposal`),
  a limit that stopped the finding (`stopped`, `reason`) or the `verdict`
  (VER-017). A finding whose probe failed gets `probe_failed` with the error
  type and `at` with the file and line in the Verifier, never the error
  message; the finding under test when the run was interrupted gets
  `interrupted`. It holds no response bodies or source text, credential values are
  redacted (VER-016), and only the owner can read it. `--resume` continues it;
  otherwise each run starts it fresh.
- `evidence/` — owner-only: `<finding>-poc.har` for every tested finding (see
  proof of concept above), the proof records `<finding>-exchanges.json` and
  `<finding>-callback-hits.json` (see proof per class above), for an XSS marker
  that executed `<finding>-xss-<n>.json` with a screenshot `.png`,
  `<finding>-access-control-<n>.png` and `<finding>-exchange-<n>.png`. XSS
  screenshots are not redacted.
  Responses and screenshots are marked for review before sharing (VER-022).
- `security-assessment.annotated.yaml` — only with `--annotate`; with
  `--in-place` the assessment itself is changed instead (VER-027).

The `export` command writes `analyzer-verification.json` for AppSec Analyzer
(VER-021).
