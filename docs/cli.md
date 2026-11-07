# AppSec Verifier: command reference

`appsec-verifier` takes a finished `security-assessment.yaml`, an
authorisation scope file and a running target. It tests the selected findings
one at a time against the application and writes a verification report. It
never re-runs or re-scores the static assessment. For installation and a quick
start, see the [README](../README.md).

The requirement IDs (VER-001 to VER-033, [`requirements.md`](../requirements.md))
are cited per command and option.

## Commands

`appsec-verifier` without arguments lists the commands;
`appsec-verifier <command> --help` lists the options of one.

**Act against a target** (makes model calls and network requests)

- `verify` — verify findings of an assessment against a running target.
- `appsec-verifier ASSESSMENT` (no command) — the guided run: asks for the
  `verify` settings with defaults, then runs `verify` (VER-031).
- `preflight` — check the assessment, scope, proxy, target, logins and model
  profile without verifying anything; `--offline` contacts nothing (VER-032).

**Inspect without touching the target** (no network, no model calls)

- `plan` — list which findings are dynamically verifiable, which are
  static-only, and which the input cannot support, without contacting the
  target (VER-006, VER-024).
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
offline, shows how many findings it holds, how many are dynamically verifiable,
and their split by class and severity, then asks for the settings of the run.
Enter accepts the default shown in brackets.

| Question | Default | Same as |
| --- | --- | --- |
| Classes to verify | all verifiable classes present | `--category` |
| Lowest severity | `high` (High and Critical); `all` for no floor | `--min-severity` |
| Scope file | `scope.yaml` next to the assessment, else in the working directory | `--scope` |
| Target URL | the scope's `base_url` | `--url` |
| Identities file | `identities.yaml` next to the scope, the assessment, or in the working directory; else `none` | `--identities` |
| Model profile | `claude` | `--profile` |
| Change the run limits? | no: `data/limits.yaml`; yes asks each limit | `--cost-limit`, `--max-calls`, `--max-requests`, `--max-attempts`, `--max-duration`, `--rate` |
| Allow intrusive probes? | no; asked only when the scope has `allow_state_change: true` | `--allow-intrusive` |
| Existing report in the output directory | append; or overwrite, or a new directory | `--append`, `--output` |

Each answer goes through the same check as its option and is asked again when
invalid: a scope that is unreadable, schema-invalid or outside its window, a URL
outside the scope, an identities file with unset variables (named, never their
values), a profile that is not available, a limit that is not a positive number.
Options given on the command line are used as given and not asked, e.g.
`appsec-verifier ./security-assessment.yaml --scope ./scope.yaml`. No question
asks for a password, token, or other secret; credentials stay in environment
variables.

Without a scope file, Enter at the scope question writes a template to
`./scope.yaml` (never over an existing file) and stops with exit 2. The template
is invalid until its target, window and owner are filled in, so the next guided
run proposes it but refuses it until it is edited. The guided run never uses a
scope it wrote and never widens one.

After the questions the run shows the `verify` settings and the equivalent
non-interactive command line, e.g.

```
appsec-verifier verify --assessment ./security-assessment.yaml --scope ./scope.yaml \
  --url http://localhost:3000 --output ./verification --min-severity high \
  --profile claude --non-interactive --yes
```

and then asks the one confirmation of VER-002; answering the questions does not
confirm. Ctrl-C or end of input at any question stops with exit 2 and contacts
nothing.

`--non-interactive` (`--ci`), or standard input that is not a terminal, turns the
questions off: `appsec-verifier ASSESSMENT --ci --scope … --profile … --yes`
behaves like `verify` with the same options. A missing `--scope` or `--profile`
blocks the run with exit 2 and names both; a missing `--yes` blocks it at the
confirmation as in `verify`.

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
(VER-002, VER-026) → check that the target answers and every identity logs in,
the pre-flight checks of [`preflight`](#preflight--check-before-a-run-ver-032)
(VER-003, VER-032; the build/version match of VER-003 is *not implemented yet*)
→ for each selected finding, run a bounded, scope-confined verification of
exactly that finding (VER-008, VER-015, VER-017) → write the report or annotate
the assessment, with evidence artefacts (VER-020, VER-027, VER-022). A failed
pre-flight check stops the run before the first model call. Its requests count
against `--max-requests`.

During the run, `verify` prints one line per event on standard error, in the
columns `TIME FINDING EVENT PROGRESS ELAPSED LEFT DETAIL`, as AppSec Analyzer
does. FINDING is the finding under test and its position among the findings
that get a probe. EVENT is `start` and `done` for a finding, `·` for a request,
browser check or source read of the agent with its result, `↻` for a step the
Verifier refused, and `⚠` for a limit that stopped the finding. The `done` line
gives the verdict, the steps and the time the finding took, and for an
inconclusive finding the reason. PROGRESS is the share of findings done,
ELAPSED the run time. LEFT is estimated from the findings done so far and never
exceeds what `--max-duration` leaves; before the first finding is done it shows
that remainder (`≤29m`). In a terminal a status line underneath shows a progress
bar, the running step (the model call or the request) and its age. Without a
terminal, a line with the running step follows after two minutes without
output. The summary at the end adds a `Run` row: run time, model calls,
requests and, except with `codex-cli` and `copilot-cli`, the spend against
`--cost-limit`. Text from the assessment, the model or the target is shown
without control characters and without credential values.

### Input and target boundary

| Flag | Meaning | Req. |
| --- | --- | --- |
| `--assessment PATH` | `security-assessment.yaml` to verify (the one the Analyzer produced). | VER-005 |
| `--scope PATH` | Authorisation scope file (`schemas/scope.schema.yaml`). The only source of the target boundary, plus the declared proxy and auth hosts. | VER-001 |
| `--url URL` (alias `--target`) | Start/base URL to test. Must fall inside the scope; mismatch is refused. If omitted, the scope's `base_url` is used. | VER-001/004 |
| `--identities PATH` | Test-identity config (`schemas/identities.schema.yaml`): bearer, basic, form, or OIDC login per role. Secret **values** come from env, never this file. | VER-016/028 |
| `--proxy URL` | *Not implemented yet; set `proxy.url` in the scope file.* Route target and auth traffic through this HTTP/HTTPS proxy, overriding the scope's `proxy.url`. Proxy credentials still come from the env vars the scope names. | VER-029 |

### Select what to verify (VER-026)

All selectors read from the referenced assessment and combine with AND. With no
selector, the run verifies every *dynamically verifiable* finding (VER-006) and
says so before it starts. Prefer categories and severities over CWEs.

| Flag | Meaning |
| --- | --- |
| `--category LIST` | Categories, by class or finer technique: `access-control`, `idor`, `sqli`, `nosqli`, `xss`, `path-traversal`, `open-redirect`, `ssrf`, … So `--category idor` verifies IDOR alone; no CWE is needed. (`plan` lists the available categories.) |
| `--severity LIST` | Exact severities, e.g. `critical,high`. |
| `--min-severity LEVEL` | Severity floor: `low\|medium\|high\|critical`. |
| `--only ID[,ID]` | Specific finding ids, e.g. `T-037,F-001`. Overrides the other selectors. |
| `--class LIST` | (advanced) weakness classes. |
| `--cwe LIST` | (advanced) specific CWEs, e.g. `CWE-79,CWE-639`. |

### Boundaries — cost and load (VER-015)

| Flag | Meaning |
| --- | --- |
| `--cost-limit USD` | Model-spend ceiling for the run. Default from `data/limits.yaml`. Reaching it stops the run (exit 3). Rejected with `codex-cli` and `copilot-cli`, which report no cost. |
| `--max-requests N` | Hard cap on total requests to the target. |
| `--max-attempts N` | Cap on agent steps per finding (each step is one planner call: a tool call or the verdict). Default 12. Reaching it ends the finding `inconclusive` with `limits_hit: attempts`. |
| `--max-calls N` | Cap on model calls (planning steps) for the run, for every profile. |
| `--max-duration S` | Wall-clock cap; cancellable mid-run. |
| `--rate RPS` | Max request rate to the target and its login endpoints: every request, redirect hops and the proof browser's included, waits until it is 1/RPS seconds after the previous one. `0` turns the rate limit off. |

Every limit must be greater than 0; only `--rate` accepts 0. A negative or zero
cap blocks the run (exit 2) before anything is contacted, as does a key in
`data/limits.yaml` that the Verifier does not enforce. A failed request is not
retried; the only resend is one new login after the target answers 401.

### Output mode and run mode

| Flag | Meaning | Req. |
| --- | --- | --- |
| `--output DIR` | Report and evidence directory (created, owner-readable). Default `./verification`. | VER-020 |
| `--report` | Write a standalone report, leave the assessment untouched. **Default.** | VER-020 |
| `--print` | Also print the per-finding verdicts to the console. | VER-013 |
| `--append` | Extend an existing report in `--output` instead of overwriting: a finding verified again replaces its earlier result, others are kept, ids renumbered. | VER-027 |
| `--annotate` | Also write `security-assessment.annotated.yaml` to `--output`: a copy of the assessment with the verification status of each finding. Never re-scores or removes a finding. | VER-027 |
| `--in-place` | With `--annotate`, modify the referenced `security-assessment.yaml` itself. Explicit, never a default. | VER-027 |
| `--non-interactive` / `--ci` | No prompts: selection, scope confirmation, and cost ceiling all come from the invocation. Recorded in the report. | VER-002/026 |
| `--allow-intrusive` | Opt out of safe mode (below) for marked state-changing or more thorough probing. Recorded in the report. | VER-030 |
| `--read-only` | Force read-only even if the scope permits state change; overrides `allow_state_change`. | VER-014 |
| `--dry-run` | Resolve selection + scope and print the plan; send nothing to the target. | VER-008 |
| `--headful` | Run the proof browser visibly (local debugging only). | VER-009 |
| `--profile NAME` | Model profile (below), as in AppSec Analyzer. Default `claude`; required with `--non-interactive`. | VER-023 |
| `--model NAME` | Model for the selected profile; default is the profile's model. | — |

**Model profiles.** The profile decides which agent CLI or API plans each step.
An unavailable profile (CLI missing or too old, not logged in, key missing,
model unknown) stops the run before anything is contacted.

| Profile | Runs | Credentials | Default model | Spend |
| --- | --- | --- | --- | --- |
| `claude` | `claude -p` | Claude login, or `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` | `claude-opus-5-5` | reported USD (API-equivalent on a subscription) |
| `codex-cli` | `codex exec`, 0.163.0+ | ChatGPT login only | `gpt-sol` | not reported |
| `copilot-cli` | `copilot`, exactly 1.0.101 | Copilot login | `gpt-5.4` | not reported; soft limit of 30 AI credits per call |
| `codex` | OpenAI Responses API | `OPENAI_API_KEY` | `gpt-sol` | tokens × `data/model-catalog.yaml` prices |
| `anthropic-api` | Anthropic Messages API via the `anthropic` SDK (`[agent]`, 0.87+) | `ANTHROPIC_API_KEY` | `claude-opus-5-5` | tokens × `data/anthropic-model-catalog.yaml` prices (Opus 5.5, Sonnet 5.5, Haiku 5.5, Fable 5.1; Haiku 5.5 at its higher rates when a prompt exceeds 100 000 tokens); an unlisted model is refused |

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

- Access control: two cited requests with the same method, path, parameters and
  body, sent as two different identities (no role counts as anonymous), both
  answered 2xx with a non-empty body.
- Injection: two cited requests with the same method, path and identity but a
  different input, answered with a different status or body. Or, by timing: at
  least two delayed and two undelayed answers, every delayed one at least 2 s
  slower than every undelayed one. The time is measured per exchange, without
  the wait for `--rate`; the model is told to keep delays between 2 and 5
  seconds.
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

A `confirmed` verdict that fails its check becomes `inconclusive` ("indicative,
not proven: …"), with the model's claim kept in the rationale. When the check
passes, the code's record replaces the model's evidence. For access control,
injection, open redirect and path traversal that is
`evidence/<finding>-exchanges.json` (owner-only): per cited step the method,
path, parameters, body, identity, status, length and a hash of the redacted
response body, no response body and no headers. For SSRF it is
`evidence/<finding>-callback-hits.json` with time, method and source address of
each hit.

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
go back to the browser so each hop is checked, and anything else is aborted
(WebSockets and service workers included). Chrome itself is started inside a
network namespace of its own (`unshare --user --net --map-current-user`) that
has no interface but loopback, so traffic the interception never sees, such as
WebRTC/UDP, cannot leave the machine either. This needs Linux, `unshare` from
util-linux and unprivileged user namespaces. Chrome runs with its own sandbox.
Where the namespace or the sandbox is unavailable (other systems, some
containers), the browser does not start and XSS findings cannot be confirmed.

Each finding gets a random two-part marker; the payload must call
`alert('<part1>'+'<part2>')`, and only a dialog
showing the joined value counts, so a page that merely echoes the payload text
is not mistaken for execution. If any request of the probe carried the joined
value itself (also percent-encoded), the dialog does not count either: a page
that shows a parameter through `alert()` by design would display it without
any injected script. A `confirmed` XSS verdict without such an
executed marker is downgraded to `inconclusive` ("indicative, not executed"),
whatever the model says. On execution the browser draws a banner and saves a
screenshot and a JSON event record under `evidence/` (owner-only). Screenshots
can show target data; the report marks them for review before sharing, and the
Analyzer export never references them. Without Playwright or Chrome the
`Browser` line in the run settings says so and XSS findings cannot be confirmed.

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

The console looks like AppSec Analyzer's. Before the first request `verify`
prints its settings as `Key : value` lines: the assessment, the target, the
scope and its owner, the selection, the profile and model, the limits and the
mode (safe or intrusive), and asks `Proceed against this target? [y/N]`. At the
end it prints `Done` with the number of findings per verdict and the paths of
the report files. `--print` adds one line per finding with its verdict (`✓`
confirmed, `✗` not reproducible, `⊘` blocked by a control, `?` inconclusive,
`·` not attempted) and the rationale.

On a terminal the output is in colour and starts with the logo: a confirmed
finding is red, not reproducible or blocked green, inconclusive yellow, and
severities and pre-flight results have their own colours. `NO_COLOR` (any
value) turns colour off, `FORCE_COLOR=1` turns it on without a terminal, and
`COLORTERM=truecolor` selects the 24-bit palette. Without a terminal, for
example in CI or when redirected to a file, the output is plain text.

**Exit codes.**

| Code | Meaning |
| --- | --- |
| `0` | All selected findings were tested, whatever the verdict. A confirmed weakness is a successful run. |
| `2` | The run was blocked before testing: malformed assessment, invalid or expired scope, unset proxy or identity variable, unusable model profile, missing confirmation, unreachable target, rejected login, or empty selection. |
| `3` | A limit was reached for at least one finding, for example the cost ceiling, the request cap, the steps per finding, or the end of the scope window. |

## `preflight` — check before a run (VER-032)

```
appsec-verifier preflight --assessment ./security-assessment.yaml --scope ./scope.yaml \
  [--url URL] [--identities ./identities.yaml] [--profile P] [--model M] \
  [--offline] [--json] [--yes] [--non-interactive] \
  [--test-model (--cost-limit USD | --max-calls 1)]
```

Runs the checks `verify` runs before its first model call, and verifies nothing.
Each check prints one line: `✓` passed, `⚠` works with a caveat, `✗` failed,
`·` not checked or not applicable.

| Check | What it does | Contacts |
| --- | --- | --- |
| Assessment | Checks the fields the Verifier reads against `schemas/assessment.schema.yaml` and that finding ids are unique. Shows project, date, and how many findings are dynamic, static-only, input-incomplete. Messages name the place and the rule; only a repeated id is quoted, escaped. | nothing |
| Scope | Schema, window, URL inside the scope. | nothing |
| Proxy | The proxy URL is http(s) without inline credentials, and `username_env`/`password_env` are both set. | nothing |
| Identities | Schema, every `*_env` variable set, endpoints and `check_url` inside the scope. | nothing |
| Model | The profile resolves (CLI present and logged in, or key set; model known and priced). For `codex` and `anthropic-api` one metadata request shows the key is accepted and the model offered; it generates nothing and proves no quota. | the provider (not with `--offline`) |
| Target | One GET to the URL through the scope gate and the declared proxy. A redirect is not followed. Any HTTP answer counts as reachable; 5xx warns. A failure names its cause: name resolution, refused connection, timeout, TLS certificate or handshake, proxy refusal or proxy authentication (407), or an address the scope refuses. | the target |
| per role | One login for `form` and OIDC identities, never retried. With `auth.check_url`, one GET there with the identity's credentials: 2xx accepted, 401/403 rejected, anything else unclear. `bearer` and `basic` without `check_url` are reported as not checked against the target. | target, login endpoints |
| Model test | Only with `--test-model`: one fixed prompt without target data, findings or credentials. Passes when the host stays confined and replies with exactly the requested step. | the provider |

The offline checks run first. If one fails, nothing is contacted. The target and
login checks run only after one explicit confirmation (VER-002): at the prompt,
or with `--yes`. `--non-interactive` without `--yes` contacts nothing and fails.
A failed target check skips the logins.

`--test-model` needs its own limit: `--cost-limit` of at least USD 0.01 for
`claude`, `codex` and `anthropic-api`, `--max-calls 1` for `codex-cli` and
`copilot-cli`. It cannot be combined with `--offline` and runs only when all other
checks passed.

`--json` prints `{"kind": "preflight", "ok": …, "verification": "not_run",
"checks": [{"check", "status", "message"}]}` on stdout and the progress lines on
stderr. It never prompts, so contacting the target needs `--yes`.

Messages never contain a secret, a token, a response body or a raw error text,
which can hold proxy credentials (VER-016). Exit code `0` when no check failed,
`2` otherwise.

## `plan` — what is verifiable, offline

```
appsec-verifier plan --assessment ./security-assessment.yaml [--class LIST]
```

Reads the assessment and prints, per finding: id, title, CWE, class, and whether
it is `dynamic` (verifiable), `static-only` (out of scope for dynamic
verification, with reason), or `input-incomplete` (missing evidence
file/line/route). No target contact, no model calls (VER-006, VER-024).

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
`analyzer-verification.json` in the working directory, JSON format.

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

The scope file is the only source of what the Verifier may contact. Schema:
`schemas/scope.schema.yaml`; examples in `examples/`. A minimal scope needs
`schema_version`, `base_url`, `window` and `owner`; the README's quick start
shows one.

| Key | Meaning |
| --- | --- |
| `base_url` | Absolute http(s) URL of the target. Hosts and ports default to those of this URL. |
| `hosts`, `ports`, `schemes`, `path_prefixes` | What may be contacted. `schemes` defaults to `https`. |
| `deny_paths` | Paths that are never contacted, compared regardless of case and percent-encoding. |
| `networks` | CIDR ranges of private or loopback addresses that may be contacted (see below). |
| `window` | Authorised test period (`from`, `until`, ISO 8601 UTC). |
| `owner` | The person or party responsible for the test. |
| `allow_state_change` | `true` allows writing requests together with `--allow-intrusive` (VER-030). |
| `auth_hosts` | SSO, OIDC and token endpoints that may be contacted only to log in, never tested. |
| `proxy` | HTTP(S) proxy for target and login traffic; credentials are named as environment variables (`username_env`, `password_env`), never in the URL. `no_proxy` lists hosts reached directly. |
| `callback` | Listener for SSRF proofs (see above). |
| `marker_file` | Path and token of the marker file for path-traversal proofs. |

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
replaced by `[redacted]` in tool results and in the report. Values shorter
than 4 characters are not replaced, and screenshots are not redacted.

### Limits — `data/limits.yaml`

Default limits of a run: model cost, model calls, requests, steps per finding,
run time and request rate. The options `--cost-limit`, `--max-calls`,
`--max-requests`, `--max-attempts`, `--max-duration` and `--rate` override them
per run (VER-015).

## Outputs

Written to `--output` (default `./verification`):

- `verification.md` — the report: one section per finding with verdict,
  evidence and the authorisation context.
- `verification.yaml` — the same results as data
  (`schemas/verification.schema.yaml`), each entry linked to its finding by id
  and `match_key` (VER-007, VER-020).
- `agent-log.jsonl` — written when the target is contacted: one JSON object per
  agent step of every finding, with `time`, `finding`, `step` and either the
  tool call (`tool`, `args`, `result` with status, body length, error or the
  browser's blocked requests), a step that was refused (`refused`, `proposal`),
  a limit that stopped the finding (`stopped`, `reason`) or the `verdict`
  (VER-017). It holds no response bodies or source text, credential values are
  redacted (VER-016), and only the owner can read it. `--append` extends it;
  otherwise each run starts it fresh.
- `evidence/` — owner-only proof records: `<finding>-exchanges.json` and
  `<finding>-callback-hits.json` (see proof per class above), and for an XSS
  marker that executed `<finding>-xss-<n>.json` with a screenshot `.png`.
  Screenshots are not redacted and are marked for review before sharing
  (VER-022).
- `security-assessment.annotated.yaml` — only with `--annotate`; with
  `--in-place` the assessment itself is changed instead (VER-027).

The `export` command writes `analyzer-verification.json` for AppSec Analyzer
(VER-021).
