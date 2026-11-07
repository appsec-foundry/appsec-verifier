# AppSec Verifier — CLI design

`appsec-verifier` is a standalone Python CLI (same packaging shape as
`appsec-analyzer`: `pipx install`, `console_scripts` entry point, a reviewed
`scripts/` + `schemas/` + `data/` runtime). It takes a finished
`security-assessment.yaml`, an authorisation **scope file**, and a running
target, verifies findings one at a time against the live application, and writes
a verification report. It never re-runs or re-scores the static assessment.

Design maps to `requirements.md` (VER-001 … VER-025); the relevant IDs are cited
per command and flag.

---

## Commands

`appsec-verifier --help` groups the commands as below.
`appsec-verifier <command> --help` lists each command's options.

**Act against a target** (makes model calls and network requests)

- `verify` — verify findings of an assessment against a running target.

**Inspect without touching the target** (no network, no model calls)

- `plan` — list which findings are dynamically verifiable, which are
  static-only, and which the input cannot support — without contacting the
  target (VER-006, VER-024).
- `scope` — resolve and print a scope file, show what is in and out of scope,
  and validate it against the schema (VER-001).

**Post-processing** (no model calls)

- `export` — re-emit the verdicts of a finished `verification.yaml` in a form
  AppSec Analyzer can read back; no re-verification (VER-021, VER-015).

---

## `verify` — verify findings against a running target

This is the command you run right after an AppSec Analyzer assessment. You point
it at the `security-assessment.yaml` that run produced, give it the boundaries of
what it may do (target scope, cost, request/time limits), choose which findings
to verify (by class, severity, CWE, or id), and decide whether it writes its own
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

Flow: load and schema-check the assessment (VER-005) → resolve the selection and
the scope and, interactively, **print both for one explicit confirmation**
(VER-002, VER-026) → probe the target for reachability and build/version match
(VER-003) → for each selected finding, run a bounded, scope-confined verification
of exactly that finding (VER-008, VER-015, VER-017) → write the report or
annotate the assessment, with evidence artefacts (VER-020, VER-027, VER-022).

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
| `--category LIST` | Categories, by class or finer technique: `access-control`, `idor`, `sqli`, `nosqli`, `xss`, `path-traversal`, `open-redirect`, `ssrf`, … So `--category idor` verifies IDOR alone — no CWE needed. (`plan` lists the available categories.) |
| `--severity LIST` | Exact severities, e.g. `critical,high`. |
| `--min-severity LEVEL` | Severity floor: `low\|medium\|high\|critical`. |
| `--only ID[,ID]` | Specific finding ids, e.g. `T-037,F-001`. Overrides the other selectors. |
| `--class LIST` | (advanced) weakness classes. |
| `--cwe LIST` | (advanced) specific CWEs, e.g. `CWE-79,CWE-639`. |

### Boundaries — cost and load (VER-015)

| Flag | Meaning |
| --- | --- |
| `--cost-limit USD` | Model-spend ceiling for the run. Default from `data/limits.yaml`. Interactive runs may ask to raise it; non-interactive runs stop (exit 3). Rejected with `codex-cli` and `copilot-cli`, which report no cost. |
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
| `--annotate [PATH]` | Add verification status to the assessment instead. Writes a copy next to the report by default; the bare in-place form needs the explicit `--in-place`. Never re-scores or removes a finding. | VER-027 |
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

Every host only proposes the next step as one JSON object; the Verifier
validates it strictly and executes it through the same scope-guarded tools for
every profile (VER-017, VER-019). The agent loop checks every step against the
strict tool schemas again, whichever profile produced it; an invalid step ends
the finding `inconclusive` and nothing runs. A failing step (target not
reachable, login rejected, unknown role) goes back to the agent as an error; a
check that fails entirely ends its finding `inconclusive` and the run goes on. The CLIs run in an empty temporary directory
with no built-in tools, MCP servers, settings, skills, custom instructions or
session history, and receive only the environment they need: no identity
secrets, and no API keys of other providers. `claude` and `codex-cli` also
check each call for tool use; a session that offers or uses a tool ends the
finding `inconclusive` and stops every later model call of the run. Copilot CLI
prints only the answer, so its confinement rests on the pinned version and its
flags. `codex-cli` and `copilot-cli` have only offline tests so far.

**Proof per class (VER-009 to VER-013).** A `confirmed` verdict must list the
steps that prove it in `proof_steps` (step numbers as in the prompt and in
`agent-log.jsonl`), and the code checks them against what the tools returned
(`agent/proof.py`). Access control: two cited `http_request` steps with the
same method, path, params and body, sent as two different identities (no role
counts as the anonymous one), both answered 2xx with a non-empty body.
Injection: two cited steps with the same method, path and identity but a
different input, answered with a different status or body; or, by timing,
cited steps with the same method, path and identity that split into at least
two undelayed and two delayed answers, every delayed one at least 2 s slower
than every undelayed one and sent with another input. `http_request` reports
`elapsed_ms`, the time httpx measured for the exchange (the wait for `--rate`
is not part of it); the agent is told to keep delays between 2 and 5 seconds.
XSS: a
`browser_check` in which the marker executed (below). Open redirect: a cited
`http_request` answered 301, 302, 303, 307 or 308 whose `Location` leads to
`<marker>.invalid`, a host drawn at random per finding and given to the agent;
`.invalid` never resolves (RFC 6761). `http_request` never follows redirects:
a 3xx answer is returned with its `location`, and any next hop is a request of
its own. Path traversal: a cited `http_request` whose response held the
content of the scope's `marker_file`, recognised in code (`marker_read`); the
model is told the file's path, never its content, which shows as
`[marker-file]` in every tool result, and a request that carried the content
does not count. SSRF: a request with the finding's marker reached the callback
listener; no `proof_steps` are needed. A
`confirmed` verdict that fails its check becomes `inconclusive`
("indicative, not proven: …") with the model's claim kept in the rationale. A
passing check replaces the model's evidence with the code's: for access control,
injection, open redirect and path traversal `evidence/<finding>-exchanges.json`
(owner-only) with method, path, params, body, identity, status, length and a
hash of the redacted response body per cited step, for a redirect the host it
leads to, for a traversal whether the marker was read; no response body and no
headers. For SSRF `evidence/<finding>-callback-hits.json` with time, method and
source address of each hit.

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
Each finding gets a random two-part
marker; the payload must call `alert('<part1>'+'<part2>')`, and only a dialog
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
pre-flight box says so and XSS findings cannot be confirmed.

**Safe mode (default, VER-030).** Unless `--allow-intrusive` is given, the run
stays read-only even when the scope permits state change, sends the single most
benign payload that can still decide a verdict, keeps request count and rate
low, and avoids pervasive or noisy behaviour (wordlist fuzzing, broad parameter
sweeps, many payload variants). Writing to the target — needed for stored XSS
and some IDOR cases — happens only with `--allow-intrusive`, the scope's
`allow_state_change` true, and `--read-only` unset; such requests use unique
markers, are logged, and are cleaned up where possible (VER-014). Deletes,
bulk/destructive operations, DoS, and evasion must never be performed, regardless
of flags. The code enforces the methods: safe mode sends only GET, HEAD and
OPTIONS, intrusive mode adds POST, PUT and PATCH, and DELETE and every other
method are refused in the HTTP client for every caller. A POST can still change
or remove data, so use intrusive mode only against a disposable test instance.

**Verifying one category.** The selectors isolate a single category —
`--category xss`, or `--category idor` for IDOR alone — and safe mode applies the
same way. Combine with a severity floor, e.g. `--category idor --min-severity high`.

### Interactive vs non-interactive

- **Interactive** (default, a TTY): the run prints the pre-flight box and waits
  for one confirmation before the first request (VER-002); if the cost ceiling
  would be hit it may ask to raise it (VER-015). This is the mode you use by hand
  right after an assessment.
- **Non-interactive** (`--non-interactive` / `--ci`, or no TTY): no prompts. The
  selection, the scope confirmation, and the cost ceiling must all be supplied on
  the command line; a missing confirmation or an exceeded ceiling stops the run
  rather than prompting. For CI gates and scripted post-assessment runs.

### What it looks like

The console mirrors AppSec Analyzer: a pre-flight box with the run settings and
the resolved scope, one line per finding as it is verified (`▶` started, `✓`
confirmed/blocked/etc., `·` detail) with elapsed and rough-remaining time, and a
closing summary block.

```
┌─ AppSec Verifier ───────────────────────────────────────────────┐
│ assessment   security-assessment.yaml  (juice-shop @ 1f3c9a2)    │
│ target       http://localhost:3000     reachable · build match   │
│ scope        localhost:3000  /*         window ok · owner: m.r.   │
│ selection    class=xss,access-control   min-severity=high  → 14   │
│ boundaries   cost ≤ $5.00 · ≤ 2000 req · ≤ 20 min · 5 rps         │
│ output       report → ./verification    state-change: allowed     │
│ mode         interactive                                          │
└──────────────────────────────────────────────────────────────────┘
Proceed against this target? [y/N]

▶ Verifying 14 selected findings  (0% · 0s elapsed)
✓ T-037  Stored XSS — about.component.ts:119      confirmed (high)
  · marker executed in browser · screenshot + HAR saved
✓ F-001  IDOR — GET /api/baskets/:id              confirmed (high)
  · customer-a read customer-b's basket
✗ T-052  Reflected XSS — search                   not-reproducible
  · payload reflected but Angular-sanitised, no execution
■ Verified 14 findings: 9 confirmed, 3 not reproducible, 2 blocked.
  cost $3.12 · 11m 40s · report: ./verification/verification.md
```

**Exit codes.** `0` all selected findings tested (whatever the verdict); `2`
run blocked before testing (bad/expired scope, unconfirmed authorisation,
unreachable target, missing required identity, empty selection); `3` a limit —
including the cost ceiling — stopped the run before all selected findings were
tested. Verdicts themselves never set a non-zero exit — a confirmed weakness is a
successful run.

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
  --format analyzer-annotations --output ./verification/analyzer-verification.json
```

Transforms a finished `verification.yaml` into a verdict set keyed by finding id
and the cross-run `match_key` (VER-007) that AppSec Analyzer can re-ingest to
annotate findings with their dynamic-verification status. Additive and explicit;
it never rewrites or re-scores the assessment (VER-021). No model calls (VER-015
philosophy: a saved, validated result exports without new work).

---

## Configuration files

### Scope file — `scope.yaml` (authorisation, VER-001)

The single authority for what the Verifier may contact. Schema:
`schemas/scope.schema.yaml`. Carries `base_url`, allowed `hosts`, `ports`,
`path_prefixes`, an authorisation `window` (`from`/`until`), the responsible
`owner`, `allow_state_change`, the callback listener used for SSRF proofs, and
the `marker_file` (path and token) used for path-traversal proofs. For authenticated targets it also carries `auth_hosts` (SSO / OIDC and
token endpoints the Verifier may contact only to log in — never probed for
findings) and `proxy` (an HTTP/HTTPS proxy to route target and auth traffic
through, with proxy credentials named as env vars). Anything not inside it —
target, auth host, or proxy — is refused, not attempted. `base_url` must be an
absolute http(s) URL with a host; a scope without a usable host or port allows
nothing. Paths are compared percent-decoded, `deny_paths` also regardless of
case, and a path a server could resolve to another resource (a `.` or `..`
segment, `//`, `\`, `;`, or `%2e`, `%2f`, `%5c`, `%3b`, `%25`, `%00`) is always
refused. Proxy variables in the environment (`HTTPS_PROXY` and the like) are
ignored; only the scope's `proxy` is used. Addresses are checked when the
connection is made (VER-018): each host name is resolved once, every address
it resolves to is checked, and the connection goes to a checked address, so a
DNS answer that changes after the scope check cannot steer a request elsewhere.
Public addresses are allowed. Loopback, private and other non-public addresses
need the scope's `networks` (CIDR list), unless the host is written as that
address or as `localhost`. Link-local addresses (cloud metadata at
169.254.169.254 included), other known metadata addresses, multicast,
unspecified and reserved addresses are never contacted. If any address of a
host is refused, the request is refused. Through a proxy only the proxy's
address is checked; the proxy resolves the target. Hosts in `proxy.no_proxy`
(exact names or addresses) are reached directly, and their addresses are
checked as without a proxy. The `window` is checked before every
request and every planning step, not only at start: once it has closed, the
current finding ends `inconclusive` with `limits_hit: window`, no further request
is sent, and the run exits with 3.

### Identities file — `identities.yaml` (sessions, VER-016/028)

Lists the test identities by **role label** and, per identity, the login
`method` and the environment variables that hold its credentials. The file holds
no secret values. Schema: `schemas/identities.schema.yaml`. Supported methods:
`bearer` (static token), `basic`, `form`, `oidc-password`,
`oidc-client-credentials`, `oidc-authorization-code`, and `none` (anonymous).

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
the target or a scope `auth_hosts` entry (VER-028), and attaches the session it
obtains only to its own origin: `auth.target_origin`, by default the target base
URL. A request as that role to any other origin is refused (VER-018). Before
the first request `verify` checks the file against the schema, checks that every
`*_env` variable it names is set, and that login endpoints and `target_origin`
lie inside the scope; any failure stops the run with exit 2 and names the
variable, never a value. `oidc-authorization-code` is not implemented yet and is
refused there. The HTTP client keeps no cookies: sessions travel only in the
headers the Verifier attaches, never in a cookie the target set for another
identity. Credential and token values
are read from the environment at run time, used only to obtain a session, and
never written to logs, the report, evidence artefacts, or any model prompt —
only the role label travels, and captured requests are redacted of Authorization
headers, cookies, and token parameters (VER-016, VER-022). If the target echoes a
credential, every value the run knows (each `*_env` value and each token
obtained, also JSON-escaped and URL-encoded) is replaced by `[redacted]` in tool
results before the model sees them and in the report; values shorter than 4
characters are not replaced. Screenshots are not redacted. Worked examples:
`examples/juice-shop/` (form login) and `examples/sso-proxy/` (OIDC + proxy).

### Limits — `data/limits.yaml`

Default execution bounds (requests, attempts, duration, rate), overridable per
run by the `--max-*` / `--rate` flags (VER-015).

---

## Outputs

Written under `--output` (default `./verification`):

- `verification.md` — human-readable report, one section per finding, verdict +
  evidence + authorisation context.
- `verification.yaml` — structured results (`schemas/verification.schema.yaml`),
  each entry keyed to the source finding by id + match_key (VER-007, VER-020).
- `agent-log.jsonl` — action log, written when a probe contacts the target: one
  JSON object per line for every agent step of every finding, with `time`,
  `finding`, `step` and either the tool call (`tool`, `args`, `result` with
  status, body length, error or the browser's blocked requests), a proposal the
  step contract refused (`refused`, `proposal`), a limit that stopped the
  finding (`stopped`, `reason`) or the `verdict`. Refused actions are logged, not
  only refused (VER-017). No response body or source text, credential values
  redacted (VER-016), owner-only (0600). `--append` extends it; otherwise each
  run starts it fresh.
- `evidence/` — request/response traces, browser events, screenshots, and
  callback records, redacted of credentials and sensitive target data (VER-022).
  Today only the proof browser writes here: `<finding>-xss-<n>.json` and `.png`
  when an XSS marker executed. Screenshots are not redacted and are marked so.
- `analyzer-verification.json` — optional Analyzer re-ingest export (VER-021),
  produced by `--format analyzer-annotations` or the `export` command.

## Runtime layout (planned)

```
appsec_verifier/            # package: version info, entry point
scripts/
  cli/            # argparse: verify, plan, scope, export
  loader/         # read + schema-check assessment, select findings, recompute match_key
  scope/          # scope resolution + connection-bound enforcement (VER-001/018)
  agent/          # verification agent loop + narrow tool wiring (VER-017/019)
  auth/           # session acquisition: bearer, basic, form, OIDC flows (VER-028)
  tools/          # scoped HTTP client (proxy-aware), sandboxed browser, marker/callback service
  probes/         # per-class proof logic: xss, access-control, injection, traversal...
  report/         # verification.yaml + verification.md writers, evidence store
  export/         # analyzer-annotations exporter
schemas/          # verification, scope, identities, analyzer-annotations (JSON Schema in YAML)
data/             # limits.yaml, verifiable-cwes.yaml
tests/            # safety-control tests (VER-025)
```
