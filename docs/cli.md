# AppSec Verifier: command reference

`appsec-verifier` takes a finished `security-assessment.yaml`, an authorisation scope file and a running target. It tests the selected findings one at a time against the application and writes a verification report. It never re-runs or re-scores the static assessment. For installation and a quick start, see the [README](../README.md).

The requirement IDs (VER-…) from [`requirements.md`](../requirements.md) are cited per command and option.

## Commands

`appsec-verifier` without arguments, or with `--help`, lists the commands with examples. `appsec-verifier <command> --help` lists the options of one by group, with example calls; `appsec-verifier ASSESSMENT --help` does the same for the guided run. A wrong call shows the short usage, the error and where the examples are. Options count only as written: an abbreviation such as `--show-cost` is an error that names the option meant (`did you mean --show-costs?`), and nothing is contacted.

**Act against a target** (makes model calls and network requests)

- `verify` — verify findings of an assessment against a running target.
- `appsec-verifier ASSESSMENT` (no command) — the guided run: asks for the `verify` settings that have no usable default, then runs `verify` (VER-031).
- `preflight` — check the assessment, scope, proxy, target, logins and model profile without verifying anything; `--offline` contacts nothing (VER-032).

**Inspect without touching the target** (no network, no model calls)

- `scope` — resolve and print a scope file, show what is in and out of scope, and validate it against the schema (VER-001).

**Post-processing** (no model calls)

- `export` — re-emit the verdicts of a finished `verification.yaml` in a form meant for AppSec Analyzer, which does not read it yet; no re-verification (VER-021, VER-015).

**Maintain the installation**

- `update` — update a pipx installation of the Verifier after your yes (VER-033).

## Guided run — `appsec-verifier ASSESSMENT` (VER-031)

Called with an assessment and no command, the Verifier reads the assessment offline, shows how many findings it holds, how many can be tested against the running app and how many are unsupported or incomplete, and their split by class and severity, then asks only for what has no usable default. What the selected findings need (a test identity, the proof browser, a marker file, a callback) is shown in the test plan of `verify`; `preflight` shows how to provide it.

Without options the run tests findings of severity high and above, of every class present, with the profile `claude` and the limits of `data/limits.yaml`. `--min-severity`, `--category`, `--profile`, `--cost-limit`, `--max-calls`, `--max-requests`, `--max-attempts`, `--max-duration` and `--rate` change that. The run prints the selection, e.g. `→ 24 findings to verify, severity high and above (--min-severity to change)`, and shows the floor again in the `Selection` line before the confirmation. If no finding of severity high or above can be verified dynamically, it asks whether to verify those of the next lower severity that has any, e.g. `Verify the 3 of severity medium? [Y/n]`; no ends the run without contact. A profile that is not available ends the run before any question and names `--profile`.

Questions come only where there is no usable default. Enter accepts the default shown in brackets.

| Question | Default | Same as |
| --- | --- | --- |
| Target URL | none; asked only without a scope file (below) | `--url` |
| Identities file | asked only when `identities.yaml` is found next to the scope, the assessment, or in the working directory, and not with `--account` or `--admin-account`; `none` for no identities. A file that starts login programs needs its own `Run them? [y/N]` | `--identities` |
| Allow intrusive probes? | no; asked only when the scope has `allow_state_change: true` | `--allow-intrusive` |
| Existing report in the output directory | `There is already a report in ./verification. Overwrite it? [y/N]`; a no stops the run before anything is contacted. Not asked with `--overwrite` or `--resume`, nor without a terminal, where the run stops as `verify` does | `--output`, `--overwrite`, `--resume` |

Each answer goes through the same check as its option and is asked again when invalid: a URL without http or https, with a user name or password, or with an ambiguous path, or an identities file that cannot be used. Options given on the command line are used as given and not asked, e.g. `appsec-verifier ./security-assessment.yaml --target http://localhost:3000` asks nothing but the confirmation. A credential variable the identities file names but the environment lacks is asked for without echo, e.g. `alice: VERIFIER_ALICE_PASS (password_env) is not set; enter its value (hidden):`; Enter alone leaves it unset. The value is kept only for this run, never written and never put into the environment.

A `scope.yaml` next to the assessment, else in the working directory, is used without a question; the run prints its path. If it cannot be used, for instance because its window has closed, the run stops with exit 2 and says why. Correct the file, or move it away to enter a target URL instead.

Without a scope file the run asks for the target URL, which has no default and is never taken from the assessment. The run then tests only that URL's scheme, host and port, as `verify --url` does without `--scope`, and writes no file.

Without an identities file, when the selection holds access-control findings for which the scope declares `test_resources`, the run offers to take the session of each role those resources name from your browser: `Paste sessions for user-a, user-b? [y/N]`. Sign in to the application as that user (a private window or another browser profile for the second one), open the developer tools, and in the Network tab copy any request the application sends to the target with "Copy as cURL (bash)". Paste it at `Request copied as user-a (hidden; Enter alone skips this role):` and press Enter. The pasted text is not echoed and never run; the run keeps only its Cookie and Authorization headers and refuses a request to another site. When the copied request was a GET, the pre-flight check sends it once with the session to see that it is accepted. Pasted sessions are not renewed, so a session that expires during the run ends that role's tests. The equivalent invocation printed before the confirmation does not include them; for a repeatable run put them in an identities file with `method: session`.

After the questions the run shows the `verify` settings and the equivalent non-interactive command line, e.g.

```
appsec-verifier verify --assessment ./security-assessment.yaml \
  --url http://localhost:3000 --output ./verification --min-severity high \
  --profile claude --non-interactive --yes
```

and then asks the one confirmation of VER-002 as `[Y/n]`: Enter starts the run. Answering the questions does not confirm. Ctrl-C or end of input at any question stops with exit 2 and contacts nothing.

`--non-interactive` (`--ci`), or standard input that is not a terminal, turns the questions off: `appsec-verifier ASSESSMENT --ci --scope … --profile … --yes` behaves like `verify` with the same options. Without `--scope` or `--url`, or without `--profile`, the run stops with exit 2 and names what is missing; a missing `--yes` blocks it at the confirmation as in `verify`.

## `verify` — verify findings against a running target

`verify` takes the `security-assessment.yaml` of an AppSec Analyzer run, the scope and limits of the test, and the selection of findings, and writes its own report; with `--annotate` also annotated copies of the assessment and of the Analyzer's report.

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

Flow: check the assessment's structure, the scope and proxy settings, the identities file and the model profile (VER-005, VER-032) → resolve the selection and the scope and, interactively, **print both for one explicit confirmation** (VER-002, VER-026) → check that the target answers, that every identity logs in, and that the model answers one fixed prompt, the pre-flight checks of [`preflight`](#preflight--check-before-a-run-ver-032) (VER-003, VER-032; the build/version match of VER-003 is *not implemented yet*) → for each selected finding, run a bounded, scope-confined verification of exactly that finding (VER-008, VER-015, VER-017) → write the report with evidence artefacts and, with `--annotate`, the annotated copies (VER-020, VER-022, VER-027, VER-038). Each check prints one line under `Preflight`. A failed check stops the run before the first finding (exit 2). Its requests count against `--max-requests`; the model test counts as one model call against `--max-calls` and `--cost-limit`.

Before the confirmation, `Test plan` lists the findings the run will test, each with its severity, class, the requests the assessment names for it (for example `GET /rest/basket/:id (login)`) and its title. The requests come from the finding's scenario and attack steps and from the assessment's `attack_surface`: an entry point that matches a named request, or whose handler is at the finding's location, gives the path template and, with `auth_required: true`, the `(login)` mark. `page /#/search` is a browser route. The agent gets these requests and the finding's scenario and attack steps; without `--source` it is not offered `read_source`.

`Not testable` groups the findings this run cannot confirm by what they need, with how to provide it: a test identity (an access-control finding, or one whose named requests all need a login), an access request (an access-control finding without a `test_resources` entry whose named requests allow none of the proofs: a GET request for the comparison with an `--admin-account`, or a write request that creates a record, one that names no existing record in its path, together with a GET request or a write request that changes the record by its identifier; a DELETE is never sent), the proof browser (XSS), a marker file (path traversal), a callback (SSRF), an injection contract (an injection finding without its `injection_inputs` entry), a route (the assessment names no request for the finding and there is no `--source` to read one from), intrusive mode (every named request writes), a test capability (a reported variant needs a tool the run lacks), or a repeatable request (every request an injection finding names writes and its `injection_inputs` entry, if any, declares no query parameter, which a GET request on its path would carry; the proof sends each control twice but never repeats a write, so `--allow-intrusive` does not help). `verify` names what to provide in a few words; `preflight` shows how, with the lines to copy into a scope file. They are not tested and appear in the report as `not-attempted` with the reason; `--test-all` tests them anyway. When nothing is left to test, the run stops with exit 2: nothing is contacted and no report is written.

During the run, `verify` prints one entry per event on standard error, in the columns `TIME FINDING EVENT PROGRESS ELAPSED LEFT DETAIL`, as AppSec Analyzer does. A blank line separates the findings. FINDING is the finding under test and its position among the findings that get a probe. The `start` entry gives its title, then its severity, class and up to two requests from the test plan, then the agent that tests it: its model in short form and its runtime (`agent Sonnet 4.5 via Claude CLI`), its steps (`≤12 steps`, set with `--max-attempts`), the identities it may act as, and `source code` when `--source` lets it read the source. A finding that is not tested because an earlier finding reached a run-wide limit has no agent row. EVENT is `start` and `done` for a finding, `·` for a request, browser check or source read of the agent, `↻` for a step the Verifier refused, and `⚠` for a limit that stopped the finding. A `·` entry gives the agent's note on what the step checks, then the request with its query and JSON body, the result, how long the model took to propose the step (`model 14s`) and, when costs are shown, what the step's model call cost (`$0.04`). The `done` entry gives the verdict, the steps, the time the finding took, when costs are shown the finding's model cost and the run's spend (`$0.08 · run $0.42 of $10.00`), then the agent's rationale; a confirmed verdict also says `proof checked`, because it stands only when the Verifier found the proof its class requires. In a terminal these parts stand on rows of their own: the title in bold, the tested request in its own colour under the note, the rationale under the verdict, and the amounts highlighted. Without a terminal each entry is one line. Under it a line names each screenshot the finding produced and where it lies (`screenshot verification/evidence/T-036-xss-1.png`): its EVENT is `proof` when the Verifier checked the verdict's proof, otherwise `img`. The verdict is green when the finding is confirmed, red when it was not reproduced or a control blocked it (a likely false positive), and yellow when it stays inconclusive; the results at the end use the same colours. When a Claude CLI call fails, the reason names the CLI's error kind where it reports one, for example `host_error (error_max_turns, exit 1)`. PROGRESS is the share of findings done, ELAPSED the run time. LEFT is estimated from the findings done so far and never exceeds what `--max-duration` leaves; before the first finding is done it shows that remainder (`≤29m`). In a terminal a status line underneath shows a progress bar, when costs are shown the run's spend so far (`$0.42 of $10.00`), the running step (`Sonnet 4.5 plans` during the model call, otherwise the request) and its age. Without a terminal, a line with the same follows after two minutes without output. The summary at the end adds a `Run` row: run time, model calls, requests and, when costs are shown, the spend against `--cost-limit`. Costs are shown with API billing (`codex`, `anthropic-api`, and `claude` with `ANTHROPIC_API_KEY` or a login that bills the API), and with `--show-costs` in any mode, as in AppSec Analyzer. With a Claude subscription the amount is what the calls would cost at API prices and is marked `at API prices`; with `codex-cli` and `copilot-cli` the `Run` row says `cost not reported (subscription)`. Text from the assessment, the model or the target is shown without control characters and without credential values.

### Input and target boundary

| Flag | Meaning | Req. |
| --- | --- | --- |
| `--assessment PATH` | `security-assessment.yaml` to verify (the one the Analyzer produced). | VER-005 |
| `--scope PATH` | Authorisation scope file (`schemas/scope.schema.yaml`): the target boundary, the declared proxy and auth hosts, the test window and the owner. Without it, `--url` alone sets the boundary. | VER-001 |
| `--url URL` (alias `--target`) | Start/base URL to test. With `--scope` it must fall inside the scope; a mismatch is refused, and without `--url` the scope's `base_url` is used. Without `--scope` it is required and is the whole boundary: its scheme, host and port, with no window and no owner. | VER-001/004 |
| `--identities PATH` | Test-identity config (`schemas/identities.schema.yaml`): per role a bearer token, basic, form, copied browser headers, an OIDC flow or a login program. Secret **values** come from env, or are asked hidden in an interactive run, never from this file. | VER-016/028/040 |
| `--account USER[=VAR]` | A test account by user name, instead of `--identities`; repeat it for a second account. The password comes from the variable `VAR`, or is asked hidden. See [Test accounts on the command line](#test-accounts-on-the-command-line-ver-041). | VER-041 |
| `--admin-account USER[=VAR]` | A privileged test account. It sends only GET, HEAD and OPTIONS, also with `--allow-intrusive`. | VER-041 |
| `--login-url URL` | Where `--account` and `--admin-account` sign in. Default: the login entry point the assessment names for the target. | VER-041 |
| `--proxy URL` | *Not implemented yet; set `proxy.url` in the scope file.* Route target and auth traffic through this HTTP/HTTPS proxy, overriding the scope's `proxy.url`. Proxy credentials still come from the env vars the scope names. | VER-029 |

### Select what to verify (VER-026)

All selectors read from the referenced assessment and combine with AND. With no selector, the run verifies every *dynamically verifiable* finding (VER-006) and says so before it starts. Prefer categories and severities over CWEs.

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

Every limit must be greater than 0; only `--rate` accepts 0. A negative or zero cap blocks the run (exit 2) before anything is contacted, as does a key in `data/limits.yaml` that the Verifier does not enforce.

Once the cost ceiling, the request cap, the call cap, the run time or the scope window is reached, the finding under test ends `inconclusive` and the remaining findings are not tested: they appear as `not-attempted` with the limit in `limits_hit`, no further model call is made, and the run exits with 3. After three failed model calls in a row, for example an exhausted quota or a rejected key, the run makes no further model call and the remaining findings end `inconclusive` with the reason.

A session whose expiry is known (an OIDC `expires_in`, the `exp` of a JWT, or a login program's `expires_at`) is renewed a minute before it expires: with the refresh token where the flow issued one, otherwise by logging in again or running the login program again. A session from environment variables or a paste is not renewed and is no longer sent once it has expired. A failed request is not retried; only GET, HEAD and OPTIONS may be resent once after a 401 and session renewal. POST, PUT and PATCH are never automatically resent. When the request is answered 401 again with the new session, that identity is not logged in again until one of its requests is accepted. A login the target refuses is not tried again in the run. Each answer is read for at most 30 seconds and up to 10 MiB after decompression; a slower or larger answer ends that request with an error the agent sees.

Ctrl-C stops the run: the finding under test ends `inconclusive`, the remaining ones are `not-attempted`, the report is written with the results so far and `meta.interrupted: true`, and the run exits with 130.

### Continuous control (VER-036)

Before each model call and tool action, the Verifier checks the remaining time and authorisation window. It checks every request in a batch separately. Active work, including final proof rendering and screenshots, is interrupted when either deadline expires. Recorded exchanges are saved without browser or network activity, with a separate five-second shutdown allowance. A screenshot timeout preserves the established verdict and recorded evidence, notes the missing rendering and stops further findings. This requires a POSIX main thread; active verification stops where that deadline mechanism is unavailable. Offline commands remain available.

A request must match a route in the selected finding variant, the finding's declared endpoints or its operator-declared test resources. With source access, the nearest preceding literal `get('/route', ...)`, `app.get` or `router.get` declaration within 40 lines of the finding's evidenced location can also supply a route, including corresponding HTTP methods. Missing routes stop requests rather than allowing guesses. An accepted test plan narrows subsequent requests to its route and method; experiment requests must use its declared input and control values. Access-control requests retain the declared resource inputs and roles. When the Verifier creates the resource itself, the owning account, and no other, may also write to the finding's routes. Variant input declarations also restrict parameter names. Diagnostic requests may precede a plan within those same boundaries.

The same read action or request may execute twice per finding, allowing repeated proof controls. The same write request may execute only once. A third repetition stops before execution. Three consecutive tool errors or HTTP server errors stop before the next model call. Rewording a plan does not reset these allowances. A plan the Verifier rejects does not count as a repetition, so the corrected plan can still run; its rejection still counts as a tool error. The finding ends `inconclusive` with `limits_hit: stagnation`, its reason and collected evidence; other findings may continue. This is not a negative verdict about the target.

Model decisions, request actions and actual HTTP requests are counted separately. `--max-attempts` limits both decisions and HTTP/browser actions per finding. A batch uses one decision but multiple request actions; browser resources and logins count against `--max-requests`. The model receives the remaining decision and request allowances with each step.

Source files larger than 1 MiB are refused before decoding. Agent CLI stdout and stderr together are limited to 1 MiB while they are read; exceeding that limit terminates the process group. Marker restrictions also apply to query parameters embedded in request URLs.

### Output mode and run mode

| Flag | Meaning | Req. |
| --- | --- | --- |
| `--output DIR` | Report and evidence directory (created, owner-readable). Default `./verification`. | VER-020 |
| `--report` | Write a standalone report, leave the assessment untouched. **Default.** | VER-020 |
| `--print` | List every finding in the results at the end, unsupported or incomplete ones included, with the whole reason. | VER-013 |
| `--show-costs` | Show model costs on the console also with subscription billing; by default only with API billing (see the `Run` row above). Changes no limit and nothing in the report. | VER-015 |
| `--resume` | Continue the report in `--output`: findings with confirmed, not-reproducible or blocked-by-control and a code-checked proof contract 3 keep it; older or unchecked results are tested again; the other selected findings (inconclusive, not attempted, or not in the report) are tested and their results replace the earlier ones. The action log is continued. When every selected finding has a verdict, nothing is contacted (exit 0). Without a report in `--output` the run starts as usual. A report that cannot be read, does not match `schemas/verification.schema.yaml`, or was written for another assessment (by SHA-256) or target blocks the run (exit 2) before anything is contacted. Cannot be combined with `--overwrite`. | VER-027 |
| `--overwrite` | Replace a report already in `--output` (`verification.md` or `verification.yaml`). Without it, and without `--resume`, such a report stops the run (exit 2) before anything is contacted. | VER-027 |
| `--annotate` | Also write two copies to `--output` and leave the originals unchanged: `security-assessment.annotated.yaml`, the assessment with a `dynamic_verification` block per finding, and `security-assessment.annotated.md`, the Analyzer's Markdown report with the results. See [Annotated copies](#annotated-copies-ver-027-ver-038-ver-039). | VER-027/038/039 |
| `--non-interactive` / `--ci` | No prompts: selection, scope confirmation, and cost ceiling all come from the invocation. Recorded in the report. | VER-002/026 |
| `--allow-intrusive` | Opt out of safe mode (below) for marked state-changing or more thorough probing, with or without a scope file. A scope file with `allow_state_change: false` stops such a run before anything is contacted. Recorded in the report. | VER-030 |
| `--read-only` | No write requests, even with `--allow-intrusive`. | VER-014 |
| `--dry-run` | Resolve selection + scope and print the plan; send nothing to the target. | VER-008 |
| `--test-all` | Also test findings this run cannot confirm (see the test plan below); by default they are not tested and reported `not-attempted` with the reason. | VER-008 |
| `--headful` | Run the proof browser visibly (local debugging only). | VER-009 |
| `--screenshots CLASSES` | Classes that get screenshots, comma-separated: `xss`, `access-control`, `injection`, `open-redirect`, `path-traversal`, `ssrf`, `session`; or `none`. Default: all. Without screenshots an XSS proof still holds. | VER-035 |
| `--profile NAME` | Model profile (below), as in AppSec Analyzer. Default `claude`; required with `--non-interactive`. | VER-023 |
| `--model NAME` | Model for the selected profile; default is the profile's model. | — |

**Model profiles.** The profile decides which agent CLI or API plans each step. An unavailable profile (CLI missing or too old, not logged in, key missing, model unknown) stops the run before anything is contacted.

| Profile | Runs | Credentials | Default model | Spend |
| --- | --- | --- | --- | --- |
| `claude` | `claude -p` | Claude login, or `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` | `claude-sonnet-5-5` | reported USD (API-equivalent on a subscription) |
| `codex-cli` | `codex exec`, 0.163.0+ | ChatGPT login only | `gpt-sol` | not reported |
| `copilot-cli` | `copilot`, exactly 1.0.101 | Copilot login | `gpt-5.4` | not reported; soft limit of 30 AI credits per call |
| `codex` | OpenAI Responses API | `OPENAI_API_KEY` | `gpt-sol` | tokens × `data/model-catalog.yaml` prices |
| `anthropic-api` | Anthropic Messages API via the `anthropic` SDK (`[agent]`, 0.87+) | `ANTHROPIC_API_KEY` | `claude-sonnet-5-5` | tokens × `data/anthropic-model-catalog.yaml` prices (Opus 5.5, Sonnet 5.5, Haiku 5.5, Fable 5.1; Haiku 5.5 at its higher rates when a prompt exceeds 100 000 tokens); an unlisted model is refused |

Whatever the profile, the model only proposes the next step as one JSON object. The Verifier checks it against strict schemas and runs it with the same scope-guarded tools (VER-017, VER-019). Nothing invalid runs: a tool call with arguments outside its schema goes back to the model as an error and counts as a failed step, and any other invalid step ends the finding `inconclusive`. A step that fails (target not reachable, login rejected, unknown role) goes back to the model as an error. A finding whose check fails entirely ends `inconclusive`, and the run goes on.

The CLIs run in an empty temporary directory without built-in tools, MCP servers, settings, skills, custom instructions or session history. They get only the environment they need: no identity secrets and no API keys of other providers. `claude` and `codex-cli` also check each call for tool use; a session that offers or uses a tool ends the finding `inconclusive` and stops all later model calls of the run. Copilot CLI prints only the answer, so its isolation rests on the pinned version and its flags. `codex-cli` and `copilot-cli` have only offline tests so far.

**Proof per class (VER-009 to VER-013).** A `confirmed` verdict must name the steps that prove it in `proof_steps` (step numbers as in `agent-log.jsonl`). The code checks them against what the tools returned (`agent/proof.py`):

- Access control: declare a test with an operator-supplied `test_resources` entry. The same method, path and inputs must return its known harmless marker both for an allowed role and a denied role with independent credentials. Two successful responses alone do not establish unauthorized access. A `test_resources` entry always takes precedence and gives confidence `high`. Without one, IDOR and missing-authorisation findings (CWE-639, 862, 863) can be proven in two more ways, each with confidence `medium`:
  - Own resource, with two normal accounts and `--allow-intrusive`: the Verifier draws a random marker for the finding. One account, the owner, creates something with one write to a route of the finding that names no existing record in its path, such as a POST to a collection, that holds the marker, and reads it back. The same GET without a login must not show the marker, otherwise the resource is public and the finding stays `inconclusive`. If the other account's GET shows the marker, the finding is `confirmed`; 403 or 404 gives `blocked-by-control`. Only the owner may send the marker, and a read that sends it does not count. The created record stays on the target; the report gives its marker under `proof.marker`.
  - Write on the own resource, for a finding whose request changes a record by its identifier, such as `PUT /api/Feedbacks/:id`, with the same accounts: the plan names that request as its change, and the Verifier draws a second marker. The owner creates the record as above and reads it back. The other account then sends the change with the second marker to the identifier the creating answer returned, in the `id` field of the answer or of its `data` wrapper or in the `Location` header, once the owner's read has shown the first marker there; any other identifier is refused, also that of a record nested in the answer, such as its owner. If the owner's next read shows the second marker, the finding is `confirmed`; if the change was answered 403 or 404 and the read still shows the first marker, it is `blocked-by-control`. When the finding names no GET request, the record is read with GET on the path of the change, and only that record. Without a request that creates a record and one that changes it, this proof is not available. The record with both markers stays on the target; the report gives them under `proof.marker` and `proof.second_marker`.
  - Privileged function, with an `--account` and an `--admin-account`: the privileged account gets a 2xx answer with content, the same GET without a login gets 401 or 403, and the normal account gets the identical answer: `confirmed`. 403 or 404 for the normal account gives `blocked-by-control`; any other answer stays `inconclusive`. The answers are compared as received, before credentials and user names are redacted: an answer that names the signed-in user or holds that user's credential differs between the accounts and never counts as identical, while a list that names every user can. This shows that the normal account receives what the privileged account receives, not that the function is meant for privileged accounts only.

  Same-named roles with the same session never count as two accounts. Exposure findings (CWE-200) and missing authentication (CWE-306) still need a `test_resources` entry.
- Injection: declare the hypothesis, one input to change and the observation before collecting evidence. Repeat a working baseline, a true condition and a false condition at least twice each. All other inputs and the identity stay fixed. A selected JSON field must be stable, reproduce the nonempty baseline for the true condition and differ for the false condition. Reflected input, status changes and generic errors are insufficient. The Verifier generates the true and false conditions itself, and only for an input the scope declares in `injection_inputs` (see below). A repeated delay alone never confirms injection. Repeated citations to one request never count as repetitions.
- XSS: a `browser_check` in which the marker executed (see below).
- Open redirect: a cited request answered 301, 302, 303, 307 or 308 whose `Location` leads to `<marker>.invalid`, a host drawn at random per finding. `.invalid` never resolves (RFC 6761). Redirects are never followed; a 3xx answer comes back with its `Location`, and a next hop is a request of its own.
- Path traversal: a cited request whose response held the content of the scope's `marker_file`, recognised in code. The model is told the file's path, never its content, which shows as `[marker-file]` in every tool result. A request that itself carried the content does not count.
- SSRF: a request with the finding's marker reached the callback listener. No `proof_steps` are needed.

When a firm verdict lacks its required evidence, the agent receives the missing checks and may correct its experiment within the remaining step, request and model budgets. At most two correction rounds are allowed. An unresolved claim ends `inconclusive`, with the missing evidence in the report. Confidence is assigned by the checker: medium for injection and checked negative results, high for other confirmed proofs, low for unresolved or unattempted findings. Evidence the model lists itself is never taken over. When the check passes, the code adds the record it checked. For access control, injection, open redirect and path traversal that is `evidence/<finding>-exchanges.json` (owner-only): per cited step the method, path, parameters, body, identity, status, length and a hash of the redacted response body. For SSRF it is `evidence/<finding>-callback-hits.json` with time, method and source address of each hit.

Negative verdicts also need evidence. Without an answered request the result is `not-attempted`. Injection needs the same repeated controls, either with a stable nonempty observation or a repeatable rejection against a working baseline. Access control needs the declared resource visible to its allowed role and absent for an independent denied role; a 403 or 404 supports `blocked-by-control`. A timeout, scope refusal, missing capability or server error establishes no control. XSS needs a completed browser attempt carrying the marker parts; other marker classes currently retain unsuccessful attempts as `inconclusive`. Every checked result and exported annotation states that it covers only its cited requests and variant.

The assessment’s optional `verification_context` version 1 carries per-variant input locations, query construction, dialect and driver where known, processing and filter order, controls, prerequisites, observations, negative controls, unknowns and sources. The agent reads this context on demand; legacy mechanism traces, scenarios, attack steps and evidence are also retained with explicit size limits. This context supplies hypotheses, never target authorization. A `plan_test` declaration binds its variant to the method and route. Missing header or browser-interaction support is reported before testing when all declared variants require it. Form bodies are supported with POST, PUT and PATCH under the existing intrusive-mode controls.

The agent can use `read_response` to inspect or compare a JSON field or a 1,500-character window from this finding’s recorded, redacted responses, without sending another request. Inspection retains at most 64,000 characters per response and 256,000 per finding; incomplete bodies cannot support field comparisons. Context and result fields stay structured, so long text does not remove measured durations or statuses.

**Proof of concept (VER-034).** Every finding the agent tested gets a proof of concept, whatever the verdict, also when a limit stopped it. The code records each request an agent step sent to the target and the response to it: `http_request` one exchange (two when it renewed a session after a 401), `browser_check` every request of the page that the guarded client answered, with bodies only for documents, XHR and fetch. They are written to `evidence/<finding>-poc.har` (HTTP Archive 1.2, owner-only), which Burp, ZAP or a browser's developer tools can import. Each entry names its step (`_step`), and `_decisive` marks the steps the verdict rests on: for a confirmed verdict the steps its proof check used, for XSS also the `browser_check` in which the marker executed and for SSRF the request that reached the listener; for any other verdict the steps it cites in `proof_steps`. The report lists every step in one line and shows the decisive ones as raw HTTP with the time of the answer: the request in full, and of the response the status, the headers and 1,500 characters of the body around the part that decides (the marker file's content, the XSS marker, the first difference between two injection answers, otherwise the start). The model sees none of this beyond its own tool results.

Before an exchange is recorded, headers the identity added read `[identity <role>]`. The values of `Authorization`, `Cookie` and `Set-Cookie` (cookie names and attributes stay), of other headers whose name contains `token`, `secret`, `passw`, `api-key`, `session`, `credential` or the word `auth`, of query parameters named that way, every credential value the run knows and every JWT read `[redacted]`. Bodies are kept up to 256 KiB each after redaction and up to 4 MiB for all bodies of a finding, binary bodies only with type, length and hash. Other data the target returned stays, because the proof needs it: the report says to review the evidence before sharing it, and `export` never references the HAR file.

**Markers for path traversal and SSRF (VER-012).** These probes are aimed only at harmless markers. In a path-traversal probe, a parameter or body value that names a file (it contains `..` or a NUL, or starts with `/`, `\`, `~` or a drive letter) must name the marker file; without `marker_file` in the scope no such value is sent. The traversal goes in a parameter or the body, because the guard refuses dot segments and encoded separators in the URL path. In an SSRF probe, a value that holds a URL (`://` or a leading `//`) must point at the callback listener's origin. Values are percent-decoded up to three times before the check; other encodings a target may accept are not decoded, and the agent is told the same rule. The listener (`tools/callback.py`) binds only to a loopback `callback.host`. When the target is on `localhost`, `127.x.x.x` or `[::1]` and the scope declares no `callback`, the listener binds to a free loopback port by itself, and the run settings say so. That works only when the target reaches this machine's loopback, e.g. a process started directly or a container run with `docker run --network host`; with `docker run -p` the container's `localhost` is the container itself, and SSRF findings stay `inconclusive`. A target on another machine reaches the listener through a TLS-terminating proxy or tunnel the operator runs, named in `callback.base_url`, which must then be https. The listener answers every request with an empty 204, keeps only time, method and source address of requests that carry a marker, and is never a target of the Verifier itself. If it cannot bind, the run goes on and SSRF findings stay unconfirmed.

**XSS proof browser (VER-009, VER-018, VER-022).** For XSS findings the agent gets one more tool, `browser_check`, which loads a target page in headless Google Chrome (Playwright, `appsec-verifier[browser]`; `--headful` shows it). Chrome opens no connection itself: every request of the page is intercepted and sent through the same scope guard, budget and safe mode as the agent's HTTP requests, identity headers are added only for the identity's origin, redirects go back to the browser so each hop is checked, and anything else is aborted, service workers included. WebSockets are never connected to a server. Chrome itself is started inside a network namespace of its own (`unshare --user --net --map-current-user`) that has no interface but loopback, so traffic the interception never sees, such as WebRTC/UDP, cannot leave the machine either. This needs Linux, `unshare` from util-linux and unprivileged user namespaces. Chrome runs with its own sandbox. Where the namespace or the sandbox is unavailable (other systems, some containers), the browser does not start and XSS findings cannot be confirmed. If Chrome fails during the run, that check ends with an error the agent sees, and the next check starts a new Chrome. A check takes at most about 45 seconds: 30 for loading the page, then the wait the agent asked for (at most 5), and 5 each for marking the page and taking its screenshot. A request of the page other than a document gets at most 5 seconds, so a long poll the server holds open does not hold up the check; a page that does not answer in time keeps its proof of execution but gets no screenshot.

Each finding gets a random two-part marker; the payload must call `alert('<part1>'.concat('<part2>'))`, without `+`, which many applications read as a space in a query string, and only a dialog showing the joined value counts, so a page that merely echoes the payload text is not mistaken for execution. If any request of the probe carried the joined value itself (also percent-encoded), the dialog does not count either: a page that shows a parameter through `alert()` by design would display it without any injected script. A `confirmed` XSS verdict without such an executed marker is downgraded to `inconclusive` ("indicative, not executed"), whatever the model says. On execution the browser saves a JSON event record under `evidence/` (owner-only) and, unless `--screenshots` leaves out `xss`, a screenshot. In it the element that carries the payload is outlined in red, with a label beside it that names the call that ran (`executed: alert('<marker>')`). The caption at the bottom names the finding, the URL as requested, the identity, the time and the payload element; the page is moved clear of the caption. Whatever of the page covers the payload element, such as a dialog and its backdrop, is hidden for the screenshot and named in the caption and in the event record. The proof does not depend on the screenshot. Screenshots can show target data; the report marks them for review before sharing, and the Analyzer export never references them. Without Playwright or Chrome the `Browser` line in the run settings says so and XSS findings cannot be confirmed. The line also names the classes that get screenshots.

**Access-control screenshots (VER-035).** For a confirmed access-control finding, each decisive response that is an HTML page is rendered in the proof browser from the recorded, redacted response. Only the page itself is answered; images, styles and scripts are aborted and scripts are off, so nothing is sent to the target and the page may look unstyled. The exchange screenshot below is taken as well. The caption names finding, step, request, identity, status and time. Up to three values the model names in `highlight`, such as the other identity's email, are marked in yellow when they occur in the response, and the caption says what is marked.

**Exchange screenshots (VER-035).** Every tested finding gets `evidence/<finding>-exchange-<n>.png` when `--screenshots` includes its class, also beside the page screenshot of an executed XSS or an access-control page. It shows the steps its verdict rests on (see proof of concept above); when the verdict cites none, for example because a limit stopped the finding, it shows the answered requests after the last test plan, and its header says that the image proves nothing. The steps appear request and response side by side as recorded and redacted, built as a page without scripts and rendered in the proof browser without a new request. Marked in yellow is what the code can locate, each kind with a red label that says what it is (`payload`, `input`, `answer differs`): the identities an access-control proof compares, the XSS or SSRF marker, the redirect host and the `Location` header, the marker file's name and content, the input and the part of the answer that differ between two injection requests, a different status, and the session cookie's `Set-Cookie` line with the checked attribute (`HttpOnly missing`). Above each step the image states facts about it, in bold where the verdict rests on them: the injection input decoded, the answer times when they differ by 2 s or more, for SSRF whether the listener received the marker, for XSS which page the browser opened (with the payload, also when it sits in the `#` fragment that never reaches the server) and whether the marker executed. The proof browser starts for screenshots only when a finding of an included class is selected; without Playwright or Chrome no screenshot is taken and the verdicts stand.

**Safe mode (default, VER-030).** Without `--allow-intrusive` the run stays read-only. It sends the most harmless payload that can still decide a verdict, keeps request count and rate low, and does no wordlist fuzzing, broad parameter sweeps or long series of payload variants. Writing to the target, needed for stored XSS and some IDOR cases, happens only with `--allow-intrusive` and without `--read-only`, and never when a scope file says `allow_state_change: false`; such requests use unique markers and are logged (VER-014). The Verifier refuses a write that does not carry the finding's marker (the `vrf…` part named in the model's instructions) in its path or a value, and a write whose path names an existing record: a segment at a placeholder of the route (`:id`, `{id}`, `<id>`), or a segment of digits or a UUID. A write may create, never change what may belong to someone else, such as `PUT /api/BasketItems/1` in another account's basket. An operator-declared `test_resources` request is sent as declared, and in a write proof the other account may change the record the owner created in that finding (see **Proof per class**). Identifiers in a request body are not recognised; the model is told not to name another account's record there. A reused command line with `--allow-intrusive` writes to whatever target it names, so check the target before you confirm. A `localhost` reached through `ssh -L` or `kubectl port-forward` is a remote system. The Verifier does not clean up what they wrote, so reset the target after the run. The HTTP client enforces the methods for every caller: safe mode sends only GET, HEAD and OPTIONS, intrusive mode adds POST, PUT and PATCH, and DELETE and every other method are refused. A POST can still change or remove data, so use intrusive mode only against a disposable test instance.

### Interactive and non-interactive

- Interactive (default, with a terminal): the run prints its settings and waits for one confirmation before the first request (VER-002). A credential variable that is not set is asked for hidden before that, and sign-ins in your browser (`oidc-authorization-code`, `oidc-device-code`) happen after it, before the first finding. The run never asks again later. The guided run (above) asks for the settings first.
- Non-interactive (`--non-interactive` / `--ci`, or no terminal): no prompts. Selection, profile and confirmation (`--yes`) come from the command line; a missing confirmation stops the run. Every credential variable must be set, and an identity that needs a person to sign in stops the run before anything is contacted; use a login program or client credentials there.

### Console output

The console is laid out like AppSec Analyzer's, with a red logo and red accents instead of its turquoise. Before the first request `verify` prints its settings as `Key : value` lines: the assessment, the target, the scope and its owner (or `no scope file`), the selection with its severity floor, the profile and model, the limits and the mode. For selected classes that need a preparation and have it, one more line names it: `Identities` (roles only; with `--account` the `Accounts` line names them), `Browser`, `Callback` and `Marker file` (its path only). Then follows the test plan described above, and the question `Proceed against this target? [y/N]`, or `[Y/n]` in the guided run.

The `Report` line names where the report goes, `verification.md` (Markdown) and `verification.yaml` (YAML, for tools, `--resume` and `export`), and says `replaces` when `--overwrite` replaces a report already there.

At the end `Results` lists each finding testable against the app: a mark (`✓` confirmed, `✗` not reproducible, `⊘` blocked by a control, `?` inconclusive, `·` not tested), id, severity, class, result and title, and under it the reason in one line. A finding this run could not test shows what it needs as its result (`needs test identity`). Confirmed findings come first. `--print` lists every finding, unsupported or incomplete ones included, with the whole reason. `Done` then gives the paths of the report, its data, the evidence and the action log, the run's usage and the count per result.

When a run cannot start or go on, `verify` says so on standard error in one form: a line marked `✗` with what is wrong, the details under it, a line marked `→` with what to do, and `Nothing was contacted.` when that is so.

On a terminal the output is in colour and starts with the logo: a confirmed finding is green, not reproducible or blocked red, inconclusive yellow, and severities and pre-flight results have their own colours. `NO_COLOR` (any value) turns colour off, `FORCE_COLOR=1` turns it on without a terminal, and `COLORTERM=truecolor` selects the 24-bit palette. Without a terminal, for example in CI or when redirected to a file, the output is plain text.

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

Runs the checks `verify` runs before its first finding, and verifies nothing. Each check prints one line: `✓` passed, `⚠` works with a caveat, `✗` failed, `·` not checked or not applicable.

| Check | What it does | Contacts |
| --- | --- | --- |
| Assessment | Checks the fields the Verifier reads against `schemas/assessment.schema.yaml` and that finding ids are unique. Shows project, date, and how many findings are dynamic, static-only, input-incomplete. Messages name the place and the rule; only a repeated id is quoted, escaped. | nothing |
| Scope | Schema, window, URL inside the scope. | nothing |
| Proxy | The proxy URL is http(s) without inline credentials, and `username_env`/`password_env` are both set. | nothing |
| Identities | Schema, every `*_env` variable set (asked for hidden at a terminal, except with `--offline`), endpoints and `check_url` inside the scope, login programs found, and sign-ins that need a person only at a terminal. | nothing |
| Programs | The login programs the identities start, as written. They run at the login check below, with your rights. | nothing |
| Test plan | The test plan `verify` shows, for every finding and in safe mode: which findings a run tests, and which it cannot test because they need what the run lacks, grouped by that need with how to add it and the lines to copy. Warns when a finding cannot be tested, never fails. Only when the checks above passed. | nothing |
| Model | The profile resolves (CLI present and logged in, or key set; model known and priced). For `codex` and `anthropic-api` one metadata request shows the key is accepted and the model offered; it generates nothing and proves no quota. | the provider (not with `--offline`) |
| Target | One GET to the URL through the scope gate and the declared proxy. A redirect is not followed. Any HTTP answer counts as reachable; 5xx warns. A failure names its cause: name resolution, refused connection, timeout, TLS certificate or handshake, proxy refusal or proxy authentication (407), or an address the scope refuses. | the target |
| per role | One login for `form`, OIDC and `command` identities, never retried; for `oidc-authorization-code` and `oidc-device-code` you sign in now. With `auth.check_url`, one GET there with the identity's credentials: 2xx accepted, 401/403 rejected, anything else unclear. `bearer`, `basic` and `session` without `check_url` are reported as not checked against the target. Two roles whose tokens name the same account (the same `iss` and `sub`) fail, because an access-control proof needs two independent accounts; sessions that do not name their account, such as cookies, are not compared. | target, login endpoints, login programs |
| Model test | Only with `--test-model` (`verify` always runs it, within its own limits): one fixed prompt without target data, findings or credentials. Passes when the host stays confined and replies with exactly the requested step. | the provider |

The offline checks run first. If one fails, nothing is contacted. The target and login checks run only after one explicit confirmation (VER-002): at the prompt, or with `--yes`. `--non-interactive` without `--yes` contacts nothing and fails. A failed target check skips the logins. The test plan itself is printed after the checks, before the result.

`--test-model` needs its own limit: `--cost-limit` of at least USD 0.01 for `claude`, `codex` and `anthropic-api`, `--max-calls 1` for `codex-cli` and `copilot-cli`. It cannot be combined with `--offline` and runs only when all other checks passed. Its line names the call's cost with API billing, and with `--show-costs` in any mode, as `verify` does.

`--json` prints `{"kind": "preflight", "ok": …, "verification": "not_run", "checks": [{"check", "status", "message"}]}` on stdout and the progress lines and the test plan on stderr. It never prompts, so contacting the target needs `--yes`.

Messages never contain a secret, a token, a response body or a raw error text, which can hold proxy credentials (VER-016). Exit code `0` when no check failed, `2` otherwise.

## `scope` — resolve and check a scope file

```
appsec-verifier scope --scope ./scope.yaml [--target URL]
```

Validates the scope against `schemas/scope.schema.yaml`, prints the resolved boundary (host, ports, path prefixes, window, owner), and, with `--target`, reports whether that URL is inside it. Contacts nothing (VER-001).

## `export` — hand verdicts back to the Analyzer

```
appsec-verifier export --verification ./verification/verification.yaml \
  --output ./verification/analyzer-verification.json [--format json|yaml]
```

Converts a finished `verification.yaml` into a set of verdicts keyed by finding id and the cross-run `match_key` (VER-007), meant for AppSec Analyzer to mark findings with their verification status. The Analyzer does not read this file yet. It never changes or re-scores the assessment (VER-021), contacts nothing and makes no model calls. Default output: `analyzer-verification.json` in the working directory, JSON format. A file that cannot be read or does not match `schemas/verification.schema.yaml` stops it with exit 2.

## `update` — update the installed Verifier (VER-033)

```
appsec-verifier update
```

- Reinstalls the Verifier from the source pipx recorded at install time, such as GitHub or a local checkout. Credentials in a recorded URL are not shown.
- Shows the installed version and the source, then asks `[Y/n]`. Enter or `y` confirms; anything else, or closed input, installs nothing.
- Runs `pipx upgrade --pip-args=--force-reinstall appsec-verifier`, which you can also run yourself. `--force-reinstall` reinstalls even when the version number is unchanged, as is usual between GitHub commits. Like a new `pipx install`, it takes the newest dependency versions `setup.py` allows, not the pins of `requirements.lock`; packages added with `pipx inject` stay.
- Hides the pipx output and shows it only when the update fails (exit 2).
- Afterwards shows the new version as `appsec-verifier --version` prints it, read from the new installation: the engine version with commit and date of the build, e.g. `0.1.0a1 (a26a8e10, 2026-11-07)`. `(unchanged)` means the source had nothing newer.
- Needs an interactive terminal outside CI (`CI` set); no option skips the question. Otherwise it exits 2 and names the pipx command to run yourself.
- An installation without pipx (a venv from `requirements.lock`, an editable checkout) is not changed; update it the way you installed it.

To switch the source, run `pipx install --force` with the new source. A checkout installed with `pipx install --force .` stays the source: change it, for example with `git pull`, and run `update`.

`--version` names the build. `setup.py` stamps commit, date and local changes into the package (`build-info.json`); a checkout without a stamp is read from Git; a build without either shows `(commit unknown)`.

## Configuration files

### Scope file — `scope.yaml` (authorisation, VER-001)

The scope file states what the Verifier may contact, during which window, and who is responsible. Schema: `schemas/scope.schema.yaml`; examples in `examples/`. A minimal scope needs `schema_version`, `base_url`, `window` and `owner`; the README's quick start shows one.

Without a scope file, `--url` alone is the scope: the URL's scheme, host and port, the whole host, for that run. Write requests need `--allow-intrusive` either way. You need a scope file for anything more: several hosts or ports, path prefixes, `deny_paths`, a host name that resolves to a private address (`networks`), a proxy, login hosts other than a `--login-url`, an SSRF callback for a target that is not on `localhost`, the marker file, or a test window and owner on record.

| Key | Meaning |
| --- | --- |
| `base_url` | Absolute http(s) URL of the target. Hosts and ports default to those of this URL. |
| `hosts`, `ports`, `schemes`, `path_prefixes` | What may be contacted. `schemes` defaults to the scheme of `base_url`, so plain http is allowed only when `base_url` or `schemes` names it. |
| `deny_paths` | Paths that are never contacted, compared regardless of case and percent-encoding. |
| `networks` | CIDR ranges of private or loopback addresses that may be contacted (see below). |
| `window` | Authorised test period (`from`, `until`, ISO 8601 UTC). |
| `owner` | The person or party responsible for the test. |
| `allow_state_change` | `false` forbids writing requests: a run with `--allow-intrusive` stops before anything is contacted. Absent or `true` leaves it to `--allow-intrusive` (VER-030). |
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

Without a `test_resources` entry, IDOR and missing-authorisation findings can also be proven with two accounts and `--allow-intrusive`, or with an `--admin-account`; see **Proof per class** under [Output mode and run mode](#output-mode-and-run-mode).

Anything outside the scope, whether target, login host or proxy, is refused and not attempted. A path that a server could resolve to another resource (a `.` or `..` segment, `//`, `\`, `;`, or `%2e`, `%2f`, `%5c`, `%3b`, `%25`, `%00`) is always refused. Proxy variables in the environment (`HTTPS_PROXY` and the like) are ignored; only the scope's `proxy` is used.

Addresses are checked when the connection is made (VER-018). Each host name is resolved once, every address it resolves to is checked, and the connection goes to a checked address, so a DNS answer that changes later cannot redirect a request. Public addresses are allowed. Loopback, private and other non-public addresses need `networks`, unless the host is written as that address or as `localhost`. Link-local addresses (including cloud metadata at 169.254.169.254), other known metadata addresses, multicast, unspecified and reserved addresses are never contacted. If any address of a host is refused, the request is refused. Through a proxy only the proxy's address is checked; hosts in `proxy.no_proxy` are checked as without a proxy.

The `window` is checked before every request and every planning step. Once it has closed, the current finding ends `inconclusive` with `limits_hit: window`, no further request is sent, and the run exits with 3.

### Identities file — `identities.yaml` (sessions, VER-016/028/040)

Lists the test identities by role name and, per identity, the login `method` and where its credentials come from. The file holds no secret values: it names the environment variables that hold them. Use accounts made for the test, not your own company account, because the run acts with that account's rights. Schema: `schemas/identities.schema.yaml`. Examples: `examples/juice-shop/` (form login), `examples/sso-proxy/` (SSO sign-in in your browser, behind a proxy) and `examples/login-program/` (a login program).

| Method | Session |
| --- | --- |
| `none` | no credentials, for anonymous requests |
| `bearer` | the token in `token_env`, sent as `Authorization: Bearer` |
| `basic` | `username_env` and `password_env` as HTTP Basic |
| `session` | headers copied from a signed-in browser, each from its own variable, e.g. `headers_env: {Cookie: VERIFIER_A_COOKIE}`; also for API keys such as `X-Api-Key` |
| `form` | a JSON login at `login_url` that returns a token |
| `oidc-password` | the OIDC password grant; meant for test realms, many providers refuse it for accounts with MFA |
| `oidc-client-credentials` | the client-credentials grant, for service identities |
| `oidc-authorization-code` | you sign in in your own browser; needs a terminal and a browser on the same machine |
| `oidc-device-code` | you sign in on any device with a code the Verifier shows; needs a terminal |
| `command` | your login program prints the session |

```yaml
identities:
  - role: user-a                       # sign-in in your browser, MFA included
    method: oidc-authorization-code
    auth:
      issuer: https://sso.example.com/realms/app
      client_id: verifier-cli
      scope: openid
      check_url: https://app.example.com/api/me
  - role: user-b                       # a session copied from the browser
    method: session
    auth:
      headers_env: { Cookie: VERIFIER_USER_B_COOKIE }
      check_url: https://app.example.com/api/me
  - role: user-c                       # your own login program
    method: command
    auth:
      command: [./login.py, user-c]
      headers: [Cookie]
  - role: service                      # client credentials
    method: oidc-client-credentials
    auth: { issuer: https://sso.example.com/realms/app, client_id: verifier-svc, client_secret_env: VERIFIER_SVC_SECRET }
  - role: anonymous
    method: none
```

For the OIDC methods `issuer` is enough: the Verifier reads `<issuer>/.well-known/openid-configuration` and takes the endpoints not given as `token_url`, `authorize_url` or `device_url`. Every endpoint must be the target or an `auth_hosts` entry of the scope, also one the discovery document names. Optional fields: `client_id` or `client_id_env`; `client_secret_env` for a confidential client, sent in the body (`client_auth: post`, the default) or as HTTP Basic (`client_auth: basic`); `scope`; `audience`, which Auth0 requires; `resource`, which Entra ID v1 requires; and `token: id` for an application that expects the ID token instead of the access token.

`oidc-authorization-code` needs a client at your identity provider that allows a loopback redirect and issues tokens the application's API accepts. The Verifier prints the authorize URL, opens it in your browser where there is a display, and waits up to 5 minutes for the redirect to `http://127.0.0.1:<port>/callback`. The listener there accepts only that path with the run's `state`, answers that one request and closes. The code is exchanged with PKCE (S256). If the provider needs the redirect registered with a fixed port, set `redirect_uri: http://127.0.0.1:8400/callback` (or `localhost`). The Verifier sends `prompt=login`, so the provider asks again for each role instead of signing the second role in as the first; `prompt: select_account` or `consent` change that. The Verifier never sees your password. This fits applications whose API accepts the provider's token. An application that keeps its own session cookie after the SSO sign-in needs `session` or a login program.

`oidc-device-code` shows a URL and a code, e.g. `Sign in as user-a: open https://sso.example.com/device and enter the code WDJB-MJHT`, and polls the token endpoint at the interval the provider sets, for at most 15 minutes. It also works over SSH.

Both sign-ins happen after the confirmation and before the first finding. A run without a terminal refuses such an identity before anything is contacted. Their sessions are renewed with the refresh token the provider issued; when that fails later in the run, the role is unavailable for the rest of it, because the run never asks again.

A login program (`method: command`) is the way for everything else: a provider that needs a script, a classic login form with a CSRF token, or a CI run. `command` is the program and its arguments as a list; it is run without a shell from the directory of the identities file, so `./login.py` is found next to it. Any language works, e.g. `[/home/me/sso-venv/bin/python, login.py, user-a]`; use your own Python environment for what the program needs, not the Verifier's. The program prints the session on standard output, at most 64 KiB, either one line with a bearer token, or one JSON object:

```json
{"headers": {"Authorization": "Bearer eyJ…"}, "cookies": {"SESSION": "…"}, "expires_at": "2026-11-08T14:30:00Z"}
```

`cookies` are sent as one `Cookie` header, `expires_at` (ISO 8601 with a time zone) or `expires_in` (seconds) say when to run it again. Only the header names listed in `headers` are accepted (default `[Authorization]`), and a value with a line break or another control character is refused. `timeout` is 120 seconds by default, at most 900. In an interactive run the program shares your terminal, so it can ask for a one-time code itself; write such prompts to standard error. Otherwise its input is empty. Its standard error goes to the terminal as it is and is never recorded. It gets your environment without the model providers' credentials (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, `CODEX_API_KEY`, `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`). A program that exits with a status other than 0 is reported by that status only, and it is not run again in the run. Otherwise it runs again only to renew the session: shortly before its expiry and once after a 401. The program's own requests are outside the run's scope, limits, rate and safe mode: it runs with your rights, like a command you start yourself. The run lists each program in its settings before the confirmation, and in the guided run a found identities file that starts programs needs its own yes.

Each identity sends its credentials only to the endpoint it names, which must be the target or a scope `auth_hosts` entry (VER-028). The session it obtains is attached only to its own origin, `auth.target_origin`, by default the target base URL; a request as that role to any other origin is refused, and its headers are removed when a redirect leads to another origin (VER-018). The HTTP client keeps no cookies, so a session never travels in a cookie the target set for another identity.

Before the first request `verify` checks the file against the schema, that every variable it names is set, that login endpoints and `target_origin` lie inside the scope, and that login programs exist. In an interactive run a variable that is not set is asked for without echo and kept only for the run; without a terminal the run stops with exit 2 and names the variable, never its value. To keep a value out of your shell history, set it with `read -rs VERIFIER_ALICE_PASS && export VERIFIER_ALICE_PASS`. A secret manager can set the variables for the one command, e.g. `op run --env-file=verifier.env -- appsec-verifier verify …`, `doppler run -- appsec-verifier verify …` or `sops exec-env secrets.enc.yaml 'appsec-verifier verify …'`. After the confirmation and before the first model call, every identity that logs in does so once; a rejected login stops the run (VER-032). A `bearer`, `basic` or `session` identity is checked against the target only when it names `auth.check_url`, a URL on the origin its credentials are sent to, which the pre-flight check requests once. Two roles signed in as the same account also stop the run.

Credential and token values are used only to obtain and send a session. They are never written to logs, the report, evidence files or a model prompt; only the role name is passed on, and recorded requests are stripped of Authorization headers, cookies and token parameters (VER-016, VER-022). If the target echoes a credential, every value the run knows (each variable's value, each value entered hidden or pasted, each token, refresh token and cookie value obtained, also JSON-escaped and URL-encoded) is replaced by `[redacted]` in tool results, the report and the proof of concept. Values shorter than 4 characters are not replaced, and XSS screenshots are not redacted.

### Test accounts on the command line (VER-041)

For a login that answers a JSON POST with a token, such as OWASP Juice Shop, you can name the accounts on the command line instead of writing an identities file:

```sh
appsec-verifier ./security-assessment.yaml --target http://localhost:3000 \
  --account jim@juice-sh.op --account bender@juice-sh.op=VERIFIER_BENDER_PASS --admin-account admin@juice-sh.op
```

Each `--account` is a user name, optionally followed by `=VARIABLE`, the environment variable that holds its password. Without a variable the password is asked hidden, e.g. `Password for account-1 (jim@juice-sh.op), hidden:`; without a terminal the run stops and names the account. `--account` and `--identities` cannot be combined, and the same user name given twice stops the run, because an access-control proof needs independent accounts.

The model knows the accounts as `account-1`, `account-2` and `admin-1`, never by user name or password. User names are redacted like passwords, but they stand in your shell history and, while the run lasts, in the process list. An `--admin-account` sends only GET, HEAD and OPTIONS, also with `--allow-intrusive`, and the model is told that it is privileged. Its answers are the reference for privileged functions, and it never creates a resource (VER-010; see **Proof per class** under [Output mode and run mode](#output-mode-and-run-mode)).

The accounts sign in at `--login-url`, or else at the one POST entry point in the assessment's `attack_surface` whose path looks like a login (`login`, `signin`, `logon`, `authenticate`, `session`), below the target URL. When the assessment names none or several, the run stops before anything is contacted and lists what it found; give the endpoint with `--login-url`. Without a scope file, a `--login-url` on another host is allowed for this run only to sign in, and it must be https unless it is on the target or this machine; with a scope file it must be the target or an `auth_hosts` entry. The run settings show the endpoint before the confirmation, e.g. `account-1, account-2 · sign in at POST http://localhost:3000/rest/user/login (from the assessment); the model chooses the field names`.

After the confirmation, one model call proposes up to two pairs of field names for the user name and the password, from the endpoint and, with `--source`, the handler's source. The model sees no value. Each account then tries at most two pairs, and a pair that worked is used for the other accounts. A login that returns no token stops the run, e.g. `Login fields … no token for account-2. A login that does not answer a JSON POST with a token needs --identities`. The token is sent as `Authorization: Bearer` and renewed like a `form` login from an identities file. `preflight` takes the same options; with `--offline` it checks the endpoint without asking for passwords.

### Limits — `data/limits.yaml`

Default limits of a run: model cost, model calls, requests, steps per finding, run time and request rate. The options `--cost-limit`, `--max-calls`, `--max-requests`, `--max-attempts`, `--max-duration` and `--rate` override them per run (VER-015).

## Outputs

Written to `--output` (default `./verification`):

- `verification.md` — the report: one section per finding with verdict, evidence and its proof of concept, and the authorisation context.
- `verification.yaml` — the same results as data (`schemas/verification.schema.yaml`), each entry linked to its finding by id and `match_key` (VER-007, VER-020).
- `agent-log.jsonl` — written when the target is contacted: one JSON object per agent step of every finding, with `time`, `finding`, `step` and either the tool call (`tool`, `args`, `result` with status, body length, error or the browser's blocked requests), a step that was refused (`refused`, `proposal`), a limit that stopped the finding (`stopped`, `reason`) or the `verdict` (VER-017). A finding whose probe failed gets `probe_failed` with the error type and `at` with the file and line in the Verifier, never the error message; the finding under test when the run was interrupted gets `interrupted`. It holds no response bodies or source text, credential values are redacted (VER-016), and only the owner can read it. `--resume` continues it; otherwise each run starts it fresh.
- `evidence/` — owner-only: `<finding>-poc.har` for every tested finding (see proof of concept above), the proof records `<finding>-exchanges.json` and `<finding>-callback-hits.json` (see proof per class above), for an XSS marker that executed `<finding>-xss-<n>.json` with a screenshot `.png`, `<finding>-access-control-<n>.png` and `<finding>-exchange-<n>.png`. XSS screenshots are not redacted. Responses and screenshots are marked for review before sharing (VER-022).
- `security-assessment.annotated.yaml` and `security-assessment.annotated.md`, with the figures of the Analyzer's report — only with `--annotate`, see below (VER-027, VER-038).

The `export` command writes `analyzer-verification.json` for AppSec Analyzer (VER-021).

### Annotated copies (VER-027, VER-038, VER-039)

With `--annotate` the run writes two copies next to its report. The assessment and the Analyzer's report stay unchanged, also because AppSec Analyzer records a SHA-256 of each file it saved and refuses `export` and `review` of an assessment whose files changed.

`security-assessment.annotated.yaml` is the assessment with a top-level `dynamic_verification` entry for the run (schema version, time, Verifier version, path of `verification.yaml`) and a `dynamic_verification` block on each finding of the report: verdict, confidence, time, result id, what the checked proof covers, the rating after verification, and the paths of the proof of concept (HAR) and of the screenshots, relative to the report. The block carries no requests, responses or images. Schema: `schemas/annotated-assessment.schema.yaml`. Nothing else in the document changes, so it stays valid against the Analyzer's schema, and the Analyzer's own `verification` field is kept.

`security-assessment.annotated.md` is written when the Analyzer's Markdown report lies next to the assessment under the same name, `security-assessment.md` for `security-assessment.yaml`. It is a copy of that report with three additions. A `Dynamic verification` section before the Management Summary names the target, counts the verdicts and lists each tested finding with the Analyzer's severity and the severity after verification. The changelog table gets a row for the verification run at the top; a report without that table gets the entry in the new section instead. Each tested finding gets a `Dynamic verification` section at its end with the verdict, the rating after verification, the agent's rationale (quoted), the proof of concept and the screenshots. Findings that were not tested get no section.

A finding whose anchor in the report is missing or appears more than once is listed at the end of the copy. Figures the report names by a plain file name are copied next to the copy. A report larger than 32 MiB is not copied, and the `Annotated report` line in `Done` says why when no copy is written. The copy contains recorded responses and screenshots: review it before sharing (VER-022).

**Rating after verification (VER-039).** The Analyzer's rating stays as it is; both copies show a second one next to it. Severity is the Analyzer's `effective_severity`, else its `risk`. The rules, applied in code:

| Verdict, with a checked proof | Likelihood | Severity |
| --- | --- | --- |
| confirmed, likelihood below High | becomes High | one level higher, at most Critical |
| confirmed, likelihood High or Critical | unchanged | unchanged |
| blocked by control | one level lower | one level lower, at least Informational |
| any other verdict, or no checked proof | unchanged | unchanged |

Impact never changes. Of a finding with declared variants, one confirmed variant counts, and a block counts only when every variant was blocked. A block covers only the tested requests: a filter that rejects the test payloads lowers the rating although another path may still work, which is why the Analyzer's rating stays next to it. A finding whose likelihood or severity is not one of the Analyzer's levels (Critical, High, Medium, Low, Informational) is not rated.

`--strict-severity` disables additional selection below `--min-severity`. Otherwise at most eight findings are added within the other selection filters: explicit prerequisites and access or exposure findings on `/actuator`, `/management`, `/admin`, `/metrics` or `/debug` routes. Health, readiness and liveness routes do not qualify on their own. The additions are shown with their reason before confirmation. Missing operator resources still block their tests.

A finding can name `verification_dependencies: [T-002]` in the assessment. Those findings run first when selected. `attack_steps`, optional `attack_walkthrough`, related `components`, `data_flows`, `trust_boundaries`, `security_controls` and optional `compound_chains` supply bounded planning context. Chains use `findings` IDs or `keystones`/`contributors` entries with `ref` IDs. Chain membership supplies context; only explicit dependencies impose an order. Rendered Markdown walkthrough fragments are not automatically imported. Prior results cover individual requests; transitions between findings remain unverified. Cyclic dependencies do not establish prerequisites.

Before collecting injection or access-control proof the agent declares its strategy, prerequisites and counter-hypothesis. Plan revisions explain the new observation and next change. A new plan requires fresh evidence. The console shows one line per accepted plan, with its request and, for a revision, the reason; the report retains the whole plans with their assumptions under `Test planning`. `run_experiment` collects five read-only controls twice under the existing request, time and per-finding attempt limits. It never automatically repeats writes, and a boolean or timing plan with a write method or a form field, which only a write carries, is refused before any request, because its controls are sent twice. SQL controls use `sql_template` with one `{{predicate}}` placeholder. Command, template and XPath controls use `expression_template` with one `{{expression}}` placeholder and verify fresh products and sums in a selected JSON field. Arbitrary response changes and timing alone cannot confirm injection. NoSQL checks compare fresh equality and membership operators; LDAP checks compare complementary filter predicates. Both require a declared literal-input contract. The planner should use source-supported processing order and filter behavior to justify any encoding or syntax adaptation.

For session-cookie attributes, identify the cookie and a harmless GET that issues it in the scope file:

```yaml
session_checks:
  - id: customer-session
    finding_id: T-042
    path: /session-status
    cookie_name: sessionid
    role: customer-a
```

Omit `role` for an anonymous observation. The agent declares a `session` plan with this resource ID and repeats the observation. CWE-614 checks Secure, CWE-1004 HttpOnly and CWE-1275 SameSite (Lax or Strict). An absent, expired or ambiguous cookie remains inconclusive in this check. Cookie values never reach the model or report. Session fixation, logout, expiry enforcement and token-validation weaknesses require separate lifecycle checks. `--screenshots` also accepts `session`; its exchange image shows redacted Set-Cookie attributes. The screenshot does not determine the verdict.

Each declared finding variant runs separately. Resume accepts checked proof contract 3 for the matching variant content; older proofs are tested again. Merging preserves different variants and their evidence. Annotation distinguishes a confirmed weakness from incomplete variant coverage. The assessment and target must still match the prior report.

XSS confirmation currently requires execution in the checked page's main frame and origin without a sandbox response policy. Child-frame execution stays unconfirmed because its effective permissions are not established. SSRF uses a fresh callback marker per request and records hits only within that attempt's observation window. A callback proves that retrieval, not arbitrary internal reachability.

SQL and expression confirmation also require the operator to identify an input that must treat its value as literal data. This distinguishes injection from an intended calculator, template editor or query language. The declaration supplies the expected contract; fresh runtime observations must still prove evaluation:

```yaml
injection_inputs:
  - finding_id: T-012
    path: /search
    input_location: params
    input_name: q
    semantics: literal
```

Without that declaration the agent can inspect the context and run bounded controls, but the expression proof plan is refused and the finding stays open.

NoSQL uses `operator_challenge: nosql` with `input_location: json`. It compares literal baseline lookup with fresh equality and membership operators. LDAP uses `predicate_template` with one `{{predicate}}` placeholder and an evidenced `predicate_attribute`; generated complementary filters must repeat the baseline for true predicates and suppress it for false predicates. Both use the same operator-declared `injection_inputs` contract and ten recorded requests. Command templates are confined to a plain baseline followed by `; printf '%s' "$(({{expression}}))"`. Other commands and extra inputs are refused.

SSRF confirmation additionally requires `callback.expect_rejected: true` in the operator's scope: fetching this controlled destination must violate the intended access policy. Without that declaration a hit is recorded as retrieval observed and the finding remains inconclusive. An intended URL-fetch feature alone is not a confirmed SSRF boundary violation. The listener the Verifier starts by itself for a `localhost` target needs no declaration: it is on a loopback address, and an application that fetches a loopback URL it was given has reached an internal address.

### Runtime candidates and test preparation

A supported CWE is a candidate for runtime testing, not a promise of a completed proof. A CWE without a supported proof method is `unsupported`, not automatically static-only. Older reports with `static-only` remain readable. Missing inputs and test resources are reported separately from unavailable proof capabilities. Injection through write requests is currently unsupported by the repeated-control method, even in intrusive mode; declare a GET input only if that endpoint actually implements the same operation.

For legacy access-control findings without structured variants, preparation can add a POST that the assessment explicitly lists for the exact collection of the finding's record route. The POST must have a handler location in a source file cited by the finding or the exact matching record-route registration, and the collection and POST must be unambiguous. The test plan shows the preparation request. Only the owner under an accepted access-control plan can use it, with the existing marker, scope and write-permission checks. No route is invented and structured variants keep their explicit request boundary. Existing reads, or the existing read of a created record under a change plan, supply the comparison.

Exchange screenshots show selected excerpts and the roles and statuses of the comparison, with up to two exchanges per panel. JSON is formatted, HTML error pages show visible text rather than styles, and routine headers are omitted. Each panel states the verdict and links it to the recorded steps; an inconclusive result remains inconclusive. The complete recorded exchanges remain in the HAR. XSS screenshots crop the located payload and caption together where they fit; otherwise the viewport remains visible. Unsuccessful HTML control responses remain in the exchange panels rather than creating separate page images.

## Evidence presentation review

After all selected variants of a tested finding finish, a separate reviewer checks whether the evidence text explains the scope, identities, comparison and result. It also receives deterministic presentation checks, including the dimensions of generated screenshots. The first stage does not send image pixels to a model and cannot judge whether a screenshot visually shows the right element. The report states this limit explicitly.

If the reviewer finds a presentation problem, the original test agent receives the feedback and can add a short explanation with exact quotes from the recorded request or response. The report labels these as explanations, not additional proof. When screenshots are enabled, corrections also produce a compact explanation panel alongside the original evidence. The full HAR and original proof images remain available. Corrections never contact the target or change the verdict, confidence or proof validation.

Each finding has at most two correction rounds shared by its tested variants: one initial review and at most two correction calls and two further reviews. That is at most five additional model calls, using the selected profile and the run's existing cost, call and time limits. Repeated issue categories without improvement, unchanged corrections, invalid responses, cancellation or exhausted limits end the loop early. A review failure preserves the technical result.

The console prints `review`, `revise`, `quality` and, when needed, `issue` rows with the finding ID and correction count. The report records `clear`, `needs-attention`, `stopped` or `not-reviewed` separately from the technical verdict, lists unresolved issues, and names the reviewed variants. Untested variants are not reviewed. A finding with more than 16 tested variants, or evidence exceeding the bounded review context, is reported as not reviewed. Screenshot checks flag panels larger than 1280 by 1200 pixels; passing them does not establish visual clarity. Models see bounded, redacted excerpts and panel text; marker-file contents and credentials remain excluded.
