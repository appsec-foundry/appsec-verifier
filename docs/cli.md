# AppSec Verifier: command reference

`appsec-verifier` reads a finished `security-assessment.yaml`, tests the selected findings one at a time against a running target inside an authorised scope, and writes a verification report. It does not re-run or re-score the static assessment. Installation and quick start: [README](../README.md). The requirement IDs (VER-…) refer to [`requirements.md`](../requirements.md).

## Commands

| Command | Does | Contacts |
| --- | --- | --- |
| `appsec-verifier ASSESSMENT` | Guided run: asks for the `verify` settings that have no usable default, then runs `verify` (VER-031). | target, model |
| `verify` | Tests findings of an assessment against a running target. | target, model |
| `preflight` | Checks assessment, scope, proxy, target, logins and model profile; tests no finding (VER-032). | target, model provider; nothing with `--offline` |
| `scope` | Resolves and validates a scope file and shows what is in and out of scope (VER-001). | nothing |
| `export` | Converts the verdicts of a finished `verification.yaml` into a file meant for AppSec Analyzer, which does not read it yet; no re-verification (VER-021, VER-015). | nothing |
| `update` | Reinstalls a pipx installation of the Verifier after you confirm (VER-033). | the install source, through pipx |

`appsec-verifier` without arguments, or with `--help`, lists the commands with examples. `appsec-verifier <command> --help` lists the options of one command by group, with example calls; `appsec-verifier ASSESSMENT --help` does the same for the guided run. A wrong call shows the short usage, the error and where the examples are. Options count only as written: an abbreviation such as `--show-cost` is an error that names the option meant (`did you mean --show-costs?`), and nothing is contacted.

## Guided run — `appsec-verifier ASSESSMENT` (VER-031)

Called with an assessment and no command, the Verifier reads the assessment offline and shows how many findings it holds, how many of them are candidates for testing against the running app and their severities, and how many lack a code location. It then asks only for what has no usable default. What the selected findings need (a test identity, the proof browser, a marker file, a callback) appears in the test plan of `verify`; `preflight` shows how to provide it.

By default the run tests findings of severity high and above, of every class present, with the profile `claude` and the limits of `data/limits.yaml`. `--min-severity`, `--category`, `--profile`, `--cost-limit`, `--max-calls`, `--max-requests`, `--max-attempts`, `--max-duration` and `--rate` change that. The run prints the selection, e.g. `→ 24 findings to verify, severity high and above (--min-severity to change)`, and repeats the floor in the `Selection` line before the confirmation. If no finding of severity high or above can be tested, it offers the next lower severity that has any, e.g. `Verify the 3 of severity medium? [Y/n]`; no ends the run without contact. A profile that is not available ends the run before any question and names `--profile`.

Enter accepts the default shown in brackets.

| Question | Default | Same as |
| --- | --- | --- |
| Target URL | none; asked only without a scope file (below) | `--url` |
| Identities file | asked only when `identities.yaml` is found next to the scope, the assessment, or in the working directory, and not with `--account` or `--admin-account`; `none` for no identities. A file that starts login programs needs its own `Run them? [y/N]` | `--identities` |
| Allow intrusive probes? | no; asked only when the scope has `allow_state_change: true` | `--allow-intrusive` |
| Existing report in the output directory | `There is already a report in ./verification. Overwrite it? [y/N]`; no stops the run before anything is contacted. Not asked with `--overwrite` or `--resume`, nor without a terminal, where the run stops as `verify` does | `--output`, `--overwrite`, `--resume` |

Each answer goes through the same check as its option and is asked again when invalid: a URL without http or https, with a user name or password, or with an ambiguous path, or an identities file that cannot be used. Options given on the command line are not asked, e.g. `appsec-verifier ./security-assessment.yaml --target http://localhost:3000` asks nothing but the confirmation. A credential variable that the identities file names but the environment lacks is asked for without echo, e.g. `alice: VERIFIER_ALICE_PASS (password_env) is not set; enter its value (hidden):`; Enter alone leaves it unset. The value is kept only for this run, never written and never put into the environment.

A `scope.yaml` next to the assessment, else in the working directory, is used without a question, and the run prints its path. If it cannot be used, for instance because its window has closed, the run stops with exit 2 and says why; correct the file, or move it away to enter a target URL instead. Without a scope file the run asks for the target URL, which has no default and is never taken from the assessment. It then tests only that URL's scheme, host and port, as `verify --url` does without `--scope`, and writes no scope file.

Without an identities file, when the selection holds access-control findings for which the scope declares `test_resources`, the run offers to take the session of each role those resources name from your browser: `Paste sessions for user-a, user-b? [y/N]`. Sign in to the application as that user (a private window or another browser profile for the second one), open the developer tools, copy any request the application sends to the target in the Network tab with "Copy as cURL (bash)", paste it at `Request copied as user-a (hidden; Enter alone skips this role):` and press Enter. The pasted text is not echoed and never run. The run keeps only its Cookie and Authorization headers and refuses a request to another site. When the copied request was a GET, the pre-flight check sends it once with the session to see that it is accepted. Pasted sessions are not renewed, so a session that expires during the run ends that role's tests. The command line printed before the confirmation does not include them; for a repeatable run put them in an identities file with `method: session`.

After the questions the run shows the `verify` settings and the equivalent non-interactive command line, e.g.

```
appsec-verifier verify --assessment ./security-assessment.yaml \
  --url http://localhost:3000 --output ./verification --min-severity high \
  --profile claude --non-interactive --yes
```

and then asks the one confirmation of VER-002 as `[Y/n]`: Enter starts the run. Answering the questions does not confirm. Ctrl-C or end of input at any question stops with exit 2 and contacts nothing.

`--non-interactive` (`--ci`), or standard input that is not a terminal, turns the questions off: `appsec-verifier ASSESSMENT --ci --scope … --profile … --yes` behaves like `verify` with the same options. Without `--scope` or `--url`, or without `--profile`, the run stops with exit 2 and names what is missing; without `--yes` it stops at the confirmation as `verify` does.

## `verify` — verify findings against a running target

`verify` takes the assessment, the scope and limits of the test and a selection of findings, and writes its own report; with `--annotate` also annotated copies of the assessment and of the Analyzer's report.

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

A run has five steps:

1. Check the assessment's structure, the scope and proxy settings, the identities file and the model profile (VER-005, VER-032).
2. Resolve selection and scope and, interactively, print both for one explicit confirmation (VER-002, VER-026).
3. Run the checks of [`preflight`](#preflight--check-before-a-run-ver-032): the target answers, every identity logs in, and the model answers one fixed prompt (VER-003, VER-032). Each check prints one line under `Preflight`, and a failed check stops the run before the first finding (exit 2). These requests count against `--max-requests`, the model test as one call against `--max-calls` and `--cost-limit`. The build check of VER-003 is not implemented yet.
4. Test each selected finding, bounded and inside the scope (VER-008, VER-015, VER-017).
5. Write the report with its evidence and, with `--annotate`, the annotated copies (VER-020, VER-022, VER-027, VER-038).

Before the confirmation, `Test plan` lists the findings the run will test, one line each with severity, class, title and the requests the assessment names for it (for example `GET /rest/basket/:id`), followed by the requests that prepare a test resource, marked `(prepares)`. On a terminal `verify` cuts a line to the terminal's width; `preflight` shows it whole. The requests come from the finding's scenario and attack steps, where several methods before one path, as in `GET and DELETE /api/BasketItems/:id`, each name a request, and from the assessment's `attack_surface`: an entry point that matches a named request, whose `route_ids` hold an ID the finding or one of its instances lists in `route_ids`, or whose handler or registration (`handler:` and `registered:` in its notes) is at the finding's location, gives the path template, and `auth_required: true` adds the `(login)` mark to the request in the line that starts a finding during the run. `page /#/search` is a browser route. The agent gets these requests and the finding's scenario and attack steps; it reads source code only with `--source`.

`Not testable` groups the findings this run cannot confirm by what they need, with how to provide it:

| Need | When |
| --- | --- |
| test identity | an access-control finding, or one whose named requests all need a login |
| access request | an access-control finding without a `test_resources` entry whose named requests allow none of the [proofs](#proof-per-class-ver-009-to-ver-013): a GET for the comparison with an `--admin-account`, or a write that creates a record (one that names no existing record in its path) together with a GET or a write that changes the record by its identifier. DELETE is never sent. |
| proof browser | XSS |
| marker file | path traversal |
| callback | SSRF |
| injection contract | an injection finding without its `injection_inputs` entry |
| request information | the assessment names no request for the finding and there is no `--source` to read one from. `--source` helps only when the finding's file declares its route (see [Continuous control](#continuous-control-ver-036)); an access-control finding can name its request in a `test_resources` entry instead. |
| intrusive mode | every named request writes |
| test capability | a reported variant needs a tool the run lacks |
| repeatable request | every request an injection finding names writes, and its `injection_inputs` entry, if any, declares no query parameter that a GET on its path would carry. The proof sends each control twice but never repeats a write, so `--allow-intrusive` does not help. |

`verify` names what to provide in a few words, one line per need; `preflight` shows how, with the lines to copy into a scope file. These findings are not tested and appear in the report as `not-attempted` with the reason; `--test-all` tests them anyway. When nothing is left to test, the run stops with exit 2, contacts nothing and writes no report. What `verify` prints while it runs is described under [Console output](#console-output).

### Input and target boundary

| Flag | Meaning | Req. |
| --- | --- | --- |
| `--assessment PATH` | `security-assessment.yaml` to verify, as the Analyzer wrote it. | VER-005 |
| `--scope PATH` | Authorisation scope file (`schemas/scope.schema.yaml`): the target boundary, the declared proxy and auth hosts, the test window and the owner. Without it, `--url` alone sets the boundary. | VER-001 |
| `--url URL` (alias `--target`) | Start URL of the target. With `--scope` it must fall inside the scope, and without `--url` the scope's `base_url` is used. Without `--scope` it is required and is the whole boundary: its scheme, host and port, with no window and no owner. | VER-001/004 |
| `--identities PATH` | Test identities (`schemas/identities.schema.yaml`): per role a bearer token, basic, form, copied browser headers, an OIDC flow or a login program. Secret values come from environment variables, or are asked hidden in an interactive run, never from this file. | VER-016/028/040 |
| `--account USER[=VAR]` | A test account by user name, instead of `--identities`; repeat it for a second account. The password comes from the variable `VAR`, or is asked hidden. See [Test accounts on the command line](#test-accounts-on-the-command-line-ver-041). | VER-041 |
| `--admin-account USER[=VAR]` | A privileged test account. It sends only GET, HEAD and OPTIONS, also with `--allow-intrusive`. | VER-041 |
| `--login-url URL` | Where `--account` and `--admin-account` sign in. Default: the login entry point the assessment names for the target. | VER-041 |
| `--source DIR` | Checkout of the application's source code. The agent may read it, but not `.env` files, keys, credential stores or `.git/`. | — |
| `--proxy URL` | *Not implemented yet; set `proxy.url` in the scope file.* Route target and auth traffic through this HTTP(S) proxy, overriding the scope's `proxy.url`. Proxy credentials still come from the variables the scope names. | VER-029 |

### Select what to verify (VER-026)

All selectors read from the assessment and combine with AND. Without a selector the run verifies every finding that can be tested dynamically (VER-006) and says so before it starts. Prefer categories and severities over CWEs.

| Flag | Meaning |
| --- | --- |
| `--category LIST` | Classes or finer techniques: `access-control`, `idor`, `sqli`, `nosqli`, `xss`, `path-traversal`, `open-redirect`, `ssrf`, … So `--category idor` verifies IDOR alone. The guided run names the classes the assessment holds. |
| `--severity LIST` | Exact severities, e.g. `critical,high`. |
| `--min-severity LEVEL` | Severity floor: `low\|medium\|high\|critical`. |
| `--strict-severity` | Keep the floor exact: add no findings below it (see below). |
| `--only ID[,ID]` | Specific finding ids, e.g. `T-037,F-001`. Overrides the other selectors. |
| `--class LIST` | (advanced) Weakness classes. |
| `--cwe LIST` | (advanced) Specific CWEs, e.g. `CWE-79,CWE-639`. |

With `--min-severity` and without `--strict-severity`, up to eight findings below the floor are added within the other filters: declared prerequisites of selected findings, and access or exposure findings on `/actuator`, `/management`, `/admin`, `/metrics` or `/debug` routes. Health, readiness and liveness routes do not qualify on their own. The test plan names each addition and its reason before the confirmation. `--severity`, `--only`, category and CWE filters stay strict. An added finding that lacks an operator resource is still not tested.

A finding can name prerequisites with `verification_dependencies: [T-002]` in the assessment; selected prerequisites run first. Only these explicit dependencies set an order, and cyclic dependencies establish none. The agent also gets bounded planning context from `attack_steps`, the optional `attack_walkthrough`, related `components`, `data_flows`, `trust_boundaries`, `security_controls`, and the optional `compound_chains`, which use `findings` IDs or `keystones`/`contributors` entries with `ref` IDs. A prior result covers only its own requests. The transitions between findings stay unverified, so verified findings do not establish a complete attack chain.

### Boundaries — cost and load (VER-015)

| Flag | Meaning |
| --- | --- |
| `--cost-limit USD` | Model spend for the run. Reaching it stops the run (exit 3), and so does a model call that reports no usable cost. Rejected with `codex-cli` and `copilot-cli`, which report no cost. |
| `--max-requests N` | Total requests to the target. Refused requests are not counted. |
| `--max-attempts N` | Agent steps per finding; each step is one model call that proposes a tool call or the verdict. Default 12. Reaching it ends the finding `inconclusive` with `limits_hit: attempts`. |
| `--max-calls N` | Model calls for the run, for every profile. |
| `--max-duration S` | Run time in seconds. |
| `--rate RPS` | Requests per second to the target and its login endpoints, redirect hops and the proof browser included. `0` turns the rate limit off. |

The defaults are in `data/limits.yaml`. Every limit must be greater than 0; only `--rate` accepts 0. A negative or zero limit, or a key in `data/limits.yaml` that the Verifier does not enforce, blocks the run (exit 2) before anything is contacted.

When the cost, request, call or time limit or the end of the scope window is reached, the finding under test ends `inconclusive`, the remaining findings are reported `not-attempted` with the limit in `limits_hit`, no further model call is made, and the run exits with 3. After three failed model calls in a row, for example an exhausted quota or a rejected key, the run makes no further model call and the remaining findings end `inconclusive` with the reason.

A failed request is not retried. Only GET, HEAD and OPTIONS may be resent once after a 401 and a session renewal; POST, PUT and PATCH are never resent. Each answer is read for at most 30 seconds and up to 10 MiB after decompression; a slower or larger answer ends that request with an error the agent sees.

Ctrl-C stops the run: the finding under test ends `inconclusive`, the remaining ones are `not-attempted`, the report is written with the results so far and `meta.interrupted: true`, and the run exits with 130.

### Continuous control (VER-036)

Before each model call and each tool action, the Verifier checks the remaining run time and the scope window, and it checks each request of a batch separately. When either runs out, active work stops, final proof rendering and screenshots included. Recorded exchanges are still saved, without browser or network activity, within five more seconds. A screenshot timeout keeps the verdict and the recorded evidence, notes the missing image and stops further findings. These deadlines need POSIX timers in the main thread; where they are missing, for example on Windows, active verification stops. Offline commands work everywhere.

Each request must match a route of the selected finding variant, the finding's declared endpoints or its `test_resources`. With `--source`, a literal `get('/route', ...)`, `app.get` or `router.get` declaration up to 40 lines before the finding's evidenced location can also supply a route, with its HTTP methods. Without a route no request is sent; the Verifier does not guess. Once a test plan is accepted, later requests are limited to its route and method, and experiment requests must use its declared input and control values. Access-control requests keep the declared resource inputs and roles. When the Verifier creates the resource itself, only the owning account may also write to the finding's routes. A variant's input declarations also restrict parameter names. Diagnostic requests before a plan are allowed within the same limits.

The same read request or action may run twice per finding, so proof controls can be repeated; the same write request runs only once. A third repetition is stopped before it runs. Three tool errors or HTTP server errors in a row stop the finding before the next model call. Rewording a plan does not reset these counts. A plan the Verifier rejects is not a repetition, so the corrected plan can still run, but the rejection counts as a tool error. The finding then ends `inconclusive` with `limits_hit: stagnation`, its reason and the evidence so far, and the other findings continue. This is no negative verdict about the target.

Model decisions, request actions and HTTP requests are counted separately. `--max-attempts` limits both the decisions and the HTTP or browser actions per finding. A batch is one decision but several request actions; browser resources and logins count against `--max-requests`. With each step the model is told how many decisions and requests are left.

Source files larger than 1 MiB are not read. An agent CLI call whose output exceeds 1 MiB is ended.

### Output mode and run mode

| Flag | Meaning | Req. |
| --- | --- | --- |
| `--output DIR` | Report and evidence directory, created owner-readable. Default `./verification`. | VER-020 |
| `--report` | Write a standalone report and leave the assessment untouched. Default. | VER-020 |
| `--print` | List every finding in the results at the end, unsupported or incomplete ones included, with the whole reason. | VER-013 |
| `--show-costs` | Show model costs on the console also with subscription billing (see [Console output](#console-output)). Changes no limit and nothing in the report. | VER-015 |
| `--resume` | Continue the report in `--output`. A finding variant with `confirmed`, `not-reproducible` or `blocked-by-control` and a checked proof of the current contract (3) keeps its result; older or unchecked results and all other selected findings (inconclusive, not attempted, or not in the report) are tested, and their results replace the earlier ones. Different variants and their evidence are merged, and the action log is continued. When every selected finding has a verdict, nothing is contacted (exit 0). Without a report in `--output` the run starts as usual. A report that cannot be read, does not match `schemas/verification.schema.yaml`, or was written for another assessment (by SHA-256) or target blocks the run (exit 2) before anything is contacted. Cannot be combined with `--overwrite`. | VER-027 |
| `--overwrite` | Replace a report already in `--output` (`verification.md` or `verification.yaml`). Without it, and without `--resume`, such a report stops the run (exit 2) before anything is contacted. | VER-027 |
| `--annotate` | Also write annotated copies of the assessment and of the Analyzer's Markdown report to `--output`; the originals stay unchanged. See [Annotated copies](#annotated-copies-ver-027-ver-038-ver-039). | VER-027/038/039 |
| `--non-interactive` / `--ci` | No prompts: selection, scope confirmation and cost limit all come from the command line. Recorded in the report. | VER-002/026 |
| `--yes` | Confirm the test without a prompt. Recorded in the report. | VER-002 |
| `--allow-intrusive` | Leave [safe mode](#safe-mode-ver-030) for marked write requests, with or without a scope file. A scope file with `allow_state_change: false` stops such a run before anything is contacted. Recorded in the report. | VER-030 |
| `--read-only` | No write requests, even with `--allow-intrusive`. | VER-014 |
| `--dry-run` | Resolve selection and scope, print the plan, then stop: writes nothing, contacts nothing. | VER-008 |
| `--test-all` | Also test the findings listed under `Not testable`; by default they are reported `not-attempted` with the reason. | VER-008 |
| `--headful` | Show the proof browser (local debugging only). | VER-009 |
| `--screenshots CLASSES` | Classes that get screenshots, comma-separated: `xss`, `access-control`, `injection`, `open-redirect`, `path-traversal`, `ssrf`, `session`; or `none`. Default: all. Proofs do not depend on screenshots. | VER-035 |
| `--profile NAME` | Model profile (below), as in AppSec Analyzer. Default `claude`; required with `--non-interactive`. | VER-023 |
| `--model NAME` | Model for the selected profile; default is the profile's model. | — |

**Model profiles.** The profile decides which agent CLI or API plans each step. An unavailable profile (CLI missing or too old, not logged in, key missing, model unknown) stops the run before anything is contacted.

| Profile | Runs | Credentials | Default model | Spend |
| --- | --- | --- | --- | --- |
| `claude` | `claude -p` | Claude login, or `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` | `claude-sonnet-5-5` | reported in USD (API prices on a subscription) |
| `codex-cli` | `codex exec`, 0.163.0 or later | ChatGPT login only | `gpt-sol` | not reported |
| `copilot-cli` | `copilot`, exactly 1.0.101 | Copilot login | `gpt-5.4` | not reported; soft limit of 30 AI credits per call |
| `codex` | OpenAI Responses API | `OPENAI_API_KEY` | `gpt-sol` | tokens × `data/model-catalog.yaml` prices |
| `anthropic-api` | Anthropic Messages API through the `anthropic` SDK (`[agent]`, 0.87 or later) | `ANTHROPIC_API_KEY` | `claude-sonnet-5-5` | tokens × `data/anthropic-model-catalog.yaml` prices (Opus 5.5, Sonnet 5.5, Haiku 5.5, Fable 5.1; Haiku 5.5 at its higher rates when a prompt exceeds 100 000 tokens); an unlisted model is refused |

Whatever the profile, the model only proposes the next step as one JSON object, and the Verifier checks it against strict schemas and runs it with the same scope-guarded tools (VER-017, VER-019). Nothing invalid runs. A tool call whose arguments are not one JSON object or break its schema goes back to the model as an error and counts as a failed step; any other invalid step, such as an unknown action or an invalid verdict, ends the finding `inconclusive`. A step that fails (target not reachable, login rejected, unknown role) goes back to the model as an error. A finding whose check fails entirely ends `inconclusive`, and the run goes on.

The CLIs run in an empty temporary directory without built-in tools, MCP servers, settings, skills, custom instructions or session history. They get only the environment they need: no identity secrets and no API keys of other providers. For `claude` and `codex-cli` each call is also checked for tool use; a session that offers or uses a tool ends the finding `inconclusive` and stops all later model calls of the run. Copilot CLI prints only the answer, so its isolation rests on the pinned version and its flags. `codex-cli` and `copilot-cli` have only been tested with simulated answers.

### Test planning by the agent (VER-043)

Each declared variant of a finding is tested separately. Before collecting evidence, the agent declares a plan: its strategy, the data flow, prerequisites, the route, variant and identities a proof must match, a counter-hypothesis, the expected observation and when to stop. A revision explains the new observation and the next change. The console shows one line per accepted plan with its request and, for a revision, the reason; the report's appendix keeps the whole plans with their assumptions under `Test plan`.

The plan guides the agent but does not decide what counts. For a confirmation, cited requests count when they meet the proof of their class, whether they were sent before or after the latest plan, and a prerequisite the plan still lists as `missing` blocks nothing once the proof shows it was met. Injection experiments are the exception: they must be declared before their requests, and a new injection plan needs fresh evidence (VER-011). A negative result needs attempts after its plan.

When a verdict lacks the evidence its class requires, `proof_feedback` tells the agent which step is missing or must be repeated, such as `step 3 precedes the plan in step 5 and must be repeated`. The agent may then correct its experiment within the remaining step, request and model limits, in at most two correction rounds. A claim that stays unproven ends `inconclusive`, with the missing evidence in the report.

The assessment's optional `verification_context` (version 1) gives per variant the input locations, query construction, dialect and driver where known, processing and filter order, controls, prerequisites, observations, negative controls, unknowns and sources. The agent reads it on demand, together with the older mechanism traces, scenarios, attack steps and evidence, each within a size limit. Assessments without it remain readable. This context supplies hypotheses, never authorisation to test. When every declared variant needs custom request headers or browser interactions such as clicks, which the Verifier does not support, the finding is reported untestable before the run. Form bodies are supported with POST, PUT and PATCH in intrusive mode.

With `read_response` the agent can inspect or compare a JSON field or a window of 1,500 characters in this finding's recorded, redacted responses without sending another request. Up to 64,000 characters per response and 256,000 per finding are kept for this; a truncated body cannot support a field comparison.

### Proof per class (VER-009 to VER-013)

A `confirmed` verdict must name the steps that prove it in `proof_steps`, with step numbers as in `agent-log.jsonl`. The Verifier checks them in code against what its tools returned; evidence the model lists itself is never taken over. When the check passes, the Verifier adds the record it checked: for access control, injection, open redirect and path traversal `evidence/<finding>-exchanges.json` (owner-only), with method, path, parameters, body, identity, status, length and a hash of the redacted response body per cited step; for SSRF `evidence/<finding>-callback-hits.json` with time, method and source address of each hit.

**Access control (CWE-639, 862, 863, 306, 200).** With a `test_resources` entry from the scope, the same method, path and inputs must return the entry's harmless marker both to an allowed role and to a denied role with independent credentials. Two successful responses alone do not establish unauthorised access. A `test_resources` entry always takes precedence and gives confidence `high`. Exposure findings (CWE-200) and missing authentication (CWE-306) always need one. Without an entry, IDOR and missing-authorisation findings (CWE-639, 862, 863) can be proven in three more ways, each with confidence `medium`:

- Own resource, with two normal accounts and `--allow-intrusive`: the Verifier draws a random marker for the finding. One account, the owner, creates a record that holds the marker with one write to a route of the finding that names no existing record in its path, such as a POST to a collection, and reads it back. The same GET without a login must not show the marker; otherwise the resource is public and the finding stays `inconclusive`. If the other account's GET shows the marker, the finding is `confirmed`; 403 or 404 gives `blocked-by-control`. Only the owner may send the marker, and a read that sends it does not count. The created record stays on the target; the report gives its marker under `proof.marker`.
- Write on the own resource, with the same accounts, for a finding whose request changes a record by its identifier, such as `PUT /api/Feedbacks/:id`: the plan names that request as its change, and the Verifier draws a second marker. The owner creates the record as above and reads it back. Once the owner's read has shown the first marker, the other account sends the change with the second marker to the identifier the creating answer returned (in the `id` field of the answer or of its `data` wrapper, or in the `Location` header); any other identifier is refused, also that of a record nested in the answer, such as its owner. If the owner's next read shows the second marker, the finding is `confirmed`; if the change was answered 403 or 404 and the read still shows the first marker, it is `blocked-by-control`. When the finding names no GET request, the record is read with GET on the path of the change, and only that record. Without a request that creates a record and one that changes it, this proof is not available. The record stays on the target; the report gives both markers under `proof.marker` and `proof.second_marker`.
- Privileged function, with an `--account` and an `--admin-account`: when the privileged account gets a 2xx answer with content, the same GET without a login gets 401 or 403, and the normal account gets the identical answer, the finding is `confirmed`. 403 or 404 for the normal account gives `blocked-by-control`; any other answer stays `inconclusive`. The answers are compared as received, before credentials and user names are redacted, so an answer that names the signed-in user or holds that user's credential never counts as identical, while a list that names every user can. This shows that the normal account receives what the privileged account receives, not that the function is meant for privileged accounts only.

Roles with the same name and the same session never count as two accounts. For the preparation request the Verifier can add for these proofs, see [Runtime candidates and test preparation](#runtime-candidates-and-test-preparation).

**Injection (CWE-89, 943, 78, 1336, 643, 90).** The Verifier generates the controls itself, and only for an input the scope declares as literal data in [`injection_inputs`](#scope-file--scopeyaml-authorisation-ver-001). The declaration separates injection from an intended calculator, template editor or query language; fresh observations must still prove evaluation. Without it the agent can inspect the context and run bounded controls, but the proof plan is refused and the finding stays open. The agent declares the hypothesis, the one input to change and the observation before collecting evidence. A working baseline, a true condition and a false condition are each repeated at least twice, with all other inputs and the identity fixed. The selected JSON field must be stable, reproduce the nonempty baseline for the true condition and differ for the false one. A timing experiment never confirms injection, however clear the delay; it can only support a negative verdict, when all responses are identical successful answers within 0.5 seconds of each other. Reflected input, status changes, generic errors and ordinary search differences never confirm injection either, and citing one request several times does not count as a repetition. `run_experiment` collects the read-only controls twice, within the request, time and step limits. It never repeats a write, so a boolean or timing plan with a write method or a form field is refused before any request; injection through write requests cannot be tested even in intrusive mode. Declare a GET input only if that endpoint implements the same operation. Per mechanism:

| Mechanism | Plan | Controls |
| --- | --- | --- |
| SQL (CWE-89) | `sql_template` with one `{{predicate}}` placeholder | fresh complementary true and false predicates |
| NoSQL (CWE-943) | `operator_challenge: nosql` with `input_location: json` | a literal baseline lookup against fresh equality and membership operators, ten recorded requests |
| LDAP (CWE-90) | `predicate_template` with one `{{predicate}}` placeholder and an evidenced `predicate_attribute` | complementary filters that repeat the baseline for true predicates and suppress it for false ones, ten recorded requests |
| Command, template, XPath (CWE-78, 1336, 643) | `expression_template` with one `{{expression}}` placeholder | fresh products and sums that must appear in a selected JSON field |

Command templates are limited to a plain baseline followed by `; printf '%s' "$(({{expression}}))"`; other commands and extra inputs are refused.

**XSS (CWE-79).** A `browser_check` in which the marker executed. Each finding gets a random two-part marker. The payload must call `alert('<part1>'.concat('<part2>'))`, without `+`, which many applications read as a space in a query string, and only a dialog showing the joined value counts, so a page that merely echoes the payload text is not taken for execution. If any request of the probe carried the joined value itself, also percent-encoded, the dialog does not count either: a page that shows a parameter through `alert()` by design would display it without any injected script. Execution must happen in the checked page's main frame and origin, without a sandbox response policy; execution in a child frame stays unconfirmed because its permissions are not established. A `confirmed` XSS verdict without such an executed marker becomes `inconclusive` ("indicative, not executed"), whatever the model says. On execution the browser saves a JSON event record under `evidence/` (owner-only) and, unless `--screenshots` leaves out `xss`, a screenshot.

The proof browser is headless Google Chrome (Playwright, `appsec-verifier[browser]`; `--headful` shows it). Chrome opens no connection itself: every request of the page goes through the same scope check, limits and safe mode as the agent's HTTP requests, identity headers are added only for the identity's origin, redirects go back to the browser so each hop is checked, and anything else is aborted, service workers included. WebSockets are never connected. Chrome runs in a network namespace of its own (`unshare --user --net --map-current-user`) with only a loopback interface, so traffic the interception never sees, such as WebRTC over UDP, cannot leave the machine. This needs Linux, `unshare` from util-linux and unprivileged user namespaces, and Chrome runs with its own sandbox. Without Playwright or Chrome, or where the namespace or the sandbox is unavailable (other systems, some containers), the browser does not start and XSS findings cannot be confirmed. Without Playwright or Chrome the `Browser` line in the run settings says so; the line also names the classes that get screenshots. If Chrome fails during the run, that check ends with an error the agent sees, and the next check starts a new Chrome. A check takes at most about 45 seconds: 30 for loading the page, then the wait the agent asked for (at most 5), and 5 each for marking the page and taking its screenshot. A request of the page other than a document gets at most 5 seconds, so a long poll the server holds open does not hold up the check; a page that does not answer in time keeps its proof of execution but gets no screenshot.

**Open redirect (CWE-601).** A cited request answered 301, 302, 303, 307 or 308 whose `Location` leads to `<marker>.invalid`, a host drawn at random per finding. `.invalid` never resolves (RFC 6761). Redirects are never followed: a 3xx answer comes back with its `Location`, and a next hop is a request of its own.

**Path traversal (CWE-22).** A cited request whose response held the content of the scope's `marker_file`. The model is told the file's path, never its content, which shows as `[marker-file]` in every tool result. A request that itself carried the content does not count.

**SSRF (CWE-918).** A request with the finding's marker reached the callback listener; no `proof_steps` are needed. Each request gets a fresh marker, and only hits within that attempt's observation window count. A hit proves that retrieval, not that arbitrary internal addresses are reachable. To confirm, the scope must also set `callback.expect_rejected: true`, which states that fetching this destination violates the intended access policy; an intended URL-fetch feature is no SSRF. Without it a hit is recorded as retrieval observed and the finding stays `inconclusive`. The listener the Verifier starts by itself for a `localhost` target needs no declaration: it is on a loopback address, and an application that fetches a loopback URL it was given has reached an internal address.

Path-traversal and SSRF probes may aim only at these markers. In a path-traversal probe, a parameter or body value that names a file (it contains `..` or a NUL, or starts with `/`, `\`, `~` or a drive letter) must name the marker file; without `marker_file` in the scope no such value is sent. The traversal goes in a parameter or the body, because dot segments and encoded separators in the URL path are refused. In an SSRF probe, a value that holds a URL (`://` or a leading `//`) must point at the listener's origin. These rules also apply to query parameters written into the URL. Values are percent-decoded up to three times before the check; other encodings a target may accept are not decoded, and the agent is told the same rule.

The listener binds only to a loopback `callback.host`. When the target is on `localhost`, `127.x.x.x` or `[::1]` and the scope declares no `callback`, the listener binds to a free loopback port by itself, and the run settings say so. That works only when the target reaches this machine's loopback, e.g. a process started directly or a container run with `docker run --network host`; with `docker run -p` the container's `localhost` is the container itself, and SSRF findings stay `inconclusive`. A target on another machine reaches the listener through a TLS-terminating proxy or tunnel you run, named in `callback.base_url`, which must then be https. The listener answers every request with an empty 204, keeps only time, method and source address of requests that carry a marker, and is never a target of the Verifier itself. If it cannot bind, the run goes on and SSRF findings stay unconfirmed.

**Session cookies (CWE-614, 1004, 1275).** The scope's [`session_checks`](#scope-file--scopeyaml-authorisation-ver-001) names the cookie and a harmless GET that issues it. The agent declares a `session` plan with that entry and repeats the observation. CWE-614 checks Secure, CWE-1004 HttpOnly and CWE-1275 SameSite (Lax or Strict). An absent, expired or ambiguous cookie stays `inconclusive`. Cookie values never reach the model or the report. Session fixation, logout, expiry and token validation are not inferred from these attributes; they need separate checks.

**Negative verdicts and confidence.** Negative verdicts also need evidence. Without an answered request the result is `not-attempted`. Injection needs the same repeated controls, either with a stable nonempty observation or a repeatable rejection against a working baseline. Access control needs the declared resource visible to its allowed role and absent for an independent denied role; a 403 or 404 supports `blocked-by-control`. A timeout, scope refusal, missing capability or server error establishes no control. XSS needs a completed browser attempt that carried the marker parts; for the other marker classes an unsuccessful attempt stays `inconclusive`. Confidence is set by the check: `medium` for injection and checked negative results, `high` for other confirmed proofs, `low` for unresolved or unattempted findings. Every checked result and exported annotation states that it covers only its cited requests and variant.

### Proof of concept and evidence (VER-034, VER-035)

Every finding the agent tested gets a proof of concept, whatever the verdict, also when a limit stopped it. Each request an agent step sent to the target is recorded with its response: `http_request` gives one exchange (two when it renewed a session after a 401), `browser_check` every request of the page that the Verifier answered, with bodies only for documents, XHR and fetch. They are written to `evidence/<finding>-poc.har` (HTTP Archive 1.2, owner-only), which Burp, ZAP or a browser's developer tools can import. Each entry names its step (`_step`), and `_decisive` marks the steps the verdict rests on: for a confirmed verdict the steps its proof check used, for XSS also the `browser_check` in which the marker executed and for SSRF the request that reached the listener; for any other verdict the steps it cites in `proof_steps`. The model sees none of this beyond its own tool results.

The report lists every step in one line, a `browser_check` with the page it opened, and shows the decisive ones as HTTP excerpts: the request line with `Authorization` and `Content-Type` and up to 350 characters of the body, and of the response the status, a few headers and the part of the body that decides. A body of up to 600 characters and 12 lines is shown whole. A longer one is cut to a window around the part that decides (the marker file's content, the XSS marker, the first difference between two injection answers, otherwise the start). A long JSON body outside injection shows only its marked fields and fields such as `id`, `UserId` and `role`, and a long HTML page its visible text. For XSS the page source is left out when the marker is not in it, because the browser's observation decides. ⟦…⟧ marks the decisive parts; the HAR keeps the exchanges unmarked.

Before an exchange is recorded, headers the identity added read `[identity <role>]`. The following read `[redacted]`: the values of `Authorization`, `Cookie` and `Set-Cookie` (cookie names and attributes stay), of other headers whose name contains `token`, `secret`, `passw`, `api-key`, `session`, `credential` or the word `auth`, of query parameters named that way, every credential value the run knows and every JWT. Bodies are kept up to 256 KiB each after redaction and up to 4 MiB for all bodies of a finding, binary bodies only with type, length and hash. Other data the target returned stays, because the proof needs it; `export` never references the HAR file.

**Application screenshots.** For UI findings the leading image shows the exploit or its visible effect in the application, and the recorded HTTP exchanges always accompany it. In the report, application screenshots come before the HTTP details. For XSS it is the page where the marker executed. At the top the screenshot shows the URL as requested in an address bar, below it the dialog the payload opened with the marker as its text, drawn from the recorded call because a browser's own dialog never appears in a page screenshot (the image says so), then the section of the page around the payload element, at least 280 pixels high, with the element outlined in red, and below the page a caption with the finding, identity, status, time and payload element. Whatever of the page covers the payload element, such as a dialog and its backdrop, and floating layers that do not contain it, such as notifications or confetti, are hidden for the screenshot and named in the caption and in the event record; a bar along the top edge, such as the application's header, stays.

The agent shapes this evidence. Where a page of the application can show the effect, it may choose test inputs whose effect is visible there, such as XSS that also writes visible text; anything stored still carries the finding's marker. For confirmed access-control and injection findings it picks, in `browser_evidence`, a known UI route, a decisive successful GET step, up to three values from that step's response to mark, and optionally one of the run's identities (by default the step's). The browser opens that route once, read-only, under that identity, and saves the screenshot only when it reads the same resource successfully and finds a selected value on the page. This also covers the owner's read-back of a confirmed write. These requests count against the scope and run limits and are added to the HAR; they never repeat the write or change the verdict. For any confirmed finding, XSS included, the agent adds `image_explanation`, one sentence on what the leading screenshot shows, which the report prints under the image as `Test agent's explanation: …`; it is never proof. If no UI route is known, the browser cannot show the effect, or screenshots are off or unavailable, the report says so. API-only findings use the HTTP exchanges as their evidence; the Verifier does not make up a UI for them.

**Access-control pages.** For a confirmed access-control finding, each decisive response that is an HTML page is rendered in the proof browser from the recorded, redacted response, without a new request. Only the page itself is answered; images, styles and scripts are aborted and scripts are off, so the page may look unstyled. The caption names finding, step, request, identity, status and time. Up to three values the model names in `highlight`, such as the other identity's email, are marked in yellow where they occur in the response, and the caption says what is marked.

**HTTP screenshots.** Every tested finding gets `evidence/<name>-http-<n>.png` (names: see [Outputs](#outputs)) when `--screenshots` includes its class, also beside the page screenshot of an XSS or an access-control page. These images, like the explanation panels of the evidence review, stay in `evidence/` for later use and are not embedded in either report. They show the steps the verdict rests on; when the verdict cites none, for example because a limit stopped the finding, they show the answered requests after the last test plan, and the header says the image proves nothing. Request and response stand side by side as recorded and redacted, rendered in the proof browser without a new request, with up to two exchanges per panel. JSON is formatted, HTML error pages show their visible text, and routine headers and unrelated HTML are left out; the HAR keeps the complete exchanges. Each panel states the verdict and links it to the recorded steps. Unsuccessful HTML control responses stay in the panels and get no page image of their own. Marked in yellow, each with a red label (`payload`, `input`, `answer differs`), is what the Verifier can locate: the identities an access-control proof compares, the XSS or SSRF marker, the redirect host and the `Location` header, the marker file's name and content, the input and the part of the answer that differ between two injection requests, a different status, and the session cookie's `Set-Cookie` line with the checked attribute (`HttpOnly missing`); cookie values stay redacted. Above each step the image states facts about it, in bold where the verdict rests on them: the decoded injection input, the answer times when they differ by 2 seconds or more, for SSRF whether the listener received the marker, and for XSS which page the browser opened (with the payload, also when it sits in the `#` fragment that never reaches the server) and whether the marker executed.

The proof browser starts for screenshots only when a finding of an included class is selected; without Playwright or Chrome no screenshot is taken and the verdicts stand. No verdict depends on a screenshot.

### Safe mode (VER-030)

Safe mode is the default. Without `--allow-intrusive` the run sends only GET, HEAD and OPTIONS. It sends the most harmless payload that can still decide a verdict, keeps request count and rate low, and does no wordlist fuzzing, broad parameter sweeps or long series of payload variants.

Write requests (POST, PUT, PATCH), needed for stored XSS and some access-control cases, are sent only with `--allow-intrusive`, not with `--read-only`, and never when a scope file says `allow_state_change: false`. They carry unique markers and are logged (VER-014). The Verifier refuses a write that does not carry the finding's marker (the `vrf…` part named in the model's instructions) in its path or a value, and a write whose path names an existing record: a segment at a placeholder of the route (`:id`, `{id}`, `<id>`), or a segment of digits or a UUID. A write may create, never change what may belong to someone else, such as `PUT /api/BasketItems/1` in another account's basket. A `test_resources` request is sent as declared, and in a write proof the other account may change the record the owner created for that finding (see [Proof per class](#proof-per-class-ver-009-to-ver-013)). Identifiers in a request body are not recognised; the model is told not to name another account's record there. DELETE and every method other than GET, HEAD, OPTIONS, POST, PUT and PATCH are always refused.

A POST can still change or remove data, so use intrusive mode only against a test instance you can reset. A reused command line with `--allow-intrusive` writes to whatever target it names, so check the target before you confirm; a `localhost` reached through `ssh -L` or `kubectl port-forward` is a remote system. The Verifier does not clean up what it wrote; reset the target after the run.

### Interactive and non-interactive

- Interactive (default, with a terminal): the run prints its settings and waits for one confirmation before the first request (VER-002). A credential variable that is not set is asked for hidden before that, and sign-ins in your browser (`oidc-authorization-code`, `oidc-device-code`) happen after it, before the first finding. The run never asks again later. The guided run (above) asks for the settings first.
- Non-interactive (`--non-interactive` / `--ci`, or no terminal): no prompts. Selection, profile and confirmation (`--yes`) come from the command line; a missing confirmation stops the run. Every credential variable must be set, and an identity that needs a person to sign in stops the run before anything is contacted; use a login program or client credentials there.

### Console output

The console is laid out like AppSec Analyzer's, with a red logo and red accents instead of its turquoise. Before the first request `verify` prints its settings as `Key : value` lines: the assessment, the selection with its severity floor, the target with its scope and owner (or `no scope file`), the mode, the profile and model, and the limits. The guided run shows the assessment once at the start, with how many of its findings are runtime candidates and their severities, and does not repeat it in the settings. For selected classes that need a preparation and have it, one more line names it: `Identities` (roles only; with `--account` the `Accounts` line names them), `Browser`, `Callback` and `Marker file` (its path only). The `Report` line names the Markdown report `verification.md`, next to which `verification.yaml` (YAML, for tools, `--resume` and `export`) is written, and says `replaces` when `--overwrite` replaces a report already there. Then follow the test plan and the question `Proceed against this target? [y/N]`, or `[Y/n]` in the guided run.

During the run, `verify` prints one entry per event on standard error, in the columns `TIME FINDING EVENT PROGRESS ELAPSED LEFT DETAIL`, as AppSec Analyzer does, with a blank line between findings. FINDING is the finding under test and its position among the findings that get a probe. PROGRESS is the share of findings done and ELAPSED the run time. LEFT is estimated from the findings done so far and never exceeds what `--max-duration` leaves; before the first finding is done it shows that remainder (`≤29m`).

| EVENT | Shows |
| --- | --- |
| `start` | The finding's title, severity, class and up to two requests from the test plan. |
| `agent` | `▶ test agent started` with the model in short form and its runtime (`Sonnet 5.5 via Claude CLI`), its steps (`≤12 steps`, set with `--max-attempts`), the identities it may act as, and `source code` with `--source`; `■ test agent finished` with its steps and time. A finding not tested because an earlier one reached a run-wide limit has no `agent` entries. |
| `·` | A request, browser check or source read of the agent: its note on what the step checks, the request with its query and JSON body, the result, how long the model took to propose the step (`model 14s`) and, when costs are shown, the step's model cost (`$0.04`). A result a proof needs (`script executed`, `marker file read`, `callback hit`) is green. |
| `↻` | A step the Verifier refused. |
| `⚠` | A limit that stopped the finding. |
| `proof` | The proof check after the agent finished: green `✓ proof checked` with what the proof showed and the steps it rests on, or yellow `✗ no proof` with what the check missed, the limit that stopped the agent, or the agent's rationale. While steps are left, a rejected confirmation shows `✗ proof not accepted: …` and the agent continues. |
| `rating` | A [rating after verification](#annotated-copies-ver-027-ver-038-ver-039) that differs from the Analyzer's, e.g. `severity Medium → High · likelihood Low → High · confirmed with a checked proof`; shown also without `--annotate`. |
| `done` | The verdict in bold with a mark (`✔ confirmed`, `✘ not reproducible`, `✘ blocked by control`, `? inconclusive`), the time the finding took, when costs are shown the finding's model cost and the run's spend (`$0.08 · run $0.42 of $10.00`), and for a confirmed finding the agent's rationale. |

Under the `done` entry, one line per screenshot names where it lies (`screenshot verification/evidence/T-036-dom-xss-in-search-results.png`), with the EVENT `proof` when the Verifier checked the verdict's proof, otherwise `img`. The evidence review adds its own entries (see [Evidence presentation review](#evidence-presentation-review)). When a Claude CLI call fails, the reason names the CLI's error kind where it reports one, e.g. `host_error (error_max_turns, exit 1)`. Text from the assessment, the model or the target is shown without control characters and without credential values.

In a terminal the title is bold, the tested request stands on its own row in its own colour under the note, the rationale stands under the verdict, and amounts are highlighted. A status line underneath shows a progress bar, the run's spend so far when costs are shown (`$0.42 of $10.00`), the running step (`Sonnet 5.5 plans` during a model call, otherwise the request) and its age. Without a terminal each entry is one line, and a line with the status follows after two minutes without output.

Costs are shown with API billing (`codex`, `anthropic-api`, and `claude` with `ANTHROPIC_API_KEY` or a login that bills the API), and with `--show-costs` in any mode, as in AppSec Analyzer. With a Claude subscription the amount is what the calls would cost at API prices and is marked `at API prices`; with `codex-cli` and `copilot-cli` the `Run` row says `cost not reported (subscription)`.

At the end `Results` lists each finding that can be tested against the app: a mark (`✓` confirmed, `✗` not reproducible, `⊘` blocked by a control, `?` inconclusive, `·` not tested), id, severity, class, result and title, with the reason in one line under it. A finding this run could not test shows what it needs as its result (`needs test identity`). Confirmed findings come first. `--print` lists every finding, unsupported or incomplete ones included, with the whole reason. A `Run` row gives run time, model calls, requests and, when costs are shown, the spend against `--cost-limit`. `Done` then gives the paths of the report, its data, the evidence and the action log, and the count per result.

When a run cannot start or go on, `verify` says so on standard error in one form: a line marked `✗` with what is wrong, the details under it, a line marked `→` with what to do, and `Nothing was contacted.` when that is so.

On a terminal the output is in colour and starts with the logo. A confirmed finding is green; not reproducible or blocked by a control is red, which suggests a false positive; inconclusive is yellow. Severities and pre-flight results have their own colours. `NO_COLOR` (any value) turns colour off, `FORCE_COLOR=1` turns it on without a terminal, and `COLORTERM=truecolor` selects the 24-bit palette. Without a terminal, for example in CI or when redirected to a file, the output is plain text.

**Exit codes.**

| Code | Meaning |
| --- | --- |
| `0` | All selected findings were tested, whatever the verdict. A confirmed weakness is a successful run. |
| `2` | The run was blocked before testing: malformed assessment, unreadable, invalid or expired scope, unset proxy or identity variable, unusable model profile, missing confirmation, unreachable target, rejected login, failed model test, empty selection, no selected finding testable in this run, a report already in `--output` without `--overwrite` or `--resume`, or a `--resume` report that cannot be continued. |
| `3` | A limit was reached for at least one finding, for example the cost limit, the request limit, the steps per finding, or the end of the scope window. |
| `130` | Interrupted with Ctrl-C. A `verify` run that had started testing writes its report with the results so far. |

## `preflight` — check before a run (VER-032)

```
appsec-verifier preflight --assessment ./security-assessment.yaml --scope ./scope.yaml \
  [--url URL] [--identities ./identities.yaml] [--profile P] [--model M] \
  [--offline] [--json] [--yes] [--non-interactive] \
  [--test-model (--cost-limit USD | --max-calls 1) [--show-costs]]
```

Runs the checks `verify` runs before its first finding and tests no finding. Each check prints one line: `✓` passed, `⚠` works with a caveat, `✗` failed, `·` not checked or not applicable. `--account`, `--admin-account` and `--login-url` work as in `verify`; with `--offline` the login endpoint is checked without asking for passwords.

| Check | What it does | Contacts |
| --- | --- | --- |
| Assessment | Checks the fields the Verifier reads against `schemas/assessment.schema.yaml` and that finding ids are unique. Shows project, date, and how many findings are dynamic, static-only or input-incomplete. Messages name the place and the rule; only a repeated id is quoted, escaped. | nothing |
| Scope | Schema, window, URL inside the scope. | nothing |
| Proxy | The proxy URL is http(s) without inline credentials, and `username_env` and `password_env` are both set. | nothing |
| Identities | Schema, every `*_env` variable set (asked for hidden at a terminal, except with `--offline`), endpoints and `check_url` inside the scope, login programs found, and sign-ins that need a person only at a terminal. | nothing |
| Programs | The login programs the identities start, as written. They run at the login check below, with your rights. | nothing |
| Test plan | The test plan `verify` shows, for every finding and in safe mode: which findings a run tests, and which it cannot test, grouped by what they need, with how to add it and the lines to copy. Warns when a finding cannot be tested, never fails. Runs only when the checks above passed, and is printed after the checks, before the result. | nothing |
| Model | The profile resolves (CLI present and logged in, or key set; model known and priced). For `codex` and `anthropic-api` one metadata request shows the key is accepted and the model offered; it generates nothing and proves no quota. | the provider (not with `--offline`) |
| Target | One GET to the URL through the scope check and the declared proxy. A redirect is not followed. Any HTTP answer counts as reachable; 5xx warns. A failure names its cause: name resolution, refused connection, timeout, TLS certificate or handshake, proxy refusal or proxy authentication (407), or an address the scope refuses. | the target |
| per role | One login for `form`, OIDC and `command` identities, never retried; for `oidc-authorization-code` and `oidc-device-code` you sign in now. With `auth.check_url`, one GET there with the identity's credentials: 2xx accepted, 401 or 403 rejected, anything else unclear. `bearer`, `basic` and `session` without `check_url` are reported as not checked against the target. Two roles whose tokens name the same account (the same `iss` and `sub`) fail, because an access-control proof needs two independent accounts; sessions that do not name their account, such as cookies, are not compared. | target, login endpoints, login programs |
| Model test | Only with `--test-model` (`verify` always runs it, within its own limits): one fixed prompt without target data, findings or credentials. Passes when the host stays confined and replies with exactly the requested step. | the provider |

The offline checks run first; if one fails, nothing is contacted. The target and login checks run only after one explicit confirmation (VER-002), at the prompt or with `--yes`. `--non-interactive` without `--yes` contacts nothing and fails. A failed target check skips the logins.

`--test-model` needs its own limit: `--cost-limit` of at least USD 0.01 for `claude`, `codex` and `anthropic-api`, `--max-calls 1` for `codex-cli` and `copilot-cli`. It cannot be combined with `--offline` and runs only when all other checks passed. Its line shows the call's cost under the same rules as `verify`.

`--json` prints `{"kind": "preflight", "ok": …, "verification": "not_run", "checks": [{"check", "status", "message"}]}` on stdout, and the progress lines and the test plan on stderr. It never prompts, so contacting the target needs `--yes`.

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

Converts a finished `verification.yaml` into verdicts keyed by finding id and the cross-run `match_key` (VER-007), meant for AppSec Analyzer to mark findings with their verification status. The Analyzer does not read this file yet. It never changes or re-scores the assessment (VER-021), contacts nothing and makes no model calls. Default output: `analyzer-verification.json` in the working directory, as JSON. A file that cannot be read or does not match `schemas/verification.schema.yaml` stops it with exit 2.

## `update` — update the installed Verifier (VER-033)

```
appsec-verifier update
```

- Reinstalls the Verifier from the source pipx recorded at install time, such as GitHub or a local checkout. Credentials in a recorded URL are not shown.
- Shows the installed version and the source, then asks `[Y/n]`. Enter or `y` confirms; anything else, or closed input, installs nothing.
- Runs `pipx upgrade --pip-args=--force-reinstall appsec-verifier`, which you can also run yourself. `--force-reinstall` reinstalls even when the version number is unchanged, as is usual between GitHub commits. Like a new `pipx install`, it takes the newest dependency versions `setup.py` allows, not the pins of `requirements.lock`; packages added with `pipx inject` stay.
- Hides the pipx output and shows it only when the update fails (exit 2).
- Afterwards shows the new version as `appsec-verifier --version` prints it from the new installation: the engine version with commit and date of the build, e.g. `0.1.0a1 (a26a8e10, 2026-11-07)`. `(unchanged)` means the source had nothing newer.
- Needs an interactive terminal outside CI (`CI` set); no option skips the question. Otherwise it exits 2 and names the pipx command to run yourself.
- An installation without pipx (a venv from `requirements.lock`, an editable checkout) is not changed; update it the way you installed it.

To switch the source, run `pipx install --force` with the new source. A checkout installed with `pipx install --force .` stays the source: change it, for example with `git pull`, and run `update`.

`--version` names the build: commit, date and local changes, stamped at install time. A checkout without a stamp is read from Git, and a build without either shows `(commit unknown)`.

## Configuration files

### Scope file — `scope.yaml` (authorisation, VER-001)

The scope file states what the Verifier may contact, during which window, and who is responsible. Schema: `schemas/scope.schema.yaml`; examples in `examples/`. A minimal scope needs `schema_version`, `base_url`, `window` and `owner`; the README's quick start shows one.

Without a scope file, `--url` alone is the scope for that run: the URL's scheme, host and port, the whole host. Write requests need `--allow-intrusive` either way. You need a scope file for anything more: several hosts or ports, path prefixes, `deny_paths`, a host name that resolves to a private address (`networks`), a proxy, login hosts other than a `--login-url`, an SSRF callback for a target that is not on `localhost`, the marker file, test resources, injection inputs, session checks, or a test window and owner on record.

| Key | Meaning |
| --- | --- |
| `base_url` | Absolute http(s) URL of the target. Hosts and ports default to those of this URL. |
| `hosts`, `ports`, `schemes`, `path_prefixes` | What may be contacted. `schemes` defaults to the scheme of `base_url`, so plain http is allowed only when `base_url` or `schemes` names it. |
| `deny_paths` | Paths that are never contacted, compared regardless of case and percent-encoding. |
| `networks` | CIDR ranges of private or loopback addresses that may be contacted (see below). |
| `window` | Authorised test period (`from`, `until`, ISO 8601 UTC). |
| `owner` | The person or party responsible for the test. |
| `allow_state_change` | `false` forbids write requests: a run with `--allow-intrusive` stops before anything is contacted. Absent or `true` leaves it to `--allow-intrusive` (VER-030). |
| `auth_hosts` | SSO, OIDC and token endpoints that may be contacted only to log in, never tested. |
| `proxy` | HTTP(S) proxy for target and login traffic; credentials are named as environment variables (`username_env`, `password_env`), never in the URL. `no_proxy` lists hosts reached directly. |
| `callback` | Listener for SSRF proofs; `expect_rejected: true` states that the target must not fetch it (see [SSRF](#proof-per-class-ver-009-to-ver-013)). |
| `marker_file` | Path and token of the marker file for path-traversal proofs. |
| `test_resources` | Known harmless resources for access-control checks, each bound to a finding, a concrete request, allowed and denied roles, and an expected response marker. |
| `injection_inputs` | Inputs that must treat their value as literal data, per finding; needed for injection proofs. |
| `session_checks` | Session cookies to check, each with a harmless GET that issues it. |

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

Use the actual finding ID, path, roles and a non-sensitive marker from your test setup. `pointer` selects a JSON response field in JSON Pointer syntax. An empty pointer checks a literal text marker instead, which must not occur in the request. `anonymous` names a caller without credentials. Optional `params`, `json` or `form` bind fixed inputs; choose one body format. Role lists must be disjoint, and the resource must be inside the target scope. These entries state expected access; they allow no additional requests. Without a `test_resources` entry, IDOR and missing-authorisation findings can also be proven with two accounts and `--allow-intrusive`, or with an `--admin-account`; see [Proof per class](#proof-per-class-ver-009-to-ver-013).

For injection findings, declare the input that must treat its value as literal data:

```yaml
injection_inputs:
  - finding_id: T-012
    path: /search
    input_location: params
    input_name: q
    semantics: literal
```

For session-cookie findings, name the cookie and a harmless GET that issues it; omit `role` for an anonymous observation:

```yaml
session_checks:
  - id: customer-session
    finding_id: T-042
    path: /session-status
    cookie_name: sessionid
    role: customer-a
```

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

Both sign-ins happen after the confirmation and before the first finding. A run without a terminal refuses such an identity before anything is contacted.

A login program (`method: command`) covers everything else: a provider that needs a script, a classic login form with a CSRF token, or a CI run. `command` is the program and its arguments as a list; it is run without a shell from the directory of the identities file, so `./login.py` is found next to it. Any language works, e.g. `[/home/me/sso-venv/bin/python, login.py, user-a]`; use your own Python environment for what the program needs, not the Verifier's. The program prints the session on standard output, at most 64 KiB, either one line with a bearer token or one JSON object:

```json
{"headers": {"Authorization": "Bearer eyJ…"}, "cookies": {"SESSION": "…"}, "expires_at": "2026-11-08T14:30:00Z"}
```

`cookies` are sent as one `Cookie` header; `expires_at` (ISO 8601 with a time zone) or `expires_in` (seconds) say when to run it again. Only the header names listed in `headers` are accepted (default `[Authorization]`), and a value with a line break or another control character is refused. `timeout` is 120 seconds by default, at most 900. In an interactive run the program shares your terminal, so it can ask for a one-time code itself; write such prompts to standard error. Otherwise its input is empty. Its standard error goes to the terminal unchanged and is never recorded. It gets your environment without the model providers' credentials (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, `CODEX_API_KEY`, `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`). A program that exits with a status other than 0 is reported by that status only and not run again in the run. Otherwise it runs again only to renew the session: shortly before its expiry and once after a 401. The program's own requests are outside the run's scope, limits, rate and safe mode: it runs with your rights, like a command you start yourself. The run lists each program in its settings before the confirmation, and in the guided run a found identities file that starts programs needs its own yes.

Each identity sends its credentials only to the endpoint it names, which must be the target or a scope `auth_hosts` entry (VER-028). The session it obtains is attached only to its own origin, `auth.target_origin`, by default the target base URL; a request as that role to any other origin is refused, and its headers are removed when a redirect leads to another origin (VER-018). The Verifier keeps no cookies the target sets, so a session never travels in a cookie the target set for another identity.

A session whose expiry is known (an OIDC `expires_in`, the `exp` of a JWT, or a login program's `expires_at`) is renewed a minute before it expires: with the refresh token where the flow issued one, otherwise by logging in or running the login program again. When renewing a browser sign-in fails later in the run, that role is unavailable for the rest of it, because the run never asks again. A session from environment variables or a paste is not renewed and is no longer sent once it has expired. When a request is answered 401 again with a renewed session, that identity is not logged in again until one of its requests is accepted. A login the target refuses is not tried again in the run.

Before the first request `verify` checks the file against the schema, that every variable it names is set, that login endpoints and `target_origin` lie inside the scope, and that login programs exist. In an interactive run a variable that is not set is asked for without echo and kept only for the run; without a terminal the run stops with exit 2 and names the variable, never its value. To keep a value out of your shell history, set it with `read -rs VERIFIER_ALICE_PASS && export VERIFIER_ALICE_PASS`. A secret manager can set the variables for the one command, e.g. `op run --env-file=verifier.env -- appsec-verifier verify …`, `doppler run -- appsec-verifier verify …` or `sops exec-env secrets.enc.yaml 'appsec-verifier verify …'`. After the confirmation and before the first model call, every identity that logs in does so once; a rejected login stops the run (VER-032). A `bearer`, `basic` or `session` identity is checked against the target only when it names `auth.check_url`, a URL on the origin its credentials are sent to, which the pre-flight check requests once. Two roles signed in as the same account also stop the run.

Credential and token values are used only to obtain and send a session. They are never written to logs, the report, evidence files or a model prompt; only the role name is passed on, and recorded requests are stripped of Authorization headers, cookies and token parameters (VER-016, VER-022). If the target echoes a credential, every value the run knows (each variable's value, each value entered hidden or pasted, each token, refresh token and cookie value obtained, also JSON-escaped and URL-encoded) is replaced by `[redacted]` in tool results, the report and the proof of concept. Values shorter than 4 characters are not replaced, and application screenshots are not redacted.

### Test accounts on the command line (VER-041)

For a login that answers a JSON POST with a token, such as OWASP Juice Shop, you can name the accounts on the command line instead of writing an identities file:

```sh
appsec-verifier ./security-assessment.yaml --target http://localhost:3000 \
  --account jim@juice-sh.op --account bender@juice-sh.op=VERIFIER_BENDER_PASS --admin-account admin@juice-sh.op
```

Each `--account` is a user name, optionally followed by `=VARIABLE`, the environment variable that holds its password. Without a variable the password is asked hidden, e.g. `Password for account-1 (jim@juice-sh.op), hidden:`; without a terminal the run stops and names the account. `--account` and `--identities` cannot be combined, and the same user name given twice stops the run, because an access-control proof needs independent accounts.

The model knows the accounts as `account-1`, `account-2` and `admin-1`, never by user name or password. User names are redacted like passwords, but they stand in your shell history and, while the run lasts, in the process list. The model is told that an `--admin-account` is privileged. Its answers are the reference for privileged functions, and it never creates a resource (VER-010; see [Proof per class](#proof-per-class-ver-009-to-ver-013)).

The accounts sign in at `--login-url`, or else at the one POST entry point in the assessment's `attack_surface` whose path looks like a login (`login`, `signin`, `logon`, `authenticate`, `session`), below the target URL. When the assessment names none or several, the run stops before anything is contacted and lists what it found; give the endpoint with `--login-url`. Without a scope file, a `--login-url` on another host is allowed for this run only to sign in, and it must be https unless it is on the target or this machine; with a scope file it must be the target or an `auth_hosts` entry. The run settings show the endpoint before the confirmation, e.g. `account-1, account-2 · sign in at POST /rest/user/login (from the assessment)`, with the full URL when the endpoint is not below the target. The model chooses the field names.

After the confirmation, one model call proposes up to two pairs of field names for the user name and the password, from the endpoint and, with `--source`, the handler's source. The model sees no value. Each account then tries at most two pairs, and a pair that worked is used for the other accounts. A login that returns no token stops the run, e.g. `Login fields … no token for account-2. A login that does not answer a JSON POST with a token needs --identities`. The token is sent as `Authorization: Bearer` and renewed like a `form` login from an identities file.

### Limits — `data/limits.yaml`

Default limits of a run: model cost, model calls, requests, steps per finding, run time and request rate. `--cost-limit`, `--max-calls`, `--max-requests`, `--max-attempts`, `--max-duration` and `--rate` override them per run (VER-015).

## Outputs

Written to `--output` (default `./verification`):

- `verification.md`: the report. At the top: target, run, mode, scope, authorisation and, when the Analyzer's report lies next to the assessment (its name with `.md`), a link to it. The summary counts the results and lists the tested findings, each linked to its entry, with the result (🟥 confirmed, 🟩 not reproducible or blocked by control, 🟨 inconclusive), the rating before and after verification in the Analyzer's severity colours ([VER-039](#annotated-copies-ver-027-ver-038-ver-039), a change in bold and listed under the table) and one line on what the test showed or why it is not confirmed; then the findings not tested, most severe first, with what the run lacked. Each tested finding follows with a table of result and confidence, rating, CWE and class and, with the Analyzer's report, a link to the finding there (shown as `F-005` for `T-005`, as that report names it). Below it: what the checked proof showed, built from its steps and never from the model's words, or why it is not confirmed (what the proof check missed, the limit that stopped it, or the comparison that is missing); the limits of the proof and any deviation; the requests as a table with the steps the verdict rests on in bold; the application screenshot; the proof of concept with request and response of each decisive step in one block; and the `match_key` and evidence files. A collapsed appendix holds per tested finding the test plan, the test agent's own explanation, its other observations (not verified) and the evidence review.
- `verification.yaml`: the same results as data (`schemas/verification.schema.yaml`), each entry linked to its finding by id and `match_key` (VER-007, VER-020).
- `agent-log.jsonl`: written once the target is contacted, owner-only. One JSON object per agent step of every finding, with `time`, `finding`, `step` and either the tool call (`tool`, `args`, `result` with status, body length, error or the browser's blocked requests), a refused step (`refused`, `proposal`), a limit that stopped the finding (`stopped`, `reason`) or the `verdict` (VER-017). A finding whose probe failed gets `probe_failed` with the error type and `at` with file and line in the Verifier, never the error message; the finding under test when the run was interrupted gets `interrupted`. It holds no response bodies or source text, and credential values are redacted (VER-016). `--resume` continues it; otherwise each run starts it fresh.
- `evidence/`, owner-only: `<finding>-poc.har` for every tested finding, the proof records `<finding>-exchanges.json` and `<finding>-callback-hits.json`, and the images, named after the finding and its title, such as `T-042-product-update-route-has-no-authorization-guard` for "Product update route has no authorization guard — server.ts:369": the application screenshot `<name>.png` of an executed XSS, an application page or an access-control page (more than one: `<name>-2.png`), for an executed XSS marker its record `<name>.json`, the HTTP screenshots `<name>-http-<n>.png` and the evidence review's explanation panels `<name>-explanation-<n>.png` (see [Proof of concept and evidence](#proof-of-concept-and-evidence-ver-034-ver-035)). The title becomes lowercase ASCII words joined by hyphens, at most 60 characters, without the file and line at its end; a finding with variants keeps its variant key after the finding id.
- With `--annotate`: `security-assessment.annotated.yaml` and `security-assessment.annotated.md`, with the figures of the Analyzer's report (see below; VER-027, VER-038).

Recorded responses and screenshots can show target data, and application screenshots are not redacted. The report marks them for review before you share them (VER-022). The `export` command writes `analyzer-verification.json` for AppSec Analyzer (VER-021).

### Annotated copies (VER-027, VER-038, VER-039)

With `--annotate` the run writes two copies next to its report. The assessment and the Analyzer's report stay unchanged, also because AppSec Analyzer records a SHA-256 of each file it saved and refuses `export` and `review` of an assessment whose files changed.

`security-assessment.annotated.yaml` is the assessment with a top-level `dynamic_verification` entry for the run (schema version, time, Verifier version, path of `verification.yaml`) and a `dynamic_verification` block on each finding of the report: verdict, confidence, time, result id, what the checked proof covers, the rating after verification, and the paths of the proof of concept (HAR) and of the screenshots, relative to the report. A finding is found by its id, and by its `match_key` only when the tested finding has another id in this assessment and no other untested finding carries that key, so a finding that merely shares the key of a tested one gets no block. The block distinguishes a confirmed weakness from incomplete coverage of a finding's variants, and carries no requests, responses or images. Schema: `schemas/annotated-assessment.schema.yaml`. Nothing else in the document changes, so it stays valid against the Analyzer's schema, and the Analyzer's own `verification` field is kept.

`security-assessment.annotated.md` is written when the Analyzer's Markdown report lies next to the assessment under the same name, `security-assessment.md` for `security-assessment.yaml`. It is a copy of that report with three additions. A `Dynamic verification` section before the Management Summary names the target, counts the verdicts and lists each tested finding with the Analyzer's severity and the severity after verification. The changelog table gets a row for the verification run at the top; a report without that table gets the entry in the new section instead. Each tested finding gets a `Dynamic verification` section at its end with the verdict, the rating after verification, the agent's rationale (quoted), the proof of concept and the screenshots. Findings that were not tested get no section.

A finding whose anchor in the report is missing or appears more than once is listed at the end of the copy. Figures the report names by a plain file name are copied next to the copy. A report larger than 32 MiB is not copied, and the `Annotated report` line in `Done` says why when no copy is written. The copy contains recorded responses and screenshots; review it before sharing (VER-022).

**Rating after verification (VER-039).** The Analyzer's rating stays as it is; both copies show a second one next to it. Severity is the Analyzer's `effective_severity`, else its `risk`. The rules:

| Verdict, with a checked proof | Likelihood | Severity |
| --- | --- | --- |
| confirmed, likelihood below High | becomes High | one level higher, at most Critical |
| confirmed, likelihood High or Critical | unchanged | unchanged |
| blocked by control | one level lower | one level lower, at least Informational |
| any other verdict, or no checked proof | unchanged | unchanged |

Impact never changes. Of a finding with declared variants, one confirmed variant counts, and a block counts only when every variant was blocked. A block covers only the tested requests: a filter that rejects the test payloads lowers the rating although another path may still work, which is why the Analyzer's rating stays next to it. A finding whose likelihood or severity is not one of the Analyzer's levels (Critical, High, Medium, Low, Informational) is not rated. During `verify` the console shows a changed rating as a `rating` entry, with or without `--annotate`.

### Runtime candidates and test preparation

Before testing, each finding is listed as a candidate for runtime testing or as unsupported or incomplete. A supported CWE makes a finding a candidate; it does not mean the run has a suitable proof method and every prerequisite. A CWE without a supported proof method is `unsupported`, not automatically static-only; older reports with `static-only` remain readable. `preflight --offline` reports missing request information, missing test preparation and unsupported proof methods separately.

For access-control findings, the preparation adds, for each record route the finding names (a GET, PUT or PATCH ending in a placeholder such as `/api/Addresss/:id`), the POST that the assessment's attack surface lists for its exact collection (`POST /api/Addresss`), also when the finding itself does not name it (VER-043). A parent path, a sub-route or another method never counts, and no route is invented. The test plan shows the preparation request before the run. It needs two normal accounts and `--allow-intrusive`, and only the owner under an accepted access-control plan can use it, with the usual marker, scope and write checks. Once such a request is answered, the result records it as a deviation (VER-008): `Deviation: the owner created its own test resource with POST /api/Addresss, a route the assessment names for this resource outside this finding (VER-043).` Existing reads, or the existing read of a created record under a change plan, supply the comparison.

## Evidence presentation review

After all tested variants of a finding finish, a separate model reviewer checks whether the evidence text explains the scope, identities, comparison and result. It also gets the checked proof, the metadata of the application screenshots, including the observed XSS execution, and layout checks done in code, such as screenshot dimensions; panels larger than 1280 by 1200 pixels are flagged.

The reviewer also looks at the application screenshots the report shows and judges whether a reader sees the exploit or its effect: the marked element or value visible and not covered, enough application context, and caption and agent explanation consistent with the image. It reports image problems as `screenshot` issues. Only application screenshots go to the model, at most three per review call, never HTTP, exchange or explanation-panel images. A screenshot is sent only if its visible text, its form field values and the text drawn around the image held no credential value and no content of the scope's marker file when it was taken. Pixels themselves cannot be redacted, so an image that fails this check, or whose text could not be read, stays out of the review. The images sent can show target data, for example account names, and each costs about 1,000 to 1,500 input tokens per review. All five profiles can send images; `codex-cli` only when its version offers `exec --image`. If a host rejects a call with images, the rest of the run reviews text only. The report lists the screenshots a model reviewed, or says that none was shown, and the console says why.

If the reviewer finds a problem, the original test agent gets the feedback and can add a short explanation with exact quotes from the recorded request or response. If no excerpts were recorded, it can explain the missing evidence without inventing a quote. `verification.yaml` keeps these explanations and quotes as explanations, not additional proof; the report leaves them out, because they repeat its proof of concept. With screenshots enabled, a correction also produces a compact explanation panel beside the original evidence; the full HAR and the original images stay. Corrections never change the verdict, confidence or proof check, and they contact the target in one case only: for a `screenshot` issue on a confirmed access-control or injection result, the test agent can choose another page as in `browser_evidence`. The Verifier opens it once per correction round, read-only and with the same checks; the new screenshot replaces the earlier one only if the page shows a selected value, and its requests are added to the HAR.

Each finding has at most two correction rounds, shared by its tested variants: one first review, at most two corrections and two further reviews. That is at most five more model calls, within the run's cost, call and time limits and with the selected profile. Repeated issues without improvement, unchanged corrections, invalid responses, cancellation or exhausted limits end the review early. A failed review keeps the technical result.

The console shows `▶ evidence reviewer started` and `■ evidence reviewer finished` with the review status as `agent` entries, `review` and `revise` entries for each correction round and, when needed, `issue` entries, each with the finding ID. A review that never started gets a `quality` entry with the reason. The report's appendix records `clear`, `needs-attention`, `stopped` or `not-reviewed` apart from the technical verdict and the first sentence of each unresolved issue, with its variant where a finding has several; `verification.yaml` keeps the full text, and the annotated report shows the same after each finding's proof of concept. Untested variants are not reviewed. A finding with more than 16 tested variants, or with evidence too large for the review, is reported as not reviewed. The model sees only bounded, redacted excerpts, panel text and the cleared application screenshots, never marker-file content or credentials.
