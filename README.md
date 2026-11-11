# AppSec Verifier

AppSec Verifier tests whether the findings of a static security assessment can be reproduced in the running application. It reads the `security-assessment.yaml` written by [AppSec Analyzer](https://github.com/appsec-foundry/appsec-analyzer), tests the selected findings against a target you are authorised to test, and reports for each finding whether the weakness is real.

An AI agent plans each test step. The Verifier sends every request itself, only inside the scope you define, and counts a finding as confirmed only when the proof passes a check in code. It does not repeat the static analysis and does not change severities. This is an early version; see [Limitations](#limitations).

## Quick start

You need Python 3.10 or later, [pipx](https://pipx.pypa.io/stable/), an assessment from AppSec Analyzer, and the Claude CLI (`claude`), installed and logged in. Other models are listed under [Model profiles](#model-profiles).

1. Install the Verifier. XSS findings also need the proof browser; see [Install](#install).

   ```sh
   pipx install git+https://github.com/appsec-foundry/appsec-verifier.git
   ```

2. Optional: write a scope file. Without one, the guided run asks for the target URL (or takes it from `--target`) and tests only its host and port, read-only. A scope file can allow more, such as several hosts or a proxy, and records the test period and who is responsible:

   ```yaml
   # scope.yaml
   schema_version: 1
   base_url: http://localhost:3000
   window: {from: "2026-11-01T00:00:00Z", until: "2026-11-30T23:59:59Z"}  # your test period
   owner: {name: Your Name}   # who is responsible for the test
   ```

3. Optional: add test accounts. Access-control findings need two. For a login that answers a JSON POST with a token, name them on the command line, for example `--account jim@juice-sh.op --account bender@juice-sh.op`; the Verifier asks for the passwords with hidden input. Other logins, SSO included, go into an `identities.yaml` that names environment variables, never the passwords themselves ([example](examples/juice-shop/identities.yaml), [details](docs/cli.md#identities-file--identitiesyaml-sessions-ver-016028040)).

4. Start the guided run:

   ```sh
   appsec-verifier ./out/security-assessment.yaml
   ```

   It shows which findings it can test and what the others need, and tests findings of severity high and above with the `claude` profile (`--min-severity` and `--profile` change that).

5. Read the report in `./verification/verification.md`.

To try it on a deliberately vulnerable application, run OWASP Juice Shop locally (`docker run --rm -p 3000:3000 bkimminich/juice-shop`) and use the files in [`examples/juice-shop/`](examples/juice-shop/).

## What it verifies

A finding counts as `confirmed` only with the proof in the last column; the exact rules are under [Proof per class](docs/cli.md#proof-per-class-ver-009-to-ver-013), the CWEs in [`data/verifiable-cwes.yaml`](data/verifiable-cwes.yaml). Request details the assessment leaves open the agent takes from the source code and from forms and links on the target, within the finding and the scope ([test planning](docs/cli.md#test-planning-by-the-agent-ver-043)). [How verification works](docs/how-verification-works.md) follows one XSS finding through the agent's steps, its prompt and the proof check.

| Class | CWEs | Needs | Confirmed when |
| --- | --- | --- | --- |
| Cross-site scripting | 79 | the proof browser | a marker script runs in the browser; reflected text does not count |
| Access control | 639, 862, 863, 306, 200 | a test resource in the scope (`test_resources`); for 639, 862 and 863 alternatively two accounts and `--allow-intrusive`, or an `--account` and an `--admin-account` | an account gets a resource it must not get: the declared test resource, a record another account created, or the admin's answer |
| SQL, NoSQL and LDAP injection | 89, 943, 90 | an input the finding's evidence names, or one named in the scope (`injection_inputs`) | a field in the response changes with true and false conditions the Verifier generates; its injected marker comes back (SQL); or a malformed input makes the database report an error a valid one does not. A delay alone never counts. For a login bypass, the true condition logs in and the false one does not |
| Command, template and XPath injection | 78, 1336, 643 | as for SQL injection | the target returns the results of arithmetic the Verifier generates; for XPath and template injection, a malformed input makes the engine report an error a valid one does not |
| Blind code and template injection | 94, 95, 1336 | a callback listener the target can reach, as for SSRF | the injected payload makes the target call the listener; the same URL sent as plain data does not |
| Path traversal | 22 | a marker file named in the scope, or a disposable upload location for archives (`archive_checks`) and `--allow-intrusive` | the target returns the marker file, or a file from an uploaded ZIP can be read outside the directory it is unpacked to |
| Open redirect | 601 | nothing | the target redirects to a random host under `.invalid`; the redirect is not followed |
| SSRF | 918 | a listener the target can reach: started by the Verifier for a `localhost` target, otherwise named in the scope (`callback`) | the target calls the listener |
| Session cookie | 614, 1004, 1275 | the cookie named in the scope (`session_checks`) | the cookie repeatedly lacks Secure, HttpOnly, or SameSite Lax or Strict |

Each finding ends with one of these verdicts. A negative verdict covers only the request and variant that were tested.

| Verdict | Meaning |
| --- | --- |
| `confirmed` | The weakness was reproduced and the proof checked. |
| `not-reproducible` | Tested, but the weakness did not show. |
| `blocked-by-control` | A protection the static analysis could not see stopped the attack. |
| `inconclusive` | No decision, for example because a request failed, a limit was reached or the proof did not hold. |
| `not-attempted` | Not testable against a running system (such as a weak random number generator or a hard-coded secret), or not reached because a limit was hit or the run was interrupted. |

## Safety

`verify` is an active security test. These rules are enforced in code, outside the model:

- Only the hosts, ports, paths and schemes in the scope are contacted, and only within its time window. Private and loopback addresses must be listed in the scope (`networks`), unless the scope names the host as `localhost` or as an IP address. Cloud metadata addresses are never contacted.
- The Verifier shows the plan and asks before the first request. In CI, `--yes` gives this confirmation.
- By default it sends only GET, HEAD and OPTIONS. Write requests (POST, PUT, PATCH), needed for stored XSS and some access-control tests, require `--allow-intrusive` or, in a terminal, your yes when the test agent asks for one during a test, and a scope can forbid them with `allow_state_change: false`. Use them only against a test instance you can reset; records the Verifier creates stay on the target. DELETE is never sent.
- Requests, request rate, model calls, model cost and run time are capped; the defaults are in [`data/limits.yaml`](data/limits.yaml). A limit that is reached stops the finding or the run it applies to; in a terminal the run first asks whether to raise the cost limit. Ctrl-C stops the run and still writes the report.
- Passwords and tokens come from environment variables or hidden input and are not stored. They are kept out of the model's input, the logs and the report; the model knows the accounts by role name only. An `--admin-account` sends only GET, HEAD and OPTIONS.
- The model sees the target's responses and, for the evidence review, application screenshots. Both can contain target data such as account names. The error text a malformed input provokes and the token of a login bypass stay in the owner-only evidence; no model sees them.
- The agent proposes one step at a time, and the Verifier checks each step before it runs it. The agent has no shell and no file access. With `--source` it can read the target's source code, but not `.env` files, keys or `.git/`.

## Model profiles

Choose the model with `--profile`, as in AppSec Analyzer.

| Profile | Uses | Limited by |
| --- | --- | --- |
| `claude` (default) | Claude CLI with its login or `ANTHROPIC_API_KEY` | cost, calls, time |
| `codex-cli` | Codex CLI 0.163.0 or later with a ChatGPT login | calls, time |
| `copilot-cli` | GitHub Copilot CLI 1.0.101 with its login | calls, time |
| `codex` | OpenAI API with `OPENAI_API_KEY` | cost, calls, time |
| `anthropic-api` | Anthropic API with `ANTHROPIC_API_KEY`, no CLI needed | cost, calls, time |

The CLIs run without tools, MCP servers, settings or session history. Using a subscription is subject to the provider's terms for that plan.

The console shows model costs only with API billing: `codex`, `anthropic-api`, and `claude` with `ANTHROPIC_API_KEY` or a login that bills the API. With a Claude subscription, `--show-costs` shows what the calls would cost at API prices; `codex-cli` and `copilot-cli` report no cost. Whether costs are shown does not change the cost limit.

## Commands

| Command | Does |
| --- | --- |
| `appsec-verifier ASSESSMENT` | Guided run: asks for the settings, then runs `verify`. |
| `verify` | Tests the selected findings against the target. |
| `preflight` | Checks assessment, scope, target, logins and model, and shows which findings a run can test; tests no finding. `--offline` contacts nothing. |
| `scope` | Validates a scope file and shows whether a URL is inside it. Offline. |
| `export` | Converts a `verification.yaml` into a file for AppSec Analyzer. The Analyzer does not read this file. |
| `update` | Updates a pipx installation after you confirm. |

Select findings with `--category` (for example `xss`, `idor`, `sqli`), `--severity`, `--min-severity` or `--only <id>`. A severity selection also tests XSS and SQL or NoSQL injection findings of other severities when the assessment names a read request for them ([details](docs/cli.md#select-what-to-verify-ver-026)); `--strict-severity` leaves them out. All options are in [`docs/cli.md`](docs/cli.md) and in `appsec-verifier <command> --help`.

## Run without questions (CI)

The guided run prints the matching `verify` command before it asks for confirmation. With `--non-interactive`, or without a terminal, nothing is asked: `--yes` gives the confirmation and `--profile` is required.

```sh
appsec-verifier verify --non-interactive --yes --profile claude \
  --assessment ./out/security-assessment.yaml \
  --scope ./scope.yaml --identities ./identities.yaml \
  --min-severity high --cost-limit 5 --output ./verification
```

Run `appsec-verifier preflight` with the same files first to check them without testing a finding.

## Output

Before it contacts the target, `verify` shows the test plan: the findings it will test, and the findings it cannot test in this run with what they need. Those are skipped unless you add `--test-all`. During the run it prints each agent step with the request and its result, and each verdict with its reason ([console output](docs/cli.md#console-output)). At the end it lists every finding with its result.

`verify` writes to `--output` (default `./verification`):

- `verification.md`: the report, with verdict, confidence and evidence per finding, and the proof of concept: the requests the verdict rests on, as raw HTTP with the decisive part of the response, and for UI findings a screenshot of the exploit or its effect.
- `verification.yaml`: the same results as data ([schema](schemas/verification.schema.yaml)).
- `agent-log.jsonl`: every step of the agent, refused steps included.
- `console.log`, with `--console-log`: what the run printed, in colour or with `--console-log plain` without.
- `evidence/`: the recorded requests and responses of each finding (`<finding>-poc.har`) and the screenshots; `--screenshots` chooses the classes. They can show target data; check them before sharing. Known credentials are masked in application screenshots.

Two further model reviews run within the run's limits: one checks negative and unproven results for missing tests and whether a confirmed access-control result shows access the application intends, the other checks that the evidence of a confirmed finding is understandable ([technical QA](docs/cli.md#technical-qa-ver-046), [presentation review](docs/cli.md#evidence-presentation-review)).

`--resume` continues a run that did not finish: findings with a verdict keep it, the others are tested. A report already in `--output` is replaced only with `--overwrite`. `--annotate` also writes copies of the assessment and of the Analyzer's Markdown report with the verdict, the rating after verification and the proof of concept of each tested finding; the originals stay unchanged.

## Install

```sh
pipx install git+https://github.com/appsec-foundry/appsec-verifier.git
pipx inject appsec-verifier playwright==1.64.1    # proof browser, needed for XSS
pipx inject appsec-verifier 'anthropic>=0.87,<1'   # only for --profile anthropic-api
```

The proof browser uses the installed Google Chrome and starts it without network access, which needs Linux with `unshare` (util-linux) and unprivileged user namespaces. Elsewhere XSS findings cannot be confirmed.

For the CLI profiles, install the CLI and log in (`claude`, `codex login`, `copilot login`).

`appsec-verifier update` shows the installed version and asks before it reinstalls from the source you installed from. Like a new install, it takes the newest dependency versions allowed ([details](docs/cli.md#update--update-the-installed-verifier-ver-033)).

To install from a checkout with every package pinned and hash-checked in [`requirements.lock`](requirements.lock), the proof browser and the `anthropic` SDK included:

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install --no-deps --no-build-isolation .
```

## Configuration

- Scope file: [`schemas/scope.schema.yaml`](schemas/scope.schema.yaml), explained in [Scope file](docs/cli.md#scope-file--scopeyaml-authorisation-ver-001)
- Test accounts: [`schemas/identities.schema.yaml`](schemas/identities.schema.yaml): a bearer token, basic, form login, headers copied from the browser, an OIDC flow (sign-in in your browser, device code, client credentials, password grant) or a login program; see [Identities file](docs/cli.md#identities-file--identitiesyaml-sessions-ver-016028040) and [Test accounts on the command line](docs/cli.md#test-accounts-on-the-command-line-ver-041)
- Default limits: [`data/limits.yaml`](data/limits.yaml)
- Models and prices: [`data/model-catalog.yaml`](data/model-catalog.yaml) (OpenAI), [`data/anthropic-model-catalog.yaml`](data/anthropic-model-catalog.yaml) (Anthropic API)

Examples: [`examples/juice-shop/`](examples/juice-shop/) (local target, form login), [`examples/sso-proxy/`](examples/sso-proxy/) (target behind a company proxy, SSO sign-in in the browser) and [`examples/login-program/`](examples/login-program/) (a login program for a form with a CSRF token).

## Limitations

- Boolean injection checks need a stable JSON field in the response. Custom request headers and browser interactions such as clicks are not supported; findings whose variants need them are shown as untestable.
- How well the agent chooses its tests has been tried with a live model only against a local OWASP Juice Shop, with the `claude` profile. The proof browser has only been tested against a local fake target, and the `codex-cli` and `copilot-cli` profiles only with simulated answers.
- The path-traversal and SSRF checks decode percent-encoding, but no other encodings a target might accept.
- A sign-in in the browser works for applications whose API accepts the identity provider's token. An application that keeps its own session cookie after the SSO sign-in needs a copied session or a login program. Sessions copied from the browser are not renewed during the run.
- A confirmed finding shows that the tested step works, not that a complete attack chain does.

## Non-goals

The Verifier is not a scanner and not a pentest agent. It does not search for new weaknesses, chain exploits, extract real data or escalate privileges. It only tests the findings it is given.

## Development

Setup, checks and repository layout: [`AGENTS.md`](AGENTS.md). Requirements and their VER-IDs: [`requirements.md`](requirements.md).
