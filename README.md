# AppSec Verifier

AppSec Verifier checks whether the findings of a static security assessment can
be reproduced in the running application. It reads the
`security-assessment.yaml` written by
[AppSec Analyzer](https://github.com/appsec-foundry/appsec-analyzer), tests the
selected findings against a target you are authorised to test, and reports for
each finding whether the weakness is real.

An AI model plans each test step. The Verifier sends every request itself, only
inside the scope you define, and accepts a finding as confirmed only when the
proof holds up in a check in code. It does not repeat the static analysis and
does not change severities.

This is an early version; see [Limitations](#limitations).

## Quick start

You need Python 3.10 or later, [pipx](https://pipx.pypa.io/stable/), an
assessment from AppSec Analyzer, and the Claude CLI (`claude`), installed and
logged in. Other models are listed under [Model profiles](#model-profiles).

1. Install the Verifier:

   ```sh
   pipx install git+https://github.com/appsec-foundry/appsec-verifier.git
   ```

2. Optional: write a scope file. Without one, the guided run asks for the
   target URL and tests only that URL's host and port, read-only. A scope file
   authorises more, such as several hosts, a proxy or write requests, and
   records the test period and who is responsible. The Verifier contacts
   nothing outside it. For a test instance on your own machine:

   ```yaml
   # scope.yaml
   schema_version: 1
   base_url: http://localhost:3000
   window: {from: "2026-11-01T00:00:00Z", until: "2026-11-30T23:59:59Z"}  # your test period
   owner: {name: Your Name}   # who is responsible for the test
   ```

3. Optional: add test accounts in `identities.yaml`. Access-control findings
   need two of them. The file names environment variables, never the passwords
   themselves; see [`examples/juice-shop/identities.yaml`](examples/juice-shop/identities.yaml).

4. Start the guided run with the assessment:

   ```sh
   appsec-verifier ./out/security-assessment.yaml
   ```

   It shows how many findings can be tested and what they need, such as test
   accounts or the browser, and tests findings of severity high and above with
   the `claude` profile; `--min-severity` and `--profile` change that. Without a
   scope file it asks for the target URL, or takes it from `--target`. It asks
   once more before it sends the first request.

5. Read the report in `./verification/verification.md`.

To try it on a deliberately vulnerable application, run OWASP Juice Shop
locally (`docker run --rm -p 3000:3000 bkimminich/juice-shop`) and use the files
in [`examples/juice-shop/`](examples/juice-shop/).

## Run without questions (CI)

The guided run prints the matching `verify` command before it asks for the
confirmation. Without a terminal, or with `--non-interactive`, nothing is
asked; `--yes` gives the confirmation and `--profile` is required:

```sh
appsec-verifier verify --non-interactive --yes --profile claude \
  --assessment ./out/security-assessment.yaml \
  --scope ./scope.yaml --identities ./identities.yaml \
  --min-severity high --cost-limit 5 --output ./verification
```

`appsec-verifier preflight`, with `--assessment`, `--scope`, `--identities` and
`--profile`, checks the assessment, scope, target, logins and model without
testing any finding, and shows which findings a run can test and what the
others still need.

## What it verifies

A finding counts as confirmed only with the proof in the right column.

| Class | CWEs | Confirmed when |
| --- | --- | --- |
| Cross-site scripting | CWE-79 | a marker script runs in a real browser; text that is only reflected does not count |
| Broken access control / IDOR | CWE-639, 862, 863 | the same request succeeds with content for two different identities, or for one identity and without login |
| SQL / NoSQL injection | CWE-89, 943 | a different input changes the answer, or a delay input slows it by at least 2 seconds, measured twice; no data is extracted |
| Path traversal | CWE-22 | the target returns a marker file you placed on it |
| Open redirect | CWE-601 | the target redirects to a marker host that does not exist; the redirect is not followed |
| SSRF | CWE-918 | the target calls a listener the Verifier runs on your machine |

XSS needs the proof browser (see [Install](#install)), path traversal a marker
file named in the scope (`marker_file`), and SSRF a listener the target can
reach (`callback`). Details: [`docs/cli.md`](docs/cli.md).

Each finding ends with one of these verdicts:

| Verdict | Meaning |
| --- | --- |
| `confirmed` | The weakness was reproduced and the proof checked. |
| `not-reproducible` | Tested, but the weakness did not show. |
| `blocked-by-control` | A protection the static analysis could not see stopped the attack. |
| `inconclusive` | No decision, for example because a request failed, a limit was reached, or the proof did not hold. |
| `not-attempted` | The finding cannot be tested against a running system, such as a weak random number generator or a hard-coded secret, or it was not reached because a run limit was hit or the run was interrupted. |

The testable CWEs are listed in [`data/verifiable-cwes.yaml`](data/verifiable-cwes.yaml).

## Safety

`verify` is an active security test. It does only what you allow, and these
rules are enforced in code, outside the model:

- Only the hosts, ports, paths and schemes in the scope file are contacted, and
  only within its time window. Private and loopback addresses must be listed in
  the scope (`networks`), unless the scope names the host as `localhost` or as
  an IP address. Cloud metadata addresses are never contacted.
- The Verifier shows the plan and asks before the first request. In CI, `--yes`
  gives this confirmation.
- By default it sends only GET, HEAD and OPTIONS requests, with one harmless
  payload per test. Writing requests (POST, PUT, PATCH), needed for stored XSS
  and some access-control cases, require `--allow-intrusive` and
  `allow_state_change: true` in the scope. Use them only against a test
  instance you can reset. DELETE is never sent.
- Requests, request rate, model calls, model cost and run time are capped; the
  defaults are in [`data/limits.yaml`](data/limits.yaml). A limit that is
  reached stops the finding or the run it applies to. Ctrl-C stops the run and
  still writes the report with the results so far.
- Passwords and tokens are read from environment variables. They are kept out
  of the model's input, the logs and the report; the model only sees role
  names.
- The model proposes one step at a time, and the Verifier checks each step
  before it runs it. The model has no shell and no file access. With
  `--source` it can read the target's source code, but not `.env` files, keys
  or `.git/`.

## Model profiles

Choose the model with `--profile`, as in AppSec Analyzer.

| Profile | Uses | Limited by |
| --- | --- | --- |
| `claude` (default) | Claude CLI with its login or `ANTHROPIC_API_KEY` | cost, calls, time |
| `codex-cli` | Codex CLI 0.163.0 or later with a ChatGPT login | calls, time |
| `copilot-cli` | GitHub Copilot CLI 1.0.101 with its login | calls, time |
| `codex` | OpenAI API with `OPENAI_API_KEY` | cost, calls, time |
| `anthropic-api` | Anthropic API with `ANTHROPIC_API_KEY`, no CLI needed | cost, calls, time |

The CLIs run without tools, MCP servers, settings or session history. Use of a
subscription is subject to the provider's terms for that plan.

As in AppSec Analyzer, the console shows model costs only with API billing:
`codex`, `anthropic-api`, and `claude` with `ANTHROPIC_API_KEY` or a login that
bills the API. `--show-costs` shows them with a subscription too. The Claude CLI
then reports what the calls would cost at API prices and marks the amount `at
API prices`; `codex-cli` and `copilot-cli` report no cost. The cost limit
applies either way.

## Commands

| Command | Does |
| --- | --- |
| `appsec-verifier ASSESSMENT` | Guided run: asks for the settings, then runs `verify`. |
| `verify` | Tests the selected findings against the target. |
| `preflight` | Checks assessment, scope, target, logins and model, and shows which findings a run can test; tests no finding. `--offline` contacts nothing. |
| `scope` | Validates a scope file and shows whether a URL is inside it. Offline. |
| `export` | Converts a `verification.yaml` into a file AppSec Analyzer can read. |
| `update` | Updates a pipx installation after you confirm. |

Select findings with `--category` (for example `xss`, `idor`, `sqli`),
`--severity`, `--min-severity` or `--only <id>`. All options:
[`docs/cli.md`](docs/cli.md) or `appsec-verifier <command> --help`.

## Output

Before it contacts the target, `verify` shows a test plan: the findings it will
test with the requests the assessment names, and the findings it cannot test in
this run, grouped by what they need (a test identity, the proof browser, a
marker file, a callback, or `--allow-intrusive`) and how to provide it. Those
are not tested unless you add `--test-all`.

While `verify` runs, it prints its progress on standard error: one line when a
finding starts, one per request or source read of the agent with what it
checks and its result, and one with the verdict and its reason: green
confirmed, red not reproduced, yellow inconclusive. Each line shows the
finding, the share of findings done, the run time and the time left. In a
terminal a status line underneath shows the running step and how long it has
been running.
[`docs/cli.md`](docs/cli.md#verify--verify-findings-against-a-running-target)
describes the columns.

`verify` writes to `--output` (default `./verification`):

- `verification.md`: the report, with verdict, confidence and evidence per
  finding, and the proof of concept: the requests the verdict rests on, as raw
  HTTP with the decisive part of the response.
- `verification.yaml`: the same results as data
  ([schema](schemas/verification.schema.yaml)).
- `agent-log.jsonl`: every step of the agent, refused steps included.
- `evidence/`: per tested finding `<finding>-poc.har` with every request the
  agent sent and the response to it, the proof records, and a screenshot: the
  page in which an XSS payload ran, an access-control HTML page, or else an
  image of the decisive requests and responses with what decides marked.
  `--screenshots` chooses the classes. Responses and screenshots can show data
  of the target; check them before you share them.

At the end `verify` lists each finding with its result and the reason.
`--print` adds the code-only findings, and `--resume` continues a
report whose run did not finish: findings with a verdict keep it, the others
are tested. `--annotate` writes `security-assessment.annotated.yaml`, a
copy of the assessment with the verdict of each finding.

## Install

```sh
pipx install git+https://github.com/appsec-foundry/appsec-verifier.git
```

Install the optional parts right away, so that the Verifier can test every
class of finding; without the proof browser no XSS finding can be confirmed:

```sh
pipx inject appsec-verifier playwright==1.64.1    # proof browser for XSS
pipx inject appsec-verifier 'anthropic>=0.87,<1'   # only for --profile anthropic-api
```

The proof browser uses the installed Google Chrome and runs only on Linux with
`unshare` (util-linux) and unprivileged user namespaces, because Chrome is
started without network access. Elsewhere XSS findings cannot be confirmed.

For the CLI profiles, install the CLI and log in (`claude`, `codex login`,
`copilot login`).

To update later, run `appsec-verifier update`. It shows the installed version
and asks before it reinstalls from the source you installed from. Like a new
install, it takes the newest dependency versions allowed. Details:
[`docs/cli.md`](docs/cli.md#update--update-the-installed-verifier-ver-033).

To install from a checkout with every package pinned and hash-checked in
[`requirements.lock`](requirements.lock), the proof browser and the
`anthropic` SDK included:

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install --no-deps --no-build-isolation .
```

## Configuration

- Scope file: [`schemas/scope.schema.yaml`](schemas/scope.schema.yaml)
- Test accounts: [`schemas/identities.schema.yaml`](schemas/identities.schema.yaml),
  with `bearer`, `basic`, `form` or OIDC login
- Default limits: [`data/limits.yaml`](data/limits.yaml)
- Models and prices: [`data/model-catalog.yaml`](data/model-catalog.yaml)
  (OpenAI), [`data/anthropic-model-catalog.yaml`](data/anthropic-model-catalog.yaml)
  (Anthropic API)

Examples: [`examples/juice-shop/`](examples/juice-shop/) (local target, form
login) and [`examples/sso-proxy/`](examples/sso-proxy/) (target behind a
company proxy, OIDC login).

## Limitations

- The proof browser has only been tested against a local fake target, and the
  `codex-cli` and `copilot-cli` profiles only with simulated answers.
- The path-traversal and SSRF checks decode percent-encoding, but no other
  encodings a target might accept.
- Not implemented yet: the check that the target runs the assessed build
  (`expected_build`), the `--proxy` option (set `proxy.url` in the scope), and
  the `oidc-authorization-code` login.

## Non-goals

The Verifier is not a scanner and not a pentest agent. It does not search for
new weaknesses, chain exploits, extract real data or escalate privileges. It
only tests the findings it is given.

## Development

Setup, checks and repository layout: [`AGENTS.md`](AGENTS.md). Requirements
VER-001 to VER-035: [`requirements.md`](requirements.md).
