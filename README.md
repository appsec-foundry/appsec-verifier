# AppSec Verifier

AppSec Verifier tests the findings of a static security assessment against the
running application. It reads the `security-assessment.yaml` written by
[AppSec Analyzer](https://github.com/appsec-foundry/appsec-analyzer), sends
requests to a target you are authorised to test, and records for each selected
finding whether the weakness can be reproduced. It does not repeat the static
analysis and does not change severities.

## Status

Early version.

- `plan`, `scope` and `export` work offline.
- `verify` runs an AI agent per finding. The agent reads the finding and, with
  `--source`, the relevant source code, then sends HTTP requests within the
  scope. It has no other tools.
- The model comes from a profile, chosen as in AppSec Analyzer (`--profile`):

  | Profile | Uses | Bounded by |
  | --- | --- | --- |
  | `claude` (default) | Claude CLI with its login or `ANTHROPIC_API_KEY` | USD, calls, time |
  | `codex-cli` | Codex CLI 0.163.0+ with a ChatGPT login | calls, time |
  | `copilot-cli` | GitHub Copilot CLI 1.0.101 with its login | calls, time |
  | `codex` | OpenAI Responses API with `OPENAI_API_KEY` | USD, calls, time |
  | `anthropic-api` | Anthropic API with `ANTHROPIC_API_KEY`, no CLI needed | calls, time |

  Every CLI runs without tools, MCP servers, settings or session history and
  only proposes the next step; the Verifier checks it and executes it within the
  scope. `--non-interactive` requires an explicit `--profile`. Codex CLI and
  Copilot CLI have no live end-to-end test yet. Subscription use follows the
  provider's terms for that plan.
- XSS findings are confirmed only in a headless proof browser (Google Chrome
  through Playwright, `appsec-verifier[browser]`): the payload must evaluate a
  per-finding marker, and a screenshot is saved when it does. Every request the
  browser makes goes through the scope check, and Chrome itself runs in a network
  namespace without network access. That needs Linux with `unshare` (util-linux)
  and unprivileged user namespaces; elsewhere the browser does not start. Without
  the browser, XSS findings cannot be confirmed. The browser has only been tested
  offline so far; see `tests/test_browser_live.py` to run it against real Chrome.
- Not built yet: the callback listener for SSRF. Other classes are judged from
  HTTP responses.

## Usage

```sh
appsec-analyzer assess --repo … --output ./out        # writes security-assessment.yaml

appsec-verifier verify --profile claude \
  --assessment ./out/security-assessment.yaml \
  --scope ./scope.yaml --identities ./identities.yaml \
  --url https://localhost:3000 \
  --category xss,access-control --min-severity high \
  --cost-limit 5 --output ./verification
```

`--scope` defines what may be contacted. `--identities` adds test accounts;
access-control checks need at least two. Select findings with `--category`,
`--severity`, `--min-severity` or `--only <id>`. `appsec-verifier plan` shows
what a selection contains without contacting anything.

Before the first request, `verify` prints the plan and asks for confirmation. In
CI, pass `--non-interactive --yes`. `--dry-run` prints the plan and stops.

## What it verifies

A finding counts as confirmed only with the proof in the right column.

| Class | CWEs | Confirmed when |
| --- | --- | --- |
| Cross-site scripting | CWE-79 | the marker payload executes in a browser; reflection alone is not enough |
| Broken access control / IDOR | CWE-639, 862, 863 | one test identity reads or changes data of another |
| SQL / NoSQL injection | CWE-89, 943 | a controlled difference in response or timing appears; no data is extracted |
| Path traversal | CWE-22 | a marker file placed beforehand can be read |
| Open redirect | CWE-601 | a harmless, controlled redirect works |
| SSRF | CWE-918 | the target calls a listener run by the Verifier |

Findings that cannot be tested against a running system, such as a weak random
number generator or a hard-coded secret, are reported `not-attempted` with a
reason. The list of testable CWEs is in
[`data/verifiable-cwes.yaml`](data/verifiable-cwes.yaml).

Possible verdicts: `confirmed`, `not-reproducible`, `blocked-by-control` (a
protection the static analysis could not see stops the attack), `inconclusive`,
`not-attempted`. If a check fails, for example because the target does not
answer or a login is rejected, that finding ends `inconclusive` and the run
continues.

## Safety

`verify` performs an active security test, so it only does what the operator
explicitly allows. The controls follow the
[AI Secure Coding Baseline](https://github.com/appsec-foundry/aiscb).

- The scope file lists the hosts, ports and paths that may be contacted, the
  time window, the responsible owner, and any proxy and login (SSO) hosts.
  Requests outside it are refused. A path that a server could resolve to a
  different resource (`..`, `//`, `;`, `\` or an encoded separator such as
  `%2f`) is refused, and `deny_paths` match regardless of case and percent
  encoding. Proxy settings from the environment (`HTTPS_PROXY` and the like)
  are ignored; only the scope's proxy is used.
- Passwords, tokens and client secrets are read from environment variables. They
  do not appear in logs or the report, and the agent only sees role names. If the
  target echoes one back, it is replaced by `[redacted]` before the model or the
  report sees it. The
  identities file is checked before the first request: a missing variable, or a
  login endpoint or `target_origin` outside the scope, stops the run. An
  identity's credentials are sent only to its own origin (`target_origin`, by
  default the target URL). The HTTP client keeps no cookies, so one identity's
  session never travels with another identity's or an anonymous request.
- Requests, attempts per finding, model calls, request rate, run time and model
  spend are capped. Defaults are in [`data/limits.yaml`](data/limits.yaml).
  Reaching a limit stops the work it affects. Spend is counted for `claude` and
  `codex`; `codex-cli` and `copilot-cli` report no cost and reject
  `--cost-limit`.
- Safe mode is the default. The agent can then only send GET, HEAD and OPTIONS
  requests, uses one harmless payload per test and keeps the request count low.
  Write requests (needed for stored XSS and some IDOR cases) require
  `--allow-intrusive` and `allow_state_change: true` in the scope.
- Intrusive mode adds POST, PUT and PATCH. DELETE and every other method are
  never sent. Use intrusive mode only against a disposable test instance.
- Every step the model proposes is checked against a strict schema before it
  runs, whichever profile produced it; an invalid step ends the finding
  `inconclusive`.

## Install

Python 3.10 or later, with [pipx](https://pipx.pypa.io/stable/):

```sh
pipx install git+https://github.com/appsec-foundry/appsec-verifier.git
pipx inject appsec-verifier anthropic      # only for --profile anthropic-api
pipx inject appsec-verifier playwright==1.64.1   # XSS proof browser; uses the installed Google Chrome
```

For the CLI profiles, install the agent CLI and log in (`claude`, `codex login`,
`copilot login`).

From a local checkout: `pip install -e '.[agent,browser]'`.

## Commands

Details in [`docs/cli.md`](docs/cli.md).

- `plan` lists which findings of an assessment can be tested dynamically. Offline.
- `scope` validates a scope file and checks whether a URL falls inside it. Offline.
- `verify` tests the selected findings against the target.
- `export` converts a `verification.yaml` into a file AppSec Analyzer can read.

## Configuration

- Scope file: [`schemas/scope.schema.yaml`](schemas/scope.schema.yaml)
- Identities file: [`schemas/identities.schema.yaml`](schemas/identities.schema.yaml).
  Test accounts by role, with `bearer`, `basic`, `form` or OIDC login. Secrets
  only as names of environment variables.
- Default limits: [`data/limits.yaml`](data/limits.yaml)
- OpenAI models and prices for `codex` and `codex-cli`:
  [`data/model-catalog.yaml`](data/model-catalog.yaml)

Examples: [`examples/juice-shop/`](examples/juice-shop/) (local target, form
login) and [`examples/sso-proxy/`](examples/sso-proxy/) (target behind a
corporate proxy, login via OIDC).

## Output

`verify` writes `verification.md` and `verification.yaml`
([schema](schemas/verification.schema.yaml)) to `--output`, with verdict,
confidence and evidence per finding. `--print` also shows the verdicts in the
console, and `--append` adds to an existing report. `--annotate` also writes
`security-assessment.annotated.yaml`, a copy of the assessment with the
verification status per finding; `--in-place` changes the original instead.
Findings and severities stay as they are.

## Non-goals

The Verifier is not a scanner and not a pentest agent. It does not search for
new weaknesses, chain exploits, extract real data or escalate privileges. It
only tests the findings it is given.

## Repository layout

```
appsec_verifier/    package: CLI, loader, scope guard, limits, HTTP client, auth, agent, verify
schemas/            JSON schemas (as YAML) for scope, identities, verification, analyzer annotations
data/               verifiable-cwes.yaml, limits.yaml
docs/cli.md         command reference
requirements.md     requirements VER-001 … VER-030
examples/           sample scope and identities files
tests/
```
