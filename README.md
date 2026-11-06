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
- `verify` runs an AI agent per finding (Anthropic API, default model
  `claude-opus-5-5`, change with `--model`). The agent reads the finding and,
  with `--source`, the relevant source code, then sends HTTP requests within the
  scope. It has no other tools. Without `ANTHROPIC_API_KEY` (and without
  `--backend claude-code`), `verify` contacts nothing and marks every finding
  `not-attempted`.
- `--backend claude-code` runs the model through a local, logged-in Claude Code
  (`claude -p`) instead of an API key, for example on a Claude subscription.
  Claude Code then has no tools, settings or MCP servers and only proposes the
  next step; the Verifier executes it within the scope. This backend is never
  chosen automatically. Check Anthropic's current terms before using a
  subscription this way.
- Not built yet: the headless browser that shows an XSS payload actually
  executes, and the callback listener for SSRF. For now the agent judges from
  HTTP responses only.

## Usage

```sh
appsec-analyzer assess --repo … --output ./out        # writes security-assessment.yaml

export ANTHROPIC_API_KEY=…
appsec-verifier verify \
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
`not-attempted`.

## Safety

`verify` performs an active security test, so it only does what the operator
explicitly allows. The controls follow the
[AI Secure Coding Baseline](https://github.com/appsec-foundry/aiscb).

- The scope file lists the hosts, ports and paths that may be contacted, the
  time window, the responsible owner, and any proxy and login (SSO) hosts.
  Requests outside it are refused.
- Passwords, tokens and client secrets are read from environment variables. They
  do not appear in logs or the report, and the agent only sees role names.
- Requests, attempts per finding, request rate, run time and model spend are
  capped. Defaults are in [`data/limits.yaml`](data/limits.yaml). Reaching a
  limit stops the work it affects.
- Safe mode is the default. The agent can then only send GET, HEAD and OPTIONS
  requests, uses one harmless payload per test and keeps the request count low.
  Write requests (needed for stored XSS and some IDOR cases) require
  `--allow-intrusive` and `allow_state_change: true` in the scope.
- Intrusive mode currently allows every HTTP method, including DELETE. Use it
  only against a disposable test instance.

## Install

Python 3.10 or later, with [pipx](https://pipx.pypa.io/stable/):

```sh
pipx install git+https://github.com/appsec-foundry/appsec-verifier.git
pipx inject appsec-verifier anthropic      # needed for verify with an API key (not for --backend claude-code)
```

From a local checkout: `pip install -e '.[agent]'`.

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
