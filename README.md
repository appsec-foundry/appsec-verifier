# AppSec Verifier

> **Status: early, partial.** The specification — requirements, CLI design, and
> schemas — is complete, and the two offline commands run today: `plan` (classify
> an assessment's findings) and `scope` (validate an authorisation scope). The
> commands that contact a target — `verify` and `export` — are specified but
> **not implemented yet**; they exit with that notice. Nothing here contacts a
> target or makes a model call yet.

AppSec Verifier takes the findings of a static security assessment and tries to
**prove or disprove each one against the running application**. Where
[AppSec Analyzer](https://github.com/appsec-foundry/appsec-analyzer) reasons about
source code, the Verifier interacts with a live target: it reproduces a finding
with a safe, marked probe, observes the application's real behaviour, and records
whether the weakness is confirmed, not reproducible, or blocked by a control the
static view could not see.

It reads a finished `security-assessment.yaml`, verifies the findings you select
against a target you are authorised to test, and writes its own report — or
annotates the assessment. It never re-runs the static analysis and never
re-scores a finding on its own.

## How it fits after an Analyzer run

```
appsec-analyzer assess --repo … --output ./out        # produces security-assessment.yaml
appsec-verifier verify \
  --assessment ./out/security-assessment.yaml \
  --scope ./scope.yaml --identities ./identities.yaml \
  --class xss,access-control --min-severity high \
  --cost-limit 5 --output ./verification
```

You hand the Verifier the assessment the Analyzer produced, the boundaries of
what it may do (target scope, cost, request/time limits), and the findings to
check (by class, severity, CWE, or id). It confirms what it can, with evidence,
and leaves everything else clearly marked as unverified — never as refuted.

## What it verifies (V1)

| Class | CWEs | Proof |
| --- | --- | --- |
| Cross-site scripting | CWE-79 | Marker payload actually executes in a real headless browser. A merely reflected payload is *not* confirmed. |
| Broken access control / IDOR | CWE-639, 862, 863 | One identity reaches or alters what belongs to another, contrasted across two test identities. |
| Injection (SQL / NoSQL) | CWE-89, 943 | A controlled, observable response/timing difference — never exfiltrated data. |
| Path traversal · open redirect · SSRF | CWE-22, 601, 918 | A pre-placed marker file, a controlled benign redirect, or a hit on a callback the Verifier itself listens on. |

Findings whose weakness cannot be probed against a running system (a weak PRNG
choice, a hard-coded secret literal) are reported as *out of scope for dynamic
verification* with a reason — not as unconfirmed. The positive list lives in
[`data/verifiable-cwes.yaml`](data/verifiable-cwes.yaml).

## Safety model

Running the Verifier against a system is an active security test, so it acts only
within boundaries the operator sets explicitly. These controls follow the
[AI Secure Coding Baseline](https://github.com/appsec-foundry/aiscb); they are the
point of the tool, not optional hardening.

- **Authorisation scope.** A scope file is the single authority for what the
  Verifier may contact — target host, ports, path prefixes, a time window, the
  responsible owner, plus any declared proxy and SSO/identity-provider hosts.
  Anything outside it is refused, not attempted; an interactive run confirms the
  scope before the first request.
- **Credentials as secrets.** Bearer tokens, usernames and passwords, and client
  secrets come from environment variables, never from files in the repo. Their
  values never reach logs, the report, evidence, or any model prompt — only a
  role label travels.
- **Bounded.** Total requests, per-finding attempts, request rate, wall-clock
  time, and model spend are all capped; reaching a bound stops the run.
- **Safe probes.** State-changing probes run only with a disposable/authorised
  target, use unique markers, and are cleaned up. Deletes, bulk or destructive
  operations, denial-of-service, and detection evasion are never performed.

## Install

Like AppSec Analyzer, the Verifier installs as a single command with
[pipx](https://pipx.pypa.io/stable/) (Python 3.10+). The install carries its own
schemas and data.

```sh
pipx install git+https://github.com/appsec-foundry/appsec-verifier.git
```

From a local checkout:

```sh
pipx install /path/to/appsec-analyzer-verifier      # or: pip install -e .
```

Then:

```sh
appsec-verifier --version
appsec-verifier plan  --assessment ./out/security-assessment.yaml --class xss --min-severity high
appsec-verifier scope --scope ./scope.yaml --target http://localhost:3000
```

## Commands

Full design in [`docs/cli.md`](docs/cli.md).

- `plan` — list which findings are dynamically verifiable, offline (no target, no
  model calls). **Runs today.**
- `scope` — resolve and validate a scope file, offline. **Runs today.**
- `verify` — verify selected findings against a running target. *Not implemented yet.*
- `export` — re-emit verdicts in a form AppSec Analyzer can read back. *Not implemented yet.*

## Configuration

- **Scope file** — [`schemas/scope.schema.yaml`](schemas/scope.schema.yaml).
  Target boundary, authorisation window, proxy, and SSO/auth hosts.
- **Identities file** — [`schemas/identities.schema.yaml`](schemas/identities.schema.yaml).
  Test identities by role, with `bearer`, `basic`, `form`, or OIDC login; secrets
  as environment-variable references only.
- **Limits** — [`data/limits.yaml`](data/limits.yaml). Default execution bounds.

Worked examples: [`examples/juice-shop/`](examples/juice-shop/) (local target,
form login) and [`examples/sso-proxy/`](examples/sso-proxy/) (target behind a
corporate proxy, sessions from an OIDC provider).

## Outputs

- `verification.md` + `verification.yaml`
  ([schema](schemas/verification.schema.yaml)) — the standalone report (default),
  one entry per finding with verdict, confidence, and evidence.
- `evidence/` — request/response traces, browser events, screenshots, callback
  records, redacted of credentials and sensitive data.
- Optional **annotate** mode, or an
  [analyzer-annotations](schemas/analyzer-annotations.schema.yaml) export, that
  lets AppSec Analyzer show each finding's dynamic-verification status. Additive,
  keyed by finding id + a cross-run key; it never re-scores the assessment.

## Non-goals

The Verifier is not a scanner and not a pentest agent. It does not crawl for new
weaknesses, chain exploits for impact, extract real data, or escalate privileges
for their own sake. It confirms or refutes the specific findings it is given.

## Repository layout

```
appsec_verifier/    the installable package: cli, loader, match-key, version
setup.py            pipx/pip installer; bundles schemas/ + data/ into the wheel
pyproject.toml      build system and lint config
requirements.md     what the Verifier must do (VER-001 … VER-029)
docs/cli.md         command and console design
schemas/            verification, scope, identities, analyzer-annotations (JSON Schema in YAML)
data/               verifiable-cwes.yaml (positive list), limits.yaml (default bounds)
examples/           juice-shop/ and sso-proxy/ scope + identities
```
