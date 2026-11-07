# AGENTS.md

AppSec Verifier is a Python CLI that tests the findings of an AppSec Analyzer
`security-assessment.yaml` against a running application and reports per finding
whether the weakness reproduces. It is an active security test tool, so its
safety controls are part of the product, not optional hardening.

User-facing overview: `README.md`. Command reference: `docs/cli.md`.
Requirements (VER-001 … VER-031): `requirements.md`.

## Setup and checks

```sh
pip install --require-hashes -r requirements-dev.lock   # pinned, hash-checked; Python 3.10
pip install --no-deps --no-build-isolation -e .
python -m pytest -q         # must pass
ruff check .                # must be clean (config in pyproject.toml)
```

## Dependencies

`requirements.lock` (runtime: base, `[agent]`, `[browser]`) and
`requirements-dev.lock` (plus `[dev]`) pin every package, build tools
included, with hashes. They were generated for Python 3.10 with pip-tools
7.6.2; the command is in each file's header.

Versions are never raised automatically. Do not run `pip-compile --upgrade`,
do not merge bot or tool updates unreviewed, and do not install from the
version ranges in `setup.py` where the lockfiles apply. Regenerating a lockfile
after a change to `setup.py` keeps the existing pins; check the diff, and
revert any pin that moved without a reason. Raising a version is a change of
its own: name the packages, read their changelog, check them for known
vulnerabilities (OSV), run the tests with the new lockfile, and give the
reason in the commit. `anthropic` stays below 1 (1.x moved to httpx2;
`host_anthropic.py` is written against 0.x) until that migration is done.
`ENGINE_VERSION` is also raised only on purpose, not by tooling.

Tests run offline. Network, model and agent-CLI calls are replaced by fakes
(`FakeTransport`, `FakeClient`, `FakeRun`, `httpx.MockTransport`). Never let a
test start a real CLI, reach a real host, or need a real API key. The only
exception is opt-in: `APPSEC_VERIFIER_BROWSER_TESTS=1 python -m pytest
tests/test_browser_live.py` starts Google Chrome against a fake target (needs
the `[browser]` extra; still no network).

## Layout

| Path | Role |
| --- | --- |
| `appsec_verifier/cli.py` | argparse entry point: `plan`, `scope`, `verify`, `export` |
| `loader.py`, `matchkey.py` | read the assessment, classify and select findings (offline) |
| `scope/guard.py` | `ScopeGuard`: allows or refuses each host, port, path and scheme |
| `limits.py` | `RunBudget`: request, model-call, cost and time caps, raises `LimitExceeded` |
| `tools/http.py` | `GuardedHttpClient`: every target request goes through scope and budget |
| `auth/sessions.py` | sessions per test identity; secrets come from env vars |
| `agent/` | agent loop and narrow tool set; model profiles (`profiles.py`), the shared action schemas and prompts (`prompts.py`), the step contract (`steps.py`), `HostPlanner` (`hosts.py`) with one `host_*.py` per CLI/API |
| `verify/` | runner (injectable, offline-testable), probes, report/export/annotate |
| `schemas/`, `data/` | JSON schemas (YAML) and defaults (`limits.yaml`, `verifiable-cwes.yaml`, `model-catalog.yaml`, `anthropic-model-catalog.yaml`) |
| `examples/` | sample scope and identities files |

## Safety invariants (do not weaken)

These implement VER-001, -014 to -018, -025, -030. A change that loosens one
needs an explicit decision from the maintainer, not a workaround.

- Every request to the target goes through `GuardedHttpClient` and `ScopeGuard`.
  Do not add a code path that opens connections directly. The resolved address
  is checked when the connection is made (`AddressCheckingBackend` in
  `tools/httpx_transport.py`, rule in `ScopeGuard.address_allowed`); metadata
  and other link-local addresses are never contacted (VER-018).
- Limits are enforced in code, outside the model. Reaching one stops the
  affected work.
- The agent's tools are only those in `agent/tools.py`: guarded HTTP as a named
  identity, and read-only source access confined to the repository, without
  `.env` files, keys, credential stores or `.git/`. No shell,
  no raw network, no file writes.
- Safe mode is the default: only GET, HEAD and OPTIONS. Write requests need
  `--allow-intrusive` and `allow_state_change: true` in the scope.
- Secret values only come from environment variables. They never appear in
  logs, reports, prompts or files. The agent sees role names only.
- Credentials are dropped on cross-origin redirects.
- Model hosts only plan. Agent CLIs run without tools, MCP servers, settings
  or session history, from an empty temp directory, with an allow-listed
  environment (no identity secrets, no other provider's keys). Every step goes
  through `steps.parse_step`; where a CLI reports tool use (`claude`,
  `codex-cli`), it is a breach that stops all later model calls. Keep the
  isolation flags in line with AppSec Analyzer's adapters.
- The proof browser (`tools/browser.py`) never connects by itself: every page
  request goes through `answer()` and the `GuardedHttpClient`, or is aborted.
  Chrome runs in a network namespace without network access
  (`unshare --user --net`); without it the browser does not start.
- The SSRF callback listener (`tools/callback.py`) binds only to loopback, is
  never a target of the Verifier itself (`ScopeGuard`), and keeps only time,
  method and source of marker hits. Path-traversal and SSRF probes may aim
  only at the scope's marker file and the listener (`AgentTools`); the marker
  file's content never reaches the model (VER-012).
- A confirmed verdict needs the proof its class requires, checked in code
  against the cited steps (`agent/proof.py`): XSS a `browser_check` with
  `executed: true`, access control a two-identity contrast, injection a
  response that flips with the input or a 2 s delay seen twice against two
  undelayed answers, open redirect a 3xx to the finding's
  `<marker>.invalid` host, path traversal a read of the marker file, SSRF a
  hit on the listener. The model's verdict alone never
  suffices (VER-009 to VER-013).
- Missing or invalid scope, identity or confirmation blocks the run.

Changes to these controls need tests that cover the refused case
(out of scope, over limit, missing secret), not only the allowed one.

## Conventions

- `from __future__ import annotations`, line length 120, ruff rules
  `E, F, I, UP, B`.
- Module docstrings name the VER-IDs they implement. Keep that up to date.
- `anthropic` (`[agent]`) and `playwright` (`[browser]`, pinned) are optional and
  imported lazily. `plan`, `scope` and `export` must work without them.
- Runtime files are found with `version_info.resource_root()`. A new runtime
  directory must be added to `RUNTIME_DIRS` in `setup.py`, `_RUNTIME_DIRS` in
  `version_info.py`, and `MANIFEST.in`.
- The version is defined once: `ENGINE_VERSION` in `version_info.py`.
- If you change behaviour or flags, update `README.md` and `docs/cli.md` in the
  same change. Mark flags that are documented but not implemented as such.

## Commits

Subject `area: summary` (e.g. `verify:`, `agent:`, `tools+auth:`, `docs:`),
body says what changed and why. Never commit `.env` files, the `verification/`
output directory, or real credentials.
