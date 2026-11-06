# AGENTS.md

AppSec Verifier is a Python CLI that tests the findings of an AppSec Analyzer
`security-assessment.yaml` against a running application and reports per finding
whether the weakness reproduces. It is an active security test tool, so its
safety controls are part of the product, not optional hardening.

User-facing overview: `README.md`. Command reference: `docs/cli.md`.
Requirements (VER-001 … VER-030): `requirements.md`.

## Setup and checks

```sh
pip install -e '.[dev]'     # pytest + anthropic; Python >= 3.10
python -m pytest -q         # must pass
ruff check .                # must be clean (config in pyproject.toml)
```

Tests run offline. Network and model calls are replaced by fakes
(`FakeTransport`, `FakeClient`, `httpx.MockTransport`). Never let a test
reach a real host or need a real `ANTHROPIC_API_KEY`.

## Layout

| Path | Role |
| --- | --- |
| `appsec_verifier/cli.py` | argparse entry point: `plan`, `scope`, `verify`, `export` |
| `loader.py`, `matchkey.py` | read the assessment, classify and select findings (offline) |
| `scope/guard.py` | `ScopeGuard`: allows or refuses each host, port, path and scheme |
| `limits.py` | `RunBudget`: request, cost and time caps, raises `LimitExceeded` |
| `tools/http.py` | `GuardedHttpClient`: every target request goes through scope and budget |
| `auth/sessions.py` | sessions per test identity; secrets come from env vars |
| `agent/` | agent loop, planners (Anthropic API, Claude Code), the agent's narrow tool set, source reader |
| `verify/` | runner (injectable, offline-testable), probes, report/export/annotate |
| `schemas/`, `data/` | JSON schemas (YAML) and defaults (`limits.yaml`, `verifiable-cwes.yaml`) |
| `examples/` | sample scope and identities files |

## Safety invariants (do not weaken)

These implement VER-001, -014 to -018, -025, -030. A change that loosens one
needs an explicit decision from the maintainer, not a workaround.

- Every request to the target goes through `GuardedHttpClient` and `ScopeGuard`.
  Do not add a code path that opens connections directly.
- Limits are enforced in code, outside the model. Reaching one stops the
  affected work.
- The agent's tools are only those in `agent/tools.py`: guarded HTTP as a named
  identity, and read-only source access confined to the repository. No shell,
  no raw network, no file writes.
- Safe mode is the default: only GET, HEAD and OPTIONS. Write requests need
  `--allow-intrusive` and `allow_state_change: true` in the scope.
- Secret values only come from environment variables. They never appear in
  logs, reports, prompts or files. The agent sees role names only.
- Credentials are dropped on cross-origin redirects.
- The Claude Code backend (`agent/planner_claude_code.py`) runs `claude -p`
  without tools, settings, MCP servers or session persistence, checks the
  session's tool set on every call, and is never selected by `--backend auto`.
- Missing or invalid scope, identity or confirmation blocks the run.

Changes to these controls need tests that cover the refused case
(out of scope, over limit, missing secret), not only the allowed one.

## Conventions

- `from __future__ import annotations`, line length 120, ruff rules
  `E, F, I, UP, B`.
- Module docstrings name the VER-IDs they implement. Keep that up to date.
- `anthropic` is optional (`[agent]` extra) and imported lazily in
  `agent/planner_anthropic.py`. `plan`, `scope` and `export` must work without it.
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
