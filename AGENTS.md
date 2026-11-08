# AGENTS.md

AppSec Verifier is a Python CLI that tests the findings of an AppSec Analyzer `security-assessment.yaml` against a running application and reports per finding whether the weakness reproduces. It is an active security test tool, so its safety controls are part of the product, not optional hardening.

User-facing overview: `README.md`. Command reference: `docs/cli.md`. Requirements (VER-001 … VER-035): `requirements.md`. Internal analyses and handoffs: `docs/internal/analysis/<topic>-<YYYY-MM-DD>.md` (not packaged).

## Setup and checks

```sh
pip install --require-hashes -r requirements-dev.lock   # pinned, hash-checked; Python 3.10
pip install --no-deps --no-build-isolation -e .
python -m pytest -q         # must pass
ruff check .                # must be clean (config in pyproject.toml)
```

Choose checks by what the change affects. Code, schema, data and packaging changes need `python -m pytest -q` and `ruff check .`; the suite is small, so run it whole. Purely editorial changes to documentation or these instructions need no pytest: check the diff, the links, and that commands and flags match `--help`. Do not repeat a passing check unless what it checks has changed. Report which checks ran and which did not; never present a failing or unexecuted check as passed.

Do not run `verify`, `preflight` or the guided run against a real target, or with real model calls, to check a change. That needs an explicit request, a target the maintainer is authorised to test, and a cost limit; a request to test or verify a change is not one. `scope` and `preflight --offline` contact nothing and may be used.

## Requirements and features

Read `requirements.md` before changing observable behaviour. Keep VER-IDs stable when moving or rewording entries, and never reuse a removed ID. Keep entries short, refer to other VER-IDs instead of repeating them, and put details in `docs/cli.md`.

A new or extended feature starts with an agreed requirement, before any code. A feature is a new user outcome or a change to what a VER entry promises, such as a new command, probe class or report content, or changed target contact, model use, data sent to models, or credential use. A fix that restores what an entry already says, clearer help or messages, refactoring, tests and documentation need no new requirement. If it is unclear whether a change is a feature, ask.

1. Propose the entry as it would read in `requirements.md`: a short label and the user outcome in plain language, without file or module names. For a changed entry, show only the changed sentences.
2. Below it, name the risks and side effects that apply: target contact or state change, model cost, data sent to models, credential use, changes to existing commands or saved results. Name a simpler or safer variant if there is one.
3. Wait until the maintainer explicitly approves the wording. A request for the feature alone is not approval.
4. Add the approved entry to `requirements.md`. Implement it only if the maintainer asked for that. If it cannot be met as written, propose a revision instead of deviating silently.

## Branches

Before the first edit to a tracked file for a change, ask whether to work on a feature branch from `main` or directly on `main`, and wait for the answer. Recommend one with a short reason, for example a branch for a feature built over several steps and `main` for a self-contained change of a few files. If the request names the branch, use it. The answer covers that change only. Create a feature branch in a separate git worktree, because other sessions may use the shared checkout at the same time. The choice does not authorise commits, merges or pushes.

## Dependencies

`requirements.lock` (runtime: base, `[agent]`, `[browser]`) and `requirements-dev.lock` (plus `[dev]`) pin every package, build tools included, with hashes. They were generated for Python 3.10 with pip-tools 7.6.2; the command is in each file's header.

Versions are never raised automatically. Do not run `pip-compile --upgrade`, do not merge bot or tool updates unreviewed, and do not install from the version ranges in `setup.py` where the lockfiles apply. Regenerating a lockfile after a change to `setup.py` keeps the existing pins; check the diff, and revert any pin that moved without a reason. Raising a version is a change of its own: name the packages, read their changelog, check them for known vulnerabilities (OSV), run the tests with the new lockfile, and give the reason in the commit. `anthropic` stays below 1 (1.x moved to httpx2; `host_anthropic.py` is written against 0.x) until that migration is done.

Tests run offline. Network, model and agent-CLI calls are replaced by fakes (`FakeTransport`, `FakeClient`, `FakeRun`, `httpx.MockTransport`). Never let a test start a real CLI, reach a real host, or need a real API key. The only exception is opt-in: `APPSEC_VERIFIER_BROWSER_TESTS=1 python -m pytest tests/test_browser_live.py` starts Google Chrome against a fake target (needs the `[browser]` extra; still no network).

## Versions and releases

Only the maintainer releases a version. Coding agents do not change `ENGINE_VERSION` or `INTERFACE_VERSION`, whatever the change (feature, fix or breaking change), and do not create tags or push, unless the maintainer asks for exactly that. If a change seems to need a new version, say so in the summary instead.

## Layout

| Path | Role |
| --- | --- |
| `appsec_verifier/cli.py` | argparse entry point: `scope`, `verify`, `preflight`, `export`, `update`; without a command the guided run (`guided.py`) |
| `loader.py`, `matchkey.py` | read the assessment, classify and select findings (offline) |
| `scope/guard.py` | `ScopeGuard`: allows or refuses each host, port, path and scheme |
| `preflight.py` | confirmation gate (VER-002) and the pre-flight checks before the first finding (VER-032) |
| `limits.py` | `RunBudget`: request, model-call, cost and time caps, raises `LimitExceeded` |
| `term_style.py` | console colour and logo, adapted from AppSec Analyzer; colour only after `printable` |
| `progress.py` | `RunProgress`: the run's progress grid and live status line during `verify`, as in AppSec Analyzer |
| `update.py`, `version_info.py` | `update`: pipx reinstall after a yes (VER-033); `--version` from the build stamp `build-info.json` (written by `setup.py`) or Git |
| `tools/http.py` | `GuardedHttpClient`: every target request goes through scope and budget |
| `auth/sessions.py` | sessions per test identity; secrets come from env vars |
| `agent/` | agent loop and narrow tool set; model profiles (`profiles.py`), the shared action schemas and prompts (`prompts.py`), the step contract (`steps.py`), `HostPlanner` (`hosts.py`) with one `host_*.py` per CLI/API |
| `verify/` | runner (injectable, offline-testable), probes, proof of concept per finding (`poc.py`), report/export/annotate |
| `schemas/`, `data/` | JSON schemas (YAML) and defaults (`limits.yaml`, `verifiable-cwes.yaml`, `model-catalog.yaml`, `anthropic-model-catalog.yaml`) |
| `examples/` | sample scope and identities files |

## Relation to AppSec Analyzer

The Verifier reads the Analyzer's `security-assessment.yaml` and mirrors parts of its code and data. The Analyzer is the reference: where the two differ, the Verifier follows, and the Analyzer repository is not changed for the Verifier unless the maintainer asks for it. The Analyzer does not mention the Verifier, so a change there raises no flag here. When you work on a row below, compare it with the Analyzer's current file. Deliberate differences are noted in the Verifier file's docstring or comment.

| Verifier | AppSec Analyzer (reference) |
| --- | --- |
| `loader.py`, `schemas/assessment.schema.yaml` (only the fields read) | `schemas/threat-model.output.schema.yaml`, published as `security-assessment.yaml` |
| `matchkey.py` | `_match_key` and `_CWE_FAMILIES` in `scripts/model/build_threat_model_yaml.py` (`MATCH_KEY_VERSION` 2) |
| `data/model-catalog.yaml` | `data/model-catalog.yaml`: same models and prices |
| `agent/host_codex_cli.py`, `agent/host_copilot_cli.py` | `appsec_analyzer/codex_cli.py`, `appsec_analyzer/copilot_cli.py`: same flags, versions and environment |
| `agent/host_claude.py` | `scripts/runtime/analyst_host.py`; the Verifier is stricter and stays so |
| `--profile` selection, cost limit and cost display in `cli.py` | `appsec_analyzer/cli.py` |
| `term_style.py`, `progress.py` | `scripts/renderers/term_style.py`, `appsec_analyzer/assessment/console.py` |
| `export`, `schemas/analyzer-annotations.schema.yaml` (VER-021) | no reader yet |

## Safety invariants (do not weaken)

These implement VER-001, -014 to -018, -025, -030. A change that loosens one needs an explicit decision from the maintainer, not a workaround.

- Every request to the target goes through `GuardedHttpClient` and `ScopeGuard`. Do not add a code path that opens connections directly. The resolved address is checked when the connection is made (`AddressCheckingBackend` in `tools/httpx_transport.py`, rule in `ScopeGuard.address_allowed`); metadata and other link-local addresses are never contacted (VER-018).
- Limits are enforced in code, outside the model. Reaching one stops the affected work.
- The agent's tools are only those in `agent/tools.py`: guarded HTTP as a named identity, and read-only source access confined to the repository, without `.env` files, keys, credential stores or `.git/`. No shell, no raw network, no file writes.
- Safe mode is the default: only GET, HEAD and OPTIONS. Write requests need `--allow-intrusive` and `allow_state_change: true` in the scope.
- Secret values only come from environment variables. They never appear in logs, reports, prompts or files. The agent sees role names only.
- Credentials are dropped on cross-origin redirects.
- Model hosts only plan. Agent CLIs run without tools, MCP servers, settings or session history, from an empty temp directory, with an allow-listed environment (no identity secrets, no other provider's keys). Every step goes through `steps.parse_step`; where a CLI reports tool use (`claude`, `codex-cli`), it is a breach that stops all later model calls. Keep the isolation flags at least as strict as AppSec Analyzer's adapters (see Relation to AppSec Analyzer).
- The proof browser (`tools/browser.py`) never connects by itself: every page request goes through `answer()` and the `GuardedHttpClient`, is answered from a recorded response (`render`, `render_exchanges`, scripts off), or is aborted. Chrome runs in a network namespace without network access (`unshare --user --net`); without it the browser does not start.
- The SSRF callback listener (`tools/callback.py`) binds only to loopback, is never a target of the Verifier itself (`ScopeGuard`), and keeps only time, method and source of marker hits. Path-traversal and SSRF probes may aim only at the scope's marker file and the listener (`AgentTools`); the marker file's content never reaches the model (VER-012).
- A confirmed verdict needs the proof its class requires, checked in code against the cited steps (`agent/proof.py`): XSS a `browser_check` with `executed: true`, access control a two-identity contrast, injection a response that flips with the input or a 2 s delay seen twice against two undelayed answers, open redirect a 3xx to the finding's `<marker>.invalid` host, path traversal a read of the marker file, SSRF a hit on the listener. The model's verdict alone never suffices (VER-009 to VER-013).
- Missing or invalid scope, identity or confirmation blocks the run. The scope is a scope file or, without one, the `--url` alone: its scheme, host and port, read-only (VER-001). Enter confirms only in the guided run, never in `verify` or `preflight` (VER-002).

Changes to these controls need tests that cover the refused case (out of scope, over limit, missing secret), not only the allowed one.

## Conventions

- `from __future__ import annotations`, line length 120, ruff rules `E, F, I, UP, B`.
- Module docstrings name the VER-IDs they implement. Keep that up to date.
- `anthropic` (`[agent]`) and `playwright` (`[browser]`, pinned) are optional and imported lazily. `scope` and `export` must work without them.
- Runtime files are found with `version_info.resource_root()`. A new runtime directory must be added to `RUNTIME_DIRS` in `setup.py`, `_RUNTIME_DIRS` in `version_info.py`, and `MANIFEST.in`.
- The version is defined once: `ENGINE_VERSION` in `version_info.py`.
- Before removing code that looks unused, check lazy imports (`anthropic`, `playwright`), the host registry (`agent/registry.py`) and profiles, tests, packaging and documented interfaces. An import search alone does not prove it is dead.
- If you change behaviour or flags, update `README.md` and `docs/cli.md` in the same change. Mark flags that are documented but not implemented as such.

## Writing documentation

Applies to `README.md`, `docs/`, changelog and release notes, help texts and messages users read.

- Write for the user: what changes for them, what they have to do, what they will see. Leave out internals (class names, refactorings, how a bug was found) unless the user needs them to act.
- Plain, factual sentences. No promotional or inflated words ("powerful", "seamless", "robust", "comprehensive", "significantly"), no filler ("It's worth noting", "Note that", "In summary"), no closing summary section.
- Say each thing once. No extra headings, lists, tables or examples that add nothing new; a short paragraph is often clearer than a nested list. Bold sparingly, no emoji, no dashes in place of commas or full stops.
- Name things as the user sees them: command, flag, file, message text. Describe only what the code does now.
- In every Markdown file, including `requirements.md` and this one, write each paragraph and each list item on one source line, as AppSec Analyzer does. Headings, tables and code blocks keep their own lines.
- Changelog: one line per change, breaking changes first with what to do. Not "Introduced a robust self-update mechanism that significantly improves the upgrade experience", but "New `update` command: reinstalls the Verifier with pipx after you confirm."

## Commits

Subject `area: summary` (e.g. `verify:`, `agent:`, `tools+auth:`, `docs:`), body says what changed and why. Never commit `.env` files, run output directories (`verification/`, `verification-2/` and the like), or real credentials.
