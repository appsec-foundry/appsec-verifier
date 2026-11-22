# Injection proof-form selection: confirm cheaply before exploiting (2026-11-21)

Analysis assignment for a following session, not packaged. It asks for a generic way to make the Verifier reach a confirmation of an injection finding by the cheapest robust form first, and spend on the expensive forms only when the finding needs them. It follows `verification-cost-followup-plan-2026-11-10.md` and the VER-054 work in `0242af9`, which fixed one instance of the same pattern. Nothing in the repository was changed for this assignment except this file.

## Trigger

Run 142 against a local Juice Shop (Verifier `165634f`, Sonnet 5.5 through the Claude CLI, `--allow-intrusive --source`, limits USD 30 and 30 minutes, output in `/tmp/142`): `T-004` (SQL injection in `GET /rest/products/search`, a reflected query with a 200 baseline) spent about USD 3.74 and nine minutes over its two variants and ended inconclusive, a textbook UNION SQL injection.

## What the run showed

| Fact | Evidence |
| --- | --- |
| The agent chose the returned-marker form (`sql_marker`, a Verifier-built UNION) for both variants of T-004 | `/tmp/142/console.log`, `agent-log.jsonl` |
| Every UNION answered HTTP 500 with `SQLITE_ERROR: SELECTs to the left and right of UNION do not have the same number of result columns` | `/tmp/142/evidence/T-004-930a49d43872218b-poc.har` |
| The agent guessed the column count (9, then 8, then fewer), each guess a separate plan revision (a model call), interleaved with repeated source reads to derive the count | `console.log` steps per variant |
| variant-001: 28 steps, 4m26s, USD 1.92, experiment allowance exhausted, inconclusive. variant-002: again `sql_marker`, 22 steps, 4m34s, cumulative USD 3.74, inconclusive | `console.log` |
| The same finding on the same target was confirmed in an earlier run by the engine-error probe alone: `q=apple'` returned 500, `q=apple''` returned 200 (one break/balance pair) | `/tmp/142/evidence/T-004-930a49d43872218b-exchanges.json` |

## Root cause, stated generically

The engine-error probe (`error_probe`, VER-053) is the cheapest robust confirmer for the classes it covers (CWE-89, CWE-643, CWE-943 through a JSON input, CWE-94, CWE-95, CWE-1336): one break/balance pair, any answer status counts, no scope file, no column width, no reflection. It already confirms these findings in recorded runs.
The heavier forms each carry a structural cost. The response-field form needs several comparable 2xx answers, so a write needs one model call per request and a refused baseline cannot pass it. The returned-marker form needs the exact `SELECT *` column width, which the schema itself notes is "the one part of the declaration the agent cannot read off the source" (`agent/experiments.py:158`).
Everything needed for the cheap path is already present. The system prompt tells the model to run the control-character probe first for these classes (`agent/prompts.py:453`) and to give `sql_marker` columns as a list of up to three counts the Verifier tries in turn without a model call (`prompts.py:75`, `tools.py:324`). `fixed_forms` orders `error_probe` before the confirming form (`experiments.py:277`). `probe_first` (VER-054) attaches a reminder when a boolean plan skips the probe (`tools.py:738`, `experiments.py:1073`).
The steering is soft. The reminder is a note, never a gate (VER-043), and returns `None` for a plan whose `kind` is not `boolean`. So when the model reaches for an expensive form instead of the probe, nothing redirects it, and it spends the finding's whole experiment allowance on a form that is harder or, for that finding, impossible. In run 142 the model skipped the probe for T-004, submitted single column counts (defeating the in-code auto-advance), and tried to derive the width from source.
This is the recurring shape, not a single bug. `0242af9` fixed the sibling case (`T-011`, login SQL injection, a refused 401 baseline, the response-field form, about USD 4.41 in run 141) by naming the probe after a refused baseline. T-004 is the working-baseline, returned-marker sibling that trigger does not reach. Each new finding shape the model mishandles is otherwise patched reactively.

## The question to answer

How should the Verifier make "confirm by the cheapest robust form first, reach the expensive forms only when the finding needs them" hold for a model that does not follow soft guidance, without the code scripting the exploit (model drives the exploit; code records and checks) and without gating legitimate plans beyond VER-043.

## Candidate levers, with their tensions

1. Order-gate the probe for the classes it covers. For a CWE in `ENGINE_ERROR_CWES` on a given input, do not accept a response-field or returned-marker plan on that same input until the probe has run on it. This turns the VER-054 reminder into a narrow gate; it is pure form-ordering of the model's own forms, not exploit scripting, and it is the broadest lever. Tension: VER-043 states the reminder is never a gate, a deliberate choice, so this needs the maintainer's decision. It must leave a path for inputs and classes the probe cannot reach (NoSQL other than JSON, command injection).
2. A per-form cost circuit-breaker. When controls on one form stop the same way more than a small number of times (repeated column-count or server errors), stop spending plan revisions on that form and surface the cheaper form or end the finding, rather than exhausting the whole allowance. Generic across forms. Tension: must not cut off a form that is one revision from success.
3. Width discovery for the returned-marker form. The schema concedes the width is not source-derivable and the server returns an explicit column-count error; extend the existing in-code candidate auto-advance (today capped at three counts the model enumerates) into a bounded code-driven width sweep when a column-count error recurs. Tension: this moves a slice of exploit construction from the model into the code, which touches the model-drives-exploit invariant, so it needs the maintainer's call; note it extends an already-accepted in-code enumeration rather than introducing a new principle.

Lever 1 has the broadest reach and the best fit with the model-drives-exploit invariant; recommend starting there.

## What to establish offline before any requirement

- Replay runs 141 and 142 with a fake planner and transport: does enforcing probe-first remove the inconclusive and expensive outcome for T-004 and T-011, and how many findings in those runs change verdict or cost.
- No regression: for every injection CWE in `data/verifiable-cwes.yaml`, confirm the gate still leaves a path for findings the probe cannot confirm, so they are not blocked from the heavier form.
- Quantify the cost delta per finding and per run against the recorded `agent-log.jsonl` costs.
- Check the interaction with VER-049 (`auth_artifact`) and the response-field repetition rule, so the gate does not conflict with the `0242af9` changes.

## Constraints

- The model drives the exploit; the code records and checks; the proof rules in `agent/proof.py` stay as they are (Safety invariants, VER-009 to VER-013).
- A behaviour change needs an agreed requirement first (AGENTS.md, Requirements and features). This file proposes none yet.
- No target-specific logic; a measure must hold for arbitrary targets and ORMs.

## Next step

Pick one lever (recommended: lever 1), run the offline verification above, then propose the requirement wording for approval.
