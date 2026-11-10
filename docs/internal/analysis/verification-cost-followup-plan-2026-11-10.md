# Cheaper verification, second round: implementation plan (2026-11-10)

Handoff for an implementing session. It follows `verification-simplification-plan-2026-11-10.md` (implemented in `63cec0e`) and records what a review of that commit and a first full run showed, the requirement wording that still needs approval, and the work packages in order. Nothing in the repository was changed for this plan except this file.

## Sources

- Review of `63cec0e` against the first plan: diff read per work package, `python3 -m pytest -q` (1670 passed, 2 skipped) and `ruff check .` clean, and offline replays with fake planners and transports.
- Run: guided run against a local Juice Shop with `--allow-intrusive --source /home/mrohr/juice-shop --annotate`, profile `claude` (Sonnet 5.5 through the Claude CLI), Verifier `63cec0e`, limits USD 10 and 30 minutes, output in `/tmp/125` (`agent-log.jsonl`, `evidence/`). 38 of 44 findings were planned. After 13 minutes and USD 4.83 three findings were finished: T-004 confirmed, T-010 and T-011 inconclusive.

## What the run showed

| Finding | Cost | Observation | Cause | Applies beyond this finding |
| --- | --- | --- | --- | --- |
| T-011, SQL injection in `POST /rest/user/login` | about USD 1.90, inconclusive | Steps 5 to 8 showed 200 with a token for both true controls and 401 for both false controls. The verdict was rejected twice with `repeat every declared input at least twice using distinct requests` | The plan used the response-field form, which demands a uniform 2xx status (`injection_check` in `agent/experiments.py`), so a 401 to 200 flip can never pass it. The form made for this case, `auth_artifact: true` (VER-049, `auth_artifact_check`), needs no repetition and steps 5 to 8 would have met it. The system prompt never mentions `auth_artifact`; it exists only as an undescribed boolean in `PLAN_SCHEMA`. The feedback named neither the missing controls nor the other form | Every login-bypass injection |
| T-011, same run | each control cost USD 0.16 to 0.18 | Five controls were five model calls | A write is never sent by the Verifier itself (`experiment_requests` in `agent/tools.py` refuses non-safe methods), so the response-field form on a write needs ten model calls for ten requests and cannot fit into twelve steps | Every injection finding carried by POST, PUT or PATCH; in this run also T-012, T-025, T-035 |
| T-010, IDOR in `routes/payment.ts`, no route in the assessment | USD 1.47, no request sent | Eight of ten steps were `find_source` with queries such as `getPaymentMethods`, `app.use`, `payment/cards` | `SourceReader.find` (`agent/source_reader.py`) matches file names and paths only (VER-050). Every symbol query returned zero matches without saying why. The registration is `server.ts:439`, `app.get('/api/Cards', ...)`, which a content search finds in one call | Every finding whose route is registered in another file than its evidenced location |
| T-010, same run | USD 0.36 | Technical QA ran twice on a finding that had sent no request | QA runs for every unproven conclusion (VER-046) | Findings that end before the first request |
| T-004, SQL injection in `GET /rest/products/search` | USD 0.85, confirmed | Three plans (30 s, 35 s, 66 s of model time) before the parentheses balanced; each plan carried 1,660 to 2,548 characters of `strategy` | A wrong template costs a whole plan revision. `agent/prompts.py` lines 289 to 292 and 307 still demand a plan with strategy for every class, although VER-043 says no plan is required | All classes (strategy), all SQL injections (template) |
| T-004, evidence review | USD 0.63, `needs-attention`, both correction rounds without effect | The reviewer reported `input, decoded: ...` eight times in a row per step, an uninformative `Comparison` line and truncated excerpts | `verify/poc.py` lines 595 to 607 append the `input, decoded` fact once per comparison partner, so a step compared with eight others carries it eight times. These are parts the Verifier renders; the test agent can only add an explanation and quotes | Every injection finding with more than two shown steps |
| T-004, console | cost shown on the wrong row | The review's USD 0.63 and 2m06s appear on variant-002's line `not attempted` | The review of a finding runs inside its last variant's row | Every finding with variants |

Cost per model call was USD 0.09 to 0.18, for a file-name search as for a plan. The first call of a finding, with an empty history, already cost USD 0.09 to 0.13, so most of a call's cost is a fixed part and not the history. What that part consists of (the 21,354-character system prompt, the CLI's own overhead, thinking output) is not known: the action log records no usage. At about USD 1 to 2 per finding, 38 findings need more than USD 40 in any order.

## Cost target

The maintainer set the target on 2026-11-10: verification must stay affordable, at USD 0.40 to 0.60 per tested finding.

- Measure: total model cost of a run at API prices, as `--show-costs` reports it, divided by the number of findings that were tested. Reviews (technical QA, evidence review) and the retired variants of a finding count into its finding; the preflight does not. Reference run: the command above with profile `claude`.
- What the target implies at the prices observed: a model call cost USD 0.09 to 0.18, so USD 0.40 to 0.60 allows three to five calls per finding, reviews included. A finding with a proof the code can check should need source read, one declaration or probe, and the verdict. Access-control findings need more steps (preparation, two identities), so the average is reached only if the fixed cost per call falls as well. WP12 is therefore part of reaching the target, not an optional tuning step, and WP6 has to come before the first acceptance run.
- The target is a goal for this plan, not a requirement entry: it depends on model prices and on the profile. If the maintainer wants a promise the Verifier enforces, the existing per-finding spend cap (`finding_cost_fraction`, `min_finding_cost_usd`, VER-051) is the place, and changing its default is a decision of its own.
- Report against the target after every acceptance run: cost per tested finding, model calls per finding, and the three most expensive findings with the step that cost most. A finding above USD 1 gets a cause, as in the table above.

## Open points from the review of `63cec0e`

These are deviations from the first plan that its status section does not list as deferred.

1. The prompt still instructs a plan with strategy before proof (see T-004 above). The first plan's status attributes this to its deferred WP4, but it is D1 content.
2. `proof.proof_ready` reports an XSS step as ready when `executed` and `context_verified` are true, without the route binding `_xss` applies. A replay on another variant's route got `proof_ready` and then a downgraded verdict.
3. "Proof steps chosen by code" for injection is missing: after an experiment that reports `proof: holds`, a confirmed verdict that cites no or too few steps ends inconclusive after two correction rounds.
4. `proof_ready` does not cover open redirect.
5. The experiment feedback after a failed control gives `repeat every declared input at least twice using distinct requests`, not the control's status and error excerpt.
6. The comment in `Controller.before` (`agent/controller.py`, the `experiment` branch) says re-running the same plan reaches the repetition allowance. At loop level a re-declared identical plan runs ten more controls, because the generated values change the plan token. Only the three-experiment bound limits it.
7. Tests the first plan names are missing: the loop-level T-004 replay in `tests/test_agent_probe.py`; XSS confirmed without `plan_test` on the pinned variant and downgraded on another variant's route; the `proof: holds` feedback; a 500 on a control; a write declaration that sends nothing (the refused case); `proof_ready` in the loop and its absence for access control; a duplicate-variant case with another input. `test_an_accepted_plan_runs_its_controls_once_automatically` lost its assertions on `stagnation` and on ten PoC steps.
8. `docs/cli.md`, "Evidence presentation review", still says panels larger than 1280 by 1200 pixels are flagged; that holds only for application screenshots. A plan without strategy probably renders `strategy: null` in the report's `Test plan` appendix (`verify/poc.py` line 892; read from the code, not rendered).

Not from `63cec0e`, seen on `HEAD~1` as well: an execution plan that names another variant and its route is accepted and then confirms under the pinned variant. Outside this plan; report it to the maintainer if touched.

## Decisions

The maintainer asked for this plan on 2026-11-10 after seeing the recommendations. No requirement wording below is approved yet; the question about R1 was asked and not answered.

- Decided: the cost target above.
- Recommended order: fixes and measurement first (WP1 to WP7), a first acceptance run to get usage data, then the features in the order R1, R2, R3, R4 (WP8 to WP11) and the prompt size with the measured data (WP12). WP12 may move ahead of the features if the first run shows the fixed cost per call is what keeps a finding above the target.
- Not recommended in this round: model-assessed confirmation (D5 of the first plan), because all three findings failed on mechanics and not on the proof form; ordering across severities; skipping technical QA for a finding without a request, which the content search should make rare.

## Rules for the implementing session

- Follow `AGENTS.md`. Ask the maintainer whether to work on a feature branch or on `main` before the first edit to a tracked file. This plan recommends `main` for WP1 to WP7 committed as they are finished, and a feature branch in its own worktree for WP8 to WP11.
- Present the requirement wordings one at a time, each with its risks, and wait for explicit approval before adding it to `requirements.md` and before implementing its package. WP1 to WP7 need no requirement, with the two questions marked in WP4 and WP6.
- Do not weaken the safety invariants in `AGENTS.md`. R1 changes the sentence "writes ... never repeated automatically"; change it only as approved, and update the invariant text in `AGENTS.md` in the same commit.
- Changes to a control need a test for the refused case as well as the allowed one. Tests stay offline. Do not run `verify`, `preflight` or the guided run against a target or with real model calls; the acceptance run is the maintainer's.
- Do not change `ENGINE_VERSION` or `INTERFACE_VERSION`. Update `docs/cli.md` and, where a summary sentence becomes wrong, `README.md` in the same change. Checks: `python3 -m pytest -q` and `ruff check .`; the browser live tests and one progress test need to run outside the Bash sandbox.

## Proposed requirement wording (needs approval)

Only the changed sentences are shown.

- R1, VER-011, replace "the agent sends each control itself, since a write never repeats automatically." with: "There the Verifier sends the declared controls in one step when the agent asks for it, each control at most twice, and stops at the first control that fails; it never sends them unasked."
  - Risks: the same writes the proof needs today, but the agent no longer sees each answer in between, so a control that reaches an update or delete sink runs up to twice before the agent can react. Nothing changes without `--allow-intrusive`, and `allow_state_change: false` still forbids it. About nine model calls fewer per such finding. No new data to models, no credential use.
  - Cheaper variant, not recommended: send the controls on acceptance of the plan, as for reads. It saves one more call, but then the declaration itself triggers writes.
- R2, VER-050, add: "It can also search file contents for a literal string and gets the matching paths and line numbers with the matching line, under the same confinement and exclusions."
  - Risks: more source text reaches the model, bounded per match and per search; the same files `read_source` can already send. No target contact.
  - Optional extension, decide after a run with R2: VER-008, add "With a source checkout, a route registered in another file for a handler in the finding's file can supply the finding's request, and the plan shows where it came from." It changes which requests a finding may send, so it needs its own approval.
- R3, VER-011, add after the sentence on the template: "The declaration may carry up to three candidate templates; the Verifier uses the first whose controls the target answers without a server error."
  - Risks: up to two more aborted experiments' requests per declaration, read-only, inside the existing three-experiment bound. Fewer model calls.
- R4, VER-026, replace the last sentence with: "Findings are tested most severe first, with prerequisites before the findings that depend on them; within one severity, findings whose request the assessment names and that need no write come first. A run stopped by a limit has spent its budget on the highest-severity findings it could reach."
  - Risks: the order of results within a severity changes between versions; `--resume` and saved reports are keyed by finding and are not affected. No target or model change.

## Work packages

Each package ends with the full test suite and ruff.

### WP1: prompt says what the requirements say (fix, VER-043, VER-049)

- `agent/prompts.py` `_system`: delete the sentences in lines 289 to 292 ("Before proof collection, record strategy in plan_test ... For a revision, include strategy.revision_reason ..."). Replace the sentence in line 307 ("Call plan_test before injection proof requests; for other classes call it before citing proof ...") with one that says a plan is declared only where the Verifier must generate something (an injection experiment, an access-control marker, a session check) and that the other classes need none.
- `_tool_defs`, `plan_test` description (from line 48): drop the prerequisite-status text and "for other classes the plan guides you". Keep accepting a supplied `strategy` in `PLAN_SCHEMA`.
- Add the auth-artifact form to the injection paragraph: where the effect is a login or session, declare `auth_artifact: true` with `pointer` at the token field; the proof is the artifact under the true controls and its absence under the false ones, a 401 to 200 split is expected, and each control is sent once. Check the wording against `auth_artifact_check` and the acceptance rule in `AgentTools.plan_test` (line 361).
- Tests in `tests/test_hosts.py`: the system prompt contains neither "record strategy" nor "revision_reason", says that no plan is required, and names `auth_artifact`. A loop test: the T-011 sequence (plan with `auth_artifact`, true, false, true-other, false-other on a POST in intrusive mode with a fake target that returns a token or 401) confirms with those four steps.

### WP2: feedback that names what is missing (fix, VER-043)

- `injection_check`: replace the bare "repeat every declared input ..." with the count per declared control, for example `baseline 0 of 2, positive 2 of 2, negative 1 of 2`, and the step of the plan the counts start from.
- When the cited responses split into 2xx and 401 or 403 and the plan has no `auth_artifact`, the reason names that form instead of only "error/status changes alone do not prove injection".
- `injection_ready` (`agent/experiments.py`): when the experiment stopped at a failed control, add that control's step, status and a bounded excerpt of the recorded error body. The step is already in the history the model sees; nothing new enters the prompt.
- Tests: each message for its case; the refused cases stay refused (the proof still fails).

### WP3: close the review points in proof and controller (fix)

- `proof.proof_ready`, XSS: apply the same route selection as `_xss` (pinned variant's request route, derived requests, a declared plan path) and its echo guard, best by sharing one helper so the two cannot drift. Add open redirect: a cited-able step answered 3xx with `location_host` equal to `redirect_host(ctx.marker)`, as `_redirect` checks.
- Injection steps chosen by code (`check_proof`, injection branch near line 160): when the cited steps fail and a later `experiment` history entry after the latest plan reports `proof: holds`, re-check with that entry's steps and, if they pass, record them as the proof steps.
- `Controller.before`: correct the comment about re-running the same plan (review point 6); no behaviour change.
- `docs/cli.md`: correct the 1280 by 1200 sentence (review point 8). In `verify/poc.py` leave `strategy` out of `result.planning` when the plan has none, and check the report's `Test plan` appendix with a rendered sample.
- Tests: `proof_ready` absent on another variant's route and present on the pinned one; open redirect sets it; never for access control; a confirmed verdict with empty `proof_steps` after a holding experiment is confirmed with the experiment's steps, and stays inconclusive when the experiment did not hold.

### WP4: evidence panels and review (fix, VER-035, VER-042)

- `verify/poc.py` lines 595 to 607: record the `input, decoded` fact once per step. Reproduce first from `/tmp/125/evidence` or a fixture with ten injection steps, then judge the rendered panel, following the maintainer's preference for evidence images (few precise marks, nothing doubled).
- Review loop (`verify/evidence_review.py`): issues about parts the Verifier renders itself (the panel facts, the `Comparison` line, excerpt length) cannot be corrected by the test agent. Report them in the review result and do not start a correction round for them; rounds stay for what the agent can change (its explanation, quotes, the application screenshot). Question for the maintainer before implementing: VER-042 says issues are returned to the test agent; confirm that leaving out the ones it cannot act on is a fix and not a changed promise.
- Console: show the review's time and cost on a row of its own for the finding, not on its last variant's `done` line. A display change; `docs/cli.md` only.
- Tests: one `input, decoded` line per step; no correction call for a panel-only issue, one for an explanation issue; the `not attempted` variant's line carries no review cost.

### WP5: tests the first plan named (fix)

- Add the tests listed in review point 7 that WP1 to WP3 do not already add. The offline replays used for the review are a starting point; they are not in the repository, rebuild them from the helpers in `tests/test_planning_changes.py` (`_ctx`, `Resp`, `plan`), `tests/test_controller.py` (`xss_context`, `SEARCH_VARIANT`, `Script`) and `tests/test_runner.py` (`_run`).
- Restore in `test_an_accepted_plan_runs_its_controls_once_automatically` an assertion on the recorded PoC steps.

### WP6: token usage per model call (measurement; WP8 of the first plan)

- The Claude CLI's final `result` event carries `usage` next to `total_cost_usd` (`agent/host_claude.py` line 125). Check the event's fields against the CLI's current documentation, pass input, cache-creation, cache-read and output token counts through `HostReply` (`agent/hosts.py`), and write them with the cost to the action-log record of the step; numbers only. Check what the other hosts report before adding fields for them.
- `docs/cli.md` line 574 documents `agent-log.jsonl`, so the format is an interface: agree the field names with the maintainer first, then document them there.
- Purpose: decide whether the system prompt, the CLI's overhead, thinking output or the history makes up the fixed USD 0.10 per call, before WP12.

### WP7: an empty source search says why (fix, VER-050)

- `SourceReader.find` or `AgentTools.find_source`: with zero matches, add a note that the search covers file names and paths, not contents. With R2 implemented, point to the content search instead.
- Test: the note appears with zero matches and not otherwise.

### WP8: write controls in one step (R1)

- A new agent action, for example `send_controls`, offered only in intrusive mode (`not ctx.safe and not ctx.read_only`) and only after an accepted boolean challenge plan on a non-safe method. Do not reuse the name `run_experiment`; tests assert its absence.
- `AgentTools.experiment_requests`: keep the refusal for non-safe methods as the default and allow it only for this action. An `auth_artifact` plan sends each control once, because its proof needs no repetition; the response-field form sends each twice.
- `agent/loop.py`: reuse `send_experiment_controls`. Every request still passes `Controller.before(..., experiment=True)` (route, method, declared sink value, write rules, `allow_state_change`), the guard and the budgets, and gets its own step number. Stop rule: for the response-field form the first non-2xx, as for reads; for `auth_artifact` only a transport error or a 5xx, because 401 is the expected answer of the false controls. Then report `injection_ready`, extended to the auth-artifact check.
- Acceptance of a plan still sends nothing on a write.
- Update `requirements.md`, the invariant sentence in `AGENTS.md`, and the Injection paragraph in `docs/cli.md`.
- Tests: the action is refused in safe mode, with `allow_state_change: false`, without an accepted plan, and on a plan for another route; in intrusive mode it sends the controls once (auth artifact) or twice (response field), stops at the first failed control, and a second call for the same plan stops at the repetition allowance; privileged accounts still cannot write.

### WP9: search file contents (R2, VER-050)

- `SourceReader`: a content search for a literal string (no regular expression from the model), case-insensitive, with the confinement of `find`: `_PRUNE_DIRS`, `_holds_secrets`, `_FIND_SCAN_CAP`, files above `MAX_SOURCE_BYTES` skipped, symlinks not followed. Return at most 40 matches as path, line number and the matching line cut to a fixed length; say when the result is truncated.
- Offer it as its own action or as a mode of `find_source`; keep the tool description explicit about which one matches names and which contents. `.env` files, keys, credential stores and `.git/` stay excluded, with a test for each.
- Tests against a fixture tree: `getPaymentMethods` finds the registration line in another file; a match inside an excluded file or directory is not returned; the caps hold; a query with a NUL byte is refused.
- Optional extension after a run (own approval, see R2): resolve the route in code before the agent starts, by finding the file that imports the finding's file and the `app.<method>('/route', ...)` lines that use the import, with the same literal pattern as `Controller.observe` (line 376). It would let the test plan show the route and R4 classify the finding.

### WP10: several template candidates (R3)

- `PLAN_SCHEMA` (`agent/experiments.py`): allow up to three candidates for `sql_template` and `expression_template`, keeping the single string valid.
- On acceptance of a read-only plan the loop runs the first candidate; when its controls stop at a server error, it runs the next one. Each candidate is an experiment of its own for the per-plan repetition namespace and counts against the three-experiment bound in `Controller.before`. The feedback names the candidate that ran to the end, or each candidate's failed control.
- With R1, `send_controls` on a write uses the first candidate only; the agent chooses another by revising the plan, so no write is sent for a template the agent has not looked at.
- Tests: candidates one and two fail with a 500 on a fake SQLite target, the third confirms in one plan step; four candidates are refused by the schema; the bound stops a fourth experiment across plans.

### WP11: easier findings first within a severity (R4, VER-026)

- `planning.severity_order`: add a secondary key between severity and finding number: findings with a request named by the assessment on a safe method first, then findings whose named requests all write, then findings without a named request. `dependency_order` still runs afterwards.
- Check the guided run's test-plan listing, `--resume`, `--only` and the progress grid, which show findings in run order.
- Tests in `tests/test_planning_changes.py`: order within one severity; a critical finding without a route still precedes a high one with a route; prerequisites still precede their dependants.

### WP12: class-scoped prompts (WP4 of the first plan)

- Required for the cost target. Do this after WP6 has data from a maintainer run. The scope is the first plan's WP4: the system prompt built from a common part plus the finding's class, offered actions per class, bounded history, and size-guard tests.
- Let the data choose the lever. If the system prompt dominates, the class split comes first. If the CLI adds a baseline of its own to every call, compare the `claude` profile with the API profile on the same findings before changing prompts; whether the CLI offers a supported way to reduce that baseline or to bound thinking must be checked against its current documentation and the Analyzer's adapter (`scripts/runtime/analyst_host.py`), not added from memory. If the history dominates, bound what older steps carry.

## Acceptance

- Offline: `python3 -m pytest -q` passes and `ruff check .` is clean after every package; the tests named above exist, including the refused cases.
- Maintainer's run, only on the maintainer's explicit request and with a cost limit: the command of the run above. Expected after WP1 to WP7: T-004 confirmed without a strategy in its plans and without correction rounds in the evidence review; T-011 confirmed through the auth-artifact form in about seven model calls. After WP8 to WP10: T-011 in about four calls, T-004 in three (source, plan, verdict), T-010 sends its first request to `/api/Cards` within four steps.
- Cost target: the run's cost per tested finding is USD 0.40 to 0.60, measured as the cost target section says. The first run after WP1 to WP7 is not expected to meet it; it provides the usage data. The target counts as met when a run over at least ten findings of mixed classes stays in the range. Whether the packages reach it is an estimate until WP6 provides usage data; if a run after WP12 is still above it, report the remaining cost by cause to the maintainer instead of tuning further without a decision.

## Implementation status (2026-11-10)

Implemented on `main`, not committed. `python3 -m pytest -q`: 1707 passed, 2 skipped (the browser-live opt-in; run outside the Bash sandbox, where one progress test needs `unshare`). `ruff check .` clean. No run against a target and no real model call.

- Requirements: R1 to R4 as proposed (VER-011, VER-050, VER-026), the VER-008 route extension (approved 2026-11-10), and VER-042 ("Issues in what the Verifier renders itself are reported and not returned to the test agent"). `AGENTS.md`: the safe-mode invariant names `send_controls`.
- WP1: prompt without strategy and plan precondition; the auth-artifact form named; `plan_test` offered without `strategy` (still accepted).
- WP2: feedback with per-control counts, the auth-artifact hint on a 401/200 split, and the failed control's step, status and excerpt.
- WP3: `proof_ready` shares the XSS route and echo rules with `_xss` and covers open redirect; injection proof steps chosen by code from a holding experiment, for the response-field and the auth-artifact form; controller comment corrected; no empty `strategy` in `Test plan`.
- WP4: `input, decoded` once per step; readability and missing-evidence issues are reported and start no correction round; the review's time and cost on the reviewer's own row.
- WP6: `model` entries with `usd` and token counts in `agent-log.jsonl` (`claude`, `anthropic-api`); field names chosen here, documented in `docs/cli.md` — confirm or rename before relying on them.
- WP7: empty `find_source` points to `search_source`.
- WP8: `send_controls` for write experiments in intrusive mode, once per plan; an auth-artifact control is sent once and stops only on an error or 5xx.
- WP9: `search_source` content search; route resolution from a registering file (`registration_routes` in `agent/derivation.py`).
- WP10: up to three template candidates, tried in turn on a server error for read plans; a write uses the first.
- WP11: within one severity, read-reachable findings first.
- WP12: class-scoped system prompt and offered actions (XSS about 13,900 characters instead of 21,400); history not bounded yet, pending usage data.
- Console counts: the test-plan head, `Not testable`, the settings and the grid count findings, not variants.
- Category `quick` (VER-026, approved 2026-11-10): XSS and SQL or NoSQL injection whose request the assessment names and a read can send; a severity selection adds those of other severities, marked in the test plan, unless `--strict-severity` or `--only`; `--category quick` selects them alone.

Open: the maintainer's acceptance run with a cost limit; bounding the history in `steps.prompt` once usage data exist. Each generated control carries only the declared input, so a write endpoint that needs other fields still needs the agent's own requests.
