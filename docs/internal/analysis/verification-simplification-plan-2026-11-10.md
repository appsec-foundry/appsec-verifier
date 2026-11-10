# Simpler, cheaper verification: implementation plan (2026-11-10)

Handoff for an implementing session. It records why a simple SQL injection ended inconclusive at USD 2.21, the maintainer's decisions, the requirement wording that still needs approval, and the work packages in order. Nothing in the repository was changed for this plan except this file.

## What the run showed

Run: `verify --only T-004 --profile claude --allow-intrusive` against a local Juice Shop, Verifier `55a6260`, output in `/tmp/124` (`agent-log.jsonl`, `verification.yaml`). T-004 is SQL injection in `GET /rest/products/search?q=`. Both variants ended `inconclusive`; 18 model calls, 21 requests, 6m32s, USD 2.21.

| Observation | Cause | Applies beyond this finding |
| --- | --- | --- |
| Stopped with `action repetition allowance exhausted` in the second control round | The first `run_experiment` aborted on a 500 (unbalanced template) after sending the baseline once. The controls' repetition namespace (`Controller.before`, `experiment=True`) is per finding, not per accepted plan, so the corrected plan could send the same baseline only once more | Any injection finding whose first template fails |
| The model had the contrast after step 8 (true 19805 B, false 30 B) and still needed a plan revision, ten controls and a verdict call | Proof is only accepted in the declared-plan form; `plan_test` requires a `strategy` object (data flow, prerequisites, choice, counter-hypothesis, expected, stop) of about 2,500 characters per plan | All classes: `_xss` in `agent/proof.py` downgrades an executed marker when no execution plan selected the variant; `_negative` and `experiment_groups` demand a plan too |
| USD 0.10 to 0.19 per model call | Every step is a fresh `claude -p` call carrying a 22,000-character system prompt (all classes' rules and all action schemas, `PLAN_SCHEMA` alone 3,400) and the whole history. The split between input, cache and output tokens is not known: the action log records no usage | All classes, all profiles |
| The same request was tested twice | The assessment lists two variants with the identical request (method, path, input). Variants are retired only after a confirmed one (`confirmed_ids` in `verify/runner.py`) | Any finding with duplicate variants |
| Evidence review spent USD 0.17 on an inconclusive result and stopped itself | It runs after every tested finding. `_checks` in `verify/evidence_review.py` flagged the Verifier's own HTTP panel (1200 by 1394 pixels) and sent that to the test agent, which cannot change a panel size; the revision then failed on `quote not present in recorded evidence` | Any finding with a long HTTP panel |

The ten control requests took about one second. Time and cost are almost entirely model calls, so the plan reduces calls first, then tokens per call.

## Decisions

The maintainer decided on 2026-11-10 to follow the recommendations below ("mache wie du das empfiehlst"). D1 was presented in full; D2 to D4 were listed by title and are filled in here with the recommendation. D5 was raised afterwards and is not decided.

- D1, decided: a test plan is no longer a precondition. The agent sends requests within the finding's routes and submits a verdict; the code checks recorded steps against the proof of the class. A short declaration remains only where the code must generate something: injection controls and the access-control marker. The strategy text is dropped.
- D2, as recommended: no automatic verdict. When the recorded steps already meet the proof of the class, the tool result says so and names the steps; the agent's next call submits the verdict and chooses page, highlight and explanation (VER-035). Reason: the maintainer wants the model to choose what the evidence shows.
- D3, as recommended: a variant whose request (method, path, inputs) another variant of the same finding already tested is not tested again, whatever that verdict was.
- D4, as recommended: the evidence review (VER-042) runs only for a finding with a confirmed variant. Technical QA (VER-046) is skipped for a confirmed verdict whose proof check passed and stays for negative and unproven conclusions, where it can point at an attempt that is missing.
- D5, open: model-assessed confirmation where no scripted proof form fits. See its own section; do not implement without the maintainer's explicit decision.

## Rules for the implementing session

- Follow `AGENTS.md`. Ask the maintainer whether to work on a feature branch or on `main` before the first edit to a tracked file; this plan recommends a feature branch in its own worktree, because the work spans several packages.
- The requirement wording below is a proposal. Show it to the maintainer and wait for explicit approval before adding it to `requirements.md` and before implementing the packages that depend on it (WP2 to WP6). WP1 and WP7 are fixes and need no requirement.
- Do not weaken the safety invariants in `AGENTS.md`: every request through `GuardedHttpClient` and `ScopeGuard`, limits in code, safe mode by default, writes only with marker and never repeated automatically, no secret in prompts or logs, and a confirmed verdict only with the proof its class requires, checked in code. Removing the plan as a precondition removes a formality, not a control: route restriction (`Controller._routes`, `_target`), write rules and budgets stay as they are.
- Changes to a control need a test for the refused case as well as the allowed one.
- Tests stay offline. Do not run `verify`, `preflight` or the guided run against a target or with real model calls; the acceptance run at the end is the maintainer's.
- Do not change `ENGINE_VERSION` or `INTERFACE_VERSION`. Update `docs/cli.md` and, where a summary sentence becomes wrong, `README.md` in the same change.
- Checks: `python3 -m pytest -q` and `ruff check .` (there is no `python` binary on the maintainer's machine; the browser live tests and one progress test need to run outside the Bash sandbox).

## Proposed requirement wording (needs approval)

Only the changed sentences are shown.

- VER-011, replace "Declare the hypothesis, changed input and observation before gathering proof." with: "The agent names the input, the observation and a template for the injected value; the Verifier generates the controls from it, sends a read-only experiment at once and reports whether the proof holds."
- VER-043, replace the three sentences from "The plan guides the run" to "once the proof shows it was met." with: "No test plan is required. A confirmation counts when recorded steps meet the proof of their class (VER-009 to VER-012); the agent declares only what the Verifier needs to generate controls or a marker (VER-010, VER-011). The Verifier tells the agent when the recorded steps already meet the proof."
- VER-039, extend the last sentence: "Variants of the same finding stop testing after the first one confirms, and a variant whose request another variant already tested is not tested again; the remaining ones end as not-attempted with that reason, and the finding's rating uses the confirmed verdict."
- VER-042, replace "After each tested finding" with "After each finding with a confirmed variant".
- VER-046, add: "A confirmed verdict whose proof check passed is not reviewed."
- VER-036 keeps its wording. The allowances it refers to change in `docs/cli.md`: experiment controls count per declared experiment, and a finding runs at most three experiments.

Risks and side effects to name with the proposal: no new target contact or state change (the same read-only controls, sent one model call earlier; an experiment on a write is still never sent automatically); fewer model calls and less data sent to models (no strategy text, no review of unconfirmed findings); the report's `Test plan` appendix shrinks to the declarations; saved results keep their fields, with `planning[].strategy` absent in new runs; a duplicate variant shows `not-attempted` with its reason instead of a second verdict. Simpler variant of D1 that was rejected: keep the plan mandatory and make only `strategy` optional, which saves output tokens but neither the extra call nor the downgrades.

## Work packages

Order matters: WP1 stands alone and can be committed first. WP2 to WP6 follow the approved wording. Each package ends with the full test suite and ruff.

### WP1: experiment controls count per accepted plan (fix, VER-036)

- Where: `Controller.before` and `Controller.observe` in `agent/controller.py`.
- Change: scope the `experiment-control` repetition key to the accepted plan, for example by including a token of the accepted experiment (`self.plan`) in the key. A revised plan gets its own two sends per control; re-running the same plan still stops at the allowance.
- Bound to add, so a revised plan cannot be used to send controls without end: at most three executed experiments per finding, raised as `LimitExceeded("stagnation", ...)` with a message that names the bound.
- Tests in `tests/test_controller.py`: after an aborted experiment (baseline sent once), a revised plan with the same baseline sends each control twice; a third send of a control under the same plan stops; a fourth experiment in one finding stops. Add a loop-level test in `tests/test_agent_probe.py` that replays the T-004 sequence with a fake planner and fake transport: experiment aborts on 500, revised plan, full experiment, confirmed.

### WP2: no plan as a precondition (D1)

- `strategy` becomes optional: remove it from `required` in `PLAN_SCHEMA` (`agent/experiments.py`); in `AgentTools.plan_test` (`agent/tools.py`) read prerequisites only when a strategy is given and drop the rule "a revised plan must explain the new observation" (line 464). `verify/poc.py` (`result.planning`), `progress.py` (plan row) and the report's `Test plan` appendix must render a declaration without strategy. Keep accepting a supplied strategy, so saved plans and other planners stay valid.
- XSS (`_xss` in `agent/proof.py`): stop requiring an execution plan. Bind the executed `browser_check` to the variant the probe is pinned to (`ctx.plan.variant_id`, set by `planning.expand_variants`): its request route, or a request the code derived for it (`derivation.covers`). Without variants any executed, context-verified `browser_check` counts, as today; the controller has already confined it to the finding's routes. The echo guard and `context_verified` stay.
- Injection, read-only: accepting a declaration runs it. In `agent/loop.py`, when `plan_test` is accepted and `tools.experiment_requests()` applies (boolean challenge with `sql_template`, `expression_template` or `operator_challenge` on a safe method), send the controls in the same action through the existing `run_experiment` branch, then evaluate `injection_check` over exactly those steps and append the outcome to the plan's result for the model: `proof: holds` with the step numbers, or `proof: missing` with the reason and, when a control failed, its status and the recorded error excerpt. Remove `run_experiment` from the actions offered to the model and from the prompt once this works; keep the per-request guard, budget and step numbering.
- Injection on a write, timing, out-of-band (VER-048) and auth-artifact (VER-049) keep their current flow: the declaration is accepted, the agent sends the controls.
- Proof steps chosen by code: when a confirmed injection verdict cites no steps or cites steps that fail, and the latest experiment's own steps pass `injection_check`, check and report those steps. XSS and SSRF already work this way.
- Access control and session keep their declarations (`owner`, `reference`, `resource`, session check id), because the code issues the marker or reads the operator's resource from them. Only the strategy becomes optional.
- Tests: XSS confirmed without `plan_test` for a pinned variant; XSS on another variant's route still downgraded; injection declaration executes controls and returns `proof: holds`; a 500 on a control returns the reason and stops the experiment; a write declaration sends nothing automatically (refused case); a declaration outside the finding's routes or variant inputs is still refused; existing tests that assert the old gates are updated, not deleted, where the gate itself is the control (route, input, write, marker).

### WP3: tell the agent when the proof holds (D2)

- Where: `agent/loop.py`, with a side-effect-free predicate next to `check_proof` in `agent/proof.py`. `check_proof` writes evidence records (`_write_record`), so the readiness check must not call it as is.
- Change: after each recorded action, when the steps so far meet the class proof with steps the code can select itself (XSS executed marker, SSRF callback hit, open redirect to the marker host, path-traversal marker read, injection experiment that holds), add to that tool result a short field, for example `proof_ready: {"steps": [...]}`, and say in the prompt that the next step is then `submit_verdict`. No verdict is submitted by code.
- Tests: each of the five cases sets the field; a reflected but unexecuted XSS payload does not; the field never appears for access control without the full contrast.

### WP4: smaller prompts (no requirement change)

- `agent/prompts.py` `_system`: build the text from a short common part plus the paragraphs of the finding's class only. An XSS finding does not get the injection, access-control, session, traversal or SSRF rules. Rewrite the planning paragraphs for D1 and D2 and remove what they make wrong ("Before proof collection, record strategy in plan_test", the `run_experiment` instructions).
- `agent/steps.py` `system_prompt`: offer only the actions the class can use (`browser_check` for XSS, `archive_probe` only with a declared archive check, `plan_test` for injection, access control and session). Validation stays global, so an action that is not offered is still checked and answered with an error.
- History in `steps.prompt`: measure first (WP8), then bound what older steps carry. Candidate: keep full result text for the last four steps and status, length and a short excerpt for older ones; `read_response` remains for details.
- Guard against regrowth: tests that the system prompt for an XSS finding and for an injection finding stays under a fixed size, chosen after the rewrite, and that neither contains another class's proof instructions.
- Keep credential and target-content rules: nothing new enters a prompt.

### WP5: test an identical variant once (D3)

- Where: the loop over plans in `verify/runner.py`, next to `confirmed_ids`.
- Change: remember per finding the request signature (method, path, sorted inputs) of every variant that was tested. A later variant with the same signature gets `not-attempted` with "not tested: variant <id> already tested the same request", like the existing confirmed case, and `progress.finding(plan, agent=False)`.
- Check `--resume` and `--only` with saved results, and `rating_after_verification`, which rests on all variants of the finding.
- Tests in `tests/test_runner.py`: duplicate variant not tested after an inconclusive first one; a variant with another input or path is still tested.

### WP6: reviews where they add something (D4)

- Evidence review: in `verify/runner.py`, call `review_finding` only when a variant of the finding is confirmed; otherwise record `not-reviewed` with the reason "no confirmed result to present". `review_finding` already fills `evidence_review` through its `stop` path; reuse that.
- Technical QA: in `agent/loop.py`, do not call `qa.consider` for a confirmed verdict whose proof check passed; record `not-reviewed` with the reason. Negative and unproven conclusions are reviewed as before.
- Tests: no reviewer call for an inconclusive finding; reviewer call for a confirmed one; no QA call after a checked confirmation; QA call after `not-reproducible`.

### WP7: evidence panel defects (fix)

- The HTTP panel renderer produced 1200 by 1394 pixels, above the 1280 by 1200 limit that `_checks` in `verify/evidence_review.py` enforces, and the issue went to the test agent, which can only add an explanation and quotes. Either keep the renderer within the limit or stop sending layout issues of the Verifier's own panels to a model for correction; report them instead. Find the renderer from `verify/poc.py`.
- The reviewer reported the line `input, decoded: ...` repeated five to six times per step in the panel text. This is the reviewer's observation and is not verified; reproduce it from `/tmp/124/evidence` or a test fixture before changing anything.
- Follow the maintainer's standing preference for evidence images: few precise marks, nothing doubled, judged from rendered samples.

### WP8: record token usage per model call (measurement)

- The Claude CLI's final `result` event carries `usage` (input, cache creation, cache read and output tokens) next to `total_cost_usd`. Pass the numbers through `HostReply` and write them to the action log per step; numbers only, never content. Check that the other hosts report nothing comparable before adding fields for them.
- Purpose: decide with data whether thinking output, the system prompt or the history dominates, before tuning any of them. Whether the CLI offers a supported way to bound thinking for these calls must be checked against its current documentation and the Analyzer's adapter (`scripts/runtime/analyst_host.py`); do not add a flag or environment variable from memory.
- If the maintainer sees the action-log format as an interface, agree the fields first.

### WP9: documentation

- `docs/cli.md`: rewrite "Test planning by the agent (VER-043)" for D1 and D2, "Continuous control (VER-036)" for the per-plan allowance and the three-experiment bound, "Proof per class" for the immediate experiment and code-selected steps, "Technical QA" and "Evidence presentation review" for D4, and the variant sentence for D3. Rewrite the affected sentences; do not append paragraphs.
- `README.md`: adjust only sentences that become wrong.
- Module docstrings name the VER-IDs they implement; keep them current.

## D5, open: model-assessed confirmation

The maintainer asked that the model have sensible freedom to verify without a perfect script. D1 and D2 already free the path: payloads, order, pages and evidence are the model's choice. What stays scripted is the proof form per class, and some true findings do not fit it: an effect in an HTML response rather than a JSON field, an error-based contrast, a class without a proof check (`there is no proof check for class ...`).

Two steps, the first inside the current requirements:

- Widen the scripted observation (no decision needed, VER-011 already allows "another recorded signal"): make `pointer` optional for a boolean injection experiment. Without it the observation is the whole response body with the sent control value removed, compared by hash. This covers server-rendered pages. Tests: HTML responses split into two stable classes; a page that only reflects the input does not confirm.
- Model-assessed confirmation (needs an explicit decision, because it changes the invariant "the model's verdict alone never suffices" and VER-013): where no code check fits or the code check cannot be met, the agent may claim confirmation by citing recorded steps, exact quotes from their responses and a control step. The code checks that the steps are answered requests of this finding and that every quote occurs in the recorded response; an independent reviewer with a fresh context (the technical QA agent) must agree. Recommended presentation: `confirmed` with confidence `low`, labelled "model-assessed, not code-checked" in report, YAML and export, and no rating change under VER-039. Safer alternative: keep today's `inconclusive` with "indicative, not proven". Risks: a wrong confirmation in the report; target responses are untrusted text and could argue for a conclusion, which the quote check and the second reviewer limit but do not exclude; one more model call per such finding.

## Implementation status (2026-11-10)

Done on `main`, full suite green (`python3 -m pytest -q`: 1669 passed, 2 skipped — the browser-live opt-in) and `ruff check .` clean:

- Requirement wording: VER-011, VER-039, VER-042, VER-043, VER-046 updated as proposed.
- WP1: experiment controls keyed per accepted plan; at most three experiments per finding.
- WP2: no plan precondition; `strategy` optional; the revision-reason rule dropped; XSS confirms on an executed marker on the pinned variant's route without an execution plan; an accepted read-only injection plan runs its controls on acceptance and the loop reports `injection_ready`; `run_experiment` removed as a model action and from the prompt.
- WP3: `proof.proof_ready` reports citable steps for XSS, SSRF and path-traversal on each recorded action; the prompt tells the agent to submit the verdict when it sees `proof_ready`.
- WP5: a variant whose request another variant already tested ends `not-attempted` (`verify/runner.py`).
- WP6: the evidence review runs only for a finding with a confirmed variant; technical QA is skipped for a confirmed verdict whose proof check passed, and still runs when it already engaged the finding on an earlier conclusion.
- WP7 (dimension part): the compact 1280 by 1200 limit is checked only for application screenshots; tall HTTP exchange panels, which are saved as files and not embedded, are no longer flagged.
- WP9: `docs/cli.md` updated (Test planning, Continuous control, Injection, Technical QA, Evidence presentation review); `README.md` needed no change.

Deferred, with reason:

- WP4 (class-scoped prompts and offered actions): a token-size optimization, not a call-count one. The dominant cost — the number of model calls — is already cut by WP2, WP3, WP5 and WP6. Splitting the shared prompt or filtering offered actions per class risks a finding missing an instruction or action, and the plan sequences WP8 (measurement) before tuning. Do it with usage data and a maintainer acceptance run.
- WP8 (per-call token usage in the action log): the action-log format may be an interface; agree the fields with the maintainer first, then thread `usage` from the Claude CLI `result` event through `HostReply`.
- WP7, second part (the repeated `input, decoded: …` line in HTTP panels): the reviewer's observation is unverified; reproduce it from a rendered panel before changing the renderer.
- D5 (model-assessed confirmation, and the optional `pointer` for whole-body injection comparison): left out of this round by its own recommendation; needs an explicit maintainer decision.

## Acceptance

- Offline: `python3 -m pytest -q` passes and `ruff check .` is clean after every package; the new tests named above exist, including the refused cases.
- Maintainer's run (only on the maintainer's explicit request, with a cost limit): the T-004 command from the run above. Expected: first variant `confirmed` with one template correction at most, in about four model calls; second variant `not-attempted` with its reason; no evidence-review call unless confirmed; cost well under the USD 1.14 the first variant took. An XSS finding of the same assessment: source read, `browser_check`, verdict. These numbers are estimates until WP8 provides usage data.
