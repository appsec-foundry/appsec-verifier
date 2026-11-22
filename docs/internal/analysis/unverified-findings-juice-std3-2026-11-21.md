# Analysis brief: unverified findings, juice-shop-std3 run (2026-11-21)

## How to use this brief

You are a fresh session asked to turn one `verify` run against OWASP Juice Shop into generic Verifier improvements.
Work the way the maintainer wants run analyses done: name generic causes (Verifier bugs, misleading gates, proof checks that fight their own intent, design limits worth a feature), rank proposed measures by how many findings and how many target apps they help, and keep every proposed change free of anything specific to Juice Shop.
For each measure say whether it is a fix (restores what a VER entry already promises) or needs a new/changed requirement first; the latter waits for the maintainer's wording approval before any code.
Reproduce each suspected bug offline before proposing its fix (`preflight --offline`, the module's tests, the non-Juice assessments). Do not run `verify`, `preflight` or a guided run against a real target.
Read the full run before trusting this brief: `console.log`, `agent-log.jsonl`, `verification.yaml` in the run directory below. This brief cites what was checked, but the raw run is the authority.

## Run under analysis

Command: intrusive, strict-severity critical+high, `--allow-intrusive`, source given, 30-finding selection, cost limit $30, default time/calls/requests caps.
Run directory: `/tmp/143/` (console.log, agent-log.jsonl, verification.yaml, evidence/). Target: local Juice Shop at http://127.0.0.1:3000. Assessment: juice-shop-std3.
Outcome: 5 confirmed, 5 inconclusive, 33 not tested, 26 unsupported/incomplete.
Binding constraint: wall-clock time. Run ended at 29m55s of the 1800s cap (`limits.py:145` `max_duration_s=1800`) at finding 10 of 30. Money ($10.92 of $30), model calls (102 of 500) and requests (149 of 2000) were all far from their caps.
Parallelism: effectively serial. No `--parallel` was passed (default 1), and in intrusive mode a write finding is tested alone anyway (`runner.py` `alone()`, VER-065).

## Headline: most findings failed for throughput, not for proof quality

"Access control: 0 of 20 confirmed" overstates a proof problem. 18 of the 20 access-control findings were never attempted: the clock ran out at finding 10. The same time wall left T-037 (template injection) and T-044 (SSRF) untested and 6 confirmed-variants and 2 further findings unrun.
The findings that did not run are mostly the cheapest to prove: unauthenticated file reads (`/encryptionkeys/:file`, `/support/logs/:file`, keyServer), "any authenticated user lists all users", a reset response returning the full record. These are single-request or two-identity GET contrasts that finish in seconds. They sat last because the selection is tested in assessment order (`runner.py`: planned order, only a confirmed finding's extra variants deferred), behind the slow injection findings that consumed the half-hour.
Where the time went: the four injection findings before access control took ~24 min, most of it in protocol friction, not in exploitation. T-012 4m48s, T-025 5m15s, T-034 3m40s, T-035 4m01s. T-002 variant-001 then spent its whole 3m39s on ten source reads and never sent one HTTP request before the wall.

So the top-breadth question for this session: why does a 30-finding intrusive run exhaust 30 minutes after 10 findings, and which of (a) scheduling/ordering, (b) serial write mode, (c) per-finding protocol friction, (d) the default cap itself relative to the other caps is the right lever. This one lever decides more findings than every proof fix below combined.

## Group A — never reached (time limit). Highest breadth.

Findings: T-042, T-053, T-058, T-060, T-069, T-026, T-030, T-046, T-050, T-051, T-052, T-057, T-059, T-061, T-063, T-065, T-039, T-064 (all access-control), plus T-037, T-044, T-002 variants 2-3, and 6 confirmed-variants. 18+ findings.
Cause: the run never got to them; the 1800s cap tripped at finding 10 while other caps idled.
What to verify offline:
- Confirm the cap and that time, not budget, is the usual binding limit for a large intrusive selection (`limits.py`, `budget_prompt.py`).
- Confirm the test order is "as planned" with no cost or duration awareness (`runner.py` around the `order`/`deferred` logic, lines ~314-356).
- Confirm that in intrusive mode the read-only findings (all-GET access-control, exposure) are not parallelised past the lone write findings, so a slow write finding blocks fast reads behind it.
Candidate measures, ranked by breadth, each marked fix vs needs-VER:
1. Order the selection cheapest-expected-first, or interleave fast read-only findings with slow write findings, so a time-out loses the fewest findings. Needs-VER if it changes the documented test order or result numbering; a fix if "test order" is unspecified and only the tie-break changes. Decide by reading what VER/docs promise about order.
2. Let read-only findings run in parallel even inside an intrusive run, reserving the "alone" rule for the write findings that need it (VER-065 already separates the two). Likely needs-VER (changes what "intrusive run parallelism" means) — propose wording.
3. When the time cap is the binding limit and other caps idle, surface it up front (the run already knew 30 findings, serial, 30 min) and in the summary point at `--parallel` and `--max-duration`. Message/console only, no VER (see memory console-display-needs-no-requirement).
4. Re-tune the default caps so they trip together for a typical selection, or scale the time cap with finding count. Needs-VER (changes a documented default).
Do not: special-case Juice Shop's routes or hard-code which findings are "cheap".

## Group B — reached but blocked by proof/tooling. Medium breadth.

### T-010 (IDOR payment cards, critical, access-control) — a defensible negative recorded as inconclusive
Runtime result: account-1 saw only its own card, account-2 only its own (agent-log steps 9, 11). Source confirms both card routes filter by `req.body.UserId`, which middleware overwrites with the session user (`routes/payment.ts`; `lib/insecurity.ts` appendUserId). The weakness very likely does not reproduce — useful signal that the analyzer over-flagged.
Why it landed inconclusive, not "not reproduced":
- The access-control plan pinned one route shape (`GET /api/Cards`, the list). The direct cross-object read `GET /api/Cards/5 as account-2` — the clean IDOR contrast — was refused "request does not match the accepted test plan" (step 10). The sibling `/:id` route could not be exercised under the list-route plan.
- The marker-plant create (`POST /api/Cards`) was refused: "no matching route in this finding or its operator-declared resources" (step 7).
- The agent's negative verdict was then rejected by the proof check: "step 5 precedes the plan in step 6 ... cite a reference plus a fresh test attempt sent after its plan" (`agent/proof.py`). A reasonable "isolation holds" could not be recorded.
What to verify offline: in `agent/proof.py` and the access-control plan handling (`agent/tools.py`), whether an access-control plan can cover both a collection route and its `/:id` member, and whether a negative verdict (protection holds) requires the same reference+fresh-test-after-plan ritual as a positive one.
Candidate measures:
1. Let an access-control finding with no declared request test the `/:id` member read as the cross-identity contrast, not only the collection route. Likely needs-VER (what access-control proof accepts). Propose wording.
2. Accept a clean negative access-control verdict (two-identity contrast shows isolation) as "not reproduced" without the positive-proof ordering ritual, so a false-positive analyzer finding is reported as such instead of inconclusive. Needs-VER — this is new reportable output (a negative verdict class). High value: "not reproduced" is information the maintainer wants. See memory latitude-in-finding-strictness-in-proof.
Do not weaken the positive-proof gate to achieve this; a negative verdict is a distinct, additive path.

### T-012 (code injection via Pug/eval, critical) and by extension T-037, T-059 — two stacked blockers
Blocker 1, session not recognised (generic, high breadth): every `GET /profile` as account-1 returned HTTP 500 with identical body length across all inputs (agent-log steps 24, 27). Source: `routes/userProfile.ts` reads the identity from `req.cookies.token`; a missing identity throws "Blocked illegal activity", which is the 500. The Verifier's form login (`auth/sessions.py:599-605`) observes the login's Set-Cookie (line 601) but returns `Session({"Authorization": "Bearer <token>"})` only — the `token` cookie the login set is dropped from the session headers (same drop at lines 614-624 for the HTML-form path). Routes that read the session from a cookie never see the identity.
Blocker 2, second-order flow (medium breadth): the sink reads `user.username` from the database, written earlier via `POST /profile` (the username form field) and only evaluated on `GET /profile` render. The declared variant is `GET /profile` with `username` in the request JSON, which the handler never reads. The expression/boolean proof forms model one request where the injected input travels in the same request being observed; a write-here-render-there (stored) injection is not expressible.
What to verify offline:
- In `auth/sessions.py`, that a form login which yields a token attaches only the Authorization header and not the cookie the login set; check against a local cookie-session app (memory local-oidc-providers-must-work has sample servers) and the non-Juice assessments.
- That `GET /profile`, `POST /profile/image/*` (T-059) and T-037 all read `req.cookies.token`, so the same drop blocks all of them.
Candidate measures:
1. When a login returns a token and also sets a cookie, carry both (Authorization header and the Set-Cookie value) in the session, as a browser would, so cookie-reading routes recognise the identity. Likely a fix (the session is meant to be "what an identity attaches to its origin"; dropping the login's own cookie under-delivers that). Verify no secret-handling/VER-016 regression: the cookie value is already remembered as a secret; attaching it to its origin is the intended use. High breadth — any app that authenticates by cookie.
2. A way to express a second-order injection: the sink input is written through one request and observed through another. Needs-VER (a new proof shape). Propose wording; this is a larger feature and may be out of scope for a first pass.
Measure 1 alone may move T-012/T-037/T-059 from "500 before the sink" to actually reaching the sink; keep them separate.

### T-025 (code injection via notevil in vm, high) — no reflected channel, plus an auth bug
Design limit: `routes/b2bOrder.ts` runs `safeEval(orderLinesData)` but discards the result; the response is always `{cid, orderNo, paymentDue}`. The evaluated value is never returned, so the expression proof ("does the answer show 5422*6720?") can never succeed. The only observable effects of this sink are a timeout/infinite-loop (a DoS the Verifier must not trigger) and an evaluation error. The weakness is real but has no safe reflected-output channel.
Separate bug (verify): the engine-error probe controls (agent-log T-025 steps 3-18) were dispatched unauthenticated and got HTTP 401, although the accepted plan declared `role: account-1` (step 2 args). Contrast T-012, where the GET controls carried `role=account-1`. 16 requests and a chunk of the clock were spent against a 401 wall before the model re-sent authenticated by hand. In `agent/tools.py` `experiment_requests` (lines 769-827) the control's role comes from the `role=` parameter, not from `self._experiment["role"]`; check why the write/error_probe dispatch path did not pass the plan's role while the GET path did.
Candidate measures:
1. Propagate the accepted plan's role into every generated control request (engine-error, operator, arithmetic), on both the read-at-acceptance and send_controls paths, so an auth-required sink is never probed anonymously. Fix. Medium-high breadth (any authenticated injection sink). Add a test that an authenticated plan's generated controls carry the role.
2. For a code-evaluation sink with no reflected value, offer an error-differential proof: an expression that evaluates cleanly vs one that references an undefined identifier (only evaluated code errors on an undefined name, not data echoed as a string). This proves "the string is executed as code" without a DoS and without a reflected result. Needs-VER (a new confirming signal for code-eval); note it is weaker than a computed-value echo, so word the proof carefully. A delay alone must still never suffice (existing rule).
Do not add a timeout/infinite-loop proof; that is a DoS against the target.

### T-035 (NoSQL operator injection, PATCH reviews, high) — the operator probe uses an operator the backend rejects
Mechanism (verified in code): `agent/experiments.py` `operator_controls` (lines 449-462) generates the positive/negative pair as `{"$eq": baseline}` / `{"$eq": absent}` and the second pair as `{"$in": [...]}`. Juice Shop's Mongo clone (MarsDB) does not implement `$eq`; the "true" control returns HTTP 500 "Unrecognized operator: $eq" (agent-log steps 8, 14 failed_control excerpt). The experiment check stops at the first 500 on a true control, so the `$in` pair that the backend does support is never reached. Technical QA caught exactly this: the alternate `$in` candidate was generated but the re-sent requests were byte-identical `$eq`.
Second, semantic point: `{"$eq": baseline}` vs `{"$in": [baseline]}` both match only the one baseline review — the same as a literal id. They do not demonstrate the dangerous property the finding is about (an operator matching many documents so `multi:true` overwrites others). A positive that matches many (e.g. an inequality against an absent value) vs a negative that matches none would be both backend-portable and on-point.
What to verify offline: reproduce the stop-on-first-500 ordering with a fake MarsDB-like backend; confirm `operator_controls` leads with `$eq` and that the sequence aborts before the `$in` pair; check which operators the supported-target backends (and the non-Juice assessments' stacks) implement.
Candidate measures:
1. Do not lead the operator probe with `$eq`; use operators that lightweight Mongo clones and older query engines implement (membership/inequality), and when a control returns "unrecognized operator" fall through to the next operator in the Verifier's own set instead of aborting the experiment or requiring a plan revision that re-emits the same template. Fix (restores VER-011's "the Verifier generates and sends working controls"). Medium breadth (every NoSQL operator finding on a non-Mongo-server backend).
2. Choose the operator-challenge positive/negative so they differ in how many documents match (many vs none), observed through the result count, not equality on one id. Fix or needs-VER depending on whether it changes what VER-011 promises the operator challenge proves; check the wording.
Do not hard-code MarsDB's operator list; derive portability generically (lead with the widely-supported operators, fall through on rejection).

## Group C — data gap, expected, not a bug

T-023, T-024 (path traversal): "needs marker file". The finding class requires a `marker_file` in a scope file (VER-012); without one the probe target does not exist. This is a declared input the run did not supply, not a defect. The run already prints how to provide it (preflight / docs/cli.md). No measure unless the goal is to make the hint even clearer (message-only).

## Suggested order of work for the reader session

1. Group A throughput first (ordering/parallel/caps): one lever, more findings than everything else. Settle the fix-vs-VER question against what `runner.py` and the docs promise about order and parallelism, then take one decision to the maintainer (memory decisions-one-at-a-time).
2. T-012 blocker 1 (login cookie) and T-025 bug 1 (role propagation): both look like fixes, both high breadth, both testable offline against non-Juice apps. Confirm, add the refused-case test, propose.
3. T-035 operator set: fix, reproduce with a fake backend.
4. T-010 negative-verdict and the `/:id` contrast, T-012 second-order, T-025 error-differential, T-037 template: each needs a requirement decision first; propose wording one at a time, do not implement before approval.

## Guardrails (from the maintainer's standing guidance)

Generic causes and generic code only; reading Juice Shop source to check a design fits is fine, tuning to it is not.
Before proposing a measure, show offline that it removes the symptom in every case it claims to, not just the first.
Never weaken a code-checked proof, a scope rule, a budget or the write gate to get a finding through; a negative or error-differential verdict is an additive path, not a loosening.
Widening any proof form or an AGENTS.md safety invariant needs a requirement and the maintainer's explicit decision before code.
