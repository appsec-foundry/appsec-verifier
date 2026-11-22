# Run 144 analysis: why no access-control finding was confirmed

Date: 2026-11-22. Written by a coding session against appsec-verifier `main` at 6c25aa1, then cross-checked by a second session against the code, the run artifacts and offline experiments. Status: diagnosis, no code changed. This document is an internal analysis (not packaged, per AGENTS.md).

## Purpose

Turn the observations of verification run 144 (Juice Shop) into generic, target-neutral causes ranked by breadth, and judge one proposed improvement. Every claim has an evidence pointer: a source `file:line`, a requirement ID, a console timestamp or step, or one of the offline experiments described at the end.

## What was run

Target: local Juice Shop at `http://127.0.0.1:3000` (Docker `bkimminich/juice-shop`, port 3000). Assessment: `/home/mrohr/assessments/juice-shop-std3/security-assessment.yaml`. Source checkout: `/home/mrohr/juice-shop`.

Mode: intrusive, state-changing. Profile: claude (Sonnet 5.5 via Claude CLI, planning only). Selection: 32 findings, severity high and above (the default `--min-severity high`). Limits: 30 min, $30, 500 model calls, 2000 requests, 5 req/s. Non-interactive run.

Equivalent command (from the run's own CI echo):

```
appsec-verifier verify --assessment /home/mrohr/assessments/juice-shop-std3/security-assessment.yaml --url http://127.0.0.1:3000 --source /home/mrohr/juice-shop --output /tmp/144 --min-severity high --cost-limit 30.0 --profile claude --console-log color --account jim@juice-sh.op=... --account bender@juice-sh.op=... --admin-account admin@juice-sh.op=... --overwrite --annotate --allow-intrusive --show-costs --non-interactive --yes
```

Artifacts: `/tmp/144/{console.log,verification.yaml,verification.md,agent-log.jsonl,evidence/}`. Note: `/tmp` is cleared on a WSL reboot. Run 143's output was lost that way before this session. Copy the four files out of `/tmp/144` if they must survive. This document does not depend on them surviving.

## Result tally

6 confirmed, 5 inconclusive, 32 not tested, 26 unsupported or incomplete. Run: 29m57s, 107 model calls, 124 requests, $12.76. The run hit the 30-minute time limit at finding 10 of 30.

Confirmed (all injection/XSS, tested first, 1m01s to 2m22s each): T-004 SQLi search (medium), T-011 SQLi login (medium), T-001 XSS (high), T-033 NoSQL `$where` reviews (medium), T-034 NoSQL `$where` trackOrder (medium), T-035 NoSQL operator (medium).

Inconclusive: T-012 code injection (cookie, 6m12s), T-025 notevil eval (wrong probes, 3m10s), T-010 IDOR (proof rejected, 3m24s), T-002 ownership x2 variants (step and time limits, 5m07s and 2m12s).

Not tested: 18 access-control findings never started (time ran out), the untested variants of the confirmed findings, T-037 (template injection) and T-044 (SSRF). T-023/T-024 (path traversal) need a marker file in a scope file and were not testable in this run.

## Headline finding

20 of the 32 selected findings are access-control and none was confirmed. The main cause is the run's time, not the proof model. The run tests one finding at a time because it may send write requests (console line 7), a started finding took about 3 minutes, and the 30-minute limit ended the run at finding 10 of 30. Only T-010 and T-002 of the 20 started; the other 18 are "not attempted" (console 08:34:34). The cost limit was not the constraint ($12.76 of $30).

Of the two that started, the proof model blocks only T-002's basket variant; T-010 fails earlier, at preparation. Most of the 20 findings test writes or function-level access, which a read-only proof does not touch (see Breadth).

Symptom A, wasted steps: T-002 variant-001 spent all 12 steps (5m07s) searching the source for a basket creation route ("Find how a basket is created", "Find route to create basket items", "Find the route to create a new basket") and sent no decisive probe (console 08:27:14 to 08:32:22); variant-002 hit the run's time limit mid-search (console 08:34:34). T-010 tried `POST /api/Cards` to plant a marked card (step 7, 08:26:42) and was refused: "request has no matching route in this finding or its operator-declared resources; allowed: GET /api/Cards/:id, GET /api/Cards". Deriving the route (step 8) was refused: "only recorded source declarations and application links or forms supply requests".

Symptom B, rejected reads: when the agent submits a verdict from reads alone, the proof check asks for an owner write. T-010 done (08:27:14): "cite the owner's answered write that carries the marker."

## Root cause per finding

### T-010 (GET /api/Cards/:id): preparation, not the proof form

A creation route exists, `app.post('/api/Cards', security.appendUserId())` (juice-shop server.ts:438), but the Verifier offers the agent no way to it. `preparation_endpoints` (appsec_verifier/endpoints.py:167) takes the POST only from the assessment's attack surface, and T-010 names no request; its GET routes come from `source_registrations` (appsec_verifier/agent/derivation.py:354). `derive_request` refuses a `search_source` step as evidence (derivation.py:702; the run's step 8 cited step 2, a search). Offline it also refuses a `read_source` of server.ts with "the source is not the finding's evidence or a recorded local import from it" (derivation.py:617), because server.ts is not an import of routes/payment.ts and the POST registers no handler of that file. No agent behaviour could have reached the created-resource proof.

The target is probably not vulnerable: `getPaymentMethodById` filters by `UserId: req.body.UserId`, which `appendUserId` sets from the session (juice-shop routes/payment.ts:41). A working created-resource proof would most likely end not reproducible. The QA hint (send account-2 `GET /api/Cards/5`) would not have produced a checked verdict either, because `owned_check` requires the owner's write for negative verdicts too.

### T-002 basket variants (GET /rest/basket/{id}): the proof form

No creation route exists. Juice Shop creates the basket at login (juice-shop routes/login.ts:21, `BasketModel.findOrCreate`), and a basket item carries only ProductId, BasketId and quantity (juice-shop models/basketitem.ts:19-22), no text for a marker. `retrieveBasket` looks the basket up by id alone (juice-shop routes/basket.ts:19), so the finding is real.

Here the proof model is the blocker. The object-level forms in `proof_form` (appsec_verifier/agent/proof.py:322) are `signed_in` (VER-057), `change`, `owner` and `reference`. `owned_check` (appsec_verifier/agent/experiments.py:1373) requires a non-empty owner write that carries the marker ("cite the owner's answered write that carries the marker", line 1388; "no cited write of the owner carries the marker", line 1390). `privileged_check` (line 1519) and `signed_in_check` (line 1555) only read but cover privileged functions and access without credentials. No form compares two accounts' reads of an existing record. VER-010's assumed restriction names "a record an account created", which a basket made at login is not.

Nothing told the agent that the plan has no preparation route for this record, so it searched for one until its steps ran out.

## Correction on the merged changes

Three changes from the prior session are on `main`: da71da9 (T-025 role fix), 834eae6 (T-035 `$in`/`$nin` operator controls), 6c25aa1 (VER-066 name test). Run 144 shows:

1. da71da9 (role fix) WORKED. At T-025 the generated controls reach the target as account-1 and return 500 (application error), not 401. Earlier runs failed with auth errors; here the controls arrive authenticated (console 08:22:07, break/balanced both answered 500; no 401).
2. 834eae6 (`$in`/`$nin`) was NOT the cause of T-035's confirmation, and was not exercised. T-035 is confirmed via the ENGINE-ERROR probe with a `$regex` operator, not via the membership (operator) controls. Evidence: verification.yaml T-035 `proof.form: engine-error`; break `{"$regex":"(vrf..."}` to 500, balanced `{"$regex":"vrf..."}` to 200 (console 08:13:13, steps 7-10). The agent tried the `operator_challenge` path (step 4, 08:12:53) but it failed schema validation ("'baseline' is a required property") and was abandoned. So T-035 is genuinely confirmed, but by a different mechanism than the merged change; the `$in`/`$nin` change is unverified by this run.
3. VER-066 (name test) was NEVER reached. verification.yaml summary `shown_without_exploit: 0`. At T-025 the agent spent 31 steps on the engine-error probe and the expression test and never used `name_template` (console 08:20:48 to 08:23:50).

Re-checked by the second session: the T-035 proof form and `shown_without_exploit: 0` in verification.yaml. The console details of points 1 and 2 were not re-checked.

## The other inconclusives (lower breadth, for completeness)

T-012 (code injection, GET /profile): unrelated to our changes. The baseline GET /profile as account-1 itself returns 500 because the handler reads the auth token from a cookie (`security.authenticatedUsers.get(req.cookies.token)` returns null). Juice Shop sets that `token` cookie client-side in JS after login, so the Verifier's login session does not carry it (console 08:15:12 step 2 → 500; done 08:20:40). Generic angle: some apps authenticate protected routes via a cookie set by client-side JS, which a headless/API login does not obtain. This is a known pending item (the T-012 cookie feature).

T-025 (notevil eval, POST /b2b/v2/orders): the route is the textbook VER-066 case. Source `routes/b2bOrder.ts`: when `rceChallenge` or `rceOccupyChallenge` is enabled it runs `vm.runInContext('safeEval(orderLinesData)', sandbox, {timeout: 2000})` and on success returns `res.json({cid, orderNo, paymentDue})` — the eval result is never returned; on throw it calls `next(err)` → HTTP 500. So valid expression → 200, throwing expression → 500, no return channel. The name test (unknown name → ReferenceError → 500 fail; known name like `(undefined)`/`(Number)` → 200 pass) is the correct and only viable proof. The agent never used it. It burned budget on: (a) the engine-error probe, which is template-oriented (break/balance pairs `${`/`$` etc.) and does not fit a JavaScript eval sink because the "balanced" counterpart is also invalid JS, so both returned 500 and the probe correctly reported "the break is not what caused it" (console 08:22:10 step 25); (b) the expression test, which cannot work here (no return channel) and whose `1+1` baseline control was rejected for not carrying the marker on a write (VER-014), which the agent did not fix (console 08:22:28 step 27, repeated 08:22:47 step 29, then gave up). Generic angle: for CWE-94/95 where the sink's response does not carry the eval result, the agent should pivot to `name_template`; whether to steer it there is a prompt/feedback change, testable only in a live run.

## Breadth: object-level reads of an existing record

Offline count over five assessments with their sources (method at the end). An access-control finding needs a read-only proof only where it reads a record the owner cannot create during the run.

| Assessment | Findings | Record |
| --- | --- | --- |
| juice-shop-std3 | T-002 (basket variant), T-042 | basket created at login; the account's user record |
| /home/mrohr/standard (Juice Shop) | T-002 (basket part), T-092, T-098 | basket; user record |
| /home/mrohr/thorough (Juice Shop) | T-042, T-142 | basket; user record |
| VulnerableSpringApp3 | T-037, T-001 (user part) | user record, `GET /api/users/{id}` |
| DVWA | T-073 | user profile chosen by the `user_id` cookie |

For user records the only preparation the assessments offer is the registration (`POST /api/Users` in Juice Shop), which creates a new account rather than a record of the owner. Orders that exist only after a checkout (track-order, T-102 and T-139) are not counted. The other access-control findings either have a creation route the plan offers (Recycles, BasketItems, Addresses, Spring `/orders`), test a write, or test function-level or anonymous access, for which the privileged comparison and VER-057/VER-061 exist.

The gap is generic but narrow: one to three findings per assessment, mostly the account's own user record and records the application creates implicitly.

## Proposed improvement, revised (needs approval before any code)

The first proposal was a three-way read contrast (owner reads record X, a request without credentials does not get it, the other normal account does) with the guard that the other account's own record must differ. That guard is insufficient. A differing own record only shows that the answer depends on the id, not on who asks. A record every signed-in account may read by design (shared objects, content behind a login) passes all three conditions and would be confirmed falsely.

A read-only proof needs evidence from the application that X belongs to the owner. Two anchors can be checked in code. The identity anchor: the owner's answer for X names the owner's account, as the user name of a command-line account (VER-041) or the issuer and subject its token names where the session says (appsec_verifier/preflight.py:241), and the other account's answer for its own record names that account in the same field. It fits the user records of all three applications; the Juice Shop basket names only a numeric `UserId`, which its token carries but other applications' sessions may not. The listing anchor: the owner's own collection read lists X and the other account's does not; none of the records above has such a listing. Without an anchor the result stays inconclusive.

The comparison itself should use the recorded digest, as `privileged_check` does (identical bytes for owner and other account), instead of a discriminator extracted from the body. The proof must also decide the negative side: the other account refused (403/404), or answered without the owner's anchor, gives blocked-by-control or not reproducible, as `owned_check` does for created records.

Home: VER-010 is already the longest entry, and VER-057 is the precedent for a separate comparison entry. A new short VER entry is preferable, with VER-010's restriction sentence referring to it.

Risks and side effects: three or four GETs per finding, no writes, usable in safe mode. It changes the access-control proof, a safety invariant, so it is the maintainer's decision and needs tests for the refused cases: a shared record without anchor, anonymous access, an answer identical for every record.

## Ranked next steps

1. Time and throughput. At about 3 minutes per finding, 30 findings need about 90 minutes in a serial run. For a run like 144 a longer `--max-duration` is the most effective measure and needs no code. Testing several findings at the same time in a run that may write would be the code-side lever; VER-065 allows it only for findings tested read-only, so it is a design decision.
2. Tell the agent when the planned record has no preparation route, so it does not search for one (prompt or message change, no requirement). It would have saved most of T-002 variant-001's 5 minutes.
3. The read-only proof with owner anchor above: generic but narrow, the maintainer's decision.
4. Preparation from the source: when a plan's routes come from source registrations, offer the POST to the record's exact collection that the registration file declares (VER-008 already promises evidenced creation requests for the Verifier's own test resources). In these assessments only T-010 benefits, and it would likely end not reproducible.
5. Console message: appsec_verifier/progress.py:1118 always says "Up to N findings are tested at the same time", while the run settings (appsec_verifier/cli.py:1961) say "one finding at a time" for a run that may write. Message-only fix.
6. T-012 client-side cookie authentication, which T-037 (Pug template) shares through /profile, and T-025 name-test routing (prompt or feedback; verifiable only in a live run).

## Offline experiments

Breadth: `load_plans` on each assessment's `security-assessment.yaml`, `source_registrations` with a `SourceReader` on the source checkout, and the `app.post` registrations of juice-shop server.ts, then the read handlers of the remaining findings read by hand (Spring `UserAccessController`, `OrderAccessController`; DVWA `vulnerabilities/bac/source/low.php`).

T-010 replay: `AgentProbe` with a scripted planner and a fake transport, built like `tests/test_readiness_pilot.py::test_stateful_two_account_pilot`, with the real T-010 plan from the std3 assessment and a `SourceReader` on the Juice Shop checkout. Variants: the run's sequence (a `search_source` step cited as evidence), and a `read_source` of server.ts around line 438 followed by `derive_request` with and without the card fields, each against a vulnerable and a protected fake. `POST /api/Cards` was refused in every variant.

## Cross-check results

1. Confirmed: `owned_check` requires the owner's answered write with the marker; no access-control form accepts a read-only cross-account contrast.
2. Confirmed: the forms are `signed_in`, `change`, `owner` and `reference` (proof.py:322); none compares two accounts' reads of an existing record.
3. Confirmed: VER-057 is limited to non-IDOR findings.
4. Confirmed: T-035 `proof.form` is `engine-error`, and `shown_without_exploit` is 0.
5. Confirmed: routes/b2bOrder.ts returns `{cid, orderNo, paymentDue}` on success and calls `next(err)` on a throw.
6. The "own record differs" guard is insufficient; an owner anchor is needed (see the revised proposal).
7. A new short VER entry is preferable to extending VER-010 (see the revised proposal).
