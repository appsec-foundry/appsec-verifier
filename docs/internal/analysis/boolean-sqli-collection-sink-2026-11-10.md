# Boolean SQLi proof fails on a collection/search sink (Juice Shop product search)

Run: `verify` against Juice Shop `/rest/products/search`, finding T-004 (critical, injection), variants 001 and 002.
The weakness is real and the agent reaches it, yet both variants end inconclusive.
The cause is on the Verifier side, not the target.

## What the run showed

Sink (`juice-shop/routes/search.ts:23`): `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`.
The injection point sits inside `name LIKE '%...%'`, wrapped in two parentheses and followed by the `OR description` clause, on SQLite.

Variant 001 used the template from the prompt example, `known' AND {{predicate}} -- `.
The single-line `-- ` comment removed the two closing parens, so the query became incomplete: steps 6 and 8 returned HTTP 500 `SQLITE_ERROR: incomplete input`.
The agent diagnosed this correctly in the plan revision at step 9, but was stopped at step 10 by the repetition allowance (`stagnation`) before it could send a balanced template.

Variant 002 balanced the parentheses (`x%' AND ({{predicate}})) -- ` style) and produced a clean boolean oracle:
`(397515=397515)` and `(402298<>397515)` returned 878 B, `(397515=402298)` and `(402298<>402298)` returned 30 B, each repeated twice.
That is the confirmed vulnerability. It was rejected at step 13 with `the declared JSON observation is missing or incomplete`.

## Why the proof layer rejected a genuine oracle

`agent/experiments.py:injection_check` does not look at status or body size.
It requires all cited responses to be 2xx (so variant 001's 500 can never prove anything) and reads a declared RFC-6901 pointer value from each body, then enforces:
`baseline == positive == positive_other`, nonempty, and `negative == negative_other != positive`, each stable across repeats, none reflecting the input.

Two properties of a search/collection sink break this model:

1. The natural true/false signal is empty vs. nonempty result set.
The false branch is `{"status":"success","data":[]}`.
A pointer into a result element (`/data/0/...`) does not resolve there, so `pointer_value` raises and the proof is rejected as `missing or incomplete` (`experiments.py:314`).
The pointer that would work is the container `/data` (`[]` vs. filled), but nothing steers the model there.

2. `injection_check` line 316 requires the true condition to reproduce the baseline.
Here the clean baseline `q=x` returned 6585 B while the true-injection returned 878 B, because the balancing payload comments out the `OR description LIKE` clause and so matches a smaller set.
On this sink the injected true-branch cannot reproduce an uninjected baseline at the collection level, so even `/data` fails line 316.

## Contributing friction (not the decisive cause)

`plan_test` schema: the model first sent `input_location: query` (the enum is `params`, `json`, `form`, `path`) and omitted the required `hypothesis`.
Variant 001 steps 2 and 3 were spent on these two schema errors (~0.23 USD) before any probe.

Repetition allowance: in variant 001 the model had just identified the fix and was cut off mid-repair.
The allowance counts the identical cited requests (steps 6 and 8) and does not credit a template revision that follows a plan revision.

## Candidate changes

Each is a proposal, not an applied change.
The proof-acceptance change alters what counts as confirmed (VER-009..013) and needs an agreed requirement before any code.

1. Proof model for collection sinks (decisive).
Let a boolean SQL proof use the result set's shape as the observation: nonempty vs. empty `/data` (or a declared container pointer), and define the baseline as the injected true-branch rather than the uninjected request, so `baseline == positive` holds by construction.
This is the change that would let this finding confirm.
Draft the requirement wording first.

2. Pointer steering in the prompt.
Tell the model that for a list/collection response the observation should point at the container (presence/emptiness), not at an element that vanishes in the false branch.
Prompt wording and messages only; likely no new requirement, but it does not help until change 1 relaxes the baseline rule.

3. `plan_test` ergonomics.
Accept `query` as an alias for `params`, or return a hint naming the valid enum and the querystring case; make the `hypothesis` requirement visible in the error.
Clearer tool messages/schema; confirm whether this counts as a feature.

4. Repetition allowance after a plan revision.
Do not let an accepted plan revision be immediately starved by the prior template's repetition count, so a model that correctly diagnoses a syntax problem gets at least one balanced retry.
Touches a code-enforced limit (VER-010/-036); needs a maintainer decision, with a test for the refused case.
