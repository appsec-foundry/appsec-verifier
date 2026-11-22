# Handover: access-control proofs, a step reserve and per-call cost shares (2026-11-22)

This continues the cross-check in `run-144-access-control-proof-gap-2026-11-22.md`, whose status lines ("no code changed") are outdated. Everything below was verified offline against the code at c441a36 or measured in the named runs; open items say what is not verified.

## Done on main

| Commit | What it changed |
| --- | --- |
| 9cdfb36, 37679dc | VER-067: prove a read of a record an account already has, by its user name, in safe mode. |
| 18b09db | `derive_request` cited with a search step says to read the declaring file with `read_source` and cite that step. |
| 93f5951 | A derivation refused for an input its evidence does not show says to derive the request without it, where the request alone would be accepted. |
| b7357b2, 3e8e885 | VER-067 extended: a record is the owner's also when the owner's GET of its collection lists its id and the other account's GET of it does not hold it; any 4xx except 401, 407, 408, 429 counts as refused when the other account gets its own record. Works for accounts without user names; the test plan offers it in safe mode where a named GET has a collection. Proof form `listed-record`. |
| a3c8229 | A rejected access-control verdict gets `needs` in proof_feedback: every request its proof form cites. A negative verdict that cites a non-request step or a step before its plan is refused with the requests to cite. |
| 0b1da35 | Existing-record image: the other account's own list and record show as allowed normal requests, not refused controls. |
| c441a36 | Console and images use the report's colours, seen from the application: red confirmed, green blocked or not reproducible. Marks `!` confirmed, `⊘` blocked, `○` not reproducible. A blocked comparison image is headed with what was refused. |

## Runs and what they show

All runs are T-010, T-002 or T-042 of `/home/mrohr/assessments/juice-shop-std3` against the local Juice Shop, with `--account jim@juice-sh.op` (account-1), `--account bender@juice-sh.op` (account-2) and an admin account.

| Run | Result | Meaning |
| --- | --- | --- |
| 146 | 6 inconclusive | VER-067 by user name chosen everywhere; card and basket name no user name; T-042 found no own record; cost limit 10 gave $2.50 per finding. |
| 147 | T-042 v2 inconclusive | 18b09db worked (search step, then read_source server.ts:381); next refusal was the undocumented input `message`, fixed in 93f5951 (not yet seen live). |
| 149, 150 | T-002 inconclusive | Juice has no basket list (`GET /rest/basket` answers 500); basket stays unprovable. |
| 151, 152, 153 | T-010 inconclusive | List anchor works on Juice (cards 5 and 6, 400 for the other's card); proof incomplete: feedback named one gap per round, a variant gets two repairs, and steps ran out. Led to a3c8229. |
| 155, 157, 158 | T-010 blocked-by-control | With a3c8229 one feedback round suffices. 155 and 158 needed 15 to 16 steps (plan at step 6 to 7 after source reading), 157 fitted in 12. |
| 154, 156, 159 | inconclusive after 5 model calls | Not a step limit: the first agent call failed with `host_error (exit 1)` and technical QA with `error_max_budget_usd`. See open issue 2. |

A measurement on the local Juice Shop (login and GETs only, done by the maintainer with a read-only script) showed: the sign-in answer names `bid` (account-1 2, account-2 3); `GET /rest/basket/2` returns account-1's basket identically to account-2; `/api/Cards` and `/api/Addresss` list only the caller's records, `/api/Users`, `/api/BasketItems` and `/api/Complaints` list the same for both. Identifiers from the sign-in answer were rejected as an ownership anchor: `bid 2` matched `/api/Users/2` just as well, so they are not bound to a collection.

## Open decision 1: a step reserve where a proof is close (VER-015)

Across 263 variant runs (Juice and DVWA logs), about a third of every class ends inconclusive with its steps used up, but most of those never reached a checkable proof; raising `--max-attempts` for everyone would mostly lengthen hopeless attempts and, in serial intrusive runs, the 30-minute limit. 19 variants were rejected by the proof check right at the limit (verdict at the last step, or feedback with two steps or fewer left), 15 of them under an accepted test plan: T-010 four times (provable, see 155, 157, 158), T-042 v1 twice (plausible), the Juice basket three times (not provable), DVWA T-032 and T-002 (unclear). The maintainer prefers more steps only where sensible.

Proposed wording, an added sentence in VER-015, not yet approved: "A test agent whose verdict under an accepted test plan fails its proof check with fewer than four steps left gets up to four further steps once per finding variant to act on the proof feedback; this reserve belongs to the documented per-finding attempts bound and counts against every other limit."

Cost: at most four more model calls (about $0.15) for about 6 % of variants; requests stay within mode and limits. The repair condition sits in `agent/loop.py` where proof_feedback is built (`repairs < 2 and decision < self._max_steps`); a verdict at the last step currently gets no feedback at all. `docs/specification.md` describes `--max-attempts` in the flag table and under Continuous control.

## Open issue 2: per-call cost shares cap sequential calls (limits.py)

`RunBudget.model_slot` (35cbfa1, bfdcff8) gives a capped call (Claude CLI, `--max-budget-usd`) a share of five times the dearest call so far once three calls reported a cost and the free budget covers two shares. The condition does not require another call in flight, so a run testing one finding caps every later call too, although the comment says "while others run beside it". The dearest call is learned from the cheap calls before testing (model test $0.003, the login-field proposal) and from steps that hit the prompt cache.

Reproduction: `RunBudget(Limits(cost_limit_usd=30.0))`, three capped calls costing 0.003, 0.0004 and 0.0069, then a fourth call with nothing else running gets `call_allowance()` 0.0345, passed to the CLI as `--max-budget-usd 0.03` with $29.99 left. A QA review costs about $0.039 and a step without a cache hit more than $0.01, so the CLI stops them. This explains 154, 156 and 159 (5 model calls, then inconclusive) and why 155, 157 and 158, with the same command, ran through. Parallel safe-mode runs (four findings by default) are likely hit more often.

Directions to evaluate, possibly with a revision of VER-065 or VER-015: give a share only while another call is in flight; keep the pre-flight calls out of the dearest; give the share a floor, or bound a call from its prompt length, the model's prices and its output limit instead of from earlier calls; replay recorded parallel runs to check that no call exceeds its share. Not known: why the failed step calls report `host_error` instead of `budget_exhausted`; the CLI's error text is not recorded in `failed-findings.json`.

## Other findings, not acted on

- Proof checks accept cited reads sent with `prerequisite: true`, in every proof form, although VER-047 says a prerequisite read is never a proof (seen in 149 and 158). A fix would apply to all forms.
- Technical QA, reviewing an early verdict, asked twice for the source of `appendUserId` (152, 153), which cost three to four steps without bearing on the access proof. A QA prompt change is possible but unverified.
- VER-008 refuses deriving a route from a file that is neither the finding's evidence nor a recorded local import: T-010's `POST /api/Cards` in `server.ts`, and DVWA T-044 and T-045 in four and seven runs. Needs a decision on the VER-008 wording.
- The list anchor reads JSON lists only; an HTML "my orders" page gives no anchor.
- The Juice basket (T-002) stays inconclusive; only a `test_resources` entry proves it without risk.
- 93f5951 (derive without undocumented inputs) has not yet been seen in a live run; T-042 variant-002 (complaints) is the case to watch.

## How to continue

- Targeted runs: `appsec-verifier verify --assessment /home/mrohr/assessments/juice-shop-std3/security-assessment.yaml --url http://127.0.0.1:3000 --source /home/mrohr/juice-shop --output /tmp/<n> --only T-010 --cost-limit 30 --profile claude --account jim@juice-sh.op=VERIFIER_JIM_PASS --account bender@juice-sh.op=VERIFIER_BENDER_PASS --admin-account admin@juice-sh.op=VERIFIER_ADMIN_PASS --overwrite --annotate --show-costs --non-interactive --yes`, without `--allow-intrusive` for the list proof; add `--max-attempts 16` until the reserve exists.
- The replays behind a3c8229 and 3e8e885 are encoded in `tests/test_existing_record.py` (run 153 sequence, card fixture with 400 refusals, lists alike for both accounts) and `tests/test_own_access.py` (request lists per proof form).
- Per AGENTS.md (76e4b96): state prompt and tool-result growth per change; the step reserve adds no prompt text.
