# Genericity review: handoff (2026-11-12)

Handoff for later sessions. The maintainer asked whether the Verifier's rules were tuned to Juice Shop, whether the test agent has enough latitude where it matters, and whether findings without a fitting proof form can still be verified. This file records what an offline review against non-Juice assessments showed, what was changed in `42dc88d` and `9f6d2fa`, and what is still open.

## Sources

- Assessments: `/home/mrohr/assessments/DVWA` (PHP), `/home/mrohr/assessments/VulnerableSpringApp3` (Spring Boot, Thymeleaf), `/home/mrohr/assessments/juice-shop-std3`, plus the Juice Shop runs in `/home/mrohr/thorough`, `/home/mrohr/standard` and `/home/mrohr/appsec-reports/*`. Every earlier `verify` run had been against Juice Shop.
- Sources: `/home/mrohr/DVWA`, `/home/mrohr/vulnerable-spring-app`, `/home/mrohr/juice-shop`, `/home/mrohr/insecure-python-app` (FastAPI-style `@api.get`, Django `path()`), `/home/mrohr/VulnerableApp` (Spring).
- The Analyzer's `data/pentest-eligible-cwes.yaml` as the reference for which CWEs are dynamically testable.
- Method: `appsec_verifier.loader.load_plans` on an assessment, `SourceReader(repo).read_window(file, line)` to see what the agent sees, and the derivation and proof functions called directly. Nothing contacted a target and no model was called.
- Checks after the changes: `ruff check .` clean, `python3 -m pytest -q` outside the Bash sandbox 1956 passed, 2 skipped.

## Agreed principle

Latitude in finding, strictness in proof. Where a wrong guess only costs budget (which route, which input, which observation), the model proposes and the code checks a recorded, framework-neutral piece of evidence. What counts as `confirmed` stays a code check (VER-009 to VER-013), with scope, marked writes and budgets unchanged. Measures are judged on the non-Juice assessments before they are implemented.

## What the review found

| Area | Observation | Measured | Status |
| --- | --- | --- | --- |
| CWE positive list | A finding is tested only when its exact CWE is in `data/verifiable-cwes.yaml` | unsupported: DVWA 41 of 73, Spring 26 of 43, Juice Shop 59 of 110; most of them static (hard-coded secrets, hashing, crypto) | partly addressed, see open items |
| CWE drift in the Analyzer | One weakness gets different CWEs in different runs | Juice Shop authentication-details: 200, 213, 285, 639, 862, 863; data-erasure file read: 22, 73; deluxe upgrade: 20, 285, 840, 841, 862 | `9f6d2fa`: CWE-285, 23 and 73 take their class's proof |
| Findings without a request | `endpoints.py` took only `METHOD /path` from the text; source routes were read in Express syntax; a Spring route lost its class-level prefix; PHP has no route declarations | routeless: DVWA 30 of 32, Spring 8 of 17, Juice Shop 9 of 51; Spring derivations that matched the named request: 0 of 9 | `42dc88d`: URL with query as GET, framework-neutral declarations with prefixes (Spring now 9 of 11, routeless with the right route 5 of 8, Juice Shop unchanged), VER-056 file-path rule (applies to 27 of 28 routeless DVWA findings; 16 tie offline through a form or link, up to 26 depending on runtime answers) |
| Injection observation | Boolean, arithmetic and negative injection proofs read only a JSON pointer | server-rendered apps could not confirm command, template or boolean SQL injection, nor reach a negative verdict | `42dc88d`: VER-055 text and whole-number observation in page answers |
| Engine errors | Microsoft SQL Server, H2 and Db2 syntax errors were not recognised | | `42dc88d` |
| Access control in safe mode | With two normal accounts and neither a `test_resources` entry, writes nor a privileged account, no access-control proof is available (`access_methods`) | the largest supported class (CWE-639, 862, 863: 20 to 28 findings per app) | open |
| Tool capabilities | The agent cannot send custom headers, XML or raw bodies, or multipart uploads | JWT (CWE-347) 5, XXE (CWE-611) 5, upload (CWE-434) 4 findings across the three apps | open, each a safety decision of its own |
| Command injection | `plan_test` accepts only `<baseline>; printf '%s' "$((…))"` | one CWE-78 finding per app | open |
| Recording limit | 64,000 characters per answer, 256,000 per finding | an experiment of ten answers on pages above about 25 KB ends truncated and inconclusive | known limit, stated in the README |
| Automatic source route | The controller's route from reading the evidenced file (`Controller.observe`, docs/cli.md "Continuous control") still reads Express syntax | other frameworks reach the same route through `derive_request` | optional alignment |
| Separate routing files | Django `urls.py`, Laravel and Rails route files are not reachable from the finding's file | | open |

The prompts themselves carry no Juice Shop specifics; the narrowness sat in recognition code, proof forms and the CWE list. The injection prompt is close to its size bound in `tests/test_hosts.py`, raised from 21,000 to 21,250 characters for VER-055 (the prompt is about 21,180).

## Changes made

- `42dc88d` agent+verify: requests and proofs beyond Express and JSON (VER-008, VER-053, VER-055, VER-056). Requirement entries VER-055 and VER-056 are new; VER-044 and the proof invariant in AGENTS.md name the text observation.
- `9f6d2fa` data+endpoints: CWE-285 joins access control (with the owner's preparation routes), CWE-23 and CWE-73 join path traversal; VER-006 also lists CWE-94 and CWE-95. CWE-77 and CWE-917 stay unsupported: the only CWE-77 finding is a CI workflow, no assessment holds a CWE-917, and the engine-error tokens do not cover expression-language errors.

## Open items

Each needs a requirement proposal and the maintainer's approval of its wording before code (AGENTS.md).

| Item | Assessment in this session | Next step |
| --- | --- | --- |
| Indicative path for unsupported but pentest-eligible CWEs (verdict at most `inconclusive`, labelled as model-assessed) | Not recommended now: of 34 such findings in the three apps (DoS excluded) about 7 have something the current tools can observe | revisit once headers or XML bodies are available |
| Mass assignment (CWE-915) | the most frequent unsupported dynamic weakness: 10 findings across all three apps | not drafted in this session; needs a design and a maintainer decision |
| Access control in safe mode with two normal accounts | see the table above | not drafted in this session; needs a design and a maintainer decision on VER-010 |
| Further separators in the command template | small; changes what the Verifier sends | requirement text |
| XML request bodies, `Authorization` header chosen by the agent | would open XXE and JWT findings | one safety decision each |
| Routes in separate routing files (Django, Laravel, Rails) | the finding's file holds no route | design an evidence rule from the routing file to the handler |
