# Assessment handoff and bounded proof extensions

The maintainer requested the Analyzer handoff follow-up and chose direct work on `main` for this change. Existing route selection is repaired under VER-005 and VER-008. Explicit requests and resolved route references suppress unrelated source-location matches; unresolved findings retain the established fallback. Resource preparation remains a separate decision.

The maintainer explicitly approved the wording of VER-044 and VER-045 in the conversation before their implementation, together with the stated effects: later target requests, write access for uploads, possible model cost and the simpler alternative of leaving these methods unsupported. This approval authorizes local implementation and offline verification; it does not authorize a live run. The approved wording is recorded in `requirements.md`.

## Path input proof

Path inputs use the existing operator literal-data contract and fresh mechanism-specific controls. Exactly one whole-segment placeholder is bound, only that value is encoded, and the guarded transport checks the resulting URL. The controller and proof checker retain the declared template and compare fixed identity and other inputs. Tests run real SQLite queries in memory: concatenation confirms, parameter binding does not. Encoded separators remain refused. NoSQL operator controls still require JSON input; this extension does not establish a path proof for Juice Shop T-031.

## Archive upload proof

The operator declares an evidenced POST upload, multipart field, isolated extraction directory and HTTP mapping to its parent, with an optional cleanup endpoint. The model chooses only a declared check and a role. The generated ZIP has one stored entry `../<finding-marker>.txt` or `../<finding-marker>.md` with a fresh harmless value, no arbitrary contents or paths. A 404/410 baseline, successful upload and exact value at the declared outside location establish the bounded proof. The directory mapping is an operator-supplied premise; HTTP alone cannot discover the server filesystem layout.

The proof retains the exact generated entry, harmless content and archive hash so the input can be reconstructed. The probe validates every destination before starting and uses the existing guarded HTTP client for every request. Scope, authorization window, credentials, request and time limits apply. Safe/read-only mode, scope denial of state changes, privileged identities, other findings and unevidenced upload routes are refused. The upload-attempt record is set before the write; a timeout or a new tool instance cannot cause an automatic retry. Cleanup is one declared POST plus an absence check; missing, failed or interrupted cleanup remains visible in the final proof and observations. The operator reconciles remaining markers before another run. Other archive formats and deeper traversals are unsupported.

## Existing state-change proof

The inspected Verifier already implements VER-010 create/change/read proofs for operator-owned resources with two normal identities and a second marker, independently of runtime variants. This follow-up does not add an implicit workflow across variants or widen that resource boundary. Existing own-resource and proof tests remain applicable.

## Validation

The route-only saved-evidence replay uses `/tmp/appsec-verifier-handoff-replay.py` and the unchanged Juice Shop assessment. T-050 resolves only to `PUT /api/Products/:id`, with no SecurityQuestions hints; T-036 retains both named file routes. This is endpoint resolution, not runtime exploitation.

The final full offline suite passed with 1,535 tests and two skips. The skipped Analyzer annotation-schema comparison was separately enabled with `APPSEC_VERIFIER_ANALYZER_SCHEMA=/home/mrohr/appsec-analyzer/schemas/threat-model.output.schema.yaml` and passed; the live browser module remains skipped. The `.md` marker extension and scope declarations also passed six focused checks after the full-suite collection. Ruff and diff/Markdown-link checks passed. An earlier sandbox suite blocked in subprocess tests and was terminated; it is not counted as successful. The final suite ran outside the sandbox with offline transports and planners.

All implementation changes are uncommitted on `main` in `/tmp/appsec-verifier-main-delivery`, based on `7ddcdbe`. A separate checkout of the same branch was necessary because another session switched `/home/mrohr/appsec-verifier` to `injection-without-contract` during this work. That shared checkout was not used to deliver the proof extensions.

 Live target contact, real model calls, a fresh Analyzer assessment and the Analyzer golden replay are outside this local implementation. The original ignored `_last-run` golden fixture is absent.
