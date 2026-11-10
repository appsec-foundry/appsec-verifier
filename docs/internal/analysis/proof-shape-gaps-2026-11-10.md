# Proof-shape coverage gaps (2026-11-10)

Internal analysis, not packaged. Triggered by a Juice Shop run in which no finding reached `confirmed`, and the question of which proof forms are missing generally, independent of that target.

## Principle

A finding is `confirmed` only when the code in `agent/proof.py` finds the proof its class requires in the cited steps; the model's verdict alone never counts (VER-009..VER-013).
So a class is confirmable in practice only to the extent that the manifestations its CWEs take in the wild fit the one or two proof forms the code implements.
Where a finding is selected as a runtime candidate (its CWE is in `data/verifiable-cwes.yaml`) but its real manifestation fits no implemented form, the tool promises to test it and then always returns inconclusive. Those are the gaps below.

## Implemented proof forms

| Class | CWEs selected | Proof form the code checks | Observation channel |
| --- | --- | --- | --- |
| xss | CWE-79 | `browser_check` with `executed: true` | real browser execution |
| access-control | CWE-639, 862, 863, 306, 200 | two-identity contrast on an operator resource | cross-identity response difference |
| injection | CWE-89, 943 | boolean/`operator_challenge` body-field flip with complementary controls | selectable response-body value |
| injection | CWE-94, 95, 1336, 643 | `expression_template`: fresh arithmetic evaluated to expected distinct answers | reflected computed value |
| injection | CWE-90 | `predicate_template` (LDAP) reduced to the boolean body-field flip | selectable response-body value |
| injection | CWE-78 | none specific; only the forms above | none that fits |
| path-traversal | CWE-22 | marker-file readback, plus zip-slip archive readback | pre-placed marker file |
| open-redirect | CWE-601 | 3xx `Location` to `<marker>.invalid` | redirect target host |
| ssrf | CWE-918 | hit on the loopback callback listener | out-of-band callback |
| session | CWE-614, 1004, 1275 | cookie-attribute check | response cookie flags |

The injection forms share one hard constraint: the effect must surface as a value the Verifier can select from the response body with a JSON pointer, either a data-set that flips or a reflected computed answer. Timing is explicitly rejected as insufficient on its own (`experiments.py` line 256).

## Gaps, generic

### A. Injection whose effect is authenticated state, not a body value

A login-bypass SQLi or NoSQLi returns a session token and a different status (401 to 200), not a changed data-set in a comparable 2xx response.
`injection_check` requires every cited response to share one 2xx status (`experiments.py` line 238), so an auth flip is rejected as "status changes alone do not prove injection".
Affects CWE-89 and CWE-943 in their most common critical form. Not Juice Shop specific: any injection that yields an authenticated or privileged artifact rather than a differing result set.
Missing form: the positive control yields a session/auth artifact (token, authenticated identity) that baseline and negative controls do not, stable across repeats, driven only by the predicate. The strictness of the existing form is correct and should not be relaxed; this is a second, equally strict form.

### B. Blind injection with no reflected value and no result-set channel

Blind OS command injection, blind code/eval injection, blind template injection, blind XPath: nothing is reflected and no data-set flips.
The only remaining channels are timing (rejected) and out-of-band. There is no out-of-band path wired into injection; the callback listener is reachable only from the `ssrf` class.
So these are selected and never confirmable. Blind command injection is among the most critical real-world cases.

### C. Command injection has no form at all

CWE-78 is in the catalog as "mechanism-specific" but `injection_check` has no command-injection branch.
Even non-blind command injection (stdout reflected) fits no form: `expression_template` validates arithmetic evaluation, not shell output. CWE-78 is effectively uncovered today.

### D. Out-of-band oracle is locked to one class

The loopback callback listener (`tools/callback.py`) is a general, already-safe out-of-band oracle, but `proof.py` consults it only when `cls == "ssrf"`.
Opening it as a proof channel for blind injection (a command/code/SQL payload that makes the target fetch `http://<callback>/<nonce>`) would close B and C across CWE-78/94/95/1336 and the blind half of CWE-89/943 with infrastructure that already exists and is already bounded to loopback.
This is the single highest-leverage, most general addition: one oracle, many injection types.

### E. Second-order injection

Inject through one request, observe the effect through another (stored SSTI, second-order SQLi).
The injection forms cite probes on one route and method; a write-then-observe chain across routes is not modeled. Narrower than A–D, listed for completeness.

## Not gaps, by deliberate scope

Classes absent from `data/verifiable-cwes.yaml` (XXE CWE-611, insecure deserialization CWE-502, CSRF CWE-352, mass assignment, SSRF to metadata) are reported static-only and never selected. Adding them is a scope decision, separate from closing the forms above.
The access-control forms are complete; their friction is setup (an operator-declared test resource for missing-authn and information-exposure, a preparation request for IDOR), not a missing form.

## Ranked additions

1. Out-of-band oracle for injection (gap B, C, D): widest coverage, reuses the callback listener, keeps the data-never-leaves rule because only a nonce returns.
2. Auth-artifact form for injection (gap A): closes login-bypass SQLi and NoSQLi, the most common critical injection shape.
3. Command-injection form (gap C): once the out-of-band oracle exists, CWE-78 rides on it; a reflected-stdout form is a smaller add on top.

Each is a new proof class or form and changes what a `confirmed` verdict can rest on, so each needs an agreed requirement before code (VER-009..VER-013 are the entries it touches).
