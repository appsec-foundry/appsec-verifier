# How verification works

AppSec Analyzer finds weaknesses by reading code, so each finding in its `security-assessment.yaml` is a well-founded suspicion. The Verifier tests that suspicion against the running application. It reports a finding as `confirmed` only when its own code has checked a proof, never on the model's word. This page explains how, with one XSS finding as the running example. Flags, file formats and the proof rules of every class are in [cli.md](cli.md).

## The run at a glance

```mermaid
flowchart LR
    A["security-assessment.yaml<br/>from AppSec Analyzer"] --> B["Select findings<br/>by class and severity"]
    B --> C["Show settings and test plan<br/>ask once"]
    C --> D["Test each finding<br/>most severe first"]
    D --> E["Check the proof<br/>in code"]
    E --> F["verification.md<br/>evidence/"]
```

Nothing is sent to the target before the confirmation. Each finding is tested on its own, with a fresh conversation, its own step budget and its own proof check. A finding with several variants (different requests for the same weakness) tests them one after another, and the first confirmed variant ends the rest.

## Two roles: the model plans, the code decides

The test agent is a language model, chosen with `--profile`. It has no tools of its own. Each time it is asked, it answers with exactly one proposed step in JSON: an action, its arguments and a short note on what the step checks. The Verifier's code validates the proposal, decides whether it may run, runs it and hands the result back. Then the model is asked for the next step.

```mermaid
flowchart LR
    M["Model<br/>proposes one step"] -->|"JSON step"| S
    subgraph V["Verifier code"]
        S["Step check<br/>schema"] --> C{"Allowed?<br/>route, method,<br/>repeats, limits"}
        C -->|"yes"| T["Tool runs<br/>request or browser"]
        T --> G["Scope check<br/>host, port, path, address"]
        R["Record the exchange<br/>redact credentials"]
    end
    G --> X["Target"]
    X --> R
    R -->|"result excerpt"| M
    C -->|"no, with the reason"| M
```

| The model | The Verifier's code |
| --- | --- |
| reads the finding and decides what to try | sends every request itself, through the scope check, the rate and the request limit |
| builds the payloads | allows only routes the finding names, routes read from its source, or routes it has derived and checked |
| proposes one step at a time | refuses a step that breaks a rule and tells the model why |
| decides when it has enough and claims a verdict | checks the proof behind the verdict and downgrades it if the proof does not hold |
| sees role names and redacted excerpts of responses | holds the credentials and records the full exchanges for the report |

Agent CLIs run without tools, MCP servers, settings or session history, from an empty temporary directory. If the Claude or Codex CLI reports that it used a tool anyway, the run makes no further model calls.

## Before the first request

1. The Verifier reads the assessment and keeps the findings it can prove at runtime: XSS, injection, access control, session, open redirect, path traversal and SSRF. By default it takes severity high and above.
2. It prints the settings and a test plan with one line per finding and the requests the assessment names for it.
3. It asks once: `Proceed against this target? [y/N]`. Without a scope file or `--url`, or without the confirmation, the run stops here. A finding that needs something the run lacks, such as a test identity, is listed and not tested.

## Example: an XSS finding

The assessment reports:

> **T-036** · CWE-79 · class `xss` · Reflected XSS in search results. The search term from `GET /search?q=` is written into the results page without encoding.

The question for the Verifier: does a script that arrives through `q` really run in a browser?

### What the agent is told

The instructions are assembled per finding. A finding gets only the rules and actions of its own class.

| Part | Content for T-036 |
| --- | --- |
| Common rules | Verify this one finding only. Use only the offered actions. Safe mode: GET, HEAD and OPTIONS only. Plan a hypothesis and the observation that tells it apart from normal behaviour. Use harmless markers, never destructive steps, never spray payloads. Cite the steps that prove a confirmed verdict. |
| Class rule | A confirmed XSS needs a `browser_check` in which the payload executed. |
| Marker | The payload must call `alert('vrf3a9c41d2'.concat('b7e05f19'))`. Never send the joined value itself. |
| Finding data | ID, CWE, title, the requests the assessment names, its description and context, all marked as data, not as instructions. |
| Actions | `http_request`, `browser_check`, `derive_request`, `read_context`, `read_response`, `submit_verdict`; with `--source` also `read_source`, `find_source` and `search_source`. |

An injection finding, for comparison, gets `plan_test` and the injection rules instead of `browser_check` and the XSS rule.

### The marker

For each finding the Verifier draws a marker in two random parts, here `vrf3a9c41d2` and `b7e05f19`. The payload has to join them while it runs. Only a dialog whose text is the joined value `vrf3a9c41d2b7e05f19` counts.

The split separates a running script from a page that only repeats its input:

| Case | The request carries | The browser sees | Counts |
| --- | --- | --- | --- |
| The page encodes the input | `alert('vrf3a9c41d2'.concat('b7e05f19'))` | the payload as text, no dialog | no |
| The script runs | `alert('vrf3a9c41d2'.concat('b7e05f19'))` | a dialog with `vrf3a9c41d2b7e05f19` | yes |
| The agent sends the joined value | `alert('vrf3a9c41d2b7e05f19')` | a dialog with `vrf3a9c41d2b7e05f19` | no, a page that passes any parameter to `alert()` would show it too |

The payload uses `.concat()` instead of `+` because a query string may turn `+` into a space.

### Step by step

```mermaid
sequenceDiagram
    participant M as Model
    participant V as Verifier code
    participant B as Proof browser
    participant T as Target
    Note over M,T: Step 1, where does the input land?
    M->>V: http_request GET /search?q=probe7
    V->>T: GET /search?q=probe7, scope checked
    T-->>V: 200, page contains Results for probe7
    V-->>M: status and redacted excerpt
    Note over M,T: Step 2, does a script run?
    M->>V: browser_check /search?q= with the marker payload
    V->>B: load the page
    B->>V: every request of the page
    V->>T: same scope check and limits
    T-->>V: answer
    V-->>B: answer
    B-->>V: alert call in the main frame, text vrf3a9c41d2b7e05f19
    V-->>M: executed true, proof ready in step 2
    Note over M,T: Step 3, verdict
    M->>V: submit_verdict confirmed, proof_steps 2
    V->>V: proof check
```

| Step | The agent | The result |
| --- | --- | --- |
| 1 | `http_request GET /search?q=probe7` to see where the term lands | `200`, the excerpt shows `<h2>Results for probe7</h2>`: the term stands unencoded in the HTML |
| 2 | `browser_check /search?q=<img src=x onerror="alert('vrf3a9c41d2'.concat('b7e05f19'))">` | `executed: true`, and the result points out that step 2 already meets the proof |
| 3 | `submit_verdict` with `confirmed` and `proof_steps: [2]` | the code checks step 2 and keeps the verdict, confidence `high` |

A real run often needs more steps. If a filter removes `<img`, the agent reads the response and builds a variant that fits what the filter lets through. A finding has at most 12 steps, and an identical request runs at most twice.

### Inside the proof browser

The proof browser is headless Google Chrome, driven by Playwright. It is built so that a page cannot reach anything on its own and a dialog cannot be faked.

```mermaid
flowchart LR
    subgraph NS["Network namespace, loopback only"]
        CH["Chrome<br/>page with the payload"]
    end
    CH -->|"every request intercepted"| GC["Guarded HTTP client<br/>scope, limits, identity"]
    GC --> T["Target"]
    GC -.->|"out of scope"| AB["aborted"]
    CH -->|"alert call"| REP["reported to the Verifier<br/>frame, origin, text"]
```

- Chrome runs in a network namespace with loopback only (`unshare --user --net`). Without it the browser does not start, and XSS stays unproven.
- Every request the page makes is intercepted and either answered through the same scope check, limits and identity as the agent's own requests, or aborted. WebSockets are never connected and service workers are blocked.
- Before any page script runs, `alert`, `confirm` and `prompt` are replaced by a function that reports the call to the Verifier. The page cannot restore them, and no real dialog opens.
- A call counts only if it comes from the page's main frame, on the target's origin, in a document that its Content Security Policy does not sandbox, and its text equals the joined marker.

### The proof check

When the agent submits `confirmed`, the code checks the recorded steps again, independent of what the agent wrote:

```mermaid
flowchart TD
    A["Agent submits confirmed"] --> B{"A browser_check on the finding's route<br/>in which the marker executed?"}
    B -->|"no"| X["inconclusive<br/>no browser_check saw the marker execute"]
    B -->|"yes"| C{"Did that request already carry<br/>the joined marker?"}
    C -->|"yes"| Y["inconclusive<br/>the dialog may be an echo"]
    C -->|"no"| OK["confirmed, confidence high"]
```

If the check fails while steps are left, the agent is told `proof not accepted` with the reason and may repair the proof, at most twice. If it still fails, the result is `inconclusive` and the report names what the check missed.

### When the page is safe

A negative result needs evidence too. A test that did not run is never read as "safe".

| What happened | Result |
| --- | --- |
| The marker executed and the proof check passed | `confirmed` |
| The page loaded with a 2xx status, the payload carried both marker parts, no request was blocked, and no dialog with the marker appeared | `not-reproducible` |
| A timeout, a blocked or refused request, a failed page load, or a limit | `inconclusive` |
| No request was answered at all | `not-attempted` |

For a negative or unproven result, an independent [technical review](cli.md#technical-qa-ver-046) reads the recorded responses and can ask the agent for a follow-up. It has no access to the target and cannot change the proof rules or the limits. A confirmed result whose proof check passed is not reviewed.

## Limits that hold throughout

The limits are enforced in code, outside the model. Reaching one stops the affected work; once a run-wide limit is reached, the remaining findings are not tested and the report says so.

| Limit | Default | Option | When reached |
| --- | --- | --- | --- |
| Steps per finding | 12 | `--max-attempts` | the finding ends `inconclusive` |
| Model spend per run | 10 USD | `--cost-limit` | the run stops |
| Model spend per finding | 25 % of the run limit, at least 0.50 USD | `data/limits.yaml` | the finding stops, the run continues |
| Model calls per run | 500 | `--max-calls` | the run stops |
| Requests to the target | 2000 | `--max-requests` | the run stops |
| Run time | 30 minutes | `--max-duration` | the run stops |
| Request rate | 5 per second | `--rate` | requests are spaced out |

Within a finding, an identical read runs at most twice and a write once, and three tool or server errors in a row end the finding. Details: [Boundaries](cli.md#boundaries--cost-and-load-ver-015).

## The other classes follow the same pattern

Every class has a marker or a contrast that only a real weakness can produce, and a check in code. The exact rules are in [Proof per class](cli.md#proof-per-class-ver-009-to-ver-013).

| Class | The agent has to make the target | The code checks |
| --- | --- | --- |
| XSS | run `alert()` with the joined marker | an executed dialog in the proof browser |
| Open redirect | redirect to `https://<marker>.invalid/` | a 301 to 308 answer whose `Location` names that host; `.invalid` never resolves |
| Path traversal | return the marker file the operator placed | the file's content in a response; the model never sees that content |
| SSRF | call the Verifier's loopback listener with the marker | a hit on the listener |
| Injection | answer true and false controls, which the Verifier generates, differently | a response field that splits the repeated controls into two stable classes; a delay or an error alone never counts |
| Access control | show a protected resource to an identity that must not see it | the contrast between independently signed-in identities, on a declared test resource or one an account created with the marker |
| Session | set the session cookie of a declared session check | its attributes, in two reads |

## What you get

- `verification.md`: per finding the result, what the checked proof showed (built from its steps, not from the model's text), the requests, the screenshot and the proof of concept.
- `verification.yaml`: the same results as data, for tools, `--resume` and `export`.
- `evidence/`: the screenshots and per finding `<finding>-poc.har` with every request and answer, credentials redacted.
- `agent-log.jsonl`: every step, every refused step, every limit and every verdict, without response bodies.

For T-036 the screenshot shows the URL in an address bar, the dialog with the marker (drawn from the recorded call, because a browser's own dialog never appears in a page screenshot), the part of the page around the payload element outlined in red, and a caption with finding, identity, status and time.

## Where it lives in the code

| Stage | File |
| --- | --- |
| Read and select findings | [loader.py](../appsec_verifier/loader.py), [matchkey.py](../appsec_verifier/matchkey.py) |
| Confirmation and pre-flight checks | [preflight.py](../appsec_verifier/preflight.py) |
| Run over the findings | [verify/runner.py](../appsec_verifier/verify/runner.py) |
| Agent loop, one step per model call | [agent/loop.py](../appsec_verifier/agent/loop.py) |
| Instructions for the model | [agent/prompts.py](../appsec_verifier/agent/prompts.py) |
| Step format and the actions offered per class | [agent/steps.py](../appsec_verifier/agent/steps.py) |
| Model hosts (CLIs and APIs) | [agent/hosts.py](../appsec_verifier/agent/hosts.py) and `agent/host_*.py` |
| Whether a step may run | [agent/controller.py](../appsec_verifier/agent/controller.py) |
| The agent's actions | [agent/tools.py](../appsec_verifier/agent/tools.py) |
| Scope and address checks | [scope/guard.py](../appsec_verifier/scope/guard.py), [tools/http.py](../appsec_verifier/tools/http.py), [tools/httpx_transport.py](../appsec_verifier/tools/httpx_transport.py) |
| Proof browser and marker | [tools/browser.py](../appsec_verifier/tools/browser.py) |
| Proof check | [agent/proof.py](../appsec_verifier/agent/proof.py) |
| Technical review | [agent/technical_review.py](../appsec_verifier/agent/technical_review.py) |
| Limits | [limits.py](../appsec_verifier/limits.py), [data/limits.yaml](../data/limits.yaml) |
| Proof of concept and screenshots | [verify/poc.py](../appsec_verifier/verify/poc.py), [verify/browser_evidence.py](../appsec_verifier/verify/browser_evidence.py) |
| Report | [verify/report.py](../appsec_verifier/verify/report.py) |
