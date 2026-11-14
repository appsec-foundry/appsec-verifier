# Priority 1 CWE mapping review

Reviewed the six assessment YAML exports in the local AppSec Analyzer examples checkout against the Verifier positive list. Counts below are finding occurrences across exports, including repeated project reports, not vulnerability prevalence. No target was contacted and no assessment body was sent to a model; inspected metadata was limited to CWE, finding ID and title.

| CWE | Occurrences | Assessment examples | Decision |
| --- | ---: | --- | --- |
| CWE-209 | 3 | DVWA T-003 and DVWA2 T-006: database/PHP error disclosure | No blanket alias to access control: inducing and classifying an error is not equivalent to a declared protected resource read. Existing injection engine-error proof addresses a different claim. |
| CWE-489 | 1 | DVWA T-045: debug CAPTCHA backdoor | No alias: this is a CAPTCHA bypass, not simply exposed management content. |
| CWE-532 | 4 | DVWA workflow secret logging; Juice Shop T-102 browsable access logs | The log-download case resembles exposure, but workflow logging does not. Keep the broad CWE unsupported until an explicit subtype and matching proof contract are agreed. Never fetch real log contents merely to establish the mapping. |
| CWE-915 | 16 | User API mass assignment and registration role assignment | Do not treat writable fields as a proven authorization bypass. These require controlled state changes and an independently observed unauthorized effect. Outside this change. |

The review found no whole-CWE addition justified by the existing proof contracts. The positive list remains unchanged. Priority 1 improves existing exposure and access-control forms; it does not implement new finding classes or automatically reinterpret unsupported findings.
