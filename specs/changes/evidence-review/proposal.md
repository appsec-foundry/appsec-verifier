---
reason: Give every tested finding bounded feedback on whether its recorded evidence is understandable.
affected_ids: [VER-042, VER-015, VER-016, VER-019, VER-020, VER-035]
compatibility: Add optional presentation-review data to results; retain technical verdicts and existing host defaults.
verification: Offline reviewer and revision fakes, host schema and isolation tests, multi-variant bounds, report and console tests, full offline suite and lint.
---

The user approved VER-042 and its first stage, requested implementation on main and asked for review progress in the console. One initial review and at most two corrections apply to a finding together with all its variants. Each correction is followed by review, for at most five additional model calls per finding, within the existing run budget. Repeated issues without progress stop earlier.

The reviewer receives bounded, redacted recorded excerpts and deterministic layout observations through the selected model profile. No image pixels are sent, no new provider is selected and no target requests are permitted in the correction loop. Image inspection by a model is explicitly not performed. The original test agent may propose an explanation and focus on an existing excerpt; proposals cannot change the technical verdict or manufacture evidence. Live model spending was not authorized for implementation validation.
