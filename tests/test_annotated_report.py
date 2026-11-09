"""The Analyzer's report with the verification results (VER-038): placement, summary, changelog, figures."""

from __future__ import annotations

import os

from appsec_verifier.verify import annotated_report
from appsec_verifier.verify.annotated_report import annotate_report, copy_figures, write_annotated_report
from appsec_verifier.verify.report import annotate_assessment

REPORT = """# Security Assessment Report - App

## Changelog

_Append-only history of assessment runs. Most recent first._
| Version | Date | Scan | Model | Δ Threats | Note |
|--------|------|------|-------|-----------|------|
| v1 | 2026-11-03 12:42 CET | full · standard | sonnet | 4 total | first full scan |

---

## Table of Contents

- [Management Summary](#management-summary)

## Management Summary

Text.

## 8. Findings Register

### 🔴 Critical (2)

<a id="t-001"></a><a id="f-001"></a>
#### F-001 · Stored XSS

**Severity:** 🔴 Critical

```python
# a comment that looks like a heading
x = 1
```

**Fix:** escape output.

<a id="t-002"></a><a id="f-002"></a>
#### F-002 · SQL injection

**Severity:** 🟠 High

### 🟡 Medium (1)

<a id="t-003"></a>
#### F-003 · Open redirect

Text 3.

## 9. Abuse Cases

The end.
"""


def _result(n, verdict, **extra):
    return {"result_id": f"VF-00{n}", "finding_ref": {"id": f"T-00{n}", "match_key": f"k{n}"}, "verdict": verdict,
            "confidence": "high" if verdict != "not-attempted" else "low", "rationale": f"rationale {n}",
            "proof": {"checked": verdict != "not-attempted", "contract": 3}, **extra}


DOC = {
    "meta": {"generated": "2026-11-08T07:48:26.5Z", "verifier_version": "0.9", "model": "sonnet",
             "safety": {"mode": "safe"}, "target": {"base_url": "https://app.example.com"}},
    "results": [
        _result(1, "confirmed", poc={"file": "evidence/T-001-poc.har", "steps": [
            {"step": 1, "line": "GET /about?q=x → 200", "decisive": True}], "shown": [
            {"step": 1, "request": "GET /about?q=x HTTP/1.1", "response": "HTTP/1.1 200 OK\n\n```<b>x</b>"}]},
            evidence=[{"kind": "screenshot", "path": "evidence/T-001-xss-1.png"}],
            rationale="the marker ran\n## not a section"),
        _result(2, "blocked-by-control"),
        _result(3, "not-attempted"),
        _result(4, "confirmed"),
    ],
}

THREATS = [
    {"id": "T-001", "title": "Stored XSS", "likelihood": "Medium", "impact": "Critical", "risk": "High",
     "effective_severity": "High"},
    {"id": "T-002", "title": "SQL | injection", "likelihood": "High", "impact": "High", "risk": "High",
     "effective_severity": "High"},
    {"id": "T-003", "title": "Open redirect", "likelihood": "Medium", "impact": "Low", "risk": "Low"},
    {"id": "T-004", "title": "Not in the report", "likelihood": "High", "impact": "Low", "risk": "Low"},
]


def _annotated(threats=THREATS):
    return annotate_assessment({"threats": threats}, DOC, verification_report="out/verification.yaml")


def _copy(report=REPORT, threats=THREATS):
    return annotate_report(report, _annotated(threats), DOC)


def _between(text, start, end):
    return text[text.index(start):text.index(end)]


def test_each_tested_finding_gets_its_section_at_the_end_of_its_entry():
    copy = _copy()
    first = _between(copy, '<a id="t-001">', '<a id="t-002">')
    assert first.index("# a comment that looks like a heading") < first.index("**Fix:** escape output.")
    assert first.index("**Fix:** escape output.") < first.index("##### Dynamic verification")
    second = _between(copy, '<a id="t-002">', "### 🟡 Medium (1)")
    assert "##### Dynamic verification" in second and "blocked by control (high)" in second
    third = _between(copy, '<a id="t-003">', "## 9. Abuse Cases")
    assert "Dynamic verification" not in third                       # not tested, no section


def test_the_section_shows_verdict_rating_rationale_and_proof():
    first = _between(_copy(), '<a id="t-001">', '<a id="t-002">')
    assert "**Verdict:** confirmed (high) · tested 2026-11-08 07:48 UTC by AppSec Verifier 0.9" in first
    assert "likelihood Medium → High, severity High → Critical; impact unchanged" in first
    assert "###### Proof of concept" in first
    # Request and response share one fence, longer than the target's backticks, so its content stays fenced.
    assert "````http\nGET /about?q=x HTTP/1.1\n\nHTTP/1.1 200 OK\n\n```<b>x</b>\n````" in first
    assert "![Application screenshot evidence/T-001-xss-1.png](evidence/T-001-xss-1.png)" in first
    assert "> the marker ran\n> ## not a section" in first                     # the model's words stay quoted
    assert "\n## not a section" not in first


def test_a_block_is_shown_as_a_lowered_rating():
    second = _between(_copy(), '<a id="t-002">', "### 🟡 Medium (1)")
    assert "likelihood High → Medium, severity High → Medium" in second


def test_the_summary_precedes_the_findings():
    copy = _copy()
    summary = _between(copy, "## Dynamic verification\n", "## Management Summary")
    assert copy.index("## Table of Contents") < copy.index("## Dynamic verification\n")
    assert "3 findings tested: 2 confirmed · 1 blocked by control · 1 not tested." in summary
    assert "may show target data; review before sharing" in summary
    assert "| [T-001](#t-001) Stored XSS | confirmed (high) | High | Critical (changed) |" in summary
    assert "| [T-002](#t-002) SQL \\| injection | blocked by control (high) | High | Medium (changed) |" in summary
    assert "| T-004 Not in the report | confirmed (high) | Low | Low |" in summary         # not placed, no link
    assert "2 of 3 ratings changed." in summary


def test_the_changelog_gets_a_row_for_the_verification_run():
    lines = _copy().splitlines()
    sep = next(i for i, line in enumerate(lines) if line.startswith("|---"))
    row = lines[sep + 1]
    assert row.startswith("| verification | 2026-11-08 07:48 UTC | dynamic verification · safe | sonnet |")
    assert row.count("|") == lines[sep - 1].count("|")
    assert row.endswith("AppSec Verifier 0.9; ratings changed: 2 |")
    assert lines[sep + 2].startswith("| v1 |")


def test_without_a_changelog_table_the_summary_carries_the_entry():
    copy = _copy(report=REPORT.replace("## Changelog", "## History"))
    assert "Changelog: verification on 2026-11-08 07:48 UTC, AppSec Verifier 0.9; ratings changed: 2." in copy


def test_a_finding_without_a_unique_anchor_is_listed_at_the_end():
    copy = _copy(report=REPORT.replace("Text 3.", 'Text 3.\n\n<a id="t-002"></a>'))     # T-002 twice
    register, tail = copy.split("## Dynamic verification: findings not placed")
    assert register.count("##### Dynamic verification") == 1                          # T-001 only
    assert "#### T-002 · SQL | injection" in tail and "#### T-004 · Not in the report" in tail
    assert tail.count("##### Dynamic verification") == 2


def test_an_anchor_inside_a_code_block_does_not_count():
    fenced = REPORT.replace("The end.", '```\n<a id="t-004"></a>\n```')
    assert "#### T-004 · Not in the report" in _copy(report=fenced)


def test_the_copy_is_written_next_to_the_report_and_the_original_stays(tmp_path):
    src, out = tmp_path / "src", tmp_path / "out"
    src.mkdir(), out.mkdir()
    (src / "security-assessment.yaml").write_text("threats: []\n")
    (src / "security-assessment.md").write_text(REPORT)
    line = write_annotated_report(src / "security-assessment.yaml", _annotated(), DOC, out)
    assert line == f"{out / 'security-assessment.annotated.md'} (may show target data; review before sharing)"
    assert (src / "security-assessment.md").read_text() == REPORT
    assert "##### Dynamic verification" in (out / "security-assessment.annotated.md").read_text()


def test_an_oversized_or_missing_report_is_not_copied(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    assert write_annotated_report(tmp_path / "a.yaml", _annotated(), DOC, out) == (
        "not written: no file a.md next to the assessment")
    (tmp_path / "a.md").write_text(REPORT)
    monkeypatch.setattr(annotated_report, "MAX_REPORT_BYTES", 100)
    assert write_annotated_report(tmp_path / "a.yaml", _annotated(), DOC, out).startswith(
        "not written: a.md is larger than")
    assert not (out / "security-assessment.annotated.md").exists()


def test_only_plain_figure_names_next_to_the_report_are_copied(tmp_path):
    src, out = tmp_path / "src", tmp_path / "out"
    src.mkdir(), out.mkdir()
    for name in ("fig.svg", "fig-dark.svg", "notes.txt", "real.png"):
        (src / name).write_text(name)
    (tmp_path / "secret.svg").write_text("secret")
    (src / "sub").mkdir()
    (src / "sub" / "dir.png").write_text("dir")
    os.symlink(tmp_path / "secret.svg", src / "link.svg")
    markdown = ('<picture><source srcset="fig-dark.svg"><img src="fig.svg"></picture> ![a](../secret.svg) '
                '![b](sub/dir.png) ![c](notes.txt) ![d](link.svg) ![e](missing.png) ![f](real.png)')
    assert copy_figures(markdown, src, out) == ["fig-dark.svg", "fig.svg", "real.png"]
    assert sorted(p.name for p in out.iterdir()) == ["fig-dark.svg", "fig.svg", "real.png"]
    assert (out / "fig.svg").read_text() == "fig.svg"
