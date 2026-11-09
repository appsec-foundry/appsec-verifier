"""Resumed reports preserve when each result was tested (VER-037)."""

from __future__ import annotations

import copy
from datetime import datetime, timezone

from test_runner import _plan, _run

from appsec_verifier.verify.probes import ProbeRegistry, ProbeResult
from appsec_verifier.verify.report import build_annotations, merge_reports, to_markdown

OLD = "2026-11-01T10:00:00Z"
NEW = "2026-11-09T12:00:00Z"


def report(time, rows):
    return {"meta": {"generated": time}, "results": rows}


def row(fid, time=None):
    result = {"result_id": "VF-001", "finding_ref": {"id": fid}, "verdict": "confirmed"}
    if time:
        result["timing"] = {"started": time, "finished": time}
    return result


def exported(doc):
    return {a["finding_id"]: a["verified_at"]
            for a in build_annotations(doc, verification_report="verification.yaml")["annotations"]}


def test_resume_preserves_test_times_and_updates_only_retested_findings():
    old = report(OLD, [row("T-1", OLD), row("T-2", OLD)])
    before = copy.deepcopy(old)
    merged = merge_reports(old, report(NEW, [row("T-2", NEW)]))
    assert exported(merged) == {"T-1": OLD, "T-2": NEW}
    assert old == before
    markdown = to_markdown(merged)
    assert "Tested" in markdown and "2026-11-01" in markdown and "2026-11-09" in markdown


def test_legacy_fallback_remains_the_original_report_time_across_multiple_merges():
    old = report(OLD, [row("T-1")])
    merged = merge_reports(old, report(NEW, [row("T-2", NEW)]))
    merged = merge_reports(merged, report("2026-11-10T12:00:00Z", []))
    assert exported(merged) == {"T-1": OLD, "T-2": NEW}
    assert "Original report" in to_markdown(merged)
    assert "timing" not in merged["results"][0]  # do not invent a precise test time for old results


def test_runner_keeps_actual_test_times_after_evidence_review():
    class Probe:
        cls = "xss"

        def run(self, ctx):
            return ProbeResult("inconclusive", rationale="offline fixture")

    before = datetime.now(timezone.utc)
    doc = _run([_plan("T-1", "xss"), _plan("T-2", "unsupported")],
               registry=ProbeRegistry({"xss": Probe()}))
    after = datetime.now(timezone.utc)
    timing = doc["results"][0]["timing"]
    started, finished = [datetime.fromisoformat(timing[k].replace("Z", "+00:00")) for k in ("started", "finished")]
    assert before <= started <= finished <= after
    assert "timing" not in doc["results"][1]
    assert exported(doc)["T-1"] == timing["finished"]
