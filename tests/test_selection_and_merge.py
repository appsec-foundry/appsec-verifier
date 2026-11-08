"""Category selection (class or technique, no CWE needed) and report append
(VER-026, VER-027)."""

from __future__ import annotations

from appsec_verifier.loader import FindingPlan, list_categories, select
from appsec_verifier.verify.report import merge_reports, verified_findings


def test_resume_repeats_old_or_unchecked_proofs():
    rows = [{"finding_ref": {"id": "T-1"}, "verdict": "confirmed"},
            {"finding_ref": {"id": "T-2"}, "verdict": "not-reproducible", "proof": {"checked": True, "contract": 1}},
            {"finding_ref": {"id": "T-3"}, "verdict": "blocked-by-control", "proof": {"checked": True, "contract": 2}}]
    assert verified_findings({"results": rows}) == {"T-3"}


def _p(id, cls, technique, sev="High"):
    return FindingPlan(id=id, cwe="CWE-x", severity=sev, title=id, match_key=f"{id}|x",
                       instance=f"{id}.ts:1", status="dynamic", cls=cls, reason="r", technique=technique)


PLANS = [
    _p("T-1", "access-control", "idor"),
    _p("T-2", "access-control", "missing-authz"),
    _p("T-3", "injection", "sqli"),
    _p("T-4", "xss", "xss", sev="Medium"),
]


def test_category_matches_technique():
    got = [p.id for p in select(PLANS, categories={"idor"})]
    assert got == ["T-1"]


def test_category_matches_class():
    got = {p.id for p in select(PLANS, categories={"access-control"})}
    assert got == {"T-1", "T-2"}


def test_category_combines_with_min_severity():
    got = [p.id for p in select(PLANS, categories={"xss"}, min_severity="high")]
    assert got == []  # the only xss finding is Medium


def test_list_categories_includes_classes_and_techniques():
    cats = set(list_categories())
    assert {"access-control", "idor", "sqli", "xss", "ssrf"} <= cats


def test_merge_reports_replaces_and_appends():
    existing = {"meta": {"generated": "2026-01-01T00:00:00Z", "verifier_version": "t"},
                "results": [{"result_id": "VF-001", "finding_ref": {"id": "T-1"},
                             "verdict": "not-attempted", "class": "access-control"}]}
    new = {"meta": {"generated": "2026-02-02T00:00:00Z", "verifier_version": "t"},
           "results": [
               {"result_id": "VF-001", "finding_ref": {"id": "T-1"}, "verdict": "confirmed", "class": "access-control"},
               {"result_id": "VF-002", "finding_ref": {"id": "T-2"}, "verdict": "inconclusive", "class": "xss"},
           ]}
    merged = merge_reports(existing, new)
    verdicts = {r["finding_ref"]["id"]: r["verdict"] for r in merged["results"]}
    assert verdicts == {"T-1": "confirmed", "T-2": "inconclusive"}   # T-1 replaced, T-2 appended
    assert [r["result_id"] for r in merged["results"]] == ["VF-001", "VF-002"]
    assert merged["meta"]["summary"]["total"] == 2
    assert merged["meta"]["previous_generated"] == "2026-01-01T00:00:00Z"
