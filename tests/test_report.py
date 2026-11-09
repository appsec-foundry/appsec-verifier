"""Report writer produces schema-valid verification.yaml + readable md, an
additive assessment annotation, and the Analyzer re-ingest export (VER-020/021/027)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from appsec_verifier.limits import Limits
from appsec_verifier.loader import FindingPlan
from appsec_verifier.verify import build_annotations, run_verification, write_reports
from appsec_verifier.verify.report import annotate_assessment, to_markdown

SCOPE = {"base_url": "https://app.example.com", "hosts": ["app.example.com"], "ports": [443],
         "schemes": ["https"], "window": {"from": "2026-01-01T00:00:00Z", "until": "2026-12-31T23:59:59Z"},
         "owner": {"name": "tester"}}
SCHEMA = Path(__file__).resolve().parent.parent / "schemas" / "verification.schema.yaml"


def _doc():
    plan = FindingPlan(id="T-037", cwe="CWE-79", severity="High", title="Stored XSS",
                       match_key="about.ts|CWE-79", instance="about.ts:119", status="dynamic", cls="xss", reason="p")
    return run_verification(
        assessment_path=Path("security-assessment.yaml"), scope=SCOPE, scope_path=Path("scope.yaml"),
        plans=[plan], limits=Limits(), identities=[], registry=__import__(
            "appsec_verifier.verify", fromlist=["default_registry"]).default_registry(),
        verifier_version="test", target_base="https://app.example.com",
        authorization={"confirmed": True, "mode": "ci-flag", "at": "2026-11-06T12:00:00Z"},
        safe=True, read_only=True, contacted=False,
    )


def _check_required(instance, schema, where="$"):
    """Minimal structural validation when jsonschema is unavailable."""
    t = schema.get("type")
    if t == "object" and isinstance(instance, dict):
        for req in schema.get("required", []):
            assert req in instance, f"{where}: missing required '{req}'"
        for k, sub in (schema.get("properties") or {}).items():
            if k in instance and instance[k] is not None:
                _check_required(instance[k], sub, f"{where}.{k}")
    if t == "array" and isinstance(instance, list):
        item = schema.get("items") or {}
        for i, el in enumerate(instance):
            _check_required(el, item, f"{where}[{i}]")


def test_verification_doc_is_schema_valid():
    doc = _doc()
    schema = yaml.safe_load(SCHEMA.read_text())
    try:
        from jsonschema.validators import validator_for
        cls = validator_for(schema)
        cls.check_schema(schema)
        errs = sorted(e.message for e in cls(schema).iter_errors(doc))
        assert not errs, errs
    except ModuleNotFoundError:
        _check_required(doc, schema)
        assert doc["results"][0]["result_id"].startswith("VF-")


def test_exchange_evidence_is_schema_valid():
    from jsonschema.validators import validator_for

    doc = _doc()
    doc["results"][0].update(verdict="confirmed", evidence=[
        {"kind": "exchange", "path": "evidence/T-037-exchanges.json", "redacted": True, "sha256": "ab" * 32}])
    schema = yaml.safe_load(SCHEMA.read_text())
    assert not list(validator_for(schema)(schema).iter_errors(doc))


def test_write_reports_roundtrip(tmp_path):
    doc = _doc()
    paths = write_reports(doc, tmp_path)
    assert paths["yaml"].is_file() and paths["md"].is_file() and paths["evidence"].is_dir()
    back = yaml.safe_load(paths["yaml"].read_text())
    assert back["results"][0]["finding_ref"]["id"] == "T-037"
    assert "Stored XSS" in paths["md"].read_text()


def test_build_annotations_keyed_by_id_and_match_key():
    ann = build_annotations(_doc(), verification_report="verification.yaml")
    a = ann["annotations"][0]
    assert a["finding_id"] == "T-037" and a["match_key"] == "about.ts|CWE-79"
    assert a["verdict"] == "not-attempted"
    assert ann["meta"]["verification_report"] == "verification.yaml"


def test_annotate_assessment_is_additive():
    assessment = {"threats": [{"id": "T-037", "cwe": "CWE-79", "severity": "High",
                               "evidence": [{"file": "about.ts", "line": 119}], "scenario": "orig"}]}
    doc = _doc()
    out = annotate_assessment(assessment, doc, verification_report="verification/verification.yaml")
    t = out["threats"][0]
    assert t["scenario"] == "orig"          # original untouched
    assert t["dynamic_verification"]["verdict"] == "not-attempted"
    assert "T-037" == t["id"]               # identity preserved
    assert out["dynamic_verification"] == {"schema_version": 1, "generated": doc["meta"]["generated"],
                                           "verifier_version": "test",
                                           "verification_report": "verification/verification.yaml"}
    # original dict not mutated
    assert "dynamic_verification" not in assessment["threats"][0] and "dynamic_verification" not in assessment


# AppSec Analyzer's own `threats[].verification` (REQ-040) must survive annotation unchanged (VER-027).
ANALYZER_BLOCK = {"finding_ids": ["TCF-001"], "test_case_ids": ["TC-SQLI-01"]}


def test_annotation_leaves_the_analyzers_verification_block_alone():
    assessment = {"threats": [
        {"id": "T-037", "cwe": "CWE-79", "verification": dict(ANALYZER_BLOCK)},
        {"id": "T-099", "cwe": "CWE-89", "verification": dict(ANALYZER_BLOCK)},   # not in this run
    ]}
    out = annotate_assessment(assessment, _doc(), verification_report="v.yaml")
    tested, untested = out["threats"]
    assert tested["verification"] == ANALYZER_BLOCK and untested["verification"] == ANALYZER_BLOCK
    assert tested["dynamic_verification"]["result_ref"] == "VF-001"
    assert "dynamic_verification" not in untested


def test_a_finding_that_only_shares_the_key_of_a_tested_one_gets_no_result():
    """VER-027: another finding with the same cross-run key was not tested and must not carry the result."""
    assessment = {"threats": [{"id": "T-037", "cwe": "CWE-79", "evidence": [{"file": "about.ts", "line": 119}]},
                              {"id": "T-086", "cwe": "CWE-79", "evidence": [{"file": "about.ts", "line": 7}]}]}
    tested, other = annotate_assessment(assessment, _doc(), verification_report="v.yaml")["threats"]
    assert tested["dynamic_verification"]["result_ref"] == "VF-001"
    assert "dynamic_verification" not in other


def test_the_key_finds_a_result_whose_finding_has_a_new_id_only_when_it_is_unique():
    threat = {"id": "T-100", "cwe": "CWE-79", "evidence": [{"file": "about.ts", "line": 119}]}
    out = annotate_assessment({"threats": [threat]}, _doc(), verification_report="v.yaml")
    assert out["threats"][0]["dynamic_verification"]["result_ref"] == "VF-001"
    twins = annotate_assessment({"threats": [threat, {**threat, "id": "T-101"}]}, _doc(), verification_report="v")
    assert all("dynamic_verification" not in t for t in twins["threats"])


def test_variant_annotation_goes_to_the_verifiers_own_block():
    doc = _doc()
    r = doc["results"][0]
    r.update(verdict="confirmed")
    r["finding_ref"]["variant"] = "v1"
    r["proof"] = {"checked": True, "variant": "v1"}
    assessment = {"threats": [{"id": "T-037", "cwe": "CWE-79", "verification": dict(ANALYZER_BLOCK),
                               "verification_context": {"variants": [{"id": "v1"}, {"id": "v2"}]}}]}
    t = annotate_assessment(assessment, doc, verification_report="v.yaml")["threats"][0]
    assert t["verification"] == ANALYZER_BLOCK
    assert t["dynamic_verification"]["verdict"] == "confirmed"
    assert t["dynamic_verification"]["coverage"] == "partial"
    assert [v["variant"] for v in t["dynamic_verification"]["variants"]] == ["v1"]


# ── the annotated copy: schema, pointers, rating after verification (VER-027, VER-039) ──

ANNOTATED_SCHEMA = Path(__file__).resolve().parent.parent / "schemas" / "annotated-assessment.schema.yaml"


def _confirmed_doc():
    doc = _doc()
    r = doc["results"][0]
    r.update(verdict="confirmed", confidence="high",
             poc={"file": "evidence/T-037-poc.har", "steps": []},
             evidence=[{"kind": "screenshot", "path": "evidence/T-037-xss-1.png"},
                       {"kind": "browser-event", "path": "evidence/T-037-xss-1.json"}])
    r["proof"] = {"checked": True, "contract": 3, "scope": "cited requests only"}
    return doc


def _analyzer_threat(**extra):
    return {"id": "T-037", "cwe": "CWE-79", "title": "Stored XSS", "likelihood": "Medium", "impact": "High",
            "risk": "High", "effective_severity": "High", "verification": dict(ANALYZER_BLOCK), **extra}


def test_annotated_copy_matches_its_schema():
    from jsonschema.validators import validator_for

    out = annotate_assessment({"threats": [_analyzer_threat()]}, _confirmed_doc(), verification_report="v.yaml")
    schema = yaml.safe_load(ANNOTATED_SCHEMA.read_text())
    cls = validator_for(schema)
    cls.check_schema(schema)
    assert not sorted(e.message for e in cls(schema).iter_errors(out))


def test_annotation_adds_only_its_own_key():
    """The Analyzer's schema accepts extra fields at the root and on threats; nothing else may change."""
    assessment = {"meta": {"project": "p"}, "threats": [_analyzer_threat(), {"id": "T-099", "risk": "Low"}]}
    out = annotate_assessment(assessment, _confirmed_doc(), verification_report="v.yaml")
    assert {k: v for k, v in out.items() if k != "dynamic_verification"} == {
        "meta": {"project": "p"}, "threats": out["threats"]}
    for before, after in zip(assessment["threats"], out["threats"], strict=True):
        assert {k: v for k, v in after.items() if k != "dynamic_verification"} == before


# Opt-in: AppSec Analyzer's schema is not part of this repository, so the comparison needs its path.
ANALYZER_SCHEMA = os.environ.get("APPSEC_VERIFIER_ANALYZER_SCHEMA")


@pytest.mark.skipif(not ANALYZER_SCHEMA, reason="set APPSEC_VERIFIER_ANALYZER_SCHEMA to the path of AppSec "
                    "Analyzer's schemas/threat-model.output.schema.yaml")
def test_annotation_adds_no_error_under_the_analyzers_schema():
    """The copy stays valid against the Analyzer's current assessment schema (VER-027): the added fields
    cause no error the original does not have. The original holds only a finding id, so that no field of
    its own hides an error about added ones; the errors of an incomplete assessment are the same in both."""
    from jsonschema.validators import validator_for

    schema = yaml.safe_load(Path(ANALYZER_SCHEMA).read_text(encoding="utf-8"))
    cls = validator_for(schema)
    cls.check_schema(schema)
    validator = cls(schema)

    def where(e):
        return tuple(e.absolute_path), tuple(e.schema_path)

    assessment = {"threats": [{"id": "T-037"}]}
    out = annotate_assessment(assessment, _confirmed_doc(), verification_report="v.yaml")
    assert "dynamic_verification" in out and "dynamic_verification" in out["threats"][0]
    before = {where(e) for e in validator.iter_errors(assessment)}
    added = [f"{'/'.join(map(str, e.absolute_path)) or 'root'}: {e.message}"
             for e in validator.iter_errors(out) if where(e) not in before]
    assert not added


def test_annotation_points_to_the_proof_but_carries_none_of_it():
    t = annotate_assessment({"threats": [_analyzer_threat()]}, _confirmed_doc(), verification_report="v.yaml")
    block = t["threats"][0]["dynamic_verification"]
    assert block["proof_of_concept"] == ["evidence/T-037-poc.har"]
    assert block["screenshots"] == ["evidence/T-037-xss-1.png"]
    assert "poc" not in block and "evidence" not in block


def test_annotation_carries_the_rating_after_verification():
    block = annotate_assessment({"threats": [_analyzer_threat()]}, _confirmed_doc(),
                                verification_report="v.yaml")["threats"][0]["dynamic_verification"]
    assert block["rating"]["analyzer"] == {"likelihood": "Medium", "impact": "High", "severity": "High"}
    assert block["rating"]["after_verification"] == {"likelihood": "High", "impact": "High", "severity": "Critical"}
    assert block["rating"]["changed"] is True


def _variant_doc(*verdicts):
    doc = _doc()
    base = doc["results"][0]
    doc["results"] = [{**base, "result_id": f"VF-00{i}", "verdict": verdict,
                       "finding_ref": {**base["finding_ref"], "variant": f"v{i}"},
                       "proof": {"checked": True, "variant": f"v{i}"}}
                      for i, verdict in enumerate(verdicts, start=1)]
    return doc


def test_a_block_lowers_the_rating_only_when_every_variant_was_blocked():
    def rating(*verdicts):
        threat = _analyzer_threat(verification_context={"variants": [{"id": "v1"}, {"id": "v2"}]})
        out = annotate_assessment({"threats": [threat]}, _variant_doc(*verdicts), verification_report="v.yaml")
        return out["threats"][0]["dynamic_verification"]["rating"]

    assert rating("blocked-by-control")["changed"] is False                     # v2 untested
    assert rating("blocked-by-control", "inconclusive")["changed"] is False
    both = rating("blocked-by-control", "blocked-by-control")
    assert both["changed"] is True and both["after_verification"]["severity"] == "Medium"


# ── verification.md: overview, entry, not tested, appendix (VER-020, VER-024, VER-039) ──

DEVIATION = ("Deviation: the owner created its own test resource with POST /items, a route the assessment names "
             "for this resource outside this finding (VER-043).")


def _report_doc():
    doc = _confirmed_doc()
    tested = doc["results"][0]
    tested.update(rationale="The agent's account\n```\n# not a heading", observations=[DEVIATION],
                  planning=[{"step": 1, "path": "/x", "hypothesis": "q reaches innerHTML"}])
    doc["results"].append({**tested, "result_id": "VF-002", "verdict": "not-attempted", "confidence": None,
                           "rationale": "not tested: no marker_file in the scope", "poc": None, "evidence": [],
                           "planning": [], "observations": [], "proof": None,
                           "finding_ref": {"id": "T-038", "title": "Path | traversal\n<b>x</b>", "cwe": "CWE-22",
                                           "match_key": "f|CWE-22"}})
    return doc


def _report():
    assessment = {"threats": [_analyzer_threat(), {"id": "T-038", "risk": "High"}]}
    return to_markdown(_report_doc(), assessment)


def test_the_overview_links_every_finding_and_marks_confirmed_results_and_changed_ratings():
    md = _report()
    overview = md.split("## Overview", 1)[1].split("## Tested findings", 1)[0]
    assert "| [T-037](#t-037) Stored XSS | **confirmed** | **High → Critical** |" in overview
    assert "| [T-038](#t-038) " in overview and "| not tested | High |" in overview
    assert "Ratings changed: [T-037](#t-037)" in overview
    assert md.index("## Overview") < md.index('<a id="t-037"></a>\n### T-037') < md.index("## Not tested")


def test_a_tested_entry_leads_with_its_verdict_rating_and_deviation():
    entry = _report().split("### T-037", 1)[1].split("## Not tested", 1)[0]
    assert entry.split("\n")[2].startswith("**Confirmed** · rating **High → Critical** · confidence high")
    assert "- Proof checked by the code: script executed in the browser." in entry
    assert f"- {DEVIATION}" in entry and "- Rating changed: " in entry
    assert "The agent's account" not in entry and "q reaches innerHTML" not in entry    # in the appendix
    assert "[details](#details-t-037)" in entry


def test_findings_not_tested_say_why_and_keep_their_text_in_one_cell():
    rows = [line for line in _report().split("## Not tested", 1)[1].splitlines() if "T-038" in line]
    assert rows == ['| <a id="t-038"></a>T-038 Path \\| traversal &lt;b&gt;x&lt;/b&gt; | no marker_file in the scope |']


def test_the_appendix_holds_plan_explanation_and_observations_as_fenced_text():
    appendix = _report().split("## Appendix: test details", 1)[1]
    assert '<a id="details-t-037"></a>' in appendix and "q reaches innerHTML" in appendix
    assert "````text\nThe agent's account\n```\n# not a heading\n````" in appendix   # model text cannot escape


def test_without_the_assessment_the_report_still_lists_every_finding():
    md = to_markdown(_report_doc())
    assert "| [T-037](#t-037) Stored XSS | **confirmed** | – |" in md and "No rating changed" not in md


def test_write_reports_shows_the_rating_from_the_assessment(tmp_path):
    paths = write_reports(_report_doc(), tmp_path, {"threats": [_analyzer_threat()]})
    assert "**High → Critical**" in paths["md"].read_text()
