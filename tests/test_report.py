"""Report writer produces schema-valid verification.yaml + readable md, an
additive assessment annotation, and the Analyzer re-ingest export (VER-020/021/027)."""

from __future__ import annotations

from pathlib import Path

import yaml

from appsec_verifier.limits import Limits
from appsec_verifier.loader import FindingPlan
from appsec_verifier.verify import build_annotations, run_verification, write_reports
from appsec_verifier.verify.report import annotate_assessment

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
    assert out["dynamic_verification"] == {"generated": doc["meta"]["generated"], "verifier_version": "test",
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
