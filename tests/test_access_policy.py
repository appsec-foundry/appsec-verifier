"""Observed access cannot manufacture an intended restriction (VER-010, VER-046, VER-057)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from appsec_verifier.agent.access_policy import apply_intent_review, restriction
from appsec_verifier.verify.probes import ProbeResult


def policy(path, *, allowed=("account-1",), denied=("anonymous",), method="GET", finding="T-1"):
    return {"finding_id": finding, "path": path, "method": method, "allowed_roles": list(allowed),
            "denied_roles": list(denied), "restriction": "Only the declared allowed accounts may access this resource",
            "source": "operator: application access requirements section 4"}


def test_an_observed_comparison_without_policy_is_not_confirmed():
    from test_access_without_credentials import _check, comparison

    result = _check(comparison(), scope={})
    assert result.verdict == "inconclusive" and result.proof["checked"] is False
    assert result.proof["observed_access"] is True and result.proof["steps"] == [2, 3, 4]
    assert "unproven" in result.rationale and result.observations


@pytest.mark.parametrize("change", [
    {"finding_id": "another"}, {"path": "/another"}, {"method": "POST"},
    {"denied_roles": ["unrelated"]}, {"denied_roles": ["account-1", "anonymous"]},
    {"allowed_roles": ["unrelated"]},
])
def test_policy_must_apply_to_the_actual_denied_identity_resource_and_method(change):
    from test_access_without_credentials import PATH, _check, comparison

    result = _check(comparison(), scope={"access_policies": [{**policy(PATH), **change}]})
    assert result.verdict == "inconclusive" and result.proof["observed_access"]


def test_a_policy_does_not_derive_or_authorize_any_request():
    ctx = SimpleNamespace(plan=SimpleNamespace(id="T-1"), scope={"access_policies": [policy("/unrelated")]})
    assert restriction(ctx, [], []) is None


def test_an_unresolved_intent_objection_downgrades_even_a_checked_result():
    result = ProbeResult(verdict="confirmed", proof={"checked": True, "steps": [2, 3, 4]})
    result = apply_intent_review(result, {"status": "stopped", "issues": [{"code": "interpretation"}]})
    assert result.verdict == "inconclusive" and result.proof["observed_access"]
    assert result.proof["checked"] is False and result.proof["steps"] == [2, 3, 4]


def test_clear_qa_cannot_upgrade_a_missing_restriction():
    result = ProbeResult(verdict="inconclusive", proof={"checked": False})
    assert apply_intent_review(result, {"status": "clear", "issues": []}).verdict == "inconclusive"


def test_inconclusive_model_keeps_the_comparison_record_without_withheld_bodies(tmp_path):
    import json

    from test_access_without_credentials import PATH, SECRET, _run
    from test_agent_tools import Resp

    result, sent, _ = _run(tmp_path, lambda m, path, h: Resp(200, SECRET) if path == PATH else Resp(404, "missing"),
                           declared=False, verdict_kind="inconclusive")
    assert result.verdict == "inconclusive" and result.proof["observed_access"]
    assert len(sent) == 3 and result.proof["checked"] is False
    record = json.loads(next((tmp_path / "evidence").glob("*-exchanges.json")).read_text())
    exchanges = record["exchanges"]
    assert len(exchanges) == 3 and SECRET not in json.dumps(record)
    assert [x["comparison_body_group"] for x in exchanges] == [1, 1, 2]
    assert [x["body_withheld"] for x in exchanges] == [True, False, True]


def test_resume_rechecks_old_access_confirmations_without_restriction():
    from appsec_verifier.loader import FindingPlan
    from appsec_verifier.verify.report import remaining_variants

    plan = FindingPlan(id="T-1", cwe="CWE-306", severity="high", title="access", match_key="a|CWE-306",
                       instance="a:1", status="dynamic", cls="access-control", reason="test")
    entry = {"finding_ref": {"id": "T-1", "variant_digest": None}, "class": "access-control",
             "verdict": "confirmed", "proof": {"checked": True, "contract": 3}}
    assert len(remaining_variants([plan], {"results": [entry]})) == 1
    entry["proof"]["access_restriction"] = policy("/private")
    assert remaining_variants([plan], {"results": [entry]}) == []


def test_scope_policy_schema_rejects_ambiguous_paths_and_unknown_fields():
    from pathlib import Path

    import yaml
    from jsonschema import Draft202012Validator

    schema = yaml.safe_load(Path("schemas/scope.schema.yaml").read_text())["properties"]["access_policies"]
    validator = Draft202012Validator(schema)
    assert validator.is_valid([policy("/private")])
    assert not validator.is_valid([{**policy("/private"), "allow_write": True}])
    assert not validator.is_valid([policy("https://another.test/private")])
    assert not validator.is_valid([{**policy("/private"), "source": ""}])


def test_a_creation_or_anonymous_control_policy_cannot_prove_another_accounts_read():
    from test_own_access import _check, owned

    creation = policy("/api/Feedbacks", method="POST", allowed=("account-1",), denied=("account-2",))
    assert _check(owned(), scope={"access_policies": [creation]}).verdict == "inconclusive"
    history = owned()
    history[3]["result"]["status"] = 200  # An anonymous response without the protected marker.
    anonymous = policy("/api/Feedbacks/7", allowed=("account-2",), denied=("anonymous",))
    assert _check(history, scope={"access_policies": [anonymous]}).verdict == "inconclusive"


def test_report_shows_the_independent_restriction_and_its_source():
    from appsec_verifier.verify.report import to_markdown

    declared = {**policy("/private"), "source": "requirements/access.txt:7 <untrusted>"}
    doc = {"meta": {}, "results": [{"result_id": "VF-1", "finding_ref": {"id": "T-1", "title": "Access"},
           "class": "access-control", "verdict": "confirmed", "confidence": "medium",
           "proof": {"checked": True, "access_restriction": declared}}]}
    text = to_markdown(doc)
    assert "**Expected access:** Only the declared allowed accounts" in text
    assert "Source: requirements/access.txt:7 &lt;untrusted&gt;." in text
    assert "<untrusted>" not in text
