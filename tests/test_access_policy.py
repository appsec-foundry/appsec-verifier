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


def test_the_findings_restriction_confirms_only_when_the_operator_accepted_it():
    """VER-010: without a declaration the finding's restriction counts only after the operator's acceptance."""
    from test_access_without_credentials import PATH, _check, comparison

    assert _check(comparison(), scope={}).verdict == "inconclusive"
    assert _check(comparison(), scope={}, accept="yes").verdict == "inconclusive"  # only an explicit True
    result = _check(comparison(), scope={}, accept=True)
    assert result.verdict == "confirmed" and result.confidence == "medium", result.rationale
    taken = result.proof["access_restriction"]
    assert taken["accepted_from_finding"] is True and taken["source"].startswith("finding T-1 of the assessment")
    assert (taken["path"], taken["allowed_roles"], taken["denied_roles"]) == (PATH, ["account-1"], ["anonymous"])
    assert taken["restriction"] == "The request requires a signed-in account."


def test_acceptance_replaces_no_comparison_and_no_declaration():
    from test_access_without_credentials import PATH, _check, comparison

    # The comparison itself still has to hold: a refused anonymous request stays unconfirmed.
    assert _check(comparison(anonymous_status=403), scope={}, accept=True).verdict != "confirmed"
    declared = _check(comparison(), scope={"access_policies": [policy(PATH)]}, accept=True)
    assert declared.proof["access_restriction"]["source"].startswith("operator:")
    assert "accepted_from_finding" not in declared.proof["access_restriction"]


def test_acceptance_names_the_restriction_of_the_own_resource_and_privileged_forms():
    from test_own_access import _check, owned, privileged

    own = _check(owned(), scope={}, accept=True)
    assert own.verdict == "confirmed", own.rationale
    assert own.proof["access_restriction"]["restriction"].startswith("Only the account that owns the record")
    assert _check(owned(), scope={}).verdict == "inconclusive"
    function = _check(privileged(), scope={}, accept=True, cwe="CWE-862")
    assert function.verdict == "confirmed", function.rationale
    assert function.proof["access_restriction"]["allowed_roles"] == ["admin-1"]
    assert function.proof["access_restriction"]["denied_roles"] == ["account-1", "account-2"]


def test_the_guided_run_no_longer_takes_the_findings_restrictions_on_a_question():
    """VER-010/031: the guided run asks who may use a request instead (test_guided); the findings' restrictions
    count only with --accept-finding-restrictions."""
    from test_guided import SCOPE

    from appsec_verifier.cli import build_guided_parser
    from appsec_verifier.guided import Dialog, _access_preparation
    from appsec_verifier.loader import classify, load_verifiable_cwes

    plan = classify({"id": "T-1", "cwe": "CWE-306", "title": "Management exposure",
                     "severity": "high", "evidence": {"file": "app.py", "line": 1}}, load_verifiable_cwes())
    args, asked = build_guided_parser().parse_args(["assessment.yaml"]), []
    _access_preparation(Dialog(lambda prompt: asked.append(prompt) or "no", lambda _: None), args, dict(SCOPE), [plan])
    assert asked == ["Name such records? [y/N]: "]
    assert args.accept_finding_restrictions is False


# ── the operator's access rule for a request ─────────────────────────────────

def rule(request, may, source=None):
    return {"request": request, "may": may, **({"source": source} if source else {})}


@pytest.mark.parametrize("may, confirmed", [("signed-in", True), ("owner", True), ("admin", True), ("anyone", False)])
def test_access_without_credentials_breaks_every_rule_but_anyone(may, confirmed):
    from test_access_without_credentials import PATH, _check, comparison

    result = _check(comparison(), scope={"access_rules": [rule(f"GET {PATH}", may)]})
    assert (result.verdict == "confirmed") is confirmed, result.rationale
    if confirmed:
        taken = result.proof["access_restriction"]
        assert taken["source"] == f"the operator's access rule for GET {PATH} (scope)"
        assert "accepted_from_finding" not in taken and taken["denied_roles"] == ["anonymous"]
    else:
        assert result.proof["observed_access"] and "allows it" in result.rationale


@pytest.mark.parametrize("may, confirmed", [("owner", True), ("admin", True), ("signed-in", False), ("anyone", False)])
def test_another_accounts_read_of_the_owners_record_breaks_owner_and_admin(may, confirmed):
    from test_own_access import _check, owned

    result = _check(owned(), scope={"access_rules": [rule("GET /api/Feedbacks/:id", may, "guided run")]})
    assert (result.verdict == "confirmed") is confirmed, result.rationale
    if confirmed:
        assert result.proof["access_restriction"]["source"].endswith("(guided run)")


@pytest.mark.parametrize("may, confirmed", [("admin", True), ("signed-in", False), ("owner", False)])
def test_a_normal_accounts_privileged_answer_breaks_only_admin(may, confirmed):
    from test_own_access import FN, _check, privileged

    result = _check(privileged(), scope={"access_rules": [rule(f"GET {FN}", may)]}, cwe="CWE-862")
    assert (result.verdict == "confirmed") is confirmed, result.rationale


def test_a_rule_decides_before_the_accepted_restriction_and_only_for_its_own_request():
    from test_access_without_credentials import PATH, _check, comparison

    public = {"access_rules": [rule(f"GET {PATH}", "anyone")]}
    assert _check(comparison(), scope=public, accept=True).verdict == "inconclusive"
    for other in (f"POST {PATH}", "GET /rest/admin", f"GET {PATH}/more"):
        result = _check(comparison(), scope={"access_rules": [rule(other, "admin")]})
        assert result.verdict == "inconclusive" and "allows it" not in result.rationale
    declared = _check(comparison(), scope={**public, "access_policies": [policy(PATH)]})
    assert declared.verdict == "confirmed" and declared.proof["access_restriction"]["source"].startswith("operator:")
    # The comparison itself still has to hold.
    assert _check(comparison(anonymous_status=403), scope={"access_rules": [rule(f"GET {PATH}", "admin")]}
                  ).verdict != "confirmed"


def test_a_placeholder_in_a_rule_stands_for_one_segment():
    from appsec_verifier.agent.access_policy import access_rule

    scope = {"access_rules": [rule("GET /api/Recycles/:id", "owner")]}
    assert access_rule(scope, "GET", "/api/Recycles/7")["may"] == "owner"
    assert access_rule(scope, "GET", "/api/Recycles/:id?x=1") is not None
    for method, path in (("GET", "/api/Recycles"), ("GET", "/api/Recycles/7/items"), ("PUT", "/api/Recycles/7")):
        assert access_rule(scope, method, path) is None


def test_scope_access_rules_need_a_method_a_path_and_a_known_rule():
    from pathlib import Path

    import yaml
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(
        yaml.safe_load(Path("schemas/scope.schema.yaml").read_text())["properties"]["access_rules"])
    assert validator.is_valid([rule("GET /api/Users", "admin"), rule("PUT /api/Items/:id", "owner", "policy 4")])
    for bad in (rule("GET /api/Users", "everyone"), rule("/api/Users", "admin"), rule("GET https://x.test/a", "admin"),
                rule("GET /a?b=1", "admin"), rule("DELETE /a", "admin"), {**rule("GET /a", "admin"), "allow": 1}):
        assert not validator.is_valid([bad]), bad


def test_a_scope_holds_one_rule_per_request_and_only_rules_inside_its_target():
    from test_guided import SCOPE

    from appsec_verifier.cli import _validate_scope

    assert _validate_scope({**SCOPE, "access_rules": [rule("GET /api/Users", "admin")]}) == []
    twice = {**SCOPE, "access_rules": [rule("GET /a", "admin"), rule("GET /a", "owner")]}
    assert any("one rule per request" in e for e in _validate_scope(twice))
    outside = {**SCOPE, "path_prefixes": ["/api/"], "access_rules": [rule("GET /admin/x", "admin")]}
    assert any("outside the target scope" in e for e in _validate_scope(outside))


def _users_plan():
    from appsec_verifier.endpoints import Endpoint
    from appsec_verifier.loader import FindingPlan

    return FindingPlan(id="T-1", cwe="CWE-862", severity="high", title="users", match_key="a|CWE-862",
                       instance="a:1", status="dynamic", cls="access-control", reason="test",
                       endpoints=(Endpoint("GET", "/api/Users", True), Endpoint("PUT", "/api/Users/:id", True)))


ACCOUNTS = [{"role": "account-1"}, {"role": "admin-1", "privileged": True}]


def test_a_finding_whose_requests_anyone_may_use_is_not_tested():
    from appsec_verifier.cli import _blocker

    def need(rules, safe=True):
        return _blocker(_users_plan(), identities=ACCOUNTS, browser=None, listener=None,
                        scope={"access_rules": rules}, safe=safe)

    assert need([rule("GET /api/Users", "anyone")]) == ("rule", "your access rule lets anyone use GET /api/Users")
    assert need([rule("GET /api/Users", "admin")]) is None and need([]) is None


def test_the_agent_learns_the_rule_and_which_access_breaks_it():
    from appsec_verifier.agent.prompts import _access_hint

    ctx = SimpleNamespace(plan=_users_plan(), scope={"access_rules": [rule("GET /api/Users", "admin")]},
                          identities=ACCOUNTS, safe=True, read_only=True)
    hint = _access_hint(ctx)
    assert "GET /api/Users: Only an admin may use the request." in hint and "breaks admin" in hint
    assert "never a finding claim" not in hint
    ctx.scope = {}
    assert "never a finding claim" in _access_hint(ctx)
