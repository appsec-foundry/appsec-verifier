"""Access-control proof without an operator test resource (VER-010, VER-041): a resource a normal account creates
with the finding's marker, or a privileged function compared with a privileged account. Both count at medium
confidence, only the code's check confirms them, and an operator's test resource takes precedence."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_agent_tools import SCOPE, Resp, _ctx
from test_endpoints import _blocker, _plan
from test_experiments import STRATEGY

from appsec_verifier.agent.controller import Controller
from appsec_verifier.agent.prompts import _system
from appsec_verifier.agent.proof import check_proof
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.verify.probes import ProbeResult
from appsec_verifier.verify.report import to_markdown

MARKER = ("vrf1a2b3c4d", "5e6f7a8b")
M = "".join(MARKER)
ROLES = [{"role": "account-1"}, {"role": "account-2"}, {"role": "admin-1", "privileged": True}]
RESOURCE = {"id": "basket", "finding_id": "T-1", "path": "/rest/basket/2", "allowed_roles": ["account-2"],
            "denied_roles": ["account-1"], "pointer": "", "value": "owner-marker"}
FN = "/rest/admin/application-configuration"
CONFIG = '{"config":{"name":"shop"}}'


def _plan_step(**extra):
    args = {"kind": "access-control", "hypothesis": "Another account reads what belongs to the owner",
            "path": "/api/Feedbacks/:id", "strategy": copy.deepcopy(STRATEGY), **extra}
    return {"tool": "plan_test", "args": args, "result": {"accepted": True}}


def _req(role, body="", status=200, method="GET", path="/api/Feedbacks/7", json=None, params=None, session=None,
         complete=True, redacted=False):
    args = {"path": path, "method": method, **({"role": role} if role else {}), **({"json": json} if json else {}),
            **({"params": params} if params else {})}
    sha = hashlib.sha256(body.encode()).hexdigest()
    return {"tool": "http_request", "args": args,
            "result": {"role": role, "status": status, "length": len(body), "body_sha256": sha},
            "_response": {"body": body, "complete": complete, "identity": session or role or "anonymous",
                          "redacted": redacted}}


def _check(history, verdict="confirmed", cited=None, scope=None, cwe="CWE-639"):
    history = copy.deepcopy(history)
    responses = {n: h.pop("_response") for n, h in enumerate(history, 1) if "_response" in h}
    ctx = SimpleNamespace(plan=SimpleNamespace(id="T-1", cls="access-control", cwe=cwe), scope=scope or {},
                          identities=ROLES, marker=MARKER, responses=responses, sessions=None, evidence_dir=None)
    if cited is None:
        cited = [n for n, h in enumerate(history, 1) if h["tool"] == "http_request"]
    return check_proof(ctx, history, ProbeResult(verdict=verdict, confidence="high", rationale="claim"), cited)


def owned(other=f'{{"comment":"{M}"}}', other_status=200):
    return [_plan_step(owner="account-2"),
            _req("account-2", '{"id":7}', 201, "POST", "/api/Feedbacks", json={"comment": M}),
            _req("account-2", f'{{"comment":"{M}"}}'),
            _req(None, '{"error":"login required"}', 401),
            _req("account-1", other, other_status)]


def privileged(normal=CONFIG, normal_status=200, anonymous_status=401):
    return [_plan_step(reference="admin-1", path=FN),
            _req("admin-1", CONFIG, path=FN),
            _req(None, '{"error":"login required"}', anonymous_status, path=FN),
            _req("account-1", normal, normal_status, path=FN)]


# ── a resource the owner creates ──────────────────────────────────────────────

def test_the_other_account_reading_the_owners_marker_confirms_at_medium():
    result = _check(owned())
    assert result.verdict == "confirmed" and result.confidence == "medium"
    assert result.proof["marker"] == M and "account-2 created" in result.proof["scope"]
    assert "stays on the target" in result.proof["scope"]
    assert "account-2 created" in to_markdown({"meta": {}, "results": [{"result_id": "VF-001", "verdict": "confirmed",
                                                                         "proof": result.proof}]})


def _change(history, step, **changes):
    history = copy.deepcopy(history)
    for key, value in changes.items():
        if key in ("body", "complete", "identity"):
            history[step]["_response"][key] = value
        elif key == "status":
            history[step]["result"]["status"] = value
        else:
            history[step]["args"][key] = value
    return history


@pytest.mark.parametrize("history, reason", [
    (_change(owned(), 3, body=f'{{"comment":"{M}"}}', status=200), "visible without a login"),   # public resource
    (_change(owned(), 4, params={"q": M}), "other than the owner sent the marker"),            # the read sends it
    (_change(owned(), 1, role="account-1"), "other than the owner sent the marker"),           # another writer
    (_change(owned(), 4, identity="account-2"), "independent other normal account"),            # same session
    (_change(owned(), 4, role="admin-1"), "independent other normal account"),                  # a privileged read
    (_change(owned(), 1, json={"comment": "hello"}), "no cited write of the owner carries the marker"),
    (_change(owned(), 2, body="{}"), "owner's read does not show the marker"),
    (_change(owned(), 3, complete=False), "absence is not established"),
    (_change(owned(), 4, path="/api/Feedbacks/8"), "same resource with the same inputs"),
    (owned()[:3] + owned()[4:], "cite a read without a role"),
    ([owned()[1], owned()[0], *owned()[2:]], "after the declared plan"),                        # write before plan
])
def test_an_own_resource_without_the_full_contrast_stays_inconclusive(history, reason):
    result = _check(history)
    assert result.verdict == "inconclusive" and reason in result.rationale


def test_an_operator_resource_takes_precedence_over_an_own_resource():
    result = _check(owned(), scope={"test_resources": [RESOURCE]})
    assert result.verdict == "inconclusive" and "takes precedence" in result.rationale


def test_own_resource_negative_verdicts():
    assert _check(owned('{"error":"forbidden"}', 403), "blocked-by-control").verdict == "blocked-by-control"
    result = _check(owned('{"comment":"mine"}'), "not-reproducible")
    assert result.verdict == "not-reproducible" and result.confidence == "medium"
    result = _check(owned(), "not-reproducible")
    assert result.verdict == "inconclusive" and "present for the other account" in result.rationale


# ── a privileged function ─────────────────────────────────────────────────────

def test_the_identical_answer_for_a_normal_account_confirms_at_medium():
    result = _check(privileged())
    assert result.verdict == "confirmed" and result.confidence == "medium"
    assert "admin-1 does not show" in result.proof["scope"] and "marker" not in result.proof


@pytest.mark.parametrize("history, reason", [
    (privileged(anonymous_status=200), "refused with 401 or 403"),
    (privileged(normal='{"config":{"name":"other"}}'), "identical answer"),
    (_change(privileged(), 3, identity="admin-1"), "identical answer"),                          # same session
    ([_plan_step(reference="admin-1", path=FN), _req("admin-1", path=FN), _req(None, "", 401, path=FN),
      _req("account-1", path=FN)], "not answered with content"),                                  # both empty
    (privileged()[:2] + privileged()[3:], "refused with 401 or 403"),
    (privileged() + [_req("account-1", "{}", 200, "POST", FN, json={"x": "y"})], "only reads"),
])
def test_a_privileged_comparison_without_the_full_contrast_stays_inconclusive(history, reason):
    result = _check(history)
    assert result.verdict == "inconclusive" and reason in result.rationale


def test_answers_that_held_a_user_name_are_never_identical():
    history = privileged()
    for h in history[1:]:
        h["_response"]["redacted"] = True       # e.g. both named their own, redacted, user name
    result = _check(history)
    assert result.verdict == "inconclusive" and "credential or user name" in result.rationale


def test_privileged_negative_verdicts():
    assert _check(privileged('{"error":"forbidden"}', 403), "blocked-by-control").verdict == "blocked-by-control"
    result = _check(privileged(), "blocked-by-control")
    assert result.verdict == "inconclusive" and "received the privileged answer" in result.rationale
    result = _check(privileged(normal='{"other":1}'), "not-reproducible")
    assert result.verdict == "inconclusive" and "does not show that the function is protected" in result.rationale


# ── what plan_test accepts ────────────────────────────────────────────────────

IDENTITIES = [{"role": "account-1", "method": "bearer", "auth": {"token_env": "A"}},
              {"role": "account-2", "method": "bearer", "auth": {"token_env": "B"}},
              {"role": "admin-1", "method": "bearer", "auth": {"token_env": "C"}, "privileged": True}]
ENV = {"A": "token-account-1", "B": "token-account-2", "C": "token-admin-1"}


def _tools(tmp_path, *, intrusive=True, identities=IDENTITIES, scope=None, transport=None):
    ctx = _ctx(tmp_path, transport or (lambda *a, **k: Resp()), safe=not intrusive, read_only=not intrusive,
               env=ENV, idents=identities)
    ctx.marker = MARKER
    if scope:
        ctx.scope = scope
    return AgentTools(ctx)


def _plan_args(**extra):
    return {k: v for k, v in _plan_step(path="/rest/basket/:id", **extra)["args"].items()}


def test_an_owner_plan_returns_the_marker_in_intrusive_mode(tmp_path):
    result = _tools(tmp_path).plan_test(**_plan_args(owner="account-2"))
    assert result["accepted"] is True and result["marker"] == M


@pytest.mark.parametrize("kwargs, plan, reason", [
    ({"intrusive": False}, {"owner": "account-2"}, "--allow-intrusive"),
    ({}, {"owner": "admin-1"}, "owner must be a normal account"),
    ({"identities": IDENTITIES[1:]}, {"owner": "account-2"}, "two normal accounts"),
    ({"scope": {**SCOPE, "test_resources": [RESOURCE]}}, {"owner": "account-2"}, "takes precedence"),
    ({}, {"owner": "account-2", "method": "POST"}, "read with GET"),
    ({}, {"reference": "account-1"}, "must be a privileged account"),
    ({"identities": IDENTITIES[:2]}, {"reference": "account-1"}, "privileged and a normal account"),
    ({}, {"owner": "account-2", "reference": "admin-1"}, "invalid experiment declaration"),
])
def test_plan_test_refuses_an_access_plan_the_run_cannot_prove(tmp_path, kwargs, plan, reason):
    with pytest.raises(ToolError, match=reason):
        _tools(tmp_path, **kwargs).plan_test(**_plan_args(**plan))


def test_a_privileged_comparison_needs_no_writes(tmp_path):
    result = _tools(tmp_path, intrusive=False).plan_test(**_plan_args(reference="admin-1"))
    assert result["accepted"] is True and "marker" not in result


def test_exposure_findings_keep_needing_an_operator_resource(tmp_path):
    tools = _tools(tmp_path)
    tools.ctx.plan = replace(tools.ctx.plan, cwe="CWE-306")
    with pytest.raises(ToolError, match="two normal accounts"):
        tools.plan_test(**_plan_args(owner="account-2"))


def test_the_recorded_response_says_whether_it_held_a_credential_or_user_name(tmp_path):
    tools = _tools(tmp_path, transport=lambda *a, **k: Resp(200, '{"token":"token-account-1"}'))
    tools.http_request(role="account-1", path="/rest/basket/2")
    assert tools.take_response()["redacted"] is True
    tools = _tools(tmp_path, transport=lambda *a, **k: Resp(200, '{"basket":2}'))
    tools.http_request(role="account-1", path="/rest/basket/2")
    assert tools.take_response()["redacted"] is False


# ── who may write under the plan ──────────────────────────────────────────────

def _controller(tmp_path, plan):
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(), safe=False, read_only=False, env=ENV, idents=IDENTITIES)
    ctx.plan = replace(ctx.plan, endpoints=(Endpoint("POST", "/api/Feedbacks", None),
                                            Endpoint("GET", "/api/Feedbacks/:id", None)))
    c = Controller(ctx)
    c.plan = {"kind": "access-control", "path": "/api/Feedbacks/:id", **plan}
    return c


def test_only_the_owner_writes_under_an_own_resource_plan(tmp_path):
    c = _controller(tmp_path, {"owner": "account-2"})
    c.before("http_request", {"path": "/api/Feedbacks", "method": "POST", "role": "account-2", "json": {"c": M}})
    for role in ("account-1", None):
        with pytest.raises(ToolError, match="accepted test plan"):
            c.before("http_request", {"path": "/api/Feedbacks", "method": "POST", "role": role, "json": {"c": M}})
    with pytest.raises(ToolError, match="no matching route"):
        c.before("http_request", {"path": "/api/Users", "method": "POST", "role": "account-2", "json": {"c": M}})
    for role in ("account-2", None, "account-1"):
        c.before("http_request", {"path": "/api/Feedbacks/7", "role": role})


def test_a_privileged_comparison_plan_allows_no_write(tmp_path):
    c = _controller(tmp_path, {"reference": "admin-1"})
    with pytest.raises(ToolError, match="accepted test plan"):
        c.before("http_request", {"path": "/api/Feedbacks", "method": "POST", "role": "account-1", "json": {"x": 1}})


# ── whether the run tests the finding, and what the model is told ─────────────

def test_the_test_plan_follows_the_accounts_and_the_mode():
    normal, admin = [{"role": "account-1"}, {"role": "account-2"}], [{"role": "admin-1", "privileged": True}]
    plan = _plan("access-control")
    assert _blocker(plan, identities=normal)[0] == "intrusive"
    assert _blocker(plan, identities=normal, safe=False) is None
    assert _blocker(plan, identities=normal[:1] + admin) is None
    assert _blocker(plan, identities=normal[:1], safe=False)[0] == "resource"
    assert _blocker(replace(plan, cwe="CWE-306"), identities=normal + admin, safe=False)[0] == "resource"
    assert _blocker(plan, identities=normal, scope={"test_resources": [RESOURCE]}) is None
    assert _blocker(plan, identities=normal[1:], scope={"test_resources": [RESOURCE]})[0] == "resource"


@pytest.mark.parametrize("identities, safe, scope, expected", [
    (ROLES[:2], False, {}, "Own-resource proof"),
    (ROLES, True, {}, "Privileged-function proof"),
    (ROLES, False, {"test_resources": [RESOURCE]}, "use the configured test_resource"),
    (ROLES[:2], True, {}, "cannot be confirmed in this run"),
])
def test_the_prompt_names_only_the_proofs_the_run_allows(identities, safe, scope, expected):
    ctx = SimpleNamespace(plan=SimpleNamespace(id="T-1", cls="access-control", cwe="CWE-639"), identities=identities,
                          safe=safe, read_only=safe, scope=scope, marker=MARKER)
    prompt = _system(ctx)
    assert expected in prompt and M not in prompt
    assert ("Own-resource proof" in prompt) == (expected == "Own-resource proof")
