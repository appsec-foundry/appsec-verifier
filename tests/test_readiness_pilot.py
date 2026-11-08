"""VER-008/010: measured offline preparation and unchanged proof boundaries."""
from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest
from test_agent_tools import Resp, _ctx
from test_endpoints import _blocker
from test_experiments import STRATEGY
from test_own_access import ENV, IDENTITIES, MARKER

from appsec_verifier.agent.controller import Controller
from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.agent.tools import ToolError
from appsec_verifier.cli import _test_cases
from appsec_verifier.loader import plans_from
from appsec_verifier.term_style import Style


def document(collection="/api/Notes", file="routes/notes.ts"):
    return {
        "threats": [{"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "Read another user's note",
                     "scenario": "GET /api/Notes/:id", "evidence": {"file": file, "line": 20}}],
        "attack_surface": [{"entry_point": "POST " + collection, "auth_required": True,
                            "notes": "handler: routes/notes.ts:10"}],
    }


def test_preparation_changes_readiness_and_is_shown_before_execution():
    plan = plans_from(document())[0]
    assert [(e.method, e.path) for e in plan.preparation] == [("POST", "/api/Notes")]
    assert _blocker(replace(plan, preparation=()), identities=IDENTITIES[:2], safe=False)[0] == "access"
    assert _blocker(plan, identities=IDENTITIES[:2], safe=False) is None
    assert _blocker(plan, identities=IDENTITIES[:2], safe=True)[0] == "intrusive"
    assert _blocker(plan, identities=IDENTITIES[:1], safe=False)[0] == "resource"
    assert "Preparation: POST /api/Notes" in "\n".join(_test_cases(Style(False), [plan], {}))


@pytest.mark.parametrize("kind", ["other-collection", "other-file", "no-source", "duplicate", "ambiguous", "variant"])
def test_unproven_or_ambiguous_relationships_do_not_expand_requests(kind):
    doc = document()
    if kind == "other-collection":
        doc["attack_surface"][0]["entry_point"] = "POST /api/Users"
    elif kind == "other-file":
        doc["attack_surface"][0]["notes"] = "handler: routes/users.ts:10"
    elif kind == "no-source":
        doc["attack_surface"][0]["notes"] = ""
    elif kind == "duplicate":
        doc["attack_surface"] *= 2
    elif kind == "ambiguous":
        doc["threats"][0]["scenario"] += " and GET /api/Users/:id"
    else:
        doc["threats"][0]["verification_context"] = {"version": 1, "variants": []}
    assert plans_from(doc)[0].preparation == ()


def test_preparation_requires_an_accepted_owner_plan_and_cannot_escape_scope(tmp_path):
    ctx = _ctx(tmp_path, lambda *a, **k: pytest.fail("no request expected"),
               safe=False, read_only=False, env=ENV, idents=IDENTITIES[:2])
    ctx.plan, ctx.marker = plans_from(document())[0], MARKER
    args = {"method": "POST", "path": "/api/Notes", "role": "account-1", "json": {"text": "".join(MARKER)}}
    with pytest.raises(ToolError, match="no matching route"):
        Controller(ctx).before("http_request", args)
    c = Controller(ctx)
    c.plan = {"kind": "access-control", "owner": "account-1", "path": "/api/Notes/:id"}
    c.before("http_request", args)
    for changes in ({"role": "account-2"}, {"path": "https://evil.invalid/api/Notes"},
                    {"path": "/api/Users"}, {"json": {"text": "unmarked"}}):
        with pytest.raises(ToolError):
            ControllerWithPlan(ctx, c.plan).before("http_request", {**args, **changes})


def ControllerWithPlan(ctx, plan):
    c = Controller(ctx)
    c.plan = plan
    return c


@pytest.mark.parametrize("protected,public", [(False, False), (True, False), (False, True)])
def test_stateful_two_account_pilot(tmp_path, protected, public):
    """Old readiness blocks; new readiness permits real tool/proof flow over a stateful local fake.

    No fake verdict or proof checker: the transport models ownership and the planner
    proposes identical actions for vulnerable, protected and insufficient-proof cases.
    """
    state, calls = {}, []

    def transport(method, url, headers, **kw):
        calls.append((method, url))
        identity = headers.get("Authorization")
        if method == "POST":
            state.update(owner=identity, body=kw["json"])
            return Resp(201, '{"id":7}')
        if not identity and not public:
            return Resp(401, '{"error":"login required"}')
        if protected and identity != state["owner"]:
            return Resp(403, '{"error":"forbidden"}')
        return Resp(200, json.dumps(state["body"]))

    ctx = _ctx(tmp_path, transport, safe=False, read_only=False, env=ENV, idents=IDENTITIES[:2])
    ctx.plan, ctx.marker = plans_from(document())[0], MARKER
    ctx.budget = ctx.http._budget  # one shared run budget, as in the production runner
    ctx.evidence_dir = tmp_path / "evidence"
    requests = [
        {"tool": "plan_test", "args": {"kind": "access-control", "owner": "account-1",
         "path": "/api/Notes/:id", "hypothesis": "Other account reads the owner's private note", "strategy": STRATEGY}},
        {"tool": "http_request", "args": {"method": "POST", "path": "/api/Notes", "role": "account-1",
         "json": {"text": "".join(MARKER)}}},
        *[{"tool": "http_request", "args": {"path": "/api/Notes/7", **({"role": role} if role else {})}}
          for role in ("account-1", None, "account-2")],
    ]

    class Planner:
        def next_step(self, ctx, history):
            if len(history) < len(requests):
                return copy.deepcopy(requests[len(history)])
            if history[-1].get("tool") == "proof_feedback":
                return {"verdict": {"verdict": "inconclusive", "rationale": "Missing private-resource contrast"}}
            return {"verdict": {"verdict": "blocked-by-control" if protected else "confirmed",
                                "rationale": "Compare the same created note", "proof_steps": [2, 3, 4, 5]}}

    result = AgentProbe("access-control", Planner, max_steps=10).run(ctx)
    expected = "inconclusive" if public else "blocked-by-control" if protected else "confirmed"
    assert result.verdict == expected, result.rationale
    assert len(calls) == 4 and sum(method == "POST" for method, _ in calls) == 1
    assert ctx.budget.requests == 4


def test_unknown_cwe_is_unsupported_not_claimed_static_only():
    doc = document()
    doc["threats"][0]["cwe"] = "CWE-352"
    plan = plans_from(doc)[0]
    assert plan.status == "unsupported" and "no supported proof method" in plan.reason


def test_registration_evidence_can_link_separate_handlers_but_not_another_route():
    doc = document(file='routes/readNote.ts')
    doc['attack_surface'][0]['notes'] = 'handler: server.ts:427'
    registration = {'entry_point': 'GET /api/Notes/:id', 'notes': 'handler: server.ts:426'}
    doc['attack_surface'].append(registration)
    assert plans_from(doc)[0].preparation
    registration['entry_point'] = 'GET /api/Users/:id'
    assert plans_from(doc)[0].preparation == ()
    registration['entry_point'] = 'DELETE /api/Notes/:id'
    assert plans_from(doc)[0].preparation == ()
