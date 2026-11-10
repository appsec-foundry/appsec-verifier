"""Access-control proof without an operator test resource (VER-010, VER-041): a resource a normal account creates
with the finding's marker, or a privileged function compared with a privileged account. Both count at medium
confidence, only the code's check confirms them, and an operator's test resource takes precedence."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_agent_tools import SCOPE, Resp, _ctx
from test_endpoints import _blocker, _plan
from test_experiments import STRATEGY

from appsec_verifier.agent.controller import Controller
from appsec_verifier.agent.prompts import _system
from appsec_verifier.agent.proof import check_proof
from appsec_verifier.agent.tools import AgentTools, ToolError, _created_ids
from appsec_verifier.endpoints import Endpoint
from appsec_verifier.verification_context import record_segment
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
         complete=True):
    args = {"path": path, "method": method, **({"role": role} if role else {}), **({"json": json} if json else {}),
            **({"params": params} if params else {})}
    sha = hashlib.sha256(body.encode()).hexdigest()
    return {"tool": "http_request", "args": args,
            "result": {"role": role, "status": status, "length": len(body), "body_sha256": sha},
            "_response": {"body": body, "complete": complete, "identity": session or role or "anonymous",
                          "digest": sha}}


def _check(history, verdict="confirmed", cited=None, scope=None, cwe="CWE-639", owned=()):
    history = copy.deepcopy(history)
    responses = {n: h.pop("_response") for n, h in enumerate(history, 1) if "_response" in h}
    ctx = SimpleNamespace(plan=SimpleNamespace(id="T-1", cls="access-control", cwe=cwe), scope=scope or {},
                          identities=ROLES, marker=MARKER, responses=responses, sessions=None, evidence_dir=None,
                          owned=set(owned))
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
])
def test_an_own_resource_without_the_full_contrast_stays_inconclusive(history, reason):
    result = _check(history)
    assert result.verdict == "inconclusive" and reason in result.rationale


def test_steps_before_the_latest_plan_count_for_a_confirmation_but_not_for_a_negative_verdict():
    """VER-043: the plan guides; a revised plan does not discard the contrast already recorded. A negative
    verdict still needs attempts after its plan (VER-013)."""
    assert _check([*owned()[1:], owned()[0]]).verdict == "confirmed"      # all sent before the (revised) plan
    assert _check([owned()[1], owned()[0], *owned()[2:]]).verdict == "confirmed"
    forbidden = owned('{"error":"forbidden"}', 403)
    assert _check(forbidden, "blocked-by-control").verdict == "blocked-by-control"
    result = _check([*forbidden[1:], forbidden[0]], "blocked-by-control")
    assert result.verdict == "inconclusive" and "fresh test attempt" in result.rationale


def test_an_assumption_still_listed_as_missing_does_not_block_the_proof():
    history = owned()
    history[0]["args"]["strategy"]["prerequisites"] = [{"condition": "no ownership predicate", "status": "missing"}]
    assert _check(history).verdict == "confirmed"


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


def test_answers_alike_only_after_redaction_are_not_identical():
    history = privileged()
    for h, name in ((history[1], "admin@shop"), (history[3], "jim@shop")):    # each names its own, redacted, user
        h["_response"]["digest"] = hashlib.sha256(name.encode()).hexdigest()
    result = _check(history)
    assert result.verdict == "inconclusive" and "identical answer" in result.rationale
    history[1]["_response"].pop("digest")
    history[3]["_response"].pop("digest")
    assert "not answered with content" in _check(history).rationale  # without digests nothing counts as identical


def test_privileged_negative_verdicts():
    assert _check(privileged('{"error":"forbidden"}', 403), "blocked-by-control").verdict == "blocked-by-control"
    result = _check(privileged(), "blocked-by-control")
    assert result.verdict == "inconclusive" and "received the privileged answer" in result.rationale
    result = _check(privileged(normal='{"other":1}'), "not-reproducible")
    assert result.verdict == "inconclusive" and "does not show that the function is protected" in result.rationale


# ── a write on the owner's resource (VER-010) ─────────────────────────────────

SECOND = MARKER[0] + "c0ffee00"
CHANGE = {"method": "PUT", "path": "/api/Feedbacks/:id"}


def changed(after=f'{{"comment":"{SECOND}"}}', change_status=200, change_path="/api/Feedbacks/7"):
    return [_plan_step(owner="account-1", change=CHANGE, second_marker=SECOND),
            _req("account-1", '{"data":{"id":7}}', 201, "POST", "/api/Feedbacks", json={"comment": M}),
            _req("account-1", f'{{"comment":"{M}"}}'),
            _req("account-2", '{"status":"ok"}', change_status, "PUT", change_path, json={"comment": SECOND}),
            _req("account-1", after)]


def test_another_account_changing_the_owners_record_confirms_at_medium():
    result = _check(changed(), owned={"7"})
    assert result.verdict == "confirmed" and result.confidence == "medium"
    assert result.proof["marker"] == M and result.proof["second_marker"] == SECOND
    assert "another account wrote to" in result.proof["scope"]


@pytest.mark.parametrize("history, created, reason", [
    (changed(after=f'{{"comment":"{M}"}}'), {"7"}, "does not show the second marker"),
    (changed(change_path="/api/Feedbacks/8"), {"7"}, "must name the record the owner's write created"),
    (changed(), set(), "must name the record the owner's write created"),
    (_change(changed(), 3, role="account-1"), {"7"}, "the owner sent the second marker itself"),
    (_change(changed(), 3, role=None), {"7"}, "neither the owner's creation nor the other account's change"),
    (_change(changed(), 3, role="admin-1"), {"7"}, "neither the owner's creation nor the other account's change"),
    (_change(changed(), 3, identity="account-1"), {"7"}, "the owner's own session"),
    (changed()[:2] + changed()[3:], {"7"}, "does not show the marker before the change"),
    (changed()[:4], {"7"}, "cite the owner's read after the change"),
    (_change(changed(), 4, params={"q": SECOND}), {"7"}, "the owner sent the second marker itself"),
    (_change(changed(), 1, role="account-2"), {"7"}, "an identity other than the owner sent the marker"),
])
def test_a_write_proof_without_the_full_sequence_stays_inconclusive(history, created, reason):
    result = _check(history, owned=created)
    assert result.verdict == "inconclusive" and reason in result.rationale


def test_write_proof_negative_verdicts():
    refused = changed(after=f'{{"comment":"{M}"}}', change_status=403)
    assert _check(refused, "blocked-by-control", owned={"7"}).verdict == "blocked-by-control"
    result = _check(changed(change_status=403), "blocked-by-control", owned={"7"})
    assert result.verdict == "inconclusive" and "the change went through" in result.rationale
    result = _check(changed(after=f'{{"comment":"{M}"}}'), "not-reproducible", owned={"7"})
    assert result.verdict == "inconclusive" and "only a 403 or 404" in result.rationale


def _change_controller(tmp_path, plan=None, owned=(), created=None):
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(), safe=False, read_only=False, env=ENV, idents=IDENTITIES)
    ctx.plan = replace(ctx.plan, endpoints=(Endpoint("POST", "/api/Feedbacks", None),
                                            Endpoint("PUT", "/api/Feedbacks/:id", None)))
    ctx.marker, ctx.owned = MARKER, set(owned)
    ctx.created = set(owned) if created is None else set(created)
    c = Controller(ctx)
    c.plan = plan
    return c


def test_a_change_plan_reads_the_changed_path_although_the_finding_names_no_get(tmp_path):
    args = _plan_args(owner="account-1", change=CHANGE)
    args["path"] = "/api/Feedbacks/:id"
    _change_controller(tmp_path).before("plan_test", args)
    with pytest.raises(ToolError, match="no matching route"):
        _change_controller(tmp_path).before("plan_test", {k: v for k, v in args.items() if k != "change"})
    with pytest.raises(ToolError, match="change must be a write request this finding names"):
        _change_controller(tmp_path).before("plan_test", {**args, "change": {"method": "PATCH",
                                                                             "path": "/api/Feedbacks/:id"}})


def test_only_another_normal_account_changes_and_only_the_record_the_owner_created(tmp_path):
    plan = {"kind": "access-control", "path": "/api/Feedbacks/:id", "owner": "account-1", "change": CHANGE,
            "second_marker": SECOND}
    c = _change_controller(tmp_path, plan, owned={"7"})
    c.before("http_request", {"path": "/api/Feedbacks/7", "method": "PUT", "role": "account-2",
                              "json": {"comment": SECOND}})
    for role, path in (("account-2", "/api/Feedbacks/8"), ("account-1", "/api/Feedbacks/7"),
                       (None, "/api/Feedbacks/7"), ("admin-1", "/api/Feedbacks/7")):
        with pytest.raises(ToolError, match="must not name an existing record|accepted test plan"):
            c.before("http_request", {"path": path, "method": "PUT", "role": role, "json": {"comment": SECOND}})
    with pytest.raises(ToolError, match="must carry"):
        c.before("http_request", {"path": "/api/Feedbacks/7", "method": "PUT", "role": "account-2",
                                  "json": {"comment": "x"}})
    for role in ("account-1", None, "account-2"):
        c.before("http_request", {"path": "/api/Feedbacks/7", "role": role})          # the derived read
    with pytest.raises(ToolError, match="may read only the record the owner created"):
        c.before("http_request", {"path": "/api/Feedbacks/8", "role": "account-2"})
    plain = _change_controller(tmp_path, {**{k: v for k, v in plan.items() if k != "change"}}, owned={"7"})
    with pytest.raises(ToolError, match="no matching route"):
        plain.before("http_request", {"path": "/api/Feedbacks/7", "role": "account-1"})  # no change, no GET
    # The creating answer named 7, but the owner's read has not shown the marker there yet: read, never change.
    unread = _change_controller(tmp_path, plan, owned=(), created={"7"})
    unread.before("http_request", {"path": "/api/Feedbacks/7", "role": "account-1"})
    with pytest.raises(ToolError, match="must not name an existing record"):
        unread.before("http_request", {"path": "/api/Feedbacks/7", "method": "PUT", "role": "account-2",
                                       "json": {"comment": SECOND}})


def test_a_change_plan_gets_a_second_marker_of_the_verifier(tmp_path):
    result = _tools(tmp_path).plan_test(**_plan_args(owner="account-2", change=CHANGE))
    assert result["marker"] == M and result["second_marker"].startswith(MARKER[0])
    assert result["second_marker"] != M and result["experiment"]["second_marker"] == result["second_marker"]
    with pytest.raises(ToolError, match="invalid experiment declaration"):
        _tools(tmp_path).plan_test(**_plan_args(reference="admin-1", change=CHANGE))      # change only with owner
    with pytest.raises(ToolError, match="changes a record by its identifier"):
        _tools(tmp_path).plan_test(**_plan_args(owner="account-2", change={"method": "POST", "path": "/api/Feedbacks"}))
    with pytest.raises(ToolError, match="invalid experiment declaration"):
        _tools(tmp_path).plan_test(**_plan_args(owner="account-2", second_marker="mine"))  # never the model's


def test_a_change_may_name_what_the_owner_created_and_then_read_with_its_marker(tmp_path):
    reads = {"7": f'{{"comment":"{M}"}}', "8": '{"comment":"someone else"}'}

    def transport(m, u, h, **k):
        if m == "POST":
            return Resp(201, '{"status":"success","data":{"id":7,"UserId":2,"owner":{"id":1}},"flag":true}')
        return Resp(200, reads.get(u.rsplit("/", 1)[1], "{}"))

    tools = _tools(tmp_path, transport=transport)
    args = _plan_args(owner="account-1", change=CHANGE)
    tools.plan_test(**{**args, "path": "/api/Feedbacks/:id"})
    tools.http_request(role="account-2", method="POST", path="/api/Feedbacks", json={"comment": M})
    assert tools.ctx.created == set()                                  # only the owner's write creates
    tools.http_request(role="account-1", method="POST", path="/api/Feedbacks", json={"comment": M})
    assert tools.ctx.created == {"7"} and tools.ctx.owned == set()     # not its owner's id 1, not yet read
    tools.http_request(role="account-2", path="/api/Feedbacks/7")
    assert tools.ctx.owned == set()                                    # only the owner's read confirms
    tools.http_request(role="account-1", path="/api/Feedbacks/8")
    assert tools.ctx.owned == set()                                    # never created
    tools.http_request(role="account-1", path="/api/Feedbacks/7")
    assert tools.ctx.owned == {"7"}


def test_a_write_proof_runs_through_the_loop_and_changes_only_the_created_record(tmp_path):
    """The owner creates, another account changes the record by the identifier the creation returned, and the
    owner's next read shows the second marker; the change of any other record never reaches the target."""
    from urllib.parse import urlsplit

    from appsec_verifier.agent import AgentProbe

    store, writes = {"1": "someone else's"}, []

    def transport(m, u, h, **k):
        path = urlsplit(u).path
        if m == "POST" and path == "/api/Feedbacks":
            store["7"] = k["json"]["comment"]
            writes.append((m, path))
            return Resp(201, '{"status":"success","data":{"id":7}}')
        if m == "PUT":
            writes.append((m, path))
            store[path.rsplit("/", 1)[1]] = k["json"]["comment"]
            return Resp(200, '{"status":"success"}')
        if "token-" not in str(h):
            return Resp(401, '{"error":"login"}')
        return Resp(200, json.dumps({"comment": store.get(path.rsplit("/", 1)[1], "")}))

    class Planner:
        def __init__(self):
            self.second = None

        def next_step(self, ctx, history):
            n = len(history)
            if n == 1:
                self.second = history[0]["result"]["second_marker"]
            steps = [
                {"tool": "plan_test", "args": {**_plan_args(owner="account-1", change=CHANGE),
                                               "path": "/api/Feedbacks/:id"}},
                {"tool": "http_request", "args": {"role": "account-1", "method": "POST", "path": "/api/Feedbacks",
                                                  "json": {"comment": M}}},
                {"tool": "http_request", "args": {"role": "account-1", "path": "/api/Feedbacks/7"}},
                {"tool": "http_request", "args": {"role": "account-2", "method": "PUT", "path": "/api/Feedbacks/1",
                                                  "json": {"comment": self.second}}},
                {"tool": "http_request", "args": {"role": "account-2", "method": "PUT", "path": "/api/Feedbacks/7",
                                                  "json": {"comment": self.second}}},
                {"tool": "http_request", "args": {"role": "account-1", "path": "/api/Feedbacks/7"}},
                {"verdict": {"verdict": "confirmed", "rationale": "changed", "proof_steps": [2, 3, 5, 6]}},
            ]
            return steps[n]

    ctx = _ctx(tmp_path, transport, safe=False, read_only=False, env=ENV, idents=IDENTITIES)
    ctx.plan = replace(ctx.plan, endpoints=(Endpoint("POST", "/api/Feedbacks", None),
                                            Endpoint("PUT", "/api/Feedbacks/:id", None)))
    ctx.marker = MARKER
    result = AgentProbe("access-control", Planner).run(ctx)
    assert result.verdict == "confirmed" and result.confidence == "medium", result.rationale
    assert writes == [("POST", "/api/Feedbacks"), ("PUT", "/api/Feedbacks/7")]   # /api/Feedbacks/1 was refused
    assert store["1"] == "someone else's" and store["7"].startswith(MARKER[0]) and store["7"] != M


@pytest.mark.parametrize("body, location, expected", [
    ('{"id": 7, "UserId": 2}', None, {"7"}),
    ('{"data": {"id": "x9"}}', "/api/Feedbacks/12", {"x9", "12"}),
    ('{"id": 7, "owner": {"id": 1}, "items": [{"id": 2}]}', None, {"7"}),   # a nested record is not the created one
    ('{"data": {"user": {"id": 1}}}', None, set()),
    ('{"id": true}', None, set()),
    ('{"id": "a/b"}', None, set()),
    ("not json", "https://shop.example.com/api/Items/3f2504e0-4f89-11d3-9a0c-0305e82c3301",
     {"3f2504e0-4f89-11d3-9a0c-0305e82c3301"}),
])
def test_the_identifiers_a_creating_answer_returns(body, location, expected):
    assert _created_ids(body, location) == expected


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


def test_the_digest_tells_apart_answers_that_redaction_made_alike(tmp_path):
    """Each account's answer names its own credential: the same after redaction, different underneath. A list
    naming both is the same for both. Neither the value nor a plain hash of it is kept."""
    def own(m, u, h, **k):
        return Resp(200, '{"user":"token-admin-1"}' if "token-admin-1" in str(h) else '{"user":"token-account-1"}')

    def answers(transport):
        tools = _tools(tmp_path, transport=transport)
        out = []
        for role in ("account-1", "admin-1"):
            tools.http_request(role=role, path="/rest/basket/2")
            out.append(tools.take_response())
        return out

    mine, theirs = answers(own)
    assert mine["body"] == theirs["body"] and mine["digest"] != theirs["digest"]
    assert "token-account-1" not in str(mine) and hashlib.sha256(b'{"user":"token-account-1"}').hexdigest() \
        not in str(mine)
    listing = answers(lambda *a, **k: Resp(200, '{"users":["token-account-1","token-admin-1"]}'))
    assert listing[0]["digest"] == listing[1]["digest"]


# ── who may write under the plan ──────────────────────────────────────────────

def _controller(tmp_path, plan):
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(), safe=False, read_only=False, env=ENV, idents=IDENTITIES)
    ctx.plan = replace(ctx.plan, endpoints=(Endpoint("POST", "/api/Feedbacks", None),
                                            Endpoint("GET", "/api/Feedbacks/:id", None)))
    ctx.marker = MARKER
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
        c.before("http_request", {"path": "/api/Feedbacks", "method": "POST", "role": "account-1", "json": {"x": M}})


def test_a_write_carries_the_marker_and_names_no_existing_record(tmp_path):
    """VER-014: what a write changes can be found by the finding's marker, and no write changes a record named by
    its identifier in the path, since that record may belong to someone else."""
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(), safe=False, read_only=False, env=ENV, idents=IDENTITIES)
    ctx.plan = replace(ctx.plan, endpoints=tuple(Endpoint(m, p, None) for m, p in (
        ("POST", "/api/Feedbacks"), ("PUT", "/api/Feedbacks/:id"), ("PATCH", "/api/Items/7"),
        ("POST", "/rest/basket/:bid/checkout"), ("GET", "/api/Feedbacks/:id"))))
    ctx.marker = MARKER
    c = Controller(ctx)
    with pytest.raises(ToolError, match=f"must carry {MARKER[0]}"):
        c.before("http_request", {"path": "/api/Feedbacks", "method": "POST", "role": "account-1",
                                  "json": {"comment": "hello"}})
    for path, method in (("/api/Feedbacks/1", "PUT"), ("/api/Items/7", "PATCH"), ("/rest/basket/1/checkout", "POST"),
                         (f"/api/Feedbacks/{M}", "PUT")):           # a placeholder names a record, whatever fills it
        with pytest.raises(ToolError, match="must not name an existing record"):
            c.before("http_request", {"path": path, "method": method, "role": "account-1", "json": {"comment": M}})
    c.before("http_request", {"path": "/api/Feedbacks", "method": "POST", "role": "account-1", "json": {"comment": M}})
    c.before("http_request", {"path": "/api/Feedbacks/1", "role": "account-1"})        # reads stay as they are
    ctx.marker = ("", "")
    with pytest.raises(ToolError, match="no marker"):
        c.before("http_request", {"path": "/api/Feedbacks", "method": "POST", "role": "account-2",
                                  "json": {"comment": M}})


def test_an_operator_test_resource_is_written_as_declared(tmp_path):
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(), safe=False, read_only=False, env=ENV, idents=IDENTITIES)
    ctx.scope = {**ctx.scope, "test_resources": [{**RESOURCE, "finding_id": ctx.plan.id, "path": "/api/Feedbacks/2",
                                                  "method": "PUT"}]}
    Controller(ctx).before("http_request", {"path": "/api/Feedbacks/2", "method": "PUT", "role": "account-2",
                                            "json": {"c": "declared"}})


@pytest.mark.parametrize("template, path, expected", [
    ("/api/Feedbacks", None, None),
    ("/profile/image/url", "/profile/image/url", None),
    ("/rest/basket/:id/coupon/:coupon", None, ":id"),
    ("/api/Users/{uid}/role", "/api/Users/me/role", "me"),
    ("/api/Items/<item>", "/api/Items/3f2504e0-4f89-11d3-9a0c-0305e82c3301", "3f2504e0-4f89-11d3-9a0c-0305e82c3301"),
    ("/api/Items/7", "/api/Items/7", "7"),
])
def test_the_record_a_path_names(template, path, expected):
    assert record_segment(template, path) == expected


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


def test_an_access_finding_without_a_request_its_proof_can_use_is_not_tested():
    """Without source, missing preparation blocks testing. Source permits diagnosis, not DELETE (VER-014)."""
    put, delete, get = (Endpoint(m, "/api/Items/:id", True) for m in ("PUT", "DELETE", "GET"))
    two, admin = ROLES[:2], ROLES[2:]
    for endpoints in ((put,), (delete,), (put, delete)):
        plan = _plan("access-control", *endpoints)
        assert _blocker(plan, identities=two + admin, safe=False, source=False)[0] == "access"
        assert _blocker(plan, identities=two + admin, safe=False, source=True) is None
        assert _blocker(plan, identities=two, safe=False, source=False, scope={"test_resources": [RESOURCE]}) is None
    post = Endpoint("POST", "/api/Items", True)
    assert _blocker(_plan("access-control", post, get), identities=two, safe=False, source=False) is None
    # a write that names an existing record never creates one (VER-014); the comparison still can read
    assert _blocker(_plan("access-control", put, get), identities=two, safe=False, source=False)[0] == "access"
    assert _blocker(_plan("access-control", put, get), identities=two + admin, safe=False, source=False) is None
    assert _blocker(_plan("access-control", get), identities=two, safe=False, source=False)[0] == "access"
    # a write proof creates, changes by identifier and reads the changed path (VER-010)
    assert _blocker(_plan("access-control", post, put), identities=two, safe=False, source=False) is None
    assert _blocker(_plan("access-control", post), identities=two, safe=False, source=False)[1].startswith("no GET")
    assert _blocker(_plan("access-control", get), identities=two[:1] + admin, safe=False, source=False) is None
    assert _blocker(_plan("access-control"), identities=two + admin, safe=False) is None  # the route rule decides


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
