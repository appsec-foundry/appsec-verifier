"""VER-067: prove a read of an existing record by the account it names, without writes."""
from __future__ import annotations

import base64
import copy
import io
import json
from dataclasses import replace

import pytest
from test_agent_tools import Resp, _ctx
from test_endpoints import _blocker, _plan
from test_experiments import STRATEGY

from appsec_verifier.agent.controller import Controller
from appsec_verifier.agent.experiments import access_methods
from appsec_verifier.agent.loop import AgentProbe
from appsec_verifier.agent.prompts import _system
from appsec_verifier.agent.tools import AgentTools, ToolError
from appsec_verifier.loader import plans_from

USERS = {"1": "alice@example.com", "2": "bob@example.com", "3": "carol@example.com"}
NAMED = [{"role": "account-1", "method": "basic", "auth": {"username_env": "U1", "password_env": "P1"}},
         {"role": "account-2", "method": "basic", "auth": {"username_env": "U2", "password_env": "P2"}},
         {"role": "admin-1", "method": "basic", "auth": {"username_env": "U3", "password_env": "P3"},
          "privileged": True}]
ENV = {"U1": USERS["1"], "P1": "pw-account-1", "U2": USERS["2"], "P2": "pw-account-2", "U3": USERS["3"],
       "P3": "pw-admin-1"}
TOKENS = [{"role": "account-1", "method": "bearer", "auth": {"token_env": "A"}},
          {"role": "account-2", "method": "bearer", "auth": {"token_env": "B"}}]


def document():
    return {"threats": [{"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "Read another user's profile",
                         "scenario": "GET /api/users/:id", "evidence": {"file": "routes/users.ts", "line": 20}}]}


def requester(headers):
    value = headers.get("Authorization", "")
    if not value.startswith("Basic "):
        return None
    user = base64.b64decode(value[6:]).decode().split(":", 1)[0]
    return next(i for i, name in USERS.items() if name == user)


def target(kind):
    """A fake user API: `kind` decides what another account's read of the owner's record gets."""
    def transport(method, url, headers, **kw):
        assert method == "GET", "the existing-record proof only reads"
        record = url.rsplit("/", 1)[1]
        me = requester(headers)
        if me is None and kind != "public":
            return Resp(401, '{"error":"login required"}')
        if kind == "protected" and me != record:
            return Resp(403, '{"error":"forbidden"}')
        if kind == "own-only" and me != record:
            record = me
        if kind == "list":
            return Resp(200, json.dumps({"data": [{"id": i, "email": e} for i, e in USERS.items()]}))
        body = {"id": int(record), "plan": "basic"} if kind == "unnamed" else {"id": int(record),
                                                                              "email": USERS[record]}
        if kind == "viewer":
            body["viewer"] = USERS[me]
        return Resp(200, json.dumps({"status": "success", "data": body}))
    return transport


def context(tmp_path, transport, *, identities=NAMED, safe=True):
    ctx = _ctx(tmp_path, transport, safe=safe, read_only=safe, env=ENV | {"A": "token-1", "B": "token-2"},
               idents=copy.deepcopy(identities))
    ctx.plan, ctx.marker = plans_from(document())[0], ("vrf1a2b3c4d", "5e6f7a8b")
    ctx.assume_restrictions = True
    ctx.budget = ctx.http._budget
    ctx.evidence_dir = tmp_path / "evidence"
    return ctx


PLAN = {"kind": "access-control", "existing": "account-1", "path": "/api/users/:id",
        "hypothesis": "Another account reads the owner's profile by its id", "strategy": STRATEGY}
READS = [{"tool": "http_request", "args": {"path": "/api/users/1", **({"role": role} if role else {})}}
         for role in ("account-1", None, "account-2")] + [
    {"tool": "http_request", "args": {"path": "/api/users/2", "role": "account-2"}}]


def run(ctx, verdict, steps=None):
    steps = [{"tool": "plan_test", "args": PLAN}, *READS] if steps is None else steps

    class Planner:
        def next_step(self, ctx, history):
            if len(history) < len(steps):
                return copy.deepcopy(steps[len(history)])
            if history[-1].get("tool") == "proof_feedback":
                return {"verdict": {"verdict": "inconclusive", "rationale": "the proof check did not accept it"}}
            return {"verdict": {"verdict": verdict, "rationale": "Compare the owner's existing record",
                                "proof_steps": list(range(2, len(steps) + 1))}}

    return AgentProbe("access-control", Planner, max_steps=10).run(ctx)


def test_another_account_reading_a_record_that_names_its_owner_confirms_in_safe_mode(tmp_path):
    ctx = context(tmp_path, target("vulnerable"))
    result = run(ctx, "confirmed")
    assert (result.verdict, result.confidence) == ("confirmed", "medium"), result.rationale
    assert result.proof["form"] == "named-record"
    assert result.proof["access_restriction"]["assumed"] is True
    assert result.proof["access_restriction"]["allowed_roles"] == ["account-1"]
    assert "nothing was created" in result.proof["scope"]


@pytest.mark.parametrize("kind,why", [
    ("public", "visible without a login"),
    ("list", "names its user name and no other account's"),
    ("unnamed", "names its user name and no other account's"),
    ("viewer", "identical answer"),
])
def test_a_record_that_does_not_single_out_its_owner_confirms_nothing(tmp_path, kind, why):
    """Public, naming every account, naming none, or naming whoever asks: the record is not shown to be the owner's,
    or the other account did not get the owner's answer."""
    ctx = context(tmp_path, target(kind))
    result = run(ctx, "confirmed")
    assert result.verdict == "inconclusive"
    assert why in result.rationale


def test_the_other_accounts_own_record_must_name_it(tmp_path):
    steps = [{"tool": "plan_test", "args": PLAN}, *READS[:3]]
    result = run(context(tmp_path, target("vulnerable")), "confirmed", steps)
    assert result.verdict == "inconclusive"
    assert "read of its own record must name its user name" in result.rationale


@pytest.mark.parametrize("kind,verdict", [("protected", "blocked-by-control"), ("own-only", "not-reproducible")])
def test_a_refused_or_different_answer_for_the_other_account_is_a_negative_verdict(tmp_path, kind, verdict):
    result = run(context(tmp_path, target(kind)), verdict)
    assert (result.verdict, result.confidence) == (verdict, "medium"), result.rationale


def test_a_negative_verdict_is_refused_when_the_other_account_got_the_record(tmp_path):
    result = run(context(tmp_path, target("vulnerable")), "not-reproducible")
    assert result.verdict == "inconclusive"
    assert "present for the other account" in result.rationale


def test_accounts_without_a_user_name_cannot_plan_it(tmp_path):
    """A bearer token or pasted session names no user name a record could contain; safe mode then has no proof
    for an IDOR, as before."""
    tools = AgentTools(context(tmp_path, target("vulnerable"), identities=TOKENS))
    with pytest.raises(ToolError, match="sign in with a user name"):
        tools.plan_test(**PLAN)
    assert access_methods("T-1", "CWE-639", {}, TOKENS, writes=False) == []
    assert access_methods("T-1", "CWE-639", {}, NAMED, writes=False) == ["existing"]
    assert access_methods("T-1", "CWE-306", {}, NAMED, writes=False) == ["signed_in"]     # exposure: unchanged


def test_only_a_normal_account_owns_the_record_and_the_plan_only_reads(tmp_path):
    """Even in intrusive mode and with a write the finding names, the accepted plan sends no write: the owner may
    write only under an own-resource plan (VER-010)."""
    ctx = context(tmp_path, target("vulnerable"), safe=False)
    doc = document()
    doc["threats"][0]["scenario"] += " and PUT /api/users/:id"
    ctx.plan = plans_from(doc)[0]
    tools = AgentTools(ctx)
    with pytest.raises(ToolError, match="normal account"):
        tools.plan_test(**{**PLAN, "existing": "admin-1"})
    with pytest.raises(ToolError, match="read with GET"):
        tools.plan_test(**{**PLAN, "method": "PUT"})
    tools.plan_test(**PLAN)
    controller = Controller(ctx)
    controller.plan = {k: v for k, v in PLAN.items() if k != "strategy"}
    controller.before("http_request", {"role": "account-2", "path": "/api/users/1"})
    for role in ("account-1", "account-2"):
        for path, value in (("/api/users/1", "vrf1a2b3c4d"), ("/api/users", "vrf1a2b3c4d")):
            with pytest.raises(ToolError):
                controller.before("http_request", {"role": role, "method": "PUT", "path": path,
                                                   "json": {"email": value}})


def test_the_test_plan_tests_an_idor_in_safe_mode_with_named_accounts():
    plan = replace(_plan("access-control"), cwe="CWE-639")
    assert _blocker(plan, identities=NAMED, safe=True) is None
    assert _blocker(plan, identities=TOKENS, safe=True)[0] == "intrusive"


def test_the_agent_is_told_of_the_proof_and_not_to_search_for_a_creation_route(tmp_path):
    ctx = context(tmp_path, target("vulnerable"), safe=False)
    text = _system(ctx)
    assert "Existing-record proof (VER-067)" in text
    assert "No request of this finding, no evidenced preparation" in text
    assert "prefer it to searching for a creation route" in text
    tokens = context(tmp_path, target("vulnerable"), identities=TOKENS, safe=False)
    assert "Existing-record proof" not in _system(tokens)
    assert "report that missing prerequisite" in _system(tokens)


def test_a_run_that_may_write_does_not_claim_to_test_findings_at_the_same_time():
    from appsec_verifier.progress import ParallelProgress, RunProgress

    plans = [replace(_plan("xss"), id="T-1"), replace(_plan("xss"), id="T-2")]
    for writes, shown in ((False, True), (True, False)):
        stream = io.StringIO()
        ParallelProgress(RunProgress(stream, live=False, env={}), 4, writes=writes).begin(plans)
        assert ("findings are tested at the same time" in stream.getvalue()) is shown
