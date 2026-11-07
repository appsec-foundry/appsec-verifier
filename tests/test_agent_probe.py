"""The agent loop runs a real two-identity IDOR contrast through the confined
tools and a scripted planner, and ends inconclusive (never refuted) when the
planner never submits (VER-008, VER-010, VER-024)."""

from __future__ import annotations

import pytest

from appsec_verifier.agent import AgentProbe, SourceReader
from appsec_verifier.auth import SessionManager
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.loader import FindingPlan
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient
from appsec_verifier.verify.probes import ProbeContext

SCOPE = {"base_url": "https://shop.example.com", "hosts": ["shop.example.com"], "ports": [443],
         "schemes": ["https"], "path_prefixes": ["/"]}


class Resp:
    def __init__(self, status=200, text='{"id":2,"UserId":2}'):
        self.status_code = status
        self.text = text
        self.headers = {}


class ScriptedPlanner:
    def __init__(self, steps):
        self.steps = list(steps)
        self.i = 0

    def next_step(self, ctx, history):
        if self.i < len(self.steps):
            s = self.steps[self.i]
            self.i += 1
            return s
        return {"verdict": {"verdict": "inconclusive", "rationale": "script ended"}}


def _ctx(tmp_path, transport):
    (tmp_path / "routes").mkdir(exist_ok=True)
    (tmp_path / "routes" / "basket.ts").write_text("get('/rest/basket/:id', (req)=>db.basket(req.params.id))\n")
    http = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits()), transport)
    idents = [{"role": "customer-a", "method": "bearer", "auth": {"token_env": "TA"}},
              {"role": "customer-b", "method": "bearer", "auth": {"token_env": "TB"}}]
    sessions = SessionManager(idents, http, env={"TA": "AAA", "TB": "BBB"})
    plan = FindingPlan(id="T-001", cwe="CWE-639", severity="High", title="Missing ownership check",
                       match_key="routes/basket.ts|CWE-639", instance="routes/basket.ts:1",
                       status="dynamic", cls="access-control", reason="p")
    return ProbeContext(plan=plan, scope=SCOPE, guard=ScopeGuard(SCOPE), budget=RunBudget(Limits()),
                        http=http, identities=idents, callback={}, safe=True, read_only=True,
                        sessions=sessions, source=SourceReader(tmp_path), target_base=SCOPE["base_url"])


def test_idor_two_identity_contrast_confirms():
    calls = []

    def transport(m, u, h, **k):
        calls.append((u, h.get("Authorization")))
        return Resp()

    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        ctx = _ctx(Path(d), transport)
        planner = ScriptedPlanner([
            {"tool": "read_source", "args": {"path": "routes/basket.ts", "around_line": 1}},
            {"tool": "http_request", "args": {"role": "customer-a", "method": "GET", "path": "/rest/basket/2"}},
            {"tool": "http_request", "args": {"role": "customer-b", "method": "GET", "path": "/rest/basket/2"}},
            {"verdict": {"verdict": "confirmed", "confidence": "high",
                         "rationale": "customer-a read customer-b's basket",
                         "identities_used": ["customer-a", "customer-b"],
                         "proof": {"identity_a": "customer-a", "identity_b": "customer-b",
                                   "observed_difference": "a received b's basket (UserId 2)"}}},
        ])
        res = AgentProbe("access-control", lambda: planner, max_steps=10).run(ctx)

    assert res.verdict == "confirmed" and res.confidence == "high"
    assert res.identities_used == ["customer-a", "customer-b"]
    # the two requests carried the two identities' distinct sessions
    assert [a for _, a in calls] == ["Bearer AAA", "Bearer BBB"]


def test_planner_never_submits_is_inconclusive_not_refuted():
    import tempfile
    from pathlib import Path

    class LoopPlanner:
        def next_step(self, ctx, history):
            return {"tool": "read_source", "args": {"path": "routes/basket.ts", "around_line": 1}}

    with tempfile.TemporaryDirectory() as d:
        ctx = _ctx(Path(d), lambda m, u, h, **k: Resp())
        res = AgentProbe("access-control", LoopPlanner, max_steps=3).run(ctx)
    assert res.verdict == "inconclusive"
    assert res.limits_hit == "attempts"


@pytest.mark.parametrize("action", [
    {"tool": "http_request", "args": {"path": "/", "headers": {"X-Forwarded-For": "127.0.0.1"}}},  # extra arg
    {"tool": "http_request", "args": {"path": 5}},                                                  # wrong type
    {"tool": "http_request", "args": {"path": "/", "params": {"q": {"nested": 1}}}},                # nested param
    {"tool": "http_request", "args": "path=/"},                                                     # not an object
    {"tool": "shell", "args": {"cmd": "id"}},                                                       # unknown tool
    {"tool": "submit_verdict", "args": {"verdict": "confirmed", "rationale": "x"}},                 # verdict as tool
    {"tool": "http_request", "args": {"path": "/"}, "extra": True},                                 # extra key
    {"verdict": {"verdict": "confirmed", "rationale": "x", "identities_used": "customer-a"}},       # bad verdict
    "GET /",                                                                                        # not a dict
])
def test_every_action_is_schema_checked_whichever_planner_sent_it(tmp_path, action):
    sent = []
    ctx = _ctx(tmp_path, lambda m, u, h, **k: sent.append(u) or Resp())
    res = AgentProbe("access-control", lambda: ScriptedPlanner([action]), max_steps=3).run(ctx)
    assert res.verdict == "inconclusive"
    assert sent == []   # nothing ran


def test_planner_and_report_never_see_a_credential_value(tmp_path):
    """The target echoes the bearer token; the planner's history and the written
    results carry "[redacted]" instead, even where the model repeats it (VER-016)."""
    import json
    from pathlib import Path as P

    from appsec_verifier.agent import agent_registry
    from appsec_verifier.verify import run_verification

    seen = []

    class EchoPlanner:
        def next_step(self, ctx, history):
            seen.append(json.dumps(history))
            if not history:
                return {"tool": "http_request", "args": {"role": "customer-a", "path": "/whoami"}}
            if len(history) == 1:
                return {"tool": "http_request", "args": {"role": "customer-a", "path": "/AAA-not-a-secret"}}
            return {"verdict": {"verdict": "inconclusive", "rationale": "saw token AAA-SECRET-TOKEN echoed",
                                "observations": ["Bearer AAA-SECRET-TOKEN"]}}

    ctx = _ctx(tmp_path, lambda m, u, h, **k: Resp(200, f'{{"auth":"{h.get("Authorization")}"}}'))
    ctx.sessions._env = {"TA": "AAA-SECRET-TOKEN", "TB": "BBB-SECRET-TOKEN"}
    doc = run_verification(
        assessment_path=P("a.yaml"), scope=SCOPE, scope_path=P("s.yaml"), plans=[ctx.plan], limits=Limits(),
        identities=ctx.identities, registry=agent_registry(EchoPlanner), verifier_version="t",
        target_base=SCOPE["base_url"], authorization={"confirmed": True}, http=ctx.http, sessions=ctx.sessions,
        source=ctx.source)
    assert seen and all("SECRET-TOKEN" not in h for h in seen)
    assert "[redacted]" in seen[1]
    assert "SECRET-TOKEN" not in json.dumps(doc)
    assert doc["results"][0]["rationale"] == "saw token [redacted] echoed"


def test_closed_window_stops_the_finding_before_any_model_call(tmp_path):
    from datetime import datetime, timezone

    sent, asked = [], []

    class Planner:
        def next_step(self, ctx, history):
            asked.append(1)
            return {"tool": "http_request", "args": {"path": "/"}}

    ctx = _ctx(tmp_path, lambda m, u, h, **k: sent.append(u) or Resp())
    scope = dict(SCOPE, window={"until": "2026-01-01T00:00:00Z"})
    ctx.guard = ScopeGuard(scope, clock=lambda: datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc))
    res = AgentProbe("access-control", Planner, max_steps=3).run(ctx)
    assert res.verdict == "inconclusive" and res.limits_hit == "window"
    assert asked == [] and sent == []
