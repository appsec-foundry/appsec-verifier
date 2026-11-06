"""The agent loop runs a real two-identity IDOR contrast through the confined
tools and a scripted planner, and ends inconclusive (never refuted) when the
planner never submits (VER-008, VER-010, VER-024)."""

from __future__ import annotations

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
