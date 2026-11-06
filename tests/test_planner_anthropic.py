"""Anthropic planner: tool schemas, message threading, and response parsing are
tested with a fake client (no network); a scripted model drives a real IDOR
contrast through the confined tools (VER-028, VER-017). The live network call is
not exercised in this environment."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from appsec_verifier.agent import AgentProbe, AnthropicPlanner, agent_registry
from appsec_verifier.agent.planner_anthropic import _tool_defs
from appsec_verifier.auth import SessionManager
from appsec_verifier.cli import ProfileError, _build_planner_factory
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.loader import FindingPlan
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient
from appsec_verifier.verify.probes import ProbeContext


class Block:
    def __init__(self, type, name=None, input=None, id=None, text=None):
        self.type = type
        self.name = name
        self.input = input
        self.id = id
        self.text = text


class Msg:
    def __init__(self, content):
        self.content = content


class FakeMessages:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.script.pop(0)


class FakeClient:
    def __init__(self, script):
        self.messages = FakeMessages(script)


def _ctx_lite():
    plan = SimpleNamespace(id="T-1", cwe="CWE-639", cls="access-control", title="idor",
                           instance="routes/basket.ts:1", reason="scenario")
    return SimpleNamespace(plan=plan, identities=[{"role": "customer-a", "method": "bearer"}],
                           target_base="https://shop.example.com", safe=True)


def test_tool_defs_expose_only_the_three_tools():
    names = {t["name"] for t in _tool_defs()}
    assert names == {"http_request", "read_source", "submit_verdict"}
    verdict = next(t for t in _tool_defs() if t["name"] == "submit_verdict")
    assert "confirmed" in verdict["input_schema"]["properties"]["verdict"]["enum"]


def test_threading_and_parse():
    script = [
        Msg([Block("tool_use", name="http_request", input={"role": "customer-a", "path": "/rest/basket/2"}, id="tu1")]),
        Msg([Block("tool_use", name="submit_verdict",
                   input={"verdict": "confirmed", "rationale": "a read b"}, id="tu2")]),
    ]
    client = FakeClient(script)
    planner = AnthropicPlanner(client=client)
    ctx = _ctx_lite()

    a1 = planner.next_step(ctx, [])
    assert a1 == {"tool": "http_request", "args": {"role": "customer-a", "path": "/rest/basket/2"}}
    first = client.messages.calls[0]
    assert first["tool_choice"] == {"type": "auto"} and first["messages"][0]["role"] == "user"

    history = [{"tool": "http_request", "args": a1["args"], "result": {"status": 200, "body_excerpt": "{...}"}}]
    a2 = planner.next_step(ctx, history)
    assert a2 == {"verdict": {"verdict": "confirmed", "rationale": "a read b"}}
    threaded = client.messages.calls[1]["messages"]
    tool_result = threaded[-1]["content"][0]
    assert tool_result["type"] == "tool_result" and tool_result["tool_use_id"] == "tu1"


def test_end_turn_without_tool_is_inconclusive():
    planner = AnthropicPlanner(client=FakeClient([Msg([Block("text", text="I am unsure")])]))
    action = planner.next_step(_ctx_lite(), [])
    assert action["verdict"]["verdict"] == "inconclusive"


def test_anthropic_api_profile_gating():
    args = SimpleNamespace(model=None, profile="anthropic-api", non_interactive=True, cost_limit=None)
    with pytest.raises(ProfileError):
        _build_planner_factory(args, environ={})
    factory, info = _build_planner_factory(args, environ={"ANTHROPIC_API_KEY": "sk-test"})
    assert callable(factory)
    assert info["profile"] == "anthropic-api" and info["model"] == "claude-opus-5-5"


def test_agent_registry_covers_classes():
    reg = agent_registry(lambda: None)
    assert reg.get("access-control") is not None and reg.get("xss") is not None


# ── integration: scripted model drives a real two-identity IDOR contrast ──────

class Resp:
    def __init__(self, status=200, text='{"id":2,"UserId":2}'):
        self.status_code = status
        self.text = text
        self.headers = {}


def _full_ctx(tmp_path, transport):
    scope = {"base_url": "https://shop.example.com", "hosts": ["shop.example.com"], "ports": [443],
             "schemes": ["https"], "path_prefixes": ["/"]}
    (tmp_path / "routes").mkdir(exist_ok=True)
    (tmp_path / "routes" / "basket.ts").write_text("get('/rest/basket/:id')\n")
    from appsec_verifier.agent import SourceReader
    http = GuardedHttpClient(ScopeGuard(scope), RunBudget(Limits()), transport)
    idents = [{"role": "customer-a", "method": "bearer", "auth": {"token_env": "TA"}},
              {"role": "customer-b", "method": "bearer", "auth": {"token_env": "TB"}}]
    sessions = SessionManager(idents, http, env={"TA": "AAA", "TB": "BBB"})
    plan = FindingPlan(id="T-001", cwe="CWE-639", severity="High", title="idor",
                       match_key="routes/basket.ts|CWE-639", instance="routes/basket.ts:1",
                       status="dynamic", cls="access-control", reason="p")
    return ProbeContext(plan=plan, scope=scope, guard=ScopeGuard(scope), budget=RunBudget(Limits()),
                        http=http, identities=idents, callback={}, safe=True, read_only=True,
                        sessions=sessions, source=SourceReader(tmp_path), target_base=scope["base_url"])


def test_scripted_model_confirms_idor_through_tools(tmp_path):
    calls = []

    def transport(m, u, h, **k):
        calls.append(h.get("Authorization"))
        return Resp()

    script = [
        Msg([Block("tool_use", name="http_request", input={"role": "customer-a", "path": "/rest/basket/2"}, id="t1")]),
        Msg([Block("tool_use", name="http_request", input={"role": "customer-b", "path": "/rest/basket/2"}, id="t2")]),
        Msg([Block("tool_use", name="submit_verdict",
                   input={"verdict": "confirmed", "confidence": "high", "rationale": "a read b",
                          "identities_used": ["customer-a", "customer-b"]}, id="t3")]),
    ]
    ctx = _full_ctx(tmp_path, transport)
    res = AgentProbe("access-control", lambda: AnthropicPlanner(client=FakeClient(script)), max_steps=8).run(ctx)
    assert res.verdict == "confirmed" and res.identities_used == ["customer-a", "customer-b"]
    assert calls == ["Bearer AAA", "Bearer BBB"]
