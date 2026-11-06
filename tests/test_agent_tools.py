"""The agent is confined to http_request (scope-guarded, as an identity) and
read_source (repo-confined); safe mode blocks writes; unknown tools are rejected
(VER-017, VER-014/030, VER-028)."""

from __future__ import annotations

import pytest

from appsec_verifier.agent import AgentTools, ToolError
from appsec_verifier.agent.source_reader import SourceReader
from appsec_verifier.auth import SessionManager
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient
from appsec_verifier.verify.probes import ProbeContext

SCOPE = {"base_url": "https://app.example.com", "hosts": ["app.example.com"], "ports": [443],
         "schemes": ["https"], "path_prefixes": ["/"]}


class Resp:
    def __init__(self, status=200, text="{}"):
        self.status_code = status
        self.text = text
        self.headers = {}


def _ctx(tmp_path, transport, *, safe=True, read_only=True, env=None):
    (tmp_path / "routes").mkdir(exist_ok=True)
    (tmp_path / "routes" / "basket.ts").write_text("export const get = (req) => db.basket(req.params.id)\n")
    http = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits()), transport)
    idents = [{"role": "customer-a", "method": "bearer", "auth": {"token_env": "TA"}}]
    sessions = SessionManager(idents, http, env=env or {"TA": "A"})
    from appsec_verifier.loader import FindingPlan
    plan = FindingPlan(id="T-1", cwe="CWE-639", severity="High", title="idor",
                       match_key="routes/basket.ts|CWE-639", instance="routes/basket.ts:1",
                       status="dynamic", cls="access-control", reason="p")
    return ProbeContext(plan=plan, scope=SCOPE, guard=ScopeGuard(SCOPE), budget=RunBudget(Limits()),
                        http=http, identities=idents, callback={}, safe=safe, read_only=read_only,
                        sessions=sessions, source=SourceReader(tmp_path), target_base=SCOPE["base_url"])


def test_http_request_joins_path_and_attaches_identity(tmp_path):
    seen = []

    def transport(m, u, h, **k):
        seen.append((m, u, h.get("Authorization")))
        return Resp(200, '{"id":2}')

    tools = AgentTools(_ctx(tmp_path, transport))
    out = tools.http_request(role="customer-a", method="GET", path="/rest/basket/2")
    assert out["status"] == 200 and '"id":2' in out["body_excerpt"]
    assert seen == [("GET", "https://app.example.com/rest/basket/2", "Bearer A")]


def test_safe_mode_blocks_state_change(tmp_path):
    called = []
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: called.append(u) or Resp()))
    with pytest.raises(ToolError):
        tools.http_request(role="customer-a", method="POST", path="/rest/basket/2")
    assert called == []  # never sent


def test_unknown_tool_rejected(tmp_path):
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: Resp()))
    with pytest.raises(ToolError):
        tools.call("shell", {"cmd": "id"})


def test_read_source_traversal_becomes_tool_error(tmp_path):
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: Resp()))
    with pytest.raises(ToolError):
        tools.read_source(path="../../etc/passwd")


def test_auth_failure_triggers_one_refresh(tmp_path):
    calls = {"n": 0}

    def transport(m, u, h, **k):
        calls["n"] += 1
        return Resp(401) if calls["n"] == 1 else Resp(200, '{"ok":1}')

    tools = AgentTools(_ctx(tmp_path, transport))
    out = tools.http_request(role="customer-a", method="GET", path="/rest/basket/2")
    assert out["status"] == 200 and calls["n"] == 2  # retried once after 401
