"""The agent is confined to http_request (scope-guarded, as an identity) and
read_source (repo-confined); safe mode blocks writes; unknown tools are rejected;
an identity's credentials go only to its own origin; DELETE and other methods are
never sent; identity and transport failures become tool errors
(VER-017, VER-014/030, VER-018, VER-028)."""

from __future__ import annotations

import httpx
import pytest

from appsec_verifier.agent import AgentTools, ToolError
from appsec_verifier.agent.source_reader import SourceReader
from appsec_verifier.auth import SessionManager
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient
from appsec_verifier.verify.probes import ProbeContext

SCOPE = {"base_url": "https://app.example.com", "hosts": ["app.example.com", "api.example.com"], "ports": [443],
         "schemes": ["https"], "path_prefixes": ["/"]}


class Resp:
    def __init__(self, status=200, text="{}"):
        self.status_code = status
        self.text = text
        self.headers = {}


def _ctx(tmp_path, transport, *, safe=True, read_only=True, env=None, idents=None):
    (tmp_path / "routes").mkdir(exist_ok=True)
    (tmp_path / "routes" / "basket.ts").write_text("export const get = (req) => db.basket(req.params.id)\n")
    http = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits()), transport)
    idents = idents or [{"role": "customer-a", "method": "bearer", "auth": {"token_env": "TA"}}]
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


# ── methods ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("method", ["DELETE", "delete", "TRACE", "CONNECT", "PURGE"])
def test_delete_and_other_methods_are_never_sent_even_in_intrusive_mode(tmp_path, method):
    sent = []
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: sent.append(m) or Resp(), safe=False, read_only=False))
    with pytest.raises(ToolError, match="never sent"):
        tools.http_request(method=method, path="/rest/basket/2")
    assert sent == []


def test_write_methods_need_intrusive_mode_and_state_change(tmp_path):
    sent = []
    transport = lambda m, u, h, **k: sent.append(m) or Resp()  # noqa: E731
    with pytest.raises(ToolError):
        AgentTools(_ctx(tmp_path, transport, safe=False, read_only=True)).http_request(method="PUT", path="/x")
    AgentTools(_ctx(tmp_path, transport, safe=False, read_only=False)).http_request(method="PUT", path="/x")
    assert sent == ["PUT"]


# ── an identity's credentials go only to its origin (VER-018) ────────────────

def test_identity_is_not_sent_to_another_in_scope_origin(tmp_path):
    sent = []
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: sent.append((u, h.get("Authorization"))) or Resp()))
    with pytest.raises(ToolError, match="bound to"):
        tools.http_request(role="customer-a", path="https://api.example.com/collect")
    assert sent == []
    tools.http_request(path="https://api.example.com/collect")          # without a role it may go there
    assert sent == [("https://api.example.com/collect", None)]


def test_identity_with_target_origin_is_bound_to_that_origin(tmp_path):
    sent = []
    idents = [{"role": "api-user", "method": "bearer",
               "auth": {"token_env": "TA", "target_origin": "https://api.example.com"}}]
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: sent.append((u, h.get("Authorization"))) or Resp(),
                            idents=idents))
    with pytest.raises(ToolError):
        tools.http_request(role="api-user", path="/rest/basket/2")         # the target base is another origin
    tools.http_request(role="api-user", path="https://api.example.com/v1/me")
    assert sent == [("https://api.example.com/v1/me", "Bearer A")]


# ── failures become tool errors, never exceptions past the loop ──────────────

def test_unknown_role_and_missing_secret_are_tool_errors(tmp_path):
    sent = []
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: sent.append(u) or Resp(), env={"OTHER": "x"}))
    with pytest.raises(ToolError, match="unknown identity role"):
        tools.http_request(role="admin", path="/x")
    with pytest.raises(ToolError, match="TA") as exc:
        tools.http_request(role="customer-a", path="/x")
    assert "x" not in str(exc.value).split("TA")[-1]   # names the variable, no value
    assert sent == []


@pytest.mark.parametrize("error", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), OSError("down"),
                                   httpx.InvalidURL("bad")])
def test_transport_failure_is_a_tool_error(tmp_path, error):
    def transport(m, u, h, **k):
        raise error

    with pytest.raises(ToolError, match="request failed"):
        AgentTools(_ctx(tmp_path, transport)).http_request(path="/x")
