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


@pytest.mark.parametrize("path", ["/public/../rest/admin", "public/./x", "/a/..", "../../etc/passwd",
                                  "https://app.example.com/public/../rest/admin"])
def test_dot_segments_reach_the_guard_and_are_refused(tmp_path, path):
    """The path is not normalised before the guard sees it, so an ambiguous path is refused (VER-018)."""
    sent = []
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: sent.append(u) or Resp()))
    with pytest.raises(ToolError, match="ambiguous"):
        tools.http_request(path=path)
    assert sent == []


def test_query_and_base_path_are_kept(tmp_path):
    sent = []
    ctx = _ctx(tmp_path, lambda m, u, h, **k: sent.append(u) or Resp())
    ctx.target_base = "https://app.example.com/shop/"
    AgentTools(ctx).http_request(path="search?q=a/../b")
    assert sent == ["https://app.example.com/shop/search?q=a/../b"]


def test_unparseable_path_is_a_tool_error(tmp_path):
    with pytest.raises(ToolError, match="parseable"):
        AgentTools(_ctx(tmp_path, lambda m, u, h, **k: Resp())).http_request(path="https://[::1/x")


def test_redirects_are_reported_not_followed(tmp_path):
    """The agent sees the redirect and its location; no hop is sent for it, in scope or not (VER-012)."""
    sent = []

    def transport(m, u, h, **k):
        sent.append(u)
        resp = Resp(302, "")
        resp.headers = {"Location": "https://evil.example/landing?t=A-token-1234"}
        return resp

    env = {"TA": "A-token-1234"}
    out = AgentTools(_ctx(tmp_path, transport, env=env)).http_request(role="customer-a", path="/redirect")
    assert sent == ["https://app.example.com/redirect"]
    assert out["status"] == 302 and out["location"] == "https://evil.example/landing?t=[redacted]"


def test_elapsed_time_is_reported_when_the_transport_measured_it(tmp_path):
    from datetime import timedelta

    def transport(m, u, h, **k):
        resp = Resp(200, "{}")
        resp.elapsed = timedelta(seconds=3.2104)
        return resp

    assert AgentTools(_ctx(tmp_path, transport)).http_request(path="/x")["elapsed_ms"] == 3210
    assert "elapsed_ms" not in AgentTools(_ctx(tmp_path, lambda m, u, h, **k: Resp())).http_request(path="/x")


def test_elapsed_time_comes_from_httpx(tmp_path):
    import httpx

    from appsec_verifier.tools.httpx_transport import HttpxTransport

    class Stream(httpx.SyncByteStream):          # streamed like a real transport's body, so httpx times it
        def __iter__(self):
            yield b"ok"

    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=Stream())))
    ctx = _ctx(tmp_path, HttpxTransport(client=client))
    assert isinstance(AgentTools(ctx).http_request(path="/x")["elapsed_ms"], int)


def test_location_is_reported_only_for_redirects(tmp_path):
    def transport(m, u, h, **k):
        resp = Resp(201, "{}")
        resp.headers = {"Location": "/rest/basket/3"}
        return resp

    assert "location" not in AgentTools(_ctx(tmp_path, transport)).http_request(path="/rest/basket")


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


class LoginResp(Resp):
    def json(self):
        return {"token": "session-token"}


def test_echoed_token_is_redacted_before_the_excerpt_is_cut(tmp_path):
    """A token that straddles the 600-character cut must not leave its first
    characters in the excerpt (VER-016); `length` is the whole body's."""
    token = "A" * 4 + "0123456789abcdef0123456789"
    body = "x" * 590 + token + "y" * 50
    env = {"TA": token}
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: Resp(200, body), env=env))
    out = tools.http_request(role="customer-a", path="/whoami")
    assert out["length"] == len(body)
    assert token[:10] not in out["body_excerpt"] and out["body_excerpt"].startswith("x" * 590 + "[redac")


def test_forbidden_answer_never_triggers_a_new_login(tmp_path):
    """403 is an authorisation decision (often the finding's result), not an expired
    session: the session is reused and the target sees no extra login (VER-028)."""
    sent = []

    def transport(m, u, h, **k):
        sent.append((m, u))
        return LoginResp(200) if u.endswith("/login") else Resp(403)

    idents = [{"role": "alice", "method": "form",
               "auth": {"login_url": "https://app.example.com/login", "username_env": "AU", "password_env": "AP"}}]
    tools = AgentTools(_ctx(tmp_path, transport, idents=idents, env={"AU": "alice", "AP": "pw"}))
    for _ in range(3):
        assert tools.http_request(role="alice", path="/rest/admin")["status"] == 403
    assert [m for m, _ in sent] == ["POST", "GET", "GET", "GET"]


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


# ── path traversal and SSRF are steered to their markers (VER-012) ───────────

MARKER_FILE = {"path": "/srv/app/verifier-marker.txt", "content": "vrfMarkerContent0123456789"}


class FakeListener:
    base_url = "http://localhost:4444"

    def __init__(self, hit=False):
        self.hit = hit
        self.waited = []

    def hits(self, marker):
        return [{"at": "fixture-time", "method": "GET", "source": "127.0.0.1"}] if self.hit else []

    def url_for(self, marker):
        return f"{self.base_url}/{marker}"

    def wait_for(self, marker, timeout):
        self.waited.append(marker)
        return self.hit


def _probe_ctx(tmp_path, cls, transport, *, marker_file=None, listener=None):
    ctx = _ctx(tmp_path, transport)
    ctx.plan.cls = cls
    ctx.scope = dict(SCOPE, **({"marker_file": marker_file} if marker_file else {}))
    ctx.listener = listener
    ctx.marker = ("vrf0a1b2c3d", "4e5f6a7b")
    return ctx


@pytest.mark.parametrize("value", [
    "../../srv/app/verifier-marker.txt", "/srv/app/verifier-marker.txt", "..%2F..%2Fverifier-marker.txt",
    "%252e%252e%252fverifier-marker.txt", "..\\..\\verifier-marker.txt", "../verifier-marker.txt%00.md",
    "legal.md", "report",
])
def test_traversal_values_that_lead_to_the_marker_file_are_sent(tmp_path, value):
    sent = []
    tools = AgentTools(_probe_ctx(tmp_path, "path-traversal", lambda m, u, h, **k: sent.append(k) or Resp(),
                                  marker_file=MARKER_FILE))
    tools.http_request(path="/download", params={"file": value})
    assert len(sent) == 1


@pytest.mark.parametrize("params, body", [
    ({"file": "../../etc/passwd"}, None),
    ({"file": "/etc/shadow"}, None),
    ({"file": "..%2F..%2Fetc%2Fpasswd"}, None),
    ({"file": "%252e%252e%252fetc%252fpasswd"}, None),
    ({"file": "C:\\Windows\\win.ini"}, None),
    ({"file": "~/.ssh/id_rsa"}, None),
    ({"file": "../../etc/passwd%00/verifier-marker.txt"}, None),          # NUL ends the path before the name
    ({"file": "../../verifier-marker.txt.bak"}, None),
    (None, {"files": [{"name": "../../etc/hosts"}]}),                      # nested in the body
])
def test_traversal_values_that_lead_elsewhere_are_refused(tmp_path, params, body):
    sent = []
    tools = AgentTools(_probe_ctx(tmp_path, "path-traversal", lambda m, u, h, **k: sent.append(u) or Resp(),
                                  marker_file=MARKER_FILE))
    with pytest.raises(ToolError, match="marker file"):
        tools.http_request(method="GET", path="/download", params=params, json=body)
    assert sent == []


def test_without_a_marker_file_no_traversal_is_sent(tmp_path):
    tools = AgentTools(_probe_ctx(tmp_path, "path-traversal", lambda m, u, h, **k: Resp()))
    with pytest.raises(ToolError, match="names none"):
        tools.http_request(path="/download", params={"file": "../verifier-marker.txt"})


def test_marker_content_is_detected_in_code_and_hidden_from_the_model(tmp_path):
    body = "x" * 595 + MARKER_FILE["content"] + "\n"                     # straddles the excerpt cut
    ctx = _probe_ctx(tmp_path, "path-traversal", lambda m, u, h, **k: Resp(200, body), marker_file=MARKER_FILE)
    (tmp_path / "verifier-marker.txt").write_text(MARKER_FILE["content"])
    tools = AgentTools(ctx)
    out = tools.call("http_request", {"path": "/download", "params": {"file": "../verifier-marker.txt"}})
    assert out["marker_read"] is True and "vrfMarker" not in out["body_excerpt"]
    assert out["body_excerpt"].endswith("x" * 595 + "[mark")             # the cut falls in the placeholder
    assert "vrfMarker" not in str(tools.call("read_source", {"path": "verifier-marker.txt"}))
    assert AgentTools(_probe_ctx(tmp_path, "path-traversal", lambda m, u, h, **k: Resp(200, "nope"),
                                 marker_file=MARKER_FILE)).http_request(path="/d")["marker_read"] is False


def test_marker_read_is_reported_only_in_traversal_probes(tmp_path):
    ctx = _probe_ctx(tmp_path, "injection", lambda m, u, h, **k: Resp(200, MARKER_FILE["content"]),
                     marker_file=MARKER_FILE)
    out = AgentTools(ctx).call("http_request", {"path": "/x"})
    assert "marker_read" not in out and "vrfMarker" not in out["body_excerpt"]


@pytest.mark.parametrize("value", [
    "http://localhost:4444/vrf0a1b2c3d4e5f6a7b", "HTTP://LOCALHOST:4444/x?y=1",
    "http%3A%2F%2Flocalhost%3A4444%2Fvrf", "//localhost:4444/vrf", "plain text", "42",
])
def test_ssrf_values_that_point_at_the_listener_are_sent(tmp_path, value):
    sent = []
    listener = FakeListener(hit=True)
    tools = AgentTools(_probe_ctx(tmp_path, "ssrf", lambda m, u, h, **k: sent.append(u) or Resp(),
                                  listener=listener))
    out = tools.http_request(path="/fetch", params={"url": value})
    assert len(sent) == 1
    if "vrf0a1b2c3d4e5f6a7b" in value:
        assert out["callback_hit"] is True
        assert listener.waited == [out["callback_attempt"]]
        assert out["callback_attempt"] != "vrf0a1b2c3d4e5f6a7b"
    else:
        assert out["callback_hit"] is False and not listener.waited


@pytest.mark.parametrize("value", [
    "http://169.254.169.254/latest/meta-data/", "http://localhost:4444@169.254.169.254/",
    "http://localhost:4444\\@10.0.0.1/", "file:///etc/passwd", "gopher://localhost:6379/_INFO",
    "http://localhost:5555/", "https://localhost:4444/", "//10.0.0.1/admin", "http%253A%252F%252F10.0.0.1%252F",
    "see http://localhost:4444/",
])
def test_ssrf_values_that_point_elsewhere_are_refused(tmp_path, value):
    sent = []
    tools = AgentTools(_probe_ctx(tmp_path, "ssrf", lambda m, u, h, **k: sent.append(u) or Resp(),
                                  listener=FakeListener()))
    with pytest.raises(ToolError, match="callback listener"):
        tools.http_request(path="/fetch", json={"target": {"url": value}})
    assert sent == []


def test_without_a_listener_no_ssrf_url_is_sent(tmp_path):
    tools = AgentTools(_probe_ctx(tmp_path, "ssrf", lambda m, u, h, **k: Resp()))
    with pytest.raises(ToolError, match="has none"):
        tools.http_request(path="/fetch", params={"url": "http://localhost:4444/x"})
    assert "callback_hit" not in tools.http_request(path="/fetch", params={"q": "x"})


def test_other_classes_are_not_steered(tmp_path):
    sent = []
    tools = AgentTools(_probe_ctx(tmp_path, "injection", lambda m, u, h, **k: sent.append(u) or Resp()))
    tools.http_request(path="/search", params={"q": "../x", "u": "http://example.org/"})
    assert len(sent) == 1


# ── out-of-band injection is steered to the listener and correlated (VER-048) ─

_OOB_PAYLOAD = "#{http.get('http://localhost:4444/vrf0a1b2c3d4e5f6a7b')}"


def _oob_tools(tmp_path, transport, *, listener, cwe="CWE-1336"):
    ctx = _probe_ctx(tmp_path, "injection", transport, listener=listener)
    ctx.plan.cwe = cwe
    tools = AgentTools(ctx)
    tools._experiment = {"oob_template": "#{http.get('{{callback}}')}", "kind": "boolean",
                         "input_location": "params", "input_name": "q", "path": "/eval",
                         "positive": _OOB_PAYLOAD, "negative": "http://localhost:4444/vrf0a1b2c3d4e5f6a7b"}
    return tools


def test_oob_injection_payload_at_the_listener_is_sent_and_correlated(tmp_path):
    sent = []
    tools = _oob_tools(tmp_path, lambda m, u, h, **k: sent.append(u) or Resp(), listener=FakeListener(hit=True))
    out = tools.http_request(path="/eval", params={"q": _OOB_PAYLOAD})
    assert len(sent) == 1 and out["callback_hit"] is True
    assert tools.ctx.listener.waited == [out["callback_attempt"]]
    assert out["callback_attempt"] != "vrf0a1b2c3d4e5f6a7b"


@pytest.mark.parametrize("value", [
    "#{http.get('http://10.0.0.1/x')}", "#{http.get('http://169.254.169.254/')}",
    "#{http.get('file:///etc/passwd')}",
])
def test_oob_injection_payload_elsewhere_is_refused(tmp_path, value):
    sent = []
    tools = _oob_tools(tmp_path, lambda m, u, h, **k: sent.append(u) or Resp(), listener=FakeListener())
    with pytest.raises(ToolError, match="callback listener"):
        tools.http_request(path="/eval", params={"q": value})
    assert sent == []


def test_oob_plan_needs_a_listener_and_an_accepted_injection_class(tmp_path):
    from test_experiments import STRATEGY

    base = {"kind": "boolean", "hypothesis": "payload reaches a template sink", "path": "/eval",
            "method": "GET", "input_location": "params", "input_name": "q", "strategy": STRATEGY,
            "oob_template": "#{http.get('{{callback}}')}"}
    ctx = _probe_ctx(tmp_path, "injection", lambda *a, **k: Resp(), listener=None)
    ctx.plan.cwe = "CWE-1336"
    with pytest.raises(ToolError, match="no callback listener"):
        AgentTools(ctx).plan_test(**base)
    ctx.listener = FakeListener()
    for refused in ("CWE-78", "CWE-89", "CWE-943", "CWE-643"):   # command, SQL, NoSQL and XPath keep other forms
        ctx.plan.cwe = refused
        with pytest.raises(ToolError, match="out-of-band proofs need"):
            AgentTools(ctx).plan_test(**base)
    ctx.plan.cwe = "CWE-1336"
    accepted = AgentTools(ctx).plan_test(**base)
    assert accepted["accepted"] is True and accepted["experiment"]["negative"].endswith("vrf0a1b2c3d4e5f6a7b")


# ── auth-artifact login-bypass proof reports presence, never the token (VER-049) ─

def _auth_tools(tmp_path, status, body):
    ctx = _ctx(tmp_path, lambda m, u, h, **k: Resp(status, body), safe=False, read_only=False)
    ctx.plan.cls, ctx.plan.cwe = "injection", "CWE-89"
    tools = AgentTools(ctx)
    tools._experiment = {"auth_artifact": True, "pointer": "/authentication/token", "kind": "boolean",
                         "input_location": "json", "input_name": "email", "path": "/rest/user/login",
                         "positive": "x' OR (1=1) -- "}
    return tools


def test_auth_artifact_presence_is_reported_without_leaking_the_token(tmp_path):
    token = "SECRET-TOKEN-should-never-leak-xyz"
    tools = _auth_tools(tmp_path, 200, '{"authentication":{"token":"' + token + '"}}')
    out = tools.http_request(path="/rest/user/login", method="POST",
                             json={"email": "x' OR (1=1) -- ", "password": "p"})
    assert out["auth_artifact"] is True
    assert token not in str(out)                               # not in the model-visible result
    assert token not in str(tools._last_response)              # not in the recorded body read_response would serve


def test_auth_artifact_reports_absence_when_the_artifact_is_missing(tmp_path):
    tools = _auth_tools(tmp_path, 401, '{"error":"Invalid email or password."}')
    out = tools.http_request(path="/rest/user/login", method="POST",
                             json={"email": "x' OR (1=2) -- ", "password": "p"})
    assert out["auth_artifact"] is False


def test_auth_artifact_plan_needs_a_sql_or_nosql_challenge(tmp_path):
    from test_experiments import STRATEGY
    ctx = _ctx(tmp_path, lambda *a, **k: Resp(), safe=False, read_only=False)
    ctx.plan.cls, ctx.plan.cwe = "injection", "CWE-89"
    base = {"kind": "boolean", "hypothesis": "email is spliced into the login SQL query",
            "path": "/rest/user/login", "method": "POST", "input_location": "json", "input_name": "email",
            "baseline": "nobody@x", "pointer": "/authentication/token", "strategy": STRATEGY, "auth_artifact": True}
    with pytest.raises(ToolError, match="SQL or NoSQL challenge"):
        AgentTools(ctx).plan_test(**base)
    accepted = AgentTools(ctx).plan_test(**{**base, "sql_template": "x' OR {{predicate}} -- "})
    assert accepted["accepted"] is True and accepted["experiment"]["auth_artifact"] is True


# ── failures become tool errors, never exceptions past the loop ──────────────

def test_unknown_role_and_missing_secret_are_tool_errors(tmp_path):
    sent = []
    tools = AgentTools(_ctx(tmp_path, lambda m, u, h, **k: sent.append(u) or Resp(), env={"OTHER": "x"}))
    with pytest.raises(ToolError, match=r"unknown identity role 'admin'.*available: customer-a") as unknown:
        tools.http_request(role="admin", path="/x")
    assert "customer-a" in str(unknown.value)
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
