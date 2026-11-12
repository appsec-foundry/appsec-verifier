"""Sessions beyond the static methods (VER-016, VER-028, VER-032, VER-040): pasted
headers, expiry and renewal, OAuth client authentication and discovery, the
sign-ins that need a person, and the account check. Everything offline: the
transport is a fake, and the loopback listener only talks to this test."""

from __future__ import annotations

import base64
import json
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

import pytest

from appsec_verifier.auth import AuthError, SessionManager, interactive
from appsec_verifier.auth.interactive import LoginUI, LoopbackReceiver, s256
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.preflight import check_accounts
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient, ScopeViolation

SCOPE = {"base_url": "https://app.example.com", "hosts": ["app.example.com"], "ports": [443],
         "schemes": ["https"], "path_prefixes": ["/"], "auth_hosts": ["sso.example.com:443"]}
ISSUER = "https://sso.example.com/realms/app"
NOW = 1_800_000_000.0


def jwt(**claims) -> str:
    part = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"eyJhbGciOiJub25lIn0.{part}.c2ln"


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class Transport:
    """Answers by (method, url); a list answers successive calls. Records every call."""

    def __init__(self, answers=None):
        self.answers = dict(answers or {})
        self.calls = []

    def __call__(self, method, url, headers, **kw):
        self.calls.append((method, url, dict(headers), kw))
        answer = self.answers.get((method, url), Resp(200, {}))
        if isinstance(answer, list):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        return answer


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


def mgr(identities, env=None, answers=None, *, ui=None, clock=None, run_program=None, base_dir=None):
    transport = Transport(answers)
    http = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits(rate_rps=0)), transport)
    sessions = SessionManager(identities, http, env=env or {}, ui=ui, clock=clock or Clock(), sleep=lambda s: None,
                              run_program=run_program, base_dir=base_dir)
    return sessions, transport, http


# ── session headers from env (method session) ────────────────────────────────

def test_session_headers_come_from_env_and_every_cookie_value_is_redacted():
    ident = {"role": "a", "method": "session", "auth": {"headers_env": {"Cookie": "C", "X-Api-Key": "K"}}}
    sessions, _, _ = mgr([ident], {"C": "sid=abcd1234; csrf=efgh5678", "K": "key-0001"})
    assert sessions.headers_for("a") == {"Cookie": "sid=abcd1234; csrf=efgh5678", "X-Api-Key": "key-0001"}
    out = sessions.redact("echo abcd1234 and efgh5678 and key-0001")
    assert out == "echo [redacted] and [redacted] and [redacted]"


@pytest.mark.parametrize("value, problem", [("sid=1\r\nX-Evil: 1", "control character"), ("", "missing")])
def test_a_session_header_with_a_line_break_or_no_value_is_refused(value, problem):
    ident = {"role": "a", "method": "session", "auth": {"headers_env": {"Cookie": "C"}}}
    sessions, _, _ = mgr([ident], {"C": value})
    with pytest.raises(AuthError, match=problem):
        sessions.headers_for("a")


def test_identity_headers_are_dropped_on_a_cross_origin_redirect():
    ident = {"role": "a", "method": "session", "auth": {"headers_env": {"X-Api-Key": "K"}}}
    answers = {("GET", "https://app.example.com/go"): Resp(302, {}, {"Location": "https://sso.example.com/x"})}
    sessions, transport, http = mgr([ident], {"K": "key-0001"}, answers)
    headers = sessions.headers_for("a")
    http.request("GET", "https://app.example.com/go", headers, purpose="auth")
    assert transport.calls[0][2] == {"X-Api-Key": "key-0001"}
    assert transport.calls[1][1] == "https://sso.example.com/x" and transport.calls[1][2] == {}   # VER-018


def test_an_expired_static_token_is_not_used():
    ident = {"role": "a", "method": "bearer", "auth": {"token_env": "T"}}
    sessions, _, _ = mgr([ident], {"T": jwt(sub="u1", exp=NOW - 10)})
    with pytest.raises(AuthError, match="has expired"):
        sessions.headers_for("a")


# ── OAuth: grants, client authentication, expiry and renewal ─────────────────

TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
PASSWORD = {"role": "a", "method": "oidc-password", "auth": {
    "token_url": TOKEN_URL, "client_id": "cli", "username_env": "U", "password_env": "P"}}
ENV = {"U": "alice", "P": "pw-alice-1"}


def test_a_session_is_renewed_with_its_refresh_token_before_it_expires():
    clock = Clock()
    answers = {("POST", TOKEN_URL): [
        Resp(200, {"access_token": "AT-1", "expires_in": 300, "refresh_token": "RT-1"}),
        Resp(200, {"access_token": "AT-2", "expires_in": 300, "refresh_token": "RT-2"}),   # rotated
        Resp(200, {"access_token": "AT-3", "expires_in": 300}),
    ]}
    sessions, transport, _ = mgr([PASSWORD], ENV, answers, clock=clock)
    assert sessions.headers_for("a") == {"Authorization": "Bearer AT-1"}
    clock.now += 200                                           # more than RENEW_MARGIN_S before expiry
    assert sessions.headers_for("a") == {"Authorization": "Bearer AT-1"} and len(transport.calls) == 1
    clock.now += 60                                            # within the margin: renewed, no password sent
    assert sessions.headers_for("a") == {"Authorization": "Bearer AT-2"}
    assert transport.calls[1][3]["data"] == {"client_id": "cli", "grant_type": "refresh_token",
                                             "refresh_token": "RT-1"}
    clock.now += 280
    assert sessions.headers_for("a") == {"Authorization": "Bearer AT-3"}
    assert transport.calls[2][3]["data"]["refresh_token"] == "RT-2"        # the rotated one
    assert sessions.redact("RT-1 RT-2 AT-3") == "[redacted] [redacted] [redacted]"


@pytest.mark.parametrize("token", [
    {"access_token": "AT-1", "expires_in": 30},                               # shorter than the margin
    {"access_token": jwt(sub="u", exp=NOW - 5)},                              # looks expired: the clocks differ
])
def test_a_short_lived_or_skewed_token_is_not_renewed_on_every_request(token):
    clock = Clock()
    sessions, transport, _ = mgr([PASSWORD], ENV, {("POST", TOKEN_URL): Resp(200, token)}, clock=clock)
    for _ in range(5):
        sessions.headers_for("a")
        clock.now += 1
    assert len(transport.calls) == 1


def test_a_failed_refresh_falls_back_to_a_new_login_where_the_method_can():
    clock = Clock()
    answers = {("POST", TOKEN_URL): [
        Resp(200, {"access_token": "AT-1", "expires_in": 100, "refresh_token": "RT-1"}),
        Resp(400, {"error": "invalid_grant"}),
        Resp(200, {"access_token": "AT-2", "expires_in": 100}),
    ]}
    sessions, transport, _ = mgr([PASSWORD], ENV, answers, clock=clock)
    sessions.headers_for("a")
    clock.now += 90
    assert sessions.headers_for("a") == {"Authorization": "Bearer AT-2"}
    assert [c[3]["data"]["grant_type"] for c in transport.calls] == ["password", "refresh_token", "password"]


def test_after_the_sign_in_phase_an_interactive_identity_whose_renewal_fails_is_unavailable():
    ident = {"role": "a", "method": "oidc-device-code", "auth": {
        "device_url": f"{ISSUER}/device", "token_url": TOKEN_URL, "client_id": "cli"}}
    answers = {("POST", f"{ISSUER}/device"): Resp(200, {"device_code": "DEV-0001", "user_code": "WXYZ",
                                                        "verification_uri": f"{ISSUER}/device", "interval": 1}),
               ("POST", TOKEN_URL): [Resp(200, {"access_token": "AT-1", "expires_in": 100, "refresh_token": "RT"}),
                                     Resp(400, {"error": "invalid_grant"})]}
    clock, said = Clock(), []
    sessions, transport, _ = mgr([ident], {}, answers, ui=LoginUI(say=said.append, open_url=lambda u: False),
                                 clock=clock)
    sessions.headers_for("a")
    sessions.end_interactive()
    clock.now += 90
    calls = len(transport.calls)
    with pytest.raises(AuthError, match="needs a person"):
        sessions.headers_for("a")
    with pytest.raises(AuthError, match="not tried again"):
        sessions.headers_for("a")
    assert len(transport.calls) == calls + 1                   # one refresh attempt, then nothing more


def test_client_secret_basic_puts_the_secret_in_the_authorization_header_only():
    ident = {"role": "svc", "method": "oidc-client-credentials", "auth": {
        "token_url": TOKEN_URL, "client_id": "my client", "client_secret_env": "CS", "client_auth": "basic",
        "audience": "https://api.example.com", "resource": "api://app", "scope": "api.read"}}
    sessions, transport, _ = mgr([ident], {"CS": "s3cr:et"}, {("POST", TOKEN_URL): Resp(200, {"access_token": "AT"})})
    sessions.headers_for("svc")
    _, _, headers, kw = transport.calls[0]
    assert headers["Authorization"] == "Basic " + base64.b64encode(b"my+client:s3cr%3Aet").decode()
    assert kw["data"] == {"grant_type": "client_credentials", "scope": "api.read",
                          "audience": "https://api.example.com", "resource": "api://app"}


def test_the_id_token_is_attached_when_the_identity_asks_for_it():
    ident = {**PASSWORD, "auth": {**PASSWORD["auth"], "token": "id"}}
    idt = jwt(iss=ISSUER, sub="u-1")
    sessions, _, _ = mgr([ident], ENV, {("POST", TOKEN_URL): Resp(200, {"access_token": "AT", "id_token": idt})})
    assert sessions.headers_for("a") == {"Authorization": f"Bearer {idt}"}


def test_a_refused_grant_names_the_plain_error_code_but_never_free_text():
    answers = {("POST", TOKEN_URL): Resp(401, {"error": "invalid_client", "error_description": "pw-alice-1 bad"})}
    sessions, _, _ = mgr([PASSWORD], ENV, answers)
    with pytest.raises(AuthError) as exc:
        sessions.headers_for("a")
    assert "(HTTP 401) (invalid_client)" in str(exc.value) and "pw-alice-1" not in str(exc.value)


# ── discovery ────────────────────────────────────────────────────────────────

DISCOVERY = f"{ISSUER}/.well-known/openid-configuration"


def test_the_issuer_discovery_document_names_the_token_endpoint():
    ident = {"role": "a", "method": "oidc-password", "auth": {"issuer": ISSUER, "client_id": "cli",
                                                              "username_env": "U", "password_env": "P"}}
    answers = {("GET", DISCOVERY): Resp(200, {"issuer": ISSUER, "token_endpoint": TOKEN_URL}),
               ("POST", TOKEN_URL): Resp(200, {"access_token": "AT"})}
    sessions, transport, _ = mgr([ident], ENV, answers)
    assert sessions.headers_for("a") == {"Authorization": "Bearer AT"}
    assert [(c[0], c[1]) for c in transport.calls] == [("GET", DISCOVERY), ("POST", TOKEN_URL)]


def test_a_discovered_endpoint_outside_the_scope_is_never_sent_credentials():
    ident = {"role": "a", "method": "oidc-password", "auth": {"issuer": ISSUER, "client_id": "cli",
                                                              "username_env": "U", "password_env": "P"}}
    answers = {("GET", DISCOVERY): Resp(200, {"issuer": ISSUER, "token_endpoint": "https://rogue.example/token"})}
    sessions, transport, _ = mgr([ident], ENV, answers)
    with pytest.raises(ScopeViolation):
        sessions.headers_for("a")
    assert [c[1] for c in transport.calls] == [DISCOVERY]


def test_a_discovery_document_for_another_issuer_is_refused():
    ident = {"role": "a", "method": "oidc-password", "auth": {"issuer": ISSUER, "client_id": "cli",
                                                              "username_env": "U", "password_env": "P"}}
    answers = {("GET", DISCOVERY): Resp(200, {"issuer": "https://other.example", "token_endpoint": TOKEN_URL})}
    sessions, transport, _ = mgr([ident], ENV, answers)
    with pytest.raises(AuthError, match="another issuer"):
        sessions.headers_for("a")
    assert len(transport.calls) == 1


# ── accounts (VER-032) ───────────────────────────────────────────────────────

def test_two_roles_signed_in_as_the_same_account_fail_the_check():
    idents = [{"role": r, "method": "bearer", "auth": {"token_env": r.upper()}} for r in ("a", "b", "c")]
    env = {"A": jwt(iss=ISSUER, sub="alice"), "B": jwt(iss=ISSUER, sub="bob"), "C": jwt(iss=ISSUER, sub="alice")}
    sessions, _, _ = mgr(idents, env)
    for role in ("a", "b"):
        sessions.headers_for(role)
    assert check_accounts(sessions) == []
    sessions.headers_for("c")
    [check] = check_accounts(sessions)
    assert check.status == "fail" and "a and c are signed in as the same account" in check.message


def test_sessions_that_do_not_name_their_account_are_not_compared():
    idents = [{"role": r, "method": "session", "auth": {"headers_env": {"Cookie": r.upper()}}} for r in ("a", "b")]
    sessions, _, _ = mgr(idents, {"A": "sid=same-0001", "B": "sid=same-0001"})
    sessions.headers_for("a"), sessions.headers_for("b")
    assert check_accounts(sessions) == []


# ── authorization code with PKCE (RFC 7636, RFC 8252) ────────────────────────

def test_s256_matches_the_rfc_7636_example():
    assert s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class FakeReceiver:
    """Stands in for the loopback listener: answers the redirect the 'browser' would make."""

    port = 49152

    def __init__(self, reply):
        self.reply = reply
        self.opened = []

    def __call__(self, port, path):
        self.path = path
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def wait(self, state):
        return self.reply(parse_qs(urlsplit(self.opened[-1]).query), state)


AUTH_CODE = {"role": "a", "method": "oidc-authorization-code", "auth": {
    "authorize_url": f"{ISSUER}/auth", "token_url": TOKEN_URL, "client_id": "cli", "scope": "openid api"}}


def _code_flow(reply, ident=AUTH_CODE, answers=None):
    receiver, said = FakeReceiver(reply), []
    ui = LoginUI(say=said.append, open_url=receiver.opened.append, receiver=receiver)
    answers = answers or {("POST", TOKEN_URL): Resp(200, {"access_token": "AT", "id_token": jwt(iss=ISSUER, sub="a1")})}
    sessions, transport, _ = mgr([ident], {}, answers, ui=ui)
    return sessions, transport, receiver, said


def test_the_authorization_code_flow_uses_pkce_state_and_a_fresh_sign_in():
    sessions, transport, receiver, said = _code_flow(lambda q, state: {"state": state, "code": "CODE-1"})
    assert sessions.headers_for("a") == {"Authorization": "Bearer AT"}
    query = parse_qs(urlsplit(receiver.opened[0]).query)
    assert receiver.opened[0].startswith(f"{ISSUER}/auth?")
    assert {k: v[0] for k, v in query.items() if k not in ("state", "code_challenge")} == {
        "response_type": "code", "client_id": "cli", "redirect_uri": "http://127.0.0.1:49152/callback",
        "scope": "openid api", "code_challenge_method": "S256", "prompt": "login"}
    data = transport.calls[0][3]["data"]
    assert data["grant_type"] == "authorization_code" and data["code"] == "CODE-1"
    assert data["redirect_uri"] == "http://127.0.0.1:49152/callback" and "client_secret" not in data
    assert s256(data["code_verifier"]) == query["code_challenge"][0]
    assert "Sign in as a in your browser" in said[0] and receiver.opened[0] in said[0]
    assert sessions.accounts() == {"a": (ISSUER, "a1")}


def test_a_refused_sign_in_reports_only_the_error_code():
    sessions, transport, _, _ = _code_flow(lambda q, state: {"state": state, "error": "access_denied",
                                                              "error_description": "<script>"})
    with pytest.raises(AuthError, match=r"refused the sign-in \(access_denied\)$"):
        sessions.headers_for("a")
    assert transport.calls == []


def test_an_authorize_url_outside_the_scope_is_never_opened():
    ident = {**AUTH_CODE, "auth": {**AUTH_CODE["auth"], "authorize_url": "https://rogue.example/auth"}}
    sessions, transport, receiver, said = _code_flow(lambda q, state: {}, ident)
    with pytest.raises(AuthError, match="authorize endpoint is refused"):
        sessions.headers_for("a")
    assert receiver.opened == [] and said == [] and transport.calls == []


def test_a_sign_in_that_needs_a_person_fails_closed_without_one():
    sessions, transport, _ = mgr([AUTH_CODE], {})
    with pytest.raises(AuthError, match="needs a person"):
        sessions.headers_for("a")
    assert transport.calls == []


def _get(port, path):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    return data.decode("latin-1")


def test_the_loopback_listener_answers_only_its_own_path_and_state():
    with LoopbackReceiver(0, "/callback", wait_s=10) as rx:
        answers = {}

        def browser():
            answers["other"] = _get(rx.port, "/favicon.ico")
            answers["forged"] = _get(rx.port, "/callback?state=wrong&code=ATTACKER")
            answers["real"] = _get(rx.port, "/callback?state=S-1&code=C-1")

        thread = threading.Thread(target=browser)
        thread.start()
        query = rx.wait("S-1")
        thread.join()
    assert query == {"state": "S-1", "code": "C-1"}
    assert answers["other"].startswith("HTTP/1.1 404") and answers["forged"].startswith("HTTP/1.1 400")
    real = answers["real"]
    assert real.startswith("HTTP/1.1 200") and "Content-Security-Policy: default-src 'none'" in real
    assert "Cache-Control: no-store" in real and "Referrer-Policy: no-referrer" in real


def test_the_loopback_listener_binds_only_to_127_0_0_1_and_gives_up_in_time():
    with LoopbackReceiver(0, "/callback", wait_s=0.2) as rx:
        assert rx._sock.getsockname()[0] == "127.0.0.1"
        started = time.monotonic()
        with pytest.raises(AuthError, match="in time"):
            rx.wait("S")
        assert time.monotonic() - started < 3


@pytest.mark.parametrize("uri", ["https://127.0.0.1:8400/cb", "http://evil.example:8400/cb",
                                 "http://127.0.0.1:8400/cb?x=1"])
def test_only_a_loopback_redirect_uri_is_accepted(uri):
    with pytest.raises(AuthError, match="redirect_uri must be"):
        interactive._loopback(uri)


# ── device code (RFC 8628) ───────────────────────────────────────────────────

DEVICE = {"role": "d", "method": "oidc-device-code", "auth": {
    "device_url": f"{ISSUER}/device", "token_url": TOKEN_URL, "client_id": "cli", "scope": "openid"}}


def _device(token_answers, device_answer=None):
    answers = {("POST", f"{ISSUER}/device"): device_answer or Resp(200, {
                   "device_code": "DEV-SECRET-1", "user_code": "WDJB-MJHT", "verification_uri": f"{ISSUER}/device",
                   "interval": 2, "expires_in": 600}),
               ("POST", TOKEN_URL): token_answers}
    said, slept = [], []
    sessions, transport, _ = mgr([DEVICE], {}, answers, ui=LoginUI(say=said.append))
    sessions._sleep = slept.append
    return sessions, transport, said, slept


def test_the_device_flow_shows_the_code_and_polls_at_the_providers_pace():
    tokens = [Resp(400, {"error": "authorization_pending"}), Resp(400, {"error": "slow_down"}),
              Resp(200, {"access_token": "AT-D", "expires_in": 600})]
    sessions, transport, said, slept = _device(tokens)
    assert sessions.headers_for("d") == {"Authorization": "Bearer AT-D"}
    assert said == [f"Sign in as d: open {ISSUER}/device and enter the code WDJB-MJHT"]
    assert slept == [2, 2, 7]                                  # slow_down adds 5 s
    # PKCE as in the code flow: a provider that enforces it for the client (Keycloak) refuses the request without it.
    device, polls = transport.calls[0][3]["data"], [call[3]["data"] for call in transport.calls[1:]]
    verifier = polls[0]["code_verifier"]
    assert device == {"client_id": "cli", "scope": "openid", "code_challenge": s256(verifier),
                      "code_challenge_method": "S256"}
    assert polls == 3 * [{"client_id": "cli", "device_code": "DEV-SECRET-1", "code_verifier": verifier,
                          "grant_type": "urn:ietf:params:oauth:grant-type:device_code"}]
    assert sessions.redact("DEV-SECRET-1") == "[redacted]"


@pytest.mark.parametrize("error", ["access_denied", "expired_token"])
def test_a_device_sign_in_that_is_denied_or_expires_stops(error):
    sessions, _, _, _ = _device([Resp(400, {"error": error})])
    with pytest.raises(AuthError, match=f"ended without a token .*\\({error}\\)"):
        sessions.headers_for("d")
