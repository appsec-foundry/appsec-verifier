"""Sign-in flows that need a person: authorization code with PKCE in the
operator's own browser, and the device-code flow (VER-028).

The Verifier never sees the password of these sign-ins. For the authorization
code it opens (or prints) the identity provider's authorize URL, which the
scope must allow for authentication, and waits for the one redirect to a
listener on 127.0.0.1 (RFC 8252). The listener accepts only its own path with
the run's `state`, compared in constant time, answers that one request and
closes; any other request is answered 404 or 400 and does not end the wait. The
code is exchanged with the PKCE verifier (RFC 7636, S256) through the
GuardedHttpClient. The device-code flow (RFC 8628) shows the verification URL
and user code and polls the token endpoint at the interval the provider sets.

`prompt=login` is sent by default, so a second identity is not silently signed
in as the first one; the pre-flight check also compares the accounts (VER-032).
All I/O is injected (`LoginUI`, the receiver, sleep and clock), so the flows are
testable offline.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import socket
import sys
import time
import unicodedata
import webbrowser
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlsplit

from .sessions import AuthError, _error_code, _json

LOGIN_WAIT_S = 300               # how long the listener waits for the browser's redirect
DEVICE_WAIT_S = 900              # at most this long for a device-code sign-in
_MAX_REQUEST_BYTES = 8192
_MAX_CONNECTIONS = 30
_PAGE = (b"<!doctype html><meta charset=utf-8><title>AppSec Verifier</title>"
         b"<p>Sign-in received. You can close this window and return to the terminal.</p>")
_HEADERS = (b"Content-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n"
            b"Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
            b"X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n")


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _open_url(url: str) -> bool:
    """Open `url` in the operator's browser, only where there is a display: without one, Python's
    webbrowser would start a text browser in this terminal. The URL is printed in any case."""
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY") or sys.platform == "darwin"):
        return False
    try:
        return webbrowser.open(url)
    except webbrowser.Error:
        return False


@dataclass
class LoginUI:
    """How an interactive sign-in talks to the operator: a line on the terminal, the browser, the listener."""
    say: object = _say
    open_url: object = _open_url
    receiver: object = field(default=None)       # factory(port, path) -> LoopbackReceiver

    def listen(self, port: int, path: str):
        return (self.receiver or LoopbackReceiver)(port, path)


def s256(verifier: str) -> str:
    """The PKCE code challenge of `verifier` (RFC 7636, method S256)."""
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def _loopback(redirect_uri: str | None) -> tuple[int, str, str]:
    """(port, path, host) for the listener. A configured redirect_uri must be http on 127.0.0.1 or localhost."""
    if not redirect_uri:
        return 0, "/callback", "127.0.0.1"
    parts = urlsplit(redirect_uri)
    if parts.scheme != "http" or parts.hostname not in ("127.0.0.1", "localhost") or parts.query or parts.fragment:
        raise AuthError("redirect_uri must be http://127.0.0.1:<port>/<path> or http://localhost:<port>/<path>")
    return parts.port or 80, parts.path or "/", parts.hostname


class LoopbackReceiver:
    """A one-shot listener on 127.0.0.1 for the authorization-code redirect."""

    def __init__(self, port: int, path: str, *, wait_s: float = LOGIN_WAIT_S):
        self._path = path
        self._wait_s = wait_s
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._sock.bind(("127.0.0.1", port))
            self._sock.listen(4)
        except OSError:
            self._sock.close()
            raise
        self.port = self._sock.getsockname()[1]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._sock.close()

    def wait(self, state: str) -> dict:
        """The query of the one redirect that carries `state`. Raises AuthError on timeout."""
        deadline = time.monotonic() + self._wait_s
        for _ in range(_MAX_CONNECTIONS):
            left = deadline - time.monotonic()
            if left <= 0:
                break
            self._sock.settimeout(left)
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                break
            with conn:
                query = self._answer(conn, state)
            if query is not None:
                return query
        raise AuthError("no sign-in arrived from the browser in time")

    def _answer(self, conn, state: str) -> dict | None:
        conn.settimeout(5)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < _MAX_REQUEST_BYTES:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            return None
        line = data.split(b"\r\n", 1)[0].decode("latin-1")
        method, _, rest = line.partition(" ")
        target = rest.rpartition(" ")[0] or rest
        parts = urlsplit(target)
        if method != "GET" or parts.path != self._path:
            self._send(conn, b"404 Not Found", b"")
            return None
        query = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        if not secrets.compare_digest(query.get("state", "").encode(), state.encode()):
            self._send(conn, b"400 Bad Request", b"")
            return None
        self._send(conn, b"200 OK", _PAGE)
        return query

    @staticmethod
    def _send(conn, status: bytes, body: bytes) -> None:
        try:
            conn.sendall(b"HTTP/1.1 " + status + b"\r\n" + _HEADERS
                         + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        except OSError:
            pass


def authorization_code(http, auth: dict, endpoints: dict, client_id: str | None, ui: LoginUI, *, role: str) -> dict:
    """Sign in in the operator's browser; returns the token request fields for the code exchange."""
    if not endpoints.get("authorize"):
        raise AuthError("oidc-authorization-code needs an authorize_url or an issuer")
    if not client_id:
        raise AuthError("oidc-authorization-code needs a client_id")
    port, path, host = _loopback(auth.get("redirect_uri"))
    verifier, state = secrets.token_urlsafe(64), secrets.token_urlsafe(32)
    try:
        receiver = ui.listen(port, path)
    except OSError as exc:
        raise AuthError(f"the sign-in listener could not start on {host}:{port} ({type(exc).__name__})") from None
    with receiver:
        redirect_uri = auth.get("redirect_uri") or f"http://127.0.0.1:{receiver.port}{path}"
        params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
                  "scope": auth.get("scope") or "openid", "state": state,
                  "code_challenge": s256(verifier), "code_challenge_method": "S256",
                  "prompt": auth.get("prompt") or "login"}
        params.update({key: auth[key] for key in ("audience", "resource") if auth.get(key)})
        base = endpoints["authorize"]
        url = base + ("&" if "?" in base else "?") + urlencode(params)
        ui.say(f"Sign in as {_plain(role)} in your browser. If it does not open, open this URL:\n  {_plain(url, 4000)}")
        ui.open_url(url)
        query = receiver.wait(state)
    if query.get("error"):
        raise AuthError(f"the identity provider refused the sign-in{_error_code(query)}")
    if not query.get("code"):
        raise AuthError("the sign-in redirect carried no code")
    return {"grant_type": "authorization_code", "code": query["code"], "redirect_uri": redirect_uri,
            "code_verifier": verifier}


def device_code(http, auth: dict, endpoints: dict, client: tuple[dict, dict], ui: LoginUI, *, role: str,
                sleep=time.sleep, clock=time.time, remember=lambda value: None):
    """Sign in on any device with the code shown here; returns the successful token response."""
    if not endpoints.get("device") or not endpoints.get("token"):
        raise AuthError("oidc-device-code needs a device_url and a token_url, or an issuer that names both")
    fields, headers = client
    data = {**fields, **{key: auth[key] for key in ("scope", "audience", "resource") if auth.get(key)}}
    resp = http.request("POST", endpoints["device"], {"Accept": "application/json", **headers},
                        purpose="auth", data=data)
    body = _json(resp)
    device, user_code = body.get("device_code"), body.get("user_code")
    verify_url = body.get("verification_uri_complete") or body.get("verification_uri") or body.get("verification_url")
    if not 200 <= resp.status_code < 300 or not all(isinstance(v, str) and v for v in (device, user_code, verify_url)):
        raise AuthError(f"the device authorization request failed (HTTP {resp.status_code}){_error_code(body)}")
    remember(device)
    interval = _seconds(body.get("interval"), 5)
    deadline = clock() + min(_seconds(body.get("expires_in"), DEVICE_WAIT_S), DEVICE_WAIT_S)
    ui.say(f"Sign in as {_plain(role)}: open {_plain(verify_url)} and enter the code {_plain(user_code)}")
    grant = {**fields, "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": device}
    while clock() < deadline:
        sleep(interval)
        resp = http.request("POST", endpoints["token"], {"Accept": "application/json", **headers},
                            purpose="auth", data=grant)
        if 200 <= resp.status_code < 300:
            return resp
        error = _json(resp).get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        raise AuthError(f"the device sign-in ended without a token (HTTP {resp.status_code}){_error_code(_json(resp))}")
    raise AuthError("the device sign-in was not completed in time")


def _seconds(value, default: float) -> float:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) and value > 0 else default


def _plain(text: str, limit: int = 300) -> str:
    """Provider or configuration text for the terminal, without control or format characters."""
    return "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf"))[:limit]
