"""Real HTTP transport for GuardedHttpClient, backed by httpx (VER-018, VER-029).

It is the plug the guarded client sends through: `transport(method, url, headers,
**kwargs) -> httpx.Response`. Redirects are NOT followed here — GuardedHttpClient
follows them so it can re-authorise each hop and drop cross-origin credentials
(VER-018). Proxy routing and its credentials come from the scope only; proxy
variables in the environment (HTTP_PROXY, HTTPS_PROXY, ...) are ignored, and
proxy credentials are read from the environment variables the scope names,
never inlined (VER-016, VER-029).

The client keeps no cookies. A cookie the target sets is neither stored nor
sent again, so one identity's session can never ride along on another
identity's or an anonymous request; sessions travel only in the headers
SessionManager attaches (VER-010, VER-028).

Addresses are checked when the connection is made (VER-018): the network
backend resolves the host once, checks every address it got with the scope's
`address_allowed`, refuses the connection with ScopeViolation if any of them is
not allowed, and connects to a checked address, never by name again. TLS still
verifies the host name. Through a proxy the connection, and so the check, goes
to the proxy; the proxy resolves the target. httpx (0.25 to 0.28) offers no
option for the backend, so it is set on the transport's httpcore pool; if that
pool is not where it is expected, the transport is not built at all.
"""

from __future__ import annotations

import http.cookiejar
import os
import socket
from urllib.parse import quote, urlsplit, urlunsplit

import httpcore
import httpx

from ..scope.guard import ScopeGuard
from .http import ScopeViolation


class AddressCheckingBackend(httpcore.NetworkBackend):
    """httpcore network backend that resolves once, checks, and connects to the checked address."""

    def __init__(self, check, *, inner: httpcore.NetworkBackend | None = None, resolve=socket.getaddrinfo):
        self._check = check                    # check(host, address) -> Decision
        self._inner = inner or httpcore.SyncBackend()
        self._resolve = resolve

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        host = host.decode("ascii") if isinstance(host, bytes) else str(host)
        try:
            infos = self._resolve(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise httpcore.ConnectError(f"cannot resolve {host}") from exc
        addresses = list(dict.fromkeys(info[4][0] for info in infos))
        if not addresses:
            raise httpcore.ConnectError(f"no address for {host}")
        for address in addresses:              # all of them: a mixed answer is refused as a whole
            decision = self._check(host, address)
            if not decision.allowed:
                raise ScopeViolation(decision.reason)
        failure = None
        for address in addresses:
            try:
                return self._inner.connect_tcp(address, port, timeout=timeout, local_address=local_address,
                                               socket_options=socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                failure = exc
        raise failure

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise ScopeViolation("Unix sockets are never used")

    def sleep(self, seconds):
        self._inner.sleep(seconds)


def _install_backend(transport: httpx.HTTPTransport, backend: httpcore.NetworkBackend) -> None:
    pool = getattr(transport, "_pool", None)
    if pool is None or not hasattr(pool, "_network_backend"):
        raise RuntimeError("this httpx/httpcore version gives no way to check addresses at connection time")
    pool._network_backend = backend


class _NoCookies(http.cookiejar.CookiePolicy):
    """Store no cookie and send none."""

    netscape, rfc2965, hide_cookie2 = True, False, False

    def set_ok(self, cookie, request):
        return False

    def return_ok(self, cookie, request):
        return False

    def domain_return_ok(self, domain, request):
        return False

    def path_return_ok(self, path, request):
        return False


class HttpxTransport:
    def __init__(self, *, proxy: str | None = None, verify: bool = True,
                 timeout: float = 30.0, client: httpx.Client | None = None, address_check=None,
                 network_backend: httpcore.NetworkBackend | None = None, resolve=socket.getaddrinfo):
        if client is None:
            # An explicit transport: the proxy is exactly the scope's, never one from the environment.
            transport = httpx.HTTPTransport(proxy=httpx.Proxy(proxy) if proxy else None, verify=verify)
            if address_check is not None:
                _install_backend(transport, AddressCheckingBackend(address_check, inner=network_backend,
                                                                   resolve=resolve))
            client = httpx.Client(transport=transport, timeout=timeout, follow_redirects=False, trust_env=False)
        client.cookies.jar.set_policy(_NoCookies())
        self._client = client

    def __call__(self, method: str, url: str, headers: dict, **kwargs) -> httpx.Response:
        return self._client.request(method, url, headers=headers, **kwargs)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpxTransport:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _proxy_url(scope: dict, env=None) -> str | None:
    """Build the proxy URL from scope.proxy, injecting credentials from the
    environment when the proxy authenticates (VER-029)."""
    env = env if env is not None else os.environ
    proxy = (scope.get("proxy") or {})
    url = proxy.get("url")
    if not url:
        return None
    user_env, pass_env = proxy.get("username_env"), proxy.get("password_env")
    if user_env and pass_env:
        user, pwd = env.get(user_env), env.get(pass_env)
        if user and pwd:
            parts = urlsplit(url)
            netloc = f"{quote(user, safe='')}:{quote(pwd, safe='')}@{parts.netloc}"
            url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return url


def transport_from_scope(scope: dict, *, verify: bool = True, timeout: float = 30.0, env=None) -> HttpxTransport:
    return HttpxTransport(proxy=_proxy_url(scope, env=env), verify=verify, timeout=timeout,
                          address_check=ScopeGuard(scope).address_allowed)
