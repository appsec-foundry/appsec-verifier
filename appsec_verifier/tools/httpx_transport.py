"""Real HTTP transport for GuardedHttpClient, backed by httpx (VER-029).

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
"""

from __future__ import annotations

import http.cookiejar
import os
from urllib.parse import quote, urlsplit, urlunsplit

import httpx


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
                 timeout: float = 30.0, client: httpx.Client | None = None):
        if client is None:
            # An explicit transport: the proxy is exactly the scope's, never one from the environment.
            transport = httpx.HTTPTransport(proxy=httpx.Proxy(proxy) if proxy else None, verify=verify)
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
    return HttpxTransport(proxy=_proxy_url(scope, env=env), verify=verify, timeout=timeout)
