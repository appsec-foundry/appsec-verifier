"""Real HTTP transport for GuardedHttpClient, backed by httpx (VER-029).

It is the plug the guarded client sends through: `transport(method, url, headers,
**kwargs) -> httpx.Response`. Redirects are NOT followed here — GuardedHttpClient
follows them so it can re-authorise each hop and drop cross-origin credentials
(VER-018). Proxy routing and its credentials come from the scope; proxy
credentials are read from the environment, never inlined (VER-016, VER-029).
"""

from __future__ import annotations

import os
from urllib.parse import quote, urlsplit, urlunsplit

import httpx


class HttpxTransport:
    def __init__(self, *, proxy: str | None = None, verify: bool = True,
                 timeout: float = 30.0, client: httpx.Client | None = None):
        self._client = client or httpx.Client(
            proxies=proxy, verify=verify, timeout=timeout, follow_redirects=False,
        )

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
