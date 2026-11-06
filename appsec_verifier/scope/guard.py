"""Connection-time authorisation against the scope (VER-001, VER-018, VER-029).

The guard is the single decision point for "may the Verifier contact this URL?".
It checks the destination at the moment of use — scheme, host, port, path — and
classifies it by purpose: the target attack surface, an SSO/auth host, the SSRF
callback listener, or the declared proxy. Anything not covered is refused.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

_PURPOSES = ("target", "auth", "callback", "proxy")


@dataclass
class Decision:
    allowed: bool
    reason: str
    purpose: str | None = None


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _dissect(url: str) -> tuple[str, str, int | None, str]:
    u = urlparse(url)
    scheme = (u.scheme or "").lower()
    host = (u.hostname or "").lower()
    port = u.port or {"https": 443, "http": 80}.get(scheme)
    return scheme, host, port, (u.path or "/")


class ScopeGuard:
    def __init__(self, scope: dict):
        self.scope = scope or {}
        _, bh, bp, _ = _dissect(self.scope.get("base_url") or "")
        self.hosts = {h.lower() for h in (self.scope.get("hosts") or ([bh] if bh else []))}
        self.ports = set(self.scope.get("ports") or ([bp] if bp else []))
        self.schemes = set(self.scope.get("schemes") or ["https"])
        self.path_prefixes = self.scope.get("path_prefixes") or ["/"]
        self.deny_paths = self.scope.get("deny_paths") or []
        self.auth_hosts = self.scope.get("auth_hosts") or []
        self.callback = self.scope.get("callback") or {}
        self.proxy = self.scope.get("proxy") or {}

    def within_window(self, now: datetime | None = None) -> Decision:
        now = now or datetime.now(timezone.utc)
        w = self.scope.get("window") or {}
        frm, unt = _parse_iso(w.get("from")), _parse_iso(w.get("until"))
        if frm and now < frm:
            return Decision(False, f"before authorisation window (from {w.get('from')})")
        if unt and now > unt:
            return Decision(False, f"after authorisation window (until {w.get('until')})")
        return Decision(True, "within authorisation window")

    def _auth_host_matches(self, host: str, port: int | None) -> bool:
        for entry in self.auth_hosts:
            e = str(entry).strip().lower()
            if ":" in e:
                eh, _, ep = e.rpartition(":")
                if eh == host and (not ep or ep == str(port)):
                    return True
            elif e == host:
                return True
        return False

    def _on_target_host(self, host: str, port: int | None) -> bool:
        return host in self.hosts and (not self.ports or port in self.ports)

    def authorize(self, url: str, purpose: str = "target") -> Decision:
        if purpose not in _PURPOSES:
            return Decision(False, f"unknown purpose {purpose!r}", purpose)
        scheme, host, port, path = _dissect(url)
        if not host:
            return Decision(False, f"unparseable URL: {url!r}", purpose)

        if purpose == "target":
            if scheme not in self.schemes:
                return Decision(False, f"scheme {scheme!r} not allowed", purpose)
            if self.hosts and host not in self.hosts:
                return Decision(False, f"host {host!r} out of scope", purpose)
            if self.ports and port not in self.ports:
                return Decision(False, f"port {port} out of scope", purpose)
            if any(path.startswith(d) for d in self.deny_paths):
                return Decision(False, f"path {path!r} is explicitly denied", purpose)
            if not any(path.startswith(p) for p in self.path_prefixes):
                return Decision(False, f"path {path!r} outside allowed prefixes", purpose)
            return Decision(True, "target in scope", purpose)

        if purpose == "auth":
            if self._auth_host_matches(host, port) or self._on_target_host(host, port):
                return Decision(True, "authentication host allowed", purpose)
            return Decision(False, f"auth host {host}:{port} not declared in auth_hosts", purpose)

        if purpose == "callback":
            ch = (self.callback.get("host") or "").lower()
            cp = self.callback.get("port")
            if ch and host == ch and (cp is None or port == cp):
                return Decision(True, "callback listener allowed", purpose)
            return Decision(False, f"callback {host}:{port} is not the declared listener", purpose)

        # purpose == "proxy"
        _, ph, pp, _ = _dissect(self.proxy.get("url") or "")
        if ph and host == ph and (pp is None or port == pp):
            return Decision(True, "declared proxy allowed", purpose)
        return Decision(False, f"proxy {host}:{port} is not the declared proxy", purpose)
