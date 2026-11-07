"""Connection-time authorisation against the scope (VER-001, VER-018, VER-029).

The guard is the single decision point for "may the Verifier contact this URL?".
It checks the destination at the moment of use — scheme, host, port, path — and
classifies it by purpose: the target attack surface, an SSO/auth host, the SSRF
callback listener, or the declared proxy. Anything not covered is refused.

It fails closed: a scope without a usable host or port allows no target, and a
URL that cannot be parsed is refused, never raised. A path that a client or
server may normalise into a different resource (dot segments, `//`, `\\`, `;`,
encoded separators) is refused, so `deny_paths` and `path_prefixes` decide on
the resource that is actually reached; `deny_paths` match case-insensitively
on the decoded path (VER-018).

The authorisation window is checked on every request, not only at start: once
it has closed, `check_window` raises LimitExceeded("window") and the affected
work stops (VER-001, VER-015). The clock is injectable for tests.

`address_allowed` decides on the address a host name resolved to, when the
connection is made (VER-018; tools/httpx_transport.py calls it). Link-local
addresses (cloud metadata at 169.254.169.254 included), the other known
metadata addresses, multicast, unspecified and reserved addresses are never
contacted. Public addresses are allowed. Loopback, private and other
non-public addresses only when the scope's `networks` lists them, or when the
host itself is that address or `localhost`, i.e. the scope names it literally.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

from ..limits import LimitExceeded

_PURPOSES = ("target", "auth", "callback", "proxy")
# Raw path fragments that clients or servers normalise into another resource.
_AMBIGUOUS_PATH = ("//", "\\", ";", "%2e", "%2f", "%5c", "%3b", "%25", "%00")
# Cloud metadata endpoints outside link-local: AWS IPv6, Alibaba, Azure wire server.
_METADATA = frozenset(ipaddress.ip_address(a) for a in ("fd00:ec2::254", "100.100.100.200", "168.63.129.16"))
_NAT64 = ipaddress.ip_network("64:ff9b::/96")          # IPv6 prefix that embeds an IPv4 address


def parse_network(value) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """A scope `networks` entry as a network, or None when it is not one."""
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None


def _ip(value: str):
    """The address, with an IPv4 address embedded as IPv4-mapped or NAT64 IPv6 unwrapped."""
    try:
        ip = ipaddress.ip_address(str(value).strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.version == 6 and ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


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
    """Scheme, host, port and raw path. Raises ValueError for an unparseable URL
    (e.g. a port outside 0-65535)."""
    if not isinstance(url, str):
        raise ValueError("URL is not a string")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in url):
        raise ValueError("control character in URL")   # urlsplit would silently drop CR, LF and TAB
    u = urlsplit(url)
    scheme = (u.scheme or "").lower()
    host = (u.hostname or "").lower()
    port = u.port or {"https": 443, "http": 80}.get(scheme)
    return scheme, host, port, (u.path or "/")


def _safe_dissect(url) -> tuple[str, str, int | None, str] | None:
    try:
        return _dissect(url)
    except ValueError:
        return None


def _ambiguous_path(path: str) -> bool:
    low = path.lower()
    return any(a in low for a in _AMBIGUOUS_PATH) or any(seg in (".", "..") for seg in path.split("/"))


class ScopeGuard:
    def __init__(self, scope: dict, *, clock=None):
        self.scope = scope or {}
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        _, bh, bp, _ = _safe_dissect(self.scope.get("base_url") or "") or ("", "", None, "/")
        self.hosts = {h.lower() for h in (self.scope.get("hosts") or ([bh] if bh else []))}
        self.ports = set(self.scope.get("ports") or ([bp] if bp else []))
        self.schemes = set(self.scope.get("schemes") or ["https"])
        self.path_prefixes = self.scope.get("path_prefixes") or ["/"]
        self.deny_paths = self.scope.get("deny_paths") or []
        self.auth_hosts = self.scope.get("auth_hosts") or []
        self.callback = self.scope.get("callback") or {}
        self.proxy = self.scope.get("proxy") or {}
        self.networks = [n for n in map(parse_network, self.scope.get("networks") or []) if n is not None]

    def within_window(self, now: datetime | None = None) -> Decision:
        now = now or self._clock()
        w = self.scope.get("window") or {}
        frm, unt = _parse_iso(w.get("from")), _parse_iso(w.get("until"))
        if frm and now < frm:
            return Decision(False, f"before authorisation window (from {w.get('from')})")
        if unt and now > unt:
            return Decision(False, f"after authorisation window (until {w.get('until')})")
        return Decision(True, "within authorisation window")

    def address_allowed(self, host: str, address: str) -> Decision:
        """May a connection for `host` go to `address`, which `host` resolved to? (VER-018)"""
        ip = _ip(address)
        if ip is None:
            return Decision(False, f"{host} resolved to an unparseable address {str(address)[:60]!r}")
        # Python counts ::1 as reserved (it lies in ::/8); loopback is decided below like other internal addresses.
        if (ip.is_link_local or ip in _METADATA or ip.is_multicast or ip.is_unspecified
                or (ip.is_reserved and not ip.is_loopback)):
            return Decision(False, f"{host} resolved to {ip}, a link-local, metadata, multicast, unspecified or "
                                   "reserved address, which is never contacted (VER-018)")
        if ip.is_global or any(ip.version == n.version and ip in n for n in self.networks):
            return Decision(True, f"{ip} is allowed")
        if _ip(host) == ip or (host.lower().rstrip(".") == "localhost" and ip.is_loopback):
            return Decision(True, f"{ip} is the host the scope names")
        return Decision(False, f"{host} resolved to {ip}, which is not public; list its network in the "
                               "scope's `networks` to allow it (VER-018)")

    def check_window(self) -> None:
        """Raise LimitExceeded("window") unless now lies inside the authorisation window."""
        decision = self.within_window()
        if not decision.allowed:
            raise LimitExceeded("window", decision.reason)

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
        return host in self.hosts and port in self.ports

    def origin_allowed(self, url: str) -> bool:
        """Whether scheme, host and port of `url` are a target origin in scope."""
        parts = _safe_dissect(url)
        return bool(parts and parts[1]) and parts[0] in self.schemes and self._on_target_host(parts[1], parts[2])

    def authorize(self, url: str, purpose: str = "target") -> Decision:
        if purpose not in _PURPOSES:
            return Decision(False, f"unknown purpose {purpose!r}", purpose)
        parts = _safe_dissect(url)
        if parts is None or not parts[1]:
            return Decision(False, f"unparseable URL: {str(url)[:200]!r}", purpose)
        scheme, host, port, path = parts

        if purpose == "target":
            if scheme not in self.schemes:
                return Decision(False, f"scheme {scheme!r} not allowed", purpose)
            if not self.hosts or host not in self.hosts:
                return Decision(False, f"host {host!r} out of scope", purpose)
            if not self.ports or port not in self.ports:
                return Decision(False, f"port {port} out of scope", purpose)
            if _ambiguous_path(path):
                return Decision(False, f"path {path!r} is ambiguous (dot segment, '//', '\\', ';' or an "
                                       "encoded separator) and is refused", purpose)
            decoded = unquote(path)
            if any(decoded.lower().startswith(str(d).lower()) for d in self.deny_paths):
                return Decision(False, f"path {path!r} is explicitly denied", purpose)
            if not any(decoded.startswith(p) for p in self.path_prefixes):
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
        _, ph, pp, _ = _safe_dissect(self.proxy.get("url") or "") or ("", "", None, "/")
        if ph and host == ph and (pp is None or port == pp):
            return Decision(True, "declared proxy allowed", purpose)
        return Decision(False, f"proxy {host}:{port} is not the declared proxy", purpose)
