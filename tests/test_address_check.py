"""Addresses are checked when the connection is made (VER-018): a host name is
resolved once, every address is checked against the scope, and the connection
goes to a checked address. No test opens a real connection: the resolver is a
fake or gets a numeric address, and httpcore.MockBackend answers."""

from __future__ import annotations

import socket

import httpcore
import pytest

from appsec_verifier.cli import _validate_scope
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient, ScopeViolation
from appsec_verifier.tools.httpx_transport import (
    AddressCheckingBackend,
    HttpxTransport,
    _install_backend,
    transport_from_scope,
)

SCOPE = {"base_url": "http://app.example.com", "hosts": ["app.example.com"], "ports": [80],
         "schemes": ["http"], "path_prefixes": ["/"]}
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


# ── the rule ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("host, address, networks, allowed", [
    ("app.example.com", "93.184.215.14", [], True),                   # public
    ("app.example.com", "2606:2800:21f:cb07:6820:80da:af6b:8b2c", [], True),
    ("app.example.com", "127.0.0.1", [], False),                      # rebinding to loopback
    ("app.example.com", "::1", [], False),
    ("app.example.com", "::ffff:127.0.0.1", [], False),               # IPv4-mapped loopback
    ("app.example.com", "10.1.2.3", [], False),                       # private
    ("app.example.com", "10.1.2.3", ["10.0.0.0/8"], True),            # declared network
    ("app.example.com", "10.1.2.3", ["192.168.0.0/16"], False),
    ("app.example.com", "100.64.1.1", [], False),                     # shared address space
    ("app.example.com", "fd12::5", ["fd12::/48"], True),
    ("localhost", "127.0.0.1", [], True),                             # named literally by the scope
    ("localhost", "::1", [], True),
    ("localhost", "10.0.0.1", [], False),
    ("10.9.9.9", "10.9.9.9", [], True),
    ("app.example.com", "169.254.169.254", [], False),                # cloud metadata
    ("app.example.com", "169.254.169.254", ["169.254.0.0/16"], False),  # never, whatever is listed
    ("169.254.169.254", "169.254.169.254", [], False),
    ("app.example.com", "::ffff:169.254.169.254", ["0.0.0.0/0"], False),
    ("app.example.com", "64:ff9b::a9fe:a9fe", [], False),             # NAT64 form of the metadata address
    ("app.example.com", "fe80::1%eth0", ["fe80::/10"], False),        # IPv6 link-local
    ("app.example.com", "fd00:ec2::254", ["fd00::/8"], False),        # AWS IPv6 metadata
    ("app.example.com", "100.100.100.200", ["100.64.0.0/10"], False),  # Alibaba metadata
    ("app.example.com", "168.63.129.16", [], False),                  # Azure wire server
    ("app.example.com", "0.0.0.0", ["0.0.0.0/0"], False),
    ("app.example.com", "224.0.0.1", [], False),
    ("app.example.com", "240.0.0.1", [], False),
    ("app.example.com", "not-an-ip", [], False),
])
def test_address_rule(host, address, networks, allowed):
    assert ScopeGuard(dict(SCOPE, networks=networks)).address_allowed(host, address).allowed is allowed


def test_invalid_networks_entries_block_the_scope_and_allow_nothing():
    scope = dict(SCOPE, schema_version=1, owner={"name": "t"}, networks=["10.0.0.0/8", "intranet", "10.0.0.0/33"])
    errors = _validate_scope(scope)
    assert any("'intranet'" in e for e in errors) and any("'10.0.0.0/33'" in e for e in errors)
    assert not any("'10.0.0.0/8'" in e for e in errors)
    assert ScopeGuard(scope).networks == [__import__("ipaddress").ip_network("10.0.0.0/8")]


# ── the connection ────────────────────────────────────────────────────────────

class Resolver:
    """Fake getaddrinfo: answers from a list per call, records the hosts asked for."""

    def __init__(self, *answers):
        self.answers, self.asked = list(answers), []

    def __call__(self, host, port, type=0):
        self.asked.append(host)
        addresses = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
                for a in addresses]


class Backend(httpcore.MockBackend):
    """MockBackend that records the addresses it was asked to connect to."""

    def __init__(self):
        super().__init__([OK])
        self.connected = []

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.connected.append(host)
        return super().connect_tcp(host, port, timeout, local_address, socket_options)


def _client(resolver, backend, scope=SCOPE, proxy=None):
    guard = ScopeGuard(scope)
    transport = HttpxTransport(proxy=proxy, address_check=guard.address_allowed, network_backend=backend,
                               resolve=resolver)
    return GuardedHttpClient(guard, RunBudget(Limits(rate_rps=0)), transport)


def test_a_public_address_is_connected_by_address_not_by_name():
    backend, resolver = Backend(), Resolver(["93.184.215.14"])
    assert _client(resolver, backend).request("GET", "http://app.example.com/a").text == "ok"
    assert resolver.asked == ["app.example.com"] and backend.connected == ["93.184.215.14"]


@pytest.mark.parametrize("addresses", [["127.0.0.1"], ["93.184.215.14", "169.254.169.254"], ["10.0.0.7"]])
def test_a_refused_address_stops_the_request_before_any_connection(addresses):
    backend = Backend()
    with pytest.raises(ScopeViolation, match="VER-018"):
        _client(Resolver(addresses), backend).request("GET", "http://app.example.com/a")
    assert backend.connected == []


def test_a_dns_change_between_connections_is_checked_again():
    backend = Backend()
    http = _client(Resolver(["93.184.215.14"], ["127.0.0.1"]), backend)
    http.request("GET", "http://app.example.com/a")                   # the answer closes the connection
    with pytest.raises(ScopeViolation):
        http.request("GET", "http://app.example.com/b")
    assert backend.connected == ["93.184.215.14"]


def test_a_declared_network_is_reached():
    backend = Backend()
    http = _client(Resolver(["10.20.0.5"]), backend, scope=dict(SCOPE, networks=["10.20.0.0/16"]))
    assert http.request("GET", "http://app.example.com/a").status_code == 200
    assert backend.connected == ["10.20.0.5"]


def test_through_a_proxy_the_proxy_address_is_checked():
    scope = dict(SCOPE, proxy={"url": "http://proxy.corp.example:8080"})
    backend, resolver = Backend(), Resolver(["10.0.0.5"])
    with pytest.raises(ScopeViolation):
        _client(resolver, backend, scope=scope, proxy="http://proxy.corp.example:8080").request(
            "GET", "http://app.example.com/a")
    assert resolver.asked == ["proxy.corp.example"] and backend.connected == []
    backend = Backend()
    allowed = dict(scope, networks=["10.0.0.0/8"])
    _client(Resolver(["10.0.0.5"]), backend, scope=allowed, proxy="http://proxy.corp.example:8080").request(
        "GET", "http://app.example.com/a")
    assert backend.connected == ["10.0.0.5"]


def _no_proxy_client(resolver, backend, no_proxy):
    scope = dict(SCOPE, hosts=["app.example.com", "localhost"], networks=["10.0.0.0/8"],
                 proxy={"url": "http://proxy.corp.example:8080", "no_proxy": no_proxy})
    guard = ScopeGuard(scope)
    transport = HttpxTransport(proxy="http://proxy.corp.example:8080", no_proxy=no_proxy,
                               address_check=guard.address_allowed, network_backend=backend, resolve=resolver)
    return GuardedHttpClient(guard, RunBudget(Limits(rate_rps=0)), transport)


def test_no_proxy_hosts_are_reached_directly_and_checked():
    backend, resolver = Backend(), Resolver(["127.0.0.1"], ["10.0.0.5"])
    http = _no_proxy_client(resolver, backend, ["LOCALHOST", "127.0.0.1"])
    http.request("GET", "http://localhost/a")                          # direct: the target name is resolved
    http.request("GET", "http://app.example.com/a")                    # through the proxy
    assert resolver.asked == ["localhost", "proxy.corp.example"]
    assert backend.connected == ["127.0.0.1", "10.0.0.5"]


def test_a_direct_connection_still_refuses_a_forbidden_address():
    backend = Backend()
    http = _no_proxy_client(Resolver(["169.254.169.254"]), backend, ["app.example.com"])
    with pytest.raises(ScopeViolation, match="never contacted"):
        http.request("GET", "http://app.example.com/a")
    assert backend.connected == []


@pytest.mark.parametrize("entry, valid", [("localhost", True), ("10.0.0.5", True), ("[::1]", True),
                                          ("*.corp.example", False), ("corp.example/24", False), ("", False)])
def test_no_proxy_entries_must_be_exact_hosts(entry, valid):
    from appsec_verifier.cli import _validate_scope

    scope = {"schema_version": 1, "base_url": "https://app.example.com", "owner": {"name": "x"},
             "window": {"from": "2026-01-01T00:00:00Z", "until": "2026-12-31T23:59:59Z"},
             "proxy": {"url": "http://proxy.corp.example:8080", "no_proxy": [entry]}}
    assert (_validate_scope(scope) == []) is valid


def test_an_unusual_address_spelling_resolves_and_is_refused():
    """A host written as a decimal number is the metadata address 169.254.169.254;
    the real resolver turns it into that address without any DNS query."""
    scope = dict(SCOPE, hosts=["2852039166"])
    backend = AddressCheckingBackend(ScopeGuard(scope).address_allowed, inner=Backend())
    with pytest.raises(ScopeViolation, match="169.254.169.254"):
        backend.connect_tcp("2852039166", 80)


def test_unix_sockets_are_never_used():
    with pytest.raises(ScopeViolation):
        AddressCheckingBackend(ScopeGuard(SCOPE).address_allowed).connect_unix_socket("/run/docker.sock")


def test_transport_from_scope_checks_addresses():
    scope = dict(SCOPE, hosts=["169.254.169.254"], base_url="http://169.254.169.254")
    http = GuardedHttpClient(ScopeGuard(scope), RunBudget(Limits(rate_rps=0)), transport_from_scope(scope))
    with pytest.raises(ScopeViolation, match="never contacted"):
        http.request("GET", "http://169.254.169.254/latest/meta-data/")


def test_no_transport_without_the_address_check():
    class Unknown:
        pass

    with pytest.raises(RuntimeError, match="connection time"):
        _install_backend(Unknown(), AddressCheckingBackend(ScopeGuard(SCOPE).address_allowed))
