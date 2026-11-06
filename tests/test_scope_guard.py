"""Scope guard refuses out-of-scope destinations and honours the window (VER-001)."""

from __future__ import annotations

from datetime import datetime, timezone

from appsec_verifier.scope import ScopeGuard

SCOPE = {
    "base_url": "https://app.example.com",
    "hosts": ["app.example.com"],
    "ports": [443],
    "schemes": ["https"],
    "path_prefixes": ["/api/"],
    "deny_paths": ["/api/admin/"],
    "window": {"from": "2026-01-01T00:00:00Z", "until": "2026-12-31T23:59:59Z"},
    "auth_hosts": ["sso.example.com:443"],
    "callback": {"host": "cb.example.com", "port": 8000},
    "proxy": {"url": "http://proxy.corp:8080"},
}


def g():
    return ScopeGuard(SCOPE)


def test_target_in_scope_allowed():
    assert g().authorize("https://app.example.com/api/users/1", "target").allowed


def test_wrong_host_refused():
    assert not g().authorize("https://evil.example/api/x", "target").allowed


def test_wrong_scheme_refused():
    assert not g().authorize("http://app.example.com/api/x", "target").allowed


def test_wrong_port_refused():
    assert not g().authorize("https://app.example.com:8443/api/x", "target").allowed


def test_path_outside_prefix_refused():
    assert not g().authorize("https://app.example.com/public/x", "target").allowed


def test_deny_path_wins_over_allow():
    assert not g().authorize("https://app.example.com/api/admin/wipe", "target").allowed


def test_auth_host_allowed_only_for_auth_purpose():
    assert g().authorize("https://sso.example.com/token", "auth").allowed
    # the SSO host is NOT part of the attack surface
    assert not g().authorize("https://sso.example.com/token", "target").allowed


def test_callback_requires_declared_host_and_port():
    assert g().authorize("http://cb.example.com:8000/hit", "callback").allowed
    assert not g().authorize("http://cb.example.com:9000/hit", "callback").allowed


def test_proxy_destination_matches_declared_proxy():
    assert g().authorize("http://proxy.corp:8080", "proxy").allowed
    assert not g().authorize("http://other.proxy:8080", "proxy").allowed


def test_window_before_and_after():
    guard = g()
    assert not guard.within_window(datetime(2025, 6, 1, tzinfo=timezone.utc)).allowed
    assert guard.within_window(datetime(2026, 6, 1, tzinfo=timezone.utc)).allowed
    assert not guard.within_window(datetime(2027, 6, 1, tzinfo=timezone.utc)).allowed


def test_unknown_purpose_refused():
    assert not g().authorize("https://app.example.com/api/x", "exfiltrate").allowed
