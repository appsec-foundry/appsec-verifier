"""Scope guard refuses out-of-scope destinations and honours the window (VER-001);
it fails closed on a scope without host and on unparseable URLs, and refuses
paths that normalise into another resource (VER-018)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from appsec_verifier.cli import _validate_scope
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


# ── fail closed ───────────────────────────────────────────────────────────────

def test_scope_without_a_host_allows_no_target():
    guard = ScopeGuard({"base_url": "localhost:3000"})          # scheme missing: no host, no port
    for url in ("https://169.254.169.254/latest/meta-data/", "https://evil.example:8443/x",
                "https://localhost:3000/", "http://localhost:3000/"):
        assert not guard.authorize(url, "target").allowed
    assert not guard.authorize("https://localhost:3000/login", "auth").allowed


def test_schema_rejects_a_base_url_without_scheme_and_host():
    base = {"schema_version": 1, "owner": {"name": "x"},
            "window": {"from": "2026-01-01T00:00:00Z", "until": "2026-12-31T23:59:59Z"}}
    assert _validate_scope({**base, "base_url": "localhost:3000"})
    assert _validate_scope({**base, "base_url": "https:///x"})
    assert _validate_scope({**base, "base_url": "https://localhost:3000"}) == []


@pytest.mark.parametrize("url", ["https://app.example.com:99999/api/x", "https://[::1/api/x", "", None, 42])
def test_unparseable_url_is_refused_not_raised(url):
    assert not g().authorize(url, "target").allowed
    assert not g().authorize(url, "auth").allowed


@pytest.mark.parametrize("host", ["0x7f000001", "2130706433", "[::ffff:a9fe:a9fe]", "app.example.com.",
                                  "app.example.com@evil.example"])
def test_alternate_host_spellings_are_refused(host):
    assert not g().authorize(f"https://{host}/api/x", "target").allowed


# ── paths decide on the resource actually reached ─────────────────────────────

@pytest.mark.parametrize("path", ["/api/x/../admin/wipe", "/api/./admin/wipe", "/api//admin/wipe",
                                  "/api/admin;x/wipe", "/api/;/admin/wipe", "/api/%2e%2e/admin/wipe",
                                  "/api/x%2Fadmin", "/api\\admin/wipe", "/api/%252e/x", "/api/x/..",
                                  "/api/x%00", "/public/../api/x", "/api/x\x00", "/api/x\r\nX-Injected: 1",
                                  "/api/x\x7f"])
def test_paths_that_normalise_elsewhere_are_refused(path):
    assert not g().authorize("https://app.example.com" + path, "target").allowed


@pytest.mark.parametrize("path", ["/api/Admin/wipe", "/api/ADMIN/wipe", "/api/%61dmin/wipe"])
def test_deny_paths_match_decoded_and_case_insensitively(path):
    assert not g().authorize("https://app.example.com" + path, "target").allowed


@pytest.mark.parametrize("path", ["/api/users/1", "/api/search?q=../x;y", "/api/files/report%20final.pdf",
                                  "/api/v1.2/items", "/api/%61bc"])
def test_ordinary_paths_and_queries_stay_allowed(path):
    assert g().authorize("https://app.example.com" + path, "target").allowed


def test_origin_allowed_checks_scheme_host_and_port_only():
    assert g().origin_allowed("https://app.example.com")
    assert not g().origin_allowed("https://app.example.com:8443")
    assert not g().origin_allowed("http://app.example.com")
    assert not g().origin_allowed("https://sso.example.com")
