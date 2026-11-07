"""A run with the target URL alone, without a scope file (VER-001, VER-004): the
scope is that URL's scheme, host and port, read-only, without window or owner.
A missing or invalid URL blocks before anything is contacted, nothing outside
the host is allowed, intrusive mode stays read-only, and the report says there
was no scope file. Offline: a fake transport."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import yaml

from appsec_verifier import cli
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import httpx_transport
from appsec_verifier.verify.report import read_report

URL = "http://localhost:3000"
THREAT = {"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "idor", "evidence": {"file": "a.ts", "line": 1}}
INFO = {"profile": "anthropic-api", "model": "m", "runtime": "Anthropic API", "auth": "API key"}


class Target:
    """Fake transport: answers by (method, url) and records every call."""

    def __init__(self, answers=None):
        self.answers, self.calls = dict(answers or {}), []

    def __call__(self, method, url, headers, **kw):
        self.calls.append((method, url))
        if (method, url) not in self.answers:
            raise AssertionError(f"unexpected request {method} {url}")
        return self.answers[(method, url)]


def _ok():
    return SimpleNamespace(status_code=200, headers={}, json=lambda: (_ for _ in ()).throw(ValueError("no json")))


def _verify(tmp_path, monkeypatch, *extra):
    target, asked = Target({("GET", URL): _ok()}), []

    class Planner:
        def next_step(self, ctx, history):
            asked.append(ctx.plan.id)
            return {"verdict": {"verdict": "inconclusive", "rationale": "x"}}

    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, dict(INFO)))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: target)
    (tmp_path / "a.yaml").write_text(yaml.safe_dump({"threats": [THREAT]}))
    argv = ["verify", "--assessment", str(tmp_path / "a.yaml"), "--yes", "--test-all", "--output",
            str(tmp_path / "out"), *extra]
    return cli.main(argv), target, asked


def test_the_scope_of_a_url_is_its_host_and_port_read_only_without_window_or_owner():
    scope, errors = cli.url_scope(URL + "/app")
    assert errors == [] and scope == {"schema_version": 1, "base_url": URL + "/app", "schemes": ["http"],
                                      "allow_state_change": False}
    guard = ScopeGuard(scope)
    assert guard.authorize(URL + "/rest/products").allowed and guard.within_window().allowed
    for outside in ("http://localhost:3001/", "https://localhost:3000/", "http://evil.example/",
                    "http://127.0.0.2:3000/"):
        assert not guard.authorize(outside).allowed, outside


@pytest.mark.parametrize("url, expected", [
    (None, "a target URL is required"),
    ("", "a target URL is required"),
    ("localhost:3000", "absolute http or https URL"),
    ("ftp://files.example.com", "absolute http or https URL"),
    ("http://[::1", "absolute http or https URL"),
    ("http://admin:pw@localhost:3000", "leave credentials out of the URL"),
    ("http://local host:3000", "spaces or control characters"),
    ("http://localhost:3000/\x1b[2J", "spaces or control characters"),
    ("http://localhost:3000/a/../b", "ambiguous"),
])
def test_an_invalid_url_gives_no_scope(url, expected):
    scope, errors = cli.url_scope(url)
    assert scope is None and expected in errors[0]
    assert "pw" not in errors[0] and "\x1b" not in errors[0]


def test_verify_with_the_url_alone_contacts_only_that_host_and_says_so(tmp_path, monkeypatch, capsys):
    rc, target, asked = _verify(tmp_path, monkeypatch, "--url", URL)
    assert rc == cli.EXIT_OK and asked == ["T-1"]
    assert target.calls and all(url.startswith(URL + "/") or url == URL for _, url in target.calls)
    assert f"no scope file: only {URL}'s host and port, read-only" in capsys.readouterr().out
    doc, errors = read_report(tmp_path / "out" / "verification.yaml")
    assert errors == [] and doc["meta"]["scope"] == {"file": None, "sha256": None, "owner": None,
                                                     "window_from": None, "window_until": None}
    assert "no scope file" in (tmp_path / "out" / "verification.md").read_text()


def test_intrusive_mode_with_the_url_alone_stays_read_only(tmp_path, monkeypatch):
    rc, _, _ = _verify(tmp_path, monkeypatch, "--url", URL, "--allow-intrusive")
    doc, _ = read_report(tmp_path / "out" / "verification.yaml")
    assert rc == cli.EXIT_OK and doc["meta"]["safety"]["read_only"] is True


@pytest.mark.parametrize("extra, expected", [
    ((), "a target URL is required"),
    (("--url", "http://admin:pw@localhost:3000"), "leave credentials out of the URL"),
    (("--url", "file:///etc/passwd"), "absolute http or https URL"),
])
def test_verify_without_a_scope_file_and_a_valid_url_blocks_before_any_contact(tmp_path, monkeypatch, capsys,
                                                                                 extra, expected):
    rc, target, asked = _verify(tmp_path, monkeypatch, *extra)
    err = capsys.readouterr().err
    assert rc == cli.EXIT_BLOCKED and target.calls == [] and asked == []
    assert expected in err and "Nothing was contacted." in err and "pw@" not in err
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("extra, status, expected", [
    (("--url", URL), "ok", f"no scope file: only {URL}'s host and port, read-only"),
    ((), "fail", "a target URL is required"),
])
def test_preflight_takes_the_url_alone(tmp_path, capsys, extra, status, expected):
    (tmp_path / "a.yaml").write_text(yaml.safe_dump({"threats": [THREAT]}))
    cli.main(["preflight", "--assessment", str(tmp_path / "a.yaml"), "--offline", "--json", *extra])
    scope = next(c for c in json.loads(capsys.readouterr().out)["checks"] if c["check"] == "Scope")
    assert scope["status"] == status and scope["message"].startswith(expected)
