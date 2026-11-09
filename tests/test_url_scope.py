"""A run with the target URL alone, without a scope file (VER-001, VER-004): the
scope is that URL's scheme, host and port, without window or owner. A missing or
invalid URL blocks before anything is contacted, nothing outside the host is
allowed, writes need --allow-intrusive (VER-030), and the report says there was
no scope file. A scope file with allow_state_change: false blocks an intrusive
run before any contact. Offline: a fake transport."""

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


def test_the_scope_of_a_url_is_its_host_and_port_without_window_or_owner():
    scope, errors = cli.url_scope(URL + "/app")
    assert errors == [] and scope == {"schema_version": 1, "base_url": URL + "/app", "schemes": ["http"]}
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
    assert f"Target     : {URL} (no scope file: only this host and port)" in capsys.readouterr().out
    doc, errors = read_report(tmp_path / "out" / "verification.yaml")
    assert errors == [] and doc["meta"]["scope"] == {"file": None, "sha256": None, "owner": None,
                                                     "window_from": None, "window_until": None}
    assert "no scope file" in (tmp_path / "out" / "verification.md").read_text()


def test_without_allow_intrusive_the_url_alone_stays_read_only(tmp_path, monkeypatch):
    rc, _, _ = _verify(tmp_path, monkeypatch, "--url", URL)
    doc, _ = read_report(tmp_path / "out" / "verification.yaml")
    assert rc == cli.EXIT_OK and doc["meta"]["safety"]["read_only"] is True


def test_allow_intrusive_alone_permits_writes_with_the_url_alone(tmp_path, monkeypatch):
    rc, _, _ = _verify(tmp_path, monkeypatch, "--url", URL, "--allow-intrusive")
    doc, _ = read_report(tmp_path / "out" / "verification.yaml")
    assert rc == cli.EXIT_OK and doc["meta"]["safety"]["read_only"] is False


def test_read_only_wins_over_allow_intrusive(tmp_path, monkeypatch):
    rc, _, _ = _verify(tmp_path, monkeypatch, "--url", URL, "--allow-intrusive", "--read-only")
    doc, _ = read_report(tmp_path / "out" / "verification.yaml")
    assert rc == cli.EXIT_OK and doc["meta"]["safety"]["read_only"] is True


def _scope_file(tmp_path, **extra):
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump({"schema_version": 1, "base_url": URL, "owner": {"name": "t"},
                                    "window": {"from": "2020-01-01T00:00:00Z", "until": "2099-01-01T00:00:00Z"},
                                    **extra}))
    return str(path)


@pytest.mark.parametrize("extra", [{}, {"allow_state_change": True}])
def test_a_scope_file_that_does_not_forbid_writes_leaves_them_to_allow_intrusive(tmp_path, monkeypatch, extra):
    rc, _, _ = _verify(tmp_path, monkeypatch, "--scope", _scope_file(tmp_path, **extra), "--allow-intrusive")
    doc, _ = read_report(tmp_path / "out" / "verification.yaml")
    assert rc == cli.EXIT_OK and doc["meta"]["safety"]["read_only"] is False


def test_a_scope_file_that_forbids_writes_blocks_an_intrusive_run_before_any_contact(tmp_path, monkeypatch, capsys):
    scope = _scope_file(tmp_path, allow_state_change=False)
    rc, target, asked = _verify(tmp_path, monkeypatch, "--scope", scope, "--allow-intrusive")
    err = capsys.readouterr().err
    assert rc == cli.EXIT_BLOCKED and target.calls == [] and asked == []
    assert "forbids write requests" in err and "Nothing was contacted." in err
    assert not (tmp_path / "out").exists()


def test_a_scope_file_that_forbids_writes_still_runs_read_only(tmp_path, monkeypatch):
    scope = _scope_file(tmp_path, allow_state_change=False)
    for extra in ((), ("--allow-intrusive", "--read-only")):
        rc, _, _ = _verify(tmp_path, monkeypatch, "--scope", scope, "--overwrite", *extra)
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


def test_the_markdown_report_given_as_assessment_is_named_as_such(tmp_path, monkeypatch, capsys):
    report = tmp_path / "security-assessment.md"
    report.write_text("---\ntitle: x\n---\n# Report\n\n---\n| a | b |\n")
    target = Target()
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: target)
    rc = cli.main(["verify", "--assessment", str(report), "--url", URL, "--yes", "--output", str(tmp_path / "o")])
    err = capsys.readouterr().err
    assert rc == cli.EXIT_BLOCKED and "Markdown report; give the security-assessment.yaml" in err
    assert target.calls == []


@pytest.mark.parametrize("errors, expected, unexpected", [
    (["a: environment variable X (password_env) is not set"], "export the variables", "auth_hosts"),
    (["a: login_url is refused for authentication: auth host localhost:3000 not declared in auth_hosts"],
     "e.g. localhost, not 127.0.0.1", "export"),
    (["role 'a' is defined more than once"], "correct the identities file", "export"),
])
def test_the_identities_hint_follows_the_cause(errors, expected, unexpected):
    fix = cli._identities_fix(errors)
    assert expected in fix and unexpected not in fix and fix.endswith("or start without --identities")


def test_preflight_asks_for_no_credential_when_the_assessment_cannot_be_used(tmp_path, monkeypatch, capsys):
    asked = []
    monkeypatch.setattr(cli, "_ask_secret", lambda prompt: asked.append(prompt) or "")
    monkeypatch.setattr(cli, "_stdin_is_terminal", lambda: True)
    (tmp_path / "a.md").write_text("---\nx: [\n")
    (tmp_path / "ids.yaml").write_text(yaml.safe_dump({"identities": [
        {"role": "a", "method": "bearer", "auth": {"token_env": "NOT_SET_TOKEN"}}]}))
    monkeypatch.delenv("NOT_SET_TOKEN", raising=False)
    cli.main(["preflight", "--assessment", str(tmp_path / "a.md"), "--url", URL, "--offline", "--json",
              "--identities", str(tmp_path / "ids.yaml")])
    checks = {c["check"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["Assessment"]["status"] == "fail" and "Markdown report" in checks["Assessment"]["message"]
    assert checks["Identities"]["message"] == "not checked: an earlier check failed" and asked == []


@pytest.mark.parametrize("extra, status, expected", [
    (("--url", URL), "ok", f"no scope file: only {URL}'s host and port"),
    ((), "fail", "a target URL is required"),
])
def test_preflight_takes_the_url_alone(tmp_path, capsys, extra, status, expected):
    (tmp_path / "a.yaml").write_text(yaml.safe_dump({"threats": [THREAT]}))
    cli.main(["preflight", "--assessment", str(tmp_path / "a.yaml"), "--offline", "--json", *extra])
    scope = next(c for c in json.loads(capsys.readouterr().out)["checks"] if c["check"] == "Scope")
    assert scope["status"] == status and scope["message"].startswith(expected)
