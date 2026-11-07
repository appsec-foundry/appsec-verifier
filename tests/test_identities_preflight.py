"""The identities file is checked before anything is contacted: schema, set
environment variables, authentication endpoints and origins in scope. A failed
check blocks the run (VER-016, VER-025, VER-028)."""

from __future__ import annotations

import pytest
import yaml

from appsec_verifier import cli
from appsec_verifier.cli import _check_identities
from appsec_verifier.scope import ScopeGuard

SCOPE = {"schema_version": 1, "base_url": "https://app.example.com", "owner": {"name": "tester"},
         "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"},
         "auth_hosts": ["sso.example.com"]}
GUARD = ScopeGuard(SCOPE)


def _file(tmp_path, identities):
    path = tmp_path / "identities.yaml"
    path.write_text(yaml.safe_dump({"identities": identities}))
    return str(path)


def test_valid_identities_pass(tmp_path):
    path = _file(tmp_path, [
        {"role": "anonymous", "method": "none"},
        {"role": "alice", "method": "form",
         "auth": {"login_url": "https://app.example.com/login", "username_env": "AU", "password_env": "AP"}},
        {"role": "svc", "method": "oidc-client-credentials",
         "auth": {"token_url": "https://sso.example.com/token", "client_secret_env": "CS"}},
    ])
    identities, errors = _check_identities(path, GUARD, {"AU": "alice", "AP": "pw", "CS": "s3cr3t"})
    assert errors == [] and [i["role"] for i in identities] == ["anonymous", "alice", "svc"]


def test_no_identities_file_is_fine():
    assert _check_identities(None, GUARD, {}) == ([], [])


@pytest.mark.parametrize("identities, env, expected", [
    ([{"role": "a", "method": "bearer", "auth": {"token_env": "TOK"}}], {}, "TOK"),
    ([{"role": "a", "method": "bearer", "auth": {"token_env": "TOK"}}], {"TOK": ""}, "TOK"),
    ([{"role": "a", "method": "form", "auth": {"login_url": "https://evil.example/login",
                                               "username_env": "U", "password_env": "P"}}],
     {"U": "u", "P": "p"}, "login_url"),
    ([{"role": "a", "method": "bearer", "auth": {"token_env": "T", "target_origin": "https://other.example"}}],
     {"T": "t"}, "target_origin"),
    ([{"role": "a", "method": "none"}, {"role": "a", "method": "none"}], {}, "more than once"),
    ([{"role": "a", "method": "oidc-authorization-code",
       "auth": {"authorize_url": "https://sso.example.com/a", "token_url": "https://sso.example.com/t",
                "username_env": "U", "password_env": "P"}}], {"U": "u", "P": "p"}, "not implemented"),
    ([{"role": "a", "method": "bearer"}], {}, "auth"),                       # schema: auth required
    ([{"role": "a", "method": "magic"}], {}, "magic"),                       # schema: unknown method
])
def test_unusable_identities_are_reported(tmp_path, identities, env, expected):
    _, errors = _check_identities(_file(tmp_path, identities), GUARD, env)
    assert any(expected in e for e in errors)


def test_errors_name_variables_never_values(tmp_path):
    path = _file(tmp_path, [{"role": "a", "method": "basic", "auth": {"username_env": "U", "password_env": "P"}}])
    _, errors = _check_identities(path, GUARD, {"U": "VALUE-OF-U"})
    assert errors and not any("VALUE-OF-U" in e for e in errors)


def test_unreadable_identities_file_is_an_error(tmp_path):
    _, errors = _check_identities(str(tmp_path / "missing.yaml"), GUARD, {})
    assert errors == ["cannot read the identities file: FileNotFoundError"]


def test_verify_blocks_before_any_contact_when_a_secret_is_missing(tmp_path, monkeypatch, capsys):
    (tmp_path / "scope.yaml").write_text(yaml.safe_dump(SCOPE))
    (tmp_path / "assessment.yaml").write_text(yaml.safe_dump({"threats": [
        {"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "idor",
         "evidence": {"file": "routes/basket.ts", "line": 1}}]}))
    ids = _file(tmp_path, [{"role": "alice", "method": "bearer", "auth": {"token_env": "ALICE_TOKEN"}}])
    monkeypatch.delenv("ALICE_TOKEN", raising=False)

    def must_not_run(*a, **k):
        raise AssertionError("the run went past the identity check")

    monkeypatch.setattr(cli, "_build_planner_factory", must_not_run)
    rc = cli.main(["verify", "--assessment", str(tmp_path / "assessment.yaml"), "--scope",
                   str(tmp_path / "scope.yaml"), "--identities", ids, "--output", str(tmp_path / "out")])
    assert rc == cli.EXIT_BLOCKED
    assert "ALICE_TOKEN" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
