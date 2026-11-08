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
                "client_id": "cli", "username_env": "U", "password_env": "P"}}], {"U": "u", "P": "p"},
     "remove username_env and password_env"),
    ([{"role": "a", "method": "oidc-authorization-code",                    # without a terminal (VER-028)
       "auth": {"issuer": "https://sso.example.com", "client_id": "cli"}}], {}, "needs a person to sign in"),
    ([{"role": "a", "method": "oidc-device-code",
       "auth": {"issuer": "https://sso.example.com", "client_id": "cli"}}], {}, "needs a person to sign in"),
    ([{"role": "a", "method": "oidc-authorization-code", "auth": {
        "issuer": "https://sso.example.com", "client_id": "cli", "redirect_uri": "https://evil.example/cb"}}],
     {}, "redirect_uri must be http://127.0.0.1"),
    ([{"role": "a", "method": "oidc-authorization-code",                    # discovery host out of scope
       "auth": {"issuer": "https://rogue.example", "client_id": "cli"}}], {}, "issuer is refused"),
    ([{"role": "a", "method": "command", "auth": {"command": ["./no-such-login.sh"]}}], {}, "not found"),
    ([{"role": "a", "method": "command", "auth": {"command": ["true"], "headers": ["Host"]}}], {},
     "cannot be set by an identity"),
    ([{"role": "a", "method": "session", "auth": {"headers_env": {"Cookie": "SESS"}}}], {}, "SESS"),
    ([{"role": "a", "method": "form", "auth": {"login_url": "http://sso.example.com/login",   # https-only scope
                                               "username_env": "U", "password_env": "P"}}],
     {"U": "u", "P": "p"}, "scheme 'http' not allowed for authentication"),
    ([{"role": "a", "method": "bearer"}], {}, "auth"),                       # schema: auth required
    ([{"role": "a", "method": "magic"}], {}, "magic"),                       # schema: unknown method
])
def test_unusable_identities_are_reported(tmp_path, identities, env, expected):
    _, errors = _check_identities(_file(tmp_path, identities), GUARD, env)
    assert any(expected in e for e in errors)


def test_an_interactive_run_asks_once_for_each_missing_value_and_keeps_it_out_of_the_environment(tmp_path):
    import os

    path = _file(tmp_path, [
        {"role": "a", "method": "basic", "auth": {"username_env": "SHARED_U", "password_env": "A_PW"}},
        {"role": "b", "method": "basic", "auth": {"username_env": "SHARED_U", "password_env": "B_PW"}},
    ])
    asked, secrets = [], {}

    def ask(prompt):
        asked.append(prompt)
        return "" if "B_PW" in prompt else "typed-value"

    identities, errors = _check_identities(path, GUARD, {}, interactive=True, secrets=secrets, ask_secret=ask)
    assert sorted(p.split(":")[1].split()[0] for p in asked) == ["A_PW", "B_PW", "SHARED_U"]   # SHARED_U once
    assert secrets == {"SHARED_U": "typed-value", "A_PW": "typed-value"}
    assert errors == ["b: environment variable B_PW (password_env) is not set"]          # nothing typed: blocked
    assert "SHARED_U" not in os.environ and all("typed-value" not in e for e in errors)


def test_a_run_without_a_terminal_asks_nothing(tmp_path):
    path = _file(tmp_path, [{"role": "a", "method": "bearer", "auth": {"token_env": "TOK"}}])
    _, errors = _check_identities(path, GUARD, {})            # no ask_secret: the variable must be set
    assert errors == ["a: environment variable TOK (token_env) is not set"]


def test_interactive_sign_ins_pass_in_an_interactive_run(tmp_path):
    path = _file(tmp_path, [
        {"role": "a", "method": "oidc-authorization-code", "auth": {"issuer": "https://sso.example.com",
                                                                     "client_id": "cli"}},
        {"role": "b", "method": "oidc-device-code", "auth": {"device_url": "https://sso.example.com/device",
                                                              "token_url": "https://sso.example.com/token",
                                                              "client_id": "cli"}},
        {"role": "c", "method": "session", "auth": {"headers_env": {"Cookie": "C_COOKIE"}}},
    ])
    _, errors = _check_identities(path, GUARD, {"C_COOKIE": "sid=abcd"}, interactive=True)
    assert errors == []


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
