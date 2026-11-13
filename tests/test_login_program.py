"""The operator's login program (VER-040): started without a shell from the
identities file's directory, without model credentials, bounded in time and
output, and only the headers the identity allows are accepted. The programs
here are short Python one-liners; nothing leaves the machine."""

from __future__ import annotations

import sys
from datetime import datetime, timezone

import pytest

from appsec_verifier.auth import AuthError, SessionManager, program
from appsec_verifier.limits import Limits, RunBudget
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient

SCOPE = {"base_url": "https://app.example.com", "hosts": ["app.example.com"], "ports": [443],
         "schemes": ["https"], "path_prefixes": ["/"]}
NOW = 1_800_000_000.0


def _parse(text, allowed=("Authorization",)):
    return program.parse_output(text, list(allowed), clock=lambda: NOW)


# ── output ───────────────────────────────────────────────────────────────────

def test_one_line_is_a_bearer_token():
    assert _parse("tok-123\n") == ({"Authorization": "Bearer tok-123"}, None)


def test_json_gives_headers_cookies_and_expiry():
    text = '{"headers": {"authorization": "Token abc"}, "cookies": {"sid": "s-1", "csrf": "c-2"}, ' \
           '"expires_at": "2027-01-15T08:00:00Z"}'
    headers, expires = _parse(text, ["Authorization", "Cookie"])
    assert headers == {"Authorization": "Token abc", "Cookie": "sid=s-1; csrf=c-2"}
    assert expires == datetime(2027, 1, 15, 8, 0, tzinfo=timezone.utc).timestamp()
    assert _parse('{"headers": {"Authorization": "Bearer x"}, "expires_in": 60}')[1] == NOW + 60


@pytest.mark.parametrize("text, allowed, problem", [
    ('{"headers": {"X-Admin": "1"}}', ["Authorization"], "does not allow"),
    ('{"headers": {"Host": "evil"}}', ["Host"], "cannot be set by an identity"),
    ('{"headers": {"Authorization": "Bearer a\\r\\nX-Evil: 1"}}', ["Authorization"], "control character"),
    ('{"cookies": {"sid": "a;b"}}', ["Cookie"], "invalid name or value"),
    ('{"cookies": {"sid": "a"}}', ["Authorization"], "need Cookie"),
    ('{"headers": {"Authorization": "Bearer a"}, "debug": "x"}', ["Authorization"], "may hold only"),
    ('{"headers": {"Authorization": "Bearer a"}, "expires_at": "2027-01-15T08:00:00"}', ["Authorization"],
     "time zone"),
    ("{not json", ["Authorization"], "not valid JSON"),
    ("two words", ["Authorization"], "neither one token line"),
    ("tok", ["Cookie"], "does not allow Authorization"),
    ("", ["Authorization"], "wrote no session"),
    ("{}", ["Authorization"], "wrote no header"),
])
def test_output_the_identity_does_not_allow_is_refused(text, allowed, problem):
    with pytest.raises(AuthError, match=problem):
        _parse(text, allowed)


# ── running it ───────────────────────────────────────────────────────────────

def _auth(code, **extra):
    return {"command": [sys.executable, "-c", code], **extra}


def test_the_program_runs_in_the_files_directory_without_model_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-model")
    monkeypatch.setenv("GH_TOKEN", "gh-model")
    monkeypatch.setenv("VERIFIER_USER_PW", "for-the-program")
    code = ("import os, json; print(json.dumps({'headers': {'Authorization': 'Bearer ' + "
            "'|'.join([os.getcwd(), str('ANTHROPIC_API_KEY' in os.environ), str('GH_TOKEN' in os.environ), "
            "os.environ['VERIFIER_USER_PW']])}}))")
    headers, _ = program.obtain(_auth(code), base_dir=tmp_path, interactive=False)
    assert headers == {"Authorization": f"Bearer {tmp_path}|False|False|for-the-program"}


def test_a_failing_program_is_reported_by_its_status_only(tmp_path):
    code = "import sys; print('leaked-token'); print('oops leaked-pw', file=sys.stderr); sys.exit(3)"
    with pytest.raises(AuthError) as exc:
        program.obtain(_auth(code), base_dir=tmp_path, interactive=False)
    assert str(exc.value) == "the login program exited with status 3"


def test_a_program_that_takes_too_long_is_stopped(tmp_path):
    with pytest.raises(AuthError, match="did not finish within 0.5 s"):
        program.obtain(_auth("import time; time.sleep(30)", timeout=0.5), base_dir=tmp_path, interactive=False)


def test_a_program_that_writes_too_much_is_stopped(tmp_path):
    with pytest.raises(AuthError, match="more than 64 KiB"):
        program.obtain(_auth("print('x' * 100000)"), base_dir=tmp_path, interactive=False)


def test_without_a_terminal_the_program_reads_nothing(tmp_path):
    code = "import sys; data = sys.stdin.read(); print('empty' if data == '' else 'got-input')"
    headers, _ = program.obtain(_auth(code), base_dir=tmp_path, interactive=False)
    assert headers == {"Authorization": "Bearer empty"}


def test_a_program_that_cannot_start_is_reported(tmp_path):
    with pytest.raises(AuthError, match="could not be started"):
        program.obtain({"command": ["./missing-login.sh"]}, base_dir=tmp_path, interactive=False)


# ── as an identity ───────────────────────────────────────────────────────────

class Runs:
    """A fake runner: the outputs in order, the calls recorded."""

    def __init__(self, *outputs):
        self.outputs = list(outputs)
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        out = self.outputs.pop(0)
        return (1, "") if out is None else (0, out)


def _sessions(runs, *, headers=None, ui=None, clock=lambda: NOW):
    ident = {"role": "p", "method": "command", "auth": {"command": ["./login.sh", "p"],
                                                         **({"headers": headers} if headers else {})}}
    http = GuardedHttpClient(ScopeGuard(SCOPE), RunBudget(Limits(rate_rps=0)), lambda *a, **k: None)
    return SessionManager([ident], http, env={}, ui=ui, run_program=runs, clock=clock, base_dir="/srv/ids")


def test_the_program_runs_once_and_again_only_to_renew():
    runs = Runs('{"headers": {"Authorization": "Bearer PROG-1"}}', '{"headers": {"Authorization": "Bearer PROG-2"}}')
    sessions = _sessions(runs)
    assert sessions.headers_for("p") == {"Authorization": "Bearer PROG-1"}
    assert sessions.headers_for("p") == {"Authorization": "Bearer PROG-1"} and len(runs.calls) == 1
    assert runs.calls[0][0] == ["./login.sh", "p"] and runs.calls[0][1]["cwd"] == "/srv/ids"
    assert runs.calls[0][1]["interactive"] is False
    assert sessions.renew("p")                                  # after a 401
    assert sessions.headers_for("p") == {"Authorization": "Bearer PROG-2"} and len(runs.calls) == 2
    assert sessions.redact("PROG-1 PROG-2") == "[p session] [p session]"


def test_a_failed_program_is_not_run_again_in_the_run():
    runs = Runs(None)
    sessions = _sessions(runs)
    with pytest.raises(AuthError, match="exited with status 1"):
        sessions.headers_for("p")
    with pytest.raises(AuthError, match="not tried again"):
        sessions.headers_for("p")
    assert len(runs.calls) == 1


def test_a_program_session_with_an_expiry_is_renewed_before_it():
    now = [NOW]
    runs = Runs('{"headers": {"Authorization": "Bearer PROG-1"}, "expires_in": 120}',
                '{"headers": {"Authorization": "Bearer PROG-2"}, "expires_in": 120}')
    sessions = _sessions(runs, clock=lambda: now[0])
    sessions.headers_for("p")
    now[0] += 70                                                # within a minute of the expiry
    assert sessions.headers_for("p") == {"Authorization": "Bearer PROG-2"}


def test_describe_shows_the_program_as_written():
    assert program.describe({"command": ["./login sso.sh", "--role", "a"]}) == "'./login sso.sh' --role a"
