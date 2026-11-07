"""Guided run from the assessment alone (VER-031): defaults, options not asked
again, invalid answers asked again, no scope without the operator, no secret
asked, cancel contacts nothing, and without a terminal nothing is asked."""

from __future__ import annotations

import shlex
from datetime import datetime, timezone

import pytest
import yaml

from appsec_verifier import cli, guided
from appsec_verifier.preflight import Confirmation

BASE = "https://app.example.com"
SCOPE = {"schema_version": 1, "base_url": BASE, "owner": {"name": "tester"},
         "window": {"from": "2026-01-01T00:00:00Z", "until": "2099-12-31T23:59:59Z"}}
THREATS = [
    {"id": "T-1", "cwe": "CWE-79", "severity": "high", "title": "xss", "evidence": {"file": "a.ts", "line": 1}},
    {"id": "T-2", "cwe": "CWE-639", "severity": "critical", "title": "idor", "evidence": {"file": "b.ts", "line": 2}},
    {"id": "T-3", "cwe": "CWE-89", "severity": "medium", "title": "sqli", "evidence": {"file": "c.ts", "line": 3}},
    {"id": "T-4", "cwe": "CWE-330", "severity": "low", "title": "prng", "evidence": {"file": "d.ts", "line": 4}},
]
# classes, severity, scope, URL, identities, profile, change limits
DEFAULTS = ["", "", "", "", "", "", ""]
# classes, severity, and Enter at the scope question when no scope file exists
NEW_SCOPE = ["", "", ""]


class Script:
    """Answers the prompts in order; running out of answers is end of input."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        answer = self.answers.pop(0)
        if isinstance(answer, type) and issubclass(answer, BaseException):
            raise answer
        return answer


@pytest.fixture
def env(tmp_path, monkeypatch):
    """An assessment and scope in run/, an empty working directory, and a fake
    `verify` and model profile so nothing is contacted or started."""
    run, cwd = tmp_path / "run", tmp_path / "cwd"
    run.mkdir()
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    (run / "assessment.yaml").write_text(yaml.safe_dump({"threats": THREATS}))
    (run / "scope.yaml").write_text(yaml.safe_dump(SCOPE))
    calls = []
    monkeypatch.setattr(cli, "cmd_verify", lambda args, invocation=None: calls.append((args, invocation)) or 0)
    monkeypatch.setattr(cli, "_build_planner_factory",
                        lambda args, environ=None: (object, {"profile": args.profile, "model": "m",
                                                             "runtime": "fake", "auth": "none"}))

    class Env:
        pass

    e = Env()
    e.run, e.cwd, e.calls = run, cwd, calls
    e.assessment = run / "assessment.yaml"

    def go(*answers, extra=(), interactive=True, environ=None):
        args = cli.build_guided_parser().parse_args([str(e.assessment), *extra])
        script, lines = Script(*answers), []
        rc = guided.run_guided(args, interactive=interactive, ask=script, out=lines.append,
                               environ={} if environ is None else environ)
        return rc, args, script.prompts, "\n".join(lines)

    e.go = go
    return e


def test_defaults_lead_to_verify_with_high_and_above(env):
    rc, args, prompts, out = env.go(*DEFAULTS)
    assert rc == 0 and len(prompts) == 7
    assert "4 total · 3 dynamically verifiable · 1 static-only" in out
    assert "critical 1 · high 1 · medium 1" in out
    assert "→ 2 findings selected, 2 of them dynamically verifiable" in out
    assert (args.category, args.min_severity) == (None, "high")
    assert args.scope == str(env.run / "scope.yaml") and args.target == BASE
    assert args.identities is None and args.profile == "claude" and args.output == "./verification"
    assert not args.allow_intrusive and not args.append and not args.non_interactive and not args.yes
    _, invocation = env.calls[0]
    assert "--min-severity high" in invocation and invocation.endswith("--non-interactive --yes")


def test_the_overview_names_what_the_classes_present_need_before_the_run(env):
    _, _, _, out = env.go(*DEFAULTS)
    needs = next(line for line in out.splitlines() if line.lstrip().startswith("Needs"))
    assert needs.split(": ", 1)[1] == ("access-control: test identities in identities.yaml · "
                                       "xss: Google Chrome with appsec-verifier[browser]")


def test_the_overview_has_no_needs_line_when_no_class_present_needs_preparation(env):
    env.assessment.write_text(yaml.safe_dump({"threats": [THREATS[2]]}))     # injection only
    _, plans, _ = cli._load_assessment(env.assessment)
    assert "Needs" not in guided.overview(env.assessment, plans)


def test_no_question_asks_for_a_secret(env):
    _, _, prompts, _ = env.go(*DEFAULTS)
    assert not any(word in p.lower() for p in prompts for word in ("password", "token", "secret", "key"))


def test_text_from_the_assessment_cannot_control_the_terminal(env):
    env.assessment.write_text(yaml.safe_dump({"threats": [
        {**THREATS[0], "severity": "\x1b]0;owned\x07\x1b[2Jhigh‮"}]}))
    rc, _, _, out = env.go("", "all", "", "", "", "", "")
    assert rc == 0 and "\x1b" not in out and "\x07" not in out and "‮" not in out


def test_options_given_are_not_asked(env):
    rc, args, prompts, _ = env.go("", "", extra=[
        "--scope", str(env.run / "scope.yaml"), "--url", BASE + "/app", "--profile", "anthropic-api",
        "--min-severity", "medium", "--category", "xss,idor"])
    assert rc == 0
    assert [p.split(" ")[0] for p in prompts] == ["Identities", "Change"]
    assert (args.target, args.profile, args.min_severity, args.category) == (
        BASE + "/app", "anthropic-api", "medium", "xss,idor")


def test_invalid_answers_are_asked_again(env):
    rc, args, prompts, out = env.go(
        "bogus", "xss",                          # unknown class, then a valid one
        "x", "all",                              # unknown severity, then all
        str(env.run / "missing.yaml"), "",       # unreadable scope, then the proposed one
        "https://evil.example", "",              # out of scope, then the base URL
        "", "", "")
    assert rc == 0 and len(prompts) == 11
    assert "unknown class: bogus" in out and "cannot read the scope file" in out and "out of scope" in out
    assert (args.category, args.min_severity, args.target) == ("xss", None, BASE)


def test_an_empty_selection_is_asked_again(env):
    rc, args, _, out = env.go("ssrf", "", "", "", "", "", "", "", "")
    assert rc == 0 and "nothing in this selection can be verified dynamically" in out
    assert args.category is None


def test_without_a_scope_one_is_written_from_the_answers_and_used(env):
    (env.run / "scope.yaml").unlink()
    rc, args, prompts, out = env.go(*NEW_SCOPE, "http://localhost:3000", "2099-12-31", "Tess Tester", "T-42",
                                    "", "", "")
    path = env.run / "scope.yaml"
    assert rc == 0 and len(prompts) == 10 and path.is_file()
    assert prompts[2].startswith("Scope file, or Enter to write one next to the assessment")
    assert [p.split(" ")[0] for p in prompts[3:7]] == ["Target", "Authorisation", "Owner,", "Reference,"]
    assert not any(word in p.lower() for p in prompts for word in ("password", "token", "secret", "key"))
    scope = yaml.safe_load(path.read_text())
    assert set(scope) == {"schema_version", "base_url", "schemes", "window", "owner", "allow_state_change"}
    assert scope["base_url"] == "http://localhost:3000" and scope["schemes"] == ["http"]
    assert scope["window"]["until"] == "2099-12-31T23:59:59Z" and scope["allow_state_change"] is False
    assert scope["owner"] == {"name": "Tess Tester", "contact": None, "reference": "T-42"}
    assert (args.scope, args.target) == (str(path), "http://localhost:3000") and f"wrote {path}" in out
    assert not any(p.startswith("Target URL [") for p in prompts)       # the URL is not asked twice
    assert str(path) in shlex.split(env.calls[0][1])


def test_the_window_of_a_new_scope_ends_today_by_default(env):
    (env.run / "scope.yaml").unlink()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rc, _, prompts, _ = env.go(*NEW_SCOPE, BASE, "", "Tess", "", "", "", "")
    scope = yaml.safe_load((env.run / "scope.yaml").read_text())
    assert rc == 0 and prompts[4].endswith(f"[{today}T23:59:59Z]: ")
    assert scope["window"]["until"] == f"{today}T23:59:59Z" and scope["schemes"] == ["https"]
    assert scope["owner"]["reference"] is None


def test_invalid_answers_for_a_new_scope_are_asked_again(env):
    (env.run / "scope.yaml").unlink()
    rc, _, _, out = env.go(
        *NEW_SCOPE,
        "",                                       # no target
        "localhost:3000",                         # no scheme
        "ftp://files.example.com",                # not http(s)
        "http://admin:pw@localhost:3000",         # credentials in the URL
        "http://localhost:3000/a/../b",           # ambiguous path
        "http://localhost:3000",
        "2020-01-01", "tomorrow", "2099-01-01T12:00:00+02:00",   # past, unparseable, then valid
        "", "Tess",                               # no owner, then one
        "", "", "", "")
    scope_text = (env.run / "scope.yaml").read_text()
    assert rc == 0 and "admin:pw" not in scope_text
    assert "a target URL is required" in out and out.count("absolute http or https URL") == 2
    assert "leave credentials out of the URL" in out and "is ambiguous" in out
    assert out.count("enter a future date or time") == 2 and "the owner is required" in out
    assert yaml.safe_load(scope_text)["window"]["until"] == "2099-01-01T10:00:00Z"


def test_a_new_scope_never_replaces_a_file_or_follows_a_link(env, tmp_path, capsys):
    elsewhere = tmp_path / "elsewhere.yaml"
    (env.run / "scope.yaml").unlink()
    (env.run / "scope.yaml").symlink_to(elsewhere)        # dangling: not proposed, and not written through
    rc, _, _, _ = env.go(*NEW_SCOPE, BASE, "", "Tess", "")
    assert rc == cli.EXIT_BLOCKED and env.calls == [] and not elsewhere.exists()
    assert "already exists and was left unchanged" in capsys.readouterr().err


@pytest.mark.parametrize("at", range(4))
def test_cancelling_a_new_scope_writes_and_contacts_nothing(env, capsys, at):
    (env.run / "scope.yaml").unlink()
    rc, _, _, _ = env.go(*NEW_SCOPE, *[BASE, "", "Tess", ""][:at], KeyboardInterrupt)
    assert rc == cli.EXIT_BLOCKED and env.calls == [] and not (env.run / "scope.yaml").exists()
    assert "cancelled; nothing was contacted" in capsys.readouterr().err


def test_an_invalid_scope_file_is_refused_and_asked_again(env):
    (env.run / "scope.yaml").write_text(yaml.safe_dump({"schema_version": 1, "base_url": None}))
    rc, _, prompts, out = env.go("", "", "")      # accepts the proposed file, then input ends
    assert rc == cli.EXIT_BLOCKED and env.calls == [] and "base_url" in out
    assert prompts[2].startswith("Scope file [") and prompts[3].startswith("Scope file [")


def test_missing_credentials_are_named_and_asked_again(env):
    (env.run / "identities.yaml").write_text(yaml.safe_dump(
        {"identities": [{"role": "alice", "method": "bearer", "auth": {"token_env": "ALICE_TOKEN"}}]}))
    rc, args, _, out = env.go("", "", "", "", "", "none", "", "")
    assert rc == 0 and "ALICE_TOKEN" in out and args.identities is None
    assert "1 access-control finding(s) selected; without a test identity they cannot be confirmed" in out


def test_identities_are_used_and_values_never_shown(env):
    (env.run / "identities.yaml").write_text(yaml.safe_dump(
        {"identities": [{"role": "alice", "method": "bearer", "auth": {"token_env": "ALICE_TOKEN"}}]}))
    rc, args, prompts, out = env.go(*DEFAULTS, environ={"ALICE_TOKEN": "s3cr3t-value"})
    assert rc == 0 and args.identities == str(env.run / "identities.yaml") and "roles: alice" in out
    assert "cannot be confirmed" not in out
    assert "s3cr3t-value" not in out + "".join(prompts) + env.calls[0][1]


def test_intrusive_mode_needs_its_own_yes(env):
    (env.run / "scope.yaml").write_text(yaml.safe_dump({**SCOPE, "allow_state_change": True}))
    _, args, prompts, _ = env.go(*DEFAULTS, "")
    assert prompts[-1].startswith("Allow intrusive probes? [y/N]") and not args.allow_intrusive
    _, args, _, _ = env.go(*DEFAULTS, "y")
    assert args.allow_intrusive and "--allow-intrusive" in env.calls[-1][1]


def test_intrusive_mode_is_not_offered_without_state_change(env):
    _, _, prompts, _ = env.go(*DEFAULTS)
    assert not any(p.startswith("Allow intrusive") for p in prompts)


@pytest.mark.parametrize("answers, append, output", [
    (["a"], True, "./verification"),
    ([""], True, "./verification"),
    (["o"], False, "./verification"),
    (["n", ""], False, "verification-2"),
])
def test_an_existing_report_is_not_replaced_without_asking(env, answers, append, output):
    (env.cwd / "verification").mkdir()
    (env.cwd / "verification" / "verification.yaml").write_text("{}")
    rc, args, prompts, _ = env.go(*DEFAULTS, *answers)
    assert rc == 0 and prompts[7].startswith("A report already exists")
    assert (args.append, args.output) == (append, output)


def test_limits_can_be_changed_and_are_checked(env):
    rc, args, _, out = env.go(*DEFAULTS[:-1], "y", "abc", "-1", "5", "", "", "", "", "")
    assert rc == 0 and "greater than 0" in out
    assert args.cost_limit == 5.0
    assert (args.max_calls, args.max_requests, args.max_attempts, args.max_duration, args.rate) == (None,) * 5
    assert "--cost-limit 5.0" in env.calls[0][1]


def test_an_invalid_limit_option_blocks_before_any_question(env, capsys):
    rc, _, prompts, _ = env.go(extra=["--cost-limit", "-1"])
    assert rc == cli.EXIT_BLOCKED and prompts == [] and env.calls == []
    assert "invalid limits" in capsys.readouterr().err


def test_an_unavailable_profile_option_blocks_before_any_question(env, monkeypatch, capsys):
    def factory(args, environ=None):
        raise cli.ProfileError("anthropic-api: needs the 'anthropic' package")

    monkeypatch.setattr(cli, "_build_planner_factory", factory)
    rc, _, prompts, _ = env.go(extra=["--profile", "anthropic-api"])
    assert rc == cli.EXIT_BLOCKED and prompts == [] and env.calls == []
    assert "model profile unavailable" in capsys.readouterr().err


def test_no_cost_question_for_a_subscription_profile(env):
    _, _, prompts, out = env.go(*DEFAULTS[:5], "y", "", "", "", "", "", extra=["--profile", "codex-cli"])
    assert "cost not reported" in out and not any(p.startswith("Cost") for p in prompts)


def test_an_unavailable_profile_is_asked_again(env, monkeypatch):
    def factory(args, environ=None):
        if args.profile == "claude":
            raise cli.ProfileError("claude: CLI not found")
        return object, {}

    monkeypatch.setattr(cli, "_build_planner_factory", factory)
    rc, args, _, out = env.go("", "", "", "", "", "", "bogus", "anthropic-api", "")
    assert rc == 0 and "CLI not found" in out and "choose one of" in out and args.profile == "anthropic-api"


@pytest.mark.parametrize("stop", [EOFError, KeyboardInterrupt])
@pytest.mark.parametrize("at", range(len(DEFAULTS)))
def test_cancelling_contacts_nothing(env, capsys, stop, at):
    rc, _, _, _ = env.go(*DEFAULTS[:at], stop)
    assert rc == cli.EXIT_BLOCKED and env.calls == []
    assert "cancelled; nothing was contacted" in capsys.readouterr().err


def test_the_invocation_runs_the_same_settings(env):
    (env.run / "scope.yaml").write_text(yaml.safe_dump({**SCOPE, "allow_state_change": True}))
    env.go("xss,idor", "medium", "", BASE + "/app", "", "anthropic-api", "y", "7.5", "", "", "", "", "", "y")
    args, invocation = env.calls[0]
    parts = shlex.split(invocation)
    again = cli.build_parser().parse_args(parts[1:])
    for attr in ("assessment", "scope", "target", "identities", "output", "category", "min_severity", "profile",
                 "cost_limit", "max_calls", "allow_intrusive", "append"):
        assert getattr(again, attr) == getattr(args, attr), attr
    assert again.non_interactive and again.yes and again.command == "verify"


def test_unreadable_or_unverifiable_assessments_block(env, capsys):
    env.assessment.write_text(": not yaml : [")
    assert env.go()[0] == cli.EXIT_BLOCKED
    assert "cannot read it: ParserError" in capsys.readouterr().err
    env.assessment.write_text(yaml.safe_dump({"threats": [THREATS[3]]}))
    rc, _, prompts, _ = env.go()
    assert rc == cli.EXIT_BLOCKED and prompts == []
    assert "can be verified dynamically" in capsys.readouterr().err


def test_non_interactive_names_what_is_missing(env, capsys):
    (env.run / "scope.yaml").unlink()
    rc, _, prompts, _ = env.go(interactive=False)
    assert rc == cli.EXIT_BLOCKED and prompts == [] and env.calls == []
    assert not (env.run / "scope.yaml").exists() and not (env.cwd / "scope.yaml").exists()
    assert "needs --scope and --profile" in capsys.readouterr().err


def test_non_interactive_runs_verify_with_the_options(env):
    rc, args, prompts, _ = env.go(interactive=False, extra=["--scope", str(env.run / "scope.yaml"),
                                                            "--profile", "anthropic-api"])
    assert rc == 0 and prompts == []
    assert args.non_interactive and args.output == "./verification" and args.min_severity is None
    assert env.calls[0][1] is None


@pytest.mark.parametrize("terminal, extra", [(False, []), (True, ["--non-interactive"]), (True, ["--ci"])])
def test_main_asks_nothing_without_a_terminal_or_with_the_flag(env, monkeypatch, capsys, terminal, extra):
    def no_input(*a):
        raise AssertionError("asked for input")

    monkeypatch.setattr("builtins.input", no_input)
    monkeypatch.setattr(cli, "_stdin_is_terminal", lambda: terminal)
    assert cli.main([str(env.assessment), *extra]) == cli.EXIT_BLOCKED
    assert "--scope" in capsys.readouterr().err


def test_main_keeps_the_commands(env, capsys):
    assert cli.main(["scope", "--scope", str(env.run / "scope.yaml")]) == 0
    assert "· scope ·" in capsys.readouterr().out


def test_the_confirmation_is_still_asked_after_the_questions(env, monkeypatch, capsys):
    """Answering the setup questions is not the confirmation of VER-002."""
    from appsec_verifier.tools import httpx_transport

    monkeypatch.undo()
    monkeypatch.chdir(env.cwd)

    class Planner:
        def next_step(self, ctx, history):
            raise AssertionError("a planner ran without confirmation")

    def no_network(*a, **k):
        raise AssertionError("the test reached the transport")

    asked = []

    def confirm(**kw):
        asked.append(kw)
        return Confirmation(False, "interactive", "declined at the prompt")

    info = {"profile": "anthropic-api", "model": "m", "runtime": "fake", "auth": "none"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args, environ=None: (Planner, info))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: no_network)
    monkeypatch.setattr(cli, "confirm_authorization", confirm)
    rc, _, _, _ = env.go("access-control", *DEFAULTS[1:])
    out = capsys.readouterr()
    assert rc == cli.EXIT_BLOCKED and asked == [{"non_interactive": False, "assume_yes": False}]
    assert "The same run without questions" in out.out and "not authorised to proceed" in out.err
    assert not (env.cwd / "verification").exists()
