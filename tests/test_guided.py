"""Guided run from the assessment alone (VER-031): only what has no usable
default is asked, the severity floor (high) and the profile (claude) are
defaults that options change, the next lower severity is offered when nothing
of high or above can be verified, options are not asked again, invalid answers
are asked again, a found scope file is used as it is or blocks, without one only
the typed URL's host is tested and no file is written, no secret is asked,
cancel contacts nothing, Enter confirms in the guided run but not in a run
without questions, and without a terminal nothing is asked."""

from __future__ import annotations

import shlex

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
IDENTITY = {"identities": [{"role": "alice", "method": "bearer", "auth": {"token_env": "ALICE_TOKEN"}}]}
SECRET_WORDS = ("password", "token", "secret", "key")


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
    monkeypatch.setattr(cli, "cmd_verify", lambda args, invocation=None, default_yes=False:
                        calls.append((args, invocation, default_yes)) or 0)
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


def test_with_a_scope_file_nothing_is_asked_and_the_defaults_apply(env):
    rc, args, prompts, out = env.go(extra=["--cost-limit", "5"])
    assert rc == 0 and prompts == []
    assert "4 total · 3 dynamically verifiable · 1 static-only" in out
    assert "critical 1 · high 1 · medium 1" in out
    assert "→ 2 findings to verify, severity high and above (--min-severity to change)" in out
    assert (args.category, args.min_severity, args.profile) == (None, "high", "claude")
    assert args.scope == str(env.run / "scope.yaml") and f"scope   {env.run / 'scope.yaml'}" in out
    assert args.target is None                                  # verify takes the scope's base_url
    assert args.identities is None and args.output == "./verification"
    assert not args.allow_intrusive and not args.append and not args.non_interactive and not args.yes
    _, invocation, default_yes = env.calls[0]
    parts = shlex.split(invocation)
    assert "--min-severity high" in invocation and "--profile claude" in invocation and "--cost-limit 5.0" in invocation
    assert "--url" not in parts and invocation.endswith("--non-interactive --yes")
    assert default_yes                                          # Enter confirms, also with a scope file


def test_the_overview_names_what_the_classes_present_need_before_the_run(env):
    _, _, _, out = env.go()
    needs = next(line for line in out.splitlines() if line.lstrip().startswith("Needs"))
    assert needs.split(": ", 1)[1] == ("access-control: test identities in identities.yaml · "
                                       "xss: Google Chrome with appsec-verifier[browser]")


def test_the_overview_has_no_needs_line_when_no_class_present_needs_preparation(env):
    env.assessment.write_text(yaml.safe_dump({"threats": [THREATS[2]]}))     # injection only
    _, plans, _ = cli._load_assessment(env.assessment)
    assert "Needs" not in guided.overview(env.assessment, plans)


def test_no_question_asks_for_a_secret(env):
    (env.run / "scope.yaml").unlink()
    (env.run / "identities.yaml").write_text(yaml.safe_dump(IDENTITY))
    _, _, prompts, _ = env.go(BASE, "none")
    assert len(prompts) == 2 and not any(word in p.lower() for p in prompts for word in SECRET_WORDS)


def test_text_from_the_assessment_cannot_control_the_terminal(env):
    env.assessment.write_text(yaml.safe_dump({"threats": [
        {**THREATS[0], "severity": "\x1b]0;owned\x07\x1b[2Jhigh‮"}]}))
    rc, _, _, out = env.go(extra=["--only", "T-1"])
    assert rc == 0 and "\x1b" not in out and "\x07" not in out and "‮" not in out


def test_options_given_are_not_asked(env):
    rc, args, prompts, out = env.go(extra=[
        "--scope", str(env.run / "scope.yaml"), "--url", BASE + "/app", "--profile", "anthropic-api",
        "--min-severity", "medium", "--category", "xss,idor"])
    assert rc == 0 and prompts == []
    assert (args.target, args.profile, args.min_severity, args.category) == (
        BASE + "/app", "anthropic-api", "medium", "xss,idor")
    assert "→ 2 findings to verify, severity medium and above" in out


def test_a_selection_by_id_or_exact_severity_has_no_floor(env):
    _, args, _, out = env.go(extra=["--only", "T-3"])
    assert args.min_severity is None and "→ 1 finding to verify" in out and "and above" not in out
    _, args, _, _ = env.go(extra=["--severity", "medium"])
    assert args.min_severity is None


# ── nothing of high or above: the next lower severity is offered ─────────────

@pytest.mark.parametrize("threats, lower", [
    ([THREATS[2], THREATS[3]], "medium"),                       # sqli medium, prng low (static)
    ([{**THREATS[0], "severity": "low"}], "low"),               # no medium either
])
def test_without_high_findings_the_next_lower_severity_is_offered(env, threats, lower):
    env.assessment.write_text(yaml.safe_dump({"threats": threats}))
    rc, args, prompts, out = env.go("")
    assert rc == 0 and args.min_severity == lower
    assert prompts == [f"No finding of severity high or above can be verified dynamically. "
                       f"Verify the 1 of severity {lower}? [Y/n]: "]
    assert f"→ 1 finding to verify, severity {lower} and above" in out
    assert f"--min-severity {lower}" in env.calls[0][1]


def test_declining_the_lower_severity_contacts_nothing(env, capsys):
    env.assessment.write_text(yaml.safe_dump({"threats": [THREATS[2]]}))
    rc, _, _, _ = env.go("n")
    assert rc == cli.EXIT_BLOCKED and env.calls == []
    assert "nothing to verify; nothing was contacted" in capsys.readouterr().err


def test_without_a_known_severity_nothing_is_offered(env, capsys):
    env.assessment.write_text(yaml.safe_dump({"threats": [{**THREATS[0], "severity": "info"}]}))
    rc, _, prompts, _ = env.go()
    assert rc == cli.EXIT_BLOCKED and prompts == [] and env.calls == []
    assert "no finding of a known severity can be verified dynamically" in capsys.readouterr().err


def test_a_floor_given_as_option_is_not_lowered(env):
    env.assessment.write_text(yaml.safe_dump({"threats": [THREATS[2]]}))
    rc, args, prompts, out = env.go(extra=["--min-severity", "high"])
    assert rc == 0 and prompts == [] and args.min_severity == "high"
    assert "→ 0 findings to verify, severity high and above" in out


# ── without a scope file: the typed URL alone (VER-001, VER-004) ─────────────

def test_without_a_scope_file_the_typed_url_is_the_scope_and_nothing_is_written(env):
    (env.run / "scope.yaml").unlink()
    rc, args, prompts, out = env.go("http://localhost:3000")
    assert rc == 0 and prompts == ["Target URL you are authorised to test: "]
    assert "tests only the host and port of the URL you enter, read-only" in out
    assert (args.scope, args.target) == (None, "http://localhost:3000")
    assert not (env.run / "scope.yaml").exists() and not (env.cwd / "scope.yaml").exists()
    _, invocation, default_yes = env.calls[0]
    parts = shlex.split(invocation)
    assert "--scope" not in parts and parts[parts.index("--url") + 1] == "http://localhost:3000"
    assert default_yes


def test_an_invalid_target_url_is_asked_again(env):
    (env.run / "scope.yaml").unlink()
    rc, args, _, out = env.go(
        "",                                       # no target
        "localhost:3000",                         # no scheme
        "ftp://files.example.com",                # not http(s)
        "http://[::1",                            # not a URL
        "http://admin:pw@localhost:3000",         # credentials in the URL
        "http://localhost:3000/a/../b",           # ambiguous path
        "http://localhost:3000")
    assert rc == 0 and args.target == "http://localhost:3000"
    assert "a target URL is required" in out and out.count("absolute http or https URL") == 3
    assert "leave credentials out of the URL" in out and "is ambiguous" in out
    assert "admin:pw" not in env.calls[0][1]


def test_a_url_given_as_option_is_used_without_asking(env):
    (env.run / "scope.yaml").unlink()
    rc, args, prompts, _ = env.go(extra=["--url", BASE])
    assert rc == 0 and prompts == []
    assert (args.scope, args.target) == (None, BASE)


def test_an_invalid_url_option_blocks_and_contacts_nothing(env, capsys):
    (env.run / "scope.yaml").unlink()
    rc, _, _, _ = env.go(extra=["--url", "http://admin:pw@localhost:3000"])
    err = capsys.readouterr().err
    assert rc == cli.EXIT_BLOCKED and env.calls == []
    assert "leave credentials out of the URL" in err and "pw@" not in err


# ── a scope file given or found (VER-001) ────────────────────────────────────

@pytest.mark.parametrize("scope, reason", [
    ({**SCOPE, "window": {"from": "2026-01-01T00:00:00Z", "until": "2026-01-02T00:00:00Z"}},
     "the authorisation window is not open now"),
    ({"schema_version": 1, "base_url": None}, "base_url"),
])
def test_a_found_scope_file_that_cannot_be_used_blocks_and_is_not_replaced(env, capsys, scope, reason):
    (env.run / "scope.yaml").write_text(yaml.safe_dump(scope))
    before = (env.run / "scope.yaml").read_text()
    rc, _, prompts, _ = env.go()
    err = capsys.readouterr().err
    assert rc == cli.EXIT_BLOCKED and env.calls == [] and prompts == []
    assert reason in err and "move it away to enter a target URL instead" in err
    assert (env.run / "scope.yaml").read_text() == before


def test_a_scope_file_given_that_cannot_be_used_blocks(env, capsys):
    rc, _, _, _ = env.go(extra=["--scope", str(env.run / "missing.yaml")])
    err = capsys.readouterr().err
    assert rc == cli.EXIT_BLOCKED and env.calls == [] and "cannot read the scope file" in err
    assert "move it away" not in err


def test_a_scope_file_in_the_working_directory_is_found(env):
    (env.run / "scope.yaml").rename(env.cwd / "scope.yaml")
    rc, args, _, _ = env.go()
    assert rc == 0 and args.scope == str(env.cwd / "scope.yaml")


# ── identities (VER-010, VER-016, VER-028) ──────────────────────────────────

def test_identities_are_asked_only_when_a_file_is_found(env):
    _, _, prompts, _ = env.go()
    assert not any(p.startswith("Identities") for p in prompts)


def test_missing_credentials_are_named_and_asked_again(env):
    (env.run / "identities.yaml").write_text(yaml.safe_dump(IDENTITY))
    rc, args, prompts, out = env.go("", "none")
    assert rc == 0 and "ALICE_TOKEN" in out and args.identities is None
    assert prompts[0].startswith(f"Identities file (test roles; credentials come from environment variables), "
                                 f"or 'none' [{env.run / 'identities.yaml'}]")


def test_identities_are_used_and_values_never_shown(env):
    (env.run / "identities.yaml").write_text(yaml.safe_dump(IDENTITY))
    rc, args, prompts, out = env.go("", environ={"ALICE_TOKEN": "s3cr3t-value"})
    assert rc == 0 and args.identities == str(env.run / "identities.yaml") and "roles: alice" in out
    assert "s3cr3t-value" not in out + "".join(prompts) + env.calls[0][1]


# ── model, mode, output ──────────────────────────────────────────────────────

def test_intrusive_mode_needs_its_own_yes(env):
    (env.run / "scope.yaml").write_text(yaml.safe_dump({**SCOPE, "allow_state_change": True}))
    _, args, prompts, _ = env.go("")
    assert prompts[-1].startswith("Allow intrusive probes? [y/N]") and not args.allow_intrusive
    _, args, _, _ = env.go("y")
    assert args.allow_intrusive and "--allow-intrusive" in env.calls[-1][1]


def test_intrusive_mode_is_not_offered_without_state_change(env):
    _, _, prompts, _ = env.go()
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
    rc, args, prompts, _ = env.go(*answers)
    assert rc == 0 and prompts[0].startswith("A report already exists")
    assert (args.append, args.output) == (append, output)


def test_an_invalid_limit_option_blocks_before_any_question(env, capsys):
    rc, _, prompts, _ = env.go(extra=["--cost-limit", "-1"])
    assert rc == cli.EXIT_BLOCKED and prompts == [] and env.calls == []
    assert "invalid limits" in capsys.readouterr().err


@pytest.mark.parametrize("extra", [[], ["--profile", "anthropic-api"]])
def test_an_unavailable_profile_blocks_before_any_question_and_names_the_option(env, monkeypatch, capsys, extra):
    def factory(args, environ=None):
        raise cli.ProfileError(f"{args.profile}: not available")

    monkeypatch.setattr(cli, "_build_planner_factory", factory)
    (env.run / "scope.yaml").unlink()                           # the URL question would come next
    rc, _, prompts, _ = env.go(extra=extra)
    err = capsys.readouterr().err
    assert rc == cli.EXIT_BLOCKED and prompts == [] and env.calls == []
    assert f"model profile unavailable: {(extra or ['', 'claude'])[1]}: not available" in err
    assert "choose another with --profile (claude, codex-cli" in err


@pytest.mark.parametrize("stop", [EOFError, KeyboardInterrupt])
@pytest.mark.parametrize("question", ["lower severity", "target URL", "identities", "intrusive", "report"])
def test_cancelling_at_any_question_contacts_nothing(env, capsys, stop, question):
    if question == "lower severity":
        env.assessment.write_text(yaml.safe_dump({"threats": [THREATS[2]]}))
    elif question == "target URL":
        (env.run / "scope.yaml").unlink()
    elif question == "identities":
        (env.run / "identities.yaml").write_text(yaml.safe_dump(IDENTITY))
    elif question == "intrusive":
        (env.run / "scope.yaml").write_text(yaml.safe_dump({**SCOPE, "allow_state_change": True}))
    else:
        (env.cwd / "verification").mkdir()
        (env.cwd / "verification" / "verification.yaml").write_text("{}")
    rc, _, prompts, _ = env.go(stop)
    assert rc == cli.EXIT_BLOCKED and env.calls == [] and len(prompts) == 1
    assert not (env.run / "scope.yaml").exists() or question != "target URL"
    assert "cancelled; nothing was contacted" in capsys.readouterr().err


@pytest.mark.parametrize("with_scope", [True, False])
def test_the_invocation_runs_the_same_settings(env, with_scope):
    options = ["--category", "xss,idor", "--min-severity", "medium", "--profile", "anthropic-api"]
    if with_scope:
        (env.run / "scope.yaml").write_text(yaml.safe_dump({**SCOPE, "allow_state_change": True}))
        env.go("y", extra=[*options, "--cost-limit", "7.5"])
    else:
        (env.run / "scope.yaml").unlink()
        env.go("http://localhost:3000", extra=options)
    args, invocation, _ = env.calls[0]
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
    assert "needs --scope or --url and --profile" in capsys.readouterr().err


@pytest.mark.parametrize("target", [["--scope", "SCOPE"], ["--url", BASE]])
def test_non_interactive_runs_verify_with_the_options(env, target):
    target = [str(env.run / "scope.yaml") if t == "SCOPE" else t for t in target]
    rc, args, prompts, _ = env.go(interactive=False, extra=[*target, "--profile", "anthropic-api"])
    assert rc == 0 and prompts == []
    assert args.non_interactive and args.output == "./verification" and args.min_severity is None
    assert env.calls[0][1] is None and env.calls[0][2] is False


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


@pytest.mark.parametrize("typed", [False, True])
def test_the_confirmation_is_still_asked_after_the_questions(env, monkeypatch, capsys, typed):
    """Nothing asked before is the confirmation of VER-002; Enter confirms
    there, with a scope file as with a typed URL. The settings show the floor."""
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
    if typed:
        (env.run / "scope.yaml").unlink()
        rc, _, _, _ = env.go(BASE, extra=["--category", "access-control"])
    else:
        rc, _, _, _ = env.go(extra=["--category", "access-control"])
    out = capsys.readouterr()
    assert rc == cli.EXIT_BLOCKED and asked == [{"non_interactive": False, "assume_yes": False, "default_yes": True}]
    assert "1 dynamic · severity high and above · classes: access-control" in out.out
    assert "The same run without questions" in out.out and "not authorised to proceed" in out.err
    assert not (env.cwd / "verification").exists()
