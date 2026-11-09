"""Console output in the look of AppSec Analyzer: colour only on a terminal or
with FORCE_COLOR, never with NO_COLOR, and escape sequences only from the
Verifier itself, never from the assessment or the model (VER-005)."""

from __future__ import annotations

import io
import re

import pytest
import yaml

from appsec_verifier import cli, guided
from appsec_verifier.preflight import Check, render
from appsec_verifier.term_style import Style, color_enabled

SGR = re.compile(r"\x1b\[[0-9;]*m")
HOSTILE = "\x1b]0;pwned\x07\x1b[2J"   # sets the window title, rings, clears the screen


class Tty(io.StringIO):
    def isatty(self):
        return True


@pytest.mark.parametrize(("env", "tty", "expected"), [
    ({}, True, True),
    ({}, False, False),
    ({"NO_COLOR": "1"}, True, False),
    ({"NO_COLOR": "1", "FORCE_COLOR": "1"}, True, False),
    ({"FORCE_COLOR": "1"}, False, True),
    ({"FORCE_COLOR": "0"}, False, False),
    ({"TERM": "dumb"}, True, False),
])
def test_colour_follows_no_color_force_color_and_the_terminal(env, tty, expected):
    assert color_enabled(Tty() if tty else io.StringIO(), env) is expected


def test_truecolor_only_when_the_terminal_says_so():
    assert Style.for_stream(Tty(), {"COLORTERM": "truecolor"})("x", "ok") == "\x1b[38;2;143;209;158mx\x1b[0m"
    assert Style.for_stream(Tty(), {})("x", "ok") == "\x1b[32mx\x1b[0m"


@pytest.fixture
def assessment(tmp_path):
    threats = [
        {"id": "T-1", "cwe": "CWE-79", "severity": f"high{HOSTILE}", "title": "xss",
         "evidence": {"file": "a.ts", "line": 1}},
        {"id": "T-2", "cwe": "CWE-89", "severity": "critical", "title": "sqli",
         "evidence": {"file": "b.ts", "line": 2}},
    ]
    path = tmp_path / "assessment.yaml"
    path.write_text(yaml.safe_dump({"threats": threats}))
    return path


def _overview(path) -> str:
    """The first screen of the guided run."""
    _, plans, errors = cli._load_assessment(path)
    assert errors == []
    return guided.overview(path, plans)


def test_without_a_terminal_the_output_is_plain_with_analyzer_style_facts(assessment):
    out = _overview(assessment)
    assert "\x1b" not in out and "\x07" not in out
    assert out.startswith("▶ AppSec Verifier · assessment · ")
    assert "  Findings   : 2 runtime candidates of 2 · critical 1 · " in out


def test_force_color_colours_the_overview_but_strips_escapes_from_the_assessment(assessment, monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    out = _overview(assessment)
    assert SGR.search(out) and "appsec-verifier" in out                      # the logo
    assert "\x1b[31mcritical 1\x1b[0m" in out                                 # severity colour
    plain = SGR.sub("", out)
    assert "\x1b" not in plain and "\x07" not in plain and "high]0;pwned[2j 1" in plain


def test_no_color_wins_over_force_color(assessment, monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b" not in _overview(assessment)


def test_results_strip_escapes_from_assessment_and_model_text(capsys):
    doc = {"results": [{"finding_ref": {"id": f"T-1{HOSTILE}", "title": f"xss{HOSTILE}"}, "class": "xss",
                        "verdict": "confirmed", "confidence": f"high{HOSTILE}", "rationale": f"ran{HOSTILE}"}]}
    for st in (Style(False), Style(True)):
        plain = SGR.sub("", "\n".join(cli._results(st, doc, [], {}, full=True)))
        assert "\x1b" not in plain and "\x07" not in plain
        assert "confirmed" in plain and "ran]0;pwned[2J" in plain


def test_facts_strip_escapes_and_colour_by_role():
    lines = cli._facts(Style(True), [("Target", f"http://a{HOSTILE} (will contact)"), ("Mode", "safe", "ok"),
                                     ("Verdicts", [("1 confirmed", "critical"), (f"0 blocked{HOSTILE}", "muted")])])
    plain = SGR.sub("", "\n".join(lines))
    assert "\x1b" not in plain and "\x07" not in plain
    assert "\x1b[95mhttp://a]0;pwned[2J\x1b[0m\x1b[90m (will contact)\x1b[0m" in lines[0]
    assert "\x1b[32msafe\x1b[0m" in lines[1] and "\x1b[31m1 confirmed\x1b[0m" in lines[2]
    assert [SGR.sub("", line) for line in lines][:2] == ["  Target     : http://a]0;pwned[2J (will contact)",
                                                          "  Mode       : safe"]


def test_how_tos_wrap_at_spaces_only_so_paths_and_ids_stay_whole():
    assert cli._wrap_whole("example: /home/u/appsec-verifier/examples/juice-shop/identities.yaml (docs)", 20) == [
        "example:", "/home/u/appsec-verifier/examples/juice-shop/identities.yaml", "(docs)"]
    assert cli._wrap_whole("T-101, T-102, T-103", 8) == ["T-101,", "T-102,", "T-103"]


def test_the_logo_appears_once_per_run_then_the_title_line():
    st = Style(True)
    first, second = cli._title(st, "assessment"), cli._title(st, "verify")
    assert len(first) == 3 and "appsec-verifier" in first[0] and "assessment" in SGR.sub("", first[2])
    assert [SGR.sub("", line) for line in second] == [f"▶ AppSec Verifier · verify · {cli.version_string()}"]
    assert cli._title(Style(False), "scope") == [f"▶ AppSec Verifier · scope · {cli.version_string()}"]


def test_preflight_marks_take_the_colour_of_their_status():
    checks = [Check("Target", "ok", "200"), Check("alice", "warn", "w"), Check("bob", "fail", f"401{HOSTILE}"),
              Check("Proxy", "info", "-")]
    coloured = render(checks, Style(True)).split("\n")
    assert [line[2:12] for line in coloured] == ["\x1b[32m✓\x1b[0m", "\x1b[33m⚠\x1b[0m", "\x1b[31m✗\x1b[0m",
                                                  "\x1b[90m·\x1b[0m"]
    assert "\x1b" not in SGR.sub("", "\n".join(coloured))
    assert render(checks) == ("  ✓ Target       200\n  ⚠ alice        w\n  ✗ bob          401]0;pwned[2J\n"
                              "  · Proxy        -")


# ── help and usage errors ─────────────────────────────────────────────────────

@pytest.mark.parametrize("argv, expected", [
    (["verify", "security-assessment.yaml"], [
        "usage: appsec-verifier verify --assessment FILE (--scope FILE | --url URL) [options]",
        "appsec-verifier verify: error: the following arguments are required: --assessment",
        "To be asked for the settings instead: appsec-verifier ASSESSMENT",
        "Options and examples: appsec-verifier verify --help"]),
    (["security-assessment.yaml", "--bogus"], [
        "usage: appsec-verifier ASSESSMENT [options]",
        "appsec-verifier: error: unrecognized arguments: --bogus",
        "Options and examples: appsec-verifier ASSESSMENT --help"]),
])
def test_a_usage_error_shows_the_short_usage_and_where_the_examples_are(argv, expected, capsys):
    with pytest.raises(SystemExit) as exit_:
        cli.main(argv)
    assert exit_.value.code == cli.EXIT_BLOCKED and capsys.readouterr().err.splitlines() == expected


@pytest.mark.parametrize("argv, error", [
    (["a.yaml", "--target", "http://x", "--show-cost"],
     "appsec-verifier: error: unrecognized arguments: --show-cost; did you mean --show-costs?"),
    (["verify", "--assessment", "a.yaml", "--url", "http://x", "--min-sev", "low"],
     "appsec-verifier: error: unrecognized arguments: --min-sev low; did you mean --min-severity?"),
    (["preflight", "--assessment", "a.yaml", "--url", "http://x", "--test-mod"],
     "appsec-verifier: error: unrecognized arguments: --test-mod; did you mean --test-model?"),
])
def test_an_abbreviated_option_is_an_error_that_names_the_option_meant(argv, error, capsys):
    """argparse would take `--show-cost` for `--show-costs`; an option counts only as written."""
    with pytest.raises(SystemExit) as exit_:
        cli.main(argv)
    assert exit_.value.code == cli.EXIT_BLOCKED and error in capsys.readouterr().err.splitlines()


def test_the_documented_aliases_still_work():
    args = cli.build_guided_parser().parse_args(["a.yaml", "--target", "http://x", "--ci"])
    assert (args.target, args.non_interactive) == ("http://x", True)
    args = cli.build_parser().parse_args(["verify", "--assessment", "a.yaml", "--target", "http://x", "--show-costs"])
    assert (args.target, args.show_costs) == ("http://x", True)


@pytest.mark.parametrize("argv", [["verify", "--help"], ["preflight", "--help"], ["scope", "--help"],
                                  ["export", "--help"], ["security-assessment.yaml", "--help"]])
def test_help_ends_with_examples_that_fit_a_terminal(argv, capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "80")
    with pytest.raises(SystemExit) as exit_:
        cli.main(argv)
    out = capsys.readouterr().out
    assert exit_.value.code == 0 and ("\nExamples:\n" in out or "\nExample:\n" in out)
    assert max(len(line) for line in out.splitlines()) <= 90


def test_verify_help_groups_its_options(capsys):
    with pytest.raises(SystemExit):
        cli.main(["verify", "--help"])
    out = capsys.readouterr().out
    assert [g for g in ("target and input:", "findings to test:", "model:", "limits:", "mode:", "output:")
            if f"\n{g}\n" in out] == ["target and input:", "findings to test:", "model:", "limits:", "mode:",
                                      "output:"]


def test_top_level_help_lists_the_commands_with_examples(capsys):
    assert cli.main(["--help"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "Commands:" in out and "\nExamples:\n" in out and "  plan " not in out
