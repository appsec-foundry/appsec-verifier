"""Console output in the look of AppSec Analyzer: colour only on a terminal or
with FORCE_COLOR, never with NO_COLOR, and escape sequences only from the
Verifier itself, never from the assessment or the model (VER-005). With
--console-log the run's console output is also saved, owner-only and without
the status line. Offline: a fake transport and planner."""

from __future__ import annotations

import io
import re
import stat
import sys
from types import SimpleNamespace

import pytest
import yaml

from appsec_verifier import cli, guided
from appsec_verifier.preflight import Check, render
from appsec_verifier.progress import _CLEAR, _FRAME_OPEN, console_log
from appsec_verifier.term_style import Style, color_enabled
from appsec_verifier.tools import httpx_transport

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


def test_results_name_what_an_untested_variant_needs_and_how_to_provide_it():
    """docs/cli.md (Results): a finding or variant the run could not test shows what it needs, keyed as the test
    plan keys it (the variant's digest), and under it how to provide it; a tested variant says why it is not
    confirmed, as the report does."""
    digest = "ab" * 32
    rows = [{"finding_ref": {"id": "T-2", "title": "idor", "variant": "variant-002", "variant_digest": digest},
             "class": "access-control", "verdict": "not-attempted",
             "rationale": "not tested: safe mode; every declared variant needs a state change"},
            {"finding_ref": {"id": "T-2", "title": "idor", "variant": "variant-001", "variant_digest": "cd" * 32},
             "class": "access-control", "verdict": "inconclusive", "rationale": "no proof"},
            {"finding_ref": {"id": "T-3", "title": "sqli"}, "class": "injection", "verdict": "not-attempted",
             "rationale": "not tested: safe mode"}]
    rows = [{**row, "eligibility": {"status": "dynamic"}} for row in rows]
    blocked = {"T-2-" + digest[:16]: ("intrusive", "safe mode"), "T-3": ("marker", "no marker_file")}
    lines = [" ".join(line.split()) for line in cli._results(Style(False), {"results": rows}, [], blocked)]
    at = lines.index("· T-2 access-control needs intrusive mode idor")
    assert lines[at + 1] == "run with --allow-intrusive"
    at = lines.index("· T-3 injection needs marker file sqli")
    assert lines[at + 1] == "a marker_file in a scope file"
    at = lines.index("? T-2 access-control inconclusive idor")
    assert lines[at + 1] == "Agent's assessment: no proof."


def test_results_list_no_needs_of_a_confirmed_finding_and_count_alike_variants():
    """Run 133: T-001 was confirmed, so its variants that would need --allow-intrusive are not listed; T-002's three
    untested variants with one need share a line that counts them. --print still lists each one."""
    def row(fid, digest, verdict, rationale=""):
        return {"finding_ref": {"id": fid, "title": fid.lower(), "variant_digest": digest}, "class": "xss",
                "verdict": verdict, "rationale": rationale, "eligibility": {"status": "dynamic"}}

    rows = [row("T-1", "a" * 64, "confirmed", "script ran"), row("T-1", "b" * 64, "not-attempted"),
            row("T-1", "c" * 64, "not-attempted", "not tested: another variant of this finding already confirmed it"),
            *(row("T-2", d * 64, "not-attempted") for d in "def")]
    blocked = {f"T-{n}-{d * 16}": ("intrusive", "safe mode") for n, d in (("1", "b"), ("2", "d"), ("2", "e"),
                                                                           ("2", "f"))}
    lines = [" ".join(line.split()) for line in cli._results(Style(False), {"results": rows}, [], blocked)]
    assert [line for line in lines if line.startswith(("✓", "·"))] == [
        "✓ T-1 xss confirmed t-1", "· T-2 xss needs intrusive mode t-2"]
    assert lines[lines.index("· T-2 xss needs intrusive mode t-2") + 1] == "run with --allow-intrusive · 3 variants"
    full = cli._results(Style(False), {"results": rows}, [], blocked, full=True)
    assert sum("needs intrusive mode" in line for line in full) == 4


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


# ── --console-log ─────────────────────────────────────────────────────────────

URL = "http://localhost:3000"


def _verify(tmp_path, monkeypatch, *extra):
    """A run against a fake target whose planner answers at once; returns the exit code and the output dir."""
    class Planner:
        def next_step(self, ctx, history):
            return {"verdict": {"verdict": "inconclusive", "rationale": "x"}}

    def target(method, url, headers, **kw):
        assert (method, url) == ("GET", URL), url
        return SimpleNamespace(status_code=200, headers={}, json=lambda: (_ for _ in ()).throw(ValueError()))

    info = {"profile": "anthropic-api", "model": "m", "runtime": "Anthropic API", "auth": "API key"}
    monkeypatch.setattr(cli, "_build_planner_factory", lambda args: (Planner, dict(info)))
    monkeypatch.setattr(httpx_transport, "transport_from_scope", lambda scope: target)
    threat = {"id": "T-1", "cwe": "CWE-639", "severity": "high", "title": "idor",
              "evidence": {"file": "a.ts", "line": 1}}
    (tmp_path / "a.yaml").write_text(yaml.safe_dump({"threats": [threat]}))
    out = tmp_path / "out"
    rc = cli.main(["verify", "--assessment", str(tmp_path / "a.yaml"), "--yes", "--test-all", "--output", str(out),
                   *extra])
    return rc, out


def test_the_console_log_is_written_only_with_console_log(tmp_path, monkeypatch, capsys):
    rc, out = _verify(tmp_path, monkeypatch, "--url", URL)
    assert rc == cli.EXIT_OK and (out / "verification.md").is_file() and not (out / "console.log").exists()
    assert "console.log" not in capsys.readouterr().out

    rc, out = _verify(tmp_path, monkeypatch, "--url", URL, "--console-log", "--overwrite")
    shown = capsys.readouterr()
    log = (out / "console.log").read_text(encoding="utf-8")
    assert rc == cli.EXIT_OK and stat.S_IMODE((out / "console.log").stat().st_mode) == 0o600
    # everything the run printed, from its settings before the output directory existed to the summary that names
    # the log, in the order printed
    for line in (shown.out + shown.err).splitlines():
        assert line in log
    assert log.index("Assessment :") < log.index("Preflight") < log.index("Done") < log.index(f"Console    : {out}/")


def test_the_console_log_is_plain_unless_color(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("FORCE_COLOR", "1")
    _verify(tmp_path, monkeypatch, "--url", URL, "--console-log")
    assert SGR.search(capsys.readouterr().out)          # the console keeps its colour
    log = (tmp_path / "out" / "console.log").read_text()
    assert "\x1b" not in log and "Done" in log

    _verify(tmp_path, monkeypatch, "--url", URL, "--console-log", "color", "--overwrite")
    assert SGR.search(capsys.readouterr().out) and SGR.search((tmp_path / "out" / "console.log").read_text())


def test_a_blocked_run_writes_no_console_log(tmp_path, monkeypatch):
    rc, out = _verify(tmp_path, monkeypatch, "--url", "localhost:3000", "--console-log")
    assert rc == cli.EXIT_BLOCKED and not out.exists()


def test_the_console_log_leaves_out_the_status_line_and_appends_on_resume(tmp_path, capsys):
    path = tmp_path / "console.log"
    with console_log() as log:
        print("before the output directory")
        sys.stderr.write(_FRAME_OPEN + "⠋ status \x1b[K\r\x1b[?25h\x1b[?2026l")
        sys.stderr.write(_CLEAR)
        log.start(path)
        print("entry")
    assert path.read_text() == "before the output directory\nentry\n"
    assert "status" in capsys.readouterr().err         # the console still shows the status line

    with console_log() as log:
        log.start(path, append=True)
        print("resumed")
    assert path.read_text() == "before the output directory\nentry\nresumed\n"

    with console_log():
        print("a run that ends before its output directory")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["console.log"]
