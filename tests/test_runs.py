"""The `runs` command (VER-064): it lists the runs of the data directory (VER-058) by project, newest first, with
target, mode, verdicts, state and size, and removes runs only after a yes in an interactive terminal. It never
removes a run in progress, anything outside the data directory, a symbolic link or what it was not asked to.
Offline; the data directory is a temporary one (conftest)."""

from __future__ import annotations

import os
import sys
import time

import pytest
import yaml
from test_failure_handling import _verify

from appsec_verifier import cli
from appsec_verifier.run_dirs import LOCK, data_base, hold_run, in_progress, remove_if_empty

DAY = 24 * 60 * 60


def _run(project, name, *, report=None, age_days=0.0, size=10):
    """A run directory with a console.log of size bytes and, if given, a report with that meta; it last wrote
    age_days ago."""
    run = data_base() / project / name
    run.mkdir(parents=True)
    (run / "console.log").write_bytes(b"x" * size)
    if report is not None:
        (run / "verification.yaml").write_text(yaml.safe_dump({"meta": report, "results": []}))
    return _age(run, age_days)


def _age(run, days):
    """Let run have last written days ago."""
    then = time.time() - days * DAY
    for path in (*run.iterdir(), run):
        os.utime(path, (then, then))
    return run


FINISHED = {"target": {"base_url": "http://localhost:4280/"}, "safety": {"mode": "intrusive"}, "interrupted": False,
            "summary": {"confirmed": 4, "not_reproducible": 0, "blocked": 1, "inconclusive": 12,
                        "not_attempted": 50, "total": 67}}


def _terminal(monkeypatch, answer="y"):
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    asked = []
    monkeypatch.setattr("builtins.input", lambda *a: asked.append(1) or answer)
    return asked


# ── the lock of a run in progress ───────────────────────────────────────────────

def test_a_held_run_is_in_progress_until_the_block_ends_and_leaves_no_lock_behind(tmp_path):
    assert not in_progress(tmp_path)
    with hold_run(tmp_path):
        assert in_progress(tmp_path)
    assert not in_progress(tmp_path) and not (tmp_path / LOCK).exists()
    remove_if_empty(tmp_path)
    assert not tmp_path.exists()                        # an empty run stays removable


def test_a_second_hold_on_a_held_run_leaves_the_first_ones_lock_alone(tmp_path):
    with hold_run(tmp_path):
        with pytest.raises(BlockingIOError), hold_run(tmp_path):
            pytest.fail("a second writer entered the run")
        assert in_progress(tmp_path)
    assert not in_progress(tmp_path)


def test_a_lock_file_left_by_a_killed_run_does_not_mark_it_in_progress(tmp_path):
    (tmp_path / LOCK).write_bytes(b"")
    assert not in_progress(tmp_path)


def test_a_verify_run_holds_its_directory_while_it_runs(tmp_path, monkeypatch):
    seen = []

    class Planner:
        def next_step(self, ctx, history):
            seen.extend(in_progress(run) for run in data_base().glob("*/*"))
            return {"verdict": {"verdict": "not-attempted", "rationale": "checked"}}

    assert _verify(tmp_path, monkeypatch, Planner, output=False)[0] == cli.EXIT_OK
    (run,) = data_base().glob("*/*")
    assert seen and all(seen)
    assert not in_progress(run) and not (run / LOCK).exists() and (run / "verification.yaml").is_file()


# ── listing ─────────────────────────────────────────────────────────────────────

def test_the_list_shows_each_projects_runs_newest_first_with_what_they_did(capsys):
    _run("dvwa", "2026-11-13T14-30-05", report=FINISHED, size=2_500_000)
    _run("dvwa", "2026-11-14T09-00-00")                                         # no report: unfinished
    _run("dvwa", "2026-11-14T10-00-00", report={**FINISHED, "interrupted": True})
    (_run("dvwa", "2026-11-14T11-00-00") / "verification.yaml").write_text("a: [\n")
    _run("juice-shop", "2026-11-12T08-00-00-2", report={"safety": {"mode": "safe"}})
    assert cli.main(["runs"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert f"Runs in {data_base()}\n" in out
    lines = [" ".join(line.split()) for line in out.splitlines()]
    dvwa = lines.index("dvwa · 4 runs · 2.5 MB")
    rows = lines[dvwa + 1:dvwa + 5]
    verdicts = ("intrusive http://localhost:4280/ 4 confirmed · 1 blocked by control · 12 inconclusive · "
                "50 not attempted")
    assert [row.split()[0] for row in rows] == ["2026-11-14T11-00-00", "2026-11-14T10-00-00", "2026-11-14T09-00-00",
                                                "2026-11-13T14-30-05"]
    assert rows[0].endswith(" 15 B report unreadable") and rows[2].endswith(" 10 B unfinished")
    assert rows[1].endswith(f" B interrupted {verdicts}")
    assert rows[3] == f"2026-11-13T14-30-05 2.5 MB finished {verdicts}"
    juice = next(i for i, line in enumerate(lines) if line.startswith("juice-shop · 1 run · "))
    assert lines[juice + 1].split()[0] == "2026-11-12T08-00-00-2" and lines[juice + 1].split()[3:] == ["finished",
                                                                                                    "safe"]


def test_the_list_shows_a_run_in_progress_as_running(capsys):
    run = _run("dvwa", "2026-11-14T09-00-00")
    with hold_run(run):
        assert cli.main(["runs"]) == cli.EXIT_OK
    assert "2026-11-14T09-00-00 10 B running" in " ".join(capsys.readouterr().out.split())


def test_without_runs_the_list_names_the_data_directory(capsys):
    assert cli.main(["runs"]) == cli.EXIT_OK
    assert capsys.readouterr().out == f"No runs in {data_base()}.\n"


def test_only_run_directories_are_listed_never_symbolic_links_or_other_entries(tmp_path, capsys):
    outside = tmp_path / "outside"
    (outside / "2026-11-14T09-00-00").mkdir(parents=True)
    _run("dvwa", "2026-11-13T14-30-05")
    (data_base() / "dvwa" / "2026-11-14T09-00-00").symlink_to(outside / "2026-11-14T09-00-00")
    (data_base() / "linked").symlink_to(outside)
    (data_base() / "dvwa" / "notes").mkdir()
    (data_base() / "dvwa" / "2026-11-15T09-00-00").write_text("a file")
    assert cli.main(["runs"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "dvwa · 1 run" in out and "linked" not in out and "notes" not in out
    assert "2026-11-14T09-00-00" not in out and "2026-11-15T09-00-00" not in out


def test_text_from_a_report_reaches_the_terminal_without_control_characters(capsys):
    _run("dvwa", "2026-11-13T14-30-05", report={**FINISHED, "target": {"base_url": "http://t/\x1b[2J‮"}})
    assert cli.main(["runs"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "http://t/[2J " in out and "\x1b" not in out and "‮" not in out


# ── removal ─────────────────────────────────────────────────────────────────────

def test_named_runs_are_removed_after_a_yes_and_an_emptied_project_with_them(monkeypatch, capsys):
    old = _run("dvwa", "2026-11-13T14-30-05", size=1500)
    kept = _run("dvwa", "2026-11-14T09-00-00")
    other = _run("juice-shop", "2026-11-12T08-00-00")
    asked = _terminal(monkeypatch)
    assert cli.main(["runs", "--remove", "dvwa/2026-11-13T14-30-05", "juice-shop/2026-11-12T08-00-00"]) == 0
    out = capsys.readouterr().out
    assert asked and "Remove 2 runs (1.5 KB)? Their reports and evidence cannot be restored. [y/N]" in out  # 1510 B
    assert out.index("2026-11-13T14-30-05") < out.index("[y/N]") and "2026-11-14T09-00-00" not in out
    assert "Removed 2 runs, 1.5 KB." in out
    assert not old.exists() and not other.exists() and not other.parent.exists() and kept.is_dir()


@pytest.mark.parametrize("answer", ["", "n", "no", "ja"])
def test_without_a_yes_nothing_is_removed(monkeypatch, capsys, answer):
    run = _run("dvwa", "2026-11-13T14-30-05")
    _terminal(monkeypatch, answer)
    assert cli.main(["runs", "--remove", "dvwa/2026-11-13T14-30-05"]) == cli.EXIT_OK
    assert "Nothing was removed." in capsys.readouterr().out and run.is_dir()


def test_closed_input_removes_nothing(monkeypatch, capsys):
    run = _run("dvwa", "2026-11-13T14-30-05")
    _terminal(monkeypatch)

    def closed(*a):
        raise EOFError

    monkeypatch.setattr("builtins.input", closed)
    assert cli.main(["runs", "--remove", "dvwa/2026-11-13T14-30-05"]) == cli.EXIT_OK
    assert run.is_dir()


@pytest.mark.parametrize("terminal, ci", [(False, None), (True, "true")])
def test_without_an_interactive_terminal_or_in_ci_nothing_is_asked_or_removed(monkeypatch, capsys, terminal, ci):
    run = _run("dvwa", "2026-11-13T14-30-05")
    asked = _terminal(monkeypatch)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: terminal)
    if ci:
        monkeypatch.setenv("CI", ci)
    assert cli.main(["runs", "--remove", "dvwa/2026-11-13T14-30-05"]) == cli.EXIT_BLOCKED
    captured = capsys.readouterr()
    assert "2026-11-13T14-30-05" in captured.out                         # what it would remove
    assert "needs an interactive terminal. Nothing was removed." in captured.err
    assert not asked and run.is_dir()


@pytest.mark.parametrize("name", ["dvwa/../../outside", "../outside", "dvwa", "dvwa/2026-11-13T14-30-05/evidence",
                                  "{outside}", "dvwa/2026-11-13T14-30-06", "dvwa/2026-11-14T09-00-00"])
def test_only_listed_runs_can_be_named_and_an_unknown_name_removes_nothing(tmp_path, monkeypatch, capsys, name):
    outside = tmp_path / "outside" / "2026-11-13T14-30-05"
    outside.mkdir(parents=True)
    run = _run("dvwa", "2026-11-13T14-30-05")
    (run / "evidence").mkdir()
    (data_base() / "dvwa" / "2026-11-14T09-00-00").symlink_to(outside)
    asked = _terminal(monkeypatch)
    argv = ["runs", "--remove", "dvwa/2026-11-13T14-30-05", name.format(outside=outside)]
    assert cli.main(argv) == cli.EXIT_BLOCKED
    assert "Nothing was removed." in capsys.readouterr().err
    assert not asked and run.is_dir() and outside.is_dir()


def test_a_run_in_progress_stays_also_when_named(monkeypatch, capsys):
    running = _run("dvwa", "2026-11-13T14-30-05")
    asked = _terminal(monkeypatch)
    with hold_run(running):
        _age(running, 40)                                               # a run that hangs writes nothing
        assert cli.main(["runs", "--remove", "dvwa/2026-11-13T14-30-05"]) == cli.EXIT_OK
        assert cli.main(["runs", "--remove-older-than", "30"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert out.count("dvwa/2026-11-13T14-30-05 is in progress and stays.") == 2
    assert out.count("No run to remove.") == 2 and not asked and running.is_dir()


def test_a_run_that_started_again_after_the_list_stays(monkeypatch, capsys):
    run = _run("dvwa", "2026-11-13T14-30-05")
    held = hold_run(run)

    def start_then_answer(*a):
        held.__enter__()
        return "y"

    _terminal(monkeypatch)
    monkeypatch.setattr("builtins.input", start_then_answer)
    try:
        assert cli.main(["runs", "--remove", "dvwa/2026-11-13T14-30-05"]) == cli.EXIT_OK
    finally:
        held.__exit__(None, None, None)
    out = capsys.readouterr().out
    assert "is in progress and stays." in out and "Removed 0 runs, 0 B." in out and run.is_dir()


def test_runs_that_wrote_nothing_for_more_than_the_given_days_are_removed(monkeypatch, capsys):
    old = _run("dvwa", "2026-10-01T09-00-00", age_days=31)
    resumed = _run("dvwa", "2026-10-02T09-00-00", age_days=40)
    (resumed / "agent-log.jsonl").write_text("{}")                      # a later --resume wrote into it
    recent = _run("juice-shop", "2026-11-13T09-00-00", age_days=29)
    _terminal(monkeypatch)
    assert cli.main(["runs", "--remove-older-than", "30"]) == cli.EXIT_OK
    assert "Remove 1 run" in capsys.readouterr().out
    assert not old.exists() and resumed.is_dir() and recent.is_dir()


def test_no_run_older_than_the_given_days_asks_nothing(monkeypatch, capsys):
    _run("dvwa", "2026-11-13T09-00-00", age_days=1)
    asked = _terminal(monkeypatch)
    assert cli.main(["runs", "--remove-older-than", "7"]) == cli.EXIT_OK
    assert "No run to remove." in capsys.readouterr().out and not asked


def test_a_symbolic_link_inside_a_run_is_removed_without_touching_its_target(tmp_path, monkeypatch, capsys):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    run = _run("dvwa", "2026-11-13T14-30-05")
    (run / "evidence").symlink_to(outside)
    _terminal(monkeypatch)
    assert cli.main(["runs", "--remove", "dvwa/2026-11-13T14-30-05"]) == cli.EXIT_OK
    assert not run.exists() and (outside / "keep.txt").read_text() == "keep"


@pytest.mark.parametrize("days", ["-1", "two", "1.5"])
def test_the_age_is_a_whole_number_of_days(capsys, days):
    with pytest.raises(SystemExit) as stop:
        cli.main(["runs", "--remove-older-than", days])
    assert stop.value.code == 2 and "a whole number of days, 0 or more" in capsys.readouterr().err
