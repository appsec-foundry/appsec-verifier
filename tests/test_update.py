"""The `update` command (VER-033): no installation without a yes or Enter, and
nothing asked or installed outside a pipx installation, without a terminal, or
in CI. Offline: pipx and the version check of the new installation are fakes."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from appsec_verifier import cli, update

SOURCE = "https://example.test/appsec-verifier.git"
PIPX_OUTPUT = "appsec-verifier is already at latest version 0.1.0a1\n"
PIPX = ["/usr/bin/pipx", "upgrade", "--pip-args=--force-reinstall", "appsec-verifier"]
BEFORE = "0.1.0a1 (1a2b3c4d, 2026-10-01)"
AFTER = "0.1.0a1 (9f8e7d6c, 2026-10-30)"


def _setup(monkeypatch, *, answer="y", returncode=0, source=SOURCE, after=AFTER):
    calls = []

    def run(argv, **kwargs):
        if argv[1:] == ["-I", "-m", "appsec_verifier", "--version"]:
            # The new installation reports its version in a process of its own.
            if after is None:
                return subprocess.CompletedProcess(argv, 1, stdout="")
            return subprocess.CompletedProcess(argv, 0, stdout=f"{after}\n")
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout=PIPX_OUTPUT)

    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(update, "version_string", lambda: BEFORE)
    monkeypatch.setattr(update, "_pipx_source", lambda: source)
    monkeypatch.setattr(update.shutil, "which", lambda name, **kw: "/usr/bin/pipx")
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("builtins.input", lambda *a: answer)
    return calls


@pytest.mark.parametrize("answer", ["y", "YES", ""])
def test_yes_or_enter_upgrades_the_pipx_installation_and_names_the_source(monkeypatch, capsys, answer):
    calls = _setup(monkeypatch, answer=answer)
    assert cli.main(["update"]) == 0
    assert calls == [PIPX]
    output = capsys.readouterr().out
    assert "[Y/n]" in output
    assert output.index(f"Installed version: {BEFORE}") < output.index("[Y/n]")
    assert f"Verifier was reinstalled from {SOURCE}." in output
    assert "already at latest version" not in output
    assert f"Installed version: {AFTER} (was {BEFORE})" in output


@pytest.mark.parametrize(
    "after, shown",
    [
        (BEFORE, f"Installed version: {BEFORE} (unchanged)"),
        (None, "The new version could not be read; check it with `appsec-verifier --version`."),
        (AFTER + "\x1b[31m", "Installed version: 0.1.0a1 (9f8e7d6c, 2026-10-30) [31m (was"),
    ],
)
def test_the_update_names_the_version_it_installed(monkeypatch, capsys, after, shown):
    _setup(monkeypatch, after=after)
    assert cli.main(["update"]) == 0
    output = capsys.readouterr().out
    assert shown in output and "\x1b" not in output


@pytest.mark.parametrize("answer", ["n", "no", "maybe"])
def test_anything_but_yes_or_enter_installs_nothing(monkeypatch, capsys, answer):
    calls = _setup(monkeypatch, answer=answer)
    assert cli.main(["update"]) == 0
    assert calls == []
    output = capsys.readouterr().out
    assert f"Installed version: {BEFORE}" in output
    assert "Nothing was installed" in output


def test_end_of_input_installs_nothing(monkeypatch):
    calls = _setup(monkeypatch)

    def closed(*args):
        raise EOFError

    monkeypatch.setattr("builtins.input", closed)
    assert cli.main(["update"]) == 0
    assert calls == []


def test_failed_upgrade_shows_the_pipx_output_and_exits_with_an_error(monkeypatch, capsys):
    _setup(monkeypatch, returncode=1)
    assert cli.main(["update"]) == cli.EXIT_BLOCKED
    captured = capsys.readouterr()
    assert "the update failed" in captured.err
    assert PIPX_OUTPUT in captured.err
    assert "reinstalled" not in captured.out


@pytest.mark.parametrize("failure", [OSError("no such file"), subprocess.TimeoutExpired("pipx", 600)])
def test_an_upgrade_that_cannot_run_or_times_out_exits_with_an_error(monkeypatch, capsys, failure):
    _setup(monkeypatch)

    def run(argv, **kwargs):
        raise failure

    monkeypatch.setattr(subprocess, "run", run)
    assert cli.main(["update"]) == cli.EXIT_BLOCKED
    assert "the update could not be completed" in capsys.readouterr().err


@pytest.mark.parametrize("case", ["ci", "no-terminal", "no-stdin", "not-pipx", "no-pipx-executable"])
def test_nothing_is_asked_or_installed_when_it_must_not_be(monkeypatch, capsys, case):
    calls = _setup(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("must not ask"))
    if case == "ci":
        monkeypatch.setenv("CI", "true")
    elif case == "no-terminal":
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    elif case == "no-stdin":
        monkeypatch.setattr(sys, "stdin", None)
    elif case == "not-pipx":
        monkeypatch.setattr(update, "_pipx_source", lambda: None)
    else:
        monkeypatch.setattr(update.shutil, "which", lambda name, **kw: None)
    assert cli.main(["update"]) == cli.EXIT_BLOCKED
    assert calls == []
    assert "appsec-verifier: error:" in capsys.readouterr().err


def test_update_takes_no_assume_yes_option(monkeypatch):
    calls = _setup(monkeypatch)
    with pytest.raises(SystemExit):
        cli.main(["update", "--yes"])
    assert calls == []


def _metadata(monkeypatch, tmp_path, main_package):
    (tmp_path / "pipx_metadata.json").write_text(json.dumps({"main_package": main_package}))
    monkeypatch.setattr(sys, "prefix", str(tmp_path))


@pytest.mark.parametrize(
    "recorded, shown",
    [
        ("git+https://user:not-a-token@github.com/org/appsec-verifier.git?token=abc#egg=x",
         "https://github.com/org/appsec-verifier.git"),
        ("/home/user/appsec-verifier", "/home/user/appsec-verifier"),
    ],
)
def test_the_recorded_source_is_shown_without_credentials(monkeypatch, tmp_path, recorded, shown):
    _metadata(monkeypatch, tmp_path, {"package": "appsec-verifier", "package_or_url": recorded})
    assert update._pipx_source() == shown


@pytest.mark.parametrize(
    "main_package",
    [
        {"package": "appsec-analyzer", "package_or_url": SOURCE},
        {"package": "appsec-verifier", "package_or_url": ""},
        {"package": "appsec-verifier", "package_or_url": 5},
        {"package": "appsec-verifier"},
        "not a dict",
    ],
)
def test_other_or_malformed_pipx_metadata_is_not_a_pipx_installation(monkeypatch, tmp_path, main_package):
    _metadata(monkeypatch, tmp_path, main_package)
    assert update._pipx_source() is None


def test_without_pipx_metadata_it_is_not_a_pipx_installation(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    assert update._pipx_source() is None


def test_update_is_a_command_not_a_guided_run_with_an_assessment_named_update(monkeypatch):
    called = []
    monkeypatch.setattr(update, "update_installation", lambda: called.append(True) or 0)
    monkeypatch.setattr("appsec_verifier.guided.run_guided", lambda *a, **k: pytest.fail("guided run"))
    assert cli.main(["update"]) == 0
    assert called == [True]
