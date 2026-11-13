"""Where a run writes without --output (VER-058): the platform's user data directory, a directory per project
named from the assessment, a new private directory per run, removed again when nothing was written to it, and
the newest fitting run for --resume. Offline."""

from __future__ import annotations

import stat
from datetime import datetime
from pathlib import Path

import pytest

from appsec_verifier.run_dirs import data_base, latest_run, new_run, project_name, remove_if_empty

HOME = Path("/home/me")
START = datetime(2026, 11, 13, 14, 30, 5)


@pytest.mark.parametrize("platform, env, expected", [
    ("linux", {}, HOME / ".local/share"),
    ("linux", {"XDG_DATA_HOME": "/data"}, Path("/data")),
    ("linux", {"XDG_DATA_HOME": "relative/data"}, HOME / ".local/share"),       # the XDG rule ignores it
    ("darwin", {"XDG_DATA_HOME": "/data"}, HOME / "Library/Application Support"),
    ("win32", {"LOCALAPPDATA": "/local"}, Path("/local")),
    ("win32", {}, HOME / "AppData/Local"),
])
def test_the_runs_lie_in_the_platforms_user_data_directory(platform, env, expected):
    assert data_base(env, platform, HOME) == expected / "appsec-verifier" / "runs"


@pytest.mark.parametrize("doc, expected", [
    ({"meta": {"project": "OWASP Juice Shop"}}, "owasp-juice-shop"),
    ({"meta": {"project": "../../etc/passwd"}}, "etc-passwd"),
    ({"meta": {"project": ".."}}, "assessment"),
    ({"meta": {"project": "Ärger"}}, "rger"),
    ({"meta": {"project": 42}}, "42"),
    ({"meta": {"project": "x" * 60}}, "x" * 40),
    ({"meta": {"project": None}}, "assessment"),
    ({"meta": "DVWA"}, "assessment"),
    ({"threats": []}, "assessment"),
])
def test_the_project_names_a_directory_that_stays_inside_the_runs(doc, expected):
    assert project_name(doc) == expected


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_a_new_run_gets_a_private_directory_named_by_its_start_time(tmp_path):
    tmp_path.chmod(0o755)
    project = tmp_path / "share" / "appsec-verifier" / "runs" / "dvwa"
    first = new_run(project, START)
    assert first == project / "2026-11-13T14-30-05" and first.is_dir()
    assert [_mode(p) for p in (tmp_path / "share", project.parent.parent, project.parent, project, first)] == \
        [0o700] * 5
    assert _mode(tmp_path) == 0o755                                       # what existed stays as it was


def test_a_run_never_shares_a_directory_with_another(tmp_path):
    runs = [new_run(tmp_path, START) for _ in range(3)]
    assert [r.name for r in runs] == ["2026-11-13T14-30-05", "2026-11-13T14-30-05-2", "2026-11-13T14-30-05-3"]
    (tmp_path / "2026-11-13T14-30-06").write_text("not a directory")
    assert new_run(tmp_path, START.replace(second=6)).name == "2026-11-13T14-30-06-2"


def test_resume_takes_the_newest_run_whose_report_fits(tmp_path):
    for name, text in (("2026-11-12T09-00-00", "fits"), ("2026-11-13T09-00-00", "fits"),
                       ("2026-11-13T10-00-00", "other target")):
        (tmp_path / name).mkdir()
        (tmp_path / name / "verification.yaml").write_text(text)
    (tmp_path / "2026-11-14T09-00-00").mkdir()                            # no report: never a candidate
    seen = []

    def fits(path):
        seen.append(path.parent.name)
        return path.read_text() == "fits"

    assert latest_run(tmp_path, fits) == tmp_path / "2026-11-13T09-00-00"
    assert seen == ["2026-11-13T10-00-00", "2026-11-13T09-00-00"]
    assert latest_run(tmp_path, lambda path: False) is None
    assert latest_run(tmp_path / "missing", fits) is None


def test_only_an_empty_run_directory_is_removed(tmp_path):
    empty, used = new_run(tmp_path, START), new_run(tmp_path, START)
    (used / "verification.yaml").write_text("report")
    remove_if_empty(empty)
    remove_if_empty(used)
    remove_if_empty(tmp_path / "missing")
    assert not empty.exists() and (used / "verification.yaml").read_text() == "report"
