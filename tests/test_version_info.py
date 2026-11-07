"""`--version` names the build: the commit and its date from the build stamp or
the checkout, else "commit unknown" (VER-033). Offline; needs only git."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from appsec_verifier import version_info
from appsec_verifier.version_info import ENGINE_VERSION

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "17f22aa9" + "0" * 32
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


def _stamp(tmp_path, monkeypatch, info):
    """An installed package: a stamp inside the package directory and no checkout beside it."""
    package = tmp_path / "site-packages" / "appsec_verifier"
    package.mkdir(parents=True)
    if info is not None:
        (package / "build-info.json").write_text(info if isinstance(info, str) else json.dumps(info))
    monkeypatch.setattr(version_info, "PACKAGE", package)


def _info(**changes):
    return {"commit": COMMIT, "date": "2026-10-26", "dirty": False, **changes}


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({}, f"{ENGINE_VERSION} (17f22aa9, 2026-10-26)"),
        ({"dirty": True}, f"{ENGINE_VERSION} (17f22aa9, 2026-10-26, local changes)"),
        ({"dirty": "yes"}, f"{ENGINE_VERSION} (17f22aa9, 2026-10-26)"),
    ],
)
def test_stamp_gives_commit_and_date(tmp_path, monkeypatch, changes, expected):
    _stamp(tmp_path, monkeypatch, _info(**changes))
    assert version_info.version_string() == expected


@pytest.mark.parametrize(
    "stamp",
    [None, "not json", "[]", _info(commit="zz"), _info(commit=COMMIT + "\x1b[31m"), _info(date="yesterday"),
     _info(date="2026-10-26\x1b[2J")],
)
def test_missing_or_malformed_stamp_is_reported_as_unknown(tmp_path, monkeypatch, stamp):
    _stamp(tmp_path, monkeypatch, stamp)
    assert version_info.version_string() == f"{ENGINE_VERSION} (commit unknown)"


def _repository(path):
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.test",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.test",
        "GIT_COMMITTER_DATE": "2026-03-04T12:00:00+00:00",
        "GIT_AUTHOR_DATE": "2026-03-04T12:00:00+00:00",
    }

    def git(*args):
        return subprocess.run(["git", "-c", "commit.gpgsign=false", "-C", str(path), *args],
                              check=True, capture_output=True, text=True, env=env)

    path.mkdir(exist_ok=True)
    git("init", "-q")
    if not (path / "file.txt").exists():
        (path / "file.txt").write_text("one")
    git("add", "-A")
    git("commit", "-qm", "one")
    return git


def test_read_git_reports_commit_date_and_local_changes(tmp_path):
    git = _repository(tmp_path / "repo")
    clean = version_info.read_git(tmp_path / "repo")
    assert clean == {"commit": git("rev-parse", "HEAD").stdout.strip(), "date": "2026-03-04", "dirty": False}
    (tmp_path / "repo" / "file.txt").write_text("two")
    assert version_info.read_git(tmp_path / "repo")["dirty"] is True


def test_read_git_is_empty_outside_a_repository(tmp_path):
    assert version_info.read_git(tmp_path) == {}


def test_a_checkout_without_stamp_is_read_from_git(tmp_path, monkeypatch):
    _repository(tmp_path / "repo")
    package = tmp_path / "repo" / "appsec_verifier"
    package.mkdir()
    monkeypatch.setattr(version_info, "PACKAGE", package)
    assert version_info.version_string().endswith(", 2026-03-04)")


def test_an_installed_package_does_not_read_an_enclosing_repository(tmp_path, monkeypatch):
    _repository(tmp_path)
    _stamp(tmp_path, monkeypatch, None)
    assert version_info.version_string() == f"{ENGINE_VERSION} (commit unknown)"


def test_installed_version_ignores_checkout_and_pythonpath_packages(tmp_path):
    import venv

    environment = tmp_path / "environment"
    venv.EnvBuilder(with_pip=False).create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    probe = subprocess.run(
        [str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        capture_output=True, text=True, check=True, timeout=15,
    )
    package = Path(probe.stdout.strip()) / "appsec_verifier"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "__main__.py").write_text("print('installed-build')\n")
    shutil.copy2(ROOT / "appsec_verifier/version_info.py", package / "version_info.py")
    marker = tmp_path / "untrusted-code-ran"
    shadows = [tmp_path / "checkout", tmp_path / "pythonpath"]
    for shadow in shadows:
        fake = shadow / "appsec_verifier"
        fake.mkdir(parents=True)
        (fake / "__init__.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
        (fake / "__main__.py").write_text("print('shadow-build')\n")
    result = subprocess.run(
        [str(python), "-I", "-c", "from appsec_verifier.version_info import installed_version; "
                                  "print(installed_version())"],
        cwd=shadows[0], env={**os.environ, "PYTHONPATH": str(shadows[1])},
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "installed-build"
    assert not marker.exists()


def test_built_package_reports_its_commit_and_drops_a_stamp_it_cannot_renew(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("setup.py", "README.md"):
        shutil.copy2(ROOT / name, source / name)
    for name in ("appsec_verifier", "schemas", "data"):
        shutil.copytree(ROOT / name, source / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    lib = tmp_path / "lib"

    def build_and_ask():
        built = subprocess.run(
            [sys.executable, "setup.py", "-q", "build_py", "--build-lib", str(lib)],
            cwd=source, capture_output=True, text=True, timeout=120,
        )
        assert built.returncode == 0, built.stderr
        asked = subprocess.run(
            [sys.executable, "-m", "appsec_verifier", "--version"],
            cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(lib)}, capture_output=True, text=True, timeout=60,
        )
        assert asked.returncode == 0, asked.stderr
        return asked.stdout.strip()

    git = _repository(source)
    commit = git("rev-parse", "HEAD").stdout.strip()
    assert build_and_ask() == f"{ENGINE_VERSION} ({commit[:8]}, 2026-03-04)"
    shutil.rmtree(source / ".git")
    assert build_and_ask() == f"{ENGINE_VERSION} (commit unknown)"
    assert not (lib / "appsec_verifier" / "build-info.json").exists()
