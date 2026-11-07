"""Version, build stamp, and the boundary that locates runtime resources (schemas, data).

Mirrors AppSec Analyzer: resources live at the repo root in a source checkout,
and are copied into this package inside the built wheel (see setup.py), so a
`pipx install` carries them. `resource_root()` finds them in either place.

The build also writes `build-info.json` (commit, date, local changes) into the
package, so `--version` and `update` (VER-033) name the installed build; a
checkout without a stamp is read from Git.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

INTERFACE_VERSION = 1
ENGINE_VERSION = "0.1.0a1"

_RUNTIME_DIRS = ("schemas", "data")

# This module imports nothing from appsec_verifier, because setup.py executes it from its file.
PACKAGE = Path(__file__).resolve().parent
BUILD_INFO = "build-info.json"
GIT_TIMEOUT = 10
VERSION_TIMEOUT = 30
_COMMIT = re.compile(r"[0-9a-f]{40}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def resource_root() -> Path:
    """Directory holding `schemas/` and `data/` — the wheel's private copy if
    present, else the source tree root."""
    package = Path(__file__).resolve().parent
    if all((package / d).is_dir() for d in _RUNTIME_DIRS):
        return package
    source = package.parent
    if all((source / d).is_dir() for d in _RUNTIME_DIRS):
        return source
    raise RuntimeError("AppSec Verifier runtime resources (schemas/, data/) are missing")


def _git(root: Path, *args: str) -> str | None:
    search_path = os.pathsep.join(p for p in os.get_exec_path() if Path(p).is_absolute())
    git = shutil.which("git", path=search_path)
    if not git:
        return None
    try:
        result = subprocess.run(
            [git, "-c", "core.fsmonitor=false", "-C", str(root), *args],
            capture_output=True, text=True, timeout=GIT_TIMEOUT, check=False,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def read_git(root: Path) -> dict:
    """Commit, commit date and local-change flag of the checkout at root; empty if unreadable."""
    commit = _git(root, "rev-parse", "HEAD")
    date = _git(root, "show", "-s", "--format=%cs", "HEAD")
    if not commit or not date:
        return {}
    return {
        "commit": commit,
        "date": date,
        "dirty": bool(_git(root, "status", "--porcelain", "--untracked-files=no")),
    }


def _clean(info: object) -> dict | None:
    """Keep only well-formed values, because the text is printed to the terminal."""
    if not isinstance(info, dict):
        return None
    commit, date = info.get("commit"), info.get("date")
    if not (isinstance(commit, str) and _COMMIT.fullmatch(commit) and isinstance(date, str) and _DATE.fullmatch(date)):
        return None
    return {"commit": commit, "date": date, "dirty": info.get("dirty") is True}


def build_info() -> dict | None:
    """The stamp of an installed package, else the checkout the package runs from."""
    try:
        stamped = json.loads((PACKAGE / BUILD_INFO).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        stamped = None
    info = _clean(stamped)
    if info is None and (PACKAGE.parent / ".git").exists():
        info = _clean(read_git(PACKAGE.parent))
    return info


def version_string() -> str:
    """ENGINE_VERSION with the commit and date of the build, or of the checkout it runs from."""
    info = build_info()
    if info is None:
        return f"{ENGINE_VERSION} (commit unknown)"
    changes = ", local changes" if info["dirty"] else ""
    return f"{ENGINE_VERSION} ({info['commit'][:8]}, {info['date']}{changes})"


def installed_version() -> str | None:
    """What `--version` of the installed package reports now; ``None`` when it cannot be read.

    After a reinstall this process still runs the replaced code, so the new
    installation is asked in a process of its own, from the same environment;
    `-I` keeps the working directory and PYTHONPATH out.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-m", "appsec_verifier", "--version"],
            capture_output=True, text=True, timeout=VERSION_TIMEOUT, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    # The text reaches the terminal.
    version = " ".join(re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", result.stdout).split())[:120]
    return version or None


def version_change(before: str, after: str | None) -> str | None:
    """The installed version after an update, marked as unchanged or with the one it replaced."""
    if after is None:
        return None
    return after + (" (unchanged)" if after == before else f" (was {before})")
