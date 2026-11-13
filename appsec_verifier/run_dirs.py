"""Where a run writes without --output (VER-058): a new directory of its own,
`<data>/appsec-verifier/runs/<project>/<start time>/`, readable only by the operator.

`<data>` is the platform's per-user data directory, and the project the assessment's `meta.project` reduced to
lower-case letters, digits and dashes, as AppSec Analyzer places and names its assessments
(`data_base` and `_slug` in its `scripts/shared/assessment_location.py`). The run directory is created when the run
starts, so two runs never share one, and removed again when the run wrote nothing into it. `--resume` without
--output continues the newest run of the project whose report fits (VER-037)."""

from __future__ import annotations

import contextlib
import itertools
import os
import re
import sys
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path

APP_DIRECTORY = "appsec-verifier"
RUNS_DIRECTORY = "runs"
NAME_LIMIT = 40
REPORT = "verification.yaml"


def data_base(env: Mapping[str, str] | None = None, platform: str | None = None, home: Path | None = None) -> Path:
    """The per-user directory that holds the runs of every project."""
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = Path.home() if home is None else home
    if platform == "win32":
        local = env.get("LOCALAPPDATA", "")
        root = Path(local) if local and Path(local).is_absolute() else home / "AppData" / "Local"
    elif platform == "darwin":
        root = home / "Library" / "Application Support"
    else:
        xdg = env.get("XDG_DATA_HOME", "")
        # The XDG specification ignores a relative value.
        root = Path(xdg) if xdg and Path(xdg).is_absolute() else home / ".local" / "share"
    return root / APP_DIRECTORY / RUNS_DIRECTORY


def project_name(doc: dict) -> str:
    """The assessment's project as a directory name; `assessment` when it names none."""
    meta = doc.get("meta") if isinstance(doc, dict) else None
    project = meta.get("project") if isinstance(meta, dict) else None
    slug = re.sub(r"[^a-z0-9]+", "-", str(project or "").lower()).strip("-")[:NAME_LIMIT].strip("-")
    return slug or "assessment"


def new_run(project_dir: Path, now: datetime | None = None) -> Path:
    """Create the directory of a new run in project_dir, named by its local start time; a name another run took
    gets a number (`…T14-30-05-2`)."""
    _mkdir_private(project_dir)
    stamp = (now or datetime.now()).strftime("%Y-%m-%dT%H-%M-%S")
    for n in itertools.count(1):
        run = project_dir / (stamp if n == 1 else f"{stamp}-{n}")
        try:
            run.mkdir(mode=0o700)
            return run
        except FileExistsError:
            continue


def latest_run(project_dir: Path, fits: Callable[[Path], bool]) -> Path | None:
    """The newest run in project_dir whose report `fits`, or None."""
    try:
        runs = sorted((p for p in project_dir.iterdir() if (p / REPORT).is_file()), key=lambda p: p.name,
                      reverse=True)
    except FileNotFoundError:
        return None
    return next((run for run in runs if fits(run / REPORT)), None)


def remove_if_empty(run: Path) -> None:
    """Remove a run directory nothing was written to; one that holds anything stays."""
    with contextlib.suppress(OSError):
        run.rmdir()


def _mkdir_private(path: Path) -> None:
    """Create path and its missing parents readable only by the operator; existing ones stay as they are."""
    missing = []
    while not path.is_dir():
        missing.append(path)
        path = path.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
