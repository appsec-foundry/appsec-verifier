"""The `runs` command (VER-064): list the runs written without --output (VER-058) and remove the ones the operator
names, or those that wrote nothing for a given number of days, after a yes in an interactive terminal. Only a
directory found in the data directory under a run's name can be removed, never a symbolic link or a run in
progress (`run_dirs.hold_run`). Contacts nothing."""

from __future__ import annotations

import os
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

from .preflight import printable
from .run_dirs import REPORT, RUN_NAME, data_base, hold_run, in_progress, remove_if_empty
from .term_style import Style

EXIT_OK = 0
EXIT_BLOCKED = 2
DAY = 24 * 60 * 60
# Data only, as yaml.safe_load; the C loader reads a report in milliseconds instead of most of a second.
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_VERDICTS = (("confirmed", "confirmed"), ("shown_without_exploit", "shown without exploit"),
             ("not_reproducible", "not reproducible"), ("blocked", "blocked by control"),
             ("inconclusive", "inconclusive"), ("not_attempted", "not attempted"))
_STATE_ROLES = {"running": "accent", "finished": "ok", "interrupted": "warn", "unfinished": "warn",
                "report unreadable": "critical"}


@dataclass
class Run:
    project: str
    path: Path
    size: int
    changed: float              # when the run last wrote, as a timestamp
    state: str                  # a key of _STATE_ROLES
    mode: str = ""
    target: str = ""
    verdicts: str = ""

    @property
    def key(self) -> str:
        """How the operator names the run: `<project>/<start time>`."""
        return f"{self.project}/{self.path.name}"


def find_runs(base: Path) -> list[Run]:
    """The runs below base, by project and newest first. Symbolic links and entries without a run's name are no
    runs."""
    runs = []
    for project in _entries(base):
        if project.is_symlink() or not project.is_dir():
            continue
        for run in reversed(_entries(project)):
            if RUN_NAME.fullmatch(run.name) and not run.is_symlink() and run.is_dir():
                runs.append(_read(project.name, run))
    return runs


def runs_command(remove: list[str] | None = None, older_than: int | None = None) -> int:
    """List the runs; with remove or older_than, remove those runs after the operator's yes."""
    base = data_base()
    runs = find_runs(base)
    st = Style.for_stream(sys.stdout)
    if remove is None and older_than is None:
        if not runs:
            print(f"No runs in {base}.")
            return EXIT_OK
        print(f"Runs in {base}\n")
        print("\n".join(_listing(runs, st)))
        print("\nTo remove runs: appsec-verifier runs --remove PROJECT/RUN … or --remove-older-than DAYS; "
              "both ask first.")
        return EXIT_OK
    known = {run.key for run in runs}
    unknown = [name for name in remove or () if name not in known]
    if unknown:
        print(f"appsec-verifier: error: no run {', '.join(printable(n) for n in unknown)} in {base}; "
              "`appsec-verifier runs` lists them. Nothing was removed.", file=sys.stderr)
        return EXIT_BLOCKED
    now = time.time()
    chosen = [run for run in runs
              if run.key in (remove or ()) or (older_than is not None and now - run.changed > older_than * DAY)]
    for run in chosen:
        if run.state == "running":
            print(f"{run.key} is in progress and stays.")
    chosen = [run for run in chosen if run.state != "running"]
    if not chosen:
        print("No run to remove.")
        return EXIT_OK
    print(f"To remove from {base}:\n")
    print("\n".join(_listing(chosen, st)))
    print()
    interactive = sys.stdin is not None and sys.stdin.isatty() and sys.stdout.isatty()
    if os.environ.get("CI") or not interactive:
        print("appsec-verifier: error: removing runs asks first and needs an interactive terminal. "
              "Nothing was removed.", file=sys.stderr)
        return EXIT_BLOCKED
    print(f"Remove {_count(len(chosen))} ({_size(sum(run.size for run in chosen))})? Their reports and evidence "
          "cannot be restored. [y/N] ", end="", flush=True)
    try:
        answer = input().strip().lower()
    except EOFError:
        answer = ""
    if answer not in ("y", "yes"):
        print("Nothing was removed.")
        return EXIT_OK
    return _remove(chosen)


def _remove(runs: list[Run]) -> int:
    removed, freed, failed = 0, 0, []
    for run in runs:
        try:
            with hold_run(run.path):
                shutil.rmtree(run.path)
        except BlockingIOError:
            print(f"{run.key} is in progress and stays.")
            continue
        except OSError as exc:
            failed.append(f"{run.key}: {type(exc).__name__}")
            continue
        removed, freed = removed + 1, freed + run.size
        remove_if_empty(run.path.parent)
    print(f"Removed {_count(removed)}, {_size(freed)}.")
    if failed:
        print("appsec-verifier: error: not removed: " + "; ".join(failed), file=sys.stderr)
        return EXIT_BLOCKED
    return EXIT_OK


def _read(project: str, path: Path) -> Run:
    size, changed = _usage(path)
    running = in_progress(path)
    if not (path / REPORT).is_file():
        return Run(project, path, size, changed, "running" if running else "unfinished")
    meta = _meta(path / REPORT)
    if meta is None:
        return Run(project, path, size, changed, "running" if running else "report unreadable")
    summary = meta.get("summary") if isinstance(meta.get("summary"), dict) else {}
    counts = ((summary.get(key), label) for key, label in _VERDICTS)
    return Run(project, path, size, changed,
               "running" if running else "interrupted" if meta.get("interrupted") is True else "finished",
               mode=_field(meta, "safety", "mode"), target=_field(meta, "target", "base_url"),
               verdicts=" · ".join(f"{n} {label}" for n, label in counts
                                   if isinstance(n, int) and not isinstance(n, bool) and n > 0))


def _meta(report: Path) -> dict | None:
    try:
        with open(report, encoding="utf-8") as handle:
            doc = yaml.load(handle, Loader=_LOADER)
    except (OSError, ValueError, yaml.YAMLError):
        return None
    meta = doc.get("meta") if isinstance(doc, dict) else None
    return meta if isinstance(meta, dict) else None


def _field(meta: dict, section: str, key: str) -> str:
    value = meta.get(section)
    value = value.get(key) if isinstance(value, dict) else None
    return printable(value) if isinstance(value, str) else ""


def _usage(path: Path) -> tuple[int, float]:
    """The bytes of the run's files and when it last wrote: the newest change of the directory or an entry in it."""
    size, changed = 0, 0.0
    try:
        changed = path.lstat().st_mtime
        for entry in path.iterdir():
            changed = max(changed, entry.lstat().st_mtime)
    except OSError:
        pass
    for root, _dirs, files in os.walk(path):        # does not follow symbolic links
        for name in files:
            try:
                size += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return size, changed


def _entries(path: Path) -> list[Path]:
    try:
        return sorted(path.iterdir())
    except OSError:
        return []


def _listing(runs: list[Run], st: Style) -> list[str]:
    """One heading per project with its runs below it, one row each."""
    width = {name: max(len(getattr(run, name)) for run in runs) for name in ("state", "mode")}
    stem = max(len(run.path.name) for run in runs)
    lines: list[str] = []
    for project in dict.fromkeys(run.project for run in runs):
        own = [run for run in runs if run.project == project]
        if lines:
            lines.append("")
        lines.append(st(printable(project), "bold")
                     + st(f" · {_count(len(own))} · {_size(sum(run.size for run in own))}", "muted"))
        for run in own:
            cells = [run.path.name.ljust(stem), _size(run.size).rjust(8),
                     st(run.state, _STATE_ROLES[run.state]) + " " * (width["state"] - len(run.state))]
            if run.mode or run.target or run.verdicts:
                cells += [run.mode.ljust(width["mode"]), run.target, run.verdicts]
            lines.append(("  " + "  ".join(cells)).rstrip())
    return lines


def _count(n: int) -> str:
    return f"{n} run" if n == 1 else f"{n} runs"


def _size(n: float) -> str:
    if n < 1000:
        return f"{n:.0f} B"
    n /= 1000
    for unit in ("KB", "MB"):
        if n < 1000:
            return f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} GB"
