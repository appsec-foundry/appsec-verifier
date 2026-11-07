"""Update a pipx installation of the Verifier on request (VER-033)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .version_info import installed_version, version_change, version_string

PIPX_PACKAGE = "appsec-verifier"
# --force-reinstall: a GitHub installation keeps its version number between commits.
PIPX_UPGRADE = ("upgrade", "--pip-args=--force-reinstall", PIPX_PACKAGE)
UPDATE_TIMEOUT = 10 * 60


class UpdateError(Exception):
    """The update cannot start or did not complete; the message names why."""


def _pipx_source() -> str | None:
    """The source pipx recorded when this Verifier was installed as its own pipx application."""
    try:
        with (Path(sys.prefix) / "pipx_metadata.json").open(encoding="utf-8") as handle:
            main = json.load(handle)["main_package"]
        source = main["package_or_url"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if main.get("package") != PIPX_PACKAGE or not isinstance(source, str) or not source:
        return None
    # A recorded URL may carry credentials; show only where it points.
    parts = urlsplit(source.removeprefix("git+"))
    shown = urlunsplit((parts.scheme, parts.netloc.rpartition("@")[2], parts.path, "", ""))
    return shown if parts.scheme else source


def update_installation() -> int:
    """Upgrade a pipx installation after a yes or Enter; install nothing otherwise."""
    command = f"pipx {' '.join(PIPX_UPGRADE)}"
    source = _pipx_source()
    if not source:
        raise UpdateError("this Verifier was not installed with pipx; update it the way you installed it "
                          "(README, Install)")
    interactive = sys.stdin is not None and sys.stdin.isatty() and sys.stdout.isatty()
    if os.environ.get("CI") or not interactive:
        raise UpdateError(f"update asks before it installs and needs an interactive terminal; run `{command}` "
                          "yourself")
    search_path = os.pathsep.join(p for p in os.get_exec_path() if Path(p).is_absolute())
    pipx = shutil.which("pipx", path=search_path)
    if not pipx:
        raise UpdateError("pipx was not found on PATH; install pipx or update the way you installed the Verifier")
    before = version_string()
    print(f"Installed version: {before}")
    print(f"Update the installed Verifier from {source} with `{command}`? [Y/n] ", end="", flush=True)
    try:
        answer = input().strip().lower()
    except EOFError:
        answer = "n"
    if answer not in ("", "y", "yes"):
        print("Nothing was installed.")
        return 0
    print("Reinstalling ...", flush=True)
    try:
        result = subprocess.run(
            [pipx, *PIPX_UPGRADE],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=UPDATE_TIMEOUT, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise UpdateError("the update could not be completed") from None
    if result.returncode:
        print(result.stdout, end="", file=sys.stderr)
        raise UpdateError("the update failed, see the pipx output above")
    print(f"Verifier was reinstalled from {source}.")
    after = version_change(before, installed_version())
    if after is None:
        print("The new version could not be read; check it with `appsec-verifier --version`.")
    else:
        print(f"Installed version: {after}")
    return 0
