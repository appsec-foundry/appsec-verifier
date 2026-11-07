"""Version and the boundary that locates runtime resources (schemas, data).

Mirrors AppSec Analyzer: resources live at the repo root in a source checkout,
and are copied into this package inside the built wheel (see setup.py), so a
`pipx install` carries them. `resource_root()` finds them in either place.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

INTERFACE_VERSION = 1
ENGINE_VERSION = "0.1.0a1"

_RUNTIME_DIRS = ("schemas", "data")


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


def version_string() -> str:
    """Release version, with the short commit and date when run from a checkout."""
    root = Path(__file__).resolve().parent.parent
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "describe", "--always", "--dirty", "--abbrev=8"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        sha = out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        sha = ""
    return f"{ENGINE_VERSION} ({sha})" if sha else ENGINE_VERSION
