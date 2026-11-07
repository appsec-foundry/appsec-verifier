from __future__ import annotations

import pytest

from appsec_verifier import cli


@pytest.fixture(autouse=True)
def _plain_console(monkeypatch):
    """Console colour follows NO_COLOR, FORCE_COLOR and the terminal; tests start
    from plain output whatever the developer's environment sets."""
    for name in ("FORCE_COLOR", "NO_COLOR", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "_logo_shown", False)
