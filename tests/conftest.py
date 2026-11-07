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


REAL_MODEL_TEST = cli._model_test


@pytest.fixture(autouse=True)
def _passing_model_test(monkeypatch):
    """`verify` asks the model once before the first finding (VER-032). Most tests
    fake the planner without a host, so the test passes here; the tests of the
    model test itself restore REAL_MODEL_TEST."""
    from appsec_verifier.preflight import Check

    monkeypatch.setattr(cli, "_model_test", lambda factory, budget: Check("Model test", "ok", "fake model answered"))
