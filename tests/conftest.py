from __future__ import annotations

import pytest

from appsec_verifier import cli


@pytest.fixture(autouse=True)
def _no_implicit_live_browser(request, monkeypatch):
    """Unit/CLI tests must inject a browser; only the opt-in browser module may start Chrome."""
    if request.node.path.name == "test_browser_live.py":
        return
    from appsec_verifier.tools.browser import ProofBrowser

    original = ProofBrowser.__init__

    def refused(_headless):
        raise AssertionError("offline tests must supply a fake browser launcher")

    def initialize(self, *args, **kwargs):
        kwargs.setdefault("launcher", refused)
        original(self, *args, **kwargs)

    monkeypatch.setattr(ProofBrowser, "__init__", initialize)


@pytest.fixture(autouse=True)
def _plain_console(monkeypatch):
    """Console colour follows NO_COLOR, FORCE_COLOR and the terminal; tests start
    from plain output whatever the developer's environment sets."""
    for name in ("FORCE_COLOR", "NO_COLOR", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "_logo_shown", False)


@pytest.fixture(autouse=True)
def _temporary_data_directory(tmp_path_factory):
    """A run without --output writes below the user data directory (VER-058); tests get a temporary one. Its own
    MonkeyPatch, so a test's monkeypatch.undo() cannot send a run into the developer's home."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("XDG_DATA_HOME", str(tmp_path_factory.mktemp("data")))
        yield


REAL_MODEL_TEST = cli._model_test


@pytest.fixture(autouse=True)
def _passing_model_test(monkeypatch):
    """`verify` asks the model once before the first finding (VER-032). Most tests
    fake the planner without a host, so the test passes here; the tests of the
    model test itself restore REAL_MODEL_TEST."""
    from appsec_verifier.preflight import Check

    monkeypatch.setattr(cli, "_model_test",
                        lambda factory, budget, **_: Check("Model test", "ok", "fake model answered"))
