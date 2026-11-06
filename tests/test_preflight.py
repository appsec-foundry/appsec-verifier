"""Authorisation gate: explicit confirmation required; non-interactive needs the
CI flag; silence never confirms (VER-002)."""

from __future__ import annotations

from appsec_verifier.preflight import confirm_authorization


def test_interactive_yes_confirms():
    c = confirm_authorization(non_interactive=False, assume_yes=False, prompt=lambda _: "y")
    assert c.confirmed and c.mode == "interactive"


def test_interactive_default_no_declines():
    c = confirm_authorization(non_interactive=False, assume_yes=False, prompt=lambda _: "")
    assert not c.confirmed


def test_interactive_eof_declines():
    def boom(_):
        raise EOFError
    c = confirm_authorization(non_interactive=False, assume_yes=False, prompt=boom)
    assert not c.confirmed


def test_non_interactive_without_flag_not_confirmed():
    c = confirm_authorization(non_interactive=True, assume_yes=False)
    assert not c.confirmed and c.mode == "ci-flag"


def test_ci_flag_confirms_without_prompt():
    def must_not_run(_):
        raise AssertionError("prompt must not be called when --yes is set")
    c = confirm_authorization(non_interactive=True, assume_yes=True, prompt=must_not_run)
    assert c.confirmed and c.mode == "ci-flag"
