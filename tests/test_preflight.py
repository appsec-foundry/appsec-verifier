"""Authorisation gate: explicit confirmation required; non-interactive needs the
CI flag; silence never confirms. Enter confirms only with default_yes, which the
guided run sets when the operator typed the target URL in it (VER-002)."""

from __future__ import annotations

import pytest

from appsec_verifier.preflight import confirm_authorization


def test_interactive_yes_confirms():
    c = confirm_authorization(non_interactive=False, assume_yes=False, prompt=lambda _: "y")
    assert c.confirmed and c.mode == "interactive"


def test_interactive_default_no_declines():
    c = confirm_authorization(non_interactive=False, assume_yes=False, prompt=lambda _: "")
    assert not c.confirmed


def test_enter_confirms_only_with_default_yes_and_the_prompt_says_so():
    prompts = []

    def enter(text):
        prompts.append(text)
        return ""

    assert not confirm_authorization(non_interactive=False, assume_yes=False, prompt=enter).confirmed
    assert confirm_authorization(non_interactive=False, assume_yes=False, default_yes=True, prompt=enter).confirmed
    assert prompts == ["Proceed against this target? [y/N] ", "Proceed against this target? [Y/n] "]


@pytest.mark.parametrize("answer", ["n", "no", "x", "ja"])
def test_with_default_yes_any_other_answer_declines(answer):
    c = confirm_authorization(non_interactive=False, assume_yes=False, default_yes=True, prompt=lambda _: answer)
    assert not c.confirmed


@pytest.mark.parametrize("stop", [EOFError, KeyboardInterrupt])
def test_with_default_yes_no_input_declines(stop):
    def gone(_):
        raise stop

    assert not confirm_authorization(non_interactive=False, assume_yes=False, default_yes=True, prompt=gone).confirmed


def test_default_yes_does_not_confirm_a_non_interactive_run():
    def must_not_run(_):
        raise AssertionError("prompted")

    c = confirm_authorization(non_interactive=True, assume_yes=False, default_yes=True, prompt=must_not_run)
    assert not c.confirmed


def test_interactive_eof_declines():
    def boom(_):
        raise EOFError
    c = confirm_authorization(non_interactive=False, assume_yes=False, prompt=boom)
    assert not c.confirmed


def test_interactive_ctrl_c_declines():
    def interrupt(_):
        raise KeyboardInterrupt
    c = confirm_authorization(non_interactive=False, assume_yes=False, prompt=interrupt)
    assert not c.confirmed


def test_non_interactive_without_flag_not_confirmed():
    c = confirm_authorization(non_interactive=True, assume_yes=False)
    assert not c.confirmed and c.mode == "ci-flag"


def test_ci_flag_confirms_without_prompt():
    def must_not_run(_):
        raise AssertionError("prompt must not be called when --yes is set")
    c = confirm_authorization(non_interactive=True, assume_yes=True, prompt=must_not_run)
    assert c.confirmed and c.mode == "ci-flag"
