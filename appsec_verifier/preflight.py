"""Pre-flight authorisation gate (VER-002, VER-003).

Before the first request the Verifier shows the resolved scope and obtains one
explicit confirmation. Silence, a timeout, or a non-interactive run without the
CI flag do not count as confirmation. This module is pure decision logic; I/O
(the prompt, the clock) is injected so it is testable without a terminal.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Confirmation:
    confirmed: bool
    mode: str          # "interactive" | "ci-flag"
    reason: str


def confirm_authorization(*, non_interactive: bool, assume_yes: bool, prompt=input) -> Confirmation:
    """Decide whether the run is authorised to start.

    - ``--yes`` confirms without a prompt and is recorded as ``ci-flag``.
    - A non-interactive run without ``--yes`` is NOT confirmed (it must not
      prompt and must not assume consent).
    - An interactive run asks once; only an explicit yes confirms.
    """
    if assume_yes:
        return Confirmation(True, "ci-flag", "authorised by explicit flag")
    if non_interactive:
        return Confirmation(False, "ci-flag", "non-interactive run without --yes: not confirmed")
    try:
        answer = prompt("Proceed against this target? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return Confirmation(False, "interactive", "no input available: not confirmed")
    if answer in ("y", "yes"):
        return Confirmation(True, "interactive", "confirmed at the prompt")
    return Confirmation(False, "interactive", "declined at the prompt")
