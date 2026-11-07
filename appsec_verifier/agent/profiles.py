"""Model profiles: which agent CLI or API plans the verification (VER-023).

Named and chosen as in AppSec Analyzer. Without --profile an interactive run
uses `claude`; a non-interactive run must name its profile so the command shows
its provider. `codex-cli` and `copilot-cli` use a subscription that reports no
cost, so they are bounded by calls and time instead of USD. `anthropic-api`
serves CI without an installed agent CLI. Every profile is a host behind
HostPlanner, so the same bounds and the same step contract apply to all.
"""

from __future__ import annotations

import os

from .hosts import HostPlanner, HostUnavailable

PROFILES = ("claude", "codex-cli", "copilot-cli", "codex", "anthropic-api")
DEFAULT_PROFILE = "claude"
SUBSCRIPTION_PROFILES = frozenset(("codex-cli", "copilot-cli"))


def resolve(profile: str, *, model: str | None = None, environ=None):
    """Return (planner factory, agent info) for a profile, or raise HostUnavailable.
    The factory returns a fresh planner per finding; all planners of a run share
    one host, so a failed confinement check stops the rest of the run."""
    environ = os.environ if environ is None else environ
    if profile == "anthropic-api":
        from .host_anthropic import AnthropicHost as host_cls
    elif profile == "claude":
        from .host_claude import ClaudeHost as host_cls
    elif profile == "codex-cli":
        from .host_codex_cli import CodexCliHost as host_cls
    elif profile == "copilot-cli":
        from .host_copilot_cli import CopilotCliHost as host_cls
    elif profile == "codex":
        from .host_openai import OpenAIHost as host_cls
    else:
        raise HostUnavailable(f"unknown profile {profile!r}; choose one of {', '.join(PROFILES)}")
    host = host_cls.resolve(model=model, environ=environ)
    info = {"profile": profile, "model": host.model, "runtime": f"{host.label} {host.version}".strip(),
            "auth": host.auth}
    return (lambda: HostPlanner(host)), info
