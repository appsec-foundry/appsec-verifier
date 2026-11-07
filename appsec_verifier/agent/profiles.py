"""Model profiles: which agent CLI or API plans the verification (VER-023, VER-032).

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


ACCESS_TIMEOUT_S = 30.0


def resolve(profile: str, *, model: str | None = None, environ=None, check_access: bool = False):
    """Return (planner factory, agent info) for a profile, or raise HostUnavailable.
    The factory returns a fresh planner per finding; all planners of a run share
    one host, so a failed confinement check stops the rest of the run.
    `check_access` asks an API host for the model's metadata once (VER-032); an
    agent CLI has only its local login checked. `info["check"]` says which.
    `info["api_billing"]` says whether the run is billed by the API, so the
    console shows its costs without --show-costs, as in AppSec Analyzer."""
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
    check = "local configuration checked"
    if check_access and hasattr(host, "check_access"):
        host.check_access(ACCESS_TIMEOUT_S)
        check = "model metadata accessible"
    info = {"profile": profile, "model": host.model, "runtime": f"{host.label} {host.version}".strip(),
            "auth": host.auth, "check": check, "api_billing": host.api_billing}
    return PlannerFactory(host), info


class PlannerFactory:
    """A fresh HostPlanner per finding, all over the run's one host. `host` is
    also what `preflight --test-model` calls once."""

    def __init__(self, host):
        self.host = host

    def __call__(self) -> HostPlanner:
        return HostPlanner(self.host)
