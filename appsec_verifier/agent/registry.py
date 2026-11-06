"""Build a ProbeRegistry of agent-driven probes for the verifiable classes.

Each class gets an AgentProbe wired to a fresh planner per run (the factory).
The planner reads the finding's class from the ProbeContext, so one factory
serves every class.
"""

from __future__ import annotations

from collections.abc import Callable

from ..verify.probes import ProbeRegistry
from .loop import AgentProbe, Planner

AGENT_CLASSES = ("access-control", "xss", "injection", "path-traversal", "open-redirect", "ssrf")


def agent_registry(make_planner: Callable[[], Planner], *, classes=None, max_steps: int = 12) -> ProbeRegistry:
    reg = ProbeRegistry()
    for cls in (classes or AGENT_CLASSES):
        reg.register(AgentProbe(cls, make_planner, max_steps=max_steps))
    return reg
