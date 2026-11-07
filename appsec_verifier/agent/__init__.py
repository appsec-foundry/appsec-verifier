"""Agent-driven verification (VER-017, VER-028).

A probe is an LLM agent that reads the finding and the evidenced source, then
plans and executes requests — but ONLY through the narrow, scope-confined tools
here (guarded HTTP as a chosen identity, read-only source access), never an open
shell or raw network. The model (planner) is injected, so the loop is tested
offline with a scripted planner; the real planners are selected by model
profile (profiles.py): agent CLIs and the OpenAI and Anthropic APIs, each a
host behind HostPlanner (hosts.py).
"""

from __future__ import annotations

from .hosts import HostPlanner, HostReply, HostUnavailable
from .loop import AgentProbe, Planner
from .profiles import DEFAULT_PROFILE, PROFILES, SUBSCRIPTION_PROFILES
from .registry import AGENT_CLASSES, agent_registry
from .source_reader import SourceReader
from .tools import AgentTools, ToolError

__all__ = [
    "AgentProbe", "Planner", "AgentTools", "ToolError", "SourceReader",
    "HostPlanner", "HostReply", "HostUnavailable",
    "DEFAULT_PROFILE", "PROFILES", "SUBSCRIPTION_PROFILES",
    "agent_registry", "AGENT_CLASSES",
]
