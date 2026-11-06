"""Agent-driven verification (VER-017, VER-028).

A probe is an LLM agent that reads the finding and the evidenced source, then
plans and executes requests — but ONLY through the narrow, scope-confined tools
here (guarded HTTP as a chosen identity, read-only source access), never an open
shell or raw network. The model (planner) is injected, so the loop is tested
offline with a scripted planner; the real planners (Anthropic API, Claude Code)
are wired separately.
"""

from __future__ import annotations

from .loop import AgentProbe, Planner
from .planner_anthropic import AnthropicPlanner
from .planner_claude_code import ClaudeCodeBackend, ClaudeCodePlanner, ClaudeCodeUnavailable
from .registry import AGENT_CLASSES, agent_registry
from .source_reader import SourceReader
from .tools import AgentTools, ToolError

__all__ = [
    "AgentProbe", "Planner", "AgentTools", "ToolError", "SourceReader",
    "AnthropicPlanner", "ClaudeCodeBackend", "ClaudeCodePlanner", "ClaudeCodeUnavailable",
    "agent_registry", "AGENT_CLASSES",
]
