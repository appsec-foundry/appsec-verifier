"""Runtime prerequisites are checked against recorded target answers (VER-008, VER-047)."""

from __future__ import annotations

import pytest
from test_agent_tools import _ctx

from appsec_verifier.agent.tools import AgentTools, ToolError


@pytest.mark.parametrize("body,status,expected", [
    ("Active backend: relational", 200, "observed"),
    ("Active backend: document", 200, "not-observed"),
    ("Active backend: relational", 500, "not-observed"),
    ("Active backend: relational", 302, "not-observed"),
])
def test_prerequisite_uses_runtime_configuration_without_extra_requests(tmp_path, body, status, expected):
    ctx = _ctx(tmp_path, lambda *a, **k: pytest.fail("no target request"))
    ctx.agent_history = [{"tool": "http_request", "args": {"path": "/settings"}, "result": {"status": status}}]
    ctx.responses = {1: {"complete": True, "body": body}}
    result = AgentTools(ctx).call("check_prerequisite", {
        "condition": "The relational backend must be active", "steps": [1], "text": "Active backend: relational"})
    assert result["status"] == expected and ctx.budget.requests == 0
    assert ctx.prerequisite_checks == [result] and not ctx.derived_requests


@pytest.mark.parametrize("tool,complete,withheld", [
    ("read_source", True, False), ("http_request", False, False), ("http_request", True, True),
])
def test_source_incomplete_and_withheld_answers_cannot_establish_runtime_state(tmp_path, tool, complete, withheld):
    ctx = _ctx(tmp_path, lambda *a, **k: pytest.fail("no target request"))
    ctx.agent_history = [{"tool": tool, "result": {"status": 200, "body_withheld": withheld}}]
    ctx.responses = {1: {"complete": complete, "body": "enabled"}}
    with pytest.raises(ToolError):
        AgentTools(ctx).check_prerequisite(condition="Feature enabled at runtime", steps=[1], text="enabled")
    assert not getattr(ctx, "prerequisite_checks", [])
