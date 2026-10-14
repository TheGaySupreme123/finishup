"""Delivery policy for Yoetz observing its own MCP tool calls (#564)."""

from __future__ import annotations

import pytest

from yoetz.adapters.integrations.observation_local import (
    YOETZ_OWNED_TOOL_NAMES,
    YOETZ_READ_TOOL_NAMES,
    YOETZ_TOOL_NAMES,
    self_observation_deliverable,
)
from yoetz.domain.values import JsonValue
from yoetz.ports.integrations import YOETZ_WORKFLOW_TOOL_NAMES

_HOST_SPELLINGS = (
    "{name}",
    "mcp__yoetz__{name}",
    "mcp__plugin_yoetz_yoetz__{name}",
    "yoetz:{name}",
    "plugin-yoetz-yoetz:{name}",
)
_READS = ("status", "receipt", "read_guidance")
_MUTATIONS = ("start", "publish_work", "check", "respond")


def test_tool_name_sets_derive_from_the_one_registry_tuple() -> None:
    """The hand-written predecessor omitted ``read_guidance``; derivation forbids that drift."""

    assert set(_READS) | set(_MUTATIONS) == set(YOETZ_WORKFLOW_TOOL_NAMES)
    for name in YOETZ_WORKFLOW_TOOL_NAMES:
        assert name in YOETZ_TOOL_NAMES
        assert f"mcp__yoetz__{name}" in YOETZ_TOOL_NAMES
        for spelling in _HOST_SPELLINGS:
            assert spelling.format(name=name) in YOETZ_OWNED_TOOL_NAMES
    assert YOETZ_TOOL_NAMES < YOETZ_OWNED_TOOL_NAMES
    assert YOETZ_READ_TOOL_NAMES < YOETZ_OWNED_TOOL_NAMES
    assert {name.rsplit("__", 1)[-1].rsplit(":", 1)[-1] for name in YOETZ_READ_TOOL_NAMES} == set(
        _READS
    )


@pytest.mark.parametrize("spelling", _HOST_SPELLINGS)
@pytest.mark.parametrize("name", _READS)
def test_successful_or_outcome_less_yoetz_read_is_retained_locally_only(
    spelling: str, name: str
) -> None:
    tool = spelling.format(name=name)
    assert self_observation_deliverable("PreToolUse", {"tool_name": tool}) is False
    assert self_observation_deliverable("PostToolUse", {"tool_name": tool}) is False
    assert (
        self_observation_deliverable("PostToolUse", {"tool_name": tool, "success": True}) is False
    )
    assert (
        self_observation_deliverable("PostToolUse", {"tool_name": tool, "exit_status": 0}) is False
    )
    assert (
        self_observation_deliverable(
            "PostToolUse", {"tool_name": tool, "result_status": "completed"}
        )
        is False
    )


@pytest.mark.parametrize("spelling", _HOST_SPELLINGS)
@pytest.mark.parametrize("name", _MUTATIONS)
def test_yoetz_mutation_delivers_its_post_event_only(spelling: str, name: str) -> None:
    tool = spelling.format(name=name)
    assert self_observation_deliverable("PreToolUse", {"tool_name": tool}) is False
    assert self_observation_deliverable("PostToolUse", {"tool_name": tool}) is True
    assert self_observation_deliverable("PostToolUse", {"tool_name": tool, "success": True}) is True


@pytest.mark.parametrize(
    "failure",
    [
        {"success": False},
        {"denied": True},
        {"exit_status": 1},
        {"result_status": "failed"},
        {"result_status": "error"},
        {"action": "claude_mcp_failure"},
        # An explicit failure wins over a conflicting success fact.
        {"success": True, "exit_status": 2},
    ],
)
@pytest.mark.parametrize("phase", ["PreToolUse", "PostToolUse"])
def test_explicit_failure_or_denial_of_any_yoetz_tool_is_delivered(
    failure: dict[str, JsonValue], phase: str
) -> None:
    for tool in ("mcp__yoetz__status", "mcp__plugin_yoetz_yoetz__check", "receipt"):
        assert self_observation_deliverable(phase, {"tool_name": tool, **failure}) is True


def test_non_yoetz_tools_and_non_tool_phases_are_unchanged() -> None:
    for phase in ("PreToolUse", "PostToolUse"):
        assert self_observation_deliverable(phase, {"tool_name": "shell"}) is True
        assert self_observation_deliverable(phase, {"tool_name": "Read", "success": True}) is True
        assert self_observation_deliverable(phase, {}) is True
        assert self_observation_deliverable(phase, {"tool_name": 7}) is True
    for phase in ("PermissionRequest", "SessionStart", "Stop", "SessionEnd", ""):
        assert self_observation_deliverable(phase, {"tool_name": "mcp__yoetz__status"}) is True
    # Names that merely resemble a Yoetz tool are not Yoetz-owned.
    assert self_observation_deliverable("PostToolUse", {"tool_name": "mcp__other__status"}) is True
    assert self_observation_deliverable("PostToolUse", {"tool_name": "status_check"}) is True


@pytest.mark.parametrize("name", (*_READS, *_MUTATIONS))
def test_cursor_generic_mcp_spelling_is_not_proof_of_a_yoetz_call(name: str) -> None:
    """tb4 n5 round 2: ``MCP:<tool>`` names no server, so it may be another server's tool.

    The policy alone never suppresses it; only the Cursor adapter, holding the bridge's record of
    serving that exact call, may hand the policy Yoetz's scoped spelling instead.
    """

    for phase in ("PreToolUse", "PostToolUse"):
        assert self_observation_deliverable(phase, {"tool_name": f"MCP:{name}"}) is True
