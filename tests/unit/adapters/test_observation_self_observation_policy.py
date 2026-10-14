"""Delivery policy for FinishUP observing its own MCP tool calls (#564)."""

from __future__ import annotations

import pytest

from finishup.adapters.integrations.observation_local import (
    FINISHUP_OWNED_TOOL_NAMES,
    FINISHUP_READ_TOOL_NAMES,
    FINISHUP_TOOL_NAMES,
    self_observation_deliverable,
)
from finishup.domain.values import JsonValue
from finishup.ports.integrations import FINISHUP_WORKFLOW_TOOL_NAMES

_HOST_SPELLINGS = (
    "{name}",
    "mcp__finishup__{name}",
    "mcp__plugin_finishup_finishup__{name}",
    "finishup:{name}",
    "plugin-finishup-finishup:{name}",
    # The legacy server name a 0.1-0.2.5 registration and its recorded observations carry
    # (ADR-048): the policy reads it exactly as the current one.
    "mcp__yoetz__{name}",
    "mcp__plugin_yoetz_yoetz__{name}",
    "yoetz:{name}",
    "plugin-yoetz-yoetz:{name}",
)
_READS = ("status", "receipt", "read_guidance")
_MUTATIONS = ("start", "publish_work", "check", "respond")


def test_tool_name_sets_derive_from_the_one_registry_tuple() -> None:
    """The hand-written predecessor omitted ``read_guidance``; derivation forbids that drift."""

    assert set(_READS) | set(_MUTATIONS) == set(FINISHUP_WORKFLOW_TOOL_NAMES)
    for name in FINISHUP_WORKFLOW_TOOL_NAMES:
        assert name in FINISHUP_TOOL_NAMES
        assert f"mcp__finishup__{name}" in FINISHUP_TOOL_NAMES
        assert f"mcp__yoetz__{name}" in FINISHUP_TOOL_NAMES
        for spelling in _HOST_SPELLINGS:
            assert spelling.format(name=name) in FINISHUP_OWNED_TOOL_NAMES
    assert FINISHUP_TOOL_NAMES < FINISHUP_OWNED_TOOL_NAMES
    assert FINISHUP_READ_TOOL_NAMES < FINISHUP_OWNED_TOOL_NAMES
    assert {
        name.rsplit("__", 1)[-1].rsplit(":", 1)[-1] for name in FINISHUP_READ_TOOL_NAMES
    } == set(_READS)


@pytest.mark.parametrize("spelling", _HOST_SPELLINGS)
@pytest.mark.parametrize("name", _READS)
def test_successful_or_outcome_less_finishup_read_is_retained_locally_only(
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
def test_finishup_mutation_delivers_its_post_event_only(spelling: str, name: str) -> None:
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
def test_explicit_failure_or_denial_of_any_finishup_tool_is_delivered(
    failure: dict[str, JsonValue], phase: str
) -> None:
    for tool in ("mcp__finishup__status", "mcp__plugin_finishup_finishup__check", "receipt"):
        assert self_observation_deliverable(phase, {"tool_name": tool, **failure}) is True


def test_non_finishup_tools_and_non_tool_phases_are_unchanged() -> None:
    for phase in ("PreToolUse", "PostToolUse"):
        assert self_observation_deliverable(phase, {"tool_name": "shell"}) is True
        assert self_observation_deliverable(phase, {"tool_name": "Read", "success": True}) is True
        assert self_observation_deliverable(phase, {}) is True
        assert self_observation_deliverable(phase, {"tool_name": 7}) is True
    for phase in ("PermissionRequest", "SessionStart", "Stop", "SessionEnd", ""):
        assert self_observation_deliverable(phase, {"tool_name": "mcp__finishup__status"}) is True
    # Names that merely resemble a FinishUP tool are not FinishUP-owned.
    assert self_observation_deliverable("PostToolUse", {"tool_name": "mcp__other__status"}) is True
    assert self_observation_deliverable("PostToolUse", {"tool_name": "status_check"}) is True
    assert self_observation_deliverable("PostToolUse", {"tool_name": "mcp__yoetzx__status"}) is True
    assert self_observation_deliverable("PostToolUse", {"tool_name": "yoetz:statusx"}) is True
