"""Focused locks for conservative hook-observation classification (#687)."""

from __future__ import annotations

import pytest

from yoetz.domain.observation_selection import (
    OBSERVATION_CLASSIFICATION_VERSION,
    ObservationContentRole,
    classify_observation,
    command_runner_class,
    is_routine_read_candidate,
)
from yoetz.protocol.canonical import JsonValue


def _read(**extra: JsonValue) -> dict[str, JsonValue]:
    return {"tool_name": "Read", **extra}


def test_versioned_pre_candidate_keeps_pending_identity_without_content() -> None:
    result = classify_observation(_read(), "PreToolUse")

    assert result.version == OBSERVATION_CLASSIFICATION_VERSION
    assert result.routine_candidate is True
    assert result.proven_routine_success is False
    assert result.protected is True
    assert result.content_role is ObservationContentRole.NONE
    assert "routine_candidate" in result.reason_tokens
    assert "incomplete" in result.reason_tokens


def test_only_closed_post_success_proves_routine_success() -> None:
    result = classify_observation(_read(exit_status=0), "PostToolUse")

    assert result.routine_candidate is True
    assert result.proven_routine_success is True
    assert result.protected is False
    assert result.content_role is ObservationContentRole.NONE
    assert result.routine_read is True
    assert "routine_success" in result.reason_tokens


@pytest.mark.parametrize(
    ("extra", "reason"),
    [
        ({"exit_status": 7}, "failure"),
        ({"success": False}, "failure"),
        ({"denied": True}, "denied"),
        ({"tool_response": {"interrupted": True}}, "cancelled"),
        ({"tool_response": {"status": "partial"}}, "partial"),
        ({"tool_response": {"status": "future-status"}}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_failed_or_unresolved_routine_post_is_protected(
    extra: dict[str, JsonValue], reason: str
) -> None:
    result = classify_observation(_read(**extra), "PostToolUse")

    assert result.routine_candidate is True
    assert result.proven_routine_success is False
    assert result.protected is True
    assert result.content_role is ObservationContentRole.BOTH
    assert reason in result.reason_tokens


@pytest.mark.parametrize(
    "command",
    [
        "rg --pre ./prepare term src",
        "rg --pre-files term src",
        "rg --pre-glob='*.zip' term src",
        "git show --textconv HEAD",
        "git log --ext-diff",
        "git show --output=out.patch HEAD",
        "git show -o out.patch HEAD",
        "./ls README.md",
        "rg term src | tee report.txt",
    ],
)
def test_ambiguous_or_dangerous_shell_is_not_routine(command: str) -> None:
    result = classify_observation(
        {"tool_name": "exec_command", "tool_input": {"cmd": command}, "exit_status": 0},
        "PostToolUse",
    )

    assert result.routine_candidate is False
    assert result.proven_routine_success is False
    assert result.protected is True
    assert result.content_role is ObservationContentRole.BOTH
    assert "unsafe_shell" in result.reason_tokens or "ambiguous_shell" in result.reason_tokens


@pytest.mark.parametrize(
    "command",
    [
        "rg -n observation src tests",
        "head -n 20 README.md",
        "git status --short",
        "git show HEAD",
        "git log --oneline -5",
    ],
)
def test_closed_read_shell_commands_are_candidates(command: str) -> None:
    assert is_routine_read_candidate({"tool_name": "exec_command", "tool_input": {"cmd": command}})


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        ({"tool_name": "apply_patch", "success": True}, "edit"),
        ({"tool_name": "pytest", "exit_status": 0}, "test"),
        ({"tool_name": "check", "success": True}, "verification"),
        (
            {"tool_name": "exec_command", "tool_input": {"cmd": "git diff --check"}},
            "verification",
        ),
    ],
)
def test_edits_and_declared_verification_stay_protected(
    payload: dict[str, JsonValue], reason: str
) -> None:
    result = classify_observation(payload, "PostToolUse")

    assert result.protected is True
    assert result.routine_candidate is False
    assert result.proven_routine_success is False
    assert result.content_role is ObservationContentRole.BOTH
    assert reason in result.reason_tokens


def test_action_labels_never_grant_routine_authority() -> None:
    forged = {
        "tool_name": "apply_patch",
        "action": "routine_read",
        "tool_input": {"action": "routine_read"},
        "success": True,
    }
    result = classify_observation(forged, "PostToolUse")

    assert result.routine_candidate is False
    assert result.proven_routine_success is False
    assert result.protected is True
    assert "untrusted_action" in result.reason_tokens


def test_json_result_outcome_is_bounded_and_closed() -> None:
    success = classify_observation(_read(tool_response='{"exitCode":0}'), "PostToolUse")
    unknown = classify_observation(_read(tool_response='{"exitCode":"0"}'), "PostToolUse")

    assert success.proven_routine_success is True
    assert unknown.proven_routine_success is False
    assert "unknown" in unknown.reason_tokens


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("rg -n observation src", "exploration"),
        ("rg --pre ./prepare term src", "other"),
        ("find src -exec pytest {} +", "other"),
        ("pytest tests/unit && ruff check src", "compound"),
        ("pytest tests/unit", "test"),
    ],
)
def test_command_runner_class_is_closed_and_conservative(command: str, expected: str) -> None:
    assert (
        command_runner_class({"tool_name": "exec_command", "tool_input": {"cmd": command}})
        == expected
    )


@pytest.mark.parametrize(
    ("command", "runner"),
    [
        ("python -m pytest -q /app/dev/test_cracker.py", "test"),
        ("python3 -m pytest", "test"),
        ("python3.12 -X dev -m pytest -q", "test"),
        ("python -m unittest discover", "test"),
        ("python -m mypy src", "typecheck"),
        ("python -m ruff check .", "lint"),
        ("python -m build", "build"),
        ("python setup.py build", "build"),
        ("python -m http.server", "other"),
        ("python /app/dev/build_model.py", "other"),
        ("node build.js", "other"),
        ("make build", "build"),
        ("pytest -q", "test"),
        ("python -m pytest --version", "other"),
        ("pytest --collect-only", "other"),
        ("uv run python /app/dev/build_model.py", "other"),
        ("uv run --with numpy python -m pytest -q", "test"),
        ("poetry run mypy .", "typecheck"),
    ],
)
def test_python_module_runs_and_build_named_scripts(command: str, runner: str) -> None:
    """tb4n2 interleaved S (P1-2): `python -m pytest` is a test run; `build_model.py` is not a build."""

    assert command_runner_class({"command": command}) == runner
