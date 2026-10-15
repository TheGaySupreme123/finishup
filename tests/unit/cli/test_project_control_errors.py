"""CLI rendering for bounded project-control refusals."""

from __future__ import annotations

import pytest

from finishup.cli.app import control_failure
from finishup.cli.render import recovery_directive_json
from finishup.domain.coordination import CoordinationErrorCode
from finishup.ports.control import ControlError
from finishup.protocol.recovery import continuation_for_reason, directive_for


def test_implicit_project_refusal_has_json_reason_and_invalid_request_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted: list[object] = []
    monkeypatch.setattr("finishup.cli.app._stdout_json", emitted.append)

    code = control_failure(ControlError("implicit_project_requires_opt_out"), json_output=True)

    refresh = directive_for("lineage_state_refresh")
    assert refresh is not None
    assert code == 2
    assert emitted == [
        {
            "ok": False,
            "public_code": "INVALID_REQUEST",
            "reason": "implicit_project_requires_opt_out",
            "retryable": False,
            "recovery": recovery_directive_json(refresh),
        }
    ]


def test_implicit_project_refusal_has_human_opt_out_remedy(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = control_failure(ControlError("implicit_project_requires_opt_out"))

    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "implicit_project_requires_opt_out" in captured.err
    assert "finishup project opt-out" in captured.err


@pytest.mark.parametrize("reason", tuple(code.value for code in CoordinationErrorCode))
def test_every_project_reason_maps_to_invalid_request_json(
    reason: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted: list[object] = []
    monkeypatch.setattr("finishup.cli.app._stdout_json", emitted.append)

    code = control_failure(ControlError(reason), json_output=True)

    assert code == 2
    assert len(emitted) == 1
    payload = emitted[0]
    assert isinstance(payload, dict)
    assert payload["ok"] is False
    assert payload["public_code"] == "INVALID_REQUEST"
    assert payload["reason"] == reason
    assert payload["retryable"] is False
    directive = directive_for(continuation_for_reason(reason))
    assert directive is not None
    assert payload["recovery"] == recovery_directive_json(directive)


@pytest.mark.parametrize("reason", tuple(code.value for code in CoordinationErrorCode))
def test_every_project_reason_names_its_continuation_on_stderr(
    reason: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The human line gains the same directive the JSON body carries (ADR-030, #741)."""

    control_failure(ControlError(reason))

    directive = directive_for(continuation_for_reason(reason))
    assert directive is not None
    error = capsys.readouterr().err
    assert error.startswith(f"{reason}: ")
    assert f"Continuation: {directive.token}" in error
    assert f"Next: {directive.directive}" in error


def test_source_policy_refusal_does_not_recommend_workspace_consent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert control_failure(ControlError("coordination_source_policy_denied")) == 2
    error = capsys.readouterr().err
    assert "coordination disclosure policy" in error
    assert "workspace consent alone does not authorize this flow" in error
    assert "obtain current source-workspace consent" not in error
