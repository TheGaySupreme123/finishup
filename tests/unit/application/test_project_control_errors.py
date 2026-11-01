"""Project control errors preserve the finite coordination refusal vocabulary."""

from __future__ import annotations

import pytest

from finishup.application.projects import ProjectCommandError, build_project_support_handler
from finishup.domain.coordination import CoordinationErrorCode
from finishup.ports.control import ControlError

_PROJECT_ID = "prj_69000000-0000-4000-8000-000000000001"
_EXPECTED_GENERATION = 7


class _FailingProjectApplication:
    def __init__(self, code: CoordinationErrorCode) -> None:
        self.code = code
        self.dissolve_calls: list[tuple[str, int | None]] = []

    async def dissolve(self, *, project_id: str, expected_generation: int | None) -> object:
        self.dissolve_calls.append((project_id, expected_generation))
        raise ProjectCommandError(self.code)


@pytest.mark.anyio
@pytest.mark.parametrize("code", tuple(CoordinationErrorCode))
async def test_project_support_preserves_each_finite_refusal(
    code: CoordinationErrorCode,
) -> None:
    application = _FailingProjectApplication(code)
    handler = build_project_support_handler(application)  # type: ignore[arg-type]

    with pytest.raises(ControlError) as raised:
        await handler(
            {
                "operation": "dissolve",
                "project_id": _PROJECT_ID,
                "expected_generation": _EXPECTED_GENERATION,
            }
        )

    assert raised.value.reason == code.value
    assert raised.value.retryable is False
    assert application.dissolve_calls == [(_PROJECT_ID, _EXPECTED_GENERATION)]


@pytest.mark.parametrize("code", tuple(CoordinationErrorCode))
def test_coordination_refusals_cannot_be_marked_retryable(code: CoordinationErrorCode) -> None:
    with pytest.raises(ValueError, match="coordination_control_error_must_not_be_retryable"):
        ControlError(code.value, retryable=True)


# ``invalid_request`` is a registered transport refusal, even on the project surface.
@pytest.mark.parametrize("reason", ("invalid_project_request", "project-title-leak", ""))
def test_control_error_rejects_non_vocabulary_project_reason(reason: str) -> None:
    with pytest.raises(TypeError, match="control_error_reason_invalid"):
        ControlError(reason)
