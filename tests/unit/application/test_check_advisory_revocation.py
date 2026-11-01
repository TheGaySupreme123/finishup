"""Revocation fences for current project advisory notes."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest

import finishup.application.check as check
from finishup.domain.coordination import CoordinationError, CoordinationErrorCode

_PROJECT = "prj_00000000-0000-4000-8000-000000000001"
_REQUESTER = "tsk_00000000-0000-4000-8000-000000000001"
_COUNTERPART = "tsk_00000000-0000-4000-8000-000000000002"


@pytest.mark.anyio
@pytest.mark.parametrize("authority_change", ("revoke", "new_generation_same_members"))
async def test_advisory_notes_suppress_after_duplicate_reads_are_revoked(
    monkeypatch: pytest.MonkeyPatch,
    authority_change: str,
) -> None:
    class Catalog:
        generation = 1

        async def project_state(self, project: str) -> object:
            assert project == _PROJECT
            return SimpleNamespace(membership_generation=self.generation)

        async def list_task_project_ids(self, task_id: str) -> tuple[str, ...]:
            assert task_id == _REQUESTER
            return (_PROJECT,)

    class ProjectApplication:
        def __init__(self) -> None:
            self.catalog = Catalog()
            self.live_reads = 0
            self.revoked = False

        async def live_admitted_member_task_ids(
            self, task_id: str, *, project: str, expected_generation: int
        ) -> tuple[str, ...]:
            assert task_id == _REQUESTER
            assert project == _PROJECT
            self.live_reads += 1
            if expected_generation != self.catalog.generation:
                raise ValueError("coordination_generation_revoked")
            return () if self.revoked else (_COUNTERPART,)

    project_application = ProjectApplication()
    app = SimpleNamespace(project_application=project_application)

    async def duplicate_after_revoke(*_args: object, **_kwargs: object) -> tuple[str, ...]:
        # Model the awaited context/ledger reads in the real duplicate helper: authority is
        # revoked after the pre-duplicate fence but before the note is projected.
        if authority_change == "revoke":
            project_application.revoked = True
        else:
            # A newly granted generation can contain identical members. Their equality must
            # not authorize duplicate finding facts read under the earlier generation.
            project_application.catalog.generation += 1
        return (_REQUESTER, _COUNTERPART)

    monkeypatch.setattr(check, "_duplicate_project_advisory_task_ids", duplicate_after_revoke)

    notes_reader = cast(
        Callable[[object, str, tuple[object, ...]], Awaitable[tuple[object, ...]]],
        getattr(check, "_current_project_advisory_notes"),
    )
    notes = await notes_reader(app, _REQUESTER, ())

    assert notes == ()
    assert project_application.live_reads == 3


@pytest.mark.anyio
@pytest.mark.parametrize(
    "reason",
    (
        CoordinationErrorCode.CONSENT_REQUIRED,
        CoordinationErrorCode.GRANT_REVOKED,
        CoordinationErrorCode.GENERATION_MISMATCH,
    ),
)
async def test_expected_authority_refusal_skips_fallback_without_internal_diagnostic(
    monkeypatch: pytest.MonkeyPatch, reason: CoordinationErrorCode
) -> None:
    admitted_project = "prj_00000000-0000-4000-8000-000000000002"

    async def live_members(
        task_id: str, *, project: str, expected_generation: int
    ) -> tuple[str, ...]:
        assert task_id == _REQUESTER
        assert expected_generation == 1
        if project == _PROJECT:
            raise CoordinationError(reason)
        assert project == admitted_project
        return (_COUNTERPART,)

    fallback = AsyncMock(side_effect=AssertionError("authority refusal must not use fallback"))
    app = SimpleNamespace(
        project_application=SimpleNamespace(
            catalog=SimpleNamespace(
                list_task_project_ids=AsyncMock(return_value=(_PROJECT, admitted_project)),
                project_state=AsyncMock(return_value=SimpleNamespace(membership_generation=1)),
            ),
            live_admitted_member_task_ids=live_members,
            coordination_advice_for=fallback,
        )
    )
    diagnostics = Mock()
    monkeypatch.setattr(check, "record_unexpected_exception_without_raising", diagnostics)
    monkeypatch.setattr(check, "_duplicate_project_advisory_task_ids", AsyncMock(return_value=()))
    notes_reader = cast(
        Callable[[object, str, tuple[object, ...]], Awaitable[tuple[object, ...]]],
        getattr(check, "_current_project_advisory_notes"),
    )

    notes = await notes_reader(app, _REQUESTER, ())

    assert len(notes) == 1
    assert getattr(notes[0], "project_id") == admitted_project
    fallback.assert_not_awaited()
    diagnostics.assert_not_called()


@pytest.mark.anyio
@pytest.mark.parametrize("invalid_contract", (False, True))
async def test_unexpected_advisory_failure_still_records_diagnostic(
    monkeypatch: pytest.MonkeyPatch, invalid_contract: bool
) -> None:
    failure = (
        CoordinationError(CoordinationErrorCode.INVALID)
        if invalid_contract
        else RuntimeError("synthetic projection failure")
    )
    app = SimpleNamespace(
        project_application=SimpleNamespace(
            catalog=SimpleNamespace(
                list_task_project_ids=AsyncMock(return_value=(_PROJECT,)),
                project_state=AsyncMock(return_value=SimpleNamespace(membership_generation=1)),
            ),
            live_admitted_member_task_ids=AsyncMock(side_effect=failure),
        )
    )
    diagnostics = Mock()
    monkeypatch.setattr(check, "record_unexpected_exception_without_raising", diagnostics)
    notes_reader = cast(
        Callable[[object, str, tuple[object, ...]], Awaitable[tuple[object, ...]]],
        getattr(check, "_current_project_advisory_notes"),
    )

    assert await notes_reader(app, _REQUESTER, ()) == ()
    diagnostics.assert_called_once_with(
        failure, component="check", operation="project_advisory_read"
    )
