"""``status view=operation`` tells a refused or in-flight check admission from an unknown id.

Issue #838: two native deterministic checks answered ``OPERATION_PENDING`` while the recovery
page read ``found=false,state=absent``, which is also exactly what a never-submitted request
reads. The page now carries a structural ``admission`` stage for the exact (writer, request) key
while the service holds a live acquisition reservation or a recent pre-admission refusal, and
omits it otherwise. It never names payloads, other requests, or other writers.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from builders.projection_workflow import (
    ProjectionCase,
    project_case,
    request_base,
    run_projection_workflow,
)
from builders.start_application import protocol_id
from finishup.adapters.memory.ledger import note_check_admission_refusal
from finishup.application.status import Application as StatusApplication
from finishup.application.status import StatusInternalResult, execute_status
from finishup.cli.render import render_check_admission_lines
from finishup.ports.control import ControlMethod
from finishup.ports.ledger import CheckAdmissionStage
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import StatusOperationPageModel, StatusRequest
from integration.application.test_status_operation_view import (
    _publish_composition,  # pyright: ignore[reportPrivateUsage]
    _status_operation_request,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
_REQUEST = "req_00000000-0000-4000-8000-0000000009e1"


class _Reservation:
    """Duck-typed live acquisition reservation, as either ledger installs one."""

    def __init__(self, session_id: str, expires_at: datetime) -> None:
        self.session_id = session_id
        self.expires_at = expires_at


async def test_absent_operation_page_projects_a_refused_admission() -> None:
    app, _objects, seed, ledger = _publish_composition()
    state = ledger._state  # pyright: ignore[reportPrivateUsage]
    key = (seed.writer_id, _REQUEST)
    note_check_admission_refusal(
        state, key, CheckAdmissionStage.CAPTURE_HANDOFF_PENDING, _NOW - timedelta(seconds=14)
    )
    note_check_admission_refusal(state, key, CheckAdmissionStage.CAPTURE_HANDOFF_PENDING, _NOW)

    status = await execute_status(
        cast(StatusApplication, app),
        _status_operation_request(
            session_id=seed.session_id,
            writer_id=seed.writer_id,
            operation_request_id=_REQUEST,
            request_tail=8381,
        ),
    )
    page = status.page
    assert type(page) is StatusOperationPageModel
    assert page.found is False
    assert page.state == "absent"
    assert page.operation_kind is None
    admission = page.admission
    assert admission is not None
    assert admission.stage == "capture_handoff_pending"
    assert admission.refusal_count == "2"
    assert admission.retry_after_ms == "5000"
    assert admission.first_observed_at == "2026-07-19T11:59:46.000Z"
    assert admission.last_observed_at == "2026-07-19T12:00:00.000Z"
    assert admission.elapsed_ms == "14000"
    assert render_check_admission_lines(admission)[0] == (
        "Check admission: capture_handoff_pending (refusals 2); elapsed 14s"
    )

    # Another writer on the same task learns nothing about this exact key.
    other = await execute_status(
        cast(StatusApplication, app),
        _status_operation_request(
            session_id=seed.session_id,
            writer_id=seed.writer_id,
            operation_request_id="req_00000000-0000-4000-8000-0000000009e2",
            request_tail=8382,
        ),
    )
    assert cast(StatusOperationPageModel, other.page).admission is None


async def test_live_acquisition_reads_as_acquiring_without_a_refusal() -> None:
    app, _objects, seed, ledger = _publish_composition()
    state = ledger._state  # pyright: ignore[reportPrivateUsage]
    reservations = cast(dict[tuple[str, str], object], state.check_reservations)
    reservations[(seed.writer_id, _REQUEST)] = _Reservation(
        seed.session_id, _NOW + timedelta(seconds=58)
    )

    status = await execute_status(
        cast(StatusApplication, app),
        _status_operation_request(
            session_id=seed.session_id,
            writer_id=seed.writer_id,
            operation_request_id=_REQUEST,
            request_tail=8383,
        ),
    )
    admission = cast(StatusOperationPageModel, status.page).admission
    assert admission is not None
    assert admission.stage == "acquiring"
    assert admission.refusal_count == "0"
    assert admission.elapsed_ms == "2000"
    assert admission.retry_after_ms == "2000"


async def test_absent_operation_page_omits_admission_when_nothing_is_known() -> None:
    app, _objects, seed, _ledger = _publish_composition()
    status = await execute_status(
        cast(StatusApplication, app),
        _status_operation_request(
            session_id=seed.session_id,
            writer_id=seed.writer_id,
            operation_request_id=_REQUEST,
            request_tail=8384,
        ),
    )
    page = cast(StatusOperationPageModel, status.page)
    assert page.state == "absent"
    assert page.admission is None
    assert "admission" not in cast(dict[str, JsonValue], status.as_json()["page"])


async def test_admission_read_failure_never_fails_operation_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _objects, seed, ledger = _publish_composition()

    async def broken(writer_id: str, operation_id: str) -> object:
        del writer_id, operation_id
        raise RuntimeError("admission_journal_unreadable")

    monkeypatch.setattr(ledger, "lookup_check_admission", broken)
    status = await execute_status(
        cast(StatusApplication, app),
        _status_operation_request(
            session_id=seed.session_id,
            writer_id=seed.writer_id,
            operation_request_id=_REQUEST,
            request_tail=8385,
        ),
    )
    page = cast(StatusOperationPageModel, status.page)
    assert page.state == "absent"
    assert page.admission is None


async def test_admission_page_projects_through_the_daemon_to_the_client() -> None:
    """The exact post-commit projection a caller receives carries the admission stage."""

    workflow = await run_projection_workflow()
    app = workflow.app
    started = workflow.case("start").internal
    session_id = cast(str, getattr(started, "session_id"))
    writer_id = cast(str, getattr(started, "writer_id"))
    runtime = getattr(app, "runtime")
    resources = getattr(runtime, "resources")
    ledger, _objects = next(iter(resources.values()))
    clock_now = cast(datetime, getattr(app, "clock").now_utc())
    note_check_admission_refusal(
        ledger._state,  # pyright: ignore[reportPrivateUsage]
        (writer_id, _REQUEST),
        CheckAdmissionStage.ACQUISITION_CONTENDED,
        clock_now,
    )
    status_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", 8386)),
        "session_id": session_id,
        "writer_id": writer_id,
        "view": "operation",
        "limit": "1",
        "filter": {"operation_request_id": _REQUEST},
    }
    internal = await app.status(StatusRequest.model_validate(status_body))
    assert type(internal) is StatusInternalResult
    projected = await project_case(
        app,
        ProjectionCase("status/operation-admission", ControlMethod.STATUS, status_body, internal),
        8386,
    )
    page = cast(dict[str, JsonValue], projected["page"])
    assert page["found"] is False
    assert page["state"] == "absent"
    admission = cast(dict[str, JsonValue], page["admission"])
    assert admission["stage"] == "acquisition_contended"
    assert admission["refusal_count"] == "1"
    assert admission["retry_after_ms"] == "1000"
    assert set(admission) == {
        "elapsed_ms",
        "first_observed_at",
        "last_observed_at",
        "observed_at",
        "refusal_count",
        "retry_after_ms",
        "stage",
    }
