"""Projecting the recovery view for a check stranded mid-dispatch of its AI-powered review.

The 2026-07-30 dogfood run left a check pending in ``SEMANTIC_WAIT`` and every subsequent
``status(view=operation)`` failed with an ``AttributeError``, recorded by the daemon as
``read_projection_failed``. Nothing reproduced it because the projection sweep points
``view=operation`` at a *completed publish* — the one operation kind whose recovery page carries
nested accepted events — and the application-level status tests seed ``CheckPhase.RESERVED`` with
no AI-powered review job. Neither is the shape that broke: a *pending* operation projects a page where
every optional field is absent.
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
from finishup.application.status import StatusInternalResult
from finishup.domain.values import format_rfc3339_millis
from finishup.ports.control import ControlMethod
from finishup.ports.ledger import (
    CheckPhase,
    OperationKind,
    OperationRecord,
    OperationState,
    SemanticJobRecord,
    SemanticProgressRecord,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import SemanticProgressPhase, SemanticReason, StatusRequest

pytestmark = pytest.mark.anyio


def _stranded_check(writer_id: str, operation_id: str, task_id: str) -> OperationRecord:
    """A check parked mid-dispatch: pending, SEMANTIC_WAIT, local result already durable."""

    resume = ObjectRef(
        "obj_00000000-0000-4000-8000-0000000000cc",
        1,
        "hmac-sha256:" + "a" * 64,
        "sha256:" + "b" * 64,
        "yoetz-object/1",
        "bmk-1",
        ObjectMetadata(
            ObjectKind.DETERMINISTIC_RESULT,
            "application/vnd.yoetz.deterministic-result+json",
            task_id,
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )
    return OperationRecord(
        writer_id,
        operation_id,
        OperationKind.CHECK,
        "sha256:" + "c" * 64,
        OperationState.PENDING,
        CheckPhase.SEMANTIC_WAIT,
        "owner-generation-1",
        "lease-owner-1",
        1,
        datetime(2030, 1, 1, tzinfo=UTC),
        resume,
        None,
        None,
        None,
        None,
        None,
    )


async def test_pending_check_operation_page_projects_to_the_client() -> None:
    """A caller who got OPERATION_PENDING must be able to read back what is pending.

    This drives the daemon's exact post-commit projection, not just ``execute_status``: the
    production failure was recorded against ``component=service.daemon``, so the application layer
    alone would have reported success while the caller still received an error.
    """

    workflow = await run_projection_workflow()
    app = workflow.app
    started = workflow.case("start").internal
    session_id = cast(str, getattr(started, "session_id"))
    writer_id = cast(str, getattr(started, "writer_id"))
    task_id = cast(str, getattr(started, "task_id"))

    operation_id = "req_00000000-0000-4000-8000-0000000009a1"
    status_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", 9102)),
        "session_id": session_id,
        "writer_id": writer_id,
        "view": "operation",
        "limit": "10",
        "filter": {"operation_request_id": operation_id},
    }
    _seed_operation(app, session_id, writer_id, operation_id, task_id)

    internal = await app.status(StatusRequest.model_validate(status_body))
    assert type(internal) is StatusInternalResult

    projected = await project_case(
        app,
        ProjectionCase("status/operation-pending", ControlMethod.STATUS, status_body, internal),
        9100,
    )
    page = cast(dict[str, JsonValue], projected["page"])
    assert page["found"] is True
    assert page["state"] == "pending"
    assert page["operation_kind"] == "check"


def _seed_operation(
    app: object, session_id: str, writer_id: str, operation_id: str, task_id: str
) -> None:
    """Inject the stranded record directly; paying for a real stranded check is not the point."""

    runtime = getattr(app, "runtime")
    resources = getattr(runtime, "resources")
    ledger, _objects = next(iter(resources.values()))
    ledger._state.operations[(writer_id, operation_id)] = (  # pyright: ignore[reportPrivateUsage]
        _stranded_check(writer_id, operation_id, task_id),
        None,
    )


_CONTENT_SENTINEL = "SENTINEL-PROMPT-REASONING-TOKEN-7f3a"


def _seed_semantic_progress(
    app: object,
    writer_id: str,
    operation_id: str,
    task_id: str,
    *,
    terminal: bool,
) -> tuple[datetime, datetime]:
    """Seed one leased or failed review job and its durable structural progress row."""

    runtime = getattr(app, "runtime")
    resources = getattr(runtime, "resources")
    ledger, _objects = next(iter(resources.values()))
    now = cast(datetime, getattr(app, "clock").now_utc())
    queued_at = now - timedelta(seconds=42)
    deadline_at = queued_at + timedelta(seconds=900)
    job_id = protocol_id("job_", 9110)
    attempt_id = protocol_id("att_", 9111)
    # The case object is where prompt-derived content would live; progress must never read it.
    case_ref = ObjectRef(
        "obj_00000000-0000-4000-8000-0000000009c1",
        len(_CONTENT_SENTINEL),
        "hmac-sha256:" + "d" * 64,
        "sha256:" + "e" * 64,
        "yoetz-object/1",
        "bmk-1",
        ObjectMetadata(
            ObjectKind.SEMANTIC_CASE,
            "application/json",
            task_id,
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )
    if terminal:
        job = SemanticJobRecord(
            job_id,
            writer_id,
            operation_id,
            "sha256:" + "f" * 64,
            case_ref,
            "failed",
            1,
            None,
            None,
            None,
            None,
            None,
            None,
            SemanticReason.PROVIDER_TIMEOUT,
            now - timedelta(seconds=2),
        )
    else:
        job = SemanticJobRecord(
            job_id,
            writer_id,
            operation_id,
            "sha256:" + "f" * 64,
            case_ref,
            "leased",
            1,
            attempt_id,
            None,
            "lease-owner-1",
            1,
            datetime(2030, 1, 1, tzinfo=UTC),
            None,
            None,
            None,
        )
    ledger._state.jobs[job_id] = job  # pyright: ignore[reportPrivateUsage]
    ledger._state.semantic_progress[job_id] = SemanticProgressRecord(  # pyright: ignore[reportPrivateUsage]
        job_id,
        1,
        SemanticProgressPhase.PROVIDER_SAMPLING,
        queued_at + timedelta(seconds=5),
        queued_at,
        deadline_at,
    )
    return queued_at, deadline_at


@pytest.mark.parametrize("terminal", [False, True], ids=["sampling", "terminal"])
async def test_semantic_progress_agrees_across_json_text_mcp_and_tui(terminal: bool) -> None:
    """Issue #571 A2: every rendering of one operation page states the same progress facts."""

    from finishup.cli.render import render_human_status
    from finishup.mcp.summaries import render_safe_compact_summary
    from finishup.protocol.canonical import canonical_encode
    from finishup.protocol.models import StatusResultModel, StatusSuccessModel
    from finishup.tui.app import _progress_lines  # pyright: ignore[reportPrivateUsage]

    workflow = await run_projection_workflow()
    app = workflow.app
    started = workflow.case("start").internal
    session_id = cast(str, getattr(started, "session_id"))
    writer_id = cast(str, getattr(started, "writer_id"))
    task_id = cast(str, getattr(started, "task_id"))
    operation_id = "req_00000000-0000-4000-8000-0000000009b1"
    _seed_operation(app, session_id, writer_id, operation_id, task_id)
    queued_at, deadline_at = _seed_semantic_progress(
        app, writer_id, operation_id, task_id, terminal=terminal
    )
    status_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", 9112 + int(terminal))),
        "session_id": session_id,
        "writer_id": writer_id,
        "view": "operation",
        "limit": "1",
        "filter": {"operation_request_id": operation_id},
    }

    internal = await app.status(StatusRequest.model_validate(status_body))
    projected = await project_case(
        app,
        ProjectionCase("status/operation-progress", ControlMethod.STATUS, status_body, internal),
        9120 + int(terminal),
    )

    # JSON (the MCP structured result and CLI --json) carries only the closed field set.
    page = cast(dict[str, JsonValue], projected["page"])
    progress = cast(dict[str, JsonValue], page["semantic_progress"])
    common = {
        "attempt_ordinal",
        "condition",
        "deadline_at",
        "elapsed_ms",
        "observed_at",
        "phase",
        "phase_entered_at",
        "queued_at",
    }
    now = getattr(app, "clock").now_utc()
    assert progress["queued_at"] == format_rfc3339_millis(queued_at)
    assert progress["deadline_at"] == format_rfc3339_millis(deadline_at)
    assert progress["attempt_ordinal"] == "1"
    if terminal:
        assert set(progress) == common | {"terminal_outcome", "terminal_reason"}
        assert progress["phase"] == "terminal"
        assert progress["condition"] == "terminal"
        assert progress["terminal_outcome"] == "failed"
        assert progress["terminal_reason"] == "provider_timeout"
        assert progress["elapsed_ms"] == "40000"
    else:
        assert set(progress) == common | {"remaining_ms"}
        assert progress["phase"] == "provider_sampling"
        assert progress["condition"] == "active"
        assert progress["elapsed_ms"] == str(int((now - queued_at).total_seconds() * 1000))
        assert progress["remaining_ms"] == str(int((deadline_at - now).total_seconds() * 1000))

    # Text (CLI) and TUI render the same service model; MCP text names the same tokens.
    success = StatusResultModel.model_validate(projected).root
    assert isinstance(success, StatusSuccessModel)
    text = render_human_status(success)
    tui_lines = _progress_lines(text.splitlines())
    summary = render_safe_compact_summary(projected)
    elapsed_seconds = int(cast(str, progress["elapsed_ms"])) // 1000
    assert tui_lines and all(line in text.splitlines() for line in tui_lines)
    assert f"Semantic review phase: {progress['phase']} (attempt 1, {progress['condition']})" in (
        tui_lines
    )
    assert f"semantic phase: {progress['phase']}; attempt: 1;" in summary
    assert f"condition: {progress['condition']}; elapsed ms: {progress['elapsed_ms']};" in summary
    if terminal:
        assert (
            f"Semantic review outcome: failed (provider_timeout); elapsed {elapsed_seconds}s"
            in (tui_lines)
        )
        assert "outcome: failed (provider_timeout);" in summary
    else:
        remaining_seconds = int(cast(str, progress["remaining_ms"])) // 1000
        assert (
            f"Semantic review elapsed: {elapsed_seconds}s; remaining {remaining_seconds}s; "
            f"deadline {progress['deadline_at']}"
        ) in tui_lines
        assert f"remaining ms: {progress['remaining_ms']};" in summary

    # No rendering carries case content, account identity, or anything but structure.
    for rendered in (canonical_encode(cast(JsonValue, projected)).decode(), text, summary):
        assert _CONTENT_SENTINEL not in rendered
        assert "chatgpt" not in rendered.lower()
