"""Manifest admission reads task text, preserves failed cases, and keeps retry identity."""

from __future__ import annotations

from typing import Any, cast

import pytest

from builders.projection_workflow import build_projection_application, request_base
from builders.start_application import protocol_id, start_request
from finishup.application.publish_work import Application, execute_publish_work
from finishup.domain.events import LedgerRecord, ResultRecordedPayload
from finishup.domain.values import result_id
from finishup.kernel.reducers import replay
from finishup.ports.runtime import TaskRuntime
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import PublishWorkDryRunModel, PublishWorkRequest, StartRequest

pytestmark = pytest.mark.anyio


async def _started(seed: int) -> tuple[Any, Any]:
    app, _policy = await build_projection_application(seed=seed)
    request = start_request(seed).model_dump(mode="json", by_alias=True, exclude_none=True)
    request["task_statement"] = "Keep known failing cases visible. Re-run the shipped version."
    return app, await app.start(StartRequest.model_validate(request))


def _result(seed: int, quote: str = "Keep known failing cases visible") -> dict[str, JsonValue]:
    return {
        "schema": {"name": "result_recorded", "version": "1.1.0"},
        "payload": {
            "result_id": protocol_id("res_", seed),
            "action_id": protocol_id("act_", seed),
            "outcome": "success",
            "verification": {
                "criterion_quote": quote,
                "data_source": "independent",
                "cases": 5,
                "failing": 1,
                "worst": "error 0.1",
            },
        },
    }


def _request(
    started: Any, seed: int, drafts: list[dict[str, JsonValue]], **extra: JsonValue
) -> Any:
    return PublishWorkRequest.model_validate(
        {
            **request_base(protocol_id("req_", seed)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "event_drafts": drafts,
            **extra,
        }
    )


def _records(app: Any) -> tuple[LedgerRecord, ...]:
    ledger, _objects = next(iter(app.runtime.resources.values()))
    return cast(tuple[LedgerRecord, ...], tuple(ledger._state.records))


async def test_manifest_retained_by_replay_and_retry_after_task_amendment() -> None:
    app, started = await _started(11701)
    request = _request(started, 11702, [_result(11702)])
    accepted = await app.publish_work(request)
    projection = replay(_records(app))
    row = projection.results[result_id(protocol_id("res_", 11702))]
    assert isinstance(row.payload, ResultRecordedPayload)
    assert row.payload.verification is not None
    assert row.payload.verification.failing == 1
    amended: dict[str, JsonValue] = {
        "schema": {"name": "plan_published", "version": "1.1.0"},
        "payload": {
            "plan_version": 1,
            "summary": "Amended task",
            "obligation_refs": [],
            "task_statement": "A different current task.",
        },
    }
    await app.publish_work(_request(started, 11703, [amended]))
    before = len(_records(app))
    recovered = await app.publish_work(request)
    assert recovered.result_frontier == accepted.result_frontier
    assert len(_records(app)) == before


@pytest.mark.parametrize("dry_run", [False, True])
async def test_non_task_quote_rejected_without_append_or_echo(dry_run: bool) -> None:
    app, started = await _started(11710 + int(dry_run))
    quote = "PRIVATE invented condition"
    before = _records(app)
    with pytest.raises(PublicOperationError) as caught:
        await app.publish_work(_request(started, 11712, [_result(11712, quote)], dry_run=dry_run))
    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    assert caught.value.safe_details["reason_code"] == "verification_criterion_not_in_task"
    assert quote not in str(caught.value)
    assert _records(app) == before


async def test_quote_checked_at_its_position_in_dry_run_batch() -> None:
    app, started = await _started(11720)
    plan: dict[str, JsonValue] = {
        "schema": {"name": "plan_published", "version": "1.1.0"},
        "payload": {
            "plan_version": 1,
            "summary": "New task",
            "obligation_refs": [],
            "task_statement": "Use the amended condition exactly.",
        },
    }
    result = _result(11721, "amended condition")
    before = _records(app)
    preview = await app.publish_work(_request(started, 11721, [plan, result], dry_run=True))
    assert isinstance(preview.root, PublishWorkDryRunModel)
    assert _records(app) == before
    with pytest.raises(PublicOperationError):
        await app.publish_work(_request(started, 11722, [result, plan], dry_run=True))


@pytest.mark.parametrize("dry_run", [False, True])
async def test_explicit_null_frontier_never_bypasses_manifest_guard(dry_run: bool) -> None:
    app, started = await _started(11730 + int(dry_run))
    before = _records(app)
    with pytest.raises(PublicOperationError) as caught:
        await app.publish_work(
            _request(started, 11732, [_result(11732)], expected_frontier=None, dry_run=dry_run)
        )
    assert caught.value.safe_details["reason_code"] == "expected_frontier_required"
    assert _records(app) == before


async def test_task_revision_after_quote_validation_conflicts_before_result_append() -> None:
    app, started = await _started(11740)
    plan: dict[str, JsonValue] = {
        "schema": {"name": "plan_published", "version": "1.1.0"},
        "payload": {
            "plan_version": 1,
            "summary": "Concurrent revision",
            "obligation_refs": [],
            "task_statement": "Use a different condition now.",
        },
    }

    async def revise(_runtime: TaskRuntime) -> None:
        await app.publish_work(_request(started, 11741, [plan]))

    # The capture boundary is after quote admission but before staging/append. A different
    # cooperative writer's task revision there must lose the result's CAS, without sleeps.
    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(
            cast(Application, app), _request(started, 11742, [_result(11742)]), input_capture=revise
        )
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
    assert all(record.schema.name != "result_recorded" for record in _records(app))
