"""A card-only agent never reads status for a frontier (tb4n5, issue #1048, ADR-022/ADR-047).

tb4n5 shipped "a prior status read is optional" while three surfaces still named status as the
frontier source: six first-plan batches sent ``expected_frontier: null`` right after a status read,
and 85 of 87 later state-sensitive publishes read status first only to copy its head. The guard
itself stays (ADR-022): this drives the sequence the guidance now teaches - the first plan with the
frontier ``start`` returned, every later write with the previous write's ``result_frontier`` -
across hook observations that land in between, with no status read, and keeps a cooperative write
in between a conflict.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import Any, cast

import pytest

from builders.projection_workflow import build_projection_application, frontier_json, request_base
from builders.start_application import protocol_id, start_request
from yoetz.application.observation_materialize import observation_author
from yoetz.application.service import Application
from yoetz.application.start import StartInternalResult
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventDraft,
    EventPayload,
    EventSchema,
    ResultOutcome,
    ResultRecordedPayload,
    encode_payload,
    media_type_for,
)
from yoetz.domain.values import Frontier, action_id, event_id, result_id, timestamp_from_datetime
from yoetz.kernel.observed_failures import observed_action_description
from yoetz.ports.ledger import AppendCommand, AppendEntry, OperationKind
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from yoetz.protocol.canonical import canonical_encode
from yoetz.protocol.coverage import PublicationChannel, coverage_for_channel
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import PublishWorkRequest
from yoetz.protocol.recovery import RECOVERY_DIRECTIVES

pytestmark = pytest.mark.anyio

_OBLIGATION = protocol_id("obl_", 8101)
_ACTION = protocol_id("act_", 8102)
_RESULT = protocol_id("res_", 8103)
_DIGEST = "sha256:" + "5" * 64


class _Drafts:
    def __init__(self, start: int) -> None:
        self.number = start

    def __call__(self, name: str, payload: dict[str, Any], version: str = "1.0.0") -> Any:
        self.number += 1
        return {
            "event_id": protocol_id("evt_", self.number),
            "schema": {"name": name, "version": version},
            "occurred_at": "2026-10-13T12:00:00.000Z",
            "causal_parents": [],
            "artifact_refs": [],
            "evidence_refs": [],
            "payload": payload,
        }


def _obligation(status: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "obligation_id": _OBLIGATION,
        "description": "The parser accepts the documented grammar",
        "evidence_expectation": "A recorded test run",
        "status": status,
    }
    if status == "resolved":
        payload["resolution_evidence_refs"] = [_RESULT]
    return payload


def _request(
    started: StartInternalResult, frontier: Any, drafts: list[Any], seed: int
) -> PublishWorkRequest:
    return PublishWorkRequest.model_validate(
        {
            **request_base(protocol_id("req_", seed)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": frontier,
            "event_drafts": drafts,
        }
    )


async def _publish(
    app: Application, started: StartInternalResult, frontier: Any, drafts: list[Any], seed: int
) -> Frontier:
    result = await app.publish_work(_request(started, frontier, drafts, seed))
    return cast(Frontier, result.result_frontier)


async def _append_observed(
    app: Application, started: StartInternalResult, *, seed: int, after: int
) -> Frontier:
    """A hook-observed command and its result, service-stamped like the observation path."""

    runtime = cast(Any, app.runtime)
    ledger, objects = next(iter(runtime.resources.values()))
    now = app.clock.now_utc()
    items: tuple[tuple[str, EventPayload], ...] = (
        (
            "action_recorded",
            ActionRecordedPayload(
                action_id(protocol_id("act_", seed)),
                ActionKind.COMMAND,
                observed_action_description("Observed command via Codex hook", "Bash", None),
                command="omitted:structural",
            ),
        ),
        (
            "result_recorded",
            ResultRecordedPayload(
                result_id(protocol_id("res_", seed + 1)),
                action_id(protocol_id("act_", seed)),
                ResultOutcome.SUCCESS,
                exit_status=0,
                summary="Observed result status=success",
            ),
        ),
    )
    entries: list[AppendEntry] = []
    for offset, (schema_name, payload) in enumerate(items):
        encoded = canonical_encode(encode_payload(payload))
        metadata = ObjectMetadata(
            ObjectKind.EVENT_PAYLOAD, media_type_for(schema_name), started.task_id, now
        )
        staged = await objects.stage(
            ObjectSource(data=encoded, declared_size=len(encoded)), metadata
        )
        payload_ref = await objects.finalize(staged)
        entries.append(
            AppendEntry(
                EventDraft(
                    event_id(protocol_id("evt_", seed + 10 + offset)),
                    EventSchema(schema_name, "1.0.0"),
                    timestamp_from_datetime(now),
                    (),
                    payload,
                    (),
                    (),
                ),
                observation_author(),
                payload_ref,
                payload_ref.commitment,
                metadata.media_type,
                payload_ref.plaintext_size,
                PublicationChannel.HOOK_OBSERVED,
                coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
                "projected",
            )
        )
    appended = await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", seed + 90),
            OperationKind.PUBLISH_WORK,
            _DIGEST,
            after,
            tuple(entries),
            None,
        )
    )
    return cast(Frontier, appended.result_frontier)


async def test_first_plan_uses_the_start_frontier_and_later_writes_the_returned_one() -> None:
    app, _policy = await build_projection_application(seed=8000)
    started = await app.start(start_request(8000, title="Parser grammar"))
    held = started.frontier
    draft = _Drafts(8200)

    # Hooks observe a command between start and the first plan: the start frontier still holds.
    observed = await _append_observed(app, started, seed=8300, after=int(held.sequence))
    assert observed.sequence > int(held.sequence)
    first = await _publish(
        app,
        started,
        frontier_json(held),
        [
            draft(
                "plan_published",
                {"plan_version": 1, "summary": "Fix the parser", "obligation_refs": [_OBLIGATION]},
            ),
            draft("obligation_published", _obligation("open")),
        ],
        8400,
    )
    # Appended at the real head, after the observation suffix.
    assert first.sequence == observed.sequence + 2

    # More hook observations land; the frontier the plan write returned still holds.
    observed = await _append_observed(app, started, seed=8500, after=first.sequence)
    second = await _publish(
        app,
        started,
        frontier_json(first),
        [
            draft(
                "action_recorded",
                {
                    "action_id": _ACTION,
                    "action_kind": "edit",
                    "description": "Rewrote the grammar rule",
                    "obligation_refs": [_OBLIGATION],
                },
            ),
            draft(
                "result_recorded",
                {"result_id": _RESULT, "action_id": _ACTION, "outcome": "success"},
            ),
            draft("obligation_published", _obligation("resolved")),
        ],
        8600,
    )
    assert second.sequence == observed.sequence + 3

    # A cooperative write in between is not observation-authored: the older frontier conflicts.
    with pytest.raises(PublicOperationError) as caught:
        await _publish(
            app,
            started,
            frontier_json(first),
            [
                draft(
                    "decision_recorded",
                    {
                        "statement": "Keep the existing tokenizer.",
                        "rationale": "The grammar fix does not need a new tokenizer.",
                        "authority": "harness:test",
                    },
                )
            ],
            8700,
        )
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
    assert caught.value.safe_details.get("reason_code") == "frontier_changed"
    assert caught.value.safe_details.get("continuation") == "frontier_refresh_required"


async def test_a_null_frontier_names_the_held_frontier_not_a_status_read() -> None:
    app, _policy = await build_projection_application(seed=8800)
    started = await app.start(start_request(8800, title="Parser grammar"))
    draft = _Drafts(8900)
    plan = [
        draft(
            "plan_published",
            {"plan_version": 1, "summary": "Fix the parser", "obligation_refs": [_OBLIGATION]},
        ),
        draft("obligation_published", _obligation("open")),
    ]

    with pytest.raises(PublicOperationError) as caught:
        await app.publish_work(_request(started, None, plan, 8950))

    error = caught.value
    assert error.code is PublicErrorCode.EVENT_INVALID
    assert error.retryable is True
    assert error.safe_details.get("reason_code") == "expected_frontier_required"
    assert error.safe_details.get("continuation") == "frontier_held_required"
    for text in (error.message, RECOVERY_DIRECTIVES["frontier_held_required"].directive):
        assert "start" in text
        assert "result_frontier" in text
        assert "same request_id" in text
        assert "Call status to read" not in text
        assert "Read status for the current frontier" not in text

    # The same body with the start frontier is accepted under the same request id.
    accepted = await _publish(app, started, frontier_json(started.frontier), plan, 8950)
    assert accepted.sequence == int(started.frontier.sequence) + 2
