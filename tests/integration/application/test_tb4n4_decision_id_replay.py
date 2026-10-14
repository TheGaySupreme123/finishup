"""tb4n4 (issue #1049): an ignored ``decision_id`` never changes what is recorded or replayed.

Ten tb4n4 attempts sent ``decision_recorded`` with a ``decision_id`` and were refused. The key is
now accepted and ignored. This drives the real publish operation: the decision is recorded without
the key, and a retry of the same ``request_id`` without it is a replay of the same request (one
request digest), never a ``REQUEST_IDENTITY_CONFLICT``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import pytest

from builders.projection_workflow import (
    build_projection_application,
    frontier_json,
    request_base,
)
from builders.start_application import protocol_id, start_request
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.domain.events import DecisionRecordedPayload, LedgerRecord, encode_payload
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import PublishWorkRequest

pytestmark = pytest.mark.anyio


def _decision(*, with_id: bool) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = {
        "statement": "Keep the existing wire format.",
        "rationale": "The client already parses it.",
        "authority": "codex",
    }
    if with_id:
        payload["decision_id"] = "dec-1"
    return payload


async def test_a_decision_id_is_ignored_on_record_and_on_replay() -> None:
    seed = 10490
    app, _policy = await build_projection_application(seed=seed)
    started = await app.start(start_request(seed, title="Decision ids"))

    def request(*, with_id: bool) -> PublishWorkRequest:
        return PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 1)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(started.frontier),
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 2),
                        "schema": {"name": "decision_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-10-12T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": _decision(with_id=with_id),
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )

    first = await app.publish_work(request(with_id=True))
    assert isinstance(first, PublishWorkInternalResult)
    assert first.outcome == "accepted"
    retry = await app.publish_work(request(with_id=False))
    assert isinstance(retry, PublishWorkInternalResult)
    assert retry.outcome == "replayed"
    assert retry.request_digest == first.request_digest
    assert retry.accepted_events == first.accepted_events
    again = await app.publish_work(request(with_id=True))
    assert isinstance(again, PublishWorkInternalResult)
    assert again.outcome == "replayed"
    assert again.request_digest == first.request_digest

    ledger, _objects = next(iter(cast(Any, app.runtime).resources.values()))
    records = cast(tuple[LedgerRecord, ...], tuple(ledger._state.records))
    (decision,) = [row for row in records if row.schema.name == "decision_recorded"]
    assert type(decision.payload) is DecisionRecordedPayload
    assert "decision_id" not in cast(Mapping[str, object], encode_payload(decision.payload))
