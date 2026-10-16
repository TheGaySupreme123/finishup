"""Issue #1084: the service fills publish boilerplate, names what it filled, and stays idempotent.

These drive the real publish operation through the ready application. Each derived value has
three cases: absent -> derived and named in ``server_filled``; present -> honored byte for byte;
present but inconsistent -> the earlier typed rejection.
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
from finishup.domain.events import LedgerRecord
from finishup.ports.ledger import OperationKind
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import (
    PublishWorkDryRunModel,
    PublishWorkRequest,
    PublishWorkResultModel,
    PublishWorkServerFilledModel,
)
from finishup.protocol.publish_boilerplate import (
    derive_publish_request_id,
    mint_draft_event_id,
)

pytestmark = pytest.mark.anyio

_ALL_FILLED = ("artifact_refs", "causal_parents", "event_id", "evidence_refs", "occurred_at")


def _sparse_base() -> dict[str, JsonValue]:
    base = dict(request_base(protocol_id("req_", 1)))
    del base["request_id"]
    return base


def _action(seed: int) -> dict[str, JsonValue]:
    return {
        "schema": {"name": "action_recorded", "version": "1.0.0"},
        "payload": {
            "action_id": protocol_id("act_", seed),
            "action_kind": "command",
            "command": "pytest -q",
            "description": "Ran the unit tests.",
        },
    }


def _evidence(seed: int) -> dict[str, JsonValue]:
    return {
        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
        "payload": {
            "evidence_id": protocol_id("evd_", seed),
            "evidence_kind": "test_result",
            "strength": "metadata_only",
            "description": "12 passed",
            "observed_at": "2026-10-16T12:00:00.000Z",
        },
    }


def _result(seed: int, *, evidence: tuple[str, ...]) -> dict[str, JsonValue]:
    return {
        "schema": {"name": "result_recorded", "version": "1.0.0"},
        "payload": {
            "result_id": protocol_id("res_", seed),
            "action_id": protocol_id("act_", seed),
            "outcome": "success",
            "summary": "12 passed",
            "evidence_refs": list(evidence),
        },
    }


def _records(app: object) -> tuple[LedgerRecord, ...]:
    ledger, _objects = next(iter(cast(Any, app).runtime.resources.values()))
    return cast(tuple[LedgerRecord, ...], tuple(ledger._state.records))


async def _started(seed: int) -> tuple[Any, Any]:
    app, _policy = await build_projection_application(seed=seed)
    started = await app.start(start_request(seed, title="Server-filled publish"))
    return app, started


def _sparse_request(started: Any, drafts: list[dict[str, JsonValue]], **extra: JsonValue) -> Any:
    return PublishWorkRequest.model_validate(
        {
            **_sparse_base(),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "event_drafts": drafts,
            **extra,
        }
    )


async def test_a_sparse_batch_is_completed_named_and_recorded() -> None:
    app, started = await _started(10840)
    evidence_a, evidence_b = sorted(
        (protocol_id("evd_", 10842), protocol_id("evd_", 10841)), key=str.encode
    )
    request = _sparse_request(
        started,
        [
            _action(10841),
            _evidence(10841),
            _evidence(10842),
            # Unsorted, duplicated payload refs: canonicalized, never refused.
            _result(10841, evidence=(evidence_b, evidence_a, evidence_b)),
        ],
    )
    assert request.request_id_derived is True
    assert request.expected_frontier_latest is True

    result = await app.publish_work(request)
    assert isinstance(result, PublishWorkInternalResult)
    assert result.outcome == "accepted"
    assert result.request_id == request.request_id
    expected_ids = tuple(
        mint_draft_event_id(request.request_id, index, dry_run=False) for index in range(4)
    )
    assert tuple(event.event_id for event in result.accepted_events) == expected_ids

    body = result.as_json()
    filled = cast(Mapping[str, JsonValue], body["server_filled"])
    assert filled["request"] == ("expected_frontier", "request_id")
    # One group: every draft had the same five envelope values filled.
    assert filled["drafts"] == ({"fields": _ALL_FILLED, "indexes": ("0", "1", "2", "3")},)

    records = {str(record.event_id): record for record in _records(app)}
    stored = records[expected_ids[3]]
    assert stored.evidence_refs == (evidence_a, evidence_b)
    assert stored.causal_parents == ()
    # The service clock, recorded once for the whole operation.
    assert len({records[event_id].occurred_at.wire for event_id in expected_ids}) == 1

    # The operation record keeps the same names after the fact (durable provenance).
    ledger, _objects = next(iter(app.runtime.resources.values()))
    operation = await ledger.lookup_operation(started.writer_id, request.request_id)
    assert operation is not None
    assert operation.operation_kind is OperationKind.PUBLISH_WORK
    stored_result = cast(Mapping[str, JsonValue], strict_json_parse(operation.result_canonical))
    assert stored_result["server_filled"] == {
        "request": ["expected_frontier", "request_id"],
        "drafts": [{"fields": list(_ALL_FILLED), "indexes": ["0", "1", "2", "3"]}],
    }

    # The record validates against the published result contract's closed model.
    PublishWorkServerFilledModel.model_validate(filled)


async def test_resending_the_same_sparse_body_replays_without_a_request_id() -> None:
    app, started = await _started(10850)
    drafts = [_action(10851), _result(10851, evidence=())]
    first = await app.publish_work(_sparse_request(started, drafts))
    assert isinstance(first, PublishWorkInternalResult)
    assert first.outcome == "accepted"

    retry = await app.publish_work(_sparse_request(started, drafts))
    assert isinstance(retry, PublishWorkInternalResult)
    assert retry.outcome == "replayed"
    assert retry.request_id == first.request_id
    assert retry.request_digest == first.request_digest
    assert retry.accepted_events == first.accepted_events
    assert retry.as_json()["server_filled"] == first.as_json()["server_filled"]
    assert len([row for row in _records(app) if row.schema.name == "action_recorded"]) == 1
    # The replay says nothing new was appended, and how to repeat on purpose.
    assert "replay_notice" not in first.as_json()
    notice = cast(Mapping[str, JsonValue], retry.as_json()["replay_notice"])
    assert notice["notice"] == "identical_body_replayed"
    assert "send a fresh request_id" in cast(str, notice["text"])


async def test_an_explicit_request_id_replay_carries_no_replay_notice() -> None:
    app, started = await _started(10930)
    explicit = protocol_id("req_", 10935)
    drafts = [_action(10931), _result(10931, evidence=())]
    first = await app.publish_work(_sparse_request(started, drafts, request_id=explicit))
    retry = await app.publish_work(_sparse_request(started, drafts, request_id=explicit))
    assert isinstance(first, PublishWorkInternalResult)
    assert isinstance(retry, PublishWorkInternalResult)
    assert retry.outcome == "replayed"
    assert "replay_notice" not in retry.as_json()


async def test_a_corrected_body_gets_a_new_identity() -> None:
    app, started = await _started(10860)
    wrong = await app.publish_work(
        _sparse_request(started, [_action(10861), _result(10861, evidence=())])
    )
    assert isinstance(wrong, PublishWorkInternalResult)
    corrected = _result(10861, evidence=())
    cast(dict[str, JsonValue], corrected["payload"])["summary"] = "13 passed"
    corrected_request = _sparse_request(started, [_action(10862), corrected])
    assert corrected_request.request_id != wrong.request_id


async def test_a_dry_run_never_mints_the_ids_its_commit_records() -> None:
    app, started = await _started(10870)
    explicit = protocol_id("req_", 10875)
    drafts = [_action(10871), _result(10871, evidence=())]
    preview = await app.publish_work(
        _sparse_request(started, drafts, request_id=explicit, dry_run=True)
    )
    assert isinstance(preview, PublishWorkResultModel)
    assert isinstance(preview.root, PublishWorkDryRunModel)
    preview_ids = tuple(item.event_id for item in preview.root.would_accept)
    commit = await app.publish_work(_sparse_request(started, drafts, request_id=explicit))
    assert isinstance(commit, PublishWorkInternalResult)
    commit_ids = tuple(event.event_id for event in commit.accepted_events)
    assert not set(preview_ids) & set(commit_ids)
    assert commit.as_json()["server_filled"] == {
        "request": ("expected_frontier",),
        "drafts": ({"fields": _ALL_FILLED, "indexes": ("0", "1")},),
    }


async def test_present_values_are_honored_and_a_complete_body_is_unchanged() -> None:
    app, started = await _started(10880)
    occurred = "2026-10-16T11:59:59.000Z"
    evidence = protocol_id("evd_", 10881)
    request = PublishWorkRequest.model_validate(
        {
            **request_base(protocol_id("req_", 10885)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": frontier_json(started.frontier),
            "event_drafts": [
                {
                    **_action(10881),
                    "event_id": protocol_id("evt_", 10881),
                    "occurred_at": occurred,
                    "causal_parents": [],
                    "artifact_refs": [],
                    "evidence_refs": [],
                },
                {
                    **_evidence(10881),
                    "event_id": protocol_id("evt_", 10882),
                    "occurred_at": occurred,
                    "causal_parents": [],
                    "artifact_refs": [],
                    "evidence_refs": [],
                },
                {
                    **_result(10881, evidence=(evidence,)),
                    "event_id": protocol_id("evt_", 10883),
                    "occurred_at": occurred,
                    "causal_parents": [protocol_id("evt_", 10881)],
                    "artifact_refs": [],
                    "evidence_refs": [evidence],
                },
            ],
        }
    )
    assert request.request_id_derived is False
    assert request.expected_frontier_latest is False
    result = await app.publish_work(request)
    assert isinstance(result, PublishWorkInternalResult)
    body = result.as_json()
    assert "server_filled" not in body
    records = {str(record.event_id): record for record in _records(app)}
    assert records[protocol_id("evt_", 10883)].occurred_at.wire == occurred
    assert records[protocol_id("evt_", 10883)].causal_parents == (protocol_id("evt_", 10881),)

    ledger, _objects = next(iter(app.runtime.resources.values()))
    operation = await ledger.lookup_operation(started.writer_id, request.request_id)
    assert operation is not None
    assert "server_filled" not in cast(
        Mapping[str, JsonValue], strict_json_parse(operation.result_canonical)
    )


async def test_an_inconsistent_present_mirror_is_still_refused() -> None:
    app, started = await _started(10890)
    evidence = protocol_id("evd_", 10891)
    draft = _result(10891, evidence=(evidence,))
    draft["evidence_refs"] = []
    with pytest.raises(PublicOperationError) as caught:
        await app.publish_work(_sparse_request(started, [_action(10891), _evidence(10891), draft]))
    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    assert caught.value.safe_details is not None
    assert caught.value.safe_details.get("reason_code") == "ref_mirror_mismatch"


async def test_a_supplied_frontier_keeps_its_compare_and_set_guard() -> None:
    app, started = await _started(10900)
    first = await app.publish_work(
        _sparse_request(started, [_action(10901), _result(10901, evidence=())])
    )
    assert isinstance(first, PublishWorkInternalResult)
    stale = _sparse_request(
        started,
        [_action(10902), _result(10902, evidence=())],
        expected_frontier=frontier_json(started.frontier),
    )
    with pytest.raises(PublicOperationError) as caught:
        await app.publish_work(stale)
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT

    # The same batch in ``latest`` mode lands on the current frontier.
    latest = await app.publish_work(
        _sparse_request(started, [_action(10902), _result(10902, evidence=())])
    )
    assert isinstance(latest, PublishWorkInternalResult)
    assert latest.subject_frontier == first.result_frontier


async def test_an_explicit_null_frontier_keeps_its_earlier_meaning() -> None:
    app, started = await _started(10910)
    with pytest.raises(PublicOperationError) as caught:
        await app.publish_work(
            _sparse_request(
                started, [_action(10911), _result(10911, evidence=())], expected_frontier=None
            )
        )
    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    assert caught.value.safe_details is not None
    assert caught.value.safe_details.get("reason_code") == "expected_frontier_required"


def test_the_request_id_derivation_is_stable_and_excludes_itself() -> None:
    body: dict[str, JsonValue] = {"a": 1, "b": ["x"]}
    assert derive_publish_request_id(body) == derive_publish_request_id({"b": ["x"], "a": 1})
    assert derive_publish_request_id(body) != derive_publish_request_id({"a": 2, "b": ["x"]})
    with pytest.raises(ValueError):
        derive_publish_request_id({"request_id": protocol_id("req_", 1)})


async def test_mixed_drafts_group_by_their_filled_fields() -> None:
    """A draft that sent some envelope values is named in its own group, by batch index."""

    app, started = await _started(10920)
    evidence = protocol_id("evd_", 10921)
    explicit_time = _result(10921, evidence=(evidence,))
    explicit_time["occurred_at"] = "2026-10-16T11:00:00.000Z"
    explicit_time["evidence_refs"] = [evidence]
    result = await app.publish_work(
        _sparse_request(started, [_action(10921), _evidence(10921), explicit_time])
    )
    assert isinstance(result, PublishWorkInternalResult)
    filled = cast(Mapping[str, JsonValue], result.as_json()["server_filled"])
    assert filled["drafts"] == (
        {"fields": _ALL_FILLED, "indexes": ("0", "1")},
        {"fields": ("artifact_refs", "causal_parents", "event_id"), "indexes": ("2",)},
    )
    records = {str(record.event_id): record for record in _records(app)}
    explicit = records[str(result.accepted_events[2].event_id)]
    assert explicit.occurred_at.wire == "2026-10-16T11:00:00.000Z"
    PublishWorkServerFilledModel.model_validate(filled)


def test_server_filled_wire_refuses_overlapping_or_unsorted_groups() -> None:
    from finishup.protocol.publish_boilerplate import server_filled_from_json

    good = {"request": [], "drafts": [{"fields": ["event_id"], "indexes": ["0", "2"]}]}
    assert server_filled_from_json(good).as_json()["drafts"] == (
        {"fields": ("event_id",), "indexes": ("0", "2")},
    )
    for bad in (
        {"request": [], "drafts": [{"fields": ["event_id"], "indexes": ["2", "0"]}]},
        {
            "request": [],
            "drafts": [
                {"fields": ["event_id"], "indexes": ["0"]},
                {"fields": ["occurred_at"], "indexes": ["0"]},
            ],
        },
        {"request": [], "drafts": [{"fields": ["event_id"], "indexes": []}]},
        {"request": ["frontier"], "drafts": []},
        {"request": [], "drafts": [{"fields": ["payload"], "indexes": ["0"]}]},
    ):
        with pytest.raises(ValueError):
            server_filled_from_json(bad)
