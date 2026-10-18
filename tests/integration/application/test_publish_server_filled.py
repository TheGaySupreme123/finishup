"""Issue #1084: the service fills publish boilerplate, names what it filled, and stays idempotent.

These drive the real publish operation through the ready application. Each derived value has
three cases: absent -> derived and named in ``server_filled``; present -> honored byte for byte;
present but inconsistent -> the earlier typed rejection. The request identity is never derived:
the service requires ``request_id`` (the MCP bridge and the CLI mint one per call, see
``tests/unit/mcp/test_server_filled_bridge.py``), and the round-1 review counterexamples of PR
#1088 are pinned here as regressions (R1-R4, R6, R7).
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, cast

import pytest
from pydantic import ValidationError

import finishup.application.publish_work as publish_module
from builders.projection_workflow import (
    build_projection_application,
    frontier_json,
    request_base,
)
from builders.start_application import protocol_id, start_request
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.application.semantic_case import _history_json
from finishup.domain.events import LedgerRecord
from finishup.domain.privacy import ConversationReview
from finishup.kernel.deterministic_checks import (
    deterministic_case_from_json,
    deterministic_case_to_json,
)
from finishup.kernel.review_mode import conversation_review_mode
from finishup.ports.ledger import OperationKind
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import (
    PublishWorkAcceptedProjectionUnavailableModel,
    PublishWorkDryRunModel,
    PublishWorkRequest,
    PublishWorkResultModel,
    PublishWorkServerFilledModel,
    StatusRequest,
)
from finishup.protocol.publish_boilerplate import (
    DraftMintScope,
    mint_draft_event_id,
    server_filled_from_json,
)

pytestmark = pytest.mark.anyio

_ALL_FILLED = ("artifact_refs", "causal_parents", "event_id", "evidence_refs", "occurred_at")


def _action(seed: int, **extra: JsonValue) -> dict[str, JsonValue]:
    return {
        "schema": {"name": "action_recorded", "version": "1.0.0"},
        "payload": {
            "action_id": protocol_id("act_", seed),
            "action_kind": "command",
            "command": "pytest -q",
            "description": "Ran the unit tests.",
            **extra,
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


def _result(
    seed: int, *, evidence: tuple[str, ...], outcome: str = "success"
) -> dict[str, JsonValue]:
    return {
        "schema": {"name": "result_recorded", "version": "1.0.0"},
        "payload": {
            "result_id": protocol_id("res_", seed),
            "action_id": protocol_id("act_", seed),
            "outcome": outcome,
            "summary": "12 passed",
            "evidence_refs": list(evidence),
        },
    }


def _decision(mode: str, statement: str, **extra: JsonValue) -> dict[str, JsonValue]:
    return {
        "schema": {"name": "decision_recorded", "version": "1.1.0"},
        "payload": {
            "statement": statement,
            "rationale": "The current task review choice.",
            "authority": "projection-sweep",
            "review_mode": mode,
            **extra,
        },
    }


def _ledger(app: object) -> Any:
    ledger, _objects = next(iter(cast(Any, app).runtime.resources.values()))
    return ledger


def _objects(app: object) -> Any:
    _ledger_adapter, objects = next(iter(cast(Any, app).runtime.resources.values()))
    return objects


def _records(app: object) -> tuple[LedgerRecord, ...]:
    return cast(tuple[LedgerRecord, ...], tuple(_ledger(app)._state.records))


async def _started(seed: int) -> tuple[Any, Any]:
    app, _policy = await build_projection_application(seed=seed)
    started = await app.start(start_request(seed, title="Server-filled publish"))
    return app, started


def _sparse_request(
    started: Any, drafts: list[dict[str, JsonValue]], *, request_id: str, **extra: JsonValue
) -> Any:
    return PublishWorkRequest.model_validate(
        {
            **request_base(request_id),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "event_drafts": drafts,
            **extra,
        }
    )


def _scope(started: Any, request_id: str, *, dry_run: bool = False) -> DraftMintScope:
    return DraftMintScope(started.task_id, started.writer_id, request_id, dry_run)


async def test_a_sparse_batch_is_completed_named_and_recorded() -> None:
    app, started = await _started(10840)
    rid = protocol_id("req_", 10845)
    evidence_a, evidence_b = sorted(
        (protocol_id("evd_", 10842), protocol_id("evd_", 10841)), key=str.encode
    )
    request = _sparse_request(
        started,
        [
            _action(10841),
            _evidence(10841),
            _evidence(10842),
            # Unsorted, duplicated payload refs of an allowlisted set: canonicalized, not refused.
            _result(10841, evidence=(evidence_b, evidence_a, evidence_b)),
        ],
        request_id=rid,
    )
    assert request.expected_frontier_omitted is True

    result = await app.publish_work(request)
    assert isinstance(result, PublishWorkInternalResult)
    assert result.outcome == "accepted"
    assert result.request_id == rid
    expected_ids = tuple(mint_draft_event_id(_scope(started, rid), index) for index in range(4))
    assert tuple(event.event_id for event in result.accepted_events) == expected_ids

    body = result.as_json()
    filled = cast(Mapping[str, JsonValue], body["server_filled"])
    # The service fills the frontier; it never fills (or derives) the request identity.
    assert filled["request"] == ("expected_frontier",)
    assert filled["drafts"] == ({"fields": _ALL_FILLED, "indexes": ("0", "1", "2", "3")},)

    records = {str(record.event_id): record for record in _records(app)}
    stored = records[expected_ids[3]]
    assert stored.evidence_refs == (evidence_a, evidence_b)
    assert stored.causal_parents == ()
    # The service clock, recorded once for the whole operation.
    assert len({records[event_id].occurred_at.wire for event_id in expected_ids}) == 1

    operation = await _ledger(app).lookup_operation(started.writer_id, rid)
    assert operation is not None
    assert operation.operation_kind is OperationKind.PUBLISH_WORK
    stored_result = cast(Mapping[str, JsonValue], strict_json_parse(operation.result_canonical))
    assert stored_result["server_filled"] == {
        "request": ["expected_frontier"],
        "drafts": [{"fields": list(_ALL_FILLED), "indexes": ["0", "1", "2", "3"]}],
    }
    PublishWorkServerFilledModel.model_validate(filled)


async def test_the_service_never_derives_an_omitted_request_id() -> None:
    """Review R1: an id-less body is refused at the service; the host owns the identity."""

    _app, started = await _started(10855)
    body = {
        **request_base(protocol_id("req_", 1)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "event_drafts": [_action(10856)],
    }
    del body["request_id"]
    with pytest.raises(ValidationError):
        PublishWorkRequest.model_validate(body)


async def test_a_deliberate_review_mode_switch_back_is_recorded() -> None:
    """Review R1: ai -> local -> ai under three call identities records three decisions.

    The second ``ai_powered`` body is byte-identical to the first. Under the round-1 design its
    body-derived id replayed the first switch and the conversation stayed ``local``.
    """

    app, started = await _started(10860)
    outcomes: list[str] = []
    for index, mode in enumerate(("ai_powered", "local", "ai_powered")):
        result = await app.publish_work(
            _sparse_request(
                started,
                [_decision(mode, f"Switch the review to {mode}.")],
                request_id=protocol_id("req_", 10861 + index),
            )
        )
        assert isinstance(result, PublishWorkInternalResult)
        outcomes.append(result.outcome)
    assert outcomes == ["accepted", "accepted", "accepted"]
    modes = [
        cast(Any, record.payload).review_mode.value
        for record in _records(app)
        if record.schema.name == "decision_recorded"
    ]
    assert modes == ["ai_powered", "local", "ai_powered"]
    resolved = conversation_review_mode(
        _ledger(app)._state.projection,
        ConversationReview.LOCAL_AGENT_OPT_IN,
        ai_review_available=True,
        setting_explicit=True,
    )
    assert resolved.mode.value == "ai_powered"


async def test_a_retry_replays_the_committed_operations_provenance() -> None:
    """Review R6: a replay reports what was filled for the committed append, not the retry."""

    app, started = await _started(10850)
    rid = protocol_id("req_", 10855)
    drafts = [_decision("local", "Keep local review for this task.")]
    first = await app.publish_work(_sparse_request(started, drafts, request_id=rid))
    assert isinstance(first, PublishWorkInternalResult)
    assert first.outcome == "accepted"

    # The retry spells out the minted id and the empty lists: an equivalent wire form whose
    # normalized request digest is unchanged, so it is the same operation.
    explicit = [
        {
            **drafts[0],
            "event_id": first.accepted_events[0].event_id,
            "causal_parents": [],
            "artifact_refs": [],
            "evidence_refs": [],
        }
    ]
    retry = await app.publish_work(_sparse_request(started, explicit, request_id=rid))
    assert isinstance(retry, PublishWorkInternalResult)
    assert retry.outcome == "replayed"
    assert retry.request_digest == first.request_digest
    assert retry.accepted_events == first.accepted_events
    assert retry.as_json()["server_filled"] == first.as_json()["server_filled"]
    assert cast(Mapping[str, Any], retry.as_json()["server_filled"])["drafts"] == (
        {"fields": _ALL_FILLED, "indexes": ("0",)},
    )
    assert len([row for row in _records(app) if row.schema.name == "decision_recorded"]) == 1

    # The operation page, the other public recovery route, names the same provenance.
    page = await app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", 10859)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "operation",
                "filter": {"operation_request_id": rid},
            }
        )
    )
    operation_page = cast(Mapping[str, Any], page.as_json()["page"])
    assert server_filled_from_json(operation_page["server_filled"]) == server_filled_from_json(
        retry.as_json()["server_filled"]
    )


async def test_a_degraded_replay_keeps_its_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review R1: the reduced success of a replay still names what the service filled."""

    app, started = await _started(10865)
    rid = protocol_id("req_", 10866)
    request = _sparse_request(started, [_decision("local", "Use local review.")], request_id=rid)
    first = await app.publish_work(request)
    assert isinstance(first, PublishWorkInternalResult)

    async def fail(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("intentional_response_failure")

    monkeypatch.setattr(publish_module, "_internal_result", fail)
    reduced = await app.publish_work(request)
    assert isinstance(reduced, PublishWorkResultModel)
    root = reduced.root
    assert isinstance(root, PublishWorkAcceptedProjectionUnavailableModel)
    assert root.outcome == "replayed"
    assert root.server_filled is not None
    assert root.server_filled.model_dump(mode="json") == {
        "request": ["expected_frontier"],
        "drafts": [{"fields": list(_ALL_FILLED), "indexes": ["0"]}],
    }


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
    assert preview_ids == tuple(
        mint_draft_event_id(_scope(started, explicit, dry_run=True), index) for index in range(2)
    )
    assert commit.as_json()["server_filled"] == {
        "request": ("expected_frontier",),
        "drafts": ({"fields": _ALL_FILLED, "indexes": ("0", "1")},),
    }


async def test_minted_event_ids_carry_the_whole_operation_scope() -> None:
    """Review R4: two writers reusing one explicit request_id never mint the same event id."""

    app, started = await _started(10880)
    other = await app.start(start_request(10881, mode="attach", session_id=started.session_id))
    assert other.task_id == started.task_id
    assert (other.session_id, other.writer_id) != (started.session_id, started.writer_id)
    rid = protocol_id("req_", 10882)
    first = await app.publish_work(
        _sparse_request(started, [_decision("local", "Writer A decides.")], request_id=rid)
    )
    second = await app.publish_work(
        _sparse_request(other, [_decision("local", "Writer B decides.")], request_id=rid)
    )
    assert isinstance(first, PublishWorkInternalResult)
    assert isinstance(second, PublishWorkInternalResult)
    assert first.outcome == second.outcome == "accepted"
    assert first.accepted_events[0].event_id != second.accepted_events[0].event_id
    assert second.accepted_events[0].event_id == mint_draft_event_id(_scope(other, rid), 0)
    # Each scope field changes the id on its own; position and role do too.
    base = _scope(started, rid)
    variants = {
        mint_draft_event_id(base, 0),
        mint_draft_event_id(DraftMintScope(protocol_id("tsk_", 9), base.writer_id, rid, False), 0),
        mint_draft_event_id(DraftMintScope(base.task_id, protocol_id("wri_", 9), rid, False), 0),
        mint_draft_event_id(
            DraftMintScope(base.task_id, base.writer_id, protocol_id("req_", 9), False), 0
        ),
        mint_draft_event_id(base, 1),
        mint_draft_event_id(_scope(started, rid, dry_run=True), 0),
    }
    assert len(variants) == 6


async def test_present_values_are_honored_and_a_complete_body_is_unchanged() -> None:
    app, started = await _started(10890)
    occurred = "2026-10-16T11:59:59.000Z"
    evidence = protocol_id("evd_", 10891)
    rid = protocol_id("req_", 10895)
    request = PublishWorkRequest.model_validate(
        {
            **request_base(rid),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": frontier_json(started.frontier),
            "event_drafts": [
                {
                    **_action(10891),
                    "event_id": protocol_id("evt_", 10891),
                    "occurred_at": occurred,
                    "causal_parents": [],
                    "artifact_refs": [],
                    "evidence_refs": [],
                },
                {
                    **_evidence(10891),
                    "event_id": protocol_id("evt_", 10892),
                    "occurred_at": occurred,
                    "causal_parents": [],
                    "artifact_refs": [],
                    "evidence_refs": [],
                },
                {
                    **_result(10891, evidence=(evidence,)),
                    "event_id": protocol_id("evt_", 10893),
                    "occurred_at": occurred,
                    "causal_parents": [protocol_id("evt_", 10891)],
                    "artifact_refs": [],
                    "evidence_refs": [evidence],
                },
            ],
        }
    )
    assert request.expected_frontier_omitted is False
    result = await app.publish_work(request)
    assert isinstance(result, PublishWorkInternalResult)
    body = result.as_json()
    assert "server_filled" not in body
    records = {str(record.event_id): record for record in _records(app)}
    assert records[protocol_id("evt_", 10893)].occurred_at.wire == occurred
    assert records[protocol_id("evt_", 10893)].causal_parents == (protocol_id("evt_", 10891),)

    operation = await _ledger(app).lookup_operation(started.writer_id, rid)
    assert operation is not None
    assert "server_filled" not in cast(
        Mapping[str, JsonValue], strict_json_parse(operation.result_canonical)
    )


async def test_id_shaped_free_text_is_recorded_exactly() -> None:
    """Review R2: a text tuple whose members look like ids keeps its order and multiplicity."""

    app, started = await _started(10900)
    high, low = protocol_id("evd_", 2), protocol_id("evd_", 1)
    rid = protocol_id("req_", 10905)
    draft = {
        **_decision("local", "Keep local review.", alternatives=[high, low, high]),
        "event_id": protocol_id("evt_", 10901),
        "occurred_at": "2026-10-16T00:00:00.000Z",
        "causal_parents": [],
        "artifact_refs": [],
        "evidence_refs": [],
    }
    complete = {
        **request_base(rid),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(started.frontier),
        "event_drafts": [draft],
    }
    request = PublishWorkRequest.model_validate(complete)
    # The model never rewrites the free-text tuple.
    assert list(cast(Mapping[str, Any], request.event_drafts[0])["payload"]["alternatives"]) == [
        high,
        low,
        high,
    ]
    result = await app.publish_work(request)
    assert isinstance(result, PublishWorkInternalResult)
    assert "server_filled" not in result.as_json()
    (row,) = [record for record in _records(app) if record.schema.name == "decision_recorded"]
    assert cast(Any, row.payload).alternatives == (high, low, high)

    # The prior committed operation replays under its exact original body (same digest).
    replay = await app.publish_work(PublishWorkRequest.model_validate(complete))
    assert isinstance(replay, PublishWorkInternalResult)
    assert replay.outcome == "replayed"
    assert replay.request_digest == result.request_digest

    # Other text tuples are untouched as well, even when every member is a typed id.
    items = [protocol_id("obl_", 2), protocol_id("obl_", 1)]
    action = _action(10902, attempted_items=cast(JsonValue, items))
    action_request = _sparse_request(started, [action], request_id=protocol_id("req_", 10906))
    payload = cast(Mapping[str, Any], action_request.event_drafts[0])["payload"]
    assert list(payload["attempted_items"]) == items


async def test_allowlisted_reference_sets_are_canonicalized() -> None:
    _app, started = await _started(10910)
    high, low = protocol_id("obl_", 2), protocol_id("obl_", 1)
    plan: dict[str, JsonValue] = {
        "schema": {"name": "plan_published", "version": "1.0.0"},
        "payload": {"plan_version": 1, "summary": "plan", "obligation_refs": [high, low, high]},
    }
    request = _sparse_request(started, [plan], request_id=protocol_id("req_", 10911))
    assert cast(Mapping[str, Any], request.event_drafts[0])["payload"]["obligation_refs"] == [
        low,
        high,
    ]


async def test_an_inconsistent_present_mirror_is_still_refused() -> None:
    app, started = await _started(10920)
    evidence = protocol_id("evd_", 10921)
    draft = _result(10921, evidence=(evidence,))
    draft["evidence_refs"] = []
    with pytest.raises(PublicOperationError) as caught:
        await app.publish_work(
            _sparse_request(
                started,
                [_action(10921), _evidence(10921), draft],
                request_id=protocol_id("req_", 10925),
            )
        )
    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    assert caught.value.safe_details is not None
    assert caught.value.safe_details.get("reason_code") == "ref_mirror_mismatch"


def _claim(seed: int, *, evidence: str, **extra: JsonValue) -> dict[str, JsonValue]:
    """A ``claim_recorded/1.1.0`` draft that leaves its empty sets out unless ``extra`` names them."""

    return {
        "schema": {"name": "claim_recorded", "version": "1.1.0"},
        "payload": {
            "claim_id": protocol_id("clm_", seed),
            "claim_kind": "material",
            "statement": "The parser change is complete.",
            "supporting_refs": [evidence],
            **extra,
        },
    }


async def test_an_omitted_empty_claim_set_records_the_explicit_bytes_and_digest() -> None:
    """n7 RC3a: 57 of 60 trials were refused for leaving out an empty claim set.

    Both spellings run on identically seeded applications, so equal request digests and payload
    references prove that they are one request recording one payload.
    """

    seen: list[tuple[object, object]] = []
    spellings: tuple[dict[str, JsonValue], ...] = (
        {},
        {"limitation_refs": [], "supersedes_claim_refs": []},
    )
    for explicit in spellings:
        app, started = await _started(10930)
        rid = protocol_id("req_", 10935)
        evidence = protocol_id("evd_", 10931)
        result = await app.publish_work(
            _sparse_request(
                started,
                [_evidence(10931), _claim(10931, evidence=evidence, **explicit)],
                request_id=rid,
            )
        )
        assert isinstance(result, PublishWorkInternalResult)
        assert result.outcome == "accepted"
        # Only envelope fields are named: an empty payload set asserts nothing (ADR-050 decision 7).
        assert cast(Mapping[str, Any], result.as_json()["server_filled"]) == {
            "request": ("expected_frontier",),
            "drafts": ({"fields": _ALL_FILLED, "indexes": ("0", "1")},),
        }
        (claim,) = [row for row in _records(app) if row.schema.name == "claim_recorded"]
        payload = cast(Any, claim).payload
        assert payload.limitation_refs == ()
        assert payload.supersedes_claim_refs == ()
        operation = await _ledger(app).lookup_operation(started.writer_id, rid)
        assert operation is not None
        seen.append((operation.request_digest, cast(Any, claim).payload_ref))
    assert seen[0] == seen[1]


async def test_a_retry_with_the_omitted_form_replays_an_explicit_commit() -> None:
    app, started = await _started(10940)
    rid = protocol_id("req_", 10945)
    evidence = protocol_id("evd_", 10941)
    explicit = [
        _evidence(10941),
        _claim(10941, evidence=evidence, limitation_refs=[], supersedes_claim_refs=[]),
    ]
    first = await app.publish_work(_sparse_request(started, explicit, request_id=rid))
    assert isinstance(first, PublishWorkInternalResult)
    assert first.outcome == "accepted"
    omitted = [_evidence(10941), _claim(10941, evidence=evidence)]
    retry = await app.publish_work(_sparse_request(started, omitted, request_id=rid))
    assert isinstance(retry, PublishWorkInternalResult)
    assert retry.outcome == "replayed"
    assert retry.request_digest == first.request_digest
    assert retry.accepted_events == first.accepted_events
    assert len([row for row in _records(app) if row.schema.name == "claim_recorded"]) == 1


async def test_an_omitted_limitation_set_still_names_missing_live_failures() -> None:
    """The default is the empty set, which the domain still judges: a live failure is named."""

    app, started = await _started(10950)
    evidence = protocol_id("evd_", 10951)
    failed = protocol_id("res_", 10951)
    obligation = protocol_id("obl_", 10951)
    plan: dict[str, JsonValue] = {
        "schema": {"name": "plan_published", "version": "1.0.0"},
        "payload": {"plan_version": 1, "summary": "plan", "obligation_refs": [obligation]},
    }
    published: dict[str, JsonValue] = {
        "schema": {"name": "obligation_published", "version": "1.0.0"},
        "payload": {
            "obligation_id": obligation,
            "description": "Fix the parser.",
            "acceptance_criteria": "The parser tests pass.",
            "evidence_expectation": "test",
            "status": "open",
        },
    }
    completion = _claim(10952, evidence=evidence, obligation_refs=[obligation])
    cast(dict[str, JsonValue], completion["payload"])["claim_kind"] = "completion"
    with pytest.raises(PublicOperationError) as caught:
        await app.publish_work(
            _sparse_request(
                started,
                [
                    plan,
                    published,
                    _action(10951),
                    _evidence(10951),
                    _result(10951, evidence=(evidence,), outcome="failure"),
                    completion,
                ],
                request_id=protocol_id("req_", 10955),
            )
        )
    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    assert caught.value.safe_details is not None
    assert caught.value.safe_details.get("invariant") == "limitation_refs_complete"
    assert caught.value.safe_details.get("field") == "/event_drafts/5/payload/limitation_refs"
    assert failed in caught.value.message


def _pause_staging(app: object, marker: bytes) -> tuple[asyncio.Event, asyncio.Event]:
    """Hold the publish whose payload carries ``marker`` at object staging (after admission)."""

    objects = _objects(app)
    original = objects.stage
    admitted, release = asyncio.Event(), asyncio.Event()

    async def stage(source: Any, metadata: Any) -> Any:
        if marker in (source.data or b""):
            admitted.set()
            await release.wait()
        return await original(source, metadata)

    objects.stage = stage
    return admitted, release


async def test_an_omitted_frontier_rejects_an_in_flight_cooperative_change() -> None:
    """Review R3: a newer switch that lands while an older one is in flight is not overtaken."""

    app, started = await _started(10930)
    admitted, release = _pause_staging(app, b"stale-writer-local")
    pending = asyncio.create_task(
        app.publish_work(
            _sparse_request(
                started,
                [_decision("local", "stale-writer-local")],
                request_id=protocol_id("req_", 10931),
            )
        )
    )
    await asyncio.wait_for(admitted.wait(), 10)
    newer = await app.publish_work(
        _sparse_request(
            started,
            [_decision("ai_powered", "newer-writer-ai")],
            request_id=protocol_id("req_", 10932),
        )
    )
    assert isinstance(newer, PublishWorkInternalResult)
    release.set()
    with pytest.raises(PublicOperationError) as caught:
        await asyncio.wait_for(pending, 10)
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
    assert caught.value.safe_details is not None
    assert caught.value.safe_details.get("reason_code") == "frontier_changed"
    modes = [
        cast(Any, record.payload).review_mode.value
        for record in _records(app)
        if record.schema.name == "decision_recorded"
    ]
    assert modes == ["ai_powered"]


async def test_an_omitted_frontier_keeps_a_stale_resolution_out() -> None:
    """Review R3: a resolution prepared before a newer failure lands is refused, not accepted."""

    app, started = await _started(10940)
    obligation = protocol_id("obl_", 10941)
    meaning = {
        "obligation_id": obligation,
        "description": "Implement the required parser grammar",
        "evidence_expectation": "A recorded test result",
    }

    def event(name: str, payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
        return {"schema": {"name": name, "version": "1.0.0"}, "payload": payload}

    def action(seed: int) -> dict[str, JsonValue]:
        return event(
            "action_recorded",
            {
                "action_id": protocol_id("act_", seed),
                "action_kind": "command",
                "command": "pytest parser",
                "description": "Run the parser test",
                "obligation_refs": [obligation],
            },
        )

    def result(seed: int, outcome: str) -> dict[str, JsonValue]:
        return event(
            "result_recorded",
            {
                "result_id": protocol_id("res_", seed),
                "action_id": protocol_id("act_", seed),
                "outcome": outcome,
                "summary": outcome,
                "exit_status": 0 if outcome == "success" else 1,
            },
        )

    initial = await app.publish_work(
        _sparse_request(
            started,
            [
                event(
                    "plan_published",
                    {
                        "plan_version": 1,
                        "summary": "Implement grammar",
                        "obligation_refs": [obligation],
                    },
                ),
                event("obligation_published", {**meaning, "status": "open"}),
                action(10942),
                result(10942, "success"),
            ],
            request_id=protocol_id("req_", 10943),
        )
    )
    assert isinstance(initial, PublishWorkInternalResult)
    admitted, release = _pause_staging(app, b'"status":"resolved"')
    pending = asyncio.create_task(
        app.publish_work(
            _sparse_request(
                started,
                [
                    event(
                        "obligation_published",
                        {
                            **meaning,
                            "status": "resolved",
                            "resolution_evidence_refs": [protocol_id("res_", 10942)],
                        },
                    )
                ],
                request_id=protocol_id("req_", 10944),
            )
        )
    )
    await asyncio.wait_for(admitted.wait(), 10)
    newer = await app.publish_work(
        _sparse_request(
            started,
            [action(10945), result(10945, "failure")],
            request_id=protocol_id("req_", 10946),
        )
    )
    assert isinstance(newer, PublishWorkInternalResult)
    release.set()
    with pytest.raises(PublicOperationError) as caught:
        await asyncio.wait_for(pending, 10)
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
    page = await app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", 10947)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "obligations",
                "filter": {"include_resolved": True},
            }
        )
    )
    (item,) = cast(Mapping[str, Any], page.as_json()["page"])["items"]
    assert item["status"] == "open"


async def _append_observed(app: Any, started: Any, *, seed: int, after: int) -> Any:
    """A hook-observed command and its result, service-stamped like the observation path."""

    from finishup.application.observation_materialize import observation_author
    from finishup.domain.events import (
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
    from finishup.domain.values import action_id, event_id, result_id, timestamp_from_datetime
    from finishup.kernel.observed_failures import observed_action_description
    from finishup.ports.ledger import AppendCommand, AppendEntry
    from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
    from finishup.protocol.canonical import canonical_encode
    from finishup.protocol.coverage import PublicationChannel, coverage_for_channel

    ledger, objects = _ledger(app), _objects(app)
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
            "sha256:" + "5" * 64,
            after,
            tuple(entries),
            None,
        )
    )
    return appended.result_frontier


async def test_an_omitted_frontier_tolerates_observation_only_appends() -> None:
    """ADR-022: hook observations landing while the batch is in flight are not a conflict."""

    app, started = await _started(10950)
    admitted, release = _pause_staging(app, b"observed-tolerance")
    pending = asyncio.create_task(
        app.publish_work(
            _sparse_request(
                started,
                [_decision("local", "observed-tolerance")],
                request_id=protocol_id("req_", 10951),
            )
        )
    )
    await asyncio.wait_for(admitted.wait(), 10)
    head = await _ledger(app).load_frontier()
    observed = await _append_observed(app, started, seed=10960, after=head.sequence)
    release.set()
    accepted = await asyncio.wait_for(pending, 10)
    assert isinstance(accepted, PublishWorkInternalResult)
    assert accepted.outcome == "accepted"
    assert accepted.subject_frontier.sequence == observed.sequence


async def test_a_supplied_frontier_keeps_its_compare_and_set_guard() -> None:
    app, started = await _started(10970)
    first = await app.publish_work(
        _sparse_request(
            started,
            [_action(10971), _result(10971, evidence=())],
            request_id=protocol_id("req_", 10972),
        )
    )
    assert isinstance(first, PublishWorkInternalResult)
    stale = _sparse_request(
        started,
        [_action(10973), _result(10973, evidence=())],
        request_id=protocol_id("req_", 10974),
        expected_frontier=frontier_json(started.frontier),
    )
    with pytest.raises(PublicOperationError) as caught:
        await app.publish_work(stale)
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT

    # The same batch with the frontier omitted is guarded by the one read at admission.
    current = await app.publish_work(
        _sparse_request(
            started,
            [_action(10973), _result(10973, evidence=())],
            request_id=protocol_id("req_", 10974),
        )
    )
    assert isinstance(current, PublishWorkInternalResult)
    assert current.subject_frontier == first.result_frontier


async def test_an_explicit_null_frontier_keeps_its_earlier_meaning() -> None:
    app, started = await _started(10980)
    with pytest.raises(PublicOperationError) as caught:
        await app.publish_work(
            _sparse_request(
                started,
                [_action(10981), _result(10981, evidence=())],
                request_id=protocol_id("req_", 10982),
                expected_frontier=None,
            )
        )
    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    assert caught.value.safe_details is not None
    assert caught.value.safe_details.get("reason_code") == "expected_frontier_required"


async def test_mixed_drafts_group_by_their_filled_fields() -> None:
    """A draft that sent some envelope values is named in its own group, by batch index."""

    app, started = await _started(10990)
    evidence = protocol_id("evd_", 10991)
    explicit_time = _result(10991, evidence=(evidence,))
    explicit_time["occurred_at"] = "2026-10-16T11:00:00.000Z"
    explicit_time["evidence_refs"] = [evidence]
    result = await app.publish_work(
        _sparse_request(
            started,
            [_action(10991), _evidence(10991), explicit_time],
            request_id=protocol_id("req_", 10992),
        )
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


async def test_history_and_frozen_review_inputs_label_a_service_clock_time() -> None:
    """Review R7: a service-recorded occurred_at is labelled wherever the timeline is read."""

    app, started = await _started(11000)
    explicit_time = _result(11001, evidence=())
    explicit_time["occurred_at"] = "2026-10-16T11:00:00.000Z"
    result = await app.publish_work(
        _sparse_request(
            started, [_action(11001), explicit_time], request_id=protocol_id("req_", 11002)
        )
    )
    assert isinstance(result, PublishWorkInternalResult)
    filled_event = str(result.accepted_events[0].event_id)
    asserted_event = str(result.accepted_events[1].event_id)

    history = await app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", 11003)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "view": "history",
                "detail": "full",
            }
        )
    )
    rows = {
        item["event_id"]: item
        for item in cast(Mapping[str, Any], history.as_json()["page"])["items"]
    }
    assert rows[filled_event]["occurred_at_source"] == "service_clock"
    assert "occurred_at_source" not in rows[asserted_event]

    ledger = _ledger(app)
    frozen = await ledger.freeze_case(
        started.session_id,
        started.writer_id,
        None,
        protocol_id("req_", 11004),
        "sha256:" + "4" * 64,
    )
    case = frozen.case
    labels = {str(item.event_id): item.occurred_at_source for item in case.history}
    assert labels[filled_event] == "service_clock"
    assert labels[asserted_event] is None
    # The label survives the frozen case's durable form and reaches the review packet.
    restored = deterministic_case_from_json(deterministic_case_to_json(case))
    assert {str(item.event_id): item.occurred_at_source for item in restored.history} == labels
    packet_rows = {
        str(item.event_id): _history_json(
            item, include_content=False, include_exact_command_text=False
        )[0]
        for item in restored.history
    }
    assert '"occurred_at_source":"service_clock"' in packet_rows[filled_event]
    assert "occurred_at_source" not in packet_rows[asserted_event]


def test_server_filled_wire_refuses_overlapping_or_unsorted_groups() -> None:
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
        # The service never fills the request identity (review R1).
        {"request": ["request_id"], "drafts": []},
        {"request": [], "drafts": [{"fields": ["payload"], "indexes": ["0"]}]},
    ):
        with pytest.raises(ValueError):
            server_filled_from_json(bad)
