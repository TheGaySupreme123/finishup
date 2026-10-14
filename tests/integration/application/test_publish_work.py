"""Integration coverage for application publication over the memory ledger oracle."""

from __future__ import annotations

from typing import cast

import pytest
from pydantic import ValidationError

from builders.ledger_adapters import (
    FixedClock,
    MemoryObjects,
    append_command,
    memory_adapter,
    ownership_fence,
)
from finishup.application.import_review import (
    _publication_frontier,  # pyright: ignore[reportPrivateUsage]
)
from finishup.application.publish_work import Application, execute_publish_work
from finishup.application.status import Application as StatusApplication
from finishup.application.status import execute_status
from finishup.domain.events import ClaimRecordedPayload, ClaimRecordedPayloadV1_1
from finishup.domain.values import Frontier, session_id
from finishup.kernel.plan_scope import current_plan_scope
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.importer import ImporterPort, ImportStatusSnapshot
from finishup.ports.ledger import ProjectionView
from finishup.ports.objects import ObjectKind, ObjectRef, ObjectStorePort, StagedObject
from finishup.ports.runtime import RouteCommand, TaskRuntime
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import (
    PublishWorkDryRunModel,
    PublishWorkRequestModel,
    StatusHistoryPageModel,
    StatusOperationPageModel,
    StatusRequest,
    StatusResultsPageModel,
)

pytestmark = pytest.mark.anyio


class _IdleImporter:
    async def status(self, session: str) -> ImportStatusSnapshot:
        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


class _Runtime:
    def __init__(self, task: TaskRuntime) -> None:
        self.task = task
        self.routes: list[RouteCommand] = []
        self.release_count = 0

    async def route(self, command: RouteCommand) -> TaskRuntime:
        self.routes.append(command)
        return self.task

    async def release(self, runtime: TaskRuntime) -> None:
        assert runtime is self.task
        self.release_count += 1


class _Application:
    def __init__(self, runtime: _Runtime) -> None:
        self.runtime = runtime
        self.clock = FixedClock()
        self.status_cursor_key = b"publish-work-status-cursor-key!!"

    def authorizes_import_publication(self, request: PublishWorkRequestModel) -> bool:
        del request
        return False


def _composition() -> tuple[_Application, MemoryObjects]:
    seed = append_command()
    ledger = memory_adapter(seed)
    objects = cast(MemoryObjects, ledger._objects)  # pyright: ignore[reportPrivateUsage]
    assert objects is not None
    task = TaskRuntime(
        seed.task_id,
        seed.session_id,
        seed.writer_id,
        frozenset(
            {
                RuntimeCapability.WRITE,
                RuntimeCapability.STRUCTURAL_READ,
                RuntimeCapability.PAYLOAD_READ,
            }
        ),
        ledger,
        cast(ObjectStorePort, objects),
        cast(ImporterPort, _IdleImporter()),
        "0.1.0",
        "0.1.0",
        "0.1",
        "1.0.0",
        ownership_fence(),
    )
    runtime = _Runtime(task)
    return _Application(runtime), objects


def _draft(
    *,
    event_tail: int,
    action_tail: int,
    action_kind: str = "other",
) -> dict[str, object]:
    return {
        "event_id": f"evt_00000000-0000-4000-8000-{event_tail:012d}",
        "schema": {"name": "action_recorded", "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:00.000Z",
        "causal_parents": (),
        "payload": {
            "action_id": f"act_00000000-0000-4000-8000-{action_tail:012d}",
            "action_kind": action_kind,
            "description": "Materialized one coherent slice",
        },
        "artifact_refs": (),
        "evidence_refs": (),
    }


def _request(
    *,
    family: str = "action_recorded",
    description: str = "Materialized one coherent slice",
    request_tail: int = 201,
    event_tail: int = 202,
    action_tail: int = 203,
    expected_frontier: object = None,
    event_drafts: tuple[dict[str, object], ...] | None = None,
) -> PublishWorkRequestModel:
    seed = append_command()
    payload: object
    if family == "action_recorded":
        payload = {
            "action_id": f"act_00000000-0000-4000-8000-{action_tail:012d}",
            "action_kind": "other",
            "description": description,
        }
    else:
        payload = {
            "task_title": "forbidden lifecycle publication",
            "client_kind": "test_client",
            "client_version": "0.1.0",
            "integration": "local_cli",
            "profile": "test-fake",
        }
    return PublishWorkRequestModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": f"req_00000000-0000-4000-8000-{request_tail:012d}",
            "session_id": seed.session_id,
            "writer_id": seed.writer_id,
            "expected_frontier": expected_frontier,
            "event_drafts": event_drafts
            or (
                {
                    "event_id": f"evt_00000000-0000-4000-8000-{event_tail:012d}",
                    "schema": {"name": family, "version": "1.0.0"},
                    "occurred_at": "2026-07-19T12:00:00.000Z",
                    "causal_parents": (),
                    "payload": payload,
                    "artifact_refs": (),
                    "evidence_refs": (),
                },
            ),
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "local_cli",
            },
        }
    )


async def test_rejected_draft_is_located_by_ordinal_without_echoing_payload_content() -> None:
    """A multi-draft batch must say which draft failed, using only frozen names and an ordinal.

    The 2026-07-26 dogfood published a four-event batch whose only diagnostic was
    ``reason_code: invalid_event_enum`` — enough to know something was wrong, not enough to know
    which event or field to fix.
    """

    app, _objects = _composition()
    secret = "never-echo-this-private-title"
    forbidden: dict[str, object] = {
        "event_id": "evt_00000000-0000-4000-8000-000000000305",
        "schema": {"name": "session_opened", "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:00.000Z",
        "causal_parents": (),
        "payload": {
            "task_title": secret,
            "client_kind": "test_client",
            "client_version": "0.1.0",
            "integration": "local_cli",
            "profile": "test-fake",
        },
        "artifact_refs": (),
        "evidence_refs": (),
    }
    request = _request(
        event_drafts=(
            _draft(event_tail=301, action_tail=302),
            _draft(event_tail=303, action_tail=304),
            forbidden,
        )
    )

    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(cast(Application, app), request)

    details = caught.value.safe_details
    # The ordinal is the failing draft, not merely the first one.
    assert details["field"] == "/event_drafts/2/schema"
    assert details["reason_code"] == "event_family_not_admitted"
    assert secret not in repr(dict(details))
    assert secret not in caught.value.message


async def test_publish_is_object_first_atomic_and_same_id_replay_is_stable() -> None:
    app, objects = _composition()
    first = await execute_publish_work(cast(Application, app), _request())
    durable_after_first = len(objects._data)  # pyright: ignore[reportPrivateUsage]
    replay = await execute_publish_work(cast(Application, app), _request())

    assert first.ok is True
    assert first.outcome == "accepted"
    assert replay.ok is True
    assert replay.outcome == "replayed"
    assert replay.accepted_events == first.accepted_events
    assert len(objects._data) == durable_after_first  # pyright: ignore[reportPrivateUsage]
    assert app.runtime.release_count == 2


async def test_second_payload_finalize_failure_abandons_batch_then_same_request_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #339: a failed second payload must not leave the first finalized object."""

    app, objects = _composition()
    request = _request(
        request_tail=204,
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
        event_drafts=(
            _draft(event_tail=205, action_tail=206),
            _draft(event_tail=207, action_tail=208),
        ),
    )
    refs_before = objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD)
    data_before = len(objects._data)  # pyright: ignore[reportPrivateUsage]
    original_finalize = objects.finalize
    finalize_calls = 0

    async def _fail_second_finalize(staged: StagedObject) -> ObjectRef:
        nonlocal finalize_calls
        finalize_calls += 1
        if finalize_calls == 2:
            raise OSError("simulated_second_finalize_failure")
        return await original_finalize(staged)

    monkeypatch.setattr(objects, "finalize", _fail_second_finalize)

    with pytest.raises(OSError, match="simulated_second_finalize_failure"):
        await execute_publish_work(cast(Application, app), request)
    assert objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD) == refs_before
    assert len(objects._data) == data_before  # pyright: ignore[reportPrivateUsage]
    assert (
        await app.runtime.task.ledger.lookup_operation(request.writer_id, request.request_id)
        is None
    )

    retried = await execute_publish_work(cast(Application, app), request)
    assert retried.outcome == "accepted"
    assert len(objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD)) == len(refs_before) + 2
    durable_after_retry = len(objects._data)  # pyright: ignore[reportPrivateUsage]
    replayed = await execute_publish_work(cast(Application, app), request)
    assert replayed.outcome == "replayed"
    assert replayed.result_frontier == retried.result_frontier
    assert len(objects._data) == durable_after_retry  # pyright: ignore[reportPrivateUsage]


async def test_forbidden_family_rejects_before_object_publication() -> None:
    app, objects = _composition()
    before = len(objects._data)  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(cast(Application, app), _request(family="session_opened"))

    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    # The rejected draft is named by ordinal and owning field so a multi-draft batch does not
    # have to be re-derived to find the one bad member.
    assert caught.value.safe_details == {
        "continuation": "input_correction_new_identity",
        "field": "/event_drafts/0/schema",
        "reason_code": "event_family_not_admitted",
    }
    assert len(objects._data) == before  # pyright: ignore[reportPrivateUsage]
    assert app.runtime.release_count == 1


async def test_same_request_id_replay_returns_the_stored_result_without_rewriting() -> None:
    """The recovery the MCP post-commit error advertises must actually work.

    When response shaping fails after a durable commit, the bridge tells the caller to retry with
    the same request_id. That guidance is only honest if an identical replay returns the committed
    result instead of appending a second event.
    """

    app, objects = _composition()
    request = _request(expected_frontier={"sequence": "0", "head_digest": "genesis"})
    first = await execute_publish_work(cast(Application, app), request)
    durable_after_first = len(objects._data)  # pyright: ignore[reportPrivateUsage]

    # This exact frontier is stale after the first append. Completed-operation replay must resolve
    # before the ledger evaluates it, or this would incorrectly become FRONTIER_CONFLICT.
    second = await execute_publish_work(cast(Application, app), request)

    assert first.outcome == "accepted"
    assert second.outcome == "replayed"
    # The replayed response must describe the same committed events and frontier as the original.
    assert second.result_frontier == first.result_frontier
    assert second.subject_frontier == first.subject_frontier
    assert tuple(item.event_id for item in second.accepted_events) == tuple(
        item.event_id for item in first.accepted_events
    )
    assert tuple(item.ingestion_sequence for item in second.accepted_events) == tuple(
        item.ingestion_sequence for item in first.accepted_events
    )
    # No second write: the replay reads stored state rather than re-publishing.
    assert len(objects._data) == durable_after_first  # pyright: ignore[reportPrivateUsage]


async def test_import_replay_recovers_the_original_subject_frontier_after_ambiguous_append() -> (
    None
):
    app, _objects = _composition()
    original = _request(expected_frontier={"sequence": "0", "head_digest": "genesis"})
    first = await execute_publish_work(cast(Application, app), original)

    # Simulate the importer crashing after the ledger commit but before record_batch. Its own row
    # still selects this batch while the task head has advanced past the original request frontier.
    assert await app.runtime.task.ledger.load_frontier() == first.result_frontier
    recovered = await _publication_frontier(app.runtime.task, original.request_id)
    assert recovered == first.subject_frontier == Frontier.genesis()
    assert original.expected_frontier is not None
    assert original.expected_frontier.model_dump(mode="json") == dict(recovered.as_wire())

    replay = await execute_publish_work(cast(Application, app), original)
    assert replay.outcome == "replayed"
    assert replay.result_frontier == first.result_frontier


async def test_same_id_changed_logical_request_conflicts_before_reencryption() -> None:
    app, objects = _composition()
    first = await execute_publish_work(cast(Application, app), _request())
    durable_after_first = len(objects._data)  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(
            cast(Application, app), _request(description="Changed logical work")
        )

    assert caught.value.code is PublicErrorCode.REQUEST_IDENTITY_CONFLICT
    assert caught.value.safe_details.get("reason_code") == "request_identity_conflict"
    assert caught.value.safe_details.get("sequence") == first.result_frontier.sequence
    assert caught.value.safe_details.get("head_digest") == first.result_frontier.head_digest
    assert caught.value.safe_details.get("count") == len(first.accepted_events)
    assert len(objects._data) == durable_after_first  # pyright: ignore[reportPrivateUsage]


async def test_stale_expected_frontier_sequence_conflicts() -> None:
    app, _ = _composition()
    first = await execute_publish_work(cast(Application, app), _request())

    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(
            cast(Application, app),
            _request(
                request_tail=211,
                event_tail=212,
                action_tail=213,
                expected_frontier={"sequence": "0", "head_digest": "genesis"},
            ),
        )

    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
    assert caught.value.retryable is True
    assert caught.value.safe_details.get("reason_code") == "frontier_changed"
    # The conflict must carry the *current* head so a caller can retry without a status round-trip.
    assert caught.value.safe_details.get("sequence") == first.result_frontier.sequence
    assert caught.value.safe_details.get("head_digest") == first.result_frontier.head_digest


async def test_caller_cannot_spoof_observation_author_to_bypass_frontier_guard() -> None:
    app, _ = _composition()
    spoofed_wire = _request().model_dump(mode="json")
    spoofed_wire.pop("dry_run", None)
    spoofed_wire["actor"] = {
        "actor_id": "yoetz:observation-coordinator",
        "actor_type": "harness",
    }
    first = await execute_publish_work(
        cast(Application, app), PublishWorkRequestModel.model_validate(spoofed_wire)
    )

    stale_spoofed_wire = dict(spoofed_wire)
    stale_spoofed_wire["request_id"] = "req_00000000-0000-4000-8000-000000000219"
    stale_spoofed_wire["expected_frontier"] = {
        "sequence": "0",
        "head_digest": "genesis",
    }
    stale_spoofed_event = dict(cast(list[dict[str, object]], stale_spoofed_wire["event_drafts"])[0])
    stale_spoofed_event["event_id"] = "evt_00000000-0000-4000-8000-000000000220"
    stale_spoofed_payload = dict(cast(dict[str, object], stale_spoofed_event["payload"]))
    stale_spoofed_payload["action_id"] = "act_00000000-0000-4000-8000-000000000221"
    stale_spoofed_event["payload"] = stale_spoofed_payload
    stale_spoofed_wire["event_drafts"] = [stale_spoofed_event]

    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(
            cast(Application, app),
            PublishWorkRequestModel.model_validate(stale_spoofed_wire),
        )

    assert first.result_frontier.sequence == 1
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT


async def test_state_sensitive_batch_without_frontier_names_required_field() -> None:
    app, _ = _composition()
    action = _draft(event_tail=214, action_tail=215)
    result: dict[str, object] = {
        "event_id": "evt_00000000-0000-4000-8000-000000000216",
        "schema": {"name": "result_recorded", "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:01:00.000Z",
        "causal_parents": (action["event_id"],),
        "payload": {
            "result_id": "res_00000000-0000-4000-8000-000000000217",
            "action_id": "act_00000000-0000-4000-8000-000000000215",
            "outcome": "success",
            "summary": "Completed the bounded action.",
        },
        "artifact_refs": (),
        "evidence_refs": (),
    }

    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(
            cast(Application, app),
            _request(request_tail=218, event_drafts=(action, result)),
        )

    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    assert caught.value.retryable is True
    assert caught.value.safe_details.get("reason_code") == "expected_frontier_required"
    assert "expected_frontier" in caught.value.message


async def test_mutated_event_drafts_same_request_id_is_request_identity_conflict() -> None:
    """Run-3 sequence: same request_id with a different body must not re-append or invalidate."""

    app, objects = _composition()
    original = _request(
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
        event_drafts=(
            _draft(event_tail=401, action_tail=402),
            _draft(event_tail=403, action_tail=404),
        ),
    )
    first = await execute_publish_work(cast(Application, app), original)
    durable_after_first = len(objects._data)  # pyright: ignore[reportPrivateUsage]

    mutated = _request(
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
        event_drafts=(
            _draft(event_tail=401, action_tail=402),
            {
                **_draft(event_tail=403, action_tail=404),
                "payload": {
                    "action_id": "act_00000000-0000-4000-8000-000000000404",
                    "action_kind": "other",
                    "description": "Mutated draft body that is no longer the original",
                },
            },
        ),
    )
    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(cast(Application, app), mutated)

    assert caught.value.code is PublicErrorCode.REQUEST_IDENTITY_CONFLICT
    assert caught.value.safe_details.get("reason_code") == "request_identity_conflict"
    assert caught.value.safe_details.get("sequence") == first.result_frontier.sequence
    assert caught.value.safe_details.get("head_digest") == first.result_frontier.head_digest
    assert caught.value.safe_details.get("count") == len(first.accepted_events)
    assert len(objects._data) == durable_after_first  # pyright: ignore[reportPrivateUsage]


async def test_status_view_operation_returns_stored_publish_result() -> None:
    app, _ = _composition()
    request = _request(request_tail=501, event_tail=502, action_tail=503)
    first = await execute_publish_work(cast(Application, app), request)
    seed = append_command()

    status = await execute_status(
        cast(StatusApplication, app),
        StatusRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": "req_00000000-0000-4000-8000-000000000510",
                "session_id": seed.session_id,
                "writer_id": seed.writer_id,
                "view": "operation",
                "limit": "1",
                "filter": {"operation_request_id": request.request_id},
                "actor": {"actor_id": "harness:test", "actor_type": "harness"},
                "client": {
                    "kind": "test_client",
                    "version": "0.1.0",
                    "integration": "local_cli",
                },
            }
        ),
    )

    assert status.view == "operation"
    page = status.page
    assert type(page) is StatusOperationPageModel
    assert page.found is True
    assert page.state == "complete"
    assert page.operation_kind == "publish_work"
    assert page.outcome == "accepted"
    assert page.result_frontier is not None
    assert page.result_frontier.sequence == str(first.result_frontier.sequence)
    assert tuple(item.event_id for item in page.accepted_events) == tuple(
        item.event_id for item in first.accepted_events
    )
    assert tuple(item.entry_digest for item in page.accepted_events) == tuple(
        item.entry_digest for item in first.accepted_events
    )


async def test_status_view_operation_absent_for_unknown_request_id() -> None:
    app, _ = _composition()
    request = _request(request_tail=521)
    await execute_publish_work(cast(Application, app), request)
    seed = append_command()

    unknown = await execute_status(
        cast(StatusApplication, app),
        StatusRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": "req_00000000-0000-4000-8000-000000000522",
                "session_id": seed.session_id,
                "writer_id": seed.writer_id,
                "view": "operation",
                "limit": "1",
                "filter": {"operation_request_id": "req_00000000-0000-4000-8000-000000000599"},
                "actor": {"actor_id": "harness:test", "actor_type": "harness"},
                "client": {
                    "kind": "test_client",
                    "version": "0.1.0",
                    "integration": "local_cli",
                },
            }
        ),
    )
    page = cast(StatusOperationPageModel, unknown.page)
    assert page.found is False
    assert page.state == "absent"
    assert page.accepted_events == ()

    # Cross-writer lookup: operations are keyed by (writer_id, request_id). A different writer
    # identity for the same session reports absent rather than leaking another writer's result.
    foreign_writer = "wri_00000000-0000-4000-8000-000000000599"
    assert foreign_writer != seed.writer_id
    # The memory harness routes a single TaskRuntime writer; foreign writer_id cannot be routed
    # without SESSION_CONFLICT. Prove the ledger lookup keying instead (same contract the status
    # application uses before projecting the recovery page).
    assert (
        await app.runtime.task.ledger.lookup_operation(foreign_writer, request.request_id)
    ) is None
    assert (
        await app.runtime.task.ledger.lookup_operation(seed.writer_id, request.request_id)
    ) is not None


async def test_dry_run_appends_nothing_and_leaves_request_id_reusable() -> None:
    """dry_run validates without durable effects; the same request_id still publishes later."""

    app, objects = _composition()
    frontier_before = await app.runtime.task.ledger.load_frontier()
    durable_before = len(objects._data)  # pyright: ignore[reportPrivateUsage]
    request = _request(
        request_tail=601,
        event_tail=602,
        action_tail=603,
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    preview_payload = request.model_dump(mode="json", by_alias=True, exclude_none=True)
    preview_payload["dry_run"] = True
    preview_request = PublishWorkRequestModel.model_validate(preview_payload)

    preview = await execute_publish_work(cast(Application, app), preview_request)

    assert preview.ok is True
    assert preview.outcome == "dry_run"
    assert preview.subject_frontier.sequence == str(frontier_before.sequence)
    assert preview.result_frontier == preview.subject_frontier
    assert type(preview.root) is PublishWorkDryRunModel
    assert preview.root.evidential is False
    assert len(preview.root.would_accept) == 1
    draft0 = cast(dict[str, object], request.event_drafts[0])
    assert preview.root.would_accept[0].event_id == draft0["event_id"]

    frontier_after_preview = await app.runtime.task.ledger.load_frontier()
    assert frontier_after_preview.sequence == frontier_before.sequence
    assert frontier_after_preview.head_digest == frontier_before.head_digest
    assert len(objects._data) == durable_before  # pyright: ignore[reportPrivateUsage]
    assert (
        await app.runtime.task.ledger.lookup_operation(request.writer_id, request.request_id)
    ) is None

    accepted = await execute_publish_work(cast(Application, app), request)
    assert accepted.ok is True
    assert accepted.outcome == "accepted"
    assert accepted.result_frontier.sequence != str(frontier_before.sequence)
    assert (
        await app.runtime.task.ledger.lookup_operation(request.writer_id, request.request_id)
    ) is not None


async def test_dry_run_rejects_duplicate_event_id_like_real_publish() -> None:
    """would_accept must not be a false positive when the event id is already on the ledger."""

    app, _objects = _composition()
    first = _request(
        request_tail=611,
        event_tail=612,
        action_tail=613,
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    accepted = await execute_publish_work(cast(Application, app), first)
    assert accepted.outcome == "accepted"
    frontier = await app.runtime.task.ledger.load_frontier()

    reuse = _request(
        request_tail=614,
        event_tail=612,
        action_tail=615,
        expected_frontier={
            "sequence": str(frontier.sequence),
            "head_digest": frontier.head_digest,
        },
    )
    preview_payload = reuse.model_dump(mode="json", by_alias=True, exclude_none=True)
    preview_payload["dry_run"] = True
    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(preview_payload)
        )
    assert caught.value.code is PublicErrorCode.EVENT_INVALID


async def test_dry_run_rejects_missing_causal_parent_like_real_publish() -> None:
    """A parent that is neither in the ledger nor earlier in the batch cannot would_accept."""

    app, _objects = _composition()
    draft = _draft(event_tail=622, action_tail=623)
    draft["causal_parents"] = ("evt_00000000-0000-4000-8000-000000000999",)
    request = _request(
        request_tail=621,
        event_drafts=(draft,),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    preview_payload = request.model_dump(mode="json", by_alias=True, exclude_none=True)
    preview_payload["dry_run"] = True
    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(preview_payload)
        )
    assert caught.value.code is PublicErrorCode.EVENT_INVALID
    # Real publish fails the same way.
    with pytest.raises(PublicOperationError) as real:
        await execute_publish_work(cast(Application, app), request)
    assert real.value.code is PublicErrorCode.EVENT_INVALID


async def test_unsorted_obligation_ids_match_on_dry_run_and_publish() -> None:
    """A two-member unsorted assignment list is EVENT_INVALID on both dry_run and commit.

    Issue #579: one-element dry_run subsets are trivially sorted, so bisection cannot find the
    set-order rule. Both the preview and the real append must reject the same pointer.
    """

    app, _objects = _composition()
    draft: dict[str, object] = {
        "event_id": "evt_00000000-0000-4000-8000-000000000701",
        "schema": {"name": "assignment_recorded", "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:00.000Z",
        "causal_parents": (),
        "payload": {
            "assignee_actor_id": "harness:test",
            "obligation_ids": (
                "obl_00000000-0000-4000-8000-000000000002",
                "obl_00000000-0000-4000-8000-000000000001",
            ),
            "scope_description": "One independently reviewable work package.",
        },
        "artifact_refs": (),
        "evidence_refs": (),
    }
    request = _request(
        request_tail=700,
        event_drafts=(draft,),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    preview_payload = request.model_dump(mode="json", by_alias=True, exclude_none=True)
    preview_payload["dry_run"] = True
    with pytest.raises(PublicOperationError) as preview:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(preview_payload)
        )
    with pytest.raises(PublicOperationError) as real:
        await execute_publish_work(cast(Application, app), request)

    assert preview.value.code is PublicErrorCode.EVENT_INVALID
    assert real.value.code is PublicErrorCode.EVENT_INVALID
    expected = {
        "continuation": "sorted_set_required",
        "field": "/event_drafts/0/payload/obligation_ids",
        "reason_code": "unsorted_set_field",
    }
    assert dict(preview.value.safe_details) == expected
    assert dict(real.value.safe_details) == expected
    assert "ascending ASCII" in preview.value.message
    assert preview.value.message == real.value.message


async def test_dry_run_frontier_gate_matches_sequence_only_publish_predicate() -> None:
    """Mismatched head_digest with matching sequence is accepted by both dry_run and publish."""

    app, _objects = _composition()
    first = _request(
        request_tail=631,
        event_tail=632,
        action_tail=633,
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    accepted = await execute_publish_work(cast(Application, app), first)
    assert accepted.outcome == "accepted"
    frontier = await app.runtime.task.ledger.load_frontier()
    # Sequence is correct; digest is deliberately wrong (not the acceptance gate for publish).
    second = _request(
        request_tail=634,
        event_tail=635,
        action_tail=636,
        expected_frontier={
            "sequence": str(frontier.sequence),
            "head_digest": "sha256:" + ("ab" * 32),
        },
    )
    preview_payload = second.model_dump(mode="json", by_alias=True, exclude_none=True)
    preview_payload["dry_run"] = True
    preview = await execute_publish_work(
        cast(Application, app), PublishWorkRequestModel.model_validate(preview_payload)
    )
    assert preview.outcome == "dry_run"
    published = await execute_publish_work(cast(Application, app), second)
    assert published.outcome == "accepted"


_OBLIGATION_ID = "obl_00000000-0000-4000-8000-000000000701"
_EVIDENCE_ID = "evd_00000000-0000-4000-8000-000000000702"
_OPEN_MEANING: dict[str, object] = {
    "obligation_id": _OBLIGATION_ID,
    "description": "Close the loop with exact evidence.",
    "acceptance_criteria": "The focused slice is green.",
    "evidence_expectation": "A named test run at the claimed state.",
    "status": "open",
    "requested_items": [{"item_kind": "command", "value": "pytest -q"}],
}


def _obligation_draft(event_tail: int, payload: dict[str, object]) -> dict[str, object]:
    return {
        "event_id": f"evt_00000000-0000-4000-8000-{event_tail:012d}",
        "schema": {"name": "obligation_published", "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:00.000Z",
        "causal_parents": (),
        "payload": payload,
        "artifact_refs": (),
        "evidence_refs": (),
    }


def _evidence_draft(event_tail: int) -> dict[str, object]:
    return {
        "event_id": f"evt_00000000-0000-4000-8000-{event_tail:012d}",
        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:00.000Z",
        "causal_parents": (),
        "payload": {
            "evidence_id": _EVIDENCE_ID,
            "evidence_kind": "test_result",
            "strength": "content_digest",
            "content_digest": "sha256:" + "11" * 32,
            "observed_at": "2026-07-19T12:00:00.000Z",
            "description": "Focused slice result.",
        },
        "artifact_refs": (),
        "evidence_refs": (),
    }


def _typed_evidence_draft(
    event_tail: int,
    *,
    evidence_kind: str,
    digest_subject: str,
    provenance: str = "caller_asserted",
) -> dict[str, object]:
    draft = _evidence_draft(event_tail)
    draft["schema"] = {
        "name": "evidence_recorded",
        "version": "1.2.0" if provenance == "observation_captured" else "1.1.0",
    }
    payload = cast(dict[str, object], draft["payload"])
    payload["evidence_kind"] = evidence_kind
    payload["digest_binding"] = {
        "subject": digest_subject,
        "content_availability": (
            "captured" if provenance == "observation_captured" else "digest_only"
        ),
        "byte_count": 128,
        "provenance": provenance,
    }
    if provenance == "approved_check":
        binding = cast(dict[str, object], payload["digest_binding"])
        binding["approval_commitment"] = "sha256:" + "22" * 32
        binding["approved_check_result_digest"] = "sha256:" + "33" * 32
    elif provenance == "observation_captured":
        payload["strength"] = "immutable_snapshot"
        payload["captured_object_id"] = "obj_00000000-0000-4000-8000-000000000302"
        draft["artifact_refs"] = (payload["captured_object_id"],)
    return draft


@pytest.mark.anyio
async def test_typed_digest_subject_mismatch_and_reserved_provenance_fail_before_staging() -> None:
    app, objects = _composition()
    before = len(objects._data)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValidationError, match="schema_instance_invalid"):
        _request(
            request_tail=690,
            event_drafts=(
                _typed_evidence_draft(
                    691,
                    evidence_kind="test_result",
                    digest_subject="source_diff",
                ),
            ),
            expected_frontier={"sequence": "0", "head_digest": "genesis"},
        )
    assert len(objects._data) == before  # pyright: ignore[reportPrivateUsage]

    reserved = _request(
        request_tail=692,
        event_drafts=(
            _typed_evidence_draft(
                693,
                evidence_kind="test_result",
                digest_subject="test_stdout",
                provenance="approved_check",
            ),
        ),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    with pytest.raises(PublicOperationError) as authority:
        await execute_publish_work(cast(Application, app), reserved)
    assert authority.value.safe_details["reason_code"] == "evidence_digest_provenance_invalid"
    assert len(objects._data) == before  # pyright: ignore[reportPrivateUsage]

    captured = _request(
        request_tail=696,
        event_drafts=(
            _typed_evidence_draft(
                697,
                evidence_kind="artifact",
                digest_subject="bounded_excerpt",
                provenance="observation_captured",
            ),
        ),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    with pytest.raises(PublicOperationError) as captured_authority:
        await execute_publish_work(cast(Application, app), captured)
    assert (
        captured_authority.value.safe_details["reason_code"] == "evidence_digest_provenance_invalid"
    )
    assert len(objects._data) == before  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_honest_source_diff_digest_is_admitted_with_caller_coverage() -> None:
    app, _objects = _composition()
    request = _request(
        request_tail=694,
        event_drafts=(
            _typed_evidence_draft(
                695,
                evidence_kind="artifact",
                digest_subject="source_diff",
            ),
        ),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    result = await execute_publish_work(cast(Application, app), request)
    assert result.outcome == "accepted"
    records = [
        row async for row in app.runtime.task.ledger.load_events(app.runtime.task.session_id)
    ]
    record = records[0]
    assert record.coverage.authorship_assurance.value == "self_asserted"
    assert record.coverage.artifact_observation.value == "published_only"


def _plan_draft(
    event_tail: int,
    *,
    obligation_refs: list[str],
    no_obligations_reason: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "plan_version": 1,
        "summary": "Bounded implementation plan.",
        "obligation_refs": obligation_refs,
    }
    if no_obligations_reason is not None:
        payload["no_obligations_reason"] = no_obligations_reason
    return {
        "event_id": f"evt_00000000-0000-4000-8000-{event_tail:012d}",
        "schema": {"name": "plan_published", "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:00.000Z",
        "causal_parents": (),
        "payload": payload,
        "artifact_refs": (),
        "evidence_refs": (),
    }


def _plan_revision_draft(
    event_tail: int,
    *,
    obligation_id: str,
    no_obligations_reason: str,
) -> dict[str, object]:
    return {
        "event_id": f"evt_00000000-0000-4000-8000-{event_tail:012d}",
        "schema": {"name": "plan_revised", "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:00.000Z",
        "causal_parents": (),
        "payload": {
            "plan_version": 2,
            "supersedes_plan_version": 1,
            "reason": "The scope expanded.",
            "summary": "One obligation now applies.",
            "obligation_changes": [
                {
                    "obligation_id": obligation_id,
                    "change": "carried",
                }
            ],
            "no_obligations_reason": no_obligations_reason,
        },
        "artifact_refs": (),
        "evidence_refs": (),
    }


def _empty_scope_revision_draft(
    event_tail: int,
    *,
    plan_version: int,
    supersedes_plan_version: int,
    no_obligations_reason: str | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "plan_version": plan_version,
        "supersedes_plan_version": supersedes_plan_version,
        "reason": "Restate the current empty completion scope.",
        "summary": "No effective obligation references.",
        "obligation_changes": [],
    }
    if no_obligations_reason is not None:
        payload["no_obligations_reason"] = no_obligations_reason
    return {
        "event_id": f"evt_00000000-0000-4000-8000-{event_tail:012d}",
        "schema": {"name": "plan_revised", "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:00.000Z",
        "causal_parents": (),
        "payload": payload,
        "artifact_refs": (),
        "evidence_refs": (),
    }


async def _publish_open_obligation(app: _Application) -> Frontier:
    request = _request(
        request_tail=701,
        event_drafts=(_obligation_draft(702, dict(_OPEN_MEANING)),),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    result = await execute_publish_work(cast(Application, app), request)
    assert result.outcome == "accepted"
    return await app.runtime.task.ledger.load_frontier()


async def test_obligation_resolution_exact_repeat_is_accepted_on_publish() -> None:
    app, _objects = _composition()
    frontier = await _publish_open_obligation(app)
    resolved: dict[str, object] = {
        **_OPEN_MEANING,
        "status": "resolved",
        "resolution_evidence_refs": [_EVIDENCE_ID],
    }
    request = _request(
        request_tail=703,
        event_drafts=(
            _evidence_draft(704),
            _obligation_draft(705, resolved),
        ),
        expected_frontier={
            "sequence": str(frontier.sequence),
            "head_digest": frontier.head_digest,
        },
    )
    result = await execute_publish_work(cast(Application, app), request)
    assert result.outcome == "accepted"


async def test_obligation_resolution_mismatch_is_identical_on_dry_run_and_publish() -> None:
    """Omitting a meaning field surfaces the same typed public error on both paths."""

    app, _objects = _composition()
    frontier = await _publish_open_obligation(app)
    mismatched: dict[str, object] = {
        "obligation_id": _OBLIGATION_ID,
        "description": _OPEN_MEANING["description"],
        "evidence_expectation": "Shortened expectation.",
        "status": "resolved",
        "resolution_evidence_refs": [_EVIDENCE_ID],
    }
    request = _request(
        request_tail=706,
        event_drafts=(
            _evidence_draft(707),
            _obligation_draft(708, mismatched),
        ),
        expected_frontier={
            "sequence": str(frontier.sequence),
            "head_digest": frontier.head_digest,
        },
    )
    preview_payload = request.model_dump(mode="json", by_alias=True, exclude_none=True)
    preview_payload["dry_run"] = True
    with pytest.raises(PublicOperationError) as dry:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(preview_payload)
        )
    with pytest.raises(PublicOperationError) as durable:
        await execute_publish_work(cast(Application, app), request)

    for caught in (dry, durable):
        error = caught.value
        assert error.code is PublicErrorCode.EVENT_INVALID
        assert error.safe_details["reason_code"] == "obligation_resolution_mismatch"
        assert error.safe_details["field"] == "/event_drafts/1/payload"
        assert "meaning_fields_must_repeat" in error.message
        assert "acceptance_criteria" in error.message
        assert "evidence_expectation" in error.message
        assert "Shortened expectation" not in error.message
        assert "Close the loop" not in error.message
        assert "finishup://guidance/publication-policy.md" in error.message

    assert dict(dry.value.safe_details) == dict(durable.value.safe_details)
    assert dry.value.message == durable.value.message


def _claim_revision_action_draft(event_tail: int, action_tail: int) -> dict[str, object]:
    draft = _draft(event_tail=event_tail, action_tail=action_tail)
    payload = cast(dict[str, object], draft["payload"])
    payload["obligation_refs"] = [_OBLIGATION_ID]
    return draft


def _claim_revision_result_draft(
    event_tail: int,
    *,
    action_tail: int,
    result_tail: int,
) -> dict[str, object]:
    return {
        "event_id": f"evt_00000000-0000-4000-8000-{event_tail:012d}",
        "schema": {"name": "result_recorded", "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:00.000Z",
        "causal_parents": (f"evt_00000000-0000-4000-8000-{event_tail - 1:012d}",),
        "payload": {
            "result_id": f"res_00000000-0000-4000-8000-{result_tail:012d}",
            "action_id": f"act_00000000-0000-4000-8000-{action_tail:012d}",
            "outcome": "partial",
            "summary": "The bounded action completed only in part.",
        },
        "artifact_refs": (),
        "evidence_refs": (),
    }


def _claim_revision_draft(
    event_tail: int,
    *,
    claim_tail: int,
    version: str,
    supporting_refs: list[str],
    limitation_refs: list[str] | None = None,
    supersedes_claim_refs: list[str] | None = None,
    disputes_refs: list[str] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "claim_id": f"clm_00000000-0000-4000-8000-{claim_tail:012d}",
        "claim_kind": "completion",
        "statement": "The declared scope is complete subject to the named limitation.",
        "supporting_refs": supporting_refs,
        "obligation_refs": [_OBLIGATION_ID],
    }
    if limitation_refs is not None:
        payload["limitation_refs"] = limitation_refs
    if supersedes_claim_refs is not None:
        payload["supersedes_claim_refs"] = supersedes_claim_refs
    if disputes_refs is not None:
        payload["disputes_refs"] = disputes_refs
    return {
        "event_id": f"evt_00000000-0000-4000-8000-{event_tail:012d}",
        "schema": {"name": "claim_recorded", "version": version},
        "occurred_at": "2026-07-19T12:00:00.000Z",
        "causal_parents": (),
        "payload": payload,
        "artifact_refs": (),
        "evidence_refs": (),
    }


async def test_partial_result_claim_repair_preflights_and_preserves_history() -> None:
    """The #419 dogfood sequence is repairable without rewriting the overclaim."""

    app, objects = _composition()
    result_ref = "res_00000000-0000-4000-8000-000000000732"
    old_claim = "clm_00000000-0000-4000-8000-000000000733"
    new_claim = "clm_00000000-0000-4000-8000-000000000734"
    initial = _request(
        request_tail=729,
        event_drafts=(
            _obligation_draft(730, dict(_OPEN_MEANING)),
            _claim_revision_action_draft(731, 731),
            _claim_revision_result_draft(732, action_tail=731, result_tail=732),
            _claim_revision_draft(
                733,
                claim_tail=733,
                version="1.0.0",
                supporting_refs=[result_ref],
            ),
        ),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    accepted = await execute_publish_work(cast(Application, app), initial)
    assert accepted.outcome == "accepted"

    seed = append_command()
    status = await execute_status(
        cast(StatusApplication, app),
        StatusRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": "req_00000000-0000-4000-8000-000000000736",
                "session_id": seed.session_id,
                "writer_id": seed.writer_id,
                "view": "results",
                "limit": "10",
                "at_frontier": str(accepted.result_frontier.sequence),
                "actor": {"actor_id": "harness:test", "actor_type": "harness"},
                "client": {
                    "kind": "test_client",
                    "version": "0.1.0",
                    "integration": "local_cli",
                },
            }
        ),
    )
    result_item = cast(StatusResultsPageModel, status.page).items[0]
    assert result_item.result_id == result_ref
    assert result_item.source_event_id == "evt_00000000-0000-4000-8000-000000000732"
    assert result_item.outcome == "partial"

    frontier = await app.runtime.task.ledger.load_frontier()
    incomplete = _request(
        request_tail=735,
        event_drafts=(
            _claim_revision_draft(
                734,
                claim_tail=734,
                version="1.1.0",
                supporting_refs=[],
                limitation_refs=[],
                supersedes_claim_refs=[old_claim],
            ),
        ),
        expected_frontier={
            "sequence": str(frontier.sequence),
            "head_digest": frontier.head_digest,
        },
    )
    incomplete_wire = incomplete.model_dump(mode="json", by_alias=True, exclude_none=True)
    incomplete_wire["dry_run"] = True
    object_count = len(objects._data)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PublicOperationError) as rejected:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(incomplete_wire)
        )
    assert rejected.value.safe_details == {
        "count": 1,
        "field": "/event_drafts/0/payload/limitation_refs",
        "invariant": "limitation_refs_complete",
        "reason_code": "claim_revision_mismatch",
    }
    assert "limitation_refs_complete" in rejected.value.message
    assert len(objects._data) == object_count  # pyright: ignore[reportPrivateUsage]
    assert await app.runtime.task.ledger.load_frontier() == frontier

    disputed = _request(
        request_tail=737,
        event_drafts=(
            _claim_revision_draft(
                737,
                claim_tail=737,
                version="1.1.0",
                supporting_refs=[],
                limitation_refs=[result_ref],
                supersedes_claim_refs=[old_claim],
                disputes_refs=[old_claim],
            ),
        ),
        expected_frontier={
            "sequence": str(frontier.sequence),
            "head_digest": frontier.head_digest,
        },
    )
    disputed_wire = disputed.model_dump(mode="json", by_alias=True, exclude_none=True)
    disputed_wire["dry_run"] = True
    with pytest.raises(PublicOperationError) as contradiction:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(disputed_wire)
        )
    assert contradiction.value.safe_details == {
        "field": "/event_drafts/0/payload/disputes_refs",
        "invariant": "replacement_must_not_dispute",
        "reason_code": "claim_revision_mismatch",
    }
    assert "replacement_must_not_dispute" in contradiction.value.message

    overwrite = _request(
        request_tail=739,
        event_drafts=(
            _claim_revision_draft(
                739,
                claim_tail=733,
                version="1.1.0",
                supporting_refs=[],
                limitation_refs=[result_ref],
                supersedes_claim_refs=[],
            ),
        ),
        expected_frontier={
            "sequence": str(frontier.sequence),
            "head_digest": frontier.head_digest,
        },
    )
    overwrite_wire = overwrite.model_dump(mode="json", by_alias=True, exclude_none=True)
    overwrite_wire["dry_run"] = True
    with pytest.raises(PublicOperationError) as identity:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(overwrite_wire)
        )
    assert identity.value.safe_details == {
        "field": "/event_drafts/0/payload/claim_id",
        "invariant": "claim_id_must_be_fresh",
        "reason_code": "claim_revision_mismatch",
    }
    assert "claim_id_must_be_fresh" in identity.value.message

    corrected = _request(
        request_tail=735,
        event_drafts=(
            _claim_revision_draft(
                734,
                claim_tail=734,
                version="1.1.0",
                supporting_refs=[],
                limitation_refs=[result_ref],
                supersedes_claim_refs=[old_claim],
            ),
        ),
        expected_frontier={
            "sequence": str(frontier.sequence),
            "head_digest": frontier.head_digest,
        },
    )
    corrected_wire = corrected.model_dump(mode="json", by_alias=True, exclude_none=True)
    corrected_wire["dry_run"] = True
    preview = await execute_publish_work(
        cast(Application, app), PublishWorkRequestModel.model_validate(corrected_wire)
    )
    assert preview.outcome == "dry_run"
    repaired = await execute_publish_work(cast(Application, app), corrected)
    assert repaired.outcome == "accepted"

    history = await execute_status(
        cast(StatusApplication, app),
        StatusRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": "req_00000000-0000-4000-8000-000000000745",
                "session_id": seed.session_id,
                "writer_id": seed.writer_id,
                "view": "history",
                "limit": "10",
                "at_frontier": str(repaired.result_frontier.sequence),
                "actor": {"actor_id": "harness:test", "actor_type": "harness"},
                "client": {
                    "kind": "test_client",
                    "version": "0.1.0",
                    "integration": "local_cli",
                },
            }
        ),
    )
    claim_history = tuple(
        (item.event_id, item.schema_version)
        for item in cast(StatusHistoryPageModel, history.page).items
        if item.schema_name == "claim_recorded"
    )
    assert claim_history == (
        ("evt_00000000-0000-4000-8000-000000000733", "1.0.0"),
        ("evt_00000000-0000-4000-8000-000000000734", "1.1.0"),
    )

    records = tuple(
        [record async for record in app.runtime.task.ledger.load_events(seed.session_id)]
    )
    claims = [record.payload for record in records if record.schema.name == "claim_recorded"]
    assert len(claims) == 2
    assert type(claims[0]) is ClaimRecordedPayload
    assert type(claims[1]) is ClaimRecordedPayloadV1_1
    replacement = claims[1]
    assert type(replacement) is ClaimRecordedPayloadV1_1
    assert replacement.claim_id == new_claim
    assert replacement.limitation_refs == (result_ref,)
    assert replacement.supersedes_claim_refs == (old_claim,)

    stale = _request(
        request_tail=738,
        event_drafts=(
            _claim_revision_draft(
                738,
                claim_tail=738,
                version="1.1.0",
                supporting_refs=[],
                limitation_refs=[result_ref],
                supersedes_claim_refs=[old_claim],
            ),
        ),
        expected_frontier={
            "sequence": str(repaired.result_frontier.sequence),
            "head_digest": repaired.result_frontier.head_digest,
        },
    )
    stale_wire = stale.model_dump(mode="json", by_alias=True, exclude_none=True)
    stale_wire["dry_run"] = True
    with pytest.raises(PublicOperationError) as ineffective:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(stale_wire)
        )
    assert ineffective.value.safe_details == {
        "field": "/event_drafts/0/payload/supersedes_claim_refs",
        "invariant": "superseded_claim_must_be_effective",
        "reason_code": "claim_revision_mismatch",
    }
    assert "superseded_claim_must_be_effective" in ineffective.value.message


async def test_claim_replacement_must_change_effective_meaning() -> None:
    app, _objects = _composition()
    old_claim = "clm_00000000-0000-4000-8000-000000000741"
    initial = _request(
        request_tail=740,
        event_drafts=(
            _obligation_draft(740, dict(_OPEN_MEANING)),
            _claim_revision_draft(
                741,
                claim_tail=741,
                version="1.0.0",
                supporting_refs=[],
            ),
        ),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    accepted = await execute_publish_work(cast(Application, app), initial)
    no_op = _request(
        request_tail=742,
        event_drafts=(
            _claim_revision_draft(
                742,
                claim_tail=742,
                version="1.1.0",
                supporting_refs=[],
                limitation_refs=[],
                supersedes_claim_refs=[old_claim],
            ),
        ),
        expected_frontier={
            "sequence": str(accepted.result_frontier.sequence),
            "head_digest": accepted.result_frontier.head_digest,
        },
    )
    wire = no_op.model_dump(mode="json", by_alias=True, exclude_none=True)
    wire["dry_run"] = True
    with pytest.raises(PublicOperationError) as rejected:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(wire)
        )
    assert rejected.value.safe_details == {
        "field": "/event_drafts/0/payload/supersedes_claim_refs",
        "invariant": "replacement_must_change_effective_claim",
        "reason_code": "claim_revision_mismatch",
    }
    assert "replacement_must_change_effective_claim" in rejected.value.message


async def test_claim_replacement_links_a_limitation_whose_action_is_unrecorded() -> None:
    """A result with no readable action scope is task-wide relevant, so it must be linkable.

    Relevance treats an absent or tombstoned action conservatively as task-wide, which makes
    `limitation_refs_complete` demand the result. Rejecting the very same reference from
    `limitation_refs` left no recordable completion claim at all (ADR-025 decision 3).
    """

    app, _objects = _composition()
    result_ref = "res_00000000-0000-4000-8000-000000000751"
    old_claim = "clm_00000000-0000-4000-8000-000000000751"
    partial = _claim_revision_result_draft(751, action_tail=751, result_tail=751)
    partial["causal_parents"] = ()
    initial = _request(
        request_tail=750,
        event_drafts=(
            _obligation_draft(750, dict(_OPEN_MEANING)),
            partial,
            _claim_revision_draft(
                752,
                claim_tail=751,
                version="1.0.0",
                supporting_refs=[result_ref],
            ),
        ),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    accepted = await execute_publish_work(cast(Application, app), initial)
    replacement = _request(
        request_tail=753,
        event_drafts=(
            _claim_revision_draft(
                753,
                claim_tail=752,
                version="1.1.0",
                supporting_refs=[],
                limitation_refs=[result_ref],
                supersedes_claim_refs=[old_claim],
            ),
        ),
        expected_frontier={
            "sequence": str(accepted.result_frontier.sequence),
            "head_digest": accepted.result_frontier.head_digest,
        },
    )
    wire = replacement.model_dump(mode="json", by_alias=True, exclude_none=True)
    wire["dry_run"] = True
    preview = await execute_publish_work(
        cast(Application, app), PublishWorkRequestModel.model_validate(wire)
    )
    assert preview.ok is True
    assert preview.outcome == "dry_run"

    silent = _request(
        request_tail=754,
        event_drafts=(
            _claim_revision_draft(
                754,
                claim_tail=753,
                version="1.1.0",
                supporting_refs=[],
                limitation_refs=[],
                supersedes_claim_refs=[old_claim],
            ),
        ),
        expected_frontier={
            "sequence": str(accepted.result_frontier.sequence),
            "head_digest": accepted.result_frontier.head_digest,
        },
    )
    silent_wire = silent.model_dump(mode="json", by_alias=True, exclude_none=True)
    silent_wire["dry_run"] = True
    with pytest.raises(PublicOperationError) as rejected:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(silent_wire)
        )
    assert rejected.value.safe_details == {
        "count": 1,
        "field": "/event_drafts/0/payload/limitation_refs",
        "invariant": "limitation_refs_complete",
        "reason_code": "claim_revision_mismatch",
    }
    assert "limitation_refs_complete" in rejected.value.message


async def test_no_obligations_reason_conflict_is_identical_on_dry_run_and_publish() -> None:
    """A typed empty-scope reason cannot accompany a positive effective declaration."""

    app, _objects = _composition()
    request = _request(
        request_tail=712,
        event_drafts=(
            _plan_draft(
                713,
                obligation_refs=[_OBLIGATION_ID],
                no_obligations_reason="single_atomic_change",
            ),
        ),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    preview_payload = request.model_dump(mode="json", by_alias=True, exclude_none=True)
    preview_payload["dry_run"] = True
    with pytest.raises(PublicOperationError) as dry:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(preview_payload)
        )
    with pytest.raises(PublicOperationError) as durable:
        await execute_publish_work(cast(Application, app), request)

    for caught in (dry, durable):
        error = caught.value
        assert error.code is PublicErrorCode.EVENT_INVALID
        assert error.safe_details == {
            "reason_code": "no_obligations_reason_conflict",
            "field": "/event_drafts/0/payload/no_obligations_reason",
        }
        assert "single_atomic_change" not in error.message
        assert _OBLIGATION_ID not in error.message

    assert dry.value.message == durable.value.message


async def test_revision_reason_conflict_is_identical_on_dry_run_and_publish() -> None:
    """A revision cannot retain an empty-scope reason while carrying an obligation."""

    app, _objects = _composition()
    initial = _request(
        request_tail=714,
        event_drafts=(
            _plan_draft(
                715,
                obligation_refs=[],
                no_obligations_reason="exploratory_scope_unknown",
            ),
        ),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    accepted = await execute_publish_work(cast(Application, app), initial)
    assert accepted.outcome == "accepted"
    frontier = await app.runtime.task.ledger.load_frontier()

    revision = _request(
        request_tail=716,
        event_drafts=(
            _plan_revision_draft(
                717,
                obligation_id=_OBLIGATION_ID,
                no_obligations_reason="exploratory_scope_unknown",
            ),
        ),
        expected_frontier={
            "sequence": str(frontier.sequence),
            "head_digest": frontier.head_digest,
        },
    )
    preview_payload = revision.model_dump(mode="json", by_alias=True, exclude_none=True)
    preview_payload["dry_run"] = True
    with pytest.raises(PublicOperationError) as dry:
        await execute_publish_work(
            cast(Application, app), PublishWorkRequestModel.model_validate(preview_payload)
        )
    with pytest.raises(PublicOperationError) as durable:
        await execute_publish_work(cast(Application, app), revision)

    for caught in (dry, durable):
        error = caught.value
        assert error.code is PublicErrorCode.EVENT_INVALID
        assert error.safe_details == {
            "reason_code": "no_obligations_reason_conflict",
            "field": "/event_drafts/0/payload/no_obligations_reason",
        }
        assert "exploratory_scope_unknown" not in error.message
        assert _OBLIGATION_ID not in error.message

    assert dry.value.message == durable.value.message


async def test_durable_revisions_add_replace_and_clear_empty_scope_declaration() -> None:
    app, _objects = _composition()
    initial = await execute_publish_work(
        cast(Application, app),
        _request(
            request_tail=718,
            event_drafts=(_plan_draft(719, obligation_refs=[]),),
            expected_frontier={"sequence": "0", "head_digest": "genesis"},
        ),
    )
    assert initial.outcome == "accepted"

    transitions = (
        (2, "no_material_change", 720, 721),
        (3, "single_atomic_change", 722, 723),
        (4, None, 724, 725),
    )
    for plan_version, reason, request_tail, event_tail in transitions:
        frontier = await app.runtime.task.ledger.load_frontier()
        published = await execute_publish_work(
            cast(Application, app),
            _request(
                request_tail=request_tail,
                event_drafts=(
                    _empty_scope_revision_draft(
                        event_tail,
                        plan_version=plan_version,
                        supersedes_plan_version=plan_version - 1,
                        no_obligations_reason=reason,
                    ),
                ),
                expected_frontier={
                    "sequence": str(frontier.sequence),
                    "head_digest": frontier.head_digest,
                },
            ),
        )
        assert published.outcome == "accepted"

        stored = await app.runtime.task.ledger.load_projection(
            app.runtime.task.session_id,
            ProjectionView.CANDIDATE_FINDINGS,
        )
        assert stored is not None
        projection = stored.state
        assert not isinstance(projection, tuple)
        scope = current_plan_scope(projection.plans, projection.coverage_gaps)
        assert scope.declared_obligation_count == 0
        assert (
            None if scope.no_obligations_reason is None else scope.no_obligations_reason.value
        ) == reason


async def test_obligation_resolution_omitting_only_acceptance_criteria_names_that_field() -> None:
    app, _objects = _composition()
    frontier = await _publish_open_obligation(app)
    mismatched: dict[str, object] = {
        "obligation_id": _OBLIGATION_ID,
        "description": _OPEN_MEANING["description"],
        "evidence_expectation": _OPEN_MEANING["evidence_expectation"],
        "status": "resolved",
        "requested_items": _OPEN_MEANING["requested_items"],
        "resolution_evidence_refs": [_EVIDENCE_ID],
    }
    request = _request(
        request_tail=709,
        event_drafts=(
            _evidence_draft(710),
            _obligation_draft(711, mismatched),
        ),
        expected_frontier={
            "sequence": str(frontier.sequence),
            "head_digest": frontier.head_digest,
        },
    )
    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(cast(Application, app), request)
    assert caught.value.safe_details["reason_code"] == "obligation_resolution_mismatch"
    assert "mismatched fields: acceptance_criteria" in caught.value.message


@pytest.mark.parametrize("preview", (True, False))
@pytest.mark.parametrize("missing", (True, False))
async def test_new_completion_scope_is_explicit_before_any_append(
    preview: bool, missing: bool
) -> None:
    app, objects = _composition()
    draft = _claim_revision_draft(
        859,
        claim_tail=859,
        version="1.1.0",
        supporting_refs=[_OBLIGATION_ID],
        limitation_refs=[],
        supersedes_claim_refs=[],
    )
    payload = cast(dict[str, object], draft["payload"])
    if missing:
        del payload["obligation_refs"]
    else:
        payload["obligation_refs"] = []
    request = _request(
        request_tail=859,
        event_drafts=(draft,),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    ).model_copy(update={"dry_run": preview})
    frontier = await app.runtime.task.ledger.load_frontier()
    objects_before = len(objects._data)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(cast(Application, app), request)
    assert caught.value.safe_details == {
        "reason_code": "claim_revision_mismatch",
        "invariant": "completion_scope_must_be_explicit"
        if missing
        else "empty_scope_must_not_support_obligations",
        "field": "/event_drafts/0/payload/obligation_refs",
    }
    assert await app.runtime.task.ledger.load_frontier() == frontier
    assert len(objects._data) == objects_before  # pyright: ignore[reportPrivateUsage]


async def test_explicit_empty_completion_scope_remains_authorable() -> None:
    app, _ = _composition()
    draft = _claim_revision_draft(
        860,
        claim_tail=860,
        version="1.1.0",
        supporting_refs=[],
        limitation_refs=[],
        supersedes_claim_refs=[],
    )
    cast(dict[str, object], draft["payload"])["obligation_refs"] = []
    request = _request(
        request_tail=860,
        event_drafts=(draft,),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    preview = await execute_publish_work(
        cast(Application, app), request.model_copy(update={"dry_run": True})
    )
    assert preview.outcome == "dry_run"
    accepted = await execute_publish_work(cast(Application, app), request)
    assert accepted.outcome == "accepted"


@pytest.mark.parametrize("scoped_replacement", (False, True))
async def test_claim_without_obligation_scope_can_be_corrected(scoped_replacement: bool) -> None:
    """TB4 pilot (finding F): an early claim naming no obligations stays correctable.

    The pilot's own session ran 0.2.5, which rejected this correction with
    ``scope_overlap_required``; an empty-scope target has no scope to overlap, so a replacement
    with either an empty or a populated scope is admitted. A populated target still requires
    overlap (kernel replay tests lock that side).
    """

    app, _ = _composition()
    first = _claim_revision_draft(
        870,
        claim_tail=870,
        version="1.1.0",
        supporting_refs=[],
        limitation_refs=[],
        supersedes_claim_refs=[],
    )
    cast(dict[str, object], first["payload"])["obligation_refs"] = []
    accepted = await execute_publish_work(
        cast(Application, app),
        _request(
            request_tail=870,
            event_drafts=(first,),
            expected_frontier={"sequence": "0", "head_digest": "genesis"},
        ),
    )
    assert accepted.outcome == "accepted"
    correction = _claim_revision_draft(
        871,
        claim_tail=871,
        version="1.1.0",
        supporting_refs=[],
        limitation_refs=[],
        supersedes_claim_refs=["clm_00000000-0000-4000-8000-000000000870"],
    )
    payload = cast(dict[str, object], correction["payload"])
    payload["statement"] = "Corrected: the earlier claim overstated the result."
    if not scoped_replacement:
        payload["obligation_refs"] = []
    frontier = await app.runtime.task.ledger.load_frontier()
    request = _request(
        request_tail=871,
        event_drafts=(correction,),
        expected_frontier={"sequence": str(frontier.sequence), "head_digest": frontier.head_digest},
    )
    preview = await execute_publish_work(
        cast(Application, app), request.model_copy(update={"dry_run": True})
    )
    assert preview.outcome == "dry_run"
    corrected = await execute_publish_work(cast(Application, app), request)
    assert corrected.outcome == "accepted"


@pytest.mark.parametrize("route_field", ("session_id", "writer_id"))
@pytest.mark.parametrize("preview", (True, False))
async def test_empty_scope_correction_keeps_session_and_writer_fences(
    route_field: str, preview: bool
) -> None:
    app, _ = _composition()
    draft = _claim_revision_draft(
        861,
        claim_tail=861,
        version="1.1.0",
        supporting_refs=[],
        limitation_refs=[],
        supersedes_claim_refs=["clm_00000000-0000-4000-8000-000000000860"],
    )
    cast(dict[str, object], draft["payload"])["obligation_refs"] = []
    req = _request(
        request_tail=861,
        event_drafts=(draft,),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    prefix = "ses" if route_field == "session_id" else "wri"
    req = req.model_copy(
        update={route_field: f"{prefix}_00000000-0000-4000-8000-000000000999", "dry_run": preview}
    )
    before = await app.runtime.task.ledger.load_frontier()
    with pytest.raises(PublicOperationError) as caught:
        await execute_publish_work(cast(Application, app), req)
    assert caught.value.code is PublicErrorCode.SESSION_CONFLICT
    assert await app.runtime.task.ledger.load_frontier() == before


async def test_a_plain_obligation_published_as_1_1_0_is_accepted() -> None:
    """tb4n2 cad D (issue #1023): a feature-free obligation at 1.1.0 is admitted.

    1.1.0 is a superset of 1.0.0; before #1023 the exact-version rule refused a plain obligation
    copied from the 1.1.0 template, and 24 of 28 such attempts in the run were rejected.
    """

    app, _objects = _composition()
    draft = _obligation_draft(
        712,
        {
            "obligation_id": "obl_00000000-0000-4000-8000-000000000711",
            "description": "Complete within 28800 seconds",
            "evidence_expectation": "The task finishes inside its time budget.",
            "status": "open",
            "requested_items": [],
        },
    )
    draft["schema"] = {"name": "obligation_published", "version": "1.1.0"}
    request = _request(
        request_tail=713,
        event_drafts=(draft,),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    preview = await execute_publish_work(
        cast(Application, app), request.model_copy(update={"dry_run": True})
    )
    assert preview.outcome == "dry_run"
    result = await execute_publish_work(cast(Application, app), request)
    assert result.outcome == "accepted"


async def test_a_roled_obligation_published_as_1_0_0_names_the_1_1_0_correction() -> None:
    """The application decode path attributes the version refusal to the obligation hint.

    The wire request schema already refuses ``role`` on a 1.0.0 obligation, so the batch is
    swapped in after model validation (``model_copy`` does not revalidate) to reach
    ``_decode_draft`` itself, which must name the 1.1.0 correction (issue #1023).
    """

    app, _objects = _composition()
    roled = _obligation_draft(
        722,
        {
            "obligation_id": "obl_00000000-0000-4000-8000-000000000721",
            "description": "Write the outputs",
            "evidence_expectation": "The produced files",
            "status": "open",
            "requested_items": [{"item_kind": "file", "value": "/app/out.json", "role": "output"}],
        },
    )
    with pytest.raises(ValidationError):
        _request(request_tail=723, event_drafts=(roled,))
    request = _request(
        request_tail=723,
        event_drafts=(_obligation_draft(722, dict(_OPEN_MEANING)),),
        expected_frontier={"sequence": "0", "head_digest": "genesis"},
    )
    for dry_run in (True, False):
        with pytest.raises(PublicOperationError) as caught:
            await execute_publish_work(
                cast(Application, app),
                request.model_copy(update={"event_drafts": (roled,), "dry_run": dry_run}),
            )
        assert caught.value.code is PublicErrorCode.EVENT_INVALID
        details = caught.value.safe_details
        assert details["reason_code"] == "invalid_event_schema"
        assert details["field"] == "/event_drafts/0/payload"
        assert "obligation_published/1.1.0" in caught.value.message
        assert "obligation_published/1.0.0 cannot carry" in caught.value.message
        # The caller's payload text never reaches the error.
        assert "/app/out.json" not in caught.value.message
        assert "/app/out.json" not in repr(dict(details))
