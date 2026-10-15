"""Native start correlation never lets response IDs discover or select a task."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import pytest

from finishup.application.observation_coordinator import ObservationCoordinator
from finishup.cli.observe_hooks import map_hook_payload_to_envelope
from finishup.domain.observation import ObservationEnvelope
from finishup.ports.runtime import TaskRuntime
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id

pytestmark = pytest.mark.anyio


def _callback() -> tuple[dict[str, JsonValue], dict[str, str]]:
    ids = {
        name: new_id(kind)
        for name, kind in (
            ("task_id", IdKind.TASK),
            ("session_id", IdKind.SESSION),
            ("writer_id", IdKind.WRITER),
            ("parent_task_id", IdKind.TASK),
        )
    }
    return {
        "session_id": "native-session",
        "subagent_id": "worker",
        "tool_use_id": "attach-call",
        "parent_tool_call_id": "spawn-call",
        "tool_name": "mcp__finishup__start",
        "tool_response": {"ok": True, "outcome": "attached", **ids},
    }, ids


def _envelope(payload: dict[str, JsonValue]) -> ObservationEnvelope:
    return map_hook_payload_to_envelope(
        "PostToolUse",
        payload,
        session_commitment="hmac-sha256:" + "a" * 64,
        event_ordinal=1,
        key_material=b"k" * 32,
        source_generation=1,
    )


@pytest.mark.parametrize("wrong_field", ["task_id", "session_id", "writer_id", "parent_task_id"])
async def test_bridge_rejects_response_identity_before_recording(wrong_field: str) -> None:
    payload, ids = _callback()
    registry = SimpleNamespace(record_host_lineage_observation=AsyncMock())
    catalog = SimpleNamespace(
        task_lineage=AsyncMock(return_value=SimpleNamespace(parent_task_id=ids["parent_task_id"]))
    )
    coordinator = cast(
        ObservationCoordinator,
        SimpleNamespace(
            host_lineage_registry=registry, lineage_coordinator=SimpleNamespace(catalog=catalog)
        ),
    )
    runtime = cast(
        TaskRuntime,
        SimpleNamespace(
            task_id=ids["task_id"], session_id=ids["session_id"], writer_id=ids["writer_id"]
        ),
    )
    result = cast(dict[str, JsonValue], payload["tool_response"])
    result[wrong_field] = new_id(
        {
            "task_id": IdKind.TASK,
            "session_id": IdKind.SESSION,
            "writer_id": IdKind.WRITER,
            "parent_task_id": IdKind.TASK,
        }[wrong_field]
    )
    gap = await ObservationCoordinator._bind_native_child_start(  # pyright: ignore[reportPrivateUsage]
        coordinator,
        runtime,
        _envelope(payload),
        writer_routes=(),
    )
    assert gap == "host_lineage_identity_conflict"
    registry.record_host_lineage_observation.assert_not_awaited()
    if wrong_field != "parent_task_id":
        catalog.task_lineage.assert_not_awaited()


@pytest.mark.parametrize(
    "identity",
    [
        "missing",
        "conflicting",
        "invalid_parent",
        "invalid_tool_use",
        "invalid_tool_call",
        "conflicting_calls",
        "null_call",
    ],
)
async def test_bridge_missing_native_identity_cannot_make_annotation(identity: str) -> None:
    payload, ids = _callback()
    if identity == "missing":
        payload.pop("subagent_id")
    elif identity == "conflicting":
        payload["agent_id"] = "another-worker"
    elif identity == "invalid_parent":
        payload["parent_tool_call_id"] = {"not": "a-token"}
    elif identity == "conflicting_calls":
        payload["tool_call_id"] = "another-attach-call"
    elif identity == "null_call":
        payload["tool_call_id"] = None
    else:
        payload.pop("parent_tool_call_id")
        payload["tool_use_id" if identity == "invalid_tool_use" else "tool_call_id"] = {
            "not": "a-token"
        }
    registry = SimpleNamespace(record_host_lineage_observation=AsyncMock())
    catalog = SimpleNamespace(
        task_lineage=AsyncMock(return_value=SimpleNamespace(parent_task_id=ids["parent_task_id"]))
    )
    coordinator = cast(
        ObservationCoordinator,
        SimpleNamespace(
            host_lineage_registry=registry, lineage_coordinator=SimpleNamespace(catalog=catalog)
        ),
    )
    runtime = cast(
        TaskRuntime,
        SimpleNamespace(
            task_id=ids["task_id"], session_id=ids["session_id"], writer_id=ids["writer_id"]
        ),
    )
    gap = await ObservationCoordinator._bind_native_child_start(  # pyright: ignore[reportPrivateUsage]
        coordinator,
        runtime,
        _envelope(payload),
        writer_routes=(),
    )
    assert gap == "missing_subagent_identity"
    registry.record_host_lineage_observation.assert_not_awaited()


@pytest.mark.parametrize("parent_call", ["spawn-call", None])
async def test_bridge_uses_admitted_history_and_spawn_call_not_attach_call(
    parent_call: str | None,
) -> None:
    payload, ids = _callback()
    payload["tool_call_id"] = "attach-call"
    if parent_call is None:
        payload.pop("parent_tool_call_id")
    registry = SimpleNamespace(
        record_host_lineage_observation=AsyncMock(
            return_value=SimpleNamespace(correlation_id="corr")
        ),
        bind_provisional_annotation=AsyncMock(),
    )
    catalog = SimpleNamespace(
        task_lineage=AsyncMock(return_value=SimpleNamespace(parent_task_id=ids["parent_task_id"]))
    )
    coordinator = cast(
        ObservationCoordinator,
        SimpleNamespace(
            host_lineage_registry=registry, lineage_coordinator=SimpleNamespace(catalog=catalog)
        ),
    )
    runtime = cast(
        TaskRuntime,
        SimpleNamespace(
            task_id=ids["task_id"],
            session_id=new_id(IdKind.SESSION),
            writer_id=new_id(IdKind.WRITER),
        ),
    )
    gap = await ObservationCoordinator._bind_native_child_start(  # pyright: ignore[reportPrivateUsage]
        coordinator,
        runtime,
        _envelope(payload),
        writer_routes=((ids["session_id"], ids["writer_id"]),),
    )
    assert gap is None
    call = registry.record_host_lineage_observation.await_args
    assert call is not None
    assert call.args[0] == ids["parent_task_id"]
    assert call.args[1].correlation.parent_tool_call_id == parent_call
    registry.bind_provisional_annotation.assert_awaited_once_with(
        ids["parent_task_id"], "corr", ids["task_id"]
    )


def test_only_successful_owned_start_response_supplies_bridge_facts() -> None:
    payload, _ids = _callback()
    envelope = _envelope(payload)
    assert "lineage_child_task_id" in envelope.structural_payload
    variants: tuple[dict[str, JsonValue], ...] = (
        {**payload, "tool_name": "foreign_start"},
        {**payload, "tool_response": {"ok": False}},
        {**payload, "tool_response": {"ok": True, "outcome": "delegated"}},
        {**payload, "tool_response": {}, "lineage_child_task_id": new_id(IdKind.TASK)},
    )
    for changed in variants:
        assert "lineage_child_task_id" not in _envelope(changed).structural_payload


@pytest.mark.parametrize(
    ("disposition", "age", "rotated", "event_kind", "expected"),
    [
        ("accepted", 0, False, "PostToolUse", True),
        ("accepted", 60, False, "PostToolUse", True),
        # A retry whose first ingest committed re-offers the same evidence; lineage applies it
        # idempotently at its own time, so the duplicate is no longer lost as contact (#837).
        ("duplicate", 0, False, "PostToolUse", True),
        # Swept or queued rows arrive after the lease they prove; they are offered with their
        # receipt time rather than dropped by delivery age.
        ("accepted", 61, False, "PostToolUse", True),
        ("accepted", 86_460, False, "PostToolUse", True),
        ("accepted", 86_461, False, "PostToolUse", False),
        ("accepted", -1, False, "PostToolUse", False),
        ("rejected", 0, False, "PostToolUse", False),
        ("accepted", 0, True, "PostToolUse", False),
        ("accepted", 0, False, "SessionEnd", False),
        # End of a turn or of a native child proves the host was alive when it fired.
        ("accepted", 0, False, "SubagentStop", True),
        ("accepted", 0, False, "Stop", True),
    ],
)
async def test_current_native_activity_is_offered_with_its_own_time(
    disposition: str, age: int, rotated: bool, event_kind: str, expected: bool
) -> None:
    from dataclasses import replace
    from datetime import timedelta

    from finishup.application.observation_materialize import observation_writer_id
    from finishup.domain.observation import ObservationIngestDisposition

    payload, ids = _callback()
    envelope = replace(_envelope(payload), event_kind=event_kind)
    hook = AsyncMock()
    coordinator = cast(
        ObservationCoordinator,
        SimpleNamespace(
            observed_activity_hook=hook,
            observed_activity_max_age_seconds=ObservationCoordinator.observed_activity_max_age_seconds,
            clock=SimpleNamespace(
                now_utc=lambda: envelope.receipt_time.as_datetime() + timedelta(seconds=age)
            ),
        ),
    )
    runtime = cast(
        TaskRuntime,
        SimpleNamespace(
            task_id=ids["task_id"],
            writer_id=observation_writer_id(ids["task_id"], ids["session_id"]),
            session_id=new_id(IdKind.SESSION) if rotated else ids["session_id"],
        ),
    )
    await ObservationCoordinator._renew_observed_activity(  # pyright: ignore[reportPrivateUsage]
        coordinator,
        runtime,
        envelope,
        disposition=ObservationIngestDisposition(disposition),
        predecessor_session_id=ids["session_id"],
        predecessor_writer_id=ids["writer_id"],
        route_bound=True,
        workspace="hmac-sha256:" + "a" * 64,
        codex_session_id="native-correlation",
    )
    assert hook.await_count == int(expected)
    if expected:
        hook.assert_awaited_once_with(
            ids["task_id"],
            ids["session_id"],
            ids["writer_id"],
            envelope.receipt_time.as_datetime(),
        )


@pytest.mark.parametrize("parent_alias", ["call-b", {"not": "a-token"}])
def test_subagent_hook_conflicting_parent_alias_cannot_weaken_identity(
    parent_alias: JsonValue,
) -> None:
    from finishup.application.observation_materialize import materialize_observation_envelope
    from finishup.domain.host_lineage import host_lineage_from_envelope

    payload, ids = _callback()
    payload["tool_use_id"] = parent_alias
    envelope = map_hook_payload_to_envelope(
        "SubagentStart",
        payload,
        session_commitment="hmac-sha256:" + "a" * 64,
        event_ordinal=1,
        key_material=b"k" * 32,
        source_generation=1,
    )
    assert host_lineage_from_envelope(envelope) is None
    batch = materialize_observation_envelope(envelope, task_id=ids["task_id"])
    assert batch.skip_reason == "missing_subagent_identity"
    assert batch.drafts == ()


def _child_header_envelope(*, with_identity: bool = True) -> ObservationEnvelope:
    """One v2 child rollout header as the child's own session observes it (issue #754)."""

    from finishup.adapters.importers.codex_jsonl import CodexParsedRecord
    from finishup.adapters.integrations.codex_session_stream import envelope_from_stream_record
    from finishup.adapters.integrations.observation_local import STREAM_MAPPING_VERSION
    from finishup.domain.observation import ObservationCursor
    from finishup.domain.values import JsonObject

    payload: dict[str, JsonValue] = {
        "agent_path": "/root/canary_review",
        "cli_version": "0.153.4",
        "history_mode": "paginated",
        "id": "019f8b27-b98e-7061-bbb5-d0b897594de7",
        "multi_agent_version": "v2",
        "session_id": "019f8b27-b98e-7061-bbb5-d0b897594de6",
        "thread_source": "subagent",
    }
    if with_identity:
        payload["parent_thread_id"] = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    return envelope_from_stream_record(
        CodexParsedRecord(
            1,
            0,
            256,
            "session_meta",
            None,
            JsonObject({"payload": payload, "type": "session_meta"}),
        ),
        session_commitment="hmac-sha256:" + "b" * 64,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=256,
            event_position=1,
            last_source_commitment="hmac-sha256:" + "b" * 64,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
    )


def _child_header_coordinator(
    *, parent_task_id: str | None
) -> tuple[ObservationCoordinator, SimpleNamespace]:
    registry = SimpleNamespace(
        record_host_lineage_observation=AsyncMock(
            return_value=SimpleNamespace(correlation_id="corr")
        ),
        bind_provisional_annotation=AsyncMock(),
    )
    lineage = None if parent_task_id is None else SimpleNamespace(parent_task_id=parent_task_id)
    catalog = SimpleNamespace(task_lineage=AsyncMock(return_value=lineage))
    coordinator = cast(
        ObservationCoordinator,
        SimpleNamespace(
            host_lineage_registry=registry, lineage_coordinator=SimpleNamespace(catalog=catalog)
        ),
    )
    return coordinator, registry


async def test_child_header_start_is_filed_under_the_admitted_parent_and_bound() -> None:
    """The child observes its own delegation, so the parent task comes from catalog lineage."""

    child_task = new_id(IdKind.TASK)
    parent_task = new_id(IdKind.TASK)
    coordinator, registry = _child_header_coordinator(parent_task_id=parent_task)
    runtime = cast(TaskRuntime, SimpleNamespace(task_id=child_task))

    handled, gap = await ObservationCoordinator._bind_child_session_start(  # pyright: ignore[reportPrivateUsage]
        coordinator, runtime, _child_header_envelope()
    )

    assert (handled, gap) == (True, None)
    call = registry.record_host_lineage_observation.await_args
    assert call is not None
    # Never the observing (child) task, and never a host token: the parent is admitted state.
    assert call.args[0] == parent_task
    assert call.args[1].correlation.subagent_id == "019f8b27-b98e-7061-bbb5-d0b897594de7"
    assert call.args[1].correlation.parent_tool_call_id is None
    registry.bind_provisional_annotation.assert_awaited_once_with(parent_task, "corr", child_task)


async def test_child_header_without_admitted_lineage_keeps_a_bounded_gap() -> None:
    coordinator, registry = _child_header_coordinator(parent_task_id=None)
    runtime = cast(TaskRuntime, SimpleNamespace(task_id=new_id(IdKind.TASK)))

    handled, gap = await ObservationCoordinator._bind_child_session_start(  # pyright: ignore[reportPrivateUsage]
        coordinator, runtime, _child_header_envelope()
    )

    assert handled is True
    assert gap == "host_lineage_child_not_found"
    registry.record_host_lineage_observation.assert_not_awaited()
    registry.bind_provisional_annotation.assert_not_awaited()


async def test_child_header_without_identity_annotates_nothing() -> None:
    coordinator, registry = _child_header_coordinator(parent_task_id=new_id(IdKind.TASK))
    runtime = cast(TaskRuntime, SimpleNamespace(task_id=new_id(IdKind.TASK)))
    envelope = _child_header_envelope(with_identity=False)

    handled, gap = await ObservationCoordinator._bind_child_session_start(  # pyright: ignore[reportPrivateUsage]
        coordinator, runtime, envelope
    )

    assert envelope.gap_codes == ("missing_subagent_identity",)
    assert (handled, gap) == (True, None)
    registry.record_host_lineage_observation.assert_not_awaited()


async def test_parent_observed_subagent_activity_stays_on_the_ordinary_path() -> None:
    """A parent's own spawn item is filed against the observing parent task, unbound."""

    from finishup.adapters.importers.codex_jsonl import CodexParsedRecord
    from finishup.adapters.integrations.codex_session_stream import envelope_from_stream_record
    from finishup.adapters.integrations.observation_local import STREAM_MAPPING_VERSION
    from finishup.domain.observation import ObservationCursor
    from finishup.domain.values import JsonObject

    coordinator, registry = _child_header_coordinator(parent_task_id=new_id(IdKind.TASK))
    envelope = envelope_from_stream_record(
        CodexParsedRecord(
            1,
            0,
            256,
            "event_msg",
            "SubAgentActivity",
            JsonObject(
                {
                    "payload": {
                        "item": {
                            "agent_path": "/root/canary_review",
                            "agent_thread_id": "019f8b27-b98e-7061-bbb5-d0b897594de7",
                            "id": "call_CANARY0153SPAWN",
                            "kind": "started",
                            "type": "SubAgentActivity",
                        },
                        "type": "item_completed",
                    },
                    "type": "event_msg",
                }
            ),
        ),
        session_commitment="hmac-sha256:" + "b" * 64,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=256,
            event_position=1,
            last_source_commitment="hmac-sha256:" + "b" * 64,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
    )

    handled, gap = await ObservationCoordinator._bind_child_session_start(  # pyright: ignore[reportPrivateUsage]
        coordinator, cast(TaskRuntime, SimpleNamespace(task_id=new_id(IdKind.TASK))), envelope
    )

    assert envelope.event_kind == "SubagentStart"
    assert (handled, gap) == (False, None)
    registry.record_host_lineage_observation.assert_not_awaited()
