"""Long-session checkpoints survive the object cap and SQLite restart without sleeps."""

from __future__ import annotations

from dataclasses import replace
from typing import Literal, cast

import pytest

import finishup.adapters.objects.check_resume as resume_module
from builders.ledger_adapters import (
    FixedClock,
    MemoryObjects,
    append_command,
    memory_adapter,
    ownership_fence,
    sqlite_adapter,
)
from builders.start_application import protocol_id
from finishup.adapters.memory.ledger import load_frozen_case_from_resume
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.domain.events import DecisionRecordedPayload, EventDraft, EventSchema, encode_payload
from finishup.domain.findings import CheckVerdict, RankedFindings
from finishup.domain.values import actor_id, event_id
from finishup.kernel.deterministic_checks import deterministic_case_to_json
from finishup.ports.ledger import AppendEntry, CheckPhase, CheckPolicyExecution, FrozenCase
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from finishup.protocol.canonical import canonical_encode, strict_json_parse
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import MAX_OBJECT_PLAINTEXT_BYTES, SemanticReason, SemanticStatus
from finishup.protocol.recovery import directive_for

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("kind", ("memory", "sqlite"))
async def test_long_ledger_freezes_reopens_and_commits_past_four_mib(
    kind: Literal["memory", "sqlite"],
) -> None:
    command = append_command()
    adapter = memory_adapter(command) if kind == "memory" else sqlite_adapter(command)
    objects = adapter._objects  # pyright: ignore[reportPrivateUsage]
    assert isinstance(objects, MemoryObjects)
    await adapter.append_batch(command)
    template = command.entries[0]
    clock = FixedClock()
    # 40 valid records exceed 4 MiB of ledger payloads. Each request and event remains
    # below its own bound; it is the cumulative checkpoint that used to fail in ObjectSource.
    for batch in range(10):
        entries: list[AppendEntry] = []
        for offset in range(4):
            number = 10_000 + batch * 4 + offset
            payload = DecisionRecordedPayload(
                f"decision {number} " + "s" * 8_100,
                "r" * 8_192,
                actor_id(template.author.actor_id),
                alternatives=tuple(str(i) + "a" * 8_190 for i in range(12)),
            )
            data = canonical_encode(encode_payload(payload))
            ref = await objects.finalize(
                await objects.stage(
                    ObjectSource(data=data),
                    ObjectMetadata(
                        ObjectKind.EVENT_PAYLOAD,
                        "application/vnd.yoetz.decision_recorded+json",
                        command.task_id,
                        clock.now_utc(),
                    ),
                )
            )
            entries.append(
                replace(
                    template,
                    draft=EventDraft(
                        event_id(protocol_id("evt_", number)),
                        EventSchema("decision_recorded", "1.0.0"),
                        template.draft.occurred_at,
                        (),
                        payload,
                        (),
                        (),
                    ),
                    payload_object=ref,
                    payload_commitment=ref.commitment,
                    media_type=ref.metadata.media_type,
                    plaintext_size=ref.plaintext_size,
                )
            )
        await adapter.append_batch(
            replace(
                command,
                operation_id=protocol_id("req_", 20_000 + batch),
                expected_frontier=1 + batch * 4,
                entries=tuple(entries),
            )
        )
    request_id = protocol_id("req_", 30_000)
    digest = "sha256:" + "9" * 64
    frozen = await adapter.freeze_case(
        command.session_id, command.writer_id, 41, request_id, digest
    )
    assert isinstance(frozen, FrozenCase)
    case_json = deterministic_case_to_json(frozen.case)
    canonical_case = canonical_encode(case_json)
    assert len(canonical_case) > MAX_OBJECT_PLAINTEXT_BYTES
    # Identify the growing component: the retained projection alone exceeds one object.
    assert len(canonical_encode(case_json["projection"])) > MAX_OBJECT_PLAINTEXT_BYTES
    operation = await adapter.lookup_operation(command.writer_id, request_id)
    assert operation is not None and operation.resume_object_ref is not None
    root = operation.resume_object_ref
    raw = b"".join([part async for part in objects.open_verified(root)])
    manifest = strict_json_parse(raw)
    assert isinstance(manifest, dict) and manifest["schema"] == "yoetz.check-resume-pages/1"
    pages = objects.refs_for_kind(ObjectKind.CHECK_RESUME)
    assert len(pages) >= 3
    assert all(ref.plaintext_size <= MAX_OBJECT_PLAINTEXT_BYTES for ref in pages)
    if isinstance(adapter, SqliteLedger):
        db = adapter._db  # pyright: ignore[reportPrivateUsage]
        inventoried = {
            row[0] for row in db.execute("SELECT object_id FROM objects WHERE state='present'")
        }
        assert {ref.object_id for ref in pages} <= inventoried
        # Restart recovers solely through the durable root, not an in-memory frozen case.
        adapter = SqliteLedger(
            db=db,
            task_id=command.task_id,
            ownership_fence=ownership_fence(),
            clock=clock,
            ids=objects._ids,  # pyright: ignore[reportPrivateUsage]
            objects=objects,
        )
        operation = await adapter.lookup_operation(command.writer_id, request_id)
        assert operation is not None
    reopened = await load_frozen_case_from_resume(
        objects, operation, task=command.task_id, session=command.session_id
    )
    assert canonical_encode(deterministic_case_to_json(reopened)) == canonical_case
    # Advance and commit a real verdict; completed same-ID replay must remain exact.
    local_ref = await objects.finalize(
        await objects.stage(
            ObjectSource(data=b"{}"),
            ObjectMetadata(
                ObjectKind.DETERMINISTIC_RESULT,
                "application/vnd.yoetz.deterministic-result+json",
                command.task_id,
                clock.now_utc(),
            ),
        )
    )
    lease = await adapter.advance_check_phase(
        frozen.lease, CheckPhase.RESERVED, CheckPhase.LOCAL_READY, local_ref
    )
    lease = await adapter.advance_check_phase(
        lease, CheckPhase.LOCAL_READY, CheckPhase.READY_TO_FINALIZE
    )
    committed = await adapter.commit_check_if_current(
        FrozenCase(reopened, lease),
        RankedFindings((), 0, CheckVerdict.NO_ISSUE_DETECTED, template.coverage),
        (CheckPolicyExecution("work-integrity", "0.3.0", "run", "completed"),),
        SemanticStatus.NOT_REQUESTED,
        SemanticReason.DETERMINISTIC_MODE,
        None,
        request_id,
    )
    assert committed.outcome == "committed"
    replay = await adapter.freeze_case(
        command.session_id, command.writer_id, 41, request_id, digest
    )
    assert replay == replace(committed, outcome="replayed")


async def test_resume_capacity_is_typed_before_staging(monkeypatch: pytest.MonkeyPatch) -> None:
    command = append_command()
    adapter = memory_adapter(command)
    objects = adapter._objects  # pyright: ignore[reportPrivateUsage]
    assert isinstance(objects, MemoryObjects)
    await adapter.append_batch(command)
    monkeypatch.setattr(resume_module, "MAX_CHECK_RESUME_BYTES", 1)
    with pytest.raises(PublicOperationError) as caught:
        await adapter.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            protocol_id("req_", 40_000),
            "sha256:" + "9" * 64,
        )
    error = caught.value
    assert error.code is PublicErrorCode.LIMIT_EXCEEDED
    assert not error.retryable
    assert error.safe_details["reason_code"] == "check_resume_capacity_exceeded"
    assert error.safe_details["continuation"] == "check_capacity_handoff"
    assert cast(int, error.safe_details["count"]) > cast(int, error.safe_details["limit"])
    assert directive_for("check_capacity_handoff") is not None
    assert await adapter.lookup_operation(command.writer_id, protocol_id("req_", 40_000)) is None
    assert objects.refs_for_kind(ObjectKind.CHECK_RESUME) == ()
