"""Deterministic ledger adapter builders shared by storage/conformance tests."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import cast

import apsw

from builders.replay import replay_records
from finishup.adapters.memory.importer import MemoryImportState
from finishup.adapters.memory.ledger import MemoryLedgerAdapter, MemoryLedgerState
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.domain.events import EventDraft, EventPayload
from finishup.domain.values import parse_rfc3339_millis
from finishup.ports.ledger import AppendCommand, AppendEntry, OperationKind
from finishup.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectRootSnapshot,
    ObjectSource,
    StagedObject,
)
from finishup.ports.runtime import OwnershipFence
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind


class FixedClock:
    def now_utc(self) -> datetime:
        return datetime(2026, 7, 19, 12, 0, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 1.0


class FixedIds:
    def __init__(self) -> None:
        self._next = 100

    def new(self, kind: IdKind) -> str:
        self._next += 1
        return PREFIX_BY_KIND[kind] + str(uuid.UUID(int=self._next, version=4))


class MemoryObjects:
    def __init__(self, ids: FixedIds) -> None:
        self._ids = ids
        self._data: dict[str, bytes] = {}
        self._refs: dict[str, ObjectRef] = {}

    def refs_for_kind(self, kind: ObjectKind) -> tuple[ObjectRef, ...]:
        """Expose finalized references to tests without leaking mutable storage."""

        return tuple(ref for ref in self._refs.values() if ref.metadata.kind is kind)

    async def commitment_for(self, data: bytes, kind: ObjectKind) -> str:
        del kind
        return "hmac-sha256:" + hashlib.sha256(data).hexdigest()

    async def stage(
        self, source: ObjectSource, metadata: ObjectMetadata, *, object_id: str | None = None
    ) -> StagedObject:
        assert source.data is not None
        object_id = object_id if object_id is not None else self._ids.new(IdKind.OBJECT)
        if object_id in self._data and self._data[object_id] != source.data:
            raise ValueError("object_identity_conflict")
        commitment = await self.commitment_for(source.data, metadata.kind)
        self._data[object_id] = source.data
        return StagedObject(
            object_id,
            len(source.data),
            commitment,
            "sha256:" + hashlib.sha256(b"envelope" + source.data).hexdigest(),
            "yoetz-object/1",
            "slot-1",
            metadata,
            object(),
        )

    async def finalize(self, staged: StagedObject) -> ObjectRef:
        ref = ObjectRef(
            staged.object_id,
            staged.plaintext_size,
            staged.commitment,
            staged.envelope_digest,
            staged.encryption_format,
            staged.key_slot,
            staged.metadata,
        )
        self._refs[ref.object_id] = ref
        return ref

    async def abandon(self, staged: StagedObject) -> None:
        self._data.pop(staged.object_id, None)
        self._refs.pop(staged.object_id, None)

    async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
        ref = self._refs[object_id]
        if ref.envelope_digest != envelope_digest:
            raise ValueError("object_verification_failed")
        return ref

    async def _open(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        yield self._data[ref.object_id]

    def open_verified(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        return self._open(ref)

    async def sweep_orphans(self, root_snapshot: ObjectRootSnapshot, now: datetime) -> int:
        del root_snapshot, now
        return 0


def ownership_fence(*, generation: int = 1, nonce: str = "ledger-test-nonce") -> OwnershipFence:
    return OwnershipFence("svc_00000000-0000-4000-8000-000000000001", generation, generation, nonce)


def append_command(*, request_suffix: str = "1") -> AppendCommand:
    record = replay_records("projection-rebuild")[0]
    assert record.payload is not None
    draft = EventDraft(
        record.event_id,
        record.schema,
        record.occurred_at,
        record.causal_parents,
        cast(EventPayload, record.payload),
        record.artifact_refs,
        record.evidence_refs,
    )
    metadata = ObjectMetadata(
        ObjectKind.EVENT_PAYLOAD,
        record.payload_ref.media_type,
        record.task_id,
        parse_rfc3339_millis(record.ledger.accepted_at.wire),
    )
    ref = ObjectRef(
        record.payload_ref.object_id,
        record.payload_ref.plaintext_size,
        record.payload_ref.commitment,
        "sha256:" + "1" * 64,
        "yoetz-object/1",
        "slot-1",
        metadata,
    )
    return AppendCommand(
        record.task_id,
        record.session_id,
        record.writer.writer_id,
        f"req_00000000-0000-4000-8000-00000000000{request_suffix}",
        OperationKind.PUBLISH_WORK,
        "sha256:" + "2" * 64,
        0,
        (
            AppendEntry(
                draft,
                record.author,
                ref,
                ref.commitment,
                metadata.media_type,
                ref.plaintext_size,
                record.publication_channel,
                record.coverage,
                "projected",
            ),
        ),
    )


def memory_adapter(command: AppendCommand) -> MemoryLedgerAdapter:
    ids = FixedIds()
    return MemoryLedgerAdapter(
        task_id=command.task_id,
        ownership_fence=ownership_fence(),
        state=MemoryLedgerState(),
        import_state=MemoryImportState(),
        transaction_lock=asyncio.Lock(),
        clock=FixedClock(),
        ids=ids,
        objects=MemoryObjects(ids),
    )


def sqlite_adapter(command: AppendCommand, db: apsw.Connection | None = None) -> SqliteLedger:
    connection = apsw.Connection(":memory:") if db is None else db
    if connection.execute("PRAGMA user_version").fetchone() == (0,):
        initialize_bundle(
            connection,
            {
                "task_id": command.task_id,
                "owner_generation": "1",
                "owner_nonce": "ledger-test-nonce",
            },
        )
    ids = FixedIds()
    return SqliteLedger(
        db=connection,
        task_id=command.task_id,
        ownership_fence=ownership_fence(),
        clock=FixedClock(),
        ids=ids,
        objects=MemoryObjects(ids),
    )
