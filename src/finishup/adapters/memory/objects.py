"""In-memory reference implementation of the encrypted object store."""

from __future__ import annotations

import hashlib
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Final, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from finishup.adapters.objects.envelope import (
    ObjectEnvelope,
    ObjectEnvelopeHeader,
    decode_object_envelope,
    encode_object_envelope,
)
from finishup.domain.values import format_rfc3339_millis
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.keys import BundleKeys, WrappedDek
from finishup.ports.objects import (
    OBJECT_COMMITMENT_DOMAINS,
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectRootSnapshot,
    ObjectSource,
    StagedObject,
)
from finishup.ports.secret_memory import SecretConsumer, SecretMemoryPort, SecretPurpose
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id
from finishup.protocol.models import MAX_OBJECT_PLAINTEXT_BYTES

__all__ = ["MemoryObjectStore"]

_CHUNK_SIZE: Final = 64 * 1024
_ORPHAN_WINDOW: Final = timedelta(hours=24)

type CurrentRootSnapshot = Callable[[], Awaitable[ObjectRootSnapshot]]


def _verification_failed() -> ValueError:
    return ValueError("object_verification_failed")


async def _read_object_source(source: ObjectSource) -> bytes:
    if source.data is not None:
        return source.data
    assert source.stream is not None
    assert source.declared_size is not None
    collected = bytearray()
    async for chunk in source.stream:
        if type(chunk) is not bytes:
            raise ValueError("invalid_object_source")
        collected.extend(chunk)
        if len(collected) > MAX_OBJECT_PLAINTEXT_BYTES:
            collected.clear()
            raise ValueError("object_plaintext_limit_exceeded")
    if len(collected) != source.declared_size:
        collected.clear()
        raise ValueError("object_source_size_mismatch")
    result = bytes(collected)
    collected.clear()
    return result


def _created_at_wire(value: datetime) -> str:
    format_rfc3339_millis(value)
    normalized = value.astimezone(UTC)
    return (
        f"{normalized.year:04d}-{normalized.month:02d}-{normalized.day:02d}"
        f"T{normalized.hour:02d}:{normalized.minute:02d}:{normalized.second:02d}."
        f"{normalized.microsecond:06d}Z"
    )


def _object_ref_from_staged(staged: StagedObject) -> ObjectRef:
    return ObjectRef(
        object_id=staged.object_id,
        plaintext_size=staged.plaintext_size,
        commitment=staged.commitment,
        envelope_digest=staged.envelope_digest,
        encryption_format=staged.encryption_format,
        key_slot=staged.key_slot,
        metadata=staged.metadata,
    )


def _same_reference_header(ref: ObjectRef, envelope: ObjectEnvelope) -> bool:
    header = envelope.header
    return (
        header.object_id == ref.object_id
        and header.plaintext_size == ref.plaintext_size
        and header.encryption_format == ref.encryption_format
        and header.key_slot == ref.key_slot
        and header.object_kind is ref.metadata.kind
        and header.media_type == ref.metadata.media_type
        and header.task_id == ref.metadata.task_id
        and header.created_at == _created_at_wire(ref.metadata.created_at)
        and header.payload_algorithm == "aes-256-gcm"
        and header.wrap_algorithm == "aes-256-kw-rfc3394"
    )


def _root_snapshot_identity(snapshot: ObjectRootSnapshot) -> tuple[object, ...]:
    return (
        snapshot.task_id,
        snapshot.route_identity_digest,
        snapshot.route_generation,
        snapshot.bundle_generation,
        snapshot.privacy_root_generation,
        snapshot.ledger_roots_digest,
        snapshot.importer_roots_digest,
        snapshot.privacy_roots_digest,
        snapshot.maintenance_pin_digest,
        snapshot.live_object_ids,
    )


@dataclass(frozen=True, slots=True)
class _MemoryStageHandle:
    store_token: object
    preexisting: bool = False


@dataclass(slots=True)
class _MemoryRecord:
    staged: StagedObject
    frame: bytes
    recorded_at: datetime
    finalized: ObjectRef | None = None
    abandoned: bool = False


class MemoryObjectStore:
    """Protocol oracle with the same envelope, key, and verification rules as files."""

    def __init__(
        self,
        *,
        bundle_keys: BundleKeys,
        secret_memory: SecretMemoryPort,
        clock: ClockPort,
        id_port: IdPort,
        current_root_snapshot: CurrentRootSnapshot,
    ) -> None:
        if type(bundle_keys) is not BundleKeys:
            raise TypeError("bundle_keys_invalid")
        if not callable(current_root_snapshot):
            raise TypeError("root_snapshot_provider_invalid")
        self._keys = bundle_keys
        self._secret_memory = secret_memory
        self._clock = clock
        self._id_port = id_port
        self._current_root_snapshot = current_root_snapshot
        self._token = object()
        self._staging: dict[int, _MemoryRecord] = {}
        self._durable: dict[str, _MemoryRecord] = {}
        self._allocated_ids: set[str] = set()
        self._lock = RLock()

    async def commitment_for(self, data: bytes, kind: ObjectKind) -> str:
        if type(data) is not bytes or len(data) > MAX_OBJECT_PLAINTEXT_BYTES:
            raise ValueError("invalid_object_source")
        if type(kind) is not ObjectKind:
            raise ValueError("invalid_object_kind")
        return self._keys.commitment_key.mac(OBJECT_COMMITMENT_DOMAINS[kind], data)

    async def stage(
        self,
        source: ObjectSource,
        metadata: ObjectMetadata,
        *,
        object_id: str | None = None,
    ) -> StagedObject:
        if type(source) is not ObjectSource or type(metadata) is not ObjectMetadata:
            raise ValueError("invalid_object_stage")
        if metadata.kind is ObjectKind.IMPORT_STDERR:
            raise ProtocolValueError("commitment_only_object_kind")
        plaintext = await _read_object_source(source)
        recorded_at = self._clock.now_utc()
        format_rfc3339_millis(recorded_at)
        if object_id is not None:
            try:
                validate_id(IdKind.OBJECT, object_id)
            except (TypeError, ValueError) as exc:
                raise ValueError("object_id_invalid") from exc
            with self._lock:
                existing = self._durable.get(object_id)
                if existing is not None:
                    frame = existing.frame
                else:
                    frame = None
            if frame is not None:
                try:
                    envelope = decode_object_envelope(frame)
                    header = envelope.header
                    if (
                        header.object_id != object_id
                        or header.object_kind is not metadata.kind
                        or header.media_type != metadata.media_type
                        or header.task_id != metadata.task_id
                        or header.plaintext_size != len(plaintext)
                    ):
                        raise ValueError("object_destination_collision")
                    commitment = self._keys.commitment_key.mac(
                        OBJECT_COMMITMENT_DOMAINS[metadata.kind], plaintext
                    )
                    ref = ObjectRef(
                        object_id=object_id,
                        plaintext_size=header.plaintext_size,
                        commitment=commitment,
                        envelope_digest=f"sha256:{hashlib.sha256(frame).hexdigest()}",
                        encryption_format=header.encryption_format,
                        key_slot=header.key_slot,
                        metadata=ObjectMetadata(
                            header.object_kind,
                            header.media_type,
                            header.task_id,
                            header.created_at_datetime,
                        ),
                    )
                    observed = await self._open_verified_bytes(ref)
                    if observed != plaintext:
                        raise ValueError("object_destination_collision")
                except (TypeError, ValueError) as exc:
                    if str(exc) == "object_destination_collision":
                        raise
                    raise ValueError("object_destination_collision") from exc
                with self._lock:
                    assert existing is not None
                    handle = _MemoryStageHandle(self._token, preexisting=True)
                    staged = StagedObject(
                        object_id=ref.object_id,
                        plaintext_size=ref.plaintext_size,
                        commitment=ref.commitment,
                        envelope_digest=ref.envelope_digest,
                        encryption_format=ref.encryption_format,
                        key_slot=ref.key_slot,
                        metadata=ref.metadata,
                        staging_handle=handle,
                    )
                    existing.staged = staged
                    existing.finalized = ref
                    self._staging[id(handle)] = existing
                    return staged
        with self._lock:
            allocated_object_id = object_id or self._allocate_object_id()
            if object_id is not None:
                if object_id in self._allocated_ids or object_id in self._durable:
                    raise ValueError("object_destination_collision")
                self._allocated_ids.add(object_id)
            try:
                payload_nonce = os.urandom(12)
                commitment = self._keys.commitment_key.mac(
                    OBJECT_COMMITMENT_DOMAINS[metadata.kind], plaintext
                )
                frame = self._encrypt_frame(allocated_object_id, plaintext, payload_nonce, metadata)
                handle = _MemoryStageHandle(self._token)
                staged = StagedObject(
                    object_id=allocated_object_id,
                    plaintext_size=len(plaintext),
                    commitment=commitment,
                    envelope_digest=f"sha256:{hashlib.sha256(frame).hexdigest()}",
                    encryption_format="yoetz-object/1",
                    key_slot=self._keys.key_slot,
                    metadata=metadata,
                    staging_handle=handle,
                )
                self._staging[id(handle)] = _MemoryRecord(staged, frame, recorded_at)
                return staged
            except Exception:
                self._allocated_ids.discard(allocated_object_id)
                raise

    async def finalize(self, staged: StagedObject) -> ObjectRef:
        with self._lock:
            record = self._record_for(staged)
            if record.abandoned:
                raise ValueError("abandoned_staged_object")
            if record.finalized is not None:
                return record.finalized
            if staged.object_id in self._durable:
                raise ValueError("object_destination_collision")
            result = _object_ref_from_staged(staged)
            record.finalized = result
            self._durable[staged.object_id] = record
            return result

    async def abandon(self, staged: StagedObject) -> None:
        """Forget one caller-owned stage that has not been admitted to a durable root."""

        with self._lock:
            record = self._record_for(staged)
            if record.abandoned:
                return
            if cast(_MemoryStageHandle, staged.staging_handle).preexisting:
                return
            durable = self._durable.get(staged.object_id)
            if durable is not None and durable is not record:
                raise ValueError("object_destination_collision")
            self._durable.pop(staged.object_id, None)
            self._allocated_ids.discard(staged.object_id)
            # Parity with the file store, which unlinks both the temp and the final path: the
            # staged bytes go too, not only the durable admission. The record itself stays so a
            # repeat abandon is idempotent and a later finalize still fails closed, mirroring the
            # file store's retained ``_StageState``; the orphan sweep never revisits it.
            record.frame = b""
            record.finalized = None
            record.abandoned = True

    async def _open_verified_bytes(self, ref: ObjectRef) -> bytes:
        if type(ref) is not ObjectRef or ref.key_slot != self._keys.key_slot:
            raise _verification_failed()
        with self._lock:
            record = self._durable.get(ref.object_id)
            frame = None if record is None else record.frame
        if frame is None:
            raise _verification_failed()
        try:
            if f"sha256:{hashlib.sha256(frame).hexdigest()}" != ref.envelope_digest:
                raise _verification_failed()
            envelope = decode_object_envelope(frame)
            if not _same_reference_header(ref, envelope):
                raise _verification_failed()
            dek = self._keys.wrap_key.unwrap_dek(
                WrappedDek("aes-256-kw-rfc3394", envelope.header.wrapped_dek)
            )

            def _decrypt(key: memoryview) -> bytes:
                return AESGCM(key).decrypt(
                    envelope.payload_nonce,
                    envelope.ciphertext + envelope.tag,
                    envelope.header_bytes,
                )

            plaintext = dek.consume(SecretConsumer.OBJECT_CRYPTO, _decrypt)
            if len(plaintext) != ref.plaintext_size:
                raise _verification_failed()
            commitment = self._keys.commitment_key.mac(
                OBJECT_COMMITMENT_DOMAINS[ref.metadata.kind], plaintext
            )
            if commitment != ref.commitment:
                raise _verification_failed()
            return plaintext
        except InvalidTag as exc:
            raise _verification_failed() from exc

    async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
        """Resolve one durable reference only under its catalog-pinned envelope digest."""

        try:
            validate_id(IdKind.OBJECT, object_id)
            with self._lock:
                record = self._durable.get(object_id)
                ref = None if record is None else record.finalized
            if ref is None or ref.envelope_digest != envelope_digest:
                raise _verification_failed()
            await self._open_verified_bytes(ref)
            return ref
        except (TypeError, ValueError) as exc:
            if isinstance(exc, ValueError) and str(exc) == "object_verification_failed":
                raise
            raise _verification_failed() from exc

    async def _verified_chunks(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        plaintext = await self._open_verified_bytes(ref)
        for start in range(0, len(plaintext), _CHUNK_SIZE):
            yield plaintext[start : start + _CHUNK_SIZE]

    def open_verified(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        return self._verified_chunks(ref)

    async def sweep_orphans(self, root_snapshot: ObjectRootSnapshot, now: datetime) -> int:
        if type(root_snapshot) is not ObjectRootSnapshot:
            raise ValueError("object_root_snapshot_invalid")
        format_rfc3339_millis(now)
        expected = _root_snapshot_identity(root_snapshot)
        await self._require_current_snapshot(expected)
        cutoff = now - _ORPHAN_WINDOW
        live_ids = frozenset(root_snapshot.live_object_ids)
        with self._lock:
            staged_candidates = tuple(
                key
                for key, record in self._staging.items()
                if not record.abandoned
                and record.finalized is None
                and record.staged.object_id not in live_ids
                and record.recorded_at <= cutoff
            )
            durable_candidates = tuple(
                object_id
                for object_id, record in self._durable.items()
                if object_id not in live_ids and record.recorded_at <= cutoff
            )
        removed = 0
        for key in staged_candidates:
            await self._require_current_snapshot(expected)
            with self._lock:
                record = self._staging.get(key)
                if (
                    record is None
                    or record.finalized is not None
                    or record.staged.object_id in live_ids
                ):
                    continue
                del self._staging[key]
                self._allocated_ids.discard(record.staged.object_id)
                removed += 1
        for object_id in durable_candidates:
            await self._require_current_snapshot(expected)
            with self._lock:
                if object_id not in self._durable or object_id in live_ids:
                    continue
                record = self._durable.pop(object_id)
                self._allocated_ids.discard(object_id)
                self._staging.pop(id(record.staged.staging_handle), None)
                removed += 1
        await self._require_current_snapshot(expected)
        return removed

    async def _require_current_snapshot(self, expected: tuple[object, ...]) -> None:
        current = await self._current_root_snapshot()
        if type(current) is not ObjectRootSnapshot or _root_snapshot_identity(current) != expected:
            raise RuntimeError("object_root_snapshot_changed")

    def _encrypt_frame(
        self,
        object_id: str,
        plaintext: bytes,
        payload_nonce: bytes,
        metadata: ObjectMetadata,
    ) -> bytes:
        source = bytearray(os.urandom(32))
        dek = self._secret_memory.capture(SecretPurpose.OBJECT_PAYLOAD, source)

        def _encrypt(key: memoryview) -> bytes:
            wrap_copy = self._secret_memory.capture(SecretPurpose.OBJECT_PAYLOAD, bytearray(key))
            wrapped = self._keys.wrap_key.wrap_dek(wrap_copy)
            header = ObjectEnvelopeHeader(
                created_at=_created_at_wire(metadata.created_at),
                encryption_format="yoetz-object/1",
                key_slot=self._keys.key_slot,
                media_type=metadata.media_type,
                object_id=object_id,
                object_kind=metadata.kind,
                payload_algorithm="aes-256-gcm",
                plaintext_size=len(plaintext),
                task_id=metadata.task_id,
                wrap_algorithm="aes-256-kw-rfc3394",
                wrapped_dek=wrapped.wrapped,
            )
            aad = canonical_encode(cast(JsonValue, header.to_json()))
            encrypted = AESGCM(key).encrypt(payload_nonce, plaintext, aad)
            return encode_object_envelope(header, payload_nonce, encrypted[:-16], encrypted[-16:])

        return dek.consume(SecretConsumer.OBJECT_CRYPTO, _encrypt)

    def _allocate_object_id(self) -> str:
        for _ in range(128):
            candidate = self._id_port.new(IdKind.OBJECT)
            validate_id(IdKind.OBJECT, candidate)
            if candidate not in self._allocated_ids:
                self._allocated_ids.add(candidate)
                return candidate
        raise ValueError("object_id_collision")

    def _record_for(self, staged: StagedObject) -> _MemoryRecord:
        if (
            type(staged) is not StagedObject
            or type(staged.staging_handle) is not _MemoryStageHandle
        ):
            raise ValueError("foreign_staged_object")
        handle = staged.staging_handle
        if handle.store_token is not self._token:
            raise ValueError("foreign_staged_object")
        record = self._staging.get(id(handle))
        if record is None or record.staged is not staged:
            raise ValueError("foreign_staged_object")
        return record
