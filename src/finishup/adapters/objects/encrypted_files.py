"""Durable encrypted-file implementation of the immutable object store."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
from finishup.ports.ids import IdPort
from finishup.ports.keys import BundleKeys, WrappedDek
from finishup.ports.objects import (
    MAX_OBJECT_HEADER_BYTES,
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

__all__ = ["EncryptedFilesObjectStore"]

_CHUNK_SIZE: Final = 64 * 1024
_ORPHAN_WINDOW: Final = timedelta(hours=24)
_MAX_FRAME_BYTES: Final = 4 + 1 + 4 + MAX_OBJECT_HEADER_BYTES + 12 + MAX_OBJECT_PLAINTEXT_BYTES + 16
# These are adapter-owned structural failures.  They describe an object that cannot be
# authenticated as the finalized object named by the caller, so they must remain deterministic
# verification failures even though the low-level reader uses ``OSError`` to report them.
_DETERMINISTIC_OPEN_OSERRORS: Final = frozenset(
    {
        "object_file_truncated",
        "object_file_unsafe",
        "object_path_unsafe",
        "object_root_unsafe",
    }
)

type CurrentRootSnapshot = Callable[[], Awaitable[ObjectRootSnapshot]]


def _verification_failed() -> ValueError:
    return ValueError("object_verification_failed")


def _is_environmental_open_fault(exc: BaseException) -> bool:
    """True when a verified open failed because the environment, not the object, is unreadable.

    ``FileNotFoundError`` stays a verification mismatch: a missing id is the same deterministic
    outcome as a digest mismatch, and the object-store port requires ``object_verification_failed``
    for that case. Adapter-owned structural faults (truncation and unsafe finalized-object
    metadata) use ``OSError`` internally but are deterministic verification failures too. Other
    ``OSError`` instances (EIO, permission, and similar host I/O) are environmental and must not
    be collapsed into that token.
    """

    if not isinstance(exc, OSError) or isinstance(exc, FileNotFoundError):
        return False
    return not (exc.errno is None and str(exc) in _DETERMINISTIC_OPEN_OSERRORS)


def root_snapshot_identity(snapshot: ObjectRootSnapshot) -> tuple[object, ...]:
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


async def read_object_source(source: ObjectSource) -> bytes:
    if source.data is not None:
        return source.data
    assert source.stream is not None
    assert source.declared_size is not None
    collected = bytearray()
    async for chunk in source.stream:
        if type(chunk) is not bytes:
            raise ValueError("invalid_object_source")
        if len(chunk) > MAX_OBJECT_PLAINTEXT_BYTES - len(collected):
            collected.clear()
            raise ValueError("object_plaintext_limit_exceeded")
        collected.extend(chunk)
    if len(collected) != source.declared_size:
        collected.clear()
        raise ValueError("object_source_size_mismatch")
    result = bytes(collected)
    collected.clear()
    return result


def created_at_wire(value: datetime) -> str:
    # The reviewed yoetz-object/1 vectors freeze six fractional digits. The value port still
    # enforces millisecond alignment, so the final three digits are always zero.
    format_rfc3339_millis(value)
    normalized = value.astimezone(UTC)
    return (
        f"{normalized.year:04d}-{normalized.month:02d}-{normalized.day:02d}"
        f"T{normalized.hour:02d}:{normalized.minute:02d}:{normalized.second:02d}."
        f"{normalized.microsecond:06d}Z"
    )


def object_ref_from_staged(staged: StagedObject) -> ObjectRef:
    return ObjectRef(
        object_id=staged.object_id,
        plaintext_size=staged.plaintext_size,
        commitment=staged.commitment,
        envelope_digest=staged.envelope_digest,
        encryption_format=staged.encryption_format,
        key_slot=staged.key_slot,
        metadata=staged.metadata,
    )


def same_reference_header(ref: ObjectRef, envelope: ObjectEnvelope) -> bool:
    header = envelope.header
    return (
        header.object_id == ref.object_id
        and header.plaintext_size == ref.plaintext_size
        and header.encryption_format == ref.encryption_format
        and header.key_slot == ref.key_slot
        and header.object_kind is ref.metadata.kind
        and header.media_type == ref.metadata.media_type
        and header.task_id == ref.metadata.task_id
        and header.created_at == created_at_wire(ref.metadata.created_at)
        and header.payload_algorithm == "aes-256-gcm"
        and header.wrap_algorithm == "aes-256-kw-rfc3394"
    )


@dataclass(frozen=True, slots=True)
class _FileStageHandle:
    store_token: object
    temp_path: Path
    final_path: Path
    preexisting: bool = False


@dataclass(slots=True)
class _StageState:
    staged: StagedObject
    finalized: ObjectRef | None = None
    abandoned: bool = False


class EncryptedFilesObjectStore:
    """Publish immutable encrypted objects beneath one validated task-bundle root."""

    def __init__(
        self,
        *,
        bundle_root: Path,
        bundle_keys: BundleKeys,
        secret_memory: SecretMemoryPort,
        id_port: IdPort,
        current_root_snapshot: CurrentRootSnapshot,
    ) -> None:
        if not bundle_root.is_absolute():
            raise ValueError("object_root_invalid")
        if type(bundle_keys) is not BundleKeys:
            raise TypeError("bundle_keys_invalid")
        if not callable(current_root_snapshot):
            raise TypeError("root_snapshot_provider_invalid")
        self._bundle_root = bundle_root
        self._objects_root = bundle_root / "objects"
        self._staging_root = self._objects_root / ".staging"
        self._keys = bundle_keys
        self._secret_memory = secret_memory
        self._id_port = id_port
        self._current_root_snapshot = current_root_snapshot
        self._token = object()
        self._stages: dict[int, _StageState] = {}
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
        plaintext = await read_object_source(source)
        with self._lock:
            self._prepare_directories()
            if object_id is not None:
                try:
                    validate_id(IdKind.OBJECT, object_id)
                except (TypeError, ValueError) as exc:
                    raise ValueError("object_id_invalid") from exc
                final_path = self._path_for(object_id)
                if final_path.exists():
                    try:
                        frame = self._read_private_file(final_path)
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
                    handle = _FileStageHandle(
                        self._token,
                        final_path,
                        final_path,
                        preexisting=True,
                    )
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
                    self._stages[id(handle)] = _StageState(staged, finalized=ref)
                    return staged
                if any(self._staging_root.glob(f"{object_id}.*.tmp")):
                    raise OSError("object_destination_collision")
            else:
                object_id = self._allocate_object_id()
                final_path = self._path_for(object_id)
            payload_nonce = os.urandom(12)
            commitment = self._keys.commitment_key.mac(
                OBJECT_COMMITMENT_DOMAINS[metadata.kind], plaintext
            )
            frame = self._encrypt_frame(object_id, plaintext, payload_nonce, metadata)
            envelope_digest = f"sha256:{hashlib.sha256(frame).hexdigest()}"
            temp_path = self._new_temp_path(object_id)
            self._write_temp(temp_path, frame)
            handle = _FileStageHandle(self._token, temp_path, final_path)
            staged = StagedObject(
                object_id=object_id,
                plaintext_size=len(plaintext),
                commitment=commitment,
                envelope_digest=envelope_digest,
                encryption_format="yoetz-object/1",
                key_slot=self._keys.key_slot,
                metadata=metadata,
                staging_handle=handle,
            )
            self._stages[id(handle)] = _StageState(staged)
            return staged

    async def finalize(self, staged: StagedObject) -> ObjectRef:
        with self._lock:
            state, handle = self._state_for(staged)
            if state.abandoned:
                raise ValueError("abandoned_staged_object")
            if state.finalized is not None:
                return state.finalized
            self._prepare_directories()
            handle.final_path.parent.mkdir(mode=0o700, exist_ok=True)
            self._validate_private_directory(handle.final_path.parent)
            if handle.final_path.exists():
                if self._digest_file(handle.final_path) != staged.envelope_digest:
                    raise OSError("object_destination_collision")
            else:
                self._fsync_file(handle.temp_path)
                os.replace(handle.temp_path, handle.final_path)
            self._fsync_directory(handle.final_path.parent)
            result = object_ref_from_staged(staged)
            state.finalized = result
            return result

    def _remove_stage_path(self, path: Path, envelope_digest: str) -> None:
        try:
            path.lstat()
        except FileNotFoundError:
            return
        self._validate_private_directory(path.parent)
        if self._digest_file(path) != envelope_digest:
            raise OSError("object_destination_collision")
        try:
            path.unlink()
        except FileNotFoundError:
            return
        self._fsync_directory(path.parent)

    async def abandon(self, staged: StagedObject) -> None:
        """Remove one exact caller-owned stage before its reference is durably admitted."""

        with self._lock:
            state, handle = self._state_for(staged)
            if state.abandoned:
                return
            if handle.preexisting:
                # A reserved retry may have resolved an already-finalized object.  That object is
                # owned by the prior attempt and must remain available to the journal replay.
                return
            self._prepare_directories()
            failures: list[OSError] = []
            removed_final = False
            for path in (handle.temp_path, handle.final_path):
                try:
                    self._remove_stage_path(path, staged.envelope_digest)
                except OSError as exc:
                    # Every path gets its own attempt: stopping at the first failure would strand
                    # the finalized orphan this call exists to remove, which is the accumulation
                    # the caller's abandon is there to prevent. The first failure still leaves.
                    failures.append(exc)
                else:
                    removed_final = removed_final or path == handle.final_path
            if removed_final:
                state.finalized = None
            if failures:
                # The stage stays un-abandoned so a later retry re-attempts both paths.
                raise failures[0]
            state.abandoned = True

    async def _open_verified_bytes(self, ref: ObjectRef) -> bytes:
        if type(ref) is not ObjectRef or ref.key_slot != self._keys.key_slot:
            raise _verification_failed()
        path = self._path_for(ref.object_id)
        try:
            self._validate_object_path(path)
            frame = self._read_private_file(path)
            observed_digest = f"sha256:{hashlib.sha256(frame).hexdigest()}"
            if observed_digest != ref.envelope_digest:
                raise _verification_failed()
            envelope = decode_object_envelope(frame)
            if not same_reference_header(ref, envelope):
                raise _verification_failed()
            wrapped = WrappedDek("aes-256-kw-rfc3394", envelope.header.wrapped_dek)
            dek = self._keys.wrap_key.unwrap_dek(wrapped)

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
        except (OSError, TypeError, ValueError) as exc:
            if _is_environmental_open_fault(exc):
                raise
            if isinstance(exc, ValueError) and str(exc) == "object_verification_failed":
                raise
            raise _verification_failed() from exc

    async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
        """Reconstruct and authenticate one exact catalog-pinned object reference."""

        try:
            path = self._path_for(object_id)
            self._validate_object_path(path)
            frame = self._read_private_file(path)
            observed_digest = f"sha256:{hashlib.sha256(frame).hexdigest()}"
            if observed_digest != envelope_digest:
                raise _verification_failed()
            envelope = decode_object_envelope(frame)
            header = envelope.header
            if header.object_id != object_id or header.key_slot != self._keys.key_slot:
                raise _verification_failed()
            wrapped = WrappedDek("aes-256-kw-rfc3394", header.wrapped_dek)
            dek = self._keys.wrap_key.unwrap_dek(wrapped)

            def _decrypt(key: memoryview) -> bytes:
                return AESGCM(key).decrypt(
                    envelope.payload_nonce,
                    envelope.ciphertext + envelope.tag,
                    envelope.header_bytes,
                )

            plaintext = dek.consume(SecretConsumer.OBJECT_CRYPTO, _decrypt)
            if len(plaintext) != header.plaintext_size:
                raise _verification_failed()
            commitment = self._keys.commitment_key.mac(
                OBJECT_COMMITMENT_DOMAINS[header.object_kind], plaintext
            )
            metadata = ObjectMetadata(
                header.object_kind,
                header.media_type,
                header.task_id,
                header.created_at_datetime,
            )
            return ObjectRef(
                object_id=header.object_id,
                plaintext_size=header.plaintext_size,
                commitment=commitment,
                envelope_digest=envelope_digest,
                encryption_format=header.encryption_format,
                key_slot=header.key_slot,
                metadata=metadata,
            )
        except InvalidTag as exc:
            raise _verification_failed() from exc
        except (OSError, TypeError, ValueError) as exc:
            if _is_environmental_open_fault(exc):
                raise
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
        expected = root_snapshot_identity(root_snapshot)
        await self._require_current_snapshot(expected)
        cutoff = now.timestamp() - _ORPHAN_WINDOW.total_seconds()
        candidates = self._orphan_candidates(root_snapshot, cutoff)
        removed = 0
        for path in candidates:
            await self._require_current_snapshot(expected)
            self._validate_private_directory(path.parent)
            if not self._eligible_regular_file(path, cutoff):
                continue
            try:
                path.unlink()
            except FileNotFoundError:
                continue
            removed += 1
            self._fsync_directory(path.parent)
        await self._require_current_snapshot(expected)
        return removed

    async def _require_current_snapshot(self, expected: tuple[object, ...]) -> None:
        current = await self._current_root_snapshot()
        if type(current) is not ObjectRootSnapshot or root_snapshot_identity(current) != expected:
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
                created_at=created_at_wire(metadata.created_at),
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

    def _prepare_directories(self) -> None:
        self._validate_private_directory(self._bundle_root)
        self._objects_root.mkdir(mode=0o700, exist_ok=True)
        self._validate_private_directory(self._objects_root)
        self._staging_root.mkdir(mode=0o700, exist_ok=True)
        self._validate_private_directory(self._staging_root)

    @staticmethod
    def _validate_private_directory(path: Path) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError as exc:
            raise OSError("object_root_missing") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise OSError("object_root_unsafe")

    def _allocate_object_id(self) -> str:
        for _ in range(128):
            candidate = self._id_port.new(IdKind.OBJECT)
            validate_id(IdKind.OBJECT, candidate)
            if not self._path_for(candidate).exists() and not any(
                self._staging_root.glob(f"{candidate}.*.tmp")
            ):
                return candidate
        raise OSError("object_id_collision")

    def _path_for(self, object_id: str) -> Path:
        validate_id(IdKind.OBJECT, object_id)
        shard = object_id[4:6]
        return self._objects_root / shard / object_id

    def _validate_object_path(self, path: Path) -> None:
        self._validate_private_directory(self._bundle_root)
        self._validate_private_directory(self._objects_root)
        if path.parent.parent != self._objects_root:
            raise OSError("object_path_unsafe")
        try:
            self._validate_private_directory(path.parent)
        except OSError as exc:
            # A never-written object_id has no shard directory. That is a missing object, not a
            # missing store root, so verified open must keep the port's verification token.
            if str(exc) == "object_root_missing":
                raise FileNotFoundError from exc
            raise

    def _new_temp_path(self, object_id: str) -> Path:
        for _ in range(128):
            path = self._staging_root / f"{object_id}.{os.urandom(16).hex()}.tmp"
            if not path.exists():
                return path
        raise OSError("object_staging_collision")

    @staticmethod
    def _write_temp(path: Path, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            view = memoryview(data)
            written = 0
            while written < len(view):
                written += os.write(descriptor, view[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _fsync_file(path: Path) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("object_file_unsafe")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _read_private_file(path: Path) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size > _MAX_FRAME_BYTES
            ):
                raise OSError("object_file_unsafe")
            chunks: list[bytes] = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(descriptor, min(_CHUNK_SIZE, remaining))
                if not chunk:
                    raise OSError("object_file_truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    @classmethod
    def _digest_file(cls, path: Path) -> str:
        return f"sha256:{hashlib.sha256(cls._read_private_file(path)).hexdigest()}"

    def _state_for(self, staged: StagedObject) -> tuple[_StageState, _FileStageHandle]:
        if type(staged) is not StagedObject or type(staged.staging_handle) is not _FileStageHandle:
            raise ValueError("foreign_staged_object")
        handle = staged.staging_handle
        if handle.store_token is not self._token:
            raise ValueError("foreign_staged_object")
        state = self._stages.get(id(handle))
        if state is None or state.staged is not staged:
            raise ValueError("foreign_staged_object")
        return state, handle

    def _orphan_candidates(
        self, root_snapshot: ObjectRootSnapshot, cutoff_timestamp: float
    ) -> tuple[Path, ...]:
        live_ids = frozenset(root_snapshot.live_object_ids)
        candidates: list[Path] = []
        self._validate_private_directory(self._bundle_root)
        if not self._objects_root.exists():
            return ()
        self._validate_private_directory(self._objects_root)
        if self._staging_root.exists():
            self._validate_private_directory(self._staging_root)
            for path in self._staging_root.iterdir():
                pieces = path.name.split(".")
                if len(pieces) != 3 or pieces[2] != "tmp" or pieces[0] in live_ids:
                    continue
                if self._eligible_regular_file(path, cutoff_timestamp):
                    candidates.append(path)
        if self._objects_root.is_dir():
            for shard in self._objects_root.iterdir():
                if shard.name == ".staging" or len(shard.name) != 2:
                    continue
                try:
                    self._validate_private_directory(shard)
                except OSError:
                    continue
                for path in shard.iterdir():
                    if path.name in live_ids:
                        continue
                    try:
                        validate_id(IdKind.OBJECT, path.name)
                    except (TypeError, ValueError):
                        continue
                    if path.parent.name != path.name[4:6]:
                        continue
                    if self._eligible_regular_file(path, cutoff_timestamp):
                        candidates.append(path)
        return tuple(sorted(candidates, key=lambda item: os.fsencode(item)))

    @staticmethod
    def _eligible_regular_file(path: Path, cutoff_timestamp: float) -> bool:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        return (
            stat.S_ISREG(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) & 0o077 == 0
            and info.st_mtime <= cutoff_timestamp
        )
