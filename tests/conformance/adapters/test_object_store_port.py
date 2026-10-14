"""Object-store conformance parity across memory and encrypted files."""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from finishup.adapters.memory.objects import MemoryObjectStore
from finishup.adapters.objects.encrypted_files import EncryptedFilesObjectStore
from finishup.ports.keys import BundleKeys, WrappedDek
from finishup.ports.objects import (
    OBJECT_COMMITMENT_DOMAINS,
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectRootSnapshot,
    ObjectSource,
)
from finishup.ports.secret_memory import (
    SecretConsumer,
    SecretMemoryCapability,
    SecretPurpose,
)
from finishup.protocol.ids import IdKind

if TYPE_CHECKING:
    from finishup.ports.secret_memory import SecretHandle

_DIGEST = "sha256:" + "0" * 64
_TASK_ID = "tsk_30000000-0000-4000-8000-000000000001"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Secret:
    def __init__(self, value: bytes | bytearray) -> None:
        self._value = bytearray(value)
        self._consumed = False

    @property
    def purpose(self) -> SecretPurpose:
        return SecretPurpose.OBJECT_PAYLOAD

    def consume[T](self, consumer: SecretConsumer, fn: Callable[[memoryview], T]) -> T:
        if consumer is not SecretConsumer.OBJECT_CRYPTO or self._consumed:
            raise ValueError("secret_handle_invalid")
        self._consumed = True
        try:
            return fn(memoryview(self._value))
        finally:
            self._value[:] = b"\0" * len(self._value)


class _SecretMemory:
    def capability(self) -> SecretMemoryCapability:
        return SecretMemoryCapability("active", "unavailable", "unavailable", "active", "active")

    def capture(self, purpose: SecretPurpose, source: bytearray) -> _Secret:
        assert purpose is SecretPurpose.OBJECT_PAYLOAD
        result = _Secret(source)
        source[:] = b"\0" * len(source)
        return result

    def allocate(self, purpose: SecretPurpose, size: int) -> _Secret:
        assert purpose is SecretPurpose.OBJECT_PAYLOAD
        return _Secret(bytes(size))

    def close(self) -> None:
        return None


class _WrapKey:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def wrap_dek(self, dek: SecretHandle) -> WrappedDek:
        wrapped = dek.consume(
            SecretConsumer.OBJECT_CRYPTO,
            lambda value: aes_key_wrap(self._key, bytes(value)),
        )
        return WrappedDek("aes-256-kw-rfc3394", wrapped)

    def unwrap_dek(self, wrapped: WrappedDek) -> _Secret:
        return _Secret(aes_key_unwrap(self._key, wrapped.wrapped))


class _MacKey:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def mac(self, domain: bytes, message: bytes) -> str:
        return "hmac-sha256:" + hmac.new(self._key, domain + message, hashlib.sha256).hexdigest()


class _Ids:
    def __init__(self) -> None:
        self._next = 1

    def new(self, kind: IdKind) -> str:
        assert kind is IdKind.OBJECT
        value = f"obj_{self._next:08x}-0000-4000-8000-000000000001"
        self._next += 1
        return value


class _Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def now_utc(self) -> datetime:
        return self.now

    def monotonic_seconds(self) -> float:
        return 0.0


class _Roots:
    def __init__(self, value: ObjectRootSnapshot) -> None:
        self.value = value

    async def current(self) -> ObjectRootSnapshot:
        return self.value


def _snapshot(now: datetime, live: tuple[str, ...] = ()) -> ObjectRootSnapshot:
    return ObjectRootSnapshot(
        task_id=_TASK_ID,
        route_identity_digest=_DIGEST,
        route_generation=1,
        bundle_generation=1,
        privacy_root_generation=0,
        ledger_roots_digest=_DIGEST,
        importer_roots_digest=_DIGEST,
        privacy_roots_digest=_DIGEST,
        maintenance_pin_digest=_DIGEST,
        captured_at=now,
        live_object_ids=live,
    )


def _stores(tmp_path: Path, now: datetime) -> tuple[MemoryObjectStore, EncryptedFilesObjectStore]:
    tmp_path.chmod(0o700)
    roots = _Roots(_snapshot(now))
    keys = BundleKeys("bmk-1", _WrapKey(bytes(range(32))), _MacKey(bytes(range(32, 64))))
    memory = MemoryObjectStore(
        bundle_keys=keys,
        secret_memory=_SecretMemory(),
        clock=_Clock(now),
        id_port=_Ids(),
        current_root_snapshot=roots.current,
    )
    files = EncryptedFilesObjectStore(
        bundle_root=tmp_path,
        bundle_keys=keys,
        secret_memory=_SecretMemory(),
        id_port=_Ids(),
        current_root_snapshot=roots.current,
    )
    return memory, files


async def _read(ref: ObjectRef, store: MemoryObjectStore | EncryptedFilesObjectStore) -> bytes:
    return b"".join([chunk async for chunk in store.open_verified(ref)])


async def _source_chunks() -> AsyncIterator[bytes]:
    yield b"\0FINISHUP"
    yield b"\xff synthetic object payload\n"


@pytest.mark.anyio
async def test_stage_finalize_open_parity(tmp_path: Path) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    stores = _stores(tmp_path, now)
    metadata = ObjectMetadata(
        ObjectKind.CAPTURED_CONTENT, "application/octet-stream", _TASK_ID, now
    )
    plaintext = b"\0FINISHUP\xff synthetic object payload\n"

    results: list[tuple[str, bytes]] = []
    for store in stores:
        expected = await store.commitment_for(plaintext, metadata.kind)
        staged = await store.stage(ObjectSource(data=plaintext), metadata)
        ref = await store.finalize(staged)
        assert await store.finalize(staged) == ref
        results.append((ref.commitment, await _read(ref, store)))
        assert ref.commitment == expected

        repeated = await store.finalize(
            await store.stage(
                ObjectSource(stream=_source_chunks(), declared_size=len(plaintext)),
                metadata,
            )
        )
        assert repeated.object_id != ref.object_id
        assert repeated.envelope_digest != ref.envelope_digest
        assert repeated.commitment == ref.commitment
        assert await _read(repeated, store) == plaintext

    assert results == [(results[0][0], plaintext), (results[0][0], plaintext)]


@pytest.mark.anyio
async def test_abandon_removes_unadmitted_staged_and_finalized_objects(tmp_path: Path) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    metadata = ObjectMetadata(ObjectKind.RECEIPT, "application/json", _TASK_ID, now)
    for store in _stores(tmp_path, now):
        staged = await store.stage(ObjectSource(data=b"{}"), metadata)
        ref = await store.finalize(staged)

        await store.abandon(staged)
        await store.abandon(staged)

        with pytest.raises(ValueError, match="object_verification_failed"):
            await _read(ref, store)
        # The bytes are gone now, not merely unreferenced: the catalog-pinned resume path must
        # not resolve an abandoned object on either adapter.
        with pytest.raises(ValueError, match="object_verification_failed"):
            await store.resolve_verified(ref.object_id, ref.envelope_digest)
        with pytest.raises(ValueError, match="abandoned_staged_object"):
            await store.finalize(staged)

        unfinalized = await store.stage(ObjectSource(data=b'{"next":true}'), metadata)
        await store.abandon(unfinalized)
        with pytest.raises(ValueError, match="abandoned_staged_object"):
            await store.finalize(unfinalized)


@pytest.mark.anyio
async def test_abandon_leaves_no_staged_bytes_behind(tmp_path: Path) -> None:
    """The file store unlinks the temp path; the memory oracle must not keep the frame.

    Residency is not visible through ``ObjectStorePort`` on either adapter, so the two stores are
    each checked where their bytes actually live: the staging directory for files, the staging
    record for memory. Without this, the memory oracle silently retains every abandoned frame and
    ``sweep_orphans`` never reclaims it, because it skips records already marked abandoned.
    """

    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    metadata = ObjectMetadata(ObjectKind.RECEIPT, "application/json", _TASK_ID, now)
    memory, files = _stores(tmp_path, now)

    memory_staged = await memory.stage(ObjectSource(data=b"{}"), metadata)
    await memory.finalize(memory_staged)
    await memory.abandon(memory_staged)
    residual = memory._staging  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    assert [record.frame for record in residual.values()] == [b""]

    files_staged = await files.stage(ObjectSource(data=b"{}"), metadata)
    await files.finalize(files_staged)
    await files.abandon(files_staged)
    assert not tuple((tmp_path / "objects" / ".staging").iterdir())


@pytest.mark.anyio
async def test_failure_atomicity_parity(tmp_path: Path) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    metadata = ObjectMetadata(ObjectKind.IMPORT_STDERR, "text/plain", _TASK_ID, now)
    for store in _stores(tmp_path, now):
        commitment = await store.commitment_for(b"stderr", ObjectKind.IMPORT_STDERR)
        assert commitment.startswith("hmac-sha256:")
        with pytest.raises(ValueError, match="commitment_only_object_kind"):
            await store.stage(ObjectSource(data=b"stderr"), metadata)


@pytest.mark.anyio
async def test_redaction_and_missing_object_parity(tmp_path: Path) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    metadata = ObjectMetadata(ObjectKind.RECEIPT, "application/json", _TASK_ID, now)
    for store in _stores(tmp_path, now):
        staged = await store.stage(ObjectSource(data=b"{}"), metadata)
        ref = await store.finalize(staged)
        missing = ObjectRef(
            object_id="obj_ffffffff-0000-4000-8000-000000000001",
            plaintext_size=ref.plaintext_size,
            commitment=ref.commitment,
            envelope_digest=ref.envelope_digest,
            encryption_format=ref.encryption_format,
            key_slot=ref.key_slot,
            metadata=ref.metadata,
        )
        with pytest.raises(ValueError, match="object_verification_failed"):
            await _read(missing, store)


@pytest.mark.anyio
async def test_catalog_pinned_resolution_requires_exact_id_and_envelope_digest(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    metadata = ObjectMetadata(ObjectKind.START_RESULT, "application/json", _TASK_ID, now)
    for store in _stores(tmp_path, now):
        ref = await store.finalize(await store.stage(ObjectSource(data=b"{}"), metadata))
        assert await store.resolve_verified(ref.object_id, ref.envelope_digest) == ref
        with pytest.raises(ValueError, match="object_verification_failed"):
            await store.resolve_verified(ref.object_id, "sha256:" + "f" * 64)
        with pytest.raises(ValueError, match="object_verification_failed"):
            await store.resolve_verified(
                "obj_ffffffff-0000-4000-8000-000000000001",
                ref.envelope_digest,
            )


@pytest.mark.anyio
async def test_generation_fenced_sweep_parity(tmp_path: Path) -> None:
    now = datetime(2026, 3, 5, 5, 6, 7, tzinfo=UTC)
    roots = _Roots(_snapshot(now))
    keys = BundleKeys("bmk-1", _WrapKey(bytes(range(32))), _MacKey(bytes(range(32, 64))))
    memory_clock = _Clock(now - timedelta(days=2))
    tmp_path.chmod(0o700)
    stores: tuple[MemoryObjectStore, EncryptedFilesObjectStore] = (
        MemoryObjectStore(
            bundle_keys=keys,
            secret_memory=_SecretMemory(),
            clock=memory_clock,
            id_port=_Ids(),
            current_root_snapshot=roots.current,
        ),
        EncryptedFilesObjectStore(
            bundle_root=tmp_path,
            bundle_keys=keys,
            secret_memory=_SecretMemory(),
            id_port=_Ids(),
            current_root_snapshot=roots.current,
        ),
    )
    metadata = ObjectMetadata(
        ObjectKind.PRIVACY_AUDIT,
        "application/vnd.yoetz.privacy-audit+json",
        _TASK_ID,
        now - timedelta(days=2),
    )
    refs: list[ObjectRef] = []
    for store in stores:
        ref = await store.finalize(await store.stage(ObjectSource(data=b"{}"), metadata))
        refs.append(ref)
    file_path = tmp_path / "objects" / refs[1].object_id[4:6] / refs[1].object_id
    old = (now - timedelta(days=2)).timestamp()
    os.utime(file_path, (old, old))

    roots.value = _snapshot(now, tuple(sorted((refs[0].object_id,), key=str.encode)))
    assert await stores[0].sweep_orphans(roots.value, now) == 0
    roots.value = _snapshot(now, tuple(sorted((refs[1].object_id,), key=str.encode)))
    assert await stores[1].sweep_orphans(roots.value, now) == 0

    roots.value = _snapshot(now)
    assert await stores[0].sweep_orphans(roots.value, now) == 1
    assert await stores[1].sweep_orphans(roots.value, now) == 1

    stale = roots.value
    roots.value = ObjectRootSnapshot(
        task_id=stale.task_id,
        route_identity_digest=stale.route_identity_digest,
        route_generation=2,
        bundle_generation=stale.bundle_generation,
        privacy_root_generation=stale.privacy_root_generation,
        ledger_roots_digest=stale.ledger_roots_digest,
        importer_roots_digest=stale.importer_roots_digest,
        privacy_roots_digest=stale.privacy_roots_digest,
        maintenance_pin_digest=stale.maintenance_pin_digest,
        captured_at=stale.captured_at,
        live_object_ids=stale.live_object_ids,
    )
    for store in stores:
        with pytest.raises(RuntimeError, match="object_root_snapshot_changed"):
            await store.sweep_orphans(stale, now)


def test_commitment_domain_fixture_shape() -> None:
    assert len(OBJECT_COMMITMENT_DOMAINS) == len(ObjectKind) == 19
    assert all(value.endswith(b"\0") for value in OBJECT_COMMITMENT_DOMAINS.values())
    assert OBJECT_COMMITMENT_DOMAINS[ObjectKind.PROJECT_TEXT] == b"yoetz/object/project_text/v1\0"
    assert (
        OBJECT_COMMITMENT_DOMAINS[ObjectKind.CHANGE_CAPTURE] == b"yoetz/object/change_capture/v1\0"
    )
