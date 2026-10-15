"""Generation-fenced object garbage collection behavior."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from finishup.adapters.objects.encrypted_files import EncryptedFilesObjectStore
from finishup.ports.keys import BundleKeys, WrappedDek
from finishup.ports.objects import (
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

_TASK_ID = "tsk_30000000-0000-4000-8000-000000000001"
_DIGEST = "sha256:" + "0" * 64


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


class SecretMemoryForObjectTest:
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


class WrapKeyForObjectTest:
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


class MacKeyForObjectTest:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def mac(self, domain: bytes, message: bytes) -> str:
        return "hmac-sha256:" + hmac.new(self._key, domain + message, hashlib.sha256).hexdigest()


class IdsForObjectTest:
    def __init__(self) -> None:
        self._next = 32

    def new(self, kind: IdKind) -> str:
        assert kind is IdKind.OBJECT
        result = f"obj_{self._next:08x}-0000-4000-8000-000000000001"
        self._next += 1
        return result


class RootsForObjectTest:
    def __init__(self, value: ObjectRootSnapshot) -> None:
        self.value = value

    async def current(self) -> ObjectRootSnapshot:
        return self.value


def object_snapshot(now: datetime, live: tuple[str, ...] = ()) -> ObjectRootSnapshot:
    return ObjectRootSnapshot(
        _TASK_ID,
        _DIGEST,
        1,
        1,
        0,
        _DIGEST,
        _DIGEST,
        _DIGEST,
        _DIGEST,
        now,
        live,
    )


def _store(
    tmp_path: Path, current_roots: Callable[[], Awaitable[ObjectRootSnapshot]]
) -> EncryptedFilesObjectStore:
    tmp_path.chmod(0o700)
    return EncryptedFilesObjectStore(
        bundle_root=tmp_path,
        bundle_keys=BundleKeys(
            "bmk-1",
            WrapKeyForObjectTest(bytes(range(32))),
            MacKeyForObjectTest(bytes(range(32, 64))),
        ),
        secret_memory=SecretMemoryForObjectTest(),
        id_port=IdsForObjectTest(),
        current_root_snapshot=current_roots,
    )


def _publish(
    store: EncryptedFilesObjectStore,
    metadata: ObjectMetadata,
    data: bytes,
) -> ObjectRef:
    return asyncio.run(store.finalize(asyncio.run(store.stage(ObjectSource(data=data), metadata))))


def _age_file(tmp_path: Path, ref: ObjectRef, at: datetime) -> Path:
    path = tmp_path / "objects" / ref.object_id[4:6] / ref.object_id
    timestamp = at.timestamp()
    os.utime(path, (timestamp, timestamp))
    return path


def test_gc_keeps_live_refs_and_pins(tmp_path: Path) -> None:
    now = datetime(2026, 3, 6, 5, 6, 7, tzinfo=UTC)
    roots = RootsForObjectTest(object_snapshot(now))
    store = _store(tmp_path, roots.current)
    metadata = ObjectMetadata(
        ObjectKind.CAPTURED_CONTENT,
        "application/octet-stream",
        _TASK_ID,
        now - timedelta(days=2),
    )
    live = _publish(store, metadata, b"live")
    orphan = _publish(store, metadata, b"orphan")
    _age_file(tmp_path, live, now - timedelta(days=2))
    orphan_path = _age_file(tmp_path, orphan, now - timedelta(days=2))
    roots.value = object_snapshot(now, (live.object_id,))

    assert asyncio.run(store.sweep_orphans(roots.value, now)) == 1
    assert not orphan_path.exists()

    async def read_live() -> bytes:
        return b"".join([chunk async for chunk in store.open_verified(live)])

    assert asyncio.run(read_live()) == b"live"


def test_gc_keeps_catalog_privacy_roots_without_ledger_inventory(tmp_path: Path) -> None:
    now = datetime(2026, 3, 6, 5, 6, 7, tzinfo=UTC)
    roots = RootsForObjectTest(object_snapshot(now))
    store = _store(tmp_path, roots.current)
    metadata = ObjectMetadata(
        ObjectKind.PRIVACY_AUDIT,
        "application/vnd.yoetz.privacy-audit+json",
        _TASK_ID,
        now - timedelta(days=2),
    )
    privacy_ref = _publish(store, metadata, b"{}")
    privacy_path = _age_file(tmp_path, privacy_ref, now - timedelta(days=2))
    roots.value = object_snapshot(now, (privacy_ref.object_id,))
    assert asyncio.run(store.sweep_orphans(roots.value, now)) == 0
    assert privacy_path.exists()


def test_generation_drift_aborts_before_deletion(tmp_path: Path) -> None:
    now = datetime(2026, 3, 6, 5, 6, 7, tzinfo=UTC)
    expected = object_snapshot(now)
    metadata = ObjectMetadata(
        ObjectKind.CAPTURED_CONTENT,
        "application/octet-stream",
        _TASK_ID,
        now - timedelta(days=2),
    )
    changed = ObjectRootSnapshot(
        task_id=expected.task_id,
        route_identity_digest=expected.route_identity_digest,
        route_generation=2,
        bundle_generation=expected.bundle_generation,
        privacy_root_generation=expected.privacy_root_generation,
        ledger_roots_digest=expected.ledger_roots_digest,
        importer_roots_digest=expected.importer_roots_digest,
        privacy_roots_digest=expected.privacy_roots_digest,
        maintenance_pin_digest=expected.maintenance_pin_digest,
        captured_at=expected.captured_at,
        live_object_ids=expected.live_object_ids,
    )
    calls = 0

    async def drifting_roots() -> ObjectRootSnapshot:
        nonlocal calls
        calls += 1
        return expected if calls == 1 else changed

    store = _store(tmp_path, drifting_roots)
    orphan = _publish(store, metadata, b"orphan")
    orphan_path = _age_file(tmp_path, orphan, now - timedelta(days=2))
    with pytest.raises(RuntimeError, match="object_root_snapshot_changed"):
        asyncio.run(store.sweep_orphans(expected, now))
    assert orphan_path.exists()


def test_redacted_or_revoked_object_cannot_be_reopened(tmp_path: Path) -> None:
    now = datetime(2026, 3, 6, 5, 6, 7, tzinfo=UTC)
    roots = RootsForObjectTest(object_snapshot(now))
    store = _store(tmp_path, roots.current)
    metadata = ObjectMetadata(
        ObjectKind.CAPTURED_CONTENT,
        "application/octet-stream",
        _TASK_ID,
        now - timedelta(days=2),
    )
    ref = _publish(store, metadata, b"redacted")
    _age_file(tmp_path, ref, now - timedelta(days=2))
    assert asyncio.run(store.sweep_orphans(roots.value, now)) == 1

    async def reopen() -> bytes:
        return b"".join([chunk async for chunk in store.open_verified(ref)])

    with pytest.raises(ValueError, match="object_verification_failed"):
        asyncio.run(reopen())
