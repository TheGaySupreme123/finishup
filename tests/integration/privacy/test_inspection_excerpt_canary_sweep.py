"""Plaintext and encrypted-object canary sweeps for inspection snapshots."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import apsw
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from finishup.adapters.objects.encrypted_files import EncryptedFilesObjectStore
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation import SqliteObservationStore
from finishup.application.observation_coordinator import build_inspection_excerpt_manifest
from finishup.domain.values import Timestamp
from finishup.observability.privacy import scan_for_sensitive_content
from finishup.ports.keys import BundleKeys, WrappedDek
from finishup.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectRootSnapshot,
    ObjectSource,
)
from finishup.ports.secret_memory import SecretConsumer, SecretMemoryCapability, SecretPurpose
from finishup.ports.workspace_inspect import InspectedArtifact
from finishup.protocol.ids import IdKind

if TYPE_CHECKING:
    from finishup.ports.secret_memory import SecretHandle

_DIGEST = "sha256:" + "0" * 64
_TASK_ID = "tsk_30000000-0000-4000-8000-000000000001"
_WORKSPACE = "hmac-sha256:" + "11" * 32
_SESSION = "ses_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
_SECRET = b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


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


class _Roots:
    def __init__(self, value: ObjectRootSnapshot) -> None:
        self.value = value

    async def current(self) -> ObjectRootSnapshot:
        return self.value


def _snapshot(now: datetime) -> ObjectRootSnapshot:
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
        live_object_ids=(),
    )


def _artifact(relative_path: str, excerpt: bytes) -> InspectedArtifact:
    digest = "sha256:" + hashlib.sha256(excerpt).hexdigest()
    return InspectedArtifact(relative_path, digest, excerpt, False, len(excerpt))


def test_inspection_snapshot_plaintext_and_ciphertext_stay_canary_free(tmp_path: Path) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    bundle = tmp_path / "bundle"
    bundle.mkdir(mode=0o700)
    keys = BundleKeys("bmk-1", _WrapKey(bytes(range(32))), _MacKey(bytes(range(32, 64))))
    objects = EncryptedFilesObjectStore(
        bundle_root=bundle,
        bundle_keys=keys,
        secret_memory=_SecretMemory(),
        id_port=_Ids(),
        current_root_snapshot=_Roots(_snapshot(now)).current,
    )
    db = apsw.Connection(str(tmp_path / "task.sqlite"))
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)

    encoded, unavailable, redacted, truncated = build_inspection_excerpt_manifest(
        (_artifact("src/env.py", b"export " + _SECRET + b"\n"),)
    )
    assert unavailable is False
    # B1 (#982, owner decision 2026-10-07): a heuristic-only credential shape stays raw at capture
    # for local and deterministic checks and is redacted only at egress. It still never reaches
    # plaintext SQLite or the object files: the sweep below runs over the encrypted surfaces.
    assert redacted is False
    assert truncated is False
    assert encoded is not None

    async def persist() -> ObjectRef:
        metadata = ObjectMetadata(
            ObjectKind.CAPTURED_CONTENT,
            "application/vnd.yoetz.observation-content+json",
            _TASK_ID,
            now,
        )
        staged = await objects.stage(
            ObjectSource(data=encoded, declared_size=len(encoded)), metadata
        )
        return await objects.finalize(staged)

    ref = asyncio.run(persist())
    store.record_inspection_snapshot(
        workspace=_WORKSPACE,
        finishup_session_id=_SESSION,
        subject_state_digest=_DIGEST,
        changed_paths_digest=_DIGEST,
        relative_paths=("src/env.py",),
        facts_ref=None,
        facts_content_digest=None,
        facts_content_bytes=None,
        excerpt_ref=ref,
        excerpt_content_digest="sha256:" + hashlib.sha256(encoded).hexdigest(),
        excerpt_content_bytes=len(encoded),
        excerpt_redacted=redacted,
        excerpt_truncated=truncated,
        recorded_at=Timestamp("2026-03-04T05:06:07.000Z"),
    )
    snapshot = store.load_inspection_snapshot(
        workspace=_WORKSPACE,
        finishup_session_id=_SESSION,
        subject_state_digest=_DIGEST,
    )
    assert snapshot is not None
    assert snapshot.excerpt_object_id == ref.object_id
    assert snapshot.excerpt_content_digest == "sha256:" + hashlib.sha256(encoded).hexdigest()
    assert snapshot.excerpt_content_bytes == len(encoded)
    assert snapshot.excerpt_redacted is False
    assert snapshot.excerpt_truncated is False

    surfaces = {
        "catalog_db": Path(tmp_path / "task.sqlite").read_bytes(),
        **{
            str(path): path.read_bytes()
            for path in bundle.rglob("*")
            if path.is_file() and ".staging" not in path.parts
        },
    }
    assert surfaces, "inspection persistence must write sqlite and object bytes"
    for name, data in surfaces.items():
        findings = scan_for_sensitive_content(data, canaries=(_SECRET, b"wJalrXUtnFEMI"))
        assert findings == (), f"inspection canary leaked into {name!r}: {findings}"
        assert _SECRET not in data
        assert b"wJalrXUtnFEMI" not in data

    async def decrypt() -> bytes:
        return b"".join([chunk async for chunk in objects.open_verified(ref)])

    recovered = asyncio.run(decrypt())
    # The decrypted vault object is the raw local excerpt (B1): egress re-scans and redacts it.
    assert recovered == encoded
    assert b"excerpt_b64" in recovered
