"""Reviewed envelope vectors and durable encrypted-file lifecycle."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from finishup.adapters.objects import encrypted_files as encrypted_files_module
from finishup.adapters.objects.encrypted_files import (
    EncryptedFilesObjectStore,
    object_ref_from_staged,
)
from finishup.adapters.objects.envelope import (
    ObjectEnvelopeHeader,
    decode_object_envelope,
    encode_object_envelope,
)
from finishup.ports.keys import BundleKeys, WrappedDek
from finishup.ports.objects import (
    OBJECT_COMMITMENT_DOMAINS,
    ObjectKind,
    ObjectMetadata,
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


class SecretForObjectTest:
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

    def capture(self, purpose: SecretPurpose, source: bytearray) -> SecretForObjectTest:
        assert purpose is SecretPurpose.OBJECT_PAYLOAD
        result = SecretForObjectTest(source)
        source[:] = b"\0" * len(source)
        return result

    def allocate(self, purpose: SecretPurpose, size: int) -> SecretForObjectTest:
        assert purpose is SecretPurpose.OBJECT_PAYLOAD
        return SecretForObjectTest(bytes(size))

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

    def unwrap_dek(self, wrapped: WrappedDek) -> SecretForObjectTest:
        return SecretForObjectTest(aes_key_unwrap(self._key, wrapped.wrapped))


class MacKeyForObjectTest:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def mac(self, domain: bytes, message: bytes) -> str:
        return "hmac-sha256:" + hmac.new(self._key, domain + message, hashlib.sha256).hexdigest()


class IdsForObjectTest:
    def __init__(self) -> None:
        self._next = 16

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


def object_store(tmp_path: Path, now: datetime) -> EncryptedFilesObjectStore:
    tmp_path.chmod(0o700)
    roots = RootsForObjectTest(object_snapshot(now))
    return EncryptedFilesObjectStore(
        bundle_root=tmp_path,
        bundle_keys=BundleKeys(
            "bmk-1",
            WrapKeyForObjectTest(bytes(range(32))),
            MacKeyForObjectTest(bytes(range(32, 64))),
        ),
        secret_memory=SecretMemoryForObjectTest(),
        id_port=IdsForObjectTest(),
        current_root_snapshot=roots.current,
    )


def _fixture() -> dict[str, object]:
    path = Path(__file__).parents[3] / "fixtures" / "canonical" / "object-envelope.case.json"
    return cast(dict[str, object], json.loads(path.read_bytes()))


def test_reviewed_envelope_vectors_round_trip_and_reject_mutations() -> None:
    fixture = _fixture()
    fixture_input = cast(dict[str, object], fixture["input"])
    publications = cast(list[dict[str, object]], fixture_input["object_publications"])
    for publication in publications:
        artifact = cast(dict[str, object], publication["envelope"])
        blob = base64.b64decode(cast(str, artifact["base64"]), validate=True)
        decoded = decode_object_envelope(blob)
        assert decoded.header_bytes.hex() == publication["header_hex"]
        assert decoded.header.created_at.endswith("000Z")
        assert (
            encode_object_envelope(
                decoded.header,
                decoded.payload_nonce,
                decoded.ciphertext,
                decoded.tag,
            )
            == blob
        )
        assert len(decoded.header_bytes) == 444

    first_artifact = cast(dict[str, object], publications[0]["envelope"])
    valid = base64.b64decode(cast(str, first_artifact["base64"]), validate=True)
    invalid = (
        valid[:-1],
        valid + b"\0",
        b"BAD!" + valid[4:],
        valid[:4] + b"\x02" + valid[5:],
        valid[:5] + (0).to_bytes(4, "big") + valid[9:],
    )
    for candidate in invalid:
        with pytest.raises(ValueError, match="invalid_object_envelope"):
            decode_object_envelope(candidate)


def test_reviewed_commitment_vectors_are_byte_exact() -> None:
    fixture_input = cast(dict[str, object], _fixture()["input"])
    plaintexts = cast(list[dict[str, object]], fixture_input["plaintexts"])
    raw = cast(dict[str, object], plaintexts[0]["bytes"])
    plaintext = base64.b64decode(cast(str, raw["base64"]), validate=True)
    vectors = cast(list[dict[str, object]], fixture_input["commitment_vectors"])
    key = MacKeyForObjectTest(bytes(range(32, 64)))
    # CAN-009 is a frozen v1.0 corpus.  PROJECT_TEXT was added by the current 0.3
    # coordination surface and CHANGE_CAPTURE by the check-time change (ADR-031), so their
    # current domains are pinned below without rewriting that historical vector set.
    assert len(vectors) == 17
    vector_kinds = {ObjectKind(cast(str, vector["kind"])) for vector in vectors}
    assert vector_kinds == set(ObjectKind) - {ObjectKind.PROJECT_TEXT, ObjectKind.CHANGE_CAPTURE}
    for vector in vectors:
        kind = ObjectKind(cast(str, vector["kind"]))
        domain = base64.b64decode(cast(str, vector["domain_base64"]), validate=True)
        assert domain == OBJECT_COMMITMENT_DOMAINS[kind]
        assert domain.endswith(b"\0")
        assert key.mac(domain, plaintext) == vector["commitment"]
    project_text_domain = OBJECT_COMMITMENT_DOMAINS[ObjectKind.PROJECT_TEXT]
    assert project_text_domain == b"yoetz/object/project_text/v1\0"
    assert key.mac(project_text_domain, plaintext) == (
        "hmac-sha256:cb9066d717d938caee9d1013127c792b38891acb4ced2303849a2111c30f66c6"
    )
    change_capture_domain = OBJECT_COMMITMENT_DOMAINS[ObjectKind.CHANGE_CAPTURE]
    assert change_capture_domain == b"yoetz/object/change_capture/v1\0"
    assert key.mac(change_capture_domain, plaintext) == (
        "hmac-sha256:3ebd0ba68f42370fff7c53aa0016b92099fa7c688f92bd8f103eb1088c711675"
    )


def test_stage_fsync_rename_dirfsync_finalize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    store = object_store(tmp_path, now)
    metadata = ObjectMetadata(
        ObjectKind.CAPTURED_CONTENT, "application/octet-stream", _TASK_ID, now
    )
    staged = asyncio.run(store.stage(ObjectSource(data=b"payload"), metadata))

    events: list[str] = []
    real_fsync = encrypted_files_module.os.fsync
    real_replace = encrypted_files_module.os.replace

    def recording_fsync(descriptor: int) -> None:
        events.append("fsync")
        real_fsync(descriptor)

    def recording_replace(source: os.PathLike[str], destination: os.PathLike[str]) -> None:
        events.append("rename")
        real_replace(source, destination)

    monkeypatch.setattr(encrypted_files_module.os, "fsync", recording_fsync)
    monkeypatch.setattr(encrypted_files_module.os, "replace", recording_replace)
    ref = asyncio.run(store.finalize(staged))
    assert events[0:3] == ["fsync", "rename", "fsync"]
    assert asyncio.run(store.finalize(staged)) == ref


def test_abandon_removes_a_final_file_after_post_rename_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #339: a failed dir fsync after rename must leave an exact removable stage."""

    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    store = object_store(tmp_path, now)
    metadata = ObjectMetadata(ObjectKind.RECEIPT, "application/json", _TASK_ID, now)
    staged = asyncio.run(store.stage(ObjectSource(data=b"{}"), metadata))
    final_path = tmp_path / "objects" / staged.object_id[4:6] / staged.object_id
    staging_root = tmp_path / "objects" / ".staging"
    real_fsync_directory = EncryptedFilesObjectStore._fsync_directory  # pyright: ignore[reportPrivateUsage]
    calls = 0

    def fail_first_directory_fsync(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated_dir_fsync_failure")
        real_fsync_directory(path)

    monkeypatch.setattr(
        EncryptedFilesObjectStore,
        "_fsync_directory",
        staticmethod(fail_first_directory_fsync),
    )
    with pytest.raises(OSError, match="simulated_dir_fsync_failure"):
        asyncio.run(store.finalize(staged))
    assert final_path.exists()
    assert not tuple(staging_root.iterdir())

    asyncio.run(store.abandon(staged))
    assert not final_path.exists()
    asyncio.run(store.abandon(staged))
    with pytest.raises(ValueError, match="abandoned_staged_object"):
        asyncio.run(store.finalize(staged))


def test_abandon_removes_the_final_copy_even_when_the_temp_path_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #339: a temp-path fault must not strand the finalized orphan it precedes."""

    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    store = object_store(tmp_path, now)
    metadata = ObjectMetadata(ObjectKind.RECEIPT, "application/json", _TASK_ID, now)
    staged = asyncio.run(store.stage(ObjectSource(data=b"{}"), metadata))
    staging_root = tmp_path / "objects" / ".staging"
    final_path = tmp_path / "objects" / staged.object_id[4:6] / staged.object_id

    def copy_instead_of_rename(source: object, destination: object) -> None:
        target = Path(cast(Path, destination))
        target.write_bytes(Path(cast(Path, source)).read_bytes())
        target.chmod(0o600)

    # Leave both owned locations populated so abandon has to reach the second one.
    monkeypatch.setattr(encrypted_files_module.os, "replace", copy_instead_of_rename)
    asyncio.run(store.finalize(staged))
    assert final_path.exists()
    assert len(tuple(staging_root.iterdir())) == 1

    real_digest_file = EncryptedFilesObjectStore._digest_file  # pyright: ignore[reportPrivateUsage]

    def fail_for_staged_bytes(_cls: type[EncryptedFilesObjectStore], path: Path) -> str:
        if path.parent == staging_root:
            raise OSError("simulated_temp_read_failure")
        return real_digest_file(path)

    monkeypatch.setattr(
        EncryptedFilesObjectStore, "_digest_file", classmethod(fail_for_staged_bytes)
    )
    with pytest.raises(OSError, match="simulated_temp_read_failure"):
        asyncio.run(store.abandon(staged))
    assert not final_path.exists()

    # The stage stayed un-abandoned, so the retry that clears the fault finishes the removal.
    monkeypatch.setattr(EncryptedFilesObjectStore, "_digest_file", real_digest_file)
    asyncio.run(store.abandon(staged))
    assert not tuple(staging_root.iterdir())
    with pytest.raises(ValueError, match="abandoned_staged_object"):
        asyncio.run(store.finalize(staged))


def test_abandon_fails_closed_when_the_owned_final_bytes_drift(tmp_path: Path) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    store = object_store(tmp_path, now)
    metadata = ObjectMetadata(ObjectKind.RECEIPT, "application/json", _TASK_ID, now)
    staged = asyncio.run(store.stage(ObjectSource(data=b"{}"), metadata))
    ref = asyncio.run(store.finalize(staged))
    final_path = tmp_path / "objects" / ref.object_id[4:6] / ref.object_id
    final_path.write_bytes(b"drifted")

    with pytest.raises(OSError, match="object_destination_collision"):
        asyncio.run(store.abandon(staged))
    assert final_path.read_bytes() == b"drifted"


def test_verified_open_reads_only_finalized_objects(tmp_path: Path) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    store = object_store(tmp_path, now)
    metadata = ObjectMetadata(ObjectKind.RECEIPT, "application/json", _TASK_ID, now)
    staged = asyncio.run(store.stage(ObjectSource(data=b"{}"), metadata))

    async def read_before_finalize() -> bytes:
        return b"".join(
            [chunk async for chunk in store.open_verified(object_ref_from_staged(staged))]
        )

    with pytest.raises(ValueError, match="object_verification_failed"):
        asyncio.run(read_before_finalize())
    ref = asyncio.run(store.finalize(staged))

    async def read_after_finalize() -> bytes:
        return b"".join([chunk async for chunk in store.open_verified(ref)])

    assert asyncio.run(read_after_finalize()) == b"{}"


def test_verified_open_reraises_environmental_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    store = object_store(tmp_path, now)
    metadata = ObjectMetadata(ObjectKind.RECEIPT, "application/json", _TASK_ID, now)
    ref = asyncio.run(store.finalize(asyncio.run(store.stage(ObjectSource(data=b"{}"), metadata))))

    def failing_read(_descriptor: int, _n: int) -> bytes:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(encrypted_files_module.os, "read", failing_read)

    async def read_after_finalize() -> bytes:
        return b"".join([chunk async for chunk in store.open_verified(ref)])

    with pytest.raises(OSError) as caught:
        asyncio.run(read_after_finalize())
    assert caught.value.errno == 5
    assert not isinstance(caught.value, ValueError)

    with pytest.raises(OSError) as resolve_caught:
        asyncio.run(store.resolve_verified(ref.object_id, ref.envelope_digest))
    assert resolve_caught.value.errno == 5


def test_adapter_generated_truncation_stays_storage_corrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A finalized object that ends before its recorded frame size is deterministic corruption."""

    import finishup.observability.diagnostics as diagnostics
    from finishup.application.receipt import (  # noqa: SLF001
        _read_object,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.observability.diagnostics import lookup_diagnostic_records
    from finishup.protocol.errors import PublicErrorCode, PublicOperationError

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    store = object_store(tmp_path, now)
    metadata = ObjectMetadata(ObjectKind.RECEIPT, "application/json", _TASK_ID, now)
    ref = asyncio.run(store.finalize(asyncio.run(store.stage(ObjectSource(data=b"{}"), metadata))))

    # Keep the adapter's real fstat/open path, but make the finalized file return EOF before its
    # recorded size. This reaches the adapter-owned ``object_file_truncated`` fault rather than a
    # caller-side stub and proves it is converted to deterministic verification failure.
    def truncated_read(_descriptor: int, _n: int) -> bytes:
        return b""

    monkeypatch.setattr(encrypted_files_module.os, "read", truncated_read)

    with pytest.raises(ValueError, match="object_verification_failed"):
        asyncio.run(store.resolve_verified(ref.object_id, ref.envelope_digest))

    async def read_receipt() -> bytes:
        return await _read_object(SimpleNamespace(objects=store), ref)  # type: ignore[arg-type]

    with pytest.raises(PublicOperationError) as caught:
        asyncio.run(read_receipt())
    assert caught.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert caught.value.retryable is False
    assert caught.value.message == "The stored receipt is invalid."
    assert caught.value.correlation_id is not None
    found = lookup_diagnostic_records(caught.value.correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["operation"] == "receipt_object_read"
    assert found[0]["reason"] == "exception_value_error"


def test_read_object_through_encrypted_files_maps_eio_to_retryable_storage_unsafe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """execute_receipt replay reads through ``_read_object``; use the real adapter, not a stub."""

    import finishup.observability.diagnostics as diagnostics
    from finishup.application.receipt import (  # noqa: SLF001
        _read_object,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.observability.diagnostics import lookup_diagnostic_records
    from finishup.protocol.errors import PublicErrorCode, PublicOperationError

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    store = object_store(tmp_path, now)
    metadata = ObjectMetadata(ObjectKind.RECEIPT, "application/json", _TASK_ID, now)
    ref = asyncio.run(store.finalize(asyncio.run(store.stage(ObjectSource(data=b"{}"), metadata))))
    runtime = SimpleNamespace(objects=store)

    async def read_ok() -> bytes:
        return await _read_object(runtime, ref)  # type: ignore[arg-type]

    assert asyncio.run(read_ok()) == b"{}"

    def failing_read(_descriptor: int, _n: int) -> bytes:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(encrypted_files_module.os, "read", failing_read)

    async def read_eio() -> bytes:
        return await _read_object(runtime, ref)  # type: ignore[arg-type]

    with pytest.raises(PublicOperationError) as caught:
        asyncio.run(read_eio())
    assert caught.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert caught.value.retryable is True
    assert caught.value.message == "Receipt object storage is unavailable."
    assert caught.value.correlation_id is not None
    found = lookup_diagnostic_records(caught.value.correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["reason"] == "exception_os_error"
    assert found[0]["operation"] == "receipt_object_read"
    origin = found[0].get("origin")
    assert type(origin) is str
    assert origin.startswith("finishup.")
    assert "Input/output error" not in caught.value.message


def test_header_and_envelope_digest_fields_match_reference(tmp_path: Path) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    store = object_store(tmp_path, now)
    metadata = ObjectMetadata(
        ObjectKind.CAPTURED_CONTENT, "application/octet-stream", _TASK_ID, now
    )
    ref = asyncio.run(
        store.finalize(asyncio.run(store.stage(ObjectSource(data=b"payload"), metadata)))
    )
    path = tmp_path / "objects" / ref.object_id[4:6] / ref.object_id
    frame = path.read_bytes()
    envelope = decode_object_envelope(frame)
    assert hashlib.sha256(frame).hexdigest() == ref.envelope_digest.removeprefix("sha256:")
    assert envelope.header == ObjectEnvelopeHeader(
        created_at="2026-03-04T05:06:07.000000Z",
        encryption_format=ref.encryption_format,
        key_slot=ref.key_slot,
        media_type=metadata.media_type,
        object_id=ref.object_id,
        object_kind=metadata.kind,
        payload_algorithm="aes-256-gcm",
        plaintext_size=ref.plaintext_size,
        task_id=metadata.task_id,
        wrap_algorithm="aes-256-kw-rfc3394",
        wrapped_dek=envelope.header.wrapped_dek,
    )


def test_staging_path_derivation_is_collision_safe(tmp_path: Path) -> None:
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    store = object_store(tmp_path, now)
    metadata = ObjectMetadata(
        ObjectKind.CAPTURED_CONTENT, "application/octet-stream", _TASK_ID, now
    )
    first = asyncio.run(store.stage(ObjectSource(data=b"same"), metadata))
    second = asyncio.run(store.stage(ObjectSource(data=b"same"), metadata))
    staging_root = tmp_path / "objects" / ".staging"
    staged_paths = tuple(staging_root.iterdir())
    assert first.object_id != second.object_id
    assert len(staged_paths) == 2
    assert len({path.name for path in staged_paths}) == 2
    assert all(path.parent == staging_root for path in staged_paths)
    assert all(
        path.resolve().is_relative_to((tmp_path / "objects").resolve()) for path in staged_paths
    )
