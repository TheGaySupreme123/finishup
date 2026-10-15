"""Receipt object-store faults stay classified instead of becoming INTERNAL_ERROR."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from finishup.application.receipt import (  # noqa: SLF001
    _abandon_preappend_objects,  # pyright: ignore[reportPrivateUsage]
    _finalize_object,  # pyright: ignore[reportPrivateUsage]
    _read_object,  # pyright: ignore[reportPrivateUsage]
    _stage_object,  # pyright: ignore[reportPrivateUsage]
)
from finishup.observability.diagnostics import diagnostic_log_path, lookup_diagnostic_records
from finishup.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectSource,
    StagedObject,
)
from finishup.ports.runtime import TaskRuntime
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

pytestmark = pytest.mark.anyio

_REQUEST_ID = "req_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


@pytest.fixture(autouse=True)
def _diagnostic_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:  # pyright: ignore[reportUnusedFunction]
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    return tmp_path


def _receipt_ref(*, plaintext_size: int = 2) -> ObjectRef:
    return ObjectRef(
        "obj_ffffffff-0000-4000-8000-000000000001",
        plaintext_size,
        "hmac-sha256:" + "a" * 64,
        "sha256:" + "b" * 64,
        "yoetz-object/1",
        "test-key-1",
        ObjectMetadata(
            ObjectKind.RECEIPT,
            "application/vnd.yoetz.receipt+json",
            "tsk_ffffffff-0000-4000-8000-000000000001",
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )


def _runtime_with_open(open_verified: object) -> TaskRuntime:
    return cast(TaskRuntime, SimpleNamespace(objects=SimpleNamespace(open_verified=open_verified)))


def _runtime_with_store(*, stage: object, finalize: object) -> TaskRuntime:
    return cast(
        TaskRuntime,
        SimpleNamespace(objects=SimpleNamespace(stage=stage, finalize=finalize)),
    )


def _assert_classified(
    error: PublicOperationError,
    *,
    code: PublicErrorCode,
    message: str,
    retryable: bool,
    reason: str,
    operation: str,
    root: Path,
) -> None:
    assert error.code is code
    assert error.message == message
    assert error.retryable is retryable
    assert error.correlation_id is not None
    assert error.correlation_id.startswith("err_")
    found = lookup_diagnostic_records(error.correlation_id, root=root)
    assert len(found) == 1
    assert found[0]["reason"] == reason
    assert found[0]["operation"] == operation
    assert found[0]["component"] == "application.receipt"
    assert found[0]["request_id"] == _REQUEST_ID
    recorded_operation = found[0]["operation"]
    assert type(recorded_operation) is str
    assert "internal_error" not in recorded_operation
    assert "Input/output error" not in error.message
    assert "object_verification_failed" not in error.message


@pytest.mark.parametrize(
    ("error", "code", "message", "retryable", "reason"),
    (
        (
            ValueError("object_verification_failed"),
            PublicErrorCode.STORAGE_CORRUPT,
            "The stored receipt is invalid.",
            False,
            "exception_value_error",
        ),
        (
            KeyError("missing"),
            PublicErrorCode.STORAGE_CORRUPT,
            "The stored receipt is invalid.",
            False,
            "exception_key_error",
        ),
        (
            TypeError("bad chunk"),
            PublicErrorCode.STORAGE_CORRUPT,
            "The stored receipt is invalid.",
            False,
            "exception_type_error",
        ),
        (
            OSError(5, "Input/output error"),
            PublicErrorCode.STORAGE_UNSAFE,
            "Receipt object storage is unavailable.",
            True,
            "exception_os_error",
        ),
    ),
)
async def test_read_object_classifies_store_faults(
    error: Exception,
    code: PublicErrorCode,
    message: str,
    retryable: bool,
    reason: str,
    _diagnostic_dir: Path,
) -> None:
    def open_verified(_ref: ObjectRef) -> AsyncIterator[bytes]:
        raise error

    with pytest.raises(PublicOperationError) as caught:
        await _read_object(
            _runtime_with_open(open_verified), _receipt_ref(), request_id=_REQUEST_ID
        )
    _assert_classified(
        caught.value,
        code=code,
        message=message,
        retryable=retryable,
        reason=reason,
        operation="receipt_object_read",
        root=_diagnostic_dir,
    )


async def test_read_object_maps_size_mismatch_to_storage_corrupt(_diagnostic_dir: Path) -> None:
    async def open_verified(_ref: ObjectRef) -> AsyncIterator[bytes]:
        yield b"x"

    with pytest.raises(PublicOperationError) as caught:
        await _read_object(
            _runtime_with_open(open_verified),
            _receipt_ref(plaintext_size=2),
            request_id=_REQUEST_ID,
        )
    _assert_classified(
        caught.value,
        code=PublicErrorCode.STORAGE_CORRUPT,
        message="The receipt object is invalid.",
        retryable=False,
        reason="exception_value_error",
        operation="receipt_object_read",
        root=_diagnostic_dir,
    )


async def test_persist_object_maps_stage_oserror_to_retryable_storage_unsafe(
    _diagnostic_dir: Path,
) -> None:
    async def stage(_source: ObjectSource, _metadata: ObjectMetadata) -> object:
        raise OSError("No space left on device")

    async def finalize(_staged: object) -> ObjectRef:
        raise AssertionError("finalize must not run after stage failure")

    with pytest.raises(PublicOperationError) as caught:
        await _stage_object(
            _runtime_with_store(stage=stage, finalize=finalize),
            ObjectSource(data=b"{}", declared_size=2),
            _receipt_ref().metadata,
            request_id=_REQUEST_ID,
        )
    _assert_classified(
        caught.value,
        code=PublicErrorCode.STORAGE_UNSAFE,
        message="Receipt object storage is unavailable.",
        retryable=True,
        reason="exception_os_error",
        operation="receipt_object_persist",
        root=_diagnostic_dir,
    )
    assert "No space left on device" not in caught.value.message


async def test_persist_object_maps_finalize_oserror_to_retryable_storage_unsafe(
    _diagnostic_dir: Path,
) -> None:
    async def stage(_source: ObjectSource, _metadata: ObjectMetadata) -> object:
        return object()

    async def finalize(_staged: object) -> ObjectRef:
        raise OSError("object_destination_collision")

    ref = _receipt_ref()
    staged = StagedObject(
        ref.object_id,
        ref.plaintext_size,
        ref.commitment,
        ref.envelope_digest,
        ref.encryption_format,
        ref.key_slot,
        ref.metadata,
        object(),
    )
    with pytest.raises(PublicOperationError) as caught:
        await _finalize_object(
            _runtime_with_store(stage=stage, finalize=finalize),
            staged,
            request_id=_REQUEST_ID,
        )
    _assert_classified(
        caught.value,
        code=PublicErrorCode.STORAGE_UNSAFE,
        message="Receipt object storage is unavailable.",
        retryable=True,
        reason="exception_os_error",
        operation="receipt_object_persist",
        root=_diagnostic_dir,
    )
    assert "object_destination_collision" not in caught.value.message


async def test_abandon_finishes_every_stage_before_repeated_cancellation_propagates() -> None:
    first_ref = _receipt_ref()
    first = StagedObject(
        first_ref.object_id,
        first_ref.plaintext_size,
        first_ref.commitment,
        first_ref.envelope_digest,
        first_ref.encryption_format,
        first_ref.key_slot,
        first_ref.metadata,
        object(),
    )
    second = StagedObject(
        "obj_ffffffff-0000-4000-8000-000000000002",
        first.plaintext_size,
        first.commitment,
        first.envelope_digest,
        first.encryption_format,
        first.key_slot,
        first.metadata,
        object(),
    )
    started = asyncio.Event()
    release = asyncio.Event()
    abandoned: list[str] = []

    async def abandon(staged: StagedObject) -> None:
        abandoned.append(staged.object_id)
        if len(abandoned) == 1:
            started.set()
            await release.wait()

    runtime = cast(TaskRuntime, SimpleNamespace(objects=SimpleNamespace(abandon=abandon)))
    cleanup = asyncio.create_task(
        _abandon_preappend_objects(runtime, (first, second), request_id=_REQUEST_ID)
    )
    await started.wait()
    cleanup.cancel()
    cleanup.cancel()
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await cleanup
    assert abandoned == [second.object_id, first.object_id]


def _staged(object_id: str) -> StagedObject:
    ref = _receipt_ref()
    return StagedObject(
        object_id,
        ref.plaintext_size,
        ref.commitment,
        ref.envelope_digest,
        ref.encryption_format,
        ref.key_slot,
        ref.metadata,
        object(),
    )


def _abandon_diagnostics(root: Path) -> tuple[Mapping[str, object], ...]:
    path = diagnostic_log_path(root=root)
    if not path.is_file():
        return ()
    records: list[Mapping[str, object]] = []
    for raw in path.read_bytes().splitlines():
        if not raw.strip():
            continue
        parsed: object = json.loads(raw.decode("ascii"))
        assert type(parsed) is dict
        source = cast(Mapping[str, object], parsed)
        if source.get("operation") == "receipt_object_abandon_failed":
            records.append(source)
    return tuple(records)


async def test_abandon_never_replaces_the_caller_error_with_a_base_exception(
    _diagnostic_dir: Path,
) -> None:
    """A cleanup escape stays a diagnostic; the caller keeps its classified retryable error."""

    staged = _staged("obj_ffffffff-0000-4000-8000-000000000003")

    async def abandon(_staged: StagedObject) -> None:
        raise asyncio.CancelledError

    runtime = cast(TaskRuntime, SimpleNamespace(objects=SimpleNamespace(abandon=abandon)))
    # No raise: the caller's ``raise`` after cleanup must be the one that reaches the client.
    await _abandon_preappend_objects(runtime, (staged,), request_id=_REQUEST_ID)
    assert len(_abandon_diagnostics(_diagnostic_dir)) == 1


async def test_abandon_records_a_diagnostic_when_the_cleanup_task_cannot_start(
    _diagnostic_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A closing loop refuses ``create_task`` outside the cleanup task entirely."""

    staged = _staged("obj_ffffffff-0000-4000-8000-000000000004")
    abandoned: list[str] = []

    async def abandon(staged_object: StagedObject) -> None:
        abandoned.append(staged_object.object_id)

    def refuse_task(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("Event loop is closed")

    runtime = cast(TaskRuntime, SimpleNamespace(objects=SimpleNamespace(abandon=abandon)))
    monkeypatch.setattr(asyncio, "create_task", refuse_task)
    # This path never suspends, so the patched factory is restored before the loop needs it again.
    await _abandon_preappend_objects(runtime, (staged,), request_id=_REQUEST_ID)
    monkeypatch.undo()

    assert abandoned == []
    records = _abandon_diagnostics(_diagnostic_dir)
    assert len(records) == 1
    assert records[0]["reason"] == "exception_runtime_error"
