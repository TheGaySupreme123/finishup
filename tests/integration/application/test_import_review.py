"""Integration coverage for bounded Codex import capture and review admission."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from typing import cast

import pytest

from builders import ids
from builders.ledger_adapters import FixedClock, FixedIds, MemoryObjects, ownership_fence
from finishup.adapters.importers.codex_jsonl import (
    CODEX_JSONL_MAPPING_VERSION,
    CodexMappingContext,
    parse_codex_jsonl,
    plan_codex_mapping,
    profile_for_codex_version,
)
from finishup.adapters.memory.importer import (
    ImportPlanMaterial,
    MemoryImporter,
    MemoryImportState,
)
from finishup.application.import_review import (
    Application,
    ImportCodexJsonlRequest,
    ImportReportInternal,
    ReviewRequest,
    execute_import_codex_jsonl,
    import_request_from_control,
)
from finishup.domain.values import Frontier, Timestamp, request_id, session_id, writer_id
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.importer import ImportAllocation, ImportCaptureInput, PreparedImportPlan
from finishup.ports.ledger import LedgerPort
from finishup.ports.objects import ObjectRef, ObjectStorePort
from finishup.protocol.coverage import PublicationChannel, coverage_for_channel
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

pytestmark = pytest.mark.anyio


class _Bytes:
    def __init__(self, value: bytes) -> None:
        self._value = value
        self.closed = False

    @property
    def declared_size(self) -> int:
        return len(self._value)

    async def _chunks(self) -> AsyncIterator[bytes]:
        yield self._value

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self._chunks()

    async def close(self) -> None:
        self.closed = True


async def _no_plan(allocation: ImportAllocation) -> PreparedImportPlan:
    del allocation
    raise AssertionError("plan_not_used")


async def _no_read(ref: ObjectRef) -> ImportPlanMaterial:
    del ref
    raise AssertionError("plan_not_used")


def _capture_importer() -> tuple[MemoryImporter, MemoryObjects]:
    id_source = FixedIds()
    objects = MemoryObjects(id_source)
    importer = MemoryImporter(
        task_id=ids.task_id("import-integration"),
        admitted_session_id=ids.session_id("import-integration"),
        ownership_fence=ownership_fence(),
        state=MemoryImportState(),
        transaction_lock=asyncio.Lock(),
        objects=cast(ObjectStorePort, objects),
        ledger=cast(LedgerPort, object()),
        clock=cast(ClockPort, FixedClock()),
        ids=cast(IdPort, id_source),
        plan_preparer=_no_plan,
        plan_reader=_no_read,
    )
    return importer, objects


async def test_codex_jsonl_import_preserves_source_and_quarantine() -> None:
    source = _Bytes(b'{"type":"turn.started"}\n')
    importer, objects = _capture_importer()
    captured = await importer.capture(
        ImportCaptureInput(
            source,
            "0.139.0",
            "codex-exec-jsonl/0.139.0/v1",
            (),
            "control-import",
            0,
            Timestamp("2026-07-19T12:00:00.000Z"),
            "stdin",
        )
    )

    assert source.closed is True
    assert objects._data[captured.source_object.object_id] == (  # pyright: ignore[reportPrivateUsage]
        b'{"type":"turn.started"}\n'
    )
    assert (
        captured.stderr_present,
        captured.stderr_captured_bytes,
        captured.stderr_truncated,
        captured.stderr_commitment,
    ) == (False, 0, False, None)
    structural_report = ImportReportInternal(
        "1.0.0",
        request_id(ids.request_id("import-report")),
        ids.task_id("import-integration"),
        session_id(ids.session_id("import-integration")),
        "sha256:" + "1" * 64,
        ids.object_id("import-report"),
        "sha256:" + "2" * 64,
        1,
        0,
        0,
        0,
        1,
        Frontier.genesis(),
        Frontier.genesis(),
        coverage_for_channel(PublicationChannel.CODEX_JSONL_IMPORT),
        (),
        "codex-exec-jsonl/0.139.0/v1",
        CODEX_JSONL_MAPPING_VERSION,
    )
    assert "privacy_projection" not in structural_report.as_json()

    crafted = object.__new__(ImportCodexJsonlRequest)
    object.__setattr__(crafted, "stderr_present", True)
    object.__setattr__(crafted, "stderr_captured_bytes", 1)
    object.__setattr__(crafted, "stderr_truncated", True)

    class _NeverRuntime:
        async def route(self, command: object) -> object:
            del command
            raise AssertionError("capture_was_reached")

    class _App:
        runtime = _NeverRuntime()
        clock = FixedClock()

    with pytest.raises(PublicOperationError) as caught:
        await execute_import_codex_jsonl(cast(Application, _App()), crafted)
    assert caught.value.code is PublicErrorCode.INVALID_REQUEST


async def test_control_import_body_decodes_to_the_typed_bounded_source() -> None:
    source = b'{"type":"turn.started"}\n'
    request = import_request_from_control(
        {
            "schema_version": "1.0.0",
            "codex_capability_profile_id": "codex-exec-jsonl/0.139.0/v1",
            "codex_version": "0.139.0",
            "exit_status": 0,
            "mapping_version": CODEX_JSONL_MAPPING_VERSION,
            "request_id": ids.request_id("import-control"),
            "session_id": ids.session_id("import-control"),
            "source_bytes_base64": base64.b64encode(source).decode("ascii"),
            "source_encoding": "base64",
            "source_kind": "stdin",
            "stderr_captured_bytes": 0,
            "stderr_present": False,
            "stderr_truncated": False,
            "writer_id": ids.writer_id("import-control"),
        }
    )
    assert request.source.declared_size == len(source)
    assert b"".join([chunk async for chunk in request.source]) == source
    await request.source.close()

    with pytest.raises(PublicOperationError) as caught:
        import_request_from_control({"source_encoding": "base64", "source_bytes_base64": "***"})
    assert caught.value.code is PublicErrorCode.INVALID_REQUEST


async def test_review_selection_and_validation_are_bounded() -> None:
    digest = "sha256:" + "1" * 64
    request = ReviewRequest(
        "1.0.0",
        request_id(ids.request_id("review-request")),
        session_id(ids.session_id("review-session")),
        writer_id(ids.writer_id("review-writer")),
        Frontier.genesis(),
        (digest,),
        "deterministic_only",
    )
    assert request.source_identity_digests == (digest,)

    with pytest.raises(ValueError, match="import_review_selection_invalid"):
        ReviewRequest(
            "1.0.0",
            request_id(ids.request_id("bad-review-request")),
            session_id(ids.session_id("review-session")),
            writer_id(ids.writer_id("review-writer")),
            Frontier.genesis(),
            (),
            "deterministic_only",
        )


async def test_imported_observations_use_codex_publication_channel() -> None:
    source_bytes = b'{"type":"turn.started"}\n'
    importer, _ = _capture_importer()
    captured = await importer.capture(
        ImportCaptureInput(
            _Bytes(source_bytes),
            "0.139.0",
            "codex-exec-jsonl/0.139.0/v1",
            (),
            "control-import",
            0,
            Timestamp("2026-07-19T12:00:00.000Z"),
            "stdin",
        )
    )
    parsed = parse_codex_jsonl(source_bytes, profile_for_codex_version("0.139.0"))
    context = CodexMappingContext(
        captured.source_object,
        captured.source_commitment,
        Timestamp("2026-07-19T12:00:00.000Z"),
        profile_for_codex_version("0.139.0"),
        CODEX_JSONL_MAPPING_VERSION,
        coverage_for_channel(PublicationChannel.CODEX_JSONL_IMPORT),
    )
    planned = plan_codex_mapping(parsed, context)

    assert len(planned.candidates) == 1
    assert planned.gaps[0].coverage.publication_channels == (PublicationChannel.CODEX_JSONL_IMPORT,)
    assert planned.candidates[0].target_schema.name == "codex_jsonl_observation"
