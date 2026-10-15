"""Production Codex import-plan preparation and immediate consent pause."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import cast

import pytest

from builders import ids
from builders.ledger_adapters import FixedClock, FixedIds, MemoryObjects, ownership_fence
from finishup.adapters.importers.codex_jsonl import CODEX_JSONL_MAPPING_VERSION
from finishup.adapters.importers.codex_plan import CodexImportPlans
from finishup.adapters.memory.importer import (
    MemoryImporter,
    MemoryImportState,
    event_draft_bytes,
)
from finishup.domain.values import Timestamp, request_id, session_id, task_id, writer_id
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.importer import (
    ImportAllocationOutcome,
    ImportByteSource,
    ImportCaptureInput,
    ImportCommand,
    ImportSourceIdentity,
)
from finishup.ports.ledger import LedgerPort
from finishup.ports.objects import ObjectStorePort
from finishup.protocol.canonical import canonical_digest, strict_json_parse
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import PublishWorkRequestModel
from finishup.service.elevated_bootstrap import (
    claim_pending_for_review,
    complete_review,
    load_import_publication_authorization,
    load_pending,
    record_import_publication_authorization,
)
from finishup.service.import_publication_authority import ImportPublicationAuthority


class _Bytes:
    def __init__(self, value: bytes) -> None:
        self._value = value

    @property
    def declared_size(self) -> int:
        return len(self._value)

    async def _chunks(self) -> AsyncIterator[bytes]:
        yield self._value

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self._chunks()

    async def close(self) -> None:
        return None


def _publication_request(
    *,
    request: str,
    session: str,
    writer: str,
    event_drafts: tuple[object, ...],
    dry_run: bool | None = None,
) -> PublishWorkRequestModel:
    value: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request,
        "session_id": session,
        "writer_id": writer,
        "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
        "event_drafts": event_drafts,
        "actor": {"actor_id": "importer", "actor_type": "importer"},
        "client": {
            "kind": "importer",
            "version": CODEX_JSONL_MAPPING_VERSION,
            "integration": "codex_jsonl_import",
        },
    }
    if dry_run is not None:
        value["dry_run"] = dry_run
    return PublishWorkRequestModel.model_validate(value)


@pytest.mark.anyio
async def test_production_plan_is_persisted_and_immediately_resumable_for_consent(
    tmp_path: Path,
) -> None:
    task = ids.task_id("codex-plan")
    session = ids.session_id("codex-plan")
    writer = ids.writer_id("codex-plan")
    id_port = FixedIds()
    objects = MemoryObjects(id_port)
    plans = CodexImportPlans(
        task_id=task,
        objects=cast(ObjectStorePort, objects),
        clock=cast(ClockPort, FixedClock()),
        ids=cast(IdPort, id_port),
    )
    importer = MemoryImporter(
        task_id=task,
        admitted_session_id=session,
        ownership_fence=ownership_fence(),
        state=MemoryImportState(),
        transaction_lock=asyncio.Lock(),
        objects=cast(ObjectStorePort, objects),
        ledger=cast(LedgerPort, object()),
        clock=cast(ClockPort, FixedClock()),
        ids=cast(IdPort, id_port),
        plan_preparer=plans.prepare,
        plan_reader=plans.read,
    )
    captured = await importer.capture(
        ImportCaptureInput(
            cast(ImportByteSource, _Bytes(b'{"type":"turn.started"}\n')),
            "0.139.0",
            "codex-exec-jsonl/0.139.0/v1",
            (),
            "control-import",
            0,
            Timestamp("2026-07-19T12:00:00.000Z"),
            "stdin",
        )
    )
    identity_body = {
        "codex_capability_profile_id": captured.codex_capability_profile_id,
        "mapping_version": CODEX_JSONL_MAPPING_VERSION,
        "source_commitment": captured.source_commitment,
        "task_id": task,
    }
    identity = ImportSourceIdentity(
        task_id(task),
        captured.source_commitment,
        captured.codex_capability_profile_id,
        CODEX_JSONL_MAPPING_VERSION,
        canonical_digest(identity_body),
    )

    def command(request: str) -> ImportCommand:
        return ImportCommand(
            session_id(session),
            writer_id(writer),
            request_id(request),
            canonical_digest({"request_id": request}),
            identity,
            CODEX_JSONL_MAPPING_VERSION,
        )

    allocation = await importer.reserve_or_resume(command(ids.request_id("plan-1")), captured)
    plan = await importer.prepare_plan(allocation)
    allocation = await importer.publish_plan(allocation, plan)
    assert plan.candidate_count == 1
    assert allocation.captured_source == captured
    material = await plans.read(plan.batch_plan_objects[0])
    assert tuple(draft.event_id for draft in material.event_drafts) == (
        plan.candidates[0].event_id,
    )

    authority = ImportPublicationAuthority(state_path=tmp_path)
    with pytest.raises(PublicOperationError) as caught:
        authority.activate(allocation)
    assert caught.value.code is PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED
    pending = load_pending(_state=tmp_path)
    assert pending is not None
    assert pending.import_publication_preview is not None
    assert pending.import_publication_preview["reasoning_items_included"] is False

    await importer.release_lease_for_authorization(allocation)
    resumed = await importer.reserve_or_resume(command(ids.request_id("plan-2")), captured)
    assert resumed.outcome is ImportAllocationOutcome.RESUMED
    assert resumed.plan_digest == plan.plan_digest
    claimed = claim_pending_for_review(_state=tmp_path)
    authorization = record_import_publication_authorization(claimed, _state=tmp_path)
    complete_review(claimed, outcome="approved", _state=tmp_path)
    token = authority.activate(resumed)
    draft_values = tuple(
        strict_json_parse(event_draft_bytes(draft)) for draft in material.event_drafts
    )
    publication = _publication_request(
        request=plan.batch_request_ids[0],
        session=session,
        writer=writer,
        event_drafts=draft_values,
    )
    authority.bind(
        token,
        request_id=plan.batch_request_ids[0],
        event_ids=tuple(candidate.event_id for candidate in plan.candidates),
    )
    assert (
        authority(
            _publication_request(
                request=plan.batch_request_ids[0],
                session=session,
                writer=writer,
                event_drafts=draft_values,
                dry_run=True,
            )
        )
        is False
    )
    assert authority(publication) is True
    assert authority(publication) is False
    authority.deactivate(token, completed=False)
    assert (
        load_import_publication_authorization(authorization.target_digest, _state=tmp_path)
        == authorization
    )

    restarted = ImportPublicationAuthority(state_path=tmp_path)
    restart_token = restarted.activate(resumed)
    restarted.bind(
        restart_token,
        request_id=plan.batch_request_ids[0],
        event_ids=tuple(candidate.event_id for candidate in plan.candidates),
    )
    assert restarted(publication) is True
    restarted.deactivate(restart_token, completed=True)
    assert (
        load_import_publication_authorization(authorization.target_digest, _state=tmp_path) is None
    )
