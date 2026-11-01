"""Production plan preparation for the bounded ``codex exec --json`` importer."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import cast

from finishup.adapters.importers.codex_jsonl import (
    CODEX_JSONL_MAPPING_VERSION,
    CodexMappingContext,
    CodexMaterializationIds,
    materialize_codex_mapping,
    parse_codex_jsonl,
    plan_codex_mapping,
    profile_for_codex_version,
)
from finishup.adapters.memory.importer import (
    ImportPlanMaterial,
    event_draft_bytes,
    event_draft_from_json,
    read_exact_object,
)
from finishup.domain.values import (
    EventId,
    EvidenceId,
    RequestId,
    Timestamp,
    event_id,
    evidence_id,
    request_id,
    timestamp_from_string,
)
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.importer import (
    ImportAllocation,
    ImportEventCandidate,
    ImportGap,
    ImportLineOutcome,
    ImportLineStatus,
    PreparedImportPlan,
)
from finishup.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectSource,
    ObjectStorePort,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.coverage import (
    Coverage,
    PublicationChannel,
    coverage_for_channel,
    coverage_from_json,
    coverage_to_json,
    weakest,
)
from finishup.protocol.ids import IdKind
from finishup.protocol.models import MAX_EVENTS_PER_BATCH

__all__ = ["CodexImportPlans"]

_PLAN_MEDIA_TYPE = "application/vnd.yoetz.import_plan+json"


def _line_json(value: ImportLineOutcome) -> dict[str, JsonValue]:
    return {
        "line_ordinal": value.line_ordinal,
        "byte_start": value.byte_start,
        "byte_end": value.byte_end,
        "status": value.status.value,
        "source_category": value.source_category,
        "candidate_indexes": list(value.candidate_indexes),
        "gap_code": value.gap_code,
    }


def _gap_json(value: ImportGap) -> dict[str, JsonValue]:
    return {
        "code": value.code,
        "source_object_id": value.source_object_id,
        "line_ordinal": value.line_ordinal,
        "byte_start": value.byte_start,
        "byte_end": value.byte_end,
        "coverage": coverage_to_json(value.coverage),
    }


def _line_from_json(value: object) -> ImportLineOutcome:
    row = cast(Mapping[str, object], value)
    return ImportLineOutcome(
        line_ordinal=cast(int, row["line_ordinal"]),
        byte_start=cast(int, row["byte_start"]),
        byte_end=cast(int, row["byte_end"]),
        status=ImportLineStatus(cast(str, row["status"])),
        source_category=cast(str | None, row["source_category"]),
        candidate_indexes=tuple(cast(tuple[int, ...], row["candidate_indexes"])),
        gap_code=cast(str | None, row["gap_code"]),
    )


def _gap_from_json(value: object) -> ImportGap:
    row = cast(Mapping[str, object], value)
    return ImportGap(
        code=cast(str, row["code"]),
        source_object_id=cast(str, row["source_object_id"]),
        line_ordinal=cast(int, row["line_ordinal"]),
        byte_start=cast(int, row["byte_start"]),
        byte_end=cast(int, row["byte_end"]),
        coverage=coverage_from_json(cast(JsonValue, row["coverage"])),
    )


class CodexImportPlans:
    """Prepare and read encrypted batch plans through the owning object-store port."""

    def __init__(
        self,
        *,
        task_id: str,
        objects: ObjectStorePort,
        clock: ClockPort,
        ids: IdPort,
    ) -> None:
        self._task_id = task_id
        self._objects = objects
        self._clock = clock
        self._ids = ids

    async def _captured_at(self, allocation: ImportAllocation) -> Timestamp:
        captured = allocation.captured_source
        raw = await read_exact_object(self._objects, captured.capture_metadata_object)
        parsed = strict_json_parse(raw)
        if not isinstance(parsed, dict) or canonical_encode(parsed) != raw:
            raise ValueError("import_capture_manifest_invalid")
        if parsed.get("source_object_id") != captured.source_object.object_id:
            raise ValueError("import_capture_manifest_invalid")
        return timestamp_from_string(parsed["captured_at"])

    async def _finalize_plan_object(
        self,
        *,
        drafts: tuple[object, ...],
        outcomes: tuple[ImportLineOutcome, ...],
        gaps: tuple[ImportGap, ...],
        coverage: Coverage,
    ) -> ObjectRef:
        body: dict[str, JsonValue] = {
            "schema": "yoetz.import-plan/1",
            "event_drafts": list(cast(tuple[JsonValue, ...], drafts)),
            "line_outcomes": [_line_json(item) for item in outcomes],
            "gaps": [_gap_json(item) for item in gaps],
            "coverage": coverage_to_json(coverage),
        }
        raw = canonical_encode(body)
        staged = await self._objects.stage(
            ObjectSource(data=raw, declared_size=len(raw)),
            ObjectMetadata(
                ObjectKind.IMPORT_PLAN,
                _PLAN_MEDIA_TYPE,
                self._task_id,
                self._clock.now_utc(),
            ),
        )
        return await self._objects.finalize(staged)

    async def prepare(self, allocation: ImportAllocation) -> PreparedImportPlan:
        captured = allocation.captured_source
        source_bytes = await read_exact_object(self._objects, captured.source_object)
        profile = profile_for_codex_version(captured.codex_version)
        if profile.profile_id != captured.codex_capability_profile_id:
            raise ValueError("codex_mapping_profile_mismatch")
        context = CodexMappingContext(
            captured.source_object,
            captured.source_commitment,
            await self._captured_at(allocation),
            profile,
            CODEX_JSONL_MAPPING_VERSION,
            coverage_for_channel(PublicationChannel.CODEX_JSONL_IMPORT),
        )
        template = plan_codex_mapping(parse_codex_jsonl(source_bytes, profile), context)
        event_ids = {
            candidate.local_key: self._ids.new(IdKind.EVENT) for candidate in template.candidates
        }
        logical_ids = {
            candidate.logical_key: self._ids.new(
                IdKind.ACTION if candidate.kind == "action" else IdKind.RESULT
            )
            for candidate in template.candidates
            if candidate.logical_key is not None
        }
        placeholder = ObjectRef(
            self._ids.new(IdKind.OBJECT),
            0,
            captured.source_commitment,
            captured.source_object.envelope_digest,
            "yoetz-object/1",
            captured.source_object.key_slot,
            ObjectMetadata(
                ObjectKind.IMPORT_PLAN,
                _PLAN_MEDIA_TYPE,
                self._task_id,
                self._clock.now_utc(),
            ),
        )
        materialized = materialize_codex_mapping(
            template,
            CodexMaterializationIds(event_ids, logical_ids, placeholder),
        )
        references: list[ObjectRef] = []
        candidates: list[ImportEventCandidate] = []
        request_ids: list[RequestId] = []
        for start in range(0, len(materialized.event_drafts), MAX_EVENTS_PER_BATCH):
            end = min(start + MAX_EVENTS_PER_BATCH, len(materialized.event_drafts))
            batch_candidates = materialized.candidates[start:end]
            indexes = {candidate.candidate_index for candidate in batch_candidates}
            outcomes = tuple(
                outcome
                for outcome in materialized.line_outcomes
                if indexes.intersection(outcome.candidate_indexes)
            )
            ranges = tuple(
                (candidate.byte_start, candidate.byte_end) for candidate in batch_candidates
            )
            gaps = tuple(
                gap
                for gap in materialized.gaps
                if any(
                    not (gap.byte_end <= left or gap.byte_start >= right) for left, right in ranges
                )
            )
            coverage = context.coverage
            for candidate in batch_candidates:
                coverage = weakest(coverage, candidate.coverage)
            for gap in gaps:
                coverage = weakest(coverage, gap.coverage)
            drafts_json = tuple(
                strict_json_parse(event_draft_bytes(draft))
                for draft in materialized.event_drafts[start:end]
            )
            ref = await self._finalize_plan_object(
                drafts=drafts_json,
                outcomes=outcomes,
                gaps=gaps,
                coverage=coverage,
            )
            references.append(ref)
            request_ids.append(request_id(self._ids.new(IdKind.REQUEST)))
            candidates.extend(replace(candidate, plan_object=ref) for candidate in batch_candidates)
        report_request_id: RequestId = request_id(self._ids.new(IdKind.REQUEST))
        report_event_id: EventId = event_id(self._ids.new(IdKind.EVENT))
        report_evidence_id: EvidenceId = evidence_id(self._ids.new(IdKind.EVIDENCE))
        plan_manifest: dict[str, JsonValue] = {
            "schema": "yoetz.import-plan-manifest/1",
            "source_identity_digest": allocation.source_identity.identity_digest,
            "mapping_version": allocation.source_identity.mapping_version,
            "batch_request_ids": [str(value) for value in request_ids],
            "batch_plan_objects": [
                {
                    "object_id": ref.object_id,
                    "commitment": ref.commitment,
                    "envelope_digest": ref.envelope_digest,
                }
                for ref in references
            ],
            "event_ids": [str(candidate.event_id) for candidate in candidates],
            "report_request_id": str(report_request_id),
            "report_event_id": str(report_event_id),
            "report_evidence_id": str(report_evidence_id),
        }
        plan_digest = canonical_digest(plan_manifest)
        return PreparedImportPlan(
            source_identity=allocation.source_identity,
            mapping_version=allocation.source_identity.mapping_version,
            line_outcomes=materialized.line_outcomes,
            candidates=tuple(candidates),
            gaps=materialized.gaps,
            candidate_count=len(candidates),
            gap_count=len(materialized.gaps),
            batch_plan_objects=tuple(references),
            batch_request_ids=tuple(request_ids),
            report_request_id=report_request_id,
            report_event_id=report_event_id,
            report_evidence_id=report_evidence_id,
            plan_digest=plan_digest,
        )

    async def read(self, ref: ObjectRef) -> ImportPlanMaterial:
        raw = await read_exact_object(self._objects, ref)
        parsed = strict_json_parse(raw)
        if not isinstance(parsed, Mapping) or canonical_encode(parsed) != raw:
            raise ValueError("import_plan_object_invalid")
        if parsed.get("schema") != "yoetz.import-plan/1":
            raise ValueError("import_plan_object_invalid")
        return ImportPlanMaterial(
            event_drafts=tuple(
                event_draft_from_json(item)
                for item in cast(tuple[object, ...], parsed["event_drafts"])
            ),
            line_outcomes=tuple(
                _line_from_json(item) for item in cast(tuple[object, ...], parsed["line_outcomes"])
            ),
            gaps=tuple(_gap_from_json(item) for item in cast(tuple[object, ...], parsed["gaps"])),
            coverage=coverage_from_json(parsed["coverage"]),
        )
