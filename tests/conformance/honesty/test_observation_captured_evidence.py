"""Issue #302 captured-observation evidence provenance and weakening rules."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

from finishup.application.observation_materialize import (
    materialize_observation_envelope,
    materialize_observation_inspection_snapshot,
)
from finishup.domain.events import (
    EVIDENCE_SCHEMA_VERSION,
    EvidenceDigestProvenance,
    EvidenceImmutability,
    EvidenceRecordedPayload,
    ResultRecordedPayload,
)
from finishup.domain.observation import (
    ObservationContentKind,
    ObservationContentManifest,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationInspectionSnapshot,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.coverage import ArtifactObservation, AuthorshipAssurance, PublicationChannel
from fixture_loader import load_fixture_json

_FIXTURE = "canonical/OBS-001-captured-evidence.case.json"


def _case() -> dict[str, Any]:
    return cast(dict[str, Any], load_fixture_json(_FIXTURE))


def _inputs() -> tuple[str, ObservationEnvelope, tuple[ObservationContentManifest, ...]]:
    fixture = _case()["input"]
    raw = fixture["envelope"]
    cursor = raw["cursor"]
    envelope = ObservationEnvelope(
        session_commitment=raw["session_commitment"],
        event_kind=raw["event_kind"],
        source_identity=raw["source_identity"],
        source=ObservationSource(raw["source"]),
        cursor=ObservationCursor(
            cursor["hook_seq"],
            cursor["session_stream_pos"],
            cursor["source_ordinal"],
            cursor["last_commitment"],
            cursor["mapping_version"],
        ),
        receipt_time=Timestamp(raw["receipt_time"]),
        structural_payload=JsonObject(raw["structural_payload"]),
        content_object_refs=tuple(raw["content_object_refs"]),
        gap_codes=tuple(raw["gap_codes"]),
    )
    manifests = tuple(
        ObservationContentManifest(
            object_id=item["object_id"],
            envelope_digest=item["envelope_digest"],
            content_kind=ObservationContentKind(item["content_kind"]),
            part_index=item["part_index"],
            part_count=item["part_count"],
            redacted=item["redacted"],
            content_digest=item["content_digest"],
            content_bytes=item["content_bytes"],
        )
        for item in fixture["manifests"]
    )
    return fixture["task_id"], envelope, manifests


def test_captured_evidence_matches_golden_vector_and_excludes_narrative_content() -> None:
    task_id, envelope, manifests = _inputs()
    expected = _case()["expected"]
    batch = materialize_observation_envelope(envelope, task_id=task_id, captured_content=manifests)

    assert [item.draft.schema.name for item in batch.drafts] == expected["draft_schema_names"]
    evidence_draft = batch.drafts[1].draft
    assert evidence_draft.schema.version == EVIDENCE_SCHEMA_VERSION == "1.2.0"
    payload = cast(EvidenceRecordedPayload, evidence_draft.payload)
    assert payload.captured_object_id == expected["evidence"]["captured_object_id"]
    assert payload.content_digest == expected["evidence"]["content_digest"]
    assert payload.strength.value == expected["evidence"]["strength"]
    assert payload.digest_binding is not None
    assert payload.digest_binding.provenance.value == expected["evidence"]["provenance"]
    assert payload.digest_binding.subject.value == expected["evidence"]["digest_subject"]
    assert (
        payload.digest_binding.content_availability.value
        == expected["evidence"]["content_availability"]
    )
    assert batch.coverage.artifact_observation.value == expected["coverage"]["artifact_observation"]
    assert batch.coverage.authorship_assurance.value == expected["coverage"]["authorship_assurance"]
    assert (
        batch.coverage.evidence_immutability.value == expected["coverage"]["evidence_immutability"]
    )
    assert [item.value for item in batch.coverage.publication_channels] == expected["coverage"][
        "publication_channels"
    ]
    assert list(batch.coverage.known_gaps) == expected["coverage"]["known_gaps"]
    artifact_refs = {str(ref) for item in batch.drafts for ref in item.draft.artifact_refs}
    assert not artifact_refs.intersection(expected["excluded_object_ids"])
    result = cast(ResultRecordedPayload, batch.drafts[-1].draft.payload)
    assert result.evidence_refs == (payload.evidence_id,)


def test_missing_old_and_redacted_capture_bindings_weaken_without_invention() -> None:
    task_id, envelope, manifests = _inputs()
    captured = manifests[0]

    missing = materialize_observation_envelope(envelope, task_id=task_id, captured_content=())
    assert missing.coverage.artifact_observation is ArtifactObservation.HOOK_OBSERVED
    assert ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value in missing.gaps
    assert all(item.draft.schema.name != "evidence_recorded" for item in missing.drafts)

    historical = replace(captured, content_digest=None, content_bytes=None)
    old_row = materialize_observation_envelope(
        replace(envelope, content_object_refs=(captured.object_id,)),
        task_id=task_id,
        captured_content=(historical,),
    )
    assert ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value in old_row.gaps
    assert old_row.coverage.artifact_observation is ArtifactObservation.HOOK_OBSERVED

    redacted = materialize_observation_envelope(
        replace(envelope, content_object_refs=(captured.object_id,)),
        task_id=task_id,
        captured_content=(replace(captured, redacted=True),),
    )
    assert redacted.coverage.artifact_observation is ArtifactObservation.CONTENT_CAPTURED
    assert redacted.coverage.evidence_immutability is EvidenceImmutability.IMMUTABLE_SNAPSHOT
    assert ObservationGapCode.CONTENT_REDACTED.value in redacted.gaps
    assert ObservationGapCode.CONTENT_REDACTED.value in redacted.coverage.known_gaps

    unselected = materialize_observation_envelope(
        replace(envelope, content_object_refs=(captured.object_id,)),
        task_id=task_id,
        captured_content=(
            replace(captured, content_kind=ObservationContentKind.VISIBLE_USER_MESSAGE),
        ),
    )
    assert unselected.coverage.artifact_observation is ArtifactObservation.HOOK_OBSERVED
    assert ObservationGapCode.CONTENT_UNSELECTED.value in unselected.gaps
    assert all(item.draft.schema.name != "evidence_recorded" for item in unselected.drafts)

    stale = materialize_observation_envelope(
        replace(
            envelope,
            content_object_refs=(captured.object_id,),
            gap_codes=(ObservationGapCode.CURSOR_STALE.value,),
        ),
        task_id=task_id,
        captured_content=(captured,),
    )
    assert stale.coverage.artifact_observation is ArtifactObservation.CONTENT_CAPTURED
    assert ObservationGapCode.CURSOR_STALE.value in stale.coverage.known_gaps


def test_inspection_objects_materialize_as_separate_bounded_evidence() -> None:
    task_id, _envelope, _manifests = _inputs()
    snapshot = ObservationInspectionSnapshot(
        snapshot_id="inspection-302",
        finishup_session_id="ses_00000000-0000-4000-8000-000000000302",
        subject_state_digest="sha256:" + "1" * 64,
        changed_paths_digest="sha256:" + "2" * 64,
        facts_object_id="obj_00000000-0000-4000-8000-000000000304",
        facts_content_digest="sha256:" + "3" * 64,
        facts_content_bytes=40,
        excerpt_object_id="obj_00000000-0000-4000-8000-000000000305",
        excerpt_content_digest="sha256:" + "4" * 64,
        excerpt_content_bytes=80,
        excerpt_redacted=True,
        excerpt_truncated=True,
        recorded_at=Timestamp("2026-08-30T00:00:01.000Z"),
    )
    batch = materialize_observation_inspection_snapshot(snapshot, task_id=task_id)
    assert batch.skip_reason is None
    assert len(batch.drafts) == 2
    assert batch.channel is PublicationChannel.HOOK_OBSERVED
    assert batch.coverage.authorship_assurance is AuthorshipAssurance.HARNESS_OBSERVED
    assert batch.coverage.artifact_observation is ArtifactObservation.CONTENT_CAPTURED
    assert ObservationGapCode.CONTENT_REDACTED.value in batch.coverage.known_gaps
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value in batch.coverage.known_gaps
    for item in batch.drafts:
        payload = cast(EvidenceRecordedPayload, item.draft.payload)
        assert payload.strength is EvidenceImmutability.IMMUTABLE_SNAPSHOT
        assert payload.digest_binding is not None
        assert payload.digest_binding.provenance is EvidenceDigestProvenance.OBSERVATION_CAPTURED
        assert payload.subject_state is not None
        assert payload.subject_state.described_state == (
            "observation-inspection:" + snapshot.subject_state_digest
        )


def test_multipart_result_refs_are_canonical_when_object_order_differs(
    monkeypatch: Any,
) -> None:
    import finishup.application.observation_materialize as materialize_module

    task_id, envelope, manifests = _inputs()
    first = replace(manifests[0], part_index=0, part_count=2)
    second = replace(
        first,
        object_id="obj_ffffffff-ffff-4fff-8fff-ffffffffffff",
        part_index=1,
    )
    envelope = replace(
        envelope, content_object_refs=tuple(sorted((first.object_id, second.object_id)))
    )
    original = materialize_module._captured_evidence_drafts  # pyright: ignore[reportPrivateUsage]
    input_refs: list[str] = []

    def descending_inputs(*args: Any, **kwargs: Any) -> object:
        rows = kwargs["manifests"]
        ordered = sorted(
            rows,
            key=lambda row: original(*args, **{**kwargs, "manifests": (row,)})[1][0],
            reverse=True,
        )
        input_refs.extend(
            original(*args, **{**kwargs, "manifests": (row,)})[1][0] for row in ordered
        )
        return original(*args, **{**kwargs, "manifests": tuple(ordered)})

    monkeypatch.setattr(materialize_module, "_captured_evidence_drafts", descending_inputs)
    batch = materialize_observation_envelope(
        envelope, task_id=task_id, captured_content=(first, second)
    )
    assert len(input_refs) == 2 and input_refs != sorted(input_refs)
    result = next(
        item.draft.payload
        for item in batch.drafts
        if isinstance(item.draft.payload, ResultRecordedPayload)
    )
    assert result.evidence_refs == tuple(sorted(input_refs))
