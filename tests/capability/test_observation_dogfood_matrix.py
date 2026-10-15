"""Offline dogfood matrix for structural observation across synthetic Codex profiles.

Non-live: proves generic structural ingestion for an unknown future Codex version and for
older/current fixture profiles when present. Live codex-testing binary paths stay marked
``@pytest.mark.live`` and are skipped unless explicitly authorized.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    capability_evidence_output_root,
    live_codex_authorized,
    record_and_write,
    runtime_capability_context,
)

from builders.codex_rollout import completed_shell_rollout
from finishup.adapters.importers.codex_jsonl import (
    SUPPORTED_CODEX_PROFILES,
    CodexCapabilityProfile,
    parse_codex_jsonl,
    profile_for_codex_version,
)
from finishup.adapters.integrations.codex_session_stream import (
    SessionStreamReader,
    default_stream_profile,
    envelope_from_stream_record,
    structural_from_stream_record,
)
from finishup.adapters.integrations.observation_local import (
    STREAM_MAPPING_VERSION,
    LocalObservationStore,
)
from finishup.domain.observation import (
    ObservationCursor,
    ObservationGapCode,
    ObservationSource,
    ObservationStatusQuery,
)
from finishup.protocol.canonical import canonical_digest

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_EMPTY = "hmac-sha256:" + ("0" * 64)


def _case(case_id: str, claim: str) -> CapabilityCase:
    return CapabilityCase(
        case_id=case_id,
        requirement_id="ADR-010.observation-dogfood",
        claim_id=claim,
        capability_family="codex_observation_dogfood",
        required_observation_codes=frozenset({"structural_ingest_ok"}),
        allowed_observation_codes=frozenset(
            {
                "structural_ingest_ok",
                "unknown_future_gap",
                "fixture_profile_present",
                "generic_mapping_used",
            }
        ),
    )


def test_synthetic_unknown_future_codex_version_generic_ingest(tmp_path: Path) -> None:
    """Prove generic parsing of an unfamiliar host record (stable facts + coverage gap).

    Does not inject a pre-built unsupported envelope into an old profile. Instead builds a
    future host JSON record, extracts allowlisted structural facts via the stream mapper,
    and records an unsupported-event gap without inventing success.
    """

    evidence_root = capability_evidence_output_root(tmp_path)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("future-codex")
    store.bind_session(workspace, session)

    from finishup.adapters.importers.codex_jsonl import CodexParsedRecord
    from finishup.domain.values import JsonObject

    # Unfamiliar future host wrapper — not a known profile envelope injection.
    future_record = CodexParsedRecord(
        1,
        0,
        160,
        "future.host.event.v99",
        "command_execution",
        JsonObject(
            {
                "type": "future.host.event.v99",
                "item": {
                    "id": "fx-future-1",
                    "type": "command_execution",
                    "exit_code": 0,
                    "status": "completed",
                    "novel_prose": "must-not-become-success-proof",
                },
                "codex_version": "99.0.0-future",
            }
        ),
    )
    structural, gaps = structural_from_stream_record(future_record)
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in gaps
    # Validated stable structural facts only (exit status / tool identity), never prose.
    assert structural.get("exit_status") == 0 or structural.get("tool_name") is not None
    assert "novel_prose" not in structural
    envelope = envelope_from_stream_record(
        future_record,
        session_commitment=session,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=160,
            event_position=1,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
    )
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in envelope.gap_codes
    assert store.ingest(envelope).disposition.value == "accepted"
    # Observation continues: a later known stream line still ingests on a fresh generation.
    path = tmp_path / "future.jsonl"
    path.write_bytes(completed_shell_rollout())
    reader = SessionStreamReader(
        session_commitment=session,
        profile=default_stream_profile(),
        cursor=ObservationCursor(
            source_generation=2,
            byte_position=0,
            event_position=0,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
        key_material=store.key_material(),
    )
    advance = reader.advance(path)
    assert advance.envelopes
    for item in advance.envelopes:
        assert store.ingest(item).disposition.value in {"accepted", "duplicate"}
    status = store.status(ObservationStatusQuery(workspace))
    assert status.source_coverage[ObservationSource.CODEX_SESSION_STREAM] is True
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in status.gaps

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"synthetic-future-codex-obs"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest(
            {"codex_version": "99.0.0-future", "mode": "generic_structural"}
        ),
        external_tool="codex",
        external_version="99.0.0-future",
        integration_channel="codex_session_stream",
    )
    evidence = record_and_write(
        _case("OBS-DOGFOOD-FUTURE", "E-013.observation-future-generic"),
        context,
        (
            Observation("structural_ingest_ok", boolean_value=True),
            Observation("generic_mapping_used", boolean_value=True),
            Observation("unknown_future_gap", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        (),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


def test_fixture_profiles_older_or_current_when_present(tmp_path: Path) -> None:
    evidence_root = capability_evidence_output_root(tmp_path)
    profiles = tuple(sorted(SUPPORTED_CODEX_PROFILES))
    assert profiles, "expected at least one registered Codex profile"
    selected: list[CodexCapabilityProfile] = []
    for version in profiles:
        try:
            selected.append(profile_for_codex_version(version))
        except ValueError:
            continue
    assert selected
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for index, profile in enumerate(selected[:2]):
        session = store.session_commitment(f"profile-{index}")
        store.bind_session(workspace, session)
        sample = (
            b'{"type":"item.completed","item":{"id":"p%d","type":"command_execution",'
            b'"command":"true","aggregated_output":"","exit_code":0,"status":"completed"}}\n'
            % index
        )
        parsed = parse_codex_jsonl(sample, profile=profile)
        assert parsed.records
        for record in parsed.records:
            envelope = envelope_from_stream_record(
                record,
                session_commitment=session,
                cursor=ObservationCursor(
                    source_generation=1,
                    byte_position=max(8, (index + 1) * 16),
                    event_position=index + 1,
                    last_source_commitment=_EMPTY,
                    mapping_version=STREAM_MAPPING_VERSION,
                ),
            )
            assert store.ingest(envelope).disposition.value in {"accepted", "duplicate"}

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"fixture-profile-obs-matrix"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"profiles": list(profiles[:2])}),
        external_tool="codex",
        external_version=str(profiles[0]),
        integration_channel="codex_session_stream",
    )
    evidence = record_and_write(
        _case("OBS-DOGFOOD-PROFILES", "E-013.observation-fixture-profiles"),
        context,
        (
            Observation("structural_ingest_ok", boolean_value=True),
            Observation("fixture_profile_present", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        (),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


@pytest.mark.live
def test_live_codex_observation_dogfood_optional(tmp_path: Path) -> None:
    if not live_codex_authorized():
        pytest.skip("live codex not authorized")
    pytest.skip("live codex-testing binary observation dogfood not required offline")
