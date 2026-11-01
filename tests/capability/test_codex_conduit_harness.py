"""Gate 2 Codex conduit harness: fail closed when no exact Codex artifact is available."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    capability_evidence_output_root,
    record_and_write,
    runtime_capability_context,
)

from finishup.adapters.integrations.codex_capability_harness import (
    CODEX_ARTIFACT_UNAVAILABLE,
    CODEX_CONDUIT_DRIVER_UNAVAILABLE,
    evaluate_codex_conduit_availability,
)
from finishup.protocol.canonical import canonical_digest

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())


def test_codex_conduit_harness_fails_closed_without_artifact(tmp_path: Path) -> None:
    """Gate 2 skeleton: without an exact Codex artifact, never silently pass.

    Real app-server protocol driving is out of scope for this change. Discovery returning nothing
    must surface ``codex_artifact_unavailable``.
    """

    evidence_root = capability_evidence_output_root(tmp_path)
    availability, identity = evaluate_codex_conduit_availability()
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"gate2-codex-conduit-skeleton"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"gate": "2", "harness": "codex_conduit"}),
        external_tool="codex",
        external_version="unprofiled",
        integration_channel="codex_app_server",
    )
    case = CapabilityCase(
        case_id="CODEX-G2-CONDUIT",
        requirement_id="codex_conduit_app_server",
        claim_id="E-002.codex-conduit-skeleton",
        capability_family="codex_app_server_conduit",
        required_observation_codes=frozenset({"conduit_availability"}),
        allowed_observation_codes=frozenset({"conduit_availability", "artifact_digest_present"}),
    )
    if availability == CODEX_ARTIFACT_UNAVAILABLE:
        assert identity is None
        evidence = record_and_write(
            case,
            context,
            (Observation("conduit_availability", enum_value=CODEX_ARTIFACT_UNAVAILABLE),),
            EvidenceOutcome.UNSUPPORTED,
            (CODEX_ARTIFACT_UNAVAILABLE,),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        pytest.skip(CODEX_ARTIFACT_UNAVAILABLE)
    assert identity is not None
    evidence = record_and_write(
        case,
        context,
        (
            Observation("artifact_digest_present", digest_value=identity.executable_digest),
            Observation("conduit_availability", enum_value=CODEX_CONDUIT_DRIVER_UNAVAILABLE),
        ),
        EvidenceOutcome.UNSUPPORTED,
        (CODEX_CONDUIT_DRIVER_UNAVAILABLE,),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
    pytest.skip("codex_conduit_driver_unavailable: Gate 2 app-server driving not implemented")
