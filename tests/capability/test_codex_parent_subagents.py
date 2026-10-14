"""Parent/subagent attribution capability evidence.

Non-live cells record that multi-agent claims remain unsupported while Codex capability profiles
are unfrozen. Live coordination through real Codex subagents requires ``FINISHUP_LIVE_CODEX=1``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    codex_profiles_frozen,
    live_codex_authorized,
    record_and_write,
    runtime_capability_context,
)
from finishup.adapters.integrations.codex_skill import CODEX_HARNESS_PROFILE
from finishup.protocol.canonical import canonical_digest

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_VERSION = "0.139.0"


def test_multi_agent_claim_unsupported_while_profiles_unfrozen(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    assert CODEX_HARNESS_PROFILE.capability_profile_ids == ()
    assert CODEX_HARNESS_PROFILE.supported_versions == ()
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"parent-subagents-unprofiled"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "parent_subagents"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    if codex_profiles_frozen():
        pytest.skip("frozen profiles move parent/subagent cells into the live matrix")
    evidence = record_and_write(
        CapabilityCase(
            case_id="PSA-001",
            requirement_id="ADR-005.parent-subagents",
            claim_id="E-002.parent-subagents",
            capability_family="codex_parent_subagents",
            required_observation_codes=frozenset(
                {"profiles_frozen", "harness_profile_empty", "simulated_propagation"}
            ),
            allowed_observation_codes=frozenset(
                {
                    "profiles_frozen",
                    "harness_profile_empty",
                    "simulated_propagation",
                }
            ),
        ),
        context,
        (
            Observation("profiles_frozen", boolean_value=False),
            Observation("harness_profile_empty", boolean_value=True),
            Observation("simulated_propagation", boolean_value=False),
        ),
        EvidenceOutcome.UNSUPPORTED,
        ("codex_subagent_context_unprobed",),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
    assert evidence.reasons == ("codex_subagent_context_unprobed",)


def test_writer_attribution_must_not_upgrade_from_prompt_labels(tmp_path: Path) -> None:
    """Negative control: capability evidence forbids treating caller labels as verified identity."""

    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"no-assurance-upgrade"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "assurance_boundary"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="PSA-002",
            requirement_id="ADR-005.parent-subagents",
            claim_id="E-002.parent-subagents",
            capability_family="codex_parent_subagents",
            required_observation_codes=frozenset({"assurance_upgrade_attempted"}),
            allowed_observation_codes=frozenset({"assurance_upgrade_attempted"}),
        ),
        context,
        (Observation("assurance_upgrade_attempted", boolean_value=False),),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


@pytest.mark.live
def test_live_parent_and_two_subagents(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"live-parent-subagents"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "live_parent_subagents"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
    )
    if not live_codex_authorized():
        evidence = record_and_write(
            CapabilityCase(
                case_id="PSA-LIVE-001",
                requirement_id="ADR-005.parent-subagents",
                claim_id="E-002.parent-subagents-live",
                capability_family="codex_parent_subagents",
                required_observation_codes=frozenset({"live_authorized"}),
                allowed_observation_codes=frozenset({"live_authorized"}),
            ),
            context,
            (Observation("live_authorized", boolean_value=False),),
            EvidenceOutcome.UNSUPPORTED,
            ("live_codex_not_authorized",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return
    pytest.fail(
        "live parent/subagent matrix authorized; observe distinct writers, contradiction, "
        "and receipt before claiming pass"
    )
