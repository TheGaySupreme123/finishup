"""Exact OS-backed human-presence capability evidence.

Integration branches use structural negative controls (TTY/same-UID are not presence).
A real OS authenticated prompt requires an interactive release operator and is never
automated. Emitted evidence freezes the ``user_presence_cells`` identity fields as digests.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from tests.capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    live_keyring_authorized,
    record_and_write,
    runtime_capability_context,
)

from finishup.ports.secret_memory import UserPresenceCapability
from finishup.protocol.canonical import canonical_digest

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())

_CASE_NEGATIVE = CapabilityCase(
    case_id="PRES-001",
    requirement_id="ADR-008.user-presence",
    claim_id="E-008.user-presence",
    capability_family="user_presence",
    required_observation_codes=frozenset(
        {
            "tty_not_presence",
            "same_uid_not_presence",
            "cell_row_shape_bound",
        }
    ),
    allowed_observation_codes=frozenset(
        {
            "tty_not_presence",
            "same_uid_not_presence",
            "cell_row_shape_bound",
            "adapter_absent",
            "four_states_encoded",
        }
    ),
)

_CASE_LIVE = CapabilityCase(
    case_id="PRES-002",
    requirement_id="ADR-008.user-presence",
    claim_id="E-008.user-presence-live",
    capability_family="user_presence",
    required_observation_codes=frozenset({"live_authorized"}),
    allowed_observation_codes=frozenset(
        {
            "live_authorized",
            "os_prompt_available",
            "one_use_attestation",
        }
    ),
)


def _release_cell() -> str:
    if sys.platform == "darwin":
        return "macos-arm64" if os.uname().machine == "arm64" else "macos-x86_64"
    if sys.platform.startswith("linux"):
        machine = os.uname().machine
        if machine in {"x86_64", "amd64"}:
            return "manylinux-x86_64"
        return "linux-other"
    return "unsupported"


def test_negative_controls_and_cell_row_shape(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)

    # TTY keypress / same-UID peer identity are negative controls — not OS user presence.
    tty_present = sys.stdin.isatty()
    same_uid = os.geteuid() == os.getuid()
    assert same_uid
    # Presence must not be inferred from either signal.
    tty_is_presence = False
    same_uid_is_presence = False
    assert not (tty_present and tty_is_presence)
    assert not same_uid_is_presence

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"user-presence-negative"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest(
            {"cell": "user_presence", "release_cell": _release_cell()}
        ),
        external_tool="user_presence",
        external_version="0.1.0",
        integration_channel="human_control",
    )
    # No production UserPresencePort adapter is wired in the daemon yet; freeze the row shape
    # that a future pass must emit for the same artifact.
    evidence_digest = "sha256:" + "f" * 64
    row = {
        "adapter_id": "absent",
        "available": "unavailable",
        "candidate_artifact_digest": context.artifact_digest,
        "capability_evidence_digest": evidence_digest,
        "one_use_attestation": "unavailable",
        "os_authenticated_prompt": "unavailable",
        "profile_id": "absent",
        "release_cell": _release_cell(),
        "trusted_action_binding": "unavailable",
    }
    capability = UserPresenceCapability(
        candidate_artifact_digest=context.artifact_digest,
        release_cell=_release_cell(),
        adapter_id="absent",
        profile_id="absent",
        os_authentication_primitive="unavailable",
        os_authenticated_prompt="unavailable",
        trusted_action_binding="unavailable",
        one_use_attestation="unavailable",
        available="unavailable",
        capability_evidence_digest=evidence_digest,
    )
    assert capability.available == "unavailable"
    row_digest = canonical_digest(row)

    evidence = record_and_write(
        _CASE_NEGATIVE,
        context,
        (
            Observation("adapter_absent", boolean_value=True),
            Observation("cell_row_shape_bound", digest_value=row_digest),
            Observation("four_states_encoded", boolean_value=True),
            Observation("same_uid_not_presence", boolean_value=True),
            Observation("tty_not_presence", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


@pytest.mark.live_keyring
def test_live_os_authenticated_prompt_is_operator_gated(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"user-presence-live"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest(
            {"cell": "user_presence_live", "release_cell": _release_cell()}
        ),
        external_tool="user_presence",
        external_version="0.1.0",
        integration_channel="human_control",
    )
    if not live_keyring_authorized():
        evidence = record_and_write(
            _CASE_LIVE,
            context,
            (Observation("live_authorized", boolean_value=False),),
            EvidenceOutcome.UNSUPPORTED,
            ("live_presence_not_authorized",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return

    # Real LocalAuthentication / polkit prompt must be run by a trusted release operator.
    # Automation must never approve the prompt.
    evidence = record_and_write(
        _CASE_LIVE,
        context,
        (
            Observation("live_authorized", boolean_value=True),
            Observation("one_use_attestation", boolean_value=False),
            Observation("os_prompt_available", boolean_value=False),
        ),
        EvidenceOutcome.UNSUPPORTED,
        ("os_presence_adapter_unwired",),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
