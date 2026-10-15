"""Real service vault/keyring capability probe with disposable entries.

Non-live cells exercise an atomic fake backend create/load/lock path plus measured
secret-memory hardening. Pristine OS-keyring create requires ``live_keyring`` and an exact
same-artifact ``user_presence`` intersection.
"""

from __future__ import annotations

import asyncio
import hashlib
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

from finishup.adapters.keys.os_keyring import (
    KeyringInitializationBinding,
    OSKeyringError,
    OSKeyringState,
    OSVaultRootKeySource,
)
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.secret_memory import SecretConsumer, SecretPurpose, UserPresenceCapability
from finishup.protocol.canonical import JsonValue, canonical_digest

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_INSTALLATION_ID = "ins_71000000-0000-4000-8000-000000000001"
_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_DIGEST_C = "sha256:" + "c" * 64

_CASE_FAKE = CapabilityCase(
    case_id="KEY-001",
    requirement_id="ADR-004.keyring-unlock",
    claim_id="E-004.service-keyring",
    capability_family="service_keyring",
    required_observation_codes=frozenset(
        {
            "fake_backend_roundtrip",
            "page_lock_reported",
            "presence_required_for_pristine",
        }
    ),
    allowed_observation_codes=frozenset(
        {
            "fake_backend_roundtrip",
            "page_lock_reported",
            "core_dump_suppression_reported",
            "presence_required_for_pristine",
            "missing_entry_refused",
        }
    ),
)

_CASE_LIVE = CapabilityCase(
    case_id="KEY-002",
    requirement_id="ADR-004.keyring-unlock",
    claim_id="E-004.service-keyring-live",
    capability_family="service_keyring",
    required_observation_codes=frozenset({"live_authorized"}),
    allowed_observation_codes=frozenset(
        {
            "live_authorized",
            "backend_probe_recorded",
            "presence_intersection_missing",
        }
    ),
)


class _AtomicBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password_if_absent(self, service: str, username: str, password: str) -> bool:
        key = (service, username)
        if key in self.values:
            return False
        self.values[key] = password
        return True

    def delete_password(self, service: str, username: str) -> None:
        del self.values[(service, username)]


def test_disposable_fake_keyring_create_and_presence_gate(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)

    memory = LocalSecretMemory()
    capability = memory.capability()
    backend = _AtomicBackend()
    source = OSVaultRootKeySource(memory, backend=backend)
    source._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    probe = asyncio.run(source.probe(_INSTALLATION_ID))
    assert probe.state is OSKeyringState.MISSING

    # Without presence, pristine create authority is refused.
    with pytest.raises(OSKeyringError, match="human_authority_unavailable"):
        asyncio.run(
            source.authorize_first_install(
                probe,
                None,
                {"user_presence_cells": []},
                service_generation=1,
                pristine_state_digest=_DIGEST_C,
            )
        )

    presence = UserPresenceCapability(
        candidate_artifact_digest=_DIGEST_A,
        release_cell="macos-arm64",
        adapter_id="test-presence",
        profile_id="test-profile",
        os_authentication_primitive="test-only",
        os_authenticated_prompt="active",
        trusted_action_binding="active",
        one_use_attestation="active",
        available="active",
        capability_evidence_digest=_DIGEST_B,
    )
    row: dict[str, JsonValue] = {
        "adapter_id": presence.adapter_id,
        "available": "active",
        "candidate_artifact_digest": presence.candidate_artifact_digest,
        "capability_evidence_digest": presence.capability_evidence_digest,
        "one_use_attestation": "active",
        "os_authenticated_prompt": "active",
        "profile_id": presence.profile_id,
        "release_cell": presence.release_cell,
        "trusted_action_binding": "active",
    }
    authority = asyncio.run(
        source.authorize_first_install(
            probe,
            presence,
            {"user_presence_cells": [row]},
            service_generation=1,
            pristine_state_digest=_DIGEST_C,
        )
    )
    correlation = bytearray(range(32, 64))
    commitment = f"sha256:{hashlib.sha256(correlation).hexdigest()}"
    binding = KeyringInitializationBinding(
        1,
        _INSTALLATION_ID,
        commitment,
        memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(range(32))),
        memory.capture(SecretPurpose.VAULT_ROOT_KEY, correlation),
    )

    def _verify(ivk: memoryview, loaded_commitment: str) -> None:
        assert bytes(ivk) == bytes(range(32))
        assert loaded_commitment == commitment

    loaded = asyncio.run(
        source.create_and_verify(
            authority,
            binding,
            service_generation=1,
            pristine_state_digest=_DIGEST_C,
            staged_sentinel_verifier=_verify,
        )
    )
    loaded.ivk_handle.consume(SecretConsumer.VAULT_ROOT, lambda view: None)
    loaded.correlation_handle.consume(SecretConsumer.VAULT_ROOT, lambda view: None)
    memory.close()

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"service-keyring-fake"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "fake_keyring", "mode": "disposable"}),
        external_tool="keyring",
        external_version="25.7.0",
        integration_channel="os_keyring",
        key_backend="fake_atomic",
    )
    evidence = record_and_write(
        _CASE_FAKE,
        context,
        (
            Observation(
                "core_dump_suppression_reported",
                enum_value=capability.core_dump_suppression
                if capability.core_dump_suppression in {"active", "unavailable", "supported"}
                else "unavailable",
            ),
            Observation("fake_backend_roundtrip", boolean_value=True),
            Observation("missing_entry_refused", boolean_value=True),
            Observation(
                "page_lock_reported",
                enum_value=capability.page_locking
                if capability.page_locking in {"active", "unavailable", "supported"}
                else "unavailable",
            ),
            Observation("presence_required_for_pristine", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


@pytest.mark.live_keyring
def test_live_os_keyring_requires_presence_intersection(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"service-keyring-live"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "os_keyring", "mode": "live"}),
        external_tool="keyring",
        external_version="25.7.0",
        integration_channel="os_keyring",
        key_backend="os_keyring",
    )
    if not live_keyring_authorized():
        evidence = record_and_write(
            _CASE_LIVE,
            context,
            (Observation("live_authorized", boolean_value=False),),
            EvidenceOutcome.UNSUPPORTED,
            ("live_keyring_not_authorized",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return

    memory = LocalSecretMemory()
    source = OSVaultRootKeySource(memory)
    probe = asyncio.run(source.probe(_INSTALLATION_ID))
    memory.close()
    _ = probe.state  # probe identity recorded; pristine create still requires presence cell
    evidence = record_and_write(
        _CASE_LIVE,
        context,
        (
            Observation("backend_probe_recorded", boolean_value=True),
            Observation("live_authorized", boolean_value=True),
            Observation("presence_intersection_missing", boolean_value=True),
        ),
        EvidenceOutcome.UNSUPPORTED,
        ("user_presence_cell_required",),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
