from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import replace
from typing import Literal, cast

import pytest

from finishup.domain.privacy import PrivacyPolicyChange, PrivacyPolicyChangeValue
from finishup.protocol.canonical import canonical_digest
from finishup.service.confidential_protocol import (
    CEREMONY_EXPIRY_SECONDS,
    MAX_HUMAN_CONTROL_FRAME_BYTES,
    MAX_SECRET_BYTES,
    PASSPHRASE_MAX_BYTES,
    PASSPHRASE_MIN_BYTES,
    PROVIDER_CREDENTIAL_MAX_BYTES,
    AuthorizationRequiredPhase,
    CancelAction,
    ClientActionEnvelope,
    ClientCancelEnvelope,
    ClientOpenEnvelope,
    ConfidentialProtocolError,
    ConfidentialSecretPurpose,
    DecisionAction,
    DecisionRequiredPhase,
    EmptyVaultTarget,
    HumanCeremonyBinding,
    HumanCeremonyKind,
    HumanOpenTarget,
    IdleRelockPolicyTarget,
    InstallationRecoveryPreview,
    InstallationRecoveryResult,
    InstallationRecoveryTarget,
    KeyringRetryPhase,
    KeyringRetryResult,
    PortableRecoveryTarget,
    PrivacyPendingTarget,
    PrivacyPolicyDecisionPreview,
    PrivacyPolicyTransitionPreviewMember,
    ProviderCredentialTarget,
    RetryAction,
    SecretIngressBinding,
    SecretRequiredPhase,
    SelectAuthorizationSourceAction,
    ServerCloseEnvelope,
    ServerErrorEnvelope,
    ServerOpenedEnvelope,
    ServerPhaseEnvelope,
    ServerResultEnvelope,
    VaultInitializePreview,
    VaultPassphraseRotatePreview,
    VaultStateResult,
    decode_human_frame,
    decode_secret_header,
    encode_human_frame,
    encode_secret_header,
    human_target_json,
    monotonic_milliseconds,
    new_binding_expiry_ms,
    validate_passphrase_buffer,
    validate_provider_credential_buffer,
)

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000001"
_REQUEST_ID = "req_00000000-0000-4000-8000-000000000002"
_DIGEST_A = "sha256:" + "a" * 64
_PURPOSE_DIGEST = "sha256:df4c93f6d19a44d9b8b6c8eae62a0cf3203cde00f35fb220c42ec2a02d5ee8c1"
_REPOSITORY = "hmac-sha256:" + "b" * 64


def _binding(
    purpose: ConfidentialSecretPurpose = ConfidentialSecretPurpose.VAULT_UNLOCK,
) -> SecretIngressBinding:
    return SecretIngressBinding(
        binding_version=1,
        ceremony_id="1" * 64,
        secret_challenge="2" * 64,
        purpose=purpose,
        service_instance_id=_SERVICE_ID,
        service_generation=3,
        vault_generation=4,
        policy_generation=None,
        target_digest=_DIGEST_A,
        expires_at_monotonic_ms=60_000,
    )


def _provider_target(action: str) -> ProviderCredentialTarget:
    return ProviderCredentialTarget(
        action=cast(Literal["set", "rotate"], action),
        provider_id="openai",
        model_id="gpt-5",
        endpoint_profile_id="openai.responses",
        endpoint_profile_version="1.0.0",
        purpose="semantic-review",
        scope_digest=_DIGEST_A,
        purpose_digest=_PURPOSE_DIGEST,
    )


def _wrong_magic(value: bytes) -> bytes:
    return b"BAD!" + value[4:]


def _wrong_version(value: bytes) -> bytes:
    return value[:4] + b"\x02" + value[5:]


def _truncate(value: bytes) -> bytes:
    return value[:-1]


def _append(value: bytes) -> bytes:
    return value + b"x"


def test_frozen_constants_and_all_nine_purpose_codes() -> None:
    assert CEREMONY_EXPIRY_SECONDS == 300
    assert PASSPHRASE_MIN_BYTES == 16
    assert PASSPHRASE_MAX_BYTES == 1_024
    assert PROVIDER_CREDENTIAL_MAX_BYTES == 8_192
    assert MAX_SECRET_BYTES == 16_384
    assert [(item.value, item.name.lower()) for item in ConfidentialSecretPurpose] == [
        (1, "vault_initialize"),
        (2, "vault_unlock"),
        (3, "portable_recovery"),
        (4, "provider_reauthentication"),
        (5, "provider_credential"),
        (6, "privacy_reauthentication"),
        (7, "security_reauthentication"),
        (8, "installation_recovery"),
        (9, "vault_rewrap"),
    ]


def test_client_open_has_literal_reviewed_golden_bytes() -> None:
    envelope = ClientOpenEnvelope(
        connection_nonce="0" * 64,
        ceremony_kind=HumanCeremonyKind.VAULT_INITIALIZE,
        target=EmptyVaultTarget(),
    )
    expected = (
        b'YZH1\x01\x01\x00\x00\x00\xc9{"ceremony_kind":"vault_initialize",'
        b'"connection_nonce":"0000000000000000000000000000000000000000000000000000000000000000",'
        b'"protocol_version":1,"target":{"expected_mode":"uninitialized","kind":"vault"}}'
    )
    assert encode_human_frame(envelope) == expected
    assert decode_human_frame(expected) == envelope


@pytest.mark.parametrize(
    ("kind", "target"),
    [
        (HumanCeremonyKind.VAULT_INITIALIZE, EmptyVaultTarget()),
        (
            HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE,
            EmptyVaultTarget(expected_mode="passphrase"),
        ),
        (HumanCeremonyKind.VAULT_UNLOCK, EmptyVaultTarget(expected_mode="passphrase")),
        (HumanCeremonyKind.KEYRING_RETRY, EmptyVaultTarget(expected_mode="os_keyring")),
        (
            HumanCeremonyKind.PORTABLE_RECOVERY,
            PortableRecoveryTarget("create", _REQUEST_ID, _DIGEST_A),
        ),
        (
            HumanCeremonyKind.INSTALLATION_RECOVERY,
            InstallationRecoveryTarget(
                "restore",
                _REQUEST_ID,
                _DIGEST_A,
                2,
                "self_contained",
                "generated_code",
                "platform_auto_unlock",
            ),
        ),
        (HumanCeremonyKind.PROVIDER_CREDENTIAL_SET, _provider_target("set")),
        (HumanCeremonyKind.PROVIDER_CREDENTIAL_ROTATE, _provider_target("rotate")),
        (
            HumanCeremonyKind.PRIVACY_POLICY_DECISION,
            PrivacyPendingTarget("policy", "pending-policy"),
        ),
        (
            HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION,
            PrivacyPendingTarget("disclosure", "pending-disclosure"),
        ),
        (
            HumanCeremonyKind.IDLE_RELOCK_POLICY_CHANGE,
            IdleRelockPolicyTarget("disable"),
        ),
    ],
)
def test_all_open_targets_are_closed_and_round_trip(
    kind: HumanCeremonyKind,
    target: object,
) -> None:
    envelope = ClientOpenEnvelope("0" * 64, kind, cast(HumanOpenTarget, target))
    assert decode_human_frame(encode_human_frame(envelope)) == envelope


def test_provider_credential_ceremony_is_bound_to_the_trusted_repository() -> None:
    unbound = _provider_target("set")
    bound = replace(unbound, repository_privacy_commitment=_REPOSITORY)

    assert bound.target_digest() != unbound.target_digest()
    envelope = ClientOpenEnvelope("0" * 64, HumanCeremonyKind.PROVIDER_CREDENTIAL_SET, bound)
    assert decode_human_frame(encode_human_frame(envelope)) == envelope


def test_provider_credential_target_digest_hashes_the_one_wire_shape() -> None:
    """Issue #169: a second hand-maintained target serialization drifted from this digest.

    The service binds the ceremony session to ``target_digest()`` and the trusted client
    re-derives it from the shared serializer; both must hash exactly the wire shape, with the
    repository commitment present in both the bound and unbound forms.
    """

    unbound = _provider_target("set")
    bound = replace(unbound, repository_privacy_commitment=_REPOSITORY)
    for target in (unbound, bound):
        wire = human_target_json(target)
        assert "repository_privacy_commitment" in wire
        assert wire["repository_privacy_commitment"] == target.repository_privacy_commitment
        assert target.target_digest() == canonical_digest(wire)


def test_open_kind_and_target_cannot_be_crossed() -> None:
    with pytest.raises(ValueError, match="ceremony_target_mismatch"):
        ClientOpenEnvelope(
            "0" * 64,
            HumanCeremonyKind.VAULT_UNLOCK,
            PrivacyPendingTarget("policy", "pending"),
        )
    with pytest.raises(ValueError, match="ceremony_target_mismatch"):
        ClientOpenEnvelope(
            "0" * 64,
            HumanCeremonyKind.PROVIDER_CREDENTIAL_SET,
            _provider_target("rotate"),
        )


def test_idle_policy_target_is_exactly_set_or_disable() -> None:
    assert IdleRelockPolicyTarget("set", 60).seconds == 60
    assert IdleRelockPolicyTarget("disable").seconds is None
    for invalid in (59, 86_401, None):
        with pytest.raises(ValueError, match="idle_relock_policy_target_invalid"):
            IdleRelockPolicyTarget("set", invalid)
    with pytest.raises(ValueError, match="idle_relock_policy_target_invalid"):
        IdleRelockPolicyTarget("disable", 900)


def test_actions_and_phases_have_no_edit_or_metadata_branch() -> None:
    actions = (
        RetryAction(),
        SelectAuthorizationSourceAction("os_user_presence"),
        DecisionAction("approve"),
        CancelAction(),
    )
    for step, action in enumerate(actions, 1):
        frame = ClientActionEnvelope("1" * 64, step, action)
        assert decode_human_frame(encode_human_frame(frame)) == frame
    phases = (
        SecretRequiredPhase(_binding()),
        AuthorizationRequiredPhase(("os_user_presence", "secret_reauthentication")),
        KeyringRetryPhase(),
        DecisionRequiredPhase(),
    )
    for step, phase in enumerate(phases, 1):
        frame = ServerPhaseEnvelope("1" * 64, step, phase)
        assert decode_human_frame(encode_human_frame(frame)) == frame
    assert b'"edit"' not in b"".join(
        encode_human_frame(ClientActionEnvelope("1" * 64, 1, a)) for a in actions
    )


def test_installation_recovery_preview_and_result_round_trip_without_paths() -> None:
    target = InstallationRecoveryTarget(
        "restore",
        _REQUEST_ID,
        _DIGEST_A,
        2,
        "self_contained",
        "generated_code",
        "passphrase",
    )
    preview = InstallationRecoveryPreview(
        target.operation,
        target.request_id,
        target.confirmed_plan_digest,
        target.recovery_generation,
        target.set_mode,
        target.secret_kind,
        target.target_envelope,
        12,
        4096,
        True,
    )
    opened = ServerOpenedEnvelope(
        "1" * 64,
        1,
        HumanCeremonyBinding(
            1,
            "1" * 64,
            "0" * 64,
            HumanCeremonyKind.INSTALLATION_RECOVERY,
            _SERVICE_ID,
            3,
            0,
            None,
            _DIGEST_A,
            60_000,
        ),
        preview,
        SecretRequiredPhase(_binding(ConfidentialSecretPurpose.INSTALLATION_RECOVERY)),
    )
    encoded = encode_human_frame(opened)
    assert b"path" not in encoded
    assert decode_human_frame(encoded) == opened

    result = ServerResultEnvelope(
        "1" * 64,
        2,
        InstallationRecoveryResult("restore", "completed", 2, _DIGEST_A),
    )
    assert decode_human_frame(encode_human_frame(result)) == result


def test_opened_binding_and_terminal_close_round_trip() -> None:
    ceremony = HumanCeremonyBinding(
        1,
        "1" * 64,
        "0" * 64,
        HumanCeremonyKind.VAULT_INITIALIZE,
        _SERVICE_ID,
        3,
        0,
        None,
        _DIGEST_A,
        60_000,
    )
    opened = ServerOpenedEnvelope(
        "1" * 64,
        1,
        ceremony,
        VaultInitializePreview(),
        SecretRequiredPhase(_binding(ConfidentialSecretPurpose.VAULT_INITIALIZE)),
    )
    assert decode_human_frame(encode_human_frame(opened)) == opened
    close = ServerCloseEnvelope("1" * 64, 2, "completed")
    assert decode_human_frame(encode_human_frame(close)) == close


def test_vault_passphrase_rotation_preview_is_structural_and_round_trips() -> None:
    ceremony = HumanCeremonyBinding(
        1,
        "1" * 64,
        "0" * 64,
        HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE,
        _SERVICE_ID,
        3,
        4,
        None,
        _DIGEST_A,
        60_000,
    )
    opened = ServerOpenedEnvelope(
        "1" * 64,
        1,
        ceremony,
        VaultPassphraseRotatePreview(),
        AuthorizationRequiredPhase(("secret_reauthentication",)),
    )
    assert decode_human_frame(encode_human_frame(opened)) == opened


@pytest.mark.parametrize(
    "result",
    [
        VaultStateResult("locked", "human_authority_unavailable"),
        VaultStateResult("locked", "unlock_failed"),
        VaultStateResult("locked", "unlock_wrong"),
        VaultStateResult("ready", "succeeded"),
        KeyringRetryResult("locked", "keyring_unavailable"),
    ],
)
def test_vault_and_keyring_result_reasons_accept_only_frozen_underscore_codes(
    result: VaultStateResult | KeyringRetryResult,
) -> None:
    envelope = ServerResultEnvelope("1" * 64, 2, result)
    assert decode_human_frame(encode_human_frame(envelope)) == envelope
    with pytest.raises(ValueError):
        replace(result, reason="arbitrary-lower-kebab")


def test_secret_header_has_literal_reviewed_golden_bytes_and_round_trips() -> None:
    expected = (
        b'YZS1\x01\x02\x01\xd5\x00\x00\x00\x10{"binding_version":1,'
        b'"ceremony_id":"1111111111111111111111111111111111111111111111111111111111111111",'
        b'"expires_at_monotonic_ms":60000,"policy_generation":null,"purpose":"vault_unlock",'
        b'"secret_challenge":"2222222222222222222222222222222222222222222222222222222222222222",'
        b'"service_generation":3,"service_instance_id":"svc_00000000-0000-4000-8000-000000000001",'
        b'"target_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"vault_generation":4}'
    )
    assert encode_secret_header(_binding(), 16) == expected
    assert decode_secret_header(expected) == (_binding(), 16)


@pytest.mark.parametrize("purpose", list(ConfidentialSecretPurpose))
def test_all_secret_purpose_headers_round_trip(purpose: ConfidentialSecretPurpose) -> None:
    binding = _binding(purpose)
    assert decode_secret_header(encode_secret_header(binding, 16)) == (binding, 16)


def test_secret_header_rejects_wire_and_binding_purpose_crossing() -> None:
    encoded = bytearray(encode_secret_header(_binding(), 16))
    encoded[5] = ConfidentialSecretPurpose.PORTABLE_RECOVERY
    with pytest.raises(ConfidentialProtocolError, match="binding_invalid"):
        decode_secret_header(encoded)


@pytest.mark.parametrize(
    "mutate",
    [
        _wrong_magic,
        _wrong_version,
        _truncate,
        _append,
    ],
)
def test_human_frame_rejects_wrong_protocol_partial_and_extra(
    mutate: Callable[[bytes], bytes],
) -> None:
    good = encode_human_frame(ClientCancelEnvelope(ceremony_id="1" * 64, step=1))
    with pytest.raises(ConfidentialProtocolError):
        decode_human_frame(mutate(good))


def test_human_frame_rejects_duplicate_unknown_float_bom_nul_and_noncanonical() -> None:
    bad_payloads = (
        b'{"ceremony_id":"' + b"1" * 64 + b'","step":1,"step":1}',
        b'{"ceremony_id":"' + b"1" * 64 + b'","extra":1,"step":1}',
        b'{"ceremony_id":"' + b"1" * 64 + b'","step":1.0}',
        b'\xef\xbb\xbf{"ceremony_id":"' + b"1" * 64 + b'","step":1}',
        b'{"ceremony_id":"' + b"1" * 64 + b'","step":"\x00"}',
        b'{ "ceremony_id":"' + b"1" * 64 + b'","step":1}',
    )
    for payload in bad_payloads:
        frame = struct.pack(">4sBBI", b"YZH1", 1, 7, len(payload)) + payload
        with pytest.raises(ConfidentialProtocolError, match="invalid_frame"):
            decode_human_frame(frame)


def test_declared_human_cap_rejected_before_payload() -> None:
    frame = struct.pack(">4sBBI", b"YZH1", 1, 7, MAX_HUMAN_CONTROL_FRAME_BYTES + 1)
    with pytest.raises(ConfidentialProtocolError, match="frame_too_large"):
        decode_human_frame(frame)


@pytest.mark.parametrize("size", [15, 1_025])
def test_passphrase_byte_bounds_reject(size: int) -> None:
    source = bytearray(b"a" * size)
    with pytest.raises(ConfidentialProtocolError, match="secret_rejected"):
        validate_passphrase_buffer(memoryview(source))


def test_passphrase_accepts_bounds_and_preserves_composed_decomposed_distinction() -> None:
    for source in (
        bytearray(b"a" * 16),
        bytearray(b"a" * 1_024),
        bytearray("caf\u00e9-very-secret".encode()),
        bytearray("cafe\u0301-very-secret".encode()),
    ):
        validate_passphrase_buffer(memoryview(source))


@pytest.mark.parametrize(
    "source",
    [
        bytearray(b"a" * 15 + b"\x00"),
        bytearray(b"a" * 15 + b"\n"),
        bytearray(b"a" * 15 + b"\r"),
        bytearray(b"a" * 15 + b"\xff"),
        bytearray(b"a" * 15 + b"\xed\xa0\x80"),
    ],
)
def test_passphrase_rejects_controls_and_invalid_utf8(source: bytearray) -> None:
    with pytest.raises(ConfidentialProtocolError, match="secret_rejected"):
        validate_passphrase_buffer(memoryview(source))


@pytest.mark.parametrize("size", [0, 8_193])
def test_provider_credential_bounds_reject(size: int) -> None:
    with pytest.raises(ConfidentialProtocolError, match="secret_rejected"):
        validate_provider_credential_buffer(memoryview(bytearray(b"x" * size)))


def test_provider_credential_generic_guard_is_opaque_and_rejects_controls() -> None:
    validate_provider_credential_buffer(memoryview(bytearray(b"x")))
    validate_provider_credential_buffer(memoryview(bytearray(b"x" * 8_192)))
    for source in (bytearray(b"\x00"), bytearray(b"\n"), bytearray(b"\r")):
        with pytest.raises(ConfidentialProtocolError, match="secret_rejected"):
            validate_provider_credential_buffer(memoryview(source))


def test_monotonic_expiry_is_floor_integer_only_and_safe() -> None:
    assert monotonic_milliseconds(1.9999) == 1_999
    assert new_binding_expiry_ms(1.9999) == 1_999 + CEREMONY_EXPIRY_SECONDS * 1_000
    for value in (cast(float, 1), -0.1, float("nan"), float("inf"), 2**53 / 1_000):
        with pytest.raises(ValueError, match="monotonic_sample_invalid"):
            monotonic_milliseconds(value)


def test_errors_are_bounded_and_do_not_echo_input() -> None:
    error = ServerErrorEnvelope("secret_rejected", False, "1" * 64, 3)
    assert decode_human_frame(encode_human_frame(error)) == error
    with pytest.raises(ValueError, match="server_error_code_invalid"):
        replace(error, code="secret-value-do-not-echo")


# ---------------------------------------------------------------------------
# The privacy-widening preview carries the whole diff, or it does not open
# ---------------------------------------------------------------------------


def _policy_changes() -> tuple[PrivacyPolicyChange, ...]:
    """A mixed widening: destination enabled, confirmation removed, disclosure narrowed."""

    return (
        PrivacyPolicyChange(
            "global",
            "network_egress",
            None,
            PrivacyPolicyChangeValue.of_flag(False),
            PrivacyPolicyChangeValue.of_flag(True),
            True,
        ),
        PrivacyPolicyChange(
            "channel",
            "preview_required",
            "llm_inference",
            PrivacyPolicyChangeValue.of_flag(True),
            PrivacyPolicyChangeValue.of_flag(False),
            True,
        ),
        PrivacyPolicyChange(
            "agent_context",
            "categories",
            None,
            PrivacyPolicyChangeValue.of_labels(("claim_text", "declared_file_type")),
            PrivacyPolicyChangeValue.of_labels(("declared_file_type",)),
            False,
        ),
    )


def _policy_preview() -> PrivacyPolicyDecisionPreview:
    return PrivacyPolicyDecisionPreview("pending-1", _DIGEST_A, _policy_changes())


def test_privacy_policy_preview_round_trips_the_complete_change_set() -> None:
    envelope = ServerOpenedEnvelope(
        "1" * 64,
        1,
        HumanCeremonyBinding(
            1,
            "1" * 64,
            "0" * 64,
            HumanCeremonyKind.PRIVACY_POLICY_DECISION,
            _SERVICE_ID,
            3,
            0,
            None,
            _DIGEST_A,
            60_000,
        ),
        _policy_preview(),
        DecisionRequiredPhase(),
    )

    assert decode_human_frame(encode_human_frame(envelope)) == envelope


def test_compound_privacy_preview_round_trips_both_authority_layers() -> None:
    preview = PrivacyPolicyDecisionPreview(
        "pending-1",
        _DIGEST_A,
        (),
        (
            PrivacyPolicyTransitionPreviewMember("machine_ceiling", "replace", _policy_changes()),
            PrivacyPolicyTransitionPreviewMember("repository_grant", "insert", _policy_changes()),
        ),
    )
    envelope = ServerOpenedEnvelope(
        "1" * 64,
        1,
        HumanCeremonyBinding(
            1,
            "1" * 64,
            "0" * 64,
            HumanCeremonyKind.PRIVACY_POLICY_DECISION,
            _SERVICE_ID,
            3,
            0,
            None,
            _DIGEST_A,
            60_000,
        ),
        preview,
        DecisionRequiredPhase(),
    )

    assert decode_human_frame(encode_human_frame(envelope)) == envelope


def test_repository_insert_preview_requires_the_explicit_private_baseline_diff() -> None:
    with pytest.raises(ValueError, match="privacy_policy_preview_member_invalid"):
        PrivacyPolicyTransitionPreviewMember("repository_grant", "insert", ())


def test_a_widening_preview_cannot_be_opened_with_an_incomplete_change_set() -> None:
    """The finding, at the protocol boundary.

    The ceremony exists only for a widening. A change set with nothing that widens means the
    diff is missing whatever caused the classification, so the preview refuses to exist rather
    than rendering an empty approval screen.
    """

    tightening_only = (_policy_changes()[2],)
    for changes in ((), tightening_only):
        with pytest.raises(ValueError, match="privacy_policy_preview_invalid"):
            PrivacyPolicyDecisionPreview("pending-1", _DIGEST_A, changes)


def test_a_privacy_preview_rejects_duplicates_misordering_and_oversize() -> None:
    changes = _policy_changes()
    for invalid in (
        (changes[0], changes[0]),
        tuple(reversed(changes)),
        (changes[0],) * 200,
    ):
        with pytest.raises(ValueError, match="privacy_policy_preview_invalid"):
            PrivacyPolicyDecisionPreview("pending-1", _DIGEST_A, invalid)


def test_a_decoded_privacy_preview_rejects_an_unknown_area_field_or_extra_key() -> None:
    """A token the trusted renderer has no fixed label for never reaches an approval screen."""

    encoded = encode_human_frame(
        ServerOpenedEnvelope(
            "1" * 64,
            1,
            HumanCeremonyBinding(
                1,
                "1" * 64,
                "0" * 64,
                HumanCeremonyKind.PRIVACY_POLICY_DECISION,
                _SERVICE_ID,
                3,
                0,
                None,
                _DIGEST_A,
                60_000,
            ),
            _policy_preview(),
            DecisionRequiredPhase(),
        )
    )
    magic, version, frame_type, _length = struct.unpack(">4sBBI", encoded[:10])
    body = encoded[10:].decode("utf-8")
    for original, replacement in (
        ('"area":"global"', '"area":"telemetry"'),
        ('"field":"network_egress"', '"field":"send_everything"'),
        ('"widens":true', '"widens":true,"explanation":"perfectly safe"'),
    ):
        assert original in body, original
        tampered = body.replace(original, replacement, 1).encode("utf-8")
        frame = struct.pack(">4sBBI", magic, version, frame_type, len(tampered)) + tampered
        with pytest.raises((ValueError, ConfidentialProtocolError)):
            decode_human_frame(frame)
