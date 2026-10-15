"""Foreground human-control phase, binding, and authority integration coverage."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

import pytest

from finishup.adapters.keys.installation_recovery import (
    InstallationRecoveryArtifact,
    InstallationRecoveryMode,
    InstallationRecoverySecretKind,
    create_installation_recovery_artifact,
)
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.control import ServiceState
from finishup.ports.secret_memory import (
    HumanAuthorizationProof,
    SecretConsumer,
    SecretHandle,
    SecretPurpose,
    UserPresenceAttestation,
    UserPresenceCapability,
    UserPresenceChallenge,
)
from finishup.protocol.canonical import canonical_digest
from finishup.service.confidential_protocol import (
    AuthorizationRequiredPhase,
    ClientActionEnvelope,
    ClientOpenEnvelope,
    ConfidentialSecretPurpose,
    DecisionAction,
    DecisionRequiredPhase,
    EmptyVaultTarget,
    HumanCeremonyKind,
    HumanPreview,
    IdleRelockPolicyResult,
    IdleRelockPolicyTarget,
    InstallationRecoveryPreview,
    InstallationRecoveryResult,
    InstallationRecoveryTarget,
    KeyringRetryPreview,
    OwnerReceiptViewResult,
    OwnerReceiptViewTarget,
    PortableRecoveryResult,
    PortableRecoveryTarget,
    PrivacyDecisionResult,
    PrivacyDisclosureDecisionPreview,
    PrivacyPendingTarget,
    ProviderCredentialResult,
    ProviderCredentialSetPreview,
    ProviderCredentialTarget,
    RetryAction,
    SecretRequiredPhase,
    SelectAuthorizationSourceAction,
    ServerPhaseEnvelope,
    ServerResultEnvelope,
    VaultPassphraseRotatePreview,
    VaultStateResult,
    VaultUnlockPreview,
)
from finishup.service.human_control import HumanControlError, HumanControlService
from finishup.service.unlock import UnlockCoordinator, UnlockThrottleStore

INSTALLATION_ID = "ins_20000000-0000-4000-8000-000000000001"
SERVICE_ID = "svc_20000000-0000-4000-8000-000000000002"
TARGET_DIGEST = "sha256:" + "2" * 64
ZERO_DIGEST = "sha256:" + "0" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _Clock:
    monotonic: float = 100.0
    utc: datetime = datetime(2026, 7, 19, 13, 0, 0, tzinfo=UTC)

    def now_utc(self) -> datetime:
        return self.utc

    def monotonic_seconds(self) -> float:
        return self.monotonic


@dataclass(frozen=True)
class _Instance:
    instance_id: str = SERVICE_ID
    generation: int = 7


class _Lifecycle:
    def __init__(self, state: ServiceState) -> None:
        self.instance = _Instance()
        self.state = state

    async def transition(
        self, target: ServiceState, *, vault_generation: int | None = None
    ) -> None:
        if target is ServiceState.READY and vault_generation is None:
            raise AssertionError("ready requires vault generation")
        self.state = target


@dataclass(frozen=True)
class _VaultStatus:
    reason: str | None = None


class _Vault:
    def __init__(self, mode: str, *, ready: bool) -> None:
        self.mode = mode
        self.generation = 3
        self.ready = ready
        self.status = _VaultStatus()
        self.presence: _Presence | None = None

    @property
    def state(self) -> str:
        return "ready" if self.ready else "locked"

    async def retry_keyring(self, user_presence_capability: UserPresenceCapability | None) -> None:
        self.ready = user_presence_capability is not None

    async def initialize_passphrase(
        self, handle: SecretHandle, throttle_record_digest: str
    ) -> None:
        assert throttle_record_digest.startswith("sha256:")
        handle.consume(SecretConsumer.VAULT_ROOT, bytes)
        self.mode = "passphrase"
        self.ready = True
        self.generation += 1

    async def unlock(self, handle: SecretHandle) -> None:
        handle.consume(SecretConsumer.VAULT_ROOT, bytes)
        self.ready = True
        self.generation += 1

    async def recover_passphrase(
        self,
        artifact: InstallationRecoveryArtifact,
        recovery_secret: SecretHandle,
        rewrap_secret: SecretHandle,
        *,
        throttle_record_digest: str,
    ) -> None:
        assert type(artifact) is InstallationRecoveryArtifact
        assert throttle_record_digest.startswith("sha256:")
        recovery_secret.consume(SecretConsumer.INSTALLATION_RECOVERY, bytes)
        rewrap_secret.consume(SecretConsumer.VAULT_REWRAPPER, bytes)
        self.mode = "passphrase"
        self.ready = True
        self.generation += 1

    async def lock(self) -> None:
        self.ready = False
        self.generation += 1

    async def mint_human_authorization(
        self,
        source: UserPresenceAttestation | SecretHandle,
        challenge: UserPresenceChallenge,
    ) -> HumanAuthorizationProof:
        if hasattr(source, "purpose"):
            secret = cast(SecretHandle, source)
            consumer = {
                SecretPurpose.PROVIDER_REAUTHENTICATION: SecretConsumer.PROVIDER_AUTHORIZER,
                SecretPurpose.PRIVACY_REAUTHENTICATION: SecretConsumer.PRIVACY_AUTHORIZER,
                SecretPurpose.SECURITY_REAUTHENTICATION: SecretConsumer.SECURITY_AUTHORIZER,
            }[secret.purpose]
            secret.consume(consumer, bytes)
        else:
            assert self.presence is not None
            self.presence.consume(cast(UserPresenceAttestation, source), challenge)
        return HumanAuthorizationProof(
            proof_id="proof-test",
            purpose=challenge.purpose,
            target_digest=challenge.target_digest,
            service_generation=challenge.service_generation,
            vault_generation=challenge.vault_generation,
            policy_generation=challenge.policy_generation,
            issued_at_monotonic=100.0,
            expires_at_monotonic=challenge.expires_at_monotonic,
        )


class _SecretIngress:
    """A stub that still enforces the one rule the real ingress enforces: one nonce, one frame.

    The real `accept_once` refuses a `secret_challenge` it has already accepted. A stub that
    ignored the binding entirely let the server hand two consecutive frames the same consumed
    unlock challenge and still pass, which is exactly how the reauthentication chain shipped
    unable to reach its second secret.
    """

    def __init__(self, handles: list[SecretHandle]) -> None:
        self.handles = handles
        self.cancelled = 0
        self.challenges: list[str] = []

    async def accept_once(self, expected_binding: object) -> SecretHandle:
        challenge = cast(str, getattr(expected_binding, "secret_challenge"))
        if challenge in self.challenges:
            raise AssertionError("secret_challenge_replayed")
        self.challenges.append(challenge)
        return self.handles.pop(0)

    async def cancel_pending(self) -> None:
        self.cancelled += 1

    async def close(self) -> None:
        return None


@dataclass
class _Attestation:
    used: bool = False


class _Presence:
    def __init__(self, *, active: bool = True) -> None:
        self.active = active
        self.last_challenge: UserPresenceChallenge | None = None
        self.attestation = _Attestation()

    def capability(self) -> UserPresenceCapability:
        state: Literal["active", "unavailable"] = "active" if self.active else "unavailable"
        return UserPresenceCapability(
            candidate_artifact_digest=ZERO_DIGEST,
            release_cell="test-cell",
            adapter_id="test.presence",
            profile_id="test.profile",
            os_authentication_primitive="test prompt",
            os_authenticated_prompt=state,
            trusted_action_binding=state,
            one_use_attestation=state,
            available=state,
            capability_evidence_digest=ZERO_DIGEST,
        )

    async def assert_presence(self, challenge: UserPresenceChallenge) -> UserPresenceAttestation:
        self.last_challenge = challenge
        return cast(UserPresenceAttestation, self.attestation)

    def consume(
        self, attestation: UserPresenceAttestation, challenge: UserPresenceChallenge
    ) -> None:
        assert attestation is self.attestation
        assert challenge is self.last_challenge
        if self.attestation.used:
            raise ValueError("replay")
        self.attestation.used = True

    def close(self) -> None:
        return None


class _Effects:
    def __init__(self, artifact: InstallationRecoveryArtifact | None = None) -> None:
        self.proofs: list[HumanAuthorizationProof | None] = []
        self.artifact = artifact
        self.continuation_finished: bool | None = None

    async def prepare(self, request: ClientOpenEnvelope) -> tuple[HumanPreview, str, int | None]:
        if request.ceremony_kind is HumanCeremonyKind.VAULT_UNLOCK:
            return VaultUnlockPreview(), TARGET_DIGEST, None
        if request.ceremony_kind is HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE:
            return VaultPassphraseRotatePreview(), TARGET_DIGEST, None
        if request.ceremony_kind is HumanCeremonyKind.KEYRING_RETRY:
            return KeyringRetryPreview("existing_load"), TARGET_DIGEST, None
        if request.ceremony_kind is HumanCeremonyKind.PROVIDER_CREDENTIAL_SET:
            return (
                ProviderCredentialSetPreview(cast(ProviderCredentialTarget, request.target)),
                TARGET_DIGEST,
                None,
            )
        if request.ceremony_kind is HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION:
            target = cast(PrivacyPendingTarget, request.target)
            return (
                PrivacyDisclosureDecisionPreview(
                    pending_id=target.pending_id,
                    excerpt_preview="bounded preview",
                    excerpt_digest=ZERO_DIGEST,
                    category="ordinary-content",
                    destination_commitment=ZERO_DIGEST,
                    byte_count=15,
                    token_count=2,
                    policy_digest=ZERO_DIGEST,
                ),
                TARGET_DIGEST,
                4,
            )
        if request.ceremony_kind is HumanCeremonyKind.INSTALLATION_RECOVERY:
            target = cast(InstallationRecoveryTarget, request.target)
            return (
                InstallationRecoveryPreview(
                    target.operation,
                    target.request_id,
                    target.confirmed_plan_digest,
                    target.recovery_generation,
                    target.set_mode,
                    target.secret_kind,
                    target.target_envelope,
                    1,
                    1,
                    False,
                ),
                target.plan_digest(),
                None,
            )
        raise AssertionError(request.ceremony_kind)

    async def complete_portable_recovery(
        self, target: PortableRecoveryTarget, secret: SecretHandle
    ) -> PortableRecoveryResult:
        del target, secret
        raise AssertionError("not used")

    async def complete_installation_provision(
        self,
        target: InstallationRecoveryTarget,
        secret: SecretHandle,
        rewrap_secret: SecretHandle | None,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> InstallationRecoveryResult:
        secret.consume(SecretConsumer.INSTALLATION_RECOVERY, bytes)
        if rewrap_secret is not None:
            rewrap_secret.consume(SecretConsumer.VAULT_REWRAPPER, bytes)
        proof.consume(
            "installation_recovery_change",
            proof.target_digest,
            7,
            3,
            None,
            now_monotonic,
        )
        self.proofs.append(proof)
        return InstallationRecoveryResult(
            target.operation,
            "completed",
            target.recovery_generation,
            proof.target_digest,
        )

    async def revoke_installation_recovery(
        self,
        target: InstallationRecoveryTarget,
        rewrap_secret: SecretHandle,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> InstallationRecoveryResult:
        rewrap_secret.consume(SecretConsumer.VAULT_REWRAPPER, bytes)
        proof.consume(
            "installation_recovery_change",
            proof.target_digest,
            7,
            3,
            None,
            now_monotonic,
        )
        return InstallationRecoveryResult(
            "revoke", "completed", target.recovery_generation, proof.target_digest
        )

    def begin_installation_restore(self, target: InstallationRecoveryTarget) -> tuple[object, str]:
        assert target.operation == "restore"
        assert self.artifact is not None
        return self.artifact, "f" * 64

    def finish_installation_restore(self, continuation_id: str, *, success: bool) -> None:
        assert continuation_id == "f" * 64
        self.continuation_finished = success

    async def cancel_installation_recovery(self, target: InstallationRecoveryTarget) -> None:
        del target

    async def store_provider_credential(
        self,
        target: ProviderCredentialTarget,
        secret: SecretHandle,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> ProviderCredentialResult:
        secret.consume(SecretConsumer.PROVIDER_AUTHORIZER, bytes)
        proof.consume("provider_credential_set", TARGET_DIGEST, 7, 3, None, now_monotonic)
        self.proofs.append(proof)
        return ProviderCredentialResult(target.action, 1, "stored")

    async def rotate_vault_passphrase(
        self,
        target: EmptyVaultTarget,
        secret: SecretHandle,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> VaultStateResult:
        assert target.expected_mode == "passphrase"
        secret.consume(SecretConsumer.VAULT_REWRAPPER, bytes)
        proof.consume("vault_passphrase_rotate", TARGET_DIGEST, 7, 3, None, now_monotonic)
        self.proofs.append(proof)
        return VaultStateResult("ready", "succeeded")

    async def decide_privacy(
        self,
        target: PrivacyPendingTarget,
        decision: Literal["approve", "deny"],
        proof: HumanAuthorizationProof | None,
        now_monotonic: float,
    ) -> PrivacyDecisionResult:
        del target, now_monotonic
        self.proofs.append(proof)
        return PrivacyDecisionResult(
            "committed" if decision == "approve" else "denied", ZERO_DIGEST
        )

    async def change_idle_relock_policy(
        self,
        target: IdleRelockPolicyTarget,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> IdleRelockPolicyResult:
        del target, proof, now_monotonic
        raise AssertionError("not used")

    async def deny_idle_relock_policy(
        self,
        target: IdleRelockPolicyTarget,
        now_monotonic: float,
    ) -> IdleRelockPolicyResult:
        del target, now_monotonic
        raise AssertionError("not used")

    async def authorize_owner_receipt_view(
        self,
        target: OwnerReceiptViewTarget,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> OwnerReceiptViewResult:
        del target, proof, now_monotonic
        raise AssertionError("not used")


def _service(
    tmp_path: Path,
    *,
    mode: str,
    ready: bool,
    handles: list[SecretHandle],
    presence: _Presence | None = None,
    effects: _Effects | None = None,
) -> tuple[HumanControlService, _Clock, _Lifecycle, _Vault, _Effects]:
    tmp_path.chmod(0o700)
    clock = _Clock()
    lifecycle = _Lifecycle(ServiceState.READY if ready else ServiceState.LOCKED)
    vault = _Vault(mode, ready=ready)
    vault.presence = presence
    throttle = UnlockThrottleStore(
        tmp_path / "unlock-throttle.json",
        installation_id=INSTALLATION_ID,
        writer_instance_id=SERVICE_ID,
        clock=clock,
    )
    if mode == "passphrase":
        throttle.stage_initial_record()

    async def activate_ready(service_generation: int, vault_generation: int) -> None:
        assert service_generation == lifecycle.instance.generation
        assert vault_generation == vault.generation
        assert vault.ready
        await lifecycle.transition(ServiceState.READY, vault_generation=vault_generation)

    unlock = UnlockCoordinator(
        clock=clock,
        throttle=throttle,
        vault=vault,
        lifecycle=lifecycle,
        activate_ready=activate_ready,
    )
    effects = _Effects() if effects is None else effects
    service = HumanControlService(
        clock=clock,
        lifecycle=lifecycle,
        vault=vault,
        unlock=unlock,
        secret_ingress=_SecretIngress(handles),
        effects=effects,
        user_presence=presence,
    )
    return service, clock, lifecycle, vault, effects


@pytest.mark.anyio
async def test_passphrase_unlock_uses_separate_exact_secret_binding(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    handle = memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(b"correct horse battery"))
    service, _, lifecycle, vault, _ = _service(
        tmp_path, mode="passphrase", ready=False, handles=[handle]
    )
    opened = await service.open_ceremony(
        ClientOpenEnvelope(
            "1" * 64,
            HumanCeremonyKind.VAULT_UNLOCK,
            EmptyVaultTarget(expected_mode="passphrase"),
        )
    )
    assert type(opened.phase) is SecretRequiredPhase
    assert opened.phase.binding.purpose is ConfidentialSecretPurpose.VAULT_UNLOCK
    result = await service.secret_completed(opened.ceremony_id)
    assert type(result) is ServerResultEnvelope
    assert result.step == 2
    assert result.result == cast(object, result.result)
    assert lifecycle.state is ServiceState.READY
    assert vault.ready
    memory.close()


@pytest.mark.anyio
async def test_installation_recovery_uses_two_distinct_secret_frames(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    recovery_bytes = bytearray(b"recovery horse battery staple")
    artifact = create_installation_recovery_artifact(
        memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(b"i" * 32)),
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(recovery_bytes)),
        recovery_generation=1,
        mode=InstallationRecoveryMode.COMPACT,
        secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        snapshot_manifest_digest=None,
    )
    recovery_handle = memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(recovery_bytes))
    rewrap_handle = memory.capture(
        SecretPurpose.VAULT_REWRAP, bytearray(b"new correct horse battery")
    )
    provisional = InstallationRecoveryTarget(
        "restore",
        "req_20000000-0000-4000-8000-000000000009",
        ZERO_DIGEST,
        1,
        "compact",
        "argon2id_passphrase",
        "passphrase",
    )
    target = InstallationRecoveryTarget(
        provisional.operation,
        provisional.request_id,
        provisional.plan_digest(),
        provisional.recovery_generation,
        provisional.set_mode,
        provisional.secret_kind,
        provisional.target_envelope,
    )
    effects = _Effects(artifact)
    service, _, lifecycle, vault, _ = _service(
        tmp_path,
        mode="passphrase",
        ready=False,
        handles=[recovery_handle, rewrap_handle],
        effects=effects,
    )

    opened = await service.open_ceremony(
        ClientOpenEnvelope(
            "9" * 64,
            HumanCeremonyKind.INSTALLATION_RECOVERY,
            target,
        )
    )
    assert type(opened.phase) is SecretRequiredPhase
    assert opened.phase.binding.purpose is ConfidentialSecretPurpose.INSTALLATION_RECOVERY
    second = await service.secret_completed(opened.ceremony_id)
    assert type(second) is ServerPhaseEnvelope
    assert type(second.phase) is SecretRequiredPhase
    assert second.phase.binding.purpose is ConfidentialSecretPurpose.VAULT_REWRAP
    assert second.phase.binding.secret_challenge != opened.phase.binding.secret_challenge

    completed = await service.secret_completed(opened.ceremony_id)
    assert type(completed) is ServerResultEnvelope
    assert type(completed.result) is InstallationRecoveryResult
    assert completed.result.status == "completed"
    assert lifecycle.state is ServiceState.READY
    assert vault.ready is True
    assert effects.continuation_finished is True
    memory.close()


@pytest.mark.anyio
async def test_installation_provision_requires_decision_and_reauthentication(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    reauthentication = memory.capture(
        SecretPurpose.SECURITY_REAUTHENTICATION,
        bytearray(b"current correct horse battery"),
    )
    recovery = memory.capture(
        SecretPurpose.INSTALLATION_RECOVERY,
        bytearray(b"recovery correct horse battery"),
    )
    provisional = InstallationRecoveryTarget(
        "provision",
        "req_20000000-0000-4000-8000-000000000010",
        ZERO_DIGEST,
        1,
        "compact",
        "argon2id_passphrase",
        "preserve",
    )
    target = InstallationRecoveryTarget(
        provisional.operation,
        provisional.request_id,
        provisional.plan_digest(),
        provisional.recovery_generation,
        provisional.set_mode,
        provisional.secret_kind,
        provisional.target_envelope,
    )
    service, _, _, _, effects = _service(
        tmp_path,
        mode="passphrase",
        ready=True,
        handles=[reauthentication, recovery],
    )
    opened = await service.open_ceremony(
        ClientOpenEnvelope(
            "8" * 64,
            HumanCeremonyKind.INSTALLATION_RECOVERY,
            target,
        )
    )
    assert type(opened.phase) is DecisionRequiredPhase
    authorization = await service.submit_action(
        ClientActionEnvelope(opened.ceremony_id, 2, DecisionAction("approve"))
    )
    assert type(authorization) is ServerPhaseEnvelope
    assert type(authorization.phase) is AuthorizationRequiredPhase
    reauth_phase = await service.submit_action(
        ClientActionEnvelope(
            opened.ceremony_id,
            authorization.step + 1,
            SelectAuthorizationSourceAction("secret_reauthentication"),
        )
    )
    assert type(reauth_phase) is ServerPhaseEnvelope
    assert type(reauth_phase.phase) is SecretRequiredPhase
    assert reauth_phase.phase.binding.purpose is (
        ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION
    )
    recovery_phase = await service.secret_completed(opened.ceremony_id)
    assert type(recovery_phase) is ServerPhaseEnvelope
    assert type(recovery_phase.phase) is SecretRequiredPhase
    assert recovery_phase.phase.binding.purpose is ConfidentialSecretPurpose.INSTALLATION_RECOVERY
    completed = await service.secret_completed(opened.ceremony_id)
    assert type(completed) is ServerResultEnvelope
    assert type(completed.result) is InstallationRecoveryResult
    assert completed.result.operation == "provision"
    assert completed.result.status == "completed"
    assert len(effects.proofs) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("operation", "secret_purposes"),
    [
        (
            "rotate",
            (
                SecretPurpose.SECURITY_REAUTHENTICATION,
                SecretPurpose.INSTALLATION_RECOVERY,
                SecretPurpose.VAULT_REWRAP,
            ),
        ),
        (
            "revoke",
            (
                SecretPurpose.SECURITY_REAUTHENTICATION,
                SecretPurpose.VAULT_REWRAP,
            ),
        ),
    ],
)
async def test_installation_rotation_and_revoke_use_distinct_new_passphrase_frame(
    tmp_path: Path,
    operation: str,
    secret_purposes: tuple[SecretPurpose, ...],
) -> None:
    memory = LocalSecretMemory()
    handles = [
        memory.capture(purpose, bytearray(f"{purpose.value} horse battery".encode()))
        for purpose in secret_purposes
    ]
    provisional = InstallationRecoveryTarget(
        cast(Literal["rotate", "revoke"], operation),
        "req_20000000-0000-4000-8000-000000000011",
        ZERO_DIGEST,
        2 if operation == "rotate" else 1,
        "compact",
        "argon2id_passphrase",
        "passphrase",
    )
    target = InstallationRecoveryTarget(
        provisional.operation,
        provisional.request_id,
        provisional.plan_digest(),
        provisional.recovery_generation,
        provisional.set_mode,
        provisional.secret_kind,
        provisional.target_envelope,
    )
    service, _, _, _, _ = _service(
        tmp_path,
        mode="passphrase",
        ready=True,
        handles=handles,
    )
    opened = await service.open_ceremony(
        ClientOpenEnvelope("9" * 64, HumanCeremonyKind.INSTALLATION_RECOVERY, target)
    )
    authorization = await service.submit_action(
        ClientActionEnvelope(opened.ceremony_id, 2, DecisionAction("approve"))
    )
    assert type(authorization) is ServerPhaseEnvelope
    phase = await service.submit_action(
        ClientActionEnvelope(
            opened.ceremony_id,
            authorization.step + 1,
            SelectAuthorizationSourceAction("secret_reauthentication"),
        )
    )
    assert type(phase) is ServerPhaseEnvelope
    observed: list[ConfidentialSecretPurpose] = []
    while type(phase) is ServerPhaseEnvelope:
        assert type(phase.phase) is SecretRequiredPhase
        observed.append(phase.phase.binding.purpose)
        phase = await service.secret_completed(opened.ceremony_id)
    assert type(phase) is ServerResultEnvelope
    assert observed == (
        [
            ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION,
            ConfidentialSecretPurpose.INSTALLATION_RECOVERY,
            ConfidentialSecretPurpose.VAULT_REWRAP,
        ]
        if operation == "rotate"
        else [
            ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION,
            ConfidentialSecretPurpose.VAULT_REWRAP,
        ]
    )


@pytest.mark.anyio
async def test_vault_passphrase_rotation_reauthenticates_then_rewraps(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    reauth = memory.capture(
        SecretPurpose.SECURITY_REAUTHENTICATION,
        bytearray(b"current correct horse battery"),
    )
    replacement = memory.capture(
        SecretPurpose.VAULT_REWRAP,
        bytearray(b"replacement correct horse battery"),
    )
    service, _, _, _, effects = _service(
        tmp_path, mode="passphrase", ready=True, handles=[reauth, replacement]
    )
    opened = await service.open_ceremony(
        ClientOpenEnvelope(
            "6" * 64,
            HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE,
            EmptyVaultTarget(expected_mode="passphrase"),
        )
    )
    assert type(opened.preview) is VaultPassphraseRotatePreview
    assert type(opened.phase) is AuthorizationRequiredPhase
    first = await service.submit_action(
        ClientActionEnvelope(
            opened.ceremony_id,
            2,
            SelectAuthorizationSourceAction("secret_reauthentication"),
        )
    )
    assert type(first) is ServerPhaseEnvelope
    assert cast(SecretRequiredPhase, first.phase).binding.purpose is (
        ConfidentialSecretPurpose.SECURITY_REAUTHENTICATION
    )
    second = await service.secret_completed(opened.ceremony_id)
    assert type(second) is ServerPhaseEnvelope
    assert cast(SecretRequiredPhase, second.phase).binding.purpose is (
        ConfidentialSecretPurpose.VAULT_REWRAP
    )
    assert (
        cast(SecretRequiredPhase, first.phase).binding.secret_challenge
        != cast(SecretRequiredPhase, second.phase).binding.secret_challenge
    )
    result = await service.secret_completed(opened.ceremony_id)
    assert type(result) is ServerResultEnvelope
    assert result.result == VaultStateResult("ready", "succeeded")
    assert len(effects.proofs) == 1
    memory.close()


@pytest.mark.anyio
async def test_provider_secret_reauthentication_is_exact_and_proof_is_single_use(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    reauth = memory.capture(
        SecretPurpose.PROVIDER_REAUTHENTICATION, bytearray(b"correct horse battery")
    )
    credential = memory.capture(
        SecretPurpose.PROVIDER_CREDENTIAL, bytearray(b"provider-token-value")
    )
    service, _, _, _, effects = _service(
        tmp_path, mode="passphrase", ready=True, handles=[reauth, credential]
    )
    purpose = "semantic-review"
    target = ProviderCredentialTarget(
        action="set",
        provider_id="openai",
        model_id="gpt-5",
        endpoint_profile_id="responses",
        endpoint_profile_version="1",
        purpose=purpose,
        scope_digest=ZERO_DIGEST,
        purpose_digest=canonical_digest({"purpose": purpose}),
    )
    opened = await service.open_ceremony(
        ClientOpenEnvelope("2" * 64, HumanCeremonyKind.PROVIDER_CREDENTIAL_SET, target)
    )
    assert type(opened.phase) is AuthorizationRequiredPhase
    assert opened.phase.available_sources == ("secret_reauthentication",)
    phase = await service.submit_action(
        ClientActionEnvelope(
            opened.ceremony_id, 2, SelectAuthorizationSourceAction("secret_reauthentication")
        )
    )
    assert type(phase) is ServerPhaseEnvelope
    assert cast(SecretRequiredPhase, phase.phase).binding.purpose is (
        ConfidentialSecretPurpose.PROVIDER_REAUTHENTICATION
    )
    credential_phase = await service.secret_completed(opened.ceremony_id)
    assert type(credential_phase) is ServerPhaseEnvelope
    assert cast(SecretRequiredPhase, credential_phase.phase).binding.purpose is (
        ConfidentialSecretPurpose.PROVIDER_CREDENTIAL
    )
    assert (
        cast(SecretRequiredPhase, credential_phase.phase).binding.secret_challenge
        != cast(SecretRequiredPhase, phase.phase).binding.secret_challenge
    )
    result = await service.secret_completed(opened.ceremony_id)
    assert type(result) is ServerResultEnvelope
    assert result.result == ProviderCredentialResult("set", 1, "stored")
    assert len(effects.proofs) == 1
    with pytest.raises(Exception, match="already_consumed"):
        cast(HumanAuthorizationProof, effects.proofs[0]).consume(
            "provider_credential_set", TARGET_DIGEST, 7, 3, None, 100.0
        )
    memory.close()


@pytest.mark.anyio
async def test_os_presence_is_exact_challenge_bound_and_consumed_once(tmp_path: Path) -> None:
    presence = _Presence()
    memory = LocalSecretMemory()
    credential = memory.capture(
        SecretPurpose.PROVIDER_CREDENTIAL, bytearray(b"provider-token-value")
    )
    service, _, _, _, _ = _service(
        tmp_path, mode="os_keyring", ready=True, handles=[credential], presence=presence
    )
    purpose = "semantic-review"
    target = ProviderCredentialTarget(
        "set",
        "openai",
        "gpt-5",
        "responses",
        "1",
        purpose,
        ZERO_DIGEST,
        canonical_digest({"purpose": purpose}),
    )
    opened = await service.open_ceremony(
        ClientOpenEnvelope("3" * 64, HumanCeremonyKind.PROVIDER_CREDENTIAL_SET, target)
    )
    phase = await service.submit_action(
        ClientActionEnvelope(
            opened.ceremony_id, 2, SelectAuthorizationSourceAction("os_user_presence")
        )
    )
    assert type(phase) is ServerPhaseEnvelope
    assert presence.attestation.used
    assert presence.last_challenge is not None
    assert presence.last_challenge.target_digest == TARGET_DIGEST
    await service.cancel(opened.ceremony_id)
    memory.close()


@pytest.mark.anyio
async def test_disclosure_consent_needs_no_strong_reauth_and_wrong_phase_is_consumed(
    tmp_path: Path,
) -> None:
    service, _, _, _, effects = _service(tmp_path, mode="os_keyring", ready=True, handles=[])
    target = PrivacyPendingTarget("disclosure", "pending-1")
    opened = await service.open_ceremony(
        ClientOpenEnvelope("4" * 64, HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION, target)
    )
    result = await service.submit_action(
        ClientActionEnvelope(opened.ceremony_id, 2, DecisionAction("approve"))
    )
    assert type(result) is ServerResultEnvelope
    assert result.result == PrivacyDecisionResult("committed", ZERO_DIGEST)
    assert effects.proofs == [None]

    reopened = await service.open_ceremony(
        ClientOpenEnvelope("5" * 64, HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION, target)
    )
    with pytest.raises(HumanControlError, match="phase_invalid"):
        await service.submit_action(ClientActionEnvelope(reopened.ceremony_id, 2, RetryAction()))
    with pytest.raises(HumanControlError, match="replay"):
        await service.cancel(reopened.ceremony_id)


@pytest.mark.anyio
async def test_close_during_secret_wait_does_not_deadlock(tmp_path: Path) -> None:
    """Issue #434: stop()/close() must not wait on the YZS1 acceptor mutex."""

    started = asyncio.Event()
    hang = asyncio.Event()

    class _HangIngress:
        cancelled = 0

        async def accept_once(self, expected_binding: object) -> SecretHandle:
            del expected_binding
            started.set()
            await hang.wait()
            raise AssertionError("secret_wait_should_have_been_cancelled")

        async def cancel_pending(self) -> None:
            self.cancelled += 1
            hang.set()

        async def close(self) -> None:
            return None

    service, _, lifecycle, _, _ = _service(tmp_path, mode="passphrase", ready=False, handles=[])
    service._secret_ingress = _HangIngress()  # pyright: ignore[reportPrivateUsage]
    opened = await service.open_ceremony(
        ClientOpenEnvelope(
            "1" * 64,
            HumanCeremonyKind.VAULT_UNLOCK,
            EmptyVaultTarget(expected_mode="passphrase"),
        )
    )
    waiter = asyncio.create_task(service.secret_completed(opened.ceremony_id))
    await asyncio.wait_for(started.wait(), 1.0)
    await asyncio.wait_for(service.close(), 1.0)
    with pytest.raises(HumanControlError, match="cancelled"):
        await asyncio.wait_for(waiter, 1.0)
    assert lifecycle.state is ServiceState.LOCKED
