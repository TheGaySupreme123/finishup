"""Original- and clean-profile installation-vault recovery drills."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from yoetz.adapters.keys.encrypted_vault import EncryptedVaultError, EncryptedVaultStore
from yoetz.adapters.keys.installation_recovery import (
    InstallationRecoveryMode,
    InstallationRecoverySecretKind,
    unlock_installation_recovery_artifact,
)
from yoetz.adapters.keys.secret_memory import LocalSecretMemory
from yoetz.application.receipt import ReceiptInternalResult
from yoetz.config.models import YoetzConfig
from yoetz.domain.privacy import AuthorizationScope, AuthorizationScopeKind
from yoetz.ports.control import ServiceState
from yoetz.ports.keys import MacKeyPurpose
from yoetz.ports.ledger import CheckCommitResult
from yoetz.ports.secret_memory import HumanAuthorizationProof, SecretPurpose
from yoetz.protocol.models import CheckRequest, ReceiptRequest, StartRequest
from yoetz.service.confidential_protocol import (
    ClientOpenEnvelope,
    HumanCeremonyKind,
    InstallationRecoveryTarget,
)
from yoetz.service.daemon import (
    _InstallationStateStore,
    _LockedHumanEffects,
    _PrivacyPolicyAppRelay,
)
from yoetz.service.installation_recovery import InstallationRecoverySetStore
from yoetz.service.lifecycle import ServiceLifecycle
from yoetz.service.ready_composition import build_ready_application_factory
from yoetz.service.unlock import UnlockCoordinator, UnlockThrottleStore
from yoetz.service.vault import (
    VaultMode,
    VaultService,
    VaultState,
    provider_credential_profile_binding,
)

INSTALLATION_ID = "ins_30000000-0000-4000-8000-000000000001"
SERVICE_ID = "svc_30000000-0000-4000-8000-000000000002"
TASK_ID = "tsk_30000000-0000-4000-8000-000000000003"


@dataclass
class _Clock:
    monotonic: float = 10.0

    def now_utc(self) -> datetime:
        return datetime(2026, 8, 23, 20, 0, 0, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return self.monotonic


class _GenerationStore:
    def advance(self, instance_id: str) -> int:
        del instance_id
        return 1


@dataclass(frozen=True)
class _Paths:
    bundle: Path
    state: Path


def _private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True)
    path.chmod(0o700)


@pytest.fixture
def private_test_root() -> Iterator[Path]:
    """Keep synthetic installation state outside pytest's shared temporary root."""

    with tempfile.TemporaryDirectory(
        prefix=".yoetz-installation-recovery-",
        dir=Path.home(),
    ) as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        yield root


@pytest.mark.anyio
async def test_self_contained_clean_profile_restores_same_vault_authority(
    private_test_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    original_bundle = private_test_root / "original"
    original_state = private_test_root / "original-state"
    _private_dir(original_bundle)
    _private_dir(original_state)
    original_throttle = UnlockThrottleStore(
        original_state / "unlock-throttle.json",
        installation_id=INSTALLATION_ID,
        writer_instance_id=SERVICE_ID,
        clock=clock,
    )
    throttle_record = original_throttle.stage_initial_record()
    marker_store = _InstallationStateStore(
        original_bundle / "installation-state.json",
        original_state / "unlock-throttle.json",
        original_state / "service-generation.json",
    )
    memory = LocalSecretMemory()
    vault = VaultService(
        installation_id=INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(original_bundle / "vault"),
        pristine_state_digest="sha256:" + "1" * 64,
        publish_mode=marker_store.publish,
    )
    await vault.initialize_passphrase(
        memory.capture(
            SecretPurpose.VAULT_INITIALIZE,
            bytearray(b"original correct horse battery"),
        ),
        throttle_record.record_digest,
    )
    await vault.create_bundle_keys(TASK_ID)
    original_lifecycle = ServiceLifecycle(
        clock,
        singleton_lock_path=original_state / "service.lock",
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "3" * 64,
        instance_id=SERVICE_ID,
    )
    await original_lifecycle.acquire_singleton()
    await original_lifecycle.transition(ServiceState.LOCKED)
    original_app = await build_ready_application_factory(
        lifecycle=original_lifecycle,
        vault=vault,
        config=YoetzConfig(),
        paths=_Paths(original_bundle, original_state),
        clock=clock,
        secret_memory=memory,
    )(1, vault.generation)
    object.__setattr__(original_app, "enforce_repository_identity", False)
    common = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "actor": {"actor_id": "harness:recovery", "actor_type": "harness"},
        "client": {
            "kind": "test_client",
            "version": "0.1.0",
            "integration": "local_cli",
        },
    }
    started = await original_app.start(
        StartRequest.model_validate(
            {
                **common,
                "request_id": "req_30000000-0000-4000-8000-000000000010",
                "mode": "create",
                "task_title": "Recover the complete synthetic installation",
                "requested_view": "compact",
            }
        )
    )
    assert started.ok is True
    policy_app = original_app.privacy.policy_application
    assert policy_app is not None
    policy_scope = AuthorizationScope(AuthorizationScopeKind.MACHINE, INSTALLATION_ID)
    original_policy = await policy_app.policy_store.effective_policy(policy_scope)
    provider_binding = provider_credential_profile_binding("openai", "gpt-5", "responses", "1")
    provider_target = provider_binding.target_digest("set")
    await vault.store_provider_credential(
        "set",
        provider_binding,
        memory.capture(
            SecretPurpose.PROVIDER_CREDENTIAL,
            bytearray(b"synthetic-provider-token"),
        ),
        HumanAuthorizationProof(
            "recovery-provider-proof",
            "provider_credential_set",
            provider_target,
            1,
            vault.generation,
            None,
            10.0,
            20.0,
        ),
        10.0,
        target_digest=provider_target,
    )
    await original_app.close()
    await original_lifecycle.close()

    sets = InstallationRecoverySetStore(original_bundle)
    snapshot = sets.prepare_snapshot(1)
    recovery_secret = bytearray(b"recovery correct horse battery")
    artifact = await vault.build_installation_recovery_artifact(
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(recovery_secret)),
        recovery_generation=1,
        mode=InstallationRecoveryMode.SELF_CONTAINED,
        secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        snapshot_manifest_digest=snapshot.manifest_digest,
    )
    metadata = sets.stage(artifact, snapshot)
    await vault.commit_installation_recovery_metadata(metadata)
    sets.activate(metadata)
    archive = private_test_root / "installation-recovery.yirs"
    sets.export_generation(1, archive)

    clean_bundle = private_test_root / "clean"
    clean_state = private_test_root / "clean-state"
    _private_dir(clean_bundle)
    _private_dir(clean_state)
    clean_sets = InstallationRecoverySetStore(clean_bundle)
    assert clean_sets.import_archive(archive) == metadata
    assert clean_sets.install_snapshot_into_pristine(1) == snapshot.manifest_digest
    clean_marker_store = _InstallationStateStore(
        clean_bundle / "installation-state.json",
        clean_state / "unlock-throttle.json",
        clean_state / "service-generation.json",
        clean_sets,
    )
    marker = clean_marker_store.load()
    assert marker is not None
    assert marker.installation_id == INSTALLATION_ID
    assert marker.root_envelope is not None
    clean_throttle = UnlockThrottleStore(
        clean_state / "unlock-throttle.json",
        installation_id=INSTALLATION_ID,
        writer_instance_id=SERVICE_ID,
        clock=clock,
    )
    recovery_throttle = clean_throttle.stage_recovery_record()
    clean_memory = LocalSecretMemory()
    recovered_vault = VaultService(
        installation_id=INSTALLATION_ID,
        service_generation=2,
        mode=marker.vault_mode,
        secret_memory=clean_memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(clean_bundle / "vault"),
        root_envelope=marker.root_envelope,
        replace_mode=clean_marker_store.replace_after_recovery,
        snapshot_recovery_admission=clean_sets.admits_clean_restore,
    )
    continuation = clean_sets.begin_recovery(1)
    result = await recovered_vault.recover_passphrase(
        clean_sets.load(1),
        clean_memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(recovery_secret)),
        clean_memory.capture(
            SecretPurpose.VAULT_REWRAP,
            bytearray(b"clean profile new horse battery"),
        ),
        throttle_record_digest=recovery_throttle.record_digest,
    )
    assert result.state is VaultState.READY
    assert await recovered_vault.load_bundle_keys(TASK_ID)
    assert await recovered_vault.has_provider_credential(provider_binding)

    clean_lifecycle = ServiceLifecycle(
        clock,
        singleton_lock_path=clean_state / "service.lock",
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "4" * 64,
        instance_id=SERVICE_ID,
    )
    await clean_lifecycle.acquire_singleton()
    await clean_lifecycle.transition(ServiceState.LOCKED)
    clean_app = await build_ready_application_factory(
        lifecycle=clean_lifecycle,
        vault=recovered_vault,
        config=YoetzConfig(),
        paths=_Paths(clean_bundle, clean_state),
        clock=clock,
        secret_memory=clean_memory,
    )(1, recovered_vault.generation)
    object.__setattr__(clean_app, "enforce_repository_identity", False)
    try:
        routes, events, objects = await clean_app.verify_recovery_candidate()
        assert routes == 1
        assert events >= 1
        assert objects >= 1
        recovered_policy_app = clean_app.privacy.policy_application
        assert recovered_policy_app is not None
        recovered_policy = await recovered_policy_app.policy_store.effective_policy(policy_scope)
        assert recovered_policy.effective_digest == original_policy.effective_digest

        checked = await clean_app.check(
            CheckRequest.model_validate(
                {
                    **common,
                    "request_id": "req_30000000-0000-4000-8000-000000000011",
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": {
                        "sequence": str(started.frontier.sequence),
                        "head_digest": started.frontier.head_digest,
                    },
                    "mode": "deterministic_only",
                    "max_findings": "3",
                    "policy_packs": ["work-integrity/0.3.0"],
                }
            )
        )
        assert type(checked) is CheckCommitResult
        receipt = await clean_app.receipt(
            ReceiptRequest.model_validate(
                {
                    **common,
                    "request_id": "req_30000000-0000-4000-8000-000000000012",
                    "task_id": checked.task_id,
                    "session_id": checked.session_id,
                    "writer_id": checked.writer_id,
                    "expected_frontier": {
                        "sequence": str(checked.result_frontier.sequence),
                        "head_digest": checked.result_frontier.head_digest,
                    },
                    "format": "json",
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            )
        )
        assert type(receipt) is ReceiptInternalResult
        assert receipt.ok is True
        original_finalize = clean_sets.finalize_committed_recovery
        finalize_attempts = 0

        def _interrupted_finalize(recovery_generation: int) -> None:
            nonlocal finalize_attempts
            finalize_attempts += 1
            if finalize_attempts == 1:
                raise OSError("simulated_crash_after_recovery_marker_switch")
            original_finalize(recovery_generation)

        monkeypatch.setattr(clean_sets, "finalize_committed_recovery", _interrupted_finalize)
        recovered_vault.commit_recovery_marker()
        assert finalize_attempts == 2
        clean_sets.finish_recovery(continuation, success=True)
        assert await recovered_vault.load_installation_recovery_metadata(1) == metadata
        assert clean_marker_store.load() is not None
    finally:
        await clean_app.close()
        await clean_lifecycle.close()

    await recovered_vault.close()
    reopened_marker = clean_marker_store.load()
    assert reopened_marker is not None and reopened_marker.root_envelope is not None
    reopened_memory = LocalSecretMemory()
    reopened_vault = VaultService(
        installation_id=INSTALLATION_ID,
        service_generation=3,
        mode=reopened_marker.vault_mode,
        secret_memory=reopened_memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(clean_bundle / "vault"),
        root_envelope=reopened_marker.root_envelope,
    )
    reopened = await reopened_vault.unlock(
        reopened_memory.capture(
            SecretPurpose.VAULT_UNLOCK,
            bytearray(b"clean profile new horse battery"),
        )
    )
    assert reopened.state is VaultState.READY
    assert await reopened_vault.has_provider_credential(provider_binding)
    reopen_lifecycle = ServiceLifecycle(
        clock,
        singleton_lock_path=clean_state / "service.lock",
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "5" * 64,
        instance_id=SERVICE_ID,
    )
    await reopen_lifecycle.acquire_singleton()
    await reopen_lifecycle.transition(ServiceState.LOCKED)
    reopened_app = await build_ready_application_factory(
        lifecycle=reopen_lifecycle,
        vault=reopened_vault,
        config=YoetzConfig(),
        paths=_Paths(clean_bundle, clean_state),
        clock=clock,
        secret_memory=reopened_memory,
    )(1, reopened_vault.generation)
    try:
        (
            reopened_routes,
            reopened_events,
            reopened_objects,
        ) = await reopened_app.verify_recovery_candidate()
        assert reopened_routes == 1
        assert reopened_events >= events
        assert reopened_objects >= objects
        reopened_policy_app = reopened_app.privacy.policy_application
        assert reopened_policy_app is not None
        reopened_policy = await reopened_policy_app.policy_store.effective_policy(policy_scope)
        assert reopened_policy.effective_digest == original_policy.effective_digest
    finally:
        await reopened_app.close()
        await reopen_lifecycle.close()
        await reopened_vault.close()
        reopened_memory.close()


@pytest.mark.anyio
async def test_rotation_reencrypts_live_vault_and_revokes_older_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    bundle = tmp_path / "bundle"
    state = tmp_path / "state"
    _private_dir(bundle)
    _private_dir(state)
    throttle = UnlockThrottleStore(
        state / "unlock-throttle.json",
        installation_id=INSTALLATION_ID,
        writer_instance_id=SERVICE_ID,
        clock=clock,
    )
    initial_throttle = throttle.stage_initial_record()
    sets = InstallationRecoverySetStore(bundle)
    marker_store = _InstallationStateStore(
        bundle / "installation-state.json",
        state / "unlock-throttle.json",
        state / "service-generation.json",
        sets,
    )
    memory = LocalSecretMemory()
    vault = VaultService(
        installation_id=INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(bundle / "vault"),
        pristine_state_digest="sha256:" + "2" * 64,
        publish_mode=marker_store.publish,
        replace_root=marker_store.replace_after_root_rotation,
    )
    await vault.initialize_passphrase(
        memory.capture(
            SecretPurpose.VAULT_INITIALIZE,
            bytearray(b"original rotation horse battery"),
        ),
        initial_throttle.record_digest,
    )
    await vault.create_bundle_keys(TASK_ID)
    before_commitment = vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP).mac(
        b"yoetz/start-title/v1\x00", b"stable-title"
    )

    old_secret = bytearray(b"old recovery horse battery")
    old_artifact = await vault.build_installation_recovery_artifact(
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(old_secret)),
        recovery_generation=1,
        mode=InstallationRecoveryMode.COMPACT,
        secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        snapshot_manifest_digest=None,
    )
    old_metadata = sets.stage(old_artifact)
    await vault.commit_installation_recovery_metadata(old_metadata)
    sets.activate(old_metadata)

    await vault.stage_root_rotation(2)
    new_secret = bytearray(b"new recovery horse battery")
    new_artifact = await vault.build_installation_recovery_artifact(
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(new_secret)),
        recovery_generation=2,
        mode=InstallationRecoveryMode.COMPACT,
        secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        snapshot_manifest_digest=None,
    )
    new_metadata = sets.stage(new_artifact)
    await vault.commit_installation_recovery_metadata(new_metadata)
    rotation_throttle = throttle.stage_recovery_record()
    await vault.prepare_root_rotation_envelope(
        memory.capture(
            SecretPurpose.VAULT_REWRAP,
            bytearray(b"rotated vault passphrase battery"),
        ),
        throttle_record_digest=rotation_throttle.record_digest,
        action="rotate",
    )
    original_activate = sets.activate
    activation_attempts = 0

    def _interrupted_activate(metadata: object) -> None:
        nonlocal activation_attempts
        activation_attempts += 1
        if activation_attempts == 1:
            raise OSError("simulated_crash_after_marker_switch")
        original_activate(metadata)  # type: ignore[arg-type]

    monkeypatch.setattr(sets, "activate", _interrupted_activate)
    await vault.commit_root_rotation()

    assert activation_attempts == 2
    assert not (bundle / "installation-recovery" / "root-rotation-journal.json").exists()
    assert (
        sets.status(
            installation_exists=True,
            vault_ready=True,
            ordinary_unlock_available=True,
            auto_unlock_repairable=False,
        ).active_generation
        == 2
    )
    assert await vault.load_bundle_keys(TASK_ID)
    assert (
        vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP).mac(
            b"yoetz/start-title/v1\x00", b"stable-title"
        )
        == before_commitment
    )

    old_material = unlock_installation_recovery_artifact(
        old_artifact,
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(old_secret)),
    )
    old_root = old_material.consume_ivk(lambda view: bytearray(view))
    try:
        rejected = EncryptedVaultStore(bundle / "vault")
        with pytest.raises(EncryptedVaultError):
            rejected.initialize(memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(old_root)))
    finally:
        old_root[:] = b"\x00" * len(old_root)

    assert (bundle / "installation-recovery" / "rollback-vaults" / "rotate-generation-2").is_dir()
    await vault.lock()
    unlocked = await vault.unlock(
        memory.capture(
            SecretPurpose.VAULT_UNLOCK,
            bytearray(b"rotated vault passphrase battery"),
        )
    )
    assert unlocked.state is VaultState.READY
    assert await vault.load_bundle_keys(TASK_ID)

    lifecycle = ServiceLifecycle(
        clock,
        singleton_lock_path=tmp_path / "lifecycle.lock",
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "6" * 64,
        instance_id=SERVICE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    await lifecycle.transition(ServiceState.UNLOCKING)
    await lifecycle.transition(ServiceState.READY, vault_generation=vault.generation)

    async def _unused_activation(_service_generation: int, _vault_generation: int) -> None:
        raise AssertionError("root rotation does not reactivate the application")

    unlock = UnlockCoordinator(
        clock=clock,
        throttle=throttle,
        vault=vault,
        lifecycle=lifecycle,
        activate_ready=_unused_activation,
    )
    effects = _LockedHumanEffects(
        lifecycle,
        vault,
        _PrivacyPolicyAppRelay(),
        sets,
        unlock,
    )
    provisional_revoke = InstallationRecoveryTarget(
        "revoke",
        "req_30000000-0000-4000-8000-000000000020",
        "sha256:" + "0" * 64,
        2,
        "compact",
        "argon2id_passphrase",
        "passphrase",
    )
    revoke_target = replace(
        provisional_revoke,
        confirmed_plan_digest=provisional_revoke.plan_digest(),
    )
    _preview, confirmed_revoke_digest, _policy_generation = await effects.prepare(
        ClientOpenEnvelope(
            "a" * 64,
            HumanCeremonyKind.INSTALLATION_RECOVERY,
            revoke_target,
        )
    )
    revoke_result = await effects.revoke_installation_recovery(
        revoke_target,
        memory.capture(
            SecretPurpose.VAULT_REWRAP,
            bytearray(b"revoked vault passphrase battery"),
        ),
        HumanAuthorizationProof(
            "revoke-proof",
            "installation_recovery_change",
            confirmed_revoke_digest,
            lifecycle.instance.generation,
            vault.generation,
            None,
            10.0,
            20.0,
        ),
        10.0,
    )
    assert revoke_result.status == "completed"
    revoked = sets.status(
        installation_exists=True,
        vault_ready=True,
        ordinary_unlock_available=True,
        auto_unlock_repairable=False,
    )
    assert revoked.reason == "recovery_material_revoked"
    assert revoked.available_modes == ()
    assert (bundle / "installation-recovery" / "rollback-vaults" / "revoke-generation-2").is_dir()

    rotated_material = unlock_installation_recovery_artifact(
        new_artifact,
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(new_secret)),
    )
    rotated_root = rotated_material.consume_ivk(lambda view: bytearray(view))
    try:
        rejected = EncryptedVaultStore(bundle / "vault")
        with pytest.raises(EncryptedVaultError):
            rejected.initialize(
                memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(rotated_root))
            )
    finally:
        rotated_root[:] = b"\x00" * len(rotated_root)

    await vault.lock()
    reopened_after_revoke = await vault.unlock(
        memory.capture(
            SecretPurpose.VAULT_UNLOCK,
            bytearray(b"revoked vault passphrase battery"),
        )
    )
    assert reopened_after_revoke.state is VaultState.READY
    await lifecycle.close()
