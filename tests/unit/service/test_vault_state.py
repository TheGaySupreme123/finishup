from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from finishup.adapters.keys.encrypted_vault import EncryptedVaultStore
from finishup.adapters.keys.installation_recovery import (
    InstallationRecoveryArtifact,
    InstallationRecoveryMetadata,
    InstallationRecoveryMode,
    InstallationRecoverySecretKind,
    unlock_installation_recovery_artifact,
)
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.adapters.keys.vault_passphrase import VaultRootEnvelope
from finishup.ports.keys import (
    REPOSITORY_PRIVACY_MAC_DOMAIN,
    KeyStoreError,
    MacKeyPurpose,
)
from finishup.ports.secret_memory import (
    HumanAuthorizationProof,
    ProviderAttemptAuthBinding,
    SecretMemoryError,
    SecretPurpose,
    UserPresenceChallenge,
)
from finishup.service.vault import (
    VaultError,
    VaultMode,
    VaultService,
    VaultState,
    provider_credential_profile_binding,
)

_INSTALLATION_ID = "ins_00000000-0000-4000-8000-000000000001"
_TASK_ID = "tsk_00000000-0000-4000-8000-000000000002"


@dataclass(slots=True)
class _Clock:
    monotonic: float = 10.0

    def monotonic_seconds(self) -> float:
        return self.monotonic

    def now_utc(self) -> object:
        raise AssertionError("wall clock forbidden")


def _service(
    tmp_path: Path,
    memory: LocalSecretMemory,
    clock: _Clock,
    *,
    publish_mode: Callable[[VaultMode, VaultRootEnvelope | None, str], None] | None = None,
    replace_mode: Callable[[VaultMode, VaultRootEnvelope, str, int], None] | None = None,
    replace_passphrase: Callable[[VaultRootEnvelope], None] | None = None,
) -> VaultService:
    vault_dir = tmp_path / "vault"
    return VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=7,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,  # pyright: ignore[reportArgumentType] - wall clock is not sampled by vault
        vault_store_factory=lambda: EncryptedVaultStore(vault_dir),
        pristine_state_digest="sha256:" + "1" * 64,
        publish_mode=publish_mode,
        replace_mode=replace_mode,
        replace_passphrase=replace_passphrase,
    )


async def _initialize(service: VaultService, memory: LocalSecretMemory) -> None:
    handle = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    status = await service.initialize_passphrase(handle, "sha256:" + "2" * 64)
    assert status.mode is VaultMode.PASSPHRASE
    assert status.state is VaultState.READY
    assert status.vault_generation == 1


@pytest.mark.anyio
async def test_locked_vault_returns_no_handles_and_has_bounded_status(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    with pytest.raises(KeyStoreError, match="vault_locked"):
        await service.load_bundle_keys(_TASK_ID)
    status = service.status
    assert status.mode is VaultMode.UNINITIALIZED
    assert status.state is VaultState.LOCKED
    assert status.reason is None


@pytest.mark.anyio
async def test_passphrase_initialization_is_distinct_and_first_install_only(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    wrong = memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(b"correct horse battery"))
    with pytest.raises(VaultError, match="secret_purpose_mismatch"):
        await service.initialize_passphrase(wrong, "sha256:" + "2" * 64)

    await _initialize(service, memory)
    another = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"another secure phrase"))
    with pytest.raises(VaultError, match="initialization_forbidden"):
        await service.initialize_passphrase(another, "sha256:" + "2" * 64)


@pytest.mark.anyio
async def test_ready_passphrase_rewrap_keeps_vault_data_and_replaces_only_envelope(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    published: list[VaultRootEnvelope] = []
    replaced: list[VaultRootEnvelope] = []

    def publish(mode: VaultMode, envelope: VaultRootEnvelope | None, digest: str) -> None:
        assert mode is VaultMode.PASSPHRASE
        assert envelope is not None
        assert digest.startswith("sha256:")
        published.append(envelope)

    service = _service(
        tmp_path,
        memory,
        _Clock(),
        publish_mode=publish,
        replace_passphrase=replaced.append,
    )
    await _initialize(service, memory)
    await service.create_bundle_keys(_TASK_ID)
    result = await service.rewrap_passphrase(
        memory.capture(SecretPurpose.VAULT_REWRAP, bytearray(b"new correct horse battery"))
    )
    assert result.state is VaultState.READY
    assert len(replaced) == 1
    assert replaced[0] != published[0]
    await service.lock()
    memory.close()

    reopened_memory = LocalSecretMemory()
    reopened = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=8,
        mode=VaultMode.PASSPHRASE,
        secret_memory=reopened_memory,
        clock=_Clock(),  # pyright: ignore[reportArgumentType]
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        root_envelope=replaced[0],
    )
    await reopened.unlock(
        reopened_memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(b"new correct horse battery"))
    )
    assert reopened.ready
    assert await reopened.load_bundle_keys(_TASK_ID)
    reopened_memory.close()


@pytest.mark.anyio
async def test_bundle_and_installation_handles_are_generation_fenced(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    await _initialize(service, memory)
    bundle = await service.create_bundle_keys(_TASK_ID)
    mac = bundle.commitment_key.mac(b"yoetz/object/request/v1\x00", b"payload")
    assert mac.startswith("hmac-sha256:")

    catalog = service.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
    assert catalog.mac(b"yoetz/start-title/v1\x00", b"title").startswith("hmac-sha256:")
    privacy_audit = service.installation_mac_handle(MacKeyPurpose.PRIVACY_AUDIT)
    assert privacy_audit.mac(
        b"yoetz/privacy-audit/authorization/v1\x00", b"authorization"
    ).startswith("hmac-sha256:")
    repository = service.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
    assert repository.mac(REPOSITORY_PRIVACY_MAC_DOMAIN, b"repository").startswith("hmac-sha256:")
    with pytest.raises(KeyStoreError, match="mac_domain_forbidden"):
        catalog.mac(b"yoetz/session-log-id/v1\x00", b"title")

    await service.lock()
    with pytest.raises(KeyStoreError, match="stale_key_handle"):
        bundle.commitment_key.mac(b"yoetz/object/request/v1\x00", b"payload")
    with pytest.raises(KeyStoreError, match="stale_key_handle"):
        catalog.mac(b"yoetz/start-title/v1\x00", b"title")
    with pytest.raises(KeyStoreError, match="stale_key_handle"):
        repository.mac(REPOSITORY_PRIVACY_MAC_DOMAIN, b"repository")


@pytest.mark.anyio
async def test_create_bundle_is_once_and_load_derives_equivalent_operations(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    await _initialize(service, memory)
    created = await service.create_bundle_keys(_TASK_ID)
    with pytest.raises(KeyStoreError):
        await service.create_bundle_keys(_TASK_ID)
    loaded = await service.load_bundle_keys(_TASK_ID)
    domain = b"yoetz/object/result/v1\x00"
    assert created.commitment_key.mac(domain, b"same") == loaded.commitment_key.mac(domain, b"same")


@pytest.mark.anyio
async def test_installation_recovery_artifact_keeps_ivk_inside_vault_boundary(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    await _initialize(service, memory)
    secret = bytearray(b"correct horse battery staple")
    artifact = await service.build_installation_recovery_artifact(
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(secret)),
        recovery_generation=1,
        mode=InstallationRecoveryMode.COMPACT,
        secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        snapshot_manifest_digest=None,
    )
    metadata = InstallationRecoveryMetadata(
        1,
        InstallationRecoveryMode.COMPACT,
        InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        artifact.artifact_digest,
        None,
    )
    await service.commit_installation_recovery_metadata(metadata)
    assert await service.load_installation_recovery_metadata(1) == metadata
    recovered = unlock_installation_recovery_artifact(
        artifact,
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(secret)),
    )
    assert recovered.consume_ivk(bytes) != bytes(32)
    with pytest.raises(VaultError, match="record_binding_mismatch"):
        await service.commit_installation_recovery_metadata(metadata)
    memory.close()


@pytest.mark.anyio
async def test_installation_recovery_verifies_metadata_and_selects_new_envelope(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    published: list[VaultRootEnvelope] = []
    replaced: list[tuple[VaultRootEnvelope, str, int]] = []

    def publish(mode: VaultMode, envelope: VaultRootEnvelope | None, digest: str) -> None:
        assert mode is VaultMode.PASSPHRASE
        assert envelope is not None
        assert digest.startswith("sha256:")
        published.append(envelope)

    def replace(
        mode: VaultMode,
        envelope: VaultRootEnvelope,
        digest: str,
        generation: int,
    ) -> None:
        assert mode is VaultMode.PASSPHRASE
        replaced.append((envelope, digest, generation))

    service = _service(
        tmp_path,
        memory,
        _Clock(),
        publish_mode=publish,
        replace_mode=replace,
    )
    await _initialize(service, memory)
    await service.create_bundle_keys(_TASK_ID)
    recovery_secret = bytearray(b"recovery horse battery staple")
    artifact = await service.build_installation_recovery_artifact(
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(recovery_secret)),
        recovery_generation=1,
        mode=InstallationRecoveryMode.COMPACT,
        secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        snapshot_manifest_digest=None,
    )
    await service.commit_installation_recovery_metadata(
        InstallationRecoveryMetadata(
            1,
            InstallationRecoveryMode.COMPACT,
            InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
            artifact.artifact_digest,
            None,
        )
    )
    await service.lock()

    recovered = await service.recover_passphrase(
        artifact,
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(recovery_secret)),
        memory.capture(SecretPurpose.VAULT_REWRAP, bytearray(b"new correct horse battery")),
        throttle_record_digest="sha256:" + "3" * 64,
    )
    assert recovered.state is VaultState.READY
    assert replaced == []
    service.commit_recovery_marker()
    assert replaced[0][1:] == ("sha256:" + "3" * 64, 1)
    assert await service.load_bundle_keys(_TASK_ID)

    await service.close()
    reopened_memory = LocalSecretMemory()
    reopened = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=8,
        mode=VaultMode.PASSPHRASE,
        secret_memory=reopened_memory,
        clock=_Clock(),  # pyright: ignore[reportArgumentType]
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        root_envelope=replaced[0][0],
    )
    with pytest.raises(VaultError, match="unlock_wrong"):
        await reopened.unlock(
            reopened_memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(b"correct horse battery"))
        )
    assert (
        await reopened.unlock(
            reopened_memory.capture(
                SecretPurpose.VAULT_UNLOCK, bytearray(b"new correct horse battery")
            )
        )
    ).state is VaultState.READY


@pytest.mark.anyio
async def test_provider_credential_is_exact_attempt_bound_and_one_use(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    clock = _Clock()
    service = _service(tmp_path, memory, clock)
    await _initialize(service, memory)
    binding = provider_credential_profile_binding(
        "openai",
        "gpt-5",
        "openai-responses",
        "1",
    )
    assert await service.has_provider_credential(binding) is False
    proof = HumanAuthorizationProof(
        "proof-test",
        "provider_credential_set",
        binding.target_digest("set"),
        7,
        service.generation,
        None,
        9.0,
        20.0,
    )
    credential = memory.capture(
        SecretPurpose.PROVIDER_CREDENTIAL, bytearray(b"sk-test-token-value")
    )
    await service.store_provider_credential("set", binding, credential, proof, 10.0)
    assert await service.has_provider_credential(binding) is True
    replacement_proof = HumanAuthorizationProof(
        "proof-test-replacement",
        "provider_credential_set",
        binding.target_digest("set"),
        7,
        service.generation,
        None,
        10.0,
        20.0,
    )
    replacement = memory.capture(
        SecretPurpose.PROVIDER_CREDENTIAL, bytearray(b"sk-replacement-value")
    )
    await service.store_provider_credential("set", binding, replacement, replacement_proof, 11.0)
    attempt = ProviderAttemptAuthBinding(
        binding.provider_id,
        binding.model_id,
        binding.endpoint_profile_id,
        binding.endpoint_profile_version,
        binding.purpose,
        binding.authorization_scope_digest,
        binding.purpose_digest,
        "dsp_00000000-0000-4000-8000-000000000004",
        "sha256:" + "4" * 64,
        7,
        15.0,
    )
    handle = await service.provider_credential(attempt)

    class Callback:
        async def inject_and_start(self, credential_view: memoryview) -> str:
            assert hashlib.sha256(credential_view).digest()
            assert bytes(credential_view) == b"sk-replacement-value"
            return "started"

    assert await handle.authorize_attempt(attempt, Callback()) == "started"
    with pytest.raises(SecretMemoryError, match="already_consumed"):
        await handle.authorize_attempt(attempt, Callback())


@pytest.mark.anyio
async def test_discard_provider_credential_withdraws_an_unusable_key(tmp_path: Path) -> None:
    """A provider that refused the key must leave no stored record that looks configured."""

    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    await _initialize(service, memory)
    binding = provider_credential_profile_binding(
        "openai",
        "gpt-5",
        "openai-responses",
        "1",
    )
    proof = HumanAuthorizationProof(
        "proof-test",
        "provider_credential_set",
        binding.target_digest("set"),
        7,
        service.generation,
        None,
        9.0,
        20.0,
    )
    credential = memory.capture(
        SecretPurpose.PROVIDER_CREDENTIAL, bytearray(b"sk-test-token-value")
    )
    await service.store_provider_credential("set", binding, credential, proof, 10.0)
    assert await service.has_provider_credential(binding) is True

    await service.discard_provider_credential(binding)

    assert await service.has_provider_credential(binding) is False
    # Idempotent: already-absent is success, not an error.
    await service.discard_provider_credential(binding)


@pytest.mark.anyio
@pytest.mark.parametrize("invalid", [None, "purpose", "target", "generation", "expired"])
async def test_remove_provider_credential_requires_exact_fresh_proof(
    tmp_path: Path, invalid: str | None
) -> None:
    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    await _initialize(service, memory)
    binding = provider_credential_profile_binding("openai", "gpt-5", "openai-responses", "1")
    other = provider_credential_profile_binding("openai", "gpt-5-mini", "openai-responses", "1")
    for item in (binding, other):
        proof = HumanAuthorizationProof(
            "set-proof",
            "provider_credential_set",
            item.target_digest("set"),
            7,
            service.generation,
            None,
            9.0,
            20.0,
        )
        await service.store_provider_credential(
            "set",
            item,
            memory.capture(SecretPurpose.PROVIDER_CREDENTIAL, bytearray(b"sk-test-key-value-1119")),
            proof,
            10.0,
        )
    proof = HumanAuthorizationProof(
        "remove-proof",
        "provider_credential_rotate" if invalid == "purpose" else "provider_credential_remove",
        other.target_digest("remove") if invalid == "target" else binding.target_digest("remove"),
        8 if invalid == "generation" else 7,
        service.generation,
        None,
        9.0,
        9.5 if invalid == "expired" else 20.0,
    )
    if invalid is not None:
        with pytest.raises((VaultError, SecretMemoryError)):
            await service.remove_provider_credential(binding, proof, 10.0)
        assert await service.has_provider_credential(binding) is True
    else:
        proof = await service.mint_human_authorization(
            memory.capture(
                SecretPurpose.PROVIDER_REAUTHENTICATION, bytearray(b"correct horse battery")
            ),
            UserPresenceChallenge(
                "provider_credential_remove",
                "sha256:" + "a" * 64,
                binding.target_digest("remove"),
                "sha256:" + "b" * 64,
                7,
                service.generation,
                None,
                20.0,
            ),
        )
        attempt = ProviderAttemptAuthBinding(
            binding.provider_id,
            binding.model_id,
            binding.endpoint_profile_id,
            binding.endpoint_profile_version,
            binding.purpose,
            binding.authorization_scope_digest,
            binding.purpose_digest,
            "dsp_00000000-0000-4000-8000-000000000004",
            "sha256:" + "4" * 64,
            7,
            15.0,
        )
        pending_handle = await service.provider_credential(attempt)
        await service.remove_provider_credential(binding, proof, 10.0)
        assert await service.has_provider_credential(binding) is False

        class Callback:
            async def inject_and_start(self, credential_view: memoryview) -> str:
                raise AssertionError("a removed key must not start a new request")

        with pytest.raises(SecretMemoryError):
            await pending_handle.authorize_attempt(attempt, Callback())
        with pytest.raises((VaultError, SecretMemoryError)):
            await service.remove_provider_credential(binding, proof, 10.0)
    assert await service.has_provider_credential(other) is True


@pytest.mark.anyio
async def test_remove_provider_credential_refuses_missing_and_locked(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    await _initialize(service, memory)
    binding = provider_credential_profile_binding("openai", "gpt-5", "openai-responses", "1")

    def proof() -> HumanAuthorizationProof:
        return HumanAuthorizationProof(
            "remove-proof",
            "provider_credential_remove",
            binding.target_digest("remove"),
            7,
            service.generation,
            None,
            9.0,
            20.0,
        )

    with pytest.raises(VaultError, match="record_missing"):
        await service.remove_provider_credential(binding, proof(), 10.0)
    await service.lock()
    with pytest.raises(KeyStoreError, match="locked"):
        await service.remove_provider_credential(binding, proof(), 10.0)


@pytest.mark.anyio
async def test_uninitialized_keyring_has_no_passphrase_fallback(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    status = await service.initialize(None)
    assert status.mode is VaultMode.UNINITIALIZED
    assert status.state is VaultState.LOCKED
    assert status.reason == "keyring_unavailable"


@pytest.mark.anyio
async def test_the_pre_publication_drill_reopens_the_persisted_set(tmp_path: Path) -> None:
    """ADR-024 step 5: prove the set opens this vault before anything advertises it.

    Marking a generation `completed` without ever reopening it means a set that cannot actually
    be opened is discovered during a real recovery, when the person who could redo the ceremony
    is long gone.
    """

    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    await _initialize(service, memory)
    secret = bytearray(b"correct horse battery staple")
    persisted: list[InstallationRecoveryArtifact] = []

    def _publish(built: InstallationRecoveryArtifact) -> InstallationRecoveryArtifact:
        persisted.append(built)
        return built

    artifact = await service.build_and_verify_installation_recovery_artifact(
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(secret)),
        recovery_generation=1,
        mode=InstallationRecoveryMode.COMPACT,
        secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        snapshot_manifest_digest=None,
        publish=_publish,
    )
    assert persisted == [artifact]
    # The drill's own reopen is the proof, and the set stays usable afterwards.
    recovered = unlock_installation_recovery_artifact(
        artifact,
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(secret)),
    )
    assert recovered.recovery_generation == 1
    memory.close()


@pytest.mark.anyio
async def test_a_set_that_does_not_survive_staging_is_never_published(tmp_path: Path) -> None:
    """The drill reopens what staging actually wrote, so corruption in between is caught."""

    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    await _initialize(service, memory)
    secret = bytearray(b"correct horse battery staple")

    foreign = await service.build_installation_recovery_artifact(
        memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(b"a different secret here")),
        recovery_generation=1,
        mode=InstallationRecoveryMode.COMPACT,
        secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
        snapshot_manifest_digest=None,
    )

    def _publish_something_else(
        built: InstallationRecoveryArtifact,
    ) -> InstallationRecoveryArtifact:
        del built
        return foreign

    with pytest.raises(VaultError, match="recovery_artifact_invalid"):
        await service.build_and_verify_installation_recovery_artifact(
            memory.capture(SecretPurpose.INSTALLATION_RECOVERY, bytearray(secret)),
            recovery_generation=1,
            mode=InstallationRecoveryMode.COMPACT,
            secret_kind=InstallationRecoverySecretKind.ARGON2ID_PASSPHRASE,
            snapshot_manifest_digest=None,
            publish=_publish_something_else,
        )
    memory.close()


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["before", "after"])
async def test_remove_checks_record_generation_and_refuses_ambiguous_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from collections.abc import Mapping

    from finishup.adapters.keys.encrypted_vault import EncryptedVaultError, VaultRecordKind

    memory = LocalSecretMemory()
    service = _service(tmp_path, memory, _Clock())
    await _initialize(service, memory)
    binding = provider_credential_profile_binding("openai", "gpt-5", "openai-responses", "1")
    for _ in range(2):
        proof = HumanAuthorizationProof(
            "set-proof",
            "provider_credential_set",
            binding.target_digest("set"),
            7,
            service.generation,
            None,
            9.0,
            20.0,
        )
        await service.store_provider_credential(
            "set",
            binding,
            memory.capture(SecretPurpose.PROVIDER_CREDENTIAL, bytearray(b"sk-test-key-value-1119")),
            proof,
            10.0,
        )
    original = EncryptedVaultStore.delete_record
    generations: list[int] = []

    def delete(
        store: EncryptedVaultStore,
        kind: VaultRecordKind,
        structural_binding: Mapping[str, str],
        *,
        expected_generation: int,
    ) -> None:
        generations.append(expected_generation)
        assert kind is VaultRecordKind.PROVIDER_CREDENTIAL
        assert dict(structural_binding) == binding.record_binding()
        if failure == "before":
            raise EncryptedVaultError("io_failure")
        original(store, kind, structural_binding, expected_generation=expected_generation)
        raise EncryptedVaultError("io_failure")

    monkeypatch.setattr(EncryptedVaultStore, "delete_record", delete)
    proof = HumanAuthorizationProof(
        "remove-proof",
        "provider_credential_remove",
        binding.target_digest("remove"),
        7,
        service.generation,
        None,
        9.0,
        20.0,
    )
    with pytest.raises(VaultError, match="vault_tampered"):
        await service.remove_provider_credential(binding, proof, 10.0)
    assert generations == [2]
    assert await service.has_provider_credential(binding) is (failure == "before")
