from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from finishup.adapters.keys.encrypted_vault import EncryptedVaultStore
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.control import ServiceState
from finishup.ports.keys import KeyStoreError
from finishup.ports.secret_memory import SecretPurpose
from finishup.service.lifecycle import ServiceLifecycle, SessionSecurityEvent
from finishup.service.unlock import UnlockCoordinator, UnlockThrottleStore
from finishup.service.vault import VaultError, VaultMode, VaultService, VaultState

_INSTALLATION_ID = "ins_00000000-0000-4000-8000-000000000001"
_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000002"
_TASK_ID = "tsk_00000000-0000-4000-8000-000000000003"


@dataclass(slots=True)
class _Clock:
    monotonic: float = 10.0

    def monotonic_seconds(self) -> float:
        return self.monotonic

    def now_utc(self) -> object:
        raise AssertionError("wall clock forbidden")


class _GenerationStore:
    def advance(self, instance_id: str) -> int:
        assert instance_id == _INSTANCE_ID
        return 1


@pytest.mark.anyio
async def test_passphrase_ready_relock_unlock_uses_fresh_vault_generation(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    clock = _Clock()
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,  # pyright: ignore[reportArgumentType]
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "1" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "2" * 64)
    assert vault.ready and vault.generation == 1

    async def close_ready() -> None:
        await vault.lock()

    lifecycle = ServiceLifecycle(
        clock,  # pyright: ignore[reportArgumentType]
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "3" * 64,
        instance_id=_INSTANCE_ID,
        close_ready_composition=close_ready,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.READY, vault_generation=vault.generation)
    bundle = await vault.create_bundle_keys(_TASK_ID)
    await lifecycle.on_session_event(SessionSecurityEvent.SYSTEM_SUSPEND)
    assert lifecycle.state is ServiceState.LOCKED
    assert vault.state is VaultState.LOCKED
    with pytest.raises(KeyStoreError, match="stale_key_handle"):
        bundle.commitment_key.mac(b"yoetz/object/evidence/v1\x00", b"payload")

    await lifecycle.on_session_event(SessionSecurityEvent.SYSTEM_RESUME)
    assert lifecycle.state is ServiceState.LOCKED
    await lifecycle.transition(ServiceState.UNLOCKING)
    unlock = memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(b"correct horse battery"))
    await vault.unlock(unlock)
    await lifecycle.transition(ServiceState.READY, vault_generation=vault.generation)
    assert vault.generation == 3  # lock invalidation and the fresh unlock each advance the fence
    loaded = await vault.load_bundle_keys(_TASK_ID)
    assert loaded.commitment_key.mac(b"yoetz/object/evidence/v1\x00", b"payload").startswith(
        "hmac-sha256:"
    )


@pytest.mark.anyio
async def test_wrong_unlock_remains_locked_and_never_opens_ready_composition(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    clock = _Clock()
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,  # pyright: ignore[reportArgumentType]
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "1" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "2" * 64)
    await vault.lock()
    wrong = memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(b"wrong phrase long enough"))
    with pytest.raises(VaultError, match="unlock_wrong"):
        await vault.unlock(wrong)
    assert vault.state is VaultState.LOCKED
    with pytest.raises(KeyStoreError, match="vault_locked"):
        await vault.load_bundle_keys(_TASK_ID)


@pytest.mark.anyio
async def test_ready_activation_failure_relocks_after_correct_passphrase(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    clock = _Clock()
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,  # pyright: ignore[reportArgumentType]
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "1" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "2" * 64)
    await vault.lock()

    lifecycle = ServiceLifecycle(
        clock,  # pyright: ignore[reportArgumentType]
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "3" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    throttle = UnlockThrottleStore(
        tmp_path / "unlock-throttle.json",
        installation_id=_INSTALLATION_ID,
        writer_instance_id=_INSTANCE_ID,
        clock=clock,  # pyright: ignore[reportArgumentType]
    )
    throttle.stage_initial_record()
    activation_calls: list[tuple[int, int, bool]] = []

    async def fail_ready_activation(service_generation: int, vault_generation: int) -> None:
        activation_calls.append((service_generation, vault_generation, vault.ready))
        raise RuntimeError("startup gate failed")

    coordinator = UnlockCoordinator(
        clock=clock,  # pyright: ignore[reportArgumentType]
        throttle=throttle,
        vault=vault,
        lifecycle=lifecycle,
        activate_ready=fail_ready_activation,
    )
    challenge = await coordinator.begin_passphrase_unlock(target_digest="sha256:" + "4" * 64)
    unlock = memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(b"correct horse battery"))

    result = await coordinator.complete_passphrase_unlock(challenge, unlock)

    assert result.state == "locked"
    assert result.reason == "unlock_failed"
    assert activation_calls == [(1, 3, True)]
    assert lifecycle.state is ServiceState.LOCKED
    assert vault.state is VaultState.LOCKED
    assert vault.generation == 4
    assert throttle.record.consecutive_failures == 0
    assert throttle.record.attempt_in_progress is False
    memory.close()
