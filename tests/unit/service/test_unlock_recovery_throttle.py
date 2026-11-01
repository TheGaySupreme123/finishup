"""Installation recovery verifies a secret, so it must be throttled like one.

Recovery staged its clean throttle generation *before* `recover_passphrase` had verified
anything. That write zeroes `consecutive_failures` and the pending delay, so every failed attempt
handed back an unthrottled next attempt, and merely starting a recovery cleared a delay the
passphrase path had accumulated. `begin_installation_recovery` also skipped the delay check that
`begin_passphrase_unlock` performs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from finishup.adapters.keys.encrypted_vault import EncryptedVaultStore
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.control import ServiceState
from finishup.ports.secret_memory import SecretPurpose
from finishup.service.lifecycle import ServiceLifecycle
from finishup.service.unlock import (
    UnlockCoordinator,
    UnlockError,
    UnlockThrottleStore,
)
from finishup.service.vault import VaultMode, VaultService

_INSTALLATION_ID = "ins_00000000-0000-4000-8000-0000000000c1"
_INSTANCE_ID = "svc_00000000-0000-4000-8000-0000000000c2"


@dataclass(slots=True)
class _Clock:
    monotonic: float = 10.0

    def monotonic_seconds(self) -> float:
        return self.monotonic

    def now_utc(self) -> datetime:
        return datetime(2026, 8, 24, 12, 0, 0, tzinfo=UTC)


def _throttle(tmp_path: Path, clock: _Clock) -> UnlockThrottleStore:
    throttle = UnlockThrottleStore(
        tmp_path / "unlock-throttle.json",
        installation_id=_INSTALLATION_ID,
        writer_instance_id=_INSTANCE_ID,
        clock=clock,  # pyright: ignore[reportArgumentType]
    )
    throttle.stage_initial_record()
    return throttle


def _fail_recovery_attempt(throttle: UnlockThrottleStore) -> None:
    """One recovery attempt that reserves, prepares its record, and does not authenticate."""

    throttle.reserve_attempt()
    throttle.prepare_recovery_record()
    throttle.charge_failure()


def test_failed_recovery_attempts_accumulate_delay(tmp_path: Path) -> None:
    clock = _Clock()
    throttle = _throttle(tmp_path, clock)

    for _ in range(3):
        assert throttle.remaining_delay() == 0.0
        _fail_recovery_attempt(throttle)

    assert throttle.record.consecutive_failures == 3
    assert throttle.remaining_delay() > 0.0

    # The delay is the same schedule an ordinary passphrase failure earns, not a private one.
    with pytest.raises(UnlockError, match="unlock_rate_limited"):
        throttle.reserve_attempt()


def test_a_failed_recovery_does_not_clear_the_passphrase_delay(tmp_path: Path) -> None:
    clock = _Clock()
    throttle = _throttle(tmp_path, clock)

    for _ in range(3):
        throttle.reserve_attempt()
        throttle.charge_failure()
    earned = throttle.remaining_delay()
    assert earned > 0.0

    # Preparing the record a recovery would install must persist nothing at all.
    prepared = throttle.prepare_recovery_record()
    assert prepared.consecutive_failures == 0
    assert throttle.remaining_delay() == earned
    assert throttle.record.consecutive_failures == 3

    # Only an authenticated recovery installs it, and only then is the delay cleared.
    throttle.commit_recovery_record(prepared)
    assert throttle.record.consecutive_failures == 0
    assert throttle.remaining_delay() == 0.0


@pytest.mark.anyio
async def test_begin_installation_recovery_is_refused_while_rate_limited(
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
    throttle = _throttle(tmp_path, clock)

    async def _activate(service_generation: int, vault_generation: int) -> None:
        del service_generation, vault_generation

    coordinator = UnlockCoordinator(
        clock=clock,  # pyright: ignore[reportArgumentType]
        throttle=throttle,
        vault=vault,
        lifecycle=lifecycle,
        activate_ready=_activate,
    )
    target_digest = "sha256:" + "4" * 64

    for _ in range(3):
        throttle.reserve_attempt()
        throttle.charge_failure()
    owed = throttle.remaining_delay()
    assert owed > 0.0

    with pytest.raises(UnlockError, match="unlock_rate_limited"):
        await coordinator.begin_installation_recovery(target_digest=target_digest)
    # A refused start must not leave the service stranded mid-unlock.
    assert lifecycle.state is ServiceState.LOCKED

    # It is the owed delay that refuses the attempt, not recovery itself.
    clock.monotonic += owed
    assert throttle.remaining_delay() == 0.0
    await coordinator.begin_installation_recovery(target_digest=target_digest)
    assert lifecycle.state is ServiceState.UNLOCKING
    await lifecycle.transition(ServiceState.LOCKED)
    memory.close()
    await lifecycle.close()


class _GenerationStore:
    def advance(self, instance_id: str) -> int:
        assert instance_id == _INSTANCE_ID
        return 1
