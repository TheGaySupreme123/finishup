"""The real vault mints a proof only from the presence provider's own one-use attestation."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from yoetz.adapters.keys.encrypted_vault import EncryptedVaultStore
from yoetz.adapters.keys.macos_user_presence import MacOSLocalAuthenticationPresence
from yoetz.adapters.keys.secret_memory import LocalSecretMemory
from yoetz.ports.secret_memory import SecretPurpose, UserPresenceChallenge
from yoetz.service.vault import VaultError, VaultMode, VaultService

pytestmark = pytest.mark.anyio

_INSTALLATION_ID = "ins_00000000-0000-4000-8000-0000000000f1"
_TARGET = "sha256:" + "9" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass(slots=True)
class _Clock:
    monotonic: float = 10.0

    def monotonic_seconds(self) -> float:
        return self.monotonic

    def now_utc(self) -> object:
        raise AssertionError("wall clock forbidden")


async def _approve(
    argv: Sequence[str], stdin: bytes, env: Mapping[str, str], timeout: float
) -> tuple[int, bytes]:
    del argv, stdin, env, timeout
    return 0, b"approved\n"


async def _ready_vault(
    tmp_path: Path, memory: LocalSecretMemory, presence: MacOSLocalAuthenticationPresence
) -> VaultService:
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=7,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=_Clock(),  # pyright: ignore[reportArgumentType] - wall clock is not sampled
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "1" * 64,
        user_presence_port=presence,
    )
    handle = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(handle, "sha256:" + "2" * 64)
    assert vault.ready
    return vault


def _challenge(vault: VaultService) -> UserPresenceChallenge:
    return UserPresenceChallenge(
        purpose="owner_receipt_view",
        ceremony_digest="sha256:" + "c" * 64,
        target_digest=_TARGET,
        display_summary_digest=_TARGET,
        service_generation=7,
        vault_generation=vault.generation,
        policy_generation=None,
        expires_at_monotonic=300.0,
    )


async def test_an_approved_attestation_mints_one_proof_and_never_a_second(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    presence = MacOSLocalAuthenticationPresence(
        runner=_approve, platform=lambda: "darwin", helper_present=lambda: True
    )
    vault = await _ready_vault(tmp_path, memory, presence)
    challenge = _challenge(vault)

    attestation = await presence.assert_presence(challenge)
    proof = await vault.mint_human_authorization(attestation, challenge)
    assert proof.purpose == "owner_receipt_view"
    assert proof.target_digest == _TARGET

    with pytest.raises(VaultError, match="human_authority_unavailable"):
        await vault.mint_human_authorization(attestation, challenge)

    other = await presence.assert_presence(challenge)
    with pytest.raises(VaultError, match="human_authority_unavailable"):
        await vault.mint_human_authorization(
            other, replace(challenge, target_digest="sha256:" + "8" * 64)
        )

    class _Forged:
        pass

    with pytest.raises(VaultError, match="human_authority_unavailable"):
        await vault.mint_human_authorization(_Forged(), challenge)  # pyright: ignore[reportArgumentType]
    await vault.close()
    memory.close()
