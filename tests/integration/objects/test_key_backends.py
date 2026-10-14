"""Key-backend and encrypted-vault bounded behavior."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import keywrap

from finishup.adapters.keys.encrypted_vault import (
    EncryptedVaultError,
    EncryptedVaultStore,
    VaultRecordKind,
)
from finishup.adapters.keys.os_keyring import (
    AutoUnlockPassphraseStore,
    KeyringInitializationBinding,
    OSKeyringError,
    OSKeyringState,
    OSVaultRootKeySource,
)
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.secret_memory import (
    SecretConsumer,
    SecretMemoryError,
    SecretPurpose,
    UserPresenceCapability,
)
from finishup.protocol.canonical import JsonValue

_INSTALLATION_ID = "ins_30000000-0000-4000-8000-000000000004"
_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_DIGEST_C = "sha256:" + "c" * 64


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

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password


def test_auto_unlock_passphrase_round_trips_through_approved_platform_store(
    tmp_path: Path,
) -> None:
    backend = _AtomicBackend()
    store = AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    created = store.load_or_create()
    loaded = store.load()

    assert 32 <= len(created) <= 128
    assert loaded == created
    assert "bundle-" in next(iter(backend.values))[1]
    assert bytes(created) not in repr(store).encode()


def test_auto_unlock_load_distinguishes_absent_rejected_and_provisioned(
    tmp_path: Path,
) -> None:
    backend = _AtomicBackend()
    store = AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    assert store.load_with_reason() == (None, "auto_unlock_absent")
    backend.values[("yoetz.auto-unlock.v1", store._username)] = "not-base64!"  # pyright: ignore[reportPrivateUsage]
    assert store.load_with_reason() == (None, "auto_unlock_rejected")
    backend.values[("yoetz.auto-unlock.v1", store._username)] = "YWFh="  # pyright: ignore[reportPrivateUsage]
    assert store.load_with_reason() == (None, "auto_unlock_rejected")

    value = bytearray(b"a" * 48)
    store.save(value)
    loaded, reason = store.load_with_reason()
    assert loaded == value
    assert reason == "none"

    unicode_value = bytearray("correct horse 🔐 battery staple".encode())
    store.save(unicode_value)
    loaded, reason = store.load_with_reason()
    assert loaded == unicode_value
    assert reason == "none"


def test_initialization_refuses_preexisting_auto_unlock_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.adapters.keys.os_keyring as keyring_module

    backend = _AtomicBackend()
    store = AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]
    store.save(bytearray(b"a" * 48))
    original_entry = dict(backend.values)
    wiped: list[bytes] = []
    original_overwrite = keyring_module._overwrite  # pyright: ignore[reportPrivateUsage]

    def observe_overwrite(value: bytearray) -> None:
        original_overwrite(value)
        wiped.append(bytes(value))

    monkeypatch.setattr(keyring_module, "_overwrite", observe_overwrite)
    with pytest.raises(OSKeyringError) as exc:
        store.stage_for_initialization()

    assert exc.value.reason == "entry_exists"
    assert backend.values == original_entry
    assert wiped and set(wiped[-1]) <= {0}


def test_staged_initialization_promotes_only_after_explicit_promotion(tmp_path: Path) -> None:
    """#511: staging never touches the active slot; promotion is a separate verified step."""

    backend = _AtomicBackend()
    store = AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    generated = store.stage_for_initialization()
    assert 32 <= len(generated) <= 128
    assert store.load() is None, "the active slot must stay empty until promotion"
    assert store.slot_report() == {
        "active": "absent",
        "staged_initialization": "present",
        "staged_rotation": "absent",
    }

    store.promote_staged_initialization()
    assert store.load() == generated
    assert store.slot_report() == {
        "active": "present",
        "staged_initialization": "absent",
        "staged_rotation": "absent",
    }
    assert all("staged-initialization" not in account for _service, account in backend.values)


def test_staged_initialization_discard_removes_exactly_the_staged_entry(tmp_path: Path) -> None:
    backend = _AtomicBackend()
    store = AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    store.stage_for_initialization()
    store.discard_staged_initialization()

    assert backend.values == {}
    assert store.slot_report() == {
        "active": "absent",
        "staged_initialization": "absent",
        "staged_rotation": "absent",
    }


def test_staged_initialization_leftover_refuses_a_second_staging(tmp_path: Path) -> None:
    """#511: an unreconciled staged entry is never silently overwritten or adopted."""

    backend = _AtomicBackend()
    store = AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    first = store.stage_for_initialization()
    with pytest.raises(OSKeyringError) as exc:
        store.stage_for_initialization()

    assert exc.value.reason == "staged_entry_exists"
    staged_key = (
        "yoetz.auto-unlock.v1",
        store._staged_init_username,  # pyright: ignore[reportPrivateUsage]
    )
    encoded = backend.values[staged_key]
    assert base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)) == bytes(first)


def test_staged_initialization_guard_is_exclusive_per_bundle(tmp_path: Path) -> None:
    """#511 review: staging, promotion, and proof-based discard serialize on one bundle lock."""

    backend = _AtomicBackend()
    bundle = tmp_path.resolve()
    holder = AutoUnlockPassphraseStore(bundle, backend=backend)
    contender = AutoUnlockPassphraseStore(bundle, backend=backend)
    holder._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]
    contender._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    with holder.staged_initialization_guard():
        with pytest.raises(OSKeyringError) as exc:
            with contender.staged_initialization_guard():
                pass
        assert exc.value.reason == "initialization_in_progress"

    # Released on exit: the contender can now take it.
    with contender.staged_initialization_guard():
        pass


def test_staged_initialization_is_a_restart_unlock_candidate(tmp_path: Path) -> None:
    backend = _AtomicBackend()
    store = AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    generated = store.stage_for_initialization()
    candidates, reason = store.load_candidates_with_reason()

    assert reason == "none"
    assert [(bytes(value), slot) for value, slot in candidates] == [
        (bytes(generated), "staged_initialization")
    ]


def test_auto_unlock_rotation_stages_recovers_and_promotes_without_secret_output(
    tmp_path: Path,
) -> None:
    backend = _AtomicBackend()
    store = AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]
    active = store.load_or_create()
    staged = store.stage_for_rotation()

    candidates, reason = store.load_candidates_with_reason()
    assert reason == "none"
    assert [(bytes(value), slot) for value, slot in candidates] == [
        (bytes(active), "active"),
        (bytes(staged), "staged_rotation"),
    ]

    store.promote_staged_rotation()
    loaded = store.load()
    recovered, recovered_reason = store.load_candidates_with_reason()
    assert loaded == staged
    assert recovered_reason == "none"
    assert [(bytes(value), slot) for value, slot in recovered] == [(bytes(staged), "active")]
    assert all("staged-rotation" not in account for _service, account in backend.values)


def test_auto_unlock_rotation_discard_preserves_active_entry(tmp_path: Path) -> None:
    backend = _AtomicBackend()
    store = AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]
    active = store.load_or_create()
    staged = store.stage_for_rotation()

    store.discard_staged_rotation()

    assert store.load() == active
    assert bytes(staged) != bytes(active)
    assert all("staged-rotation" not in account for _service, account in backend.values)


def test_auto_unlock_rotation_can_stage_an_exact_user_selected_value(tmp_path: Path) -> None:
    backend = _AtomicBackend()
    store = AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]
    active = store.load_or_create()
    selected = bytearray(b"user selected replacement passphrase")

    store.stage_value_for_rotation(selected)
    candidates, reason = store.load_candidates_with_reason()

    assert reason == "none"
    assert [(bytes(value), slot) for value, slot in candidates] == [
        (bytes(active), "active"),
        (bytes(selected), "staged_rotation"),
    ]


class _WriteRaisesBackend:
    def get_password(self, _service: str, _username: str) -> None:
        return None

    def set_password(self, _service: str, _username: str, _password: str) -> None:
        raise RuntimeError


class _ReadbackRaisesBackend:
    def __init__(self) -> None:
        self.calls = 0

    def get_password(self, _service: str, _username: str) -> None:
        self.calls += 1
        if self.calls > 1:
            raise RuntimeError

    def set_password(self, _service: str, _username: str, _password: str) -> None:
        pass


class _ReadbackMismatchBackend:
    def __init__(self) -> None:
        self.calls = 0

    def get_password(self, _service: str, _username: str) -> str | None:
        self.calls += 1
        return None if self.calls == 1 else "different"

    def set_password(self, _service: str, _username: str, _password: str) -> None:
        pass


@pytest.mark.parametrize(
    ("backend_type", "reason"),
    [
        (_WriteRaisesBackend, "ambiguous_write"),
        (_ReadbackRaisesBackend, "readback_failed"),
        (_ReadbackMismatchBackend, "unverified"),
    ],
)
def test_auto_unlock_creation_fails_closed_and_wipes_generated_buffer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend_type: type[object],
    reason: str,
) -> None:
    import finishup.adapters.keys.os_keyring as keyring_module

    backend = backend_type()
    store = AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]
    wiped: list[bytes] = []
    original_overwrite = keyring_module._overwrite  # pyright: ignore[reportPrivateUsage]

    def observe_overwrite(value: bytearray) -> None:
        original_overwrite(value)
        wiped.append(bytes(value))

    monkeypatch.setattr(keyring_module, "_overwrite", observe_overwrite)
    with pytest.raises(OSKeyringError) as exc:
        store.load_or_create()
    assert exc.value.reason == reason
    assert wiped and set(wiped[-1]) <= {0}


def test_bundle_hkdf_and_aes_kw_known_answers() -> None:
    kek = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7")
    assert keywrap.aes_key_wrap(kek, key) == expected
    assert keywrap.aes_key_unwrap(kek, expected) == key


def test_create_and_load_backends(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    vault_dir = tmp_path / "vault"
    store = EncryptedVaultStore(vault_dir)
    store.initialize(memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(range(32))))
    binding = {"installation_id": _INSTALLATION_ID}
    record_id = store.create_record(
        VaultRecordKind.VAULT_SENTINEL,
        binding,
        memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(b"sentinel")),
    )
    assert record_id.startswith("vrec_")
    loaded = store.load_record(VaultRecordKind.VAULT_SENTINEL, binding)
    assert loaded.consume(SecretConsumer.VAULT_ROOT, bytes) == b"sentinel"
    store.close()

    reopened = EncryptedVaultStore(vault_dir)
    reopened.initialize(memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(range(32))))
    reopened.verify_sentinel(binding)
    reopened.close()
    memory.close()


def test_locked_missing_and_unsupported_fail_closed(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    store = EncryptedVaultStore(tmp_path / "vault")
    store.initialize(memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(range(32))))
    with pytest.raises(EncryptedVaultError, match="record_missing"):
        store.load_record(VaultRecordKind.VAULT_SENTINEL, {"installation_id": _INSTALLATION_ID})
    store.close()
    memory.close()


def test_key_domain_mismatch_is_detected() -> None:
    memory = LocalSecretMemory()
    source = bytearray(b"0123456789abcdef")
    handle = memory.capture(SecretPurpose.PORTABLE_RECOVERY, source)
    assert source == bytearray(16)
    with pytest.raises(SecretMemoryError, match="consumer_forbidden"):
        handle.consume(SecretConsumer.VAULT_ROOT, bytes)
    memory.close()


def test_keyring_create_requires_first_install_authority() -> None:
    memory = LocalSecretMemory()
    backend = _AtomicBackend()
    source = OSVaultRootKeySource(memory, backend=backend)
    source._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]
    probe = asyncio.run(source.probe(_INSTALLATION_ID))
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
    manifest: dict[str, JsonValue] = {"user_presence_cells": [row]}
    authority = asyncio.run(
        source.authorize_first_install(
            probe,
            presence,
            manifest,
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
    assert loaded.installation_id == _INSTALLATION_ID
    assert loaded.correlation_commitment == commitment
    loaded.ivk_handle.consume(SecretConsumer.VAULT_ROOT, lambda view: None)
    loaded.correlation_handle.consume(SecretConsumer.VAULT_ROOT, lambda view: None)
    memory.close()


def test_keyring_signatures_and_unapproved_backend_are_fail_closed() -> None:
    assert tuple(inspect.signature(OSVaultRootKeySource).parameters) == (
        "secret_memory",
        "backend",
    )
    assert tuple(inspect.signature(OSVaultRootKeySource.create_and_verify).parameters) == (
        "self",
        "authority",
        "binding",
        "service_generation",
        "pristine_state_digest",
        "staged_sentinel_verifier",
    )
    memory = LocalSecretMemory()
    source = OSVaultRootKeySource(memory, backend=_AtomicBackend())
    probe = asyncio.run(source.probe(_INSTALLATION_ID))
    assert probe.state is OSKeyringState.UNSUPPORTED
    assert probe.create_if_absent
    memory.close()


def test_staged_initialization_guard_creates_a_missing_bundle_root_owner_private(
    tmp_path: Path,
) -> None:
    """#565: trusted initialization before any service start must not read as unsupported."""

    import stat

    parent = tmp_path.resolve() / "isolated"
    parent.mkdir(mode=0o700)
    bundle = parent / "data"
    store = AutoUnlockPassphraseStore(bundle, backend=_AtomicBackend())
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    with store.staged_initialization_guard():
        pass

    facts = bundle.lstat()
    assert stat.S_ISDIR(facts.st_mode) and not stat.S_ISLNK(facts.st_mode)
    assert stat.S_IMODE(facts.st_mode) == 0o700
    assert stat.S_IMODE((bundle / "auto-unlock-init.lock").lstat().st_mode) == 0o600
    assert sorted(child.name for child in parent.iterdir()) == ["data"]


def test_staged_initialization_guard_reports_a_missing_bundle_parent_distinctly(
    tmp_path: Path,
) -> None:
    """#565: only the exact bundle root is created; a missing parent is its own outcome."""

    absent_parent = tmp_path.resolve() / "absent"
    store = AutoUnlockPassphraseStore(absent_parent / "data", backend=_AtomicBackend())
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(OSKeyringError) as exc:
        with store.staged_initialization_guard():
            pass

    assert exc.value.reason == "bundle_parent_missing"
    assert not absent_parent.exists()


def test_staged_initialization_guard_rejects_a_symlinked_bundle_root(tmp_path: Path) -> None:
    """#565: a symlink where the bundle root belongs is unsafe, never merely unsupported."""

    root = tmp_path.resolve()
    real = root / "real-data"
    real.mkdir(mode=0o700)
    link = root / "data"
    link.symlink_to(real, target_is_directory=True)
    store = AutoUnlockPassphraseStore(link, backend=_AtomicBackend())
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(OSKeyringError) as exc:
        with store.staged_initialization_guard():
            pass

    assert exc.value.reason == "bundle_unsafe"
    assert not (real / "auto-unlock-init.lock").exists()


def test_staged_initialization_guard_rejects_a_symlinked_lock_file(tmp_path: Path) -> None:
    """#565: O_NOFOLLOW rejection of a planted lock symlink stays distinct from unsupported."""

    bundle = tmp_path.resolve() / "data"
    bundle.mkdir(mode=0o700)
    (bundle / "elsewhere").write_bytes(b"")
    (bundle / "auto-unlock-init.lock").symlink_to(bundle / "elsewhere")
    store = AutoUnlockPassphraseStore(bundle, backend=_AtomicBackend())
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(OSKeyringError) as exc:
        with store.staged_initialization_guard():
            pass

    assert exc.value.reason == "bundle_unsafe"


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="permission checks need a non-root uid"
)
def test_staged_initialization_guard_reports_a_permission_failure_distinctly(
    tmp_path: Path,
) -> None:
    """#565: an unwritable parent is a permission outcome, not a keyring verdict."""

    parent = tmp_path.resolve() / "readonly"
    parent.mkdir(mode=0o500)
    store = AutoUnlockPassphraseStore(parent / "data", backend=_AtomicBackend())
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]

    try:
        with pytest.raises(OSKeyringError) as exc:
            with store.staged_initialization_guard():
                pass
    finally:
        parent.chmod(0o700)

    assert exc.value.reason == "bundle_permission_denied"
    assert not (parent / "data").exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="installed macOS keyring backend")
def test_installed_macos_keyring_guard_succeeds_on_a_pristine_bundle_root(
    tmp_path: Path,
) -> None:
    """#565: the real installed macOS backend is supported and its guard opens before any
    service has created the bundle root. The guard never touches the keychain itself."""

    import keyring

    store = AutoUnlockPassphraseStore(tmp_path.resolve() / "data", backend=keyring.get_keyring())
    if store._backend_id != "keyring.backends.macOS.Keyring":  # pyright: ignore[reportPrivateUsage]
        pytest.skip("macOS keychain backend is not the installed default here")

    assert store.available is True
    with store.staged_initialization_guard():
        pass
    assert (tmp_path.resolve() / "data" / "auto-unlock-init.lock").exists()
