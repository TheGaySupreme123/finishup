from __future__ import annotations

import hmac
import json
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from finishup.adapters.keys.encrypted_vault import (
    EncryptedVaultError,
    EncryptedVaultStore,
    VaultRecordKind,
)
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.secret_memory import SecretConsumer, SecretPurpose
from finishup.protocol.canonical import JsonValue, canonical_encode

_INSTALLATION_ID = "ins_00000000-0000-4000-8000-000000000001"
_TASK_ID = "tsk_00000000-0000-4000-8000-000000000002"


def _capture(memory: LocalSecretMemory, value: bytes, purpose: SecretPurpose):
    return memory.capture(purpose, bytearray(value))


def test_records_round_trip_without_plaintext_or_independent_mac_key_records(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    root = b"r" * 32
    store = EncryptedVaultStore(tmp_path / "vault")
    store.initialize(_capture(memory, root, SecretPurpose.VAULT_ROOT_KEY))
    store.create_record(
        VaultRecordKind.VAULT_SENTINEL,
        {"installation_id": _INSTALLATION_ID},
        _capture(memory, b"sentinel-canary", SecretPurpose.VAULT_ROOT_KEY),
    )
    store.create_record(
        VaultRecordKind.BUNDLE_KEY,
        {"task_id": _TASK_ID, "key_slot": "bmk-test"},
        _capture(memory, b"bundle-master-key-canary-32byt!", SecretPurpose.VAULT_ROOT_KEY),
    )
    loaded = store.load_record(
        VaultRecordKind.BUNDLE_KEY,
        {"task_id": _TASK_ID, "key_slot": "bmk-test"},
    )
    assert loaded.consume(SecretConsumer.VAULT_ROOT, bytes) == b"bundle-master-key-canary-32byt!"

    disk = b"".join(path.read_bytes() for path in (tmp_path / "vault").iterdir())
    assert b"sentinel-canary" not in disk
    assert b"bundle-master-key-canary" not in disk
    assert b"catalog_lookup" not in disk
    assert b"log_correlation" not in disk
    assert b"privacy_audit" not in disk


def test_wrong_root_and_frame_tamper_fail_closed(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    vault_dir = tmp_path / "vault"
    store = EncryptedVaultStore(vault_dir)
    store.initialize(_capture(memory, b"a" * 32, SecretPurpose.VAULT_ROOT_KEY))
    store.create_record(
        VaultRecordKind.VAULT_SENTINEL,
        {"installation_id": _INSTALLATION_ID},
        _capture(memory, b"sentinel", SecretPurpose.VAULT_ROOT_KEY),
    )
    store.close()

    wrong = EncryptedVaultStore(vault_dir)
    with pytest.raises(EncryptedVaultError):
        wrong.initialize(_capture(memory, b"b" * 32, SecretPurpose.VAULT_ROOT_KEY))

    frame = next(vault_dir.glob("vrec_*.1.yzv"))
    data = bytearray(frame.read_bytes())
    data[-1] ^= 1
    frame.write_bytes(data)
    reopened = EncryptedVaultStore(vault_dir)
    with pytest.raises(EncryptedVaultError):
        reopened.initialize(_capture(memory, b"a" * 32, SecretPurpose.VAULT_ROOT_KEY))


def test_root_rotation_reencrypts_every_record_and_preserves_commitment_root(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    old_root = b"o" * 32
    new_root = b"n" * 32
    vault_dir = tmp_path / "vault"
    store = EncryptedVaultStore(vault_dir)
    store.initialize(_capture(memory, old_root, SecretPurpose.VAULT_ROOT_KEY))
    store.create_record(
        VaultRecordKind.VAULT_SENTINEL,
        {"installation_id": _INSTALLATION_ID},
        _capture(memory, b"sentinel", SecretPurpose.VAULT_ROOT_KEY),
    )
    store.create_record(
        VaultRecordKind.BUNDLE_KEY,
        {"task_id": _TASK_ID, "key_slot": "bmk-test"},
        _capture(memory, b"bundle-key", SecretPurpose.VAULT_ROOT_KEY),
    )
    before_mac_root = store.installation_mac_root().consume(SecretConsumer.VAULT_ROOT, bytes)

    prepared = store.prepare_root_rotation(
        _capture(memory, new_root, SecretPurpose.VAULT_ROOT_KEY),
        recovery_generation=2,
    )

    old_candidate = EncryptedVaultStore(prepared.stage)
    with pytest.raises(EncryptedVaultError):
        old_candidate.initialize(_capture(memory, old_root, SecretPurpose.VAULT_ROOT_KEY))

    rotated = EncryptedVaultStore(prepared.stage)
    rotated.initialize(_capture(memory, new_root, SecretPurpose.VAULT_ROOT_KEY))
    rotated.verify_sentinel({"installation_id": _INSTALLATION_ID})
    loaded = rotated.load_record(
        VaultRecordKind.BUNDLE_KEY,
        {"task_id": _TASK_ID, "key_slot": "bmk-test"},
    )
    assert loaded.consume(SecretConsumer.VAULT_ROOT, bytes) == b"bundle-key"
    assert (
        rotated.installation_mac_root().consume(SecretConsumer.VAULT_ROOT, bytes) == before_mac_root
    )
    parsed_wrapper: object = json.loads((prepared.stage / "vault-index.json").read_bytes())
    assert type(parsed_wrapper) is dict
    wrapper = cast(dict[str, object], parsed_wrapper)
    assert type(wrapper["index"]) is dict
    old_locator = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"yoetz/vault-internal-root/v1",
        info=b"yoetz/vault-record-locator/v1",
    ).derive(old_root)
    legacy_index_mac = (
        "hmac-sha256:"
        + hmac.digest(
            old_locator,
            b"yoetz/vault-record-index/v1\x00"
            + canonical_encode(cast(dict[str, JsonValue], wrapper["index"])),
            "sha256",
        ).hex()
    )
    assert wrapper["index_mac"] != legacy_index_mac

    disk = b"".join(path.read_bytes() for path in prepared.stage.iterdir())
    assert old_root not in disk
    assert new_root not in disk
    assert before_mac_root not in disk
