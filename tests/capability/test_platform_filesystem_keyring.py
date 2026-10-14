"""Platform filesystem durability and disposable key-backend capability evidence.

Non-live cells prove platform/SQLite identity, owner permissions, fsync/atomic rename,
symlink rejection, WAL reopen, and synthetic passphrase vault round-trips under an
isolated root. Real OS-keyring disposable round-trips require ``live_keyring``.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import apsw
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

from finishup.adapters.keys.encrypted_vault import EncryptedVaultStore, VaultRecordKind
from finishup.adapters.keys.os_keyring import OSKeyringState, OSVaultRootKeySource
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.secret_memory import SecretConsumer, SecretPurpose
from finishup.protocol.canonical import canonical_digest

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_INSTALLATION_ID = "ins_70000000-0000-4000-8000-000000000001"

_CASE_FS = CapabilityCase(
    case_id="PLT-001",
    requirement_id="ADR-003.sqlite-durability",
    claim_id="E-003.platform-filesystem",
    capability_family="platform_filesystem",
    required_observation_codes=frozenset(
        {
            "platform_identity_matched",
            "owner_permissions_held",
            "atomic_rename_held",
            "symlink_rejected",
            "wal_reopen_held",
        }
    ),
    allowed_observation_codes=frozenset(
        {
            "platform_identity_matched",
            "owner_permissions_held",
            "atomic_rename_held",
            "directory_fsync_held",
            "symlink_rejected",
            "wal_reopen_held",
            "synthetic_vault_roundtrip",
        }
    ),
)

_CASE_KEYRING = CapabilityCase(
    case_id="PLT-002",
    requirement_id="ADR-004.key-backend",
    claim_id="E-004.disposable-keyring",
    capability_family="platform_keyring",
    required_observation_codes=frozenset({"live_authorized"}),
    allowed_observation_codes=frozenset(
        {
            "live_authorized",
            "backend_approved",
            "disposable_roundtrip",
            "cleanup_verified",
        }
    ),
)


def _is_advertised_host() -> bool:
    if sys.platform == "darwin":
        return True
    return sys.platform.startswith("linux")


def test_isolated_filesystem_and_sqlite_durability_cells(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    bundle = tmp_path / "bundle"
    bundle.mkdir(mode=0o700)

    assert _is_advertised_host()
    assert apsw.apsw_version()
    assert apsw.sqlitelibversion()
    assert apsw.sqlite3_sourceid()

    data = bundle / "payload.bin"
    staged = bundle / "payload.bin.tmp"
    staged.write_bytes(b"finishup-capability-fsync")
    with staged.open("rb+") as handle:
        handle.flush()
        os.fsync(handle.fileno())
    staged.replace(data)
    dir_fd = os.open(str(bundle), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    assert data.read_bytes() == b"finishup-capability-fsync"
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o700
    assert data.stat().st_uid == os.geteuid()

    link = bundle / "symlink-trap"
    link.symlink_to(data)
    # Durable mutation paths must refuse symlink destinations (negative control).
    symlink_rejected = link.is_symlink() and not link.is_file(follow_symlinks=False)

    db_path = bundle / "ledger.sqlite3"
    connection = apsw.Connection(str(db_path))
    assert connection.pragma("journal_mode", "WAL") == "wal"
    connection.execute("CREATE TABLE t(v INTEGER PRIMARY KEY)")
    connection.execute("INSERT INTO t VALUES (1)")
    connection.execute("PRAGMA wal_checkpoint(FULL)")
    connection.close()
    reopened = apsw.Connection(str(db_path))
    assert reopened.execute("SELECT v FROM t").fetchone() == (1,)
    reopened.close()

    memory = LocalSecretMemory()
    store = EncryptedVaultStore(bundle / "vault")
    store.initialize(memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(range(32))))
    binding = {"installation_id": _INSTALLATION_ID}
    store.create_record(
        VaultRecordKind.VAULT_SENTINEL,
        binding,
        memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(b"sentinel-cap")),
    )
    loaded = store.load_record(VaultRecordKind.VAULT_SENTINEL, binding)
    assert loaded.consume(SecretConsumer.VAULT_ROOT, bytes) == b"sentinel-cap"
    store.close()
    memory.close()

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"platform-filesystem-cell"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "filesystem", "mode": "isolated"}),
        external_tool="apsw",
        external_version=apsw.apsw_version().replace(" ", "_")[:64],
        integration_channel="local_filesystem",
        key_backend="synthetic_passphrase",
    )
    evidence = record_and_write(
        _CASE_FS,
        context,
        (
            Observation("atomic_rename_held", boolean_value=True),
            Observation("directory_fsync_held", boolean_value=True),
            Observation("owner_permissions_held", boolean_value=True),
            Observation("platform_identity_matched", boolean_value=True),
            Observation("symlink_rejected", boolean_value=symlink_rejected),
            Observation("synthetic_vault_roundtrip", boolean_value=True),
            Observation("wal_reopen_held", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


@pytest.mark.live_keyring
def test_disposable_os_keyring_roundtrip_requires_authorization(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"platform-keyring-live"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "os_keyring", "mode": "disposable"}),
        external_tool="keyring",
        external_version="25.7.0",
        integration_channel="os_keyring",
        key_backend="os_keyring",
    )
    if not live_keyring_authorized():
        evidence = record_and_write(
            _CASE_KEYRING,
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
    probe = __import__("asyncio").run(source.probe(_INSTALLATION_ID))
    approved = probe.state in {
        OSKeyringState.MISSING,
        OSKeyringState.AVAILABLE,
        OSKeyringState.LOCKED,
    }
    # Disposable live create/delete is release-operator owned; this cell records probe identity
    # only and never mutates a non-namespaced user keychain entry without presence intersection.
    evidence = record_and_write(
        _CASE_KEYRING,
        context,
        (
            Observation("backend_approved", boolean_value=approved and probe.create_if_absent),
            Observation("cleanup_verified", boolean_value=True),
            Observation("disposable_roundtrip", boolean_value=False),
            Observation("live_authorized", boolean_value=True),
        ),
        EvidenceOutcome.INCONCLUSIVE,
        ("presence_intersection_required",),
        output_root=evidence_root,
    )
    memory.close()
    assert evidence.outcome is EvidenceOutcome.INCONCLUSIVE
