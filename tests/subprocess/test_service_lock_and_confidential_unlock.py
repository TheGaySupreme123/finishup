from __future__ import annotations

import json
import os
import struct
import sys
from pathlib import Path
from typing import cast

from helpers.child import (
    ChildLimits,
    ChildResult,
    ChildSpec,
    assert_no_owned_children,
    communicate_bounded,
    spawn_installed,
)

_IVK_CANARY = b"vault-ivk-canary-2026-0000000000"
_CEREMONY_CANARY = b"ceremony-secret-canary-2026"

_HUMAN_FRAME_PROBE = r"""
import json, os, sys
from finishup.service.confidential_protocol import ConfidentialProtocolError, decode_human_frame

frame = bytearray(sys.stdin.buffer.read())
secret = bytes(frame).split(b'"secret":"', 1)[1].split(b'"', 1)[0]
try:
    decode_human_frame(frame)
    reason = "unexpected_accept"
except ConfidentialProtocolError as exc:
    reason = exc.reason
output = {"argv_leak": any(secret in item.encode() for item in sys.argv),
          "env_leak": any(secret in value.encode("utf-8", "surrogateescape") for value in os.environ.values()),
          "reason": reason}
frame[:] = b"\x00" * len(frame)
print(json.dumps(output, separators=(",", ":"), sort_keys=True))
"""

_VAULT_PROBE = r"""
import asyncio, hashlib, json, os, sys
from datetime import UTC, datetime
from pathlib import Path
from finishup.adapters.keys.encrypted_vault import EncryptedVaultStore, VaultRecordKind
from finishup.adapters.keys.os_keyring import KeyringInitializationBinding
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.keys import KeyStoreError, MacKeyPurpose
from finishup.ports.secret_memory import SecretPurpose
from finishup.service.vault import VaultMode, VaultService

class Clock:
    def now_utc(self): return datetime(2026, 7, 19, tzinfo=UTC)
    def monotonic_seconds(self): return 1.0

async def main():
    ivk = bytearray(sys.stdin.buffer.read())
    if len(ivk) != 32: raise RuntimeError("invalid test key length")
    memory = LocalSecretMemory()
    installation = "ins_11111111-1111-4111-8111-111111111111"
    vault_dir = Path.cwd() / "vault"
    initial = EncryptedVaultStore(vault_dir)
    initial.initialize(memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(ivk)))
    initial.create_record(VaultRecordKind.VAULT_SENTINEL, {"installation_id": installation},
        memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(os.urandom(32))))
    initial.close()
    correlation = bytearray(os.urandom(32))
    commitment = "sha256:" + hashlib.sha256(correlation).hexdigest()
    class Source:
        async def load(self, requested):
            assert requested == installation
            return KeyringInitializationBinding(1, installation, commitment,
                memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(ivk)),
                memory.capture(SecretPurpose.VAULT_ROOT_KEY, bytearray(correlation)))
    vault = VaultService(installation_id=installation, service_generation=7, mode=VaultMode.OS_KEYRING,
        secret_memory=memory, clock=Clock(), vault_store_factory=lambda: EncryptedVaultStore(vault_dir),
        keyring_source=Source())
    ready = await vault.initialize(None)
    mac = vault.installation_mac_handle(MacKeyPurpose.LOG_CORRELATION)
    before = mac.mac(b"yoetz/session-log-id/v1\x00", b"session")
    locked = await vault.lock()
    try: mac.mac(b"yoetz/session-log-id/v1\x00", b"session"); stale = "unexpected_accept"
    except KeyStoreError as exc: stale = exc.reason.value
    try: await vault.load_bundle_keys("tsk_22222222-2222-4222-8222-222222222222"); locked_reason = "unexpected_accept"
    except KeyStoreError as exc: locked_reason = exc.reason.value
    raw_leak = any(path.is_file() and bytes(ivk) in path.read_bytes() for path in Path.cwd().rglob("*"))
    output = {"argv_leak": any(ivk in item.encode() for item in sys.argv),
        "env_leak": any(ivk in value.encode("utf-8", "surrogateescape") for value in os.environ.values()),
        "locked_generation": locked.vault_generation, "locked_reason": locked_reason,
        "locked_state": locked.state.value, "mac_shape": before.startswith("hmac-sha256:"),
        "raw_secret_in_artifacts": raw_leak, "ready_generation": ready.vault_generation,
        "ready_state": ready.state.value, "stale_reason": stale}
    await vault.close(); memory.close(); ivk[:] = b"\x00" * len(ivk); correlation[:] = b"\x00" * len(correlation)
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))

asyncio.run(main())
"""


def _run_probe() -> ChildResult:
    assert len(_IVK_CANARY) == 32
    spec = ChildSpec(
        executable=Path(sys.executable),
        argv=("-I", "-c", _VAULT_PROBE),
        limits=ChildLimits(wall_time_seconds=30.0, max_output_bytes=65_536),
    )
    handle = spawn_installed(
        spec,
        {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "VIRTUAL_ENV": sys.prefix},
    )
    result = communicate_bounded(handle, _IVK_CANARY)
    assert_no_owned_children(result.temp_root)
    assert result.limit_verdict == "passed"
    assert result.exit_code == 0
    assert result.stderr == b""
    assert _IVK_CANARY not in result.stdout + result.stderr
    for path in result.temp_root.rglob("*"):
        if path.is_file():
            assert _IVK_CANARY not in path.read_bytes()
    return result


def _run_human_frame_probe(frame: bytes) -> ChildResult:
    spec = ChildSpec(
        executable=Path(sys.executable),
        argv=("-I", "-c", _HUMAN_FRAME_PROBE),
        limits=ChildLimits(wall_time_seconds=20.0, max_output_bytes=65_536),
    )
    handle = spawn_installed(
        spec,
        {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "VIRTUAL_ENV": sys.prefix},
    )
    result = communicate_bounded(handle, frame)
    assert_no_owned_children(result.temp_root)
    assert result.limit_verdict == "passed"
    assert result.exit_code == 0
    assert result.stderr == b""
    assert _CEREMONY_CANARY not in result.stdout + result.stderr
    return result


def test_lock_invalidates_ready_generation_and_preserves_only_ciphertext() -> None:
    observed = cast(dict[str, object], json.loads(_run_probe().stdout))
    assert observed == {
        "argv_leak": False,
        "env_leak": False,
        "locked_generation": 2,
        "locked_reason": "vault_locked",
        "locked_state": "locked",
        "mac_shape": True,
        "raw_secret_in_artifacts": False,
        "ready_generation": 1,
        "ready_state": "ready",
        "stale_reason": "stale_key_handle",
    }


def test_malformed_human_ceremony_frame_fails_closed_without_secret_echo() -> None:
    payload = b'{"kind":"open","secret":"' + _CEREMONY_CANARY + b'"}'
    frame = struct.pack(">4sBBI", b"YZH1", 1, 1, len(payload)) + payload
    observed = cast(dict[str, object], json.loads(_run_human_frame_probe(frame).stdout))
    assert observed == {"argv_leak": False, "env_leak": False, "reason": "invalid_frame"}
