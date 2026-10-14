"""Agent-authorized vault initialization over the real client/service composition (#510/#511).

The defects these lock against: `finishup consent authorize` completed the real human-control
ceremony, received a non-ready `VaultStateResult`, and still consumed the approval before the
result was validated (#510); and the generated auto-unlock credential was durably written before
the ceremony, so a failed initialization stranded it with no recovery path — the retry refused
the abandoned same-attempt entry as `auto_unlock_entry_exists` (#511). These tests run real agent
attestation, the real staged-initialization keyring lifecycle over an in-memory backend, the real
YZH1/YZS1 client and service transport, and a real unlock throttle, mocking only the OS keyring
backend itself.
"""

from __future__ import annotations

import asyncio
import base64
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

import finishup.service.daemon as daemon_module
from finishup.adapters.control.unix_socket import (
    bind_control_listener,
    bind_human_control_listener,
    bind_secret_listener,
)
from finishup.adapters.keys.os_keyring import AutoUnlockPassphraseStore, OSKeyringError
from finishup.cli import elevated
from finishup.config.load import FinishUpConfig
from finishup.service.daemon import ServiceDaemon
from finishup.service.elevated_bootstrap import ElevatedBootstrapError, load_pending
from finishup.service.unlock import UnlockThrottleRecord

_FOREIGN_INSTALLATION_ID = "ins_30000000-0000-4000-8000-000000000001"
_FOREIGN_WRITER_ID = "svc_30000000-0000-4000-8000-000000000002"
_SERVICE_NAME = "yoetz.auto-unlock.v1"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def runtime_directory(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Short in-tree socket directory: AF_UNIX paths bound under tmp_path are too long."""

    runtime = Path(tempfile.mkdtemp(prefix=".yctl-", dir=Path.cwd()))
    runtime.chmod(0o700)
    monkeypatch.setattr(
        "finishup.adapters.control.unix_socket._runtime_directory",
        lambda: runtime,
    )
    try:
        yield runtime
    finally:
        shutil.rmtree(runtime, ignore_errors=True)


class _MemoryKeyring:
    """In-memory platform credential store standing in for the OS keyring backend."""

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        del self.values[(service, username)]


def _approved_store(bundle: Path, backend: _MemoryKeyring) -> AutoUnlockPassphraseStore:
    store = AutoUnlockPassphraseStore(bundle, backend=backend)
    store._backend_id = "keyring.backends.macOS.Keyring"  # pyright: ignore[reportPrivateUsage]
    return store


def _entry_bytes(backend: _MemoryKeyring, account: str) -> bytes:
    encoded = backend.values[(_SERVICE_NAME, account)]
    return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))


def _slot_accounts(store: AutoUnlockPassphraseStore) -> tuple[str, str]:
    active = store._username  # pyright: ignore[reportPrivateUsage]
    staged = store._staged_init_username  # pyright: ignore[reportPrivateUsage]
    return active, staged


def _stage_non_pristine_throttle_record(path: Path) -> None:
    """The exact repro state (#510): uninitialized bundle, non-pristine per-user throttle."""

    import os

    record = UnlockThrottleRecord.create(
        installation_id=_FOREIGN_INSTALLATION_ID,
        record_generation=1,
        consecutive_failures=1,
        attempt_in_progress=False,
        last_failure_utc="2026-08-31T11:00:00.000Z",
        last_writer_instance_id=_FOREIGN_WRITER_ID,
    )
    path.write_bytes(record.encode())
    os.chmod(path, 0o600)


async def _production_daemon(tmp_path: Path, *, pristine: bool) -> ServiceDaemon:
    root = tmp_path / "data"
    metadata = tmp_path / "state"
    root.mkdir(mode=0o700, exist_ok=True)
    metadata.mkdir(mode=0o700, exist_ok=True)
    if not pristine:
        _stage_non_pristine_throttle_record(metadata / "unlock-throttle.json")
    paths = daemon_module._ProductionPaths(  # pyright: ignore[reportPrivateUsage]
        root,
        metadata / "service-generation.json",
        metadata / "unlock-throttle.json",
        metadata / "service.lock",
        metadata,
    )
    binders = daemon_module._ListenerBinders(  # pyright: ignore[reportPrivateUsage]
        bind_control_listener,
        bind_secret_listener,
        bind_human_control_listener,
    )
    composition = await daemon_module._production_composition(  # pyright: ignore[reportPrivateUsage]
        _config=FinishUpConfig(),
        _paths=paths,
        _binders=binders,
    )
    return ServiceDaemon(_composition=composition)


def _approve_attestation(pending: object) -> dict[str, object]:
    return {
        "schema": "yoetz.chat-user-attestation/1",
        "channel": "agent_attested_chat_instruction",
        "client_kind": "codex",
        "instruction_source": "explicit_current_chat_user",
        "pending_id": getattr(pending, "pending_id"),
        "operation": getattr(pending, "operation"),
        "danger_digest": getattr(pending, "danger_digest"),
        "target_digest": getattr(pending, "target_digest"),
        "warning_acknowledged": True,
        "decision": "approve",
    }


def _assert_no_secret_bytes(tree: Path, secret: bytes) -> None:
    for path in tree.rglob("*"):
        if path.is_file() and not path.is_symlink():
            assert secret not in path.read_bytes(), path


@pytest.mark.anyio
async def test_failed_initialize_discards_staged_credential_and_retry_succeeds(
    tmp_path: Path,
    runtime_directory: Path,
) -> None:
    """#511 acceptance: a definitive pre-commit failure leaves no orphan, and a fresh exact
    consent attempt after restart succeeds without `auto_unlock_entry_exists`."""

    tmp_path.chmod(0o700)
    consent_state = tmp_path / "consent"
    consent_state.mkdir(mode=0o700)
    backend = _MemoryKeyring()
    store = _approved_store(tmp_path / "data", backend)
    active_account, staged_account = _slot_accounts(store)

    daemon = await _production_daemon(tmp_path, pristine=False)
    await daemon.start()
    serving = asyncio.create_task(daemon.serve())
    try:
        with (
            patch("finishup.service.elevated_bootstrap.state_dir", return_value=consent_state),
            patch("finishup.cli.elevated._auto_unlock_store", return_value=store),
        ):
            elevated.prepare_elevated("vault_initialize")
            pending = load_pending(_state=consent_state)
            assert pending is not None
            with pytest.raises(ElevatedBootstrapError) as exc:
                await asyncio.wait_for(
                    elevated.authorize_elevated(_approve_attestation(pending)), timeout=30
                )

            assert exc.value.reason == "vault_result_throttle_record_exists"
            assert load_pending(_state=consent_state) is None
            # Failure atomicity: the exact same-attempt staged credential was removed after
            # the live service proved the vault is still uninitialized. Nothing is stranded.
            assert backend.values == {}
            assert daemon.status().vault_mode == "uninitialized"
            assert not (tmp_path / "data" / "vault").exists()
    finally:
        await daemon.stop()
        await asyncio.wait_for(serving, timeout=10)

    # Operator repair of the unrelated foreign throttle record, then a sanctioned restart.
    (tmp_path / "state" / "unlock-throttle.json").unlink()
    retry_daemon = await _production_daemon(tmp_path, pristine=True)
    await retry_daemon.start()
    retry_serving = asyncio.create_task(retry_daemon.serve())
    try:
        with (
            patch("finishup.service.elevated_bootstrap.state_dir", return_value=consent_state),
            patch("finishup.cli.elevated._auto_unlock_store", return_value=store),
        ):
            elevated.prepare_elevated("vault_initialize")
            pending = load_pending(_state=consent_state)
            assert pending is not None
            result = await asyncio.wait_for(
                elevated.authorize_elevated(_approve_attestation(pending)), timeout=30
            )

            assert result["outcome"] == "completed"
            assert result["result"] == {"state": "ready", "reason": "succeeded"}
            assert retry_daemon.status().vault_mode == "passphrase"
            # The credential is bundle-scoped, promoted to the active slot, and the staged
            # slot is clear.
            assert (_SERVICE_NAME, active_account) in backend.values
            assert (_SERVICE_NAME, staged_account) not in backend.values
    finally:
        await retry_daemon.stop()
        await asyncio.wait_for(retry_serving, timeout=10)

    secret = _entry_bytes(backend, active_account)
    _assert_no_secret_bytes(tmp_path, secret)
    _assert_no_secret_bytes(runtime_directory, secret)


@pytest.mark.anyio
async def test_agent_authorized_initialize_non_ready_result_is_bounded_and_never_approved(
    tmp_path: Path,
    runtime_directory: Path,
) -> None:
    tmp_path.chmod(0o700)
    consent_state = tmp_path / "consent"
    consent_state.mkdir(mode=0o700)
    backend = _MemoryKeyring()
    store = _approved_store(tmp_path / "data", backend)

    daemon = await _production_daemon(tmp_path, pristine=False)
    # Publish the endpoints before any client runs; serve() then only arms the accept loops.
    await daemon.start()
    serving = asyncio.create_task(daemon.serve())
    try:
        with (
            patch("finishup.service.elevated_bootstrap.state_dir", return_value=consent_state),
            patch("finishup.cli.elevated._auto_unlock_store", return_value=store),
        ):
            elevated.prepare_elevated("vault_initialize")
            pending = load_pending(_state=consent_state)
            assert pending is not None
            with pytest.raises(ElevatedBootstrapError) as exc:
                await asyncio.wait_for(
                    elevated.authorize_elevated(_approve_attestation(pending)), timeout=30
                )

            # The actionable service reason survives as a bounded token, never the generic
            # authorize_failed collapse.
            assert exc.value.reason == "vault_result_throttle_record_exists"
            # The approval is consumed as failed with a stable correlation; nothing durable
            # claims success and the audit never says approved.
            assert load_pending(_state=consent_state) is None
            audit_lines = (
                (consent_state / "elevated-bootstrap" / "elevated-bootstrap-audit.jsonl")
                .read_text("utf-8")
                .splitlines()
            )
            assert not any('"outcome":"approved"' in line for line in audit_lines)
            consumed = [line for line in audit_lines if '"event":"review_consumed"' in line]
            assert len(consumed) == 1
            assert '"outcome":"failed"' in consumed[0]
            assert '"failure_reason":"vault_result_throttle_record_exists"' in consumed[0]
            assert pending.pending_id in consumed[0]

            # The daemon still reports the truthful vault state.
            assert daemon.status().vault_mode == "uninitialized"
            assert not (tmp_path / "data" / "vault").exists()
    finally:
        await daemon.stop()
        await asyncio.wait_for(serving, timeout=10)

    # No credential entry survived the failed attempt.
    assert backend.values == {}


@pytest.mark.anyio
async def test_agent_authorized_initialize_succeeds_on_pristine_state_without_secret_exposure(
    tmp_path: Path,
    runtime_directory: Path,
) -> None:
    tmp_path.chmod(0o700)
    consent_state = tmp_path / "consent"
    consent_state.mkdir(mode=0o700)
    backend = _MemoryKeyring()
    store = _approved_store(tmp_path / "data", backend)
    active_account, staged_account = _slot_accounts(store)

    daemon = await _production_daemon(tmp_path, pristine=True)
    await daemon.start()
    serving = asyncio.create_task(daemon.serve())
    try:
        with (
            patch("finishup.service.elevated_bootstrap.state_dir", return_value=consent_state),
            patch("finishup.cli.elevated._auto_unlock_store", return_value=store),
        ):
            elevated.prepare_elevated("vault_initialize")
            pending = load_pending(_state=consent_state)
            assert pending is not None
            result = await asyncio.wait_for(
                elevated.authorize_elevated(_approve_attestation(pending)), timeout=30
            )

            assert result["outcome"] == "completed"
            assert result["result"] == {"state": "ready", "reason": "succeeded"}
            assert load_pending(_state=consent_state) is None
            audit_lines = (
                (consent_state / "elevated-bootstrap" / "elevated-bootstrap-audit.jsonl")
                .read_text("utf-8")
                .splitlines()
            )
            assert any('"outcome":"approved"' in line for line in audit_lines)
            assert not any('"outcome":"failed"' in line for line in audit_lines)
            assert daemon.status().vault_mode == "passphrase"
            assert (_SERVICE_NAME, active_account) in backend.values
            assert (_SERVICE_NAME, staged_account) not in backend.values
    finally:
        await daemon.stop()
        await asyncio.wait_for(serving, timeout=10)

    secret = _entry_bytes(backend, active_account)
    _assert_no_secret_bytes(tmp_path, secret)
    _assert_no_secret_bytes(runtime_directory, secret)


@pytest.mark.anyio
async def test_promotion_crash_is_reconciled_by_proof_at_restart(
    tmp_path: Path,
    runtime_directory: Path,
) -> None:
    """#511 acceptance: the vault commits, keyring promotion fails, the operation still
    completes, and the next service start promotes the staged entry by cryptographic proof."""

    tmp_path.chmod(0o700)
    consent_state = tmp_path / "consent"
    consent_state.mkdir(mode=0o700)
    backend = _MemoryKeyring()
    store = _approved_store(tmp_path / "data", backend)
    active_account, staged_account = _slot_accounts(store)

    daemon = await _production_daemon(tmp_path, pristine=True)
    await daemon.start()
    serving = asyncio.create_task(daemon.serve())
    try:
        with (
            patch("finishup.service.elevated_bootstrap.state_dir", return_value=consent_state),
            patch("finishup.cli.elevated._auto_unlock_store", return_value=store),
            patch.object(
                AutoUnlockPassphraseStore,
                "promote_staged_initialization",
                side_effect=OSKeyringError("ambiguous_write"),
            ),
        ):
            elevated.prepare_elevated("vault_initialize")
            pending = load_pending(_state=consent_state)
            assert pending is not None
            result = await asyncio.wait_for(
                elevated.authorize_elevated(_approve_attestation(pending)), timeout=30
            )

            # The vault committed and activated; the keyring hygiene failure does not turn a
            # completed operation into a failure.
            assert result["outcome"] == "completed"
            assert result["result"] == {"state": "ready", "reason": "succeeded"}
            assert daemon.status().vault_mode == "passphrase"
            assert (_SERVICE_NAME, staged_account) in backend.values
            assert (_SERVICE_NAME, active_account) not in backend.values
    finally:
        await daemon.stop()
        await asyncio.wait_for(serving, timeout=10)

    staged_secret = _entry_bytes(backend, staged_account)

    def bound_store(bundle: Path) -> AutoUnlockPassphraseStore:
        return _approved_store(Path(bundle), backend)

    restart_daemon: ServiceDaemon | None = None
    with patch.object(daemon_module, "AutoUnlockPassphraseStore", bound_store):
        restart_daemon = await _production_daemon(tmp_path, pristine=True)
        await restart_daemon.start()
    restart_serving = asyncio.create_task(restart_daemon.serve())
    try:
        # Startup tried the active slot (absent), proved the staged-initialization candidate
        # against the real envelope, and promoted exactly it.
        assert restart_daemon.status().vault_mode == "passphrase"
        assert cast(str, restart_daemon.status().state.value) == "ready"
        assert (_SERVICE_NAME, active_account) in backend.values
        assert (_SERVICE_NAME, staged_account) not in backend.values
        assert _entry_bytes(backend, active_account) == staged_secret
    finally:
        await restart_daemon.stop()
        await asyncio.wait_for(restart_serving, timeout=10)

    _assert_no_secret_bytes(tmp_path, staged_secret)
    _assert_no_secret_bytes(runtime_directory, staged_secret)
