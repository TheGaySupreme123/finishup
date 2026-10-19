from __future__ import annotations

import json
import os
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import finishup.cli.app as module
import finishup.cli.unlock as unlock_module


class _Client:
    def __init__(self, *, state: str, reason: str, vault_mode: str = "passphrase") -> None:
        self._status = SimpleNamespace(
            state=SimpleNamespace(value=state),
            state_reason=reason,
            vault_mode=vault_mode,
        )
        self.closed = False

    async def service_status(self) -> Any:
        return self._status

    async def close(self) -> None:
        self.closed = True


class _Store:
    custody = "platform_store"

    def __init__(
        self,
        secret: bytearray | None,
        reason: str,
        *,
        staged_initialization: str = "absent",
    ) -> None:
        self.secret = secret
        self.reason = reason
        self.saved: bytes | None = None
        self.staged_initialization = staged_initialization
        self.discarded = 0

    def load_with_reason(self) -> tuple[bytearray | None, str]:
        return self.secret, self.reason

    def slot_report(self) -> dict[str, str]:
        if self.reason == "auto_unlock_backend_unavailable":
            return {
                "active": "unavailable",
                "staged_initialization": "unavailable",
                "staged_rotation": "unavailable",
            }
        return {
            "active": "present" if self.secret is not None else "absent",
            "staged_initialization": self.staged_initialization,
            "staged_rotation": "absent",
        }

    def discard_staged_initialization(self) -> None:
        self.staged_initialization = "absent"
        self.discarded += 1

    @contextmanager
    def staged_initialization_guard(self) -> Generator[None]:
        self.guard_acquisitions = getattr(self, "guard_acquisitions", 0) + 1
        yield

    def save(self, value: bytearray) -> None:
        self.saved = bytes(value)


def test_auto_unlock_store_uses_daemon_environment_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import finishup.adapters.keys.os_keyring as keyring_module
    import finishup.config.load as config_module
    import finishup.config.paths as paths_module

    selected = tmp_path / "environment-selected-data"
    sentinel = object()
    seen: dict[str, object] = {}
    monkeypatch.setenv("FINISHUP_STORAGE_DATA_DIR", str(selected))

    def fake_load(overrides: object, env: object, config_path: object) -> SimpleNamespace:
        seen["overrides"] = overrides
        seen["env"] = env
        seen["config_path"] = config_path
        return SimpleNamespace(storage=SimpleNamespace(data_dir=selected))

    def fake_bundle_root(*, _data_dir: Path | None = None) -> Path:
        seen["data_dir"] = _data_dir
        return selected.resolve()

    def fake_store(bundle: Path) -> object:
        seen["bundle"] = bundle
        return sentinel

    monkeypatch.setattr(config_module, "load_config", fake_load)
    monkeypatch.setattr(paths_module, "bundle_root", fake_bundle_root)
    monkeypatch.setattr(keyring_module, "AutoUnlockPassphraseStore", fake_store)

    assert module._auto_unlock_store() is sentinel  # pyright: ignore[reportPrivateUsage]
    assert seen["env"] is os.environ
    assert seen["data_dir"] == selected
    assert seen["bundle"] == selected.resolve()


@pytest.mark.anyio
async def test_auto_unlock_status_reports_service_verified_stale_without_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = bytearray(b"a" * 48)
    store = _Store(secret, "none")
    client = _Client(state="locked", reason="auto_unlock_stale")
    monkeypatch.setattr(module, "_auto_unlock_store", lambda: store)
    monkeypatch.setattr(module, "build_service_client", lambda: _async_value(client))

    assert (
        await module._service_auto_unlock_status(  # pyright: ignore[reportPrivateUsage]
            True
        )
        == 20
    )

    report = json.loads(capsys.readouterr().out)
    assert report == {
        "custody": "platform_store",
        "next_command": "finishup service auto-unlock repair",
        "schema": "yoetz.auto-unlock-status/2",
        "service_state": "locked",
        "service_state_reason": "auto_unlock_stale",
        "slots": {
            "active": "present",
            "staged_initialization": "absent",
            "staged_rotation": "absent",
        },
        "state": "stale",
        "vault_mode": "passphrase",
    }
    assert secret == bytearray(len(secret))
    assert client.closed


@pytest.mark.anyio
async def test_auto_unlock_status_prioritizes_service_rejection(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store = _Store(bytearray(b"a" * 48), "none")
    client = _Client(state="locked", reason="auto_unlock_rejected")
    monkeypatch.setattr(module, "_auto_unlock_store", lambda: store)
    monkeypatch.setattr(module, "build_service_client", lambda: _async_value(client))

    assert (
        await module._service_auto_unlock_status(  # pyright: ignore[reportPrivateUsage]
            True
        )
        == 20
    )

    report = json.loads(capsys.readouterr().out)
    assert report["state"] == "rejected"
    assert report["next_command"] == "finishup service auto-unlock repair"


@pytest.mark.anyio
async def test_auto_unlock_status_reports_initialization_orphan_with_repair_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#511: a staged entry beside an uninitialized vault is a typed, repairable orphan."""

    store = _Store(None, "auto_unlock_absent", staged_initialization="present")
    client = _Client(state="locked", reason="none", vault_mode="uninitialized")
    monkeypatch.setattr(module, "_auto_unlock_store", lambda: store)
    monkeypatch.setattr(module, "build_service_client", lambda: _async_value(client))

    assert (
        await module._service_auto_unlock_status(  # pyright: ignore[reportPrivateUsage]
            True
        )
        == 20
    )

    report = json.loads(capsys.readouterr().out)
    assert report["state"] == "initialization_orphaned"
    assert report["slots"]["staged_initialization"] == "present"
    assert report["next_command"] == "finishup service auto-unlock repair"


@pytest.mark.anyio
async def test_auto_unlock_status_reports_unreconciled_staged_initialization(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#511: with a committed vault the staged entry waits for proof-based reconciliation."""

    store = _Store(None, "auto_unlock_absent", staged_initialization="present")
    client = _Client(state="locked", reason="passphrase_required", vault_mode="passphrase")
    monkeypatch.setattr(module, "_auto_unlock_store", lambda: store)
    monkeypatch.setattr(module, "build_service_client", lambda: _async_value(client))

    assert (
        await module._service_auto_unlock_status(  # pyright: ignore[reportPrivateUsage]
            True
        )
        == 20
    )

    report = json.loads(capsys.readouterr().out)
    assert report["state"] == "initialization_unreconciled"
    assert report["next_command"] == "finishup service restart"


@pytest.mark.anyio
async def test_auto_unlock_status_distinguishes_pre_existing_unadoptable_entry(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#511: an active entry beside an uninitialized vault is named, not called provisioned."""

    store = _Store(bytearray(b"a" * 48), "none")
    client = _Client(state="locked", reason="none", vault_mode="uninitialized")
    monkeypatch.setattr(module, "_auto_unlock_store", lambda: store)
    monkeypatch.setattr(module, "build_service_client", lambda: _async_value(client))

    assert (
        await module._service_auto_unlock_status(  # pyright: ignore[reportPrivateUsage]
            True
        )
        == 20
    )

    report = json.loads(capsys.readouterr().out)
    assert report["state"] == "pre_existing_unadoptable"
    assert report["next_command"] is None


@pytest.mark.anyio
async def test_auto_unlock_repair_discards_initialization_orphan_with_proof(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#511: repair removes the orphan only because the service proved no envelope exists."""

    store = _Store(None, "auto_unlock_absent", staged_initialization="present")
    client = _Client(state="locked", reason="none", vault_mode="uninitialized")
    monkeypatch.setattr(module, "_auto_unlock_store", lambda: store)
    monkeypatch.setattr(module, "build_service_client", lambda: _async_value(client))

    assert (
        await module._service_auto_unlock_repair(  # pyright: ignore[reportPrivateUsage]
            True
        )
        == 0
    )

    report = json.loads(capsys.readouterr().out)
    assert report["outcome"] == "initialization_orphan_cleared"
    assert report["next_command"] == "finishup consent prepare vault_initialize"
    assert store.discarded == 1
    assert store.guard_acquisitions == 1, "discard must happen under the exclusive guard"
    assert client.closed


@pytest.mark.anyio
async def test_auto_unlock_repair_refuses_orphan_discard_when_reproof_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#511 review: the vault state is re-proven under the guard; a change refuses deletion."""

    store = _Store(None, "auto_unlock_absent", staged_initialization="present")
    first = _Client(state="locked", reason="none", vault_mode="uninitialized")
    second = _Client(state="unlocking", reason="none", vault_mode="uninitialized")
    clients = iter([first, second])
    monkeypatch.setattr(module, "_auto_unlock_store", lambda: store)
    monkeypatch.setattr(module, "build_service_client", lambda: _async_value(next(clients)))

    assert (
        await module._service_auto_unlock_repair(  # pyright: ignore[reportPrivateUsage]
            True
        )
        == 20
    )

    assert "auto_unlock_repair_unproven" in capsys.readouterr().err
    assert store.discarded == 0


@pytest.mark.anyio
async def test_auto_unlock_repair_proves_passphrase_before_saving_and_wipes_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    passphrase = bytearray("correct horse 🔐 battery staple".encode())
    original = bytes(passphrase)
    store = _Store(None, "auto_unlock_absent")
    client = _Client(state="locked", reason="passphrase_required")
    supplied: list[bytes] = []

    async def unlock(value: bytearray | None = None) -> Any:
        supplied.append(bytes(value or b""))
        return SimpleNamespace(state="ready")

    monkeypatch.setattr(module, "_auto_unlock_store", lambda: store)
    monkeypatch.setattr(module, "build_service_client", lambda: _async_value(client))
    monkeypatch.setattr(unlock_module, "read_vault_passphrase_for_auto_unlock", lambda: passphrase)
    monkeypatch.setattr(unlock_module, "unlock_vault", unlock)

    assert (
        await module._service_auto_unlock_repair(  # pyright: ignore[reportPrivateUsage]
            True
        )
        == 0
    )

    report = json.loads(capsys.readouterr().out)
    assert report["outcome"] == "repaired"
    assert supplied == [original]
    assert store.saved == original
    assert passphrase == bytearray(len(passphrase))
    assert client.closed


@pytest.mark.anyio
async def test_auto_unlock_repair_names_the_missing_trusted_tty_instead_of_bad_input(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No console FinishUP owns is an environment fact; 'invalid input' sent operators hunting."""

    client = _Client(state="locked", reason="passphrase_required")

    def no_tty() -> bytearray:
        raise unlock_module.HumanCeremonyCliError("trusted_console_required")

    monkeypatch.setattr(module, "build_service_client", lambda: _async_value(client))
    monkeypatch.setattr(unlock_module, "read_vault_passphrase_for_auto_unlock", no_tty)

    assert (
        await module._service_auto_unlock_repair(  # pyright: ignore[reportPrivateUsage]
            True
        )
        == 2
    )
    captured = capsys.readouterr().err
    assert captured.startswith("trusted_console_required: ")
    assert "foreground terminal" in captured
    assert "invalid_request" not in captured


def test_foreground_terminal_accepts_macos_controlling_tty_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A macOS /dev/tty alias may be root-owned and device-distinct from stdio."""

    opened: list[int] = []
    closed: list[int] = []

    def fake_open(_path: str, _flags: int) -> int:
        opened.append(9)
        return 9

    def fake_close(fd: int) -> None:
        closed.append(fd)

    def fake_fstat(fd: int) -> SimpleNamespace:
        if fd in {0, 2}:
            return SimpleNamespace(st_rdev=101, st_uid=501)
        assert fd == 9
        return SimpleNamespace(st_rdev=202, st_uid=0)

    def fake_isatty(_fd: int) -> bool:
        return True

    def fake_tcgetpgrp(_fd: int) -> int:
        return 41

    import finishup.cli.trusted_console as console_module

    monkeypatch.setattr(console_module.os, "isatty", fake_isatty)
    monkeypatch.setattr(console_module.os, "open", fake_open)
    monkeypatch.setattr(console_module.os, "close", fake_close)
    monkeypatch.setattr(console_module.os, "fstat", fake_fstat)
    monkeypatch.setattr(console_module.os, "tcgetpgrp", fake_tcgetpgrp)
    monkeypatch.setattr(console_module.os, "getpgrp", lambda: 41)

    terminal = unlock_module._ForegroundTerminal()  # pyright: ignore[reportPrivateUsage]
    with terminal:
        assert opened == [9]

    assert opened == [9]
    assert closed == [9]


@pytest.mark.anyio
async def test_unlock_vault_prefers_scoped_platform_entry_without_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = bytearray(b"correct horse battery staple!!")
    seen: list[bytearray | None] = []

    async def ceremony(
        kind: object,
        target: object,
        passphrase: bytearray | None = None,
        **_kwargs: object,
    ) -> Any:
        del kind, target
        seen.append(None if passphrase is None else bytearray(passphrase))
        return SimpleNamespace(state="ready")

    async def not_stale() -> bool:
        return False

    monkeypatch.setattr(unlock_module, "_service_reports_unusable_auto_unlock", not_stale)
    monkeypatch.setattr(
        unlock_module,
        "_load_scoped_auto_unlock_passphrase",
        lambda: secret,
    )
    monkeypatch.setattr(unlock_module, "run_human_ceremony", ceremony)

    result = await unlock_module.unlock_vault()
    assert result.state == "ready"
    assert seen == [bytearray(b"correct horse battery staple!!")]


@pytest.mark.anyio
async def test_unlock_vault_falls_back_to_interactive_when_store_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[bool] = []

    async def ceremony(
        kind: object,
        target: object,
        passphrase: bytearray | None = None,
        **_kwargs: object,
    ) -> Any:
        del kind, target
        seen.append(passphrase is None)
        return SimpleNamespace(state="ready")

    async def not_stale() -> bool:
        return False

    monkeypatch.setattr(unlock_module, "_service_reports_unusable_auto_unlock", not_stale)
    monkeypatch.setattr(unlock_module, "_load_scoped_auto_unlock_passphrase", lambda: None)
    monkeypatch.setattr(unlock_module, "run_human_ceremony", ceremony)

    result = await unlock_module.unlock_vault()
    assert result.state == "ready"
    assert seen == [True]


@pytest.mark.anyio
async def test_unlock_vault_falls_back_when_silent_ceremony_stays_locked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = bytearray(b"correct horse battery staple!!")
    seen: list[bool] = []
    calls = 0

    async def ceremony(
        kind: object,
        target: object,
        passphrase: bytearray | None = None,
        **_kwargs: object,
    ) -> Any:
        del kind, target
        nonlocal calls
        calls += 1
        seen.append(passphrase is None)
        if calls == 1:
            return SimpleNamespace(state="locked")
        return SimpleNamespace(state="ready")

    async def not_stale() -> bool:
        return False

    monkeypatch.setattr(unlock_module, "_service_reports_unusable_auto_unlock", not_stale)
    monkeypatch.setattr(unlock_module, "_load_scoped_auto_unlock_passphrase", lambda: secret)
    monkeypatch.setattr(unlock_module, "run_human_ceremony", ceremony)

    result = await unlock_module.unlock_vault()
    assert result.state == "ready"
    assert seen == [False, True]


@pytest.mark.anyio
async def test_unlock_vault_skips_stored_entry_when_service_reports_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[bool] = []
    loads = 0

    async def ceremony(
        kind: object,
        target: object,
        passphrase: bytearray | None = None,
        **_kwargs: object,
    ) -> Any:
        del kind, target
        seen.append(passphrase is None)
        return SimpleNamespace(state="ready")

    async def stale() -> bool:
        return True

    def load() -> bytearray | None:
        nonlocal loads
        loads += 1
        return bytearray(b"correct horse battery staple!!")

    monkeypatch.setattr(unlock_module, "_service_reports_unusable_auto_unlock", stale)
    monkeypatch.setattr(unlock_module, "_load_scoped_auto_unlock_passphrase", load)
    monkeypatch.setattr(unlock_module, "run_human_ceremony", ceremony)

    result = await unlock_module.unlock_vault()
    assert result.state == "ready"
    assert loads == 0
    assert seen == [True]


async def _async_value(value: Any) -> Any:
    return value
