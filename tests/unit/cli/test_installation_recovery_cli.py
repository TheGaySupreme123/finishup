from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from typer.testing import CliRunner

from finishup.cli import app as cli
from finishup.cli.exits import exit_code_for
from finishup.cli.unlock import InstallationRecoveryImportResult
from finishup.ports.control import ControlError
from finishup.protocol.errors import PublicErrorCode
from finishup.service.confidential_protocol import InstallationRecoveryTarget
from finishup.service.installation_recovery import (
    InstallationRecoveryState,
    InstallationRecoveryStatus,
)


def _stub_config(*_args: object, **_kwargs: object) -> SimpleNamespace:
    """Bypass the strict loader, which refuses the unknown FINISHUP_* variables CI sets."""

    return SimpleNamespace(storage=SimpleNamespace(data_dir=None))


def test_recovery_cli_surface_and_target_envelopes_are_explicit() -> None:
    result = CliRunner().invoke(cli.app, ["service", "recovery", "--help"])
    assert result.exit_code == 0
    for command in ("status", "import", "export", "provision", "rotate", "revoke", "restore"):
        assert command in result.stdout

    provision = cast(
        InstallationRecoveryTarget,
        cli._installation_recovery_target(  # pyright: ignore[reportPrivateUsage]
            operation="provision",
            recovery_generation=1,
            set_mode="compact",
            secret_kind="generated_code",
        ),
    )
    rotate = cast(
        InstallationRecoveryTarget,
        cli._installation_recovery_target(  # pyright: ignore[reportPrivateUsage]
            operation="rotate",
            recovery_generation=2,
            set_mode="self_contained",
            secret_kind="argon2id_passphrase",
        ),
    )
    assert provision.target_envelope == "preserve"
    assert rotate.target_envelope == "passphrase"
    assert provision.confirmed_plan_digest == provision.plan_digest()
    assert rotate.confirmed_plan_digest == rotate.plan_digest()


@pytest.mark.anyio
async def test_recovery_commands_bound_store_status_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _Store:
        def status(self, **_kwargs: object) -> InstallationRecoveryStatus:
            raise OSError("private-path-detail")

    monkeypatch.setattr(cli, "_installation_recovery_store", lambda: _Store())
    operations = (
        lambda: cli._service_recovery_export(False),  # pyright: ignore[reportPrivateUsage]
        lambda: cli._service_recovery_create(  # pyright: ignore[reportPrivateUsage]
            "provision", "compact", "generated-code", False
        ),
        lambda: cli._service_recovery_create(  # pyright: ignore[reportPrivateUsage]
            "rotate", "compact", "generated-code", False
        ),
        lambda: cli._service_recovery_revoke(False),  # pyright: ignore[reportPrivateUsage]
        lambda: cli._service_recovery_restore(False),  # pyright: ignore[reportPrivateUsage]
    )

    for operation in operations:
        assert await operation() == exit_code_for(PublicErrorCode.STORAGE_CORRUPT)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "storage_corrupt: the installation recovery set could not be read"
    ] * len(operations)
    assert "private-path-detail" not in captured.err


@pytest.mark.anyio
async def test_recovery_commands_bound_store_metadata_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _Store:
        def status(self, **_kwargs: object) -> InstallationRecoveryStatus:
            return InstallationRecoveryStatus(
                InstallationRecoveryState.RECOVERY_MATERIAL_REQUIRED,
                "provisioned_recovery_available",
                4,
                ("compact",),
                None,
                "finishup service recovery restore",
            )

        def metadata(self, _generation: int) -> object:
            raise ValueError("private-metadata-detail")

    monkeypatch.setattr(cli, "_installation_recovery_store", lambda: _Store())

    assert await cli._service_recovery_revoke(False) == exit_code_for(  # pyright: ignore[reportPrivateUsage]
        PublicErrorCode.STORAGE_CORRUPT
    )
    assert await cli._service_recovery_restore(False) == exit_code_for(  # pyright: ignore[reportPrivateUsage]
        PublicErrorCode.STORAGE_CORRUPT
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "storage_corrupt: the installation recovery set could not be read",
        "storage_corrupt: the installation recovery set could not be read",
    ]
    assert "private-metadata-detail" not in captured.err


@pytest.mark.anyio
async def test_recovery_status_is_pathless_and_agent_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = tmp_path / "installation-state.json"
    marker.write_text("structural", encoding="utf-8")
    canary_path = "/" + "Users/canary/secret/recovery.yirs"

    class _Store:
        def status(self, **_kwargs: object) -> InstallationRecoveryStatus:
            return InstallationRecoveryStatus(
                InstallationRecoveryState.RECOVERY_MATERIAL_REQUIRED,
                "provisioned_recovery_available",
                4,
                ("self_contained",),
                None,
                "finishup service recovery restore",
            )

    async def _unavailable() -> object:
        raise ControlError("service_unavailable")

    def _bundle_root(*, _data_dir: Path | None = None) -> Path:
        del _data_dir
        return tmp_path

    monkeypatch.setattr(cli, "_installation_recovery_store", lambda: _Store())
    monkeypatch.setattr(cli, "build_service_client", _unavailable)
    monkeypatch.setattr("finishup.config.paths.bundle_root", _bundle_root)
    # Keep inherited configuration out of this status-only test.
    # Status reporting is what is under test here, not configuration resolution.
    monkeypatch.setattr("finishup.config.load.load_config", _stub_config)

    assert await cli._service_recovery_status(True) == 0  # pyright: ignore[reportPrivateUsage]
    report = json.loads(capsys.readouterr().out)
    assert report["state"] == "recovery_material_required"
    assert report["next_command"] == "finishup service recovery restore"
    encoded = json.dumps(report)
    assert canary_path not in encoded
    assert "secret" not in encoded


@pytest.mark.anyio
async def test_clean_profile_restore_stops_after_the_offline_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installing the snapshot and running the ceremony cannot happen in one invocation.

    The snapshot install holds the daemon's singleton exclusion, so it only runs while the
    service is stopped, and the CLI never starts a service. Opening the ceremony straight
    afterwards therefore dialled a socket that by construction had nobody listening.
    """

    from finishup.cli import unlock as unlock_module

    bundle = tmp_path / "bundle"
    bundle.mkdir(mode=0o700)
    installed: list[int] = []
    written: list[str] = []

    class _Terminal:
        def __enter__(self) -> _Terminal:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def write(self, value: str) -> None:
            written.append(value)

    class _Lease:
        def __init__(self, _path: Path) -> None:
            self.entered = False

        def __enter__(self) -> _Lease:
            self.entered = True
            leases.append(self)
            return self

        def __exit__(self, *_args: object) -> None:
            self.released = True

    class _Store:
        def __init__(self, _root: Path) -> None:
            pass

        def install_snapshot_into_pristine(self, generation: int) -> str:
            installed.append(generation)
            return "sha256:" + "e" * 64

    leases: list[_Lease] = []

    async def _forbidden_ceremony(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the daemon is stopped; no ceremony may be opened here")

    monkeypatch.setattr(unlock_module, "_ForegroundTerminal", _Terminal)
    monkeypatch.setattr(unlock_module, "run_human_ceremony", _forbidden_ceremony)
    monkeypatch.setattr(
        "finishup.service.installation_recovery.OfflineInstallationRecoveryLease", _Lease
    )
    monkeypatch.setattr(
        "finishup.service.installation_recovery.InstallationRecoverySetStore", _Store
    )
    monkeypatch.setattr("finishup.config.load.load_config", _stub_config)

    def _bundle_root(*, _data_dir: Path | None = None) -> Path:
        del _data_dir
        return bundle

    def _state_dir() -> Path:
        return tmp_path / "state"

    monkeypatch.setattr("finishup.config.paths.bundle_root", _bundle_root)
    monkeypatch.setattr("finishup.config.paths.state_dir", _state_dir)

    target = cli._installation_recovery_target(  # pyright: ignore[reportPrivateUsage]
        operation="restore",
        recovery_generation=4,
        set_mode="self_contained",
        secret_kind="argon2id_passphrase",
    )
    result = await unlock_module.restore_installation_recovery(cast(Any, target))

    assert installed == [4]
    assert leases and leases[0].entered
    # The offline phase reports its own structural outcome, never a ceremony result.
    assert type(result) is InstallationRecoveryImportResult
    assert result.outcome == "snapshot_installed"
    assert result.recovery_generation == 4
    assert result.next_command == "finishup service run"
    # The operator is told both halves: start the service, then run restore again.
    instruction = "".join(written)
    assert "finishup service run" in instruction
    assert "finishup service recovery restore" in instruction
