"""Absolute registrations require the current installation's byte-bound console script."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
from collections.abc import Iterator
from importlib.metadata import FileHash, PackagePath
from pathlib import Path

import anyio
import pytest

from finishup.adapters.integrations import codex_launcher
from finishup.adapters.integrations.codex_launcher import installed_launcher
from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter, CommandOutput
from finishup.application.applied_mcp_route import read_applied_route
from finishup.application.harness_mcp import HarnessMcpService, McpRegistrationConfirmation
from finishup.config.paths import PathSafetyError
from finishup.ports.harness_mcp import (
    HarnessBinary,
    McpRegistrationAction,
    McpRegistrationCommand,
    McpRegistrationError,
    McpRegistrationReason,
    McpRegistrationState,
)
from finishup.ports.integrations import HarnessId

_BINARY = HarnessBinary(HarnessId.CODEX, "/test/codex", "0.150.1", "supported")


@pytest.fixture
def private_root() -> Iterator[Path]:
    # The launcher gate deliberately refuses shared/writable ancestors, including /tmp.
    with tempfile.TemporaryDirectory(prefix=".yz654-", dir=Path.home()) as root:
        yield Path(root)


@pytest.fixture
def launcher(private_root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = private_root
    script = root / "finishup"
    raw = b"#!/test/python\nfrom finishup.cli.app import main\nmain()\n"
    script.write_bytes(raw)
    script.chmod(0o700)
    record = PackagePath("finishup")
    record.hash = FileHash(
        "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
    )
    record.size = len(raw)

    class Package:
        files = [record]

        def locate_file(self, path: PackagePath) -> Path:
            return root / path

    def package(_name: str) -> Package:
        return Package()

    def scripts(_name: str) -> str:
        return str(root)

    monkeypatch.setattr("finishup.adapters.integrations.codex_launcher.distribution", package)
    monkeypatch.setattr("finishup.adapters.integrations.codex_launcher.sysconfig.get_path", scripts)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: root)
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_launcher.read_runtime_pin", lambda: None
    )
    assert installed_launcher() is not None
    return script


def test_absolute_registration_is_owned(launcher: Path) -> None:
    entry = {
        "command": str(launcher),
        "args": ["mcp", "serve", "--host", "codex"],
        "env": {"FINISHUP_ISOLATED_ROOT": str(launcher.parent)},
    }
    adapter = CodexMcpAdapter(lambda _: CommandOutput(0, json.dumps(entry).encode()))
    observed = anyio.run(lambda: adapter.observe_registration(_BINARY))
    assert observed.state is McpRegistrationState.FINISHUP_OWNED
    assert observed.route_profile == "policy"
    assert observed.isolation_binding == "isolated_exact"


class Host:
    def __init__(self, entry: dict[str, object] | None = None) -> None:
        self.entry = entry
        self.mutations: list[tuple[str, ...]] = []

    def __call__(self, argv: tuple[str, ...]) -> CommandOutput:
        if argv[2] == "get":
            return (
                CommandOutput(1, b"")
                if self.entry is None
                else CommandOutput(0, json.dumps(self.entry).encode())
            )
        if argv[2] == "list":
            return CommandOutput(0, b"[]")
        self.mutations.append(argv)
        if argv[2] == "remove":
            self.entry = None
        else:
            index = argv.index("--")
            entry: dict[str, object] = {"command": argv[index + 1], "args": list(argv[index + 2 :])}
            self.entry = entry
            if "--env" in argv:
                key, value = argv[argv.index("--env") + 1].split("=", 1)
                self.entry["env"] = {key: value}
        return CommandOutput(0, b"")


def test_absolute_lifecycle_preserves_command_and_applied_route(launcher: Path) -> None:
    host = Host()
    adapter = CodexMcpAdapter(host)
    service = HarnessMcpService(adapter)
    preview = anyio.run(lambda: adapter.preview_registration(_BINARY))
    assert preview.action is McpRegistrationAction.REGISTER
    assert preview.serve_command == (str(launcher), "mcp", "serve", "--host", "codex")
    confirmation = McpRegistrationConfirmation(preview.preview_digest, True, "noninteractive_flag")
    result = anyio.run(
        lambda: service.register(_BINARY, confirmation, _state=launcher.parent / "store")
    )
    assert result.state_after is McpRegistrationState.FINISHUP_OWNED
    record = read_applied_route(_state=launcher.parent / "store")
    assert record is not None
    assert record["applied_serve_command"] == list(preview.serve_command)
    noop = anyio.run(lambda: adapter.preview_registration(_BINARY))
    assert noop.action is McpRegistrationAction.NOOP
    anyio.run(
        lambda: adapter.apply_registration(
            _BINARY, McpRegistrationCommand(noop.preview_digest, True)
        )
    )
    assert len(host.mutations) == 1
    strict = CodexMcpAdapter(host, route_profile="strict")
    changed = anyio.run(lambda: strict.preview_registration(_BINARY))
    assert changed.action is McpRegistrationAction.REREGISTER
    assert changed.serve_command[0] == str(launcher)
    anyio.run(
        lambda: strict.apply_registration(
            _BINARY, McpRegistrationCommand(changed.preview_digest, True)
        )
    )
    assert anyio.run(lambda: strict.observe_registration(_BINARY)).route_profile == "strict"
    remove = anyio.run(lambda: strict.preview_unregistration(_BINARY))
    assert remove.serve_command == changed.serve_command
    anyio.run(
        lambda: strict.apply_unregistration(
            _BINARY, McpRegistrationCommand(remove.preview_digest, True)
        )
    )
    assert anyio.run(lambda: strict.status_registration(_BINARY)) is McpRegistrationState.ABSENT
    assert (
        anyio.run(lambda: strict.preview_unregistration(_BINARY)).action
        is McpRegistrationAction.NOOP
    )


@pytest.mark.parametrize("legacy", [False, True])
def test_bare_compatibility_migrates_to_proven_absolute(launcher: Path, legacy: bool) -> None:
    host = Host(
        {"command": "finishup", "args": ["mcp", "serve"] + ([] if legacy else ["--host", "codex"])}
    )
    adapter = CodexMcpAdapter(host)
    assert (
        anyio.run(lambda: adapter.status_registration(_BINARY))
        is McpRegistrationState.FINISHUP_OWNED
    )
    preview = anyio.run(lambda: adapter.preview_registration(_BINARY))
    assert preview.action is McpRegistrationAction.REREGISTER
    assert preview.serve_command[0] == str(launcher)


@pytest.mark.parametrize(
    "change",
    [
        "modified",
        "symlink",
        "writable",
        "missing",
        "same_name",
        "arguments",
        "environment",
        "root",
        "cwd",
        "dual_transport",
        "disabled",
    ],
)
def test_unsafe_absolute_entries_are_preserved(launcher: Path, change: str) -> None:
    entry: dict[str, object] = {
        "command": str(launcher),
        "args": ["mcp", "serve", "--host", "codex"],
        "env": {"FINISHUP_ISOLATED_ROOT": str(launcher.parent)},
    }
    if change == "modified":
        launcher.write_bytes(b"#!/bin/sh\nexit 0\n")
    elif change == "symlink":
        other = launcher.with_name("original")
        launcher.rename(other)
        launcher.symlink_to(other)
    elif change == "writable":
        launcher.chmod(0o777)
    elif change == "missing":
        launcher.unlink()
    elif change == "same_name":
        other_dir = launcher.parent / "foreign"
        other_dir.mkdir()
        other = other_dir / "finishup"
        other.write_bytes(launcher.read_bytes())
        other.chmod(0o700)
        entry["command"] = str(other)
    elif change == "arguments":
        entry["args"] = ["mcp", "serve", "--host", "codex", "--extra"]
    elif change == "environment":
        entry["env"] = {"PYTHONPATH": "/other"}
    elif change == "root":
        entry["env"] = {"FINISHUP_ISOLATED_ROOT": str(launcher.parent / "other")}
    elif change == "cwd":
        entry["cwd"] = "/other"
    elif change == "dual_transport":
        entry["transport"] = dict(entry)
    elif change == "disabled":
        entry["enabled"] = False
    host = Host(entry)
    adapter = CodexMcpAdapter(host)
    assert (
        anyio.run(lambda: adapter.status_registration(_BINARY))
        is McpRegistrationState.FOREIGN_PRESENT
    )
    preview = anyio.run(lambda: adapter.preview_unregistration(_BINARY))
    with pytest.raises(McpRegistrationError):
        anyio.run(
            lambda: adapter.apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert host.mutations == []


@pytest.mark.parametrize("removal", [False, True])
def test_absolute_preview_rejects_route_drift(launcher: Path, removal: bool) -> None:
    host = Host({"command": str(launcher), "args": ["mcp", "serve", "--host", "codex"]})
    adapter = CodexMcpAdapter(host)
    preview_method = adapter.preview_unregistration if removal else adapter.preview_registration
    apply_method = adapter.apply_unregistration if removal else adapter.apply_registration
    preview = anyio.run(lambda: preview_method(_BINARY))
    assert host.entry is not None
    host.entry["args"] = ["mcp", "serve", "--host", "codex", "--semantic", "off"]
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: apply_method(_BINARY, McpRegistrationCommand(preview.preview_digest, True))
        )
    assert caught.value.reason is McpRegistrationReason.PREVIEW_STALE
    assert host.mutations == []


@pytest.mark.parametrize(
    "change", ["missing_hash", "unsupported_hash", "duplicate", "missing_entry", "size"]
)
def test_record_must_supply_unique_matching_identity(launcher: Path, change: str) -> None:
    package = codex_launcher.distribution("finishup")
    entries = package.files
    assert entries
    if change == "missing_hash":
        entries[0].hash = None
    elif change == "unsupported_hash":
        entries[0].hash = FileHash("md5=not-sha256")
    elif change == "duplicate":
        entries.append(entries[0])
    elif change == "missing_entry":
        entries.clear()
    else:
        entries[0].size = 1
    assert launcher.is_file()
    assert installed_launcher() is None


def test_invalid_runtime_pin_never_confers_ownership(
    launcher: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def invalid_pin() -> None:
        raise PathSafetyError("runtime_pin_invalid")

    monkeypatch.setattr(codex_launcher, "read_runtime_pin", invalid_pin)
    assert installed_launcher() is None
    host = Host({"command": str(launcher), "args": ["mcp", "serve", "--host", "codex"]})
    assert (
        anyio.run(lambda: CodexMcpAdapter(host).status_registration(_BINARY))
        is McpRegistrationState.FOREIGN_PRESENT
    )


def test_preview_binds_a_replaced_but_valid_installed_script(launcher: Path) -> None:
    host = Host()
    adapter = CodexMcpAdapter(host)
    preview = anyio.run(lambda: adapter.preview_registration(_BINARY))
    raw = launcher.read_bytes() + b"# new installation\n"
    launcher.write_bytes(raw)
    entries = codex_launcher.distribution("finishup").files
    assert entries
    entries[0].hash = FileHash(
        "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
    )
    entries[0].size = len(raw)
    assert installed_launcher() is not None
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: adapter.apply_registration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.PREVIEW_STALE
    assert host.mutations == []
