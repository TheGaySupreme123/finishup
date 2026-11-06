"""``finishup server folders``: the owner admits, lists and removes outside folders here (ADR-051).

Adding a folder lets a remote target's server read beneath it through this client's workspace
agent, so it needs the typed target name on the trusted console and the input-root rule a local
service uses; removing it is the way out and needs nothing; ``list`` and ``status`` show them.
Refusals are fixed text with a closed reason and never echo the folder.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Self, cast

import pytest
from typer.testing import CliRunner, Result

from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.cli import server as server_cli
from finishup.cli import trusted_console
from finishup.client import targets
from finishup.client.server_folders import add_folder, folders_path, read_folders
from finishup.config.paths import reset_selection_memo
from finishup.protocol.canonical import JsonValue

_RUNNER = CliRunner()


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def remote(home: Path) -> tuple[targets.ServerTarget, Path]:
    del home
    with targets.registry_lock():
        return targets.new_remote_target("lab", "https", base_url="https://lab.example")


@pytest.fixture
def folder(tmp_path: Path) -> str:
    shared = (tmp_path / "shared").resolve()
    shared.mkdir()
    return os.fspath(shared)


@pytest.fixture
def confirmed(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Record the trusted-console confirmations instead of opening /dev/tty."""

    seen: list[tuple[str, str]] = []

    def confirm(record: targets.ServerTarget, folder: str) -> None:
        seen.append((record.target_id, folder))

    monkeypatch.setattr(server_cli, "_confirm_folder_on_trusted_console", confirm)
    return seen


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, ["server", "folders", *arguments])


@pytest.mark.parametrize("command", ["", "add", "list", "remove"])
def test_every_folders_command_renders_its_help(home: Path, command: str) -> None:
    del home
    result = _RUNNER.invoke(
        cli.app, ["server", "folders", *([command] if command else []), "--help"]
    )
    assert result.exit_code == 0, result.output
    assert "Usage" in result.output


def test_adding_needs_the_trusted_console(
    remote: tuple[targets.ServerTarget, Path], folder: str
) -> None:
    record, root = remote
    result = _invoke("add", "lab", folder)
    assert result.exit_code == 2
    assert result.stderr.startswith("trusted_console_required:")
    assert folder not in result.stderr
    assert read_folders(root, record.target_id) == ()


def test_add_list_and_remove_are_a_reverse_pair(
    remote: tuple[targets.ServerTarget, Path], folder: str, confirmed: list[tuple[str, str]]
) -> None:
    record, root = remote
    added = _invoke("add", "lab", folder + "/")  # recorded in normal form
    assert added.exit_code == 0, added.output
    assert confirmed == [(record.target_id, folder)]
    assert read_folders(root, record.target_id) == (folder,)
    # Already admitted: nothing to confirm again.
    again = _invoke("add", "lab", folder)
    assert again.exit_code == 0 and "already" in again.stdout
    assert len(confirmed) == 1
    listed = _invoke("list", "lab")
    assert listed.exit_code == 0 and f"  {folder}" in listed.stdout.splitlines()
    removed = _invoke("remove", "lab", folder)
    assert removed.exit_code == 0 and "no longer read" in removed.stdout
    assert read_folders(root, record.target_id) == ()
    assert "may read no folder" in _invoke("list", "lab").stdout
    missing = _invoke("remove", "lab", folder)
    assert missing.exit_code == 0 and "No such folder" in missing.stdout


def test_declining_on_the_console_changes_nothing(
    remote: tuple[targets.ServerTarget, Path], folder: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = remote
    shown: list[str] = []

    class _Console:
        def __enter__(self) -> Self:
            return self

        def __exit__(
            self,
            _kind: type[BaseException] | None,
            _value: BaseException | None,
            _traceback: TracebackType | None,
        ) -> None:
            return None

        def write(self, text: str) -> None:
            shown.append(text)

        def read_choice(self, _prompt: str, allowed: tuple[bytes, ...]) -> bytes:
            assert allowed == (b"lab",)
            raise trusted_console.TrustedConsoleError("input_invalid")

    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", _Console)
    result = _invoke("add", "lab", folder)
    assert result.exit_code == 2
    assert result.stderr.startswith("authorization_declined:")
    assert read_folders(root, record.target_id) == ()
    # The owner saw which server and which folder, on the console only.
    assert any(record.target_id in line and "lab" in line for line in shown)
    assert f"  {folder}\n" in shown
    assert folder not in result.output


@pytest.mark.parametrize(
    "value",
    ["relative/folder", "/etc", "missing", "link", "hidden"],
)
def test_a_folder_the_input_root_rule_refuses_is_refused_before_asking(
    remote: tuple[targets.ServerTarget, Path],
    folder: str,
    tmp_path: Path,
    confirmed: list[tuple[str, str]],
    value: str,
) -> None:
    record, root = remote
    if value == "missing":
        value = os.fspath(tmp_path.resolve() / "missing")
    elif value == "link":
        link = tmp_path.resolve() / "link"
        link.symlink_to(folder)
        value = os.fspath(link)
    elif value == "hidden":
        hidden = tmp_path.resolve() / ".hidden"
        hidden.mkdir()
        value = os.fspath(hidden)
    result = _invoke("add", "lab", value)
    assert result.exit_code == 2
    assert result.stderr.startswith("folder_invalid:")
    assert value not in result.stderr
    assert confirmed == []
    assert read_folders(root, record.target_id) == ()


@pytest.mark.parametrize("which", ["home", "holds_home", "private"])
def test_a_folder_the_home_rules_refuse_is_refused_before_asking(
    remote: tuple[targets.ServerTarget, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    confirmed: list[tuple[str, str]],
    which: str,
) -> None:
    """The owner is never asked to consent to a folder that would then be refused."""

    record, root = remote
    user_home = (tmp_path / "users" / "me").resolve()
    (user_home / "Library" / "Mail").mkdir(parents=True)
    monkeypatch.setenv("HOME", os.fspath(user_home))
    value = {
        "home": user_home,
        "holds_home": user_home.parent,
        "private": user_home / "Library" / "Mail",
    }[which]
    result = _invoke("add", "lab", os.fspath(value))
    assert result.exit_code == 2
    assert result.stderr.startswith("folder_invalid:")
    assert os.fspath(value) not in result.output
    assert confirmed == []
    assert read_folders(root, record.target_id) == ()


def test_a_local_or_unknown_target_has_no_folders(
    home: Path, folder: str, confirmed: list[tuple[str, str]]
) -> None:
    del home
    with targets.registry_lock():
        targets.new_local_target("bench")
    for arguments in (("add", "bench", folder), ("list", "bench"), ("remove", "bench", folder)):
        result = _invoke(*arguments)
        assert result.exit_code == 2
        assert result.stderr.startswith("folders_not_applicable:")
    assert _invoke("list", "nowhere").stderr.startswith("target_unknown:")
    assert confirmed == []


def test_a_damaged_record_is_reported_and_remove_all_clears_it(
    remote: tuple[targets.ServerTarget, Path], folder: str
) -> None:
    record, root = remote
    add_folder(root, record.target_id, folder)
    folders_path(root).write_text("{damaged\n")
    for arguments in (("list", "lab"), ("remove", "lab", folder)):
        result = _invoke(*arguments)
        assert result.exit_code == 20
        assert result.stderr.startswith("folders_record_invalid:")
        assert "--all" in result.stderr
    usage = _invoke("remove", "lab")
    assert usage.exit_code == 2 and usage.stderr.startswith("usage:")
    cleared = _invoke("remove", "lab", "--all")
    assert cleared.exit_code == 0, cleared.output
    assert not folders_path(root).exists()
    assert read_folders(root, record.target_id) == ()


def test_status_shows_the_folders_a_remote_target_may_read(
    remote: tuple[targets.ServerTarget, Path], folder: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.target_runtime import ProbeResult

    record, root = remote

    def unreachable(_record: targets.ServerTarget | None, _root: Path | None) -> ProbeResult:
        return ProbeResult("unavailable", reason="x")

    monkeypatch.setattr(server_cli, "_probe", unreachable)
    document = server_cli.build_status_document("lab")
    assert server_cli.admitted_folder_lines(document) == (
        "Folders it may read outside your projects: none",
    )
    add_folder(root, record.target_id, folder)
    lines = server_cli.status_lines(document, server_cli.admitted_folder_lines(document))
    at = lines.index("Folders it may read outside your projects:")
    assert lines[at + 1] == f"  {folder}"
    # The JSON contract is unchanged: the record is shown to the owner, never sent anywhere.
    assert folder not in repr(cast(JsonValue, document))
    folders_path(root).chmod(0o644)
    assert "cannot be read" in server_cli.admitted_folder_lines(document)[0]
    # The everyday server has no folder record.
    local = server_cli.build_status_document("local")
    assert server_cli.admitted_folder_lines(local) == ()
