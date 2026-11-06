"""``finishup server folders``: what a server may read outside the owner's projects (ADR-051).

``mode NAME local`` lets a remote target's server read outside the claimed project as FinishUP on
this computer would, so it needs the typed target name on the trusted console; ``mode NAME
listed`` is the way back and needs nothing. In ``listed`` mode the server reads only beneath the
folders listed for it: adding one needs the same typed confirmation and the input-root rule a
local service uses; removing it is the way out and needs nothing. ``list``, ``status`` (text and
JSON) and ``add`` show the mode. Refusals are fixed text with a closed reason and never echo the
folder.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from types import MappingProxyType, TracebackType
from typing import Self, cast

import pytest
from typer.testing import CliRunner, Result

from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.cli import server as server_cli
from finishup.cli import trusted_console
from finishup.client import targets
from finishup.client.server_folders import (
    FolderRecord,
    OutsideReads,
    add_folder,
    folders_path,
    read_folders,
    read_record,
    set_mode,
)
from finishup.config.paths import reset_selection_memo
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import validate_schema_instance

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


@pytest.mark.parametrize("command", ["", "add", "list", "remove", "mode"])
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
    # And, before consenting, what a server that breaks FinishUP's rules could still do there.
    notice = " ".join(line.strip() for line in shown)
    assert "does not bind a server that breaks FinishUP's rules" in notice
    assert "could read any other such file beneath this folder" in notice
    assert "list the names in its folders" in notice


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
    assert "could not be read" in cleared.stdout and "mode listed" in cleared.stdout
    # Replaced by an empty record in the 'listed' mode a damaged one stood for, never removed.
    assert read_record(root, record.target_id) == FolderRecord((), "listed")


def test_status_shows_the_folders_a_remote_target_may_read(
    remote: tuple[targets.ServerTarget, Path], folder: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.target_runtime import ProbeResult

    record, root = remote

    def unreachable(_record: targets.ServerTarget | None, _root: Path | None) -> ProbeResult:
        return ProbeResult("unavailable", reason="x")

    monkeypatch.setattr(server_cli, "_probe", unreachable)
    document = server_cli.build_status_document("lab")
    assert cast(dict[str, JsonValue], document["target"])["outside_reads"] == {
        "mode": "listed",
        "mode_source": "kind_default",
        "folders": [],
    }
    lines = server_cli.status_lines(document)
    assert (
        "Outside your projects: reads only folders you list (mode listed, the default for a web server)"
        in lines
    )
    assert "Folders it may read outside your projects: none" in lines
    add_folder(root, record.target_id, folder)
    document = server_cli.build_status_document("lab")
    validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, document))
    assert cast(dict[str, JsonValue], document["target"])["outside_reads"] == {
        "mode": "listed",
        "mode_source": "kind_default",
        "folders": [folder],
    }
    lines = server_cli.status_lines(document)
    at = lines.index("Folders it may read outside your projects:")
    assert lines[at + 1] == f"  {folder}"
    folders_path(root).chmod(0o644)
    unreadable = server_cli.build_status_document("lab")
    assert cast(dict[str, JsonValue], unreadable["target"])["outside_reads"] == {
        "mode": "listed",
        "mode_source": "unreadable",
        "folders": [],
    }
    assert any("cannot be read" in line for line in server_cli.status_lines(unreadable))
    # The everyday server has no folder record.
    local = server_cli.build_status_document("local")
    assert cast(dict[str, JsonValue], local["target"])["outside_reads"] is None
    assert not any("Outside your projects" in line for line in server_cli.status_lines(local))


# --- the outside-read mode -------------------------------------------------------------------


@pytest.fixture
def local_confirmed(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the trusted-console confirmations of mode local instead of opening /dev/tty."""

    seen: list[str] = []

    def confirm(record: targets.ServerTarget) -> None:
        seen.append(record.target_id)

    monkeypatch.setattr(server_cli, "_confirm_local_mode_on_trusted_console", confirm)
    return seen


def _ssh(home: Path) -> tuple[targets.ServerTarget, Path]:
    del home
    with targets.registry_lock():
        return targets.new_remote_target("devbox", "ssh", host="devbox.example", port=22)


def test_mode_local_needs_the_trusted_console_and_listed_is_the_way_back(
    remote: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = remote
    refused = _invoke("mode", "lab", "local")
    assert refused.exit_code == 2
    assert refused.stderr.startswith("trusted_console_required:")
    assert read_record(root, record.target_id) == FolderRecord()
    seen: list[str] = []

    def confirm(target: targets.ServerTarget) -> None:
        seen.append(target.target_id)

    monkeypatch.setattr(server_cli, "_confirm_local_mode_on_trusted_console", confirm)
    widened = _invoke("mode", "lab", "local")
    assert widened.exit_code == 0, widened.output
    assert seen == [record.target_id]
    assert "as FinishUP on this computer would (mode local)" in widened.stdout
    assert "'finishup server folders mode lab listed'" in widened.stdout
    assert read_record(root, record.target_id) == FolderRecord((), "local")
    again = _invoke("mode", "lab", "local")
    assert again.exit_code == 0 and "already in mode local" in again.stdout
    assert seen == [record.target_id]  # nothing to confirm again

    # The way back narrows, so it needs no console.
    def no_console(_target: targets.ServerTarget) -> None:
        raise AssertionError("listed asks for no confirmation")

    monkeypatch.setattr(server_cli, "_confirm_local_mode_on_trusted_console", no_console)
    narrowed = _invoke("mode", "lab", "listed")
    assert narrowed.exit_code == 0, narrowed.output
    assert "only beneath folders you list (mode listed)" in narrowed.stdout
    assert read_record(root, record.target_id) == FolderRecord((), "listed")
    listed = _invoke("list", "lab")
    assert "(mode listed, set by you)" in listed.stdout


def test_declining_mode_local_on_the_console_changes_nothing(
    remote: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
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
    result = _invoke("mode", "lab", "local")
    assert result.exit_code == 2
    assert result.stderr.startswith("authorization_declined:")
    assert read_record(root, record.target_id) == FolderRecord()
    notice = " ".join(line.strip() for line in shown)
    assert record.target_id in notice and "(mode local)" in notice
    assert "does not bind a server that breaks FinishUP's rules" in notice
    assert "could read any other such file on this computer" in notice
    assert "Undo it with 'finishup server folders mode lab listed'" in notice


def test_a_default_local_is_recorded_only_with_the_typed_name(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A recorded 'local' outlives any later change of default, so an agent's shell, which has
    no trusted console, never records it: the target keeps following its kind's default."""

    from finishup.client import server_folders

    record, root = _ssh(home)
    listed = _invoke("list", "devbox")
    assert "(mode local, the default for an SSH server)" in listed.stdout
    assert "'finishup server folders mode devbox listed'" in listed.stdout
    # No trusted console (stdin is not a terminal here): nothing is recorded, and it says so.
    result = _invoke("mode", "devbox", "local")
    assert result.exit_code == 0, result.output
    assert "already in mode local, the default for an SSH server" in result.stdout
    assert "nothing was recorded" in result.stdout
    assert read_record(root, record.target_id) == FolderRecord()
    assert not folders_path(root).exists()
    # So a later change of the kind's default still applies to it.
    with monkeypatch.context() as patched:
        patched.setattr(
            server_folders, "DEFAULT_OUTSIDE_READ_MODE", MappingProxyType({"ssh": "listed"})
        )
        assert server_folders.outside_reads_of(root, record) == OutsideReads(
            "listed", (), "kind_default"
        )
    # On the trusted console, the owner's typed name records it, and it outlives that change.
    seen: list[str] = []

    def confirm(target: targets.ServerTarget) -> None:
        seen.append(target.target_id)

    monkeypatch.setattr(server_cli, "_confirm_local_mode_on_trusted_console", confirm)
    recorded = _invoke("mode", "devbox", "local")
    assert recorded.exit_code == 0, recorded.output
    assert seen == [record.target_id]
    assert "stays in mode local, now set by you" in recorded.stdout
    assert "'finishup server folders mode devbox listed'" in recorded.stdout
    assert read_record(root, record.target_id) == FolderRecord((), "local")
    monkeypatch.setattr(
        server_folders, "DEFAULT_OUTSIDE_READ_MODE", MappingProxyType({"ssh": "listed"})
    )
    assert server_folders.outside_reads_of(root, record) == OutsideReads("local", (), "owner")


def test_declining_a_default_local_on_the_console_records_nothing(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = _ssh(home)

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

        def write(self, _text: str) -> None:
            return None

        def read_choice(self, _prompt: str, allowed: tuple[bytes, ...]) -> bytes:
            assert allowed == (b"devbox",)
            raise trusted_console.TrustedConsoleError("input_invalid")

    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", _Console)
    result = _invoke("mode", "devbox", "local")
    assert result.exit_code == 2
    assert result.stderr.startswith("authorization_declined:")
    assert read_record(root, record.target_id) == FolderRecord()


def test_a_default_listed_is_recorded_without_a_console(
    remote: tuple[targets.ServerTarget, Path],
) -> None:
    """Recording 'listed' narrows, so it needs no console, and it outlives a change of default."""

    record, root = remote
    result = _invoke("mode", "lab", "listed")
    assert result.exit_code == 0, result.output
    assert "stays in mode listed, now set by you" in result.stdout
    assert "'finishup server folders mode lab local'" in result.stdout
    assert read_record(root, record.target_id) == FolderRecord((), "listed")
    again = _invoke("mode", "lab", "listed")
    assert again.exit_code == 0 and "already in mode listed, set by you" in again.stdout


@pytest.mark.parametrize("value", ["open", "LOCAL", "", "unrestricted"])
def test_an_unknown_mode_is_refused_without_echoing_it(
    remote: tuple[targets.ServerTarget, Path], value: str
) -> None:
    record, root = remote
    result = _invoke("mode", "lab", value)
    assert result.exit_code == 2
    assert result.stderr.startswith("outside_read_mode_invalid:")
    assert "'local'" in result.stderr and "'listed'" in result.stderr
    if value:
        assert value not in result.stderr.split(":", 1)[1]
    assert read_record(root, record.target_id) == FolderRecord()


def test_mode_applies_only_to_a_remote_target_and_refuses_a_damaged_record(
    remote: tuple[targets.ServerTarget, Path], local_confirmed: list[str]
) -> None:
    record, root = remote
    with targets.registry_lock():
        targets.new_local_target("bench")
    for mode in ("local", "listed"):
        assert _invoke("mode", "bench", mode).stderr.startswith("folders_not_applicable:")
        assert _invoke("mode", "nowhere", mode).stderr.startswith("target_unknown:")
    folders_path(root).parent.mkdir(exist_ok=True)
    folders_path(root).write_text("{damaged\n")
    folders_path(root).chmod(0o600)
    for mode in ("local", "listed"):
        result = _invoke("mode", "lab", mode)
        assert result.exit_code == 20
        assert result.stderr.startswith("folders_record_invalid:")
        assert "--all" in result.stderr and "mode listed" in result.stderr
    assert local_confirmed == []
    # The way out: an empty record in mode listed, then local is chosen again on the console.
    assert _invoke("remove", "lab", "--all").exit_code == 0
    assert _invoke("mode", "lab", "local").exit_code == 0
    assert local_confirmed == [record.target_id]
    assert read_record(root, record.target_id) == FolderRecord((), "local")


def test_in_mode_local_list_add_and_remove_say_the_folders_wait_for_mode_listed(
    home: Path, folder: str, confirmed: list[tuple[str, str]]
) -> None:
    record, root = _ssh(home)
    added = _invoke("add", "devbox", folder)
    assert added.exit_code == 0, added.output
    assert confirmed == [(record.target_id, folder)]
    assert "It is in mode local" in added.stdout
    listed = _invoke("list", "devbox").stdout.splitlines()
    assert "Folders listed for it, read only in mode listed:" in listed
    assert f"  {folder}" in listed
    removed = _invoke("remove", "devbox", folder)
    assert removed.exit_code == 0, removed.output
    assert "no longer lists that folder" in removed.stdout
    assert "still reads as FinishUP on this computer would" in removed.stdout
    assert "'finishup server folders mode devbox listed'" in removed.stdout
    assert read_record(root, record.target_id) == FolderRecord()


def test_status_text_and_json_show_the_mode_and_its_origin(
    home: Path, folder: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.target_runtime import ProbeResult

    def unreachable(_record: targets.ServerTarget | None, _root: Path | None) -> ProbeResult:
        return ProbeResult("unavailable", reason="x")

    monkeypatch.setattr(server_cli, "_probe", unreachable)
    record, root = _ssh(home)
    add_folder(root, record.target_id, folder)
    document = server_cli.build_status_document("devbox")
    validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, document))
    assert cast(dict[str, JsonValue], document["target"])["outside_reads"] == {
        "mode": "local",
        "mode_source": "kind_default",
        "folders": [folder],
    }
    lines = server_cli.status_lines(document)
    assert (
        "Outside your projects: reads as FinishUP on this computer would (mode local, the default "
        "for an SSH server)"
    ) in lines
    at = lines.index("Folders listed for it, read only in mode listed:")
    assert lines[at + 1] == f"  {folder}"
    with targets.registry_lock():
        set_mode(root, record.target_id, "listed")
    document = server_cli.build_status_document("devbox")
    assert cast(dict[str, JsonValue], document["target"])["outside_reads"] == {
        "mode": "listed",
        "mode_source": "owner",
        "folders": [folder],
    }
    lines = server_cli.status_lines(document)
    assert "Outside your projects: reads only folders you list (mode listed, set by you)" in lines
    # Through the command: the JSON form carries it too (stdout is not a terminal here).
    result = _RUNNER.invoke(cli.app, ["server", "status", "devbox", "--json"])
    assert result.exit_code == 0, result.output
    shown = cast(dict[str, JsonValue], json.loads(result.stdout))
    assert cast(dict[str, JsonValue], shown["target"])["outside_reads"] == {
        "mode": "listed",
        "mode_source": "owner",
        "folders": [folder],
    }
