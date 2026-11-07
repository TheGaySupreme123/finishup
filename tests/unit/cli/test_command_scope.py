"""Every CLI and terminal command has one scope, and server-host commands refuse remote targets.

ADR-051 (design section 2): ``any``, ``server_host``, or ``client_only``. The table in
``finishup.cli.command_scope`` has no default, so a new command fails here until it is classified.
The cut-line ledger's ``server_host_only`` crossings must be reached only from ``server_host``
commands; a crossing that sits directly in a command callback must name that command.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from tests.unit.architecture.client_server_ledger import LEDGER
from typer.testing import CliRunner

from finishup.cli import app as cli
from finishup.cli import command_scope
from finishup.cli.command_scope import (
    COMMAND_SCOPES,
    TUI_COMMAND_SCOPES,
    ServerHostRequired,
    ServerTargetUnreadable,
    iter_command_paths,
    require_server_host,
)
from finishup.cli.command_scope import (
    command_scope as scope_of,
)
from finishup.client.targets import ServerTarget
from finishup.tui.commands import SLASH_COMMANDS


def _paths() -> dict[str, Callable[..., Any]]:
    commands: dict[str, Callable[..., Any]] = {}
    for path, info in iter_command_paths(cli.app):
        assert info.callback is not None, path
        commands[path] = info.callback
    return commands


def _remote_record() -> ServerTarget:
    return ServerTarget(
        "t_0a1b2c3d",
        "lab-box",
        "ssh",
        "2026-11-05T12:00:00.000Z",
        user="owner",
        host="lab.example",
        port=22,
        claim_salt="A" * 43 + "=",
        authorized_at="2026-11-05T12:00:00.000Z",
        disclosure_version=1,
    )


def test_every_cli_command_has_a_scope() -> None:
    unclassified: list[str] = []
    for path in _paths():
        try:
            scope_of(path)
        except KeyError:
            unclassified.append(path)
    assert unclassified == []


def test_every_scope_rule_names_a_real_command() -> None:
    paths = tuple(_paths())
    stale = [
        key for key in COMMAND_SCOPES if not any(p == key or p.startswith(f"{key} ") for p in paths)
    ]
    assert stale == []


def test_every_slash_command_has_a_scope_and_no_other_is_listed() -> None:
    assert {command.name for command in SLASH_COMMANDS} == set(TUI_COMMAND_SCOPES)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("service run", "server_host"),
        ("service unlock", "server_host"),
        ("service start", "server_host"),
        ("service endpoint", "server_host"),
        ("service status", "any"),
        ("service stop", "any"),
        ("setup vault", "server_host"),
        ("provider status", "server_host"),
        ("ai key", "server_host"),
        ("recommend list", "server_host"),
        ("privacy setup", "server_host"),
        ("privacy show", "any"),
        ("observe status", "any"),
        ("observe grant", "any"),
        ("observe checks trust", "any"),
        ("backup preview", "server_host"),
        ("consent authorize", "server_host"),
        ("integrate skill install", "server_host"),
        ("integrate mcp install", "client_only"),
        ("integrate plugin install", "client_only"),
        ("setup disconnect", "client_only"),
        ("server use", "client_only"),
        ("server folders add", "client_only"),
        ("server folders list", "client_only"),
        ("server folders remove", "client_only"),
        ("hooks claude-observe", "any"),
        ("mcp serve", "any"),
        ("start", "any"),
        ("check", "any"),
        ("receipt", "any"),
    ],
)
def test_design_table_spot_checks(path: str, expected: str) -> None:
    assert path in _paths()
    assert scope_of(path) == expected


def test_server_host_only_crossings_are_reached_only_from_server_host_commands() -> None:
    paths = _paths()
    by_callback: dict[tuple[str, str], set[str]] = {}
    for path, callback in paths.items():
        original = inspect.unwrap(callback)
        key = (original.__module__, original.__qualname__.split(".")[0])
        by_callback.setdefault(key, set()).add(path)
    for entry in LEDGER:
        if entry.disposition != "server_host_only":
            continue
        for command in entry.commands:
            if command.startswith("/"):
                assert TUI_COMMAND_SCOPES[command[1:]] == "server_host", entry
            else:
                assert command in paths, (entry, command)
                assert scope_of(command) == "server_host", (entry, command)
        direct = by_callback.get((entry.importer, entry.scope.split(".")[0]), set())
        assert direct <= set(entry.commands), (entry, direct)


def test_every_server_host_callback_is_guarded_and_no_other_is() -> None:
    for path, callback in _paths().items():
        guarded = bool(getattr(callback, "__finishup_server_host_guard__", False))
        assert guarded is (scope_of(path) == "server_host"), path


def test_guarded_callbacks_keep_their_signature() -> None:
    callback = _paths()["service endpoint"]
    assert "json_output" in inspect.signature(callback).parameters


def test_require_server_host_passes_on_a_local_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("finishup.client.targets.active_target_record", lambda: None)
    require_server_host("service run")
    require_server_host("/observe")


def test_require_server_host_refuses_a_remote_target(monkeypatch: pytest.MonkeyPatch) -> None:
    record = _remote_record()
    monkeypatch.setattr("finishup.client.targets.active_target_record", lambda: record)
    with pytest.raises(ServerHostRequired) as raised:
        require_server_host("service run")
    assert raised.value.target_id == "t_0a1b2c3d"
    assert raised.value.kind == "ssh"
    with pytest.raises(ServerHostRequired):
        require_server_host("/privacy")
    # ``any`` and ``client_only`` commands are never refused.
    require_server_host("status")
    require_server_host("server use")
    require_server_host("/server")


def test_observe_commands_run_on_the_client_of_a_remote_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client's observation store is the remote target's authority (ADR-051 decision 12)."""

    record = _remote_record()
    monkeypatch.setattr("finishup.client.targets.active_target_record", lambda: record)
    observe = [path for path in _paths() if path.split()[0] == "observe"]
    assert observe
    for path in observe:
        require_server_host(path)
    require_server_host("/observe")
    assert TUI_COMMAND_SCOPES["observe"] == "any"
    assert not any(
        entry.disposition == "server_host_only"
        and any(command.split()[0] in {"observe", "/observe"} for command in entry.commands)
        for entry in LEDGER
    )


def test_a_guarded_command_refuses_before_running_with_no_owner_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _remote_record()
    monkeypatch.setattr("finishup.client.targets.active_target_record", lambda: record)
    result = CliRunner().invoke(cli.app, ["service", "endpoint", "--json"])
    assert result.exit_code == 2
    assert "requires_server_host" in result.stderr
    assert "t_0a1b2c3d" in result.stderr
    assert "lab-box" not in result.output + result.stderr
    assert "lab.example" not in result.output + result.stderr
    assert result.stdout == ""


def test_a_refused_input_root_says_where_it_runs_and_what_that_means_for_a_remote_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``privacy input-roots`` admits a folder on the server host, which must exist there: the
    refusal says so in fixed words, and names the client's own way in for a folder on this
    computer, 'server folders add' (ADR-051 decision 5, 2026-11-07). Other commands keep their
    line."""

    record = _remote_record()
    monkeypatch.setattr("finishup.client.targets.active_target_record", lambda: record)
    result = CliRunner().invoke(cli.app, ["privacy", "input-roots", "add", "/srv/specs"])
    assert result.exit_code == 2
    assert "requires_server_host" in result.stderr
    assert "run it on the server host" in result.stderr
    assert "the folder must exist there" in result.stderr
    assert "list it for that server here with 'finishup server folders add NAME FOLDER'" in (
        result.stderr
    )
    assert "/srv/specs" not in result.output + result.stderr
    other = CliRunner().invoke(cli.app, ["service", "endpoint", "--json"])
    assert "must exist there" not in other.stderr


def test_root_wizard_flags_refuse_a_remote_target(monkeypatch: pytest.MonkeyPatch) -> None:
    record = _remote_record()
    monkeypatch.setattr("finishup.client.targets.active_target_record", lambda: record)
    for flag in ("--privacy", "--set"):
        result = CliRunner().invoke(cli.app, [flag])
        assert result.exit_code == 2, flag
        assert "requires_server_host" in result.stderr


def test_a_guarded_command_runs_unchanged_on_a_local_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("finishup.client.targets.active_target_record", lambda: None)
    result = CliRunner().invoke(cli.app, ["service", "endpoint", "--json"])
    assert result.exit_code == 0, result.output
    report = cast(dict[str, object], json.loads(result.stdout))
    assert report["schema"] == "yoetz.service-endpoint/1"
    assert str(report["endpoint"]).endswith("/control.sock")


def test_an_unresolvable_root_is_left_to_the_command(monkeypatch: pytest.MonkeyPatch) -> None:
    from finishup.client.targets import TargetError

    def broken() -> None:
        raise TargetError("target_root_unsafe")

    monkeypatch.setattr("finishup.client.targets.active_target_record", broken)
    require_server_host("service run")
    assert command_scope.REQUIRES_SERVER_HOST == "requires_server_host"


@pytest.fixture
def selected_ssh_target(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A real selected ``ssh`` target in an owner-only ambient home; yields its ``target.json``."""

    from builders.server_targets import ambient_home
    from finishup.client import targets

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab", "ssh", user="owner", host="lab.example", port=22
            )
        targets.write_selection(record)
        yield root / "target.json"


def _shared_mode(record: Path) -> None:
    record.chmod(0o644)


def _newer_release_field(record: Path) -> None:
    record.write_bytes(record.read_bytes().replace(b'{"', b'{"added_later":1,"', 1))


@pytest.mark.parametrize(
    ("damage", "reason"),
    [(_shared_mode, "target_root_unsafe"), (_newer_release_field, "target_record_invalid")],
)
def test_an_unreadable_target_record_fails_closed(
    selected_ssh_target: Path, damage: Callable[[Path], None], reason: str
) -> None:
    """ADR-051: a root whose record cannot be read may be remote, so server-host commands refuse."""

    from finishup.config.paths import active_root, reset_selection_memo

    damage(selected_ssh_target)
    reset_selection_memo()
    assert active_root() == selected_ssh_target.parent  # the root itself still resolves
    for command in ("service run", "service start", "setup vault", "/privacy"):
        with pytest.raises(ServerTargetUnreadable) as refused:
            require_server_host(command)
        assert refused.value.reason == reason
        assert refused.value.target_id == selected_ssh_target.parent.name
    require_server_host("status")  # commands that are not server-host still run

    result = CliRunner().invoke(cli.app, ["service", "endpoint", "--json"])
    assert result.exit_code == 2
    assert result.stderr.startswith(f"{reason}: this command runs only on the FinishUP server host")
    assert "'finishup server use local'" in result.stderr
    assert "lab.example" not in result.stderr and "owner" not in result.stderr
    assert result.stdout == ""
