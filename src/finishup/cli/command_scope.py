"""Where each command may run: on any target, on the server host only, or on the client only.

The client/server cut line (ADR-051) labels every CLI command path and every terminal-interface
command with one closed scope:

* ``any`` — works against whichever server target is selected (it speaks the control protocol, or
  acts only on the active root's own client state, such as the observation store that is the
  client's authority on a remote target).
* ``server_host`` — administers the server host itself (its vault, recovery set, provider runtime,
  privacy ceremonies, observation store, backups, or the service process). On a remote target it
  is refused with ``requires_server_host`` before it runs; a local target (the everyday server or a
  named local server) is the server host, so nothing changes there.
* ``client_only`` — acts on this machine's host registrations or server targets and never on a
  server.

The table is explicit and keyed by command path or group prefix (longest prefix wins). There is
no default: ``tests/unit/cli/test_command_scope.py`` walks the Typer tree and the slash-command
registry and fails on any command this table does not classify.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterator, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, Literal

if TYPE_CHECKING:
    import typer

__all__ = [
    "COMMAND_SCOPES",
    "TUI_COMMAND_SCOPES",
    "CommandScope",
    "ServerHostRequired",
    "ServerTargetUnreadable",
    "command_scope",
    "install_server_host_guards",
    "iter_command_paths",
    "require_server_host",
    "server_host_refusal_line",
    "tui_command_scope",
]

type CommandScope = Literal["any", "server_host", "client_only"]

REQUIRES_SERVER_HOST: Final = "requires_server_host"

COMMAND_SCOPES: Final[Mapping[str, CommandScope]] = MappingProxyType(
    {
        # The workflow and support operations travel over the control protocol.
        "check": "any",
        "closure-prepare": "any",
        "closure-schema": "any",
        "import": "any",
        "project": "any",
        "publish-work": "any",
        "receipt": "any",
        "record-test": "any",
        "respond": "any",
        "review": "any",
        "start": "any",
        "status": "any",
        "privacy pending": "any",
        "privacy propose": "any",
        "privacy receipts": "any",
        "privacy show": "any",
        "privacy tighten": "any",
        "service lock": "any",
        "service status": "any",
        "service stop": "any",
        # Client processes and client-local facts.
        "hooks": "any",
        "mcp": "any",
        "menu": "any",
        "instance": "any",
        # The active root's own observation store: consent, selection, approved-check trust, the
        # outbox. On a remote target it is the client's, and the authority (ADR-051 decision 12).
        "observe": "any",
        "service isolation": "any",
        "setup run": "any",
        "setup status": "any",
        "state": "any",
        "upgrade": "any",
        "version": "any",
        # The server host's own vault, recovery set, provider runtime, configuration, privacy
        # ceremonies, backups, consent handoff, and service process.
        "ai": "server_host",
        "backup": "server_host",
        "consent": "server_host",
        "elevated-bootstrap": "server_host",
        "integrate skill": "server_host",
        "migrate": "server_host",
        "privacy apply-desired": "server_host",
        "privacy conversations": "server_host",
        "privacy credential-heuristic": "server_host",
        "privacy decide-disclosure": "server_host",
        "privacy decide-policy": "server_host",
        "privacy export-desired": "server_host",
        "privacy input-roots": "server_host",
        "privacy setup": "server_host",
        "provider": "server_host",
        "recommend": "server_host",
        "restore": "server_host",
        "service auto-unlock": "server_host",
        "service diagnostics": "server_host",
        "service endpoint": "server_host",
        "service idle-relock": "server_host",
        "service initialize-passphrase": "server_host",
        "service recovery": "server_host",
        "service restart": "server_host",
        "service rotate-passphrase": "server_host",
        "service run": "server_host",
        "service start": "server_host",
        "service unlock": "server_host",
        "setup vault": "server_host",
        # This machine's host registrations and server targets.
        "integrate admission": "client_only",
        "integrate mcp": "client_only",
        "integrate plugin": "client_only",
        "integrate project-mcp": "client_only",
        "server": "client_only",
        "setup disconnect": "client_only",
    }
)

# Slash commands of the terminal interface (``finishup.tui.commands.SLASH_COMMANDS``).
TUI_COMMAND_SCOPES: Final[Mapping[str, CommandScope]] = MappingProxyType(
    {
        "status": "any",
        "work": "any",
        "lineage": "any",
        "project": "any",
        "findings": "any",
        "notes": "any",
        "observe": "any",
        "check": "any",
        "progress": "any",
        "receipt": "any",
        "connect": "client_only",
        "coverage": "any",
        "disconnect": "client_only",
        "privacy": "server_host",
        "provider": "server_host",
        "service": "server_host",
        "server": "client_only",
        "doctor": "any",
        "help": "any",
        "quit": "any",
    }
)


class ServerHostRequired(Exception):
    """A ``server_host`` command was asked of a remote server target.

    Carries the target id (``t_<8 hex>``, generated, never a name the owner typed) and its closed
    kind token, so a refusal line can say which target without echoing user-controlled text.
    """

    reason: str
    target_id: str | None
    kind: str | None

    def __init__(self, target_id: str | None, kind: str | None) -> None:
        self.reason = REQUIRES_SERVER_HOST
        self.target_id = target_id
        self.kind = kind
        super().__init__(REQUIRES_SERVER_HOST)


class ServerTargetUnreadable(ServerHostRequired):
    """A ``server_host`` command while the active root's server target record cannot be read.

    The root holds a ``target.json`` that is unsafe or invalid (a restored backup with the wrong
    mode, a record a newer release wrote), so whether it is this machine's server is unknown and
    the command fails closed rather than running a server-host action in what may be a remote
    target's root. ``reason`` is the record's closed refusal (``target_root_unsafe`` or
    ``target_record_invalid``); the kind is unknown.
    """

    def __init__(self, reason: str, target_id: str | None) -> None:
        super().__init__(target_id, None)
        self.reason = reason
        self.args = (reason,)


def command_scope(path: str) -> CommandScope:
    """Return the scope of a space-separated command path; ``KeyError`` when unclassified."""

    parts = path.split()
    for length in range(len(parts), 0, -1):
        scope = COMMAND_SCOPES.get(" ".join(parts[:length]))
        if scope is not None:
            return scope
    raise KeyError(path)


def tui_command_scope(name: str) -> CommandScope:
    """Return the scope of one slash command name (without its slash)."""

    return TUI_COMMAND_SCOPES[name]


def require_server_host(command: str) -> None:
    """Refuse a server-host command while a remote server target is the active root.

    ``command`` is a CLI command path or a slash command token (``/observe``). A local root — the
    everyday server, an explicitly isolated root, or a named local server — is the server host, so
    this returns. A target root whose ``target.json`` names a remote kind raises
    ``ServerHostRequired``; one whose ``target.json`` cannot be read raises
    ``ServerTargetUnreadable`` (fail closed). A root that cannot be resolved at all is left to the
    command's own fail-closed path, so a broken root is reported exactly as before.
    """

    from finishup.client.targets import TargetError, TargetRecordUnreadable, active_target_record

    scope = (
        tui_command_scope(command.removeprefix("/"))
        if command.startswith("/")
        else command_scope(command)
    )
    if scope != "server_host":
        return
    try:
        record = active_target_record()
    except TargetRecordUnreadable as error:
        raise ServerTargetUnreadable(error.reason, error.target_id) from None
    except TargetError:
        return
    if record is not None and record.is_remote:
        raise ServerHostRequired(record.target_id, record.kind)


def server_host_refusal_line(error: ServerHostRequired) -> str:
    """One bounded operator line for a refused server-host command (closed tokens and an id)."""

    if isinstance(error, ServerTargetUnreadable):
        which = "" if error.target_id is None else f" {error.target_id}"
        return (
            f"{error.reason}: this command runs only on the FinishUP server host, and the server "
            f"target record of this process's FinishUP root{which} cannot be read, so it was not "
            "run; repair or remove that target, or select this machine's server with "
            "'finishup server use local'"
        )
    return (
        f"{REQUIRES_SERVER_HOST}: this command runs on the FinishUP server host, and the "
        f"selected server target {error.target_id} ({error.kind}) is not this machine; run it "
        "on the server host, or select this machine's server with 'finishup server use local'"
    )


def iter_command_paths(app: typer.Typer, prefix: tuple[str, ...] = ()) -> Iterator[tuple[str, Any]]:
    """Yield ``(command path, CommandInfo)`` for every command registered beneath ``app``."""

    for info in app.registered_commands:
        callback = info.callback
        name = info.name or (
            callback.__name__.replace("_", "-") if callback is not None else "unnamed"
        )
        yield " ".join((*prefix, name)), info
    for group in app.registered_groups:
        instance = group.typer_instance
        if instance is None or group.name is None:
            continue
        yield from iter_command_paths(instance, (*prefix, group.name))


def _guarded(callback: Callable[..., Any], path: str) -> Callable[..., Any]:
    @functools.wraps(callback)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        import typer

        try:
            require_server_host(path)
        except ServerHostRequired as error:
            typer.echo(server_host_refusal_line(error), err=True)
            from finishup.cli.exits import exit_code_for
            from finishup.protocol.errors import PublicErrorCode

            raise typer.Exit(exit_code_for(PublicErrorCode.INVALID_REQUEST)) from None
        return callback(*args, **kwargs)

    guarded.__finishup_server_host_guard__ = True  # type: ignore[attr-defined]
    return guarded


def install_server_host_guards(app: typer.Typer) -> None:
    """Wrap every ``server_host`` command callback beneath ``app`` with ``require_server_host``.

    The wrapper keeps the callback's signature (Typer reads it through ``__wrapped__``), so help,
    options and output are unchanged; on a local root it only resolves the active root and calls
    through. A callback registered under two paths is wrapped once.
    """

    for path, info in iter_command_paths(app):
        callback = info.callback
        if callback is None or command_scope(path) != "server_host":
            continue
        if getattr(callback, "__finishup_server_host_guard__", False):
            continue
        info.callback = _guarded(callback, path)
