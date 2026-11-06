"""``finishup server``: choose which FinishUP server this computer's client uses (ADR-051).

Every command here acts on this machine's server targets and selection (scope ``client_only``).
Names and addresses appear only in owner displays (``list``, ``status``, ``test``) and on the
trusted console; refusals name a target by its id or not at all, with a closed reason token.

* ``add NAME --local`` makes a named local server (its own vault, ledger, and on-demand service);
  ``add NAME --port PORT``, ``add NAME ssh://…`` and ``add NAME https://…`` record a remote target
  after the owner types the target name on the trusted console to accept the versioned
  disclosure. ``remove`` is the reverse.
* ``use NAME|local`` writes or removes the owner-only selection; remote targets need the same
  typed confirmation. ``use local`` is the reverse.
* ``login``/``logout`` store or delete an HTTPS target's API key (platform store or owner-only
  file); ``connect``/``disconnect`` make the target usable or stop what this client runs for it.
* ``list``, ``status [--json]`` and ``test`` show the deciding source, the target, and a probe.

An isolation root or a runtime pin outranks the selection; while one is in force every command
that would change or use the selection is refused with ``selection_overridden``.
"""

from __future__ import annotations

import functools
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Final, Literal, NoReturn, cast

import typer

from finishup import __version__
from finishup.client.target_runtime import (
    ProbeResult,
    TargetRuntimeError,
    runtime_for,
)
from finishup.client.targets import (
    DISCLOSURE_VERSION,
    ServerTarget,
    TargetError,
    TargetKind,
    active_target_record,
    clear_selection,
    find_target,
    list_targets,
    normalize_https_url,
    parse_ssh_url,
    read_selected_target_id,
    reauthorized,
    registry_lock,
    selection_source,
    target_root,
    validate_name,
    write_selection,
    write_target,
)
from finishup.config.installation import format_rfc3339_ms
from finishup.config.paths import PathSafetyError
from finishup.protocol.canonical import JsonValue, canonical_encode

__all__ = [
    "DISCLOSURE_LINES",
    "ROOT_UNUSABLE_MESSAGE",
    "ServerCommandRefused",
    "TargetRow",
    "build_status_document",
    "refusal_message",
    "render_target_rows",
    "server_app",
    "status_lines",
    "target_rows",
    "use_target",
]

server_app = typer.Typer(
    help="Choose which FinishUP server this computer's agents, CLI, and terminal use.",
    no_args_is_help=True,
)

_JSON = Annotated[bool, typer.Option("--json", help="Emit canonical JSON.")]
_EXPLICIT_SOURCES: Final = frozenset({"environment", "runtime_pin", "environment_and_pin"})
# p95 status round trip above which a required-mode startup gate (0.65 s for connect + status)
# would likely deny on a cold hook (design section 8).
_STARTUP_GATE_RISK_MS: Final = 200
_USAGE: Final = 2
_UNSAFE: Final = 20
_UNAVAILABLE: Final = 20

# Remedies are fixed text: no name, host, path, or other owner-typed value is ever echoed.
_REMEDIES: Final[dict[str, tuple[str, int]]] = {
    "selection_overridden": (
        "FINISHUP_ISOLATED_ROOT or a runtime pin decides this process's FinishUP root, so the "
        "server selection is not used here; run this from an ordinary shell",
        _USAGE,
    ),
    "target_name_invalid": (
        "a target name is 1 to 16 lowercase letters, digits, or hyphens, starting with a letter "
        "or digit",
        _USAGE,
    ),
    "target_name_reserved": (
        "'local' always means this computer's everyday FinishUP server; choose another name",
        _USAGE,
    ),
    "target_name_taken": (
        "a target already has that name; choose another, or remove that target first",
        _USAGE,
    ),
    "target_unknown": ("no target has that name; 'finishup server list' shows them", _USAGE),
    "target_selected": (
        "that target is selected; pass --select-local to switch to this computer's everyday "
        "server and remove it",
        _USAGE,
    ),
    "target_record_invalid": (
        "a server target record is damaged; 'finishup server list' fails until it is removed "
        "or restored",
        _UNSAFE,
    ),
    "target_url_invalid": (
        "give https://host[:port][/base] (no user, query, or fragment; plain http is refused), "
        "ssh://[user@]host[:port], or --port PORT for this computer's loopback",
        _USAGE,
    ),
    "target_tls_invalid": (
        "give at most one of --ca-file FILE and --tls-pin sha256:<64 lowercase hex>, and only "
        "with an HTTPS target",
        _USAGE,
    ),
    "target_path_invalid": ("give absolute paths for remote and certificate files", _USAGE),
    "target_root_too_long": (
        "the FinishUP state folder is too deep for a local socket path; FinishUP cannot add a "
        "server target under it",
        _UNSAFE,
    ),
    "target_root_unsafe": (
        "a FinishUP server folder is not owner-only or contains a symlink; fix its permissions "
        "and retry",
        _UNSAFE,
    ),
    "selection_invalid": (
        "the server selection is damaged or names a server folder that is missing or unsafe; "
        "'finishup server use local' clears it",
        _UNSAFE,
    ),
    "trusted_console_required": (
        "authorizing a remote server needs your own interactive terminal; run this command there",
        _USAGE,
    ),
    "authorization_declined": ("the target name was not typed; nothing was changed", _USAGE),
    "zero_network_in_force": (
        "this computer's FinishUP is set to make no network connections, so it cannot use a "
        "server on another machine; change the privacy policy on this computer first",
        _USAGE,
    ),
    "network_policy_unreadable": (
        "this computer's FinishUP has its own privacy policy, which could not be read (its "
        "service is stopped, locked, or did not answer), so a server on another machine is "
        "refused; start it with 'finishup service start', unlock it if it is locked, and retry",
        _UNAVAILABLE,
    ),
    "credential_not_applicable": (
        "only HTTPS targets take an API key; SSH targets use your OpenSSH keys and agent",
        _USAGE,
    ),
    "credential_invalid": (
        "the key must be one line of 16 to 512 printable characters, from your terminal or an "
        "owner-only (0600) key file",
        _USAGE,
    ),
    "credential_unavailable": ("no key could be read; nothing was changed", _USAGE),
    "credential_store_unavailable": (
        "neither the platform credential store nor the owner-only key file could be used",
        _UNAVAILABLE,
    ),
    "runtime_unavailable": (
        "this FinishUP build has no client runtime for that kind of server target",
        _UNAVAILABLE,
    ),
    "selection_active": (
        "another server is selected, so this computer's everyday server cannot be started from "
        "here; run 'finishup server use local' first",
        _USAGE,
    ),
    "usage": (
        "give exactly one of --local, --port PORT, or an ssh:// or https:// address",
        _USAGE,
    ),
}

DISCLOSURE_LINES: Final = (
    "Authorize a FinishUP server target (disclosure {version})",
    "",
    "Sent to that server: task statements, published work, evidence, and check, respond,",
    "and receipt traffic.",
    "When it checks or reviews your work, the FinishUP workspace agent on this computer reads",
    "what it asks for (the change being checked, bounded file excerpts for review, declared",
    "task inputs, and results of checks you approved in .finishup/checks.toml) and sends it,",
    "labelled as read on this computer.",
    "No file path from this computer is sent; repositories are named by a keyed label.",
    "That server's own privacy policy decides whether anything goes on to an AI-powered",
    "review provider.",
    "This is your decision on this terminal, not a vault re-authentication. Undo it with",
    "'finishup server use local' or 'finishup server remove'.",
    "",
)


class ServerCommandRefused(Exception):
    """A refused ``finishup server`` step: closed reason and detail tokens, fixed message text."""

    def __init__(
        self, reason: str, *, detail: str | None = None, message: str | None = None
    ) -> None:
        self.reason = reason
        self.detail = detail
        self.message = message
        super().__init__(reason)


_DEFAULT_REMEDY: Final = "the server target did not respond as needed"
# Written once, when the everyday installation's vault is initialized.
_INSTALLATION_MARKER: Final = "installation-state.json"
ROOT_UNUSABLE_MESSAGE: Final = (
    "this process's FinishUP root cannot be used; 'finishup service isolation' explains which "
    "source decided it"
)


def refusal_message(error: ServerCommandRefused) -> str:
    """The fixed text for a refusal (never owner-typed), with its closed detail."""

    remedy, _code = _REMEDIES.get(error.reason, (_DEFAULT_REMEDY, _UNAVAILABLE))
    text = error.message or remedy
    return text if error.detail is None else f"{text} ({error.detail})"


def _fail(reason: str, *, detail: str | None = None, message: str | None = None) -> NoReturn:
    _remedy, code = _REMEDIES.get(reason, (_DEFAULT_REMEDY, _UNAVAILABLE))
    text = refusal_message(ServerCommandRefused(reason, detail=detail, message=message))
    typer.echo(f"{reason}: {text}", err=True)
    raise typer.Exit(code)


def _cli[**P](command: Callable[P, None]) -> Callable[P, None]:
    """Render a ``ServerCommandRefused`` as one bounded line and its exit code."""

    @functools.wraps(command)
    def run(*args: P.args, **kwargs: P.kwargs) -> None:
        try:
            command(*args, **kwargs)
        except ServerCommandRefused as error:
            _fail(error.reason, detail=error.detail, message=error.message)
        except TargetError as error:
            _fail(error.reason)
        except PathSafetyError as error:
            # The everyday folders themselves cannot be chosen (for example data under both
            # product names): the registry lives there, so nothing can be read or written.
            _fail(error.reason_code, message=ROOT_UNUSABLE_MESSAGE)

    return run


def _runtime_failure(error: TargetRuntimeError) -> NoReturn:
    if error.phase == "runtime_unavailable":
        raise ServerCommandRefused(
            "runtime_unavailable", detail=f"{error.reason}, phase {error.phase}"
        )
    raise ServerCommandRefused(
        error.reason, detail=None if error.phase is None else f"phase {error.phase}"
    )


def _explicit_source_present() -> bool:
    """Whether the isolation variable or a runtime pin decides this process's root.

    Read without resolving the selection, so the ways back from a damaged or dangling selection
    (``use local``, ``remove --select-local``) still work. A variable or pin that cannot be used is
    still an explicit source: it fails closed with its own path-safety reason.
    """

    from finishup.config.paths import isolated_root_variable, read_runtime_pin

    try:
        return isolated_root_variable() is not None or read_runtime_pin() is not None
    except PathSafetyError as error:
        raise ServerCommandRefused(error.reason_code, message=ROOT_UNUSABLE_MESSAGE) from None


def _source() -> str:
    try:
        return selection_source()
    except PathSafetyError as error:
        if not _explicit_source_present():
            # Neither the variable nor a pin is set, so the selection is what cannot be used: a
            # damaged file, or a missing or unsafe target folder. Its remedy works from here.
            raise ServerCommandRefused("selection_invalid") from None
        raise ServerCommandRefused(error.reason_code, message=ROOT_UNUSABLE_MESSAGE) from None


def _require_selection_in_force() -> None:
    """Refuse while the isolation variable or a runtime pin outranks the selection."""

    if _source() in _EXPLICIT_SOURCES:
        raise ServerCommandRefused("selection_overridden")


def _require_no_explicit_source() -> None:
    """``_require_selection_in_force`` without resolving the selection (the ways back)."""

    if _explicit_source_present():
        raise ServerCommandRefused("selection_overridden")


def _target_or_fail(name: str) -> ServerTarget:
    try:
        return find_target(name)
    except TargetError as error:
        raise ServerCommandRefused(error.reason)


def _location(record: ServerTarget | None) -> str | None:
    if record is None or record.kind == "local":
        return None
    if record.kind == "ssh":
        host = cast(str, record.host)
        authority = f"[{host}]" if ":" in host else host
        user = "" if record.user is None else f"{record.user}@"
        return f"ssh://{user}{authority}:{record.port}"
    return record.base_url


def _kind_label(kind: str) -> str:
    return {
        "local": "a named local server on this computer",
        "local_port": "a FinishUP server on this computer's loopback, over HTTPS",
        "ssh": "a FinishUP server on another machine, over SSH",
        "https": "a FinishUP server over HTTPS",
    }[kind]


def _everyday_installation_exists() -> bool:
    """Whether this computer's everyday FinishUP was set up (its vault initialized).

    Read under ``selection_override(None)``. The installation marker is written once, when the
    vault is initialized, so its presence means this computer has a privacy policy of its own.
    Anything that keeps the answer from being known (a configuration or folder that cannot be
    read) fails closed: it counts as set up.
    """

    import os

    from finishup.config.load import load_config
    from finishup.config.models import ConfigError
    from finishup.config.paths import bundle_root

    try:
        config = load_config({}, os.environ, None)
        (bundle_root(_data_dir=config.storage.data_dir) / _INSTALLATION_MARKER).lstat()
    except FileNotFoundError:
        return False
    except (ConfigError, OSError, PathSafetyError):
        return True
    return True


def _zero_network_in_force() -> bool:
    """Whether this computer is in the zero-network state that refuses a remote hop (ADR-051).

    Every remote kind is a hop, ``local_port`` included: a loopback port can forward anywhere.
    This computer's own FinishUP decides. When its everyday installation was set up, its running
    service's effective policy decides, and a policy that does not permit network egress is the
    zero-network state; when that policy cannot be read (the service is stopped, locked, or does
    not answer) the hop is refused with ``network_policy_unreadable``, never allowed. A computer
    whose everyday FinishUP was never set up has no policy of its own, so nothing here refuses
    it: it is a client of the server it names, and that server's own policy governs its data.
    """

    import anyio

    from finishup.config.paths import selection_override
    from finishup.domain.values import JsonObject
    from finishup.ports.control import ControlClientKind, ControlError
    from finishup.service.client import connect_service

    async def effective() -> bool | None:
        try:
            with anyio.fail_after(3.0):
                client = await connect_service(ControlClientKind.CLI, workspace_locator=None)
        except (ControlError, TimeoutError):
            return None
        try:
            response = await client.privacy_get_setup(JsonObject({"schema_version": "2.0.0"}))
        except ControlError:
            return None
        finally:
            await client.close()
        # The reply is a frozen ``JsonObject`` (a ``Mapping``, not a ``dict``) on the wire.
        policy = response.get("composed_policy")
        if not isinstance(policy, Mapping):
            return None
        return cast(Mapping[str, object], policy).get("network_egress_permitted") is not True

    with selection_override(None):
        if not _everyday_installation_exists():
            return False
        answer = anyio.run(effective)
    if answer is None:
        raise ServerCommandRefused("network_policy_unreadable")
    return answer


def _confirm_on_trusted_console(name: str, kind: str) -> None:
    """Show the versioned disclosure and require the owner to type the target name."""

    from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole

    try:
        with TrustedForegroundConsole() as console:
            for line in DISCLOSURE_LINES:
                console.write(line.format(version=DISCLOSURE_VERSION) + "\n")
            console.write(f"Target: {name}, {_kind_label(kind)}.\n")
            console.read_choice(
                "Type the target name to authorize it (anything else cancels): ",
                (name.encode("ascii"),),
            )
    except TrustedConsoleError as error:
        if error.reason == "trusted_console_required":
            raise ServerCommandRefused("trusted_console_required")
        raise ServerCommandRefused("authorization_declined")


def _authorize_remote(name: str, kind: str) -> None:
    # Every remote kind is a network hop, ``local_port`` included (ADR-051 section 3).
    if _zero_network_in_force():
        raise ServerCommandRefused("zero_network_in_force")
    _confirm_on_trusted_console(name, kind)


def _emit(lines: tuple[str, ...]) -> None:
    for line in lines:
        typer.echo(line)


def _warn_open_sessions() -> None:
    typer.echo(
        "New hooks and CLI calls use it now. Restart open agent sessions: a running FinishUP "
        "MCP bridge keeps the server it started with."
    )


@server_app.command("add")
@_cli
def server_add(
    name: Annotated[str, typer.Argument(help="Target name: 1-16 lowercase letters, digits, -.")],
    address: Annotated[
        str | None,
        typer.Argument(help="ssh://[user@]host[:port] or https://host[:port][/base]."),
    ] = None,
    local: Annotated[
        bool, typer.Option("--local", help="A named local server on this computer.")
    ] = False,
    port: Annotated[
        int | None,
        typer.Option("--port", min=1, max=65_535, help="A server on this computer's loopback."),
    ] = None,
    remote_root: Annotated[
        str | None,
        typer.Option("--remote-root", help="SSH: the server's absolute isolated root."),
    ] = None,
    remote_launcher: Annotated[
        str | None,
        typer.Option("--remote-launcher", help="SSH: absolute path to the server's finishup."),
    ] = None,
    ca_file: Annotated[
        Path | None, typer.Option("--ca-file", help="HTTPS: CA certificate file to trust.")
    ] = None,
    tls_pin: Annotated[
        str | None, typer.Option("--tls-pin", help="HTTPS: sha256:<hex> certificate pin.")
    ] = None,
) -> None:
    """Add a server target: a named local server, or a remote one after typed authorization."""

    _require_selection_in_force()
    try:
        validate_name(name)
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    chosen = sum((local, port is not None, address is not None))
    if chosen != 1:
        raise ServerCommandRefused("usage")
    kind: TargetKind
    base_url: str | None = None
    user: str | None = None
    host: str | None = None
    ssh_port: int | None = None
    try:
        if local:
            kind = "local"
        elif port is not None:
            kind = "local_port"
            base_url = normalize_https_url(f"https://127.0.0.1:{port}", loopback_only=True)
        elif cast(str, address).startswith("ssh://"):
            kind = "ssh"
            user, host, ssh_port = parse_ssh_url(cast(str, address))
        else:
            base_url = normalize_https_url(cast(str, address))
            # ``https://127.0.0.1:PORT`` and ``https://[::1]:PORT`` are this computer's loopback
            # ports (ADR-051 section 3), exactly as ``--port PORT`` records 127.0.0.1.
            kind = "local_port" if _loopback_origin(base_url) else "https"
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    if (remote_root is not None or remote_launcher is not None) and kind != "ssh":
        raise ServerCommandRefused("usage")
    if (ca_file is not None or tls_pin is not None) and kind not in {"https", "local_port"}:
        raise ServerCommandRefused("target_tls_invalid")
    if ca_file is not None and tls_pin is not None:
        raise ServerCommandRefused("target_tls_invalid")
    ca_text: str | None = None
    if ca_file is not None:
        resolved = ca_file.expanduser()
        resolved = resolved if resolved.is_absolute() else Path.cwd() / resolved
        if not resolved.is_file():
            raise ServerCommandRefused("target_path_invalid")
        ca_text = str(resolved)
    try:
        taken = any(record.name == name for record in list_targets())
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    if taken:
        raise ServerCommandRefused("target_name_taken")
    if kind != "local":
        _authorize_remote(name, kind)
    try:
        with registry_lock():
            if kind == "local":
                from finishup.client.targets import new_local_target

                record, _root = new_local_target(name)
            else:
                from finishup.client.targets import new_remote_target

                record, _root = new_remote_target(
                    name,
                    kind,
                    base_url=base_url,
                    ca_file=ca_text,
                    tls_pin=tls_pin,
                    user=user,
                    host=host,
                    port=ssh_port,
                    remote_root=remote_root,
                    remote_launcher=remote_launcher,
                )
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    typer.echo(f"Added server target {record.name} ({record.target_id}, {record.kind}).")
    if kind == "local":
        _emit(
            (
                f"Select it with 'finishup server use {record.name}', then run 'finishup setup' "
                "to set up its vault.",
            )
        )
    elif kind in {"https", "local_port"}:
        _emit((f"Store its API key with 'finishup server login {record.name}'.",))
    else:
        _emit((f"Check it with 'finishup server test {record.name}'.",))


def _loopback_origin(base_url: str) -> bool:
    """Whether a normalized HTTPS address is a loopback origin with an explicit port."""

    try:
        return normalize_https_url(base_url, loopback_only=True) == base_url
    except TargetError:
        return False


@dataclass(frozen=True, slots=True)
class TargetRow:
    """One owner-display row of ``finishup server list`` (and the terminal's ``/server``)."""

    selected: bool
    name: str
    kind: str
    target_id: str | None
    location: str | None


def target_rows() -> tuple[tuple[TargetRow, ...], str]:
    """Every target as a display row (``local`` first), and the deciding source."""

    source = _source()
    try:
        records = list_targets()
        selected = read_selected_target_id()
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    current = None if source in _EXPLICIT_SOURCES else selected
    rows = [TargetRow(current is None, "local", "local", None, None)]
    rows.extend(
        TargetRow(
            record.target_id == current,
            record.name,
            record.kind,
            record.target_id,
            _location(record),
        )
        for record in records
    )
    return tuple(rows), source


def render_target_rows(rows: tuple[TargetRow, ...], source: str) -> tuple[str, ...]:
    table = [
        (
            "*" if row.selected else " ",
            row.name,
            row.kind,
            row.target_id or "-",
            row.location or "this computer",
        )
        for row in rows
    ]
    widths = [max(len(line[index]) for line in table) for index in range(1, 4)]
    lines = [
        f"{mark} {name.ljust(widths[0])}  {kind.ljust(widths[1])}  "
        f"{target_id.ljust(widths[2])}  {where}"
        for mark, name, kind, target_id, where in table
    ]
    if source in _EXPLICIT_SOURCES:
        lines.append(f"The selection is not used here: the {source} decides this process's root.")
    return tuple(lines)


@server_app.command("list")
@_cli
def server_list() -> None:
    """List server targets; the selected one is marked with *."""

    rows, source = target_rows()
    _emit(render_target_rows(rows, source))


def use_target(
    name: str, *, authorize: Callable[[str, str], None] | None = None
) -> ServerTarget | None:
    """Select ``name`` (``None`` back means this computer's everyday server).

    A remote target needs the typed confirmation on the trusted console every time
    (``authorize`` defaults to it), which also refreshes its recorded authorization.
    """

    if name == "local":
        # The way back never resolves the selection it removes: a damaged selection, or one that
        # names a missing or unsafe target folder, is exactly what it must clear.
        _require_no_explicit_source()
        try:
            with registry_lock():
                clear_selection()
        except TargetError as error:
            raise ServerCommandRefused(error.reason) from None
        return None
    _require_selection_in_force()
    record = _target_or_fail(name)
    if record.is_remote:
        (authorize or _authorize_remote)(record.name, record.kind)
        record = reauthorized(record)
    try:
        with registry_lock():
            if record.is_remote:
                write_target(target_root(record.target_id), record)
            write_selection(record)
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    return record


@server_app.command("use")
@_cli
def server_use(
    name: Annotated[str, typer.Argument(help="A target name, or 'local' for this computer.")],
) -> None:
    """Select the server new client processes use ('local' returns to this computer's)."""

    record = use_target(name)
    if record is None:
        typer.echo("Using this computer's everyday FinishUP server.")
    else:
        typer.echo(f"Using server target {record.name} ({record.target_id}, {record.kind}).")
    _warn_open_sessions()


def _probe_document(result: ProbeResult | None, error: TargetRuntimeError | None) -> JsonValue:
    if error is not None:
        return {
            "outcome": "unavailable",
            "reason": error.reason,
            "phase": error.phase,
            "service_version": None,
            "service_instance_id": None,
            "service_state": None,
            "vault_mode": None,
            "round_trip_p95_ms": None,
            "samples": 0,
        }
    assert result is not None
    return {
        "outcome": result.outcome,
        "reason": result.reason,
        "phase": result.phase,
        "service_version": result.service_version,
        "service_instance_id": result.service_instance_id,
        "service_state": result.service_state,
        "vault_mode": result.vault_mode,
        "round_trip_p95_ms": result.round_trip_p95_ms,
        "samples": result.samples,
    }


def _resolve(name: str | None) -> tuple[ServerTarget | None, Path | None, bool]:
    """``(record, root, everyday)`` for ``name``, or for this process's own root when omitted."""

    if name is None:
        try:
            record = active_target_record()
        except TargetError as error:
            raise ServerCommandRefused(error.reason)
        if record is not None:
            return record, target_root(record.target_id), False
        from finishup.config.paths import active_root

        try:
            root = active_root()
        except PathSafetyError as error:
            raise ServerCommandRefused(error.reason_code, message=ROOT_UNUSABLE_MESSAGE) from None
        return None, root, root is None
    _require_selection_in_force()
    if name == "local":
        return None, None, True
    record = _target_or_fail(name)
    return record, target_root(record.target_id), False


def _probe(record: ServerTarget | None, root: Path | None) -> ProbeResult:
    kind: TargetKind = "local" if record is None else record.kind
    return runtime_for(kind).probe(root)


def build_status_document(
    name: str | None, *, now: Callable[[], datetime] | None = None
) -> dict[str, JsonValue]:
    """The ``server-target-status`` 1.0.0 document for ``name`` (or this process's root)."""

    source = _source()
    try:
        selected = read_selected_target_id()
    except TargetError:
        selected = None
    record, root, everyday = _resolve(name)
    result: ProbeResult | None = None
    failure: TargetRuntimeError | None = None
    try:
        result = _probe(record, root)
    except TargetRuntimeError as error:
        failure = error
    authorization: JsonValue = None
    if record is not None and record.is_remote:
        authorization = {
            "authorized_at": cast(str, record.authorized_at),
            "disclosure_version": cast(int, record.disclosure_version),
            "current": not record.needs_reauthorization,
        }
    credential: str = "not_applicable"
    if record is not None and record.kind in {"https", "local_port"}:
        credential = record.credential or "none"
    target: dict[str, JsonValue] = {
        "target_id": None if record is None else record.target_id,
        "name": "local" if everyday else (None if record is None else record.name),
        "kind": "local" if record is None else record.kind,
        "location": _location(record),
        "credential": credential,
        "authorization": authorization,
    }
    stamp = (now or (lambda: datetime.now(UTC)))()
    document: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "source": source,
        "selection_overridden": source in _EXPLICIT_SOURCES and selected is not None,
        "client_version": __version__,
        "target": target,
        "probe": _probe_document(result, failure),
        "observed_at": format_rfc3339_ms(stamp),
    }
    from finishup.protocol.server_target_status import ServerTargetStatusContract

    ServerTargetStatusContract.model_validate(document)
    return document


def status_lines(document: dict[str, JsonValue]) -> tuple[str, ...]:
    target = cast(dict[str, JsonValue], document["target"])
    probe = cast(dict[str, JsonValue], document["probe"])
    name = target["name"] or "this process's isolated root"
    identity = "" if target["target_id"] is None else f"{target['target_id']}, "
    lines = [f"Server: {name} ({identity}{target['kind']}); chosen by: {document['source']}"]
    if target["location"] is not None:
        lines.append(f"Address: {target['location']}")
    if target["credential"] != "not_applicable":
        lines.append(f"API key: {target['credential']}")
    authorization = target["authorization"]
    if isinstance(authorization, dict) and authorization.get("current") is False:
        lines.append("Authorization: an older disclosure; 'finishup server use' asks again")
    state = probe["service_state"] or probe["outcome"]
    reason = "" if probe["reason"] is None else f" ({probe['reason']}"
    if probe["phase"] is not None:
        reason += f", phase {probe['phase']}"
    reason += ")" if reason else ""
    lines.append(f"State: {state}{reason}")
    lines.append(
        f"Release: client {document['client_version']}, server "
        f"{probe['service_version'] or 'unknown'}"
    )
    if probe["vault_mode"] is not None:
        lines.append(f"Vault: {probe['vault_mode']}")
    if probe["round_trip_p95_ms"] is not None:
        lines.append(
            f"Round trip p95: {probe['round_trip_p95_ms']} ms over {probe['samples']} status calls"
        )
    if document["selection_overridden"]:
        lines.append("The server selection is not used here: an isolation root decides it.")
    return tuple(lines)


@server_app.command("status")
@_cli
def server_status(
    name: Annotated[str | None, typer.Argument(help="A target name, or 'local'.")] = None,
    json_output: _JSON = False,
) -> None:
    """Show which source decides the server, the target, and one probe of it."""

    document = build_status_document(name)
    if json_output or not sys.stdout.isatty():
        sys.stdout.buffer.write(canonical_encode(cast(JsonValue, document)) + b"\n")
        sys.stdout.flush()
        return
    _emit(status_lines(document))


@server_app.command("test")
@_cli
def server_test(
    name: Annotated[str | None, typer.Argument(help="A target name, or 'local'.")] = None,
) -> None:
    """Probe a target and compare its round trip with the hook and startup-gate budgets."""

    document = build_status_document(name)
    _emit(status_lines(document))
    probe = cast(dict[str, JsonValue], document["probe"])
    if probe["outcome"] not in {"ready", "reachable"}:
        typer.echo("The target did not answer a status call.", err=True)
        raise typer.Exit(_UNAVAILABLE)
    p95 = probe["round_trip_p95_ms"]
    if isinstance(p95, int) and p95 > _STARTUP_GATE_RISK_MS:
        typer.echo(
            f"Warning: {p95} ms p95 is above {_STARTUP_GATE_RISK_MS} ms; with the required "
            "startup gate (0.65 s for connect and status) agent tools would likely be denied."
        )
    else:
        typer.echo("Within the hook budgets (0.65 s startup gate, 1.0 s hook connect).")


@server_app.command("remove")
@_cli
def server_remove(
    name: Annotated[str, typer.Argument(help="The target to remove.")],
    select_local: Annotated[
        bool,
        typer.Option("--select-local", help="If it is selected, switch to 'local' first."),
    ] = False,
) -> None:
    """Remove a target: stop what this client runs for it, delete its key and its folder."""

    _require_no_explicit_source()
    record = _target_or_fail(name)
    unreadable_selection = False
    try:
        selected = read_selected_target_id()
    except TargetError as error:
        if not select_local:
            raise ServerCommandRefused(
                "selection_invalid" if error.reason == "target_root_unsafe" else error.reason
            ) from None
        # A selection that cannot be read may name this target; --select-local clears it first.
        selected, unreadable_selection = None, True
    if selected == record.target_id and not select_local:
        raise ServerCommandRefused("target_selected")
    root = target_root(record.target_id)
    if record.is_remote:
        try:
            runtime_for(record.kind).stop(root)
        except TargetRuntimeError:
            pass
        from finishup.client.credentials import CredentialError, KeyringOrFileCredential

        try:
            KeyringOrFileCredential(record.target_id, root, recorded=record.credential).delete()
        except CredentialError as error:
            raise ServerCommandRefused(error.reason)
    try:
        with registry_lock():
            if selected == record.target_id or unreadable_selection:
                clear_selection()
            if record.kind == "local":
                from finishup.cli.instance import dispose_instance
                from finishup.config.installation import InstanceIdentityError

                try:
                    dispose_instance(root=root)
                except InstanceIdentityError as error:
                    typer.echo(
                        f"{error.reason}: the named local server could not be removed",
                        err=True,
                    )
                    raise typer.Exit(_UNSAFE) from None
            else:
                from finishup.client.targets import remove_target_root

                remove_target_root(record)
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    except PathSafetyError as error:
        typer.echo(f"{error.reason_code}: the target folder is unsafe to remove", err=True)
        raise typer.Exit(_UNSAFE) from None
    typer.echo(f"Removed server target {record.name} ({record.target_id}).")
    if selected == record.target_id or unreadable_selection:
        typer.echo("Using this computer's everyday FinishUP server.")
        _warn_open_sessions()


def _read_secret_on_console() -> str:
    from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole
    from finishup.client.credentials import CredentialError, validate_secret

    try:
        with TrustedForegroundConsole() as console:
            value = console.read_secret("API key (input hidden): ", 512)
    except TrustedConsoleError as error:
        if error.reason == "trusted_console_required":
            raise ServerCommandRefused("trusted_console_required")
        raise ServerCommandRefused("credential_unavailable")
    try:
        text = bytes(value).decode("ascii")
    except UnicodeDecodeError:
        raise ServerCommandRefused("credential_invalid")
    finally:
        for index in range(len(value)):
            value[index] = 0
    try:
        return validate_secret(text)
    except CredentialError as error:
        raise ServerCommandRefused(error.reason)


@server_app.command("login")
@_cli
def server_login(
    name: Annotated[str, typer.Argument(help="An HTTPS server target.")],
    key_file: Annotated[
        Path | None,
        typer.Option("--key-file", help="Read the key once from an owner-only (0600) file."),
    ] = None,
) -> None:
    """Store an HTTPS target's API key (masked prompt, or --key-file read once)."""

    from finishup.client.credentials import CredentialError, KeyringOrFileCredential, read_key_file

    _require_selection_in_force()
    record = _target_or_fail(name)
    if record.kind not in {"https", "local_port"}:
        raise ServerCommandRefused("credential_not_applicable")
    try:
        secret = read_key_file(key_file) if key_file is not None else _read_secret_on_console()
        root = target_root(record.target_id)
        location = KeyringOrFileCredential(
            record.target_id, root, recorded=record.credential
        ).store(secret)
        with registry_lock():
            write_target(root, replace(record, credential=location))
    except CredentialError as error:
        raise ServerCommandRefused(error.reason)
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    where = "the platform credential store" if location == "keyring" else "an owner-only file"
    typer.echo(f"Stored the API key for {record.target_id} in {where}.")


@server_app.command("logout")
@_cli
def server_logout(name: Annotated[str, typer.Argument(help="An HTTPS server target.")]) -> None:
    """Delete an HTTPS target's stored API key."""

    from finishup.client.credentials import CredentialError, KeyringOrFileCredential

    _require_selection_in_force()
    record = _target_or_fail(name)
    if record.kind not in {"https", "local_port"}:
        raise ServerCommandRefused("credential_not_applicable")
    root = target_root(record.target_id)
    try:
        removed = KeyringOrFileCredential(
            record.target_id, root, recorded=record.credential
        ).delete()
        with registry_lock():
            write_target(root, replace(record, credential=None))
    except CredentialError as error:
        raise ServerCommandRefused(error.reason)
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    typer.echo(
        f"Deleted the API key for {record.target_id}."
        if removed
        else f"No API key was stored for {record.target_id}."
    )


def _runtime_call(name: str | None, action: Literal["ensure_ready", "stop"]) -> str:
    record, root, everyday = _resolve(name)
    kind: TargetKind = "local" if record is None else record.kind
    if action == "ensure_ready" and everyday:
        try:
            if read_selected_target_id() is not None and _source() not in _EXPLICIT_SOURCES:
                raise ServerCommandRefused("selection_active")
        except TargetError as error:
            raise ServerCommandRefused(error.reason)
    try:
        runtime = runtime_for(kind)
        if action == "ensure_ready":
            runtime.ensure_ready(root)
        else:
            runtime.stop(root)
    except TargetRuntimeError as error:
        _runtime_failure(error)
    if record is not None:
        return f"{record.name} ({record.target_id})"
    return "this computer's everyday server" if everyday else "this process's isolated root"


@server_app.command("connect")
@_cli
def server_connect(
    name: Annotated[str | None, typer.Argument(help="A target name, or 'local'.")] = None,
) -> None:
    """Make a target usable now (start its service or its connection); it also starts on demand."""

    label = _runtime_call(name, "ensure_ready")
    typer.echo(f"Connected: {label}.")


@server_app.command("disconnect")
@_cli
def server_disconnect(
    name: Annotated[str | None, typer.Argument(help="A target name, or 'local'.")] = None,
) -> None:
    """Stop the service or connection this client runs for a target (never by pattern)."""

    label = _runtime_call(name, "stop")
    typer.echo(f"Disconnected: {label}.")
