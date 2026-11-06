"""``finishup service gateway``: serve this server host to remote clients over HTTPS (ADR-051).

Server-host commands (scope ``server_host``):

* ``run --listen HOST:PORT (--tls-cert F --tls-key F | --behind-proxy)`` serves the HTTPS
  binding v1 in the foreground until interrupted (Ctrl-C or a supervisor is the reverse);
* ``key create --label L --scope agent|operator [--expires-in-days N] [--rotate KEY_ID]
  [--output-file F]`` makes an API key and shows it exactly once: on this terminal, or written
  owner-only (0600) to ``F``;
* ``key list`` shows every key's id, label, scope and times (never a secret);
* ``key revoke KEY_ID`` is ``create``'s reverse: the key fails its next request and its sessions
  close.

Refusals are closed tokens with fixed remedy text; no label, key or path is echoed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated, Final, Literal, cast

import typer

from finishup.protocol.canonical import JsonValue, canonical_encode

__all__ = ["gateway_app"]

gateway_app = typer.Typer(
    help="Serve this server host's FinishUP to remote clients over HTTPS (keys and scopes).",
    no_args_is_help=True,
)
key_app = typer.Typer(help="Create, list and revoke the gateway's API keys.", no_args_is_help=True)
gateway_app.add_typer(key_app, name="key")

_USAGE: Final = 2
_UNSAFE: Final = 20
_REMEDIES: Final[dict[str, tuple[str, int]]] = {
    "gateway_listen_invalid": ("give --listen HOST:PORT with an IP address or localhost", _USAGE),
    "gateway_tls_required": (
        "give --tls-cert and --tls-key, or --behind-proxy on a loopback address behind a TLS proxy",
        _USAGE,
    ),
    "gateway_proxy_not_loopback": (
        "--behind-proxy serves plain HTTP, so it listens on a loopback address only",
        _USAGE,
    ),
    "gateway_tls_invalid": (
        "the certificate and key could not be loaded together (or were given with --behind-proxy)",
        _USAGE,
    ),
    "gateway_keys_invalid": (
        "the gateway key file is damaged; restore it or move it aside and create new keys",
        _UNSAFE,
    ),
    "gateway_keys_unsafe": (
        "the gateway key folder or file is not owner-only; fix its permissions and retry",
        _UNSAFE,
    ),
    "gateway_key_unknown": ("no key has that id; 'finishup service gateway key list'", _USAGE),
    "gateway_key_label_invalid": (
        "a label is 1 to 64 letters, digits, spaces, dots, hyphens or underscores",
        _USAGE,
    ),
    "gateway_key_expiry_invalid": ("--expires-in-days takes 1 to 3650", _USAGE),
    "gateway_key_limit": ("the gateway holds its maximum of 256 keys; revoke unused ones", _USAGE),
    "gateway_key_output_exists": (
        "the output file already exists; choose a new path (a key is never written over a file)",
        _USAGE,
    ),
    "trusted_console_required": (
        "a key is shown only on your own interactive terminal; run this there or pass "
        "--output-file to write it to a new owner-only file",
        _USAGE,
    ),
}


def _fail(reason: str) -> typer.Exit:
    text, code = _REMEDIES.get(reason, ("the gateway could not do that", _UNSAFE))
    typer.echo(f"{reason}: {text}", err=True)
    return typer.Exit(code)


def _keys_directory() -> Path:
    from finishup.config.paths import state_dir
    from finishup.gateway.keys import GATEWAY_DIR_NAME

    return state_dir() / GATEWAY_DIR_NAME


@gateway_app.command("run")
def gateway_run(
    listen: Annotated[str, typer.Option("--listen", help="HOST:PORT to listen on.")],
    tls_cert: Annotated[
        Path | None, typer.Option("--tls-cert", help="PEM certificate chain.")
    ] = None,
    tls_key: Annotated[Path | None, typer.Option("--tls-key", help="PEM private key.")] = None,
    behind_proxy: Annotated[
        bool,
        typer.Option(
            "--behind-proxy", help="Plain HTTP on loopback, behind a TLS-terminating proxy."
        ),
    ] = False,
) -> None:
    """Serve the HTTPS binding in the foreground until interrupted."""

    from finishup.gateway.serve import GatewayConfigError, run_gateway

    try:
        code = run_gateway(
            listen=listen, tls_cert=tls_cert, tls_key=tls_key, behind_proxy=behind_proxy
        )
    except GatewayConfigError as error:
        raise _fail(error.reason) from None
    if code == 21:
        typer.echo(
            "gateway_stale: the FinishUP service on this host runs another release; restart the "
            "gateway with the same release",
            err=True,
        )
    raise typer.Exit(code)


def _open_new_owner_only(path: Path) -> int:
    """Create ``path`` owner-only (0600); an existing file is never written over."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        return os.open(path, flags, 0o600)
    except FileExistsError:
        raise _fail("gateway_key_output_exists") from None
    except OSError:
        raise _fail("gateway_keys_unsafe") from None


def _stdin_is_terminal() -> bool:
    return sys.stdin.isatty()


def _show_on_console(text: str) -> None:
    from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole

    try:
        with TrustedForegroundConsole() as console:
            console.write("API key (shown once; store it now):\n")
            console.write(text + "\n")
    except TrustedConsoleError:
        raise _fail("trusted_console_required") from None


@key_app.command("create")
def key_create(
    label: Annotated[
        str | None, typer.Option("--label", help="Your name for this key (key list only).")
    ] = None,
    scope: Annotated[
        str | None,
        typer.Option("--scope", help="agent (workflow and status) or operator (adds support)."),
    ] = None,
    expires_in_days: Annotated[
        int | None, typer.Option("--expires-in-days", help="Expire after N days.")
    ] = None,
    rotate: Annotated[
        str | None,
        typer.Option("--rotate", help="Copy label and scope from this key id; revoke it later."),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", help="Write the key to this new owner-only (0600) file."),
    ] = None,
) -> None:
    """Create an API key and show it once (or write it to a new owner-only file)."""

    from finishup.gateway.keys import GatewayKeyError, create_key

    if scope is not None and scope not in {"agent", "operator"}:
        raise _fail("gateway_keys_invalid")
    if (label is None or scope is None) and rotate is None:
        typer.echo("usage: give --label and --scope, or --rotate KEY_ID", err=True)
        raise typer.Exit(_USAGE)
    if output_file is None and not _stdin_is_terminal():
        raise _fail("trusted_console_required")
    # The output file is made first, so a key is never created whose secret cannot be delivered.
    descriptor = None if output_file is None else _open_new_owner_only(output_file)
    try:
        record, key = create_key(
            _keys_directory(),
            label=label,
            scope=cast(Literal["agent", "operator"] | None, scope),
            expires_in_days=expires_in_days,
            rotate=rotate,
        )
    except GatewayKeyError as error:
        if descriptor is not None:
            os.close(descriptor)
            cast(Path, output_file).unlink(missing_ok=True)
        raise _fail(error.reason) from None
    if descriptor is not None:
        try:
            os.write(descriptor, (key + "\n").encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    else:
        _show_on_console(key)
    typer.echo(f"Created key {record.key_id} (scope {record.scope}).")
    if rotate is not None:
        typer.echo(
            f"Log the clients in with the new key, then run "
            f"'finishup service gateway key revoke {rotate}'."
        )


@key_app.command("list")
def key_list(
    json_output: Annotated[bool, typer.Option("--json", help="Emit canonical JSON.")] = False,
) -> None:
    """List the gateway's keys: id, label, scope and times (never a secret)."""

    from finishup.gateway.keys import GatewayKeyError, list_keys

    try:
        keys = list_keys(_keys_directory())
    except GatewayKeyError as error:
        raise _fail(error.reason) from None
    rows: list[JsonValue] = [
        {
            "key_id": key.key_id,
            "label": key.label,
            "scope": key.scope,
            "created_at": key.created_at,
            "expires_at": key.expires_at,
            "revoked_at": key.revoked_at,
            "last_used_at": key.last_used_at,
        }
        for key in keys
    ]
    if json_output:
        sys.stdout.buffer.write(canonical_encode({"keys": rows}) + b"\n")
        sys.stdout.flush()
        return
    if not keys:
        typer.echo("No gateway keys.")
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    for key in keys:
        # The state the gateway itself decides on its next request (revoked first, then expiry).
        state = {"api_key_revoked": "revoked", "api_key_expired": "expired", None: "active"}[
            key.failure(now)
        ]
        typer.echo(
            f"{key.key_id}  {key.scope:<8}  {state:<7}  created {key.created_at}  "
            f"last used {key.last_used_at or 'never'}  {key.label}"
        )


@key_app.command("revoke")
def key_revoke(key_id: Annotated[str, typer.Argument(help="The key id to revoke.")]) -> None:
    """Revoke a key: its next request fails and its sessions close."""

    from finishup.gateway.keys import GatewayKeyError, revoke_key

    try:
        record = revoke_key(_keys_directory(), key_id)
    except GatewayKeyError as error:
        raise _fail(error.reason) from None
    typer.echo(f"Revoked key {record.key_id}.")
