"""``finishup service api-key``: the network API keys of this server host (ADR-051).

These commands run on the server host only (scope ``server_host``) and edit the service's own key
file, ``<state>/network/api-keys.json``, directly under its lock; nothing here reaches the service
over the network, and the running service picks a change up on its next request.

* ``create --label L --scope agent|operator [--expires-in-days N] [--rotate KEY_ID]
  [--output-file F]`` prints the new key once (or writes it to a new owner-only file). The key is
  stored only as a salted hash. ``--rotate`` keeps an older key's principal, so a client that
  switches to the new key keeps reaching the same workspaces; revoke the old key afterwards.
* ``list [--json]`` shows each key's id, label, scope, state, and dates (never a key).
* ``revoke KEY_ID`` ends a key; its next request and its registered agents are refused.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Final, NoReturn, cast

import typer

from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.service.api_keys import ApiKeyError, ApiKeyRecord, default_api_key_store
from finishup.service.network_protocol import ApiScope

__all__ = ["api_key_app"]

api_key_app = typer.Typer(
    help="Create, list, and revoke this server's network API keys (run on the server host).",
    no_args_is_help=True,
)

_USAGE: Final = 2
_UNSAFE: Final = 20
_MESSAGES: Final[dict[str, tuple[str, int]]] = {
    "api_key_label_invalid": (
        "a label is 1 to 48 letters, digits, spaces, dots, underscores, or hyphens",
        _USAGE,
    ),
    "api_key_scope_invalid": ("the scope is 'agent' or 'operator'", _USAGE),
    "api_key_expiry_invalid": ("--expires-in-days is a whole number from 1 to 3650", _USAGE),
    "api_key_unknown": ("no key has that id; 'finishup service api-key list' shows them", _USAGE),
    "api_key_limit": ("this server already holds 256 keys; revoke unused ones first", _USAGE),
    "api_keys_unsafe": (
        "the key file or its folder is not owner-only, or is not a regular file; fix its "
        "permissions and retry",
        _UNSAFE,
    ),
    "api_keys_damaged": (
        "the key file is damaged; restore it from a backup or move it aside to start over",
        _UNSAFE,
    ),
    "output_file_unavailable": (
        "the output file could not be created; give a new path in an existing folder",
        _USAGE,
    ),
}


def _fail(reason: str) -> NoReturn:
    message, code = _MESSAGES.get(reason, ("the key file could not be used", _UNSAFE))
    typer.echo(f"{reason}: {message}", err=True)
    raise typer.Exit(code)


def _write_key_file(path: Path, text: str) -> None:
    """Write the key to a new owner-only file; an existing path is never replaced."""

    target = path.expanduser()
    target = target if target.is_absolute() else Path.cwd() / target
    try:
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
    except OSError:
        _fail("output_file_unavailable")
    try:
        os.write(descriptor, (text + "\n").encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@api_key_app.command("create")
def api_key_create(
    label: Annotated[str, typer.Option("--label", help="Your name for the key (shown in list).")],
    scope: Annotated[
        str, typer.Option("--scope", help="agent (agents and hooks) or operator (management).")
    ],
    expires_in_days: Annotated[
        int | None, typer.Option("--expires-in-days", help="Expire the key after N days.")
    ] = None,
    rotate: Annotated[
        str | None,
        typer.Option("--rotate", help="Replace KEY_ID: keep its principal (revoke it after)."),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", help="Write the key to a new owner-only file instead."),
    ] = None,
) -> None:
    """Create a key and show it once; only a salted hash of it is stored."""

    if scope not in {"agent", "operator"}:
        _fail("api_key_scope_invalid")
    try:
        record, text = default_api_key_store().create(
            label,
            cast(ApiScope, scope),
            expires_in_days=expires_in_days,
            rotate=rotate,
        )
    except ApiKeyError as error:
        _fail(error.reason)
    if output_file is not None:
        _write_key_file(output_file, text)
        typer.echo(f"Created key {record.key_id} ({record.scope}); written to the output file.")
        return
    typer.echo(f"Created key {record.key_id} ({record.scope}). It is shown once:")
    typer.echo(text)
    typer.echo("On the client: finishup server login NAME (paste it at the hidden prompt).")


def _row(record: ApiKeyRecord, now: datetime) -> dict[str, JsonValue]:
    return {
        "key_id": record.key_id,
        "label": record.label,
        "scope": record.scope,
        "state": record.state(now),
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "revoked_at": record.revoked_at,
    }


@api_key_app.command("list")
def api_key_list(
    json_output: Annotated[bool, typer.Option("--json", help="Emit canonical JSON.")] = False,
) -> None:
    """List keys: id, label, scope, state, and dates (never a key)."""

    try:
        records = default_api_key_store().records()
    except ApiKeyError as error:
        _fail(error.reason)
    now = datetime.now(UTC)
    rows = [_row(record, now) for record in records]
    if json_output or not sys.stdout.isatty():
        document: dict[str, JsonValue] = {
            "keys": cast(JsonValue, rows),
            "schema": "yoetz.api-key-list/1",
        }
        sys.stdout.buffer.write(canonical_encode(document) + b"\n")
        sys.stdout.flush()
        return
    if not rows:
        typer.echo("No network API keys.")
        return
    for row in rows:
        expires = "" if row["expires_at"] is None else f", expires {row['expires_at']}"
        typer.echo(
            f"{row['key_id']}  {row['scope']:<8}  {row['state']:<7}  {row['label']}  "
            f"(created {row['created_at']}{expires})"
        )


@api_key_app.command("revoke")
def api_key_revoke(key_id: Annotated[str, typer.Argument(help="The key id to revoke.")]) -> None:
    """Revoke a key; its next request and its registered agents are refused."""

    try:
        revoked = default_api_key_store().revoke(key_id)
    except ApiKeyError as error:
        _fail(error.reason)
    typer.echo(f"Revoked key {key_id}." if revoked else f"Key {key_id} was already revoked.")
