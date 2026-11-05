"""``finishup connector run --root R``: the relay behind a remote server target (hidden).

Started on demand by every client surface for a remote target root, and by ``finishup server
connect``; an owner may also run it in the foreground. ADR-051, approach A.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Final

import typer

__all__ = ["connector_app"]

connector_app = typer.Typer(
    help="Relay a remote FinishUP server target's local endpoint (started on demand).",
    no_args_is_help=True,
    hidden=True,
)

_REFUSALS: Final = {
    2: (
        "connector_root_invalid: give a remote server target's own root; an isolation variable "
        "or runtime pin naming another root also refuses"
    ),
    20: "connector_failed: the target's local endpoint could not be bound safely",
}


@connector_app.command("run")
def connector_run(
    root: Annotated[Path, typer.Option("--root", help="The remote target's root.")],
) -> None:
    """Serve the remote target root's control endpoint until stopped or idle for 15 minutes."""

    from finishup.client.connector import run_connector

    code = run_connector(root)
    if code in _REFUSALS:
        typer.echo(_REFUSALS[code], err=True)
    raise typer.Exit(code)
