"""``finishup agent run --root <target root>``: the workspace agent of a remote server (ADR-051).

Client processes start it on demand for a remote server target and it stops on its own after 15
minutes without work; ``finishup server disconnect`` stops it sooner. It answers the server's
bounded questions about the project folders this computer's sessions work in (see
``finishup.client.agent``). Scope ``client_only``: it never acts on a server host's own state.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

__all__ = ["agent_app"]

agent_app = typer.Typer(
    help="The workspace agent a remote FinishUP server reads your project through (automatic).",
    no_args_is_help=True,
)


@agent_app.command("run")
def agent_run(
    root: Annotated[
        Path, typer.Option("--root", help="The remote server target's folder on this computer.")
    ],
) -> None:
    """Serve the workspace calls of one remote server target until idle (runs in foreground)."""

    from finishup.client.agent import run_workspace_agent

    raise typer.Exit(run_workspace_agent(root.expanduser().absolute()))
