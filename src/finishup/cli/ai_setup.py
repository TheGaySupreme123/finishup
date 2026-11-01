"""The shared, nonsecret optional-reviewer question (issue #1119)."""

from __future__ import annotations

from pathlib import Path
from typing import Final, Literal

import typer

ReviewerConnection = Literal["codex_subscription", "api_key", "local_only"]
REVIEWER_QUESTION: Final = "How should FinishUP reach an AI reviewer?"
REVIEWER_CHOICES: Final[tuple[tuple[ReviewerConnection, str], ...]] = (
    ("codex_subscription", "Sign in with your ChatGPT subscription (uses Codex)"),
    ("api_key", "Use an API key"),
    ("local_only", "Not now — stay local for now"),
)


def prompt_reviewer_connection() -> ReviewerConnection:
    """An answer chooses a route; it grants no disclosure or credential authority."""

    typer.echo(REVIEWER_QUESTION)
    for index, (_, label) in enumerate(REVIEWER_CHOICES, 1):
        typer.echo(f"  {index}) {label}")
    while True:
        raw = typer.prompt("Reviewer connection", default="1").strip()
        if raw in {"1", "2", "3"}:
            return REVIEWER_CHOICES[int(raw) - 1][0]
        typer.echo("Choose 1, 2, or 3.", err=True)


def prompt_reviewer_binding() -> Path | Literal["codex_subscription", "local_only"] | None:
    """Select only nonsecret configuration; the caller owns privacy and hidden entry."""

    from finishup.cli.provider_binding import prompt_provider_endpoint_binding

    connection = prompt_reviewer_connection()
    if connection != "api_key":
        return connection
    return prompt_provider_endpoint_binding(show_standalone_next_step=False, api_only=True)
