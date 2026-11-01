"""Optional-reviewer selection views; credentials stay on the trusted terminal."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence

from finishup.cli.ai_setup import REVIEWER_CHOICES, REVIEWER_QUESTION
from finishup.tui.widgets.views import BaseView, Option, SelectionView, TextEntryView

Ask = Callable[[BaseView], Awaitable[str | None]]


async def choose_connection(ask: Ask) -> str | None:
    return await ask(
        SelectionView(
            name="reviewer-connection",
            title=REVIEWER_QUESTION,
            options=[Option(key, label) for key, label in REVIEWER_CHOICES],
            hint="enter to choose · esc to cancel",
        )
    )


async def choose_model(ask: Ask, label: str, models: Sequence[str]) -> str | None:
    if models:
        selected = await ask(
            SelectionView(
                name="provider-model",
                title=f"Choose a {label} model",
                options=[
                    Option(str(index), model + (" (recommended)" if index == 1 else ""))
                    for index, model in enumerate(models, 1)
                ]
                + [Option("custom", "Type another model ID")],
                hint="enter to choose · esc to cancel",
            )
        )
        if selected is None:
            return None
        if selected != "custom":
            return models[int(selected) - 1]
    entry = TextEntryView(
        name="provider-custom-model", title=label, label="Model identifier", placeholder="model id"
    )
    if await ask(entry) is None:
        return None
    return entry.value.strip() or None
