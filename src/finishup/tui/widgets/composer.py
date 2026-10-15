"""The persistent composer, its slash-command popup, and the contextual footer.

The composer is the one surface that survives every temporary view: opening a
picker hides it, and dismissing that picker restores whatever was half-typed.
That is why the composer owns its text rather than being rebuilt on each mount.
"""

from __future__ import annotations

from typing import ClassVar

from rich.text import Text
from textual import events
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Input, Static

from finishup.tui.commands import SlashCommand, filter_commands
from finishup.tui.symbols import Level, symbol_for
from finishup.tui.text import truncate

__all__ = ["CommandPopup", "Composer", "CommandSubmitted", "Footer"]


class CommandSubmitted(Message):
    """Posted when the composer accepts a line of input."""

    def __init__(self, value: str) -> None:
        super().__init__()
        self.value = value


class CommandPopup(Static):
    """The filtered slash-command list shown above the composer while typing."""

    def __init__(self) -> None:
        super().__init__(id="command-popup")
        self._matches: tuple[SlashCommand, ...] = ()
        self._cursor = 0
        self.display = False

    @property
    def matches(self) -> tuple[SlashCommand, ...]:
        return self._matches

    @property
    def selected(self) -> SlashCommand | None:
        if not self._matches:
            return None
        return self._matches[min(self._cursor, len(self._matches) - 1)]

    def update_query(self, query: str) -> None:
        """Show and rank matches, or hide entirely when the line is not a command."""

        if not query.startswith("/"):
            self._matches = ()
            self.display = False
            return
        self._matches = filter_commands(query)
        self._cursor = 0
        self.display = bool(self._matches)
        self._redraw()

    def move(self, delta: int) -> None:
        if not self._matches:
            return
        self._cursor = max(0, min(len(self._matches) - 1, self._cursor + delta))
        self._redraw()

    def close(self) -> None:
        self._matches = ()
        self.display = False

    def _redraw(self) -> None:
        width = max(self.size.width or 60, 40)
        text = Text()
        name_width = max((len(item.token) for item in self._matches), default=0)
        for index, command in enumerate(self._matches):
            if index:
                text.append("\n")
            selected = index == self._cursor
            marker = symbol_for(Level.SELECTED) if selected else " "
            text.append(f"{marker} ")
            text.append(command.token.ljust(name_width), style="bold cyan" if selected else "cyan")
            text.append(
                "  " + truncate(command.summary, max(width - name_width - 6, 12)),
                style="bright_black",
            )
        self.update(text)


class Composer(Vertical):
    """The persistent input line plus its command popup."""

    DEFAULT_ID: ClassVar[str] = "composer-area"

    def __init__(self) -> None:
        super().__init__(id="composer-area")
        self._popup = CommandPopup()
        self._input = Input(placeholder="Type / for FinishUP commands", id="composer")

    @property
    def popup(self) -> CommandPopup:
        return self._popup

    @property
    def text(self) -> str:
        return self._input.value

    @text.setter
    def text(self, value: str) -> None:
        self._input.value = value

    def compose(self):  # pyright: ignore[reportMissingParameterType]
        yield self._popup
        with Horizontal(id="composer-row"):
            yield Static(Text(f"{symbol_for(Level.SELECTED)} ", style="cyan"))
            yield self._input

    def focus_input(self) -> None:
        self._input.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "composer":
            return
        event.stop()
        self._popup.update_query(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "composer":
            return
        event.stop()
        event.prevent_default()
        selected = self._popup.selected
        value = event.value
        # A visible popup means the user is choosing from it, not typing free text.
        if self._popup.display and selected is not None:
            _, separator, arguments = value.strip().partition(" ")
            value = selected.token + (f" {arguments}" if separator else "")
        self._popup.close()
        self._input.value = ""
        self.post_message(CommandSubmitted(value))

    def on_key(self, event: events.Key) -> None:
        if not self._popup.display:
            return
        if event.key in {"up", "down"}:
            event.stop()
            event.prevent_default()
            self._popup.move(-1 if event.key == "up" else 1)
        elif event.key == "escape":
            event.stop()
            event.prevent_default()
            self._popup.close()


class Footer(Static):
    """A one-line contextual footer: what to press, and where things stand."""

    def __init__(self) -> None:
        super().__init__(id="footer-row")
        self._left = "? for shortcuts"
        self._right = ""

    def set_state(self, *, left: str | None = None, right: str | None = None) -> None:
        if left is not None:
            self._left = left
        if right is not None:
            self._right = right
        self._redraw()

    def on_mount(self) -> None:
        self._redraw()

    def on_resize(self, event: events.Resize) -> None:
        self._redraw()

    def _redraw(self) -> None:
        width = max(self.size.width or 60, 20)
        gap = width - len(self._left) - len(self._right)
        if gap < 1:
            self.update(Text(truncate(self._left, width), style="bright_black"))
            return
        self.update(Text(f"{self._left}{' ' * gap}{self._right}", style="bright_black"))
