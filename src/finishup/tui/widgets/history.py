"""The session header and the scrollable transcript.

The transcript is the product's memory of what it claimed: an append-only list
of completed actions with their certainty symbol intact. An in-flight activity
line is the one exception — it is replaced in place when the work it describes
finishes, so a running step becomes a completed step rather than accumulating a
second line that contradicts the first.
"""

from __future__ import annotations

from rich.text import Text
from textual.containers import VerticalScroll
from textual.widgets import Static

from finishup.tui.events import HistoryEvent, Transcript
from finishup.tui.render import render_session_header
from finishup.tui.symbols import symbol_for
from finishup.tui.widgets.style import COLOURS, styled

__all__ = ["History", "SessionHeader"]


class SessionHeader(Static):
    """The compact rounded header: project, harness state, and privacy posture."""

    def __init__(self) -> None:
        super().__init__(id="session-header")
        self._version = "0.0.0"
        self._project = ""
        self._harness = "not connected"
        self._privacy = "local only"

    def set_state(
        self,
        *,
        version: str | None = None,
        project: str | None = None,
        harness: str | None = None,
        privacy: str | None = None,
    ) -> None:
        if version is not None:
            self._version = version
        if project is not None:
            self._project = project
        if harness is not None:
            self._harness = harness
        if privacy is not None:
            self._privacy = privacy
        self.refresh_header()

    def on_mount(self) -> None:
        self.refresh_header()

    def on_resize(self, event: object) -> None:
        self.refresh_header()

    def refresh_header(self) -> None:
        width = self.size.width or 72
        # A very short terminal cannot spare three lines and a border for chrome.
        compact = (self.screen.size.height or 24) < 16
        self.set_class(compact, "compact")
        if compact:
            self.update(
                Text(f">_ FinishUP v{self._version}  ·  {self._harness}  ·  {self._privacy}")
            )
            return
        lines = render_session_header(
            version=self._version,
            project_root=self._project,
            harness_state=self._harness,
            privacy_summary=self._privacy,
            width=width,
        )
        text = Text()
        for index, line in enumerate(lines):
            if index:
                text.append("\n")
            if index == 0:
                text.append(line, style="bold cyan")
            elif ":" in line:
                label, _, value = line.partition(":")
                text.append(label + ":", style="bright_black")
                text.append(value)
            else:
                text.append(line)
        self.update(text)


class History(VerticalScroll):
    """The scrollable transcript of everything FinishUP did this session."""

    def __init__(self, transcript: Transcript) -> None:
        super().__init__(id="history")
        self._transcript = transcript

    @property
    def transcript(self) -> Transcript:
        return self._transcript

    def append(self, event: HistoryEvent) -> None:
        self._transcript.append(event)
        self.mount(_EventWidget(event))
        self.scroll_end(animate=False)

    def replace_last(self, event: HistoryEvent) -> None:
        """Collapse the in-flight activity line into its finished form."""

        self._transcript.replace_last(event)
        widgets = self.query(_EventWidget)
        if widgets:
            widgets.last().set_event(event)
        else:
            self.mount(_EventWidget(event))
        self.scroll_end(animate=False)

    def clear_events(self) -> None:
        self._transcript.clear()
        self.query(_EventWidget).remove()


class _EventWidget(Static):
    """One transcript entry: a symbol-led title and an optional indented body."""

    def __init__(self, event: HistoryEvent) -> None:
        super().__init__(classes="event")
        self._event = event

    def on_mount(self) -> None:
        self._redraw()

    def set_event(self, event: HistoryEvent) -> None:
        self._event = event
        self._redraw()

    def _redraw(self) -> None:
        event = self._event
        text = Text()
        if event.title:
            text.append(symbol_for(event.level), style=COLOURS[event.level])
            text.append(" ")
            text.append(event.title, style="bold" if event.body else "")
            if event.body:
                text.append("\n")
                text.append_text(styled(f"  {line}" if line else "" for line in event.body))
        else:
            # A titleless event is a rendered block that carries its own symbols.
            text.append_text(styled(event.body))
        if event.has_details:
            text.append("\n")
            text.append("  D for technical details", style="bright_black")
        self.update(text)
