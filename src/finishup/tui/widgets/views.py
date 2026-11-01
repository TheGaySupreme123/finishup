"""The temporary bottom-pane views: pickers, approvals, entry, and details.

Every view here replaces the composer while it is open and restores it exactly
as it was on dismissal. Three rules are load-bearing and are enforced in this
module rather than left to each caller:

* ``Esc`` never means yes. It dismisses with ``None``, and an approval treats
  ``None`` as "no change was made".
* A key that closes a view is consumed by that view. Nothing carries into
  whatever opens next, so an ``Enter`` that confirms one picker can never also
  confirm the picker that replaces it.
* Disabled rows are skipped by the cursor and cannot be chosen, by arrow key or
  by number.

Number shortcuts and other printable keys are only ever interpreted when no text
or secret field has focus.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar, Final

from rich.text import Text
from textual import events
from textual.containers import Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Input, Static

from finishup.tui.symbols import Level, symbol_for
from finishup.tui.text import truncate, wrap
from finishup.tui.widgets.style import styled, styled_line

__all__ = [
    "BACK",
    "ApprovalView",
    "DetailsView",
    "MultiSelectionView",
    "Option",
    "SelectionView",
    "TextEntryView",
    "ViewDismissed",
]

# Going back and cancelling are different answers and must not share one. `Esc` still means
# "stop, change nothing"; this says "re-ask the previous question". The NUL prefix keeps it
# outside the option-key vocabulary, so no view can offer a row that collides with it.
BACK: Final = "\x00back"


@dataclass(frozen=True, slots=True)
class Option:
    """One selectable row."""

    key: str
    label: str
    description: str = ""
    disabled: bool = False
    disabled_reason: str = ""

    @property
    def search_text(self) -> str:
        return f"{self.label} {self.description}".lower()


class ViewDismissed(Message):
    """Posted when a temporary view closes, with the chosen key or ``None``."""

    def __init__(self, view: BaseView, result: str | None) -> None:
        super().__init__()
        self.view = view
        self.result = result


class BaseView(Vertical):
    """Shared behaviour for every temporary bottom-pane view."""

    DEFAULT_CLASSES: ClassVar[str] = "view"
    # The view itself takes focus so its key handling runs even when it holds no
    # input field; without this the hidden composer would keep the keyboard.
    can_focus = True

    def __init__(self, *, name: str, title: str = "", hint: str = "") -> None:
        super().__init__()
        self.view_name = name
        self.technical_details: tuple[str, ...] = ()
        self.title_text = title
        self.hint_text = hint
        self._dismissed = False

    def dismiss(self, result: str | None) -> None:
        """Close once. A second dismissal is ignored, not re-posted."""

        if self._dismissed:
            return
        self._dismissed = True
        self.post_message(ViewDismissed(self, result))

    @property
    def accepts_printable_shortcuts(self) -> bool:
        """False whenever a text or secret field currently has focus."""

        return True


class DetailsView(BaseView):
    """A read-only detail or error panel with its own scroll."""

    def __init__(self, *, name: str, title: str, lines: Sequence[str], hint: str = "") -> None:
        super().__init__(name=name, title=title, hint=hint or "esc to close")
        self._lines = tuple(lines)

    def compose(self):  # pyright: ignore[reportMissingParameterType]
        if self.title_text:
            yield Static(styled_line(self.title_text), classes="view-title")
        body = VerticalScroll(Static(styled(self._lines)), id="details-panel")
        yield body
        yield Static(Text(self.hint_text, style="bright_black"), classes="view-hint")

    def on_mount(self) -> None:
        self.focus()

    def on_key(self, event: events.Key) -> None:
        if event.key in {"escape", "q"}:
            event.stop()
            event.prevent_default()
            self.dismiss(None)


class SelectionView(BaseView):
    """A keyboard-driven picker, optionally with a search field.

    When ``searchable`` is set an ``Input`` takes focus and every printable key
    — digits included — belongs to the query. When it is not set, ``1``-``9``
    select the corresponding enabled row.
    """

    def __init__(
        self,
        *,
        name: str,
        title: str = "",
        body: Sequence[str] = (),
        options: Sequence[Option],
        searchable: bool = False,
        hint: str = "",
        search_placeholder: str = "Type to filter",
        allow_back: bool = False,
    ) -> None:
        super().__init__(name=name, title=title, hint=hint)
        self._all_options = tuple(options)
        self._visible: tuple[Option, ...] = self._all_options
        self._body = tuple(body)
        self._searchable = searchable
        self._placeholder = search_placeholder
        self._cursor = self._first_enabled(self._visible)
        # A searchable view gives every printable key to the query, so 'b' there is a letter
        # the user is typing, never a command. Back is offered only where nothing owns input.
        self._allow_back = allow_back and not searchable
        if self._allow_back and BACK in {option.key for option in self._all_options}:
            raise ValueError("view_back_key_reserved")

    # -- option state ---------------------------------------------------

    @staticmethod
    def _first_enabled(options: Sequence[Option]) -> int:
        for index, option in enumerate(options):
            if not option.disabled:
                return index
        return 0

    @property
    def options(self) -> tuple[Option, ...]:
        return self._visible

    @property
    def cursor(self) -> int:
        return self._cursor

    @property
    def selected(self) -> Option | None:
        if not self._visible:
            return None
        option = self._visible[self._cursor]
        return None if option.disabled else option

    @property
    def accepts_printable_shortcuts(self) -> bool:
        return not self._searchable

    def move(self, delta: int) -> None:
        """Move the cursor, stepping over disabled rows and stopping at the ends."""

        if not self._visible:
            return
        enabled = [index for index, option in enumerate(self._visible) if not option.disabled]
        if not enabled:
            return
        if self._cursor in enabled:
            position = enabled.index(self._cursor)
            position = max(0, min(len(enabled) - 1, position + delta))
        else:
            position = 0 if delta > 0 else len(enabled) - 1
        self._cursor = enabled[position]
        self._refresh_options()

    def jump(self, *, end: bool) -> None:
        enabled = [index for index, option in enumerate(self._visible) if not option.disabled]
        if not enabled:
            return
        self._cursor = enabled[-1] if end else enabled[0]
        self._refresh_options()

    def choose_number(self, number: int) -> bool:
        """Select the ``number``-th visible row if it exists and is enabled."""

        index = number - 1
        if not 0 <= index < len(self._visible) or self._visible[index].disabled:
            return False
        self._cursor = index
        self._refresh_options()
        self.dismiss(self._visible[index].key)
        return True

    def filter(self, query: str) -> None:
        token = query.strip().lower()
        if not token:
            self._visible = self._all_options
        else:
            exact = [o for o in self._all_options if o.label.lower() == token]
            prefix = [
                o for o in self._all_options if o.label.lower().startswith(token) and o not in exact
            ]
            rest = [
                o
                for o in self._all_options
                if token in o.search_text and o not in exact and o not in prefix
            ]
            self._visible = tuple(exact + prefix + rest)
        self._cursor = self._first_enabled(self._visible)
        self._refresh_options()

    # -- rendering ------------------------------------------------------

    def _option_lines(self) -> Text:
        # Before the first layout the widget reports zero width; fall back to a
        # readable default rather than wrapping every label into a column.
        width = max(self.size.width - 2, 1) if self.size.width else 60
        text = Text()
        if not self._visible:
            return Text("no matching options", style="bright_black")
        for index, option in enumerate(self._visible):
            if index:
                text.append("\n")
            selected = index == self._cursor and not option.disabled
            marker = symbol_for(Level.SELECTED) if selected else " "
            number = f"{index + 1}. " if index < 9 and not self._searchable else ""
            label = truncate(f"{marker} {number}{option.label}", width)
            if option.disabled:
                text.append(label, style="bright_black")
                if option.disabled_reason:
                    text.append(f"  ({option.disabled_reason})", style="bright_black")
            elif selected:
                text.append(label, style="bold cyan")
            else:
                text.append(label)
            if option.description:
                for line in wrap(option.description, max(width - 5, 1)):
                    text.append("\n")
                    text.append(truncate(f"     {line}", width), style="bright_black")
        return text

    def compose(self):  # pyright: ignore[reportMissingParameterType]
        if self.title_text:
            yield Static(styled_line(self.title_text), classes="view-title")
        if self._body:
            yield VerticalScroll(Static(styled(self._body)), classes="view-body")
        if self._searchable:
            yield Input(placeholder=self._placeholder, id="view-search", classes="entry")
        yield Static(self._option_lines(), id="option-list")
        if self.hint_text:
            yield Static(Text(self.hint_text, style="bright_black"), classes="view-hint")

    def on_mount(self) -> None:
        if self._searchable:
            self.query_one("#view-search", Input).focus()
        else:
            self.focus()
        self._refresh_options()

    def on_resize(self, event: events.Resize) -> None:
        """Re-lay the rows against the width the widget actually has."""

        self._refresh_options()

    def _refresh_options(self) -> None:
        try:
            option_list = self.query_one("#option-list", Static)
        except NoMatches:
            # Not mounted yet; compose will render the current state.
            return
        option_list.update(self._option_lines())

    # -- input ----------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "view-search":
            event.stop()
            self.filter(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "view-search":
            return
        event.stop()
        event.prevent_default()
        option = self.selected
        if option is not None:
            self.dismiss(option.key)

    def on_key(self, event: events.Key) -> None:
        key = event.key
        if key == "escape":
            event.stop()
            event.prevent_default()
            self.dismiss(None)
            return
        if key in {"up", "down", "pageup", "pagedown", "home", "end"}:
            event.stop()
            event.prevent_default()
            if key == "up":
                self.move(-1)
            elif key == "down":
                self.move(1)
            elif key == "pageup":
                self.move(-5)
            elif key == "pagedown":
                self.move(5)
            else:
                self.jump(end=key == "end")
            return
        if key == "enter":
            event.stop()
            event.prevent_default()
            option = self.selected
            if option is not None:
                self.dismiss(option.key)
            return
        # Printable shortcuts are only ever read when no field owns the keyboard.
        if not self.accepts_printable_shortcuts:
            return
        if self._allow_back and key.lower() == "b":
            event.stop()
            event.prevent_default()
            self.dismiss(BACK)
            return
        if key.isdigit() and key != "0":
            event.stop()
            event.prevent_default()
            self.choose_number(int(key))


class MultiSelectionView(SelectionView):
    """Choose any nonempty subset; Enter submits and Escape always cancels."""

    def __init__(self, *, name: str, options: Sequence[Option], title: str = "") -> None:
        super().__init__(
            name=name,
            title=title,
            options=options,
            hint="space or number to toggle · enter to continue · esc to cancel",
        )
        self._checked: set[str] = set()

    @property
    def selected_keys(self) -> tuple[str, ...]:
        return tuple(option.key for option in self.options if option.key in self._checked)

    def toggle(self, key: str) -> None:
        if any(option.key == key and not option.disabled for option in self.options):
            self._checked.symmetric_difference_update((key,))
            self._refresh_options()

    def _option_lines(self) -> Text:
        text = Text()
        width = max(self.size.width - 2, 1) if self.size.width else 60
        for index, option in enumerate(self.options):
            if index:
                text.append("\n")
            text.append(
                truncate(
                    f"{'›' if index == self._cursor else ' '} {index + 1}. "
                    f"[{'x' if option.key in self._checked else ' '}] {option.label}",
                    width,
                ),
                style="bright_black"
                if option.disabled
                else "bold cyan"
                if index == self._cursor
                else "",
            )
            if option.description:
                for line in wrap(option.description, max(width - 5, 1)):
                    text.append("\n" + truncate(f"     {line}", width), style="bright_black")
        return text

    def on_key(self, event: events.Key) -> None:
        if event.key in {"enter", "space"} or (event.key.isdigit() and event.key != "0"):
            event.stop()
            event.prevent_default()
            if event.key == "enter":
                if self.selected_keys:
                    self.dismiss("submit")
            elif event.key == "space":
                if self.selected is not None:
                    self.toggle(self.selected.key)
            else:
                index = int(event.key) - 1
                if index < len(self.options):
                    self.toggle(self.options[index].key)
            return
        super().on_key(event)


class ApprovalView(SelectionView):
    """A selection whose dismissal without a choice is explicitly *not* approval.

    The affirmative row is never the one a stray ``Enter`` lands on for a
    privacy-widening or otherwise irreversible change: such views are built with
    ``default_to_safe`` so the cursor starts on the declining option.
    """

    def __init__(
        self,
        *,
        name: str,
        title: str,
        body: Sequence[str],
        approve_label: str,
        decline_label: str,
        approve_key: str = "approve",
        decline_key: str = "decline",
        extra: Sequence[Option] = (),
        default_to_safe: bool = False,
        hint: str = "enter to choose · esc to cancel · D for technical details",
        allow_back: bool = False,
    ) -> None:
        options = [
            Option(approve_key, approve_label),
            Option(decline_key, decline_label),
            *extra,
        ]
        super().__init__(
            name=name,
            title=title,
            body=body,
            options=options,
            searchable=False,
            hint=hint,
            allow_back=allow_back,
        )
        if default_to_safe:
            self._cursor = 1

    def on_key(self, event: events.Key) -> None:
        # 'D' opens technical details; the app owns what that means per view.
        if event.key.lower() == "d" and self.accepts_printable_shortcuts:
            event.stop()
            event.prevent_default()
            self.post_message(DetailsRequested(self))
            return
        super().on_key(event)


class DetailsRequested(Message):
    """Posted when the user asks a view for its technical details."""

    def __init__(self, view: BaseView) -> None:
        super().__init__()
        self.view = view


class TextEntryView(BaseView):
    """A focused single-line entry. Printable shortcuts are inert while it is open.

    ``password`` is supported for completeness, but FinishUP never routes a real
    secret through it: provider keys and vault passphrases go to the confidential
    ceremony on the controlling terminal instead, so no secret byte can reach a
    widget, the transcript, or a snapshot.
    """

    def __init__(
        self,
        *,
        name: str,
        title: str,
        label: str,
        initial: str = "",
        placeholder: str = "",
        password: bool = False,
        empty_is_cancel: bool = True,
        hint: str = "enter to confirm · esc to cancel",
    ) -> None:
        super().__init__(name=name, title=title, hint=hint)
        self._label = label
        self._initial = initial
        self._placeholder = placeholder
        self._password = password
        self._empty_is_cancel = empty_is_cancel
        self.value: str = initial

    @property
    def accepts_printable_shortcuts(self) -> bool:
        return False

    def compose(self):  # pyright: ignore[reportMissingParameterType]
        if self.title_text:
            yield Static(styled_line(self.title_text), classes="view-title")
        yield Static(Text(self._label), classes="entry-label")
        yield Input(
            value=self._initial,
            placeholder=self._placeholder,
            password=self._password,
            id="view-entry",
            classes="entry",
        )
        yield Static(Text(self.hint_text, style="bright_black"), classes="view-hint")

    def on_mount(self) -> None:
        self.query_one("#view-entry", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        event.prevent_default()
        self.value = event.value
        submitted = bool(event.value.strip()) or not self._empty_is_cancel
        self.dismiss("submit" if submitted else None)

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            event.stop()
            event.prevent_default()
            self.dismiss(None)


def option_rows(view: Widget) -> tuple[Option, ...]:
    """Return the visible options of a selection view, for tests and callers."""

    return view.options if isinstance(view, SelectionView) else ()
