"""The FinishUP full-screen terminal application.

One continuous surface: a compact session header, a scrollable transcript, and a
bottom pane that is either the composer or a temporary view stacked over it.
There is no settings dashboard, no sidebar, and no page chrome, because the
interaction this product wants is a calm conversation about verification rather
than an administration console.

Flows read as linear ``async`` functions. ``ask()`` opens a temporary view and
awaits its dismissal, so a first-run sequence or a provider setup is written the
way it is experienced — one step after another, each completed step collapsing
into a short line in the transcript above the active one. Every step's actual
work is delegated to :mod:`finishup.tui.runtime`, which is the only thing here that
talks to the application services; this module decides what to show, never what
is true.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar, Final, Literal, cast

from textual import events, on
from textual.app import App, ComposeResult, SuspendNotSupported
from textual.containers import Vertical
from textual.css.query import NoMatches

from finishup import __version__
from finishup.domain.observation_budget import (
    LARGEST_SUPPORTED_QUEUE_COUNT,
    MIN_CUSTOM_QUEUE_COUNT,
    CapacityRequest,
    parse_capacity_request,
)
from finishup.domain.observation_capacity_policy import (
    WORKSPACE_PLACEHOLDER,
    canonical_safe_command,
    render_capacity_disclosure_lines,
)
from finishup.legacy_names import LAUNCHER_NAME, LEGACY_LAUNCHER_NAME, RENAME_NOTE
from finishup.tui.commands import SLASH_COMMANDS, command_named
from finishup.tui.events import HistoryEvent, Transcript
from finishup.tui.models import (
    PRIVACY_RECIPES,
    CheckMode,
    Detection,
    HarnessOption,
    IntegrationPlan,
    LayerState,
    PrivacyChoice,
    StorageChoice,
)
from finishup.tui.render import (
    render_detection,
    render_doctor,
    render_finish,
    render_foreign_entry,
    render_integration_preview,
    render_integration_technical_details,
    render_layers,
    render_project_trust,
    render_provider_endpoint,
    render_provider_stored,
    render_receipt,
    render_status,
    render_welcome,
    render_work_detail,
)
from finishup.tui.runtime import FinishUpRuntime, ObservationCapacityUnavailable, RuntimeError_
from finishup.tui.styles import FINISHUP_CSS
from finishup.tui.symbols import Level
from finishup.tui.text import middle_truncate
from finishup.tui.widgets.composer import CommandSubmitted, Composer, Footer
from finishup.tui.widgets.history import History, SessionHeader
from finishup.tui.widgets.views import (
    BACK,
    ApprovalView,
    BaseView,
    DetailsRequested,
    DetailsView,
    Option,
    SelectionView,
    TextEntryView,
    ViewDismissed,
)

__all__ = ["FinishUpTui"]

_CODEX_EFFORTS: Final[tuple[str, ...]] = ("high", "low", "medium", "xhigh", "max", "ultra")
_SHORTCUTS: Final[tuple[str, ...]] = (
    "Up / Down     move through options",
    "Enter         confirm or select",
    "Esc           go back, cancel, or close this view",
    "1 to 9        pick a numbered option",
    "/             open the command list",
    "?             show these shortcuts",
    "D             show technical details where offered",
    "Ctrl+C        interrupt work, or close this view",
    "Page Up/Down  scroll a long list or the history",
    "Home / End    jump to the first or last option",
)

_NEVER_SENT: Final[tuple[str, ...]] = (
    "API keys, passphrases, and anything else secret",
    "Raw repository file contents that no rule selected",
    "Absolute filesystem paths",
)

# Which durable profile each recipe lands on, used only to notice that the current policy
# already matches the recommendation and stop offering it as a change.
_PROFILE_FOR_RECIPE: Final[dict[str, str]] = {
    "private": PrivacyChoice.LOCAL_ONLY.value,
    "metadata_only": PrivacyChoice.CONFIRM_EVERY_REQUEST.value,
}


def relaunch_command(package: str) -> str:
    """The launcher an upgraded install has on PATH, for "then re-run <launcher>" (ADR-048).

    The transitional ``yoetz`` distribution links only ``yoetz``, so naming ``finishup`` there
    would send the user to a command that does not exist.
    """

    return LEGACY_LAUNCHER_NAME if package == LEGACY_LAUNCHER_NAME else LAUNCHER_NAME


def _progress_lines(lines: Sequence[str]) -> tuple[str, ...]:
    """Keep only the structural review-progress lines of a rendered operation page."""

    return tuple(line for line in lines if line.startswith("Semantic review"))


# -- /observe capacity helpers ----------------------------------------------
#
# Every value below is read from a product-built record and re-validated as a closed token or
# a bounded integer before it is shown, so a malformed payload renders as "unknown" instead of
# carrying arbitrary text into the transcript.

_MIN_QUEUE_ROWS: Final = MIN_CUSTOM_QUEUE_COUNT
_MAX_QUEUE_ROWS: Final = LARGEST_SUPPORTED_QUEUE_COUNT
_CAPACITY_UNCHANGED: Final = "Capacity was left unchanged."
_CAPACITY_LABELS: Final = frozenset({"standard", "larger", "largest", "custom"})
_DETAILS: Final = frozenset({"focused", "detailed"})
_LIMITING_DIMENSIONS: Final = frozenset({"count", "bytes", "oldest_age", "capture_backlog"})
_CAPACITY_REASONS: Final[dict[str, str]] = {
    "selected": "selected",
    "workspace_aggregate": "workspace aggregate (the largest active selection in this workspace)",
}
_CAPACITY_WORDS: Final[dict[str, str]] = {
    "recommended": "recommended",
    "larger": "larger",
    "largest": "largest",
    "no_cap": "no_cap",
}
_PAUSE_COMMAND: Final = f"finishup observe pause --workspace {WORKSPACE_PLACEHOLDER}"
_RESUME_COMMAND: Final = f"finishup observe resume --workspace {WORKSPACE_PLACEHOLDER}"
_REVOKE_COMMAND: Final = (
    f"finishup observe selection-revoke --workspace {WORKSPACE_PLACEHOLDER} --persist"
)
_MIB: Final = 1024 * 1024


def _mapping_or_empty(value: object) -> Mapping[str, object]:
    return cast(Mapping[str, object], value) if isinstance(value, Mapping) else {}


def _closed_token(value: object, allowed: frozenset[str]) -> str:
    return value if type(value) is str and value in allowed else "unknown"


def _bounded_count(value: object) -> int | None:
    return value if type(value) is int and 0 < value <= _MAX_QUEUE_ROWS else None


def _capacity_phrase(count: object, label: object) -> str:
    rows = _bounded_count(count)
    if rows is None:
        return "unknown"
    return f"{rows:,} rows ({_closed_token(label, _CAPACITY_LABELS)})"


def _selection_capacity_phrase(
    selection: Mapping[str, object], fallback: Mapping[str, object]
) -> str:
    """Name a selection's queue rows and label, preferring the selection record."""

    label = selection.get("capacity_profile", selection.get("label"))
    phrase = _capacity_phrase(selection.get("queue_count"), label)
    if phrase != "unknown" and _closed_token(label, _CAPACITY_LABELS) != "unknown":
        return phrase
    fallback_phrase = _capacity_phrase(fallback.get("queue_count"), fallback.get("label"))
    return fallback_phrase if fallback_phrase != "unknown" else phrase


def _disclosure_command(disclosure: Mapping[str, object], key: str, fallback: str) -> str:
    """Return a disclosure command when it is a safe placeholder command, else ``fallback``.

    A record written before the rename is rendered with the current launcher (ADR-048).
    """

    command = canonical_safe_command(disclosure.get(key))
    return fallback if command is None else command


def _capacity_request_for(choice: str) -> CapacityRequest | None:
    word = _CAPACITY_WORDS.get(choice)
    return None if word is None else parse_capacity_request(word)


def _whole_mib(value: object) -> str:
    if type(value) is int and value > 0 and value % _MIB == 0:
        return f"{value // _MIB:,} MiB"
    if type(value) is int and value > 0:
        return f"{value:,} bytes"
    return "unknown"


def _no_cap_line(no_cap: Mapping[str, object]) -> str:
    if no_cap.get("available") is False and no_cap.get("reason") == "state_document_ceiling":
        ceiling = _whole_mib(no_cap.get("state_document_ceiling_bytes"))
        return f"no FinishUP cap: unavailable (state document ceiling {ceiling})"
    return "no FinishUP cap: unknown"


def _effective_budget_lines(budget: Mapping[str, object]) -> tuple[str, ...]:
    """Summarize the effective-budget record: capacity, closest limit, no-cap availability."""

    if not budget:
        return (
            "capacity: unknown",
            "closest limit: unknown",
            "no FinishUP cap: unknown",
        )
    selected = _capacity_phrase(
        budget.get("selected_queue_count"), budget.get("selected_capacity_label")
    )
    effective = _capacity_phrase(
        budget.get("effective_queue_count"), budget.get("effective_capacity_label")
    )
    reason = budget.get("effective_reason")
    reason_text = (
        _CAPACITY_REASONS[reason]
        if type(reason) is str and reason in _CAPACITY_REASONS
        else "unknown"
    )
    dimension = _closed_token(budget.get("limiting_dimension"), _LIMITING_DIMENSIONS)
    utilization = budget.get("utilization_bps")
    usage = (
        f"{utilization / 100:.2f}% used ({utilization} bps)"
        if type(utilization) is int and 0 <= utilization <= 1_000_000
        else "usage unknown"
    )
    return (
        f"capacity: selected {selected}; effective {effective}",
        f"capacity reason: {reason_text}",
        f"closest limit: {dimension}; {usage}",
        _no_cap_line(_mapping_or_empty(budget.get("no_cap"))),
    )


class FinishUpTui(App[int]):
    """The interactive FinishUP surface. A presentation layer over existing services."""

    CSS: ClassVar[str] = FINISHUP_CSS
    TITLE = "FinishUP"
    BINDINGS: ClassVar[list[Any]] = []
    # How often a running check's structural progress is re-read while its result is awaited.
    progress_poll_seconds: float = 5.0

    def __init__(
        self,
        runtime: FinishUpRuntime | None = None,
        *,
        first_run: bool = False,
        cwd: Path | None = None,
    ) -> None:
        super().__init__()
        self.runtime = runtime or FinishUpRuntime(cwd=cwd)
        self.first_run = first_run
        self.transcript = Transcript()
        self._stack: list[BaseView] = []
        self._pending: dict[int, asyncio.Future[str | None]] = {}
        self._flow: Any = None
        self._detection: Detection | None = None
        self._active_task_title: str | None = None
        self.exit_code = 0

    # -- layout ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield SessionHeader()
        yield History(self.transcript)
        with Vertical(id="bottom-pane"):
            yield Composer()
            yield Footer()

    @property
    def header_widget(self) -> SessionHeader:
        return self.query_one(SessionHeader)

    @property
    def history(self) -> History:
        return self.query_one(History)

    @property
    def composer(self) -> Composer:
        return self.query_one(Composer)

    @property
    def footer_widget(self) -> Footer:
        return self.query_one(Footer)

    @property
    def open_view(self) -> BaseView | None:
        return self._stack[-1] if self._stack else None

    async def on_mount(self) -> None:
        self.header_widget.set_state(version=__version__, project=str(self.runtime.project_root()))
        self.composer.focus_input()
        self._flow = self.run_worker(
            self._first_run_flow() if self.first_run else self._resume_flow(),
            name="flow",
            exclusive=True,
        )

    # -- transcript helpers ---------------------------------------------

    def say(
        self,
        level: Level,
        title: str,
        body: Sequence[str] = (),
        *,
        details: Sequence[str] = (),
    ) -> HistoryEvent:
        event = HistoryEvent(level, title, tuple(body), tuple(details))
        self.history.append(event)
        return event

    def settle(
        self,
        level: Level,
        title: str,
        body: Sequence[str] = (),
        *,
        details: Sequence[str] = (),
    ) -> HistoryEvent:
        """Replace the in-flight activity line with its completed form."""

        event = HistoryEvent(level, title, tuple(body), tuple(details))
        self.history.replace_last(event)
        return event

    @property
    def body_width(self) -> int:
        return max((self.size.width or 80) - 4, 32)

    # -- temporary view stack -------------------------------------------

    def push_view(self, view: BaseView) -> None:
        try:
            pane = self.query_one("#bottom-pane", Vertical)
        except NoMatches:
            return
        if self._stack:
            self._stack[-1].display = False
        else:
            self.composer.display = False
        self._stack.append(view)
        pane.mount(view, before=self.footer_widget)
        self.footer_widget.set_state(left="esc to go back")

    async def pop_view(self) -> BaseView | None:
        """Close the top view and restore whatever was underneath it.

        Tolerates a partially torn-down screen: a flow cancelled during shutdown
        unwinds through here, and by then the composer may already be gone.
        """

        if not self._stack:
            return None
        view = self._stack.pop()
        try:
            await view.remove()
            if self._stack:
                self._stack[-1].display = True
                self._stack[-1].focus()
            else:
                self.composer.display = True
                self.composer.focus_input()
                self.footer_widget.set_state(left="? for shortcuts")
        except NoMatches:
            pass
        return view

    async def ask(self, view: BaseView) -> str | None:
        """Open a temporary view and wait for the user to resolve it.

        The composer keeps its half-typed text while a view is open, so
        dismissing one restores exactly what the user had been writing.
        """

        future: asyncio.Future[str | None] = asyncio.get_running_loop().create_future()
        self._pending[id(view)] = future
        self.push_view(view)
        try:
            return await future
        except asyncio.CancelledError:
            self._pending.pop(id(view), None)
            if self.open_view is view:
                await self.pop_view()
            raise

    @on(ViewDismissed)
    async def _on_view_dismissed(self, message: ViewDismissed) -> None:
        message.stop()
        future = self._pending.pop(id(message.view), None)
        if self.open_view is message.view:
            await self.pop_view()
        if future is not None and not future.done():
            future.set_result(message.result)

    @on(DetailsRequested)
    async def _on_details_requested(self, message: DetailsRequested) -> None:
        message.stop()
        lines = message.view.technical_details
        if not lines:
            event = self.transcript.latest_with_details()
            lines = event.details if event is not None else ("No technical details recorded.",)
        await self.ask(DetailsView(name="details", title="Technical details", lines=tuple(lines)))

    # -- key handling ----------------------------------------------------

    async def on_key(self, event: events.Key) -> None:
        view = self.open_view
        if event.key == "question_mark" and (view is None or view.accepts_printable_shortcuts):
            event.stop()
            event.prevent_default()
            await self.ask(
                DetailsView(name="shortcuts", title="Keyboard shortcuts", lines=_SHORTCUTS)
            )
            return
        if event.key.lower() != "d" or view is not None:
            return
        try:
            composer_text = self.composer.text
        except NoMatches:
            return
        if not composer_text:
            latest = self.transcript.latest_with_details()
            if latest is not None:
                event.stop()
                event.prevent_default()
                await self.ask(
                    DetailsView(name="details", title="Technical details", lines=latest.details)
                )

    async def action_interrupt(self) -> None:
        """Ctrl+C: close a temporary view, else stop active work, else leave."""

        if self._stack:
            view = self.open_view
            if view is not None:
                view.dismiss(None)
            return
        flow = self._flow
        if flow is not None and not flow.is_finished:
            flow.cancel()
            self.say(Level.UNPROVEN, "Stopped. Nothing further was changed.")
            self._flow = None
            return
        self.exit(self.exit_code)

    async def on_event(self, event: events.Event) -> None:
        # Textual delivers Ctrl+C as a key when the app owns the terminal.
        if isinstance(event, events.Key) and event.key == "ctrl+c":
            event.stop()
            event.prevent_default()
            await self.action_interrupt()
            return
        await super().on_event(event)

    # -- composer --------------------------------------------------------

    @on(CommandSubmitted)
    async def _on_command(self, message: CommandSubmitted) -> None:
        message.stop()
        raw = message.value.strip()
        if not raw:
            return
        command = command_named(raw)
        if command is None:
            self.say(
                Level.UNPROVEN,
                f"{raw} is not a FinishUP command",
                ("Type / to see what is available.",),
            )
            return
        self._flow = self.run_worker(self._dispatch(command.name), name="command", exclusive=True)

    async def _dispatch(self, name: str) -> None:
        handlers: dict[str, Callable[[], Awaitable[None]]] = {
            "status": self.command_status,
            "observe": self.command_observe,
            "work": self.command_work,
            "lineage": self.command_lineage,
            "project": self.command_project,
            "findings": self.command_findings,
            "check": self.command_check,
            "progress": self.command_progress,
            "receipt": self.command_receipt,
            "connect": self.command_connect,
            "disconnect": self.command_disconnect,
            "privacy": self.command_privacy,
            "provider": self.command_provider,
            "service": self.command_service,
            "doctor": self.command_doctor,
            "help": self.command_help,
            "quit": self.command_quit,
        }
        handler = handlers.get(name)
        if handler is None:
            return
        try:
            await handler()
        except asyncio.CancelledError:
            raise
        except RuntimeError_ as error:
            self._report(error)

    def _report(self, error: RuntimeError_) -> None:
        from finishup.cli.render import render_local_recovery_lines

        extra = (f"Reason: {error.reason}", *render_local_recovery_lines(error.reason))
        self.say(
            Level.BLOCKED,
            error.message,
            extra,
            details=error.details or (f"reason={error.reason}",),
        )

    # ------------------------------------------------------------------
    # First run
    # ------------------------------------------------------------------

    async def _first_run_flow(self) -> None:
        detection = await self.runtime.detect()
        self._detection = detection
        self.say(Level.ACTIVE, "", render_welcome(self.body_width))
        self.say(Level.ACTIVE, "", render_detection(detection, self.body_width))
        await self._refresh_header()

        choice = await self.ask(
            SelectionView(
                name="welcome",
                options=[
                    Option(
                        "connect",
                        "Connect FinishUP to an agent",
                        "Recommended. Adds the local integration for this project.",
                        disabled=not detection.harnesses,
                        disabled_reason="no agent installation found",
                    ),
                    Option(
                        "local",
                        "Set up FinishUP without an agent",
                        "Use local checks and receipts from the terminal.",
                    ),
                    Option("exit", "Exit"),
                ],
                hint="press enter to continue",
            )
        )
        if choice in {None, "exit"}:
            self.say(Level.OPTIONAL, "Setup stopped. Nothing was changed.")
            self.exit(0)
            return
        if choice == "local":
            review = await self._ask_review_mode(allow_back=True)
            while review == BACK:
                review = await self._ask_review_mode(allow_back=True)
            if review is None:
                self.say(Level.OPTIONAL, "Setup stopped. Nothing was changed.")
                return
            await self._choose_storage(detection)
            await self._run_initial_review(review, connected=False)
            return

        # Each question can send the user back to the one before it, so the answered steps are
        # walked as a cursor rather than a straight line. Only the questions run in this loop;
        # once `_connect` applies a change there is nothing to step back to, and the loop ends.
        option: HarnessOption | None = None
        codex_home: Path | None = None
        review: str | None = None
        step = 0
        while step < 4:
            if step == 0:
                option = await self._choose_harness(detection.harnesses)
                if option is None:
                    self.say(Level.OPTIONAL, "Setup stopped. Nothing was changed.")
                    return
                if option.host != "codex":
                    review = await self._ask_review_mode()
                    if review is None:
                        return
                    if await self._connect_selected_host(
                        option, route="policy" if review == "semantic" else "strict"
                    ):
                        await self._choose_storage(detection)
                        await self._run_initial_review(review, connected=True)
                    return
                codex_home = None
                step = 1
            elif step == 1:
                assert option is not None
                codex_home = await self._choose_codex_home(option)
                if codex_home is None:
                    self.say(Level.OPTIONAL, "Setup stopped. Nothing was changed.")
                    return
                step = 2
            elif step == 2:
                trust = await self._confirm_project_trust(detection, allow_back=True)
                if trust is BACK:
                    step = 0
                    continue
                if not trust:
                    return
                step = 3
            else:
                # The review answer decides which MCP command is registered, so it is asked
                # before the registration -- and before the approval screen that shows that
                # command. Registering first and asking after is how an AI-powered review install ends
                # up on the strict route.
                review = await self._ask_review_mode(allow_back=True)
                if review == BACK:
                    step = 2
                    continue
                if review is None:
                    self.say(Level.OPTIONAL, "Setup stopped. Nothing was changed.")
                    return
                step = 4

        assert option is not None
        assert codex_home is not None
        if not await self._connect(
            option, codex_home, "policy" if review == "semantic" else "strict"
        ):
            return
        await self._choose_storage(detection)
        await self._run_initial_review(review, connected=True, option=option, codex_home=codex_home)

    async def _ask_review_mode(self, *, allow_back: bool = False) -> str | None:
        """Ask the posture question only; applying the answer belongs to the caller.

        AI-powered review is listed first, so it is where the cursor rests. That is a choice
        about this question, not about what an installation seeds: the durable policy is still
        ``local_only``, and this answer only leads to the provider binding, credential, and
        separately reauthenticated policy commit that egress actually requires.
        """

        return await self.ask(
            SelectionView(
                name="review-mode",
                title="How should FinishUP review work?",
                options=[
                    Option(
                        "semantic",
                        "Add AI-powered review",
                        "Recommended. Configure a provider, API key, and explicit privacy "
                        "boundary.",
                    ),
                    Option(
                        "local",
                        "Local only",
                        "Local checks; nothing leaves this computer.",
                    ),
                ],
                hint="enter to choose · b to go back" if allow_back else "enter to choose",
                allow_back=allow_back,
            )
        )

    async def _run_initial_review(
        self,
        choice: str | None,
        *,
        connected: bool,
        option: HarnessOption | None = None,
        codex_home: Path | None = None,
    ) -> None:
        # Only an explicit local answer finishes as local-only. Dismiss (None) is handled by
        # the first-run callers before storage or registration, so it must not fall through here.
        if choice == "local":
            await self._finish_setup(connected=connected)
            return
        if choice != "semantic":
            return
        await self.command_provider()
        provider = await self.runtime.provider_posture()
        if (
            not provider.endpoint_bound
            or provider.credential_connected is not True
            or provider.llm_inference_enabled is not True
        ):
            self.say(
                Level.BLOCKED,
                "AI-powered review setup is not complete",
                ("A provider binding, privacy policy, and stored credential are required.",),
            )
            await self._offer_local_only_finish(option, connected=connected, codex_home=codex_home)
            return
        await self._finish_setup(connected=connected)

    async def _offer_local_only_finish(
        self,
        option: HarnessOption | None,
        *,
        connected: bool,
        codex_home: Path | None = None,
    ) -> None:
        """Leave a coherent installation when AI-powered review setup does not complete.

        AI-powered review was chosen, so the policy route is already registered. Returning here
        without a decision leaves that route registered with no provider behind it and no setup
        marker written -- an install that is neither local-only nor AI-powered. Offer the finish
        that makes it one of the two.
        """

        choice = await self.ask(
            SelectionView(
                name="semantic-incomplete",
                title="Finish as local only instead?",
                options=[
                    Option(
                        "local",
                        "Yes, finish as local only",
                        "Registers the local-only command and completes setup.",
                    ),
                    Option(
                        "leave",
                        "No, leave setup unfinished",
                        "Change nothing further; rerun 'finishup setup' when ready.",
                    ),
                ],
                hint="enter to choose",
            )
        )
        if choice != "local":
            self.say(
                Level.OPTIONAL,
                "Setup was not completed.",
                (
                    "Rerun 'finishup setup' to finish, or 'finishup provider status' to see what "
                    "is still missing.",
                ),
            )
            return
        # Re-registering the other route is a change to the project, so it goes through the
        # same preview and approval as the first registration -- never a silent mutation.
        if (
            connected
            and option is not None
            and codex_home is not None
            and not await self._connect(option, codex_home, "strict")
        ):
            return
        await self._finish_setup(connected=connected)

    async def _choose_harness(self, options: Sequence[HarnessOption]) -> HarnessOption | None:
        if not options:
            return None
        if len(options) == 1:
            return options[0]
        rows = [
            Option(str(index), option.label, option.description)
            for index, option in enumerate(options)
        ]
        rows.append(Option("other", "Choose another executable"))
        chosen = await self.ask(
            SelectionView(
                name="harness",
                title="Choose an agent installation",
                options=rows,
                hint="enter to choose · esc to cancel",
            )
        )
        if chosen is None:
            return None
        if chosen == "other":
            while True:
                entry = TextEntryView(
                    name="harness-path",
                    title="Choose another executable",
                    label="Full path to the Codex executable",
                    placeholder="/usr/local/bin/codex",
                    empty_is_cancel=False,
                )
                if await self.ask(entry) is None:
                    return None
                path = entry.value.strip()
                if path and Path(path).is_file() and os.access(path, os.X_OK):
                    return HarnessOption(
                        executable_path=path,
                        reported_version=None,
                        label="Codex",
                        description="Executable you selected",
                    )
                self.say(
                    Level.BLOCKED,
                    "That path is not an executable file",
                    ("Nothing was changed. Enter another path or press Esc to cancel.",),
                )
        return options[int(chosen)]

    async def _choose_codex_home(self, option: HarnessOption) -> Path | None:
        """Collect the exact home paired with one selected executable; never infer it."""

        suggested = self.runtime.suggested_codex_home()
        while True:
            entry = TextEntryView(
                name="codex-home-path",
                title="Confirm the Codex home for this installation",
                label=f"Codex home used by {option.executable_path}",
                initial="" if suggested is None else str(suggested),
                placeholder="/absolute/path/to/.codex",
                empty_is_cancel=False,
                hint="enter to confirm · edit the path if Codex uses another home · esc to cancel",
            )
            if await self.ask(entry) is None:
                return None
            raw = entry.value.strip()
            candidate = Path(raw).expanduser()
            if (
                raw
                and candidate.is_absolute()
                and candidate.is_dir()
                and not candidate.is_symlink()
            ):
                return candidate
            self.say(
                Level.BLOCKED,
                "That Codex home is not an existing absolute directory",
                (
                    "Nothing was changed. Enter the exact home for the selected executable "
                    "or press Esc to cancel.",
                ),
            )

    async def _confirm_project_trust(
        self, detection: Detection, *, allow_back: bool = False
    ) -> bool | str:
        answer = await self.ask(
            ApprovalView(
                name="trust",
                title="",
                body=render_project_trust(detection, self.body_width),
                approve_label="Yes, continue",
                decline_label="No, quit",
                hint=(
                    "enter to choose · b to go back · esc to cancel"
                    if allow_back
                    else "enter to choose · esc to cancel"
                ),
                allow_back=allow_back,
            )
        )
        if answer == BACK:
            return BACK
        if answer != "approve":
            self.say(Level.OPTIONAL, "Setup stopped. This project was not changed.")
            return False
        return True

    async def _connect(
        self,
        option: HarnessOption,
        codex_home: Path,
        route_profile: Literal["policy", "strict"] | None = None,
    ) -> bool:
        try:
            plan = await self.runtime.integration_plan(option, codex_home, route_profile)
        except RuntimeError_ as error:
            self._report(error)
            return False
        if plan.foreign_entry:
            await self._handle_foreign_entry(option)
            return False
        if not await self._approve_plan(plan):
            self.say(Level.OPTIONAL, "This project was left unchanged.")
            return False
        return await self._apply_plan(option, plan)

    async def _approve_plan(self, plan: IntegrationPlan) -> bool:
        view = ApprovalView(
            name="integration",
            title="",
            body=render_integration_preview(plan, self.body_width),
            approve_label="Yes, connect FinishUP",
            decline_label="No, keep this project unchanged",
        )
        # 'D' on this view must show the exact paths, digests, and command.
        view.technical_details = render_integration_technical_details(plan, self.body_width)
        return await self.ask(view) == "approve"

    async def _apply_plan(self, option: HarnessOption, plan: IntegrationPlan) -> bool:
        self.say(Level.ACTIVE, "Connecting FinishUP (esc to interrupt)")
        try:
            outcome = await self.runtime.apply_integration(option, plan)
        except RuntimeError_ as error:
            self.settle(Level.BLOCKED, error.message, (f"Reason: {error.reason}",))
            return False
        if outcome.foreign_entry:
            await self._handle_foreign_entry(option)
            return False
        lines = render_layers(outcome.layers, self.body_width)
        blocked = [layer for layer in outcome.layers if layer.state is LayerState.BLOCKED]
        if blocked:
            self.settle(
                Level.BLOCKED,
                "FinishUP could not finish connecting",
                lines,
                details=(f"outcome={outcome.outcome}", f"reason={outcome.reason}"),
            )
            return False
        unproven = [layer for layer in outcome.layers if layer.state is LayerState.UNPROVEN]
        self.settle(
            Level.UNPROVEN if unproven else Level.VERIFIED,
            "FinishUP is connected to this project"
            if not unproven
            else "FinishUP is connected, with some steps unproven",
            lines,
            details=(f"outcome={outcome.outcome}", f"state={outcome.existing_entry_detail}"),
        )
        return True

    async def _handle_foreign_entry(self, option: HarnessOption) -> None:
        detail = await self.runtime.foreign_entry_detail(option)
        self.say(
            Level.BLOCKED,
            "Could not register FinishUP with Codex",
            render_foreign_entry("", self.body_width)[2:],
            details=detail,
        )
        while True:
            choice = await self.ask(
                SelectionView(
                    name="foreign",
                    options=[
                        Option("show", "Show the existing connection"),
                        Option("local", "Continue with local FinishUP only"),
                        Option("manual", "Show manual resolution instructions"),
                        Option("exit", "Exit"),
                    ],
                    hint="Nothing was replaced or removed · esc to go back",
                )
            )
            if choice == "show":
                await self.ask(
                    DetailsView(
                        name="foreign-detail",
                        title="The existing connection",
                        lines=detail,
                    )
                )
                continue
            if choice == "manual":
                await self.ask(
                    DetailsView(
                        name="foreign-manual",
                        title="Resolving this by hand",
                        lines=(
                            "FinishUP will never replace an MCP entry it does not own.",
                            "",
                            "1. Inspect the existing entry:",
                            "     codex mcp get finishup",
                            "2. If it is yours and you no longer need it, remove it:",
                            "     codex mcp remove finishup",
                            "3. Return here and run /connect again.",
                            "",
                            "If the entry belongs to another tool, leave it alone and",
                            "keep using FinishUP locally — /check and /receipt work without",
                            "the Codex integration.",
                        ),
                    )
                )
                continue
            if choice == "local":
                await self._finish_setup(connected=False)
            return

    async def _choose_storage(self, detection: Detection) -> None:
        choice = await self.ask(
            SelectionView(
                name="storage",
                title="Where should FinishUP keep local secrets?",
                options=[
                    Option(
                        StorageChoice.SYSTEM_KEYRING.value,
                        "Use system secure storage",
                        "Recommended. Unlocks automatically for the operating-system user.",
                        disabled=not detection.secure_storage_available,
                        disabled_reason=detection.secure_storage_reason
                        or "not available on this machine",
                    ),
                    Option(
                        StorageChoice.PASSPHRASE.value,
                        "Use a FinishUP passphrase",
                        "Enter a passphrase when FinishUP needs to unlock.",
                    ),
                ],
                hint="enter to choose · esc to skip for now",
            )
        )
        if choice is None:
            return
        posture = await self.runtime.vault_posture()
        if not posture.reachable:
            self.say(
                Level.UNPROVEN,
                "Secure storage was not set up",
                (
                    "The local service is not running yet.",
                    "Start it with 'finishup service run', then use /service.",
                ),
            )
            return
        if posture.vault_mode not in {None, "uninitialized"}:
            self.say(Level.VERIFIED, "Secure storage is already set up")
            return
        if choice == StorageChoice.PASSPHRASE.value:
            await self._run_confidential(
                "Choose a FinishUP passphrase",
                self.runtime.initialize_passphrase_vault,
                fallback_command="finishup service initialize-passphrase",
            )
        else:
            await self._run_confidential(
                "Set up system secure storage",
                self.runtime.initialize_system_keyring,
                fallback_command=None,
            )

    async def hand_over_terminal(self, operation: Callable[[], Awaitable[Any]]) -> Any:
        """Run ``operation`` with the full-screen interface suspended.

        This is the seam through which every secret is entered. Suspending gives
        the controlling terminal back to the ceremony in ``finishup.cli.unlock``,
        which opens ``/dev/tty`` itself, checks that it really is the controlling
        terminal, and disables echo — so no key press ever reaches a widget and
        no secret byte can end up in the transcript, a log, or a snapshot.
        """

        with self.suspend():
            return await operation()

    async def _run_confidential(
        self,
        title: str,
        operation: Callable[[], Awaitable[Any]],
        *,
        fallback_command: str | None = "finishup service unlock",
    ) -> Any:
        """Ask for explicit consent, then hand the terminal to the ceremony."""

        confirmed = await self.ask(
            ApprovalView(
                name="confidential",
                title=title,
                body=(
                    "FinishUP will hand this terminal to its secure entry prompt.",
                    "",
                    "What you type there is hidden, goes straight into the local",
                    "vault, and never appears in this window, the history above,",
                    "any log, or any file in your project.",
                ),
                approve_label="Continue to secure entry",
                decline_label="Not now",
            )
        )
        if confirmed != "approve":
            self.say(Level.OPTIONAL, "Secure entry was cancelled. Nothing was stored.")
            return None
        try:
            return await self.hand_over_terminal(operation)
        except SuspendNotSupported:
            # Rather than take the secret through a widget, say so and name the
            # command that runs the same ceremony directly.
            guidance = (
                ("Run this from your shell instead:", "", f"    {fallback_command}", "")
                if fallback_command is not None
                else (
                    "No equivalent shell command is exposed for this operation.",
                    "Run FinishUP again in a terminal that supports secure handoff.",
                    "",
                )
            )
            self.say(
                Level.UNPROVEN,
                "This terminal cannot hand over for secure entry",
                (
                    "FinishUP will not accept a secret through this window.",
                    *guidance,
                    "Nothing was stored.",
                ),
                details=("app.suspend is unavailable in this environment",),
            )
            return None
        except RuntimeError_ as error:
            self.say(
                Level.BLOCKED,
                error.message,
                (f"Reason: {error.reason}",),
                details=(f"reason={error.reason}",),
            )
            return None

    async def _finish_setup(self, *, connected: bool) -> None:
        from finishup.cli.setup import write_setup_marker

        write_setup_marker("registered" if connected else "local_only")
        snapshot = await self.runtime.status_snapshot()
        await self._refresh_header()
        self.say(Level.VERIFIED, "", render_finish(snapshot, self.body_width))
        await self._maybe_say_package_update_tip()

    async def _resume_flow(self) -> None:
        """Post-install landing: a header, a tip, and the composer. No dashboard."""

        await self._refresh_header()
        if await self._maybe_say_package_update_tip():
            return
        self.say(
            Level.ACTIVE,
            "",
            (
                "Tip: Ask Codex to use FinishUP when a task needs an auditable",
                "record of claims, evidence, checks, and limitations.",
            ),
        )

    async def _maybe_say_package_update_tip(self) -> bool:
        """Show a package-update tip when policy permits and a newer release exists.

        Returns True when a tip was shown so callers can skip the generic Codex tip.
        Network and policy failures are silent (no tip).
        """

        try:
            advisory = await self.runtime.package_update_advisory(allow_network=True)
        except Exception:
            return False
        lines = advisory.tip_lines()
        if not lines:
            return False
        self.say(Level.OPTIONAL, "Package update available", lines)
        return True

    async def _refresh_header(self) -> None:
        harnesses = self.runtime.discover_harnesses()
        state = "not connected"
        observed: list[str] = []
        for harness in harnesses:
            try:
                observed.append(await self.runtime.mcp_state(harness))
            except RuntimeError_:
                observed.append("unknown")
        if observed:
            if "yoetz_owned" in observed:
                mcp = "yoetz_owned"
            elif "foreign_present" in observed:
                mcp = "foreign_present"
            elif all(item == "absent" for item in observed):
                mcp = "absent"
            else:
                mcp = "unknown"
            state = {
                "yoetz_owned": "connected",
                "absent": "not connected",
                "foreign_present": "blocked — Codex already has a non-FinishUP MCP server named finishup",
            }.get(mcp, mcp)
        privacy = await self.runtime.privacy_posture()
        vault = await self.runtime.vault_posture()
        self.header_widget.set_state(
            version=__version__,
            project=middle_truncate(str(self.runtime.project_root()), 48),
            harness=state,
            privacy=privacy.summary,
        )
        self.footer_widget.set_state(right=self._footer_right(privacy.summary, vault.ready))

    def _footer_right(self, privacy_summary: str, service_ready: bool) -> str:
        """The footer states what was observed, never a default optimism.

        "ready" here means the local service reported itself ready. A footer that
        says it regardless would be the smallest possible version of exactly the
        dishonesty this product exists to avoid.
        """

        return f"{privacy_summary} · {'ready' if service_ready else 'service not ready'}"

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    async def command_help(self) -> None:
        lines = ["What you can do here:", ""]
        width = max(len(item.token) for item in SLASH_COMMANDS)
        lines.extend(f"{item.token.ljust(width)}  {item.summary}" for item in SLASH_COMMANDS)
        lines.extend(("", f"{RENAME_NOTE} Docs: https://finishup.dev"))
        self.say(Level.ACTIVE, "", lines)

    async def command_quit(self) -> None:
        self.exit(self.exit_code)

    async def command_status(self) -> None:
        self.say(Level.ACTIVE, "FinishUP status")
        snapshot = await self.runtime.status_snapshot()
        self.settle(
            Level.ACTIVE,
            "FinishUP status",
            render_status(snapshot, self.body_width),
            details=render_layers(snapshot.layers, self.body_width),
        )
        await self._refresh_header()

    async def command_observe(self) -> None:
        """Show observation selection, then offer a disclosed capacity change.

        Status stays separate from privacy and readiness.  A capacity change is
        always previewed first (current → proposed, scope, local-resource
        consequences, remaining limits, and the lower/pause path) and applied only
        on an explicit choice; ``Esc`` or cancel changes nothing.
        """

        self.say(Level.ACTIVE, "Observation selection")
        status = await self.runtime.observation_selection_status()
        selected = status.get("selected")
        effective = status.get("effective")
        selected_map: Mapping[str, object] = (
            cast(Mapping[str, object], selected) if isinstance(selected, Mapping) else {}
        )
        effective_map: Mapping[str, object] = (
            cast(Mapping[str, object], effective) if isinstance(effective, Mapping) else {}
        )
        accounting = status.get("accounting")
        accounting_map: Mapping[str, object] = (
            cast(Mapping[str, object], accounting) if isinstance(accounting, Mapping) else {}
        )
        budget = _mapping_or_empty(status.get("effective_budget"))

        def counter(name: str) -> str:
            value = accounting_map.get(name)
            return str(value) if type(value) is int else "unknown"

        body = (
            "selected: "
            f"{selected_map.get('mode', 'unknown')} / "
            f"{selected_map.get('capacity_profile', 'unknown')}",
            "effective: "
            f"{effective_map.get('mode', 'unknown')} / "
            f"{effective_map.get('capacity_profile', 'unknown')}",
            f"origin: {selected_map.get('origin', 'unknown')}",
            f"scope: {'session' if status.get('session_scope') is True else 'workspace/default'}; "
            f"expires: {selected_map.get('expires_at', 'none') or 'none'}",
            f"reason: {status.get('effective_reason', 'unknown')}",
            "accounting: "
            f"observed={counter('observed_count')}; "
            f"admitted={counter('admitted_input_count')}; "
            f"delivered={counter('delivered_input_count')}; "
            f"summarized={counter('summarized_input_count')}; "
            f"omitted={counter('intentionally_omitted_input_count')}; "
            f"unrecoverable={counter('unrecoverable_input_count')}",
            *_effective_budget_lines(budget),
            "detail and capacity do not change content or privacy authority",
        )
        self.settle(Level.ACTIVE, "Observation selection", body)
        await self._change_observation_capacity(budget)

    async def _change_observation_capacity(self, budget: Mapping[str, object]) -> None:
        current = _capacity_phrase(
            budget.get("selected_queue_count"), budget.get("selected_capacity_label")
        )
        choice = await self.ask(
            SelectionView(
                name="observe-capacity",
                title="Change local retention capacity?",
                options=[
                    Option(
                        "keep",
                        "Keep current",
                        f"Stay on {current}. Changes nothing."
                        if current != "unknown"
                        else "Changes nothing.",
                    ),
                    Option("recommended", "Recommended (512 rows)", "The standard capacity."),
                    Option(
                        "larger",
                        "Larger (2,048 rows)",
                        "Can use more local disk, memory, and CPU work.",
                    ),
                    Option(
                        "largest",
                        "Largest (8,192 rows)",
                        "The largest supported finite capacity; uses the most local resources.",
                    ),
                    Option(
                        "custom",
                        "Custom",
                        f"Type a queue row count from {_MIN_QUEUE_ROWS:,} to {_MAX_QUEUE_ROWS:,}.",
                    ),
                    Option(
                        "no_cap",
                        "No FinishUP cap",
                        "Explains why this is not available for this queue.",
                    ),
                ],
                hint="enter to choose · esc to keep the current setting",
            )
        )
        if choice is None or choice == "keep":
            self.say(Level.OPTIONAL, _CAPACITY_UNCHANGED)
            return
        request: CapacityRequest | None
        if choice == "custom":
            request = await self._ask_custom_capacity()
        else:
            request = _capacity_request_for(choice)
        if request is None:
            self.say(Level.OPTIONAL, _CAPACITY_UNCHANGED)
            return
        try:
            preview = await self.runtime.preview_observation_selection(request)
        except ObservationCapacityUnavailable as unavailable:
            self._say_capacity_unavailable(unavailable)
            return
        except RuntimeError_ as error:
            self.say(
                Level.BLOCKED,
                "The capacity preview could not be built",
                (f"Reason: {error.reason}", *error.details, _CAPACITY_UNCHANGED),
            )
            return
        await self._confirm_capacity_preview(request, preview)

    async def _ask_custom_capacity(self) -> CapacityRequest | None:
        """Ask for a custom count until it is valid or the user presses ``Esc``.

        The typed text is never echoed back: an invalid entry is answered with the
        accepted range only.
        """

        while True:
            entry = TextEntryView(
                name="observe-capacity-custom",
                title="Custom local retention capacity",
                label=f"Queue rows ({_MIN_QUEUE_ROWS}–{_MAX_QUEUE_ROWS:,})",
                placeholder="1024",
            )
            if await self.ask(entry) is None:
                return None
            text = entry.value.strip().replace(",", "")
            if text.isascii() and text.isdigit() and len(text) <= 6:
                try:
                    return parse_capacity_request("custom", queue_count=int(text))
                except ValueError:
                    pass
            self.say(
                Level.BLOCKED,
                "That is not a supported queue row count",
                (
                    f"Enter a whole number from {_MIN_QUEUE_ROWS} to {_MAX_QUEUE_ROWS:,}, "
                    "or press esc to cancel.",
                    "Nothing changed.",
                ),
            )

    def _say_capacity_unavailable(self, unavailable: ObservationCapacityUnavailable) -> None:
        command = canonical_safe_command(unavailable.alternative_command)
        alternative = (
            f"Alternative: choose Largest ({_MAX_QUEUE_ROWS:,} rows) in /observe."
            if command is None
            else f"Alternative: choose Largest ({_MAX_QUEUE_ROWS:,} rows) in /observe, or run: "
            f"{command}"
        )
        self.say(
            Level.OPTIONAL,
            "No FinishUP cap is not available",
            (*unavailable.lines, alternative, _CAPACITY_UNCHANGED),
        )

    async def _confirm_capacity_preview(
        self, request: CapacityRequest, preview: Mapping[str, object]
    ) -> None:
        disclosure = _mapping_or_empty(preview.get("disclosure"))
        digest = preview.get("preview_digest")
        try:
            disclosure_lines = render_capacity_disclosure_lines(disclosure)
        except ValueError:
            disclosure_lines = ()
        if type(digest) is not str or not disclosure_lines:
            self.say(
                Level.BLOCKED,
                "The capacity preview could not be shown",
                ("Reason: observation_selection_preview_invalid", _CAPACITY_UNCHANGED),
            )
            return
        change = disclosure.get("change")
        current_selection = _mapping_or_empty(preview.get("current_selection"))
        requested_selection = _mapping_or_empty(preview.get("requested_selection"))
        current = _selection_capacity_phrase(
            current_selection, _mapping_or_empty(disclosure.get("current"))
        )
        proposed = _selection_capacity_phrase(
            requested_selection, _mapping_or_empty(disclosure.get("requested"))
        )
        detail = _closed_token(requested_selection.get("detail"), _DETAILS)
        if change == "unchanged":
            self.say(
                Level.OPTIONAL,
                "Local retention capacity",
                (*disclosure_lines, _CAPACITY_UNCHANGED),
            )
            return
        self.say(
            Level.ACTIVE,
            "Proposed local retention capacity",
            (
                f"Capacity: {current} → {proposed}",
                f"Detail: {detail} (unchanged)",
                "Scope: this workspace (persisted)",
                *disclosure_lines,
            ),
        )
        view = ApprovalView(
            name="observe-capacity-apply",
            title="Apply this capacity change?",
            body=(),
            approve_label="Apply",
            decline_label="Cancel",
            approve_key="apply",
            decline_key="cancel",
            default_to_safe=True,
            hint="enter to choose · esc to cancel · D for technical details",
        )
        view.technical_details = (f"preview_digest={digest}",)
        if await self.ask(view) != "apply":
            self.say(Level.OPTIONAL, _CAPACITY_UNCHANGED)
            return
        try:
            applied = await self.runtime.apply_observation_selection(request, digest)
        except ObservationCapacityUnavailable as unavailable:
            self._say_capacity_unavailable(unavailable)
            return
        except RuntimeError_ as error:
            self.say(
                Level.BLOCKED,
                "The capacity change did not complete",
                (
                    f"Reason: {error.reason}",
                    *error.details,
                    "Run /observe to see the current setting.",
                ),
            )
            return
        self._say_capacity_applied(applied)

    def _say_capacity_applied(self, applied: Mapping[str, object]) -> None:
        selection = _mapping_or_empty(applied.get("selection"))
        budget = _mapping_or_empty(applied.get("effective_budget"))
        disclosure = _mapping_or_empty(applied.get("disclosure"))
        confirmed = applied.get("applied") is True and bool(selection)
        self.say(
            Level.VERIFIED if confirmed else Level.UNPROVEN,
            "Local retention capacity applied"
            if confirmed
            else "The capacity change could not be confirmed",
            (
                f"Selected: {_selection_capacity_phrase(selection, {})}, "
                f"detail {_closed_token(selection.get('detail'), _DETAILS)}, "
                "this workspace",
                *_effective_budget_lines(budget),
                (
                    "Lower it later with: "
                    f"{_disclosure_command(disclosure, 'lower_command', _PAUSE_COMMAND)}"
                    if disclosure.get("change") == "increase"
                    else "Return to the default with: "
                    f"{_disclosure_command(disclosure, 'revoke_command', _REVOKE_COMMAND)}"
                ),
                "Pause new observation ingest with: "
                f"{_disclosure_command(disclosure, 'pause_command', _PAUSE_COMMAND)}",
                "Resume with: "
                f"{_disclosure_command(disclosure, 'resume_command', _RESUME_COMMAND)}",
            ),
        )

    async def command_doctor(self) -> None:
        self.say(Level.ACTIVE, "Checking this installation")
        report = await self.runtime.doctor()
        blocked = report.blocked
        self.settle(
            Level.BLOCKED if blocked else Level.ACTIVE,
            "Installation report" if not blocked else "Installation problems found",
            render_doctor(report, self.body_width),
            details=tuple(
                f"{entry.key}={entry.state.value} {entry.detail}".strip()
                for entry in report.entries
            ),
        )

    async def command_connect(self) -> None:
        harnesses = self.runtime.discover_harnesses()
        if not harnesses:
            self.say(
                Level.OPTIONAL,
                "No agent installation was found",
                (
                    "FinishUP still works offline: /check runs local checks",
                    "and /receipt produces an honest record.",
                ),
            )
            return
        option = await self._choose_harness(harnesses)
        if option is None:
            return
        if option.host != "codex":
            review = await self._ask_review_mode()
            if review is not None:
                await self._connect_selected_host(
                    option, route="policy" if review == "semantic" else "strict"
                )
            return
        if not await self._offer_package_upgrade_if_newer():
            return
        choice = await self.ask(
            SelectionView(
                name="connect",
                title=f"{option.label}",
                options=[
                    Option("inspect", "Inspect this connection", "Read-only. Changes nothing."),
                    Option("repair", "Connect or repair", "Shows the exact change first."),
                    Option("technical", "Show exact technical state"),
                ],
                hint="enter to choose · esc to go back",
            )
        )
        if choice is None:
            return
        if choice == "inspect":
            state = await self.runtime.mcp_state(option)
            self.say(
                Level.ACTIVE,
                f"{option.label}",
                (f"Registration: {state}", f"Executable: {option.executable_path}"),
            )
            return
        codex_home = await self._choose_codex_home(option)
        if codex_home is None:
            self.say(Level.OPTIONAL, "Connection was left unchanged.")
            return
        if choice == "technical":
            plan = await self.runtime.integration_plan(option, codex_home)
            await self.ask(
                DetailsView(
                    name="connect-technical",
                    title="Exact technical state",
                    lines=render_integration_technical_details(plan, self.body_width),
                )
            )
            return
        await self._connect(option, codex_home)
        await self._refresh_header()

    async def command_disconnect(self) -> None:
        option = await self._choose_harness(self.runtime.discover_harnesses())
        if option is not None:
            await self._connect_selected_host(option, disconnect=True)

    async def _connect_selected_host(
        self,
        option: HarnessOption,
        *,
        route: Literal["policy", "strict"] = "strict",
        disconnect: bool = False,
    ) -> bool:
        from anyio.to_thread import run_sync

        from finishup.cli.host_connection import (
            CONNECTION_ERRORS,
            apply_selected,
            connection_continuation,
            connection_summary,
            launch_details,
            prepare_selected,
            select_installation,
        )
        from finishup.protocol.ids import IdKind, new_id

        request = new_id(IdKind.REQUEST)
        try:
            selected = await run_sync(
                lambda: select_installation(
                    option.host,
                    Path(option.executable_path),
                    None if option.config_root is None else Path(option.config_root),
                )
            )

            def prepare():
                return prepare_selected(
                    selected,
                    self.runtime.project_root(),
                    action="disconnect" if disconnect else "connect",
                    route=route,
                    request_value=request,
                )

            plan = await run_sync(prepare)
            if not plan.unchanged:
                approved = await self.ask(
                    SelectionView(
                        name="host-connection",
                        title=f"{'Disconnect' if disconnect else 'Connect'} {option.label}",
                        options=[
                            Option(
                                "apply", "Apply this plan", " · ".join(connection_summary(plan))
                            ),
                            Option("cancel", "Cancel"),
                        ],
                        hint="enter to choose · esc to cancel",
                    )
                )
                if approved != "apply":
                    self.say(Level.OPTIONAL, "Connection left unchanged.")
                    return False

                async def apply_on_terminal():
                    if option.host == "codex":
                        return await run_sync(lambda: apply_selected(plan, prepare))
                    # PAM must own the main thread's signal deadline while the UI is suspended.
                    return apply_selected(plan, prepare)

                try:
                    status = await self.hand_over_terminal(apply_on_terminal)
                except SuspendNotSupported:
                    self.say(
                        Level.UNPROVEN,
                        "This terminal cannot hand over for connection approval",
                        ("Run this command in your terminal:", connection_continuation(plan)),
                    )
                    return False
            else:
                status = await run_sync(plan.status)
            self.say(
                Level.ACTIVE,
                "Integration removed" if disconnect else "Integration configured",
                (
                    "Start a fresh session: "
                    + str(launch_details(selected, self.runtime.project_root())["shell_command"])
                    if not disconnect
                    else "Restart the host. Your FinishUP data is retained.",
                ),
                details=tuple(f"{key}: {value}" for key, value in status.items()),
            )
            return True
        except CONNECTION_ERRORS as error:
            self.say(
                Level.BLOCKED,
                "Connection needs attention",
                ("Run finishup setup run --host " + option.host + " in a trusted local terminal.",),
                details=(type(error).__name__,),
            )
            return False

    async def _offer_package_upgrade_if_newer(self) -> bool:
        """When a newer package exists, offer upgrade before harness re-apply.

        Returns False only when the user chooses to exit and re-run after upgrading.
        Continuing with the current version still repairs/adds harnesses without
        reinstalling the same package bits.
        """

        try:
            advisory = await self.runtime.package_update_advisory(allow_network=True)
        except Exception:
            return True
        if not advisory.is_newer or advisory.latest_version is None:
            return True
        choice = await self.ask(
            SelectionView(
                name="package-upgrade",
                title="A newer FinishUP package is available",
                options=[
                    Option(
                        "upgrade",
                        f"Upgrade to {advisory.latest_version} first",
                        f"Run: {advisory.upgrade_command}",
                    ),
                    Option(
                        "continue",
                        f"Continue with {advisory.installed_version}",
                        "Add or repair harness integration without reinstalling the package.",
                    ),
                ],
                hint="enter to choose · esc to go back",
            )
        )
        if choice is None:
            return False
        if choice == "upgrade":
            self.say(
                Level.ACTIVE,
                f"Upgrade the package, then re-run {relaunch_command(advisory.package)}",
                (
                    f"Installed: {advisory.installed_version}",
                    f"Available: {advisory.latest_version}",
                    f"Command: {advisory.upgrade_command}",
                    "This process cannot upgrade itself; exit and run the command.",
                ),
            )
            return False
        return True

    async def command_privacy(self) -> None:
        """Show where privacy stands, then the one recommended move, then everything else.

        This screen selects; it never authorizes. The old flow took its own approval here and
        then handed over to a second, differently worded approval in the trusted terminal —
        two consents for one decision, of which only the second one actually gated anything.
        The trusted terminal ceremony is now the sole authorization for a widening, and it is
        the only place the exact ``before → after`` policy diff is rendered.
        """

        current = await self.runtime.privacy_posture()
        recommendation = self.runtime.privacy_recommendation(current)
        on_recipe = current.choice is not None and current.profile == _PROFILE_FOR_RECIPE.get(
            recommendation.recipe
        )
        # An earlier version of the same recipe is not "already recommended": the newer one
        # (for example Expanded under privacy policy 1.2.0) still needs its own approval.
        already = on_recipe and not current.recipe_outdated
        authority_lines = [f"Repository grant: {current.repository_authority_summary}"]
        if current.repository_migration_summary is not None:
            authority_lines.append(current.repository_migration_summary)
        if current.task_statement_disclosure is not None:
            authority_lines.append(f"Task statement: {current.task_statement_disclosure}")
        if current.credential_heuristic_summary is not None:
            # Owner opt-out (issue #982): the same pair and sentence as `finishup status`.
            authority_lines.append(current.credential_heuristic_summary)
        self.say(
            Level.ACTIVE,
            "Privacy",
            (
                f"Currently: {current.summary}",
                *authority_lines,
                f"Recommended: {recommendation.label}",
                recommendation.reason,
                recommendation.tradeoff,
            ),
        )
        options = [Option("keep", "Keep current", f"Stay on {current.summary}.")]
        if already:
            self.say(
                Level.OPTIONAL,
                "You are already on the recommended privacy policy.",
            )
        else:
            if on_recipe:
                self.say(
                    Level.OPTIONAL,
                    "A newer version of your recipe is available. Your current policy stays until "
                    "you review and approve it in the trusted terminal.",
                )
            options.append(
                Option(
                    "recommended",
                    f"Review recommended change ({recommendation.label})",
                    "Opens the trusted terminal, which shows the exact change and asks there.",
                )
            )
        options.append(
            Option("other", "Other privacy options", "Choose a different named policy, or Custom.")
        )
        chosen = await self.ask(
            SelectionView(
                name="privacy",
                title="What may leave this computer?",
                options=options,
                hint="enter to choose · esc to keep the current setting",
            )
        )
        if chosen is None or chosen == "keep":
            self.say(Level.OPTIONAL, "Privacy was left unchanged.")
            return
        recipe = recommendation.recipe
        if chosen == "other":
            picked = await self.ask(
                SelectionView(
                    name="privacy-recipe",
                    title="Choose a privacy policy",
                    options=[
                        Option(name, label, description)
                        for name, label, description in PRIVACY_RECIPES
                    ],
                    hint="enter to choose · esc to keep the current setting",
                )
            )
            if picked is None:
                self.say(Level.OPTIONAL, "Privacy was left unchanged.")
                return
            recipe = picked
        await self._hand_privacy_to_trusted_terminal(recipe)

    async def _hand_privacy_to_trusted_terminal(self, recipe: str) -> None:
        """Suspend and let the trusted CLI ceremony own the decision end to end."""

        try:
            report = await self.hand_over_terminal(lambda: self.runtime.run_privacy_setup(recipe))
        except SuspendNotSupported:
            self.say(
                Level.UNPROVEN,
                "This terminal cannot open the trusted privacy ceremony",
                (
                    "Nothing has changed. Run this command from your shell:",
                    "",
                    "    finishup privacy setup",
                ),
            )
            return
        except RuntimeError_ as error:
            self.say(
                Level.BLOCKED,
                "Privacy setup did not complete",
                (f"Reason: {error.reason}",),
            )
            return
        outcome = getattr(report, "outcome", "failed")
        if outcome in {"configured", "unchanged"}:
            await self._refresh_header()
            authority = getattr(report, "grant_state", None)
            migration = getattr(report, "migration_state", None)
            details = [f"Effective profile: {getattr(report, 'profile', recipe)}"]
            if authority == "granted":
                details.append("Repository grant: granted for this repository")
            elif authority == "missing":
                details.append("Repository grant: missing; external model review remains off")
            if migration == "consumed":
                details.append("An existing permission was carried forward without a new prompt.")
            self.say(
                Level.VERIFIED,
                "Privacy setup complete",
                tuple(details),
            )
            return
        self.say(
            Level.BLOCKED,
            "Privacy setup did not complete",
            (f"Reason: {getattr(report, 'reason', 'privacy_setup_failed')}",),
        )

    async def _command_codex_subscription(self, *, switch_account: bool = False) -> None:
        executable_default, home_default, model_default, effort_default = (
            self.runtime.codex_subscription_defaults()
        )
        if not executable_default:
            self.say(
                Level.OPTIONAL,
                "No eligible Codex evaluator runtime was found",
                (
                    "To download the admitted release, run this in your shell:",
                    "finishup provider codex-subscription runtime install --download",
                    "The command asks before downloading. Then return to /provider, or enter "
                    "the path to a local admitted runtime below.",
                ),
            )
        entries = (
            TextEntryView(
                name="codex-subscription-executable",
                title="Codex with ChatGPT subscription",
                label="Codex evaluator executable (FinishUP keeps a verified private copy)",
                initial=executable_default,
                placeholder="/absolute/path/to/codex",
            ),
            TextEntryView(
                name="codex-subscription-home",
                title="Dedicated evaluator home",
                label="Owner-private CODEX_HOME",
                initial=home_default,
                placeholder="/absolute/path/to/dedicated/home",
            ),
            TextEntryView(
                name="codex-subscription-model",
                title="Exact evaluator selection",
                label=(
                    "Model identifier (gpt-6.1-sol is suggested; setup uses gpt-6-luna and says "
                    "so if this Codex does not list it)"
                    if model_default == "gpt-6.1-sol"
                    else "Model identifier"
                ),
                initial=model_default,
                placeholder="gpt-6.1-sol",
            ),
        )
        values: list[str] = []
        for entry in entries:
            if await self.ask(entry) is None:
                self.say(Level.OPTIONAL, "Codex subscription setup was cancelled.")
                return
            values.append(entry.value.strip())
        effort = await self.ask(
            SelectionView(
                name="codex-subscription-reasoning",
                title="Final review reasoning effort",
                options=[
                    Option(value, value, "Used for completion reviews; recorded per check.")
                    for value in _efforts_with_default(effort_default)
                ],
            )
        )
        if effort is None:
            self.say(Level.OPTIONAL, "Codex subscription setup was cancelled.")
            return
        # A new binding recommends a bounded routine effort; an existing binding's routine
        # choice (or legacy single effort) is offered first so setup never silently lowers it.
        routine_default = self.runtime.codex_subscription_routine_default() or effort
        routine_effort = await self.ask(
            SelectionView(
                name="codex-subscription-routine-reasoning",
                title="Routine checkpoint reasoning effort",
                options=[
                    Option(value, value, "Used for checks without a completion claim.")
                    for value in (
                        routine_default,
                        *(item for item in _CODEX_EFFORTS if item != routine_default),
                    )
                ],
            )
        )
        if routine_effort is None:
            self.say(Level.OPTIONAL, "Codex subscription setup was cancelled.")
            return
        executable, codex_home, model = values
        try:
            preview = self.runtime.preview_codex_subscription(
                executable, codex_home, model, effort, routine_effort
            )
        except RuntimeError_ as error:
            self._report(error)
            return
        body = (
            f"Runtime source: {preview.get('executable_path')}",
            "Bound runtime: FinishUP's verified private copy; updating your everyday Codex leaves it.",
            f"Executable digest: {preview.get('executable_sha256')}",
            f"Codex version: {preview.get('runtime_version')}",
            f"Capability cell: {preview.get('capability_cell_sha256')}",
            f"Cell evidence expires: {preview.get('capability_evidence_expires_at')}",
            f"Dedicated CODEX_HOME: {preview.get('codex_home')}",
            f"Model: {model}"
            + (
                " (suggested; gpt-6-luna if this Codex does not list it)"
                if model == model_default == "gpt-6.1-sol"
                else ""
            ),
            f"Reasoning: final {effort} / routine {routine_effort}",
            "Destination: OpenAI through Codex-managed ChatGPT authentication.",
            "Data-use posture: unknown; your ChatGPT plan and terms apply.",
            "FinishUP never receives the OAuth credential or the upstream OpenAI body.",
            "Disconnect logs out only this dedicated home; rollback preserves it.",
        )
        if switch_account:
            body = (
                *body,
                "This will log out the dedicated home first, then open Codex sign-in.",
            )
        else:
            body = (
                *body,
                "A home Codex already reports signed in is reused without a new sign-in.",
                'Choose "Switch Codex ChatGPT account" instead to sign in as someone else.',
            )
        confirmed = await self.ask(
            ApprovalView(
                name="codex-subscription-confirm",
                title="Open Codex-managed ChatGPT sign-in?",
                body=body,
                approve_label="Continue to Codex sign-in",
                decline_label="Cancel",
                default_to_safe=True,
            )
        )
        if confirmed != "approve":
            self.say(Level.OPTIONAL, "Codex subscription setup was cancelled.")
            return
        try:
            status = await self.hand_over_terminal(
                lambda: self.runtime.setup_codex_subscription(
                    executable,
                    codex_home,
                    model,
                    effort,
                    switch_account=switch_account,
                    routine_reasoning_effort=routine_effort,
                    model_is_suggestion=model == model_default,
                )
            )
        except SuspendNotSupported:
            self.say(
                Level.UNPROVEN,
                "This terminal cannot open Codex sign-in",
                (
                    "Run this from your shell instead:",
                    "finishup provider codex-subscription setup",
                ),
            )
            return
        except RuntimeError_ as error:
            self._report(error)
            return
        sign_in = (
            "reused the existing Codex login"
            if status.get("login_reused") is True
            else "completed through Codex"
        )
        self.say(
            Level.VERIFIED,
            "Codex subscription binding is ready",
            (
                f"Sign-in: {sign_in}",
                f"Model: {status.get('model') or model}"
                + (
                    f" (suggested {status.get('model_fallback_from')} is not listed by this Codex)"
                    if isinstance(status.get("model_fallback_from"), str)
                    else ""
                ),
                f"Auth mode: {status.get('auth_mode')}",
                f"Plan: {status.get('plan_type') or 'not reported'}",
                f"Model available: {status.get('model_available')}",
                f"Process cleanup: {status.get('process_cleanup')}",
            ),
        )
        try:
            report = await self.hand_over_terminal(
                lambda: self.runtime.run_privacy_setup("assisted_review", offer_recommended=True)
            )
        except (SuspendNotSupported, RuntimeError_) as error:
            if isinstance(error, RuntimeError_):
                self._report(error)
            else:
                self.say(
                    Level.UNPROVEN,
                    "The evaluator is bound, but privacy setup still needs review",
                    ("Run 'finishup privacy setup' from your shell.",),
                )
            return
        if getattr(report, "outcome", "failed") not in {"configured", "unchanged"}:
            self.say(
                Level.BLOCKED,
                "The evaluator is bound, but external review remains off",
                (f"Privacy outcome: {getattr(report, 'outcome', 'failed')}",),
            )
            return
        posture = await self.runtime.provider_posture()
        self.say(Level.ACTIVE, "", render_provider_stored(posture, self.body_width))

    async def _command_codex_subscription_status(self) -> None:
        try:
            status = await self.runtime.codex_subscription_status()
        except RuntimeError_ as error:
            self._report(error)
            return
        from finishup.cli.provider_status import review_budget_human_line

        budgets = review_budget_human_line(status)
        self.say(
            Level.ACTIVE,
            "Codex subscription status",
            (
                f"Auth mode: {status.get('auth_mode') or 'not signed in'}",
                f"Plan: {status.get('plan_type') or 'not reported'}",
                f"Model: {status.get('model') or 'not reported'}",
                f"Model available: {status.get('model_available')}",
                *(() if budgets is None else (f"Review budgets: {budgets}",)),
                f"Process cleanup: {status.get('process_cleanup')}",
            ),
        )

    async def _command_codex_subscription_disconnect(self) -> None:
        confirmed = await self.ask(
            ApprovalView(
                name="codex-subscription-disconnect",
                title="Log out the dedicated Codex home?",
                body=(
                    "Codex will log out only this evaluator home.",
                    "FinishUP then removes the subscription binding and recomposes the service.",
                ),
                approve_label="Disconnect",
                decline_label="Cancel",
                default_to_safe=True,
            )
        )
        if confirmed != "approve":
            self.say(Level.OPTIONAL, "Codex subscription disconnect was cancelled.")
            return
        try:
            status = await self.runtime.disconnect_codex_subscription()
        except RuntimeError_ as error:
            self._report(error)
            return
        self.say(
            Level.VERIFIED,
            "Codex subscription disconnected",
            (
                f"Binding removed: {status.get('binding_removed')}",
                f"Process cleanup: {status.get('process_cleanup')}",
            ),
        )

    async def _command_codex_subscription_rollback(self) -> None:
        confirmed = await self.ask(
            ApprovalView(
                name="codex-subscription-rollback",
                title="Remove only the FinishUP Codex binding?",
                body=(
                    "The dedicated Codex home and installation stay in place.",
                    "The running service is recomposed so the old cell cannot dispatch.",
                ),
                approve_label="Roll back binding",
                decline_label="Cancel",
                default_to_safe=True,
            )
        )
        if confirmed != "approve":
            self.say(Level.OPTIONAL, "Codex subscription rollback was cancelled.")
            return
        try:
            status = await self.runtime.rollback_codex_subscription()
        except RuntimeError_ as error:
            self._report(error)
            return
        self.say(
            Level.VERIFIED,
            "Codex subscription binding rolled back",
            (
                f"Binding removed: {status.get('binding_removed')}",
                "Dedicated home and Codex installation were preserved.",
            ),
        )

    async def _command_codex_subscription_repair(self) -> None:
        try:
            plan = self.runtime.codex_subscription_repair_plan()
        except RuntimeError_ as error:
            self._report(error)
            return
        changed = plan.get("changed_fields")
        changed_text = (
            ", ".join(str(item) for item in cast(list[object], changed))
            if isinstance(changed, list) and changed
            else "none"
        )
        confirmed = await self.ask(
            ApprovalView(
                name="codex-subscription-repair",
                title="Repair the Codex evaluator binding?",
                body=(
                    f"Current state: {plan.get('state_before')}",
                    f"Runtime source: {plan.get('source_path')}",
                    f"Bound runtime: {plan.get('executable_path_after')}",
                    f"Capability profile: {plan.get('capability_profile_before')} -> "
                    f"{plan.get('capability_profile_after')}",
                    f"Changed fields: {changed_text}",
                    "Model, reasoning effort, timeout, retries, dedicated home, endpoint role, "
                    "and privacy grants are kept.",
                    "The existing sign-in is reused only if Codex reports it; repair never signs "
                    "in, logs out, or switches accounts.",
                ),
                approve_label="Repair binding",
                decline_label="Cancel",
                default_to_safe=True,
            )
        )
        if confirmed != "approve":
            self.say(Level.OPTIONAL, "Codex evaluator repair was cancelled.")
            return
        try:
            status = await self.runtime.repair_codex_subscription()
        except RuntimeError_ as error:
            self._report(error)
            return
        self.say(
            Level.VERIFIED,
            "Codex evaluator binding repaired",
            (
                "Sign-in: reused the existing Codex login",
                f"Bound runtime: {status.get('executable_path')}",
                f"Model available: {status.get('model_available')}",
                f"Process cleanup: {status.get('process_cleanup')}",
            ),
        )

    async def _command_codex_evaluator_runtime_status(self) -> None:
        try:
            report = self.runtime.codex_evaluator_runtime_status()
        except RuntimeError_ as error:
            self._report(error)
            return
        managed = report.get("managed_runtime")
        binding = report.get("binding")
        managed_state = (
            cast(Mapping[str, object], managed).get("state")
            if isinstance(managed, Mapping)
            else None
        )
        host = (
            cast(Mapping[str, object], managed).get("code_mode_host")
            if isinstance(managed, Mapping)
            else None
        )
        host_state = (
            cast(Mapping[str, object], host).get("state") if isinstance(host, Mapping) else None
        )
        binding_state = (
            cast(Mapping[str, object], binding).get("state")
            if isinstance(binding, Mapping)
            else None
        )
        next_command = report.get("next_command")
        self.say(
            Level.ACTIVE if binding_state in {None, "ready"} else Level.BLOCKED,
            "Codex evaluator runtime",
            (
                f"Retained runtime: {managed_state or 'unavailable on this platform'}",
                f"Retained code-mode host: {host_state or 'unavailable on this platform'}",
                f"Binding: {binding_state or 'not configured'}",
                "Sign-in was not checked; use Codex subscription status for that.",
                *(() if next_command is None else (f"Next: {next_command}",)),
            ),
        )

    async def command_provider(self) -> None:
        options = self.runtime.provider_options()
        chosen = await self.ask(
            SelectionView(
                name="provider",
                title="Choose a provider for optional deeper review",
                options=[
                    Option(option.choice, option.label, option.endpoint_text) for option in options
                ]
                + [
                    Option(
                        "codex_status",
                        "Codex subscription status",
                        "Structural account and model read; no task case.",
                    ),
                    Option(
                        "codex_disconnect",
                        "Disconnect dedicated Codex home",
                        "Codex logout, then remove the FinishUP binding.",
                    ),
                    Option(
                        "codex_rollback",
                        "Roll back FinishUP Codex binding",
                        "Remove the binding; preserve home and install.",
                    ),
                    Option(
                        "codex_switch",
                        "Switch Codex ChatGPT account",
                        "Log out the dedicated home, then sign in again.",
                    ),
                    Option(
                        "codex_repair",
                        "Repair Codex evaluator binding",
                        "Rebind to FinishUP's retained runtime; keep sign-in and settings.",
                    ),
                    Option(
                        "codex_runtime",
                        "Codex evaluator runtime status",
                        "Retained runtime and binding structure; no sign-in check.",
                    ),
                ],
                searchable=True,
                hint="type to filter · enter to choose · esc to cancel",
            )
        )
        if chosen is None:
            self.say(Level.OPTIONAL, "No provider was configured.")
            return
        if chosen == "codex_subscription":
            await self._command_codex_subscription()
            return
        if chosen == "codex_status":
            await self._command_codex_subscription_status()
            return
        if chosen == "codex_disconnect":
            await self._command_codex_subscription_disconnect()
            return
        if chosen == "codex_rollback":
            await self._command_codex_subscription_rollback()
            return
        if chosen == "codex_switch":
            await self._command_codex_subscription(switch_account=True)
            return
        if chosen == "codex_repair":
            await self._command_codex_subscription_repair()
            return
        if chosen == "codex_runtime":
            await self._command_codex_evaluator_runtime_status()
            return
        option = next(item for item in options if item.choice == chosen)
        origin: str | None = None
        if option.requires_origin:
            entry = TextEntryView(
                name="provider-origin",
                title=option.label,
                label="HTTPS origin of your endpoint",
                placeholder="https://example.internal",
            )
            if await self.ask(entry) is None:
                return
            origin = entry.value.strip()
        model_entry = TextEntryView(
            name="provider-model",
            title=option.label,
            label="Model identifier",
            initial=option.default_model,
            placeholder="model id",
        )
        if await self.ask(model_entry) is None:
            self.say(Level.OPTIONAL, "No provider was configured.")
            return
        model = model_entry.value.strip()

        confirmed = await self.ask(
            ApprovalView(
                name="provider-confirm",
                title="",
                body=render_provider_endpoint(option, model, self.body_width),
                approve_label="Save this provider binding",
                decline_label="Cancel",
            )
        )
        if confirmed != "approve":
            self.say(Level.OPTIONAL, "No provider was configured.")
            return
        try:
            self.runtime.save_provider_binding(option, model, https_origin=origin)
        except RuntimeError_ as error:
            self._report(error)
            return
        try:
            # Authorize the exact provider channel before any credential-bearing probe can run.
            report = await self.hand_over_terminal(
                lambda: self.runtime.run_privacy_setup(None, offer_recommended=True)
            )
        except SuspendNotSupported:
            self.say(
                Level.UNPROVEN,
                "This terminal cannot open the trusted privacy ceremony",
                ("Run 'finishup privacy setup' from your shell before storing the API key.",),
            )
            return
        except RuntimeError_ as error:
            self._report(error)
            return
        if getattr(report, "outcome", "failed") not in {"configured", "unchanged"}:
            self.say(
                Level.BLOCKED,
                "AI-powered review privacy setup is not complete",
                (f"Reason: {getattr(report, 'reason', 'privacy_setup_failed')}",),
            )
            return
        grant_state = getattr(report, "grant_state", None)
        if grant_state != "granted":
            self.say(
                Level.BLOCKED,
                "Provider binding saved, without repository authority",
                (
                    "The exact repository grant is missing, so no API key was requested.",
                    "Run /privacy from this repository before continuing provider setup.",
                ),
            )
            return
        authority_details = [
            "Provider binding saved.",
            "Exact repository grant: granted for this repository.",
        ]
        if getattr(report, "migration_state", None) == "consumed":
            authority_details.append(
                "Existing permission was carried forward and narrowed to this repository."
            )
        self.say(
            Level.VERIFIED,
            "Repository privacy authority ready",
            tuple(authority_details),
        )
        status = await self._run_confidential(
            "Provider API key",
            self.runtime.store_provider_credential,
            fallback_command="finishup provider credential set",
        )
        posture = await self.runtime.provider_posture()
        if status is None:
            self.say(
                Level.UNPROVEN,
                "Provider binding saved, without a key",
                ("The endpoint is recorded. No API key was stored.",),
            )
            return
        self.say(Level.ACTIVE, "", render_provider_stored(posture, self.body_width))

    async def command_service(self) -> None:
        posture = await self.runtime.vault_posture()
        self.say(
            Level.ACTIVE,
            "Local service",
            (
                f"Reachable: {'yes' if posture.reachable else 'no'}",
                f"State: {posture.state or 'not running'}",
                f"Secure storage: {posture.vault_mode or 'not set up'}",
            ),
        )
        choice = await self.ask(
            SelectionView(
                name="service",
                options=[
                    Option("unlock", "Unlock", "Uses the secure prompt on this terminal."),
                    Option("init", "Set up a passphrase", "First install only."),
                    Option(
                        "rotate",
                        "Change the passphrase",
                        "Confirms the current one, then asks for a new one.",
                    ),
                    Option("lock", "Lock now"),
                    Option("stop", "Stop the service", "FinishUP will not restart it for you."),
                ],
                hint="enter to choose · esc to go back",
            )
        )
        if choice is None:
            return
        if choice == "unlock":
            await self._run_confidential("Unlock FinishUP", self.runtime.unlock_vault)
        elif choice == "init":
            await self._run_confidential(
                "Choose a FinishUP passphrase",
                self.runtime.initialize_passphrase_vault,
                fallback_command="finishup service initialize-passphrase",
            )
        elif choice == "rotate":
            await self._run_confidential(
                "Change your FinishUP passphrase",
                self.runtime.rotate_vault_passphrase,
                fallback_command="finishup service rotate-passphrase",
            )
        elif choice == "lock":
            state = await self.runtime.service_lock()
            self.say(Level.VERIFIED, f"Locked. Service state: {state}")
        else:
            confirmed = await self.ask(
                ApprovalView(
                    name="service-stop",
                    title="Stop the local service?",
                    body=(
                        "FinishUP will stop responding to checks and receipts until",
                        "you start it again with 'finishup service run'.",
                    ),
                    approve_label="Yes, stop it",
                    decline_label="No, leave it running",
                    default_to_safe=True,
                )
            )
            if confirmed == "approve":
                state = await self.runtime.service_stop()
                self.say(Level.VERIFIED, f"Stopping. Service state: {state}")
            else:
                self.say(Level.OPTIONAL, "The service is still running.")

    async def command_work(self) -> None:
        recent = self.runtime.opened_titles
        rows = [Option(f"task:{title}", title, "opened in this session") for title in recent]
        rows.append(Option("open", "Open a task by session ID"))
        chosen = await self.ask(
            SelectionView(
                name="work",
                title="Your work",
                body=()
                if recent
                else (
                    "Open a task using the session ID returned by FinishUP start.",
                    "Its title or workspace alone cannot select work to resume.",
                ),
                options=rows,
                searchable=bool(recent),
                hint="enter to choose · esc to go back",
            )
        )
        if chosen is None:
            return
        title = chosen[5:] if chosen.startswith("task:") else None
        if title is None:
            entry = TextEntryView(
                name="work-open",
                title="Open a task",
                label="Session ID",
                placeholder="ses_…",
            )
            if await self.ask(entry) is None:
                return
            title = entry.value.strip()
        self.say(Level.ACTIVE, f"Opening {title}")
        detail = await self.runtime.open_task(title)
        self._active_task_title = title
        self.settle(Level.ACTIVE, title, render_work_detail(detail, self.body_width))

    async def command_lineage(self) -> None:
        await self._command_task_view("lineage")

    async def command_project(self) -> None:
        await self._command_task_view("project")

    async def command_findings(self) -> None:
        await self._command_task_view("findings")

    async def _command_task_view(self, view: Literal["lineage", "project", "findings"]) -> None:
        title = await self._require_task()
        if title is None:
            return
        heading = {"lineage": "Child tasks", "project": "Project", "findings": "Findings"}[view]
        cursor: str | None = None
        while True:
            page = await self.runtime.task_status(title, view, cursor=cursor)
            self.settle(Level.ACTIVE, heading, page.lines)
            if page.next_cursor is None:
                return
            chosen = await self.ask(
                SelectionView(
                    name="task-view-page",
                    title="More results are available",
                    options=[
                        Option("next", "Next page", "Continue this task view."),
                        Option("done", "Done", "Return to the conversation."),
                    ],
                    hint="enter to choose · esc to finish",
                )
            )
            if chosen != "next":
                return
            cursor = page.next_cursor

    async def command_check(self) -> None:
        title = await self._require_task()
        if title is None:
            return
        chosen = await self.ask(
            SelectionView(
                name="check-mode",
                title="How should FinishUP check this?",
                options=[Option(mode.value, mode.label, mode.description) for mode in CheckMode],
                hint="enter to choose · esc to cancel",
            )
        )
        if chosen is None:
            return
        mode = CheckMode(chosen)
        heading = f"Checking {title} ({mode.label.lower()})"
        self.say(Level.ACTIVE, heading)
        check = asyncio.ensure_future(self.runtime.run_check(title, mode))
        try:
            while True:
                done, _pending = await asyncio.wait({check}, timeout=self.progress_poll_seconds)
                if done:
                    break
                # Structural phase and elapsed time only; the check itself keeps running
                # service-side even if this view stops polling (issue #571 A2).
                try:
                    progress = await self.runtime.check_progress(title)
                except RuntimeError_:
                    continue
                self.settle(Level.ACTIVE, heading, _progress_lines(progress.lines))
        finally:
            if not check.done():
                check.cancel()
        verdict, lines = check.result()
        if verdict in {"awaiting_human", "awaiting_input"}:
            heading = (
                "Check awaiting review input"
                if verdict == "awaiting_input"
                else "Check awaiting your decision"
            )
            self.settle(Level.ACTIVE, heading, lines)
            return
        level = Level.VERIFIED if verdict == "pass" else Level.UNPROVEN
        self.settle(level, f"Check complete: {verdict}", lines)

    async def command_progress(self) -> None:
        title = await self._require_task()
        if title is None:
            return
        page = await self.runtime.check_progress(title)
        self.settle(Level.ACTIVE, "Check progress", page.lines)

    async def command_receipt(self) -> None:
        title = await self._require_task()
        if title is None:
            return
        chosen = await self.ask(
            SelectionView(
                name="receipt-format",
                title="Receipt format",
                options=[
                    Option("markdown", "Markdown", "Readable, good for sharing."),
                    Option("text", "Plain text"),
                    Option("json", "JSON", "Exact machine-readable record."),
                ],
                hint="enter to choose · esc to cancel",
            )
        )
        if chosen is None:
            return
        self.say(Level.ACTIVE, f"Building a receipt for {title}")
        summary = await self.runtime.build_receipt(title, chosen)
        self.settle(
            Level.ACTIVE,
            f"Receipt for {title}",
            render_receipt(summary, self.body_width),
            details=(f"format={chosen}", f"task_id={summary.subject_id}"),
        )

    async def _require_task(self) -> str | None:
        if self._active_task_title is not None:
            return self._active_task_title
        await self.command_work()
        return self._active_task_title


def _efforts_with_default(default: str) -> tuple[str, ...]:
    """The reviewed reasoning efforts with ``default`` first, so the preselection preserves it."""

    efforts = ("high", "low", "medium", "xhigh", "max", "ultra")
    return (default, *(item for item in efforts if item != default))
