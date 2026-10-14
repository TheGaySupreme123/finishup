"""``/observe`` shows the effective budget and changes capacity only through a disclosed preview.

A larger local retention capacity costs disk, memory, and CPU work, and "no FinishUP cap" is not
supported by the structural queue in this storage revision (#828). These tests drive the flow
with a fake runtime and pin the owner-visible contract: the status block names the effective
budget, every change is previewed with the shared disclosure wording before anything is applied,
cancel and ``Esc`` change nothing and say so, apply sends exactly the previewed digest, and a
no-cap request explains itself without calling apply.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from finishup.domain.observation_budget import (
    STANDARD_CAPACITY,
    BudgetLimits,
    CapacityRequest,
    ObservationCapacity,
    no_cap_support,
)
from finishup.domain.observation_capacity_policy import (
    capacity_change_disclosure,
    render_capacity_disclosure_lines,
)
from finishup.tui.app import FinishUpTui
from finishup.tui.commands import command_named
from finishup.tui.runtime import ObservationCapacityUnavailable, RuntimeError_
from finishup.tui.symbols import Level
from finishup.tui.widgets.views import ApprovalView, BaseView, SelectionView, TextEntryView

pytestmark = pytest.mark.anyio

_ROOT = Path("/srv/finishup")
_DIGEST = "sha256:" + "ab" * 32
_ALTERNATIVE = (
    "finishup observe selection-preview --workspace <workspace> --detail focused "
    "--capacity largest --persist"
)

type Answer = str | None | tuple[str, str]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _effective_budget(
    capacity: ObservationCapacity = STANDARD_CAPACITY, *, utilization_bps: int = 1_250
) -> dict[str, object]:
    limits = BudgetLimits.for_capacity(capacity)
    return {
        "schema": "yoetz.observation-effective-budget/1",
        "budget_policy_version": "observation-budget-v2-provisional",
        "validation_status": "not_validated",
        "scope": "workspace",
        "selected_queue_count": capacity.queue_count,
        "selected_capacity_label": capacity.label,
        "effective_queue_count": capacity.queue_count,
        "effective_capacity_label": capacity.label,
        "effective_reason": "selected",
        "limits": {
            "queue_count": limits.queue_count,
            "queue_bytes": limits.queue_bytes,
            "state_bytes": limits.state_bytes,
        },
        "limiting_dimension": "count",
        "utilization_bps": utilization_bps,
        "no_cap": dict(no_cap_support()),
    }


def _status(*, budget: bool = True) -> dict[str, object]:
    selected = {
        "detail": "focused",
        "mode": "focused",
        "capacity": 512,
        "capacity_profile": "standard",
        "queue_count": 512,
        "origin": "default",
        "expires_at": None,
    }
    status: dict[str, object] = {
        "selected": selected,
        "effective": selected,
        "effective_reason": "selected",
        "session_scope": False,
        "accounting": {"observed_count": 3},
    }
    if budget:
        status["effective_budget"] = _effective_budget()
    return status


def _selection(capacity: ObservationCapacity) -> dict[str, object]:
    return {
        "detail": "focused",
        "mode": "focused",
        "capacity": capacity.queue_count,
        "capacity_profile": capacity.label,
        "queue_count": capacity.queue_count,
        "origin": "workspace",
        "expires_at": None,
    }


class _Runtime:
    """Only what ``/observe`` asks: status, preview, apply, and the project root."""

    def __init__(
        self,
        *,
        budget: bool = True,
        preview_error: RuntimeError_ | None = None,
        current: ObservationCapacity = STANDARD_CAPACITY,
    ) -> None:
        self._status = _status(budget=budget)
        self._current = current
        self._preview_error = preview_error
        self.previews: list[CapacityRequest] = []
        self.applies: list[tuple[CapacityRequest, str]] = []

    def project_root(self) -> Path:
        return _ROOT

    async def observation_selection_status(self) -> Mapping[str, object]:
        return self._status

    def _disclosure(self, capacity: CapacityRequest) -> Mapping[str, object]:
        return capacity_change_disclosure(
            current=self._current,
            current_origin="default",
            requested=capacity,
            scope="workspace",
        )

    async def preview_observation_selection(
        self, capacity: CapacityRequest
    ) -> Mapping[str, object]:
        self.previews.append(capacity)
        if self._preview_error is not None:
            raise self._preview_error
        disclosure = self._disclosure(capacity)
        if capacity.capacity is None:
            raise ObservationCapacityUnavailable(
                render_capacity_disclosure_lines(disclosure), _ALTERNATIVE
            )
        return {
            "preview_digest": _DIGEST,
            "disclosure": disclosure,
            "current_selection": _selection(STANDARD_CAPACITY) | {"origin": "default"},
            "requested_selection": _selection(capacity.capacity),
            "current_effective_budget": _effective_budget(),
            "next_command": "finishup observe selection-apply --workspace <workspace>",
        }

    async def apply_observation_selection(
        self, capacity: CapacityRequest, preview_digest: str
    ) -> Mapping[str, object]:
        self.applies.append((capacity, preview_digest))
        assert capacity.capacity is not None
        return {
            "applied": True,
            "selection": _selection(capacity.capacity),
            "effective_budget": _effective_budget(capacity.capacity, utilization_bps=156),
            "disclosure": self._disclosure(capacity),
        }


class _Harness:
    """A ``FinishUpTui`` with the mounted-widget surfaces replaced by recording stubs."""

    def __init__(self, runtime: _Runtime, answers: Sequence[Answer]) -> None:
        self.runtime = runtime
        self.app = FinishUpTui(runtime)  # pyright: ignore[reportArgumentType]
        self.said: list[tuple[Level, str, tuple[str, ...]]] = []
        self.views: list[BaseView] = []
        self.answers: list[Answer] = list(answers)

        def say(
            level: Level,
            title: str,
            body: Sequence[str] = (),
            *,
            details: Sequence[str] = (),
        ) -> None:
            del details
            self.said.append((level, title, tuple(body)))

        async def ask(view: BaseView) -> str | None:
            self.views.append(view)
            answer = self.answers.pop(0)
            if isinstance(view, TextEntryView):
                if answer is None:
                    return None
                assert isinstance(answer, tuple)
                view.value = answer[1]
                return answer[0]
            assert isinstance(view, SelectionView)
            assert not isinstance(answer, tuple)
            return answer

        self.app.say = say  # pyright: ignore[reportAttributeAccessIssue]
        self.app.settle = say  # pyright: ignore[reportAttributeAccessIssue]
        self.app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]

    async def run(self) -> None:
        await self.app.command_observe()
        assert self.answers == [], "the flow asked fewer questions than scripted"

    @property
    def transcript(self) -> str:
        return "\n".join(f"{title}\n" + "\n".join(body) for _level, title, body in self.said)

    def titled(self, title: str) -> tuple[Level, tuple[str, ...]]:
        # The latest event wins: an activity line is settled into its completed form.
        for level, said_title, body in reversed(self.said):
            if said_title == title:
                return level, body
        raise AssertionError(f"nothing said under {title!r}:\n{self.transcript}")


def _custom(count: int) -> CapacityRequest:
    return CapacityRequest.for_capacity(ObservationCapacity(count))


async def test_status_shows_the_effective_budget_then_offers_keep_first() -> None:
    harness = _Harness(_Runtime(), [None])

    await harness.run()

    _level, body = harness.titled("Observation selection")
    assert "capacity: selected 512 rows (standard); effective 512 rows (standard)" in body
    assert "capacity reason: selected" in body
    assert "closest limit: count; 12.50% used (1250 bps)" in body
    assert "no FinishUP cap: unavailable (state document ceiling 16 MiB)" in body
    assert "detail and capacity do not change content or privacy authority" in body
    view = harness.views[0]
    assert isinstance(view, SelectionView)
    assert view.title_text == "Change local retention capacity?"
    assert [option.key for option in view.options] == [
        "keep",
        "recommended",
        "larger",
        "largest",
        "custom",
        "no_cap",
    ]
    # Keep is the default: a stray Enter never changes anything.
    assert view.cursor == 0
    larger = next(option for option in view.options if option.key == "larger")
    assert larger.description == "Can use more local disk, memory, and CPU work."


async def test_a_status_without_an_effective_budget_says_unknown() -> None:
    harness = _Harness(_Runtime(budget=False), ["keep"])

    await harness.run()

    _level, body = harness.titled("Observation selection")
    assert "capacity: unknown" in body
    assert "closest limit: unknown" in body
    assert "no FinishUP cap: unknown" in body


@pytest.mark.parametrize("answer", [None, "keep"])
async def test_keeping_or_escaping_changes_nothing(answer: str | None) -> None:
    runtime = _Runtime()
    harness = _Harness(runtime, [answer])

    await harness.run()

    assert runtime.previews == []
    assert runtime.applies == []
    assert "Capacity was left unchanged." in harness.transcript


@pytest.mark.parametrize("answer", ["cancel", None])
async def test_custom_preview_discloses_the_change_and_cancel_leaves_it_unchanged(
    answer: str | None,
) -> None:
    runtime = _Runtime()
    harness = _Harness(runtime, ["custom", ("submit", "1024"), answer])

    await harness.run()

    assert runtime.previews == [_custom(1024)]
    assert runtime.applies == []
    _level, body = harness.titled("Proposed local retention capacity")
    assert "Capacity: 512 rows (standard) → 1,024 rows (custom)" in body
    assert "Detail: focused (unchanged)" in body
    assert "Scope: this workspace (persisted)" in body
    shown = "\n".join(body)
    assert "Larger local retention can increase disk use" in shown
    assert "Still limited: 256 pending pairs" in shown
    assert (
        "The shared workspace queue follows the largest active selection, so this can raise "
        "the queue and state-document bounds for every session in the workspace."
    ) in shown
    assert (
        "Pause new observation ingest with: finishup observe pause --workspace <workspace>" in shown
    )
    assert "Resume with: finishup observe resume --workspace <workspace>." in shown
    assert str(_ROOT) not in shown
    assert "Performance validation is provisional (not_validated)." in shown
    approval = harness.views[-1]
    assert isinstance(approval, ApprovalView)
    assert [option.key for option in approval.options] == ["apply", "cancel"]
    # Cancel is the default on the apply question.
    assert approval.options[approval.cursor].key == "cancel"
    assert "Capacity was left unchanged." in harness.transcript


async def test_applying_a_decrease_points_back_at_the_default_instead_of_lowering() -> None:
    # After lowering to Recommended, "lower it later -> Recommended" would be
    # circular; after a custom count below 512 it would raise the capacity.
    runtime = _Runtime(current=ObservationCapacity(2_048))
    harness = _Harness(runtime, ["recommended", "apply"])

    await harness.run()

    assert runtime.applies == [(CapacityRequest.for_capacity(STANDARD_CAPACITY), _DIGEST)]
    _, body = harness.titled("Local retention capacity applied")
    assert "Lower it later: /observe → Recommended." not in body
    assert (
        "Return to the default with: finishup observe selection-revoke --workspace <workspace> "
        "--persist" in body
    )


async def test_apply_sends_the_previewed_digest_and_shows_the_lower_and_pause_path() -> None:
    runtime = _Runtime()
    harness = _Harness(runtime, ["larger", "apply"])

    await harness.run()

    larger = ObservationCapacity(2_048)
    assert runtime.previews == [CapacityRequest.for_capacity(larger)]
    assert runtime.applies == [(CapacityRequest.for_capacity(larger), _DIGEST)]
    level, body = harness.titled("Local retention capacity applied")
    assert level is Level.VERIFIED
    assert "Selected: 2,048 rows (larger), detail focused, this workspace" in body
    assert "capacity: selected 2,048 rows (larger); effective 2,048 rows (larger)" in body
    assert "closest limit: count; 1.56% used (156 bps)" in body
    assert any(
        line.startswith("Lower it later with: finishup observe selection-preview") for line in body
    )
    assert "--capacity standard --persist" in " ".join(body)
    assert (
        "Pause new observation ingest with: finishup observe pause --workspace <workspace>" in body
    )
    assert "Resume with: finishup observe resume --workspace <workspace>" in body
    # The project path is never echoed into a command.
    assert str(_ROOT) not in harness.transcript
    # The setting is never described as safe, and validation is never claimed.
    assert re.search(r"\bsafe\b", harness.transcript, re.IGNORECASE) is None
    assert "not_validated" in harness.transcript
    assert "validated as" not in harness.transcript


async def test_custom_increase_below_standard_restores_the_smaller_count() -> None:
    runtime = _Runtime(current=ObservationCapacity(64))
    harness = _Harness(runtime, ["custom", ("submit", "128"), "apply"])

    await harness.run()

    assert runtime.applies == [(CapacityRequest.for_capacity(ObservationCapacity(128)), _DIGEST)]
    _, body = harness.titled("Local retention capacity applied")
    assert any(
        line.startswith("Lower it later with: finishup observe selection-preview") for line in body
    )
    assert "--capacity custom --queue-count 64 --persist" in " ".join(body)
    assert "Recommended" not in " ".join(body)
    assert "--capacity standard" not in " ".join(body)


async def test_no_cap_explains_the_ceiling_and_never_applies() -> None:
    runtime = _Runtime()
    harness = _Harness(runtime, ["no_cap"])

    await harness.run()

    assert runtime.previews == [CapacityRequest("no_cap", None)]
    assert runtime.applies == []
    level, body = harness.titled("No FinishUP cap is not available")
    assert level is Level.OPTIONAL
    shown = "\n".join(body)
    assert "No FinishUP cap is not available for the structural queue" in shown
    assert "16 MiB safety ceiling" in shown
    assert f"Alternative: choose Largest (8,192 rows) in /observe, or run: {_ALTERNATIVE}" in shown
    assert "Capacity was left unchanged." in shown
    # No apply/cancel question is ever opened for an unsupported request.
    assert not any(isinstance(view, ApprovalView) for view in harness.views)


async def test_invalid_custom_input_is_blocked_without_echo_and_changes_nothing() -> None:
    runtime = _Runtime()
    harness = _Harness(
        runtime,
        ["custom", ("submit", "lots-of-rows"), ("submit", "63"), ("submit", "9000"), None],
    )

    await harness.run()

    assert runtime.previews == []
    assert runtime.applies == []
    blocked = [body for level, _title, body in harness.said if level is Level.BLOCKED]
    assert len(blocked) == 3
    assert all("Nothing changed." in body for body in blocked)
    assert "lots-of-rows" not in harness.transcript
    assert "Capacity was left unchanged." in harness.transcript
    entry = harness.views[1]
    assert isinstance(entry, TextEntryView)


async def test_a_corrected_custom_entry_is_previewed_after_a_blocked_one() -> None:
    runtime = _Runtime()
    harness = _Harness(runtime, ["custom", ("submit", "99999"), ("submit", "4,096"), "cancel"])

    await harness.run()

    assert runtime.previews == [_custom(4_096)]
    assert runtime.applies == []


async def test_a_preview_failure_is_blocked_and_changes_nothing() -> None:
    runtime = _Runtime(
        preview_error=RuntimeError_(
            "observation_selection_preview_failed",
            "the capacity preview could not be built",
        )
    )
    harness = _Harness(runtime, ["largest"])

    await harness.run()

    level, body = harness.titled("The capacity preview could not be built")
    assert level is Level.BLOCKED
    assert "Reason: observation_selection_preview_failed" in body
    assert "Capacity was left unchanged." in body
    assert runtime.applies == []


def test_the_command_list_names_the_capacity_change() -> None:
    command = command_named("/observe")
    assert command is not None
    assert command.summary == "show observation selection and change local retention capacity"
