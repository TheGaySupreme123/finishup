"""A shell write after a check supersedes it like an edit tool does (ADR-045, ADR-046, #1029).

A COMMAND action whose runtime tokens record ``write workspace`` / ``write outside_workspace``
(the hook's lexical read of ``cat > f``, ``sed -i``) is an edit by the one rule
``observed_shell_write_counts`` that ``task_facts`` already used for the latest edit. Before this
change ``classify_later_material`` sent it through the runner class to ``OTHER``, so the check
stayed current-with-a-gap and a stale ``declared_output_emptied`` fact survived a refill.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

from builders.observed_runs import ObservedLedger
from finishup.application.review_concern import _is_material  # pyright: ignore[reportPrivateUsage]
from finishup.domain.events import (
    AcceptedEvent,
    ActionKind,
    CheckRecordedPayload,
    DeliverableState,
    ResultOutcome,
)
from finishup.domain.values import obligation_id
from finishup.kernel.closure_class import (
    _emptied_obligations,  # pyright: ignore[reportPrivateUsage]
)
from finishup.kernel.concern import ConcernKey
from finishup.kernel.later_material import LaterMaterialClass, classify_later_material
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay
from unit.kernel.test_tb4n3_own_calls import (  # noqa: F401 - fixture + helpers
    _after_check,  # pyright: ignore[reportPrivateUsage]
    _surfaces,  # pyright: ignore[reportPrivateUsage]
    identity_key,  # noqa: F401  # pyright: ignore[reportUnusedImport]
)

_C = LaterMaterialClass


def _shell(
    ledger: ObservedLedger, scope: str | None, outcome: ResultOutcome, **kwargs: Any
) -> None:
    ledger.run(
        None,
        outcome,
        exit_status=0 if outcome is ResultOutcome.SUCCESS else None,
        kind=ActionKind.COMMAND,
        tool="exec_command",
        runner="compound",
        write_scope=scope,
        **kwargs,
    )


def _classes(ledger: ObservedLedger) -> set[LaterMaterialClass]:
    projection = replay(ledger.prefix)
    return {classify_later_material(r, projection).material_class for r in ledger.prefix[-2:]}


@pytest.mark.parametrize(
    "outcome", (ResultOutcome.SUCCESS, ResultOutcome.FAILURE, ResultOutcome.UNKNOWN)
)
# n7 RC2 (#1106): a write of only project documentation leaves verification current but is
# still material work after a check.
@pytest.mark.parametrize("scope", ("workspace", "outside_workspace", "docs"))
def test_a_shell_write_supersedes_the_check_whatever_its_outcome(
    scope: str, outcome: ResultOutcome
) -> None:
    ledger = _after_check()
    _shell(ledger, scope, outcome)
    assert _classes(ledger) == {_C.EDIT_OR_WRITE}
    surfaces = _surfaces(ledger.prefix)
    assert surfaces.superseded is True
    assert surfaces.readiness_applicability == "not_applicable"
    assert "check_not_applicable" in surfaces.readiness_actionable


@pytest.mark.parametrize("scope", (None, "none"))
def test_a_command_without_a_write_scope_stays_unclassified(scope: str | None) -> None:
    ledger = _after_check()
    _shell(ledger, scope, ResultOutcome.SUCCESS)
    assert _classes(ledger) == {_C.OTHER}
    assert _surfaces(ledger.prefix).superseded is False


def test_finishup_exploration_commands_never_supersede() -> None:
    """A read-shaped command never supersedes. PR #1080: its text alone no longer makes it
    exploration either; only the hook's ``unchanged`` workspace fingerprint does."""

    from finishup.kernel.later_material import workspace_effects

    for effect, expected in ((None, _C.OTHER), ("unchanged", _C.EXPLORATION)):
        ledger = _after_check()
        ledger.run(
            None,
            ResultOutcome.SUCCESS,
            exit_status=0,
            kind=ActionKind.COMMAND,
            tool="exec_command",
            runner="exploration",
            workspace_effect=effect,
        )
        projection = replay(ledger.prefix)
        effects = workspace_effects(ledger.prefix, projection)
        assert {
            classify_later_material(r, projection, effects=effects).material_class
            for r in ledger.prefix[-2:]
        } == {expected}
        assert _surfaces(ledger.prefix).superseded is False


def test_a_shell_write_to_scratch_is_not_an_edit() -> None:
    ledger = _after_check()
    _shell(ledger, "scratch", ResultOutcome.SUCCESS)
    assert _surfaces(ledger.prefix).superseded is False


def test_a_refill_by_shell_write_clears_the_stale_emptied_fact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check read the file emptied; the agent refills it with ``cat >``; the fact is stale."""

    from finishup.kernel import closure_class
    from finishup.kernel.check_standing import check_standing

    ledger = _after_check()
    check = cast(AcceptedEvent, ledger.prefix[-1])
    obligation = obligation_id("obl_00000000-0000-4000-8000-0000000000e1")
    emptied = replace(
        cast(CheckRecordedPayload, check.payload),
        deliverable_states=(
            DeliverableState(obligation, 0, change="emptied", proof="task_base", size_bytes=0),
        ),
    )
    # The emptied check record is a stand-in (a real one needs a re-sealed entry digest); the
    # standing is still computed from the real ledger.
    stand_in = SimpleNamespace(event_id=check.event_id, payload=emptied)

    def real_standing(state: ProjectionState, _records: object) -> Any:
        return check_standing(state, ledger.prefix)

    monkeypatch.setattr(closure_class, "check_standing", real_standing)

    def emptied_now() -> frozenset[Any]:
        return _emptied_obligations(replay(ledger.prefix), cast(Any, (stand_in,)))

    assert emptied_now() == {obligation}
    _shell(ledger, "workspace", ResultOutcome.SUCCESS)
    assert emptied_now() == frozenset()


def _concern_index(ledger: ObservedLedger) -> Any:
    projection = replay(ledger.prefix)
    return SimpleNamespace(
        case=SimpleNamespace(projection=projection),
        linked_refs=lambda _obligations: frozenset[str](),  # pyright: ignore[reportUnknownLambdaType]
    )


@pytest.mark.parametrize(
    ("scope", "material"), (("workspace", True), ("docs", True), (None, False))
)
def test_a_shell_write_defeats_a_concern_fold(scope: str | None, material: bool) -> None:
    ledger = _after_check()
    _shell(ledger, scope, ResultOutcome.SUCCESS)
    projection = replay(ledger.prefix)
    action_ref, action = list(projection.actions.items())[-1]
    concern = ConcernKey(obligations=frozenset({"obl_x"}), refs=frozenset())
    row = SimpleNamespace(kind="action", ref=str(action_ref), sequence=action.source_frontier)
    assert _is_material(_concern_index(ledger), cast(Any, row), concern) is material
