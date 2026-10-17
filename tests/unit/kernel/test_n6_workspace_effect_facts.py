"""How the kernel folds a call's workspace facts (PR #1080 round 6, review findings 1 and 3).

A later delivery's fact arrives as an observed evidence annotation under the call's action; it is
folded with the result's own fact, ``changed``/``unavailable`` winning. A task that declares a
delivery where the fingerprint does not fully walk gets no ``unchanged`` command at all.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.domain.events import (
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
)
from finishup.domain.values import obligation_id
from finishup.domain.workspace_effect import path_beyond_workspace_fingerprint
from finishup.kernel.closing_review_delta import closing_material_frontier, closing_review_delta
from finishup.kernel.later_material import (
    LaterMaterialClass,
    classify_later_material,
    counted_later_material,
    workspace_effects,
)
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def test_a_later_unchanged_annotation_quiets_a_call_recorded_without_a_fact() -> None:
    ledger = ObservedLedger()
    result = ledger.passes("date -u")
    state = replay(ledger.prefix)
    assert closing_material_frontier(state, ledger.prefix) > 0
    annotation = ledger.annotate_workspace_effect(result, "unchanged")
    state = replay(ledger.prefix)
    effects = workspace_effects(ledger.prefix, state)
    assert effects.quiet and dict(effects.annotations) == {annotation: next(iter(effects.quiet))}
    assert not any(closing_review_delta(row, state, effects=effects) for row in ledger.prefix)
    assert closing_material_frontier(state, ledger.prefix) == 0
    row = ledger.records[-1]
    classified = classify_later_material(row, state, effects=effects)
    assert classified.material_class is LaterMaterialClass.EXPLORATION
    assert classified.rule == "workspace_effect_of_action"
    assert counted_later_material(ledger.records, state, all_records=ledger.prefix) == ()


@pytest.mark.parametrize("later", ["changed", "unavailable"])
def test_a_contradicting_annotation_rearms_at_its_own_position(later: str) -> None:
    ledger = ObservedLedger()
    result = ledger.passes("date -u", workspace_effect="unchanged")
    reviewed = len(ledger.records)
    ledger.annotate_workspace_effect(result, later)
    state = replay(ledger.prefix)
    effects = workspace_effects(ledger.prefix, state)
    assert not effects.quiet
    assert closing_review_delta(ledger.records[-1], state, effects=effects)
    # A closing review taken after the original result is stale once the contradiction lands.
    assert closing_material_frontier(state, ledger.prefix) > reviewed
    counted = counted_later_material(ledger.records[reviewed:], state, all_records=ledger.prefix)
    assert counted == (ledger.records[-1],)


def test_an_agent_published_or_unlinked_annotation_says_nothing() -> None:
    ledger = ObservedLedger()
    result = ledger.passes("date -u")
    ledger.annotate_workspace_effect(result, "unchanged", observed=False)
    state = replay(ledger.prefix)
    effects = workspace_effects(ledger.prefix, state)
    assert effects.quiet == frozenset() and not effects.annotations
    assert closing_material_frontier(state, ledger.prefix) > 0


def test_another_tools_annotation_follows_its_tool_rule() -> None:
    """A non-shell tool is material only on ``changed``, whichever row carries the fact."""

    from finishup.domain.events import ActionKind, ResultOutcome

    for effect, material in (("changed", True), ("unavailable", False), ("unchanged", False)):
        ledger = ObservedLedger()
        result = ledger.run(
            None, ResultOutcome.SUCCESS, kind=ActionKind.OTHER, tool="write_stdin", runner="other"
        )
        ledger.annotate_workspace_effect(result, effect)
        state = replay(ledger.prefix)
        assert (closing_material_frontier(state, ledger.prefix) > 0) is material, effect


def _declare(ledger: ObservedLedger, value: str, role: RequestedItemRole | None) -> None:
    obligation = obligation_id("obl_00000000-0000-4000-8000-000000001086")
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=obligation,
            description="Deliver the report",
            evidence_expectation="A report",
            status=ObligationStatus.OPEN,
            requested_items=(RequestedItem(RequestedItemKind.FILE, value, role),),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Deliver the report", (obligation,)),
        observed=False,
    )


@pytest.mark.parametrize(
    "value",
    [
        "venv/report.txt",
        ".venv/lib/python3.12/site-packages/pkg/patch.py",
        "node_modules/pkg/index.js",
        ".git/config",
        "src/__pycache__/module.cpython-312.pyc",
        ".pytest_cache/report.txt",
        "out/finishup-receipt.md",
    ],
)
def test_a_declared_delivery_the_fingerprint_cannot_fully_see_quiets_nothing(value: str) -> None:
    """The review's ``venv/report.txt`` probe: a quiet command no longer outranks the delivery."""

    assert path_beyond_workspace_fingerprint(value)
    ledger = ObservedLedger()
    _declare(ledger, value, RequestedItemRole.OUTPUT)
    start = len(ledger.records)
    ledger.passes("python generate.py", workspace_effect="unchanged")
    state = replay(ledger.prefix)
    assert workspace_effects(ledger.prefix, state).quiet == frozenset()
    assert any(
        closing_review_delta(row, state, effects=workspace_effects(ledger.prefix, state))
        for row in ledger.records[start:]
    )


@pytest.mark.parametrize(
    "value,role",
    [
        ("report.txt", RequestedItemRole.OUTPUT),
        ("src/__pycache__/notes.txt", RequestedItemRole.OUTPUT),
        ("venv/report.txt", RequestedItemRole.INPUT),
    ],
)
def test_an_ordinary_or_input_declaration_keeps_unchanged_commands_quiet(
    value: str, role: RequestedItemRole
) -> None:
    assert path_beyond_workspace_fingerprint(value) is (value == "venv/report.txt")
    ledger = ObservedLedger()
    _declare(ledger, value, role)
    start = len(ledger.records)
    ledger.passes("python generate.py", workspace_effect="unchanged")
    state = replay(ledger.prefix)
    assert workspace_effects(ledger.prefix, state).quiet
    assert closing_material_frontier(state, ledger.prefix) <= start
