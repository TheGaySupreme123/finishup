"""Declared output paths that order the check-time change (tb4n2 R7, P1-11, #1016)."""

from __future__ import annotations

from builders.observed_runs import ObservedLedger
from finishup.application.check_change import declared_output_paths
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
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")


def _items_projection(*items: RequestedItem) -> ProjectionState:
    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Deliver the outputs",
            evidence_expectation="The files",
            status=ObligationStatus.OPEN,
            requested_items=items,
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    return replay(ledger.prefix)


def test_declared_output_paths_order_outputs_first_and_skip_inputs() -> None:
    projection = _items_projection(
        RequestedItem(RequestedItemKind.FILE, "notes.md"),
        RequestedItem(RequestedItemKind.FILE, "/app/spec.json", role=RequestedItemRole.INPUT),
        RequestedItem(RequestedItemKind.FILE, "/output/plan.json", role=RequestedItemRole.OUTPUT),
        RequestedItem(RequestedItemKind.DIRECTORY, "src", role=RequestedItemRole.OUTPUT),
        RequestedItem(RequestedItemKind.FILE, "out/*.json", role=RequestedItemRole.OUTPUT),
        RequestedItem(RequestedItemKind.FILE, "notes.md"),
    )

    assert declared_output_paths(projection) == ("/output/plan.json", "src", "notes.md")


def test_a_requested_change_that_names_its_files_in_prose_declares_them_last() -> None:
    """Issue #1082 (sglang, react-lead-form): obligations named their deliverables only inside
    a requested ``change`` item's prose, so the change never rendered them first."""

    projection = _items_projection(
        RequestedItem(
            RequestedItemKind.CHANGE,
            "Parser fixes in python/sglang/parser.py and test/test_parser.py, see notes",
        ),
        RequestedItem(RequestedItemKind.FILE, "/output/plan.json", role=RequestedItemRole.OUTPUT),
        RequestedItem(RequestedItemKind.COMMAND, "pytest tests/test_parser.py"),
    )

    assert declared_output_paths(projection) == (
        "/output/plan.json",
        "python/sglang/parser.py",
        "test/test_parser.py",
    )
