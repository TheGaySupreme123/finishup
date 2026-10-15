"""Requested-output facts for declared input/output roles and directories (issue #1002)."""

from __future__ import annotations

import pytest

from builders.observed_runs import ObservedLedger
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationResolutionMismatch,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
)
from finishup.domain.values import ObligationId, action_id, evidence_id, obligation_id
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import (
    REQUESTED_OUTPUT_GIT_IGNORED_GAP,
    REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,
    REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,
    REQUESTED_OUTPUT_UNCHANGED_GAP,
    REQUESTED_OUTPUT_UNVERIFIED_GAP,
    RequestedOutputState,
    declared_output_items,
    open_effective_obligations,
    requested_output_facts,
)

_A = obligation_id("obl_10020000-0000-4000-8000-00000000000a")
_B = obligation_id("obl_10020000-0000-4000-8000-00000000000b")
_V1_0 = EventSchema("obligation_published", "1.0.0")
_V1_1 = EventSchema("obligation_published", "1.1.0")


def _obligation(
    obligation: ObligationId,
    *items: RequestedItem,
    status: ObligationStatus = ObligationStatus.OPEN,
) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=obligation,
        description="Deliver the outputs",
        evidence_expectation="The files",
        status=status,
        requested_items=items,
        resolution_evidence_refs=(
            (evidence_id("evd_10020000-0000-4000-8000-000000000001"),)
            if status is ObligationStatus.RESOLVED
            else ()
        ),
    )


def _projection(
    obligations: tuple[ObligationPublishedPayload, ...],
    *,
    edited: tuple[str, ...] = (),
) -> ProjectionState:
    ledger = ObservedLedger()
    for payload in obligations:
        ledger.append(_version(payload), payload, observed=False)
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", tuple(sorted({o.obligation_id for o in obligations}))),
        observed=False,
    )
    if edited:
        ledger.append(
            EventSchema("action_recorded", "1.0.0"),
            ActionRecordedPayload(
                action_id("act_10020000-0000-4000-8000-000000000001"),
                ActionKind.EDIT,
                "Wrote outputs.",
                attempted_items=tuple(sorted(edited)),
            ),
            observed=False,
        )
    return replay(ledger.prefix)


def _version(payload: ObligationPublishedPayload) -> EventSchema:
    # The version is a pure function of the payload (#1002).
    return _V1_1 if payload.requires_obligation_v1_1 else _V1_0


_INPUT = RequestedItem(RequestedItemKind.FILE, "/app/layout_spec.json", RequestedItemRole.INPUT)


@pytest.mark.parametrize(
    "state",
    [
        RequestedOutputState("inside", exists=True, ignored=False, changed=False),
        RequestedOutputState("inside", exists=False, ignored=False, changed=False),
        RequestedOutputState("inside", exists=True, ignored=True, changed=False),
        RequestedOutputState(
            "inside", exists=True, ignored=True, changed=False, ignored_by_task=True
        ),
        RequestedOutputState("outside"),
        RequestedOutputState("unverified"),
    ],
    ids=("unchanged", "absent", "ignored", "git_ignored", "outside", "unverified"),
)
def test_an_input_item_never_yields_a_requested_output_fact(state: RequestedOutputState) -> None:
    """tb4n1 layout-config: the read-only /app/layout_spec.json was reported unchanged."""

    projection = _projection((_obligation(_A, _INPUT),), edited=(_INPUT.value,))
    assert requested_output_facts(projection, {(_A, 0): state}, blocked=()) == ((), ())


def test_an_output_item_counts_as_written_without_an_edit_action() -> None:
    output = RequestedItem(RequestedItemKind.FILE, "report.json", RequestedItemRole.OUTPUT)
    outside = RequestedItem(RequestedItemKind.FILE, "/elsewhere/out.json", RequestedItemRole.OUTPUT)
    undeclared = RequestedItem(RequestedItemKind.FILE, "kept.txt")
    projection = _projection((_obligation(_A, output, outside, undeclared),))
    unchanged = RequestedOutputState("inside", exists=True, ignored=False, changed=False)
    states = {
        (_A, 0): unchanged,
        (_A, 1): RequestedOutputState("outside"),
        # No role: still only reported once an edit action names it (tb4v1).
        (_A, 2): unchanged,
    }

    assert requested_output_facts(projection, states, blocked=()) == (
        (),
        (
            (REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP, _A),
            (REQUESTED_OUTPUT_UNCHANGED_GAP, _A),
        ),
    )
    # Without the declared role the same states raise nothing.
    plain = _projection(
        (
            _obligation(
                _A,
                RequestedItem(RequestedItemKind.FILE, "report.json"),
                RequestedItem(RequestedItemKind.FILE, "/elsewhere/out.json"),
                undeclared,
            ),
        )
    )
    assert requested_output_facts(plain, states, blocked=()) == ((), ())


def test_a_directory_item_reads_like_a_file_item() -> None:
    """retro-console-soc: /app/src, declared as the output directory."""

    src = RequestedItem(RequestedItemKind.DIRECTORY, "/app/src", RequestedItemRole.OUTPUT)
    projection = _projection((_obligation(_A, src),))
    changed = RequestedOutputState("inside", exists=True, ignored=False, changed=True)
    absent = RequestedOutputState("inside", exists=False, ignored=False, changed=False)
    ignored = RequestedOutputState("inside", exists=True, ignored=True, changed=True)
    assert requested_output_facts(projection, {(_A, 0): changed}, blocked=()) == ((), ())
    assert requested_output_facts(projection, {(_A, 0): absent}, blocked=()) == (((_A, 0),), ())
    assert requested_output_facts(projection, {(_A, 0): ignored}, blocked=()) == (
        (),
        ((REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP, _A),),
    )
    assert requested_output_facts(
        projection, {(_A, 0): RequestedOutputState("unverified")}, blocked=()
    ) == (
        (),
        ((REQUESTED_OUTPUT_UNVERIFIED_GAP, _A),),
    )
    git_ignored = RequestedOutputState(
        "inside", exists=True, ignored=True, changed=True, ignored_by_task=True
    )
    assert requested_output_facts(projection, {(_A, 0): git_ignored}, blocked=()) == (
        (),
        ((REQUESTED_OUTPUT_GIT_IGNORED_GAP, _A),),
    )


def test_declared_output_items_lists_role_output_files_and_directories_in_order() -> None:
    projection = _projection(
        (
            _obligation(
                _B,
                RequestedItem(RequestedItemKind.FILE, "b.json", RequestedItemRole.OUTPUT),
                _INPUT,
                RequestedItem(RequestedItemKind.FILE, "plain.txt"),
                RequestedItem(RequestedItemKind.COMMAND, "make test"),
                RequestedItem(RequestedItemKind.DIRECTORY, "dist", RequestedItemRole.OUTPUT),
            ),
            _obligation(
                _A,
                RequestedItem(RequestedItemKind.DIRECTORY, "/app/src", RequestedItemRole.OUTPUT),
            ),
        )
    )
    assert declared_output_items(projection) == (
        (_A, 0, RequestedItemKind.DIRECTORY, "/app/src"),
        (_B, 0, RequestedItemKind.FILE, "b.json"),
        (_B, 4, RequestedItemKind.DIRECTORY, "dist"),
    )
    assert declared_output_items(_projection((_obligation(_A, _INPUT),))) == ()


def test_resolution_must_repeat_roles_and_directory_items() -> None:
    src = RequestedItem(RequestedItemKind.DIRECTORY, "/app/src", RequestedItemRole.OUTPUT)
    ledger = ObservedLedger()
    ledger.append(_V1_1, _obligation(_A, src), observed=False)
    ledger.append(_V1_1, _obligation(_A, src, status=ObligationStatus.RESOLVED), observed=False)
    resolved = replay(ledger.prefix).obligations[_A].payload
    assert resolved is not None and resolved.requested_items == (src,)

    changed_role = ObservedLedger()
    changed_role.append(_V1_1, _obligation(_A, src), observed=False)
    changed_role.append(
        _V1_1,
        _obligation(
            _A,
            RequestedItem(RequestedItemKind.DIRECTORY, "/app/src", RequestedItemRole.INPUT),
            status=ObligationStatus.RESOLVED,
        ),
        observed=False,
    )
    with pytest.raises(ObligationResolutionMismatch):
        replay(changed_role.prefix)


def _acknowledged(obligation: ObligationId) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=obligation,
        description="Deliver the outputs",
        evidence_expectation="The files",
        status=ObligationStatus.ACKNOWLEDGED_NOT_DONE,
        acknowledged_not_done_reason="The upstream service this needs is not reachable.",
    )


def test_acknowledged_not_done_projects_and_last_effective_status_wins() -> None:
    """#1002/#996: open -> acknowledged_not_done -> open -> resolved; #1022: then reopened."""

    ledger = ObservedLedger()
    ledger.append(_V1_0, _obligation(_A), observed=False)
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_A,)),
        observed=False,
    )
    ledger.append(_V1_1, _acknowledged(_A), observed=False)
    acknowledged = replay(ledger.prefix)
    payload = acknowledged.obligations[_A].payload
    assert payload is not None and payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
    assert payload.acknowledged_not_done_reason is not None
    # Not resolved and not open (#997): counted once, as not done.
    assert open_effective_obligations(acknowledged) == ()

    ledger.append(_V1_0, _obligation(_A), observed=False)
    reopened = replay(ledger.prefix).obligations[_A].payload
    assert reopened is not None and reopened.status is ObligationStatus.OPEN

    ledger.append(_V1_1, _acknowledged(_A), observed=False)
    ledger.append(_V1_0, _obligation(_A, status=ObligationStatus.RESOLVED), observed=False)
    resolved_state = replay(ledger.prefix)
    resolved = resolved_state.obligations[_A].payload
    assert resolved is not None and resolved.status is ObligationStatus.RESOLVED
    assert open_effective_obligations(resolved_state) == ()

    # tb4n2 R2 (#1022): a resolution no longer holding is acknowledged as not done...
    ledger.append(_V1_1, _acknowledged(_A), observed=False)
    after = replay(ledger.prefix).obligations[_A].payload
    assert after is not None and after.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
    # ...but a resolution is never re-recorded in place.
    ledger.append(_V1_0, _obligation(_A, status=ObligationStatus.RESOLVED), observed=False)
    ledger.append(_V1_0, _obligation(_A, status=ObligationStatus.RESOLVED), observed=False)
    with pytest.raises(ObligationResolutionMismatch):
        replay(ledger.prefix)

    # Meaning fields must still repeat on acknowledgement.
    changed = ObservedLedger()
    changed.append(_V1_0, _obligation(_A), observed=False)
    changed.append(
        _V1_1,
        ObligationPublishedPayload(
            obligation_id=_A,
            description="Something else",
            evidence_expectation="The files",
            status=ObligationStatus.ACKNOWLEDGED_NOT_DONE,
            acknowledged_not_done_reason="why",
        ),
        observed=False,
    )
    with pytest.raises(ObligationResolutionMismatch):
        replay(changed.prefix)


def test_the_status_obligations_row_carries_the_acknowledgement_reason() -> None:
    from finishup.adapters.memory import ledger as memory_ledger

    ledger = ObservedLedger()
    ledger.append(_V1_0, _obligation(_A), observed=False)
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_A,)),
        observed=False,
    )
    ledger.append(_V1_1, _acknowledged(_A), observed=False)
    record = replay(ledger.prefix).obligations[_A]
    build = getattr(memory_ledger, "_obligation_item")
    row = build(str(_A), record, (), frozenset())
    assert row.status == "acknowledged_not_done"
    assert row.acknowledged_not_done_reason == "The upstream service this needs is not reachable."
