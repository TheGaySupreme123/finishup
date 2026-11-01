"""Agent text markers keep their pre-rename ``yoetz`` spelling forever (ADR-048).

Decision statements recorded before the product was renamed carry ``yoetz-blocker:``,
``yoetz-assumption:``, ``yoetz-verification-limit:``, ``yoetz-no-material-work:`` and
``yoetz:test-change:`` lines. Every projection rebuild re-parses them, so a ledger written with the
legacy spelling must derive exactly what the same ledger derives with the ``finishup`` spelling.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import pytest

from builders.observed_runs import ObservedLedger
from finishup.domain.events import (
    DecisionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from finishup.domain.task_statement import (
    LEGACY_NO_MATERIAL_WORK_MARKER,
    NO_MATERIAL_WORK_MARKER,
    NO_MATERIAL_WORK_MARKERS,
)
from finishup.domain.values import EventId, ObligationId, actor_id, obligation_id
from finishup.kernel.closure_readiness import closure_readiness_facts, derive_closure_readiness
from finishup.kernel.delivered_set import path_assumption
from finishup.kernel.plan_drift import no_material_work_decided
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import (
    BLOCKER_MARKER,
    DISCLOSURE_MARKERS,
    LEGACY_BLOCKER_MARKER,
    LEGACY_DISCLOSURE_MARKERS,
    blocked_obligations,
    blocker_declarations,
    blocker_publication_notices,
    decision_batches,
    disclosure_declarations,
    disclosure_line_obligations,
    task_fact_signals,
)

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_OTHER = obligation_id("obl_00000000-0000-4000-8000-000000000002")
_UNKNOWN = obligation_id("obl_00000000-0000-4000-8000-0000000000ff")
_DECISION_SCHEMA = EventSchema("decision_recorded", "1.0.0")

# The two spellings of every marker, keyed by what each spelling is called here.
_NEW = {
    "blocker": BLOCKER_MARKER,
    "assumption": "finishup-assumption",
    "verification_limit": "finishup-verification-limit",
}
_LEGACY = {
    "blocker": LEGACY_BLOCKER_MARKER,
    "assumption": "yoetz-assumption",
    "verification_limit": "yoetz-verification-limit",
}

type _Spelling = Callable[[str], str]


def _new(kind: str) -> str:
    return _NEW[kind]


def _legacy(kind: str) -> str:
    return _LEGACY[kind]


def test_the_marker_constants_name_both_spellings() -> None:
    assert BLOCKER_MARKER == "finishup-blocker"
    assert LEGACY_BLOCKER_MARKER == "yoetz-blocker"
    assert dict(DISCLOSURE_MARKERS) == {
        "finishup-assumption": "assumption",
        "finishup-verification-limit": "verification_limit",
    }
    assert dict(LEGACY_DISCLOSURE_MARKERS) == {
        "yoetz-assumption": "assumption",
        "yoetz-verification-limit": "verification_limit",
    }
    assert NO_MATERIAL_WORK_MARKER == "finishup-no-material-work"
    assert LEGACY_NO_MATERIAL_WORK_MARKER == "yoetz-no-material-work"
    # The new spelling comes first: teaching text uses it.
    assert NO_MATERIAL_WORK_MARKERS == (NO_MATERIAL_WORK_MARKER, LEGACY_NO_MATERIAL_WORK_MARKER)


def _ledger() -> ObservedLedger:
    ledger = ObservedLedger()
    for obligation in (_OBLIGATION, _OTHER):
        ledger.append(
            EventSchema("obligation_published", "1.0.0"),
            ObligationPublishedPayload(
                obligation_id=obligation,
                description="Synthetic obligation",
                evidence_expectation="Observed run",
                status=ObligationStatus.OPEN,
                requested_items=(),
            ),
            observed=False,
        )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION, _OTHER)),
        observed=False,
    )
    return ledger


def _decide(
    ledger: ObservedLedger,
    statement: str,
    *obligations: ObligationId,
    batch: int,
    supersedes: EventId | None = None,
) -> EventId:
    return ledger.append(
        _DECISION_SCHEMA,
        DecisionRecordedPayload(
            statement=statement,
            rationale="The deployment credential is held by the operator.",
            authority=actor_id("agt_codex"),
            affected_obligation_ids=tuple(sorted(obligations)),
            supersedes_event_id=supersedes,
        ),
        observed=False,
        operation=f"req_04800000-0000-4000-8000-{batch:012d}",
    )


def _history(blocker: _Spelling, disclosure: _Spelling) -> ObservedLedger:
    """One task's decisions: a claimed then confirmed blocker, disclosures, a withdrawn one."""

    ledger = _ledger()
    _decide(ledger, f"Blocked.\n{blocker('blocker')}:credential", _OBLIGATION, batch=1)
    _decide(ledger, f"Still blocked.\n{blocker('blocker')}:credential", _OBLIGATION, batch=2)
    _decide(ledger, f"{blocker('blocker')}:consent", _OTHER, batch=2)
    _decide(
        ledger,
        "Chose the documented default.\n"
        f"{disclosure('assumption')}:{_OTHER}\n"
        f"  {disclosure('verification_limit')}:{_OTHER}  \n"
        f"{disclosure('assumption')}:{_UNKNOWN}",
        batch=3,
    )
    withdrawn = _decide(ledger, f"{disclosure('assumption')}:{_OBLIGATION}", batch=4)
    _decide(ledger, "The assumption no longer applies.", batch=5, supersedes=withdrawn)
    return ledger


def _derived(ledger: ObservedLedger) -> Mapping[str, Any]:
    """Everything the kernel derives from the decisions, with the statement text left out."""

    prefix = ledger.prefix
    projection: ProjectionState = replay(prefix)
    batches = decision_batches(prefix)
    facts = closure_readiness_facts(projection, prefix)
    readiness = derive_closure_readiness(
        ("obligations_open",), (), facts, semantic_review_required=False
    )
    return {
        "obligations": projection.obligations,
        "plans": projection.plans,
        "coverage_gaps": projection.coverage_gaps,
        "superseded": {
            key: row.superseded_by_event_id for key, row in projection.decisions.items()
        },
        "blockers": dict(blocker_declarations(projection, batches)),
        "blocked": dict(blocked_obligations(projection, batches)),
        "disclosures": disclosure_declarations(projection),
        "signals": task_fact_signals(projection, prefix),
        "facts": facts,
        "readiness": readiness,
    }


def test_a_ledger_with_legacy_markers_replays_to_identical_projections() -> None:
    new = _derived(_history(_new, _new))
    legacy = _derived(_history(_legacy, _legacy))

    assert legacy == new
    # Not vacuous: the markers took effect under either spelling.
    assert new["blocked"] == {_OBLIGATION: "credential"}
    assert {(row.obligation_id, row.kind) for row in new["disclosures"]} == {
        (_OTHER, "assumption"),
        (_OTHER, "verification_limit"),
    }
    assert any(gap.endswith(f":{_UNKNOWN}") for gap in new["coverage_gaps"])
    unmarked = _derived(_history(lambda _kind: "not-a-marker", lambda _kind: "not-a-marker"))
    assert unmarked["blocked"] == {} and unmarked["disclosures"] == ()


def test_a_ledger_mixing_both_spellings_replays_to_the_same_projections() -> None:
    """An install upgraded mid-task holds both spellings; they are one marker to every rule."""

    assert _derived(_history(_legacy, _new)) == _derived(_history(_new, _new))
    assert _derived(_history(_new, _legacy)) == _derived(_history(_new, _new))


@pytest.mark.parametrize(
    ("claim", "confirm"),
    ((_legacy, _new), (_new, _legacy), (_legacy, _legacy)),
)
def test_a_blocker_claimed_in_one_spelling_is_confirmed_in_the_other(
    claim: _Spelling, confirm: _Spelling
) -> None:
    ledger = _ledger()
    first = _decide(ledger, f"{claim('blocker')}:authority", _OBLIGATION, batch=1)
    second = _decide(ledger, f"{confirm('blocker')}:authority", _OBLIGATION, batch=2)
    prefix = ledger.prefix
    projection = replay(prefix)

    declaration = blocker_declarations(projection, decision_batches(prefix))[_OBLIGATION]
    assert (declaration.kind, declaration.decision_event_id) == ("authority", first)
    assert declaration.confirmation_event_id == second


def test_both_spellings_in_one_decision_never_confirm_themselves() -> None:
    ledger = _ledger()
    _decide(
        ledger,
        f"{LEGACY_BLOCKER_MARKER}:credential\n{BLOCKER_MARKER}:credential",
        _OBLIGATION,
        batch=1,
    )
    prefix = ledger.prefix
    declaration = blocker_declarations(replay(prefix), decision_batches(prefix))[_OBLIGATION]
    assert declaration.kind == "credential"
    assert not declaration.confirmed


def test_the_publish_time_notice_reads_a_legacy_blocker_line() -> None:
    ledger = _ledger()
    _decide(ledger, f"{LEGACY_BLOCKER_MARKER}:dependency_unavailable", _OBLIGATION, batch=1)
    payload = DecisionRecordedPayload(
        statement=f"{LEGACY_BLOCKER_MARKER}:dependency_unavailable",
        rationale="The upstream mirror is offline.",
        authority=actor_id("agt_codex"),
        affected_obligation_ids=(_OBLIGATION,),
    )
    projection = replay(ledger.prefix)
    event = next(iter(projection.decisions))

    [notice] = blocker_publication_notices(projection, ((event, payload),))
    assert (notice.obligation_id, notice.kind) == (_OBLIGATION, "dependency_unavailable")


@pytest.mark.parametrize(
    ("statement", "expected"),
    (
        (f"yoetz-assumption:{_OBLIGATION}", (("assumption", _OBLIGATION),)),
        (f"finishup-assumption:{_OBLIGATION}", (("assumption", _OBLIGATION),)),
        (
            f"yoetz-assumption:{_OBLIGATION}\nfinishup-assumption:{_OBLIGATION}",
            (("assumption", _OBLIGATION),),
        ),
        (
            f"  yoetz-verification-limit : {_OTHER}  ",
            (("verification_limit", _OTHER),),
        ),
        # Only the exact markers: no other casing, no other prefix, no prose around them.
        (f"Yoetz-assumption:{_OBLIGATION}", ()),
        (f"FINISHUP-assumption:{_OBLIGATION}", ()),
        (f"yoetz:assumption:{_OBLIGATION}", ()),
        (f"I assume yoetz-assumption:{_OBLIGATION}", ()),
    ),
)
def test_disclosure_lines_accept_exactly_both_spellings(
    statement: str, expected: tuple[tuple[str, ObligationId], ...]
) -> None:
    assert disclosure_line_obligations(statement) == expected


@pytest.mark.parametrize("marker", ("yoetz-assumption", "finishup-assumption"))
def test_a_path_assumption_is_accepted_under_either_spelling(marker: str) -> None:
    ledger = _ledger()
    decision = _decide(
        ledger, f"Kept the old report.\n{marker}:{_OBLIGATION}\nout/report.md", batch=1
    )
    projection = replay(ledger.prefix)

    assert path_assumption(projection, (_OBLIGATION,), ("out/report.md",)) == decision


@pytest.mark.parametrize(
    "statement",
    (
        "No material work.\nyoetz-no-material-work:{event}",
        "No material work.\nfinishup-no-material-work:{event}",
        "  yoetz-no-material-work:{event}  \nfinishup-no-material-work:{event}",
    ),
)
def test_a_no_material_work_decision_counts_under_either_spelling(statement: str) -> None:
    ledger = _ledger()
    event = ledger.records[0].event_id
    _decide(ledger, statement.format(event=event), batch=1)
    projection = replay(ledger.prefix)

    assert no_material_work_decided(projection, event, workspace_changed=False)
    assert not no_material_work_decided(projection, event, workspace_changed=None)


@pytest.mark.parametrize(
    "statement",
    (
        "Yoetz-no-material-work:{event}",
        "yoetz:no-material-work:{event}",
        "The request needs none (yoetz-no-material-work:{event}).",
    ),
)
def test_no_other_spelling_of_the_no_material_work_marker_counts(statement: str) -> None:
    ledger = _ledger()
    event = ledger.records[0].event_id
    _decide(ledger, statement.format(event=event), batch=1)

    assert not no_material_work_decided(replay(ledger.prefix), event, workspace_changed=False)
