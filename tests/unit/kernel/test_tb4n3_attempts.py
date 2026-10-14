"""tb4n3 RC-5: what counts as an attempt of a requested item (issue #1028, ADR-045).

``requested_item_never_attempted`` compared the agent's published ``attempted_items`` with the
requested value byte for byte, and let one untargeted action mark every obligation "acted on":
retro S was told it never attempted ``make`` targets the hook had watched run (and a file it
spelled ``out/x.log`` for ``/app/out/x.log``), and lake S was told an output was absent while the
training that writes it was still running.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
)
from yoetz.domain.findings import FindingKind
from yoetz.domain.values import action_id, obligation_id
from yoetz.kernel.command_attempts import same_requested_path, value_in_attempted
from yoetz.kernel.deterministic_checks import CaseAvailabilityFacts, build_deterministic_case
from yoetz.kernel.policies.work_integrity import work_integrity_findings
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import register_command_identity_key

_OBL = obligation_id("obl_00000000-0000-4000-8000-0000000000a1")


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _ledger(*items: RequestedItem) -> ObservedLedger:
    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=_OBL,
            description="Build and check the design",
            evidence_expectation="The runs",
            status=ObligationStatus.OPEN,
            requested_items=items,
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBL,)),
        observed=False,
    )
    return ledger


def _publish(
    ledger: ObservedLedger,
    number: int,
    *,
    kind: ActionKind = ActionKind.COMMAND,
    refs: tuple[object, ...] = (),
    attempted: tuple[str, ...] = (),
) -> None:
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            action_id=action_id(f"act_00000000-0000-4000-8000-{number:012d}"),
            action_kind=kind,
            description="Work on the task",
            obligation_refs=refs,  # type: ignore[arg-type]
            attempted_items=attempted,
            command=None if kind is not ActionKind.COMMAND else "omitted:structural",
        ),
        observed=False,
    )


def _never_attempted(ledger: ObservedLedger) -> bool:
    records = ledger.prefix
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    return any(
        item.candidate.kind is FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED
        for item in work_integrity_findings(case, absent_outputs=frozenset())
    )


def test_an_observed_run_of_the_planned_command_is_an_attempt() -> None:
    """retro S: the make targets ran (the hook saw them); the agent published them differently."""

    ledger = _ledger(
        RequestedItem(RequestedItemKind.COMMAND, "make synth"),
        RequestedItem(RequestedItemKind.COMMAND, "make timing"),
    )
    _publish(ledger, 1, refs=(_OBL,), attempted=("run the flow",))
    ledger.claim()
    assert _never_attempted(ledger)
    ledger.passes("cd /app && make synth")
    assert _never_attempted(ledger)  # make timing was never run
    ledger.passes("timeout 600 make timing")
    assert not _never_attempted(ledger)


def test_a_failed_run_is_still_an_attempt() -> None:
    ledger = _ledger(RequestedItem(RequestedItemKind.COMMAND, "make synth"))
    _publish(ledger, 1, refs=(_OBL,))
    ledger.claim()
    ledger.fail("make synth")
    assert not _never_attempted(ledger)


def test_a_run_of_a_different_command_is_not_an_attempt() -> None:
    ledger = _ledger(RequestedItem(RequestedItemKind.COMMAND, "make synth"))
    _publish(ledger, 1, refs=(_OBL,))
    ledger.claim()
    ledger.passes("make clean")
    ledger.passes("ls")
    assert _never_attempted(ledger)


def test_an_output_named_in_another_spelling_is_attempted() -> None:
    item = RequestedItem(
        RequestedItemKind.FILE, "/app/out/build.log", role=RequestedItemRole.OUTPUT
    )
    ledger = _ledger(item)
    _publish(ledger, 1, kind=ActionKind.EDIT, refs=(_OBL,), attempted=("out/build.log",))
    ledger.claim()
    assert not _never_attempted(ledger)
    other = _ledger(item)
    _publish(other, 1, kind=ActionKind.EDIT, refs=(_OBL,), attempted=("out/other.log",))
    other.claim()
    assert _never_attempted(other)


def test_an_untargeted_action_no_longer_marks_every_obligation_acted_on() -> None:
    """lake S: one untargeted command while training ran made the absent output reportable."""

    item = RequestedItem(RequestedItemKind.FILE, "/app/out/model.pt", role=RequestedItemRole.OUTPUT)
    ledger = _ledger(item)
    _publish(ledger, 1)  # no obligation_refs, names nothing
    records = ledger.prefix
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    from yoetz.kernel.policies.work_integrity import reportable_absent_outputs

    absent = frozenset({(_OBL, 0)})
    assert reportable_absent_outputs(case, absent) == frozenset()
    # Naming the item makes the action work on that obligation.
    named = _ledger(item)
    _publish(named, 1, attempted=("/app/out/model.pt",))
    records = named.prefix
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    assert reportable_absent_outputs(case, absent) == absent


@pytest.mark.parametrize(
    ("requested", "other", "same"),
    [
        ("/app/out/x.log", "out/x.log", True),
        ("/app/out/x.log", "./out/x.log", True),
        ("/app/solve.sage", "solve.sage", True),
        ("solve.sage", "/app/solve.sage", True),
        ("/app/out/x.log", "/app/out/x.log", True),
        ("/app/out/x.log", "/srv/out/x.log", False),
        ("/app/out/x.log", "out/y.log", False),
        ("/app/out/x.log", "../x.log", False),
        ("/app/out/x.log", "", False),
    ],
)
def test_same_requested_path(requested: str, other: str, same: bool) -> None:
    assert same_requested_path(requested, other) is same
    assert value_in_attempted(requested, (other,)) is same
