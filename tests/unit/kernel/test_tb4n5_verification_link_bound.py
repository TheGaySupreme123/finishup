"""Coverage reads every flagged obligation's verification link, not the first eight (#1079).

``closure_readiness.admissible_verification`` is a bounded status field: at most eight
obligations. The coverage judgement (``unresolved_verification_limitation``) and the receipt
pairing lines read the same links, and must not inherit that bound. These build nine flagged
resolved obligations, each citing its own observed run, and check that none is reported
unlinked while the status field stays at eight rows.
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
from finishup.domain.values import ObligationId, ResultId, obligation_id
from finishup.kernel.acceptance_risk import (
    EVIDENCE_NOT_LINKED,
    ITEM_NEVER_ATTEMPTED,
    acceptance_risk,
)
from finishup.kernel.claim_verification import (
    CLAIM_VERIFICATION_HEADER,
    claim_verification_lines,
    unresolved_verification_obligations,
)
from finishup.kernel.closure_readiness import closure_readiness_facts
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key
from finishup.kernel.verification_link import (
    MAX_ADMISSIBLE_OBLIGATIONS,
    admissible_verification_refs,
)

_OBLIGATION_V1_1 = EventSchema("obligation_published", "1.1.0")
_FLAGGED: tuple[ObligationId, ...] = tuple(
    obligation_id(f"obl_00000000-0000-4000-8000-00000000e00{index}") for index in range(1, 10)
)


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _obligation(
    identifier: ObligationId,
    item: RequestedItem,
    status: ObligationStatus = ObligationStatus.OPEN,
    resolution: tuple[ResultId, ...] = (),
) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=identifier,
        description="Deliver the requested outcome",
        evidence_expectation="A recorded run",
        status=status,
        requested_items=(item,),
        resolution_evidence_refs=resolution,
    )


def _ledger() -> tuple[ObservedLedger, dict[ObligationId, ResultId]]:
    """Nine resolutions, each flagged (its output is never written) and each citing its own
    observed run."""

    ledger = ObservedLedger()
    items = {
        identifier: RequestedItem(
            RequestedItemKind.FILE, f"out/missing-{index}.txt", RequestedItemRole.OUTPUT
        )
        for index, identifier in enumerate(_FLAGGED, start=1)
    }
    for identifier in _FLAGGED:
        ledger.append(_OBLIGATION_V1_1, _obligation(identifier, items[identifier]), observed=False)
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", _FLAGGED),
        observed=False,
    )
    runs = {
        identifier: ledger.passes(f"pytest -q tests/test_part_{index}.py")
        for index, identifier in enumerate(_FLAGGED, start=1)
    }
    for identifier in _FLAGGED:
        ledger.append(
            _OBLIGATION_V1_1,
            _obligation(
                identifier, items[identifier], ObligationStatus.RESOLVED, (runs[identifier],)
            ),
            observed=False,
        )
    return ledger, runs


def test_every_flagged_obligation_past_the_status_bound_keeps_its_observed_link() -> None:
    ledger, runs = _ledger()
    state = replay(ledger.prefix)
    flagged = acceptance_risk(state, ledger.prefix, _FLAGGED)
    assert tuple(obligation for obligation, _reasons in flagged) == _FLAGGED
    assert len(_FLAGGED) > MAX_ADMISSIBLE_OBLIGATIONS

    assert unresolved_verification_obligations(state, ledger.prefix) == ()
    lines = claim_verification_lines(state, ledger.prefix)
    assert lines[0] == CLAIM_VERIFICATION_HEADER
    for identifier in _FLAGGED:
        assert (
            f"{identifier} {ITEM_NEVER_ATTEMPTED},{EVIDENCE_NOT_LINKED} linked {runs[identifier]}"
            in lines
        )
    assert not any(line.endswith("no_verification_limit") for line in lines)

    bounded = admissible_verification_refs(state, ledger.prefix, _FLAGGED)
    assert len(bounded) == MAX_ADMISSIBLE_OBLIGATIONS
    every = dict(admissible_verification_refs(state, ledger.prefix, _FLAGGED, limit=None))
    assert every == {identifier: (str(runs[identifier]),) for identifier in _FLAGGED}

    facts = closure_readiness_facts(state, ledger.prefix)
    assert facts.acceptance_risk_obligation_ids == _FLAGGED
    assert facts.admissible_verification is not None
    assert len(facts.admissible_verification) <= MAX_ADMISSIBLE_OBLIGATIONS
