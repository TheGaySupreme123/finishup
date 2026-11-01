"""The shared completion-claim limitation rule names exactly what the reducer demands (F3).

tb4n1: 34 of 35 ``claim_revision_mismatch`` rejections were ``limitation_refs_complete`` -- the
first completion claim omitted a live failed or partial result and only the retry, built from the
rejection's missing ids, succeeded. The pure helper lets a surface name those ids before the
claim; these vectors prove it agrees with the reducer's rejection on the same accepted prefix.
"""

from __future__ import annotations

import pytest

from builders.observed_runs import ObservedLedger
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayloadV1_1,
    ClaimRevisionMismatch,
    EventSchema,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.values import (
    ObligationId,
    ResultId,
    action_id,
    claim_id,
    obligation_id,
    result_id,
)
from finishup.kernel.claim_limitations import required_limitation_ids_for_projection
from finishup.kernel.claims import effective_claim_ids
from finishup.kernel.observed_failures import observed_event_ids_from_records
from finishup.kernel.reducers import replay

_ACTION = EventSchema("action_recorded", "1.0.0")
_RESULT = EventSchema("result_recorded", "1.0.0")
_CLAIM = EventSchema("claim_recorded", "1.1.0")
_OBL_A = obligation_id("obl_00000000-0000-4000-8000-00000000000a")
_OBL_B = obligation_id("obl_00000000-0000-4000-8000-00000000000b")


def _cooperative(
    ledger: ObservedLedger,
    number: int,
    outcome: ResultOutcome,
    obligations: tuple[ObligationId, ...] = (),
) -> ResultId:
    action = action_id(f"act_00000000-0000-4000-8000-{900 + number:012d}")
    ledger.append(
        _ACTION,
        ActionRecordedPayload(
            action,
            ActionKind.COMMAND,
            "Ran the acceptance suite",
            command="pytest -q tests/acceptance",
            obligation_refs=obligations,
        ),
        observed=False,
    )
    result = result_id(f"res_00000000-0000-4000-8000-{900 + number:012d}")
    ledger.append(
        _RESULT,
        ResultRecordedPayload(result, action, outcome, summary="suite outcome"),
        observed=False,
    )
    return result


def _claim(
    ledger: ObservedLedger,
    number: int,
    limitations: tuple[ResultId, ...],
    scope: tuple[ObligationId, ...] = (),
) -> None:
    ledger.append(
        _CLAIM,
        ClaimRecordedPayloadV1_1(
            claim_id=claim_id(f"clm_00000000-0000-4000-8000-{number:012d}"),
            claim_kind=ClaimKind.COMPLETION,
            statement="The change is complete.",
            supporting_refs=(),
            obligation_refs=scope,
            limitation_refs=limitations,
            supersedes_claim_refs=(),
        ),
        observed=False,
    )


def _required(ledger: ObservedLedger, scope: tuple[ObligationId, ...] = ()) -> tuple[str, ...]:
    return required_limitation_ids_for_projection(
        replay(ledger.prefix),
        observed_event_ids_from_records(ledger.prefix),
        claim_scope=frozenset(scope),
    )


def _rejected_missing(ledger: ObservedLedger, scope: tuple[ObligationId, ...] = ()) -> set[str]:
    probe = ObservedLedger(records=list(ledger.records), runs=ledger.runs)
    _claim(probe, 99, (), scope)
    with pytest.raises(ClaimRevisionMismatch) as caught:
        replay(probe.prefix)
    assert caught.value.invariant == "limitation_refs_complete"
    return set(caught.value.missing_refs)


def _mixed_ledger() -> tuple[ObservedLedger, dict[str, ResultId]]:
    ledger = ObservedLedger()
    ids = {
        # Superseded by an identical later pass (#909): not required.
        "superseded": ledger.fail("pytest -q tests/x.py"),
        "rerun_pass": ledger.passes("pytest -q tests/x.py"),
        # Live observed failure, untouched by an edit: required.
        "live": ledger.fail("cargo test -p pest_meta"),
        "edit": ledger.edit(),
        # Observed safe exploration that failed: not required.
        "exploration": ledger.run(
            "ls missing", ResultOutcome.FAILURE, exit_status=2, runner="exploration"
        ),
        # Cooperative typed outcomes; unknown is never required.
        "partial_a": _cooperative(ledger, 1, ResultOutcome.PARTIAL, (_OBL_A,)),
        "failure_b": _cooperative(ledger, 2, ResultOutcome.FAILURE, (_OBL_B,)),
        "unknown": _cooperative(ledger, 3, ResultOutcome.UNKNOWN),
    }
    return ledger, ids


def test_whole_task_required_set_matches_the_reducer_rejection() -> None:
    ledger, ids = _mixed_ledger()
    required = _required(ledger)
    assert set(required) == {ids["live"], ids["partial_a"], ids["failure_b"]}
    assert required == tuple(sorted(required, key=str.encode))
    assert set(required) == _rejected_missing(ledger)


def test_scoped_required_set_keeps_unscoped_and_claimed_obligation_results() -> None:
    ledger, ids = _mixed_ledger()
    # Observed actions name no obligation, so they stay relevant to every scoped claim.
    required = _required(ledger, (_OBL_A,))
    assert set(required) == {ids["live"], ids["partial_a"]}
    assert set(required) == _rejected_missing(ledger, (_OBL_A,))


def test_a_first_claim_built_from_the_surfaced_ids_is_accepted() -> None:
    ledger, _ = _mixed_ledger()
    required = _required(ledger)
    _claim(ledger, 1, tuple(result_id(value) for value in required))
    state = replay(ledger.prefix)
    assert effective_claim_ids(state) == frozenset(
        {claim_id("clm_00000000-0000-4000-8000-000000000001")}
    )


def test_nothing_is_required_once_every_failure_was_superseded() -> None:
    ledger = ObservedLedger()
    ledger.fail("pytest -q tests/x.py")
    ledger.passes("pytest -q tests/x.py")
    assert _required(ledger) == ()
