"""Scope comparison never expands plans or mistakes unreadability for exclusion."""

from dataclasses import replace

import pytest

from builders.policy_cases import clm, make_case, obl, obligation_record, plan_record, record
from finishup.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from finishup.kernel.completion_scope import (
    CLAIM_OUTSIDE_PLAN,
    PLAN_NOT_CLAIMED,
    completion_scope_codes,
    completion_scope_differences,
)
from finishup.kernel.projections import ProjectionState


def state(refs: tuple[int, ...], *, kind: ClaimKind = ClaimKind.COMPLETION) -> ProjectionState:
    return make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Plan", (obl(1), obl(2))), 1)},
        obligations={
            obl(n): obligation_record(
                ObligationPublishedPayload(obl(n), "Work", "Evidence", ObligationStatus.OPEN), n + 1
            )
            for n in (1, 2, 3)
        },
        claims={
            clm(1): record(
                ClaimRecordedPayload(
                    clm(1),
                    kind,
                    "Claim",
                    supporting_refs=(),
                    obligation_refs=tuple(obl(n) for n in refs),
                ),
                5,
            )
        },
    ).projection


@pytest.mark.parametrize(
    ("refs", "codes"),
    [
        ((1, 2), ()),
        ((1, 2, 3), (CLAIM_OUTSIDE_PLAN,)),
        ((1,), (PLAN_NOT_CLAIMED,)),
        ((3,), (CLAIM_OUTSIDE_PLAN, PLAN_NOT_CLAIMED)),
        ((), (PLAN_NOT_CLAIMED,)),
    ],
)
def test_two_directions_are_distinct(refs: tuple[int, ...], codes: tuple[str, ...]) -> None:
    assert completion_scope_codes(state(refs)) == codes


def test_material_and_superseded_claims_are_excluded() -> None:
    assert completion_scope_codes(state((3,), kind=ClaimKind.MATERIAL)) == ()
    original = state((3,))
    assert (
        completion_scope_codes(
            replace(
                original,
                claims={clm(1): replace(original.claims[clm(1)], superseded_by_claim_id=clm(2))},
            )
        )
        == ()
    )


@pytest.mark.parametrize("unreadable", ("plan", "claim", "obligation", "missing", "unknown_plan"))
def test_unreadability_is_not_an_empty_scope(unreadable: str) -> None:
    original = state((1, 2, 3))
    if unreadable == "plan":
        original = replace(
            original, plans={1: replace(original.plans[1], payload=None, redacted=True)}
        )
    elif unreadable == "claim":
        original = replace(
            original, claims={clm(1): replace(original.claims[clm(1)], payload=None, redacted=True)}
        )
    elif unreadable == "obligation":
        original = replace(
            original,
            obligations={
                **original.obligations,
                obl(3): replace(original.obligations[obl(3)], payload=None, redacted=True),
            },
        )
    elif unreadable == "missing":
        original = replace(
            original,
            obligations={key: row for key, row in original.obligations.items() if key != obl(3)},
        )
    else:
        original = replace(
            original,
            unknown_event_count=1,
            coverage_gaps=(
                "unknown_event:evt_10000000-0000-4000-8000-000000000099:plan_revised@9.0.0",
            ),
        )
    assert completion_scope_differences(original) == ()


def test_partial_claims_do_not_silently_union_into_whole_plan_completion() -> None:
    original = state((1,))
    other = record(
        ClaimRecordedPayload(
            clm(2), ClaimKind.COMPLETION, "Other", supporting_refs=(), obligation_refs=(obl(2),)
        ),
        6,
    )
    combined = replace(original, claims={**original.claims, clm(2): other})
    assert tuple(row.not_claimed for row in completion_scope_differences(combined)) == (
        (obl(2),),
        (obl(1),),
    )


def _ack_case(refs: tuple[int, ...], acknowledged: frozenset[int]):  # noqa: ANN202
    def payload(n: int) -> ObligationPublishedPayload:
        if n in acknowledged:
            return ObligationPublishedPayload(
                obl(n),
                "Work",
                "Evidence",
                ObligationStatus.ACKNOWLEDGED_NOT_DONE,
                acknowledged_not_done_reason="The licence is unavailable; reported.",
            )
        return ObligationPublishedPayload(obl(n), "Work", "Evidence", ObligationStatus.OPEN)

    return make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Plan", (obl(1), obl(2))), 1)},
        obligations={obl(n): obligation_record(payload(n), n + 1) for n in (1, 2, 3)},
        claims={
            clm(1): record(
                ClaimRecordedPayload(
                    clm(1),
                    ClaimKind.COMPLETION,
                    "Claim",
                    supporting_refs=(),
                    obligation_refs=tuple(obl(n) for n in refs),
                ),
                5,
            )
        },
    )


def test_an_acknowledged_obligation_omitted_from_the_claim_is_not_plan_not_claimed() -> None:
    """tb4n2 cargo/payments/vpp S (issue #1022): the honest claim omits what it acknowledged."""

    two = frozenset({2})
    assert completion_scope_codes(_ack_case((1,), two).projection) == ()
    # Status is read from the current projection: reopened, it is plan scope again.
    assert completion_scope_codes(_ack_case((1,), frozenset()).projection) == (PLAN_NOT_CLAIMED,)
    # Only the acknowledged one is exempt; another omitted obligation still counts.
    projection = _ack_case((), two).projection
    assert completion_scope_codes(projection) == (PLAN_NOT_CLAIMED,)
    assert completion_scope_differences(projection)[0].not_claimed == (obl(1),)


def test_a_claim_naming_an_acknowledged_obligation_still_raises_the_open_obligation_finding() -> (
    None
):
    from finishup.domain.findings import FindingKind
    from finishup.kernel.deterministic_checks import DETERMINISTIC_FINDING_TEMPLATES
    from finishup.kernel.policies.work_integrity import (
        _completion_findings,  # pyright: ignore[reportPrivateUsage]
    )

    case = _ack_case((1, 2), frozenset({2}))
    assert completion_scope_codes(case.projection) == ()
    findings = _completion_findings(case)
    # obl 1 is open and obl 2 acknowledged: naming either in a completion claim is flagged.
    assert len(findings) == 2
    remediation = DETERMINISTIC_FINDING_TEMPLATES[
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    ].next_action
    assert "omit it from the completion claim" in remediation
