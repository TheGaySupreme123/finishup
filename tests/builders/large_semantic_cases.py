"""Builders for AI-powered review cases large enough to exercise envelope bounding.

The 2026-07-30 dogfood failure needed a case the repo could not construct: 24 frozen-history
events, 13 local assessments and 62 AI-powered review items, producing a ~44 KiB structural
envelope. Every prior envelope test used a three-record case whose envelope was under 4 KiB, so
the bounding ladder was never executed by a test at all. These builders close that gap.
"""

from __future__ import annotations

from collections.abc import Sequence

from builders.policy_cases import (
    clm,
    evd,
    evidence_record,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
)
from finishup.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from finishup.domain.values import ClaimId, EvidenceId, ObligationId, timestamp_from_string
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.kernel.projections import (
    ClaimProjectionRecord,
    EvidenceProjectionRecord,
    ObligationProjectionRecord,
)
from finishup.protocol.coverage import EvidenceImmutability

__all__ = ["large_case"]

# Prose long enough to be realistic without dominating the envelope: the envelope carries only
# metadata and digests per item, so item count — not item size — is what grows it.
# Deliberately contains the non-ASCII characters agents actually type — an em dash and a curly
# apostrophe. The case builder used to decode canonical UTF-8 as ASCII, so a single one of these
# anywhere in the ledger killed the whole AI-powered review with coordinator_failure.
_DETAIL = (
    "The reviewer needs enough surrounding context — including the author’s stated intent — to "
    "judge whether the claimed change is supported by recorded evidence rather than asserted."
)


def large_case(
    *,
    obligation_count: int = 10,
    claim_count: int = 8,
    evidence_count: int = 6,
) -> DeterministicCase:
    """A frozen case with enough distinct subjects to produce a multi-kilobyte envelope.

    The defaults yield 13 local assessments and a ~28 KiB structural envelope — the shape
    that failed in production against the old 16 KiB bound — while staying modest enough that the
    wider review profiles remain buildable. Counts are parameterised so a test can push past the
    selection limits deliberately.
    """

    sequence = 1
    plan = plan_record(
        PlanPublishedPayload(
            1,
            "Ship the AI-powered review pipeline end to end without silent truncation",
            tuple(obl(index) for index in range(1, obligation_count + 1)),
        ),
        sequence,
    )
    sequence += 1

    obligations: dict[ObligationId, ObligationProjectionRecord] = {}
    for index in range(1, obligation_count + 1):
        obligations[obl(index)] = obligation_record(
            ObligationPublishedPayload(
                obl(index),
                f"Obligation {index}: {_DETAIL}",
                f"Acceptance {index}: the local check suite and the AI-powered review both pass.",
                ObligationStatus.OPEN,
            ),
            sequence,
        )
        sequence += 1

    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    for index in range(1, evidence_count + 1):
        evidence[evd(index)] = evidence_record(
            EvidenceRecordedPayload(
                evd(index),
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-07-01T00:00:00.000Z"),
                description=f"test output {index}: {_DETAIL}",
            ),
            sequence,
        )
        sequence += 1

    claims: dict[ClaimId, ClaimProjectionRecord] = {}
    for index in range(1, claim_count + 1):
        # Half the claims cite evidence and half do not, so the local policies produce a
        # realistic mix of assessments rather than one repeated finding.
        supports: Sequence[EvidenceId] = (
            (evd(index),) if index % 2 == 0 and index <= evidence_count else ()
        )
        claims[clm(index)] = record(
            ClaimRecordedPayload(
                clm(index),
                ClaimKind.COMPLETION,
                f"Claim {index}: the work is complete. {_DETAIL}",
                tuple(supports),
                obligation_refs=(obl(min(index, obligation_count)),),
            ),
            sequence,
        )
        sequence += 1

    extra = (
        *(obl(index) for index in range(1, obligation_count + 1)),
        *(clm(index) for index in range(1, claim_count + 1)),
        *(evd(index) for index in range(1, evidence_count + 1)),
    )
    return make_case(
        plans={1: plan},
        obligations=obligations,
        claims=claims,
        evidence=evidence,
        extra_refs=extra,
    )
