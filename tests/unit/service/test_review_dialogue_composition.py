"""The composition keeps the review dialogue's disclosures across recovery (issue #905)."""

from __future__ import annotations

from finishup.application.semantic_case import SemanticPacketView
from finishup.domain.receipts import SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP
from finishup.ports.semantic import PriorFindingVerdict, SemanticJudgment
from finishup.service import ready_composition


def test_a_trimmed_packet_view_adds_the_prior_findings_gap() -> None:
    gaps = ready_composition._packet_view_gaps  # pyright: ignore[reportPrivateUsage]
    trimmed = SemanticPacketView(frozenset(), frozenset(), prior_findings_trimmed=True)
    whole = SemanticPacketView(frozenset(), frozenset(), prior_findings_trimmed=False)
    assert gaps(trimmed) == frozenset({SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP})
    assert gaps(whole) == frozenset()


def test_the_durable_judgment_keeps_the_dropped_ruling_count() -> None:
    """A recovered check must still disclose rulings the normalizer dropped."""

    encode = ready_composition._judgment_to_response_json  # pyright: ignore[reportPrivateUsage]
    decode = ready_composition._judgment_from_response_json  # pyright: ignore[reportPrivateUsage]
    judgment = SemanticJudgment(
        "insufficient_packet",
        (),
        (PriorFindingVerdict("fnd_10000000-0000-4000-8000-000000000001", "unassessable", ()),),
        prior_finding_verdicts_dropped=3,
    )
    stored = encode(judgment)
    assert stored["prior_finding_verdicts_dropped"] == 3
    assert decode(stored) == judgment
    plain = SemanticJudgment("no_material_discrepancy", ())
    assert "prior_finding_verdicts_dropped" not in encode(plain)
    assert decode(encode(plain)) == plain
