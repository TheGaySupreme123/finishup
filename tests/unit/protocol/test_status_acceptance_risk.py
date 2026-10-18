"""The status ``closure_readiness.acceptance_risk`` wire (ADR-033, owner decision D1).

Obligation ids and closed reason tokens only, in the kernel's canonical order; a named coverage
limit is always a standing limitation on the same readiness (one verdict, ADR-046). The reason
tokens and the fallback sentence are repeated in the hook-safe text module; these pin the copies.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from finishup.domain.receipts import UNRESOLVED_VERIFICATION_LIMITATION
from finishup.kernel.acceptance_risk import ACCEPTANCE_RISK_REASONS
from finishup.protocol import models, readiness_text
from finishup.protocol.models import StatusAcceptanceRiskModel, StatusClosureReadinessModel

_A = "obl_00000000-0000-4000-8000-0000000000a1"
_B = "obl_00000000-0000-4000-8000-0000000000b2"
_CODE = "unresolved_verification_limitation"


def _readiness(**fields: Any) -> dict[str, Any]:
    return {
        "declared_obligation_count": "2",
        "no_obligations_reason": None,
        "open_obligation_count": "0",
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "0",
        "blocking_conditions": [],
        "state": "ready_with_limitations",
        "gap_classification_version": "8",
        "agent_actionable": [],
        "standing_limitations": [_CODE],
        "acknowledged_not_done": [],
        "acknowledged_not_done_count": "0",
        **fields,
    }


def test_the_reason_tokens_and_fallback_sentence_are_one_set_everywhere() -> None:
    assert readiness_text.ACCEPTANCE_RISK_REASON_TOKENS == ACCEPTANCE_RISK_REASONS
    assert models._ACCEPTANCE_RISK_REASON_ORDER == ACCEPTANCE_RISK_REASONS  # pyright: ignore[reportPrivateUsage]
    assert readiness_text._ACCEPTANCE_RISK_FALLBACK == UNRESOLVED_VERIFICATION_LIMITATION  # pyright: ignore[reportPrivateUsage]


def test_a_row_takes_one_to_three_known_reasons_in_canonical_order() -> None:
    row = StatusAcceptanceRiskModel.model_validate(
        {"obligation_id": _A, "reasons": list(ACCEPTANCE_RISK_REASONS)}
    )
    assert row.reasons == ACCEPTANCE_RISK_REASONS
    for reasons in (
        [],
        ["it_passed"],
        ["evidence_self_asserted_only", "requested_item_never_attempted"],
        ["evidence_self_asserted_only", "evidence_self_asserted_only"],
        [*ACCEPTANCE_RISK_REASONS, "evidence_self_asserted_only"],
    ):
        with pytest.raises(ValidationError):
            StatusAcceptanceRiskModel.model_validate({"obligation_id": _A, "reasons": reasons})
    with pytest.raises(ValidationError):
        StatusAcceptanceRiskModel.model_validate(
            {"obligation_id": "res_00000000-0000-4000-8000-0000000000a1", "reasons": []}
        )
    with pytest.raises(ValidationError):
        StatusAcceptanceRiskModel.model_validate(
            {"obligation_id": _A, "reasons": ["evidence_self_asserted_only"], "summary": "met"}
        )


def test_the_readiness_list_is_sorted_unique_and_always_a_standing_limitation() -> None:
    row_a = {"obligation_id": _A, "reasons": ["evidence_self_asserted_only"]}
    row_b = {"obligation_id": _B, "reasons": ["requested_item_never_attempted"]}
    parsed = StatusClosureReadinessModel.model_validate(_readiness(acceptance_risk=[row_a, row_b]))
    assert parsed.acceptance_risk is not None
    assert [item.obligation_id for item in parsed.acceptance_risk] == [_A, _B]
    for rows in ([row_b, row_a], [row_a, row_a]):
        with pytest.raises(ValidationError):
            StatusClosureReadinessModel.model_validate(_readiness(acceptance_risk=rows))
    # A named coverage limit without the standing code would state two verdicts.
    with pytest.raises(ValidationError, match="closure_readiness_acceptance_risk_unbounded"):
        StatusClosureReadinessModel.model_validate(
            _readiness(acceptance_risk=[row_a], standing_limitations=[])
        )
