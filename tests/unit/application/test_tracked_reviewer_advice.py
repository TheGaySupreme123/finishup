"""Tracked reviewer advice (#1162): verified rows and the strongest remaining check get identities.

A verified row marked ``not_supported`` or ``not_assessable`` that cites an obligation or claim,
and the reviewer's single strongest remaining check, become advisory rows with a closed ``origin``.
A verified row about events alone stays a plain verified row. The judgment is scripted; the fence
and the case builder are production's.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.adapters.providers.openai_responses import (
    STRICT_JUDGMENT_JSON_SCHEMA,
    normalize_judgment,
)
from finishup.application.check import SemanticJudgmentReview, validate_semantic_judgment
from finishup.domain.correctness_advisories import validate_advisories
from finishup.domain.events import (
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from finishup.domain.findings import SamplingParams, SemanticDispatchKind, SemanticProvenance
from finishup.domain.values import JsonObject, obligation_id
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    DeterministicCase,
    build_deterministic_case,
)
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key
from finishup.ports.semantic import RemainingCheck, SemanticJudgment, VerifiedReviewItem
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import SemanticReason, SemanticStatus
from finishup.service.ready_composition import (
    _judgment_from_response_json,  # pyright: ignore[reportPrivateUsage]
    _judgment_to_response_json,  # pyright: ignore[reportPrivateUsage]
)

_DIGEST = "sha256:" + "a" * 64
_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_TEXT = "Decrypt the interleaved streams"


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _provenance() -> SemanticProvenance:
    return SemanticProvenance(
        provider="fake",
        endpoint_profile_id="fake",
        endpoint_profile_version="1.0.0",
        model="fake/model",
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        semantic_attempt_id="att_20000000-0000-4000-8000-000000001162",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_20000000-0000-4000-8000-000000001162",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-1162",
        egress_authorization_id="aut_20000000-0000-4000-8000-000000001162",
        request_commitment="hmac-sha256:" + "b" * 64,
    )


def _case() -> tuple[DeterministicCase, str]:
    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description=_TEXT,
            evidence_expectation="The sample decrypts",
            status=ObligationStatus.OPEN,
        ),
        observed=False,
    )
    plan_event = ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    prefix = ledger.prefix
    case = build_deterministic_case(replay(prefix), prefix, CaseAvailabilityFacts())
    return case, str(plan_event)


def _review(
    case: DeterministicCase, judgment: SemanticJudgment, *, phase: str = "final"
) -> SemanticJudgmentReview:
    return validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
        provider_input_text_by_ref={str(_OBLIGATION): (_TEXT,)},
        review_phase=phase,  # type: ignore[arg-type]
    )


def test_verified_rows_citing_an_obligation_and_the_strongest_check_are_tracked() -> None:
    case, _event = _case()
    judgment = SemanticJudgment(
        "no_material_discrepancy",
        (),
        review_summary="The decryption path was traced.",
        verified=(
            VerifiedReviewItem("Streams decrypt", "not_supported", (str(_OBLIGATION),), _TEXT),
            VerifiedReviewItem("Long seeds decrypt", "not_assessable", (str(_OBLIGATION),)),
            VerifiedReviewItem("The sample decrypts", "supported", (str(_OBLIGATION),), _TEXT),
        ),
        strongest_remaining_check=RemainingCheck(
            "Decrypt a 32-character seed and compare with the reference.", (str(_OBLIGATION),)
        ),
    )
    review = _review(case, judgment)
    rows = review.correctness_advisories
    assert [row["origin"] for row in rows] == [
        "strongest_remaining_check",
        "verified_not_supported",
        "verified_not_assessable",
    ]
    assert [row["summary"] for row in rows] == [
        "Decrypt a 32-character seed and compare with the reference.",
        "Streams decrypt",
        "Long seeds decrypt",
    ]
    assert all(row["subject_refs"] == (str(_OBLIGATION),) for row in rows)
    # Tracked rows are not routine notes: the challenge accounting is unchanged.
    assert review.advisory_notes == 0
    validate_advisories(rows)


def test_a_verified_row_about_events_alone_stays_plain() -> None:
    case, plan_event = _case()
    judgment = SemanticJudgment(
        "no_material_discrepancy",
        (),
        verified=(VerifiedReviewItem("The plan is complete", "not_assessable", (plan_event,)),),
    )
    review = validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
        review_phase="final",
    )
    assert review.verified == judgment.verified
    assert review.correctness_advisories == ()


def test_a_strongest_check_on_unsent_refs_is_removed_and_disclosed() -> None:
    case, plan_event = _case()
    judgment = SemanticJudgment(
        "no_material_discrepancy",
        (),
        strongest_remaining_check=RemainingCheck("Rerun the plan check.", (plan_event,)),
    )
    review = _review(case, judgment)
    assert review.correctness_advisories == ()
    assert review.refs_reduced == 1


def test_advisory_rows_admit_only_closed_origins() -> None:
    row = {"summary": "s", "detail": "s", "subject_refs": (str(_OBLIGATION),)}
    validate_advisories((JsonObject({**row, "origin": "verified_not_assessable"}),))
    validate_advisories((JsonObject(row),))
    with pytest.raises(ProtocolValueError):
        validate_advisories((JsonObject({**row, "origin": "invented"}),))


def test_the_provider_contract_carries_an_optional_strongest_check() -> None:
    definitions = STRICT_JUDGMENT_JSON_SCHEMA["$defs"]
    assert isinstance(definitions, dict)
    for branch in (
        "ProviderJudgmentNoDiscrepancy",
        "ProviderJudgmentChallenges",
        "ProviderJudgmentInsufficient",
    ):
        body = definitions[branch]
        assert isinstance(body, dict)
        assert "strongest_remaining_check" in body["required"]  # type: ignore[operator]
    reply: dict[str, Any] = {
        "judgment": {
            "conclusion": "no_material_discrepancy",
            "review_summary": "Checked the decryption path.",
            "verified": [],
            "reviewer_challenges": [],
            "prior_finding_verdicts": [],
            "strongest_remaining_check": {
                "check": "Decrypt a 32-character seed.",
                "cited_refs": [str(_OBLIGATION)],
            },
        }
    }
    judgment = normalize_judgment(reply, require_part2=True)
    assert judgment.strongest_remaining_check == RemainingCheck(
        "Decrypt a 32-character seed.", (str(_OBLIGATION),)
    )
    # A malformed optional check costs only itself, never the judgment.
    broken: dict[str, Any] = {
        "judgment": {**reply["judgment"], "strongest_remaining_check": {"check": ""}}
    }
    assert normalize_judgment(broken, require_part2=True).strongest_remaining_check is None
    absent: dict[str, Any] = {"judgment": {**reply["judgment"], "strongest_remaining_check": None}}
    assert normalize_judgment(absent, require_part2=True).strongest_remaining_check is None


def test_the_durable_response_keeps_the_strongest_check_and_old_bytes() -> None:
    plain = SemanticJudgment("no_material_discrepancy", ())
    assert "strongest_remaining_check" not in _judgment_to_response_json(plain)
    tracked = SemanticJudgment(
        "no_material_discrepancy",
        (),
        strongest_remaining_check=RemainingCheck("Decrypt a seed.", (str(_OBLIGATION),)),
    )
    encoded = _judgment_to_response_json(tracked)
    assert _judgment_from_response_json(encoded) == tracked
