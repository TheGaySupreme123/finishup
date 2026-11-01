"""Prove the scripted fake provider drives the application through the full AI-powered review matrix.

These tests exercise the real, production AI-powered review post-validation fence
(:func:`finishup.application.check.validate_semantic_judgment`) against results produced by
:class:`finishup.adapters.providers.fake.ScriptedFakeSemanticEvaluator`, without any network access.
The fake is never asked to interpret case content; it only proves that whatever it returns is
carried through the same fences a live adapter's output would face.
"""

from __future__ import annotations

import inspect
import socket
from dataclasses import fields, replace
from datetime import UTC, datetime
from typing import Literal, cast

import pytest

from builders.policy_cases import BASE_COVERAGE, clm, make_case
from finishup.adapters.providers.fake import (
    FakeSemanticScript,
    ScriptedFakeSemanticEvaluator,
    scripted_invalid,
    scripted_late,
    scripted_refusal,
    scripted_success,
    scripted_timeout,
)
from finishup.application.check import (
    SEMANTIC_REJECTED_HIDDEN_SOURCE_CLAIM,
    SEMANTIC_REJECTED_REF_OUTSIDE_CASE,
    SemanticJudgmentRejected,
    validate_semantic_judgment,
)
from finishup.domain.findings import (
    FindingKind,
    SemanticDispatchKind,
    SemanticProvenance,
)
from finishup.domain.privacy import ApprovedOutboundCase, DataCategory, ProviderBinding
from finishup.ports.semantic import (
    Deadline,
    ProviderAttemptProvenance,
    ReviewerChallenge,
    SemanticJudgment,
    SemanticResultInvalid,
    SemanticResultLate,
    SemanticResultRefused,
    SemanticResultSuccess,
    SemanticResultTimeout,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import SemanticReason, SemanticStatus

_CASE_ID = "cas_30000000-0000-4000-8000-000000000001"
_REQUEST_ID = "req_30000000-0000-4000-8000-000000000001"
_AUTH_ID = "aut_30000000-0000-4000-8000-000000000001"


def _binding() -> ProviderBinding:
    return ProviderBinding(
        provider_id="openai",
        model_id="gpt-5-fake",
        endpoint_profile_id="openai-responses",
        endpoint_profile_version="1.0.0",
        transport="external",
    )


def _approved_case(
    *,
    categories: tuple[DataCategory, ...] = (DataCategory.TASK_DESCRIPTION,),
    included_item_ids: tuple[str, ...] = ("goal-1",),
) -> ApprovedOutboundCase:
    payload = canonical_encode(
        cast(JsonValue, {"goal": "Ship the fix", "obligations": [], "claims": []})
    )
    return ApprovedOutboundCase(
        case_id=_CASE_ID,
        request_id=_REQUEST_ID,
        payload=payload,
        media_type="application/json",
        schema_id="yoetz-semantic-case-1.0.0",
        included_item_ids=included_item_ids,
        approved_categories=categories,
        blocked_categories=(),
        byte_count=len(payload),
        token_count=32,
        provider_binding=_binding(),
        purpose="semantic-review",
        authorization_id=_AUTH_ID,
        policy_digest="sha256:" + "1" * 64,
        case_digest="sha256:" + "2" * 64,
    )


def _deadline() -> Deadline:
    return Deadline(datetime(2030, 1, 1, tzinfo=UTC), 10_000.0)


type _NextStep = Literal[
    "act",
    "provide_evidence",
    "revise_claim",
    "dispute_with_evidence",
    "state_unresolved_limitation",
]


def _challenge(*refs: str, next_step: _NextStep = "provide_evidence") -> ReviewerChallenge:
    return ReviewerChallenge(
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        "Evidence gap",
        tuple(sorted(refs)),
        "The claim lacks a recorded basis.",
        "The claim may remain unresolved.",
        "Main agent: address the discrepancy.",
        next_step,
        "The missing material may exist outside the case.",
    )


def _finalize(provenance: ProviderAttemptProvenance, *, seed: str) -> SemanticProvenance:
    """Simulate what a real coordinator does once the terminal privacy receipt is durable."""

    return SemanticProvenance(
        provider=provenance.provider,
        endpoint_profile_id=provenance.endpoint_profile_id,
        endpoint_profile_version=provenance.endpoint_profile_version,
        model=provenance.model,
        sdk_version=provenance.sdk_version,
        prompt_digest=provenance.prompt_digest,
        schema_digest=provenance.schema_digest,
        policy_digest=provenance.policy_digest,
        privacy_policy_digest=provenance.privacy_policy_digest,
        sampling_params=provenance.sampling_params,
        latency_ms=provenance.latency_ms,
        semantic_attempt_id=f"att_30000000-0000-4000-8000-{seed:0>12}",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id=f"egr_30000000-0000-4000-8000-{seed:0>12}",
        status=provenance.status,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id=provenance.provider_request_id,
        egress_authorization_id=f"aut_30000000-0000-4000-8000-{seed:0>12}",
        request_commitment="hmac-sha256:" + "b" * 64,
    )


@pytest.mark.anyio
async def test_fake_success_refusal_timeout_invalid_and_late() -> None:
    case = _approved_case()
    deadline = _deadline()
    judgment = SemanticJudgment("no_material_discrepancy", ())
    script = FakeSemanticScript(
        (
            scripted_success(judgment),
            scripted_refusal(),
            scripted_timeout(),
            scripted_invalid(raw_size=12),
            scripted_late(),
        )
    )
    evaluator = ScriptedFakeSemanticEvaluator(script)

    success = await evaluator.evaluate(case, deadline)
    refusal = await evaluator.evaluate(case, deadline)
    timeout = await evaluator.evaluate(case, deadline)
    invalid = await evaluator.evaluate(case, deadline)
    late = await evaluator.evaluate(case, deadline)

    assert isinstance(success, SemanticResultSuccess)
    assert success.judgment.conclusion == "no_material_discrepancy"
    assert success.provenance.status is SemanticStatus.SUCCEEDED
    assert isinstance(refusal, SemanticResultRefused)
    assert refusal.provenance.status is SemanticStatus.REFUSED
    assert isinstance(timeout, SemanticResultTimeout)
    assert timeout.provenance.status is SemanticStatus.TIMEOUT
    assert isinstance(invalid, SemanticResultInvalid)
    assert invalid.raw_size == 12
    assert invalid.provenance.status is SemanticStatus.INVALID
    assert isinstance(late, SemanticResultLate)
    assert late.provenance.status is SemanticStatus.LATE

    # A late result is never folded into success, and every scripted outcome above is
    # distinguishable purely by its closed result type -- no two collapse to the same shape.
    assert {type(success), type(refusal), type(timeout), type(invalid), type(late)} == {
        SemanticResultSuccess,
        SemanticResultRefused,
        SemanticResultTimeout,
        SemanticResultInvalid,
        SemanticResultLate,
    }

    # Every scripted outcome reports the approved case's policy digest, not the script's
    # placeholder, and finalization carries that real value through to the recorded provenance.
    for result in (success, refusal, timeout, invalid, late):
        assert result.provenance.policy_digest == case.policy_digest
        assert result.provenance.privacy_policy_digest == case.policy_digest
    finalized = _finalize(success.provenance, seed="9")
    assert finalized.policy_digest == case.policy_digest
    assert finalized.privacy_policy_digest == case.policy_digest
    assert finalized.policy_digest != "sha256:" + "0" * 64

    with pytest.raises(RuntimeError, match="fake_semantic_script_exhausted"):
        await evaluator.evaluate(case, deadline)


@pytest.mark.anyio
async def test_fake_invented_ids_and_coverage_upgrades_are_rejected() -> None:
    case = _approved_case()
    deadline = _deadline()
    det_case = make_case(extra_refs=(clm(1),))
    invented = "clm_20000000-0000-4000-8000-000000000099"

    invented_evaluator = ScriptedFakeSemanticEvaluator(
        FakeSemanticScript(
            (scripted_success(SemanticJudgment("challenges_returned", (_challenge(invented),))),)
        )
    )
    invented_result = await invented_evaluator.evaluate(case, deadline)
    assert isinstance(invented_result, SemanticResultSuccess)
    # An invented ref still yields no finding; it now costs only its own challenge, and the drop
    # is counted rather than taking the judgment (and the check) down with it.
    invented_review = validate_semantic_judgment(
        det_case,
        (),
        invented_result.judgment,
        _finalize(invented_result.provenance, seed="1"),
        expected_frontier=det_case.frontier,
    )
    assert invented_review.candidates == ()
    assert invented_review.rejected_by_reason == ((SEMANTIC_REJECTED_REF_OUTSIDE_CASE, 1),)

    stale_evaluator = ScriptedFakeSemanticEvaluator(
        FakeSemanticScript(
            (scripted_success(SemanticJudgment("challenges_returned", (_challenge(str(clm(1))),))),)
        )
    )
    stale_result = await stale_evaluator.evaluate(case, deadline)
    assert isinstance(stale_result, SemanticResultSuccess)
    with pytest.raises(SemanticJudgmentRejected, match="semantic_judgment_invalid"):
        validate_semantic_judgment(
            det_case,
            (),
            stale_result.judgment,
            _finalize(stale_result.provenance, seed="2"),
            expected_frontier=type(det_case.frontier)(99, "sha256:" + "c" * 64),
        )

    accepted_evaluator = ScriptedFakeSemanticEvaluator(
        FakeSemanticScript(
            (scripted_success(SemanticJudgment("challenges_returned", (_challenge(str(clm(1))),))),)
        )
    )
    accepted_result = await accepted_evaluator.evaluate(case, deadline)
    assert isinstance(accepted_result, SemanticResultSuccess)
    accepted = validate_semantic_judgment(
        det_case,
        (),
        accepted_result.judgment,
        _finalize(accepted_result.provenance, seed="3"),
        expected_frontier=det_case.frontier,
    )
    assert len(accepted.candidates) == 1
    assert accepted.candidates[0].subject_refs == (clm(1),)
    assert accepted.rejected_by_reason == ()


@pytest.mark.anyio
async def test_fake_coordinator_does_not_require_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _forbidden_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("scripted fake evaluation must never open a socket")

    monkeypatch.setattr(socket, "socket", _forbidden_socket)
    monkeypatch.setattr(socket, "create_connection", _forbidden_socket)

    case = _approved_case()
    deadline = _deadline()
    script = FakeSemanticScript(
        (
            scripted_success(SemanticJudgment("no_material_discrepancy", ())),
            scripted_refusal(),
            scripted_timeout(),
            scripted_invalid(raw_size=4),
            scripted_late(),
        )
    )
    evaluator = ScriptedFakeSemanticEvaluator(script)

    for _ in range(5):
        result = await evaluator.evaluate(case, deadline)
        assert result is not None


@pytest.mark.anyio
async def test_fake_structured_packet_and_challenge_matrix() -> None:
    det_case = make_case(extra_refs=(clm(1),))
    next_steps: tuple[_NextStep, ...] = (
        "act",
        "provide_evidence",
        "revise_claim",
        "dispute_with_evidence",
        "state_unresolved_limitation",
    )

    for index, next_step in enumerate(next_steps):
        # Distinct "profiles" are opaque bytes to the fake; only the shape of included items
        # changes here, proving the fake never inspects the packet to decide its scripted answer.
        profile_case = _approved_case(
            categories=(DataCategory.TASK_DESCRIPTION, DataCategory.CLAIM_TEXT),
            included_item_ids=(f"goal-{index}",),
        )
        evaluator = ScriptedFakeSemanticEvaluator(
            FakeSemanticScript(
                (
                    scripted_success(
                        SemanticJudgment(
                            "challenges_returned",
                            (_challenge(str(clm(1)), next_step=next_step),),
                        )
                    ),
                )
            )
        )
        result = await evaluator.evaluate(profile_case, _deadline())
        assert isinstance(result, SemanticResultSuccess)
        assert result.judgment.challenges[0].requested_next_step == next_step

        review = validate_semantic_judgment(
            det_case,
            (),
            result.judgment,
            _finalize(result.provenance, seed=str(10 + index)),
            expected_frontier=det_case.frontier,
        )
        assert len(review.candidates) == 1

    # The false "missing diff means no change" case: a challenge that claims things are
    # unchanged while its cited ref's recorded coverage says the source was withheld/missing
    # must be rejected, never accepted as a legitimate "no material discrepancy" signal.
    hidden_case = make_case(
        extra_refs=(clm(1),),
        coverage_overrides={clm(1): replace(BASE_COVERAGE, known_gaps=("missing_ref",))},
    )
    hidden_challenge = ReviewerChallenge(
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        "Claims no change",
        (str(clm(1)),),
        "The file is unchanged.",
        "Nothing was modified.",
        "Main agent: no further action required.",
        "state_unresolved_limitation",
        "The excerpt was never disclosed.",
    )
    hidden_evaluator = ScriptedFakeSemanticEvaluator(
        FakeSemanticScript(
            (scripted_success(SemanticJudgment("challenges_returned", (hidden_challenge,))),)
        )
    )
    hidden_result = await hidden_evaluator.evaluate(_approved_case(), _deadline())
    assert isinstance(hidden_result, SemanticResultSuccess)
    hidden_review = validate_semantic_judgment(
        hidden_case,
        (),
        hidden_result.judgment,
        _finalize(hidden_result.provenance, seed="99"),
        expected_frontier=hidden_case.frontier,
    )
    assert hidden_review.candidates == ()
    assert hidden_review.rejected_by_reason == ((SEMANTIC_REJECTED_HIDDEN_SOURCE_CLAIM, 1),)


@pytest.mark.anyio
async def test_fake_has_no_source_fetch_authority() -> None:
    evaluator = ScriptedFakeSemanticEvaluator(
        FakeSemanticScript((scripted_success(SemanticJudgment("no_material_discrepancy", ())),))
    )

    # The port surface is exactly (case, deadline): no repository/filesystem/object handle.
    signature = inspect.signature(evaluator.evaluate)
    assert list(signature.parameters) == ["case", "deadline"]

    # The approved case itself carries only opaque authorized bytes and identifiers, never a
    # live handle the fake (or a real adapter) could use to fetch a second round of content.
    handle_like_names = {"repository", "workspace", "fs", "filesystem", "object_store", "git"}
    assert not handle_like_names & {field.name for field in fields(ApprovedOutboundCase)}

    case = _approved_case()
    deadline = _deadline()
    first = await evaluator.evaluate(case, deadline)
    assert isinstance(first, SemanticResultSuccess)

    # Calling again for "more" without a fresh scripted step fails loudly rather than quietly
    # granting a second look at anything.
    with pytest.raises(RuntimeError, match="fake_semantic_script_exhausted"):
        await evaluator.evaluate(case, deadline)
