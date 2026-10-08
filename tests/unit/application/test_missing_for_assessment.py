"""Classification and delivery of what an ``insufficient_packet`` review named (issue #907)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from builders.policy_cases import (
    act,
    claim_record,
    clm,
    evd,
    evidence_record,
    evt,
    make_case,
    obl,
    obligation_record,
    record,
    res,
)
from builders.privacy_policies import local_only_policy, minimal_external_policy
from yoetz.application.missing_for_assessment import (
    check_change_binary_paths,
    review_missing_for_assessment,
    supplied_since,
    unsuppliable_missing_kinds,
    unsupported_data_type,
)
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    ClientKind,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceKind,
    EvidenceRecordedPayload,
    IntegrationKind,
    MissingForAssessmentItem,
    ObligationPublishedPayload,
    ObligationStatus,
    ResultOutcome,
    ResultRecordedPayload,
    RuntimeProfile,
    SessionOpenedPayload,
)
from yoetz.domain.privacy import (
    EgressChannel,
    PrivacyPolicy,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.domain.values import (
    ActionId,
    ClaimId,
    EvidenceId,
    ObligationId,
    ResultId,
    event_id,
    object_id,
    timestamp_from_string,
)
from yoetz.kernel.deterministic_checks import DeterministicCase, FindingBasisRef
from yoetz.kernel.projections import (
    ClaimProjectionRecord,
    EvidenceProjectionRecord,
    ObligationProjectionRecord,
    PendingMissingForAssessment,
    ProjectionRecord,
)
from yoetz.mcp.summaries import summary_for_check
from yoetz.ports.change_capture import CheckChangeCapture
from yoetz.ports.runtime import TaskRuntime
from yoetz.ports.semantic import (
    MissingForAssessment,
    MissingForAssessmentKind,
    PriorFindingVerdict,
    SemanticJudgment,
)
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.coverage import EvidenceImmutability
from yoetz.service import ready_composition

_CLAIM = "clm_10000000-0000-4000-8000-000000000001"


def test_expanded_selection_leaves_every_kind_suppliable() -> None:
    selection = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    assert unsuppliable_missing_kinds(selection, ()) == ()


def test_structural_and_withheld_selections_name_what_no_agent_action_can_carry() -> None:
    structural = ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL)
    assert unsuppliable_missing_kinds(structural, ()) == (
        "command_identity",
        "current_diff_for_path",
        "other",
        "plan_or_claim_text",
        "task_statement",
        "verification_output",
    )
    assisted = ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED)
    # Assisted never carries exact command text.
    assert unsuppliable_missing_kinds(assisted, ()) == ("command_identity",)
    expanded = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    assert "verification_output" in unsuppliable_missing_kinds(expanded, ("evidence_excerpt",))
    narrow = replace(expanded, excerpt_kinds=("command", "failure", "test"))
    assert unsuppliable_missing_kinds(narrow, ()) == ("current_diff_for_path",)


def test_check_summary_names_missing_items_with_closed_tokens_only() -> None:
    envelope: dict[str, JsonValue] = {
        "verdict": "insufficient_coverage",
        "findings": [],
        "suppressed_count": "0",
        "semantic_status": "succeeded",
        "semantic_reason": "semantic_completed",
        "missing_for_assessment": [
            {
                "availability": "agent_suppliable",
                "kind": "verification_output",
                "target_refs": [_CLAIM],
            },
            {
                "availability": "structurally_unavailable_on_this_host",
                "kind": "command_identity",
                "target_refs": [],
            },
            {"availability": "agent_suppliable", "kind": "</script>", "target_refs": []},
        ],
    }
    text = summary_for_check(envelope)
    assert "missing for assessment: 2 (agent-suppliable: 1)" in text
    assert "verification_output=agent_suppliable" in text
    assert "command_identity=structurally_unavailable_on_this_host" in text
    assert "</script>" not in text
    assert len(text.encode("ascii")) <= 512


def test_durable_semantic_response_keeps_named_items_and_reads_legacy_bytes() -> None:
    judgment = SemanticJudgment(
        "insufficient_packet",
        (),
        missing_for_assessment=(
            MissingForAssessment("verification_output", (_CLAIM,), "The jest summary is absent."),
        ),
    )
    encoded = ready_composition._judgment_to_response_json(judgment)  # pyright: ignore[reportPrivateUsage]
    assert ready_composition._judgment_from_response_json(encoded) == judgment  # pyright: ignore[reportPrivateUsage]
    # Issue #905 rulings travel in the same durable response beside the named items.
    ruled = replace(
        judgment,
        prior_finding_verdicts=(
            PriorFindingVerdict("fnd_30000000-0000-4000-8000-000000000001", "unassessable", ()),
        ),
    )
    encoded_ruled = ready_composition._judgment_to_response_json(ruled)  # pyright: ignore[reportPrivateUsage]
    assert ready_composition._judgment_from_response_json(encoded_ruled) == ruled  # pyright: ignore[reportPrivateUsage]
    legacy: dict[str, JsonValue] = {"conclusion": "insufficient_packet", "reviewer_challenges": []}
    decoded = ready_composition._judgment_from_response_json(legacy)  # pyright: ignore[reportPrivateUsage]
    assert decoded == SemanticJudgment("insufficient_packet", ())


def test_only_agent_published_actions_and_results_answer_a_request() -> None:
    """Hook capture records every tool call; it never turns a still-missing item into supplied."""

    hook_action = ActionRecordedPayload(
        act(60),
        ActionKind.COMMAND,
        "Observed command via Claude Code",
        command="omitted:structural",
    )
    agent_action = ActionRecordedPayload(
        act(62), ActionKind.COMMAND, "Ran the unit tests", command="uv run pytest -q"
    )
    case = make_case(
        actions={act(60): record(hook_action, 60), act(62): record(agent_action, 62)},
        results={
            res(61): record(
                ResultRecordedPayload(res(61), act(60), ResultOutcome.SUCCESS, summary="1 passed"),
                61,
            ),
            res(63): record(
                ResultRecordedPayload(res(63), act(62), ResultOutcome.SUCCESS, summary="1 passed"),
                63,
            ),
        },
        extra_refs=(act(60), res(61), act(62), res(63)),
    )
    pending = PendingMissingForAssessment(
        evt(50),
        50,
        (
            MissingForAssessmentItem("command_identity", (), "agent_suppliable"),
            MissingForAssessmentItem("verification_output", (), "agent_suppliable"),
        ),
    )
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    # Authorship is the service-stamped envelope fact the frozen case carries, never payload text.
    observed = frozenset(
        {
            str(case.projection.actions[act(60)].source_event_id),
            str(case.projection.results[res(61)].source_event_id),
        }
    )
    assert supplied_since(case.projection, pending, allowed, observed) == (
        tuple(sorted((str(act(62)), str(res(63))), key=str.encode)),
        (str(res(63)),),
    )
    # Without the stamp, an action worded like a hook row is the agent's own answer.
    assert supplied_since(case.projection, pending, allowed) == (
        tuple(sorted((str(act(60)), str(act(62)), str(res(61)), str(res(63))), key=str.encode)),
        tuple(sorted((str(res(61)), str(res(63))), key=str.encode)),
    )


def test_packet_planning_ceiling_is_the_narrower_owner_channel_limit() -> None:
    """Issue #907: plan against max_bytes or max_tokens at four bytes per token, whichever binds."""

    policy = minimal_external_policy()
    llm = next(
        item for item in policy.channel_policies if item.channel is EgressChannel.LLM_INFERENCE
    )

    def with_limits(max_bytes: int, max_tokens: int) -> PrivacyPolicy:
        channel = replace(llm, max_bytes=max_bytes, max_tokens=max_tokens)
        return replace(
            policy,
            channel_policies=tuple(
                channel if item.channel is EgressChannel.LLM_INFERENCE else item
                for item in policy.channel_policies
            ),
        )

    ceiling = ready_composition._semantic_prepared_byte_ceiling  # pyright: ignore[reportPrivateUsage]
    assert ceiling(with_limits(100_000, 10_000)) == 40_000
    assert ceiling(with_limits(30_000, 10_000)) == 30_000
    assert ceiling(with_limits(0, 5_000)) == 20_000
    assert ceiling(with_limits(0, 0)) is None
    assert ceiling(local_only_policy()) is None


def _requested_case(
    results: Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]],
) -> DeterministicCase:
    action = ActionRecordedPayload(
        act(62), ActionKind.COMMAND, "Ran the unit tests", command="uv run pytest -q"
    )
    case = make_case(
        actions={act(62): record(action, 62)},
        results=results,
        extra_refs=(act(62), *results),
    )
    pending = PendingMissingForAssessment(
        evt(50), 50, (MissingForAssessmentItem("verification_output", (), "agent_suppliable"),)
    )
    return replace(
        case, projection=replace(case.projection, pending_missing_for_assessment=pending)
    )


def test_an_output_free_result_never_answers_a_request_for_verification_output() -> None:
    """Greptile P1 on #940: a bare outcome row names a run, not what it printed."""

    bare = ResultRecordedPayload(res(63), act(62), ResultOutcome.SUCCESS)
    summarized = ResultRecordedPayload(
        res(64), act(62), ResultOutcome.SUCCESS, summary="41 passed, 0 failed"
    )
    case = _requested_case({res(63): record(bare, 63)})
    pending = case.projection.pending_missing_for_assessment
    assert pending is not None
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    assert supplied_since(case.projection, pending, allowed) == ((),)

    # The reviewer asks again without citing the bare row: the request stays named, not dropped.
    judgment = SemanticJudgment(
        "insufficient_packet",
        (),
        missing_for_assessment=(
            MissingForAssessment("verification_output", (), "The test output is still absent."),
        ),
    )
    review = review_missing_for_assessment(case, (), judgment, unsuppliable_kinds=frozenset())
    assert [item.kind for item in review.items] == ["verification_output"]
    assert "semantic_missing_already_supplied" not in review.gaps
    assert "semantic_missing_non_convergent" in review.gaps

    # A genuinely new target remains an ordinary actionable request; the non-convergence marker
    # only applies when the reviewer repeats the same target set without a related publication.
    new_target = review_missing_for_assessment(
        _pending(
            case,
            MissingForAssessmentItem("verification_output", (str(act(62)),), "agent_suppliable"),
        ),
        (),
        SemanticJudgment(
            "insufficient_packet",
            (),
            missing_for_assessment=(
                MissingForAssessment("verification_output", (str(res(63)),), "new target"),
            ),
        ),
        unsuppliable_kinds=frozenset(),
    )
    assert "semantic_missing_non_convergent" not in new_target.gaps

    # A result that carries its output does answer it.
    answered = _requested_case({res(63): record(bare, 63), res(64): record(summarized, 64)})
    answered_pending = answered.projection.pending_missing_for_assessment
    assert answered_pending is not None
    assert supplied_since(answered.projection, answered_pending, allowed | {str(res(64))}) == (
        (str(res(64)),),
    )
    dropped = review_missing_for_assessment(answered, (), judgment, unsuppliable_kinds=frozenset())
    assert dropped.items == ()
    assert "semantic_missing_already_supplied" in dropped.gaps


def _repeat(kind: MissingForAssessmentKind, *targets: str) -> SemanticJudgment:
    return SemanticJudgment(
        "insufficient_packet",
        (),
        missing_for_assessment=(MissingForAssessment(kind, targets, "still absent"),),
    )


def _run(number: int, command: str) -> ActionRecordedPayload:
    return ActionRecordedPayload(act(number), ActionKind.COMMAND, "Ran tests", command=command)


def _output(number: int, action: int) -> ResultRecordedPayload:
    return ResultRecordedPayload(
        res(number), act(action), ResultOutcome.SUCCESS, summary="3 passed, 0 failed"
    )


def _pending(case: DeterministicCase, *items: MissingForAssessmentItem) -> DeterministicCase:
    pending = PendingMissingForAssessment(evt(50), 50, items)
    return replace(
        case, projection=replace(case.projection, pending_missing_for_assessment=pending)
    )


def test_material_for_another_target_never_answers_a_named_request() -> None:
    """R940-01: a same-kind record for target B leaves the repeated request for A named."""

    case = _pending(
        make_case(
            actions={
                act(1): record(_run(1, "pytest tests/a"), 10),
                act(62): record(_run(62, "pytest tests/b"), 62),
            },
            results={res(63): record(_output(63, 62), 63)},
            extra_refs=(act(1), act(62), res(63)),
        ),
        MissingForAssessmentItem("verification_output", (str(act(1)),), "agent_suppliable"),
    )
    pending = case.projection.pending_missing_for_assessment
    assert pending is not None
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    assert supplied_since(case.projection, pending, allowed) == ((),)
    review = review_missing_for_assessment(
        case, (), _repeat("verification_output", str(act(1))), unsuppliable_kinds=frozenset()
    )
    # Still named and still the agent's work: a run never recorded is owed (tb4n1 D1 review);
    # the review round stops separately after one retry (kernel.review_round).
    assert [(item.kind, item.target_refs, item.availability) for item in review.items] == [
        ("verification_output", (str(act(1)),), "agent_suppliable")
    ]
    assert "semantic_missing_already_supplied" not in review.gaps
    assert "semantic_missing_non_convergent" in review.gaps

    # The output of the named action, or of a rerun of its exact command, does answer it.
    for action, command in ((1, "pytest tests/a"), (64, "pytest tests/a")):
        answered = _pending(
            make_case(
                actions={
                    act(1): record(_run(1, "pytest tests/a"), 10),
                    act(64): record(_run(64, command), 64),
                },
                results={res(65): record(_output(65, action), 65)},
                extra_refs=(act(1), act(64), res(65)),
            ),
            MissingForAssessmentItem("verification_output", (str(act(1)),), "agent_suppliable"),
        )
        dropped = review_missing_for_assessment(
            answered,
            (),
            _repeat("verification_output", str(act(1))),
            unsuppliable_kinds=frozenset(),
        )
        assert dropped.items == ()
        assert "semantic_missing_already_supplied" in dropped.gaps


def _diff(number: int, path: str) -> EvidenceRecordedPayload:
    return EvidenceRecordedPayload(
        evd(number),
        EvidenceKind.ARTIFACT,
        EvidenceImmutability.METADATA_ONLY,
        timestamp_from_string("2026-09-27T00:00:00.000Z"),
        reference=path,
        description=f"diff of {path}",
    )


def test_a_diff_of_another_path_never_answers_a_request_for_this_path() -> None:
    """R940-01: current_diff_for_path for A stays named when only B's diff was recorded."""

    def case_with(later: EvidenceRecordedPayload) -> DeterministicCase:
        return _pending(
            make_case(
                evidence={
                    evd(1): evidence_record(_diff(1, "src/a.py"), 10),
                    later.evidence_id: evidence_record(later, 70),
                },
                extra_refs=(evd(1), later.evidence_id),
            ),
            MissingForAssessmentItem("current_diff_for_path", (str(evd(1)),), "agent_suppliable"),
        )

    other = case_with(_diff(70, "src/b.py"))
    review = review_missing_for_assessment(
        other, (), _repeat("current_diff_for_path", str(evd(1))), unsuppliable_kinds=frozenset()
    )
    assert [item.target_refs for item in review.items] == [(str(evd(1)),)]
    assert "semantic_missing_already_supplied" not in review.gaps

    same = case_with(_diff(70, "src/a.py"))
    dropped = review_missing_for_assessment(
        same, (), _repeat("current_diff_for_path", str(evd(1))), unsuppliable_kinds=frozenset()
    )
    assert dropped.items == ()
    assert "semantic_missing_already_supplied" in dropped.gaps


def test_a_request_naming_two_targets_converges_per_target() -> None:
    """Only the target that was answered stops being listed; the other stays named."""

    case = _pending(
        make_case(
            actions={
                act(1): record(_run(1, "pytest tests/a"), 10),
                act(2): record(_run(2, "pytest tests/b"), 11),
            },
            results={res(63): record(_output(63, 2), 63)},
            extra_refs=(act(1), act(2), res(63)),
        ),
        MissingForAssessmentItem(
            "verification_output",
            tuple(sorted((str(act(1)), str(act(2))), key=str.encode)),
            "agent_suppliable",
        ),
    )
    pending = case.projection.pending_missing_for_assessment
    assert pending is not None
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    assert supplied_since(case.projection, pending, allowed) == ((str(res(63)),),)
    kept = review_missing_for_assessment(
        case, (), _repeat("verification_output", str(act(1))), unsuppliable_kinds=frozenset()
    )
    assert [item.target_refs for item in kept.items] == [(str(act(1)),)]
    assert "semantic_missing_already_supplied" not in kept.gaps
    dropped = review_missing_for_assessment(
        case, (), _repeat("verification_output", str(act(2))), unsuppliable_kinds=frozenset()
    )
    assert dropped.items == ()
    assert "semantic_missing_already_supplied" in dropped.gaps


def test_a_claim_is_answered_only_by_material_its_correction_cites() -> None:
    """Output recorded beside a claim answers it once a claim correction cites that output."""

    claim = ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "Lookups repaired", ())
    output = _diff(70, "pytest-output.txt")

    def case_with(corrected: bool) -> DeterministicCase:
        claims = {clm(1): claim_record(claim, 3)}
        if corrected:
            claims[clm(1)] = claim_record(claim, 3, superseded_by_claim_id=clm(71))
            claims[clm(71)] = record(
                ClaimRecordedPayloadV1_1(
                    clm(71),
                    ClaimKind.COMPLETION,
                    "Lookups repaired",
                    (evd(70),),
                    supersedes_claim_refs=(clm(1),),
                ),
                71,
            )
        return _pending(
            make_case(
                claims=claims,
                evidence={evd(70): evidence_record(output, 70)},
                extra_refs=(clm(1), evd(70)),
            ),
            MissingForAssessmentItem("verification_output", (str(clm(1)),), "agent_suppliable"),
        )

    loose = review_missing_for_assessment(
        case_with(False),
        (),
        _repeat("verification_output", str(clm(1))),
        unsuppliable_kinds=frozenset(),
    )
    assert [item.target_refs for item in loose.items] == [(str(clm(1)),)]
    bound = review_missing_for_assessment(
        case_with(True),
        (),
        _repeat("verification_output", str(clm(1))),
        unsuppliable_kinds=frozenset(),
    )
    assert bound.items == ()
    assert "semantic_missing_already_supplied" in bound.gaps


def test_hook_command_placeholders_never_make_two_runs_the_same_command() -> None:
    """``omitted:structural`` stands in for text Yoetz did not keep; it identifies no command."""

    case = _pending(
        make_case(
            actions={
                act(1): record(_run(1, "omitted:structural"), 10),
                act(62): record(_run(62, "omitted:structural"), 62),
            },
            results={res(63): record(_output(63, 62), 63)},
            extra_refs=(act(1), act(62), res(63)),
        ),
        MissingForAssessmentItem("verification_output", (str(act(1)),), "agent_suppliable"),
    )
    review = review_missing_for_assessment(
        case, (), _repeat("verification_output", str(act(1))), unsuppliable_kinds=frozenset()
    )
    assert [item.target_refs for item in review.items] == [(str(act(1)),)]


# --- R940-01 follow-up: binding is a direct relation, normalized but exact ------------------------


def _dropped(
    case: DeterministicCase,
    kind: MissingForAssessmentKind,
    target: str,
    *,
    observed: frozenset[str] = frozenset(),
    captured_edit_paths: Mapping[str, frozenset[str]] | None = None,
    workspace_root: str | None = None,
) -> bool:
    """Whether a repeat of the pending request for ``target`` is dropped as already supplied."""

    case = _pending(case, MissingForAssessmentItem(kind, (target,), "agent_suppliable"))
    case = replace(case, observation_event_ids=frozenset(event_id(item) for item in observed))
    # Only the options a test sets are passed, so a test fails on a missing rule, not a keyword.
    options: dict[str, object] = {}
    if captured_edit_paths is not None:
        options["captured_edit_paths"] = captured_edit_paths
    if workspace_root is not None:
        options["workspace_root"] = workspace_root
    review = review_missing_for_assessment(
        case,
        (),
        _repeat(kind, target),
        unsuppliable_kinds=frozenset(),
        **options,  # pyright: ignore[reportArgumentType]
    )
    if review.items == ():
        assert "semantic_missing_already_supplied" in review.gaps
        return True
    assert [item.target_refs for item in review.items] == [(target,)]
    assert "semantic_missing_already_supplied" not in review.gaps
    return False


def _refs(*mappings: Iterable[object]) -> tuple[FindingBasisRef, ...]:
    return tuple(cast(FindingBasisRef, ref) for mapping in mappings for ref in mapping)


def _cases(
    *,
    actions: Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]] | None = None,
    results: Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]] | None = None,
    evidence: Mapping[EvidenceId, EvidenceProjectionRecord] | None = None,
    claims: Mapping[ClaimId, ClaimProjectionRecord] | None = None,
    obligations: Mapping[ObligationId, ObligationProjectionRecord] | None = None,
) -> DeterministicCase:
    return make_case(
        actions=actions,
        results=results,
        evidence=evidence,
        claims=claims,
        obligations=obligations,
        extra_refs=_refs(*(item or {} for item in (actions, results, evidence, claims))),
    )


def test_reciting_the_old_target_beside_another_paths_diff_never_answers_it() -> None:
    """Only new material tied to the target counts; citing the old target again is not new."""

    diff_b = {act(70): record(_run(70, "git diff src/b.py"), 70)}
    diffs = {
        evd(1): evidence_record(_diff(1, "src/a.py"), 10),
        evd(71): evidence_record(_diff(71, "src/b.py"), 71),
    }
    via_result = _cases(
        actions=diff_b,
        evidence=diffs,
        results={
            res(72): record(
                ResultRecordedPayload(
                    res(72), act(70), ResultOutcome.SUCCESS, evidence_refs=(evd(1), evd(71))
                ),
                72,
            )
        },
    )
    assert not _dropped(via_result, "current_diff_for_path", str(evd(1)))
    via_claim = _cases(
        evidence=diffs,
        claims={
            clm(72): record(
                ClaimRecordedPayload(clm(72), ClaimKind.MATERIAL, "Both diffs", (evd(1), evd(71))),
                72,
            )
        },
    )
    assert not _dropped(via_claim, "current_diff_for_path", str(evd(1)))


def test_a_shared_obligation_never_ties_a_sibling_run_to_the_target() -> None:
    obligation = ObligationPublishedPayload(obl(60), "Verify", "tests pass", ObligationStatus.OPEN)
    case = _cases(
        obligations={obl(60): obligation_record(obligation, 60)},
        actions={
            act(1): record(_run(1, "pytest tests/a"), 10),
            act(61): record(
                ActionRecordedPayload(
                    act(61),
                    ActionKind.COMMAND,
                    "Rerun",
                    "pytest tests/a",
                    obligation_refs=(obl(60),),
                ),
                61,
            ),
            act(63): record(
                ActionRecordedPayload(
                    act(63),
                    ActionKind.COMMAND,
                    "Sibling",
                    "pytest tests/b",
                    obligation_refs=(obl(60),),
                ),
                63,
            ),
        },
        results={
            res(62): record(ResultRecordedPayload(res(62), act(61), ResultOutcome.SUCCESS), 62),
            res(64): record(_output(64, 63), 64),
        },
    )
    assert not _dropped(case, "verification_output", str(act(1)))


def test_a_generic_shared_reference_is_not_the_same_subject() -> None:
    case = _cases(
        evidence={
            evd(1): evidence_record(_diff(1, "stdout"), 10),
            evd(70): evidence_record(_diff(70, "stdout"), 70),
        }
    )
    assert not _dropped(case, "current_diff_for_path", str(evd(1)))
    # Naming the target itself as the reference is an explicit tie.
    tied = _cases(
        evidence={
            evd(1): evidence_record(_diff(1, "stdout"), 10),
            evd(70): evidence_record(_diff(70, str(evd(1))), 70),
        }
    )
    assert _dropped(tied, "current_diff_for_path", str(evd(1)))


def test_a_claim_correction_answers_only_with_material_tied_to_the_claims_support() -> None:
    supported = ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "A passes", (res(2),))

    def case_with(command: str) -> DeterministicCase:
        return _cases(
            actions={
                act(2): record(_run(2, "pytest tests/a"), 8),
                act(70): record(_run(70, command), 70),
            },
            results={res(2): record(_output(2, 2), 9), res(71): record(_output(71, 70), 71)},
            claims={
                clm(1): claim_record(supported, 10, superseded_by_claim_id=clm(72)),
                clm(72): record(
                    ClaimRecordedPayloadV1_1(
                        clm(72),
                        ClaimKind.COMPLETION,
                        "A passes",
                        (res(71),),
                        supersedes_claim_refs=(clm(1),),
                    ),
                    72,
                ),
            },
        )

    assert not _dropped(case_with("pytest tests/b"), "verification_output", str(clm(1)))
    assert _dropped(case_with("pytest tests/a"), "verification_output", str(clm(1)))


def test_paths_and_commands_compare_normalized_but_exact() -> None:
    for reference in ("./src//a.py", "src/./a.py", "src/a.py/"):
        case = _cases(
            evidence={
                evd(1): evidence_record(_diff(1, "src/a.py"), 10),
                evd(70): evidence_record(_diff(70, reference), 70),
            }
        )
        assert _dropped(case, "current_diff_for_path", str(evd(1))), reference
    # An absolute path is anchored to the workspace root (see the root tests below).
    absolute = _reference_case("src/a.py", "/work/repo/src/a.py")
    assert _dropped(absolute, "current_diff_for_path", str(evd(1)), workspace_root="/work/repo")
    for reference in ("src/A.py", "src/a.pyc", "lib/src/a.py.bak"):
        case = _cases(
            evidence={
                evd(1): evidence_record(_diff(1, "src/a.py"), 10),
                evd(70): evidence_record(_diff(70, reference), 70),
            }
        )
        assert not _dropped(case, "current_diff_for_path", str(evd(1))), reference
    spaced = _cases(
        actions={
            act(1): record(_run(1, "pytest  tests/a"), 10),
            act(70): record(_run(70, " pytest tests/a\t"), 70),
        },
        results={res(71): record(_output(71, 70), 71)},
    )
    assert _dropped(spaced, "verification_output", str(act(1)))


def test_a_hook_rerun_with_the_same_command_digest_is_the_same_command() -> None:
    def case_with(digest: str) -> tuple[DeterministicCase, frozenset[str]]:
        case = _cases(
            actions={
                act(1): record(_run(1, "omitted:sha256:" + "a" * 64), 10),
                act(70): record(_run(70, "omitted:sha256:" + digest * 64), 70),
            },
            results={res(71): record(_output(71, 70), 71)},
        )
        # The rerun itself is hook-observed; the agent published the result that carries output.
        return case, frozenset({str(case.projection.actions[act(70)].source_event_id)})

    same, observed = case_with("a")
    assert _dropped(same, "verification_output", str(act(1)), observed=observed)
    other, observed = case_with("b")
    assert not _dropped(other, "verification_output", str(act(1)), observed=observed)


def _captured(number: int) -> EvidenceRecordedPayload:
    return EvidenceRecordedPayload(
        evd(number),
        EvidenceKind.OTHER,
        EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        timestamp_from_string("2026-09-27T00:00:00.000Z"),
        captured_object_id=object_id(f"obj_00000000-0000-4000-8000-{number:012x}"),
        content_digest="sha256:" + "c" * 64,
        description="Observation-captured tool_input bytes part=1/1",
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
            content_availability=EvidenceContentAvailability.CAPTURED,
            byte_count=10,
            provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
        ),
    )


def test_a_fresh_git_diff_of_the_captured_path_answers_a_hook_captured_edit() -> None:
    """Hook captures carry no reference; the path the capture records binds a fresh diff."""

    def case_with(path: str) -> DeterministicCase:
        return _cases(
            evidence={
                evd(1): evidence_record(_captured(1), 10),
                evd(71): evidence_record(
                    EvidenceRecordedPayload(
                        evd(71),
                        EvidenceKind.COMMAND_OUTPUT,
                        EvidenceImmutability.METADATA_ONLY,
                        timestamp_from_string("2026-09-27T00:00:00.000Z"),
                        description="diff --git a/x b/x",
                    ),
                    71,
                ),
            },
            actions={act(70): record(_run(70, f"git diff -- {path}"), 70)},
            results={
                res(72): record(
                    ResultRecordedPayload(
                        res(72), act(70), ResultOutcome.SUCCESS, evidence_refs=(evd(71),)
                    ),
                    72,
                )
            },
        )

    paths = {str(evd(1)): frozenset({"src/a.py"})}
    assert _dropped(
        case_with("src/a.py"), "current_diff_for_path", str(evd(1)), captured_edit_paths=paths
    )
    assert not _dropped(
        case_with("src/b.py"), "current_diff_for_path", str(evd(1)), captured_edit_paths=paths
    )
    # Without the capture's paths (a recovered review), the request stays named.
    assert not _dropped(case_with("src/a.py"), "current_diff_for_path", str(evd(1)))


# --- R940-01 second follow-up: workspace-anchored paths, git diff forms, full coverage -----------


def _reference_case(target_reference: str, *references: str) -> DeterministicCase:
    return _cases(
        evidence={
            evd(1): evidence_record(_diff(1, target_reference), 10),
            **{
                evd(70 + index): evidence_record(_diff(70 + index, reference), 70 + index)
                for index, reference in enumerate(references)
            },
        }
    )


def _diff_run_case(*commands: str) -> DeterministicCase:
    """A hook-captured edit (evd 1) and one agent ``git diff`` run with output per command."""

    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {
        evd(1): evidence_record(_captured(1), 10)
    }
    actions: dict[ActionId, ProjectionRecord[ActionRecordedPayload]] = {}
    results: dict[ResultId, ProjectionRecord[ResultRecordedPayload]] = {}
    for index, command in enumerate(commands):
        number = 60 + index * 3
        actions[act(number)] = record(_run(number, command), number)
        evidence[evd(number + 1)] = evidence_record(
            EvidenceRecordedPayload(
                evd(number + 1),
                EvidenceKind.COMMAND_OUTPUT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-09-27T00:00:00.000Z"),
                description="diff --git a/x b/x",
            ),
            number + 1,
        )
        results[res(number + 2)] = record(
            ResultRecordedPayload(
                res(number + 2),
                act(number),
                ResultOutcome.SUCCESS,
                evidence_refs=(evd(number + 1),),
            ),
            number + 2,
        )
    return _cases(evidence=evidence, actions=actions, results=results)


def _answers_capture(
    paths: frozenset[str], *commands: str, workspace_root: str | None = None
) -> bool:
    return _dropped(
        _diff_run_case(*commands),
        "current_diff_for_path",
        str(evd(1)),
        captured_edit_paths={str(evd(1)): paths},
        workspace_root=workspace_root,
    )


def test_an_absolute_path_answers_only_inside_the_workspace_root() -> None:
    for target, reference in (
        ("src/a.py", "/other/repo/src/a.py"),
        ("a.py", "/x/pkg/a.py"),
        ("README.md", "/repo/docs/README.md"),
    ):
        # Without a workspace root, and with a different one, an absolute path never matches.
        for root in (None, "/work/repo"):
            case = _reference_case(target, reference)
            assert not _dropped(case, "current_diff_for_path", str(evd(1)), workspace_root=root), (
                target,
                reference,
                root,
            )
    assert not _answers_capture(frozenset({"src/a.py"}), "git diff /other/repo/src/a.py")
    inside = _reference_case("src/a.py", "/work/repo/src/a.py")
    assert _dropped(inside, "current_diff_for_path", str(evd(1)), workspace_root="/work/repo")
    assert not _dropped(inside, "current_diff_for_path", str(evd(1)), workspace_root="/work")
    assert _answers_capture(
        frozenset({"src/a.py"}), "git diff /work/repo/src/a.py", workspace_root="/work/repo"
    )


def test_an_aliased_workspace_root_resolves_to_the_same_files(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    # The root is resolved; an agent path is only compared lexically, never resolved.
    for written in (link, real):
        case = _reference_case("src/a.py", f"{written}/src/a.py")
        assert _dropped(case, "current_diff_for_path", str(evd(1)), workspace_root=str(link))
    via_link = _reference_case("src/a.py", f"{link}/src/a.py")
    assert not _dropped(via_link, "current_diff_for_path", str(evd(1)), workspace_root=str(real))


def test_an_agent_named_absolute_path_is_never_resolved_on_the_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the workspace root is resolved; a path the agent names could be an unreachable mount."""

    root = str(tmp_path)
    resolve = os.path.realpath
    touched: list[str] = []

    def guarded(path: str | os.PathLike[str], *, strict: bool = False) -> str:
        if os.fspath(path) != root:
            touched.append(os.fspath(path))
            raise AssertionError("agent-named path resolved")
        return resolve(path, strict=strict)

    monkeypatch.setattr(os.path, "realpath", guarded)
    for reference in ("/net/unreachable/src/a.py", f"{root}/src/a.py"):
        case = _reference_case("src/a.py", reference)
        _dropped(case, "current_diff_for_path", str(evd(1)), workspace_root=root)
    assert not _answers_capture(
        frozenset({"src/a.py"}), "git diff /net/unreachable/src/a.py", workspace_root=root
    )
    assert touched == []


def test_a_bare_or_dot_file_name_is_a_path_when_the_other_side_is_one() -> None:
    for name in ("Makefile", "Dockerfile", ".gitignore", ".env"):
        assert _dropped(_reference_case(name, f"./{name}"), "current_diff_for_path", str(evd(1)))
        assert _dropped(
            _reference_case(name, f"/work/repo/{name}"),
            "current_diff_for_path",
            str(evd(1)),
            workspace_root="/work/repo",
        )
        # Two bare words are never assumed to be the same file.
        assert not _dropped(_reference_case(name, name), "current_diff_for_path", str(evd(1)))
        assert _answers_capture(frozenset({name}), f"git diff -- {name}")
    # Naming the target's id is always an explicit tie.
    assert _dropped(_reference_case("Makefile", str(evd(1))), "current_diff_for_path", str(evd(1)))


def test_every_content_form_of_git_diff_answers_and_summary_forms_do_not() -> None:
    target = frozenset({"src/a.py"})
    for command in (
        "git --no-pager diff src/a.py",
        "git diff src/",
        "git diff src",
        "git diff",
        "git diff HEAD",
        "git diff --cached",
        "git -C . diff src/a.py",
    ):
        assert _answers_capture(target, command), command
    assert _answers_capture(target, "git -C /work/repo diff src/a.py", workspace_root="/work/repo")
    for command in (
        "git -C /elsewhere diff src/a.py",
        "git diff lib/",
        "git diff --stat src/a.py",
        "git diff --name-only",
        "git diff --numstat -- src/a.py",
        "git diff src/a.pyc",
    ):
        assert not _answers_capture(target, command, workspace_root="/work/repo"), command


def test_a_multi_path_capture_needs_every_path_it_records() -> None:
    both = frozenset({"src/a.py", "src/b.py"})
    assert not _answers_capture(both, "git diff src/a.py")
    assert _answers_capture(both, "git diff src/a.py src/b.py")
    assert _answers_capture(both, "git diff src/a.py", "git diff -- src/b.py")
    assert _answers_capture(both, "git diff")


def test_an_artifact_a_command_wrote_is_answered_only_by_that_commands_runs() -> None:
    """``reports/junit.xml`` from another command is not the named run's output."""

    def case_with(command: str, cited: bool) -> DeterministicCase:
        junit = EvidenceRecordedPayload(
            evd(3),
            EvidenceKind.TEST_RESULT,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-09-27T00:00:00.000Z"),
            reference="reports/junit.xml",
            description="junit",
        )
        later = replace(junit, evidence_id=evd(72))
        return _cases(
            actions={
                act(1): record(_run(1, "pytest tests/a"), 8),
                act(70): record(_run(70, command), 70),
            },
            evidence={evd(3): evidence_record(junit, 9), evd(72): evidence_record(later, 72)},
            results={
                res(2): record(
                    ResultRecordedPayload(
                        res(2), act(1), ResultOutcome.SUCCESS, evidence_refs=(evd(3),)
                    ),
                    10,
                ),
                res(71): record(
                    ResultRecordedPayload(
                        res(71),
                        act(70),
                        ResultOutcome.SUCCESS,
                        evidence_refs=(evd(72),) if cited else (),
                    ),
                    71,
                ),
            },
        )

    assert not _dropped(case_with("pytest tests/b", True), "verification_output", str(evd(3)))
    assert not _dropped(case_with("pytest tests/b", False), "verification_output", str(evd(3)))
    assert _dropped(case_with("pytest tests/a", True), "verification_output", str(evd(3)))


class _OpenedLedger:
    def __init__(self, workspace_ref: str | None) -> None:
        self._payload = SessionOpenedPayload(
            task_title="Repair lookups",
            client_kind=ClientKind.TEST_CLIENT,
            client_version="0.1.0",
            integration=IntegrationKind.LOCAL_CLI,
            profile=RuntimeProfile.TEST_FAKE,
            workspace_ref=workspace_ref,
        )

    async def load_events(self, session_id: str) -> AsyncIterator[object]:
        del session_id
        yield SimpleNamespace(payload=self._payload)


@pytest.mark.anyio
async def test_the_review_reads_the_workspace_root_the_session_opened_with() -> None:
    root_of = ready_composition._workspace_root_for_runtime  # pyright: ignore[reportPrivateUsage]
    for workspace_ref, expected in (("/work/repo", "/work/repo"), ("repo", None), (None, None)):
        runtime = SimpleNamespace(ledger=_OpenedLedger(workspace_ref), session_id="ses")
        assert await root_of(cast(TaskRuntime, runtime)) == expected
    assert await root_of(None) is None


def test_a_composed_run_keys_on_its_leading_identity() -> None:
    """Adversarial review of E3 (#988): the segment suffix must not split one command in two."""

    from yoetz.application import missing_for_assessment
    from yoetz.domain.events import ActionRecordedPayload as _Action
    from yoetz.domain.values import action_id as _action_id

    identity = "hmac-sha256:" + "a" * 64
    segment = "hmac-sha256:" + "b" * 64
    run_key = getattr(missing_for_assessment, "_run_key")
    before = _Action(
        _action_id("act_00000000-0000-4000-8000-000000000001"),
        ActionKind.COMMAND,
        "Observed command",
        command=f"omitted:{identity}",
    )
    after = _Action(
        _action_id("act_00000000-0000-4000-8000-000000000002"),
        ActionKind.COMMAND,
        "Observed command",
        command=f"omitted:{identity} and_chain {segment}",
    )
    assert run_key(before) == run_key(after) == ("digest", identity)


def _first_request(kind: str, target: str) -> SemanticJudgment:
    return _repeat(cast(MissingForAssessmentKind, kind), target)


def test_an_image_or_binary_target_is_an_unsupported_data_type_never_agent_work() -> None:
    """tb4n1 D1 (cad-model, medical, freecad S): a PNG or CAD deliverable is never carried."""

    for name in ("out/schematic.PNG", "/app/english_model.bin", "model.FCStd", "drawing.pdf"):
        case = make_case(
            evidence={evd(5): evidence_record(_diff(5, name), 5)},
            extra_refs=(evd(5),),
        )
        review = review_missing_for_assessment(
            case, (), _first_request("other", str(evd(5))), unsuppliable_kinds=frozenset()
        )
        assert [item.availability for item in review.items] == [
            "yoetz_limit_unsupported_data_type"
        ], name
        assert "semantic_missing_agent_suppliable" not in review.gaps
        assert "semantic_missing_yoetz_limit" in review.gaps


def test_content_the_packet_named_but_could_not_carry_is_packet_room_not_agent_work() -> None:
    """tb4n1 D1 (interleaved-vigenere S): a clipped deliverable diff is Yoetz's limit.

    The reviewer said "current cracker.py implementation is not available for review" while
    the check-time change was clipped; Yoetz asked the agent to supply it, and the agent moved
    the deliverable's data table into an undelivered file. The same request is now Yoetz's
    packet-room limit, so no ``supply_missing_input`` follows.
    """

    case = make_case(
        evidence={evd(5): evidence_record(_diff(5, "cracker.py"), 5)},
        extra_refs=(evd(5),),
    )
    clipped = review_missing_for_assessment(
        case,
        (),
        _first_request("current_diff_for_path", str(evd(5))),
        unsuppliable_kinds=frozenset(),
        change_clipped=True,
    )
    assert [item.availability for item in clipped.items] == ["yoetz_limit_packet_room"]
    unselected = review_missing_for_assessment(
        case,
        (),
        _first_request("verification_output", str(evd(5))),
        unsuppliable_kinds=frozenset(),
        packet_limited_refs=frozenset({str(evd(5))}),
    )
    assert [item.availability for item in unselected.items] == ["yoetz_limit_packet_room"]
    # A diff the packet carried whole, of a text file, stays a request the agent can answer.
    shown = review_missing_for_assessment(
        case,
        (),
        _first_request("current_diff_for_path", str(evd(5))),
        unsuppliable_kinds=frozenset(),
    )
    assert [item.availability for item in shown.items] == ["agent_suppliable"]


def test_a_hook_observed_image_is_an_unsupported_data_type() -> None:
    """tb4n1 D6 + L3 P3-2: an observed image tool result is kept as a digest only, never sent."""

    image = EvidenceRecordedPayload(
        evd(7),
        EvidenceKind.ARTIFACT,
        EvidenceImmutability.CONTENT_DIGEST,
        timestamp_from_string("2026-09-27T00:00:00.000Z"),
        content_digest="sha256:" + "d" * 64,
        description="Observed image tool result image/png 800x600 (5120 bytes); "
        "pixels were not captured or sent",
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.ARTIFACT_BYTES,
            content_availability=EvidenceContentAvailability.DIGEST_ONLY,
            byte_count=5120,
            provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
        ),
    )
    case = make_case(evidence={evd(7): evidence_record(image, 7)}, extra_refs=(evd(7),))
    review = review_missing_for_assessment(
        case, (), _first_request("other", str(evd(7))), unsuppliable_kinds=frozenset()
    )
    assert [item.availability for item in review.items] == ["yoetz_limit_unsupported_data_type"]


def test_agent_rendered_text_of_a_binary_answers_a_request_for_it() -> None:
    """PL5-2 (#1004): text output recorded with the binary's path as its reference supplies it.

    The reviewer named the PDF deliverable; the agent then records ``pdftotext`` output whose
    ``reference`` is that PDF's path. The request is counted as supplied and dropped, never
    asked again.
    """

    rendering = EvidenceRecordedPayload(
        evd(70),
        EvidenceKind.COMMAND_OUTPUT,
        EvidenceImmutability.METADATA_ONLY,
        timestamp_from_string("2026-09-27T00:00:00.000Z"),
        reference="out/invoice.pdf",
        description="INVOICE 2026-0042\nTotal due: 1,240.00 EUR",
    )
    case = _pending(
        make_case(
            evidence={
                evd(5): evidence_record(_diff(5, "out/invoice.pdf"), 5),
                evd(70): evidence_record(rendering, 70),
            },
            extra_refs=(evd(5), evd(70)),
        ),
        MissingForAssessmentItem("other", (str(evd(5)),), "yoetz_limit_unsupported_data_type"),
    )
    pending = case.projection.pending_missing_for_assessment
    assert pending is not None
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    assert supplied_since(case.projection, pending, allowed) == ((str(evd(70)),),)
    dropped = review_missing_for_assessment(
        case, (), _repeat("other", str(evd(5))), unsuppliable_kinds=frozenset()
    )
    assert dropped.items == ()
    assert "semantic_missing_already_supplied" in dropped.gaps


def _requesting(number: int, *files: str) -> ObligationPublishedPayload:
    from yoetz.domain.events import RequestedItem, RequestedItemKind

    return ObligationPublishedPayload(
        obl(number),
        "Deliver the requested files",
        "the files",
        ObligationStatus.OPEN,
        requested_items=tuple(RequestedItem(RequestedItemKind.FILE, name) for name in files),
    )


def test_an_other_item_is_a_yoetz_limit_only_when_every_requested_output_is_binary() -> None:
    """tb4n1 review: cad-model's unseen schematic is a limit; satb's unwritten score is work."""

    cad = make_case(
        obligations={
            obl(3): obligation_record(_requesting(3, "/app/part.step", "/app/part.png"), 3)
        },
        extra_refs=(obl(3),),
    )
    review = review_missing_for_assessment(
        cad, (), _first_request("other", str(obl(3))), unsuppliable_kinds=frozenset()
    )
    assert [item.availability for item in review.items] == ["yoetz_limit_unsupported_data_type"]
    satb = make_case(
        obligations={
            obl(3): obligation_record(_requesting(3, "/app/input.mp3", "/app/score.musicxml"), 3)
        },
        extra_refs=(obl(3),),
    )
    review = review_missing_for_assessment(
        satb, (), _first_request("other", str(obl(3))), unsuppliable_kinds=frozenset()
    )
    assert [item.availability for item in review.items] == ["agent_suppliable"]


# --- tb4n2 A11: edge-case file types and suffix-less binaries ------------------------------------

_A11_SUFFIXES = (
    # Archives and containers (a multi-suffix name matches on its last suffix).
    *(
        ".rar .lz4 .lzma .cab .iso .dmg .img .qcow2 .vmdk .deb .rpm .apk .ipa .whl .egg .war .ear"
    ).split(),
    *".aar .nupkg .sif .tar.zst .tar.lz4 .tar.xz".split(),
    # Zip-based office and app files.
    *".doc .ppt .odt .ods .odp .epub .key .pages .numbers .mscz .3mf .sketch .fig".split(),
    # Audio and video.
    *".flac .ogg .opus .m4a .aac .aiff .wma .mov .avi .mkv .webm .m4v .wmv".split(),
    # Images.
    *".psd .raw .cr2 .nef .dng .exr .hdr .tga .jp2 .jxl".split(),
    # CAD, 3D and EDA.
    *".glb .fbx .3dm .skp .f3d .sldprt .sldasm .ipt .iam .catpart .x_b .sab .gds .oas".split(),
    *".brd .bit .svf".split(),
    # ROMs and fonts.
    *".rom .nes .gb .gba .sfc .ttf .otf .woff .woff2".split(),
    # Data and model files.
    *".feather .arrow .orc .avro .tfrecord .lmdb .hdf5 .hdf .nc .mat .sav .dta .rds".split(),
    *".rdata .joblib .ckpt .gguf .ggml .tflite .pb .keras .mlmodel".split(),
    # Databases, natives and captures.
    *".sqlite3 .db3 .duckdb .mdb .accdb .a .lib .elf .ko .pyd .msi .beam .pcap .pcapng".split(),
)


def _named_file_review(
    name: str, kind: str = "other", *, binary_paths: frozenset[str] = frozenset()
) -> list[str]:
    case = make_case(
        evidence={evd(5): evidence_record(_diff(5, name), 5)},
        extra_refs=(evd(5),),
    )
    review = review_missing_for_assessment(
        case,
        (),
        _first_request(kind, str(evd(5))),
        unsuppliable_kinds=frozenset(),
        workspace_root="/work/repo",
        binary_paths=binary_paths,
    )
    return [item.availability for item in review.items]


@pytest.mark.parametrize("suffix", _A11_SUFFIXES)
def test_every_listed_binary_kind_is_an_unsupported_data_type(suffix: str) -> None:
    """tb4n2 A11: content the packet cannot carry is Yoetz's limit, whatever its case."""

    assert unsupported_data_type(f"out/deliverable{suffix}")
    assert unsupported_data_type(f"out/DELIVERABLE{suffix.upper()}")
    assert _named_file_review(f"out/deliverable{suffix}") == ["yoetz_limit_unsupported_data_type"]


@pytest.mark.parametrize(
    "name", ("Makefile", "Dockerfile", "solver.c", "build.sh", "README", ".a", "notes.txt")
)
def test_text_and_suffix_less_names_stay_agent_work_without_a_binary_mark(name: str) -> None:
    assert not unsupported_data_type(name)
    assert _named_file_review(name) == ["agent_suppliable"]


_BINARY_CHANGE = (
    b"Yoetz check-time change: captured by the Yoetz service when this check ran; "
    b"the agent did not supply it.\n"
    b"Base: the commit HEAD named when this task started.\n"
    b"Scope: committed and uncommitted changes.\n"
    b"Changed files: 3 tracked, 3 untracked. Not shown: 0.\n"
    b"Files:\n"
    b"  M bin/firmware (binary)\n"
    b"  M src/solver.c (+3 -1)\n"
    b"  D old tool (binary)\n"
    b"  A solver (binary) untracked\n"
    b'  A "caf\\303\\251" (binary) untracked\n'
    b"  A Makefile (+2 -0) untracked\n"
    b"End of header. The unified diff follows.\n"
    b"diff --git a/bin/firmware b/bin/firmware\n"
    b"Binary files a/bin/firmware and b/bin/firmware differ\n"
    b"diff --git a/src/solver.c b/src/solver.c\n"
    b"--- a/src/solver.c\n"
    b"+++ b/src/solver.c\n"
    b"@@ -1 +1,3 @@\n"
    b"+Binary files a/fake and b/fake differ\n"
    b"diff --git a/old tool b/old tool\n"
    b"deleted file mode 100755\n"
    b"Binary files a/old tool and /dev/null differ\n"
    b"diff --git a/a.out b/a.out\n"
    b"new file mode 100755\n"
    b"Binary files /dev/null and b/a.out differ\n"
    b"diff --git a/x and b/y b/x and b/y\n"
    b"Binary files a/x and b/y and b/x and b/y differ\n"
)


def _binary_capture(text: bytes = _BINARY_CHANGE) -> CheckChangeCapture:
    return CheckChangeCapture(
        base="task_start",
        text=text,
        tracked_files=3,
        untracked_files=3,
        omitted_files=0,
        truncated=False,
    )


def test_the_check_time_change_names_its_binary_files() -> None:
    """Git's binary marks, read from the header and the diff; quoted names decoded, diff-body
    lines skipped."""

    assert check_change_binary_paths(_binary_capture()) == frozenset(
        {"bin/firmware", "old tool", "solver", "a.out", "x and b/y", "café"}
    )
    assert check_change_binary_paths(None) == frozenset()


def test_a_suffix_less_binary_the_change_marks_is_an_unsupported_data_type() -> None:
    """tb4n2 A11: a compiled ``solver`` or ELF harness reads as Yoetz's limit, never agent work."""

    binary = check_change_binary_paths(_binary_capture())
    for name in ("solver", "./solver", "/work/repo/a.out", "bin/firmware"):
        for kind in ("other", "verification_output", "current_diff_for_path"):
            assert _named_file_review(name, kind, binary_paths=binary) == [
                "yoetz_limit_unsupported_data_type"
            ], (name, kind)
    # A text file in the same change, and a binary's name outside the workspace, stay agent work.
    for name in ("Makefile", "src/solver.c", "/elsewhere/solver"):
        assert _named_file_review(name, binary_paths=binary) == ["agent_suppliable"], name


def test_an_other_item_whose_requested_outputs_are_marked_binary_is_a_yoetz_limit() -> None:
    case = make_case(
        obligations={obl(3): obligation_record(_requesting(3, "/work/repo/solver"), 3)},
        extra_refs=(obl(3),),
    )

    def availability(binary: frozenset[str]) -> list[str]:
        review = review_missing_for_assessment(
            case,
            (),
            _first_request("other", str(obl(3))),
            unsuppliable_kinds=frozenset(),
            workspace_root="/work/repo",
            binary_paths=binary,
        )
        return [item.availability for item in review.items]

    assert availability(frozenset({"solver"})) == ["yoetz_limit_unsupported_data_type"]
    assert availability(frozenset()) == ["agent_suppliable"]


def test_a_claim_target_with_only_text_evidence_stays_agent_work() -> None:
    """tb4n2 music L205: the validator's output for a claim is text the agent can publish."""

    claim = ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "harmony.mxl written", (evd(4),))
    evidence = EvidenceRecordedPayload(
        evd(4),
        EvidenceKind.COMMAND_OUTPUT,
        EvidenceImmutability.METADATA_ONLY,
        timestamp_from_string("2026-09-27T00:00:00.000Z"),
        description="validator: 0 parallel fifths",
    )
    case = make_case(
        claims={clm(1): claim_record(claim, 3)},
        evidence={evd(4): evidence_record(evidence, 4)},
        extra_refs=(clm(1), evd(4)),
    )
    review = review_missing_for_assessment(
        case,
        (),
        _first_request("verification_output", str(clm(1))),
        unsuppliable_kinds=frozenset(),
        binary_paths=frozenset({"harmony.mxl"}),
    )
    assert [item.availability for item in review.items] == ["agent_suppliable"]
