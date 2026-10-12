"""In-check follow-up rounds through the real composition and a durable ledger (issue #1047).

Drives ``_privacy_gated_semantic_evaluator`` over memory and SQLite ledgers with a fake privacy
coordinator that answers like a reviewer: ``insufficient_packet`` naming the first failing run's
output while the sent packet lacks it, a clean conclusion once it is there. It reports what the
exact sent packet carried, as production egress does. Each follow-up round is one more dispatch
through the same privacy path, in a durable job of its own; replay recovers every round without
another provider call, and a round that would add nothing is never sent.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any, cast

import pytest

import integration.service.test_semantic_fallback_dispatch as fallback
import integration.service.test_semantic_non_dispatch as non_dispatch
from builders.ledger_adapters import append_command, memory_adapter, sqlite_adapter
from builders.policy_cases import evd, res
from unit.application.test_review_follow_up import (
    _verification_case,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.adapters.memory.ledger import MemoryLedgerAdapter
from yoetz.adapters.sqlite.repository import SqliteLedger
from yoetz.application.check import FinalSemanticEvaluation
from yoetz.application.egress import SemanticEgressProviderOutcome, SemanticEgressSuccess
from yoetz.application.missing_for_assessment import ReviewFollowUp, plan_review_follow_up
from yoetz.application.semantic_case import (
    assemble_filtered_review_packet,
    review_packet_disclosure_result,
)
from yoetz.domain.events import MissingForAssessmentItem
from yoetz.domain.findings import SemanticDispatchKind, SemanticFailureClass
from yoetz.domain.privacy import (
    REVIEW_PACKET_ITEM_ID,
    CandidateContext,
    ProviderBinding,
    ReviewContextProfile,
)
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.ports.ledger import FrozenCase
from yoetz.ports.runtime import TaskRuntime
from yoetz.ports.semantic import (
    MissingForAssessment,
    SemanticJudgment,
    SemanticResultSuccess,
    SemanticResultUnavailable,
)
from yoetz.protocol.canonical import strict_json_parse
from yoetz.protocol.models import SemanticReason, SemanticStatus

_PROVIDER = non_dispatch._PROVIDER  # pyright: ignore[reportPrivateUsage]
_Privacy = non_dispatch._Privacy  # pyright: ignore[reportPrivateUsage]
_durable_semantic_case = non_dispatch._durable_semantic_case  # pyright: ignore[reportPrivateUsage]
_paired_evaluator = fallback._paired_evaluator  # pyright: ignore[reportPrivateUsage]
_provenance = fallback._provenance  # pyright: ignore[reportPrivateUsage]

type _FollowUpEvaluator = Callable[..., Awaitable[FinalSemanticEvaluation | None]]

_REQUESTED = f"excerpt-{evd(1)}"


def _sent_packet(candidate: CandidateContext, room_cut: frozenset[str]) -> bytes:
    """The exact packet a provider receives for every offered item.

    ``room_cut`` items have no catalog row in it, as when envelope bounding leaves a composed row
    out for packet room; their content cannot travel.
    """

    content = {item.item_id: item.plaintext for item in candidate.items}
    envelope = strict_json_parse(content.pop(REVIEW_PACKET_ITEM_ID))
    assert isinstance(envelope, dict)
    catalog = envelope["item_catalog"]
    assert isinstance(catalog, list)
    envelope["item_catalog"] = [
        row for row in catalog if not (isinstance(row, dict) and row.get("item_id") in room_cut)
    ]
    return assemble_filtered_review_packet(
        envelope, content_by_id=content, included_item_ids=frozenset(content)
    )


class _ReviewerPrivacy(_Privacy):
    """Answers like a reviewer that needs the first failing run's output (issue #1047)."""

    def __init__(
        self,
        *,
        task_id: str,
        fail_with_output: bool = False,
        fail_always: bool = False,
        room_cuts: int = 0,
    ) -> None:
        super().__init__(task_id=task_id, profile=ReviewContextProfile.EXPANDED)
        self.fail_with_output = fail_with_output
        self.fail_always = fail_always
        # The first ``room_cuts`` sent packets have no room for the requested output's row.
        self.room_cuts = room_cuts
        self.sent: list[tuple[str, frozenset[str]]] = []

    async def evaluate_semantic(self, candidate: object, deadline: object) -> object:
        del deadline
        assert type(candidate) is CandidateContext
        self.calls += 1
        binding = cast(ProviderBinding, candidate.provider_binding)
        items = frozenset(item.item_id for item in candidate.items)
        digest = candidate.subject_digest
        assert digest is not None
        self.sent.append((digest, items))
        ordinal = self.calls
        proposal = f"ppr_54000000-0000-4000-8000-00000000{ordinal:04d}"
        authorization = f"aut_54000000-0000-4000-8000-00000000{ordinal:04d}"
        receipt = f"egr_54000000-0000-4000-8000-00000000{ordinal:04d}"
        commitment = "hmac-sha256:" + "6" * 64
        if self.fail_always or (_REQUESTED in items and self.fail_with_output):
            return SemanticEgressProviderOutcome(
                request_id=candidate.request_id,
                privacy_proposal_id=proposal,
                authorization_id=authorization,
                dispatch_kind=SemanticDispatchKind.EXTERNAL,
                result=SemanticResultUnavailable(
                    _provenance(
                        binding,
                        status=SemanticStatus.UNAVAILABLE,
                        failure_class=SemanticFailureClass.TRANSPORT,
                    )
                ),
                case_digest=digest,
                privacy_receipt_id=receipt,
                request_commitment=commitment,
            )
        room_cut = frozenset({_REQUESTED} if ordinal <= self.room_cuts else ())
        disclosure = review_packet_disclosure_result(_sent_packet(candidate, room_cut)).disclosure
        assert disclosure is not None and disclosure.provider_input_manifest is not None
        judgment = (
            SemanticJudgment("no_material_discrepancy", (), review_summary="The run is shown.")
            if _REQUESTED in items - room_cut
            else SemanticJudgment(
                "insufficient_packet",
                (),
                missing_for_assessment=(
                    MissingForAssessment(
                        "verification_output", (str(res(1)),), "The first failure's output."
                    ),
                ),
                review_summary="The first failing run's output is not in the packet.",
            )
        )
        return SemanticEgressSuccess(
            request_id=candidate.request_id,
            privacy_proposal_id=proposal,
            authorization_id=authorization,
            dispatch_kind=SemanticDispatchKind.EXTERNAL,
            result=SemanticResultSuccess(
                judgment,
                _provenance(binding, status=SemanticStatus.SUCCEEDED, failure_class=None),
            ),
            case_digest=digest,
            privacy_receipt_id=receipt,
            request_commitment=commitment,
            disclosure=disclosure,
        )


def _plan(case: DeterministicCase, first: FinalSemanticEvaluation) -> ReviewFollowUp:
    follow_up = plan_review_follow_up(
        case.projection,
        frozenset(str(ref) for ref in case.allowed_ids),
        (
            MissingForAssessmentItem(
                "verification_output", (str(res(1)),), "yoetz_limit_packet_room"
            ),
        ),
        previous=None,
        shown_refs=first.case_excerpt_refs,
    )
    assert follow_up is not None
    return follow_up


async def _setup(
    adapter: MemoryLedgerAdapter | SqliteLedger,
    *,
    fail_with_output: bool = False,
    fail_always: bool = False,
    filler: int = 70,
    room_cuts: int = 0,
) -> tuple[DeterministicCase, FrozenCase, TaskRuntime, _ReviewerPrivacy, _FollowUpEvaluator]:
    durable, runtime = await _durable_semantic_case(adapter)
    # 70 newer output rows push the superseded first run past the Expanded 64-excerpt count.
    built, _refs = _verification_case(filler)
    # The durable lease froze its own one-event frontier; read the same rows at it (their order
    # then falls back to their ids, which number them in the same order).
    frontier = durable.lease.frontier
    projection = built.projection
    case = replace(
        built,
        frontier=frontier,
        projection=replace(
            projection,
            frontier=frontier.sequence,
            head_digest=frontier.head_digest,
            actions={
                key: replace(row, source_frontier=frontier.sequence)
                for key, row in projection.actions.items()
            },
            results={
                key: replace(row, source_frontier=frontier.sequence)
                for key, row in projection.results.items()
            },
            evidence={
                key: replace(row, source_frontier=frontier.sequence)
                for key, row in projection.evidence.items()
            },
            claims={
                key: replace(row, source_frontier=frontier.sequence)
                for key, row in projection.claims.items()
            },
        ),
    )
    privacy = _ReviewerPrivacy(
        task_id=runtime.task_id,
        fail_with_output=fail_with_output,
        fail_always=fail_always,
        room_cuts=room_cuts,
    )
    # The paired harness needs only the coordinator's evaluate/resume surface.
    evaluator = cast(
        _FollowUpEvaluator,
        _paired_evaluator(cast(Any, privacy), runtime, fallback_binding=None),
    )
    return case, FrozenCase(case, durable.lease), runtime, privacy, evaluator


@pytest.mark.anyio
@pytest.mark.parametrize(
    "adapter_factory",
    (memory_adapter, sqlite_adapter),
    ids=("memory", "sqlite"),
)
async def test_a_follow_up_round_is_its_own_durable_job_and_replays_without_dispatch(
    adapter_factory: Callable[[object], MemoryLedgerAdapter | SqliteLedger],
) -> None:
    adapter = adapter_factory(append_command())
    case, frozen, runtime, privacy, evaluator = await _setup(adapter)

    first = await evaluator(frozen, (), runtime)
    assert first is not None and first.status is SemanticStatus.SUCCEEDED
    assert first.judgment is not None and first.judgment.conclusion == "insufficient_packet"
    assert first.case_excerpt_refs is not None and str(evd(1)) not in first.case_excerpt_refs
    assert first.operation_lease is not None
    follow_up = _plan(case, first)

    second = await evaluator(
        FrozenCase(case, first.operation_lease), (), runtime, follow_up=follow_up
    )

    assert second is not None
    assert (second.status, second.reason) == (
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
    )
    assert second.judgment is not None and second.judgment.conclusion == "no_material_discrepancy"
    assert privacy.calls == 2
    (first_digest, first_items), (second_digest, second_items) = privacy.sent
    assert _REQUESTED not in first_items and _REQUESTED in second_items
    assert first_digest != second_digest
    assert str(evd(1)) in follow_up.added_by(second.case_excerpt_refs or ())
    manifest = second.review_input_manifest
    assert manifest is not None and manifest.follow_up_round == 1
    assert [row.status for row in manifest.missing_inputs] == ["supplied"]
    # One job per case the check sent, each found again by its own case digest.
    writer, operation = frozen.lease.writer_id, frozen.lease.operation_id
    base = await adapter.load_semantic_job(writer, operation, case_digest=first_digest)
    round_job = await adapter.load_semantic_job(writer, operation, case_digest=second_digest)
    assert base is not None and round_job is not None
    assert base.job_id != round_job.job_id
    assert (base.state, round_job.state) == ("succeeded", "succeeded")

    # Replay of the same request: the first review and the round recover, nothing is sent.
    assert second.operation_lease is not None
    replay = FrozenCase(case, second.operation_lease)
    again_first = await evaluator(replay, (), runtime)
    assert again_first is not None and again_first.judgment == first.judgment
    assert again_first.operation_lease is not None
    again_second = await evaluator(
        FrozenCase(case, again_first.operation_lease), (), runtime, follow_up=follow_up
    )
    assert again_second is not None and again_second.judgment == second.judgment
    assert privacy.calls == 2

    # A round that would add nothing new is never sent, and records nothing.
    assert again_second.operation_lease is not None
    spent = ReviewFollowUp(
        2,
        follow_up.items,
        follow_up.shown_refs,
        follow_up.added_by(second.case_excerpt_refs or ()),
    )
    nothing = await evaluator(
        FrozenCase(case, again_second.operation_lease), (), runtime, follow_up=spent
    )
    assert nothing is None
    assert privacy.calls == 2


@pytest.mark.anyio
@pytest.mark.parametrize(
    "adapter_factory",
    (memory_adapter, sqlite_adapter),
    ids=("memory", "sqlite"),
)
async def test_shown_and_added_are_what_the_sent_packets_carried_not_the_composed_case(
    adapter_factory: Callable[[object], MemoryLedgerAdapter | SqliteLedger],
) -> None:
    """An excerpt composed but left out of the sent packet for room was never shown (#1047).

    The first packet composes the first failing run's output, but the packet sent has no room for
    its row, so the reviewer asks for it: a round runs. That round's sent packet loses it too, so
    it is not counted as added and a later round still supplies it. Replay reads the same sets
    back from the durable responses.
    """

    adapter = adapter_factory(append_command())
    # 20 newer output rows leave the first run inside the 64-excerpt count: it is composed.
    case, frozen, runtime, privacy, evaluator = await _setup(adapter, filler=20, room_cuts=2)

    first = await evaluator(frozen, (), runtime)
    assert first is not None and first.judgment is not None
    assert first.judgment.conclusion == "insufficient_packet"
    ((_digest, first_items),) = privacy.sent
    assert _REQUESTED in first_items
    assert first.case_excerpt_refs is not None
    assert {str(res(1)), str(evd(2))} <= first.case_excerpt_refs
    assert str(evd(1)) not in first.case_excerpt_refs
    follow_up = _plan(case, first)
    assert first.operation_lease is not None

    second = await evaluator(
        FrozenCase(case, first.operation_lease), (), runtime, follow_up=follow_up
    )

    assert second is not None and second.judgment is not None
    assert privacy.calls == 2 and _REQUESTED in privacy.sent[1][1]
    assert second.judgment.conclusion == "insufficient_packet"
    added = follow_up.added_by(second.case_excerpt_refs or ())
    assert str(evd(1)) not in added
    manifest = second.provider_input_manifest
    assert manifest is not None
    assert [row["status"] for row in cast(Any, manifest["missing_inputs"])] == ["pending"]
    later = plan_review_follow_up(
        case.projection,
        frozenset(str(ref) for ref in case.allowed_ids),
        (
            MissingForAssessmentItem(
                "verification_output", (str(res(1)),), "yoetz_limit_packet_room"
            ),
        ),
        previous=replace(follow_up, added_refs=follow_up.added_refs | added),
        shown_refs=second.case_excerpt_refs,
    )
    assert later is not None and later.round == 2
    assert second.operation_lease is not None

    third = await evaluator(FrozenCase(case, second.operation_lease), (), runtime, follow_up=later)

    assert third is not None and third.judgment is not None
    assert third.judgment.conclusion == "no_material_discrepancy"
    assert privacy.calls == 3
    assert str(evd(1)) in later.added_by(third.case_excerpt_refs or ())

    # Replay recovers each review and the same carried sets without another provider call.
    assert third.operation_lease is not None
    again = await evaluator(FrozenCase(case, third.operation_lease), (), runtime)
    assert again is not None and again.case_excerpt_refs == first.case_excerpt_refs
    assert again.operation_lease is not None
    again_second = await evaluator(
        FrozenCase(case, again.operation_lease), (), runtime, follow_up=follow_up
    )
    assert again_second is not None
    assert again_second.case_excerpt_refs == second.case_excerpt_refs
    assert privacy.calls == 3


@pytest.mark.anyio
async def test_no_follow_up_is_sent_before_the_check_has_a_review_of_its_own() -> None:
    adapter = memory_adapter(append_command())
    case, frozen, runtime, privacy, evaluator = await _setup(adapter)
    shown_nothing = plan_review_follow_up(
        case.projection,
        frozenset(str(ref) for ref in case.allowed_ids),
        (
            MissingForAssessmentItem(
                "verification_output", (str(res(1)),), "yoetz_limit_packet_room"
            ),
        ),
        previous=None,
        shown_refs=frozenset(),
    )
    assert shown_nothing is not None
    assert await evaluator(frozen, (), runtime, follow_up=shown_nothing) is None
    assert privacy.calls == 0
    assert (
        await adapter.load_semantic_job(frozen.lease.writer_id, frozen.lease.operation_id) is None
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "adapter_factory",
    (memory_adapter, sqlite_adapter),
    ids=("memory", "sqlite"),
)
async def test_a_failed_follow_up_round_ends_like_a_failed_first_review(
    adapter_factory: Callable[[object], MemoryLedgerAdapter | SqliteLedger],
) -> None:
    adapter = adapter_factory(append_command())
    case, frozen, runtime, privacy, evaluator = await _setup(adapter, fail_with_output=True)
    first = await evaluator(frozen, (), runtime)
    assert first is not None and first.operation_lease is not None

    failed = await evaluator(
        FrozenCase(case, first.operation_lease), (), runtime, follow_up=_plan(case, first)
    )

    # Today's first review failing the same way, in a check of its own.
    reference_adapter = adapter_factory(append_command())
    (
        _case,
        reference_frozen,
        reference_runtime,
        reference_privacy,
        reference_evaluator,
    ) = await _setup(reference_adapter, fail_always=True)
    reference = await reference_evaluator(reference_frozen, (), reference_runtime)
    assert reference is not None

    # The round spends the same retry budget and ends in the same terminal state, with no
    # judgment: the check records it exactly as it records that failed first review.
    assert failed is not None
    assert (failed.status, failed.reason) == (reference.status, reference.reason)
    assert (failed.status, failed.reason) == (
        SemanticStatus.UNAVAILABLE,
        SemanticReason.RETRY_BUDGET_EXHAUSTED,
    )
    assert failed.judgment is None and reference.judgment is None
    calls = cast(int, getattr(privacy, "calls"))
    reference_calls = cast(int, getattr(reference_privacy, "calls"))
    assert calls - 1 == reference_calls == 3
    assert failed.review_input_manifest is not None
    assert failed.review_input_manifest.follow_up_round == 1
