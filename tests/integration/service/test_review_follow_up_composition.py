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
from types import SimpleNamespace
from typing import Any, cast

import pytest

import finishup.application.check_change as check_change_module
import finishup.service.ready_composition as ready_composition_module
import integration.service.test_semantic_fallback_dispatch as fallback
import integration.service.test_semantic_non_dispatch as non_dispatch
from builders.ledger_adapters import FixedClock, append_command, memory_adapter, sqlite_adapter
from builders.policy_cases import evd, res
from finishup.adapters.memory.ledger import MemoryLedgerAdapter
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.application.check import (
    FinalSemanticEvaluation,
    _review_follow_up,  # pyright: ignore[reportPrivateUsage]
)
from finishup.application.egress import SemanticEgressProviderOutcome, SemanticEgressSuccess
from finishup.application.missing_for_assessment import ReviewFollowUp, plan_review_follow_up
from finishup.application.semantic_case import (
    CheckTimeChange,
    assemble_filtered_review_packet,
    review_packet_disclosure_result,
)
from finishup.application.semantic_content import CapturedContentResolution
from finishup.domain.events import MissingForAssessmentItem
from finishup.domain.findings import SemanticDispatchKind, SemanticFailureClass
from finishup.domain.privacy import (
    REVIEW_PACKET_ITEM_ID,
    CandidateContext,
    ProviderBinding,
    ReviewContextProfile,
)
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.ports.ledger import FrozenCase
from finishup.ports.objects import ObjectKind
from finishup.ports.runtime import TaskRuntime
from finishup.ports.semantic import (
    MissingForAssessment,
    SemanticJudgment,
    SemanticResultSuccess,
    SemanticResultUnavailable,
)
from finishup.protocol.canonical import strict_json_parse
from finishup.protocol.models import SemanticReason, SemanticStatus
from unit.application.test_review_follow_up import (
    _captured_group_case,  # pyright: ignore[reportPrivateUsage]
    _verification_case,  # pyright: ignore[reportPrivateUsage]
)

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
        shown_parts=first.case_excerpt_parts,
    )
    assert follow_up is not None
    return follow_up


def _at_lease_frontier(built: DeterministicCase, durable: FrozenCase) -> DeterministicCase:
    """``built`` read at the durable lease's own one-event frontier.

    The rows' order then falls back to their ids, which number them in the same order.
    """

    frontier = durable.lease.frontier
    projection = built.projection
    return replace(
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
            obligations={
                key: replace(row, source_frontier=frontier.sequence)
                for key, row in projection.obligations.items()
            },
            plans={
                key: replace(row, source_frontier=frontier.sequence)
                for key, row in projection.plans.items()
            },
        ),
    )


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
    case = _at_lease_frontier(built, durable)
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
    # tb4n5: what the sent packet carried, part by part, read from the same provider manifest.
    assert first.case_excerpt_parts is not None
    assert not any(key.startswith(f"{evd(1)}#") for key in first.case_excerpt_parts)
    assert first.operation_lease is not None
    follow_up = _plan(case, first)
    assert follow_up.shown_parts == first.case_excerpt_parts

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
    assert any(
        key.startswith(f"{evd(1)}#") for key in follow_up.unseen(second.case_excerpt_parts or ())
    )
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
    # Structural progress describes the round the check records, read from its case object.
    progress = await adapter.load_semantic_progress(writer, operation)
    assert progress is not None and progress.job_id == round_job.job_id

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


_LEAD, _PART = str(evd(20)), str(evd(21))
_GROUP = f"excerpt-{_LEAD}"


class _GroupWithholdingPrivacy(_Privacy):
    """Its sent packets withhold a captured group's excerpt under the never-send heuristic.

    The omission row names the group by its lead alone; the reviewer asks for the second part.
    """

    def __init__(self, *, task_id: str) -> None:
        super().__init__(task_id=task_id, profile=ReviewContextProfile.EXPANDED)
        self.offered: list[frozenset[str]] = []

    async def evaluate_semantic(self, candidate: object, deadline: object) -> object:
        del deadline
        assert type(candidate) is CandidateContext
        self.calls += 1
        content = {item.item_id: item.plaintext for item in candidate.items}
        self.offered.append(frozenset(content))
        envelope = strict_json_parse(content.pop(REVIEW_PACKET_ITEM_ID))
        assert isinstance(envelope, dict)
        held = frozenset({_GROUP}) & frozenset(content)
        sent = {item_id: text for item_id, text in content.items() if item_id not in held}
        disclosure = review_packet_disclosure_result(
            assemble_filtered_review_packet(
                envelope,
                content_by_id=sent,
                included_item_ids=frozenset(sent),
                withheld_item_ids=held,
            )
        ).disclosure
        assert disclosure is not None
        binding = cast(ProviderBinding, candidate.provider_binding)
        digest = candidate.subject_digest
        assert digest is not None
        ordinal = self.calls
        return SemanticEgressSuccess(
            request_id=candidate.request_id,
            privacy_proposal_id=f"ppr_55000000-0000-4000-8000-00000000{ordinal:04d}",
            authorization_id=f"aut_55000000-0000-4000-8000-00000000{ordinal:04d}",
            dispatch_kind=SemanticDispatchKind.EXTERNAL,
            result=SemanticResultSuccess(
                SemanticJudgment(
                    "insufficient_packet",
                    (),
                    missing_for_assessment=(
                        MissingForAssessment(
                            "verification_output", (_PART,), "The capture's second part."
                        ),
                    ),
                    review_summary="The captured output is not in the packet.",
                ),
                _provenance(binding, status=SemanticStatus.SUCCEEDED, failure_class=None),
            ),
            case_digest=digest,
            privacy_receipt_id=f"egr_55000000-0000-4000-8000-00000000{ordinal:04d}",
            request_commitment="hmac-sha256:" + "6" * 64,
            disclosure=disclosure,
            withheld_item_ids=tuple(held),
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "adapter_factory",
    (memory_adapter, sqlite_adapter),
    ids=("memory", "sqlite"),
)
async def test_a_privacy_withheld_captured_group_is_withheld_whichever_part_is_named(
    adapter_factory: Callable[[object], MemoryLedgerAdapter | SqliteLedger],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The evaluation names every part of a group its sent packet withheld (#1047).

    The packet's omission row names the group by its lead; the check still reads a request for
    the second part as the same privacy limit, live and on recovery, and sends no round for it.
    """

    built, captured, scope = _captured_group_case(newer=0)

    async def resolve(**kwargs: object) -> CapturedContentResolution:
        del kwargs
        return CapturedContentResolution(scope=scope, content=captured, gaps=())

    def workspace(runtime: TaskRuntime) -> str:
        del runtime
        return scope.workspace_commitment

    # The group's retained parts, as the observation store would resolve them for this task.
    monkeypatch.setattr(ready_composition_module, "_observation_workspace_for_runtime", workspace)
    monkeypatch.setattr(ready_composition_module, "resolve_captured_semantic_content", resolve)
    adapter = adapter_factory(append_command())
    durable, runtime = await _durable_semantic_case(adapter)
    case = _at_lease_frontier(built, durable)
    privacy = _GroupWithholdingPrivacy(task_id=runtime.task_id)
    evaluator = cast(
        _FollowUpEvaluator,
        _paired_evaluator(cast(Any, privacy), runtime, fallback_binding=None),
    )

    async def evaluate_semantic_check(
        frozen: FrozenCase,
        deterministic_findings: tuple[object, ...],
        runtime: TaskRuntime | None = None,
        lineage_evaluation: object | None = None,
        follow_up: ReviewFollowUp | None = None,
    ) -> FinalSemanticEvaluation | None:
        del lineage_evaluation
        return await evaluator(frozen, deterministic_findings, runtime, follow_up=follow_up)

    app = SimpleNamespace(evaluate_semantic_check=evaluate_semantic_check)
    request = SimpleNamespace(final_review=False, request_id=durable.lease.operation_id)

    async def loop(result: FinalSemanticEvaluation) -> object:
        assert result.operation_lease is not None
        return await _review_follow_up(
            cast(Any, app),
            cast(Any, request),
            runtime,
            FrozenCase(case, result.operation_lease),
            (),
            result,
            lineage_evaluation=None,
            require_complete_specification=False,
            task_fact_gaps=(),
        )

    first = await evaluator(FrozenCase(case, durable.lease), (), runtime)

    assert first is not None and first.status is SemanticStatus.SUCCEEDED
    assert privacy.calls == 1 and _GROUP in privacy.offered[0]
    assert {_LEAD, _PART} <= first.case_privacy_withheld_refs
    assert first.case_excerpt_refs is not None
    assert not {_LEAD, _PART} & first.case_excerpt_refs
    assert await loop(first) is first
    assert privacy.calls == 1

    # Recovery reads the same refs back from the durable response, over the same case.
    assert first.operation_lease is not None
    again = await evaluator(FrozenCase(case, first.operation_lease), (), runtime)
    assert again is not None and again.judgment == first.judgment
    assert again.case_privacy_withheld_refs == first.case_privacy_withheld_refs
    assert await loop(again) is again
    assert privacy.calls == 1


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


_CURRENT_MARKER = b"CURRENT_LEAD_STORE_MARKER"


class _CurrentSectionPrivacy(_Privacy):
    """A reviewer that needs the current ``leadStore.ts`` (tb4n5 react-lead-form).

    It asks for the current diff of the stale edit that first added the file until a packet
    carries the file's current content, then concludes. Every packet is sent whole.
    """

    def __init__(self, *, task_id: str) -> None:
        super().__init__(task_id=task_id, profile=ReviewContextProfile.EXPANDED)
        self.sent: list[frozenset[str]] = []

    async def evaluate_semantic(self, candidate: object, deadline: object) -> object:
        del deadline
        assert type(candidate) is CandidateContext
        self.calls += 1
        content = {item.item_id: item.plaintext for item in candidate.items}
        envelope = strict_json_parse(content.pop(REVIEW_PACKET_ITEM_ID))
        assert isinstance(envelope, dict)
        self.sent.append(frozenset(content))
        disclosure = review_packet_disclosure_result(
            assemble_filtered_review_packet(
                envelope, content_by_id=content, included_item_ids=frozenset(content)
            )
        ).disclosure
        assert disclosure is not None and disclosure.provider_input_manifest is not None
        binding = cast(ProviderBinding, candidate.provider_binding)
        digest = candidate.subject_digest
        assert digest is not None
        ordinal = self.calls
        judgment = (
            SemanticJudgment("no_material_discrepancy", (), review_summary="The store is shown.")
            if any(_CURRENT_MARKER in text for text in content.values())
            else SemanticJudgment(
                "insufficient_packet",
                (),
                missing_for_assessment=(
                    MissingForAssessment(
                        "current_diff_for_path", (str(evd(1)),), "The current ledger store."
                    ),
                ),
                review_summary="Only a stale edit of the ledger store is in the packet.",
            )
        )
        return SemanticEgressSuccess(
            request_id=candidate.request_id,
            privacy_proposal_id=f"ppr_56000000-0000-4000-8000-00000000{ordinal:04d}",
            authorization_id=f"aut_56000000-0000-4000-8000-00000000{ordinal:04d}",
            dispatch_kind=SemanticDispatchKind.EXTERNAL,
            result=SemanticResultSuccess(
                judgment,
                _provenance(binding, status=SemanticStatus.SUCCEEDED, failure_class=None),
            ),
            case_digest=digest,
            privacy_receipt_id=f"egr_56000000-0000-4000-8000-00000000{ordinal:04d}",
            request_commitment="hmac-sha256:" + "6" * 64,
            disclosure=disclosure,
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "adapter_factory",
    (memory_adapter, sqlite_adapter),
    ids=("memory", "sqlite"),
)
async def test_a_current_section_round_is_durable_recorded_and_replays_without_dispatch(
    adapter_factory: Callable[[object], MemoryLedgerAdapter | SqliteLedger],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tb4n5 react-lead-form, end to end: the round answers a stale edit's current-diff request
    with the current section from the frozen change, records that file as shown, and replays
    from the durable jobs without another provider call (checker review)."""

    from finishup.application.check_change import CheckChangeOutcome
    from finishup.application.semantic_case import CHECK_TIME_SECTION_ITEM_PREFIX
    from unit.application.test_review_follow_up import (
        _LEAD,  # pyright: ignore[reportPrivateUsage]
        _stale_edit_case,  # pyright: ignore[reportPrivateUsage]
    )

    built, captured, scope, change = _stale_edit_case()
    change = CheckTimeChange(change.object_ref, replace(change.capture, base_commit="a" * 40))
    captures: list[str] = []

    async def resolve(**kwargs: object) -> CapturedContentResolution:
        del kwargs
        return CapturedContentResolution(scope=scope, content=captured, gaps=())

    def workspace(runtime: TaskRuntime) -> str:
        del runtime
        return scope.workspace_commitment

    async def capture(**kwargs: object) -> CheckChangeOutcome:
        del kwargs
        captures.append("captured")
        return CheckChangeOutcome(change=change)

    async def recover(runtime: object, binding: object) -> CheckChangeOutcome:
        del runtime, binding
        return CheckChangeOutcome(change=change)

    monkeypatch.setattr(ready_composition_module, "_observation_workspace_for_runtime", workspace)
    monkeypatch.setattr(ready_composition_module, "resolve_captured_semantic_content", resolve)
    monkeypatch.setattr(ready_composition_module, "capture_check_time_change", capture)
    monkeypatch.setattr(ready_composition_module, "recover_check_time_change", recover)
    monkeypatch.setattr(
        ready_composition_module, "current_check_workspace_source", lambda: object()
    )
    adapter = adapter_factory(append_command())
    durable, runtime = await _durable_semantic_case(adapter)
    case = _at_lease_frontier(built, durable)
    privacy = _CurrentSectionPrivacy(task_id=runtime.task_id)
    factory = cast(
        "Callable[..., _FollowUpEvaluator]",
        getattr(ready_composition_module, "_privacy_gated_semantic_evaluator"),
    )
    evaluator = factory(
        cast(Any, privacy),
        FixedClock(),
        non_dispatch._INSTALLATION,  # pyright: ignore[reportPrivateUsage]
        _resolve_primary,
        cast(
            Any,
            non_dispatch._Catalog(  # pyright: ignore[reportPrivateUsage]
                non_dispatch._route_for(  # pyright: ignore[reportPrivateUsage]
                    runtime.task_id, runtime.session_id
                )
            ),
        ),
        ready_composition_module.IdPort(),
        change_capture=object(),
    )

    async def evaluate_semantic_check(
        frozen: FrozenCase,
        deterministic_findings: tuple[object, ...],
        runtime: TaskRuntime | None = None,
        lineage_evaluation: object | None = None,
        follow_up: ReviewFollowUp | None = None,
    ) -> FinalSemanticEvaluation | None:
        del lineage_evaluation
        return await evaluator(frozen, deterministic_findings, runtime, follow_up=follow_up)

    app = SimpleNamespace(evaluate_semantic_check=evaluate_semantic_check)
    request = SimpleNamespace(final_review=False, request_id=durable.lease.operation_id)

    async def loop(result: FinalSemanticEvaluation) -> FinalSemanticEvaluation:
        assert result.operation_lease is not None
        final = await _review_follow_up(
            cast(Any, app),
            cast(Any, request),
            runtime,
            FrozenCase(case, result.operation_lease),
            (),
            result,
            lineage_evaluation=None,
            require_complete_specification=False,
            task_fact_gaps=(),
        )
        assert type(final) is FinalSemanticEvaluation
        return final

    first = await evaluator(FrozenCase(case, durable.lease), (), runtime)

    assert first is not None and first.judgment is not None
    assert first.judgment.conclusion == "insufficient_packet"
    assert first.case_current_section_parts is not None
    assert str(evd(1)) in first.case_current_section_parts
    final = await loop(first)

    assert privacy.calls == 2 and captures == ["captured"]
    assert [
        item_id for item_id in privacy.sent[1] if item_id.startswith(CHECK_TIME_SECTION_ITEM_PREFIX)
    ] == [f"{CHECK_TIME_SECTION_ITEM_PREFIX}011"]
    assert final.judgment is not None and final.judgment.conclusion == "no_material_discrepancy"
    manifest = final.provider_input_manifest
    assert manifest is not None
    assert [row["status"] for row in cast(Any, manifest["missing_inputs"])] == ["supplied"]
    # The served file is part of the record finding resolution compares (ADR-031 item 9).
    files = final.check_change_files
    first_files = first.check_change_files
    assert files is not None and files.complete
    assert first_files is not None and first_files.complete
    domain = cast(bytes, getattr(check_change_module, "_SHOWN_FILE_DOMAIN"))
    lead = await runtime.objects.commitment_for(
        domain + b"a" * 40 + b"\x00" + f"diff --git a/{_LEAD} b/{_LEAD}".encode(),
        ObjectKind.CHANGE_CAPTURE,
    )
    assert lead in files.fully_shown
    assert lead not in first_files.fully_shown and lead not in first_files.partial_files()
    # A repair review that showed only what the first packet showed never covers this one.
    assert not first_files.covers(files)

    # Replay of the same request: both reviews and the round recover; nothing is sent again.
    assert final.operation_lease is not None
    again = await evaluator(FrozenCase(case, final.operation_lease), (), runtime)
    assert again is not None and again.judgment == first.judgment
    replayed = await loop(again)
    assert replayed.judgment == final.judgment
    assert replayed.check_change_files == final.check_change_files
    assert privacy.calls == 2 and captures == ["captured"]


async def _resolve_primary() -> ProviderBinding | None:
    return _PROVIDER
