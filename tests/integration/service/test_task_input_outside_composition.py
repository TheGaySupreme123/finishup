"""An unadmitted outside task input through the real composition and every surface (#1102).

RC6f: outside-input roots were configured in none of the pilot's trials, so a task file outside
the workspace never reached the reviewer and nothing said so. The check-time read now decides,
against its own root, whether the task names an existing input outside the workspace that no
admitted root covers, and freezes that closed yes or no into the job's check-change object. The
composition turns it into the coverage code ``task_input_outside_not_admitted``, which reaches
the packet, the check's coverage, the CLI, the MCP summary and the receipt as one fixed sentence
naming the owner's step. No surface, counter or log names a path.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

import finishup.service.ready_composition as ready_composition_module
import integration.service.test_semantic_fallback_dispatch as fallback
import integration.service.test_semantic_non_dispatch as non_dispatch
from builders.ledger_adapters import FixedClock, append_command, memory_adapter, sqlite_adapter
from builders.policy_cases import evd, evt
from finishup.adapters.memory.ledger import MemoryLedgerAdapter
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.application.check import FinalSemanticEvaluation
from finishup.application.check_change import CheckChangeOutcome
from finishup.application.egress import SemanticEgressSuccess
from finishup.application.semantic_case import (
    CheckTimeChange,
    assemble_filtered_review_packet,
    review_packet_disclosure_result,
)
from finishup.application.semantic_content import CapturedContentResolution
from finishup.domain.findings import SemanticDispatchKind
from finishup.domain.privacy import (
    REVIEW_PACKET_ITEM_ID,
    CandidateContext,
    ProviderBinding,
    ReviewContextProfile,
)
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
    TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP,
    TASK_INPUT_OUTSIDE_NOT_ADMITTED_SHORT_SENTENCE,
    check_time_change_gap_sentence,
    check_time_change_unavailable_reason_gap,
    receipt_document_to_json,
    render_receipt_human,
)
from finishup.domain.task_statement import RecordedTaskStatement
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.ports.ledger import FrozenCase
from finishup.ports.runtime import TaskRuntime
from finishup.ports.semantic import MissingForAssessment, SemanticJudgment, SemanticResultSuccess
from finishup.protocol.canonical import strict_json_parse
from finishup.protocol.models import SemanticStatus


# Moved here from the retired in-check follow-up composition tests (#1047, #1118).
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


_CURRENT_MARKER = b"CURRENT_LEAD_STORE_MARKER"


class _CurrentSectionPrivacy(non_dispatch._Privacy):  # pyright: ignore[reportPrivateUsage]
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
                fallback._provenance(  # pyright: ignore[reportPrivateUsage]
                    binding, status=SemanticStatus.SUCCEEDED, failure_class=None
                ),
            ),
            case_digest=digest,
            privacy_receipt_id=f"egr_56000000-0000-4000-8000-00000000{ordinal:04d}",
            request_commitment="hmac-sha256:" + "6" * 64,
            disclosure=disclosure,
        )


async def _resolve_primary() -> ProviderBinding | None:
    return non_dispatch._PROVIDER  # pyright: ignore[reportPrivateUsage]


_CODE = TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP
_SENTENCE = check_time_change_gap_sentence(_CODE)
_OWNER_STEP = "finishup privacy input-roots add <folder>"
_durable_semantic_case = non_dispatch._durable_semantic_case  # pyright: ignore[reportPrivateUsage]

type _Evaluator = Callable[..., Awaitable[FinalSemanticEvaluation | None]]


class _PacketPrivacy(_CurrentSectionPrivacy):
    """Concludes on a packet that carries the current section, keeping each packet's bytes."""

    def __init__(self, *, task_id: str) -> None:
        super().__init__(task_id=task_id)
        self.packets: list[bytes] = []

    async def evaluate_semantic(self, candidate: object, deadline: object) -> object:
        assert type(candidate) is CandidateContext
        self.packets.extend(
            item.plaintext for item in candidate.items if item.item_id == REVIEW_PACKET_ITEM_ID
        )
        return await super().evaluate_semantic(candidate, deadline)


async def _composition(
    adapter: MemoryLedgerAdapter | SqliteLedger,
    monkeypatch: pytest.MonkeyPatch,
    *,
    flagged: bool,
    statement: str | None = None,
    captures: list[Mapping[str, object]] | None = None,
) -> tuple[FrozenCase, TaskRuntime, _PacketPrivacy, _Evaluator, list[Mapping[str, object]]]:
    from unit.application.test_review_follow_up import (
        _stale_edit_case,  # pyright: ignore[reportPrivateUsage]
    )

    built, captured, scope, change = _stale_edit_case(lead_first=True)
    change = CheckTimeChange(
        change.object_ref,
        replace(change.capture, base_commit="a" * 40, outside_inputs_not_admitted=flagged),
    )
    counts: list[Mapping[str, object]] = []
    recorded = ready_composition_module.record_bounded_counts_without_raising

    def record(**kwargs: Any) -> str:
        if kwargs.get("operation") == "semantic_case_built":
            counts.append(cast(Mapping[str, object], kwargs["counts"]))
        return recorded(**kwargs)

    async def resolve(**kwargs: object) -> CapturedContentResolution:
        del kwargs
        return CapturedContentResolution(scope=scope, content=captured, gaps=())

    def workspace(runtime: TaskRuntime) -> str:
        del runtime
        return scope.workspace_commitment

    async def capture(**kwargs: object) -> CheckChangeOutcome:
        # The service hands the read its admitted roots, so the read can decide.
        assert kwargs["admitted_roots"] == ()
        if captures is not None:
            captures.append(kwargs)
        return CheckChangeOutcome(change=change)

    async def recover(runtime: object, binding: object) -> CheckChangeOutcome:
        del runtime, binding
        return CheckChangeOutcome(change=change)

    monkeypatch.setattr(ready_composition_module, "record_bounded_counts_without_raising", record)
    monkeypatch.setattr(ready_composition_module, "_observation_workspace_for_runtime", workspace)
    monkeypatch.setattr(ready_composition_module, "resolve_captured_semantic_content", resolve)
    monkeypatch.setattr(ready_composition_module, "capture_check_time_change", capture)
    monkeypatch.setattr(ready_composition_module, "recover_check_time_change", recover)
    monkeypatch.setattr(
        ready_composition_module,
        "current_check_workspace_source",
        # The check's workspace source names its workspace; the outside read excludes it (#1118
        # unit 1). The capture itself is faked above, so the path is never opened.
        lambda: SimpleNamespace(workspace="/finishup-test-workspace"),
    )
    durable, runtime = await _durable_semantic_case(adapter)
    case = _at_lease_frontier(built, durable)
    if statement is not None:
        case = replace(
            case,
            task_statement=RecordedTaskStatement(
                text=statement,
                source_event_id=evt(1),
                source_family="session_opened",
                ingestion_sequence=case.frontier.sequence,
            ),
        )
    privacy = _PacketPrivacy(task_id=runtime.task_id)
    factory = cast(
        "Callable[..., _Evaluator]",
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
    return FrozenCase(case, durable.lease), runtime, privacy, evaluator, counts


@pytest.mark.anyio
@pytest.mark.parametrize(
    "adapter_factory",
    (memory_adapter, sqlite_adapter),
    ids=("memory", "sqlite"),
)
async def test_a_task_naming_an_unadmitted_outside_file_records_the_owner_step_code(
    adapter_factory: Callable[[object], MemoryLedgerAdapter | SqliteLedger],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = adapter_factory(append_command())
    frozen, runtime, privacy, evaluator, counts = await _composition(
        adapter, monkeypatch, flagged=True
    )

    first = await evaluator(frozen, (), runtime)

    assert first is not None and first.judgment is not None
    assert first.judgment.conclusion == "no_material_discrepancy"
    assert _CODE in first.case_content_gaps
    # The packet carries the closed code, so the reviewer's glossary explains it.
    ((packet),) = privacy.packets
    assert _CODE.encode() in packet
    # The pilot counter reads the frozen decision; every counter is an integer.
    ((built),) = counts
    assert built["semantic_task_inputs_outside_not_admitted"] == 1
    assert all(
        type(value) is int for key, value in built.items() if key.startswith("semantic_task")
    )

    # Replay recovers the same case from the frozen object without another provider call.
    assert first.operation_lease is not None
    again = await evaluator(FrozenCase(frozen.case, first.operation_lease), (), runtime)
    assert again is not None and again.judgment == first.judgment
    assert again.case_content_gaps == first.case_content_gaps
    assert len(privacy.packets) == 1


@pytest.mark.anyio
async def test_an_object_frozen_without_the_flag_records_no_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A job an earlier build froze never wrote the flag; its recovered case is unchanged."""

    frozen, runtime, _privacy, evaluator, counts = await _composition(
        memory_adapter(append_command()), monkeypatch, flagged=False
    )

    first = await evaluator(frozen, (), runtime)

    assert first is not None and _CODE not in first.case_content_gaps
    assert counts[0]["semantic_task_inputs_outside_not_admitted"] == 0


@pytest.mark.anyio
async def test_the_service_hands_the_read_the_words_the_spaces_cut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PR #1112 review: without this set the read drops no word, so ``/shared/test`` would be
    read under the task's name beside ``/shared/test data``; a path named alone is never in it."""

    captures: list[Mapping[str, object]] = []
    frozen, runtime, _privacy, evaluator, _counts = await _composition(
        memory_adapter(append_command()),
        monkeypatch,
        flagged=False,
        statement="Summarise the CSVs in '/shared/test data' and read Notes.md for /app/out.md.",
        captures=captures,
    )

    await evaluator(frozen, (), runtime)

    ((kwargs),) = captures
    assert kwargs["space_cut_paths"] == frozenset({"/shared/test"})
    inputs = cast("tuple[str, ...]", kwargs["input_paths"])
    assert {"/shared/test data", "/shared/test", "Notes.md"} <= set(inputs)


def test_every_surface_renders_the_owner_step_and_no_path() -> None:
    """CLI, MCP and the receipt (JSON, markdown, text) print the fixed sentence beside any other
    check-time code, and the MCP text never names a path (review r1-7, surfaces-r1-7)."""

    from finishup.cli.render import render_human_check
    from finishup.kernel.deterministic_checks import CaseGap
    from finishup.mcp.summaries import summary_for_check
    from finishup.protocol.models import CheckSuccessModel
    from unit.kernel.test_receipt_builder import (
        _build,  # pyright: ignore[reportPrivateUsage]
        _context,  # pyright: ignore[reportPrivateUsage]
        _coverage,  # pyright: ignore[reportPrivateUsage]
    )

    assert _SENTENCE is not None and _OWNER_STEP in _SENTENCE
    companions = (
        CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
        check_time_change_unavailable_reason_gap("not_git"),
    )
    for gaps in ((_CODE,), (*companions, _CODE)):
        summary = summary_for_check(
            {"verdict": "insufficient_coverage", "coverage": {"known_gaps": list(gaps)}}
        )
        assert _SENTENCE in summary or TASK_INPUT_OUTSIDE_NOT_ADMITTED_SHORT_SENTENCE in summary
        assert _OWNER_STEP in summary
        assert "/shared" not in summary and "/app" not in summary
        check = CheckSuccessModel.model_construct(
            verdict="insufficient_coverage",
            semantic_status="succeeded",
            semantic_reason="semantic_completed",
            semantic_route_required=False,
            findings=(),
            review_mode=None,
            totals=None,
            observations_awaited=None,
            review_input_manifest=None,
            semantic_provenance=None,
            suppressed_count=0,
            coverage=SimpleNamespace(known_gaps=gaps),
        )
        assert _SENTENCE in render_human_check(check)

    # The receipt helper's context records no check, so it carries ``check_not_recorded`` too.
    context = _context(
        coverage=replace(_coverage(), known_gaps=("check_not_recorded", _CODE)),
        gaps=(
            CaseGap("check_not_recorded", "check_not_recorded", ()),
            CaseGap(_CODE, _CODE, ()),
        ),
    )
    receipt = _build(context)
    assert _SENTENCE in str(receipt_document_to_json(receipt))
    assert _SENTENCE in render_receipt_human(receipt, markdown=True)
    assert _SENTENCE in render_receipt_human(receipt, markdown=False)
