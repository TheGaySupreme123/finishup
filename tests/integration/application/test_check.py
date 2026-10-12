from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import yoetz.application.check as check_module
import yoetz.observability.diagnostics as diagnostics_module
from builders.ledger_adapters import FixedClock, MemoryObjects
from builders.policy_cases import (
    FRONTIER,
    act,
    claim_record,
    clm,
    evd,
    evidence_record,
    evt,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from yoetz.application.check import FinalSemanticEvaluation, check_internal_json
from yoetz.application.check import execute_check as _execute_check
from yoetz.application.check import execute_check_commit as _execute_check_commit
from yoetz.application.service import VerificationPolicy
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    CheckChangeShownFiles,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceKind,
    EvidenceRecordedPayload,
    MissingForAssessmentItem,
    NoObligationsReason,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.findings import (
    Finding,
    FindingKind,
    RankedFindings,
    SemanticDispatchKind,
    SemanticProvenance,
)
from yoetz.domain.receipts import (
    COMPLETION_SCOPE_DECLARED_NONE_GAP,
    COMPLETION_SCOPE_UNDECLARED_GAP,
    SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP,
)
from yoetz.domain.values import (
    ClaimId,
    EvidenceId,
    Frontier,
    JsonObject,
    disclosure_continuation,
    object_id,
    timestamp_from_string,
)
from yoetz.kernel import deterministic_checks as deterministic_checks_module
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.kernel.projections import (
    ClaimProjectionRecord,
    EvidenceProjectionRecord,
    PendingMissingForAssessment,
)
from yoetz.ports.change_capture import (
    ChangeMetadataEntry,
    CheckChangeCapture,
    CheckChangeMetadata,
    CheckWorkspaceSource,
)
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.ids import IdPort
from yoetz.ports.ledger import (
    CheckAwaitingHuman,
    CheckCommitResult,
    CheckPhase,
    CheckPolicyExecution,
    CheckVersionSlice,
    FrozenCase,
    OperationKind,
    OperationLease,
    OperationRecord,
    OperationState,
)
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from yoetz.ports.runtime import BundleRuntimePort, OwnershipFence, RouteCommand, TaskRuntime
from yoetz.ports.semantic import (
    MissingForAssessment,
    ReviewerChallenge,
    SamplingParams,
    SemanticJudgment,
)
from yoetz.protocol.coverage import EvidenceImmutability
from yoetz.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind
from yoetz.protocol.models import CheckRequest, CheckScopeModel, SemanticReason, SemanticStatus
from yoetz.protocol.redacted_values import SemanticRedactedValue

_TASK = "tsk_30000000-0000-4000-8000-000000000001"
_SESSION = "ses_30000000-0000-4000-8000-000000000001"
_WRITER = "wri_30000000-0000-4000-8000-000000000001"
_REQUEST = "req_30000000-0000-4000-8000-000000000001"


@pytest.fixture(autouse=True)
def work_has_begun(monkeypatch: pytest.MonkeyPatch) -> None:
    """These cases exercise the review path, so the work has begun in every frozen case.

    Issue #1046 defers the AI-powered review until the first material edit; that decision is
    locked by ``tests/unit/application/test_tb4n4_review_timing.py`` and
    ``tests/integration/application/test_tb4n4_review_before_first_edit.py``. The synthetic cases
    here carry no edit action, so without this every review below would be deferred.
    """

    def edited(*_args: object) -> bool:
        return True

    monkeypatch.setattr(check_module, "material_edit_recorded", edited)


class _Ids:
    def __init__(self) -> None:
        self.count = 0
        self.object_count = 0

    def new(self, kind: IdKind) -> str:
        if kind is IdKind.FINDING:
            self.count += 1
            return f"fnd_30000000-0000-4000-8000-{self.count:012x}"
        assert kind is IdKind.OBJECT
        self.object_count += 1
        return f"obj_30000000-0000-4000-8000-{self.object_count:012x}"


async def execute_check(*args: Any, **kwargs: Any) -> CheckCommitResult:
    """Narrow to the committed branch.

    execute_check also returns CheckAwaitingHuman when a check suspends on a local disclosure
    decision. Every test here drives a terminal outcome, so a suspension is a test-setup bug and
    should fail loudly rather than surface as an attribute error 140 lines later.
    """

    result = await _execute_check(*args, **kwargs)
    assert type(result) is CheckCommitResult, f"unexpected nonterminal check: {type(result)}"
    return result


async def execute_check_commit(*args: Any, **kwargs: Any) -> CheckCommitResult:
    """Narrow to the committed branch; see execute_check above."""

    result = await _execute_check_commit(*args, **kwargs)
    assert type(result) is CheckCommitResult, f"unexpected nonterminal check: {type(result)}"
    return result


def _case() -> FrozenCase:
    claim = ClaimRecordedPayload(clm(1), ClaimKind.MATERIAL, "Unsupported", ())
    deterministic = make_case(claims={clm(1): record(claim, 1)})
    return FrozenCase(
        deterministic,
        OperationLease(
            _WRITER,
            _REQUEST,
            _SESSION,
            CheckPhase.RESERVED,
            "owner-generation-1",
            "lease-owner-1",
            1,
            datetime(2030, 1, 1, tzinfo=UTC),
            FRONTIER,
            "sha256:" + "d" * 64,
        ),
    )


class _Ledger:
    def __init__(self, frozen: FrozenCase) -> None:
        self.frozen = frozen
        self.replay: CheckCommitResult | None = None
        self.failure: BaseException | None = None
        self.commit_count = 0
        self.commit_failure: Exception | None = None
        self.fail_count = 0
        self.phase_transitions: list[tuple[CheckPhase, CheckPhase]] = []
        self.last_ranked: RankedFindings | None = None
        self.last_executions: tuple[CheckPolicyExecution, ...] | None = None
        self.last_missing: tuple[MissingForAssessmentItem, ...] = ()
        self.last_conclusion: str | None = None
        self.last_review_summary: str | None = None
        self.last_verdicts: tuple[object, ...] = ()
        self.operation: OperationRecord | None = None

    async def load_events(
        self,
        session_id: str,
        *,
        after: int = 0,
        through: int | None = None,
    ) -> Any:
        del session_id, after, through
        if False:
            yield None

    async def freeze_case(self, *args: object) -> FrozenCase | CheckCommitResult:
        if self.failure is not None:
            raise self.failure
        if self.operation is None:
            lease = self.frozen.lease
            resume = ObjectRef(
                "obj_30000000-0000-4000-8000-00000000aaaa",
                1,
                "hmac-sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
                "yoetz-object/1",
                "bmk-1",
                ObjectMetadata(
                    ObjectKind.CHECK_RESUME,
                    "application/vnd.yoetz.check-resume+json",
                    _TASK,
                    datetime(2026, 1, 1, tzinfo=UTC),
                ),
            )
            self.operation = OperationRecord(
                _WRITER,
                _REQUEST,
                OperationKind.CHECK,
                cast(str, args[4]),
                OperationState.PENDING,
                CheckPhase.RESERVED,
                lease.owner_generation,
                lease.lease_owner_id,
                lease.lease_generation,
                lease.lease_expires_at,
                resume,
                None,
                None,
                None,
                None,
                None,
            )
        return self.frozen if self.replay is None else self.replay

    async def lookup_operation(self, writer_id: str, operation_id: str) -> OperationRecord | None:
        assert (writer_id, operation_id) == (_WRITER, _REQUEST)
        return self.operation

    async def lookup_task_operation(
        self, writer_id: str, operation_id: str
    ) -> OperationRecord | None:
        return await self.lookup_operation(writer_id, operation_id)

    async def advance_check_phase(
        self,
        lease: OperationLease,
        expected_phase: CheckPhase,
        next_phase: CheckPhase,
        durable_object_ref: object = None,
    ) -> OperationLease:
        assert lease == self.frozen.lease
        assert lease.phase is expected_phase
        assert (durable_object_ref is not None) == (expected_phase is CheckPhase.RESERVED)
        replacement = replace(
            lease,
            phase=next_phase,
            lease_generation=lease.lease_generation + 1,
        )
        self.frozen = FrozenCase(self.frozen.case, replacement)
        assert self.operation is not None
        self.operation = replace(
            self.operation,
            phase=next_phase,
            resume_object_ref=(
                cast(ObjectRef, durable_object_ref)
                if durable_object_ref is not None
                else self.operation.resume_object_ref
            ),
            lease_generation=replacement.lease_generation,
        )
        self.phase_transitions.append((expected_phase, next_phase))
        return replacement

    async def commit_check_if_current(
        self,
        frozen: FrozenCase,
        ranked: RankedFindings,
        executions: tuple[CheckPolicyExecution, ...],
        semantic_status: SemanticStatus,
        semantic_reason: SemanticReason,
        semantic_provenance: SemanticProvenance | None,
        request_id: str,
        *,
        scope: CheckScopeModel | None = None,
        semantic_conclusion: str | None = None,
        prior_finding_verdicts: tuple[object, ...] = (),
        missing_for_assessment: tuple[MissingForAssessmentItem, ...] = (),
        check_change_files: CheckChangeShownFiles | None = None,
        semantic_included_refs: tuple[str, ...] | None = None,
        semantic_withheld_item_ids: tuple[str, ...] = (),
        review_input_manifest: object | None = None,
        review_summary: str | None = None,
        semantic_redacted_values: tuple[SemanticRedactedValue, ...] = (),
    ) -> CheckCommitResult:
        assert frozen == self.frozen
        self.last_review_summary = review_summary
        self.last_verdicts = prior_finding_verdicts
        self.last_missing = missing_for_assessment
        self.last_conclusion = semantic_conclusion
        if self.commit_failure is not None:
            raise self.commit_failure
        self.commit_count += 1
        self.last_ranked = ranked
        self.last_executions = executions
        return CheckCommitResult(
            "committed",
            _TASK,
            _SESSION,
            _WRITER,
            request_id,
            frozen.case.frontier,
            Frontier(frozen.case.frontier.sequence + 1, "sha256:" + "e" * 64),
            ranked.verdict,
            ranked.findings,
            ranked.suppressed_count,
            executions,
            semantic_status,
            semantic_reason,
            semantic_provenance,
            ranked.coverage,
            CheckVersionSlice(
                "0.1",
                "0.1.0",
                "0.1.0",
                ("research-evidence/0.2.0", "work-integrity/0.3.0"),
            ),
            missing_for_assessment=missing_for_assessment,
            semantic_withheld_item_ids=semantic_withheld_item_ids,
            semantic_redacted_values=semantic_redacted_values,
        )

    async def fail_check_if_current(
        self, lease: OperationLease, failure: PublicOperationError
    ) -> None:
        assert lease == self.frozen.lease
        assert failure.code is PublicErrorCode.INTERNAL_ERROR
        assert self.operation is not None
        self.fail_count += 1
        result_canonical = b'{"code":"INTERNAL_ERROR"}'
        self.operation = replace(
            self.operation,
            state=OperationState.COMPLETE,
            phase=CheckPhase.TERMINAL,
            owner_generation=None,
            lease_owner_id=None,
            lease_generation=None,
            lease_expires_at=None,
            resume_object_ref=None,
            result_canonical=result_canonical,
            result_digest=f"sha256:{hashlib.sha256(result_canonical).hexdigest()}",
            terminal_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


class _Runtime:
    def __init__(self, task: TaskRuntime) -> None:
        self.task = task
        self.release_count = 0
        self.last_command: RouteCommand | None = None

    async def route(self, command: RouteCommand) -> TaskRuntime:
        self.last_command = command
        return self.task

    async def release(self, runtime: TaskRuntime) -> None:
        assert runtime is self.task
        self.release_count += 1


class _App:
    def __init__(self, *, semantic: bool = False, crash_semantic: bool = False) -> None:
        self.id_source = _Ids()
        self.ids: IdPort = self.id_source
        self.clock = FixedClock()
        self.verification_policy = VerificationPolicy()
        self.ledger = _Ledger(_case())
        self.crash_semantic = crash_semantic
        self.semantic_calls = 0
        self.reconcile_observation_capture: Callable[[TaskRuntime], Awaitable[None]] | None = None
        self.change_capture: object | None = None
        self.start_catalog: object | None = None
        capabilities = {
            RuntimeCapability.WRITE,
            RuntimeCapability.PAYLOAD_READ,
        }
        if semantic:
            capabilities.add(RuntimeCapability.SEMANTIC)
        task = TaskRuntime(
            _TASK,
            _SESSION,
            _WRITER,
            frozenset(capabilities),
            cast(object, self.ledger),  # pyright: ignore[reportArgumentType]
            MemoryObjects(self.id_source),  # pyright: ignore[reportArgumentType]
            object(),  # pyright: ignore[reportArgumentType]
            "0.1.0",
            "0.1.0",
            "0.1",
            "1",
            OwnershipFence(
                "svc_30000000-0000-4000-8000-000000000001",
                1,
                1,
                "0123456789abcdef",
            ),
        )
        self.runtime = cast(BundleRuntimePort, _Runtime(task))
        self.semantic_result = FinalSemanticEvaluation(
            SemanticStatus.NOT_CONFIGURED,
            SemanticReason.PROVIDER_NOT_CONFIGURED,
        )

    async def evaluate_semantic_check(
        self,
        frozen: FrozenCase,
        deterministic_findings: tuple[Finding, ...],
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
    ) -> FinalSemanticEvaluation:
        _ = (frozen, deterministic_findings, runtime, lineage_evaluation)
        self.semantic_calls += 1
        if self.crash_semantic:
            raise RuntimeError("semantic_evaluator_crashed")
        return self.semantic_result


class _StructuralCapturePort:
    def __init__(self, capture: CheckChangeCapture) -> None:
        self.capture_result = capture
        self.calls: list[tuple[str, object]] = []
        self.metadata_calls: list[tuple[str, object]] = []

    def capture(self, workspace: str, base: object) -> CheckChangeCapture:
        raise AssertionError("structural accounting must not call content capture")

    def capture_metadata(self, workspace: str, base: object) -> CheckChangeMetadata:
        self.metadata_calls.append((workspace, base))
        return CheckChangeMetadata(
            base=self.capture_result.base,
            entries=(ChangeMetadataEntry("M", "tests/test_existing.py"),),
            tracked_files=1,
            untracked_files=0,
            omitted_files=0,
            truncated=False,
            base_commit=self.capture_result.base_commit,
        )


class _StructuralStartCatalog:
    async def resolve_route(self, session_id: str) -> object:
        assert session_id == _SESSION
        return SimpleNamespace(repository_privacy_commitment="hmac-sha256:" + "a" * 64)


def _request(mode: str | None = "deterministic_only", *, max_findings: str = "1") -> CheckRequest:
    body: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _REQUEST,
        "session_id": _SESSION,
        "writer_id": _WRITER,
        "expected_frontier": {
            "sequence": str(FRONTIER.sequence),
            "head_digest": FRONTIER.head_digest,
        },
        "max_findings": max_findings,
        "actor": {"actor_id": "harness:test", "actor_type": "harness"},
        "client": {
            "kind": "test_client",
            "version": "0.1.0",
            "integration": "local_cli",
        },
    }
    if mode is not None:
        body["mode"] = mode
    return CheckRequest.model_validate(body)


@pytest.mark.anyio
async def test_deterministic_check_freezes_ranks_commits_and_releases() -> None:
    app = _App()

    result = await execute_check(app, _request())

    assert result.verdict.value == "action_required"
    assert len(result.findings) == 1
    assert result.semantic_status is SemanticStatus.NOT_REQUESTED
    assert result.semantic_reason is SemanticReason.DETERMINISTIC_MODE
    assert not hasattr(app, "finalize_check_result")
    assert app.ledger.commit_count == 1
    assert app.ledger.phase_transitions == [
        (CheckPhase.RESERVED, CheckPhase.LOCAL_READY),
        (CheckPhase.LOCAL_READY, CheckPhase.READY_TO_FINALIZE),
    ]
    assert cast(_Runtime, app.runtime).release_count == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("mode", "semantic"),
    (("deterministic_only", False), ("semantic_if_configured", True)),
)
async def test_checks_account_for_preexisting_test_edits_without_provider_delivery(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    semantic: bool,
) -> None:
    capture = CheckChangeCapture(
        base="task_start",
        text=b"""Yoetz check-time change
Files:
  M tests/test_existing.py (+1 -1)
End of header. The unified diff follows.
diff --git a/tests/test_existing.py b/tests/test_existing.py
--- a/tests/test_existing.py
+++ b/tests/test_existing.py
@@ -1 +1 @@
-assert True
+assert False
""",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        base_commit="a" * 40,
    )
    app = _App(semantic=semantic)
    action = ActionRecordedPayload(
        act(1),
        ActionKind.EDIT,
        "Edit the existing test",
        attempted_items=("tests/test_existing.py",),
    )
    app.ledger.frozen = FrozenCase(
        make_case(actions={act(1): record(action, 1)}), app.ledger.frozen.lease
    )
    app.change_capture = _StructuralCapturePort(capture)
    app.start_catalog = _StructuralStartCatalog()
    source = CheckWorkspaceSource("/workspace", "hmac-sha256:" + "a" * 64)
    monkeypatch.setattr(check_module, "current_check_workspace_source", lambda: source)

    result = await execute_check_commit(app, _request(mode, max_findings="4"))

    if semantic:
        assert result.semantic_status is SemanticStatus.NOT_CONFIGURED
        assert result.semantic_reason is SemanticReason.PROVIDER_NOT_CONFIGURED
    else:
        assert result.semantic_status is SemanticStatus.NOT_REQUESTED
        assert result.semantic_reason is SemanticReason.DETERMINISTIC_MODE
    assert "preexisting_test_edit_unjustified" in result.coverage.known_gaps
    # This fixture records an edit but only a material claim. The integrity finding is gated on
    # an explicit completion claim, so routine research checks keep the structural gap visible
    # without misclassifying the test edit as an actionable completion failure.
    assert not any(
        finding.kind is FindingKind.TASK_REQUIREMENT_UNMET for finding in result.findings
    )
    assert isinstance(app.change_capture, _StructuralCapturePort)
    assert app.change_capture.calls == []
    assert app.change_capture.metadata_calls == [("/workspace", None)]


@pytest.mark.anyio
async def test_post_admission_protocol_failure_is_internal_and_terminalizes_operation() -> None:
    """An internal value failure cannot masquerade as bad input or leave CHECK pending."""

    app = _App()
    app.ledger.commit_failure = ProtocolValueError("invalid_event_value_type")

    with pytest.raises(PublicOperationError) as caught:
        await execute_check_commit(app, _request())

    assert caught.value.code is PublicErrorCode.INTERNAL_ERROR
    assert caught.value.retryable is False
    assert app.ledger.fail_count == 1
    assert app.ledger.operation is not None
    assert app.ledger.operation.state is OperationState.COMPLETE
    assert app.ledger.operation.phase is CheckPhase.TERMINAL
    assert cast(_Runtime, app.runtime).release_count == 1


@pytest.mark.anyio
@pytest.mark.parametrize("mapped", (False, True))
async def test_unmapped_task_statement_is_an_actionable_check_finding(mapped: bool) -> None:
    """TB4 pilot: an unmapped request must reach the agent as a finding, not an advisory gap."""

    from yoetz.domain.task_statement import RecordedTaskStatement

    statement_event = evt(1)
    obligation = ObligationPublishedPayload(
        obl(1),
        "Repair the planner",
        "The planner output is correct",
        ObligationStatus.OPEN,
        source_refs=(statement_event,) if mapped else (),
    )
    plan = PlanPublishedPayload(1, "Plan", (obl(1),))
    base = make_case(
        plans={1: plan_record(plan, 2)},
        obligations={obl(1): obligation_record(obligation, 3)},
        extra_refs=(statement_event,),
    )
    case = replace(
        base,
        task_statement=RecordedTaskStatement("Fix it.", statement_event, "session_opened", 1),
    )
    app = _App()
    app.ledger.frozen = FrozenCase(case, app.ledger.frozen.lease)

    checked = await execute_check_commit(app, _request(max_findings="4"))

    unmet = [item for item in checked.findings if item.kind is FindingKind.TASK_REQUIREMENT_UNMET]
    if mapped:
        assert unmet == []
    else:
        assert checked.verdict.value == "action_required"
        assert [item.subject_refs for item in unmet] == [(statement_event,)]
        assert "source_refs [" + statement_event + "]" in unmet[0].detail


def _unmapped_statement_case() -> DeterministicCase:
    from yoetz.domain.task_statement import RecordedTaskStatement

    statement_event = evt(1)
    obligation = ObligationPublishedPayload(
        obl(1), "Repair the planner", "The planner output is correct", ObligationStatus.OPEN
    )
    base = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Plan", (obl(1),)), 2)},
        obligations={obl(1): obligation_record(obligation, 3)},
        extra_refs=(statement_event,),
    )
    return replace(
        base,
        task_statement=RecordedTaskStatement("Fix it.", statement_event, "session_opened", 1),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("research_selected", (True, False))
async def test_requirement_findings_follow_the_research_pack_execution(
    research_selected: bool,
) -> None:
    """Pilot blocker R4: emission and resolution share one condition.

    The statement finding is recorded under research-evidence and only a check that completed
    that pack can resolve it, so only such a check raises it. A recorded statement is a pack root,
    so the pack runs on a plan-only case before any claim exists.
    """

    app = _App()
    app.ledger.frozen = FrozenCase(_unmapped_statement_case(), app.ledger.frozen.lease)
    request = _request(max_findings="4")
    if not research_selected:
        request = request.model_copy(update={"policy_packs": ("work-integrity/0.3.0",)})

    checked = await execute_check_commit(app, request)

    unmet = [item for item in checked.findings if item.kind is FindingKind.TASK_REQUIREMENT_UNMET]
    research = [item for item in checked.policy_executions if item.policy_id == "research-evidence"]
    if research_selected:
        assert [(item.outcome, item.reason) for item in research] == [("run", "completed")]
        assert len(unmet) == 1
    else:
        assert research == []
        assert unmet == []


@pytest.mark.anyio
async def test_completion_on_an_empty_scope_with_a_statement_is_an_actionable_finding() -> None:
    """Pilot blocker D3: a completion claim never stands on an undecomposed request."""

    from yoetz.domain.events import ClaimKind, ClaimRecordedPayloadV1_1
    from yoetz.domain.task_statement import (
        TASK_STATEMENT_SCOPE_EMPTY_SUMMARY,
        RecordedTaskStatement,
    )

    statement_event = evt(1)
    plan = PlanPublishedPayload(1, "Plan", (), (), NoObligationsReason.SINGLE_ATOMIC_CHANGE)
    claim = ClaimRecordedPayloadV1_1(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Done.",
        supporting_refs=(),
        obligation_refs=(),
        limitation_refs=(),
        supersedes_claim_refs=(),
    )
    base = make_case(
        plans={1: plan_record(plan, 2)},
        claims={clm(1): claim_record(claim, 4)},
        extra_refs=(statement_event,),
    )
    case = replace(
        base,
        task_statement=RecordedTaskStatement("Fix it.", statement_event, "session_opened", 1),
    )
    app = _App()
    app.ledger.frozen = FrozenCase(case, app.ledger.frozen.lease)

    checked = await execute_check_commit(app, _request(max_findings="8"))

    unmet = [item for item in checked.findings if item.kind is FindingKind.TASK_REQUIREMENT_UNMET]
    assert [item.summary for item in unmet] == [TASK_STATEMENT_SCOPE_EMPTY_SUMMARY]
    assert unmet[0].subject_refs == (statement_event,)
    assert "yoetz-no-material-work:" + statement_event in unmet[0].detail
    assert checked.verdict.value == "action_required"


class _MetadataOnlyCapturePort:
    def __init__(self, entries: tuple[ChangeMetadataEntry, ...]) -> None:
        self.entries = entries

    def capture(self, workspace: str, base: object) -> CheckChangeCapture:
        raise AssertionError("structural accounting must not call content capture")

    def capture_metadata(self, workspace: str, base: object) -> CheckChangeMetadata:
        return CheckChangeMetadata(
            base="task_start",
            entries=self.entries,
            tracked_files=sum(1 for item in self.entries if not item.untracked),
            untracked_files=sum(1 for item in self.entries if item.untracked),
            omitted_files=0,
            truncated=False,
            base_commit="a" * 40,
        )


@pytest.mark.anyio
@pytest.mark.parametrize("workspace", ("shell_changed", "unchanged", "capture_unavailable"))
async def test_no_material_work_decision_needs_a_capture_showing_no_changed_path(
    monkeypatch: pytest.MonkeyPatch,
    workspace: str,
) -> None:
    """The escape is cancelled by any changed path, not only by an ``edit`` action.

    Hosts record shell writes (``sed -i``, ``cat > file``) as command actions, so a task with no
    edit action can still have changed files. Only a check-time capture that shows no changed path
    honours the decision; a missing capture fails closed.
    """

    from yoetz.domain.events import (
        ClaimKind,
        ClaimRecordedPayloadV1_1,
        DecisionRecordedPayload,
        encode_payload,
    )
    from yoetz.domain.task_statement import (
        TASK_STATEMENT_SCOPE_EMPTY_SUMMARY,
        RecordedTaskStatement,
    )
    from yoetz.domain.values import actor_id
    from yoetz.kernel.projections import DecisionProjectionRecord
    from yoetz.protocol.canonical import canonical_digest

    statement_event = evt(1)
    plan = PlanPublishedPayload(1, "Plan", (), (), NoObligationsReason.NO_MATERIAL_CHANGE)
    claim = ClaimRecordedPayloadV1_1(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Answered.",
        supporting_refs=(),
        obligation_refs=(),
        limitation_refs=(),
        supersedes_claim_refs=(),
    )
    command = ActionRecordedPayload(
        act(1), ActionKind.COMMAND, "Ran a shell command", command="sed -i s/a/b/ calc.py"
    )
    decision = DecisionRecordedPayload(
        f"The request asks only for an explanation.\nyoetz-no-material-work:{statement_event}",
        "The user asked a question; no file needs to change.",
        actor_id("agent:1"),
    )
    base = make_case(
        plans={1: plan_record(plan, 2)},
        actions={act(1): record(command, 3)},
        claims={clm(1): claim_record(claim, 4)},
        extra_refs=(statement_event,),
    )
    row = DecisionProjectionRecord(
        payload=decision,
        payload_digest=canonical_digest(encode_payload(decision)),
        redacted=False,
        source_event_id=evt(5),
        source_frontier=5,
    )
    case = replace(
        replace(base, projection=replace(base.projection, decisions={evt(5): row})),
        task_statement=RecordedTaskStatement("Explain it.", statement_event, "session_opened", 1),
    )
    app = _App()
    app.ledger.frozen = FrozenCase(case, app.ledger.frozen.lease)
    if workspace != "capture_unavailable":
        entries = (ChangeMetadataEntry("M", "calc.py"),) if workspace == "shell_changed" else ()
        app.change_capture = _MetadataOnlyCapturePort(entries)
        app.start_catalog = _StructuralStartCatalog()
        source = CheckWorkspaceSource("/workspace", "hmac-sha256:" + "a" * 64)
        monkeypatch.setattr(check_module, "current_check_workspace_source", lambda: source)

    checked = await execute_check_commit(app, _request(max_findings="8"))

    unmet = [item for item in checked.findings if item.kind is FindingKind.TASK_REQUIREMENT_UNMET]
    if workspace == "unchanged":
        assert unmet == []
    else:
        assert [item.summary for item in unmet] == [TASK_STATEMENT_SCOPE_EMPTY_SUMMARY]
        assert unmet[0].subject_refs == (statement_event,)


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ("deterministic_only", "semantic_required"))
@pytest.mark.parametrize(
    ("reason", "expected_gap"),
    (
        (None, COMPLETION_SCOPE_UNDECLARED_GAP),
        (NoObligationsReason.SINGLE_ATOMIC_CHANGE, COMPLETION_SCOPE_DECLARED_NONE_GAP),
    ),
)
async def test_empty_completion_scope_gap_reaches_check_verdict(
    mode: str,
    reason: NoObligationsReason | None,
    expected_gap: str,
) -> None:
    action = ActionRecordedPayload(
        act(1),
        ActionKind.COMMAND,
        "Run the atomic change",
        command="true",
    )
    result = ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS, exit_status=0)
    claim = ClaimRecordedPayload(
        clm(1),
        ClaimKind.COMPLETION,
        "The atomic change is complete.",
        (res(1),),
    )
    plan = PlanPublishedPayload(1, "Atomic change", (), (), reason)
    base = make_case(
        plans={1: plan_record(plan, 1)},
        actions={act(1): record(action, 2)},
        results={res(1): record(result, 3)},
        claims={clm(1): record(claim, 4)},
    )
    gap = deterministic_checks_module.completion_scope_gap(base.projection)
    assert gap is not None
    case = replace(base, gaps=(gap,))
    app = _App(semantic=mode == "semantic_required")
    app.ledger.frozen = FrozenCase(case, app.ledger.frozen.lease)

    checked = await execute_check_commit(app, _request(mode))

    assert checked.findings == ()
    assert checked.verdict.value == "insufficient_coverage"
    assert expected_gap in checked.coverage.known_gaps
    assert checked.policy_executions == (
        CheckPolicyExecution("coordination", "0.1.0", "skipped", "not_applicable"),
        CheckPolicyExecution("research-evidence", "0.2.0", "run", "completed"),
        CheckPolicyExecution("work-integrity", "0.3.0", "run", "completed"),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("reason", (None, NoObligationsReason.SINGLE_ATOMIC_CHANGE))
async def test_empty_completion_scope_gap_dominates_mixed_actionable_finding(
    reason: NoObligationsReason | None,
) -> None:
    action = ActionRecordedPayload(
        act(1),
        ActionKind.COMMAND,
        "Run the atomic change",
        command="true",
    )
    result = ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS, exit_status=0)
    obligation = ObligationPublishedPayload(
        obl(1),
        "Resolve the undeclared obligation",
        "Recorded resolution evidence",
        ObligationStatus.OPEN,
    )
    claim = ClaimRecordedPayload(
        clm(1),
        ClaimKind.COMPLETION,
        "The atomic change is complete.",
        (res(1),),
        obligation_refs=(obl(1),),
    )
    plan = PlanPublishedPayload(1, "Atomic change", (), (), reason)
    base = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={obl(1): obligation_record(obligation, 2)},
        actions={act(1): record(action, 3)},
        results={res(1): record(result, 4)},
        claims={clm(1): record(claim, 5)},
    )
    gap = deterministic_checks_module.completion_scope_gap(base.projection)
    assert gap is not None
    app = _App()
    app.ledger.frozen = FrozenCase(replace(base, gaps=(gap,)), app.ledger.frozen.lease)

    checked = await execute_check_commit(app, _request())

    assert tuple(finding.kind for finding in checked.findings) == (
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
    )
    assert checked.verdict.value == "insufficient_coverage"
    assert gap.code in checked.coverage.known_gaps


@pytest.mark.anyio
async def test_resolved_declared_scope_reaches_clean_check_verdict() -> None:
    action = ActionRecordedPayload(
        act(1),
        ActionKind.COMMAND,
        "Run the declared change",
        obligation_refs=(obl(1),),
        command="true",
    )
    result = ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS, exit_status=0)
    obligation = ObligationPublishedPayload(
        obl(1),
        "Complete the declared change",
        "A successful recorded result",
        ObligationStatus.RESOLVED,
        resolution_evidence_refs=(res(1),),
    )
    claim = ClaimRecordedPayload(
        clm(1),
        ClaimKind.COMPLETION,
        "The declared change is complete.",
        (res(1),),
        obligation_refs=(obl(1),),
    )
    plan = PlanPublishedPayload(1, "Declared change", (obl(1),), ())
    case = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={obl(1): obligation_record(obligation, 2)},
        actions={act(1): record(action, 3)},
        results={res(1): record(result, 4)},
        claims={clm(1): record(claim, 5)},
    )
    assert deterministic_checks_module.completion_scope_gap(case.projection) is None
    app = _App(semantic=True)
    app.semantic_result = replace(
        _succeeded(SemanticJudgment("no_material_discrepancy", ())),
        provider_input_manifest=_provider_bound_manifest(),
    )
    app.ledger.frozen = FrozenCase(case, app.ledger.frozen.lease)

    checked = await execute_check_commit(app, _request("semantic_if_configured"))

    assert checked.findings == ()
    assert checked.coverage.known_gaps == ()
    assert checked.verdict.value == "no_issue_detected"


@pytest.mark.anyio
async def test_deterministic_only_returns_scoped_clean_without_a_review_gap() -> None:
    """A local-only check asked for on a route that requires no review discloses none (#1041)."""

    action = ActionRecordedPayload(
        act(1),
        ActionKind.COMMAND,
        "Run the declared change",
        obligation_refs=(obl(1),),
        command="true",
    )
    result = ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS, exit_status=0)
    obligation = ObligationPublishedPayload(
        obl(1),
        "Complete the declared change",
        "A successful recorded result",
        ObligationStatus.RESOLVED,
        resolution_evidence_refs=(res(1),),
    )
    claim = ClaimRecordedPayload(
        clm(1),
        ClaimKind.COMPLETION,
        "The declared change is complete.",
        (res(1),),
        obligation_refs=(obl(1),),
    )
    plan = PlanPublishedPayload(1, "Declared change", (obl(1),), ())
    case = make_case(
        plans={1: plan_record(plan, 1)},
        obligations={obl(1): obligation_record(obligation, 2)},
        actions={act(1): record(action, 3)},
        results={res(1): record(result, 4)},
        claims={clm(1): record(claim, 5)},
    )
    app = _App()
    app.ledger.frozen = FrozenCase(case, app.ledger.frozen.lease)

    checked = await execute_check_commit(app, _request("deterministic_only"))

    assert checked.findings == ()
    assert checked.verdict.value == "no_issue_detected"
    assert checked.semantic_status is SemanticStatus.NOT_REQUESTED
    assert checked.semantic_reason is SemanticReason.DETERMINISTIC_MODE
    assert checked.coverage.known_gaps == ()

    # Where the policy requires review, asking for none is still disclosed (and is agent work).
    required = _App()
    required.verification_policy = VerificationPolicy(semantic="required")
    required.ledger.frozen = FrozenCase(case, required.ledger.frozen.lease)
    unmet = await execute_check_commit(required, _request("deterministic_only"))
    assert unmet.coverage.known_gaps == ("semantic_review_not_requested",)


@pytest.mark.anyio
async def test_disabled_policy_resolves_omitted_mode_to_scoped_clean() -> None:
    action = ActionRecordedPayload(
        act(1),
        ActionKind.COMMAND,
        "Run the declared change",
        obligation_refs=(obl(1),),
        command="true",
    )
    result = ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS, exit_status=0)
    obligation = ObligationPublishedPayload(
        obl(1),
        "Complete the declared change",
        "A successful recorded result",
        ObligationStatus.RESOLVED,
        resolution_evidence_refs=(res(1),),
    )
    claim = ClaimRecordedPayload(
        clm(1),
        ClaimKind.COMPLETION,
        "The declared change is complete.",
        (res(1),),
        obligation_refs=(obl(1),),
    )
    case = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Declared change", (obl(1),), ()), 1)},
        obligations={obl(1): obligation_record(obligation, 2)},
        actions={act(1): record(action, 3)},
        results={res(1): record(result, 4)},
        claims={clm(1): record(claim, 5)},
    )
    app = _App()
    app.verification_policy = VerificationPolicy(semantic="disabled")
    app.ledger.frozen = FrozenCase(case, app.ledger.frozen.lease)

    checked = await execute_check_commit(app, _request(None))

    assert checked.findings == ()
    assert checked.verdict.value == "no_issue_detected"
    assert checked.semantic_status is SemanticStatus.NOT_REQUESTED
    assert checked.semantic_reason is SemanticReason.DETERMINISTIC_MODE
    # The owner's disabled policy made the check local-only by request: no review gap (#1041).
    assert checked.coverage.known_gaps == ()


@pytest.mark.anyio
async def test_semantic_required_unavailable_preserves_deterministic_truth() -> None:
    app = _App(semantic=True)

    result = await execute_check_commit(app, _request("semantic_required"))

    assert result.verdict.value == "incomplete_check"
    assert result.findings
    assert result.semantic_status is SemanticStatus.NOT_CONFIGURED
    assert result.semantic_provenance is None
    assert result.coverage.known_gaps == ("semantic_review_not_configured",)
    runtime = cast(_Runtime, app.runtime)
    assert runtime.last_command is not None
    assert RuntimeCapability.SEMANTIC in runtime.last_command.required_capabilities


@pytest.mark.anyio
async def test_strict_route_ceiling_never_requests_or_dispatches_semantic_capability(
    tmp_path: Path,
) -> None:
    app = _App(semantic=True)

    result = await execute_check_commit(
        app,
        _request("semantic_required"),
        route_profile="strict",
        host_profile="codex",
        _state=tmp_path,
    )

    assert result.verdict.value == "incomplete_check"
    assert result.semantic_status is SemanticStatus.BLOCKED_BY_POLICY
    assert result.semantic_reason is SemanticReason.ROUTE_SEMANTIC_CEILING
    assert result.coverage.known_gaps == ("optional_semantic_review_blocked_by_policy",)
    assert app.semantic_calls == 0
    runtime = cast(_Runtime, app.runtime)
    assert runtime.last_command is not None
    assert RuntimeCapability.SEMANTIC not in runtime.last_command.required_capabilities


@pytest.mark.anyio
async def test_strict_ceiling_with_applied_policy_carries_drift_gap(tmp_path: Path) -> None:
    """Issue #537 slice C: strict serving + applied policy names the drift structurally."""

    from yoetz.application.applied_mcp_route import record_applied_route
    from yoetz.domain.receipts import (
        OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
        OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP,
    )
    from yoetz.ports.harness_mcp import MCP_SERVE_COMMAND

    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        None,
        "sha256:" + "a" * 64,
        _state=tmp_path,
    )
    app = _App(semantic=True)

    result = await execute_check_commit(
        app,
        _request("semantic_required"),
        route_profile="strict",
        host_profile="codex",
        _state=tmp_path,
    )

    # The terminal outcome is unchanged: same status, reason, and null provenance.
    assert result.verdict.value == "incomplete_check"
    assert result.semantic_status is SemanticStatus.BLOCKED_BY_POLICY
    assert result.semantic_reason is SemanticReason.ROUTE_SEMANTIC_CEILING
    assert result.semantic_provenance is None
    assert app.semantic_calls == 0
    # The drift is a structural coverage detail alongside the ceiling gap, never instead.
    assert OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP in result.coverage.known_gaps
    assert OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP in result.coverage.known_gaps


@pytest.mark.parametrize("host_profile", ["generic", "claude", "cursor"])
@pytest.mark.anyio
async def test_strict_ceiling_does_not_apply_codex_record_to_other_hosts(
    host_profile: str, tmp_path: Path
) -> None:
    """A Codex applied route cannot identify a generic, Claude, or Cursor serving process."""

    from yoetz.application.applied_mcp_route import record_applied_route
    from yoetz.ports.harness_mcp import MCP_SERVE_COMMAND

    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        None,
        "sha256:" + "a" * 64,
        _state=tmp_path,
    )

    result = await execute_check_commit(
        _App(semantic=True),
        _request("semantic_required"),
        route_profile="strict",
        host_profile=host_profile,  # type: ignore[arg-type]
        _state=tmp_path,
    )

    assert result.semantic_reason is SemanticReason.ROUTE_SEMANTIC_CEILING
    assert result.coverage.known_gaps == ("optional_semantic_review_blocked_by_policy",)


@pytest.mark.anyio
async def test_strict_ceiling_with_applied_strict_keeps_terminal_wording(
    tmp_path: Path,
) -> None:
    """A genuinely applied strict route carries no drift gap and today's wording exactly."""

    from yoetz.application.applied_mcp_route import record_applied_route
    from yoetz.ports.harness_mcp import MCP_STRICT_SERVE_COMMAND

    record_applied_route(
        "strict",
        list(MCP_STRICT_SERVE_COMMAND),
        None,
        "sha256:" + "b" * 64,
        _state=tmp_path,
    )
    app = _App(semantic=True)

    result = await execute_check_commit(
        app,
        _request("semantic_required"),
        route_profile="strict",
        host_profile="codex",
        _state=tmp_path,
    )

    assert result.semantic_status is SemanticStatus.BLOCKED_BY_POLICY
    assert result.semantic_reason is SemanticReason.ROUTE_SEMANTIC_CEILING
    assert result.semantic_provenance is None
    assert result.coverage.known_gaps == ("optional_semantic_review_blocked_by_policy",)


@pytest.mark.anyio
async def test_strict_ceiling_without_applied_record_keeps_terminal_wording(
    tmp_path: Path,
) -> None:
    """No applied record reads as no drift: fail-soft, terminal wording unchanged."""

    app = _App(semantic=True)

    result = await execute_check_commit(
        app,
        _request("semantic_required"),
        route_profile="strict",
        host_profile="codex",
        _state=tmp_path,
    )

    assert result.semantic_status is SemanticStatus.BLOCKED_BY_POLICY
    assert result.semantic_reason is SemanticReason.ROUTE_SEMANTIC_CEILING
    assert result.semantic_provenance is None
    assert result.coverage.known_gaps == ("optional_semantic_review_blocked_by_policy",)


@pytest.mark.anyio
async def test_drift_gap_is_reread_live_never_carried_after_remove(tmp_path: Path) -> None:
    """Issue #537: remove clears the record, so no successor inherits stale drift.

    A strict check with an applied-policy record carries both gaps; after
    ``clear_applied_route`` (what ``mcp remove`` runs on UNREGISTER→ABSENT) a fresh
    strict check re-reads live state and carries only the ceiling gap, and a
    local-only successor of the drift check carries only the ceiling gap.
    """

    from yoetz.application.applied_mcp_route import clear_applied_route, record_applied_route
    from yoetz.application.check import carried_semantic_attempt_gaps
    from yoetz.domain.receipts import (
        OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
        OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP,
    )
    from yoetz.domain.values import EventId
    from yoetz.kernel.projections import LatestTestedState
    from yoetz.ports.harness_mcp import MCP_SERVE_COMMAND

    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        None,
        "sha256:" + "a" * 64,
        _state=tmp_path,
    )

    drifted = await execute_check_commit(
        _App(semantic=True),
        _request("semantic_required"),
        route_profile="strict",
        host_profile="codex",
        _state=tmp_path,
    )
    assert OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP in drifted.coverage.known_gaps
    assert OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP in drifted.coverage.known_gaps

    # `mcp remove` clears the record; absence with no record reads as no drift.
    clear_applied_route(_state=tmp_path)

    reread = await execute_check_commit(
        _App(semantic=True),
        _request("semantic_required"),
        route_profile="strict",
        host_profile="codex",
        _state=tmp_path,
    )
    assert reread.coverage.known_gaps == ("optional_semantic_review_blocked_by_policy",)

    # A local-only successor of the drift check carries the ceiling gap only.
    frozen = _case()
    successor = replace(
        frozen.case,
        projection=replace(
            frozen.case.projection,
            latest_tested_state=LatestTestedState(
                source_check_event_id=EventId("evt_30000000-0000-4000-8000-000000000001"),
                subject_frontier=frozen.case.frontier,
                verdict=drifted.verdict,
                returned_finding_ids=(),
                suppressed_count=0,
                coverage=drifted.coverage,
            ),
        ),
    )
    assert carried_semantic_attempt_gaps(successor, SemanticStatus.NOT_REQUESTED) == {
        OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP
    }


@pytest.mark.anyio
async def test_semantic_evaluator_crash_degrades_to_not_run_without_false_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement: evaluator crash/timeout degrades to not-run disclosure, never false clean."""

    from yoetz.domain.receipts import (
        SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
        SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
    )

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    crashed = _App(semantic=True, crash_semantic=True)
    crash_result = await execute_check_commit(crashed, _request("semantic_if_configured"))
    assert crash_result.findings
    assert crash_result.semantic_status is SemanticStatus.FAILED
    assert crash_result.semantic_reason is SemanticReason.COORDINATOR_FAILURE
    assert crash_result.verdict.value != "no_issue_detected"
    assert SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP in crash_result.coverage.known_gaps
    assert SEMANTIC_REVIEW_NOT_CONFIGURED_GAP not in crash_result.coverage.known_gaps
    raw = diagnostics_module.diagnostic_log_path(root=tmp_path).read_text(encoding="ascii")
    records = tuple(json.loads(line) for line in raw.splitlines() if line)
    assert len(records) == 1
    assert records[0]["component"] == "check"
    assert records[0]["operation"] == "semantic_not_dispatched_coordinator_failure"
    assert records[0]["reason"] == "exception_runtime_error"
    assert records[0]["request_id"] == _REQUEST
    assert "semantic_evaluator_crashed" not in raw
    assert "payload" not in raw
    assert str(tmp_path) not in raw

    timed_out = _App(semantic=True)
    timed_out.semantic_result = FinalSemanticEvaluation(
        SemanticStatus.UNAVAILABLE,
        SemanticReason.CREDENTIAL_UNAVAILABLE,
    )
    timeout_result = await execute_check_commit(timed_out, _request("semantic_if_configured"))
    assert timeout_result.findings
    assert timeout_result.semantic_status is SemanticStatus.UNAVAILABLE
    assert timeout_result.verdict.value != "no_issue_detected"
    assert SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP in timeout_result.coverage.known_gaps

    # Local findings remain intact (same unsupported-claim material from the frozen case).
    assert {finding.kind.value for finding in crash_result.findings} == {
        finding.kind.value for finding in timeout_result.findings
    }


@pytest.mark.anyio
async def test_check_replay_skips_policy_ids_and_second_commit() -> None:
    app = _App()
    first = await execute_check_commit(app, _request())
    app.ledger.replay = first
    allocated = app.id_source.count

    replayed = await execute_check_commit(app, _request())

    assert replayed is first
    assert app.id_source.count == allocated
    assert app.ledger.commit_count == 1


@pytest.mark.anyio
async def test_awaiting_human_replay_commits_only_after_a_terminal_decision() -> None:
    app = _App(semantic=True)
    objects = cast(MemoryObjects, cast(_Runtime, app.runtime).task.objects)
    prior = ObjectRef(
        "obj_30000000-0000-4000-8000-00000000aaaa",
        1,
        "hmac-sha256:" + "a" * 64,
        "sha256:" + "b" * 64,
        "yoetz-object/1",
        "bmk-1",
        ObjectMetadata(
            ObjectKind.CHECK_RESUME,
            "application/vnd.yoetz.check-resume+json",
            _TASK,
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )
    objects._refs[prior.object_id] = prior  # pyright: ignore[reportPrivateUsage]
    objects._data[prior.object_id] = b"{}"  # pyright: ignore[reportPrivateUsage]
    app.semantic_result = FinalSemanticEvaluation(
        SemanticStatus.AWAITING_HUMAN,
        SemanticReason.HUMAN_APPROVAL_REQUIRED,
        continuation=disclosure_continuation(
            pending_id="ppr_30000000-0000-4000-8000-000000000009",
            expires_at=datetime(2030, 1, 1, tzinfo=UTC),
            request_id=_REQUEST,
        ),
    )

    suspended = await _execute_check_commit(app, _request("semantic_if_configured"))

    assert type(suspended) is CheckAwaitingHuman
    assert app.ledger.commit_count == 0
    assert app.ledger.operation is not None
    assert app.ledger.operation.state is OperationState.PENDING
    assert app.ledger.operation.phase is CheckPhase.SEMANTIC_WAIT

    app.semantic_result = FinalSemanticEvaluation(
        SemanticStatus.HUMAN_DENIED,
        SemanticReason.HUMAN_DENIED,
    )
    committed = await _execute_check_commit(app, _request("semantic_if_configured"))

    assert type(committed) is CheckCommitResult
    assert committed.semantic_status is SemanticStatus.HUMAN_DENIED
    assert committed.semantic_reason is SemanticReason.HUMAN_DENIED
    assert app.ledger.commit_count == 1
    assert app.ledger.phase_transitions == [
        (CheckPhase.RESERVED, CheckPhase.LOCAL_READY),
        (CheckPhase.LOCAL_READY, CheckPhase.SEMANTIC_WAIT),
        (CheckPhase.SEMANTIC_WAIT, CheckPhase.READY_TO_FINALIZE),
    ]


@pytest.mark.anyio
async def test_check_conflict_and_cancellation_release_runtime() -> None:
    app = _App()
    app.ledger.failure = PublicOperationError(
        PublicErrorCode.FRONTIER_CONFLICT,
        "The frontier changed.",
        True,
    )
    with pytest.raises(PublicOperationError) as caught:
        await execute_check_commit(app, _request())
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
    assert cast(_Runtime, app.runtime).release_count == 1

    cancelled = _App()
    cancelled.ledger.failure = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await execute_check_commit(cancelled, _request())
    assert cast(_Runtime, cancelled.runtime).release_count == 1


@pytest.mark.anyio
async def test_route_identity_mismatch_maps_to_session_conflict() -> None:
    app = _App()
    cast(_Runtime, app.runtime).task = cast(
        TaskRuntime,
        type("WrongRoute", (), {"session_id": _SESSION, "writer_id": None})(),
    )

    with pytest.raises(PublicOperationError) as caught:
        await execute_check_commit(app, _request())

    assert caught.value.code is PublicErrorCode.SESSION_CONFLICT
    assert cast(_Runtime, app.runtime).release_count == 1


@pytest.mark.anyio
async def test_succeeded_review_with_withheld_context_is_not_reported_as_full_coverage() -> None:
    """A review that ran without material its own profile selected must show up in coverage.

    A live installation ran review profile ``assisted`` while its inference channel permitted
    neither ``obligation_text`` nor ``finding_summary``. The reviewer was asked whether the work
    satisfied its obligations with the obligations withheld, produced zero findings, and reported
    ``semantic_status: succeeded`` — which reads as a clean, complete review. Coverage has to
    carry the difference, or the receipt inherits the same false impression.
    """

    from yoetz.domain.receipts import SEMANTIC_REVIEW_CONTEXT_WITHHELD_GAP

    app = _App(semantic=True)
    digest = "sha256:" + "a" * 64
    app.semantic_result = FinalSemanticEvaluation(
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
        judgment=SemanticJudgment("no_material_discrepancy", ()),
        provenance=SemanticProvenance(
            provider="fake",
            endpoint_profile_id="fake",
            endpoint_profile_version="1.0.0",
            model="fake/model",
            sdk_version="1.0.0",
            prompt_digest=digest,
            schema_digest=digest,
            policy_digest=digest,
            privacy_policy_digest=digest,
            sampling_params=SamplingParams(128),
            latency_ms=1,
            semantic_attempt_id="att_30000000-0000-4000-8000-000000000001",
            dispatch_kind=SemanticDispatchKind.EXTERNAL,
            privacy_receipt_id="egr_30000000-0000-4000-8000-000000000001",
            status=SemanticStatus.SUCCEEDED,
            reason=SemanticReason.SEMANTIC_COMPLETED,
            provider_request_id="fake-semantic-request-1",
            egress_authorization_id="aut_30000000-0000-4000-8000-000000000001",
            request_commitment="hmac-sha256:" + "b" * 64,
        ),
        withheld_review_categories=("finding_summary", "obligation_text"),
    )
    result = await execute_check_commit(app, _request("semantic_if_configured"))
    assert SEMANTIC_REVIEW_CONTEXT_WITHHELD_GAP in result.coverage.known_gaps
    assert result.verdict.value != "no_issue_detected"

    # A review whose profile and channel agree declares no such gap.
    agreed = _App(semantic=True)
    agreed.semantic_result = replace(app.semantic_result, withheld_review_categories=())
    clean = await execute_check_commit(agreed, _request("semantic_if_configured"))
    assert SEMANTIC_REVIEW_CONTEXT_WITHHELD_GAP not in clean.coverage.known_gaps


@pytest.mark.anyio
async def test_withheld_review_item_is_a_review_scoped_gap_not_content_redacted() -> None:
    """Issue #982 (owner decision B2; regression from 860811ed, tb4n1 rs-archive S).

    Withholding one item from the external reviewer used to stamp ``content_redacted`` on the
    whole check, so local findings that never needed that item became unresolvable. The check now
    records only the review-scoped ``semantic_review_item_withheld``.
    """

    from yoetz.domain.receipts import SEMANTIC_REVIEW_ITEM_WITHHELD_GAP

    app = _App(semantic=True)
    app.semantic_result = replace(
        _succeeded(SemanticJudgment("no_material_discrepancy", ())),
        semantic_withheld_item_ids=("excerpt-heuristic",),
    )
    result = await execute_check_commit(app, _request("semantic_if_configured"))
    assert SEMANTIC_REVIEW_ITEM_WITHHELD_GAP in result.coverage.known_gaps
    assert "content_redacted" not in result.coverage.known_gaps


@pytest.mark.anyio
async def test_check_result_carries_redacted_value_refs_and_lines() -> None:
    """PL2-1 (issue #982): the recorded check and its result name refs and lines, never values."""

    values = (
        SemanticRedactedValue(
            "excerpt-a", "value_replaced", (3, 7), "evd_10000000-0000-4000-8000-000000000021"
        ),
        SemanticRedactedValue("excerpt-heuristic", "item_withheld", (2,)),
    )
    app = _App(semantic=True)
    app.semantic_result = replace(
        _succeeded(SemanticJudgment("no_material_discrepancy", ())),
        semantic_withheld_item_ids=("excerpt-heuristic",),
        semantic_redacted_values=values,
    )
    result = await execute_check_commit(app, _request("semantic_if_configured"))
    assert result.semantic_redacted_values == values
    wire = check_internal_json(result)
    assert wire["semantic_redacted_values"] == tuple(item.as_wire() for item in values)


def _succeeded(judgment: SemanticJudgment) -> FinalSemanticEvaluation:
    digest = "sha256:" + "a" * 64
    return FinalSemanticEvaluation(
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
        judgment=judgment,
        provenance=SemanticProvenance(
            provider="fake",
            endpoint_profile_id="fake",
            endpoint_profile_version="1.0.0",
            model="fake/model",
            sdk_version="1.0.0",
            prompt_digest=digest,
            schema_digest=digest,
            policy_digest=digest,
            privacy_policy_digest=digest,
            sampling_params=SamplingParams(128),
            latency_ms=1,
            semantic_attempt_id="att_30000000-0000-4000-8000-000000000001",
            dispatch_kind=SemanticDispatchKind.EXTERNAL,
            privacy_receipt_id="egr_30000000-0000-4000-8000-000000000001",
            status=SemanticStatus.SUCCEEDED,
            reason=SemanticReason.SEMANTIC_COMPLETED,
            provider_request_id="fake-semantic-request-1",
            egress_authorization_id="aut_30000000-0000-4000-8000-000000000001",
            request_commitment="hmac-sha256:" + "b" * 64,
        ),
    )


def _provider_bound_manifest() -> JsonObject:
    section = JsonObject(
        {
            "status": "missing",
            "source_refs": [],
            "item_ids": [],
            "omitted_refs": [],
            "omission_reasons": [],
            "revision": None,
            "content_digest": None,
            "content_bytes": 0,
        }
    )
    return JsonObject(
        {
            "schema": "yoetz.review-input-manifest/1",
            "phase": "provider_bound",
            "specification": section,
            "current_diff": section,
            "caller_evidence": section,
            "latest_verification": section,
            "prior_finding_context": section,
            "missing_inputs": [],
            "selected_item_count": 0,
            "selected_excerpt_bytes": 0,
            "omitted_item_count": 0,
        }
    )


@pytest.mark.anyio
async def test_response_content_invalid_is_a_committed_semantic_outcome() -> None:
    app = _App(semantic=True)
    succeeded = _succeeded(SemanticJudgment("no_material_discrepancy", ()))
    assert succeeded.provenance is not None
    app.semantic_result = replace(
        succeeded,
        status=SemanticStatus.INVALID,
        reason=SemanticReason.RESPONSE_CONTENT_INVALID,
        judgment=None,
        provenance=replace(
            succeeded.provenance,
            status=SemanticStatus.INVALID,
            reason=SemanticReason.RESPONSE_CONTENT_INVALID,
        ),
    )

    result = await execute_check_commit(app, _request("semantic_if_configured"))

    assert result.outcome == "committed"
    assert result.semantic_status is SemanticStatus.INVALID
    assert result.semantic_reason is SemanticReason.RESPONSE_CONTENT_INVALID
    assert result.coverage.known_gaps
    assert app.ledger.commit_count == 1
    assert app.ledger.fail_count == 0


def _reviewer_challenge(ref: str, *, summary: str = "Evidence gap") -> ReviewerChallenge:
    return ReviewerChallenge(
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        summary,
        (ref,),
        "The claim lacks a recorded basis.",
        "The claim may remain unresolved.",
        "Main agent: provide evidence for the claim.",
        "provide_evidence",
        "The missing material may exist outside the case.",
    )


@pytest.mark.anyio
async def test_rejected_judgment_commits_the_check_instead_of_failing_the_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reviewer answer the fence refuses costs the reviewer's output, never the whole check.

    Regression for a live failure: the post-validation ``ValueError`` escaped ``execute_check_commit``
    (which caught only ``ProtocolValueError``), reached the daemon catch-all, and became a
    non-retryable ``INVALID_REQUEST`` with no correlation id. No check was recorded at all, so the
    local findings were lost and nothing said why. ``SemanticStatus.INVALID`` /
    ``SEMANTIC_JUDGMENT_REJECTED`` existed for exactly this and had never once been written.

    The structural fence is unreachable through the ordinary call (the coordinator passes the frozen
    case's own frontier and a SUCCEEDED provenance by construction), so the raise is injected here:
    what is under test is the disposition of the failure, not its trigger.
    """

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)

    def _raise(*_args: object, **_kwargs: object) -> object:
        raise check_module.SemanticJudgmentRejected("semantic_judgment_invalid")

    monkeypatch.setattr(check_module, "validate_semantic_judgment", _raise)

    app = _App(semantic=True)
    app.semantic_result = _succeeded(
        SemanticJudgment("challenges_returned", (_reviewer_challenge(str(clm(1))),))
    )

    result = await execute_check_commit(app, _request("semantic_if_configured"))

    assert result.semantic_status is SemanticStatus.INVALID
    assert result.semantic_reason is SemanticReason.SEMANTIC_JUDGMENT_REJECTED
    assert result.semantic_provenance is not None
    assert result.semantic_provenance.status is SemanticStatus.INVALID
    assert result.semantic_provenance.reason is SemanticReason.SEMANTIC_JUDGMENT_REJECTED
    # The whole point: the local findings the user paid for still committed.
    assert result.findings
    assert all(finding.origin.value == "deterministic" for finding in result.findings)
    assert app.ledger.commit_count == 1
    assert result.verdict.value != "no_issue_detected"

    raw = diagnostics_module.diagnostic_log_path(root=tmp_path).read_text(encoding="ascii")
    operations = {json.loads(line)["operation"] for line in raw.splitlines() if line}
    assert "semantic_judgment_rejected" in operations


@pytest.mark.anyio
async def test_partial_rejection_keeps_accepted_challenges_and_declares_the_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One unusable challenge costs itself; the others become findings and the loss is declared."""

    from yoetz.domain.receipts import SEMANTIC_CHALLENGES_REJECTED_GAP

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    app = _App(semantic=True)
    app.semantic_result = _succeeded(
        SemanticJudgment(
            "challenges_returned",
            (
                _reviewer_challenge(str(clm(1)), summary="Accepted challenge"),
                _reviewer_challenge(
                    "clm_20000000-0000-4000-8000-000000000099", summary="Invented ref"
                ),
            ),
        )
    )

    result = await execute_check_commit(app, _request("semantic_if_configured", max_findings="4"))

    semantic_findings = [
        finding for finding in result.findings if finding.origin.value == "semantic_model_derived"
    ]
    assert [finding.summary for finding in semantic_findings] == ["Accepted challenge"]
    assert result.semantic_status is SemanticStatus.SUCCEEDED
    assert SEMANTIC_CHALLENGES_REJECTED_GAP in result.coverage.known_gaps

    raw = diagnostics_module.diagnostic_log_path(root=tmp_path).read_text(encoding="ascii")
    accounting = [
        json.loads(line)
        for line in raw.splitlines()
        if line and json.loads(line)["operation"] == "semantic_review_accounting"
    ]
    assert len(accounting) == 1
    record_json = accounting[0]
    assert record_json["semantic_conclusion"] == "challenges_returned"
    assert record_json["semantic_challenges_returned"] == 2
    assert record_json["semantic_candidates_accepted"] == 1
    assert record_json["semantic_challenges_rejected"] == 1
    assert record_json["semantic_findings_selected"] == 1
    assert record_json["semantic_findings_suppressed"] == 0
    # The record reconciles: nothing the reviewer returned is unaccounted for.
    assert record_json["semantic_challenges_returned"] == (
        record_json["semantic_candidates_accepted"] + record_json["semantic_challenges_rejected"]
    )
    assert record_json["semantic_candidates_accepted"] == (
        record_json["semantic_findings_selected"] + record_json["semantic_findings_suppressed"]
    )
    assert "Invented ref" not in raw
    assert "Accepted challenge" not in raw


@pytest.mark.anyio
async def test_challenge_citing_an_omitted_ref_is_kept_on_the_sent_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TB4 tb4v1 (issue #976): a cited ref without a sent row no longer discards the challenge.

    The reviewer cites a carried claim and a claim whose row the packet omitted, and quotes the
    carried claim in its own spelling. One AI-powered finding is minted on the carried claim with
    the verbatim sent quote; the reduction is disclosed and no snippet loss is reported.
    A second challenge citing only the omitted claim mints nothing but reaches the agent as an
    advisory concern in the review summary, under its own rejection reason.
    """

    from yoetz.domain.receipts import (
        SEMANTIC_CHALLENGES_REJECTED_GAP,
        SEMANTIC_REVIEW_REFS_REDUCED_GAP,
        SEMANTIC_REVIEW_SNIPPET_INVALID_GAP,
    )

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    app = _App(semantic=True)
    first = ClaimRecordedPayload(clm(1), ClaimKind.MATERIAL, "Annotated with a custom model", ())
    second = ClaimRecordedPayload(clm(2), ClaimKind.MATERIAL, "Domain overlap holds", ())
    app.ledger.frozen = replace(
        app.ledger.frozen,
        case=make_case(claims={clm(1): record(first, 1), clm(2): record(second, 2)}),
    )
    sent_row = json.dumps({"payload": {"statement": "The report\u2019s model\nis custom."}})
    app.semantic_result = replace(
        _succeeded(
            SemanticJudgment(
                "challenges_returned",
                (
                    replace(
                        _reviewer_challenge(str(clm(1)), summary="Kept on the sent claim"),
                        cited_refs=tuple(sorted((str(clm(1)), str(clm(2))))),
                        snippet="The report's model is custom.",
                    ),
                    replace(
                        _reviewer_challenge(str(clm(2)), summary="Only the omitted claim"),
                        snippet="Domain overlap holds",
                    ),
                ),
                review_summary="Reviewed the annotations.",
            )
        ),
        case_citable_refs=frozenset({str(clm(1)), str(clm(2))}),
        provider_input_text_by_ref={str(clm(1)): (sent_row,)},
    )

    result = await execute_check_commit(app, _request("semantic_required", max_findings="4"))

    semantic_findings = [
        finding for finding in result.findings if finding.origin.value == "semantic_model_derived"
    ]
    assert [finding.summary for finding in semantic_findings] == ["Kept on the sent claim"]
    challenge = semantic_findings[0].challenge
    assert challenge is not None
    assert challenge.snippet == "The report\u2019s model\nis custom."
    gaps = set(result.coverage.known_gaps)
    assert SEMANTIC_REVIEW_REFS_REDUCED_GAP in gaps
    assert SEMANTIC_CHALLENGES_REJECTED_GAP in gaps
    assert SEMANTIC_REVIEW_SNIPPET_INVALID_GAP not in gaps
    # The recorded review summary (check_recorded, the check result, status and receipts) carries
    # the unanchored concern; its unproven quote never travels with it.
    summary = app.ledger.last_review_summary
    assert summary is not None
    assert summary.startswith("Reviewed the annotations.")
    assert "Only the omitted claim" in summary
    assert "Domain overlap holds" not in summary

    raw = diagnostics_module.diagnostic_log_path(root=tmp_path).read_text(encoding="ascii")
    accounting = [
        json.loads(line)
        for line in raw.splitlines()
        if line and json.loads(line)["operation"] == "semantic_review_accounting"
    ]
    assert len(accounting) == 1
    record_json = accounting[0]
    assert record_json["semantic_challenges_returned"] == 2
    assert record_json["semantic_candidates_accepted"] == 1
    assert record_json["semantic_challenges_rejected"] == 1
    assert record_json["semantic_rejected_ref_not_carried"] == 1
    assert record_json["semantic_review_refs_reduced"] == 1
    assert record_json["semantic_review_snippets_rejected"] == 0
    assert "Only the omitted claim" not in raw


@pytest.mark.anyio
async def test_capacity_failure_preserves_deterministic_result_and_precise_receipt_gap() -> None:
    from yoetz.domain.receipts import semantic_coverage_gap_code

    app = _App(semantic=True)
    app.semantic_result = FinalSemanticEvaluation(
        SemanticStatus.FAILED,
        SemanticReason.CASE_CAPACITY_EXCEEDED,
        case_reference_scope_reduced=True,
    )
    result = await execute_check_commit(app, _request("semantic_required"))
    assert result.semantic_reason is SemanticReason.CASE_CAPACITY_EXCEEDED
    assert result.semantic_provenance is None
    assert "semantic_case_capacity_exceeded" in result.coverage.known_gaps
    assert "semantic_reference_scope_reduced" in result.coverage.known_gaps
    assert (
        semantic_coverage_gap_code(result.semantic_status, result.semantic_reason)
        == "semantic_case_capacity_exceeded"
    )
    assert result.verdict.value == "incomplete_check"
    assert result.findings


@pytest.mark.anyio
async def test_wide_finding_prose_gap_reaches_the_committed_check_coverage() -> None:
    """A finding wider than one case item is a coverage fact, not a failed review (issue #858).

    The case builder omits the finding's prose and declares the gap on the packet; composition
    carries it here as a case-content gap. The committed check result is the single source the
    MCP response, CLI output, status and receipt all render, so folding it once here is what makes
    those surfaces agree.
    """

    app = _App(semantic=True)
    app.semantic_result = replace(
        _succeeded(SemanticJudgment("no_material_discrepancy", ())),
        case_content_gaps=(SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP,),
    )
    result = await execute_check_commit(app, _request("semantic_required"))
    assert result.semantic_status is SemanticStatus.SUCCEEDED
    assert SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP in result.coverage.known_gaps
    assert result.coverage.ledger_freshness.value == "partial"
    # Local findings are retained whatever the review could carry.
    assert result.findings


@pytest.mark.anyio
async def test_task_statement_gaps_reach_the_committed_check_coverage() -> None:
    """Criteria 1 and 7 (issue #908): a review without the task statement is never silent.

    Composition carries the packet's task-statement codes as case-content gaps; the committed
    check result is what the MCP response, CLI, status and receipt all render.
    """

    app = _App(semantic=True)
    app.semantic_result = replace(
        _succeeded(SemanticJudgment("no_material_discrepancy", ())),
        case_content_gaps=("task_statement_not_authorized", "task_statement_unavailable"),
    )
    result = await execute_check_commit(app, _request("semantic_required"))
    assert result.semantic_status is SemanticStatus.SUCCEEDED
    assert {"task_statement_not_authorized", "task_statement_unavailable"} <= set(
        result.coverage.known_gaps
    )
    assert result.coverage.ledger_freshness.value == "partial"


@pytest.mark.anyio
async def test_native_resolution_omission_survives_successful_semantic_check() -> None:
    app = _App(semantic=True)
    app.semantic_result = replace(
        _succeeded(SemanticJudgment("no_material_discrepancy", ())),
        case_content_gaps=(
            "captured_object_unavailable",
            "content_capture_unavailable",
            "content_unselected",
        ),
    )
    result = await execute_check_commit(app, _request("semantic_if_configured"))
    assert {"captured_object_unavailable", "content_unselected"} <= set(result.coverage.known_gaps)
    assert result.verdict.value != "no_issue_detected"


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["semantic_if_configured", "semantic_required"])
async def test_insufficient_packet_is_nonblocking_but_never_clean(mode: str) -> None:
    app = _App(semantic=True)
    app.ledger.frozen = replace(app.ledger.frozen, case=make_case())
    app.semantic_result = _succeeded(SemanticJudgment("insufficient_packet", ()))
    checked = await execute_check_commit(app, _request(mode))
    assert checked.findings == ()
    assert "semantic_packet_insufficient" in checked.coverage.known_gaps
    assert checked.verdict.value == "insufficient_coverage"
    assert checked.semantic_status is SemanticStatus.SUCCEEDED
    # The gap is in the committed result, so replay/CLI/MCP do not have to infer it from prose.
    assert app.ledger.last_ranked is not None
    assert "semantic_packet_insufficient" in app.ledger.last_ranked.coverage.known_gaps


_OUTSIDE_REF = "evd_99999999-0000-4000-8000-000000000001"


def _missing_case(*, pending: bool = False, supplied: bool = False) -> DeterministicCase:
    """A claimed completion, optionally with a prior review's request and an answer since."""

    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    claims: dict[ClaimId, ClaimProjectionRecord] = {
        clm(1): record(
            ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "Lookups repaired", ()), 3
        )
    }
    if supplied:
        # The agent answers the named claim: the output, and a claim correction that cites it
        # in place of the unsupported claim, so the output is bound to the named target.
        claims[clm(1)] = claim_record(
            ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "Lookups repaired", ()),
            3,
            superseded_by_claim_id=clm(61),
        )
        claims[clm(61)] = record(
            ClaimRecordedPayloadV1_1(
                clm(61),
                ClaimKind.COMPLETION,
                "Lookups repaired",
                (evd(60),),
                supersedes_claim_refs=(clm(1),),
            ),
            61,
        )
        evidence[evd(60)] = evidence_record(
            EvidenceRecordedPayload(
                evd(60),
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-09-27T00:00:00.000Z"),
                description="12 passed in 0.31s",
            ),
            60,
        )
    case = make_case(claims=claims, evidence=evidence, extra_refs=(clm(1),))
    if not pending:
        return case
    return replace(
        case,
        projection=replace(
            case.projection,
            pending_missing_for_assessment=PendingMissingForAssessment(
                evt(50),
                50,
                (
                    MissingForAssessmentItem(
                        "verification_output", (str(clm(1)),), "agent_suppliable"
                    ),
                ),
            ),
        ),
    )


@pytest.mark.anyio
async def test_insufficient_packet_names_each_missing_item_as_a_check_limitation() -> None:
    """Issue #907: the reviewer's named items reach the agent, fenced and classified by Yoetz."""

    app = _App(semantic=True)
    app.ledger.frozen = replace(app.ledger.frozen, case=_missing_case())
    judgment = SemanticJudgment(
        "insufficient_packet",
        (),
        missing_for_assessment=(
            MissingForAssessment("verification_output", (str(clm(1)),), "test output absent"),
            MissingForAssessment("command_identity", (), "which command ran is not shown"),
            MissingForAssessment("current_diff_for_path", (_OUTSIDE_REF,), "invented target"),
        ),
    )
    app.semantic_result = replace(
        _succeeded(judgment), unsuppliable_missing_kinds=("command_identity",)
    )
    checked = await execute_check_commit(app, _request("semantic_required"))

    # A named missing item is never a finding; only the local claim rule may fire here.
    assert all(finding.provenance is None for finding in checked.findings)
    assert checked.verdict.value != "no_issue_detected"
    assert [
        (item.kind, item.target_refs, item.availability) for item in checked.missing_for_assessment
    ] == [
        ("command_identity", (), "structurally_unavailable_on_this_host"),
        ("verification_output", (str(clm(1)),), "agent_suppliable"),
    ]
    gaps = set(checked.coverage.known_gaps)
    assert {
        "semantic_packet_insufficient",
        "semantic_missing_agent_suppliable",
        "semantic_missing_structurally_unavailable",
        "semantic_missing_items_rejected",
    } <= gaps
    # Nothing the reviewer invented reaches the record.
    assert _OUTSIDE_REF not in {
        ref for item in checked.missing_for_assessment for ref in item.target_refs
    }
    assert app.ledger.last_missing == checked.missing_for_assessment
    assert app.ledger.last_conclusion == "insufficient_packet"
    wire = check_internal_json(checked)
    assert wire["missing_for_assessment"] == (
        {
            "availability": "structurally_unavailable_on_this_host",
            "kind": "command_identity",
            "target_refs": (),
        },
        {
            "availability": "agent_suppliable",
            "kind": "verification_output",
            "target_refs": (str(clm(1)),),
        },
    )


@pytest.mark.anyio
async def test_missing_item_targets_are_fenced_to_what_the_packet_showed() -> None:
    """Greptile P2 on #940: a target in the frozen case but not in the packet is not citable.

    The reviewer was shown only the packet's ``citable_refs``; like #905's cited refs, a missing
    item's targets are trimmed to them, and an item left with no target is dropped and disclosed.
    """

    app = _App(semantic=True)
    app.ledger.frozen = replace(app.ledger.frozen, case=_missing_case(supplied=True))
    assert evd(60) in app.ledger.frozen.case.allowed_ids
    judgment = SemanticJudgment(
        "insufficient_packet",
        (),
        missing_for_assessment=(
            MissingForAssessment(
                "verification_output", (str(clm(1)), str(evd(60))), "test output absent"
            ),
            MissingForAssessment("current_diff_for_path", (str(evd(60)),), "diff not shown"),
        ),
    )
    app.semantic_result = replace(_succeeded(judgment), case_citable_refs=frozenset({str(clm(1))}))
    checked = await execute_check_commit(app, _request("semantic_required"))

    assert [(item.kind, item.target_refs) for item in checked.missing_for_assessment] == [
        ("verification_output", (str(clm(1)),))
    ]
    assert "semantic_missing_items_rejected" in checked.coverage.known_gaps


@pytest.mark.anyio
async def test_insufficient_packet_naming_nothing_records_none_and_says_so() -> None:
    """A 1.0.0-shape reply (local model, prompt-only host) is read backward, never as named."""

    app = _App(semantic=True)
    app.ledger.frozen = replace(app.ledger.frozen, case=_missing_case())
    app.semantic_result = _succeeded(SemanticJudgment("insufficient_packet", ()))
    checked = await execute_check_commit(app, _request("semantic_required"))
    assert checked.missing_for_assessment == ()
    gaps = set(checked.coverage.known_gaps)
    assert "semantic_packet_insufficient" in gaps
    assert {gap for gap in gaps if gap.startswith("semantic_missing_")} == {
        "semantic_missing_items_rejected"
    }
    assert "missing_for_assessment" not in check_internal_json(checked)


@pytest.mark.anyio
@pytest.mark.parametrize("cites_new_material", [False, True])
async def test_supplied_item_is_not_listed_again_unless_the_reviewer_cites_the_new_material(
    cites_new_material: bool,
) -> None:
    """Scripted provider: the agent answered the prior request, the reviewer asks again."""

    app = _App(semantic=True)
    app.ledger.frozen = replace(app.ledger.frozen, case=_missing_case(pending=True, supplied=True))
    targets = (str(clm(1)), str(evd(60))) if cites_new_material else (str(clm(1)),)
    app.semantic_result = _succeeded(
        SemanticJudgment(
            "insufficient_packet",
            (),
            missing_for_assessment=(
                MissingForAssessment("verification_output", targets, "still cannot assess"),
            ),
        )
    )
    checked = await execute_check_commit(app, _request("semantic_required"))

    gaps = set(checked.coverage.known_gaps)
    assert "semantic_packet_insufficient" in gaps
    if cites_new_material:
        assert [item.target_refs for item in checked.missing_for_assessment] == [
            tuple(sorted(targets, key=str.encode))
        ]
        assert "semantic_missing_already_supplied" not in gaps
    else:
        # The repeat is dropped and disclosed: the agent sees nothing it can add for it.
        assert checked.missing_for_assessment == ()
        assert "semantic_missing_already_supplied" in gaps
        assert "semantic_missing_agent_suppliable" not in gaps


@pytest.mark.anyio
async def test_unanswered_prior_request_may_be_listed_again() -> None:
    app = _App(semantic=True)
    app.ledger.frozen = replace(app.ledger.frozen, case=_missing_case(pending=True))
    app.semantic_result = _succeeded(
        SemanticJudgment(
            "insufficient_packet",
            (),
            missing_for_assessment=(
                MissingForAssessment("verification_output", (str(clm(1)),), "still absent"),
            ),
        )
    )
    checked = await execute_check_commit(app, _request("semantic_required"))
    assert [item.kind for item in checked.missing_for_assessment] == ["verification_output"]
    assert "semantic_missing_already_supplied" not in checked.coverage.known_gaps


@pytest.mark.anyio
async def test_hook_captured_output_since_the_request_is_not_an_answer_to_it() -> None:
    """Issue #907: hook capture records every tool call; only agent-published material answers."""

    evidence = {
        evd(60): evidence_record(
            EvidenceRecordedPayload(
                evd(60),
                EvidenceKind.OTHER,
                EvidenceImmutability.IMMUTABLE_SNAPSHOT,
                timestamp_from_string("2026-09-27T00:00:00.000Z"),
                captured_object_id=object_id("obj_00000000-0000-4000-8000-000000000060"),
                content_digest="sha256:" + "a" * 64,
                description="Observation-captured tool_output bytes part=1/1",
                digest_binding=EvidenceDigestBinding(
                    subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
                    content_availability=EvidenceContentAvailability.CAPTURED,
                    byte_count=10,
                    provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
                ),
            ),
            60,
        )
    }
    case = make_case(
        claims={
            clm(1): record(
                ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "Lookups repaired", ()), 3
            )
        },
        evidence=evidence,
        extra_refs=(clm(1),),
    )
    case = replace(
        case,
        projection=replace(
            case.projection,
            pending_missing_for_assessment=PendingMissingForAssessment(
                evt(50),
                50,
                (
                    MissingForAssessmentItem(
                        "verification_output", (str(clm(1)),), "agent_suppliable"
                    ),
                ),
            ),
        ),
    )
    app = _App(semantic=True)
    app.ledger.frozen = replace(app.ledger.frozen, case=case)
    app.semantic_result = _succeeded(
        SemanticJudgment(
            "insufficient_packet",
            (),
            missing_for_assessment=(
                MissingForAssessment("verification_output", (str(clm(1)),), "still absent"),
            ),
        )
    )
    checked = await execute_check_commit(app, _request("semantic_required"))
    assert [item.kind for item in checked.missing_for_assessment] == ["verification_output"]
    assert "semantic_missing_already_supplied" not in checked.coverage.known_gaps


@pytest.mark.anyio
@pytest.mark.parametrize(
    "diff_path", ["src/a.py", "src/b.py", "/work/repo/src/a.py", "/other/repo/src/a.py"]
)
async def test_a_fresh_diff_answers_a_captured_edit_only_for_the_path_it_records(
    diff_path: str,
) -> None:
    """R940-01: the composed review hands the check each capture's paths, compared in process."""

    captured = EvidenceRecordedPayload(
        evd(1),
        EvidenceKind.OTHER,
        EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        timestamp_from_string("2026-09-27T00:00:00.000Z"),
        captured_object_id=object_id("obj_00000000-0000-4000-8000-000000000001"),
        content_digest="sha256:" + "a" * 64,
        description="Observation-captured tool_input bytes part=1/1",
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
            content_availability=EvidenceContentAvailability.CAPTURED,
            byte_count=10,
            provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
        ),
    )
    diff = EvidenceRecordedPayload(
        evd(61),
        EvidenceKind.COMMAND_OUTPUT,
        EvidenceImmutability.METADATA_ONLY,
        timestamp_from_string("2026-09-27T00:00:00.000Z"),
        description="diff --git a/x b/x",
    )
    case = make_case(
        evidence={evd(1): evidence_record(captured, 10), evd(61): evidence_record(diff, 61)},
        actions={
            act(60): record(
                ActionRecordedPayload(
                    act(60), ActionKind.COMMAND, "Show the diff", command=f"git diff {diff_path}"
                ),
                60,
            )
        },
        results={
            res(62): record(
                ResultRecordedPayload(
                    res(62), act(60), ResultOutcome.SUCCESS, evidence_refs=(evd(61),)
                ),
                62,
            )
        },
        extra_refs=(evd(1), evd(61), act(60), res(62)),
    )
    request = MissingForAssessmentItem("current_diff_for_path", (str(evd(1)),), "agent_suppliable")
    case = replace(
        case,
        projection=replace(
            case.projection,
            pending_missing_for_assessment=PendingMissingForAssessment(evt(50), 50, (request,)),
        ),
    )
    app = _App(semantic=True)
    app.ledger.frozen = replace(app.ledger.frozen, case=case)
    app.semantic_result = replace(
        _succeeded(
            SemanticJudgment(
                "insufficient_packet",
                (),
                missing_for_assessment=(
                    MissingForAssessment("current_diff_for_path", (str(evd(1)),), "still absent"),
                ),
            )
        ),
        case_captured_edit_paths={str(evd(1)): frozenset({"src/a.py"})},
        case_workspace_root="/work/repo",
    )
    checked = await execute_check_commit(app, _request("semantic_required"))
    gaps = set(checked.coverage.known_gaps)
    if diff_path in {"src/a.py", "/work/repo/src/a.py"}:
        assert checked.missing_for_assessment == ()
        assert "semantic_missing_already_supplied" in gaps
    else:
        assert [item.target_refs for item in checked.missing_for_assessment] == [(str(evd(1)),)]
        assert "semantic_missing_already_supplied" not in gaps


def test_withheld_item_becomes_the_capture_baseline_of_raised_ai_findings() -> None:
    """Issue #982 review: the item-withheld gap must reach the finding baseline in production.

    Composition puts it in ``case_content_gaps`` (``_egress_case_content_gaps``); this is the
    set the check stamps on every AI-powered finding the review raises.
    """

    from yoetz.application.check import semantic_capture_baseline_gaps
    from yoetz.domain.receipts import SEMANTIC_REVIEW_ITEM_WITHHELD_GAP

    result = replace(
        _succeeded(SemanticJudgment("no_material_discrepancy", ())),
        semantic_withheld_item_ids=("excerpt-heuristic",),
        case_content_gaps=(SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,),
    )
    assert SEMANTIC_REVIEW_ITEM_WITHHELD_GAP in semantic_capture_baseline_gaps(result)


# --- issue #1012: optional bounded wait for this task's hook observations ---------------------


@pytest.mark.anyio
async def test_await_observations_absent_keeps_digest_and_result_bytes() -> None:
    from yoetz.application.check import _request_digest  # pyright: ignore[reportPrivateUsage]
    from yoetz.ports.ledger import CheckObservationsAwaited
    from yoetz.protocol.canonical import canonical_digest, canonical_encode

    plain = _request()
    flagged = CheckRequest.model_validate(
        {**plain.model_dump(mode="json", exclude_none=True), "await_observations": True}
    )
    scope = check_module.normalize_check_scope(plain)
    packs = check_module._selected_packs(plain)  # pyright: ignore[reportPrivateUsage]
    digest = _request_digest(plain, scope, packs, route_profile="policy")
    # The pre-field digest: the request dump with no await_observations member at all.
    legacy: dict[str, Any] = plain.model_dump(mode="json", by_alias=True)
    legacy.pop("await_observations")
    legacy["scope"] = {"claim_ids": scope.claim_ids, "obligation_ids": scope.obligation_ids}
    legacy["policy_packs"] = packs
    legacy["route_profile"] = "policy"
    assert digest == canonical_digest(legacy)
    # The flag is outside the operation identity: a recovery may set or omit it.
    assert _request_digest(flagged, scope, packs, route_profile="policy") == digest

    result = await execute_check(_App(), plain)
    body = check_internal_json(result)
    assert "observations_awaited" not in body
    assert result.observations_awaited is None

    awaited = replace(result, observations_awaited=CheckObservationsAwaited("bounded_timeout", 2))
    awaited_body = check_internal_json(awaited)
    assert awaited_body["observations_awaited"] == {
        "state": "bounded_timeout",
        "pending_count": "2",
    }
    without = dict(awaited_body)
    del without["observations_awaited"]
    assert canonical_encode(without) == canonical_encode(body)


@pytest.mark.anyio
async def test_application_check_attaches_only_a_supplied_wait_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.application.service import Application
    from yoetz.ports.ledger import CheckObservationsAwaited

    canned = await execute_check(_App(), _request())

    async def fake_execute_check(*_args: object, **_kwargs: object) -> CheckCommitResult:
        return canned

    async def noop(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(check_module, "execute_check", fake_execute_check)
    host = SimpleNamespace(
        _require_repository_route=noop,
        _renew_activity_session=noop,
        verification_policy=VerificationPolicy(),
        change_capture=None,
    )
    plain = await Application.check(cast(Any, host), _request())
    assert plain is canned
    complete = CheckObservationsAwaited("complete", 0)
    attached = await Application.check(cast(Any, host), _request(), observations_awaited=complete)
    assert isinstance(attached, CheckCommitResult)
    assert attached.observations_awaited == complete
    assert replace(attached, observations_awaited=None) == canned


class _UnrepresentablePathCapturePort(_MetadataOnlyCapturePort):
    def capture_metadata(self, workspace: str, base: object) -> CheckChangeMetadata:
        return CheckChangeMetadata(
            base="task_start",
            entries=self.entries,
            tracked_files=0,
            untracked_files=len(self.entries) + 1,
            omitted_files=1,
            truncated=True,
            base_commit="a" * 40,
            unrepresentable_files=1,
        )


@pytest.mark.anyio
async def test_a_skipped_line_break_path_is_disclosed_by_code_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1019: the capture stays usable; the check names the skipped path's class, never it."""

    from yoetz.domain.receipts import (
        CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP,
        CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
        check_time_change_gap_sentence,
    )
    from yoetz.kernel.closure_readiness import GAP_CLASSIFICATION, GapClass

    app = _App()
    app.change_capture = _UnrepresentablePathCapturePort(
        (ChangeMetadataEntry("A", "out.txt", untracked=True),)
    )
    app.start_catalog = _StructuralStartCatalog()
    source = CheckWorkspaceSource("/workspace", "hmac-sha256:" + "a" * 64)
    monkeypatch.setattr(check_module, "current_check_workspace_source", lambda: source)

    result = await execute_check_commit(app, _request(max_findings="4"))

    assert CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP in result.coverage.known_gaps
    assert CHECK_TIME_CHANGE_UNAVAILABLE_GAP not in result.coverage.known_gaps
    assert (
        GAP_CLASSIFICATION[CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP]
        is GapClass.STANDING_LIMITATION
    )
    sentence = check_time_change_gap_sentence(CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP)
    assert sentence is not None and "line break" in sentence
