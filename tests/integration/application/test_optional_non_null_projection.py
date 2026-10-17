"""Unset optional non-null leaves must project as absence, never as JSON null.

2026-07-28 run 4 dogfood: an obligation published without ``acceptance_criteria`` broke the
default ``status view=compact`` and ``status view=obligations``. The ledger already omitted the
unset key, but ``StatusInternalResult.as_json`` dumped the page with defaulted Nones reintroduced,
and ``_public_model`` re-validated that null into the closed wire models, which reject it
(``optional_field_must_not_be_null``). The same class previously hit accepted-event ``summary``
(PR #50) and respond reason/waiver fields.

These cases pin the obligation defect end to end, keep the three content states distinguishable
(text / omission marker / total absence), reject explicit nulls at the model boundary, and walk
every public *result* model that declares ``optional_non_null_fields`` so a new member of the class
is visibly missing from the inventory table rather than silently unswept.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from pydantic import BaseModel, ValidationError

import finishup.protocol.models as protocol_models
from builders.projection_workflow import (
    ProjectionCase,
    build_projection_application,
    frontier_json,
    project_case,
    request_base,
)
from builders.start_application import protocol_id, start_request
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.application.respond import RespondInternalResult
from finishup.application.service import (
    Application,
    ClientProjectionContext,
    ControlProjectionBinding,
    ProjectionRenderMode,
)
from finishup.domain.privacy import (
    CandidateContext,
    ConsentSource,
    LocalDisclosureApproved,
    LocalDisclosureBlocked,
    LocalDisclosureOmission,
    LocalDisclosureReceipt,
    PrivacyOutcome,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptTransformations,
)
from finishup.domain.values import Frontier, review_input_continuation
from finishup.ports.control import ControlClientKind, ControlMethod
from finishup.ports.ledger import CheckAwaitingHuman, CheckCommitResult, CheckVersionSlice
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.coverage import PublicationChannel, coverage_for_channel, coverage_to_json
from finishup.protocol.models import (
    PUBLISH_RESUMED_CALL_NOTICE_TEXT,
    CheckAwaitingHumanModel,
    CheckChecklistCountsModel,
    CheckChecklistItemModel,
    CheckContinuationModel,
    CheckInspectionEvidenceSourceModel,
    CheckInspectionMissingModel,
    CheckInspectionModel,
    CheckInspectionObservedActionModel,
    CheckInspectionObservedModel,
    CheckInspectionRemainingModel,
    CheckOverallNextModel,
    CheckProjectedFindingModel,
    CheckRequest,
    CheckResultModel,
    CheckReviewModeModel,
    CheckSuccessModel,
    CheckVerifiedItemModel,
    ChildDependencySnapshotModel,
    ChildFindingSnapshotModel,
    DataCategory,
    FactLineageModel,
    ProjectTextRefModel,
    PublicErrorModel,
    PublishWorkAcceptedEventModel,
    PublishWorkAcceptedProjectionUnavailableModel,
    PublishWorkDryRunModel,
    PublishWorkReplayNoticeModel,
    PublishWorkRequest,
    PublishWorkSuccessModel,
    ReadGuidanceSuccessModel,
    RespondClosureAfterModel,
    RespondEvidenceSummaryModel,
    RespondResponseModel,
    RespondSuccessModel,
    ReviewInputManifestModel,
    SemanticRedactedValueModel,
    StartSuccessModel,
    StatusAdviceItemModel,
    StatusBlockedObligationModel,
    StatusBriefSuccessModel,
    StatusCheckCauseModel,
    StatusClosureReadinessModel,
    StatusClosureStateModel,
    StatusCompactItemModel,
    StatusCompactObligationModel,
    StatusEvidenceItemModel,
    StatusFindingItemModel,
    StatusFindingsPageModel,
    StatusHistoryItemV14Model,
    StatusLineageChildModel,
    StatusObligationItemModel,
    StatusObservedRunModel,
    StatusOperationPageModel,
    StatusPredictedReasonModel,
    StatusProjectDetectionModel,
    StatusProjectPageModel,
    StatusRequest,
    StatusRequestedItemModel,
    StatusResultItemModel,
    StatusReviewModeModel,
    StatusSemanticProgressModel,
    StatusStructuralSubjectStateModel,
    StatusVersionSliceModel,
    public_model_to_wire,
)

pytestmark = pytest.mark.anyio

# Private base is not re-exported; resolve by getattr like other protocol tests.
_CLOSED_MODEL = cast(type[BaseModel], getattr(protocol_models, "_ClosedModel"))

_DIGEST = "sha256:" + "a" * 64
_WORKSPACE = "hmac-sha256:" + "8" * 64


def _version_slice_payload() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "engine_version": "0.1.0",
        "projection_version": "yoetz/0.1.0",
        "object_format": "yoetz-object/1",
        "storage_schema": "1",
        "python_version": "3.14.6",
        "apsw_version": "3.53.3.1",
        "sqlite_version": "3.53.3",
        "sqlite_source_id": "sqlite-source",
        "policy_packs": ("work-integrity/0.3.0",),
        "provider_profiles": (),
    }


def _privacy_projection_payload() -> dict[str, object]:
    return {
        "sink": "agent_context",
        "local_disclosure_receipt_id": protocol_id("egr_", 2905),
        "policy_id": protocol_id("pvy_", 2906),
        "policy_version": "1",
        "policy_digest": _DIGEST,
        "included_categories": [],
        "blocked_categories": [],
        "omitted_pointers": [],
        "projection_commitment": _WORKSPACE,
    }


def _check_awaiting_human_payload() -> dict[str, object]:
    request_id = protocol_id("req_", 2907)
    frontier = {"sequence": "1", "head_digest": _DIGEST}
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "ok": True,
        "state": "awaiting_human",
        "task_id": protocol_id("tsk_", 2908),
        "session_id": protocol_id("ses_", 2909),
        "writer_id": protocol_id("wri_", 2910),
        "subject_frontier": frontier,
        "result_frontier": frontier,
        "semantic_status": "awaiting_human",
        "semantic_reason": "human_approval_required",
        "continuation": {
            "kind": "repository_privacy_setup",
            "command": ["finishup", "--privacy"],
            "replay_request_id": request_id,
            "instruction": "Use the trusted local privacy ceremony, then replay this exact request.",
        },
        "versions": {
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "yoetz/0.1.0",
            "policy_packs": ["work-integrity/0.3.0"],
        },
        "privacy_projection": _privacy_projection_payload(),
    }


def _status_history_v14_payload() -> dict[str, object]:
    return {
        "event_id": protocol_id("evt_", 2911),
        "schema_name": "check_recorded",
        "schema_version": "1.3.0",
        "actor_id": "harness:test",
        "publication_channel": "cooperative_mcp",
        "ingestion_sequence": "1",
        "occurred_at": "2026-07-28T12:00:00.000Z",
        "accepted_at": "2026-07-28T12:00:00.000Z",
        "occurred_at_consistency": "within_forward_skew_allowance",
        "projection_status": "projected",
        "summary_code": "check_recorded",
    }


# Every public *result* model that declares ``optional_non_null_fields``. Request and filter models
# are caller-supplied and already reject null at parse time; they are intentionally absent here.
# A new result model that joins the set without a row in this table fails the inventory test.
_RESULT_OPTIONAL_NON_NULL: tuple[tuple[type[BaseModel], frozenset[str]], ...] = (
    (CheckContinuationModel, frozenset({"pending_id", "expires_at"})),
    (RespondSuccessModel, frozenset({"closure_after"})),  # tb4n3 RC-7
    (RespondClosureAfterModel, frozenset({"limitation"})),
    (
        CheckSuccessModel,
        frozenset(
            {
                "children",
                "advisory_notes",
                "missing_for_assessment",
                "finding_checklist",
                "semantic_withheld_items",
                "review_input_manifest",
                "semantic_conclusion",
                "review_summary",
                "verified",
                "totals",
                "overall_next",
                # Issue #982 PL2-1 and issue #1012.
                "semantic_redacted_values",
                "observations_awaited",
                # Issue #986 (E2): written only as ``false``.
                "semantic_route_required",
                # ADR-045: absent when the check carries no derived fact.
                "fact_lineage",
                # ADR-049: absent when the owner's conversation setting was not read.
                "review_mode",
            }
        ),
    ),
    # ADR-049: a reason only on a check asked for AI-powered review that ran local; a switch id
    # only when the conversation's own switch chose the mode.
    (CheckReviewModeModel, frozenset({"local_reason", "switch_event_id"})),
    (StatusReviewModeModel, frozenset({"local_reason", "switch_event_id", "switch_sequence"})),
    (CheckAwaitingHumanModel, frozenset({"specification_preflight"})),
    # Issue #1048 (ADR-047): the read-only inspection branch.
    (CheckInspectionModel, frozenset({"observations_awaited"})),
    (CheckInspectionRemainingModel, frozenset({"predicted_conclusion"})),
    (CheckInspectionMissingModel, frozenset({"item_indexes"})),
    (CheckInspectionObservedModel, frozenset({"last_check_frontier"})),
    (
        CheckInspectionObservedActionModel,
        frozenset({"tool_name", "write_scope", "outcome", "exit_status", "command_commitment"}),
    ),
    (CheckInspectionEvidenceSourceModel, frozenset({"command_commitment", "outcome"})),
    # Issue #1020: present only when non-zero.
    (
        CheckChecklistCountsModel,
        frozenset(
            {
                "disputed_after_rebuttal",
                # ADR-046: the five closure counters travel together.
                "to_do",
                "awaiting_ruling",
                "unmet",
                "disclosed",
                "to_disclose",
            }
        ),
    ),
    # ADR-046: who owes the next move on a checklist row, and the predicted receipt conclusion.
    (CheckChecklistItemModel, frozenset({"closure_class", "closure_basis"})),
    (CheckOverallNextModel, frozenset({"predicted_conclusion"})),
    (StatusPredictedReasonModel, frozenset({"since_frontier"})),
    (
        ChildDependencySnapshotModel,
        frozenset(
            {
                "child_frontier",
                "child_check_id",
                "child_receipt_id",
                "membership_generation",
            }
        ),
    ),
    (ChildFindingSnapshotModel, frozenset({"resolution_event_id", "self_verified"})),
    (StatusLineageChildModel, frozenset({"self_verified_finding_count"})),
    (ProjectTextRefModel, frozenset({"envelope_digest"})),
    (PublishWorkAcceptedEventModel, frozenset({"summary"})),
    # #985 publish notices and blocker confirmation, absent when nothing applies; tb4n5 action
    # notices, absent when every action the batch recorded has a result naming it.
    # Issue #1084: server_filled is absent for a complete caller body.
    (
        PublishWorkSuccessModel,
        frozenset({"blocker_notices", "action_notices", "server_filled", "replay_notice"}),
    ),
    (PublishWorkDryRunModel, frozenset({"blocker_notices", "action_notices", "server_filled"})),
    # Issue #1084 (review R1): the reduced success keeps provenance and the resumed-call notice.
    (PublishWorkAcceptedProjectionUnavailableModel, frozenset({"server_filled", "replay_notice"})),
    # Issue #1084: the brief status body omits whatever it does not need, and its closure state
    # keeps readiness's own optional checklist leaves.
    (
        StatusBriefSuccessModel,
        frozenset(
            {
                "requested_frontier",
                "head_frontier",
                "subject_frontier",
                "projection_lag",
                "projection_version",
                "rebuild_state",
                "coverage",
                "import_status",
                "closure_readiness",
                "closure_state",
                "credential_heuristic",
                "review_mode",
            }
        ),
    ),
    (StatusClosureStateModel, frozenset({"state", "agent_actionable"})),
    (StatusBlockedObligationModel, frozenset({"confirmation", "confirmation_event_id"})),
    (StatusCheckCauseModel, frozenset({"tool"})),
    (PublicErrorModel, frozenset({"safe_details"})),
    (
        ReadGuidanceSuccessModel,
        frozenset(
            {
                "document_id",
                "revision",
                "digest",
                "total_byte_count",
                "page",
                "page_size",
                "page_offset",
                "page_byte_count",
                "page_count",
                "complete",
                "continuation",
                "sections",
            }
        ),
    ),
    (RespondEvidenceSummaryModel, frozenset({"description"})),
    (
        RespondResponseModel,
        frozenset({"reason", "waiver_scope", "waiver_expiry", "duplicate_of_finding_id"}),
    ),
    (
        StartSuccessModel,
        frozenset({"attach_handle", "parent_task_id", "depth", "origin", "acceptance"}),
    ),
    (
        StatusClosureReadinessModel,
        frozenset(
            {
                "state",
                "gap_classification_version",
                "agent_actionable",
                "standing_limitations",
                "acknowledged_not_done",
                "acknowledged_not_done_count",
                "blocked_obligations",
                "limitation_refs_required",
                "limitation_refs_required_count",
                "acknowledged_obligation_count",
                "check_cause",
                # ADR-046: the one closure verdict.
                "predicted_receipt",
                "finding_counts",
                "obligation_counts",
                "rechecks",
                "awaiting_ruling_findings",
                # ADR-045: absent when the readiness lists no derived fact.
                "fact_lineage",
                # #1044: absent unless a delivered file names an undeclared one.
                "undeclared_references",
                # #1079: absent unless a flagged obligation has a recorded verification link.
                "admissible_verification",
                # Omitted by an earlier build. "0" is a computed empty material frontier.
                "closing_material_frontier",
            }
        ),
    ),
    (
        FactLineageModel,
        frozenset(
            {
                "obligation_id",
                "item_index",
                "check_event_id",
                "frontier",
                "prior_event_id",
                "prior_frontier",
                "prior_size_bytes",
                "prior_lines",
                "now_size_bytes",
                "now_lines",
                "proof",
                "basis",
                "accepted_by",
            }
        ),
    ),
    (StatusCompactObligationModel, frozenset({"acceptance_criteria"})),
    (
        StatusFindingItemModel,
        frozenset(
            {
                "todo_state",
                "review_rounds",
                "finding_frontier",
                "challenge",
                "duplicate_of_finding_id",
                "closure_class",
                "closure_basis",
                "next_actions",
            }
        ),
    ),
    (CheckProjectedFindingModel, frozenset({"challenge"})),
    (CheckVerifiedItemModel, frozenset({"requirement_or_claim", "snippet"})),
    (StatusCompactItemModel, frozenset({"latest_check_test_edits", "latest_check"})),
    (StatusFindingsPageModel, frozenset({"attempt_budget"})),
    # Issue #1084 (review R7): a service-recorded event time is labelled on the history row.
    (StatusHistoryItemV14Model, frozenset({"review_input_manifest", "occurred_at_source"})),
    (
        ReviewInputManifestModel,
        frozenset({"review_phase", "omitted_item_total", "follow_up_round"}),
    ),
    (
        StatusObligationItemModel,
        frozenset(
            {
                "acceptance_criteria",
                "acknowledged_not_done_reason",
                "in_current_plan",
                "closure_class",
                "closure_basis",
            }
        ),
    ),
    (StatusRequestedItemModel, frozenset({"role"})),
    (StatusObservedRunModel, frozenset({"tool_name", "command_commitment", "exit_status"})),
    (StatusResultItemModel, frozenset({"observed_run"})),
    (
        StatusAdviceItemModel,
        frozenset(
            {
                "coordination_project_id",
                "coordination_detection_id",
                "coordination_membership_generation",
                "coordination_counterpart_task_id",
                "coordination_resource_paths",
            }
        ),
    ),
    (StatusProjectDetectionModel, frozenset({"resource_paths"})),
    (
        StatusOperationPageModel,
        frozenset(
            {
                "semantic_progress",
                "admission",
                "semantic_withheld_items",
                "semantic_redacted_values",
                "server_filled",
            }
        ),
    ),
    (SemanticRedactedValueModel, frozenset({"source_ref"})),
    (
        StatusSemanticProgressModel,
        frozenset({"remaining_ms", "terminal_outcome", "terminal_reason"}),
    ),
    (StatusProjectPageModel, frozenset({"title", "description", "title_ref", "description_ref"})),
    # Issue #914: the service always fills it; optional so earlier 0.3 rows still validate.
    (StatusEvidenceItemModel, frozenset({"publication_channel"})),
    (StatusStructuralSubjectStateModel, frozenset({"tree_digest", "diff_digest"})),
    (StatusVersionSliceModel, frozenset({"route_profile"})),
)

# Models that appear only on the request/filter surface — not projected result bodies.
_REQUEST_SIDE_OPTIONAL_NON_NULL = frozenset(
    {
        "ActorAssertionModel",
        "SubjectStateRefModel",
        "StartRequestModel",
        "StartRequest",
        "PublishWorkRequestModel",
        "PublishWorkRequest",
        "CheckRequestModel",
        "CheckRequest",
        "RespondRequestModel",
        "RespondRequest",
        "StatusRequestModel",
        "StatusRequest",
        "StatusAssignmentFilterModel",
        "StatusCandidateFindingsFilterModel",
        "StatusEvidenceFilterModel",
        "StatusFindingsFilterModel",
        "StatusHistoryFilterModel",
        "StatusResultsFilterModel",
        "ReadGuidanceRequest",
        "ReadGuidanceRequestModel",
        "StatusObligationsFilterModel",
    }
)


class _BlockEverything:
    """Refuse every content leaf, exactly as an unauthorized local disclosure does."""

    async def prepare_local_disclosure(
        self, candidate: CandidateContext
    ) -> LocalDisclosureApproved | LocalDisclosureBlocked:
        """Block actual content while approving candidates with no content leaves."""

        sink = candidate.local_sink
        assert sink is not None
        proposal_id = protocol_id("ppr_", 801)
        policy = ReceiptPolicyBinding(protocol_id("pvy_", 802), 1, _DIGEST, _DIGEST)
        omissions = tuple(
            sorted(
                (
                    LocalDisclosureOmission(
                        item.origin_ref,
                        item.category,
                        "local_disclosure_not_authorized",
                    )
                    for item in candidate.items
                ),
                key=lambda item: item.json_pointer.encode(),
            )
        )
        blocked = tuple(
            sorted({item.category for item in omissions}, key=lambda value: value.value)
        )
        receipt = LocalDisclosureReceipt(
            "1.0.0",
            protocol_id("egr_", 803),
            candidate.request_id,
            proposal_id,
            sink,
            PrivacyOutcome.COMPLETED,
            datetime(2026, 7, 28, 12, 0, tzinfo=UTC),
            candidate.scope,
            candidate.purpose,
            policy,
            ConsentSource.BASELINE_POLICY,
            (),
            blocked,
            ReceiptCounts(0, 0, 0, 0, 0, 0, 0),
            ReceiptTransformations(0, 0, 0),
            ReceiptSecretScan("1.0.0", _DIGEST, 0, True),
            None,
            1,
        )
        if not omissions:
            return LocalDisclosureApproved(
                proposal_id,
                candidate.request_id,
                sink,
                candidate.purpose,
                candidate.scope,
                _DIGEST,
                _WORKSPACE,
                (),
                (),
                receipt,
            )
        return LocalDisclosureBlocked(
            proposal_id,
            candidate.request_id,
            sink,
            candidate.purpose,
            candidate.scope,
            _DIGEST,
            _WORKSPACE,
            omissions,
            receipt,
        )

    async def close(self) -> None:
        """Close the stand-in privacy coordinator."""

        return None


def _obligation_draft(
    *,
    event_id: str,
    obligation_id: str,
    acceptance_criteria: str | None,
) -> dict[str, JsonValue]:
    """Build one open obligation_published draft, optionally with acceptance criteria."""

    payload: dict[str, JsonValue] = {
        "obligation_id": obligation_id,
        "description": "Publish without manufacturing a null acceptance_criteria leaf.",
        "evidence_expectation": "A linked immutable result record.",
        "status": "open",
    }
    if acceptance_criteria is not None:
        payload["acceptance_criteria"] = acceptance_criteria
    return {
        "event_id": event_id,
        "schema": {"name": "obligation_published", "version": "1.0.0"},
        "occurred_at": "2026-07-28T12:00:00.000Z",
        "causal_parents": [],
        "payload": payload,
        "artifact_refs": [],
        "evidence_refs": [],
    }


async def _publish_obligation(
    seed: int,
    *,
    acceptance_criteria: str | None,
    evidence_subject_state: Mapping[str, str] | None = None,
    declare_in_plan: bool = False,
) -> tuple[Application, str, str]:
    """Start a task and publish one obligation (optionally declared by a plan, plus evidence)."""

    app, _policy = await build_projection_application(seed=seed)
    started = await app.start(start_request(seed + 1, title="Optional non-null projection"))
    obligation_id = protocol_id("obl_", seed + 2)
    event_id = protocol_id("evt_", seed + 3)
    drafts: list[JsonValue] = []
    if declare_in_plan:
        drafts.append(
            {
                "event_id": protocol_id("evt_", seed + 7),
                "schema": {"name": "plan_published", "version": "1.0.0"},
                "occurred_at": "2026-07-28T11:59:59.000Z",
                "causal_parents": [],
                "payload": {
                    "plan_version": 1,
                    "summary": "Declare the obligation projected by the compact status view.",
                    "obligation_refs": [obligation_id],
                },
                "artifact_refs": [],
                "evidence_refs": [],
            }
        )
    drafts.append(
        _obligation_draft(
            event_id=event_id,
            obligation_id=obligation_id,
            acceptance_criteria=acceptance_criteria,
        )
    )
    if evidence_subject_state is not None:
        drafts.append(
            {
                "event_id": protocol_id("evt_", seed + 4),
                "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-28T12:00:01.000Z",
                "causal_parents": [],
                "payload": {
                    "evidence_id": protocol_id("evd_", seed + 5),
                    "evidence_kind": "test_result",
                    "strength": "metadata_only",
                    "observed_at": "2026-07-28T12:00:01.000Z",
                    "reference": "subject-state fixture",
                    "subject_state": dict(evidence_subject_state),
                },
                "artifact_refs": [],
                "evidence_refs": [],
            }
        )
    publish_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 6)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(started.frontier),
        "event_drafts": drafts,
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_body))
    assert type(published) is PublishWorkInternalResult
    return app, started.session_id, started.writer_id


async def _project_status(
    app: Application,
    *,
    session_id: str,
    writer_id: str,
    view: str,
    seed: int,
) -> Mapping[str, JsonValue]:
    """Run status for *view* through the daemon projection boundary."""

    status_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed)),
        "session_id": session_id,
        "writer_id": writer_id,
        "view": view,
        "limit": "10",
    }
    status = await app.status(StatusRequest.model_validate(status_body))
    return await project_case(
        app,
        ProjectionCase(f"status/{view}", ControlMethod.STATUS, status_body, status),
        seed + 10,
    )


async def test_project_result_for_client_routes_awaiting_input_as_nonterminal() -> None:
    """The real post-privacy projection keeps review-input suspension out of the terminal branch."""

    app, _policy = await build_projection_application(seed=2050)
    try:
        started = await app.start(start_request(2051, title="Awaiting input projection"))
        request_id = protocol_id("req_", 2052)
        frontier = Frontier(int(started.frontier.sequence), started.frontier.head_digest)
        request_body: dict[str, JsonValue] = {
            **request_base(request_id),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": frontier_json(started.frontier),
            "mode": "semantic_required",
        }
        internal = CheckAwaitingHuman(
            started.task_id,
            started.session_id,
            started.writer_id,
            request_id,
            frontier,
            frontier,
            review_input_continuation(request_id=request_id),
            CheckVersionSlice(
                "0.1",
                "0.1.0",
                "0.1.0",
                ("research-evidence/0.2.0", "work-integrity/0.3.0"),
            ),
            state="awaiting_input",
        )
        facts = await app.projection_binding_facts(ControlMethod.CHECK, request_body, internal)
        rpc_id = protocol_id("rpc_", 2053)
        service_instance_id = protocol_id("svc_", 2054)
        binding = ControlProjectionBinding(
            rpc_id,
            ControlMethod.CHECK,
            service_instance_id,
            1,
            facts.original_request_id,
            facts.route_identity_digest,
            canonical_encode(
                {
                    "rpc_id": rpc_id,
                    "method": "check",
                    "service_instance_id": service_instance_id,
                    "service_generation": "1",
                }
            ),
        )

        projected = cast(
            CheckResultModel,
            await app.project_result_for_client(
                ClientProjectionContext(
                    ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
                ),
                binding,
                internal,
            ),
        )
        assert isinstance(projected.root, CheckAwaitingHumanModel)
        assert projected.root.state == "awaiting_input"
        assert projected.root.semantic_reason == "review_input_required"
        wire = public_model_to_wire(projected)
        assert wire["state"] == "awaiting_input"
        assert wire["semantic_status"] == "awaiting_input"
        continuation = cast(Mapping[str, JsonValue], wire["continuation"])
        assert continuation["kind"] == "review_input_required"
    finally:
        await app.close()


def _obligation_from_projected(
    projected: Mapping[str, JsonValue], view: str
) -> Mapping[str, JsonValue]:
    """Pull the single obligation row out of a compact or obligations status body."""

    page = cast(Mapping[str, JsonValue], projected["page"])
    items = cast(list[Mapping[str, JsonValue]], page["items"])
    assert items, f"{view} projected empty"
    if view == "compact":
        open_obligations = cast(list[Mapping[str, JsonValue]], items[0]["open_obligations"])
        assert open_obligations, "compact open_obligations empty"
        return open_obligations[0]
    return items[0]


@pytest.mark.parametrize("view", ("compact", "obligations"))
async def test_obligation_without_acceptance_criteria_projects(view: str) -> None:
    """An obligation published without acceptance_criteria projects on both status views."""

    app, session_id, writer_id = await _publish_obligation(
        2100,
        acceptance_criteria=None,
        declare_in_plan=view == "compact",
    )
    projected = await _project_status(
        app, session_id=session_id, writer_id=writer_id, view=view, seed=2110
    )
    assert projected["ok"] is True
    obligation = _obligation_from_projected(projected, view)
    assert "acceptance_criteria" not in obligation
    # Issue #997: only an acknowledged_not_done obligation carries its reason.
    assert "acknowledged_not_done_reason" not in obligation
    assert obligation["description"] == (
        "Publish without manufacturing a null acceptance_criteria leaf."
    )
    assert obligation["evidence_expectation"] == "A linked immutable result record."
    if view == "obligations":
        # Required nullable keys that were set to null must still project as null.
        assert obligation["revision_event_id"] is None


@pytest.mark.parametrize("declared", (True, False), ids=("in-plan", "not-in-plan"))
async def test_obligations_view_marks_membership_in_the_current_plan(declared: bool) -> None:
    """#1027: the view lists every obligation ever published; the flag tells a declared one apart.

    The post-compaction recap claims a requested output as a deliverable only for an obligation
    in the current plan's effective scope, so a waived or superseded one never returns as work.
    """

    app, session_id, writer_id = await _publish_obligation(
        2300 + (0 if declared else 20), acceptance_criteria=None, declare_in_plan=declared
    )
    projected = await _project_status(
        app, session_id=session_id, writer_id=writer_id, view="obligations", seed=2350
    )
    assert projected["ok"] is True
    obligation = _obligation_from_projected(projected, "obligations")

    assert obligation["in_current_plan"] is declared


@pytest.mark.parametrize("view", ("compact", "obligations"))
async def test_obligation_with_acceptance_criteria_keeps_text(view: str) -> None:
    """When acceptance_criteria is set, the text survives projection intact."""

    text = "A linked issue exists and is referenced from the result."
    app, session_id, writer_id = await _publish_obligation(
        2200,
        acceptance_criteria=text,
        declare_in_plan=view == "compact",
    )
    projected = await _project_status(
        app, session_id=session_id, writer_id=writer_id, view=view, seed=2210
    )
    assert projected["ok"] is True
    obligation = _obligation_from_projected(projected, view)
    assert obligation["acceptance_criteria"] == text


@pytest.mark.parametrize("view", ("compact", "obligations"))
async def test_obligation_acceptance_criteria_policy_omission_is_distinct(view: str) -> None:
    """Policy-omitted acceptance_criteria is an omission marker — not absence and not null."""

    text = "Criteria present so disclosure has a real leaf to omit."
    app, session_id, writer_id = await _publish_obligation(
        2300,
        acceptance_criteria=text,
        declare_in_plan=view == "compact",
    )
    object.__setattr__(app, "privacy", _BlockEverything())

    status_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", 2320)),
        "session_id": session_id,
        "writer_id": writer_id,
        "view": view,
        "limit": "10",
    }
    status = await app.status(StatusRequest.model_validate(status_body))
    facts = await app.projection_binding_facts(ControlMethod.STATUS, status_body, status)
    rpc_id = protocol_id("rpc_", 2330)
    service_instance_id = protocol_id("svc_", 2331)
    binding = ControlProjectionBinding(
        rpc_id,
        ControlMethod.STATUS,
        service_instance_id,
        1,
        facts.original_request_id,
        facts.route_identity_digest,
        canonical_encode(
            {
                "rpc_id": rpc_id,
                "method": ControlMethod.STATUS.value,
                "service_instance_id": service_instance_id,
                "service_generation": "1",
            }
        ),
    )
    projected = public_model_to_wire(
        await app.project_result_for_client(
            ClientProjectionContext(
                ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
            ),
            binding,
            status,
        )
    )
    assert projected["ok"] is True
    obligation = _obligation_from_projected(projected, view)
    assert "acceptance_criteria" in obligation
    criteria = obligation["acceptance_criteria"]
    assert isinstance(criteria, Mapping)
    assert criteria["omitted"] is True
    assert criteria["category"] == DataCategory.OBLIGATION_TEXT.value
    assert criteria is not None


async def test_publish_accepted_events_omit_unset_summary() -> None:
    """PublishWorkAcceptedEventModel.summary stays absent when never populated (PR #50)."""

    app, _policy = await build_projection_application(seed=2400)
    started = await app.start(start_request(2401, title="Summary absence"))
    body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", 2402)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(started.frontier),
        "event_drafts": [
            _obligation_draft(
                event_id=protocol_id("evt_", 2403),
                obligation_id=protocol_id("obl_", 2404),
                acceptance_criteria=None,
            )
        ],
    }
    # #985: a dry run of a batch without finishup-blocker lines carries no blocker_notices.
    dry_body = {**body, "request_id": protocol_id("req_", 2411), "dry_run": True}
    dry = await app.publish_work(PublishWorkRequest.model_validate(dry_body))
    dumped_dry = cast(object, getattr(dry, "model_dump")(mode="json", exclude_unset=True))
    assert "blocker_notices" not in cast(Mapping[str, JsonValue], dumped_dry)
    # tb4n5: a batch that records no action carries no action_notices either.
    assert "action_notices" not in cast(Mapping[str, JsonValue], dumped_dry)
    internal = await app.publish_work(PublishWorkRequest.model_validate(body))
    assert type(internal) is PublishWorkInternalResult
    projected = await project_case(
        app,
        ProjectionCase("publish_work", ControlMethod.PUBLISH_WORK, body, internal),
        2410,
    )
    assert projected["ok"] is True
    events = cast(list[Mapping[str, JsonValue]], projected["accepted_events"])
    assert events
    for event in events:
        assert "summary" not in event
    # #985: a batch without finishup-blocker lines carries no blocker_notices at all.
    assert "blocker_notices" not in projected
    assert "action_notices" not in projected


def test_blocked_obligation_omits_an_unset_confirmation() -> None:
    """A blocked row an earlier 0.3 build shaped carries no confirmation fields (#985)."""

    parsed = StatusBlockedObligationModel.model_validate(
        {
            "obligation_id": "obl_00000000-0000-4000-8000-000000000001",
            "blocker_kind": "authority",
            "decision_event_id": "evt_00000000-0000-4000-8000-000000000001",
        }
    )
    dumped = parsed.model_dump(mode="json", exclude_unset=True)
    assert not StatusBlockedObligationModel.optional_non_null_fields & dumped.keys()


def test_check_cause_omits_an_unset_tool() -> None:
    """A later record that names no tool (stream bookkeeping, a lineage manifest) leaves it out."""

    parsed = StatusCheckCauseModel.model_validate(
        {
            "effect": "bounds_conclusion",
            "event_id": "evt_00000000-0000-4000-8000-000000000001",
            "ledger_sequence": "12",
            "check_event_id": "evt_00000000-0000-4000-8000-000000000002",
            "check_subject_frontier": "9",
            "family": "evidence_recorded",
            "material_class": "other",
            "rule": "unclassified_observed_evidence",
        }
    )
    dumped = parsed.model_dump(mode="json", exclude_unset=True)
    assert not StatusCheckCauseModel.optional_non_null_fields & dumped.keys()


async def test_respond_omits_unset_optional_response_fields() -> None:
    """RespondResponseModel reason/waiver fields and evidence description stay absent when unset."""

    from finishup.protocol.models import CheckRequest, RespondRequest

    # Dedicated path: acknowledge without reason/waiver, and reference evidence that has no
    # description, so every optional_non_null leaf on the respond result stays unset.
    app, _policy = await build_projection_application(seed=2520)
    started = await app.start(start_request(2521, title="Respond without optionals"))
    obligation_id = protocol_id("obl_", 2522)
    evidence_id = protocol_id("evd_", 2528)
    publish_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", 2523)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(started.frontier),
        "event_drafts": [
            {
                "event_id": protocol_id("evt_", 2524),
                "schema": {"name": "obligation_published", "version": "1.0.0"},
                "occurred_at": "2026-07-28T12:00:00.000Z",
                "causal_parents": [],
                "payload": {
                    "obligation_id": obligation_id,
                    "description": "An open obligation that check will flag.",
                    "evidence_expectation": "A linked result.",
                    "requested_items": [{"item_kind": "change", "value": "unset-optional"}],
                    "status": "open",
                },
                "artifact_refs": [],
                "evidence_refs": [],
            },
            {
                "event_id": protocol_id("evt_", 2525),
                "schema": {"name": "claim_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-28T12:00:01.000Z",
                "causal_parents": [],
                "payload": {
                    "claim_id": protocol_id("clm_", 2526),
                    "claim_kind": "completion",
                    "statement": "Work is complete without meeting the obligation.",
                    "supporting_refs": [obligation_id],
                    "obligation_refs": [obligation_id],
                },
                "artifact_refs": [],
                "evidence_refs": [],
            },
            {
                "event_id": protocol_id("evt_", 2530),
                "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-28T12:00:02.000Z",
                "causal_parents": [],
                "payload": {
                    "evidence_id": evidence_id,
                    "evidence_kind": "test_result",
                    "strength": "metadata_only",
                    "observed_at": "2026-07-28T12:00:02.000Z",
                    "reference": "respond-without-optionals",
                },
                "artifact_refs": [],
                "evidence_refs": [],
            },
        ],
    }
    published = await app.publish_work(PublishWorkRequest.model_validate(publish_body))
    assert type(published) is PublishWorkInternalResult
    check_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", 2527)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(published.result_frontier),
        "mode": "deterministic_only",
        "max_findings": "3",
    }
    checked = await app.check(CheckRequest.model_validate(check_body))
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    assert checked.findings
    respond_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", 2531)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(checked.result_frontier),
        "finding_id": checked.findings[0].finding_id,
        "finding_frontier": frontier_json(checked.result_frontier),
        "disposition": "acknowledged",
        "evidence_refs": [evidence_id],
    }
    responded = await app.respond(RespondRequest.model_validate(respond_body))
    assert type(responded) is RespondInternalResult
    projected = await project_case(
        app,
        ProjectionCase("respond", ControlMethod.RESPOND, respond_body, responded),
        2540,
    )
    assert projected["ok"] is True
    response = cast(Mapping[str, JsonValue], projected["response"])
    assert "reason" not in response
    assert "waiver_scope" not in response
    assert "waiver_expiry" not in response
    evidence = cast(list[Mapping[str, JsonValue]], response["evidence"])
    assert evidence
    for item in evidence:
        assert "description" not in item


@pytest.mark.parametrize(
    ("present", "absent"),
    (
        ("tree_digest", "diff_digest"),
        ("diff_digest", "tree_digest"),
    ),
)
async def test_status_evidence_omits_unset_structural_digest(present: str, absent: str) -> None:
    """StatusStructuralSubjectStateModel projects with only the set digest, never a null sibling."""

    seed = 2600 if present == "tree_digest" else 2650
    app, session_id, writer_id = await _publish_obligation(
        seed,
        acceptance_criteria=None,
        evidence_subject_state={present: _DIGEST},
    )
    projected = await _project_status(
        app, session_id=session_id, writer_id=writer_id, view="evidence", seed=seed + 10
    )
    assert projected["ok"] is True
    items = cast(
        list[Mapping[str, JsonValue]],
        cast(Mapping[str, JsonValue], projected["page"])["items"],
    )
    assert items
    subject_state = items[0].get("subject_state")
    assert isinstance(subject_state, Mapping)
    assert subject_state[present] == _DIGEST
    assert absent not in subject_state


async def test_public_error_omits_unset_safe_details() -> None:
    """PublicErrorModel.safe_details is absent when the error carries no details."""

    model = PublicErrorModel.model_validate(
        {
            "code": "INVALID_REQUEST",
            "message": "The request is invalid.",
            "retryable": False,
            "correlation_id": protocol_id("err_", 2700),
        }
    )
    dumped = model.model_dump(mode="json", exclude_unset=True)
    assert "safe_details" not in dumped
    again = PublicErrorModel.model_validate(dumped)
    assert again.safe_details is None
    assert "safe_details" not in again.model_dump(mode="json", exclude_unset=True)


async def test_review_input_manifest_omits_unset_review_phase() -> None:
    """A manifest recorded before the review phase existed stays without it (issue #976)."""

    section: dict[str, object] = {
        "status": "missing",
        "source_refs": [],
        "item_ids": [],
        "omitted_refs": [],
        "omission_reasons": [],
        "revision": None,
        "content_digest": None,
        "content_bytes": 0,
    }
    payload: dict[str, object] = {
        "schema": "yoetz.review-input-manifest/1",
        "specification": section,
        "current_diff": section,
        "caller_evidence": section,
        "latest_verification": section,
        "prior_finding_context": section,
        "phase": "provider_bound",
        "missing_inputs": [],
        "selected_item_count": 0,
        "selected_excerpt_bytes": 0,
        "omitted_item_count": 0,
    }
    model = ReviewInputManifestModel.model_validate(payload)
    dumped = model.model_dump(mode="json", by_alias=True, exclude_unset=True)
    assert "review_phase" not in dumped
    assert model.review_phase is None
    final = ReviewInputManifestModel.model_validate({**payload, "review_phase": "final"})
    assert final.model_dump(mode="json", by_alias=True)["review_phase"] == "final"
    # Issue #976: the omission total is optional in place, absent on older manifests.
    assert "omitted_item_total" not in dumped
    assert model.omitted_item_total is None
    total = ReviewInputManifestModel.model_validate({**payload, "omitted_item_total": 173})
    assert total.model_dump(mode="json", by_alias=True)["omitted_item_total"] == 173
    # Issue #1047: only an in-check follow-up packet names its round.
    assert "follow_up_round" not in dumped
    assert model.follow_up_round is None
    follow_up = ReviewInputManifestModel.model_validate({**payload, "follow_up_round": 2})
    assert follow_up.model_dump(mode="json", by_alias=True)["follow_up_round"] == 2
    for invalid in (0, 4):
        with pytest.raises(ValueError):
            ReviewInputManifestModel.model_validate({**payload, "follow_up_round": invalid})


@pytest.mark.parametrize(
    ("model_type", "payload"),
    (
        (
            StatusCompactObligationModel,
            {
                "obligation_id": protocol_id("obl_", 2801),
                "description": "d",
                "evidence_expectation": "e",
                "acceptance_criteria": None,
            },
        ),
        (
            StatusObligationItemModel,
            {
                "obligation_id": protocol_id("obl_", 2802),
                "status": "open",
                "description": "d",
                "evidence_expectation": "e",
                "source_refs": [],
                "assigned_actor_ids": [],
                "evidence_refs": [],
                "revision_event_id": None,
                "acceptance_criteria": None,
            },
        ),
        (
            StatusAdviceItemModel,
            {
                "finding_id": protocol_id("fnd_", 2808),
                "rule_code": "coordination_overlap",
                "priority": 50,
                "evidence_commitments": (_DIGEST,),
                "coverage": dict(
                    coverage_to_json(coverage_for_channel(PublicationChannel.COOPERATIVE_MCP))
                ),
                "freshness_frontier": "membership_generation:1",
                "verification_state": "not_required",
                "semantic_state": "disabled",
                "recommended_next_action": "review_coordination_advice",
                "coordination_project_id": None,
            },
        ),
        (
            StatusProjectDetectionModel,
            {
                "detection_id": protocol_id("evt_", 2809),
                "task_ids": (protocol_id("tsk_", 2810), protocol_id("tsk_", 2811)),
                "resource_count": "0",
                "open": True,
                "resource_paths": None,
            },
        ),
        (
            PublishWorkAcceptedEventModel,
            {
                "event_id": protocol_id("evt_", 2803),
                "schema_name": "obligation_published",
                "schema_version": "1.0.0",
                "writer_sequence": "1",
                "ingestion_sequence": "1",
                "accepted_at": "2026-07-28T12:00:00.000Z",
                "predecessor_digest": "genesis",
                "entry_digest": "sha256:" + "1" * 64,
                "projection_status": "projected",
                "summary": None,
            },
        ),
        (
            StatusStructuralSubjectStateModel,
            {"tree_digest": _DIGEST, "diff_digest": None},
        ),
        (
            RespondEvidenceSummaryModel,
            {"reference_id": protocol_id("evd_", 2804), "description": None},
        ),
        (
            PublicErrorModel,
            {
                "code": "INVALID_REQUEST",
                "message": "The request is invalid.",
                "retryable": False,
                "correlation_id": protocol_id("err_", 2805),
                "safe_details": None,
            },
        ),
        (
            RespondResponseModel,
            {
                "response_event_id": protocol_id("evt_", 2806),
                "finding_id": protocol_id("fnd_", 2807),
                "finding_frontier": {
                    "sequence": "1",
                    "head_digest": "sha256:" + "0" * 64,
                },
                "disposition": "acknowledged",
                "evidence": [],
                "reason": None,
            },
        ),
        (
            StatusVersionSliceModel,
            {**_version_slice_payload(), "route_profile": None},
        ),
    ),
)
def test_closed_model_still_rejects_explicit_null(
    model_type: type[BaseModel], payload: Mapping[str, object]
) -> None:
    """Producers omit unset optionals; the closed models still refuse an explicit null."""

    with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
        model_type.model_validate(payload)


def test_status_closure_readiness_omits_an_unset_checklist() -> None:
    """A readiness shaped by an earlier 0.3 build carries no checklist; it stays absent (#913)."""

    parsed = StatusClosureReadinessModel.model_validate(
        {
            "declared_obligation_count": "0",
            "no_obligations_reason": None,
            "open_obligation_count": "0",
            "unanswered_finding_count": "0",
            "receipt_blocking_finding_count": "0",
            "blocking_conditions": ["no_obligations_declared"],
        }
    )
    dumped = parsed.model_dump(mode="json", exclude_unset=True)
    assert not StatusClosureReadinessModel.optional_non_null_fields & dumped.keys()
    assert dumped["no_obligations_reason"] is None
    # ADR-045: a readiness with no derived fact lists no lineage; null is refused, not tolerated
    # (the service once sent ``null`` here and every status read failed).
    with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
        StatusClosureReadinessModel.model_validate({**dumped, "fact_lineage": None})
    # #1044: a readiness naming no undeclared file omits the list; null is refused too.
    with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
        StatusClosureReadinessModel.model_validate({**dumped, "undeclared_references": None})
    # #1079: no recorded verification link omits the list; null is refused too.
    with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
        StatusClosureReadinessModel.model_validate({**dumped, "admissible_verification": None})


def test_fact_lineage_omits_every_unset_field() -> None:
    """A lineage entry is closed tokens and counts; whatever it does not know is absent."""

    minimal = {"code": "declared_output_emptied", "rule": "deliverable_read", "state": "emptied"}
    dumped = FactLineageModel.model_validate(minimal).model_dump(mode="json", exclude_unset=True)
    assert dumped == minimal
    for field in FactLineageModel.optional_non_null_fields:
        with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
            FactLineageModel.model_validate({**minimal, field: None})


def test_closure_verdict_models_omit_unset_fields_and_refuse_null() -> None:
    """ADR-046: every closure-verdict field is absent from a result an earlier build shaped,
    appears when set, and is never null on the wire."""

    base_counts = {
        "acknowledged_not_done": "0",
        "open": "1",
        "open_at_budget": "0",
        "rejection_accepted": "0",
        "self_verified": "0",
        "verified_resolved": "0",
    }
    parsed = CheckChecklistCountsModel.model_validate(base_counts)
    dumped = parsed.model_dump(mode="json", exclude_unset=True)
    for field in ("to_do", "awaiting_ruling", "unmet", "disclosed", "to_disclose"):
        assert field not in dumped
        with pytest.raises(ValueError):
            CheckChecklistCountsModel.model_validate({**base_counts, field: None})
    full = CheckChecklistCountsModel.model_validate(
        {
            **base_counts,
            "to_do": "1",
            "awaiting_ruling": "1",
            "unmet": "0",
            "disclosed": "0",
            "to_disclose": "0",
        }
    )
    assert full.model_dump(mode="json", exclude_unset=True)["awaiting_ruling"] == "1"
    # The group travels together.
    with pytest.raises(ValueError):
        CheckChecklistCountsModel.model_validate({**base_counts, "to_do": "1"})

    item = CheckChecklistItemModel.model_validate(
        {"finding_id": protocol_id("fnd_", 2950), "todo_state": "open", "review_rounds": "0"}
    )
    assert (
        not {"closure_class", "closure_basis"}
        & item.model_dump(mode="json", exclude_unset=True).keys()
    )
    with pytest.raises(ValueError):
        CheckChecklistItemModel.model_validate(
            {
                "finding_id": protocol_id("fnd_", 2950),
                "todo_state": "open",
                "review_rounds": "0",
                "closure_class": "agent_work",
            }
        )

    reason = StatusPredictedReasonModel.model_validate(
        {"code": "findings_to_do", "rule": "R2", "count": "1", "refs": []}
    )
    assert "since_frontier" not in reason.model_dump(mode="json", exclude_unset=True)
    with pytest.raises(ValueError):
        StatusPredictedReasonModel.model_validate(
            {
                "code": "findings_to_do",
                "rule": "R2",
                "count": "1",
                "refs": [],
                "since_frontier": None,
            }
        )

    next_step = CheckOverallNextModel.model_validate(
        {"status": "ready", "action": "request_receipt", "target_refs": []}
    )
    assert "predicted_conclusion" not in next_step.model_dump(mode="json", exclude_unset=True)
    with pytest.raises(ValueError):
        CheckOverallNextModel.model_validate(
            {
                "status": "ready",
                "action": "request_receipt",
                "target_refs": [],
                "predicted_conclusion": None,
            }
        )


def test_checklist_counts_omit_an_unset_disputed_count() -> None:
    """Issue #1020: the disputed count is absent when zero, present when set, never null."""

    base = {
        "acknowledged_not_done": "0",
        "open": "1",
        "open_at_budget": "0",
        "rejection_accepted": "0",
        "self_verified": "0",
        "verified_resolved": "0",
    }
    parsed = CheckChecklistCountsModel.model_validate(base)
    assert "disputed_after_rebuttal" not in parsed.model_dump(mode="json", exclude_unset=True)
    present = CheckChecklistCountsModel.model_validate({**base, "disputed_after_rebuttal": "2"})
    assert present.model_dump(mode="json", exclude_unset=True)["disputed_after_rebuttal"] == "2"
    with pytest.raises(ValueError):
        CheckChecklistCountsModel.model_validate({**base, "disputed_after_rebuttal": None})


def test_status_version_slice_omits_unset_route_profile() -> None:
    parsed = StatusVersionSliceModel.model_validate(_version_slice_payload())
    assert "route_profile" not in parsed.model_dump(mode="json", exclude_unset=True)


async def test_root_start_and_check_omit_unset_multi_agent_fields() -> None:
    app, _policy = await build_projection_application(seed=2900)
    try:
        request = start_request(2901, title="Root without children")
        started = await app.start(request)
        projected = await project_case(
            app,
            ProjectionCase("start", ControlMethod.START, public_model_to_wire(request), started),
            2902,
        )
        assert (
            not {"attach_handle", "parent_task_id", "depth", "origin", "acceptance"}
            & projected.keys()
        )
        body = {
            **request_base(protocol_id("req_", 2903)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": frontier_json(started.frontier),
            "mode": "deterministic_only",
        }
        checked = await app.check(CheckRequest.model_validate(body))
        assert isinstance(checked, CheckCommitResult)
        projected_check = await project_case(
            app,
            ProjectionCase("check", ControlMethod.CHECK, body, checked),
            2904,
        )
        assert "children" not in projected_check
        assert "advisory_notes" not in projected_check
        # Issue #907: only an insufficient_packet review that named items emits the list.
        assert "missing_for_assessment" not in projected_check
        assert "semantic_withheld_items" not in projected_check
        assert "semantic_redacted_values" not in projected_check
        assert "observations_awaited" not in projected_check
        assert "review_input_manifest" not in projected_check
        # ADR-045: a check with no derived fact lists no lineage (absent, not an empty list).
        assert "fact_lineage" not in projected_check
        # ADR-049: a composition that cannot read the conversation setting records no mode.
        assert "review_mode" not in projected_check
        # Issue #961: reviewer output is absent on a deterministic check; frozen-work totals and
        # the overall continuation are filled on every new check but stay optional for legacy rows.
        assert not {"semantic_conclusion", "review_summary", "verified"} & projected_check.keys()
        assert {"totals", "overall_next"} <= projected_check.keys()
        # Issue #905: the checklist is current context a ledger may not offer; unset, it is
        # absent rather than null, and an explicit null is refused.
        assert "finding_checklist" in projected_check
        # Issue #986 (E2): a route that did not require AI-powered review is recorded as false.
        assert projected_check["semantic_route_required"] is False
        for field in (
            "finding_checklist",
            "semantic_route_required",
            "semantic_withheld_items",
            "review_input_manifest",
            "semantic_conclusion",
            "review_summary",
            "verified",
            "totals",
            "overall_next",
            "semantic_redacted_values",
            "observations_awaited",
            "fact_lineage",
            "review_mode",
        ):
            unset = {key: value for key, value in projected_check.items() if key != field}
            model = CheckSuccessModel.model_validate(unset)
            assert field not in model.model_dump(mode="json", exclude_unset=True)
            with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
                CheckSuccessModel.model_validate({**unset, field: None})
    finally:
        await app.close()


@pytest.mark.parametrize(
    ("model_type", "payload", "absent"),
    (
        (
            CheckAwaitingHumanModel,
            _check_awaiting_human_payload(),
            ("specification_preflight",),
        ),
        (
            ChildFindingSnapshotModel,
            {
                "finding_id": protocol_id("fnd_", 2910),
                "kind": "result_without_action",
                "origin": "deterministic",
                "priority": 2,
                "actionable": True,
                "resolved": False,
            },
            ("resolution_event_id", "self_verified"),
        ),
        (
            StatusLineageChildModel,
            {
                "task_id": protocol_id("tsk_", 2912),
                "parent_task_id": protocol_id("tsk_", 2913),
                "origin": "self_registered",
                "acceptance": "accepted",
                "work_state": "closed",
                "session_health": "ended",
                "depth": "1",
                "rollup_state": "clean",
                "blocking_conditions": (),
            },
            ("self_verified_finding_count",),
        ),
        (
            ChildDependencySnapshotModel,
            {
                "child_task_id": protocol_id("tsk_", 2911),
                "origin": "self_registered",
                "acceptance": "pending",
                "work_state": "open",
                "session_health": "contact_lost",
                "lineage_authority_revision": "1",
                "coverage": dict(
                    coverage_to_json(coverage_for_channel(PublicationChannel.COOPERATIVE_MCP))
                ),
                "findings": [],
                "read_gap_reasons": ["missing"],
            },
            ("child_frontier", "child_check_id", "child_receipt_id", "membership_generation"),
        ),
        (
            ProjectTextRefModel,
            {
                "object_id": protocol_id("obj_", 2912),
                "content_digest": _DIGEST,
                "plaintext_size": 1,
                "owner_task_id": protocol_id("tsk_", 2911),
                "route_generation": "1",
            },
            ("envelope_digest",),
        ),
        (
            StatusProjectPageModel,
            {
                "project_id": protocol_id("prj_", 2913),
                "kind": "repository",
                "membership_generation": "1",
                "grant_state": None,
                "members": [],
                "lineage": {
                    "parent_task_id": None,
                    "children": [],
                    "annotations": [],
                    "next_cursor": None,
                },
                "detections": [],
                "receipts": [],
                "next_cursor": None,
            },
            ("title", "description", "title_ref", "description_ref"),
        ),
        (
            StatusAdviceItemModel,
            {
                "finding_id": protocol_id("fnd_", 2914),
                "rule_code": "coordination_overlap",
                "priority": 50,
                "evidence_commitments": (_DIGEST,),
                "coverage": dict(
                    coverage_to_json(coverage_for_channel(PublicationChannel.COOPERATIVE_MCP))
                ),
                "freshness_frontier": "membership_generation:1",
                "verification_state": "not_required",
                "semantic_state": "disabled",
                "recommended_next_action": "review_coordination_advice",
            },
            (
                "coordination_project_id",
                "coordination_detection_id",
                "coordination_membership_generation",
                "coordination_counterpart_task_id",
                "coordination_resource_paths",
            ),
        ),
        (
            StatusFindingItemModel,
            {
                "finding_id": protocol_id("fnd_", 2918),
                "kind": "result_without_action",
                "origin": "deterministic",
                "priority": 2,
                "summary": "A result has no recorded action.",
                "detail": "Record the action that produced the result.",
                "subject_refs": (protocol_id("res_", 2919),),
                "policy_id": "work-integrity",
                "policy_version": "0.1.0",
                "subject_frontier": {"sequence": "1", "head_digest": _DIGEST},
                "coverage": dict(
                    coverage_to_json(coverage_for_channel(PublicationChannel.COOPERATIVE_MCP))
                ),
                "provenance": None,
                "disposition": "none",
                "resolved": False,
                "response_event_id": None,
                "reason": None,
                "waiver_scope": None,
                "waiver_expiry": None,
            },
            # Issue #961: a deterministic finding carries no reviewer challenge.
            ("todo_state", "review_rounds", "challenge"),
        ),
        (
            CheckProjectedFindingModel,
            {
                "finding_id": protocol_id("fnd_", 2930),
                "kind": "result_without_action",
                "origin": "deterministic",
                "priority": 2,
                "summary": "A result has no recorded action.",
                "detail": "Record the action that produced the result.",
                "subject_refs": (protocol_id("res_", 2931),),
                "policy_id": "work-integrity",
                "policy_version": "0.1.0",
                "subject_frontier": {"sequence": "1", "head_digest": _DIGEST},
                "coverage": dict(
                    coverage_to_json(coverage_for_channel(PublicationChannel.COOPERATIVE_MCP))
                ),
                "provenance": None,
            },
            ("challenge",),
        ),
        (
            CheckVerifiedItemModel,
            {
                # Only a not_assessable judgement omits its supporting snippet.
                "requirement_or_claim": "The declared change is covered.",
                "verdict": "not_assessable",
                "cited_refs": (protocol_id("evd_", 2932),),
            },
            ("snippet",),
        ),
        (
            StatusCompactItemModel,
            {
                "task_id": protocol_id("tsk_", 2933),
                "session_id": protocol_id("ses_", 2934),
                "task_title": "Compact item without a check",
                "current_plan_event_id": None,
                "declared_obligation_count": "0",
                "no_obligations_reason": None,
                "open_obligation_count": "0",
                "unanswered_finding_count": "0",
                "receipt_blocking_finding_count": "0",
                "open_obligations": (),
                "unanswered_findings": (),
                "freshness": "current",
                "coverage": dict(
                    coverage_to_json(coverage_for_channel(PublicationChannel.COOPERATIVE_MCP))
                ),
                "gaps": (),
            },
            ("latest_check_test_edits", "latest_check"),
        ),
        (StatusFindingsPageModel, {"items": [], "next_cursor": None}, ("attempt_budget",)),
        (
            StatusOperationPageModel,
            {
                "operation_request_id": protocol_id("req_", 2912),
                "found": True,
                "state": "complete",
                "operation_kind": "check",
            },
            ("semantic_withheld_items", "semantic_redacted_values"),
        ),
        (StatusRequestedItemModel, {"item_kind": "file", "value": "out.txt"}, ("role",)),
        (
            SemanticRedactedValueModel,
            {"item_id": "item-1", "disposition": "value_replaced", "lines": [3]},
            ("source_ref",),
        ),
        (
            StatusHistoryItemV14Model,
            _status_history_v14_payload(),
            ("review_input_manifest",),
        ),
        (
            StatusProjectDetectionModel,
            {
                "detection_id": protocol_id("evt_", 2915),
                "task_ids": (protocol_id("tsk_", 2916), protocol_id("tsk_", 2917)),
                "resource_count": "0",
                "open": True,
            },
            ("resource_paths",),
        ),
        (
            StatusObservedRunModel,
            {"occurrence": "1"},
            ("tool_name", "command_commitment", "exit_status"),
        ),
    ),
)
def test_nested_multi_agent_results_omit_unset_fields(
    model_type: type[BaseModel],
    payload: Mapping[str, object],
    absent: tuple[str, ...],
) -> None:
    model = model_type.model_validate(payload)
    wire = model.model_dump(mode="json", exclude_unset=True)
    assert not set(absent) & wire.keys()
    assert model_type.model_validate(wire) == model
    for field in absent:
        with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
            model_type.model_validate({**payload, field: None})


def test_verified_item_refuses_null_reviewer_text() -> None:
    """Issue #961: verified rows carry required reviewer text that can never be null."""

    payload = {
        "requirement_or_claim": "The declared change is covered.",
        "verdict": "supported",
        "cited_refs": (protocol_id("evd_", 2935),),
        "snippet": "def covered() -> bool: return True",
    }
    assert "requirement_or_claim" in CheckVerifiedItemModel.model_validate(payload).model_dump(
        mode="json", exclude_unset=True
    )
    for field in ("requirement_or_claim", "snippet"):
        with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
            CheckVerifiedItemModel.model_validate({**payload, field: None})


def test_result_optional_non_null_inventory_is_complete() -> None:
    """Every result model declaring optional_non_null_fields is listed in the inventory table."""

    empty_fields: frozenset[str] = frozenset()
    declared: dict[str, frozenset[str]] = {}
    for name in dir(protocol_models):
        obj = getattr(protocol_models, name)
        if not isinstance(obj, type) or not issubclass(obj, _CLOSED_MODEL) or obj is _CLOSED_MODEL:
            continue
        fields = cast(frozenset[str], getattr(obj, "optional_non_null_fields", empty_fields))
        if not fields or name in _REQUEST_SIDE_OPTIONAL_NON_NULL:
            continue
        declared[name] = fields

    inventoried = {model_type.__name__: fields for model_type, fields in _RESULT_OPTIONAL_NON_NULL}
    assert inventoried == declared, (
        "result optional_non_null inventory drifted: "
        f"missing={declared.keys() - inventoried.keys()} "
        f"extra={inventoried.keys() - declared.keys()} "
        f"field_mismatches="
        f"{
            {
                key: (inventoried.get(key), declared.get(key))
                for key in inventoried.keys() | declared.keys()
                if inventoried.get(key) != declared.get(key)
            }
        }"
    )


def test_every_result_optional_non_null_field_has_an_unset_projection_case() -> None:
    """Each inventoried field is covered by at least one end-to-end unset projection case.

    The mapping is the living index: add a model to ``_RESULT_OPTIONAL_NON_NULL`` and this test
    requires a coverage entry naming the test that projects the field unset.
    """

    covered: dict[tuple[str, str], str] = {
        ("CheckContinuationModel", "pending_id"): (
            "test_status_view_operation_recovers_missing_repository_grant_for_same_request"
        ),
        ("CheckContinuationModel", "expires_at"): (
            "test_status_view_operation_recovers_missing_repository_grant_for_same_request"
        ),
        ("PublishWorkAcceptedEventModel", "summary"): (
            "test_publish_accepted_events_omit_unset_summary"
        ),
        ("PublicErrorModel", "safe_details"): "test_public_error_omits_unset_safe_details",
        # Issue #1020: emitted only when non-zero.
        ("CheckChecklistCountsModel", "disputed_after_rebuttal"): (
            "test_checklist_counts_omit_an_unset_disputed_count"
        ),
        ("StatusPredictedReasonModel", "since_frontier"): (
            "test_closure_verdict_models_omit_unset_fields_and_refuse_null"
        ),
        ("CheckOverallNextModel", "predicted_conclusion"): (
            "test_closure_verdict_models_omit_unset_fields_and_refuse_null"
        ),
        ("RespondEvidenceSummaryModel", "description"): (
            "test_respond_omits_unset_optional_response_fields"
        ),
        ("RespondResponseModel", "reason"): "test_respond_omits_unset_optional_response_fields",
        ("RespondResponseModel", "waiver_scope"): (
            "test_respond_omits_unset_optional_response_fields"
        ),
        ("RespondResponseModel", "waiver_expiry"): (
            "test_respond_omits_unset_optional_response_fields"
        ),
        # Issue #996: set only on a duplicate_of answer.
        ("RespondResponseModel", "duplicate_of_finding_id"): (
            "test_respond_omits_unset_optional_response_fields"
        ),
        ("StatusCompactObligationModel", "acceptance_criteria"): (
            "test_obligation_without_acceptance_criteria_projects"
        ),
        ("StatusObligationItemModel", "acceptance_criteria"): (
            "test_obligation_without_acceptance_criteria_projects"
        ),
        ("StatusObligationItemModel", "acknowledged_not_done_reason"): (
            "test_obligation_without_acceptance_criteria_projects"
        ),
        # Issue #1027: present whenever the plan scope is readable, False off the current plan.
        ("StatusObligationItemModel", "in_current_plan"): (
            "test_obligations_view_marks_membership_in_the_current_plan"
        ),
        ("StatusRequestedItemModel", "role"): ("test_nested_multi_agent_results_omit_unset_fields"),
        # Issue #914: tests/conformance/protocol/test_status_evidence_author_fixture.py
        ("StatusEvidenceItemModel", "publication_channel"): (
            "test_rows_from_earlier_03_builds_still_validate_without_a_channel"
        ),
        ("StatusStructuralSubjectStateModel", "diff_digest"): (
            "test_status_evidence_omits_unset_structural_digest"
        ),
        ("StatusStructuralSubjectStateModel", "tree_digest"): (
            "test_status_evidence_omits_unset_structural_digest"
        ),
        ("StatusVersionSliceModel", "route_profile"): (
            "test_status_version_slice_omits_unset_route_profile"
        ),
        # Issue #571 A2: tests/integration/application/test_status_pending_operation_projection.py
        ("StatusOperationPageModel", "semantic_progress"): (
            "test_pending_check_operation_page_projects_to_the_client"
        ),
        # Issue #838: tests/integration/application/test_status_check_admission.py
        ("StatusOperationPageModel", "admission"): (
            "test_absent_operation_page_omits_admission_when_nothing_is_known"
        ),
    }
    for field in (
        "state",
        "gap_classification_version",
        "agent_actionable",
        "standing_limitations",
        "acknowledged_not_done",
        "acknowledged_not_done_count",
        # Issue #977: absent from a readiness an earlier 0.3 build shaped.
        "blocked_obligations",
        # F3: absent from a readiness an earlier 0.3 build shaped.
        "limitation_refs_required",
        "limitation_refs_required_count",
        # #997: absent from a readiness an earlier 0.3 build shaped.
        "acknowledged_obligation_count",
        # tb4n3 RC-6: absent unless it explains a listed check_not_applicable / earlier-frontier item.
        "check_cause",
        # ADR-045: absent when the readiness lists no derived fact.
        "fact_lineage",
        # #1044: absent unless a delivered file names an undeclared one.
        "undeclared_references",
        # #1079: absent unless a flagged obligation has a recorded verification link.
        "admissible_verification",
        # Omitted by an earlier build. A computed frontier, including 0, is present.
        "closing_material_frontier",
    ):
        # Issue #913: the checklist is absent as a whole on an earlier 0.3 build's readiness.
        covered["StatusClosureReadinessModel", field] = (
            "test_status_closure_readiness_omits_an_unset_checklist"
        )
    for field in (
        "predicted_receipt",
        "finding_counts",
        "obligation_counts",
        "rechecks",
        "awaiting_ruling_findings",
    ):
        covered["StatusClosureReadinessModel", field] = (
            "test_closure_verdict_models_omit_unset_fields_and_refuse_null"
        )
    for field in ("closure_class", "closure_basis", "next_actions"):
        covered["StatusFindingItemModel", field] = (
            "test_closure_verdict_models_omit_unset_fields_and_refuse_null"
        )
    for field in ("closure_class", "closure_basis"):
        covered["StatusObligationItemModel", field] = (
            "test_closure_verdict_models_omit_unset_fields_and_refuse_null"
        )
        covered["CheckChecklistItemModel", field] = (
            "test_closure_verdict_models_omit_unset_fields_and_refuse_null"
        )
    for field in ("to_do", "awaiting_ruling", "unmet", "disclosed", "to_disclose"):
        covered["CheckChecklistCountsModel", field] = (
            "test_closure_verdict_models_omit_unset_fields_and_refuse_null"
        )
    for model in ("PublishWorkSuccessModel", "PublishWorkDryRunModel"):
        covered[model, "blocker_notices"] = "test_publish_accepted_events_omit_unset_summary"
        covered[model, "action_notices"] = "test_publish_accepted_events_omit_unset_summary"
        covered[model, "server_filled"] = "test_server_filled_and_brief_fields_omit_when_unset"
    covered["PublishWorkSuccessModel", "replay_notice"] = (
        "test_server_filled_and_brief_fields_omit_when_unset"
    )
    for field in ("server_filled", "replay_notice"):
        covered["PublishWorkAcceptedProjectionUnavailableModel", field] = (
            "test_server_filled_and_brief_fields_omit_when_unset"
        )
    covered["StatusHistoryItemV14Model", "occurred_at_source"] = (
        "test_server_filled_and_brief_fields_omit_when_unset"
    )
    covered["StatusOperationPageModel", "server_filled"] = (
        "test_server_filled_and_brief_fields_omit_when_unset"
    )
    for field in StatusBriefSuccessModel.optional_non_null_fields:
        covered["StatusBriefSuccessModel", field] = (
            "test_brief_status_is_a_strict_subset_of_the_full_body"
        )
    for field in StatusClosureStateModel.optional_non_null_fields:
        covered["StatusClosureStateModel", field] = (
            "test_server_filled_and_brief_fields_omit_when_unset"
        )
    for field in ("confirmation", "confirmation_event_id"):
        covered["StatusBlockedObligationModel", field] = (
            "test_blocked_obligation_omits_an_unset_confirmation"
        )
    covered["StatusCheckCauseModel", "tool"] = "test_check_cause_omits_an_unset_tool"
    for field in ("remaining_ms", "terminal_outcome", "terminal_reason"):
        # The sampling case omits the terminal pair; the terminal case omits remaining_ms.
        covered["StatusSemanticProgressModel", field] = (
            "test_semantic_progress_agrees_across_json_text_mcp_and_tui"
        )
    for model, fields in (
        ("StartSuccessModel", ("attach_handle", "parent_task_id", "depth", "origin", "acceptance")),
        (
            "CheckSuccessModel",
            (
                "children",
                "advisory_notes",
                "missing_for_assessment",
                "finding_checklist",
                "semantic_withheld_items",
                "review_input_manifest",
                "semantic_conclusion",
                "review_summary",
                "verified",
                "totals",
                "overall_next",
                "semantic_redacted_values",
                "observations_awaited",
                "semantic_route_required",
                "fact_lineage",
                "review_mode",
            ),
        ),
    ):
        for field in fields:
            covered[model, field] = "test_root_start_and_check_omit_unset_multi_agent_fields"
    for field in CheckReviewModeModel.optional_non_null_fields:
        covered["CheckReviewModeModel", field] = "test_review_mode_omits_unset_reason_and_switch"
    for field in StatusReviewModeModel.optional_non_null_fields:
        covered["StatusReviewModeModel", field] = "test_review_mode_omits_unset_reason_and_switch"
    for field in FactLineageModel.optional_non_null_fields:
        covered["FactLineageModel", field] = "test_fact_lineage_omits_every_unset_field"
    covered["CheckAwaitingHumanModel", "specification_preflight"] = (
        "test_nested_multi_agent_results_omit_unset_fields"
    )
    covered["CheckVerifiedItemModel", "requirement_or_claim"] = (
        "test_verified_item_refuses_null_reviewer_text"
    )
    covered["StatusHistoryItemV14Model", "review_input_manifest"] = (
        "test_nested_multi_agent_results_omit_unset_fields"
    )
    covered["ReviewInputManifestModel", "review_phase"] = (
        "test_review_input_manifest_omits_unset_review_phase"
    )
    covered["ReviewInputManifestModel", "omitted_item_total"] = (
        "test_review_input_manifest_omits_unset_review_phase"
    )
    covered["ReviewInputManifestModel", "follow_up_round"] = (
        "test_review_input_manifest_omits_unset_review_phase"
    )
    covered["StatusOperationPageModel", "semantic_withheld_items"] = (
        "test_nested_multi_agent_results_omit_unset_fields"
    )
    covered["StatusOperationPageModel", "semantic_redacted_values"] = (
        "test_nested_multi_agent_results_omit_unset_fields"
    )
    covered["SemanticRedactedValueModel", "source_ref"] = (
        "test_nested_multi_agent_results_omit_unset_fields"
    )
    for model, fields in (
        ("ChildFindingSnapshotModel", ("resolution_event_id", "self_verified")),
        ("StatusLineageChildModel", ("self_verified_finding_count",)),
        (
            "ChildDependencySnapshotModel",
            ("child_frontier", "child_check_id", "child_receipt_id", "membership_generation"),
        ),
        ("ProjectTextRefModel", ("envelope_digest",)),
        (
            "StatusFindingItemModel",
            (
                "todo_state",
                "review_rounds",
                "finding_frontier",
                "challenge",
                "duplicate_of_finding_id",
            ),
        ),
        ("CheckProjectedFindingModel", ("challenge",)),
        ("CheckVerifiedItemModel", ("snippet",)),
        ("StatusCompactItemModel", ("latest_check_test_edits", "latest_check")),
        ("StatusFindingsPageModel", ("attempt_budget",)),
        ("StatusProjectPageModel", ("title", "description", "title_ref", "description_ref")),
        (
            "StatusAdviceItemModel",
            (
                "coordination_project_id",
                "coordination_detection_id",
                "coordination_membership_generation",
                "coordination_counterpart_task_id",
                "coordination_resource_paths",
            ),
        ),
        ("StatusProjectDetectionModel", ("resource_paths",)),
        # Issue #909: a legacy or shell-less observed run states no tool, identity, or exit status.
        ("StatusObservedRunModel", ("tool_name", "command_commitment", "exit_status")),
    ):
        for field in fields:
            covered[model, field] = "test_nested_multi_agent_results_omit_unset_fields"
    # Issue #909: tests/unit/kernel/test_observed_failure_supersession.py projects a cooperative
    # result through the results view and asserts `observed_run` is absent from its wire form.
    covered["StatusResultItemModel", "observed_run"] = (
        "test_results_view_names_tool_occurrence_commitment_and_exit_status"
    )
    covered["RespondSuccessModel", "closure_after"] = (
        "test_respond_closure_after_omits_unset_fields"
    )
    for model_type, fields in (
        (CheckInspectionModel, ("observations_awaited",)),
        (CheckInspectionRemainingModel, ("predicted_conclusion",)),
        (CheckInspectionMissingModel, ("item_indexes",)),
        (CheckInspectionObservedModel, ("last_check_frontier",)),
        (
            CheckInspectionObservedActionModel,
            ("tool_name", "write_scope", "outcome", "exit_status", "command_commitment"),
        ),
        (CheckInspectionEvidenceSourceModel, ("command_commitment", "outcome")),
    ):
        for field in fields:
            covered[model_type.__name__, field] = "test_inspection_omits_every_unset_optional_field"
    covered["RespondClosureAfterModel", "limitation"] = (
        "test_respond_closure_after_omits_unset_fields"
    )
    for field in (
        "document_id",
        "revision",
        "digest",
        "total_byte_count",
        "page",
        "page_size",
        "page_offset",
        "page_byte_count",
        "page_count",
        "complete",
        "continuation",
        "sections",
    ):
        covered["ReadGuidanceSuccessModel", field] = (
            "test_legacy_guidance_result_omits_unset_paging_metadata"
        )
    expected = {
        (model_type.__name__, field)
        for model_type, fields in _RESULT_OPTIONAL_NON_NULL
        for field in fields
    }
    assert set(covered) == expected, (
        f"unset-projection coverage drifted: missing={expected - set(covered)} "
        f"extra={set(covered) - expected}"
    )


def test_server_filled_and_brief_fields_omit_when_unset() -> None:
    """Issue #1084: the new optional leaves are omitted when unset and refused as null."""

    state = StatusClosureStateModel.model_validate({"blocking_conditions": []})
    assert state.model_dump(mode="json", exclude_unset=True) == {"blocking_conditions": []}
    with pytest.raises(ValidationError):
        StatusClosureStateModel.model_validate({"blocking_conditions": [], "state": None})
    page = StatusOperationPageModel.model_validate(
        {"operation_request_id": protocol_id("req_", 1084), "found": False, "state": "absent"}
    )
    assert "server_filled" not in page.model_dump(mode="json", exclude_unset=True)
    with pytest.raises(ValidationError):
        StatusOperationPageModel.model_validate(
            {
                "operation_request_id": protocol_id("req_", 1084),
                "found": False,
                "state": "absent",
                "server_filled": None,
            }
        )
    # Review R1 of PR #1088: the reduced success's provenance and resumed-call notice.
    frontier = {"sequence": "2", "head_digest": "sha256:" + "2" * 64}
    reduced_body: dict[str, Any] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": protocol_id("req_", 1085),
        "ok": True,
        "response_completeness": "accepted_projection_unavailable",
        "reason_code": "response_projection_failed",
        "correlation_id": protocol_id("err_", 1085),
        "outcome": "replayed",
        "task_id": protocol_id("tsk_", 1085),
        "session_id": protocol_id("ses_", 1085),
        "writer_id": protocol_id("wri_", 1085),
        "subject_frontier": {"sequence": "1", "head_digest": "sha256:" + "1" * 64},
        "result_frontier": frontier,
        "accepted_events": [
            {
                "event_id": protocol_id("evt_", 1085),
                "entry_digest": "sha256:" + "3" * 64,
                "ingestion_sequence": "2",
            }
        ],
    }
    reduced = PublishWorkAcceptedProjectionUnavailableModel.model_validate(reduced_body)
    dumped = reduced.model_dump(mode="json", exclude_unset=True)
    assert "server_filled" not in dumped and "replay_notice" not in dumped
    for field in ("server_filled", "replay_notice"):
        with pytest.raises(ValidationError):
            PublishWorkAcceptedProjectionUnavailableModel.model_validate(
                {**reduced_body, field: None}
            )
    success_notice = PublishWorkReplayNoticeModel.model_validate(
        {"notice": "unresolved_call_resumed", "text": PUBLISH_RESUMED_CALL_NOTICE_TEXT}
    )
    assert success_notice.notice == "unresolved_call_resumed"
    # Review R7: an unlabelled history row omits occurred_at_source and refuses null.
    row: dict[str, Any] = {
        "event_id": protocol_id("evt_", 1086),
        "schema_name": "decision_recorded",
        "schema_version": "1.0.0",
        "actor_id": "harness:test",
        "publication_channel": "cooperative_mcp",
        "ingestion_sequence": "3",
        "occurred_at": "2026-10-16T00:00:00.000Z",
        "accepted_at": "2026-10-16T00:00:00.000Z",
        "occurred_at_consistency": "within_forward_skew_allowance",
        "projection_status": "projected",
        "summary_code": "decision_recorded",
    }
    history = StatusHistoryItemV14Model.model_validate(row)
    assert "occurred_at_source" not in history.model_dump(mode="json", exclude_unset=True)
    with pytest.raises(ValidationError):
        StatusHistoryItemV14Model.model_validate({**row, "occurred_at_source": None})
    labelled = StatusHistoryItemV14Model.model_validate(
        {**row, "occurred_at_source": "service_clock"}
    )
    assert labelled.occurred_at_source == "service_clock"


def test_review_mode_omits_unset_reason_and_switch() -> None:
    """ADR-049: a conversation-default review mode omits its reason and switch; null is refused."""

    check_mode = CheckReviewModeModel.model_validate(
        {"mode": "ai_powered", "source": "conversation_default"}
    )
    assert check_mode.model_dump(mode="json", exclude_unset=True) == {
        "mode": "ai_powered",
        "source": "conversation_default",
    }
    for field in CheckReviewModeModel.optional_non_null_fields:
        with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
            CheckReviewModeModel.model_validate(
                {"mode": "local", "source": "conversation_default", field: None}
            )
    status_mode = StatusReviewModeModel.model_validate(
        {
            "mode": "local",
            "requested": "local",
            "setting": "local_agent_opt_in",
            "setting_explicit": True,
            "ai_review_available": True,
        }
    )
    assert (
        not StatusReviewModeModel.optional_non_null_fields
        & status_mode.model_dump(mode="json", exclude_unset=True).keys()
    )
    for field in StatusReviewModeModel.optional_non_null_fields:
        with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
            StatusReviewModeModel.model_validate(
                {
                    "mode": "local",
                    "requested": "local",
                    "setting": "local_agent_opt_in",
                    "setting_explicit": True,
                    "ai_review_available": True,
                    field: None,
                }
            )


def test_respond_closure_after_omits_unset_fields() -> None:
    """tb4n3 RC-7: an absent closure_after / limitation is omitted, never an explicit null."""

    from unit.protocol.test_models_and_schemas import (
        _respond_result_wire,  # pyright: ignore[reportPrivateUsage]
    )

    closure = RespondClosureAfterModel.model_validate({"todo_state": "open"})
    assert "limitation" not in closure.model_dump(mode="json", exclude_unset=True)
    with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
        RespondClosureAfterModel.model_validate({"todo_state": "open", "limitation": None})
    wire = _respond_result_wire()
    assert "closure_after" not in wire
    model = RespondSuccessModel.model_validate(wire)
    assert "closure_after" not in model.model_dump(mode="json", exclude_unset=True)
    with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
        RespondSuccessModel.model_validate({**wire, "closure_after": None})


async def test_legacy_guidance_result_omits_unset_paging_metadata() -> None:
    from finishup.mcp.server import dispatch_read_guidance

    result = await dispatch_read_guidance({"uri": "finishup://guidance/agent-instructions.md"})
    assert result.isError is False
    assert result.structuredContent is not None
    wire = result.structuredContent
    assert wire["ok"] is True
    assert wire["text"]
    for field in ReadGuidanceSuccessModel.optional_non_null_fields:
        assert field not in wire


def test_inspection_omits_every_unset_optional_field() -> None:
    """Issue #1048: an inspection row without an optional fact omits it and refuses a null."""

    rows: tuple[tuple[type[BaseModel], dict[str, object], tuple[str, ...]], ...] = (
        (
            CheckInspectionRemainingModel,
            {
                "readiness": "unknown",
                "agent_actionable": (),
                "standing_limitations": (),
                "obligations": (),
                "obligation_count": "0",
                "findings": (),
                "finding_count": "0",
            },
            ("predicted_conclusion",),
        ),
        (
            CheckInspectionMissingModel,
            {"kind": "resolution_evidence_not_cited", "owner": "agent"},
            ("item_indexes",),
        ),
        (
            CheckInspectionObservedModel,
            {"actions": (), "action_count": "0"},
            ("last_check_frontier",),
        ),
        (
            CheckInspectionObservedActionModel,
            {
                "event_id": protocol_id("evt_", 4801),
                "ledger_sequence": "3",
                "action_kind": "edit",
                "material_class": "edit_or_write",
            },
            ("tool_name", "write_scope", "outcome", "exit_status", "command_commitment"),
        ),
        (
            CheckInspectionEvidenceSourceModel,
            {"ref": protocol_id("evd_", 4802), "origin": "unattributed", "named_item_indexes": ()},
            ("command_commitment", "outcome"),
        ),
    )
    for model_type, payload, fields in rows:
        dumped = model_type.model_validate(payload).model_dump(mode="json", exclude_unset=True)
        for field in fields:
            assert field not in dumped, (model_type.__name__, field)
            with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
                model_type.model_validate({**payload, field: None})
    body: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": protocol_id("req_", 4803),
        "ok": True,
        "state": "inspected",
        "task_id": protocol_id("tsk_", 4804),
        "session_id": protocol_id("ses_", 4805),
        "writer_id": protocol_id("wri_", 4806),
        "subject_frontier": {"sequence": "0", "head_digest": "genesis"},
        "remaining": rows[0][1],
        "observed_since_check": rows[2][1],
        "evidence_alignment": {
            "basis": "recorded_links",
            "obligations": (),
            "obligation_count": "0",
            "off_declared_count": "0",
        },
        "privacy_projection": _privacy_projection_payload(),
    }
    model = CheckInspectionModel.model_validate(body)
    assert "observations_awaited" not in model.model_dump(mode="json", exclude_unset=True)
    with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
        CheckInspectionModel.model_validate({**body, "observations_awaited": None})
