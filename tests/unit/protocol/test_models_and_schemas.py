"""B0 schema-catalog checks; model parity joins this owner with models.py."""

from __future__ import annotations

import hashlib
import importlib
import shutil
import socket
from collections.abc import Callable, Mapping
from dataclasses import FrozenInstanceError, fields
from importlib import resources
from pathlib import Path
from typing import Any, ClassVar, cast
from urllib.parse import urldefrag

import pytest
from pydantic import BaseModel, Field, ValidationError

import yoetz.protocol.schemas as schemas_module
from builders.readiness import with_checklist
from yoetz.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.schemas import (
    SCHEMA_MANIFEST_SCHEMA,
    SCHEMA_MANIFEST_VERSION,
    SCHEMA_MEMBER_COUNT,
    SCHEMA_NAMESPACE,
    SchemaArtifactRole,
    SchemaCatalog,
    SchemaDocument,
    SchemaKind,
    event_schema_versions,
    load_schema_catalog,
    request_result_schema_versions,
    schema_document_for,
    schema_path_for,
    schema_uri,
    validate_schema_document,
    validate_schema_instance,
)

_VALID_COVERAGE: dict[str, JsonValue] = {
    "publication_channels": ["cooperative_mcp"],
    "authorship_assurance": "self_asserted",
    "artifact_observation": "published_only",
    "evidence_immutability": "content_digest",
    "ledger_freshness": "current",
    "check_types": ["none"],
    "known_gaps": [],
}
_SCHEMA_RESOURCE_ROOT = resources.files("yoetz").joinpath("resources").joinpath("schemas")
_EXPECTED_PROTOCOL_VERSION = "0.1"
_EXPECTED_SCHEMA_VERSION = "1.0.0"
_EXPECTED_MAX_EVENTS_PER_BATCH = 100
_EXPECTED_MAX_CANONICAL_REQUEST_BYTES = 1_048_576
_EXPECTED_MAX_FINDINGS_DEFAULT = 3
_EXPECTED_MAX_FINDINGS_LIMIT = 10
_EXPECTED_MAX_REASON_BYTES = 4_096
_EXPECTED_MAX_OBJECT_PLAINTEXT_BYTES = 4_194_304
_EXPECTED_MAX_SEMANTIC_ITEM_BYTES = 16_384
_EXPECTED_MAX_SEMANTIC_CASE_BYTES = 262_144
_EXPECTED_MAX_REVIEW_TEXT_BYTES = 4_096
_EXPECTED_MAX_REVIEW_TIMELINE_ITEMS = 64
_EXPECTED_MAX_REVIEW_ASSESSMENTS = 64
_EXPECTED_MAX_REVIEW_CHANGE_OBSERVATIONS = 32
_EXPECTED_MAX_REVIEW_EXCERPTS = 64
_EXPECTED_MAX_REVIEW_OMISSIONS = 64
_EXPECTED_MAX_REVIEW_CHALLENGES = 3
_EXPECTED_GENESIS_PREDECESSOR_DIGEST = "genesis"
_TEST_UUID = "00000000-0000-4000-8000-000000000001"

_EXPECTED_ACTOR_TYPES = {
    "delegated_subagent",
    "harness",
    "human",
    "importer",
    "logical_agent",
    "model_backed_worker",
    "yoetz_engine",
}
_EXPECTED_CLIENT_KINDS = {
    "cooperative_agent",
    "codex_cli",
    "importer",
    "test_client",
    "yoetz_cli",
}
_EXPECTED_INTEGRATION_KINDS = {
    "codex_jsonl_import",
    "cooperative_mcp",
    "local_cli",
}
_EXPECTED_DATA_CATEGORIES = {
    "bounded_structural_metadata",
    "declared_file_type",
    "task_description",
    "claim_text",
    "obligation_text",
    "decision_excerpt",
    "evidence_excerpt",
    "finding_summary",
    "command_metadata",
    "diff_metadata",
    "repository_excerpt",
    "transcript_excerpt",
    "diagnostic_metadata",
}
_EXPECTED_SEMANTIC_STATUSES = {
    "not_requested",
    "not_configured",
    "blocked_by_policy",
    "blocked_forbidden_data",
    "classification_uncertain",
    "awaiting_human",
    "human_denied",
    "approval_expired",
    "succeeded",
    "refused",
    "timeout",
    "invalid",
    "unavailable",
    "late",
    "stale",
    "failed",
}
_EXPECTED_SEMANTIC_STATUS_REASONS = {
    "not_requested": {"deterministic_mode", "no_material_semantic_case"},
    "not_configured": {"provider_not_configured", "local_model_not_configured"},
    "blocked_by_policy": {
        "network_egress_denied",
        "channel_disabled",
        "provider_binding_not_authorized",
        "scope_not_authorized",
        "content_category_not_authorized",
        "policy_generation_revoked",
        "route_semantic_ceiling",
    },
    "blocked_forbidden_data": {"never_send_detected", "secret_detected"},
    "classification_uncertain": {"classification_uncertain"},
    "awaiting_human": {"human_approval_required"},
    "human_denied": {"human_denied"},
    "approval_expired": {"human_approval_expired"},
    "succeeded": {"semantic_completed"},
    "refused": {"provider_refused"},
    "timeout": {"provider_timeout"},
    "invalid": {
        "response_schema_invalid",
        "response_content_invalid",
        "semantic_judgment_rejected",
    },
    "unavailable": {
        "credential_unavailable",
        "endpoint_profile_unavailable",
        "transport_unavailable",
        "provider_rate_limited",
        "provider_quota_exhausted",
        "retry_budget_exhausted",
        "audit_reservation_unavailable",
        "receipt_persistence_unknown",
        "outcome_unknown",
    },
    "late": {"deadline_authority_lost", "lease_authority_lost"},
    "stale": {"frontier_changed", "dependency_changed"},
    "failed": {"coordinator_failure", "case_capacity_exceeded"},
}
_REQUIRED_SEMANTIC_PROVENANCE_PAIRS = frozenset(
    (status, reason)
    for status in {"succeeded", "refused", "timeout", "invalid", "late", "stale"}
    for reason in _EXPECTED_SEMANTIC_STATUS_REASONS[status]
) | frozenset(
    {
        ("unavailable", "transport_unavailable"),
        ("unavailable", "provider_rate_limited"),
        ("unavailable", "provider_quota_exhausted"),
        ("unavailable", "outcome_unknown"),
    }
)
_OPTIONAL_SEMANTIC_PROVENANCE_PAIRS = frozenset({("failed", "coordinator_failure")})


def _models_module() -> Any:
    return importlib.import_module("yoetz.protocol.models")


def _schema_resource(rel_path: str) -> Any:
    return _SCHEMA_RESOURCE_ROOT.joinpath(*rel_path.split("/"))


def _schema_object_fields(
    rel_path: str, def_name: str | None = None
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    schema = _plain_object(_schema_resource(rel_path).read_bytes())
    node: dict[str, JsonValue]
    if def_name is None:
        node = schema
    else:
        defs = cast(dict[str, JsonValue], schema["$defs"])
        node = cast(dict[str, JsonValue], defs[def_name])
    properties = node.get("properties")
    if not isinstance(properties, dict):
        raise AssertionError("schema_properties_missing")
    required = node.get("required", [])
    if not isinstance(required, list):
        raise AssertionError("schema_required_missing")
    return tuple(properties), tuple(cast(list[str], required))


def _assert_model_contract(
    model: Any,
    rel_path: str,
    def_name: str | None = None,
) -> None:
    expected_fields, expected_required = _schema_object_fields(rel_path, def_name)
    assert set(model.model_fields) == set(expected_fields)
    assert {name for name, field in model.model_fields.items() if field.is_required()} == set(
        expected_required
    )
    config = model.model_config
    assert config.get("frozen") is True
    assert config.get("strict") is True
    assert config.get("validate_default") is True
    assert config.get("extra") == "forbid"


_COMMON_MODEL_SPECS: tuple[tuple[str, str, str | None], ...] = (
    ("ActorAssertionModel", "common/actor-assertion-1.0.0.schema.json", None),
    ("ClientInfoModel", "common/client-info-1.0.0.schema.json", None),
    ("CoverageModel", "common/coverage-1.0.0.schema.json", None),
    ("FrontierModel", "common/frontier-1.0.0.schema.json", None),
    ("PublicErrorModel", "common/public-error-1.0.0.schema.json", None),
    ("SubjectStateRefModel", "common/subject-state-ref-1.0.0.schema.json", None),
    ("OperationFailureModel", "common/operation-result-1.0.0.schema.json", "failure_result"),
    ("OmittedContentModel", "common/operation-result-1.0.0.schema.json", "omitted_content"),
    ("PrivacyProjectionModel", "common/operation-result-1.0.0.schema.json", "privacy_projection"),
    ("CheckScopeModel", "operations/check-request-1.0.0.schema.json", "check_scope"),
)

_REQUEST_MODEL_SPECS: tuple[tuple[str, str], ...] = (
    ("StartRequestModel", "operations/start-request-1.1.0.schema.json"),
    ("PublishWorkRequestModel", "operations/publish-work-request-1.1.0.schema.json"),
    ("CheckRequestModel", "operations/check-request-1.1.0.schema.json"),
    ("RespondRequestModel", "operations/respond-request-1.0.0.schema.json"),
    ("StatusRequestModel", "operations/status-request-1.2.0.schema.json"),
    ("ReceiptRequestModel", "operations/receipt-request-1.0.0.schema.json"),
)

_REQUEST_SUPPORT_MODEL_SPECS: tuple[tuple[str, str, str], ...] = (
    (
        "StatusAssignmentFilterModel",
        "operations/status-request-1.1.0.schema.json",
        "assignment_filter",
    ),
    (
        "StatusCandidateFindingsFilterModel",
        "operations/status-request-1.1.0.schema.json",
        "candidate_findings_filter",
    ),
    (
        "StatusEvidenceFilterModel",
        "operations/status-request-1.2.0.schema.json",
        "evidence_filter",
    ),
    (
        "StatusFindingsFilterModel",
        "operations/status-request-1.1.0.schema.json",
        "findings_filter",
    ),
    (
        "StatusHistoryFilterModel",
        "operations/status-request-1.1.0.schema.json",
        "history_filter",
    ),
    (
        "StatusObligationsFilterModel",
        "operations/status-request-1.1.0.schema.json",
        "obligations_filter",
    ),
)

_ROOT_RESULT_MODEL_NAMES: tuple[str, ...] = (
    "StartResultModel",
    "PublishWorkResultModel",
    "CheckResultModel",
    "RespondResultModel",
    "StatusResultModel",
    "ReceiptResultModel",
)

_RESULT_SCHEMA_BY_METHOD_FOR_TEST: tuple[tuple[str, str], ...] = (
    ("check", "check-result"),
    ("publish_work", "publish-work-result"),
    ("receipt", "receipt-result"),
    ("respond", "respond-result"),
    ("start", "start-result"),
)
_STATUS_PAGE_DEF_BY_VIEW_FOR_TEST: tuple[tuple[str, str], ...] = (
    ("advice", "advice_page"),
    ("assignment", "assignment_page"),
    ("candidate_findings", "candidate_findings_page"),
    ("compact", "compact_page"),
    ("evidence", "evidence_page"),
    ("findings", "findings_page"),
    ("history", "history_page"),
    ("obligations", "obligations_page"),
    ("operation", "operation_page"),
    ("results", "results_page"),
    ("lineage", "lineage_page"),
    ("project", "project_page"),
    ("versions", "versions_page"),
)
_EXPECTED_RESULT_PATTERN_COUNTS: dict[tuple[str, str | None], int] = {
    ("check", None): 364,
    ("publish_work", None): 57,
    ("receipt", None): 276,
    ("respond", None): 53,
    ("start", None): 72,
    ("status", None): 56,
    ("status", "advice"): 25,
    ("status", "assignment"): 6,
    ("status", "candidate_findings"): 32,
    ("status", "compact"): 57,
    ("status", "evidence"): 19,
    ("status", "findings"): 125,
    ("status", "history"): 62,
    ("status", "lineage"): 16,
    ("status", "obligations"): 39,
    ("status", "operation"): 44,
    ("status", "project"): 67,
    ("status", "results"): 11,
    ("status", "versions"): 13,
}

_RESULT_SUPPORT_MODEL_SPECS: tuple[tuple[str, str, str], ...] = (
    ("StartSuccessModel", "operations/start-result-1.1.0.schema.json", "success"),
    ("StartCompactViewModel", "operations/start-result-1.0.0.schema.json", "compact_view"),
    ("StartVersionSliceModel", "operations/start-result-1.0.0.schema.json", "version_slice"),
    (
        "PublishWorkSuccessModel",
        "operations/publish-work-result-1.0.0.schema.json",
        "success",
    ),
    (
        "PublishWorkAcceptedEventModel",
        "operations/publish-work-result-1.0.0.schema.json",
        "accepted_event",
    ),
    (
        "PublishWorkAcceptedMinimalEventModel",
        "operations/publish-work-result-1.0.0.schema.json",
        "accepted_minimal_event",
    ),
    (
        "PublishWorkAcceptedProjectionUnavailableModel",
        "operations/publish-work-result-1.0.0.schema.json",
        "accepted_projection_unavailable",
    ),
    (
        "PublishWorkVersionSliceModel",
        "operations/publish-work-result-1.0.0.schema.json",
        "version_slice",
    ),
    ("CheckSuccessModel", "operations/check-result-1.4.0.schema.json", "success"),
    (
        "CheckPolicyExecutionModel",
        "operations/check-result-1.0.0.schema.json",
        "policy_execution",
    ),
    (
        "CheckProjectedFindingModel",
        "operations/check-result-1.4.0.schema.json",
        "projected_finding",
    ),
    ("CheckVersionSliceModel", "operations/check-result-1.0.0.schema.json", "version_slice"),
    ("RespondSuccessModel", "operations/respond-result-1.0.0.schema.json", "success"),
    (
        "RespondAcceptedEventModel",
        "operations/respond-result-1.0.0.schema.json",
        "accepted_event",
    ),
    (
        "RespondEvidenceSummaryModel",
        "operations/respond-result-1.0.0.schema.json",
        "evidence_summary",
    ),
    ("RespondResponseModel", "operations/respond-result-1.0.0.schema.json", "response"),
    ("RespondVersionSliceModel", "operations/respond-result-1.0.0.schema.json", "version_slice"),
    ("StatusSuccessModel", "operations/status-result-1.1.0.schema.json", "success"),
    (
        "StatusAdviceItemModel",
        "operations/status-result-1.4.0.schema.json",
        "advice_item",
    ),
    (
        "StatusAdvicePageModel",
        "operations/status-result-1.1.0.schema.json",
        "advice_page",
    ),
    (
        "StatusAssignmentItemModel",
        "operations/status-result-1.1.0.schema.json",
        "assignment_item",
    ),
    (
        "StatusAssignmentPageModel",
        "operations/status-result-1.1.0.schema.json",
        "assignment_page",
    ),
    (
        "StatusCandidateFindingItemModel",
        "operations/status-result-1.1.0.schema.json",
        "candidate_finding_item",
    ),
    (
        "StatusCandidateFindingsPageModel",
        "operations/status-result-1.1.0.schema.json",
        "candidate_findings_page",
    ),
    ("StatusCompactFindingModel", "operations/status-result-1.1.0.schema.json", "compact_finding"),
    ("StatusCompactItemModel", "operations/status-result-1.4.0.schema.json", "compact_item"),
    (
        "StatusLatestCheckTestEditsModel",
        "operations/status-result-1.4.0.schema.json",
        "latest_check_test_edits",
    ),
    (
        "StatusCompactObligationModel",
        "operations/status-result-1.1.0.schema.json",
        "compact_obligation",
    ),
    ("StatusCompactPageModel", "operations/status-result-1.1.0.schema.json", "compact_page"),
    ("StatusEvidenceItemModel", "operations/status-result-1.4.0.schema.json", "evidence_item"),
    ("StatusEvidencePageModel", "operations/status-result-1.1.0.schema.json", "evidence_page"),
    ("StatusFindingBasisModel", "operations/status-result-1.1.0.schema.json", "finding_basis"),
    ("StatusFindingItemModel", "operations/status-result-1.4.0.schema.json", "finding_item"),
    ("StatusFindingsPageModel", "operations/status-result-1.4.0.schema.json", "findings_page"),
    ("StatusHistoryItemModel", "operations/status-result-1.1.0.schema.json", "history_item"),
    ("StatusHistoryPageModel", "operations/status-result-1.1.0.schema.json", "history_page"),
    ("StatusImportStatusModel", "operations/status-result-1.1.0.schema.json", "import_status"),
    (
        "StatusClosureReadinessModel",
        "operations/status-result-1.4.0.schema.json",
        "closure_readiness",
    ),
    # The unreleased 1.4.0 obligations row shows the acknowledgement reason (#1002).
    ("StatusObligationItemModel", "operations/status-result-1.4.0.schema.json", "obligation_item"),
    # The unreleased 1.4.0 obligations view shows directory items and their role (#1002).
    (
        "StatusRequestedItemModel",
        "operations/status-result-1.4.0.schema.json",
        "status_requested_item",
    ),
    (
        "StatusObligationsPageModel",
        "operations/status-result-1.1.0.schema.json",
        "obligations_page",
    ),
    # The unreleased 1.4.0 results view adds the optional structural observed run (#909).
    ("StatusResultItemModel", "operations/status-result-1.4.0.schema.json", "result_item"),
    ("StatusObservedRunModel", "operations/status-result-1.4.0.schema.json", "observed_run"),
    ("StatusResultsPageModel", "operations/status-result-1.1.0.schema.json", "results_page"),
    (
        "StatusStructuralSubjectStateModel",
        "operations/status-result-1.1.0.schema.json",
        "structural_subject_state",
    ),
    ("StatusVersionSliceModel", "operations/status-result-1.1.0.schema.json", "version_slice"),
    ("StatusVersionsPageModel", "operations/status-result-1.1.0.schema.json", "versions_page"),
    ("ReceiptSuccessModel", "operations/receipt-result-1.0.0.schema.json", "success"),
    (
        "ReceiptPolicyVersionEntryModel",
        "operations/receipt-result-1.0.0.schema.json",
        "policy_version_entry",
    ),
    (
        "ReceiptSchemaVersionEntryModel",
        "operations/receipt-result-1.0.0.schema.json",
        "schema_version_entry",
    ),
    ("ReceiptVersionSliceModel", "operations/receipt-result-1.0.0.schema.json", "version_slice"),
)


def _assert_enum_values(enum_type: Any, expected: set[str]) -> None:
    assert {member.value for member in enum_type} == expected


def _assert_semantic_reason_matrix(models: Any) -> None:
    status_enum = models.SemanticStatus
    reason_enum = models.SemanticReason
    relation = models.VALID_SEMANTIC_REASONS
    assert set(member.value for member in status_enum) == _EXPECTED_SEMANTIC_STATUSES
    assert {member.value for member in relation} == _EXPECTED_SEMANTIC_STATUSES
    observed_reasons: set[str] = set()
    for status_value, expected_reasons in _EXPECTED_SEMANTIC_STATUS_REASONS.items():
        status_member = status_enum(status_value)
        matrix_reasons = relation[status_member]
        observed_reasons.update(reason.value for reason in matrix_reasons)
        assert {reason.value for reason in matrix_reasons} == expected_reasons
        for reason_value in expected_reasons:
            assert (
                models.validate_semantic_outcome(status_member, reason_enum(reason_value)) is None
            )
    assert {member.value for member in reason_enum} == observed_reasons
    with pytest.raises(ProtocolValueError) as exc_info:
        models.validate_semantic_outcome(status_enum("failed"), reason_enum("semantic_completed"))
    _assert_reason(exc_info, "invalid_semantic_status_reason_pair")


def _test_id(prefix: str) -> str:
    return f"{prefix}{_TEST_UUID}"


def _actor_wire() -> dict[str, JsonValue]:
    return {"actor_id": "harness:test", "actor_type": "harness"}


def _client_wire() -> dict[str, JsonValue]:
    return {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"}


def _coverage_wire() -> dict[str, JsonValue]:
    return {
        "publication_channels": ["cooperative_mcp"],
        "authorship_assurance": "self_asserted",
        "artifact_observation": "published_only",
        "evidence_immutability": "content_digest",
        "ledger_freshness": "current",
        "check_types": ["none"],
        "known_gaps": [],
    }


def _privacy_projection_wire() -> dict[str, JsonValue]:
    return {
        "sink": "agent_context",
        "local_disclosure_receipt_id": _test_id("egr_"),
        "policy_id": _test_id("pvy_"),
        "policy_version": "1",
        "policy_digest": f"sha256:{'0' * 64}",
        "included_categories": [],
        "blocked_categories": [],
        "omitted_pointers": [],
        "projection_commitment": f"hmac-sha256:{'1' * 64}",
    }


def _start_request_wire() -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _test_id("req_"),
        "actor": _actor_wire(),
        "client": _client_wire(),
        "mode": "create",
        "task_title": "Materialize the protocol",
        "requested_view": "compact",
    }


def _start_result_wire() -> dict[str, JsonValue]:
    session_id = _test_id("ses_")
    writer_id = _test_id("wri_")
    frontier: dict[str, JsonValue] = {"sequence": "0", "head_digest": "genesis"}
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _test_id("req_"),
        "ok": True,
        "outcome": "created",
        "task_id": _test_id("tsk_"),
        "session_id": session_id,
        "writer_id": writer_id,
        "frontier": frontier,
        "compact": {
            "open_obligation_count": "0",
            "unanswered_finding_count": "0",
            "receipt_blocking_finding_count": "0",
            "ledger_freshness": "current",
            "coverage": _coverage_wire(),
            "gaps": [],
        },
        "versions": {
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "0.1.0",
            "policy_packs": [],
        },
        "next_request_template": {
            "evidential": False,
            "operation": "publish_work",
            "arguments": {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": "",
                "actor": {"actor_id": "", "actor_type": ""},
                "client": {"kind": "", "version": "", "integration": ""},
                "session_id": session_id,
                "writer_id": writer_id,
                "expected_frontier": frontier,
                "event_drafts": [
                    {
                        "event_id": "",
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "",
                        "causal_parents": [],
                        "payload": {
                            "plan_version": 1,
                            "summary": "",
                            "obligation_refs": [""],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": "",
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "",
                        "causal_parents": [],
                        "payload": {
                            "obligation_id": "",
                            "description": "",
                            "acceptance_criteria": "",
                            "evidence_expectation": "",
                            "status": "open",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            },
        },
        "privacy_projection": _privacy_projection_wire(),
    }


def _check_result_wire() -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _test_id("req_"),
        "ok": True,
        "state": "complete",
        "task_id": _test_id("tsk_"),
        "session_id": _test_id("ses_"),
        "writer_id": _test_id("wri_"),
        "subject_frontier": {"sequence": "1", "head_digest": f"sha256:{'2' * 64}"},
        "result_frontier": {"sequence": "1", "head_digest": f"sha256:{'2' * 64}"},
        "verdict": "action_required",
        "findings": [
            {
                "finding_id": _test_id("fnd_"),
                "kind": "action_without_result",
                "origin": "deterministic",
                "priority": 1,
                "summary": "An action has no result.",
                "detail": "Record the terminal result.",
                "subject_refs": [_test_id("act_")],
                "policy_id": "work-integrity",
                "policy_version": "0.1.0",
                "subject_frontier": {
                    "sequence": "1",
                    "head_digest": f"sha256:{'2' * 64}",
                },
                "coverage": _coverage_wire(),
                "provenance": None,
            }
        ],
        "suppressed_count": "0",
        "policy_executions": [
            {
                "policy_id": "work-integrity",
                "policy_version": "0.1.0",
                "outcome": "run",
                "reason": "completed",
            }
        ],
        "semantic_status": "not_requested",
        "semantic_reason": "deterministic_mode",
        "coverage": _coverage_wire(),
        "versions": {
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "0.1.0",
            "policy_packs": ["work-integrity/0.1.0"],
        },
        "privacy_projection": _privacy_projection_wire(),
    }


def _publish_result_wire() -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _test_id("req_"),
        "ok": True,
        "outcome": "accepted",
        "task_id": _test_id("tsk_"),
        "session_id": _test_id("ses_"),
        "writer_id": _test_id("wri_"),
        "subject_frontier": {"sequence": "0", "head_digest": "genesis"},
        "result_frontier": {"sequence": "1", "head_digest": f"sha256:{'2' * 64}"},
        "accepted_events": [
            {
                "event_id": _test_id("evt_"),
                "schema_name": "plan_published",
                "schema_version": "1.0.0",
                "writer_sequence": "1",
                "ingestion_sequence": "1",
                "accepted_at": "2026-07-18T12:34:56.789Z",
                "predecessor_digest": "genesis",
                "entry_digest": f"sha256:{'2' * 64}",
                "projection_status": "projected",
                "summary": "Materialize the protocol",
            }
        ],
        "warning_codes": [],
        "coverage": _coverage_wire(),
        "gaps": [],
        "versions": {
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "0.1.0",
            "policy_packs": [],
        },
        "privacy_projection": _privacy_projection_wire(),
    }


def _status_result_wire() -> dict[str, JsonValue]:
    frontier: dict[str, JsonValue] = {"sequence": "0", "head_digest": "genesis"}
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _test_id("req_"),
        "ok": True,
        "task_id": _test_id("tsk_"),
        "session_id": _test_id("ses_"),
        "writer_id": _test_id("wri_"),
        "view": "versions",
        "requested_frontier": dict(frontier),
        "head_frontier": dict(frontier),
        "subject_frontier": dict(frontier),
        "result_frontier": dict(frontier),
        "projection_lag": "0",
        "projection_version": "0.1.0",
        "rebuild_state": "current",
        "page": {"items": [], "next_cursor": None},
        "coverage": _coverage_wire(),
        "gaps": [],
        "import_status": {
            "pending_count": "0",
            "terminal_count": "0",
            "phase": None,
            "report_evidence_id": None,
            "source_identity_digest": None,
        },
        "closure_readiness": with_checklist(
            {
                "declared_obligation_count": "0",
                "no_obligations_reason": None,
                "open_obligation_count": "0",
                "unanswered_finding_count": "0",
                "receipt_blocking_finding_count": "0",
                "blocking_conditions": ["no_obligations_declared"],
            }
        ),
        "privacy_projection": _privacy_projection_wire(),
    }


def _candidate_status_result_wire(*, omitted: bool = False) -> dict[str, JsonValue]:
    result = _status_result_wire()
    result["view"] = "candidate_findings"
    content: JsonValue = (
        {
            "omitted": True,
            "category": "finding_summary",
            "reason": "local_disclosure_not_authorized",
        }
        if omitted
        else "A local candidate finding."
    )
    result["page"] = {
        "items": [
            {
                "kind": "action_without_result",
                "origin": "deterministic",
                "priority": 1,
                "summary": content,
                "detail": content,
                "subject_refs": [_test_id("act_")],
                "policy_id": "work-integrity",
                "policy_version": "0.1.0",
                "subject_frontier": {"sequence": "0", "head_digest": "genesis"},
                "coverage": _coverage_wire(),
                "basis": {
                    "rule_id": "action_without_result",
                    "observed_fact_codes": ["action_recorded"],
                    "observed_refs": [_test_id("act_")],
                    "required_missing_fact_codes": ["result_recorded"],
                    "subject_state_relation": "unknown",
                    "frozen_source_availability": "available",
                    "coverage_gaps": [],
                    "evidence_refs": [],
                },
            }
        ],
        "next_cursor": None,
    }
    return result


def test_human_status_renders_operation_continuation_and_exact_trusted_command() -> None:
    from yoetz.cli.render import render_human_status

    models = _models_module()
    result = _status_result_wire()
    operation_request_id = _test_id("req_")
    result["view"] = "operation"
    result["page"] = {
        "operation_request_id": operation_request_id,
        "found": True,
        "state": "pending",
        "operation_kind": "check",
        "outcome": None,
        "subject_frontier": None,
        "result_frontier": None,
        "accepted_events": [],
        "continuation": {
            "kind": "repository_privacy_setup",
            "command": ["yoetz", "--privacy"],
            "replay_request_id": operation_request_id,
            "instruction": "Run the trusted repository privacy setup, then replay this request.",
        },
        "next_cursor": None,
    }
    parsed = models.StatusResultModel.model_validate(result)
    assert type(parsed.root) is models.StatusSuccessModel
    rendered = render_human_status(parsed.root)
    assert "Unanswered findings: 0" in rendered
    assert "Receipt-blocking findings: 0" in rendered
    assert "Continuation: repository_privacy_setup" in rendered
    assert "Trusted command: yoetz --privacy" in rendered
    assert f"Replay request ID: {operation_request_id}" in rendered


def test_human_status_reports_latest_check_test_edit_totals() -> None:
    from yoetz.cli.render import render_human_status

    models = _models_module()
    result = _status_result_wire()
    result["view"] = "compact"
    result["page"] = {
        "items": [
            {
                "task_id": _test_id("tsk_"),
                "session_id": _test_id("ses_"),
                "task_title": "Test-edit visibility",
                "current_plan_event_id": None,
                "declared_obligation_count": "0",
                "no_obligations_reason": None,
                "open_obligation_count": "0",
                "unanswered_finding_count": "0",
                "receipt_blocking_finding_count": "0",
                "open_obligations": [],
                "unanswered_findings": [],
                "freshness": "current",
                "coverage": _coverage_wire(),
                "gaps": [],
                "latest_check_test_edits": {
                    "checked_frontier": {"sequence": "0", "head_digest": "genesis"},
                    "read_availability": "available",
                    "examined": "1",
                    "baseline_known": "1",
                    "modified": "2",
                    "renamed": "0",
                    "deleted": "0",
                    "skipped": "1",
                    "unjustified": "0",
                    "unknown": "0",
                },
            }
        ],
        "next_cursor": None,
    }
    parsed = models.StatusResultModel.model_validate(result)
    assert type(parsed.root) is models.StatusSuccessModel
    rendered = render_human_status(parsed.root)
    assert (
        "Latest check test edits: available; checked frontier 0; 2 modified, 0 renamed, "
        "0 deleted, 1 skipped, 0 unjustified, 0 unknown (baseline known 1)"
    ) in rendered


@pytest.mark.parametrize("attempt_count", [0, 3, 64])
def test_human_status_bounds_command_attempts_without_truncating_json(attempt_count: int) -> None:
    from yoetz.cli.render import render_human_status

    models = _models_module()
    result = _status_result_wire()
    result["view"] = "obligations"
    result["page"] = {
        "items": [
            {
                "obligation_id": _test_id("obl_"),
                "status": "open",
                "description": "Synthetic command obligation",
                "evidence_expectation": "Observed attempts",
                "source_refs": [],
                "assigned_actor_ids": [],
                "evidence_refs": [],
                "revision_event_id": None,
                "command_attempts": [
                    {
                        "requested_item_index": str(index),
                        "relation": "unknown",
                        "asserted_action_ids": [],
                        "observed_event_ids": [],
                    }
                    for index in range(attempt_count)
                ],
            }
        ],
        "next_cursor": None,
    }
    parsed = models.StatusResultModel.model_validate(result)
    assert type(parsed.root) is models.StatusSuccessModel
    rendered = render_human_status(parsed.root)
    assert rendered.count(" command item ") == min(attempt_count, 3)
    if attempt_count > 3:
        assert f"{attempt_count - 3} more command attempts" in rendered
        assert "use JSON status for all items" in rendered
    else:
        assert "more command attempts" not in rendered
    page = parsed.model_dump(mode="json")["page"]
    assert len(page["items"][0]["command_attempts"]) == attempt_count


def test_human_status_reports_unknown_readiness_counts_as_unavailable() -> None:
    """An unreadable compact singleton must not render as ``None`` or as a clean zero."""

    from yoetz.cli.render import render_human_status

    models = _models_module()
    result = _status_result_wire()
    result["closure_readiness"] = with_checklist(
        {
            "declared_obligation_count": None,
            "no_obligations_reason": None,
            "open_obligation_count": None,
            "unanswered_finding_count": None,
            "receipt_blocking_finding_count": None,
            "blocking_conditions": ["readiness_unknown"],
        }
    )
    parsed = models.StatusResultModel.model_validate(result)
    assert type(parsed.root) is models.StatusSuccessModel
    rendered = render_human_status(parsed.root)
    assert "None" not in rendered
    assert "Open obligations: unavailable" in rendered
    assert "Unanswered findings: unavailable" in rendered
    assert "Receipt-blocking findings: unavailable" in rendered


def _respond_result_wire() -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _test_id("req_"),
        "ok": True,
        "task_id": _test_id("tsk_"),
        "session_id": _test_id("ses_"),
        "writer_id": _test_id("wri_"),
        "subject_frontier": {"sequence": "1", "head_digest": f"sha256:{'2' * 64}"},
        "result_frontier": {"sequence": "2", "head_digest": f"sha256:{'3' * 64}"},
        "accepted_event": {
            "event_id": _test_id("evt_"),
            "writer_sequence": "2",
            "ingestion_sequence": "2",
            "accepted_at": "2026-07-18T12:34:56.789Z",
            "entry_digest": f"sha256:{'3' * 64}",
        },
        "response": {
            "response_event_id": _test_id("evt_"),
            "finding_id": _test_id("fnd_"),
            "finding_frontier": {"sequence": "1", "head_digest": f"sha256:{'2' * 64}"},
            "disposition": "rejected",
            "evidence": [
                {
                    "reference_id": _test_id("evd_"),
                    "description": "The recorded evidence is insufficient.",
                }
            ],
            "reason": "The finding remains valid.",
        },
        "coverage": _coverage_wire(),
        "warning_codes": [],
        "versions": {
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "0.1.0",
            "policy_packs": ["work-integrity/0.1.0"],
        },
        "privacy_projection": _privacy_projection_wire(),
    }


def _receipt_fixture_expected() -> dict[str, JsonValue]:
    fixture_path = (
        Path(__file__).resolve().parents[3]
        / "fixtures"
        / "receipts"
        / "deterministic-current.case.json"
    )
    fixture = _plain_object(fixture_path.read_bytes())
    expected = cast(dict[str, JsonValue], fixture["expected"])
    variants = cast(dict[str, JsonValue], expected["variants"])
    return cast(dict[str, JsonValue], variants["current_complete"])


def _semantic_provenance_wire() -> dict[str, JsonValue]:
    fixture_path = (
        Path(__file__).resolve().parents[3]
        / "fixtures"
        / "receipts"
        / "semantic-advisory.case.json"
    )
    fixture = _plain_object(fixture_path.read_bytes())
    expected = cast(dict[str, JsonValue], fixture["expected"])
    variants = cast(dict[str, JsonValue], expected["variants"])
    variant = cast(dict[str, JsonValue], variants["success_after_durable_receipt"])
    document = cast(dict[str, JsonValue], variant["receipt_document"])
    findings = cast(list[JsonValue], document["findings"])
    finding = cast(dict[str, JsonValue], findings[0])
    return cast(dict[str, JsonValue], finding["provenance"])


def _semantic_provenance_for(status: str, reason: str) -> dict[str, JsonValue]:
    provenance = _semantic_provenance_wire()
    provenance["status"] = status
    provenance["reason"] = reason
    return provenance


def _all_event_families_fixture() -> dict[str, JsonValue]:
    fixture_path = (
        Path(__file__).resolve().parents[3] / "fixtures" / "replay" / "all-event-families.case.json"
    )
    return _plain_object(fixture_path.read_bytes())


def _check_recorded_payload_wire() -> dict[str, JsonValue]:
    fixture = _all_event_families_fixture()
    fixture_input = cast(dict[str, JsonValue], fixture["input"])
    entries = cast(list[JsonValue], fixture_input["accepted_entries"])
    for raw_entry in entries:
        entry = cast(dict[str, JsonValue], raw_entry)
        envelope = cast(dict[str, JsonValue], entry["envelope"])
        schema = cast(dict[str, JsonValue], envelope["schema"])
        if schema["name"] == "check_recorded":
            return cast(dict[str, JsonValue], entry["payload"])
    raise AssertionError("check_recorded_fixture_missing")


def _accepted_event_wire() -> dict[str, JsonValue]:
    fixture = _all_event_families_fixture()
    fixture_input = cast(dict[str, JsonValue], fixture["input"])
    entries = cast(list[JsonValue], fixture_input["accepted_entries"])
    first_entry = cast(dict[str, JsonValue], entries[0])
    return cast(dict[str, JsonValue], first_entry["envelope"])


def _receipt_result_wire() -> dict[str, JsonValue]:
    expected = _receipt_fixture_expected()
    document = cast(dict[str, JsonValue], expected["receipt_document"])
    # The frozen receipt fixture predates the additive child rollup section.  Keep that fixture
    # byte-identical and construct the current 1.2 result document at the wire boundary.
    document["children"] = {"children": []}
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _test_id("req_"),
        "ok": True,
        "receipt_id": document["receipt_id"],
        "task_id": document["task_id"],
        "session_id": document["session_id"],
        "subject_frontier": document["subject_frontier"],
        "result_frontier": {"sequence": "13", "head_digest": f"sha256:{'3' * 64}"},
        "receipt_object_id": _test_id("obj_"),
        "receipt_digest": expected["canonical_receipt_digest"],
        "conclusion": document["conclusion"],
        "redaction_profile": "full_local",
        "format": "json",
        "include": "full",
        "document": document,
        "human_text": None,
        "coverage": document["coverage"],
        "suppressed_finding_count": document["suppressed_finding_count"],
        "versions": document["versions"],
        "privacy_projection": _privacy_projection_wire(),
    }


def _failure_result_wire() -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _test_id("req_"),
        "ok": False,
        "error": {
            "code": "INVALID_REQUEST",
            "message": "The request is invalid.",
            "retryable": False,
            "correlation_id": _test_id("err_"),
        },
    }


def test_shared_protocol_constants_match_frozen_values() -> None:
    models = _models_module()
    assert models.PROTOCOL_VERSION == _EXPECTED_PROTOCOL_VERSION
    assert models.MAX_EVENTS_PER_BATCH == _EXPECTED_MAX_EVENTS_PER_BATCH
    assert models.MAX_CANONICAL_REQUEST_BYTES == _EXPECTED_MAX_CANONICAL_REQUEST_BYTES
    assert models.MAX_FINDINGS_DEFAULT == _EXPECTED_MAX_FINDINGS_DEFAULT
    assert models.MAX_FINDINGS_LIMIT == _EXPECTED_MAX_FINDINGS_LIMIT
    assert models.MAX_REASON_BYTES == _EXPECTED_MAX_REASON_BYTES
    assert models.MAX_OBJECT_PLAINTEXT_BYTES == _EXPECTED_MAX_OBJECT_PLAINTEXT_BYTES
    assert models.MAX_SEMANTIC_ITEM_BYTES == _EXPECTED_MAX_SEMANTIC_ITEM_BYTES
    assert models.MAX_SEMANTIC_CASE_BYTES == _EXPECTED_MAX_SEMANTIC_CASE_BYTES
    assert models.MAX_REVIEW_TEXT_BYTES == _EXPECTED_MAX_REVIEW_TEXT_BYTES
    assert models.MAX_REVIEW_TIMELINE_ITEMS == _EXPECTED_MAX_REVIEW_TIMELINE_ITEMS
    assert models.MAX_REVIEW_ASSESSMENTS == _EXPECTED_MAX_REVIEW_ASSESSMENTS
    assert models.MAX_REVIEW_CHANGE_OBSERVATIONS == _EXPECTED_MAX_REVIEW_CHANGE_OBSERVATIONS
    assert models.MAX_REVIEW_EXCERPTS == _EXPECTED_MAX_REVIEW_EXCERPTS
    assert models.MAX_REVIEW_OMISSIONS == _EXPECTED_MAX_REVIEW_OMISSIONS
    assert models.MAX_REVIEW_CHALLENGES == _EXPECTED_MAX_REVIEW_CHALLENGES
    assert models.GENESIS_PREDECESSOR_DIGEST == _EXPECTED_GENESIS_PREDECESSOR_DIGEST
    _assert_enum_values(models.ActorType, _EXPECTED_ACTOR_TYPES)
    _assert_enum_values(models.DataCategory, _EXPECTED_DATA_CATEGORIES)
    _assert_enum_values(models.ClientKind, _EXPECTED_CLIENT_KINDS)
    _assert_enum_values(models.IntegrationKind, _EXPECTED_INTEGRATION_KINDS)
    _assert_semantic_reason_matrix(models)


@pytest.mark.parametrize(
    ("model_name", "schema_path", "def_name"),
    _COMMON_MODEL_SPECS,
)
def test_common_models_match_frozen_schemas(
    model_name: str,
    schema_path: str,
    def_name: str | None,
) -> None:
    models = _models_module()
    _assert_model_contract(getattr(models, model_name), schema_path, def_name)


@pytest.mark.parametrize(("model_name", "schema_path"), _REQUEST_MODEL_SPECS)
def test_request_models_match_frozen_schemas(
    model_name: str,
    schema_path: str,
) -> None:
    models = _models_module()
    _assert_model_contract(getattr(models, model_name), schema_path)


@pytest.mark.parametrize(
    ("model_name", "schema_path", "def_name"),
    _REQUEST_SUPPORT_MODEL_SPECS,
)
def test_request_support_models_match_frozen_schemas(
    model_name: str,
    schema_path: str,
    def_name: str,
) -> None:
    models = _models_module()
    _assert_model_contract(getattr(models, model_name), schema_path, def_name)


@pytest.mark.parametrize(
    ("model_name", "schema_path", "def_name"),
    _RESULT_SUPPORT_MODEL_SPECS,
)
def test_result_support_models_match_frozen_schemas(
    model_name: str,
    schema_path: str,
    def_name: str,
) -> None:
    models = _models_module()
    _assert_model_contract(getattr(models, model_name), schema_path, def_name)


def test_coordination_advice_selector_and_resources_are_atomic() -> None:
    models = _models_module()
    selector_fields = {
        "coordination_project_id": "prj_59000000-0000-4000-8000-000000000001",
        "coordination_detection_id": "evt_59000000-0000-4000-8000-000000000002",
        "coordination_membership_generation": "3",
        "coordination_counterpart_task_id": "tsk_59000000-0000-4000-8000-000000000003",
        "coordination_resource_paths": {
            "omitted": True,
            "category": "repository_excerpt",
            "reason": "local_disclosure_not_authorized",
        },
    }
    base = {
        "finding_id": "fnd_59000000-0000-4000-8000-000000000004",
        "rule_code": "coordination_overlap",
        "priority": 50,
        "evidence_commitments": ("sha256:" + "a" * 64,),
        "coverage": {
            "publication_channels": ["local_cli"],
            "authorship_assurance": "self_asserted",
            "artifact_observation": "published_only",
            "evidence_immutability": "mutable_reference",
            "ledger_freshness": "current",
            "check_types": ["none"],
            "known_gaps": [],
        },
        "freshness_frontier": "membership_generation:3",
        "verification_state": "not_required",
        "semantic_state": "disabled",
        "recommended_next_action": "review_coordination_advice",
    }
    names = tuple(selector_fields)
    for mask in range(1, (1 << len(names)) - 1):
        partial = {
            name: selector_fields[name] for index, name in enumerate(names) if mask & (1 << index)
        }
        with pytest.raises(ValidationError, match="coordination_advice_selector_incomplete"):
            models.StatusAdviceItemModel.model_validate({**base, **partial})
    models.StatusAdviceItemModel.model_validate({**base, **selector_fields})


def test_result_roots_are_object_valued_root_models() -> None:
    models = _models_module()
    for model_name in _ROOT_RESULT_MODEL_NAMES:
        model = getattr(models, model_name)
        assert set(model.model_fields) == {"root"}
        assert model.model_config.get("frozen") is True
        assert model.model_config.get("strict") is True
        assert model.model_config.get("validate_default") is True
        assert model.model_config.get("extra") is None
        assert getattr(model, "__pydantic_root_model__", False) is True


def test_application_aliases_are_identity_aliases() -> None:
    models = _models_module()
    alias_pairs = (
        ("StartRequest", "StartRequestModel"),
        ("StartResult", "StartResultModel"),
        ("PublishWorkRequest", "PublishWorkRequestModel"),
        ("PublishWorkResult", "PublishWorkResultModel"),
        ("CheckRequest", "CheckRequestModel"),
        ("CheckResult", "CheckResultModel"),
        ("RespondRequest", "RespondRequestModel"),
        ("RespondResult", "RespondResultModel"),
        ("StatusRequest", "StatusRequestModel"),
        ("StatusResult", "StatusResultModel"),
        ("ReceiptRequest", "ReceiptRequestModel"),
        ("ReceiptResult", "ReceiptResultModel"),
        ("ClosurePrepareRequest", "ClosurePrepareRequestModel"),
        ("ClosurePrepareResult", "ClosurePrepareResultModel"),
    )
    for public_name, model_name in alias_pairs:
        assert getattr(models, public_name) is getattr(models, model_name)


def test_protocol_models_public_exports_are_closed() -> None:
    models = _models_module()
    expected = set(
        """
        GENESIS_PREDECESSOR_DIGEST MAX_CANONICAL_REQUEST_BYTES MAX_EVENTS_PER_BATCH
        MAX_FINDINGS_DEFAULT MAX_FINDINGS_LIMIT MAX_INTERNAL_PROJECTABLE_RESULT_BYTES
        MAX_OBJECT_PLAINTEXT_BYTES MAX_PROJECTED_RESULT_BYTES MAX_PROJECTION_CONTENT_LEAVES
        MAX_PROJECTION_POINTER_BYTES MAX_REASON_BYTES MAX_SEMANTIC_ITEM_BYTES
        MAX_SEMANTIC_CASE_BYTES MAX_REVIEW_TEXT_BYTES MAX_REVIEW_TIMELINE_ITEMS
        MAX_REVIEW_ASSESSMENTS MAX_REVIEW_CHANGE_OBSERVATIONS MAX_REVIEW_EXCERPTS
        MAX_REVIEW_OMISSIONS MAX_REVIEW_CHALLENGES MAX_TASK_STATEMENT_BYTES PROTOCOL_VERSION
        ActorAssertionModel
        ActorType CheckRequest CheckRequestModel CheckResult CheckResultModel CheckScopeModel
        ClientInfoModel ClientKind CoverageModel DataCategory FrontierModel IntegrationKind
        JsonValue OmittedContentModel OperationFailureModel PrivacyProjectionModel
        PublicEnvelopeModel PublicErrorModel PublicRequestModel PublicResultModel
        PublicationChannel PublishWorkAcceptedMinimalEventModel
        PublishWorkAcceptedProjectionUnavailableModel PublishWorkRequest
        PublishWorkRequestModel PublishWorkResult PublishWorkResultModel
        WorkState SessionHealth LineageOrigin LineageAcceptance ProjectKind MembershipKind
        GrantState LineageRollupState LineageReadGapReason LineageProvenanceRestriction
        AttachHandleModel ChildFindingSnapshotModel ChildDependencySnapshotModel
        ChildDependenciesModel CheckChildPreviewItemModel CheckChildrenPreviewModel
        CheckAdvisoryNoteModel CheckFindingChallengeModel CheckVerifiedItemModel
        ProviderVerifiedItemModel StatusLineageChildModel StatusLineageAnnotationModel
        StatusLineagePageModel ProjectTextRefModel StatusProjectMemberModel
        StatusProjectCoverageModel StatusProjectDetectionModel StatusProjectReceiptModel
        StatusProjectPageModel
        ReceiptChildOutcomeModel ReceiptChildrenModel
        ProviderChallengeModel ProviderJudgmentChallengesModel
        ProviderJudgmentEnvelopeModel
        ProviderJudgmentInsufficientModel ProviderJudgmentModel ProviderMissingItemModel
        CheckMissingItemModel MAX_MISSING_FOR_ASSESSMENT MAX_MISSING_REASON_BYTES
        MAX_MISSING_TARGET_REFS MISSING_FOR_ASSESSMENT_KINDS MISSING_ITEM_AVAILABILITIES
        ProviderJudgmentNoDiscrepancyModel
        SemanticWithheldItemModel
        MAX_PRIOR_FINDING_VERDICTS PriorFindingVerdictWire ProviderPriorFindingVerdictModel
        ReceiptFormat ReceiptInclude ReceiptRedactionProfile
        ReceiptRequest ReceiptRequestModel ReceiptResult ReceiptResultModel
        REGISTERED_GUIDANCE_URIS ReadGuidanceRequest ReadGuidanceRequestModel
        ReadGuidanceContinuationModel
        ReadGuidanceResult ReadGuidanceResultModel ClosurePrepareRequest
        ClosurePrepareRequestModel ClosurePrepareResult ClosurePrepareResultModel
        ClosureSelectionModel RespondRequest
        RespondRequestModel RespondResult RespondResultModel SemanticReason SemanticStatus
        SEMANTIC_PROGRESS_PHASE_RANK SemanticProgressPhase StatusSemanticProgressModel
        StartRequest StartRequestModel StartResult StartResultModel StatusRequest
        StatusRequestModel StatusResult StatusResultModel SubjectStateRefModel
        VALID_SEMANTIC_REASONS classify_result_leaf public_model_to_wire
        validate_semantic_outcome validate_semantic_provenance_binding
        """.split()
    )
    exports = cast(list[str], getattr(models, "__all__"))
    assert type(exports) is list
    assert len(exports) == len(set(exports))
    assert set(exports) == expected
    assert all(hasattr(models, name) for name in exports)
    assert not {"BaseModel", "SafeDetails", "datetime", "re", "types"} & set(exports)


def test_operation_wire_round_trip_preserves_presence() -> None:
    models = _models_module()
    omitted = models.StartRequestModel.model_validate(_start_request_wire())
    omitted_wire = models.public_model_to_wire(omitted)
    assert "session_id" not in omitted_wire
    assert "external_ref" not in omitted_wire
    assert "workspace_ref" not in omitted_wire

    explicit_null = {
        **_start_request_wire(),
        "session_id": None,
    }
    with pytest.raises(ValidationError):
        models.StartRequestModel.model_validate(explicit_null)

    status_wire = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _test_id("req_"),
        "actor": _actor_wire(),
        "client": _client_wire(),
        "session_id": _test_id("ses_"),
        "writer_id": _test_id("wri_"),
        "view": "compact",
        "limit": "10",
        "at_frontier": None,
        "cursor": None,
    }
    status = models.StatusRequestModel.model_validate(status_wire)
    assert models.public_model_to_wire(status) == status_wire


def test_public_model_to_wire_is_the_validated_boundary() -> None:
    models = _models_module()
    request = models.StartRequestModel.model_validate(_start_request_wire())
    result = models.StartResultModel.model_validate(_start_result_wire())

    first = models.public_model_to_wire(request)
    second = models.public_model_to_wire(request)
    assert first == second == _start_request_wire()
    assert first is not second
    first["mode"] = "attach"
    assert models.public_model_to_wire(request)["mode"] == "create"

    result_wire = models.public_model_to_wire(result)
    assert result_wire == _start_result_wire()
    assert "root" not in result_wire

    with pytest.raises(TypeError, match="^public_model_wrong_type$"):
        models.public_model_to_wire(models.ActorAssertionModel.model_validate(_actor_wire()))

    class DerivedStartRequest(models.StartRequestModel):
        pass

    derived = DerivedStartRequest.model_validate(_start_request_wire())
    with pytest.raises(TypeError, match="^public_model_wrong_type$"):
        models.public_model_to_wire(derived)


def test_recursive_optional_cleanup_resolves_serialization_aliases() -> None:
    models = _models_module()

    class _AliasedLeaf(BaseModel):
        optional_non_null_fields: ClassVar[frozenset[str]] = frozenset({"omitted"})
        omitted: str | None = None

    class _AliasedParent(BaseModel):
        event_schema: _AliasedLeaf = Field(alias="schema")

    child = _AliasedLeaf.model_construct(omitted=None)
    parent = _AliasedParent.model_construct(event_schema=child)
    raw = parent.model_dump(mode="json", by_alias=True, exclude_unset=True, exclude_none=False)
    assert raw == {"schema": {"omitted": None}}

    strip = cast(
        Callable[[BaseModel, Mapping[str, JsonValue]], dict[str, JsonValue]],
        getattr(models, "_strip_optional_non_null_fields"),
    )
    assert strip(parent, cast(Mapping[str, JsonValue], raw)) == {"schema": {}}


def test_all_result_roots_serialize_success_and_shared_failure_without_wrapper() -> None:
    models = _models_module()
    success_cases: tuple[tuple[str, Callable[[], dict[str, JsonValue]]], ...] = (
        ("StartResultModel", _start_result_wire),
        ("PublishWorkResultModel", _publish_result_wire),
        ("CheckResultModel", _check_result_wire),
        ("RespondResultModel", _respond_result_wire),
        ("StatusResultModel", _status_result_wire),
        ("ReceiptResultModel", _receipt_result_wire),
    )
    for model_name, wire_factory in success_cases:
        wire = wire_factory()
        parsed = getattr(models, model_name).model_validate(wire)
        dumped = models.public_model_to_wire(parsed)
        assert dumped == wire
        assert "root" not in dumped

    failure_wire = _failure_result_wire()
    for model_name in _ROOT_RESULT_MODEL_NAMES:
        parsed = getattr(models, model_name).model_validate(failure_wire)
        dumped = models.public_model_to_wire(parsed)
        assert dumped == failure_wire
        assert "root" not in dumped


def test_closure_readiness_never_reports_unknown_state_as_a_clean_record() -> None:
    """Missing compact data must read as unknown, never as zero open obligations.

    Compact omits its singleton when the task title is unreadable. Filling that with zeros would
    manufacture "nothing is open" out of absent data — exactly the kind of unearned claim the
    coverage rules forbid.
    """

    models = _models_module()
    model = models.StatusClosureReadinessModel

    unknown = model.model_validate(
        with_checklist(
            {
                "declared_obligation_count": None,
                "no_obligations_reason": None,
                "open_obligation_count": None,
                "unanswered_finding_count": None,
                "receipt_blocking_finding_count": None,
                "blocking_conditions": ["readiness_unknown"],
            }
        )
    )
    assert unknown.open_obligation_count is None
    assert unknown.blocking_conditions == ("readiness_unknown",)

    findings = model.model_validate(
        with_checklist(
            {
                "declared_obligation_count": "1",
                "no_obligations_reason": None,
                "open_obligation_count": "0",
                "unanswered_finding_count": "2",
                "receipt_blocking_finding_count": "1",
                "blocking_conditions": [
                    "findings_unanswered",
                    "receipt_findings_unresolved",
                ],
            }
        )
    )
    assert findings.unanswered_finding_count == "2"
    assert findings.receipt_blocking_finding_count == "1"

    for missing in ("findings_unanswered", "receipt_findings_unresolved"):
        with pytest.raises(ValidationError):
            model.model_validate(
                with_checklist(
                    {
                        **findings.model_dump(mode="json"),
                        "blocking_conditions": [
                            item for item in findings.blocking_conditions if item != missing
                        ],
                    }
                )
            )

    # Absent counts must declare themselves unknown...
    with pytest.raises(ValidationError):
        model.model_validate(
            with_checklist(
                {
                    "declared_obligation_count": None,
                    "no_obligations_reason": None,
                    "open_obligation_count": None,
                    "unanswered_finding_count": None,
                    "receipt_blocking_finding_count": None,
                    "blocking_conditions": [],
                }
            )
        )
    # ...known counts must not claim to be unknown...
    with pytest.raises(ValidationError):
        model.model_validate(
            with_checklist(
                {
                    "declared_obligation_count": "0",
                    "no_obligations_reason": None,
                    "open_obligation_count": "0",
                    "unanswered_finding_count": "0",
                    "receipt_blocking_finding_count": "0",
                    "blocking_conditions": ["readiness_unknown"],
                }
            )
        )
    # ...unknown is never partial...
    with pytest.raises(ValidationError):
        model.model_validate(
            with_checklist(
                {
                    "declared_obligation_count": "2",
                    "no_obligations_reason": None,
                    "open_obligation_count": "2",
                    "unanswered_finding_count": None,
                    "receipt_blocking_finding_count": "0",
                    "blocking_conditions": ["readiness_unknown"],
                }
            )
        )
    # ...and it is never mixed with conditions derived from data that could not be read.
    with pytest.raises(ValidationError):
        model.model_validate(
            with_checklist(
                {
                    "declared_obligation_count": None,
                    "no_obligations_reason": None,
                    "open_obligation_count": None,
                    "unanswered_finding_count": None,
                    "receipt_blocking_finding_count": None,
                    "blocking_conditions": ["readiness_unknown", "no_plan_published"],
                }
            )
        )

    no_plan = model.model_validate(
        with_checklist(
            {
                "declared_obligation_count": "0",
                "no_obligations_reason": None,
                "open_obligation_count": "0",
                "unanswered_finding_count": "0",
                "receipt_blocking_finding_count": "0",
                "blocking_conditions": ["no_plan_published"],
            }
        )
    )
    assert no_plan.blocking_conditions == ("no_plan_published",)

    undeclared = model.model_validate(
        with_checklist(
            {
                "declared_obligation_count": "0",
                "no_obligations_reason": None,
                "open_obligation_count": "0",
                "unanswered_finding_count": "0",
                "receipt_blocking_finding_count": "0",
                "blocking_conditions": ["no_obligations_declared"],
            }
        )
    )
    assert undeclared.blocking_conditions == ("no_obligations_declared",)

    declared_none = model.model_validate(
        with_checklist(
            {
                "declared_obligation_count": "0",
                "no_obligations_reason": "single_atomic_change",
                "open_obligation_count": "0",
                "unanswered_finding_count": "0",
                "receipt_blocking_finding_count": "0",
                "blocking_conditions": [],
            }
        )
    )
    assert declared_none.no_obligations_reason == "single_atomic_change"

    with pytest.raises(ValidationError):
        model.model_validate(
            with_checklist(
                {
                    "declared_obligation_count": "0",
                    "no_obligations_reason": None,
                    "open_obligation_count": "0",
                    "unanswered_finding_count": "0",
                    "receipt_blocking_finding_count": "0",
                    "blocking_conditions": [],
                }
            )
        )


def test_start_compact_ties_an_unknown_receipt_count_to_its_declared_gap() -> None:
    """The null receipt-blocking count exists only for a legacy replay, and only when the replay
    also declares the gap. Neither half is allowed to appear without the other."""

    models = _models_module()
    model = models.StartCompactViewModel
    base = cast(dict[str, JsonValue], _start_result_wire()["compact"])

    known = model.model_validate(base)
    assert known.receipt_blocking_finding_count == "0"
    assert known.gaps == ()

    legacy = model.model_validate(
        {
            **base,
            "receipt_blocking_finding_count": None,
            "gaps": ["legacy_receipt_blocking_count_unknown"],
        }
    )
    assert legacy.receipt_blocking_finding_count is None

    with pytest.raises(ValidationError):
        model.model_validate({**base, "receipt_blocking_finding_count": None})
    with pytest.raises(ValidationError):
        model.model_validate({**base, "gaps": ["legacy_receipt_blocking_count_unknown"]})


def test_compact_scope_counts_preserve_known_no_plan_and_unknown_plan() -> None:
    models = _models_module()
    model = models.StatusCompactItemModel
    base: dict[str, JsonValue] = {
        "task_id": _test_id("tsk_"),
        "session_id": _test_id("ses_"),
        "task_title": "Scope model",
        "current_plan_event_id": None,
        "declared_obligation_count": "0",
        "no_obligations_reason": None,
        "open_obligation_count": "0",
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "0",
        "open_obligations": [],
        "unanswered_findings": [],
        "freshness": "current",
        "coverage": _coverage_wire(),
        "gaps": [],
    }

    no_plan = model.model_validate(base)
    assert no_plan.current_plan_event_id is None
    assert no_plan.declared_obligation_count == "0"

    unknown = model.model_validate(
        {
            **base,
            "current_plan_event_id": _test_id("evt_"),
            "declared_obligation_count": None,
            "open_obligation_count": None,
        }
    )
    assert unknown.declared_obligation_count is None
    assert unknown.open_obligation_count is None

    for invalid in (
        {**base, "declared_obligation_count": None},
        {**base, "no_obligations_reason": "single_atomic_change"},
        {
            **base,
            "current_plan_event_id": _test_id("evt_"),
            "declared_obligation_count": "1",
            "no_obligations_reason": "single_atomic_change",
        },
    ):
        with pytest.raises(ValidationError):
            model.model_validate(invalid)


def test_unknown_fields_and_result_discriminator_are_strict() -> None:
    models = _models_module()
    with pytest.raises(ValidationError):
        models.StartRequestModel.model_validate({**_start_request_wire(), "extra": True})
    with pytest.raises(ValidationError):
        models.ActorAssertionModel.model_validate({**_actor_wire(), "extra": True})
    for invalid_ok in (0, 1, "true", "false"):
        with pytest.raises(ValidationError):
            models.StartResultModel.model_validate({**_start_result_wire(), "ok": invalid_ok})


def test_operation_cross_field_matrix() -> None:
    models = _models_module()
    missing_attachment = _start_request_wire()
    missing_attachment["mode"] = "attach"
    with pytest.raises(ValidationError):
        models.StartRequestModel.model_validate(missing_attachment)
    attached = {**missing_attachment, "session_id": _test_id("ses_")}
    models.StartRequestModel.model_validate(attached)
    partial_attachment = {**_start_request_wire(), "external_ref": "external"}
    with pytest.raises(ValidationError):
        models.StartRequestModel.model_validate(partial_attachment)

    models.CheckResultModel.model_validate(_check_result_wire())

    invalid_pair = _check_result_wire()
    invalid_pair["semantic_reason"] = "semantic_completed"
    with pytest.raises(ValidationError):
        models.CheckResultModel.model_validate(invalid_pair)

    predispatch_provenance = _check_result_wire()
    predispatch_provenance["semantic_provenance"] = {}
    with pytest.raises(ValidationError):
        models.CheckResultModel.model_validate(predispatch_provenance)

    versions_status = _status_result_wire()
    page = cast(dict[str, JsonValue], versions_status["page"])
    page["items"] = [
        {
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "0.1.0",
            "object_format": "yoetz-object/1",
            "storage_schema": "1",
            "python_version": "3.14.0",
            "apsw_version": "9.9.9.9",
            "sqlite_version": "9.9.9",
            "sqlite_source_id": "sqlite-source-id",
            "policy_packs": [],
            "provider_profiles": [],
        }
    ]
    models.StatusResultModel.model_validate(versions_status)
    versions_status["view"] = "assignment"
    with pytest.raises(ValidationError):
        models.StatusResultModel.model_validate(versions_status)

    models.StatusResultModel.model_validate(_candidate_status_result_wire())
    models.StatusResultModel.model_validate(_candidate_status_result_wire(omitted=True))
    wrong_candidate_omission = _candidate_status_result_wire(omitted=True)
    candidate_page = cast(dict[str, JsonValue], wrong_candidate_omission["page"])
    candidate_items = cast(list[JsonValue], candidate_page["items"])
    candidate_item = cast(dict[str, JsonValue], candidate_items[0])
    candidate_summary = cast(dict[str, JsonValue], candidate_item["summary"])
    candidate_summary["category"] = "task_description"
    with pytest.raises(ValidationError):
        models.StatusResultModel.model_validate(wrong_candidate_omission)

    disputed_status = _status_result_wire()
    disputed_status["view"] = "findings"
    disputed_item: dict[str, JsonValue] = {
        "finding_id": _test_id("fnd_"),
        "kind": "action_without_result",
        "origin": "deterministic",
        "priority": 1,
        "summary": "A disputed finding.",
        "detail": "The finding provenance is disputed.",
        "subject_refs": [_test_id("act_")],
        "policy_id": "work-integrity",
        "policy_version": "0.1.0",
        "subject_frontier": {"sequence": "0", "head_digest": "genesis"},
        "coverage": _coverage_wire(),
        "provenance": None,
        "disposition": "provenance_disputed",
        "resolved": False,
        "response_event_id": _test_id("evt_"),
        "reason": "The finding was attributed to the wrong writer.",
        "waiver_scope": None,
        "waiver_expiry": None,
    }
    disputed_status["page"] = {"items": [disputed_item], "next_cursor": None}
    models.StatusResultModel.model_validate(disputed_status)
    validate_schema_instance("status-result", "1.4.0", disputed_status)
    for field, invalid_value in (
        ("reason", None),
        ("resolved", True),
        ("waiver_scope", "finding_only"),
        ("waiver_expiry", "2026-08-17T12:34:56.789Z"),
    ):
        invalid_status = cast(
            dict[str, JsonValue], strict_json_parse(canonical_encode(disputed_status))
        )
        invalid_page = cast(dict[str, JsonValue], invalid_status["page"])
        invalid_items = cast(list[JsonValue], invalid_page["items"])
        invalid_item = cast(dict[str, JsonValue], invalid_items[0])
        invalid_item[field] = invalid_value
        with pytest.raises(ProtocolValueError):
            validate_schema_instance("status-result", "1.4.0", invalid_status)
        with pytest.raises(ValidationError):
            models.StatusResultModel.model_validate(invalid_status)

    models.RespondResultModel.model_validate(_respond_result_wire())
    disputed = _respond_result_wire()
    disputed_response = cast(dict[str, JsonValue], disputed["response"])
    disputed_response["disposition"] = "provenance_disputed"
    models.RespondResultModel.model_validate(disputed)
    del disputed_response["reason"]
    with pytest.raises(ValidationError):
        models.RespondResultModel.model_validate(disputed)
    disputed_waiver = _respond_result_wire()
    disputed_waiver_response = cast(dict[str, JsonValue], disputed_waiver["response"])
    disputed_waiver_response["disposition"] = "provenance_disputed"
    disputed_waiver_response["waiver_scope"] = "finding_only"
    with pytest.raises(ValidationError):
        models.RespondResultModel.model_validate(disputed_waiver)
    waived = _respond_result_wire()
    waived_response = cast(dict[str, JsonValue], waived["response"])
    waived_response["disposition"] = "waived"
    waived_response["waiver_scope"] = "finding_only"
    models.RespondResultModel.model_validate(waived)
    invalid_acknowledgement = _respond_result_wire()
    acknowledged_response = cast(dict[str, JsonValue], invalid_acknowledgement["response"])
    acknowledged_response["disposition"] = "acknowledged"
    acknowledged_response["waiver_scope"] = "finding_only"
    with pytest.raises(ValidationError):
        models.RespondResultModel.model_validate(invalid_acknowledgement)

    models.ReceiptResultModel.model_validate(_receipt_result_wire())
    markdown_receipt = _receipt_result_wire()
    markdown_receipt["format"] = "markdown"
    markdown_receipt["document"] = None
    markdown_receipt["human_text"] = "A local-only receipt rendering."
    models.ReceiptResultModel.model_validate(markdown_receipt)
    markdown_receipt["human_text"] = None
    with pytest.raises(ValidationError):
        models.ReceiptResultModel.model_validate(markdown_receipt)

    invalid_timestamp = _publish_result_wire()
    accepted_events = cast(list[JsonValue], invalid_timestamp["accepted_events"])
    accepted_event = cast(dict[str, JsonValue], accepted_events[0])
    accepted_event["accepted_at"] = "2026-02-30T12:34:56.789Z"
    with pytest.raises(ValidationError):
        models.PublishWorkResultModel.model_validate(invalid_timestamp)


def test_receipt_version_slice_is_exact_and_canonical() -> None:
    models = _models_module()
    models.ReceiptResultModel.model_validate(_receipt_result_wire())

    missing_digest = _receipt_result_wire()
    missing_versions = cast(dict[str, JsonValue], missing_digest["versions"])
    del missing_versions["resource_manifest_digest"]
    with pytest.raises(ValidationError):
        models.ReceiptResultModel.model_validate(missing_digest)

    old_shape = _receipt_result_wire()
    old_shape["versions"] = {
        "protocol_version": "0.1",
        "engine_version": "0.1.0",
        "projection_version": "yoetz/0.1.0",
        "object_format": "yoetz-object/1",
        "storage_schema": "1",
        "policy_packs": ["research-evidence/0.1.0", "work-integrity/0.1.0"],
    }
    with pytest.raises(ValidationError):
        models.ReceiptResultModel.model_validate(old_shape)

    unsorted_policies = _receipt_result_wire()
    policy_versions = cast(
        list[JsonValue],
        cast(dict[str, JsonValue], unsorted_policies["versions"])["policy_versions"],
    )
    policy_versions.reverse()
    with pytest.raises(ValidationError):
        models.ReceiptResultModel.model_validate(unsorted_policies)

    duplicate_schemas = _receipt_result_wire()
    schema_versions = cast(
        list[JsonValue],
        cast(dict[str, JsonValue], duplicate_schemas["versions"])["schema_versions"],
    )
    schema_versions[1] = dict(cast(dict[str, JsonValue], schema_versions[0]))
    with pytest.raises(ValidationError):
        models.ReceiptResultModel.model_validate(duplicate_schemas)


def test_check_semantic_status_reason_and_provenance_matrix() -> None:
    models = _models_module()
    for status, reasons in _EXPECTED_SEMANTIC_STATUS_REASONS.items():
        for reason in reasons:
            wire = _check_result_wire()
            wire["semantic_status"] = status
            wire["semantic_reason"] = reason
            pair = (status, reason)
            if pair in _REQUIRED_SEMANTIC_PROVENANCE_PAIRS:
                wire["semantic_provenance"] = _semantic_provenance_for(status, reason)
            else:
                wire.pop("semantic_provenance", None)
            parsed = models.CheckResultModel.model_validate(wire)
            assert models.public_model_to_wire(parsed) == wire

            if pair in _REQUIRED_SEMANTIC_PROVENANCE_PAIRS:
                missing = dict(wire)
                missing.pop("semantic_provenance", None)
                with pytest.raises(ValidationError):
                    models.CheckResultModel.model_validate(missing)
            elif pair not in _OPTIONAL_SEMANTIC_PROVENANCE_PAIRS:
                forbidden = dict(wire)
                forbidden["semantic_provenance"] = _semantic_provenance_for(status, reason)
                with pytest.raises(ValidationError):
                    models.CheckResultModel.model_validate(forbidden)

    succeeded_without_provenance = _check_result_wire()
    succeeded_without_provenance["semantic_status"] = "succeeded"
    succeeded_without_provenance["semantic_reason"] = "semantic_completed"
    with pytest.raises(ValidationError):
        models.CheckResultModel.model_validate(succeeded_without_provenance)

    failed_with_provenance = _check_result_wire()
    failed_with_provenance["semantic_status"] = "failed"
    failed_with_provenance["semantic_reason"] = "coordinator_failure"
    failed_with_provenance["semantic_provenance"] = _semantic_provenance_for(
        "failed", "coordinator_failure"
    )
    parsed_failure = models.CheckResultModel.model_validate(failed_with_provenance)
    assert models.public_model_to_wire(parsed_failure) == failed_with_provenance

    mismatched = _check_result_wire()
    mismatched["semantic_status"] = "succeeded"
    mismatched["semantic_reason"] = "semantic_completed"
    mismatched["semantic_provenance"] = _semantic_provenance_for("refused", "provider_refused")
    with pytest.raises(ValidationError):
        models.CheckResultModel.model_validate(mismatched)

    malformed_values: tuple[JsonValue, ...] = (
        cast(JsonValue, []),
        cast(JsonValue, {"status": "succeeded"}),
        cast(JsonValue, {"reason": "semantic_completed"}),
    )
    for malformed in malformed_values:
        malformed_wire = _check_result_wire()
        malformed_wire["semantic_status"] = "succeeded"
        malformed_wire["semantic_reason"] = "semantic_completed"
        malformed_wire["semantic_provenance"] = malformed
        with pytest.raises(ValidationError):
            models.CheckResultModel.model_validate(malformed_wire)

    status_enum = models.SemanticStatus
    reason_enum = models.SemanticReason
    with pytest.raises(ProtocolValueError) as exc_info:
        models.validate_semantic_provenance_binding(
            status_enum.SUCCEEDED,
            reason_enum.SEMANTIC_COMPLETED,
            None,
            None,
        )
    _assert_reason(exc_info, "invalid_semantic_provenance")


def _binding_accepts(models: Any, status: Any, reason: Any, *, provenance: bool) -> bool:
    try:
        models.validate_semantic_provenance_binding(
            status,
            reason,
            status if provenance else None,
            reason if provenance else None,
        )
    except ProtocolValueError:
        return False
    return True


def test_semantic_provenance_partition_is_total_over_every_status_and_reason() -> None:
    """Every status/reason pair must land in exactly one provenance branch.

    Reading ``semantic_provenance == null`` as "no provider attempt was made" is only sound
    while the partition is total. A status added later that fell through every branch would
    make null ambiguous and silently break that inference — which is the one fact the AI-powered review
    dogfood gate is built on (``docs/runbooks/semantic-dogfood.md``, issue #132).
    """

    models = _models_module()
    classification: dict[tuple[Any, Any], str] = {}
    for status in models.SemanticStatus:
        reasons = models.VALID_SEMANTIC_REASONS[status]
        assert reasons, f"{status.value} has no valid reason"
        for reason in reasons:
            absent_ok = _binding_accepts(models, status, reason, provenance=False)
            present_ok = _binding_accepts(models, status, reason, provenance=True)
            # Rejecting both forms means the pair fell out of the partition entirely.
            assert absent_ok or present_ok, (status.value, reason.value)
            classification[(status, reason)] = (
                "unconstrained"
                if absent_ok and present_ok
                else ("forbidden" if absent_ok else "required")
            )

    unconstrained = {
        status.value for (status, _), kind in classification.items() if kind == "unconstrained"
    }
    # `failed` is the one status where provenance presence proves nothing either way, so a
    # dogfood run must record it as "attempt indeterminate", never as "not attempted".
    assert unconstrained == {"failed"}

    # A pre-dispatch block returns before any provider capability check, so provenance is
    # forbidden — this is exactly the receipt the strict-route dogfood session produced.
    assert (
        classification[
            (
                models.SemanticStatus.BLOCKED_BY_POLICY,
                models.SemanticReason.ROUTE_SEMANTIC_CEILING,
            )
        ]
        == "forbidden"
    )

    unavailable = {
        reason.value: kind
        for (status, reason), kind in classification.items()
        if status is models.SemanticStatus.UNAVAILABLE
    }
    # `unavailable` is the one status that splits on its reason, so each reason has to be
    # classified individually and none may be left unconstrained.
    assert set(unavailable.values()) <= {"required", "forbidden"}
    assert {reason for reason, kind in unavailable.items() if kind == "required"} == {
        "transport_unavailable",
        "provider_rate_limited",
        "provider_quota_exhausted",
        "outcome_unknown",
    }
    assert set(unavailable) == {
        reason.value for reason in models.VALID_SEMANTIC_REASONS[models.SemanticStatus.UNAVAILABLE]
    }


def test_frontier_model_enforces_genesis_cross_field_identity() -> None:
    models = _models_module()
    genesis = models.FrontierModel.model_validate({"sequence": "0", "head_digest": "genesis"})
    assert genesis.sequence == "0"
    positive = models.FrontierModel.model_validate(
        {"sequence": "1", "head_digest": f"sha256:{'1' * 64}"}
    )
    assert positive.sequence == "1"

    with pytest.raises(ValidationError):
        models.FrontierModel.model_validate({"sequence": "0", "head_digest": f"sha256:{'1' * 64}"})
    with pytest.raises(ValidationError):
        models.FrontierModel.model_validate({"sequence": "1", "head_digest": "genesis"})


def test_b1_prerequisite_event_and_receipt_schema_seams_are_exact() -> None:
    session_payload: dict[str, JsonValue] = {
        "task_title": "x" * 8_192,
        "external_ref": "external-only",
        "client_kind": "test_client",
        "client_version": "0.1.0",
        "integration": "local_cli",
        "profile": "test-fake",
    }
    validate_schema_instance("session-opened", "1.0.0", session_payload)
    for invalid_title in ("", "x" * 8_193):
        invalid_session = dict(session_payload)
        invalid_session["task_title"] = invalid_title
        with pytest.raises(ProtocolValueError) as exc_info:
            validate_schema_instance("session-opened", "1.0.0", invalid_session)
        _assert_reason(exc_info, "schema_instance_invalid")

    result_id = _test_id("res_")
    draft: dict[str, JsonValue] = {
        "event_id": _test_id("evt_"),
        "schema": {"name": "session_opened", "version": "1.0.0"},
        "occurred_at": "2026-07-18T12:34:56.789Z",
        "causal_parents": [],
        "payload": session_payload,
        "artifact_refs": [],
        "evidence_refs": [result_id],
    }
    validate_schema_instance("event-draft", "1.0.0", draft)

    subscription_payload = dict(session_payload)
    subscription_payload["profile"] = "codex-subscription"
    validate_schema_instance("session-opened", "1.1.0", subscription_payload)
    with pytest.raises(ProtocolValueError) as exc_info:
        validate_schema_instance("session-opened", "1.0.0", subscription_payload)
    _assert_reason(exc_info, "schema_instance_invalid")
    subscription_draft = dict(draft)
    subscription_draft["schema"] = {"name": "session_opened", "version": "1.1.0"}
    subscription_draft["payload"] = subscription_payload
    validate_schema_instance("event-draft", "1.1.0", subscription_draft)
    with pytest.raises(ProtocolValueError) as exc_info:
        validate_schema_instance("opaque-unknown-event-draft", "1.1.0", subscription_draft)
    _assert_reason(exc_info, "schema_instance_invalid")

    accepted = _accepted_event_wire()
    accepted["evidence_refs"] = [result_id]
    validate_schema_instance("accepted-event", "1.0.0", accepted)
    for name, value in (("event-draft", draft), ("accepted-event", accepted)):
        invalid_refs = dict(value)
        invalid_refs["evidence_refs"] = [_test_id("act_")]
        with pytest.raises(ProtocolValueError) as exc_info:
            validate_schema_instance(name, "1.0.0", invalid_refs)
        _assert_reason(exc_info, "schema_instance_invalid")

    document = cast(dict[str, JsonValue], _receipt_fixture_expected()["receipt_document"])
    document["responses"] = [
        {
            "finding_id": _test_id("fnd_"),
            "finding_frontier": {"sequence": "0", "head_digest": "genesis"},
            "disposition": "acknowledged",
            "evidence_refs": [result_id],
        }
    ]
    validate_schema_instance("receipt-document", "1.0.0", document)

    missing_items_document = cast(
        dict[str, JsonValue], _receipt_fixture_expected()["receipt_document"]
    )
    sections = cast(list[JsonValue], missing_items_document["sections"])
    first_section = cast(dict[str, JsonValue], sections[0])
    del first_section["items"]
    with pytest.raises(ProtocolValueError) as exc_info:
        validate_schema_instance("receipt-document", "1.0.0", missing_items_document)
    _assert_reason(exc_info, "schema_instance_invalid")


def test_current_receipt_document_accepts_coordination_overlap_finding() -> None:
    """The additive receipt artifact resolves current findings, including coordination overlap."""

    expected = _receipt_fixture_expected()
    document = cast(dict[str, JsonValue], expected["receipt_document"])
    document["children"] = {"children": []}
    versions = cast(dict[str, JsonValue], document["versions"])
    schema_versions = cast(list[JsonValue], versions["schema_versions"])
    for raw_entry in schema_versions:
        entry = cast(dict[str, JsonValue], raw_entry)
        if entry["schema_id"] == "findings/finding":
            entry["schema_version"] = "1.2.0"
        elif entry["schema_id"] == "receipts/receipt-document":
            entry["schema_version"] = "1.2.0"
    document["findings"] = [
        {
            "coverage": dict(_VALID_COVERAGE),
            "detail": "Two admitted tasks overlap on a shared resource.",
            "finding_id": _test_id("fnd_"),
            "kind": "coordination_overlap",
            "origin": "deterministic",
            "policy_id": "coordination",
            "policy_version": "0.1.0",
            "priority": 2,
            "subject_frontier": document["subject_frontier"],
            "subject_refs": [_test_id("evt_"), _test_id("obl_")],
            "summary": "Two admitted tasks overlap on a shared resource.",
        }
    ]
    validate_schema_instance("receipt-document", "1.3.0", document)


def test_public_status_finding_models_accept_coordination_overlap() -> None:
    """Public status projections retain the local coordination finding kind.

    The provider judgment wire intentionally has a narrower frozen allowlist, but public status
    and candidate-finding projections must carry every current ``FindingKind`` value.
    """

    models = _models_module()
    candidate_result = _candidate_status_result_wire()
    candidate_page = cast(dict[str, JsonValue], candidate_result["page"])
    candidate = cast(list[JsonValue], candidate_page["items"])[0]
    candidate_item = cast(dict[str, JsonValue], candidate)
    candidate_item["kind"] = "coordination_overlap"
    candidate_item["priority"] = 2
    candidate_item["subject_refs"] = [_test_id("evt_"), _test_id("obl_")]
    candidate_item["policy_id"] = "coordination"
    candidate_basis = cast(dict[str, JsonValue], candidate_item["basis"])
    candidate_basis["rule_id"] = "coordination_overlap"
    candidate_basis["observed_refs"] = [_test_id("evt_"), _test_id("obl_")]
    parsed_candidates = models.StatusResultModel.model_validate(candidate_result)
    candidate_row = parsed_candidates.root.page.items[0]
    assert candidate_row.kind == "coordination_overlap"
    assert candidate_row.policy_id == "coordination"

    finding_result = _status_result_wire()
    finding_result["view"] = "findings"
    finding_item = dict(candidate_item)
    finding_item.pop("basis")
    finding_result["page"] = {
        "items": [
            {
                **finding_item,
                "finding_id": _test_id("fnd_"),
                "origin": "deterministic",
                "provenance": None,
                "disposition": "none",
                "resolved": False,
                "response_event_id": None,
                "reason": None,
                "waiver_scope": None,
                "waiver_expiry": None,
            }
        ],
        "next_cursor": None,
    }
    parsed_findings = models.StatusResultModel.model_validate(finding_result)
    finding_row = parsed_findings.root.page.items[0]
    assert finding_row.kind == "coordination_overlap"
    assert finding_row.policy_id == "coordination"


def test_check_recorded_schema_matches_final_semantic_provenance_identity() -> None:
    for status, reasons in _EXPECTED_SEMANTIC_STATUS_REASONS.items():
        for reason in reasons:
            pair = (status, reason)
            payload = _check_recorded_payload_wire()
            payload["semantic_status"] = status
            payload["semantic_reason"] = reason
            if pair in _REQUIRED_SEMANTIC_PROVENANCE_PAIRS:
                payload["semantic_provenance"] = _semantic_provenance_for(status, reason)
            else:
                payload.pop("semantic_provenance", None)
            try:
                validate_schema_instance("check-recorded", "1.1.0", payload)
            except ProtocolValueError as exc:
                raise AssertionError(f"check-recorded 1.1 rejected {pair!r}") from exc

            if pair in _REQUIRED_SEMANTIC_PROVENANCE_PAIRS:
                payload.pop("semantic_provenance")
                with pytest.raises(ProtocolValueError) as exc_info:
                    validate_schema_instance("check-recorded", "1.0.0", payload)
                _assert_reason(exc_info, "schema_instance_invalid")
            elif pair not in _OPTIONAL_SEMANTIC_PROVENANCE_PAIRS:
                payload["semantic_provenance"] = _semantic_provenance_for(status, reason)
                with pytest.raises(ProtocolValueError) as exc_info:
                    validate_schema_instance("check-recorded", "1.0.0", payload)
                _assert_reason(exc_info, "schema_instance_invalid")

    failed = _check_recorded_payload_wire()
    failed["semantic_status"] = "failed"
    failed["semantic_reason"] = "coordinator_failure"
    failed["semantic_provenance"] = _semantic_provenance_for("failed", "coordinator_failure")
    validate_schema_instance("check-recorded", "1.0.0", failed)

    mismatched = _check_recorded_payload_wire()
    mismatched["semantic_status"] = "succeeded"
    mismatched["semantic_reason"] = "semantic_completed"
    mismatched["semantic_provenance"] = _semantic_provenance_for("refused", "provider_refused")
    with pytest.raises(ProtocolValueError) as exc_info:
        validate_schema_instance("check-recorded", "1.0.0", mismatched)
    _assert_reason(exc_info, "schema_instance_invalid")


def test_actor_and_client_models_validate_shape_without_granting_assurance() -> None:
    models = _models_module()
    actor_wire: dict[str, JsonValue] = {
        "actor_id": "ci-bot.7",
        "actor_type": "model_backed_worker",
        "asserted_by": "local harness",
        "display_name": "CI review worker",
    }
    actor = models.ActorAssertionModel.model_validate(actor_wire)
    assert actor.model_dump(mode="json", exclude_unset=True) == actor_wire
    assert actor.actor_id == "ci-bot.7"
    actor_fields = cast(Mapping[str, object], getattr(models.ActorAssertionModel, "model_fields"))
    assert set(actor_fields) == {
        "actor_id",
        "actor_type",
        "asserted_by",
        "display_name",
    }
    assert "authorship_assurance" not in actor_fields

    convention_actor = models.ActorAssertionModel.model_validate(
        {"actor_id": "agt_api_mapper", "actor_type": "logical_agent"}
    )
    assert convention_actor.actor_id == "agt_api_mapper"

    client_wire = _client_wire()
    client = models.ClientInfoModel.model_validate(client_wire)
    assert client.model_dump(mode="json") == client_wire
    client_fields = cast(Mapping[str, object], getattr(models.ClientInfoModel, "model_fields"))
    assert set(client_fields) == {"kind", "version", "integration"}
    assert "authorship_assurance" not in client_fields

    invalid_actors: tuple[dict[str, JsonValue], ...] = (
        {"actor_id": "", "actor_type": "harness"},
        {"actor_id": "has a space", "actor_type": "harness"},
        {"actor_id": "x" * 129, "actor_type": "harness"},
        {"actor_id": "ci-bot.7", "actor_type": 1},
        {"actor_id": "ci-bot.7", "actor_type": "unknown"},
        {"actor_id": "ci-bot.7", "actor_type": "harness", "display_name": None},
    )
    for invalid_actor in invalid_actors:
        with pytest.raises(ValidationError):
            models.ActorAssertionModel.model_validate(invalid_actor)

    invalid_clients: tuple[dict[str, JsonValue], ...] = (
        {"kind": 1, "version": "0.1.0", "integration": "local_cli"},
        {"kind": "unknown", "version": "0.1.0", "integration": "local_cli"},
        {"kind": "test_client", "version": "", "integration": "local_cli"},
        {"kind": "test_client", "version": "0.1.0", "integration": "unknown"},
        {**client_wire, "authorship_assurance": "verified"},
        {**client_wire, "id": "invented-client-id"},
    )
    for invalid_client in invalid_clients:
        with pytest.raises(ValidationError):
            models.ClientInfoModel.model_validate(invalid_client)


def test_public_error_safe_details_accept_wire_arrays_without_coercion() -> None:
    models = _models_module()
    base: dict[str, JsonValue] = {
        "code": "INVALID_REQUEST",
        "message": "The request is invalid.",
        "retryable": False,
        "correlation_id": _test_id("err_"),
    }
    cases: tuple[JsonValue, ...] = (
        {"items": ["value", 1, True], "empty": []},
        [["value", 1, True], "tail"],
    )
    for safe_details in cases:
        model = models.PublicErrorModel.model_validate({**base, "safe_details": safe_details})
        assert model.model_dump(mode="json", exclude_unset=True)["safe_details"] == safe_details

    for safe_details in ({"items": [1.5]}, [None], None):
        with pytest.raises(ValidationError):
            models.PublicErrorModel.model_validate(
                {**base, "safe_details": cast(JsonValue, safe_details)}
            )


def test_result_field_classification_is_closed() -> None:
    models = _models_module()
    assert models.MAX_PROJECTION_CONTENT_LEAVES == 512
    assert models.MAX_PROJECTION_POINTER_BYTES == 256
    assert models.MAX_INTERNAL_PROJECTABLE_RESULT_BYTES == 524_288
    assert models.MAX_PROJECTED_RESULT_BYTES == 1_048_576

    start = models.public_model_to_wire(
        models.StartResultModel.model_validate(_start_result_wire())
    )
    assert models.classify_result_leaf("start", start, "/outcome") == "public_structural"

    check = models.public_model_to_wire(
        models.CheckResultModel.model_validate(_check_result_wire())
    )
    assert (
        models.classify_result_leaf("check", check, "/findings/0/summary")
        is models.DataCategory.FINDING_SUMMARY
    )
    assert (
        models.classify_result_leaf("check", check, "/findings/0/priority") == "public_structural"
    )

    publish = models.public_model_to_wire(
        models.PublishWorkResultModel.model_validate(_publish_result_wire())
    )
    assert (
        models.classify_result_leaf("publish_work", publish, "/accepted_events/0/summary")
        is models.DataCategory.TASK_DESCRIPTION
    )

    opaque = _publish_result_wire()
    opaque_events = cast(list[JsonValue], opaque["accepted_events"])
    opaque_event = cast(dict[str, JsonValue], opaque_events[0])
    opaque_event["schema_version"] = "1.0.1"
    opaque_event["summary"] = "opaque_unknown"
    opaque_wire = models.public_model_to_wire(models.PublishWorkResultModel.model_validate(opaque))
    assert (
        models.classify_result_leaf("publish_work", opaque_wire, "/accepted_events/0/summary")
        == "public_structural"
    )

    respond = models.public_model_to_wire(
        models.RespondResultModel.model_validate(_respond_result_wire())
    )
    assert (
        models.classify_result_leaf("respond", respond, "/response/reason")
        is models.DataCategory.FINDING_SUMMARY
    )
    assert (
        models.classify_result_leaf("respond", respond, "/response/evidence/0/description")
        is models.DataCategory.EVIDENCE_EXCERPT
    )

    status = models.public_model_to_wire(
        models.StatusResultModel.model_validate(_candidate_status_result_wire())
    )
    assert (
        models.classify_result_leaf("status", status, "/page/items/0/summary")
        is models.DataCategory.FINDING_SUMMARY
    )
    omitted_status = models.public_model_to_wire(
        models.StatusResultModel.model_validate(_candidate_status_result_wire(omitted=True))
    )
    for suffix in ("category", "omitted", "reason"):
        assert (
            models.classify_result_leaf(
                "status",
                omitted_status,
                f"/page/items/0/summary/{suffix}",
            )
            == "public_structural"
        )

    receipt = models.public_model_to_wire(
        models.ReceiptResultModel.model_validate(_receipt_result_wire())
    )
    assert (
        models.classify_result_leaf("receipt", receipt, "/document/sections/0/body")
        is models.DataCategory.FINDING_SUMMARY
    )
    assert models.classify_result_leaf("receipt", receipt, "/human_text") == "public_structural"

    receipt_with_provenance = _receipt_result_wire()
    document = cast(dict[str, JsonValue], receipt_with_provenance["document"])
    provenance = _semantic_provenance_for("succeeded", "semantic_completed")
    provenance["token_usage"] = {
        "input_tokens": "103",
        "output_tokens": "19",
        "total_tokens": "122",
    }
    document["semantic_provenance"] = provenance
    receipt_with_provenance_wire = models.public_model_to_wire(
        models.ReceiptResultModel.model_validate(receipt_with_provenance)
    )
    assert (
        models.classify_result_leaf(
            "receipt",
            receipt_with_provenance_wire,
            "/document/semantic_provenance/token_usage/total_tokens",
        )
        == "public_structural"
    )

    markdown_receipt = _receipt_result_wire()
    markdown_receipt["format"] = "markdown"
    markdown_receipt["document"] = None
    markdown_receipt["human_text"] = "A local-only receipt rendering."
    markdown = models.public_model_to_wire(
        models.ReceiptResultModel.model_validate(markdown_receipt)
    )
    assert (
        models.classify_result_leaf("receipt", markdown, "/human_text")
        is models.DataCategory.FINDING_SUMMARY
    )

    omitted_text_receipt = _receipt_result_wire()
    omitted_text_receipt["format"] = "text"
    omitted_text_receipt["document"] = None
    omitted_text_receipt["human_text"] = {
        "omitted": True,
        "category": "finding_summary",
        "reason": "local_disclosure_not_authorized",
    }
    omitted_text = models.public_model_to_wire(
        models.ReceiptResultModel.model_validate(omitted_text_receipt)
    )
    for suffix in ("category", "omitted", "reason"):
        assert (
            models.classify_result_leaf("receipt", omitted_text, f"/human_text/{suffix}")
            == "public_structural"
        )

    invalid_unknown = _publish_result_wire()
    invalid_unknown_events = cast(list[JsonValue], invalid_unknown["accepted_events"])
    invalid_unknown_event = cast(dict[str, JsonValue], invalid_unknown_events[0])
    invalid_unknown_event["schema_version"] = "1.0.1"
    with pytest.raises(ProtocolValueError) as schema_exc_info:
        validate_schema_instance("publish-work-result", "1.0.0", invalid_unknown)
    _assert_reason(schema_exc_info, "schema_instance_invalid")
    with pytest.raises(ProtocolValueError) as exc_info:
        models.classify_result_leaf("publish_work", invalid_unknown, "/accepted_events/0/summary")
    _assert_reason(exc_info, "invalid_json_pointer")

    for pointer in (
        "/findings/00/summary",
        "/findings/1/summary",
        "/findings/0",
        "/findings/0/~2bad",
        "findings/0/summary",
    ):
        with pytest.raises(ProtocolValueError) as exc_info:
            models.classify_result_leaf("check", check, pointer)
        _assert_reason(exc_info, "invalid_json_pointer")

    with pytest.raises(ProtocolValueError) as exc_info:
        models.classify_result_leaf("unknown", check, "/findings/0/summary")
    _assert_reason(exc_info, "invalid_json_pointer")


def test_result_leaf_registry_has_exhaustive_schema_parity() -> None:
    models = _models_module()
    catalog = load_schema_catalog()
    rules = cast(tuple[Any, ...], getattr(models, "_RESULT_LEAF_RULES"))

    derived_patterns = _derived_result_success_patterns(catalog)
    assert len(derived_patterns) == 1394

    derived_counts = {
        context: sum(1 for method, view, _ in derived_patterns if (method, view) == context)
        for context in _EXPECTED_RESULT_PATTERN_COUNTS
    }
    assert derived_counts == _EXPECTED_RESULT_PATTERN_COUNTS

    assert type(rules) is tuple
    assert len(rules) == 1421
    assert rules == tuple(sorted(rules, key=_test_rule_sort_key))

    rule_keys = {
        (rule.method, rule.status_view, rule.event_selector, rule.segments) for rule in rules
    }
    assert len(rule_keys) == len(rules)

    registry_patterns = {(rule.method, rule.status_view, rule.segments) for rule in rules}
    assert len(registry_patterns) == 1394
    assert registry_patterns == derived_patterns

    content_rules = _expected_nonpublish_content_rules(models)
    assert set(content_rules) <= derived_patterns

    publish_summary_segments = ("accepted_events", "*", "summary")
    publish_summary_rules = tuple(
        rule
        for rule in rules
        if rule.method == "publish_work" and rule.segments == publish_summary_segments
    )
    assert len(publish_summary_rules) == 28
    assert all(rule.status_view is None for rule in publish_summary_rules)

    expected_publish = _expected_publish_summary_rules(models)
    actual_publish = {rule.event_selector: rule.classification for rule in publish_summary_rules}
    assert set(actual_publish) == set(expected_publish)
    for selector, expected_classification in expected_publish.items():
        actual_classification = actual_publish[selector]
        if expected_classification == "public_structural":
            assert actual_classification == "public_structural"
        else:
            assert actual_classification is expected_classification

    for rule in rules:
        pattern_key = (rule.method, rule.status_view, rule.segments)
        if rule.method == "publish_work" and rule.segments == publish_summary_segments:
            continue

        assert rule.event_selector is None
        expected_classification = content_rules.get(pattern_key, "public_structural")
        if expected_classification == "public_structural":
            assert rule.classification == "public_structural"
        else:
            assert rule.classification is expected_classification


def test_tuple_backed_canonical_values_validate_and_classify_offline() -> None:
    tuple_coverage = _coverage_wire()
    tuple_coverage["publication_channels"] = ("cooperative_mcp",)
    tuple_coverage["check_types"] = ("none",)
    tuple_coverage["known_gaps"] = ()
    validate_schema_instance("coverage", "1.0.0", tuple_coverage)

    models = _models_module()
    parsed = models.CheckResultModel.model_validate(_check_result_wire())
    python_wire = cast(Mapping[str, JsonValue], parsed.model_dump(mode="python"))
    assert type(python_wire["findings"]) is tuple
    assert (
        models.classify_result_leaf("check", python_wire, "/findings/0/summary")
        is models.DataCategory.FINDING_SUMMARY
    )


def test_json_pointer_lone_surrogates_fail_with_the_bounded_reason() -> None:
    models = _models_module()
    check = models.public_model_to_wire(
        models.CheckResultModel.model_validate(_check_result_wire())
    )
    with pytest.raises(ProtocolValueError) as exc_info:
        models.classify_result_leaf("check", check, "/\ud800")
    _assert_reason(exc_info, "invalid_json_pointer")

    projection = _privacy_projection_wire()
    projection["omitted_pointers"] = ["/\ud800"]
    with pytest.raises(ValidationError):
        models.PrivacyProjectionModel.model_validate(projection)


def test_privacy_projection_admits_only_the_two_ordinary_client_sinks() -> None:
    models = _models_module()
    for sink in ("agent_context", "local_human_view"):
        projection = _privacy_projection_wire()
        projection["sink"] = sink
        assert models.PrivacyProjectionModel.model_validate(projection).sink == sink
        check = _check_result_wire()
        check["privacy_projection"] = projection
        assert models.CheckResultModel.model_validate(check).root.privacy_projection.sink == sink
    for sink in ("local_model", "trusted_human_control"):
        projection = _privacy_projection_wire()
        projection["sink"] = sink
        with pytest.raises(ValidationError):
            models.PrivacyProjectionModel.model_validate(projection)


def _assert_reason(exc_info: pytest.ExceptionInfo[ProtocolValueError], reason: str) -> None:
    assert exc_info.value.reason_code == reason
    assert exc_info.value.args == (reason,)


def _walk_frozen(value: object) -> None:
    assert not isinstance(value, dict | list | set)
    if isinstance(value, Mapping):
        source = cast(Mapping[object, object], value)
        for key, item in source.items():
            assert type(key) is str
            _walk_frozen(item)
    elif isinstance(value, tuple):
        for item in cast(tuple[object, ...], value):
            _walk_frozen(item)


def _count_refs(value: object) -> int:
    count = 0
    if isinstance(value, Mapping):
        source = cast(Mapping[object, object], value)
        for key, item in source.items():
            if key == "$ref":
                assert type(item) is str
                count += 1
            count += _count_refs(item)
    elif isinstance(value, tuple):
        count += sum(_count_refs(item) for item in cast(tuple[object, ...], value))
    return count


def _schema_mapping(value: object) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise AssertionError("schema_node_not_object")
    return cast(Mapping[str, JsonValue], value)


def _schema_sequence(value: object) -> tuple[JsonValue, ...]:
    if type(value) is not tuple and type(value) is not list:
        raise AssertionError("schema_node_not_array")
    return tuple(cast(tuple[JsonValue, ...] | list[JsonValue], value))


def _resolve_test_schema_ref(
    catalog: SchemaCatalog,
    current_document: SchemaDocument,
    ref: str,
) -> tuple[SchemaDocument, Mapping[str, JsonValue], str]:
    base, fragment = urldefrag(ref)
    if base:
        target_document = catalog.by_id.get(base)
        if target_document is None:
            raise AssertionError("schema_ref_target_missing")
    else:
        target_document = current_document

    node: object = target_document.json_schema
    if fragment:
        if not fragment.startswith("/"):
            raise AssertionError("schema_ref_fragment_invalid")
        for raw_segment in fragment[1:].split("/"):
            segment = raw_segment.replace("~1", "/").replace("~0", "~")
            canonical = segment.replace("~", "~0").replace("/", "~1")
            if canonical != raw_segment:
                raise AssertionError("schema_ref_fragment_invalid")
            mapping = _schema_mapping(node)
            if segment not in mapping:
                raise AssertionError("schema_ref_fragment_missing")
            node = mapping[segment]

    return target_document, _schema_mapping(node), fragment


def _walk_schema_leaf_patterns(
    catalog: SchemaCatalog,
    document: SchemaDocument,
    node: Mapping[str, JsonValue],
    *,
    prefix: tuple[str, ...] = (),
    active_refs: frozenset[tuple[str, str]] = frozenset(),
) -> frozenset[tuple[str, ...]]:
    leaves: set[tuple[str, ...]] = set()

    raw_ref = node.get("$ref")
    if raw_ref is not None:
        if type(raw_ref) is not str:
            raise AssertionError("schema_ref_not_string")
        target_document, target_node, fragment = _resolve_test_schema_ref(
            catalog,
            document,
            raw_ref,
        )
        ref_key = (target_document.schema_id, fragment)
        if ref_key not in active_refs:
            leaves.update(
                _walk_schema_leaf_patterns(
                    catalog,
                    target_document,
                    target_node,
                    prefix=prefix,
                    active_refs=active_refs | {ref_key},
                )
            )

    for keyword in ("allOf", "anyOf", "oneOf"):
        raw_branches = node.get(keyword)
        if raw_branches is None:
            continue
        for branch in _schema_sequence(raw_branches):
            leaves.update(
                _walk_schema_leaf_patterns(
                    catalog,
                    document,
                    _schema_mapping(branch),
                    prefix=prefix,
                    active_refs=active_refs,
                )
            )

    raw_properties = node.get("properties")
    has_properties = isinstance(raw_properties, Mapping)
    if has_properties:
        properties = cast(Mapping[str, JsonValue], raw_properties)
        for property_name, child in properties.items():
            leaves.update(
                _walk_schema_leaf_patterns(
                    catalog,
                    document,
                    _schema_mapping(child),
                    prefix=(*prefix, property_name),
                    active_refs=active_refs,
                )
            )

    schema_type = node.get("type")
    is_array = schema_type == "array" or "items" in node or "prefixItems" in node
    if is_array:
        raw_items = node.get("items")
        if isinstance(raw_items, Mapping):
            leaves.update(
                _walk_schema_leaf_patterns(
                    catalog,
                    document,
                    cast(Mapping[str, JsonValue], raw_items),
                    prefix=(*prefix, "*"),
                    active_refs=active_refs,
                )
            )

        raw_prefix_items = node.get("prefixItems")
        if raw_prefix_items is not None:
            for child in _schema_sequence(raw_prefix_items):
                leaves.update(
                    _walk_schema_leaf_patterns(
                        catalog,
                        document,
                        _schema_mapping(child),
                        prefix=(*prefix, "*"),
                        active_refs=active_refs,
                    )
                )

    is_scalar_type = type(schema_type) is str and schema_type in {
        "boolean",
        "integer",
        "null",
        "number",
        "string",
    }
    is_untyped_scalar_token = (
        not is_array and not has_properties and ("const" in node or "enum" in node)
    )
    if is_scalar_type or is_untyped_scalar_token:
        leaves.add(prefix)

    return frozenset(leaves)


def _schema_success_definition(document: SchemaDocument) -> Mapping[str, JsonValue]:
    definitions = _schema_mapping(document.json_schema.get("$defs"))
    success = definitions.get("success")
    if success is None:
        raise AssertionError("schema_success_definition_missing")
    return _schema_mapping(success)


def _derived_result_success_patterns(
    catalog: SchemaCatalog,
) -> frozenset[tuple[str, str | None, tuple[str, ...]]]:
    derived: set[tuple[str, str | None, tuple[str, ...]]] = set()

    for method, schema_name in _RESULT_SCHEMA_BY_METHOD_FOR_TEST:
        document = catalog.by_name_version[
            (schema_name, catalog.request_result_versions[schema_name])
        ]
        patterns = _walk_schema_leaf_patterns(
            catalog,
            document,
            _schema_success_definition(document),
        )
        derived.update((method, None, pattern) for pattern in patterns)
        # publish_work also admits the reduced total-acceptance success branch; its leaves must
        # appear in the registry so post-commit classification never gaps after a durable append.
        definitions = _schema_mapping(document.json_schema.get("$defs"))
        reduced = definitions.get("accepted_projection_unavailable")
        if reduced is not None:
            reduced_patterns = _walk_schema_leaf_patterns(
                catalog,
                document,
                _schema_mapping(reduced),
            )
            derived.update((method, None, pattern) for pattern in reduced_patterns)
        dry_run = definitions.get("dry_run")
        if dry_run is not None:
            dry_run_patterns = _walk_schema_leaf_patterns(
                catalog,
                document,
                _schema_mapping(dry_run),
            )
            derived.update((method, None, pattern) for pattern in dry_run_patterns)
        # check admits a second success branch too: the nonterminal awaiting_human result. Its
        # leaves must classify like any other, or a suspended check would project unclassified
        # fields to a client sink.
        awaiting_human = definitions.get("awaiting_human")
        if awaiting_human is not None:
            awaiting_patterns = _walk_schema_leaf_patterns(
                catalog,
                document,
                _schema_mapping(awaiting_human),
            )
            derived.update((method, None, pattern) for pattern in awaiting_patterns)

    status_document = catalog.by_name_version[
        ("status-result", catalog.request_result_versions["status-result"])
    ]
    status_success = _schema_success_definition(status_document)
    status_properties = dict(_schema_mapping(status_success.get("properties")))
    if status_properties.pop("page", None) is None:
        raise AssertionError("status_page_property_missing")

    status_without_page: dict[str, JsonValue] = dict(status_success)
    status_without_page["properties"] = cast(JsonValue, status_properties)
    common_patterns = _walk_schema_leaf_patterns(
        catalog,
        status_document,
        status_without_page,
    )
    derived.update(("status", None, pattern) for pattern in common_patterns)

    status_definitions = _schema_mapping(status_document.json_schema.get("$defs"))
    for view, definition_name in _STATUS_PAGE_DEF_BY_VIEW_FOR_TEST:
        page_definition = status_definitions.get(definition_name)
        if page_definition is None:
            raise AssertionError("status_page_definition_missing")
        page_patterns = _walk_schema_leaf_patterns(
            catalog,
            status_document,
            _schema_mapping(page_definition),
            prefix=("page",),
        )
        derived.update(("status", view, pattern) for pattern in page_patterns)

    return frozenset(derived)


def _test_pointer_segments(pointer: str) -> tuple[str, ...]:
    if not pointer.startswith("/"):
        raise AssertionError("test_pointer_invalid")
    return tuple(pointer[1:].split("/"))


def _expected_nonpublish_content_rules(
    models: Any,
) -> dict[tuple[str, str | None, tuple[str, ...]], object]:
    finding_summary = models.DataCategory.FINDING_SUMMARY
    evidence_excerpt = models.DataCategory.EVIDENCE_EXCERPT
    obligation_text = models.DataCategory.OBLIGATION_TEXT
    task_description = models.DataCategory.TASK_DESCRIPTION
    repository_excerpt = models.DataCategory.REPOSITORY_EXCERPT

    rows: tuple[tuple[str, str | None, str, object], ...] = (
        ("check", None, "/findings/*/detail", finding_summary),
        ("check", None, "/findings/*/summary", finding_summary),
        # Reviewer-authored challenge prose, summary, and verified items (issue #961).
        ("check", None, "/findings/*/challenge/alternative_interpretation", finding_summary),
        ("check", None, "/findings/*/challenge/discrepancy", finding_summary),
        ("check", None, "/findings/*/challenge/snippet", finding_summary),
        ("check", None, "/findings/*/challenge/uncertainty", finding_summary),
        ("check", None, "/review_summary", finding_summary),
        ("check", None, "/verified/*/requirement_or_claim", finding_summary),
        ("check", None, "/verified/*/snippet", finding_summary),
        ("respond", None, "/response/evidence/*/description", evidence_excerpt),
        ("respond", None, "/response/reason", finding_summary),
        ("status", "advice", "/page/items/*/coordination_resource_paths/*", repository_excerpt),
        ("status", "project", "/page/detections/*/resource_paths/*", repository_excerpt),
        (
            "status",
            "candidate_findings",
            "/page/items/*/detail",
            finding_summary,
        ),
        (
            "status",
            "candidate_findings",
            "/page/items/*/summary",
            finding_summary,
        ),
        (
            "status",
            "compact",
            "/page/items/*/open_obligations/*/acceptance_criteria",
            obligation_text,
        ),
        (
            "status",
            "compact",
            "/page/items/*/open_obligations/*/description",
            obligation_text,
        ),
        (
            "status",
            "compact",
            "/page/items/*/open_obligations/*/evidence_expectation",
            obligation_text,
        ),
        ("status", "compact", "/page/items/*/task_title", task_description),
        (
            "status",
            "compact",
            "/page/items/*/unanswered_findings/*/detail",
            finding_summary,
        ),
        (
            "status",
            "compact",
            "/page/items/*/unanswered_findings/*/summary",
            finding_summary,
        ),
        ("status", "evidence", "/page/items/*/description", evidence_excerpt),
        ("status", "evidence", "/page/items/*/reference", evidence_excerpt),
        (
            "status",
            "findings",
            "/page/items/*/challenge/alternative_interpretation",
            finding_summary,
        ),
        ("status", "findings", "/page/items/*/challenge/discrepancy", finding_summary),
        ("status", "findings", "/page/items/*/challenge/snippet", finding_summary),
        ("status", "findings", "/page/items/*/challenge/uncertainty", finding_summary),
        ("status", "findings", "/page/items/*/detail", finding_summary),
        ("status", "findings", "/page/items/*/reason", finding_summary),
        ("status", "findings", "/page/items/*/summary", finding_summary),
        (
            "status",
            "obligations",
            "/page/items/*/acceptance_criteria",
            obligation_text,
        ),
        (
            "status",
            "obligations",
            "/page/items/*/acknowledged_not_done_reason",
            obligation_text,
        ),
        (
            "status",
            "obligations",
            "/page/items/*/description",
            obligation_text,
        ),
        (
            "status",
            "obligations",
            "/page/items/*/evidence_expectation",
            obligation_text,
        ),
        (
            "status",
            "obligations",
            "/page/items/*/requested_items/*/value",
            obligation_text,
        ),
        (
            "status",
            "obligations",
            "/page/items/*/unattempted_items/*/value",
            obligation_text,
        ),
        ("status", "project", "/page/title", task_description),
        ("status", "project", "/page/description", task_description),
        ("receipt", None, "/document/findings/*/detail", finding_summary),
        ("receipt", None, "/document/findings/*/summary", finding_summary),
        ("receipt", None, "/document/gaps/*/detail", finding_summary),
        ("receipt", None, "/document/obligations/*/summary", obligation_text),
        ("receipt", None, "/document/responses/*/reason", finding_summary),
        ("receipt", None, "/document/sections/*/body", finding_summary),
        ("receipt", None, "/document/sections/*/coverage_note", finding_summary),
        ("receipt", None, "/document/sections/*/items/*", finding_summary),
        ("receipt", None, "/document/sections/*/title", finding_summary),
        ("receipt", None, "/human_text", finding_summary),
    )
    return {
        (method, view, _test_pointer_segments(pointer)): classification
        for method, view, pointer, classification in rows
    }


def _expected_publish_summary_rules(models: Any) -> dict[object, object]:
    return {
        "<opaque>": "public_structural",
        ("action_recorded", "1.0.0"): models.DataCategory.COMMAND_METADATA,
        ("assignment_recorded", "1.0.0"): "public_structural",
        ("check_recorded", "1.0.0"): "public_structural",
        ("check_recorded", "1.1.0"): "public_structural",
        ("check_recorded", "1.2.0"): "public_structural",
        ("check_recorded", "1.3.0"): "public_structural",
        ("check_recorded", "1.4.0"): "public_structural",
        ("coordination_context_recorded", "1.0.0"): "public_structural",
        ("coordination_obligation_declared", "1.0.0"): "public_structural",
        ("coordination_disposition_recorded", "1.0.0"): "public_structural",
        ("claim_recorded", "1.0.0"): models.DataCategory.FINDING_SUMMARY,
        ("decision_recorded", "1.0.0"): models.DataCategory.DECISION_EXCERPT,
        ("evidence_recorded", "1.0.0"): models.DataCategory.EVIDENCE_EXCERPT,
        ("finding_recorded", "1.0.0"): models.DataCategory.FINDING_SUMMARY,
        ("finding_recorded", "1.1.0"): models.DataCategory.FINDING_SUMMARY,
        ("finding_recorded", "1.2.0"): models.DataCategory.FINDING_SUMMARY,
        ("finding_recorded", "1.3.0"): models.DataCategory.FINDING_SUMMARY,
        ("finding_recorded", "1.4.0"): models.DataCategory.FINDING_SUMMARY,
        ("obligation_published", "1.0.0"): models.DataCategory.TASK_DESCRIPTION,
        ("plan_published", "1.0.0"): models.DataCategory.TASK_DESCRIPTION,
        ("plan_revised", "1.0.0"): models.DataCategory.TASK_DESCRIPTION,
        ("receipt_recorded", "1.0.0"): "public_structural",
        ("redaction_recorded", "1.0.0"): "public_structural",
        ("response_recorded", "1.0.0"): models.DataCategory.FINDING_SUMMARY,
        ("result_recorded", "1.0.0"): models.DataCategory.COMMAND_METADATA,
        ("session_opened", "1.0.0"): "public_structural",
        ("session_resumed", "1.0.0"): "public_structural",
    }


def _test_rule_sort_key(
    rule: Any,
) -> tuple[bytes, bytes, bytes, tuple[bytes, ...]]:
    event_selector = rule.event_selector
    if isinstance(event_selector, tuple):
        selector_text = f"{event_selector[0]}@{event_selector[1]}"
    else:
        selector_text = event_selector or ""
    return (
        rule.method.encode("utf-8"),
        (rule.status_view or "").encode("utf-8"),
        selector_text.encode("utf-8"),
        tuple(segment.encode("utf-8") for segment in rule.segments),
    )


def _plain_object(data: bytes) -> dict[str, JsonValue]:
    value = strict_json_parse(data)
    assert type(value) is dict
    return cast(dict[str, JsonValue], value)


def _schema_tree(tmp_path: Path, case: str) -> Path:
    source = Path(__file__).resolve().parents[3] / "src" / "yoetz" / "resources" / "schemas"
    destination = tmp_path / case
    shutil.copytree(source, destination)
    return destination


def _write_canonical(path: Path, value: dict[str, JsonValue]) -> None:
    path.write_bytes(canonical_encode(value))


def _manifest_members(tree: Path) -> tuple[dict[str, JsonValue], list[JsonValue]]:
    manifest = _plain_object((tree / "manifest.json").read_bytes())
    members = manifest["members"]
    assert type(members) is list
    return manifest, cast(list[JsonValue], members)


def _rewrite_schema(
    tree: Path,
    relative_path: str,
    mutate: Callable[[dict[str, JsonValue]], None],
) -> None:
    schema_path = tree.joinpath(*relative_path.split("/"))
    schema = _plain_object(schema_path.read_bytes())
    mutate(schema)
    schema_bytes = canonical_encode(schema)
    schema_path.write_bytes(schema_bytes)

    manifest_path = tree / "manifest.json"
    manifest = _plain_object(manifest_path.read_bytes())
    members = manifest["members"]
    assert type(members) is list
    for raw_member in members:
        assert type(raw_member) is dict
        member = cast(dict[str, JsonValue], raw_member)
        if member["path"] == relative_path:
            member["byte_length"] = len(schema_bytes)
            member["sha256"] = f"sha256:{hashlib.sha256(schema_bytes).hexdigest()}"
            break
    else:
        raise AssertionError("schema_member_not_found")
    _write_canonical(manifest_path, manifest)


def _load_tree_with_reason(
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    monkeypatch.setattr(schemas_module, "_schema_root", lambda: tree)
    schemas_module._load_catalog_state.cache_clear()  # pyright: ignore[reportPrivateUsage]
    try:
        with pytest.raises(ProtocolValueError) as exc_info:
            schemas_module.load_schema_catalog()
        _assert_reason(exc_info, reason)
    finally:
        schemas_module._load_catalog_state.cache_clear()  # pyright: ignore[reportPrivateUsage]


def test_schema_catalog_reports_complete_registry() -> None:
    catalog = load_schema_catalog()
    assert SCHEMA_NAMESPACE == "https://schemas.yoetz.dev/0.1/"
    assert SCHEMA_MANIFEST_SCHEMA == "yoetz.schema-manifest/1.0.0"
    assert SCHEMA_MANIFEST_VERSION == "1.0.0"
    assert SCHEMA_MEMBER_COUNT == 228
    assert len(catalog.documents) == SCHEMA_MEMBER_COUNT

    paths = tuple(document.relative_path for document in catalog.documents)
    assert paths == tuple(sorted(paths, key=str.encode))
    assert tuple(catalog.by_path) == paths
    assert len(catalog.by_id) == len(catalog.by_name_version) == SCHEMA_MEMBER_COUNT
    assert set(SchemaKind) == {
        SchemaKind.REQUEST_RESULT,
        SchemaKind.EVENT,
        SchemaKind.CONFIG,
        SchemaKind.VERSION_MANIFEST,
    }
    assert len(SchemaArtifactRole) == 18


def test_schema_uri_and_path_resolution_are_stable() -> None:
    assert schema_path_for("action-recorded", "1.0.0") == (
        "events/action-recorded-1.0.0.schema.json"
    )
    assert schema_uri("action-recorded", "1.0.0") == (
        "https://schemas.yoetz.dev/0.1/events/action-recorded-1.0.0.schema.json"
    )
    document = schema_document_for("action-recorded", "1.0.0")
    assert document.schema_name == "action-recorded"
    assert document.schema_id == schema_uri("action-recorded", "1.0.0")

    for name, version, reason in (
        ("events/action-recorded", "1.0.0", "schema_name_invalid"),
        ("action_recorded", "1.0.0", "schema_name_invalid"),
        ("../action-recorded", "1.0.0", "schema_name_invalid"),
        ("action%2drecorded", "1.0.0", "schema_name_invalid"),
        ("é", "1.0.0", "schema_name_invalid"),
        ("action-recorded", "01.0.0", "schema_name_invalid"),
        ("action-recorded", "1.0", "schema_name_invalid"),
        ("absent-schema", "1.0.0", "schema_not_found"),
    ):
        with pytest.raises(ProtocolValueError) as exc_info:
            schema_path_for(name, version)
        _assert_reason(exc_info, reason)


def test_schema_catalog_record_shape_and_indexes_are_exact() -> None:
    assert tuple(field.name for field in fields(SchemaDocument)) == (
        "schema_kind",
        "artifact_role",
        "schema_name",
        "schema_version",
        "schema_id",
        "relative_path",
        "canonical_digest",
        "schema_bytes",
        "json_schema",
    )
    assert tuple(field.name for field in fields(SchemaCatalog)) == (
        "documents",
        "by_path",
        "by_id",
        "by_name_version",
        "request_result_versions",
        "event_schema_versions",
        "manifest_version",
        "manifest_digest",
    )

    catalog = load_schema_catalog()
    for document in catalog.documents:
        assert catalog.by_path[document.relative_path] is document
        assert catalog.by_id[document.schema_id] is document
        assert catalog.by_name_version[(document.schema_name, document.schema_version)] is document
        assert canonical_encode(document.json_schema) == document.schema_bytes
        _walk_frozen(document.json_schema)
        validate_schema_document(document)

    with pytest.raises(TypeError):
        catalog.by_path["x"] = catalog.documents[0]  # type: ignore[index]
    with pytest.raises(TypeError):
        catalog.documents[0].json_schema["x"] = None  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        catalog.documents[0].schema_name = "changed"  # type: ignore[misc]

    root = resources.files("yoetz").joinpath("resources", "schemas")
    manifest_bytes = root.joinpath("manifest.json").read_bytes()
    assert catalog.manifest_digest == f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}"
    assert sum(_count_refs(document.json_schema) for document in catalog.documents) == 7_672


def test_schema_name_derivation_and_version_maps_are_exact() -> None:
    catalog = load_schema_catalog()
    request_versions = request_result_schema_versions(catalog)
    event_versions = event_schema_versions(catalog)
    assert request_versions is catalog.request_result_versions
    assert event_versions is catalog.event_schema_versions
    assert len(request_versions) == 53
    assert len(event_versions) == 29
    assert tuple(request_versions) == tuple(sorted(request_versions, key=str.encode))
    assert tuple(event_versions) == tuple(sorted(event_versions, key=str.encode))
    assert set(request_versions.values()) == {
        "1.0.0",
        "1.1.0",
        "1.2.0",
        "1.3.0",
        "2.0.0",
        "2.9.0",
        "7.0.0",
        "1.4.0",
    }
    assert set(event_versions.values()) == {"1.0.0", "1.1.0", "1.2.0", "1.4.0"}
    assert event_versions["action_recorded"] == "1.0.0"
    assert event_versions["evidence_recorded"] == "1.2.0"
    assert event_versions["check_recorded"] == "1.4.0"
    assert event_versions["claim_recorded"] == "1.1.0"
    assert event_versions["finding_recorded"] == "1.4.0"
    # The task-statement versions (issue #908).
    assert event_versions["session_opened"] == "1.2.0"
    assert event_versions["session_resumed"] == "1.2.0"
    assert event_versions["plan_published"] == "1.1.0"
    assert event_versions["plan_revised"] == "1.1.0"
    # Role- and directory-bearing obligations (issue #1002).
    assert event_versions["obligation_published"] == "1.1.0"
    assert "accepted_event" not in event_versions
    assert "event_draft" not in event_versions
    assert "opaque_unknown_event_draft" not in event_versions


def test_schema_manifest_failure_reason_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = _schema_tree(tmp_path, "missing")
    (missing / "manifest.json").unlink()
    _load_tree_with_reason(missing, monkeypatch, "schema_manifest_missing")

    noncanonical = _schema_tree(tmp_path, "noncanonical")
    manifest_path = noncanonical / "manifest.json"
    manifest_path.write_bytes(manifest_path.read_bytes() + b"\n")
    _load_tree_with_reason(noncanonical, monkeypatch, "schema_manifest_invalid")

    duplicate = _schema_tree(tmp_path, "duplicate")
    manifest, members = _manifest_members(duplicate)
    assert type(members[0]) is dict
    members[1] = dict(cast(dict[str, JsonValue], members[0]))
    _write_canonical(duplicate / "manifest.json", manifest)
    _load_tree_with_reason(duplicate, monkeypatch, "schema_manifest_duplicate_path")

    extra = _schema_tree(tmp_path, "extra")
    (extra / "unlisted.txt").write_text("unlisted", encoding="utf-8")
    _load_tree_with_reason(extra, monkeypatch, "schema_manifest_member_mismatch")

    unsafe = _schema_tree(tmp_path, "unsafe")
    manifest, members = _manifest_members(unsafe)
    assert type(members[0]) is dict
    cast(dict[str, JsonValue], members[0])["path"] = "../escape.schema.json"
    _write_canonical(unsafe / "manifest.json", manifest)
    _load_tree_with_reason(unsafe, monkeypatch, "schema_path_unsafe")

    digest = _schema_tree(tmp_path, "digest")
    schema_path = digest / "common" / "actor-assertion-1.0.0.schema.json"
    schema_bytes = schema_path.read_bytes()
    schema_path.write_bytes(schema_bytes[:-1] + b"]")
    _load_tree_with_reason(digest, monkeypatch, "schema_digest_mismatch")

    invalid_role = _schema_tree(tmp_path, "invalid-role")
    manifest, members = _manifest_members(invalid_role)
    assert type(members[0]) is dict
    cast(dict[str, JsonValue], members[0])["artifact_role"] = "unknown-role"
    _write_canonical(invalid_role / "manifest.json", manifest)
    _load_tree_with_reason(invalid_role, monkeypatch, "schema_artifact_role_invalid")

    wrong_role = _schema_tree(tmp_path, "wrong-role")
    manifest, members = _manifest_members(wrong_role)
    assert type(members[0]) is dict
    cast(dict[str, JsonValue], members[0])["artifact_role"] = "MCP input"
    _write_canonical(wrong_role / "manifest.json", manifest)
    _load_tree_with_reason(wrong_role, monkeypatch, "schema_artifact_role_mismatch")

    wrong_kind = _schema_tree(tmp_path, "wrong-kind")
    manifest, members = _manifest_members(wrong_kind)
    assert type(members[0]) is dict
    cast(dict[str, JsonValue], members[0])["schema_kind"] = "event"
    _write_canonical(wrong_kind / "manifest.json", manifest)
    _load_tree_with_reason(wrong_kind, monkeypatch, "schema_kind_mismatch")

    wrong_draft = _schema_tree(tmp_path, "wrong-draft")

    def change_draft(schema: dict[str, JsonValue]) -> None:
        schema["$schema"] = "https://json-schema.org/draft/2019-09/schema"

    _rewrite_schema(
        wrong_draft,
        "common/actor-assertion-1.0.0.schema.json",
        change_draft,
    )
    _load_tree_with_reason(wrong_draft, monkeypatch, "schema_draft_unsupported")

    wrong_id = _schema_tree(tmp_path, "wrong-id")

    def change_id(schema: dict[str, JsonValue]) -> None:
        schema["$id"] = "https://schemas.yoetz.dev/0.1/common/not-the-route.schema.json"

    _rewrite_schema(wrong_id, "common/actor-assertion-1.0.0.schema.json", change_id)
    _load_tree_with_reason(wrong_id, monkeypatch, "schema_id_mismatch")

    invalid_schema = _schema_tree(tmp_path, "invalid-schema")

    def break_metaschema(schema: dict[str, JsonValue]) -> None:
        schema["type"] = 7

    _rewrite_schema(
        invalid_schema,
        "common/actor-assertion-1.0.0.schema.json",
        break_metaschema,
    )
    # Meta-validity moved from runtime load to a build-time invariant (#210):
    # a digest-verified member is trusted at load, so the catalog accepts this
    # tree (its manifest digest matches its bytes) — but the strict public
    # rechecker still meta-validates and must reject the document.
    monkeypatch.setattr(schemas_module, "_schema_root", lambda: invalid_schema)
    schemas_module._load_catalog_state.cache_clear()  # pyright: ignore[reportPrivateUsage]
    try:
        loaded = schemas_module.load_schema_catalog()
        broken = loaded.by_path["common/actor-assertion-1.0.0.schema.json"]
        with pytest.raises(ProtocolValueError) as strict_exc:
            schemas_module.validate_schema_document(broken)
        _assert_reason(strict_exc, "schema_bytes_invalid")
    finally:
        schemas_module._load_catalog_state.cache_clear()  # pyright: ignore[reportPrivateUsage]

    unresolved = _schema_tree(tmp_path, "unresolved")

    def add_unresolved_ref(schema: dict[str, JsonValue]) -> None:
        schema["x-unresolved"] = {
            "$ref": "https://schemas.yoetz.dev/0.1/common/missing-1.0.0.schema.json"
        }

    _rewrite_schema(
        unresolved,
        "common/actor-assertion-1.0.0.schema.json",
        add_unresolved_ref,
    )
    _load_tree_with_reason(unresolved, monkeypatch, "schema_reference_unresolved")

    version_mismatch = _schema_tree(tmp_path, "version-mismatch")
    manifest, members = _manifest_members(version_mismatch)
    assert type(members[0]) is dict
    cast(dict[str, JsonValue], members[0])["schema_version"] = "1.0.1"
    _write_canonical(version_mismatch / "manifest.json", manifest)
    _load_tree_with_reason(version_mismatch, monkeypatch, "schema_version_mismatch")

    duplicate_identity = _schema_tree(tmp_path, "duplicate-identity")
    original_identity = cast(
        Callable[[str, str], tuple[str, str]],
        getattr(schemas_module, "_derive_identity"),
    )

    def collide_identity(path: str, version: str) -> tuple[str, str]:
        if path == "common/client-info-1.0.0.schema.json":
            return original_identity("common/actor-assertion-1.0.0.schema.json", version)
        return original_identity(path, version)

    with monkeypatch.context() as case_patch:
        case_patch.setattr(schemas_module, "_derive_identity", collide_identity)
        _load_tree_with_reason(
            duplicate_identity,
            case_patch,
            "schema_duplicate_identity",
        )

    incomplete = _schema_tree(tmp_path, "incomplete")
    manifest, members = _manifest_members(incomplete)
    target_path = "common/client-info-1.0.0.schema.json"
    for raw_member in members:
        assert type(raw_member) is dict
        member = cast(dict[str, JsonValue], raw_member)
        if member["path"] == target_path:
            member["schema_kind"] = "config"
            break
    else:
        raise AssertionError("schema_member_not_found")
    _write_canonical(incomplete / "manifest.json", manifest)

    original_kind = cast(
        Callable[[str], SchemaKind],
        getattr(schemas_module, "_derive_kind"),
    )

    def reclassify_kind(path: str) -> SchemaKind:
        if path == target_path:
            return SchemaKind.CONFIG
        return original_kind(path)

    with monkeypatch.context() as case_patch:
        case_patch.setattr(schemas_module, "_derive_kind", reclassify_kind)
        _load_tree_with_reason(
            incomplete,
            case_patch,
            "schema_catalog_incomplete",
        )


def test_schema_instance_validation_is_closed_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_network(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", deny_network)
    schemas_module._load_catalog_state.cache_clear()  # pyright: ignore[reportPrivateUsage]
    try:
        validate_schema_instance("coverage", "1.0.0", _VALID_COVERAGE)

        invalid_cases: tuple[JsonValue, ...] = (
            {**_VALID_COVERAGE, "extra": True},
            {key: value for key, value in _VALID_COVERAGE.items() if key != "known_gaps"},
            {**_VALID_COVERAGE, "publication_channels": []},
        )
        for invalid in invalid_cases:
            with pytest.raises(ProtocolValueError) as exc_info:
                validate_schema_instance("coverage", "1.0.0", invalid)
            _assert_reason(exc_info, "schema_instance_invalid")

        with pytest.raises(ProtocolValueError) as exc_info:
            validate_schema_instance("coverage", "1.0.0", cast(JsonValue, {"value": 1.0}))
        _assert_reason(exc_info, "float_forbidden")
    finally:
        schemas_module._load_catalog_state.cache_clear()  # pyright: ignore[reportPrivateUsage]


def test_current_receipt_document_schema_carries_optional_semantic_provenance() -> None:
    schema_root = Path(__file__).parents[3] / "schemas"
    old_schema = cast(
        dict[str, Any],
        strict_json_parse(
            (schema_root / "receipts/receipt-document-1.1.0.schema.json").read_bytes()
        ),
    )
    current_schema = cast(
        dict[str, Any],
        strict_json_parse(
            (schema_root / "receipts/receipt-document-1.2.0.schema.json").read_bytes()
        ),
    )
    old_properties = cast(dict[str, Any], old_schema["properties"])
    current_properties = cast(dict[str, Any], current_schema["properties"])
    assert "semantic_provenance" not in old_properties
    assert current_properties["semantic_provenance"] == {
        "$ref": "https://schemas.yoetz.dev/0.1/findings/semantic-provenance-1.2.0.schema.json"
    }
    assert "semantic_provenance" not in cast(list[str], current_schema["required"])


def test_capacity_failure_forbids_attempt_provenance() -> None:
    models = _models_module()
    value = _check_result_wire()
    value["semantic_status"] = "failed"
    value["semantic_reason"] = "case_capacity_exceeded"
    value["semantic_provenance"] = None
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("check-result", "1.0.0", value)
    models.CheckResultModel.model_validate(value)
    validate_schema_instance("check-result", "1.1.0", value)
    value["semantic_provenance"] = _semantic_provenance_for("failed", "case_capacity_exceeded")
    with pytest.raises(ValueError):
        models.CheckResultModel.model_validate(value)
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("check-result", "1.1.0", value)


def test_closure_checklist_is_absent_as_a_whole_or_complete() -> None:
    """Issue #913: 1.4.0 is unreleased, so earlier 0.3 readiness shapes stay valid."""

    models = _models_module()
    legacy: dict[str, JsonValue] = {
        "declared_obligation_count": "0",
        "no_obligations_reason": None,
        "open_obligation_count": "0",
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "0",
        "blocking_conditions": ["no_obligations_declared"],
    }
    parsed = models.StatusClosureReadinessModel.model_validate(legacy)
    assert parsed.state is None
    result = _status_result_wire()
    result["closure_readiness"] = legacy
    validate_schema_instance("status-result", "1.4.0", result)
    complete = with_checklist(legacy)
    assert complete["state"] == "action_required"
    assert complete["agent_actionable"] == ["no_obligations_declared"]
    models.StatusClosureReadinessModel.model_validate(complete)
    partial = {**legacy, "state": "action_required"}
    with pytest.raises(ValidationError):
        models.StatusClosureReadinessModel.model_validate(partial)
    result["closure_readiness"] = partial
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("status-result", "1.4.0", result)
    mismatches: tuple[dict[str, JsonValue], ...] = (
        {**complete, "state": "ready_with_limitations"},
        {**complete, "agent_actionable": []},
        {**complete, "standing_limitations": ["no_obligations_declared"]},
        {**complete, "acknowledged_not_done_count": "1"},
    )
    for mismatch in mismatches:
        with pytest.raises(ValidationError):
            models.StatusClosureReadinessModel.model_validate(mismatch)


def test_status_obligations_row_shows_the_acknowledgement_reason_as_obligation_text() -> None:
    """#1002/#996: the agent's own acknowledged_not_done reason, like the obligation text."""

    models = _models_module()
    status = _status_result_wire()
    status["view"] = "obligations"
    item: dict[str, JsonValue] = {
        "obligation_id": _test_id("obl_"),
        "status": "acknowledged_not_done",
        "description": "Port the RTL to the new bus.",
        "evidence_expectation": "Simulation passes.",
        "source_refs": [],
        "assigned_actor_ids": [],
        "evidence_refs": [],
        "revision_event_id": None,
        "requested_items": [{"item_kind": "directory", "value": "/app/src", "role": "output"}],
        "acknowledged_not_done_reason": "The vendor simulator licence is unavailable.",
    }
    status["page"] = {"items": [item], "next_cursor": None}
    models.StatusResultModel.model_validate(status)
    validate_schema_instance("status-result", "1.4.0", status)
    wire = models.public_model_to_wire(models.StatusResultModel.model_validate(status))
    assert (
        models.classify_result_leaf("status", wire, "/page/items/0/acknowledged_not_done_reason")
        is models.DataCategory.OBLIGATION_TEXT
    )

    # Omitted under the obligation-text category only.
    item["acknowledged_not_done_reason"] = {
        "omitted": True,
        "category": "obligation_text",
        "reason": "never_send_redacted",
    }
    models.StatusResultModel.model_validate(status)
    item["acknowledged_not_done_reason"] = {
        "omitted": True,
        "category": "task_description",
        "reason": "never_send_redacted",
    }
    with pytest.raises(ValidationError):
        models.StatusResultModel.model_validate(status)

    # Present exactly for that status.
    del item["acknowledged_not_done_reason"]
    with pytest.raises(ValidationError):
        models.StatusResultModel.model_validate(status)
    item["status"] = "open"
    models.StatusResultModel.model_validate(status)
    item["acknowledged_not_done_reason"] = "why"
    with pytest.raises(ValidationError):
        models.StatusResultModel.model_validate(status)
