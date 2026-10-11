"""Public error vocabulary and bounded protocol-value failures."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import FrozenInstanceError, dataclass
from enum import Enum
from types import MappingProxyType
from typing import cast

__all__ = [
    "ADMITTED_CLAIM_REVISION_INVARIANTS",
    "ADMITTED_CONTINUATION_TOKENS",
    "PROTOCOL_REASON_CODES",
    "REASON_CODE_CONTINUATIONS",
    "SAFE_DETAIL_KEYS",
    "ProtocolValueError",
    "PublicErrorCode",
    "PublicOperationError",
    "SafeDetailValue",
    "attach_reason_continuation",
    "normalize_safe_details",
]


class PublicErrorCode(str, Enum):  # noqa: UP042 - the wire contract requires these exact bases
    INVALID_REQUEST = "INVALID_REQUEST"
    PROTOCOL_VERSION_UNSUPPORTED = "PROTOCOL_VERSION_UNSUPPORTED"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    SESSION_CONFLICT = "SESSION_CONFLICT"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    REQUEST_IDENTITY_CONFLICT = "REQUEST_IDENTITY_CONFLICT"
    OPERATION_PENDING = "OPERATION_PENDING"
    FRONTIER_CONFLICT = "FRONTIER_CONFLICT"
    EVENT_INVALID = "EVENT_INVALID"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    BUNDLE_BUSY = "BUNDLE_BUSY"
    STORAGE_UNSAFE = "STORAGE_UNSAFE"
    STORAGE_CORRUPT = "STORAGE_CORRUPT"
    MIGRATION_REQUIRED = "MIGRATION_REQUIRED"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    VAULT_LOCKED = "VAULT_LOCKED"
    PRIVACY_AUTHORITY_REQUIRED = "PRIVACY_AUTHORITY_REQUIRED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_REFUSED = "PROVIDER_REFUSED"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    SEMANTIC_RESULT_INVALID = "SEMANTIC_RESULT_INVALID"
    CANCELLED = "CANCELLED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# A tuple value is a bounded list of closed tokens (``blocking_reasons``, issue #1023); the
# public-error schema already admits an array of primitives as a detail value.
type SafeDetailValue = str | int | tuple[str, ...]


_PROTOCOL_REASON_CODE_VALUES: tuple[str, ...] = (
    "accepted_but_unresponsive",
    "accepted_record_shape_invalid",
    "actor_id_malformed",
    "actor_id_not_generated",
    "ambiguous_binding",
    "attach_handle_expired",
    "attach_handle_invalid",
    "attach_handle_reused",
    "attach_handle_revoked",
    "attach_result_invalid",
    "bridge_error_mapping_failed",
    "bridge_invoke_failed",
    "bridge_request_validation_failed",
    "byte_order_mark_forbidden",
    "catalog_busy",
    "catalog_maintenance_busy",
    "check_admission_capture_pending",
    "check_admission_contended",
    "check_admission_import_pending",
    "check_admission_in_progress",
    "check_pipeline_failed",
    "child_check_frontier_ahead_of_child",
    "child_check_frontier_missing",
    "child_check_frontier_without_check",
    "child_dependencies_not_canonical",
    "child_dependency_count_invalid",
    "child_finding_count_invalid",
    "child_findings_not_canonical",
    "child_frontier_missing",
    "child_gap_frontier_mismatch",
    "claim_revision_invalid",
    "claim_revision_mismatch",
    "closure_attempt_selection_required",
    "closure_claim_decision_required",
    "closure_command_revision_required",
    "closure_draft_invalid",
    "closure_evidence_unavailable",
    "closure_inventory_limit",
    "closure_item_omitted",
    "closure_item_unknown",
    "closure_obligation_content_unavailable",
    "closure_obligation_not_open",
    "closure_obligation_unknown",
    "closure_pagination_invalid",
    "closure_prepare_failed",
    "closure_resolution_decision_required",
    "closure_response_decision_required",
    "closure_result_too_large",
    "closure_result_unavailable",
    "closure_source_unknown",
    "closure_status_unavailable",
    "closure_unattempted_items",
    "commitment_only_object_kind",
    "coordination_admission_required",
    "coordination_consent_required",
    "coordination_declaration_invalid",
    "coordination_detection_mismatch",
    "coordination_disposition_invalid",
    "coordination_evidence_missing",
    "coordination_generation_mismatch",
    "coordination_generation_revoked",
    "coordination_generation_superseded",
    "coordination_grant_required",
    "coordination_invalid",
    "coordination_obligation_conflict",
    "coordination_obligation_mismatch",
    "coordination_participants_unavailable",
    "coordination_recipient_mismatch",
    "coordination_resource_count_invalid",
    "coordination_route_unavailable",
    "coordination_runtime_unavailable",
    "coordination_source_policy_denied",
    "coordination_source_unavailable",
    "coordination_task_pair_invalid",
    "coordination_tasks_not_canonical",
    "cross_repository_lineage_requires_grant",
    "cursor_mcp_route_invalid",
    "cursor_project_mcp_command_invalid",
    "cursor_project_mcp_invalid",
    "cursor_project_mcp_preview_required",
    "dependency_changed",
    "duplicate_has_duplicates",
    "duplicate_link_broken",
    "duplicate_object_key",
    "duplicate_set_member",
    "duplicate_target_different_issue",
    "duplicate_target_is_duplicate",
    "duplicate_target_not_earlier",
    "duplicate_target_same_finding",
    "duplicate_target_unknown",
    "empty_check_types",
    "empty_publication_channels",
    "empty_subject_state",
    "endpoint_unsafe",
    "engine_family_wrong_author",
    "entry_digest_mismatch",
    "event_family_not_admitted",
    "event_integer_out_of_range",
    "event_text_out_of_bounds",
    "evidence_digest_availability_invalid",
    "evidence_digest_binding_invalid",
    "evidence_digest_binding_required",
    "evidence_digest_provenance_invalid",
    "evidence_digest_subject_incompatible",
    "evidence_strength_unsupported",
    "expected_frontier_required",
    "finding_actionable_mismatch",
    "finding_json_shape_invalid",
    "finding_not_proof_limited",
    "finding_not_rechecked",
    "finding_priority_mismatch",
    "finding_resolution_mismatch",
    "finding_terminal",
    "float_forbidden",
    "frame_invalid",
    "frame_too_large",
    "frontier_changed",
    "frontier_digest_mismatch",
    "general_project_membership_conflict",
    "host_lineage_annotation_invalid",
    "id_malformed_uuid",
    "id_not_ascii",
    "id_uuid_not_version_4",
    "id_uuid_wrong_variant",
    "id_wrong_length",
    "id_wrong_prefix",
    "id_wrong_type",
    "implicit_project_requires_opt_out",
    "import_publication_authority_required",
    "import_publication_failed",
    "import_report_invalid",
    "input_not_bytes",
    "integer_out_of_safe_range",
    "integer_out_of_sqlite_range",
    "internal_error",
    "invalid_actor_type",
    "invalid_approved_check",
    "invalid_approved_check_policy",
    "invalid_chain",
    "invalid_check_types",
    "invalid_commitment",
    "invalid_continuation_expiry",
    "invalid_continuation_kind",
    "invalid_continuation_pending_id",
    "invalid_continuation_repository_setup",
    "invalid_continuation_review_input",
    "invalid_cost_fields",
    "invalid_coverage_value",
    "invalid_digest",
    "invalid_duration",
    "invalid_event_enum",
    "invalid_event_schema",
    "invalid_event_value_type",
    "invalid_external_runtime_authority",
    "invalid_finding_kind",
    "invalid_finding_origin",
    "invalid_finding_policy_identity",
    "invalid_finding_provenance",
    "invalid_finding_subject_refs",
    "invalid_frontier",
    "invalid_json_pointer",
    "invalid_known_gap",
    "invalid_payload_ref",
    "invalid_projection_locator",
    "invalid_publication_channels",
    "invalid_ranked_findings",
    "invalid_receipt_child_finding",
    "invalid_receipt_child_outcome",
    "invalid_receipt_children",
    "invalid_receipt_conclusion",
    "invalid_receipt_document",
    "invalid_receipt_gap",
    "invalid_receipt_obligation",
    "invalid_receipt_redaction",
    "invalid_receipt_response",
    "invalid_receipt_section",
    "invalid_receipt_section_order",
    "invalid_receipt_version_slice",
    "invalid_runtime_attempt_evidence",
    "invalid_sampling_params",
    "invalid_semantic_dispatch_kind",
    "invalid_semantic_failure_class",
    "invalid_semantic_fallback_origin",
    "invalid_semantic_outcome_type",
    "invalid_semantic_provenance",
    "invalid_semantic_status_reason_pair",
    "invalid_start_internal_result",
    "invalid_subject_state",
    "invalid_timestamp",
    "invalid_token_usage",
    "invalid_utf8",
    "invalid_workspace_inspect",
    "ledger_assigned_field_in_request_identity",
    "lineage_acceptance_transition",
    "lineage_catalog_busy",
    "lineage_catalog_migration_required",
    "lineage_child_missing",
    "lineage_child_not_found",
    "lineage_close_authority",
    "lineage_cycle",
    "lineage_depth_limit",
    "lineage_event_contradiction",
    "lineage_event_invalid",
    "lineage_event_operation_conflict",
    "lineage_event_operation_pending",
    "lineage_event_result_invalid",
    "lineage_fanout_limit",
    "lineage_handle_conflict",
    "lineage_handle_key_invalid",
    "lineage_handle_key_unavailable",
    "lineage_handle_missing",
    "lineage_manifest_stale",
    "lineage_operation_conflict",
    "lineage_operation_lease_expired",
    "lineage_operation_not_found",
    "lineage_operation_phase",
    "lineage_operation_quarantined",
    "lineage_parent_not_found",
    "lineage_parent_session_invalid",
    "lineage_parent_work_terminal",
    "lineage_phase_transition",
    "lineage_repository_mismatch",
    "lineage_request_identity_conflict",
    "lineage_reservation_conflict",
    "lineage_resume_work_terminal",
    "lineage_root_conflict",
    "lineage_root_dependency",
    "lineage_service_unavailable",
    "lineage_session_conflict",
    "lineage_session_not_active",
    "lineage_session_not_found",
    "lineage_session_scope",
    "lineage_task_conflict",
    "lineage_task_missing",
    "lineage_task_not_found",
    "lineage_transition_conflict",
    "lineage_work_terminal",
    "lineage_work_transition",
    "lone_surrogate",
    "maintenance_state_unverified",
    "malformed_json",
    "method_forbidden",
    "missing_payload_field",
    "nesting_too_deep",
    "no_obligations_reason_conflict",
    "noncanonical_integer_string",
    "noncanonical_json",
    "not_an_accepted_envelope",
    "nul_byte_forbidden",
    "object_key_not_string",
    "obligation_change_invalid",
    "obligation_resolution_invalid",
    "obligation_resolution_mismatch",
    "observation_selection_session_limit",
    "opaque_item_id_invalid",
    "operation_recovery_unavailable",
    "ownership_contended",
    "payload_redaction_mismatch",
    "payload_too_large",
    "peer_untrusted",
    "plan_version_conflict",
    "privacy_audit_unreadable",
    "privacy_projection_unavailable",
    "privacy_receipt_not_durable",
    "project_dissolved",
    "project_member_already_unbound",
    "project_member_not_found",
    "project_not_found",
    "projection_unavailable",
    "protocol_mismatch",
    "provider_attempt_provenance_is_not_final",
    "public_error_invalid_correlation_id",
    "public_error_invalid_message",
    "public_error_missing_correlation_id",
    "read_projection_failed",
    "receipt_child_manifest_mismatch",
    "receipt_children_not_canonical",
    "receipt_children_schema_version",
    "receipt_coverage_mismatch",
    "receipt_gap_not_in_coverage",
    "receipt_json_projection_blocked",
    "receipt_json_shape_invalid",
    "receipt_semantic_withheld_items_not_canonical",
    "redaction_target_required",
    "ref_mirror_mismatch",
    "repository_identity_mismatch",
    "repository_identity_required",
    "request_identity_conflict",
    "request_timeout",
    "requested_command_placeholder",
    "resolution_attempt_required",
    "response_fields_invalid",
    "response_projection_failed",
    "runtime_attempt_evidence_json_shape_invalid",
    "runtime_opening_authority",
    "runtime_rebind_busy",
    "schema_artifact_role_invalid",
    "schema_artifact_role_mismatch",
    "schema_bytes_invalid",
    "schema_catalog_incomplete",
    "schema_digest_mismatch",
    "schema_draft_unsupported",
    "schema_duplicate_identity",
    "schema_id_mismatch",
    "schema_instance_invalid",
    "schema_kind_mismatch",
    "schema_manifest_duplicate_path",
    "schema_manifest_invalid",
    "schema_manifest_member_mismatch",
    "schema_manifest_missing",
    "schema_name_invalid",
    "schema_not_found",
    "schema_path_unsafe",
    "schema_reference_unresolved",
    "schema_version_mismatch",
    "selector_conflict",
    "semantic_provenance_json_shape_invalid",
    "semantic_redacted_values_invalid",
    "service_draining",
    "service_generation_changed",
    "service_incompatible",
    "service_stamp_required",
    "service_unavailable",
    "session_lineage_fields_incomplete",
    "session_superseded",
    "set_member_not_ascii",
    "start_busy_retry_ready",
    "start_catalog_retry_ready",
    "start_lease_pending",
    "start_runtime_rebind_retry_ready",
    "start_state_inconsistent",
    "stored_result_shape_invalid",
    "timestamp_not_utc",
    "timestamp_out_of_range",
    "timestamp_submillisecond_precision",
    "timestamp_timezone_missing",
    "unknown_event_schema",
    "unknown_payload_field",
    "unsorted_set_field",
    "unsupported_json_type",
    "unsupported_payload_type",
    "workspace_task_exists",
)

_REASON_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
assert len(_PROTOCOL_REASON_CODE_VALUES) == 342
assert len(_PROTOCOL_REASON_CODE_VALUES) == len(set(_PROTOCOL_REASON_CODE_VALUES))
assert _PROTOCOL_REASON_CODE_VALUES == tuple(sorted(_PROTOCOL_REASON_CODE_VALUES, key=str.encode))
assert all(_REASON_CODE_PATTERN.fullmatch(value) for value in _PROTOCOL_REASON_CODE_VALUES)

PROTOCOL_REASON_CODES: frozenset[str] = frozenset(_PROTOCOL_REASON_CODE_VALUES)

SAFE_DETAIL_KEYS: tuple[str, ...] = (
    "actual_version",
    "authorize_command",
    "availability",
    "availability_inherited",
    "availability_request_id",
    "blocking_reasons",
    "component",
    "continuation",
    "count",
    "expected_version",
    "field",
    "head_digest",
    "host_profile",
    "invariant",
    "limit",
    "method",
    "operation",
    "pending_ttl_seconds",
    "phase",
    "prepare_command",
    "quarantine_code",
    "reason_code",
    "replay_request_id",
    "retry_after_ms",
    "review_command",
    "route_profile",
    "schema_name",
    "sequence",
    "session_id",
    "state",
    "status",
    "task_id",
    "view",
    "writer_id",
)

# The closed claim-revision invariant vocabulary (ADR-030). ``yoetz.domain.events`` owns the rule
# these name and cannot be imported here -- this module is a dependency root -- so the set is
# literal and the domain fails at import if the two ever disagree. Before ADR-030 the invariant
# travelled only inside the public error message, and the MCP text projector recovered it by
# matching that whole sentence with a regex; carrying it as a typed detail is what retires that.
ADMITTED_CLAIM_REVISION_INVARIANTS: frozenset[str] = frozenset(
    {
        "claim_id_must_be_fresh",
        "claim_kind_must_match",
        "completion_scope_must_be_explicit",
        "empty_scope_must_not_support_obligations",
        "limitation_refs_complete",
        "limitation_refs_must_be_relevant_non_success_results",
        "replacement_must_change_effective_claim",
        "replacement_must_not_dispute",
        "scope_overlap_required",
        "supporting_refs_must_exclude_limitations",
        "superseded_claim_must_be_effective",
        "superseded_claim_must_exist",
    }
)

_INTEGER_DETAIL_KEYS = frozenset(
    {"count", "limit", "pending_ttl_seconds", "retry_after_ms", "sequence"}
)
_BOOLEAN_DETAIL_KEYS = frozenset({"availability_inherited"})
# Closed token sets for the MCP bridge's host-binding availability facts (issue #469). The
# binding identity is the bridge's host and route profile; `availability` names the one latched
# state a later request identity may inherit.
# `continuation` and the exact command literals are typed handoffs, not free text: every value is a
# repository constant, so nothing caller-derived can ride these keys onto the wire. The token set is
# the recovery registry's own (issue #739), which began as the single initialization-required
# continuation of issue #512; the registry owns the directive text each token stands for, and that
# text never travels here.
# The closed continuation vocabulary (issue #739). This module is a dependency root and holds no
# internal imports, so the tokens are literal here and ``yoetz.protocol.recovery`` fails at import
# time if its registry and this set ever disagree. Adding a token here without registering its
# directive, or the reverse, is a build failure rather than a bare token reaching an agent.
ADMITTED_CONTINUATION_TOKENS: frozenset[str] = frozenset(
    {
        "check_admission_same_identity",
        "consent_ceremony_required",
        "field_ownership_repair",
        "frontier_refresh_required",
        "input_correction_new_identity",
        "operation_pending_inspect",
        "privacy_audit_review",
        "read_timeout_new_identity",
        "recovery_check_then_correct",
        "resource_integrity_repair",
        "service_holder_busy",
        "service_replacement_exhausted",
        "session_rebind_required",
        "sorted_set_required",
        "start_timeout_same_identity",
        "start_busy_same_identity",
        "start_pending_same_identity",
        "storage_root_unsafe",
        "vault_initialization_required",
        "write_timeout_same_identity",
        "coordination_authority_review",
        "coordination_policy_review",
        "coordination_superseded_recheck",
        "cursor_project_preview_review",
        "lineage_attach_review",
        "lineage_integrity_review",
        "lineage_operation_recovery",
        "lineage_service_review",
        "lineage_state_refresh",
        "lineage_successor_task",
        "lineage_terminal_review",
        # Local CLI lifecycle, instance, and ceremony continuations (issue #741). These are
        # reached through ``continuation_for_local_reason`` rather than a reason code, so no
        # producer attaches them to a public error today; they are admitted here because
        # ``yoetz.protocol.recovery`` requires the registry and this set to be equal, which is
        # what keeps a token from ever being admitted onto the wire without a directive behind it.
        "capacity_request_correction",
        "ceremony_refusal_terminal",
        "ceremony_result_invalid",
        "config_correction_required",
        "consent_outcome_unconfirmed",
        "consent_relay_correction",
        "instance_identity_repair",
        "instance_request_correction",
        "local_service_unavailable",
        "local_state_repair",
        "pending_decision_in_flight",
        "pending_decision_refresh",
        "provider_setup_required",
        "vault_unlock_required",
        # Provider / AI-powered review outcomes (issue #742). Resolved at render
        # time from recorded semantic_reason and adapter failure_class; not
        # attached by reason-code map.
        "semantic_capacity_exceeded",
        "semantic_coordinator_review",
        "semantic_privacy_blocked",
        "semantic_credential_rejected",
        "semantic_no_judgment",
        "semantic_rate_limited",
        "semantic_refused",
        "semantic_response_invalid",
        "semantic_response_truncated",
        "semantic_timeout",
        "semantic_transport_retry",
    }
)

# Protocol reason codes whose recovery is fully determined by the reason alone (ADR-030). The map
# lives here, beside the token set it ranges over, because attachment happens where every public
# error is built: ``PublicOperationError`` adds the continuation at construction, so a producer that
# names one of these reasons cannot ship without its directive. ``yoetz.protocol.recovery`` owns the
# directive text and fails at import if a value here is not a registered token. ``request_timeout``
# is deliberately absent: its directive depends on the operation kind and is resolved by the one
# boundary that knows it (``continuation_for_reason``).
REASON_CODE_CONTINUATIONS: Mapping[str, str] = MappingProxyType(
    {
        # A check refused before admission recorded nothing under its request identity, so the
        # exact replay is the recovery; it must never read as a stranded operation (issue #838).
        "check_admission_capture_pending": "check_admission_same_identity",
        "check_admission_contended": "check_admission_same_identity",
        "check_admission_import_pending": "check_admission_same_identity",
        "check_admission_in_progress": "check_admission_same_identity",
        "duplicate_set_member": "sorted_set_required",
        "endpoint_unsafe": "storage_root_unsafe",
        "expected_frontier_required": "frontier_refresh_required",
        "frontier_changed": "frontier_refresh_required",
        "frontier_digest_mismatch": "frontier_refresh_required",
        "operation_recovery_unavailable": "recovery_check_then_correct",
        # Issue #921: a stored privacy receipt could not be read back. The request was valid, so
        # the continuation names the audit, never a correction of the command.
        "privacy_audit_unreadable": "privacy_audit_review",
        # Issue #885: record one concrete attempt, then answer the finding under a new identity.
        "resolution_attempt_required": "input_correction_new_identity",
        # Issue #984: repair and check first, or answer the finding with another disposition,
        # under a new request identity.
        "finding_not_proof_limited": "input_correction_new_identity",
        # Issue #996: name an earlier, readable, unlinked finding, or answer the finding another
        # way, under a new request identity.
        "duplicate_has_duplicates": "input_correction_new_identity",
        "duplicate_link_broken": "input_correction_new_identity",
        "duplicate_target_different_issue": "input_correction_new_identity",
        "duplicate_target_is_duplicate": "input_correction_new_identity",
        "duplicate_target_not_earlier": "input_correction_new_identity",
        "duplicate_target_same_finding": "input_correction_new_identity",
        "duplicate_target_unknown": "input_correction_new_identity",
        "finding_not_rechecked": "input_correction_new_identity",
        "schema_digest_mismatch": "resource_integrity_repair",
        "session_superseded": "session_rebind_required",
        "unsorted_set_field": "sorted_set_required",
        "ambiguous_binding": "lineage_state_refresh",
        "attach_handle_expired": "lineage_attach_review",
        "attach_handle_invalid": "lineage_attach_review",
        "attach_handle_reused": "lineage_attach_review",
        "attach_handle_revoked": "lineage_attach_review",
        "attach_result_invalid": "lineage_integrity_review",
        "child_check_frontier_ahead_of_child": "lineage_integrity_review",
        "child_check_frontier_missing": "lineage_integrity_review",
        "child_check_frontier_without_check": "lineage_integrity_review",
        "child_dependencies_not_canonical": "sorted_set_required",
        "child_dependency_count_invalid": "lineage_integrity_review",
        "child_finding_count_invalid": "lineage_integrity_review",
        "child_findings_not_canonical": "sorted_set_required",
        "child_frontier_missing": "lineage_integrity_review",
        "child_gap_frontier_mismatch": "lineage_integrity_review",
        "coordination_admission_required": "coordination_authority_review",
        "coordination_consent_required": "coordination_authority_review",
        "coordination_declaration_invalid": "lineage_integrity_review",
        "coordination_detection_mismatch": "lineage_state_refresh",
        "coordination_disposition_invalid": "lineage_integrity_review",
        "coordination_evidence_missing": "lineage_integrity_review",
        "coordination_generation_mismatch": "lineage_state_refresh",
        "coordination_generation_revoked": "coordination_authority_review",
        "coordination_generation_superseded": "coordination_superseded_recheck",
        "coordination_grant_required": "coordination_authority_review",
        "coordination_invalid": "lineage_integrity_review",
        "coordination_obligation_conflict": "lineage_state_refresh",
        "coordination_obligation_mismatch": "lineage_state_refresh",
        "coordination_participants_unavailable": "lineage_service_review",
        "coordination_recipient_mismatch": "lineage_state_refresh",
        "coordination_resource_count_invalid": "lineage_integrity_review",
        "coordination_route_unavailable": "lineage_service_review",
        "coordination_runtime_unavailable": "lineage_service_review",
        "coordination_source_policy_denied": "coordination_policy_review",
        "coordination_source_unavailable": "lineage_service_review",
        "coordination_task_pair_invalid": "lineage_integrity_review",
        "coordination_tasks_not_canonical": "sorted_set_required",
        "cross_repository_lineage_requires_grant": "coordination_authority_review",
        "cursor_mcp_route_invalid": "cursor_project_preview_review",
        "cursor_project_mcp_command_invalid": "cursor_project_preview_review",
        "cursor_project_mcp_invalid": "cursor_project_preview_review",
        "cursor_project_mcp_preview_required": "cursor_project_preview_review",
        "finding_actionable_mismatch": "lineage_integrity_review",
        "finding_resolution_mismatch": "lineage_integrity_review",
        "general_project_membership_conflict": "lineage_state_refresh",
        "host_lineage_annotation_invalid": "lineage_integrity_review",
        "implicit_project_requires_opt_out": "lineage_state_refresh",
        "invalid_continuation_expiry": "lineage_integrity_review",
        "invalid_continuation_kind": "lineage_integrity_review",
        "invalid_continuation_pending_id": "lineage_integrity_review",
        "invalid_continuation_repository_setup": "lineage_integrity_review",
        "invalid_continuation_review_input": "lineage_integrity_review",
        "invalid_external_runtime_authority": "coordination_authority_review",
        "invalid_receipt_child_finding": "lineage_integrity_review",
        "invalid_receipt_child_outcome": "lineage_integrity_review",
        "invalid_receipt_children": "lineage_integrity_review",
        "invalid_start_internal_result": "lineage_integrity_review",
        "invalid_workspace_inspect": "lineage_integrity_review",
        "lineage_acceptance_transition": "lineage_state_refresh",
        "lineage_catalog_busy": "lineage_operation_recovery",
        "lineage_catalog_migration_required": "lineage_service_review",
        "lineage_child_missing": "lineage_state_refresh",
        "lineage_child_not_found": "lineage_state_refresh",
        "lineage_close_authority": "coordination_authority_review",
        "lineage_cycle": "lineage_state_refresh",
        "lineage_depth_limit": "lineage_state_refresh",
        "lineage_event_contradiction": "lineage_integrity_review",
        "lineage_event_invalid": "lineage_integrity_review",
        "lineage_event_operation_conflict": "lineage_operation_recovery",
        "lineage_event_operation_pending": "lineage_operation_recovery",
        "lineage_event_result_invalid": "lineage_integrity_review",
        "lineage_fanout_limit": "lineage_state_refresh",
        "lineage_handle_conflict": "lineage_attach_review",
        "lineage_handle_key_invalid": "lineage_integrity_review",
        "lineage_handle_key_unavailable": "lineage_service_review",
        "lineage_handle_missing": "lineage_attach_review",
        "lineage_manifest_stale": "lineage_state_refresh",
        "lineage_operation_conflict": "lineage_operation_recovery",
        "lineage_operation_lease_expired": "lineage_operation_recovery",
        "lineage_operation_not_found": "lineage_state_refresh",
        "lineage_operation_phase": "lineage_integrity_review",
        "lineage_operation_quarantined": "lineage_terminal_review",
        "lineage_parent_not_found": "lineage_state_refresh",
        # The parent's own session is not current; the parent, not a child, reconciles it.
        "lineage_parent_session_invalid": "lineage_state_refresh",
        "lineage_parent_work_terminal": "lineage_successor_task",
        "lineage_phase_transition": "lineage_integrity_review",
        "lineage_repository_mismatch": "lineage_state_refresh",
        "lineage_request_identity_conflict": "lineage_operation_recovery",
        "lineage_reservation_conflict": "lineage_operation_recovery",
        "lineage_resume_work_terminal": "lineage_successor_task",
        "lineage_root_conflict": "lineage_state_refresh",
        "lineage_root_dependency": "lineage_state_refresh",
        "lineage_service_unavailable": "lineage_service_review",
        "lineage_session_conflict": "lineage_state_refresh",
        "lineage_session_not_active": "lineage_state_refresh",
        "lineage_session_not_found": "lineage_state_refresh",
        "lineage_session_scope": "lineage_state_refresh",
        "lineage_task_conflict": "lineage_state_refresh",
        "lineage_task_missing": "lineage_state_refresh",
        "lineage_task_not_found": "lineage_state_refresh",
        "lineage_transition_conflict": "lineage_state_refresh",
        "lineage_work_terminal": "lineage_terminal_review",
        "lineage_work_transition": "lineage_state_refresh",
        "noncanonical_json": "lineage_integrity_review",
        "observation_selection_session_limit": "lineage_state_refresh",
        "opaque_item_id_invalid": "lineage_integrity_review",
        "project_dissolved": "lineage_terminal_review",
        "project_member_already_unbound": "lineage_state_refresh",
        "project_member_not_found": "lineage_state_refresh",
        "project_not_found": "lineage_state_refresh",
        "projection_unavailable": "lineage_service_review",
        "receipt_child_manifest_mismatch": "lineage_integrity_review",
        "receipt_children_not_canonical": "sorted_set_required",
        "receipt_children_schema_version": "lineage_integrity_review",
        "receipt_semantic_withheld_items_not_canonical": "lineage_integrity_review",
        "runtime_opening_authority": "coordination_authority_review",
        "selector_conflict": "lineage_state_refresh",
        "semantic_redacted_values_invalid": "lineage_integrity_review",
        "service_stamp_required": "lineage_service_review",
        "session_lineage_fields_incomplete": "lineage_integrity_review",
        "stored_result_shape_invalid": "lineage_integrity_review",
        "start_busy_retry_ready": "start_busy_same_identity",
        "start_catalog_retry_ready": "start_busy_same_identity",
        "start_runtime_rebind_retry_ready": "start_busy_same_identity",
        "start_lease_pending": "start_pending_same_identity",
    }
)
if set(REASON_CODE_CONTINUATIONS.values()) - ADMITTED_CONTINUATION_TOKENS:
    raise RuntimeError("reason_code_continuation_not_admitted")

_TOKEN_DETAIL_VALUES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "authorize_command": frozenset({"yoetz consent authorize"}),
        "availability": frozenset({"terminal_unavailable"}),
        "continuation": ADMITTED_CONTINUATION_TOKENS,
        "host_profile": frozenset({"generic", "codex", "claude", "cursor"}),
        "prepare_command": frozenset({"yoetz consent prepare vault_initialize"}),
        "review_command": frozenset({"yoetz consent review"}),
        "route_profile": frozenset({"policy", "strict"}),
    }
)
_HEAD_DIGEST_PATTERN = re.compile(r"^(?:genesis|sha256:[0-9a-f]{64})$", re.ASCII)
_ENUM_DETAIL_KEYS = frozenset(
    {"component", "method", "operation", "phase", "state", "status", "view"}
)
_QUARANTINE_CODES = frozenset(
    {
        "operation_event_range_mismatch",
        "operation_kind_state_contradiction",
        "operation_lease_shape_invalid",
        "operation_result_digest_mismatch",
        "operation_resume_object_invalid",
    }
)
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_LOWER_SNAKE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
# A recorded resolution-reason token: a closed reason or ``coverage:<closed gap code>``. Never
# prose; anything else drops the whole detail.
_BLOCKING_REASON_PATTERN = re.compile(r"^(?:coverage:)?[a-z][a-z0-9_]{0,95}$", re.ASCII)
_MAX_BLOCKING_REASONS = 32
_VERSION_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$", re.ASCII)
_SCHEMA_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$", re.ASCII)
_CORRELATION_ID_PATTERN = re.compile(
    r"^err_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.ASCII,
)
_REQUEST_ID_DETAIL_PATTERN = re.compile(
    r"^req_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.ASCII,
)
_PROTOCOL_ID_DETAIL_PATTERNS: Mapping[str, re.Pattern[str]] = MappingProxyType(
    {
        "availability_request_id": _REQUEST_ID_DETAIL_PATTERN,
        "replay_request_id": _REQUEST_ID_DETAIL_PATTERN,
        "session_id": re.compile(
            r"^ses_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.ASCII,
        ),
        "task_id": re.compile(
            r"^tsk_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.ASCII,
        ),
        "writer_id": re.compile(
            r"^wri_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.ASCII,
        ),
    }
)
_EMPTY_SAFE_DETAILS: Mapping[str, SafeDetailValue] = MappingProxyType({})


class ProtocolValueError(ValueError):
    """A bounded internal protocol-value failure."""

    __slots__ = ("field", "reason_code")

    reason_code: str
    field: str | None

    def __init__(self, reason_code: str, *, field: str | None = None) -> None:
        if type(reason_code) is not str or reason_code not in PROTOCOL_REASON_CODES:
            raise ValueError("unregistered_protocol_reason_code")
        if field is not None and type(field) is not str:
            raise ValueError("unregistered_protocol_reason_code")
        self.reason_code = reason_code
        # A hint naming the owning payload field, never a value. Callers that turn this into a
        # public error location must still check it against their own frozen allowlist, so a
        # caller-derived string can never reach a public pointer through this attribute.
        self.field = field
        super().__init__(reason_code)


def _valid_correlation_id(value: object) -> bool:
    return type(value) is str and _CORRELATION_ID_PATTERN.fullmatch(value) is not None


def _valid_json_pointer(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    if len(encoded) > 256 or any(byte < 0x20 or byte > 0x7E for byte in encoded):
        return False
    if not value:
        return True
    if not value.startswith("/"):
        return False
    position = 0
    while True:
        position = value.find("~", position)
        if position < 0:
            return True
        if position + 1 >= len(value) or value[position + 1] not in {"0", "1"}:
            return False
        position += 2


def _normalize_detail(key: str, value: object) -> SafeDetailValue | None:
    if key == "blocking_reasons":
        if type(value) not in {tuple, list}:
            return None
        items = tuple(cast(tuple[object, ...] | list[object], value))
        if not 1 <= len(items) <= _MAX_BLOCKING_REASONS or any(
            type(item) is not str or _BLOCKING_REASON_PATTERN.fullmatch(item) is None
            for item in items
        ):
            return None
        return cast(tuple[str, ...], items)
    if key in _INTEGER_DETAIL_KEYS:
        if type(value) is int and 0 <= value <= _MAX_SAFE_INTEGER:
            return value
        return None
    if key in _BOOLEAN_DETAIL_KEYS:
        return value if type(value) is bool else None
    tokens = _TOKEN_DETAIL_VALUES.get(key)
    if tokens is not None:
        return value if type(value) is str and value in tokens else None
    if key == "reason_code":
        if type(value) is str and value in PROTOCOL_REASON_CODES:
            return value
        return None
    if key == "invariant":
        if type(value) is str and value in ADMITTED_CLAIM_REVISION_INVARIANTS:
            return value
        return None
    if key == "quarantine_code":
        if type(value) is str and value in _QUARANTINE_CODES:
            return value
        return None
    if key == "phase" and type(value) is str:
        # Stage names are structural tokens owned by the service boundary. Accepting the
        # normalized token here lets an internal control failure carry an explicit handler,
        # projection, or unknown stage without exposing exception text.
        if value in {"replay", "model", "digest", "projection", "handler", "unknown"}:
            return value
        return None
    if key in _ENUM_DETAIL_KEYS:
        if issubclass(type(value), Enum):
            enum_value: object = cast(Enum, value).value
            if type(enum_value) is str and _LOWER_SNAKE_PATTERN.fullmatch(enum_value) is not None:
                return enum_value
        return None
    if key in {"actual_version", "expected_version"}:
        if type(value) is str and _VERSION_PATTERN.fullmatch(value) is not None:
            return value
        return None
    if key == "schema_name":
        if (
            type(value) is str
            and len(value) <= 128
            and _SCHEMA_NAME_PATTERN.fullmatch(value) is not None
        ):
            return value
        return None
    if key == "head_digest":
        if type(value) is str and _HEAD_DIGEST_PATTERN.fullmatch(value) is not None:
            return value
        return None
    if key == "field" and _valid_json_pointer(value):
        return cast(str, value)
    pattern = _PROTOCOL_ID_DETAIL_PATTERNS.get(key)
    if pattern is not None:
        if type(value) is str and pattern.fullmatch(value) is not None:
            return value
        return None
    return None


def normalize_safe_details(value: object) -> Mapping[str, SafeDetailValue]:
    """Return an immutable, bounded allowlisted detail mapping."""

    try:
        is_mapping = issubclass(type(value), Mapping)
    except BaseException:
        return _EMPTY_SAFE_DETAILS
    if not is_mapping:
        return _EMPTY_SAFE_DETAILS
    source = cast(Mapping[object, object], value)
    normalized: dict[str, SafeDetailValue] = {}
    for key in SAFE_DETAIL_KEYS:
        try:
            candidate: object = source[key]
            accepted = _normalize_detail(key, candidate)
        except BaseException:
            continue
        if accepted is not None:
            normalized[key] = accepted
    if not normalized:
        return _EMPTY_SAFE_DETAILS
    return MappingProxyType(normalized)


def attach_reason_continuation(
    details: Mapping[str, SafeDetailValue],
) -> Mapping[str, SafeDetailValue]:
    """Attach the continuation a frozen ``reason_code`` determines, when none travels already.

    Every registered reason resolves to the same directive no matter which producer raised it, so
    the attachment is made once here rather than at each raising site (ADR-030). A continuation the
    producer chose explicitly is never overridden: the one boundary that knows more than the reason
    (the MCP bridge for ``request_timeout``) has already said so. Key order stays the documented
    ASCII order of ``SAFE_DETAIL_KEYS``.
    """

    if "continuation" in details:
        return details
    reason = details.get("reason_code")
    token = REASON_CODE_CONTINUATIONS.get(reason) if type(reason) is str else None
    if token is None:
        return details
    merged: dict[str, SafeDetailValue] = dict(details)
    merged["continuation"] = token
    return MappingProxyType({key: merged[key] for key in SAFE_DETAIL_KEYS if key in merged})


def _validate_message(value: object) -> str:
    if type(value) is not str:
        raise ProtocolValueError("public_error_invalid_message")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ProtocolValueError("public_error_invalid_message") from exc
    if not 1 <= len(encoded) <= 4096:
        raise ProtocolValueError("public_error_invalid_message")
    if any(ord(character) <= 0x1F or ord(character) == 0x7F for character in value):
        raise ProtocolValueError("public_error_invalid_message")
    return value


def _validate_public_error_code(value: object) -> PublicErrorCode:
    if type(value) is not PublicErrorCode:
        raise TypeError("public_error_code_wrong_type")
    return value


@dataclass(slots=True, init=False, unsafe_hash=True)
class PublicOperationError(Exception):
    """Immutable public failure fields with normal Python exception propagation.

    ``contextlib`` restores exception tracebacks while unwinding generator context managers.
    Freezing BaseException's runtime attributes would replace the public failure with a
    FrozenInstanceError before the control adapter could render its bounded code.
    """

    code: PublicErrorCode
    message: str
    retryable: bool
    correlation_id: str | None
    safe_details: Mapping[str, SafeDetailValue]

    def __setattr__(self, name: str, value: object) -> None:
        if name in {
            "__traceback__",
            "__context__",
            "__cause__",
            "__suppress_context__",
            "__notes__",
        }:
            Exception.__setattr__(self, name, value)
            return
        raise FrozenInstanceError(f"cannot assign to field {name!r}")

    def __delattr__(self, name: str) -> None:
        if name in {
            "__traceback__",
            "__context__",
            "__cause__",
            "__suppress_context__",
            "__notes__",
        }:
            Exception.__delattr__(self, name)
            return
        raise FrozenInstanceError(f"cannot delete field {name!r}")

    def __init__(
        self,
        code: PublicErrorCode,
        message: str,
        retryable: bool,
        correlation_id: str | None = None,
        safe_details: object | None = None,
    ) -> None:
        validated_code = _validate_public_error_code(code)
        validated_message = _validate_message(message)
        if type(retryable) is not bool:
            raise TypeError("public_error_retryable_wrong_type")
        if correlation_id is not None and not _valid_correlation_id(correlation_id):
            raise ProtocolValueError("public_error_invalid_correlation_id")
        normalized_details = attach_reason_continuation(normalize_safe_details(safe_details))
        object.__setattr__(self, "code", validated_code)
        object.__setattr__(self, "message", validated_message)
        object.__setattr__(self, "retryable", retryable)
        object.__setattr__(self, "correlation_id", correlation_id)
        object.__setattr__(self, "safe_details", normalized_details)
        Exception.__init__(self, validated_message)

    def bind_correlation_id(self, value: str) -> PublicOperationError:
        if not _valid_correlation_id(value):
            raise ProtocolValueError("public_error_invalid_correlation_id")
        if self.correlation_id == value:
            return self
        if self.correlation_id is not None:
            raise ProtocolValueError("public_error_invalid_correlation_id")
        # Copy stored fields verbatim instead of re-running __init__: normalization is not
        # idempotent (enum-keyed details were already collapsed to plain strings, which the
        # enum branch would reject), and binding must change only the correlation ID.
        bound = PublicOperationError.__new__(PublicOperationError)
        object.__setattr__(bound, "code", self.code)
        object.__setattr__(bound, "message", self.message)
        object.__setattr__(bound, "retryable", self.retryable)
        object.__setattr__(bound, "correlation_id", value)
        object.__setattr__(bound, "safe_details", self.safe_details)
        Exception.__init__(bound, self.message)
        return bound

    def as_public_dict(self) -> dict[str, object]:
        if self.correlation_id is None:
            raise ProtocolValueError("public_error_missing_correlation_id")
        result: dict[str, object] = {
            "code": self.code.value,
            "message": self.message,
            "retryable": self.retryable,
            "correlation_id": self.correlation_id,
        }
        if self.safe_details:
            result["safe_details"] = {
                key: list(value) if type(value) is tuple else value
                for key, value in self.safe_details.items()
            }
        return result
