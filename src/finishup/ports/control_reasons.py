"""Lightweight closed control-error vocabulary shared by ports and hook diagnostics."""

from typing import Final

__all__ = ["CONTROL_ERROR_REASONS"]

CONTROL_ERROR_REASONS: Final = frozenset(
    {
        "service_unavailable",
        "service_incompatible",
        "peer_untrusted",
        "protocol_mismatch",
        "frame_invalid",
        "frame_too_large",
        "request_cancelled",
        "request_timeout",
        "vault_locked",
        "service_draining",
        "method_forbidden",
        "internal_error",
        "privacy_projection_unavailable",
        "privacy_projection_blocked",
        "response_projection_failed",
        "read_projection_failed",
        "privacy_audit_unreadable",
        "service_generation_changed",
        "endpoint_unsafe",
        "invalid_request",
        "coordination_invalid",
        "project_not_found",
        "project_dissolved",
        "implicit_project_requires_opt_out",
        "general_project_membership_conflict",
        "project_member_not_found",
        "selector_conflict",
        "coordination_consent_required",
        "coordination_source_policy_denied",
        "coordination_grant_required",
        "coordination_generation_revoked",
        "coordination_generation_mismatch",
        "cross_repository_lineage_requires_grant",
        "project_member_already_unbound",
    }
)
