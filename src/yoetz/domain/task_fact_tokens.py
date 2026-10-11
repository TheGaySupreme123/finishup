"""Plain-string task-fact gap tokens and the Stop-gate token set (ADR-033, ADR-045).

Dependency-free on purpose: the ordinary hook path (``yoetz.cli.closure_gate``) needs these
literals and must not import pydantic or the protocol models to get them. ``yoetz.kernel.task_facts``
re-exports every name, so the old import location keeps working.
"""

from __future__ import annotations

from typing import Final

# The readiness token raised for an ``awaiting_ruling`` finding (agent-actionable: a recorded
# action clears it). Frozen here so the Stop gate, status and the check agree on the literal.
FINDING_REJECTION_AWAITING_RULING_GAP: Final = "finding_rejection_awaiting_ruling"

__all__ = [
    "AGENT_ACTIONABLE_TASK_FACT_GAPS",
    "DECLARED_OUTPUT_CONTENT_MOVED_GAP",
    "DECLARED_OUTPUT_EMPTIED_GAP",
    "DECLARED_OUTPUT_NOT_REVIEWABLE_GAP",
    "DECLARED_OUTPUT_REMOVED_GAP",
    "DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP",
    "EDITED_AFTER_LAST_VERIFICATION_GAP",
    "FINDING_REJECTION_AWAITING_RULING_GAP",
    "INSTALL_INTO_PRIVATE_ENV_GAP",
    "INSTALL_INTO_YOETZ_RUNTIME_GAP",
    "OBLIGATION_BLOCKED_GAP",
    "OBLIGATION_BLOCKER_UNCONFIRMED_GAP",
    "PLANNED_VERIFICATION_AGENT_LINKED_GAP",
    "PLANNED_VERIFICATION_FAILED_GAP",
    "PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP",
    "PLANNED_VERIFICATION_NOT_OBSERVED_GAP",
    "PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP",
    "PLANNED_VERIFICATION_STALE_GAP",
    "PLANNED_VERIFICATION_UNOBSERVABLE_GAP",
    "REQUESTED_OUTPUT_GIT_IGNORED_GAP",
    "REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP",
    "REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP",
    "REQUESTED_OUTPUT_UNCHANGED_GAP",
    "REQUESTED_OUTPUT_UNVERIFIED_GAP",
    "STANDING_TASK_FACT_GAPS",
    "STOP_GATE_TOKENS",
    "TASK_FACT_GAPS",
    "VERIFICATION_ONLY_AS_ROOT_GAP",
    "WRITE_OUTSIDE_WORKSPACE_GAP",
]

PLANNED_VERIFICATION_NOT_OBSERVED_GAP: Final = "planned_verification_not_observed"
PLANNED_VERIFICATION_FAILED_GAP: Final = "planned_verification_failed"
PLANNED_VERIFICATION_STALE_GAP: Final = "planned_verification_stale"
PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP: Final = "planned_verification_outcome_unknown"
PLANNED_VERIFICATION_UNOBSERVABLE_GAP: Final = "planned_verification_unobservable"
PLANNED_VERIFICATION_AGENT_LINKED_GAP: Final = "planned_verification_agent_linked"
# ADR-045: a planned command matched an observed run only by its leading arguments or by its
# program and flags (the run did the planned work and more, or in another order). It counts as
# run, and is disclosed: Yoetz cannot tell whether that is what the plan meant.
PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP: Final = "planned_verification_matched_by_prefix"
EDITED_AFTER_LAST_VERIFICATION_GAP: Final = "edited_after_last_verification"
INSTALL_INTO_YOETZ_RUNTIME_GAP: Final = "install_into_yoetz_runtime"
INSTALL_INTO_PRIVATE_ENV_GAP: Final = "install_into_private_env"
WRITE_OUTSIDE_WORKSPACE_GAP: Final = "write_outside_workspace"
VERIFICATION_ONLY_AS_ROOT_GAP: Final = "verification_only_as_root"
OBLIGATION_BLOCKED_GAP: Final = "obligation_blocked_outside_agent_control"
# A recorded blocker the agent has not yet confirmed in a later decision (#985): still agent work.
OBLIGATION_BLOCKER_UNCONFIRMED_GAP: Final = "obligation_blocker_unconfirmed"
REQUESTED_OUTPUT_GIT_IGNORED_GAP: Final = "requested_output_git_ignored"
REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP: Final = "requested_output_ignored_by_repository"
REQUESTED_OUTPUT_UNCHANGED_GAP: Final = "requested_output_unchanged"
REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP: Final = "requested_output_outside_workspace"
REQUESTED_OUTPUT_UNVERIFIED_GAP: Final = "requested_output_unverified"
# A declared deliverable deleted or renamed away (ADR-035; computed in ``kernel.delivered_set``).
DECLARED_OUTPUT_REMOVED_GAP: Final = "declared_output_removed"
# Content that left a declared deliverable for an undeclared file in the same change (ADR-035):
# a non-blocking disclosure, never a Stop-gate token.
DECLARED_OUTPUT_CONTENT_MOVED_GAP: Final = "declared_output_content_moved"
# A declared deliverable of a resolved or completion-claimed obligation that is now empty or
# truncated (tb4n2 R2, ADR-035 amendment): agent work, and a Stop-gate token. While it stands the
# obligation's recorded ``resolved`` is not counted as delivered.
DECLARED_OUTPUT_EMPTIED_GAP: Final = "declared_output_emptied"
# A declared deliverable is a type the review packet never carries (binary by Git's NUL sniff, or
# an unlisted file with a binary suffix) and a review ran (ADR-045): the deliverable was present
# but not reviewed. A standing disclosure, named on status and on the receipt; never agent work.
DECLARED_OUTPUT_NOT_REVIEWABLE_GAP: Final = "declared_output_not_reviewable"
# A declared deliverable that names an existing workspace file that is neither a declared output
# nor a declared input (tb4n2 R2, ADR-035 amendment): a non-blocking disclosure only.
DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP: Final = "deliverable_references_undeclared_file"

# Facts the agent removes by its own action: run the planned verification after the last edit
# (or correct the requested item to the command it runs), or stop excluding a requested output.
AGENT_ACTIONABLE_TASK_FACT_GAPS: Final = frozenset(
    {
        PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
        PLANNED_VERIFICATION_FAILED_GAP,
        PLANNED_VERIFICATION_STALE_GAP,
        EDITED_AFTER_LAST_VERIFICATION_GAP,
        REQUESTED_OUTPUT_GIT_IGNORED_GAP,
        DECLARED_OUTPUT_REMOVED_GAP,
        DECLARED_OUTPUT_EMPTIED_GAP,
        # A claimed blocker: repair the obligation, or confirm the blocker in a later decision.
        OBLIGATION_BLOCKER_UNCONFIRMED_GAP,
    }
)
# Disclosures: recorded history (an install or write already happened), a heuristic the
# observer cannot confirm, a read Yoetz could not make, or a confirmed declared blocker.
STANDING_TASK_FACT_GAPS: Final = frozenset(
    {
        PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP,
        PLANNED_VERIFICATION_UNOBSERVABLE_GAP,
        # A planned command matched only through the agent's own link to an observed run: an
        # agent-asserted equivalence Yoetz cannot verify; the observed outcome still decides.
        PLANNED_VERIFICATION_AGENT_LINKED_GAP,
        PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP,
        INSTALL_INTO_YOETZ_RUNTIME_GAP,
        INSTALL_INTO_PRIVATE_ENV_GAP,
        WRITE_OUTSIDE_WORKSPACE_GAP,
        VERIFICATION_ONLY_AS_ROOT_GAP,
        OBLIGATION_BLOCKED_GAP,
        REQUESTED_OUTPUT_UNCHANGED_GAP,
        REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,
        REQUESTED_OUTPUT_UNVERIFIED_GAP,
        REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,
        DECLARED_OUTPUT_CONTENT_MOVED_GAP,
        DECLARED_OUTPUT_NOT_REVIEWABLE_GAP,
        DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP,
    }
)
TASK_FACT_GAPS: Final = AGENT_ACTIONABLE_TASK_FACT_GAPS | STANDING_TASK_FACT_GAPS
# The closure-readiness items that make the Stop-time gate continue the agent once: work the
# agent owes (open obligations, a receipt-blocking finding) and the task facts it can repair.
STOP_GATE_TOKENS: Final = (
    "obligations_open",
    "receipt_findings_unresolved",
    # A finding the agent rejected with a reason that awaits the reviewer's ruling (tb4n3 RC-8):
    # the gate tells the agent to run the closing review, never to acknowledge what it disputes.
    FINDING_REJECTION_AWAITING_RULING_GAP,
    # The closing AI-powered review the closure checklist requires after the last material change.
    "closing_review_required",
    PLANNED_VERIFICATION_FAILED_GAP,
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    PLANNED_VERIFICATION_STALE_GAP,
    # The work changed after the last verification-class run (tb4n2 P1-4b, ADR-042): only
    # deliverable or workspace edits count, never scratch or Yoetz-owned writes.
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    REQUESTED_OUTPUT_GIT_IGNORED_GAP,
    DECLARED_OUTPUT_REMOVED_GAP,
    DECLARED_OUTPUT_EMPTIED_GAP,
    # A blocker claimed on an open obligation and not yet confirmed (#985).
    OBLIGATION_BLOCKER_UNCONFIRMED_GAP,
)
