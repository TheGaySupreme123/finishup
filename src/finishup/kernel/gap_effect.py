"""One table of what a gap code does to a receipt (tb4n3 RC-3, issue #1026, ADR-046).

Before this module about a dozen places answered "does this gap still bound closure?" with their
own rule: closure readiness (``GAP_CLASSIFICATION``), the clean-compatible lists, the receipt's
ad-hoc advisory sets, the deterministic scope, the proof-tolerance sets. They disagreed. This table
is the one answer. Each of the 223 gap codes the product can emit has exactly one row, and a row
says two separate things:

* ``readiness`` - who owes the next move, from the closed ADR-032 vocabulary: ``A`` (an agent
  action removes it), ``S`` (no agent action removes it), ``R`` (route dependent) or, since
  issue #1209, ``F`` (fix or decline: an agent action removes it, or the agent declines it with a
  recorded reason; never a blocker, and disclosed on the receipt while it stands).
* the *effect* on the receipt, per route: ``A`` actionable, ``B`` standing and bounding, ``D``
  disclosed (listed, never bounds the conclusion), or a context rule (``D*`` a FinishUP review-packet
  budget, ``R`` the review-route rule, ``X`` the later-material rule, ``G`` the host-observation
  guard). ``d_route`` applies when the applicable check recorded that its route did not require
  AI-powered review; ``review_route`` otherwise (and whenever no check applies, the conservative
  default).

``gap_effect(marker, ctx)`` resolves a row against a ``GapContext`` and returns a ``GapEffect``
carrying the rule id and a closed ``why`` key (lineage: the agent-facing text says why a gap bounds
or is only disclosed). A code the build does not know stays ``unclassified_gap:<code>`` and
actionable, so a missing row is visible instead of silently masked.

The module is a leaf: it imports nothing from FinishUP, so ``closure_readiness``,
``deterministic_scope``, ``self_verification`` and the receipt builder can all import it. Tests
assert that the codes agree with the task-fact, plan-drift and proof-tolerance sets that own them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final

__all__ = [
    "GAP_EFFECT_TABLE",
    "GAP_EFFECT_WHY",
    "PROOF_TOLERATED_GAPS",
    "UNCLASSIFIED_GAP_PREFIX",
    "GapClass",
    "GapContext",
    "GapEffect",
    "GapEffectKind",
    "GapRow",
    "gap_base_code",
    "gap_effect",
    "judge_gaps",
    "unclassified_marker",
]

UNCLASSIFIED_GAP_PREFIX: Final = "unclassified_gap:"
_CODE_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)
# Markers that wrap a base code in a named envelope: ``coverage:<code>`` (finding resolution),
# ``check_coverage:<code>``, ``retained_finding_coverage:<code>``, ``semantic_outcome:<code>``
# (receipt case gaps) and ``lineage:<code>:<child>:<event>`` (receipt lineage gaps). Every other
# ``<code>:<subject...>`` marker (``unknown_event:``, ``missing_ref:``, ``redacted_event:``,
# ``completion_scope_undeclared:<event>``) already leads with its base code.
_WRAPPER_PREFIXES: Final = frozenset(
    {"check_coverage", "coverage", "lineage", "retained_finding_coverage", "semantic_outcome"}
)


class GapClass(str, Enum):  # noqa: UP042 - exact internal contract token
    """Who owes the next move (the ADR-032 readiness group); the status wire value."""

    AGENT_ACTIONABLE = "agent_actionable"
    STANDING_LIMITATION = "standing_limitation"
    ROUTE_DEPENDENT = "route_dependent"
    # Issue #1209 (ADR-032 amendment): a limitation the agent can remove but is not required to.
    # Non-blocking like a standing limitation (ADR-033 D1), disclosed on the receipt while it
    # stands, and named to the agent as "fix, or decline with a reason" before the receipt.
    FIX_OR_DECLINE = "fix_or_decline"


class GapEffectKind(str, Enum):  # noqa: UP042 - exact internal contract token
    """What a gap does to the receipt conclusion."""

    ACTIONABLE = "actionable"
    STANDING_BOUNDING = "standing_bounding"
    DISCLOSED = "disclosed"
    HISTORICAL = "historical"

    @property
    def bounds(self) -> bool:
        """True when the gap keeps the receipt below ``no_unresolved_deterministic_findings``."""

        return self in {GapEffectKind.ACTIONABLE, GapEffectKind.STANDING_BOUNDING}


@dataclass(frozen=True, slots=True)
class GapContext:
    """The facts a context-dependent row needs; every default is the conservative answer.

    ``route_requires_review`` is false only when the applicable check recorded
    ``semantic_route_required: false`` (an absent field keeps the missing review blocking).
    ``review_required`` is the serving route's own answer (policy requires AI-powered review and
    the route can dispatch it); it makes ``semantic_review_not_requested`` actionable while no
    review is ``review_current``. ``earlier_frontier_bounds`` is
    ``CheckStanding.bounds_conclusion``: a later record FinishUP cannot prove harmless is an
    observation. ``check_carried`` is the applicable check's ``known_gaps`` and
    ``commands_complete`` its counters showing no unknown or live-failed command.
    ``freshness_advisory`` says freshness is AI-advisory for this receipt (#1143): the applicable
    check's recorded route required review, or a review was used before it
    (``closure_readiness.freshness_review_used``), the predicate the check and readiness use.
    """

    route_requires_review: bool = True
    review_required: bool = False
    review_current: bool = False
    review_succeeded: bool = False
    reviewer_reported_insufficiency: bool = False
    check_carried: frozenset[str] = frozenset()
    commands_complete: bool = True
    earlier_frontier_bounds: bool = True
    historical: frozenset[str] = frozenset()
    freshness_advisory: bool = False


@dataclass(frozen=True, slots=True)
class GapRow:
    """One code's row: readiness group, per-route effect spec, rule id, closed ``why`` key."""

    code: str
    readiness: GapClass
    d_route: str
    review_route: str
    rule: str
    why: str
    changed: bool


@dataclass(frozen=True, slots=True)
class GapEffect:
    """The resolved effect of one gap marker (lineage: ``rule`` and ``why`` say why)."""

    code: str
    kind: GapEffectKind
    readiness_group: GapClass
    rule: str
    why: str


@dataclass(frozen=True, slots=True)
class _Family:
    rule: str
    family: str
    readiness: str
    d_route: str
    review_route: str
    changed: bool
    codes: tuple[str, ...]


# Closed sentences for each ``why`` key (ASCII). Surfaces that explain a bound or a disclosure
# render these; they never invent a second explanation.
GAP_EFFECT_WHY: Final[Mapping[str, str]] = MappingProxyType(
    {
        "agent_actionable": "an agent action removes it",
        "completion_scope": "the completion scope is not declared, which bounds completion itself",
        "route": "AI-powered review was not requested on a route that did not require it",
        "suffix": "records after the check that FinishUP cannot prove harmless",
        "host_guarded": "a host observation gap the applicable check itself carried",
        "disclosure": "recorded history, a deliberate selection or an informational fact",
        "fix_or_decline": (
            "a limit an agent action removes; the agent fixes it or declines it with a reason"
        ),
        "finishup_review_budget": "FinishUP's own review-packet size budget; no agent action clears it",
        "finishup_advice_pipeline": "the background advice pipeline's own bound; not an agent task",
        "finishup_detail_bound": "FinishUP's own summarisation bound on routine reads or listings",
        "review_dialogue_disclosure": "the prior-findings section's own bound, no weaker than before it",
        "privacy_redaction": "an owner privacy choice or placeholder redaction",
        "finishup_review_call": "FinishUP's own quote-proof fence rejected a reviewer quote",
        "review_completeness": "the AI-powered review saw less than it needed or did not complete",
        "pipeline_or_consent_loss": "events, payloads, objects or consent that could not be read",
        "capture_limit": "capture clipped or skipped content a rule or the reviewer may have needed",
        "misc_standing": "a standing limit with no safe reason to relax it",
        "evidence_strength": "agent-supplied evidence that FinishUP could only see by digest",
        "command_identity": "an attempt the agent asserted that FinishUP could not match to an observed run",
        "import_stream": "the imported source stream held less than the work",
        "lineage": "child-task facts the parent cannot change",
        "readiness_only": "synthesized by readiness from finding or obligation classes",
        "test_edit_unknown": "an unreadable baseline can hide an unjustified test edit",
        "unclassified": "a code this build does not know; treated as actionable",
    }
)

_FAMILIES: Final[tuple[_Family, ...]] = (
    _Family(
        rule="G13",
        family="readiness_only",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=True,
        codes=("unresolved_verification_limitation",),
    ),
    _Family(
        rule="G0",
        family="agent_actionable",
        readiness="A",
        d_route="A",
        review_route="A",
        changed=False,
        codes=(
            "check_in_progress",
            "check_not_applicable",
            "check_not_recorded",
            "closing_review_required",
            "command_attempt_mismatch",
            "completion_claim_outside_plan",
            "completion_plan_not_claimed",
            "completion_scope_undeclared",
            "declared_output_emptied",
            "declared_output_removed",
            "instruction_requirement_unmapped",
            "lineage_child_actionable_finding",
            "lineage_child_check_stale",
            "lineage_child_incomplete",
            "lineage_child_open",
            "lineage_child_verification_unknown",
            "lineage_manifest_not_recorded",
            "lineage_manifest_state_changed",
            "lineage_manifest_uncovered",
            "lineage_readiness_unavailable",
            "missing_ref",
            "obligation_blocker_unconfirmed",
            "planned_verification_failed",
            "planned_verification_not_observed",
            "preexisting_test_edit_unjustified",
            "requested_output_git_ignored",
            "task_statement_not_supplied",
        ),
    ),
    _Family(
        rule="G0",
        family="agent_actionable",
        readiness="A",
        d_route="A",
        review_route="A",
        changed=False,
        codes=("semantic_missing_agent_suppliable",),
    ),
    _Family(
        rule="G0f",
        family="agent_actionable",
        readiness="A",
        d_route="A",
        review_route="V",
        changed=True,
        codes=("edited_after_last_verification", "planned_verification_stale"),
    ),
    # tb4n4 (issue #1044): a delivered file that loads a file the change created and nothing
    # declares fails where the grader receives only the declared files (interleaved-vigenere S).
    # Before, a standing disclosure the agent could "resolve" by disclosing the dependency; now an
    # agent action (embed, rebuild at run time, declare) removes it and nothing else does.
    _Family(
        rule="G0c",
        family="agent_actionable",
        readiness="A",
        d_route="A",
        review_route="A",
        changed=True,
        codes=("deliverable_references_undeclared_file",),
    ),
    _Family(
        rule="G0b",
        family="completion_scope",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=("completion_scope_declared_none",),
    ),
    _Family(
        rule="G1",
        family="route",
        readiness="R",
        d_route="R",
        review_route="R",
        changed=True,
        codes=("semantic_review_not_requested",),
    ),
    _Family(
        rule="G2",
        family="suffix",
        readiness="S",
        d_route="X",
        review_route="X",
        changed=True,
        codes=("check_current_as_of_earlier_frontier",),
    ),
    _Family(
        rule="G3",
        family="host_guarded",
        readiness="S",
        d_route="G",
        review_route="G",
        changed=False,
        codes=(
            "captured_object_unavailable",
            "host_outcome_unavailable",
            "unpaired_event",
        ),
    ),
    _Family(
        rule="G3",
        family="host_guarded",
        readiness="S",
        d_route="G",
        review_route="G",
        changed=True,
        codes=("compound_outcome_unavailable",),
    ),
    _Family(
        rule="G4",
        family="disclosure",
        readiness="S",
        d_route="D",
        review_route="D",
        changed=False,
        codes=(
            "capture_handoff_retired",
            "content_redacted",
            "content_unselected",
            "declared_output_content_moved",
            "declared_output_not_reviewable",
            "install_into_private_env",
            # Frozen legacy identifier (ADR-048): recorded gap code.
            "install_into_yoetz_runtime",
            "obligation_blocked_outside_agent_control",
            "obligation_evidence_stale_after_scope_edit",
            "plan_unrefined_before_first_edit",
            "planned_verification_matched_by_prefix",
            "planned_verification_unobservable",
            "preexisting_test_deleted",
            "preexisting_test_modified",
            "preexisting_test_renamed",
            "preexisting_test_skipped",
            "requested_output_ignored_by_repository",
            "requested_output_outside_workspace",
            "requested_output_unverified",
            "verification_only_as_root",
            "write_outside_workspace",
        ),
    ),
    # Issue #1209 (ADR-032 amendment): disclosures an agent action removes. A requested file the
    # record says was written is unchanged from the task base; a planned verification was matched
    # only through the agent's own link; a planned verification's run had a host-stated outcome
    # that does not establish the planned part's (a composed command). Their receipt effect is the
    # G4 one (disclosed, never bounding), so the receipt conclusion is unchanged; only who owes the
    # next move changes: the agent fixes each one or declines it with a recorded reason, and none
    # is ever a Stop-gate item (ADR-033 D1). ``planned_verification_outcome_unknown`` is named to
    # the agent only where the host stated the run's outcome (``TaskFactSignals.fix_or_decline``);
    # where the host stated none it stays a plain disclosure.
    _Family(
        rule="G4f",
        family="fix_or_decline",
        readiness="F",
        d_route="D",
        review_route="D",
        changed=False,
        codes=(
            "planned_verification_agent_linked",
            "planned_verification_outcome_unknown",
            "requested_output_unchanged",
        ),
    ),
    _Family(
        rule="G5",
        family="finishup_review_budget",
        readiness="S",
        d_route="D",
        review_route="D*",
        changed=True,
        codes=(
            "check_time_change_truncated",
            "check_time_change_unavailable_no_packet_room",
            "semantic_case_capacity_exceeded",
            "semantic_case_content_over_item_limit",
            "semantic_case_finding_refs_over_limit",
            "semantic_included_refs_not_recorded",
            "semantic_reference_scope_reduced",
            "semantic_review_refs_reduced",
        ),
    ),
    _Family(
        rule="G5b",
        family="finishup_advice_pipeline",
        readiness="S",
        d_route="D",
        review_route="D",
        changed=True,
        codes=(
            "advice_coverage_gaps_truncated",
            "advice_evidence_refs_truncated",
            "advice_ranked_findings_truncated",
            "advice_semantic_deferred",
            "advice_semantic_output_invalid",
            "advice_semantic_pending",
            "advice_semantic_preview_required",
            "advice_semantic_text_truncated",
            "advice_semantic_unavailable",
            "observation_qualified_partial",
        ),
    ),
    _Family(
        rule="G5c",
        family="finishup_detail_bound",
        readiness="S",
        d_route="D",
        review_route="D",
        changed=True,
        codes=(
            "details_truncated",
            "optional_observation_detail_omitted",
            "routine_read_detail_omitted",
            "routine_read_summary_invalid",
            "routine_summary_invalid",
        ),
    ),
    _Family(
        rule="G5d",
        family="review_dialogue_disclosure",
        readiness="S",
        d_route="D",
        review_route="D",
        changed=True,
        codes=(
            "semantic_prior_findings_over_limit",
            "semantic_prior_verdicts_unsupported",
            "semantic_restatements_suppressed",
        ),
    ),
    # tb4n5 (the #1044 follow-up, ADR-035 amendment): created files a delivered file names only by
    # an ambiguous file name, counted (never named) on the receipt. A new code, disclosed from the
    # start: the bound the syntactic dependency read leaves open, never agent work.
    _Family(
        rule="G4b",
        family="disclosure",
        readiness="S",
        d_route="D",
        review_route="D",
        changed=True,
        codes=("deliverable_references_ambiguous_name",),
    ),
    # Issue #1042: reviewer challenges calling work "never attempted" during a routine review, or
    # about FinishUP's own capture or process state. A new code, disclosed from the start: it records what
    # the check declined to mint, never a limit on what the review saw.
    _Family(
        rule="G5d",
        family="review_dialogue_disclosure",
        readiness="S",
        d_route="D",
        review_route="D",
        changed=True,
        codes=("semantic_process_state_filtered",),
    ),
    # Issue #1102 (RC6f): the task names an input outside the workspace that no root the owner
    # admitted covers. A new code, disclosed from the start: the reviewer judged without it, and
    # only the owner's trusted-terminal ceremony admits a root, so it is never agent work, never a
    # Stop-gate item and never bounds the conclusion beyond what the review itself reports.
    # #1143 (PR #1167 review): verification freshness held only because the caller asserted its
    # per-run input declaration complete. An agent assertion, disclosed from the start: never
    # agent work, never a Stop-gate item and never proof that the check read nothing else.
    _Family(
        rule="G4d",
        family="disclosure",
        readiness="S",
        d_route="D",
        review_route="D",
        changed=True,
        codes=("verification_inputs_caller_asserted",),
    ),
    _Family(
        rule="G4c",
        family="disclosure",
        readiness="S",
        d_route="D",
        review_route="D",
        changed=True,
        codes=(
            "task_input_baseline_unavailable",
            "task_input_outside_not_admitted",
            "verification_input_directory_unresolved",
        ),
    ),
    _Family(
        rule="G6",
        family="privacy_redaction",
        readiness="S",
        d_route="D",
        review_route="D",
        changed=True,
        codes=(
            "semantic_review_credential_heuristic_disabled",
            "semantic_review_value_redacted",
        ),
    ),
    _Family(
        rule="G6",
        family="finishup_review_call",
        readiness="S",
        d_route="D",
        review_route="D",
        changed=True,
        codes=("semantic_review_snippet_invalid",),
    ),
    _Family(
        rule="G7",
        family="review_completeness",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=(
            "check_time_change_base_unavailable",
            "check_time_change_path_unrepresentable",
            "check_time_change_redacted",
            "check_time_change_resolution_unverified",
            "check_time_change_unavailable",
            "check_time_change_unavailable_capture_failed",
            "check_time_change_unavailable_changed_during_capture",
            "check_time_change_unavailable_git_failed",
            "check_time_change_unavailable_git_unavailable",
            "check_time_change_unavailable_git_version_unsupported",
            "check_time_change_unavailable_no_linked_subject",
            "check_time_change_unavailable_not_git",
            "check_time_change_unavailable_redaction_incomplete",
            "check_time_change_unavailable_repository_mismatch",
            "check_time_change_unavailable_unsafe_root",
            "check_time_change_unavailable_unsupported_repository",
        ),
    ),
    _Family(
        rule="G7",
        family="review_completeness",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=(
            "semantic_challenges_rejected",
            "semantic_missing_already_supplied",
            "semantic_missing_items_rejected",
            "semantic_missing_non_convergent",
            "semantic_missing_structurally_unavailable",
            # Frozen legacy identifier (ADR-048): recorded gap code.
            "semantic_missing_yoetz_limit",
            "semantic_packet_insufficient",
            "semantic_provider_input_manifest_invalid",
            "semantic_provider_input_manifest_mismatch",
            "semantic_provider_input_manifest_missing",
            "semantic_provider_input_manifest_parse_failed",
            "semantic_provider_input_manifest_recovery_failed",
            "semantic_review_context_withheld",
            "semantic_review_item_withheld",
            "semantic_review_skipped_insufficient_packet",
            "semantic_review_skipped_privacy_block",
            "task_statement_not_authorized",
            "task_statement_unavailable",
        ),
    ),
    _Family(
        rule="G7",
        family="review_completeness",
        readiness="S",
        d_route="D",
        review_route="B",
        changed=True,
        codes=(
            "optional_semantic_review_blocked_by_policy",
            "optional_semantic_review_registration_drift",
            "semantic_relevance_review_not_run",
            "semantic_review_not_configured",
        ),
    ),
    # tb4n4 (issue #1046, review): FinishUP's own deferral of a routine review before the first
    # material edit. Where the deferred check recorded that its route did not require review it is
    # a disclosure, like the ``semantic_review_not_requested`` it rides with (rule G1): a check the
    # agent asked to review must not read worse than a ``deterministic_only`` one on the same
    # route. Where the route requires review it bounds until a review is current.
    _Family(
        rule="G7",
        family="review_completeness",
        readiness="S",
        d_route="D",
        review_route="B",
        changed=True,
        codes=("semantic_review_deferred_before_first_edit",),
    ),
    _Family(
        rule="G8",
        family="pipeline_or_consent_loss",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=(
            "consent_missing",
            "consent_revoked",
            "cursor_stale",
            "dedup_conflict",
            "drain_diagnostic_unavailable",
            "event_payload_unavailable",
            "ledger_rejected",
            "mapping_missing",
            "missing_subagent_identity",
            "not_observable",
            "observation_input_loss",
            "observation_storage_corrupt",
            "outbox_overflow",
            "outbox_quarantined",
            "pending_attempt_expired",
            "pending_attempt_limit",
            "project_member_unavailable",
            "quarantine_detail_evicted",
            "redacted_event",
            "redacted_object",
            "revoked",
            "service_unavailable",
            "session_superseded",
            "source_lag",
            "source_unavailable",
            "unknown_event",
            "unknown_event_schema_preserved",
            "unsupported_event",
            "unsupported_format",
            "vault_locked",
        ),
    ),
    _Family(
        rule="G8b",
        family="capture_limit",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=(
            "capture_budget_exhausted",
            "content_capture_profile_mismatch",
            "content_capture_unavailable",
            "payload_content_omitted",
            "payload_too_large",
            "truncated_payload",
        ),
    ),
    _Family(
        rule="G8c",
        family="misc_standing",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=(
            "check_payload_unavailable",
            "network_check_unsupported",
            "policy_untrusted",
            "selection_route_changed",
            "verification_stale",
            "verification_rerun_question",
        ),
    ),
    _Family(
        rule="G9",
        family="evidence_strength",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=(
            "evidence_content_digest_only",
            "evidence_content_withheld",
            "evidence_digest_subject_legacy_unknown",
        ),
    ),
    _Family(
        rule="G10",
        family="command_identity",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=("command_attempt_uncorroborated",),
    ),
    _Family(
        rule="G11",
        family="import_stream",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=(
            "command_declined_not_executed",
            "command_outcome_incomplete",
            "file_content_not_captured",
            "final_newline_absent",
            "human_import_scope_not_universal",
            "import_source_range_not_universal",
            "item_shape_unsupported",
            "item_transition_invalid",
            "json_profile_unsupported",
            "line_oversized",
            "malformed_line",
            "result_outcome_incomplete",
            "source_category_not_mapped",
            "source_line_unmapped",
            "source_text_not_represented",
            "source_timestamp_unavailable",
            "truncated_final_line",
            "unknown_item_type",
            "unknown_wrapper_type",
            "unsupported_codex_profile",
            "web_results_not_captured",
            "wrapper_shape_unsupported",
        ),
    ),
    _Family(
        rule="G12",
        family="lineage",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=(
            "lineage_child_check_frontier_unknown",
            "lineage_child_coverage_gap",
            "lineage_child_frontier_unknown",
            "lineage_child_provenance_restricted",
            "lineage_child_read_gap",
            "lineage_child_unavailable",
            "lineage_invalid_acceptance_transition",
            "lineage_manifest_missing",
            "lineage_manifest_not_authorized",
            "lineage_manifest_quarantined",
            "lineage_manifest_revoked",
            "lineage_manifest_unknown",
            "lineage_manifest_unreadable",
        ),
    ),
    _Family(
        rule="G13",
        family="readiness_only",
        readiness="S",
        d_route="D",
        review_route="D",
        changed=False,
        codes=(
            "assumption_disclosed",
            "verification_limit_disclosed",
        ),
    ),
    _Family(
        rule="G13",
        family="readiness_only",
        readiness="A",
        d_route="A",
        review_route="A",
        changed=False,
        codes=("finding_rejection_awaiting_ruling",),
    ),
    _Family(
        rule="G13",
        family="readiness_only",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=(
            "finding_disputed_after_rebuttal",
            "finding_limitation_disclosed",
            "finding_premise_disputed",
            "finding_rejection_unreviewable",
            "finding_self_verified",
        ),
    ),
    _Family(
        rule="G15",
        family="test_edit_unknown",
        readiness="S",
        d_route="B",
        review_route="B",
        changed=False,
        codes=(
            "preexisting_test_baseline_unknown",
            "preexisting_test_skip_unknown",
        ),
    ),
)

_READINESS: Final[Mapping[str, GapClass]] = MappingProxyType(
    {
        "A": GapClass.AGENT_ACTIONABLE,
        "S": GapClass.STANDING_LIMITATION,
        "R": GapClass.ROUTE_DEPENDENT,
        "F": GapClass.FIX_OR_DECLINE,
    }
)
_SPECS: Final = frozenset({"A", "B", "D", "D*", "R", "X", "G", "V"})


def _build() -> Mapping[str, GapRow]:
    rows: dict[str, GapRow] = {}
    for family in _FAMILIES:
        if family.d_route not in _SPECS or family.review_route not in _SPECS:
            raise ValueError("gap_effect_spec_invalid")
        if family.family not in GAP_EFFECT_WHY:
            raise ValueError("gap_effect_why_missing")
        for code in family.codes:
            if code in rows or _CODE_RE.fullmatch(code) is None:
                raise ValueError("gap_effect_table_invalid")
            rows[code] = GapRow(
                code,
                _READINESS[family.readiness],
                family.d_route,
                family.review_route,
                family.rule,
                family.family,
                family.changed,
            )
    return MappingProxyType(dict(sorted(rows.items())))


GAP_EFFECT_TABLE: Final[Mapping[str, GapRow]] = _build()
if [
    code for code, row in GAP_EFFECT_TABLE.items() if row.readiness is GapClass.ROUTE_DEPENDENT
] != [
    "semantic_review_not_requested"
]:  # pragma: no cover - the route rule is defined for exactly one code
    raise ValueError("gap_effect_route_rule_invalid")

# The codes a later check may prove a finding absent despite (deterministic proof tolerance,
# ``finding_resolution.DETERMINISTIC_PROOF_TOLERATED_GAPS``). Carried here so this table is the
# one place that lists a code's properties; a conformance test asserts it equals that set, so there
# is no third table to drift.
PROOF_TOLERATED_GAPS: Final = frozenset(
    {
        "verification_rerun_question",
        "capture_handoff_retired",
        "captured_object_unavailable",
        "check_time_change_base_unavailable",
        "check_time_change_path_unrepresentable",
        "check_time_change_redacted",
        "check_time_change_truncated",
        "check_time_change_unavailable",
        "check_time_change_unavailable_capture_failed",
        "check_time_change_unavailable_changed_during_capture",
        "check_time_change_unavailable_git_failed",
        "check_time_change_unavailable_git_unavailable",
        "check_time_change_unavailable_git_version_unsupported",
        "check_time_change_unavailable_no_linked_subject",
        "check_time_change_unavailable_no_packet_room",
        "check_time_change_unavailable_not_git",
        "check_time_change_unavailable_redaction_incomplete",
        "check_time_change_unavailable_repository_mismatch",
        "check_time_change_unavailable_unsafe_root",
        "check_time_change_unavailable_unsupported_repository",
        "content_redacted",
        "content_unselected",
        "declared_output_content_moved",
        "declared_output_emptied",
        "declared_output_not_reviewable",
        "declared_output_removed",
        "deliverable_references_ambiguous_name",
        "deliverable_references_undeclared_file",
        "edited_after_last_verification",
        "evidence_content_digest_only",
        "evidence_content_withheld",
        "evidence_digest_subject_legacy_unknown",
        "host_outcome_unavailable",
        "install_into_private_env",
        # Frozen legacy identifier (ADR-048): recorded gap code.
        "install_into_yoetz_runtime",
        "instruction_requirement_unmapped",
        "obligation_blocked_outside_agent_control",
        "obligation_blocker_unconfirmed",
        "obligation_evidence_stale_after_scope_edit",
        "optional_semantic_review_blocked_by_policy",
        "optional_semantic_review_registration_drift",
        "plan_unrefined_before_first_edit",
        "planned_verification_agent_linked",
        "planned_verification_failed",
        "planned_verification_matched_by_prefix",
        "planned_verification_not_observed",
        "planned_verification_outcome_unknown",
        "planned_verification_stale",
        "planned_verification_unobservable",
        "requested_output_git_ignored",
        "requested_output_ignored_by_repository",
        "requested_output_outside_workspace",
        "requested_output_unchanged",
        "requested_output_unverified",
        "semantic_case_content_over_item_limit",
        "semantic_case_finding_refs_over_limit",
        "semantic_challenges_rejected",
        "semantic_included_refs_not_recorded",
        "semantic_missing_agent_suppliable",
        "semantic_missing_already_supplied",
        "semantic_missing_items_rejected",
        "semantic_missing_non_convergent",
        "semantic_missing_structurally_unavailable",
        # Frozen legacy identifier (ADR-048): recorded gap code.
        "semantic_missing_yoetz_limit",
        "semantic_packet_insufficient",
        "semantic_prior_findings_over_limit",
        "semantic_prior_verdicts_unsupported",
        "semantic_process_state_filtered",
        "semantic_provider_input_manifest_invalid",
        "semantic_provider_input_manifest_mismatch",
        "semantic_provider_input_manifest_missing",
        "semantic_provider_input_manifest_parse_failed",
        "semantic_provider_input_manifest_recovery_failed",
        "semantic_reference_scope_reduced",
        "semantic_relevance_review_not_run",
        "semantic_restatements_suppressed",
        "semantic_review_context_withheld",
        "semantic_review_credential_heuristic_disabled",
        "semantic_review_deferred_before_first_edit",
        "semantic_review_item_withheld",
        "semantic_review_not_configured",
        "semantic_review_not_requested",
        "semantic_review_refs_reduced",
        "semantic_review_skipped_insufficient_packet",
        "semantic_review_skipped_privacy_block",
        "semantic_review_snippet_invalid",
        "semantic_review_value_redacted",
        "task_input_baseline_unavailable",
        "task_input_outside_not_admitted",
        "task_statement_not_authorized",
        "task_statement_not_supplied",
        "task_statement_unavailable",
        "unpaired_event",
        "unresolved_verification_limitation",
        "verification_input_directory_unresolved",
        "verification_inputs_caller_asserted",
        "verification_only_as_root",
        "write_outside_workspace",
    }
)


def gap_base_code(marker: str) -> str:
    """Return the base code a gap marker or prefixed form classifies by.

    ``coverage:<code>``, ``check_coverage:<code>``, ``retained_finding_coverage:<code>``,
    ``semantic_outcome:<code>`` and ``lineage:<code>:...`` name their base code second; every
    other ``<code>:<subject...>`` marker names it first. A bare code is its own base.
    """

    if type(marker) is not str:
        raise TypeError("gap_marker_invalid")
    head, separator, rest = marker.partition(":")
    if not separator:
        return marker
    if head in _WRAPPER_PREFIXES:
        return rest.partition(":")[0]
    return head


def unclassified_marker(code: str) -> str:
    """Bound an unknown or unreadable code to a fixed, content-free structural token."""

    return UNCLASSIFIED_GAP_PREFIX + (code if _CODE_RE.fullmatch(code) else "unreadable_gap_code")


def _resolve(spec: str, code: str, ctx: GapContext) -> GapEffectKind:
    if spec == "A":
        return GapEffectKind.ACTIONABLE
    if spec == "B":
        return GapEffectKind.STANDING_BOUNDING
    if spec == "D":
        return GapEffectKind.DISCLOSED
    if spec == "D*":
        # A FinishUP packet-size budget: disclosed while the review succeeded and the same check
        # carries no reviewer-reported insufficiency (owner decision Q2); bounding otherwise.
        if ctx.review_succeeded and not ctx.reviewer_reported_insufficiency:
            return GapEffectKind.DISCLOSED
        return GapEffectKind.STANDING_BOUNDING
    if spec == "R":
        # ``semantic_review_not_requested``: a disclosure when the recorded route did not require
        # review; agent work when the route requires it and none is current; else bounding.
        if not ctx.route_requires_review:
            return GapEffectKind.DISCLOSED
        if ctx.review_required and not ctx.review_current:
            return GapEffectKind.ACTIONABLE
        return GapEffectKind.STANDING_BOUNDING
    if spec == "V":
        # Verification freshness (#1143): agent work unless freshness is AI-advisory; there it is
        # a standing limit, like the rerun question, never agent work and never merely disclosed.
        return (
            GapEffectKind.STANDING_BOUNDING if ctx.freshness_advisory else GapEffectKind.ACTIONABLE
        )
    if spec == "X":
        # ``check_current_as_of_earlier_frontier`` (tb4n3 RC-6): bounding only while a counted
        # later record is an observation FinishUP cannot prove harmless; the agent's own answers
        # are a disclosure. Never actionable: no recorded action regenerates it away.
        return (
            GapEffectKind.STANDING_BOUNDING
            if ctx.earlier_frontier_bounds
            else GapEffectKind.DISCLOSED
        )
    if spec == "G":
        # A host-observation gap is advisory only when the applicable check itself carried it and
        # its counters show no unknown or live-failed command.
        if code in ctx.check_carried and ctx.commands_complete:
            return GapEffectKind.DISCLOSED
        return GapEffectKind.STANDING_BOUNDING
    raise ValueError("gap_effect_spec_invalid")  # pragma: no cover - checked at import


def gap_effect(marker: str, ctx: GapContext | None = None) -> GapEffect:
    """Resolve one gap marker (a code or a wrapped marker) against the context."""

    context = GapContext() if ctx is None else ctx
    code = gap_base_code(marker)
    row = GAP_EFFECT_TABLE.get(code)
    if row is None:
        return GapEffect(
            unclassified_marker(code),
            GapEffectKind.ACTIONABLE,
            GapClass.AGENT_ACTIONABLE,
            "G-unclassified",
            "unclassified",
        )
    if code in context.historical:
        return GapEffect(code, GapEffectKind.HISTORICAL, row.readiness, row.rule, row.why)
    spec = row.review_route if context.route_requires_review else row.d_route
    return GapEffect(code, _resolve(spec, code, context), row.readiness, row.rule, row.why)


def judge_gaps(markers: Iterable[str], ctx: GapContext | None = None) -> tuple[GapEffect, ...]:
    """Resolve every marker; one entry per distinct base code, sorted by code."""

    context = GapContext() if ctx is None else ctx
    effects: dict[str, GapEffect] = {}
    for marker in markers:
        effect = gap_effect(marker, context)
        effects.setdefault(effect.code, effect)
    return tuple(effects[code] for code in sorted(effects, key=str.encode))
