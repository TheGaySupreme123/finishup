"""Immutable receipt documents, exact JSON codecs, and compact rendering."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal, cast

from yoetz.domain.bounded_text import Part, clip_to_limit, compose_parts
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    SemanticProvenance,
    WaiverScope,
    finding_from_json,
    finding_to_json,
    semantic_provenance_from_json,
    semantic_provenance_to_json,
)
from yoetz.domain.values import (
    ClaimId,
    EventId,
    EvidenceId,
    FindingId,
    Frontier,
    ObligationId,
    ReceiptId,
    ResultId,
    SessionId,
    TaskId,
    Timestamp,
    claim_id,
    event_id,
    evidence_id,
    finding_id,
    freeze_json,
    frontier_from_json,
    obligation_id,
    receipt_id,
    result_id,
    session_id,
    task_id,
    timestamp_from_string,
    validate_sha256_digest,
)
from yoetz.protocol.canonical import JsonValue as CanonicalJsonValue
from yoetz.protocol.coverage import (
    Coverage,
    coverage_from_json,
    coverage_to_json,
    weakest,
)
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.ids import validate_opaque_item_id
from yoetz.protocol.models import (
    ReceiptRedactionProfile,
    SemanticReason,
    SemanticStatus,
    validate_semantic_outcome,
)
from yoetz.protocol.recovery import continuation_for_semantic_outcome, directive_for
from yoetz.protocol.redacted_values import (
    SemanticRedactedValue,
    semantic_redacted_values_from_wire,
    validate_semantic_redacted_values,
)

__all__ = [
    "SEMANTIC_REDACTED_VALUES_AGENT_LINE",
    "SEMANTIC_REDACTED_VALUES_AGENT_LINE_SHORT",
    "semantic_redacted_value_text",
    "ACKNOWLEDGED_OBLIGATIONS_SECTION_TITLE",
    "PREMISE_DISPUTED_SECTION_TITLE",
    "DISCLOSED_ASSUMPTIONS_SECTION_TITLE",
    "ReceiptDisclosure",
    "DUPLICATE_LINKS_SECTION_TITLE",
    "ReceiptDuplicateLink",
    "SELF_VERIFIED_SECTION_TITLE",
    "VERIFICATION_LIMITS_SECTION_TITLE",
    "CONCLUSION_REASON_CODES",
    "ReceiptConclusionBasis",
    "ReceiptConclusionReason",
    "ReceiptGapEffect",
    "CHILD_SELF_VERIFIED_NOTE",
    "HISTORICAL_GAPS_SECTION_TITLE",
    "historical_gap_line",
    "historical_gaps_from_wire",
    "historical_receipt_gaps",
    "live_receipt_gap_codes",
    "receipt_document_carries_terminal_sections",
    "CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP",
    "CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP",
    "CHECK_TIME_CHANGE_GAPS",
    "CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP",
    "CAPTURE_HANDOFF_RETIRED_GAP",
    "CHECK_TIME_CHANGE_REDACTED_GAP",
    "CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP",
    "CHECK_TIME_CHANGE_TRUNCATED_GAP",
    "CHECK_TIME_CHANGE_UNAVAILABLE_GAP",
    "CHECK_TIME_CHANGE_UNAVAILABLE_REASONS",
    "CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS",
    "COMPLETION_CLAIM_OUTSIDE_PLAN_GAP",
    "COMPLETION_PLAN_NOT_CLAIMED_GAP",
    "COMPLETION_SCOPE_DECLARED_NONE_GAP",
    "COMPLETION_SCOPE_UNDECLARED_GAP",
    "PREEXISTING_TEST_BASELINE_UNKNOWN_GAP",
    "PREEXISTING_TEST_DELETED_GAP",
    "PREEXISTING_TEST_EDIT_UNJUSTIFIED_GAP",
    "PREEXISTING_TEST_MODIFIED_GAP",
    "PREEXISTING_TEST_RENAMED_GAP",
    "PREEXISTING_TEST_SKIPPED_GAP",
    "PREEXISTING_TEST_SKIP_UNKNOWN_GAP",
    "PREEXISTING_TEST_INFORMATIONAL_GAPS",
    "OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP",
    "OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP",
    "PolicyVersionEntry",
    "ReceiptConclusion",
    "ReceiptDocument",
    "ReceiptChildFinding",
    "ReceiptChildOutcome",
    "ReceiptChildren",
    "ReceiptGap",
    "ReceiptGapStatus",
    "ReceiptObligation",
    "ReceiptObligationStatus",
    "ReceiptRedaction",
    "ReceiptRedactionCategory",
    "ReceiptRedactionProfile",
    "ReceiptRedactionReason",
    "ReceiptResponse",
    "ReceiptSection",
    "ReceiptSectionKey",
    "ReceiptSemanticWithheldItem",
    "ReceiptVersionSlice",
    "SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP",
    "SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP",
    "SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP",
    "SEMANTIC_PRIOR_VERDICTS_UNSUPPORTED_GAP",
    "SEMANTIC_RESTATEMENTS_SUPPRESSED_GAP",
    "SEMANTIC_CHALLENGES_REJECTED_GAP",
    "SEMANTIC_REVIEW_SNIPPET_INVALID_GAP",
    "SEMANTIC_REVIEW_REFS_REDUCED_GAP",
    "SEMANTIC_MISSING_AGENT_SUPPLIABLE_GAP",
    "SEMANTIC_MISSING_ALREADY_SUPPLIED_GAP",
    "SEMANTIC_MISSING_ITEMS_REJECTED_GAP",
    "SEMANTIC_MISSING_NON_CONVERGENT_GAP",
    "SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP",
    "SEMANTIC_MISSING_UNAVAILABLE_GAP",
    "SEMANTIC_MISSING_YOETZ_LIMIT_GAP",
    "SEMANTIC_PROVIDER_INPUT_MANIFEST_FAILURES",
    "SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP",
    "SEMANTIC_PROVIDER_INPUT_MANIFEST_MISMATCH_GAP",
    "SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP",
    "SEMANTIC_PROVIDER_INPUT_MANIFEST_PARSE_FAILED_GAP",
    "SEMANTIC_PROVIDER_INPUT_MANIFEST_RECOVERY_FAILED_GAP",
    "SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP",
    "SEMANTIC_REVIEW_CONTEXT_WITHHELD_GAP",
    "SEMANTIC_REVIEW_CREDENTIAL_HEURISTIC_DISABLED_GAP",
    "SEMANTIC_REVIEW_EGRESS_REDACTION_GAPS",
    "SEMANTIC_REVIEW_ITEM_WITHHELD_GAP",
    "SEMANTIC_REVIEW_VALUE_REDACTED_GAP",
    "SEMANTIC_PACKET_INSUFFICIENT_GAP",
    "SEMANTIC_REVIEW_NOT_CONFIGURED_GAP",
    "SEMANTIC_REVIEW_NOT_REQUESTED_GAP",
    "SchemaVersionEntry",
    "receipt_document_from_json",
    "receipt_document_to_json",
    "receipt_weakest_coverage",
    "render_receipt_compact",
    "render_receipt_human",
    "resolved_finding_ids_for_render",
    "unresolved_findings_for_render",
    "semantic_coverage_gap_code",
    "check_time_change_gap_sentence",
    "TASK_FACT_GAP_SENTENCES",
    "check_time_change_unavailable_reason_gap",
]

# Structural completion-scope gaps. These are case-coverage facts, not policy findings: an
# explicit declaration that no obligations apply makes status authorable, but it cannot purchase
# a clean completion verdict.
COMPLETION_SCOPE_UNDECLARED_GAP: Final = "completion_scope_undeclared"
COMPLETION_SCOPE_DECLARED_NONE_GAP: Final = "completion_scope_declared_none"
# Completion claims are compared with the current plan independently. These are coverage facts,
# not policy findings, and remain bounded to two fixed relation codes regardless of claim count.
COMPLETION_CLAIM_OUTSIDE_PLAN_GAP: Final = "completion_claim_outside_plan"
COMPLETION_PLAN_NOT_CLAIMED_GAP: Final = "completion_plan_not_claimed"
# Structural, privacy-preserving test-edit accounting.  These are aggregate codes derived from
# an encrypted change capture; raw paths remain inside that object and never enter status rows.
PREEXISTING_TEST_BASELINE_UNKNOWN_GAP: Final = "preexisting_test_baseline_unknown"
PREEXISTING_TEST_MODIFIED_GAP: Final = "preexisting_test_modified"
PREEXISTING_TEST_RENAMED_GAP: Final = "preexisting_test_renamed"
PREEXISTING_TEST_DELETED_GAP: Final = "preexisting_test_deleted"
PREEXISTING_TEST_SKIPPED_GAP: Final = "preexisting_test_skipped"
PREEXISTING_TEST_EDIT_UNJUSTIFIED_GAP: Final = "preexisting_test_edit_unjustified"
# The edited pre-existing tests and their justification were read, but only path metadata was
# captured (no diff body), so whether any of them gained a skip marker is unknown. A standing
# coverage limit, deliberately not informational: it still keeps the check from reading complete.
PREEXISTING_TEST_SKIP_UNKNOWN_GAP: Final = "preexisting_test_skip_unknown"
PREEXISTING_TEST_INFORMATIONAL_GAPS: Final = frozenset(
    {
        PREEXISTING_TEST_MODIFIED_GAP,
        PREEXISTING_TEST_RENAMED_GAP,
        PREEXISTING_TEST_DELETED_GAP,
        PREEXISTING_TEST_SKIPPED_GAP,
    }
)
# The applicable check still contributes its coverage, but only because every material event
# appended after it answered a finding that same check returned. Its verdict is current as of the
# frontier it tested, not the receipt's; the gap keeps the receipt from reading as re-checked here.
CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP: Final = "check_current_as_of_earlier_frontier"
# Kept local to avoid the events -> receipts import cycle. These values exactly mirror the closed
# NoObligationsReason enum and are used only as a non-echoing render allowlist.
_NO_OBLIGATIONS_REASON_VALUES: Final = frozenset(
    {"exploratory_scope_unknown", "no_material_change", "single_atomic_change"}
)

# Structural receipt/check coverage gap codes for optional AI-powered relevance review.
# Distinct from policy-block; not-configured and evaluator failure share honest not-run wording.
# semantic_review_not_requested marks every local-only check (AI-powered review never attempted).
SEMANTIC_REVIEW_NOT_CONFIGURED_GAP: Final = "semantic_review_not_configured"
SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP: Final = "semantic_relevance_review_not_run"
# The review ran, but the inference channel withheld categories the review profile
# selected, so it judged the work without material it was configured to receive.
SEMANTIC_REVIEW_CONTEXT_WITHHELD_GAP: Final = "semantic_review_context_withheld"
# Egress-only privacy redaction of the review packet (issue #982, owner decision B2). Privacy
# filtering exists to keep sensitive values away from the external model, so these bound only the
# AI-powered review that ran without them, never local proof. ``value_redacted``: one or more
# credential-like values were replaced in place by ``EGRESS_CREDENTIAL_PLACEHOLDER`` and the rest
# of each item was sent. ``item_withheld``: in-place replacement could not make an item safe to
# send, so that item alone was left out of the packet (listed in ``semantic_withheld_items``).
SEMANTIC_REVIEW_VALUE_REDACTED_GAP: Final = "semantic_review_value_redacted"
SEMANTIC_REVIEW_ITEM_WITHHELD_GAP: Final = "semantic_review_item_withheld"
SEMANTIC_REVIEW_EGRESS_REDACTION_GAPS: Final = frozenset(
    {SEMANTIC_REVIEW_VALUE_REDACTED_GAP, SEMANTIC_REVIEW_ITEM_WITHHELD_GAP}
)
# The owner's privacy policy had the low-confidence credential heuristic turned off for this
# review's disclosure (issue #982 owner opt-out): values that only look like passwords or tokens
# were sent as written; known credential shapes, private keys and URL passwords were still
# withheld. An owner choice that disclosed more, never agent work and never a review defect.
SEMANTIC_REVIEW_CREDENTIAL_HEURISTIC_DISABLED_GAP: Final = (
    "semantic_review_credential_heuristic_disabled"
)
# A valid provider answer that could not assess the supplied content is not a clean review.
SEMANTIC_PACKET_INSUFFICIENT_GAP: Final = "semantic_packet_insufficient"
# The review ran and returned challenges, and at least one of them was dropped by the
# post-validation fence. The reviewer said something the check did not carry; coverage says so
# rather than letting the drop look like the reviewer having found nothing there.
SEMANTIC_CHALLENGES_REJECTED_GAP: Final = "semantic_challenges_rejected"
# The provider returned a supporting quote that could not be proved against the sent text of the
# packet rows it cited. The review itself remains usable; the quote is removed from a kept
# challenge (a verified row is dropped) and this gap keeps the loss visible on every receipt surface.
SEMANTIC_REVIEW_SNIPPET_INVALID_GAP: Final = "semantic_review_snippet_invalid"
# A reviewer challenge or verified row cited refs whose content the sent packet did not carry.
# Those refs were removed and the item kept on the refs that were sent (issue #976).
SEMANTIC_REVIEW_REFS_REDUCED_GAP: Final = "semantic_review_refs_reduced"
# An ``insufficient_packet`` review named what it needed (issue #907). These say, as a check
# limitation, whether any named item is one the agent can supply, whether any cannot be carried on
# this host or policy at all, whether the reviewer re-requested an item the agent had already
# supplied without citing why that material was still insufficient, and whether a named item
# pointed outside the packet and was dropped. None of them is a finding or a clean review.
SEMANTIC_MISSING_AGENT_SUPPLIABLE_GAP: Final = "semantic_missing_agent_suppliable"
SEMANTIC_MISSING_UNAVAILABLE_GAP: Final = "semantic_missing_structurally_unavailable"
# tb4n1 D1 (#983): the reviewer named content Yoetz's own packet cannot show (an unsupported data
# type, or content clipped or omitted for packet room). Never agent work; the agent self-verifies.
SEMANTIC_MISSING_YOETZ_LIMIT_GAP: Final = "semantic_missing_yoetz_limit"
SEMANTIC_MISSING_ALREADY_SUPPLIED_GAP: Final = "semantic_missing_already_supplied"
SEMANTIC_MISSING_ITEMS_REJECTED_GAP: Final = "semantic_missing_items_rejected"
# A later review named the same target again without a directly related agent publication.  This
# is a bounded non-convergence disclosure, not proof that a new target was supplied or that the
# reviewer was wrong; the next step is to publish the named relationship or stop rechecking.
SEMANTIC_MISSING_NON_CONVERGENT_GAP: Final = "semantic_missing_non_convergent"
# tb4n1 D3: the reviewer twice in a row (the request and its one retry, no edit since), or four
# times since the last assessed review, could not assess the packet, so the check runs without the
# AI-powered review instead of looping on a packet that cannot show the work
# (``kernel/review_round.py``). A Yoetz limit, never agent work; the receipt discloses it.
SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP: Final = (
    "semantic_review_skipped_insufficient_packet"
)
# A successful provider call can still lose the exact post-admission input manifest.  Keep the
# failure reason closed and coverage-bounded so a composed manifest is never presented as what the
# provider received.  These are internal provenance facts surfaced as ordinary receipt gaps.
SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP: Final = "semantic_provider_input_manifest_missing"
SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP: Final = "semantic_provider_input_manifest_invalid"
SEMANTIC_PROVIDER_INPUT_MANIFEST_PARSE_FAILED_GAP: Final = (
    "semantic_provider_input_manifest_parse_failed"
)
SEMANTIC_PROVIDER_INPUT_MANIFEST_MISMATCH_GAP: Final = "semantic_provider_input_manifest_mismatch"
SEMANTIC_PROVIDER_INPUT_MANIFEST_RECOVERY_FAILED_GAP: Final = (
    "semantic_provider_input_manifest_recovery_failed"
)
SEMANTIC_PROVIDER_INPUT_MANIFEST_FAILURES: Final = frozenset(
    {
        SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP,
        SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP,
        SEMANTIC_PROVIDER_INPUT_MANIFEST_PARSE_FAILED_GAP,
        SEMANTIC_PROVIDER_INPUT_MANIFEST_MISMATCH_GAP,
        SEMANTIC_PROVIDER_INPUT_MANIFEST_RECOVERY_FAILED_GAP,
    }
)
SEMANTIC_REVIEW_NOT_REQUESTED_GAP: Final = "semantic_review_not_requested"
# Publish-side prose accepts twice what one AI-powered review case item can carry, so text that publishes
# cleanly can still reach the reviewer shortened or replaced by a bounded-omission marker. The
# gap names that window; without it the drop was reported as an ordinary `not_selected` omission
# and read as a selection-policy choice the author had already made.
SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP: Final = "semantic_case_content_over_item_limit"
# A local finding may cite up to 64 subjects, but one AI-powered review case item links at most
# 16. A finding wider than that keeps its complete local identity and its place in the check
# result; the case carries no prose or projected assessment for it and says so with this gap
# beside the explicit `not_selected` omissions, instead of failing the whole review as a
# generic coordinator failure (issue #858).
SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP: Final = "semantic_case_finding_refs_over_limit"
# The prior-findings section carries a bounded number of earlier AI-powered findings with the
# agent's answers (issue #905). More than fit are named as `not_selected` omissions and this gap
# discloses the truncation instead of letting the reviewer's view read as the whole dialogue.
SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP: Final = "semantic_prior_findings_over_limit"
# The reviewer ruled on an earlier finding in a way the fence could not admit as given: a `fixed`
# citing nothing recorded after the finding, a ruling without cited material, a `withdrawn` with
# no rejection to accept, or a finding outside the fence (issue #905). The ruling counts for
# nothing beyond `unassessable`; this gap discloses it.
SEMANTIC_PRIOR_VERDICTS_UNSUPPORTED_GAP: Final = "semantic_prior_verdicts_unsupported"
# Issue #905: a challenge that restated a recorded AI-powered finding (same kind, subjects within
# that finding's, nothing recorded since) was "seen again, suppressed" instead of minted twice.
SEMANTIC_RESTATEMENTS_SUPPRESSED_GAP: Final = "semantic_restatements_suppressed"
# The check-time change (ADR-031) is the service's own read of the task's repository when a check
# runs. Each code names one limit on what that single object could show the reviewer. None of
# them describes an input of a local policy pack, so they bound the review and the receipt only.
# ``unavailable``: the review's recipe selected the change and the check named a workspace, but the
# service could carry none of it (a workspace outside the task's repository, an unsupported Git
# state, a failed or timed-out capture, a change withheld whole by redaction, or no packet
# subject). A check whose connection named no workspace has nothing to read and reports no code.
CHECK_TIME_CHANGE_UNAVAILABLE_GAP: Final = "check_time_change_unavailable"
# The commit recorded when the task started was absent or unresolvable, so the change is shown
# against the commit the task's first check pinned (or, when no pin could be kept, HEAD): work
# committed during the task before that commit is missing from it.
CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP: Final = "check_time_change_base_unavailable"
# The capture, or its share of the packet, stopped early: the files and parts it names as not
# shown never reached the reviewer.
CHECK_TIME_CHANGE_TRUNCATED_GAP: Final = "check_time_change_truncated"
# Credential-like spans were replaced before the change was stored or offered for review.
CHECK_TIME_CHANGE_REDACTED_GAP: Final = "check_time_change_redacted"
# The check's local read of which paths changed skipped at least one path whose name holds a
# carriage return or line feed (issue #1019). The read stays usable but is marked incomplete, so
# a requested file it could not list stays unproven rather than unchanged. Never names the path.
CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP: Final = "check_time_change_path_unrepresentable"
# Native content staged for one observed host call of this task was retired before its structural
# row could attach it (issue #1019, tb4n2 N-4): its captured bytes are missing, and for a refused
# or quarantined row the call's structural record may be missing as well. A standing limitation
# of host capture, never a finding; local packs never read captured bytes.
CAPTURE_HANDOFF_RETIRED_GAP: Final = "capture_handoff_retired"
# Why the change was unavailable, as one closed code beside ``check_time_change_unavailable``:
# ``check_time_change_unavailable_<reason>``. Each maps to one fixed sentence; neither carries a
# path, Git output or any other user-controlled text. A check recorded before reasons existed
# carries only the generic code.
CHECK_TIME_CHANGE_UNAVAILABLE_REASONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "git_unavailable": "Git is not installed where the Yoetz service runs.",
        "not_git": "the check's directory is not a Git repository.",
        "unsafe_root": (
            "the repository failed a safety check (a link, another owner, a working tree "
            "redirected elsewhere, or a directory replaced while it was read)."
        ),
        "unsupported_repository": (
            "the repository uses a setup the capture does not read (a Git filter or include, a "
            "partial clone, a borrowed object store, or Git older than 2.26)."
        ),
        "git_failed": "a Git command failed or ran out of time.",
        "changed_during_capture": (
            "the working tree kept changing while it was read, through every attempt."
        ),
        "redaction_incomplete": (
            "credential-like text remained after every redaction pass, so the change was "
            "withheld whole."
        ),
        "repository_mismatch": (
            "the check's connection named a different repository from the task's."
        ),
        "capture_failed": "the capture failed unexpectedly; service diagnostics record it.",
        "no_linked_subject": (
            "the review packet had no claim, obligation or plan to attach the change to."
        ),
        "no_packet_room": (
            "the review recipe's excerpt budget is too small for any part of the change."
        ),
    }
)
_CHECK_TIME_CHANGE_REASON_PREFIX: Final = CHECK_TIME_CHANGE_UNAVAILABLE_GAP + "_"
CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS: Final = frozenset(
    _CHECK_TIME_CHANGE_REASON_PREFIX + reason for reason in CHECK_TIME_CHANGE_UNAVAILABLE_REASONS
)
# A receipt-only disclosure (R945-02): an AI-powered finding was resolved by tolerating a repair
# review's check-time limits against a raising view recorded before view commitments existed, so
# only lengths and counts were compared. The resolution stands; it is never presented as
# content-verified. It is not a check coverage code and never tolerates anything.
CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP: Final = "check_time_change_resolution_unverified"
CHECK_TIME_CHANGE_GAPS: Final = frozenset(
    {
        CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
        CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,
        CHECK_TIME_CHANGE_TRUNCATED_GAP,
        CHECK_TIME_CHANGE_REDACTED_GAP,
        CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP,
        *CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS,
    }
)


def check_time_change_unavailable_reason_gap(reason: str) -> str:
    """The closed gap code naming why the check-time change was unavailable."""

    if reason not in CHECK_TIME_CHANGE_UNAVAILABLE_REASONS:
        raise ValueError("check_time_change_reason_invalid")
    return _CHECK_TIME_CHANGE_REASON_PREFIX + reason


def check_time_change_gap_sentence(code: str) -> str | None:
    """One plain sentence for a check-time reason or resolution code; ``None`` otherwise."""

    if code == CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP:
        return (
            "An AI-powered finding was resolved against a raising review recorded before file "
            "view commitments existed, so only the lengths and counts of what each review saw "
            "were compared, not where redactions and hunks lay."
        )
    if code == CAPTURE_HANDOFF_RETIRED_GAP:
        return (
            "Captured content for at least one observed call of this task was discarded before"
            " it could be attached, so that content is not available here; depending on why it"
            " was discarded, the call's own record may be missing too."
        )
    if code == CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP:
        return (
            "The check's read of changed files skipped at least one file whose name contains a"
            " line break, so a requested file it could not list is reported as unproven, not"
            " as unchanged."
        )
    if code not in CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS:
        return TASK_FACT_GAP_SENTENCES.get(code)
    text = CHECK_TIME_CHANGE_UNAVAILABLE_REASONS[code[len(_CHECK_TIME_CHANGE_REASON_PREFIX) :]]
    return "The check-time change was unavailable: " + text


# One fixed sentence per task-fact gap (#977, ADR-033), shown wherever check-time gap sentences
# are: receipt gap details and limitations, the CLI human check and status, the MCP check summary.
# Codes only; no path or command text exists to show.
TASK_FACT_GAP_SENTENCES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "planned_verification_not_observed": (
            "A planned verification (an obligation's requested command) was not matched to an"
            " observed run, whole or as one part of a composed command. Run it as recorded; if"
            " you ran it exactly, check the requested command string. If a script or another"
            " command ran it for you, link that run: publish `action_recorded` (kind `command`)"
            " with the planned command's exact value in `attempted_items` and the observed run's"
            " action event id (`status view=history`) in `causal_parents`. The link is disclosed"
            " as your equivalence; the observed outcome still decides."
        ),
        "planned_verification_failed": (
            "A planned verification command failed on its latest observed run."
        ),
        "planned_verification_stale": (
            "A planned verification command last ran before the latest observed edit."
        ),
        "planned_verification_outcome_unknown": (
            "A planned verification command ran, but the host stated no outcome for it."
        ),
        "planned_verification_unobservable": (
            "A planned verification could not be matched: no observed command carries a command"
            " identity, or the requested command is a placeholder or a description rather than a"
            " command."
        ),
        "planned_verification_agent_linked": (
            "A planned verification was matched only through the agent's own link of an observed"
            " run to the requested command, an equivalence Yoetz did not verify; that run's"
            " observed outcome still decides."
        ),
        "edited_after_last_verification": (
            "An observed edit followed the last observed test, lint, typecheck or build run."
        ),
        "requested_output_git_ignored": (
            "A requested output file is excluded by .git/info/exclude (a local exclude) or by a"
            " .gitignore this task created, so a diff-based delivery omits it."
        ),
        "requested_output_ignored_by_repository": (
            "A requested output file is ignored by the repository's own ignore rules, so a"
            " diff-based delivery would omit it."
        ),
        "requested_output_unchanged": (
            "A requested file the record says was edited exists but is unchanged from the task"
            " base."
        ),
        "requested_output_outside_workspace": (
            "A requested file the record says was edited lies outside the checked repository;"
            " Yoetz did not read it."
        ),
        "requested_output_unverified": ("Requested output files could not be read at check time."),
        "declared_output_removed": (
            "A declared delivered file was deleted or renamed away in the checked change. Restore"
            " the delivered file, or correct the requested item if the task asked for the"
            " deletion: Yoetz review limits never justify moving, splitting or deleting"
            " deliverables."
        ),
        "declared_output_content_moved": (
            "A declared delivered file lost most of its lines while files outside the declared"
            " delivered set changed or hold about as many lines (untracked files may predate the"
            " task): content may have moved out of a delivered file into an undelivered one."
            " Check that the deliverable still works where the task delivers it."
        ),
        "declared_output_emptied": (
            "A declared delivered file that held content earlier (at a recorded check, or at the"
            " task base) is now empty or holds a small fraction of its earlier size. Restore it"
            " and disclose its limits: a working partial is a delivery, and an empty file always"
            " grades as no solution. This stands unless the task asked for this file to be empty"
            " regardless of outcome and a yoetz-assumption decision names the file."
        ),
        "planned_verification_matched_by_prefix": (
            "A planned verification was matched to an observed run only by its leading arguments"
            " or by its program and flags: the run did the planned work and more, or in another"
            " order. It counts as run and is disclosed, not clean verification; Yoetz did not"
            " verify that the run is what the plan meant."
        ),
        "declared_output_not_reviewable": (
            "A declared delivered file is a type the AI-powered review never receives (binary, by"
            " the change's own content check, or a binary format) and a review ran: the file is"
            " present but was not reviewed. Verify it yourself and disclose how; do not reshape"
            " it for the reviewer."
        ),
        "deliverable_references_undeclared_file": (
            "A declared delivered source file names a workspace file that is not a declared output"
            " or input; a grader may receive only the declared files. Embed it, rebuild it at"
            " runtime, or disclose the dependency."
        ),
        "install_into_yoetz_runtime": (
            "A package install resolved to Yoetz's own runtime interpreter, not the task's."
        ),
        "install_into_private_env": (
            "A package install went into an environment other than the task's interpreter."
        ),
        "write_outside_workspace": (
            "A write landed outside the workspace; it is not part of the delivered change."
        ),
        "verification_only_as_root": (
            "Every observed test, lint, typecheck or build run ran as root."
        ),
        "obligation_blocked_outside_agent_control": (
            "An open obligation is named by a blocker the agent recorded as outside its control"
            " (authority, consent, credentials, or an unobtainable dependency) and confirmed in a"
            " later decision; Yoetz did not verify the claim."
        ),
        "obligation_blocker_unconfirmed": (
            "An open obligation is named by a blocker the agent claimed but did not confirm in a"
            " later decision; the obligation still counts as open work."
        ),
    }
)


OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP: Final = "optional_semantic_review_blocked_by_policy"
# The strict route ceiling blocked this process, but the durable applied-route record says the
# last install applied the policy route (issue #537). The disagreement is the whole claim: a
# route reached outside the install ceremony is a legitimate owner action, so the gap offers
# the recovery rather than asserting a stale process. Carried alongside the ceiling gap above —
# never instead of it — so the terminal status/reason/provenance binding is unchanged.
OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP: Final = (
    "optional_semantic_review_registration_drift"
)
_SEMANTIC_REVIEW_NOT_RUN_GAPS: Final = frozenset(
    {
        SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
        SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
        SEMANTIC_REVIEW_NOT_REQUESTED_GAP,
    }
)


def semantic_coverage_gap_code(status: SemanticStatus, reason: SemanticReason) -> str | None:
    """Map a terminal AI-powered review outcome to the receipt/check structural gap code, or None.

    This lives beside the gap constants rather than in the check application module because
    append-time receipt-capacity admission must fold the same code the receipt builder will
    later add. A copy that drifted would let a state pass admission and then fail receipt
    construction on the gap the copy forgot.
    """

    validate_semantic_outcome(status, reason)
    if reason is SemanticReason.CASE_CAPACITY_EXCEEDED:
        return "semantic_case_capacity_exceeded"
    if status is SemanticStatus.SUCCEEDED:
        return None
    if status is SemanticStatus.NOT_REQUESTED:
        return SEMANTIC_REVIEW_NOT_REQUESTED_GAP
    if status is SemanticStatus.BLOCKED_BY_POLICY:
        return OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP
    if status is SemanticStatus.NOT_CONFIGURED:
        return SEMANTIC_REVIEW_NOT_CONFIGURED_GAP
    return SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP


class ReceiptConclusion(str, Enum):  # noqa: UP042 - exact wire enum base
    NO_UNRESOLVED_DETERMINISTIC_FINDINGS = "no_unresolved_deterministic_findings"
    UNRESOLVED_FINDINGS_REMAIN = "unresolved_findings_remain"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"


# The receipt fields that disclose terminal finding states by id (issues #905, #984); a finding
# is in at most one of them.
_TERMINAL_ID_FIELDS: Final = (
    "acknowledged_not_done_finding_ids",
    "rejection_accepted_finding_ids",
    "self_verified_finding_ids",
    "disputed_after_rebuttal_finding_ids",
    "limitation_disclosed_finding_ids",
)
# tb4n3 RC-3 (ADR-046): a reviewer's limitation request the agent disclosed. Settled, listed
# under "Verification limits", never clean.
VERIFICATION_LIMITS_SECTION_TITLE: Final = "Verification limits"
# The closed reason codes of a conclusion basis; a conformance test keeps this equal to
# ``kernel.receipt_prediction.PREDICTION_REASON_CODES`` (the domain cannot import the kernel).
CONCLUSION_REASON_CODES: Final = {
    "completion_scope_gap": "R1",
    "findings_to_do": "R2",
    "findings_awaiting_ruling": "R2",
    "findings_unmet": "R2",
    "child_findings_actionable": "R2",
    "limitations_to_disclose": "R3",
    "findings_disclosed": "R3",
    "obligations_open": "R4",
    "obligations_acknowledged": "R4",
    "obligations_disclosed": "R4",
    "lineage_blocks": "R5",
    "no_applicable_check": "R6",
    "check_suppressed_findings": "R7",
    "check_verdict_insufficient": "R8",
    "policy_execution_incomplete": "R9",
    "live_gap_bounds": "R10",
}
MAX_CONCLUSION_REASONS: Final = 8
_REASON_REF_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", re.ASCII)


@dataclass(frozen=True, slots=True)
class ReceiptConclusionReason:
    """One rule that fired when the conclusion was chosen: why a reader sees this label."""

    code: str
    rule: str
    count: int
    refs: tuple[str, ...] = ()
    since_frontier: int | None = None

    def __post_init__(self) -> None:
        invalid = "invalid_receipt_document"
        if (
            type(self.code) is not str
            or CONCLUSION_REASON_CODES.get(self.code) != self.rule
            or type(self.count) is not int
            or not 1 <= self.count <= _MAX_SAFE_INTEGER
            or type(self.refs) is not tuple
            or len(self.refs) > 3
            or any(
                type(ref) is not str or _REASON_REF_RE.fullmatch(ref) is None for ref in self.refs
            )
            or self.refs != tuple(sorted(set(self.refs), key=str.encode))
            or (
                self.since_frontier is not None
                and (
                    type(self.since_frontier) is not int
                    or not 0 <= self.since_frontier <= _MAX_SAFE_INTEGER
                )
            )
        ):
            raise ProtocolValueError(invalid)


@dataclass(frozen=True, slots=True)
class ReceiptConclusionBasis:
    """Every rule behind the conclusion, the one that selected it first (ADR-046)."""

    reasons: tuple[ReceiptConclusionReason, ...]
    reason_total: int

    def __post_init__(self) -> None:
        if (
            type(self.reasons) is not tuple
            or len(self.reasons) > MAX_CONCLUSION_REASONS
            or any(type(item) is not ReceiptConclusionReason for item in self.reasons)
            or type(self.reason_total) is not int
            or not len(self.reasons) <= self.reason_total <= _MAX_SAFE_INTEGER
        ):
            raise ProtocolValueError("invalid_receipt_document")


# Issue #1020 (ADR-040): the agent rejected these with a reason and the reviewer repeated them
# without citing anything newer. A standing disagreement, disclosed; never agent work.
DISPUTED_AFTER_REBUTTAL_SECTION_TITLE: Final = "Disputed after rebuttal"
SELF_VERIFIED_SECTION_TITLE: Final = "Self-verified by the agent; Yoetz could not prove the repair"
# Issue #984 (ADR-034): how a child's self-verified finding reads on the parent receipt.
CHILD_SELF_VERIFIED_NOTE: Final = "self-verified by the child agent; Yoetz could not prove it"
DUPLICATE_LINKS_SECTION_TITLE: Final = "Linked duplicates"


@dataclass(frozen=True, slots=True)
class ReceiptDuplicateLink:
    """One holding ``duplicate_of`` link (issue #996): ids only, never prose."""

    finding_id: FindingId
    duplicate_of_finding_id: FindingId

    def __post_init__(self) -> None:
        object.__setattr__(self, "finding_id", finding_id(self.finding_id))
        object.__setattr__(
            self, "duplicate_of_finding_id", finding_id(self.duplicate_of_finding_id)
        )
        if self.finding_id == self.duplicate_of_finding_id:
            raise ProtocolValueError("invalid_receipt_document")


# Issue #995 (ADR-033): the agent's recorded ``yoetz-assumption:`` / ``yoetz-verification-limit:``
# decision lines. Disclosed by id and closed kind only; the rationale stays in the decision.
DISCLOSED_ASSUMPTIONS_SECTION_TITLE: Final = (
    "Assumptions and verification limits the agent disclosed"
)
RECEIPT_DISCLOSURE_KINDS: Final = ("assumption", "verification_limit")
ACKNOWLEDGED_OBLIGATIONS_SECTION_TITLE: Final = "Obligations acknowledged as not done"
PREMISE_DISPUTED_SECTION_TITLE: Final = "Not done although the review says the task requires it"


@dataclass(frozen=True, slots=True)
class ReceiptDisclosure:
    """One disclosed assumption or verification limit: ids and a closed kind, never prose."""

    obligation_id: ObligationId
    kind: str
    decision_event_id: EventId

    def __post_init__(self) -> None:
        object.__setattr__(self, "obligation_id", obligation_id(self.obligation_id))
        object.__setattr__(self, "decision_event_id", event_id(self.decision_event_id))
        if type(self.kind) is not str or self.kind not in RECEIPT_DISCLOSURE_KINDS:
            raise ProtocolValueError("invalid_receipt_document")


class ReceiptGapStatus(str, Enum):  # noqa: UP042 - exact wire enum base
    """Whether a receipt gap still bounds the receipt (issue #1017, ADR-033).

    ``historical`` marks a gap an earlier check carried that a later check no longer carries;
    it stays on the record for honesty but never lowers the conclusion or counts as a current
    limitation. Only ``historical`` is written on the wire; an absent status reads as ``live``.
    """

    LIVE = "live"
    HISTORICAL = "historical"


HISTORICAL_GAPS_SECTION_TITLE: Final = "Cleared earlier (historical)"


class ReceiptGapEffect(str, Enum):  # noqa: UP042 - exact wire enum base
    """What a live gap does to the conclusion (ADR-046): it ``bounds`` it or is only ``disclosed``."""

    BOUNDS = "bounds"
    DISCLOSED = "disclosed"


class ReceiptObligationStatus(str, Enum):  # noqa: UP042 - exact wire enum base
    OPEN = "open"
    RESOLVED = "resolved"
    SUPERSEDED = "superseded"
    WAIVED = "waived"


class ReceiptRedactionCategory(str, Enum):  # noqa: UP042 - exact wire enum base
    CLAIM_TEXT = "claim_text"
    EVIDENCE_CONTENT = "evidence_content"
    FINDING_DETAIL = "finding_detail"
    OBLIGATION_TEXT = "obligation_text"
    REPOSITORY_CONTENT = "repository_content"
    TRANSCRIPT_CONTENT = "transcript_content"


class ReceiptRedactionReason(str, Enum):  # noqa: UP042 - exact wire enum base
    INCLUDE_PROFILE_OMITTED = "include_profile_omitted"
    NEVER_SEND_REDACTED = "never_send_redacted"
    POLICY_REDACTED = "policy_redacted"
    SOURCE_REDACTED = "source_redacted"


class ReceiptSectionKey(str, Enum):  # noqa: UP042 - exact wire enum base
    SUMMARY = "summary"
    OUTSTANDING_WORK = "outstanding_work"
    FINDINGS_AND_DISPOSITIONS = "findings_and_dispositions"
    EVIDENCE_AND_CLAIM_BASIS = "evidence_and_claim_basis"
    LIMITATIONS_AND_COVERAGE = "limitations_and_coverage"
    VERSION_AND_POLICY_IDENTITY = "version_and_policy_identity"


# Owner-approved PL2-1 (issue #982): the one fixed line every human and agent rendering adds,
# once, when a check or receipt names items whose values the external reviewer did not see.
SEMANTIC_REDACTED_VALUES_AGENT_LINE: Final = (
    "Values marked [withheld-by-yoetz:possible-credential] were withheld from the external "
    "reviewer only; local checks saw them. Do not change consent, rename, hide or reshape your "
    "work to clear this. If a finding stays open only because of it, verify the repair yourself "
    "and respond self_verified."
)


# The bounded MCP summaries must keep the frontier head digest (issue #279); when the full line
# cannot fit beside it, they carry this shorter fixed form. Full renderings always use the line.
SEMANTIC_REDACTED_VALUES_AGENT_LINE_SHORT: Final = (
    "Values marked [withheld-by-yoetz:possible-credential] were withheld from the external "
    "reviewer only; do not change consent or your code; verify yourself, respond self_verified."
)


def semantic_redacted_value_text(item: SemanticRedactedValue) -> str:
    """One bounded ASCII line naming the item, its ref and lines; never a value."""

    ref = item.item_id if item.source_ref is None else f"{item.source_ref} (item {item.item_id})"
    lines = (
        "line " + str(item.lines[0])
        if len(item.lines) == 1
        else "lines " + ", ".join(str(line) for line in item.lines)
        if item.lines
        else "lines not located"
    )
    what = "value replaced" if item.disposition == "value_replaced" else "item withheld"
    # Line numbers count lines of the captured item (an excerpt or one of its parts), not of the
    # file it came from; say so, so an agent never reads them as file line numbers.
    located = f"{lines} of the captured item" if item.lines else lines
    return f"{ref}: {what}, {located}"


@dataclass(frozen=True, slots=True)
class ReceiptSemanticWithheldItem:
    """One opaque review item omitted by the never-send heuristic."""

    item_id: str
    reason: Literal["never_send_heuristic"] = "never_send_heuristic"

    def __post_init__(self) -> None:
        invalid = "invalid_receipt_semantic_withheld_item"
        try:
            validate_opaque_item_id(self.item_id)
        except (TypeError, ValueError) as exc:
            raise ProtocolValueError(invalid) from exc
        if self.reason != "never_send_heuristic":
            raise ProtocolValueError(invalid)


_SUMMARY_SECTION_KEYS: Final = (
    ReceiptSectionKey.SUMMARY,
    ReceiptSectionKey.LIMITATIONS_AND_COVERAGE,
    ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY,
)
_STANDARD_SECTION_KEYS: Final = (
    ReceiptSectionKey.SUMMARY,
    ReceiptSectionKey.OUTSTANDING_WORK,
    ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS,
    ReceiptSectionKey.LIMITATIONS_AND_COVERAGE,
    ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY,
)
_FULL_SECTION_KEYS: Final = (
    ReceiptSectionKey.SUMMARY,
    ReceiptSectionKey.OUTSTANDING_WORK,
    ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS,
    ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS,
    ReceiptSectionKey.LIMITATIONS_AND_COVERAGE,
    ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY,
)
_VALID_SECTION_KEY_SEQUENCES: Final = frozenset(
    {_SUMMARY_SECTION_KEYS, _STANDARD_SECTION_KEYS, _FULL_SECTION_KEYS}
)

_POLICY_ID_RE: Final = re.compile(
    r"^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$",
    re.ASCII,
)
_SCHEMA_ID_RE: Final = re.compile(
    r"^[a-z][a-z0-9]*(?:[-_/][a-z0-9.]+)*$",
    re.ASCII,
)
_VERSION_ID_RE: Final = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._/+:-]*$", re.ASCII)
_POSITIVE_DECIMAL_RE: Final = re.compile(r"^[1-9][0-9]*$", re.ASCII)
_UNSIGNED_DECIMAL_RE: Final = re.compile(r"^(?:0|[1-9][0-9]*)$", re.ASCII)
_GAP_CODE_RE: Final = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$", re.ASCII)
_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991


def _is_actual_mapping(value: object) -> bool:
    try:
        return issubclass(type(value), Mapping)
    except BaseException:
        return False


def _closed_object(
    value: object,
    required: frozenset[str],
    optional: frozenset[str],
    reason: str,
) -> Mapping[object, object]:
    if not _is_actual_mapping(value):
        raise ProtocolValueError(reason)
    source = cast(Mapping[object, object], value)
    try:
        keys = tuple(source)
    except Exception as exc:
        raise ProtocolValueError(reason) from exc
    if any(type(key) is not str for key in keys):
        raise ProtocolValueError(reason)
    string_keys = cast(tuple[str, ...], keys)
    key_set = frozenset(string_keys)
    if len(string_keys) != len(key_set) or not required <= key_set or key_set - required - optional:
        raise ProtocolValueError(reason)
    return source


def _field(source: Mapping[object, object], key: str, reason: str) -> object:
    try:
        return source[key]
    except Exception as exc:
        raise ProtocolValueError(reason) from exc


def _array(value: object, reason: str) -> tuple[object, ...]:
    if type(value) is list:
        return tuple(cast(list[object], value))
    if type(value) is tuple:
        return cast(tuple[object, ...], value)
    raise ProtocolValueError(reason)


def _enum_value[T: Enum](value: object, enum_type: type[T], reason: str) -> T:
    if type(value) is not str:
        raise ProtocolValueError(reason)
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ProtocolValueError(reason) from exc


def _bounded_text(value: object, minimum: int, maximum: int, reason: str) -> str:
    if type(value) is not str:
        raise ProtocolValueError(reason)
    text = value
    length = len(text)
    if length < minimum or length > maximum:
        raise ProtocolValueError(reason)
    freeze_json(text)
    return text


def _validate_tuple(value: object, minimum: int, maximum: int, reason: str) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise ProtocolValueError(reason)
    values = cast(tuple[object, ...], value)
    if not minimum <= len(values) <= maximum:
        raise ProtocolValueError(reason)
    return values


def _validate_sorted_unique_strings(values: tuple[str, ...]) -> None:
    previous: bytes | None = None
    for value in values:
        current = value.encode("ascii")
        if previous is not None:
            if current == previous:
                raise ProtocolValueError("duplicate_set_member")
            if current < previous:
                raise ProtocolValueError("unsorted_set_field")
        previous = current


def _version_identity(value: object, reason: str) -> str:
    text = _bounded_text(value, 1, 256, reason)
    if _VERSION_ID_RE.fullmatch(text) is None:
        raise ProtocolValueError(reason)
    return text


def _schema_counter_version(value: object, reason: str) -> str:
    text = _bounded_text(value, 1, 19, reason)
    if _POSITIVE_DECIMAL_RE.fullmatch(text) is None:
        raise ProtocolValueError(reason)
    return text


def _subject_ref(value: object, reason: str) -> EventId | ObligationId | ClaimId:
    if type(value) is not str:
        raise ProtocolValueError(reason)
    text = value
    if text.startswith("evt_"):
        return event_id(text)
    if text.startswith("obl_"):
        return obligation_id(text)
    if text.startswith("clm_"):
        return claim_id(text)
    raise ProtocolValueError(reason)


def _response_evidence_ref(value: object) -> EvidenceId | ResultId:
    if type(value) is not str:
        raise ProtocolValueError("invalid_receipt_response")
    text = value
    if text.startswith("evd_"):
        return evidence_id(text)
    if text.startswith("res_"):
        return result_id(text)
    raise ProtocolValueError("invalid_receipt_response")


@dataclass(frozen=True, slots=True)
class PolicyVersionEntry:
    policy_id: str
    policy_version: str

    def __post_init__(self) -> None:
        policy_id_value = _bounded_text(
            self.policy_id,
            1,
            128,
            "invalid_receipt_version_slice",
        )
        if _POLICY_ID_RE.fullmatch(policy_id_value) is None:
            raise ProtocolValueError("invalid_receipt_version_slice")
        policy_version_value = _version_identity(
            self.policy_version,
            "invalid_receipt_version_slice",
        )
        object.__setattr__(self, "policy_id", policy_id_value)
        object.__setattr__(self, "policy_version", policy_version_value)


@dataclass(frozen=True, slots=True)
class SchemaVersionEntry:
    schema_id: str
    schema_version: str

    def __post_init__(self) -> None:
        schema_id_value = _bounded_text(
            self.schema_id,
            1,
            256,
            "invalid_receipt_version_slice",
        )
        if _SCHEMA_ID_RE.fullmatch(schema_id_value) is None:
            raise ProtocolValueError("invalid_receipt_version_slice")
        schema_version_value = _version_identity(
            self.schema_version,
            "invalid_receipt_version_slice",
        )
        object.__setattr__(self, "schema_id", schema_id_value)
        object.__setattr__(self, "schema_version", schema_version_value)


@dataclass(frozen=True, slots=True)
class ReceiptVersionSlice:
    package_name: Literal["yoetz"]
    package_version: str
    protocol_version: str
    engine_version: str
    projection_version: str
    object_format_version: str
    catalog_schema_version: str
    bundle_schema_version: str
    policy_versions: tuple[PolicyVersionEntry, ...]
    schema_versions: tuple[SchemaVersionEntry, ...]
    resource_manifest_digest: str

    def __post_init__(self) -> None:
        reason = "invalid_receipt_version_slice"
        if type(self.package_name) is not str or self.package_name != "yoetz":
            raise ProtocolValueError(reason)
        for name in (
            "package_version",
            "protocol_version",
            "engine_version",
            "projection_version",
            "object_format_version",
        ):
            object.__setattr__(self, name, _version_identity(getattr(self, name), reason))
        object.__setattr__(
            self,
            "catalog_schema_version",
            _schema_counter_version(self.catalog_schema_version, reason),
        )
        object.__setattr__(
            self,
            "bundle_schema_version",
            _schema_counter_version(self.bundle_schema_version, reason),
        )
        policies = _validate_tuple(self.policy_versions, 1, 16, reason)
        if any(type(entry) is not PolicyVersionEntry for entry in policies):
            raise ProtocolValueError(reason)
        policy_entries = cast(tuple[PolicyVersionEntry, ...], policies)
        _validate_sorted_unique_strings(
            tuple(f"{entry.policy_id}\x00{entry.policy_version}" for entry in policy_entries)
        )
        schemas = _validate_tuple(self.schema_versions, 1, 64, reason)
        if any(type(entry) is not SchemaVersionEntry for entry in schemas):
            raise ProtocolValueError(reason)
        schema_entries = cast(tuple[SchemaVersionEntry, ...], schemas)
        _validate_sorted_unique_strings(
            tuple(f"{entry.schema_id}\x00{entry.schema_version}" for entry in schema_entries)
        )
        object.__setattr__(
            self,
            "resource_manifest_digest",
            validate_sha256_digest(self.resource_manifest_digest),
        )


def _receipt_document_artifact_version(versions: ReceiptVersionSlice) -> str | None:
    """Return the selected receipt-document artifact version from a receipt version slice.

    The document's ``schema_version`` field predates versioned artifact selection and therefore
    remains ``1.0.0``.  Artifact evolution is recorded in the version slice, where 1.0.0 and
    1.1.0 are the child-free readers and 1.2.0 is the additive child-bearing writer.
    """

    return next(
        (
            entry.schema_version
            for entry in versions.schema_versions
            # Stored version slices historically used the resource path while the
            # version manifest uses the request/result schema id.  Both identify the
            # same receipt-document artifact and must select the same reader/writer.
            if entry.schema_id in {"receipts/receipt-document", "receipt-document"}
        ),
        None,
    )


def receipt_document_carries_terminal_sections(versions: ReceiptVersionSlice) -> bool:
    """Whether this receipt artifact version carries the issue #905 terminal-state sections."""

    return _receipt_document_artifact_version(versions) == "1.3.0"


@dataclass(frozen=True, slots=True)
class ReceiptObligation:
    obligation_id: ObligationId
    status: ReceiptObligationStatus
    source_refs: tuple[EventId | ObligationId | ClaimId, ...]
    summary: str | None = None

    def __post_init__(self) -> None:
        reason = "invalid_receipt_obligation"
        object.__setattr__(self, "obligation_id", obligation_id(self.obligation_id))
        if type(self.status) is not ReceiptObligationStatus:
            raise ProtocolValueError(reason)
        raw_refs = _validate_tuple(self.source_refs, 0, 64, reason)
        refs = tuple(_subject_ref(value, reason) for value in raw_refs)
        _validate_sorted_unique_strings(cast(tuple[str, ...], refs))
        object.__setattr__(self, "source_refs", refs)
        if self.summary is not None:
            object.__setattr__(self, "summary", _bounded_text(self.summary, 1, 8192, reason))


@dataclass(frozen=True, slots=True)
class ReceiptResponse:
    finding_id: FindingId
    finding_frontier: Frontier
    disposition: ResponseDisposition
    evidence_refs: tuple[EvidenceId | ResultId, ...]
    reason: str | None = None
    waiver_scope: WaiverScope | None = None
    waiver_expiry: Timestamp | None = None

    def __post_init__(self) -> None:
        invalid = "invalid_receipt_response"
        object.__setattr__(self, "finding_id", finding_id(self.finding_id))
        if type(self.finding_frontier) is not Frontier:
            raise ProtocolValueError(invalid)
        if type(self.disposition) is not ResponseDisposition:
            raise ProtocolValueError(invalid)
        raw_refs = _validate_tuple(self.evidence_refs, 0, 64, invalid)
        refs = tuple(_response_evidence_ref(value) for value in raw_refs)
        _validate_sorted_unique_strings(cast(tuple[str, ...], refs))
        object.__setattr__(self, "evidence_refs", refs)
        if self.reason is not None:
            object.__setattr__(self, "reason", _bounded_text(self.reason, 1, 8192, invalid))
        if self.waiver_scope is not None and type(self.waiver_scope) is not WaiverScope:
            raise ProtocolValueError(invalid)
        if self.waiver_expiry is not None and type(self.waiver_expiry) is not Timestamp:
            raise ProtocolValueError(invalid)
        if self.disposition in {ResponseDisposition.ACKNOWLEDGED, ResponseDisposition.DUPLICATE_OF}:
            if self.waiver_scope is not None or self.waiver_expiry is not None:
                raise ProtocolValueError(invalid)
        elif self.disposition in {
            ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
            ResponseDisposition.PROVENANCE_DISPUTED,
            ResponseDisposition.REJECTED,
            ResponseDisposition.SELF_VERIFIED,
        }:
            if (
                self.reason is None
                or self.waiver_scope is not None
                or self.waiver_expiry is not None
                or (self.disposition is ResponseDisposition.SELF_VERIFIED and not refs)
            ):
                raise ProtocolValueError(invalid)
        elif self.disposition is ResponseDisposition.WAIVED:
            if self.reason is None or self.waiver_scope is None:
                raise ProtocolValueError(invalid)


@dataclass(frozen=True, slots=True)
class ReceiptGap:
    code: str
    subject_refs: tuple[EventId | ObligationId | ClaimId, ...]
    detail: str | None = None
    # Issue #1017: a gap a later check cleared stays visible as ``historical`` with the subject
    # frontier of the first check that no longer carried it. Absent (live) keeps earlier bytes.
    status: ReceiptGapStatus = ReceiptGapStatus.LIVE
    cleared_at_frontier: Frontier | None = None
    # ADR-046: absent reads "not recorded" (an earlier artifact); present only on a live gap.
    effect: ReceiptGapEffect | None = None

    def __post_init__(self) -> None:
        invalid = "invalid_receipt_gap"
        if self.effect is not None and (
            type(self.effect) is not ReceiptGapEffect or self.status is not ReceiptGapStatus.LIVE
        ):
            raise ProtocolValueError(invalid)
        code_value = _bounded_text(self.code, 1, 128, invalid)
        if _GAP_CODE_RE.fullmatch(code_value) is None:
            raise ProtocolValueError(invalid)
        object.__setattr__(self, "code", code_value)
        raw_refs = _validate_tuple(self.subject_refs, 0, 16, invalid)
        refs = tuple(_subject_ref(value, invalid) for value in raw_refs)
        _validate_sorted_unique_strings(cast(tuple[str, ...], refs))
        object.__setattr__(self, "subject_refs", refs)
        if self.detail is not None:
            object.__setattr__(self, "detail", _bounded_text(self.detail, 1, 4096, invalid))
        if type(self.status) is not ReceiptGapStatus:
            raise ProtocolValueError(invalid)
        if self.status is ReceiptGapStatus.HISTORICAL:
            if type(self.cleared_at_frontier) is not Frontier:
                raise ProtocolValueError(invalid)
        elif self.cleared_at_frontier is not None:
            raise ProtocolValueError(invalid)

    @property
    def live(self) -> bool:
        return self.status is ReceiptGapStatus.LIVE


@dataclass(frozen=True, slots=True)
class ReceiptChildFinding:
    """The bounded finding identity copied into a direct-child receipt row."""

    finding_id: FindingId
    kind: FindingKind
    origin: FindingOrigin
    priority: int
    actionable: bool
    resolved: bool
    resolution_event_id: EventId | None = None
    # Issue #984 (ADR-034): self-verified by the child agent; Yoetz could not prove it.
    self_verified: bool = False

    def __post_init__(self) -> None:
        invalid = "invalid_receipt_child_finding"
        object.__setattr__(self, "finding_id", finding_id(self.finding_id))
        if type(self.kind) is not FindingKind or type(self.origin) is not FindingOrigin:
            raise ProtocolValueError(invalid)
        if type(self.priority) is not int or not 1 <= self.priority <= 3:
            raise ProtocolValueError(invalid)
        expected_priority, expected_actionable = FINDING_KIND_TRAITS[self.kind]
        if self.priority != expected_priority or type(self.actionable) is not bool:
            raise ProtocolValueError(invalid)
        if self.actionable is not expected_actionable or type(self.resolved) is not bool:
            raise ProtocolValueError(invalid)
        resolution = (
            None if self.resolution_event_id is None else event_id(self.resolution_event_id)
        )
        if self.resolved is not (resolution is not None):
            raise ProtocolValueError(invalid)
        object.__setattr__(self, "resolution_event_id", resolution)
        if type(self.self_verified) is not bool or (
            self.self_verified and (self.resolved or not self.actionable)
        ):
            raise ProtocolValueError(invalid)


@dataclass(frozen=True, slots=True)
class ReceiptChildOutcome:
    """One direct child's frozen contribution to a parent receipt."""

    child_task_id: TaskId
    outcome: Literal["clean", "annotated", "open_gap", "incomplete", "unavailable"]
    tested_manifest_ref: EventId | None
    later_manifest_ref: EventId | None
    freshness: Literal["known", "unknown"]
    findings: tuple[ReceiptChildFinding, ...]

    def __post_init__(self) -> None:
        invalid = "invalid_receipt_child_outcome"
        object.__setattr__(self, "child_task_id", task_id(self.child_task_id))
        if self.outcome not in {"clean", "annotated", "open_gap", "incomplete", "unavailable"}:
            raise ProtocolValueError(invalid)
        tested = None if self.tested_manifest_ref is None else event_id(self.tested_manifest_ref)
        later = None if self.later_manifest_ref is None else event_id(self.later_manifest_ref)
        object.__setattr__(self, "tested_manifest_ref", tested)
        object.__setattr__(self, "later_manifest_ref", later)
        if self.freshness not in {"known", "unknown"}:
            raise ProtocolValueError(invalid)
        values = _validate_tuple(self.findings, 0, 64, invalid)
        if any(type(value) is not ReceiptChildFinding for value in values):
            raise ProtocolValueError(invalid)
        typed_values = cast(tuple[ReceiptChildFinding, ...], values)
        ordered = tuple(
            sorted(typed_values, key=lambda value: str(value.finding_id).encode("ascii"))
        )
        if typed_values != ordered or len({value.finding_id for value in typed_values}) != len(
            typed_values
        ):
            raise ProtocolValueError(invalid)
        if self.outcome == "unavailable" and tested is not None:
            raise ProtocolValueError("receipt_child_manifest_mismatch")


@dataclass(frozen=True, slots=True)
class ReceiptChildren:
    """Canonical wrapper for the receipt document's direct-child section."""

    children: tuple[ReceiptChildOutcome, ...] = ()

    def __post_init__(self) -> None:
        invalid = "invalid_receipt_children"
        values = _validate_tuple(self.children, 0, 64, invalid)
        if any(type(value) is not ReceiptChildOutcome for value in values):
            raise ProtocolValueError(invalid)
        typed_values = cast(tuple[ReceiptChildOutcome, ...], values)
        ordered = tuple(
            sorted(typed_values, key=lambda value: str(value.child_task_id).encode("ascii"))
        )
        if typed_values != ordered or len({value.child_task_id for value in typed_values}) != len(
            typed_values
        ):
            raise ProtocolValueError("receipt_children_not_canonical")


@dataclass(frozen=True, slots=True)
class ReceiptRedaction:
    category: ReceiptRedactionCategory
    reason: ReceiptRedactionReason
    count: int

    def __post_init__(self) -> None:
        invalid = "invalid_receipt_redaction"
        if type(self.category) is not ReceiptRedactionCategory:
            raise ProtocolValueError(invalid)
        if type(self.reason) is not ReceiptRedactionReason:
            raise ProtocolValueError(invalid)
        if type(self.count) is not int or not 0 <= self.count <= 9_999_999_999_999_999:
            raise ProtocolValueError(invalid)


@dataclass(frozen=True, slots=True)
class ReceiptSection:
    key: ReceiptSectionKey
    title: str
    body: str
    items: tuple[str, ...]
    coverage_note: str | None = None

    def __post_init__(self) -> None:
        invalid = "invalid_receipt_section"
        if type(self.key) is not ReceiptSectionKey:
            raise ProtocolValueError(invalid)
        object.__setattr__(self, "title", _bounded_text(self.title, 1, 128, invalid))
        object.__setattr__(self, "body", _bounded_text(self.body, 1, 32768, invalid))
        raw_items = _validate_tuple(self.items, 0, 64, invalid)
        items = tuple(_bounded_text(item, 1, 8192, invalid) for item in raw_items)
        object.__setattr__(self, "items", items)
        if self.coverage_note is not None:
            object.__setattr__(
                self,
                "coverage_note",
                _bounded_text(self.coverage_note, 1, 4096, invalid),
            )


@dataclass(frozen=True, slots=True)
class ReceiptDocument:
    # ``schema_version`` is the version carried inside the receipt document.  The receipt
    # document artifact itself is selected by ``versions.schema_versions`` and is currently
    # 1.2.0 when the additive ``children`` member is present.  The inner field intentionally
    # remains 1.0.0 for compatibility with the 1.0.0 and 1.1.0 artifact readers.
    schema_version: Literal["1.0.0"] = field(default="1.0.0", init=False)
    receipt_id: ReceiptId
    task_id: TaskId
    session_id: SessionId
    generated_at: Timestamp
    subject_frontier: Frontier
    conclusion: ReceiptConclusion
    suppressed_finding_count: int
    versions: ReceiptVersionSlice
    coverage: Coverage
    findings: tuple[Finding, ...]
    obligations: tuple[ReceiptObligation, ...]
    responses: tuple[ReceiptResponse, ...]
    claim_refs: tuple[ClaimId, ...]
    evidence_refs: tuple[EvidenceId, ...]
    gaps: tuple[ReceiptGap, ...]
    redactions: tuple[ReceiptRedaction, ...]
    sections: tuple[ReceiptSection, ...]
    children: ReceiptChildren = field(default_factory=ReceiptChildren)
    # A receipt carries the provenance of the applicable AI-powered check when one exists.  The
    # field is optional so historical local-only receipts keep their exact frozen bytes and
    # old readers can continue to omit it.
    semantic_provenance: SemanticProvenance | None = None
    # Issue #905 terminal states, disclosed by id in their own sections on a 1.3.0 artifact.
    # Absent (empty) keeps every earlier receipt's exact bytes.
    acknowledged_not_done_finding_ids: tuple[FindingId, ...] = ()
    rejection_accepted_finding_ids: tuple[FindingId, ...] = ()
    # Issue #984 (ADR-034): the agent repaired these and verified the repair itself because Yoetz
    # could not prove it. Disclosed by id in their own section; the conclusion is never clean.
    self_verified_finding_ids: tuple[FindingId, ...] = ()
    # Issue #1020 (ADR-040): the reviewer repeated these after the agent's reasoned rejection
    # without citing anything newer. Disclosed by id in their own section; never clean.
    disputed_after_rebuttal_finding_ids: tuple[FindingId, ...] = ()
    # Issue #996: holding ``duplicate_of`` links of carried findings, sorted by finding id. Each
    # duplicate reads as its earlier finding allows; the link never resolves anything.
    duplicate_finding_links: tuple[ReceiptDuplicateLink, ...] = ()
    # Opaque review item identities withheld by the never-send heuristic.  The field is omitted
    # when empty so historical receipt objects retain their exact bytes.
    semantic_withheld_items: tuple[ReceiptSemanticWithheldItem, ...] = ()
    # PL2-1 (issue #982): item refs and line numbers of values the external reviewer did not see.
    # Omitted when empty so historical receipt objects retain their exact bytes.
    semantic_redacted_values: tuple[SemanticRedactedValue, ...] = ()
    # Issue #995 (ADR-033): assumptions and inherent verification limits the agent disclosed on
    # obligations. Ids and a closed kind only; never changes the conclusion.
    disclosed_assumptions: tuple[ReceiptDisclosure, ...] = ()
    # Issue #997 (ADR-032 slice C): obligations the agent acknowledged as not done, with a
    # reason recorded on the obligation. Disclosed by id; the conclusion is never clean.
    acknowledged_not_done_obligation_ids: tuple[ObligationId, ...] = ()
    # Issue #984 (D7a): acknowledged-not-done findings whose challenge says the task itself
    # requires the work. A subset of ``acknowledged_not_done_finding_ids``, disclosed by id.
    premise_disputed_finding_ids: tuple[FindingId, ...] = ()
    # tb4n3 RC-3 (ADR-046): reviewer limitation requests the agent disclosed ("Verification
    # limits"), and every rule behind the conclusion. Absent (empty / None) keeps earlier bytes.
    limitation_disclosed_finding_ids: tuple[FindingId, ...] = ()
    conclusion_basis: ReceiptConclusionBasis | None = None

    def __post_init__(self) -> None:
        invalid = "invalid_receipt_document"
        try:
            validate_semantic_redacted_values(self.semantic_redacted_values)
        except ValueError as exc:
            raise ProtocolValueError(invalid) from exc
        if self.schema_version != "1.0.0":
            raise ProtocolValueError(invalid)
        object.__setattr__(self, "receipt_id", receipt_id(self.receipt_id))
        object.__setattr__(self, "task_id", task_id(self.task_id))
        object.__setattr__(self, "session_id", session_id(self.session_id))
        if type(self.generated_at) is not Timestamp or type(self.subject_frontier) is not Frontier:
            raise ProtocolValueError(invalid)
        if type(self.conclusion) is not ReceiptConclusion:
            raise ProtocolValueError("invalid_receipt_conclusion")
        if (
            type(self.suppressed_finding_count) is not int
            or not 0 <= self.suppressed_finding_count <= _MAX_SAFE_INTEGER
        ):
            raise ProtocolValueError(invalid)
        if type(self.versions) is not ReceiptVersionSlice or type(self.coverage) is not Coverage:
            raise ProtocolValueError(invalid)
        if (
            self.semantic_provenance is not None
            and type(self.semantic_provenance) is not SemanticProvenance
        ):
            raise ProtocolValueError(invalid)
        findings = _validate_tuple(self.findings, 0, 100, invalid)
        if any(type(value) is not Finding for value in findings):
            raise ProtocolValueError(invalid)
        obligations = _validate_tuple(self.obligations, 0, 100, invalid)
        if any(type(value) is not ReceiptObligation for value in obligations):
            raise ProtocolValueError(invalid)
        responses = _validate_tuple(self.responses, 0, 100, invalid)
        if any(type(value) is not ReceiptResponse for value in responses):
            raise ProtocolValueError(invalid)
        claim_values = _validate_tuple(self.claim_refs, 0, 100, invalid)
        claims = tuple(claim_id(value) for value in claim_values)
        _validate_sorted_unique_strings(cast(tuple[str, ...], claims))
        object.__setattr__(self, "claim_refs", claims)
        evidence_values = _validate_tuple(self.evidence_refs, 0, 100, invalid)
        evidence = tuple(evidence_id(value) for value in evidence_values)
        _validate_sorted_unique_strings(cast(tuple[str, ...], evidence))
        object.__setattr__(self, "evidence_refs", evidence)
        gaps = _validate_tuple(self.gaps, 0, 64, invalid)
        if any(type(value) is not ReceiptGap for value in gaps):
            raise ProtocolValueError(invalid)
        redactions = _validate_tuple(self.redactions, 0, 64, invalid)
        if any(type(value) is not ReceiptRedaction for value in redactions):
            raise ProtocolValueError(invalid)
        sections = _validate_tuple(self.sections, 3, 6, invalid)
        if any(type(value) is not ReceiptSection for value in sections):
            raise ProtocolValueError(invalid)
        if type(self.children) is not ReceiptChildren:
            raise ProtocolValueError(invalid)
        receipt_schema_version = _receipt_document_artifact_version(self.versions)
        if self.children.children and receipt_schema_version != "1.3.0":
            raise ProtocolValueError("receipt_children_schema_version")
        carried_ids = frozenset(
            finding.finding_id for finding in cast(tuple[Finding, ...], findings)
        )
        for name in _TERMINAL_ID_FIELDS:
            raw_ids = _validate_tuple(getattr(self, name), 0, 100, invalid)
            ids = tuple(finding_id(value) for value in raw_ids)
            _validate_sorted_unique_strings(cast(tuple[str, ...], ids))
            if ids and (receipt_schema_version != "1.3.0" or not carried_ids.issuperset(ids)):
                raise ProtocolValueError(invalid)
            object.__setattr__(self, name, ids)
        terminal_ids = [
            str(item)
            for name in _TERMINAL_ID_FIELDS
            for item in cast(tuple[FindingId, ...], getattr(self, name))
        ]
        if len(terminal_ids) != len(set(terminal_ids)):
            raise ProtocolValueError(invalid)
        if (
            self.self_verified_finding_ids
            or self.disputed_after_rebuttal_finding_ids
            or self.limitation_disclosed_finding_ids
        ) and self.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS:
            # A repair only the agent verified (issue #984), a finding the reviewer still holds
            # against the agent's rebuttal (issue #1020), or a verification limit the agent
            # disclosed (ADR-046), never reads as clean.
            raise ProtocolValueError("invalid_receipt_conclusion")
        if self.conclusion_basis is not None and (
            type(self.conclusion_basis) is not ReceiptConclusionBasis
            or _receipt_document_artifact_version(self.versions) != "1.3.0"
            or (self.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS)
            != (self.conclusion_basis.reason_total == 0)
        ):
            raise ProtocolValueError(invalid)
        links = _validate_tuple(self.duplicate_finding_links, 0, 100, invalid)
        if any(type(value) is not ReceiptDuplicateLink for value in links):
            raise ProtocolValueError(invalid)
        linked = tuple(
            str(item.finding_id) for item in cast(tuple[ReceiptDuplicateLink, ...], links)
        )
        _validate_sorted_unique_strings(linked)
        if links and (receipt_schema_version != "1.3.0" or not carried_ids.issuperset(linked)):
            raise ProtocolValueError(invalid)
        disputed = tuple(
            finding_id(value)
            for value in _validate_tuple(self.premise_disputed_finding_ids, 0, 100, invalid)
        )
        _validate_sorted_unique_strings(cast(tuple[str, ...], disputed))
        if not set(disputed) <= set(self.acknowledged_not_done_finding_ids):
            raise ProtocolValueError(invalid)
        object.__setattr__(self, "premise_disputed_finding_ids", disputed)
        acknowledged_obligations = tuple(
            obligation_id(value)
            for value in _validate_tuple(self.acknowledged_not_done_obligation_ids, 0, 100, invalid)
        )
        _validate_sorted_unique_strings(cast(tuple[str, ...], acknowledged_obligations))
        if acknowledged_obligations and receipt_schema_version != "1.3.0":
            raise ProtocolValueError(invalid)
        object.__setattr__(self, "acknowledged_not_done_obligation_ids", acknowledged_obligations)
        if (
            acknowledged_obligations
            and self.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
        ):
            # An obligation the agent will not do never reads as clean (issue #997).
            raise ProtocolValueError("invalid_receipt_conclusion")
        disclosures = _validate_tuple(self.disclosed_assumptions, 0, 64, invalid)
        if any(type(value) is not ReceiptDisclosure for value in disclosures):
            raise ProtocolValueError(invalid)
        disclosure_keys = tuple(
            (str(item.obligation_id).encode(), item.kind.encode())
            for item in cast(tuple[ReceiptDisclosure, ...], disclosures)
        )
        if disclosure_keys != tuple(sorted(set(disclosure_keys))) or (
            disclosures and receipt_schema_version != "1.3.0"
        ):
            raise ProtocolValueError(invalid)
        withheld = _validate_tuple(self.semantic_withheld_items, 0, 64, invalid)
        if any(type(value) is not ReceiptSemanticWithheldItem for value in withheld):
            raise ProtocolValueError(invalid)
        typed_withheld = cast(tuple[ReceiptSemanticWithheldItem, ...], withheld)
        withheld_ids = tuple(item.item_id for item in typed_withheld)
        if withheld_ids != tuple(sorted(set(withheld_ids), key=str.encode)):
            raise ProtocolValueError("receipt_semantic_withheld_items_not_canonical")
        section_keys = tuple(cast(ReceiptSection, section).key for section in sections)
        if section_keys not in _VALID_SECTION_KEY_SEQUENCES:
            raise ProtocolValueError("invalid_receipt_section_order")
        if (
            self.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
            and self.suppressed_finding_count != 0
        ):
            raise ProtocolValueError(invalid)
        # Resolved rows stay in ``findings`` as history, named by the summary section's items,
        # but a later qualifying check proved each such issue absent, so only current rows bound
        # the document coverage (issue #912). Documents that also folded resolved rows still
        # satisfy this weaker requirement, so issued receipts stay readable as issued.
        resolved = _summary_resolved_ids(cast(tuple[ReceiptSection, ...], sections))
        material_coverage = self.coverage
        for finding in cast(tuple[Finding, ...], findings):
            if finding.finding_id in resolved:
                continue
            material_coverage = weakest(material_coverage, finding.coverage)
        if material_coverage != self.coverage:
            raise ProtocolValueError("receipt_coverage_mismatch")
        for gap in cast(tuple[ReceiptGap, ...], gaps):
            if gap.code not in self.coverage.known_gaps:
                raise ProtocolValueError("receipt_gap_not_in_coverage")
            if gap.effect is not None and (
                _receipt_document_artifact_version(self.versions) != "1.3.0"
                or (
                    gap.effect is ReceiptGapEffect.BOUNDS
                    and self.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
                )
            ):
                # A clean conclusion beside a gap that bounds it is a contradiction (ADR-046).
                raise ProtocolValueError("invalid_receipt_gap")
        # Issue #1017: a historical gap is written only by the 1.3.0 artifact, and a code is
        # either live or historical on one receipt, never both.
        historical_codes = {gap.code for gap in cast(tuple[ReceiptGap, ...], gaps) if not gap.live}
        if historical_codes and (
            receipt_schema_version != "1.3.0"
            or historical_codes
            & {gap.code for gap in cast(tuple[ReceiptGap, ...], gaps) if gap.live}
        ):
            raise ProtocolValueError("invalid_receipt_gap")


def _policy_version_from_json(value: object) -> PolicyVersionEntry:
    invalid = "invalid_receipt_version_slice"
    source = _closed_object(
        value,
        frozenset({"policy_id", "policy_version"}),
        frozenset(),
        invalid,
    )
    return PolicyVersionEntry(
        policy_id=cast(str, _field(source, "policy_id", invalid)),
        policy_version=cast(str, _field(source, "policy_version", invalid)),
    )


def _schema_version_from_json(value: object) -> SchemaVersionEntry:
    invalid = "invalid_receipt_version_slice"
    source = _closed_object(
        value,
        frozenset({"schema_id", "schema_version"}),
        frozenset(),
        invalid,
    )
    return SchemaVersionEntry(
        schema_id=cast(str, _field(source, "schema_id", invalid)),
        schema_version=cast(str, _field(source, "schema_version", invalid)),
    )


def _version_slice_from_json(value: object) -> ReceiptVersionSlice:
    invalid = "invalid_receipt_version_slice"
    keys = frozenset(
        {
            "package_name",
            "package_version",
            "protocol_version",
            "engine_version",
            "projection_version",
            "object_format_version",
            "catalog_schema_version",
            "bundle_schema_version",
            "policy_versions",
            "schema_versions",
            "resource_manifest_digest",
        }
    )
    source = _closed_object(value, keys, frozenset(), invalid)
    policies = tuple(
        _policy_version_from_json(item)
        for item in _array(_field(source, "policy_versions", invalid), invalid)
    )
    schemas = tuple(
        _schema_version_from_json(item)
        for item in _array(_field(source, "schema_versions", invalid), invalid)
    )
    return ReceiptVersionSlice(
        package_name=cast(Literal["yoetz"], _field(source, "package_name", invalid)),
        package_version=cast(str, _field(source, "package_version", invalid)),
        protocol_version=cast(str, _field(source, "protocol_version", invalid)),
        engine_version=cast(str, _field(source, "engine_version", invalid)),
        projection_version=cast(str, _field(source, "projection_version", invalid)),
        object_format_version=cast(str, _field(source, "object_format_version", invalid)),
        catalog_schema_version=cast(str, _field(source, "catalog_schema_version", invalid)),
        bundle_schema_version=cast(str, _field(source, "bundle_schema_version", invalid)),
        policy_versions=policies,
        schema_versions=schemas,
        resource_manifest_digest=cast(str, _field(source, "resource_manifest_digest", invalid)),
    )


def _obligation_from_json(value: object) -> ReceiptObligation:
    invalid = "invalid_receipt_obligation"
    source = _closed_object(
        value,
        frozenset({"obligation_id", "status", "source_refs"}),
        frozenset({"summary"}),
        invalid,
    )
    refs = tuple(
        _subject_ref(item, invalid)
        for item in _array(_field(source, "source_refs", invalid), invalid)
    )
    keys = frozenset(cast(tuple[str, ...], tuple(source)))
    return ReceiptObligation(
        obligation_id=obligation_id(_field(source, "obligation_id", invalid)),
        status=_enum_value(
            _field(source, "status", invalid),
            ReceiptObligationStatus,
            invalid,
        ),
        source_refs=refs,
        summary=(cast(str, _field(source, "summary", invalid)) if "summary" in keys else None),
    )


def _response_from_json(value: object) -> ReceiptResponse:
    invalid = "invalid_receipt_response"
    source = _closed_object(
        value,
        frozenset({"finding_id", "finding_frontier", "disposition", "evidence_refs"}),
        frozenset({"reason", "waiver_scope", "waiver_expiry"}),
        invalid,
    )
    keys = frozenset(cast(tuple[str, ...], tuple(source)))
    refs = tuple(
        _response_evidence_ref(item)
        for item in _array(_field(source, "evidence_refs", invalid), invalid)
    )
    return ReceiptResponse(
        finding_id=finding_id(_field(source, "finding_id", invalid)),
        finding_frontier=frontier_from_json(_field(source, "finding_frontier", invalid)),
        disposition=_enum_value(
            _field(source, "disposition", invalid),
            ResponseDisposition,
            invalid,
        ),
        evidence_refs=refs,
        reason=cast(str, _field(source, "reason", invalid)) if "reason" in keys else None,
        waiver_scope=(
            _enum_value(_field(source, "waiver_scope", invalid), WaiverScope, invalid)
            if "waiver_scope" in keys
            else None
        ),
        waiver_expiry=(
            timestamp_from_string(_field(source, "waiver_expiry", invalid))
            if "waiver_expiry" in keys
            else None
        ),
    )


def _gap_from_json(value: object) -> ReceiptGap:
    invalid = "invalid_receipt_gap"
    source = _closed_object(
        value,
        frozenset({"code", "subject_refs"}),
        frozenset({"detail", "status", "cleared_at_frontier", "effect"}),
        invalid,
    )
    keys = frozenset(cast(tuple[str, ...], tuple(source)))
    # Issue #1017: present only on a historical gap, together; absent reads as live.
    historical = "status" in keys
    if historical is not ("cleared_at_frontier" in keys) or (
        historical and _field(source, "status", invalid) != ReceiptGapStatus.HISTORICAL.value
    ):
        raise ProtocolValueError(invalid)
    refs = tuple(
        _subject_ref(item, invalid)
        for item in _array(_field(source, "subject_refs", invalid), invalid)
    )
    return ReceiptGap(
        code=cast(str, _field(source, "code", invalid)),
        subject_refs=refs,
        detail=cast(str, _field(source, "detail", invalid)) if "detail" in keys else None,
        status=ReceiptGapStatus.HISTORICAL if historical else ReceiptGapStatus.LIVE,
        cleared_at_frontier=(
            frontier_from_json(_field(source, "cleared_at_frontier", invalid))
            if historical
            else None
        ),
        effect=(
            _enum_value(_field(source, "effect", invalid), ReceiptGapEffect, invalid)
            if "effect" in keys
            else None
        ),
    )


def _conclusion_basis_from_json(value: object) -> ReceiptConclusionBasis:
    invalid = "invalid_receipt_document"
    source = _closed_object(value, frozenset({"reasons", "reason_total"}), frozenset(), invalid)
    reasons: list[ReceiptConclusionReason] = []
    for item in _array(_field(source, "reasons", invalid), invalid):
        reason = _closed_object(
            item,
            frozenset({"code", "rule", "count", "refs"}),
            frozenset({"since_frontier"}),
            invalid,
        )
        refs = _array(_field(reason, "refs", invalid), invalid)
        reasons.append(
            ReceiptConclusionReason(
                code=cast(str, _field(reason, "code", invalid)),
                rule=cast(str, _field(reason, "rule", invalid)),
                count=cast(int, _field(reason, "count", invalid)),
                refs=cast(tuple[str, ...], refs),
                since_frontier=(
                    cast(int, reason["since_frontier"]) if "since_frontier" in reason else None
                ),
            )
        )
    return ReceiptConclusionBasis(
        tuple(reasons), cast(int, _field(source, "reason_total", invalid))
    )


def _child_finding_from_json(value: object) -> ReceiptChildFinding:
    invalid = "invalid_receipt_child_finding"
    source = _closed_object(
        value,
        frozenset({"finding_id", "kind", "origin", "priority", "actionable", "resolved"}),
        frozenset({"resolution_event_id", "self_verified"}),
        invalid,
    )
    # Present only when true (issue #984).
    if "self_verified" in source and _field(source, "self_verified", invalid) is not True:
        raise ProtocolValueError(invalid)
    keys = frozenset(cast(tuple[str, ...], tuple(source)))
    return ReceiptChildFinding(
        finding_id=finding_id(_field(source, "finding_id", invalid)),
        kind=_enum_value(_field(source, "kind", invalid), FindingKind, invalid),
        origin=_enum_value(_field(source, "origin", invalid), FindingOrigin, invalid),
        priority=cast(int, _field(source, "priority", invalid)),
        actionable=cast(bool, _field(source, "actionable", invalid)),
        resolved=cast(bool, _field(source, "resolved", invalid)),
        resolution_event_id=(
            event_id(_field(source, "resolution_event_id", invalid))
            if "resolution_event_id" in keys
            else None
        ),
        self_verified="self_verified" in keys,
    )


def _child_outcome_from_json(value: object) -> ReceiptChildOutcome:
    invalid = "invalid_receipt_child_outcome"
    source = _closed_object(
        value,
        frozenset(
            {
                "child_task_id",
                "outcome",
                "tested_manifest_ref",
                "freshness",
                "findings",
            }
        ),
        frozenset({"later_manifest_ref"}),
        invalid,
    )
    keys = frozenset(cast(tuple[str, ...], tuple(source)))
    tested_raw = _field(source, "tested_manifest_ref", invalid)
    later_raw = (
        _field(source, "later_manifest_ref", invalid) if "later_manifest_ref" in keys else None
    )
    return ReceiptChildOutcome(
        child_task_id=task_id(_field(source, "child_task_id", invalid)),
        outcome=cast(
            Literal["clean", "annotated", "open_gap", "incomplete", "unavailable"],
            _field(source, "outcome", invalid),
        ),
        tested_manifest_ref=None if tested_raw is None else event_id(tested_raw),
        later_manifest_ref=None if later_raw is None else event_id(later_raw),
        freshness=cast(Literal["known", "unknown"], _field(source, "freshness", invalid)),
        findings=tuple(
            _child_finding_from_json(item)
            for item in _array(_field(source, "findings", invalid), invalid)
        ),
    )


def _children_from_json(value: object) -> ReceiptChildren:
    invalid = "invalid_receipt_children"
    source = _closed_object(value, frozenset({"children"}), frozenset(), invalid)
    return ReceiptChildren(
        tuple(
            _child_outcome_from_json(item)
            for item in _array(_field(source, "children", invalid), invalid)
        )
    )


def _redaction_from_json(value: object) -> ReceiptRedaction:
    invalid = "invalid_receipt_redaction"
    source = _closed_object(
        value,
        frozenset({"category", "reason", "count"}),
        frozenset(),
        invalid,
    )
    raw_count = _field(source, "count", invalid)
    if (
        type(raw_count) is not str
        or len(raw_count) > 16
        or _UNSIGNED_DECIMAL_RE.fullmatch(raw_count) is None
    ):
        raise ProtocolValueError(invalid)
    return ReceiptRedaction(
        category=_enum_value(
            _field(source, "category", invalid),
            ReceiptRedactionCategory,
            invalid,
        ),
        reason=_enum_value(
            _field(source, "reason", invalid),
            ReceiptRedactionReason,
            invalid,
        ),
        count=int(raw_count),
    )


def _section_from_json(value: object) -> ReceiptSection:
    invalid = "invalid_receipt_section"
    source = _closed_object(
        value,
        frozenset({"key", "title", "body", "items"}),
        frozenset({"coverage_note"}),
        invalid,
    )
    keys = frozenset(cast(tuple[str, ...], tuple(source)))
    items = tuple(cast(str, item) for item in _array(_field(source, "items", invalid), invalid))
    return ReceiptSection(
        key=_enum_value(_field(source, "key", invalid), ReceiptSectionKey, invalid),
        title=cast(str, _field(source, "title", invalid)),
        body=cast(str, _field(source, "body", invalid)),
        items=items,
        coverage_note=(
            cast(str, _field(source, "coverage_note", invalid)) if "coverage_note" in keys else None
        ),
    )


def _semantic_withheld_item_from_json(value: object) -> ReceiptSemanticWithheldItem:
    invalid = "invalid_receipt_semantic_withheld_item"
    source = _closed_object(
        value,
        frozenset({"item_id", "reason"}),
        frozenset(),
        invalid,
    )
    return ReceiptSemanticWithheldItem(
        item_id=cast(str, _field(source, "item_id", invalid)),
        reason=cast(Literal["never_send_heuristic"], _field(source, "reason", invalid)),
    )


def receipt_document_from_json(value: object) -> ReceiptDocument:
    """Decode the exact closed receipt-document schema into immutable domain values."""

    invalid = "receipt_json_shape_invalid"
    keys = frozenset(
        {
            "schema_version",
            "receipt_id",
            "task_id",
            "session_id",
            "generated_at",
            "subject_frontier",
            "conclusion",
            "suppressed_finding_count",
            "versions",
            "coverage",
            "findings",
            "obligations",
            "responses",
            "claim_refs",
            "evidence_refs",
            "gaps",
            "redactions",
            "sections",
        }
    )
    if not _is_actual_mapping(value):
        raise ProtocolValueError(invalid)
    raw_schema_version = _field(cast(Mapping[object, object], value), "schema_version", invalid)
    if raw_schema_version != "1.0.0":
        raise ProtocolValueError(invalid)
    # The artifact version is selected by the version slice.  Its 1.3.0 successor adds the
    # required ``children`` member while retaining the document's historical inner version.
    source = _closed_object(
        value,
        keys,
        frozenset(
            {
                "acknowledged_not_done_finding_ids",
                "acknowledged_not_done_obligation_ids",
                "children",
                "premise_disputed_finding_ids",
                "disclosed_assumptions",
                "duplicate_finding_links",
                "rejection_accepted_finding_ids",
                "self_verified_finding_ids",
                "disputed_after_rebuttal_finding_ids",
                "semantic_withheld_items",
                "semantic_redacted_values",
                "semantic_provenance",
                "limitation_disclosed_finding_ids",
                "conclusion_basis",
            }
        ),
        invalid,
    )
    raw_suppressed = _field(source, "suppressed_finding_count", invalid)
    if type(raw_suppressed) is not int:
        raise ProtocolValueError("invalid_receipt_document")
    findings = tuple(
        finding_from_json(freeze_json(item))
        for item in _array(_field(source, "findings", invalid), invalid)
    )
    obligations = tuple(
        _obligation_from_json(item)
        for item in _array(_field(source, "obligations", invalid), invalid)
    )
    responses = tuple(
        _response_from_json(item) for item in _array(_field(source, "responses", invalid), invalid)
    )
    claims = tuple(
        claim_id(item) for item in _array(_field(source, "claim_refs", invalid), invalid)
    )
    evidence = tuple(
        evidence_id(item) for item in _array(_field(source, "evidence_refs", invalid), invalid)
    )
    gaps = tuple(_gap_from_json(item) for item in _array(_field(source, "gaps", invalid), invalid))
    redactions = tuple(
        _redaction_from_json(item)
        for item in _array(_field(source, "redactions", invalid), invalid)
    )
    sections = tuple(
        _section_from_json(item) for item in _array(_field(source, "sections", invalid), invalid)
    )
    versions = _version_slice_from_json(_field(source, "versions", invalid))
    artifact_version = _receipt_document_artifact_version(versions)
    has_children = "children" in source
    if has_children and artifact_version != "1.3.0":
        raise ProtocolValueError("invalid_receipt_document")
    if not has_children and artifact_version == "1.3.0":
        raise ProtocolValueError("invalid_receipt_document")
    for name in (*_TERMINAL_ID_FIELDS, "duplicate_finding_links"):
        if name in source and not _array(source[name], invalid):
            raise ProtocolValueError(invalid)
    for name in (
        "disclosed_assumptions",
        "acknowledged_not_done_obligation_ids",
        "premise_disputed_finding_ids",
    ):
        if name in source and not _array(source[name], invalid):
            raise ProtocolValueError(invalid)
    semantic_provenance_value = (
        semantic_provenance_from_json(freeze_json(_field(source, "semantic_provenance", invalid)))
        if "semantic_provenance" in source
        else None
    )
    semantic_withheld_items = (
        tuple(
            _semantic_withheld_item_from_json(item)
            for item in _array(_field(source, "semantic_withheld_items", invalid), invalid)
        )
        if "semantic_withheld_items" in source
        else ()
    )
    try:
        semantic_redacted_values = (
            semantic_redacted_values_from_wire(
                _array(_field(source, "semantic_redacted_values", invalid), invalid)
            )
            if "semantic_redacted_values" in source
            else ()
        )
    except ValueError as exc:
        raise ProtocolValueError(invalid) from exc
    document = ReceiptDocument(
        receipt_id=receipt_id(_field(source, "receipt_id", invalid)),
        task_id=task_id(_field(source, "task_id", invalid)),
        session_id=session_id(_field(source, "session_id", invalid)),
        generated_at=timestamp_from_string(_field(source, "generated_at", invalid)),
        subject_frontier=frontier_from_json(_field(source, "subject_frontier", invalid)),
        conclusion=_enum_value(
            _field(source, "conclusion", invalid),
            ReceiptConclusion,
            "invalid_receipt_conclusion",
        ),
        suppressed_finding_count=raw_suppressed,
        versions=versions,
        coverage=coverage_from_json(cast(CanonicalJsonValue, _field(source, "coverage", invalid))),
        findings=findings,
        obligations=obligations,
        responses=responses,
        claim_refs=claims,
        evidence_refs=evidence,
        gaps=gaps,
        redactions=redactions,
        sections=sections,
        semantic_provenance=semantic_provenance_value,
        children=(
            _children_from_json(_field(source, "children", invalid))
            if has_children
            else ReceiptChildren()
        ),
        acknowledged_not_done_finding_ids=tuple(
            finding_id(item)
            for item in _array(source.get("acknowledged_not_done_finding_ids", ()), invalid)
        ),
        rejection_accepted_finding_ids=tuple(
            finding_id(item)
            for item in _array(source.get("rejection_accepted_finding_ids", ()), invalid)
        ),
        self_verified_finding_ids=tuple(
            finding_id(item)
            for item in _array(source.get("self_verified_finding_ids", ()), invalid)
        ),
        disputed_after_rebuttal_finding_ids=tuple(
            finding_id(item)
            for item in _array(source.get("disputed_after_rebuttal_finding_ids", ()), invalid)
        ),
        duplicate_finding_links=tuple(
            _duplicate_link_from_json(item, invalid)
            for item in _array(source.get("duplicate_finding_links", ()), invalid)
        ),
        semantic_withheld_items=semantic_withheld_items,
        semantic_redacted_values=semantic_redacted_values,
        disclosed_assumptions=tuple(
            _disclosure_from_json(item)
            for item in _array(source.get("disclosed_assumptions", ()), invalid)
        ),
        acknowledged_not_done_obligation_ids=tuple(
            obligation_id(item)
            for item in _array(source.get("acknowledged_not_done_obligation_ids", ()), invalid)
        ),
        premise_disputed_finding_ids=tuple(
            finding_id(item)
            for item in _array(source.get("premise_disputed_finding_ids", ()), invalid)
        ),
        limitation_disclosed_finding_ids=tuple(
            finding_id(item)
            for item in _array(source.get("limitation_disclosed_finding_ids", ()), invalid)
        ),
        conclusion_basis=(
            _conclusion_basis_from_json(source["conclusion_basis"])
            if "conclusion_basis" in source
            else None
        ),
    )
    return document


def _duplicate_link_from_json(value: object, invalid: str) -> ReceiptDuplicateLink:
    source = _closed_object(
        value, frozenset({"finding_id", "duplicate_of_finding_id"}), frozenset(), invalid
    )
    return ReceiptDuplicateLink(
        finding_id=finding_id(_field(source, "finding_id", invalid)),
        duplicate_of_finding_id=finding_id(_field(source, "duplicate_of_finding_id", invalid)),
    )


def _disclosure_from_json(value: object) -> ReceiptDisclosure:
    invalid = "invalid_receipt_document"
    keys = frozenset({"obligation_id", "kind", "decision_event_id"})
    source = _closed_object(value, keys, frozenset(), invalid)
    return ReceiptDisclosure(
        obligation_id=obligation_id(_field(source, "obligation_id", invalid)),
        kind=cast(str, _field(source, "kind", invalid)),
        decision_event_id=event_id(_field(source, "decision_event_id", invalid)),
    )


def _frontier_to_json(frontier: Frontier) -> dict[str, object]:
    return {key: value for key, value in frontier.as_wire().items()}


def _version_slice_to_json(value: ReceiptVersionSlice) -> dict[str, object]:
    return {
        "package_name": value.package_name,
        "package_version": value.package_version,
        "protocol_version": value.protocol_version,
        "engine_version": value.engine_version,
        "projection_version": value.projection_version,
        "object_format_version": value.object_format_version,
        "catalog_schema_version": value.catalog_schema_version,
        "bundle_schema_version": value.bundle_schema_version,
        "policy_versions": [
            {"policy_id": entry.policy_id, "policy_version": entry.policy_version}
            for entry in value.policy_versions
        ],
        "schema_versions": [
            {"schema_id": entry.schema_id, "schema_version": entry.schema_version}
            for entry in value.schema_versions
        ],
        "resource_manifest_digest": value.resource_manifest_digest,
    }


def _obligation_to_json(value: ReceiptObligation) -> dict[str, object]:
    result: dict[str, object] = {
        "obligation_id": value.obligation_id,
        "status": value.status.value,
        "source_refs": list(value.source_refs),
    }
    if value.summary is not None:
        result["summary"] = value.summary
    return result


def _response_to_json(value: ReceiptResponse) -> dict[str, object]:
    result: dict[str, object] = {
        "finding_id": value.finding_id,
        "finding_frontier": _frontier_to_json(value.finding_frontier),
        "disposition": value.disposition.value,
        "evidence_refs": list(value.evidence_refs),
    }
    if value.reason is not None:
        result["reason"] = value.reason
    if value.waiver_scope is not None:
        result["waiver_scope"] = value.waiver_scope.value
    if value.waiver_expiry is not None:
        result["waiver_expiry"] = value.waiver_expiry.wire
    return result


def _gap_to_json(value: ReceiptGap) -> dict[str, object]:
    result: dict[str, object] = {"code": value.code, "subject_refs": list(value.subject_refs)}
    if value.detail is not None:
        result["detail"] = value.detail
    if value.cleared_at_frontier is not None:
        result["status"] = value.status.value
        result["cleared_at_frontier"] = _frontier_to_json(value.cleared_at_frontier)
    if value.effect is not None:
        result["effect"] = value.effect.value
    return result


def _redaction_to_json(value: ReceiptRedaction) -> dict[str, object]:
    return {
        "category": value.category.value,
        "reason": value.reason.value,
        "count": str(value.count),
    }


def _section_to_json(value: ReceiptSection) -> dict[str, object]:
    result: dict[str, object] = {
        "key": value.key.value,
        "title": value.title,
        "body": value.body,
        "items": list(value.items),
    }
    if value.coverage_note is not None:
        result["coverage_note"] = value.coverage_note
    return result


def _child_finding_to_json(value: ReceiptChildFinding) -> dict[str, object]:
    result: dict[str, object] = {
        "finding_id": value.finding_id,
        "kind": value.kind.value,
        "origin": value.origin.value,
        "priority": value.priority,
        "actionable": value.actionable,
        "resolved": value.resolved,
    }
    if value.resolution_event_id is not None:
        result["resolution_event_id"] = value.resolution_event_id
    if value.self_verified:
        result["self_verified"] = True
    return result


def _children_to_json(value: ReceiptChildren) -> dict[str, object]:
    return {
        "children": [
            {
                "child_task_id": child.child_task_id,
                "outcome": child.outcome,
                "tested_manifest_ref": child.tested_manifest_ref,
                **(
                    {}
                    if child.later_manifest_ref is None
                    else {"later_manifest_ref": child.later_manifest_ref}
                ),
                "freshness": child.freshness,
                "findings": [_child_finding_to_json(finding) for finding in child.findings],
            }
            for child in value.children
        ]
    }


def receipt_document_to_json(document: ReceiptDocument) -> dict[str, object]:
    """Encode a receipt document as the exact closed schema object."""

    if type(document) is not ReceiptDocument:
        raise ProtocolValueError("invalid_receipt_document")
    result: dict[str, object] = {
        "schema_version": document.schema_version,
        "receipt_id": document.receipt_id,
        "task_id": document.task_id,
        "session_id": document.session_id,
        "generated_at": document.generated_at.wire,
        "subject_frontier": _frontier_to_json(document.subject_frontier),
        "conclusion": document.conclusion.value,
        "suppressed_finding_count": document.suppressed_finding_count,
        "versions": _version_slice_to_json(document.versions),
        "coverage": coverage_to_json(document.coverage),
        "findings": [finding_to_json(finding) for finding in document.findings],
        "obligations": [_obligation_to_json(value) for value in document.obligations],
        "responses": [_response_to_json(value) for value in document.responses],
        "claim_refs": list(document.claim_refs),
        "evidence_refs": list(document.evidence_refs),
        "gaps": [_gap_to_json(value) for value in document.gaps],
        "redactions": [_redaction_to_json(value) for value in document.redactions],
        "sections": [_section_to_json(value) for value in document.sections],
    }
    if _receipt_document_artifact_version(document.versions) == "1.3.0":
        result["children"] = _children_to_json(document.children)
    if document.acknowledged_not_done_finding_ids:
        result["acknowledged_not_done_finding_ids"] = list(
            document.acknowledged_not_done_finding_ids
        )
    if document.rejection_accepted_finding_ids:
        result["rejection_accepted_finding_ids"] = list(document.rejection_accepted_finding_ids)
    if document.self_verified_finding_ids:
        result["self_verified_finding_ids"] = list(document.self_verified_finding_ids)
    if document.disputed_after_rebuttal_finding_ids:
        result["disputed_after_rebuttal_finding_ids"] = list(
            document.disputed_after_rebuttal_finding_ids
        )
    if document.limitation_disclosed_finding_ids:
        result["limitation_disclosed_finding_ids"] = list(document.limitation_disclosed_finding_ids)
    if document.conclusion_basis is not None:
        result["conclusion_basis"] = {
            "reasons": [
                {
                    "code": item.code,
                    "rule": item.rule,
                    "count": item.count,
                    "refs": list(item.refs),
                    **(
                        {}
                        if item.since_frontier is None
                        else {"since_frontier": item.since_frontier}
                    ),
                }
                for item in document.conclusion_basis.reasons
            ],
            "reason_total": document.conclusion_basis.reason_total,
        }
    if document.duplicate_finding_links:
        result["duplicate_finding_links"] = [
            {"finding_id": item.finding_id, "duplicate_of_finding_id": item.duplicate_of_finding_id}
            for item in document.duplicate_finding_links
        ]
    if document.premise_disputed_finding_ids:
        result["premise_disputed_finding_ids"] = list(document.premise_disputed_finding_ids)
    if document.acknowledged_not_done_obligation_ids:
        result["acknowledged_not_done_obligation_ids"] = list(
            document.acknowledged_not_done_obligation_ids
        )
    if document.disclosed_assumptions:
        result["disclosed_assumptions"] = [
            {
                "obligation_id": item.obligation_id,
                "kind": item.kind,
                "decision_event_id": item.decision_event_id,
            }
            for item in document.disclosed_assumptions
        ]
    if document.semantic_withheld_items:
        result["semantic_withheld_items"] = [
            {"item_id": item.item_id, "reason": item.reason}
            for item in document.semantic_withheld_items
        ]
    if document.semantic_redacted_values:
        result["semantic_redacted_values"] = [
            item.as_wire() for item in document.semantic_redacted_values
        ]
    # Omit absent provenance rather than emitting null: local-only and historical receipt
    # documents therefore retain their exact pre-extension bytes.
    if document.semantic_provenance is not None:
        result["semantic_provenance"] = semantic_provenance_to_json(document.semantic_provenance)
    return result


def receipt_weakest_coverage(document: ReceiptDocument) -> Coverage:
    """Fold the document coverage with its current (not resolved) findings in stored order.

    Resolved history does not lower the conclusion (issue #912); see ``ReceiptDocument``.
    """

    if type(document) is not ReceiptDocument:
        raise ProtocolValueError("invalid_receipt_document")
    resolved = resolved_finding_ids_for_render(document)
    result = document.coverage
    for finding in document.findings:
        if finding.finding_id in resolved:
            continue
        result = weakest(result, finding.coverage)
    return result


def _summary_resolved_ids(sections: tuple[ReceiptSection, ...]) -> frozenset[str]:
    summary = next(
        (section for section in sections if section.key is ReceiptSectionKey.SUMMARY),
        None,
    )
    if summary is None:
        return frozenset()
    return frozenset(item for item in summary.items if item.startswith("fnd_"))


def resolved_finding_ids_for_render(document: ReceiptDocument) -> frozenset[str]:
    """The finding ids the summary section names as resolved by a later qualifying check.

    The frozen receipt document carries no per-finding resolution flag; the builder records the
    resolved historical ids as the summary section's items, which every include level carries.
    """

    return _summary_resolved_ids(document.sections)


def unresolved_findings_for_render(document: ReceiptDocument) -> tuple[Finding, ...]:
    """Current (not resolved) finding rows, in document order.

    A ``rejection_accepted`` row (issue #905), a ``self_verified`` row (issue #984) or a
    ``disputed_after_rebuttal`` row (issue #1020) is unresolved but settled: it has its own
    section and does not count here.
    """

    resolved = resolved_finding_ids_for_render(document)
    settled = frozenset(
        (
            *document.rejection_accepted_finding_ids,
            *document.self_verified_finding_ids,
            *document.disputed_after_rebuttal_finding_ids,
        )
    )
    return tuple(
        finding
        for finding in document.findings
        if finding.finding_id not in resolved and finding.finding_id not in settled
    )


def live_receipt_gap_codes(document: ReceiptDocument) -> tuple[str, ...]:
    """Coverage gap codes that still bound this receipt, in coverage order (issue #1017).

    A ``historical`` gap (a later check no longer carried it) stays in the document's coverage
    and its gap rows, but it is never a current limitation, so counts and lists exclude it.
    """

    historical = {gap.code for gap in document.gaps if not gap.live}
    return tuple(code for code in document.coverage.known_gaps if code not in historical)


def historical_receipt_gaps(document: ReceiptDocument) -> tuple[ReceiptGap, ...]:
    """The gap rows a later check cleared, in document order (issue #1017)."""

    return tuple(gap for gap in document.gaps if not gap.live)


def historical_gap_line(gap: ReceiptGap, *, markdown: bool) -> str:
    """One fixed line for a historical gap: its code and the frontier that cleared it.

    The live gap sentence is deliberately not repeated: several carry repair instructions ("run
    it as recorded", "link that run") that would steer an agent to redo work the latest check
    already cleared (Codex review round 3).
    """

    assert gap.cleared_at_frontier is not None
    code = f"`{gap.code}`" if markdown else gap.code
    return f"- {code}: cleared at frontier {gap.cleared_at_frontier.sequence}; no action needed."


_WIRE_SEQUENCE_RE: Final = re.compile(r"^(?:0|[1-9][0-9]{0,18})$", re.ASCII)


def historical_gaps_from_wire(document: object) -> tuple[tuple[str, str], ...]:
    """``(code, cleared-at sequence)`` for each historical gap row of a receipt document wire.

    For surfaces that hold only the JSON document (CLI, MCP summary). Each value is re-gated
    against its closed shape; a malformed row is skipped, never echoed (issue #1017).
    """

    if not _is_actual_mapping(document):
        return ()
    raw_gaps = cast(Mapping[object, object], document).get("gaps")
    if not isinstance(raw_gaps, (list, tuple)):
        return ()
    result: list[tuple[str, str]] = []
    for raw in cast(Sequence[object], raw_gaps):
        if not _is_actual_mapping(raw):
            continue
        row = cast(Mapping[object, object], raw)
        code = row.get("code")
        frontier = row.get("cleared_at_frontier")
        if row.get("status") != ReceiptGapStatus.HISTORICAL.value or not _is_actual_mapping(
            frontier
        ):
            continue
        sequence = cast(Mapping[object, object], frontier).get("sequence")
        if (
            type(code) is str
            and _GAP_CODE_RE.fullmatch(code) is not None
            and type(sequence) is str
            and _WIRE_SEQUENCE_RE.fullmatch(sequence) is not None
        ):
            result.append((code, sequence))
    return tuple(result)


def _waiver_for_render(document: ReceiptDocument) -> ReceiptResponse | None:
    for response in document.responses:
        if response.disposition is ResponseDisposition.WAIVED:
            return response
    return None


def _declared_none_reason_for_render(document: ReceiptDocument) -> str | None:
    """Return a closed empty-scope reason, never arbitrary receipt detail."""

    for gap in document.gaps:
        if (
            gap.code == COMPLETION_SCOPE_DECLARED_NONE_GAP
            and gap.detail in _NO_OBLIGATIONS_REASON_VALUES
        ):
            return gap.detail
    return None


_HUMAN_TEXT_MAX: Final = 32_768
_HUMAN_TEXT_MARKER_RESERVE: Final = 900
_HUMAN_TEXT_MARKER_NAMES: Final = 10
# Who is granted room first when a long receipt must be shortened (tb4n3 RC-2, A7). Every section
# keeps at least its heading and a "not shown" line, so no section silently disappears; these
# ranks only decide whose text is cut first. Disclosures that keep a receipt from reading clean
# outrank the narrative sections.
_HUMAN_BLOCK_RANK: Final[Mapping[str, int]] = MappingProxyType(
    {
        "Summary": 0,
        "Limitations": 1,
        "Outstanding work": 3,
        "Findings": 4,
        "Evidence basis": 8,
        "Versions and policy": 9,
    }
)
_HUMAN_DISCLOSURE_RANK: Final = 2
_HUMAN_DEFAULT_RANK: Final = 6


def _human_block_name(block: str) -> str:
    return block.split("\n", 1)[0].lstrip("#").strip()


def _human_block_rank(name: str, history_title: str) -> int:
    known = _HUMAN_BLOCK_RANK.get(name)
    if known is not None:
        return known
    if name == history_title:
        return 5
    if name in {"Children", "Coverage limitations", "Recovery"}:
        return _HUMAN_DEFAULT_RANK
    # The remaining blocks are the by-id disclosures: acknowledged, self-verified, disputed,
    # rejection accepted, duplicate links, premise disputes, assumptions, withheld items.
    return _HUMAN_DISCLOSURE_RANK


def _cut_human_block(block: str, budget: int) -> str:
    """Cut ``block`` at a line boundary within ``budget`` characters and say how much is left."""

    lines = block.split("\n")
    kept: list[str] = []
    used = 0
    for line in lines:
        if used + len(line) + 1 > budget - 48:
            break
        kept.append(line)
        used += len(line) + 1
    rest = len(lines) - len(kept)
    if rest == 0:
        return block
    if len(kept) <= 1 and rest > 0:
        # One long body line: keep the start of it rather than only the heading.
        room = budget - used - 48
        if room > 80 and len(lines) > len(kept):
            kept.append(clip_to_limit(lines[len(kept)], room, marker=" [...]", ascii_only=False))
            rest -= 1
    if rest:
        kept.append(f"[... {rest} more line(s) not shown]")
    return "\n".join(kept)


def _human_block_variants(block: str) -> tuple[str, ...]:
    """The block whole, then progressively shorter line-boundary cuts, then its heading alone."""

    variants = [block]
    for budget in (12_000, 4_000, 1_500, 600):
        cut = _cut_human_block(block, budget)
        if len(cut) < len(variants[-1]):
            variants.append(cut)
    heading = block.split("\n", 1)[0]
    stub = f"{heading}\n[section content not shown]"
    if len(stub) < len(variants[-1]):
        variants.append(stub)
    return tuple(variants)


def _bound_human_text(parts: list[str], history_title: str) -> str:
    """Join the blocks, shortening by section when they exceed the bound (tb4n3 RC-2, A7).

    The old cut took the head of the joined text, so a long receipt silently lost whichever
    sections came last -- the by-id disclosures, the coverage limitations and the recovery lines
    -- under a generic marker. Each block now keeps at least its heading and a line saying its
    content was not shown, disclosures and limitations are shortened last, and the marker names
    every shortened section.
    """

    text = "\n\n".join(parts)
    if len(text) <= _HUMAN_TEXT_MAX:
        return text
    names = [_human_block_name(part) for part in parts]
    blocks = [
        Part(
            _human_block_variants(part),
            required=True,
            priority=_human_block_rank(name, history_title),
        )
        for part, name in zip(parts, names, strict=True)
    ]
    composed = compose_parts(
        blocks,
        _HUMAN_TEXT_MAX - _HUMAN_TEXT_MARKER_RESERVE,
        sep="\n\n",
        ascii_only=False,
    )
    shortened = [names[index] for index in composed.shortened]
    listed = ", ".join(shortened[:_HUMAN_TEXT_MARKER_NAMES])
    if len(shortened) > _HUMAN_TEXT_MARKER_NAMES:
        listed += f" and {len(shortened) - _HUMAN_TEXT_MARKER_NAMES} more"
    marker = (
        "\n\n[Receipt human_text truncated at 32768 characters; "
        + (f"shortened sections: {listed}. " if listed else "")
        + ("Remaining text was cut. " if composed.cut_required else "")
        + "The structured receipt (format json) holds every section in full.]"
    )
    return (
        clip_to_limit(composed.text, _HUMAN_TEXT_MAX - len(marker), marker="...", ascii_only=False)
        + marker
    )


def _semantic_recovery_lines(document: ReceiptDocument) -> list[str]:
    """Reconstruct registry recovery from recorded provenance, never provider text."""

    provenance = document.semantic_provenance
    if provenance is None:
        return []
    token = continuation_for_semantic_outcome(
        status=provenance.status,
        reason=provenance.reason,
        failure_class=provenance.failure_class,
    )
    directive = directive_for(token)
    if directive is None:
        return []
    return [f"Continuation: {directive.token}", f"Next: {directive.directive}"]


def render_receipt_human(document: ReceiptDocument, *, markdown: bool) -> str:
    """Project the canonical receipt sections into markdown or plain-text ``human_text``.

    JSON receipts carry the structured document; markdown/text receipts keep ``document``
    null by format and must still expose limitations and finding-count distinctions here
    (#437, #429). Compact one-line wording remains ``render_receipt_compact``.
    """

    if type(document) is not ReceiptDocument or type(markdown) is not bool:
        raise ProtocolValueError("invalid_receipt_document")
    parts: list[str] = []
    for section in document.sections:
        heading = f"## {section.title}" if markdown else section.title
        section_parts = [heading, section.body]
        if section.items:
            section_parts.extend(f"- {item}" for item in section.items)
        if section.coverage_note is not None:
            section_parts.append(section.coverage_note)
        parts.append("\n".join(section_parts))
    historical = historical_receipt_gaps(document)
    history_block: str | None = None
    if historical:
        heading = (
            f"## {HISTORICAL_GAPS_SECTION_TITLE}" if markdown else HISTORICAL_GAPS_SECTION_TITLE
        )
        history_block = "\n".join(
            (
                heading,
                "An earlier check carried these gaps and a later check no longer did. They "
                "stay on the record but are not current limitations and do not bound this "
                "receipt's conclusion.",
                *(historical_gap_line(gap, markdown=markdown) for gap in historical),
            )
        )
        parts.append(history_block)
    if _receipt_document_artifact_version(document.versions) == "1.3.0":
        heading = "## Children" if markdown else "Children"
        child_parts = [heading]
        if not document.children.children:
            child_parts.append("No direct child dependencies were recorded.")
        else:
            child_parts.append("Direct child dependency outcomes:")
            for child in document.children.children:
                finding_ids = tuple(str(item.finding_id) for item in child.findings)
                findings = ", ".join(finding_ids) if finding_ids else "none"
                tested = (
                    "none" if child.tested_manifest_ref is None else str(child.tested_manifest_ref)
                )
                later = (
                    "none" if child.later_manifest_ref is None else str(child.later_manifest_ref)
                )
                child_parts.append(
                    f"- {child.child_task_id}: outcome={child.outcome}; "
                    f"freshness={child.freshness}; tested_manifest={tested}; "
                    f"later_manifest={later}; findings={findings}"
                )
                child_parts.extend(
                    f"  - {item.finding_id}: {CHILD_SELF_VERIFIED_NOTE}"
                    for item in child.findings
                    if item.self_verified
                )
        parts.append("\n".join(child_parts))
    if document.acknowledged_not_done_finding_ids:
        heading = "## Acknowledged, not done" if markdown else "Acknowledged, not done"
        parts.append(
            "\n".join(
                (
                    heading,
                    "The agent recorded these findings as acknowledged and not done, each with a "
                    "reason. They remain unresolved and keep this receipt from reading clean.",
                    *(f"- {item}" for item in document.acknowledged_not_done_finding_ids),
                )
            )
        )
    if document.rejection_accepted_finding_ids:
        heading = "## Rejection accepted" if markdown else "Rejection accepted"
        parts.append(
            "\n".join(
                (
                    heading,
                    "The agent rejected these AI-powered findings with a reason and a later "
                    "review withdrew them. They are not resolved and stay on the record.",
                    *(f"- {item}" for item in document.rejection_accepted_finding_ids),
                )
            )
        )
    if document.self_verified_finding_ids:
        heading = f"## {SELF_VERIFIED_SECTION_TITLE}" if markdown else SELF_VERIFIED_SECTION_TITLE
        parts.append(
            "\n".join(
                (
                    heading,
                    "The agent repaired these findings and verified each repair itself, citing "
                    "its own recorded evidence, because Yoetz could not prove the repair. They "
                    "are not resolved by Yoetz and keep this receipt from reading clean.",
                    *(f"- {item}" for item in document.self_verified_finding_ids),
                )
            )
        )
    if document.limitation_disclosed_finding_ids:
        heading = (
            f"## {VERIFICATION_LIMITS_SECTION_TITLE}"
            if markdown
            else VERIFICATION_LIMITS_SECTION_TITLE
        )
        parts.append(
            "\n".join(
                (
                    heading,
                    "The reviewer asked the agent to state that these requirements cannot be "
                    "verified in this environment, and the agent disclosed each one. They are "
                    "not resolved and not clean: they are limits on what this receipt can "
                    "establish, listed here by id.",
                    *(f"- {item}" for item in document.limitation_disclosed_finding_ids),
                )
            )
        )
    if document.disputed_after_rebuttal_finding_ids:
        heading = (
            f"## {DISPUTED_AFTER_REBUTTAL_SECTION_TITLE}"
            if markdown
            else DISPUTED_AFTER_REBUTTAL_SECTION_TITLE
        )
        parts.append(
            "\n".join(
                (
                    heading,
                    "The agent rejected these AI-powered findings with a reason, and the reviewer "
                    "kept them open without citing anything recorded after that rejection. The "
                    "reviewer and the agent disagree; these are not agent work, are not resolved, "
                    "and keep this receipt from reading clean.",
                    *(f"- {item}" for item in document.disputed_after_rebuttal_finding_ids),
                )
            )
        )
    if document.duplicate_finding_links:
        heading = (
            f"## {DUPLICATE_LINKS_SECTION_TITLE}" if markdown else DUPLICATE_LINKS_SECTION_TITLE
        )
        parts.append(
            "\n".join(
                (
                    heading,
                    "The agent linked these findings to an earlier finding that names the same "
                    "issue. A link never resolves a finding by itself: each stays open until its "
                    "own check proves it absent, or carries the earlier finding's not-done or "
                    "self-verified answer.",
                    *(
                        f"- {item.finding_id} duplicates {item.duplicate_of_finding_id}"
                        for item in document.duplicate_finding_links
                    ),
                )
            )
        )
    if document.premise_disputed_finding_ids:
        heading = (
            f"## {PREMISE_DISPUTED_SECTION_TITLE}" if markdown else PREMISE_DISPUTED_SECTION_TITLE
        )
        parts.append(
            "\n".join(
                (
                    heading,
                    "The agent recorded these findings as not done although the AI-powered review "
                    "said the task itself requires the work. The agent's reasons are in its "
                    "responses; Yoetz did not judge them.",
                    *(f"- {item}" for item in document.premise_disputed_finding_ids),
                )
            )
        )
    if document.acknowledged_not_done_obligation_ids:
        heading = (
            f"## {ACKNOWLEDGED_OBLIGATIONS_SECTION_TITLE}"
            if markdown
            else ACKNOWLEDGED_OBLIGATIONS_SECTION_TITLE
        )
        parts.append(
            "\n".join(
                (
                    heading,
                    "The agent recorded these obligations as acknowledged and not done, each with "
                    "a reason on the obligation. They are not done and keep this receipt from "
                    "reading clean.",
                    *(f"- {item}" for item in document.acknowledged_not_done_obligation_ids),
                )
            )
        )
    if document.disclosed_assumptions:
        heading = (
            f"## {DISCLOSED_ASSUMPTIONS_SECTION_TITLE}"
            if markdown
            else DISCLOSED_ASSUMPTIONS_SECTION_TITLE
        )
        parts.append(
            "\n".join(
                (
                    heading,
                    "The agent recorded these in decisions: a best-effort assumption it made, or "
                    "a check it inherently could not run. Yoetz did not verify them; each "
                    "decision holds the agent's text.",
                    *(
                        f"- {item.obligation_id}: {item.kind} (decision {item.decision_event_id})"
                        for item in document.disclosed_assumptions
                    ),
                )
            )
        )
    if document.semantic_withheld_items:
        count = len(document.semantic_withheld_items)
        noun = "item" if count == 1 else "items"
        heading = "## Withheld review items" if markdown else "Withheld review items"
        parts.append(
            "\n".join(
                (
                    heading,
                    f"AI-powered review continued without {count} review {noun}. "
                    "The item text was not sent or echoed; reason: never_send_heuristic.",
                    *(
                        f"- {item.item_id}: {item.reason}"
                        for item in document.semantic_withheld_items
                    ),
                )
            )
        )
    if document.semantic_redacted_values:
        heading = (
            "## Withheld from external review" if markdown else "Withheld from external review"
        )
        parts.append(
            "\n".join(
                (
                    heading,
                    "Where the external reviewer's copy did not carry a credential-like value "
                    "(item refs and line numbers only; no value is shown):",
                    *(
                        f"- {semantic_redacted_value_text(item)}"
                        for item in document.semantic_redacted_values
                    ),
                    SEMANTIC_REDACTED_VALUES_AGENT_LINE,
                )
            )
        )
    advisory_count = sum(
        1 for finding in document.findings if not FINDING_KIND_TRAITS[finding.kind][1]
    )
    if advisory_count:
        heading = "## Coverage limitations" if markdown else "Coverage limitations"
        noun = "finding" if advisory_count == 1 else "findings"
        parts.append(
            f"{heading}\n{advisory_count} recorded coverage-limitation {noun} remain visible "
            "and do not by themselves select unresolved_findings_remain."
        )
    recovery = _semantic_recovery_lines(document)
    if recovery:
        heading = "## Recovery" if markdown else "Recovery"
        parts.append("\n".join((heading, *recovery)))
    text = (
        _bound_human_text(
            parts,
            HISTORICAL_GAPS_SECTION_TITLE,
        )
        if parts
        else render_receipt_compact(document)
    )
    if not text:
        raise ProtocolValueError("invalid_receipt_document")
    return text


def render_receipt_compact(document: ReceiptDocument) -> str:
    """Render the bounded, newline-free compact receipt sentence frozen by v0.1 fixtures."""

    if type(document) is not ReceiptDocument:
        raise ProtocolValueError("invalid_receipt_document")
    frontier = document.subject_frontier.sequence
    prefix = f"Yoetz receipt at frontier {frontier}: "
    # Historical gaps (issue #1017) never select a compact limitation sentence.
    gap_codes = frozenset(gap.code for gap in document.gaps if gap.live)
    unresolved = unresolved_findings_for_render(document)

    if "encryption_key_unavailable" in gap_codes:
        return (
            prefix
            + "coverage is insufficient because a referenced encrypted object cannot be opened "
            "with the available keys. No payload content is shown."
        )
    if "content_unavailable_redacted" in gap_codes:
        return (
            prefix + "coverage is insufficient because a referenced object was redacted. "
            "No payload content is shown."
        )
    if COMPLETION_SCOPE_UNDECLARED_GAP in gap_codes:
        return prefix + "coverage is insufficient because completion scope was never declared."
    if COMPLETION_SCOPE_DECLARED_NONE_GAP in gap_codes:
        reason = _declared_none_reason_for_render(document)
        if reason is None:
            return (
                prefix
                + "coverage is insufficient because the plan declared none; its closed reason "
                "is unavailable."
            )
        return (
            prefix + f"coverage is insufficient because the plan declared none, reason: {reason}."
        )
    if OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP in gap_codes:
        return (
            prefix + "coverage is insufficient because optional AI-powered review was blocked by "
            "the strict route ceiling while the last install applied the policy route. If this "
            "strict route was not intended, re-run `yoetz integrate codex mcp preview` and "
            "`yoetz integrate codex mcp install --route-profile policy`, then start a fresh "
            "Codex process. No provider attempt or AI-powered finding was recorded."
        )
    if OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP in gap_codes:
        return (
            prefix
            + "coverage is insufficient because optional AI-powered review was blocked before "
            "dispatch by network-egress policy. No provider attempt or AI-powered finding was "
            "recorded."
        )
    if gap_codes & _SEMANTIC_REVIEW_NOT_RUN_GAPS:
        if document.conclusion is ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN:
            count = len(unresolved)
            noun = "finding" if count == 1 else "findings"
            verb = "remains" if count == 1 else "remain"
            return (
                prefix
                + f"{count} unresolved {noun} {verb}; AI-powered relevance review was not run."
            )
        if document.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE:
            return prefix + "coverage is insufficient; AI-powered relevance review was not run."
        return (
            prefix + "no unresolved local issue was found in the published record; "
            "AI-powered relevance review was not run."
        )
    if {
        "import_source_range_not_universal",
        "unobserved_work_outside_accepted_ranges",
    } <= gap_codes:
        return (
            prefix
            + "coverage is insufficient. A bounded Codex import processed its accepted source "
            "range, but declared gaps prevent a claim about all work."
        )

    waiver = _waiver_for_render(document)
    if waiver is not None and waiver.waiver_expiry is not None:
        same_frontier = waiver.finding_frontier == document.subject_frontier
        if (
            document.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
            and same_frontier
            and waiver.waiver_expiry >= document.generated_at
        ):
            return (
                prefix + "no unresolved local findings are presented because the one finding "
                "has an active finding-only waiver, recorded by a local human, through "
                f"{waiver.waiver_expiry.wire}. The waiver does not apply to another frontier."
            )
        if document.conclusion is ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN:
            if not same_frontier:
                return (
                    prefix + "one unresolved finding remains. A waiver recorded for frontier "
                    f"{waiver.finding_frontier.sequence} has no effect on this frontier."
                )
            if waiver.waiver_expiry < document.generated_at:
                return (
                    prefix
                    + "one unresolved finding remains. Its recorded finding-only waiver expired "
                    f"at {waiver.waiver_expiry.wire} and is not active."
                )

    if any(finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED for finding in unresolved):
        return (
            prefix
            + "one advisory AI-powered finding remains unresolved. AI-powered review completed, but "
            "it does not upgrade local assurance or prove correctness."
        )
    if document.conclusion is ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN:
        if len(unresolved) == 3 and len(document.findings) == 3:
            return (
                prefix
                + "unresolved findings remain. Three current findings are shown: one acknowledged, "
                "one disputed by a rejection, and one without a response."
            )
        count = len(unresolved)
        noun = "finding" if count == 1 else "findings"
        verb = "remains" if count == 1 else "remain"
        return prefix + f"{count} unresolved {noun} {verb}."
    if document.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE:
        if document.acknowledged_not_done_obligation_ids:
            count = len(document.acknowledged_not_done_obligation_ids)
            noun = "obligation was" if count == 1 else "obligations were"
            return (
                prefix + f"coverage is insufficient. {count} {noun} acknowledged as not done "
                "by the agent."
            )
        if document.self_verified_finding_ids:
            count = len(document.self_verified_finding_ids)
            noun = "finding was" if count == 1 else "findings were"
            return (
                prefix + f"coverage is insufficient. {count} {noun} self-verified by the agent; "
                "Yoetz could not prove the repair."
            )
        if document.disputed_after_rebuttal_finding_ids:
            count = len(document.disputed_after_rebuttal_finding_ids)
            noun = "finding is" if count == 1 else "findings are"
            return (
                prefix + f"coverage is insufficient. {count} {noun} disputed: the agent "
                "rejected them with a reason and the reviewer repeated them without newer "
                "material."
            )
        child_self_verified = sum(
            item.self_verified for child in document.children.children for item in child.findings
        )
        if child_self_verified:
            noun = "child finding was" if child_self_verified == 1 else "child findings were"
            return (
                prefix + f"coverage is insufficient. {child_self_verified} {noun} self-verified "
                "by the child agent; Yoetz could not prove the repair."
            )
        return prefix + "coverage is insufficient. Declared gaps bound this receipt's conclusion."

    outstanding_work = next(
        (
            section.body
            for section in document.sections
            if section.key is ReceiptSectionKey.OUTSTANDING_WORK
        ),
        None,
    )
    if outstanding_work == "Declared obligations are all resolved.":
        return (
            prefix + "declared obligations are all resolved. No unresolved local findings were "
            "recorded; this is not proof of correctness."
        )

    limitations = next(
        (
            section.body
            for section in document.sections
            if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
        ),
        "",
    )
    if "referenced immutable object was available" in limitations:
        return (
            prefix + "no unresolved local findings were recorded. The referenced immutable "
            "object was available at build time."
        )
    return (
        prefix + "no unresolved local findings were recorded. Coverage is current cooperative "
        "local evidence; this is not proof of correctness."
    )
