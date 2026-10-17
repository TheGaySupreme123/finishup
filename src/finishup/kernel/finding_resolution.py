"""Proof-based finding resolution: which later check may resolve which recorded finding.

A finding is a historical fact and stays visible forever. Whether it is *current* is a separate
fact, and only one kind of evidence may change it: a later local check whose recorded
state contains the finding, whose matching policy pack ran to completion with nothing suppressed,
whose scope covers the finding's subject, whose coverage carries no weakening gap for the
finding's proof class, and which did not return the same issue again. A closed local-only
exception lets case-wide host-observation limitations remain on the receipt without vetoing clean
structured-ledger proof, and a bounded AI-powered review selection stays disclosure rather than a
veto on proof it did not weaken. A response disposition never resolves a finding; it only answers
it on the record. Weak, skipped, failed, capped, stale, unreadable, or non-overlapping checks do
nothing, and nothing here ever strengthens coverage.

Everything in this module is pure and replay-derived, so a receipt, a status counter, and a
projection checkpoint all read the same fact.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, MutableMapping
from dataclasses import dataclass, replace
from typing import Final, Literal, cast

from finishup.domain.coordination import CoordinationGapCode
from finishup.domain.events import (
    MAX_PRIOR_FINDING_LISTED_REFS,
    SEMANTIC_INCLUDED_REFS_NOT_RECORDED_GAP,
    SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP,
    ActionKind,
    CheckChangeShownFiles,
    CheckRecordedPayload,
    ClaimKind,
    LedgerRecord,
    RequestedItemKind,
    ResponseRecordedPayload,
)
from finishup.domain.findings import (
    DISPUTED_AFTER_REBUTTAL_VERDICT,
    SELF_VERIFIED_GUIDANCE,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    is_limitation_request,
)
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_GAPS,
    CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP,
    CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
    CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS,
    COMPLETION_SCOPE_DECLARED_NONE_GAP,
    COMPLETION_SCOPE_UNDECLARED_GAP,
    OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
    OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP,
    PREEXISTING_TEST_BASELINE_UNKNOWN_GAP,
    PREEXISTING_TEST_INFORMATIONAL_GAPS,
    PREEXISTING_TEST_SKIP_UNKNOWN_GAP,
    SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP,
    SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP,
    SEMANTIC_CHALLENGES_REJECTED_GAP,
    SEMANTIC_MISSING_AGENT_SUPPLIABLE_GAP,
    SEMANTIC_MISSING_ALREADY_SUPPLIED_GAP,
    SEMANTIC_MISSING_FINISHUP_LIMIT_GAP,
    SEMANTIC_MISSING_ITEMS_REJECTED_GAP,
    SEMANTIC_MISSING_NON_CONVERGENT_GAP,
    SEMANTIC_MISSING_UNAVAILABLE_GAP,
    SEMANTIC_PACKET_INSUFFICIENT_GAP,
    SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP,
    SEMANTIC_PRIOR_VERDICTS_UNSUPPORTED_GAP,
    SEMANTIC_PROCESS_STATE_FILTERED_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_MISMATCH_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_PARSE_FAILED_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_RECOVERY_FAILED_GAP,
    SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
    SEMANTIC_RESTATEMENTS_SUPPRESSED_GAP,
    SEMANTIC_REVIEW_CONTEXT_WITHHELD_GAP,
    SEMANTIC_REVIEW_CREDENTIAL_HEURISTIC_DISABLED_GAP,
    SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP,
    SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
    SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
    SEMANTIC_REVIEW_NOT_REQUESTED_GAP,
    SEMANTIC_REVIEW_REFS_REDUCED_GAP,
    SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP,
    SEMANTIC_REVIEW_SNIPPET_INVALID_GAP,
    SEMANTIC_REVIEW_VALUE_REDACTED_GAP,
    UNRESOLVED_VERIFICATION_GAP,
)
from finishup.domain.task_statement import (
    TASK_STATEMENT_FINDING_SUMMARIES,
    TASK_STATEMENT_GAPS,
    may_carry_task_statement,
)
from finishup.domain.values import ClaimId, EventId, EvidenceId, FindingId, ObligationId, ResultId
from finishup.kernel.claims import effective_claim_items
from finishup.kernel.plan_drift import (
    INSTRUCTION_REQUIREMENT_UNMAPPED_GAP,
    OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP,
    PLAN_DRIFT_GAPS,
    stale_resolved_obligations,
)
from finishup.kernel.plan_scope import current_plan_scope
from finishup.kernel.projections import (
    MAX_ABSORBED_REFS,
    MAX_CHECK_CHANGE_RAISING_CHECKS,
    STANDING_POSITION_KINDS,
    FindingProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    StandingPosition,
    is_observation_limitation,
    is_observation_limitation_kind,
    observation_finding_event_ids,
)
from finishup.kernel.task_facts import (
    INSTALL_INTO_FINISHUP_RUNTIME_GAP,
    INSTALL_INTO_PRIVATE_ENV_GAP,
    OBLIGATION_BLOCKED_GAP,
    PLANNED_VERIFICATION_AGENT_LINKED_GAP,
    PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP,
    PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP,
    PLANNED_VERIFICATION_UNOBSERVABLE_GAP,
    TASK_FACT_GAPS,
    VERIFICATION_ONLY_AS_ROOT_GAP,
    WRITE_OUTSIDE_WORKSPACE_GAP,
)
from finishup.protocol.coverage import LedgerFreshness
from finishup.protocol.models import SemanticReason, SemanticStatus
from finishup.protocol.policy_packs import (
    WORK_INTEGRITY_POLICY_ID,
    policy_version_supersedes_or_equals,
)

__all__ = [
    "AGENT_SETTLED_DISPOSITION_VALUES",
    "CAPTURE_FAILURE_GAPS",
    "DETERMINISTIC_PROOF_TOLERATED_GAPS",
    "SEMANTIC_ONLY_GAPS",
    "REVIEW_SELECTION_GAPS",
    "SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS",
    "SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP",
    "IssueKey",
    "OPEN_REVIEW_VERDICTS",
    "UNRESOLVED_FINDING_NEXT_STEPS",
    "ResolutionAttempt",
    "apply_check_resolution",
    "apply_check_rulings",
    "check_change_limits_tolerated",
    "check_change_resolution_unverified",
    "disclosing_response",
    "unverified_resolution_finding_ids",
    "finding_is_resolved",
    "finding_resolution_attempt",
    "issue_key",
    "next_standing_position",
    "position_stands",
    "prior_finding_verdict",
    "qualifying_check_resolves",
    "rejection_stands",
    "reopen_findings_resolved_by",
    "resolved_finding_ids",
    "standing_position_of",
]

IssueKey = tuple[object, ...]

# ``insufficient_packet`` and the named-missing-item disclosures that only ever ride beside it
# (issue #907). They describe one whole-packet answer, so they tolerate and veto together.
_INSUFFICIENT_PACKET_GAPS: Final = frozenset(
    {
        SEMANTIC_PACKET_INSUFFICIENT_GAP,
        SEMANTIC_MISSING_AGENT_SUPPLIABLE_GAP,
        SEMANTIC_MISSING_ALREADY_SUPPLIED_GAP,
        SEMANTIC_MISSING_ITEMS_REJECTED_GAP,
        SEMANTIC_MISSING_NON_CONVERGENT_GAP,
        SEMANTIC_MISSING_UNAVAILABLE_GAP,
        SEMANTIC_MISSING_FINISHUP_LIMIT_GAP,
    }
)

# ``SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP``: the AI-powered review packet carried the bounded
# dependency closure of what it selected rather than every reference at the frozen frontier
# (ADR-006, #675). The ledger outgrows the packet in any real session, so this is the normal case,
# not an exception. The check records the references the reduced packet included, and an AI-powered
# finding may use the unchanged scope as a baseline only when its relevant material was among them.
# Selection versus capture failure (issue #904). A *selection* code records a deliberate, bounded
# choice of what material to show; a *capture-failure* code records material that was clipped,
# redacted, or lost. Selection codes keep bounding every coverage they are folded into, and the
# receipt keeps saying the review saw a bounded scope, but they never describe the complete local
# case, so they never weaken local proof; for AI-powered proof they are compared with the finding's
# recorded baseline, so an unchanged selection is tolerated and a new one still blocks. Capture
# failures are never tolerated by either proof class and never become a baseline. This names only
# the codes #904 decided; every tolerated set below stays closed, so an unclassified code still
# blocks both proof classes until someone decides otherwise here.
REVIEW_SELECTION_GAPS: Final = frozenset(
    {"content_unselected", SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP}
)
CAPTURE_FAILURE_GAPS: Final = frozenset(
    {
        "event_payload_unavailable",
        "redacted_event",
        "redacted_object",
        # Waits for the truncation-source test and relevance rule (issue #904); until then a
        # clipped payload may be the finding's own evidence, so it blocks.
        "truncated_payload",
    }
)

# Coverage gaps that describe only the AI-powered review's own absence or weakness. A
# local finding is proven absent by the local pack that owns it, so these gaps
# do not weaken that proof; for an AI-powered finding they do, because the AI-powered review is the
# proof. The registration-drift gap is one of these: it rides alongside the ceiling gap on a
# strict check served while the applied record says policy, so a drift check still resolves
# local findings exactly like a plain ceiling check does (issue #537).
_SEMANTIC_ONLY_GAPS: Final = frozenset(
    {
        SEMANTIC_REVIEW_NOT_REQUESTED_GAP,
        # The review round was skipped because the last two completed reviews could not assess
        # the same content (TB4 tb4n1 D3): it says nothing about a local pack.
        SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP,
        # The review waited for the first material edit (issue #1046): nothing about a local pack.
        SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP,
        SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
        SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
        OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
        OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP,
        SEMANTIC_REVIEW_CONTEXT_WITHHELD_GAP,
        # Egress withholding of one packet item (issue #982, owner decision B2) decides only what
        # the external model saw; local packs never read the packet, so it never vetoes local
        # proof. For AI-powered proof it is a capture baseline (below), never a free pass.
        SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
        *_INSUFFICIENT_PACKET_GAPS,
        SEMANTIC_CHALLENGES_REJECTED_GAP,
        SEMANTIC_REVIEW_SNIPPET_INVALID_GAP,
        SEMANTIC_REVIEW_REFS_REDUCED_GAP,
        SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP,
        SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP,
        SEMANTIC_PROVIDER_INPUT_MANIFEST_PARSE_FAILED_GAP,
        SEMANTIC_PROVIDER_INPUT_MANIFEST_MISMATCH_GAP,
        SEMANTIC_PROVIDER_INPUT_MANIFEST_RECOVERY_FAILED_GAP,
        SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP,
        SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP,
        # The reviewer's missing task statement (issue #908) says nothing about a local pack.
        *TASK_STATEMENT_GAPS,
        # The check-time change is AI-powered review input only (ADR-031); local packs never
        # read it, so its limits cannot weaken a local absence proof.
        *CHECK_TIME_CHANGE_GAPS,
        # The reduced review's sent content could not be recorded (issue #904): a limit of that
        # review, never of the complete local case. For AI-powered proof it blocks.
        SEMANTIC_INCLUDED_REFS_NOT_RECORDED_GAP,
    }
)
# Evidence-strength gaps: the cited evidence was readable but its content was not captured or
# was withheld, or its digest subject predates typed bindings. They bound how strong a receipt
# can be — the receipt keeps reporting them — but they do not stop a policy pack from reading
# the ledger state it judges, so they do not weaken the proof that an issue no longer fires.
# Every other gap (redacted or unavailable payloads, redacted objects, missing refs, unknown
# events, completion-scope gaps, import ranges, and any code not named here) means the check could
# not read or bound the material, and blocks both proof classes. The set is closed on purpose: a
# new gap code blocks resolution until someone decides otherwise here. Command gaps are never
# added to this set: the separately proved subject partition below is their only exception, and
# the two content-capture codes a proven action/result link tolerates are a second, narrower one.
_EVIDENCE_STRENGTH_GAPS: Final = frozenset(
    {
        "evidence_content_digest_only",
        "evidence_content_withheld",
        "evidence_digest_subject_legacy_unknown",
    }
)
# Host observation can leave case-wide limitations even when the local policy's own
# structured ledger inputs were readable. These codes keep bounding the receipt, but do not veto
# absence proof for an already-recorded local finding whose original coverage was itself
# readable. ``captured_object_unavailable`` belongs here because local packs judge event
# payloads and their typed coverage, never captured-object bytes; if that absence matters to a
# rule, the pack re-fires the issue or returns its own coverage finding. Event-payload loss and
# source redaction remain excluded and therefore block.
_HOST_OBSERVATION_GAPS: Final = frozenset(
    {
        "captured_object_unavailable",
        # A native content handoff retired before its row attached it (issue #1019): local packs
        # never read captured bytes. A refused or quarantined row is disclosed by its own codes.
        "capture_handoff_retired",
        # Capture-time redaction of a high-confidence secret shape (issue #982). Privacy filtering
        # exists for content leaving the machine; local packs judge event payloads, never the
        # captured bytes it replaced, so it stays a receipt disclosure and never vetoes local
        # proof. It is not a capture failure: heuristic-only matches are no longer redacted at
        # capture at all.
        "content_redacted",
        "content_unselected",
        "host_outcome_unavailable",
        "unpaired_event",
    }
)
# The prior-findings section's own bound (issue #905). A section that could not carry every
# earlier finding is no weaker than the review before that section existed, so the gap stays on
# the receipt as a disclosure and proves nothing about any finding's absence either way.
_REVIEW_DIALOGUE_DISCLOSURE_GAPS: Final = frozenset(
    {
        SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP,
        SEMANTIC_PRIOR_VERDICTS_UNSUPPORTED_GAP,
        SEMANTIC_RESTATEMENTS_SUPPRESSED_GAP,
        # Issue #1042: "never attempted" during work in progress or FinishUP's own state, not minted.
        # They say nothing about what the review saw, so they never weaken either proof.
        SEMANTIC_PROCESS_STATE_FILTERED_GAP,
    }
)
# In-place egress redaction of credential-like values (issue #982, owner decision B2): the reviewer
# saw every item with only the suspicious values replaced by a fixed placeholder. A credential
# value is not what any finding is about, so the replacement stays disclosed on every receipt but
# weakens neither proof class.
_EGRESS_VALUE_REDACTION_GAPS: Final = frozenset({SEMANTIC_REVIEW_VALUE_REDACTED_GAP})
# The owner's policy turned the low-confidence credential heuristic off (issue #982 opt-out): the
# reviewer saw values it would otherwise have had replaced. An owner disclosure choice that only
# widened what the review saw, so it stays on every receipt and weakens neither proof class.
_OWNER_DISCLOSURE_CHOICE_GAPS: Final = frozenset(
    {SEMANTIC_REVIEW_CREDENTIAL_HEURISTIC_DISABLED_GAP}
)
# Plan drift (``kernel.plan_drift``) is an advisory diagnostic about the planning trace: it says the
# ledger lacks a relation needed to read the plan as current, never that a local pack could not
# read the rows it judges. It stays on every receipt but never vetoes a local absence proof.
_BASE_DETERMINISTIC_PROOF_TOLERATED_GAPS: Final = (
    _SEMANTIC_ONLY_GAPS
    | _EVIDENCE_STRENGTH_GAPS
    | _REVIEW_DIALOGUE_DISCLOSURE_GAPS
    | _EGRESS_VALUE_REDACTION_GAPS
    | _OWNER_DISCLOSURE_CHOICE_GAPS
    | PLAN_DRIFT_GAPS
    # Task facts (#977) describe the work, never whether the rows a local pack judges were
    # readable, so they never veto a local absence proof either; they stay on the receipt.
    | TASK_FACT_GAPS
    # The derived unanswered-verification limit (#1079 F2, ADR-033) says only that a resolved
    # obligation lacks observed verification or a recorded limit. It bounds the receipt and never
    # reblocks Stop, so it must not keep an unrelated repaired local finding open either.
    | {UNRESOLVED_VERIFICATION_GAP}
)
# A reduced AI-powered review scope bounds the review packet only; the local-check case is not
# reduced (ADR-006), so review selection never weakens a local absence proof (issue #904).
_DETERMINISTIC_PROOF_TOLERATED_GAPS: Final = (
    _BASE_DETERMINISTIC_PROOF_TOLERATED_GAPS | _HOST_OBSERVATION_GAPS | REVIEW_SELECTION_GAPS
)
_SEMANTIC_PROOF_TOLERATED_GAPS: Final = (
    _EVIDENCE_STRENGTH_GAPS
    | _REVIEW_DIALOGUE_DISCLOSURE_GAPS
    | _EGRESS_VALUE_REDACTION_GAPS
    | _OWNER_DISCLOSURE_CHOICE_GAPS
    # The derived unanswered-verification limit (#1079 F2, ADR-033) says nothing about what the
    # reviewer was shown, so it never keeps a repaired AI-powered finding open either; it stays on
    # the receipt through the gap-effect table.
    | {UNRESOLVED_VERIFICATION_GAP}
)
# Read-only public names for ``kernel.deterministic_scope.CLEAN_COMPATIBLE_GAPS`` (#986).
DETERMINISTIC_PROOF_TOLERATED_GAPS: Final = _DETERMINISTIC_PROOF_TOLERATED_GAPS
SEMANTIC_ONLY_GAPS: Final = _SEMANTIC_ONLY_GAPS
# Structural test-edit accounting (ADR-032) is read by exactly one local rule: the unjustified
# pre-existing test edit, which raises ``task_requirement_unmet`` with the fact
# ``preexisting_test_edit_unjustified``. It is local accounting, never a basis of any other rule.
# Tolerance is therefore decided by the finding's basis, not its kind (TB4 pilot):
#
# * the test-edit finding is bounded by an unknown edit baseline (an edit set it could not read may
#   hide the same unjustified edit), but its informational counts and the unreadable skip marker
#   never hide an unjustified edit, so it tolerates those once ``preexisting_test_edit_unjustified``
#   is gone (that actionable code is never tolerated by any proof);
# * every other finding, local or AI-powered, including the statement-based
#   ``task_requirement_unmet`` finding and an AI-powered requirement finding, judges material the
#   accounting never touches, so the standing accounting limits must not make a repaired issue
#   permanently unresolvable.
_TEST_EDIT_INFORMATIONAL_GAPS: Final = frozenset(
    {*PREEXISTING_TEST_INFORMATIONAL_GAPS, PREEXISTING_TEST_SKIP_UNKNOWN_GAP}
)
_TEST_EDIT_ACCOUNTING_GAPS: Final = frozenset(
    {PREEXISTING_TEST_BASELINE_UNKNOWN_GAP, *_TEST_EDIT_INFORMATIONAL_GAPS}
)
# These native capture limits may be compared with the readable original finding's baseline.
# The check stamps the ones its review ran under onto every semantic finding it raises, so the
# baseline is durable finding coverage, not a later reconstruction (issue #884). Recorded clipping
# of an oversized item is included: it stays disclosed on every receipt, but an unchanged,
# already-recorded limit must not make a repaired issue permanently unresolvable. Review selection
# is included for the same reason (issue #904): every review of a long session runs over a reduced
# reference scope, and a later review under that same bound saw no less than the one that raised
# the issue. They never tolerate a new limitation, hidden ledger payloads, withheld review
# categories, dropped challenges, truncated payloads, or an insufficient-packet answer.
# The task-statement gaps (issue #908) join them on the same terms: a review that lacked the
# user's request may prove absence only for an issue raised by a review that lacked it the same
# way, never for one raised with the statement in hand.
SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS: Final = (
    _HOST_OBSERVATION_GAPS
    | REVIEW_SELECTION_GAPS
    | frozenset(
        {
            "content_capture_unavailable",
            SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP,
            SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
        }
    )
    | TASK_STATEMENT_GAPS
)
_SEMANTIC_BASELINE_CAPTURE_GAPS: Final = SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS
_UNPROVEN_FRESHNESS: Final = frozenset(
    {
        LedgerFreshness.UNKNOWN,
        LedgerFreshness.REDACTED_GAP,
        LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE,
    }
)
_COMMAND_GAPS: Final = frozenset({"command_attempt_uncorroborated", "command_attempt_mismatch"})
# Local rules whose basis never reads the requested-command attempt relation, command bytes or a
# command identity (TB4 pilot). A command-attempt gap describes a requested command item of some
# obligation; it cannot weaken an absence proof for these rules, so it stays a disclosure for them.
# Rules that do read attempts or commands (requested items, failed-work supersession by command
# identity, the ledger finding that carries the gap itself, research rules that read coverage
# records) keep the strict treatment, and ``action_without_result`` keeps its proven partition.
_COMMAND_INDEPENDENT_KINDS: Final = frozenset(
    {
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        FindingKind.RESULT_WITHOUT_ACTION,
        FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
        FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED,
        FindingKind.WEAK_OR_STALE_RESPONSE,
        FindingKind.TASK_REQUIREMENT_UNMET,
    }
)
# Keep this local to avoid importing the policy module while reducers import this module. If the
# work-integrity pack changes version, its action-result exception must be reviewed explicitly.
# Reviewed for 0.2.0 and 0.3.0 (#977): the ``action_without_result`` rule did not change, so every
# version qualifies.
_ACTION_WITHOUT_RESULT_POLICIES: Final = frozenset(
    {
        (WORK_INTEGRITY_POLICY_ID, "0.1.0"),
        (WORK_INTEGRITY_POLICY_ID, "0.2.0"),
        (WORK_INTEGRITY_POLICY_ID, "0.3.0"),
    }
)
ProofStateCache = MutableMapping[tuple[int, int, str], ProjectionState | None]
# What a proven action/result link tolerates on a local ``action_without_result`` (tb4n5 follow-up,
# owner decision 2026-10-13: a plain ledger link resolves it under capture gaps, disclosed on the
# receipt). That rule reads only the action and result rows and the result's ``action_id``; a
# readable result naming the readable action at the tested frontier decides the issue absent from
# the ledger alone, and clipped or uncaptured content is never its input (tb4n5 react S stayed open
# under ``truncated_payload`` and ``content_capture_unavailable`` after the agent linked the result
# and had to answer ``self_verified``). Only those content-capture codes: the requested-command gaps
# keep #682's partition below (the owner may widen this later), and redacted or unavailable ledger
# rows keep blocking because they are the rule's input.
_ACTION_LINK_TOLERATED_GAPS: Final = frozenset({"truncated_payload", "content_capture_unavailable"})


def _action_link_candidate(finding: Finding, check: CheckRecordedPayload) -> bool:
    """Whether a proven link could change this local finding's proof (cheap guards first)."""

    return (
        finding.origin is FindingOrigin.DETERMINISTIC
        and finding.kind is FindingKind.ACTION_WITHOUT_RESULT
        and (finding.policy_id, finding.policy_version) in _ACTION_WITHOUT_RESULT_POLICIES
        and len(finding.subject_refs) == 1
        and bool(set(check.coverage.known_gaps) & _ACTION_LINK_TOLERATED_GAPS)
    )


def _action_result_link_proven(
    finding: Finding, check: CheckRecordedPayload, state: ProjectionState | None
) -> bool:
    """Whether the tested state holds a readable result naming this finding's readable action.

    The subject is the event that recorded the action; the link is a result whose payload
    ``action_id`` is that action's id, both recorded no later than the frontier the check tested.
    Anything unreadable, or a state older than that frontier, proves nothing.
    """

    if state is None or not _action_link_candidate(finding, check):
        return False
    tested = check.subject_frontier.sequence
    if state.frontier < tested:
        return False
    rows = [row for row in state.actions.values() if row.source_event_id == finding.subject_refs[0]]
    if len(rows) != 1:
        return False
    action = rows[0]
    if action.payload is None or action.redacted or action.source_frontier > tested:
        return False
    return any(
        row.payload is not None
        and not row.redacted
        and row.source_frontier <= tested
        and row.payload.action_id == action.payload.action_id
        for row in state.results.values()
    )


def _command_gap_partition(
    finding: Finding, check: CheckRecordedPayload, state: ProjectionState | None
) -> tuple[str, ...] | None:
    """Conservatively bound every possible command-gap owner at the tested frontier.

    Empty means proven independent. IDs mean overlapping command obligations; None means that
    independence is unknown. We deliberately include matching command obligations as well:
    absence of a relation on this read must never be turned into an absence proof. This narrow
    partition needs no new check payload and never reinterprets a command as execution evidence.
    """
    if (
        state is None
        or state.frontier < check.subject_frontier.sequence
        or finding.origin is not FindingOrigin.DETERMINISTIC
        or finding.kind is not FindingKind.ACTION_WITHOUT_RESULT
        or (finding.policy_id, finding.policy_version) not in _ACTION_WITHOUT_RESULT_POLICIES
        or finding.coverage.ledger_freshness in _UNPROVEN_FRESHNESS
        or not set(finding.coverage.known_gaps) <= _DETERMINISTIC_PROOF_TOLERATED_GAPS
        or state.coverage_gaps
        or len(finding.subject_refs) != 1
    ):
        return None
    # A check's own finding suffix does not change these inputs. A newer material row or
    # unreadable input prevents us from using current state as the historical checked state.
    for rows in (state.plans, state.obligations, state.actions, state.results, state.claims):
        if any(
            row.payload is None or row.source_frontier > check.subject_frontier.sequence
            for row in rows.values()
        ):
            return None
    scope = current_plan_scope(state.plans, state.coverage_gaps)
    if not scope.has_plan or scope.effective_obligation_refs is None:
        return None
    selected = {
        ref
        for _, row in effective_claim_items(state)
        if row.payload is not None and row.payload.claim_kind is ClaimKind.COMPLETION
        for ref in row.payload.obligation_refs
    }
    selected.update(
        key
        for key, row in state.obligations.items()
        if row.payload is not None and row.payload.status.value == "resolved"
    )
    selected.intersection_update(scope.effective_obligation_refs)
    if any(key not in state.obligations for key in selected):
        return None
    commands = {
        key
        for key in selected
        if (payload := state.obligations[key].payload) is not None
        and any(item.item_kind is RequestedItemKind.COMMAND for item in payload.requested_items)
    }
    if not commands:
        return None  # No bounded producer for the recorded command gap.
    actions = [
        row for row in state.actions.values() if row.source_event_id == finding.subject_refs[0]
    ]
    if len(actions) != 1 or (action := actions[0].payload) is None or not action.obligation_refs:
        return None
    if any(ref not in state.obligations for ref in action.obligation_refs):
        return None
    if not any(
        row.payload is not None and row.payload.action_id == action.action_id
        for row in state.results.values()
    ):
        return None
    related_through_action = set(commands.intersection(action.obligation_refs))
    # command_attempts has a second explicit relation channel: a resolved command obligation can
    # cite a result whose action is this very action. Treat that owner as overlapping too; otherwise
    # an unknown command relation could be mislabeled independent merely because the action omitted
    # the obligation from its direct refs.
    related_through_result = {
        key
        for key in commands
        if (
            (payload := state.obligations[key].payload) is not None
            and any(
                ref.startswith("res_")
                and (result := state.results.get(ResultId(ref))) is not None
                and result.payload is not None
                and result.payload.action_id == action.action_id
                for ref in payload.resolution_evidence_refs
            )
        )
    }
    return tuple(sorted(related_through_action | related_through_result))


def issue_key(finding: Finding) -> IssueKey:
    """The durable identity of the issue a finding reports.

    Two findings with the same key are the same issue at different times: the newer row
    supersedes the older one and starts unresolved. The key names the pack, not its version: the
    versions of one pack form one lineage, so an issue a newer version re-raises after an upgrade
    supersedes the row an earlier version recorded instead of standing beside it.
    """

    return (
        finding.origin,
        finding.policy_id,
        finding.kind,
        finding.subject_refs,
    )


def _scope_covers(check: CheckRecordedPayload, finding: Finding) -> bool:
    """Whole-case checks cover every finding; scoped checks must name one of its subjects."""

    scope = check.scope
    if not scope.claim_ids and not scope.obligation_ids:
        return True
    selected = frozenset(scope.claim_ids) | frozenset(scope.obligation_ids)
    return any(ref in selected for ref in finding.subject_refs)


def _policy_completed(check: CheckRecordedPayload, finding: Finding) -> bool:
    # The finding's pack at the version that raised it, or a later version of the same pack: a
    # finding recorded before an upgrade stays resolvable by a check the upgraded build runs.
    return any(
        execution.policy_id == finding.policy_id
        and policy_version_supersedes_or_equals(
            finding.policy_id, execution.policy_version, finding.policy_version
        )
        and execution.outcome == "run"
        and execution.reason == "completed"
        for execution in check.policy_executions
    )


def _deterministic_freshness_proven(
    finding: Finding,
    check: CheckRecordedPayload,
    gaps: frozenset[str],
) -> bool:
    """Whether aggregate freshness still proves this local issue absent.

    ``redacted_gap`` is normally unproven. The only exception is a closed host-observation class
    on a check of a local finding whose own recorded proof was readable. This prevents an
    unrelated unavailable capture from making repair impossible while keeping unknown freshness,
    stale state, unreadable original proof, and every unclassified gap fail-closed.
    """

    freshness = check.coverage.ledger_freshness
    host_limited = bool(gaps & _HOST_OBSERVATION_GAPS)
    if host_limited:
        finding_coverage = finding.coverage
        finding_gaps = frozenset(finding_coverage.known_gaps)
        if (
            finding_coverage.ledger_freshness in _UNPROVEN_FRESHNESS
            or not finding_gaps <= _DETERMINISTIC_PROOF_TOLERATED_GAPS
        ):
            return False
    if freshness not in _UNPROVEN_FRESHNESS:
        return True
    return (
        freshness is LedgerFreshness.REDACTED_GAP
        and host_limited
        and gaps <= _DETERMINISTIC_PROOF_TOLERATED_GAPS
    )


def _semantic_freshness_proven(
    freshness: LedgerFreshness, gaps: frozenset[str], tolerated: frozenset[str]
) -> bool:
    """Whether freshness is proven for semantic proof under a recorded capture baseline.

    ``redacted_gap`` is normally unproven. Mirroring the local host-limited exception, it is
    accepted only when a tolerated ``captured_object_unavailable`` explains it and every gap is
    tolerated; redacted events, unavailable payloads and redacted objects cap the same freshness
    but carry their own gap codes, which are never tolerated. Unknown and stale state always fail
    closed.
    """

    if freshness not in _UNPROVEN_FRESHNESS:
        return True
    return (
        freshness is LedgerFreshness.REDACTED_GAP
        and "captured_object_unavailable" in gaps & tolerated
        and gaps <= tolerated
    )


def _material_changes(
    finding: Finding,
    finding_source_frontier: int,
    check: CheckRecordedPayload,
    state: ProjectionState,
) -> Iterator[tuple[str, str]]:
    """Yield ``(logical ref, source event ref)`` for each material row counted as a change."""

    low = finding_source_frontier
    high = check.subject_frontier.sequence

    def changed(row: object) -> bool:
        # An unreadable (redacted) record cannot show what changed, so it proves nothing.
        source = getattr(row, "source_frontier", 0)
        readable = getattr(row, "payload", None) is not None
        return readable and type(source) is int and low < source <= high

    for rows in (state.actions, state.results, state.evidence):
        for key, row in rows.items():
            if changed(row):
                yield str(key), str(row.source_event_id)
    subjects = frozenset(str(ref) for ref in finding.subject_refs)
    for key, row in state.obligations.items():
        if (str(key) in subjects or str(row.source_event_id) in subjects) and changed(row):
            yield str(key), str(row.source_event_id)
    for key, row in state.claims.items():
        if not changed(row):
            continue
        payload = row.payload
        supersedes = getattr(payload, "supersedes_claim_refs", ()) if payload is not None else ()
        if (
            str(key) in subjects
            or str(row.source_event_id) in subjects
            or any(str(ref) in subjects for ref in supersedes)
        ):
            yield str(key), str(row.source_event_id)


def _semantic_subject_changed(
    finding: Finding,
    finding_source_frontier: int,
    check: CheckRecordedPayload,
    state: ProjectionState | None,
) -> bool:
    """Whether material work changed after *finding* and at or before the checked state.

    Counted: a new or revised action, result or evidence record (a repair, verification or
    content), or a revision of a claim or obligation the finding names, including a claim that
    supersedes a named claim. Unreadable records, responses, checks, findings and observations
    never count. FinishUP cannot bind arbitrary new evidence to a reviewer's prose, so this proves
    new material work, not its relevance; the later completed review must still not return the
    issue. Without the pre-check projection nothing is proven.
    """

    if state is None or state.frontier < check.subject_frontier.sequence:
        return False
    return any(True for _ in _material_changes(finding, finding_source_frontier, check, state))


def _response_repair_refs(finding: Finding, state: ProjectionState) -> frozenset[str] | None:
    """The repair material the finding's latest response links, or None when it is unreadable.

    This is the #898 repair-evidence relation: evidence cited directly, and the evidence of a
    cited result (the result itself when it cites none). No response links nothing. A redacted or
    unknown response, result or evidence row cannot be shown to have been in view, so it is None.
    """

    response = state.responses.get(finding.finding_id)
    if response is None:
        return frozenset()
    if response.payload is None or response.redacted:
        return None
    refs: set[str] = set()
    for cited in response.payload.evidence_refs:
        value = str(cited)
        evidence = state.evidence.get(cast(EvidenceId, value))
        if evidence is not None:
            if evidence.payload is None or evidence.redacted:
                return None
            refs.add(value)
            continue
        result = state.results.get(cast(ResultId, value))
        if result is None or result.payload is None or result.redacted:
            return None
        linked = tuple(str(ref) for ref in result.payload.evidence_refs)
        for ref in linked:
            row = state.evidence.get(cast(EvidenceId, ref))
            if row is None or row.payload is None or row.redacted:
                return None
        refs.update(linked or (value,))
    return frozenset(refs)


def _recording_records(state: ProjectionState) -> Iterator[tuple[str, ProjectionRecord[object]]]:
    """Every current ledger record the review packet can carry, keyed by its logical id."""

    for rows in (state.actions, state.results, state.evidence, state.claims, state.obligations):
        for key, row in rows.items():
            yield str(key), cast(ProjectionRecord[object], row)


def _with_recording_events(included: frozenset[str], state: ProjectionState) -> frozenset[str]:
    """*included* plus the event that recorded each readable record it carried (issue #947).

    A reviewer cites ledger material by the ``evt_`` id that recorded it, while the packet carries
    an excerpt, a claim or an obligation under its own logical id. The recording event's payload is
    that record, so a carried record credits the event that recorded its current content. Only that
    direction is derived here, from the projection the check ran over: a carried history row
    credits its record at check time, where the packet shows whether the row held the payload
    (``sent_ledger_refs``). An unreadable record credits nothing.
    """

    events = {
        str(row.source_event_id)
        for key, row in _recording_records(state)
        if key in included and row.payload is not None and not row.redacted
    }
    return included | frozenset(events)


# Record families a review packet carries only as recent ledger history (or, for evidence, a
# bounded excerpt): their recording events leave the packet once the session outgrows its window.
def _history_families(state: ProjectionState) -> Iterator[ProjectionRecord[object]]:
    for rows in (state.actions, state.results, state.evidence):
        for row in rows.values():
            yield cast(ProjectionRecord[object], row)


def _oldest_carried_history_sequence(
    included: frozenset[str], state: ProjectionState
) -> int | None:
    """The lowest ledger sequence among history rows the packet carried, if any (issue #947).

    Read from the recorded set itself (never its aliases): the recording events of actions,
    results, evidence, claims, findings and responses reach the packet only as history rows.
    Decisions, plans and the task statement travel in their own sections under event ids and are
    not counted, so an old decision never stretches the window. None means no history row was
    carried, so no event can be shown to be older than the window.
    """

    rows: list[ProjectionRecord[object]] = list(_history_families(state))
    for family in (state.claims, state.findings, state.responses):
        rows.extend(cast(ProjectionRecord[object], row) for row in family.values())
    return min(
        (row.source_frontier for row in rows if str(row.source_event_id) in included),
        default=None,
    )


def _superseded_by_sent_claim(ref: str, sent: frozenset[str], state: ProjectionState) -> bool:
    """Whether claim *ref* was replaced, directly or through a chain, by a claim the packet sent.

    The edge is the durable ``superseded_by_claim_id`` the projection records on the replaced
    claim (as ``effective_claim_ids`` reads it). The reviewer saw the correction, which is the
    claim the agent now stands behind; the replaced claim is no longer part of the account.
    """

    current = state.claims.get(cast(ClaimId, ref))
    seen: set[str] = {ref}
    while current is not None and (successor := current.superseded_by_claim_id) is not None:
        following = str(successor)
        if following in seen:
            return False
        if following in sent:
            return True
        seen.add(following)
        current = state.claims.get(successor)
    return False


def _subject_accounted(
    ref: str,
    listed: bool,
    sent: frozenset[str],
    state: ProjectionState,
    oldest_carried: int | None,
) -> bool:
    """Whether a reduced recheck accounts for one finding subject (issue #947).

    A subject is accounted when the packet sent it (a carried record counts for the event that
    recorded it), when it is a claim, or the event that recorded one, that a sent claim superseded,
    or when it is the recording event of an action, result or evidence older than every history
    row the packet carried and the sent prior-finding row listed it. The last case is the bounded
    window evicting the old account: the reviewer was shown the finding's statement, its subject
    list and the agent's answer, and must still have been sent the repair and a later change.
    """

    if ref in sent:
        return True
    claim = ref
    if ref.startswith("evt_"):
        claim = next(
            (str(key) for key, row in state.claims.items() if str(row.source_event_id) == ref),
            "",
        )
    if claim.startswith("clm_") and _superseded_by_sent_claim(claim, sent, state):
        return True
    if not listed or oldest_carried is None or not ref.startswith("evt_"):
        return False
    return any(
        str(row.source_event_id) == ref and row.source_frontier < oldest_carried
        for row in _history_families(state)
    )


def _reduced_scope_repair_in_view(
    finding: Finding,
    finding_source_frontier: int,
    check: CheckRecordedPayload,
    state: ProjectionState | None,
) -> bool:
    """Whether a reduced review packet provably sent the material this finding depends on.

    The check must record the frontier references whose own content item survived in the packet
    actually sent (issue #904). That record must hold the finding's own prior-finding row, so the
    reviewer saw what was found, the subjects it named and the agent's answer, and every subject
    must be accounted (``_subject_accounted``, issue #947): a long session's repair pushes the
    subjects out of the bounded history window and supersedes the claim the reviewer criticised,
    so requiring the previous account itself would make every real repair unprovable. Every repair
    reference the response links must be sent, and so must at least one material change made after
    the finding: the repair the later review is credited with judging (PR930-F1). A missing record,
    an unreadable response or linked row, or any relevant reference that was only mentioned,
    linked, omitted or withheld is no proof, so the reduced scope keeps blocking.
    """

    included_refs = check.semantic_included_refs
    if included_refs is None or state is None or state.frontier < check.subject_frontier.sequence:
        return False
    included = frozenset(included_refs)
    if str(finding.finding_id) not in included:
        return False
    sent = _with_recording_events(included, state)
    oldest_carried = _oldest_carried_history_sequence(included, state)
    if not all(
        _subject_accounted(
            str(ref), position < MAX_PRIOR_FINDING_LISTED_REFS, sent, state, oldest_carried
        )
        for position, ref in enumerate(finding.subject_refs)
    ):
        return False
    linked = _response_repair_refs(finding, state)
    if linked is None or not linked <= included:
        return False
    return any(
        key in included or source in included
        for key, source in _material_changes(finding, finding_source_frontier, check, state)
    )


# A check carrying either code may have left an unruled AI-powered finding unassessed (#905).
_ASSESSMENT_INCOMPLETE_GAPS: Final = frozenset(
    {SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP, SEMANTIC_PRIOR_VERDICTS_UNSUPPORTED_GAP}
)


def prior_finding_verdict(check: CheckRecordedPayload, finding: Finding) -> str | None:
    """The admitted reviewer ruling this check recorded for *finding*, if any (issue #905)."""

    for item in check.prior_finding_verdicts:
        if item.finding_id == finding.finding_id:
            return item.verdict
    return None


# What an explicit, cited ``fixed`` ruling tolerates on its own finding (issues #905, #907). The
# reviewer affirmatively ruled the finding fixed, citing refs fenced to the packet's
# ``citable_refs``, so it assessed the finding on material it was shown: neither the whole-packet
# ``insufficient_packet`` answer nor excerpts the count or byte budget cut (``content_unselected``,
# ledger or captured) weaken that ruling. Silence never gets this tolerance, so a selection gap
# still blocks closing an AI-powered finding by not returning it.
#
# ``semantic_review_refs_reduced`` joins them (TB4 tb4n1, issue #976): the fence removed a
# citation of a ref that was not sent from some reviewer item, so the reviewer cited more than it
# was shown; it does not mean the review saw less. The ``fixed`` ruling itself is admitted only
# with every cited ref intact and fenced to what was sent (``_admit_prior_verdicts``), so the
# reduction can never be the ruling's own basis. Without an explicit ``fixed`` ruling the gap
# keeps blocking AI-powered proof.
_FIXED_RULING_TOLERATED_GAPS: Final = _INSUFFICIENT_PACKET_GAPS | frozenset(
    {"content_unselected", SEMANTIC_REVIEW_REFS_REDUCED_GAP}
)


# Task-fact gaps an explicit ``fixed`` ruling tolerates on its own finding (issue #1000). They
# describe the environment the work ran in (where it wrote, a blocker outside the agent's control)
# or what FinishUP's observer could confirm of it, never what the reviewer was shown. Issue #1046
# (tb4n4: 39 ``self_verified`` answers in 24 of 61 tasks, 16 ``resolution_attempt_required``
# rounds) adds the rest of that family: verification run only as root, installs into a private
# environment or FinishUP's runtime, and the planned-verification observer heuristics. Each stays a
# standing disclosure on the receipt (gap table rule G4). Facts about the deliverable itself
# (``requested_output_*``, ``declared_output_*``, ``deliverable_references_undeclared_file``) and
# every agent-actionable fact keep blocking.
_TASK_FACT_GAPS_TOLERATED_WHEN_FIXED: Final = frozenset(
    {
        WRITE_OUTSIDE_WORKSPACE_GAP,
        OBLIGATION_BLOCKED_GAP,
        VERIFICATION_ONLY_AS_ROOT_GAP,
        INSTALL_INTO_PRIVATE_ENV_GAP,
        INSTALL_INTO_FINISHUP_RUNTIME_GAP,
        PLANNED_VERIFICATION_AGENT_LINKED_GAP,
        PLANNED_VERIFICATION_MATCHED_BY_PREFIX_GAP,
        PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP,
        PLANNED_VERIFICATION_UNOBSERVABLE_GAP,
    }
)


def _prior_verdict_effect(
    finding: Finding, check: CheckRecordedPayload
) -> tuple[bool, tuple[str, ...], frozenset[str]]:
    """How an explicit per-finding ruling bears on this finding's absence proof (issue #905).

    ``fixed`` is the reviewer judging this finding on material recorded after it, so a
    whole-packet ``insufficient_packet`` (and its coverage marker), excerpts the packet's
    budget cut (``content_unselected``, issue #907) and citations of unsent refs the fence removed
    from reviewer items (``semantic_review_refs_reduced``, issue #976) no longer veto it; every
    other rule still applies, including freshness, material change and the issue not being
    returned again. ``withdrawn`` (the reviewer accepting the agent's rejection) keeps the
    ordinary rules here, under which an assessable review that does not re-raise a finding over
    changed state proves it absent; it never lifts the ``insufficient_packet`` veto. When the
    finding's latest response is a readable ``rejected``, ``apply_check_rulings`` then records
    that same check's outcome as ``rejection_accepted`` rather than resolved. Any other
    ruling blocks this finding by name and speaks for no other finding. Without a ruling nothing
    changes (silence is never read as ``fixed``), except that a check whose packet left prior
    findings out or dropped a ruling blocks every unruled AI-powered finding
    (``reviewer_assessment_incomplete``, in ``resolution_blockers``).
    """

    verdict = prior_finding_verdict(check, finding)
    if verdict is None or verdict == "withdrawn":
        return False, (), frozenset()
    if verdict == "fixed":
        return True, (), _FIXED_RULING_TOLERATED_GAPS
    return False, (f"reviewer_verdict_{verdict}",), frozenset()


def qualifying_check_resolves(
    finding: Finding,
    finding_source_frontier: int,
    check: CheckRecordedPayload,
    returned_issue_keys: frozenset[IssueKey],
    *,
    proof_state: ProjectionState | None = None,
    raised_before_task_statement: bool = False,
    check_change_raised_files: CheckChangeShownFiles | None = None,
    raised_under_reduced_scope: bool = False,
) -> bool:
    """True when *check* proves the issue *finding* reports is absent from the state it tested.

    ``finding_source_frontier`` is the ledger sequence at which the finding was recorded; a check
    whose tested subject frontier is earlier never saw the finding, so it cannot speak to it.
    ``returned_issue_keys`` are the issue keys of every finding the check returned; a check that
    returned the same issue re-fired it rather than proving it gone.
    ``check_change_raised_files`` is what the review that raised an AI-powered *finding* saw of
    the check-time change (``None`` while unknown); see ``check_change_limits_tolerated``.
    returned the same issue re-fired it rather than proving it gone. ``raised_under_reduced_scope``
    is the replay-derived fact that the check which raised *finding* recorded a reduced review
    reference scope (``FindingProjectionRecord.reduced_scope_raising_check_event_id``).
    """

    if type(finding) is not Finding or type(check) is not CheckRecordedPayload:
        raise ValueError("finding_resolution_invalid")
    if type(finding_source_frontier) is not int or finding_source_frontier < 1:
        raise ValueError("finding_resolution_invalid")
    return not resolution_blockers(
        finding,
        finding_source_frontier,
        check,
        returned_issue_keys,
        proof_state=proof_state,
        raised_before_task_statement=raised_before_task_statement,
        check_change_raised_files=check_change_raised_files,
        raised_under_reduced_scope=raised_under_reduced_scope,
    )


_NO_CHECK_CHANGE_FILES: Final = CheckChangeShownFiles((), (), complete=True)


def check_change_limits_tolerated(
    check: CheckRecordedPayload, raised_files: CheckChangeShownFiles | None
) -> bool:
    """The shown-file rule for check-time change limits on an AI-powered repair review (ADR-031).

    A repair review's ``check_time_change_*`` codes say only that part of that one object did not
    reach it. They are tolerated when the repair saw at least what the raising review saw of the
    change: every file the raising review saw whole reached the repair whole, and every file the
    raising review saw in part (a clean prefix of n bytes) reached the repair whole or in part
    with at least n clean bytes. Commitments bind the change's base, which stays fixed for a task.
    A raising review that carried no check-time change (an empty record) is always covered; an
    unknown one (``None``) never is. The repair's record may be incomplete: each entry it holds
    is still true.
    """

    if raised_files is None:
        return False
    repair = check.check_change_files
    return (_NO_CHECK_CHANGE_FILES if repair is None else repair).covers(raised_files)


def check_change_resolution_unverified(record: FindingProjectionRecord) -> bool:
    """Whether a resolution tolerated check-time limits through a legacy raising view (R945-02).

    A raising view recorded before view commitments is compared by length and count only, so a
    moved redaction or hunk could pass. Such a resolution still stands (backward compatibility)
    but is never presented as content-verified: callers disclose it with
    ``check_time_change_resolution_unverified``.
    """

    files = record.check_change_raised_files
    return (
        record.resolved_by_check_event_id is not None
        and bool(record.resolution_depends_on_check_event_ids)
        and files is not None
        and files.has_unverified_views()
    )


def unverified_resolution_finding_ids(
    projection: ProjectionState, resolved: Iterable[FindingId]
) -> tuple[FindingId, ...]:
    """The resolved findings among ``resolved`` whose resolution compared a legacy view."""

    return tuple(
        identifier
        for identifier in resolved
        if identifier in projection.findings
        and check_change_resolution_unverified(projection.findings[identifier])
    )


def _raises_under_reduced_scope(check: CheckRecordedPayload, finding: Finding) -> bool:
    """Whether *check* is the review that raised *finding* under a reduced reference scope.

    This feeds the lifecycle fallback for AI-powered findings recorded before the raise-time stamp
    existed (issue #904): their own coverage never carries ``semantic_reference_scope_reduced``,
    while the raising check's recorded coverage does. The raising check is the one whose completed
    review produced the finding: same tested frontier and same AI-powered review attempt.
    """

    return (
        finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
        and SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP in check.coverage.known_gaps
        and finding.subject_frontier == check.subject_frontier
        and finding.provenance is not None
        and check.semantic_provenance is not None
        and finding.provenance.semantic_attempt_id == check.semantic_provenance.semantic_attempt_id
    )


def _requirement_basis(finding: Finding) -> Literal["statement", "test_edit"] | None:
    """The basis of a local ``task_requirement_unmet`` finding, or None for any other finding.

    Two local rules raise this kind: the task statement the plan does not decompose, and the
    unjustified pre-existing test edit. Their summaries are fixed service wording; any summary
    other than a statement one reads as the stricter test-edit basis, so drift fails closed.
    """

    if (
        finding.origin is not FindingOrigin.DETERMINISTIC
        or finding.kind is not FindingKind.TASK_REQUIREMENT_UNMET
    ):
        return None
    return "statement" if finding.summary in TASK_STATEMENT_FINDING_SUMMARIES else "test_edit"


def _command_subject(ref: str, state: ProjectionState) -> bool:
    """Whether one finding subject names command material (a command obligation, action or result)."""

    for key, row in state.obligations.items():
        if ref in {str(key), str(row.source_event_id)}:
            payload = row.payload
            if payload is None or any(
                item.item_kind is RequestedItemKind.COMMAND for item in payload.requested_items
            ):
                return True
    for key, row in state.actions.items():
        if ref in {str(key), str(row.source_event_id)}:
            if row.payload is None or row.payload.action_kind is ActionKind.COMMAND:
                return True
    for key, row in state.results.items():
        if ref in {str(key), str(row.source_event_id)}:
            if row.payload is None:
                return True
            action = state.actions.get(row.payload.action_id)
            if (
                action is None
                or action.payload is None
                or action.payload.action_kind is ActionKind.COMMAND
            ):
                return True
    return False


def _requested_items_without_commands(finding: Finding, state: ProjectionState | None) -> bool:
    """Whether a local requested-item finding names only obligations that request no command.

    The requested-item rule reads ``attempted_items`` assertions; a command-attempt gap says a
    requested command item lacks observed corroboration. When every obligation the finding names
    is readable in the pre-check projection and requests no command, that gap is about other
    obligations and cannot bound this proof. Without the projection nothing is proven.
    """

    if (
        state is None
        or finding.origin is not FindingOrigin.DETERMINISTIC
        or finding.kind is not FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED
        or not finding.subject_refs
    ):
        return False
    for ref in finding.subject_refs:
        row = state.obligations.get(cast(ObligationId, str(ref)))
        if row is None or row.payload is None:
            return False
        if any(item.item_kind is RequestedItemKind.COMMAND for item in row.payload.requested_items):
            return False
    return True


def _semantic_command_independent(finding: Finding, state: ProjectionState | None) -> bool:
    """Whether an AI-powered finding's subjects are provably not command material.

    A requested-command corroboration gap is about a command item and the commands that might
    satisfy it. A reviewer finding whose subjects name none of those (no command obligation,
    command action or its result, read from the pre-check projection) is not about commands, so
    the gap does not bound its absence proof. Without that projection nothing is proven.
    """

    if state is None:
        return False
    return not any(_command_subject(str(ref), state) for ref in finding.subject_refs)


def _stale_obligations_unrelated(finding: Finding, state: ProjectionState | None) -> bool:
    """Whether the stale-evidence diagnostic names none of this AI-powered finding's subjects.

    ``obligation_evidence_stale_after_scope_edit`` says a resolved obligation's evidence predates
    a later edit; an unscoped edit makes it apply to every resolved obligation until each is
    re-resolved. It bounds a review finding only when the finding is about one of those
    obligations (by id or recording event). Read from the pre-check projection; without it, or
    while any stale obligation is unreadable, nothing is proven.
    """

    if state is None:
        return False
    stale = stale_resolved_obligations(state)
    if not stale:
        return False
    names: set[str] = set()
    for obligation in stale:
        row = state.obligations.get(obligation)
        if row is None:
            return False
        names.update({str(obligation), str(row.source_event_id)})
    return not any(str(ref) in names for ref in finding.subject_refs)


def resolution_blockers(
    finding: Finding,
    finding_source_frontier: int,
    check: CheckRecordedPayload,
    returned_issue_keys: frozenset[IssueKey],
    *,
    proof_state: ProjectionState | None = None,
    raised_before_task_statement: bool = False,
    check_change_raised_files: CheckChangeShownFiles | None = None,
    raised_under_reduced_scope: bool = False,
) -> tuple[str, ...]:
    """Explain the exact qualification predicate without weakening its proof requirements.

    ``raised_before_task_statement`` is the replay-derived fact that no event able to carry a task
    statement preceded the frontier *finding* was raised at (issue #908).
    """

    reasons: list[str] = []
    if check.subject_frontier.sequence < finding_source_frontier:
        reasons.append("finding_not_in_checked_frontier")
    if issue_key(finding) in returned_issue_keys:
        reasons.append("issue_returned_again")
    if check.suppressed_count != 0:
        reasons.append("findings_suppressed")
    if not _policy_completed(check, finding):
        reasons.append("matching_policy_not_completed")
    if not _scope_covers(check, finding):
        reasons.append("subject_outside_checked_scope")
    gaps = frozenset(check.coverage.known_gaps)
    if finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED:
        # Local test-edit accounting is never the basis of a review finding, including an
        # AI-powered requirement finding, so its standing limits cannot bound this proof (see
        # ``_TEST_EDIT_ACCOUNTING_GAPS``). The actionable unjustified-edit code still blocks.
        tolerated = _SEMANTIC_PROOF_TOLERATED_GAPS | _TEST_EDIT_ACCOUNTING_GAPS
        # The agent's explicit empty-scope declaration is a recorded decision the review packet
        # shows as the plan itself, never a limit on what the reviewer could see.
        tolerated = tolerated | {COMPLETION_SCOPE_DECLARED_NONE_GAP}
        if gaps & _COMMAND_GAPS and _semantic_command_independent(finding, proof_state):
            tolerated = tolerated | _COMMAND_GAPS
        if OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP in gaps and _stale_obligations_unrelated(
            finding, proof_state
        ):
            tolerated = tolerated | {OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP}
        ruled_fixed, verdict_reasons, verdict_tolerated = _prior_verdict_effect(finding, check)
        reasons.extend(verdict_reasons)
        tolerated |= verdict_tolerated
        if ruled_fixed:
            # Task facts about the environment the work ran in (where the agent wrote, which
            # obligations it declared blocked, verification only as root, installs, what the
            # observer could confirm of a planned run) describe the work, never what the reviewer
            # was shown, so they cannot bound an explicit, cited ``fixed`` ruling; they stay on
            # the receipt (issues #1000 and #1046; tb4n1 interleaved-vigenere kept a finding the
            # reviewer ruled fixed open on write_outside_workspace, tb4n4 on
            # verification_only_as_root). A silent review keeps them blocking: a review that did
            # not rule on the finding never said the work they describe repaired it.
            tolerated = tolerated | _TASK_FACT_GAPS_TOLERATED_WHEN_FIXED
        if prior_finding_verdict(check, finding) is None and gaps & _ASSESSMENT_INCOMPLETE_GAPS:
            # The review may never have seen this finding (the prior-findings section left it out)
            # or a ruling on it may have been dropped. Either way it was not assessed, so silence
            # here proves nothing; the gaps themselves stay disclosed, not vetoes on ruled rows.
            reasons.append("reviewer_assessment_incomplete")
        if check.semantic_conclusion == "insufficient_packet" and not ruled_fixed:
            reasons.append("semantic_packet_insufficient")
        original_gaps = frozenset(finding.coverage.known_gaps)
        if raised_under_reduced_scope:
            # Lifecycle fallback (issue #904): a finding recorded before the raise-time stamp
            # lacks the scope code its raising check recorded. That recorded check coverage
            # supplies this one baseline code; the finding's own coverage is never rewritten.
            original_gaps |= {SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP}
        baseline_tolerated = _SEMANTIC_PROOF_TOLERATED_GAPS | _SEMANTIC_BASELINE_CAPTURE_GAPS
        # A limitation outside the baseline set that the raising review ran under keeps its
        # baseline unreadable only while that limitation lasts (issue #904): a later check that
        # carries none of those codes saw at least as much as the raising one. A later check that
        # still carries one keeps blocking, and unproven original freshness is never rehabilitated.
        beyond_baseline = original_gaps - baseline_tolerated
        baseline_readable = not (beyond_baseline & gaps) and _semantic_freshness_proven(
            finding.coverage.ledger_freshness, original_gaps, baseline_tolerated
        )
        if (
            check.semantic_conclusion in {"no_material_discrepancy", "challenges_returned"}
            or ruled_fixed
        ) and baseline_readable:
            # Absence proof is no weaker than the readable review that raised this issue.
            # The later review still must complete and not return the issue. Its unchanged
            # capture limitations remain on the receipt; a response alone changes nothing.
            tolerated |= original_gaps & _SEMANTIC_BASELINE_CAPTURE_GAPS
            if raised_before_task_statement and not original_gaps & TASK_STATEMENT_GAPS:
                # The review that raised this issue predates the task statement (issue #908): it
                # had at most the task title (``task_title_only``), never the user's request, so a
                # later review that still lacks the statement saw no less of the request. Without
                # this, every AI-powered finding recorded before the upgrade stays open until the
                # owner consents to sending the user's words, and forever under Structural. The
                # codes stay on every receipt.
                tolerated |= TASK_STATEMENT_GAPS
        if gaps & CHECK_TIME_CHANGE_GAPS and check_change_limits_tolerated(
            check, check_change_raised_files
        ):
            tolerated |= CHECK_TIME_CHANGE_GAPS
        changed = _semantic_subject_changed(finding, finding_source_frontier, check, proof_state)
        if (
            changed
            and SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP in gaps & tolerated
            and not _reduced_scope_repair_in_view(
                finding, finding_source_frontier, check, proof_state
            )
        ):
            # An unchanged reduced scope is a baseline only for a later review whose packet
            # provably carried this finding's subjects, its linked repair material and the change
            # itself (issue #904, PR930-F1). Otherwise the same code says nothing about whether
            # the repair was in view, so it keeps blocking.
            tolerated -= {SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP}
            reasons.append("finding_material_outside_reduced_review_scope")
        if not _semantic_freshness_proven(check.coverage.ledger_freshness, gaps, tolerated):
            reasons.append("freshness_unproven")
        if not changed:
            # A stochastic reviewer that merely does not repeat an issue proves nothing; the
            # issue may only close over state that changed materially after it was raised.
            reasons.append("no_material_change_since_finding")
        if (
            check.semantic_status is not SemanticStatus.SUCCEEDED
            or check.semantic_reason is not SemanticReason.SEMANTIC_COMPLETED
        ):
            reasons.append("semantic_review_not_completed")
    else:
        tolerated = _DETERMINISTIC_PROOF_TOLERATED_GAPS
        basis = _requirement_basis(finding)
        # Decide test-edit accounting by the finding's basis (see ``_TEST_EDIT_ACCOUNTING_GAPS``):
        # only the test-edit finding is bounded by an unknown edit baseline.
        accounting = (
            _TEST_EDIT_INFORMATIONAL_GAPS if basis == "test_edit" else _TEST_EDIT_ACCOUNTING_GAPS
        )
        tolerated = tolerated | accounting
        freshness_gaps = gaps - accounting
        # An explicit empty-scope declaration is the agent's recorded scope decision. It stays a
        # standing disclosure on every receipt, but no local pack fails to read its rows because
        # of it, so it must not make a repaired local finding in a no-material-work task
        # permanently unresolvable.
        tolerated = tolerated | {COMPLETION_SCOPE_DECLARED_NONE_GAP}
        freshness_gaps = freshness_gaps - {COMPLETION_SCOPE_DECLARED_NONE_GAP}
        if basis == "statement":
            # A check that still records the unmapped statement contradicts this finding's
            # absence, whichever rule raised the copy it returned; plan drift is otherwise a
            # tolerated diagnostic, but never for the finding it describes. Once that code is gone
            # the empty or undeclared completion scope is answered (by statement-sourced
            # obligations or a no-material-work decision), so the scope codes only disclose.
            tolerated = (tolerated - {INSTRUCTION_REQUIREMENT_UNMAPPED_GAP}) | {
                COMPLETION_SCOPE_UNDECLARED_GAP
            }
            freshness_gaps = freshness_gaps - {COMPLETION_SCOPE_UNDECLARED_GAP}
        if gaps & _ACTION_LINK_TOLERATED_GAPS and _action_result_link_proven(
            finding, check, proof_state
        ):
            # The agent linked a result to the action: the ledger relation decides the issue
            # absent, and the content-capture limits stay disclosed on the receipt. Command gaps
            # are still decided by the partition below.
            tolerated = tolerated | _ACTION_LINK_TOLERATED_GAPS
            freshness_gaps = freshness_gaps - _ACTION_LINK_TOLERATED_GAPS
        if gaps & _COMMAND_GAPS and (
            finding.kind in _COMMAND_INDEPENDENT_KINDS
            or _requested_items_without_commands(finding, proof_state)
        ):
            # The rule that raised this finding never reads the command-attempt relation, or (a
            # requested-item finding) its obligations request no command for that relation to be
            # about.
            tolerated = tolerated | _COMMAND_GAPS
            freshness_gaps = freshness_gaps - _COMMAND_GAPS
        elif gaps & _COMMAND_GAPS:
            partition = _command_gap_partition(finding, check, proof_state)
            if partition == ():
                tolerated = tolerated | _COMMAND_GAPS
                freshness_gaps = freshness_gaps - _COMMAND_GAPS
            elif partition is not None:
                reasons.append("command_relation_overlaps_obligation:" + ",".join(partition[:16]))
                if len(partition) > 16:
                    reasons.append("additional_command_obligations_omitted")
            else:
                reasons.append("command_relation_independence_unproven")
        if not _deterministic_freshness_proven(finding, check, freshness_gaps):
            reasons.append("freshness_or_original_proof_unreadable")
    reasons.extend("coverage:" + gap for gap in sorted(gaps - tolerated))
    return tuple(reasons)


def _command_partition_candidate(
    finding: Finding,
    finding_source_frontier: int,
    check: CheckRecordedPayload,
    returned_issue_keys: frozenset[IssueKey],
) -> bool:
    """Return whether replay could affect this explanation's command-gap result.

    Keep the cheap shape and applicability guards ahead of historical replay. In particular, a
    status page may contain many semantic findings that can never use the local command exception.
    """
    return (
        bool(set(check.coverage.known_gaps) & _COMMAND_GAPS)
        and finding.origin is FindingOrigin.DETERMINISTIC
        and finding.kind is FindingKind.ACTION_WITHOUT_RESULT
        and (finding.policy_id, finding.policy_version) in _ACTION_WITHOUT_RESULT_POLICIES
        and finding_source_frontier <= check.subject_frontier.sequence
        and issue_key(finding) not in returned_issue_keys
        and check.suppressed_count == 0
        and _policy_completed(check, finding)
        and _scope_covers(check, finding)
        and finding.coverage.ledger_freshness not in _UNPROVEN_FRESHNESS
        and set(finding.coverage.known_gaps) <= _DETERMINISTIC_PROOF_TOLERATED_GAPS
        and len(finding.subject_refs) == 1
    )


def _historical_proof_state(
    check: CheckRecordedPayload,
    candidate: LedgerRecord,
    records: tuple[LedgerRecord, ...],
    cache: ProofStateCache,
) -> ProjectionState | None:
    """Replay the pre-check projection, caching it for findings sharing that candidate."""
    candidate_sequence = candidate.ledger.ingestion_sequence
    key = (
        candidate_sequence,
        check.subject_frontier.sequence,
        check.subject_frontier.head_digest,
    )
    if key in cache:
        return cache[key]

    # Rebuild the projection immediately before the candidate check. The shared partition then
    # applies its own frontier guards: newer plan/obligation/action/result/claim rows fail closed,
    # while an observation/evidence/finding suffix that the reducer permits remains equivalent.
    proof_state: ProjectionState | None = None
    pre_check = tuple(row for row in records if row.ledger.ingestion_sequence < candidate_sequence)
    if len(pre_check) == candidate_sequence - 1:
        from finishup.kernel.reducers import replay

        proof_state = replay(pre_check)
    cache[key] = proof_state
    return proof_state


def _superseded_coordination_context(
    state: ProjectionState, finding: Finding
) -> tuple[int, int] | None:
    """Return ``(generation, marker frontier)`` when a revoked context closes this finding.

    A coordination finding's subject is the delivered context event it was derived from.  The
    coordination runtime records a service-stamped ``revoked`` context for the same delivery when
    that project generation is superseded (#842); this is the replay-derived fact that lets a
    receipt say *why* a later check stopped returning the finding.
    """

    if finding.kind is not FindingKind.COORDINATION_OVERLAP:
        return None
    for ref in finding.subject_refs:
        subject = state.coordination_contexts.get(EventId(ref))
        if subject is None or subject.payload is None:
            continue
        delivered = subject.payload
        identity = (
            delivered.detection_id,
            delivered.project_id,
            delivered.membership_generation,
            delivered.recipient_task_id,
            delivered.counterpart_task_id,
        )
        markers = tuple(
            record.source_frontier
            for record in state.coordination_contexts.values()
            if record.payload is not None
            and CoordinationGapCode.REVOKED in record.payload.gap_codes
            and (
                record.payload.detection_id,
                record.payload.project_id,
                record.payload.membership_generation,
                record.payload.recipient_task_id,
                record.payload.counterpart_task_id,
            )
            == identity
        )
        if markers:
            return delivered.membership_generation, min(markers)
    return None


def _check_payload(
    records: tuple[LedgerRecord, ...], check_event_id: EventId | None
) -> CheckRecordedPayload | None:
    if check_event_id is None:
        return None
    for row in records:
        if row.event_id == check_event_id and isinstance(row.payload, CheckRecordedPayload):
            return row.payload
    return None


def _check_subject_sequence(
    records: tuple[LedgerRecord, ...], check_event_id: EventId | None
) -> int | None:
    if check_event_id is None:
        return None
    for row in records:
        if row.event_id == check_event_id and isinstance(row.payload, CheckRecordedPayload):
            return row.payload.subject_frontier.sequence
    return None


_OBSERVATION_LIMITATION_NOTE: Final = (
    " Observation-authored coverage limitation: it needs no response, is not counted as "
    "unanswered, and acknowledging it does not supersede a recorded check. It stays disclosed "
    "here and on the receipt; that does not resolve it."
)


def finding_resolution_explanation(
    state: ProjectionState,
    finding_id: FindingId,
    records: tuple[LedgerRecord, ...],
    *,
    proof_state_cache: ProofStateCache | None = None,
) -> str:
    """A bounded presentation derived from recorded checks, never response prose.

    An unresolved finding is explained against the newest later check that could resolve it (a
    completed matching review over its subject), falling back to the newest later check, and names
    a newer check that could not (issue #947).

    A current observation-authored, non-actionable row (``is_observation_limitation``) also says
    that it is a disclosed limitation rather than response work (issue #911); its resolution
    requirements and ``resolved`` state are unchanged.
    """

    explanation = _finding_resolution_explanation(
        state, finding_id, records, proof_state_cache=proof_state_cache
    )
    finding_record = state.findings.get(finding_id)
    if (
        finding_record is None
        or finding_record.payload is None
        or not is_observation_limitation_kind(finding_record.payload.kind)
        or finding_is_resolved(state, finding_id)
    ):
        return explanation
    source = next((row for row in records if row.event_id == finding_record.source_event_id), None)
    if source is None or not is_observation_limitation(
        finding_record, observation_finding_event_ids((source,))
    ):
        return explanation
    return explanation + _OBSERVATION_LIMITATION_NOTE


def _finding_resolution_explanation(
    state: ProjectionState,
    finding_id: FindingId,
    records: tuple[LedgerRecord, ...],
    *,
    proof_state_cache: ProofStateCache | None,
) -> str:
    finding_record = state.findings.get(finding_id)
    if finding_record is None or finding_record.payload is None:
        return "Resolution explanation unavailable: original finding is unreadable."
    # A reviewer's limitation request (tb4n3 RC-1, ADR-046) is a disclosure to make, not a repair:
    # it never says "repair it, then check", and once disclosed it is final and never clean.
    from finishup.kernel.limitation import limitation_standing

    standing = limitation_standing(state, finding_id)
    if standing is not None and finding_record.payload.kind is FindingKind.AGENT_CRITERION_UNMET:
        # Issue #1043: the agent's own criterion beyond the task's stated scope, never the task's.
        if standing.disclosed:
            return (
                "Criterion narrowed: the agent narrowed its own criterion (a probe beyond the "
                "task's stated scope) with a recorded reason. The item is final, is not reviewed "
                "again and is not agent work; the receipt lists it as a disclosed limitation and "
                "cannot read clean."
            )
        if standing.unmet:
            return (
                "Acknowledged, not done: the agent answered `acknowledged_not_done` on its own "
                "criterion, which says it is NOT met. The item is final, is not reviewed again, "
                "and the receipt reads unresolved_findings_remain. To narrow the criterion "
                "instead, respond `reopened` with a reason and then `acknowledged`."
            )
        return (
            "Your own criterion: a probe you authored beyond the task's stated scope fails. It is "
            "not a task requirement. Fix it (a later check that proves it absent resolves it), or "
            "narrow the criterion: respond `acknowledged` with the reason, which records a "
            "disclosed limitation that does not block (the receipt cannot read clean while it is "
            "listed). Respond `rejected` only if the finding is wrong."
        )
    if standing is not None:
        if standing.disclosed:
            return (
                "Verification limit disclosed: the agent stated that the requirement may be met "
                "but cannot be verified here. The item is final, is not reviewed again and is not "
                "agent work; the receipt lists it under verification limits and cannot read clean."
            )
        if standing.unmet:
            return (
                "Acknowledged, not done: the reviewer asked the agent to state a limit that "
                "cannot be verified here, and the agent answered `acknowledged_not_done`, which "
                "says the requirement is NOT met. The item is final, is not reviewed again, and "
                "the receipt reads unresolved_findings_remain. If it may be met but cannot be "
                "verified here, respond `reopened` with a reason and then `acknowledged`."
            )
        return (
            "To disclose: the reviewer asked the agent to state a limit that cannot be verified "
            "here. This is not repair work and does not block the receipt, which cannot read "
            "clean while it is listed. If the requirement may be met but cannot be verified "
            "here, respond `acknowledged` with the reason (or record the decision line "
            "`finishup-verification-limit:<obligation id>`); respond `acknowledged_not_done` only "
            "when you know it is not met (the receipt then keeps unresolved_findings_remain); "
            "respond `rejected` only if the finding is wrong."
        )
    # Terminal to-do states are named first (issue #905): they are final, never re-reviewed, and
    # the blockers of a later check (``reviewer_assessment_incomplete`` included) do not apply.
    response = state.responses.get(finding_id)
    disposition = (
        None if response is None or response.payload is None else response.payload.disposition
    )
    if disposition is ResponseDisposition.ACKNOWLEDGED_NOT_DONE:
        return (
            "Acknowledged, not done: the agent recorded with a reason that it will not do this. "
            "The item is final, is not reviewed again, and keeps the receipt from reading clean."
        )
    if disposition is ResponseDisposition.SELF_VERIFIED:
        return (
            "Self-verified by the agent: the agent repaired this and verified the repair itself, "
            "citing its own recorded evidence, because FinishUP could not prove it (a FinishUP limit). "
            "The item is final, is not reviewed again and is not agent work; the receipt "
            "discloses it and cannot read clean."
        )
    if (
        finding_record.rejection_accepted_by_check_event_id is not None
        and disposition is ResponseDisposition.REJECTED
        and not finding_is_resolved(state, finding_id)
    ):
        return (
            "Rejection accepted: the agent rejected this AI-powered finding with a reason and "
            f"check {finding_record.rejection_accepted_by_check_event_id} withdrew it. The item "
            "is final and no longer blocks the receipt, which still lists it."
        )
    if finding_record.disputed_after_rebuttal_by_check_event_id is not None and (
        not finding_is_resolved(state, finding_id)
    ):
        # tb4n3 RC-7 (#1030): a reasoned ``acknowledged`` is a standing position too, so the latch
        # holds whatever the latest disposition is. tb4n5 (kv ``fnd_c96c2b9f``): read only for a
        # ``rejected`` answer, an acknowledged item fell through to "repair it, then check" and
        # ``self_verified``, which ``respond`` refuses on a final item.
        standing = finding_record.standing_position
        position = (
            "rejected it"
            if standing is None or standing.kind == ResponseDisposition.REJECTED.value
            else "answered it"
        )
        return (
            f"Disputed after rebuttal: the agent {position} with a reason and check "
            f"{finding_record.disputed_after_rebuttal_by_check_event_id} kept it open without "
            "citing anything recorded after that answer. The item is final, is not agent work, "
            "takes no further response and does not block; the receipt lists it as a standing "
            "disagreement and cannot read clean."
        )
    superseded = _superseded_coordination_context(state, finding_record.payload)
    if finding_is_resolved(state, finding_id):
        resolving = finding_record.resolved_by_check_event_id
        resolving_sequence = _check_subject_sequence(records, resolving)
        if (
            superseded is not None
            and resolving_sequence is not None
            and superseded[1] <= resolving_sequence
        ):
            return (
                f"Resolved by qualifying check {resolving} after project coordination generation "
                f"{superseded[0]} was superseded; the context is retained as history, not as a "
                "current coordination obligation."
            )
        resolving_check = _check_payload(records, resolving)
        if (
            resolving_check is not None
            and prior_finding_verdict(resolving_check, finding_record.payload) == "fixed"
        ):
            disclosed = sorted(
                set(resolving_check.coverage.known_gaps) & _TASK_FACT_GAPS_TOLERATED_WHEN_FIXED,
                key=str.encode,
            )
            environment = (
                ""
                if not disclosed
                else " The environment facts that check recorded ("
                + ", ".join(disclosed)
                + ") did not hold it open; the receipt still discloses them."
            )
            return (
                f"Resolved by qualifying check {resolving}: the reviewer ruled it fixed on "
                f"material recorded after the finding; retained as history.{environment}"
            )
        return f"Resolved by qualifying check {resolving}; retained as history."
    attempt = _resolution_attempt(state, finding_record, records, proof_state_cache)
    if superseded is not None:
        candidate_sequence = (
            None
            if attempt is None
            else _check_subject_sequence(records, attempt.newest_check_event_id)
        )
        if candidate_sequence is None or candidate_sequence < superseded[1]:
            return (
                f"Unresolved: project coordination generation {superseded[0]} was superseded, so "
                "this is historical context rather than a current coordination obligation; the "
                "later qualifying coordination check can resolve it."
            )
    if attempt is None:
        return "Unresolved: no later recorded check is available for an absence proof."
    if attempt.reasons == (_CHECK_UNREADABLE,):
        return f"Unresolved: check {attempt.check_event_id} is unreadable; absence is unproven."
    if attempt.reasons == (_RETURNED_FINDINGS_UNREADABLE,):
        return f"Unresolved: returned findings of check {attempt.check_event_id} are unreadable."
    reasons = attempt.reasons
    returned_again = "issue_returned_again" in reasons
    relation = "Returned again" if returned_again else "Not returned; absence remains unproven"
    if not reasons:
        # An unavailable or provenance-disputed response can retain the public resolved=false pin.
        reasons = ("response_unavailable_or_provenance_disputed",)
    detail = ", ".join(reasons)
    if len(detail.encode("utf-8")) > 5000:
        detail = (
            detail.encode("utf-8")[:4900].decode("utf-8", errors="ignore")
            + "... (additional requirements omitted; inspect recorded check coverage)"
        )
    later = (
        ""
        if attempt.check_event_id == attempt.newest_check_event_id
        else (
            f" Later check {attempt.newest_check_event_id} did not run a completed matching "
            "review over this finding's subject, so it cannot resolve it."
        )
    )
    return (
        f"{relation} in check {attempt.check_event_id} of subject frontier "
        f"{attempt.subject_sequence}. Resolution requirements not met: {detail}."
        f"{later} {UNRESOLVED_FINDING_NEXT_STEPS}"
    )


# Synthetic reasons for a resolution attempt FinishUP could not read at all.
_CHECK_UNREADABLE: Final = "check_unreadable"
_RETURNED_FINDINGS_UNREADABLE: Final = "returned_findings_unreadable"
# What every unresolved-finding explanation tells the agent to do next, in order (issue #984,
# F1): repair first; self-verify a repair only a FinishUP limit keeps unproven; acknowledge as not
# done only as the last resort. It never invites an immediate acknowledgement.
UNRESOLVED_FINDING_NEXT_STEPS: Final = (
    "Next: repair it, then check. "
    + SELF_VERIFIED_GUIDANCE
    + " Respond acknowledged_not_done only if you truly will not or cannot do it; an "
    "acknowledgement is not repair evidence."
)


@dataclass(frozen=True, slots=True)
class ResolutionAttempt:
    """Why the newest later check that could resolve a finding did not (issue #984).

    ``check_event_id`` is the newest later check that could resolve the finding (``_could_resolve``),
    falling back to the newest later check (issue #947); ``newest_check_event_id`` is the newest
    later check. ``reasons`` are exactly ``resolution_blockers`` for that check, or one of the
    synthetic ``check_unreadable`` / ``returned_findings_unreadable`` reasons. This only exposes
    what the explanation already reports; it changes no proof rule.
    """

    check_event_id: EventId
    newest_check_event_id: EventId
    could_resolve: bool
    subject_sequence: int | None
    reasons: tuple[str, ...]


def finding_resolution_attempt(
    state: ProjectionState,
    finding_id: FindingId,
    records: tuple[LedgerRecord, ...],
    *,
    proof_state_cache: ProofStateCache | None = None,
) -> ResolutionAttempt | None:
    """The newest later resolution attempt for a readable finding, or ``None`` when none exists."""

    finding_record = state.findings.get(finding_id)
    if finding_record is None or finding_record.payload is None:
        return None
    return _resolution_attempt(state, finding_record, records, proof_state_cache)


def _resolution_attempt(
    state: ProjectionState,
    finding_record: FindingProjectionRecord,
    records: tuple[LedgerRecord, ...],
    proof_state_cache: ProofStateCache | None,
) -> ResolutionAttempt | None:
    finding = finding_record.payload
    assert finding is not None
    later_checks = tuple(
        row
        for row in reversed(records)
        if row.schema.name == "check_recorded"
        and finding_record.source_frontier < row.ledger.ingestion_sequence <= state.frontier
    )
    newest = next(iter(later_checks), None)
    if newest is None:
        return None
    # Explain the newest check that could have resolved this finding (issue #947), not merely the
    # newest one: a later scoped or local-only check would otherwise hide the blockers that matter.
    candidate = next(
        (
            row
            for row in later_checks
            if _could_resolve(state, row, finding, finding_record.source_frontier)
        ),
        None,
    )
    could_resolve = candidate is not None
    if candidate is None:
        candidate = newest
    check = candidate.payload
    if (
        not isinstance(check, CheckRecordedPayload)
        or f"redacted_event:{candidate.event_id}" in state.coverage_gaps
    ):
        return ResolutionAttempt(
            candidate.event_id, newest.event_id, could_resolve, None, (_CHECK_UNREADABLE,)
        )
    returned = [state.findings.get(key) for key in check.returned_finding_ids]
    if any(row is None or row.payload is None for row in returned):
        return ResolutionAttempt(
            candidate.event_id,
            newest.event_id,
            could_resolve,
            check.subject_frontier.sequence,
            (_RETURNED_FINDINGS_UNREADABLE,),
        )
    keys = frozenset(
        issue_key(row.payload) for row in returned if row is not None and row.payload is not None
    )
    proof_state = None
    if (
        finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
        or _command_partition_candidate(finding, finding_record.source_frontier, check, keys)
        or _action_link_candidate(finding, check)
        or (
            finding.kind is FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED
            and bool(set(check.coverage.known_gaps) & _COMMAND_GAPS)
        )
    ):
        proof_state = _historical_proof_state(
            check,
            candidate,
            records,
            {} if proof_state_cache is None else proof_state_cache,
        )
    reasons = resolution_blockers(
        finding,
        finding_record.source_frontier,
        check,
        keys,
        proof_state=proof_state,
        raised_before_task_statement=_raised_before_task_statement(
            finding, first_task_statement_sequence_of(records)
        ),
        check_change_raised_files=_record_raised_files(finding_record),
        raised_under_reduced_scope=finding_record.reduced_scope_raising_check_event_id is not None,
    )
    return ResolutionAttempt(
        candidate.event_id,
        newest.event_id,
        could_resolve,
        check.subject_frontier.sequence,
        reasons,
    )


def _could_resolve(
    state: ProjectionState, row: LedgerRecord, finding: Finding, finding_source_frontier: int
) -> bool:
    """Whether a recorded check is one that could ever resolve *finding* (issue #947).

    It must be readable, test a frontier that holds the finding, run the finding's policy to
    completion over a scope that covers its subject and, for an AI-powered finding, complete an
    AI-powered review. Every other proof requirement is what the explanation then reports.
    """

    check = row.payload
    return (
        isinstance(check, CheckRecordedPayload)
        and f"redacted_event:{row.event_id}" not in state.coverage_gaps
        and check.subject_frontier.sequence >= finding_source_frontier
        and _policy_completed(check, finding)
        and _scope_covers(check, finding)
        and (
            finding.origin is not FindingOrigin.SEMANTIC_MODEL_DERIVED
            or (
                check.semantic_status is SemanticStatus.SUCCEEDED
                and check.semantic_reason is SemanticReason.SEMANTIC_COMPLETED
            )
        )
    )


def append_resolution_explanation(detail: str, explanation: str) -> str:
    """Keep the existing content field's UTF-8 bound and visibly mark any shortened original."""

    suffix = "\n\nResolution: " + explanation
    budget = 8192 - len(suffix.encode("utf-8"))
    if len(detail.encode("utf-8")) > budget:
        detail = (
            detail.encode("utf-8")[: max(0, budget - 3)].decode("utf-8", errors="ignore") + "..."
        )
    return detail + suffix


def _raised_before_task_statement(
    finding: Finding, first_task_statement_sequence: int | None | Literal["unknown"]
) -> bool:
    """Whether no statement-capable event preceded the frontier *finding* was raised at."""

    if first_task_statement_sequence == "unknown":
        return False
    return (
        first_task_statement_sequence is None
        or first_task_statement_sequence > finding.subject_frontier.sequence
    )


def first_task_statement_sequence_of(records: tuple[LedgerRecord, ...]) -> int | None:
    """The first statement-capable event's ingestion sequence in ``records``, if any."""

    return next(
        (
            record.ledger.ingestion_sequence
            for record in records
            if may_carry_task_statement(record)
        ),
        None,
    )


# Codes that imply a check-time change reached the packet in part: without ``unavailable`` they
# mean parts were carried.
# The local structural read's skipped-path disclosure (issue #1019) says nothing about the packet.
_CHECK_TIME_CHANGE_CARRIED_GAPS: Final = CHECK_TIME_CHANGE_GAPS - {
    CHECK_TIME_CHANGE_PATH_UNREPRESENTABLE_GAP,
    CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
    *CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS,
}


def _raised_by(check: CheckRecordedPayload, finding: Finding) -> bool:
    """Whether *check* is the completed review that raised the AI-powered *finding*.

    Same tested frontier and same AI-powered review attempt, as the raising check of issue #904.
    """

    return (
        finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
        and finding.subject_frontier == check.subject_frontier
        and finding.provenance is not None
        and check.semantic_provenance is not None
        and finding.provenance.semantic_attempt_id == check.semantic_provenance.semantic_attempt_id
    )


def _raised_check_change_files(check: CheckRecordedPayload) -> CheckChangeShownFiles | None:
    """What *check*'s review saw of the change: its complete record, empty without one, else
    unknown (an incomplete record, or parts carried without a record)."""

    files = check.check_change_files
    if files is not None:
        return files if files.complete else None
    gaps = set(check.coverage.known_gaps)
    if CHECK_TIME_CHANGE_UNAVAILABLE_GAP not in gaps and gaps & _CHECK_TIME_CHANGE_CARRIED_GAPS:
        # Parts reached the packet but no record of which files did (0.3 development builds).
        return None
    return _NO_CHECK_CHANGE_FILES


def _record_raised_files(record: FindingProjectionRecord) -> CheckChangeShownFiles | None:
    return record.check_change_raised_files


def _with_raising_check(
    record: FindingProjectionRecord, check: CheckRecordedPayload, check_event_id: EventId
) -> FindingProjectionRecord:
    """Add one raising review's view of the change to R (ADR-031).

    The first contributor sets R; each later one merges into it. Unknown on either side stays
    unknown. The contributing checks are kept so redacting any of them makes R unknown.
    """

    if check_event_id in record.check_change_raising_check_event_ids:
        return record
    if len(record.check_change_raising_check_event_ids) >= MAX_CHECK_CHANGE_RAISING_CHECKS:
        # Past the contributor bound R becomes unknown and stays so; the ids already kept still
        # reopen what depended on them.
        return replace(record, check_change_raised_files=None)
    seen = _raised_check_change_files(check)
    prior = record.check_change_raised_files
    if not record.check_change_raising_check_event_ids:
        merged = seen
    elif prior is None or seen is None:
        merged = None
    else:
        merged = prior.merged(seen)
    return replace(
        record,
        check_change_raising_check_event_ids=(
            *record.check_change_raising_check_event_ids,
            check_event_id,
        ),
        check_change_raised_files=merged,
    )


def apply_check_resolution(
    findings: dict[FindingId, FindingProjectionRecord],
    check: CheckRecordedPayload,
    check_event_id: EventId,
    *,
    proof_state: ProjectionState | None = None,
    first_task_statement_sequence: int | None | Literal["unknown"] = "unknown",
) -> None:
    """Fold one recorded check into the resolution facts of the findings it could speak to.

    A finding the check resolves records the ledger sequence of the state the check tested
    (``check.subject_frontier``) as ``resolution_frontier`` (tb4n3 RC-7): it tells an absence
    proof of a state recorded after an ``acknowledged_not_done`` or ``self_verified`` answer from
    one that predates it.

    Every finding the check returned becomes current again, whatever an earlier check proved.
    An AI-powered finding this check's review raised under a reduced reference scope records this
    check as its raising check (issue #904). If any returned finding is unreadable, the check
    cannot prove which issues it re-fired, so it resolves nothing. Otherwise each readable,
    still-current finding that the qualification relation admits is marked resolved by this check.
    """

    returned_keys: set[IssueKey] = set()
    readable = True
    for returned_id in check.returned_finding_ids:
        record = findings.get(returned_id)
        if record is None or (payload := record.payload) is None:
            readable = False
            continue
        returned_keys.add(issue_key(payload))
        if record.resolved_by_check_event_id is not None:
            record = replace(
                record,
                resolved_by_check_event_id=None,
                resolution_depends_on_check_event_ids=(),
                resolution_raising_check_event_id=None,
                resolution_frontier=None,
            )
        if payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED and (
            check.semantic_conclusion is not None or _raised_by(check, payload)
        ):
            # ADR-031: every review that raised or re-raised the issue adds what it was shown;
            # a repair must then have seen at least what each of them saw.
            record = _with_raising_check(record, check, check_event_id)
        if record.reduced_scope_raising_check_event_id is None and _raises_under_reduced_scope(
            check, payload
        ):
            record = replace(record, reduced_scope_raising_check_event_id=check_event_id)
        findings[returned_id] = record
    if not readable:
        return
    frozen_keys = frozenset(returned_keys)
    for current_id, record in tuple(findings.items()):
        if (
            record.payload is None
            or record.resolved_by_check_event_id is not None
            # A terminal ``rejection_accepted`` item never upgrades to resolved (issue #905), nor
            # does a ``disputed_after_rebuttal`` one (issue #1020): the reviewer still holds it, so
            # a later review that merely stops naming it is not proof it is gone.
            or record.rejection_accepted_by_check_event_id is not None
            or record.disputed_after_rebuttal_by_check_event_id is not None
            or current_id in check.returned_finding_ids
        ):
            continue
        raised_files = _record_raised_files(record)
        raising = record.reduced_scope_raising_check_event_id
        if not qualifying_check_resolves(
            record.payload,
            record.source_frontier,
            check,
            frozen_keys,
            proof_state=proof_state,
            raised_before_task_statement=_raised_before_task_statement(
                record.payload, first_task_statement_sequence
            ),
            check_change_raised_files=raised_files,
            raised_under_reduced_scope=raising is not None,
        ):
            continue
        # A check-time limit on this check was tolerated only through the raising checks'
        # recorded files; redacting any of those checks must reopen the finding.
        depends_on = (
            record.check_change_raising_check_event_ids
            if record.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
            and set(check.coverage.known_gaps) & CHECK_TIME_CHANGE_GAPS
            else ()
        )
        # A proof that qualified only through the raising check's recorded scope also reads that
        # check, so redacting it must reopen the row just as redacting this check would (#904).
        relied_on = (
            raising
            if raising is not None
            and not qualifying_check_resolves(
                record.payload,
                record.source_frontier,
                check,
                frozen_keys,
                proof_state=proof_state,
                raised_before_task_statement=_raised_before_task_statement(
                    record.payload, first_task_statement_sequence
                ),
                check_change_raised_files=raised_files,
            )
            else None
        )
        findings[current_id] = replace(
            record,
            resolved_by_check_event_id=check_event_id,
            resolution_depends_on_check_event_ids=depends_on,
            resolution_raising_check_event_id=relied_on,
            resolution_frontier=check.subject_frontier.sequence or None,
        )


OPEN_REVIEW_VERDICTS: Final = frozenset({"answered_not_fixed", "still_present", "unassessable"})


# The agent's terminal answers to a finding (issue #980). ``self_verified`` is compared by wire
# value so this fold reads ledgers written before and after that disposition exists.
AGENT_SETTLED_DISPOSITION_VALUES: Final = frozenset({"acknowledged_not_done", "self_verified"})
# Rulings that say the concern is still there; on a settled item they record a re-raise.
_RERAISE_VERDICTS: Final = frozenset({"still_present", "answered_not_fixed"})


def _absorb_refs(current: tuple[str, ...], cited: Iterable[str]) -> tuple[str, ...]:
    """Merge a re-raise's cited refs into a settled item's absorbed concern (bounded, sorted)."""

    merged = set(current)
    for ref in cited:
        if not ref.startswith(("fnd_", "res_", "evd_", "act_")):
            merged.add(ref)
    return tuple(sorted(merged, key=str.encode))[:MAX_ABSORBED_REFS]


def next_standing_position(
    current: StandingPosition | None, response: ResponseRecordedPayload, frontier: int
) -> StandingPosition | None:
    """The agent's standing position after one more answer on a finding (tb4n3 RC-7, #1030).

    The position is the earliest unretracted *reasoned* answer: ``rejected``, ``acknowledged``,
    ``acknowledged_not_done`` or ``self_verified`` with a non-blank reason. The first one fixes
    the frontier and later ones never move it, so an acknowledgement recorded after a rebuttal
    does not erase the rebuttal (D-2). A reasoned rejection anywhere in the run makes the kind
    ``rejected``. ``reopened`` retracts the position; every other disposition leaves it as it is.
    """

    disposition = response.disposition
    if disposition is ResponseDisposition.REOPENED:
        return None
    reasoned = response.reason is not None and bool(response.reason.strip())
    if disposition.value not in STANDING_POSITION_KINDS or not reasoned:
        return current
    if current is None:
        return StandingPosition(disposition.value, frontier)
    if disposition is ResponseDisposition.REJECTED and current.kind != "rejected":
        return StandingPosition("rejected", current.frontier)
    return current


def disclosing_response(
    response: ProjectionRecord[ResponseRecordedPayload] | None,
) -> bool:
    """Whether a finding's current answer is a reasoned disclosure (the Q4 disclosure form).

    ``acknowledged`` with a non-blank reason discloses a reviewer's limitation request (the
    requirement may be met but cannot be verified here), and so does ``self_verified`` (admitted
    only on a finding FinishUP's own check cannot prove, always with a reason and the agent's
    evidence): it is the agent's final, reasoned word and the request has no other exit once it is
    given (pretrain S ``fnd_1ff0de49``). ``acknowledged_not_done`` is NOT a disclosure (owner
    decision 2026-10-12): it says the requirement is not met, so the request becomes an unmet
    requirement (``kernel.limitation``, ``limitation_acknowledged_not_done``). A rejection disputes
    the request instead (the reviewer then rules on it), ``reopened`` takes an answer back, and
    every other disposition says nothing about it.
    """

    if response is None or response.payload is None or response.redacted:
        return False
    payload = response.payload
    return (
        payload.disposition in {ResponseDisposition.ACKNOWLEDGED, ResponseDisposition.SELF_VERIFIED}
        and payload.reason is not None
        and bool(payload.reason.strip())
    )


def standing_position_of(
    record: FindingProjectionRecord | None,
    latest: ProjectionRecord[ResponseRecordedPayload] | None,
) -> StandingPosition | None:
    """The agent's standing position on a finding, from the reducer fact or its fallback.

    The reducer records ``FindingProjectionRecord.standing_position`` on every response. A record
    that carries none (an older snapshot, a hand-built projection) falls back to the latest
    response when that is itself a reasoned position, which is exactly what the reducer would
    have recorded for a single answer.
    """

    if record is None:
        return None
    if record.standing_position is not None:
        return record.standing_position
    if latest is None or latest.payload is None or latest.redacted:
        return None
    return next_standing_position(None, latest.payload, latest.source_frontier)


def rejection_stands(
    record: FindingProjectionRecord | None,
    latest: ProjectionRecord[ResponseRecordedPayload] | None,
) -> bool:
    """Whether the agent's reasoned rejection of this finding still stands (tb4n3 RC-7).

    A later ``acknowledged`` answer does not retract it; only ``reopened`` does.
    """

    position = standing_position_of(record, latest)
    return position is not None and position.kind == "rejected"


def position_stands(
    record: FindingProjectionRecord | None,
    latest: ProjectionRecord[ResponseRecordedPayload] | None,
) -> bool:
    """Whether the agent holds any reasoned position on this finding (same source as above)."""

    return standing_position_of(record, latest) is not None


def apply_check_rulings(
    findings: dict[FindingId, FindingProjectionRecord],
    responses: Mapping[FindingId, ProjectionRecord[ResponseRecordedPayload]],
    check: CheckRecordedPayload,
    check_event_id: EventId,
    *,
    check_frontier: int | None = None,
) -> None:
    """Fold one recorded check into the to-do facts of the findings it assessed (issue #905).

    Runs after ``apply_check_resolution``. A readable finding the check left open gains one review
    round: a local finding the check returned again over a later subject, or an AI-powered finding
    the reviewer ruled ``still_present``, ``answered_not_fixed`` or ``unassessable``. A
    ``withdrawn`` ruling on an AI-powered finding whose latest readable response is ``rejected``
    latches ``rejection_accepted``; the reviewer accepted the agent's reasoned rejection. A
    ``disputed_after_rebuttal`` ruling (recorded by FinishUP, issue #1020) on such a finding latches
    ``disputed_after_rebuttal`` and counts no round. Final rows (resolved,
    ``rejection_accepted``, ``disputed_after_rebuttal``, ``acknowledged_not_done``) never change,
    and nothing
    here resolves or reopens a finding. Every admitted ruling on a readable AI-powered finding also
    becomes its ``last_reviewer_verdict`` (TB4 tb4n1 D7).

    One check can reach two terminal outcomes for the same rejected finding: an assessable review
    over changed state that does not return it satisfies the absence proof, so
    ``apply_check_resolution`` has just marked it resolved by *this* check, and the same review
    rules it ``withdrawn``. The explicit ruling wins over the implicit not-returned inference: the
    reviewer said it accepts the agent's reasoned rejection, not that a repair proved the issue
    gone. The same-check absence mark is dropped and ``rejection_accepted`` is latched, so the item
    has exactly one final state. A finding an *earlier* check already proved absent is final and
    stays ``verified_resolved``.

    tb4n3 RC-7 (#1030): the agent's *standing* position decides these latches, not only its
    latest response, so an acknowledgement recorded after a rebuttal never erases it.
    ``check_frontier`` (the check's ledger sequence) becomes the finding's
    ``last_ruling_frontier``.
    """

    rulings = {item.finding_id: item.verdict for item in check.prior_finding_verdicts}
    cited_by_ruling = {item.finding_id: item.cited_refs for item in check.prior_finding_verdicts}
    for ruled_id, ruling in rulings.items():
        ruled = findings.get(ruled_id)
        if (
            ruled is not None
            and ruled.payload is not None
            and ruled.payload.origin is not FindingOrigin.DETERMINISTIC
        ):
            # The reviewer's newest answer on this item, carried to the next packet beside the
            # agent's rebuttal count (TB4 tb4n1 D7). It is a dialogue fact, never a proof.
            findings[ruled_id] = replace(
                ruled,
                last_reviewer_verdict=ruling,
                last_ruling_frontier=(
                    ruled.last_ruling_frontier if check_frontier is None else check_frontier
                ),
            )
    _break_duplicate_links(findings, responses, check, check_event_id, rulings)
    touched = frozenset(check.returned_finding_ids) | frozenset(rulings)
    for current_id in sorted(touched, key=str.encode):
        record = findings.get(current_id)
        latest = responses.get(current_id)
        if (
            record is not None
            and record.payload is not None
            and record.payload.origin is not FindingOrigin.DETERMINISTIC
            and record.resolved_by_check_event_id == check_event_id
            and record.rejection_accepted_by_check_event_id is None
            and rulings.get(current_id) == "withdrawn"
            and rejection_stands(record, latest)
        ):
            findings[current_id] = replace(
                record,
                resolved_by_check_event_id=None,
                # A resolution this ruling outranks keeps no check-time dependency (ADR-031) and
                # no reduced-scope reliance (#904).
                resolution_depends_on_check_event_ids=(),
                resolution_raising_check_event_id=None,
                resolution_frontier=None,
                rejection_accepted_by_check_event_id=check_event_id,
            )
            continue
        settled = (
            latest is not None
            and latest.payload is not None
            and latest.payload.disposition.value in AGENT_SETTLED_DISPOSITION_VALUES
        ) or (
            # tb4n3 RC-1 (Q4): a limitation request the agent disclosed with a reasoned
            # acknowledgement is settled too; a repeat is a re-raise, never a review round.
            record is not None
            and record.payload is not None
            and is_limitation_request(record.payload)
            and disclosing_response(latest)
        )
        if (
            settled
            and record is not None
            and record.payload is not None
            and record.payload.origin is not FindingOrigin.DETERMINISTIC
            and rulings.get(current_id) in _RERAISE_VERDICTS
        ):
            # The reviewer re-raised the same concern after the agent's terminal answer (issue
            # #980): recorded on the item, never a new round and never a reopening.
            # The re-raise is recorded on the item and widens its concern with what it cited
            # (bounded), so a later re-raise that names only the widened part still folds here
            # instead of being minted (formal-crypto S: the obligation first appeared in a re-raise).
            findings[current_id] = replace(
                record,
                settled_reraise_count=record.settled_reraise_count + 1,
                absorbed_refs=_absorb_refs(
                    record.absorbed_refs, cited_by_ruling.get(current_id, ())
                ),
            )
            continue
        if (
            record is None
            or record.payload is None
            or record.resolved_by_check_event_id is not None
            or record.rejection_accepted_by_check_event_id is not None
            or record.disputed_after_rebuttal_by_check_event_id is not None
            # ``acknowledged_not_done`` (and ``self_verified``) is final too: a later return of
            # the same local issue, or a stray ruling, is not a new round on it.
            or settled
        ):
            continue
        finding = record.payload
        verdict = rulings.get(current_id)
        if finding.origin is FindingOrigin.DETERMINISTIC:
            reassessed = (
                current_id in check.returned_finding_ids
                and check.subject_frontier.sequence > finding.subject_frontier.sequence
            )
            if reassessed:
                findings[current_id] = replace(record, review_rounds=record.review_rounds + 1)
            continue
        if verdict in OPEN_REVIEW_VERDICTS:
            findings[current_id] = replace(record, review_rounds=record.review_rounds + 1)
        elif verdict == DISPUTED_AFTER_REBUTTAL_VERDICT and position_stands(record, latest):
            # Issue #1020 (ADR-040): the reviewer kept the item open after the agent's reasoned
            # rejection and cited nothing newer. Final and non-blocking, never a review round.
            findings[current_id] = replace(
                record, disputed_after_rebuttal_by_check_event_id=check_event_id
            )
        elif verdict == "withdrawn" and rejection_stands(record, latest):
            findings[current_id] = replace(
                record, rejection_accepted_by_check_event_id=check_event_id
            )


# The reviewer rulings that say the issue of a ``duplicate_of`` finding is still there (#996).
DUPLICATE_LINK_BREAKING_VERDICTS: Final = frozenset({"answered_not_fixed", "still_present"})


def _break_duplicate_links(
    findings: dict[FindingId, FindingProjectionRecord],
    responses: Mapping[FindingId, ProjectionRecord[ResponseRecordedPayload]],
    check: CheckRecordedPayload,
    check_event_id: EventId,
    rulings: Mapping[FindingId, str],
) -> None:
    """Record every check that raises a linked duplicate's issue again (issue #996).

    A finding whose latest readable response is ``duplicate_of`` keeps its link until a later
    check says its own issue is still there: the check returned it again, returned a readable
    local finding with the same issue key (a deterministic rule fired again on the same subject),
    or the reviewer ruled it ``still_present`` or ``answered_not_fixed``. Each such check is
    recorded, so the link stays broken while any of them remains readable (redacting one removes
    only its id, as a full replay would). An AI-powered issue key is too coarse to stand for one
    issue, so only the finding's own id or ruling breaks its link.
    """

    returned_local_keys = {
        issue_key(record.payload)
        for returned_id in check.returned_finding_ids
        if (record := findings.get(returned_id)) is not None
        and record.payload is not None
        and record.payload.origin is FindingOrigin.DETERMINISTIC
    }
    returned = frozenset(check.returned_finding_ids)
    for current_id, record in tuple(findings.items()):
        latest = responses.get(current_id)
        if (
            record.payload is None
            or check_event_id in record.duplicate_link_broken_by_check_event_ids
            or latest is None
            or latest.payload is None
            or latest.payload.disposition is not ResponseDisposition.DUPLICATE_OF
        ):
            continue
        if (
            current_id in returned
            or rulings.get(current_id) in DUPLICATE_LINK_BREAKING_VERDICTS
            or (
                record.payload.origin is FindingOrigin.DETERMINISTIC
                and issue_key(record.payload) in returned_local_keys
            )
        ):
            findings[current_id] = replace(
                record,
                duplicate_link_broken_by_check_event_ids=(
                    *record.duplicate_link_broken_by_check_event_ids,
                    check_event_id,
                ),
            )


def reopen_findings_resolved_by(
    findings: dict[FindingId, FindingProjectionRecord],
    event_ids: frozenset[EventId],
) -> None:
    """Drop resolution whose proof was redacted: unreadable proof is no proof.

    The proof is the proving check and, for a resolution that qualified only through it, the
    raising check whose recorded reduced scope supplied the baseline (issue #904). A redacted
    raising check also no longer supplies that fallback to any later check. The same holds
    for a ``rejection_accepted`` latch whose withdrawing check was redacted, and for a
    ``disputed_after_rebuttal`` latch whose recording check was redacted (issue #1020). A redacted
    raising check likewise leaves the check-time change files unknown (ADR-031), and a
    resolution that tolerated check-time limits only through those files is dropped with it.
    """

    for current_id, record in tuple(findings.items()):
        if (
            record.resolved_by_check_event_id in event_ids
            or record.resolution_raising_check_event_id in event_ids
            or event_ids & set(record.resolution_depends_on_check_event_ids)
        ):
            record = replace(
                record,
                resolved_by_check_event_id=None,
                resolution_depends_on_check_event_ids=(),
                resolution_raising_check_event_id=None,
                resolution_frontier=None,
            )
        if record.reduced_scope_raising_check_event_id in event_ids:
            record = replace(record, reduced_scope_raising_check_event_id=None)
        if record.rejection_accepted_by_check_event_id in event_ids:
            record = replace(record, rejection_accepted_by_check_event_id=None)
        if record.disputed_after_rebuttal_by_check_event_id in event_ids:
            record = replace(record, disputed_after_rebuttal_by_check_event_id=None)
        # Issue #996: a full replay of the redacted ledger never saw the breaking check.
        if event_ids & set(record.duplicate_link_broken_by_check_event_ids):
            record = replace(
                record,
                duplicate_link_broken_by_check_event_ids=tuple(
                    item
                    for item in record.duplicate_link_broken_by_check_event_ids
                    if item not in event_ids
                ),
            )
        if event_ids & set(record.check_change_raising_check_event_ids):
            record = replace(record, check_change_raised_files=None)
        findings[current_id] = record


def finding_is_resolved(state: ProjectionState, finding_id: FindingId) -> bool:
    """The one shared answer every surface reads for ``resolved``.

    True only when a later qualifying check proved the issue absent *and* the finding's latest
    response, if any, is readable and is not ``provenance_disputed``. The released
    ``status-result`` wire pins ``provenance_disputed`` rows to ``resolved=false``; that pin is
    honoured here, conservatively, rather than letting the receipt and status disagree.
    """

    record = state.findings.get(finding_id)
    if record is None or record.payload is None or record.resolved_by_check_event_id is None:
        return False
    response = state.responses.get(finding_id)
    if response is None:
        return True
    if response.payload is None:
        return False
    disposition = response.payload.disposition
    if disposition is ResponseDisposition.PROVENANCE_DISPUTED:
        return False
    if disposition in {
        ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
        ResponseDisposition.SELF_VERIFIED,
    }:
        # ``acknowledged_not_done`` (issue #905) and ``self_verified`` (issue #984) are the
        # agent's last word: a proof of a state tested *before* it never turns them into a clean
        # row. Reverse edge (tb4n3 RC-7, owner decision 8, ADR-034/040 amendment): a qualifying
        # check that tested the work *after* that answer proves the issue absent, so the agent's
        # later repair is no longer a one-way door.
        return (
            record.resolution_frontier is not None
            and record.resolution_frontier > response.source_frontier
        )
    return True


def resolved_finding_ids(state: ProjectionState) -> frozenset[FindingId]:
    """Every finding id the shared rule reports as resolved."""

    return frozenset(key for key in state.findings if finding_is_resolved(state, key))
