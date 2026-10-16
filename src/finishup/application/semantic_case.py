"""Pure frozen-authority builder for privacy-selected AI-powered review cases.

Constructs ``SemanticCase`` / ``ReviewPacket`` from the already-frozen check case,
pinned local findings/bases, and the active ``ReviewSelectionPolicy``.

This module is deliberately capability-free: no Git, filesystem, network, transcript,
environment, database, or provider access. Captured bytes, when present, arrive as frozen
service-authenticated values; missing material becomes an omission.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import shlex
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from types import MappingProxyType
from typing import Final, Literal, NamedTuple, cast

from finishup.application.check import (
    CheckScope,
    case_coverage,
    run_deterministic_policies,
)
from finishup.application.missing_for_assessment import (
    CHECK_TIME_CHANGE_SOURCE_REF,
    OBSERVED_COMMAND_OUTPUT_SPAN_PREFIX,
    ReviewFollowUp,
    check_change_binary_paths,
    check_change_text_paths,
    command_run_key,
    excerpt_span,
    excerpt_span_covered,
    excerpt_span_key,
    excerpt_span_whole,
    observed_enrichment_refs,
    observed_image_evidence,
    supplied_since,
    unsupported_data_type,
)
from finishup.domain.command_segments import command_structure, strip_wrappers
from finishup.domain.events import (
    MAX_PRIOR_FINDING_LISTED_REFS,
    ActionKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    DecisionRecordedPayload,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceImmutability,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    ResultOutcome,
    encode_payload,
)
from finishup.domain.findings import Finding, FindingKind, FindingOrigin
from finishup.domain.observation import (
    ObservationContentKind,
    ObservationContentManifest,
    ObservationSource,
)
from finishup.domain.observation_profiles import ORDINARY_CONTENT_CAPTURE_PROFILE_IDS
from finishup.domain.observation_selection import command_is_verification
from finishup.domain.privacy import (
    MAX_EGRESS_ENVELOPE_BYTES,
    REVIEW_PACKET_ITEM_ID,
    AuthorizationScope,
    CandidateContext,
    CandidateContextItem,
    EgressChannel,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,
    CHECK_TIME_CHANGE_REDACTED_GAP,
    CHECK_TIME_CHANGE_TRUNCATED_GAP,
    CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
    CHECK_TIME_CHANGE_UNAVAILABLE_REASONS,
    SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP,
    SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP,
    SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_MISMATCH_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_PARSE_FAILED_GAP,
    check_time_change_unavailable_reason_gap,
)
from finishup.domain.repository_excerpt import credential_named_path
from finishup.domain.task_statement import (
    TASK_STATEMENT_NOT_AUTHORIZED_GAP,
    TASK_STATEMENT_NOT_SUPPLIED_GAP,
    TASK_STATEMENT_SECTION,
    TASK_STATEMENT_UNAVAILABLE_GAP,
    TaskStatementSource,
)
from finishup.domain.values import (
    EventId,
    JsonObject,
    SubjectStateRelation,
    freeze_json,
    session_id,
    task_id,
    validate_commitment,
    validate_sha256_digest,
)
from finishup.domain.values import (
    action_id as validate_action_id,
)
from finishup.domain.values import (
    evidence_id as validate_evidence_id,
)
from finishup.domain.values import (
    finding_id as finding_id_value,
)
from finishup.kernel.claims import effective_claim_items
from finishup.kernel.delivered_set import declared_delivered_items
from finishup.kernel.deterministic_checks import (
    REQUESTED_OUTPUT_ABSENT_FACT,
    DeterministicAssessment,
    DeterministicCase,
    FrozenHistoryEvent,
)
from finishup.kernel.finding_resolution import AGENT_SETTLED_DISPOSITION_VALUES
from finishup.kernel.finding_todo import (
    FindingTodoState,
    duplicate_link_target,
    finding_todo_state,
)
from finishup.kernel.limitation import LimitationStanding, limitation_standing
from finishup.kernel.lineage import LineageEvaluation
from finishup.kernel.projections import (
    EvidenceProjectionRecord,
    FindingProjectionRecord,
    ProjectionState,
)
from finishup.kernel.task_facts import (
    DECLARED_OUTPUT_CONTENT_MOVED_GAP,
    DECLARED_OUTPUT_EMPTIED_GAP,
    DECLARED_OUTPUT_REMOVED_GAP,
    DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP,
    REQUESTED_OUTPUT_GIT_IGNORED_GAP,
    REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,
    REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,
    REQUESTED_OUTPUT_UNCHANGED_GAP,
    REQUESTED_OUTPUT_UNVERIFIED_GAP,
    acknowledged_obligation_ids,
    blocker_declarations,
    disclosure_declarations,
    effective_obligations,
    open_effective_obligations,
)
from finishup.kernel.test_edit_visibility import check_change_header_entries, check_change_sections
from finishup.legacy_names import LEGACY_PRODUCT_NAME, PRODUCT_NAME
from finishup.observability.privacy import (
    EGRESS_CREDENTIAL_PLACEHOLDER,
    PrivacyFenceError,
    ScanConfidence,
    redact_sensitive_content,
    scan_for_sensitive_content,
)
from finishup.ports.change_capture import (
    CHECK_CHANGE_MEDIA_TYPE,
    MAX_TASK_INPUT_FILES,
    CheckChangeCapture,
)
from finishup.ports.objects import ObjectKind, ObjectRef
from finishup.ports.semantic import (
    MAX_PRIOR_FINDING_ITEMS,
    MAX_REVIEW_INPUT_SECTION_ITEMS,
    MAX_SEMANTIC_CASE_ITEMS,
    MAX_SEMANTIC_ITEM_SUBJECT_REFS,
    SETTLED_FINDING_ITEM_PREFIX,
    ChangeObservation,
    ExcerptDigestProvenance,
    MissingForAssessmentKind,
    ReviewAssessment,
    ReviewAssessmentSkipped,
    ReviewInputManifest,
    ReviewInputMissing,
    ReviewInputSection,
    ReviewOmission,
    ReviewPacket,
    SemanticCase,
    SemanticCaseItem,
    TargetedExcerptRef,
    project_review_assessment,
)
from finishup.ports.semantic_budget import (
    SemanticBudgetProfile,
    parse_semantic_budget_profile,
    select_semantic_budget_profile,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.coverage import LedgerFreshness, coverage_to_json
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import (
    MAX_REVIEW_OMISSION_TOTAL,
    MAX_REVIEW_OMISSIONS,
    MAX_REVIEW_TEXT_BYTES,
    MAX_REVIEW_TIMELINE_ITEMS,
    MAX_SEMANTIC_CASE_BYTES,
    MAX_SEMANTIC_ITEM_BYTES,
    DataCategory,
)
from finishup.protocol.policy_packs import (
    RESEARCH_EVIDENCE_POLICY_ID,
    WORK_INTEGRITY_POLICY_ID,
    current_policy_pack,
)

__all__ = [
    "MAX_TASK_STATEMENT_ITEM_BYTES",
    "TASK_STATEMENT_ITEM_ID",
    "CHECK_TIME_CHANGE_ITEM_PREFIX",
    "CHECK_TIME_SECTION_ITEM_PREFIX",
    "DECLARED_DELIVERABLES_ITEM_ID",
    "TASK_INPUT_ITEM_PREFIX",
    "CheckTimeChangeShownFile",
    "check_time_change_bytes_carried",
    "check_time_change_parts_carried",
    "check_time_change_sections_carried",
    "check_time_change_shown_files",
    "check_time_change_shown_record",
    "CapturedContentScope",
    "CapturedSemanticContent",
    "CheckTimeChange",
    "MAX_CAPTURED_SEMANTIC_CONTENT_BYTES",
    "MAX_CAPTURED_SEMANTIC_CONTENT_PARTS",
    "MAX_CAPTURED_SEMANTIC_INPUT_BYTES",
    "LineageSemanticCapacityExceeded",
    "SemanticCaseCapacityExceeded",
    "OVER_CASE_ITEM_LIMIT_REASON",
    "REVIEW_PACKET_ITEM_ID",
    "REVIEW_PHASE_QUESTIONS",
    "SEMANTIC_REVIEW_PURPOSE",
    "assemble_filtered_review_packet",
    "build_semantic_case",
    "carries_task_inputs",
    "follow_up_byte_budget",
    "follow_up_new_parts",
    "current_section_parts",
    "bounded_catalog_item_ids",
    "recorded_blockers",
    "acknowledged_obligation_rows",
    "BLOCKER_REVIEW_INSTRUCTION",
    "review_question_set",
    "captured_edit_paths",
    "review_selection_digest",
    "ReviewPacketDisclosure",
    "ReviewPacketDisclosureResult",
    "review_input_manifest",
    "review_input_manifest_to_json",
    "declared_output_capture_order",
    "declared_output_capture_refs",
    "excerpt_content_refs",
    "repair_evidence_refs",
    "SemanticPacketView",
    "semantic_case_packet_view",
    "review_packet_content_refs",
    "review_packet_disclosure",
    "review_packet_disclosure_result",
    "sent_excerpt_content_refs",
    "sent_excerpt_parts",
    "sent_ledger_refs",
    "withheld_excerpt_content_refs",
    "semantic_case_to_candidate_context",
    "review_item_catalog",
    "review_envelope_to_candidate_context",
    "semantic_case_to_prepared_payload",
]

SEMANTIC_REVIEW_PURPOSE: Final = "semantic-review"
# Marker reason for content the case admitted and then could not carry whole. Distinct from the
# `not_selected` omission vocabulary, which means the selection policy declined to carry it.
OVER_CASE_ITEM_LIMIT_REASON: Final = "over_case_item_limit"
# Version 2 (issue #907) carries each item's recording order and excerpt freshness marks, and
# lists items in case order (section, then recording order) instead of by opaque item id.
# Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
_PACKET_SCHEMA: Final = "yoetz.review-packet-case/2"
# Packet omission-row reasons that the closed review-input section vocabulary spells differently.
_SECTION_OMISSION_REASON_ALIASES: Final[Mapping[str, str]] = {
    "never_send_heuristic": "redacted_never_send",
}
# Long output keeps its head and its tail: the command and first failure sit at the top, and the
# test/lint summary line sits at the bottom. The marker says how much was cut and where.
_ELISION_MARKER: Final = "\n[finishup: {elided} of {total} bytes elided here; head and tail kept]\n"
# Below this many bytes per side a head-and-tail split is not worth its marker; a very narrow
# custom excerpt bound keeps the head instead.
_MIN_HEAD_TAIL_SIDE_BYTES: Final = 64
# Strings at or below this size are identifiers, digests or enum tokens, never prose to clip.
_MIN_CLIPPABLE_PROSE_BYTES: Final = 256
# The gateway compares the whole prepared provider document with the channel byte ceiling, whose
# schema maximum is MAX_SEMANTIC_CASE_BYTES (and the bytes/4 token estimate reaches the same
# ceiling). Selection plans below it so a larger excerpt can never turn a reviewable case into a
# policy denial; the reserve absorbs privacy redaction markers that can differ in length. The
# same reserve applies below a narrower owner ceiling.
_PLANNING_RESERVE_BYTES: Final = 4_096
_PREPARED_PAYLOAD_PLANNING_BYTES: Final = MAX_SEMANTIC_CASE_BYTES - _PLANNING_RESERVE_BYTES
_PLANNING_GRANULARITY_BYTES: Final = 1_024
_PACKET_ID_LIST_KEYS: Final = (
    "task_statement_item_ids",
    "goal_item_ids",
    "obligation_item_ids",
    "claim_item_ids",
    "decision_item_ids",
    "prior_finding_item_ids",
    "timeline_item_ids",
)
# The prior-findings section (issue #905) has its own bounds, outside the timeline's 64 rows.
# Sixteen findings in 96 KiB (TB4 tb4n1 D10, issue #976: eight dropped open findings in six
# attempts); the section still takes only the room the case bounds leave.
MAX_PRIOR_FINDINGS: Final = 16
MAX_PRIOR_FINDING_SECTION_BYTES: Final = 96 * 1024
# Answers to local findings carried beside them (issue #976); they share the section's bounds.
MAX_LOCAL_FINDING_ANSWERS: Final = 4
# Refs listed per structural row; the full counts travel beside them.
_MAX_PRIOR_FINDING_LISTED_REFS: Final = MAX_PRIOR_FINDING_LISTED_REFS
_CANONICAL_PACKS: Final = (
    current_policy_pack(RESEARCH_EVIDENCE_POLICY_ID),
    current_policy_pack(WORK_INTEGRITY_POLICY_ID),
)
# The question set leads with the review phase, taken from the same pure selector that picks the
# check's budget profile, so the reviewer judges in-progress work as in progress and a completion
# claim as a completion claim (issue #906). No question presupposes a defect or asks for the
# agent's next step: the reviewer reports what it verified, every distinct problem it found, and the
# exact artifact any unassessable item lacks.
REVIEW_PHASE_QUESTIONS: Final[Mapping[SemanticBudgetProfile, str]] = MappingProxyType(
    {
        # Issue #1042: incomplete work only; a correctness concern is an advisory code_defect.
        "routine": (
            "Review phase: routine. Work is in progress and no completion claim is in effect: "
            "judge incomplete work only (an obligation marked resolved or left unfinished, "
            "planned verification not run, a missing or emptied output, a done or ran claim the "
            "packet does not show, an early stop); work not yet started is not a defect. Return a "
            "correctness concern as code_defect: FinishUP records it as an advisory note."
        ),
        "final": (
            "Review phase: final. This is the closing review, with or without a completion "
            "claim: judge completeness against the task statement. For each stated requirement "
            "and requested output (path), say whether the change and its recorded verification "
            "deliver it, and challenge each one they do not. A requirement only a hidden "
            "evaluator or an artifact the agent cannot obtain can establish is a not_assessable "
            "row, not a challenge, once the packet shows the agent disclosed it. For each "
            "requirement, name the assumption, method or check its result rests on and judge that "
            "against the task: a result that holds only under the agent's own premise or "
            "validator is not support (issue #1082)."
        ),
    }
)
_REVIEW_QUESTIONS: Final = (
    "What did you verify against the task and the change, how (the code path, output or recorded "
    "check you read), and with what result? What could you not check?",
    "Which distinct material problems, if any, does the readable material show, and which "
    "case-bound refs support each?",
    "For anything you could not assess, which exact artifact is missing?",
)


# The review lists claimed and confirmed blockers alike, so it never needs the publish batches.
_NO_BATCHES: Final[Mapping[EventId, str]] = MappingProxyType({})
# A closing review names at most this many recorded blockers in its blocker question.
MAX_REVIEWED_BLOCKERS: Final = 16


def recorded_blockers(projection: ProjectionState) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """``(decision event id, kind, open obligation ids)`` for each recorded blocker (#976, #977).

    Only open effective obligations count, as in closure readiness; a blocker the agent only
    claimed is listed as well as a confirmed one (#985), because the closing review is where a
    claim is tested. A blocker naming only finished obligations has no effect and is not asked
    about (its publish result already told the agent so). Ids and the closed kind only: the
    decision's statement and rationale, and the obligation's own text, reach the reviewer through
    their privacy-gated packet items, never through this summary.
    """

    open_obligations = set(open_effective_obligations(projection))
    grouped: dict[str, tuple[str, set[str]]] = {}
    for obligation, declaration in blocker_declarations(projection, _NO_BATCHES).items():
        if obligation not in open_obligations:
            continue
        row = grouped.setdefault(str(declaration.decision_event_id), (declaration.kind, set()))
        row[1].add(str(obligation))
    return tuple(
        (decision, kind, tuple(sorted(obligations, key=str.encode)))
        for decision, (kind, obligations) in sorted(
            grouped.items(), key=lambda row: row[0].encode()
        )
    )


# Obligations named per blocker decision, and the byte bound of the listing itself, so the
# question stays far below ``MAX_REVIEW_TEXT_BYTES`` however many obligations a decision names.
_MAX_BLOCKER_OBLIGATIONS_LISTED: Final = 8
_MAX_BLOCKER_LISTING_BYTES: Final = 1_536
# Issue #978 (tb4v2/tb4n1 pretrain-shard-corruption): the reviewer accepted a
# ``dependency_unavailable`` blocker on the task's main deliverable although the statement said
# "The final state should recover the intended training examples". The question therefore makes
# the reviewer read the blocked obligation's own text first and lists the cases in which a
# challenge is required, not optional. Being the main deliverable calls for scrutiny only: a
# genuine credential or authority blocker may stand there. The obligation text stays in its
# privacy-gated packet item (``obligation-<id>``); this fixed text never carries agent or user
# content.
BLOCKER_REVIEW_INSTRUCTION: Final = (
    "A blocker's kind and the agent's account of it are its claim, not evidence that an authority,"
    " a dependency or data is missing (issue #1082)."
    " For each blocker, first quote the blocked obligation's own description and evidence"
    " expectation from its packet item obligation-<obligation id> (say so if the packet does not"
    " carry it), then verify the blocker once against the task statement and the work. You must"
    " challenge it (one finding citing whichever of its decision and obligation ids citable_refs"
    " lists, naming the work the agent can still do) when any of these holds: the task statement"
    " says the outcome is achievable or the data recoverable (for example that the final state"
    " should recover the intended data); the agent has not attempted the obvious prerequisite"
    " (inspecting the inputs it has, deriving or reconstructing what is missing); the readable"
    " material contradicts it (the dependency is present, the authority was granted); or it names"
    " something FinishUP or this review could not show or prove, which is never a blocker. When the"
    " blocked obligation is the task's main deliverable, scrutinise the blocker closely, but a"
    " genuine blocker outside the agent's control (authority, consent, a credential, a dependency"
    " it cannot obtain) that none of these contradicts stands as a disclosed limitation even then:"
    " do not challenge that one."
)


def acknowledged_obligation_rows(projection: ProjectionState) -> tuple[str, ...]:
    """Effective obligations acknowledged as not done (#997), ids only, sorted.

    The closing review tests them against the task statement the way it tests blockers: an
    acknowledgement is the agent's own position and FinishUP cannot verify that the work is
    genuinely impossible.
    """

    return tuple(sorted(acknowledged_obligation_ids(projection), key=str.encode))


# Fixed text appended when the agent acknowledged obligations as not done (#997).
ACKNOWLEDGED_REVIEW_INSTRUCTION: Final = (
    "An acknowledgement is the agent's claim, not evidence that the work cannot be done."
    " For each obligation acknowledged as not done, quote its own description from its packet"
    " item obligation-<obligation id>, then verify the acknowledgement against the task statement"
    " and the work: challenge it (one finding citing the obligation id, naming the work the agent"
    " can still do) when the task statement requires that work and the readable material shows"
    " the agent can do it, or when the agent did not attempt the obvious prerequisite. A genuine"
    " blocker outside the agent's control (authority, consent, a credential, a hidden evaluator"
    " or reference it cannot obtain, an answer only the user has) that none of this contradicts"
    " stands as a disclosed limitation: do not challenge it, and where you want the limit stated"
    " ask for state_unresolved_limitation. What FinishUP or this review could not show or prove is"
    " never a reason to challenge. Never recommend emptying, deleting or withdrawing a deliverable"
    " that passes its recorded tests: it is a partial solution to keep and disclose, not"
    " an unsolved task."
)
_MAX_ACKNOWLEDGED_LISTED: Final = 8


def _acknowledged_question(acknowledged: tuple[str, ...]) -> str:
    listed = ", ".join(acknowledged[:_MAX_ACKNOWLEDGED_LISTED])
    hidden = len(acknowledged) - _MAX_ACKNOWLEDGED_LISTED
    return (
        f"Obligations acknowledged as not done: {listed}"
        + (f" (+{hidden} more)" if hidden > 0 else "")
        + ". "
        + ACKNOWLEDGED_REVIEW_INSTRUCTION
    )


def _blocker_question(
    blockers: tuple[tuple[str, str, tuple[str, ...]], ...],
    acknowledged: tuple[str, ...] = (),
) -> str:
    if not blockers:
        return _acknowledged_question(acknowledged)
    rows: list[str] = []
    used = 0
    for decision, kind, obligations in blockers[:MAX_REVIEWED_BLOCKERS]:
        listed = ", ".join(obligations[:_MAX_BLOCKER_OBLIGATIONS_LISTED])
        hidden = len(obligations) - _MAX_BLOCKER_OBLIGATIONS_LISTED
        row = f"decision {decision} declares finishup-blocker:{kind} for {listed}" + (
            f" (+{hidden} more)" if hidden > 0 else ""
        )
        if rows and used + len(row) + 2 > _MAX_BLOCKER_LISTING_BYTES:
            break
        rows.append(row)
        used += len(row) + 2
    more = len(blockers) - len(rows)
    return (
        f"Recorded blockers: {'; '.join(rows)}"
        + (f" (+{more} more blocker decisions)" if more > 0 else "")
        + ". "
        + BLOCKER_REVIEW_INSTRUCTION
        + (" " + _acknowledged_question(acknowledged) if acknowledged else "")
    )


def review_question_set(
    phase: SemanticBudgetProfile,
    blockers: tuple[tuple[str, str, tuple[str, ...]], ...] = (),
    acknowledged: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Return the closed question set for one review phase.

    The final phase adds one blocker question when ``blockers`` (``recorded_blockers``) is not
    empty; the routine phase never judges blockers.
    """

    parsed = parse_semantic_budget_profile(phase)
    extra = (
        (_blocker_question(blockers, acknowledged),)
        if parsed == "final" and (blockers or acknowledged)
        else ()
    )
    return (REVIEW_PHASE_QUESTIONS[parsed], *_REVIEW_QUESTIONS, *extra)


type _Section = Literal[
    "task_statement",
    "goal",
    "obligation",
    "claim",
    "decision",
    "prior_finding",
    "timeline",
    "deterministic_summary",
    "deterministic_detail",
    "excerpt",
]
type _SourceKind = Literal[
    "task",
    "obligation",
    "claim",
    "decision",
    "action",
    "result",
    "evidence",
    "finding",
    "test",
    "failure",
    "diff",
    "command",
    "repository",
]
type _ExcerptKind = Literal["evidence", "test", "failure", "diff", "command", "repository"]

# Fixed labels the provider packet carries beside each item of these sections. The plan item is
# the agent's own summary; only the task statement is the user's request (issue #908). A plan item
# is never labelled as the task statement, whatever its content.
_SECTION_LABELS: Final[Mapping[str, str]] = {
    TASK_STATEMENT_SECTION: (
        "task statement: what the user asked for; the source field says who supplied the text"
    ),
    "goal": "agent plan (the agent's own summary)",
}
TASK_STATEMENT_ITEM_ID: Final = "task-statement"
# Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
_TASK_STATEMENT_CONTENT_SCHEMA: Final = "yoetz.task-statement/1"
# One statement item is bounded like one excerpt: 16 KiB of canonical JSON. A longer statement
# keeps its head and tail and marks what was elided in between.
MAX_TASK_STATEMENT_ITEM_BYTES: Final = MAX_SEMANTIC_ITEM_BYTES
_PLAN_FAMILIES: Final = frozenset({"plan_published", "plan_revised"})
type _OmissionReason = Literal[
    "not_recorded",
    "not_selected",
    "withheld_by_policy",
    "redacted_never_send",
    "never_send_heuristic",
]

# The observation ingest bound is intentionally larger than one AI-powered review case item. The service-side
# resolver authenticates a complete retained chunk here, after which the selection policy clips it
# to its own excerpt/item/total limits. Keeping this bound below the ordinary object-store limit
# prevents a malformed captured-content wrapper from becoming an unbounded AI-powered review input.
MAX_CAPTURED_SEMANTIC_CONTENT_BYTES: Final = 512 * 1024
# Frozen legacy identifier (ADR-048): media type of stored observation content.
_CAPTURED_CONTENT_MEDIA_TYPE: Final = "application/vnd.yoetz.observation-content+json"
_CAPTURED_CONTENT_KINDS: Final = frozenset(
    {
        ObservationContentKind.TOOL_OUTPUT,
        ObservationContentKind.CHANGED_FILE,
        ObservationContentKind.WORKSPACE_DIFF,
    }
)
# The resolver and pure builder share the closed profile vocabulary. The builder still
# treats its scope as a service-authenticated assertion; it does not discover consent.
#
# Codex's original observation consent predates the opt-in Claude/Cursor content profiles.  The
# source token below is an internal scope label for that historical, profileless grant; it is not a
# user-selectable content profile and is never accepted by the local consent/profile adapters.
_CODEX_HISTORICAL_CAPTURE_SCOPE: Final = ObservationSource.CODEX_HOOK.value
_AUTHORIZED_CAPTURE_PROFILES: Final = frozenset(
    {*ORDINARY_CONTENT_CAPTURE_PROFILE_IDS, _CODEX_HISTORICAL_CAPTURE_SCOPE}
)
MAX_CAPTURED_SEMANTIC_CONTENT_PARTS: Final = 64
MAX_CAPTURED_SEMANTIC_INPUT_BYTES: Final = 2 * MAX_CAPTURED_SEMANTIC_CONTENT_BYTES
_CAPTURE_GAP_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)


@dataclass(frozen=True, slots=True)
class CapturedContentScope:
    """Current service-authorized boundary for native captured AI-powered review content.

    The scope is assembled by the service after it checks the active local consent arm. The pure
    case builder accepts it as a frozen assertion and still rechecks every excerpt against the
    projection and scope; it never discovers consent or reads an object itself.
    """

    task_id: str
    session_id: str
    workspace_commitment: str
    authorized_profiles: tuple[str, ...]
    # Each entry is a service-derived evidence ref → phase identity binding.  A
    # caller-supplied phase digest is useful only when it agrees with the durable
    # evidence/envelope identity that the resolver derived before opening bytes.
    phase_bindings: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "task_id", task_id(self.task_id))
            object.__setattr__(self, "session_id", session_id(self.session_id))
            object.__setattr__(
                self,
                "workspace_commitment",
                validate_commitment(self.workspace_commitment),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("semantic_case_capture_scope_invalid") from exc
        if type(self.authorized_profiles) is not tuple or not self.authorized_profiles:
            raise ValueError("semantic_case_capture_scope_invalid")
        if any(profile not in _AUTHORIZED_CAPTURE_PROFILES for profile in self.authorized_profiles):
            raise ValueError("semantic_case_capture_scope_invalid")
        if self.authorized_profiles != tuple(sorted(set(self.authorized_profiles), key=str.encode)):
            raise ValueError("semantic_case_capture_scope_invalid")
        if (
            type(self.phase_bindings) is not tuple
            or len(self.phase_bindings) > MAX_CAPTURED_SEMANTIC_CONTENT_PARTS
        ):
            raise ValueError("semantic_case_capture_scope_invalid")
        normalized_bindings: list[tuple[str, str]] = []
        for binding in self.phase_bindings:
            if type(binding) is not tuple or len(binding) != 2:
                raise ValueError("semantic_case_capture_scope_invalid")
            try:
                ref = validate_evidence_id(binding[0])
                phase = validate_sha256_digest(binding[1])
            except (TypeError, ValueError) as exc:
                raise ValueError("semantic_case_capture_scope_invalid") from exc
            normalized_bindings.append((str(ref), phase))
        if tuple(normalized_bindings) != tuple(
            sorted(set(normalized_bindings), key=lambda item: item[0].encode("ascii"))
        ):
            raise ValueError("semantic_case_capture_scope_invalid")


@dataclass(frozen=True, slots=True)
class CapturedSemanticContent:
    """One service-authenticated, complete observation-content part.

    ``content`` is the decoded inner bytes, never the encrypted object wrapper. The resolver owns
    object authentication and supplies the exact ``ObjectRef``/manifest pair. The builder then
    verifies the pair and maps only content whose object is already represented by a case-bound
    observation evidence row.
    """

    object_ref: ObjectRef
    manifest: ObservationContentManifest
    content: bytes
    task_id: str
    session_id: str
    workspace_commitment: str
    phase_identity: str
    capture_profile: str
    capture_gaps: tuple[str, ...] = ()
    # Same-phase authenticated post-tool input, supplied by the resolver; never sent.
    observed_command: str | None = dataclass_field(default=None, repr=False)
    observed_command_identity: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.object_ref) is not ObjectRef
            or type(self.manifest) is not ObservationContentManifest
        ):
            raise ValueError("semantic_case_captured_content_invalid")
        if (
            self.manifest.content_kind not in _CAPTURED_CONTENT_KINDS
            or self.manifest.envelope_digest is None
            or self.manifest.content_digest is None
            or self.manifest.content_bytes is None
            or self.manifest.correlation_identity is None
            or self.manifest.source_commitment is None
            or type(self.manifest.redacted) is not bool
        ):
            raise ValueError("semantic_case_captured_content_invalid")
        if (
            self.object_ref.metadata.kind is not ObjectKind.CAPTURED_CONTENT
            or self.object_ref.metadata.media_type != _CAPTURED_CONTENT_MEDIA_TYPE
            or self.object_ref.object_id != self.manifest.object_id
            or self.object_ref.envelope_digest != self.manifest.envelope_digest
        ):
            raise ValueError("semantic_case_captured_content_invalid")
        if (
            type(self.content) is not bytes
            or not 1 <= len(self.content) <= MAX_CAPTURED_SEMANTIC_CONTENT_BYTES
        ):
            raise ValueError("semantic_case_captured_content_invalid")
        try:
            self.content.decode("utf-8", errors="strict")
            actual_digest = "sha256:" + hashlib.sha256(self.content).hexdigest()
            object.__setattr__(self, "task_id", task_id(self.task_id))
            object.__setattr__(self, "session_id", session_id(self.session_id))
            object.__setattr__(
                self,
                "workspace_commitment",
                validate_commitment(self.workspace_commitment),
            )
            object.__setattr__(
                self,
                "phase_identity",
                validate_sha256_digest(self.phase_identity),
            )
        except (TypeError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError("semantic_case_captured_content_invalid") from exc
        if self.object_ref.metadata.task_id != self.task_id:
            raise ValueError("semantic_case_captured_content_invalid")
        if self.manifest.content_digest != actual_digest or self.manifest.content_bytes != len(
            self.content
        ):
            raise ValueError("semantic_case_captured_content_invalid")
        if (
            type(self.capture_profile) is not str
            or self.capture_profile not in _AUTHORIZED_CAPTURE_PROFILES
        ):
            raise ValueError("semantic_case_captured_content_invalid")
        if type(self.capture_gaps) is not tuple or len(self.capture_gaps) > 16:
            raise ValueError("semantic_case_captured_content_invalid")
        if any(
            type(gap) is not str or _CAPTURE_GAP_PATTERN.fullmatch(gap) is None
            for gap in self.capture_gaps
        ) or self.capture_gaps != tuple(sorted(set(self.capture_gaps), key=str.encode)):
            raise ValueError("semantic_case_captured_content_invalid")


@dataclass(frozen=True, slots=True)
class _CapturedGroup:
    evidence_refs: tuple[str, ...]
    content: bytes
    source_kind: _ExcerptKind
    digest_provenance: ExcerptDigestProvenance
    capture_gaps: tuple[str, ...]
    redacted: bool = False
    observed_command: str | None = dataclass_field(default=None, repr=False)
    observed_command_identity: str | None = None


@dataclass(frozen=True, slots=True)
class CheckTimeChange:
    """The one service-captured check-time change a case may carry (ADR-031).

    The service read the task's repository when this check ran, redacted the rendered change, and
    stored it as one encrypted object before building the case. The builder never reads Git or an
    object: it verifies the frozen value, links it to the case's claims and obligations, and splits
    its text into bounded excerpts ahead of every other excerpt.
    """

    object_ref: ObjectRef
    capture: CheckChangeCapture

    def __post_init__(self) -> None:
        if type(self.object_ref) is not ObjectRef or type(self.capture) is not CheckChangeCapture:
            raise ValueError("semantic_case_check_change_invalid")
        if (
            self.object_ref.metadata.kind is not ObjectKind.CHANGE_CAPTURE
            or self.object_ref.metadata.media_type != CHECK_CHANGE_MEDIA_TYPE
        ):
            raise ValueError("semantic_case_check_change_invalid")


# Item ids sort ahead of every other case item, so the provider document lists the change first.
CHECK_TIME_CHANGE_ITEM_PREFIX: Final = "change-check-time-"
_CHECK_TIME_CHANGE_SOURCE_REF: Final = CHECK_TIME_CHANGE_SOURCE_REF
# Read-only task input files the same service read carried (issue #1045): one excerpt each, ranked
# with the change's leftover parts ahead of older edits and general output, within at most a
# quarter of the recipe's excerpt bytes on that first offer.
TASK_INPUT_ITEM_PREFIX: Final = "task-input-"
_TASK_INPUT_SOURCE_REF: Final = "task-input"
_TASK_INPUT_SHARE_DIVISOR: Final = 4
_TASK_INPUT_LABEL: Final = (
    "[FinishUP task input file {path} ({size} bytes{cut}): named by the task, unchanged since the "
    "task started, read by the FinishUP service when this check ran; not the agent's work]\n"
)


def carries_task_inputs(selection: ReviewSelectionPolicy) -> bool:
    """Whether a review under ``selection`` carries read-only task input files (issue #1045).

    They ride the check-time read, are named by the task statement and leave as repository
    excerpts, so the recipe must carry the change, the statement and the ``repository`` kind.
    """

    return (
        selection.carries_check_time_change
        and TASK_STATEMENT_SECTION in selection.sections
        and "repository" in selection.excerpt_kinds
    )


_CHECK_TIME_CHANGE_MARKER: Final = "[FinishUP check-time change, part {index} of {count}]\n"
# The first part cut to the room a narrowed case leaves (issue #983): the reviewer still reads the
# change's leading bytes, and the cut is disclosed as a truncated change.
_CHECK_TIME_CHANGE_CUT_MARKER: Final = (
    "[FinishUP check-time change, part {index} of {count}, cut to the packet's room]\n"
)
_CHECK_TIME_CHANGE_MIN_CHUNK: Final = 256


def _check_time_change_reservation(
    selection: ReviewSelectionPolicy, first_part_bytes: int
) -> tuple[int, int]:
    """Excerpt slots and bytes held for the check-time change before any other excerpt (#883).

    Half of the recipe's excerpt count and total bytes, and never less than one slot, are offered
    to the service-captured change first. The byte share is rounded up to the change's first part,
    so a recipe whose total budget carries one part always admits it ahead of every other excerpt
    (a part is never larger than that total, see ``_check_time_change_part_limit``). Room it does
    not use stays with the other excerpts. Its parts left over then take every byte and slot the
    reserved excerpt classes (the newest captured edit per path, the latest verification runs and
    finding repair evidence) leave, ahead of older edit hunks and general tool output (issue #983):
    the service's own capture is the current state of those hunks, and a planned case narrows the
    lower-ranked excerpts before the change.
    """

    return (
        max(1, selection.max_excerpts // 2),
        max(selection.max_total_excerpt_bytes // 2, first_part_bytes),
    )


def _check_time_change_part_limit(selection: ReviewSelectionPolicy) -> int:
    """The largest check-time change part, marker included (issue #983).

    A part is an excerpt, so it takes the recipe's per-excerpt bound (16 KiB under the Expanded
    preset) like every other excerpt, not the 4 KiB bound of a structural prose item. Fewer,
    larger parts also spend less of the case on per-item rows. A part never exceeds the recipe's
    whole excerpt budget, so one part always fits it.
    """

    return min(
        selection.max_excerpt_bytes,
        selection.max_total_excerpt_bytes,
        MAX_SEMANTIC_ITEM_BYTES,
    )


def _check_time_change_chunks(text: bytes, part_limit: int) -> tuple[bytes, ...]:
    """The raw byte slices of ``text`` each part carries, in order; they concatenate to ``text``."""

    marker_room = len(_CHECK_TIME_CHANGE_MARKER.format(index=999, count=999).encode("ascii"))
    return _line_chunks(text, part_limit - marker_room)


def _line_chunks(text: bytes, chunk_limit: int) -> tuple[bytes, ...]:
    """``text`` in slices of at most ``chunk_limit`` bytes, cut on line ends where possible."""

    if chunk_limit < _CHECK_TIME_CHANGE_MIN_CHUNK:
        return ()
    chunks: list[bytes] = []
    rest = text
    while rest:
        if len(rest) <= chunk_limit:
            chunks.append(rest)
            break
        cut = _check_time_change_cut(rest, chunk_limit)
        chunks.append(rest[:cut])
        rest = rest[cut:]
    return tuple(chunks)


# tb4n5 (#1047 follow-up): the current section of a file a requested edit changed, served from
# the frozen change for an in-check ``current_diff_for_path`` request. Its own item ids, never
# the ``change-check-time-NNN`` run the shown-file record counts.
CHECK_TIME_SECTION_ITEM_PREFIX: Final = "change-section-"
_CHECK_TIME_SECTION_MARKER: Final = (
    "[FinishUP check-time change, the current state of a file a requested edit changed, "
    "section part {index} of {count}]\n"
)


def _check_time_change_sections(
    capture: CheckChangeCapture | None,
) -> dict[str, list[tuple[int, int, int]]]:
    """Each changed path's ``(start, end, ordinal)`` sections in the stored change (tb4n5)."""

    if capture is None:
        return {}
    by_path: dict[str, list[tuple[int, int, int]]] = {}
    for ordinal, (start, end, paths) in enumerate(check_change_sections(capture), start=1):
        for path in sorted(paths):
            by_path.setdefault(path, []).append((start, end, ordinal))
    return by_path


def current_section_parts(
    capture: CheckChangeCapture | None,
    edit_paths: Mapping[str, frozenset[str]] | None,
    workspace_root: str | None,
) -> Mapping[str, frozenset[str]]:
    """Each captured edit's ref mapped to its paths' sections in the change, as span keys.

    What a ``current_diff_for_path`` follow-up for that edit could serve from the frozen change
    (tb4n5), so the planner asks only while some of those bytes no packet carried. ``edit_paths``
    is ``captured_edit_paths``; paths are matched as the follow-up serves them. In process only.
    """

    if capture is None or not edit_paths:
        return {}
    sections = _check_time_change_sections(capture)
    total = len(capture.text)
    mapped: dict[str, frozenset[str]] = {}
    for ref, paths in edit_paths.items():
        keys = frozenset(
            excerpt_span_key(_CHECK_TIME_CHANGE_SOURCE_REF, start, end, total)
            for path in _relative_edit_paths(tuple(sorted(paths)), workspace_root)
            for start, end, _ordinal in sections.get(path, ())
        )
        if keys:
            mapped[ref] = keys
    return mapped


def _span_keys(ref: str, kept: tuple[tuple[int, int], ...], encoded: bytes) -> tuple[str, ...]:
    """The ``excerpt_span_key`` of each interval of ``encoded`` one excerpt part holds."""

    return tuple(excerpt_span_key(ref, low, high, len(encoded)) for low, high in kept if low < high)


def _parts_by_item(pairs: Iterable[tuple[str, str]]) -> dict[str, tuple[str, ...]]:
    """Each excerpt item's span keys, from ``(item_id, key)`` pairs (one per interval)."""

    placed: dict[str, list[str]] = {}
    for item_id, key in pairs:
        placed.setdefault(item_id, []).append(key)
    return {item_id: tuple(keys) for item_id, keys in placed.items()}


def _relative_edit_paths(paths: tuple[str, ...] | None, workspace_root: str | None) -> list[str]:
    """A captured edit's paths as the change names them (repository-relative), in order."""

    relative: list[str] = []
    root = None if workspace_root is None else workspace_root.rstrip("/") + "/"
    for path in paths or ():
        if root is not None and path.startswith(root):
            path = path[len(root) :]
        while path.startswith("./"):
            path = path[2:]
        if path and not path.startswith("/") and path not in relative:
            relative.append(path)
    return relative


def _current_section_candidate(
    text: bytes,
    start: int,
    end: int,
    ordinal: int,
    linked: tuple[str, ...],
    part_limit: int,
) -> _ExcerptCandidate:
    """One stored-change section as an excerpt candidate answering a follow-up (tb4n5).

    Cut from the frozen, capture-time redacted change; no workspace is read. Its parts take the
    recipe's per-excerpt bound like the change's own parts, each placed in the change text so a
    section an earlier packet carried is never counted as added again.
    """

    marker_room = len(_CHECK_TIME_SECTION_MARKER.format(index=999, count=999).encode("ascii"))
    chunks = _line_chunks(text[start:end], part_limit - marker_room)
    parts: list[str] = []
    keys: list[tuple[str, ...]] = []
    offset = start
    for index, chunk in enumerate(chunks):
        parts.append(
            _CHECK_TIME_SECTION_MARKER.format(index=index + 1, count=len(chunks))
            + chunk.decode("utf-8", errors="replace")
        )
        keys.append(
            (
                excerpt_span_key(
                    _CHECK_TIME_CHANGE_SOURCE_REF, offset, offset + len(chunk), len(text)
                ),
            )
        )
        offset += len(chunk)
    return _ExcerptCandidate(
        source_ref=_CHECK_TIME_CHANGE_SOURCE_REF,
        item_base=f"{CHECK_TIME_SECTION_ITEM_PREFIX}{ordinal:03d}",
        source_kind="diff",
        # The service read this from the repository itself, like the change's own parts.
        category=DataCategory.REPOSITORY_EXCERPT,
        parts=tuple(parts),
        clipped=False,
        linked=linked,
        occurred_order=0,
        content_visibility="available",
        digest_provenance=None,
        identity_refs=frozenset(linked),
        part_keys=tuple(keys),
    )


def _check_time_change_cut(rest: bytes, chunk_limit: int) -> int:
    """Where a slice of at most ``chunk_limit`` bytes of ``rest`` ends, preferring a line end."""

    window = rest[:chunk_limit]
    cut = window.rfind(b"\n") + 1
    if cut < chunk_limit // 2:
        # One very long line: cut on a UTF-8 boundary instead of a line boundary.
        cut = len(window.decode("utf-8", errors="ignore").encode("utf-8"))
    return cut


def _check_time_change_label_body(part: str) -> tuple[str, str]:
    """Leading FinishUP label lines of one part, and the change body after them."""

    labels: list[str] = []
    rest = part
    while rest.startswith("[FinishUP"):
        line, separator, rest = rest.partition("\n")
        if not separator:
            break
        labels.append(line)
    return "\n".join(labels), rest


def _check_time_change_cut_part(
    part: str, index: int, count: int, room: int
) -> tuple[str, bool] | None:
    """Part ``index`` (one-based) cut to ``room`` bytes with the cut marker, or ``None`` (#983).

    The marker line is replaced and the change bytes are cut on a line end where one lies in the
    second half of the room, so the part still starts exactly where the uncut part starts and the
    shown-file record counts exactly the bytes it carries. A fixed decisive-section note on the
    first part is kept. The flag says the part was cut.
    """

    labels, body = _check_time_change_label_body(part)
    raw = body.encode("utf-8")
    note = "".join(line + "\n" for line in labels.split("\n")[1:] if line)
    cut_marker = _CHECK_TIME_CHANGE_CUT_MARKER.format(index=index, count=count)
    prefix = cut_marker + note
    chunk_limit = room - len(prefix.encode("utf-8"))
    if chunk_limit < _CHECK_TIME_CHANGE_MIN_CHUNK:
        return None
    if len(raw) <= chunk_limit:
        return part, False
    # A cut also narrows the interval advertised by the synthetic hunk header.
    # Recompute room after updating decimal offsets; no header may claim an unseen tail.
    interval = re.search(
        r"selected original bytes (\d+):(\d+); skipped file intervals (\d+):\d+ and \d+:(\d+)", note
    )
    for _ in range(4):
        cut = _check_time_change_cut(raw, chunk_limit)
        if interval is not None:
            low = int(interval[1])
            high = low + cut
            updated = (
                note[: interval.start()]
                + f"selected original bytes {low}:{high}; skipped file intervals {interval[3]}:{low} and {high}:{interval[4]}"
                + note[interval.end() :]
            )
            prefix = cut_marker + updated
        next_limit = room - len(prefix.encode("utf-8"))
        if cut <= next_limit:
            return prefix + raw[:cut].decode("utf-8"), True
        chunk_limit = next_limit
    return None


def _check_time_change_part_chunk_bytes(content: bytes) -> int:
    """The change bytes one part item carries, after every leading FinishUP label line.

    A part is one marker line plus the change bytes. A change that does not fit may add one
    fixed label on its first part (the decisive-section note). Agent text cannot forge that
    prefix: captured lines that look like a label are neutralised before they are stored.
    """

    rest = content
    while rest.startswith(b"[FinishUP"):
        newline = rest.find(b"\n")
        if newline < 0:
            return 0
        rest = rest[newline + 1 :]
    return len(rest)


_CHECK_TIME_CHANGE_FILE_START: Final = re.compile(rb"^diff --git ", re.MULTILINE)
_CHECK_TIME_CHANGE_BINARY: Final = re.compile(rb"^Binary files ", re.MULTILINE)
_CHECK_TIME_CHANGE_DELETED: Final = re.compile(rb"^deleted file mode ", re.MULTILINE)
# Issue #1079 item 2c. Fixed text, no path: when the change does not fit, file sections that
# change a decision are admitted before boilerplate. The note rides the first part only.
_DECISIVE_PREFERENCE_NOTE: Final = (
    "[FinishUP: decision-changing sections are shown ahead of boilerplate; "
    "sections that do not fit are not shown]\n"
)
_DECISION_LINE: Final = re.compile(
    rb"^(?:if|elif|else|return|raise|assert|throw|catch|except|unless|switch|match|case)\b"
    rb"|\bif\s*\("
    rb"|\belse\s*:"
)
_BOILERPLATE_LINE: Final = re.compile(
    rb"^(?:import|from|using|require|include|use)\b"
    rb"|^(?:#|//|/\*|\*|--|<!--)"
)
# The markers capture-time redaction leaves in the stored change: a concrete credential shape
# reads ``[REDACTED]``, a value that only looks like one the self-describing placeholder (tb4n5).
# Both are withheld spans; every count and view below treats them alike. A change stored before
# the placeholder was used at capture holds ``[REDACTED]`` only, so its record is unchanged.
_REDACTION_MARKERS: Final = (b"[REDACTED]", EGRESS_CREDENTIAL_PLACEHOLDER)
_CHECK_TIME_CHANGE_HUNK: Final = re.compile(rb"^@@ [^\n]*", re.MULTILINE)
# Frozen legacy identifier (ADR-048): domain separator inside stored digests.
_VIEW_DOMAIN: Final = b"yoetz/check-change-view/v1\x00"


def _file_section_bounds(text: bytes) -> tuple[tuple[int, int], ...]:
    """``(start, end)`` of each ``diff --git`` section, in file order."""

    starts = [match.start() for match in _CHECK_TIME_CHANGE_FILE_START.finditer(text)]
    return tuple(
        (start, starts[index + 1] if index + 1 < len(starts) else len(text))
        for index, start in enumerate(starts)
    )


def _changed_code_body(line: bytes) -> bytes | None:
    """The code of one added or removed diff line, without the ``+``/``-`` prefix."""

    if line.startswith((b"+++", b"---")) or not line.startswith((b"+", b"-")):
        return None
    return line[1:].strip()


def _pure_license_notice(body: bytes) -> bool:
    """A comment or header line that is a license or copyright notice, not code.

    ``(c)`` and ``(C)`` are the copyright mark. Any other parenthesis or an assignment is code
    that happens to name a license.
    """

    if _BOILERPLATE_LINE.match(body) is not None:
        return True
    if b"=" in body:
        return False
    notice = re.sub(rb"\([cC]\)", b"", body)
    if b"(" in notice or b")" in notice:
        return False
    return re.fullmatch(rb"[A-Za-z0-9 \t.,:;/_*+-]*", notice) is not None


def _boilerplate_body(body: bytes) -> bool:
    """A changed line that is blank, a comment, an import, or a license notice.

    A line that matches ``_DECISION_LINE`` is a decision even when it names a license. Only a
    license or copyright comment or header is a notice; other code that mentions one is not.
    """

    if not body:
        return True
    if _DECISION_LINE.search(body) is not None:
        return False
    lowered = body.lower()
    if (
        b"copyright" in lowered
        or b"license" in lowered
        or b"all rights reserved" in lowered
        or b"spdx-" in lowered
    ) and _pure_license_notice(body):
        return True
    return _BOILERPLATE_LINE.match(body) is not None


def _section_rank(section: bytes) -> int:
    """0 when the section changes a decision, 1 for other code, 2 for boilerplate only.

    A decision is a changed line that starts with a branch or result keyword (``if``,
    ``return``, ``raise``, and the same shape in other languages), or an ``if (`` / ``else:``
    form. It counts even when the line names a license. The rest of that section is the rule
    the branch implements, so the whole section is kept from its start. Comments, imports and
    license or copyright comment and header lines do not count.
    """

    rank = 2
    for line in section.splitlines():
        body = _changed_code_body(line)
        if body is None or _boilerplate_body(body):
            continue
        if _DECISION_LINE.search(body) is not None:
            return 0
        rank = 1
    return rank


def _decisive_section_ranges(text: bytes) -> tuple[tuple[int, int], ...]:
    """File sections a tight packet should admit, decision first, preamble last."""

    sections = _file_section_bounds(text)
    ranked = sorted(
        (
            (_section_rank(text[start:end]), order, start, end)
            for order, (start, end) in enumerate(sections)
        ),
        key=lambda item: (item[0], item[1]),
    )
    ranges = [(start, end) for _rank, _order, start, end in ranked]
    if sections and sections[0][0] > 0:
        ranges.append((0, sections[0][0]))
    return tuple(ranges)


def _decisive_intervals(text: bytes) -> tuple[tuple[int, int], ...]:
    """Rank bounded line intervals inside hunks, preserving original byte coordinates.

    Each decision gets three lines of context and its following rule. Splitting a huge hunk
    keeps imports, comments and generated prefixes from consuming a tight packet. Unselected
    intervals remain in the offer after the decisive intervals, with no duplicated bytes.
    """

    preferred: list[tuple[int, int]] = []
    for start, end in _file_section_bounds(text):
        first_decision = next(
            (
                match.start() + start
                for match in re.finditer(rb"^[+-](.*)$", text[start:end], re.MULTILINE)
                if (body := _changed_code_body(match.group())) is not None
                and _DECISION_LINE.search(body) is not None
            ),
            None,
        )
        if first_decision is not None and first_decision - start <= 512:
            preferred.append((start, end))
            continue
        hunks = list(_CHECK_TIME_CHANGE_HUNK.finditer(text, start, end))
        for index, hunk in enumerate(hunks):
            body_start = text.find(b"\n", hunk.start(), end) + 1
            body_end = hunks[index + 1].start() if index + 1 < len(hunks) else end
            if body_start <= hunk.start():
                continue
            lines = text[body_start:body_end].splitlines(keepends=True)
            offsets = [body_start]
            for line in lines:
                offsets.append(offsets[-1] + len(line))
            for line_index, line in enumerate(lines):
                body = _changed_code_body(line)
                if body is None or _DECISION_LINE.search(body) is None:
                    continue
                low, high = max(0, line_index - 3), min(len(lines), line_index + 5)
                interval = (offsets[low], offsets[high])
                if preferred and preferred[-1][1] >= interval[0] and preferred[-1][0] >= start:
                    preferred[-1] = (preferred[-1][0], max(preferred[-1][1], interval[1]))
                else:
                    preferred.append(interval)
    if not preferred:
        return _decisive_section_ranges(text)
    remainder: list[tuple[int, int]] = []
    for low, high in _decisive_section_ranges(text):
        cursor = low
        for start, end in preferred:
            if end <= low or start >= high:
                continue
            if cursor < start:
                remainder.append((cursor, start))
            cursor = max(cursor, end)
        if cursor < high:
            remainder.append((cursor, high))
    return (*preferred, *remainder)


def _interval_label(text: bytes, start: int, end: int) -> str:
    """Self-describing context without pretending synthetic headers are captured bytes."""

    section = next(
        ((low, high) for low, high in _file_section_bounds(text) if low <= start < high), None
    )
    if section is None or start == section[0]:
        return ""
    low, high = section
    file_line = text[low : text.find(b"\n", low, high)].decode("utf-8")
    hunk = next(reversed(list(_CHECK_TIME_CHANGE_HUNK.finditer(text, low, start + 1))), None)
    hunk_line = "" if hunk is None else hunk.group().decode("utf-8")
    return (
        f"[FinishUP file: {file_line}]\n"
        f"[FinishUP hunk: {hunk_line}; selected original bytes {start}:{end}; "
        f"skipped file intervals {low}:{start} and {end}:{high} in this excerpt]\n"
    )


def _prefer_decisive_sections(
    text: bytes, linear_parts: Sequence[str], selection: ReviewSelectionPolicy
) -> bool:
    """Whether admitting the linear prefix would drop a decision behind boilerplate.

    A change that fits is left byte-identical. Otherwise decisions can move ahead of
    boilerplate within one file as well as across files.
    """

    sections = _file_section_bounds(text)
    if not sections or not linear_parts:
        return False
    intervals = _decisive_intervals(text)
    within_file = (
        any(low < intervals[0][0] < high for low, high in sections) if intervals else False
    )
    cross_file = len({_section_rank(text[start:end]) for start, end in sections}) > 1
    if not within_file and not cross_file:
        return False
    part_bytes = sum(len(part.encode("utf-8")) for part in linear_parts)
    return (
        len(linear_parts) > selection.max_excerpts or part_bytes > selection.max_total_excerpt_bytes
    )


def _chunks_with_first_limit(blob: bytes, first_limit: int, later_limit: int) -> tuple[bytes, ...]:
    """``blob`` in line-bounded chunks; only the first chunk uses ``first_limit``."""

    if not blob or first_limit < _CHECK_TIME_CHANGE_MIN_CHUNK:
        return _line_chunks(blob, later_limit)
    if len(blob) <= first_limit:
        return (blob,)
    cut = _check_time_change_cut(blob, first_limit)
    head = blob[:cut]
    return (head, *_line_chunks(blob[cut:], later_limit))


def _check_time_change_offer(
    text: bytes, selection: ReviewSelectionPolicy
) -> tuple[tuple[str, ...], tuple[int, ...]]:
    """Change parts and the original offset of each part's first change byte.

    The linear offer is the historical prefix. When the change does not fit and its files are
    not all the same kind, parts are rebuilt so a section that changes a decision precedes
    boilerplate. Offsets are into ``text``, never into the reordered part stream, so the
    shown-file record names the files that were actually carried.
    """

    part_limit = _check_time_change_part_limit(selection)
    chunks = _check_time_change_chunks(text, part_limit)
    if not chunks:
        return (), ()
    count = len(chunks)
    linear_parts = tuple(
        _CHECK_TIME_CHANGE_MARKER.format(index=index + 1, count=count) + chunk.decode("utf-8")
        for index, chunk in enumerate(chunks)
    )
    if not _prefer_decisive_sections(text, linear_parts, selection):
        offsets: list[int] = []
        cursor = 0
        for chunk in chunks:
            offsets.append(cursor)
            cursor += len(chunk)
        return linear_parts, tuple(offsets)

    marker_room = len(_CHECK_TIME_CHANGE_MARKER.format(index=999, count=999).encode("ascii"))
    body_limit = part_limit - marker_room
    note = _DECISIVE_PREFERENCE_NOTE
    note_room = len(note.encode("ascii"))
    use_note = body_limit - note_room >= _CHECK_TIME_CHANGE_MIN_CHUNK
    first_limit = body_limit - note_room if use_note else body_limit
    pieces: list[tuple[int, bytes]] = []
    for index, (start, end) in enumerate(_decisive_intervals(text)):
        blob = text[start:end]
        # Small file sections keep their original headers and historical representation.
        if start != 0 and _interval_label(text, start, end):
            label = _interval_label(text, start, end)
        else:
            label = ""
        room = body_limit - len(label.encode("utf-8"))
        ranged = (
            _chunks_with_first_limit(blob, first_limit - len(label.encode("utf-8")), room)
            if index == 0 and use_note
            else _line_chunks(blob, room)
        )
        offset = start
        for chunk in ranged:
            pieces.append((offset, chunk))
            offset += len(chunk)
    if not pieces:
        return (), ()
    total = len(pieces)
    parts: list[str] = []
    for index, (_offset, chunk) in enumerate(pieces):
        marker = _CHECK_TIME_CHANGE_MARKER.format(index=index + 1, count=total)
        prefix = (
            marker
            + (note if index == 0 and use_note else "")
            + _interval_label(text, _offset, _offset + len(chunk))
        )
        parts.append(prefix + chunk.decode("utf-8"))
    return tuple(parts), tuple(offset for offset, _chunk in pieces)


def _redaction_marker_offsets(text: bytes, start: int, visible_end: int, end: int) -> list[int]:
    """Absolute offsets of every redaction marker of ``text[start:end]`` the view shows any of.

    A marker the packet edge cut still counts: part of a redacted span was shown.
    """

    offsets: set[int] = set()
    for marker in _REDACTION_MARKERS:
        limit = min(end, visible_end + len(marker) - 1)
        position = text.find(marker, start, limit)
        while position >= 0:
            offsets.add(position)
            position = text.find(marker, position + 1, limit)
    return sorted(offsets)


def _check_time_change_view(
    text: bytes, start: int, visible_end: int, markers: Sequence[int], section_admitted: bool
) -> bytes:
    """Length-prefixed structure of one file's shown view: where markers and hunks lie."""

    parts: list[bytes] = [
        _VIEW_DOMAIN,
        (visible_end - start).to_bytes(4, "big"),
        b"\x01" if section_admitted else b"\x00",
    ]
    parts.append(len(markers).to_bytes(4, "big"))
    parts.extend((offset - start).to_bytes(4, "big") for offset in markers)
    hunks = [
        (match.start() - start, text[match.start() : min(match.end(), visible_end)])
        for match in _CHECK_TIME_CHANGE_HUNK.finditer(text, start, visible_end)
    ]
    parts.append(len(hunks).to_bytes(4, "big"))
    for offset, header in hunks:
        parts.extend((offset.to_bytes(4, "big"), len(header).to_bytes(4, "big"), header))
    return b"".join(parts)


class CheckTimeChangeShownFile(NamedTuple):
    """One changed file whose diff reached a review packet (ADR-031); counts, never content.

    ``view`` is the canonical structure of what reached the packet, for a keyed commitment only
    and never stored: the shown length, whether the whole section was admitted, the offset of
    every redaction marker, and the offset and header line of every hunk shown (R945-02).
    """

    identity: bytes
    whole: bool
    shown_bytes: int
    redactions: int
    section_admitted: bool
    clean_bytes: int
    view: bytes


def check_time_change_shown_files(
    capture: CheckChangeCapture,
    shown_bytes: int,
    served: Sequence[tuple[int, int]] = (),
) -> tuple[CheckTimeChangeShownFile, ...]:
    """Each changed file whose diff reached the packet, and how much of it (ADR-031).

    A file is its ``diff --git`` section of the stored change. Its identity is that section's
    first line plus its change kind (a binary or a deleted file), so a file whose kind changed
    between two checks never matches itself. It was shown when any of its bytes lie in the
    leading ``shown_bytes`` the packet carried, and fully shown when the whole section did and it
    holds no redaction marker. Each also carries the section bytes that reached the packet
    (markers included), the redaction markers among them (``[REDACTED]`` and the
    possible-credential placeholder alike), whether the whole section reached it, and where the
    first shown marker starts (the shown length without one). Files the change lists
    only in its header (not shown) are not returned.

    ``shown_bytes`` is the length of the change's leading bytes the packet carried
    (``check_time_change_bytes_carried``). Counting bytes rather than parts keeps the record exact
    when a narrowed case splits its parts smaller or cuts its first part to the room left (issue
    #983). The answer is a pure function of the stored object and that count, so a recovered job
    derives the same files.

    ``served`` are the byte intervals of the change that current-file sections an in-check
    follow-up served carried (``check_time_change_sections_carried``, tb4n5): a file they reach is
    shown like one the leading bytes reach. See ``check_time_change_shown_record`` for a file
    whose shown bytes are not one run from its section's start.
    """

    files, _representable = check_time_change_shown_record(capture, shown_bytes, served)
    return files


def check_time_change_shown_record(
    capture: CheckChangeCapture,
    shown_bytes: int,
    served: Sequence[tuple[int, int]] = (),
) -> tuple[tuple[CheckTimeChangeShownFile, ...], bool]:
    """``check_time_change_shown_files`` and whether every shown file could be recorded truly.

    Leading views retain their original representation. Disjoint or interior views commit to
    every original interval in a separate domain and never claim whole-file coverage. Their
    clean-prefix count is zero, so they cannot stand in for a longer leading view.
    """

    if (
        type(capture) is not CheckChangeCapture
        or type(shown_bytes) is not int
        or not 0 <= shown_bytes <= len(capture.text)
        or any(
            type(low) is not int
            or type(high) is not int
            or not 0 <= low < high <= len(capture.text)
            for low, high in served
        )
    ):
        raise ValueError("semantic_case_check_change_invalid")
    text = capture.text
    starts = [match.start() for match in _CHECK_TIME_CHANGE_FILE_START.finditer(text)]
    files: list[CheckTimeChangeShownFile] = []
    representable = True
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        reached = sorted(
            (max(low, start), min(high, end))
            for low, high in ((0, shown_bytes), *served)
            if low < end and high > start and max(low, start) < min(high, end)
        )
        if not reached:
            continue
        merged: list[tuple[int, int]] = []
        for low, high in reached:
            if merged and low <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], high))
            else:
                merged.append((low, high))
        line_end = text.find(b"\n", start, end)
        identity = text[start : end if line_end < 0 else line_end]
        section = text[start:end]
        if _CHECK_TIME_CHANGE_BINARY.search(section) is not None:
            identity += b"\x00binary"
        if _CHECK_TIME_CHANGE_DELETED.search(section) is not None:
            identity += b"\x00deleted"
        if len(merged) != 1 or merged[0][0] != start:
            markers = [
                max(low, offset)
                for low, high in merged
                for offset in _redaction_marker_offsets(text, start, high, end)
                if offset >= low
                or any(
                    text.startswith(marker, offset) and offset + len(marker) > low
                    for marker in _REDACTION_MARKERS
                )
            ]
            view = b"yoetz/check-change-interval-view/v1\x00" + b"".join(
                (low - start).to_bytes(4, "big")
                + (high - start).to_bytes(4, "big")
                + len(part).to_bytes(4, "big")
                + part
                for low, high in merged
                for part in (
                    _check_time_change_view(
                        text, low, high, [m for m in markers if low <= m < high], False
                    )
                    + _interval_hunk_context(text, start, low, end),
                )
            )
            files.append(
                CheckTimeChangeShownFile(
                    identity=identity,
                    whole=False,
                    shown_bytes=sum(high - low for low, high in merged),
                    redactions=len(set(markers)),
                    section_admitted=False,
                    clean_bytes=0,
                    view=view,
                )
            )
            continue
        run_end = merged[0][1]
        visible_end = run_end
        markers = _redaction_marker_offsets(text, start, visible_end, end)
        section_admitted = visible_end >= end
        files.append(
            CheckTimeChangeShownFile(
                identity=identity,
                whole=section_admitted
                and not any(marker in section for marker in _REDACTION_MARKERS),
                shown_bytes=visible_end - start,
                redactions=len(markers),
                section_admitted=section_admitted,
                clean_bytes=visible_end - start if not markers else markers[0] - start,
                view=_check_time_change_view(text, start, visible_end, markers, section_admitted),
            )
        )
    return tuple(files), representable


def _interval_hunk_context(text: bytes, start: int, low: int, end: int) -> bytes:
    """Bind the original hunk header repeated as context outside an interior byte interval."""

    hunk = next(
        (
            match
            for match in reversed(list(_CHECK_TIME_CHANGE_HUNK.finditer(text, start, end)))
            if match.start() <= low
        ),
        None,
    )
    if hunk is None:
        return b"\x00"
    header = hunk.group()
    return (
        b"\x01"
        + (hunk.start() - start).to_bytes(4, "big")
        + len(header).to_bytes(4, "big")
        + header
    )


def _check_time_change_links(
    projection: ProjectionState, allowed: frozenset[str]
) -> tuple[str, ...]:
    """The case subjects the change is the work product of: its claims, then its obligations."""

    refs = {
        str(claim_id)
        for claim_id, record in effective_claim_items(projection)
        if record.payload is not None and not record.redacted
    }
    refs.update(
        str(obligation_id)
        for obligation_id, record in projection.obligations.items()
        if record.payload is not None and not record.redacted
    )
    linked = tuple(sorted(refs & allowed, key=str.encode))[:MAX_SEMANTIC_ITEM_SUBJECT_REFS]
    if linked or not projection.plans:
        return linked
    plan_ref = str(projection.plans[max(projection.plans)].source_event_id)
    return (plan_ref,) if plan_ref in allowed else ()


_EVIDENCE_EXCERPT_KIND: Final[Mapping[EvidenceKind, _ExcerptKind]] = {
    EvidenceKind.ARTIFACT: "evidence",
    EvidenceKind.COMMAND_OUTPUT: "command",
    EvidenceKind.TEST_RESULT: "test",
    EvidenceKind.RESEARCH_SOURCE: "repository",
    EvidenceKind.IMPORT_REPORT: "evidence",
    EvidenceKind.OTHER: "evidence",
}
_HISTORY_KIND: Final[Mapping[str, tuple[_SourceKind, DataCategory]]] = {
    "action_recorded": ("action", DataCategory.COMMAND_METADATA),
    "check_recorded": ("finding", DataCategory.BOUNDED_STRUCTURAL_METADATA),
    "claim_recorded": ("claim", DataCategory.CLAIM_TEXT),
    "decision_recorded": ("decision", DataCategory.DECISION_EXCERPT),
    "evidence_recorded": ("evidence", DataCategory.EVIDENCE_EXCERPT),
    "finding_recorded": ("finding", DataCategory.FINDING_SUMMARY),
    "obligation_published": ("obligation", DataCategory.OBLIGATION_TEXT),
    "plan_published": ("task", DataCategory.TASK_DESCRIPTION),
    "plan_revised": ("task", DataCategory.TASK_DESCRIPTION),
    "response_recorded": ("finding", DataCategory.FINDING_SUMMARY),
    "result_recorded": ("result", DataCategory.COMMAND_METADATA),
}


def review_selection_digest(selection: ReviewSelectionPolicy) -> str:
    """Digest the closed review-selection value for case/provenance binding."""

    if type(selection) is not ReviewSelectionPolicy:
        raise TypeError("review_selection_invalid")
    return canonical_digest(
        cast(
            JsonValue,
            {
                "excerpt_kinds": list(selection.excerpt_kinds),
                "include_exact_command_text": selection.include_exact_command_text,
                "include_finding_prose": selection.include_finding_prose,
                "max_assessments": selection.max_assessments,
                "max_change_observations": selection.max_change_observations,
                "max_excerpt_bytes": selection.max_excerpt_bytes,
                "max_excerpts": selection.max_excerpts,
                "max_omissions": selection.max_omissions,
                "max_timeline_items": selection.max_timeline_items,
                "max_total_excerpt_bytes": selection.max_total_excerpt_bytes,
                "relevance": selection.relevance,
                # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
                "schema": "yoetz.review-selection/1",
                "sections": list(selection.sections),
            },
        )
    )


def _utf8(text: str, *, maximum: int = MAX_SEMANTIC_ITEM_BYTES) -> bytes:
    encoded = text.encode("utf-8")
    if not 1 <= len(encoded) <= maximum:
        raise ValueError("semantic_case_content_invalid")
    return encoded


def _elision_marker(elided: int, total: int) -> str:
    return _ELISION_MARKER.format(elided=elided, total=total)


def _head_tail(raw: bytes, limit: int) -> str:
    """Keep the head and the tail of ``raw`` within ``limit`` UTF-8 bytes and mark the cut.

    A test, build or lint run prints its verdict last, so a head-only clip dropped exactly the
    line a reviewer needs (issue #907). The middle goes instead, and the marker says how many
    bytes of how many were elided. A bound too small to hold a marker keeps the head only.
    """

    return _head_tail_kept(raw, limit)[0]


def _head_tail_kept(raw: bytes, limit: int) -> tuple[str, tuple[tuple[int, int], ...]]:
    """``_head_tail`` and the byte intervals of ``raw`` it kept (tb4n5): the head and the tail,
    never the elided middle, so a clipped excerpt never reads as the whole source."""

    total = len(raw)
    if total <= limit:
        return raw.decode("utf-8"), ((0, total),) if total else ()
    available = limit - len(_elision_marker(total, total).encode("utf-8"))
    if available >= 2 * _MIN_HEAD_TAIL_SIDE_BYTES:
        best = ""
        best_kept: tuple[tuple[int, int], ...] = ()
        for _attempt in range(4):
            head_bytes = available // 2
            head = raw[:head_bytes].decode("utf-8", errors="ignore")
            tail = raw[total - (available - head_bytes) :].decode("utf-8", errors="ignore")
            head_size = len(head.encode("utf-8"))
            tail_size = len(tail.encode("utf-8"))
            text = head + _elision_marker(total - head_size - tail_size, total) + tail
            size = len(text.encode("utf-8"))
            if size <= limit and size > len(best.encode("utf-8")):
                best = text
                best_kept = tuple(
                    (low, high)
                    for low, high in ((0, head_size), (total - tail_size, total))
                    if low < high
                )
            if size == limit:
                break
            # The marker's digit count depends on what was elided; settle on the exact fill.
            available += limit - size
        if best:
            return best, best_kept
    head = raw[:limit].decode("utf-8", errors="ignore")
    size = len(head.encode("utf-8"))
    return head, ((0, size),) if size else ()


def _content_item(
    *,
    item_id: str,
    section: _Section,
    category: DataCategory,
    source_kind: _SourceKind,
    source_ref: str,
    linked_subject_refs: tuple[str, ...],
    occurred_order: int,
    text: str,
    over_limit: set[str] | None = None,
    limit: int = MAX_REVIEW_TEXT_BYTES,
    latest_for: Literal["path", "command"] | None = None,
    superseded_by: tuple[str, ...] = (),
) -> SemanticCaseItem:
    # Bound by UTF-8 bytes, not characters — multi-byte prose must not raise.
    limit = min(limit, MAX_SEMANTIC_ITEM_BYTES)
    raw = text.encode("utf-8")
    if len(raw) > limit:
        # Publish-side prose accepts up to MAX_PROSE_CHARS, which is twice what one structural
        # case item can carry. Silent truncation here is what made a 5 KB evidence description
        # publish cleanly and then reach the reviewer as a shortened fragment with nothing saying
        # so (issue #177). The cut keeps both ends and is marked in the text (issue #907).
        raw = _head_tail(raw, limit).encode("utf-8")
        if over_limit is not None:
            over_limit.add(item_id)
    if not raw:
        raise ValueError("semantic_case_content_invalid")
    content = _utf8(raw.decode("utf-8"), maximum=limit)
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    return SemanticCaseItem(
        item_id=item_id,
        section=section,
        category=category,
        source_kind=source_kind,
        source_ref=source_ref,
        linked_subject_refs=linked_subject_refs,
        occurred_order=occurred_order,
        content=content,
        content_bytes=len(content),
        content_digest=digest,
        latest_for=latest_for,
        superseded_by=superseded_by,
    )


def _structural_json(value: Mapping[str, JsonValue]) -> str:
    # canonical_encode emits UTF-8 and does not escape non-ASCII, so these must be decoded as
    # UTF-8. Decoding as ASCII meant a single em dash, curly quote or accented character anywhere
    # in the ledger raised UnicodeDecodeError while building the case — surfacing as
    # coordinator_failure with no AI-powered review at all. Agents write such characters constantly.
    return canonical_encode(cast(JsonValue, dict(value))).decode("utf-8")


type _BoundedFit = Literal["whole", "clipped", "replaced"]


def _longest_prose_leaf(
    value: JsonValue, path: tuple[str | int, ...] = ()
) -> tuple[tuple[str | int, ...], int]:
    """Return the path and UTF-8 size of the longest string leaf (keys are never candidates)."""

    best: tuple[tuple[str | int, ...], int] = ((), 0)
    if isinstance(value, str):
        return path, len(value.encode("utf-8"))
    if isinstance(value, Mapping):
        for key in sorted(cast(Mapping[str, JsonValue], value), key=str.encode):
            found = _longest_prose_leaf(cast(Mapping[str, JsonValue], value)[key], (*path, key))
            if found[1] > best[1]:
                best = found
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(cast(Sequence[JsonValue], value)):
            found = _longest_prose_leaf(child, (*path, index))
            if found[1] > best[1]:
                best = found
    return best


def _replace_leaf(value: JsonValue, path: tuple[str | int, ...], leaf: str) -> JsonValue:
    if not path:
        return leaf
    head, rest = path[0], path[1:]
    if isinstance(value, Mapping) and type(head) is str:
        source = cast(Mapping[str, JsonValue], value)
        return {
            key: (_replace_leaf(child, rest, leaf) if key == head else child)
            for key, child in source.items()
        }
    if isinstance(value, (list, tuple)) and type(head) is int:
        return [
            _replace_leaf(child, rest, leaf) if index == head else child
            for index, child in enumerate(cast(Sequence[JsonValue], value))
        ]
    raise ValueError("semantic_case_content_invalid")


def _clip_json_prose(value: JsonValue, limit: int) -> JsonValue | None:
    """Shorten the longest prose strings, head and tail kept, until the canonical JSON fits.

    Identifiers, digests and enum tokens are short and never clipped. ``None`` means the payload
    cannot fit even with all of its prose at the minimum clip, so the caller must fall back to
    the digest-only omission marker.
    """

    current = value
    for _attempt in range(64):
        encoded = canonical_encode(current)
        if len(encoded) <= limit:
            return current
        path, size = _longest_prose_leaf(current)
        if size <= _MIN_CLIPPABLE_PROSE_BYTES:
            return None
        leaf: JsonValue = current
        for step in path:
            leaf = (
                cast(Mapping[str, JsonValue], leaf)[step]
                if type(step) is str
                else cast(Sequence[JsonValue], leaf)[cast(int, step)]
            )
        raw = cast(str, leaf).encode("utf-8")
        target = max(_MIN_CLIPPABLE_PROSE_BYTES, size - (len(encoded) - limit))
        clipped = _head_tail(raw, target)
        if len(clipped.encode("utf-8")) >= size:
            clipped = raw[:target].decode("utf-8", errors="ignore")
        current = _replace_leaf(current, path, clipped)
    return None


def _bounded_json(value: Mapping[str, JsonValue]) -> tuple[str, _BoundedFit]:
    encoded = canonical_encode(cast(JsonValue, dict(value)))
    if len(encoded) <= MAX_REVIEW_TEXT_BYTES:
        return encoded.decode("utf-8"), "whole"
    # An oversized plan, obligation, claim or decision keeps its structure and every identifier;
    # only its longest prose fields are clipped, with the cut marked in the text (issue #907).
    # Replacing the whole payload by a digest left the reviewer with nothing to read.
    clipped = _clip_json_prose(cast(JsonValue, dict(value)), MAX_REVIEW_TEXT_BYTES)
    if clipped is not None:
        return canonical_encode(clipped).decode("utf-8"), "clipped"
    # `not_selected` read as a selection-policy choice, indistinguishable from a section the
    # profile declined to carry. The payload was in fact admitted and then dropped for size, and
    # the reviewer needs to know which of the two happened (issue #177).
    marker = {
        "content_digest": canonical_digest(cast(JsonValue, dict(value))),
        "original_bytes": len(encoded),
        "reason": OVER_CASE_ITEM_LIMIT_REASON,
        # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
        "schema": "yoetz.bounded-content-omission/1",
    }
    return _structural_json(marker), "replaced"


def _without_task_statement(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """A plan payload with any revised task statement removed.

    The statement travels only in its own consented section; a plan item or timeline row that
    carried it would both mislabel the user's words as the agent's plan and send them under a
    policy that never approved the ``task_statement`` section (issue #908).
    """

    payload = dict(value)
    payload.pop("task_statement", None)
    return payload


def _task_statement_content(text: str, source: TaskStatementSource) -> tuple[str, bool]:
    """Canonical statement item content within ``MAX_TASK_STATEMENT_ITEM_BYTES``.

    Returns the content and whether an elision was needed. The head and tail are kept because a
    request usually states its goal first and its constraints last; the elided middle is named by
    byte count both in the text and in ``elided_bytes`` so the reviewer never reads a shortened
    request as the whole one.
    """

    raw = text.encode("utf-8")

    def encode(statement: str, elided: int) -> str:
        return _structural_json(
            {
                "elided_bytes": elided,
                "schema": _TASK_STATEMENT_CONTENT_SCHEMA,
                "source": source.value,
                "statement": statement,
                "statement_bytes": len(raw),
            }
        )

    whole = encode(text, 0)
    if len(whole.encode("utf-8")) <= MAX_TASK_STATEMENT_ITEM_BYTES:
        return whole, False
    # Budget in encoded bytes, so escaping (a quote or newline costs two) shortens the kept text
    # rather than the other end of it.
    budget = MAX_TASK_STATEMENT_ITEM_BYTES - len(encode("", 0).encode("utf-8")) - 64
    while budget > 0:
        head = _encoded_prefix(text, budget // 2)
        tail = _encoded_prefix(text[::-1], budget - budget // 2)[::-1]
        elided = len(raw) - len(head.encode("utf-8")) - len(tail.encode("utf-8"))
        content = encode(f"{head}\n[... {elided} bytes elided ...]\n{tail}", elided)
        excess = len(content.encode("utf-8")) - MAX_TASK_STATEMENT_ITEM_BYTES
        if excess <= 0:
            return content, True
        budget -= excess
    raise ValueError("semantic_case_content_invalid")


def _encoded_prefix(text: str, budget: int) -> str:
    """The longest prefix of ``text`` whose canonical JSON string encoding fits ``budget``."""

    used = 0
    for index, character in enumerate(text):
        code = ord(character)
        if character in {'"', "\\"} or character in "\b\t\n\f\r":
            cost = 2
        elif code < 0x20:
            cost = 6
        else:
            cost = len(character.encode("utf-8"))
        if used + cost > budget:
            return text[:index]
        used += cost
    return text


def _task_statement_item(
    text: str,
    source: TaskStatementSource,
    *,
    source_ref: str,
    linked_subject_refs: tuple[str, ...],
    occurred_order: int,
) -> tuple[SemanticCaseItem, bool]:
    content_text, elided = _task_statement_content(text, source)
    content = content_text.encode("utf-8")
    return (
        SemanticCaseItem(
            item_id=TASK_STATEMENT_ITEM_ID,
            section=TASK_STATEMENT_SECTION,
            category=DataCategory.TASK_DESCRIPTION,
            source_kind="task",
            source_ref=source_ref,
            linked_subject_refs=linked_subject_refs,
            occurred_order=occurred_order,
            content=content,
            content_bytes=len(content),
            content_digest="sha256:" + hashlib.sha256(content).hexdigest(),
        ),
        elided,
    )


DECLARED_DELIVERABLES_ITEM_ID: Final = "declared-deliverables"
# Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
_DECLARED_DELIVERABLES_SCHEMA: Final = "yoetz.declared-deliverables/1"
_MAX_DECLARED_DELIVERABLE_ROWS: Final = 32
# The check's closed delivered-set facts the reviewer reads beside the declared deliverables
# (issue #1045). Codes only: which file a fact concerns stays in the local check result.
_DELIVERED_SET_FACTS: Final = frozenset(
    {
        DECLARED_OUTPUT_CONTENT_MOVED_GAP,
        DECLARED_OUTPUT_EMPTIED_GAP,
        DECLARED_OUTPUT_REMOVED_GAP,
        DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP,
        REQUESTED_OUTPUT_ABSENT_FACT,
        REQUESTED_OUTPUT_GIT_IGNORED_GAP,
        REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,
        REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,
        REQUESTED_OUTPUT_UNCHANGED_GAP,
        REQUESTED_OUTPUT_UNVERIFIED_GAP,
    }
)
_CHANGE_STATUS: Final[Mapping[str, str]] = MappingProxyType(
    {"A": "added", "M": "modified", "D": "deleted", "R": "renamed"}
)


def _deliverable_change_status(
    value: str,
    kind: str,
    listed: Mapping[str, str],
    change: CheckChangeCapture | None,
    workspace_root: str | None,
) -> str:
    """Whether the check-time change lists one declared deliverable, in one closed word."""

    if change is None:
        return "unknown"
    if value.startswith("/"):
        if workspace_root is None:
            return "unknown"
        root = posixpath.normpath(workspace_root).rstrip("/")
        path = posixpath.normpath(value)
        if path != root and not path.startswith(root + "/"):
            return "outside_repository"
        relative = path[len(root) + 1 :]
    else:
        relative = posixpath.normpath(value)
    if not relative or relative == ".":
        return "unknown"
    if kind == "directory":
        statuses = {
            status for path, status in listed.items() if path.startswith(relative.rstrip("/") + "/")
        }
        if statuses:
            return "changed"
    elif relative in listed:
        return listed[relative]
    # A header cut for room cannot prove a file unchanged.
    return "unknown" if change.truncated else "not_changed"


def _declared_deliverables_item(
    projection: ProjectionState,
    allowed: frozenset[str],
    change: CheckChangeCapture | None,
    facts: Iterable[str],
    workspace_root: str | None,
    over_limit: set[str],
) -> SemanticCaseItem | None:
    """One compact row set naming the task's declared deliverables (issue #1045).

    The reviewer otherwise has to piece the delivered set together from every obligation's
    requested items, and took an exploratory output for the final one. Each row is a declared
    ``role: output`` file or directory (the ADR-035 delivered set): its obligation, kind, the
    declared value, and whether the check-time change lists it. ``facts`` are the check's closed
    delivered-set codes (``deliverable_references_undeclared_file`` and the rest). The values are
    the agent's own obligation text, so the item is obligation text and leaves only where
    obligations may.
    """

    rows: list[dict[str, JsonValue]] = []
    refs: list[str] = []
    order = 0
    listed: dict[str, str] = {}
    if change is not None:
        for status, path in check_change_header_entries(change):
            if path is not None:
                listed.setdefault(path, _CHANGE_STATUS.get(status, "changed"))
    for obligation, index, kind, value in declared_delivered_items(projection):
        record = projection.obligations.get(obligation)
        ref = str(obligation)
        if record is None or record.redacted or ref not in allowed:
            continue
        if len(rows) >= _MAX_DECLARED_DELIVERABLE_ROWS:
            break
        rows.append(
            {
                "in_check_time_change": _deliverable_change_status(
                    value, kind, listed, change, workspace_root
                ),
                "item_index": index,
                "item_kind": kind,
                "obligation_id": ref,
                "value": value,
            }
        )
        if ref not in refs:
            refs.append(ref)
        order = max(order, record.source_frontier)
    if not rows:
        return None
    present = sorted(set(facts) & _DELIVERED_SET_FACTS, key=str.encode)
    text, fit = _bounded_json(
        {
            "deliverables": cast(JsonValue, rows),
            "facts": cast(JsonValue, present),
            "kind": "declared_deliverables",
            "schema": _DECLARED_DELIVERABLES_SCHEMA,
        }
    )
    if fit != "whole":
        # Clipped like any oversized obligation payload, and named the same way.
        over_limit.add(DECLARED_DELIVERABLES_ITEM_ID)
    return _content_item(
        item_id=DECLARED_DELIVERABLES_ITEM_ID,
        section="obligation",
        category=DataCategory.OBLIGATION_TEXT,
        source_kind="obligation",
        source_ref=refs[0],
        linked_subject_refs=tuple(refs[:MAX_SEMANTIC_ITEM_SUBJECT_REFS]),
        occurred_order=order,
        text=text,
        over_limit=over_limit,
    )


class SemanticCaseCapacityExceeded(ValueError):
    """The case's fixed material alone exceeds ``MAX_SEMANTIC_CASE_BYTES``.

    Excerpts are cut first, so this is raised only when the non-excerpt items (task statement,
    goals, obligations, claims, decisions, timeline and finding prose) cannot fit on their own.
    Callers map it to a pre-dispatch capacity outcome instead of a generic coordinator failure.
    """


class LineageSemanticCapacityExceeded(SemanticCaseCapacityExceeded):
    """Recorded lineage cannot be carried as complete semantic items.

    One child or gap fact is larger than a single item, or the partitioned set would exceed the
    timeline item budget or the complete case byte budget, including retained parent content.
    Callers map this to a pre-dispatch capacity outcome. Partial JSON is never a substitute.
    """


# Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
_LINEAGE_INPUT_SCHEMA: Final = "yoetz.lineage-semantic-input/1"
# Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
_LINEAGE_INPUT_PART_SCHEMA: Final = "yoetz.lineage-semantic-input/2"
# One part per timeline slot. Fan-out admission is also capped at 64 children.
_MAX_LINEAGE_PARTS: Final = MAX_REVIEW_TIMELINE_ITEMS


def _lineage_rows(
    evaluation: LineageEvaluation,
) -> tuple[list[dict[str, JsonValue]], list[dict[str, JsonValue]]]:
    snapshots = {item.child_task_id: item for item in evaluation.snapshots}
    children: list[dict[str, JsonValue]] = []
    for rollup in evaluation.children:
        snapshot = snapshots.get(rollup.child_task_id)
        if snapshot is None:
            # Omitting a child would make the semantic case claim less source than the check
            # evaluated. Fail closed at case construction instead.
            raise ValueError("lineage_semantic_input_invalid")
        children.append(
            {
                "acceptance": snapshot.acceptance.value,
                "blocking_conditions": list(rollup.blockers),
                "child_check_id": snapshot.child_check_id,
                "child_check_subject_frontier": (
                    None
                    if snapshot.child_check_subject_frontier is None
                    else dict(snapshot.child_check_subject_frontier.as_wire())
                ),
                "child_frontier": (
                    None
                    if snapshot.child_frontier is None
                    else dict(snapshot.child_frontier.as_wire())
                ),
                "child_receipt_id": snapshot.child_receipt_id,
                "child_task_id": str(rollup.child_task_id),
                "coverage_gaps": list(snapshot.coverage.known_gaps),
                "finding_ids": [str(value) for value in rollup.finding_ids],
                "freshness": rollup.freshness,
                "lineage_authority_revision": snapshot.lineage_authority_revision,
                "origin": snapshot.origin.value,
                "provenance_restrictions": list(snapshot.provenance_restrictions),
                "read_gap_reasons": list(snapshot.read_gap_reasons),
                "rollup_state": rollup.state.value,
                "session_health": snapshot.session_health.value,
                "work_state": snapshot.work_state.value,
            }
        )
    gaps: list[dict[str, JsonValue]] = []
    for gap in evaluation.gaps:
        gaps.append(
            cast(
                dict[str, JsonValue],
                {
                    "code": gap.code,
                    "child_task_id": None if gap.child_task_id is None else str(gap.child_task_id),
                    "finding_ids": [str(value) for value in gap.finding_ids],
                    "manifest_event_id": (
                        None if gap.manifest_event_id is None else str(gap.manifest_event_id)
                    ),
                },
            )
        )
    return children, gaps


def _lineage_encode(body: Mapping[str, JsonValue]) -> bytes:
    return canonical_encode(cast(JsonValue, dict(body)))


def _lineage_v1_body(
    children: Sequence[Mapping[str, JsonValue]],
    gaps: Sequence[Mapping[str, JsonValue]],
    manifest_digest: str | None,
) -> dict[str, JsonValue]:
    return {
        "children": list(children),
        "gaps": list(gaps),
        "manifest_digest": manifest_digest,
        "schema": _LINEAGE_INPUT_SCHEMA,
    }


def _lineage_v2_body(
    children: Sequence[Mapping[str, JsonValue]],
    gaps: Sequence[Mapping[str, JsonValue]],
    *,
    manifest_digest: str | None,
    part_index: int,
    part_count: int,
    child_count: int,
    gap_count: int,
) -> dict[str, JsonValue]:
    return {
        "child_count": child_count,
        "children": list(children),
        "gap_count": gap_count,
        "gaps": list(gaps),
        "manifest_digest": manifest_digest,
        "part_count": part_count,
        "part_index": part_index,
        "schema": _LINEAGE_INPUT_PART_SCHEMA,
    }


def _lineage_part_bytes(
    children: Sequence[Mapping[str, JsonValue]],
    gaps: Sequence[Mapping[str, JsonValue]],
    *,
    manifest_digest: str | None,
    part_index: int,
    part_count: int,
    child_count: int,
    gap_count: int,
) -> bytes:
    return _lineage_encode(
        _lineage_v2_body(
            children,
            gaps,
            manifest_digest=manifest_digest,
            part_index=part_index,
            part_count=part_count,
            child_count=child_count,
            gap_count=gap_count,
        )
    )


def _lineage_partition(
    children: Sequence[Mapping[str, JsonValue]],
    gaps: Sequence[Mapping[str, JsonValue]],
    manifest_digest: str | None,
) -> tuple[bytes, ...]:
    """Split children and gaps into complete documents that each fit one item.

    Fit is measured against the widest part header (``part_count`` at the timeline cap) so the
    final encoding with the real count cannot grow past the item bound.
    """

    child_count = len(children)
    gap_count = len(gaps)
    child_at = 0
    gap_at = 0
    slices: list[tuple[int, int, int, int]] = []
    while child_at < child_count or gap_at < gap_count:
        if len(slices) >= _MAX_LINEAGE_PARTS:
            raise LineageSemanticCapacityExceeded("lineage_semantic_input_too_large")
        part_index = len(slices)
        child_take = 0
        if child_at < child_count:
            low, high = 1, child_count - child_at
            if (
                len(
                    _lineage_part_bytes(
                        children[child_at : child_at + 1],
                        (),
                        manifest_digest=manifest_digest,
                        part_index=part_index,
                        part_count=_MAX_LINEAGE_PARTS,
                        child_count=child_count,
                        gap_count=gap_count,
                    )
                )
                > MAX_SEMANTIC_ITEM_BYTES
            ):
                raise LineageSemanticCapacityExceeded("lineage_semantic_input_too_large")
            while low < high:
                mid = (low + high + 1) // 2
                encoded = _lineage_part_bytes(
                    children[child_at : child_at + mid],
                    (),
                    manifest_digest=manifest_digest,
                    part_index=part_index,
                    part_count=_MAX_LINEAGE_PARTS,
                    child_count=child_count,
                    gap_count=gap_count,
                )
                if len(encoded) <= MAX_SEMANTIC_ITEM_BYTES:
                    low = mid
                else:
                    high = mid - 1
            child_take = low
        gap_take = 0
        if gap_at < gap_count:
            alone = _lineage_part_bytes(
                children[child_at : child_at + child_take],
                gaps[gap_at : gap_at + 1],
                manifest_digest=manifest_digest,
                part_index=part_index,
                part_count=_MAX_LINEAGE_PARTS,
                child_count=child_count,
                gap_count=gap_count,
            )
            if len(alone) <= MAX_SEMANTIC_ITEM_BYTES:
                low, high = 1, gap_count - gap_at
                while low < high:
                    mid = (low + high + 1) // 2
                    encoded = _lineage_part_bytes(
                        children[child_at : child_at + child_take],
                        gaps[gap_at : gap_at + mid],
                        manifest_digest=manifest_digest,
                        part_index=part_index,
                        part_count=_MAX_LINEAGE_PARTS,
                        child_count=child_count,
                        gap_count=gap_count,
                    )
                    if len(encoded) <= MAX_SEMANTIC_ITEM_BYTES:
                        low = mid
                    else:
                        high = mid - 1
                gap_take = low
            elif child_take == 0:
                raise LineageSemanticCapacityExceeded("lineage_semantic_input_too_large")
        if child_take == 0 and gap_take == 0:
            raise LineageSemanticCapacityExceeded("lineage_semantic_input_too_large")
        slices.append((child_at, child_at + child_take, gap_at, gap_at + gap_take))
        child_at += child_take
        gap_at += gap_take
    part_count = len(slices)
    encoded_parts: list[bytes] = []
    for part_index, (child_start, child_end, gap_start, gap_end) in enumerate(slices):
        encoded = _lineage_part_bytes(
            children[child_start:child_end],
            gaps[gap_start:gap_end],
            manifest_digest=manifest_digest,
            part_index=part_index,
            part_count=part_count,
            child_count=child_count,
            gap_count=gap_count,
        )
        if len(encoded) > MAX_SEMANTIC_ITEM_BYTES:
            raise LineageSemanticCapacityExceeded("lineage_semantic_input_too_large")
        encoded_parts.append(encoded)
    return tuple(encoded_parts)


def _lineage_structural_item(item_id: str, occurred_order: int, encoded: bytes) -> SemanticCaseItem:
    # Structural lineage is not review prose. ``_content_item`` cuts text at the 4 KiB review
    # bound, which would publish a partial JSON document the 16 KiB item check had accepted.
    if not 1 <= len(encoded) <= MAX_SEMANTIC_ITEM_BYTES:
        raise LineageSemanticCapacityExceeded("lineage_semantic_input_too_large")
    digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    return SemanticCaseItem(
        item_id=item_id,
        section="timeline",
        category=DataCategory.BOUNDED_STRUCTURAL_METADATA,
        source_kind="task",
        source_ref="lineage",
        linked_subject_refs=(),
        occurred_order=occurred_order,
        content=encoded,
        content_bytes=len(encoded),
        content_digest=digest,
    )


def _lineage_semantic_items(evaluation: LineageEvaluation) -> tuple[SemanticCaseItem, ...]:
    """Encode recorded lineage as one or more complete structural items.

    A single ``yoetz.lineage-semantic-input/1`` document is used when it fits. Larger legal
    fan-out is split into ``yoetz.lineage-semantic-input/2`` parts that together retain every
    child and gap identity plus the shared manifest digest. Child prose never enters the case.
    """

    children, gaps = _lineage_rows(evaluation)
    single = _lineage_encode(_lineage_v1_body(children, gaps, evaluation.manifest_digest))
    if len(single) <= MAX_SEMANTIC_ITEM_BYTES:
        return (_lineage_structural_item("lineage", 0, single),)
    parts = _lineage_partition(children, gaps, evaluation.manifest_digest)
    if len(parts) == 1:
        # The part header made a one-part split larger than v1, which already did not fit.
        raise LineageSemanticCapacityExceeded("lineage_semantic_input_too_large")
    return tuple(
        _lineage_structural_item(f"lineage-{index:02d}", index, encoded)
        for index, encoded in enumerate(parts)
    )


def _history_json(
    item: FrozenHistoryEvent,
    *,
    include_content: bool,
    include_exact_command_text: bool,
) -> tuple[str, _BoundedFit]:
    body: dict[str, JsonValue] = {
        "content_visibility": item.content_visibility,
        "event_id": item.event_id,
        "ingestion_sequence": item.ingestion_sequence,
        "kind": item.schema_name,
        "occurred_at": item.occurred_at,
        "payload_digest": item.payload_digest,
    }
    if item.accepted_at is None:
        body["occurred_at_consistency"] = "not_available_in_legacy_case"
    else:
        body["accepted_at"] = item.accepted_at
        body["occurred_at_consistency"] = item.occurred_at_consistency
    reduced: dict[str, JsonValue] | None = None
    if item.schema_name == "check_recorded":
        # A check's payload may record undeclared-reference names (#1044): repository-excerpt
        # content shown only to its own author and a ``full_local`` receipt (tb4n5, ADR-035
        # amendment). This row never carries them, whether or not it carries content, and never
        # the ledger digest of a payload that held them: that digest would confirm a guessed name.
        if item.payload is None:
            # Unavailable content: whether it named files is unknown, so no digest is sent.
            body.pop("payload_digest")
            body["payload_reduced"] = "undeclared_reference_names_withheld"
        else:
            reduced = _without_undeclared_reference_names(
                cast(Mapping[str, JsonValue], item.payload)
            )
            if reduced is not None:
                body["payload_digest"] = canonical_digest(cast(JsonValue, reduced))
                body["payload_reduced"] = "undeclared_reference_names_withheld"
    if include_content and item.payload is not None:
        payload = (
            reduced if reduced is not None else dict(cast(Mapping[str, JsonValue], item.payload))
        )
        if item.schema_name == "action_recorded" and not include_exact_command_text:
            payload.pop("command", None)
        if item.schema_name in _PLAN_FAMILIES:
            payload = _without_task_statement(payload)
        body["payload"] = cast(JsonValue, payload)
    return _bounded_json(body)


def _without_undeclared_reference_names(
    payload: Mapping[str, JsonValue],
) -> dict[str, JsonValue] | None:
    """A ``check_recorded`` payload without the undeclared-reference paths, or ``None`` if none.

    tb4n4 #1044 recorded the root-relative paths of files a delivered file names on the check's
    ``deliverable_states``; they are the one path text a check records. The review packet carries
    the history row as bounded structural metadata, so the names are removed and only their count
    is kept (``undeclared_reference_count``).
    """

    # A frozen history payload holds read-only mappings and tuples, not dicts and lists.
    states = payload.get("deliverable_states")
    if (
        not isinstance(states, Sequence)
        or isinstance(states, (str, bytes))
        or not any(
            isinstance(state, Mapping) and "undeclared_references" in state for state in states
        )
    ):
        return None
    reduced_states: list[JsonValue] = []
    for state in cast(Sequence[JsonValue], states):
        if not isinstance(state, Mapping) or "undeclared_references" not in state:
            reduced_states.append(state)
            continue
        fields = cast(Mapping[str, JsonValue], state)
        names = fields["undeclared_references"]
        named = (
            len(cast(Sequence[JsonValue], names))
            if isinstance(names, Sequence) and not isinstance(names, (str, bytes))
            else 0
        )
        recorded = fields.get("undeclared_reference_count")
        count = max(named, recorded if type(recorded) is int else 0)
        reduced = {key: value for key, value in fields.items() if key != "undeclared_references"}
        reduced["undeclared_reference_count"] = count
        reduced_states.append(cast(JsonValue, reduced))
    return {**payload, "deliverable_states": reduced_states}


def _omit(
    subject_ref: str,
    category: DataCategory,
    source_kind: _SourceKind,
    reason: _OmissionReason,
) -> ReviewOmission:
    return ReviewOmission(
        subject_ref=subject_ref,
        category=category,
        source_kind=source_kind,
        reason=reason,
    )


def _omission_subject_refs(source_ref: str, linked: Sequence[str]) -> tuple[str, ...]:
    """Ledger subjects a dropped excerpt may name (issue #1077).

    A check-time change excerpt's own source is the synthetic ``check-time-change`` token.
    ``ReviewOmission`` accepts only ledger subject ids, so a dropped synthetic excerpt is
    disclosed against the valid linked subjects it answers. A recorded source keeps its own ref.
    Subject validation itself is unchanged.
    """

    if source_ref != _CHECK_TIME_CHANGE_SOURCE_REF:
        return (source_ref,)
    seen: list[str] = []
    for ref in linked:
        if type(ref) is str and ref not in seen:
            seen.append(ref)
    return tuple(sorted(seen, key=str.encode))


def _append_omission(
    omissions: list[ReviewOmission],
    source_ref: str,
    linked: Sequence[str],
    category: DataCategory,
    source_kind: _SourceKind,
    reason: _OmissionReason,
) -> None:
    """Record one omission per subject, mapping a synthetic excerpt onto its linked subjects.

    A linked token that is not a ledger subject is skipped. The ``content_unselected`` gap the
    caller already recorded stays the disclosure when no valid subject remains. A recorded
    source still raises if its own ref is not a ledger subject.
    """

    subjects = _omission_subject_refs(source_ref, linked)
    if source_ref != _CHECK_TIME_CHANGE_SOURCE_REF:
        omissions.append(_omit(subjects[0], category, source_kind, reason))
        return
    for subject in subjects:
        try:
            omissions.append(_omit(subject, category, source_kind, reason))
        except ValueError:
            continue


def _fit_excerpts_within_case_bound(
    items: Sequence[SemanticCaseItem],
    targeted: list[TargetedExcerptRef],
    omissions: list[ReviewOmission],
    capture_gaps: set[str],
    *,
    fixed_item_ids: set[str],
) -> int:
    """Drop the lowest-ranked excerpts until the case fits ``MAX_SEMANTIC_CASE_BYTES``.

    The excerpt budget and the case's aggregate item bound are independent. Since the Expanded
    excerpt count rose to the protocol maximum (issue #907 Phase 1b), a full excerpt budget beside
    rich finding prose can cross the aggregate bound, and ``SemanticCase`` would refuse the whole
    case before the channel-ceiling planner could narrow it. Only a case that would otherwise be
    refused is changed, so every constructible case keeps its exact bytes and digest. Each dropped
    excerpt is disclosed as ``not_selected`` with ``content_unselected``, never silently. Returns
    how many excerpts were dropped. Non-excerpt material over the bound on its own is not cut here.
    """

    by_id = {item.item_id: item for item in items}
    case_bytes = sum(by_id[item_id].content_bytes for item_id in fixed_item_ids if item_id in by_id)
    case_bytes += sum(by_id[excerpt.excerpt_item_id].content_bytes for excerpt in targeted)
    if case_bytes <= MAX_SEMANTIC_CASE_BYTES or not targeted:
        return 0
    selected = len(targeted)
    dropped_refs: set[str] = set()
    while targeted and case_bytes > MAX_SEMANTIC_CASE_BYTES:
        excerpt = targeted.pop()
        item = by_id[excerpt.excerpt_item_id]
        case_bytes -= item.content_bytes
        dropped_refs.add(item.source_ref)
        _append_omission(
            omissions,
            item.source_ref,
            item.linked_subject_refs,
            item.category,
            excerpt.source_kind,
            "not_selected",
        )
    capture_gaps.add("content_unselected")
    if any(by_id[excerpt.excerpt_item_id].source_ref in dropped_refs for excerpt in targeted):
        # Later parts of a split excerpt were cut while its earlier parts stay.
        capture_gaps.add("truncated_payload")
    return selected - len(targeted)


def _captured_content_groups(
    projection: object,
    allowed: frozenset[str],
    content: Sequence[CapturedSemanticContent],
    scope: CapturedContentScope | None,
) -> tuple[dict[str, _CapturedGroup], frozenset[str]]:
    """Index service-authenticated content by its case-bound evidence row.

    This is intentionally a pure check. The service has already decrypted and secret-scanned the
    object before constructing ``CapturedSemanticContent``; this function verifies that the bytes
    cannot be attached to another task, phase, profile, or evidence identity and that multipart
    content is complete before it becomes an AI-powered review excerpt.
    """

    # Importing the concrete projection type would make the public builder depend on the adapter
    # implementation. The frozen case owns the mapping and the small attribute checks below keep
    # this seam capability-free.
    evidence = getattr(projection, "evidence", None)
    if not isinstance(evidence, Mapping):
        return {}, frozenset({"content_capture_unavailable"}) if content else frozenset()

    gaps: set[str] = set()
    expected_phases = dict(scope.phase_bindings) if scope is not None else {}
    by_object: dict[str, list[tuple[str, object]]] = {}
    payload_by_ref: dict[str, EvidenceRecordedPayload] = {}
    evidence_map = cast(Mapping[object, object], evidence)
    for raw_ref, record in evidence_map.items():
        ref = str(raw_ref)
        typed_record = cast(EvidenceProjectionRecord, record)
        payload = typed_record.payload
        object_value = getattr(payload, "captured_object_id", None)
        if object_value is not None:
            by_object.setdefault(str(object_value), []).append((ref, record))
        if type(payload) is EvidenceRecordedPayload:
            payload_by_ref[ref] = payload

    parts: dict[
        tuple[str, str, str, str, str, int],
        list[tuple[str, CapturedSemanticContent]],
    ] = {}
    for item in content:
        if scope is None:
            gaps.add("content_capture_unavailable")
            continue
        if (
            item.task_id != scope.task_id
            or item.session_id != scope.session_id
            or item.workspace_commitment != scope.workspace_commitment
        ):
            gaps.add("content_unselected")
            continue
        if item.capture_profile not in scope.authorized_profiles:
            gaps.add("content_unselected")
            continue

        associations = by_object.get(item.object_ref.object_id, ())
        if len(associations) != 1:
            gaps.add("content_unselected")
            continue
        evidence_ref, record = associations[0]
        if evidence_ref not in allowed:
            gaps.add("content_unselected")
            continue
        expected_phase = expected_phases.get(evidence_ref)
        if expected_phase is None or item.phase_identity != expected_phase:
            # The phase identity is only meaningful when the service derived the
            # same identity from the envelope that materialized this evidence row.
            # A valid digest from another phase must remain excluded.
            gaps.add("content_unselected")
            continue
        payload = getattr(record, "payload", None)
        binding = getattr(payload, "digest_binding", None)
        if (
            type(payload) is not EvidenceRecordedPayload
            or payload.evidence_kind is not EvidenceKind.OTHER
            or payload.strength is not EvidenceImmutability.IMMUTABLE_SNAPSHOT
            or payload.captured_object_id != item.object_ref.object_id
            or payload.content_digest != item.manifest.content_digest
            or type(binding) is not EvidenceDigestBinding
            or binding.subject is not EvidenceDigestSubject.BOUNDED_EXCERPT
            or binding.content_availability is not EvidenceContentAvailability.CAPTURED
            or binding.provenance is not EvidenceDigestProvenance.OBSERVATION_CAPTURED
            or binding.byte_count != item.manifest.content_bytes
        ):
            gaps.add("content_capture_unavailable")
            continue
        if (
            getattr(record, "redacted", False)
            or not getattr(record, "object_available", False)
            or getattr(record, "redacted_object_id", None) is not None
        ):
            gaps.add(
                "content_redacted"
                if getattr(record, "redacted", False)
                else "content_capture_unavailable"
            )
            continue

        if item.manifest.redacted:
            gaps.add("content_redacted")
        gaps.update(item.capture_gaps)
        key = (
            item.phase_identity,
            item.capture_profile,
            item.manifest.content_kind.value,
            item.manifest.correlation_identity or "",
            item.manifest.source_commitment or "",
            item.manifest.part_count,
        )
        parts.setdefault(key, []).append((evidence_ref, item))

    groups: dict[str, _CapturedGroup] = {}
    for rows in parts.values():
        rows.sort(key=lambda row: (row[1].manifest.part_index, row[0].encode("ascii")))
        expected_count = rows[0][1].manifest.part_count
        indexes = [item.manifest.part_index for _ref, item in rows]
        if (
            len(rows) != expected_count
            or indexes != list(range(expected_count))
            or len({ref for ref, _item in rows}) != len(rows)
        ):
            gaps.add("content_capture_unavailable")
            continue
        combined = b"".join(item.content for _ref, item in rows)
        if not 1 <= len(combined) <= MAX_CAPTURED_SEMANTIC_CONTENT_BYTES:
            gaps.add("content_capture_unavailable")
            continue
        first_ref, first_item = rows[0]
        source_kind: _ExcerptKind = (
            "evidence"
            if first_item.manifest.content_kind is ObservationContentKind.TOOL_OUTPUT
            else "diff"
        )
        if len(rows) == 1:
            payload = payload_by_ref[first_ref]
            binding = payload.digest_binding
            assert type(binding) is EvidenceDigestBinding
            provenance = ExcerptDigestProvenance(
                evidence_kind=payload.evidence_kind,
                strength=payload.strength,
                content_digest=payload.content_digest or first_item.manifest.content_digest or "",
                digest_subject=binding.subject,
                content_availability=binding.content_availability,
                byte_count=binding.byte_count,
                provenance=binding.provenance,
                approval_commitment=binding.approval_commitment,
                approved_check_result_digest=binding.approved_check_result_digest,
            )
        else:
            # The ledger binds each part independently. The combined excerpt gets a freshly
            # computed digest over exactly those authenticated parts, with the same observation
            # provenance; no caller description is used as a substitute.
            provenance = ExcerptDigestProvenance(
                evidence_kind=EvidenceKind.OTHER,
                strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
                content_digest="sha256:" + hashlib.sha256(combined).hexdigest(),
                digest_subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
                content_availability=EvidenceContentAvailability.CAPTURED,
                byte_count=len(combined),
                provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
            )
        group = _CapturedGroup(
            redacted=any(item.manifest.redacted for _ref, item in rows),
            observed_command=first_item.observed_command
            if all(item.observed_command == first_item.observed_command for _ref, item in rows)
            else None,
            observed_command_identity=first_item.observed_command_identity
            if all(
                item.observed_command_identity == first_item.observed_command_identity
                for _ref, item in rows
            )
            else None,
            evidence_refs=tuple(ref for ref, _item in rows),
            content=combined,
            source_kind=source_kind,
            digest_provenance=provenance,
            capture_gaps=tuple(
                sorted({gap for _ref, item in rows for gap in item.capture_gaps}, key=str.encode)
            ),
        )
        groups[first_ref] = group

    return groups, frozenset(gaps)


def _match_assessments(
    case: DeterministicCase,
    findings: Sequence[Finding],
) -> tuple[tuple[Finding, DeterministicAssessment], ...]:
    assessments, _executions = run_deterministic_policies(
        case,
        CheckScope((), ()),
        _CANONICAL_PACKS,
    )
    by_key: dict[tuple[object, tuple[str, ...]], DeterministicAssessment] = {}
    for assessment in assessments:
        key = (
            assessment.candidate.kind,
            tuple(str(ref) for ref in assessment.candidate.subject_refs),
        )
        by_key[key] = assessment
    matched: list[tuple[Finding, DeterministicAssessment]] = []
    for finding in findings:
        key = (finding.kind, tuple(str(ref) for ref in finding.subject_refs))
        assessment = by_key.get(key)
        if assessment is not None:
            matched.append((finding, assessment))
    return tuple(matched)


# Declared outputs outside the workspace (tb4n2 R7, P1-15): the check-time change never holds
# them, so their captured evidence is reserved instead. Bounded per output and in total.
_MAX_DECLARED_OUTPUT_CAPTURES: Final = 8
_CLAIM_LINKED_CAPTURES_PER_OUTPUT: Final = 2
_DECLARED_OUTPUT_CAPTURES_PER_OUTPUT: Final = 3
# Sorts a reserved declared-output row ahead of every recency key (``-occurred_order``).
_DECLARED_ORDER_OFFSET: Final = 2**62
_DECLARED_OUTPUT_KINDS: Final = frozenset({"file", "directory"})


def _outside_workspace(value: str, workspace_root: str | None) -> str | None:
    """The normalised absolute ``value`` when it lies outside ``workspace_root``; else ``None``.

    Lexical only: nothing is opened or resolved. A relative value is inside by definition, and
    without a known root nothing can be called outside.
    """

    if workspace_root is None or not value.startswith("/") or "\x00" in value:
        return None
    root = posixpath.normpath(workspace_root)
    path = posixpath.normpath(value)
    if path == root or path.startswith(root.rstrip("/") + "/"):
        return None
    return path


def _names_output(reference: str, output: str) -> bool:
    if not reference.startswith("/") or "://" in reference:
        return False
    path = posixpath.normpath(reference.strip())
    return path == output or path.startswith(output.rstrip("/") + "/")


def declared_output_capture_refs(
    projection: ProjectionState, allowed: frozenset[str], workspace_root: str | None
) -> frozenset[str]:
    """The set form of ``declared_output_capture_order``."""

    return frozenset(declared_output_capture_order(projection, allowed, workspace_root))


def declared_output_capture_order(
    projection: ProjectionState, allowed: frozenset[str], workspace_root: str | None
) -> tuple[str, ...]:
    """Evidence that records a declared ``role: output`` item lying outside the workspace.

    tb4n2 R7 (P1-15, cargo-flight-dispatch ``/output/flight_plan.json``): the check-time change
    reads only the repository, so a deliverable the task places elsewhere reached the reviewer
    only if a hook capture of it happened to win general excerpt room. The evidence selected
    here is reserved beside the current diff instead: evidence whose own reference names the
    output, evidence of a result whose action lists the output among its attempted items, and,
    per output, the newest two content-bearing captures an effective claim on the declaring
    obligation cites. At most three rows per output (newest first) and eight in all, taken
    round-robin across outputs so one deliverable's repeats never crowd out another's. This is relevance selection only: every selected row still passes the
    content consent, capture authentication, redaction and never-send checks of any excerpt.
    """

    outputs: list[tuple[str, str]] = []
    for obligation in effective_obligations(projection):
        record = projection.obligations.get(obligation)
        if record is None or record.payload is None or record.redacted:
            continue
        for item in record.payload.requested_items:
            if (
                getattr(item.item_kind, "value", item.item_kind) not in _DECLARED_OUTPUT_KINDS
                or getattr(getattr(item, "role", None), "value", None) != "output"
            ):
                continue
            outside = _outside_workspace(item.value, workspace_root)
            if outside is not None:
                outputs.append((str(obligation), outside))
    if not outputs:
        return ()
    evidence = {
        str(key): row
        for key, row in projection.evidence.items()
        if str(key) in allowed and row.payload is not None and not row.redacted
    }
    results = {
        str(key): row
        for key, row in projection.results.items()
        if row.payload is not None and not row.redacted
    }

    def frontier(ref: str) -> int:
        return evidence[ref].source_frontier

    def result_evidence(result_ref: str) -> set[str]:
        row = results.get(result_ref)
        if row is None or row.payload is None:
            return set()
        return {str(ref) for ref in row.payload.evidence_refs if str(ref) in evidence}

    attempted: dict[str, set[str]] = {}
    for result_ref, row in results.items():
        assert row.payload is not None
        action = projection.actions.get(row.payload.action_id)
        if action is None or action.payload is None or action.redacted:
            continue
        for value in action.payload.attempted_items:
            attempted.setdefault(value, set()).update(result_evidence(result_ref))
    claims = [
        claim.payload
        for _, claim in effective_claim_items(projection)
        if claim.payload is not None and not claim.redacted
    ]

    def newest(refs: Iterable[str]) -> list[str]:
        return sorted(set(refs), key=lambda ref: (-frontier(ref), ref.encode("ascii")))

    per_output: list[list[str]] = []
    for obligation, output in outputs:
        exact = {
            ref
            for ref, row in evidence.items()
            if row.payload is not None
            and row.payload.reference is not None
            and _names_output(row.payload.reference, output)
        }
        for value, refs in attempted.items():
            if _names_output(value, output):
                exact.update(refs)
        cited: set[str] = set()
        for claim in claims:
            if obligation not in {
                *(str(ref) for ref in claim.obligation_refs),
                *(str(ref) for ref in claim.supporting_refs),
            }:
                continue
            for ref in claim.supporting_refs:
                value = str(ref)
                cited.update({value} & evidence.keys())
                cited.update(result_evidence(value))
        captured = [
            ref
            for ref in newest(cited - exact)
            if (payload := evidence[ref].payload) is not None
            and payload.captured_object_id is not None
        ]
        per_output.append(
            (newest(exact) + captured[:_CLAIM_LINKED_CAPTURES_PER_OUTPUT])[
                :_DECLARED_OUTPUT_CAPTURES_PER_OUTPUT
            ]
        )
    # Round-robin over outputs, newest first within each, so many captures of one deliverable
    # never take every reserved row from another (Codex review round 2).
    selected: dict[str, None] = {}
    for depth in range(_DECLARED_OUTPUT_CAPTURES_PER_OUTPUT):
        for refs in per_output:
            if depth < len(refs) and len(selected) < _MAX_DECLARED_OUTPUT_CAPTURES:
                selected.setdefault(refs[depth])
    return tuple(selected)


def repair_evidence_refs(projection: ProjectionState, allowed: frozenset[str]) -> frozenset[str]:
    """Select readable evidence linked by responses to in-scope, unresolved findings.

    A response may link evidence directly or one result with evidence refs. This is relevance
    selection only: it never clears a finding or bypasses capture authentication or privacy.
    """

    evidence = {str(key): row for key, row in projection.evidence.items()}
    results = {str(key): row for key, row in projection.results.items()}
    selected: set[str] = set()
    for finding_id, response in projection.responses.items():
        finding = projection.findings.get(finding_id)
        if (
            str(finding_id) not in allowed
            or finding is None
            or finding.payload is None
            or finding.redacted
            or finding.resolved_by_check_event_id is not None
            or response.payload is None
            or response.redacted
            or str(response.source_event_id) not in allowed
        ):
            continue
        refs: set[str] = set()
        for ref in response.payload.evidence_refs:
            value = str(ref)
            if value not in allowed:
                continue
            if value in evidence:
                refs.add(value)
            result = results.get(value)
            if result is not None and result.payload is not None and not result.redacted:
                refs.update(str(item) for item in result.payload.evidence_refs)
        selected.update(
            ref
            for ref in refs & allowed
            if ref in evidence and evidence[ref].payload is not None and not evidence[ref].redacted
        )
    return frozenset(selected)


# Excerpt ranks, in the reserved-room order issue #907 fixes. The task statement (#908) is a packet
# section of its own, not an excerpt: it takes no excerpt slot, and neither the excerpt byte budget
# nor the prepared-payload planning in ``build_semantic_case`` ever trims a non-excerpt section, so
# its room is held by construction ahead of every excerpt class below.
_RANK_CURRENT_DIFF: Final = 0
_RANK_LATEST_VERIFICATION: Final = 1
_RANK_PRIOR_FINDING_CONTEXT: Final = 2
# An older captured edit of a path that changed again. Captured edits are hunks, not whole files:
# a later hunk elsewhere in the file leaves this one's lines in place, so it is still code under
# review and keeps the #883 rule that a patch is never starved by tool output or file reads.
_RANK_OLDER_EDIT: Final = 3
_RANK_UNRESERVED: Final = 4
_RANK_SUPERSEDED: Final = 5
_OUTSIDE_WORKSPACE_PATH: Final = "<outside-workspace>"
_MAX_EDIT_PATHS: Final = 64
_PATCH_FILE_LINE: Final = re.compile(r"^\*\*\* (?:Update|Add|Delete) File: (.+?)[ \t]*$", re.M)
_PATCH_MOVE_LINE: Final = re.compile(r"^\*\*\* Move to: (.+?)[ \t]*$", re.M)
_GIT_DIFF_LINE: Final = re.compile(r"^diff --git a/(\S+) b/(\S+)[ \t]*$", re.M)
_UNIFIED_HEADER: Final = re.compile(r"^--- \S[^\n]*\n\+\+\+ (?:b/)?(\S+)[ \t]*$", re.M)


@dataclass(frozen=True, slots=True)
class _ExcerptCandidate:
    """One evidence row, command, or failed result that may become one or more excerpt items.

    Each candidate is exactly one recorded source: one evidence row (or one authenticated
    multipart capture), one action's command, or one result's summary. A candidate split into
    parts spends one excerpt slot per part; no excerpt ever joins two sources (issue #907).
    """

    source_ref: str
    item_base: str
    source_kind: _ExcerptKind
    category: DataCategory
    parts: tuple[str, ...]
    clipped: bool
    linked: tuple[str, ...]
    occurred_order: int
    content_visibility: Literal["available", "not_recorded"]
    digest_provenance: ExcerptDigestProvenance | None
    identity_refs: frozenset[str]
    # Changed paths of an applied (or unconfirmed) captured edit; ``None`` for anything else.
    edit_paths: tuple[str, ...] | None = None
    verification_identity: str | None = None
    verification_outcome: ResultOutcome | None = None
    verification_action: str | None = None
    verification_run: str | None = None
    structural_only: bool = False
    # An image or binary file the packet never carries, named by this row (issue #983).
    binary_notice: bool = False
    # The output path an ``artifact`` evidence row records (issue #1045); newest per path wins.
    artifact_path: str | None = None
    # Each part's place in its source text, in part order: the ``excerpt_span_key`` of every
    # byte interval of the source the part holds (a head-and-tail clip holds two), over the
    # source's own length whatever the selection. What a sent packet carried of this source, so
    # an in-check follow-up adds only parts no packet carried (tb4n5, #1047 follow-up). Empty
    # when parts cannot be placed.
    part_keys: tuple[tuple[str, ...], ...] = ()


# Offered (free slots, free bytes); returns the items and refs it admitted in that room.
type _LowerRankAdmission = Callable[
    [int, int], tuple[tuple[SemanticCaseItem, ...], tuple[TargetedExcerptRef, ...]]
]


@dataclass(frozen=True, slots=True)
class _ExcerptSelection:
    items: tuple[SemanticCaseItem, ...]
    targeted: tuple[TargetedExcerptRef, ...]
    omissions: tuple[ReviewOmission, ...]
    gaps: frozenset[str]
    over_limit: frozenset[str]
    # Items whose admitted bytes are a bounded prefix/suffix of their recorded source.  The
    # selection bound is distinct from a case-item bound: both must remain visible in the
    # section manifest after provider admission.
    truncated_item_ids: frozenset[str]
    # ``(item_id, excerpt_span_key)`` of each admitted part that can be placed in its source,
    # one pair per interval it holds.
    part_keys: tuple[tuple[str, str], ...] = ()


def _captured_edit_paths(content: bytes) -> tuple[bool, tuple[str, ...]]:
    """Return ``(failed, paths)`` for one captured edit, from its own recorded bytes only.

    Codex ``apply_patch`` and shell ``git apply`` captures are patch text; Claude Code, Cursor
    and shell whole-file writes are the changed-file JSON the hook selected. Paths are already
    workspace-relative (the hook masks anything outside the workspace), are used only to relate
    hunks of the same file, and are never copied into the packet by this function.
    """

    paths: set[str] = set()
    failed = False
    parsed: JsonValue = None
    if content.lstrip().startswith(b"{"):
        try:
            parsed = strict_json_parse(content)
        except ValueError:
            parsed = None
    if isinstance(parsed, Mapping):
        body = cast(Mapping[str, JsonValue], parsed)
        failed = body.get("edit_outcome") == "failed"
        path = body.get("path")
        if type(path) is str:
            paths.add(path)
        writes = body.get("writes")
        if isinstance(writes, (list, tuple)):
            for write in cast(Sequence[JsonValue], writes):
                if isinstance(write, Mapping):
                    target = cast(Mapping[str, JsonValue], write).get("path")
                    if type(target) is str:
                        paths.add(target)
    else:
        text = content.decode("utf-8", errors="replace")
        # Frozen legacy identifier (ADR-048): header inside stored captures.
        failed = text.startswith("# yoetz edit outcome: failed")
        paths.update(_PATCH_FILE_LINE.findall(text))
        paths.update(_PATCH_MOVE_LINE.findall(text))
        for old, new in _GIT_DIFF_LINE.findall(text):
            paths.update((old, new))
        paths.update(path for path in _UNIFIED_HEADER.findall(text) if path != "/dev/null")
    paths.discard(_OUTSIDE_WORKSPACE_PATH)
    paths.discard("")
    ordered = tuple(sorted(paths, key=lambda value: value.encode("utf-8")))
    return failed, ordered[:_MAX_EDIT_PATHS]


def _edit_paths_by_ref(groups: Mapping[str, _CapturedGroup]) -> dict[str, frozenset[str]]:
    """Every evidence ref of an applied captured edit, mapped to the paths the capture records."""

    by_ref: dict[str, frozenset[str]] = {}
    for group in groups.values():
        if group.source_kind != "diff":
            continue
        failed, paths = _captured_edit_paths(group.content)
        if failed or not paths:
            continue
        for ref in group.evidence_refs:
            by_ref[ref] = frozenset(paths)
    return by_ref


def captured_edit_paths(
    frozen_case: DeterministicCase,
    captured_content: Sequence[CapturedSemanticContent],
    captured_content_scope: CapturedContentScope | None,
) -> dict[str, frozenset[str]]:
    """Map each hook-captured edit's evidence refs to the workspace-relative paths it records.

    Issue #907: a later review compares these paths with the paths the agent names when it
    publishes a fresh diff, so a repeated ``current_diff_for_path`` request for a captured edit
    can converge. Only content the case builder would itself accept is read. The paths stay in
    process for that comparison; they are never recorded, logged or sent.
    """

    allowed = frozenset(str(ref) for ref in frozen_case.allowed_ids)
    groups, _gaps = _captured_content_groups(
        frozen_case.projection, allowed, captured_content, captured_content_scope
    )
    return _edit_paths_by_ref(groups)


# ``(identity, outcome, action ref, result ref)``: the result ref names one run, so an output and
# the failure summary of the same run are one run, never a newer run superseding its own output.
type _VerificationRun = tuple[str, ResultOutcome, str, str]


def _verification_identities(
    projection: ProjectionState,
) -> tuple[
    dict[str, _VerificationRun],
    dict[str, _VerificationRun],
    dict[str, tuple[int, str]],
    frozenset[str],
]:
    """Map evidence and result refs to the command whose run they record.

    Each run is ``(identity, outcome, action ref, result ref)``. Identity is the digest of the
    command's run key (``command_run_key``: the recorded text with whitespace collapsed, or a
    hook's keyed command identity; issue #1045), the same rule that decides whether a missing-item
    request was answered by another run of the same command. A hook run recorded without a command
    identity (``omitted:structural``) identifies nothing, so unrelated commands never supersede
    each other. The third map holds, per identity, the newest recorded run (its frontier and result
    ref), whether or not that run's output can be carried. The fourth set is identities whose
    newest run is a readable command action no readable result cites: a tombstoned result no
    longer names that action, and an older capture of the command must not be sent in its place.
    A tombstoned action has no command text and is absent here. The digest never leaves this
    function's callers.
    """

    by_evidence: dict[str, _VerificationRun] = {}
    enrichments = observed_enrichment_refs(projection)
    by_result: dict[str, _VerificationRun] = {}
    newest: dict[str, tuple[int, str]] = {}
    cited_actions: set[object] = set()
    for result_ref, row in sorted(
        projection.results.items(),
        key=lambda pair: (pair[1].source_frontier, str(pair[0]).encode("ascii")),
    ):
        payload = row.payload
        if payload is None or row.redacted:
            continue
        cited_actions.add(payload.action_id)
        action = projection.actions.get(payload.action_id)
        if (
            action is None
            or action.payload is None
            or action.redacted
            or action.payload.action_kind is not ActionKind.COMMAND
        ):
            continue
        key = command_run_key(action.payload)
        if key is None:
            continue
        identity = "command:" + hashlib.sha256("\x00".join(key).encode("utf-8")).hexdigest()
        run = (identity, payload.outcome, str(payload.action_id), str(result_ref))
        by_result[str(result_ref)] = run
        newest[identity] = (row.source_frontier, str(result_ref))
        for evidence_ref in payload.evidence_refs:
            by_evidence[str(evidence_ref)] = run
        for evidence_ref in enrichments.get(str(action.source_event_id), ()):
            by_evidence[evidence_ref] = run
    # A tombstoned result cannot cite its action. The action still names the command, and its
    # frontier is the newest run when no readable result of that command is later.
    redacted_newest: set[str] = set()
    for action_ref, action_row in projection.actions.items():
        if action_ref in cited_actions:
            continue
        action_payload = action_row.payload
        if (
            action_payload is None
            or action_row.redacted
            or action_payload.action_kind is not ActionKind.COMMAND
        ):
            continue
        key = command_run_key(action_payload)
        if key is None:
            continue
        identity = "command:" + hashlib.sha256("\x00".join(key).encode("utf-8")).hexdigest()
        rank = (action_row.source_frontier, str(action_ref))
        previous = newest.get(identity)
        if previous is None or rank > previous:
            newest[identity] = rank
            redacted_newest.add(identity)
    return by_evidence, by_result, newest, frozenset(redacted_newest)


def _artifact_path(payload: EvidenceRecordedPayload) -> str | None:
    """The normalized path an ``artifact`` evidence row records, or ``None`` (issue #1045).

    Two artifact rows with the same path record the same output file at two times, so the newer
    one supersedes the older. Only a plain path counts: no whitespace, glob, scheme or ``:``.
    """

    reference = payload.reference
    if (
        payload.evidence_kind is not EvidenceKind.ARTIFACT
        or reference is None
        or not reference
        or _NOT_AN_ARTIFACT_PATH.search(reference) is not None
    ):
        return None
    return posixpath.normpath(reference)


_NOT_AN_ARTIFACT_PATH: Final = re.compile(r"[\s*?\[\]{}~$`:]")


# Image and binary files (TB4 tb4n1 D6, issues #983 and #1004). The packet is text: their bytes
# and pixels never travel. A row that records one is carried as a notice that the agent referenced
# the file and it was not sent (the reference is the agent's, unverified; only a hook-observed
# image is "observed"), and an agent's text rendering of one (``pdftotext``, a CAD property dump,
# ``file`` or ``identify`` output recorded with the file's path as its ``reference``) is labelled as
# the agent's rendering, never as the file. Both labels are plain text inside the excerpt, so no new
# wire field is needed; the newest notices are reserved room, bounded.
_BINARY_NOTICE_MARKER: Final = (
    "[FinishUP: the agent referenced an image or binary file at {path} (evidence {ref}); "
    "it was not sent and its content is not assessable from this packet]\n"
)
_OBSERVED_IMAGE_NOTICE_MARKER: Final = (
    "[FinishUP: an image was observed (evidence {ref}); "
    "it was not sent and its content is not assessable from this packet]\n"
)
# Follow-up only (issue #1079). Prefixed after agent text is neutralised, so a capture cannot
# forge the label. The bytes stay a repository excerpt: a selection that would not already send
# one does not receive them.
_OBSERVED_COMMAND_OUTPUT_MARKER: Final = (
    "[FinishUP: observed command output captured from a command the agent ran; "
    "not an agent-published result]\n"
)
_LEDGER_SUBJECT_PREFIXES: Final = ("evt_", "obl_", "clm_", "act_", "res_", "evd_", "fnd_")
_BINARY_RENDERING_MARKER: Final = (
    "[FinishUP: agent-rendered text of {path} (evidence {ref}); the binary file itself is not"
    " sent]\n"
)
MAX_BINARY_NOTICES: Final = 16
_MAX_MARKER_PATH_CHARS: Final = 160
# A path in a FinishUP label keeps only these characters; any other becomes ``_``, so an agent's
# ``reference`` can never close the label or forge an evidence id inside it.
_MARKER_PATH_UNSAFE: Final = re.compile(r"[^A-Za-z0-9._/+@~=, -]")
# Agent-authored excerpt text never starts a line the way a FinishUP label does (issue #983): such a
# line is prefixed, so only FinishUP writes a line that begins ``[FinishUP``. The fence covers the
# legacy ``[Yoetz`` label prefix too, in any ASCII case (ADR-048): a reviewer that read labels under
# either name must not be handed a forged one.
_AGENT_TEXT_PREFIX: Final = "(agent text) "
_FORGED_LABEL_LINE: Final = re.compile(
    rf"^([ \t]*)(?=\[(?i:{re.escape(PRODUCT_NAME)}|{re.escape(LEGACY_PRODUCT_NAME)}))",
    re.MULTILINE | re.ASCII,
)
_LEADING_BLANKS: Final = re.compile(rb"[ \t]*")
# A label prefix fits in this many bytes after a line's leading blanks.
_LABEL_PROBE_BYTES: Final = 16


def _neutralised_agent_text(text: str) -> str:
    """``text`` with every line that begins like a FinishUP label marked as the agent's own."""

    return _FORGED_LABEL_LINE.sub(lambda match: match.group(1) + _AGENT_TEXT_PREFIX, text)


def _begins_like_label(content: bytes) -> bool:
    """Whether ``content`` starts, after any blanks, the way a FinishUP or Yoetz label does."""

    blanks = _LEADING_BLANKS.match(content)
    probe = content[: (blanks.end() if blanks else 0) + _LABEL_PROBE_BYTES]
    return _FORGED_LABEL_LINE.match(probe.decode("utf-8", errors="ignore")) is not None


def _marker_path(reference: str) -> str:
    """The agent's ``reference`` as it may appear in a FinishUP label: safe characters, bounded."""

    folded = _MARKER_PATH_UNSAFE.sub("_", " ".join(reference.split()))
    if len(folded) > _MAX_MARKER_PATH_CHARS:
        folded = folded[: _MAX_MARKER_PATH_CHARS - 3] + "..."
    return folded


def _known_binary(reference: str, binary_paths: frozenset[str], workspace_root: str | None) -> bool:
    """Whether ``reference`` names a file the check-time change marked binary (tb4n2 R7, P1-12).

    The change lists repository-relative paths; an absolute reference counts only under the
    workspace root. Lexical only: the path is never opened or resolved.
    """

    if not binary_paths or not reference or "://" in reference or "\x00" in reference:
        return False
    if reference.startswith("/"):
        if workspace_root is None:
            return False
        root = posixpath.normpath(workspace_root).rstrip("/") + "/"
        path = posixpath.normpath(reference)
        if not path.startswith(root):
            return False
        reference = path[len(root) :]
    relative = posixpath.normpath(reference)
    return relative in binary_paths


def _binary_file_label(
    ref: str,
    payload: EvidenceRecordedPayload,
    *,
    captured: bool,
    binary_paths: frozenset[str] = frozenset(),
    text_paths: frozenset[str] = frozenset(),
    workspace_root: str | None = None,
) -> tuple[str, bool] | None:
    """The label for a row that records an image or binary file, and whether it is a notice.

    A hook-observed image (L3 P3-2) and a row whose ``reference`` names such a file and records
    the file itself (an artifact, or its bytes' digest) are notices: the file was not sent. A row
    that names such a file but carries text (captured output, or the agent's own command output,
    test or other description) is the agent's rendering of it. The path is compared lexically,
    never opened, and enters the label only through ``_marker_path``.
    """

    if observed_image_evidence(payload):
        return _OBSERVED_IMAGE_NOTICE_MARKER.format(ref=ref), True
    reference = (payload.reference or "").strip()
    if (
        not reference
        or "://" in reference
        or not (
            _known_binary(reference, binary_paths, workspace_root)
            # Git's NUL sniff of the check-time change decides first (ADR-045): a listed text
            # file (a ``.step`` part) is no binary whatever its suffix.
            or (
                unsupported_data_type(reference)
                and not _known_binary(reference, text_paths, workspace_root)
            )
        )
    ):
        return None
    path = _marker_path(reference)
    binding = payload.digest_binding
    file_itself = payload.evidence_kind is EvidenceKind.ARTIFACT or (
        binding is not None and binding.subject is EvidenceDigestSubject.ARTIFACT_BYTES
    )
    if captured or (not file_itself and payload.description):
        return _BINARY_RENDERING_MARKER.format(path=path, ref=ref), False
    return _BINARY_NOTICE_MARKER.format(path=path, ref=ref), True


def _evidence_candidates(
    *,
    projection: ProjectionState,
    allowed: frozenset[str],
    selection: ReviewSelectionPolicy,
    linked_subjects: set[str],
    captured_groups: Mapping[str, _CapturedGroup],
    captured_group_leader: Mapping[str, str],
    excerpt_limit: int,
    part_limit: int,
    verification_by_evidence: Mapping[str, _VerificationRun],
    omissions: list[ReviewOmission],
    gaps: set[str],
    binary_paths: frozenset[str] = frozenset(),
    text_paths: frozenset[str] = frozenset(),
    workspace_root: str | None = None,
) -> list[_ExcerptCandidate]:
    candidates: list[_ExcerptCandidate] = []
    # Each admitted capture's bytes digest, mapped to its candidate's index.
    admitted_capture_digests: dict[bytes, int] = {}
    for evidence_id, record in sorted(
        projection.evidence.items(),
        key=lambda pair: (pair[1].source_frontier, str(pair[0]).encode("ascii")),
    ):
        ref = str(evidence_id)
        if ref not in allowed:
            continue
        payload = record.payload
        if payload is None or record.redacted:
            omissions.append(
                _omit(
                    ref,
                    DataCategory.EVIDENCE_EXCERPT,
                    "evidence",
                    "redacted_never_send" if record.redacted else "not_recorded",
                )
            )
            continue
        assert type(payload) is EvidenceRecordedPayload
        leader = captured_group_leader.get(ref)
        if leader is not None and leader != ref:
            # Multipart captured evidence is one AI-powered review excerpt. Carrying each part as a
            # separate excerpt would let an incomplete group look reviewable and would spend
            # the selection budget on duplicate structural descriptions.
            continue
        captured_group = captured_groups.get(ref)
        excerpt_kind = (
            captured_group.source_kind
            if captured_group is not None
            else _EVIDENCE_EXCERPT_KIND.get(payload.evidence_kind, "evidence")
        )
        if excerpt_kind not in selection.excerpt_kinds:
            if captured_group is not None:
                gaps.add("content_unselected")
            omissions.append(
                _omit(ref, DataCategory.EVIDENCE_EXCERPT, excerpt_kind, "not_selected")
            )
            continue
        if selection.relevance == "linked_subjects_only":
            source_event = str(record.source_event_id)
            if ref not in linked_subjects and source_event not in linked_subjects:
                if captured_group is not None:
                    gaps.add("content_unselected")
                omissions.append(
                    _omit(ref, DataCategory.EVIDENCE_EXCERPT, excerpt_kind, "not_selected")
                )
                continue
        if (
            captured_group is None
            and payload.captured_object_id is not None
            and payload.digest_binding is not None
            and payload.digest_binding.provenance is EvidenceDigestProvenance.OBSERVATION_CAPTURED
        ):
            # A structural capture description is never a substitute for authenticated bytes.
            # Preserve the coverage gap even when the omission list itself is capped away.
            omissions.append(
                _omit(ref, DataCategory.EVIDENCE_EXCERPT, excerpt_kind, "not_recorded")
            )
            gaps.add("captured_object_unavailable")
            continue
        digest_provenance: ExcerptDigestProvenance | None = None
        text: str | None
        capture_digest: bytes | None = None
        if captured_group is not None:
            capture_digest = hashlib.sha256(captured_group.content).digest()
            survivor = admitted_capture_digests.get(capture_digest)
            if survivor is not None:
                # Identical retained bytes (for example a patch captured by an older build
                # on both its pre- and post-tool events) are one excerpt, not two. The kept
                # excerpt answers for this row too, so a link or reservation naming this row
                # (a claim citing the later capture of a declared output, tb4n2 R7) still holds.
                candidates[survivor] = replace(
                    candidates[survivor],
                    identity_refs=candidates[survivor].identity_refs
                    | frozenset({ref, *(captured_group.evidence_refs)}),
                )
                omissions.append(
                    _omit(ref, DataCategory.EVIDENCE_EXCERPT, excerpt_kind, "not_selected")
                )
                continue
            # The service-authenticated inner bytes are the only source that may populate a
            # captured AI-powered review excerpt. Their digest provenance is retained separately
            # from the digest of the selection-clipped item below.
            text = captured_group.content.decode("utf-8")
            digest_provenance = captured_group.digest_provenance
        elif payload.content_digest is not None:
            binding = payload.digest_binding
            if binding is None:
                omissions.append(
                    _omit(ref, DataCategory.EVIDENCE_EXCERPT, excerpt_kind, "not_recorded")
                )
                continue
            digest_provenance = ExcerptDigestProvenance(
                evidence_kind=payload.evidence_kind,
                strength=payload.strength,
                content_digest=payload.content_digest,
                digest_subject=binding.subject,
                content_availability=binding.content_availability,
                byte_count=binding.byte_count,
                provenance=binding.provenance,
                approval_commitment=binding.approval_commitment,
                approved_check_result_digest=binding.approved_check_result_digest,
            )
            if payload.description:
                # Caller-authored narrative stays legible; digest identity rides on the
                # excerpt ref instead of replacing the content (issue #176).
                text = payload.description
            else:
                text = canonical_encode(
                    cast(
                        JsonValue,
                        {
                            # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
                            "schema": "yoetz.evidence-digest-provenance/1",
                            "evidence_kind": payload.evidence_kind.value,
                            "strength": payload.strength.value,
                            "content_digest": payload.content_digest,
                            "digest_subject": binding.subject.value,
                            "content_availability": binding.content_availability.value,
                            "byte_count": binding.byte_count,
                            "provenance": binding.provenance.value,
                            **(
                                {}
                                if binding.approval_commitment is None
                                else {"approval_commitment": binding.approval_commitment}
                            ),
                            **(
                                {}
                                if binding.approved_check_result_digest is None
                                else {
                                    "approved_check_result_digest": (
                                        binding.approved_check_result_digest
                                    )
                                }
                            ),
                        },
                    )
                ).decode("utf-8")
        else:
            text = payload.description or payload.reference
        if text:
            # The agent's text (its description, reference or captured tool output) never begins
            # a line the way a FinishUP label does.
            text = _neutralised_agent_text(text)
        split_diff = captured_group is not None and excerpt_kind == "diff"
        binary = (
            None
            if split_diff
            else _binary_file_label(
                ref,
                payload,
                captured=captured_group is not None,
                binary_paths=binary_paths,
                text_paths=text_paths,
                workspace_root=workspace_root,
            )
        )
        if binary is not None:
            # The label leads the excerpt, so a head-and-tail clip always keeps it.
            text = binary[0] + (text or "")
        if text is None or not text:
            omissions.append(
                _omit(ref, DataCategory.EVIDENCE_EXCERPT, excerpt_kind, "not_recorded")
            )
            continue
        encoded = text.encode("utf-8")
        clipped = False
        if split_diff:
            # Split authenticated code, not freeform claim prose, into independently bounded
            # items. Later hunks compete for the explicit count/total caps as parts of this one
            # capture; each part is one excerpt slot and no part joins two captures.
            parts: list[str] = []
            spans: list[tuple[int, int]] = []
            remaining = encoded
            while remaining and len(parts) <= selection.max_excerpts:
                # A part that would begin mid-line like a FinishUP label is marked as well.
                prefix = _AGENT_TEXT_PREFIX if _begins_like_label(remaining) else ""
                part = remaining[: part_limit - len(prefix)].decode("utf-8", errors="ignore")
                if not part:
                    break
                parts.append(prefix + part)
                start = len(encoded) - len(remaining)
                remaining = remaining[len(part.encode("utf-8")) :]
                spans.append((start, len(encoded) - len(remaining)))
            clipped = bool(remaining)
            # Placed over the capture's own length: the same bytes keep the same key whatever
            # part count or size a narrowed selection allows, and bytes no part holds stay unshown.
            part_keys = tuple(
                (excerpt_span_key(ref, low, high, len(encoded)),) for low, high in spans
            )
        else:
            # Long output keeps its head and its tail with the cut marked (issue #907).
            clipped = len(encoded) > excerpt_limit
            clip, kept = _head_tail_kept(encoded, excerpt_limit) if clipped else (text, ())
            parts = [clip]
            part_keys = (_span_keys(ref, kept if clipped else ((0, len(encoded)),), encoded),)
        group_refs = captured_group.evidence_refs if captured_group is not None else ()
        subjects = {
            ref,
            *group_refs,
            str(record.source_event_id),
            *(
                str(projection.evidence[validate_evidence_id(evidence_ref)].source_event_id)
                for evidence_ref in group_refs
                if validate_evidence_id(evidence_ref) in projection.evidence
            ),
            *(
                str(claim_id)
                for claim_id, claim_record in effective_claim_items(projection)
                if claim_record.payload is not None
                and any(
                    str(support) in (set(group_refs) if group_refs else {ref})
                    for support in claim_record.payload.supporting_refs
                )
            ),
        } & allowed
        # Within the 16-ref bound a captured group's own evidence (its lead and every part) is
        # kept ahead of the events and claims that link it: the parts are what this excerpt's
        # bytes hold (issue #1047). Any other excerpt keeps the first 16 in byte order, as
        # before; a list that fits is exactly every subject, in byte order.
        members = sorted(set(group_refs) & subjects, key=str.encode)[:16]
        others = sorted(subjects.difference(members), key=str.encode)
        linked = tuple(sorted([*members, *others[: 16 - len(members)]], key=str.encode))
        if not linked:
            if captured_group is not None:
                gaps.add("content_unselected")
            omissions.append(
                _omit(ref, DataCategory.EVIDENCE_EXCERPT, excerpt_kind, "not_selected")
            )
            continue
        edit_paths: tuple[str, ...] | None = None
        if split_diff:
            assert captured_group is not None
            failed_edit, paths = _captured_edit_paths(captured_group.content)
            edit_paths = None if failed_edit else paths
        verification = verification_by_evidence.get(ref)
        if capture_digest is not None:
            admitted_capture_digests[capture_digest] = len(candidates)
        candidates.append(
            _ExcerptCandidate(
                source_ref=ref,
                item_base=f"excerpt-{ref}",
                source_kind=excerpt_kind,
                category=DataCategory.EVIDENCE_EXCERPT,
                parts=tuple(parts),
                clipped=clipped,
                linked=linked,
                occurred_order=record.source_frontier,
                content_visibility=(
                    "available"
                    if captured_group is not None or payload.captured_object_id is None
                    else "not_recorded"
                ),
                digest_provenance=digest_provenance,
                identity_refs=frozenset({ref, *group_refs}),
                edit_paths=edit_paths,
                verification_identity=None if verification is None else verification[0],
                verification_outcome=None if verification is None else verification[1],
                verification_action=None if verification is None else verification[2],
                verification_run=None if verification is None else verification[3],
                structural_only=(
                    captured_group is None
                    and payload.evidence_kind is EvidenceKind.OTHER
                    and payload.strength is EvidenceImmutability.METADATA_ONLY
                    and payload.content_digest is None
                ),
                binary_notice=binary is not None and binary[1],
                artifact_path=None if captured_group is not None else _artifact_path(payload),
                part_keys=part_keys,
            )
        )
    return candidates


def _observed_span_refs(keys: Iterable[str]) -> frozenset[str]:
    """Evidence refs whose observed-command-output spans ``keys`` name."""

    prefix = OBSERVED_COMMAND_OUTPUT_SPAN_PREFIX
    refs: set[str] = set()
    for key in keys:
        if not key.startswith(prefix):
            continue
        span = excerpt_span(key)
        if span is None:
            continue
        ref = span[0][len(prefix) :]
        if ref.startswith("evd_"):
            refs.add(ref)
    return frozenset(refs)


def _linked_observed_subjects(
    existing: Sequence[str], targets: Sequence[str], allowed: frozenset[str]
) -> tuple[str, ...]:
    """Ledger subjects the marked command-output excerpt may name, within the 16-ref bound."""

    seen: list[str] = []
    for ref in (*existing, *targets):
        if (
            type(ref) is str
            and ref in allowed
            and ref.startswith(_LEDGER_SUBJECT_PREFIXES)
            and ref not in seen
        ):
            seen.append(ref)
    return tuple(sorted(seen, key=str.encode)[:MAX_SEMANTIC_ITEM_SUBJECT_REFS])


# Auto-supply is only for commands ``command_runner_class`` already calls verification.
# Anything else (a ``cat``, an environment dump wrapped beside pytest) is withheld whole.
_PROC_ENVIRON: Final = re.compile(r"(?:^|/)proc/(?:self|[0-9]+)/environ\Z")
_ENV_ASSIGNMENT: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_ENV_OPTIONS_WITH_OPERAND: Final = frozenset(
    {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}
)
# The disclosure scan matches a private-key BEGIN banner only. Capture redacts that banner and
# leaves the body and the END line. Auto-supply drops the item when either remains.
_PRIVATE_KEY_END: Final = re.compile(
    rb"-{5}END[ \t]+(?:OPENSSH[ \t]+|RSA[ \t]+|EC[ \t]+|DSA[ \t]+|ENCRYPTED[ \t]+)?"
    rb"PRIVATE KEY-{5}"
)
# Base64 of the OpenSSH private-key body magic (``openssh-key-v1``), not a BEGIN banner.
_OPENSSH_KEY_BODY: Final = b"b3BlbnNzaC1rZXktdjE"
_NESTED_NOT_SHOWN: Final = "its own change is not shown"


def _argv_is_environment_dump(words: Sequence[str]) -> bool:
    """Whether these argv words print the environment rather than run a verifier."""

    if not words:
        return False
    for word in words:
        if _PROC_ENVIRON.search(word.replace("\\", "/")) is not None:
            return True
    head = words[0].replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if head == "printenv":
        return True
    if head in {"export", "declare", "typeset"} and "-p" in words[1:]:
        return True
    if head == "set":
        rest = [word for word in words[1:] if word != "--"]
        return all(word in {"-o", "+o", "-p"} or word.startswith("-o") for word in rest)
    if head != "env":
        return False
    rest = list(words[1:])
    while rest:
        token = rest[0]
        if _ENV_ASSIGNMENT.match(token) is not None:
            rest.pop(0)
            continue
        if token == "--":
            rest.pop(0)
            break
        if not token.startswith("-"):
            return False
        rest.pop(0)
        bare = token.partition("=")[0]
        if bare in _ENV_OPTIONS_WITH_OPERAND and "=" not in token and rest:
            rest.pop(0)
    return True


def _command_words(text: str) -> tuple[str, ...] | None:
    try:
        return tuple(shlex.split(text, posix=True))
    except ValueError:
        return None


def _command_dumps_environment(command: str) -> bool:
    """Whether any simple command in ``command`` is an environment dump.

    ``env pytest`` runs pytest; a bare ``env``, ``printenv``, ``set``, ``export -p`` or
    ``/proc/self/environ`` prints the environment. A compound that also runs a verifier
    (``pytest -q; printenv``) still dumps, so the whole capture is withheld.
    """

    structure = command_structure(command)
    if structure is None:
        words = _command_words(command)
        return words is None or _argv_is_environment_dump(words)
    if not structure.commands:
        return True
    for simple in structure.commands:
        if _argv_is_environment_dump(simple.words):
            return True
        raw = _command_words(simple.text)
        if raw is None or _argv_is_environment_dump(raw):
            return True
    return False


def _header_not_shown_path(line: str) -> str | None:
    """The repository-relative path on a check-time change header line that says it was not shown."""

    if not line.startswith("  ") or " not shown:" not in line:
        return None
    _status, _space, remainder = line[2:].partition(" ")
    if not remainder:
        return None
    path = remainder[: remainder.find(" not shown:")].strip()
    count = path.rfind(" (+")
    if count >= 0:
        path = path[:count].strip()
    if len(path) >= 2 and path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
    path = path.strip().strip("/")
    if not path or path.endswith("...") or "\x00" in path:
        return None
    return path


def _refused_repository_paths(
    capture: CheckChangeCapture | None,
) -> tuple[frozenset[str], frozenset[str]]:
    """Paths the frozen check-time change already refused to show, and nested prefixes it omitted.

    Exact paths are header files marked ``not shown`` (credential name, nested repository, nested
    untracked, and the other content withholdings). Prefixes are nested repositories whose own
    change was not read. Gitignored paths are absent from that listing; a command that is not a
    verifier never supplies them, and a verifier that names one of these refused paths is withheld.
    """

    if capture is None:
        return frozenset(), frozenset()
    try:
        text = capture.text.decode("utf-8")
    except UnicodeDecodeError:
        return frozenset(), frozenset()
    header, separator, _rest = text.partition("\nEnd of header. The unified diff follows.\n")
    if not separator:
        header = text
    exact: set[str] = set()
    prefixes: set[str] = set()
    for line in header.splitlines():
        if line.startswith("Nested repository ") and _NESTED_NOT_SHOWN in line:
            raw = line.removeprefix("Nested repository ").split(":", 1)[0].strip().strip("/")
            if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
                raw = raw[1:-1]
            if raw and not raw.endswith("..."):
                prefixes.add(raw)
            continue
        path = _header_not_shown_path(line)
        if path is not None:
            exact.add(path)
    return frozenset(exact), frozenset(prefixes)


def _operand_pieces(word: str) -> tuple[str, ...]:
    if word.startswith("-"):
        if "=" not in word:
            return ()
        return (word.split("=", 1)[1],)
    if "=" in word:
        value = word.split("=", 1)[1]
        return (word, value) if value else (word,)
    return (word,)


def _relative_operand(value: str, workspace_root: str | None) -> str | None:
    """Workspace-relative form of one operand, or ``None`` when it is outside or cannot be proved in."""

    if "\x00" in value:
        return None
    if value.startswith("/"):
        if _outside_workspace(value, workspace_root) is not None or workspace_root is None:
            return None
        root = posixpath.normpath(workspace_root).rstrip("/") + "/"
        path = posixpath.normpath(value)
        if path == root[:-1]:
            return ""
        if not path.startswith(root):
            return None
        value = path[len(root) :]
    parts = [part for part in value.replace("\\", "/").split("/") if part not in {"", "."}]
    if ".." in parts:
        return None
    return "/".join(parts)


def _operand_refused(
    value: str,
    *,
    workspace_root: str | None,
    exact: frozenset[str],
    prefixes: frozenset[str],
) -> bool:
    """Whether a repository excerpt would withhold this command operand."""

    if not value or "\x00" in value:
        return False
    folded = value.replace("\\", "/")
    if credential_named_path(value) or credential_named_path(folded.rsplit("/", 1)[-1]):
        return True
    if _PROC_ENVIRON.search(folded) is not None:
        return True
    if value.startswith("/") and (
        workspace_root is None or _outside_workspace(value, workspace_root) is not None
    ):
        return True
    parts = [part for part in folded.split("/") if part not in {"", "."}]
    if ".." in parts or ".git" in parts:
        return True
    relative = _relative_operand(value, workspace_root)
    if relative is None:
        return value.startswith("/") or ".." in parts
    if not relative:
        return False
    if relative in exact:
        return True
    return any(
        relative == prefix or relative.startswith(prefix + "/") or prefix.startswith(relative + "/")
        for prefix in prefixes
    )


# Wrapper and tool options whose operand is a path (``env -C /tmp``, ``uv run --directory x``).
# The program path itself is not one of these: ``/usr/bin/pytest`` is the tool, not a file the
# repository excerpt would have shown.
_PATH_OPTIONS: Final = frozenset({"-C", "--chdir", "--directory", "--project", "--env-file"})
_REDIRECTION: Final = re.compile(
    r"^(?:[0-9]+|&)?(?:>>|>\||>&|>|<<<|<<-|<<|<&|<>|<)(.*)$",
    re.DOTALL,
)


def _program_path_refused(program: str) -> bool:
    """Credential name, ``.git``, or ``/proc/*/environ`` on the program path itself.

    An absolute tool path (``/usr/bin/pytest``) is outside the workspace and is not a repository
    excerpt, so it is not refused for that reason.
    """

    if credential_named_path(program):
        return True
    folded = program.replace("\\", "/")
    if _PROC_ENVIRON.search(folded) is not None:
        return True
    parts = [part for part in folded.split("/") if part not in {"", "."}]
    return ".." in parts or ".git" in parts


def _path_bearing_tokens(words: Sequence[str]) -> tuple[str, ...]:
    """Redirection targets and path-option values, which wrapper stripping would otherwise drop."""

    found: list[str] = []
    pending_redirect = False
    pending_option = False
    for word in words:
        if pending_redirect or pending_option:
            if pending_redirect and word != "/dev/null" and not word.startswith("&"):
                found.append(word)
            if pending_option:
                found.append(word)
            pending_redirect = False
            pending_option = False
            continue
        match = _REDIRECTION.fullmatch(word)
        if match is not None:
            target = match.group(1)
            if target:
                if target != "/dev/null" and not target.startswith("&"):
                    found.append(target)
            else:
                pending_redirect = True
            continue
        name, separator, value = word.partition("=")
        if name in _PATH_OPTIONS:
            if separator:
                found.append(value)
            else:
                pending_option = True
    return tuple(found)


def _command_operands(words: Sequence[str]) -> tuple[str, ...]:
    """Arguments and path operands, not the program path ``strip_wrappers`` leaves at argv[0]."""

    stripped = strip_wrappers(words)
    program = stripped[0] if stripped else ""
    arguments = stripped[1:] if program else ()
    return (*arguments, *_path_bearing_tokens(words))


def _command_names_refused_path(
    command: str,
    *,
    workspace_root: str | None,
    check_time_change: CheckChangeCapture | None,
) -> bool:
    exact, prefixes = _refused_repository_paths(check_time_change)
    programs: list[str] = []
    operands: list[str] = []
    structure = command_structure(command)
    if structure is None:
        split = _command_words(command)
        if split is None:
            return True
        stripped = strip_wrappers(split)
        if stripped:
            programs.append(stripped[0])
        operands.extend(_command_operands(split))
    else:
        if not structure.commands:
            return True
        for simple in structure.commands:
            raw = _command_words(simple.text)
            if raw is None:
                return True
            stripped = strip_wrappers(raw)
            if stripped:
                programs.append(stripped[0])
            operands.extend(_command_operands(raw))
            # Canonical argv still names the file (``python -m pytest tests/id_rsa``).
            operands.extend(simple.words[1:])
    if any(_program_path_refused(program) for program in programs):
        return True
    for word in operands:
        for piece in _operand_pieces(word):
            if piece and _operand_refused(
                piece, workspace_root=workspace_root, exact=exact, prefixes=prefixes
            ):
                return True
    return False


def _output_secret_reason(content: bytes) -> _OmissionReason | None:
    """Drop the whole capture when check-time redaction, or a private-key body, would hit.

    ``redact_sensitive_content`` is the disclosure scan the check-time change runs, heuristics
    included. A hit withholds the item instead of shipping the redacted bytes. A private-key END
    line or OpenSSH key body is the same decision: capture only replaces the BEGIN banner.
    """

    # Native tool results may themselves be serialized JSON. Scan their decoded string
    # values too: an escaped newline must not hide a secret assignment from the scanner.
    pending: list[tuple[bytes, int]] = [(content, 0)]
    inspected = 0
    while pending:
        view, depth = pending.pop()
        inspected += 1
        if inspected > 4096:
            return "redacted_never_send"
        key_material = _PRIVATE_KEY_END.search(view) is not None or _OPENSSH_KEY_BODY in view
        try:
            findings = scan_for_sensitive_content(view)
            _replaced, detected = redact_sensitive_content(
                view, heuristic_marker=EGRESS_CREDENTIAL_PLACEHOLDER
            )
        except PrivacyFenceError, TypeError, ValueError:
            return "redacted_never_send"
        high = any(finding.confidence is not ScanConfidence.HEURISTIC for finding in findings)
        if key_material or high:
            return "redacted_never_send"
        if detected or findings:
            return "never_send_heuristic"
        try:
            # This is host output, not protocol JSON: native exec results include floats.
            parsed: object = json.loads(view)
        except RecursionError:
            return "redacted_never_send"
        except TypeError, ValueError:
            continue
        if depth >= 4:
            # Deeper structured encodings are not needed by supported native hook shapes.
            return "redacted_never_send"
        values: list[object] = [parsed]
        while values:
            value = values.pop()
            if type(value) is str:
                pending.append((value.encode("utf-8"), depth + 1))
            elif isinstance(value, Mapping):
                values.extend(cast(Mapping[object, object], value).keys())
                values.extend(cast(Mapping[object, object], value).values())
            elif isinstance(value, (list, tuple)):
                values.extend(cast(Sequence[object], value))
    return None


def _observed_command_text(projection: ProjectionState, action_ref: str | None) -> str | None:
    if action_ref is None:
        return None
    try:
        key = validate_action_id(action_ref)
    except ProtocolValueError, ValueError:
        return None
    row = projection.actions.get(key)
    if row is None or row.payload is None or row.redacted:
        return None
    return row.payload.command


def _auto_supply_refusal(
    command: str | None,
    content: bytes,
    *,
    workspace_root: str | None,
    check_time_change: CheckChangeCapture | None,
    captured_command: str | None = None,
    captured_identity: str | None = None,
    capture_redacted: bool = False,
) -> _OmissionReason | None:
    """Why this capture must not be auto-supplied, or ``None`` when it may.

    Layered and fail-closed: the command must already classify as verification; an environment
    dump, a credential-named path, a path outside the workspace, a path the frozen change refused
    (nested repository or other not-shown file), or a ``.git`` path withholds the item; the
    disclosure scan then drops the whole item on any secret hit. A partially redacted capture is
    not sent.
    """

    if capture_redacted:
        return "redacted_never_send"
    # The action's text is caller writable. Only a keyed identity matching the
    # service-resolved command context may authorize automatic disclosure.
    if (
        command is None
        or not command.startswith("omitted:hmac-sha256:")
        or captured_identity != command
        or captured_command is None
    ):
        return "withheld_by_policy"
    command = captured_command
    if not command.strip() or command.lstrip().startswith("omitted:"):
        return "withheld_by_policy"
    if not command_is_verification(command):
        return "withheld_by_policy"
    if _command_dumps_environment(command) or _command_names_refused_path(
        command, workspace_root=workspace_root, check_time_change=check_time_change
    ):
        return "withheld_by_policy"
    return _output_secret_reason(content)


def _observed_command_clip(
    encoded: bytes, limit: int
) -> tuple[str, tuple[tuple[int, int], ...]] | None:
    """Head and tail of ``encoded`` within ``limit``, with a cut-edge label prefixed again.

    ``_head_tail_kept`` fills ``limit``. The elision marker ends on a newline, so the tail
    (and a head that begins on a label) can start at ``[FinishUP`` even though the bytes were
    prefixed before the cut. Those two edges are neutralised again. The elision marker stays
    a FinishUP line. The caller reserves two ``(agent text) `` prefixes so the result still
    fits the excerpt. Kept intervals index ``encoded``, not the prefixes added here.
    """

    if limit < 1:
        return None
    _clip, kept = _head_tail_kept(encoded, limit)
    if not kept:
        return None
    if len(kept) == 1 and kept[0][0] == 0:
        head = encoded[: kept[0][1]].decode("utf-8", errors="ignore")
        return _neutralised_agent_text(head), kept
    if len(kept) != 2 or kept[0][0] != 0:
        return None
    (_head_start, head_end), (tail_start, tail_end) = kept
    head = encoded[:head_end].decode("utf-8", errors="ignore")
    tail = encoded[tail_start:tail_end].decode("utf-8", errors="ignore")
    elided = len(encoded) - head_end - (tail_end - tail_start)
    body = (
        _neutralised_agent_text(head)
        + _elision_marker(elided, len(encoded))
        + _neutralised_agent_text(tail)
    )
    return body, kept


def _marked_observed_command_candidate(
    candidate: _ExcerptCandidate,
    content: bytes,
    *,
    targets: Sequence[str],
    allowed: frozenset[str],
    source_refs: frozenset[str],
    excerpt_limit: int,
) -> _ExcerptCandidate | None:
    """The same capture, labelled observed, as one repository excerpt within the excerpt bound."""

    marker = _OBSERVED_COMMAND_OUTPUT_MARKER
    marker_bytes = len(marker.encode("ascii"))
    if marker_bytes >= excerpt_limit or not content:
        return None
    body = _neutralised_agent_text(content.decode("utf-8", errors="replace"))
    encoded = body.encode("utf-8")
    room = excerpt_limit - marker_bytes
    # One prefix on the head edge and one on the tail edge, after the cut.
    prefix_room = 2 * len(_AGENT_TEXT_PREFIX.encode("ascii"))
    clipped = len(encoded) > room
    if clipped:
        if room <= prefix_room:
            return None
        clipped_body = _observed_command_clip(encoded, room - prefix_room)
        if clipped_body is None:
            return None
        clip, kept = clipped_body
    else:
        clip, kept = body, ((0, len(encoded)),) if encoded else ()
    text = marker + clip
    if len(text.encode("utf-8")) > excerpt_limit or not kept:
        return None
    span_refs = sorted(
        {
            ref
            for ref in (candidate.source_ref, *candidate.identity_refs)
            if ref.startswith("evd_") and ref in source_refs
        },
        key=str.encode,
    )
    if candidate.source_ref not in span_refs and candidate.source_ref.startswith("evd_"):
        span_refs.append(candidate.source_ref)
    total = len(encoded)
    part_keys = tuple(
        excerpt_span_key(f"{OBSERVED_COMMAND_OUTPUT_SPAN_PREFIX}{ref}", low, high, total)
        for ref in span_refs
        for low, high in kept
        if low < high <= total
    )
    if not part_keys:
        return None
    linked = _linked_observed_subjects(candidate.linked, targets, allowed)
    if not linked and candidate.source_ref in allowed:
        linked = (candidate.source_ref,)
    if not linked:
        return None
    item_base = f"observed-output-{candidate.source_ref}"
    if len(item_base) > 128:
        return None
    return _ExcerptCandidate(
        source_ref=candidate.source_ref,
        item_base=item_base,
        source_kind="command",
        category=DataCategory.REPOSITORY_EXCERPT,
        parts=(text,),
        clipped=clipped,
        linked=linked,
        occurred_order=candidate.occurred_order,
        content_visibility="available",
        digest_provenance=candidate.digest_provenance,
        identity_refs=candidate.identity_refs | frozenset(linked),
        verification_identity=candidate.verification_identity,
        verification_outcome=candidate.verification_outcome,
        verification_action=candidate.verification_action,
        verification_run=candidate.verification_run,
        part_keys=(part_keys,),
    )


def _select_targeted_excerpts(
    *,
    projection: ProjectionState,
    allowed: frozenset[str],
    selection: ReviewSelectionPolicy,
    findings: Sequence[Finding],
    review_assessments: Sequence[ReviewAssessment],
    captured_groups: Mapping[str, _CapturedGroup],
    captured_group_leader: Mapping[str, str],
    excerpt_byte_budget: int,
    excerpt_count_budget: int | None = None,
    before_lower_ranks: _LowerRankAdmission | None = None,
    declared_output_refs: tuple[str, ...] = (),
    binary_paths: frozenset[str] = frozenset(),
    text_paths: frozenset[str] = frozenset(),
    workspace_root: str | None = None,
    follow_up: ReviewFollowUp | None = None,
    check_time_change: CheckChangeCapture | None = None,
    supplied_refs: frozenset[str] = frozenset(),
) -> _ExcerptSelection:
    """Choose the excerpts that fill the approved count and byte budget, most valuable first.

    Reserved room comes first, in the order issue #907 fixes: the newest captured edit of every
    changed path, then the latest output of every identified verification command (with the last
    failure kept beside a later pass). Evidence supplied to repair a finding (#898) follows, then
    older hunks of a changed path (still code under review), then everything else by recency,
    then by link class; older runs of the same command come last. Older hunks and runs are marked
    ``superseded_by``. Every excerpt still holds exactly one
    recorded source or one part of one capture.

    ``before_lower_ranks`` is offered the slots and bytes the reserved classes (current diff,
    latest verification, finding repair evidence) leave, once, before any older edit hunk or
    unreserved excerpt is considered; what it admits is listed at that rank (issue #983).

    ``declared_output_refs`` (``declared_output_capture_refs``) rank with the current diff: they
    are the current state of a deliverable the check-time change cannot hold (tb4n2 R7).

    ``supplied_refs`` are agent-published records that answer a still-pending missing-item
    request (issue #1079). Their excerpts rank after the current diff and before other
    recorded excerpts, inside the existing count and byte budgets. A result summary is added
    only when this selection already allows an evidence or test excerpt and no excerpt of
    that result exists yet. Nothing here widens the selection or the ceilings.

    ``follow_up`` (issue #1047) is the reviewer's own in-check request: the excerpts of its
    requested rows rank ahead of every other recorded excerpt, item by item in request order and
    newest first within an item, while their bytes fit ``follow_up_byte_budget``; the rest keep
    their ordinary rank. Without it nothing changes. It works per part, never per source (tb4n5):
    a part the check's first packet carried keeps its ordinary rank, a part an earlier round added
    is ranked first again so it keeps its place, and a source larger than the share has its next
    parts ranked first rather than none of it. A ``current_diff_for_path`` request naming a
    captured edit is answered first with the current section of each path that edit changed, cut
    from ``check_time_change`` (the frozen, already redacted service capture; nothing is read
    again), unless an earlier packet carried that section: the capture may be stale, the change
    is the state when this check ran.
    """

    repair_refs = repair_evidence_refs(projection, allowed)
    linked_subjects: set[str] = set(repair_refs) | set(declared_output_refs)
    # Admission follows the round-robin order across outputs, never plain recency, so newer
    # captures of one deliverable cannot take every slot from another (Codex review round 3).
    declared_position = {ref: index for index, ref in enumerate(declared_output_refs)}
    for finding in findings:
        linked_subjects.update(str(ref) for ref in finding.subject_refs)
    for claim_id, _ in effective_claim_items(projection):
        linked_subjects.add(str(claim_id))
    for obligation_id in projection.obligations:
        linked_subjects.add(str(obligation_id))
    # Assessment supporting refs are case-bound links the reviewer may need as excerpts.
    for assessment in review_assessments:
        linked_subjects.update(str(ref) for ref in assessment.supporting_refs)
        for fact in (*assessment.observed_facts, *assessment.required_but_missing_facts):
            linked_subjects.update(str(ref) for ref in fact.subject_refs)
    for _, claim_record in effective_claim_items(projection):
        if claim_record.payload is None:
            continue
        linked_subjects.update(str(ref) for ref in claim_record.payload.supporting_refs)

    # The approved policy already allows ``max_excerpt_bytes`` per excerpt; the old 4 KiB
    # structural item clip no longer applies to excerpts (issue #907, open question 3). Nothing
    # here widens the count, the per-excerpt bound or the total the owner approved.
    excerpt_limit = min(selection.max_excerpt_bytes, MAX_SEMANTIC_ITEM_BYTES)
    # A capture split into parts never makes one part larger than the whole excerpt budget.
    part_limit = min(excerpt_limit, selection.max_total_excerpt_bytes)
    omissions: list[ReviewOmission] = []
    gaps: set[str] = set()
    (
        verification_by_evidence,
        verification_by_result,
        newest_runs,
        redacted_command_runs,
    ) = _verification_identities(projection)
    if follow_up is not None:
        linked_subjects.update(follow_up.source_refs)
    candidates = _evidence_candidates(
        projection=projection,
        allowed=allowed,
        selection=selection,
        linked_subjects=linked_subjects,
        captured_groups=captured_groups,
        captured_group_leader=captured_group_leader,
        excerpt_limit=excerpt_limit,
        part_limit=part_limit,
        verification_by_evidence=verification_by_evidence,
        omissions=omissions,
        gaps=gaps,
        binary_paths=binary_paths,
        text_paths=text_paths,
        workspace_root=workspace_root,
    )

    # Optional command excerpts from actions when expanded selection allows exact commands.
    if selection.include_exact_command_text and "command" in selection.excerpt_kinds:
        for action_id, record in sorted(projection.actions.items(), key=lambda pair: str(pair[0])):
            ref = str(action_id)
            if ref not in allowed or record.payload is None or record.redacted:
                continue
            if record.payload.action_kind is not ActionKind.COMMAND:
                continue
            command = record.payload.command
            if command is None:
                omissions.append(
                    _omit(ref, DataCategory.COMMAND_METADATA, "command", "not_recorded")
                )
                continue
            linked = (ref,) if ref in allowed else (str(record.source_event_id),)
            linked = tuple(item for item in linked if item in allowed)
            if not linked:
                continue
            command = _neutralised_agent_text(command)
            encoded = command.encode("utf-8")
            clipped = len(encoded) > excerpt_limit
            clip, kept = (
                _head_tail_kept(encoded, excerpt_limit)
                if clipped
                else (command, ((0, len(encoded)),))
            )
            candidates.append(
                _ExcerptCandidate(
                    source_ref=ref,
                    item_base=f"excerpt-cmd-{ref}",
                    source_kind="command",
                    category=DataCategory.COMMAND_METADATA,
                    parts=(clip,),
                    clipped=clipped,
                    linked=linked,
                    occurred_order=record.source_frontier,
                    content_visibility="available",
                    digest_provenance=None,
                    identity_refs=frozenset({ref, str(record.source_event_id)}),
                    part_keys=(_span_keys(ref, kept, encoded),),
                )
            )

    # Failed results as failure excerpts when description-like summary exists.
    if "failure" in selection.excerpt_kinds:
        for result_id, record in sorted(projection.results.items(), key=lambda pair: str(pair[0])):
            ref = str(result_id)
            if ref not in allowed or record.payload is None or record.redacted:
                continue
            if record.payload.outcome is not ResultOutcome.FAILURE:
                continue
            summary = record.payload.summary
            if summary is None or not summary:
                omissions.append(
                    _omit(ref, DataCategory.EVIDENCE_EXCERPT, "failure", "not_recorded")
                )
                continue
            linked = tuple(
                sorted(
                    {
                        item
                        for item in (
                            ref,
                            str(record.payload.action_id),
                            str(record.source_event_id),
                        )
                        if item in allowed
                    },
                    key=str.encode,
                )
            )[:16]
            if not linked:
                continue
            summary = _neutralised_agent_text(summary)
            encoded = summary.encode("utf-8")
            clipped = len(encoded) > excerpt_limit
            clip, kept = (
                _head_tail_kept(encoded, excerpt_limit)
                if clipped
                else (summary, ((0, len(encoded)),))
            )
            verification = verification_by_result.get(ref)
            candidates.append(
                _ExcerptCandidate(
                    source_ref=ref,
                    item_base=f"excerpt-fail-{ref}",
                    source_kind="failure",
                    category=DataCategory.EVIDENCE_EXCERPT,
                    parts=(clip,),
                    clipped=clipped,
                    linked=linked,
                    occurred_order=record.source_frontier,
                    content_visibility="available",
                    digest_provenance=None,
                    identity_refs=frozenset(
                        {ref, str(record.payload.action_id), str(record.source_event_id)}
                    ),
                    verification_identity=None if verification is None else verification[0],
                    verification_outcome=None if verification is None else verification[1],
                    verification_action=None if verification is None else verification[2],
                    verification_run=None if verification is None else verification[3],
                    part_keys=(_span_keys(ref, kept, encoded),),
                )
            )

    # Agent-published output that answers a pending missing item (issue #1079). Failure rows
    # are already candidates. A success or partial summary is the same evidence-excerpt
    # category the selection already allows, never a new category and never hook capture
    # (those refs are not in ``supplied_refs``).
    summary_kind = (
        "evidence"
        if "evidence" in selection.excerpt_kinds
        else "test"
        if "test" in selection.excerpt_kinds
        else None
    )
    if supplied_refs and summary_kind is not None:
        present = {candidate.source_ref for candidate in candidates}
        for result_id, record in sorted(projection.results.items(), key=lambda pair: str(pair[0])):
            ref = str(result_id)
            if ref not in supplied_refs or ref in present or ref not in allowed:
                continue
            if record.payload is None or record.redacted:
                continue
            summary = record.payload.summary
            if summary is None or not summary.strip():
                continue
            linked = tuple(
                sorted(
                    {
                        item
                        for item in (
                            ref,
                            str(record.payload.action_id),
                            str(record.source_event_id),
                            *(str(item) for item in record.payload.evidence_refs),
                        )
                        if item in allowed
                    },
                    key=str.encode,
                )
            )[:MAX_SEMANTIC_ITEM_SUBJECT_REFS]
            if not linked:
                continue
            summary = _neutralised_agent_text(summary)
            encoded = summary.encode("utf-8")
            clipped = len(encoded) > excerpt_limit
            clip, kept = (
                _head_tail_kept(encoded, excerpt_limit)
                if clipped
                else (summary, ((0, len(encoded)),))
            )
            if not clip:
                continue
            verification = verification_by_result.get(ref)
            candidates.append(
                _ExcerptCandidate(
                    source_ref=ref,
                    item_base=f"excerpt-supplied-{ref}",
                    source_kind=summary_kind,
                    category=DataCategory.EVIDENCE_EXCERPT,
                    parts=(clip,),
                    clipped=clipped,
                    linked=linked,
                    occurred_order=record.source_frontier,
                    content_visibility="available",
                    digest_provenance=None,
                    identity_refs=frozenset(linked),
                    verification_identity=None if verification is None else verification[0],
                    verification_outcome=None if verification is None else verification[1],
                    verification_action=None if verification is None else verification[2],
                    verification_run=None if verification is None else verification[3],
                    part_keys=(_span_keys(ref, kept, encoded),),
                )
            )

    latest_for: dict[int, Literal["path", "command"]] = {}
    superseded_by: dict[int, tuple[str, ...]] = {}
    current_diffs: set[int] = set()
    reserved_runs: set[int] = set()

    def recency(index: int) -> tuple[int, bytes]:
        candidate = candidates[index]
        return (candidate.occurred_order, candidate.source_ref.encode("ascii"))

    # Current diff: the newest applied (or unconfirmed) captured edit of each changed path. A
    # failed edit changed nothing, so it neither is current code nor supersedes anything.
    newest_for_path: dict[str, int] = {}
    for index, candidate in enumerate(candidates):
        for path in candidate.edit_paths or ():
            known = newest_for_path.get(path)
            if known is None or recency(index) > recency(known):
                newest_for_path[path] = index
    for index, candidate in enumerate(candidates):
        if candidate.edit_paths is None:
            continue
        newer = {newest_for_path[path] for path in candidate.edit_paths} - {index}
        if not candidate.edit_paths or len(newer) < len(
            {newest_for_path[path] for path in candidate.edit_paths}
        ):
            # Newest for at least one path (or a capture whose paths cannot be read): current.
            current_diffs.add(index)
            if candidate.edit_paths:
                latest_for[index] = "path"
        else:
            superseded_by[index] = tuple(
                sorted({candidates[other].source_ref for other in newer}, key=str.encode)
            )

    # Latest verification output per command identity, keeping a failure beside a later pass. A
    # run is one recorded result: its captured output and its failure summary are the same run.
    runs: dict[str, dict[str, list[int]]] = {}
    for index, candidate in enumerate(candidates):
        if candidate.verification_identity is not None and candidate.verification_run is not None:
            runs.setdefault(candidate.verification_identity, {}).setdefault(
                candidate.verification_run, []
            ).append(index)
    for identity, by_run in runs.items():
        ordered = sorted(
            by_run.values(), key=lambda members: max(recency(i) for i in members), reverse=True
        )
        latest_run = ordered[0]
        newest_recorded = newest_runs.get(identity)
        if (
            newest_recorded is not None
            and newest_recorded[1] != candidates[latest_run[0]].verification_run
            and newest_recorded[1] in allowed
        ):
            # Issue #1045: the command ran again later and that run left no output this packet
            # can carry. Every output here is older than the latest run, so none is presented as
            # the latest: each is marked superseded by the newer run and ranked last.
            for members in ordered:
                for index in members:
                    if index not in current_diffs:
                        superseded_by.setdefault(index, (newest_recorded[1],))
            continue
        newest_refs = tuple(sorted({candidates[i].source_ref for i in latest_run}, key=str.encode))
        for index in latest_run:
            reserved_runs.add(index)
            latest_for.setdefault(index, "command")
        if candidates[latest_run[0]].verification_outcome is ResultOutcome.SUCCESS:
            prior_failure = next(
                (
                    members
                    for members in ordered[1:]
                    if candidates[members[0]].verification_outcome is ResultOutcome.FAILURE
                ),
                None,
            )
            reserved_runs.update(prior_failure or ())
        for members in ordered[1:]:
            for index in members:
                if index not in current_diffs:
                    superseded_by.setdefault(index, newest_refs)
    # The newest recorded output of one artifact path wins; older rows of the same path are
    # superseded and ranked last (issue #1045).
    newest_artifact: dict[str, int] = {}
    for index, candidate in enumerate(candidates):
        if candidate.artifact_path is None:
            continue
        known = newest_artifact.get(candidate.artifact_path)
        if known is None or recency(index) > recency(known):
            newest_artifact[candidate.artifact_path] = index
    for index, candidate in enumerate(candidates):
        if candidate.artifact_path is None:
            continue
        newest_index = newest_artifact[candidate.artifact_path]
        if newest_index != index and index not in current_diffs:
            superseded_by.setdefault(index, (candidates[newest_index].source_ref,))
    # The exact command of a reserved run travels beside its output, so the reviewer can name
    # which verification it reads (Expanded selection only carries command text).
    reserved_actions = {
        candidates[index].verification_action
        for index in reserved_runs
        if candidates[index].verification_action is not None
    }
    for index, candidate in enumerate(candidates):
        if candidate.source_kind == "command" and candidate.source_ref in reserved_actions:
            reserved_runs.add(index)

    # The newest notices that an image or binary file exists and was not sent are short and are
    # what keeps a reviewer from asking for content no packet can carry (#983): reserved, bounded.
    binary_notices = set(
        sorted(
            (index for index, candidate in enumerate(candidates) if candidate.binary_notice),
            key=recency,
            reverse=True,
        )[:MAX_BINARY_NOTICES]
    )

    # Issue #1047: what the reviewer asked for in this check, in request order, within its share.
    # tb4n5: chosen per part (see the docstring), so a partly shown source can still progress.
    # Held-back indexes are newest hook-captured command outputs a verification-output follow-up
    # must not send as a raw evidence excerpt (issue #1079), and older runs of a command whose
    # newest run is a redacted occupancy (a tombstoned result whose action is still readable).
    held_back: set[int] = set()
    for index, candidate in enumerate(candidates):
        if candidate.verification_identity not in redacted_command_runs:
            continue
        held_back.add(index)
        gaps.add("content_unselected")
        _append_omission(
            omissions,
            candidate.source_ref,
            candidate.linked,
            candidate.category,
            candidate.source_kind,
            "withheld_by_policy",
        )
    requested: dict[int, int] = {}
    promoted: dict[int, tuple[int, ...]] = {}
    if follow_up is not None:
        room = follow_up_byte_budget(selection)
        sections = _check_time_change_sections(check_time_change)

        def promote(index: int) -> bool:
            nonlocal room
            candidate = candidates[index]
            chosen: list[int] = []
            for part_index, part in enumerate(candidate.parts):
                keys = (
                    candidate.part_keys[part_index] if part_index < len(candidate.part_keys) else ()
                )
                if (
                    keys
                    and all(excerpt_span_covered(key, follow_up.shown_parts) for key in keys)
                    and not all(excerpt_span_covered(key, follow_up.added_parts) for key in keys)
                ):
                    # The check's first packet carried it: it keeps its ordinary rank.
                    continue
                size = len(part.encode("utf-8"))
                if size > room:
                    break
                chosen.append(part_index)
                room -= size
            if not chosen:
                return False
            requested[index] = len(requested)
            promoted[index] = tuple(chosen)
            return True

        def observed_capture(index: int, source_refs: frozenset[str]) -> bool:
            candidate = candidates[index]
            if not candidate.identity_refs & source_refs:
                return False
            group = captured_groups.get(candidate.source_ref)
            if (
                group is None
                or group.source_kind != "evidence"
                or candidate.verification_identity is None
                or candidate.verification_action is None
                or candidate.verification_run is None
            ):
                return False
            newest = newest_runs.get(candidate.verification_identity)
            return newest is not None and newest[1] == candidate.verification_run

        served: set[int] = set()
        for follow_up_item in follow_up.items:
            matching = sorted(
                (
                    index
                    for index, candidate in enumerate(candidates)
                    if index not in requested
                    and candidate.identity_refs & follow_up_item.source_refs
                ),
                key=recency,
                reverse=True,
            )
            if follow_up_item.kind == "current_diff_for_path" and sections:
                for index in matching:
                    linked = tuple(
                        sorted(
                            candidates[index].identity_refs & follow_up_item.source_refs & allowed,
                            key=str.encode,
                        )
                    )[:MAX_SEMANTIC_ITEM_SUBJECT_REFS]
                    for path in _relative_edit_paths(candidates[index].edit_paths, workspace_root):
                        for start, end, ordinal in sections.get(path, ()):
                            if ordinal in served or not linked:
                                continue
                            served.add(ordinal)
                            assert check_time_change is not None
                            candidates.append(
                                _current_section_candidate(
                                    check_time_change.text,
                                    start,
                                    end,
                                    ordinal,
                                    linked,
                                    _check_time_change_part_limit(selection),
                                )
                            )
                            if not promote(len(candidates) - 1):
                                # Only ever carried as the answer to this request.
                                candidates.pop()
            observed_indexes = {
                index
                for index in matching
                if follow_up_item.kind == "verification_output"
                and observed_capture(index, follow_up_item.source_refs)
            }
            for index in matching:
                if index not in observed_indexes or index in held_back:
                    continue
                held_back.add(index)
                # A selection that would not already send a repository excerpt must not
                # receive the capture, including through the raw evidence-excerpt path.
                if not selection.carries_check_time_change:
                    continue
                raw = candidates[index]
                prefix = f"{OBSERVED_COMMAND_OUTPUT_SPAN_PREFIX}{raw.source_ref}#"
                if any(part.startswith(prefix) for part in follow_up.seen_parts):
                    held_back.discard(index)
                    continue
                group = captured_groups.get(raw.source_ref)
                assert group is not None
                refusal = _auto_supply_refusal(
                    _observed_command_text(projection, raw.verification_action),
                    group.content,
                    captured_command=group.observed_command,
                    captured_identity=group.observed_command_identity,
                    capture_redacted=group.redacted,
                    workspace_root=workspace_root,
                    check_time_change=check_time_change,
                )
                if refusal is not None:
                    # The raw evidence excerpt stays held back. The omission says why the
                    # capture was not sent; a secret hit is not reported as a byte-budget miss.
                    gaps.add(
                        "content_redacted"
                        if refusal != "withheld_by_policy"
                        else "content_unselected"
                    )
                    _append_omission(
                        omissions,
                        raw.source_ref,
                        raw.linked,
                        DataCategory.REPOSITORY_EXCERPT,
                        "command",
                        refusal,
                    )
                    continue
                marked = _marked_observed_command_candidate(
                    raw,
                    group.content,
                    targets=follow_up_item.target_refs,
                    allowed=allowed,
                    source_refs=follow_up_item.source_refs,
                    excerpt_limit=excerpt_limit,
                )
                if marked is None:
                    gaps.add("content_unselected")
                    _append_omission(
                        omissions,
                        raw.source_ref,
                        raw.linked,
                        DataCategory.REPOSITORY_EXCERPT,
                        "command",
                        "not_selected",
                    )
                    continue
                candidates.append(marked)
                new_index = len(candidates) - 1
                if promote(new_index):
                    latest_for[new_index] = "command"
                else:
                    candidates.pop()
                    gaps.add("content_unselected")
                    _append_omission(
                        omissions,
                        marked.source_ref,
                        marked.linked,
                        marked.category,
                        marked.source_kind,
                        "not_selected",
                    )
            for index in matching:
                if index in observed_indexes or index in held_back:
                    continue
                promote(index)

    def requested_rank(index: int) -> tuple[int, int, int, int, bytes, bytes]:
        candidate = candidates[index]
        # Ahead of every other recorded excerpt, in the request's own order.
        return (
            _RANK_CURRENT_DIFF,
            -1,
            requested[index],
            0,
            candidate.source_ref.encode("ascii"),
            candidate.item_base.encode("ascii"),
        )

    def rank(index: int) -> tuple[int, int, int, int, bytes, bytes]:
        candidate = candidates[index]
        linked = bool(candidate.identity_refs & linked_subjects)
        declared = [
            declared_position[ref] for ref in candidate.identity_refs if ref in declared_position
        ]
        if declared:
            # Ahead of the current diff's other rows, in the reservation's own order.
            return (
                _RANK_CURRENT_DIFF,
                0,
                min(declared) - _DECLARED_ORDER_OFFSET,
                0,
                candidate.source_ref.encode("ascii"),
                candidate.item_base.encode("ascii"),
            )
        # After the current diff, before other recorded excerpts: the answer the agent
        # published for a still-pending missing item. The current diff keeps its place.
        if (
            supplied_refs
            and index not in current_diffs
            and (candidate.source_ref in supplied_refs or candidate.identity_refs & supplied_refs)
        ):
            return (
                _RANK_CURRENT_DIFF,
                1,
                -candidate.occurred_order,
                0,
                candidate.source_ref.encode("ascii"),
                candidate.item_base.encode("ascii"),
            )
        if index in current_diffs:
            klass = _RANK_CURRENT_DIFF
        elif index in reserved_runs:
            klass = _RANK_LATEST_VERIFICATION
        elif candidate.identity_refs & repair_refs or index in binary_notices:
            klass = _RANK_PRIOR_FINDING_CONTEXT
        elif index in superseded_by:
            klass = _RANK_OLDER_EDIT if candidate.edit_paths is not None else _RANK_SUPERSEDED
        else:
            klass = _RANK_UNRESERVED
        # Unlinked observation metadata rows describe an event, not its content; they only fill
        # room that content-bearing material leaves.
        metadata_last = (
            1 if klass == _RANK_UNRESERVED and candidate.structural_only and not linked else 0
        )
        return (
            klass,
            metadata_last,
            -candidate.occurred_order,
            0 if linked else 1,
            candidate.source_ref.encode("ascii"),
            candidate.item_base.encode("ascii"),
        )

    items: list[SemanticCaseItem] = []
    targeted: list[TargetedExcerptRef] = []
    over_limit: set[str] = set()
    truncated_item_ids: set[str] = set()
    excerpt_bytes_used = 0
    # The slots other excerpts (the check-time change, ADR-031) already hold are not offered here.
    excerpt_count_limit = (
        selection.max_excerpts
        if excerpt_count_budget is None
        else max(0, min(selection.max_excerpts, excerpt_count_budget))
    )
    lower_ranks_offered = before_lower_ranks is None

    def offer_lower_rank_room() -> None:
        nonlocal excerpt_bytes_used, lower_ranks_offered
        lower_ranks_offered = True
        if before_lower_ranks is None:
            return
        admitted_items, admitted_refs = before_lower_ranks(
            max(0, excerpt_count_limit - len(targeted)),
            max(0, excerpt_byte_budget - excerpt_bytes_used),
        )
        items.extend(admitted_items)
        targeted.extend(admitted_refs)
        excerpt_bytes_used += sum(ref.content_bytes for ref in admitted_refs)

    # One admission entry per candidate, at its rank; a candidate with promoted parts has those
    # at the request's rank and its other parts at its ordinary rank (a served current section
    # has no ordinary rank). Without a follow-up this is every candidate's parts in rank order.
    entries: list[tuple[tuple[int, int, int, int, bytes, bytes], int, tuple[int, ...]]] = []
    for index, candidate in enumerate(candidates):
        every = tuple(range(len(candidate.parts)))
        chosen = promoted.get(index)
        if chosen is None:
            entries.append((rank(index), index, every))
            continue
        entries.append((requested_rank(index), index, chosen))
        rest = tuple(part_index for part_index in every if part_index not in chosen)
        if rest and not candidate.item_base.startswith(CHECK_TIME_SECTION_ITEM_PREFIX):
            entries.append((rank(index), index, rest))
    entries.sort(key=lambda entry: entry[0])
    admitted_by_index: dict[int, list[str]] = {}
    omitted_indexes: set[int] = set()
    part_keys: list[tuple[str, str]] = []
    for entry_rank, index, part_indexes in entries:
        if index in held_back:
            continue
        candidate = candidates[index]
        if not lower_ranks_offered and entry_rank[0] >= _RANK_OLDER_EDIT:
            offer_lower_rank_room()
        admitted_before = len(targeted)
        truncated = candidate.clipped
        admitted_item_ids: list[str] = []
        for part_index in part_indexes:
            part = candidate.parts[part_index]
            part_bytes = len(part.encode("utf-8"))
            if (
                len(targeted) >= excerpt_count_limit
                or excerpt_bytes_used + part_bytes > excerpt_byte_budget
            ):
                truncated = True
                # Issue #907: every candidate the count or byte budget cuts is disclosed, ledger
                # evidence as well as captured content. The omission row below may be capped away
                # with the omission list; the coverage gap is then the only trace.
                gaps.add("content_unselected")
                if index not in omitted_indexes:
                    omitted_indexes.add(index)
                    _append_omission(
                        omissions,
                        candidate.source_ref,
                        candidate.linked,
                        candidate.category,
                        candidate.source_kind,
                        "not_selected",
                    )
                break
            item_id = (
                candidate.item_base
                if len(candidate.parts) == 1
                else f"{candidate.item_base}-part-{part_index + 1:02d}"
            )
            item = _content_item(
                item_id=item_id,
                section="excerpt",
                category=candidate.category,
                source_kind=candidate.source_kind,
                source_ref=candidate.source_ref,
                linked_subject_refs=candidate.linked,
                occurred_order=candidate.occurred_order,
                text=part,
                over_limit=over_limit,
                limit=excerpt_limit,
                latest_for=latest_for.get(index) if index not in superseded_by else None,
                superseded_by=superseded_by.get(index, ()),
            )
            items.append(item)
            admitted_item_ids.append(item_id)
            targeted.append(
                TargetedExcerptRef(
                    excerpt_item_id=item_id,
                    source_kind=candidate.source_kind,
                    linked_subject_refs=candidate.linked,
                    subject_state_relation=SubjectStateRelation.UNKNOWN,
                    content_visibility=candidate.content_visibility,
                    content_digest=item.content_digest,
                    content_bytes=item.content_bytes,
                    digest_provenance=candidate.digest_provenance,
                )
            )
            excerpt_bytes_used += item.content_bytes
            if part_index < len(candidate.part_keys):
                part_keys.extend((item_id, key) for key in candidate.part_keys[part_index])
        if truncated and len(targeted) > admitted_before:
            gaps.add("truncated_payload")
            truncated_item_ids.update(admitted_item_ids)
        admitted_by_index.setdefault(index, []).extend(admitted_item_ids)
    if not lower_ranks_offered:
        offer_lower_rank_room()
    for index in promoted:
        # A source whose parts were split between the request's rank and its own is a partial
        # view whenever not every part it has reached the packet.
        admitted_ids = admitted_by_index.get(index, [])
        if admitted_ids and len(admitted_ids) < len(candidates[index].parts):
            gaps.add("truncated_payload")
            truncated_item_ids.update(admitted_ids)
    return _ExcerptSelection(
        items=tuple(items),
        targeted=tuple(targeted),
        omissions=tuple(omissions),
        gaps=frozenset(gaps),
        over_limit=frozenset(over_limit),
        truncated_item_ids=frozenset(truncated_item_ids),
        part_keys=tuple(part_keys),
    )


def _prior_finding_candidates(
    projection: ProjectionState, allowed: frozenset[str]
) -> list[tuple[str, FindingProjectionRecord]]:
    """Readable, open AI-powered findings inside the fence, newest first.

    Local findings are proven by the local packs that raised them and reach the reviewer as this
    check's assessments; resolved findings are history. Neither is a live question for the reviewer.
    Nor is a terminal item (issue #905): ``acknowledged_not_done``, ``rejection_accepted`` and
    ``self_verified`` (issue #984) are final and are never re-reviewed.
    """

    rows: list[tuple[str, FindingProjectionRecord]] = []
    for key, record in projection.findings.items():
        payload = record.payload
        ref = str(key)
        if (
            payload is None
            or record.redacted
            or record.resolved_by_check_event_id is not None
            or payload.origin is not FindingOrigin.SEMANTIC_MODEL_DERIVED
            or ref not in allowed
            or (
                finding_todo_state(projection, key) is not FindingTodoState.OPEN
                # Issue #996: a linked duplicate only inherits a final state; it stays in the
                # packet so the reviewer can rule still_present and break a wrong link.
                and duplicate_link_target(projection, key) is None
            )
            # tb4n3 RC-1 (Q4): a limitation request the agent disclosed is settled; it travels as
            # a non-rulable settled row marked already disclosed, never as an open question.
            or _limitation_disclosure(projection, key) is not None
        ):
            continue
        rows.append((ref, record))
    rows.sort(key=lambda pair: (-pair[1].source_frontier, pair[0].encode("ascii")))
    return rows


def _prior_finding_items(
    ref: str,
    record: FindingProjectionRecord,
    projection: ProjectionState,
    allowed: frozenset[str],
    *,
    include_prose: bool,
) -> tuple[list[SemanticCaseItem], list[ReviewOmission]]:
    """One earlier finding, what the reviewer asked, and how the main agent answered.

    The structural row is always carried: kind, ids, recorded order, the requested next step, the
    response disposition and cited refs, and the readable evidence and results recorded after the
    finding (the material a repair would have produced). Prose rows follow the profile's finding
    prose selection. A finding recorded before challenge fields were persisted degrades to its
    summary and message with an explicit ``not_recorded`` omission.
    """

    payload = record.payload
    assert payload is not None
    items: list[SemanticCaseItem] = []
    omissions: list[ReviewOmission] = []
    response_record = projection.responses.get(finding_id_value(ref))
    response = (
        None if response_record is None or response_record.redacted else response_record.payload
    )
    newer = sorted(
        (
            (row.source_frontier, str(key))
            for family in (projection.evidence, projection.results)
            for key, row in family.items()
            if row.payload is not None
            and not row.redacted
            and row.source_frontier > record.source_frontier
            and str(key) in allowed
        ),
        key=lambda pair: (-pair[0], pair[1].encode("ascii")),
    )
    subjects: list[JsonValue] = [str(item) for item in payload.subject_refs if str(item) in allowed]
    after: list[JsonValue] = [value for _order, value in newer]
    body: dict[str, JsonValue] = {
        "challenge_fields": "not_recorded" if payload.challenge is None else "recorded",
        "finding_kind": payload.kind.value,
        "finding_ref": ref,
        "recorded_after_finding": after[:_MAX_PRIOR_FINDING_LISTED_REFS],
        "recorded_after_finding_count": len(newer),
        "recorded_sequence": record.source_frontier,
        # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
        "schema": "yoetz.prior-finding/1",
        "subject_ref_count": len(payload.subject_refs),
        "subject_refs": subjects[:_MAX_PRIOR_FINDING_LISTED_REFS],
    }
    related: list[JsonValue] = [
        str(item) for item in payload.related_finding_ids if str(item) in allowed
    ]
    if related:
        body["relates_to"] = related
    if payload.challenge is not None:
        body["requested_next_step"] = payload.challenge.requested_next_step
    # The dialogue so far (TB4 tb4n1 D7): how many times the agent rebutted this finding, the
    # reviewer's newest ruling on it, and the review rounds it has been left open. Emitted only
    # when set, so a finding without dialogue keeps its earlier row bytes.
    if record.rebuttal_count:
        body["rebuttal_count"] = record.rebuttal_count
    if record.last_reviewer_verdict is not None:
        body["last_reviewer_verdict"] = record.last_reviewer_verdict
    if record.review_rounds:
        body["review_rounds"] = record.review_rounds
    if response_record is not None and response is None:
        body["response"] = {"visibility": "redacted_never_send"}
    elif response_record is not None and response is not None:
        cited: list[JsonValue] = [
            str(item) for item in response.evidence_refs if str(item) in allowed
        ]
        answer: dict[str, JsonValue] = {
            "disposition": response.disposition.value,
            "evidence_ref_count": len(response.evidence_refs),
            "evidence_refs": cited[:_MAX_PRIOR_FINDING_LISTED_REFS],
            "recorded_sequence": response_record.source_frontier,
        }
        if str(response_record.source_event_id) in allowed:
            answer["response_event_ref"] = str(response_record.source_event_id)
        # Issue #996: the earlier finding a ``duplicate_of`` answer links to, so the reviewer
        # can rule ``still_present`` on this one if it is not the same issue.
        duplicate_of = response.duplicate_of_finding_id
        if duplicate_of is not None and str(duplicate_of) in allowed:
            answer["duplicate_of_ref"] = str(duplicate_of)
        body["response"] = answer
    prose: list[tuple[str, str, int]] = []
    if include_prose:
        prose.append(("summary", payload.summary, record.source_frontier))
        prose.append(("message", payload.detail, record.source_frontier))
        if payload.challenge is None:
            omissions.append(_omit(ref, DataCategory.FINDING_SUMMARY, "finding", "not_recorded"))
        else:
            prose.append(("discrepancy", payload.challenge.discrepancy, record.source_frontier))
            prose.append(
                (
                    "alternative",
                    payload.challenge.alternative_interpretation,
                    record.source_frontier,
                )
            )
            prose.append(("uncertainty", payload.challenge.uncertainty, record.source_frontier))
        if response_record is not None and response is not None and response.reason is not None:
            prose.append(("response", response.reason, response_record.source_frontier))
        body["text_item_ids"] = {
            field: f"prior-finding-{field}-{ref}" for field, _text, _order in prose
        }
    text, _omitted = _bounded_json(body)
    items.append(
        _content_item(
            item_id=f"prior-finding-{ref}",
            section="prior_finding",
            category=DataCategory.BOUNDED_STRUCTURAL_METADATA,
            source_kind="finding",
            source_ref=ref,
            linked_subject_refs=(ref,),
            occurred_order=record.source_frontier,
            text=text,
        )
    )
    for field, value, order in prose:
        items.append(
            _content_item(
                item_id=f"prior-finding-{field}-{ref}",
                section="prior_finding",
                category=DataCategory.FINDING_SUMMARY,
                source_kind="finding",
                source_ref=ref,
                linked_subject_refs=(ref,),
                occurred_order=order,
                text=value,
            )
        )
    return items, omissions


def _prior_findings_section(
    projection: ProjectionState,
    allowed: frozenset[str],
    *,
    include_prose: bool,
    remaining_items: int,
    remaining_bytes: int,
) -> tuple[list[SemanticCaseItem], list[ReviewOmission], bool]:
    """Carry the dialogue so far, newest first, inside the section's own bounds.

    A finding is carried whole or not at all; one that does not fit is named as a ``not_selected``
    omission and the returned flag declares the truncation as a coverage gap.
    """

    items: list[SemanticCaseItem] = []
    omissions: list[ReviewOmission] = []
    truncated = False
    item_budget = min(MAX_PRIOR_FINDING_ITEMS, remaining_items)
    byte_budget = min(MAX_PRIOR_FINDING_SECTION_BYTES, remaining_bytes)
    carried = 0
    for ref, record in _prior_finding_candidates(projection, allowed):
        rows, row_omissions = _prior_finding_items(
            ref, record, projection, allowed, include_prose=include_prose
        )
        size = sum(item.content_bytes for item in rows)
        if (
            carried >= MAX_PRIOR_FINDINGS
            or len(rows) > item_budget - len(items)
            or size > byte_budget
        ):
            truncated = True
            omissions.append(
                _omit(
                    ref,
                    DataCategory.FINDING_SUMMARY
                    if include_prose
                    else DataCategory.BOUNDED_STRUCTURAL_METADATA,
                    "finding",
                    "not_selected",
                )
            )
            continue
        carried += 1
        byte_budget -= size
        items.extend(rows)
        omissions.extend(row_omissions)
    # The agent's answers to FinishUP's own local findings (issue #976). They are not rulable, so
    # they never enter prior_finding_refs, but the reviewer judges their substance: an answer that
    # says a requested output "cannot be produced" is exactly what a closing review must test.
    answers = 0
    for ref, record in _local_answer_candidates(projection, allowed):
        rows = _local_answer_items(ref, record, projection, include_prose=include_prose)
        size = sum(item.content_bytes for item in rows)
        if (
            answers >= MAX_LOCAL_FINDING_ANSWERS
            or len(rows) > item_budget - len(items)
            or size > byte_budget
        ):
            truncated = True
            continue
        answers += 1
        byte_budget -= size
        items.extend(rows)
    # Findings the agent settled (issue #980): nameable in ``restates``, never rulable, so a
    # re-raise of a concern the agent gave up on is recorded on that item instead of minted again.
    # They take only what the open findings left of the same 16-finding / 96 KiB bounds, newest
    # first. One that does not fit is not a truncation of the rulable section: the reviewer can
    # still rule on every open finding, and an unnamed re-raise becomes a new finding as before.
    for ref, record in _settled_finding_candidates(projection, allowed):
        rows = _settled_finding_items(ref, record, projection, allowed, include_prose=include_prose)
        size = sum(item.content_bytes for item in rows)
        if (
            carried >= MAX_PRIOR_FINDINGS
            or len(rows) > item_budget - len(items)
            or size > byte_budget
        ):
            continue
        carried += 1
        byte_budget -= size
        items.extend(rows)
    return items, omissions, truncated


def _settled_finding_candidates(
    projection: ProjectionState, allowed: frozenset[str]
) -> list[tuple[str, FindingProjectionRecord]]:
    """Readable, unresolved AI-powered findings the agent settled, newest answer first (#980).

    Settled means the agent's latest readable answer is ``acknowledged_not_done`` or
    ``self_verified`` (matched by wire value), or the item is ``disputed_after_rebuttal`` (a
    reasoned ``rejected`` the reviewer repeated without newer material, issue #1020). They are
    final and never re-reviewed, but the
    reviewer must be able to name one when it raises the same concern again.
    """

    rows: list[tuple[int, str, FindingProjectionRecord]] = []
    for key, record in projection.findings.items():
        payload = record.payload
        ref = str(key)
        if (
            payload is None
            or record.redacted
            or record.resolved_by_check_event_id is not None
            or payload.origin is not FindingOrigin.SEMANTIC_MODEL_DERIVED
            or ref not in allowed
        ):
            continue
        response = projection.responses.get(key)
        disclosure = _limitation_disclosure(projection, key)
        if disclosure is not None:
            # tb4n3 RC-1 (Q4): a limitation request the agent disclosed (a reasoned
            # acknowledgement, or a finishup-verification-limit decision on its obligation).
            order = (
                response.source_frontier
                if disclosure.since_frontier is not None and response is not None
                else record.source_frontier
            )
            rows.append((order, ref, record))
            continue
        if (
            response is None
            or response.redacted
            or response.payload is None
            or (
                response.payload.disposition.value not in AGENT_SETTLED_DISPOSITION_VALUES
                # Issue #1020: a standing disagreement is final too; the reviewer sees the
                # agent's rebuttal and can name it, but never rules on it again.
                and finding_todo_state(projection, key)
                is not FindingTodoState.DISPUTED_AFTER_REBUTTAL
            )
        ):
            continue
        rows.append((response.source_frontier, ref, record))
    rows.sort(key=lambda row: (-row[0], row[1].encode("ascii")))
    return [(ref, record) for _order, ref, record in rows]


def _observed_evidence(record: EvidenceProjectionRecord) -> bool:
    """Whether one evidence row is hook-captured and readable."""

    payload = record.payload
    binding = None if payload is None else payload.digest_binding
    return (
        payload is not None
        and not record.redacted
        and binding is not None
        and binding.provenance is EvidenceDigestProvenance.OBSERVATION_CAPTURED
    )


def _resolved_criterion_basis(
    payload: ObligationPublishedPayload,
    projection: ProjectionState,
    allowed: frozenset[str],
) -> dict[str, JsonValue] | None:
    """Refs that let the reviewer judge one resolved obligation as one question.

    The criterion stays the obligation's own text. This adds only refs already inside the
    fence and closed tokens: the result the resolution cites, the newest hook-captured
    verification of that result, and ``missing_input`` when either is not readable. No command
    text, summary, or path is copied in, so the row stays obligation text the policy already
    sends. A redacted result is not readable, so the evidence it cites is not walked.
    """

    if payload.status is not ObligationStatus.RESOLVED:
        return None
    results = {str(key): row for key, row in projection.results.items()}
    evidence = {str(key): row for key, row in projection.evidence.items()}
    claimed: list[str] = []
    observed: list[tuple[int, str]] = []

    def consider(token: str) -> None:
        row = evidence.get(token)
        if row is None or token not in allowed or not _observed_evidence(row):
            return
        observed.append((row.source_frontier, token))

    for ref in payload.resolution_evidence_refs:
        token = str(ref)
        if token not in allowed:
            continue
        result = results.get(token)
        if result is not None and result.payload is not None and not result.redacted:
            claimed.append(token)
            for evidence_ref in result.payload.evidence_refs:
                consider(str(evidence_ref))
            continue
        # A resolution ref that is not a readable result may itself be observed evidence.
        # A redacted result is neither: its payload is gone, so its evidence is not named.
        if result is None:
            consider(token)
    claimed_refs: list[JsonValue] = []
    for token in sorted(set(claimed), key=str.encode)[:16]:
        claimed_refs.append(token)
    newest: list[JsonValue] = []
    for _frontier, token in sorted(set(observed), key=lambda item: (-item[0], item[1].encode())):
        if token not in newest:
            newest.append(token)
        if len(newest) == 4:
            break
    missing: list[JsonValue] = []
    if not claimed_refs:
        missing.append("claimed_result")
    if not newest:
        missing.append("verification_output")
    return {
        "claimed_result_refs": claimed_refs,
        "latest_observed_verification_refs": newest,
        "missing_input": missing,
    }


def _obligation_disclosures(
    projection: ProjectionState, allowed: frozenset[str]
) -> dict[str, dict[str, JsonValue]]:
    """What the agent already disclosed per obligation, as ids and closed tokens only.

    An obligation acknowledged as not done, a ``finishup-verification-limit`` decision and a
    ``finishup-assumption`` decision are the agent's own disclosure of a limit. The reviewer reads
    them beside the obligation they cover, marked already disclosed, so it asks for nothing more
    than the disclosure (tb4n3 RC-1, owner decision Q4). Decision ids ride only when citable.
    """

    found: dict[str, dict[str, JsonValue]] = {}
    for obligation_id, record in projection.obligations.items():
        payload = record.payload
        if (
            payload is not None
            and not record.redacted
            and payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
        ):
            found.setdefault(str(obligation_id), {})["acknowledged_not_done"] = True
    for declaration in disclosure_declarations(projection):
        row = found.setdefault(str(declaration.obligation_id), {})
        row[declaration.kind] = (
            str(declaration.decision_event_id)
            if str(declaration.decision_event_id) in allowed
            else True
        )
    for row in found.values():
        row["already_disclosed"] = True
    return found


def _limitation_disclosure(projection: ProjectionState, key: object) -> LimitationStanding | None:
    """The disclosed limitation standing of a finding, or ``None`` (tb4n3 RC-1, Q4)."""

    standing = limitation_standing(projection, finding_id_value(str(key)))
    return standing if standing is not None and standing.disclosed else None


def _settled_finding_items(
    ref: str,
    record: FindingProjectionRecord,
    projection: ProjectionState,
    allowed: frozenset[str],
    *,
    include_prose: bool,
) -> list[SemanticCaseItem]:
    """One settled finding as a non-rulable row, plus its headline and the agent's reason."""

    payload = record.payload
    response = projection.responses.get(finding_id_value(ref))
    disclosure = _limitation_disclosure(projection, ref)
    assert payload is not None
    answer = None if response is None or response.redacted else response.payload
    # A limitation disclosed by a decision line has no answer of its own.
    assert answer is not None or disclosure is not None
    subjects: list[JsonValue] = [str(item) for item in payload.subject_refs if str(item) in allowed]
    order = (
        record.source_frontier if answer is None or response is None else response.source_frontier
    )
    body: dict[str, JsonValue] = {
        "disposition": "none" if answer is None else answer.disposition.value,
        "finding_kind": payload.kind.value,
        "finding_ref": ref,
        "recorded_sequence": record.source_frontier,
        "response_sequence": order,
        "rulable": False,
        # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
        "schema": "yoetz.settled-finding/1",
        "subject_ref_count": len(payload.subject_refs),
        "subject_refs": subjects[:_MAX_PRIOR_FINDING_LISTED_REFS],
    }
    if disclosure is not None:
        # The agent already stated the limit you asked for: do not challenge it again.
        body["limitation_already_disclosed"] = True
        body["limitation_disclosed_by"] = disclosure.basis or ""
    if record.settled_reraise_count:
        body["settled_reraise_count"] = record.settled_reraise_count
    prose: list[tuple[str, str]] = []
    if include_prose:
        prose.append(("summary", payload.summary))
        if answer is not None and answer.reason is not None:
            prose.append(("response", answer.reason))
        body["text_item_ids"] = {
            field: f"{SETTLED_FINDING_ITEM_PREFIX}{field}-{ref}" for field, _text in prose
        }
    text, _omitted = _bounded_json(body)
    items = [
        _content_item(
            item_id=f"{SETTLED_FINDING_ITEM_PREFIX}{ref}",
            section="prior_finding",
            category=DataCategory.BOUNDED_STRUCTURAL_METADATA,
            source_kind="finding",
            source_ref=ref,
            linked_subject_refs=(ref,),
            occurred_order=order,
            text=text,
        )
    ]
    for field, value in prose:
        items.append(
            _content_item(
                item_id=f"{SETTLED_FINDING_ITEM_PREFIX}{field}-{ref}",
                section="prior_finding",
                category=DataCategory.FINDING_SUMMARY,
                source_kind="finding",
                source_ref=ref,
                linked_subject_refs=(ref,),
                occurred_order=order,
                text=value,
            )
        )
    return items


def _local_answer_candidates(
    projection: ProjectionState, allowed: frozenset[str]
) -> list[tuple[str, FindingProjectionRecord]]:
    """Open local findings the main agent answered with a readable reason, newest answer first."""

    rows: list[tuple[int, str, FindingProjectionRecord]] = []
    for key, record in projection.findings.items():
        payload = record.payload
        ref = str(key)
        if (
            payload is None
            or record.redacted
            or payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
            or ref not in allowed
            or record.resolved_by_check_event_id is not None
            or finding_todo_state(projection, key)
            in {
                FindingTodoState.VERIFIED_RESOLVED,
                FindingTodoState.REJECTION_ACCEPTED,
                FindingTodoState.SELF_VERIFIED,
            }
        ):
            continue
        response = projection.responses.get(key)
        if (
            response is None
            or response.redacted
            or response.payload is None
            or response.payload.reason is None
        ):
            continue
        rows.append((response.source_frontier, ref, record))
    rows.sort(key=lambda row: (-row[0], row[1].encode("ascii")))
    return [(ref, record) for _order, ref, record in rows]


def _local_answer_items(
    ref: str,
    record: FindingProjectionRecord,
    projection: ProjectionState,
    *,
    include_prose: bool,
) -> list[SemanticCaseItem]:
    payload = record.payload
    response = projection.responses.get(finding_id_value(ref))
    assert payload is not None and response is not None and response.payload is not None
    body: dict[str, JsonValue] = {
        "disposition": response.payload.disposition.value,
        "finding_kind": payload.kind.value,
        "finding_ref": ref,
        "recorded_sequence": record.source_frontier,
        "response_sequence": response.source_frontier,
        "rulable": False,
        # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
        "schema": "yoetz.local-finding-answer/1",
    }
    if include_prose:
        body["text_item_ids"] = {"answer": f"local-finding-answer-text-{ref}"}
    text, _omitted = _bounded_json(body)
    items = [
        _content_item(
            item_id=f"local-finding-answer-{ref}",
            section="prior_finding",
            category=DataCategory.BOUNDED_STRUCTURAL_METADATA,
            source_kind="finding",
            source_ref=ref,
            linked_subject_refs=(ref,),
            occurred_order=response.source_frontier,
            text=text,
        )
    ]
    if include_prose:
        items.append(
            _content_item(
                item_id=f"local-finding-answer-text-{ref}",
                section="prior_finding",
                category=DataCategory.FINDING_SUMMARY,
                source_kind="finding",
                source_ref=ref,
                linked_subject_refs=(ref,),
                occurred_order=response.source_frontier,
                text=response.payload.reason or "",
            )
        )
    return items


def build_semantic_case(
    *,
    case_id: str,
    frozen_case: DeterministicCase,
    dependency_digest: str,
    findings: Sequence[Finding],
    review_context_profile: ReviewContextProfile,
    review_selection: ReviewSelectionPolicy,
    policy_id: str,
    policy_version: str,
    lineage_evaluation: LineageEvaluation | None = None,
    captured_content: Sequence[CapturedSemanticContent] = (),
    captured_content_scope: CapturedContentScope | None = None,
    captured_content_gaps: Sequence[str] = (),
    prepared_byte_ceiling: int | None = None,
    workspace_root: str | None = None,
    check_time_change: CheckTimeChange | None = None,
    check_time_change_unavailable: bool = False,
    check_time_change_unavailable_reason: str | None = None,
    final_review: bool = False,
    follow_up: ReviewFollowUp | None = None,
) -> SemanticCase:
    """Build one pre-egress AI-powered review case from frozen authority only.

    ``final_review`` is the check request's closing-review choice (issue #976): the final review
    phase runs with or without a completion claim. A recovered check replays the same request,
    so the phase and the case digest are rebuilt identically.

    ``check_time_change`` is the service's own capture of the repository when this check ran
    (ADR-031); ``check_time_change_unavailable`` records that the recipe selected it but the
    service could not capture it, and ``check_time_change_unavailable_reason`` the closed code
    for why, disclosed beside the generic gap. All are ignored when the recipe selects no diff
    excerpts.

    Excerpts may now fill the approved per-excerpt bound, so the case plans its excerpts below
    the channel byte ceiling as measured on the exact prepared document the gateway will size
    (issue #907) when the caller passes ``prepared_byte_ceiling`` (the effective policy's own
    channel ceiling, its ``max_bytes`` and ``max_tokens`` measured the way the gateway measures
    them); without it the caller plans the released payload itself. An over-plan case is rebuilt
    with a smaller
    excerpt budget; the dropped excerpts are ordinary ``not_selected`` omissions with
    ``content_unselected``. The gateway still enforces the owner's ceiling on every dispatch.
    ``workspace_root`` anchors absolute paths when the prior missing-item request's answers are
    matched (issue #907); it is compared in process and never enters the case.

    ``follow_up`` (issue #1047) builds an in-check follow-up packet: the same case with the
    excerpts the reviewer asked for ranked first within ``follow_up_byte_budget``, and an input
    manifest whose ``follow_up_round`` and ``missing_inputs`` say what FinishUP added. Without it the
    case is built exactly as before.
    """

    if prepared_byte_ceiling is not None and (
        type(prepared_byte_ceiling) is not int or prepared_byte_ceiling < 1
    ):
        raise ValueError("semantic_case_prepared_ceiling_invalid")
    planning_bytes = (
        _PREPARED_PAYLOAD_PLANNING_BYTES
        if prepared_byte_ceiling is None
        else max(0, min(MAX_SEMANTIC_CASE_BYTES, prepared_byte_ceiling) - _PLANNING_RESERVE_BYTES)
    )

    def build(excerpt_byte_budget: int | None) -> SemanticCase:
        return _build_semantic_case_once(
            case_id=case_id,
            frozen_case=frozen_case,
            dependency_digest=dependency_digest,
            findings=findings,
            review_context_profile=review_context_profile,
            review_selection=review_selection,
            policy_id=policy_id,
            policy_version=policy_version,
            lineage_evaluation=lineage_evaluation,
            captured_content=captured_content,
            captured_content_scope=captured_content_scope,
            captured_content_gaps=captured_content_gaps,
            excerpt_byte_budget=excerpt_byte_budget,
            workspace_root=workspace_root,
            check_time_change=check_time_change,
            check_time_change_unavailable=check_time_change_unavailable,
            check_time_change_unavailable_reason=check_time_change_unavailable_reason,
            final_review=final_review,
            follow_up=follow_up,
        )

    def fits(candidate: SemanticCase) -> bool | None:
        try:
            prepared = semantic_case_to_prepared_payload(
                candidate, {item.item_id for item in candidate.items}
            )
        except SemanticCaseTooLarge:
            # The structural envelope cannot be bounded at all; the coordinator maps that to
            # its own terminal capacity outcome. Excerpt planning cannot help it.
            return None
        return len(prepared) <= planning_bytes

    case = build(None)
    if prepared_byte_ceiling is None:
        # Without an explicit ceiling the caller plans (issue #907 Phase 1b): the review
        # composition sizes the payload the channel will actually release and rebuilds below it
        # (``service/semantic_ceiling.plan_under_channel_ceiling``), so items the channel withholds
        # never cost eligible excerpts their room. The aggregate case bound is still enforced by
        # the pre-construction cut either way.
        return case
    excerpt_bytes = sum(item.content_bytes for item in case.items if item.section == "excerpt")
    if not excerpt_bytes or fits(case) is not False:
        return case
    # JSON escaping makes the prepared document grow by a content-dependent factor, so search the
    # largest excerpt byte budget whose exact document fits. Admission runs in rank order, so a
    # smaller budget drops the lowest-ranked excerpts first.
    best = build(0)
    low, high = 0, excerpt_bytes
    while high - low > _PLANNING_GRANULARITY_BYTES:
        middle = (low + high) // 2
        candidate = build(middle)
        if fits(candidate):
            low, best = middle, candidate
        else:
            high = middle
    return best


def _build_semantic_case_once(
    *,
    case_id: str,
    frozen_case: DeterministicCase,
    dependency_digest: str,
    findings: Sequence[Finding],
    review_context_profile: ReviewContextProfile,
    review_selection: ReviewSelectionPolicy,
    policy_id: str,
    policy_version: str,
    lineage_evaluation: LineageEvaluation | None,
    captured_content: Sequence[CapturedSemanticContent],
    captured_content_scope: CapturedContentScope | None,
    captured_content_gaps: Sequence[str],
    excerpt_byte_budget: int | None,
    workspace_root: str | None = None,
    check_time_change: CheckTimeChange | None = None,
    check_time_change_unavailable: bool = False,
    check_time_change_unavailable_reason: str | None = None,
    final_review: bool = False,
    follow_up: ReviewFollowUp | None = None,
) -> SemanticCase:
    if type(frozen_case) is not DeterministicCase:
        raise TypeError("deterministic_case_invalid")
    if follow_up is not None and type(follow_up) is not ReviewFollowUp:
        raise TypeError("semantic_case_follow_up_invalid")
    review_phase = select_semantic_budget_profile(frozen_case.projection, final_review=final_review)
    if type(review_context_profile) is not ReviewContextProfile:
        raise TypeError("review_context_profile_invalid")
    if type(review_selection) is not ReviewSelectionPolicy:
        raise TypeError("review_selection_invalid")
    if type(captured_content) not in {tuple, list} or any(
        type(item) is not CapturedSemanticContent for item in captured_content
    ):
        raise TypeError("semantic_case_captured_content_invalid")
    if len(captured_content) > MAX_CAPTURED_SEMANTIC_CONTENT_PARTS:
        raise ValueError("semantic_case_captured_content_over_limit")
    captured_input_bytes = sum(len(item.content) for item in captured_content)
    if captured_input_bytes > MAX_CAPTURED_SEMANTIC_INPUT_BYTES:
        raise ValueError("semantic_case_captured_content_over_limit")
    if (
        captured_content_scope is not None
        and type(captured_content_scope) is not CapturedContentScope
    ):
        raise TypeError("semantic_case_capture_scope_invalid")
    if type(captured_content_gaps) not in {tuple, list} or len(captured_content_gaps) > 16:
        raise TypeError("semantic_case_capture_gaps_invalid")
    capture_gaps = tuple(captured_content_gaps)
    if any(
        type(gap) is not str or _CAPTURE_GAP_PATTERN.fullmatch(gap) is None for gap in capture_gaps
    ) or capture_gaps != tuple(sorted(set(capture_gaps), key=str.encode)):
        raise ValueError("semantic_case_capture_gaps_invalid")
    if captured_content and captured_content_scope is None:
        # Content is an explicitly scoped disclosure. A bare byte sequence cannot enter a case,
        # even when it happens to match a durable evidence digest.
        raise ValueError("semantic_case_capture_scope_required")
    if check_time_change is not None and type(check_time_change) is not CheckTimeChange:
        raise TypeError("semantic_case_check_change_invalid")
    if type(check_time_change_unavailable) is not bool or (
        check_time_change_unavailable and check_time_change is not None
    ):
        raise ValueError("semantic_case_check_change_invalid")
    if check_time_change_unavailable_reason is not None and (
        not check_time_change_unavailable
        or check_time_change_unavailable_reason not in CHECK_TIME_CHANGE_UNAVAILABLE_REASONS
    ):
        raise ValueError("semantic_case_check_change_invalid")
    if review_context_profile is not ReviewContextProfile.CUSTOM:
        expected = ReviewSelectionPolicy.for_profile(review_context_profile)
        if review_selection != expected:
            # Custom overlays may meet() narrower; allow any selection that is a meet of profile.
            meet = expected.meet(review_selection)
            if meet != review_selection:
                raise ValueError("review_selection_profile_mismatch")

    selection = review_selection
    sections = frozenset(selection.sections)
    # The check-time change is diff content: a recipe without diff excerpts never carries it and
    # never reports its absence, exactly as it declines every other excerpt kind.
    check_change_selected = (
        "targeted_excerpts" in sections
        and selection.max_excerpts > 0
        and "diff" in selection.excerpt_kinds
    )
    if not check_change_selected:
        check_time_change = None
        check_time_change_unavailable = False
        check_time_change_unavailable_reason = None
    frontier_refs = frozenset(str(ref) for ref in frozen_case.allowed_ids)
    local_check_refs = frozenset(str(item.finding_id) for item in findings)
    # A recheck re-derives a live recorded finding under its recorded id (issue #186), so the same
    # fnd_ ref is both frozen ledger material and one of this run's findings. It is this check's
    # own finding: the packet names it as assessment.finding_ref and post-validation resolves any
    # cited fnd_ against this run's findings. Own the overlap locally so the two sets stay a
    # partition of `allowed` and the assessment survives the boundary fence (issue #304).
    frontier_refs = frontier_refs - local_check_refs
    allowed = frontier_refs | local_check_refs
    projection = frozen_case.projection

    captured_groups, captured_gaps = _captured_content_groups(
        projection,
        allowed,
        captured_content,
        captured_content_scope,
    )
    capture_gap_set = {*capture_gaps, *captured_gaps}
    if captured_content_scope is not None and "content_unselected" not in capture_gap_set:
        supplied_objects = {item.object_ref.object_id for item in captured_content}
        for record in projection.evidence.values():
            payload = record.payload
            if (
                payload is not None
                and payload.captured_object_id is not None
                and str(payload.captured_object_id) not in supplied_objects
            ):
                capture_gap_set.add("content_capture_unavailable")
    capture_gaps = tuple(sorted(capture_gap_set, key=str.encode))
    captured_group_leader: dict[str, str] = {}
    for leader, group in captured_groups.items():
        for evidence_ref in group.evidence_refs:
            captured_group_leader[evidence_ref] = leader

    items: list[SemanticCaseItem] = []
    # Item ids whose recorded text was admitted by the publish-side prose bound and then could
    # not be carried whole by the case. Folded into the packet coverage below so the omission is
    # an author-visible fact rather than a silent shortening (issue #177).
    over_limit: set[str] = set()
    # Selection-clipped excerpts need their own item-level marker so the input manifest can
    # distinguish an admitted prefix from a complete verification or diff section.
    truncated_item_ids: set[str] = set()
    omissions: list[ReviewOmission] = []
    task_statement_ids: list[str] = []
    task_statement_gaps: set[str] = set()
    goal_ids: list[str] = []
    obligation_ids: list[str] = []
    claim_ids: list[str] = []
    decision_ids: list[str] = []
    timeline_ids: list[str] = []
    targeted: list[TargetedExcerptRef] = []
    changes: list[ChangeObservation] = []

    # --- Task statement (what the user asked for; never the agent's plan) ---
    # Source order: the agent-supplied statement, then the task title. The host-captured prompt
    # is a reserved third source that no path records yet, so captured prompt text never enters
    # this section. Nothing is built unless the approved policy names the section: an approval
    # given before the section existed never covers the user's words (issue #908). A title that
    # stands in carries its own ``task_title_only`` source label, which is the disclosure; the
    # coverage gaps name only a withheld section or a task with neither statement nor title.
    recorded_statement = frozen_case.task_statement
    if TASK_STATEMENT_SECTION not in sections:
        task_statement_gaps.update(
            {TASK_STATEMENT_UNAVAILABLE_GAP, TASK_STATEMENT_NOT_AUTHORIZED_GAP}
        )
    elif recorded_statement is not None:
        statement_ref = str(recorded_statement.source_event_id)
        item, elided = _task_statement_item(
            recorded_statement.text,
            recorded_statement.source,
            source_ref=statement_ref,
            linked_subject_refs=(statement_ref,) if statement_ref in allowed else (),
            occurred_order=recorded_statement.ingestion_sequence,
        )
        items.append(item)
        task_statement_ids.append(item.item_id)
        if elided:
            over_limit.add(item.item_id)
    elif frozen_case.task_title is not None:
        item, elided = _task_statement_item(
            frozen_case.task_title,
            TaskStatementSource.TASK_TITLE_ONLY,
            source_ref="task-title",
            linked_subject_refs=(),
            occurred_order=0,
        )
        items.append(item)
        task_statement_ids.append(item.item_id)
        if elided:
            over_limit.add(item.item_id)
    else:
        task_statement_gaps.update(
            {TASK_STATEMENT_UNAVAILABLE_GAP, TASK_STATEMENT_NOT_SUPPLIED_GAP}
        )

    # --- Agent plan (latest plan summary; the agent's own account, not the user's request) ---
    if projection.plans:
        latest_version = max(projection.plans)
        plan = projection.plans[latest_version]
        plan_ref = str(plan.source_event_id)
        if "goal" in sections and plan.payload is not None and not plan.redacted:
            text, fit = _bounded_json(
                _without_task_statement(cast(Mapping[str, JsonValue], encode_payload(plan.payload)))
            )
            item = _content_item(
                item_id=f"goal-{latest_version}",
                section="goal",
                category=DataCategory.TASK_DESCRIPTION,
                source_kind="task",
                source_ref=plan_ref,
                linked_subject_refs=(plan_ref,) if plan_ref in allowed else (),
                occurred_order=plan.source_frontier,
                text=text,
                over_limit=over_limit,
            )
            items.append(item)
            goal_ids.append(item.item_id)
            if fit != "whole":
                over_limit.add(item.item_id)
            if fit == "replaced":
                omissions.append(
                    _omit(plan_ref, DataCategory.TASK_DESCRIPTION, "task", "not_selected")
                )
        elif "goal" not in sections:
            omissions.append(_omit(plan_ref, DataCategory.TASK_DESCRIPTION, "task", "not_selected"))
        elif plan.redacted:
            omissions.append(
                _omit(plan_ref, DataCategory.TASK_DESCRIPTION, "task", "redacted_never_send")
            )
        else:
            omissions.append(_omit(plan_ref, DataCategory.TASK_DESCRIPTION, "task", "not_recorded"))

    # --- Obligations ---
    disclosures = _obligation_disclosures(projection, allowed)
    for obligation_id, record in sorted(
        projection.obligations.items(), key=lambda pair: str(pair[0])
    ):
        ref = str(obligation_id)
        if ref not in allowed and str(record.source_event_id) not in allowed:
            continue
        source_ref = ref if ref in allowed else str(record.source_event_id)
        if "obligations" not in sections:
            omissions.append(
                _omit(source_ref, DataCategory.OBLIGATION_TEXT, "obligation", "not_selected")
            )
            continue
        payload = record.payload
        if record.redacted or payload is None:
            omissions.append(
                _omit(
                    source_ref,
                    DataCategory.OBLIGATION_TEXT,
                    "obligation",
                    "redacted_never_send" if record.redacted else "not_recorded",
                )
            )
            continue
        assert type(payload) is ObligationPublishedPayload
        linked = tuple(
            sorted(
                {
                    source_ref,
                    *(str(item) for item in payload.source_refs if str(item) in allowed),
                },
                key=str.encode,
            )
        )[:16]
        obligation_json = dict(cast(Mapping[str, JsonValue], encode_payload(payload)))
        disclosed = disclosures.get(ref)
        if disclosed is not None:
            # tb4n3 RC-1: recorded limitation decisions and the acknowledgement state sit beside
            # the obligation they cover, so the reviewer cannot read them as undisclosed.
            # Frozen legacy identifier (ADR-048): packet key; the recorded manifest is re-verified.
            obligation_json["yoetz_already_disclosed"] = cast(JsonValue, disclosed)
        basis = _resolved_criterion_basis(payload, projection, allowed)
        if basis is not None:
            # Issue #1079: the criterion (this item), the claimed result, the latest observed
            # verification and any missing input, as one object. Refs and closed tokens only.
            obligation_json["resolved_basis"] = cast(JsonValue, basis)
        text, fit = _bounded_json(cast(Mapping[str, JsonValue], obligation_json))
        item = _content_item(
            item_id=f"obligation-{ref}",
            section="obligation",
            category=DataCategory.OBLIGATION_TEXT,
            source_kind="obligation",
            source_ref=source_ref,
            linked_subject_refs=linked if linked else (source_ref,),
            occurred_order=record.source_frontier,
            text=text,
            over_limit=over_limit,
        )
        items.append(item)
        obligation_ids.append(item.item_id)
        if fit != "whole":
            over_limit.add(item.item_id)
        if fit == "replaced":
            omissions.append(
                _omit(source_ref, DataCategory.OBLIGATION_TEXT, "obligation", "not_selected")
            )

    # --- Declared deliverables (issue #1045): the delivered set in one row set, first ---
    if "obligations" in sections:
        deliverables = _declared_deliverables_item(
            projection,
            allowed,
            None if check_time_change is None else check_time_change.capture,
            capture_gap_set,
            workspace_root,
            over_limit,
        )
        if deliverables is not None:
            items.append(deliverables)
            # Ahead of every obligation row, so the obligation cap never drops it.
            obligation_ids.insert(0, deliverables.item_id)

    # --- Claims ---
    for claim_id, record in effective_claim_items(projection):
        ref = str(claim_id)
        if ref not in allowed:
            continue
        if "claims" not in sections:
            omissions.append(_omit(ref, DataCategory.CLAIM_TEXT, "claim", "not_selected"))
            continue
        payload = record.payload
        if record.redacted or payload is None:
            omissions.append(
                _omit(
                    ref,
                    DataCategory.CLAIM_TEXT,
                    "claim",
                    "redacted_never_send" if record.redacted else "not_recorded",
                )
            )
            continue
        assert type(payload) in {ClaimRecordedPayload, ClaimRecordedPayloadV1_1}
        text, fit = _bounded_json(cast(Mapping[str, JsonValue], encode_payload(payload)))
        item = _content_item(
            item_id=f"claim-{ref}",
            section="claim",
            category=DataCategory.CLAIM_TEXT,
            source_kind="claim",
            source_ref=ref,
            linked_subject_refs=(ref,),
            occurred_order=record.source_frontier,
            text=text,
            over_limit=over_limit,
        )
        items.append(item)
        claim_ids.append(item.item_id)
        if fit != "whole":
            over_limit.add(item.item_id)
        if fit == "replaced":
            omissions.append(_omit(ref, DataCategory.CLAIM_TEXT, "claim", "not_selected"))

        if "change_observations" in sections and payload.subject_state is not None:
            changes.append(
                ChangeObservation(
                    subject_refs=(ref,),
                    claimed_change=True,
                    subject_state_relation=SubjectStateRelation.UNKNOWN,
                    content_visibility=(
                        "available" if "targeted_excerpts" in sections else "not_selected"
                    ),
                )
            )

    # --- Decisions ---
    # Recorded blockers go first so the decision cap never drops one the closing review must
    # verify (#976, #977).
    blocker_decision_refs = {
        str(item.decision_event_id)
        for item in blocker_declarations(projection, _NO_BATCHES).values()
    }
    for event_id, record in sorted(
        projection.decisions.items(),
        key=lambda pair: (str(pair[0]) not in blocker_decision_refs, str(pair[0])),
    ):
        ref = str(event_id)
        if ref not in allowed:
            continue
        if "decisions" not in sections:
            omissions.append(_omit(ref, DataCategory.DECISION_EXCERPT, "decision", "not_selected"))
            continue
        payload = record.payload
        if record.redacted or payload is None:
            omissions.append(
                _omit(
                    ref,
                    DataCategory.DECISION_EXCERPT,
                    "decision",
                    "redacted_never_send" if record.redacted else "not_recorded",
                )
            )
            continue
        assert type(payload) is DecisionRecordedPayload
        text, fit = _bounded_json(cast(Mapping[str, JsonValue], encode_payload(payload)))
        item = _content_item(
            item_id=f"decision-{ref}",
            section="decision",
            category=DataCategory.DECISION_EXCERPT,
            source_kind="decision",
            source_ref=ref,
            linked_subject_refs=(ref,),
            occurred_order=record.source_frontier,
            text=text,
            over_limit=over_limit,
        )
        items.append(item)
        decision_ids.append(item.item_id)
        if fit != "whole":
            over_limit.add(item.item_id)
        if fit == "replaced":
            omissions.append(_omit(ref, DataCategory.DECISION_EXCERPT, "decision", "not_selected"))

    # --- Frozen accepted-event history ---
    if "timeline" in sections and frozen_case.history_availability == "available":
        detailed_history = bool({"goal", "obligations", "claims", "decisions"} & sections)
        reserve_window_item = bool(frozen_case.history_omitted_before_count)
        history_limit = max(0, selection.max_timeline_items - (1 if reserve_window_item else 0))
        history_rows = frozen_case.history[-history_limit:] if history_limit else ()
        omitted_rows = frozen_case.history[: len(frozen_case.history) - len(history_rows)]
        for history_item in omitted_rows:
            source_kind, category = _HISTORY_KIND[history_item.schema_name]
            omissions.append(
                _omit(str(history_item.event_id), category, source_kind, "not_selected")
            )
        if reserve_window_item and selection.max_timeline_items:
            first_sequence = history_rows[0].ingestion_sequence if history_rows else 1
            item = _content_item(
                item_id="history-window",
                section="timeline",
                category=DataCategory.BOUNDED_STRUCTURAL_METADATA,
                source_kind="task",
                source_ref="history-window",
                linked_subject_refs=(),
                occurred_order=max(0, first_sequence - 1),
                text=_structural_json(
                    {
                        "kind": "history_window",
                        "omitted_before_count": frozen_case.history_omitted_before_count,
                        "reason": "not_selected",
                    }
                ),
                over_limit=over_limit,
            )
            items.append(item)
            timeline_ids.append(item.item_id)
        for history_item in history_rows:
            source_kind, content_category = _HISTORY_KIND[history_item.schema_name]
            include_content = detailed_history and history_item.content_visibility == "available"
            category = (
                content_category if include_content else DataCategory.BOUNDED_STRUCTURAL_METADATA
            )
            text, fit = _history_json(
                history_item,
                include_content=include_content,
                include_exact_command_text=selection.include_exact_command_text,
            )
            event_ref = str(history_item.event_id)
            item = _content_item(
                item_id=f"history-{event_ref}",
                section="timeline",
                category=category,
                source_kind=source_kind,
                source_ref=event_ref,
                linked_subject_refs=(event_ref,) if event_ref in allowed else (),
                occurred_order=history_item.ingestion_sequence,
                text=text,
                over_limit=over_limit,
            )
            items.append(item)
            timeline_ids.append(item.item_id)
            if history_item.content_visibility != "available":
                omissions.append(
                    _omit(
                        event_ref,
                        content_category,
                        source_kind,
                        history_item.content_visibility,
                    )
                )
            else:
                if fit != "whole":
                    over_limit.add(item.item_id)
                if not detailed_history or fit == "replaced":
                    omissions.append(
                        _omit(event_ref, content_category, source_kind, "not_selected")
                    )

    if (
        "timeline" in sections
        and frozen_case.history_availability == "not_recorded"
        and projection.plans
    ):
        latest_plan = projection.plans[max(projection.plans)]
        omissions.append(
            _omit(
                str(latest_plan.source_event_id),
                DataCategory.BOUNDED_STRUCTURAL_METADATA,
                "task",
                "not_recorded",
            )
        )

    # --- Projection fallback timeline for legacy/synthetic frozen cases ---
    if "timeline" in sections and frozen_case.history_availability == "not_recorded":
        timeline_candidates: list[tuple[int, str, _SourceKind, str, Mapping[str, JsonValue]]] = []
        for obligation_id, record in projection.obligations.items():
            timeline_candidates.append(
                (
                    record.source_frontier,
                    str(record.source_event_id),
                    "obligation",
                    str(obligation_id)
                    if str(obligation_id) in allowed
                    else str(record.source_event_id),
                    {
                        "kind": "obligation_published",
                        "obligation_id": str(obligation_id),
                        "source_event_id": str(record.source_event_id),
                        "status": (
                            record.payload.status.value
                            if record.payload is not None
                            else "unavailable"
                        ),
                    },
                )
            )
        for claim_id, record in projection.claims.items():
            timeline_candidates.append(
                (
                    record.source_frontier,
                    str(record.source_event_id),
                    "claim",
                    str(claim_id),
                    {
                        "kind": "claim_recorded",
                        "claim_id": str(claim_id),
                        "source_event_id": str(record.source_event_id),
                        "claim_kind": (
                            record.payload.claim_kind.value
                            if record.payload is not None
                            else "unavailable"
                        ),
                    },
                )
            )
        for action_id, record in projection.actions.items():
            timeline_candidates.append(
                (
                    record.source_frontier,
                    str(record.source_event_id),
                    "action",
                    str(action_id) if str(action_id) in allowed else str(record.source_event_id),
                    {
                        "kind": "action_recorded",
                        "action_id": str(action_id),
                        "source_event_id": str(record.source_event_id),
                        "action_kind": (
                            record.payload.action_kind.value
                            if record.payload is not None
                            else "unavailable"
                        ),
                    },
                )
            )
        for result_id, record in projection.results.items():
            timeline_candidates.append(
                (
                    record.source_frontier,
                    str(record.source_event_id),
                    "result",
                    str(result_id) if str(result_id) in allowed else str(record.source_event_id),
                    {
                        "kind": "result_recorded",
                        "result_id": str(result_id),
                        "source_event_id": str(record.source_event_id),
                        "outcome": (
                            record.payload.outcome.value
                            if record.payload is not None
                            else "unavailable"
                        ),
                    },
                )
            )
        for evidence_id, record in projection.evidence.items():
            timeline_candidates.append(
                (
                    record.source_frontier,
                    str(record.source_event_id),
                    "evidence",
                    str(evidence_id)
                    if str(evidence_id) in allowed
                    else str(record.source_event_id),
                    {
                        "kind": "evidence_recorded",
                        "evidence_id": str(evidence_id),
                        "source_event_id": str(record.source_event_id),
                        "evidence_kind": (
                            record.payload.evidence_kind.value
                            if record.payload is not None
                            else "unavailable"
                        ),
                    },
                )
            )
        for event_id, record in projection.decisions.items():
            timeline_candidates.append(
                (
                    record.source_frontier,
                    str(record.source_event_id),
                    "decision",
                    str(event_id),
                    {
                        "kind": "decision_recorded",
                        "source_event_id": str(event_id),
                    },
                )
            )
        # Always record the frozen frontier as a structural anchor.
        timeline_candidates.append(
            (
                frozen_case.frontier.sequence,
                f"frontier-{frozen_case.frontier.sequence}",
                "task",
                f"frontier-{frozen_case.frontier.sequence}",
                {
                    "kind": "frontier",
                    "sequence": frozen_case.frontier.sequence,
                    "head_digest": frozen_case.frontier.head_digest,
                    "dependency_digest": dependency_digest,
                },
            )
        )
        timeline_candidates.sort(
            key=lambda row: (row[0], row[1].encode("ascii"), row[3].encode("ascii"))
        )
        # item_id is timeline-{source_ref}; duplicate source_ref would invalidate the case.
        seen_timeline_refs: set[str] = set()
        deduped_timeline: list[tuple[int, str, _SourceKind, str, Mapping[str, JsonValue]]] = []
        for row in timeline_candidates:
            source_ref = row[3]
            if source_ref in seen_timeline_refs:
                continue
            seen_timeline_refs.add(source_ref)
            deduped_timeline.append(row)
        for order, _event, source_kind, source_ref, body in deduped_timeline[
            : selection.max_timeline_items
        ]:
            linked = (source_ref,) if source_ref in allowed else ()
            item = _content_item(
                item_id=f"timeline-{source_ref}",
                section="timeline",
                category=DataCategory.BOUNDED_STRUCTURAL_METADATA,
                source_kind=source_kind,
                source_ref=source_ref,
                linked_subject_refs=linked,
                occurred_order=order,
                text=_structural_json(body),
                over_limit=over_limit,
            )
            items.append(item)
            timeline_ids.append(item.item_id)

    # --- The prior review's missing-item request and what was recorded since (issue #907) ---
    prior_missing_item: SemanticCaseItem | None = None
    missing_answers: tuple[tuple[str, ...], ...] = ()
    pending_missing = projection.pending_missing_for_assessment
    answered_since: tuple[tuple[str, ...], ...] = ()
    if pending_missing is not None:
        answered_since = supplied_since(
            projection,
            pending_missing,
            frozenset(allowed),
            frozenset(str(item) for item in frozen_case.observation_event_ids),
            _edit_paths_by_ref(captured_groups),
            workspace_root,
        )
    supplied_answer_refs = frozenset(ref for group in answered_since for ref in group)
    if pending_missing is not None and "timeline" in sections and selection.max_timeline_items:
        answered = answered_since
        missing_answers = answered
        check_ref = str(pending_missing.source_check_event_id)
        prior_missing_item = _content_item(
            item_id="prior-missing-for-assessment",
            section="timeline",
            category=DataCategory.BOUNDED_STRUCTURAL_METADATA,
            source_kind="finding",
            source_ref=check_ref,
            linked_subject_refs=(check_ref,) if check_ref in allowed else (),
            occurred_order=pending_missing.source_frontier,
            text=_structural_json(
                {
                    "items": [
                        {
                            "availability": item.availability,
                            "kind": item.kind,
                            "supplied_since": list(supplied),
                            "target_refs": [ref for ref in item.target_refs if ref in allowed],
                        }
                        for item, supplied in zip(pending_missing.items, answered, strict=True)
                    ],
                    "kind": "prior_missing_for_assessment",
                    "source_check_event_id": check_ref,
                }
            ),
            over_limit=over_limit,
            limit=MAX_SEMANTIC_ITEM_BYTES,
        )
        items.append(prior_missing_item)

    # --- Local assessments + optional finding prose ---
    review_assessments: list[ReviewAssessment] = []
    finding_refs_over_limit = False
    if "deterministic_assessments" in sections:
        matched = _match_assessments(frozen_case, findings)
        for finding, assessment in matched[: selection.max_assessments]:
            summary_id: str | None = None
            detail_id: str | None = None
            if selection.include_finding_prose:
                finding_ref = str(finding.finding_id)
                linked = tuple(str(ref) for ref in finding.subject_refs)
                # Prose requires exact-match allowlist on every subject_ref; otherwise keep the
                # local assessment without summary/detail content items.
                if linked and len(linked) > MAX_SEMANTIC_ITEM_SUBJECT_REFS:
                    # A finding may cite up to 64 subjects; one case item links at most 16. The
                    # complete tuple used to reach SemanticCaseItem and fail its bound, which
                    # surfaced as coordinator_failure with no review at all (issue #858). Slicing
                    # the tuple would present a partial subject list as the finding's own, so the
                    # prose is omitted whole and named: the finding keeps its identity in
                    # local_check_refs and the check result, the omission says which category was
                    # withheld, and coverage carries the capacity reason. The projected
                    # assessment below skips itself for the same width with its own omission.
                    omissions.append(
                        _omit(finding_ref, DataCategory.FINDING_SUMMARY, "finding", "not_selected")
                    )
                    finding_refs_over_limit = True
                elif linked and set(linked) <= allowed:
                    summary_id = f"finding-summary-{finding_ref}"
                    detail_id = f"finding-detail-{finding_ref}"
                    items.append(
                        _content_item(
                            item_id=summary_id,
                            section="deterministic_summary",
                            category=DataCategory.FINDING_SUMMARY,
                            source_kind="finding",
                            source_ref=finding_ref,
                            linked_subject_refs=linked,
                            occurred_order=finding.subject_frontier.sequence,
                            text=finding.summary,
                            over_limit=over_limit,
                        )
                    )
                    items.append(
                        _content_item(
                            item_id=detail_id,
                            section="deterministic_detail",
                            category=DataCategory.FINDING_SUMMARY,
                            source_kind="finding",
                            source_ref=finding_ref,
                            linked_subject_refs=linked,
                            occurred_order=finding.subject_frontier.sequence,
                            text=finding.detail,
                            over_limit=over_limit,
                        )
                    )
            projected = project_review_assessment(
                assessment,
                str(finding.finding_id),
                summary_item_id=summary_id,
                detail_item_id=detail_id,
            )
            if type(projected) is ReviewAssessment:
                review_assessments.append(projected)
            elif type(projected) is ReviewAssessmentSkipped:
                omissions.append(projected.omission)

    # --- Targeted excerpts (recorded text only; never fetch objects) ---
    excerpt_bytes_used = 0
    # One excerpt byte budget for every excerpt: the recipe total, narrowed by in-builder
    # planning below an explicit ceiling (#907). The check-time change shares it (ADR-031).
    total_excerpt_budget = (
        selection.max_total_excerpt_bytes
        if excerpt_byte_budget is None
        else min(selection.max_total_excerpt_bytes, excerpt_byte_budget)
    )
    check_change_parts: tuple[str, ...] = ()
    # Where each part's change bytes start in the stored change text (tb4n5, #1047 follow-up).
    check_change_offsets: tuple[int, ...] = ()
    # ``(item_id, excerpt_span_key)`` of every excerpt placed in its source text.
    excerpt_part_keys: list[tuple[str, str]] = []
    check_change_links: tuple[str, ...] = ()
    check_change_admitted = 0
    check_change_cut = False
    if check_time_change_unavailable:
        capture_gap_set.add(CHECK_TIME_CHANGE_UNAVAILABLE_GAP)
        if check_time_change_unavailable_reason is not None:
            capture_gap_set.add(
                check_time_change_unavailable_reason_gap(check_time_change_unavailable_reason)
            )
    if check_time_change is not None:
        change = check_time_change.capture
        if change.base in {"head", "first_check"}:
            # Not the task-start commit: work committed before the base is not in the change.
            capture_gap_set.add(CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP)
        if change.truncated:
            capture_gap_set.add(CHECK_TIME_CHANGE_TRUNCATED_GAP)
        if change.redacted:
            capture_gap_set.add(CHECK_TIME_CHANGE_REDACTED_GAP)
        check_change_links = _check_time_change_links(projection, allowed)
        if check_change_links:
            check_change_parts, check_change_offsets = _check_time_change_offer(
                change.text, selection
            )
    # Read-only task input files (issue #1045), linked to the statement that names them.
    task_inputs: tuple[tuple[str, bool], ...] = ()
    task_input_links: tuple[str, ...] = ()
    task_inputs_admitted = 0
    if check_time_change is not None and carries_task_inputs(selection):
        statement_links: set[str] = (
            {str(recorded_statement.source_event_id)} & allowed
            if recorded_statement is not None
            else set()
        )
        task_input_links = tuple(sorted({*statement_links, *check_change_links}, key=str.encode))[
            :MAX_SEMANTIC_ITEM_SUBJECT_REFS
        ]
        if task_input_links:
            task_inputs = tuple(
                (
                    _TASK_INPUT_LABEL.format(
                        path=_marker_path(item.path),
                        size=item.size,
                        cut="" if len(item.text) >= item.size else ", head and tail shown",
                    )
                    + _neutralised_agent_text(item.text.decode("utf-8")),
                    len(item.text) < item.size,
                )
                for item in check_time_change.capture.inputs
            )

    def task_input_excerpts(
        slot_limit: int, byte_limit: int
    ) -> tuple[tuple[SemanticCaseItem, ...], tuple[TargetedExcerptRef, ...]]:
        """The next task input files that fit, one excerpt each (issue #1045)."""

        nonlocal task_inputs_admitted
        admitted_items: list[SemanticCaseItem] = []
        admitted_refs: list[TargetedExcerptRef] = []
        bytes_used = 0
        limit = min(selection.max_excerpt_bytes, MAX_SEMANTIC_ITEM_BYTES)
        while task_inputs_admitted < len(task_inputs) and len(admitted_refs) < slot_limit:
            text, cut = task_inputs[task_inputs_admitted]
            size = min(len(text.encode("utf-8")), limit)
            if bytes_used + size > byte_limit:
                break
            item = _content_item(
                item_id=f"{TASK_INPUT_ITEM_PREFIX}{task_inputs_admitted + 1:02d}",
                section="excerpt",
                category=DataCategory.REPOSITORY_EXCERPT,
                source_kind="repository",
                source_ref=_TASK_INPUT_SOURCE_REF,
                linked_subject_refs=task_input_links,
                occurred_order=0,
                text=text,
                limit=limit,
            )
            if cut or len(text.encode("utf-8")) > limit:
                truncated_item_ids.add(item.item_id)
            admitted_items.append(item)
            admitted_refs.append(
                TargetedExcerptRef(
                    excerpt_item_id=item.item_id,
                    source_kind="repository",
                    linked_subject_refs=task_input_links,
                    subject_state_relation=SubjectStateRelation.UNKNOWN,
                    content_visibility="available",
                    content_digest=item.content_digest,
                    content_bytes=item.content_bytes,
                )
            )
            bytes_used += item.content_bytes
            task_inputs_admitted += 1
        return tuple(admitted_items), tuple(admitted_refs)

    def lower_rank_room(
        slot_limit: int, byte_limit: int
    ) -> tuple[tuple[SemanticCaseItem, ...], tuple[TargetedExcerptRef, ...]]:
        """Room the reserved excerpt classes leave: task inputs (within their share), then the
        change's remaining parts, all ahead of older edits and general output (#983, #1045)."""

        input_items, input_refs = task_input_excerpts(
            min(slot_limit, MAX_TASK_INPUT_FILES),
            min(byte_limit, selection.max_total_excerpt_bytes // _TASK_INPUT_SHARE_DIVISOR),
        )
        used = sum(ref.content_bytes for ref in input_refs)
        if not check_change_parts:
            return input_items, input_refs
        change_items, change_refs = check_time_change_parts(
            max(0, slot_limit - len(input_refs)), max(0, byte_limit - used)
        )
        return (*input_items, *change_items), (*input_refs, *change_refs)

    def check_time_change_parts(
        slot_limit: int, byte_limit: int
    ) -> tuple[tuple[SemanticCaseItem, ...], tuple[TargetedExcerptRef, ...]]:
        """The next check-time change parts within one share of the room (ADR-031, #983)."""

        nonlocal check_change_admitted, check_change_cut
        admitted_items: list[SemanticCaseItem] = []
        admitted_refs: list[TargetedExcerptRef] = []
        bytes_used = 0
        part_limit = _check_time_change_part_limit(selection)
        while (
            not check_change_cut
            and check_change_admitted < len(check_change_parts)
            and len(admitted_refs) < slot_limit
        ):
            part = check_change_parts[check_change_admitted]
            size = len(part.encode("utf-8"))
            if bytes_used + size > byte_limit:
                if check_change_admitted:
                    break
                # A narrowed case (its excerpt budget planned below the channel ceiling) can leave
                # less room than one whole part. The change under review still outranks every
                # recorded excerpt, so its first part is cut to the room instead of yielding it
                # to them (issue #983); nothing follows a cut part.
                cut = _check_time_change_cut_part(
                    part, 1, len(check_change_parts), byte_limit - bytes_used
                )
                if cut is None:
                    break
                part, check_change_cut = cut
            item = _content_item(
                item_id=f"{CHECK_TIME_CHANGE_ITEM_PREFIX}{check_change_admitted + 1:03d}",
                section="excerpt",
                # The service read this from the repository itself: it leaves only where the
                # channel allows repository excerpts, never as recorded evidence.
                category=DataCategory.REPOSITORY_EXCERPT,
                source_kind="diff",
                source_ref=_CHECK_TIME_CHANGE_SOURCE_REF,
                linked_subject_refs=check_change_links,
                # Ordered ahead of every recorded excerpt: it is the change under review.
                occurred_order=0,
                text=part,
                over_limit=over_limit,
                limit=part_limit,
            )
            admitted_items.append(item)
            admitted_refs.append(
                TargetedExcerptRef(
                    excerpt_item_id=item.item_id,
                    source_kind="diff",
                    linked_subject_refs=check_change_links,
                    subject_state_relation=SubjectStateRelation.UNKNOWN,
                    content_visibility="available",
                    content_digest=item.content_digest,
                    content_bytes=item.content_bytes,
                )
            )
            bytes_used += item.content_bytes
            assert check_time_change is not None
            chunk_bytes = _check_time_change_part_chunk_bytes(item.content)
            if chunk_bytes and check_change_admitted < len(check_change_offsets):
                part_start = check_change_offsets[check_change_admitted]
                excerpt_part_keys.append(
                    (
                        item.item_id,
                        excerpt_span_key(
                            _CHECK_TIME_CHANGE_SOURCE_REF,
                            part_start,
                            part_start + chunk_bytes,
                            len(check_time_change.capture.text),
                        ),
                    )
                )
            check_change_admitted += 1
        return tuple(admitted_items), tuple(admitted_refs)

    def admit_check_time_change(slot_limit: int, byte_limit: int) -> None:
        """Admit the next parts within one share and what the whole budget still has free."""

        nonlocal excerpt_bytes_used
        admitted_items, admitted_refs = check_time_change_parts(
            min(slot_limit, max(0, selection.max_excerpts - len(targeted))),
            min(byte_limit, max(0, total_excerpt_budget - excerpt_bytes_used)),
        )
        items.extend(admitted_items)
        targeted.extend(admitted_refs)
        excerpt_bytes_used += sum(ref.content_bytes for ref in admitted_refs)

    if "targeted_excerpts" in sections and selection.max_excerpts > 0:
        # The service-captured change takes its reserved share first; see
        # ``_check_time_change_reservation`` for how the rest of the budget is shared.
        admit_check_time_change(
            *_check_time_change_reservation(
                selection,
                len(check_change_parts[0].encode("utf-8")) if check_change_parts else 0,
            )
        )
        # Recorded excerpts then fill what the change left, most valuable first (#907). The
        # change's remaining parts take the room the reserved classes leave, ahead of older edit
        # hunks and general output (#983), so a planned case narrows those first.
        excerpts = _select_targeted_excerpts(
            projection=projection,
            allowed=allowed,
            selection=selection,
            findings=findings,
            review_assessments=review_assessments,
            captured_groups=captured_groups,
            captured_group_leader=captured_group_leader,
            excerpt_count_budget=selection.max_excerpts - len(targeted),
            excerpt_byte_budget=(max(0, total_excerpt_budget - excerpt_bytes_used)),
            before_lower_ranks=lower_rank_room if check_change_parts or task_inputs else None,
            declared_output_refs=declared_output_capture_order(projection, allowed, workspace_root),
            # A suffix-less binary the change marked (a compiled ``solver``) gets the same
            # "not sent" notice as a named binary type (tb4n2 P1-12).
            binary_paths=check_change_binary_paths(
                None if check_time_change is None else check_time_change.capture
            ),
            text_paths=check_change_text_paths(
                None if check_time_change is None else check_time_change.capture
            ),
            workspace_root=workspace_root,
            follow_up=follow_up,
            supplied_refs=supplied_answer_refs,
            # A follow-up may answer from the frozen change, only when this recipe carries it.
            check_time_change=(
                check_time_change.capture
                if check_time_change is not None and check_change_parts
                else None
            ),
        )
        items.extend(excerpts.items)
        excerpt_part_keys.extend(excerpts.part_keys)
        targeted.extend(excerpts.targeted)
        omissions.extend(excerpts.omissions)
        capture_gap_set.update(excerpts.gaps)
        over_limit.update(excerpts.over_limit)
        truncated_item_ids.update(excerpts.truncated_item_ids)
        excerpt_bytes_used += sum(ref.content_bytes for ref in excerpts.targeted)

        # Parts still left backfill whatever budget every other excerpt left, then task inputs
        # the first offer's share left out (issue #1045).
        admit_check_time_change(selection.max_excerpts, selection.max_total_excerpt_bytes)
        input_items, input_refs = task_input_excerpts(
            max(0, selection.max_excerpts - len(targeted)),
            max(0, total_excerpt_budget - excerpt_bytes_used),
        )
        items.extend(input_items)
        targeted.extend(input_refs)
        excerpt_bytes_used += sum(ref.content_bytes for ref in input_refs)

    if check_time_change is not None:
        if not check_change_admitted:
            # Captured, but nothing reached the packet: no linkable subject, or a recipe budget
            # too small for one readable part.
            capture_gap_set.add(CHECK_TIME_CHANGE_UNAVAILABLE_GAP)
            capture_gap_set.add(
                check_time_change_unavailable_reason_gap(
                    "no_linked_subject" if not check_change_links else "no_packet_room"
                )
            )
        elif check_change_admitted < len(check_change_parts) or check_change_cut:
            capture_gap_set.add(CHECK_TIME_CHANGE_TRUNCATED_GAP)
            truncated_item_ids.update(
                ref.excerpt_item_id
                for ref in targeted
                if ref.excerpt_item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
            )

    lineage_items: tuple[SemanticCaseItem, ...] = ()
    if lineage_evaluation is not None:
        # Lineage is an independent C9 channel.  Keep every part in the provider packet even
        # when the review selection caps ordinary timeline rows; it is structural authority for
        # this parent check, not child prose selected by the review profile.
        lineage_items = _lineage_semantic_items(lineage_evaluation)
        items.extend(lineage_items)

    # Cap lists per selection.  Reserve one timeline slot per lineage part.  Dropped ordinary
    # timeline items are removed below with the rest of the post-cap catalog so SemanticCase's
    # referenced-item invariant remains exact.
    # A valid capture can exist even when a custom policy disables the excerpt section entirely or
    # sets its excerpt count to zero. Keep that policy exclusion visible just as we do for a group
    # rejected by kind/relevance, while retaining only bounded identity metadata in the omission.
    if captured_groups and ("targeted_excerpts" not in sections or selection.max_excerpts == 0):
        capture_gap_set.add("content_unselected")
        for ref, captured_group in sorted(
            captured_groups.items(), key=lambda pair: pair[0].encode("ascii")
        ):
            omissions.append(
                _omit(
                    ref,
                    DataCategory.EVIDENCE_EXCERPT,
                    captured_group.source_kind,
                    "not_selected",
                )
            )

    # Cap lists per selection.
    task_statement_ids = task_statement_ids[:1]
    goal_ids = goal_ids[:4]
    obligation_ids = obligation_ids[:32]
    claim_ids = claim_ids[:32]
    decision_ids = decision_ids[:16]
    timeline_ids = timeline_ids[: selection.max_timeline_items]
    if lineage_items:
        timeline_ids = timeline_ids[: max(0, selection.max_timeline_items - len(lineage_items))]
        timeline_ids.extend(item.item_id for item in lineage_items)
    if prior_missing_item is not None:
        # The prior request holds its own timeline slot: without it the reviewer cannot tell a
        # supplied item from one still missing, which is the loop issue #907 closes.
        timeline_ids = [
            item_id for item_id in timeline_ids if item_id != prior_missing_item.item_id
        ]
        if len(timeline_ids) >= selection.max_timeline_items:
            ordinary = [
                item_id
                for item_id in timeline_ids
                if item_id not in {item.item_id for item in lineage_items}
            ]
            if ordinary:
                timeline_ids.remove(ordinary[-1])
        if len(timeline_ids) < selection.max_timeline_items:
            timeline_ids.append(prior_missing_item.item_id)
    review_assessments = review_assessments[: selection.max_assessments]
    changes = changes[: selection.max_change_observations]
    targeted = targeted[: selection.max_excerpts]
    excerpts_cut_for_case_bound = _fit_excerpts_within_case_bound(
        items,
        targeted,
        omissions,
        capture_gap_set,
        fixed_item_ids={
            *task_statement_ids,
            *goal_ids,
            *obligation_ids,
            *claim_ids,
            *decision_ids,
            *timeline_ids,
            *(
                item_id
                for assessment in review_assessments
                if assessment.summary_item_id is not None and assessment.detail_item_id is not None
                for item_id in (assessment.summary_item_id, assessment.detail_item_id)
            ),
        },
    )

    if check_change_admitted:
        # The case-bound cut drops the lowest-ranked excerpts, which can include check-time change
        # parts that only backfilled free room. The binding and the shown-file record must name
        # the parts the case still carries, and the cut is disclosed like any other (ADR-031).
        carried_parts = sum(
            excerpt.excerpt_item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
            for excerpt in targeted
        )
        if carried_parts < check_change_admitted:
            check_change_admitted = carried_parts
            if carried_parts:
                capture_gap_set.add(CHECK_TIME_CHANGE_TRUNCATED_GAP)
            else:
                capture_gap_set.add(CHECK_TIME_CHANGE_UNAVAILABLE_GAP)
                capture_gap_set.add(check_time_change_unavailable_reason_gap("no_packet_room"))

    kind_order = {
        kind: ordinal
        for ordinal, kind in enumerate(
            (
                FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
                FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
                FindingKind.FAILED_WORK_OMITTED,
                FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
                FindingKind.RESULT_WITHOUT_ACTION,
                FindingKind.ACTION_WITHOUT_RESULT,
                FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
                FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED,
                FindingKind.LEDGER_STALE_OR_INCOMPLETE,
                FindingKind.WEAK_OR_STALE_RESPONSE,
                FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
                FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
                FindingKind.MATERIAL_LIMITATION_OMITTED,
                FindingKind.QUESTIONABLE_FINDING_REJECTION,
            )
        )
    }
    review_assessments.sort(
        key=lambda item: (
            # The finding registry is extensible by coordination lanes.  Keep the historical
            # review order for the core kinds, while placing a newly registered kind after that
            # stable prefix instead of raising a KeyError during semantic case construction.
            kind_order.get(item.finding_kind, len(kind_order)),
            tuple(ref.encode("ascii") for ref in item.subject_refs),
        )
    )
    changes.sort(key=lambda item: tuple(ref.encode("ascii") for ref in item.subject_refs))
    # Every distinct omission, before the listed rows are capped: the manifest reports this true
    # total beside the capped listed count, which otherwise saturates (issue #976, tb4n1 D11).
    omission_universe = set(omissions)
    omissions = sorted(
        omission_universe,
        key=lambda item: (
            item.subject_ref.encode("ascii"),
            item.category.value.encode("ascii"),
            item.reason.encode("ascii"),
        ),
    )[: selection.max_omissions]

    # Keep only items that remain referenced after caps.
    keep_ids = (
        set(task_statement_ids)
        | set(goal_ids)
        | set(obligation_ids)
        | set(claim_ids)
        | set(decision_ids)
        | set(timeline_ids)
    )
    for assessment in review_assessments:
        if assessment.summary_item_id is not None and assessment.detail_item_id is not None:
            keep_ids.add(assessment.summary_item_id)
            keep_ids.add(assessment.detail_item_id)
    for excerpt in targeted:
        keep_ids.add(excerpt.excerpt_item_id)

    items = [item for item in items if item.item_id in keep_ids]

    # --- Earlier AI-powered findings and the main agent's answers (issue #905) ---
    # The reviewer has no memory between checks; this ledger-backed section is the channel. It
    # rides the findings selection (never a new disclosure category): structural rows always,
    # prose only where the profile already sends finding prose. Its own bounds keep it out of the
    # 64-row timeline, and it takes only capacity the case bounds leave.
    prior_finding_ids: list[str] = []
    prior_finding_refs: list[str] = []
    # A selection without the assessments section shows the reviewer no earlier finding at all;
    # when any is open, that is the same disclosed truncation as a full section.
    prior_findings_truncated = "deterministic_assessments" not in sections and bool(
        _prior_finding_candidates(projection, allowed)
    )
    if "deterministic_assessments" in sections:
        prior_items, prior_omissions, prior_findings_truncated = _prior_findings_section(
            projection,
            allowed,
            include_prose=selection.include_finding_prose,
            remaining_items=MAX_SEMANTIC_CASE_ITEMS - len(items),
            remaining_bytes=MAX_SEMANTIC_CASE_BYTES - sum(item.content_bytes for item in items),
        )
        items.extend(prior_items)
        prior_finding_ids = [item.item_id for item in prior_items]
        # One rulable entry per carried finding (its structural row), never one per prose row.
        prior_finding_refs = [
            item.source_ref
            for item in prior_items
            if item.item_id == f"prior-finding-{item.source_ref}"
        ]
        if prior_omissions:
            omission_universe.update(prior_omissions)
            omissions = sorted(
                set([*omissions, *prior_omissions]),
                key=lambda item: (
                    item.subject_ref.encode("ascii"),
                    item.category.value.encode("ascii"),
                    item.reason.encode("ascii"),
                ),
            )[: selection.max_omissions]

    # Sort items per SemanticCase order.
    _SECTION_ORDINAL = {
        TASK_STATEMENT_SECTION: -1,
        "goal": 0,
        "obligation": 1,
        "claim": 2,
        "decision": 3,
        "prior_finding": 4,
        "timeline": 5,
        "deterministic_summary": 6,
        "deterministic_detail": 7,
        "excerpt": 8,
    }
    items.sort(
        key=lambda item: (
            _SECTION_ORDINAL[item.section],
            item.occurred_order,
            item.source_ref.encode("ascii"),
            item.item_id.encode("ascii"),
        )
    )

    if not items:
        # Empty frozen case: still emit a frontier structural item so the case is valid.
        body = {
            "kind": "frontier",
            "sequence": frozen_case.frontier.sequence,
            "head_digest": frozen_case.frontier.head_digest,
            "dependency_digest": dependency_digest,
        }
        item = _content_item(
            item_id="timeline-frontier",
            section="timeline",
            category=DataCategory.BOUNDED_STRUCTURAL_METADATA,
            source_kind="task",
            source_ref=f"frontier-{frozen_case.frontier.sequence}",
            linked_subject_refs=(),
            occurred_order=frozen_case.frontier.sequence,
            text=_structural_json(body),
            over_limit=over_limit,
        )
        items = [item]
        timeline_ids = [item.item_id]

    if lineage_items and sum(item.content_bytes for item in items) > MAX_SEMANTIC_CASE_BYTES:
        # Every lineage part may fit individually while their sum, or their sum with
        # selected parent content, exceeds SemanticCase's independent aggregate bound.
        # Refuse with the same typed pre-dispatch outcome instead of leaking the
        # constructor's generic semantic_case_invalid ValueError to the coordinator.
        raise LineageSemanticCapacityExceeded("lineage_semantic_case_too_large")
    if sum(item.content_bytes for item in items) > MAX_SEMANTIC_CASE_BYTES:
        # Excerpts were already cut to fit, so what remains over the bound is fixed material.
        raise SemanticCaseCapacityExceeded("semantic_case_too_large")

    capture_gaps = tuple(sorted(capture_gap_set, key=str.encode))
    coverage = case_coverage(frozen_case, semantic=True)
    if task_statement_gaps:
        # The reviewer is told, in the packet it reads, that it has no statement of the user's
        # request (or only the title) and why. The check result carries the same codes.
        coverage = replace(
            coverage,
            ledger_freshness=(
                LedgerFreshness.PARTIAL
                if coverage.ledger_freshness is LedgerFreshness.CURRENT
                else coverage.ledger_freshness
            ),
            known_gaps=tuple(sorted({*coverage.known_gaps, *task_statement_gaps}, key=str.encode)),
        )
    if capture_gaps:
        coverage = replace(
            coverage,
            ledger_freshness=(
                LedgerFreshness.PARTIAL
                if coverage.ledger_freshness is LedgerFreshness.CURRENT
                else coverage.ledger_freshness
            ),
            known_gaps=tuple(sorted({*coverage.known_gaps, *capture_gaps}, key=str.encode)),
        )
    # Count only overflow on items the caps kept: an item dropped downstream is already disclosed
    # as an omission, and naming it here would report a shortening the reviewer never saw.
    if over_limit & {item.item_id for item in items}:
        coverage = replace(
            coverage,
            ledger_freshness=(
                LedgerFreshness.PARTIAL
                if coverage.ledger_freshness is LedgerFreshness.CURRENT
                else coverage.ledger_freshness
            ),
            known_gaps=tuple(
                sorted(
                    {*coverage.known_gaps, SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP},
                    key=str.encode,
                )
            ),
        )
    if finding_refs_over_limit:
        # The finding is still a local check result the reviewer can cite; only its prose and
        # projected basis are absent from this case. Coverage says so, as with shortened prose.
        coverage = replace(
            coverage,
            ledger_freshness=(
                LedgerFreshness.PARTIAL
                if coverage.ledger_freshness is LedgerFreshness.CURRENT
                else coverage.ledger_freshness
            ),
            known_gaps=tuple(
                sorted(
                    {*coverage.known_gaps, SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP},
                    key=str.encode,
                )
            ),
        )
    if prior_findings_truncated:
        # Earlier findings the section could not carry are named as omissions above; coverage
        # says the reviewer saw only part of the dialogue.
        coverage = replace(
            coverage,
            ledger_freshness=(
                LedgerFreshness.PARTIAL
                if coverage.ledger_freshness is LedgerFreshness.CURRENT
                else coverage.ledger_freshness
            ),
            known_gaps=tuple(
                sorted(
                    {*coverage.known_gaps, SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP},
                    key=str.encode,
                )
            ),
        )
    # The excerpts the case still carries, each placed in its source (in process only).
    carried_item_ids = {item.item_id for item in items}
    excerpt_parts = tuple(
        sorted(
            (pair for pair in excerpt_part_keys if pair[0] in carried_item_ids),
            key=lambda pair: pair[0].encode("ascii"),
        )
    )
    input_manifest = review_input_manifest(
        frozen_case=frozen_case,
        review_selection=selection,
        sections=sections,
        items=items,
        omissions=omissions,
        omitted_item_total=len(omission_universe),
        task_statement_ids=task_statement_ids,
        task_statement_gaps=task_statement_gaps,
        recorded_statement=recorded_statement,
        pending_missing=pending_missing,
        supplied_missing=missing_answers,
        prior_finding_refs=prior_finding_refs,
        check_time_change_selected=check_change_selected,
        check_time_change_unavailable=check_time_change_unavailable,
        review_phase=review_phase,
        follow_up=follow_up,
        excerpt_parts=_parts_by_item(excerpt_parts),
        truncated_item_ids=tuple(
            sorted(
                (set(over_limit) | truncated_item_ids) & {item.item_id for item in items},
                key=str.encode,
            )
        ),
    )
    packet = ReviewPacket(
        task_statement_item_ids=tuple(task_statement_ids),
        goal_item_ids=tuple(goal_ids),
        obligation_item_ids=tuple(obligation_ids),
        claim_item_ids=tuple(claim_ids),
        decision_item_ids=tuple(decision_ids),
        timeline_item_ids=tuple(timeline_ids),
        deterministic_assessments=tuple(review_assessments),
        change_observations=tuple(changes),
        coverage=coverage,
        targeted_excerpts=tuple(targeted),
        omissions=tuple(omissions),
        prior_finding_item_ids=tuple(prior_finding_ids),
        prior_finding_refs=tuple(prior_finding_refs),
        input_manifest=input_manifest,
    )

    # The local case owns the complete frontier. The reviewer needs the dependency
    # closure of its selected packet, not every unrelated logical/source ID in that frontier.
    required_refs: set[str] = set(local_check_refs) | {
        str(ref) for ref in projection.findings if str(ref) in allowed
    }

    def retain(value: JsonValue) -> None:
        if isinstance(value, str):
            if value in allowed:
                required_refs.add(value)
        elif isinstance(value, dict):
            for child in value.values():
                retain(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                retain(child)

    retain(_packet_to_json(packet))
    retain(cast(JsonValue, review_item_catalog(items)))
    for item in items:
        if item.section == "excerpt":
            continue
        # Canonical payload/structural items carry typed dependencies beyond their short
        # linked_subject_refs catalog. Prose and captured byte excerpts are not parsed as IDs.
        try:
            content = strict_json_parse(item.content)
        except ValueError:
            continue
        retain(content)
    # Follow typed recorded payload dependencies to a fixed point. This keeps support,
    # limitations, availability and provenance connected without emitting unselected prose.
    records_by_ref = {
        str(ref): record
        for family in (
            projection.obligations,
            projection.actions,
            projection.results,
            projection.evidence,
            projection.claims,
            projection.findings,
        )
        for ref, record in family.items()
    }
    visited: set[str] = set()
    while pending := required_refs - visited:
        for ref in sorted(pending):
            visited.add(ref)
            record = records_by_ref.get(ref)
            if record is None:
                continue
            if str(record.source_event_id) in allowed:
                required_refs.add(str(record.source_event_id))
            if record.payload is not None and not record.redacted:
                retain(cast(JsonValue, encode_payload(record.payload)))
    if (
        not task_statement_ids
        and recorded_statement is not None
        and (recorded_statement.source_family in {"session_opened", "session_resumed"})
    ):
        # The frozen case holds a lifecycle event only because it recorded the statement. When
        # the policy withholds the statement, its own gaps already say so; counting that event
        # as a reduced reference scope would add ``semantic_reference_scope_reduced`` to every
        # check an existing approval runs (issue #908). A reference something else requires
        # stays counted.
        frontier_refs = frontier_refs - ({str(recorded_statement.source_event_id)} - required_refs)
    selected_frontier_refs = frozenset(required_refs & frontier_refs)
    omitted_reference_count = len(frontier_refs - selected_frontier_refs)
    frontier_refs = selected_frontier_refs
    if omitted_reference_count:
        packet = replace(
            packet,
            coverage=replace(
                packet.coverage,
                ledger_freshness=LedgerFreshness.PARTIAL,
                known_gaps=tuple(
                    sorted(
                        {*packet.coverage.known_gaps, "semantic_reference_scope_reduced"},
                        key=str.encode,
                    )
                ),
            ),
        )

    selection_digest = review_selection_digest(selection)
    # A case without a selected check-time change keeps its historical digest input exactly.
    check_change_binding: dict[str, JsonValue] = {}
    if check_time_change is not None:
        check_change_binding["check_time_change"] = {
            "base": check_time_change.capture.base,
            "content_digest": "sha256:"
            + hashlib.sha256(check_time_change.capture.text).hexdigest(),
            "envelope_digest": check_time_change.object_ref.envelope_digest,
            "object_id": check_time_change.object_ref.object_id,
            "parts_admitted": check_change_admitted,
            "redacted": check_time_change.capture.redacted,
            "truncated": check_time_change.capture.truncated,
        }
    elif check_time_change_unavailable:
        check_change_binding["check_time_change"] = {
            "unavailable": True,
            **(
                {}
                if check_time_change_unavailable_reason is None
                else {"reason": check_time_change_unavailable_reason}
            ),
        }
    # A pure function of the frozen projection, so recovery rebuilds the same phase and digest.
    question_set = review_question_set(
        review_phase,
        recorded_blockers(frozen_case.projection),
        acknowledged_obligation_rows(frozen_case.projection),
    )
    # tb4n5: which excerpts supply the follow-up beyond the first packet, so the provider-bound
    # manifest recomputes ``supplied`` from the ones admission kept. Bound into the digest only for
    # a follow-up case, so every other case digest is unchanged.
    follow_up_supplied: frozenset[str] = (
        frozenset()
        if follow_up is None
        else _follow_up_supplied_item_ids(items, _parts_by_item(excerpt_parts), follow_up)
    )
    # Bind assessments/omissions/packet lists into the digest so provenance covers the full case.
    case_digest = canonical_digest(
        cast(
            JsonValue,
            {
                **check_change_binding,
                "dependency_digest": dependency_digest,
                "frontier_refs": sorted(frontier_refs),
                "omitted_reference_count": omitted_reference_count,
                "items": [
                    {
                        "content_digest": item.content_digest,
                        "item_id": item.item_id,
                        "occurred_order": item.occurred_order,
                        "section": item.section,
                        **_freshness_json(item),
                    }
                    for item in items
                ],
                **(
                    {}
                    if follow_up is None
                    else {"follow_up_supplied_item_ids": sorted(follow_up_supplied)}
                ),
                "local_check_refs": sorted(local_check_refs),
                "policy_id": policy_id,
                "policy_version": policy_version,
                "question_set": list(question_set),
                "review_context_profile": review_context_profile.value,
                "review_packet": _packet_to_json(packet),
                "review_selection_digest": selection_digest,
                # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
                "schema": "yoetz.semantic-case/1",
                "subject_frontier": dict(frozen_case.frontier.as_wire()),
                "captured_content_gaps": list(capture_gaps),
                "captured_content_scope": (
                    None
                    if captured_content_scope is None
                    else {
                        "authorized_profiles": list(captured_content_scope.authorized_profiles),
                        "phase_bindings": [
                            {"evidence_ref": ref, "phase_identity": phase}
                            for ref, phase in captured_content_scope.phase_bindings
                        ],
                        "session_id": captured_content_scope.session_id,
                        "task_id": captured_content_scope.task_id,
                        "workspace_commitment": captured_content_scope.workspace_commitment,
                    }
                ),
                "captured_content": [
                    {
                        "capture_profile": item.capture_profile,
                        "content_digest": item.manifest.content_digest,
                        "content_kind": item.manifest.content_kind.value,
                        "correlation_identity": item.manifest.correlation_identity,
                        "envelope_digest": item.object_ref.envelope_digest,
                        "object_id": item.object_ref.object_id,
                        "part_count": item.manifest.part_count,
                        "part_index": item.manifest.part_index,
                        "phase_identity": item.phase_identity,
                        "source_commitment": item.manifest.source_commitment,
                    }
                    for item in sorted(
                        captured_content,
                        key=lambda item: (
                            item.object_ref.object_id.encode("ascii"),
                            item.manifest.part_index,
                        ),
                    )
                ],
            },
        )
    )

    return SemanticCase(
        case_id=case_id,
        subject_frontier=frozen_case.frontier,
        dependency_digest=dependency_digest,
        frontier_refs=frontier_refs,
        local_check_refs=local_check_refs,
        review_context_profile=review_context_profile,
        review_selection=selection,
        policy_id=policy_id,
        policy_version=policy_version,
        packet=packet,
        items=tuple(items),
        question_set=question_set,
        case_digest=case_digest,
        omitted_reference_count=omitted_reference_count,
        excerpts_cut_for_case_bound=excerpts_cut_for_case_bound,
        excerpt_parts=excerpt_parts,
        follow_up_supplied_item_ids=follow_up_supplied,
    )


def _assessment_to_json(assessment: ReviewAssessment) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "coverage_gaps": list(assessment.coverage_gaps),
        "finding_kind": assessment.finding_kind.value,
        "finding_ref": str(assessment.finding_ref),
        "observed_facts": [
            {"fact_code": fact.fact_code, "subject_refs": list(fact.subject_refs)}
            for fact in assessment.observed_facts
        ],
        "priority": assessment.priority,
        "required_but_missing_facts": [
            {"fact_code": fact.fact_code, "subject_refs": list(fact.subject_refs)}
            for fact in assessment.required_but_missing_facts
        ],
        "rule_id": assessment.rule_id,
        "source_availability": assessment.source_availability.value,
        "subject_refs": list(assessment.subject_refs),
        "subject_state_relation": assessment.subject_state_relation.value,
        "supporting_refs": list(assessment.supporting_refs),
    }
    if assessment.summary_item_id is not None and assessment.detail_item_id is not None:
        body["summary_item_id"] = assessment.summary_item_id
        body["detail_item_id"] = assessment.detail_item_id
    return body


def _digest_provenance_json(provenance: ExcerptDigestProvenance) -> dict[str, JsonValue]:
    return {
        "byte_count": provenance.byte_count,
        "content_availability": provenance.content_availability.value,
        "content_digest": provenance.content_digest,
        "digest_subject": provenance.digest_subject.value,
        "evidence_kind": provenance.evidence_kind.value,
        "provenance": provenance.provenance.value,
        "strength": provenance.strength.value,
        **(
            {}
            if provenance.approval_commitment is None
            else {"approval_commitment": provenance.approval_commitment}
        ),
        **(
            {}
            if provenance.approved_check_result_digest is None
            else {"approved_check_result_digest": provenance.approved_check_result_digest}
        ),
    }


def _packet_to_json(packet: ReviewPacket) -> dict[str, JsonValue]:
    manifest = packet.input_manifest
    return cast(
        dict[str, JsonValue],
        {
            "change_observations": [
                {
                    "claimed_change": item.claimed_change,
                    "content_visibility": item.content_visibility,
                    "subject_refs": list(item.subject_refs),
                    "subject_state_relation": item.subject_state_relation.value,
                    **(
                        {
                            "after_state_digest": item.after_state_digest,
                            "before_state_digest": item.before_state_digest,
                        }
                        if item.before_state_digest is not None
                        else {}
                    ),
                }
                for item in packet.change_observations
            ],
            "claim_item_ids": list(packet.claim_item_ids),
            "coverage": coverage_to_json(packet.coverage),
            "decision_item_ids": list(packet.decision_item_ids),
            "deterministic_assessments": [
                _assessment_to_json(item) for item in packet.deterministic_assessments
            ],
            "goal_item_ids": list(packet.goal_item_ids),
            "task_statement_item_ids": list(packet.task_statement_item_ids),
            "obligation_item_ids": list(packet.obligation_item_ids),
            "prior_finding_item_ids": list(packet.prior_finding_item_ids),
            "prior_finding_refs": list(packet.prior_finding_refs),
            **(
                {}
                if manifest is None
                else {"review_input_manifest": review_input_manifest_to_json(manifest)}
            ),
            "omissions": [
                {
                    "category": item.category.value,
                    "reason": item.reason,
                    "source_kind": item.source_kind,
                    "subject_ref": item.subject_ref,
                }
                for item in packet.omissions
            ],
            "targeted_excerpts": [
                {
                    "content_bytes": item.content_bytes,
                    "content_digest": item.content_digest,
                    "content_visibility": item.content_visibility,
                    **(
                        {}
                        if item.digest_provenance is None
                        else {"digest_provenance": _digest_provenance_json(item.digest_provenance)}
                    ),
                    "excerpt_item_id": item.excerpt_item_id,
                    "linked_subject_refs": list(item.linked_subject_refs),
                    "source_kind": item.source_kind,
                    "subject_state_relation": item.subject_state_relation.value,
                }
                for item in packet.targeted_excerpts
            ],
            "timeline_item_ids": list(packet.timeline_item_ids),
        },
    )


def _review_input_section_to_json(section: ReviewInputSection) -> dict[str, JsonValue]:
    return {
        "content_bytes": section.content_bytes,
        "content_digest": section.content_digest,
        "item_ids": list(section.selected_item_ids),
        "omission_reasons": list(section.omission_reasons),
        "omitted_refs": list(section.omitted_refs),
        "revision": section.revision,
        "source_refs": list(section.source_refs),
        "status": section.status,
    }


def review_input_manifest_to_json(manifest: ReviewInputManifest) -> dict[str, JsonValue]:
    """Encode one metadata-only input manifest for check, receipt and event projections."""

    if type(manifest) is not ReviewInputManifest:
        raise TypeError("review_input_manifest_invalid")
    return {
        "caller_evidence": _review_input_section_to_json(manifest.caller_evidence),
        "current_diff": _review_input_section_to_json(manifest.current_diff),
        **(
            {}
            if manifest.follow_up_round is None
            else {"follow_up_round": manifest.follow_up_round}
        ),
        "latest_verification": _review_input_section_to_json(manifest.latest_verification),
        "missing_inputs": [
            {
                "kind": item.kind,
                "status": item.status,
                "supplied_refs": list(item.supplied_refs),
                "target_refs": list(item.target_refs),
            }
            for item in manifest.missing_inputs
        ],
        "omitted_item_count": manifest.omitted_item_count,
        **(
            {}
            if manifest.omitted_item_total is None
            else {"omitted_item_total": manifest.omitted_item_total}
        ),
        "phase": manifest.phase,
        "prior_finding_context": _review_input_section_to_json(manifest.prior_finding_context),
        **({} if manifest.review_phase is None else {"review_phase": manifest.review_phase}),
        "schema": manifest.schema,
        "selected_excerpt_bytes": manifest.selected_excerpt_bytes,
        "selected_item_count": manifest.selected_item_count,
        "specification": _review_input_section_to_json(manifest.specification),
    }


def _freshness_json(item: SemanticCaseItem) -> dict[str, JsonValue]:
    """Excerpt freshness marks; absent on every item that has none."""

    body: dict[str, JsonValue] = {}
    if item.latest_for is not None:
        body["latest_for"] = item.latest_for
    if item.superseded_by:
        body["superseded_by"] = list(item.superseded_by)
    return body


def _manifest_digest(items: Sequence[SemanticCaseItem]) -> str | None:
    """Digest the selected item content without exposing that content in the manifest."""

    if not items:
        return None
    return canonical_digest(
        cast(
            JsonValue,
            {
                "items": [
                    {
                        "content_bytes": item.content_bytes,
                        "content_digest": item.content_digest,
                        "item_id": item.item_id,
                    }
                    for item in items
                ],
                # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
                "schema": "yoetz.review-input-manifest-content/1",
            },
        )
    )


def _manifest_section(
    name: Literal[
        "specification",
        "current_diff",
        "caller_evidence",
        "latest_verification",
        "prior_finding_context",
    ],
    *,
    status: Literal[
        "complete",
        "partial",
        "title_only",
        "missing",
        "withheld",
        "not_selected",
    ],
    items: Sequence[SemanticCaseItem] = (),
    source_refs: Sequence[str] = (),
    omitted_refs: Sequence[str] = (),
    omission_reasons: Sequence[str] = (),
    revision: int | None = None,
    content_digest: str | None = None,
    content_bytes: int | None = None,
) -> ReviewInputSection:
    selected = tuple(sorted(items, key=lambda item: item.item_id.encode("ascii")))
    refs = tuple(sorted(set(source_refs), key=str.encode))[:16]
    omitted = tuple(sorted(set(omitted_refs), key=str.encode))[:16]
    # Packet omissions distinguish heuristic hits; section manifests use their existing
    # closed redaction reason, as the post-egress manifest does. Withholding must not crash.
    reasons = tuple(
        sorted(
            {
                "redacted_never_send" if reason == "never_send_heuristic" else reason
                for reason in omission_reasons
            },
            key=str.encode,
        )
    )
    return ReviewInputSection(
        name=name,
        status=status,
        source_refs=refs,
        selected_item_ids=tuple(item.item_id for item in selected),
        omitted_refs=omitted,
        omission_reasons=reasons,
        revision=revision,
        content_digest=(
            content_digest if content_digest is not None else _manifest_digest(selected)
        ),
        content_bytes=(
            sum(item.content_bytes for item in selected) if content_bytes is None else content_bytes
        ),
    )


def review_input_manifest(
    *,
    frozen_case: DeterministicCase,
    review_selection: ReviewSelectionPolicy,
    sections: frozenset[str],
    items: Sequence[SemanticCaseItem],
    omissions: Sequence[ReviewOmission],
    task_statement_ids: Sequence[str],
    task_statement_gaps: frozenset[str] | set[str],
    recorded_statement: object | None,
    pending_missing: object | None,
    omitted_item_total: int | None = None,
    supplied_missing: Sequence[Sequence[str]] = (),
    prior_finding_refs: Sequence[str] = (),
    check_time_change_selected: bool = False,
    check_time_change_unavailable: bool = False,
    truncated_item_ids: Sequence[str] = (),
    review_phase: SemanticBudgetProfile | None = None,
    follow_up: ReviewFollowUp | None = None,
    excerpt_parts: Mapping[str, Sequence[str]] | None = None,
) -> ReviewInputManifest:
    """Build the bounded per-check input manifest from frozen case material.

    This is a structural view of the case after selection. It intentionally receives already
    selected ``SemanticCaseItem`` values and omission rows, never a provider body or a live
    workspace. The statement's digest/length/revision are included even though its prose remains
    in the separately authorized task-statement item. ``omitted_item_total`` is every distinct
    omission before the listed rows were capped (never fewer than the rows listed).

    A follow-up packet (issue #1047) names its ``follow_up_round``, and its ``missing_inputs``
    list the reviewer's in-check request instead of an earlier check's: ``supplied`` with the
    excerpt sources FinishUP added for the item beyond the check's first packet, else ``pending``.
    A source counts as added when the packet carries a part of it (``excerpt_parts`` places each
    excerpt in its source) that the first packet did not carry (tb4n5).
    """

    typed_statement = recorded_statement
    statement_items = [item for item in items if item.item_id in set(task_statement_ids)]
    truncated = set(truncated_item_ids)
    statement_truncated = bool({item.item_id for item in statement_items} & truncated)
    statement_ref: str | None = None
    statement_revision: int | None = None
    statement_digest: str | None = None
    statement_bytes: int | None = None
    statement_status: Literal[
        "complete",
        "partial",
        "title_only",
        "missing",
        "withheld",
        "not_selected",
    ]
    if "task_statement" not in sections:
        statement_status = "withheld"
    elif typed_statement is not None and hasattr(typed_statement, "text"):
        text = cast(str, getattr(typed_statement, "text"))
        statement_ref = str(getattr(typed_statement, "source_event_id"))
        statement_revision = cast(int, getattr(typed_statement, "ingestion_sequence"))
        statement_digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        statement_bytes = len(text.encode("utf-8"))
        statement_status = "complete"
        # A recorded statement can still be clipped while it is rendered into the bounded case
        # item. Validate the effective row's bytes and digest here, so the composed manifest does
        # not call a long statement complete merely because its item id survived selection. The
        # provider-bound projection repeats this check after privacy admission.
        if not statement_items:
            statement_status = "partial"
        else:
            for item in statement_items:
                try:
                    rendered = strict_json_parse(item.content)
                except ValueError:
                    statement_status = "partial"
                    continue
                if not isinstance(rendered, dict) or type(rendered.get("statement")) is not str:
                    statement_status = "partial"
                    continue
                rendered_bytes = cast(str, rendered["statement"]).encode("utf-8")
                rendered_digest = "sha256:" + hashlib.sha256(rendered_bytes).hexdigest()
                if (
                    rendered_digest != statement_digest
                    or len(rendered_bytes) != statement_bytes
                    or rendered.get("elided_bytes") not in {0, None}
                ):
                    statement_status = "partial"
    elif frozen_case.task_title is not None:
        statement_ref = "task-title"
        statement_digest = (
            "sha256:" + hashlib.sha256(frozen_case.task_title.encode("utf-8")).hexdigest()
        )
        statement_bytes = len(frozen_case.task_title.encode("utf-8"))
        statement_status = "title_only"
    else:
        statement_status = "missing"
    if statement_truncated and statement_status in {"complete", "title_only"}:
        statement_status = "partial"
    statement = _manifest_section(
        "specification",
        status=statement_status,
        items=statement_items,
        source_refs=() if statement_ref is None else (statement_ref,),
        omitted_refs=(
            (statement_ref,)
            if statement_ref is not None and statement_status in {"withheld", "not_selected"}
            else ()
        ),
        omission_reasons=(
            [*sorted(task_statement_gaps, key=str.encode)]
            + (["truncated_payload"] if statement_truncated else [])
        ),
        revision=statement_revision,
        content_digest=statement_digest,
        content_bytes=statement_bytes,
    )

    excerpt_items = [item for item in items if item.section == "excerpt"]
    omitted_by_kind: dict[str, list[ReviewOmission]] = {}
    for omission in omissions:
        omitted_by_kind.setdefault(omission.source_kind, []).append(omission)

    current_diff = [
        item
        for item in excerpt_items
        if item.source_kind == "diff" or item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    ]
    diff_omissions = omitted_by_kind.get("diff", [])
    diff_refs = [item.source_ref for item in current_diff]
    diff_refs.extend(item.subject_ref for item in diff_omissions)
    if "targeted_excerpts" not in sections or review_selection.max_excerpts == 0:
        diff_status: Literal[
            "complete",
            "partial",
            "title_only",
            "missing",
            "withheld",
            "not_selected",
        ] = "not_selected"
    elif current_diff and (diff_omissions or {item.item_id for item in current_diff} & truncated):
        diff_status = "partial"
    elif current_diff:
        diff_status = "complete"
    elif check_time_change_unavailable:
        diff_status = "missing"
    else:
        diff_status = "missing"
    diff_revision = max((item.occurred_order for item in current_diff), default=None)
    current_diff_section = _manifest_section(
        "current_diff",
        status=diff_status,
        items=current_diff,
        source_refs=diff_refs,
        omitted_refs=[item.subject_ref for item in diff_omissions],
        omission_reasons=(
            [item.reason for item in diff_omissions]
            + (["truncated_payload"] if {item.item_id for item in current_diff} & truncated else [])
            + (["capture_unavailable"] if check_time_change_unavailable else [])
        ),
        revision=diff_revision,
    )

    verification = [
        item
        for item in excerpt_items
        if item.source_kind in {"test", "failure", "command"} or item.latest_for == "command"
    ]
    verification_omissions = [
        omission
        for kind in ("test", "failure", "command")
        for omission in omitted_by_kind.get(kind, [])
    ]
    verification_status: Literal[
        "complete",
        "partial",
        "title_only",
        "missing",
        "withheld",
        "not_selected",
    ] = (
        "not_selected"
        if "targeted_excerpts" not in sections or review_selection.max_excerpts == 0
        else "partial"
        if verification
        and (verification_omissions or {item.item_id for item in verification} & truncated)
        else "complete"
        if verification
        else "missing"
    )
    latest_verification = _manifest_section(
        "latest_verification",
        status=verification_status,
        items=verification,
        source_refs=[item.source_ref for item in verification]
        + [item.subject_ref for item in verification_omissions],
        omitted_refs=[item.subject_ref for item in verification_omissions],
        omission_reasons=[item.reason for item in verification_omissions]
        + (["truncated_payload"] if {item.item_id for item in verification} & truncated else []),
        revision=max((item.occurred_order for item in verification), default=None),
    )

    caller_evidence = [
        item
        for item in excerpt_items
        if item.source_kind in {"evidence", "repository"}
        and item not in current_diff
        and item not in verification
    ]
    caller_omissions = [
        omission
        for kind in ("evidence", "repository")
        for omission in omitted_by_kind.get(kind, [])
    ]
    caller_status: Literal[
        "complete",
        "partial",
        "title_only",
        "missing",
        "withheld",
        "not_selected",
    ] = (
        "not_selected"
        if "targeted_excerpts" not in sections or review_selection.max_excerpts == 0
        else "partial"
        if caller_evidence
        and (caller_omissions or {item.item_id for item in caller_evidence} & truncated)
        else "complete"
        if caller_evidence
        else "missing"
    )
    caller_section = _manifest_section(
        "caller_evidence",
        status=caller_status,
        items=caller_evidence,
        source_refs=[item.source_ref for item in caller_evidence]
        + [item.subject_ref for item in caller_omissions],
        omitted_refs=[item.subject_ref for item in caller_omissions],
        omission_reasons=[item.reason for item in caller_omissions]
        + (["truncated_payload"] if {item.item_id for item in caller_evidence} & truncated else []),
        revision=max((item.occurred_order for item in caller_evidence), default=None),
    )

    prior_items = [
        item
        for item in items
        if item.section == "prior_finding"
        or item.item_id == "prior-missing-for-assessment"
        or item.source_ref in set(prior_finding_refs)
    ]
    prior_status: Literal[
        "complete",
        "partial",
        "title_only",
        "missing",
        "withheld",
        "not_selected",
    ] = (
        "not_selected"
        if "deterministic_assessments" not in sections
        else "partial"
        if prior_items and {item.item_id for item in prior_items} & truncated
        else "complete"
        if prior_items
        else "missing"
    )
    prior_section = _manifest_section(
        "prior_finding_context",
        status=prior_status,
        items=prior_items,
        source_refs=[item.source_ref for item in prior_items],
        omission_reasons=(
            ["truncated_payload"] if {item.item_id for item in prior_items} & truncated else []
        ),
        revision=max((item.occurred_order for item in prior_items), default=None),
    )

    missing_rows: list[ReviewInputMissing] = []
    if follow_up is not None:
        placed: Mapping[str, Sequence[str]] = {} if excerpt_parts is None else excerpt_parts
        for follow_up_item in follow_up.items[:8]:
            carried_refs: set[str] = set()
            for item in excerpt_items:
                refs = (
                    frozenset(
                        _excerpt_row_content_refs(
                            item.section,
                            item.category.value,
                            item.source_ref,
                            item.linked_subject_refs,
                        )
                    )
                    & follow_up_item.source_refs
                )
                keys = placed.get(item.item_id, ())
                if item.source_ref != _CHECK_TIME_CHANGE_SOURCE_REF and not (
                    _observed_span_refs(keys) & follow_up_item.source_refs
                ):
                    # A served current section, and a marked observed-command excerpt, answer
                    # even when the first packet showed the underlying ref whole.
                    refs -= follow_up.shown_refs
                if refs and (
                    not keys
                    or any(not excerpt_span_covered(key, follow_up.shown_parts) for key in keys)
                ):
                    carried_refs.update(refs)
            added = sorted(carried_refs, key=str.encode)[:4]
            missing_rows.append(
                ReviewInputMissing(
                    kind=cast(MissingForAssessmentKind, follow_up_item.kind),
                    target_refs=follow_up_item.target_refs,
                    supplied_refs=tuple(added),
                    status="supplied" if added else "pending",
                )
            )
    elif pending_missing is not None and hasattr(pending_missing, "items"):
        pending_items = tuple(getattr(pending_missing, "items"))
        for index, item in enumerate(pending_items[:8]):
            supplied = tuple(supplied_missing[index]) if index < len(supplied_missing) else ()
            availability = str(getattr(item, "availability", "agent_suppliable"))
            if availability != "agent_suppliable":
                status: Literal["pending", "supplied", "unavailable", "repeated"] = "unavailable"
            elif supplied:
                status = "supplied"
            elif frozen_case.frontier.sequence <= int(getattr(pending_missing, "source_frontier")):
                status = "repeated"
            else:
                status = "pending"
            missing_rows.append(
                ReviewInputMissing(
                    kind=cast(MissingForAssessmentKind, getattr(item, "kind")),
                    target_refs=tuple(getattr(item, "target_refs")),
                    supplied_refs=supplied,
                    status=status,
                )
            )

    omitted_item_count = min(
        MAX_REVIEW_OMISSIONS,
        len(omissions),
    )
    omitted_total = min(
        MAX_REVIEW_OMISSION_TOTAL,
        max(
            omitted_item_count, len(omissions) if omitted_item_total is None else omitted_item_total
        ),
    )
    return ReviewInputManifest(
        # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
        schema="yoetz.review-input-manifest/1",
        specification=statement,
        current_diff=current_diff_section,
        caller_evidence=caller_section,
        latest_verification=latest_verification,
        prior_finding_context=prior_section,
        missing_inputs=tuple(missing_rows),
        selected_item_count=len(items),
        selected_excerpt_bytes=sum(item.content_bytes for item in excerpt_items),
        omitted_item_count=omitted_item_count,
        omitted_item_total=omitted_total,
        review_phase=review_phase,
        follow_up_round=None if follow_up is None else follow_up.round,
    )


def follow_up_byte_budget(selection: ReviewSelectionPolicy) -> int:
    """The excerpt bytes an in-check follow-up may rank first (issue #1047).

    Half the approved total excerpt bytes of one packet, over all of a check's follow-up rounds:
    the reviewer's own request is answered first, and the rest of the packet keeps at least half
    of its room for the selection it had. Items rank first in request order, so what an earlier
    round added keeps its place; nothing here widens what the owner approved per packet.
    """

    return selection.max_total_excerpt_bytes // 2


def review_item_catalog(
    items: Sequence[SemanticCaseItem], follow_up_supplied: frozenset[str] = frozenset()
) -> list[dict[str, JsonValue]]:
    """Metadata-only catalog so egress can project without reverse-engineering origin_ref.

    ``occurred_order`` is the ledger ingestion order of the item's source, so the reviewer can
    tell earlier material from later material without trusting the opaque item ids (#907).
    ``follow_up_supplied`` excerpts carry ``follow_up_supplied: true`` (tb4n5): the assembler
    counts a follow-up item supplied only through a marked excerpt it carried. The flag stays in
    the envelope; packet rows never copy it.
    """

    return [
        cast(
            dict[str, JsonValue],
            {
                "category": item.category.value,
                "content_bytes": item.content_bytes,
                "content_digest": item.content_digest,
                "item_id": item.item_id,
                "linked_subject_refs": list(item.linked_subject_refs),
                "occurred_order": item.occurred_order,
                "section": item.section,
                "source_kind": item.source_kind,
                "source_ref": item.source_ref,
                **_freshness_json(item),
                **(
                    {"label": _SECTION_LABELS[item.section]}
                    if item.section in _SECTION_LABELS
                    else {}
                ),
                **({"follow_up_supplied": True} if item.item_id in follow_up_supplied else {}),
            },
        )
        for item in items
    ]


def _case_envelope_json(case: SemanticCase) -> dict[str, JsonValue]:
    return cast(
        dict[str, JsonValue],
        {
            "case_digest": case.case_digest,
            "case_id": case.case_id,
            "dependency_digest": case.dependency_digest,
            "frontier_refs": sorted(case.frontier_refs),
            "omitted_reference_count": str(case.omitted_reference_count),
            "item_catalog": review_item_catalog(case.items, case.follow_up_supplied_item_ids),
            "local_check_refs": sorted(case.local_check_refs),
            "policy_id": case.policy_id,
            "policy_version": case.policy_version,
            "question_set": list(case.question_set),
            "review_context_profile": case.review_context_profile.value,
            "review_packet": _packet_to_json(case.packet),
            "review_selection_digest": review_selection_digest(case.review_selection),
            "schema": _PACKET_SCHEMA,
            "subject_frontier": dict(case.subject_frontier.as_wire()),
        },
    )


def assemble_filtered_review_packet(
    envelope: Mapping[str, object],
    *,
    content_by_id: Mapping[str, bytes],
    included_item_ids: frozenset[str] | set[str],
    withheld_item_ids: frozenset[str] | set[str] = frozenset(),
    redacted_item_ids: frozenset[str] | set[str] = frozenset(),
) -> bytes:
    """Assemble ``yoetz.review-packet-case/2`` from a builder envelope + approved content.

    Single shared projection used by the application prepared-payload path and the privacy
    enforcer. Filters by approved item id only; never re-derives section/source metadata from
    origin pointers.
    """

    included = set(included_item_ids)
    withheld = set(withheld_item_ids)
    redacted = set(redacted_item_ids)
    frontier_raw = envelope.get("frontier_refs")
    local_raw = envelope.get("local_check_refs")
    frontier_refs: set[str] = (
        {item for item in cast(list[object], frontier_raw) if type(item) is str}
        if type(frontier_raw) is list
        else set()
    )
    local_check_refs: set[str] = (
        {item for item in cast(list[object], local_raw) if type(item) is str}
        if type(local_raw) is list
        else set()
    )
    allowed: set[str] = frontier_refs | local_check_refs

    catalog_raw = envelope.get("item_catalog")
    catalog: list[dict[str, object]] = []
    if type(catalog_raw) is list:
        for row in cast(list[object], catalog_raw):
            if isinstance(row, dict):
                catalog.append(cast(dict[str, object], row))

    content_rows: list[dict[str, JsonValue]] = []
    omitted_extra: list[dict[str, JsonValue]] = []
    follow_up_supplied = frozenset(
        cast(str, meta["item_id"])
        for meta in catalog
        if type(meta.get("item_id")) is str and meta.get("follow_up_supplied") is True
    )
    for meta in catalog:
        item_id = meta.get("item_id")
        if type(item_id) is not str or item_id == REVIEW_PACKET_ITEM_ID:
            continue
        category = meta.get("category")
        source_kind = meta.get("source_kind")
        source_ref = meta.get("source_ref")
        section = meta.get("section")
        label = meta.get("label")
        linked_raw = meta.get("linked_subject_refs")
        linked = (
            [ref for ref in cast(list[object], linked_raw) if type(ref) is str]
            if type(linked_raw) is list
            else []
        )
        if item_id in included and item_id in content_by_id:
            plaintext = content_by_id[item_id]
            try:
                text = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                continue
            occurred_order = meta.get("occurred_order")
            latest_for = meta.get("latest_for")
            superseded_raw = meta.get("superseded_by")
            superseded = (
                [ref for ref in cast(list[object], superseded_raw) if type(ref) is str]
                if type(superseded_raw) is list
                else []
            )
            content_rows.append(
                cast(
                    dict[str, JsonValue],
                    {
                        "category": category if type(category) is str else "",
                        "content": text,
                        "content_bytes": len(plaintext),
                        "content_digest": "sha256:" + hashlib.sha256(plaintext).hexdigest(),
                        "item_id": item_id,
                        "linked_subject_refs": linked,
                        "occurred_order": occurred_order if type(occurred_order) is int else 0,
                        "section": section if type(section) is str else "timeline",
                        "source_kind": source_kind if type(source_kind) is str else "task",
                        "source_ref": source_ref if type(source_ref) is str else item_id,
                        **(
                            {
                                "transformations": [
                                    {
                                        "after_bytes": len(plaintext),
                                        "before_bytes": (
                                            meta.get("content_bytes")
                                            if type(meta.get("content_bytes")) is int
                                            and cast(int, meta["content_bytes"]) >= 0
                                            else len(plaintext)
                                        ),
                                        "kind": "redacted",
                                        "reason": "sensitive_redacted",
                                    }
                                ]
                            }
                            if item_id in redacted
                            else {}
                        ),
                        **({"latest_for": latest_for} if type(latest_for) is str else {}),
                        **({"superseded_by": cast(JsonValue, superseded)} if superseded else {}),
                        # tb4n5: this excerpt supplies the reviewer's in-check request beyond
                        # the check's first packet; the provider-bound manifest counts only these.
                        **({"follow_up_supplied": True} if item_id in follow_up_supplied else {}),
                        # Only the fixed section label the builder catalogued, never caller text.
                        **(
                            {"label": _SECTION_LABELS[section]}
                            if type(section) is str
                            and section in _SECTION_LABELS
                            and label == _SECTION_LABELS[section]
                            else {}
                        ),
                    },
                )
            )
            continue
        if item_id in included:
            continue
        # Prefer allowlisted source_ref, then any allowlisted linked ref; skip only if none.
        subject: str | None = None
        if type(source_ref) is str and source_ref in allowed:
            subject = source_ref
        else:
            for ref in linked:
                if ref in allowed:
                    subject = ref
                    break
        if subject is None:
            continue
        omitted_extra.append(
            cast(
                dict[str, JsonValue],
                {
                    "category": category if type(category) is str else "",
                    "reason": (
                        "never_send_heuristic" if item_id in withheld else "withheld_by_policy"
                    ),
                    "source_kind": source_kind if type(source_kind) is str else "task",
                    "subject_ref": subject,
                },
            )
        )
    # Rows keep the case's own order: section, then recording order. Sorting by item id put
    # excerpts in the order of their random evidence ids, so a superseded hunk could read as the
    # newest one (issue #907).

    packet_raw = envelope.get("review_packet")
    packet_obj: dict[str, JsonValue] = (
        cast(dict[str, JsonValue], dict(cast(dict[object, object], packet_raw)))
        if isinstance(packet_raw, dict)
        else {}
    )

    # Filter by what the document will actually carry — approved *and* catalogued. Filtering by
    # approval alone let an id survive here whose catalog row bounding had already removed, so the
    # packet pointed at an item absent from ``items``.
    carried = {cast(str, row["item_id"]) for row in content_rows}

    def _filter_ids(raw: object) -> list[JsonValue]:
        if type(raw) is not list:
            return []
        return [
            item_id
            for item_id in cast(list[object], raw)
            if type(item_id) is str and item_id in carried
        ]

    for key in _PACKET_ID_LIST_KEYS:
        packet_obj[key] = _filter_ids(packet_obj.get(key))
    _sync_prior_finding_refs(packet_obj)

    excerpts_raw = packet_obj.get("targeted_excerpts")
    if type(excerpts_raw) is list:
        targeted: list[JsonValue] = []
        for raw in cast(list[object], excerpts_raw):
            if not isinstance(raw, dict):
                continue
            row = dict(cast(dict[str, JsonValue], cast(dict[object, object], raw)))
            item_id = row.get("excerpt_item_id")
            if type(item_id) is not str or item_id not in carried:
                continue
            if item_id in redacted:
                row["content_visibility"] = "redacted_never_send"
            targeted.append(cast(JsonValue, row))
        packet_obj["targeted_excerpts"] = targeted
    else:
        packet_obj["targeted_excerpts"] = cast(JsonValue, [])

    assessments_raw = packet_obj.get("deterministic_assessments")
    filtered_assessments: list[JsonValue] = []
    if type(assessments_raw) is list:
        for raw in cast(list[object], assessments_raw):
            if not isinstance(raw, dict):
                continue
            row = dict(cast(dict[str, JsonValue], cast(dict[object, object], raw)))
            summary = row.get("summary_item_id")
            detail = row.get("detail_item_id")
            if type(summary) is str and type(detail) is str:
                if summary not in carried or detail not in carried:
                    row.pop("summary_item_id", None)
                    row.pop("detail_item_id", None)
            filtered_assessments.append(row)
    packet_obj["deterministic_assessments"] = filtered_assessments

    base_omissions: list[dict[str, JsonValue]] = []
    omissions_raw = packet_obj.get("omissions")
    if type(omissions_raw) is list:
        for raw in cast(list[object], omissions_raw):
            if isinstance(raw, dict):
                base_omissions.append(
                    cast(dict[str, JsonValue], dict(cast(dict[object, object], raw)))
                )

    seen: set[tuple[str, str, str]] = set()
    omissions: list[JsonValue] = []
    for row in [*base_omissions, *omitted_extra]:
        subject_ref = row.get("subject_ref")
        category = row.get("category")
        reason = row.get("reason")
        if type(subject_ref) is not str or type(category) is not str or type(reason) is not str:
            continue
        key = (subject_ref, category, reason)
        if key in seen:
            continue
        if subject_ref not in allowed:
            continue
        seen.add(key)
        omissions.append(row)
    omissions.sort(
        key=lambda row: (
            cast(str, cast(dict[str, JsonValue], row)["subject_ref"]).encode("ascii"),
            cast(str, cast(dict[str, JsonValue], row)["category"]).encode("ascii"),
            cast(str, cast(dict[str, JsonValue], row)["reason"]).encode("ascii"),
        )
    )
    packet_obj["omissions"] = omissions

    # The builder manifest describes the composed case. Keep a second, provider-bound view after
    # approval/minimization and envelope filtering so a receipt or provider packet never claims
    # that an item survived when its content row was withheld or trimmed. This is structural
    # metadata only; no source prose is copied into either manifest.
    composed_manifest = packet_obj.get("review_input_manifest")
    if isinstance(composed_manifest, dict):
        withheld_excerpt_refs = frozenset(
            ref
            for meta in catalog
            if meta.get("item_id") not in included
            for ref in _excerpt_row_content_refs(
                meta.get("section"),
                meta.get("category"),
                meta.get("source_ref"),
                meta.get("linked_subject_refs"),
            )
        )
        provider_manifest = _provider_bound_input_manifest(
            composed_manifest,
            content_rows,
            omissions,
            redacted_item_ids=redacted,
            privacy_withheld_refs=withheld_excerpt_refs,
        )
        packet_obj["provider_input_manifest"] = provider_manifest

    # Preserve change_observations / coverage as supplied by the builder envelope.
    if "change_observations" not in packet_obj:
        packet_obj["change_observations"] = cast(JsonValue, [])
    if "coverage" not in packet_obj:
        packet_obj["coverage"] = cast(JsonValue, {})

    # Approved content whose catalog row is absent cannot be described (the catalog *is* its
    # metadata), so it cannot travel. Counting it keeps the omission visible instead of letting
    # the packet read as though that material was never approved.
    uncatalogued = sum(
        1
        for item_id in included
        if item_id != REVIEW_PACKET_ITEM_ID and item_id in content_by_id and item_id not in carried
    )
    accounting_raw = envelope.get("selection_accounting")
    accounting: dict[str, JsonValue] = (
        cast(dict[str, JsonValue], dict(cast(dict[object, object], accounting_raw)))
        if isinstance(accounting_raw, dict)
        else {
            "assessment_links_stripped_count": "0",
            "catalog_dropped_count": "0",
            "change_observations_dropped_count": "0",
            "deterministic_assessments_dropped_count": "0",
            "omissions_dropped_count": "0",
            "reason": "not_minimized",
            "targeted_excerpts_dropped_count": "0",
        }
    )
    accounting["uncatalogued_approved_count"] = str(uncatalogued)

    document = cast(
        dict[str, JsonValue],
        {
            "case_digest": envelope.get("case_digest", ""),
            "case_id": envelope.get("case_id", ""),
            # The exact ids post-validation will accept in a challenge's cited_refs, in one place
            # the reviewer can read: refs whose content this packet carries (a content row's
            # source or linked subject) and this check's local findings whose assessment row
            # survived. items[].item_id — the ids most visible in the document — are not citable.
            # Advertising every frontier ref, including ones whose rows were omitted, invited
            # citations post-validation then had to discard (TB4 tb4v1, issue #976).
            "citable_refs": sorted(
                _carried_citable_refs(
                    content_rows, filtered_assessments, allowed, local_check_refs
                ),
                key=str.encode,
            ),
            "omitted_reference_count": envelope.get("omitted_reference_count", "0"),
            "selection_accounting": cast(JsonValue, accounting),
            "dependency_digest": envelope.get("dependency_digest", ""),
            "frontier_refs": sorted(frontier_refs),
            "items": content_rows,
            "local_check_refs": sorted(local_check_refs),
            "policy_id": envelope.get("policy_id", ""),
            "policy_version": envelope.get("policy_version", ""),
            "question_set": (
                list(cast(list[object], envelope["question_set"]))
                if type(envelope.get("question_set")) is list
                else []
            ),
            "review_context_profile": envelope.get("review_context_profile", ""),
            "review_packet": packet_obj,
            "review_selection_digest": envelope.get("review_selection_digest", ""),
            "schema": _PACKET_SCHEMA,
            "subject_frontier": (
                dict(cast(dict[object, object], envelope["subject_frontier"]))
                if isinstance(envelope.get("subject_frontier"), dict)
                else {}
            ),
        },
    )
    return canonical_encode(cast(JsonValue, document))


def _carried_citable_refs(
    content_rows: Sequence[Mapping[str, JsonValue]],
    assessments: Sequence[JsonValue],
    allowed: set[str],
    local_check_refs: set[str],
) -> set[str]:
    """Refs the reviewer can cite because the packet carries content or an assessment for them.

    This mirrors the provider-bound text index post-validation proves quotes against (a content
    row's ``source_ref`` and ``linked_subject_refs``), so a reviewer that cites only advertised
    refs never has a citation removed for want of sent content.
    """

    carried: set[str] = set()
    for row in content_rows:
        source = row.get("source_ref")
        if type(source) is str:
            carried.add(source)
        linked = row.get("linked_subject_refs")
        if type(linked) is list:
            carried.update(ref for ref in cast(list[JsonValue], linked) if type(ref) is str)
    for raw in assessments:
        if isinstance(raw, dict):
            ref = raw.get("finding_ref")
            if type(ref) is str and ref in local_check_refs:
                carried.add(ref)
    return carried & allowed


def _excerpt_row_content_refs(
    section: object, category: object, source_ref: object, linked: object
) -> tuple[str, ...]:
    """The refs one excerpt row's content holds; see ``excerpt_content_refs``."""

    if section != "excerpt" or type(source_ref) is not str:
        return ()
    if source_ref == _CHECK_TIME_CHANGE_SOURCE_REF and type(linked) in {list, tuple}:
        # A current file section a follow-up served links the requested edit it answers (tb4n5);
        # the change's own parts link claims, obligations or the plan, never an ``evd_``.
        return (
            source_ref,
            *(
                ref
                for ref in cast(list[object] | tuple[object, ...], linked)
                if type(ref) is str and ref.startswith("evd_")
            ),
        )
    if (
        category != DataCategory.EVIDENCE_EXCERPT.value
        or not source_ref.startswith("evd_")
        or type(linked) not in {list, tuple}
    ):
        return (source_ref,)
    parts = (
        ref
        for ref in cast(list[object] | tuple[object, ...], linked)
        if type(ref) is str and ref.startswith("evd_")
    )
    return (source_ref, *parts)


def excerpt_content_refs(items: Iterable[SemanticCaseItem]) -> frozenset[str]:
    """The refs whose content these items' excerpts hold (issue #1047).

    Each excerpt's ``source_ref``; a multi-part captured group is one evidence excerpt keyed by
    its lead, and also holds the other parts' bytes, its ``evd_`` linked references, as
    ``review_packet_disclosure_result`` counts a carried group. A reviewer may name any part.
    """

    return frozenset(
        ref
        for item in items
        for ref in _excerpt_row_content_refs(
            item.section, item.category.value, item.source_ref, item.linked_subject_refs
        )
    )


def _sent_excerpt_item_ids(
    case: SemanticCase, provider_manifest: Mapping[str, object] | None
) -> frozenset[str] | None:
    """The excerpt item ids the exact sent packet carried, from its provider-bound manifest."""

    if type(case) is not SemanticCase:
        raise TypeError("semantic_case_invalid")
    manifest = _decode_review_input_manifest(provider_manifest, expected_phase="provider_bound")
    if manifest is None:
        return None
    return frozenset(
        item_id
        for section in (
            manifest.current_diff,
            manifest.caller_evidence,
            manifest.latest_verification,
        )
        for item_id in section.selected_item_ids
    )


def sent_excerpt_content_refs(
    case: SemanticCase, provider_manifest: Mapping[str, object] | None
) -> frozenset[str] | None:
    """The ``excerpt_content_refs`` the exact sent packet's excerpts held whole (issue #1047).

    Read from the packet's provider-bound input manifest, whose sections name the rows that
    crossed the provider boundary after envelope bounding, privacy admission and minimization;
    an excerpt the case composed and the sent packet lost is not among them. A source split into
    parts counts only when every part it has was sent (tb4n5): a capture whose first part alone
    reached the reviewer still has parts an in-check follow-up may add. ``None`` when that
    manifest is unknown (not retained, or unreadable), so nothing is claimed shown.
    """

    sent = _sent_excerpt_item_ids(case, provider_manifest)
    if sent is None:
        return None
    placed = _parts_by_item(case.excerpt_parts)
    sent_keys = [key for item_id in sent for key in placed.get(item_id, ())]
    return excerpt_content_refs(
        item
        for item in case.items
        if item.item_id in sent
        and (item.item_id not in placed or excerpt_span_whole(placed[item.item_id][0], sent_keys))
    )


def sent_excerpt_parts(
    case: SemanticCase, provider_manifest: Mapping[str, object] | None
) -> frozenset[str] | None:
    """The excerpt parts (``excerpt_span_key``) the exact sent packet carried (tb4n5).

    What an in-check follow-up compares, per part and never per source, so a later part of a
    partly shown source counts as progress and a repeated one does not. ``None`` when the
    provider-bound manifest is unknown.
    """

    sent = _sent_excerpt_item_ids(case, provider_manifest)
    if sent is None:
        return None
    return frozenset(key for item_id, key in case.excerpt_parts if item_id in sent)


def follow_up_new_parts(
    case: SemanticCase,
    follow_up: ReviewFollowUp,
    *,
    withheld_categories: Iterable[str] = (),
    carried_item_ids: Iterable[str] | None = None,
) -> frozenset[str]:
    """The requested excerpt parts this follow-up case carries that no sent packet carried.

    A follow-up round is sent only when this is not empty (issue #1047, tb4n5): an excerpt
    holding a source the round asks for (``excerpt_content_refs``, a served current section
    included) that the first packet did not show whole and no round completed, whose part no
    sent packet of the check carried. An item of a category the channel withholds never counts:
    it would not travel. ``carried_item_ids``, when given, are the items admission keeps (the
    bounded envelope's catalog and the channel's admission): an item it drops never counts,
    so a round whose new parts all fall to admission is never sent. An excerpt that cannot be
    placed in its source counts by its id, as the source-level rule always did.
    """

    if type(case) is not SemanticCase or type(follow_up) is not ReviewFollowUp:
        raise TypeError("semantic_case_invalid")
    withheld = frozenset(withheld_categories)
    carried = None if carried_item_ids is None else frozenset(carried_item_ids)
    wanted = follow_up.source_refs - follow_up.shown_refs - follow_up.added_refs
    placed = _parts_by_item(case.excerpt_parts)
    new: set[str] = set()
    for item in case.items:
        if item.section != "excerpt" or item.category.value in withheld:
            continue
        if carried is not None and item.item_id not in carried:
            continue
        refs = frozenset(
            _excerpt_row_content_refs(
                item.section, item.category.value, item.source_ref, item.linked_subject_refs
            )
        )
        keys = placed.get(item.item_id)
        observed = bool(_observed_span_refs(keys or ()) & follow_up.source_refs)
        if not refs & (
            # A served current section, and a marked observed-command excerpt, answer even
            # when the first packet showed the underlying ref whole. Whether the bytes are
            # new is the part test below.
            follow_up.source_refs
            if item.source_ref == _CHECK_TIME_CHANGE_SOURCE_REF or observed
            else wanted
        ):
            continue
        if keys is None:
            new.add(item.item_id)
        else:
            new.update(follow_up.unseen(keys))
    return frozenset(new)


def bounded_catalog_item_ids(case: SemanticCase) -> frozenset[str]:
    """The item ids whose catalog rows ``bounded_case_envelope`` keeps: what can travel."""

    if type(case) is not SemanticCase:
        raise TypeError("semantic_case_invalid")
    return _catalog_item_ids(
        cast(Mapping[str, JsonValue], strict_json_parse(bounded_case_envelope(case)))
    )


def _follow_up_supplied_item_ids(
    items: Iterable[SemanticCaseItem],
    placed: Mapping[str, Sequence[str]],
    follow_up: ReviewFollowUp,
) -> frozenset[str]:
    """The excerpts that supply a follow-up item beyond the check's first packet (tb4n5).

    An excerpt holding a requested source (a served current section for the edit it answers)
    with a part the first packet did not carry. Marked in the envelope's catalog so the
    provider-bound manifest says ``supplied`` only for such an excerpt that admission kept.
    """

    supplied: set[str] = set()
    for item in items:
        if item.section != "excerpt":
            continue
        refs = (
            frozenset(
                _excerpt_row_content_refs(
                    item.section, item.category.value, item.source_ref, item.linked_subject_refs
                )
            )
            & follow_up.source_refs
        )
        keys = placed.get(item.item_id, ())
        if item.source_ref != _CHECK_TIME_CHANGE_SOURCE_REF and not (
            _observed_span_refs(keys) & follow_up.source_refs
        ):
            refs -= follow_up.shown_refs
        if refs and (
            not keys or any(not excerpt_span_covered(key, follow_up.shown_parts) for key in keys)
        ):
            supplied.add(item.item_id)
    return frozenset(supplied)


def withheld_excerpt_content_refs(case: SemanticCase, withheld: frozenset[str]) -> frozenset[str]:
    """``withheld`` and what this case's excerpts keyed by a withheld ref hold (issue #1047).

    An omission row names a withheld captured group by its lead evidence alone; the group's other
    parts were withheld with it, so a request naming any part is the same limit as one naming
    the lead.
    """

    if type(case) is not SemanticCase:
        raise TypeError("semantic_case_invalid")
    return withheld | excerpt_content_refs(
        item for item in case.items if item.source_ref in withheld
    )


def _provider_bound_input_manifest(
    composed: Mapping[str, JsonValue],
    content_rows: Sequence[Mapping[str, JsonValue]],
    omissions: Sequence[JsonValue],
    *,
    redacted_item_ids: frozenset[str] | set[str] = frozenset(),
    privacy_withheld_refs: frozenset[str] = frozenset(),
) -> dict[str, JsonValue]:
    """Project a composed input manifest onto the exact provider-bound rows.

    In a follow-up packet a request is ``supplied`` only through a carried excerpt row the
    builder marked ``follow_up_supplied`` (tb4n5): an old part the first packet already carried
    never stands in for new parts admission dropped. The mark travels on the row itself, so a
    reader re-deriving this projection from the sent packet reaches the same answer.
    """

    carried_by_id = {
        item_id: row for row in content_rows if type(item_id := row.get("item_id")) is str
    }
    omission_rows = [
        cast(Mapping[str, JsonValue], row) for row in omissions if isinstance(row, Mapping)
    ]
    projected: dict[str, JsonValue] = {
        "phase": "provider_bound",
        # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
        "schema": "yoetz.review-input-manifest/1",
    }
    if composed.get("review_phase") in {"routine", "final"}:
        projected["review_phase"] = composed["review_phase"]
    if type(composed.get("follow_up_round")) is int:
        # Issue #1047: the round is the packet's own fact; its rows are fenced below like any.
        projected["follow_up_round"] = composed["follow_up_round"]
    section_names = (
        "specification",
        "current_diff",
        "caller_evidence",
        "latest_verification",
        "prior_finding_context",
    )
    total_excerpt_bytes = 0
    for name in section_names:
        raw = composed.get(name)
        if not isinstance(raw, dict):
            continue
        section = dict(raw)
        raw_ids = section.get("item_ids")
        item_ids = (
            [
                item_id
                for item_id in cast(list[object], raw_ids)
                if type(item_id) is str and item_id in carried_by_id
            ]
            if type(raw_ids) is list
            else []
        )
        original_refs = (
            {ref for ref in cast(list[object], section.get("source_refs")) if type(ref) is str}
            if type(section.get("source_refs")) is list
            else set[str]()
        )
        if type(section.get("omitted_refs")) is list:
            original_refs.update(
                ref for ref in cast(list[object], section.get("omitted_refs")) if type(ref) is str
            )
        section_omissions = [
            row
            for row in omission_rows
            if type(row.get("subject_ref")) is str
            and cast(str, row["subject_ref"]) in original_refs
        ]
        section["item_ids"] = cast(JsonValue, item_ids)
        selected_bytes = sum(
            content_bytes
            for item_id in item_ids
            for content_bytes in (carried_by_id[item_id].get("content_bytes", 0),)
            if type(content_bytes) is int
        )
        section["content_bytes"] = selected_bytes
        section_refs = [
            cast(str, carried_by_id[item_id].get("source_ref"))
            for item_id in item_ids
            if type(carried_by_id[item_id].get("source_ref")) is str
        ]
        section["source_refs"] = cast(JsonValue, sorted(set(section_refs), key=str.encode)[:16])
        original_status = section.get("status")
        rendered_digest: str | None = None
        if name == "specification" and item_ids:
            row = carried_by_id[item_ids[0]]
            try:
                rendered = strict_json_parse(cast(str, row.get("content", "")).encode("utf-8"))
            except TypeError, ValueError:
                rendered = None
            if isinstance(rendered, dict) and type(rendered.get("statement")) is str:
                statement = cast(str, rendered["statement"])
                raw_statement = statement.encode("utf-8")
                rendered_digest = "sha256:" + hashlib.sha256(raw_statement).hexdigest()
                section["content_bytes"] = len(raw_statement)
                if rendered.get("elided_bytes") not in {0, None}:
                    section["status"] = "partial"
            else:
                rendered_digest = cast(str | None, row.get("content_digest"))
        elif item_ids:
            rendered_digest = canonical_digest(
                cast(
                    JsonValue,
                    {
                        "items": [
                            {
                                "content_bytes": row.get("content_bytes", 0),
                                "content_digest": row.get("content_digest", ""),
                                "item_id": item_id,
                            }
                            for item_id in item_ids
                            for row in (carried_by_id[item_id],)
                        ],
                        # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
                        "schema": "yoetz.review-input-manifest-content/1",
                    },
                )
            )
        section["content_digest"] = rendered_digest
        if any(item_id in redacted_item_ids for item_id in item_ids):
            section["status"] = "partial"
        if item_ids:
            if (
                type(raw_ids) is list
                and len(item_ids) < len(raw_ids)
                and original_status not in {"title_only", "missing", "withheld"}
            ):
                section["status"] = "partial"
            elif (
                original_status == "complete"
                and type(section.get("content_digest")) is str
                and type(raw.get("content_digest")) is str
                and (
                    section["content_digest"] != raw["content_digest"]
                    or (
                        type(raw.get("content_bytes")) is int
                        and section["content_bytes"] != raw["content_bytes"]
                    )
                )
            ):
                # A row can be admitted while its rendered content was clipped or rematerialized.
                # Keep the provider-bound status partial until the caller can inspect the exact
                # effective digest and byte length.
                section["status"] = "partial"
        elif (
            type(raw_ids) is list
            and raw_ids
            and original_status
            not in {
                "title_only",
                "missing",
                "withheld",
            }
        ):
            section["status"] = "withheld"
        elif original_status == "title_only":
            section["status"] = "withheld"
        prior_omitted = (
            [ref for ref in cast(list[object], section.get("omitted_refs")) if type(ref) is str]
            if type(section.get("omitted_refs")) is list
            else []
        )
        section_omitted_refs = [
            cast(str, row["subject_ref"])
            for row in section_omissions
            if type(row.get("subject_ref")) is str
        ]
        section["omitted_refs"] = cast(
            JsonValue,
            sorted(set([*prior_omitted, *section_omitted_refs]), key=str.encode)[:16],
        )
        prior_reasons = (
            [
                reason
                for reason in cast(list[object], section.get("omission_reasons"))
                if type(reason) is str
            ]
            if type(section.get("omission_reasons")) is list
            else []
        )
        omission_reasons: set[str] = set(prior_reasons)
        if any(item_id in redacted_item_ids for item_id in item_ids):
            omission_reasons.add("redacted_never_send")
        # Packet omission rows name a heuristic withholding ``never_send_heuristic``; the section
        # manifest's closed vocabulary (``ports/semantic.py``) records the same loss as
        # ``redacted_never_send``.  Copying the row reason verbatim made the provider-bound
        # manifest undecodable and dropped its ``review_phase`` (issue #979).
        omission_reasons.update(
            _SECTION_OMISSION_REASON_ALIASES.get(reason, reason)
            for row in section_omissions
            for reason in (row.get("reason"),)
            if type(reason) is str
        )
        section["omission_reasons"] = cast(
            JsonValue, sorted(omission_reasons, key=lambda value: value.encode())[:8]
        )
        projected[name] = cast(JsonValue, section)
        total_excerpt_bytes += sum(
            content_bytes
            for item_id in item_ids
            if carried_by_id[item_id].get("section") == "excerpt"
            for content_bytes in (carried_by_id[item_id].get("content_bytes", 0),)
            if type(content_bytes) is int
        )
    # This is the count of rows that actually crossed the provider boundary.  Section manifests
    # intentionally cover only their five named input families; structural goal/claim/decision/
    # timeline rows are still part of ``items`` and must be included in the final accounting.
    projected["selected_item_count"] = len(content_rows)
    projected["selected_excerpt_bytes"] = total_excerpt_bytes
    projected["omitted_item_count"] = min(MAX_REVIEW_OMISSIONS, len(omission_rows))
    composed_listed = composed.get("omitted_item_count")
    composed_total = composed.get("omitted_item_total")
    if type(composed_total) is int and type(composed_listed) is int:
        # The composed total, plus every row egress added beyond the rows the composed case
        # listed (content withheld or trimmed after composition); never below the rows listed.
        projected["omitted_item_total"] = min(
            MAX_REVIEW_OMISSION_TOTAL,
            max(
                len(omission_rows),
                composed_total + max(0, len(omission_rows) - composed_listed),
            ),
        )
    admitted_refs = {
        cast(str, row["source_ref"]) for row in content_rows if type(row.get("source_ref")) is str
    }
    admitted_refs.update(
        ref
        for row in content_rows
        if type(row.get("linked_subject_refs")) is list
        for ref in cast(list[object], row["linked_subject_refs"])
        if type(ref) is str
    )
    if "follow_up_round" in projected:
        # Issue #1047: what FinishUP added is excerpt content; a ref the sent rows only link to was
        # not added, so only what carried excerpt rows hold counts (a group's parts included).
        admitted_refs = {
            ref
            for row in content_rows
            if row.get("follow_up_supplied") is True
            for ref in _excerpt_row_content_refs(
                row.get("section"),
                row.get("category"),
                row.get("source_ref"),
                row.get("linked_subject_refs"),
            )
        }
    missing_rows: list[JsonValue] = []
    raw_missing = composed.get("missing_inputs")
    if type(raw_missing) is list:
        for raw in cast(list[object], raw_missing):
            if not isinstance(raw, dict):
                continue
            row = dict(cast(dict[str, JsonValue], raw))
            composed_supplied = [
                ref for ref in cast(list[object], row.get("supplied_refs", [])) if type(ref) is str
            ]
            supplied = [ref for ref in composed_supplied if ref in admitted_refs]
            row["supplied_refs"] = cast(JsonValue, supplied)
            if row.get("status") == "supplied" and not supplied:
                # Admission cuts can still be supplied later; privacy-withheld sources cannot.
                # Keep the dispatched round counted, but never present its exhausted request as
                # pending work or as content the provider saw.
                row["status"] = (
                    "unavailable"
                    if composed_supplied and set(composed_supplied) <= privacy_withheld_refs
                    else "pending"
                )
            missing_rows.append(cast(JsonValue, row))
    projected["missing_inputs"] = missing_rows
    return projected


_REVIEW_INPUT_MANIFEST_KEYS: Final = frozenset(
    {
        "caller_evidence",
        "current_diff",
        "latest_verification",
        "missing_inputs",
        "omitted_item_count",
        "phase",
        "prior_finding_context",
        "schema",
        "selected_excerpt_bytes",
        "selected_item_count",
        "specification",
    }
)
_REVIEW_INPUT_SECTION_KEYS: Final = frozenset(
    {
        "content_bytes",
        "content_digest",
        "item_ids",
        "omission_reasons",
        "omitted_refs",
        "revision",
        "source_refs",
        "status",
    }
)
_REVIEW_INPUT_MISSING_KEYS: Final = frozenset({"kind", "status", "supplied_refs", "target_refs"})
_REVIEW_INPUT_SECTION_NAMES: Final = (
    "specification",
    "current_diff",
    "caller_evidence",
    "latest_verification",
    "prior_finding_context",
)


def _tuple_strings(value: object, *, maximum: int) -> tuple[str, ...] | None:
    """Decode one bounded JSON string array for the typed input-manifest model."""

    if type(value) not in {list, tuple}:
        return None
    values = tuple(cast(list[object] | tuple[object, ...], value))
    if len(values) > maximum or any(type(item) is not str for item in values):
        return None
    return cast(tuple[str, ...], values)


def _decode_review_input_manifest(
    raw: object, *, expected_phase: Literal["composed", "provider_bound"]
) -> ReviewInputManifest | None:
    """Validate a wire manifest through the domain model before exposing it in disclosure."""

    if not isinstance(raw, Mapping):
        return None
    body = cast(Mapping[str, object], raw)
    if (
        any(type(key) is not str for key in body)
        or frozenset(body) - {"review_phase", "omitted_item_total", "follow_up_round"}
        != _REVIEW_INPUT_MANIFEST_KEYS
        or body.get("review_phase", "routine") not in {"routine", "final"}
    ):
        return None
    schema = body.get("schema")
    phase = body.get("phase")
    # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
    if schema != "yoetz.review-input-manifest/1" or phase != expected_phase:
        return None

    section_values: dict[str, ReviewInputSection] = {}
    for name in _REVIEW_INPUT_SECTION_NAMES:
        value = body.get(name)
        if not isinstance(value, Mapping):
            return None
        section = cast(Mapping[str, object], value)
        if (
            any(type(key) is not str for key in section)
            or frozenset(section) != _REVIEW_INPUT_SECTION_KEYS
        ):
            return None
        status = section.get("status")
        revision = section.get("revision")
        content_digest = section.get("content_digest")
        content_bytes = section.get("content_bytes")
        if (
            type(status) is not str
            or (revision is not None and type(revision) is not int)
            or (content_digest is not None and type(content_digest) is not str)
            or type(content_bytes) is not int
        ):
            return None
        source_refs = _tuple_strings(section.get("source_refs"), maximum=16)
        item_ids = _tuple_strings(section.get("item_ids"), maximum=MAX_REVIEW_INPUT_SECTION_ITEMS)
        omitted_refs = _tuple_strings(section.get("omitted_refs"), maximum=16)
        omission_reasons = _tuple_strings(section.get("omission_reasons"), maximum=8)
        if (
            source_refs is None
            or item_ids is None
            or omitted_refs is None
            or omission_reasons is None
        ):
            return None
        try:
            section_values[name] = ReviewInputSection(
                name=name,
                status=cast(
                    Literal[
                        "complete",
                        "partial",
                        "title_only",
                        "missing",
                        "withheld",
                        "not_selected",
                    ],
                    status,
                ),
                source_refs=source_refs,
                selected_item_ids=item_ids,
                omitted_refs=omitted_refs,
                omission_reasons=omission_reasons,
                revision=revision,
                content_digest=content_digest,
                content_bytes=content_bytes,
            )
        except TypeError, ValueError:
            return None

    missing_raw = body.get("missing_inputs")
    if type(missing_raw) not in {list, tuple}:
        return None
    missing_rows: list[ReviewInputMissing] = []
    for value in cast(list[object] | tuple[object, ...], missing_raw):
        if not isinstance(value, Mapping):
            return None
        row = cast(Mapping[str, object], value)
        if any(type(key) is not str for key in row) or frozenset(row) != _REVIEW_INPUT_MISSING_KEYS:
            return None
        kind = row.get("kind")
        status = row.get("status")
        target_refs = _tuple_strings(row.get("target_refs"), maximum=4)
        supplied_refs = _tuple_strings(row.get("supplied_refs"), maximum=4)
        if (
            type(kind) is not str
            or type(status) is not str
            or target_refs is None
            or supplied_refs is None
        ):
            return None
        try:
            missing_rows.append(
                ReviewInputMissing(
                    kind=cast(MissingForAssessmentKind, kind),
                    target_refs=target_refs,
                    supplied_refs=supplied_refs,
                    status=cast(Literal["pending", "supplied", "unavailable", "repeated"], status),
                )
            )
        except TypeError, ValueError:
            return None

    selected_item_count = body.get("selected_item_count")
    selected_excerpt_bytes = body.get("selected_excerpt_bytes")
    omitted_item_count = body.get("omitted_item_count")
    omitted_item_total = body.get("omitted_item_total")
    if (
        type(selected_item_count) is not int
        or type(selected_excerpt_bytes) is not int
        or type(omitted_item_count) is not int
        or (omitted_item_total is not None and type(omitted_item_total) is not int)
    ):
        return None
    try:
        return ReviewInputManifest(
            # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
            schema=cast(Literal["yoetz.review-input-manifest/1"], schema),
            specification=section_values["specification"],
            current_diff=section_values["current_diff"],
            caller_evidence=section_values["caller_evidence"],
            latest_verification=section_values["latest_verification"],
            prior_finding_context=section_values["prior_finding_context"],
            phase=cast(Literal["composed", "provider_bound"], phase),
            missing_inputs=tuple(missing_rows),
            selected_item_count=selected_item_count,
            selected_excerpt_bytes=selected_excerpt_bytes,
            omitted_item_count=omitted_item_count,
            omitted_item_total=omitted_item_total,
            review_phase=cast(Literal["routine", "final"] | None, body.get("review_phase")),
            follow_up_round=cast(int | None, body.get("follow_up_round")),
        )
    except KeyError, TypeError, ValueError:
        return None


@dataclass(frozen=True, slots=True)
class ReviewPacketDisclosure:
    """What one exact sent review packet carried, read from its provider-facing bytes (#904).

    ``carried`` holds the frontier references whose own content item survived: the ``source_ref``
    of a carried item, plus the member evidence of a carried multi-part evidence excerpt (its
    ``evd_`` linked references, whose bytes that excerpt combines). Every reference any omission row
    names is removed, except that an earlier finding whose structural prior-finding row was carried
    stays unless an omission row withholds it (issue #947). ``withheld`` holds the references an
    omission row names for a reason other than ``not_recorded``: that reason means the ledger had no
    more readable content for the record than its own recorded payload. ``payload_events`` are the
    carried ``evt_`` history items whose own content holds the event's recorded payload, read from
    the item itself: a structural-only item or one replaced by the size-bound marker is not one,
    whatever omission rows survived the omission cap.
    """

    carried: frozenset[str]
    withheld: frozenset[str]
    payload_events: frozenset[str]
    # tb4n1 D1: the subset of ``withheld`` an owner privacy rule withheld (policy, never-send),
    # so a reviewer request for it is a privacy limit, not packet room.
    privacy_withheld: frozenset[str] = frozenset()
    # Metadata emitted from the exact provider-bound packet after privacy admission and
    # minimization.  This is kept separate from the composed manifest so a receipt cannot
    # accidentally report pre-admission selection as provider delivery.
    provider_input_manifest: JsonObject | None = None
    # Ephemeral safe text view of the exact provider-bound rows.  It is used only while fencing
    # reviewer quotes and is never serialized into a check result or response object.  A source
    # ref may have more than one row, so retain all exact row texts rather than choosing one.
    provider_input_text_by_ref: Mapping[str, tuple[str, ...]] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class ReviewPacketDisclosureResult:
    """Disclosure plus a closed reason when provider-bound metadata was not retained."""

    disclosure: ReviewPacketDisclosure | None
    failure: str | None = None

    def __post_init__(self) -> None:
        if self.failure not in {
            None,
            SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP,
            SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP,
            SEMANTIC_PROVIDER_INPUT_MANIFEST_PARSE_FAILED_GAP,
            SEMANTIC_PROVIDER_INPUT_MANIFEST_MISMATCH_GAP,
        }:
            raise ValueError("review_packet_disclosure_failure_invalid")
        if self.failure is None and self.disclosure is None:
            raise ValueError("review_packet_disclosure_result_invalid")


_PRIVACY_OMISSION_REASONS: Final = frozenset(
    {"withheld_by_policy", "redacted_never_send", "never_send_heuristic"}
)


def review_packet_disclosure(prepared: bytes) -> ReviewPacketDisclosure | None:
    """Read a sent packet, preserving the historical ``None`` compatibility result."""

    result = review_packet_disclosure_result(prepared)
    # Keep the pre-#965 helper's fail-closed contract for existing callers.  The egress mapper
    # uses ``review_packet_disclosure_result`` when it needs the bounded provenance reason.
    return (
        result.disclosure
        if result.failure in {None, SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP}
        else None
    )


def review_packet_disclosure_result(prepared: bytes) -> ReviewPacketDisclosureResult:
    """Read what the sent review packet carried, after envelope bounding and minimization.

    A mention in another item's content, a typed link (other than the combined parts of a carried
    evidence excerpt), the citable-reference list, or an omission row never counts as carried.
    ``disclosure`` is ``None`` when the document is not a readable review packet.  A readable
    packet with a missing or invalid provider-bound manifest keeps its carried-reference
    projection but returns a closed ``failure`` so callers cannot substitute the composed case.
    """

    try:
        document = strict_json_parse(prepared)
    except ValueError:
        return ReviewPacketDisclosureResult(None, SEMANTIC_PROVIDER_INPUT_MANIFEST_PARSE_FAILED_GAP)
    if not isinstance(document, dict) or document.get("schema") != _PACKET_SCHEMA:
        return ReviewPacketDisclosureResult(None, SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP)
    frontier_raw = document.get("frontier_refs")
    items_raw = document.get("items")
    packet_raw = document.get("review_packet")
    if (
        type(frontier_raw) is not list
        or type(items_raw) is not list
        or not isinstance(packet_raw, dict)
    ):
        return ReviewPacketDisclosureResult(None, SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP)
    frontier = {ref for ref in cast(list[JsonValue], frontier_raw) if type(ref) is str}
    provider_present = "provider_input_manifest" in packet_raw
    provider_raw = packet_raw.get("provider_input_manifest")
    omissions_raw = packet_raw.get("omissions", [])
    structural_failure = (
        SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP if type(omissions_raw) is not list else None
    )
    omission_rows = omissions_raw if type(omissions_raw) is list else []
    omitted: set[str] = set()
    withheld: set[str] = set()
    privacy_withheld: set[str] = set()
    for row in cast(list[JsonValue], omission_rows):
        if not isinstance(row, dict) or type(subject := row.get("subject_ref")) is not str:
            continue
        omitted.add(subject)
        if row.get("reason") != "not_recorded":
            withheld.add(subject)
        if row.get("reason") in _PRIVACY_OMISSION_REASONS:
            privacy_withheld.add(subject)
    carried: set[str] = set()
    payload_events: set[str] = set()
    finding_rows: set[str] = set()
    redacted_item_ids: set[str] = set()
    provider_text_by_ref: dict[str, list[str]] = {}
    for row in cast(list[JsonValue], items_raw):
        if not isinstance(row, dict) or type(source := row.get("source_ref")) is not str:
            continue
        item_id = row.get("item_id")
        transformations = row.get("transformations")
        if type(item_id) is str and type(transformations) is list:
            for transformation in cast(list[object], transformations):
                if not isinstance(transformation, dict):
                    continue
                typed_transformation = cast(Mapping[str, object], transformation)
                if (
                    typed_transformation.get("kind") == "redacted"
                    and typed_transformation.get("reason") == "sensitive_redacted"
                ):
                    redacted_item_ids.add(item_id)
                    break
        content = row.get("content")
        if type(content) is str:
            provider_text_by_ref.setdefault(source, []).append(content)
            linked_for_text = row.get("linked_subject_refs")
            if type(linked_for_text) is list:
                for linked_ref in cast(list[JsonValue], linked_for_text):
                    if type(linked_ref) is str:
                        provider_text_by_ref.setdefault(linked_ref, []).append(content)
        if row.get("section") == "prior_finding":
            # An earlier finding counts as sent only through its structural row, which names its
            # subjects, the requested step and the agent's answer (issue #947); its prose rows
            # alone do not. A ``not_recorded`` omission on its prose (a finding recorded before
            # challenge fields existed) leaves that row as everything the ledger holds for it.
            if row.get("item_id") == f"prior-finding-{source}":
                finding_rows.add(source)
            continue
        carried.add(source)
        category = row.get("category")
        if source.startswith("evt_") and _history_item_carries_payload(source, row.get("content")):
            payload_events.add(source)
        linked = row.get("linked_subject_refs")
        if (
            row.get("section") == "excerpt"
            and category == DataCategory.EVIDENCE_EXCERPT.value
            and source.startswith("evd_")
            and source not in omitted
            and type(linked) is list
        ):
            # A multi-part captured group is one excerpt keyed by its lead evidence; the other
            # parts' bytes are combined into it, and only those parts are linked as ``evd_``.
            carried.update(
                ref
                for ref in cast(list[JsonValue], linked)
                if type(ref) is str and ref.startswith("evd_")
            )
    # This check's local findings reach the reviewer as assessment rows, not content rows. A
    # surviving row is text the provider received for that finding, so it proves the finding was
    # sent: a challenge may anchor to it and quote it (issue #976). It is not a carried frontier
    # ref, so it never enters ``kept``.
    local_raw = document.get("local_check_refs")
    local_refs = (
        {ref for ref in cast(list[JsonValue], local_raw) if type(ref) is str}
        if type(local_raw) is list
        else set[str]()
    )
    assessments_raw = packet_raw.get("deterministic_assessments")
    if type(assessments_raw) is list:
        for raw_row in cast(list[JsonValue], assessments_raw):
            if not isinstance(raw_row, dict):
                continue
            finding_ref = raw_row.get("finding_ref")
            if type(finding_ref) is str and finding_ref in local_refs:
                provider_text_by_ref.setdefault(finding_ref, []).append(
                    canonical_encode(raw_row).decode("utf-8")
                )
    kept = frozenset(((carried & frontier) - omitted) | ((finding_rows & frontier) - withheld))
    provider_manifest: JsonObject | None = None
    failure: str | None = structural_failure or (
        SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP if not provider_present else None
    )
    if provider_present:
        if not isinstance(provider_raw, dict):
            failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP
        elif _decode_review_input_manifest(provider_raw, expected_phase="provider_bound") is None:
            failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP
        else:
            try:
                frozen_provider = freeze_json(cast(JsonValue, provider_raw))
            except TypeError, ValueError:
                failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP
            else:
                if type(frozen_provider) is not JsonObject:
                    failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP
                elif (
                    # Frozen legacy identifier (ADR-048): protocol 0.1 tag, re-verified.
                    frozen_provider.get("schema") != "yoetz.review-input-manifest/1"
                    or frozen_provider.get("phase") != "provider_bound"
                ):
                    failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP
                else:
                    composed_raw = packet_raw.get("review_input_manifest")
                    if (
                        _decode_review_input_manifest(composed_raw, expected_phase="composed")
                        is None
                    ):
                        failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP
                    else:
                        content_rows: list[Mapping[str, JsonValue]] = []
                        content_item_ids: set[str] = set()
                        for row in cast(list[JsonValue], items_raw):
                            if not isinstance(row, dict) or type(row.get("item_id")) is not str:
                                failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP
                                break
                            item_id = cast(str, row["item_id"])
                            if item_id in content_item_ids:
                                failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP
                                break
                            content_item_ids.add(item_id)
                            content_rows.append(cast(Mapping[str, JsonValue], row))
                        if failure is None:
                            targeted_raw = packet_raw.get("targeted_excerpts")
                            if type(targeted_raw) is list:
                                for raw_row in cast(list[object], targeted_raw):
                                    if not isinstance(raw_row, dict):
                                        continue
                                    row = cast(
                                        Mapping[str, JsonValue],
                                        cast(dict[str, JsonValue], raw_row),
                                    )
                                    item_id = row.get("excerpt_item_id")
                                    if (
                                        row.get("content_visibility") == "redacted_never_send"
                                        and type(item_id) is str
                                    ):
                                        redacted_item_ids.add(item_id)
                            expected = _provider_bound_input_manifest(
                                cast(Mapping[str, JsonValue], composed_raw),
                                content_rows,
                                cast(list[JsonValue], omission_rows),
                                redacted_item_ids=redacted_item_ids,
                            )
                            try:
                                frozen_expected = freeze_json(cast(JsonValue, expected))
                            except TypeError, ValueError:
                                failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_MISMATCH_GAP
                            else:
                                if (
                                    type(frozen_expected) is not JsonObject
                                    or frozen_expected != frozen_provider
                                ):
                                    failure = SEMANTIC_PROVIDER_INPUT_MANIFEST_MISMATCH_GAP
                                else:
                                    provider_manifest = frozen_provider
    disclosure = ReviewPacketDisclosure(
        carried=kept,
        withheld=frozenset(withheld & frontier),
        privacy_withheld=frozenset(privacy_withheld & frontier),
        payload_events=frozenset(payload_events) & kept,
        provider_input_manifest=provider_manifest,
        provider_input_text_by_ref=MappingProxyType(
            {
                ref: tuple(texts)
                for ref, texts in sorted(
                    provider_text_by_ref.items(), key=lambda item: item[0].encode()
                )
            }
        ),
    )
    return ReviewPacketDisclosureResult(disclosure, failure)


def _history_item_carries_payload(event_ref: str, content: JsonValue | None) -> bool:
    """Whether a carried history item's own content holds this event's recorded payload."""

    if type(content) is not str:
        return False
    try:
        body = strict_json_parse(content.encode("utf-8"))
    except ValueError:
        return False
    return isinstance(body, dict) and body.get("event_id") == event_ref and "payload" in body


def review_packet_content_refs(prepared: bytes) -> frozenset[str] | None:
    """The frontier references whose own content the sent packet carried (see above)."""

    disclosure = review_packet_disclosure(prepared)
    return None if disclosure is None else disclosure.carried


def sent_ledger_refs(
    disclosure: ReviewPacketDisclosure, projection: ProjectionState
) -> frozenset[str]:
    """The ledger references a sent packet carried, including records carried by their event.

    With recorded history, an action, result, evidence, claim or obligation record usually travels
    as the history item of the event that recorded it, keyed by that ``evt_`` id; a superseded
    claim travels only that way (issue #947). Such a record counts as sent when that item carried
    its recorded payload and no omission row withholds the record itself (a ``not_recorded``
    omission does not: the payload is all the ledger holds for it). Evidence with a captured object
    never counts this way: its payload only describes bytes the reviewer needs to see, so it counts
    only when its own excerpt was carried, whatever the omission rows say. An unreadable record
    never counts. Each history item credits at most its one record, so the recorded set stays
    within ``MAX_SEMANTIC_INCLUDED_REFS``. The reverse direction, a carried record crediting the
    event that recorded it, is derived when a finding is resolved, from the same projection.
    """

    extra: set[str] = set()
    for family in (
        projection.actions,
        projection.results,
        projection.evidence,
        projection.claims,
        projection.obligations,
    ):
        for key, row in family.items():
            ref = str(key)
            if (
                ref in disclosure.carried
                or ref in disclosure.withheld
                or row.payload is None
                or row.redacted
                or getattr(row.payload, "captured_object_id", None) is not None
            ):
                continue
            if str(row.source_event_id) in disclosure.payload_events:
                extra.add(ref)
    return disclosure.carried | frozenset(extra)


class SemanticCaseTooLarge(ValueError):
    """The structural envelope cannot be reduced within its bound.

    Raised only when the irreducible core alone exceeds ``MAX_EGRESS_ENVELOPE_BYTES``. Every
    droppable row has already been removed and accounted for by then, so this is a genuine
    "this case cannot be reviewed", not a transient coordinator fault. Callers must map it to a
    terminal AI-powered review outcome rather than swallowing it as an unexpected exception.
    """


def _catalog_rows(envelope: Mapping[str, JsonValue]) -> list[dict[str, JsonValue]]:
    raw = envelope.get("item_catalog")
    if type(raw) is not list:
        return []
    return [
        cast(dict[str, JsonValue], row) for row in cast(list[object], raw) if isinstance(row, dict)
    ]


def _catalog_item_ids(envelope: Mapping[str, JsonValue]) -> frozenset[str]:
    ids: set[str] = set()
    for row in _catalog_rows(envelope):
        item_id = row.get("item_id")
        if type(item_id) is str:
            ids.add(item_id)
    return frozenset(ids)


def _drop_catalog_row(envelope: dict[str, JsonValue]) -> bool:
    """Remove the lowest-priority catalog row and every reference that would dangle.

    Catalog order is the case's own section/occurrence order, so the tail is the least
    structurally load-bearing row. Dropping a row without also dropping its ids would leave
    ``*_item_ids`` and ``targeted_excerpts`` pointing at an item the packet no longer carries.
    """

    rows = _catalog_rows(envelope)
    if not rows:
        return False
    dropped = rows.pop()
    envelope["item_catalog"] = cast(JsonValue, rows)
    dropped_id = dropped.get("item_id")
    if type(dropped_id) is not str:
        return True
    packet_obj = envelope.get("review_packet")
    if not isinstance(packet_obj, dict):
        return True
    for key in _PACKET_ID_LIST_KEYS:
        current = packet_obj.get(key)
        if type(current) is list:
            packet_obj[key] = cast(
                JsonValue,
                [
                    value
                    for value in cast(list[object], current)
                    if not (type(value) is str and value == dropped_id)
                ],
            )
    _sync_prior_finding_refs(packet_obj)
    excerpts = packet_obj.get("targeted_excerpts")
    if type(excerpts) is list:
        packet_obj["targeted_excerpts"] = cast(
            JsonValue,
            [
                row
                for row in cast(list[object], excerpts)
                if not (
                    isinstance(row, dict)
                    and cast(dict[str, object], row).get("excerpt_item_id") == dropped_id
                )
            ],
        )
    for key in ("summary_item_id", "detail_item_id"):
        assessments = packet_obj.get("deterministic_assessments")
        if type(assessments) is not list:
            continue
        for raw in cast(list[object], assessments):
            if isinstance(raw, dict) and cast(dict[str, object], raw).get(key) == dropped_id:
                cast(dict[str, object], raw).pop(key, None)
    return True


def _sync_prior_finding_refs(packet_obj: dict[str, JsonValue]) -> None:
    """Keep a rulable earlier finding only while its structural row is still carried (#905).

    ``prior_finding_refs`` is the list the reviewer rules on, one entry per finding. When bounding
    or approval removes a finding's structural row, the finding leaves that list too, so the
    reviewer is never asked to rule on a finding the packet no longer shows.
    """

    refs = packet_obj.get("prior_finding_refs")
    if type(refs) is not list:
        return
    ids = packet_obj.get("prior_finding_item_ids")
    carried = (
        {value for value in cast(list[object], ids) if type(value) is str}
        if type(ids) is list
        else set[str]()
    )
    packet_obj["prior_finding_refs"] = cast(
        JsonValue,
        [
            value
            for value in cast(list[object], refs)
            if type(value) is str and f"prior-finding-{value}" in carried
        ],
    )


def _drop_prior_finding_rows(envelope: dict[str, JsonValue]) -> int:
    """Remove prior-finding rows until the envelope fits (issue #905): settled findings first,
    then open findings oldest first.

    The dialogue section yields before any work content: every other row keeps exactly the
    bounding it had without the section. A finding's rows leave together, its ids leave the
    packet, and the packet coverage names the truncation.
    """

    rows = _catalog_rows(envelope)
    order: list[tuple[bool, str]] = []
    for row in rows:
        source = row.get("source_ref")
        item_id = row.get("item_id")
        if row.get("section") == "prior_finding" and type(source) is str:
            settled = type(item_id) is str and item_id.startswith(SETTLED_FINDING_ITEM_PREFIX)
            if (settled, source) not in order:
                order.append((settled, source))
    # Settled findings are context only: every one leaves before any open finding does, and only
    # an open finding's loss weakens a silent review (``semantic_prior_findings_over_limit``).
    # The catalog lists rows oldest first (section, then occurrence), so the oldest settled one
    # leaves first; the most recently settled is the one a reviewer is most likely to raise again.
    order.sort(key=lambda entry: not entry[0])
    dropped = 0
    packet_obj = envelope.get("review_packet")
    for settled, source in order:
        if len(canonical_encode(cast(JsonValue, envelope))) <= MAX_EGRESS_ENVELOPE_BYTES:
            break
        removed = {
            cast(str, row.get("item_id"))
            for row in rows
            if row.get("section") == "prior_finding"
            and row.get("source_ref") == source
            and str(row.get("item_id", "")).startswith(SETTLED_FINDING_ITEM_PREFIX) == settled
        }
        rows = [row for row in rows if row.get("item_id") not in removed]
        envelope["item_catalog"] = cast(JsonValue, rows)
        dropped += len(removed)
        if isinstance(packet_obj, dict):
            current = packet_obj.get("prior_finding_item_ids")
            if type(current) is list:
                packet_obj["prior_finding_item_ids"] = cast(
                    JsonValue,
                    [value for value in cast(list[object], current) if value not in removed],
                )
            _sync_prior_finding_refs(packet_obj)
            coverage = packet_obj.get("coverage")
            if not settled and isinstance(coverage, dict):
                gaps = coverage.get("known_gaps")
                if type(gaps) is list and SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP not in gaps:
                    coverage["known_gaps"] = cast(
                        JsonValue,
                        sorted(
                            [*cast(list[str], gaps), SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP],
                            key=str.encode,
                        ),
                    )
    return dropped


def _fit_packet_section(
    envelope: dict[str, JsonValue],
    reductions: dict[str, int],
    key: str,
    accounting_key: str,
) -> bytes | None:
    """Find the first fitting suffix reduction, or remove this section completely."""

    packet_obj = envelope.get("review_packet")
    if not isinstance(packet_obj, dict):
        return None
    rows = packet_obj.get(key)
    if type(rows) is not list or not rows:
        return None
    original_rows = cast(list[JsonValue], rows)
    total = len(original_rows)
    prior_count = reductions[accounting_key]

    def encode_after_dropping(count: int) -> bytes:
        packet_obj[key] = original_rows[: total - count]
        reductions[accounting_key] = prior_count + count
        _set_selection_accounting(envelope, reductions)
        return canonical_encode(cast(JsonValue, envelope))

    best = encode_after_dropping(total)
    if len(best) > MAX_EGRESS_ENVELOPE_BYTES:
        return None
    low, high = 1, total
    # Removing a row cannot increase encoded size: the row/comma bytes offset
    # any extra counter digit. Search the same first-fitting point as the old
    # one-row-at-a-time loop, including its exact selection accounting.
    while low < high:
        middle = (low + high) // 2
        candidate = encode_after_dropping(middle)
        if len(candidate) <= MAX_EGRESS_ENVELOPE_BYTES:
            high = middle
            best = candidate
        else:
            low = middle + 1
    return best


def _strip_assessment_links(envelope: dict[str, JsonValue]) -> int:
    """Drop assessment item-id links, which duplicate ids the catalog already carries."""

    packet_obj = envelope.get("review_packet")
    if not isinstance(packet_obj, dict):
        return 0
    rows = packet_obj.get("deterministic_assessments")
    if type(rows) is not list:
        return 0
    removed = 0
    for raw in cast(list[object], rows):
        if not isinstance(raw, dict):
            continue
        row = cast(dict[str, object], raw)
        for key in ("summary_item_id", "detail_item_id"):
            if row.pop(key, None) is not None:
                removed += 1
    return removed


def _set_selection_accounting(
    envelope: dict[str, JsonValue], reductions: Mapping[str, int]
) -> None:
    """Record what bounding removed, so a truncated packet can never read as a complete one."""

    minimized = any(count > 0 for count in reductions.values())
    envelope["selection_accounting"] = cast(
        JsonValue,
        {
            "assessment_links_stripped_count": str(reductions["assessment_links_stripped_count"]),
            "catalog_dropped_count": str(reductions["catalog_dropped_count"]),
            "change_observations_dropped_count": str(
                reductions["change_observations_dropped_count"]
            ),
            "deterministic_assessments_dropped_count": str(
                reductions["deterministic_assessments_dropped_count"]
            ),
            "omissions_dropped_count": str(reductions["omissions_dropped_count"]),
            "reason": "size_minimized" if minimized else "not_minimized",
            "targeted_excerpts_dropped_count": str(reductions["targeted_excerpts_dropped_count"]),
        },
    )


def bounded_case_envelope(case: SemanticCase) -> bytes:
    """Canonical case envelope guaranteed to fit ``MAX_EGRESS_ENVELOPE_BYTES``.

    The previous implementation was a fixed three-stage ladder whose last stage truncated the
    catalog to 64 rows — dead code, because a ``SemanticCase`` already admits at most 64 items.
    A real 44 KiB case therefore reduced to 38 KiB and then raised, stranding the whole check.

    Packet sections keep their declared priority and exact first-fitting suffix, found with a
    bounded search instead of re-encoding the whole document after every removed row. Catalog
    fallback still removes one row at a time with its reference cleanup. Anything removed is
    counted in ``selection_accounting`` so the packet and its receipt disclose minimization.
    """

    envelope = _case_envelope_json(case)
    reductions = {
        "assessment_links_stripped_count": 0,
        "catalog_dropped_count": 0,
        "change_observations_dropped_count": 0,
        "deterministic_assessments_dropped_count": 0,
        "omissions_dropped_count": 0,
        "targeted_excerpts_dropped_count": 0,
    }
    _set_selection_accounting(envelope, reductions)
    encoded = canonical_encode(cast(JsonValue, envelope))
    if len(encoded) <= MAX_EGRESS_ENVELOPE_BYTES:
        return encoded

    # Earlier findings yield before any work content (issue #905).
    reductions["catalog_dropped_count"] += _drop_prior_finding_rows(envelope)
    _set_selection_accounting(envelope, reductions)
    encoded = canonical_encode(cast(JsonValue, envelope))
    if len(encoded) <= MAX_EGRESS_ENVELOPE_BYTES:
        return encoded

    reductions["assessment_links_stripped_count"] += _strip_assessment_links(envelope)
    _set_selection_accounting(envelope, reductions)
    encoded = canonical_encode(cast(JsonValue, envelope))
    if len(encoded) <= MAX_EGRESS_ENVELOPE_BYTES:
        return encoded
    for key, accounting_key in (
        ("change_observations", "change_observations_dropped_count"),
        ("targeted_excerpts", "targeted_excerpts_dropped_count"),
        ("omissions", "omissions_dropped_count"),
        ("deterministic_assessments", "deterministic_assessments_dropped_count"),
    ):
        fitted = _fit_packet_section(envelope, reductions, key, accounting_key)
        if fitted is not None:
            return fitted
    while _drop_catalog_row(envelope):
        reductions["catalog_dropped_count"] += 1
        _set_selection_accounting(envelope, reductions)
        encoded = canonical_encode(cast(JsonValue, envelope))
        if len(encoded) <= MAX_EGRESS_ENVELOPE_BYTES:
            return encoded
    raise SemanticCaseTooLarge("semantic_case_envelope_too_large")


@dataclass(frozen=True, slots=True)
class SemanticPacketView:
    """What the reviewer is actually shown, for fencing its per-finding rulings (issue #905)."""

    prior_finding_refs: frozenset[str]
    citable_refs: frozenset[str]
    # Envelope bounding removed prior-finding rows the case had admitted.
    prior_findings_trimmed: bool
    # Findings the agent settled whose non-rulable row survived bounding: nameable in
    # ``restates``, never ruled on (issue #980).
    settled_finding_refs: frozenset[str] = frozenset()


def semantic_case_packet_view(case: SemanticCase) -> SemanticPacketView:
    """The earlier findings the reviewer's packet carries, and the refs it offers as citable.

    A ruling may only speak for a finding whose prior-findings row survived envelope bounding,
    and only cite what ``citable_refs`` listed.
    """

    if type(case) is not SemanticCase:
        raise TypeError("semantic_case_invalid")
    try:
        catalogued = _catalog_item_ids(
            cast(Mapping[str, JsonValue], strict_json_parse(bounded_case_envelope(case)))
        )
    except SemanticCaseTooLarge:
        catalogued = frozenset(item.item_id for item in case.items)
    carried = frozenset(
        item.source_ref
        for item in case.items
        if item.section == "prior_finding" and item.item_id == f"prior-finding-{item.source_ref}"
    )
    prior = frozenset(ref for ref in carried if f"prior-finding-{ref}" in catalogued)
    settled = frozenset(
        item.source_ref
        for item in case.items
        if item.section == "prior_finding"
        and item.item_id == f"{SETTLED_FINDING_ITEM_PREFIX}{item.source_ref}"
        and item.item_id in catalogued
    )
    return SemanticPacketView(
        prior,
        frozenset(case.frontier_refs | case.local_check_refs),
        prior != carried,
        settled,
    )


def check_time_change_parts_carried(
    case: SemanticCase, *, withheld_categories: Sequence[str] = ()
) -> int:
    """How many leading check-time change parts the provider-facing envelope carries (ADR-031).

    The shown-file record must describe what the reviewer could read, not the case before
    ``bounded_case_envelope`` minimized it: a part whose catalog row bounding dropped is never
    offered for authorization, and a channel that withholds ``repository_excerpt`` receives no
    part at all. Parts are admitted and dropped in order, so only the unbroken run from the
    first part counts. The answer is a pure function of the frozen case and the policy's
    withheld categories, so a recovered job derives the same count.
    """

    if type(case) is not SemanticCase:
        raise TypeError("semantic_case_invalid")
    if DataCategory.REPOSITORY_EXCERPT.value in withheld_categories:
        return 0
    admitted = sum(
        item.excerpt_item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
        for item in case.packet.targeted_excerpts
    )
    if not admitted:
        return 0
    catalogued = _catalog_item_ids(
        cast(Mapping[str, JsonValue], strict_json_parse(bounded_case_envelope(case)))
    )
    carried = 0
    while carried < admitted and f"{CHECK_TIME_CHANGE_ITEM_PREFIX}{carried + 1:03d}" in catalogued:
        carried += 1
    return carried


def _carried_change_spans(case: SemanticCase, carried: int) -> tuple[tuple[int, int], ...]:
    """Original ``(start, end)`` of each carried ``change-check-time`` part that recorded one."""

    wanted = {f"{CHECK_TIME_CHANGE_ITEM_PREFIX}{index:03d}" for index in range(1, carried + 1)}
    spans: list[tuple[int, int]] = []
    for item_id, key in case.excerpt_parts:
        if item_id not in wanted:
            continue
        span = excerpt_span(key)
        if span is not None and span[0] == _CHECK_TIME_CHANGE_SOURCE_REF:
            spans.append((span[1], span[2]))
    return tuple(spans)


def check_time_change_sections_carried(
    case: SemanticCase, *, withheld_categories: Sequence[str] = ()
) -> tuple[tuple[int, int], ...]:
    """The change intervals the provider-facing envelope carried outside its leading prefix.

    Current-file sections a follow-up served (``change-section-``) are included as before
    (tb4n5). A check-time change part that is not inside the leading bytes
    (``check_time_change_bytes_carried``) is included too, so a decision section admitted ahead
    of the diff prefix is still a shown file. None when the channel withholds
    ``repository_excerpt``. A pure function of the frozen case and the withheld categories.
    """

    if type(case) is not SemanticCase:
        raise TypeError("semantic_case_invalid")
    if DataCategory.REPOSITORY_EXCERPT.value in withheld_categories:
        return ()
    sections = [
        (item_id, key)
        for item_id, key in case.excerpt_parts
        if item_id.startswith(CHECK_TIME_SECTION_ITEM_PREFIX)
    ]
    catalogued = _catalog_item_ids(
        cast(Mapping[str, JsonValue], strict_json_parse(bounded_case_envelope(case)))
    )
    carried: list[tuple[int, int]] = []
    for item_id, key in sections:
        span = excerpt_span(key)
        if item_id in catalogued and span is not None and span[0] == _CHECK_TIME_CHANGE_SOURCE_REF:
            carried.append((span[1], span[2]))
    part_count = check_time_change_parts_carried(case, withheld_categories=withheld_categories)
    if part_count:
        leading = check_time_change_bytes_carried(case, withheld_categories=withheld_categories)
        for low, high in _carried_change_spans(case, part_count):
            if low >= leading:
                carried.append((low, high))
            elif high > leading:
                carried.append((leading, high))
    return tuple(sorted(set(carried)))


def check_time_change_bytes_carried(
    case: SemanticCase, *, withheld_categories: Sequence[str] = ()
) -> int:
    """How many leading bytes of the stored change the provider-facing envelope carries (ADR-031).

    The contiguous run from byte 0 of the parts ``check_time_change_parts_carried`` counts, each
    part's marker line excluded. A part admitted from later in the change does not extend this
    count; ``check_time_change_sections_carried`` reports that interval instead. This is what
    ``check_time_change_shown_files`` takes: it stays exact whatever part size a narrowed
    selection chose and when the first part was cut to the room left (issue #983), and it is a
    pure function of the frozen case and the withheld categories, so a recovered job derives the
    same count. A part with no recorded span falls back to summing change bytes, which is the
    leading prefix those parts were.
    """

    carried = check_time_change_parts_carried(case, withheld_categories=withheld_categories)
    if not carried:
        return 0
    by_id = {item.item_id: item for item in case.items}
    spans = _carried_change_spans(case, carried)
    if len(spans) != carried:
        return sum(
            _check_time_change_part_chunk_bytes(
                by_id[f"{CHECK_TIME_CHANGE_ITEM_PREFIX}{index:03d}"].content
            )
            for index in range(1, carried + 1)
            if f"{CHECK_TIME_CHANGE_ITEM_PREFIX}{index:03d}" in by_id
        )
    end = 0
    for low, high in sorted(spans):
        if low > end:
            break
        end = max(end, high)
    return end


def semantic_case_to_candidate_context(
    case: SemanticCase,
    *,
    request_id: str,
    scope: AuthorizationScope,
    provider_binding: ProviderBinding,
) -> CandidateContext:
    """Project an AI-powered review case into separate privacy-classified candidate items."""

    if type(case) is not SemanticCase:
        raise TypeError("semantic_case_invalid")
    envelope = bounded_case_envelope(case)
    return review_envelope_to_candidate_context(
        envelope,
        case.items,
        request_id=request_id,
        scope=scope,
        provider_binding=provider_binding,
        subject_digest=case.case_digest,
    )


def review_envelope_to_candidate_context(
    envelope: bytes,
    case_items: Sequence[SemanticCaseItem],
    *,
    request_id: str,
    scope: AuthorizationScope,
    provider_binding: ProviderBinding,
    subject_digest: str,
) -> CandidateContext:
    """Offer a frozen review envelope and only its catalogued, classified content.

    Used by explicit checks and background advice; both feed the same approved-id filter.
    """
    # The catalog is the authority for what the provider payload may carry, so an item bounding
    # removed from the catalog must not travel as a candidate item either. Offering content whose
    # catalog row is gone would get it approved by privacy and then silently discarded during
    # assembly — the packet would claim coverage it never had.
    catalogued = _catalog_item_ids(cast(Mapping[str, JsonValue], strict_json_parse(envelope)))

    items: list[CandidateContextItem] = [
        CandidateContextItem(
            REVIEW_PACKET_ITEM_ID,
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            scope,
            "/case/review-packet",
            envelope,
        )
    ]
    for item in case_items:
        if item.item_id not in catalogued:
            continue
        items.append(
            CandidateContextItem(
                item.item_id,
                item.category,
                scope,
                f"/case/{item.section}/{item.item_id}",
                item.content,
            )
        )
    return CandidateContext(
        request_id=request_id,
        channel=EgressChannel.LLM_INFERENCE,
        local_sink=None,
        purpose=SEMANTIC_REVIEW_PURPOSE,
        scope=scope,
        subject_digest=subject_digest,
        provider_binding=provider_binding,
        items=tuple(items),
    )


def semantic_case_to_prepared_payload(
    case: SemanticCase,
    included_item_ids: frozenset[str] | set[str],
) -> bytes:
    """Assemble the provider-facing review-packet document from privacy-approved items."""

    if type(case) is not SemanticCase:
        raise TypeError("semantic_case_invalid")
    content_by_id = {item.item_id: item.content for item in case.items}
    # Assemble from the same bounded envelope that was offered for authorization, never the
    # unbounded one: the prepared payload must describe exactly what privacy approved.
    envelope = cast(Mapping[str, JsonValue], strict_json_parse(bounded_case_envelope(case)))
    return assemble_filtered_review_packet(
        envelope,
        content_by_id=content_by_id,
        included_item_ids=included_item_ids,
    )
