"""Immutable generation-1 work projections and canonical snapshots."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Set
from contextvars import ContextVar
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, Protocol, cast

from finishup.domain.events import (
    PAYLOAD_TYPES,
    ActionRecordedPayload,
    AssignmentRecordedPayload,
    CheckChangeShownFiles,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    CoordinationContextRecordedPayload,
    CoordinationDispositionRecordedPayload,
    CoordinationObligationDeclaredPayload,
    DecisionRecordedPayload,
    EventPayload,
    EventSchema,
    EvidenceRecordedPayload,
    LedgerRecord,
    MissingForAssessmentItem,
    ObligationChangeKind,
    ObligationPublishedPayload,
    PlanPublishedPayload,
    PlanRevisedPayload,
    ResponseRecordedPayload,
    ResultRecordedPayload,
    check_change_files_from_json,
    check_change_files_to_json,
    decode_payload,
    encode_payload,
    is_observation_authored,
)
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    PRIOR_FINDING_VERDICTS,
    CheckVerdict,
    Finding,
    FindingKind,
    ResponseDisposition,
)
from finishup.domain.values import (
    ActionId,
    ClaimId,
    EventId,
    EvidenceId,
    FindingId,
    Frontier,
    ObjectId,
    ObligationId,
    ResultId,
    action_id,
    claim_id,
    event_id,
    evidence_id,
    finding_id,
    freeze_json,
    frontier_from_json,
    object_id,
    obligation_id,
    result_id,
    validate_sha256_digest,
)
from finishup.domain.values import (
    JsonValue as DomainJsonValue,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_integer_string,
    parse_canonical_integer_string,
)
from finishup.protocol.coverage import (
    Coverage,
    LedgerFreshness,
    coverage_from_json,
    coverage_to_json,
)

__all__ = [
    "OBSERVATION_LIMITATION_KINDS",
    "MAX_ABSORBED_REFS",
    "MAX_CHECK_CHANGE_RAISING_CHECKS",
    "PROJECTION_GENERATION",
    "PROJECTION_VERSION",
    "ContradictionKey",
    "ClaimProjectionRecord",
    "ContradictionRecord",
    "DecisionProjectionRecord",
    "EvidenceProjectionRecord",
    "FindingProjectionRecord",
    "LatestTestedState",
    "ObligationProjectionRecord",
    "PendingMissingForAssessment",
    "PlanProjectionRecord",
    "ProjectionRecord",
    "ProjectionState",
    "STANDING_POSITION_KINDS",
    "StandingPosition",
    "empty_projection_state",
    "is_observation_limitation",
    "is_observation_limitation_kind",
    "observation_finding_event_ids",
    "observation_limitation_finding_ids",
    "projection_digest",
    "projection_from_snapshot",
    "projection_snapshot",
    "unanswered_finding_count",
    "unanswered_finding_ids",
]

# Frozen legacy identifier (ADR-048): projection version the SQL CHECK and replay compare.
PROJECTION_VERSION: Final = "yoetz/0.1.0"
PROJECTION_GENERATION: Final = 1
# At most this many checks contribute to one finding's check-time requirement (ADR-031).
MAX_CHECK_CHANGE_RAISING_CHECKS: Final = 64

_MAX_SAFE_INTEGER: Final = 2**53 - 1
_MAX_SQLITE_SIGNED_INTEGER: Final = 2**63 - 1
_MAX_COVERAGE_GAPS: Final = 64
_SCHEMA_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-z][a-z0-9_]{0,63}$",
    re.ASCII,
)
_SEMVER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$",
    re.ASCII,
)


def _invalid() -> ValueError:
    return ValueError("invalid_projection_state")


def _positive_frontier(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_SQLITE_SIGNED_INTEGER:
        raise _invalid()
    return value


def _nonnegative_safe_integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise _invalid()
    return value


def _ascii_sorted_unique(values: tuple[str, ...]) -> bool:
    if type(values) is not tuple:
        return False
    try:
        return values == tuple(sorted(set(values), key=lambda item: item.encode("ascii")))
    except AttributeError, UnicodeEncodeError:
        return False


def _validate_claim_or_event(value: object) -> ClaimId | EventId:
    try:
        if type(value) is str and value.startswith("clm_"):
            return claim_id(value)
        return event_id(value)
    except ValueError as exc:
        raise _invalid() from exc


def _validate_missing_target(value: object) -> str:
    if type(value) is not str:
        raise _invalid()
    validators = {
        "act_": action_id,
        "clm_": claim_id,
        "evd_": evidence_id,
        "evt_": event_id,
        "fnd_": finding_id,
        "obl_": obligation_id,
        "res_": result_id,
    }
    for prefix, validator in validators.items():
        if value.startswith(prefix):
            try:
                validator(value)
            except ValueError as exc:
                raise _invalid() from exc
            return value
    raise _invalid()


def _validate_gap(marker: object) -> str:
    if type(marker) is not str:
        raise _invalid()
    if marker.startswith("unknown_event:"):
        parts = marker.split(":", 2)
        if len(parts) != 3 or "@" not in parts[2]:
            raise _invalid()
        schema_name, schema_version = parts[2].rsplit("@", 1)
        try:
            event_id(parts[1])
        except ValueError as exc:
            raise _invalid() from exc
        if (
            _SCHEMA_NAME_PATTERN.fullmatch(schema_name) is None
            or _SEMVER_PATTERN.fullmatch(schema_version) is None
        ):
            raise _invalid()
        return marker
    if marker.startswith("redacted_event:"):
        try:
            event_id(marker.removeprefix("redacted_event:"))
        except ValueError as exc:
            raise _invalid() from exc
        return marker
    if marker.startswith("redacted_object:"):
        try:
            object_id(marker.removeprefix("redacted_object:"))
        except ValueError as exc:
            raise _invalid() from exc
        return marker
    if marker.startswith("missing_ref:"):
        parts = marker.split(":", 2)
        if len(parts) != 3:
            raise _invalid()
        try:
            event_id(parts[1])
        except ValueError as exc:
            raise _invalid() from exc
        _validate_missing_target(parts[2])
        return marker
    raise _invalid()


@dataclass(frozen=True, slots=True)
class ProjectionRecord[T]:
    payload: T | None
    payload_digest: str
    redacted: bool
    source_event_id: EventId
    source_frontier: int

    def __post_init__(self) -> None:
        try:
            validate_sha256_digest(self.payload_digest)
            object.__setattr__(self, "source_event_id", event_id(self.source_event_id))
        except ValueError as exc:
            raise _invalid() from exc
        if type(self.redacted) is not bool or (self.payload is None) is not self.redacted:
            raise _invalid()
        object.__setattr__(self, "source_frontier", _positive_frontier(self.source_frontier))


class _ProjectionRecordLike(Protocol):
    @property
    def payload(self) -> object | None: ...

    @property
    def payload_digest(self) -> str: ...

    @property
    def redacted(self) -> bool: ...

    @property
    def source_event_id(self) -> EventId: ...

    @property
    def source_frontier(self) -> int: ...


@dataclass(frozen=True, slots=True)
class PlanProjectionRecord(ProjectionRecord[PlanPublishedPayload | PlanRevisedPayload]):
    superseded_by_plan_version: int | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.payload is not None and type(self.payload) not in {
            PlanPublishedPayload,
            PlanRevisedPayload,
        }:
            raise _invalid()
        if self.superseded_by_plan_version is not None:
            if (
                type(self.superseded_by_plan_version) is not int
                or not 1 <= self.superseded_by_plan_version <= _MAX_SAFE_INTEGER
            ):
                raise _invalid()


@dataclass(frozen=True, slots=True)
class ObligationProjectionRecord(ProjectionRecord[ObligationPublishedPayload]):
    """One recorded obligation plus its plan-change facts.

    ``introduced_frontier`` (tb4n3 RC-7, issue #1030) is the ledger sequence of the obligation's
    *first* publication. A republication may change only its status (the meaning fields must
    repeat), so it is bookkeeping about an obligation that already existed; an obligation first
    published after an answer is new material. ``None`` means ``source_frontier`` (a first
    publication, or a record built without the fact).
    """

    plan_change: ObligationChangeKind | None = None
    plan_change_reason: str | None = None
    superseded_by_obligation_ids: tuple[ObligationId, ...] = ()
    introduced_frontier: int | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.payload is not None and type(self.payload) is not ObligationPublishedPayload:
            raise _invalid()
        if self.introduced_frontier is not None and (
            type(self.introduced_frontier) is not int
            or not 1 <= self.introduced_frontier <= self.source_frontier
        ):
            raise _invalid()
        if self.plan_change is not None and type(self.plan_change) is not ObligationChangeKind:
            raise _invalid()
        if self.plan_change_reason is not None:
            if (
                type(self.plan_change_reason) is not str
                or not self.plan_change_reason
                or len(self.plan_change_reason.encode("utf-8")) > 4_096
            ):
                raise _invalid()
        if type(self.superseded_by_obligation_ids) is not tuple:
            raise _invalid()
        try:
            replacements = tuple(
                obligation_id(value) for value in self.superseded_by_obligation_ids
            )
        except ValueError as exc:
            raise _invalid() from exc
        if not _ascii_sorted_unique(cast(tuple[str, ...], replacements)):
            raise _invalid()
        object.__setattr__(self, "superseded_by_obligation_ids", replacements)
        if self.plan_change is None and (self.plan_change_reason is not None or replacements):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class DecisionProjectionRecord(ProjectionRecord[DecisionRecordedPayload]):
    superseded_by_event_id: EventId | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.payload is not None and type(self.payload) is not DecisionRecordedPayload:
            raise _invalid()
        if self.superseded_by_event_id is not None:
            try:
                object.__setattr__(
                    self,
                    "superseded_by_event_id",
                    event_id(self.superseded_by_event_id),
                )
            except ValueError as exc:
                raise _invalid() from exc


# The agent's reasoned dialogue positions on a finding (issue #1030, tb4n3 RC-7, ADR-040
# amendment). ``reopened`` is not one: it retracts the standing position.
# At most this many subject refs of re-raises recorded on a settled finding widen its concern.
MAX_ABSORBED_REFS: Final = 32
STANDING_POSITION_KINDS: Final = frozenset(
    {"rejected", "acknowledged", "acknowledged_not_done", "self_verified"}
)


@dataclass(frozen=True, slots=True)
class StandingPosition:
    """The agent's earliest unretracted reasoned position on one finding (tb4n3 RC-7).

    ``frontier`` is the ledger sequence of the first reasoned answer (``rejected``,
    ``acknowledged`` with a reason, ``acknowledged_not_done`` or ``self_verified``) recorded since
    the last ``reopened`` answer: later answers of another kind do not move it, so an
    acknowledgement recorded after a rebuttal never erases the rebuttal. ``kind`` is
    ``rejected`` once any answer in that run was a reasoned rejection (the strongest dispute
    stance a reviewer can accept, ``withdrawn``), otherwise the first answer's kind.
    """

    kind: str
    frontier: int

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in STANDING_POSITION_KINDS:
            raise _invalid()
        if type(self.frontier) is not int or not 1 <= self.frontier <= _MAX_SQLITE_SIGNED_INTEGER:
            raise _invalid()


# Optional finding-record event references, each emitted in a snapshot only when set.
_FINDING_RESOLUTION_EVENT_FIELDS: Final = (
    "resolved_by_check_event_id",
    "rejection_accepted_by_check_event_id",
    "disputed_after_rebuttal_by_check_event_id",
    "reduced_scope_raising_check_event_id",
    "resolution_raising_check_event_id",
)


@dataclass(frozen=True, slots=True)
class FindingProjectionRecord(ProjectionRecord[Finding]):
    """One recorded finding plus its proof-based resolution fact.

    ``resolved_by_check_event_id`` names the later ``check_recorded`` event whose recorded state
    qualified to resolve this finding's issue (``kernel/finding_resolution.py``). It is ``None``
    while the finding is current. A response disposition never sets it; a check that returns the
    finding again clears it; redacting the proving check clears it.

    ``review_rounds`` counts the later recorded checks that assessed this finding and left it
    open (issue #905): a local check that returned it again, or an AI-powered review that ruled it
    ``still_present``, ``answered_not_fixed`` or ``unassessable``. It feeds the per-item attempt
    budget and never closes anything. ``rejection_accepted_by_check_event_id`` names the later
    check whose reviewer withdrew this AI-powered finding after the agent rejected it with a
    reason; it latches the terminal ``rejection_accepted`` state.
    ``disputed_after_rebuttal_by_check_event_id`` (issue #1020, ADR-040) names the later check
    that recorded the ruling ``disputed_after_rebuttal``: the reviewer kept this AI-powered finding
    open after the agent rejected it with a reason and cited nothing recorded after that
    rejection. It latches the final, non-blocking ``disputed_after_rebuttal`` state.

    The check-time change facts (ADR-031) are replay-derived from recorded checks, never from the
    finding's own payload. ``check_change_raising_check_event_ids`` names, in fold order, every
    ``check_recorded`` event whose completed AI-powered review raised or re-raised this finding;
    ``check_change_raised_files`` merges what those reviews were shown of the check-time change
    (keyed commitments; for each file seen in part, the bytes shown and the redacted spans among
    them), empty when they carried none, and ``None`` while unknown (an incomplete record, parts
    carried without a record, or a contributing check since redacted).
    ``resolution_depends_on_check_event_ids`` are those checks when the resolving check's
    check-time limits were tolerated only because of those files; redacting any reopens it.

    ``reduced_scope_raising_check_event_id`` names the ``check_recorded`` event whose completed
    AI-powered review raised this finding when that check's recorded coverage carried
    ``semantic_reference_scope_reduced`` (issue #904). It is the replay-derived lifecycle fallback
    for findings recorded before the raise-time stamp: the finding's own recorded coverage is never
    rewritten. Redacting that check clears it.

    ``resolution_raising_check_event_id`` names that same raising check when the resolution named
    by ``resolved_by_check_event_id`` qualified only through its recorded reduced scope. Redacting
    it reopens the finding exactly like redacting the proving check: unreadable proof is no proof.

    The dialogue facts (TB4 tb4n1 D7) record every rebuttal and the reviewer's answer to it:
    ``rebuttal_count`` counts the agent's ``rejected`` responses recorded on this finding (each
    respond is its own event; the projection otherwise keeps only the latest), and
    ``last_reviewer_verdict`` is the newest admitted reviewer ruling on it (``fixed``,
    ``still_present``, ``answered_not_fixed``, ``withdrawn`` or ``unassessable``). Both are carried
    to the next review packet's prior-finding row; neither closes or reopens anything.
    ``settled_reraise_count`` counts the reviewer's re-raises of this same concern recorded after
    the agent's terminal answer (``acknowledged_not_done``, or ``self_verified``; issue #980): the
    agent stopped, the reviewer did not. It never reopens the item; it is what
    ``kernel.finding_todo`` reads as a standing premise dispute.
    The tb4n3 RC-7 dialogue facts (issue #1030) are replay-derived like the counters above:
    ``standing_position`` is the agent's earliest unretracted reasoned answer
    (``StandingPosition``; ``reopened`` retracts it), ``last_ruling_frontier`` is the ledger
    sequence of the newest check that recorded a reviewer ruling on this finding (so "was the
    rejection ruled on?" is a comparison, not a guess), and ``resolution_frontier`` is the ledger
    sequence of the check named by ``resolved_by_check_event_id`` (so an absence proof recorded
    *after* an ``acknowledged_not_done`` or ``self_verified`` answer can be told from one recorded
    before it). ``absorbed_refs`` are the subject refs (bounded, sorted, never a finding, result,
    evidence or action id) of the re-raises recorded on a settled item; they widen its concern so
    a later re-raise naming only what the first re-raise added still folds onto it instead of
    minting a new item (formal-crypto S: the open obligation first appeared in a re-raise).
    The retirement facts (#1104, ADR-025 amendment) are replay-derived by
    ``kernel.finding_retirement``. ``observed_failed_command`` marks an observation-authored
    ``failed_work_omitted`` finding that names no claim (an observed failed-command finding);
    ``failed_run_result_id`` is the one hook-observed failed result it names, when exactly one is
    named; ``retired_by_event_id`` and ``retired_frontier`` name the earliest later hook-observed
    *passing* run of the same command identity (or a passing ``single``/``and_chain`` command whose
    segments include it), or of a planned verification (a verifier run of a command an
    obligation effective when it passed requests), which retires the finding;
    ``retired_by_planned_verification`` says it was the second kind (owner decisions 2026-10-18). A retirement is a proof like a check's: redacting the passing run or the failed
    run drops it, and nothing is deleted.
    ``duplicate_link_broken_by_check_event_ids`` (issue #996) names, in fold order, every later
    check that raised this finding's issue again (returned it, or the reviewer ruled it
    ``still_present`` or ``answered_not_fixed``) while its latest response was ``duplicate_of``.
    While any remains, the ``duplicate_of`` link no longer applies: the finding needs its own
    answer (``duplicate_link_holds``). Redacting one of those checks removes only that id, exactly
    as a full replay of the remaining readable checks would.
    """

    resolved_by_check_event_id: EventId | None = None
    review_rounds: int = 0
    rejection_accepted_by_check_event_id: EventId | None = None
    disputed_after_rebuttal_by_check_event_id: EventId | None = None
    check_change_raising_check_event_ids: tuple[EventId, ...] = ()
    check_change_raised_files: CheckChangeShownFiles | None = None
    resolution_depends_on_check_event_ids: tuple[EventId, ...] = ()
    reduced_scope_raising_check_event_id: EventId | None = None
    resolution_raising_check_event_id: EventId | None = None
    rebuttal_count: int = 0
    last_reviewer_verdict: str | None = None
    settled_reraise_count: int = 0
    duplicate_link_broken_by_check_event_ids: tuple[EventId, ...] = ()
    standing_position: StandingPosition | None = None
    last_ruling_frontier: int | None = None
    resolution_frontier: int | None = None
    absorbed_refs: tuple[str, ...] = ()
    observed_failed_command: bool = False
    failed_run_result_id: ResultId | None = None
    retired_by_event_id: EventId | None = None
    retired_frontier: int | None = None
    retired_by_planned_verification: bool = False

    @property
    def proof_event_id(self) -> EventId | None:
        """The event that resolved this finding by proof: the proving check, else the passing run."""

        return self.resolved_by_check_event_id or self.retired_by_event_id

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.payload is not None and type(self.payload) is not Finding:
            raise _invalid()
        if type(self.observed_failed_command) is not bool:
            raise _invalid()
        if self.failed_run_result_id is not None:
            if not self.observed_failed_command:
                raise _invalid()
            try:
                object.__setattr__(
                    self, "failed_run_result_id", result_id(self.failed_run_result_id)
                )
            except ValueError as exc:
                raise _invalid() from exc
        if (self.retired_by_event_id is None) is not (self.retired_frontier is None):
            raise _invalid()
        if type(self.retired_by_planned_verification) is not bool or (
            self.retired_by_planned_verification and self.retired_by_event_id is None
        ):
            raise _invalid()
        if self.retired_by_event_id is not None:
            if self.failed_run_result_id is None:
                raise _invalid()
            try:
                object.__setattr__(self, "retired_by_event_id", event_id(self.retired_by_event_id))
            except ValueError as exc:
                raise _invalid() from exc
            if (
                type(self.retired_frontier) is not int
                or not 1 <= self.retired_frontier <= _MAX_SQLITE_SIGNED_INTEGER
            ):
                raise _invalid()
        if (
            type(self.absorbed_refs) is not tuple
            or len(self.absorbed_refs) > MAX_ABSORBED_REFS
            or any(type(item) is not str or not 1 <= len(item) <= 64 for item in self.absorbed_refs)
            or list(self.absorbed_refs) != sorted(set(self.absorbed_refs), key=str.encode)
        ):
            raise _invalid()
        if (
            self.standing_position is not None
            and type(self.standing_position) is not StandingPosition
        ):
            raise _invalid()
        for frontier_name in ("last_ruling_frontier", "resolution_frontier"):
            frontier_value = getattr(self, frontier_name)
            if frontier_value is not None and (
                type(frontier_value) is not int
                or not 1 <= frontier_value <= _MAX_SQLITE_SIGNED_INTEGER
            ):
                raise _invalid()
        if self.resolution_frontier is not None and self.resolved_by_check_event_id is None:
            raise _invalid()
        if (
            type(self.rebuttal_count) is not int
            or not 0 <= self.rebuttal_count <= _MAX_SQLITE_SIGNED_INTEGER
            or type(self.settled_reraise_count) is not int
            or not 0 <= self.settled_reraise_count <= _MAX_SQLITE_SIGNED_INTEGER
        ):
            raise _invalid()
        if self.last_reviewer_verdict is not None and (
            type(self.last_reviewer_verdict) is not str
            or self.last_reviewer_verdict not in PRIOR_FINDING_VERDICTS
        ):
            raise _invalid()
        for name in _FINDING_RESOLUTION_EVENT_FIELDS:
            value = getattr(self, name)
            if value is None:
                continue
            try:
                object.__setattr__(self, name, event_id(value))
            except ValueError as exc:
                raise _invalid() from exc
        if (
            type(self.review_rounds) is not int
            or not 0 <= self.review_rounds <= _MAX_SQLITE_SIGNED_INTEGER
        ):
            raise _invalid()
        for name in (
            "check_change_raising_check_event_ids",
            "resolution_depends_on_check_event_ids",
        ):
            value = getattr(self, name)
            if type(value) is not tuple:
                raise _invalid()
            try:
                ids = tuple(event_id(item) for item in cast(tuple[object, ...], value))
            except ValueError as exc:
                raise _invalid() from exc
            if len(set(ids)) != len(ids) or len(ids) > MAX_CHECK_CHANGE_RAISING_CHECKS:
                raise _invalid()
            object.__setattr__(self, name, ids)
        breaks = self.duplicate_link_broken_by_check_event_ids
        if type(breaks) is not tuple:
            raise _invalid()
        try:
            break_ids = tuple(event_id(item) for item in cast(tuple[object, ...], breaks))
        except ValueError as exc:
            raise _invalid() from exc
        if len(set(break_ids)) != len(break_ids):
            raise _invalid()
        object.__setattr__(self, "duplicate_link_broken_by_check_event_ids", break_ids)
        files = self.check_change_raised_files
        if files is not None and (
            not self.check_change_raising_check_event_ids
            or type(files) is not CheckChangeShownFiles
            or not files.complete
        ):
            raise _invalid()
        if self.resolution_depends_on_check_event_ids and self.resolved_by_check_event_id is None:
            raise _invalid()
        if (
            self.resolution_raising_check_event_id is not None
            and self.resolved_by_check_event_id is None
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ClaimProjectionRecord(ProjectionRecord[ClaimRecordedPayload | ClaimRecordedPayloadV1_1]):
    """One recorded claim plus the durable revision edge that replaced it.

    ``superseded_by_claim_id`` names the later ``claim_recorded/1.1.0`` claim that declared this
    claim in ``supersedes_claim_refs``. It is recorded on the target when the replacement is
    applied, so supersession survives a later ``redaction_recorded`` that tombstones the
    replacement's payload: deriving the edge from live payloads would resurrect the middle of a
    correction chain as a current claim (ADR-025 decision 2 keeps replaced claims out of the
    effective set). It is ``None`` while the claim is effective.
    """

    superseded_by_claim_id: ClaimId | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.payload is not None and type(self.payload) not in {
            ClaimRecordedPayload,
            ClaimRecordedPayloadV1_1,
        }:
            raise _invalid()
        if self.superseded_by_claim_id is not None:
            try:
                object.__setattr__(
                    self,
                    "superseded_by_claim_id",
                    claim_id(self.superseded_by_claim_id),
                )
            except ValueError as exc:
                raise _invalid() from exc


@dataclass(frozen=True, slots=True)
class EvidenceProjectionRecord(ProjectionRecord[EvidenceRecordedPayload]):
    object_available: bool = True
    redacted_object_id: ObjectId | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.payload is not None and type(self.payload) is not EvidenceRecordedPayload:
            raise _invalid()
        if type(self.object_available) is not bool:
            raise _invalid()
        if self.redacted_object_id is not None:
            try:
                object.__setattr__(
                    self,
                    "redacted_object_id",
                    object_id(self.redacted_object_id),
                )
            except ValueError as exc:
                raise _invalid() from exc
        if self.object_available is (self.redacted_object_id is not None):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class LatestTestedState:
    source_check_event_id: EventId
    subject_frontier: Frontier
    verdict: CheckVerdict
    returned_finding_ids: tuple[FindingId, ...]
    suppressed_count: int
    coverage: Coverage

    def __post_init__(self) -> None:
        try:
            object.__setattr__(
                self,
                "source_check_event_id",
                event_id(self.source_check_event_id),
            )
            finding_ids = tuple(finding_id(value) for value in self.returned_finding_ids)
        except ValueError as exc:
            raise _invalid() from exc
        if type(self.subject_frontier) is not Frontier:
            raise _invalid()
        if type(self.verdict) is not CheckVerdict:
            raise _invalid()
        if not _ascii_sorted_unique(cast(tuple[str, ...], finding_ids)):
            raise _invalid()
        object.__setattr__(self, "returned_finding_ids", finding_ids)
        object.__setattr__(
            self,
            "suppressed_count",
            _nonnegative_safe_integer(self.suppressed_count),
        )
        if type(self.coverage) is not Coverage:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class PendingMissingForAssessment:
    """What the latest assessed AI-powered review named as missing (issue #907).

    Set by a ``check_recorded`` 1.3.0 ``insufficient_packet`` that recorded missing items and
    cleared by any later check with another assessed conclusion, or by redacting that check. A
    later ``insufficient_packet`` that recorded no item leaves it standing. The next
    review packet shows each item with what was recorded since, so a reviewer can tell a supplied
    item from one still missing.
    """

    source_check_event_id: EventId
    source_frontier: int
    items: tuple[MissingForAssessmentItem, ...]

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "source_check_event_id", event_id(self.source_check_event_id))
        except ValueError as exc:
            raise _invalid() from exc
        object.__setattr__(self, "source_frontier", _nonnegative_safe_integer(self.source_frontier))
        if (
            type(self.items) is not tuple
            or not self.items
            or any(type(item) is not MissingForAssessmentItem for item in self.items)
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ContradictionKey:
    disputing_claim_id: ClaimId
    disputed_ref: ClaimId | EventId

    def __post_init__(self) -> None:
        try:
            object.__setattr__(
                self,
                "disputing_claim_id",
                claim_id(self.disputing_claim_id),
            )
            object.__setattr__(
                self,
                "disputed_ref",
                _validate_claim_or_event(self.disputed_ref),
            )
        except ValueError as exc:
            raise _invalid() from exc


@dataclass(frozen=True, slots=True)
class ContradictionRecord:
    disputing_claim_id: ClaimId
    disputed_ref: ClaimId | EventId
    source_event_id: EventId
    source_frontier: int

    def __post_init__(self) -> None:
        try:
            object.__setattr__(
                self,
                "disputing_claim_id",
                claim_id(self.disputing_claim_id),
            )
            object.__setattr__(
                self,
                "disputed_ref",
                _validate_claim_or_event(self.disputed_ref),
            )
            object.__setattr__(self, "source_event_id", event_id(self.source_event_id))
        except ValueError as exc:
            raise _invalid() from exc
        object.__setattr__(self, "source_frontier", _positive_frontier(self.source_frontier))


_ABSENT: Final = object()
# Set only by ``derive_projection_state`` for the duration of one constructor call. A record
# object that the already-validated prior projection holds under the same key was validated when
# that prior was built; records are frozen, so re-encoding and re-digesting its payload on every
# fold step only turned a linear replay quadratic (issue #886). New or replaced records, keys and
# every scalar field are still validated in full.
_TRUSTED_PRIOR: ContextVar[ProjectionState | None] = ContextVar(
    "finishup_trusted_prior_projection", default=None
)


@dataclass(frozen=True, slots=True)
class ProjectionState:
    frontier: int
    head_digest: str
    plans: Mapping[int, PlanProjectionRecord]
    obligations: Mapping[ObligationId, ObligationProjectionRecord]
    decisions: Mapping[EventId, DecisionProjectionRecord]
    assignments: Mapping[EventId, ProjectionRecord[AssignmentRecordedPayload]]
    actions: Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]]
    results: Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]]
    evidence: Mapping[EvidenceId, EvidenceProjectionRecord]
    claims: Mapping[ClaimId, ClaimProjectionRecord]
    contradictions: Mapping[ContradictionKey, ContradictionRecord]
    findings: Mapping[FindingId, FindingProjectionRecord]
    responses: Mapping[FindingId, ProjectionRecord[ResponseRecordedPayload]]
    latest_tested_state: LatestTestedState | None
    freshness: LedgerFreshness
    unknown_event_count: int
    coverage_gaps: tuple[str, ...]
    # Coordination context/disposition records are recipient-ledger facts.  They remain separate
    # from the semantic case collections so a check can consume only frozen, source-authorized
    # coordination evidence.
    coordination_contexts: Mapping[
        EventId, ProjectionRecord[CoordinationContextRecordedPayload]
    ] = field(
        default_factory=lambda: cast(
            dict[EventId, ProjectionRecord[CoordinationContextRecordedPayload]], {}
        )
    )
    coordination_dispositions: Mapping[
        EventId, ProjectionRecord[CoordinationDispositionRecordedPayload]
    ] = field(
        default_factory=lambda: cast(
            dict[EventId, ProjectionRecord[CoordinationDispositionRecordedPayload]], {}
        )
    )
    coordination_declarations: Mapping[
        EventId, ProjectionRecord[CoordinationObligationDeclaredPayload]
    ] = field(
        default_factory=lambda: cast(
            dict[EventId, ProjectionRecord[CoordinationObligationDeclaredPayload]], {}
        )
    )
    pending_missing_for_assessment: PendingMissingForAssessment | None = None

    def __post_init__(self) -> None:
        if type(self.frontier) is not int or not 0 <= self.frontier <= _MAX_SQLITE_SIGNED_INTEGER:
            raise _invalid()
        try:
            if self.frontier == 0:
                if type(self.head_digest) is not str or self.head_digest != "genesis":
                    raise _invalid()
            else:
                validate_sha256_digest(self.head_digest)
        except ValueError as exc:
            raise _invalid() from exc
        if type(self.freshness) is not LedgerFreshness:
            raise _invalid()
        object.__setattr__(
            self,
            "unknown_event_count",
            _nonnegative_safe_integer(self.unknown_event_count),
        )
        if type(self.coverage_gaps) is not tuple or len(self.coverage_gaps) > _MAX_COVERAGE_GAPS:
            raise _invalid()
        gaps = tuple(_validate_gap(marker) for marker in self.coverage_gaps)
        if not _ascii_sorted_unique(gaps):
            raise _invalid()
        if self.unknown_event_count != sum(marker.startswith("unknown_event:") for marker in gaps):
            raise _invalid()
        object.__setattr__(self, "coverage_gaps", gaps)
        if self.latest_tested_state is not None:
            if (
                type(self.latest_tested_state) is not LatestTestedState
                or self.latest_tested_state.subject_frontier.sequence > self.frontier
            ):
                raise _invalid()
        if self.pending_missing_for_assessment is not None and (
            type(self.pending_missing_for_assessment) is not PendingMissingForAssessment
            or self.pending_missing_for_assessment.source_frontier > self.frontier
        ):
            raise _invalid()

        prior = _TRUSTED_PRIOR.get()
        if type(prior) is not ProjectionState or prior.frontier > self.frontier:
            prior = None
        plans = self._copy_plans(self.plans, None if prior is None else prior.plans)
        obligations = self._copy_mapping(
            self.obligations,
            None if prior is None else prior.obligations,
            obligation_id,
            ObligationProjectionRecord,
            ObligationPublishedPayload,
            "obligation_id",
        )
        decisions = self._copy_event_mapping(
            self.decisions,
            None if prior is None else prior.decisions,
            DecisionProjectionRecord,
            DecisionRecordedPayload,
            source_key=True,
        )
        assignments = self._copy_event_mapping(
            self.assignments,
            None if prior is None else prior.assignments,
            ProjectionRecord,
            AssignmentRecordedPayload,
            source_key=True,
        )
        actions = self._copy_mapping(
            self.actions,
            None if prior is None else prior.actions,
            action_id,
            ProjectionRecord,
            ActionRecordedPayload,
            "action_id",
        )
        results = self._copy_mapping(
            self.results,
            None if prior is None else prior.results,
            result_id,
            ProjectionRecord,
            ResultRecordedPayload,
            "result_id",
        )
        evidence = self._copy_mapping(
            self.evidence,
            None if prior is None else prior.evidence,
            evidence_id,
            EvidenceProjectionRecord,
            EvidenceRecordedPayload,
            "evidence_id",
        )
        claims = self._copy_mapping(
            self.claims,
            None if prior is None else prior.claims,
            claim_id,
            ClaimProjectionRecord,
            (ClaimRecordedPayload, ClaimRecordedPayloadV1_1),
            "claim_id",
        )
        findings = self._copy_mapping(
            self.findings,
            None if prior is None else prior.findings,
            finding_id,
            FindingProjectionRecord,
            Finding,
            "finding_id",
        )
        responses = self._copy_mapping(
            self.responses,
            None if prior is None else prior.responses,
            finding_id,
            ProjectionRecord,
            ResponseRecordedPayload,
            "finding_id",
        )
        contradictions = self._copy_contradictions(self.contradictions)
        coordination_contexts: dict[
            EventId, ProjectionRecord[CoordinationContextRecordedPayload]
        ] = self._copy_event_mapping(
            self.coordination_contexts,
            None if prior is None else prior.coordination_contexts,
            ProjectionRecord,
            CoordinationContextRecordedPayload,
            source_key=True,
        )
        coordination_dispositions: dict[
            EventId, ProjectionRecord[CoordinationDispositionRecordedPayload]
        ] = self._copy_event_mapping(
            self.coordination_dispositions,
            None if prior is None else prior.coordination_dispositions,
            ProjectionRecord,
            CoordinationDispositionRecordedPayload,
            source_key=True,
        )
        coordination_declarations: dict[
            EventId, ProjectionRecord[CoordinationObligationDeclaredPayload]
        ] = self._copy_event_mapping(
            self.coordination_declarations,
            None if prior is None else prior.coordination_declarations,
            ProjectionRecord,
            CoordinationObligationDeclaredPayload,
            source_key=True,
        )

        object.__setattr__(self, "plans", MappingProxyType(plans))
        object.__setattr__(self, "obligations", MappingProxyType(obligations))
        object.__setattr__(self, "decisions", MappingProxyType(decisions))
        object.__setattr__(self, "assignments", MappingProxyType(assignments))
        object.__setattr__(self, "actions", MappingProxyType(actions))
        object.__setattr__(self, "results", MappingProxyType(results))
        object.__setattr__(self, "evidence", MappingProxyType(evidence))
        object.__setattr__(self, "claims", MappingProxyType(claims))
        object.__setattr__(self, "contradictions", MappingProxyType(contradictions))
        object.__setattr__(self, "findings", MappingProxyType(findings))
        object.__setattr__(self, "responses", MappingProxyType(responses))
        object.__setattr__(self, "coordination_contexts", MappingProxyType(coordination_contexts))
        object.__setattr__(
            self,
            "coordination_dispositions",
            MappingProxyType(coordination_dispositions),
        )
        object.__setattr__(
            self,
            "coordination_declarations",
            MappingProxyType(coordination_declarations),
        )

    def _validate_record(self, record: _ProjectionRecordLike) -> None:
        if record.source_frontier > self.frontier:
            raise _invalid()
        if record.payload is not None:
            try:
                digest = canonical_digest(encode_payload(cast(EventPayload, record.payload)))
            except ValueError as exc:
                raise _invalid() from exc
            if digest != record.payload_digest:
                raise _invalid()

    def _copy_plans(
        self,
        source: Mapping[int, PlanProjectionRecord],
        trusted: Mapping[int, PlanProjectionRecord] | None,
    ) -> dict[int, PlanProjectionRecord]:
        if not isinstance(cast(object, source), Mapping):
            raise _invalid()
        result: dict[int, PlanProjectionRecord] = {}
        for key, record in source.items():
            if trusted is not None and trusted.get(key, _ABSENT) is record:
                result[key] = record
                continue
            if type(key) is not int or not 1 <= key <= _MAX_SAFE_INTEGER:
                raise _invalid()
            if type(record) is not PlanProjectionRecord:
                raise _invalid()
            self._validate_record(record)
            if record.payload is not None and record.payload.plan_version != key:
                raise _invalid()
            result[key] = record
        return result

    def _copy_event_mapping[T: _ProjectionRecordLike](
        self,
        source: Mapping[EventId, T],
        trusted: Mapping[EventId, T] | None,
        record_type: type[object],
        payload_type: type[object],
        *,
        source_key: bool,
    ) -> dict[EventId, T]:
        if not isinstance(cast(object, source), Mapping):
            raise _invalid()
        result: dict[EventId, T] = {}
        for raw_key, record in source.items():
            if trusted is not None and trusted.get(raw_key, _ABSENT) is record:
                result[raw_key] = record
                continue
            try:
                key = event_id(raw_key)
            except ValueError as exc:
                raise _invalid() from exc
            if type(record) is not record_type:
                raise _invalid()
            self._validate_record(record)
            if record.payload is not None and type(record.payload) is not payload_type:
                raise _invalid()
            if source_key and record.source_event_id != key:
                raise _invalid()
            result[key] = record
        return result

    def _copy_mapping[K: str, T: _ProjectionRecordLike](
        self,
        source: Mapping[K, T],
        trusted: Mapping[K, T] | None,
        key_validator: Callable[[object], K],
        record_type: type[object],
        payload_type: type[object] | tuple[type[object], ...],
        payload_key: str,
    ) -> dict[K, T]:
        if not isinstance(cast(object, source), Mapping):
            raise _invalid()
        result: dict[K, T] = {}
        for raw_key, record in source.items():
            if trusted is not None and trusted.get(raw_key, _ABSENT) is record:
                result[raw_key] = record
                continue
            try:
                key = key_validator(raw_key)
            except ValueError as exc:
                raise _invalid() from exc
            if type(record) is not record_type:
                raise _invalid()
            self._validate_record(record)
            if record.payload is not None:
                allowed_types: tuple[type[object], ...] = (
                    payload_type if isinstance(payload_type, tuple) else (payload_type,)
                )
                if type(record.payload) not in allowed_types:
                    raise _invalid()
                if getattr(record.payload, payload_key) != key:
                    raise _invalid()
            result[key] = record
        return result

    def _copy_contradictions(
        self,
        source: Mapping[ContradictionKey, ContradictionRecord],
    ) -> dict[ContradictionKey, ContradictionRecord]:
        if not isinstance(cast(object, source), Mapping):
            raise _invalid()
        result: dict[ContradictionKey, ContradictionRecord] = {}
        for key, record in source.items():
            if type(key) is not ContradictionKey or type(record) is not ContradictionRecord:
                raise _invalid()
            if (
                key.disputing_claim_id != record.disputing_claim_id
                or key.disputed_ref != record.disputed_ref
                or record.source_frontier > self.frontier
            ):
                raise _invalid()
            result[key] = record
        return result


def derive_projection_state(
    prior: ProjectionState,
    **fields: object,
) -> ProjectionState:
    """Build the next projection, skipping re-validation of records carried unchanged from prior.

    ``prior`` must itself be a constructed (and therefore validated) ``ProjectionState`` at a
    frontier no later than the new one; otherwise every record is validated in full.
    """

    token = _TRUSTED_PRIOR.set(prior)
    try:
        return ProjectionState(**fields)  # type: ignore[arg-type]
    finally:
        _TRUSTED_PRIOR.reset(token)


def empty_projection_state() -> ProjectionState:
    """Return the exact generation-1 genesis projection."""

    return ProjectionState(
        frontier=0,
        head_digest="genesis",
        plans={},
        obligations={},
        decisions={},
        assignments={},
        actions={},
        results={},
        evidence={},
        claims={},
        contradictions={},
        findings={},
        responses={},
        latest_tested_state=None,
        freshness=LedgerFreshness.UNKNOWN,
        unknown_event_count=0,
        coverage_gaps=(),
    )


def observation_finding_event_ids(records: Iterable[LedgerRecord]) -> frozenset[EventId]:
    """Return the event ids of service-stamped observation-authored ``finding_recorded`` records.

    Authorship is an envelope fact the projection does not retain, so surfaces that must tell an
    observation-authored finding from a check-returned one read it from the accepted records.
    """

    return frozenset(
        record.event_id
        for record in records
        if record.schema.name == "finding_recorded" and is_observation_authored(record)
    )


# Finding kinds deliberately classified as disclosed observation limitations (issue #911). This is an
# explicit allowlist, not the generic ``actionable`` trait: a kind added or reclassified later is
# response work until someone decides here that an observation-authored row of it needs no answer
# and that answering it cannot change a later check.
OBSERVATION_LIMITATION_KINDS: Final = frozenset({FindingKind.LEDGER_STALE_OR_INCOMPLETE})


def is_observation_limitation(
    record: FindingProjectionRecord, observation_finding_events: Set[EventId]
) -> bool:
    """True for a readable limitation-kind finding whose record the observation service authored.

    Observation advice such as "Observation coverage is incomplete or stale" discloses a coverage
    limitation of the harness; no check returns it and no agent action in the task can repair it
    (issue #911). Such a row is carried as a disclosed limitation rather than as response work:
    it does not count as unanswered, and acknowledging it does not supersede a recorded check.
    It stays unresolved and keeps its coverage on the receipt. The decision is structural (the
    record's service-stamped authorship plus ``is_observation_limitation_kind``), never a finding
    id, and an unreadable payload is conservatively not a limitation.
    """

    payload = record.payload
    return (
        payload is not None
        and record.source_event_id in observation_finding_events
        and is_observation_limitation_kind(payload.kind)
    )


def is_observation_limitation_kind(kind: FindingKind) -> bool:
    """True when *kind* is allowlisted in ``OBSERVATION_LIMITATION_KINDS`` and not actionable.

    Both conditions must hold, so neither a new non-actionable kind nor an allowlisted kind that
    becomes actionable is silently removed from response work.
    """

    return kind in OBSERVATION_LIMITATION_KINDS and not FINDING_KIND_TRAITS[kind][1]


def observation_limitation_finding_ids(
    state: ProjectionState, records: Iterable[LedgerRecord]
) -> frozenset[FindingId]:
    """Every finding id ``is_observation_limitation`` admits for ``state`` over ``records``."""

    events = observation_finding_event_ids(records)
    if not events:
        return frozenset()
    return frozenset(
        key for key, record in state.findings.items() if is_observation_limitation(record, events)
    )


def unanswered_finding_ids(
    state: ProjectionState, records: Iterable[LedgerRecord]
) -> frozenset[FindingId]:
    """Findings that still need a response: no recorded response and not a disclosed limitation.

    Any recorded response answers the finding, whatever its stance: a rejection, waiver, or
    provenance dispute answers the finding on the record, and its own quality surfaces as a later
    finding. An observation-authored, non-actionable finding (``is_observation_limitation``) is a
    disclosed coverage limitation that needs no response, so it is never response work. Neither
    rule sets the receipt's ``resolved`` field, which remains false for every response disposition.

    A readable finding a later qualifying check already proved absent, with no response, is
    ``verified_resolved``: that state is final and ``respond`` refuses it, so counting it as
    response work would leave an agent that repaired before answering with a readiness item it
    can never clear (pilot blocker).

    A reviewer's limitation request the agent disclosed with a ``finishup-verification-limit``
    decision is not response work either (tb4n3 RC-1); an undisclosed one still is.

    A ``duplicate_of`` answer (issue #996) answers the finding only while its link holds
    (``duplicate_link_holds``). Once a later check broke the link, or the earlier finding became
    unreadable, that answer no longer applies and the finding needs its own answer again.
    """

    limitations = observation_limitation_finding_ids(state, records)
    waiting = frozenset(
        key
        for key, record in state.findings.items()
        if (key not in state.responses or _duplicate_answer_lapsed(state, key))
        and key not in limitations
        and not (record.payload is not None and record.resolved_by_check_event_id is not None)
    )
    return waiting - _disclosed_limitations(state, waiting)


def _disclosed_limitations(
    state: ProjectionState, candidates: frozenset[FindingId]
) -> frozenset[FindingId]:
    """Waiting reviewer limitation requests the agent already disclosed by a decision line.

    A ``finishup-verification-limit:<obligation id>`` decision settles a limitation request without
    a response (tb4n3 RC-1, owner decision Q4), so the request is no longer response work. Only a
    request still without an answer can be settled this way, hence only *candidates* are read.
    The import is local: ``kernel.limitation`` reads the projection this module defines.
    """

    from finishup.domain.findings import is_limitation_request
    from finishup.kernel.limitation import limitation_disclosed_ids

    requests = frozenset(
        key
        for key in candidates
        if (record := state.findings.get(key)) is not None
        and record.payload is not None
        and is_limitation_request(record.payload)
    )
    return frozenset(limitation_disclosed_ids(state, requests)) if requests else frozenset()


def duplicate_link_holds(state: ProjectionState, key: FindingId) -> FindingId | None:
    """The earlier finding a holding ``duplicate_of`` answer links *key* to (issue #996).

    ``None`` unless the finding is readable, its latest readable response is ``duplicate_of``, no
    remaining readable check broke the link, and the named finding is readable, recorded earlier,
    and reports the same origin and kind. The earlier-only rule keeps every chain finite.
    """

    record = state.findings.get(key)
    response = state.responses.get(key)
    if (
        record is None
        or record.payload is None
        or record.duplicate_link_broken_by_check_event_ids
        or response is None
        or response.payload is None
        or response.payload.disposition is not ResponseDisposition.DUPLICATE_OF
    ):
        return None
    target = response.payload.duplicate_of_finding_id
    target_record = None if target is None else state.findings.get(target)
    if (
        target is None
        or target_record is None
        or target_record.payload is None
        or target_record.source_frontier >= record.source_frontier
        or target_record.payload.origin is not record.payload.origin
        or target_record.payload.kind is not record.payload.kind
    ):
        return None
    return target


def _duplicate_answer_lapsed(state: ProjectionState, key: FindingId) -> bool:
    """A ``duplicate_of`` answer whose link no longer holds answers nothing (#996)."""

    response = state.responses.get(key)
    return (
        response is not None
        and response.payload is not None
        and response.payload.disposition is ResponseDisposition.DUPLICATE_OF
        and duplicate_link_holds(state, key) is None
    )


def unanswered_finding_count(state: ProjectionState, records: Iterable[LedgerRecord]) -> int:
    """Count ``unanswered_finding_ids``; ``records`` are the accepted records ``state`` replays."""

    return len(unanswered_finding_ids(state, records))


def _record_snapshot(record: _ProjectionRecordLike) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "payload": (
            None
            if record.payload is None
            else cast(JsonValue, encode_payload(cast(EventPayload, record.payload)))
        ),
        "payload_digest": record.payload_digest,
        "redacted": record.redacted,
        "source_event_id": record.source_event_id,
        "source_frontier": canonical_integer_string(record.source_frontier),
    }
    if type(record) is PlanProjectionRecord:
        if record.superseded_by_plan_version is not None:
            result["superseded_by_plan_version"] = canonical_integer_string(
                record.superseded_by_plan_version
            )
    elif type(record) is ObligationProjectionRecord:
        if record.plan_change is not None:
            result["plan_change"] = record.plan_change.value
            if record.plan_change_reason is not None:
                result["plan_change_reason"] = record.plan_change_reason
            result["superseded_by_obligation_ids"] = list(record.superseded_by_obligation_ids)
        # tb4n3 RC-7: emitted only for a republication, so earlier snapshots keep their bytes.
        if record.introduced_frontier is not None:
            result["introduced_frontier"] = canonical_integer_string(record.introduced_frontier)
    elif type(record) is ClaimProjectionRecord:
        # Emitted only when set, so every snapshot of a task without a claim correction stays
        # byte-identical to the generation-1 shape frozen before versioned claim correction.
        if record.superseded_by_claim_id is not None:
            result["superseded_by_claim_id"] = record.superseded_by_claim_id
    elif type(record) is DecisionProjectionRecord:
        if record.superseded_by_event_id is not None:
            result["superseded_by_event_id"] = record.superseded_by_event_id
    elif type(record) is EvidenceProjectionRecord:
        result["object_available"] = record.object_available
        if record.redacted_object_id is not None:
            result["redacted_object_id"] = record.redacted_object_id
    elif type(record) is FindingProjectionRecord:
        # Emitted only when set, so every snapshot of a task whose findings were never resolved
        # stays byte-identical to the generation-1 shape frozen before proof-based resolution.
        if record.resolved_by_check_event_id is not None:
            result["resolved_by_check_event_id"] = record.resolved_by_check_event_id
        # Issue #905 facts follow the same rule: absent until set, so earlier snapshots keep
        # their exact bytes.
        if record.review_rounds:
            result["review_rounds"] = record.review_rounds
        if record.rejection_accepted_by_check_event_id is not None:
            result["rejection_accepted_by_check_event_id"] = (
                record.rejection_accepted_by_check_event_id
            )
        # Issue #1020: emitted only when set, so earlier snapshots keep their bytes.
        if record.disputed_after_rebuttal_by_check_event_id is not None:
            result["disputed_after_rebuttal_by_check_event_id"] = (
                record.disputed_after_rebuttal_by_check_event_id
            )
        # Likewise emitted only when set (ADR-031), so earlier snapshots keep their bytes.
        if record.check_change_raising_check_event_ids:
            result["check_change_raising_check_event_ids"] = list(
                record.check_change_raising_check_event_ids
            )
        if record.check_change_raised_files is not None:
            result["check_change_raised_files"] = cast(
                JsonValue, freeze_json(check_change_files_to_json(record.check_change_raised_files))
            )
        if record.resolution_depends_on_check_event_ids:
            result["resolution_depends_on_check_event_ids"] = list(
                record.resolution_depends_on_check_event_ids
            )
        # Likewise emitted only when a raising check recorded a reduced reference scope (#904).
        if record.reduced_scope_raising_check_event_id is not None:
            result["reduced_scope_raising_check_event_id"] = (
                record.reduced_scope_raising_check_event_id
            )
        if record.resolution_raising_check_event_id is not None:
            result["resolution_raising_check_event_id"] = record.resolution_raising_check_event_id
        # TB4 tb4n1 D7 dialogue facts: emitted only when set, so earlier snapshots keep their bytes.
        if record.rebuttal_count:
            result["rebuttal_count"] = record.rebuttal_count
        if record.last_reviewer_verdict is not None:
            result["last_reviewer_verdict"] = record.last_reviewer_verdict
        if record.settled_reraise_count:
            result["settled_reraise_count"] = record.settled_reraise_count
        # Issue #1030 (tb4n3 RC-7) dialogue facts: emitted only when set.
        if record.standing_position is not None:
            result["standing_position"] = {
                "kind": record.standing_position.kind,
                "frontier": record.standing_position.frontier,
            }
        if record.last_ruling_frontier is not None:
            result["last_ruling_frontier"] = record.last_ruling_frontier
        if record.resolution_frontier is not None:
            result["resolution_frontier"] = record.resolution_frontier
        if record.absorbed_refs:
            result["absorbed_refs"] = list(record.absorbed_refs)
        # Issue #1104 retirement facts: emitted only when set, so a task without an observed
        # failed-command finding keeps its exact snapshot bytes.
        if record.observed_failed_command:
            result["observed_failed_command"] = True
        if record.failed_run_result_id is not None:
            result["failed_run_result_id"] = record.failed_run_result_id
        if record.retired_by_event_id is not None:
            result["retired_by_event_id"] = record.retired_by_event_id
        if record.retired_frontier is not None:
            result["retired_frontier"] = record.retired_frontier
        if record.retired_by_planned_verification:
            result["retired_by_planned_verification"] = True
        # Issue #996: emitted only when a check broke a ``duplicate_of`` link.
        if record.duplicate_link_broken_by_check_event_ids:
            result["duplicate_link_broken_by_check_event_ids"] = list(
                record.duplicate_link_broken_by_check_event_ids
            )
    return result


def _latest_tested_snapshot(value: LatestTestedState) -> dict[str, JsonValue]:
    return {
        "source_check_event_id": value.source_check_event_id,
        "subject_frontier": value.subject_frontier.as_wire(),
        "verdict": value.verdict.value,
        "returned_finding_ids": list(value.returned_finding_ids),
        "suppressed_count": value.suppressed_count,
        "coverage": coverage_to_json(value.coverage),
    }


def _string_key(value: object) -> str:
    return str(value)


def _plan_key(value: int) -> str:
    return canonical_integer_string(value)


def _sorted_record_map[K](
    source: Mapping[K, _ProjectionRecordLike],
    *,
    key_text: Callable[[K], str] = _string_key,
) -> dict[str, JsonValue]:
    rows = sorted(
        ((key_text(key), record) for key, record in source.items()),
        key=lambda item: item[0].encode("ascii"),
    )
    return {key: _record_snapshot(record) for key, record in rows}


def projection_snapshot(state: ProjectionState) -> dict[str, JsonValue]:
    """Return the exact canonical JSON-compatible generation-1 snapshot."""

    if type(state) is not ProjectionState:
        raise _invalid()
    contradictions = {
        f"{key.disputing_claim_id}|{key.disputed_ref}": {
            "disputing_claim_id": record.disputing_claim_id,
            "disputed_ref": record.disputed_ref,
            "source_event_id": record.source_event_id,
            "source_frontier": canonical_integer_string(record.source_frontier),
        }
        for key, record in sorted(
            state.contradictions.items(),
            key=lambda item: (f"{item[0].disputing_claim_id}|{item[0].disputed_ref}").encode(
                "ascii"
            ),
        )
    }
    snapshot: dict[str, JsonValue] = {
        "frontier": canonical_integer_string(state.frontier),
        "head_digest": state.head_digest,
        "plans": _sorted_record_map(
            cast(Mapping[int, _ProjectionRecordLike], state.plans),
            key_text=_plan_key,
        ),
        "obligations": _sorted_record_map(
            cast(Mapping[ObligationId, _ProjectionRecordLike], state.obligations)
        ),
        "decisions": _sorted_record_map(
            cast(Mapping[EventId, _ProjectionRecordLike], state.decisions)
        ),
        "assignments": _sorted_record_map(
            cast(Mapping[EventId, _ProjectionRecordLike], state.assignments)
        ),
        "actions": _sorted_record_map(
            cast(Mapping[ActionId, _ProjectionRecordLike], state.actions)
        ),
        "results": _sorted_record_map(
            cast(Mapping[ResultId, _ProjectionRecordLike], state.results)
        ),
        "evidence": _sorted_record_map(
            cast(Mapping[EvidenceId, _ProjectionRecordLike], state.evidence)
        ),
        "claims": _sorted_record_map(cast(Mapping[ClaimId, _ProjectionRecordLike], state.claims)),
        "contradictions": contradictions,
        "findings": _sorted_record_map(
            cast(Mapping[FindingId, _ProjectionRecordLike], state.findings)
        ),
        "responses": _sorted_record_map(
            cast(Mapping[FindingId, _ProjectionRecordLike], state.responses)
        ),
        "latest_tested_state": (
            None
            if state.latest_tested_state is None
            else _latest_tested_snapshot(state.latest_tested_state)
        ),
        "freshness": state.freshness.value,
        "unknown_event_count": state.unknown_event_count,
        "coverage_gaps": list(state.coverage_gaps),
    }
    # Keep empty generation-1 snapshots byte-identical.  Coordination keys are emitted as soon
    # as the recipient ledger records one of the new event families.
    if state.coordination_contexts:
        snapshot["coordination_contexts"] = _sorted_record_map(
            cast(Mapping[EventId, _ProjectionRecordLike], state.coordination_contexts)
        )
    if state.coordination_dispositions:
        snapshot["coordination_dispositions"] = _sorted_record_map(
            cast(Mapping[EventId, _ProjectionRecordLike], state.coordination_dispositions)
        )
    if state.coordination_declarations:
        snapshot["coordination_declarations"] = _sorted_record_map(
            cast(Mapping[EventId, _ProjectionRecordLike], state.coordination_declarations)
        )
    if state.pending_missing_for_assessment is not None:
        pending = state.pending_missing_for_assessment
        snapshot["pending_missing_for_assessment"] = {
            "items": [
                {
                    "availability": item.availability,
                    "kind": item.kind,
                    "target_refs": list(item.target_refs),
                }
                for item in pending.items
            ],
            "source_check_event_id": pending.source_check_event_id,
            "source_frontier": canonical_integer_string(pending.source_frontier),
        }
    return snapshot


_SNAPSHOT_KEYS: Final = frozenset(
    {
        "frontier",
        "head_digest",
        "plans",
        "obligations",
        "decisions",
        "assignments",
        "actions",
        "results",
        "evidence",
        "claims",
        "contradictions",
        "findings",
        "responses",
        "latest_tested_state",
        "freshness",
        "unknown_event_count",
        "coverage_gaps",
        "coordination_contexts",
        "coordination_dispositions",
        "coordination_declarations",
        "pending_missing_for_assessment",
    }
)
_REQUIRED_SNAPSHOT_KEYS: Final = _SNAPSHOT_KEYS - {
    "coordination_contexts",
    "coordination_dispositions",
    "coordination_declarations",
    "pending_missing_for_assessment",
}
_RECORD_KEYS: Final = frozenset(
    {"payload", "payload_digest", "redacted", "source_event_id", "source_frontier"}
)
_COLLECTION_SCHEMAS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "plans": ("plan_published", "plan_revised"),
        "obligations": ("obligation_published",),
        "decisions": ("decision_recorded",),
        "assignments": ("assignment_recorded",),
        "actions": ("action_recorded",),
        "results": ("result_recorded",),
        "evidence": ("evidence_recorded",),
        "claims": ("claim_recorded",),
        "findings": ("finding_recorded",),
        "responses": ("response_recorded",),
        "coordination_contexts": ("coordination_context_recorded",),
        "coordination_dispositions": ("coordination_disposition_recorded",),
        "coordination_declarations": ("coordination_obligation_declared",),
    }
)


def _snapshot_object(
    value: object,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise _invalid()
    source = cast(Mapping[object, object], value)
    keys = tuple(source)
    if any(type(key) is not str for key in keys):
        raise _invalid()
    typed = cast(Mapping[str, JsonValue], source)
    key_set = frozenset(cast(tuple[str, ...], keys))
    if not required <= key_set or key_set - required - optional:
        raise _invalid()
    return typed


def _snapshot_map(value: object) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise _invalid()
    source = cast(Mapping[object, object], value)
    keys = tuple(source)
    if any(type(key) is not str for key in keys):
        raise _invalid()
    return cast(Mapping[str, JsonValue], source)


def _snapshot_array(value: object) -> tuple[JsonValue, ...]:
    if type(value) is not tuple:
        raise _invalid()
    return cast(tuple[JsonValue, ...], value)


def _snapshot_uint(value: object, *, safe: bool = False) -> int:
    parsed = parse_canonical_integer_string(cast(str, value))
    if safe and parsed > _MAX_SAFE_INTEGER:
        raise _invalid()
    return parsed


def _schema_versions(schema_name: str) -> tuple[str, ...]:
    """Every known wire version of one schema name, newest first."""

    versions = sorted(
        {schema.version for schema in PAYLOAD_TYPES if schema.name == schema_name},
        key=lambda version: tuple(int(part) for part in version.split(".")),
        reverse=True,
    )
    if not versions:
        raise _invalid()
    return tuple(versions)


def _decoded_payload(value: JsonValue, schemas: tuple[str, ...]) -> EventPayload:
    # A snapshot record carries no schema version: generation-1 snapshots were minted when every
    # family had exactly one, and adding the version to the record would change the canonical
    # bytes every stored case_digest and resume pointer is bound to. Decoding with a pinned
    # "1.0.0" therefore rejected any payload a later version admits — an evidence record with a
    # ``digest_binding`` (evidence_recorded/1.1.0) failed as ``unknown_payload_field``, which
    # turned every deferred rehydration of a frozen case (privacy-wait replay, ledger recovery)
    # into a non-retryable STORAGE_CORRUPT on an intact bundle (issue #427). Each name decodes
    # under its newest admitting version instead; the name ambiguity check is unchanged.
    decoded: list[EventPayload] = []
    for schema_name in schemas:
        for version in _schema_versions(schema_name):
            try:
                payload = decode_payload(
                    EventSchema(schema_name, version),
                    cast(DomainJsonValue, value),
                )
            except ValueError:
                continue
            decoded.append(payload)
            break
    if len(decoded) != 1:
        raise _invalid()
    return decoded[0]


def _record_from_snapshot(
    value: JsonValue,
    *,
    collection: str,
) -> _ProjectionRecordLike:
    optional: frozenset[str]
    required = _RECORD_KEYS
    if collection == "plans":
        optional = frozenset({"superseded_by_plan_version"})
    elif collection == "obligations":
        optional = frozenset(
            {
                "plan_change",
                "plan_change_reason",
                "superseded_by_obligation_ids",
                "introduced_frontier",
            }
        )
    elif collection == "claims":
        optional = frozenset({"superseded_by_claim_id"})
    elif collection == "decisions":
        optional = frozenset({"superseded_by_event_id"})
    elif collection == "evidence":
        required = _RECORD_KEYS | frozenset({"object_available"})
        optional = frozenset({"redacted_object_id"})
    elif collection == "findings":
        optional = frozenset(
            {
                *_FINDING_RESOLUTION_EVENT_FIELDS,
                "review_rounds",
                "check_change_raising_check_event_ids",
                "check_change_raised_files",
                "resolution_depends_on_check_event_ids",
                "rebuttal_count",
                "last_reviewer_verdict",
                "settled_reraise_count",
                "duplicate_link_broken_by_check_event_ids",
                "standing_position",
                "last_ruling_frontier",
                "resolution_frontier",
                "absorbed_refs",
                "observed_failed_command",
                "failed_run_result_id",
                "retired_by_event_id",
                "retired_frontier",
                "retired_by_planned_verification",
            }
        )
    else:
        optional = frozenset()
    source = _snapshot_object(value, required=required, optional=optional)
    raw_payload = source["payload"]
    payload = (
        None
        if raw_payload is None
        else _decoded_payload(raw_payload, _COLLECTION_SCHEMAS[collection])
    )
    payload_digest = source["payload_digest"]
    redacted = source["redacted"]
    if type(payload_digest) is not str or type(redacted) is not bool:
        raise _invalid()
    source_event_id = event_id(source["source_event_id"])
    source_frontier = _snapshot_uint(source["source_frontier"])
    if collection == "plans":
        raw_superseded = source.get("superseded_by_plan_version")
        if "superseded_by_plan_version" in source and raw_superseded is None:
            raise _invalid()
        return PlanProjectionRecord(
            payload=cast(PlanPublishedPayload | PlanRevisedPayload | None, payload),
            payload_digest=payload_digest,
            redacted=redacted,
            source_event_id=source_event_id,
            source_frontier=source_frontier,
            superseded_by_plan_version=(
                None if raw_superseded is None else _snapshot_uint(raw_superseded, safe=True)
            ),
        )
    if collection == "obligations":
        has_change = "plan_change" in source
        if has_change is not ("superseded_by_obligation_ids" in source):
            raise _invalid()
        if not has_change and "plan_change_reason" in source:
            raise _invalid()
        if "plan_change_reason" in source and source["plan_change_reason"] is None:
            raise _invalid()
        raw_replacements = source.get("superseded_by_obligation_ids", ())
        return ObligationProjectionRecord(
            payload=cast(ObligationPublishedPayload | None, payload),
            payload_digest=payload_digest,
            redacted=redacted,
            source_event_id=source_event_id,
            source_frontier=source_frontier,
            plan_change=(
                None if not has_change else ObligationChangeKind(cast(str, source["plan_change"]))
            ),
            plan_change_reason=cast(str | None, source.get("plan_change_reason")),
            superseded_by_obligation_ids=cast(
                tuple[ObligationId, ...],
                _snapshot_array(raw_replacements),
            ),
            introduced_frontier=(
                _snapshot_uint(source["introduced_frontier"], safe=True)
                if "introduced_frontier" in source
                else None
            ),
        )
    if collection == "claims":
        if "superseded_by_claim_id" in source and source["superseded_by_claim_id"] is None:
            raise _invalid()
        return ClaimProjectionRecord(
            payload=cast(ClaimRecordedPayload | ClaimRecordedPayloadV1_1 | None, payload),
            payload_digest=payload_digest,
            redacted=redacted,
            source_event_id=source_event_id,
            source_frontier=source_frontier,
            superseded_by_claim_id=cast(ClaimId | None, source.get("superseded_by_claim_id")),
        )
    if collection == "decisions":
        if "superseded_by_event_id" in source and source["superseded_by_event_id"] is None:
            raise _invalid()
        return DecisionProjectionRecord(
            payload=cast(DecisionRecordedPayload | None, payload),
            payload_digest=payload_digest,
            redacted=redacted,
            source_event_id=source_event_id,
            source_frontier=source_frontier,
            superseded_by_event_id=cast(EventId | None, source.get("superseded_by_event_id")),
        )
    if collection == "evidence":
        if "redacted_object_id" in source and source["redacted_object_id"] is None:
            raise _invalid()
        return EvidenceProjectionRecord(
            payload=cast(EvidenceRecordedPayload | None, payload),
            payload_digest=payload_digest,
            redacted=redacted,
            source_event_id=source_event_id,
            source_frontier=source_frontier,
            object_available=cast(bool, source["object_available"]),
            redacted_object_id=cast(ObjectId | None, source.get("redacted_object_id")),
        )
    if collection == "findings":
        for name in (
            *_FINDING_RESOLUTION_EVENT_FIELDS,
            "check_change_raising_check_event_ids",
            "check_change_raised_files",
            "resolution_depends_on_check_event_ids",
            "duplicate_link_broken_by_check_event_ids",
        ):
            if name in source and source[name] is None:
                raise _invalid()

        rounds = source.get("review_rounds", 0)
        if "review_rounds" in source and (type(rounds) is not int or rounds < 1):
            raise _invalid()
        rebuttals = source.get("rebuttal_count", 0)
        if "rebuttal_count" in source and (type(rebuttals) is not int or rebuttals < 1):
            raise _invalid()
        reraises = source.get("settled_reraise_count", 0)
        if "settled_reraise_count" in source and (type(reraises) is not int or reraises < 1):
            raise _invalid()
        last_verdict = source.get("last_reviewer_verdict")
        if "last_reviewer_verdict" in source and type(last_verdict) is not str:
            raise _invalid()
        standing: StandingPosition | None = None
        if "standing_position" in source:
            raw_position = _snapshot_object(
                source["standing_position"], required=frozenset({"kind", "frontier"})
            )
            kind_value, frontier_value = raw_position["kind"], raw_position["frontier"]
            if type(kind_value) is not str or type(frontier_value) is not int:
                raise _invalid()
            standing = StandingPosition(kind_value, frontier_value)
        absorbed: tuple[str, ...] = ()
        if "absorbed_refs" in source:
            raw_absorbed = source["absorbed_refs"]
            if type(raw_absorbed) not in {list, tuple} or not raw_absorbed:
                raise _invalid()
            absorbed = tuple(cast(list[str], raw_absorbed))
        for frontier_name in ("last_ruling_frontier", "resolution_frontier", "retired_frontier"):
            if frontier_name in source:
                frontier_raw = source[frontier_name]
                if type(frontier_raw) is not int or frontier_raw < 1:
                    raise _invalid()
        for flag in ("observed_failed_command", "retired_by_planned_verification"):
            if flag in source and source[flag] is not True:
                raise _invalid()
        for name in ("failed_run_result_id", "retired_by_event_id"):
            if name in source and type(source[name]) is not str:
                raise _invalid()

        def event_ids(name: str) -> tuple[EventId, ...]:
            raw = source.get(name)
            if raw is None:
                return ()
            if type(raw) not in {list, tuple} or not raw:
                raise _invalid()
            return cast(tuple[EventId, ...], tuple(cast(list[object], raw)))

        raw_files = source.get("check_change_raised_files")
        try:
            raised_files = None if raw_files is None else check_change_files_from_json(raw_files)
        except ValueError as exc:
            raise _invalid() from exc
        return FindingProjectionRecord(
            payload=cast(Finding | None, payload),
            payload_digest=payload_digest,
            redacted=redacted,
            source_event_id=source_event_id,
            source_frontier=source_frontier,
            resolved_by_check_event_id=cast(
                EventId | None, source.get("resolved_by_check_event_id")
            ),
            review_rounds=cast(int, rounds),
            rejection_accepted_by_check_event_id=cast(
                EventId | None, source.get("rejection_accepted_by_check_event_id")
            ),
            disputed_after_rebuttal_by_check_event_id=cast(
                EventId | None, source.get("disputed_after_rebuttal_by_check_event_id")
            ),
            check_change_raising_check_event_ids=event_ids("check_change_raising_check_event_ids"),
            check_change_raised_files=raised_files,
            resolution_depends_on_check_event_ids=event_ids(
                "resolution_depends_on_check_event_ids"
            ),
            reduced_scope_raising_check_event_id=cast(
                EventId | None, source.get("reduced_scope_raising_check_event_id")
            ),
            resolution_raising_check_event_id=cast(
                EventId | None, source.get("resolution_raising_check_event_id")
            ),
            rebuttal_count=cast(int, rebuttals),
            last_reviewer_verdict=cast(str | None, last_verdict),
            settled_reraise_count=cast(int, reraises),
            duplicate_link_broken_by_check_event_ids=event_ids(
                "duplicate_link_broken_by_check_event_ids"
            ),
            standing_position=standing,
            last_ruling_frontier=cast(int | None, source.get("last_ruling_frontier")),
            resolution_frontier=cast(int | None, source.get("resolution_frontier")),
            absorbed_refs=absorbed,
            observed_failed_command="observed_failed_command" in source,
            failed_run_result_id=cast(ResultId | None, source.get("failed_run_result_id")),
            retired_by_event_id=cast(EventId | None, source.get("retired_by_event_id")),
            retired_frontier=cast(int | None, source.get("retired_frontier")),
            retired_by_planned_verification="retired_by_planned_verification" in source,
        )
    return ProjectionRecord(
        payload=payload,
        payload_digest=payload_digest,
        redacted=redacted,
        source_event_id=source_event_id,
        source_frontier=source_frontier,
    )


def _record_map_from_snapshot(
    value: JsonValue,
    *,
    collection: str,
) -> dict[str, _ProjectionRecordLike]:
    source = _snapshot_map(value)
    return {
        key: _record_from_snapshot(record, collection=collection) for key, record in source.items()
    }


def _plans_from_snapshot(value: JsonValue) -> dict[int, PlanProjectionRecord]:
    decoded = _record_map_from_snapshot(value, collection="plans")
    return {
        _snapshot_uint(key, safe=True): cast(PlanProjectionRecord, record)
        for key, record in decoded.items()
    }


def _latest_tested_from_snapshot(value: JsonValue) -> LatestTestedState | None:
    if value is None:
        return None
    source = _snapshot_object(
        value,
        required=frozenset(
            {
                "source_check_event_id",
                "subject_frontier",
                "verdict",
                "returned_finding_ids",
                "suppressed_count",
                "coverage",
            }
        ),
    )
    return LatestTestedState(
        source_check_event_id=cast(EventId, source["source_check_event_id"]),
        subject_frontier=frontier_from_json(source["subject_frontier"]),
        verdict=CheckVerdict(cast(str, source["verdict"])),
        returned_finding_ids=cast(
            tuple[FindingId, ...],
            _snapshot_array(source["returned_finding_ids"]),
        ),
        suppressed_count=cast(int, source["suppressed_count"]),
        coverage=coverage_from_json(source["coverage"]),
    )


def _pending_missing_from_snapshot(value: JsonValue | None) -> PendingMissingForAssessment | None:
    if value is None:
        return None
    source = _snapshot_object(
        value, required=frozenset({"items", "source_check_event_id", "source_frontier"})
    )
    items: list[MissingForAssessmentItem] = []
    for raw in _snapshot_array(source["items"]):
        row = _snapshot_object(raw, required=frozenset({"availability", "kind", "target_refs"}))
        items.append(
            MissingForAssessmentItem(
                kind=cast(str, row["kind"]),
                target_refs=cast(tuple[str, ...], _snapshot_array(row["target_refs"])),
                availability=cast(str, row["availability"]),
            )
        )
    return PendingMissingForAssessment(
        source_check_event_id=cast(EventId, source["source_check_event_id"]),
        source_frontier=_snapshot_uint(source["source_frontier"], safe=True),
        items=tuple(items),
    )


def _contradictions_from_snapshot(
    value: JsonValue,
) -> dict[ContradictionKey, ContradictionRecord]:
    source = _snapshot_map(value)
    result: dict[ContradictionKey, ContradictionRecord] = {}
    for encoded_key, raw_record in source.items():
        parts = encoded_key.split("|")
        if len(parts) != 2:
            raise _invalid()
        record_source = _snapshot_object(
            raw_record,
            required=frozenset(
                {
                    "disputing_claim_id",
                    "disputed_ref",
                    "source_event_id",
                    "source_frontier",
                }
            ),
        )
        if parts != [record_source["disputing_claim_id"], record_source["disputed_ref"]]:
            raise _invalid()
        key = ContradictionKey(
            disputing_claim_id=cast(ClaimId, record_source["disputing_claim_id"]),
            disputed_ref=cast(ClaimId | EventId, record_source["disputed_ref"]),
        )
        result[key] = ContradictionRecord(
            disputing_claim_id=key.disputing_claim_id,
            disputed_ref=key.disputed_ref,
            source_event_id=cast(EventId, record_source["source_event_id"]),
            source_frontier=_snapshot_uint(record_source["source_frontier"]),
        )
    return result


def projection_from_snapshot(value: JsonValue) -> ProjectionState:
    """Decode and revalidate one exact generation-1 projection snapshot."""

    try:
        frozen = freeze_json(value)
        source = _snapshot_object(
            frozen,
            required=frozenset(_REQUIRED_SNAPSHOT_KEYS),
            optional=frozenset(
                {
                    "coordination_contexts",
                    "coordination_dispositions",
                    "coordination_declarations",
                    "pending_missing_for_assessment",
                }
            ),
        )
        freshness_value = source["freshness"]
        if type(freshness_value) is not str:
            raise _invalid()
        return ProjectionState(
            frontier=_snapshot_uint(source["frontier"]),
            head_digest=cast(str, source["head_digest"]),
            plans=_plans_from_snapshot(source["plans"]),
            obligations=cast(
                Mapping[ObligationId, ObligationProjectionRecord],
                _record_map_from_snapshot(source["obligations"], collection="obligations"),
            ),
            decisions=cast(
                Mapping[EventId, DecisionProjectionRecord],
                _record_map_from_snapshot(source["decisions"], collection="decisions"),
            ),
            assignments=cast(
                Mapping[EventId, ProjectionRecord[AssignmentRecordedPayload]],
                _record_map_from_snapshot(source["assignments"], collection="assignments"),
            ),
            actions=cast(
                Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]],
                _record_map_from_snapshot(source["actions"], collection="actions"),
            ),
            results=cast(
                Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]],
                _record_map_from_snapshot(source["results"], collection="results"),
            ),
            evidence=cast(
                Mapping[EvidenceId, EvidenceProjectionRecord],
                _record_map_from_snapshot(source["evidence"], collection="evidence"),
            ),
            claims=cast(
                Mapping[ClaimId, ClaimProjectionRecord],
                _record_map_from_snapshot(source["claims"], collection="claims"),
            ),
            contradictions=_contradictions_from_snapshot(source["contradictions"]),
            findings=cast(
                Mapping[FindingId, FindingProjectionRecord],
                _record_map_from_snapshot(source["findings"], collection="findings"),
            ),
            responses=cast(
                Mapping[FindingId, ProjectionRecord[ResponseRecordedPayload]],
                _record_map_from_snapshot(source["responses"], collection="responses"),
            ),
            latest_tested_state=_latest_tested_from_snapshot(source["latest_tested_state"]),
            freshness=LedgerFreshness(freshness_value),
            unknown_event_count=cast(int, source["unknown_event_count"]),
            coverage_gaps=cast(tuple[str, ...], _snapshot_array(source["coverage_gaps"])),
            coordination_contexts=cast(
                Mapping[EventId, ProjectionRecord[CoordinationContextRecordedPayload]],
                _record_map_from_snapshot(
                    source.get("coordination_contexts", {}),
                    collection="coordination_contexts",
                ),
            ),
            coordination_dispositions=cast(
                Mapping[EventId, ProjectionRecord[CoordinationDispositionRecordedPayload]],
                _record_map_from_snapshot(
                    source.get("coordination_dispositions", {}),
                    collection="coordination_dispositions",
                ),
            ),
            coordination_declarations=cast(
                Mapping[EventId, ProjectionRecord[CoordinationObligationDeclaredPayload]],
                _record_map_from_snapshot(
                    source.get("coordination_declarations", {}),
                    collection="coordination_declarations",
                ),
            ),
            pending_missing_for_assessment=_pending_missing_from_snapshot(
                source.get("pending_missing_for_assessment")
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        if type(exc) is ValueError and str(exc) == "invalid_projection_state":
            raise
        raise _invalid() from exc


def projection_digest(state: ProjectionState) -> str:
    """Digest the exact canonical projection snapshot."""

    return canonical_digest(projection_snapshot(state))
