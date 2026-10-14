"""Pure accepted-event replay into immutable work projections."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Final, cast

from finishup.domain.events import (
    LINEAGE_SERVICE_STAMPED_FAMILIES,
    AcceptedEvent,
    ActionRecordedPayload,
    AssignmentRecordedPayload,
    CheckRecordedPayload,
    ChildDependenciesRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    ClaimRevisionMismatch,
    CoordinationContextRecordedPayload,
    CoordinationDispositionRecordedPayload,
    CoordinationObligationDeclaredPayload,
    DecisionRecordedPayload,
    EvidenceRecordedPayload,
    FindingRecordedPayload,
    LedgerRecord,
    NoObligationsReasonMismatch,
    ObligationPublishedPayload,
    ObligationResolutionMismatch,
    ObligationStatus,
    PlanPublishedPayload,
    PlanRevisedPayload,
    RedactionRecordedPayload,
    ResponseRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    UnknownEvent,
    encode_payload,
    is_lineage_service_stamped,
    is_observation_authored,
    obligation_meaning_field_diffs,
)
from finishup.domain.findings import Finding, ResponseDisposition
from finishup.domain.task_statement import may_carry_task_statement
from finishup.domain.values import (
    ActionId,
    ClaimId,
    EventId,
    EvidenceId,
    FindingId,
    ObjectId,
    ObligationId,
    ResultId,
    action_id,
    claim_id,
    event_id,
    evidence_id,
    finding_id,
    object_id,
    obligation_id,
    result_id,
    validate_sha256_digest,
)
from finishup.kernel.claim_limitations import (
    DISCLOSABLE_LIMITING_OUTCOMES,
    required_limitation_result_ids,
    result_is_relevant_to_claim_scope,
)
from finishup.kernel.finding_resolution import (
    apply_check_resolution,
    apply_check_rulings,
    next_standing_position,
    reopen_findings_resolved_by,
)
from finishup.kernel.later_material import (
    LaterMaterialClass,
    classify_later_material,
    later_material_class,
)
from finishup.kernel.observed_failures import is_observed_run_record
from finishup.kernel.plan_scope import current_plan_scope
from finishup.kernel.projections import (
    ClaimProjectionRecord,
    ContradictionKey,
    ContradictionRecord,
    DecisionProjectionRecord,
    EvidenceProjectionRecord,
    FindingProjectionRecord,
    LatestTestedState,
    ObligationProjectionRecord,
    PendingMissingForAssessment,
    PlanProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    derive_projection_state,
    empty_projection_state,
    is_observation_limitation,
)
from finishup.kernel.task_facts import disclosure_line_obligations
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.coverage import LedgerFreshness

__all__ = [
    "EvidenceObjectSource",
    "LaterMaterialClass",
    "ReplayIndex",
    "build_replay_index",
    "empty_replay_index",
    "extend_replay_index",
    "invalidates_recorded_check",
    "is_material_event_family",
    "later_material_class",
    "reduce_event",
    "replay_with_index",
    "replay_extension",
    "replay_extension_with_index",
    "validate_replay_index",
    "supersedes_recorded_check",
    "replay",
]

_MAX_SQLITE_SIGNED_INTEGER: Final = 2**63 - 1
# Responses that dispute a finding and count as rebuttals (TB4 tb4n1 D7). ``self_verified`` is
# compared by its wire value so this fold reads ledgers written before and after that
# disposition exists.
_REBUTTAL_DISPOSITION_VALUES: Final = frozenset(
    {ResponseDisposition.REJECTED.value, "self_verified"}
)
# The v1.1 completion-claim limitation rule lives in ``finishup.kernel.claim_limitations`` so a
# surface can name the required ids before the claim (F3); the reducer reads the same rule.
_MATERIAL_FAMILIES: Final = frozenset(
    {
        "action_recorded",
        "assignment_recorded",
        "claim_recorded",
        "decision_recorded",
        "evidence_recorded",
        "finding_recorded",
        "obligation_published",
        "plan_published",
        "plan_revised",
        "response_recorded",
        "result_recorded",
        # A child-dependency aggregate changes the parent-visible work facts.  It is retained as
        # a structural event (the pure lineage evaluator owns its contents), but a later event
        # still has to participate in the check/receipt freshness walk.
        "child_dependencies_recorded",
        "coordination_context_recorded",
        "coordination_obligation_declared",
        "coordination_disposition_recorded",
    }
)

_LINEAGE_EVENT_FAMILIES: Final = frozenset(
    {
        "delegation_declared",
        "delegation_cancelled",
        "child_accepted",
        "child_rejected",
        "child_written_off",
        "child_dependencies_recorded",
        "work_closed",
        "work_abandoned",
        "work_cancelled",
        "work_written_off",
    }
)


def is_material_event_family(name: str) -> bool:
    """True when the family ordinarily represents a material work-state transition."""
    return name in _MATERIAL_FAMILIES


# Dispositions no local policy pack scores (only ``rejected`` and ``waived`` responses can raise
# ``weak_or_stale_response`` or ``questionable_finding_rejection``), so recording one cannot change
# what a later check would conclude about the answered finding.
_UNSCORED_RESPONSE_DISPOSITIONS: Final = frozenset(
    {ResponseDisposition.ACKNOWLEDGED, ResponseDisposition.PROVENANCE_DISPUTED}
)


def supersedes_recorded_check(
    name: str,
    payload: object,
    returned_finding_ids: tuple[FindingId, ...],
    limitation_finding_ids: frozenset[FindingId] = frozenset(),
) -> bool:
    """True when a record of *name* carrying *payload* supersedes a check returning those findings.

    Answering a finding the check itself returned reports on that check's own output rather than
    publishing untested work, so such a response leaves the check attributable to a later receipt.
    Acknowledging (or disputing the provenance of) an observation-authored, non-actionable finding
    in *limitation_finding_ids* is likewise not new work: no check returns such a disclosed
    limitation, no policy pack scores that disposition, and a recheck could not change its result
    (issue #911). Every other material-family record supersedes the check, including any other
    response to a finding the check did not return (a response can change what the next check
    judges) and a response whose payload is unreadable.
    """

    if not is_material_event_family(name):
        return False
    if (
        name == "child_dependencies_recorded"
        and type(payload) is ChildDependenciesRecordedPayload
        and not payload.children
    ):
        # An observed empty inventory establishes the baseline but adds no child-derived work.
        # It must not make an otherwise qualifying check stale when maintenance records that
        # baseline after the check; a later non-empty replacement remains material.
        return False
    if name != "response_recorded":
        return True
    if type(payload) is not ResponseRecordedPayload:
        return True
    if payload.finding_id in returned_finding_ids:
        return False
    return not (
        payload.finding_id in limitation_finding_ids
        and payload.disposition in _UNSCORED_RESPONSE_DISPOSITIONS
    )


def invalidates_recorded_check(
    record: LedgerRecord,
    check_sequence: int,
    returned_finding_ids: tuple[FindingId, ...],
    *,
    limitation_finding_ids: frozenset[FindingId],
    projection: ProjectionState,
) -> bool:
    """True when *record* supersedes the check recorded at *check_sequence*.

    ``limitation_finding_ids`` is ``projections.observation_limitation_finding_ids`` over the same
    projection and records, so every surface applies the reducer's issue #911 rule identically.
    ``projection`` is the one the caller holds for the same prefix: an observed edit supersedes
    the check by the shared ``later_material_class`` rule (tb4n3 RC-6), which reads the declared
    outputs to decide which writes count and the action row a result answers.
    """

    if record.ledger.ingestion_sequence <= check_sequence:
        return False
    return _record_supersedes_recorded_check(
        record, returned_finding_ids, limitation_finding_ids, projection
    )


def _record_supersedes_recorded_check(
    record: LedgerRecord,
    returned_finding_ids: tuple[FindingId, ...],
    limitation_finding_ids: frozenset[FindingId],
    projection: ProjectionState,
) -> bool:
    """Apply the shared authorship-aware supersession rule to a later record."""

    if is_observation_authored(record):
        # Hook delivery reports what the harness observed; it does not publish new cooperative
        # work on the participant's behalf. Keep the check attributable across that motion unless
        # the observation suffix materialized a finding that the older check could not cover, or
        # an observed deliverable/workspace edit changed the state the check read (tb4n3 RC-6,
        # C7). FinishUP's own calls, exploration and host bookkeeping never do.
        return (
            record.schema.name == "finding_recorded"
            or classify_later_material(record, projection).supersedes
        )
    return supersedes_recorded_check(
        record.schema.name, record.payload, returned_finding_ids, limitation_finding_ids
    )


def _answered_limitation_ids(
    state: ProjectionState, event: AcceptedEvent, replay_index: ReplayIndex
) -> frozenset[FindingId]:
    """The answered finding's id when *event* responds to an observation-authored limitation."""

    payload = event.payload
    if event.schema.name != "response_recorded" or type(payload) is not ResponseRecordedPayload:
        return frozenset()
    answered = state.findings.get(payload.finding_id)
    if answered is None or not is_observation_limitation(
        answered, replay_index.observation_finding_event_ids
    ):
        return frozenset()
    return frozenset({payload.finding_id})


def _corrupt() -> ValueError:
    return ValueError("projection_corrupt")


def _ascii_key(value: str) -> bytes:
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise _corrupt() from exc


def _next_record(frontier: int, head_digest: str, event: LedgerRecord) -> None:
    if type(event) not in {AcceptedEvent, UnknownEvent}:
        raise _corrupt()
    if (
        event.ledger.ingestion_sequence != frontier + 1
        or event.ledger.previous_entry_digest != head_digest
    ):
        raise _corrupt()


@dataclass(frozen=True, slots=True)
class EvidenceObjectSource:
    evidence_id: EvidenceId
    source_event_id: EventId

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "evidence_id", evidence_id(self.evidence_id))
            object.__setattr__(self, "source_event_id", event_id(self.source_event_id))
        except ValueError as exc:
            raise _corrupt() from exc


_ABSENT: Final = object()
# Set only by ``extend_replay_index`` around one constructor call: entries carried unchanged (by
# identity) from the already-validated prior index skip per-id re-validation, which otherwise made
# every stepwise replay quadratic in ledger length (issue #886). Whole-index invariants still run.
_TRUSTED_PRIOR_INDEX: ContextVar[ReplayIndex | None] = ContextVar(
    "finishup_trusted_prior_replay_index", default=None
)


@dataclass(frozen=True, slots=True)
class ReplayIndex:
    frontier: int
    head_digest: str
    payload_event_by_object: Mapping[ObjectId, EventId]
    evidence_sources_by_object: Mapping[ObjectId, tuple[EvidenceObjectSource, ...]]
    redaction_root_by_object: Mapping[ObjectId, EventId]
    # Service-stamped observation-authored ``finding_recorded`` events. Authorship is an envelope
    # fact the projection does not retain; the fold needs it to keep a check attributable across
    # an acknowledgement of an observation-authored limitation (issue #911).
    observation_finding_event_ids: frozenset[EventId]
    # Service-stamped hook-observed action/result events. Authorship lives on the envelope, not
    # the projection, so the claim-revision invariant reads provenance here (#909).
    observed_event_ids: frozenset[EventId] = frozenset()
    # The ingestion sequence of the first event that may have carried a task statement
    # (``may_carry_task_statement``, issue #908); ``None`` while the prefix has none. Finding resolution uses it to recognize an
    # AI-powered finding raised before any review could have received a statement.
    first_task_statement_sequence: int | None = None

    def __post_init__(self) -> None:
        if type(self.frontier) is not int or not 0 <= self.frontier <= _MAX_SQLITE_SIGNED_INTEGER:
            raise _corrupt()
        first = self.first_task_statement_sequence
        if first is not None and (type(first) is not int or not 1 <= first <= self.frontier):
            raise _corrupt()
        try:
            if self.frontier == 0:
                if type(self.head_digest) is not str or self.head_digest != "genesis":
                    raise _corrupt()
            else:
                validate_sha256_digest(self.head_digest)
        except ValueError as exc:
            raise _corrupt() from exc
        prior = _TRUSTED_PRIOR_INDEX.get()
        if type(prior) is not ReplayIndex or prior.frontier > self.frontier:
            prior = None
        payloads = self._copy_payload_owners(
            self.payload_event_by_object, None if prior is None else prior.payload_event_by_object
        )
        evidence = self._copy_evidence_sources(
            self.evidence_sources_by_object,
            None if prior is None else prior.evidence_sources_by_object,
        )
        roots = self._copy_redaction_roots(
            self.redaction_root_by_object,
            None if prior is None else prior.redaction_root_by_object,
        )
        accepted_event_ids = frozenset(payloads.values())
        if len(payloads) != self.frontier or len(accepted_event_ids) != len(payloads):
            raise _corrupt()
        seen_associations: set[EvidenceObjectSource] = set()
        for associations in evidence.values():
            for association in associations:
                if (
                    association.source_event_id not in accepted_event_ids
                    or association in seen_associations
                ):
                    raise _corrupt()
                seen_associations.add(association)
        if any(root not in accepted_event_ids for root in roots.values()):
            raise _corrupt()
        if type(self.observed_event_ids) is not frozenset or not (
            self.observed_event_ids <= accepted_event_ids
        ):
            raise _corrupt()
        observation_findings = self._copy_observation_findings(
            self.observation_finding_event_ids,
            None if prior is None else prior.observation_finding_event_ids,
        )
        if any(item not in accepted_event_ids for item in observation_findings):
            raise _corrupt()
        object.__setattr__(self, "payload_event_by_object", MappingProxyType(payloads))
        object.__setattr__(self, "evidence_sources_by_object", MappingProxyType(evidence))
        object.__setattr__(self, "redaction_root_by_object", MappingProxyType(roots))
        object.__setattr__(self, "observation_finding_event_ids", observation_findings)

    @staticmethod
    def _copy_observation_findings(
        source: frozenset[EventId],
        trusted: frozenset[EventId] | None,
    ) -> frozenset[EventId]:
        if trusted is not None and source is trusted:
            return trusted
        if type(cast(object, source)) is not frozenset:
            raise _corrupt()
        try:
            return frozenset(event_id(item) for item in source)
        except ValueError as exc:
            raise _corrupt() from exc

    @staticmethod
    def _copy_payload_owners(
        source: Mapping[ObjectId, EventId],
        trusted: Mapping[ObjectId, EventId] | None,
    ) -> dict[ObjectId, EventId]:
        if not isinstance(cast(object, source), Mapping):
            raise _corrupt()
        result: dict[ObjectId, EventId] = {}
        try:
            for raw_object, raw_event in source.items():
                if trusted is not None and trusted.get(raw_object, _ABSENT) is raw_event:
                    result[raw_object] = raw_event
                    continue
                result[object_id(raw_object)] = event_id(raw_event)
        except ValueError as exc:
            raise _corrupt() from exc
        return result

    @staticmethod
    def _copy_evidence_sources(
        source: Mapping[ObjectId, tuple[EvidenceObjectSource, ...]],
        trusted: Mapping[ObjectId, tuple[EvidenceObjectSource, ...]] | None,
    ) -> dict[ObjectId, tuple[EvidenceObjectSource, ...]]:
        if not isinstance(cast(object, source), Mapping):
            raise _corrupt()
        result: dict[ObjectId, tuple[EvidenceObjectSource, ...]] = {}
        try:
            for raw_object, raw_sources in source.items():
                if trusted is not None and trusted.get(raw_object, _ABSENT) is raw_sources:
                    result[raw_object] = raw_sources
                    continue
                key = object_id(raw_object)
                if type(raw_sources) is not tuple or any(
                    type(item) is not EvidenceObjectSource for item in raw_sources
                ):
                    raise _corrupt()
                ordered = tuple(
                    sorted(
                        raw_sources,
                        key=lambda item: (
                            _ascii_key(item.evidence_id),
                            _ascii_key(item.source_event_id),
                        ),
                    )
                )
                if raw_sources != ordered or len(raw_sources) != len(set(raw_sources)):
                    raise _corrupt()
                result[key] = tuple(raw_sources)
        except ValueError as exc:
            if str(exc) == "projection_corrupt":
                raise
            raise _corrupt() from exc
        return result

    @staticmethod
    def _copy_redaction_roots(
        source: Mapping[ObjectId, EventId],
        trusted: Mapping[ObjectId, EventId] | None,
    ) -> dict[ObjectId, EventId]:
        if not isinstance(cast(object, source), Mapping):
            raise _corrupt()
        result: dict[ObjectId, EventId] = {}
        try:
            for raw_object, raw_event in source.items():
                if trusted is not None and trusted.get(raw_object, _ABSENT) is raw_event:
                    result[raw_object] = raw_event
                    continue
                result[object_id(raw_object)] = event_id(raw_event)
        except ValueError as exc:
            raise _corrupt() from exc
        return result


def empty_replay_index() -> ReplayIndex:
    """Return the exact non-plaintext genesis reverse index."""

    return ReplayIndex(
        frontier=0,
        head_digest="genesis",
        payload_event_by_object={},
        evidence_sources_by_object={},
        redaction_root_by_object={},
        observation_finding_event_ids=frozenset(),
    )


def extend_replay_index(index: ReplayIndex, event: LedgerRecord) -> ReplayIndex:
    """Validate and extend the reverse index by one accepted envelope."""

    if type(index) is not ReplayIndex:
        raise _corrupt()
    _next_record(index.frontier, index.head_digest, event)
    payload_owners = dict(index.payload_event_by_object)
    evidence_sources = dict(index.evidence_sources_by_object)
    redaction_roots = dict(index.redaction_root_by_object)

    payload_object = event.payload_ref.object_id
    if payload_object in payload_owners:
        raise _corrupt()
    payload_owners[payload_object] = event.event_id

    if type(event) is AcceptedEvent and event.schema.name == "evidence_recorded":
        logical_key = event.projection_locator.logical_key
        if logical_key is None or len(event.artifact_refs) > 1:
            raise _corrupt()
        try:
            evidence_key = evidence_id(logical_key)
        except ValueError as exc:
            raise _corrupt() from exc
        if event.payload is not None:
            payload = cast(EvidenceRecordedPayload, event.payload)
            expected = () if payload.captured_object_id is None else (payload.captured_object_id,)
            if event.artifact_refs != expected:
                raise _corrupt()
        for captured_object in event.artifact_refs:
            association = EvidenceObjectSource(evidence_key, event.event_id)
            current = evidence_sources.get(captured_object, ())
            if association in current:
                raise _corrupt()
            evidence_sources[captured_object] = tuple(
                sorted(
                    (*current, association),
                    key=lambda item: (
                        _ascii_key(item.evidence_id),
                        _ascii_key(item.source_event_id),
                    ),
                )
            )

    if type(event) is AcceptedEvent and event.schema.name == "redaction_recorded":
        targets = event.projection_locator.redaction_target_object_ids
        if event.artifact_refs != targets or event.payload_ref.object_id in targets:
            raise _corrupt()
        if event.payload is not None:
            payload = cast(RedactionRecordedPayload, event.payload)
            if (
                payload.target_event_ids != event.projection_locator.redaction_target_event_ids
                or payload.target_object_ids != targets
            ):
                raise _corrupt()
        for target in targets:
            redaction_roots.setdefault(target, event.event_id)

    observed = (
        index.observed_event_ids | {event.event_id}
        if is_observed_run_record(event)
        else index.observed_event_ids
    )
    observation_findings = index.observation_finding_event_ids
    if _is_observation_finding_record(event):
        observation_findings = observation_findings | {event.event_id}

    token = _TRUSTED_PRIOR_INDEX.set(index)
    try:
        return ReplayIndex(
            frontier=event.ledger.ingestion_sequence,
            head_digest=event.entry_digest,
            payload_event_by_object=payload_owners,
            evidence_sources_by_object=evidence_sources,
            redaction_root_by_object=redaction_roots,
            observed_event_ids=observed,
            observation_finding_event_ids=observation_findings,
            first_task_statement_sequence=(
                index.first_task_statement_sequence
                if index.first_task_statement_sequence is not None
                or not may_carry_task_statement(event)
                else event.ledger.ingestion_sequence
            ),
        )
    finally:
        _TRUSTED_PRIOR_INDEX.reset(token)


def _is_observation_finding_record(event: LedgerRecord) -> bool:
    return (
        type(event) is AcceptedEvent
        and event.schema.name == "finding_recorded"
        and is_observation_authored(event)
    )


def _projection_record[T](event: AcceptedEvent, payload: T) -> ProjectionRecord[T]:
    return ProjectionRecord(
        payload=payload,
        payload_digest=event.projection_locator.canonical_payload_digest,
        redacted=False,
        source_event_id=event.event_id,
        source_frontier=event.ledger.ingestion_sequence,
    )


def _tombstone[T](event: AcceptedEvent, payload_type: type[T]) -> ProjectionRecord[T]:
    del payload_type
    return ProjectionRecord(
        payload=None,
        payload_digest=event.projection_locator.canonical_payload_digest,
        redacted=True,
        source_event_id=event.event_id,
        source_frontier=event.ledger.ingestion_sequence,
    )


def _finding_record(event: AcceptedEvent, payload: Finding | None) -> FindingProjectionRecord:
    return FindingProjectionRecord(
        payload=payload,
        payload_digest=event.projection_locator.canonical_payload_digest,
        redacted=payload is None,
        source_event_id=event.event_id,
        source_frontier=event.ledger.ingestion_sequence,
    )


def _verify_exact_event(state: ProjectionState, event: LedgerRecord, index: ReplayIndex) -> None:
    if type(state) is not ProjectionState or type(index) is not ReplayIndex:
        raise _corrupt()
    _next_record(state.frontier, state.head_digest, event)
    if (
        index.frontier != event.ledger.ingestion_sequence
        or index.head_digest != event.entry_digest
        or index.payload_event_by_object.get(event.payload_ref.object_id) != event.event_id
    ):
        raise _corrupt()
    for marker in state.coverage_gaps:
        if marker.startswith("redacted_object:"):
            try:
                target = object_id(marker.removeprefix("redacted_object:"))
            except ValueError as exc:
                raise _corrupt() from exc
            if target not in index.redaction_root_by_object:
                raise _corrupt()
    if type(event) is AcceptedEvent and event.payload is not None:
        if (
            canonical_digest(encode_payload(event.payload))
            != event.projection_locator.canonical_payload_digest
        ):
            raise _corrupt()
    if type(event) is AcceptedEvent and event.schema.name == "evidence_recorded":
        logical_key = event.projection_locator.logical_key
        if logical_key is None:
            raise _corrupt()
        association = EvidenceObjectSource(evidence_id(logical_key), event.event_id)
        associated_objects = tuple(
            target_object
            for target_object, sources in index.evidence_sources_by_object.items()
            if association in sources
        )
        if tuple(sorted(associated_objects, key=_ascii_key)) != event.artifact_refs:
            raise _corrupt()
    if type(event) is AcceptedEvent and event.schema.name == "redaction_recorded":
        for target_object in event.projection_locator.redaction_target_object_ids:
            if target_object not in index.redaction_root_by_object:
                raise _corrupt()


def _plan_key(event: AcceptedEvent) -> int:
    logical_key = event.projection_locator.logical_key
    if logical_key is None:
        raise _corrupt()
    try:
        parsed = int(logical_key)
    except ValueError as exc:
        raise _corrupt() from exc
    if str(parsed) != logical_key or parsed < 1:
        raise _corrupt()
    return parsed


def _locator_id[T](event: AcceptedEvent, constructor: Callable[[object], T]) -> T:
    logical_key = event.projection_locator.logical_key
    if logical_key is None:
        raise _corrupt()
    try:
        return constructor(logical_key)
    except ValueError as exc:
        raise _corrupt() from exc


_OBLIGATION_TRANSITIONS: Final = frozenset(
    {
        (ObligationStatus.OPEN, ObligationStatus.RESOLVED),
        (ObligationStatus.OPEN, ObligationStatus.ACKNOWLEDGED_NOT_DONE),
        (ObligationStatus.ACKNOWLEDGED_NOT_DONE, ObligationStatus.OPEN),
        (ObligationStatus.ACKNOWLEDGED_NOT_DONE, ObligationStatus.RESOLVED),
        # tb4n2 R2 (issue #1022, ADR-041): a resolution is no longer latched. When its
        # deliverable no longer holds (an emptied output, an acceptance criterion its own output
        # contradicts), the agent reopens it or acknowledges it as not done. Re-resolving a
        # resolved obligation is still refused: a resolution is recorded once per transition.
        (ObligationStatus.RESOLVED, ObligationStatus.OPEN),
        (ObligationStatus.RESOLVED, ObligationStatus.ACKNOWLEDGED_NOT_DONE),
    }
)


def _apply_obligation(
    obligations: dict[ObligationId, ObligationProjectionRecord],
    event: AcceptedEvent,
) -> None:
    key = _locator_id(event, obligation_id)
    existing = obligations.get(key)
    if event.payload is None:
        obligations[key] = ObligationProjectionRecord(
            payload=None,
            payload_digest=event.projection_locator.canonical_payload_digest,
            redacted=True,
            source_event_id=event.event_id,
            source_frontier=event.ledger.ingestion_sequence,
        )
        return
    payload = cast(ObligationPublishedPayload, event.payload)
    if existing is not None and existing.payload is not None:
        previous = existing.payload
        # Resolution is open→resolved only. Meaning fields must repeat; only status and
        # resolution_evidence_refs may change. The comparison deliberately clears evidence
        # refs for meaning equality — that is not free mutation of resolved history.
        # Issue #997 (ADR-032 slice C): an open obligation may be acknowledged as not done, and
        # an acknowledged one reopened or resolved by a later publication (the reverse path).
        meaning_diffs = obligation_meaning_field_diffs(previous, payload)
        # ``acknowledged_not_done`` (obligation_published 1.1.0, #997/#1002) is not resolved; the
        # last effective status wins among open, acknowledged_not_done and resolved. A resolved
        # obligation may be reopened or acknowledged (#1022), never re-resolved in place.
        valid_transition = (previous.status, payload.status) in _OBLIGATION_TRANSITIONS
        if not valid_transition or meaning_diffs:
            if meaning_diffs:
                raise ObligationResolutionMismatch(
                    meaning_diffs,
                    invariant="meaning_fields_must_repeat",
                    event_id=event.event_id,
                )
            raise ObligationResolutionMismatch(
                ("status",),
                invariant="open_to_resolved_only",
                event_id=event.event_id,
                prior_status="resolved" if previous.status is ObligationStatus.RESOLVED else "open",
            )
    obligations[key] = ObligationProjectionRecord(
        payload=payload,
        payload_digest=event.projection_locator.canonical_payload_digest,
        redacted=False,
        source_event_id=event.event_id,
        source_frontier=event.ledger.ingestion_sequence,
        plan_change=None if existing is None else existing.plan_change,
        plan_change_reason=None if existing is None else existing.plan_change_reason,
        superseded_by_obligation_ids=(
            () if existing is None else existing.superseded_by_obligation_ids
        ),
        # A republication only changes status (the meaning fields must repeat), so the obligation
        # keeps the sequence it was first published at (tb4n3 RC-7).
        introduced_frontier=(
            None
            if existing is None or existing.payload is None
            else (existing.introduced_frontier or existing.source_frontier)
        ),
    )


def _claim_scope(
    payload: ClaimRecordedPayload | ClaimRecordedPayloadV1_1,
) -> frozenset[ObligationId]:
    return frozenset(payload.obligation_refs)


def _result_is_relevant_to_claim(
    payload: ClaimRecordedPayload | ClaimRecordedPayloadV1_1,
    result_record: ProjectionRecord[ResultRecordedPayload],
    actions: Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]],
    *,
    claim_frontier: int,
) -> bool:
    return result_is_relevant_to_claim_scope(
        _claim_scope(payload),
        result_record,
        actions,
        claim_frontier=claim_frontier,
    )


def _claim_effective_meaning(
    payload: ClaimRecordedPayload | ClaimRecordedPayloadV1_1,
) -> tuple[object, ...]:
    """Comparable claim meaning, excluding identity and revision linkage."""

    return (
        payload.claim_kind,
        payload.statement,
        payload.supporting_refs,
        payload.subject_state,
        payload.obligation_refs,
        payload.disputes_refs,
        payload.limitation_refs if type(payload) is ClaimRecordedPayloadV1_1 else (),
    )


def _limitation_scope_is_authorable(
    payload: ClaimRecordedPayloadV1_1,
    result_record: ProjectionRecord[ResultRecordedPayload],
    actions: Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]],
    *,
    claim_frontier: int,
) -> bool:
    """Accept exactly the limitations relevance already treats as in scope.

    An earlier draft additionally required a readable action record, which contradicted the
    conservative task-wide relevance above: redacting an action (or a result whose action id was
    never recorded) made the result relevant -- so ``limitation_refs_complete`` demanded it -- while
    rejecting it from ``limitation_refs``, leaving no recordable completion claim at all. The two
    predicates must agree for the append-only repair path of ADR-025 to stay authorable.
    """

    return _result_is_relevant_to_claim(
        payload,
        result_record,
        actions,
        claim_frontier=claim_frontier,
    )


def _apply_claim(
    claims: dict[ClaimId, ClaimProjectionRecord],
    actions: Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]],
    results: Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]],
    event: AcceptedEvent,
    observed_event_ids: frozenset[EventId] = frozenset(),
    obligations: Mapping[ObligationId, ObligationProjectionRecord] | None = None,
) -> None:
    key = _locator_id(event, claim_id)
    # A v1.0 claim id may be re-published, and an unreadable payload tombstones the row in place.
    # Neither undoes a correction that already replaced this claim, so the revision edge is carried
    # across every rewrite of the row rather than derived from the row being written.
    existing_supersession = (
        None if (existing := claims.get(key)) is None else existing.superseded_by_claim_id
    )
    if event.payload is None:
        claims[key] = ClaimProjectionRecord(
            payload=None,
            payload_digest=event.projection_locator.canonical_payload_digest,
            redacted=True,
            source_event_id=event.event_id,
            source_frontier=event.ledger.ingestion_sequence,
            superseded_by_claim_id=existing_supersession,
        )
        return
    payload = cast(ClaimRecordedPayload, event.payload)
    if type(payload) is ClaimRecordedPayloadV1_1:
        if key in claims:
            raise ClaimRevisionMismatch(
                "claim_id",
                "claim_id_must_be_fresh",
                event.event_id,
            )
        if payload.supersedes_claim_refs and payload.disputes_refs:
            raise ClaimRevisionMismatch(
                "disputes_refs",
                "replacement_must_not_dispute",
                event.event_id,
            )
        if any(
            (record := results.get(result_id(result_ref))) is not None
            and record.payload is not None
            and record.payload.outcome in {ResultOutcome.FAILURE, ResultOutcome.PARTIAL}
            for result_ref in payload.supporting_refs
            if result_ref.startswith("res_")
        ):
            raise ClaimRevisionMismatch(
                "supporting_refs",
                "supporting_refs_must_exclude_limitations",
                event.event_id,
            )
        # Superseded observed failures (#909) and observed explorations are not required; the
        # rule is shared with the surfaces that list the required ids before a claim (F3).
        required = required_limitation_result_ids(
            results,
            actions,
            observed_event_ids,
            claim_scope=_claim_scope(payload),
            claim_frontier=event.ledger.ingestion_sequence,
        )
        supplied = frozenset(payload.limitation_refs)
        inadmissible = tuple(
            result_ref
            for result_ref in payload.limitation_refs
            if (record := results.get(result_ref)) is None
            or record.payload is None
            or record.payload.outcome not in DISCLOSABLE_LIMITING_OUTCOMES
            or not _limitation_scope_is_authorable(
                payload,
                record,
                actions,
                claim_frontier=event.ledger.ingestion_sequence,
            )
        )
        if inadmissible:
            raise ClaimRevisionMismatch(
                "limitation_refs",
                "limitation_refs_must_be_relevant_non_success_results",
                event.event_id,
                offending_refs=inadmissible,
            )
        if payload.claim_kind is ClaimKind.COMPLETION and not required <= supplied:
            raise ClaimRevisionMismatch(
                "limitation_refs",
                "limitation_refs_complete",
                event.event_id,
                missing_refs=tuple(required - supplied),
            )
        if payload.supersedes_claim_refs:
            for target in payload.supersedes_claim_refs:
                prior = claims.get(target)
                if prior is None or prior.payload is None:
                    raise ClaimRevisionMismatch(
                        "supersedes_claim_refs",
                        "superseded_claim_must_exist",
                        event.event_id,
                    )
                if prior.superseded_by_claim_id is not None:
                    raise ClaimRevisionMismatch(
                        "supersedes_claim_refs",
                        "superseded_claim_must_be_effective",
                        event.event_id,
                    )
                if prior.payload.claim_kind is not payload.claim_kind:
                    raise ClaimRevisionMismatch(
                        "claim_kind",
                        "claim_kind_must_match",
                        event.event_id,
                    )
                prior_scope = _claim_scope(prior.payload)
                current_scope = _claim_scope(payload)
                # An accepted empty scope has no overlap to preserve. Explicit supersession
                # repairs that authoring mistake without inferring scope from supporting_refs.
                # Populated targets still require overlap, including in a mixed target batch.
                # tb4n2 R2 (#1022): a completion claim whose every obligation is now acknowledged
                # as not done claims nothing; its honest replacement may drop them all.
                withdrawn = obligations is not None and all(
                    (row := obligations.get(ref)) is not None
                    and row.payload is not None
                    and row.payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
                    for ref in prior_scope
                )
                if (
                    prior_scope
                    and not withdrawn
                    and (not current_scope or prior_scope.isdisjoint(current_scope))
                ):
                    raise ClaimRevisionMismatch(
                        "obligation_refs",
                        "scope_overlap_required",
                        event.event_id,
                    )
            if len(payload.supersedes_claim_refs) == 1:
                prior = claims[payload.supersedes_claim_refs[0]]
                assert prior.payload is not None
                if _claim_effective_meaning(prior.payload) == _claim_effective_meaning(payload):
                    raise ClaimRevisionMismatch(
                        "supersedes_claim_refs",
                        "replacement_must_change_effective_claim",
                        event.event_id,
                    )
            # Record the revision edge on each target now. Deriving it later from the
            # replacement's live payload would resurrect a superseded claim once a
            # redaction_recorded tombstones that payload; the edge is set by the same ordered
            # replay on every path, so it stays deterministic.
            for target in payload.supersedes_claim_refs:
                claims[target] = replace(claims[target], superseded_by_claim_id=key)
    claims[key] = ClaimProjectionRecord(
        payload=payload,
        payload_digest=event.projection_locator.canonical_payload_digest,
        redacted=False,
        source_event_id=event.event_id,
        source_frontier=event.ledger.ingestion_sequence,
        superseded_by_claim_id=existing_supersession,
    )


def _redact_current_records(
    target_event_ids: tuple[EventId, ...],
    plans: dict[int, PlanProjectionRecord],
    obligations: dict[ObligationId, ObligationProjectionRecord],
    decisions: dict[EventId, DecisionProjectionRecord],
    assignments: dict[EventId, ProjectionRecord[AssignmentRecordedPayload]],
    actions: dict[ActionId, ProjectionRecord[ActionRecordedPayload]],
    results: dict[ResultId, ProjectionRecord[ResultRecordedPayload]],
    evidence: dict[EvidenceId, EvidenceProjectionRecord],
    claims: dict[ClaimId, ClaimProjectionRecord],
    findings: dict[FindingId, FindingProjectionRecord],
    responses: dict[FindingId, ProjectionRecord[ResponseRecordedPayload]],
    coordination_contexts: dict[EventId, ProjectionRecord[CoordinationContextRecordedPayload]],
    coordination_declarations: dict[
        EventId, ProjectionRecord[CoordinationObligationDeclaredPayload]
    ],
    coordination_dispositions: dict[
        EventId, ProjectionRecord[CoordinationDispositionRecordedPayload]
    ],
) -> None:
    targets = frozenset(target_event_ids)
    for key, record in tuple(plans.items()):
        if record.source_event_id in targets:
            plans[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(obligations.items()):
        if record.source_event_id in targets:
            obligations[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(decisions.items()):
        if record.source_event_id in targets:
            decisions[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(assignments.items()):
        if record.source_event_id in targets:
            assignments[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(actions.items()):
        if record.source_event_id in targets:
            actions[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(results.items()):
        if record.source_event_id in targets:
            results[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(evidence.items()):
        if record.source_event_id in targets:
            evidence[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(claims.items()):
        if record.source_event_id in targets:
            claims[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(findings.items()):
        if record.source_event_id in targets:
            findings[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(responses.items()):
        if record.source_event_id in targets:
            responses[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(coordination_contexts.items()):
        if record.source_event_id in targets:
            coordination_contexts[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(coordination_declarations.items()):
        if record.source_event_id in targets:
            coordination_declarations[key] = replace(record, payload=None, redacted=True)
    for key, record in tuple(coordination_dispositions.items()):
        if record.source_event_id in targets:
            coordination_dispositions[key] = replace(record, payload=None, redacted=True)


def _recompute_secondary_effects(
    plans: dict[int, PlanProjectionRecord],
    obligations: dict[ObligationId, ObligationProjectionRecord],
    decisions: dict[EventId, DecisionProjectionRecord],
    claims: Mapping[ClaimId, ClaimProjectionRecord],
) -> dict[ContradictionKey, ContradictionRecord]:
    for key, record in tuple(plans.items()):
        plans[key] = replace(record, superseded_by_plan_version=None)
    for key, record in tuple(obligations.items()):
        obligations[key] = replace(
            record,
            plan_change=None,
            plan_change_reason=None,
            superseded_by_obligation_ids=(),
        )
    revisions = sorted(
        (record for record in plans.values() if type(record.payload) is PlanRevisedPayload),
        key=lambda record: (record.source_frontier, _ascii_key(record.source_event_id)),
    )
    for record in revisions:
        payload = cast(PlanRevisedPayload, record.payload)
        prior = plans.get(payload.supersedes_plan_version)
        if prior is not None:
            plans[payload.supersedes_plan_version] = replace(
                prior,
                superseded_by_plan_version=payload.plan_version,
            )
        for change in payload.obligation_changes:
            obligation = obligations.get(change.obligation_id)
            if obligation is not None:
                obligations[change.obligation_id] = replace(
                    obligation,
                    plan_change=change.change,
                    plan_change_reason=change.reason,
                    superseded_by_obligation_ids=change.replacement_obligation_ids,
                )

    for key, record in tuple(decisions.items()):
        decisions[key] = replace(record, superseded_by_event_id=None)
    ordered_decisions = sorted(
        (
            record
            for record in decisions.values()
            if type(record.payload) is DecisionRecordedPayload
        ),
        key=lambda record: (record.source_frontier, _ascii_key(record.source_event_id)),
    )
    for record in ordered_decisions:
        payload = cast(DecisionRecordedPayload, record.payload)
        if payload.supersedes_event_id is not None:
            prior = decisions.get(payload.supersedes_event_id)
            if prior is not None:
                decisions[payload.supersedes_event_id] = replace(
                    prior,
                    superseded_by_event_id=record.source_event_id,
                )

    contradictions: dict[ContradictionKey, ContradictionRecord] = {}
    for record in sorted(
        claims.values(),
        key=lambda item: (item.source_frontier, _ascii_key(item.source_event_id)),
    ):
        if type(record.payload) not in {ClaimRecordedPayload, ClaimRecordedPayloadV1_1}:
            continue
        claim = cast(ClaimRecordedPayload | ClaimRecordedPayloadV1_1, record.payload)
        for disputed_ref in claim.disputes_refs:
            key = ContradictionKey(claim.claim_id, disputed_ref)
            contradictions[key] = ContradictionRecord(
                disputing_claim_id=claim.claim_id,
                disputed_ref=disputed_ref,
                source_event_id=record.source_event_id,
                source_frontier=record.source_frontier,
            )
    return contradictions


def _target_visible(
    target: str,
    obligations: Mapping[ObligationId, object],
    actions: Mapping[ActionId, object],
    results: Mapping[ResultId, object],
    evidence: Mapping[EvidenceId, object],
    claims: Mapping[ClaimId, object],
    findings: Mapping[FindingId, object],
) -> bool:
    if target.startswith("obl_"):
        return obligation_id(target) in obligations
    if target.startswith("act_"):
        return action_id(target) in actions
    if target.startswith("res_"):
        return result_id(target) in results
    if target.startswith("evd_"):
        return evidence_id(target) in evidence
    if target.startswith("clm_"):
        return claim_id(target) in claims
    if target.startswith("fnd_"):
        return finding_id(target) in findings
    raise _corrupt()


def _recompute_missing_gaps(
    retained_gaps: set[str],
    plans: Mapping[int, PlanProjectionRecord],
    obligations: Mapping[ObligationId, ObligationProjectionRecord],
    decisions: Mapping[EventId, DecisionProjectionRecord],
    assignments: Mapping[EventId, ProjectionRecord[AssignmentRecordedPayload]],
    actions: Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]],
    results: Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]],
    evidence: Mapping[EvidenceId, EvidenceProjectionRecord],
    claims: Mapping[ClaimId, ClaimProjectionRecord],
    findings: Mapping[FindingId, FindingProjectionRecord],
    responses: Mapping[FindingId, ProjectionRecord[ResponseRecordedPayload]],
    coordination_dispositions: Mapping[
        EventId, ProjectionRecord[CoordinationDispositionRecordedPayload]
    ],
) -> tuple[str, ...]:
    gaps = {marker for marker in retained_gaps if not marker.startswith("missing_ref:")}

    def require(source_event: EventId, target: str) -> None:
        if not _target_visible(
            target,
            obligations,
            actions,
            results,
            evidence,
            claims,
            findings,
        ):
            gaps.add(f"missing_ref:{source_event}:{target}")

    for record in plans.values():
        payload = record.payload
        if type(payload) is PlanPublishedPayload:
            for target in payload.obligation_refs:
                require(record.source_event_id, target)
        elif type(payload) is PlanRevisedPayload:
            for change in payload.obligation_changes:
                require(record.source_event_id, change.obligation_id)
                for target in change.replacement_obligation_ids:
                    require(record.source_event_id, target)
    for record in obligations.values():
        if record.payload is not None:
            for target in record.payload.resolution_evidence_refs:
                require(record.source_event_id, target)
    for record in decisions.values():
        if record.payload is not None:
            for target in record.payload.affected_obligation_ids:
                require(record.source_event_id, target)
            # A disclosure line names its obligation in the statement (#995).
            for _kind, target in disclosure_line_obligations(record.payload.statement):
                require(record.source_event_id, target)
    for record in assignments.values():
        if record.payload is not None:
            for target in record.payload.obligation_ids:
                require(record.source_event_id, target)
    for record in actions.values():
        if record.payload is not None:
            for target in record.payload.obligation_refs:
                require(record.source_event_id, target)
    for record in results.values():
        if record.payload is not None:
            require(record.source_event_id, record.payload.action_id)
            for target in record.payload.evidence_refs:
                require(record.source_event_id, target)
    for record in claims.values():
        if record.payload is not None:
            for target in record.payload.supporting_refs:
                require(record.source_event_id, target)
            for target in record.payload.obligation_refs:
                require(record.source_event_id, target)
            for target in record.payload.disputes_refs:
                if target.startswith("clm_"):
                    require(record.source_event_id, target)
            if type(record.payload) is ClaimRecordedPayloadV1_1:
                for target in record.payload.limitation_refs:
                    require(record.source_event_id, target)
                for target in record.payload.supersedes_claim_refs:
                    require(record.source_event_id, target)
    for record in findings.values():
        if record.payload is not None:
            for target in record.payload.subject_refs:
                if not target.startswith("evt_"):
                    require(record.source_event_id, target)
    for record in responses.values():
        if record.payload is not None:
            require(record.source_event_id, record.payload.finding_id)
            for target in record.payload.evidence_refs:
                require(record.source_event_id, target)
    for record in coordination_dispositions.values():
        if record.payload is not None:
            for target in record.payload.evidence_refs:
                require(record.source_event_id, target)
    return tuple(sorted(gaps, key=_ascii_key))


def _freshness(
    frontier: int,
    gaps: tuple[str, ...],
    *,
    stale: bool,
    check_freshness: LedgerFreshness | None,
) -> LedgerFreshness:
    """Fold the projection scalar from carried state alone.

    ``check_freshness`` is the retained check's own recorded freshness, not a signal that decays
    with the event that recorded it: a check that reported ``partial`` coverage keeps the
    projection at ``partial`` for as long as that check is the retained one. Only supersession
    (``stale``), a redaction of the check itself, or a later check replacing it may move the
    scalar off that value, so the scalar can never read cleaner than the coverage of the very
    check reported beside it (issue #307).
    """

    if frontier == 0:
        return LedgerFreshness.UNKNOWN
    if any(marker.startswith("redacted_") for marker in gaps):
        return LedgerFreshness.REDACTED_GAP
    if any(
        marker.startswith("unknown_event:") or marker.startswith("missing_ref:") for marker in gaps
    ):
        return LedgerFreshness.PARTIAL
    if stale:
        return LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE
    if check_freshness is not None:
        return check_freshness
    return LedgerFreshness.CURRENT


def reduce_event(
    state: ProjectionState,
    event: LedgerRecord,
    replay_index: ReplayIndex,
) -> ProjectionState:
    """Fold one exact next accepted record without I/O or mutation."""

    _verify_exact_event(state, event, replay_index)
    plans = dict(state.plans)
    obligations = dict(state.obligations)
    decisions = dict(state.decisions)
    assignments = dict(state.assignments)
    actions = dict(state.actions)
    results = dict(state.results)
    evidence = dict(state.evidence)
    claims = dict(state.claims)
    findings = dict(state.findings)
    responses = dict(state.responses)
    coordination_contexts = dict(state.coordination_contexts)
    coordination_declarations = dict(state.coordination_declarations)
    coordination_dispositions = dict(state.coordination_dispositions)
    contradictions = dict(state.contradictions)
    gaps = set(state.coverage_gaps)
    latest = state.latest_tested_state
    pending_missing = state.pending_missing_for_assessment
    unknown_count = state.unknown_event_count
    stale = state.freshness is LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE

    if type(event) is UnknownEvent:
        unknown_count += 1
        gaps.add(f"unknown_event:{event.event_id}:{event.schema.name}@{event.schema.version}")
        coverage_gaps = tuple(sorted(gaps, key=_ascii_key))
    else:
        accepted = cast(AcceptedEvent, event)
        family = accepted.schema.name
        payload = accepted.payload
        if latest is not None and _record_supersedes_recorded_check(
            event,
            latest.returned_finding_ids,
            _answered_limitation_ids(state, accepted, replay_index),
            state,
        ):
            stale = True

        if family in {"session_opened", "session_resumed", "receipt_recorded"}:
            pass
        elif family in {"plan_published", "plan_revised"}:
            key = _plan_key(accepted)
            if key in plans:
                raise _corrupt()
            if payload is None:
                plans[key] = PlanProjectionRecord(
                    payload=None,
                    payload_digest=accepted.projection_locator.canonical_payload_digest,
                    redacted=True,
                    source_event_id=accepted.event_id,
                    source_frontier=accepted.ledger.ingestion_sequence,
                )
            else:
                plans[key] = PlanProjectionRecord(
                    payload=cast(PlanPublishedPayload | PlanRevisedPayload, payload),
                    payload_digest=accepted.projection_locator.canonical_payload_digest,
                    redacted=False,
                    source_event_id=accepted.event_id,
                    source_frontier=accepted.ledger.ingestion_sequence,
                )
                typed_plan = cast(PlanPublishedPayload | PlanRevisedPayload, payload)
                if typed_plan.no_obligations_reason is not None:
                    scope = current_plan_scope(
                        plans,
                        tuple(sorted(gaps, key=_ascii_key)),
                    )
                    if not scope.readable or scope.declared_obligation_count != 0:
                        raise NoObligationsReasonMismatch(event_id=accepted.event_id)
        elif family == "obligation_published":
            _apply_obligation(obligations, accepted)
        elif family == "assignment_recorded":
            if accepted.event_id in assignments:
                raise _corrupt()
            assignments[accepted.event_id] = (
                _tombstone(accepted, AssignmentRecordedPayload)
                if payload is None
                else _projection_record(accepted, cast(AssignmentRecordedPayload, payload))
            )
        elif family == "decision_recorded":
            if accepted.event_id in decisions:
                raise _corrupt()
            decisions[accepted.event_id] = DecisionProjectionRecord(
                payload=(None if payload is None else cast(DecisionRecordedPayload, payload)),
                payload_digest=accepted.projection_locator.canonical_payload_digest,
                redacted=payload is None,
                source_event_id=accepted.event_id,
                source_frontier=accepted.ledger.ingestion_sequence,
            )
        elif family == "action_recorded":
            key = _locator_id(accepted, action_id)
            actions[key] = (
                _tombstone(accepted, ActionRecordedPayload)
                if payload is None
                else _projection_record(accepted, cast(ActionRecordedPayload, payload))
            )
        elif family == "result_recorded":
            key = _locator_id(accepted, result_id)
            results[key] = (
                _tombstone(accepted, ResultRecordedPayload)
                if payload is None
                else _projection_record(accepted, cast(ResultRecordedPayload, payload))
            )
        elif family == "evidence_recorded":
            key = _locator_id(accepted, evidence_id)
            evidence[key] = EvidenceProjectionRecord(
                payload=(None if payload is None else cast(EvidenceRecordedPayload, payload)),
                payload_digest=accepted.projection_locator.canonical_payload_digest,
                redacted=payload is None,
                source_event_id=accepted.event_id,
                source_frontier=accepted.ledger.ingestion_sequence,
            )
        elif family == "claim_recorded":
            _apply_claim(
                claims,
                actions,
                results,
                accepted,
                replay_index.observed_event_ids,
                obligations,
            )
        elif family == "finding_recorded":
            key = _locator_id(accepted, finding_id)
            findings[key] = _finding_record(
                accepted, None if payload is None else cast(FindingRecordedPayload, payload)
            )
        elif family == "response_recorded":
            key = _locator_id(accepted, finding_id)
            responses[key] = (
                _tombstone(accepted, ResponseRecordedPayload)
                if payload is None
                else _projection_record(accepted, cast(ResponseRecordedPayload, payload))
            )
            rebutted = findings.get(key)
            if (
                payload is not None
                and rebutted is not None
                and cast(ResponseRecordedPayload, payload).disposition.value
                in _REBUTTAL_DISPOSITION_VALUES
            ):
                # Every rebuttal is counted, not only the latest response (TB4 tb4n1 D7): the
                # next review packet carries the count beside the reviewer's last verdict. A
                # ``self_verified`` answer (the agent repaired the item and verified it itself,
                # because FinishUP could not prove it) also disputes the reviewer's standing claim.
                findings[key] = replace(rebutted, rebuttal_count=rebutted.rebuttal_count + 1)
            if payload is not None and key in findings:
                # tb4n3 RC-7: the agent's earliest unretracted reasoned position is a reducer
                # fact, so a later answer of another kind never erases a rebuttal (D-2).
                findings[key] = replace(
                    findings[key],
                    standing_position=next_standing_position(
                        findings[key].standing_position,
                        cast(ResponseRecordedPayload, payload),
                        accepted.ledger.ingestion_sequence,
                    ),
                )
        elif family == "coordination_context_recorded":
            if accepted.event_id in coordination_contexts:
                raise _corrupt()
            coordination_contexts[accepted.event_id] = (
                _tombstone(accepted, CoordinationContextRecordedPayload)
                if payload is None
                else _projection_record(
                    accepted,
                    cast(CoordinationContextRecordedPayload, payload),
                )
            )
        elif family == "coordination_obligation_declared":
            if accepted.event_id in coordination_declarations:
                raise _corrupt()
            coordination_declarations[accepted.event_id] = (
                _tombstone(accepted, CoordinationObligationDeclaredPayload)
                if payload is None
                else _projection_record(
                    accepted,
                    cast(CoordinationObligationDeclaredPayload, payload),
                )
            )
        elif family == "coordination_disposition_recorded":
            if accepted.event_id in coordination_dispositions:
                raise _corrupt()
            coordination_dispositions[accepted.event_id] = (
                _tombstone(accepted, CoordinationDispositionRecordedPayload)
                if payload is None
                else _projection_record(
                    accepted,
                    cast(CoordinationDispositionRecordedPayload, payload),
                )
            )
        elif family == "check_recorded":
            if payload is None:
                latest = None
                stale = False
            else:
                check = cast(CheckRecordedPayload, payload)
                latest = LatestTestedState(
                    source_check_event_id=accepted.event_id,
                    subject_frontier=check.subject_frontier,
                    verdict=check.verdict,
                    returned_finding_ids=check.returned_finding_ids,
                    suppressed_count=check.suppressed_count,
                    coverage=check.coverage,
                )
                stale = (
                    check.coverage.ledger_freshness is LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE
                )
                # Resolution is a fold over every recorded check, not a property of the latest
                # one: a finding proven absent stays resolved when a later weaker check adds
                # nothing, and is re-fired only when a check returns the same issue again.
                apply_check_resolution(
                    findings,
                    check,
                    accepted.event_id,
                    proof_state=state,
                    first_task_statement_sequence=replay_index.first_task_statement_sequence,
                )
                apply_check_rulings(
                    findings,
                    responses,
                    check,
                    accepted.event_id,
                    check_frontier=accepted.ledger.ingestion_sequence,
                )
                # Issue #907: the latest assessed review decides what is still named missing. A
                # local-only or failed check leaves the prior request standing, and so does an
                # ``insufficient_packet`` that recorded no item (a reply that named nothing, or
                # whose items were all dropped): it assessed nothing and supplied nothing, so the
                # next packet keeps the earlier request and its ``supplied_since`` context.
                if check.semantic_conclusion == "insufficient_packet":
                    if check.missing_for_assessment:
                        pending_missing = PendingMissingForAssessment(
                            accepted.event_id,
                            accepted.ledger.ingestion_sequence,
                            check.missing_for_assessment,
                        )
                elif check.semantic_conclusion is not None:
                    pending_missing = None
        elif family == "redaction_recorded":
            event_targets = set(accepted.projection_locator.redaction_target_event_ids)
            object_targets = accepted.projection_locator.redaction_target_object_ids
            for target_object in object_targets:
                owner = replay_index.payload_event_by_object.get(target_object)
                if owner is not None:
                    event_targets.add(owner)
            ordered_event_targets = tuple(sorted(event_targets, key=_ascii_key))
            _redact_current_records(
                ordered_event_targets,
                plans,
                obligations,
                decisions,
                assignments,
                actions,
                results,
                evidence,
                claims,
                findings,
                responses,
                coordination_contexts,
                coordination_declarations,
                coordination_dispositions,
            )
            if latest is not None and latest.source_check_event_id in event_targets:
                latest = None
                stale = False
            if (
                pending_missing is not None
                and pending_missing.source_check_event_id in event_targets
            ):
                pending_missing = None
            reopen_findings_resolved_by(findings, frozenset(ordered_event_targets))
            for target_event in ordered_event_targets:
                gaps.add(f"redacted_event:{target_event}")
            for target_object in object_targets:
                root = replay_index.redaction_root_by_object.get(target_object)
                if root is None:
                    raise _corrupt()
                del root
                for association in replay_index.evidence_sources_by_object.get(target_object, ()):
                    record = evidence.get(association.evidence_id)
                    if record is not None and record.source_event_id == association.source_event_id:
                        evidence[association.evidence_id] = replace(
                            record,
                            object_available=False,
                            redacted_object_id=target_object,
                        )
                    gaps.add(f"redacted_object:{target_object}")
        elif family in _LINEAGE_EVENT_FAMILIES:
            # These events carry service-owned lifecycle/manifest facts.  Their projection is
            # intentionally structural no-op: the catalog owns lifecycle state and the pure
            # lineage evaluator consumes only the recorded aggregate.  A manifest (and the other
            # service-only lineage families) must nevertheless retain the coordinator authorship
            # stamp all the way through replay; a valid payload with caller/import authorship is
            # a corrupt ledger record, never an acceptable child fact.
            if family in LINEAGE_SERVICE_STAMPED_FAMILIES and not is_lineage_service_stamped(
                accepted
            ):
                raise _corrupt()
            if (
                family == "child_dependencies_recorded"
                and payload is not None
                and type(payload) is not ChildDependenciesRecordedPayload
            ):
                raise _corrupt()
        else:
            raise _corrupt()

        contradictions = _recompute_secondary_effects(
            plans,
            obligations,
            decisions,
            claims,
        )
        coverage_gaps = _recompute_missing_gaps(
            gaps,
            plans,
            obligations,
            decisions,
            assignments,
            actions,
            results,
            evidence,
            claims,
            findings,
            responses,
            coordination_dispositions,
        )

    frontier = event.ledger.ingestion_sequence
    freshness = _freshness(
        frontier,
        coverage_gaps,
        stale=stale,
        check_freshness=None if latest is None else latest.coverage.ledger_freshness,
    )
    return derive_projection_state(
        state,
        frontier=frontier,
        head_digest=event.entry_digest,
        plans=plans,
        obligations=obligations,
        decisions=decisions,
        assignments=assignments,
        actions=actions,
        results=results,
        evidence=evidence,
        claims=claims,
        contradictions=contradictions,
        findings=findings,
        responses=responses,
        coordination_contexts=coordination_contexts,
        coordination_declarations=coordination_declarations,
        coordination_dispositions=coordination_dispositions,
        latest_tested_state=latest,
        freshness=freshness,
        unknown_event_count=unknown_count,
        coverage_gaps=coverage_gaps,
        pending_missing_for_assessment=pending_missing,
    )


def replay(events: Iterable[LedgerRecord]) -> ProjectionState:
    """Fold an already ledger-ordered iterable from genesis without sorting."""

    projection, _index = replay_with_index(events)
    return projection


def replay_with_index(events: Iterable[LedgerRecord]) -> tuple[ProjectionState, ReplayIndex]:
    """Fold an accepted prefix and retain the immutable reverse index used by the fold."""

    state = empty_projection_state()
    index = empty_replay_index()
    for event in events:
        index = extend_replay_index(index, event)
        state = reduce_event(state, event, index)
    return state, index


def build_replay_index(events: tuple[LedgerRecord, ...]) -> ReplayIndex:
    """Build an immutable reverse index from one exact accepted prefix in linear time.

    This uses the same chain, payload-owner, evidence-association, and redaction-root checks as
    ``extend_replay_index`` while mutating local maps once.  The immutable ``ReplayIndex`` is
    created only after the complete prefix has been checked, so callers can safely retain it
    across the subsequent local-case capacity validation.
    """

    if type(events) is not tuple:
        raise _corrupt()
    frontier = 0
    head_digest = "genesis"
    first_task_statement_sequence: int | None = None
    payload_event_by_object: dict[ObjectId, EventId] = {}
    evidence_sources_by_object: dict[ObjectId, tuple[EvidenceObjectSource, ...]] = {}
    redaction_root_by_object: dict[ObjectId, EventId] = {}
    observed_event_ids: set[EventId] = set()
    observation_finding_event_ids: set[EventId] = set()
    for event in events:
        _next_record(frontier, head_digest, event)
        if is_observed_run_record(event):
            observed_event_ids.add(event.event_id)
        payload_object = event.payload_ref.object_id
        if payload_object in payload_event_by_object:
            raise _corrupt()
        payload_event_by_object[payload_object] = event.event_id

        if type(event) is AcceptedEvent and event.schema.name == "evidence_recorded":
            logical_key = event.projection_locator.logical_key
            if logical_key is None or len(event.artifact_refs) > 1:
                raise _corrupt()
            try:
                evidence_key = evidence_id(logical_key)
            except ValueError as exc:
                raise _corrupt() from exc
            if event.payload is not None:
                payload = cast(EvidenceRecordedPayload, event.payload)
                expected = (
                    () if payload.captured_object_id is None else (payload.captured_object_id,)
                )
                if event.artifact_refs != expected:
                    raise _corrupt()
            for captured_object in event.artifact_refs:
                association = EvidenceObjectSource(evidence_key, event.event_id)
                current = evidence_sources_by_object.get(captured_object, ())
                if association in current:
                    raise _corrupt()
                evidence_sources_by_object[captured_object] = tuple(
                    sorted(
                        (*current, association),
                        key=lambda item: (
                            _ascii_key(item.evidence_id),
                            _ascii_key(item.source_event_id),
                        ),
                    )
                )

        if type(event) is AcceptedEvent and event.schema.name == "redaction_recorded":
            targets = event.projection_locator.redaction_target_object_ids
            if event.artifact_refs != targets or event.payload_ref.object_id in targets:
                raise _corrupt()
            if event.payload is not None:
                payload = cast(RedactionRecordedPayload, event.payload)
                if (
                    payload.target_event_ids != event.projection_locator.redaction_target_event_ids
                    or payload.target_object_ids != targets
                ):
                    raise _corrupt()
            for target in targets:
                redaction_root_by_object.setdefault(target, event.event_id)

        if _is_observation_finding_record(event):
            observation_finding_event_ids.add(event.event_id)

        frontier = event.ledger.ingestion_sequence
        head_digest = event.entry_digest
        if first_task_statement_sequence is None and may_carry_task_statement(event):
            first_task_statement_sequence = frontier

    return ReplayIndex(
        frontier=frontier,
        head_digest=head_digest,
        payload_event_by_object=payload_event_by_object,
        evidence_sources_by_object=evidence_sources_by_object,
        redaction_root_by_object=redaction_root_by_object,
        observed_event_ids=frozenset(observed_event_ids),
        observation_finding_event_ids=frozenset(observation_finding_event_ids),
        first_task_statement_sequence=first_task_statement_sequence,
    )


def validate_replay_index(index: ReplayIndex, events: tuple[LedgerRecord, ...]) -> None:
    """Validate that an immutable index belongs to one exact accepted prefix."""

    if type(index) is not ReplayIndex or type(events) is not tuple:
        raise _corrupt()
    expected = build_replay_index(events)
    if expected != index:
        raise _corrupt()


def replay_extension_with_index(
    prior_projection: ProjectionState,
    prior_records: tuple[LedgerRecord, ...],
    appended_records: tuple[LedgerRecord, ...],
) -> tuple[ProjectionState, ReplayIndex]:
    """Extend a trusted projection and return the final immutable replay index with it."""

    if (
        type(prior_projection) is not ProjectionState
        or type(prior_records) is not tuple
        or type(appended_records) is not tuple
    ):
        raise _corrupt()
    index = build_replay_index(prior_records)
    if (
        index.frontier != prior_projection.frontier
        or index.head_digest != prior_projection.head_digest
    ):
        raise _corrupt()
    state = prior_projection
    for event in appended_records:
        index = extend_replay_index(index, event)
        state = reduce_event(state, event, index)
    return state, index


def replay_extension(
    prior_projection: ProjectionState,
    prior_records: tuple[LedgerRecord, ...],
    appended_records: tuple[LedgerRecord, ...],
) -> ProjectionState:
    """Extend a trusted projection by folding only the newly appended records.

    The prior records are still authenticated into a fresh reverse index, but their reducers do
    not run again. Callers use this only after recovery or a prior append has established that the
    supplied projection is the exact replay of ``prior_records``. Keeping the trust boundary
    explicit prevents this helper from becoming a general replacement for genesis replay.
    """

    state, _index = replay_extension_with_index(
        prior_projection,
        prior_records,
        appended_records,
    )
    return state
