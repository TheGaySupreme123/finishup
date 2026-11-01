"""Property strategies for event payloads, unknown drafts, and causal sequences."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Final, Literal, cast

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from builders.clock import format_utc_millis
from finishup.domain.events import (
    EVENT_FAMILIES,
    RESPONSE_EVENT_SCHEMA_VERSION,
    SCHEMA_VERSION,
    ActionKind,
    ActionRecordedPayload,
    AssignmentRecordedPayload,
    CheckMode,
    CheckRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    ClientKind,
    DecisionRecordedPayload,
    EventDraft,
    EventPayload,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    IntegrationKind,
    LedgerChain,
    NoObligationsReason,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    PlanRevisedPayload,
    PolicyVersion,
    ReceiptRecordedPayload,
    RedactionMethod,
    RedactionReasonCategory,
    RedactionRecordedPayload,
    ResponseRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    RuntimeProfile,
    SessionOpenedPayload,
    SessionResumedPayload,
    WritePolicy,
    WriterChain,
    encode_payload,
)
from finishup.domain.findings import (
    CheckVerdict,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    WaiverScope,
)
from finishup.domain.receipts import ReceiptConclusion
from finishup.domain.values import (
    ActionId,
    ActorId,
    ClaimId,
    EventId,
    EvidenceId,
    FindingId,
    Frontier,
    JsonValue,
    ObjectId,
    ObligationId,
    ReceiptId,
    ResultId,
    SubjectStateRef,
    Timestamp,
    WriterId,
    action_id,
    actor_id,
    claim_id,
    event_id,
    evidence_id,
    finding_id,
    freeze_json,
    object_id,
    obligation_id,
    receipt_id,
    result_id,
    timestamp_from_string,
    writer_id,
)
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind
from finishup.protocol.models import (
    CheckPolicyExecutionModel,
    CheckScopeModel,
    ReceiptRedactionProfile,
    SemanticReason,
    SemanticStatus,
)

__all__ = [
    "strategy_event_sequences",
    "event_schema_version_for",
    "strategy_invalid_event_payloads",
    "strategy_unknown_event_drafts",
    "strategy_valid_event_payloads",
]

_TEXT_ALPHABET = st.characters(codec="utf-8", blacklist_characters="\x00")
_ACTOR_ALPHABET: Final[str] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
_WORK_POLICY: Final = PolicyVersion("work-integrity", "0.1.0")
_RESEARCH_POLICY: Final = PolicyVersion("research-evidence", "0.1.0")
_POLICY_SELECTIONS: Final[tuple[tuple[PolicyVersion, ...], ...]] = (
    (_RESEARCH_POLICY,),
    (_WORK_POLICY,),
    (_RESEARCH_POLICY, _WORK_POLICY),
)
# (required priority, owning policy pack) exactly as frozen in docs/INTERFACES.md section 8.
_FINDING_KIND_FACTS: Final[Mapping[FindingKind, tuple[int, str]]] = {
    FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS: (1, "work-integrity"),
    FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED: (2, "work-integrity"),
    FindingKind.FAILED_WORK_OMITTED: (1, "work-integrity"),
    FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE: (1, "work-integrity"),
    FindingKind.RESULT_WITHOUT_ACTION: (2, "work-integrity"),
    FindingKind.ACTION_WITHOUT_RESULT: (3, "work-integrity"),
    FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE: (2, "work-integrity"),
    FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED: (1, "work-integrity"),
    FindingKind.LEDGER_STALE_OR_INCOMPLETE: (3, "work-integrity"),
    FindingKind.WEAK_OR_STALE_RESPONSE: (2, "work-integrity"),
    FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM: (1, "research-evidence"),
    FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT: (1, "research-evidence"),
    FindingKind.MATERIAL_LIMITATION_OMITTED: (1, "research-evidence"),
    FindingKind.QUESTIONABLE_FINDING_REJECTION: (2, "research-evidence"),
    FindingKind.COORDINATION_OVERLAP: (2, "coordination"),
}
# The exact non-default (required) field names per family, mirroring each payload dataclass's
# constructor signature in ``domain/events.py``/``domain/findings.py``.
_REQUIRED_FIELDS: Final[Mapping[str, frozenset[str]]] = {
    "session_opened": frozenset(
        {"task_title", "client_kind", "client_version", "integration", "profile"}
    ),
    "session_resumed": frozenset(
        {"client_kind", "client_version", "integration", "profile", "resumed_frontier"}
    ),
    "plan_published": frozenset({"plan_version", "summary", "obligation_refs"}),
    "obligation_published": frozenset(
        {"obligation_id", "description", "evidence_expectation", "status"}
    ),
    "assignment_recorded": frozenset({"assignee_actor_id", "obligation_ids", "scope_description"}),
    "decision_recorded": frozenset({"statement", "rationale", "authority"}),
    "action_recorded": frozenset({"action_id", "action_kind", "description"}),
    "result_recorded": frozenset({"result_id", "action_id", "outcome"}),
    "evidence_recorded": frozenset({"evidence_id", "evidence_kind", "strength", "observed_at"}),
    "claim_recorded": frozenset({"claim_id", "claim_kind", "statement", "supporting_refs"}),
    "plan_revised": frozenset(
        {"plan_version", "supersedes_plan_version", "reason", "summary", "obligation_changes"}
    ),
    "finding_recorded": frozenset(
        {
            "finding_id",
            "kind",
            "origin",
            "priority",
            "summary",
            "detail",
            "subject_refs",
            "policy_id",
            "policy_version",
            "subject_frontier",
            "coverage",
        }
    ),
    "response_recorded": frozenset({"finding_id", "finding_frontier", "disposition"}),
    "redaction_recorded": frozenset(
        {
            "target_event_ids",
            "target_object_ids",
            "method",
            "reason_category",
            "authority",
            "remaining_gap",
        }
    ),
    "check_recorded": frozenset(
        {
            "mode",
            "policies",
            "scope",
            "policy_executions",
            "subject_frontier",
            "verdict",
            "returned_finding_ids",
            "suppressed_count",
            "coverage",
            "semantic_status",
            "semantic_reason",
            "engine_version",
            "projection_version",
        }
    ),
    "receipt_recorded": frozenset(
        {
            "receipt_id",
            "subject_frontier",
            "receipt_digest",
            "receipt_object_id",
            "conclusion_code",
            "redaction_profile",
        }
    ),
}


def _missing_field_reason(family: str) -> str:
    return "finding_json_shape_invalid" if family == "finding_recorded" else "missing_payload_field"


def _unknown_field_reason(family: str) -> str:
    return "finding_json_shape_invalid" if family == "finding_recorded" else "unknown_payload_field"


def _typed_id[T](kind: IdKind, constructor: Callable[[object], T]) -> SearchStrategy[T]:
    prefix = PREFIX_BY_KIND[kind]
    return st.uuids(version=4).map(lambda value: constructor(f"{prefix}{value}"))


_event_ids: SearchStrategy[EventId] = _typed_id(IdKind.EVENT, event_id)
_obligation_ids: SearchStrategy[ObligationId] = _typed_id(IdKind.OBLIGATION, obligation_id)
_claim_ids: SearchStrategy[ClaimId] = _typed_id(IdKind.CLAIM, claim_id)
_action_ids: SearchStrategy[ActionId] = _typed_id(IdKind.ACTION, action_id)
_result_ids: SearchStrategy[ResultId] = _typed_id(IdKind.RESULT, result_id)
_evidence_ids: SearchStrategy[EvidenceId] = _typed_id(IdKind.EVIDENCE, evidence_id)
_finding_ids: SearchStrategy[FindingId] = _typed_id(IdKind.FINDING, finding_id)
_object_ids: SearchStrategy[ObjectId] = _typed_id(IdKind.OBJECT, object_id)
_receipt_ids: SearchStrategy[ReceiptId] = _typed_id(IdKind.RECEIPT, receipt_id)
_writer_ids: SearchStrategy[WriterId] = _typed_id(IdKind.WRITER, writer_id)
_actor_ids: SearchStrategy[ActorId] = st.text(
    alphabet=_ACTOR_ALPHABET, min_size=1, max_size=32
).map(actor_id)


def _digest_str() -> SearchStrategy[str]:
    return st.text(alphabet="0123456789abcdef", min_size=64, max_size=64).map(
        lambda hex_text: f"sha256:{hex_text}"
    )


def _short_text(min_size: int, max_size: int) -> SearchStrategy[str]:
    return st.text(_TEXT_ALPHABET, min_size=min_size, max_size=max_size)


def _timestamp() -> SearchStrategy[Timestamp]:
    return st.datetimes(
        min_value=datetime(2020, 1, 1),  # noqa: DTZ001 - bound is timezone-attached below
        max_value=datetime(2035, 1, 1),  # noqa: DTZ001
        timezones=st.just(UTC),
    ).map(lambda value: timestamp_from_string(format_utc_millis(value)))


@st.composite
def _frontier(draw: st.DrawFn) -> Frontier:
    if draw(st.booleans()):
        return Frontier.genesis()
    sequence = draw(st.integers(min_value=1, max_value=1_000_000))
    digest = draw(_digest_str())
    return Frontier(sequence, digest)


@st.composite
def _coverage(draw: st.DrawFn) -> Coverage:
    # publication_channels/check_types/known_gaps are held at one proven-valid baseline (matching
    # the sole-member ``none`` check-type rule in docs/INTERFACES.md section 5); every ordered
    # dimension is still genuinely varied.
    return Coverage(
        publication_channels=(PublicationChannel.COOPERATIVE_MCP,),
        authorship_assurance=draw(st.sampled_from(list(AuthorshipAssurance))),
        artifact_observation=draw(st.sampled_from(list(ArtifactObservation))),
        evidence_immutability=draw(st.sampled_from(list(EvidenceImmutability))),
        ledger_freshness=draw(st.sampled_from(list(LedgerFreshness))),
        check_types=(CheckType.NONE,),
        known_gaps=(),
    )


@st.composite
def _subject_state_ref(draw: st.DrawFn) -> SubjectStateRef:
    return SubjectStateRef(tree_digest=draw(_digest_str()))


@st.composite
def _session_opened(draw: st.DrawFn) -> SessionOpenedPayload:
    return SessionOpenedPayload(
        task_title=draw(_short_text(1, 64)),
        client_kind=draw(st.sampled_from(list(ClientKind))),
        client_version=draw(_short_text(1, 16)),
        integration=draw(st.sampled_from(list(IntegrationKind))),
        profile=draw(st.sampled_from(list(RuntimeProfile))),
        external_ref=draw(st.none() | _short_text(1, 32)),
        workspace_ref=draw(st.none() | _short_text(1, 32)),
    )


@st.composite
def _session_resumed(draw: st.DrawFn) -> SessionResumedPayload:
    return SessionResumedPayload(
        client_kind=draw(st.sampled_from(list(ClientKind))),
        client_version=draw(_short_text(1, 16)),
        integration=draw(st.sampled_from(list(IntegrationKind))),
        profile=draw(st.sampled_from(list(RuntimeProfile))),
        resumed_frontier=draw(_frontier()),
    )


@st.composite
def _plan_published(draw: st.DrawFn) -> PlanPublishedPayload:
    no_obligations_reason = draw(st.none() | st.sampled_from(list(NoObligationsReason)))
    return PlanPublishedPayload(
        plan_version=draw(st.integers(min_value=1, max_value=1_000)),
        summary=draw(_short_text(1, 64)),
        obligation_refs=(draw(_obligation_ids),) if no_obligations_reason is None else (),
        no_obligations_reason=no_obligations_reason,
    )


@st.composite
def _obligation_published(draw: st.DrawFn) -> ObligationPublishedPayload:
    status = draw(st.sampled_from(list(ObligationStatus)))
    resolution_refs = (draw(_evidence_ids),) if status is ObligationStatus.RESOLVED else ()
    return ObligationPublishedPayload(
        obligation_id=draw(_obligation_ids),
        description=draw(_short_text(1, 64)),
        evidence_expectation=draw(_short_text(1, 64)),
        status=status,
        resolution_evidence_refs=resolution_refs,
    )


@st.composite
def _assignment_recorded(draw: st.DrawFn) -> AssignmentRecordedPayload:
    return AssignmentRecordedPayload(
        assignee_actor_id=draw(_actor_ids),
        obligation_ids=(draw(_obligation_ids),),
        scope_description=draw(_short_text(1, 64)),
        write_policy=draw(st.none() | st.sampled_from(list(WritePolicy))),
    )


@st.composite
def _decision_recorded(draw: st.DrawFn) -> DecisionRecordedPayload:
    return DecisionRecordedPayload(
        statement=draw(_short_text(1, 64)),
        rationale=draw(_short_text(1, 64)),
        authority=draw(_actor_ids),
    )


@st.composite
def _action_recorded(draw: st.DrawFn) -> ActionRecordedPayload:
    kind = draw(st.sampled_from(list(ActionKind)))
    command = draw(_short_text(1, 32)) if kind is ActionKind.COMMAND else draw(st.none())
    return ActionRecordedPayload(
        action_id=draw(_action_ids),
        action_kind=kind,
        description=draw(_short_text(1, 64)),
        command=command,
    )


@st.composite
def _result_recorded(draw: st.DrawFn) -> ResultRecordedPayload:
    return ResultRecordedPayload(
        result_id=draw(_result_ids),
        action_id=draw(_action_ids),
        outcome=draw(st.sampled_from(list(ResultOutcome))),
        exit_status=draw(st.none() | st.integers(min_value=0, max_value=255)),
    )


@st.composite
def _evidence_recorded(draw: st.DrawFn) -> EvidenceRecordedPayload:
    strength = draw(st.sampled_from(list(EvidenceImmutability)))
    kind = draw(
        st.sampled_from([item for item in EvidenceKind if item is not EvidenceKind.IMPORT_REPORT])
    )
    reference: str | None = None
    captured_object_id: str | None = None
    content_digest: str | None = None
    description: str | None = None
    subject_state: SubjectStateRef | None = None
    if strength is EvidenceImmutability.MUTABLE_REFERENCE:
        reference = draw(_short_text(1, 32))
    elif strength is EvidenceImmutability.METADATA_ONLY:
        description = draw(_short_text(1, 32))
    elif strength is EvidenceImmutability.CONTENT_DIGEST:
        content_digest = draw(_digest_str())
    elif strength is EvidenceImmutability.IMMUTABLE_SNAPSHOT:
        captured_object_id = draw(_object_ids)
        content_digest = draw(_digest_str())
    else:
        captured_object_id = draw(_object_ids)
        content_digest = draw(_digest_str())
        subject_state = draw(_subject_state_ref())
    return EvidenceRecordedPayload(
        evidence_id=draw(_evidence_ids),
        evidence_kind=kind,
        strength=strength,
        observed_at=draw(_timestamp()),
        reference=reference,
        captured_object_id=captured_object_id,
        content_digest=content_digest,
        description=description,
        subject_state=subject_state,
    )


@st.composite
def _claim_recorded(draw: st.DrawFn) -> ClaimRecordedPayload:
    return ClaimRecordedPayload(
        claim_id=draw(_claim_ids),
        claim_kind=draw(st.sampled_from(list(ClaimKind))),
        statement=draw(_short_text(1, 64)),
        supporting_refs=(draw(_evidence_ids),),
    )


@st.composite
def _plan_revised(draw: st.DrawFn) -> PlanRevisedPayload:
    return PlanRevisedPayload(
        plan_version=draw(st.integers(min_value=2, max_value=1_000)),
        supersedes_plan_version=draw(st.integers(min_value=1, max_value=1_000)),
        reason=draw(_short_text(1, 64)),
        summary=draw(_short_text(1, 64)),
        obligation_changes=(),
    )


@st.composite
def _finding_recorded(draw: st.DrawFn) -> Finding:
    kind = draw(st.sampled_from(list(FindingKind)))
    priority, policy_id = _FINDING_KIND_FACTS[kind]
    return Finding(
        finding_id=draw(_finding_ids),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=priority,
        summary=draw(_short_text(1, 64)),
        detail=draw(_short_text(1, 64)),
        subject_refs=(draw(_obligation_ids),),
        policy_id=policy_id,
        policy_version="0.1.0",
        subject_frontier=draw(_frontier()),
        coverage=draw(_coverage()),
        provenance=None,
    )


@st.composite
def _response_recorded(draw: st.DrawFn) -> ResponseRecordedPayload:
    disposition = draw(st.sampled_from(list(ResponseDisposition)))
    reason: str | None
    waiver_scope: WaiverScope | None = None
    waiver_expiry: Timestamp | None = None
    if disposition is ResponseDisposition.ACKNOWLEDGED:
        reason = draw(st.none() | _short_text(1, 32))
    elif disposition in {
        ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
        ResponseDisposition.PROVENANCE_DISPUTED,
        ResponseDisposition.REJECTED,
    }:
        reason = draw(_short_text(1, 32))
    else:
        reason = draw(_short_text(1, 32))
        waiver_scope = WaiverScope.FINDING_ONLY
        waiver_expiry = draw(st.none() | _timestamp())
    return ResponseRecordedPayload(
        finding_id=draw(_finding_ids),
        finding_frontier=draw(_frontier()),
        disposition=disposition,
        reason=reason,
        waiver_scope=waiver_scope,
        waiver_expiry=waiver_expiry,
    )


@st.composite
def _redaction_recorded(draw: st.DrawFn) -> RedactionRecordedPayload:
    return RedactionRecordedPayload(
        target_event_ids=(draw(_event_ids),),
        target_object_ids=(),
        method=draw(st.sampled_from(list(RedactionMethod))),
        reason_category=draw(st.sampled_from(list(RedactionReasonCategory))),
        authority=draw(_actor_ids),
        remaining_gap=draw(_short_text(0, 32)),
    )


@st.composite
def _check_recorded(draw: st.DrawFn) -> CheckRecordedPayload:
    policies = draw(st.sampled_from(_POLICY_SELECTIONS))
    executions = tuple(
        CheckPolicyExecutionModel(
            policy_id=cast(
                Literal["research-evidence", "work-integrity"],
                policy.policy_id,
            ),
            policy_version=cast(Literal["0.1.0"], policy.policy_version),
            outcome="run",
            reason="completed",
        )
        for policy in policies
    )
    return CheckRecordedPayload(
        mode=draw(st.sampled_from(list(CheckMode))),
        policies=policies,
        scope=CheckScopeModel(claim_ids=(), obligation_ids=()),
        policy_executions=executions,
        subject_frontier=draw(_frontier()),
        verdict=draw(st.sampled_from(list(CheckVerdict))),
        returned_finding_ids=(),
        suppressed_count=draw(st.integers(min_value=0, max_value=5)),
        coverage=draw(_coverage()),
        semantic_status=SemanticStatus.NOT_REQUESTED,
        semantic_reason=SemanticReason.DETERMINISTIC_MODE,
        engine_version="0.1.0",
        projection_version="yoetz/0.1.0",
        semantic_provenance=None,
    )


@st.composite
def _receipt_recorded(draw: st.DrawFn) -> ReceiptRecordedPayload:
    return ReceiptRecordedPayload(
        receipt_id=draw(_receipt_ids),
        subject_frontier=draw(_frontier()),
        receipt_digest=draw(_digest_str()),
        receipt_object_id=draw(_object_ids),
        conclusion_code=draw(st.sampled_from(list(ReceiptConclusion))),
        redaction_profile=draw(st.sampled_from(list(ReceiptRedactionProfile))),
    )


_FAMILY_BUILDERS: Final[Mapping[str, SearchStrategy[EventPayload]]] = {
    "session_opened": cast(SearchStrategy[EventPayload], _session_opened()),
    "session_resumed": cast(SearchStrategy[EventPayload], _session_resumed()),
    "plan_published": cast(SearchStrategy[EventPayload], _plan_published()),
    "obligation_published": cast(SearchStrategy[EventPayload], _obligation_published()),
    "assignment_recorded": cast(SearchStrategy[EventPayload], _assignment_recorded()),
    "decision_recorded": cast(SearchStrategy[EventPayload], _decision_recorded()),
    "action_recorded": cast(SearchStrategy[EventPayload], _action_recorded()),
    "result_recorded": cast(SearchStrategy[EventPayload], _result_recorded()),
    "evidence_recorded": cast(SearchStrategy[EventPayload], _evidence_recorded()),
    "claim_recorded": cast(SearchStrategy[EventPayload], _claim_recorded()),
    "plan_revised": cast(SearchStrategy[EventPayload], _plan_revised()),
    "finding_recorded": cast(SearchStrategy[EventPayload], _finding_recorded()),
    "response_recorded": cast(SearchStrategy[EventPayload], _response_recorded()),
    "redaction_recorded": cast(SearchStrategy[EventPayload], _redaction_recorded()),
    "check_recorded": cast(SearchStrategy[EventPayload], _check_recorded()),
    "receipt_recorded": cast(SearchStrategy[EventPayload], _receipt_recorded()),
}


@st.composite
def _valid_event_payload(draw: st.DrawFn) -> tuple[str, EventPayload]:
    family = draw(st.sampled_from(EVENT_FAMILIES))
    payload = draw(_FAMILY_BUILDERS[family])
    return family, payload


@st.composite
def _invalid_event_payload(draw: st.DrawFn) -> tuple[str, dict[str, JsonValue], str]:
    family, payload = draw(_valid_event_payload())
    wire = dict(cast(Mapping[str, JsonValue], encode_payload(payload)))
    mutation = draw(st.sampled_from(("missing_required_field", "unknown_field")))
    if mutation == "missing_required_field":
        field = draw(st.sampled_from(sorted(_REQUIRED_FIELDS[family])))
        del wire[field]
        label = _missing_field_reason(family)
    else:
        wire["__strategy_probe_extra_field__"] = True
        label = _unknown_field_reason(family)
    return family, wire, label


@st.composite
def _unknown_event_draft(draw: st.DrawFn) -> EventDraft:
    case = draw(st.sampled_from(("unregistered_family", "future_version")))
    if case == "unregistered_family":
        name = draw(
            st.sampled_from(("custom_extension_event", "third_party_signal", "legacy_marker"))
        )
        version = SCHEMA_VERSION
    else:
        name = draw(st.sampled_from(EVENT_FAMILIES))
        version = draw(st.sampled_from(("1.0.1", "1.1.0", "2.0.0")))
    schema = EventSchema(name, version)
    raw_payload = draw(st.dictionaries(_short_text(1, 8), _short_text(0, 16), max_size=4))
    payload: JsonValue = freeze_json(raw_payload)
    return EventDraft(
        event_id=draw(_event_ids),
        schema=schema,
        occurred_at=draw(_timestamp()),
        causal_parents=(),
        payload=payload,
        artifact_refs=(),
        evidence_refs=(),
    )


def _artifact_refs_for(family: str, payload: EventPayload) -> tuple[ObjectId, ...]:
    """Mirror the envelope artifact-ref rules ``EventDraft`` cross-checks per family."""

    if family == "evidence_recorded":
        captured = cast(EvidenceRecordedPayload, payload).captured_object_id
        return () if captured is None else (captured,)
    if family == "receipt_recorded":
        return (cast(ReceiptRecordedPayload, payload).receipt_object_id,)
    if family == "redaction_recorded":
        return cast(RedactionRecordedPayload, payload).target_object_ids
    return ()


def event_schema_version_for(payload: EventPayload) -> str:
    """The version a drawn payload is recorded under.

    ``acknowledged_not_done`` rides ``response_recorded`` 1.1.0 only (issue #905); every other
    drawn payload uses the frozen 1.0.0 family.
    """

    if (
        type(payload) is ResponseRecordedPayload
        and payload.disposition is ResponseDisposition.ACKNOWLEDGED_NOT_DONE
    ):
        return RESPONSE_EVENT_SCHEMA_VERSION
    return SCHEMA_VERSION


@st.composite
def _event_sequences(
    draw: st.DrawFn,
) -> tuple[tuple[EventDraft, WriterChain, LedgerChain], ...]:
    length = draw(st.integers(min_value=1, max_value=6))
    writer = draw(_writer_ids)
    records: list[tuple[EventDraft, WriterChain, LedgerChain]] = []
    event_ids: list[EventId] = []
    for sequence in range(1, length + 1):
        family, payload = draw(_valid_event_payload())
        schema = EventSchema(family, event_schema_version_for(payload))
        candidate_parents = (
            tuple(
                sorted(
                    draw(
                        st.lists(
                            st.sampled_from(event_ids),
                            max_size=min(len(event_ids), 4),
                            unique=True,
                        )
                    ),
                    key=lambda value: value.encode("ascii"),
                )
            )
            if event_ids
            else ()
        )
        this_event_id = draw(_event_ids)
        draft = EventDraft(
            event_id=this_event_id,
            schema=schema,
            occurred_at=draw(_timestamp()),
            causal_parents=candidate_parents,
            payload=payload,
            artifact_refs=_artifact_refs_for(family, payload),
            evidence_refs=(),
        )
        writer_previous = "genesis" if sequence == 1 else draw(_digest_str())
        writer_chain = WriterChain(writer, sequence, writer_previous)
        ledger_previous = "genesis" if sequence == 1 else draw(_digest_str())
        ledger_chain = LedgerChain(sequence, ledger_previous, draw(_timestamp()))
        records.append((draft, writer_chain, ledger_chain))
        event_ids.append(this_event_id)
    return tuple(records)


strategy_valid_event_payloads: SearchStrategy[tuple[str, EventPayload]] = _valid_event_payload()
strategy_invalid_event_payloads: SearchStrategy[tuple[str, dict[str, JsonValue], str]] = (
    _invalid_event_payload()
)
strategy_unknown_event_drafts: SearchStrategy[EventDraft] = _unknown_event_draft()
strategy_event_sequences: SearchStrategy[
    tuple[tuple[EventDraft, WriterChain, LedgerChain], ...]
] = _event_sequences()
