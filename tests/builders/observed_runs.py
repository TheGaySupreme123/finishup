"""Hook-observed ledgers for the failure-supersession tests (#909).

``ObservedLedger`` builds one exact accepted prefix the way the observation coordinator writes it:
hook-observed actions and results carry the service-stamped observation authorship and the
``hook_observed`` channel, and a command action carries the ``omitted:<hmac commitment>``
identity materialization derives from the hook's keyed ``command_commitment``. Cooperative
claims and results use an ordinary agent author. The helpers then run the production replay,
case builder, composed local packs and receipt builder over that prefix.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import cast

from finishup.application.check import CheckScope, run_deterministic_policies
from finishup.application.closure_basis import finding_states
from finishup.application.observation_materialize import observation_author
from finishup.domain.command_segments import command_segment_commitments
from finishup.domain.events import (
    EVIDENCE_SCHEMA_VERSION,
    RESPONSE_EVENT_SCHEMA_VERSION,
    RESPONSE_V1_1_DISPOSITIONS,
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    EventPayload,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    LedgerChain,
    LedgerRecord,
    ObligationChange,
    ObligationChangeKind,
    ObligationPublishedPayload,
    ObligationStatus,
    PayloadRef,
    PlanPublishedPayload,
    PlanRevisedPayload,
    ProjectionLocator,
    RedactionMethod,
    RedactionReasonCategory,
    RedactionRecordedPayload,
    RedactionState,
    RequestedItem,
    RequestedItemKind,
    ResponseRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    WriterChain,
    encode_payload,
    media_type_for,
)
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
)
from finishup.domain.observation import normalize_observed_command, observed_command_commitment
from finishup.domain.observation_selection import command_runner_class
from finishup.domain.receipts import (
    PolicyVersionEntry,
    ReceiptDocument,
    ReceiptSectionKey,
    ReceiptVersionSlice,
    SchemaVersionEntry,
)
from finishup.domain.values import (
    ActionId,
    Actor,
    ActorType,
    ClaimId,
    EventId,
    FindingId,
    Frontier,
    ObligationId,
    ResultId,
    SubjectStateRef,
    action_id,
    actor_id,
    claim_id,
    event_id,
    evidence_id,
    finding_id,
    object_id,
    obligation_id,
    receipt_id,
    request_id,
    result_id,
    session_id,
    task_id,
    timestamp_from_string,
    writer_id,
)
from finishup.domain.workspace_effect import (
    result_summary_with_workspace_effect,
    workspace_effect_annotation,
)
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    CaseGap,
    DeterministicAssessment,
    build_deterministic_case,
)
from finishup.kernel.observed_failures import observed_action_description, observed_command_field
from finishup.kernel.receipt_builder import ReceiptBuildContext, build_receipt
from finishup.kernel.reducers import replay
from finishup.protocol.canonical import canonical_digest, canonical_encode, entry_digest
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
    coverage_for_channel,
    coverage_to_json,
)
from finishup.protocol.models import ReceiptInclude, ReceiptRedactionProfile
from finishup.protocol.policy_packs import CURRENT_POLICY_VERSIONS

__all__ = [
    "INSTALLATION_KEY",
    "OMISSION_KINDS",
    "ObservedLedger",
    "command_identity_for",
    "omissions",
    "observed_receipt",
    "omitted_results",
    "receipt_limitations",
]

_TASK = task_id("tsk_00000000-0000-4000-8000-000000000909")
_SESSION = session_id("ses_00000000-0000-4000-8000-000000000909")
_WRITER = writer_id("wri_00000000-0000-4000-8000-000000000909")
_OPERATION = request_id("req_00000000-0000-4000-8000-000000000909")
_NOW = timestamp_from_string("2026-09-29T17:58:11.363Z")
_AGENT = Actor(actor_id("agt_codex"), ActorType.LOGICAL_AGENT, AuthorshipAssurance.SELF_ASSERTED)
INSTALLATION_KEY = b"k" * 32
_ACTION = EventSchema("action_recorded", "1.0.0")
_RESULT = EventSchema("result_recorded", "1.0.0")
_CLAIM_V1 = EventSchema("claim_recorded", "1.0.0")
_CLAIM_V1_1 = EventSchema("claim_recorded", "1.1.0")
_OBLIGATION = EventSchema("obligation_published", "1.1.0")
_PACKS = ("research-evidence/0.2.0", "work-integrity/0.3.0")
OMISSION_KINDS = frozenset(
    {FindingKind.FAILED_WORK_OMITTED, FindingKind.MATERIAL_LIMITATION_OMITTED}
)


def command_identity_for(command: str) -> str:
    """The action ``command`` a hook-observed run of ``command`` materializes to."""

    normalized = normalize_observed_command(command)
    assert normalized is not None
    # The hook commits to the whole command and, for a composed one, to its simple commands
    # (#977); materialization writes both into the action's ``command`` field.
    segments = command_segment_commitments(INSTALLATION_KEY, normalized)
    return observed_command_field(
        observed_command_commitment(INSTALLATION_KEY, normalized),
        None if segments is None else segments[0],
        None if segments is None else segments[1],
    )


def _logical_key(payload: EventPayload, identifier: EventId) -> str | None:
    if type(payload).__name__ in {"SessionOpenedPayload", "RedactionRecordedPayload"}:
        # A session or redaction event projects no record of its own.
        return None
    if isinstance(payload, Finding | ResponseRecordedPayload):
        return str(payload.finding_id)
    for name in ("result_id", "action_id", "claim_id", "obligation_id", "evidence_id"):
        value = getattr(payload, name, None)
        if value is not None:
            return str(value)
    plan_version = getattr(payload, "plan_version", None)
    if plan_version is not None:
        return str(plan_version)
    if type(payload).__name__ in {"DecisionRecordedPayload", "CheckRecordedPayload"}:
        return str(identifier)
    raise AssertionError("unsupported payload")


@dataclass
class ObservedLedger:
    """One exact accepted prefix of hook-observed runs and cooperative claims."""

    records: list[LedgerRecord] = field(default_factory=lambda: [])
    runs: int = 0
    _plan_version: int = 0

    def _append(
        self,
        schema: EventSchema,
        payload: EventPayload,
        *,
        observed: bool,
        known_gaps: tuple[str, ...] = (),
        causal_parents: tuple[EventId, ...] = (),
        operation: str | None = None,
        channel: PublicationChannel | None = None,
    ) -> EventId:
        sequence = len(self.records) + 1
        operation_ref = _OPERATION if operation is None else request_id(operation)
        previous = "genesis" if not self.records else self.records[-1].entry_digest
        encoded = canonical_encode(encode_payload(payload))
        identifier = event_id(f"evt_00000000-0000-4000-8000-{sequence:012d}")
        reference = object_id(f"obj_00000000-0000-4000-8000-{sequence:012d}")
        commitment = "hmac-sha256:" + f"{sequence:064x}"
        author = observation_author() if observed else _AGENT
        if channel is None:
            channel = PublicationChannel.HOOK_OBSERVED if observed else PublicationChannel.LOCAL_CLI
        coverage = coverage_for_channel(channel)
        if known_gaps:
            coverage = replace(coverage, known_gaps=known_gaps)
        media = media_type_for(schema.name)
        preimage = {
            "protocol": "yoetz.event",
            "protocol_version": "0.1",
            "event_id": identifier,
            "task_id": _TASK,
            "session_id": _SESSION,
            "schema": {"name": schema.name, "version": schema.version},
            "author": {
                "actor_id": author.actor_id,
                "actor_type": author.actor_type.value,
                "assurance": author.assurance.value,
            },
            "writer": {
                "writer_id": _WRITER,
                "sequence": str(sequence),
                "previous_entry_digest": previous,
            },
            "ledger": {
                "ingestion_sequence": str(sequence),
                "previous_entry_digest": previous,
                "accepted_at": _NOW.wire,
            },
            "operation_id": operation_ref,
            "occurred_at": _NOW.wire,
            "causal_parents": causal_parents,
            "publication_channel": channel.value,
            "coverage": coverage_to_json(coverage),
            "payload_ref": {
                "object_id": reference,
                "media_type": media,
                "plaintext_size": len(encoded),
                "commitment": commitment,
                "encryption_format": "yoetz-object/1",
            },
            "redaction": "present",
            "artifact_refs": (),
            "evidence_refs": (),
        }
        self.records.append(
            AcceptedEvent(
                event_id=identifier,
                task_id=_TASK,
                session_id=_SESSION,
                schema=schema,
                author=author,
                writer=WriterChain(_WRITER, sequence, previous),
                ledger=LedgerChain(sequence, previous, _NOW),
                operation_id=operation_ref,
                occurred_at=_NOW,
                causal_parents=causal_parents,
                publication_channel=channel,
                coverage=coverage,
                payload_ref=PayloadRef(reference, media, len(encoded), commitment),
                redaction=RedactionState.PRESENT,
                artifact_refs=(),
                evidence_refs=(),
                entry_digest=entry_digest(preimage),
                payload=payload,
                projection_locator=ProjectionLocator(
                    schema=schema,
                    logical_key=_logical_key(payload, identifier),
                    canonical_payload_digest=canonical_digest(encode_payload(payload)),
                    redaction_target_event_ids=(
                        payload.target_event_ids
                        if isinstance(payload, RedactionRecordedPayload)
                        else ()
                    ),
                    redaction_target_object_ids=(),
                ),
            )
        )
        return identifier

    def events_of(self, result: ResultId) -> tuple[EventId, EventId]:
        """The action and result event ids of the call that recorded *result*."""

        result_record = next(
            record
            for record in self.records
            if isinstance(record, AcceptedEvent)
            and isinstance(record.payload, ResultRecordedPayload)
            and record.payload.result_id == result
        )
        payload = cast(ResultRecordedPayload, result_record.payload)
        action_event = next(
            record.event_id
            for record in self.records
            if isinstance(record, AcceptedEvent)
            and isinstance(record.payload, ActionRecordedPayload)
            and record.payload.action_id == payload.action_id
        )
        return action_event, result_record.event_id

    def advice_finding(
        self,
        refs: tuple[EventId, ...],
        *,
        number: int = 1,
        subject: tuple[str, ...] | None = None,
    ) -> FindingId:
        """Append the observation coordinator's ``failed_command_unresolved`` finding.

        Mirrors ``ObservationCoordinator._materialize_advice_findings``: an observation-authored,
        engine-derived ``finding_recorded`` (work-integrity, ``failed_work_omitted``) whose
        subject refs are the event ids the failed envelope materialized, sorted.
        """

        identifier = finding_id(f"fnd_00000000-0000-4000-8000-{number:012d}")
        kind = FindingKind.FAILED_WORK_OMITTED
        subject_refs = (
            tuple(sorted({str(ref) for ref in refs}, key=str.encode))
            if subject is None
            else subject
        )
        finding = Finding(
            identifier,
            kind,
            FindingOrigin.DETERMINISTIC,
            FINDING_KIND_TRAITS[kind][0],
            "Unresolved failed command observed",
            "A command FinishUP saw fail has no later passing run of the same command.",
            subject_refs,  # type: ignore[arg-type]
            "work-integrity",
            CURRENT_POLICY_VERSIONS["work-integrity"],
            self.frontier,
            coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
            None,
        )
        self._append(
            EventSchema("finding_recorded", "1.2.0"),
            finding,
            observed=True,
            channel=PublicationChannel.ENGINE_DERIVED,
        )
        return identifier

    def respond(
        self,
        finding: FindingId,
        disposition: ResponseDisposition,
        *,
        reason: str | None = None,
    ) -> EventId:
        """Append the agent's ``response_recorded`` answer to *finding* at the current frontier."""

        version = (
            RESPONSE_EVENT_SCHEMA_VERSION if disposition in RESPONSE_V1_1_DISPOSITIONS else "1.0.0"
        )
        return self._append(
            EventSchema("response_recorded", version),
            ResponseRecordedPayload(finding, self.frontier, disposition, reason),
            observed=False,
        )

    def redact(self, *targets: EventId) -> EventId:
        """Append a logical redaction of *targets* (their payloads become unreadable)."""

        return self._append(
            EventSchema("redaction_recorded", "1.0.0"),
            RedactionRecordedPayload(
                target_event_ids=targets,
                target_object_ids=(),
                method=RedactionMethod.LOGICAL_REDACTION,
                reason_category=RedactionReasonCategory.SECRET,
                authority=actor_id("agt_observed_runs"),
                remaining_gap="One event payload is no longer readable.",
            ),
            observed=False,
        )

    @property
    def frontier(self) -> Frontier:
        if not self.records:
            return Frontier.genesis()
        return Frontier(len(self.records), self.records[-1].entry_digest)

    def append(
        self,
        schema: EventSchema,
        payload: EventPayload,
        *,
        observed: bool,
        causal_parents: tuple[EventId, ...] = (),
        operation: str | None = None,
    ) -> EventId:
        """Append one materialized or cooperative draft payload.

        ``operation`` is the publish batch's request id; the default puts every append in one
        batch, as the records were before the field mattered (#985 blocker confirmation).
        """

        return self._append(
            schema, payload, observed=observed, causal_parents=causal_parents, operation=operation
        )

    def run(
        self,
        command: str | None,
        outcome: ResultOutcome,
        *,
        exit_status: int | None = None,
        kind: ActionKind = ActionKind.COMMAND,
        observed: bool = True,
        raw_command: str | None = None,
        tool: str | None = None,
        subject_state: SubjectStateRef | None = None,
        install_target: str | None = None,
        write_outside_workspace: bool = False,
        effective_user: str | None = None,
        runner: str | None = None,
        write_scope: str | None = None,
        workspace_effect: str | None = None,
        workspace_write_scopes: tuple[str, ...] | None = None,
        workspace_changed_entries: tuple[str, ...] | None = None,
    ) -> ResultId:
        """Record one tool call as the coordinator materializes it: action, then result.

        ``workspace_effect`` is the hook's before/after fingerprint token (PR #1080) the result
        summary carries; ``None`` records no fact, as every result before the fact existed.
        """

        action = self.begin(
            command,
            kind=kind,
            observed=observed,
            raw_command=raw_command,
            tool=tool,
            subject_state=subject_state,
            install_target=install_target,
            write_outside_workspace=write_outside_workspace,
            effective_user=effective_user,
            runner=runner,
            write_scope=write_scope,
        )
        return self.end(
            action,
            outcome,
            exit_status=exit_status,
            observed=observed,
            subject_state=subject_state,
            workspace_effect=workspace_effect,
            workspace_write_scopes=workspace_write_scopes,
            workspace_changed_entries=workspace_changed_entries,
        )

    def begin(
        self,
        command: str | None,
        *,
        kind: ActionKind = ActionKind.COMMAND,
        observed: bool = True,
        raw_command: str | None = None,
        tool: str | None = None,
        subject_state: SubjectStateRef | None = None,
        install_target: str | None = None,
        write_outside_workspace: bool = False,
        effective_user: str | None = None,
        runner: str | None = None,
        write_scope: str | None = None,
    ) -> ActionId:
        """Record only a call's action (a paired ``PreToolUse``, or a call still running).

        ``end`` records its result later, so another call's events can land in between.
        """

        self.runs += 1
        number = self.runs
        action = action_id(f"act_00000000-0000-4000-8000-{number:012d}")
        if kind is ActionKind.COMMAND:
            recorded = (
                raw_command
                if raw_command is not None
                else ("omitted:structural" if command is None else command_identity_for(command))
            )
        else:
            recorded = None
        default_tool = (
            tool
            if tool is not None
            else "exec_command"
            if kind is ActionKind.COMMAND
            else "apply_patch"
        )
        runner_class = (
            runner
            if runner is not None
            else command_runner_class(
                {"tool_name": default_tool, "command": command}  # type: ignore[dict-item]
            )
        )
        self._append(
            _ACTION,
            ActionRecordedPayload(
                action,
                kind,
                observed_action_description(
                    f"Observed {kind.value} via Codex hook",
                    default_tool,
                    runner_class,
                    install_target=install_target,
                    write_outside_workspace=write_outside_workspace,
                    effective_user=effective_user,
                    write_scope=write_scope,
                ),
                command=recorded,
                subject_state=subject_state,
            ),
            observed=observed,
        )
        return action

    def end(
        self,
        action: ActionId,
        outcome: ResultOutcome,
        *,
        exit_status: int | None = None,
        observed: bool = True,
        subject_state: SubjectStateRef | None = None,
        workspace_effect: str | None = None,
        workspace_write_scopes: tuple[str, ...] | None = None,
        workspace_changed_entries: tuple[str, ...] | None = None,
    ) -> ResultId:
        """Record the result of a call ``begin`` recorded."""

        number = int(str(action).rsplit("-", 1)[1])
        result = result_id(f"res_00000000-0000-4000-8000-{number:012d}")
        self._append(
            _RESULT,
            ResultRecordedPayload(
                result,
                action,
                outcome,
                exit_status=exit_status,
                summary=result_summary_with_workspace_effect(
                    f"Observed result status={outcome.value}",
                    workspace_effect,
                    workspace_write_scopes,
                    workspace_changed_entries,
                ),
                subject_state=subject_state,
            ),
            observed=observed,
            # The coordinator marks an outcome-less observed result with the one standing gap.
            known_gaps=(
                ("host_outcome_unavailable",)
                if observed and outcome is ResultOutcome.UNKNOWN and exit_status is None
                else ()
            ),
        )
        return result

    def correct_outcome(
        self, unknown: ResultId, outcome: ResultOutcome, *, exit_status: int | None
    ) -> ResultId:
        """Append the host stream's corrected result for the action of one unknown hook result.

        Mirrors ``materialize_observation_outcome_correction``: a second, immutable result
        linked to the same action, with no gap (#1001).
        """

        action = next(
            record.payload.action_id
            for record in self.records
            if isinstance(record, AcceptedEvent)
            and isinstance(record.payload, ResultRecordedPayload)
            and record.payload.result_id == unknown
        )
        self.runs += 1
        result = result_id(f"res_00000000-0000-4000-8000-{self.runs:012d}")
        self._append(
            _RESULT,
            ResultRecordedPayload(
                result,
                action,
                outcome,
                exit_status=exit_status,
                summary=f"Observed corrected result status={outcome.value}",
            ),
            observed=True,
        )
        return result

    def annotate_workspace_effect(
        self,
        result: ResultId,
        effect: str,
        *,
        observed: bool = True,
        scopes: tuple[str, ...] | None = None,
    ) -> EventId:
        """Append a later delivery's workspace fact for the call of *result* (PR #1080 round 6).

        Mirrors ``materialize_workspace_effect_annotation``: one metadata-only evidence row whose
        causal parent is the call's action event and whose description is the exact annotation.
        """

        action = next(
            record.payload.action_id
            for record in self.records
            if isinstance(record, AcceptedEvent)
            and isinstance(record.payload, ResultRecordedPayload)
            and record.payload.result_id == result
        )
        action_event = next(
            record.event_id
            for record in self.records
            if isinstance(record, AcceptedEvent)
            and isinstance(record.payload, ActionRecordedPayload)
            and record.payload.action_id == action
        )
        self.runs += 1
        description = workspace_effect_annotation(effect, scopes)
        assert description is not None
        return self._append(
            EventSchema("evidence_recorded", EVIDENCE_SCHEMA_VERSION),
            EvidenceRecordedPayload(
                evidence_id(f"evd_00000000-0000-4000-8000-{self.runs:012d}"),
                EvidenceKind.OTHER,
                EvidenceImmutability.METADATA_ONLY,
                _NOW,
                description=description,
            ),
            observed=observed,
            causal_parents=(action_event,),
        )

    def fail(self, command: str | None, *, exit_status: int = 1) -> ResultId:
        return self.run(command, ResultOutcome.FAILURE, exit_status=exit_status)

    def passes(self, command: str | None, *, workspace_effect: str | None = None) -> ResultId:
        return self.run(
            command, ResultOutcome.SUCCESS, exit_status=0, workspace_effect=workspace_effect
        )

    def edit(
        self,
        outcome: ResultOutcome = ResultOutcome.SUCCESS,
        *,
        subject_state: SubjectStateRef | None = None,
        write_outside_workspace: bool = False,
        write_scope: str | None = None,
    ) -> ResultId:
        """An observed apply_patch/edit capture; Codex states its exit code (#883)."""

        return self.run(
            None,
            outcome,
            kind=ActionKind.EDIT,
            subject_state=subject_state,
            write_outside_workspace=write_outside_workspace,
            write_scope=write_scope,
        )

    def claim(
        self,
        number: int = 1,
        *,
        limitations: tuple[ResultId, ...] = (),
        versioned: bool = False,
        supersedes: tuple[ClaimId, ...] = (),
        statement: str = "The change is complete.",
    ) -> ClaimId:
        identifier = claim_id(f"clm_00000000-0000-4000-8000-{number:012d}")
        payload: EventPayload
        if versioned or limitations or supersedes:
            payload = ClaimRecordedPayloadV1_1(
                claim_id=identifier,
                claim_kind=ClaimKind.COMPLETION,
                statement=statement,
                supporting_refs=(),
                obligation_refs=(),
                limitation_refs=limitations,
                supersedes_claim_refs=supersedes,
            )
            schema = _CLAIM_V1_1
        else:
            payload = ClaimRecordedPayload(
                claim_id=identifier,
                claim_kind=ClaimKind.COMPLETION,
                statement=statement,
                supporting_refs=(),
            )
            schema = _CLAIM_V1
        self._append(schema, payload, observed=False)
        return identifier

    def plan(self, *commands: str, number: int = 1) -> ObligationId:
        """Publish one obligation requesting ``commands`` (kind ``command``) and a plan naming it.

        The planned verification a passing run can match (#1104); the first plan is version 1.
        """

        identifier = obligation_id(f"obl_00000000-0000-4000-8000-{number:012d}")
        self._append(
            _OBLIGATION,
            ObligationPublishedPayload(
                obligation_id=identifier,
                description="Make the regression suite pass.",
                evidence_expectation="A recorded passing run.",
                status=ObligationStatus.OPEN,
                requested_items=tuple(
                    RequestedItem(RequestedItemKind.COMMAND, command) for command in commands
                ),
            ),
            observed=False,
        )
        self._plan_version += 1
        self._append(
            EventSchema("plan_published", "1.0.0"),
            PlanPublishedPayload(self._plan_version, "Plan", (identifier,)),
            observed=False,
        )
        return identifier

    def acknowledge_not_done(self, obligation: ObligationId, *commands: str) -> EventId:
        """Republish *obligation* (requesting ``commands``) as acknowledged not done (#997)."""

        return self._append(
            _OBLIGATION,
            ObligationPublishedPayload(
                obligation_id=obligation,
                description="Make the regression suite pass.",
                evidence_expectation="A recorded passing run.",
                status=ObligationStatus.ACKNOWLEDGED_NOT_DONE,
                requested_items=tuple(
                    RequestedItem(RequestedItemKind.COMMAND, command) for command in commands
                ),
                acknowledged_not_done_reason="The suite needs a service this sandbox lacks.",
            ),
            observed=False,
        )

    def waive(self, obligation: ObligationId) -> EventId:
        """Revise the current plan to waive *obligation* (its requested commands stop counting)."""

        self._plan_version += 1
        return self._append(
            EventSchema("plan_revised", "1.0.0"),
            PlanRevisedPayload(
                plan_version=self._plan_version,
                supersedes_plan_version=self._plan_version - 1,
                reason="The suite is out of scope.",
                summary="Waive it.",
                obligation_changes=(
                    ObligationChange(
                        obligation, ObligationChangeKind.WAIVED, "Out of scope for this task."
                    ),
                ),
            ),
            observed=False,
        )

    @property
    def prefix(self) -> tuple[LedgerRecord, ...]:
        return tuple(self.records)


def omissions(ledger: ObservedLedger) -> tuple[DeterministicAssessment, ...]:
    records = ledger.prefix
    projection = replay(records)
    case = build_deterministic_case(projection, records, CaseAvailabilityFacts())
    assessments, executions = run_deterministic_policies(case, CheckScope((), ()), _PACKS)
    assert all(item.outcome == "run" for item in executions)
    return tuple(item for item in assessments if item.candidate.kind in OMISSION_KINDS)


def omitted_results(ledger: ObservedLedger) -> tuple[str, ...]:
    """The observed result each omission finding names, in finding order."""

    refs: list[str] = []
    for item in omissions(ledger):
        facts = item.basis.observed_facts + item.basis.required_but_missing_facts
        refs.extend(
            ref
            for fact in facts
            if fact.fact_code in {"failed_result_present", "material_limitation_present"}
            for ref in fact.subject_refs
            if ref.startswith("res_")
        )
    return tuple(refs)


def observed_receipt(
    ledger: ObservedLedger, *, extra_gaps: tuple[str, ...] = ()
) -> ReceiptDocument:
    """The production receipt over the ledger's exact prefix, with no check recorded."""

    records = ledger.prefix
    projection = replay(records)
    coverage = Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.PARTIAL,
        check_types=(CheckType.NONE,),
        known_gaps=tuple(sorted({"check_not_recorded", *extra_gaps})),
    )
    context = ReceiptBuildContext(
        projection=projection,
        subject_frontier=Frontier(projection.frontier, projection.head_digest),
        availability=CaseAvailabilityFacts(),
        coverage=coverage,
        gaps=tuple(CaseGap(code, code, ()) for code in sorted({"check_not_recorded", *extra_gaps})),
        # The production per-finding states (to-do state and closure class), as the receipt
        # operation computes them; empty for a ledger without findings.
        finding_states=finding_states(projection, records),
        applicable_check=None,
        records=records,
    )
    receipt = build_receipt(
        context,
        receipt_id("rcp_00000000-0000-4000-8000-000000000909"),
        _TASK,
        _SESSION,
        _NOW,
        ReceiptVersionSlice(
            package_name="finishup",
            package_version="0.3.0",
            protocol_version="0.1",
            engine_version="0.1.0",
            projection_version="yoetz/0.1.0",
            object_format_version="yoetz-object/1",
            catalog_schema_version="1",
            bundle_schema_version="1",
            policy_versions=(
                PolicyVersionEntry("research-evidence", "0.1.0"),
                PolicyVersionEntry("work-integrity", "0.1.0"),
            ),
            schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.0.0"),),
            resource_manifest_digest="sha256:" + "9" * 64,
        ),
        ReceiptRedactionProfile.FULL_LOCAL,
        ReceiptInclude.FULL,
    )
    return receipt


def receipt_limitations(ledger: ObservedLedger, *, extra_gaps: tuple[str, ...] = ()) -> str:
    receipt = observed_receipt(ledger, extra_gaps=extra_gaps)
    return next(
        section.body
        for section in receipt.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
