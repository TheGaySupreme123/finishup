"""Honesty conformance: adversarial fixtures never let Yoetz overclaim capability or coverage.

Grounded entirely in the reviewed ``fixtures/adversarial/ADV-*.case.json`` corpus and its
``owns_requirements`` declarations: every registered ``FindingKind`` is owned by exactly one of the
seven mapped adversarial cases, each mapped case carries a genuine trigger, an in-fixture
remediation/closest-non-trigger pairing that clears the finding, and every finding object inside the
corpus round-trips through the real domain codec (``finding_from_json``) -- proving the fixtures
describe structurally admissible, policy-bound findings rather than free-form prose.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

from fixture_loader import FixtureLoader, JsonValue
from yoetz.domain.events import (
    EVIDENCE_SCHEMA_VERSION,
    AcceptedEvent,
    EventPayload,
    EventSchema,
    EvidenceRecordedPayload,
    LedgerChain,
    LedgerRecord,
    PayloadRef,
    ProjectionLocator,
    RedactionRecordedPayload,
    RedactionState,
    ResponseRecordedPayload,
    ResultRecordedPayload,
    UnknownEvent,
    WriterChain,
    decode_payload,
    encode_payload,
    media_type_for,
)
from yoetz.domain.findings import CandidateFinding, Finding, FindingKind, finding_from_json
from yoetz.domain.values import (
    Actor,
    ActorType,
    EventId,
    EvidenceId,
    Frontier,
    ObjectId,
    ResultId,
    actor_id,
    event_id,
    freeze_json,
    frontier_from_json,
    object_id,
    request_id,
    session_id,
    task_id,
    timestamp_from_string,
    writer_id,
)
from yoetz.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    UnavailableCapturedObject,
    build_deterministic_case,
    healthy_storage_availability,
    run_deterministic_policies,
)
from yoetz.kernel.policies.research_evidence import RESEARCH_EVIDENCE_POLICY_PACK
from yoetz.kernel.policies.work_integrity import WORK_INTEGRITY_POLICY_PACK
from yoetz.kernel.reducers import replay
from yoetz.protocol.canonical import canonical_digest, canonical_encode, entry_digest
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
    coverage_to_json,
)

# The exhaustive public policy-rule mapping frozen by the fixture ``owns_requirements`` fields.
# The fourteen built-in policy FindingKind values are owned by exactly one of these seven
# adversarial cases. ``coordination_overlap`` is deliberately outside this generic corpus: it is a
# local coordination-runtime finding with its own project acceptance cases, not an external
# semantic or built-in deterministic policy fixture. ADV-005/007/010/011 exist but are deliberately
# excluded from this mapping (they exercise plan-revision honesty, crash/retry idempotency,
# cross-channel import comparison, and completion-scope coverage -- not a new FindingKind of their
# own).
_ADV_KIND_MAP: dict[str, frozenset[FindingKind]] = {
    "ADV-001-abandoned-obligation": frozenset(
        {
            FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
            FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
            FindingKind.ACTION_WITHOUT_RESULT,
        }
    ),
    "ADV-002-omitted-failed-test": frozenset(
        {
            FindingKind.FAILED_WORK_OMITTED,
            FindingKind.RESULT_WITHOUT_ACTION,
            FindingKind.MATERIAL_LIMITATION_OMITTED,
        }
    ),
    "ADV-003-stale-test-after-edit": frozenset({FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE}),
    "ADV-004-irrelevant-evidence": frozenset(
        {
            FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
            FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
            FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
        }
    ),
    "ADV-006-parent-subagent-contradiction": frozenset(
        {FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED}
    ),
    "ADV-008-stale-redacted-ledger": frozenset({FindingKind.LEDGER_STALE_OR_INCOMPLETE}),
    "ADV-009-wrong-semantic-finding-rejected": frozenset(
        {FindingKind.WEAK_OR_STALE_RESPONSE, FindingKind.QUESTIONABLE_FINDING_REJECTION}
    ),
}

# All eleven adversarial cases, including the four excluded from the kind-ownership mapping above.
_ALL_ADV_IDS = (
    "ADV-001-abandoned-obligation",
    "ADV-002-omitted-failed-test",
    "ADV-003-stale-test-after-edit",
    "ADV-004-irrelevant-evidence",
    "ADV-005-legitimate-plan-revision",
    "ADV-006-parent-subagent-contradiction",
    "ADV-007-crash-retry-duplicate",
    "ADV-008-stale-redacted-ledger",
    "ADV-009-wrong-semantic-finding-rejected",
    "ADV-010-import-detects-missing-publication",
    "ADV-011-empty-completion-scope",
)

# ADV-007 exercises write idempotency at the ledger adapter boundary, ADV-010 first maps a Codex
# JSONL import before comparing channels, and ADV-011 owns coverage/readiness outcomes rather than a
# FindingKind. Every other case is eligible for replay below; keeping the exclusion set explicit
# prevents a newly added ADV case from silently escaping classification.
_NON_DIRECT_ENGINE_ADV_IDS = frozenset(
    {
        "ADV-007-crash-retry-duplicate",
        "ADV-010-import-detects-missing-publication",
        "ADV-011-empty-completion-scope",
    }
)
_DIRECT_ENGINE_ADV_IDS = tuple(
    adv_id for adv_id in _ALL_ADV_IDS if adv_id not in _NON_DIRECT_ENGINE_ADV_IDS
)

# Skip only variants that have no ledger events to replay (provider-script / post-validation
# vectors). Event-bearing empty-finding variants still run the engine so a silent owned-kind
# regression cannot hide behind the skip list.
_NON_DIRECT_ENGINE_VARIANTS = frozenset(
    {
        ("ADV-004-irrelevant-evidence", "semantic_basis_mutation"),
        ("ADV-004-irrelevant-evidence", "semantic_invented_ref"),
    }
)
_POLICY_PACKS = {
    WORK_INTEGRITY_POLICY_PACK.policy_id: WORK_INTEGRITY_POLICY_PACK,
    RESEARCH_EVIDENCE_POLICY_PACK.policy_id: RESEARCH_EVIDENCE_POLICY_PACK,
}
_UNAVAILABLE_OBJECT_STATUSES = frozenset(
    {"unavailable", "unavailable_at_freeze", "key_unavailable"}
)
_PRESENT_OBJECT_STATUSES = frozenset({"available", "logically_redacted"})

_FIXTURE_TASK_ID = task_id("tsk_f0000000-0000-4000-8000-000000000001")
_FIXTURE_SESSION_ID = session_id("ses_f0000000-0000-4000-8000-000000000001")
_FIXTURE_WRITER_ID = writer_id("wri_f0000000-0000-4000-8000-000000000001")
_FIXTURE_COVERAGE = Coverage(
    publication_channels=(PublicationChannel.COOPERATIVE_MCP,),
    authorship_assurance=AuthorshipAssurance.SELF_ASSERTED,
    artifact_observation=ArtifactObservation.CONTENT_CAPTURED,
    evidence_immutability=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
    ledger_freshness=LedgerFreshness.CURRENT,
    check_types=(CheckType.NONE,),
    known_gaps=(),
)
_FINDING_EXPECTATION_KEYS = ("kind", "subject_refs", "summary", "detail", "priority")


def _fixture_path(adv_id: str) -> str:
    return f"adversarial/{adv_id}.case.json"


def _load_expected(fixture_loader: FixtureLoader, adv_id: str) -> dict[str, object]:
    document = cast(dict[str, object], fixture_loader.load_json(_fixture_path(adv_id)))
    return cast(dict[str, object], document["expected"])


def _variants(expected: dict[str, object]) -> dict[str, dict[str, object]]:
    raw = cast(dict[str, object], expected["variants"])
    return {name: cast(dict[str, object], value) for name, value in raw.items()}


def _relationships(expected: dict[str, object]) -> list[dict[str, str]]:
    return cast(list[dict[str, str]], expected["relationships"])


def _input_variants(document: dict[str, object]) -> dict[str, dict[str, object]]:
    raw_input = cast(dict[str, object], document["input"])
    raw_variants = cast(dict[str, object], raw_input["variants"])
    return {name: cast(dict[str, object], value) for name, value in raw_variants.items()}


def _expected_rules_by_variant(
    expected: dict[str, object],
) -> dict[str, tuple[frozenset[str], frozenset[FindingKind]]]:
    """Bind each counterexample/remediation component to the rules that fixture owns.

    A full policy pack can report other independently owned concerns in the same synthetic event
    prefix. The relationship graph is the fixture's explicit boundary: findings anywhere in one
    connected component select the exact policy packs and finding kinds compared for every trigger
    and non-trigger in that component.
    """

    variants = _variants(expected)
    neighbors = {name: set[str]() for name in variants}
    for relationship in _relationships(expected):
        left = relationship["from"]
        right = relationship["to"]
        neighbors[left].add(right)
        neighbors[right].add(left)

    result: dict[str, tuple[frozenset[str], frozenset[FindingKind]]] = {}
    remaining = set(variants)
    while remaining:
        seed = min(remaining)
        component: set[str] = set()
        pending = [seed]
        while pending:
            name = pending.pop()
            if name in component:
                continue
            component.add(name)
            pending.extend(neighbors[name] - component)
        remaining -= component
        policy_ids = frozenset(
            cast(str, finding["policy_id"])
            for name in component
            for finding in cast(list[dict[str, object]], variants[name].get("findings", []))
        )
        kinds = frozenset(
            FindingKind(cast(str, finding["kind"]))
            for name in component
            for finding in cast(list[dict[str, object]], variants[name].get("findings", []))
        )
        for name in component:
            result[name] = (policy_ids, kinds)
    return result


def _event_schema(raw: dict[str, object]) -> EventSchema:
    schema = raw.get("schema")
    if schema is not None:
        wire = cast(dict[str, object], schema)
        return EventSchema(cast(str, wire["name"]), cast(str, wire["version"]))
    return EventSchema(cast(str, raw["family"]), "1.0.0")


def _evidence_digest_subject(kind: object) -> str:
    return {
        "artifact": "artifact_bytes",
        "command_output": "command_stdout",
        "research_source": "bounded_excerpt",
        "test_result": "test_report",
    }.get(cast(str, kind), "bounded_excerpt")


def _event_payload(
    raw: dict[str, object], schema: EventSchema
) -> tuple[EventSchema, EventPayload | None]:
    raw_payload = raw.get("payload")
    if raw_payload is None:
        return schema, None
    wire = dict(cast(dict[str, JsonValue], raw_payload))

    # The ADV corpus predates evidence-recorded/1.1.0 and uses its captured object plus digest as
    # shorthand for a content-captured immutable snapshot. Upgrade that shorthand at the fixture
    # adapter boundary so the current engine sees the same declared evidence semantics instead of
    # treating these intentionally synthetic vectors as legacy digest-only production records.
    if (
        schema == EventSchema("evidence_recorded", "1.0.0")
        and wire.get("content_digest") is not None
    ):
        schema = EventSchema("evidence_recorded", EVIDENCE_SCHEMA_VERSION)
        captured = wire.get("captured_object_id") is not None
        description = wire.get("description")
        if captured:
            byte_count = (
                len(description.encode("utf-8")) if type(description) is str and description else 1
            )
        else:
            byte_count = 0
        wire["digest_binding"] = {
            "subject": _evidence_digest_subject(wire.get("evidence_kind")),
            "content_availability": "captured" if captured else "digest_only",
            "byte_count": byte_count,
            "provenance": "caller_asserted",
        }
    payload = decode_payload(schema, freeze_json(cast(JsonValue, wire)))
    return schema, payload


def _logical_key(schema: EventSchema, payload: EventPayload | None, event: str) -> str | None:
    if payload is None:
        return None
    wire = cast(dict[str, JsonValue], encode_payload(cast(Any, payload)))
    if schema.name in {"plan_published", "plan_revised"}:
        return str(wire["plan_version"])
    if schema.name == "obligation_published":
        return cast(str, wire["obligation_id"])
    if schema.name in {"assignment_recorded", "decision_recorded", "check_recorded"}:
        return event
    key_by_family = {
        "action_recorded": "action_id",
        "result_recorded": "result_id",
        "evidence_recorded": "evidence_id",
        "claim_recorded": "claim_id",
        "finding_recorded": "finding_id",
        "response_recorded": "finding_id",
    }
    field = key_by_family.get(schema.name)
    return None if field is None else cast(str, wire[field])


def _record_refs(
    raw: dict[str, object], payload: EventPayload | None
) -> tuple[tuple[ObjectId, ...], tuple[EvidenceId | ResultId, ...]]:
    artifact_refs = tuple(
        object_id(value) for value in cast(list[str], raw.get("artifact_refs", []))
    )
    evidence_refs = cast(
        tuple[EvidenceId | ResultId, ...],
        tuple(cast(list[str], raw.get("evidence_refs", []))),
    )
    if type(payload) is EvidenceRecordedPayload:
        artifact_refs = () if payload.captured_object_id is None else (payload.captured_object_id,)
    elif type(payload) is RedactionRecordedPayload:
        artifact_refs = payload.target_object_ids
    if type(payload) is ResultRecordedPayload:
        evidence_refs = payload.evidence_refs
    elif type(payload) is ResponseRecordedPayload:
        evidence_refs = payload.evidence_refs
    return artifact_refs, evidence_refs


def _fixture_record(
    raw: dict[str, object],
    *,
    sequence: int,
    previous_entry_digest: str,
) -> LedgerRecord:
    event = event_id(raw["event_id"])
    schema, payload = _event_payload(raw, _event_schema(raw))
    occurred_at = timestamp_from_string(
        cast(str, raw.get("occurred_at", "2026-01-01T00:00:00.000Z"))
    )
    actor = Actor(
        actor_id(raw.get("actor_id", "agt.fixture.main")),
        ActorType.LOGICAL_AGENT,
        AuthorshipAssurance.SELF_ASSERTED,
    )
    writer = WriterChain(_FIXTURE_WRITER_ID, sequence, previous_entry_digest)
    ledger = LedgerChain(sequence, previous_entry_digest, occurred_at)
    operation = request_id(f"req_f0000000-0000-4000-8000-{sequence:012x}")
    payload_object = object_id(f"obj_f0000000-0000-4000-8000-{sequence:012x}")
    artifact_refs, evidence_refs = _record_refs(raw, payload)
    payload_digest = (
        cast(str, raw["canonical_payload_digest"])
        if payload is None
        else canonical_digest(encode_payload(cast(Any, payload)))
    )
    payload_size = (
        0 if payload is None else len(canonical_encode(encode_payload(cast(Any, payload))))
    )
    payload_ref = PayloadRef(
        object_id=payload_object,
        media_type=media_type_for(schema.name),
        plaintext_size=payload_size,
        commitment=f"hmac-sha256:{sequence:064x}",
    )
    event_targets: tuple[EventId, ...] = ()
    object_targets: tuple[ObjectId, ...] = ()
    if type(payload) is RedactionRecordedPayload:
        event_targets = payload.target_event_ids
        object_targets = payload.target_object_ids
    locator = ProjectionLocator(
        schema=schema,
        logical_key=_logical_key(schema, payload, event),
        canonical_payload_digest=payload_digest,
        redaction_target_event_ids=event_targets,
        redaction_target_object_ids=object_targets,
    )
    causal_parents = tuple(
        event_id(value) for value in cast(list[str], raw.get("causal_parents", []))
    )
    channel = PublicationChannel(cast(str, raw.get("publication_channel", "cooperative_mcp")))
    coverage = replace(_FIXTURE_COVERAGE, publication_channels=(channel,))
    preimage = {
        "protocol": "yoetz.event",
        "protocol_version": "0.1",
        "event_id": event,
        "task_id": _FIXTURE_TASK_ID,
        "session_id": _FIXTURE_SESSION_ID,
        "schema": {"name": schema.name, "version": schema.version},
        "author": {
            "actor_id": actor.actor_id,
            "actor_type": actor.actor_type.value,
            "assurance": actor.assurance.value,
        },
        "writer": {
            "writer_id": writer.writer_id,
            "sequence": str(writer.sequence),
            "previous_entry_digest": writer.previous_entry_digest,
        },
        "ledger": {
            "ingestion_sequence": str(ledger.ingestion_sequence),
            "previous_entry_digest": ledger.previous_entry_digest,
            "accepted_at": ledger.accepted_at.wire,
        },
        "operation_id": operation,
        "occurred_at": occurred_at.wire,
        "causal_parents": list(causal_parents),
        "publication_channel": channel.value,
        "coverage": coverage_to_json(coverage),
        "payload_ref": {
            "object_id": payload_ref.object_id,
            "media_type": payload_ref.media_type,
            "plaintext_size": payload_ref.plaintext_size,
            "commitment": payload_ref.commitment,
            "encryption_format": payload_ref.encryption_format,
        },
        "redaction": RedactionState.PRESENT.value,
        "artifact_refs": list(artifact_refs),
        "evidence_refs": list(evidence_refs),
    }
    record_digest = entry_digest(cast(Any, preimage))
    if payload is None:
        return UnknownEvent(
            event_id=event,
            task_id=_FIXTURE_TASK_ID,
            session_id=_FIXTURE_SESSION_ID,
            schema=schema,
            author=actor,
            writer=writer,
            ledger=ledger,
            operation_id=operation,
            occurred_at=occurred_at,
            causal_parents=causal_parents,
            publication_channel=channel,
            coverage=coverage,
            payload_ref=payload_ref,
            redaction=RedactionState.PRESENT,
            artifact_refs=artifact_refs,
            evidence_refs=evidence_refs,
            entry_digest=record_digest,
            payload=None,
            projection_locator=locator,
            canonical_payload_digest=payload_digest,
        )
    return AcceptedEvent(
        event_id=event,
        task_id=_FIXTURE_TASK_ID,
        session_id=_FIXTURE_SESSION_ID,
        schema=schema,
        author=actor,
        writer=writer,
        ledger=ledger,
        operation_id=operation,
        occurred_at=occurred_at,
        causal_parents=causal_parents,
        publication_channel=channel,
        coverage=coverage,
        payload_ref=payload_ref,
        redaction=RedactionState.PRESENT,
        artifact_refs=artifact_refs,
        evidence_refs=evidence_refs,
        entry_digest=record_digest,
        payload=payload,
        projection_locator=locator,
    )


def _padding_event(sequence: int) -> dict[str, object]:
    return {
        "event_id": f"evt_f0000000-0000-4000-8000-{sequence:012x}",
        "family": "session_opened",
        "occurred_at": "2026-01-01T00:00:00.000Z",
        "publication_channel": "cooperative_mcp",
        "payload": {
            "task_title": "Adversarial fixture prefix",
            "client_kind": "cooperative_agent",
            "client_version": "fixture-1",
            "integration": "cooperative_mcp",
            "profile": "test-fake",
        },
    }


def _availability_facts(
    input_variant: dict[str, object],
    projection: object,
    prefix: tuple[LedgerRecord, ...],
) -> CaseAvailabilityFacts:
    """Prefer healthy storage facts, then overlay fixture ``object_availability``.

    ``available`` and ``logically_redacted`` objects are not storage outages: redaction is
    already recorded on the ledger and must not appear in ``unavailable_captured_objects``.
    Explicit unavailable statuses become ``UnavailableCapturedObject`` rows bound to the
    evidence event that captured that object.
    """

    healthy = healthy_storage_availability(cast(Any, projection), prefix)
    raw_availability = input_variant.get("object_availability")
    if raw_availability is None:
        return healthy
    captured_sources: dict[ObjectId, EventId] = {}
    for record in prefix:
        payload = record.payload
        if type(payload) is EvidenceRecordedPayload and payload.captured_object_id is not None:
            captured_sources[payload.captured_object_id] = record.event_id
    unavailable: list[UnavailableCapturedObject] = []
    for raw_object, status in cast(dict[str, str], raw_availability).items():
        assert status in _PRESENT_OBJECT_STATUSES | _UNAVAILABLE_OBJECT_STATUSES, (
            raw_object,
            status,
        )
        if status in _PRESENT_OBJECT_STATUSES:
            continue
        captured = object_id(raw_object)
        unavailable.append(
            UnavailableCapturedObject(captured_sources[captured], captured),
        )
    objects = tuple(
        sorted(
            unavailable,
            key=lambda item: (
                _ascii_availability_key(item.source_event_id),
                _ascii_availability_key(item.object_id),
            ),
        )
    )
    return CaseAvailabilityFacts(healthy.unavailable_event_ids, objects)


def _ascii_availability_key(value: str) -> bytes:
    return value.encode("ascii")


def _declared_frontier(input_variant: dict[str, object]) -> Frontier:
    raw = input_variant.get("checked_frontier")
    assert raw is not None
    return frontier_from_json(freeze_json(cast(JsonValue, raw)))


def _deterministic_findings(
    input_variant: dict[str, object],
    policy_ids: frozenset[str],
) -> tuple[CandidateFinding, ...]:
    raw_events = cast(list[dict[str, object]], input_variant["events"])
    frontier = _declared_frontier(input_variant)
    padding_count = frontier.sequence - len(raw_events)
    assert padding_count >= 0
    rows = [*(_padding_event(index) for index in range(1, padding_count + 1)), *raw_events]
    records: list[LedgerRecord] = []
    previous_digest = "genesis"
    for sequence, row in enumerate(rows, start=1):
        record = _fixture_record(
            row,
            sequence=sequence,
            previous_entry_digest=previous_digest,
        )
        records.append(record)
        previous_digest = record.entry_digest
    prefix = tuple(records)
    projection = replay(prefix)
    case = build_deterministic_case(
        projection,
        prefix,
        _availability_facts(input_variant, projection, prefix),
    )
    # The fixtures intentionally use readable synthetic digest sentinels instead of re-pinning a
    # complete accepted-entry chain. Preserve the replayed state while running at that exact
    # declared frontier identity.
    projection = replace(case.projection, head_digest=frontier.head_digest)
    case = replace(case, projection=projection, frontier=frontier)
    assert policy_ids <= _POLICY_PACKS.keys()
    return tuple(
        assessment.candidate
        for policy_id in sorted(policy_ids)
        for policy in (_POLICY_PACKS[policy_id],)
        for assessment in run_deterministic_policies(case, policy).assessments
    )


def _finding_expectation(value: CandidateFinding | dict[str, object]) -> dict[str, JsonValue]:
    if isinstance(value, CandidateFinding):
        return {
            "kind": value.kind.value,
            "subject_refs": list(value.subject_refs),
            "summary": value.summary,
            "detail": value.detail,
            "priority": value.priority,
        }
    return {key: cast(JsonValue, value[key]) for key in _FINDING_EXPECTATION_KEYS}


def _finding_set_bytes(
    values: tuple[CandidateFinding, ...] | list[dict[str, object]],
) -> tuple[bytes, ...]:
    return tuple(
        sorted(canonical_encode(cast(Any, _finding_expectation(value))) for value in values)
    )


def _finding_kinds(variant: dict[str, object]) -> frozenset[FindingKind]:
    raw = variant.get("finding_kinds")
    if raw is None:
        return frozenset()
    return frozenset(FindingKind(value) for value in cast(list[str], raw))


def _raw_findings(variant: dict[str, object]) -> list[dict[str, object]]:
    # Local-origin variants store their payload under "findings"; accepted AI-powered-origin
    # findings (ADV-004's "semantic_present_irrelevant") store the same shape under
    # "accepted_semantic_findings" instead.
    raw = variant.get("findings") or variant.get("accepted_semantic_findings")
    if not raw:
        return []
    return cast(list[dict[str, object]], raw)


_FINDING_WIRE_KEYS = frozenset(
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
        "provenance",
    }
)


def _decode_findings(variant: dict[str, object]) -> tuple[Finding, ...]:
    # Fixture finding objects carry extra fixture-authoring fields beyond the closed wire
    # ``finding-1.0.0`` schema -- ``basis`` (the local/AI-powered rule id, observed/missing
    # facts, and state relation that document *why* the finding exists) and, for accepted AI-powered
    # findings, ``reviewer_challenge``. Strip everything outside the real wire field set before
    # round-tripping through the real domain codec.
    findings: list[Finding] = []
    for raw in _raw_findings(variant):
        wire = {key: value for key, value in raw.items() if key in _FINDING_WIRE_KEYS}
        findings.append(finding_from_json(freeze_json(cast(JsonValue, wire))))
    return tuple(findings)


def test_adversarial_expected_findings_match_deterministic_engine(
    fixture_loader: FixtureLoader,
) -> None:
    """Every owned rule relationship pins exact current-engine finding bytes."""

    assert frozenset(_DIRECT_ENGINE_ADV_IDS) | _NON_DIRECT_ENGINE_ADV_IDS == frozenset(_ALL_ADV_IDS)
    assert frozenset(_DIRECT_ENGINE_ADV_IDS) & _NON_DIRECT_ENGINE_ADV_IDS == frozenset()

    expected_compared = sum(
        1
        for adv_id in _DIRECT_ENGINE_ADV_IDS
        for name, input_variant in _input_variants(
            cast(dict[str, object], fixture_loader.load_json(_fixture_path(adv_id)))
        ).items()
        if "events" in input_variant and (adv_id, name) not in _NON_DIRECT_ENGINE_VARIANTS
    )
    compared = 0
    for adv_id in _DIRECT_ENGINE_ADV_IDS:
        document = cast(dict[str, object], fixture_loader.load_json(_fixture_path(adv_id)))
        input_variants = _input_variants(document)
        expected = cast(dict[str, object], document["expected"])
        expected_variants = _variants(expected)
        rules_by_variant = _expected_rules_by_variant(expected)
        assert input_variants.keys() == expected_variants.keys(), adv_id

        for name, input_variant in input_variants.items():
            expected_variant = expected_variants[name]
            policy_ids, owned_kinds = rules_by_variant[name]
            has_events = "events" in input_variant
            if (adv_id, name) in _NON_DIRECT_ENGINE_VARIANTS:
                assert not has_events, (adv_id, name)
                assert not policy_ids, (adv_id, name)
                assert not cast(list[object], expected_variant.get("findings", [])), (adv_id, name)
                continue
            assert has_events, (adv_id, name)
            if not policy_ids:
                owned_kinds = _ADV_KIND_MAP[adv_id]
                policy_ids = frozenset(_POLICY_PACKS)
            assert policy_ids, (adv_id, name)
            assert owned_kinds, (adv_id, name)
            actual_findings = tuple(
                finding
                for finding in _deterministic_findings(
                    input_variant,
                    policy_ids,
                )
                if finding.kind in owned_kinds
            )
            expected_findings = cast(list[dict[str, object]], expected_variant.get("findings", []))
            assert _finding_set_bytes(actual_findings) == _finding_set_bytes(expected_findings), (
                adv_id,
                name,
            )
            compared += 1

    assert compared == expected_compared


def test_adv_claim_fixtures_fail_closed(fixture_loader: FixtureLoader) -> None:
    """Every generic-policy FindingKind is owned by exactly one mapped case, with no leftovers."""

    union: set[FindingKind] = set()
    for adv_id, kinds in _ADV_KIND_MAP.items():
        assert kinds, adv_id
        overlap = union & kinds
        assert not overlap, (adv_id, overlap)
        union |= kinds
    # Kinds outside the adversarial corpus, each with its owning coverage:
    # - COORDINATION_OVERLAP comes from the coordination projection, not a policy pack.
    # - CODE_DEFECT is named only by the AI-powered verifying reviewer (#906).
    # - TASK_REQUIREMENT_UNMET is AI-reviewer-named, and its one deterministic producer (an
    #   unjustified pre-existing test edit, #961) is locked by
    #   tests/unit/kernel/test_test_edit_visibility.py and
    #   tests/integration/application/test_check.py; it has no ADV case yet.
    expected_generic_kinds = frozenset(FindingKind) - {
        FindingKind.COORDINATION_OVERLAP,
        FindingKind.CODE_DEFECT,
        FindingKind.TASK_REQUIREMENT_UNMET,
    }
    assert union == expected_generic_kinds, expected_generic_kinds - union

    for adv_id, mapped_kinds in _ADV_KIND_MAP.items():
        expected = _load_expected(fixture_loader, adv_id)
        variants = _variants(expected)
        observed_kinds: set[FindingKind] = set()

        for name, variant in variants.items():
            declared = _finding_kinds(variant)
            # A fixture never claims a kind outside its own declared, policy-mapped set -- there is
            # no lookup of an undeclared policy-resource path.
            assert declared <= mapped_kinds, (adv_id, name, declared - mapped_kinds)
            observed_kinds |= declared

            # Every finding admissibly round-trips through the real domain codec: malformed or
            # policy-mismatched data would raise here instead of silently being accepted, and the
            # decoded kind set always matches what the fixture itself declares.
            findings = _decode_findings(variant)
            assert {finding.kind for finding in findings} == declared, (adv_id, name)
            for finding in findings:
                assert finding.kind in mapped_kinds

        # Every kind this case owns is actually exercised by at least one trigger variant.
        assert observed_kinds == mapped_kinds, (adv_id, mapped_kinds - observed_kinds)


def test_claim_language_remains_within_supported_bounds(fixture_loader: FixtureLoader) -> None:
    """Finding summaries/details in the adversarial corpus stay within conservative wording."""

    banned_tokens = (
        "definitely",
        "100%",
        "guarantee",
        "proven",
        "always correct",
        "certainly true",
    )
    checked_any = False
    for adv_id in _ALL_ADV_IDS:
        expected = _load_expected(fixture_loader, adv_id)
        for name, variant in _variants(expected).items():
            for finding in _decode_findings(variant):
                checked_any = True
                for text in (finding.summary, finding.detail):
                    lowered = text.lower()
                    for token in banned_tokens:
                        assert token not in lowered, (adv_id, name, token, text)
            must_not_claim = variant.get("must_not_claim")
            if must_not_claim:
                # A variant that explicitly records forbidden phrasing never lets that phrasing
                # leak into its own findings/detail text.
                for phrase in cast(list[str], must_not_claim):
                    for finding in _decode_findings(variant):
                        assert phrase not in finding.summary, (adv_id, name, phrase)
                        assert phrase not in finding.detail, (adv_id, name, phrase)
    assert checked_any


def test_counterexample_shrinks_to_named_claim(fixture_loader: FixtureLoader) -> None:
    """Every adversarial relationship names two real variants and a nonempty explanation."""

    for adv_id in _ALL_ADV_IDS:
        expected = _load_expected(fixture_loader, adv_id)
        variants = _variants(expected)
        relationships = _relationships(expected)
        assert relationships, adv_id

        for relationship in relationships:
            source_name = relationship["from"]
            target_name = relationship["to"]
            assertion = relationship["assertion"]
            assert source_name in variants, (adv_id, source_name)
            assert target_name in variants, (adv_id, target_name)
            assert isinstance(assertion, str) and assertion.strip(), (adv_id, relationship)

            source = variants[source_name]
            target = variants[target_name]
            if "finding_kinds" in source and "finding_kinds" in target:
                source_kinds = _finding_kinds(source)
                target_kinds = _finding_kinds(target)
                # Where both sides declare finding kinds, the two named claim sets are always
                # nested (one is a subset of the other, usually the empty set on one side) -- a
                # relationship never links two orthogonal, unrelated named claims.
                assert source_kinds <= target_kinds or target_kinds <= source_kinds, (
                    adv_id,
                    source_name,
                    target_name,
                    source_kinds,
                    target_kinds,
                )


def test_empty_completion_scope_fixture_keeps_declared_none_coverage_incomplete(
    fixture_loader: FixtureLoader,
) -> None:
    """ADV-011 distinguishes readiness repair from completion-coverage sufficiency."""

    fixture = cast(
        dict[str, object],
        fixture_loader.load_json(_fixture_path("ADV-011-empty-completion-scope")),
    )
    variants = _variants(cast(dict[str, object], fixture["expected"]))
    undeclared = variants["undeclared_trigger"]
    declared_at_publication = variants["declared_none_at_publication"]
    declared_by_revision = variants["declared_none_by_revision"]
    declared_and_resolved = variants["declared_and_resolved"]

    assert undeclared["blocking_conditions"] == ["no_obligations_declared"]
    assert undeclared["no_obligations_reason"] is None
    assert cast(dict[str, object], undeclared["coverage"])["known_gaps"] == [
        "completion_scope_undeclared"
    ]
    assert undeclared["receipt_scope_wording"] == "scope was never declared"

    for variant, reason in (
        (declared_at_publication, "single_atomic_change"),
        (declared_by_revision, "no_material_change"),
    ):
        assert variant["blocking_conditions"] == []
        assert variant["declared_obligation_count"] == "0"
        assert variant["no_obligations_reason"] == reason
        assert variant["completeness"] == "coverage_incomplete"
        assert variant["verdict"] == "insufficient_coverage"
        assert cast(dict[str, object], variant["coverage"])["known_gaps"] == [
            "completion_scope_declared_none"
        ]
        assert variant["receipt_scope_wording"] == f"the plan declared none, reason: {reason}"

    assert declared_and_resolved["declared_obligation_count"] == "1"
    assert declared_and_resolved["no_obligations_reason"] is None
    assert cast(dict[str, object], declared_and_resolved["coverage"])["known_gaps"] == []
    assert declared_and_resolved["receipt_scope_wording"] == (
        "declared obligations are all resolved"
    )

    input_variants = cast(dict[str, object], cast(dict[str, object], fixture["input"])["variants"])
    resolved_events = cast(
        list[dict[str, object]],
        cast(dict[str, object], input_variants["declared_and_resolved"])["events"],
    )
    completion = next(
        event
        for event in resolved_events
        if cast(dict[str, object], event["schema"])["name"] == "claim_recorded"
    )
    assert cast(dict[str, object], completion["payload"])["obligation_refs"] == [
        "obl_00000000-0000-4000-8000-000000000111"
    ]


def test_semantic_packet_and_challenge_fixtures_are_exact(fixture_loader: FixtureLoader) -> None:
    """ADV-002, ADV-003, ADV-004, and ADV-009 lock their documented AI-powered review authority fences."""

    # ADV-002: the trigger's reviewer challenge asks the main agent for the smallest useful next
    # step, citing real refs; a fixture that discloses the failure carries no residual challenge.
    adv_002 = _variants(_load_expected(fixture_loader, "ADV-002-omitted-failed-test"))
    trigger_002 = adv_002["trigger"]
    challenges = cast(list[dict[str, object]], trigger_002["assisted_semantic_challenges"])
    assert challenges
    for challenge in challenges:
        assert challenge["requested_next_step"]
        assert cast(list[str], challenge["cited_refs"])
    disclosed = adv_002["disclosed_partial"]
    assert disclosed.get("assisted_semantic_challenges") == []
    assert _finding_kinds(disclosed) == frozenset()

    # ADV-003: claimed change, the same|different|unknown state relation, and content visibility
    # vary independently; withholding excerpt content never renders as "no diff" (never "same").
    adv_003 = _variants(_load_expected(fixture_loader, "ADV-003-stale-test-after-edit"))
    for name in ("trigger", "changed_state_content_withheld"):
        findings = _raw_findings(adv_003[name])
        assert findings, name
        for finding in findings:
            basis = cast(dict[str, object], finding["basis"])
            relation = basis["subject_state_relation"]
            assert relation in {"same", "different", "unknown"}, (name, relation)
            assert relation != "same", (
                name,
                "withheld or observed-different content is never same",
            )
    assert _finding_kinds(adv_003["closest_non_trigger_same_state"]) == frozenset()

    # ADV-004: refs cited by an accepted AI-powered finding are limited to the case's own admissible
    # set; an invented reference or a mutated local basis is rejected before construction.
    adv_004 = _variants(_load_expected(fixture_loader, "ADV-004-irrelevant-evidence"))
    for rejected_name, expected_reason in (
        ("semantic_invented_ref", "rejected_reference_outside_case"),
        ("semantic_basis_mutation", "rejected_basis_mutation"),
    ):
        rejected = adv_004[rejected_name]
        assert rejected["accepted_semantic_findings"] == []
        assert rejected["post_validation"] == expected_reason

    # ADV-009: accepted reviewer guidance always requires a fresh check, and no variant grants the
    # model a waiver of the finding.
    adv_009 = _variants(_load_expected(fixture_loader, "ADV-009-wrong-semantic-finding-rejected"))
    assert adv_009
    for name, variant in adv_009.items():
        assert "waiver" not in variant and "waiver_scope" not in variant, name
        fresh_required = variant.get("fresh_check_required")
        if fresh_required is not None:
            assert fresh_required is True, name
