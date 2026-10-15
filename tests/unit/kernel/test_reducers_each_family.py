"""Family-by-family pure reducer transition conformance."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import fields, replace
from typing import Any, cast

import pytest

from finishup.domain.events import (
    PAYLOAD_TYPES,
    AcceptedEvent,
    EventSchema,
    LedgerChain,
    LedgerRecord,
    PayloadRef,
    ProjectionLocator,
    RedactionState,
    UnknownEvent,
    WriterChain,
    decode_payload,
)
from finishup.domain.values import (
    Actor,
    ActorType,
    actor_id,
    event_id,
    finding_id,
    freeze_json,
    object_id,
    request_id,
    session_id,
    task_id,
    timestamp_from_string,
    writer_id,
)
from finishup.kernel.projections import projection_digest
from finishup.kernel.reducers import (
    EvidenceObjectSource,
    ReplayIndex,
    build_replay_index,
    empty_replay_index,
    extend_replay_index,
    reduce_event,
    replay,
    replay_extension,
    replay_extension_with_index,
    replay_with_index,
    validate_replay_index,
)
from finishup.protocol.canonical import JsonValue as CanonicalJsonValue
from finishup.protocol.canonical import entry_digest
from finishup.protocol.coverage import (
    AuthorshipAssurance,
    Coverage,
    LedgerFreshness,
    PublicationChannel,
    coverage_from_json,
)
from fixture_loader import load_fixture_json


def _fixture(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], load_fixture_json(f"replay/{name}.case.json"))


def _schema(row: dict[str, Any]) -> EventSchema:
    envelope = cast(dict[str, Any], row["envelope"])
    wire = cast(dict[str, Any], envelope["schema"])
    return EventSchema(cast(str, wire["name"]), cast(str, wire["version"]))


def _locator(row: dict[str, Any], schema: EventSchema) -> ProjectionLocator:
    envelope = cast(dict[str, Any], row["envelope"])
    payload = cast(dict[str, Any], row["payload"])
    family = schema.name
    logical_key: str | None
    if family in {"plan_published", "plan_revised"}:
        logical_key = str(payload["plan_version"])
    elif family == "obligation_published":
        logical_key = cast(str, payload["obligation_id"])
    elif family in {"assignment_recorded", "decision_recorded", "check_recorded"}:
        logical_key = cast(str, envelope["event_id"])
    elif family == "action_recorded":
        logical_key = cast(str, payload["action_id"])
    elif family == "result_recorded":
        logical_key = cast(str, payload["result_id"])
    elif family == "evidence_recorded":
        logical_key = cast(str, payload["evidence_id"])
    elif family == "claim_recorded":
        logical_key = cast(str, payload["claim_id"])
    elif family in {"finding_recorded", "response_recorded"}:
        logical_key = cast(str, payload["finding_id"])
    else:
        logical_key = None
    if family == "redaction_recorded":
        event_targets = cast(tuple[Any, ...], tuple(cast(list[str], payload["target_event_ids"])))
        object_targets = cast(
            tuple[Any, ...],
            tuple(cast(list[str], payload["target_object_ids"])),
        )
    else:
        event_targets = ()
        object_targets = ()
    return ProjectionLocator(
        schema=schema,
        logical_key=logical_key,
        canonical_payload_digest=cast(str, row["canonical_payload_digest"]),
        redaction_target_event_ids=event_targets,
        redaction_target_object_ids=object_targets,
    )


def _coverage(value: object) -> Coverage:
    return coverage_from_json(cast(CanonicalJsonValue, freeze_json(value)))


def _record(row: dict[str, Any]) -> LedgerRecord:
    envelope = cast(dict[str, Any], row["envelope"])
    author = cast(dict[str, Any], envelope["author"])
    writer = cast(dict[str, Any], envelope["writer"])
    ledger = cast(dict[str, Any], envelope["ledger"])
    payload_ref = cast(dict[str, Any], envelope["payload_ref"])
    schema = _schema(row)
    common: dict[str, Any] = {
        "event_id": event_id(envelope["event_id"]),
        "task_id": task_id(envelope["task_id"]),
        "session_id": session_id(envelope["session_id"]),
        "schema": schema,
        "author": Actor(
            actor_id(author["actor_id"]),
            ActorType(author["actor_type"]),
            AuthorshipAssurance(author["assurance"]),
        ),
        "writer": WriterChain(
            writer_id(writer["writer_id"]),
            int(writer["sequence"]),
            cast(str, writer["previous_entry_digest"]),
        ),
        "ledger": LedgerChain(
            int(ledger["ingestion_sequence"]),
            cast(str, ledger["previous_entry_digest"]),
            timestamp_from_string(ledger["accepted_at"]),
        ),
        "operation_id": request_id(envelope["operation_id"]),
        "occurred_at": timestamp_from_string(envelope["occurred_at"]),
        "causal_parents": cast(tuple[Any, ...], tuple(cast(list[str], envelope["causal_parents"]))),
        "publication_channel": PublicationChannel(envelope["publication_channel"]),
        "coverage": _coverage(envelope["coverage"]),
        "payload_ref": PayloadRef(
            object_id(payload_ref["object_id"]),
            cast(str, payload_ref["media_type"]),
            cast(int, payload_ref["plaintext_size"]),
            cast(str, payload_ref["commitment"]),
        ),
        "redaction": RedactionState(envelope["redaction"]),
        "artifact_refs": cast(tuple[Any, ...], tuple(cast(list[str], envelope["artifact_refs"]))),
        "evidence_refs": cast(tuple[Any, ...], tuple(cast(list[str], envelope["evidence_refs"]))),
        "entry_digest": cast(str, envelope["entry_digest"]),
    }
    if schema in PAYLOAD_TYPES:
        payload = decode_payload(schema, freeze_json(row["payload"]))
        return AcceptedEvent(
            **common,
            payload=payload,
            projection_locator=_locator(row, schema),
        )
    digest = cast(str, row["canonical_payload_digest"])
    return UnknownEvent(
        **common,
        payload=freeze_json(row["payload"]),
        projection_locator=ProjectionLocator(schema, None, digest),
        canonical_payload_digest=digest,
    )


def _records(name: str) -> tuple[LedgerRecord, ...]:
    document = _fixture(name)
    raw_input = cast(dict[str, Any], document["input"])
    rows = cast(list[dict[str, Any]], raw_input["accepted_entries"])
    return tuple(_record(row) for row in rows)


def _expected(name: str) -> dict[str, Any]:
    expected = cast(dict[str, Any], _fixture(name)["expected"])
    return cast(dict[str, Any], expected["final_projection"])


def test_session_events_advance_frontier_only() -> None:
    records = _records("all-event-families")
    state = replay(records[:1])
    assert state.frontier == 1
    assert state.head_digest == records[0].entry_digest
    assert not state.plans
    assert not state.obligations
    assert state.freshness.value == "current"


def test_replay_rejects_a_mid_chain_suffix_as_corrupt() -> None:
    """Replay is genesis-anchored by contract (issue #200).

    A suffix that starts past the genesis anchor is a corrupt projection, not a partial one, so a
    caller that reads only part of a task's chain — for example by filtering rows to one session —
    has to be fixed at the record-loading layer. Loosening this check instead would let a
    projection be built from an unverified chain.
    """

    records = _records("all-event-families")
    with pytest.raises(ValueError, match="projection_corrupt"):
        replay(records[1:])
    with pytest.raises(ValueError, match="projection_corrupt"):
        replay(records[3:5])


def test_plan_and_obligation_supersession() -> None:
    records = _records("supersession-redaction")
    state = replay(records)
    assert projection_digest(state) == _expected("supersession-redaction")["digest"]
    assert any(record.superseded_by_plan_version is not None for record in state.plans.values())
    assert any(record.plan_change is not None for record in state.obligations.values())


def test_assignment_decision_action_result_links() -> None:
    state = replay(_records("all-event-families")[:7])
    assert len(state.assignments) == 1
    assert len(state.decisions) == 1
    assert len(state.actions) == 1
    assert len(state.results) == 1
    assert not tuple(marker for marker in state.coverage_gaps if marker.startswith("missing_ref:"))


def test_evidence_claim_response_redaction_paths() -> None:
    state = replay(_records("all-event-families")[:14])
    assert len(state.evidence) == 1
    assert len(state.claims) == 1
    assert len(state.responses) == 1
    evidence = next(iter(state.evidence.values()))
    assert evidence.redacted is True
    assert "redacted_event:evt_20000002-0000-4000-8000-000000000008" in state.coverage_gaps
    assert "redacted_object:obj_20000002-0000-4000-8000-000000000900" in state.coverage_gaps


def test_finding_event_subject_ref_outside_prefix_does_not_overflow_projection_gaps() -> None:
    records = list(_records("all-event-families"))
    finding = next(
        record
        for record in records
        if type(record) is AcceptedEvent and record.schema.name == "finding_recorded"
    )
    assert finding.payload is not None
    from finishup.domain.events import encode_payload
    from finishup.protocol.canonical import canonical_digest

    phantom = event_id("evt_40000000-0000-4000-8000-0000000000aa")
    payload = replace(finding.payload, subject_refs=(phantom,))
    records[records.index(finding)] = replace(
        finding,
        payload=payload,
        projection_locator=replace(
            finding.projection_locator,
            canonical_payload_digest=canonical_digest(encode_payload(payload)),
        ),
    )
    state = replay(tuple(records))
    assert not any(marker.startswith("missing_ref:") for marker in state.coverage_gaps)


def test_finding_check_receipt_records() -> None:
    records = _records("all-event-families")
    before_redaction = replay(records[:13])
    assert len(before_redaction.findings) == 1
    assert before_redaction.latest_tested_state is not None
    assert before_redaction.latest_tested_state.returned_finding_ids
    assert before_redaction.latest_tested_state.suppressed_count == 0
    final = replay(records)
    assert projection_digest(final) == _expected("all-event-families")["digest"]


def test_unknown_event_preserves_gap_metadata() -> None:
    state = replay(_records("unknown-schema"))
    assert state.unknown_event_count == 1
    assert any(marker.startswith("unknown_event:") for marker in state.coverage_gaps)
    assert projection_digest(state) == _expected("unknown-schema")["digest"]


@pytest.mark.parametrize(
    "fixture_name",
    (
        "empty",
        "all-event-families",
        "multi-writer",
        "page-size-equivalence",
        "projection-rebuild",
        "supersession-redaction",
        "unknown-schema",
        "wall-clock-reversal",
    ),
)
def test_all_reviewed_replay_fixtures_match_generation_one_digest(
    fixture_name: str,
) -> None:
    assert projection_digest(replay(_records(fixture_name))) == _expected(fixture_name)["digest"]


def test_each_transition_uses_exact_prefix_replay_index() -> None:
    records = _records("all-event-families")
    fixture_expected = cast(dict[str, Any], _fixture("all-event-families")["expected"])
    checkpoints = cast(list[dict[str, Any]], fixture_expected["projection_checkpoints"])
    state = replay(())
    index = empty_replay_index()
    assert projection_digest(state) == checkpoints[0]["incremental_replay_digest"]
    for record, checkpoint in zip(records, checkpoints[1:], strict=True):
        previous_state = state
        previous_index = index
        index = extend_replay_index(index, record)
        state = reduce_event(state, record, index)
        assert projection_digest(state) == checkpoint["incremental_replay_digest"]
        assert state.frontier == previous_state.frontier + 1
        assert index.frontier == previous_index.frontier + 1

    future_index = index
    with pytest.raises(ValueError, match="projection_corrupt"):
        reduce_event(replay(records[:1]), records[1], future_index)


@pytest.mark.parametrize(
    "fixture_name",
    ("all-event-families", "supersession-redaction", "unknown-schema"),
)
def test_replay_extension_matches_genesis_replay_for_mixed_prefixes(fixture_name: str) -> None:
    records = _records(fixture_name)
    expected = replay(records)
    for split in sorted({0, len(records) // 2, len(records)}):
        prior_records = records[:split]
        extended = replay_extension(replay(prior_records), prior_records, records[split:])
        assert extended == expected


@pytest.mark.parametrize(
    "fixture_name",
    ("all-event-families", "supersession-redaction", "unknown-schema"),
)
def test_replay_index_can_be_reused_after_full_or_extension_replay(fixture_name: str) -> None:
    records = _records(fixture_name)
    expected_projection, expected_index = replay_with_index(records)
    sequential_index = empty_replay_index()
    for record in records:
        sequential_index = extend_replay_index(sequential_index, record)
    assert build_replay_index(records) == sequential_index
    validate_replay_index(expected_index, records)
    assert expected_projection == replay(records)

    split = len(records) // 2
    extended_projection, extended_index = replay_extension_with_index(
        replay(records[:split]),
        records[:split],
        records[split:],
    )
    assert extended_projection == expected_projection
    assert extended_index == expected_index


@pytest.mark.parametrize("mismatch", ("payload", "evidence", "redaction", "observation"))
def test_replay_index_validation_rejects_same_frontier_with_wrong_maps(mismatch: str) -> None:
    records = _records("all-event-families")
    _projection, index = replay_with_index(records)
    payloads = dict(index.payload_event_by_object)
    evidence = dict(index.evidence_sources_by_object)
    roots = dict(index.redaction_root_by_object)
    observation_findings = index.observation_finding_event_ids
    if mismatch == "payload":
        objects = tuple(payloads)
        payloads[objects[0]], payloads[objects[1]] = payloads[objects[1]], payloads[objects[0]]
    elif mismatch == "evidence":
        object_key = next(iter(evidence))
        evidence[object_key] = ()
    elif mismatch == "redaction":
        object_key = next(iter(roots))
        roots[object_key] = next(
            event.event_id for event in records if event.event_id != roots[object_key]
        )
    else:
        # A cooperative finding record claimed as observation-authored would let the fold keep a
        # check attributable across a response it must treat as material (issue #911).
        observation_findings = observation_findings | {
            next(event.event_id for event in records if event.schema.name == "finding_recorded")
        }
    corrupt = ReplayIndex(
        frontier=index.frontier,
        head_digest=index.head_digest,
        payload_event_by_object=payloads,
        evidence_sources_by_object=evidence,
        redaction_root_by_object=roots,
        observation_finding_event_ids=observation_findings,
        observed_event_ids=index.observed_event_ids,
    )
    with pytest.raises(ValueError, match="projection_corrupt"):
        validate_replay_index(corrupt, records)


@pytest.mark.parametrize("bad_prefix", ("duplicate", "missing_genesis"))
def test_linear_replay_index_builder_rejects_malformed_chain(bad_prefix: str) -> None:
    records = _records("all-event-families")
    malformed = (records[0], records[0]) if bad_prefix == "duplicate" else records[1:]
    with pytest.raises(ValueError, match="projection_corrupt"):
        build_replay_index(malformed)


def test_object_only_redaction_resolves_both_envelope_associations() -> None:
    records = _records("supersession-redaction")
    original = replay(records)
    redaction = next(
        cast(AcceptedEvent, record)
        for record in records
        if record.schema.name == "redaction_recorded"
    )
    event_targets = frozenset(redaction.projection_locator.redaction_target_event_ids)
    object_targets = frozenset(redaction.projection_locator.redaction_target_object_ids)
    payload_owners = {record.payload_ref.object_id: record.event_id for record in records}
    effective_targets = event_targets | frozenset(
        payload_owners[target] for target in object_targets if target in payload_owners
    )
    deleted = tuple(
        replace(record, payload=None)
        if type(record) is AcceptedEvent and record.event_id in effective_targets
        else record
        for record in records
    )
    rebuilt = replay(deleted)
    assert projection_digest(rebuilt) == projection_digest(original)
    assert rebuilt == original


def test_payload_unavailable_does_not_invent_redaction_marker() -> None:
    records = _records("projection-rebuild")
    action = next(
        record
        for record in records
        if type(record) is AcceptedEvent and record.schema.name == "action_recorded"
    )
    unavailable = tuple(
        replace(record, payload=None) if record is action else record for record in records
    )
    state = replay(unavailable)
    projected_action = next(iter(state.actions.values()))
    assert projected_action.payload is None
    assert projected_action.redacted is True
    assert not any(marker.startswith("redacted_") for marker in state.coverage_gaps)


def test_repeated_object_redaction_keeps_first_cause_root() -> None:
    document = _fixture("all-event-families")
    raw_input = cast(dict[str, Any], document["input"])
    rows = cast(list[dict[str, Any]], raw_input["accepted_entries"])
    repeated = deepcopy(
        next(
            row
            for row in rows
            if cast(dict[str, Any], cast(dict[str, Any], row["envelope"])["schema"])["name"]
            == "redaction_recorded"
        )
    )
    envelope = cast(dict[str, Any], repeated["envelope"])
    last_envelope = cast(dict[str, Any], rows[-1]["envelope"])
    writer = cast(dict[str, Any], envelope["writer"])
    ledger = cast(dict[str, Any], envelope["ledger"])
    payload_ref = cast(dict[str, Any], envelope["payload_ref"])
    envelope["event_id"] = "evt_20000002-0000-4000-8000-000000000011"
    envelope["operation_id"] = "req_20000002-0000-4000-8000-000000000011"
    envelope["occurred_at"] = "2026-03-02T00:00:17.000Z"
    envelope["causal_parents"] = [last_envelope["event_id"]]
    writer["sequence"] = "2"
    writer["previous_entry_digest"] = cast(dict[str, Any], rows[13]["envelope"])["entry_digest"]
    ledger["ingestion_sequence"] = "17"
    ledger["previous_entry_digest"] = last_envelope["entry_digest"]
    ledger["accepted_at"] = "2026-03-02T00:16:57.000Z"
    payload_ref["object_id"] = "obj_20000002-0000-4000-8000-000000100011"
    preimage = deepcopy(envelope)
    preimage.pop("entry_digest")
    envelope["entry_digest"] = entry_digest(cast(CanonicalJsonValue, freeze_json(preimage)))
    second = _record(repeated)

    records = (*_records("all-event-families"), second)
    index = empty_replay_index()
    for record in records:
        index = extend_replay_index(index, record)
    target = object_id("obj_20000002-0000-4000-8000-000000000900")
    assert index.redaction_root_by_object[target] == event_id(
        "evt_20000002-0000-4000-8000-00000000000e"
    )
    state = replay(records)
    assert state.coverage_gaps.count(f"redacted_object:{target}") == 1


def test_replay_index_is_frozen_and_nonplaintext() -> None:
    assert tuple(field.name for field in fields(ReplayIndex)) == (
        "frontier",
        "head_digest",
        "payload_event_by_object",
        "evidence_sources_by_object",
        "redaction_root_by_object",
        "observation_finding_event_ids",
        "observed_event_ids",
        "first_task_statement_sequence",
    )
    assert tuple(field.name for field in fields(EvidenceObjectSource)) == (
        "evidence_id",
        "source_event_id",
    )
    index = empty_replay_index()
    assert type(index.payload_event_by_object).__name__ == "mappingproxy"
    # Provenance ids only: which accepted events are hook-observed actions or results (#909).
    assert index.observed_event_ids == frozenset()
    with pytest.raises(TypeError):
        cast(dict[object, object], index.payload_event_by_object)[
            object_id("obj_00000000-0000-4000-8000-000000000099")
        ] = _records("all-event-families")[0].event_id


def test_missing_evidence_index_association_is_projection_corruption() -> None:
    records = _records("all-event-families")
    state = replay(records[:7])
    index = empty_replay_index()
    for record in records[:8]:
        index = extend_replay_index(index, record)
    assert index.evidence_sources_by_object
    corrupt = ReplayIndex(
        frontier=index.frontier,
        head_digest=index.head_digest,
        payload_event_by_object=index.payload_event_by_object,
        evidence_sources_by_object={},
        redaction_root_by_object=index.redaction_root_by_object,
        observation_finding_event_ids=index.observation_finding_event_ids,
        observed_event_ids=index.observed_event_ids,
    )
    with pytest.raises(ValueError, match="projection_corrupt"):
        reduce_event(state, records[7], corrupt)


def _check_with_partial_coverage(
    records: tuple[LedgerRecord, ...],
    *,
    returned: tuple[Any, ...] | None = None,
) -> tuple[LedgerRecord, ...]:
    """Rewrite the fixture's ``check_recorded`` to the coverage a gap-declaring check records.

    ``application/check.py`` downgrades a check's own ``ledger_freshness`` to ``partial`` when the
    check declares a coverage gap — a declined AI-powered review, for instance. No reviewed replay
    fixture carries such a check, so the projection's handling of one is rewritten here rather
    than by editing a frozen fixture. ``returned`` overrides the check's returned findings, which
    is what decides whether the fixture's later response supersedes it.
    """

    from finishup.domain.events import encode_payload
    from finishup.protocol.canonical import canonical_digest

    rewritten: list[LedgerRecord] = []
    for record in records:
        if record.schema.name != "check_recorded":
            rewritten.append(record)
            continue
        accepted = cast(AcceptedEvent, record)
        payload = cast(Any, accepted.payload)
        coverage = replace(
            payload.coverage,
            ledger_freshness=LedgerFreshness.PARTIAL,
            known_gaps=("semantic_review_not_requested",),
        )
        rewired = replace(payload, coverage=coverage)
        if returned is not None:
            rewired = replace(rewired, returned_finding_ids=returned)
        rewritten.append(
            replace(
                accepted,
                payload=rewired,
                projection_locator=replace(
                    accepted.projection_locator,
                    canonical_payload_digest=canonical_digest(encode_payload(rewired)),
                ),
            )
        )
    return tuple(rewritten)


def test_retained_check_freshness_outlives_the_event_that_recorded_it() -> None:
    """Issue #307: the projection scalar reported a gap-declaring check's ``partial`` freshness
    only while folding the check itself and reverted to ``current`` on the next event of any
    family, while ``latest_tested_state.coverage`` kept the gaps. One status item then carried two
    disagreeing freshness fields.

    The retained check governs the scalar for as long as it is the retained check, so the scalar
    is now a function of carried state rather than of which event happens to be folding.
    """

    records = _check_with_partial_coverage(_records("all-event-families"))
    families = tuple(record.schema.name for record in records)
    assert families[10] == "check_recorded"
    # The response answers a finding the check itself returned, so it never supersedes the check;
    # the receipt's family is not material at all. Neither may clear the recorded gaps.
    assert families[11:13] == ("response_recorded", "receipt_recorded")

    at_check = replay(records[:11])
    assert at_check.latest_tested_state is not None
    assert at_check.latest_tested_state.coverage.ledger_freshness is LedgerFreshness.PARTIAL
    assert at_check.freshness is LedgerFreshness.PARTIAL

    for through in (12, 13):
        later = replay(records[:through])
        retained = later.latest_tested_state
        assert retained is not None, f"the check must still be retained at {through}"
        assert retained.coverage.ledger_freshness is LedgerFreshness.PARTIAL
        # The scalar and the retained check's own coverage are one fact, so they cannot diverge.
        assert later.freshness is retained.coverage.ledger_freshness


def test_material_change_still_outranks_a_retained_partial_check() -> None:
    """Carrying the check's freshness must not mask supersession: material work published after a
    ``partial`` check leaves the ledger stale, which is the stronger statement about the same
    check and the one the receipt applicability rule already makes.

    The fixture's ``response_recorded`` answers a finding the check returned, which is the one
    material-family record that deliberately does not supersede. Pointing the check at a different
    finding makes that same record work the check never covered.
    """

    records = _check_with_partial_coverage(
        _records("all-event-families"),
        returned=(finding_id("fnd_20000002-0000-4000-8000-0000000001ff"),),
    )
    assert records[11].schema.name == "response_recorded"
    superseded = replay(records[:12])
    assert superseded.freshness is LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE
    # The retained check is untouched; the scalar reports the newer, stronger fact about it.
    assert superseded.latest_tested_state is not None
    assert superseded.latest_tested_state.coverage.ledger_freshness is LedgerFreshness.PARTIAL


def test_redacting_a_partial_check_clears_its_carried_freshness() -> None:
    """A redaction that removes the check removes what the scalar was reporting. The projection
    drops ``latest_tested_state``, so the carried ``partial`` goes with it and the redaction's own
    marker governs instead of a value with no surviving check behind it.
    """

    records = _check_with_partial_coverage(_records("all-event-families"))
    assert records[13].schema.name == "redaction_recorded"
    redacted = replay(records[:14])
    assert redacted.freshness is LedgerFreshness.REDACTED_GAP
