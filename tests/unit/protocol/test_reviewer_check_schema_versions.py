"""#1118 R7: the reviewer record rides only check-recorded and check-result 1.6.0.

The integration first added ``reviewer`` in place to check-recorded 1.4.0/1.5.0 and check-result
1.5.0. Those schemas are closed, so a reader of the earlier bytes of those versions refused the
field: the in-place change broke unreleased prerelease readers. The record now has new versions,
the earlier documents are byte-identical to before, and their readers still refuse the field.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError
from tests.unit.kernel import test_receipt_builder as receipt_test
from tests.unit.protocol.test_check_continuation_branch import (
    _check_outcome,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.protocol.test_models_and_schemas import (
    _check_result_wire,  # pyright: ignore[reportPrivateUsage]
    _semantic_provenance_for,  # pyright: ignore[reportPrivateUsage]
    _semantic_provenance_wire,  # pyright: ignore[reportPrivateUsage]
    _status_result_wire,  # pyright: ignore[reportPrivateUsage]
)

from finishup.domain.events import (
    REVIEWER_CHECK_EVENT_SCHEMA_VERSION,
    CheckMode,
    EventPayload,
    EventSchema,
    decode_payload,
    encode_payload,
)
from finishup.domain.findings import CheckVerdict
from finishup.domain.receipts import SchemaVersionEntry, receipt_document_to_json
from finishup.domain.reviewer_reads import reviewer_record_from_wire
from finishup.domain.values import (
    JsonObject,
    freeze_json,
    receipt_id,
    session_id,
    task_id,
    timestamp_from_string,
)
from finishup.domain.values import JsonValue as DomainJsonValue
from finishup.kernel.receipt_builder import build_receipt
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import (
    CheckResult,
    ChildFindingSnapshotModel,
    ReceiptInclude,
    ReceiptRedactionProfile,
    SemanticReason,
    SemanticStatus,
    validate_semantic_provenance_binding,
)
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from unit.application import test_undeclared_names_never_egress as named_checks

_ROOT = Path(__file__).resolve().parents[3]
_FIXTURE = _ROOT / "fixtures/canonical/check-reviewer-record-1.6.0.case.json"
# SHA-256 of each document as it stood before the reviewer integration (7bd8eb2fe).
_FROZEN = {
    "schemas/events/check-recorded-1.4.0.schema.json": (
        "57544bb1480c906a8edfbcbeafe9976f9ce31755ee613b95b268e748973fba1a"
    ),
    "schemas/events/check-recorded-1.5.0.schema.json": (
        "6aa755d7038c695fa4929f26ef2386f95a7a325bedca367650a965e4d5ffcd4b"
    ),
    "schemas/operations/check-result-1.4.0.schema.json": (
        "9fcd3c474fdcb5caf2d5e8e6e814ec3bc3152b173f9a4fb65d633ccc46b62e17"
    ),
    "schemas/operations/check-result-1.5.0.schema.json": (
        "d03e8a3fd92b1f239a0aae66f691f65b863efda492016a518187b2144a09fd6c"
    ),
}


def _decode(version: str, body: dict[str, Any]) -> EventPayload:
    return decode_payload(EventSchema("check_recorded", version), cast(DomainJsonValue, body))


def _vectors() -> list[dict[str, Any]]:
    fixture = cast(dict[str, Any], json.loads(_FIXTURE.read_bytes()))
    assert fixture["fixture_id"] == "CHK-160"
    return cast(list[dict[str, Any]], fixture["input"]["vectors"])


def _event_body() -> dict[str, Any]:
    """A schema-valid check-recorded 1.4.0 body (review output, no reviewer record)."""

    row, _digest = named_checks._check_row(with_names=True)  # pyright: ignore[reportPrivateUsage]
    return cast(dict[str, Any], json.loads(canonical_encode(row.payload)))


def test_requested_but_stopped_pair_has_no_new_provider_attempt_and_uses_1_6() -> None:
    fixture = json.loads(_FIXTURE.read_bytes())
    pair = fixture["input"]["stopped_review"]
    event = _event_body()
    event.update(pair)
    event.pop("semantic_provenance", None)
    event.pop("semantic_conclusion", None)
    event.pop("semantic_included_refs", None)
    validate_schema_instance("check-recorded", "1.6.0", event)
    payload = _decode("1.6.0", event)
    encoded = encode_payload(payload)
    assert isinstance(encoded, Mapping)
    assert encoded["semantic_reason"] == "round_limit_unassessable"
    result = _check_result_wire()
    result.update(pair)
    result["semantic_provenance"] = None
    validate_schema_instance("check-result", "1.6.0", result)
    CheckResult.model_validate(result)
    for version in ("1.4.0", "1.5.0"):
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("check-recorded", version, event)
        with pytest.raises(ProtocolValueError):
            _decode(version, event)


@pytest.mark.parametrize("path", sorted(_FROZEN))
def test_earlier_check_schemas_are_byte_identical_to_before_the_reviewer(path: str) -> None:
    assert hashlib.sha256((_ROOT / path).read_bytes()).hexdigest() == _FROZEN[path]
    document = json.loads((_ROOT / path).read_text(encoding="utf-8"))
    assert "reviewer_record" not in document.get("$defs", {})


@pytest.mark.parametrize("version", ("1.4.0", "1.5.0", "1.6.0"))
def test_decision_findings_start_at_check_result_1_6(version: str) -> None:
    instance = _check_result_wire()
    finding = cast(list[dict[str, Any]], instance["findings"])[0]
    finding.update(
        kind="decision_needed",
        origin="semantic_model_derived",
        priority=3,
        provenance=_semantic_provenance_wire(),
    )
    if version == "1.6.0":
        validate_schema_instance("check-result", version, instance)
        CheckResult.model_validate(instance)
    else:
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("check-result", version, instance)


def test_child_snapshot_preserves_a_non_actionable_decision() -> None:
    body = {
        "finding_id": "fnd_10000000-0000-4000-8000-000000000001",
        "kind": "decision_needed",
        "origin": "semantic_model_derived",
        "priority": 3,
        "actionable": False,
        "resolved": False,
    }
    snapshot = ChildFindingSnapshotModel.model_validate(body)
    assert snapshot.kind == "decision_needed" and not snapshot.actionable
    for invalid in ({"priority": 2}, {"actionable": True}):
        with pytest.raises(ValidationError):
            ChildFindingSnapshotModel.model_validate({**body, **invalid})


@pytest.mark.parametrize("vector", _vectors(), ids=lambda vector: str(vector["vector_id"]))
def test_reviewer_vectors_are_canonical_and_decode(vector: dict[str, Any]) -> None:
    payload = cast(dict[str, Any], vector["payload"])
    assert canonical_encode(payload).hex() == vector["canonical_hex"]
    assert canonical_digest(payload) == vector["digest"]
    assert vector["admitted_versions"] == ["1.6.0"]
    record = reviewer_record_from_wire(payload)
    assert record is not None and record.as_wire() == payload


@pytest.mark.parametrize("vector", _vectors(), ids=lambda vector: str(vector["vector_id"]))
def test_check_recorded_admits_the_reviewer_only_on_1_6(vector: dict[str, Any]) -> None:
    body = {**_event_body(), "reviewer": vector["payload"]}
    for version in cast(list[str], vector["refused_versions"]):
        # The decoder refuses the field exactly as a pre-integration reader of that version did.
        with pytest.raises(ProtocolValueError) as refused:
            _decode(version, body)
        assert str(refused.value) == "unknown_payload_field"
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("check-recorded", version, body)
    decoded = _decode(REVIEWER_CHECK_EVENT_SCHEMA_VERSION, body)
    validate_schema_instance("check-recorded", "1.6.0", body)
    assert canonical_encode(encode_payload(decoded)) == canonical_encode(body)


def test_check_recorded_1_6_requires_the_reviewer_and_older_bytes_still_replay() -> None:
    body = _event_body()
    _decode("1.4.0", body)
    with pytest.raises(ProtocolValueError):
        _decode("1.6.0", body)
    check = receipt_test._check(  # pyright: ignore[reportPrivateUsage]
        CheckVerdict.INSUFFICIENT_COVERAGE,
        receipt_test._coverage(),  # pyright: ignore[reportPrivateUsage]
    )
    reviewer = cast(JsonObject, freeze_json(_vectors()[0]["payload"]))
    with_reviewer = replace(check, reviewer=reviewer)
    encoded = cast(dict[str, Any], json.loads(canonical_encode(encode_payload(with_reviewer))))
    with pytest.raises(ProtocolValueError):
        _decode("1.5.0", encoded)
    _decode("1.6.0", encoded)


@pytest.mark.parametrize("vector", _vectors(), ids=lambda vector: str(vector["vector_id"]))
def test_check_result_admits_the_reviewer_only_on_1_6(vector: dict[str, Any]) -> None:
    instance = {**cast(dict[str, Any], json.loads(json.dumps(_check_result_wire())))}
    validate_schema_instance("check-result", "1.5.0", instance)
    instance["reviewer"] = vector["payload"]
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("check-result", "1.5.0", instance)
    validate_schema_instance("check-result", "1.6.0", instance)
    try:
        CheckResult.model_validate(instance)
    except ValidationError as error:  # pragma: no cover - the current model is the 1.6.0 contract
        raise AssertionError(error) from error


def test_new_reviewer_schemas_use_the_product_name() -> None:
    for path, title in (
        ("schemas/events/check-recorded-1.6.0.schema.json", "FinishUP check recorded 1.6.0"),
        ("schemas/operations/check-result-1.6.0.schema.json", "FinishUP check result 1.6.0"),
    ):
        document = json.loads((_ROOT / path).read_text(encoding="utf-8"))
        assert document["title"] == title
        assert document["$id"] == "https://schemas.yoetz.dev/0.1/" + path.removeprefix("schemas/")


def test_correctness_advisory_rows_use_1_6_and_keep_original_concern() -> None:
    fixture = json.loads(_FIXTURE.read_bytes())
    concern = fixture["input"]["correctness_advisory"]
    body = _event_body()
    body["correctness_advisories"] = [concern]
    validate_schema_instance("check-recorded", "1.6.0", body)
    decoded = _decode("1.6.0", body)
    assert (
        json.loads(canonical_encode(encode_payload(decoded)))["correctness_advisories"][0]
        == concern
    )
    malformed_ref: dict[str, Any] = {
        **body,
        "correctness_advisories": [{**concern, "subject_refs": ["evt_" + "a" * 36]}],
    }
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("check-recorded", "1.6.0", malformed_ref)
    for version in ("1.4.0", "1.5.0"):
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("check-recorded", version, body)
        with pytest.raises(ProtocolValueError):
            _decode(version, body)


def test_tracked_advice_rows_carry_a_closed_origin_on_1_6_and_the_check_result() -> None:
    """#1162 tracked advice: the golden rows validate on check-recorded and check-result 1.6.0."""

    from finishup.adapters.providers.openai_responses import normalize_judgment
    from finishup.domain.correctness_advisories import validate_advisories

    tracked = json.loads(_FIXTURE.read_bytes())["input"]["tracked_advice"]
    body = _event_body()
    body["correctness_advisories"] = tracked["check_recorded_rows"]
    validate_schema_instance("check-recorded", "1.6.0", body)
    decoded = _decode("1.6.0", body)
    assert (
        json.loads(canonical_encode(encode_payload(decoded)))["correctness_advisories"]
        == tracked["check_recorded_rows"]
    )
    validate_advisories(
        tuple(cast(JsonObject, freeze_json(row)) for row in tracked["check_recorded_rows"])
    )
    invented: dict[str, Any] = {
        **body,
        "correctness_advisories": [{**tracked["check_recorded_rows"][0], "origin": "invented"}],
    }
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("check-recorded", "1.6.0", invented)
    instance = {**cast(dict[str, Any], json.loads(json.dumps(_check_result_wire())))}
    instance["correctness_advisories"] = [tracked["check_result_row"]]
    for version in ("1.6.0", "1.7.0"):
        validate_schema_instance("check-result", version, instance)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("check-result", "1.5.0", instance)
    CheckResult.model_validate(instance)
    judgment = normalize_judgment(
        {
            "conclusion": "no_material_discrepancy",
            "review_summary": "Checked.",
            "verified": [],
            "reviewer_challenges": [],
            "prior_finding_verdicts": [],
            "strongest_remaining_check": tracked["provider_strongest_remaining_check"],
        },
        require_part2=True,
    )
    assert judgment.strongest_remaining_check is not None
    assert (
        judgment.strongest_remaining_check.check
        == (tracked["provider_strongest_remaining_check"]["check"])
    )


def test_declared_test_verdict_rows_carry_their_digest_on_1_6_and_the_check_result() -> None:
    """#1145: the golden verdict rows decode, and the advisory row they become validates."""

    from finishup.adapters.providers.openai_responses import normalize_judgment
    from finishup.domain.correctness_advisories import validate_advisories

    vector = json.loads(_FIXTURE.read_bytes())["input"]["declared_test_advice"]
    body = _event_body()
    body["correctness_advisories"] = [vector["check_recorded_row"]]
    validate_schema_instance("check-recorded", "1.6.0", body)
    decoded = _decode("1.6.0", body)
    assert json.loads(canonical_encode(encode_payload(decoded)))["correctness_advisories"] == [
        vector["check_recorded_row"]
    ]
    validate_advisories((cast(JsonObject, freeze_json(vector["check_recorded_row"])),))
    instance = {**cast(dict[str, Any], json.loads(json.dumps(_check_result_wire())))}
    instance["correctness_advisories"] = [vector["check_result_row"]]
    for version in ("1.6.0", "1.7.0"):
        validate_schema_instance("check-result", version, instance)
    CheckResult.model_validate(instance)
    judgment = normalize_judgment(
        {
            "conclusion": "no_material_discrepancy",
            "review_summary": "Checked.",
            "verified": [],
            "reviewer_challenges": [],
            "prior_finding_verdicts": [],
            "declared_test_verdicts": vector["provider_declared_test_verdicts"],
        },
        require_part2=True,
    )
    assert [row.test_ref for row in judgment.declared_test_verdicts] == ["dt1", "dt2"]


def test_advisory_decisions_are_typed_and_never_switch_review_mode() -> None:
    from finishup.domain.events import EventSchema, decode_payload

    fixture = json.loads(_FIXTURE.read_bytes())
    body: Any = {
        "statement": "Correctness advisory disposition (agent-reported; non-blocking).",
        "rationale": "Retained the approximation with an explicit limitation.",
        "authority": "harness:test",
        "advisory_response": fixture["input"]["advisory_response"],
    }
    validate_schema_instance("decision-recorded", "1.1.0", body)
    decision = decode_payload(EventSchema("decision_recorded", "1.1.0"), body)
    assert decision.review_mode is None  # type: ignore[union-attr]
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("decision-recorded", "1.0.0", body)
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("decision_recorded", "1.0.0"), body)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("decision-recorded", "1.1.0", {**body, "review_mode": "local"})
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance(
            "decision-recorded",
            "1.1.0",
            {
                **body,
                "advisory_response": {
                    **body["advisory_response"],
                    "evidence_refs": ["evd_" + "a" * 36],
                },
            },
        )


def test_check_recorded_1_6_admits_a_review_refused_at_the_privacy_boundary() -> None:
    """#1138: a privacy-blocked check names its ``review_blocked`` item, which only 1.6.0 admits."""

    from finishup.protocol.redacted_values import SemanticRedactedValue

    body = _event_body()
    for name in ("semantic_provenance", "semantic_conclusion", "semantic_included_refs"):
        body.pop(name, None)
    body["semantic_status"] = "blocked_forbidden_data"
    body["semantic_reason"] = "never_send_detected"
    body["semantic_redacted_values"] = [
        SemanticRedactedValue(
            "excerpt-evd_10000000-0000-4000-8000-000000000001",
            "review_blocked",
            (),
            None,
            "reviewer_exchange",
            "heuristic",
        ).as_wire()
    ]
    validate_schema_instance("check-recorded", "1.6.0", body)
    assert canonical_encode(encode_payload(_decode("1.6.0", body))) == canonical_encode(body)
    # A refusal composes no conclusion, and the pair stays exact.
    for change in (
        {"semantic_conclusion": "no_material_discrepancy"},
        {"semantic_reason": "secret_detected"},
    ):
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("check-recorded", "1.6.0", {**body, **change})


# #1118: every outcome a reviewer conversation can end on without a conclusion. Its first exchange
# may be refused at the privacy or policy boundary or by the owner, or any exchange may meet a
# provider failure, a capacity refusal (the read-exchange-full exit), a coordinator failure or an
# exhausted retry budget. ``run_reviewer`` keeps the conversation's record on each, so the check
# records the pair beside its reviewer record, which only check-recorded 1.6.0 carries.
_UNCONCLUDED_OUTCOMES = (
    ("approval_expired", "human_approval_expired"),
    ("blocked_by_policy", "channel_disabled"),
    ("blocked_by_policy", "content_category_not_authorized"),
    ("blocked_by_policy", "network_egress_denied"),
    ("blocked_by_policy", "provider_binding_not_authorized"),
    ("blocked_by_policy", "scope_not_authorized"),
    ("blocked_forbidden_data", "never_send_detected"),
    ("classification_uncertain", "classification_uncertain"),
    ("failed", "case_capacity_exceeded"),
    ("failed", "coordinator_failure"),
    ("human_denied", "human_denied"),
    ("invalid", "response_content_invalid"),
    ("invalid", "response_schema_invalid"),
    ("late", "deadline_authority_lost"),
    ("refused", "provider_refused"),
    ("timeout", "provider_timeout"),
    ("unavailable", "audit_reservation_unavailable"),
    ("unavailable", "outcome_unknown"),
    ("unavailable", "provider_quota_exhausted"),
    ("unavailable", "provider_rate_limited"),
    ("unavailable", "receipt_persistence_unknown"),
    ("unavailable", "retry_budget_exhausted"),
    ("unavailable", "transport_unavailable"),
)


def _needs_provenance(status: SemanticStatus, reason: SemanticReason) -> bool:
    """Whether the closed binding requires the final attempt's provenance beside this pair."""

    try:
        validate_semantic_provenance_binding(status, reason, None, None)
    except ProtocolValueError:
        return True
    return False


def _unconcluded_event(status: SemanticStatus, reason: SemanticReason) -> EventPayload:
    """The check event the check path records for this outcome, with the reviewer record."""

    provenance = (
        replace(receipt_test._provenance(), status=status, reason=reason)  # pyright: ignore[reportPrivateUsage]
        if _needs_provenance(status, reason)
        else None
    )
    return replace(
        receipt_test._check(  # pyright: ignore[reportPrivateUsage]
            CheckVerdict.INSUFFICIENT_COVERAGE,
            receipt_test._coverage(),  # pyright: ignore[reportPrivateUsage]
        ),
        mode=CheckMode.SEMANTIC_IF_CONFIGURED,
        semantic_status=status,
        semantic_reason=reason,
        semantic_provenance=provenance,
        reviewer=cast(JsonObject, freeze_json(_vectors()[0]["payload"])),
    )


@pytest.mark.parametrize(("status", "reason"), _UNCONCLUDED_OUTCOMES)
def test_a_review_that_ended_without_a_conclusion_records_with_its_reviewer(
    status: str, reason: str
) -> None:
    """#1118: each such outcome validates on every contract that carries it."""

    event = _unconcluded_event(SemanticStatus(status), SemanticReason(reason))
    body = cast(dict[str, Any], json.loads(canonical_encode(encode_payload(event))))
    assert "reviewer" in body and "semantic_conclusion" not in body
    # The writer's version rule puts it on 1.6.0, whose schema now admits it.
    decoded = _decode(REVIEWER_CHECK_EVENT_SCHEMA_VERSION, body)
    validate_schema_instance("check-recorded", "1.6.0", body)
    assert canonical_encode(encode_payload(decoded)) == canonical_encode(body)

    result = cast(dict[str, Any], json.loads(json.dumps(_check_result_wire())))
    result.pop("semantic_conclusion", None)
    result.update(
        semantic_status=status,
        semantic_reason=reason,
        semantic_provenance=(
            _semantic_provenance_for(status, reason) if "semantic_provenance" in body else None
        ),
        reviewer=body["reviewer"],
    )
    validate_schema_instance("check-result", "1.7.0", result)
    CheckResult.model_validate(result)

    outcome = _check_outcome()
    for name in ("semantic_conclusion", "missing_for_assessment"):
        outcome.pop(name)
    outcome.update(semantic_status=status, semantic_reason=reason)
    page = _status_result_wire()
    page["view"] = "operation"
    page["page"] = {
        "operation_request_id": page["request_id"],
        "found": True,
        "state": "complete",
        "operation_kind": "check",
        "check_outcome": cast(Any, outcome),
        "accepted_events": [],
        "continuation": None,
        "next_cursor": None,
        "outcome": None,
        "result_frontier": None,
        "subject_frontier": None,
    }
    validate_schema_instance("status-result", "1.5.0", page)

    # The receipt carries no pair for it (only the attempt's provenance, when there is one).
    receipt = build_receipt(
        receipt_test._context(  # pyright: ignore[reportPrivateUsage]
            check=cast(Any, event),
            coverage=receipt_test._coverage(),  # pyright: ignore[reportPrivateUsage]
        ),
        receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
        task_id("tsk_00000000-0000-4000-8000-000000000001"),
        session_id("ses_00000000-0000-4000-8000-000000000001"),
        timestamp_from_string("2026-07-19T00:00:00.000Z"),
        replace(
            receipt_test._versions(),  # pyright: ignore[reportPrivateUsage]
            schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        ),
        ReceiptRedactionProfile.FULL_LOCAL,
        ReceiptInclude.FULL,
    )
    wire = receipt_document_to_json(receipt)
    assert "semantic_status" not in wire
    validate_schema_instance("receipt-document", "1.3.0", cast(Any, wire))


@pytest.mark.parametrize(("status", "reason"), _UNCONCLUDED_OUTCOMES)
def test_an_unconcluded_review_still_refuses_a_conclusion(status: str, reason: str) -> None:
    """Only a completed review composes a conclusion; the stopped and refused pairs stay exact."""

    body = cast(
        dict[str, Any],
        json.loads(
            canonical_encode(
                encode_payload(_unconcluded_event(SemanticStatus(status), SemanticReason(reason)))
            )
        ),
    )
    validate_schema_instance("check-recorded", "1.6.0", body)
    for conclusion in ("no_material_discrepancy", "challenges_returned", "insufficient_packet"):
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance(
                "check-recorded", "1.6.0", {**body, "semantic_conclusion": conclusion}
            )


@pytest.mark.parametrize(
    ("status", "reason"),
    (
        # Decided before any conversation runs, or (a rejected judgment) recorded without it.
        ("awaiting_human", "human_approval_required"),
        ("blocked_by_policy", "route_semantic_ceiling"),
        ("blocked_forbidden_data", "secret_detected"),
        ("invalid", "semantic_judgment_rejected"),
        ("late", "lease_authority_lost"),
        ("stale", "frontier_changed"),
        ("unavailable", "credential_unavailable"),
    ),
)
def test_check_recorded_1_6_admits_no_other_outcome_beside_a_reviewer(
    status: str, reason: str
) -> None:
    body = cast(
        dict[str, Any],
        json.loads(
            canonical_encode(
                encode_payload(_unconcluded_event(SemanticStatus(status), SemanticReason(reason)))
            )
        ),
    )
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("check-recorded", "1.6.0", body)
