"""check-result 1.5.0 admits the pre-edit deferral reason; 1.4.0 still refuses it."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError
from tests.unit.protocol.test_models_and_schemas import (
    _check_result_wire,  # pyright: ignore[reportPrivateUsage]
)

from finishup.application.check import (
    _skipped_review_reason,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.receipts import (
    DEFERRED_BEFORE_FIRST_EDIT_TEXT,
    review_deferred_before_first_edit,
)
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.models import CheckRequest, CheckResult, SemanticReason
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures/canonical/deferred-before-first-edit-1.5.0.case.json"
)
_RECORDED = Path(__file__).resolve().parents[3] / "schemas/events/check-recorded-1.4.0.schema.json"
_RECORDED_NEXT = (
    Path(__file__).resolve().parents[3] / "schemas/events/check-recorded-1.5.0.schema.json"
)
_STATUS = Path(__file__).resolve().parents[3] / "schemas/operations/status-result-1.4.0.schema.json"
_SENTENCE = "AI-powered review is on; it starts after your first edit."


def _vectors() -> list[dict[str, Any]]:
    fixture = cast(dict[str, Any], json.loads(_FIXTURE.read_bytes()))
    assert fixture["fixture_id"] == "CAN-021"
    return cast(list[dict[str, Any]], fixture["input"]["vectors"])


def _instance(payload: dict[str, Any]) -> dict[str, Any]:
    base = cast(dict[str, Any], json.loads(json.dumps(_check_result_wire())))
    base.update(payload)
    return base


def _admits(version: str, instance: dict[str, Any]) -> bool:
    try:
        validate_schema_instance("check-result", version, instance)
        schema_ok = True
    except SchemaInstanceInvalid:
        schema_ok = False
    try:
        CheckResult.model_validate(instance)
        model_ok = True
    except ValidationError:
        model_ok = False
    # The current model is the 1.5.0 contract. 1.4.0 is schema-only.
    if version == "1.5.0":
        assert schema_ok == model_ok, instance["semantic_reason"]
    return schema_ok


@pytest.mark.parametrize("vector", _vectors(), ids=lambda vector: str(vector["vector_id"]))
def test_vectors_are_canonical(vector: dict[str, Any]) -> None:
    payload = cast(dict[str, Any], vector["payload"])
    assert canonical_encode(payload).hex() == vector["canonical_hex"]
    assert canonical_digest(payload) == vector["digest"]
    instance = _instance(payload)
    assert _admits("1.5.0", instance) is vector["admitted"]


def test_older_check_result_still_reads_the_local_only_reason_and_refuses_the_new_one() -> None:
    by_id = {vector["vector_id"]: vector for vector in _vectors()}
    deferred = _instance(
        cast(dict[str, Any], by_id["not_requested_deferred_before_first_edit"]["payload"])
    )
    local_only = _instance(
        cast(dict[str, Any], by_id["not_requested_deterministic_mode"]["payload"])
    )
    assert _admits("1.4.0", local_only) is True
    assert _admits("1.4.0", deferred) is False
    assert _admits("1.5.0", deferred) is True
    assert _admits("1.5.0", local_only) is True


def test_check_recorded_1_5_is_the_only_event_schema_that_names_the_reason() -> None:
    previous = json.loads(_RECORDED.read_text(encoding="utf-8"))
    current = json.loads(_RECORDED_NEXT.read_text(encoding="utf-8"))
    previous_enum = previous["properties"]["semantic_reason"]["enum"]
    current_enum = current["properties"]["semantic_reason"]["enum"]
    assert "deferred_before_first_edit" not in previous_enum
    assert "deterministic_mode" in previous_enum
    assert "deferred_before_first_edit" in current_enum
    assert "deterministic_mode" in current_enum
    previous_reasons = [
        branch["properties"]["semantic_reason"]["const"]
        for branch in previous["$defs"]["semantic_binding"]["oneOf"]
    ]
    current_reasons = [
        branch["properties"]["semantic_reason"]["const"]
        for branch in current["$defs"]["semantic_binding"]["oneOf"]
    ]
    assert "deferred_before_first_edit" not in previous_reasons
    assert "deferred_before_first_edit" in current_reasons


def test_new_check_schema_titles_use_the_product_name() -> None:
    """ADR-048: a new schema's prose title says FinishUP; released titles and $id stay."""

    result_previous = (
        Path(__file__).resolve().parents[3] / "schemas/operations/check-result-1.4.0.schema.json"
    )
    result_next = (
        Path(__file__).resolve().parents[3] / "schemas/operations/check-result-1.5.0.schema.json"
    )
    recorded = json.loads(_RECORDED.read_text(encoding="utf-8"))
    recorded_next = json.loads(_RECORDED_NEXT.read_text(encoding="utf-8"))
    previous = json.loads(result_previous.read_text(encoding="utf-8"))
    current = json.loads(result_next.read_text(encoding="utf-8"))
    assert recorded["title"] == "Yoetz check recorded 1.4.0"
    assert recorded_next["title"] == "FinishUP check recorded 1.5.0"
    assert previous["title"] == "Yoetz check result 1.4.0"
    assert current["title"] == "FinishUP check result 1.5.0"
    assert recorded_next["$id"].startswith("https://schemas.yoetz.dev/0.1/")
    assert current["$id"].startswith("https://schemas.yoetz.dev/0.1/")


def test_status_job_terminal_reason_does_not_admit_the_check_deferral() -> None:
    """The status terminal-reason enum is the durable job code, not the check outcome."""

    status = json.loads(_STATUS.read_text(encoding="utf-8"))
    terminal = status["$defs"]["semantic_progress"]["properties"]["terminal_reason"]["enum"]
    assert "deferred_before_first_edit" not in terminal
    assert "deterministic_mode" in terminal


def test_skipped_review_reason_splits_deferral_from_a_local_only_stop() -> None:
    deferred = CheckRequest.model_construct(mode="semantic_required")
    assert (
        _skipped_review_reason(deferred, round_stopped=True, deferred_before_first_edit=True)
        is SemanticReason.DEFERRED_BEFORE_FIRST_EDIT
    )
    stopped = CheckRequest.model_construct(mode="semantic_required")
    assert (
        _skipped_review_reason(stopped, round_stopped=True, deferred_before_first_edit=False)
        is SemanticReason.ROUND_LIMIT_UNASSESSABLE
    )
    local = CheckRequest.model_construct(mode="deterministic_only")
    assert (
        _skipped_review_reason(local, round_stopped=False, deferred_before_first_edit=False)
        is SemanticReason.DETERMINISTIC_MODE
    )
    reviewing = CheckRequest.model_construct(mode="semantic_required")
    assert (
        _skipped_review_reason(reviewing, round_stopped=False, deferred_before_first_edit=False)
        is None
    )


def test_prose_uses_the_exact_sentence_for_the_new_reason_and_the_older_gap() -> None:
    assert DEFERRED_BEFORE_FIRST_EDIT_TEXT == _SENTENCE
    assert review_deferred_before_first_edit("deferred_before_first_edit", ())
    assert review_deferred_before_first_edit(
        "deterministic_mode", ("semantic_review_deferred_before_first_edit",)
    )
    assert not review_deferred_before_first_edit("deterministic_mode", ())


def test_check_recorded_1_5_admits_exactly_the_deferred_check_written_on_it() -> None:
    """The writer records 1.5.0 for the deferral alone; that event, and no other pair, validates."""

    from dataclasses import replace

    from tests.unit.kernel import test_receipt_builder as receipt_test

    from finishup.domain.events import CheckMode, EventSchema, decode_payload, encode_payload
    from finishup.domain.findings import CheckVerdict
    from finishup.domain.values import JsonValue as DomainJsonValue
    from finishup.protocol.models import SemanticStatus

    deferred = replace(
        receipt_test._check(  # pyright: ignore[reportPrivateUsage]
            CheckVerdict.INSUFFICIENT_COVERAGE,
            receipt_test._coverage(),  # pyright: ignore[reportPrivateUsage]
        ),
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.NOT_REQUESTED,
        semantic_reason=SemanticReason.DEFERRED_BEFORE_FIRST_EDIT,
    )
    body = cast(dict[str, Any], json.loads(canonical_encode(encode_payload(deferred))))
    # The writer's version rule.
    decode_payload(EventSchema("check_recorded", "1.5.0"), cast(DomainJsonValue, body))
    validate_schema_instance("check-recorded", "1.5.0", body)
    for change in (
        {"semantic_conclusion": "no_material_discrepancy"},
        {"semantic_reason": "deterministic_mode"},
        {"semantic_status": "unavailable", "semantic_reason": "round_limit_unassessable"},
    ):
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("check-recorded", "1.5.0", {**body, **change})
    # Neither 1.4.0 nor the reviewer's 1.6.0 carries a deferral.
    for version in ("1.4.0", "1.6.0"):
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("check-recorded", version, body)
