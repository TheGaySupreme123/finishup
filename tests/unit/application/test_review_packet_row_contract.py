"""The case/2 provider rows have an explicit, packaged boundary contract."""

# jsonschema exposes untyped validate(); the shared scenario builders are deliberate test seams.
# pyright: reportUnknownMemberType=false, reportPrivateUsage=false

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from finishup.application.semantic_case import (
    AGENT_DISCLOSURES_ITEM_ID,
    assemble_filtered_review_packet,
    bounded_case_envelope,
)
from finishup.protocol.canonical import strict_json_parse
from unit.application.test_review_follow_up import (
    _build,
    _excerpt_refs,
    _follow_up,
    _verification_case,
)
from unit.application.test_semantic_case_prior_findings import (
    _build as build_prior,
)
from unit.application.test_semantic_case_prior_findings import (
    _numba_case,
    _with_limit_decision,
)

_SCHEMA = (
    Path(__file__).resolve().parents[3] / "schemas/privacy/review-packet-row-2.0.0.schema.json"
)
_VECTOR = (
    Path(__file__).resolve().parents[3] / "fixtures/canonical/review-packet-rows-2.0.0.case.json"
)


def test_real_packet_rows_and_follow_up_markers_obey_the_boundary_contract() -> None:
    validator = Draft202012Validator(json.loads(_SCHEMA.read_bytes()))
    case, _refs = _verification_case(20)
    first = _build(case)
    second = _build(case, follow_up=_follow_up(case, _excerpt_refs(first)))
    marked = 0
    unmarked = 0
    for built in (first, second):
        envelope = strict_json_parse(bounded_case_envelope(built))
        assert isinstance(envelope, dict)
        content = {item.item_id: item.content for item in built.items}
        packet = strict_json_parse(
            assemble_filtered_review_packet(
                envelope, content_by_id=content, included_item_ids=frozenset(content)
            )
        )
        assert isinstance(packet, dict) and isinstance(packet["items"], list)
        for row in packet["items"]:
            validator.validate(row)
            assert isinstance(row, dict)
            marked += row.get("follow_up_supplied") is True
            unmarked += "follow_up_supplied" not in row
    assert marked > 0 and unmarked > 0


def test_packet_row_golden_vectors_cover_compatibility_and_partial_admission() -> None:
    validator = Draft202012Validator(json.loads(_SCHEMA.read_bytes()))
    vectors = json.loads(_VECTOR.read_bytes())["vectors"]
    assert {vector["name"] for vector in vectors} == {
        "legacy_absent",
        "follow_up_true",
        "partial_admission",
        "privacy_withheld",
    }
    for vector in vectors:
        for row in vector["rows"]:
            validator.validate(row)
    row = vectors[1]["rows"][0]
    with pytest.raises(ValidationError):
        validator.validate({**row, "follow_up_supplied": False})
    with pytest.raises(ValidationError):
        validator.validate({**row, "follow_up_supplied": "true"})


def test_the_agent_disclosures_row_obeys_the_row_contract() -> None:
    """n7 RC7 (#1108): the agent's disclosures travel in their own row, inside the closed row
    contract: section ``decision``, category ``obligation_text``, no new label."""

    validator = Draft202012Validator(json.loads(_SCHEMA.read_bytes()))
    built = build_prior(_with_limit_decision(_numba_case()))
    envelope = strict_json_parse(bounded_case_envelope(built))
    assert isinstance(envelope, dict)
    content = {item.item_id: item.content for item in built.items}
    packet = strict_json_parse(
        assemble_filtered_review_packet(
            envelope, content_by_id=content, included_item_ids=frozenset(content)
        )
    )
    assert isinstance(packet, dict) and isinstance(packet["items"], list)
    (row,) = (
        row
        for row in packet["items"]
        if isinstance(row, dict) and row.get("item_id") == AGENT_DISCLOSURES_ITEM_ID
    )
    validator.validate(row)
    assert row["section"] == "decision"
    assert row["category"] == "obligation_text"
    for other in packet["items"]:
        validator.validate(other)
