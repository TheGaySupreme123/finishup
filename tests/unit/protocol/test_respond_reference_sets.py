"""``respond`` ``evidence_refs`` is a reference set (n7 RC3b, issue #1103).

n7 counted 53 respond calls refused because ``evidence_refs`` was not ASCII-sorted, after
``publish_work`` stopped asking for sorted sets; 17 agents cut their evidence to one id instead.
The request model now canonicalizes the set before the schema check, as publish does (#1084).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from finishup.mcp.errors import safe_validation_locations
from finishup.protocol.models import RespondRequest

_UUID = "00000000-0000-4000-8000-00000000000"
_FRONTIER = {"sequence": "3", "head_digest": "sha256:" + "0" * 64}
_LOW, _HIGH, _RESULT = f"evd_{_UUID}1", f"evd_{_UUID}2", f"res_{_UUID}1"


def _respond(**extra: object) -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": f"req_{_UUID}1",
        "session_id": f"ses_{_UUID}1",
        "writer_id": f"wri_{_UUID}1",
        "actor": {"actor_id": "codex", "actor_type": "logical_agent"},
        "client": {"kind": "codex_cli", "version": "1", "integration": "cooperative_mcp"},
        "expected_frontier": _FRONTIER,
        "finding_id": f"fnd_{_UUID}1",
        "finding_frontier": _FRONTIER,
        "disposition": "acknowledged",
        **extra,
    }


@pytest.mark.parametrize(
    "sent",
    [
        [_HIGH, _LOW],
        [_RESULT, _HIGH, _LOW],
        [_LOW, _HIGH, _LOW],
        (_HIGH, _HIGH, _LOW),
    ],
)
def test_respond_evidence_refs_are_sorted_and_deduplicated_before_the_schema_check(
    sent: list[str] | tuple[str, ...],
) -> None:
    request = RespondRequest.model_validate(_respond(evidence_refs=sent))
    expected = tuple(sorted(set(sent), key=lambda member: member.encode("ascii")))
    assert request.evidence_refs == expected
    canonical = RespondRequest.model_validate(_respond(evidence_refs=list(expected)))
    # One request: the JSON form the request digest hashes is identical.
    assert request.model_dump(mode="json") == canonical.model_dump(mode="json")


def test_a_canonical_set_is_left_as_sent() -> None:
    request = RespondRequest.model_validate(_respond(evidence_refs=[_LOW, _HIGH]))
    assert request.evidence_refs == (_LOW, _HIGH)
    assert RespondRequest.model_validate(_respond()).evidence_refs is None


@pytest.mark.parametrize(
    "sent",
    [
        [_HIGH, "not-an-id"],
        [_HIGH, f"clm_{_UUID}1"],
        [_HIGH, 3],
    ],
)
def test_a_non_id_member_keeps_its_exact_refusal(sent: list[object]) -> None:
    with pytest.raises(ValidationError) as caught:
        RespondRequest.model_validate(_respond(evidence_refs=sent))
    fields = {location["field"] for location in safe_validation_locations(caught.value)}
    assert fields and all(field.startswith("/evidence_refs") for field in fields)


def test_explicit_null_evidence_refs_is_still_refused() -> None:
    # Canonicalization hands ``null`` back untouched, so the optional-non-null rule still refuses it.
    with pytest.raises(ValidationError, match="optional_field_must_not_be_null"):
        RespondRequest.model_validate(_respond(evidence_refs=None))
