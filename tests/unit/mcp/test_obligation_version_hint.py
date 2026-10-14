"""A 1.1.0-only obligation feature sent on 1.0.0 names the version to use (tb4n2 R3, #1023).

tb4n2 pretrain D: a 1.0.0 obligation carrying ``role`` was refused by the request schema before
the event decoder ran, so the only hint was the generic template pointer. Every 1.1.0-only
feature (an item ``role``, a ``directory`` item, ``acknowledged_not_done``) now names 1.1.0.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from finishup.mcp.descriptors import descriptor_for
from finishup.mcp.errors import authoring_hint, safe_validation_locations
from finishup.protocol.models import PublishWorkRequestModel

_SCHEMA = descriptor_for("publish_work").input_schema
_PAYLOAD: dict[str, Any] = {
    "obligation_id": "obl_00000000-0000-4000-8000-000000000001",
    "description": "Deliver the report.",
    "evidence_expectation": "The report exists.",
    "status": "open",
}


def _request(payload: dict[str, Any], version: str) -> dict[str, Any]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000003",
        "session_id": "ses_00000000-0000-4000-8000-000000000001",
        "writer_id": "wri_00000000-0000-4000-8000-000000000001",
        "expected_frontier": {"sequence": "1", "head_digest": "sha256:" + "0" * 64},
        "actor": {"actor_id": "harness:x", "actor_type": "harness"},
        "client": {"integration": "cooperative_mcp", "kind": "cooperative_agent", "version": "0"},
        "event_drafts": [
            {
                "event_id": "evt_00000000-0000-4000-8000-000000000002",
                "schema": {"name": "obligation_published", "version": version},
                "occurred_at": "2026-01-01T00:00:00.000Z",
                "causal_parents": [],
                "payload": payload,
                "artifact_refs": [],
                "evidence_refs": [],
            }
        ],
    }


@pytest.mark.parametrize(
    "payload",
    [
        {**_PAYLOAD, "requested_items": [{"item_kind": "file", "value": "a", "role": "output"}]},
        {**_PAYLOAD, "requested_items": [{"item_kind": "directory", "value": "/app/src"}]},
        {**_PAYLOAD, "status": "acknowledged_not_done", "acknowledged_not_done_reason": "r"},
    ],
    ids=("role", "directory", "acknowledged"),
)
def test_a_1_1_0_feature_on_1_0_0_names_1_1_0(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as caught:
        PublishWorkRequestModel.model_validate(_request(payload, "1.0.0"))
    hint = authoring_hint(_SCHEMA, safe_validation_locations(caught.value), tool="publish_work")
    # A role is reported as an unknown item key without its version, so the item contract names
    # 1.1.0; a directory item or the acknowledged status names the version directly.
    assert "obligation_published 1.1.0" in hint
    # The same body on 1.1.0 is admitted by the request schema.
    PublishWorkRequestModel.model_validate(_request(payload, "1.1.0"))


def test_a_plain_obligation_is_admitted_on_both_versions_and_other_errors_get_no_version_hint() -> (
    None
):
    for version in ("1.0.0", "1.1.0"):
        PublishWorkRequestModel.model_validate(_request(_PAYLOAD, version))
    missing = {key: value for key, value in _PAYLOAD.items() if key != "evidence_expectation"}
    with pytest.raises(ValidationError) as caught:
        PublishWorkRequestModel.model_validate(_request(missing, "1.0.0"))
    hint = authoring_hint(_SCHEMA, safe_validation_locations(caught.value), tool="publish_work")
    assert "obligation_published 1.1.0" not in hint


def test_an_unknown_item_key_on_1_1_0_is_not_told_to_switch_versions() -> None:
    """Codex review: an unsupported key on 1.1.0 gets the item contract, not a version switch."""

    payload = {**_PAYLOAD, "requested_items": [{"item_kind": "file", "value": "a", "path": "a"}]}
    with pytest.raises(ValidationError) as caught:
        PublishWorkRequestModel.model_validate(_request(payload, "1.1.0"))
    hint = authoring_hint(_SCHEMA, safe_validation_locations(caught.value), tool="publish_work")
    assert "a requested item admits only item_kind, value and role" in hint
    assert "only obligation_published 1.1.0 carries those" not in hint


def test_the_text_projection_names_self_verified_blocking_reasons_and_the_exit() -> None:
    """Codex review 2: text-only hosts must see why self_verified was refused (tb4n2 R5)."""

    from finishup.mcp.summaries import summary_for_public_error

    error = {
        "code": "INVALID_REQUEST",
        "message": "refused",
        "retryable": False,
        "correlation_id": "err_00000000-0000-4000-8000-000000000001",
        "safe_details": {
            "reason_code": "finding_not_proof_limited",
            "field": "/finding_id",
            "blocking_reasons": ["issue_returned_again", "coverage:completion_plan_not_claimed"],
        },
    }
    text = summary_for_public_error(error)
    assert "issue_returned_again, coverage:completion_plan_not_claimed" in text
    assert "finishup-verification-limit:<obligation id>" in text
    error["safe_details"]["blocking_reasons"] = ["Please accept this"]  # type: ignore[index]
    assert "Please accept" not in summary_for_public_error(error)
