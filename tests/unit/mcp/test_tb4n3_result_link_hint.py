"""tb4n3 N3-5: a result that names its action only by causal parent is told what links it.

pretrain D published ``result_recorded`` with the action's event as the causal parent and no
``action_id``; the whole batch was rejected with a bare ``invalid_type_or_value`` at the payload.
The wire contract is frozen (a result links by ``action_id``), so the rejection now says so.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from builders.projection_workflow import request_base
from builders.start_application import protocol_id
from finishup.mcp.errors import safe_validation_locations
from finishup.mcp.server import invalid_request_message
from finishup.protocol.models import PublishWorkRequest


def _request(payload: dict[str, object]) -> dict[str, object]:
    return {
        **request_base(protocol_id("req_", 7100)),
        "session_id": protocol_id("ses_", 7101),
        "writer_id": protocol_id("wri_", 7102),
        "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
        "event_drafts": [
            {
                "event_id": protocol_id("evt_", 7103),
                "schema": {"name": "result_recorded", "version": "1.0.0"},
                "occurred_at": "2026-09-28T12:10:00.000Z",
                "causal_parents": [protocol_id("evt_", 7104)],
                "payload": payload,
                "artifact_refs": [],
                "evidence_refs": [],
            }
        ],
    }


def test_a_result_without_action_id_is_told_that_a_causal_parent_does_not_link_it() -> None:
    with pytest.raises(ValidationError) as rejected:
        PublishWorkRequest.model_validate(
            _request({"result_id": protocol_id("res_", 7105), "outcome": "success"})
        )
    message = invalid_request_message("publish_work", safe_validation_locations(rejected.value))
    assert "action_id" in message
    assert "a causal parent alone does not link it" in message
    assert "not the action event's id" in message
