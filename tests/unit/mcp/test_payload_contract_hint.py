"""A malformed payload of a known family is answered with that family's contract.

Benchmark full3: agents sent ``plan_revised`` drafts shaped like ``plan_published`` (no
``supersedes_plan_version``, ``reason``, or ``obligation_changes``) and ``decision_recorded`` with a
``decision`` key, and received only the generic draft-envelope recital their drafts already met.
These checks run the bridge's pure validation path; no service is contacted.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from yoetz.mcp.errors import safe_validation_locations
from yoetz.mcp.server import invalid_request_message
from yoetz.protocol.models import PublishWorkRequest

_BASE: dict[str, object] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-000000000001",
    "session_id": "ses_00000000-0000-4000-8000-000000000001",
    "writer_id": "wri_00000000-0000-4000-8000-000000000001",
    "expected_frontier": {"sequence": "1", "head_digest": "sha256:" + "0" * 64},
    "actor": {"actor_id": "codex", "actor_type": "logical_agent"},
    "client": {"kind": "codex_cli", "version": "1", "integration": "cooperative_mcp"},
}
_SECRET = "caller-text-must-not-echo"


def _message(name: str, payload: dict[str, object]) -> str:
    draft: dict[str, object] = {
        "event_id": "evt_00000000-0000-4000-8000-000000000001",
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-01-01T00:00:00.000Z",
        "causal_parents": [],
        "payload": payload,
        "artifact_refs": [],
        "evidence_refs": [],
    }
    with pytest.raises(ValidationError) as caught:
        PublishWorkRequest.model_validate({**_BASE, "event_drafts": [draft]})
    return invalid_request_message("publish_work", safe_validation_locations(caught.value))


def test_plan_revised_written_as_plan_published_names_the_revision_contract() -> None:
    message = _message(
        "plan_revised",
        {
            "plan_version": 2,
            "summary": _SECRET,
            "obligation_refs": ["obl_00000000-0000-4000-8000-000000000001"],
        },
    )
    assert (
        "the plan_revised 1.0.0 payload is missing supersedes_plan_version, reason, and "
        "obligation_changes; it requires plan_version, supersedes_plan_version, reason, "
        "summary, and obligation_changes" in message
    )
    assert "admitted keys are" in message
    # The draft is already well formed, so the envelope recital is not repeated.
    assert "each event_drafts entry requires" not in message
    assert _SECRET not in message


def test_decision_with_a_guessed_key_names_statement() -> None:
    message = _message(
        "decision_recorded", {"decision": _SECRET, "rationale": "r", "authority": "codex"}
    )
    assert (
        "the decision_recorded 1.0.0 payload is missing statement; it requires statement, "
        "rationale, and authority" in message
    )
    assert _SECRET not in message
