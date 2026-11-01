"""``decision_recorded`` 1.1.0: the task's review-mode switch (ADR-049)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Final, cast

import pytest

from finishup.domain.events import (
    DECISION_REVIEW_MODE_SCHEMA_VERSION,
    DecisionRecordedPayload,
    EventSchema,
    ReviewMode,
    decode_payload,
    encode_payload,
)
from finishup.domain.values import JsonObject, actor_id
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import PublishWorkRequest
from finishup.protocol.schemas import validate_schema_instance

_REPO: Final = Path(__file__).resolve().parents[3]
_JSON_FENCE: Final = re.compile(r"```json\n(?P<body>.*?)\n```", re.DOTALL)
_SWITCH: Final[JsonObject] = JsonObject(
    {
        "statement": "Turn on AI-powered review for the rest of this task.",
        "rationale": "Cross-module change that local checks cannot judge.",
        "authority": "harness:mcp-template",
        "review_mode": "ai_powered",
    }
)


def test_the_switch_rides_1_1_0_and_round_trips() -> None:
    assert DECISION_REVIEW_MODE_SCHEMA_VERSION == "1.1.0"
    schema = EventSchema("decision_recorded", "1.1.0")
    decoded = decode_payload(schema, _SWITCH)
    assert type(decoded) is DecisionRecordedPayload
    assert decoded.review_mode is ReviewMode.AI_POWERED
    assert encode_payload(decoded) == _SWITCH
    validate_schema_instance("decision-recorded", "1.1.0", _SWITCH)


def test_1_1_0_requires_the_switch_and_1_0_0_refuses_it() -> None:
    plain = JsonObject({key: value for key, value in _SWITCH.items() if key != "review_mode"})
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("decision_recorded", "1.1.0"), plain)
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("decision_recorded", "1.0.0"), _SWITCH)
    # A plain decision keeps its released 1.0.0 bytes.
    released = decode_payload(EventSchema("decision_recorded", "1.0.0"), plain)
    assert type(released) is DecisionRecordedPayload
    assert released.review_mode is None
    assert encode_payload(released) == plain


def test_only_the_two_closed_modes_decode() -> None:
    with pytest.raises(ProtocolValueError):
        decode_payload(
            EventSchema("decision_recorded", "1.1.0"),
            JsonObject({**_SWITCH, "review_mode": "semantic"}),
        )


def test_the_payload_type_carries_the_mode_as_a_closed_enum() -> None:
    payload = DecisionRecordedPayload(
        statement="s",
        rationale="r",
        authority=actor_id("harness:agent"),
        review_mode=ReviewMode.LOCAL,
    )
    assert payload.review_mode is ReviewMode.LOCAL
    with pytest.raises(ProtocolValueError):
        DecisionRecordedPayload(
            statement="s",
            rationale="r",
            authority=actor_id("harness:agent"),
            review_mode=cast(Any, "local"),
        )


def _drafts_from(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    blocks = [json.loads(match.group("body")) for match in _JSON_FENCE.finditer(text)]
    drafts: list[dict[str, Any]] = []
    for block in blocks:
        if "event_drafts" in block:
            drafts.extend(block["event_drafts"])
        elif "schema" in block and "payload" in block:
            drafts.append(block)
    return [
        draft
        for draft in drafts
        if draft["schema"] == {"name": "decision_recorded", "version": "1.1.0"}
    ]


def test_the_guidance_switch_is_the_exact_valid_draft() -> None:
    """``review.md`` shows the one draft an agent sends; it must be the template's draft."""

    (review_draft,) = _drafts_from(_REPO / "guidance" / "review.md")
    (template_draft,) = _drafts_from(_REPO / "guidance" / "request-templates.md")
    assert review_draft == template_draft
    validate_schema_instance("decision-recorded", "1.1.0", review_draft["payload"])
    decoded = decode_payload(EventSchema("decision_recorded", "1.1.0"), review_draft["payload"])
    assert type(decoded) is DecisionRecordedPayload
    assert decoded.review_mode is ReviewMode.AI_POWERED
    request = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000014",
        "session_id": "ses_00000000-0000-4000-8000-000000000001",
        "writer_id": "wri_00000000-0000-4000-8000-000000000001",
        "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
        "event_drafts": [review_draft],
        "actor": {"actor_id": "harness:mcp-template", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }
    PublishWorkRequest.model_validate(request)
