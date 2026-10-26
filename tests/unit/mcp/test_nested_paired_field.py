"""A nested pairing rule names itself instead of a generic error (issue #1226).

tq6: ``result_recorded`` 1.1.0 made ``test_file``, ``results_file`` and ``report_digest``
all-or-none and the nested ``dependentRequired`` failure surfaced as ``invalid_type_or_value``.
``test_file`` now stands alone (owner decision); the report pair still requires each other and
``test_file``, and a broken pair is ``paired_field_required`` with a hint in schema words only.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from finishup.mcp.descriptors import descriptor_for
from finishup.mcp.errors import authoring_hint, safe_validation_locations
from finishup.protocol.models import PublishWorkRequestModel
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_SCHEMA = descriptor_for("publish_work").input_schema
# Caller values that must never travel into a location, a reason or a hint.
_SENTINEL = "zz_caller_sentinel"
_DIGEST = "sha256:" + "a" * 64


def _payload(**verification: Any) -> dict[str, Any]:
    return {
        "result_id": "res_00000000-0000-4000-8000-000000000001",
        "action_id": "act_00000000-0000-4000-8000-000000000001",
        "outcome": "success",
        "verification": {
            "criterion_quote": f"{_SENTINEL} quote",
            "data_source": "unknown",
            "cases": 1,
            "failing": 0,
            **verification,
        },
    }


def _request(payload: dict[str, Any]) -> dict[str, Any]:
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
                "schema": {"name": "result_recorded", "version": "1.1.0"},
                "occurred_at": "2026-01-01T00:00:00.000Z",
                "causal_parents": [],
                "payload": payload,
                "artifact_refs": [],
                "evidence_refs": [],
            }
        ],
    }


def test_a_test_file_alone_and_the_full_triple_are_admitted() -> None:
    for verification in (
        {"test_file": f"{_SENTINEL}.py"},
        {"test_file": "t.py", "results_file": "r.json", "report_digest": _DIGEST},
    ):
        PublishWorkRequestModel.model_validate(_request(_payload(**verification)))
        validate_schema_instance("result-recorded", "1.1.0", _payload(**verification))


@pytest.mark.parametrize(
    ("verification", "missing", "sentences"),
    [
        (
            {"test_file": "t.py", "results_file": f"{_SENTINEL}.json"},
            ("report_digest",),
            (
                "verification.results_file requires report_digest; declare report_digest too,"
                " or omit verification.results_file",
            ),
        ),
        (
            {"test_file": "t.py", "report_digest": _DIGEST},
            ("results_file",),
            (
                "verification.report_digest requires results_file; declare results_file too,"
                " or omit verification.report_digest",
            ),
        ),
        (
            {"results_file": f"{_SENTINEL}.json"},
            ("test_file", "report_digest"),
            (
                "verification.results_file requires test_file and report_digest; declare"
                " test_file and report_digest too, or omit verification.results_file",
            ),
        ),
        (
            {"results_file": f"{_SENTINEL}.json", "report_digest": _DIGEST},
            ("test_file",),
            (
                "verification.report_digest requires test_file; declare test_file too, or omit"
                " verification.report_digest",
                "verification.results_file requires test_file; declare test_file too, or omit"
                " verification.results_file",
            ),
        ),
    ],
)
def test_a_broken_report_pair_is_named_from_schema_words_only(
    verification: dict[str, Any], missing: tuple[str, ...], sentences: tuple[str, ...]
) -> None:
    with pytest.raises(SchemaInstanceInvalid) as schema_error:
        validate_schema_instance("result-recorded", "1.1.0", _payload(**verification))
    assert schema_error.value.absolute_path == ("verification",)
    assert schema_error.value.reason == "paired_field_required"
    assert schema_error.value.missing_fields == missing

    with pytest.raises(ValidationError) as caught:
        PublishWorkRequestModel.model_validate(_request(_payload(**verification)))
    locations = safe_validation_locations(caught.value)
    assert [(item["field"], item["reason"]) for item in locations] == [
        ("/event_drafts/0/payload/verification", "paired_field_required")
    ]
    hint = authoring_hint(_SCHEMA, locations, tool="publish_work")
    for sentence in sentences:
        assert sentence in hint
    assert _SENTINEL not in repr(locations) and _SENTINEL not in hint
    assert "invalid_type_or_value" not in repr(locations)


def test_the_text_channel_states_the_pairing_only_for_the_manifest() -> None:
    """Text-only hosts get the fixed rule; another pointer or reason does not."""

    from finishup.mcp.summaries import summary_for_public_error

    def text(field: str, reason: str) -> str:
        return summary_for_public_error(
            {
                "code": "INVALID_REQUEST",
                "message": "refused",
                "retryable": False,
                "correlation_id": "err_00000000-0000-4000-8000-000000000001",
                "safe_details": {"fields": [field], "reasons": [reason]},
            }
        )

    rule = "test_file may stand alone; results_file and report_digest go together"
    named = text("/event_drafts/0/payload/verification", "paired_field_required")
    assert "paired_field_required at /event_drafts/0/payload/verification" in named
    assert rule in named
    assert rule not in text("/event_drafts/0/payload/verification", "invalid_type_or_value")
    assert rule not in text("/workspace_ref", "paired_field_required")
