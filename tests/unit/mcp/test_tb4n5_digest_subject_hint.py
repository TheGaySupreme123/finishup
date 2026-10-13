"""The digest subject hint names the subset the evidence kind admits (tb4n5, issue #1049).

Five tb4n5 publishes were refused at ``digest_binding/subject`` and every refusal named the
property's whole nine-value union. Two agents then sent ``artifact_bytes`` - inside the union -
with ``evidence_kind: test_result``, whose branch admits four subjects, and were refused again.
These replay the five recorded shapes (a path, ``other``, ``artifact`` and ``artifact_bytes`` as
the subject of a ``test_result``) and check that every pair the hint suggests validates, that a
remaining independent defect is still the one reported, and that no caller value is echoed.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Final

import pytest
from pydantic import ValidationError

from yoetz.mcp.errors import safe_validation_locations
from yoetz.mcp.server import invalid_request_message
from yoetz.protocol.models import PublishWorkRequest

_SESSION: Final = "ses_00000000-0000-4000-8000-000000000001"
_WRITER: Final = "wri_00000000-0000-4000-8000-000000000001"
_HEAD: Final = "sha256:" + "1" * 64
_TEST_RESULT_SUBSET: Final = (
    "approved_check_receipt, static_analysis_report, test_report, test_stdout"
)
# The five recorded subjects (live-database S, medical D twice, medical S twice).
_RECORDED_SUBJECTS: Final = (
    "verification/differential.json",
    "other",
    "artifact_bytes",
    "artifact",
    "artifact_bytes",
)
_HINT_PAIR: Final = re.compile(r"([a-z_]+) admits ([a-z_, ]+)")


def _evidence(subject: str, kind: str = "test_result", *, tail: int = 1) -> dict[str, Any]:
    return {
        "event_id": f"evt_00000000-0000-4000-8000-{tail:012d}",
        "schema": {"name": "evidence_recorded", "version": "1.1.0"},
        "occurred_at": "2026-10-12T19:41:38.030Z",
        "causal_parents": [],
        "payload": {
            "evidence_id": f"evd_00000000-0000-4000-8000-{tail:012d}",
            "evidence_kind": kind,
            "strength": "content_digest",
            "content_digest": "sha256:" + "2" * 64,
            "digest_binding": {
                "subject": subject,
                "content_availability": "digest_only",
                "byte_count": 6140,
                "provenance": "caller_asserted",
            },
            "observed_at": "2026-10-12T19:41:38.030Z",
            "description": "Differential test output",
        },
        "artifact_refs": [],
        "evidence_refs": [],
    }


def _body(*drafts: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000001",
        "session_id": _SESSION,
        "writer_id": _WRITER,
        "expected_frontier": {"sequence": "12", "head_digest": _HEAD},
        "event_drafts": list(drafts),
        "actor": {"actor_id": "harness:test", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _message(body: dict[str, Any]) -> tuple[str, tuple[dict[str, str], ...]]:
    with pytest.raises(ValidationError) as caught:
        PublishWorkRequest.model_validate(body)
    locations = safe_validation_locations(caught.value)
    return invalid_request_message("publish_work", locations), locations


def _suggested_pairs(message: str) -> dict[str, tuple[str, ...]]:
    """``{evidence kind: subjects}`` the hint names, minus a subject a peer const constrains."""

    constrained = set(re.findall(r"([a-z_]+) needs provenance", message))
    pairs: dict[str, tuple[str, ...]] = {}
    lead = re.search(r"subject for evidence_kind ([a-z_]+) admits ([a-z_, ]+?)(?: \(|;|$)", message)
    assert lead is not None, message
    pairs[lead.group(1)] = tuple(item.strip() for item in lead.group(2).split(","))
    others = message.partition("(other evidence_kind values: ")[2].partition(")")[0]
    for kind, subjects in _HINT_PAIR.findall(others):
        pairs[kind] = tuple(item.strip() for item in subjects.split(","))
    return {
        kind: tuple(subject for subject in subjects if subject not in constrained)
        for kind, subjects in pairs.items()
    }


@pytest.mark.parametrize("subject", _RECORDED_SUBJECTS)
def test_a_refused_subject_names_the_test_result_subset_not_the_union(subject: str) -> None:
    message, locations = _message(_body(_evidence(subject)))

    assert locations[0]["field"] == "/event_drafts/0/payload/digest_binding/subject"
    assert f"subject for evidence_kind test_result admits {_TEST_RESULT_SUBSET}" in message
    # The whole union (which admits artifact_bytes) is no longer offered for this field.
    assert "subject admits approved_check_receipt, artifact_bytes" not in message
    assert "approved_check_receipt needs provenance approved_check" in message
    # The caller's own value never reaches the text.
    assert "verification/differential.json" not in message
    assert "Differential test output" not in message
    # The wire carries only the field and the reason; the branch facts ride for the hint alone.
    assert set(locations[0]) >= {"field", "reason"}


@pytest.mark.parametrize("subject", _RECORDED_SUBJECTS)
def test_every_suggested_kind_and_subject_pair_validates(subject: str) -> None:
    message, _locations = _message(_body(_evidence(subject)))
    pairs = _suggested_pairs(message)
    assert pairs["test_result"] == ("static_analysis_report", "test_report", "test_stdout")
    assert set(pairs) == {
        "test_result",
        "artifact",
        "command_output",
        "research_source",
        "other",
    } | ({"import_report"} if "import_report" in pairs else set())
    for kind, subjects in pairs.items():
        for suggested in subjects:
            if kind == "import_report":
                continue  # import evidence is import-observed only; its peer note names it
            PublishWorkRequest.model_validate(_body(_evidence(suggested, kind)))


def test_a_remaining_independent_defect_is_still_the_one_reported() -> None:
    """live-database S: after the subject, the batch's decision lacked ``authority``."""

    decision: dict[str, Any] = {
        "event_id": "evt_00000000-0000-4000-8000-000000000009",
        "schema": {"name": "decision_recorded", "version": "1.0.0"},
        "occurred_at": "2026-10-12T19:41:38.030Z",
        "causal_parents": [],
        "payload": {"statement": "Keep the cutover window.", "rationale": "It is measured."},
        "artifact_refs": [],
        "evidence_refs": [],
    }
    body = _body(_evidence("verification/differential.json"), decision)
    first, _ = _message(body)
    assert f"subject for evidence_kind test_result admits {_TEST_RESULT_SUBSET}" in first

    repaired = copy.deepcopy(body)
    repaired["event_drafts"][0]["payload"]["digest_binding"]["subject"] = "test_stdout"
    second, locations = _message(repaired)
    assert locations[0]["field"] == "/event_drafts/1/payload"
    assert "the decision_recorded 1.0.0 payload is missing authority" in second
    assert "evidence_kind" not in second


def test_without_a_selected_branch_the_hint_names_every_kind() -> None:
    """When no branch was named, the recipe states every kind's subset (and no union)."""

    message = invalid_request_message(
        "publish_work",
        (
            {
                "field": "/event_drafts/0/payload/digest_binding/subject",
                "reason": "invalid_type_or_value",
                "family": "evidence_recorded",
                "family_version": "1.1.0",
            },
        ),
    )
    assert "subject depends on evidence_kind: artifact admits artifact_bytes, bounded_excerpt" in (
        message
    )
    assert f"test_result admits {_TEST_RESULT_SUBSET}" in message
    assert "other admits bounded_excerpt" in message
    assert "subject admits approved_check_receipt, artifact_bytes" not in message
