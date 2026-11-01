"""Fixture-backed idempotency and exact-frontier protocol conformance."""

from __future__ import annotations

from typing import Any, cast

import pytest
from pydantic import ValidationError

from finishup.protocol.canonical import JsonValue, request_digest
from finishup.protocol.models import FrontierModel
from fixture_loader import FixtureLoader


def _fixture(loader: FixtureLoader) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        loader.load_json("adversarial/ADV-007-crash-retry-duplicate.case.json"),
    )


def test_retry_same_identity_returns_same_public_result(fixture_loader: FixtureLoader) -> None:
    document = _fixture(fixture_loader)
    fixture_input = cast(dict[str, Any], document["input"])
    expected = cast(dict[str, Any], document["expected"])
    logical = cast(dict[str, Any], fixture_input["logical_request"])
    variants = cast(dict[str, dict[str, Any]], fixture_input["variants"])
    outcomes = cast(dict[str, dict[str, Any]], expected["variants"])

    digest = request_digest(cast(JsonValue, logical["canonical_request"]))
    assert digest == logical["request_digest"]
    for name in ("kill_before_commit", "kill_after_commit_before_response"):
        variant = variants[name]
        retry = cast(dict[str, Any], variant["retry"])
        outcome = outcomes[name]
        assert retry["request_id"] == variant["request_id"]
        assert retry["request_digest"] == digest
        assert outcome["retry"]["result"] == outcome["stable_result"]
        assert outcome["logical_event_count"] == 2
        assert outcome["no_partial_batch"] is True


def test_changed_identity_conflicts_under_same_request_id(
    fixture_loader: FixtureLoader,
) -> None:
    document = _fixture(fixture_loader)
    fixture_input = cast(dict[str, Any], document["input"])
    expected = cast(dict[str, Any], document["expected"])
    logical = cast(dict[str, Any], fixture_input["logical_request"])
    changed = cast(dict[str, Any], fixture_input["changed_logical_request"])
    variants = cast(dict[str, dict[str, Any]], fixture_input["variants"])
    conflict = variants["changed_request_same_key"]
    new_key = variants["new_key_changed_request"]

    logical_digest = request_digest(cast(JsonValue, logical["canonical_request"]))
    changed_digest = request_digest(cast(JsonValue, changed["canonical_request"]))
    assert logical_digest == logical["request_digest"]
    assert changed_digest == changed["request_digest"]
    assert logical_digest != changed_digest
    assert conflict["request_id"] == logical["canonical_request"]["request_id"]
    assert conflict["request_digest"] == changed_digest
    assert new_key["request_id"] != conflict["request_id"]
    assert new_key["request_digest"] == changed_digest
    error = cast(dict[str, Any], expected["variants"])["changed_request_same_key"]["error"]
    assert error == {"code": "REQUEST_IDENTITY_CONFLICT", "retryable": False}


def test_frontier_handling_matches_operation_contract(fixture_loader: FixtureLoader) -> None:
    document = _fixture(fixture_loader)
    fixture_input = cast(dict[str, Any], document["input"])
    expected = cast(dict[str, Any], document["expected"])
    entries = cast(list[dict[str, Any]], fixture_input["accepted_entries"])
    outcomes = cast(dict[str, dict[str, Any]], expected["variants"])
    observed = cast(dict[str, Any], entries[-1]["digest_preimage"])
    observed_ledger = cast(dict[str, Any], observed["ledger"])
    observed_frontier = {
        "sequence": observed_ledger["ingestion_sequence"],
        "head_digest": entries[-1]["entry_digest"],
    }

    current = FrontierModel.model_validate(observed_frontier)
    assert current.sequence == observed_frontier["sequence"]
    assert current.head_digest == observed_frontier["head_digest"]
    for name in ("kill_before_commit", "kill_after_commit_before_response"):
        result = cast(dict[str, Any], outcomes[name]["stable_result"])
        assert result["result_frontier"] == observed_frontier

    stale = FrontierModel.model_validate({"sequence": "1", "head_digest": "sha256:" + "1" * 64})
    assert stale != current
    with pytest.raises((ValidationError, ValueError)):
        FrontierModel.model_validate({"sequence": "0", "head_digest": current.head_digest})
    with pytest.raises((ValidationError, ValueError)):
        FrontierModel.model_validate({"sequence": current.sequence, "head_digest": "genesis"})
