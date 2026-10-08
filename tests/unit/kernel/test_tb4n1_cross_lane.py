"""Cross-lane contracts of the tb4n1 remediation that no single lane could test alone.

- PL2-2 (L2 #982 -> L4 #984): the egress privacy gaps are standing Yoetz limits, so a finding the
  reviewer still sees only because Yoetz withheld or redacted packet content is answerable with
  ``respond self_verified``.
- Status-result 1.4.0 (L2 credential heuristic, L4 limitation refs and acknowledged count, L6
  obligation acknowledgement reason and directory/role items) carries every lane's addition in one
  document, and the packaged copy is byte-identical.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any, cast

import pytest

from yoetz.domain.findings import FindingOrigin
from yoetz.domain.receipts import (
    SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
)
from yoetz.kernel.closure_readiness import GAP_CLASSIFICATION, GapClass
from yoetz.kernel.self_verification import reasons_proof_limited

_PRIVACY_GAPS = (
    SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
    "semantic_review_value_redacted",
    "semantic_review_credential_heuristic_disabled",
)


@pytest.mark.parametrize("code", _PRIVACY_GAPS)
def test_egress_privacy_gaps_are_standing_limitations(code: str) -> None:
    assert GAP_CLASSIFICATION[code] is GapClass.STANDING_LIMITATION


@pytest.mark.parametrize("code", _PRIVACY_GAPS[:2])
def test_a_privacy_limited_review_finding_is_self_verifiable(code: str) -> None:
    # The reviewer still raises it, but its packet lacked the withheld item or value.
    reasons = ("reviewer_verdict_still_present", f"coverage:{code}")
    assert reasons_proof_limited(reasons, FindingOrigin.SEMANTIC_MODEL_DERIVED) is True
    # Without the privacy limit the same ruling is agent work, not a Yoetz limit.
    assert (
        reasons_proof_limited(
            ("reviewer_verdict_still_present",), FindingOrigin.SEMANTIC_MODEL_DERIVED
        )
        is False
    )


def _status_schema() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[3]
    source = (root / "schemas/operations/status-result-1.4.0.schema.json").read_bytes()
    packaged = (
        resources.files("yoetz")
        .joinpath("resources", "schemas", "operations", "status-result-1.4.0.schema.json")
        .read_bytes()
    )
    assert packaged == source
    return cast(dict[str, Any], json.loads(source))


def test_status_result_1_4_0_carries_every_lanes_addition() -> None:
    defs = _status_schema()["$defs"]
    # L2: the possible-credential filter pair, visible before any check.
    assert set(defs["success"]["properties"]["credential_heuristic"]["required"]) == {
        "machine_default",
        "repository",
    }
    # L4: required limitation ids (F3) and the acknowledged obligation count (#997).
    readiness = defs["closure_readiness"]["properties"]
    assert "limitation_refs_required" in readiness
    assert "acknowledged_obligation_count" in readiness
    # L6: the not-done marker row with its reason, and 1.1.0 requested items.
    obligation = defs["obligation_item"]["properties"]
    assert "acknowledged_not_done" in obligation["status"]["enum"]
    assert "acknowledged_not_done_reason" in obligation
    item = defs["status_requested_item"]["properties"]
    assert "directory" in item["item_kind"]["enum"]
    assert item["role"]["enum"] == ["input", "output"]
