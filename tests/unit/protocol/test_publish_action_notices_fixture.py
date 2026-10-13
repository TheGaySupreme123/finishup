"""Golden vectors for the publish-time action notices (tb4n5 follow-up, fixture CAN-018).

The generator ``scripts/generate_publish_action_notices_fixture.py`` owns the bytes and the
resource ripple checks them; this test reads the committed vectors and admits each exactly as
frozen against the closed publish-work-result 1.1.0 schema and the public result model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from yoetz.mcp.summaries import render_publish_action_notices
from yoetz.protocol.canonical import canonical_digest, canonical_encode
from yoetz.protocol.models import (
    MAX_EVENTS_PER_BATCH,
    PUBLISH_ACTION_NOTICE_TEXTS,
    PublishWorkResultModel,
)
from yoetz.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures/canonical/publish-action-notices-1.1.0.case.json"
)


def _vectors() -> list[dict[str, Any]]:
    fixture = cast(dict[str, Any], json.loads(_FIXTURE.read_bytes()))
    assert fixture["fixture_id"] == "CAN-018"
    return cast(list[dict[str, Any]], fixture["input"]["vectors"])


@pytest.mark.parametrize("vector", _vectors(), ids=lambda vector: str(vector["vector_id"]))
def test_vectors_are_canonical_and_admitted_exactly_as_frozen(vector: dict[str, Any]) -> None:
    payload = cast(dict[str, Any], vector["payload"])
    assert canonical_encode(payload).hex() == vector["canonical_hex"]
    assert canonical_digest(payload) == vector["digest"]
    try:
        validate_schema_instance("publish-work-result", "1.1.0", payload)
        schema_ok = True
    except SchemaInstanceInvalid:
        schema_ok = False
    try:
        PublishWorkResultModel.model_validate(payload)
        model_ok = True
    except ValidationError:
        model_ok = False
    assert schema_ok is vector["schema_admitted"]
    assert model_ok is vector["admitted"]


def test_a_full_batch_names_every_action_and_paired_batches_carry_no_field() -> None:
    by_id = {str(vector["vector_id"]): vector for vector in _vectors()}
    for vector_id in ("success_full_batch_every_notice", "dry_run_full_batch_every_notice"):
        rows = by_id[vector_id]["payload"]["action_notices"]
        assert len(rows) == MAX_EVENTS_PER_BATCH
        assert {row["text"] for row in rows} == {PUBLISH_ACTION_NOTICE_TEXTS["result_not_linked"]}
    assert "action_notices" not in by_id["success_all_paired_absent"]["payload"]
    rendered = render_publish_action_notices(by_id["success_one_unpaired"]["payload"])
    assert rendered.startswith("Action notice for act_")
