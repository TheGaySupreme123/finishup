"""Manifest corrections locate schema names while keeping submitted text out of errors."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, cast

import pytest
from pydantic import ValidationError

from builders.publish_identity import bridge_bound
from finishup.mcp.descriptors import descriptor_for
from finishup.mcp.errors import authoring_hint, safe_validation_locations
from finishup.protocol.models import PublishWorkRequest


@pytest.mark.parametrize("bad_field", ["data_source", "cases"])
def test_manifest_error_locates_nested_field_without_echo(bad_field: str) -> None:
    schema = descriptor_for("publish_work").input_schema
    request = deepcopy(cast(list[dict[str, Any]], schema["examples"])[0])
    secret = "PRIVATE-criterion-and-value-never-echo"
    manifest: dict[str, Any] = {
        "criterion_quote": secret,
        "data_source": "independent",
        "cases": 1,
        "failing": 0,
    }
    if bad_field == "data_source":
        manifest[bad_field] = secret
    else:
        del manifest[bad_field]
    request["event_drafts"] = [
        {
            "schema": {"name": "result_recorded", "version": "1.1.0"},
            "payload": {
                "result_id": "res_00000000-0000-4000-8000-000000001170",
                "action_id": "act_00000000-0000-4000-8000-000000001170",
                "outcome": "success",
                "verification": manifest,
            },
        }
    ]
    with pytest.raises(ValidationError) as captured:
        PublishWorkRequest.model_validate(bridge_bound(request))
    locations = safe_validation_locations(captured.value)
    assert any(
        item["field"] == f"/event_drafts/0/payload/verification/{bad_field}" for item in locations
    ), locations
    assert secret not in repr(locations)
    assert secret not in authoring_hint(schema, locations)
