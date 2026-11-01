import json
from pathlib import Path

import pytest

from finishup.protocol.canonical import canonical_digest
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance


def test_host_connection_golden_plan_is_bound_and_rejects_observed_claim() -> None:
    root = Path(__file__).resolve().parents[3]
    plan = json.loads((root / "fixtures/integrations/host-connection.case.json").read_bytes())[
        "plan"
    ]
    validate_schema_instance("host-connection", "1.0.0", plan)
    assert plan["preview_digest"] == canonical_digest(
        {key: value for key, value in plan.items() if key != "preview_digest"}
    )
    plan["connection_observed"] = True
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("host-connection", "1.0.0", plan)
