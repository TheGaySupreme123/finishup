"""The new change-identity field is bounded and additive only on the active control wire."""

from typing import Any, cast

import pytest

from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import validate_schema_instance
from fixture_loader import FixtureLoader


def test_change_identity_vectors(fixture_loader: FixtureLoader) -> None:
    document = cast(
        dict[str, Any], fixture_loader.load_json("observations/verification-freshness.case.json")
    )
    assert document["fixture_id"] == "FRESH-1143"
    for vector in document["input"]["vectors"]:
        request = vector["request"]
        assert canonical_digest(request) == vector["canonical_sha256"]
        assert len(canonical_encode(request)) == vector["byte_length"]
        if vector["valid"]:
            validate_schema_instance("control-request", "2.9.0", request)
        else:
            with pytest.raises(ProtocolValueError):
                validate_schema_instance("control-request", "2.9.0", request)
        structural = request["body"]["envelope"]["structural_payload"]
        if "workspace_changed_entries" in structural:
            with pytest.raises(ProtocolValueError):
                validate_schema_instance("control-request", "2.8.0", request)
