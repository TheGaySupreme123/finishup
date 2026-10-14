"""Support-command request bodies must satisfy the frozen control-request schema.

A body that omits a required field fails frame encoding inside the client, before anything is
sent, and the caller sees only a closed ``invalid_request`` naming no field. That is how
``privacy propose`` — and with it every policy widening, including the one ``privacy setup``
performs — stayed unusable: the body it built was missing the const ``schema_version``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from builders.privacy_policies import local_only_policy
from finishup.cli.app import (
    support_methods_carrying_schema_version,
    with_body_schema_version,
)
from finishup.domain.values import JsonObject
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_REPO = Path(__file__).resolve().parents[3]
_FROZEN_REQUEST_SCHEMA = _REPO / "schemas" / "service" / "control-request-1.0.0.schema.json"


def _frame(method: str, body: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "kind": "call",
        "protocol_version": "1.0",
        "rpc_id": "rpc_00000000-0000-4000-8000-000000000001",
        "service_instance_id": "svc_00000000-0000-4000-8000-000000000001",
        "service_generation": "1",
        "method": method,
        "body": cast(JsonValue, dict(body)),
    }


def test_derived_method_set_matches_the_frozen_schema() -> None:
    """The runtime set is read from the packaged schema; this reads the repository artifact."""

    document = cast(dict[str, Any], json.loads(_FROZEN_REQUEST_SCHEMA.read_text()))
    defs = cast(dict[str, Any], document["$defs"])
    expected: set[str] = set()
    for branch in cast(list[Any], document["oneOf"]):
        properties = cast(dict[str, Any], cast(dict[str, Any], branch).get("properties", {}))
        method_node = properties.get("method")
        body_node = properties.get("body")
        if not isinstance(method_node, dict) or not isinstance(body_node, dict):
            continue
        method = cast(dict[str, Any], method_node).get("const")
        reference = cast(dict[str, Any], body_node).get("$ref")
        if type(method) is not str or type(reference) is not str:
            continue
        # Workflow methods point at external operation schemas rather than a local $def; their
        # bodies are built from the owning pydantic model, which already carries schema_version.
        body = defs.get(reference.removeprefix("#/$defs/"))
        if not isinstance(body, dict):
            continue
        if "schema_version" in cast(list[str], cast(dict[str, Any], body).get("required", [])):
            expected.add(method)

    assert support_methods_carrying_schema_version() == frozenset(expected)
    assert "privacy_propose_policy" in expected
    # A body whose schema does not declare the field must not have one injected: the setup-wizard
    # contract closes over unevaluated properties, so an added key would be rejected outright.
    assert "privacy_get_setup" not in expected


def test_cli_fills_the_const_schema_version_and_never_overwrites_one() -> None:
    supplied = JsonObject({"expected_policy_digest": "sha256:" + "a" * 64})
    filled = with_body_schema_version("privacy_propose_policy", supplied)
    assert filled["schema_version"] == "1.0.0"
    assert filled["expected_policy_digest"] == supplied["expected_policy_digest"]

    untouched = JsonObject({"message_type": "begin"})
    assert with_body_schema_version("privacy_get_setup", untouched) == untouched

    # A caller that names a version keeps it, so a wrong one is still rejected downstream rather
    # than silently corrected into a request the caller did not write.
    explicit = JsonObject({"schema_version": "9.9.9"})
    assert with_body_schema_version("privacy_propose_policy", explicit)["schema_version"] == "9.9.9"


def test_propose_body_without_schema_version_fails_frame_validation() -> None:
    """Pins the failure mode, so the fix above is testing something real."""

    from finishup.adapters.privacy.catalog import encode_privacy_policy_json

    policy = encode_privacy_policy_json(local_only_policy())
    policy["schema_version"] = "1.0.0"
    body: dict[str, JsonValue] = {
        "expected_policy_digest": "sha256:" + "a" * 64,
        "candidate_policy": cast(JsonValue, policy),
    }
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance(
            "control-request", "1.0.0", cast(JsonValue, _frame("privacy_propose_policy", body))
        )

    validate_schema_instance(
        "control-request",
        "1.0.0",
        cast(JsonValue, _frame("privacy_propose_policy", {**body, "schema_version": "1.0.0"})),
    )


@pytest.mark.anyio
async def test_privacy_setup_propose_sends_a_body_the_frozen_schema_accepts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The interactive setup flow builds its own body; it must satisfy the same schema."""

    import finishup.cli.app as app_module
    from finishup.cli.privacy_setup import _propose  # pyright: ignore[reportPrivateUsage]

    sent: list[JsonObject] = []

    class _Client:
        async def privacy_propose_policy(self, request: JsonObject) -> JsonObject:
            sent.append(request)
            return JsonObject(
                {
                    "schema_version": "2.0.0",
                    "outcome": "decision_required",
                    "proposal_id": "ppr_00000000-0000-4000-8000-000000000001",
                }
            )

        async def close(self) -> None:
            return None

    async def _client(*_args: object, **_kwargs: object) -> object:
        return _Client()

    monkeypatch.setattr(app_module, "build_service_client", _client)

    policy = local_only_policy()
    proposal_id = await _propose(policy, policy.policy_digest)
    assert proposal_id == "ppr_00000000-0000-4000-8000-000000000001"
    assert len(sent) == 1
    validate_schema_instance(
        "control-request",
        "2.4.0",
        cast(JsonValue, _frame("privacy_propose_policy", sent[0])),
    )


@pytest.mark.parametrize("policy_version", ["1.0.0", "1.1.0"])
def test_current_control_accepts_saved_and_current_policy_versions(policy_version: str) -> None:
    from finishup.adapters.privacy.catalog import encode_privacy_policy_json

    policy = encode_privacy_policy_json(local_only_policy())
    policy["schema_version"] = policy_version
    body: dict[str, JsonValue] = {
        "schema_version": "2.0.0",
        "authority_digest": "sha256:" + "a" * 64,
        "candidate_policy": cast(JsonValue, policy),
    }
    validate_schema_instance(
        "control-request", "2.4.0", cast(JsonValue, _frame("privacy_propose_policy", body))
    )
