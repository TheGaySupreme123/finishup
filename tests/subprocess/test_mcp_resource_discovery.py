"""The advertised resource surface must match what the server actually serves.

The 2026-07-27 Codex dogfood recorded
``codex_core::tools::router: resources/list failed for 'yoetz': Unexpected response type`` and the
postmortem attributed it to Yoetz. These cases pin the served wire shape against the MCP schema so
that claim can be settled from evidence rather than inferred, and so a future regression in the
payload is caught here rather than in a dogfood. Issue #173 later reproduced the same host error
against this conformant payload; Step 0 must not treat a list failure as a missing server.
The Codex ``0.148.0-alpha.6`` ``rmcp 3.0.0`` pin decodes this same payload as
``ServerResult::ListResourcesResult`` for the full shape and for the title / annotations /
size / minimal subsets, so optional-field stripping is not a Yoetz-side fix.

`resources/templates/list` returning method-not-found is correct: no templates are declared, so the
capability is not advertised. That is asserted rather than "fixed".
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, Final, cast

import pytest
from mcp import types

from yoetz.mcp.resources import GUIDANCE_RESOURCES

_TIMEOUT: Final = 90


def _serve(*requests: str) -> list[dict[str, Any]]:
    initialize = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": types.LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "conformance-probe", "version": "0.1.0"},
            },
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )
    frames = "\n".join(
        (initialize, '{"jsonrpc":"2.0","method":"notifications/initialized"}', *requests)
    )
    process = subprocess.run(
        [sys.executable, "-m", "yoetz", "mcp", "serve"],
        input=(frames + "\n").encode("ascii"),
        capture_output=True,
        timeout=_TIMEOUT,
        env={**os.environ},
    )
    assert process.returncode == 0, process.stderr[-2000:]
    assert b"Traceback" not in process.stderr
    return [cast(dict[str, Any], json.loads(line)) for line in process.stdout.splitlines() if line]


@pytest.fixture(scope="module")
def responses() -> list[dict[str, Any]]:
    return _serve(
        '{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}',
        '{"jsonrpc":"2.0","id":4,"method":"resources/templates/list","params":{}}',
    )


def _by_id(responses: list[dict[str, Any]], identifier: int) -> dict[str, Any]:
    for response in responses:
        if response.get("id") == identifier:
            return response
    raise AssertionError(f"no response with id {identifier}")


def test_the_server_advertises_the_resources_capability(responses: list[dict[str, Any]]) -> None:
    capabilities = _by_id(responses, 1)["result"]["capabilities"]
    assert "resources" in capabilities, "resources are served, so the capability must be declared"
    # Neither is implemented, so neither may be claimed.
    assert capabilities["resources"] == {"subscribe": False, "listChanged": False}


def test_resources_list_returns_a_result_not_an_error(responses: list[dict[str, Any]]) -> None:
    listed = _by_id(responses, 3)
    assert "error" not in listed, listed.get("error")
    assert "resources" in listed["result"]


def test_resources_list_result_is_not_a_tool_result_shape(
    responses: list[dict[str, Any]],
) -> None:
    """Codex maps a non-ListResourcesResult ServerResult to Unexpected response type.

    The live payload must stay a list result (``resources`` only) so a host that
    decodes ``rmcp``'s untagged ``ServerResult`` can still select that variant.
    """

    result = _by_id(responses, 3)["result"]
    assert set(result) == {"resources"}
    assert "content" not in result
    assert "structuredContent" not in result


def test_the_served_payload_validates_against_the_mcp_schema(
    responses: list[dict[str, Any]],
) -> None:
    # Parsing with the SDK's own model is the closest available stand-in for a strict client.
    parsed = types.ListResourcesResult.model_validate(_by_id(responses, 3)["result"])
    assert len(parsed.resources) == len(GUIDANCE_RESOURCES)
    served = {str(resource.uri) for resource in parsed.resources}
    assert served == {resource.uri for resource in GUIDANCE_RESOURCES}


def test_every_served_resource_carries_its_registry_facts(responses: list[dict[str, Any]]) -> None:
    served = {
        cast(str, entry["uri"]): entry for entry in _by_id(responses, 3)["result"]["resources"]
    }
    for resource in GUIDANCE_RESOURCES:
        entry = served[resource.uri]
        assert entry["name"] == resource.name
        assert entry["title"] == resource.title
        assert entry["description"] == resource.description
        assert entry["mimeType"] == resource.media_type
        # Size must be the real byte length; a wrong one misleads context-window budgeting.
        assert entry["size"] == resource.size
        assert entry["annotations"]["audience"] == list(resource.annotations.audience)
        # e260b250: a fractional priority is not served (Codex rmcp cannot decode a buffered
        # float). The registry values stay locked by the MCP contract matrix conformance test.
        assert "priority" not in entry["annotations"]


def test_resource_uris_are_parseable_absolute_uris(responses: list[dict[str, Any]]) -> None:
    # A client that parses uri as a URL must not choke on the custom scheme.
    for entry in _by_id(responses, 3)["result"]["resources"]:
        uri = cast(str, entry["uri"])
        assert uri.startswith("yoetz://guidance/")
        assert uri.isascii()
        assert " " not in uri


def test_templates_list_is_method_not_found_because_none_are_declared(
    responses: list[dict[str, Any]],
) -> None:
    # Declaring no templates and answering method-not-found is the conformant pairing. Guidance
    # must not present template discovery as an available recovery path.
    templates = _by_id(responses, 4)
    assert "result" not in templates
    assert templates["error"]["code"] == -32601


def test_each_listed_resource_can_actually_be_read(responses: list[dict[str, Any]]) -> None:
    # Listing a URI that cannot be read is the packaging failure this suite exists to prevent.
    reads = [
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 10 + index,
                "method": "resources/read",
                "params": {"uri": cast(str, entry["uri"])},
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
        for index, entry in enumerate(_by_id(responses, 3)["result"]["resources"])
    ]
    for index, response in enumerate(_serve(*reads)):
        if response.get("id", 0) < 10:
            continue
        assert "error" not in response, response.get("error")
        contents = response["result"]["contents"]
        assert contents and contents[0]["text"].strip(), index
        uri = contents[0]["uri"]
        resource = next(item for item in GUIDANCE_RESOURCES if item.uri == uri)
        listed = next(
            item for item in _by_id(responses, 3)["result"]["resources"] if item["uri"] == uri
        )
        assert contents[0]["mimeType"] == resource.media_type
        assert contents[0]["mimeType"] == listed["mimeType"]
