"""Issue #1012: `yoetz check --await-observations` and the rendered wait outcome (CLI + MCP)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from tests.unit.protocol.test_models_and_schemas import (
    _check_result_wire,  # pyright: ignore[reportPrivateUsage]
)
from typer.testing import CliRunner

import yoetz.cli.app as module
from yoetz.cli.render import render_human_check
from yoetz.mcp.summaries import summary_for_check
from yoetz.protocol.models import CheckRequest, CheckResult, CheckSuccessModel

_REQUEST: dict[str, Any] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-0000000000e1",
    "session_id": "ses_00000000-0000-4000-8000-0000000000e2",
    "writer_id": "wri_00000000-0000-4000-8000-0000000000e3",
    "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
    "mode": "deterministic_only",
    "actor": {"actor_id": "harness:test", "actor_type": "harness"},
    "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
}


def _result_wire(awaited: dict[str, str] | None) -> dict[str, Any]:
    wire = cast(dict[str, Any], json.loads(json.dumps(_check_result_wire())))
    if awaited is not None:
        wire["observations_awaited"] = awaited
    return wire


class _Client:
    def __init__(self, result: CheckResult) -> None:
        self.result = result
        self.requests: list[CheckRequest] = []

    async def check(self, request: CheckRequest, *, deadline_ms: int | None) -> CheckResult:
        del deadline_ms
        self.requests.append(request)
        return self.result

    async def close(self) -> None:
        return None


async def _async_value(value: object) -> object:
    return value


@pytest.mark.parametrize(
    ("flag", "inline", "expected"),
    [
        (True, {}, True),
        (False, {}, None),
        # A request that already carries the member keeps its own value.
        (True, {"await_observations": False}, False),
    ],
)
def test_cli_flag_sets_the_request_member(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    flag: bool,
    inline: dict[str, Any],
    expected: bool | None,
) -> None:
    client = _Client(
        CheckResult.model_validate(_result_wire({"state": "complete", "pending_count": "0"}))
    )
    monkeypatch.setattr(module, "build_service_client", lambda: _async_value(client))
    request_path = tmp_path / "check.json"
    request_path.write_text(json.dumps({**_REQUEST, **inline}))
    arguments = ["check", "--input", str(request_path), "--json"]
    if flag:
        arguments.append("--await-observations")

    outcome = CliRunner().invoke(module.app, arguments)

    assert outcome.exit_code == 0, outcome.output
    assert client.requests[0].await_observations is expected
    printed = json.loads(outcome.stdout)
    assert printed["observations_awaited"] == {"pending_count": "0", "state": "complete"}


@pytest.mark.parametrize(
    ("awaited", "line", "clause"),
    [
        (
            {"state": "complete", "pending_count": "0"},
            "Hook observations awaited: complete",
            "hook observations awaited: complete; ",
        ),
        (
            {"state": "bounded_timeout", "pending_count": "4"},
            "Hook observations awaited: bounded_timeout (4 still pending",
            "hook observations awaited: bounded_timeout, 4 still pending; ",
        ),
        (
            {"state": "unavailable", "pending_count": "0"},
            "Hook observations awaited: unavailable",
            "hook observations awaited: unavailable; ",
        ),
    ],
)
def test_human_and_mcp_summaries_name_the_wait(
    awaited: dict[str, str], line: str, clause: str
) -> None:
    wire = _result_wire(awaited)
    success = CheckResult.model_validate(wire).root
    assert isinstance(success, CheckSuccessModel)

    assert line in render_human_check(success)
    assert clause in summary_for_check(wire)


def test_absent_field_renders_nothing_new() -> None:
    wire = _result_wire(None)
    success = CheckResult.model_validate(wire).root
    assert isinstance(success, CheckSuccessModel)

    assert "observations awaited" not in render_human_check(success).lower()
    assert "observations awaited" not in summary_for_check(wire)


def test_mcp_check_tool_advertises_the_optional_flag() -> None:
    from yoetz.mcp.descriptors import (  # pyright: ignore[reportPrivateUsage]
        _mcp_presentation_schema,  # pyright: ignore[reportPrivateUsage]
        _tool_input_schema_version,  # pyright: ignore[reportPrivateUsage]
    )

    schema = _mcp_presentation_schema("check-request", _tool_input_schema_version("check"))
    properties = cast(dict[str, Any], schema["properties"])
    flag = cast(dict[str, Any], properties["await_observations"])
    assert flag["type"] == "boolean"
    assert "instead of polling status" in flag["description"]
    assert "await_observations" not in cast(list[str], schema.get("required", []))
