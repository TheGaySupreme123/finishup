"""Issue #986 (owner decision E2): the recorded review route on check renderings (CLI + MCP)."""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
from tests.unit.protocol.test_models_and_schemas import (
    _check_result_wire,  # pyright: ignore[reportPrivateUsage]
)

from yoetz.application.check import semantic_route_required
from yoetz.cli.render import render_human_check
from yoetz.mcp.summaries import summary_for_check
from yoetz.protocol.models import CheckResult, CheckSuccessModel

_CLI = "the route did not require it, so it does not block a clean receipt"
_MCP = "route did not require AI-powered review (disclosed; does not block receipt); "


def _wire(route_required: bool | None) -> dict[str, Any]:
    wire = cast(dict[str, Any], json.loads(json.dumps(_check_result_wire())))
    if route_required is not None:
        wire["semantic_route_required"] = route_required
    return wire


def test_a_route_without_required_review_is_named_on_every_check_rendering() -> None:
    wire = _wire(False)
    result = CheckResult.model_validate(wire).root
    assert type(result) is CheckSuccessModel
    assert result.semantic_route_required is False
    assert _CLI in render_human_check(result)
    assert _MCP in summary_for_check(wire)


@pytest.mark.parametrize("route_required", (None, True))
def test_a_requiring_or_unrecorded_route_renders_as_before(route_required: bool | None) -> None:
    wire = _wire(route_required)
    result = CheckResult.model_validate(wire).root
    assert type(result) is CheckSuccessModel
    assert _CLI not in render_human_check(result)
    assert _MCP not in summary_for_check(wire)
    baseline = _wire(None)
    assert summary_for_check(wire) == summary_for_check(baseline)


def test_the_route_field_is_a_strict_boolean() -> None:
    with pytest.raises(ValueError):
        CheckResult.model_validate({**_wire(None), "semantic_route_required": "false"})
    with pytest.raises(ValueError):
        CheckResult.model_validate({**_wire(None), "semantic_route_required": None})


@pytest.mark.parametrize(
    ("mode", "policy", "required"),
    [
        ("deterministic_only", "disabled", False),
        ("deterministic_only", "optional", False),
        ("semantic_if_configured", "optional", False),
        ("deterministic_only", "required", True),
        ("semantic_if_configured", "required", True),
        ("semantic_required", "optional", True),
        ("semantic_required", "disabled", True),
    ],
)
def test_route_required_review_definition(mode: str, policy: Any, required: bool) -> None:
    assert semantic_route_required(mode, policy) is required


@pytest.mark.parametrize(
    ("mode", "drift", "required"),
    [
        # Issue #1021 (owner decision tb4n2 P0-8): an explicitly deterministic-only (strict)
        # route did not require review, even under a ``required`` verification policy.
        ("deterministic_only", False, False),
        ("semantic_if_configured", False, False),
        (None, False, False),
        # Asking for review still requires it on any route.
        ("semantic_required", False, True),
        # A strict process serving a host whose applied route is policy is stale, not an owner
        # choice: the policy decides.
        ("deterministic_only", True, True),
    ],
)
def test_a_strict_route_does_not_require_review(
    mode: str | None, drift: bool, required: bool
) -> None:
    assert (
        semantic_route_required(mode, "required", route_profile="strict", route_drift=drift)
        is required
    )
