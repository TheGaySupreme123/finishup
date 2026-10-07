"""Status names the possible-credential filter state before any check runs (issue #982)."""

from __future__ import annotations

import asyncio
import json
from importlib.resources import files
from types import SimpleNamespace
from typing import Any, cast

from yoetz.application.service import Application
from yoetz.domain.values import JsonObject
from yoetz.mcp.summaries import (
    _credential_heuristic_clause,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.ports.control import ControlMethod, RepositoryIdentityKind, RepositoryPrivacyContext
from yoetz.protocol.models import StatusCredentialHeuristicModel

_COMMITMENT = "hmac-sha256:" + "1" * 64


def _fake(setup: Any, machine: Any) -> Any:
    async def support(method: ControlMethod, request: object, **_: object) -> JsonObject:
        del request
        if method is ControlMethod.PRIVACY_GET_SETUP:
            if isinstance(setup, Exception):
                raise setup
            return JsonObject(setup)
        return JsonObject(machine)

    return SimpleNamespace(
        support_handlers={
            ControlMethod.PRIVACY_GET_SETUP: object(),
            ControlMethod.PRIVACY_GET_EFFECTIVE: object(),
        },
        _support=support,
    )


def _state(fake: Any, *, context: bool = True) -> tuple[str, str] | None:
    repository = (
        RepositoryPrivacyContext(_COMMITMENT, cast(RepositoryIdentityKind, "git_common_root"))
        if context
        else None
    )
    return asyncio.run(
        Application._credential_heuristic_state(fake, repository)  # pyright: ignore[reportPrivateUsage]
    )


def test_repository_follows_its_own_grant_and_the_machine_default_is_shown() -> None:
    off = {"credential_heuristic": "disabled"}
    granted_off = {"grant_state": "granted", "composed_policy": off}
    granted_on: dict[str, object] = {"grant_state": "granted", "composed_policy": {}}
    assert _state(_fake(granted_off, {"policy": {}})) == ("disabled", "enforced")
    assert _state(_fake(granted_on, {"policy": off})) == ("enforced", "disabled")
    # No grant: nothing reaches the external reviewer, so the repository reads enforced.
    assert _state(_fake({"grant_state": "missing"}, {"policy": off})) == ("enforced", "disabled")


def test_unreadable_policy_reads_unknown_and_no_support_omits_the_field() -> None:
    assert _state(_fake(RuntimeError("down"), {"policy": {}})) == ("unknown", "enforced")
    assert _state(_fake({}, {"policy": {}}), context=False) == ("unknown", "enforced")
    bare = SimpleNamespace(support_handlers={})
    assert _state(bare) is None


def test_status_schema_model_and_summary_carry_the_state() -> None:
    document = json.loads(
        files("yoetz.resources")
        .joinpath("schemas/operations/status-result-1.4.0.schema.json")
        .read_bytes()
    )
    field = document["$defs"]["success"]["properties"]["credential_heuristic"]
    assert field["required"] == ["machine_default", "repository"]
    assert "credential_heuristic" not in document["$defs"]["success"]["required"]
    model = StatusCredentialHeuristicModel(repository="disabled", machine_default="enforced")
    assert model.repository == "disabled"
    assert _credential_heuristic_clause(
        {"credential_heuristic": {"repository": "disabled", "machine_default": "enforced"}}
    ).startswith("possible-credential filter: off")
    assert (
        _credential_heuristic_clause(
            {"credential_heuristic": {"repository": "enforced", "machine_default": "disabled"}}
        )
        == ""
    )


def test_cli_status_names_the_filter_for_this_repository_and_the_default() -> None:
    from yoetz.cli.render import (
        _credential_heuristic_lines,  # pyright: ignore[reportPrivateUsage]
    )

    state = StatusCredentialHeuristicModel(repository="disabled", machine_default="enforced")
    lines = _credential_heuristic_lines(cast(Any, SimpleNamespace(credential_heuristic=state)))
    assert lines == (
        "Possible-credential filter (external reviewer): off for this repository; "
        "installation default on",
    )
    assert _credential_heuristic_lines(cast(Any, SimpleNamespace(credential_heuristic=None))) == ()
