"""Status names the possible-credential filter state before any check runs (issue #982)."""

from __future__ import annotations

import asyncio
import json
from importlib.resources import files
from types import SimpleNamespace
from typing import Any, cast

from finishup.application.service import Application
from finishup.domain.values import JsonObject
from finishup.mcp.summaries import (
    _credential_heuristic_clause,  # pyright: ignore[reportPrivateUsage]
)
from finishup.ports.control import ControlMethod, RepositoryIdentityKind, RepositoryPrivacyContext
from finishup.protocol.models import StatusCredentialHeuristicModel

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


def _setup(repository: str, machine_default: str) -> dict[str, object]:
    return {
        "grant_state": "granted",
        "credential_heuristic": {"repository": repository, "machine_default": machine_default},
    }


def test_status_shows_the_setup_reads_derived_pair() -> None:
    """Status, provider status and the terminal interface read one derivation (issue #982)."""

    assert _state(_fake(_setup("disabled", "enforced"), {"policy": {}})) == (
        "disabled",
        "enforced",
    )
    assert _state(_fake(_setup("enforced", "disabled"), {"policy": {}})) == (
        "enforced",
        "disabled",
    )
    assert _state(_fake(_setup("unknown", "disabled"), {"policy": {}})) == ("unknown", "disabled")


def test_unreadable_policy_reads_unknown_and_no_support_omits_the_field() -> None:
    off = {"credential_heuristic": "disabled"}
    assert _state(_fake(RuntimeError("down"), {"policy": off})) == ("unknown", "disabled")
    assert _state(_fake({}, {"policy": {}}), context=False) == ("unknown", "enforced")
    bare = SimpleNamespace(support_handlers={})
    assert _state(bare) is None


def test_status_schema_model_and_summary_carry_the_state() -> None:
    document = json.loads(
        files("finishup.resources")
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
        == "possible-credential filter: on for this repository, installation default off (owner setting); "
    )
    assert "unknown for this repository" in _credential_heuristic_clause(
        {"credential_heuristic": {"repository": "unknown", "machine_default": "enforced"}}
    )
    assert (
        _credential_heuristic_clause(
            {"credential_heuristic": {"repository": "enforced", "machine_default": "enforced"}}
        )
        == ""
    )


def test_cli_status_names_the_filter_for_this_repository_and_the_default() -> None:
    from finishup.cli.render import (
        _credential_heuristic_lines,  # pyright: ignore[reportPrivateUsage]
    )

    state = StatusCredentialHeuristicModel(repository="disabled", machine_default="enforced")
    lines = _credential_heuristic_lines(cast(Any, SimpleNamespace(credential_heuristic=state)))
    assert lines == (
        "Possible-credential filter (external reviewer): off for this repository; "
        "installation default on. Turn it back on here with "
        "'finishup privacy credential-heuristic enable'",
    )
    default_off = StatusCredentialHeuristicModel(repository="enforced", machine_default="disabled")
    (line,) = _credential_heuristic_lines(
        cast(Any, SimpleNamespace(credential_heuristic=default_off))
    )
    assert "enable --machine-default" in line
    assert _credential_heuristic_lines(cast(Any, SimpleNamespace(credential_heuristic=None))) == ()


def test_the_shared_derivation_covers_grants_migrations_and_the_default() -> None:
    from finishup.application.privacy_policy import credential_heuristic_state
    from finishup.domain.privacy import CredentialHeuristic

    off, on = CredentialHeuristic.DISABLED, CredentialHeuristic.ENFORCED
    machine = SimpleNamespace(credential_heuristic=on)

    def policy(value: CredentialHeuristic) -> Any:
        return SimpleNamespace(credential_heuristic=value)

    def authority(**fields: object) -> Any:
        base: dict[str, object] = {
            "grant_state": "missing",
            "machine_policy": machine,
            "migration_frontiers": (),
            "effective": SimpleNamespace(policy=policy(on)),
        }
        base.update(fields)
        return SimpleNamespace(**base)

    def meeting(frontier_value: CredentialHeuristic) -> Any:
        def meet(other: Any) -> Any:
            both_off = frontier_value is off and other.credential_heuristic is off
            return policy(off if both_off else on)

        return SimpleNamespace(meet=meet)

    granted = authority(grant_state="granted", effective=SimpleNamespace(policy=policy(off)))
    assert credential_heuristic_state(granted).repository == "disabled"
    assert credential_heuristic_state(authority()).repository == "enforced"
    machine_off = policy(off)
    pending_off = authority(machine_policy=machine_off, migration_frontiers=(meeting(off),))
    state = credential_heuristic_state(pending_off)
    assert (state.repository, state.machine_default) == ("disabled", "disabled")
    mixed = authority(machine_policy=machine_off, migration_frontiers=(meeting(off), meeting(on)))
    assert credential_heuristic_state(mixed).repository == "unknown"
    no_machine = authority(machine_policy=None)
    assert credential_heuristic_state(no_machine).machine_default == "unknown"
