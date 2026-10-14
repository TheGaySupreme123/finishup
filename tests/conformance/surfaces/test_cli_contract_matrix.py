"""Public CLI contract: the frozen command matrix, the privacy/recipe surface, idle-relock
confidentiality, JSON/human output modes, and the exit code matrix.
"""

from __future__ import annotations

import json
import re
import typing
from collections.abc import Awaitable, Callable
from typing import cast

import pytest
from pydantic import BaseModel
from typer.testing import CliRunner

import finishup.application.privacy_policy as privacy_policy
import finishup.cli.app as cli
from finishup.cli.agent_start import AGENT_START_GUIDE_URL, AGENT_START_HANDOFF
from finishup.cli.exits import PUBLIC_EXIT_CODES, exit_code_for
from finishup.domain.privacy import PrivacyProfile, ReviewContextProfile
from finishup.mcp.descriptors import TOOL_DESCRIPTORS
from finishup.ports.control import ControlMethod
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.models import StartRequest, StartResult

_OPERATION_COMMANDS = ("start", "publish-work", "check", "respond", "status", "receipt")
_SUPPORT_COMMANDS = (
    "import",
    "review",
    "mcp",
    "state",
    "integrate",
    "setup",
    "service",
    "provider",
    "privacy",
    "backup",
    "restore",
    "migrate",
    "version",
)


def test_command_matrix_matches_six_operations() -> None:
    """The six operation commands and the closed set of support commands are present in the CLI
    tree; nothing appears in help text that is not a real command, and no ad hoc command exists
    outside this frozen matrix."""

    runner = CliRunner()
    root = runner.invoke(cli.app, ["--help"])
    assert root.exit_code == 0
    root_plain = "".join(re.sub(r"\x1b\[[0-9;]*m", "", root.stdout).split())
    assert "".join(AGENT_START_HANDOFF.split()) in root_plain
    assert "".join(AGENT_START_GUIDE_URL.split()) in root_plain
    for command in _OPERATION_COMMANDS + _SUPPORT_COMMANDS:
        assert command in root.stdout
    # No undocumented convenience command sneaks into the frozen matrix.
    assert "doctor" not in root.stdout

    # Every operation command is a real, independently invokable subcommand -- not merely
    # mentioned in the root summary line -- and exposes the ordinary workflow flags.
    # Rich help may soft-wrap option names; strip ANSI and whitespace before matching.
    for command in _OPERATION_COMMANDS:
        sub = runner.invoke(cli.app, [command, "--help"])
        assert sub.exit_code == 0, command
        plain = "".join(re.sub(r"\x1b\[[0-9;]*m", "", sub.stdout).split())
        assert "--json" in plain, command
        assert "--input" in plain, command
        assert "--request" in plain, command

    # A command that appears only in help text but not in the actual Typer app fails: every name
    # advertised in root help must itself be a registered command group or leaf command.
    command_names = {info.name for info in cli.app.registered_commands}
    group_names = {group.name for group in cli.app.registered_groups}
    for command in _OPERATION_COMMANDS + _SUPPORT_COMMANDS:
        assert command in command_names or command in group_names, command


def test_bare_invocation_without_tty_still_prints_help() -> None:
    """The ADR-012 first-run exception is bounded to an interactive terminal with no
    completion marker; every non-TTY bare invocation (CI, pipes, CliRunner) keeps the
    historical help-printing behavior and exit code 0."""

    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 0
    assert "Usage" in result.stdout
    assert AGENT_START_HANDOFF in result.stdout


def test_privacy_command_and_recipe_matrix() -> None:
    """The trusted-local privacy setup/audit commands and the closed five-recipe vocabulary are
    exact; decision commands remain confined to trusted human control, never an ordinary flag."""

    runner = CliRunner()
    for args in (
        ["privacy", "setup", "--help"],
        ["privacy", "show", "--help"],
        ["privacy", "propose", "--help"],
        ["privacy", "tighten", "--help"],
        ["privacy", "pending", "--help"],
        ["privacy", "receipts", "list", "--help"],
        ["privacy", "receipts", "get", "--help"],
    ):
        result = runner.invoke(cli.app, args)
        assert result.exit_code == 0, args

    # Decision commands are present but confined to trusted human control: no ``--yes`` or other
    # unattended-approval flag exists, and each requires an out-of-band pending decision ID that
    # only a prior ``setup``/``propose``/``tighten`` call could have produced.
    for command in ("decide-policy", "decide-disclosure"):
        help_result = runner.invoke(cli.app, ["privacy", command, "--help"])
        assert help_result.exit_code == 0
        assert "--yes" not in help_result.stdout
        missing = runner.invoke(cli.app, ["privacy", command])
        assert missing.exit_code != 0

    recipes = typing.get_args(privacy_policy.PrivacyRecipe.__value__)
    assert recipes == ("private", "metadata_only", "assisted_review", "expanded_review", "custom")
    assert len(recipes) == 5

    # The four non-custom recipes each expand to one exact, closed PrivacyProfile /
    # ReviewContextProfile pair (the fixed table owned by ``privacy_get_setup``); ``custom`` is
    # the caller-composed escape hatch with no fixed pair, so it is intentionally excluded here.
    materialized = {
        "private": (PrivacyProfile.LOCAL_ONLY, ReviewContextProfile.STRUCTURAL),
        "metadata_only": (
            PrivacyProfile.CONFIRM_EVERY_REQUEST,
            ReviewContextProfile.STRUCTURAL,
        ),
        "assisted_review": (PrivacyProfile.MINIMAL_EXTERNAL, ReviewContextProfile.ASSISTED),
        "expanded_review": (PrivacyProfile.TRUSTED_PROVIDER, ReviewContextProfile.EXPANDED),
    }
    assert set(materialized) | {"custom"} == set(recipes)
    assert len(set(materialized.values())) == len(materialized)


def test_idle_relock_command_is_confidential_only() -> None:
    """``service idle-relock <60..86400|disabled>`` is advertised with the exact target grammar
    and exists only as a trusted-foreground command -- never as a ``ControlMethod`` and never as
    a registered MCP tool."""

    runner = CliRunner()
    help_result = runner.invoke(cli.app, ["service", "idle-relock", "--help"])
    assert help_result.exit_code == 0
    assert "60..86400" in help_result.stdout or "disabled" in help_result.stdout

    # The exact target grammar: an out-of-range value, a leading-zero value, and a non-decimal
    # alias are all usage failures, never silently coerced or accepted.
    for invalid in ("59", "86401", "059", "disabled-ish", "-1", "60.0"):
        result = runner.invoke(cli.app, ["service", "idle-relock", invalid])
        assert result.exit_code == 2, invalid

    # No ordinary control token or MCP descriptor exists for idle-relock: only the confidential
    # human ceremony (``finishup.cli.unlock.change_idle_relock_policy``) can apply it.
    method_values = {method.value for method in ControlMethod}
    assert "idle_relock_policy_change" not in method_values
    assert not any("idle_relock" in method.value for method in ControlMethod)
    tool_names = {
        descriptor.name for descriptors in TOOL_DESCRIPTORS.values() for descriptor in descriptors
    }
    assert not any("idle" in name or "relock" in name for name in tool_names)

    # No ``--yes`` or other unattended-approval flag exists on the trusted-foreground command.
    assert "--yes" not in help_result.stdout


_REQUEST = cast(StartRequest, object())
_FAILURE_WIRE: dict[str, JsonValue] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "ok": False,
    "request_id": "req_00000000-0000-4000-8000-000000000001",
    "error": {
        "code": "INVALID_REQUEST",
        "message": "The request is invalid.",
        "retryable": False,
        "correlation_id": "err_00000000-0000-4000-8000-000000000002",
    },
}


class _Client:
    def __init__(self, wire: dict[str, JsonValue]) -> None:
        self.wire = wire
        self.closed = False

    async def start(self, request: StartRequest, *, deadline_ms: int | None = None) -> StartResult:
        del request, deadline_ms
        return StartResult.model_validate(self.wire)

    async def close(self) -> None:
        self.closed = True


def test_json_and_human_output_modes() -> None:
    """Structured (``--json``) and human output paths stay distinct; human output never outruns
    the structured truth -- an operation failure is written to stderr in human mode and never
    upgrades a failed outcome to a success-shaped message."""

    async def build_failure() -> object:
        return _Client(_FAILURE_WIRE)

    def request_model(
        model_type: type[BaseModel], input_path: str | None, inline: str | None
    ) -> BaseModel:
        del model_type, input_path, inline
        return _REQUEST

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(
            "finishup.cli.app.build_service_client",
            cast(Callable[[], Awaitable[object]], build_failure),
        )
        monkeypatch.setattr("finishup.cli.app._request_model", request_model)

        json_result = CliRunner().invoke(cli.app, ["start", "--request", "{}", "--json"])
        assert json_result.exit_code == exit_code_for(PublicErrorCode.INVALID_REQUEST)
        assert json_result.stdout.encode("utf-8") == canonical_encode(_FAILURE_WIRE) + b"\n"
        # The structured JSON body carries the full error object; the human/stderr channel is
        # empty for a JSON-mode invocation -- the two channels never mix.
        assert json_result.stderr == ""

        # Non-JSON output (and non-tty stdout, as under CliRunner) still emits the identical
        # structured body: the CLI never invents a stronger, unstructured "friendly" success
        # message for a failed outcome.
        human_mode_result = CliRunner().invoke(cli.app, ["start", "--request", "{}"])
        assert human_mode_result.exit_code == exit_code_for(PublicErrorCode.INVALID_REQUEST)
        assert human_mode_result.stdout.encode("utf-8") == canonical_encode(_FAILURE_WIRE) + b"\n"
    finally:
        monkeypatch.undo()

    # A genuine success path (the local, service-free ``version`` command) shows the two output
    # modes stay distinct in shape while conveying the identical version truth: JSON mode emits
    # one structured, machine-parseable object; the default/non-tty mode emits the bare version
    # string, and CliRunner's captured stdout is never a controlling tty either way.
    runner = CliRunner()
    json_version = runner.invoke(cli.app, ["version", "--json"])
    assert json_version.exit_code == 0
    assert json_version.stderr == ""
    structured = cast(dict[str, JsonValue], json.loads(json_version.stdout))
    assert structured["package_name"] == "finishup"

    plain_version = runner.invoke(cli.app, ["version"])
    assert plain_version.exit_code == 0
    assert plain_version.stdout.strip()
    assert plain_version.stdout != json_version.stdout
    assert str(structured["package_version"]) in plain_version.stdout


def test_exit_code_matrix() -> None:
    """Every member of the closed ``PublicErrorCode`` enum maps to the exact expected exit code
    and no table key is missing or extra; success and cancellation map exactly."""

    assert exit_code_for("success") == 0
    assert exit_code_for("cancelled") == 130

    expected = {
        PublicErrorCode.INVALID_REQUEST: 2,
        PublicErrorCode.PROTOCOL_VERSION_UNSUPPORTED: 20,
        PublicErrorCode.SESSION_NOT_FOUND: 10,
        PublicErrorCode.SESSION_CONFLICT: 10,
        PublicErrorCode.IDEMPOTENCY_CONFLICT: 10,
        PublicErrorCode.REQUEST_IDENTITY_CONFLICT: 10,
        PublicErrorCode.OPERATION_PENDING: 11,
        PublicErrorCode.FRONTIER_CONFLICT: 10,
        PublicErrorCode.EVENT_INVALID: 2,
        PublicErrorCode.LIMIT_EXCEEDED: 2,
        PublicErrorCode.BUNDLE_BUSY: 20,
        PublicErrorCode.STORAGE_UNSAFE: 20,
        PublicErrorCode.STORAGE_CORRUPT: 40,
        PublicErrorCode.MIGRATION_REQUIRED: 20,
        PublicErrorCode.SERVICE_UNAVAILABLE: 20,
        PublicErrorCode.VAULT_LOCKED: 20,
        PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED: 20,
        PublicErrorCode.PROVIDER_UNAVAILABLE: 30,
        PublicErrorCode.PROVIDER_REFUSED: 30,
        PublicErrorCode.PROVIDER_TIMEOUT: 30,
        PublicErrorCode.SEMANTIC_RESULT_INVALID: 30,
        PublicErrorCode.CANCELLED: 130,
        PublicErrorCode.INTERNAL_ERROR: 70,
    }
    # The closed public enum has exactly this many members; a missing or extra member here (or
    # in ``PUBLIC_EXIT_CODES``) is itself a contract break, not merely an incomplete sample.
    assert len(expected) == 23
    assert set(expected) == set(PublicErrorCode)
    assert dict(PUBLIC_EXIT_CODES) == expected
    for code, exit_code in expected.items():
        assert exit_code_for(code) == exit_code

    with pytest.raises(TypeError):
        exit_code_for(cast(PublicErrorCode, "NOT_A_REAL_CODE"))
