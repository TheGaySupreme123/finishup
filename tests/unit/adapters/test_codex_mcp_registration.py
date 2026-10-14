"""Codex MCP registration adapter: classification, digest binding, and refusal rules."""

from __future__ import annotations

import json
from pathlib import Path

import anyio
import pytest

from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter, CommandOutput
from finishup.config.paths import PathSafetyError
from finishup.ports.harness_mcp import (
    MCP_LEGACY_SERVE_COMMAND,
    MCP_LEGACY_STRICT_SERVE_COMMAND,
    MCP_SERVE_COMMAND,
    MCP_STRICT_SERVE_COMMAND,
    HarnessBinary,
    McpRegistrationAction,
    McpRegistrationCommand,
    McpRegistrationError,
    McpRegistrationReason,
    McpRegistrationState,
)
from finishup.ports.integrations import HarnessId
from finishup.protocol.canonical import canonical_digest

_BINARY = HarnessBinary(
    harness_id=HarnessId.CODEX,
    executable_path="/opt/harness/bin/codex",
    reported_version="0.144.5",
    compatibility="untested",
)


@pytest.fixture(autouse=True)
def scripted_registration_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    # The scripted host entries below model ambient registration by default.
    # Isolated-registration cases explicitly override this adapter lookup;
    # keep the process-wide isolation guard intact for all other test effects.
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", lambda: None)


def _finishup_entry(
    *, strict: bool = False, isolated_root: str | None = None, legacy: bool = False
) -> bytes:
    command = (
        MCP_LEGACY_STRICT_SERVE_COMMAND
        if strict and legacy
        else MCP_LEGACY_SERVE_COMMAND
        if legacy
        else MCP_STRICT_SERVE_COMMAND
        if strict
        else MCP_SERVE_COMMAND
    )
    args = list(command[1:])
    transport: dict[str, object] = {"command": "finishup", "args": args}
    if isolated_root is not None:
        transport["env"] = {"FINISHUP_ISOLATED_ROOT": isolated_root}
    return json.dumps(transport).encode("utf-8")


def _absent_outputs() -> list[CommandOutput]:
    """A failed named lookup plus a successful structural proof of absence."""

    return [CommandOutput(1, b""), CommandOutput(0, b"[]")]


class _Runner:
    """Scripted subprocess stand-in recording every argv it was asked to run."""

    def __init__(self, outputs: list[CommandOutput]) -> None:
        self.outputs = outputs
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: tuple[str, ...]) -> CommandOutput:
        self.calls.append(argv)
        return self.outputs.pop(0)


def test_status_absent_only_after_successful_list_confirmation() -> None:
    runner = _Runner(_absent_outputs())
    adapter = CodexMcpAdapter(runner)
    state = anyio.run(lambda: adapter.status_registration(_BINARY))
    assert state is McpRegistrationState.ABSENT
    assert runner.calls == [
        ("/opt/harness/bin/codex", "mcp", "get", "finishup", "--json"),
        ("/opt/harness/bin/codex", "mcp", "list", "--json"),
    ]


def test_status_nonzero_get_fails_closed_when_list_cannot_confirm_absence() -> None:
    runner = _Runner([CommandOutput(1, b""), CommandOutput(1, b"")])
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(lambda: CodexMcpAdapter(runner).status_registration(_BINARY))
    assert caught.value.reason is McpRegistrationReason.HARNESS_UNAVAILABLE


def test_status_nonzero_get_recovers_owned_entry_from_list() -> None:
    listed = json.dumps(
        [{"name": "finishup", "transport": {"command": "finishup", "args": ["mcp", "serve"]}}]
    ).encode("utf-8")
    runner = _Runner([CommandOutput(1, b""), CommandOutput(0, listed)])
    state = anyio.run(lambda: CodexMcpAdapter(runner).status_registration(_BINARY))
    assert state is McpRegistrationState.FINISHUP_OWNED


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"{}",
        b"[1]",
        b'[{"transport": {}}]',
        b'[{"name":"finishup"},{"name":"finishup"}]',
        b'[{"name":"finishup","name":"other"}]',
        b'[{"name":"other","value":NaN}]',
    ],
)
def test_status_nonzero_get_rejects_malformed_or_ambiguous_list(payload: bytes) -> None:
    runner = _Runner([CommandOutput(1, b""), CommandOutput(0, payload)])
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(lambda: CodexMcpAdapter(runner).status_registration(_BINARY))
    assert caught.value.reason is McpRegistrationReason.PARSE_FAILED


def test_status_nonzero_get_rejects_truncated_list_output() -> None:
    runner = _Runner([CommandOutput(1, b""), CommandOutput(0, b"[]", stdout_truncated=True)])
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(lambda: CodexMcpAdapter(runner).status_registration(_BINARY))
    assert caught.value.reason is McpRegistrationReason.PARSE_FAILED


def test_status_finishup_owned_on_exact_command_match() -> None:
    for payload in (
        {"command": "finishup", "args": ["mcp", "serve"]},
        {"command": ["finishup", "mcp", "serve"]},
        {
            "name": "finishup",
            "enabled": True,
            "transport": {
                "type": "stdio",
                "command": "finishup",
                "args": ["mcp", "serve"],
            },
        },
    ):
        runner = _Runner([CommandOutput(0, json.dumps(payload).encode("utf-8"))])
        state = anyio.run(lambda: CodexMcpAdapter(runner).status_registration(_BINARY))
        assert state is McpRegistrationState.FINISHUP_OWNED


def test_status_foreign_on_different_or_unreadable_command() -> None:
    for payload in (
        {"command": "other-server"},
        {"command": "finishup", "args": ["serve", "--http"]},
        {"command": "wrapper", "args": ["finishup", "mcp", "serve"]},
        {"command": "finishup", "args": ["mcp", "serve", "--extra"]},
        {"command": ["wrapper", "finishup", "mcp", "serve", "--semantic", "off"]},
        {"name": "finishup"},
        {"command": 7},
        {
            "name": "finishup",
            "transport": {"type": "stdio", "command": "other", "args": ["mcp", "serve"]},
        },
        {
            "name": "finishup",
            "transport": {
                "type": "stdio",
                "command": "finishup",
                "args": ["mcp", "serve"],
                "env": {"ARBITRARY_KEY": "value"},
            },
        },
        {
            "name": "finishup",
            "transport": {
                "type": "stdio",
                "command": "finishup",
                "args": ["mcp", "serve"],
                "env_vars": ["FINISHUP_ISOLATED_ROOT"],
            },
        },
        {
            "command": "finishup",
            "args": ["mcp", "serve"],
            "env": {"ARBITRARY_KEY": "value"},
            "transport": {"type": "stdio"},
        },
    ):
        runner = _Runner([CommandOutput(0, json.dumps(payload).encode("utf-8"))])
        state = anyio.run(lambda: CodexMcpAdapter(runner).status_registration(_BINARY))
        assert state is McpRegistrationState.FOREIGN_PRESENT, payload


def test_observe_reports_which_route_is_registered() -> None:
    """`yoetz_owned` alone cannot answer "can the agent get AI-powered review".

    Both serve commands classify as owned, so an operator reading only registration state sees a
    strict route and a policy route as the same thing. The observation carries the difference.
    """

    for strict, expected in ((False, "policy"), (True, "strict")):
        runner = _Runner([CommandOutput(0, _finishup_entry(strict=strict))])
        observation = anyio.run(lambda: CodexMcpAdapter(runner).observe_registration(_BINARY))
        assert observation.state is McpRegistrationState.FINISHUP_OWNED
        assert observation.route_profile == expected
        assert observation.isolation_binding == "ambient"
        assert observation.harness_id is HarnessId.CODEX


def test_observe_reports_exact_missing_and_different_isolation_bindings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = str(tmp_path)
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", root)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: tmp_path)

    exact = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry(isolated_root=root))])
        ).observe_registration(_BINARY)
    )
    missing = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry())])
        ).observe_registration(_BINARY)
    )
    different = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry(isolated_root="/different/root"))])
        ).observe_registration(_BINARY)
    )

    assert exact.isolation_binding == "isolated_exact"
    assert missing.isolation_binding == "missing"
    assert different.isolation_binding == "different"


def test_observe_reports_no_route_when_the_entry_is_not_ours() -> None:
    absent = anyio.run(
        lambda: CodexMcpAdapter(_Runner(_absent_outputs())).observe_registration(_BINARY)
    )
    assert absent.state is McpRegistrationState.ABSENT
    assert absent.route_profile is None

    foreign_output = CommandOutput(0, json.dumps({"command": "other-server"}).encode("utf-8"))
    foreign = anyio.run(
        lambda: CodexMcpAdapter(_Runner([foreign_output])).observe_registration(_BINARY)
    )
    assert foreign.state is McpRegistrationState.FOREIGN_PRESENT
    assert foreign.route_profile is None


def test_observe_does_not_depend_on_the_adapter_route_profile() -> None:
    """The observation reports what is registered, never what this adapter would register."""

    runner = _Runner([CommandOutput(0, _finishup_entry(strict=True))])
    observation = anyio.run(
        lambda: CodexMcpAdapter(runner, route_profile="policy").observe_registration(_BINARY)
    )
    assert observation.route_profile == "strict"


def test_observe_parse_failure_is_a_typed_error() -> None:
    runner = _Runner([CommandOutput(0, b"not json")])
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(lambda: CodexMcpAdapter(runner).observe_registration(_BINARY))
    assert caught.value.reason is McpRegistrationReason.PARSE_FAILED


def test_invalid_isolated_root_fails_before_the_host_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def invalid_root() -> Path:
        raise PathSafetyError("isolation_root_invalid")

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", invalid_root)
    runner = _Runner([])

    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(lambda: CodexMcpAdapter(runner).observe_registration(_BINARY))

    assert caught.value.reason is McpRegistrationReason.ISOLATION_INVALID
    assert caught.value.safe_details == {"reason": "isolation_root_invalid"}
    assert runner.calls == []


def test_observe_rejects_a_non_codex_binary() -> None:
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(_Runner([])).observe_registration(
                object()  # type: ignore[arg-type]
            )
        )
    assert caught.value.reason is McpRegistrationReason.HARNESS_UNAVAILABLE


def test_status_parse_failure_is_a_typed_error() -> None:
    for output in (
        CommandOutput(0, b"not json"),
        CommandOutput(0, b"[1,2]"),
        CommandOutput(0, b"\xff\xfe"),
        CommandOutput(0, b'{"command":"finishup","command":"other"}'),
        CommandOutput(0, b'{"command":"other","value":NaN}'),
        CommandOutput(0, b'{"command":"finishup"}', stdout_truncated=True),
    ):
        runner = _Runner([output])
        with pytest.raises(McpRegistrationError) as caught:
            anyio.run(lambda: CodexMcpAdapter(runner).status_registration(_BINARY))
        assert caught.value.reason is McpRegistrationReason.PARSE_FAILED


def test_preview_register_for_absent_and_noop_for_owned() -> None:
    absent = anyio.run(
        lambda: CodexMcpAdapter(_Runner(_absent_outputs())).preview_registration(_BINARY)
    )
    assert absent.action is McpRegistrationAction.REGISTER
    assert absent.state_before is McpRegistrationState.ABSENT
    assert absent.warnings == ()

    owned = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry())])
        ).preview_registration(_BINARY)
    )
    assert owned.action is McpRegistrationAction.NOOP
    assert owned.state_before is McpRegistrationState.FINISHUP_OWNED


def test_preview_foreign_carries_warning_and_noop() -> None:
    runner = _Runner([CommandOutput(0, json.dumps({"command": "other"}).encode("utf-8"))])
    preview = anyio.run(lambda: CodexMcpAdapter(runner).preview_registration(_BINARY))
    assert preview.action is McpRegistrationAction.NOOP
    assert preview.warnings == ("foreign_entry_present",)


def test_strict_preview_binds_exact_command_and_changes_digest() -> None:
    policy = anyio.run(
        lambda: CodexMcpAdapter(_Runner(_absent_outputs())).preview_registration(_BINARY)
    )
    strict = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner(_absent_outputs()),
            route_profile="strict",
        ).preview_registration(_BINARY)
    )

    assert policy.serve_command == MCP_SERVE_COMMAND
    assert policy.route_profile == "policy"
    assert policy.preview_digest == canonical_digest(
        {
            "action": "register",
            "executable_path": _BINARY.executable_path,
            "harness": "codex",
            "schema": "yoetz.mcp-registration-preview/1",
            "serve_command": list(MCP_SERVE_COMMAND),
            "server_name": "finishup",
            "state_before": "absent",
        }
    )
    assert strict.serve_command == MCP_STRICT_SERVE_COMMAND
    assert strict.route_profile == "strict"
    assert strict.preview_digest != policy.preview_digest


def test_isolated_preview_binds_exact_root_and_requires_reregistration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = str(tmp_path)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: tmp_path)
    ambient = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry())])
        ).preview_registration(_BINARY)
    )
    exact = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry(isolated_root=root))])
        ).preview_registration(_BINARY)
    )

    assert ambient.action is McpRegistrationAction.REREGISTER
    assert ambient.isolated_root == root
    assert exact.action is McpRegistrationAction.NOOP
    assert exact.isolated_root == root


def test_explicit_preview_allows_reregistering_an_owned_route_profile() -> None:
    planned = CodexMcpAdapter(
        _Runner([CommandOutput(0, _finishup_entry())]),
        route_profile="strict",
    )
    preview = anyio.run(lambda: planned.preview_registration(_BINARY))
    assert preview.action is McpRegistrationAction.REREGISTER

    runner = _Runner(
        [
            CommandOutput(0, _finishup_entry()),
            CommandOutput(0, b""),
            CommandOutput(0, _finishup_entry(strict=True)),
        ]
    )
    result = anyio.run(
        lambda: CodexMcpAdapter(
            runner,
            route_profile="strict",
        ).apply_registration(
            _BINARY,
            McpRegistrationCommand(preview.preview_digest, True),
        )
    )

    assert result.action is McpRegistrationAction.REREGISTER
    assert runner.calls[1][-len(MCP_STRICT_SERVE_COMMAND) :] == MCP_STRICT_SERVE_COMMAND


def test_apply_requires_explicit_acceptance_and_exact_digest() -> None:
    adapter = CodexMcpAdapter(_Runner(_absent_outputs()))
    preview = anyio.run(lambda: adapter.preview_registration(_BINARY))

    declined = CodexMcpAdapter(_Runner(_absent_outputs()))
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: declined.apply_registration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, False)
            )
        )
    assert caught.value.reason is McpRegistrationReason.CONFIRMATION_REQUIRED

    stale = CodexMcpAdapter(_Runner(_absent_outputs()))
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: stale.apply_registration(
                _BINARY, McpRegistrationCommand("sha256:" + "0" * 64, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.PREVIEW_STALE


def test_apply_registers_then_verifies_by_rereading_state() -> None:
    plan_adapter = CodexMcpAdapter(_Runner(_absent_outputs()))
    preview = anyio.run(lambda: plan_adapter.preview_registration(_BINARY))

    runner = _Runner(
        [
            CommandOutput(1, b""),  # get: absent
            CommandOutput(0, b"[]"),  # list: confirms absence
            CommandOutput(0, b""),  # add
            CommandOutput(0, _finishup_entry()),  # verify get
        ]
    )
    result = anyio.run(
        lambda: CodexMcpAdapter(runner).apply_registration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert result.action is McpRegistrationAction.REGISTER
    assert result.state_before is McpRegistrationState.ABSENT
    assert result.state_after is McpRegistrationState.FINISHUP_OWNED
    assert runner.calls[2] == (
        "/opt/harness/bin/codex",
        "mcp",
        "add",
        "finishup",
        "--",
        *MCP_SERVE_COMMAND,
    )


def test_apply_isolated_registration_passes_only_the_reviewed_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = str(tmp_path)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: tmp_path)
    preview = anyio.run(
        lambda: CodexMcpAdapter(_Runner(_absent_outputs())).preview_registration(_BINARY)
    )
    runner = _Runner(
        [
            *_absent_outputs(),
            CommandOutput(0, b""),
            CommandOutput(0, _finishup_entry(isolated_root=root)),
        ]
    )

    result = anyio.run(
        lambda: CodexMcpAdapter(runner).apply_registration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )

    assert result.state_after is McpRegistrationState.FINISHUP_OWNED
    assert runner.calls[2] == (
        "/opt/harness/bin/codex",
        "mcp",
        "add",
        "finishup",
        "--env",
        f"FINISHUP_ISOLATED_ROOT={root}",
        "--",
        *MCP_SERVE_COMMAND,
    )


def test_apply_reregisters_a_legacy_bare_entry_with_the_isolated_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = str(tmp_path)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: tmp_path)
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry(legacy=True))])
        ).preview_registration(_BINARY)
    )
    assert preview.action is McpRegistrationAction.REREGISTER
    runner = _Runner(
        [
            CommandOutput(0, _finishup_entry(legacy=True)),
            CommandOutput(0, b""),
            CommandOutput(0, _finishup_entry(isolated_root=root)),
        ]
    )

    result = anyio.run(
        lambda: CodexMcpAdapter(runner).apply_registration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )

    assert result.action is McpRegistrationAction.REREGISTER
    assert runner.calls[1][4:7] == (
        "--env",
        f"FINISHUP_ISOLATED_ROOT={root}",
        "--",
    )


def test_apply_reports_failure_when_verify_does_not_show_ownership() -> None:
    plan_adapter = CodexMcpAdapter(_Runner(_absent_outputs()))
    preview = anyio.run(lambda: plan_adapter.preview_registration(_BINARY))

    runner = _Runner(
        [
            CommandOutput(1, b""),  # get: absent
            CommandOutput(0, b"[]"),  # list: confirms absence
            CommandOutput(0, b""),  # add claims success
            CommandOutput(1, b""),  # verify still absent
            CommandOutput(0, b"[]"),  # list: confirms it is still absent
        ]
    )
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(runner).apply_registration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.REGISTRATION_FAILED


def test_apply_does_not_add_when_failed_get_cannot_confirm_absence() -> None:
    plan_adapter = CodexMcpAdapter(_Runner(_absent_outputs()))
    preview = anyio.run(lambda: plan_adapter.preview_registration(_BINARY))
    runner = _Runner([CommandOutput(1, b""), CommandOutput(1, b"")])
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(runner).apply_registration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.HARNESS_UNAVAILABLE
    assert all(call[1:3] != ("mcp", "add") for call in runner.calls)


def test_apply_never_replaces_a_foreign_entry() -> None:
    foreign = CommandOutput(0, json.dumps({"command": "other"}).encode("utf-8"))
    plan_adapter = CodexMcpAdapter(_Runner([foreign]))
    preview = anyio.run(lambda: plan_adapter.preview_registration(_BINARY))

    runner = _Runner([CommandOutput(0, json.dumps({"command": "other"}).encode("utf-8"))])
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(runner).apply_registration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.FOREIGN_ENTRY_PRESENT
    # The refusal happened before any mutating `mcp add` invocation.
    assert all(call[1:3] == ("mcp", "get") for call in runner.calls)


def test_apply_noop_when_already_finishup_owned() -> None:
    plan_adapter = CodexMcpAdapter(_Runner([CommandOutput(0, _finishup_entry())]))
    preview = anyio.run(lambda: plan_adapter.preview_registration(_BINARY))

    runner = _Runner([CommandOutput(0, _finishup_entry())])
    result = anyio.run(
        lambda: CodexMcpAdapter(runner).apply_registration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert result.action is McpRegistrationAction.NOOP
    assert result.state_before is result.state_after is McpRegistrationState.FINISHUP_OWNED
    assert all(call[1:3] == ("mcp", "get") for call in runner.calls)


def test_preview_unregistration_of_owned_entry() -> None:
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry())])
        ).preview_unregistration(_BINARY)
    )
    assert preview.action is McpRegistrationAction.UNREGISTER
    assert preview.state_before is McpRegistrationState.FINISHUP_OWNED
    assert preview.warnings == ("host_remove_not_compare_and_swap",)


def test_preview_unregistration_of_foreign_entry_warns_without_echoing_argv() -> None:
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, json.dumps({"command": "other"}).encode("utf-8"))])
        ).preview_unregistration(_BINARY)
    )
    assert preview.action is McpRegistrationAction.UNREGISTER
    assert preview.state_before is McpRegistrationState.FOREIGN_PRESENT
    assert preview.warnings == ("foreign_entry_present",)
    assert preview.serve_command == MCP_SERVE_COMMAND
    preview = anyio.run(
        lambda: CodexMcpAdapter(_Runner(_absent_outputs())).preview_unregistration(_BINARY)
    )
    assert preview.action is McpRegistrationAction.NOOP
    assert preview.state_before is McpRegistrationState.ABSENT


@pytest.mark.parametrize("exit_code", [0, 1])
def test_apply_unregistration_removes_owned_entry(exit_code: int) -> None:
    plan_adapter = CodexMcpAdapter(_Runner([CommandOutput(0, _finishup_entry())]))
    preview = anyio.run(lambda: plan_adapter.preview_unregistration(_BINARY))
    runner = _Runner(
        [
            CommandOutput(0, _finishup_entry()),
            CommandOutput(0, _finishup_entry()),
            CommandOutput(exit_code, b"host output must not be reported"),
            CommandOutput(1, b""),
            CommandOutput(0, b"[]"),
        ]
    )
    result = anyio.run(
        lambda: CodexMcpAdapter(runner).apply_unregistration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert result.action is McpRegistrationAction.UNREGISTER
    assert result.state_after is McpRegistrationState.ABSENT
    assert result.warnings == (("host_remove_returned_nonzero",) if exit_code else ())
    assert runner.calls[2] == ("/opt/harness/bin/codex", "mcp", "remove", "finishup")
    assert runner.calls[3:] == [
        ("/opt/harness/bin/codex", "mcp", "get", "finishup", "--json"),
        ("/opt/harness/bin/codex", "mcp", "list", "--json"),
    ]


@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize(
    ("post_outputs", "verified_state"),
    [
        ([CommandOutput(0, _finishup_entry())], "yoetz_owned"),
        ([CommandOutput(0, b'{"command":"foreign"}')], "foreign_present"),
        (
            [CommandOutput(1, b""), CommandOutput(0, b'[{"name":"finishup","command":"foreign"}]')],
            "foreign_present",
        ),
        ([CommandOutput(0, b"invalid")], None),
        ([CommandOutput(1, b""), CommandOutput(0, b"invalid")], None),
        ([CommandOutput(1, b""), CommandOutput(0, b"[]", True)], None),
        ([CommandOutput(1, b""), CommandOutput(1, b"[]")], None),
    ],
)
def test_removal_never_succeeds_without_positive_absence(
    exit_code: int, post_outputs: list[CommandOutput], verified_state: str | None
) -> None:
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry())])
        ).preview_unregistration(_BINARY)
    )
    runner = _Runner(
        [
            CommandOutput(0, _finishup_entry()),
            CommandOutput(0, _finishup_entry()),
            CommandOutput(exit_code, b"private-host-payload"),
            *post_outputs,
        ]
    )
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(runner).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.REGISTRATION_FAILED
    assert caught.value.safe_details.get("verified_state") == verified_state
    assert caught.value.safe_details.get("exit_code_class") == ("nonzero" if exit_code else None)
    assert "private-host-payload" not in str(caught.value.safe_details)
    assert sum(call[1:3] == ("mcp", "remove") for call in runner.calls) == 1


def test_apply_unregistration_refuses_replacement_before_name_based_remove() -> None:
    plan_adapter = CodexMcpAdapter(_Runner([CommandOutput(0, _finishup_entry())]))
    preview = anyio.run(lambda: plan_adapter.preview_unregistration(_BINARY))
    foreign = CommandOutput(0, json.dumps({"command": "other"}).encode("utf-8"))
    runner = _Runner(
        [
            CommandOutput(0, _finishup_entry()),
            foreign,
        ]
    )

    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(runner).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )

    assert caught.value.reason is McpRegistrationReason.FOREIGN_ENTRY_PRESENT
    assert all(call[1:3] == ("mcp", "get") for call in runner.calls)


def test_apply_unregistration_refuses_an_isolated_root_replacement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = str(tmp_path)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: tmp_path)
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry(isolated_root=root))])
        ).preview_unregistration(_BINARY)
    )
    runner = _Runner(
        [
            CommandOutput(0, _finishup_entry(isolated_root=root)),
            CommandOutput(0, _finishup_entry(isolated_root="/replacement/root")),
        ]
    )

    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(runner).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )

    assert caught.value.reason is McpRegistrationReason.PREVIEW_STALE
    assert all(call[1:3] != ("mcp", "remove") for call in runner.calls)


def test_apply_unregistration_does_not_remove_after_unreadable_ownership_recheck() -> None:
    plan_adapter = CodexMcpAdapter(_Runner([CommandOutput(0, _finishup_entry())]))
    preview = anyio.run(lambda: plan_adapter.preview_unregistration(_BINARY))
    runner = _Runner(
        [
            CommandOutput(0, _finishup_entry()),
            CommandOutput(1, b""),
            CommandOutput(1, b""),
        ]
    )
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(runner).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.HARNESS_UNAVAILABLE
    assert all(call[1:3] != ("mcp", "remove") for call in runner.calls)


def test_apply_unregistration_does_not_claim_success_after_unreadable_verification() -> None:
    plan_adapter = CodexMcpAdapter(_Runner([CommandOutput(0, _finishup_entry())]))
    preview = anyio.run(lambda: plan_adapter.preview_unregistration(_BINARY))
    runner = _Runner(
        [
            CommandOutput(0, _finishup_entry()),
            CommandOutput(0, _finishup_entry()),
            CommandOutput(0, b""),
            CommandOutput(1, b""),
            CommandOutput(1, b""),
        ]
    )
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(runner).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.REGISTRATION_FAILED
    assert runner.calls[2][1:3] == ("mcp", "remove")


@pytest.mark.parametrize(
    "reason",
    [McpRegistrationReason.TIMEOUT, McpRegistrationReason.HARNESS_UNAVAILABLE],
)
def test_apply_unregistration_normalizes_mutating_remove_errors(
    reason: McpRegistrationReason,
) -> None:
    plan_adapter = CodexMcpAdapter(_Runner([CommandOutput(0, _finishup_entry())]))
    preview = anyio.run(lambda: plan_adapter.preview_unregistration(_BINARY))
    outputs = [CommandOutput(0, _finishup_entry()), CommandOutput(0, _finishup_entry())]
    calls: list[tuple[str, ...]] = []

    def fail_remove(argv: tuple[str, ...]) -> CommandOutput:
        calls.append(argv)
        if argv[1:3] == ("mcp", "remove"):
            raise McpRegistrationError(reason, {})
        return outputs.pop(0)

    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(fail_remove).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )

    assert caught.value.reason is McpRegistrationReason.REGISTRATION_FAILED
    assert calls[2][1:3] == ("mcp", "remove")


def test_apply_unregistration_normalizes_malformed_post_remove_verification() -> None:
    plan_adapter = CodexMcpAdapter(_Runner([CommandOutput(0, _finishup_entry())]))
    preview = anyio.run(lambda: plan_adapter.preview_unregistration(_BINARY))
    runner = _Runner(
        [
            CommandOutput(0, _finishup_entry()),
            CommandOutput(0, _finishup_entry()),
            CommandOutput(0, b""),
            CommandOutput(1, b""),
            CommandOutput(0, b"not-json"),
        ]
    )

    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(runner).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )

    assert caught.value.reason is McpRegistrationReason.REGISTRATION_FAILED
    assert runner.calls[2][1:3] == ("mcp", "remove")


def test_apply_unregistration_refuses_foreign_entry() -> None:
    foreign = CommandOutput(0, json.dumps({"command": "other"}).encode("utf-8"))
    plan_adapter = CodexMcpAdapter(_Runner([foreign]))
    preview = anyio.run(lambda: plan_adapter.preview_unregistration(_BINARY))
    runner = _Runner([CommandOutput(0, json.dumps({"command": "other"}).encode("utf-8"))])
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(runner).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.FOREIGN_ENTRY_PRESENT
    assert all(call[1:3] == ("mcp", "get") for call in runner.calls)


def test_apply_unregistration_is_noop_when_absent() -> None:
    plan_adapter = CodexMcpAdapter(_Runner(_absent_outputs()))
    preview = anyio.run(lambda: plan_adapter.preview_unregistration(_BINARY))
    runner = _Runner(_absent_outputs())
    result = anyio.run(
        lambda: CodexMcpAdapter(runner).apply_unregistration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert result.action is McpRegistrationAction.NOOP
    assert result.state_after is McpRegistrationState.ABSENT
    assert [call[1:3] for call in runner.calls] == [("mcp", "get"), ("mcp", "list")]


def test_preview_names_an_unproven_launcher_instead_of_falling_back_to_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A console script that cannot prove itself (group-writable prefix, symlink, modified
    RECORD) must not register a bare ``finishup`` and must say which condition it hit (#766)."""

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", lambda: None)
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp.invoking_launcher",
        lambda: "/opt/homebrew/bin/finishup",
    )
    runner = _Runner(_absent_outputs())
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(lambda: CodexMcpAdapter(runner).preview_registration(_BINARY))
    assert caught.value.reason is McpRegistrationReason.HARNESS_UNAVAILABLE
    assert caught.value.safe_details == {"detail": "launcher_unproven"}
    assert all(call[1:3] != ("mcp", "add") for call in runner.calls)


def test_selected_home_is_used_for_every_registration_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An explicit test home must not register into the ambient user's Codex config."""
    import sys

    ambient = tmp_path / "ambient"
    selected = tmp_path / "selected"
    ambient.mkdir()
    selected.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(ambient))
    monkeypatch.setenv("CODEX_TESTING_HOME", str(ambient))
    host = tmp_path / "codex"
    host.write_text(
        f"#!{sys.executable}\n"
        "import json,os,pathlib,sys\n"
        "home=pathlib.Path(os.environ['CODEX_HOME'])\n"
        "assert str(home)==os.environ['CODEX_TESTING_HOME']\n"
        "entry=home/'mcp-entry.json'\n"
        "args=sys.argv[1:]\n"
        "if args[1]=='get':\n"
        " if not entry.exists():sys.exit(1)\n"
        " print(entry.read_text())\n"
        "elif args[1]=='list':print('[]')\n"
        "elif args[1]=='add':\n"
        " command=args[args.index('--')+1:]\n"
        " entry.write_text(json.dumps({'command':command[0],'args':command[1:]}))\n"
        "elif args[1]=='remove':entry.unlink()\n"
    )
    host.chmod(0o700)
    binary = HarnessBinary(HarnessId.CODEX, str(host), "0.153.4", "untested")
    adapter = CodexMcpAdapter(codex_home=selected)
    preview = anyio.run(lambda: adapter.preview_registration(binary))
    command = McpRegistrationCommand(
        preview_digest=preview.preview_digest, explicitly_accepted=True
    )
    anyio.run(lambda: adapter.apply_registration(binary, command))
    assert (selected / "mcp-entry.json").exists()
    assert not tuple(ambient.iterdir())
    removal = anyio.run(lambda: adapter.preview_unregistration(binary))
    anyio.run(
        lambda: adapter.apply_unregistration(
            binary,
            McpRegistrationCommand(preview_digest=removal.preview_digest, explicitly_accepted=True),
        )
    )
    assert not (selected / "mcp-entry.json").exists()
    assert not tuple(ambient.iterdir())


def test_registration_preview_cannot_be_replayed_for_a_different_home(tmp_path: Path) -> None:
    first = CodexMcpAdapter(_Runner(_absent_outputs()), codex_home=tmp_path / "one")
    second = CodexMcpAdapter(_Runner(_absent_outputs()), codex_home=tmp_path / "two")
    preview = anyio.run(lambda: first.preview_registration(_BINARY))
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: second.apply_registration(
                _BINARY,
                McpRegistrationCommand(
                    preview_digest=preview.preview_digest, explicitly_accepted=True
                ),
            )
        )
    assert caught.value.reason is McpRegistrationReason.PREVIEW_STALE
