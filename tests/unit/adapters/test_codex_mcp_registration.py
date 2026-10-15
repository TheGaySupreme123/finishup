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
    McpRegistrationObservation,
    McpRegistrationReason,
    McpRegistrationState,
    mcp_command_profile,
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
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp.installed_launcher",
        lambda name="finishup": None,
    )
    # No transitional ``yoetz`` distribution unless a case installs one (ADR-048).
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp._legacy_distribution_installed", lambda: False
    )


def _finishup_entry(
    *,
    strict: bool = False,
    isolated_root: str | None = None,
    legacy: bool = False,
    launcher: str = "finishup",
    root_names: tuple[str, ...] = ("FINISHUP_ISOLATED_ROOT", "YOETZ_ISOLATED_ROOT"),
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
    transport: dict[str, object] = {"command": launcher, "args": args}
    if isolated_root is not None:
        # A new registration binds both spellings of the root to one value (ADR-048).
        transport["env"] = dict.fromkeys(root_names, isolated_root)
    return json.dumps(transport).encode("utf-8")


def _listing(name: str, entry: bytes) -> bytes:
    """A ``codex mcp list --json`` payload holding one named entry."""

    return json.dumps([{"name": name, "transport": json.loads(entry)}]).encode("utf-8")


def _mutations(calls: list[tuple[str, ...]]) -> list[tuple[str, ...]]:
    """Only the host-mutating ``add``/``remove`` calls, in order."""

    return [call for call in calls if call[1:3] in {("mcp", "add"), ("mcp", "remove")}]


def _absent_outputs() -> list[CommandOutput]:
    """A failed named lookup plus a successful structural proof of absence."""

    return [CommandOutput(1, b""), CommandOutput(0, b"[]")]


class _Runner:
    """Scripted subprocess stand-in recording every argv it was asked to run.

    Every observation lists the host's entries once to read the legacy ``yoetz`` key (ADR-048).
    After a successful named ``get`` that list is answered from ``listing`` (no legacy entry by
    default) instead of the scripted queue, so each script names only the calls it is about.
    """

    def __init__(self, outputs: list[CommandOutput], *, listing: bytes = b"[]") -> None:
        self.outputs = outputs
        self.listing = listing
        self.calls: list[tuple[str, ...]] = []
        self._after_found_get = False

    def __call__(self, argv: tuple[str, ...]) -> CommandOutput:
        self.calls.append(argv)
        if argv[1:3] == ("mcp", "list") and self._after_found_get:
            self._after_found_get = False
            return CommandOutput(0, self.listing)
        output = self.outputs.pop(0)
        self._after_found_get = argv[1:3] == ("mcp", "get") and output.exit_code == 0
        return output


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
    assert _mutations(runner.calls)[0][-len(MCP_STRICT_SERVE_COMMAND) :] == MCP_STRICT_SERVE_COMMAND


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
        "--env",
        f"YOETZ_ISOLATED_ROOT={root}",
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
    assert _mutations(runner.calls)[0][4:9] == (
        "--env",
        f"FINISHUP_ISOLATED_ROOT={root}",
        "--env",
        f"YOETZ_ISOLATED_ROOT={root}",
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
    assert _mutations(runner.calls) == []


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
    assert _mutations(runner.calls) == []


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
    assert _mutations(runner.calls) == [("/opt/harness/bin/codex", "mcp", "remove", "finishup")]
    assert runner.calls[-2:] == [
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
    assert _mutations(runner.calls) == []


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
    assert len(_mutations(runner.calls)) == 1


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
        if argv[1:3] == ("mcp", "list"):
            return CommandOutput(0, b"[]")
        return outputs.pop(0)

    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(fail_remove).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )

    assert caught.value.reason is McpRegistrationReason.REGISTRATION_FAILED
    assert _mutations(calls) == [("/opt/harness/bin/codex", "mcp", "remove", "finishup")]


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
    assert len(_mutations(runner.calls)) == 1


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
    assert _mutations(runner.calls) == []


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


# Legacy ``yoetz`` registration key (ADR-048).

_LEGACY_BARE = (
    "yoetz",  # Frozen legacy identifier (ADR-048): the pre-rename bare launcher.
    *MCP_SERVE_COMMAND[1:],
)


def _legacy_entry() -> bytes:
    return _finishup_entry(launcher="yoetz")


def test_profile_accepts_either_bare_launcher_spelling() -> None:
    assert mcp_command_profile(_LEGACY_BARE) == "policy"
    assert mcp_command_profile(("yoetz", *MCP_STRICT_SERVE_COMMAND[1:])) == "strict"
    assert mcp_command_profile(("finishup-other", *MCP_SERVE_COMMAND[1:])) is None


def test_status_reads_an_owned_legacy_only_entry_as_owned_but_outdated() -> None:
    runner = _Runner([CommandOutput(1, b""), CommandOutput(0, _listing("yoetz", _legacy_entry()))])
    observation = anyio.run(lambda: CodexMcpAdapter(runner).observe_registration(_BINARY))
    assert observation.state is McpRegistrationState.FINISHUP_OWNED
    assert observation.legacy_registration == "legacy_only"
    assert observation.serve_command == _LEGACY_BARE
    assert observation.route_profile == "policy"
    assert observation.isolation_binding == "ambient"
    # One get plus one list reads both keys; nothing is mutated.
    assert [call[2] for call in runner.calls] == ["get", "list"]


def test_status_reports_duplicate_and_foreign_legacy_entries() -> None:
    duplicate = _Runner(
        [CommandOutput(0, _finishup_entry())], listing=_listing("yoetz", _legacy_entry())
    )
    observed = anyio.run(lambda: CodexMcpAdapter(duplicate).observe_registration(_BINARY))
    assert observed.state is McpRegistrationState.FINISHUP_OWNED
    assert observed.serve_command == MCP_SERVE_COMMAND
    assert observed.legacy_registration == "duplicate"

    foreign = _listing("yoetz", json.dumps({"command": "other-server"}).encode("utf-8"))
    alone = _Runner([CommandOutput(1, b""), CommandOutput(0, foreign)])
    observed = anyio.run(lambda: CodexMcpAdapter(alone).observe_registration(_BINARY))
    assert observed.state is McpRegistrationState.ABSENT
    assert observed.legacy_registration == "foreign"
    assert observed.serve_command is None


def test_status_without_legacy_entry_reports_none() -> None:
    runner = _Runner([CommandOutput(0, _finishup_entry())])
    observed = anyio.run(lambda: CodexMcpAdapter(runner).observe_registration(_BINARY))
    assert observed.legacy_registration == "none"


def test_status_refuses_a_duplicated_legacy_name_in_the_listing() -> None:
    entry = {"name": "yoetz", "transport": json.loads(_legacy_entry())}
    listing = json.dumps([entry, entry]).encode("utf-8")
    runner = _Runner([CommandOutput(0, _finishup_entry())], listing=listing)
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(lambda: CodexMcpAdapter(runner).status_registration(_BINARY))
    assert caught.value.reason is McpRegistrationReason.PARSE_FAILED


def test_integrate_migrates_an_owned_legacy_entry_in_one_preview() -> None:
    legacy_only = [CommandOutput(1, b""), CommandOutput(0, _listing("yoetz", _legacy_entry()))]
    preview = anyio.run(
        lambda: CodexMcpAdapter(_Runner(list(legacy_only))).preview_registration(_BINARY)
    )
    assert preview.action is McpRegistrationAction.REREGISTER
    assert preview.state_before is McpRegistrationState.FINISHUP_OWNED
    assert preview.legacy_registration == "legacy_only"
    assert preview.warnings == ("legacy_registration_owned",)
    assert preview.serve_command == MCP_SERVE_COMMAND
    # A key migration keeps the route the entry already serves.
    assert preview.route_profile_before == "policy"

    legacy = _listing("yoetz", _legacy_entry())
    calls: list[tuple[str, ...]] = []

    def host(argv: tuple[str, ...]) -> CommandOutput:
        # Before the add the new key is absent; after it, it is owned. The legacy entry stays
        # listed until its removal runs.
        calls.append(argv)
        added = any(call[2] == "add" for call in calls)
        removed = any(call[2] == "remove" for call in calls)
        if argv[2] in {"add", "remove"}:
            return CommandOutput(0, b"")
        if argv[2] == "get":
            return CommandOutput(0, _finishup_entry()) if added else CommandOutput(1, b"")
        return CommandOutput(0, b"[]" if removed else legacy)

    result = anyio.run(
        lambda: CodexMcpAdapter(host).apply_registration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert result.action is McpRegistrationAction.REREGISTER
    assert result.state_after is McpRegistrationState.FINISHUP_OWNED
    # The new key is written before the legacy one goes, so a failure never leaves neither.
    assert _mutations(calls) == [
        ("/opt/harness/bin/codex", "mcp", "add", "finishup", "--", *MCP_SERVE_COMMAND),
        ("/opt/harness/bin/codex", "mcp", "remove", "yoetz"),
    ]


def test_integrate_never_touches_a_foreign_legacy_entry() -> None:
    foreign = _listing("yoetz", json.dumps({"command": "other-server"}).encode("utf-8"))
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(1, b""), CommandOutput(0, foreign)])
        ).preview_registration(_BINARY)
    )
    assert preview.action is McpRegistrationAction.REGISTER
    assert preview.legacy_registration == "foreign"
    assert preview.warnings == ("legacy_registration_foreign",)
    runner = _Runner(
        [
            CommandOutput(1, b""),
            CommandOutput(0, foreign),
            CommandOutput(0, b""),
            CommandOutput(0, _finishup_entry()),
        ],
        listing=foreign,
    )
    result = anyio.run(
        lambda: CodexMcpAdapter(runner).apply_registration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert result.state_after is McpRegistrationState.FINISHUP_OWNED
    assert _mutations(runner.calls) == [
        ("/opt/harness/bin/codex", "mcp", "add", "finishup", "--", *MCP_SERVE_COMMAND)
    ]


def test_integrate_stops_before_removing_a_legacy_entry_that_changed() -> None:
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner(
                [CommandOutput(0, _finishup_entry())], listing=_listing("yoetz", _legacy_entry())
            )
        ).preview_registration(_BINARY)
    )
    assert preview.legacy_registration == "duplicate"
    assert preview.action is McpRegistrationAction.REREGISTER
    replaced = _listing("yoetz", json.dumps({"command": "other-server"}).encode("utf-8"))
    listings = iter([_listing("yoetz", _legacy_entry()), replaced])
    calls: list[tuple[str, ...]] = []

    def host(argv: tuple[str, ...]) -> CommandOutput:
        calls.append(argv)
        if argv[2] == "list":
            return CommandOutput(0, next(listings))
        return CommandOutput(0, _finishup_entry())

    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(host).apply_registration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.REGISTRATION_FAILED
    assert caught.value.safe_details.get("legacy_state") == "foreign_present"
    # The current entry already matched, so nothing was added and nothing was removed.
    assert _mutations(calls) == []


def test_remove_takes_owned_entries_under_both_keys() -> None:
    legacy = _listing("yoetz", _legacy_entry())
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry())], listing=legacy)
        ).preview_unregistration(_BINARY)
    )
    assert preview.action is McpRegistrationAction.UNREGISTER
    assert preview.legacy_registration == "duplicate"
    assert preview.warnings == ("host_remove_not_compare_and_swap", "legacy_registration_owned")
    listings = iter([legacy, legacy, legacy, b"[]"])
    calls: list[tuple[str, ...]] = []

    def host(argv: tuple[str, ...]) -> CommandOutput:
        calls.append(argv)
        if argv[2] == "list":
            return CommandOutput(0, next(listings))
        if argv[2] == "remove":
            return CommandOutput(0, b"")
        absent = sum(call[2] == "remove" for call in calls) > 0
        return CommandOutput(1, b"") if absent else CommandOutput(0, _finishup_entry())

    result = anyio.run(
        lambda: CodexMcpAdapter(host).apply_unregistration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert result.state_after is McpRegistrationState.ABSENT
    assert _mutations(calls) == [
        ("/opt/harness/bin/codex", "mcp", "remove", "finishup"),
        ("/opt/harness/bin/codex", "mcp", "remove", "yoetz"),
    ]


def test_remove_of_a_legacy_only_entry_leaves_a_foreign_one_alone() -> None:
    legacy = _listing("yoetz", _legacy_entry())
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(1, b""), CommandOutput(0, legacy)])
        ).preview_unregistration(_BINARY)
    )
    assert preview.state_before is McpRegistrationState.FINISHUP_OWNED
    assert preview.serve_command == _LEGACY_BARE
    runner = _Runner(
        [
            CommandOutput(1, b""),
            CommandOutput(0, legacy),
            CommandOutput(1, b""),
            CommandOutput(0, legacy),
            CommandOutput(0, b""),
            CommandOutput(1, b""),
            CommandOutput(0, b"[]"),
        ]
    )
    result = anyio.run(
        lambda: CodexMcpAdapter(runner).apply_unregistration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert result.state_after is McpRegistrationState.ABSENT
    assert _mutations(runner.calls) == [("/opt/harness/bin/codex", "mcp", "remove", "yoetz")]

    foreign = _listing("yoetz", json.dumps({"command": "other-server"}).encode("utf-8"))
    noop = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(1, b""), CommandOutput(0, foreign)])
        ).preview_unregistration(_BINARY)
    )
    assert noop.action is McpRegistrationAction.NOOP
    assert noop.state_before is McpRegistrationState.ABSENT
    assert noop.warnings == ("legacy_registration_foreign",)


@pytest.mark.parametrize("exit_code", [0, 23])
def test_remove_owned_legacy_entry_beside_foreign_current_entry(exit_code: int) -> None:
    foreign = CommandOutput(0, b'{"command":"other-server","args":["private-value"]}')
    legacy = _listing("yoetz", _legacy_entry())
    preview = anyio.run(
        lambda: CodexMcpAdapter(_Runner([foreign], listing=legacy)).preview_unregistration(_BINARY)
    )
    assert preview.action is McpRegistrationAction.UNREGISTER
    assert preview.state_before is McpRegistrationState.FINISHUP_OWNED
    assert preview.serve_command == _LEGACY_BARE
    assert preview.warnings == (
        "foreign_entry_present",
        "host_remove_not_compare_and_swap",
        "legacy_registration_owned",
    )
    calls: list[tuple[str, ...]] = []

    def host(argv: tuple[str, ...]) -> CommandOutput:
        calls.append(argv)
        if argv[2] == "get":
            return foreign
        if argv[2] == "remove":
            assert argv[3] == "yoetz"
            return CommandOutput(exit_code, b"")
        removed = any(call[2] == "remove" for call in calls)
        return CommandOutput(0, b"[]" if removed else legacy)

    result = anyio.run(
        lambda: CodexMcpAdapter(host).apply_unregistration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert result.state_after is McpRegistrationState.ABSENT
    assert _mutations(calls) == [("/opt/harness/bin/codex", "mcp", "remove", "yoetz")]
    assert result.warnings == (("host_remove_returned_nonzero",) if exit_code else ())
    # Registering would overwrite the foreign new key and still refuses on this same state.
    registration = anyio.run(
        lambda: CodexMcpAdapter(_Runner([foreign], listing=legacy)).preview_registration(_BINARY)
    )
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(_Runner([foreign], listing=legacy)).apply_registration(
                _BINARY, McpRegistrationCommand(registration.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.FOREIGN_ENTRY_PRESENT


def test_remove_rechecks_the_legacy_key_after_removing_the_current_key() -> None:
    legacy = _listing("yoetz", _legacy_entry())
    foreign = _listing("yoetz", b'{"command":"other-server"}')
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, _finishup_entry())], listing=legacy)
        ).preview_unregistration(_BINARY)
    )
    calls: list[tuple[str, ...]] = []

    def host(argv: tuple[str, ...]) -> CommandOutput:
        calls.append(argv)
        removed = any(call[2] == "remove" for call in calls)
        if argv[2] == "get":
            return CommandOutput(1, b"") if removed else CommandOutput(0, _finishup_entry())
        if argv[2] == "remove":
            return CommandOutput(0, b"")
        return CommandOutput(0, foreign if removed else legacy)

    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(host).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.REGISTRATION_FAILED
    assert caught.value.safe_details == {"legacy_state": "foreign_present"}
    assert _mutations(calls) == [("/opt/harness/bin/codex", "mcp", "remove", "finishup")]


@pytest.mark.parametrize("exit_code", [0, 23])
def test_removed_legacy_key_requires_positive_absence(exit_code: int) -> None:
    legacy = _listing("yoetz", _legacy_entry())
    foreign = _listing("yoetz", b'{"command":"other-server"}')
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(1, b""), CommandOutput(0, legacy)])
        ).preview_unregistration(_BINARY)
    )
    runner = _Runner(
        [
            CommandOutput(1, b""),
            CommandOutput(0, legacy),
            CommandOutput(1, b""),
            CommandOutput(0, legacy),
            CommandOutput(exit_code, b""),
            CommandOutput(1, b""),
            CommandOutput(0, foreign),
        ]
    )
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(runner).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.REGISTRATION_FAILED
    assert caught.value.safe_details.get("legacy_state") == "foreign_present"
    assert _mutations(runner.calls) == [("/opt/harness/bin/codex", "mcp", "remove", "yoetz")]


def test_migration_requires_positive_absence_of_the_removed_legacy_key() -> None:
    legacy = _listing("yoetz", _legacy_entry())
    foreign = _listing("yoetz", b'{"command":"other-server"}')
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(1, b""), CommandOutput(0, legacy)])
        ).preview_registration(_BINARY)
    )
    calls: list[tuple[str, ...]] = []

    def host(argv: tuple[str, ...]) -> CommandOutput:
        calls.append(argv)
        if argv[2] in {"add", "remove"}:
            return CommandOutput(0, b"")
        added = any(call[2] == "add" for call in calls)
        removed = any(call[2] == "remove" for call in calls)
        if argv[2] == "get":
            return CommandOutput(0, _finishup_entry()) if added else CommandOutput(1, b"")
        return CommandOutput(0, foreign if removed else legacy)

    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(host).apply_registration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.REGISTRATION_FAILED
    assert caught.value.safe_details == {"legacy_state": "foreign_present"}
    assert _mutations(calls)[-1] == ("/opt/harness/bin/codex", "mcp", "remove", "yoetz")


@pytest.mark.parametrize("removed_name", ["finishup", "yoetz"])
def test_remove_does_not_report_absence_when_another_owned_key_appears(removed_name: str) -> None:
    legacy = _listing("yoetz", _legacy_entry())
    foreign = CommandOutput(0, b'{"command":"other-server"}')
    initial = (
        _Runner([CommandOutput(0, _finishup_entry())])
        if removed_name == "finishup"
        else _Runner([foreign], listing=legacy)
    )
    preview = anyio.run(lambda: CodexMcpAdapter(initial).preview_unregistration(_BINARY))
    calls: list[tuple[str, ...]] = []

    def host(argv: tuple[str, ...]) -> CommandOutput:
        calls.append(argv)
        removed = any(call[2] == "remove" for call in calls)
        if argv[2] == "remove":
            return CommandOutput(0, b"")
        if argv[2] == "get":
            if removed_name == "finishup":
                return CommandOutput(1, b"") if removed else CommandOutput(0, _finishup_entry())
            return CommandOutput(0, _finishup_entry()) if removed else foreign
        if removed_name == "finishup":
            return CommandOutput(0, legacy if removed else b"[]")
        return CommandOutput(0, b"[]" if removed else legacy)

    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: CodexMcpAdapter(host).apply_unregistration(
                _BINARY, McpRegistrationCommand(preview.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.REGISTRATION_FAILED
    assert _mutations(calls) == [("/opt/harness/bin/codex", "mcp", "remove", removed_name)]


@pytest.mark.parametrize(
    ("root_names", "action"),
    [
        (("FINISHUP_ISOLATED_ROOT", "YOETZ_ISOLATED_ROOT"), McpRegistrationAction.NOOP),
        (("FINISHUP_ISOLATED_ROOT",), McpRegistrationAction.REREGISTER),
        (("YOETZ_ISOLATED_ROOT",), McpRegistrationAction.REREGISTER),
    ],
)
def test_isolation_root_is_read_under_either_spelling(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    root_names: tuple[str, ...],
    action: McpRegistrationAction,
) -> None:
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: tmp_path)
    entry = _finishup_entry(isolated_root=str(tmp_path), root_names=root_names)
    observed = anyio.run(
        lambda: CodexMcpAdapter(_Runner([CommandOutput(0, entry)])).observe_registration(_BINARY)
    )
    assert observed.state is McpRegistrationState.FINISHUP_OWNED
    assert observed.isolation_binding == "isolated_exact"
    preview = anyio.run(
        lambda: CodexMcpAdapter(_Runner([CommandOutput(0, entry)])).preview_registration(_BINARY)
    )
    assert preview.action is action


def test_two_different_isolation_roots_are_not_finishups_binding() -> None:
    entry = json.dumps(
        {
            "command": "finishup",
            "args": list(MCP_SERVE_COMMAND[1:]),
            "env": {"FINISHUP_ISOLATED_ROOT": "/a", "YOETZ_ISOLATED_ROOT": "/b"},
        }
    ).encode("utf-8")
    state = anyio.run(
        lambda: CodexMcpAdapter(_Runner([CommandOutput(0, entry)])).status_registration(_BINARY)
    )
    assert state is McpRegistrationState.FOREIGN_PRESENT


def test_absolute_legacy_alias_beside_the_proven_launcher_is_owned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The transitional ``yoetz`` RECORD proof is unavailable, so the exact sibling of the proven
    # ``finishup`` script is the fallback ownership evidence (ADR-048).
    def proof(name: str = "finishup") -> tuple[str, str] | None:
        if name == "finishup":
            return "/opt/runtime/bin/finishup", "sha256:" + "0" * 64
        return None

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", proof)
    alias = _finishup_entry(launcher="/opt/runtime/bin/yoetz")
    elsewhere = _finishup_entry(launcher="/opt/other/bin/yoetz")
    owned = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(1, b""), CommandOutput(0, _listing("yoetz", alias))])
        ).observe_registration(_BINARY)
    )
    assert owned.state is McpRegistrationState.FINISHUP_OWNED
    assert owned.legacy_registration == "legacy_only"
    other = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(1, b""), CommandOutput(0, _listing("yoetz", elsewhere))])
        ).observe_registration(_BINARY)
    )
    assert other.state is McpRegistrationState.ABSENT
    assert other.legacy_registration == "foreign"


def test_absolute_legacy_alias_is_proven_by_the_transitional_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The RECORD-checked ``yoetz`` script owns the entry even without a ``finishup`` proof."""

    requested: list[str] = []

    def proof(name: str = "finishup") -> tuple[str, str] | None:
        requested.append(name)
        if name == "yoetz":
            return "/opt/runtime/bin/yoetz", "sha256:" + "1" * 64
        return None

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", proof)
    alias = _finishup_entry(launcher="/opt/runtime/bin/yoetz")
    owned = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(1, b""), CommandOutput(0, _listing("yoetz", alias))])
        ).observe_registration(_BINARY)
    )
    assert owned.state is McpRegistrationState.FINISHUP_OWNED
    assert owned.legacy_registration == "legacy_only"
    assert "yoetz" in requested


def _observe_sibling_alias(
    monkeypatch: pytest.MonkeyPatch,
    scripts: Path,
    *,
    distribution_installed: bool,
) -> McpRegistrationObservation:
    """Observe ``<scripts>/yoetz`` while its RECORD proof is unavailable (ADR-048)."""

    def proof(name: str = "finishup") -> tuple[str, str] | None:
        if name == "finishup":
            return str(scripts / "finishup"), "sha256:" + "0" * 64
        return None

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", proof)
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp._legacy_distribution_installed",
        lambda: distribution_installed,
    )
    alias = _finishup_entry(launcher=str(scripts / "yoetz"))
    return anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(1, b""), CommandOutput(0, _listing("yoetz", alias))])
        ).observe_registration(_BINARY)
    )


def test_a_legacy_script_its_record_rejects_is_never_owned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With the transitional distribution installed, a modified ``yoetz`` script is foreign."""

    scripts = tmp_path / "bin"
    scripts.mkdir()
    (scripts / "yoetz").write_bytes(b"#!/bin/sh\nexec something-else\n")

    observed = _observe_sibling_alias(monkeypatch, scripts, distribution_installed=True)

    assert observed.legacy_registration == "foreign"


def test_a_legacy_script_is_owned_by_location_only_without_the_transitional_distribution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scripts = tmp_path / "bin"
    scripts.mkdir()
    (scripts / "yoetz").write_bytes(b"#!/bin/sh\n")

    observed = _observe_sibling_alias(monkeypatch, scripts, distribution_installed=False)

    assert observed.state is McpRegistrationState.FINISHUP_OWNED
    assert observed.legacy_registration == "legacy_only"


def test_a_registration_naming_a_missing_legacy_script_stays_removable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No bytes at the sibling path, so no RECORD rejected any: the entry stays migratable."""

    scripts = tmp_path / "bin"
    scripts.mkdir()

    observed = _observe_sibling_alias(monkeypatch, scripts, distribution_installed=True)

    assert observed.legacy_registration == "legacy_only"


def test_the_legacy_distribution_probe_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from importlib.metadata import PackageNotFoundError

    from finishup.adapters.integrations import codex_mcp

    monkeypatch.undo()

    def absent(_name: str) -> object:
        raise PackageNotFoundError("yoetz")

    def unreadable(_name: str) -> object:
        raise OSError("unreadable")

    probe = codex_mcp._legacy_distribution_installed  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(codex_mcp, "distribution", absent)
    assert probe() is False
    monkeypatch.setattr(codex_mcp, "distribution", unreadable)
    assert probe() is True

    def installed(_name: str) -> object:
        return object()

    monkeypatch.setattr(codex_mcp, "distribution", installed)
    assert probe() is True


@pytest.mark.parametrize(
    "environment",
    [
        {"FINISHUP_ISOLATED_ROOT": ["/a"]},
        {"YOETZ_ISOLATED_ROOT": {"root": "/a"}},
        {"FINISHUP_ISOLATED_ROOT": "/a", "YOETZ_ISOLATED_ROOT": ["/a"]},
    ],
)
def test_a_non_string_isolation_root_value_is_foreign_not_a_crash(
    environment: dict[str, object],
) -> None:
    from finishup.adapters.integrations import codex_mcp

    entry = {"command": "finishup", "args": ["mcp", "serve", "--host", "codex"], "env": environment}
    parse = codex_mcp._entry_isolated_root  # pyright: ignore[reportPrivateUsage]
    assert parse(entry) == (False, None, True)
    observed = anyio.run(
        lambda: CodexMcpAdapter(
            _Runner([CommandOutput(0, json.dumps(entry).encode())])
        ).observe_registration(_BINARY)
    )
    assert observed.state is McpRegistrationState.FOREIGN_PRESENT


class _KeyedHost:
    """Both Codex keys with ``add`` and ``remove``, so the adapter both decides and applies."""

    def __init__(self, *, legacy: bytes | None = None, current: bytes | None = None) -> None:
        self.entries: dict[str, bytes] = {}
        if current is not None:
            self.entries["finishup"] = current
        if legacy is not None:
            self.entries["yoetz"] = legacy
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: tuple[str, ...]) -> CommandOutput:
        self.calls.append(argv)
        verb = argv[2]
        if verb == "get":
            raw = self.entries.get(argv[3])
            return CommandOutput(1, b"") if raw is None else CommandOutput(0, raw)
        if verb == "list":
            rows = [
                {"name": name, "transport": json.loads(raw)} for name, raw in self.entries.items()
            ]
            return CommandOutput(0, json.dumps(rows).encode("utf-8"))
        if verb == "add":
            command = argv[argv.index("--") + 1 :]
            self.entries[argv[3]] = json.dumps(
                {"command": command[0], "args": list(command[1:])}
            ).encode("utf-8")
            return CommandOutput(0, b"")
        if verb == "remove":
            self.entries.pop(argv[3], None)
            return CommandOutput(0, b"")
        raise AssertionError(f"unexpected host command: {argv}")


def _home_with_legacy_grant(tmp_path: Path, *, trusted: int = 0) -> tuple[Path, Path]:
    """A Codex home whose trusted project A keeps Yoetz 0.2's exact approval table."""

    from finishup.adapters.integrations.host_admission import CODEX_LEGACY_ADMISSION_TABLES

    home, project = tmp_path / "home", tmp_path / "a"
    home.mkdir(mode=0o700)
    (project / ".codex").mkdir(parents=True, mode=0o700)
    rows = [f'[projects."{project}"]\ntrust_level = "trusted"\n']
    for index in range(trusted):
        other = tmp_path / f"other-{index:02d}"
        other.mkdir(mode=0o700)
        rows.append(f'[projects."{other}"]\ntrust_level = "trusted"\n')
    (home / "config.toml").write_text("\n".join(rows), encoding="utf-8")
    (project / ".codex" / "config.toml").write_text(
        CODEX_LEGACY_ADMISSION_TABLES[0], encoding="utf-8"
    )
    return home, project


def test_a_legacy_entry_a_project_still_needs_is_kept_beside_finishup(tmp_path: Path) -> None:
    """A Yoetz 0.2 ``integrate codex admission grant`` left ``[mcp_servers.yoetz.tools.check]``
    in A. Migrating the user-level ``yoetz`` entry would leave that table without a transport,
    and Codex would refuse to load A's configuration. The adapter keeps it beside ``finishup``."""

    home, project = _home_with_legacy_grant(tmp_path)
    host = _KeyedHost(legacy=_legacy_entry())
    adapter = CodexMcpAdapter(host, codex_home=home)

    preview = anyio.run(lambda: adapter.preview_registration(_BINARY))

    assert preview.action is McpRegistrationAction.REREGISTER
    assert preview.legacy_registration == "legacy_only"
    assert preview.legacy_kept_for == (str(project),)
    assert preview.legacy_kept_unchecked is False
    assert "legacy_registration_kept" in preview.warnings
    anyio.run(
        lambda: adapter.apply_registration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert _mutations(host.calls) == [
        ("/opt/harness/bin/codex", "mcp", "add", "finishup", "--", *MCP_SERVE_COMMAND)
    ]
    assert set(host.entries) == {"finishup", "yoetz"}
    # Nothing is left to migrate while A still needs it: connecting again changes nothing.
    again = anyio.run(lambda: adapter.preview_registration(_BINARY))
    assert again.action is McpRegistrationAction.NOOP
    assert again.legacy_registration == "duplicate"
    assert again.legacy_kept_for == (str(project),)


def test_the_kept_legacy_decision_is_bound_in_the_digest(tmp_path: Path) -> None:
    home, project = _home_with_legacy_grant(tmp_path)
    host = _KeyedHost(legacy=_legacy_entry())
    adapter = CodexMcpAdapter(host, codex_home=home)
    kept = anyio.run(lambda: adapter.preview_registration(_BINARY))
    assert kept.legacy_kept_for == (str(project),)

    # A's table goes (an admission revoke): the approved "keep" no longer describes the home.
    (project / ".codex" / "config.toml").write_text("", encoding="utf-8")
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: adapter.apply_registration(
                _BINARY, McpRegistrationCommand(kept.preview_digest, True)
            )
        )
    assert caught.value.reason is McpRegistrationReason.PREVIEW_STALE
    assert _mutations(host.calls) == []

    migrate = anyio.run(lambda: adapter.preview_registration(_BINARY))
    assert migrate.legacy_kept_for == ()
    assert "legacy_registration_kept" not in migrate.warnings
    assert migrate.preview_digest != kept.preview_digest
    anyio.run(
        lambda: adapter.apply_registration(
            _BINARY, McpRegistrationCommand(migrate.preview_digest, True)
        )
    )
    assert _mutations(host.calls) == [
        ("/opt/harness/bin/codex", "mcp", "add", "finishup", "--", *MCP_SERVE_COMMAND),
        ("/opt/harness/bin/codex", "mcp", "remove", "yoetz"),
    ]
    assert set(host.entries) == {"finishup"}


def test_a_kept_entry_on_another_review_mode_is_named(tmp_path: Path) -> None:
    home, _project = _home_with_legacy_grant(tmp_path)
    adapter = CodexMcpAdapter(
        _KeyedHost(legacy=_legacy_entry()), route_profile="strict", codex_home=home
    )

    preview = anyio.run(lambda: adapter.preview_registration(_BINARY))

    # The kept ``yoetz`` entry would go on serving its own (policy) route beside a strict
    # ``finishup``: the preview says so, and the front ends stop on it.
    assert "legacy_registration_route_kept" in preview.warnings
    assert preview.legacy_route_profile == "policy"


def test_a_home_with_many_known_projects_still_migrates(tmp_path: Path) -> None:
    """Every known project is read for this decision (no 32-project window): a home with more
    projects than that, none of which needs the ``yoetz`` key, migrates it (#1073 round 3)."""

    home, project = _home_with_legacy_grant(tmp_path, trusted=40)
    (project / ".codex" / "config.toml").write_text("", encoding="utf-8")
    host = _KeyedHost(legacy=_legacy_entry())
    adapter = CodexMcpAdapter(host, codex_home=home)

    preview = anyio.run(lambda: adapter.preview_registration(_BINARY))

    assert preview.legacy_kept_for == ()
    assert preview.legacy_kept_unchecked is False
    assert preview.warnings == ("legacy_registration_owned",)
    anyio.run(
        lambda: adapter.apply_registration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert set(host.entries) == {"finishup"}


def test_a_dependent_past_the_first_32_projects_is_still_found(tmp_path: Path) -> None:
    from finishup.adapters.integrations.host_admission import CODEX_LEGACY_ADMISSION_TABLES

    home, project = _home_with_legacy_grant(tmp_path, trusted=40)
    (project / ".codex" / "config.toml").write_text("", encoding="utf-8")
    last = tmp_path / "zz-last"
    (last / ".codex").mkdir(parents=True, mode=0o700)
    (last / ".codex" / "config.toml").write_text(CODEX_LEGACY_ADMISSION_TABLES[0])
    with (home / "config.toml").open("a", encoding="utf-8") as handle:
        handle.write(f'\n[projects."{last}"]\ntrust_level = "trusted"\n')

    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _KeyedHost(legacy=_legacy_entry()), codex_home=home
        ).preview_registration(_BINARY)
    )

    assert preview.legacy_kept_for == (str(last),)
    assert preview.legacy_kept_unchecked is False


def test_an_unreadable_home_config_keeps_the_entry_and_says_why(tmp_path: Path) -> None:
    """Only a genuinely unreadable input leaves the decision unchecked; the preview names it."""

    home, project = _home_with_legacy_grant(tmp_path)
    (project / ".codex" / "config.toml").write_text("", encoding="utf-8")
    config = home / "config.toml"
    real = tmp_path / "dotfiles-config.toml"
    real.write_text(config.read_text(), encoding="utf-8")
    config.unlink()
    config.symlink_to(real)
    host = _KeyedHost(legacy=_legacy_entry())
    adapter = CodexMcpAdapter(host, codex_home=home)

    preview = anyio.run(lambda: adapter.preview_registration(_BINARY))

    assert preview.legacy_kept_unchecked is True
    assert preview.legacy_kept_unread == ("user_config_unreadable",)
    anyio.run(
        lambda: adapter.apply_registration(
            _BINARY, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert set(host.entries) == {"finishup", "yoetz"}


def test_an_unreadable_project_config_is_kept_for_and_named_unreadable(tmp_path: Path) -> None:
    home, project = _home_with_legacy_grant(tmp_path)
    real = tmp_path / "shared.toml"
    real.write_text('model = "o3"\n', encoding="utf-8")
    (project / ".codex" / "config.toml").unlink()
    (project / ".codex" / "config.toml").symlink_to(real)

    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _KeyedHost(legacy=_legacy_entry()), codex_home=home
        ).preview_registration(_BINARY)
    )

    assert preview.legacy_kept_for == (str(project),)
    assert preview.legacy_kept_unreadable == (str(project),)
    assert preview.legacy_kept_unchecked is False


def test_a_control_character_project_path_never_fails_the_preview(tmp_path: Path) -> None:
    """A trusted path with a control character is not read and never echoed: the entry stays,
    with a bounded reason, and the preview itself still works (#1073 round 3)."""

    from finishup.adapters.integrations.host_admission import CODEX_LEGACY_ADMISSION_TABLES

    home, project = _home_with_legacy_grant(tmp_path)
    (project / ".codex" / "config.toml").write_text("", encoding="utf-8")
    weird = tmp_path / "a\tb"
    (weird / ".codex").mkdir(parents=True, mode=0o700)
    (weird / ".codex" / "config.toml").write_text(CODEX_LEGACY_ADMISSION_TABLES[0])
    with (home / "config.toml").open("a", encoding="utf-8") as handle:
        handle.write('\n[projects."' + str(weird).replace("\t", "\\t") + '"]\n')
        handle.write('trust_level = "trusted"\n')

    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _KeyedHost(legacy=_legacy_entry()), codex_home=home
        ).preview_registration(_BINARY)
    )

    assert preview.legacy_kept_for == ()
    assert preview.legacy_kept_unread == ("project_path_unsafe",)
    assert preview.legacy_kept_unchecked is True


def test_no_project_needing_the_legacy_key_leaves_the_migration_unchanged(
    tmp_path: Path,
) -> None:
    home, project = _home_with_legacy_grant(tmp_path)
    # Only an exact FinishUP table: it needs ``finishup``, which the migration registers.
    from finishup.adapters.integrations.host_admission import CODEX_EXTERNAL_ADMISSION_TABLE

    (project / ".codex" / "config.toml").write_text(
        CODEX_EXTERNAL_ADMISSION_TABLE, encoding="utf-8"
    )
    preview = anyio.run(
        lambda: CodexMcpAdapter(
            _KeyedHost(legacy=_legacy_entry()), codex_home=home
        ).preview_registration(_BINARY)
    )
    assert preview.legacy_kept_for == ()
    assert preview.warnings == ("legacy_registration_owned",)
