"""Exercise the real adapter/service/CLI chain with bounded host responses."""

import json
import shlex
from pathlib import Path

import anyio
import pytest

from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter, CommandOutput
from finishup.application.applied_mcp_route import read_applied_route, record_applied_route
from finishup.cli import setup
from finishup.ports.harness_mcp import MCP_SERVE_COMMAND, HarnessBinary
from finishup.ports.integrations import HarnessId
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import validate_schema_instance


@pytest.mark.parametrize("post_state", ["absent", "yoetz_owned", "foreign_present", "unreadable"])
@pytest.mark.parametrize("exit_code", [0, 1])
def test_remove_json_exit_and_bookkeeping_agree(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    post_state: str,
    exit_code: int,
) -> None:
    binary = HarnessBinary(HarnessId.CODEX, "/opt/test codex", "0.153.4", "untested")
    owned = CommandOutput(
        0, json.dumps({"command": "finishup", "args": list(MCP_SERVE_COMMAND[1:])}).encode()
    )
    calls: list[tuple[str, ...]] = []
    post = {
        "absent": [CommandOutput(1, b""), CommandOutput(0, b"[]")],
        "yoetz_owned": [owned],
        "foreign_present": [CommandOutput(0, b'{"command":"foreign"}')],
        "unreadable": [CommandOutput(1, b""), CommandOutput(1, b"private-host-payload")],
    }[post_state]
    outputs = [owned, owned, owned, owned, CommandOutput(exit_code, b"private-host-payload"), *post]

    found = False

    def runner(argv: tuple[str, ...]) -> CommandOutput:
        nonlocal found
        calls.append(argv)
        if argv[1:3] == ("mcp", "list") and found:
            # The legacy ``yoetz`` key read that follows a found entry (ADR-048): none here.
            found = False
            return CommandOutput(0, b"[]")
        output = outputs.pop(0)
        found = argv[1:3] == ("mcp", "get") and output.exit_code == 0
        return output

    adapter = CodexMcpAdapter(runner)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", lambda: None)
    monkeypatch.setattr(setup, "discover_codex_binaries", lambda: (binary,))

    def selected_adapter(*_args: object, **_kwargs: object) -> CodexMcpAdapter:
        return adapter

    monkeypatch.setattr(setup, "_mcp_adapter", selected_adapter)
    monkeypatch.setattr(setup, "_is_interactive_terminal", lambda: False)
    preview = anyio.run(lambda: adapter.preview_unregistration(binary))
    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        preview.preview_digest,
        _state=tmp_path,
    )
    code = anyio.run(
        lambda: setup.integrate_mcp(
            "remove",
            "codex",
            codex_path=None,
            codex_home=tmp_path / "codex home",
            accept=True,
            preview_digest=preview.preview_digest,
            json_output=True,
            _state=tmp_path,
        )
    )
    captured = capsys.readouterr()
    body = json.loads(captured.out)
    removal = body["removal"]
    validate_schema_instance("mcp-removal", "1.0.0", removal)
    assert removal["warnings"] == (["host_remove_returned_nonzero"] if exit_code else [])
    assert "private-host-payload" not in captured.out + captured.err
    assert sum(call[1:3] == ("mcp", "remove") for call in calls) == 1
    assert not outputs
    if post_state == "absent":
        assert code == 0
        assert body["action"] == "unregister"
        assert body["state_after"] == removal["state_after"] == "absent"
        assert removal["outcome"] == "completed"
        assert read_applied_route(_state=tmp_path) is None
    else:
        assert code == 20
        assert removal["outcome"] == "unverified"
        assert removal["state_after"] == (None if post_state == "unreadable" else post_state)
        assert removal["next_action"] == "inspect_registration"
        assert read_applied_route(_state=tmp_path) is not None
        continuation = shlex.split(body["next_command"])
        assert continuation[-9:] == [
            "integrate",
            "codex",
            "mcp",
            "status",
            "--codex-path",
            binary.executable_path,
            "--codex-home",
            str(tmp_path / "codex home"),
            "--json",
        ]
        assert "mcp_registration_registration_failed" in captured.err


def test_mcp_removal_golden_vectors() -> None:
    root = Path(__file__).resolve().parents[3]
    vectors = json.loads((root / "fixtures/integrations/mcp-removal.case.json").read_bytes())
    for report in vectors["reports"]:
        validate_schema_instance("mcp-removal", "1.0.0", report)


@pytest.mark.parametrize(
    "field,value",
    [
        ("state_after", "foreign_present"),
        ("warnings", ["untrusted-host-message"]),
        ("warnings", ["host_remove_returned_nonzero", "host_remove_returned_nonzero"]),
    ],
)
def test_completed_removal_contract_rejects_false_absence_and_host_payloads(
    field: str,
    value: JsonValue,
) -> None:
    report: dict[str, JsonValue] = {
        "schema": "yoetz.mcp-removal/1",
        "outcome": "completed",
        "state_after": "absent",
        "warnings": [],
        "next_action": None,
    }
    report[field] = value
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("mcp-removal", "1.0.0", report)
