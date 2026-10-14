"""Registration-drift tests (issue #537).

Covers the closed diagnostic token, ``mcp status --json`` drift fields, the bridge-startup
drift comparison that is the sole emitter, and the hook path's deliberate silence. Every
writer here is synchronous, so assertions read the bounded file directly rather than
waiting or sleeping.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.applied_mcp_route import read_applied_route, record_applied_route
from finishup.cli import setup as setup_cli
from finishup.cli.hook_diagnostics import record_hook_diagnostic
from finishup.mcp.server import record_startup_route_drift
from finishup.ports.harness_mcp import (
    MCP_SERVE_COMMAND,
    MCP_STRICT_SERVE_COMMAND,
    HarnessBinary,
    McpRegistrationAction,
    McpRegistrationObservation,
    McpRegistrationPreview,
    McpRegistrationState,
)
from finishup.ports.integrations import HarnessId

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "a" * 64
_BINARY = HarnessBinary(
    harness_id=HarnessId.CODEX,
    executable_path="/opt/harness/bin/codex",
    reported_version=None,
    compatibility="untested",
)


def _diagnostic_path(state: Path) -> Path:
    return state / "observation" / "hook-diagnostics.jsonl"


def _reasons_in(state: Path) -> list[str]:
    """Return every recorded reason. The writer is synchronous, so no waiting is needed."""

    path = _diagnostic_path(state)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    reasons: list[str] = []
    for line in text.splitlines():
        try:
            row: object = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            reason: object = cast(dict[str, object], row).get("reason")
            if isinstance(reason, str):
                reasons.append(reason)
    return reasons


def test_registration_drift_is_a_closed_diagnostic_token(tmp_path: Path) -> None:
    record_hook_diagnostic("registration_drift", "mcp_serve", _state=tmp_path)
    assert _reasons_in(tmp_path) == ["registration_drift"]
    row = json.loads(_diagnostic_path(tmp_path).read_text(encoding="utf-8").splitlines()[-1])
    assert set(row) == {"event", "reason", "ts"}
    # `mcp_serve` is a closed token: an unknown event would be recorded as `unknown_event`.
    assert row["event"] == "mcp_serve"
    assert row["reason"] == "registration_drift"


def _observation_with_state(
    state: McpRegistrationState, profile: str | None
) -> McpRegistrationObservation:
    return McpRegistrationObservation(
        HarnessId.CODEX,
        state,
        profile,  # type: ignore[arg-type]
        "ambient" if profile is not None else None,
    )


async def _status_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    registered: str | None,
    applied: str | None,
    state: McpRegistrationState = McpRegistrationState.FINISHUP_OWNED,
) -> dict[str, Any]:
    if applied is not None:
        serve = MCP_STRICT_SERVE_COMMAND if applied == "strict" else MCP_SERVE_COMMAND
        record_applied_route(applied, list(serve), list(serve), _DIGEST, _state=tmp_path)
    monkeypatch.setattr(setup_cli, "discover_codex_binaries", lambda: (_BINARY,))

    async def _fake_observe(self: object, _binary: object) -> McpRegistrationObservation:
        return _observation_with_state(state, registered)

    monkeypatch.setattr("finishup.application.harness_mcp.HarnessMcpService.observe", _fake_observe)
    captured: dict[str, Any] = {}

    def _capture(value: object, *, json_output: bool) -> None:
        del json_output
        assert isinstance(value, dict)
        captured.update(cast(dict[str, Any], value))

    monkeypatch.setattr(setup_cli, "_emit", _capture)
    code = await setup_cli.integrate_mcp(
        "status",
        "codex",
        codex_path=None,
        accept=False,
        preview_digest=None,
        json_output=True,
        _state=tmp_path,
    )
    assert code == 0
    return captured


async def test_mcp_status_json_reports_drift_when_serving_differs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = await _status_json(monkeypatch, tmp_path, registered="strict", applied="policy")
    assert body["state"] == "yoetz_owned"
    assert body["route_profile"] == "strict"
    assert body["registered_profile"] == "strict"
    assert body["applied_profile"] == "policy"
    assert body["drift_since_install"] is True


async def test_mcp_status_json_reports_no_drift_when_profiles_match(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = await _status_json(monkeypatch, tmp_path, registered="policy", applied="policy")
    assert body["applied_profile"] == "policy"
    assert body["drift_since_install"] is False


async def test_mcp_status_json_without_record_has_no_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = await _status_json(monkeypatch, tmp_path, registered="policy", applied=None)
    assert body["applied_profile"] is None
    assert body["drift_since_install"] is False


async def test_mcp_status_json_absent_with_policy_record_has_no_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ABSENT (registered None) with a policy record never reports drift (B1)."""

    body = await _status_json(
        monkeypatch,
        tmp_path,
        registered=None,
        applied="policy",
        state=McpRegistrationState.ABSENT,
    )
    assert body["state"] == "absent"
    assert body["registered_profile"] is None
    assert body["applied_profile"] == "policy"
    assert body["drift_since_install"] is False


async def test_mcp_status_json_foreign_with_policy_record_has_no_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """FOREIGN_PRESENT (registered None) with a policy record never reports drift (B1)."""

    body = await _status_json(
        monkeypatch,
        tmp_path,
        registered=None,
        applied="policy",
        state=McpRegistrationState.FOREIGN_PRESENT,
    )
    assert body["registered_profile"] is None
    assert body["applied_profile"] == "policy"
    assert body["drift_since_install"] is False


async def test_mcp_status_json_unowned_profile_none_with_policy_record_has_no_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Registered None (DUAL/FOREIGN shape) with a policy record never reports drift (B1)."""

    body = await _status_json(monkeypatch, tmp_path, registered=None, applied="policy")
    assert body["registered_profile"] is None
    assert body["applied_profile"] == "policy"
    assert body["drift_since_install"] is False


async def test_mcp_remove_noop_absent_clears_stale_record(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Policy record + manual host delete + `mcp remove` NOOP clears the record (M1)."""

    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        _DIGEST,
        _state=tmp_path,
    )
    assert read_applied_route(_state=tmp_path) is not None
    monkeypatch.setattr(setup_cli, "discover_codex_binaries", lambda: (_BINARY,))

    preview = McpRegistrationPreview(
        HarnessId.CODEX,
        McpRegistrationAction.NOOP,
        McpRegistrationState.ABSENT,
        (),
        _DIGEST,
        MCP_SERVE_COMMAND,
        "policy",
    )

    async def _fake_preview_unregistration(self: object, _binary: object) -> McpRegistrationPreview:
        return preview

    monkeypatch.setattr(
        "finishup.application.harness_mcp.HarnessMcpService.preview_unregistration",
        _fake_preview_unregistration,
    )
    captured: dict[str, Any] = {}

    def _capture(value: object, *, json_output: bool) -> None:
        del json_output
        assert isinstance(value, dict)
        captured.update(cast(dict[str, Any], value))

    monkeypatch.setattr(setup_cli, "_emit", _capture)
    code = await setup_cli.integrate_mcp(
        "remove",
        "codex",
        codex_path=None,
        accept=True,
        preview_digest=_DIGEST,
        json_output=True,
        _state=tmp_path,
    )
    assert code == 0
    assert captured.get("action") == "noop"
    # The stale policy record is gone, so later drift reads False.
    assert read_applied_route(_state=tmp_path) is None


async def test_mcp_install_noop_refreshes_a_stale_record(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A deliberate strict re-registration the host already satisfies must clear the drift.

    The record said `policy`; something reverted the host to strict; the owner accepted a
    strict install, which had nothing to write. Without refreshing the record here the
    stale `policy` entry reports drift against the route the owner just re-accepted.
    """

    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        _DIGEST,
        _state=tmp_path,
    )
    monkeypatch.setattr(setup_cli, "discover_codex_binaries", lambda: (_BINARY,))

    preview = McpRegistrationPreview(
        HarnessId.CODEX,
        McpRegistrationAction.NOOP,
        McpRegistrationState.FINISHUP_OWNED,
        (),
        _DIGEST,
        MCP_STRICT_SERVE_COMMAND,
        "strict",
    )

    async def _fake_preview(self: object, _binary: object) -> McpRegistrationPreview:
        return preview

    async def _fake_observe(self: object, _binary: object) -> McpRegistrationObservation:
        return _observation_with_state(McpRegistrationState.FINISHUP_OWNED, "strict")

    monkeypatch.setattr("finishup.application.harness_mcp.HarnessMcpService.preview", _fake_preview)
    monkeypatch.setattr("finishup.application.harness_mcp.HarnessMcpService.observe", _fake_observe)
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp.CodexMcpAdapter.observe_registration",
        _fake_observe,
    )

    def _discard(value: object, *, json_output: bool) -> None:
        del value, json_output

    monkeypatch.setattr(setup_cli, "_emit", _discard)

    code = await setup_cli.integrate_mcp(
        "install",
        "codex",
        codex_path=None,
        accept=True,
        preview_digest=_DIGEST,
        json_output=True,
        route_profile="strict",
        _state=tmp_path,
    )
    assert code == 0
    record = read_applied_route(_state=tmp_path)
    assert record is not None
    assert record["applied_profile"] == "strict"


def test_bridge_startup_emits_drift_on_mismatch(tmp_path: Path) -> None:
    """The MCP bridge is the sole emitter: it compares its own serving argv."""

    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        _DIGEST,
        _state=tmp_path,
    )
    record_startup_route_drift("strict", host_profile="codex", _state=tmp_path)
    assert _reasons_in(tmp_path) == ["registration_drift"]
    row = json.loads(_diagnostic_path(tmp_path).read_text(encoding="utf-8").splitlines()[-1])
    assert row["event"] == "mcp_serve"


def test_bridge_startup_emits_nothing_when_matching(tmp_path: Path) -> None:
    record_applied_route(
        "strict",
        list(MCP_STRICT_SERVE_COMMAND),
        list(MCP_STRICT_SERVE_COMMAND),
        _DIGEST,
        _state=tmp_path,
    )
    record_startup_route_drift("strict", host_profile="codex", _state=tmp_path)
    assert _reasons_in(tmp_path) == []


def test_bridge_startup_emits_nothing_without_record(tmp_path: Path) -> None:
    record_startup_route_drift("strict", host_profile="codex", _state=tmp_path)
    assert _reasons_in(tmp_path) == []


def test_bridge_startup_emits_nothing_for_an_unknown_serving_route(tmp_path: Path) -> None:
    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        _DIGEST,
        _state=tmp_path,
    )
    record_startup_route_drift("unknown", _state=tmp_path)
    assert _reasons_in(tmp_path) == []


@pytest.mark.parametrize("host_profile", ["generic", "claude", "cursor"])
def test_bridge_startup_does_not_compare_other_host_to_codex_record(
    host_profile: str, tmp_path: Path
) -> None:
    """Only an explicit Codex bridge may emit Codex registration drift."""

    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        _DIGEST,
        _state=tmp_path,
    )
    record_startup_route_drift("strict", host_profile=host_profile, _state=tmp_path)  # type: ignore[arg-type]
    assert _reasons_in(tmp_path) == []


def test_observe_session_start_runs_no_host_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The SessionStart hook path emits no drift and shells out to no host binary.

    A hook process has no serving route of its own, so the only comparison available
    there is a `codex mcp get` subprocess plus the PATH version probes needed to find
    the binary — more than the end-to-end hook budget can carry, and the #209-#213
    latency loop again. Discovery raising here is the guard: nothing may call it.
    """

    from finishup.cli.observe_hooks import handle_observe

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        _DIGEST,
        _state=tmp_path,
    )

    def _explode() -> tuple[object, ...]:
        raise AssertionError("a hook must not probe the host for the applied route")

    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_discovery.discover_codex_binaries", _explode
    )

    stdout = io.BytesIO()
    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": "drift-session", "hook_event_name": "SessionStart", "cwd": "."}
        ).encode(),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    # Output shape is unchanged: exactly one JSON object on stdout.
    json.loads(stdout.getvalue().decode("utf-8"))
    assert _reasons_in(tmp_path) == []
