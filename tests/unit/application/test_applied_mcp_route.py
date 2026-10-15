"""Applied Codex MCP route record: roundtrip, corruption, permissions, and leakage."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Literal

import anyio
import pytest

from finishup.application.applied_mcp_route import (
    clear_applied_route,
    read_applied_route,
    record_applied_route,
)
from finishup.application.harness_mcp import HarnessMcpService, McpRegistrationConfirmation
from finishup.ports.harness_mcp import (
    MCP_SERVE_COMMAND,
    MCP_STRICT_SERVE_COMMAND,
    HarnessBinary,
    McpRegistrationAction,
    McpRegistrationCommand,
    McpRegistrationError,
    McpRegistrationObservation,
    McpRegistrationPreview,
    McpRegistrationReason,
    McpRegistrationResult,
    McpRegistrationState,
)
from finishup.ports.integrations import HarnessId
from finishup.protocol.canonical import canonical_digest, canonical_encode

_DIGEST = "sha256:" + "a" * 64
_OTHER_DIGEST = "sha256:" + "b" * 64
_BINARY = HarnessBinary(
    harness_id=HarnessId.CODEX,
    executable_path="/opt/harness/bin/codex",
    reported_version=None,
    compatibility="untested",
)
_STORE_RELATIVE = Path("integrations") / "applied-mcp-routes.json"


def _store_file(state: Path) -> Path:
    return state / _STORE_RELATIVE


def test_record_read_roundtrip_policy(tmp_path: Path) -> None:
    record = record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        _DIGEST,
        _state=tmp_path,
    )
    assert record["schema"] == "yoetz.applied-mcp-route/1"
    assert record["host"] == "codex"
    assert record["applied_profile"] == "policy"
    assert record["applied_serve_command"] == list(MCP_SERVE_COMMAND)
    assert record["observed_serve_command_post_write"] == list(MCP_SERVE_COMMAND)
    assert record["preview_digest"] == _DIGEST
    assert record["observation_digest"] == canonical_digest(list(MCP_SERVE_COMMAND))
    assert isinstance(record["applied_at"], str) and record["applied_at"].endswith("Z")
    # The tamper-evident digest binds the domain-separated canonical body.
    body = {key: value for key, value in record.items() if key != "record_digest"}
    expected = (
        "sha256:"
        + hashlib.sha256(
            b"yoetz/applied-mcp-route/v1\x00" + canonical_encode(body)  # type: ignore[arg-type]
        ).hexdigest()
    )
    assert record["record_digest"] == expected
    assert read_applied_route(_state=tmp_path) == record


def test_record_with_unobserved_post_write_command(tmp_path: Path) -> None:
    record = record_applied_route(
        "strict",
        list(MCP_STRICT_SERVE_COMMAND),
        None,
        _OTHER_DIGEST,
        _state=tmp_path,
    )
    assert record["observed_serve_command_post_write"] is None
    assert record["observation_digest"] == canonical_digest(None)
    assert read_applied_route(_state=tmp_path) == record


def test_missing_route_reads_as_none(tmp_path: Path) -> None:
    assert read_applied_route(_state=tmp_path) is None


def test_corrupt_store_reads_as_none(tmp_path: Path) -> None:
    path = _store_file(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\x00\x01not-json")
    assert read_applied_route(_state=tmp_path) is None


def test_tampered_record_reads_as_none(tmp_path: Path) -> None:
    record_applied_route(
        "policy", list(MCP_SERVE_COMMAND), list(MCP_SERVE_COMMAND), _DIGEST, _state=tmp_path
    )
    path = _store_file(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["codex"]["applied_profile"] = "strict"
    path.write_text(json.dumps(document), encoding="utf-8")
    assert read_applied_route(_state=tmp_path) is None


def test_wrong_schema_reads_as_none(tmp_path: Path) -> None:
    path = _store_file(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"codex":{"schema":"yoetz.other/1"}}')
    assert read_applied_route(_state=tmp_path) is None


def test_symlinked_store_reads_as_none(tmp_path: Path) -> None:
    record_applied_route(
        "policy", list(MCP_SERVE_COMMAND), list(MCP_SERVE_COMMAND), _DIGEST, _state=tmp_path
    )
    path = _store_file(tmp_path)
    raw = path.read_bytes()
    path.unlink()
    outside = tmp_path / "outside.json"
    outside.write_bytes(raw)
    path.symlink_to(outside)
    assert read_applied_route(_state=tmp_path) is None


def test_clear_removes_the_record_and_tolerates_absence(tmp_path: Path) -> None:
    record_applied_route(
        "policy", list(MCP_SERVE_COMMAND), list(MCP_SERVE_COMMAND), _DIGEST, _state=tmp_path
    )
    assert _store_file(tmp_path).exists()
    clear_applied_route(_state=tmp_path)
    assert read_applied_route(_state=tmp_path) is None
    assert not _store_file(tmp_path).exists()
    clear_applied_route(_state=tmp_path)


def test_clear_without_record_creates_no_state(tmp_path: Path) -> None:
    clear_applied_route(_state=tmp_path)
    assert not (tmp_path / "integrations").exists()


def test_strict_registration_overwrites_policy(tmp_path: Path) -> None:
    record_applied_route(
        "policy", list(MCP_SERVE_COMMAND), list(MCP_SERVE_COMMAND), _DIGEST, _state=tmp_path
    )
    record_applied_route(
        "strict",
        list(MCP_STRICT_SERVE_COMMAND),
        list(MCP_STRICT_SERVE_COMMAND),
        _OTHER_DIGEST,
        _state=tmp_path,
    )
    record = read_applied_route(_state=tmp_path)
    assert record is not None
    assert record["applied_profile"] == "strict"
    assert record["applied_serve_command"] == list(MCP_STRICT_SERVE_COMMAND)
    assert record["preview_digest"] == _OTHER_DIGEST


def test_store_permissions_are_owner_only(tmp_path: Path) -> None:
    record_applied_route(
        "policy", list(MCP_SERVE_COMMAND), list(MCP_SERVE_COMMAND), _DIGEST, _state=tmp_path
    )
    path = _store_file(tmp_path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_store_carries_no_paths_or_config_text(tmp_path: Path) -> None:
    record_applied_route(
        "policy", list(MCP_SERVE_COMMAND), list(MCP_SERVE_COMMAND), _DIGEST, _state=tmp_path
    )
    raw = _store_file(tmp_path).read_bytes()
    assert b"yoetz.applied-mcp-route/1" in raw
    assert raw.count(b"sha256:") >= 3
    assert b"config.toml" not in raw
    assert b"/opt/harness/bin/codex" not in raw
    assert b"secret" not in raw.lower()


def test_invalid_inputs_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="applied_mcp_route_profile_invalid"):
        record_applied_route(
            "unknown",
            list(MCP_SERVE_COMMAND),
            list(MCP_SERVE_COMMAND),
            _DIGEST,
            _state=tmp_path,
        )
    with pytest.raises(ValueError, match="applied_mcp_route_command_invalid"):
        # A strict record must carry the strict argv, never the policy one.
        record_applied_route(
            "strict",
            list(MCP_SERVE_COMMAND),
            list(MCP_SERVE_COMMAND),
            _DIGEST,
            _state=tmp_path,
        )
    with pytest.raises(ValueError, match="applied_mcp_route_command_invalid"):
        record_applied_route(
            "policy",
            list(MCP_SERVE_COMMAND),
            ["evil", "argv"],
            _DIGEST,
            _state=tmp_path,
        )
    with pytest.raises(ValueError, match="applied_mcp_route_digest_invalid"):
        record_applied_route(
            "policy",
            list(MCP_SERVE_COMMAND),
            list(MCP_SERVE_COMMAND),
            "not-a-digest",
            _state=tmp_path,
        )
    assert read_applied_route(_state=tmp_path) is None


class _RoutePort:
    """Harness port with a configurable observed route profile."""

    _profile: Literal["policy", "strict"]
    _already_owned: bool
    _observe_fails: bool

    def __init__(
        self,
        profile: Literal["policy", "strict"] = "policy",
        *,
        already_owned: bool = False,
        observe_fails: bool = False,
    ) -> None:
        self._profile = profile
        self._already_owned = already_owned
        self._observe_fails = observe_fails

    def _serve_command(self) -> tuple[str, ...]:
        return MCP_STRICT_SERVE_COMMAND if self._profile == "strict" else MCP_SERVE_COMMAND

    async def status_registration(self, binary: HarnessBinary) -> McpRegistrationState:
        del binary
        return (
            McpRegistrationState.FINISHUP_OWNED
            if self._already_owned
            else McpRegistrationState.ABSENT
        )

    async def observe_registration(self, binary: HarnessBinary) -> McpRegistrationObservation:
        if self._observe_fails:
            raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {})
        return McpRegistrationObservation(
            binary.harness_id,
            McpRegistrationState.FINISHUP_OWNED,
            self._profile,
            "ambient",
        )

    async def preview_registration(self, binary: HarnessBinary) -> McpRegistrationPreview:
        state = await self.status_registration(binary)
        return McpRegistrationPreview(
            binary.harness_id,
            McpRegistrationAction.NOOP if self._already_owned else McpRegistrationAction.REGISTER,
            state,
            (),
            _DIGEST,
            self._serve_command(),
            self._profile,
        )

    async def apply_registration(
        self,
        binary: HarnessBinary,
        command: McpRegistrationCommand,
    ) -> McpRegistrationResult:
        del command
        if self._already_owned:
            return McpRegistrationResult(
                binary.harness_id,
                McpRegistrationAction.NOOP,
                McpRegistrationState.FINISHUP_OWNED,
                McpRegistrationState.FINISHUP_OWNED,
                _DIGEST,
            )
        return McpRegistrationResult(
            binary.harness_id,
            McpRegistrationAction.REGISTER,
            McpRegistrationState.ABSENT,
            McpRegistrationState.FINISHUP_OWNED,
            _DIGEST,
        )

    async def preview_unregistration(self, binary: HarnessBinary) -> McpRegistrationPreview:
        return McpRegistrationPreview(
            binary.harness_id,
            McpRegistrationAction.UNREGISTER,
            McpRegistrationState.FINISHUP_OWNED,
            (),
            _DIGEST,
            self._serve_command(),
            self._profile,
        )

    async def apply_unregistration(
        self,
        binary: HarnessBinary,
        command: McpRegistrationCommand,
    ) -> McpRegistrationResult:
        del command
        return McpRegistrationResult(
            binary.harness_id,
            McpRegistrationAction.UNREGISTER,
            McpRegistrationState.FINISHUP_OWNED,
            McpRegistrationState.ABSENT,
            _DIGEST,
        )


def _confirmation() -> McpRegistrationConfirmation:
    return McpRegistrationConfirmation(_DIGEST, True, "noninteractive_flag")


def test_service_register_records_the_observed_route(tmp_path: Path) -> None:
    service = HarnessMcpService(_RoutePort("policy"))
    result = anyio.run(lambda: service.register(_BINARY, _confirmation(), _state=tmp_path))
    assert result.state_after is McpRegistrationState.FINISHUP_OWNED
    record = read_applied_route(_state=tmp_path)
    assert record is not None
    assert record["applied_profile"] == "policy"
    assert record["applied_serve_command"] == list(MCP_SERVE_COMMAND)
    assert record["preview_digest"] == _DIGEST


def test_service_strict_reregistration_overwrites_policy(tmp_path: Path) -> None:
    anyio.run(
        lambda: HarnessMcpService(_RoutePort("policy")).register(
            _BINARY, _confirmation(), _state=tmp_path
        )
    )
    anyio.run(
        lambda: HarnessMcpService(_RoutePort("strict")).register(
            _BINARY, _confirmation(), _state=tmp_path
        )
    )
    record = read_applied_route(_state=tmp_path)
    assert record is not None
    assert record["applied_profile"] == "strict"
    assert record["applied_serve_command"] == list(MCP_STRICT_SERVE_COMMAND)


def test_service_noop_register_still_records_the_route(tmp_path: Path) -> None:
    """A NOOP register leaves the host on the accepted route, so the record must agree.

    Skipping it left an earlier entry behind, and every later status then reported drift
    against the very route the owner had just re-accepted (issue #537).
    """

    service = HarnessMcpService(_RoutePort("policy", already_owned=True))
    result = anyio.run(lambda: service.register(_BINARY, _confirmation(), _state=tmp_path))
    assert result.action is McpRegistrationAction.NOOP
    record = read_applied_route(_state=tmp_path)
    assert record is not None
    assert record["applied_profile"] == "policy"


def test_service_reconcile_overwrites_a_stale_record(tmp_path: Path) -> None:
    """The CLI's own NOOP short-circuits never reach `register`, so they call this."""

    record_applied_route(
        "policy", list(MCP_SERVE_COMMAND), list(MCP_SERVE_COMMAND), _DIGEST, _state=tmp_path
    )
    service = HarnessMcpService(_RoutePort("strict", already_owned=True))
    preview = anyio.run(lambda: service.preview(_BINARY))
    assert preview.action is McpRegistrationAction.NOOP
    service.reconcile_applied_route(_BINARY, preview, _state=tmp_path)
    record = read_applied_route(_state=tmp_path)
    assert record is not None
    assert record["applied_profile"] == "strict"


def test_service_unregister_clears_the_record(tmp_path: Path) -> None:
    record_applied_route(
        "policy", list(MCP_SERVE_COMMAND), list(MCP_SERVE_COMMAND), _DIGEST, _state=tmp_path
    )
    service = HarnessMcpService(_RoutePort("policy"))
    result = anyio.run(lambda: service.unregister(_BINARY, _confirmation(), _state=tmp_path))
    assert result.state_after is McpRegistrationState.ABSENT
    assert read_applied_route(_state=tmp_path) is None


def test_service_register_survives_persistence_failure(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_bytes(b"unrelated")
    service = HarnessMcpService(_RoutePort("policy"))
    result = anyio.run(lambda: service.register(_BINARY, _confirmation(), _state=blocker))
    assert result.state_after is McpRegistrationState.FINISHUP_OWNED


def test_service_register_survives_observation_failure(tmp_path: Path) -> None:
    service = HarnessMcpService(_RoutePort("policy", observe_fails=True))
    result = anyio.run(lambda: service.register(_BINARY, _confirmation(), _state=tmp_path))
    assert result.state_after is McpRegistrationState.FINISHUP_OWNED
    assert read_applied_route(_state=tmp_path) is None


def test_service_strict_register_with_observe_failure_clears_stale_policy(
    tmp_path: Path,
) -> None:
    """A failed strict post-write verification must not leave a stale policy record (B4).

    The install itself still succeeds (fail-soft); only the durable record is
    cleared so later drift cannot compare against a route this install did not verify.
    """

    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        _DIGEST,
        _state=tmp_path,
    )
    assert read_applied_route(_state=tmp_path) is not None
    service = HarnessMcpService(_RoutePort("strict", observe_fails=True))
    result = anyio.run(lambda: service.register(_BINARY, _confirmation(), _state=tmp_path))
    assert result.state_after is McpRegistrationState.FINISHUP_OWNED
    assert read_applied_route(_state=tmp_path) is None


def test_service_never_records_a_non_codex_route(tmp_path: Path) -> None:
    foreign = HarnessBinary(
        harness_id=HarnessId.CURSOR,
        executable_path="/opt/harness/bin/cursor",
        reported_version=None,
        compatibility="untested",
    )
    service = HarnessMcpService(_RoutePort("policy"))
    result = anyio.run(lambda: service.register(foreign, _confirmation(), _state=tmp_path))
    assert result.state_after is McpRegistrationState.FINISHUP_OWNED
    assert read_applied_route(_state=tmp_path) is None


@pytest.mark.parametrize(
    "launcher", ["yoetz", "/opt/runtime/bin/yoetz", "finishup", "/opt/runtime/bin/finishup"]
)
def test_record_written_with_either_launcher_spelling_reads_back(
    tmp_path: Path, launcher: str
) -> None:
    """Stored records from before the rename name the ``yoetz`` launcher (ADR-048)."""

    command = [launcher, *MCP_SERVE_COMMAND[1:]]
    record = record_applied_route("policy", command, command, _DIGEST, _state=tmp_path)
    assert read_applied_route(_state=tmp_path) == record
    assert record["applied_serve_command"] == command


def test_record_refuses_an_unknown_bare_launcher(tmp_path: Path) -> None:
    command = ["yoetz-server", *MCP_SERVE_COMMAND[1:]]
    with pytest.raises(ValueError, match="applied_mcp_route_command_invalid"):
        record_applied_route("policy", command, command, _DIGEST, _state=tmp_path)
