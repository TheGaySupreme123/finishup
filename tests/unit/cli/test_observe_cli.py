"""Unit tests for observe CLI consent controls and path commitments."""

from __future__ import annotations

import errno
import io
import json
import os
import re
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from yoetz.adapters.check_sandbox import LinuxCheckSandbox
from yoetz.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.cli import observe as observe_cli
from yoetz.cli.app import app
from yoetz.cli.hook_diagnostics import record_hook_diagnostic
from yoetz.cli.observe_hooks import handle_observe
from yoetz.cli.render import local_recovery_json
from yoetz.domain.observation import (
    OBSERVATION_BACKPRESSURE_REASON,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestResult,
    ObservationLifecycle,
    ObservationStatusQuery,
    observation_ingest_result_to_json,
)
from yoetz.protocol.ids import IdKind, new_id

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _terminal_compact(text: str) -> str:
    """Normalize Rich styling and soft wraps before asserting CLI contract text."""

    return "".join(_ANSI_ESCAPE.sub("", text).split())


def test_grant_pause_resume_revoke_roundtrip(tmp_path: Path, capsys: object) -> None:
    workspace = str(tmp_path)
    assert observe_cli.grant_observation(workspace=workspace, _state=tmp_path) == 0
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "observation_consent_granted:hmac-sha256:" in out
    assert workspace not in out

    assert observe_cli.pause_observation(workspace=workspace, _state=tmp_path) == 0
    assert observe_cli.resume_observation(workspace=workspace, _state=tmp_path) == 0
    assert observe_cli.revoke_observation(workspace=workspace, _state=tmp_path) == 0

    code = observe_cli.observe_status(workspace=workspace, json_output=False, _state=tmp_path)
    assert code == 0
    status_out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "consent: revoked" in status_out
    assert ObservationLifecycle.STOPPED.value in status_out
    assert workspace not in status_out


def test_git_subdirectory_consent_and_hook_share_one_canonical_workspace(
    tmp_path: Path,
    capsys: object,
) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repo"
    nested = repository / "packages/app"
    nested.mkdir(parents=True)
    (repository / ".git").mkdir()

    assert observe_cli.grant_observation(workspace=str(nested), _state=state) == 0
    store = LocalObservationStore(_state=state)
    root_commitment = store.workspace_commitment(str(repository))
    subdirectory_commitment = store.workspace_commitment(str(nested))
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    unrelated_commitment = store.workspace_commitment(str(unrelated))
    store.grant_consent(unrelated_commitment)
    assert root_commitment != subdirectory_commitment
    consent = store.consent_for(root_commitment)
    assert consent is not None and consent.active
    assert store.consent_for(subdirectory_commitment) is None

    assert observe_cli.pause_observation(workspace=str(nested), _state=state) == 0
    assert observe_cli.resume_observation(workspace=str(nested), _state=state) == 0
    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": "git-subdir-session", "hook_event_name": "SessionStart"}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(nested),
        _state=state,
        skip_service=True,
    )
    assert code == 0
    assert store.find_workspace_for_codex_session("git-subdir-session") == root_commitment
    assert store.find_workspace_for_codex_session("git-subdir-session") != unrelated_commitment

    assert observe_cli.revoke_observation(workspace=str(nested), _state=state) == 0
    revoked = store.consent_for(root_commitment)
    assert revoked is not None and not revoked.active
    assert str(repository) not in capsys.readouterr().out  # type: ignore[attr-defined]


def test_non_git_hook_workspace_keeps_exact_locator_with_multiple_consents(tmp_path: Path) -> None:
    state = tmp_path / "state"
    workspace_path = tmp_path / "plain-workspace"
    unrelated = tmp_path / "unrelated"
    workspace_path.mkdir()
    unrelated.mkdir()
    store = LocalObservationStore(_state=state)
    workspace_commitment = store.workspace_commitment(str(workspace_path))
    store.grant_consent(workspace_commitment)
    store.grant_consent(store.workspace_commitment(str(unrelated)))

    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": "plain-workspace-session", "hook_event_name": "SessionStart"}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(workspace_path),
        _state=state,
        skip_service=True,
    )

    assert code == 0
    assert store.find_workspace_for_codex_session("plain-workspace-session") == workspace_commitment


def test_explicit_git_root_does_not_fall_back_to_legacy_subdirectory_consent(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repo"
    legacy_subdirectory = repository / "packages/app"
    legacy_subdirectory.mkdir(parents=True)
    (repository / ".git").mkdir()
    store = LocalObservationStore(_state=state)
    legacy_commitment = store.workspace_commitment(str(legacy_subdirectory))
    store.grant_consent(legacy_commitment)
    assert store.consent_for(store.workspace_commitment(str(repository))) is None

    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": "legacy-subdir-session", "hook_event_name": "SessionStart"}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(repository),
        _state=state,
        skip_service=True,
    )

    assert code == 0
    assert store.codex_sessions_for_workspace(legacy_commitment) == ()
    assert store.list_pending_outbox_rows(legacy_commitment) == ()


def test_workspace_commitment_stable_and_path_free(tmp_path: Path) -> None:
    from yoetz.adapters.integrations.observation_local import LocalObservationStore

    store = LocalObservationStore(_state=tmp_path)
    one = store.workspace_commitment(str(tmp_path.resolve()))
    two = store.workspace_commitment(str(tmp_path.resolve()))
    assert one == two
    assert one.startswith("hmac-sha256:")
    assert str(tmp_path) not in one


def test_status_separates_undelivered_from_lag_and_reports_ambiguous_activation(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_inspection(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("status must not inspect activation without an exact executable")

    monkeypatch.setattr(observe_cli, "inspect_activation", unexpected_inspection)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "status-session", "tool_name": "shell", "event_ordinal": 1}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    record_hook_diagnostic("service_unavailable", "PostToolUse", _state=tmp_path)

    assert (
        observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=tmp_path) == 0
    )
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["status"]["lag_events"] == 0
    assert payload["undelivered_count"] == 1
    assert payload["delivery_causes"] == {"not_attempted": 1}
    assert payload["pending_delivery_causes"] == {"not_attempted": 1}
    assert payload["last_successful_drain"] == "never"
    assert payload["mapping_present"] is False
    assert payload["plugin_activation"] == "unknown"
    unavailable = payload["hook_diagnostics"]["reasons"]["service_unavailable"]
    assert unavailable["count"] == 1
    # A live failure reads as live; a stale one is dated instead of tallied (#310).
    assert unavailable["recent"] == 1
    assert unavailable["first_seen"] == unavailable["last_seen"]
    assert payload["hook_diagnostics"]["recent_count"] == 1


def test_status_surfaces_quarantine_depth_and_reclaim_empties_it(
    tmp_path: Path, capsys: object
) -> None:
    """#211: quarantine is a first-class status line, and reclaim drops it loudly."""

    from yoetz.cli.observe_hooks import map_hook_payload_to_envelope

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "quarantine-cli")
    session = store.session_commitment("quarantine-cli")
    for ordinal in (1, 2):
        envelope = map_hook_payload_to_envelope(
            "PostToolUse",
            {"session_id": "quarantine-cli", "tool_name": "shell", "correlation_id": f"q{ordinal}"},
            session_commitment=session,
            event_ordinal=ordinal,
            key_material=store.key_material(),
        )
        store.ingest(envelope)
        store.enqueue_outbox(workspace, "quarantine-cli", envelope)
        assert store.quarantine_outbox(
            workspace,
            "quarantine-cli",
            envelope.source_identity,
            ObservationGapCode.LEDGER_REJECTED.value,
        )

    assert (
        observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=tmp_path) == 0
    )
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["quarantine_count"] == 2
    # Per-reason depth (#272): a destroyed-and-replaced event is visible as its
    # cause, not hidden inside one opaque number.
    assert payload["quarantine_causes"] == {ObservationGapCode.LEDGER_REJECTED.value: 2}
    assert payload["delivery_causes"] == {ObservationGapCode.LEDGER_REJECTED.value: 2}
    assert payload["pending_delivery_causes"] == {}
    assert payload["quarantine_evicted_count"] == 0

    assert (
        observe_cli.observe_status(workspace=str(tmp_path), json_output=False, _state=tmp_path) == 0
    )
    text = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "quarantine: 2" in text
    assert "cause: ledger_rejected=2" in text
    assert (
        "reclaim by changing to the selected workspace and running "
        "'yoetz observe reclaim --workspace .'"
    ) in text
    assert str(tmp_path) not in text

    assert (
        observe_cli.reclaim_observation(workspace=str(tmp_path), json_output=True, _state=tmp_path)
        == 0
    )
    reclaim_payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert reclaim_payload["reclaimed"] == 2
    assert reclaim_payload["quarantine_count"] == 0
    # A voluntary reclaim is never reported as involuntary eviction.
    assert reclaim_payload["quarantine_evicted_count"] == 0
    assert reclaim_payload["quarantine_reclaimed_count"] == 2
    assert str(tmp_path) not in json.dumps(reclaim_payload)

    assert (
        observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=tmp_path) == 0
    )
    after = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert after["quarantine_count"] == 0
    assert after["quarantine_evicted_count"] == 0
    assert after["quarantine_reclaimed_count"] == 2


def test_status_inspects_only_the_explicit_codex_target(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    codex_path = tmp_path / "bin" / "codex-testing"
    codex_home = tmp_path / ".codex-testing"
    observed: dict[str, object] = {}

    class State:
        value = "active"

    class Inspection:
        state = State()

    def inspect(target: object, **kwargs: object) -> object:
        observed["target"] = target
        observed.update(kwargs)
        return Inspection()

    monkeypatch.setattr(observe_cli, "inspect_activation", inspect)

    assert (
        observe_cli.observe_status(
            workspace=str(tmp_path),
            codex_path=codex_path,
            codex_home=codex_home,
            json_output=True,
            _state=tmp_path,
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["plugin_activation"] == "active"
    assert observed["executable_path"] == str(codex_path)
    assert observed["codex_home"] == codex_home


def test_status_reports_modified_present_plugin_as_installed_not_activated(
    tmp_path: Path, capsys: object
) -> None:
    """#347: exercise the production activation classifier through observe status."""

    from yoetz.adapters.integrations.codex_plugin import install_plugin
    from yoetz.ports.integrations import IntegrationScope, IntegrationTarget

    state = tmp_path / "state"
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project))
    install_plugin(target, allow_untested=True, codex_version=None)
    hooks = project / ".agents/plugins/yoetz/hooks/hooks.json"
    hooks.write_bytes(hooks.read_bytes() + b"\n")

    assert (
        observe_cli.observe_status(
            workspace=str(project),
            codex_path=Path(sys.executable),
            codex_home=codex_home,
            json_output=True,
            _state=state,
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["plugin_activation"] == "installed_not_activated"


def test_status_help_exposes_exact_activation_target_options() -> None:
    result = CliRunner().invoke(app, ["observe", "status", "--help"])

    assert result.exit_code == 0
    output = _terminal_compact(result.stdout)
    assert "--codex-path" in output
    assert "ExactCodexexecutable" in output
    assert "--codex-home" in output
    assert "ExpectedCodexhome/cache" in output


@pytest.mark.parametrize(
    "arguments",
    [
        ("--codex-path", "/exact/bin/codex"),
        ("--codex-home", "/exact/codex-home"),
    ],
)
def test_status_command_rejects_partial_activation_target(arguments: tuple[str, str]) -> None:
    result = CliRunner().invoke(app, ["observe", "status", *arguments])

    assert result.exit_code == 2
    assert "--codex-pathand--codex-homemustbeprovidedtogether" in _terminal_compact(result.stderr)


def test_status_command_forwards_the_exact_activation_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    codex_path = tmp_path / "bin" / "codex-testing"
    codex_home = tmp_path / ".codex-testing"
    observed: dict[str, object] = {}

    def status(**kwargs: object) -> int:
        observed.update(kwargs)
        return 0

    monkeypatch.setattr(observe_cli, "observe_status", status)
    result = CliRunner().invoke(
        app,
        [
            "observe",
            "status",
            "--workspace",
            str(tmp_path),
            "--codex-path",
            str(codex_path),
            "--codex-home",
            str(codex_home),
            "--json",
        ],
    )

    assert result.exit_code == 0
    assert observed == {
        "workspace": str(tmp_path),
        "codex_path": codex_path,
        "codex_home": codex_home,
        "json_output": True,
    }


@pytest.mark.anyio
async def test_drain_quarantines_setup_probe_and_routes_other_rows(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for session in ("yoetz-setup-probe-session", "ordinary-session"):
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {"session_id": session, "tool_name": "shell", "event_ordinal": 1}
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )
    assert code == 0
    assert summary["attempted"] == 1
    assert summary["acknowledged"] == 1
    assert summary["quarantined"] == 1
    assert summary["reasons"] == {"setup_probe": 1}
    assert store.pending_outbox_count(workspace) == 0
    assert store.quarantined_count(workspace) == 1


@pytest.mark.anyio
async def test_manual_drain_retains_protocol_failure_for_reconnect(tmp_path: Path) -> None:
    """#691: a failed protocol response is not a typed ledger refusal."""

    from yoetz.ports.control import ControlError

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "manual-control-error", "tool_name": "shell", "event_ordinal": 1}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            raise ControlError("frame_invalid", retryable=False)

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 0
    assert summary["quarantined"] == 0
    assert summary["retry_pending"] == 1
    assert summary["reasons"] == {"control_frame_invalid": 1}
    assert len(store.list_pending_outbox_rows(workspace)) == 1
    assert store.list_quarantine(workspace) == ()


@pytest.mark.anyio
async def test_manual_drain_retires_retrying_lane_before_later_row(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session_id = "manual-fifo"
    for ordinal in (1, 2):
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": session_id,
                    "tool_name": "shell",
                    "event_ordinal": ordinal,
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
    calls = 0

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            nonlocal calls
            del body, deadline_ms
            calls += 1
            return observation_ingest_result_to_json(
                ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.SERVICE_UNAVAILABLE.value,
                    None,
                )
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 0
    assert calls == 1
    assert summary["attempted"] == 1
    assert summary["retry_pending"] == 1
    rows = store.list_pending_outbox_rows(workspace)
    assert len(rows) == 2
    assert rows[0].attempts == 1
    assert rows[1].attempts == 0
    assert rows[1].last_reason == ObservationGapCode.SERVICE_UNAVAILABLE.value


@pytest.mark.anyio
@pytest.mark.parametrize("reason", ["vault_locked", "paused", "observation_disabled"])
async def test_manual_drain_stops_workspace_after_global_retry_reason(
    tmp_path: Path,
    reason: str,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for index in (1, 2):
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": f"manual-global-{index}",
                    "tool_name": "shell",
                    "event_ordinal": 1,
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
    calls = 0

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            nonlocal calls
            del body, deadline_ms
            calls += 1
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.REJECTED, reason, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 0
    assert calls == 1
    assert summary["attempted"] == 1
    assert summary["retry_pending"] == 1
    assert len(store.list_pending_outbox_rows(workspace)) == 2


@pytest.mark.anyio
async def test_manual_drain_does_not_project_designed_backpressure_gap(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "manual-barrier", "tool_name": "shell", "event_ordinal": 1}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            return observation_ingest_result_to_json(
                ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    OBSERVATION_BACKPRESSURE_REASON,
                    None,
                )
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert (
        OBSERVATION_BACKPRESSURE_REASON not in store.status(ObservationStatusQuery(workspace)).gaps
    )


@pytest.mark.anyio
async def test_manual_drain_quarantines_ended_unmapped_lane(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session_id = "manual-ended-unmapped"
    for ordinal in (1, 2):
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {"session_id": session_id, "tool_name": "shell", "event_ordinal": ordinal}
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
    store.note_session_end(workspace, store.session_commitment(session_id))

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            return observation_ingest_result_to_json(
                ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.MAPPING_MISSING.value,
                    None,
                )
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 0
    assert summary["quarantined"] == 2
    assert store.list_pending_outbox_rows(workspace) == ()


@pytest.mark.anyio
async def test_manual_drain_lane_lock_failure_does_not_abort_other_lanes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#554: an OSError from one lane's ended-unmapped terminalization (the
    lifecycle lock) stays inside that lane, as in the hook drain. The lane's rows
    remain pending for the next run, the later lane is still quarantined, and the
    command exits normally instead of escaping to the process catch-all."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    locked_session = "manual-lock-failed"
    healthy_session = "manual-lock-healthy"
    for session_id, ordinals in ((locked_session, (1, 2)), (healthy_session, (1,))):
        for ordinal in ordinals:
            handle_observe(
                event_name="PostToolUse",
                stdin_bytes=json.dumps(
                    {"session_id": session_id, "tool_name": "shell", "event_ordinal": ordinal}
                ).encode(),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
            )
        store.note_session_end(workspace, store.session_commitment(session_id))

    original = LocalObservationStore.quarantine_ended_unmapped_session

    def failing_for_locked_lane(
        self: LocalObservationStore, workspace: str, codex_session_id: str, reason: str
    ) -> int:
        if codex_session_id == locked_session:
            raise OSError(errno.EAGAIN, "lifecycle lock unavailable")
        return original(self, workspace, codex_session_id, reason)

    monkeypatch.setattr(
        LocalObservationStore, "quarantine_ended_unmapped_session", failing_for_locked_lane
    )

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            return observation_ingest_result_to_json(
                ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.MAPPING_MISSING.value,
                    None,
                )
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 0
    assert summary["quarantined"] == 1
    assert summary["pending_after"] == 2
    assert summary["terminal"] == "retry_pending"
    remaining = store.list_pending_outbox_rows(workspace)
    assert {row.codex_session_id for row in remaining} == {locked_session}
    assert len(remaining) == 2
    assert {row.last_reason for row in remaining} == {ObservationGapCode.MAPPING_MISSING.value}


@pytest.mark.anyio
async def test_manual_drain_retires_lane_after_attempt_cas_loss(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session_id = "manual-cas-loss"
    for ordinal in (1, 2):
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {"session_id": session_id, "tool_name": "shell", "event_ordinal": ordinal}
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
    selected = store.list_pending_outbox_rows(workspace)[0]
    calls = 0

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            nonlocal calls
            del body, deadline_ms
            calls += 1
            assert store.bump_outbox_row_attempt(
                workspace,
                selected,
                reason=ObservationGapCode.SERVICE_UNAVAILABLE.value,
            )
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert calls == 1
    assert len(store.list_pending_outbox_rows(workspace)) == 2


@pytest.mark.anyio
async def test_manual_drain_retry_ceiling_quarantines_head_and_continues_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yoetz.application.observation_drain as drain_module

    monkeypatch.setattr(drain_module, "MAX_CONSECUTIVE_OBSERVATION_REJECTIONS", 2)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session_id = "manual-ceiling"
    for ordinal in (1, 2):
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": session_id,
                    "tool_name": "shell",
                    "event_ordinal": ordinal,
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
    first = store.list_pending_outbox_rows(workspace)[0]
    store.bump_outbox_row_attempt(
        workspace,
        first,
        reason=ObservationGapCode.SERVICE_UNAVAILABLE.value,
    )
    identities = [row.envelope.source_identity for row in store.list_pending_outbox_rows(workspace)]

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del deadline_ms
            identity = body["envelope"]["source_identity"]  # type: ignore[index]
            result = (
                ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.SERVICE_UNAVAILABLE.value,
                    None,
                )
                if identity == identities[0]
                else ObservationIngestResult(
                    ObservationIngestDisposition.DUPLICATE,
                    None,
                    None,
                )
            )
            return observation_ingest_result_to_json(result)

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 0
    assert summary["attempted"] == 2
    assert summary["quarantined"] == 1
    assert summary["acknowledged"] == 1
    assert store.list_pending_outbox_rows(workspace) == ()
    assert store.list_quarantine(workspace)[0][1].source_identity == identities[0]


@pytest.mark.parametrize(
    "workspace", ["", "/private/does-not-exist/CANARY"], ids=["empty", "missing"]
)
def test_status_names_an_unresolvable_locator_instead_of_internal_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], workspace: str
) -> None:
    """`--workspace ""` (an unset CLAUDE_PROJECT_DIR) is a typed refusal, exit 2 (#428)."""

    code = observe_cli.observe_status(workspace=workspace, json_output=False, _state=tmp_path)
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert captured.err.startswith("observation_status_failed:workspace_unresolvable: ")
    assert "CLAUDE_PROJECT_DIR" in captured.err
    assert "internal_error" not in captured.err
    assert "CANARY" not in captured.err

    code = observe_cli.observe_status(workspace=workspace, json_output=True, _state=tmp_path)
    captured = capsys.readouterr()
    assert code == 2
    error = json.loads(captured.out)["error"]
    assert error["reason"] == "workspace_unresolvable"
    assert error["code"] == "INVALID_REQUEST"
    assert error["operation"] == "status"
    assert error["retryable"] is False
    assert "CANARY" not in captured.out


def test_status_command_reports_typed_workspace_failure_through_the_console(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yoetz.adapters.integrations.observation_local as local

    monkeypatch.setattr(local, "state_dir", lambda: tmp_path)
    result = CliRunner().invoke(app, ["observe", "status", "--workspace", "", "--json"])
    assert result.exit_code == 2
    assert "internal_error" not in result.output
    assert json.loads(result.stdout)["error"]["reason"] == "workspace_unresolvable"


def test_status_maps_bounded_storage_refusals_to_their_public_exit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from yoetz.protocol.errors import PublicErrorCode, PublicOperationError

    def corrupt(self: LocalObservationStore, workspace: str) -> object:
        raise PublicOperationError(
            PublicErrorCode.STORAGE_CORRUPT, "Observation state is invalid.", False
        )

    monkeypatch.setattr(LocalObservationStore, "consent_for", corrupt)
    code = observe_cli.observe_status(workspace=str(tmp_path), json_output=False, _state=tmp_path)
    captured = capsys.readouterr()
    assert code == 40
    assert captured.err == (
        "observation_status_failed:storage_corrupt: Observation state is invalid.\n"
    )

    def unsafe(self: LocalObservationStore, workspace: str) -> object:
        raise PublicOperationError(PublicErrorCode.STORAGE_UNSAFE, "Runtime gate is unsafe.", True)

    monkeypatch.setattr(LocalObservationStore, "consent_for", unsafe)
    code = observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=tmp_path)
    captured = capsys.readouterr()
    assert code == 20
    error = json.loads(captured.out)["error"]
    assert (error["reason"], error["code"], error["retryable"]) == (
        "storage_unsafe",
        "STORAGE_UNSAFE",
        True,
    )


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="owner permission refusal requires a non-root POSIX process",
)
def test_status_maps_real_lock_open_permission_refusal_without_leaking_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The issue #428 sandbox failure is forced at the real ``os.open`` boundary."""

    import yoetz.adapters.integrations.observation_local as local

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    observation = state / "observation"
    observation.mkdir(mode=0o700)
    lock_path = observation / ".store.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0)
    monkeypatch.setattr(local, "state_dir", lambda: state)
    try:
        result = CliRunner().invoke(
            app, ["observe", "status", "--workspace", str(tmp_path), "--json"]
        )
    finally:
        lock_path.chmod(0o600)

    assert result.exit_code == 20
    assert result.stderr == ""
    error = json.loads(result.stdout)["error"]
    assert error == {
        "code": "SERVICE_UNAVAILABLE",
        "message": (
            "the local Yoetz observation store could not be opened or locked from this process; "
            "make the owner-only state directory accessible and writable from the supported host "
            "surface, then retry"
        ),
        "operation": "status",
        "reason": "storage_unavailable",
        "retryable": True,
        "recovery": local_recovery_json("storage_unavailable"),
    }
    assert str(state) not in result.stdout
    assert "internal_error" not in result.stdout


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="read-only directory refusal requires a non-root POSIX process",
)
def test_status_maps_real_read_only_state_directory_to_storage_unavailable(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"

    def read_only_store(*, _state: Path | None = None, **_kwargs: object) -> LocalObservationStore:
        store = LocalObservationStore(_state=_state)
        store._root.chmod(0o500)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        return store

    monkeypatch.setattr(observe_cli, "LocalObservationStore", read_only_store)
    try:
        code = observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=state)
    finally:
        (state / "observation").chmod(0o700)

    captured = capsys.readouterr()
    assert code == 20
    error = json.loads(captured.out)["error"]
    assert (error["reason"], error["code"], error["retryable"]) == (
        "storage_unavailable",
        "SERVICE_UNAVAILABLE",
        True,
    )
    assert str(state) not in captured.out


def test_status_maps_real_unsafe_lock_path_to_storage_unsafe(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    lock_path = state / "observation" / ".store.lock"
    lock_path.parent.mkdir(mode=0o700)
    lock_path.mkdir(mode=0o700)

    code = observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=state)

    captured = capsys.readouterr()
    assert code == 20
    error = json.loads(captured.out)["error"]
    assert (error["reason"], error["code"], error["retryable"]) == (
        "storage_unsafe",
        "STORAGE_UNSAFE",
        False,
    )
    assert str(state) not in captured.out


def test_status_maps_real_missing_store_parent_to_storage_unavailable(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"

    def missing_parent_store(
        *, _state: Path | None = None, **_kwargs: object
    ) -> LocalObservationStore:
        store = LocalObservationStore(_state=_state)
        store._root.rmdir()  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        return store

    monkeypatch.setattr(observe_cli, "LocalObservationStore", missing_parent_store)
    code = observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=state)

    captured = capsys.readouterr()
    assert code == 20
    error = json.loads(captured.out)["error"]
    assert (error["reason"], error["code"], error["retryable"]) == (
        "storage_unavailable",
        "SERVICE_UNAVAILABLE",
        True,
    )
    assert str(state) not in captured.out


def test_status_maps_real_lock_contention_to_storage_unavailable(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.adapters.integrations.observation_local as local

    if local.fcntl is None:
        pytest.skip("POSIX flock is unavailable")
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    observation = state / "observation"
    observation.mkdir(mode=0o700)
    lock_path = observation / ".store.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    local.fcntl.flock(descriptor, local.fcntl.LOCK_EX | local.fcntl.LOCK_NB)
    monkeypatch.setattr(local, "_STORE_LOCK_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(local, "_STORE_LOCK_POLL_SECONDS", 0.005)
    try:
        code = observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=state)
    finally:
        local.fcntl.flock(descriptor, local.fcntl.LOCK_UN)
        os.close(descriptor)

    captured = capsys.readouterr()
    assert code == 20
    error = json.loads(captured.out)["error"]
    assert (error["reason"], error["code"], error["retryable"]) == (
        "storage_unavailable",
        "SERVICE_UNAVAILABLE",
        True,
    )
    assert str(state) not in captured.out


def test_status_leaves_genuinely_unexpected_defects_for_the_internal_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def defect(self: LocalObservationStore, path: str) -> str:
        del self, path
        raise RuntimeError("unexpected_observation_defect")

    monkeypatch.setattr(LocalObservationStore, "workspace_commitment", defect)
    with pytest.raises(RuntimeError, match="unexpected_observation_defect"):
        observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=tmp_path)


@pytest.mark.parametrize(
    ("verb", "method"),
    [
        ("pause", "pause"),
        ("resume", "resume"),
        ("revoke", "revoke"),
    ],
)
def test_control_verbs_preserve_bounded_public_error_exits(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    verb: str,
    method: str,
) -> None:
    from yoetz.protocol.errors import PublicErrorCode, PublicOperationError

    def corrupt(self: LocalObservationStore, command: object) -> object:
        del self, command
        raise PublicOperationError(
            PublicErrorCode.STORAGE_CORRUPT, "Observation state is invalid.", False
        )

    monkeypatch.setattr(LocalObservationStore, method, corrupt)
    if verb == "pause":
        code = observe_cli.pause_observation(workspace=str(tmp_path), _state=tmp_path)
    elif verb == "resume":
        code = observe_cli.resume_observation(workspace=str(tmp_path), _state=tmp_path)
    else:
        code = observe_cli.revoke_observation(workspace=str(tmp_path), _state=tmp_path)
    assert code == 40
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"observation_{verb}_failed:storage_corrupt: Observation state is invalid.\n"
    )


def test_status_maps_an_unsafe_state_path_to_storage_unsafe(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from yoetz.config.paths import PathSafetyError

    def unsafe_store(*args: object, **kwargs: object) -> object:
        raise PathSafetyError("path_contains_symlink")

    monkeypatch.setattr(observe_cli, "LocalObservationStore", unsafe_store)
    code = observe_cli.observe_status(workspace=str(tmp_path), json_output=False, _state=tmp_path)
    captured = capsys.readouterr()
    assert code == 20
    assert captured.err.startswith(
        "observation_status_failed:storage_unsafe: the local Yoetz observation store has an "
        "unsafe file or path shape"
    )


def test_other_observe_verbs_share_the_typed_workspace_refusal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for verb, call in (
        ("grant", lambda: observe_cli.grant_observation(workspace="", _state=tmp_path)),
        ("pause", lambda: observe_cli.pause_observation(workspace="", _state=tmp_path)),
        ("resume", lambda: observe_cli.resume_observation(workspace="", _state=tmp_path)),
        ("revoke", lambda: observe_cli.revoke_observation(workspace="", _state=tmp_path)),
        (
            "reclaim",
            lambda: observe_cli.reclaim_observation(
                workspace="", json_output=False, _state=tmp_path
            ),
        ),
        (
            "drain",
            lambda: observe_cli.drain_observation(workspace="", json_output=False, _state=tmp_path),
        ),
    ):
        assert call() == 2
        captured = capsys.readouterr()
        assert captured.err.startswith(f"observation_{verb}_failed:workspace_unresolvable: ")


def _enqueue_shell_rows(root: Path, session_id: str, ordinals: tuple[int, ...]) -> None:
    for ordinal in ordinals:
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {"session_id": session_id, "tool_name": "shell", "event_ordinal": ordinal}
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(root),
            _state=root,
            skip_service=True,
        )


def _accepted() -> object:
    # DUPLICATE is the cursor-free acknowledgement shape; ACCEPTED carries a cursor.
    return observation_ingest_result_to_json(
        ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, "duplicate", None)
    )


def _rejected(reason: str) -> object:
    return observation_ingest_result_to_json(
        ObservationIngestResult(ObservationIngestDisposition.REJECTED, reason, None)
    )


@pytest.mark.anyio
async def test_manual_drain_repeats_passes_while_progressing_until_drained(
    tmp_path: Path,
) -> None:
    """#564: one retryable head no longer ends the whole drain; passes repeat on progress."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    _enqueue_shell_rows(tmp_path, "lane-a", (1, 2))
    _enqueue_shell_rows(tmp_path, "lane-b", (1, 2))
    calls: list[str] = []

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del deadline_ms
            session = str(body["codex_session_id"])  # type: ignore[index]
            calls.append(session)
            if session == "lane-a" and calls.count("lane-a") == 1:
                return _rejected(ObservationGapCode.SERVICE_UNAVAILABLE.value)
            return _accepted()

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 0
    # Pass 1: lane-a head retries and retires its lane, lane-b drains. Pass 2: lane-a drains.
    assert calls == ["lane-a", "lane-b", "lane-b", "lane-a", "lane-a"]
    assert summary["passes"] == 2
    assert summary["terminal"] == "drained"
    assert summary["pending_after"] == 0
    assert summary["attempted"] == 5
    assert summary["acknowledged"] == 4
    assert summary["retry_pending"] == 1
    assert summary["reasons"] == {ObservationGapCode.SERVICE_UNAVAILABLE.value: 1}
    assert store.pending_outbox_count(workspace) == 0


@pytest.mark.anyio
async def test_manual_drain_stops_at_retry_pending_when_a_pass_resolves_nothing(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    _enqueue_shell_rows(tmp_path, "barrier", (1, 2))
    calls = 0

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            nonlocal calls
            del body, deadline_ms
            calls += 1
            return _rejected(OBSERVATION_BACKPRESSURE_REASON)

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 0
    assert calls == 1
    assert summary["passes"] == 1
    assert summary["terminal"] == "retry_pending"
    assert summary["pending_after"] == 2
    assert summary["reasons"] == {OBSERVATION_BACKPRESSURE_REASON: 1}
    assert store.pending_outbox_count(workspace) == 2


@pytest.mark.anyio
async def test_manual_drain_names_service_unavailable_terminal_with_the_pending_count(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    _enqueue_shell_rows(tmp_path, "offline", (1, 2, 3))

    async def connect(_kind: object):
        raise ConnectionRefusedError

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 20
    assert summary["passes"] == 0
    assert summary["terminal"] == "service_unavailable"
    assert summary["pending_after"] == 3
    assert summary["retry_pending"] == 3
    assert summary["reasons"] == {ObservationGapCode.SERVICE_UNAVAILABLE.value: 3}


@pytest.mark.anyio
async def test_manual_drain_is_bounded_against_a_producer_that_never_stops(
    tmp_path: Path,
) -> None:
    """Passes are capped by the backlog at entry, so a live producer cannot hold the CLI."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    _enqueue_shell_rows(tmp_path, "producer", (1, 2))
    next_ordinal = 3

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            nonlocal next_ordinal
            del body, deadline_ms
            # Every delivery is answered by a fresh hook row: the #564 loop in miniature.
            _enqueue_shell_rows(tmp_path, "producer", (next_ordinal,))
            next_ordinal += 1
            return _accepted()

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code, summary = await observe_cli._drain_observation_async(  # pyright: ignore[reportPrivateUsage]
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
    )

    assert code == 0
    assert summary["passes"] == 2
    assert summary["terminal"] == "pass_limit"
    assert summary["acknowledged"] == 4
    assert summary["pending_after"] == 2
    assert store.pending_outbox_count(workspace) == 2


def test_drain_text_output_reports_the_terminal_condition(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    _enqueue_shell_rows(tmp_path, "text", (1,))

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            return _accepted()

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    monkeypatch.setattr(observe_cli, "connect_service_on_demand", connect)
    original = observe_cli._drain_observation_async  # pyright: ignore[reportPrivateUsage]

    async def patched(**kwargs: object):
        kwargs["connect"] = connect
        return await original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(observe_cli, "_drain_observation_async", patched)
    assert (
        observe_cli.drain_observation(workspace=str(tmp_path), json_output=False, _state=tmp_path)
        == 0
    )
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "passes=1 pending_after=0 terminal=drained" in out
    assert "reasons: none" in out


def test_status_reports_the_oldest_pending_receipt_for_convergence(
    tmp_path: Path, capsys: object
) -> None:
    """#564: status names how old the backlog head is, next to the last successful drain."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    assert (
        observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=tmp_path) == 0
    )
    empty = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert empty["undelivered_count"] == 0
    assert empty["oldest_pending_receipt"] is None

    _enqueue_shell_rows(tmp_path, "convergence", (1, 2))
    rows = store.list_pending_outbox_rows(workspace)
    oldest = min(row.envelope.receipt_time for row in rows)

    assert (
        observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=tmp_path) == 0
    )
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["undelivered_count"] == 2
    assert payload["oldest_pending_receipt"] == oldest.wire
    assert payload["oldest_pending_receipt"] == rows[0].envelope.receipt_time.wire

    assert (
        observe_cli.observe_status(workspace=str(tmp_path), json_output=False, _state=tmp_path) == 0
    )
    text = capsys.readouterr().out  # type: ignore[attr-defined]
    assert f"oldest: {oldest.wire}" in text
    assert "last successful drain: never" in text


def test_explicit_recovery_persists_profile_and_rotation_frontier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from builders.codex_rollout import encode_lines, function_call, session_meta

    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "other-home"))
    store = LocalObservationStore(_state=state)
    commitment = store.workspace_commitment(str(workspace))
    store.grant_consent(commitment)
    # Keep the established opaque-tail fallback for non-native explicit paths.
    path = tmp_path / "manual-recovery.jsonl"
    session = store.session_commitment("recovery")
    path.write_bytes(encode_lines(session_meta(), function_call(name="shell", call_id="first")))

    # A regression to separately saving any generation-coupled component must fail: recovery
    # must commit the same complete transaction as automatic reconciliation.
    def separate_save(*args: object, **kwargs: object) -> None:
        raise AssertionError("non-atomic stream state write")

    monkeypatch.setattr(LocalObservationStore, "set_stream_cursor", separate_save)
    monkeypatch.setattr(LocalObservationStore, "set_stream_partial", separate_save)
    monkeypatch.setattr(LocalObservationStore, "set_stream_profile", separate_save)
    for version in ("0.148.0", "0.150.1"):
        if version == "0.150.1":
            replacement = tmp_path / "replacement.jsonl"
            replacement.write_bytes(
                encode_lines(
                    session_meta(cli_version=version, history_mode="paginated"),
                    function_call(name="shell", call_id="second"),
                    function_call(name="shell", call_id="third"),
                )
            )
            replacement.replace(path)
        assert (
            observe_cli.reconcile_session_stream(
                session_file=str(path), workspace=str(workspace), json_output=True, _state=state
            )
            == 0
        )
        reopened = LocalObservationStore(_state=state)
        cursor = reopened.get_stream_cursor(commitment, session)
        assert cursor is not None
        assert cursor.byte_position == path.stat().st_size
        assert cursor.source_generation == (1 if version == "0.148.0" else 2)
        assert reopened.stream_profile_for_session(commitment, session) == (
            f"codex-rollout-jsonl/{version}/v1"
        )
        assert reopened.stream_source_identity_for_session(commitment, session) is not None
        tools = reopened.stream_call_tools_for_session(
            commitment, session, source_generation=cursor.source_generation
        )
        assert set(tools) == ({"first"} if version == "0.148.0" else {"second", "third"})


def test_explicit_recovery_uses_full_mapped_native_session_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A native rollout filename must retain the full mapped UUID for recovery."""

    from builders.codex_rollout import encode_lines, function_call, session_meta

    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    codex_home = tmp_path / "codex-home"
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    path = codex_home / "sessions" / "2026" / "09" / "07"
    path.mkdir(parents=True)
    session_file = path / f"rollout-2026-09-07T12-00-00-{session_id}.jsonl"
    session_file.write_bytes(
        encode_lines(session_meta(), function_call(name="shell", call_id="native-call"))
    )
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    store = LocalObservationStore(_state=state)
    workspace_commitment = store.workspace_commitment(str(workspace))
    store.grant_consent(workspace_commitment)
    full_session_commitment = store.session_commitment(session_id)
    store.bind_codex_session(workspace_commitment, session_id)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=session_id,
            yoetz_task_id=new_id(IdKind.TASK),
            yoetz_session_id=new_id(IdKind.SESSION),
            yoetz_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        ),
        _state=state,
    )

    assert (
        observe_cli.reconcile_session_stream(
            session_file=str(session_file),
            workspace=str(workspace),
            json_output=True,
            _state=state,
        )
        == 0
    )
    cursor = store.get_stream_cursor(workspace_commitment, full_session_commitment)
    assert cursor is not None
    assert cursor.byte_position == session_file.stat().st_size
    assert (
        store.get_stream_cursor(
            workspace_commitment, store.session_commitment(session_id.rsplit("-", 1)[-1])
        )
        is None
    )

    # The automatic adapter path sees the same cursor/profile and does not create a
    # second stream identity after manual recovery.
    from yoetz.adapters.integrations.codex_session_stream import (
        CodexSessionStreamLocator,
        reconcile_session_stream,
    )

    again = reconcile_session_stream(
        store,
        workspace_commitment=workspace_commitment,
        session_commitment=full_session_commitment,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(codex_home),
    )
    assert again["accepted"] == 0
    assert store.stream_profile_for_session(workspace_commitment, full_session_commitment) == (
        "codex-rollout-jsonl/0.148.0/v1"
    )


def test_explicit_recovery_refuses_unmapped_native_rollout(tmp_path: Path, capsys: object) -> None:
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    session_file = tmp_path / f"rollout-2026-09-07T12-00-00-{session_id}.jsonl"
    session_file.write_bytes(b"{}\n")
    store = LocalObservationStore(_state=state)
    workspace_commitment = store.workspace_commitment(str(workspace))
    store.grant_consent(workspace_commitment)

    assert (
        observe_cli.reconcile_session_stream(
            session_file=str(session_file),
            workspace=str(workspace),
            json_output=False,
            _state=state,
        )
        == 20
    )
    assert "observation_reconcile_failed:mapping_missing" in capsys.readouterr().err  # type: ignore[attr-defined]
    assert store.codex_sessions_for_workspace(workspace_commitment) == ()


def test_explicit_recovery_refuses_rollout_bound_to_another_workspace(
    tmp_path: Path, capsys: object
) -> None:
    state = tmp_path / "state"
    selected_workspace = tmp_path / "selected"
    other_workspace = tmp_path / "other"
    selected_workspace.mkdir()
    other_workspace.mkdir()
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    session_file = tmp_path / f"rollout-2026-09-07T12-00-00-{session_id}.jsonl"
    session_file.write_bytes(b"{}\n")
    store = LocalObservationStore(_state=state)
    selected_commitment = store.workspace_commitment(str(selected_workspace))
    other_commitment = store.workspace_commitment(str(other_workspace))
    store.grant_consent(selected_commitment)
    store.grant_consent(other_commitment)
    store.bind_codex_session(other_commitment, session_id)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=session_id,
            yoetz_task_id=new_id(IdKind.TASK),
            yoetz_session_id=new_id(IdKind.SESSION),
            yoetz_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        ),
        _state=state,
    )

    assert (
        observe_cli.reconcile_session_stream(
            session_file=str(session_file),
            workspace=str(selected_workspace),
            json_output=False,
            _state=state,
        )
        == 20
    )
    assert "observation_reconcile_failed:mapping_missing" in capsys.readouterr().err  # type: ignore[attr-defined]
    assert store.codex_sessions_for_workspace(selected_commitment) == ()


def test_explicit_recovery_uses_full_mapping_for_compressed_rollout_variant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    codex_home = tmp_path / "codex-home"
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    rollout_id = "019f8b27-cccc-7061-bbb5-d0b897594de6"
    path = codex_home / "sessions" / "2026" / "09" / "07"
    path.mkdir(parents=True)
    session_file = path / f"rollout-2026-09-07T12-00-00-{session_id}_{rollout_id}.jsonl.zst"
    session_file.write_bytes(b"\x28\xb5\x2f\xfdnot-a-real-frame")
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    store = LocalObservationStore(_state=state)
    workspace_commitment = store.workspace_commitment(str(workspace))
    store.grant_consent(workspace_commitment)
    store.bind_codex_session(workspace_commitment, session_id)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=session_id,
            yoetz_task_id=new_id(IdKind.TASK),
            yoetz_session_id=new_id(IdKind.SESSION),
            yoetz_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        ),
        _state=state,
    )

    assert (
        observe_cli.reconcile_session_stream(
            session_file=str(session_file),
            workspace=str(workspace),
            json_output=True,
            _state=state,
        )
        == 0
    )
    status = store.status(ObservationStatusQuery(workspace_commitment))
    assert "unsupported_format" in status.gaps


def _write_check_policy(workspace: Path) -> None:
    policy_dir = workspace / ".yoetz"
    policy_dir.mkdir()
    (policy_dir / "checks.toml").write_bytes(
        b'format = "yoetz.approved-check-policy/1"\n'
        b"\n"
        b"[[checks]]\n"
        b'id = "smoke"\n'
        b'argv = ["/usr/bin/true"]\n'
        b"timeout_seconds = 10\n"
        b"network = false\n"
    )


@pytest.mark.parametrize("reason", ["bwrap_missing", "bwrap_unusable", "ready"])
def test_checks_status_names_the_probed_sandbox_outcome(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    """`observe checks status` carries the host sandbox answer, not just the policy state.

    The dependency is named once here (issue #720); `yoetz service status` deliberately does not
    report it, because sandbox availability is a fact about the host running the check.
    """

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write_check_policy(workspace)
    bwrap = tmp_path / "bwrap"
    if reason != "bwrap_missing":
        bwrap.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        bwrap.chmod(0o755)
    sandbox = LinuxCheckSandbox(
        bwrap=str(bwrap),
        _probe=lambda _argv: 0 if reason == "ready" else 1,
        _true="/usr/bin/true",
    )
    availability = sandbox.availability()
    monkeypatch.setattr(observe_cli, "probe_check_sandbox", sandbox.availability)

    code = observe_cli.observe_checks_status(
        workspace=str(workspace), json_output=True, _state=tmp_path / "state"
    )

    assert code == 0
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["sandbox"] == {
        "mechanism": "bubblewrap",
        "reason": reason,
        "remediation": availability.remediation,
        "status": "ready" if reason == "ready" else "unavailable",
    }
    assert payload["state"] == "untrusted"
    if reason != "ready":
        assert payload["sandbox"]["remediation"] != ""


def test_checks_status_reports_missing_policy_as_not_configured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A workspace without `.yoetz/checks.toml` is the ordinary opt-in state (tb4v1).

    It used to print `observation_checks_status_failed:invalid_policy` and exit 20, which an agent
    read as an owner-authority blocker.
    """

    workspace = tmp_path / "workspace"
    workspace.mkdir()

    code = observe_cli.observe_checks_status(
        workspace=str(workspace), json_output=True, _state=tmp_path / "state"
    )

    captured = capsys.readouterr()
    assert code == 0
    assert "invalid_policy" not in captured.err
    payload = json.loads(captured.out)
    assert payload["state"] == "not_configured"
    assert payload["policy_digest"] is None
    assert payload["executable_checks"] == []
    assert payload["network_check_state"] == "not_requested"
    assert "not a task blocker" in payload["note"]
    assert set(payload) == {
        "workspace_commitment",
        "policy_digest",
        "state",
        "sandbox",
        "executable_checks",
        "network_check_state",
        "note",
    }


def test_checks_status_text_output_reports_not_configured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    code = observe_cli.observe_checks_status(
        workspace=str(workspace), json_output=False, _state=tmp_path / "state"
    )

    captured = capsys.readouterr()
    assert code == 0
    assert "state: not_configured" in captured.out
    assert captured.err == ""


@pytest.mark.parametrize("operation", ["preview", "trust", "run"])
def test_checks_operations_name_missing_policy_and_say_it_is_not_a_blocker(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], operation: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    kwargs: dict[str, object] = {"workspace": str(workspace), "_state": tmp_path / "state"}
    if operation == "trust":
        kwargs["policy_digest"] = "sha256:" + "0" * 64
    else:
        kwargs["json_output"] = True

    code = getattr(observe_cli, f"observe_checks_{operation}")(**kwargs)

    err = capsys.readouterr().err
    assert code == 20
    assert f"observation_checks_{operation}_failed:policy_not_configured" in err
    assert "invalid_policy" not in err
    assert "not a task blocker" in err


@pytest.mark.parametrize("operation", ["status", "preview", "trust", "run"])
def test_checks_operations_keep_invalid_policy_for_a_broken_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], operation: str
) -> None:
    workspace = tmp_path / "workspace"
    (workspace / ".yoetz").mkdir(parents=True)
    (workspace / ".yoetz" / "checks.toml").write_bytes(b"format = 1\n")
    kwargs: dict[str, object] = {"workspace": str(workspace), "_state": tmp_path / "state"}
    if operation == "trust":
        kwargs["policy_digest"] = "sha256:" + "0" * 64
    else:
        kwargs["json_output"] = True

    code = getattr(observe_cli, f"observe_checks_{operation}")(**kwargs)

    captured = capsys.readouterr()
    assert code == 20
    assert captured.out == ""
    assert f"observation_checks_{operation}_failed:invalid_policy" in captured.err
    assert "not a task blocker" in captured.err


@pytest.mark.parametrize("operation", ["status", "preview", "run"])
def test_checks_operations_do_not_call_a_missing_workspace_a_policy_fault(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], operation: str
) -> None:
    code = getattr(observe_cli, f"observe_checks_{operation}")(
        workspace=str(tmp_path / "absent-workspace"), json_output=True, _state=tmp_path / "state"
    )

    err = capsys.readouterr().err
    assert code == 20
    assert "invalid_policy" not in err
    assert "policy_not_configured" not in err
