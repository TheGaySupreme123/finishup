"""Fresh repository facts, bounded reads, and actual host stdout contracts (#857)."""

from __future__ import annotations

import io
import json
import os
import time
from functools import partial
from pathlib import Path
from typing import cast

import anyio
import pytest
from anyio.to_thread import run_sync

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import host_startup_advisory as advisory
from finishup.cli import observe_hooks
from finishup.cli.hooks import ServiceConnector
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.values import JsonObject
from finishup.ports.control import ControlClientKind


class GrantClient:
    def __init__(self, grant: object = None) -> None:
        self.grant = grant
        self.reads = 0
        self.closed = 0
        self.deadlines: list[int] = []

    async def privacy_get_setup(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> object:
        assert request == {"schema_version": "2.0.0"}
        assert deadline_ms is not None
        self.deadlines.append(deadline_ms)
        self.reads += 1
        return self.grant

    async def close(self) -> None:
        self.closed += 1

    async def connect(self, kind: ControlClientKind) -> GrantClient:
        assert kind is ControlClientKind.CLI
        return self


GRANTED = {
    "grant_state": "granted",
    "composed_policy": {"channel_policies": [{"channel": "llm_inference", "enabled": True}]},
}


def notice(root: Path, client: GrantClient, *, host: str = "claude", **kwargs: object) -> str:
    return advisory.append_admission_notice(
        "existing context",
        host,
        str(root),
        connect=client.connect,
        run_async=anyio.run,
        deadline=time.monotonic() + 1,
        max_chars=2_000,
        **kwargs,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("host", ["claude", "codex", "cursor"])
def test_notice_reports_grant_without_inferring_route_or_host_approval(
    tmp_path: Path, host: str
) -> None:
    client = GrantClient(GRANTED)
    before = set(tmp_path.rglob("*"))
    result = notice(tmp_path, client, host=host)
    assert result.startswith("existing context At session start, FinishUP read a repository grant")
    assert f"finishup integrate {host} admission grant" in result
    assert "Route and host approval remain unconfirmed" in result
    assert "preserve the exact request" in result
    assert "route: policy" not in result and "retry" not in result
    assert str(tmp_path) not in result
    assert client.reads == client.closed == 1
    assert 0 < client.deadlines[0] <= 500
    assert set(tmp_path.rglob("*")) == before  # no cache, settings or retry markers


@pytest.mark.parametrize(
    "grant",
    [
        None,
        {},
        {"grant_state": "missing"},
        {
            "grant_state": "granted",
            "composed_policy": {
                "channel_policies": [{"channel": "llm_inference", "enabled": False}]
            },
        },
        "UNTRUSTED_CANARY",
    ],
)
def test_unconfirmed_grant_preserves_existing_context(tmp_path: Path, grant: object) -> None:
    client = GrantClient(grant)
    assert notice(tmp_path, client) == "existing context"
    assert client.reads == client.closed == 1


@pytest.mark.parametrize("state", ["present", "partial", "foreign", "unknown", "CANARY"])
def test_any_admission_state_except_absent_skips_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    def read_state(*args: object, **kwargs: object) -> str:
        return state

    monkeypatch.setattr(advisory, "read_admission_state", read_state)
    client = GrantClient(GRANTED)
    assert notice(tmp_path, client) == "existing context"
    assert client.reads == 0


@pytest.mark.parametrize("case", ["skip", "unbound", "host", "time", "space"])
def test_ineligible_notice_never_reads_admission_or_connects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    def forbidden(*args: object, **kwargs: object) -> str:
        pytest.fail("ineligible notice must not read local admission")

    monkeypatch.setattr(advisory, "read_admission_state", forbidden)
    client = GrantClient(GRANTED)
    result = advisory.append_admission_notice(
        "existing context",
        "unknown" if case == "host" else "claude",
        None if case == "unbound" else str(tmp_path),
        connect=client.connect,
        run_async=anyio.run,
        deadline=time.monotonic() + (-1 if case == "time" else 1),
        max_chars=20 if case == "space" else 2_000,
        skip_service=case == "skip",
    )
    assert result == "existing context" and client.reads == 0


@pytest.mark.parametrize("phase", ["connect", "request", "close"])
def test_one_deadline_bounds_connection_rpc_and_cleanup(tmp_path: Path, phase: str) -> None:
    class HungClient(GrantClient):
        async def connect(self, kind: ControlClientKind) -> GrantClient:
            if phase == "connect":
                await anyio.sleep_forever()
            return self

        async def privacy_get_setup(
            self, request: JsonObject, *, deadline_ms: int | None = None
        ) -> object:
            if phase == "request":
                await anyio.sleep_forever()
            return GRANTED

        async def close(self) -> None:
            if phase == "close":
                await anyio.sleep_forever()

    client = HungClient()

    async def bounded() -> str:
        # The outer bound turns a lost deadline into a failure rather than a hung test.
        with anyio.fail_after(1):
            return await run_sync(
                lambda: advisory.append_admission_notice(
                    "existing",
                    "claude",
                    str(tmp_path),
                    connect=client.connect,
                    run_async=anyio.run,
                    deadline=time.monotonic() + 0.1,
                    max_chars=2_000,
                ),
                abandon_on_cancel=True,
            )

    assert anyio.run(bounded) == "existing"


def test_time_spent_reading_admission_does_not_start_another_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticks = iter([0.0, 0.0, 0.6])

    def read_state(*args: object, **kwargs: object) -> str:
        return "absent"

    monkeypatch.setattr(advisory, "read_admission_state", read_state)
    client = GrantClient(GRANTED)
    result = advisory.append_admission_notice(
        "existing",
        "claude",
        str(tmp_path),
        connect=client.connect,
        run_async=anyio.run,
        deadline=1.0,
        max_chars=2_000,
        monotonic=lambda: next(ticks),
    )
    assert result == "existing" and client.reads == 0


def test_admission_fifo_is_unknown_without_waiting(tmp_path: Path) -> None:
    root = tmp_path / ".claude"
    root.mkdir()
    os.mkfifo(root / "settings.local.json", 0o600)
    assert notice(tmp_path, GrantClient(GRANTED)) == "existing context"


def test_admission_reads_repository_root_when_hook_starts_in_subdirectory(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    settings = tmp_path / ".claude"
    settings.mkdir()
    (settings / "settings.local.json").write_text(
        json.dumps(
            {
                "permissions": {
                    "allow": ["mcp__plugin_finishup_finishup__check", "mcp__finishup__check"]
                }
            }
        )
    )
    child = tmp_path / "child"
    child.mkdir()
    client = GrantClient(GRANTED)
    assert notice(child, client) == "existing context"
    assert client.reads == 0


@pytest.mark.parametrize(
    ("host", "profile"),
    [
        ("claude", None),
        ("codex", None),
        ("cursor", None),
        ("claude", CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID),
        ("cursor", CURSOR_ORDINARY_OBSERVATION_PROFILE_ID),
    ],
)
@pytest.mark.parametrize("skip_service", [False, True])
def test_real_hook_ingress_delivers_only_on_supported_context_channel(
    tmp_path: Path, host: str, profile: str | None, skip_service: bool
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    store.grant_consent(store.workspace_commitment(str(tmp_path.resolve())))
    client = GrantClient(GRANTED)
    output = io.BytesIO()
    event = "sessionStart" if host == "cursor" else "SessionStart"
    payload = {
        "session_id": "session-start",
        "conversation_id": "session-start",
        "hook_event_name": event,
        "source": "startup",
    }
    handler = {
        "claude": partial(observe_hooks.handle_claude_observe, observation_profile=profile),
        "cursor": partial(observe_hooks.handle_cursor_observe, observation_profile=profile),
        "codex": observe_hooks.handle_observe,
    }[host]
    assert (
        handler(
            event_name=event,
            stdin_bytes=json.dumps(payload).encode(),
            stdout=output,
            workspace=str(tmp_path),
            _state=tmp_path,
            connect=cast(ServiceConnector, client.connect),
            skip_service=skip_service,
        )
        == 0
    )  # type: ignore[arg-type]
    result = json.loads(output.getvalue())
    text = (
        result["additional_context"]
        if host == "cursor"
        else result["hookSpecificOutput"]["additionalContext"]
    )
    assert (f"finishup integrate {host} admission grant" in text) is not skip_service
    assert "permissionDecision" not in result and "systemMessage" not in result
    assert client.reads == (0 if skip_service else 1)
