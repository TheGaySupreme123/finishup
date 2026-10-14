"""CLI coverage for `finishup hooks session-start` inactive mapping path."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from importlib import import_module
from pathlib import Path

import pytest
from typer.testing import CliRunner

import finishup.cli.app as cli
from finishup.config.paths import state_dir

_RUNNER = CliRunner()

# The resume path reaches these through lazy in-function imports, so load them up front: their
# `state_dir` bindings must already exist when `_redirect_state_dir` scans `sys.modules`.
_LAZILY_REACHED_MODULES = (
    "finishup.adapters.integrations.codex_lifecycle",
    "finishup.adapters.integrations.observation_local",
    "finishup.cli.observe_hooks",
)


def _redirect_state_dir(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    """Point every imported binding of ``state_dir`` at ``root``.

    Each module does ``from finishup.config.paths import state_dir``, so patching one module leaves
    the others bound to the real user state directory. Patching only ``codex_lifecycle`` let the
    ``resume`` path reach ``observation_local``'s binding and read real host observation state:
    the assertions below then passed on a clean runner and failed on any machine that had used
    FinishUP, so dogfooding the tool broke its own suite.
    """

    def _state_dir(*, _probe: object | None = None) -> Path:
        del _probe
        return root

    for name in _LAZILY_REACHED_MODULES:
        import_module(name)

    patched = 0
    for name, module in tuple(sys.modules.items()):
        if not name.startswith("finishup."):
            continue
        if getattr(module, "state_dir", None) is None:
            continue
        monkeypatch.setattr(module, "state_dir", _state_dir, raising=False)
        patched += 1
    # A future module that resolves its own state root must not silently reintroduce host reads.
    assert patched >= 2, f"expected several state_dir bindings, patched {patched}"


def test_hooks_session_start_inactive_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _redirect_state_dir(monkeypatch, tmp_path)
    result = _RUNNER.invoke(
        cli.app,
        ["hooks", "session-start"],
        input=json.dumps(
            {
                "session_id": "subprocess-session-1",
                "source": "resume",
                "hook_event_name": "SessionStart",
            }
        ),
    )
    assert result.exit_code == 0, result.stderr
    body = json.loads(result.stdout)
    context = body["hookSpecificOutput"]["additionalContext"]
    assert "No FinishUP task is mapped" in context
    assert "tsk_" not in context


def _populate_wall_clock_store(state: Path, workspace_dir: Path) -> None:
    """Grow one workspace to the shape the #242 latency report was measured at."""

    from datetime import UTC, datetime

    from finishup.adapters.integrations.observation_local import (
        LocalObservationStore,
        ObservationOutboxRow,
        _dedup_key,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.domain.observation import (
        ObservationCursor,
        ObservationEnvelope,
        ObservationSource,
    )
    from finishup.domain.values import JsonObject, timestamp_from_datetime

    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(workspace_dir))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "wall")
    now = timestamp_from_datetime(datetime.now(UTC).replace(microsecond=0))

    def envelope(ordinal: int) -> ObservationEnvelope:
        return ObservationEnvelope(
            session_commitment=session,
            event_kind="PostToolUse",
            source_identity=f"hook:bulk:{ordinal}",
            source=ObservationSource.CODEX_HOOK,
            cursor=ObservationCursor(
                source_generation=1,
                byte_position=ordinal * 8,
                event_position=ordinal,
                last_source_commitment=session,
                mapping_version="codex-obs-hook/1.0.0",
            ),
            receipt_time=now,
            structural_payload=JsonObject({"tool_name": "shell", "exit_status": 0}),
            content_object_refs=(),
            gap_codes=(),
        )

    state_value = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert state_value.envelopes is not None
    assert state_value.dedup is not None
    assert state_value.pending_outbox is not None
    assert state_value.quarantine is not None
    for ordinal in range(1, 510):
        item = envelope(ordinal)
        if ordinal <= 250:
            state_value.envelopes.append(item)
            state_value.dedup.add(_dedup_key(workspace, item))
        elif ordinal <= 310:
            state_value.pending_outbox.append(
                ObservationOutboxRow(codex_session_id="wall", envelope=item)
            )
        else:
            state_value.quarantine.append(("wall", item, "service_unavailable", now))
    store._save(workspace, state_value)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.slow
def test_observe_hook_process_wall_clock_including_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The only guard that can see process startup — the term #242 says nothing bounds.

    Every in-process latency test starts after the interpreter and the import
    graph are already paid, which is exactly why 3.5-7.5s per tool call reached
    a real session while CI stayed green. This runs the installed console
    script the plugin actually invokes, against a realistic store, and bounds
    the whole thing.
    """

    launcher = Path(__file__).resolve().parents[2] / ".venv/bin/finishup"
    if not launcher.is_file():
        pytest.skip("no installed console script to measure")

    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    state = state_dir()
    state.mkdir(parents=True)
    state.chmod(0o700)
    workspace_dir = home / "project"
    workspace_dir.mkdir()
    _populate_wall_clock_store(state, workspace_dir)
    store_file = next((state / "observation" / "workspaces").glob("*.json"))
    assert store_file.stat().st_size >= 250_000, (
        f"the wall-clock guard must run against a realistic store; got {store_file.stat().st_size}"
    )
    before = store_file.read_bytes()

    environment = dict(os.environ)
    environment["HOME"] = str(home)
    payload = json.dumps(
        {"session_id": "wall", "tool_name": "shell", "exit_status": 0, "correlation_id": "w1"}
    ).encode()

    started = time.monotonic()
    completed = subprocess.run(  # noqa: S603 - fixed in-repository launcher
        [
            os.fspath(launcher),
            "hooks",
            "observe",
            "--workspace",
            os.fspath(workspace_dir),
            "--event",
            "PostToolUse",
        ],
        input=payload,
        capture_output=True,
        env=environment,
        check=False,
        timeout=30,
    )
    elapsed = time.monotonic() - started

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert completed.stdout.endswith(b"\n")
    assert store_file.read_bytes() != before, (
        "the hook process did not write the redirected store; the measured time "
        "is not the realistic-store path"
    )
    # 0.55s measured locally and 1.09s on a loaded Linux runner after the import
    # diet and write batch. Keep enough shared-runner headroom while still
    # excluding the pre-fix 1.67-2.50s band.
    assert elapsed < 1.5, (
        f"one observe hook process took {elapsed:.2f}s end to end, startup included"
    )
