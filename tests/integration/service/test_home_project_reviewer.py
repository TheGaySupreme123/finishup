"""#1161: real HOME ignore probes feed the service's reviewer broker, without live state."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.ports.change_capture import CheckWorkspaceSource, check_workspace_source_scope
from finishup.protocol.models import SemanticStatus
from integration.service import test_reviewer_conversation_composition as c
from integration.service import test_semantic_non_dispatch as n
from unit.adapters.test_requested_path_probe import _git  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
@pytest.mark.parametrize("source_suffix", ("", "/"))
async def test_home_reviewer_reads_source_but_refuses_host_state_and_absolute_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source_suffix: str
) -> None:
    root = (tmp_path / "work").resolve()
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    def probe() -> GitChangeCaptureAdapter:
        _git(root, "init", "--quiet")
        (root / ".codex").mkdir()
        (root / ".codex/auth.json").write_text("private host canary\n")
        (root / "auth.json").write_text("private auth canary\n")
        return GitChangeCaptureAdapter(admitted_home_project=True)

    # Replace only the old helper's stubbed ignore port; the production composition,
    # read broker, local privacy admission and descriptor-safe reader remain real.
    monkeypatch.setattr(c, "_Probe", probe)
    with check_workspace_source_scope(
        CheckWorkspaceSource(str(root) + source_suffix, n._REPOSITORY)  # pyright: ignore[reportPrivateUsage]
    ):
        result, gateway, _runtime = await c._run(  # pyright: ignore[reportPrivateUsage]
            tmp_path,
            monkeypatch,
            c._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
            c._read_file(".codex/auth.json"),  # pyright: ignore[reportPrivateUsage]
            c._read_file("auth.json"),  # pyright: ignore[reportPrivateUsage]
            c._FINAL,  # pyright: ignore[reportPrivateUsage]
            # Three reads need more than the minimal policy's room since #1173 (ADR-006).
            policy=c._ROOMY,  # pyright: ignore[reportPrivateUsage]
        )
    assert result.status is SemanticStatus.SUCCEEDED, result.reason
    assert result.reviewer is not None
    first, hidden, auth = result.reviewer.reads
    assert first.status == "ok"
    assert hidden.reason == auth.reason == "forbidden_path"
    history = gateway.exchanges[-1][1]
    observation = json.loads(history[4][1])
    assert "return a + b" in observation["data"]["text"]
    assert "private host canary" not in str(history) and "private auth canary" not in str(history)


@pytest.mark.anyio
async def test_home_reviewer_keeps_relative_selector_and_git_ignore_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = (tmp_path / "work").resolve()
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    def probe() -> GitChangeCaptureAdapter:
        _git(root, "init", "--quiet")
        (root / ".gitignore").write_text("secret.txt\n")
        return GitChangeCaptureAdapter(admitted_home_project=True)

    monkeypatch.setattr(c, "_Probe", probe)
    with check_workspace_source_scope(
        CheckWorkspaceSource(str(root), n._REPOSITORY)  # pyright: ignore[reportPrivateUsage]
    ):
        result, _gateway, _runtime = await c._run(  # pyright: ignore[reportPrivateUsage]
            tmp_path,
            monkeypatch,
            c._read_file(str(root / "calc.py")),  # pyright: ignore[reportPrivateUsage]
            c._read_file("secret.txt"),  # pyright: ignore[reportPrivateUsage]
            c._FINAL,  # pyright: ignore[reportPrivateUsage]
            # A long absolute-path action beside a corrected refusal needs more than the minimal
            # policy's room since #1173 (ADR-006).
            policy=c._ROOMY,  # pyright: ignore[reportPrivateUsage]
        )
    assert result.status is SemanticStatus.SUCCEEDED, result.reason
    assert result.reviewer is not None
    assert all(read.reason == "forbidden_path" for read in result.reviewer.reads)


@pytest.mark.anyio
@pytest.mark.parametrize("source_kind", ("absent", "different_workspace", "different_repository"))
async def test_a_claimed_home_in_task_history_is_not_home_read_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source_kind: str
) -> None:
    root = (tmp_path / "work").resolve()
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    def probe() -> GitChangeCaptureAdapter:
        _git(root, "init", "--quiet")
        return GitChangeCaptureAdapter(admitted_home_project=True)

    monkeypatch.setattr(c, "_Probe", probe)
    source = (
        None
        if source_kind == "absent"
        else CheckWorkspaceSource(
            str(root.parent if source_kind == "different_workspace" else root),
            "hmac-sha256:" + "a" * 64 if source_kind == "different_repository" else n._REPOSITORY,  # pyright: ignore[reportPrivateUsage]
        )
    )
    with check_workspace_source_scope(source):
        result, gateway, _runtime = await c._run(  # pyright: ignore[reportPrivateUsage]
            tmp_path,
            monkeypatch,
            c._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
            c._FINAL,  # pyright: ignore[reportPrivateUsage]
        )
    assert result.status is SemanticStatus.SUCCEEDED, result.reason
    assert result.reviewer is not None
    assert result.reviewer.reads[0].reason == "forbidden_path"
    assert "return a + b" not in str(gateway.exchanges)
