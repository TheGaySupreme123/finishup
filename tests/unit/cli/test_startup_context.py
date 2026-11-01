"""The startup cue is a stateless fresh-process path even with broken observation."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Literal

import pytest

from finishup.cli import startup_context


@pytest.mark.parametrize("host", ["claude", "cursor"])
def test_cue_contains_bounded_bootstrap_and_resume_rules(host: Literal["claude", "cursor"]) -> None:
    out = io.BytesIO()
    assert startup_context.handle_startup_context(host=host, stdout=out) == 0
    body = json.loads(out.getvalue())
    cue = (
        body["hookSpecificOutput"]["additionalContext"]
        if host == "claude"
        else body["additional_context"]
    )
    assert len(cue) < 2_000
    for phrase in (
        "finishup://guidance/workflow.md",
        "Skip trivial",
        "tool schemas",
        "start mode=attach",
        "effective obligations",
        "resume or compaction",
        "does not activate",
        "semantic disclosure.",
    ):
        assert phrase in cue
    assert "permissionDecision" not in body
    assert "permission" not in body


def test_missing_packaged_guidance_keeps_a_recovery_cue(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(_package: str) -> object:
        raise OSError("private path must not appear")

    monkeypatch.setattr(startup_context.resources, "files", unavailable)
    out = io.BytesIO()
    startup_context.handle_startup_context(host="cursor", stdout=out)
    cue = json.loads(out.getvalue())["additional_context"]
    assert "read_guidance" in cue
    assert "private path" not in cue


@pytest.mark.parametrize("host", ["claude", "cursor"])
def test_real_entry_never_reads_observation_service_or_stdin(tmp_path: Path, host: str) -> None:
    # Blocking these imports proves that disabled/paused/busy/corrupt local state
    # cannot influence this path. A nonexistent root additionally catches writes.
    source = """
import importlib.abc
import sys
class NoState(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith(('finishup.adapters', 'finishup.config', 'finishup.service',
                                'finishup.application', 'finishup.cli.observe_hooks',
                                'finishup.cli.app', 'typer', 'pydantic')):
            raise AssertionError('startup cue accessed state or heavyweight runtime')
class NoInput:
    @property
    def buffer(self):
        raise AssertionError('startup cue read host payload')
sys.meta_path.insert(0, NoState())
sys.stdin = NoInput()
from finishup.cli.entry import main
sys.argv = ['finishup', 'hooks', 'startup-context', '--host', sys.argv[1]]
main()
"""
    isolated = tmp_path / "must-not-exist"
    completed = subprocess.run(
        [sys.executable, "-c", source, host],
        env={**os.environ, "FINISHUP_ISOLATED_ROOT": str(isolated)},
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    assert completed.stderr == b""
    assert len(completed.stdout.splitlines()) == 1
    body = json.loads(completed.stdout)
    if host == "claude":
        assert body["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    else:
        assert set(body) == {"additional_context"}
    assert not isolated.exists()
