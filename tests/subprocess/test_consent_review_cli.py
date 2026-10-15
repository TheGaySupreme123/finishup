"""Real CLI subprocess negatives for the trusted consent-review boundary."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_CHILD = r"""
import sys
from pathlib import Path
import finishup.service.elevated_bootstrap as bootstrap

root = Path(sys.argv[1])
bootstrap.state_dir = lambda: root

from finishup.cli.app import app
app(args=sys.argv[2:], prog_name="finishup")
"""


def _run(
    state: Path, arguments: list[str], *, input_bytes: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = "src"
    return subprocess.run(
        [sys.executable, "-c", _CHILD, str(state), *arguments],
        input=input_bytes,
        capture_output=True,
        check=False,
        env=environment,
        timeout=10,
    )


def test_redirected_stdin_cannot_approve_or_consume_pending(tmp_path: Path) -> None:
    prepared = _run(tmp_path, ["consent", "prepare", "vault_initialize"])
    assert prepared.returncode == 0
    projection = json.loads(prepared.stdout)
    assert projection["pending"]["review_command"] == ["finishup", "consent", "review"]

    pending = tmp_path / "elevated-bootstrap" / "elevated-bootstrap-pending.json"
    before = pending.read_bytes()
    reviewed = _run(tmp_path, ["consent", "review"], input_bytes=b"approve\n")
    assert reviewed.returncode == 2
    assert b"human_authority_unavailable" in reviewed.stderr
    assert pending.read_bytes() == before
    assert b"Traceback" not in reviewed.stderr


def test_forged_review_arguments_fail_before_pending_mutation(tmp_path: Path) -> None:
    assert _run(tmp_path, ["consent", "prepare", "vault_initialize"]).returncode == 0
    pending = tmp_path / "elevated-bootstrap" / "elevated-bootstrap-pending.json"
    before = pending.read_bytes()

    forged = _run(tmp_path, ["consent", "review", "--approve"])
    assert forged.returncode == 2
    assert pending.read_bytes() == before
    assert b"Traceback" not in forged.stderr
