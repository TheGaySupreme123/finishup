"""Pure isolation boundary regressions, with a foreign ambient root in both launch modes."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from tests.capability.child_environment import child_environment
from tests.capability.test_codex_six_tools import (
    _serve_parameters,  # pyright: ignore[reportPrivateUsage]
)


@pytest.mark.parametrize("candidate", ["", sys.executable])
def test_child_paths_cannot_select_inherited_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, candidate: str
) -> None:
    outer = tmp_path / "synthetic-outer"
    outer.mkdir(mode=0o700)
    marker = outer / "holder"
    marker.write_text("outer-instance-holder")
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(outer))
    monkeypatch.setenv("FINISHUP_CANDIDATE_PYTHON", candidate)
    parameters = _serve_parameters(tmp_path)
    assert parameters.command == (candidate or "uv")
    environment = parameters.env
    assert environment is not None
    root = Path(environment["FINISHUP_ISOLATED_ROOT"])
    assert root != outer
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    probe = subprocess.run(
        [
            candidate or sys.executable,
            "-c",
            "import json; from finishup.config.paths import state_dir, log_dir, runtime_dir; "
            "print(json.dumps([str(f()) for f in (state_dir, log_dir, runtime_dir)]))",
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    paths = json.loads(probe.stdout)
    assert all(Path(path).is_relative_to(root) for path in paths)
    assert marker.read_text() == "outer-instance-holder"
    assert list(outer.iterdir()) == [marker]
    assert os.environ["FINISHUP_ISOLATED_ROOT"] == str(outer)


def test_child_environment_rejects_linked_root(tmp_path: Path) -> None:
    home = tmp_path / "mcp-home"
    target = tmp_path / "foreign"
    target.mkdir(mode=0o700)
    home.symlink_to(target, target_is_directory=True)
    from finishup.config.paths import PathSafetyError

    with pytest.raises(PathSafetyError, match="path_contains_symlink"):
        child_environment(tmp_path)
