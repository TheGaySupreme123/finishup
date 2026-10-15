"""Committed agent-tree generator: stale pre-rename ``yoetz`` trees (ADR-048)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from finishup.adapters.integrations.codex_plugin import render_plugin_install_tree

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sync_committed_agent_trees.py"


def _script(root: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    spec = importlib.util.spec_from_file_location("sync_committed_agent_trees", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "_ROOT", root)
    return module


def _legacy_plugin_tree(root: Path) -> Path:
    legacy = root / ".agents/plugins/yoetz"
    for relative, data in render_plugin_install_tree().items():
        path = legacy / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return legacy


def test_a_stale_legacy_tree_fails_check_and_write_removes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script = _script(tmp_path, monkeypatch)
    legacy = _legacy_plugin_tree(tmp_path)

    assert script.main(["--preflight"]) == 0
    assert script.main(["--check"]) == 1
    assert "(legacy_agent_tree) .agents/plugins/yoetz" in capsys.readouterr().err

    assert script.main(["--write"]) == 0
    assert not legacy.exists()
    assert (tmp_path / ".agents/plugins/finishup/.mcp.json").is_file()
    assert (tmp_path / ".agents/skills/finishup/SKILL.md").is_file()
    assert script.main(["--check"]) == 0


def test_a_legacy_tree_with_foreign_files_is_never_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script = _script(tmp_path, monkeypatch)
    legacy = _legacy_plugin_tree(tmp_path)
    (legacy / "owner-notes.md").write_bytes(b"not generated\n")

    assert script.main(["--write"]) == 1
    assert "(foreign_agent_files) .agents/plugins/yoetz" in capsys.readouterr().err
    assert (legacy / "owner-notes.md").read_bytes() == b"not generated\n"
    assert not (tmp_path / ".agents/plugins/finishup").exists()
