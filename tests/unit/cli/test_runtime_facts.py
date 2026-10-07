"""Hook runtime-fact classifier (issue #977): install target, write scope, effective user."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from yoetz.cli import runtime_facts
from yoetz.cli.runtime_facts import install_target_class, runtime_structural_facts
from yoetz.protocol.canonical import JsonValue


def _executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """A fake runtime prefix, a workspace, a private venv and a system bin, all on PATH."""

    runtime = tmp_path / "runtime"
    workspace = tmp_path / "work"
    private = tmp_path / "private"
    system = tmp_path / "usr"
    workspace.mkdir()
    (private).mkdir()
    (private / "pyvenv.cfg").write_text("home = /x\n")
    for directory, names in (
        (runtime / "bin", ("pip", "python3")),
        (workspace / ".venv" / "bin", ("pip",)),
        (private / "bin", ("pip", "python3")),
        (system / "bin", ("pip", "python3", "pipx", "uv")),
    ):
        for name in names:
            _executable(directory / name)
    (workspace / ".venv" / "pyvenv.cfg").write_text("home = /x\n")
    monkeypatch.setattr(sys, "prefix", str(runtime))
    monkeypatch.setenv("PATH", str(system / "bin"))
    return {"runtime": runtime, "workspace": workspace, "private": private, "system": system}


def _target(command: str, env: dict[str, Path]) -> str | None:
    return install_target_class(command, str(env["workspace"]))


def test_bare_pip_resolves_through_path(env: dict[str, Path]) -> None:
    assert _target("pip install x", env) == "system"
    assert _target("python3 -m pip install x", env) == "system"


def test_pip_not_on_path_is_unresolved(
    env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(env["workspace"] / "nowhere"))
    assert _target("pip install x", env) == "unresolved"


def test_interpreter_classes_by_location(env: dict[str, Path]) -> None:
    runtime_pip = env["runtime"] / "bin" / "pip"
    assert _target(f"{runtime_pip} install x", env) == "yoetz_runtime"
    assert _target(f"{env['private'] / 'bin' / 'pip'} install x", env) == "private_env"
    assert _target(f"{env['workspace'] / '.venv' / 'bin' / 'pip'} install x", env) == (
        "workspace_env"
    )
    assert _target(f"{env['system'] / 'bin' / 'python3'} -m pip install x", env) == "system"


def test_yoetz_runtime_via_path(env: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(env["runtime"] / "bin"))
    assert _target("pip install x", env) == "yoetz_runtime"


def test_uv_variants(env: dict[str, Path]) -> None:
    assert _target(f"uv pip install --python {env['private']}/bin/python3 x", env) == "private_env"
    assert _target(f"uv pip install --python={env['runtime']}/bin/python3 x", env) == (
        "yoetz_runtime"
    )
    assert _target("uv pip install --python /some/venv/bin/python x", env) == "system"
    assert _target("uv pip install x", env) == "unresolved"
    assert _target("uv pip install --system x", env) == "system"
    assert _target("uv add x", env) == "workspace_env"
    assert _target("uv sync", env) == "workspace_env"


def test_pipx_is_private_env(env: dict[str, Path]) -> None:
    assert _target("pipx install x", env) == "private_env"


def test_compound_commands_and_prefixes(env: dict[str, Path]) -> None:
    assert _target("cd /w && pip install x", env) == "system"
    assert _target("sudo pip install x", env) == "system"
    assert _target("FOO=1 pip install x", env) == "system"
    # Ranking: the worst-first class wins across segments.
    assert _target(f"uv add x && {env['private']}/bin/pip install y", env) == "private_env"


@pytest.mark.parametrize("command", ["ls -la", "pip list", "echo pip install x", "", "git status"])
def test_non_install_commands_are_none(command: str, env: dict[str, Path]) -> None:
    assert _target(command, env) is None


def test_unbalanced_quotes_do_not_raise(env: dict[str, Path]) -> None:
    assert _target("pip install 'x", env) is None


# --- runtime_structural_facts ------------------------------------------------------------------


def _inside(root: Path) -> Callable[[str], bool]:
    prefix = str(root).rstrip("/") + "/"

    def inside(path: str) -> bool:
        return path == str(root) or path.startswith(prefix)

    return inside


def _facts(tool: str | None, tool_input: dict[str, JsonValue], root: Path) -> dict[str, JsonValue]:
    return runtime_structural_facts(
        {"tool_input": tool_input},
        tool_name=tool,
        workspace_locator=str(root),
        inside=_inside(root),
    )


@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit", "write_file"])
def test_edit_tool_outside_workspace(tool: str, tmp_path: Path) -> None:
    assert _facts(tool, {"file_path": "/elsewhere/x.py"}, tmp_path) == {
        "write_scope": "outside_workspace"
    }
    assert _facts(tool, {"file_path": str(tmp_path / "a.py")}, tmp_path) == {}
    assert _facts(tool, {"file_path": "relative/a.py"}, tmp_path) == {}


def test_edit_tool_without_workspace_claims_no_scope(tmp_path: Path) -> None:
    facts = runtime_structural_facts(
        {"tool_input": {"file_path": "/elsewhere/x.py"}},
        tool_name="Write",
        workspace_locator=None,
        inside=_inside(tmp_path),
    )
    assert facts == {}


def test_apply_patch_absolute_vs_relative(tmp_path: Path) -> None:
    outside = "*** Begin Patch\n*** Add File: /elsewhere/x\n+hi\n*** End Patch\n"
    relative = "*** Begin Patch\n*** Add File: pkg/x\n+hi\n*** End Patch\n"
    inside = f"*** Begin Patch\n*** Update File: {tmp_path}/y\n@@\n-a\n+b\n*** End Patch\n"
    assert _facts("apply_patch", {"command": outside}, tmp_path) == {
        "write_scope": "outside_workspace"
    }
    assert _facts("apply_patch", {"command": relative}, tmp_path) == {}
    assert _facts("apply_patch", {"command": inside}, tmp_path) == {}


def test_shell_redirect_scope(tmp_path: Path) -> None:
    assert (
        _facts("Bash", {"command": "echo x > /tmp/elsewhere/y"}, tmp_path)["write_scope"]
        == "outside_workspace"
    )
    assert (
        _facts("Bash", {"command": "echo x >> /tmp/elsewhere/y"}, tmp_path)["write_scope"]
        == "outside_workspace"
    )
    assert (
        _facts("Bash", {"command": "echo x | tee /tmp/elsewhere/y"}, tmp_path)["write_scope"]
        == "outside_workspace"
    )
    for harmless in (
        "echo x > /dev/null",
        "echo x 2>&1",
        f"echo x > {tmp_path}/ok",
        "echo x > relative/ok",
    ):
        assert "write_scope" not in _facts("Bash", {"command": harmless}, tmp_path), harmless


def test_effective_user_only_for_shell_tools(tmp_path: Path) -> None:
    shell = _facts("Bash", {"command": "ls"}, tmp_path)
    assert shell["effective_user"] in ("root", "non_root")
    expected = "root" if getattr(os, "geteuid")() == 0 else "non_root"
    assert shell["effective_user"] == expected
    assert "effective_user" not in _facts("Write", {"file_path": str(tmp_path / "a")}, tmp_path)
    assert _facts("Read", {"file_path": "/etc/passwd"}, tmp_path) == {}
    assert _facts(None, {"command": "ls"}, tmp_path) == {}


def test_effective_user_follows_geteuid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime_facts.os, "geteuid", lambda: 0, raising=False)
    assert _facts("Bash", {"command": "ls"}, tmp_path)["effective_user"] == "root"
    monkeypatch.setattr(runtime_facts.os, "geteuid", lambda: 501, raising=False)
    assert _facts("Bash", {"command": "ls"}, tmp_path)["effective_user"] == "non_root"


def test_install_target_fact_is_closed_token_only(env: dict[str, Path], tmp_path: Path) -> None:
    facts = runtime_structural_facts(
        {"tool_input": {"command": "pip install secret-pkg"}},
        tool_name="Bash",
        workspace_locator=str(env["workspace"]),
        inside=_inside(env["workspace"]),
    )
    assert facts["install_target"] in runtime_facts.INSTALL_TARGET_VALUES
    assert "secret-pkg" not in repr(facts)


def test_quoted_text_and_heredoc_bodies_are_not_write_targets() -> None:
    from yoetz.cli.runtime_facts import _write_targets  # pyright: ignore[reportPrivateUsage]

    assert _write_targets('git commit -m "x > /y"') == []
    assert _write_targets('echo "a>/b"') == []
    assert _write_targets("cat > /tmp/x <<EOF\nhello > /etc/z\nEOF") == ["/tmp/x"]
    assert _write_targets("bash run.sh > /tmp/log 2>&1") == ["/tmp/log"]
    assert _write_targets("echo x | tee -a /var/out") == ["/var/out"]


def test_a_system_interpreter_prefix_is_never_yoetz_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import sys

    from yoetz.cli import runtime_facts

    monkeypatch.setattr(sys, "prefix", "/usr")
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    assert runtime_facts.install_target_class("/usr/bin/pip install x", None) == "system"
