"""Hook runtime-fact classifier (issue #977): install target, write scope, effective user."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from builders.shell_write_vectors import VECTORS, ShellWriteVector
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
    # A named interpreter that does not exist resolves nothing.
    assert _target("uv pip install --python /some/venv/bin/python x", env) == "unresolved"
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


# --- task interpreter (tb4n1 regressions) ------------------------------------------------------


def _venv(root: Path, *names: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyvenv.cfg").write_text("home = /usr/bin\n")
    for name in names:
        _executable(root / "bin" / name)
    return root


@pytest.fixture
def task_venv(env: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> Path:
    """The image ships its task interpreter as a venv first on the agent's PATH (``/opt/venv``)."""

    task = _venv(env["system"].parent / "opt" / "venv", "python", "python3", "pip")
    monkeypatch.setenv("PATH", os.pathsep.join([str(task / "bin"), str(env["system"] / "bin")]))
    return task


def test_bare_install_into_the_task_venv_is_no_fact(env: dict[str, Path], task_venv: Path) -> None:
    assert _target("pip install x", env) == "system"
    assert _target("python -m pip install x", env) == "system"
    assert _target(f"{task_venv}/bin/pip install x", env) == "system"
    assert _target(f"uv pip install --python {task_venv}/bin/python x", env) == "system"
    # --user is that interpreter's own user site, not another environment.
    assert _target("pip install --user x", env) == "system"


def test_task_venv_reached_through_a_directory_link_is_the_task(
    env: dict[str, Path], task_venv: Path
) -> None:
    alias = env["system"].parent / "venv-link"
    alias.symlink_to(task_venv, target_is_directory=True)
    assert _target(f"{alias}/bin/pip install x", env) == "system"


def test_another_venv_by_explicit_path_is_private_env(
    env: dict[str, Path], task_venv: Path
) -> None:
    telecom = _venv(env["system"].parent / "tmp" / "telecom_venv", "pip", "python")
    sglang = _venv(env["system"].parent / "tmp" / "sglang-stream-tests312", "python")
    assert _target(f"{telecom}/bin/pip install x", env) == "private_env"
    assert _target(f"{sglang}/bin/python -m pip install x", env) == "private_env"


def test_a_system_interpreter_beside_a_venv_task_is_private_env(
    env: dict[str, Path], task_venv: Path
) -> None:
    assert _target(f"{env['system']}/bin/python3 -m pip install x", env) == "private_env"


def test_a_system_task_interpreter_keeps_other_system_pips_unflagged(env: dict[str, Path]) -> None:
    local = env["system"].parent / "usr-local"
    _executable(local / "bin" / "pip")
    # ``/usr/local/bin/pip`` usually serves ``/usr/bin/python3``; without reading it, no fact.
    assert _target(f"{local}/bin/pip install x", env) == "system"


@pytest.mark.parametrize(
    "command",
    [
        "pip install --target /tmp/deps x",
        "pip install -t /tmp/deps x",
        "pip install --target=/tmp/deps x",
        "python3 -m pip install --prefix /tmp/p x",
        "pip install --root /tmp/r x",
        "uv pip install --target /tmp/deps x",
    ],
)
def test_install_location_outside_workspace_is_private_env(
    command: str, env: dict[str, Path], task_venv: Path
) -> None:
    assert _target(command, env) == "private_env"


def test_install_location_inside_workspace_or_unknown(env: dict[str, Path]) -> None:
    assert _target(f"pip install --target {env['workspace']}/vendor x", env) == "workspace_env"
    assert _target("pip install --target vendor x", env) == "unresolved"
    assert _target("pip install --target $DEPS x", env) == "unresolved"


def test_yoetz_runtime_stays_flagged_and_is_never_the_task(
    env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The runtime first on PATH: bare pip is still Yoetz's runtime (``/opt/yr/bin/pip``).
    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(env["runtime"] / "bin"), str(env["system"] / "bin")])
    )
    assert _target("pip install x", env) == "yoetz_runtime"
    assert _target(f"{env['runtime']}/bin/pip install x", env) == "yoetz_runtime"
    assert runtime_facts._task_roots() == frozenset(  # pyright: ignore[reportPrivateUsage]
        {str(env["system"].resolve())}
    )


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
        _facts("Bash", {"command": "echo x > /opt/elsewhere/y"}, tmp_path)["write_scope"]
        == "outside_workspace"
    )
    assert (
        _facts("Bash", {"command": "echo x >> /opt/elsewhere/y"}, tmp_path)["write_scope"]
        == "outside_workspace"
    )
    assert (
        _facts("Bash", {"command": "echo x | tee /opt/elsewhere/y"}, tmp_path)["write_scope"]
        == "outside_workspace"
    )
    for harmless in ("echo x > /dev/null", "echo x 2>&1"):
        assert "write_scope" not in _facts("Bash", {"command": harmless}, tmp_path), harmless


def test_printing_an_operator_or_tee_is_not_an_outside_write(tmp_path: Path) -> None:
    """Text is not syntax, at the hook entry point and for absolute paths (Codex review, #1028)."""

    for printed in (
        'echo ">" /etc/motd',
        "echo tee /etc/motd",
        "echo 'a > /etc/motd'",
        "echo \\> /etc/motd",
        "echo hi # > /etc/motd",
    ):
        assert "write_scope" not in _facts("Bash", {"command": printed}, tmp_path), printed
    # The shell the host wraps the command in still runs the real write.
    wrapped = _facts("Bash", {"command": "/bin/bash -lc 'echo x > /etc/motd'"}, tmp_path)
    assert wrapped["write_scope"] == "outside_workspace"
    # ADR-045: a command that visibly writes the workspace is an edit, so it says so.
    for workspace_write in (f"echo x > {tmp_path}/ok", "echo x > relative/ok"):
        assert (
            _facts("Bash", {"command": workspace_write}, tmp_path)["write_scope"] == "workspace"
        ), workspace_write


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


def test_quoted_text_and_heredoc_bodies_are_not_write_targets(tmp_path: Path) -> None:
    """The hook entry point reads the one shared parser (``domain.shell_writes``), and the
    classifier that parser feeds decides every written path, outside ones included."""

    def scope(command: str) -> JsonValue:
        return _facts("Bash", {"command": command}, tmp_path).get("write_scope")

    assert scope('git commit -m "x > /y"') is None
    assert scope('echo "a>/b"') is None
    assert scope("cat > /tmp/x <<EOF\nhello > /etc/z\nEOF") is None  # /tmp/x is scratch
    assert scope("bash run.sh > /tmp/log 2>&1") is None
    assert scope("echo x | tee -a /var/out") == "outside_workspace"
    assert scope("cat > /tmp/x <<EOF\nhello\nEOF\necho y > /etc/z") == "outside_workspace"


@pytest.mark.parametrize("vector", VECTORS, ids=[f"{n:03d}" for n, _ in enumerate(VECTORS)])
def test_the_hook_claims_the_scope_the_shared_vectors_name(vector: ShellWriteVector) -> None:
    """tb4n3 shell-write review (#1028): the same exact commands the domain and stream tests read.

    The workspace is ``/app`` (lexical, never touched); ``write_scope`` is absent when the
    command claims none."""

    facts = runtime_structural_facts(
        {"tool_input": {"command": vector.command}},
        tool_name="Bash",
        workspace_locator="/app",
        inside=lambda path: path == "/app" or path.startswith("/app/"),
    )
    assert facts.get("write_scope") == vector.hook, vector.command


def test_a_yoetz_receipt_copied_outside_the_workspace_is_yoetz_owned_not_outside(
    tmp_path: Path,
) -> None:
    """Review 3: the outside precheck returned before the ownership rule, so a saved receipt made
    a verification stale. One classifier decides, for a shell command as for an edit tool."""

    for command in (
        "cp source.json /opt/yoetz_receipt.json",
        "echo '{}' > /opt/yoetz_receipt.json",
        "cat /app/r.json | tee /opt/out/yoetz_export.json",
    ):
        assert _facts("Bash", {"command": command}, tmp_path)["write_scope"] == "yoetz_owned"
    assert _facts("Write", {"file_path": "/opt/yoetz_receipt.json"}, tmp_path) == {
        "write_scope": "yoetz_owned"
    }
    # Any real outside write still wins over Yoetz's own material.
    both = "cp a /opt/yoetz_receipt.json && cp b /opt/result.json"
    assert _facts("Bash", {"command": both}, tmp_path)["write_scope"] == "outside_workspace"


def test_a_literal_dollar_or_star_in_an_outside_target_is_still_an_outside_write(
    tmp_path: Path,
) -> None:
    """Review 4: quoting makes ``$`` and ``*`` literal; an expansion names no path."""

    for literal in ("echo x > '/opt/$report.txt'", "echo x > /opt/file\\*.py"):
        assert _facts("Bash", {"command": literal}, tmp_path)["write_scope"] == "outside_workspace"
    for expansion in ('echo x > "/opt/$report.txt"', "echo x > /opt/file*.py", "echo x > $OUT"):
        assert "write_scope" not in _facts("Bash", {"command": expansion}, tmp_path), expansion


def test_a_system_interpreter_prefix_is_never_yoetz_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import sys

    from yoetz.cli import runtime_facts

    monkeypatch.setattr(sys, "prefix", "/usr")
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    assert runtime_facts.install_target_class("/usr/bin/pip install x", None) != "yoetz_runtime"


# --- temporary directories are scratch, not misplaced deliverables (E6, tb4n1) ------------------


@pytest.mark.parametrize(
    "target",
    [
        "/tmp/build.log",
        "/tmp/nested/dir/run.log",
        "/private/tmp/x.log",
        "/var/tmp/x.log",
        "/private/var/tmp/x.log",
        "/dev/shm/x",
        "/var/folders/ab/cd1234/T/tmp.x/log.txt",
        "/private/var/folders/ab/cd1234/T/log.txt",
        "/tmp//double/slash.log",
        "/tmp/./dot.log",
    ],
)
def test_temporary_directory_writes_claim_no_scope(target: str, tmp_path: Path) -> None:
    workspace = tmp_path / "work"
    for command in (
        f"python run.py > {target} 2>&1",
        f"pytest -q 2>&1 | tee {target}",
        f"cat > {target} <<'EOF'\nlog\nEOF",
    ):
        assert "write_scope" not in _facts("Bash", {"command": command}, workspace), command
    # An edit tool's scratch write claims no outside scope; it is named ``scratch`` so it never
    # makes an earlier verification stale (ADR-042, tb4n2 R4).
    for tool in ("Write", "Edit"):
        assert _facts(tool, {"file_path": target}, workspace) == {"write_scope": "scratch"}, tool
    patch = f"*** Begin Patch\n*** Add File: {target}\n+hi\n*** End Patch\n"
    assert _facts("apply_patch", {"command": patch}, workspace) == {"write_scope": "scratch"}


@pytest.mark.parametrize(
    "target",
    [
        "/tmp/../etc/passwd",
        "/tmp/x/../../etc/hosts",
        "/dev/shm/../../etc/x",
        "/var/tmp/../lib/x",
        "/var/folders/ab/cd/C/cache.db",
        "/private/var/folders/ab/cd/T/../../../../etc/x",
        "/tmpfoo/x.log",
        "/opt/tmp/x.log",
    ],
)
def test_climbing_out_of_a_temporary_root_still_counts(target: str, tmp_path: Path) -> None:
    workspace = tmp_path / "work"
    assert _facts("Bash", {"command": f"echo x > {target}"}, workspace) == {
        "write_scope": "outside_workspace",
        "effective_user": "root" if getattr(os, "geteuid")() == 0 else "non_root",
    }
    assert _facts("Write", {"file_path": target}, workspace) == {"write_scope": "outside_workspace"}


def test_process_temp_dir_is_scratch(monkeypatch: pytest.MonkeyPatch) -> None:
    # A host TMPDIR outside every fixed temporary root (a cluster scratch volume, say).
    scratch = "/srv/scratch-tmp"
    monkeypatch.setenv("TMPDIR", scratch + "/")
    monkeypatch.setenv("HOME", "/home/someone")
    workspace = Path("/srv/work")
    assert "write_scope" not in _facts(
        "Bash", {"command": f"make > {scratch}/build.log"}, workspace
    )
    assert _facts("Write", {"file_path": f"{scratch}/../escape.txt"}, workspace) == {
        "write_scope": "outside_workspace"
    }


@pytest.mark.parametrize("tmpdir", ["/", "/home", "/home/someone"])
def test_a_temp_dir_that_contains_home_is_never_trusted(
    tmpdir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TMPDIR", tmpdir)
    monkeypatch.setenv("HOME", "/home/someone")
    workspace = Path("/srv/work")
    assert _facts("Write", {"file_path": "/home/someone/notes.txt"}, workspace) == {
        "write_scope": "outside_workspace"
    }


def test_temp_roots_never_probe_the_filesystem(monkeypatch: pytest.MonkeyPatch) -> None:
    """L3 review: gettempdir probes, can fall back to cwd and raises when no dir is usable."""

    import tempfile

    def unusable() -> str:
        raise FileNotFoundError("No usable temporary directory found")

    monkeypatch.setattr(tempfile, "gettempdir", unusable)
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", "/home/someone")
    workspace = Path("/srv/work")
    facts = _facts("Bash", {"command": "make > /srv/elsewhere/build.log"}, workspace)
    assert facts["write_scope"] == "outside_workspace"
    assert "write_scope" not in _facts("Bash", {"command": "make > /tmp/build.log"}, workspace)


@pytest.mark.parametrize("tmpdir", ["/srv/work", "/srv", "/srv/work/"])
def test_a_temp_dir_that_is_or_contains_the_workspace_is_never_trusted(
    tmpdir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TMPDIR", tmpdir)
    monkeypatch.setenv("HOME", "/home/someone")
    workspace = Path("/srv/work")
    assert _facts("Write", {"file_path": "/srv/other/out.txt"}, workspace) == {
        "write_scope": "outside_workspace"
    }


# --- adversarial review follow-ups (E5, E6) -----------------------------------------------------


def test_sudo_options_and_attached_target_are_read(env: dict[str, Path], task_venv: Path) -> None:
    telecom = _venv(env["system"].parent / "tmp" / "telecom_venv", "pip", "python")
    assert _target(f"sudo -H -u builder {telecom}/bin/pip install x", env) == "private_env"
    assert _target("sudo -E pip install x", env) == "system"
    assert _target("pip install -t/opt/deps x", env) == "private_env"


def test_a_conda_environment_is_an_environment_of_its_own(
    env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    base = env["system"].parent / "opt" / "conda"
    (base / "conda-meta").mkdir(parents=True)
    for name in ("python", "python3", "pip"):
        _executable(base / "bin" / name)
    other = base / "envs" / "scratch"
    (other / "conda-meta").mkdir(parents=True)
    _executable(other / "bin" / "pip")
    monkeypatch.setenv("PATH", os.pathsep.join([str(base / "bin"), str(env["system"] / "bin")]))
    assert _target("pip install x", env) == "system"
    assert _target(f"{other}/bin/pip install x", env) == "private_env"


def test_a_temp_dir_not_named_as_temporary_space_is_never_trusted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A TMPDIR pointed at a deliverable directory (`/results`) must not hide writes there."""

    monkeypatch.setenv("TMPDIR", "/results")
    monkeypatch.setenv("HOME", "/home/someone")
    workspace = Path("/srv/work")
    assert _facts("Write", {"file_path": "/results/report.json"}, workspace) == {
        "write_scope": "outside_workspace"
    }


@pytest.mark.parametrize(
    "target",
    ["/mnt/c/Users/dev/AppData/Local/Temp/run.log", "/mnt/d/Windows/Temp/x.txt"],
)
def test_wsl_windows_temp_is_scratch(target: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", "/home/someone")
    assert _facts("Write", {"file_path": target}, Path("/srv/work")) == {"write_scope": "scratch"}


def test_a_patch_that_deletes_a_workspace_file_is_a_workspace_edit(tmp_path: Path) -> None:
    """Codex review round 1: Delete File paths count, so a mixed patch is never scratch."""

    workspace = tmp_path / "work"
    patch = (
        "*** Begin Patch\n"
        f"*** Delete File: {workspace}/src/core.py\n"
        "*** Add File: /tmp/notes.py\n+x\n*** End Patch\n"
    )
    assert _facts("apply_patch", {"command": patch}, workspace) == {}
