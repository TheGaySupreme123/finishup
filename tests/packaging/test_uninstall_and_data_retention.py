"""Package removal without user-data loss.

Proves that ``uv tool uninstall`` (the documented v0.1 uninstall path, ADR-007 point 9) removes only
the package-managed executable/environment while leaving app-data bundles, an externally-integrated
skill copy, and a locally modified skill copy byte-identical -- and that reinstalling from the same
offline wheel afterward rediscovers the preserved data untouched.

Scope note: exercising this against a fully unlocked vault would require driving the real
foreground passphrase-vault ceremony, which needs a genuine controlling TTY
(``TrustedForegroundConsole`` opens ``/dev/tty`` on POSIX and checks
``os.tcgetpgrp``/isatty plus matching stdin/stderr terminal endpoints). That is real, deliberate, out-of-scope-to-relax product
security (not a gap in this file), and is exercised in ``test_clean_install.py``/
``test_offline_reinstall.py`` instead. This file's own invariant -- "package removal never deletes
user ledger/object/backup/key data" -- does not require an unlocked vault to prove: it is proven by
placing synthetic-but-realistic bytes at the exact contractual paths ``finishup.config.paths`` computes
(``bundle_root()``, ``catalog_path()``, ``task_bundle_dir()``), recording their digests, and showing
``uv tool uninstall``/reinstall never touches anything outside its own isolated tool environment.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class _BuiltDist:
    directory: Path
    wheel: Path


@pytest.fixture(scope="module")
def built_dist(tmp_path_factory: pytest.TempPathFactory) -> _BuiltDist:
    dist_dir = tmp_path_factory.mktemp("uninstall-dist")
    result = subprocess.run(
        ["uv", "build", "--no-sources", "-o", str(dist_dir), str(_REPO_ROOT)],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    wheels = sorted(dist_dir.glob("*.whl"))
    assert len(wheels) == 1
    return _BuiltDist(dist_dir, wheels[0])


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_digests(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {
        str(path.relative_to(root)): _digest(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _bundle_root(python: Path, home: Path) -> Path:
    probe = "from finishup.config.paths import bundle_root; print(bundle_root())"
    result = subprocess.run(
        [str(python), "-c", probe],
        capture_output=True,
        timeout=30,
        env={**os.environ, "HOME": str(home)},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return Path(result.stdout.decode("utf-8").strip())


def _tool_install(
    dist_dir: Path,
    root: Path,
    home: Path,
    *,
    extras: tuple[str, ...] = (),
) -> tuple[Path, dict[str, str]]:
    """Install (offline, warming the shared cache once if needed) and return (finishup_exe, env)."""

    tool_dir = root / "tool"
    bin_dir = root / "bin"
    wheels = sorted(dist_dir.glob("*.whl"))
    assert len(wheels) == 1
    spec = str(wheels[0]) + (f"[{','.join(extras)}]" if extras else "")
    # Overriding HOME isolates the *application's* paths (bundle_root() etc.), but uv's own
    # download cache must keep resolving to the real, already-warm shared cache -- otherwise an
    # --offline install has nothing to install from. Pin UV_CACHE_DIR to the real cache explicitly.
    real_cache_dir = (
        subprocess.run(["uv", "cache", "dir"], capture_output=True, timeout=15, check=False)
        .stdout.decode("utf-8")
        .strip()
    )
    env = {
        **os.environ,
        "HOME": str(home),
        "UV_TOOL_DIR": str(tool_dir),
        "UV_TOOL_BIN_DIR": str(bin_dir),
        "UV_CACHE_DIR": real_cache_dir,
    }

    def _install(offline: bool) -> subprocess.CompletedProcess[bytes]:
        args = ["uv", "tool", "install", "--python", "3.14"]
        if offline:
            args.append("--offline")
        args += ["--find-links", str(dist_dir), spec]
        return subprocess.run(args, capture_output=True, timeout=180, env=env, check=False)

    result = _install(offline=True)
    if result.returncode != 0:
        warm_venv = root / "warm"
        subprocess.run(
            ["uv", "venv", "--python", "3.14", str(warm_venv)],
            capture_output=True,
            timeout=120,
            env=env,
            check=False,
        )
        subprocess.run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(warm_venv / "bin" / "python"),
                "--find-links",
                str(dist_dir),
                spec,
            ],
            capture_output=True,
            timeout=180,
            env=env,
            check=False,
        )
        result = _install(offline=True)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return bin_dir / "finishup", env


def _tool_uninstall(env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["uv", "tool", "uninstall", "finishup"],
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )


# ---------------------------------------------------------------------------
# Base uninstall preserves app-data
# ---------------------------------------------------------------------------


def test_base_uninstall_preserves_bundle_and_catalog_bytes(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install-root"
    home = root / "home"
    home.mkdir(parents=True)

    finishup_exe, env = _tool_install(built_dist.directory, root, home)
    assert finishup_exe.is_file()

    help_result = subprocess.run(
        [str(finishup_exe), "--help"], capture_output=True, timeout=15, env=env, check=False
    )
    assert help_result.returncode == 0

    bundle = _bundle_root(root / "tool" / "finishup" / "bin" / "python", home)
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "catalog.sqlite3").write_bytes(b"sqlite-format-3\x00synthetic-catalog-bytes")
    task_dir = bundle / "tasks" / "tsk_0000000000000000000000000001"
    task_dir.mkdir(parents=True)
    (task_dir / "receipt.json").write_text(
        json.dumps({"schema": "yoetz.receipt-document/1.0.0", "note": "synthetic"}),
        encoding="utf-8",
    )
    before = _tree_digests(bundle)
    assert before, "synthetic bundle inventory must be non-empty"

    uninstall_result = _tool_uninstall(env)
    assert uninstall_result.returncode == 0, uninstall_result.stderr

    assert not finishup_exe.exists()
    assert not (root / "tool" / "finishup").exists()

    after = _tree_digests(bundle)
    assert after == before


def test_base_uninstall_removes_the_tool_bin_and_environment(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install-root"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)
    assert finishup_exe.is_file()
    result = _tool_uninstall(env)
    assert result.returncode == 0, result.stderr
    assert not finishup_exe.exists()
    remaining_tools = list((root / "tool").glob("*")) if (root / "tool").exists() else []
    assert "finishup" not in {path.name for path in remaining_tools}


# ---------------------------------------------------------------------------
# Extra uninstall
# ---------------------------------------------------------------------------


def test_extra_uninstall_preserves_bundle_bytes_too(built_dist: _BuiltDist, tmp_path: Path) -> None:
    root = tmp_path / "install-root"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(
        built_dist.directory, root, home, extras=("portable-recovery",)
    )
    assert finishup_exe.is_file()

    bundle = _bundle_root(root / "tool" / "finishup" / "bin" / "python", home)
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "catalog.sqlite3").write_bytes(b"extra-cell-synthetic-bytes")
    before = _tree_digests(bundle)

    result = _tool_uninstall(env)
    assert result.returncode == 0, result.stderr
    assert not finishup_exe.exists()
    assert _tree_digests(bundle) == before


# ---------------------------------------------------------------------------
# Integrated skill preservation: identical vs locally modified copy
# ---------------------------------------------------------------------------


def test_uninstall_never_touches_a_workspace_integrated_skill_copy(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install-root"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)

    # A workspace-integrated skill copy lives entirely outside the tool env / bundle root.
    workspace = tmp_path / "workspace"
    skill_dir = workspace / ".codex" / "skills" / "finishup"
    skill_dir.mkdir(parents=True)
    packaged_skill = _REPO_ROOT / "skills" / "codex" / "finishup" / "SKILL.md"
    (skill_dir / "SKILL.md").write_bytes(packaged_skill.read_bytes())
    identical_digest_before = _digest(skill_dir / "SKILL.md")

    modified_dir = tmp_path / "workspace-modified"
    modified_skill_dir = modified_dir / ".codex" / "skills" / "finishup"
    modified_skill_dir.mkdir(parents=True)
    (modified_skill_dir / "SKILL.md").write_bytes(
        packaged_skill.read_bytes() + b"\n<!-- locally modified by a user -->\n"
    )
    modified_digest_before = _digest(modified_skill_dir / "SKILL.md")

    result = _tool_uninstall(env)
    assert result.returncode == 0, result.stderr
    assert not finishup_exe.exists()

    assert _digest(skill_dir / "SKILL.md") == identical_digest_before
    assert _digest(modified_skill_dir / "SKILL.md") == modified_digest_before


# ---------------------------------------------------------------------------
# Reinstall reattaches preserved data
# ---------------------------------------------------------------------------


def test_reinstall_from_the_same_offline_wheel_reattaches_preserved_data(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install-root"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)

    bundle = _bundle_root(root / "tool" / "finishup" / "bin" / "python", home)
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "catalog.sqlite3").write_bytes(b"reinstall-preserved-bytes")
    before = _tree_digests(bundle)

    uninstall_result = _tool_uninstall(env)
    assert uninstall_result.returncode == 0, uninstall_result.stderr
    assert not finishup_exe.exists()
    assert _tree_digests(bundle) == before

    reinstalled_exe, _ = _tool_install(built_dist.directory, root, home)
    assert reinstalled_exe.is_file()
    help_result = subprocess.run(
        [str(reinstalled_exe), "--help"], capture_output=True, timeout=15, env=env, check=False
    )
    assert help_result.returncode == 0
    assert _tree_digests(bundle) == before


# ---------------------------------------------------------------------------
# Uninstall/reinstall failure does not trigger a broader cleanup
# ---------------------------------------------------------------------------


def test_uninstalling_an_absent_tool_fails_without_touching_the_bundle(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install-root"
    home = root / "home"
    home.mkdir(parents=True)
    env = {
        **os.environ,
        "HOME": str(home),
        "UV_TOOL_DIR": str(root / "tool"),
        "UV_TOOL_BIN_DIR": str(root / "bin"),
    }
    bundle = _bundle_root(_repo_dev_python(), home)
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "catalog.sqlite3").write_bytes(b"never-touched")
    before = _tree_digests(bundle)

    result = _tool_uninstall(env)
    assert result.returncode != 0
    assert _tree_digests(bundle) == before
    shutil.rmtree(root, ignore_errors=True)


def _repo_dev_python() -> Path:
    return _REPO_ROOT / ".venv" / "bin" / "python"
