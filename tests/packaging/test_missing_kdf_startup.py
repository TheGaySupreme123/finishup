"""Installed-wheel fail-closed coverage for the passphrase KDF dependency."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Final

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]


def test_missing_installed_argon2_kdf_reports_a_bounded_startup_remedy(tmp_path: Path) -> None:
    """Fault only the disposable wheel install, never the developer environment."""

    root = tmp_path / "issue157"
    dist = root / "dist"
    env = {
        **os.environ,
        "HOME": str(root / "home"),
        "UV_CACHE_DIR": str(root / "cache"),
        "UV_TOOL_BIN_DIR": str(root / "bin"),
        "UV_TOOL_DIR": str(root / "tool"),
        "FINISHUP_STORAGE_DATA_DIR": str(root / "data"),
    }
    build = subprocess.run(
        ["uv", "build", "--no-sources", "-o", str(dist), str(_REPO_ROOT)],
        capture_output=True,
        timeout=180,
        env=env,
        check=False,
    )
    assert build.returncode == 0, build.stderr.decode("utf-8", errors="replace")
    wheels = sorted(dist.glob("*.whl"))
    assert len(wheels) == 1, "expected exactly one real wheel artifact"
    install = subprocess.run(
        [
            "uv",
            "tool",
            "install",
            "--python",
            "3.14.6",
            "--find-links",
            str(dist),
            str(wheels[0]),
        ],
        capture_output=True,
        timeout=180,
        env=env,
        check=False,
    )
    assert install.returncode == 0, install.stderr.decode("utf-8", errors="replace")

    executable = Path(env["UV_TOOL_BIN_DIR"]) / "finishup"
    argon2 = next(
        (root / "tool" / "finishup").rglob("cryptography/hazmat/primitives/kdf/argon2.py")
    )
    argon2.rename(argon2.with_suffix(".py.hidden"))

    startup = subprocess.run(
        [str(executable), "service", "run"],
        capture_output=True,
        timeout=15,
        env=env,
        check=False,
    )
    assert startup.returncode == 20
    assert b"passphrase_kdf_unavailable" in startup.stderr
    assert b"reinstall this FinishUP package" in startup.stderr
    assert b"Traceback (most recent call last)" not in startup.stderr
    assert not (root / "data").exists(), "missing KDF must fail before any retained-state write"
