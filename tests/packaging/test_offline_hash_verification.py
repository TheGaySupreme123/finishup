"""Exact-hash verification of the release wheel, with no index and no network.

Proves that a hash-locked ``--offline --no-index --no-deps`` install of the real built wheel
succeeds only when the bytes match the pinned digest, and that a corrupted copy fails closed
before anything importable lands. These installs need no dependency wheels, so this module carries
no warmed cache: the tagged release job runs it with every ``uv pip install`` forced to
``--no-index`` against an empty cache (``.github/workflows/release.yml``), which a cache-warming
install could not satisfy. ``test_offline_reinstall.py`` owns the warmed-cache cases.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class _BuiltDist:
    directory: Path
    wheel: Path
    version: str


@pytest.fixture(scope="module")
def built_dist(tmp_path_factory: pytest.TempPathFactory) -> _BuiltDist:
    dist_dir = tmp_path_factory.mktemp("hash-dist")
    result = subprocess.run(
        ["uv", "build", "--no-sources", "-o", str(dist_dir), str(_REPO_ROOT)],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    wheels = sorted(dist_dir.glob("*.whl"))
    assert len(wheels) == 1
    version = wheels[0].name.split("-")[1]
    return _BuiltDist(dist_dir, wheels[0], version)


def _offline_env(home: Path) -> dict[str, str]:
    return {**os.environ, "HOME": str(home), "UV_PYTHON_DOWNLOADS": "never"}


def _create_offline_venv(venv: Path, env: dict[str, str]) -> None:
    # Changing HOME hides uv-managed interpreters: reuse the interpreter running this test.
    created = subprocess.run(
        ["uv", "venv", "--offline", "--python", sys.executable, str(venv)],
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert created.returncode == 0, created.stderr.decode("utf-8", errors="replace")


def _corrupt_wheel_copy(original: Path, destination_dir: Path) -> Path:
    destination_dir.mkdir(parents=True, exist_ok=True)
    corrupted = destination_dir / original.name
    with zipfile.ZipFile(original) as source:
        names = source.namelist()
        payload = {name: source.read(name) for name in names}
    target = next(name for name in names if name.endswith("/__init__.py") and name.count("/") == 1)
    payload[target] = payload[target] + b"\n# corrupted-for-hash-test\n"
    with zipfile.ZipFile(corrupted, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            archive.writestr(name, payload[name])
    return corrupted


def test_corrupted_wheel_fails_exact_hash_verification_before_any_install(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    correct_digest = hashlib.sha256(built_dist.wheel.read_bytes()).hexdigest()
    corrupt_dir = tmp_path / "corrupt-wheelhouse"
    corrupted = _corrupt_wheel_copy(built_dist.wheel, corrupt_dir)
    assert hashlib.sha256(corrupted.read_bytes()).hexdigest() != correct_digest

    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        f"finishup=={built_dist.version} --hash=sha256:{correct_digest}\n", encoding="utf-8"
    )

    venv = tmp_path / "venv"
    home = tmp_path / "home"
    home.mkdir()
    env = _offline_env(home)
    _create_offline_venv(venv, env)
    result = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(venv / "bin" / "python"),
            "--offline",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "-r",
            str(requirements),
            "--find-links",
            str(corrupt_dir),
        ],
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert result.returncode != 0
    stderr = result.stderr.decode("utf-8", errors="replace").lower()
    assert "hash mismatch" in stderr
    assert correct_digest not in result.stdout.decode("utf-8", errors="replace")

    check = subprocess.run(
        [str(venv / "bin" / "python"), "-c", "import finishup"],
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert check.returncode != 0


def test_correct_hash_matching_the_real_wheel_installs_cleanly(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    correct_digest = hashlib.sha256(built_dist.wheel.read_bytes()).hexdigest()
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        f"finishup=={built_dist.version} --hash=sha256:{correct_digest}\n", encoding="utf-8"
    )

    venv = tmp_path / "venv"
    home = tmp_path / "home"
    home.mkdir()
    env = _offline_env(home)
    _create_offline_venv(venv, env)
    result = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(venv / "bin" / "python"),
            "--offline",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "-r",
            str(requirements),
            "--find-links",
            str(built_dist.directory),
        ],
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
