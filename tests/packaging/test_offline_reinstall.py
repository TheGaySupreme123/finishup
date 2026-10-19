"""Hash-locked, network-denied reinstall.

Proves that the captured release wheelhouse (the real built wheel plus a warmed, real ``uv`` cache
standing in for the release wheelhouse) is sufficient to install and reinstall strict-local FinishUP
with ``--offline`` -- uv's own hard network-denial flag -- and that missing dependencies, a
platform/arch mismatch, and a corrupted/hash-mismatched wheel each fail closed before a partial
usable environment, rather than silently falling back to a registry, a source build, or a relaxed
hash.

Scope note: this single-machine session has no dedicated multi-host network-denied VM/container
fleet. ``--offline`` is ``uv``'s own documented, enforced network-denial mechanism (an install that
needs the network with ``--offline`` set simply fails, as demonstrated by the "missing dependency"
and "wrong platform" cases below); this file treats it as the real, verifiable network-denial gate
rather than fabricating an external network-namespace sandbox.
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
    dist_dir = tmp_path_factory.mktemp("offline-dist")
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


def _real_cache_dir() -> str:
    result = subprocess.run(["uv", "cache", "dir"], capture_output=True, timeout=15, check=False)
    return result.stdout.decode("utf-8").strip()


@pytest.fixture(scope="module", autouse=True)
def warm_wheelhouse_cache(built_dist: _BuiltDist) -> None:
    """Populate the real uv cache once per module: the release-evidence equivalent of capturing
    a wheelhouse. Every test in this module then installs with --offline against that capture."""

    warm_dir = built_dist.directory.parent / "warm-venv"
    created = subprocess.run(
        ["uv", "venv", "--python", sys.executable, str(warm_dir)],
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert created.returncode == 0, created.stderr.decode("utf-8", errors="replace")
    installed = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(warm_dir / "bin" / "python"),
            "--find-links",
            str(built_dist.directory),
            f"finishup[semantic-openai,portable-recovery]=={built_dist.version}",
        ],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert installed.returncode == 0, installed.stderr.decode("utf-8", errors="replace")


def _offline_env(home: Path) -> dict[str, str]:
    return {
        **os.environ,
        "HOME": str(home),
        "UV_CACHE_DIR": _real_cache_dir(),
        "UV_PYTHON_DOWNLOADS": "never",
    }


def _create_offline_venv(venv: Path, env: dict[str, str]) -> None:
    # Changing HOME hides uv-managed interpreters. Resolve no version here: use the interpreter
    # already running this test, and deny downloads during environment creation as well.
    created = subprocess.run(
        ["uv", "venv", "--offline", "--python", sys.executable, str(venv)],
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert created.returncode == 0, created.stderr.decode("utf-8", errors="replace")


def _offline_venv_install(
    dist_dir: Path, venv: Path, home: Path, spec: str, *, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    env = _offline_env(home)
    if extra_env:
        env.update(extra_env)
    _create_offline_venv(venv, env)
    return subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(venv / "bin" / "python"),
            "--offline",
            "--find-links",
            str(dist_dir),
            spec,
        ],
        capture_output=True,
        timeout=120,
        env=env,
        check=False,
    )


# ---------------------------------------------------------------------------
# Clean offline install / base and extras
# ---------------------------------------------------------------------------


def test_clean_offline_install_of_the_base_package(built_dist: _BuiltDist, tmp_path: Path) -> None:
    venv = tmp_path / "venv"
    home = tmp_path / "home"
    home.mkdir()
    result = _offline_venv_install(
        built_dist.directory, venv, home, f"finishup=={built_dist.version}"
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    version = subprocess.run(
        [str(venv / "bin" / "finishup"), "--version"], capture_output=True, timeout=15, check=False
    )
    assert version.returncode == 0
    assert built_dist.version.encode() in version.stdout


@pytest.mark.parametrize("extra", ["semantic-openai", "portable-recovery"])
def test_clean_offline_install_of_each_advertised_extra(
    built_dist: _BuiltDist, tmp_path: Path, extra: str
) -> None:
    venv = tmp_path / "venv"
    home = tmp_path / "home"
    home.mkdir()
    result = _offline_venv_install(
        built_dist.directory, venv, home, f"finishup[{extra}]=={built_dist.version}"
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


def test_offline_install_never_touches_the_network(built_dist: _BuiltDist, tmp_path: Path) -> None:
    venv = tmp_path / "venv"
    home = tmp_path / "home"
    home.mkdir()
    # Poisoned proxy env: if uv ever attempted a network request despite --offline, routing
    # through this unreachable proxy would surface as a distinct connection-refused failure
    # instead of a clean cache-only resolution.
    poisoned = {
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
    }
    result = _offline_venv_install(
        built_dist.directory, venv, home, f"finishup=={built_dist.version}", extra_env=poisoned
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert b"127.0.0.1:1" not in result.stderr


# ---------------------------------------------------------------------------
# Uninstall / reinstall with retained data, replayed from the same wheelhouse
# ---------------------------------------------------------------------------


def test_uninstall_then_offline_reinstall_from_the_same_wheelhouse(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    venv = tmp_path / "venv"
    home = tmp_path / "home"
    home.mkdir()
    first = _offline_venv_install(
        built_dist.directory, venv, home, f"finishup=={built_dist.version}"
    )
    assert first.returncode == 0, first.stderr

    env = _offline_env(home)
    uninstall = subprocess.run(
        ["uv", "pip", "uninstall", "--python", str(venv / "bin" / "python"), "finishup"],
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert uninstall.returncode == 0, uninstall.stderr
    check_removed = subprocess.run(
        [str(venv / "bin" / "python"), "-c", "import finishup"],
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert check_removed.returncode != 0

    second = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(venv / "bin" / "python"),
            "--offline",
            "--find-links",
            str(built_dist.directory),
            f"finishup=={built_dist.version}",
        ],
        capture_output=True,
        timeout=120,
        env=env,
        check=False,
    )
    assert second.returncode == 0, second.stderr.decode("utf-8", errors="replace")
    version = subprocess.run(
        [str(venv / "bin" / "finishup"), "--version"], capture_output=True, timeout=15, check=False
    )
    assert version.returncode == 0


# ---------------------------------------------------------------------------
# Missing dependency wheel: an empty cache fails closed
# ---------------------------------------------------------------------------


def test_missing_dependency_wheel_in_an_empty_cache_fails_closed(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    empty_cache = tmp_path / "empty-cache"
    empty_cache.mkdir()
    venv = tmp_path / "venv"
    home = tmp_path / "home"
    home.mkdir()
    env = {**_offline_env(home), "UV_CACHE_DIR": str(empty_cache)}
    _create_offline_venv(venv, env)
    result = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(venv / "bin" / "python"),
            "--offline",
            "--find-links",
            str(built_dist.directory),
            f"finishup=={built_dist.version}",
        ],
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert result.returncode != 0
    stderr = result.stderr.decode("utf-8", errors="replace").lower()
    assert "network was disabled" in stderr or "no solution" in stderr
    # No partial usable environment: the package must not have been linked in despite the failure.
    check = subprocess.run(
        [str(venv / "bin" / "python"), "-c", "import finishup"],
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert check.returncode != 0


def test_missing_dependency_wheel_never_falls_back_to_a_source_build(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    empty_cache = tmp_path / "empty-cache"
    empty_cache.mkdir()
    venv = tmp_path / "venv"
    home = tmp_path / "home"
    home.mkdir()
    env = {**_offline_env(home), "UV_CACHE_DIR": str(empty_cache)}
    _create_offline_venv(venv, env)
    result = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(venv / "bin" / "python"),
            "--offline",
            "--no-build",
            "--find-links",
            str(built_dist.directory),
            f"finishup=={built_dist.version}",
        ],
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert result.returncode != 0
    stderr = result.stderr.decode("utf-8", errors="replace").lower()
    assert "compil" not in stderr
    assert "building" not in stderr


# ---------------------------------------------------------------------------
# Wrong-platform wheel: cross-platform resolution fails closed offline
# ---------------------------------------------------------------------------


def test_wrong_platform_apsw_wheel_fails_before_install(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    venv = tmp_path / "venv"
    home = tmp_path / "home"
    home.mkdir()
    env = _offline_env(home)
    _create_offline_venv(venv, env)
    foreign_platform = (
        "x86_64-manylinux_2_28" if os.uname().machine == "arm64" else "aarch64-apple-darwin"
    )
    result = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(venv / "bin" / "python"),
            "--offline",
            "--python-platform",
            foreign_platform,
            "--find-links",
            str(built_dist.directory),
            f"finishup=={built_dist.version}",
        ],
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert result.returncode != 0
    stderr = result.stderr.decode("utf-8", errors="replace").lower()
    assert "network was disabled" in stderr or "no solution" in stderr


# ---------------------------------------------------------------------------
# Corrupted hash: exact hash pinning rejects a mutated wheel before install
# ---------------------------------------------------------------------------


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
