"""Isolated-root runtime boundary against the real installed launcher (issue #518).

Proves the one supported exact-target isolation contract end to end: with
``FINISHUP_ISOLATED_ROOT`` set, a real installed ``finishup`` runtime places its service singleton
(lock, generation), control endpoint, storage bundle, config, cache, and logs beneath the
isolated root; an ambient client of the same installation cannot reach that service; the
ambient home tree is byte-identical before and after the isolated run; and removing the root
removes every trace of the test-owned runtime.

Like the rest of ``tests/packaging``, this spawns real CLIs against install roots under
``~/.yz-*`` and must run from the primary checkout, never concurrently with another pytest run.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Final

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
# The installed client's own wait for a service it starts (service/client.py
# _SERVICE_START_TIMEOUT_SECONDS). A first start also builds the retained release-runtime snapshot,
# bytecode included, so it is slower than a warm start.
_SERVICE_START_WAIT_SECONDS: Final = 30.0


def _is_advertised_host() -> bool:
    if sys.platform == "darwin":
        return platform.machine() == "arm64"
    if sys.platform.startswith("linux"):
        return platform.machine() in {"x86_64", "amd64"}
    return False


pytestmark = pytest.mark.skipif(
    not _is_advertised_host(),
    reason="only the v0.1 advertised macOS arm64 / manylinux_2_28 x86-64 cells are certified",
)


def _real_cache_dir() -> str:
    result = subprocess.run(["uv", "cache", "dir"], capture_output=True, timeout=15, check=False)
    return result.stdout.decode("utf-8").strip()


def _short_home(tag: str) -> Path:
    # AF_UNIX socket paths derived from the isolation root must stay well under the ~104-byte
    # sockaddr_un limit, contain no symlink component, and avoid shared temp directories; the
    # real user home is the only location on this host satisfying all of that. Fully disposable.
    base = Path.home() / f".yz-{tag}"
    base.mkdir(mode=0o700, exist_ok=True)
    root = base / secrets.token_hex(3)
    root.mkdir(mode=0o700)
    (root / "h").mkdir(mode=0o700)
    return root


def _tool_install(dist_dir: Path, root: Path, home: Path) -> tuple[Path, dict[str, str]]:
    tool_dir = root / "tool"
    bin_dir = root / "bin"
    wheels = sorted(dist_dir.glob("*.whl"))
    assert len(wheels) == 1
    spec = str(wheels[0])
    env = {
        **os.environ,
        "HOME": str(home),
        "UV_TOOL_DIR": str(tool_dir),
        "UV_TOOL_BIN_DIR": str(bin_dir),
        "UV_CACHE_DIR": _real_cache_dir(),
    }

    def _install(offline: bool) -> subprocess.CompletedProcess[bytes]:
        args = ["uv", "tool", "install", "--python", "3.14.6"]
        if offline:
            args.append("--offline")
        args += ["--find-links", str(dist_dir), spec]
        return subprocess.run(args, capture_output=True, timeout=180, env=env, check=False)

    result = _install(offline=True)
    if result.returncode != 0:
        result = _install(offline=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return bin_dir / "finishup", env


@pytest.fixture(scope="module")
def built_dist(tmp_path_factory: pytest.TempPathFactory) -> Path:
    dist_dir = tmp_path_factory.mktemp("isolated-root-dist")
    result = subprocess.run(
        ["uv", "build", "--no-sources", "-o", str(dist_dir), str(_REPO_ROOT)],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    wheels = sorted(dist_dir.glob("*.whl"))
    assert len(wheels) == 1
    return dist_dir


def _home_tree_digest(home: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(home.rglob("*")):
        relative = str(path.relative_to(home))
        if path.is_symlink():
            snapshot[relative] = "symlink:" + str(path.readlink())
        elif path.is_file():
            snapshot[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif path.is_dir():
            snapshot[relative] = "dir"
    return snapshot


def _stop_service(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_isolation_report_modes_and_fail_closed_root(built_dist: Path) -> None:
    root = _short_home("iso-report")
    try:
        home = root / "h"
        finishup_exe, env = _tool_install(built_dist, root, home)

        ambient = subprocess.run(
            [str(finishup_exe), "service", "isolation", "--json"],
            capture_output=True,
            timeout=20,
            env=env,
            check=False,
        )
        assert ambient.returncode == 0, ambient.stderr
        ambient_report = json.loads(ambient.stdout)
        assert ambient_report["mode"] == "ambient"

        iso = root / "iso"
        iso.mkdir(mode=0o700)
        isolated = subprocess.run(
            [str(finishup_exe), "service", "isolation", "--json"],
            capture_output=True,
            timeout=20,
            env={**env, "FINISHUP_ISOLATED_ROOT": str(iso)},
            check=False,
        )
        assert isolated.returncode == 0, isolated.stderr
        isolated_report = json.loads(isolated.stdout)
        assert isolated_report["mode"] == "isolated"
        assert isolated_report["schema"] == "yoetz.isolation-report/1"
        assert isolated_report["config_content"] is None
        for key in (
            "state_path_digest",
            "endpoint_path_digest",
            "storage_path_digest",
            "config_path_digest",
        ):
            assert isolated_report["path_identity"][key] != ambient_report["path_identity"][key]
        # Digest-only privacy boundary: the report publishes no raw path.
        assert str(iso) not in isolated.stdout.decode("utf-8")

        unusable = subprocess.run(
            [str(finishup_exe), "service", "isolation", "--json"],
            capture_output=True,
            timeout=20,
            env={**env, "FINISHUP_ISOLATED_ROOT": str(root / "never-created")},
            check=False,
        )
        assert unusable.returncode == 2
        assert b"isolation_invalid: isolation_root_invalid" in unusable.stderr
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_isolated_service_singleton_cannot_be_reached_ambiently_and_leaves_no_trace(
    built_dist: Path,
) -> None:
    root = _short_home("iso-boundary")
    try:
        home = root / "h"
        finishup_exe, env = _tool_install(built_dist, root, home)
        iso = root / "iso"
        iso.mkdir(mode=0o700)
        env_iso = {**env, "FINISHUP_ISOLATED_ROOT": str(iso)}

        before = _home_tree_digest(home)

        service = subprocess.Popen(
            [str(finishup_exe), "service", "run"],
            env=env_iso,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + _SERVICE_START_WAIT_SECONDS
            reachable = False
            while time.monotonic() < deadline:
                if service.poll() is not None:
                    raise AssertionError("isolated service exited during startup")
                status = subprocess.run(
                    [str(finishup_exe), "service", "status", "--json"],
                    capture_output=True,
                    timeout=10,
                    env=env_iso,
                    check=False,
                )
                if status.returncode == 0:
                    reachable = True
                    break
                time.sleep(0.2)
            assert reachable, "isolated client never reached the isolated service"

            # Every singleton identity artifact lives beneath the isolated root.
            assert (iso / "state" / "service.lock").is_file()
            assert (iso / "run" / "control.sock").is_socket()

            # The same installation without the isolation root resolves the ambient endpoint
            # and must NOT reach the isolated singleton (`service status` never spawns).
            ambient_status = subprocess.run(
                [str(finishup_exe), "service", "status", "--json"],
                capture_output=True,
                timeout=10,
                env=env,
                check=False,
            )
            assert ambient_status.returncode != 0
            assert b"Traceback (most recent call last)" not in ambient_status.stderr
        finally:
            _stop_service(service)

        # Before/after: the isolated run wrote nothing into the ambient home tree.
        assert _home_tree_digest(home) == before

        # Rollback removes only test-owned state: everything the run created is under the root.
        shutil.rmtree(iso)
        assert _home_tree_digest(home) == before
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)
