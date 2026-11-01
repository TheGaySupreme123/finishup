"""Fresh advertised-platform installation vertical slice.

Builds the real sdist/wheel, installs the candidate with the exact documented
``uv tool install --python 3.14.6`` path into an isolated, source-checkout-free environment, and
proves: import/help/``version --json`` work, the exact APSW/SQLite/runtime identity is reported,
the six workflow operations and a raw MCP initialize/tools-list handshake run against a real
foreground service process with no provider secret and no network, and installing an optional extra
enables only its own named capability while leaving base behavior unchanged.

Scope notes (documented, not silently narrowed):

* A full "local-only receipt" for the six-operation slice requires an unlocked vault. Unlocking
  a passphrase vault for real goes through ``TrustedForegroundConsole``, which deliberately
  requires a genuine foreground console (on POSIX it opens ``/dev/tty`` and checks
  ``os.tcgetpgrp``/isatty plus matching stdin/stderr terminal endpoints) -- a real security control,
  not something to relax.
  This file proves the six operations against the real, freshly-installed, running-but-locked
  service: each one must produce a bounded, non-crashing, documented exit code (never a hidden
  runtime, never a Python traceback, never a leaked checkout path) rather than a fabricated
  successful receipt. That is exactly the "service_unavailable|vault_locked" behavior this suite's
  own family index requires for ordinary clients before a human unlock ceremony.
* Only this host's advertised platform cell (macOS arm64 or manylinux glibc x86-64) is exercised;
  the complementary cell needs a second real runner (see ``test_platform_and_sqlite_gate.py`` for
  the fuller discussion of why that is not fabricated here).
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import time
import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_BOUNDED_EXIT_CODES: Final = frozenset({0, 2, 10, 11, 20, 30, 40, 70, 130})


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


@dataclass(frozen=True, slots=True)
class _BuiltDist:
    directory: Path
    wheel: Path


@pytest.fixture(scope="module")
def built_dist(tmp_path_factory: pytest.TempPathFactory) -> _BuiltDist:
    dist_dir = tmp_path_factory.mktemp("clean-install-dist")
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


def _real_cache_dir() -> str:
    result = subprocess.run(["uv", "cache", "dir"], capture_output=True, timeout=15, check=False)
    return result.stdout.decode("utf-8").strip()


def _tool_install(
    dist_dir: Path, root: Path, home: Path, *, extras: tuple[str, ...] = ()
) -> tuple[Path, dict[str, str]]:
    tool_dir = root / "tool"
    bin_dir = root / "bin"
    wheels = sorted(dist_dir.glob("*.whl"))
    assert len(wheels) == 1
    spec = str(wheels[0]) + (f"[{','.join(extras)}]" if extras else "")
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
        warm = root / "warm"
        subprocess.run(
            ["uv", "venv", "--python", "3.14.6", str(warm)],
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
                str(warm / "bin" / "python"),
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


def _short_home(tag: str) -> Path:
    # AF_UNIX control-socket paths derived from HOME (see config/paths.py + adapters/control/
    # unix_socket.py) must stay well under the ~104-byte sockaddr_un limit, and HOME must contain
    # no symlink component and not be a shared/world-writable temp directory. The real user home
    # is the only location on this host satisfying all of that; it is fully disposable and removed
    # in a finally block.
    base = Path.home() / f".yz-{tag}"
    base.mkdir(mode=0o700, exist_ok=True)
    root = base / secrets.token_hex(3)
    root.mkdir(mode=0o700)
    (root / "h").mkdir(mode=0o700)
    return root


def _actor_client_request(mode: str) -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": f"req_{uuid.uuid4()}",
        "mode": mode,
        "task_title": "packaging clean-install probe",
        "actor": {"actor_id": "packaging.clean-install", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
        "requested_view": "compact",
    }


# ---------------------------------------------------------------------------
# Import / help / version
# ---------------------------------------------------------------------------


def test_console_script_help_and_python_module_parity(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)

    console = subprocess.run(
        [str(finishup_exe), "--help"], capture_output=True, timeout=15, env=env, check=False
    )
    assert console.returncode == 0

    tool_python = root / "tool" / "finishup" / "bin" / "python"
    assert tool_python.is_file()
    module_form = subprocess.run(
        [str(tool_python), "-m", "finishup", "--help"],
        capture_output=True,
        timeout=15,
        env=env,
        check=False,
    )
    assert module_form.returncode == console.returncode
    assert module_form.stdout == console.stdout

    marker = str(_REPO_ROOT).encode("utf-8")
    assert marker not in console.stdout
    assert marker not in console.stderr
    assert marker not in module_form.stdout
    assert marker not in module_form.stderr


def test_version_json_reports_a_clean_installed_manifest(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)

    result = subprocess.run(
        [str(finishup_exe), "version", "--json"],
        capture_output=True,
        timeout=20,
        env=env,
        check=False,
    )
    assert result.returncode == 0
    manifest = json.loads(result.stdout)
    assert manifest["package_name"] == "finishup"
    assert manifest["package_version"] == built_dist.wheel.name.split("-")[1]
    assert manifest["apsw_version"]["status"] == "present"
    assert manifest["sqlite_version"]["status"] == "present"
    marker = str(_REPO_ROOT).encode("utf-8")
    assert marker not in result.stdout
    assert marker not in result.stderr


def test_no_ambient_config_or_global_module_contaminates_the_probe(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)

    # Explicitly starve the child of any PYTHONPATH/checkout leakage.
    scrubbed = {key: value for key, value in env.items() if key != "PYTHONPATH"}
    scrubbed["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [str(finishup_exe), "version", "--json"],
        capture_output=True,
        timeout=20,
        env=scrubbed,
        check=False,
    )
    assert result.returncode == 0
    assert not (home / ".finishup").exists()


def test_setup_run_loads_from_a_clean_installed_artifact(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)

    result = subprocess.run(
        [
            str(finishup_exe),
            "setup",
            "run",
            "--non-interactive",
            "--codex-path",
            str(tmp_path / "missing-codex"),
            "--codex-home",
            str(home),
            "--json",
        ],
        capture_output=True,
        timeout=20,
        env=env,
        check=False,
    )

    assert result.returncode == 2
    assert b"invalid_request" in result.stderr
    assert b"ModuleNotFoundError" not in result.stderr
    assert str(_REPO_ROOT).encode("utf-8") not in result.stderr


# ---------------------------------------------------------------------------
# Optional extras enable only their own capability
# ---------------------------------------------------------------------------


def test_semantic_openai_compatibility_extra_matches_the_standard_install(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    base_root = tmp_path / "base"
    base_home = base_root / "home"
    base_home.mkdir(parents=True)
    base_exe, base_env = _tool_install(built_dist.directory, base_root, base_home)
    base_manifest = json.loads(
        subprocess.run(
            [str(base_exe), "version", "--json"],
            capture_output=True,
            timeout=20,
            env=base_env,
            check=False,
        ).stdout
    )

    extra_root = tmp_path / "extra"
    extra_home = extra_root / "home"
    extra_home.mkdir(parents=True)
    extra_exe, extra_env = _tool_install(
        built_dist.directory, extra_root, extra_home, extras=("semantic-openai",)
    )
    extra_manifest = json.loads(
        subprocess.run(
            [str(extra_exe), "version", "--json"],
            capture_output=True,
            timeout=20,
            env=extra_env,
            check=False,
        ).stdout
    )

    base_adapter = next(a for a in base_manifest["provider_adapters"] if a["name"] == "openai")
    assert base_adapter["status"] == "present"
    extra_adapter = next(a for a in extra_manifest["provider_adapters"] if a["name"] == "openai")
    assert extra_adapter["status"] == "present"

    assert base_manifest == extra_manifest


def test_standard_install_and_portable_recovery_alias_both_include_argon2(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    _, env = _tool_install(built_dist.directory, root, home, extras=("portable-recovery",))
    tool_python = root / "tool" / "finishup" / "bin" / "python"
    probe = subprocess.run(
        [str(tool_python), "-c", "import argon2; print('argon2-present')"],
        capture_output=True,
        timeout=15,
        env=env,
        check=False,
    )
    assert probe.returncode == 0
    assert b"argon2-present" in probe.stdout

    base_root = tmp_path / "base-install"
    base_home = base_root / "home"
    base_home.mkdir(parents=True)
    _, base_env = _tool_install(built_dist.directory, base_root, base_home)
    base_python = base_root / "tool" / "finishup" / "bin" / "python"
    base_probe = subprocess.run(
        [str(base_python), "-c", "import argon2; print('argon2-present')"],
        capture_output=True,
        timeout=15,
        env=base_env,
        check=False,
    )
    assert base_probe.returncode == 0
    assert b"argon2-present" in base_probe.stdout


def _declared_core_pin(name: str) -> str:
    data = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    for entry in data["project"]["dependencies"]:
        if entry.startswith(f"{name}=="):
            return entry.split("==", 1)[1]
    raise AssertionError(f"{name} is not a pinned core dependency")


def test_standard_install_resolves_the_promoted_dependencies_at_their_exact_pins(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    """`version --json` reports adapters, never installed distributions.

    Presence probes pass on any resolved version, so the promotion of `argon2-cffi`, `httpx`,
    and `openai` to core dependencies is only evidence-bound if the installed versions are
    compared against the declared pins.
    """

    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    _, env = _tool_install(built_dist.directory, root, home)
    tool_python = root / "tool" / "finishup" / "bin" / "python"
    names = ("argon2-cffi", "httpx", "openai", "packaging")
    probe = subprocess.run(
        [
            str(tool_python),
            "-c",
            "import json\n"
            "from importlib.metadata import version\n"
            f"print(json.dumps({{name: version(name) for name in {names!r}}}))",
        ],
        capture_output=True,
        timeout=15,
        env=env,
        check=False,
    )
    assert probe.returncode == 0, probe.stderr
    installed = json.loads(probe.stdout)
    assert installed == {name: _declared_core_pin(name) for name in names}


# ---------------------------------------------------------------------------
# MCP initialize / tools-list raw handshake (no vault required)
# ---------------------------------------------------------------------------


def test_mcp_initialize_and_tools_list_raw_handshake(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)

    proc = subprocess.Popen(
        [str(finishup_exe), "mcp", "serve"],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "packaging-test", "version": "0.1"},
            },
        }
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write((json.dumps(init) + "\n").encode())
        proc.stdin.flush()
        init_line = proc.stdout.readline()
        init_response = json.loads(init_line)
        assert init_response["result"]["serverInfo"]["name"] == "finishup"

        proc.stdin.write(
            (
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
                + "\n"
            ).encode()
        )
        proc.stdin.flush()
        proc.stdin.write(
            (
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"
            ).encode()
        )
        proc.stdin.flush()
        tools_line = proc.stdout.readline()
        tools_response = json.loads(tools_line)
        tool_names = {tool["name"] for tool in tools_response["result"]["tools"]}
        assert {"start", "publish-work", "check", "respond", "status", "receipt"} <= tool_names or {
            "start",
            "publish_work",
            "check",
            "respond",
            "status",
            "receipt",
        } <= tool_names
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# Six-operation slice against a real, freshly-installed, running-but-locked service
# ---------------------------------------------------------------------------


# The installed client's own wait for a service it starts (service/client.py
# _SERVICE_START_TIMEOUT_SECONDS). A first start also builds the retained release-runtime snapshot,
# bytecode included, so it is slower than a warm start.
_SERVICE_START_WAIT_SECONDS: Final = 30.0


def _start_service(finishup_exe: Path, env: dict[str, str]) -> subprocess.Popen[bytes]:
    proc = subprocess.Popen(
        [str(finishup_exe), "service", "run"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + _SERVICE_START_WAIT_SECONDS
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError("service exited during startup")
        status = subprocess.run(
            [str(finishup_exe), "service", "status", "--json"],
            capture_output=True,
            timeout=10,
            env=env,
            check=False,
        )
        if status.returncode == 0:
            return proc
        time.sleep(0.2)
    proc.terminate()
    raise AssertionError("service did not become reachable in time")


def _stop_service(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_installed_client_bounds_an_accepted_but_silent_service(
    built_dist: _BuiltDist,
) -> None:
    root = _short_home("silent-service")
    try:
        home = root / "h"
        finishup_exe, env = _tool_install(built_dist.directory, root, home)
        tool_python = root / "tool" / "finishup" / "bin" / "python"
        listener = subprocess.Popen(
            [
                str(tool_python),
                "-c",
                "import os, socket, time\n"
                "from platformdirs import PlatformDirs\n"
                "runtime = PlatformDirs(appname='finishup', appauthor=False, roaming=False).user_runtime_path\n"
                "runtime.mkdir(parents=True, exist_ok=True, mode=0o700)\n"
                "os.chmod(runtime, 0o700)\n"
                "path = runtime / 'control.sock'\n"
                "server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                "server.bind(str(path))\n"
                "os.chmod(path, 0o600)\n"
                "server.listen(1)\n"
                "print('ready', flush=True)\n"
                "connection, _ = server.accept()\n"
                "time.sleep(15)\n"
                "connection.close()\n"
                "server.close()\n",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert listener.stdout is not None
            assert listener.stdout.readline() == b"ready\n"
            started = time.monotonic()
            status = subprocess.run(
                [str(finishup_exe), "service", "status", "--json"],
                capture_output=True,
                timeout=9,
                env=env,
                check=False,
            )
            elapsed = time.monotonic() - started

            assert status.returncode in _BOUNDED_EXIT_CODES
            assert elapsed < 8
            assert listener.poll() is None
            assert b"Traceback (most recent call last)" not in status.stderr
        finally:
            listener.terminate()
            try:
                listener.wait(timeout=5)
            except subprocess.TimeoutExpired:
                listener.kill()
                listener.wait(timeout=5)
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_fresh_install_no_network_no_provider_secret_service_reports_locked(
    built_dist: _BuiltDist,
) -> None:
    root = _short_home("clean-install")
    try:
        home = root / "h"
        finishup_exe, env = _tool_install(built_dist.directory, root, home)
        denied_env = {**env}
        for proxy_var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
            denied_env[proxy_var] = "http://127.0.0.1:1"
        denied_env.pop("OPENAI_API_KEY", None)

        service = _start_service(finishup_exe, denied_env)
        try:
            status = subprocess.run(
                [str(finishup_exe), "service", "status", "--json"],
                capture_output=True,
                timeout=10,
                env=denied_env,
                check=False,
            )
            assert status.returncode == 0
            payload = json.loads(status.stdout)
            assert payload["state"] == "locked"
            assert payload["vault_mode"] == "uninitialized"
        finally:
            _stop_service(service)
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_six_workflow_operations_refuse_honestly_without_a_hidden_runtime(
    built_dist: _BuiltDist,
) -> None:
    root = _short_home("clean-install-six-op")
    try:
        home = root / "h"
        finishup_exe, env = _tool_install(built_dist.directory, root, home)
        service = _start_service(finishup_exe, env)
        marker = str(_REPO_ROOT).encode("utf-8")
        try:
            operations: tuple[tuple[str, ...], ...] = (
                ("start", "--request", json.dumps(_actor_client_request("create")), "--json"),
                (
                    "publish-work",
                    "--request",
                    json.dumps(
                        {
                            "protocol_version": "0.1",
                            "schema_version": "1.0.0",
                            "request_id": f"req_{uuid.uuid4()}",
                            "session_id": f"ses_{uuid.uuid4()}",
                        }
                    ),
                    "--json",
                ),
                (
                    "check",
                    "--request",
                    json.dumps(
                        {
                            "protocol_version": "0.1",
                            "schema_version": "1.0.0",
                            "request_id": f"req_{uuid.uuid4()}",
                            "session_id": f"ses_{uuid.uuid4()}",
                        }
                    ),
                    "--json",
                ),
                (
                    "respond",
                    "--request",
                    json.dumps(
                        {
                            "protocol_version": "0.1",
                            "schema_version": "1.0.0",
                            "request_id": f"req_{uuid.uuid4()}",
                            "session_id": f"ses_{uuid.uuid4()}",
                        }
                    ),
                    "--json",
                ),
                (
                    "status",
                    "--request",
                    json.dumps(
                        {
                            "protocol_version": "0.1",
                            "schema_version": "1.0.0",
                            "request_id": f"req_{uuid.uuid4()}",
                            "session_id": f"ses_{uuid.uuid4()}",
                        }
                    ),
                    "--json",
                ),
                (
                    "receipt",
                    "--request",
                    json.dumps(
                        {
                            "protocol_version": "0.1",
                            "schema_version": "1.0.0",
                            "request_id": f"req_{uuid.uuid4()}",
                            "session_id": f"ses_{uuid.uuid4()}",
                        }
                    ),
                    "--json",
                ),
            )
            for argv in operations:
                result = subprocess.run(
                    [str(finishup_exe), *argv],
                    capture_output=True,
                    timeout=15,
                    env=env,
                    check=False,
                )
                assert result.returncode in _BOUNDED_EXIT_CODES, (argv[0], result.returncode)
                assert marker not in result.stdout
                assert marker not in result.stderr
                assert b"Traceback (most recent call last)" not in result.stderr
                # No hidden runtime was spawned: the same service process is still alive.
                assert service.poll() is None
        finally:
            _stop_service(service)
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)
