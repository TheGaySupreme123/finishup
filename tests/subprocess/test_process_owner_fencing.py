"""Installed-process singleton and successor-generation fencing."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import TypedDict, cast

_SERVICE_PROBE = "from finishup.service.daemon import main; main()"
_CLIENT_PROBE = r"""
import anyio, json, sys
from finishup.ports.control import ControlClientKind
from finishup.service.client import connect_service

async def run():
    client = await connect_service(ControlClientKind.CLI)
    try:
        if sys.argv[1] == "stop":
            await client.stop()
            print('{"stopped":true}')
            return
        status = await client.service_status()
        print(json.dumps({
            "generation": int(status.service_generation),
            "instance_id": status.service_instance_id,
            "state": status.state.value,
        }, separators=(",", ":"), sort_keys=True))
    finally:
        await client.close()

anyio.run(run)
"""


class ServiceProcessStatus(TypedDict):
    generation: int
    instance_id: str
    state: str


def isolated_environment(root: Path) -> dict[str, str]:
    """Build an owner-only XDG layout that path safety will accept.

    Pytest's default basetemp lives under shared ``/tmp``, which
    ``verify_private_local_bundle`` rejects as ``path_shared_temp``. Keep the
    runtime directory under a shared temp (sockets only) and place the private
    installation tree under the caller's home cache instead.
    """

    del root  # callers pass tmp_path labels; private data cannot live there on Linux.
    runtime_parent = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
    runtime = Path(tempfile.mkdtemp(prefix="yzrt-", dir=runtime_parent))
    base = Path.home() / ".cache" / "finishup-subprocess-isolation"
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    base.chmod(0o700)
    installation = Path(tempfile.mkdtemp(prefix="installation-", dir=base))
    installation.chmod(0o700)
    paths = {
        "HOME": installation / "home",
        "TMPDIR": installation / "tmp",
        "XDG_CACHE_HOME": installation / "cache",
        "XDG_CONFIG_HOME": installation / "config",
        "XDG_DATA_HOME": installation / "data",
        "XDG_RUNTIME_DIR": runtime,
        "XDG_STATE_HOME": installation / "state",
    }
    for path in paths.values():
        if path == runtime:
            continue
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
    return {
        **{key: os.fspath(path) for key, path in paths.items()},
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
        "_FINISHUP_TEST_INSTALLATION": os.fspath(installation),
    }


def cleanup_environment(environment: dict[str, str]) -> None:
    runtime = Path(environment["XDG_RUNTIME_DIR"])
    if runtime.parent not in {Path("/private/tmp"), Path("/tmp")} or not runtime.name.startswith(
        "yzrt-"
    ):
        raise AssertionError("suite runtime ownership invalid")
    shutil.rmtree(runtime, ignore_errors=False)
    installation = Path(environment["_FINISHUP_TEST_INSTALLATION"])
    base = Path.home() / ".cache" / "finishup-subprocess-isolation"
    if installation.parent != base or not installation.name.startswith("installation-"):
        raise AssertionError("suite installation ownership invalid")
    shutil.rmtree(installation, ignore_errors=False)


def spawn_service(environment: dict[str, str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        (sys.executable, "-I", "-c", _SERVICE_PROBE),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        close_fds=True,
        start_new_session=True,
    )


def run_client(
    environment: dict[str, str], action: str, *, timeout: float = 5.0
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        (sys.executable, "-I", "-c", _CLIENT_PROBE, action),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=environment,
        close_fds=True,
        timeout=timeout,
        check=False,
    )


def wait_status(
    environment: dict[str, str],
    processes: tuple[subprocess.Popen[bytes], ...],
    *,
    timeout: float = 15.0,
) -> ServiceProcessStatus:
    deadline = time.monotonic() + timeout
    last_stderr = b""
    while time.monotonic() < deadline:
        # The endpoint can exist while the daemon is still completing its bounded startup
        # integrity checks. A probe may therefore connect successfully and then reach its own
        # deadline before the handshake is served. Treat that like every other not-ready sample
        # and keep polling within this helper's outer deadline instead of aborting the test on the
        # first cold-start probe.
        remaining = deadline - time.monotonic()
        try:
            observed = run_client(environment, "status", timeout=remaining)
        except subprocess.TimeoutExpired:
            if all(process.poll() is not None for process in processes):
                break
            time.sleep(0.02)
            continue
        if observed.returncode == 0:
            assert observed.stderr == b""
            decoded = json.loads(observed.stdout)
            if type(decoded) is not dict:
                raise AssertionError("service status was not an object")
            source = cast(dict[object, object], decoded)
            generation = source.get("generation")
            instance_id = source.get("instance_id")
            state = source.get("state")
            if (
                type(generation) is not int
                or generation <= 0
                or type(instance_id) is not str
                or type(state) is not str
            ):
                raise AssertionError("service status shape invalid")
            return ServiceProcessStatus(
                generation=generation,
                instance_id=instance_id,
                state=state,
            )
        last_stderr = observed.stderr[-4_096:]
        if all(process.poll() is not None for process in processes):
            break
        time.sleep(0.02)
    raise AssertionError(
        f"service did not become ready; probe stderr digest bytes={len(last_stderr)}"
    )


def terminate_service(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except PermissionError:
        if process.poll() is None:
            raise
        return
    process.wait(timeout=5)


def stop_service_public(environment: dict[str, str], process: subprocess.Popen[bytes]) -> None:
    stopped = run_client(environment, "stop")
    assert stopped.returncode == 0
    assert stopped.stdout == b'{"stopped":true}\n'
    assert stopped.stderr == b""
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 0
    assert stdout == stderr == b""


def test_live_owner_fences_second_daemon_before_generation_advance(tmp_path: Path) -> None:
    environment = isolated_environment(tmp_path / "installation")
    owner = spawn_service(environment)
    contender: subprocess.Popen[bytes] | None = None
    try:
        before = wait_status(environment, (owner,))
        contender = spawn_service(environment)
        contender_stdout, contender_stderr = contender.communicate(timeout=10)

        assert contender.returncode not in {None, 0}
        assert contender_stdout == b""
        assert b"service_already_running" in contender_stderr
        after = wait_status(environment, (owner,))
        assert after == before

        stop_service_public(environment, owner)
    finally:
        if contender is not None:
            terminate_service(contender)
        terminate_service(owner)
        cleanup_environment(environment)


def test_sigkill_owner_two_successors_choose_one_generation_winner(tmp_path: Path) -> None:
    environment = isolated_environment(tmp_path / "installation")
    owner = spawn_service(environment)
    successors: list[subprocess.Popen[bytes]] = []
    try:
        before = wait_status(environment, (owner,))
        os.killpg(owner.pid, signal.SIGKILL)
        owner.wait(timeout=5)
        assert owner.returncode == -signal.SIGKILL

        successors = [spawn_service(environment), spawn_service(environment)]
        after = wait_status(environment, tuple(successors))
        assert after["generation"] == before["generation"] + 1
        assert after["instance_id"] != before["instance_id"]

        deadline = time.monotonic() + 10.0
        while (
            time.monotonic() < deadline
            and sum(process.poll() is None for process in successors) != 1
        ):
            time.sleep(0.01)
        alive = [process for process in successors if process.poll() is None]
        losers = [process for process in successors if process.poll() is not None]
        assert len(alive) == len(losers) == 1
        loser_stdout, loser_stderr = losers[0].communicate(timeout=5)
        assert loser_stdout == b""
        assert b"service_already_running" in loser_stderr

        stable = wait_status(environment, (alive[0],))
        assert stable == after
        stop_service_public(environment, alive[0])
    finally:
        terminate_service(owner)
        for process in successors:
            terminate_service(process)
        cleanup_environment(environment)
