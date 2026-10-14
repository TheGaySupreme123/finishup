"""``finishup service run`` on a conda image, and a startup failure named on every surface (#1040).

``condaforge/miniforge3:24.9.2-0`` is Ubuntu 20.04 with glibc 2.31. glibc before 2.32 has no
no-follow ``fchmodat``, so CPython raises ``NotImplementedError`` for
``os.chmod(..., follow_symlinks=False)``; the service used exactly that call on its endpoint and
exited 70 with only ``internal_error: the command could not be completed``, and the agent's
``start`` was told the service was merely not running. The probes below reproduce that interpreter
behaviour together with the image's environment (conda first on ``PATH``, its ``CONDA_*`` and
locale variables, and the ``LD_LIBRARY_PATH`` the issue suspected), and inject a startup failure
through the real endpoint code to hold the typed reason on the service log, the durable record,
the MCP ``start`` result and the CLI.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest
from mcp import types
from test_process_owner_fencing import (
    cleanup_environment,
    isolated_environment,
    stop_service_public,
    terminate_service,
    wait_status,
)
from typer.testing import CliRunner

# CPython on glibc < 2.32: a no-follow chmod is refused before it reaches the file system.
_OLD_GLIBC_CHMOD = r"""
import os
_real_chmod = os.chmod
def _chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
    if not follow_symlinks:
        raise NotImplementedError("chmod: follow_symlinks unavailable on this platform")
    return _real_chmod(path, mode, dir_fd=dir_fd)
os.chmod = _chmod
"""
# An injected startup failure in the real endpoint code: the socket mode cannot be set at all.
_ENDPOINT_CHMOD_FAILS = r"""
import os
_real_chmod = os.chmod
def _chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
    if os.fspath(path).endswith(".sock"):
        raise NotImplementedError("injected: endpoint mode unavailable")
    return _real_chmod(path, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
os.chmod = _chmod
"""
_SERVICE_RUN = r"""
import sys
sys.argv = ["finishup", "service", "run"]
from finishup.cli.app import main
main()
"""
_DIAGNOSTICS = r"""
import sys
sys.argv = ["finishup", "service", "diagnostics", "--json", "--correlation-id", sys.argv[1]]
from finishup.cli.app import main
main()
"""


def _conda_environment(environment: dict[str, str]) -> dict[str, str]:
    """Overlay the variables ``condaforge/miniforge3:24.9.2-0`` and ``conda activate`` set."""

    prefix = Path(environment["_FINISHUP_TEST_INSTALLATION"]) / "opt" / "conda"
    (prefix / "bin").mkdir(parents=True, mode=0o700)
    (prefix / "lib").mkdir(mode=0o700)
    # The image's ``python`` is conda's 3.12, never the FinishUP runtime; one that is resolved from
    # PATH would fail loudly here.
    shim = prefix / "bin" / "python"
    shim.write_text("#!/bin/sh\nexit 97\n", encoding="ascii")
    shim.chmod(0o700)
    return {
        **environment,
        "PATH": f"{prefix / 'bin'}:{environment['PATH']}",
        "CONDA_DIR": os.fspath(prefix),
        "CONDA_PREFIX": os.fspath(prefix),
        "CONDA_DEFAULT_ENV": "base",
        "CONDA_SHLVL": "1",
        "CONDA_EXE": os.fspath(prefix / "bin" / "conda"),
        "CONDA_PYTHON_EXE": os.fspath(shim),
        "CONDA_PROMPT_MODIFIER": "(base) ",
        "LD_LIBRARY_PATH": os.fspath(prefix / "lib"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _spawn(environment: dict[str, str], prelude: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        (sys.executable, "-I", "-c", prelude + _SERVICE_RUN),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        close_fds=True,
        start_new_session=True,
    )


def _diagnostics(environment: dict[str, str], correlation_id: str) -> dict[str, object]:
    completed = subprocess.run(
        (sys.executable, "-I", "-c", _DIAGNOSTICS, correlation_id),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=environment,
        close_fds=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2_000:]
    return cast(dict[str, object], json.loads(completed.stdout))


def test_service_starts_and_stops_under_the_conda_image_environment(tmp_path: Path) -> None:
    environment = _conda_environment(isolated_environment(tmp_path / "installation"))
    process = _spawn(environment, _OLD_GLIBC_CHMOD)
    try:
        status = wait_status(environment, (process,), timeout=30.0)
        assert status["state"] == "locked"
        stop_service_public(environment, process)
    finally:
        terminate_service(process)
        cleanup_environment(environment)


def test_an_injected_startup_failure_is_typed_on_the_service_log_and_its_record(
    tmp_path: Path,
) -> None:
    environment = _conda_environment(isolated_environment(tmp_path / "installation"))
    process = _spawn(environment, _ENDPOINT_CHMOD_FAILS)
    try:
        stdout, stderr = process.communicate(timeout=60)
    finally:
        terminate_service(process)
    try:
        assert process.returncode == 70
        assert stdout == b""
        text = stderr.decode("ascii")
        assert "Traceback" not in text
        assert "the command could not be completed" not in text
        assert "injected" not in text
        assert environment["_FINISHUP_TEST_INSTALLATION"] not in text
        lines = text.splitlines()
        typed = [line for line in lines if line.startswith("internal_error:")]
        assert len(typed) == 1
        assert typed[0].startswith(
            "internal_error: the service could not start (stage: activation; "
            "exception_not_implemented_error; at finishup.adapters.control.unix_socket:"
        )
        correlation_id = typed[0].split("correlation_id ", 1)[1].split(";", 1)[0]
        # The structural stderr record carries the same identity.
        structural = [json.loads(line) for line in lines if line.startswith("{")]
        assert any(
            record.get("operation") == "service_startup_failed"
            and record.get("correlation_id") == correlation_id
            and record.get("phase") == "activation"
            for record in structural
        )

        resolved = _diagnostics(environment, correlation_id)
        (record,) = cast(list[dict[str, object]], resolved["records"])
        assert record["component"] == "service.daemon"
        assert record["operation"] == "service_startup_failed"
        assert record["phase"] == "activation"
        assert record["reason"] == "exception_not_implemented_error"
        assert cast(str, record["origin"]).startswith("finishup.adapters.control.unix_socket:")
    finally:
        cleanup_environment(environment)


@pytest.fixture
def injected_spawn_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[list[object]]:
    """Make every service this process spawns on demand fail at activation, and reap it."""

    import finishup.observability.diagnostics as diagnostics
    import finishup.service.client as client_module
    from finishup.config.paths import log_dir

    # The suite points this process's diagnostic ring at a temp directory; the spawned service
    # writes to the hermetic installation's real log directory, which is where a bridge reads.
    monkeypatch.setattr(diagnostics, "log_dir", log_dir)
    site = tmp_path / "site"
    site.mkdir()
    (site / "sitecustomize.py").write_text(_ENDPOINT_CHMOD_FAILS, encoding="ascii")
    monkeypatch.setenv("PYTHONPATH", os.fspath(site))
    spawned: list[object] = []
    original = client_module._spawn_service_process  # pyright: ignore[reportPrivateUsage]

    def spawn() -> object:
        started = original()
        spawned.append(started)
        return started

    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    try:
        yield spawned
    finally:
        for started in spawned:
            process = cast(subprocess.Popen[bytes], getattr(started, "process"))
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)


def _service_log() -> str:
    from finishup.config.paths import log_dir

    return (log_dir() / "service.stderr.jsonl").read_text(encoding="ascii")


@pytest.mark.anyio
async def test_mcp_start_names_the_spawned_service_startup_failure(
    injected_spawn_failure: list[object],
) -> None:
    import finishup.mcp.server as bridge

    request = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000001040",
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "mode": "create",
        "task_title": "Conda image",
        "requested_view": "compact",
    }
    runtime = bridge.build_bridge_runtime()
    try:
        result = await bridge.dispatch_start(request, runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)

    assert len(injected_spawn_failure) == 1
    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert error["retryable"] is False
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "service_start_failed"
    assert details["phase"] == "activation"
    assert cast(str, error["message"]).startswith(
        "The local FinishUP service exited while starting (stage: activation; "
        "exception_not_implemented_error; at finishup.adapters.control.unix_socket:"
    )
    text = cast(types.TextContent, result.content[0]).text
    assert "Reason: service_start_failed (stage: activation)." in text
    correlation_id = cast(str, error["correlation_id"])
    assert correlation_id in text
    # The spawned service's own log line names the same failure under the same id.
    log = _service_log()
    assert (
        "internal_error: the service could not start (stage: activation; "
        "exception_not_implemented_error"
    ) in log
    assert f"correlation_id {correlation_id}" in log


def test_cli_on_demand_start_names_the_spawned_service_startup_failure(
    injected_spawn_failure: list[object],
) -> None:
    import finishup.cli.app as cli

    result = CliRunner().invoke(cli.app, ["service", "restart"])

    assert len(injected_spawn_failure) == 1
    assert result.exit_code == 20
    assert result.stderr.startswith(
        "service_unavailable: the local service exited while starting (stage: activation; "
        "exception_not_implemented_error; at finishup.adapters.control.unix_socket:"
    )
    assert "under your selected user supervisor" not in result.stderr


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
