"""Platform capability evidence for the same-UID local control transport."""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import stat
import sys
import tempfile
from pathlib import Path

import pytest

from finishup.adapters.control.unix_socket import (
    CONTROL_ENDPOINT_BASENAME,
    ENDPOINT_MODE,
    RUNTIME_DIRECTORY_MODE,
    authenticate_peer,
    bind_control_listener,
    close_endpoint,
    connect_control,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.skipif(
    not (sys.platform == "darwin" or sys.platform.startswith("linux")),
    reason="certified local peer APIs are macOS/Linux only",
)
async def test_real_peer_credentials_modes_and_close_on_exec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = Path(tempfile.mkdtemp(prefix=".yctl-cap-", dir=Path.cwd()))
    runtime.chmod(RUNTIME_DIRECTORY_MODE)
    monkeypatch.setattr(
        "finishup.adapters.control.unix_socket._runtime_directory",
        lambda: runtime,
    )
    listener = await bind_control_listener()
    accept_task = asyncio.create_task(listener.accept())
    client = await connect_control()
    server = await accept_task
    try:
        endpoint = runtime / CONTROL_ENDPOINT_BASENAME
        assert stat.S_IMODE(runtime.lstat().st_mode) == RUNTIME_DIRECTORY_MODE
        assert stat.S_IMODE(endpoint.lstat().st_mode) == ENDPOINT_MODE
        assert endpoint.lstat().st_uid == os.geteuid()
        assert not os.get_inheritable(listener.fileno())
        assert not os.get_inheritable(client.fileno())
        assert not os.get_inheritable(server.fileno())
        with socket.socket(fileno=os.dup(client.fileno())) as duplicate:
            assert repr(authenticate_peer(duplicate)).startswith("PeerIdentityHandle(")
    finally:
        await client.aclose()
        await server.aclose()
        await close_endpoint(listener)
        shutil.rmtree(runtime)
