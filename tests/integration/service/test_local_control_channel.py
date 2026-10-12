"""Authenticated fixed-path Unix transport integration coverage."""

from __future__ import annotations

import asyncio
import os
import pickle
import shutil
import socket
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

import yoetz.adapters.control as control_package
import yoetz.service.daemon as daemon_module
from yoetz.adapters.control.unix_socket import (
    CONTROL_ENDPOINT_BASENAME,
    ENDPOINT_MODE,
    HUMAN_CONTROL_ENDPOINT_BASENAME,
    RUNTIME_DIRECTORY_MODE,
    SECRET_ENDPOINT_BASENAME,
    EndpointKind,
    LocalControlTransportError,
    authenticate_peer,
    bind_control_listener,
    bind_human_control_listener,
    bind_secret_listener,
    close_endpoint,
    connect_control,
    connect_human_control,
    connect_secret,
    remove_stale_endpoint,
)
from yoetz.ports.control import ServiceState
from yoetz.service.lifecycle import ServiceLifecycle

_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000071"
_COMMITMENT = "sha256:" + "7" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def runtime_directory(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    runtime = Path(tempfile.mkdtemp(prefix=".yctl-", dir=Path.cwd()))
    runtime.chmod(RUNTIME_DIRECTORY_MODE)
    monkeypatch.setattr(
        "yoetz.adapters.control.unix_socket._runtime_directory",
        lambda: runtime,
    )
    try:
        yield runtime
    finally:
        shutil.rmtree(runtime)


class _HeldServiceLock:
    def assert_held(self) -> None:
        return None


class _MissingServiceLock:
    def assert_held(self) -> None:
        raise RuntimeError("not held")


class _Clock:
    def monotonic_seconds(self) -> float:
        return 1.0

    def now_utc(self) -> object:
        raise AssertionError("wall clock forbidden")


class _GenerationStore:
    def advance(self, instance_id: str) -> int:
        assert instance_id == _INSTANCE_ID
        return 1


def test_control_package_marker_is_inert() -> None:
    assert control_package.__all__ == []


@pytest.mark.anyio
async def test_stale_recovery_creates_only_the_fixed_owner_runtime_directory(
    runtime_directory: Path,
) -> None:
    runtime_directory.rmdir()
    with pytest.raises(LocalControlTransportError, match="endpoint_missing"):
        await remove_stale_endpoint(EndpointKind.CONTROL, _HeldServiceLock())
    facts = runtime_directory.lstat()
    assert stat.S_ISDIR(facts.st_mode)
    assert stat.S_IMODE(facts.st_mode) == RUNTIME_DIRECTORY_MODE
    assert facts.st_uid == os.geteuid()


@pytest.mark.anyio
async def test_three_fixed_endpoints_are_owner_only_and_bidirectional(
    runtime_directory: Path,
) -> None:
    listeners = (
        await bind_control_listener(),
        await bind_secret_listener(),
        await bind_human_control_listener(),
    )
    try:
        assert stat.S_IMODE(runtime_directory.lstat().st_mode) == RUNTIME_DIRECTORY_MODE
        for basename in (
            CONTROL_ENDPOINT_BASENAME,
            SECRET_ENDPOINT_BASENAME,
            HUMAN_CONTROL_ENDPOINT_BASENAME,
        ):
            facts = (runtime_directory / basename).lstat()
            assert stat.S_ISSOCK(facts.st_mode)
            assert stat.S_IMODE(facts.st_mode) == ENDPOINT_MODE
            assert facts.st_uid == os.geteuid()
            assert facts.st_nlink == 1

        for listener, connect in zip(
            listeners,
            (connect_control, connect_secret, connect_human_control),
            strict=True,
        ):
            accept_task = asyncio.create_task(listener.accept())
            client = await connect()
            server = await accept_task
            try:
                assert repr(client.peer_identity) == "PeerIdentityHandle(<redacted>)"
                assert repr(server.peer_identity) == "PeerIdentityHandle(<redacted>)"
                with pytest.raises(TypeError, match="not_serializable"):
                    pickle.dumps(client.peer_identity)
                assert not os.get_inheritable(client.fileno())
                assert not os.get_inheritable(server.fileno())
                assert not os.get_inheritable(listener.fileno())
                await client.send_all(b"client payload")
                assert await server.receive() == b"client payload"
                await server.send_all(bytearray(b"server payload"))
                assert await client.receive() == b"server payload"
                with pytest.raises(ValueError, match="receive_size_invalid"):
                    await client.receive(65_537)
            finally:
                await client.aclose()
                await server.aclose()
    finally:
        for listener in listeners:
            await close_endpoint(listener)

    assert not tuple(runtime_directory.glob("*.sock"))


@pytest.mark.anyio
async def test_endpoint_type_mode_and_identity_fail_closed_before_payload(
    runtime_directory: Path,
) -> None:
    endpoint = runtime_directory / CONTROL_ENDPOINT_BASENAME
    endpoint.write_bytes(b"not a socket")
    endpoint.chmod(ENDPOINT_MODE)
    with pytest.raises(LocalControlTransportError, match="endpoint_unsafe"):
        await connect_control()
    endpoint.unlink()

    unsafe_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unsafe_socket.bind(os.fspath(endpoint))
    endpoint.chmod(0o666)
    try:
        with pytest.raises(LocalControlTransportError, match="endpoint_unsafe"):
            await connect_control()
    finally:
        unsafe_socket.close()
        endpoint.unlink()

    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(LocalControlTransportError, match="peer_untrusted"):
            authenticate_peer(left, _expected_effective_uid=os.geteuid() + 1)
    finally:
        left.close()
        right.close()


@pytest.mark.anyio
async def test_stale_removal_requires_lock_and_never_removes_live_endpoint(
    runtime_directory: Path,
) -> None:
    listener = await bind_control_listener()
    endpoint = runtime_directory / CONTROL_ENDPOINT_BASENAME
    live_inode = endpoint.lstat().st_ino
    with pytest.raises(LocalControlTransportError, match="endpoint_exists"):
        await bind_control_listener()
    assert endpoint.lstat().st_ino == live_inode
    with pytest.raises(LocalControlTransportError, match="service_lock_required"):
        await remove_stale_endpoint(EndpointKind.CONTROL, _MissingServiceLock())
    with pytest.raises(LocalControlTransportError, match="endpoint_in_use"):
        await remove_stale_endpoint(EndpointKind.CONTROL, _HeldServiceLock())
    assert endpoint.exists()
    await close_endpoint(listener)

    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(os.fspath(endpoint))
    os.chmod(endpoint, ENDPOINT_MODE)
    stale.close()
    await remove_stale_endpoint(EndpointKind.CONTROL, _HeldServiceLock())
    assert not endpoint.exists()


@pytest.mark.anyio
async def test_production_listener_publication_recovers_all_stale_fixed_endpoints(
    runtime_directory: Path,
) -> None:
    for basename in (
        CONTROL_ENDPOINT_BASENAME,
        SECRET_ENDPOINT_BASENAME,
        HUMAN_CONTROL_ENDPOINT_BASENAME,
    ):
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(os.fspath(runtime_directory / basename))
        os.chmod(runtime_directory / basename, ENDPOINT_MODE)
        stale.close()

    listeners = daemon_module._ProductionListeners(  # pyright: ignore[reportPrivateUsage]
        daemon_module._ListenerBinders(  # pyright: ignore[reportPrivateUsage]
            bind_control_listener,
            bind_secret_listener,
            bind_human_control_listener,
        )
    )
    lifecycle = ServiceLifecycle(
        _Clock(),  # pyright: ignore[reportArgumentType] - wall clock is intentionally unavailable
        generation_store=_GenerationStore(),
        process_start_identity_commitment=_COMMITMENT,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=runtime_directory / "service.lock",
        endpoint_recovery=listeners.recover_stale,
        endpoint_publisher=listeners.bind,
        endpoint_cleanup=listeners.close,
    )

    await lifecycle.acquire_singleton()
    await lifecycle.publish_endpoint()
    for connect in (connect_control, connect_secret, connect_human_control):
        stream = await connect()
        await stream.aclose()

    await lifecycle.transition(ServiceState.LOCKED)
    await lifecycle.close()
    assert not tuple(runtime_directory.glob("*.sock"))


@pytest.mark.anyio
async def test_close_never_unlinks_a_replaced_endpoint(runtime_directory: Path) -> None:
    listener = await bind_control_listener()
    endpoint = runtime_directory / CONTROL_ENDPOINT_BASENAME
    endpoint.unlink()
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    replacement.bind(os.fspath(endpoint))
    os.chmod(endpoint, ENDPOINT_MODE)
    try:
        with pytest.raises(LocalControlTransportError, match="endpoint_unsafe"):
            await close_endpoint(listener)
        assert endpoint.exists()
    finally:
        replacement.close()
        endpoint.unlink()


def _without_no_follow_chmod(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Make ``os.chmod`` behave as CPython does on glibc before 2.32 (#1040).

    There ``fchmodat(..., AT_SYMLINK_NOFOLLOW)`` always fails with ``ENOTSUP`` and CPython raises
    ``NotImplementedError`` for ``follow_symlinks=False``; that is what made every service start
    exit 70 on ``condaforge/miniforge3:24.9.2-0`` (Ubuntu 20.04, glibc 2.31).
    """

    real_chmod = os.chmod
    refused: list[bool] = []

    def chmod(
        path: object, mode: int, *, dir_fd: int | None = None, follow_symlinks: bool = True
    ) -> None:
        if not follow_symlinks:
            refused.append(True)
            raise NotImplementedError("chmod: follow_symlinks unavailable on this platform")
        real_chmod(path, mode, dir_fd=dir_fd)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(os, "chmod", chmod)
    return refused


@pytest.mark.anyio
async def test_endpoints_bind_owner_only_where_no_follow_chmod_is_unavailable(
    runtime_directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    refused = _without_no_follow_chmod(monkeypatch)
    listeners = (
        await bind_control_listener(),
        await bind_secret_listener(),
        await bind_human_control_listener(),
    )
    try:
        assert len(refused) == 3
        for basename in (
            CONTROL_ENDPOINT_BASENAME,
            SECRET_ENDPOINT_BASENAME,
            HUMAN_CONTROL_ENDPOINT_BASENAME,
        ):
            facts = (runtime_directory / basename).lstat()
            assert stat.S_ISSOCK(facts.st_mode)
            assert stat.S_IMODE(facts.st_mode) == ENDPOINT_MODE
        accept_task = asyncio.create_task(listeners[0].accept())
        client = await connect_control()
        server = await accept_task
        await client.aclose()
        await server.aclose()
    finally:
        for listener in listeners:
            await close_endpoint(listener)


def test_no_follow_fallback_never_chmods_through_a_replaced_entry(
    runtime_directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yoetz.adapters.control.unix_socket import (
        _restrict_bound_endpoint,  # pyright: ignore[reportPrivateUsage]
    )

    _without_no_follow_chmod(monkeypatch)
    target = runtime_directory / "target"
    target.write_bytes(b"")
    target.chmod(0o640)
    endpoint = runtime_directory / CONTROL_ENDPOINT_BASENAME
    endpoint.symlink_to(target)
    with pytest.raises(LocalControlTransportError, match="endpoint_unsafe"):
        _restrict_bound_endpoint(endpoint, (target.stat().st_dev, target.stat().st_ino))
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    endpoint.unlink()

    bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        bound.bind(os.fspath(endpoint))
        facts = endpoint.lstat()
        with pytest.raises(LocalControlTransportError, match="endpoint_unsafe"):
            _restrict_bound_endpoint(endpoint, (facts.st_dev, facts.st_ino + 1))
        _restrict_bound_endpoint(endpoint, (facts.st_dev, facts.st_ino))
        assert stat.S_IMODE(endpoint.lstat().st_mode) == ENDPOINT_MODE
    finally:
        bound.close()
        endpoint.unlink()
