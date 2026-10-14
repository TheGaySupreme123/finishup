"""Owner-only, same-effective-UID Unix-domain socket transport."""

from __future__ import annotations

import asyncio
import ctypes
import os
import socket
import stat
import struct
import sys
from collections.abc import Buffer
from enum import Enum
from pathlib import Path
from typing import Final, NoReturn, Protocol, Self

from yoetz.config.paths import PathSafetyError, ensure_owner_only_dir, runtime_dir

__all__ = [
    "CONTROL_ENDPOINT_BASENAME",
    "ENDPOINT_MODE",
    "HUMAN_CONTROL_ENDPOINT_BASENAME",
    "RUNTIME_DIRECTORY_MODE",
    "SECRET_ENDPOINT_BASENAME",
    "AuthenticatedUnixStream",
    "EndpointKind",
    "LocalControlTransportError",
    "PeerIdentityHandle",
    "UnixEndpointListener",
    "authenticate_peer",
    "bind_control_listener",
    "bind_human_control_listener",
    "bind_secret_listener",
    "close_endpoint",
    "connect_control",
    "connect_human_control",
    "connect_secret",
    "remove_stale_endpoint",
]

CONTROL_ENDPOINT_BASENAME: Final = "control.sock"
SECRET_ENDPOINT_BASENAME: Final = "secret-ingress.sock"
HUMAN_CONTROL_ENDPOINT_BASENAME: Final = "human-control.sock"
RUNTIME_DIRECTORY_MODE: Final = 0o700
ENDPOINT_MODE: Final = 0o600

_LISTEN_BACKLOG: Final = 128
_MAX_ACTIVE_CONNECTIONS: Final = 128
_MAX_RECEIVE_BYTES: Final = 65_536
_STALE_PROBE_SECONDS: Final = 0.25
_TRANSPORT_REASONS: Final = frozenset(
    {
        "connection_failed",
        "endpoint_exists",
        "endpoint_in_use",
        "endpoint_missing",
        "endpoint_unsafe",
        "listener_closed",
        "peer_untrusted",
        "runtime_directory_unsafe",
        "service_lock_required",
        "unsupported_platform",
    }
)


class EndpointKind(str, Enum):  # noqa: UP042 - fixed endpoint discriminator
    CONTROL = "control"
    SECRET = "secret"
    HUMAN_CONTROL = "human_control"


_ENDPOINT_BASENAMES: Final = {
    EndpointKind.CONTROL: CONTROL_ENDPOINT_BASENAME,
    EndpointKind.SECRET: SECRET_ENDPOINT_BASENAME,
    EndpointKind.HUMAN_CONTROL: HUMAN_CONTROL_ENDPOINT_BASENAME,
}


class LocalControlTransportError(Exception):
    """A bounded transport failure that never includes a path or peer value."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _TRANSPORT_REASONS:
            raise ValueError("local_control_transport_reason_invalid")
        self.reason = reason
        super().__init__(reason)


_PEER_HANDLE_TOKEN: Final = object()


class PeerIdentityHandle:
    """Opaque, nonserializable evidence of a positively authenticated local peer."""

    __slots__ = ("_effective_uid",)

    _effective_uid: int

    def __init__(self, effective_uid: int, *, _token: object) -> None:
        if _token is not _PEER_HANDLE_TOKEN:
            raise TypeError("peer_identity_handle_constructor_private")
        self._effective_uid = effective_uid

    def __repr__(self) -> str:
        return "PeerIdentityHandle(<redacted>)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("peer_identity_handle_not_serializable")


class _ServiceLockAuthority(Protocol):
    def assert_held(self) -> None: ...


class AuthenticatedUnixStream:
    """A nonblocking byte stream whose peer UID was authenticated before return."""

    __slots__ = ("_closed", "_peer_identity", "_release_slot", "_socket")

    _closed: bool
    _peer_identity: PeerIdentityHandle
    _release_slot: tuple[asyncio.Semaphore, bool] | None
    _socket: socket.socket

    def __init__(
        self,
        raw_socket: socket.socket,
        peer_identity: PeerIdentityHandle,
        *,
        _release_slot: asyncio.Semaphore | None = None,
    ) -> None:
        raw_socket.setblocking(False)
        raw_socket.set_inheritable(False)
        self._socket = raw_socket
        self._peer_identity = peer_identity
        self._release_slot = None if _release_slot is None else (_release_slot, False)
        self._closed = False

    @property
    def peer_identity(self) -> PeerIdentityHandle:
        return self._peer_identity

    def fileno(self) -> int:
        """Return the live descriptor number for inheritance/capability probes."""

        return self._socket.fileno()

    async def receive(self, max_bytes: int = _MAX_RECEIVE_BYTES) -> bytes:
        """Receive one bounded chunk, returning ``b\"\"`` only for peer EOF."""

        if self._closed:
            raise LocalControlTransportError("connection_failed")
        if type(max_bytes) is not int or not 1 <= max_bytes <= _MAX_RECEIVE_BYTES:
            raise ValueError("receive_size_invalid")
        try:
            return await asyncio.get_running_loop().sock_recv(self._socket, max_bytes)
        except OSError as exc:
            raise LocalControlTransportError("connection_failed") from exc

    async def send_all(self, data: Buffer) -> None:
        """Write all supplied bytes while allowing the socket to apply backpressure."""

        if self._closed:
            raise LocalControlTransportError("connection_failed")
        view = memoryview(data)
        if view.ndim != 1 or not view.contiguous:
            raise TypeError("send_buffer_invalid")
        try:
            await asyncio.get_running_loop().sock_sendall(self._socket, view)
        except OSError as exc:
            raise LocalControlTransportError("connection_failed") from exc

    async def shutdown_write(self) -> None:
        if self._closed:
            return
        try:
            self._socket.shutdown(socket.SHUT_WR)
        except OSError as exc:
            raise LocalControlTransportError("connection_failed") from exc

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._socket.close()
        release = self._release_slot
        if release is not None and not release[1]:
            release[0].release()
            self._release_slot = (release[0], True)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


class UnixEndpointListener:
    """A fixed-path listener with bounded accepted-connection admission."""

    __slots__ = (
        "_closed",
        "_endpoint_inode",
        "_endpoint_kind",
        "_endpoint_path",
        "_slots",
        "_socket",
    )

    _closed: bool
    _endpoint_inode: tuple[int, int]
    _endpoint_kind: EndpointKind
    _endpoint_path: Path
    _slots: asyncio.Semaphore
    _socket: socket.socket

    def __init__(
        self,
        raw_socket: socket.socket,
        endpoint_kind: EndpointKind,
        endpoint_path: Path,
        endpoint_inode: tuple[int, int],
    ) -> None:
        self._socket = raw_socket
        self._endpoint_kind = endpoint_kind
        self._endpoint_path = endpoint_path
        self._endpoint_inode = endpoint_inode
        self._slots = asyncio.Semaphore(_MAX_ACTIVE_CONNECTIONS)
        self._closed = False

    @property
    def endpoint_kind(self) -> EndpointKind:
        return self._endpoint_kind

    def fileno(self) -> int:
        """Return the live descriptor number for inheritance/capability probes."""

        return self._socket.fileno()

    async def accept(self) -> AuthenticatedUnixStream:
        if self._closed:
            raise LocalControlTransportError("listener_closed")
        await self._slots.acquire()
        accepted: socket.socket | None = None
        try:
            accepted, _address = await asyncio.get_running_loop().sock_accept(self._socket)
            accepted.setblocking(False)
            accepted.set_inheritable(False)
            peer = authenticate_peer(accepted)
            return AuthenticatedUnixStream(accepted, peer, _release_slot=self._slots)
        except LocalControlTransportError:
            if accepted is not None:
                accepted.close()
            self._slots.release()
            raise
        except OSError as exc:
            if accepted is not None:
                accepted.close()
            self._slots.release()
            reason = "listener_closed" if self._closed else "connection_failed"
            raise LocalControlTransportError(reason) from exc

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._socket.close()

        runtime = _verify_runtime_directory(create=False)
        if self._endpoint_path.parent != runtime:
            raise LocalControlTransportError("endpoint_unsafe")
        directory_fd = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            current = os.stat(
                self._endpoint_path.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (current.st_dev, current.st_ino) != self._endpoint_inode:
                raise LocalControlTransportError("endpoint_unsafe")
            os.unlink(self._endpoint_path.name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except FileNotFoundError:
            return
        except LocalControlTransportError:
            raise
        except OSError as exc:
            raise LocalControlTransportError("endpoint_unsafe") from exc
        finally:
            os.close(directory_fd)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await close_endpoint(self)


def _current_effective_uid() -> int:
    try:
        return os.geteuid()
    except AttributeError as exc:
        raise LocalControlTransportError("unsupported_platform") from exc


def _peer_effective_uid(peer_socket: socket.socket) -> int:
    if sys.platform.startswith("linux"):
        option = getattr(socket, "SO_PEERCRED", 17)
        try:
            credentials = peer_socket.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
            _pid, effective_uid, _gid = struct.unpack("3i", credentials)
        except (OSError, struct.error) as exc:
            raise LocalControlTransportError("peer_untrusted") from exc
        return effective_uid

    if sys.platform == "darwin":
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            getpeereid = libc.getpeereid
            getpeereid.argtypes = [
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint32),
            ]
            getpeereid.restype = ctypes.c_int
            effective_uid = ctypes.c_uint32()
            effective_gid = ctypes.c_uint32()
            result = getpeereid(
                peer_socket.fileno(), ctypes.byref(effective_uid), ctypes.byref(effective_gid)
            )
        except (AttributeError, OSError, TypeError) as exc:
            raise LocalControlTransportError("peer_untrusted") from exc
        if result != 0:
            raise LocalControlTransportError("peer_untrusted")
        return int(effective_uid.value)

    raise LocalControlTransportError("unsupported_platform")


def authenticate_peer(
    peer_socket: socket.socket, *, _expected_effective_uid: int | None = None
) -> PeerIdentityHandle:
    """Authenticate a connected AF_UNIX peer as the current effective user."""

    if type(peer_socket) is not socket.socket or peer_socket.family != socket.AF_UNIX:
        raise LocalControlTransportError("peer_untrusted")
    expected = (
        _current_effective_uid() if _expected_effective_uid is None else _expected_effective_uid
    )
    if type(expected) is not int or expected < 0:
        raise LocalControlTransportError("peer_untrusted")
    actual = _peer_effective_uid(peer_socket)
    if actual != expected:
        raise LocalControlTransportError("peer_untrusted")
    return PeerIdentityHandle(actual, _token=_PEER_HANDLE_TOKEN)


def _runtime_directory() -> Path:
    # Derives from the one isolation contract in yoetz.config.paths: an isolated runtime binds
    # and connects beneath its isolation root, never at the ambient platform endpoint. A set but
    # unusable isolation root fails closed as the bounded transport reason.
    try:
        return runtime_dir()
    except PathSafetyError as exc:
        raise LocalControlTransportError("runtime_directory_unsafe") from exc


def _endpoint_path(kind: EndpointKind) -> Path:
    if type(kind) is not EndpointKind:
        raise TypeError("endpoint_kind_invalid")
    return _runtime_directory() / _ENDPOINT_BASENAMES[kind]


def _verify_runtime_directory(*, create: bool) -> Path:
    runtime = _runtime_directory()
    try:
        if create:
            ensure_owner_only_dir(runtime)
        facts = runtime.lstat()
    except (OSError, PathSafetyError, ValueError) as exc:
        raise LocalControlTransportError("runtime_directory_unsafe") from exc
    if (
        not stat.S_ISDIR(facts.st_mode)
        or stat.S_ISLNK(facts.st_mode)
        or facts.st_uid != _current_effective_uid()
        or stat.S_IMODE(facts.st_mode) != RUNTIME_DIRECTORY_MODE
    ):
        raise LocalControlTransportError("runtime_directory_unsafe")
    return runtime


def _verify_endpoint(path: Path) -> tuple[int, int]:
    try:
        facts = path.lstat()
    except FileNotFoundError as exc:
        raise LocalControlTransportError("endpoint_missing") from exc
    except OSError as exc:
        raise LocalControlTransportError("endpoint_unsafe") from exc
    if (
        not stat.S_ISSOCK(facts.st_mode)
        or stat.S_ISLNK(facts.st_mode)
        or facts.st_uid != _current_effective_uid()
        or facts.st_nlink != 1
        or stat.S_IMODE(facts.st_mode) != ENDPOINT_MODE
    ):
        raise LocalControlTransportError("endpoint_unsafe")
    return facts.st_dev, facts.st_ino


def _restrict_bound_endpoint(path: Path, created_inode: tuple[int, int]) -> None:
    """Set the owner-only mode on the socket this process just bound, never through a symlink.

    glibc before 2.32 (Ubuntu 20.04, Debian 11, RHEL 8 and images built on them, such as
    ``condaforge/miniforge3:24.9.2-0``) has no no-follow ``fchmodat``, so the no-follow call
    raises ``NotImplementedError`` there and every service start failed (#1040). The fallback
    chmods the entry by name only after ``lstat`` shows it is still the socket this process
    bound: it sits in the runtime directory just verified as owner-only, so no other principal
    can replace it, and ``_bind`` re-verifies type, mode and inode afterwards.
    """

    try:
        os.chmod(path, ENDPOINT_MODE, follow_symlinks=False)
        return
    except NotImplementedError:
        pass
    current = path.lstat()
    if not stat.S_ISSOCK(current.st_mode) or (current.st_dev, current.st_ino) != created_inode:
        raise LocalControlTransportError("endpoint_unsafe")
    os.chmod(path, ENDPOINT_MODE)


async def _bind(kind: EndpointKind) -> UnixEndpointListener:
    _verify_runtime_directory(create=True)
    path = _endpoint_path(kind)
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise LocalControlTransportError("endpoint_unsafe") from exc
    else:
        raise LocalControlTransportError("endpoint_exists")

    raw_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    raw_socket.set_inheritable(False)
    created_inode: tuple[int, int] | None = None
    try:
        raw_socket.bind(os.fspath(path))
        created = path.lstat()
        created_inode = (created.st_dev, created.st_ino)
        _restrict_bound_endpoint(path, created_inode)
        inode = _verify_endpoint(path)
        if inode != created_inode:
            raise LocalControlTransportError("endpoint_unsafe")
        raw_socket.listen(_LISTEN_BACKLOG)
        raw_socket.setblocking(False)
    except BaseException as exc:
        raw_socket.close()
        try:
            current = path.lstat()
            if created_inode is not None and (current.st_dev, current.st_ino) == created_inode:
                path.unlink()
        except OSError:
            pass
        if isinstance(exc, LocalControlTransportError):
            raise
        if isinstance(exc, OSError):
            raise LocalControlTransportError("endpoint_unsafe") from exc
        raise
    return UnixEndpointListener(raw_socket, kind, path, inode)


async def bind_control_listener() -> UnixEndpointListener:
    return await _bind(EndpointKind.CONTROL)


async def bind_secret_listener() -> UnixEndpointListener:
    return await _bind(EndpointKind.SECRET)


async def bind_human_control_listener() -> UnixEndpointListener:
    return await _bind(EndpointKind.HUMAN_CONTROL)


async def _connect(kind: EndpointKind) -> AuthenticatedUnixStream:
    _verify_runtime_directory(create=False)
    path = _endpoint_path(kind)
    expected_inode = _verify_endpoint(path)
    raw_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    raw_socket.setblocking(False)
    raw_socket.set_inheritable(False)
    try:
        await asyncio.get_running_loop().sock_connect(raw_socket, os.fspath(path))
        peer = authenticate_peer(raw_socket)
        if _verify_endpoint(path) != expected_inode:
            raise LocalControlTransportError("endpoint_unsafe")
    except LocalControlTransportError:
        raw_socket.close()
        raise
    except (FileNotFoundError, ConnectionRefusedError) as exc:
        raw_socket.close()
        raise LocalControlTransportError("connection_failed") from exc
    except OSError as exc:
        raw_socket.close()
        raise LocalControlTransportError("connection_failed") from exc
    return AuthenticatedUnixStream(raw_socket, peer)


async def connect_control() -> AuthenticatedUnixStream:
    return await _connect(EndpointKind.CONTROL)


async def connect_secret() -> AuthenticatedUnixStream:
    return await _connect(EndpointKind.SECRET)


async def connect_human_control() -> AuthenticatedUnixStream:
    return await _connect(EndpointKind.HUMAN_CONTROL)


def _assert_service_lock(service_lock: _ServiceLockAuthority) -> None:
    try:
        service_lock.assert_held()
    except Exception as exc:
        raise LocalControlTransportError("service_lock_required") from exc


async def remove_stale_endpoint(kind: EndpointKind, service_lock: _ServiceLockAuthority) -> None:
    """Remove one proven-stale fixed endpoint while singleton authority is held."""

    if type(kind) is not EndpointKind:
        raise TypeError("endpoint_kind_invalid")
    _assert_service_lock(service_lock)
    runtime = _verify_runtime_directory(create=True)
    path = _endpoint_path(kind)
    expected_inode = _verify_endpoint(path)

    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.setblocking(False)
    probe.set_inheritable(False)
    try:
        await asyncio.wait_for(
            asyncio.get_running_loop().sock_connect(probe, os.fspath(path)),
            timeout=_STALE_PROBE_SECONDS,
        )
    except ConnectionRefusedError, FileNotFoundError:
        pass
    except TimeoutError as exc:
        raise LocalControlTransportError("endpoint_in_use") from exc
    except OSError as exc:
        raise LocalControlTransportError("endpoint_in_use") from exc
    else:
        try:
            authenticate_peer(probe)
        finally:
            probe.close()
        raise LocalControlTransportError("endpoint_in_use")
    finally:
        probe.close()

    directory_fd = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        current = os.stat(_ENDPOINT_BASENAMES[kind], dir_fd=directory_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != expected_inode:
            raise LocalControlTransportError("endpoint_unsafe")
        os.unlink(_ENDPOINT_BASENAMES[kind], dir_fd=directory_fd)
        os.fsync(directory_fd)
    except LocalControlTransportError:
        raise
    except OSError as exc:
        raise LocalControlTransportError("endpoint_unsafe") from exc
    finally:
        os.close(directory_fd)


async def close_endpoint(instance: UnixEndpointListener) -> None:
    """Close a listener and unlink only the endpoint inode it originally bound."""

    if type(instance) is not UnixEndpointListener:
        raise TypeError("endpoint_instance_invalid")
    await instance.aclose()
