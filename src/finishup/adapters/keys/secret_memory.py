"""In-process bounded mutable secret memory with measured OS hardening."""

from __future__ import annotations

import ctypes
import mmap
import os
import sys
from collections.abc import Callable, Mapping
from threading import Lock
from typing import Final

if sys.platform == "win32":
    resource = None
else:
    import resource

from finishup.ports.secret_memory import (
    SecretConsumer,
    SecretHandle,
    SecretMemoryCapability,
    SecretMemoryError,
    SecretMemoryPort,
    SecretPurpose,
)

__all__ = ["LocalSecretMemory"]

_MAX_ALLOCATION_BYTES: Final = 4 * 1024 * 1024
_PURPOSE_CONSUMERS: Final[Mapping[SecretPurpose, frozenset[SecretConsumer]]] = {
    SecretPurpose.VAULT_INITIALIZE: frozenset({SecretConsumer.VAULT_ROOT}),
    SecretPurpose.VAULT_UNLOCK: frozenset({SecretConsumer.VAULT_ROOT}),
    SecretPurpose.VAULT_ROOT_KEY: frozenset({SecretConsumer.VAULT_ROOT}),
    SecretPurpose.PORTABLE_RECOVERY: frozenset({SecretConsumer.RECOVERY_WRAPPER}),
    SecretPurpose.INSTALLATION_RECOVERY: frozenset({SecretConsumer.INSTALLATION_RECOVERY}),
    SecretPurpose.VAULT_REWRAP: frozenset(
        {SecretConsumer.VAULT_ROOT, SecretConsumer.VAULT_REWRAPPER}
    ),
    SecretPurpose.OBJECT_PAYLOAD: frozenset({SecretConsumer.OBJECT_CRYPTO}),
    SecretPurpose.PROVIDER_REAUTHENTICATION: frozenset(
        {SecretConsumer.VAULT_ROOT, SecretConsumer.PROVIDER_AUTHORIZER}
    ),
    SecretPurpose.PROVIDER_CREDENTIAL: frozenset(
        {SecretConsumer.VAULT_ROOT, SecretConsumer.PROVIDER_AUTHORIZER}
    ),
    SecretPurpose.PRIVACY_REAUTHENTICATION: frozenset(
        {SecretConsumer.VAULT_ROOT, SecretConsumer.PRIVACY_AUTHORIZER}
    ),
    SecretPurpose.SECURITY_REAUTHENTICATION: frozenset(
        {SecretConsumer.VAULT_ROOT, SecretConsumer.SECURITY_AUTHORIZER}
    ),
}


class LocalSecretMemory(SecretMemoryPort):
    """A closed, fork-fenced owner of one-shot anonymous mappings."""

    def __init__(self, *, require_page_locking: bool = False) -> None:
        if type(require_page_locking) is not bool:
            raise TypeError("require_page_locking_invalid")
        self._pid = os.getpid()
        self._lock = Lock()
        self._closed = False
        self._handles: list[_LocalSecretHandle] = []
        self._libc = _load_libc()
        self._page_lock_active = _probe_page_lock(self._libc)
        self._core_dump_active = _suppress_core_dumps()
        if require_page_locking and not self._page_lock_active:
            raise SecretMemoryError("memory_lock_failed")
        page_state = "active" if self._page_lock_active else "unavailable"
        core_state = "active" if self._core_dump_active else "unavailable"
        self._capability = SecretMemoryCapability(
            bounded_mutable_allocation="active",
            page_locking=page_state,
            core_dump_suppression=core_state,
            one_shot_consumption="active",
            best_effort_overwrite="active",
        )

    def capability(self) -> SecretMemoryCapability:
        self._require_live()
        return self._capability

    def capture(self, purpose: SecretPurpose, source: bytearray) -> SecretHandle:
        if type(source) is not bytearray:
            raise TypeError("secret_source_invalid")
        try:
            handle = self.allocate(purpose, len(source))
            if not isinstance(handle, _LocalSecretHandle):
                raise SecretMemoryError("internal_error")
            handle._write(source)  # pyright: ignore[reportPrivateUsage]
            return handle
        finally:
            source[:] = b"\x00" * len(source)

    def allocate(self, purpose: SecretPurpose, size: int) -> SecretHandle:
        if type(purpose) is not SecretPurpose:
            raise TypeError("secret_purpose_invalid")
        if type(size) is not int or not 1 <= size <= _MAX_ALLOCATION_BYTES:
            raise SecretMemoryError("size_invalid")
        with self._lock:
            self._require_live()
            try:
                mapping = mmap.mmap(-1, size, access=mmap.ACCESS_WRITE)
            except (OSError, ValueError) as exc:
                raise SecretMemoryError("internal_error") from exc
            locked = _lock_mapping(self._libc, mapping, size) if self._page_lock_active else False
            if self._page_lock_active and not locked:
                _overwrite_mapping(mapping, size)
                mapping.close()
                raise SecretMemoryError("memory_lock_failed")
            _exclude_from_core_dump(mapping, size)
            handle = _LocalSecretHandle(self, mapping, size, purpose, locked, self._pid)
            self._handles.append(handle)
            return handle

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            handles = tuple(self._handles)
            self._handles.clear()
        for handle in handles:
            handle._invalidate()  # pyright: ignore[reportPrivateUsage]

    def _remove(self, handle: _LocalSecretHandle) -> None:
        with self._lock:
            try:
                self._handles.remove(handle)
            except ValueError:
                pass

    def _require_live(self) -> None:
        if self._closed:
            raise SecretMemoryError("closed")
        if os.getpid() != self._pid:
            raise SecretMemoryError("closed")


class _LocalSecretHandle:
    __slots__ = (
        "_consumed",
        "_locked",
        "_lock",
        "_mapping",
        "_owner",
        "_pid",
        "_purpose",
        "_size",
    )

    def __init__(
        self,
        owner: LocalSecretMemory,
        mapping: mmap.mmap,
        size: int,
        purpose: SecretPurpose,
        locked: bool,
        pid: int,
    ) -> None:
        self._owner = owner
        self._mapping: mmap.mmap | None = mapping
        self._size = size
        self._purpose = purpose
        self._locked = locked
        self._pid = pid
        self._consumed = False
        self._lock = Lock()

    @property
    def purpose(self) -> SecretPurpose:
        return self._purpose

    def consume[T](self, consumer: SecretConsumer, fn: Callable[[memoryview], T]) -> T:
        if type(consumer) is not SecretConsumer:
            raise SecretMemoryError("consumer_forbidden")
        if consumer not in _PURPOSE_CONSUMERS[self._purpose]:
            raise SecretMemoryError("consumer_forbidden")
        with self._lock:
            if self._consumed:
                raise SecretMemoryError("already_consumed")
            if os.getpid() != self._pid:
                self._consumed = True
                self._destroy()
                raise SecretMemoryError("closed")
            self._owner._require_live()  # pyright: ignore[reportPrivateUsage]
            mapping = self._mapping
            if mapping is None:
                raise SecretMemoryError("closed")
            self._consumed = True
            view = memoryview(mapping)
            try:
                return fn(view)
            finally:
                view.release()
                self._destroy()
                self._owner._remove(self)  # pyright: ignore[reportPrivateUsage]

    def _write(self, source: bytearray) -> None:
        with self._lock:
            if self._mapping is None or self._consumed:
                raise SecretMemoryError("closed")
            self._mapping.seek(0)
            self._mapping.write(source)
            self._mapping.seek(0)

    def _invalidate(self) -> None:
        with self._lock:
            self._consumed = True
            self._destroy()

    def _destroy(self) -> None:
        mapping = self._mapping
        if mapping is None:
            return
        self._mapping = None
        try:
            _overwrite_mapping(mapping, self._size)
            if self._locked:
                _unlock_mapping(
                    self._owner._libc,  # pyright: ignore[reportPrivateUsage]
                    mapping,
                    self._size,
                )
        finally:
            try:
                mapping.close()
            except BufferError, OSError:
                pass

    def __repr__(self) -> str:
        return f"<{type(self).__name__} purpose={self._purpose.value} consumed={self._consumed}>"

    def __copy__(self) -> _LocalSecretHandle:
        raise TypeError("secret_handle_not_copyable")

    def __deepcopy__(self, memo: Mapping[int, object]) -> _LocalSecretHandle:
        del memo
        raise TypeError("secret_handle_not_copyable")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("secret_handle_not_serializable")


def _load_libc() -> ctypes.CDLL | None:
    if sys.platform not in {"darwin", "linux"}:
        return None
    try:
        return ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None


def _mapping_address(mapping: mmap.mmap) -> tuple[ctypes.Array[ctypes.c_char], int]:
    buffer = (ctypes.c_char * len(mapping)).from_buffer(mapping)
    return buffer, ctypes.addressof(buffer)


def _probe_page_lock(libc: ctypes.CDLL | None) -> bool:
    if libc is None:
        return False
    size = max(1, mmap.PAGESIZE)
    try:
        mapping = mmap.mmap(-1, size, access=mmap.ACCESS_WRITE)
        locked = _lock_mapping(libc, mapping, size)
        if locked:
            _unlock_mapping(libc, mapping, size)
        mapping.close()
        return locked
    except OSError, BufferError, ValueError:
        return False


def _lock_mapping(libc: ctypes.CDLL | None, mapping: mmap.mmap, size: int) -> bool:
    if libc is None:
        return False
    try:
        buffer, address = _mapping_address(mapping)
        result = libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
        del buffer
        return result == 0
    except AttributeError, BufferError, ValueError:
        return False


def _unlock_mapping(libc: ctypes.CDLL | None, mapping: mmap.mmap, size: int) -> None:
    if libc is None:
        return
    try:
        buffer, address = _mapping_address(mapping)
        libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
        del buffer
    except AttributeError, BufferError, ValueError:
        pass


def _exclude_from_core_dump(mapping: mmap.mmap, size: int) -> None:
    if sys.platform != "linux":
        return
    libc = _load_libc()
    if libc is None:
        return
    try:
        buffer, address = _mapping_address(mapping)
        libc.madvise(ctypes.c_void_p(address), ctypes.c_size_t(size), ctypes.c_int(16))
        del buffer
    except AttributeError, BufferError, ValueError:
        pass


def _suppress_core_dumps() -> bool:
    if resource is None:
        return False
    try:
        _, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
        return resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    except OSError, ValueError:
        return False


def _overwrite_mapping(mapping: mmap.mmap, size: int) -> None:
    try:
        mapping.seek(0)
        remaining = size
        zeroes = b"\x00" * min(size, 65_536)
        while remaining:
            chunk = min(remaining, len(zeroes))
            mapping.write(zeroes[:chunk])
            remaining -= chunk
        mapping.flush()
        mapping.seek(0)
    except BufferError, OSError, ValueError:
        pass
