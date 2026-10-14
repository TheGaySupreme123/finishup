"""Verified APSW connections and the single-writer execution thread.

Connection objects are package-private capabilities.  They must never cross the
``yoetz.adapters.sqlite`` boundary.
"""

from __future__ import annotations

import os
import queue
import stat
import threading
import warnings
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, cast

import apsw

from yoetz.config.paths import PathSafetyError, verify_private_local_bundle
from yoetz.ports.runtime import OwnershipFence

__all__ = [
    "BUSY_TIMEOUT_MS",
    "REQUIRED_APSW_VERSION",
    "REQUIRED_SQLITE_SOURCE_ID",
    "REQUIRED_SQLITE_VERSION",
    "STATEMENT_CACHE_SIZE",
    "WRITER_QUEUE_DEPTH",
    "YOETZ_APPLICATION_ID",
    "SchemaIdentity",
    "SqliteBuildReport",
    "SqliteWriterThread",
    "StorageUnsafeError",
    "assert_active_bundle_generation",
    "open_catalog_writer",
    "open_read_only",
    "open_writer",
    "verify_schema_identity",
    "verify_sqlite_build",
]

REQUIRED_APSW_VERSION: Final = "3.53.3.1"
REQUIRED_SQLITE_VERSION: Final = "3.53.3"
REQUIRED_SQLITE_SOURCE_ID: Final = (
    "2026-06-26 20:14:12 d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62"
)
YOETZ_APPLICATION_ID: Final = 0x594F4554
BUSY_TIMEOUT_MS: Final = 5_000
STATEMENT_CACHE_SIZE: Final = 100
WRITER_QUEUE_DEPTH: Final = 64

_SUPPORTED_CATALOG_SCHEMA_VERSION: Final = 5
_SUPPORTED_BUNDLE_SCHEMA_VERSION: Final = 16
_SUPPORTED_SCHEMA_VERSION: Final = _SUPPORTED_BUNDLE_SCHEMA_VERSION
_PROTOCOL_VERSION: Final = "0.1"
_SQLITE_OPEN_WRITER: Final = apsw.SQLITE_OPEN_READWRITE | apsw.SQLITE_OPEN_CREATE
_READ_ONLY_ALLOWED_PRAGMAS: Final = frozenset(
    {
        "application_id",
        "compile_options",
        "foreign_key_check",
        "integrity_check",
        "query_only",
        "quick_check",
        "schema_version",
        "user_version",
    }
)
_WRITER_ALLOWED_PRAGMAS: Final = _READ_ONLY_ALLOWED_PRAGMAS | frozenset(
    {"application_id", "user_version", "wal_checkpoint"}
)
_WRITER_SAFE_CONFIGURATION_PRAGMAS: Final = {
    "defer_foreign_keys": frozenset({None, "ON", "1"}),
    "foreign_keys": frozenset({None, "ON", "1"}),
    "trusted_schema": frozenset({None, "OFF", "0"}),
}
# Observation consent supports both structural-only and native-content bundle
# schemas. Permit read-only column probes for the non-metadata tables used by
# integrity capture, while keeping bundle_meta and the no-argument form
# restricted; this is not permission to run arbitrary PRAGMAs (#616).
_READ_ONLY_SCHEMA_PRAGMAS: Final = {"table_info": frozenset({"observation_consent"})}
_STORAGE_UNSAFE_REASONS: Final = frozenset(
    {
        "application_id_mismatch",
        "apsw_version_mismatch",
        "bundle_generation_lost",
        "compile_options_mismatch",
        "database_missing",
        "foreign_keys_not_enabled",
        "full_sync_not_active",
        "mmap_not_disabled",
        "not_amalgamation",
        "schema_metadata_disagrees",
        "schema_newer_than_binary",
        "sqlite_source_id_mismatch",
        "sqlite_version_mismatch",
        "storage_path_unsafe",
        "temp_store_not_memory",
        "trusted_schema_not_disabled",
        "wal_not_enabled",
    }
)


class StorageUnsafeError(Exception):
    """A bounded internal storage failure mapped to ``STORAGE_UNSAFE``."""

    reason_code: str

    def __init__(self, reason_code: str) -> None:
        if type(reason_code) is not str or reason_code not in _STORAGE_UNSAFE_REASONS:
            raise ValueError("storage_unsafe_reason_invalid")
        self.reason_code = reason_code
        super().__init__(reason_code)


class _WriterBusyError(Exception):
    """Bounded queue/SQLite contention mapped to retryable ``BUNDLE_BUSY``."""

    def __init__(self) -> None:
        super().__init__("bundle_busy")


@dataclass(frozen=True, slots=True)
class SqliteBuildReport:
    apsw_version: str
    sqlite_version: str
    source_id: str
    compile_options: tuple[str, ...]
    manifest_id: str


@dataclass(frozen=True, slots=True)
class SchemaIdentity:
    state: Literal["uninitialized", "current", "migration_required"]
    user_version: int


@dataclass(frozen=True, slots=True)
class _SqliteSupportPolicy:
    """Exact reviewed compile-option policy supplied by the release manifest."""

    manifest_id: str
    required_options: frozenset[str]
    denied_options: frozenset[str]


_support_policy: _SqliteSupportPolicy | None = None
_support_policy_lock = threading.Lock()
_active_fences: dict[Path, OwnershipFence] = {}
_active_fences_lock = threading.Lock()


def _install_support_policy(  # pyright: ignore[reportUnusedFunction]
    policy: _SqliteSupportPolicy | None,
) -> None:
    """Install a verified release policy; used by version startup and focused tests."""

    global _support_policy
    with _support_policy_lock:
        _support_policy = policy


def _register_active_fence(path: Path, fence: OwnershipFence) -> None:  # pyright: ignore[reportUnusedFunction]
    if type(fence) is not OwnershipFence:
        raise TypeError("active_fence_invalid")
    with _active_fences_lock:
        _active_fences[path.resolve(strict=False)] = fence


def _clear_active_fence(path: Path, fence: OwnershipFence | None = None) -> None:
    normalized = path.resolve(strict=False)
    with _active_fences_lock:
        current = _active_fences.get(normalized)
        if fence is None or current == fence:
            _active_fences.pop(normalized, None)


def _active_fence(path: Path) -> OwnershipFence:
    with _active_fences_lock:
        fence = _active_fences.get(path.resolve(strict=False))
    if fence is None:
        raise AssertionError("active_bundle_generation_not_registered")
    return fence


def _first_value(db: apsw.Connection, sql: str) -> object:
    row = db.execute(sql).fetchone()
    if row is None or len(row) != 1:
        raise StorageUnsafeError("schema_metadata_disagrees")
    return row[0]


def _pragma_int(db: apsw.Connection, name: str) -> int:
    value = db.pragma(name)
    if type(value) is not int:
        raise StorageUnsafeError("schema_metadata_disagrees")
    return value


def _close_quietly(db: apsw.Connection) -> None:
    try:
        db.close(force=True)
    except Exception:
        pass


def _verify_database_file(path: Path, *, may_create: bool) -> None:
    """Reject links/non-regular files and create new files owner-only without following links."""

    try:
        facts = path.lstat()
    except FileNotFoundError:
        if not may_create:
            raise StorageUnsafeError("database_missing") from None
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise StorageUnsafeError("storage_path_unsafe") from exc
        else:
            os.close(descriptor)
        facts = path.lstat()
    except OSError as exc:
        raise StorageUnsafeError("storage_path_unsafe") from exc

    mode = facts.st_mode
    if (
        stat.S_ISLNK(mode)
        or not stat.S_ISREG(mode)
        or facts.st_nlink != 1
        or stat.S_IMODE(mode) & 0o077
    ):
        raise StorageUnsafeError("storage_path_unsafe")
    if hasattr(os, "geteuid") and facts.st_uid != os.geteuid():
        raise StorageUnsafeError("storage_path_unsafe")


def _verify_safe_path(path: Path, *, may_create: bool) -> None:
    if not path.is_absolute():
        raise StorageUnsafeError("storage_path_unsafe")
    try:
        verify_private_local_bundle(path.parent)
        verify_private_local_bundle(path)
    except PathSafetyError as exc:
        raise StorageUnsafeError("storage_path_unsafe") from exc
    _verify_database_file(path, may_create=may_create)


def _configure_writer(db: apsw.Connection) -> None:
    db.set_busy_timeout(BUSY_TIMEOUT_MS)
    db.enable_load_extension(False)
    db.pragma("foreign_keys", 1)
    if db.pragma("foreign_keys") != 1:
        raise StorageUnsafeError("foreign_keys_not_enabled")
    db.pragma("trusted_schema", 0)
    if db.pragma("trusted_schema") != 0:
        raise StorageUnsafeError("trusted_schema_not_disabled")
    db.pragma("temp_store", 2)
    if db.pragma("temp_store") != 2:
        raise StorageUnsafeError("temp_store_not_memory")
    mode = db.pragma("journal_mode", "WAL")
    if type(mode) is not str or mode.lower() != "wal":
        raise StorageUnsafeError("wal_not_enabled")
    db.pragma("synchronous", 2)
    if db.pragma("synchronous") != 2:
        raise StorageUnsafeError("full_sync_not_active")
    db.pragma("wal_autocheckpoint", 0)
    db.pragma("mmap_size", 0)
    if db.pragma("mmap_size") != 0:
        raise StorageUnsafeError("mmap_not_disabled")


def verify_sqlite_build(db: apsw.Connection) -> SqliteBuildReport:
    """Verify the exact APSW/SQLite build and reviewed compile-option policy."""

    apsw_version = apsw.apsw_version()
    if apsw_version != REQUIRED_APSW_VERSION:
        raise StorageUnsafeError("apsw_version_mismatch")
    sqlite_version = apsw.sqlite_lib_version()
    if sqlite_version != REQUIRED_SQLITE_VERSION:
        raise StorageUnsafeError("sqlite_version_mismatch")
    if not apsw.using_amalgamation:
        raise StorageUnsafeError("not_amalgamation")
    source_id = _first_value(db, "SELECT sqlite_source_id()")
    if source_id != REQUIRED_SQLITE_SOURCE_ID:
        raise StorageUnsafeError("sqlite_source_id_mismatch")
    raw_options: object = db.pragma("compile_options")
    if type(raw_options) is not list:
        raise StorageUnsafeError("compile_options_mismatch")
    raw_option_items = cast(list[object], raw_options)
    if any(type(item) is not str for item in raw_option_items):
        raise StorageUnsafeError("compile_options_mismatch")
    compile_options = tuple(
        sorted((cast(str, item) for item in raw_option_items), key=lambda item: item.encode())
    )
    if len(compile_options) != len(set(compile_options)):
        raise StorageUnsafeError("compile_options_mismatch")
    with _support_policy_lock:
        policy = _support_policy
    if policy is None:
        # Wave F owns the signed-off runtime-support resource.  Absence cannot
        # silently widen write support during an incomplete source build.
        raise StorageUnsafeError("compile_options_mismatch")
    option_set = frozenset(compile_options)
    if not policy.required_options <= option_set or policy.denied_options & option_set:
        raise StorageUnsafeError("compile_options_mismatch")
    return SqliteBuildReport(
        apsw_version=apsw_version,
        sqlite_version=sqlite_version,
        source_id=cast(str, source_id),
        compile_options=compile_options,
        manifest_id=policy.manifest_id,
    )


def _table_names(db: apsw.Connection) -> frozenset[str]:
    rows = db.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    if any(len(row) != 1 or type(row[0]) is not str for row in rows):
        raise StorageUnsafeError("schema_metadata_disagrees")
    return frozenset(cast(str, row[0]) for row in rows)


def _metadata(db: apsw.Connection, table: str) -> dict[str, str]:
    rows = db.execute(f"SELECT key, value FROM {table} ORDER BY key").fetchall()
    if any(len(row) != 2 or type(row[0]) is not str or type(row[1]) is not str for row in rows):
        raise StorageUnsafeError("schema_metadata_disagrees")
    result = {cast(str, row[0]): cast(str, row[1]) for row in rows}
    if len(result) != len(rows):
        raise StorageUnsafeError("schema_metadata_disagrees")
    return result


def verify_schema_identity(db: apsw.Connection) -> SchemaIdentity:
    """Verify application/schema identity without mutating the database."""

    application_id = _pragma_int(db, "application_id")
    tables = _table_names(db)
    if application_id == 0 and not tables:
        return SchemaIdentity(state="uninitialized", user_version=0)
    if application_id != YOETZ_APPLICATION_ID:
        raise StorageUnsafeError("application_id_mismatch")

    user_version = _pragma_int(db, "user_version")
    if "bundle_meta" in tables:
        supported = _SUPPORTED_BUNDLE_SCHEMA_VERSION
    elif "catalog_meta" in tables:
        supported = _SUPPORTED_CATALOG_SCHEMA_VERSION
    else:
        supported = _SUPPORTED_SCHEMA_VERSION
    if user_version > supported:
        raise StorageUnsafeError("schema_newer_than_binary")
    state: Literal["current", "migration_required"]
    state = "current" if user_version == supported else "migration_required"

    if "bundle_meta" in tables:
        metadata = _metadata(db, "bundle_meta")
        if (
            metadata.get("storage_schema_version") != str(user_version)
            or metadata.get("protocol_version") != _PROTOCOL_VERSION
        ):
            raise StorageUnsafeError("schema_metadata_disagrees")
    return SchemaIdentity(state=state, user_version=user_version)


def _read_only_authorizer(
    action: int,
    first: str | None,
    second: str | None,
    database: str | None,
    trigger: str | None,
) -> int:
    del database, trigger
    if action in {
        apsw.SQLITE_SELECT,
        apsw.SQLITE_READ,
        apsw.SQLITE_FUNCTION,
        apsw.SQLITE_RECURSIVE,
    }:
        return apsw.SQLITE_OK
    if action == apsw.SQLITE_PRAGMA:
        if second is None and first in _READ_ONLY_ALLOWED_PRAGMAS:
            return apsw.SQLITE_OK
        # ``capture_sqlite_integrity`` uses the table-valued form
        # ``pragma_table_info(?)`` to derive a stable column order for every
        # preserved table.  Column metadata is read-only; the argument is
        # still bound by SQLite and cannot introduce SQL syntax.
        if first == "table_info" and second not in {None, "bundle_meta"}:
            return apsw.SQLITE_OK
        if first in _READ_ONLY_SCHEMA_PRAGMAS and second in _READ_ONLY_SCHEMA_PRAGMAS[first]:
            return apsw.SQLITE_OK
    return apsw.SQLITE_DENY


def _writer_authorizer(
    action: int,
    first: str | None,
    second: str | None,
    database: str | None,
    trigger: str | None,
) -> int:
    del database, trigger
    if action in {
        apsw.SQLITE_ATTACH,
        apsw.SQLITE_CREATE_VTABLE,
        apsw.SQLITE_DETACH,
        apsw.SQLITE_DROP_VTABLE,
    }:
        return apsw.SQLITE_DENY
    if action == apsw.SQLITE_FUNCTION and second == "load_extension":
        return apsw.SQLITE_DENY
    if action == apsw.SQLITE_PRAGMA:
        if first in _WRITER_ALLOWED_PRAGMAS:
            return apsw.SQLITE_OK
        if first == "table_info" and second not in {None, "bundle_meta"}:
            return apsw.SQLITE_OK
        if first in _READ_ONLY_SCHEMA_PRAGMAS and second in _READ_ONLY_SCHEMA_PRAGMAS[first]:
            return apsw.SQLITE_OK
        if (
            first in _WRITER_SAFE_CONFIGURATION_PRAGMAS
            and second in _WRITER_SAFE_CONFIGURATION_PRAGMAS[first]
        ):
            return apsw.SQLITE_OK
        return apsw.SQLITE_DENY
    return apsw.SQLITE_OK


def _migration_authorizer(  # pyright: ignore[reportUnusedFunction]
    action: int,
    first: str | None,
    second: str | None,
    database: str | None,
    trigger: str | None,
) -> int:
    """Extend the canonical writer policy only for migration-scoped PRAGMAs."""

    if action == apsw.SQLITE_PRAGMA and first in {"foreign_keys", "legacy_alter_table"}:
        if second in {None, "ON", "OFF", "1", "0"}:
            return apsw.SQLITE_OK
    return _writer_authorizer(action, first, second, database, trigger)


def _open_structural_read_only(path: Path) -> apsw.Connection:
    _verify_safe_path(path, may_create=False)
    db: apsw.Connection | None = None
    try:
        db = apsw.Connection(
            str(path),
            flags=apsw.SQLITE_OPEN_READONLY,
            statementcachesize=STATEMENT_CACHE_SIZE,
        )
        db.set_busy_timeout(BUSY_TIMEOUT_MS)
        db.enable_load_extension(False)
        db.pragma("query_only", 1)
        if db.pragma("query_only") != 1:
            raise StorageUnsafeError("storage_path_unsafe")
        db.pragma("trusted_schema", 0)
        if db.pragma("trusted_schema") != 0:
            raise StorageUnsafeError("trusted_schema_not_disabled")
        db.pragma("mmap_size", 0)
        if db.pragma("mmap_size") != 0:
            raise StorageUnsafeError("mmap_not_disabled")
        db.set_authorizer(_read_only_authorizer)
        return db
    except Exception:
        if db is not None:
            _close_quietly(db)
        raise


def open_read_only(path: Path) -> apsw.Connection:
    """Open a literal-filename, non-creating, authorizer-guarded inspection connection."""

    db = _open_structural_read_only(path)
    try:
        try:
            verify_sqlite_build(db)
        except StorageUnsafeError as exc:
            if exc.reason_code not in {
                "apsw_version_mismatch",
                "compile_options_mismatch",
                "not_amalgamation",
                "sqlite_source_id_mismatch",
                "sqlite_version_mismatch",
            }:
                raise
            warnings.warn("sqlite_build_unsupported", RuntimeWarning, stacklevel=2)
        try:
            verify_schema_identity(db)
        except StorageUnsafeError as exc:
            if exc.reason_code != "schema_newer_than_binary":
                raise
            warnings.warn("sqlite_schema_newer_than_binary", RuntimeWarning, stacklevel=2)
        return db
    except Exception:
        _close_quietly(db)
        raise


def assert_active_bundle_generation(path: Path) -> None:
    """Prove the registered writer fence still matches durable owner metadata."""

    fence = _active_fence(path)
    db = _open_structural_read_only(path)
    try:
        tables = _table_names(db)
        if "bundle_meta" in tables:
            metadata = _metadata(db, "bundle_meta")
        elif "catalog_meta" in tables:
            metadata = _metadata(db, "catalog_meta")
        else:
            raise StorageUnsafeError("bundle_generation_lost")
        stored_generation = metadata.get("owner_generation")
        if (
            stored_generation != str(fence.owner_generation)
            or metadata.get("owner_nonce") != fence.nonce
        ):
            raise StorageUnsafeError("bundle_generation_lost")
    except StorageUnsafeError:
        _clear_active_fence(path, fence)
        raise
    finally:
        _close_quietly(db)


def _open_verified_writer(path: Path, *, require_fence: bool) -> apsw.Connection:
    if require_fence:
        assert_active_bundle_generation(path)
    _verify_safe_path(path, may_create=True)
    db: apsw.Connection | None = None
    try:
        db = apsw.Connection(
            str(path), flags=_SQLITE_OPEN_WRITER, statementcachesize=STATEMENT_CACHE_SIZE
        )
        _configure_writer(db)
        verify_sqlite_build(db)
        identity = verify_schema_identity(db)
        if identity.state == "migration_required":
            raise StorageUnsafeError("schema_metadata_disagrees")
        db.set_authorizer(_writer_authorizer)
        return db
    except Exception:
        if db is not None:
            _close_quietly(db)
        raise


def _open_recovery_writer(  # pyright: ignore[reportUnusedFunction]
    path: Path,
) -> apsw.Connection:
    """Open the sole pre-fence writer used by migration/ownership recovery."""

    return _open_verified_writer(path, require_fence=False)


def _open_catalog_migration_writer(  # pyright: ignore[reportUnusedFunction]
    path: Path,
) -> apsw.Connection:
    """Open one existing stale catalog for exclusive ready-startup migration.

    This capability deliberately has no SQL authorizer because schema migration requires DDL.
    It accepts neither fresh databases nor bundle databases, and callers must close it before
    reopening the catalog through :func:`open_catalog_writer`.
    """

    _verify_safe_path(path, may_create=False)
    db: apsw.Connection | None = None
    try:
        db = apsw.Connection(
            str(path),
            flags=apsw.SQLITE_OPEN_READWRITE,
            statementcachesize=STATEMENT_CACHE_SIZE,
        )
        _configure_writer(db)
        verify_sqlite_build(db)
        tables = _table_names(db)
        if "catalog_meta" not in tables or "bundle_meta" in tables:
            raise StorageUnsafeError("schema_metadata_disagrees")
        identity = verify_schema_identity(db)
        if identity.state != "migration_required":
            raise StorageUnsafeError("schema_metadata_disagrees")
        return db
    except Exception:
        if db is not None:
            _close_quietly(db)
        raise


def _open_bundle_migration_writer(  # pyright: ignore[reportUnusedFunction]
    path: Path,
) -> apsw.Connection:
    """Open one existing stale bundle for the controlled upgrade phase.

    This is deliberately narrower than a normal writer and is not a recovery or runtime-open
    escape hatch.  It accepts only an initialized bundle whose schema is older than this binary;
    callers must quiesce the service and close the connection before reopening through
    :func:`open_writer`.  The ordinary authorizer is installed before returning, and the
    migration runner temporarily replaces it only for its bounded DDL window.
    """

    _verify_safe_path(path, may_create=False)
    db: apsw.Connection | None = None
    try:
        db = apsw.Connection(
            str(path),
            flags=apsw.SQLITE_OPEN_READWRITE,
            statementcachesize=STATEMENT_CACHE_SIZE,
        )
        _configure_writer(db)
        db.set_authorizer(_writer_authorizer)
        verify_sqlite_build(db)
        tables = _table_names(db)
        if "bundle_meta" not in tables or "catalog_meta" in tables or "events" not in tables:
            raise StorageUnsafeError("schema_metadata_disagrees")
        identity = verify_schema_identity(db)
        if identity.state != "migration_required":
            raise StorageUnsafeError("schema_metadata_disagrees")
        return db
    except Exception:
        if db is not None:
            _close_quietly(db)
        raise


def open_catalog_writer(path: Path) -> apsw.Connection:
    """Open the generation-owned catalog writer before any bundle fence exists."""

    return _open_verified_writer(path, require_fence=False)


def open_writer(path: Path) -> apsw.Connection:
    """Open a fully verified writer after proving the durable generation fence."""

    return _open_verified_writer(path, require_fence=True)


@dataclass(slots=True)
class _WriterJob:
    function: Callable[[apsw.Connection], Any]
    future: Future[Any]


_CLOSE_SENTINEL: Final = object()


class SqliteWriterThread:
    """One connection owned for its entire lifetime by one dedicated thread."""

    _path: Path
    _queue: queue.Queue[_WriterJob | object]
    _thread: threading.Thread
    _ready: Future[None]
    _accepting: bool
    _state_lock: threading.Lock

    def __init__(self, path: Path) -> None:
        self._path = path
        self._queue = queue.Queue(maxsize=WRITER_QUEUE_DEPTH)
        self._ready = Future()
        self._accepting = True
        self._state_lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._run,
            name="yoetz-sqlite-writer",
            daemon=False,
        )
        self._thread.start()
        self._ready.result()

    def submit[T](self, function: Callable[[apsw.Connection], T]) -> Future[T]:
        if not callable(function):
            raise TypeError("writer_job_not_callable")
        future: Future[T] = Future()
        job = _WriterJob(
            cast(Callable[[apsw.Connection], Any], function), cast(Future[Any], future)
        )
        with self._state_lock:
            if not self._accepting:
                raise RuntimeError("writer_thread_closed")
            try:
                self._queue.put_nowait(job)
            except queue.Full as exc:
                raise _WriterBusyError() from exc
        return future

    def close(self) -> None:
        with self._state_lock:
            if not self._accepting:
                return
            self._accepting = False
        self._queue.put(_CLOSE_SENTINEL)
        self._thread.join()

    def _run(self) -> None:
        db: apsw.Connection | None = None
        try:
            db = open_writer(self._path)
        except BaseException as exc:
            self._ready.set_exception(exc)
            return
        self._ready.set_result(None)
        try:
            while True:
                item = self._queue.get()
                if item is _CLOSE_SENTINEL:
                    break
                job = cast(_WriterJob, item)
                if not job.future.set_running_or_notify_cancel():
                    continue
                try:
                    result = job.function(db)
                except apsw.BusyError, apsw.LockedError:
                    job.future.set_exception(_WriterBusyError())
                except BaseException as exc:
                    job.future.set_exception(exc)
                else:
                    job.future.set_result(result)
        finally:
            try:
                db.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
            except Exception:
                pass
            _close_quietly(db)
