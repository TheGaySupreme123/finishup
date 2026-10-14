from __future__ import annotations

from pathlib import Path
from typing import Final, cast

import apsw
import pytest

import finishup.adapters.sqlite.connection as connection_module
from finishup.adapters.sqlite.connection import (
    REQUIRED_APSW_VERSION,
    REQUIRED_SQLITE_SOURCE_ID,
    REQUIRED_SQLITE_VERSION,
    SqliteBuildReport,
    StorageUnsafeError,
    open_read_only,
    open_writer,
)
from finishup.adapters.sqlite.migrations import BUNDLE_MIGRATIONS, current_schema_version
from finishup.ports.runtime import OwnershipFence

# Tracks the migration registry so a new bundle migration does not silently turn this
# fixture into a "migration_required" database that open_writer refuses.
_CURRENT_BUNDLE_VERSION: Final = current_schema_version(BUNDLE_MIGRATIONS)


def _create_current_bundle(path: Path, *, owner_generation: int, owner_nonce: str) -> None:
    db = apsw.Connection(str(path))
    try:
        db.pragma("application_id", 0x594F4554)
        db.execute(
            "CREATE TABLE bundle_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) "
            "STRICT, WITHOUT ROWID"
        )
        db.executemany(
            "INSERT INTO bundle_meta(key, value) VALUES (?, ?)",
            (
                ("owner_generation", str(owner_generation)),
                ("owner_nonce", owner_nonce),
                ("protocol_version", "0.1"),
                ("storage_schema_version", str(_CURRENT_BUNDLE_VERSION)),
            ),
        )
        db.pragma("user_version", _CURRENT_BUNDLE_VERSION)
    finally:
        db.close()
    path.chmod(0o600)


def _accept_build(_db: apsw.Connection) -> SqliteBuildReport:
    return SqliteBuildReport(
        apsw_version=REQUIRED_APSW_VERSION,
        sqlite_version=REQUIRED_SQLITE_VERSION,
        source_id=REQUIRED_SQLITE_SOURCE_ID,
        compile_options=(),
        manifest_id="test-runtime-support",
    )


def _register(path: Path, fence: OwnershipFence) -> None:
    active = cast(
        dict[Path, OwnershipFence],
        getattr(connection_module, "_active_fences"),
    )
    active[path.resolve(strict=False)] = fence


def _accept_path(_path: Path) -> None:
    return None


@pytest.fixture(autouse=True)
def _safe_test_connections(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _accept_path)
    monkeypatch.setattr(connection_module, "verify_sqlite_build", _accept_build)
    active = cast(
        dict[Path, OwnershipFence],
        getattr(connection_module, "_active_fences"),
    )
    active.clear()


def test_current_generation_can_write(tmp_path: Path) -> None:
    database = tmp_path / "ledger.sqlite3"
    nonce = "current-owner-nonce-0001"
    _create_current_bundle(database, owner_generation=4, owner_nonce=nonce)
    fence = OwnershipFence(
        service_instance_id="svc_00000000-0000-4000-8000-000000000001",
        service_generation=7,
        owner_generation=4,
        nonce=nonce,
    )
    _register(database, fence)

    db = open_writer(database)
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO bundle_meta VALUES ('heartbeat_at', '2026-07-19T00:00:00.000Z')")
        db.execute("COMMIT")
    finally:
        db.close()


def test_stale_generation_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "ledger.sqlite3"
    nonce = "current-owner-nonce-0002"
    _create_current_bundle(database, owner_generation=5, owner_nonce=nonce)
    _register(
        database,
        OwnershipFence(
            service_instance_id="svc_00000000-0000-4000-8000-000000000001",
            service_generation=7,
            owner_generation=4,
            nonce=nonce,
        ),
    )

    with pytest.raises(StorageUnsafeError, match="bundle_generation_lost") as captured:
        open_writer(database)
    assert captured.value.reason_code == "bundle_generation_lost"


def test_cli_style_and_mcp_style_ownership_match(tmp_path: Path) -> None:
    database = tmp_path / "ledger.sqlite3"
    nonce = "current-owner-nonce-0003"
    _create_current_bundle(database, owner_generation=2, owner_nonce=nonce)
    fence = OwnershipFence(
        service_instance_id="svc_00000000-0000-4000-8000-000000000001",
        service_generation=3,
        owner_generation=2,
        nonce=nonce,
    )
    for _surface in ("cli", "mcp"):
        _register(database, fence)
        db = open_writer(database)
        db.close()


def test_read_only_connection_denies_mutation(tmp_path: Path) -> None:
    database = tmp_path / "ledger.sqlite3"
    _create_current_bundle(database, owner_generation=1, owner_nonce="current-owner-nonce-0004")

    db = open_read_only(database)
    try:
        assert db.pragma("query_only") == 1
        with pytest.raises(apsw.AuthError):
            db.execute("CREATE TABLE forbidden(value TEXT)")
    finally:
        db.close()


def test_read_only_path_is_literal_not_uri(tmp_path: Path) -> None:
    database = tmp_path / "literal?mode=rw.sqlite3"
    _create_current_bundle(database, owner_generation=1, owner_nonce="current-owner-nonce-0005")

    db = open_read_only(database)
    try:
        assert db.pragma("query_only") == 1
    finally:
        db.close()
