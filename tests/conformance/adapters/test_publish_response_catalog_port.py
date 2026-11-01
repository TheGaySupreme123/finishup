"""Memory/SQLite parity for durable publish-response replay storage."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import anyio
import apsw
import pytest

from finishup.adapters.memory.start_catalog import (
    MemoryStartCatalogAdapter,
    MemoryStartCatalogState,
)
from finishup.adapters.sqlite.migrations import initialize_catalog
from finishup.adapters.sqlite.start_catalog import SqliteStartCatalog
from finishup.domain.privacy import LocalDisclosureSink
from finishup.ports.publish_response_catalog import PublishResponseKey, StoredPublishResponse
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id


class _Ids:
    def new(self, kind: IdKind) -> str:
        return new_id(kind)


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 7, 27, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 0.0


def _sqlite_catalog(db: apsw.Connection, installation_id: str) -> SqliteStartCatalog:
    return SqliteStartCatalog(
        db,
        installation_id=installation_id,
        lookup=object(),  # type: ignore[arg-type]
        clock=_Clock(),
        ids=_Ids(),
    )


def _response(key: PublishResponseKey, value: str) -> StoredPublishResponse:
    canonical = canonical_encode({"outcome": value})
    return StoredPublishResponse(
        key=key,
        result_canonical=canonical,
        result_digest=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
    )


def _seed_route(db: apsw.Connection, key: PublishResponseKey) -> None:
    route_digest = canonical_digest(
        {
            "task_id": key.task_id,
            "bundle_relpath": f"tasks/{key.task_id}",
            "route_generation": 1,
        }
    )
    db.execute(
        "INSERT INTO task_routes("
        "task_id,workspace_ref_commitment,external_ref_commitment,active_session_id,"
        "bundle_relpath,route_generation,active_route_identity_digest,state,quarantine_code,"
        "created_at,updated_at) VALUES(?,NULL,NULL,?,?,1,?,'active',NULL,?,?)",
        (
            key.task_id,
            key.session_id,
            f"tasks/{key.task_id}",
            route_digest,
            "2026-07-27T00:00:00.000Z",
            "2026-07-27T00:00:00.000Z",
        ),
    )


@pytest.mark.anyio
async def test_put_lookup_winner_and_identity_conflict_parity() -> None:
    installation_id = new_id(IdKind.INSTALLATION)
    state = MemoryStartCatalogState()
    memory = MemoryStartCatalogAdapter(
        installation_id=installation_id,
        lookup=object(),  # type: ignore[arg-type]
        state=state,
        transaction_lock=anyio.Lock(),
        clock=_Clock(),
        ids=_Ids(),
    )
    db = apsw.Connection(":memory:")
    initialize_catalog(db)
    sqlite = _sqlite_catalog(db, installation_id)
    key = PublishResponseKey(
        task_id=new_id(IdKind.TASK),
        session_id=new_id(IdKind.SESSION),
        writer_id=new_id(IdKind.WRITER),
        request_id=new_id(IdKind.REQUEST),
        request_digest="sha256:" + "1" * 64,
        sink=LocalDisclosureSink.AGENT_CONTEXT,
    )
    _seed_route(db, key)
    first = _response(key, "first")
    competing = _response(key, "competing")

    for catalog in (memory, sqlite):
        assert await catalog.lookup(key) is None
        assert await catalog.put_if_absent(first) == first
        assert await catalog.put_if_absent(competing) == first
        assert await catalog.lookup(key) == first

        conflicting_keys = (
            replace(key, task_id=new_id(IdKind.TASK)),
            replace(key, session_id=new_id(IdKind.SESSION)),
            replace(key, request_digest="sha256:" + "9" * 64),
        )
        for conflicting_key in conflicting_keys:
            with pytest.raises(PublicOperationError) as put_failure:
                await catalog.put_if_absent(_response(conflicting_key, "conflict"))
            assert put_failure.value.code is PublicErrorCode.STORAGE_CORRUPT
            with pytest.raises(PublicOperationError) as lookup_failure:
                await catalog.lookup(conflicting_key)
            assert lookup_failure.value.code is PublicErrorCode.STORAGE_CORRUPT


@pytest.mark.anyio
async def test_sqlite_response_survives_reopen(tmp_path: Path) -> None:
    path = tmp_path / "catalog.sqlite3"
    installation_id = new_id(IdKind.INSTALLATION)
    key = PublishResponseKey(
        task_id=new_id(IdKind.TASK),
        session_id=new_id(IdKind.SESSION),
        writer_id=new_id(IdKind.WRITER),
        request_id=new_id(IdKind.REQUEST),
        request_digest="sha256:" + "2" * 64,
        sink=LocalDisclosureSink.LOCAL_HUMAN_VIEW,
    )
    expected = _response(key, "durable")

    db = apsw.Connection(str(path))
    initialize_catalog(db)
    _seed_route(db, key)
    assert await _sqlite_catalog(db, installation_id).put_if_absent(expected) == expected
    db.close()

    reopened = apsw.Connection(str(path))
    try:
        assert await _sqlite_catalog(reopened, installation_id).lookup(key) == expected
    finally:
        reopened.close()


def test_stored_response_requires_canonical_bytes_and_matching_digest() -> None:
    key = PublishResponseKey(
        task_id=new_id(IdKind.TASK),
        session_id=new_id(IdKind.SESSION),
        writer_id=new_id(IdKind.WRITER),
        request_id=new_id(IdKind.REQUEST),
        request_digest="sha256:" + "3" * 64,
        sink=LocalDisclosureSink.AGENT_CONTEXT,
    )
    noncanonical = b'{"outcome": "spaced"}'
    with pytest.raises(ValueError, match="invalid_publish_response_catalog_value"):
        StoredPublishResponse(
            key,
            noncanonical,
            f"sha256:{hashlib.sha256(noncanonical).hexdigest()}",
        )
    with pytest.raises(ValueError, match="invalid_publish_response_catalog_value"):
        StoredPublishResponse(key, b'{"outcome":"valid"}', "sha256:" + "0" * 64)
