"""Migration 0002 observation tables: forward migrate and backward-read of v1 DBs."""

from __future__ import annotations

import apsw

from yoetz.adapters.sqlite.migrations import (
    BUNDLE_MIGRATIONS,
    current_schema_version,
    initialize_bundle,
    run_migrations,
)
from yoetz.adapters.sqlite.observation import SqliteObservationStore
from yoetz.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestDisposition,
    ObservationSource,
    ObservationStatusQuery,
)
from yoetz.domain.values import JsonObject, Timestamp

_WORKSPACE = "hmac-sha256:" + "a" * 64
_SESSION = "hmac-sha256:" + "b" * 64
_SOURCE = "hmac-sha256:" + "c" * 64
_TIME = Timestamp("2026-07-22T22:00:00.000Z")


def test_forward_migrate_0001_to_0002_then_observation_ingest() -> None:
    bundle = apsw.Connection(":memory:")
    bundle.execute("PRAGMA foreign_keys = ON")
    bundle.execute("PRAGMA trusted_schema = OFF")
    ddl = BUNDLE_MIGRATIONS[0].ddl.decode("utf-8")
    with bundle:
        bundle.execute(ddl)
        bundle.execute(
            "INSERT INTO bundle_meta(key, value) VALUES "
            "('task_id', 'task_test'), "
            "('owner_generation', '1'), "
            "('storage_schema_version', '1'), "
            "('protocol_version', '0.1'), "
            "('import_schema_version', '1')"
        )
        bundle.execute("INSERT INTO counters(name, next_value) VALUES ('ingestion_sequence', 1)")
    assert bundle.execute("PRAGMA user_version").fetchone() == (1,)
    # Pre-0002: observation tables absent; ledger tables remain readable.
    assert (
        bundle.execute("SELECT 1 FROM sqlite_schema WHERE name = 'events'").fetchone() is not None
    )
    assert (
        bundle.execute("SELECT 1 FROM sqlite_schema WHERE name = 'observation_consent'").fetchone()
        is None
    )

    report = run_migrations(bundle, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert report.applied_versions == (
        "0002",
        "0003",
        "0004",
        "0005",
        "0006",
        "0007",
        "0008",
        "0009",
        "0010",
        "0011",
        "0012",
        "0013",
        "0014",
        "0015",
        "0016",
    )
    assert report.applied_versions == tuple(item.version for item in BUNDLE_MIGRATIONS[1:])
    assert bundle.execute("PRAGMA user_version").fetchone() == (
        current_schema_version(BUNDLE_MIGRATIONS),
    )
    for table in (
        "observation_consent",
        "observation_cursors",
        "observation_dedup",
        "observation_events",
        "observation_advice",
    ):
        assert bundle.execute(
            "SELECT 1 FROM sqlite_schema WHERE name = ?", (table,)
        ).fetchone() == (1,)
    # Old ledger tables still present (backward-read of pre-observation data).
    assert bundle.execute("SELECT 1 FROM sqlite_schema WHERE name = 'events'").fetchone() == (1,)

    store = SqliteObservationStore(bundle)

    async def _ingest() -> ObservationIngestDisposition:
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)
        result = await store.ingest(
            ObservationEnvelope(
                session_commitment=_SESSION,
                event_kind="PostToolUse",
                source_identity="hook:migrated",
                source=ObservationSource.CODEX_HOOK,
                cursor=ObservationCursor(
                    source_generation=1,
                    byte_position=8,
                    event_position=1,
                    last_source_commitment=_SOURCE,
                    mapping_version="codex-obs-hook/1.0.0",
                ),
                receipt_time=_TIME,
                structural_payload=JsonObject({"tool_name": "shell", "exit_status": 0}),
                content_object_refs=(),
                gap_codes=(),
            )
        )
        return result.disposition

    import asyncio

    assert asyncio.run(_ingest()) is ObservationIngestDisposition.ACCEPTED
    status = asyncio.run(store.status(ObservationStatusQuery(_WORKSPACE)))
    assert status.source_coverage[ObservationSource.CODEX_HOOK] is True


def test_fresh_initialize_includes_0002_and_reads_empty_observation() -> None:
    bundle = apsw.Connection(":memory:")
    initialize_bundle(bundle, {"task_id": "fresh", "owner_generation": "1"})
    assert bundle.execute("PRAGMA user_version").fetchone() == (
        current_schema_version(BUNDLE_MIGRATIONS),
    )
    store = SqliteObservationStore(bundle)
    import asyncio

    status = asyncio.run(store.status(ObservationStatusQuery(_WORKSPACE)))
    assert status.lifecycle.value == "stopped"
    assert status.gaps == ()
