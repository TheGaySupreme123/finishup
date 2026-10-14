"""Migration 0008 observation-content plaintext digest bindings."""

from __future__ import annotations

from pathlib import Path

import apsw
import pytest

from yoetz.adapters.sqlite.migrations import (
    BUNDLE_MIGRATIONS,
    current_schema_version,
    run_migrations,
)


def _schema_seven(path: Path) -> apsw.Connection:
    db = apsw.Connection(str(path))
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    with db:
        for migration in BUNDLE_MIGRATIONS[:7]:
            db.execute(migration.ddl.decode())
        db.execute(
            "INSERT INTO objects(object_id,kind,plaintext_size,commitment,envelope_digest,"
            "encryption_format,key_slot,state,durable_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "obj_00000000-0000-4000-8000-000000000801",
                "captured_content",
                32,
                "hmac-sha256:" + "1" * 64,
                "sha256:" + "2" * 64,
                "yoetz-object/1",
                "slot-1",
                "present",
                "2026-08-30T00:00:00.000Z",
            ),
        )
        db.execute(
            "INSERT INTO observation_content_manifests("
            "object_id,workspace_commitment,logical_identity,content_kind,"
            "correlation_identity,source_commitment,media_type,part_index,part_count,"
            "plaintext_size,content_commitment,redacted,recorded_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "obj_00000000-0000-4000-8000-000000000801",
                "hmac-sha256:" + "3" * 64,
                "sha256:" + "4" * 64,
                "tool_output",
                "call-801",
                "hmac-sha256:" + "5" * 64,
                "text/plain",
                0,
                1,
                32,
                "hmac-sha256:" + "1" * 64,
                0,
                "2026-08-30T00:00:00.000Z",
            ),
        )
        db.execute(
            "INSERT INTO observation_inspection_snapshots("
            "snapshot_id,workspace_commitment,yoetz_session_id,subject_state_digest,"
            "changed_paths_digest,relative_paths_json,facts_object_id,excerpt_object_id,"
            "is_current,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                "inspection-801",
                "hmac-sha256:" + "3" * 64,
                "ses_00000000-0000-4000-8000-000000000801",
                "sha256:" + "6" * 64,
                "sha256:" + "7" * 64,
                b'{"relative_paths":[]}',
                "obj_00000000-0000-4000-8000-000000000801",
                None,
                1,
                "2026-08-30T00:00:00.000Z",
            ),
        )
    return db


def test_schema_seven_upgrade_keeps_old_rows_weak_and_accepts_exact_bindings(
    tmp_path: Path,
) -> None:
    db = _schema_seven(tmp_path / "bundle.sqlite3")
    report = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    assert report.applied_versions == (
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
    assert db.execute("PRAGMA user_version").fetchone() == (
        current_schema_version(BUNDLE_MIGRATIONS),
    )
    assert db.execute(
        "SELECT content_digest,content_bytes FROM observation_content_manifests"
    ).fetchone() == (None, None)
    assert db.execute(
        "SELECT facts_content_digest,facts_content_bytes,excerpt_content_digest,"
        "excerpt_content_bytes,excerpt_redacted,excerpt_truncated "
        "FROM observation_inspection_snapshots"
    ).fetchone() == (None, None, None, None, 0, 0)

    digest = "sha256:" + "a" * 64
    with db:
        db.execute(
            "UPDATE observation_content_manifests SET content_digest=?,content_bytes=?",
            (digest, 31),
        )
        db.execute(
            "UPDATE observation_inspection_snapshots SET facts_content_digest=?,"
            "facts_content_bytes=?",
            (digest, 31),
        )
    assert db.execute(
        "SELECT content_digest,content_bytes FROM observation_content_manifests"
    ).fetchone() == (digest, 31)


@pytest.mark.parametrize(
    ("digest", "byte_count"),
    [
        ("sha256:" + "A" * 64, 1),
        ("sha256:" + "g" * 64, 1),
        ("sha256:" + "a" * 64, 0),
    ],
)
def test_schema_eight_rejects_noncanonical_content_bindings(
    tmp_path: Path, digest: str, byte_count: int
) -> None:
    db = _schema_seven(tmp_path / "bundle.sqlite3")
    run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    with pytest.raises(apsw.ConstraintError):
        with db:
            db.execute(
                "UPDATE observation_content_manifests SET content_digest=?,content_bytes=?",
                (digest, byte_count),
            )
