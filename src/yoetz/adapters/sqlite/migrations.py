"""Frozen SQLite migration registries and fresh-database initialization."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from time import monotonic_ns
from typing import TYPE_CHECKING, Final, cast

import apsw

from yoetz.adapters.sqlite.connection import (  # pyright: ignore[reportPrivateUsage]
    _migration_authorizer,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from yoetz.ports.maintenance import MaintenanceHandle

YOETZ_APPLICATION_ID: Final = 0x594F4554
EMPTY_PROJECTION_DIGEST: Final = (
    "sha256:0f8ec0c66f196bee631ef5447ef5c914e812fe530ee1f4b7477e24b22a9911c9"
)


@dataclass(frozen=True, slots=True)
class Migration:
    """One immutable numbered migration loaded from installed resources."""

    version: str
    ddl: bytes

    def __post_init__(self) -> None:
        if len(self.version) != 4 or not self.version.isascii() or not self.version.isdigit():
            raise ValueError("migration_version_invalid")
        _validate_ddl_bytes(self.ddl)


@dataclass(frozen=True, slots=True)
class MigrationReport:
    """Bounded structural result of a migration registry check or application."""

    from_version: int
    to_version: int
    applied_versions: tuple[str, ...]
    backup_manifest_digest: str | None
    duration_ms: int


def _validate_ddl_bytes(value: bytes) -> None:
    if value.startswith(b"\xef\xbb\xbf"):
        raise ValueError("migration_bom_forbidden")
    if b"\r" in value:
        raise ValueError("migration_line_ending_invalid")
    if not value.endswith(b"\n") or value.endswith(b"\n\n"):
        raise ValueError("migration_final_lf_invalid")
    try:
        value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("migration_utf8_invalid") from error


def _load_resource(family: str, version: str) -> bytes:
    target = resources.files("yoetz").joinpath("resources", "migrations", family, f"{version}.sql")
    value = target.read_bytes()
    _validate_ddl_bytes(value)
    return value


CATALOG_MIGRATIONS: Final[tuple[Migration, ...]] = (
    Migration("0001", _load_resource("catalog", "0001")),
    Migration("0002", _load_resource("catalog", "0002")),
    Migration("0003", _load_resource("catalog", "0003")),
    Migration("0004", _load_resource("catalog", "0004")),
    Migration("0005", _load_resource("catalog", "0005")),
)
BUNDLE_MIGRATIONS: Final[tuple[Migration, ...]] = (
    Migration("0001", _load_resource("bundle", "0001")),
    Migration("0002", _load_resource("bundle", "0002")),
    Migration("0003", _load_resource("bundle", "0003")),
    Migration("0004", _load_resource("bundle", "0004")),
    Migration("0005", _load_resource("bundle", "0005")),
    Migration("0006", _load_resource("bundle", "0006")),
    Migration("0007", _load_resource("bundle", "0007")),
    Migration("0008", _load_resource("bundle", "0008")),
    Migration("0009", _load_resource("bundle", "0009")),
    Migration("0010", _load_resource("bundle", "0010")),
    Migration("0011", _load_resource("bundle", "0011")),
    Migration("0012", _load_resource("bundle", "0012")),
    Migration("0013", _load_resource("bundle", "0013")),
    Migration("0014", _load_resource("bundle", "0014")),
    Migration("0015", _load_resource("bundle", "0015")),
    Migration("0016", _load_resource("bundle", "0016")),
)


def _validate_registry(registry: Sequence[Migration]) -> None:
    if not registry:
        raise ValueError("migration_registry_empty")
    expected = 1
    seen: set[str] = set()
    for migration in registry:
        if migration.version in seen:
            raise ValueError("migration_version_duplicate")
        if int(migration.version) != expected:
            raise ValueError("migration_version_noncontiguous")
        seen.add(migration.version)
        expected += 1


_validate_registry(CATALOG_MIGRATIONS)
_validate_registry(BUNDLE_MIGRATIONS)


def current_schema_version(registry: Sequence[Migration]) -> int:
    """Return the positive current version after validating registry continuity."""

    _validate_registry(registry)
    return int(registry[-1].version)


def _pragma_int(db: apsw.Connection, name: str) -> int:
    row = db.execute(f"PRAGMA {name}").fetchone()
    if row is None or type(row[0]) is not int:
        raise RuntimeError("schema_pragma_invalid")
    return row[0]


def _require_fresh(db: apsw.Connection) -> None:
    if _pragma_int(db, "user_version") != 0:
        raise RuntimeError("schema_already_initialized")
    row = db.execute(
        "SELECT 1 FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'index', 'view', 'trigger') LIMIT 1"
    ).fetchone()
    if row is not None:
        raise RuntimeError("schema_objects_preexisting")


def _configure_schema_connection(db: apsw.Connection) -> None:
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    if _pragma_int(db, "foreign_keys") != 1 or _pragma_int(db, "trusted_schema") != 0:
        raise RuntimeError("schema_security_pragma_mismatch")


def _execute(db: apsw.Connection, migration: Migration) -> None:
    db.execute(migration.ddl.decode("utf-8"))


@contextmanager
def _migration_authorization_window(db: apsw.Connection):
    """Temporarily grant migration DDL PRAGMAs, then restore runtime write policy."""

    previous_authorizer = db.authorizer
    db.set_authorizer(_migration_authorizer)
    try:
        yield
    finally:
        db.set_authorizer(previous_authorizer)


def _requires_foreign_keys_disabled(pending: Sequence[Migration]) -> bool:
    """Return whether pending migrations include a dependent-table rebuild."""

    return any(item.version in {"0014", "0016"} for item in pending)


def _validate_v10_bundle_layout(
    db: apsw.Connection,
    current: int,
    pending: Sequence[Migration],
) -> None:
    """Refuse ambiguous pre-refresh bundles before any upgrade writes.

    Released v0.2 v10 has the native-content consent column and the original events CHECK.
    The short-lived 0.3 development v10 used the same user_version for its events CHECK
    rebuild and therefore lacks that consent column.  There is no safe way to infer whether
    that development schema has user data that can be replayed into the released frontier.
    Only the released layout may continue through 0011-0014; every other combination fails
    closed before opening a migration transaction.
    """

    if current not in {10, 11, 12, 13} or not any(item.version == "0014" for item in pending):
        return
    profile_columns = {
        cast(str, row[1])
        for row in db.execute("PRAGMA table_info(observation_consent)")
        if len(row) > 1 and type(row[1]) is str
    }
    event_row = db.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'events'"
    ).fetchone()
    event_sql = event_row[0].casefold() if event_row and type(event_row[0]) is str else ""
    has_content_profiles = "content_capture_profiles_json" in profile_columns
    has_lineage_summary = "delegation_declared" in event_sql
    required_v12_tables: set[str] = {"observation_capture_tickets"} if current >= 11 else set()
    if current >= 12:
        required_v12_tables.add("observation_advice_semantic_attempts")
    tables = {
        cast(str, row[0])
        for row in db.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        if len(row) == 1 and type(row[0]) is str
    }
    usage_columns = {
        cast(str, row[1]) for row in db.execute("PRAGMA table_info(semantic_attempts)")
    }
    required_usage_columns = {
        "usage_input_tokens",
        "usage_cached_input_tokens",
        "usage_cache_write_input_tokens",
        "usage_output_tokens",
        "usage_reasoning_output_tokens",
        "usage_total_tokens",
    }
    usage_layout_valid = current < 13 or required_usage_columns <= usage_columns
    if (
        has_content_profiles
        and not has_lineage_summary
        and required_v12_tables <= tables
        and usage_layout_valid
    ):
        return
    raise RuntimeError("schema_upgrade_path_unknown")


def _set_event_summary_rebuild_mode(db: apsw.Connection) -> None:
    """Permit the append-only events rebuild while preserving child-table references."""

    # foreign_keys is a connection setting and must be changed outside a transaction.
    # legacy_alter_table keeps REFERENCES events clauses unchanged while the old table is
    # renamed and replaced.  Both settings are restored by the matching helper below.
    if db.get_autocommit() is False:
        raise RuntimeError("schema_rebuild_transaction_active")
    foreign_keys_disabled = False
    legacy_alter_enabled = False
    try:
        db.execute("PRAGMA foreign_keys = OFF")
        foreign_keys_disabled = True
        db.execute("PRAGMA legacy_alter_table = ON")
        legacy_alter_enabled = True
        if _pragma_int(db, "foreign_keys") != 0 or _pragma_int(db, "legacy_alter_table") != 1:
            raise RuntimeError("schema_rebuild_pragma_mismatch")
    except BaseException:
        if legacy_alter_enabled:
            db.execute("PRAGMA legacy_alter_table = OFF")
        if foreign_keys_disabled:
            db.execute("PRAGMA foreign_keys = ON")
        raise


def _clear_event_summary_rebuild_mode(db: apsw.Connection) -> None:
    """Restore the reviewed schema connection settings after an events rebuild."""

    db.execute("PRAGMA legacy_alter_table = OFF")
    db.execute("PRAGMA foreign_keys = ON")
    if _pragma_int(db, "foreign_keys") != 1 or _pragma_int(db, "legacy_alter_table") != 0:
        raise RuntimeError("schema_rebuild_pragma_mismatch")


def _verify_identity(db: apsw.Connection, expected_version: int) -> None:
    if _pragma_int(db, "foreign_keys") != 1 or _pragma_int(db, "trusted_schema") != 0:
        raise RuntimeError("schema_security_pragma_mismatch")
    if _pragma_int(db, "application_id") != YOETZ_APPLICATION_ID:
        raise RuntimeError("schema_application_id_mismatch")
    if _pragma_int(db, "user_version") != expected_version:
        raise RuntimeError("schema_user_version_mismatch")
    violations = db.execute("PRAGMA foreign_key_check").fetchone()
    if violations is not None:
        raise RuntimeError("schema_foreign_key_violation")


def initialize_catalog(db: apsw.Connection) -> None:
    """Install the standalone catalog migration on a fresh staged database."""

    _configure_schema_connection(db)
    _require_fresh(db)
    with db:
        for migration in CATALOG_MIGRATIONS:
            _execute(db, migration)
    _verify_identity(db, current_schema_version(CATALOG_MIGRATIONS))


def initialize_bundle(db: apsw.Connection, bundle_meta_seed: Mapping[str, str]) -> None:
    """Install and seed the standalone task-bundle migration atomically."""

    _configure_schema_connection(db)
    _require_fresh(db)
    seed = dict(bundle_meta_seed)
    if any(type(key) is not str or type(value) is not str for key, value in seed.items()):
        raise ValueError("bundle_meta_seed_invalid")
    if "import_schema_version" in seed and seed["import_schema_version"] != "1":
        raise ValueError("import_schema_version_mismatch")
    seed["import_schema_version"] = "1"
    target_version = current_schema_version(BUNDLE_MIGRATIONS)
    seed["storage_schema_version"] = str(target_version)

    # Fresh installation has no dependent event rows, but 0014 still uses the same narrowly
    # scoped migration authorization window as an upgrade.  The runtime writer authorizer is
    # restored before this function returns.
    with _migration_authorization_window(db):
        with db:
            for migration in BUNDLE_MIGRATIONS:
                _execute(db, migration)
            db.executemany(
                "INSERT INTO bundle_meta(key, value) VALUES (?, ?)",
                sorted(seed.items()),
            )
            db.execute("INSERT INTO counters(name, next_value) VALUES ('ingestion_sequence', 1)")
            db.execute(
                "INSERT INTO projection_state("
                "projection_name, projection_version, projection_generation, "
                "applied_through_seq, state_digest, engine_version"
                ") VALUES ('work', 'yoetz/0.1.0', 1, 0, ?, '0.1.0')",
                (EMPTY_PROJECTION_DIGEST,),
            )
            db.execute(
                "INSERT INTO p1_projection_state("
                "projection_name, frontier_seq, head_digest, "
                "task_title_source_event_id, current_plan_source_event_id, "
                "open_obligation_count, unresolved_finding_count, "
                "status_coverage_canonical, status_gap_codes_canonical, "
                "latest_check_event_id, latest_subject_frontier_seq, "
                "latest_subject_frontier_digest, latest_verdict, "
                "latest_returned_finding_ids, latest_suppressed_count, "
                "latest_coverage_canonical, freshness, unknown_event_count"
                ") VALUES ("
                "'work', 0, 'genesis', NULL, NULL, 0, 0, NULL, NULL, "
                "NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'unknown', 0"
                ")"
            )
            db.execute(
                "INSERT INTO p1_query_snapshots("
                "valid_from_seq, valid_to_seq, head_digest, "
                "task_title_source_event_id, current_plan_source_event_id, "
                "open_obligation_count, unresolved_finding_count, freshness, "
                "coverage_canonical, gap_codes_canonical"
                ") VALUES (0, NULL, 'genesis', NULL, NULL, 0, 0, 'unknown', NULL, NULL)"
            )
    _verify_identity(db, current_schema_version(BUNDLE_MIGRATIONS))


def run_migrations(
    db: apsw.Connection,
    registry: Sequence[Migration],
    *,
    maintenance: MaintenanceHandle | None,
) -> MigrationReport:
    """Return the bounded migration result for an already initialized database."""

    del maintenance
    started = monotonic_ns()
    _configure_schema_connection(db)
    target = current_schema_version(registry)
    current = _pragma_int(db, "user_version")
    if current == 0:
        raise RuntimeError("schema_initialization_required")
    if current > target:
        raise RuntimeError("schema_newer_than_binary")
    applied: list[str] = []
    if current < target:
        pending = tuple(item for item in registry if int(item.version) > current)
        if not pending or int(pending[0].version) != current + 1:
            raise RuntimeError("schema_version_unknown")
        _validate_v10_bundle_layout(db, current, pending)
        rebuild_mode = _requires_foreign_keys_disabled(pending)
        with _migration_authorization_window(db):
            if rebuild_mode:
                _set_event_summary_rebuild_mode(db)
            try:
                with db:
                    for migration in pending:
                        _execute(db, migration)
                        applied.append(migration.version)
                    tables = {
                        cast(str, row[0])
                        for row in db.execute(
                            "SELECT name FROM sqlite_schema "
                            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                        )
                    }
                    if "bundle_meta" in tables:
                        db.execute(
                            "INSERT INTO bundle_meta(key, value) VALUES('storage_schema_version', ?) "
                            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                            (str(target),),
                        )
                    elif "catalog_meta" in tables:
                        db.execute(
                            "INSERT INTO catalog_meta(key, value) VALUES('storage_schema_version', ?) "
                            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                            (str(target),),
                        )
            finally:
                if rebuild_mode:
                    _clear_event_summary_rebuild_mode(db)
        current = _pragma_int(db, "user_version")
    _verify_identity(db, target)
    elapsed_ms = max(0, (monotonic_ns() - started) // 1_000_000)
    return MigrationReport(
        from_version=current if not applied else int(applied[0]) - 1,
        to_version=target,
        applied_versions=tuple(applied),
        backup_manifest_digest=None,
        duration_ms=elapsed_ms,
    )


__all__ = [
    "BUNDLE_MIGRATIONS",
    "CATALOG_MIGRATIONS",
    "Migration",
    "MigrationReport",
    "current_schema_version",
    "initialize_bundle",
    "initialize_catalog",
    "run_migrations",
]
