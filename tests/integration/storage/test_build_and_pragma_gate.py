from __future__ import annotations

import asyncio
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Literal, Protocol, cast

import apsw
import pytest

import finishup.adapters.sqlite.connection as connection_module
from finishup.adapters.sqlite.connection import (
    REQUIRED_APSW_VERSION,
    REQUIRED_SQLITE_SOURCE_ID,
    REQUIRED_SQLITE_VERSION,
    StorageUnsafeError,
    open_read_only,
    verify_sqlite_build,
)
from finishup.adapters.sqlite.migrations import BUNDLE_MIGRATIONS, initialize_bundle
from finishup.adapters.sqlite.observation import SqliteObservationStore
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestDisposition,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp


class _SupportPolicyFactory(Protocol):
    def __call__(
        self,
        *,
        manifest_id: str,
        required_options: frozenset[str],
        denied_options: frozenset[str],
    ) -> object: ...


class _SupportPolicyInstaller(Protocol):
    def __call__(self, policy: object | None) -> None: ...


def _policy_installer() -> _SupportPolicyInstaller:
    return cast(_SupportPolicyInstaller, getattr(connection_module, "_install_support_policy"))


def _open_unfenced_writer(path: Path) -> apsw.Connection:
    opener = cast(
        Callable[[Path], apsw.Connection],
        getattr(connection_module, "_open_recovery_writer"),
    )
    return opener(path)


def _actual_compile_options() -> frozenset[str]:
    database = apsw.Connection(":memory:")
    try:
        raw_options: object = database.pragma("compile_options")
    finally:
        database.close()
    assert type(raw_options) is list
    option_items = cast(list[object], raw_options)
    assert all(type(item) is str for item in option_items)
    return frozenset(cast(str, item) for item in option_items)


def _install_exact_test_policy() -> frozenset[str]:
    options = _actual_compile_options()
    factory = cast(
        _SupportPolicyFactory,
        getattr(connection_module, "_SqliteSupportPolicy"),
    )
    policy = factory(
        manifest_id="test-reviewed-runtime-support",
        required_options=options,
        denied_options=frozenset({"OMIT_FOREIGN_KEY", "OMIT_WAL", "THREADSAFE=0"}),
    )
    _policy_installer()(policy)
    return options


def _review_private_test_path(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    database: Path,
) -> list[Path]:
    root.chmod(0o700)
    observed: list[Path] = []

    def verify(path: Path) -> None:
        observed.append(path)
        if path == root:
            assert stat.S_IMODE(path.stat().st_mode) == 0o700
            return
        if path == database:
            if path.exists():
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
            return
        raise AssertionError("unexpected_storage_path")

    monkeypatch.setattr(connection_module, "verify_private_local_bundle", verify)
    return observed


@pytest.fixture(autouse=True)
def _reset_support_policy() -> Iterator[None]:  # pyright: ignore[reportUnusedFunction]
    installer = _policy_installer()
    installer(None)
    yield
    installer(None)


def test_certified_build_identity_is_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "certified.sqlite3"
    _review_private_test_path(monkeypatch, tmp_path, database_path)
    expected_options = _install_exact_test_policy()

    database = _open_unfenced_writer(database_path)
    try:
        report = verify_sqlite_build(database)
    finally:
        database.close()

    assert report.apsw_version == REQUIRED_APSW_VERSION
    assert report.sqlite_version == REQUIRED_SQLITE_VERSION
    assert report.source_id == REQUIRED_SQLITE_SOURCE_ID
    assert report.compile_options == tuple(sorted(expected_options, key=str.encode))
    assert report.manifest_id == "test-reviewed-runtime-support"


@pytest.mark.parametrize("mismatch", ("sqlite_version", "source_id", "amalgamation"))
def test_wrong_build_identity_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: Literal["sqlite_version", "source_id", "amalgamation"],
) -> None:
    database_path = tmp_path / f"wrong-{mismatch}.sqlite3"
    _review_private_test_path(monkeypatch, tmp_path, database_path)
    _install_exact_test_policy()

    expected_reason: str
    if mismatch == "sqlite_version":
        monkeypatch.setattr(connection_module, "REQUIRED_SQLITE_VERSION", "0.0.0")
        expected_reason = "sqlite_version_mismatch"
    elif mismatch == "source_id":
        monkeypatch.setattr(connection_module, "REQUIRED_SQLITE_SOURCE_ID", "unsupported-source")
        expected_reason = "sqlite_source_id_mismatch"
    else:
        monkeypatch.setattr(apsw, "using_amalgamation", False)
        expected_reason = "not_amalgamation"

    with pytest.raises(StorageUnsafeError, match=expected_reason) as captured:
        _open_unfenced_writer(database_path)
    assert captured.value.reason_code == expected_reason

    inspection = apsw.Connection(str(database_path), flags=apsw.SQLITE_OPEN_READONLY)
    try:
        assert (
            inspection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            == []
        )
    finally:
        inspection.close()


def test_pragma_state_matches_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "pragma-contract.sqlite3"
    observed_paths = _review_private_test_path(monkeypatch, tmp_path, database_path)
    _install_exact_test_policy()

    database = _open_unfenced_writer(database_path)
    try:
        assert observed_paths == [tmp_path, database_path]
        assert stat.S_IMODE(database_path.stat().st_mode) == 0o600
        authorizer: object = database.authorizer
        assert callable(authorizer)
        with pytest.raises(apsw.AuthError):
            database.execute("ATTACH DATABASE ':memory:' AS forbidden")
        with pytest.raises(apsw.SQLError, match="not authorized to use function"):
            database.execute("SELECT load_extension('forbidden')").fetchall()
        database.execute("PRAGMA defer_foreign_keys=ON")
        assert database.pragma("defer_foreign_keys") == 1
        with pytest.raises(apsw.AuthError):
            database.execute("PRAGMA writable_schema=ON")

        database.set_authorizer(None)
        try:
            assert database.pragma("foreign_keys") == 1
            assert database.pragma("trusted_schema") == 0
            assert database.pragma("temp_store") == 2
            assert database.pragma("journal_mode") == "wal"
            assert database.pragma("synchronous") == 2
            assert database.pragma("wal_autocheckpoint") == 0
            assert database.pragma("mmap_size") == 0
        finally:
            database.set_authorizer(cast(Callable[..., int], authorizer))
    finally:
        database.close()


@pytest.mark.parametrize(
    ("source", "profiles"),
    [
        (ObservationSource.CODEX_HOOK, ()),
        (ObservationSource.CLAUDE_HOOK, ("claude-code-ordinary-observation-v1",)),
        (ObservationSource.CURSOR_HOOK, ("cursor-ordinary-observation-v1",)),
    ],
)
def test_observation_ingest_uses_production_writer_and_read_only_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: ObservationSource,
    profiles: tuple[str, ...],
) -> None:
    """#616: fresh guarded bundles accept all hosts and reopen their consent."""

    path = tmp_path / "observation.sqlite3"
    _review_private_test_path(monkeypatch, tmp_path, path)
    _install_exact_test_policy()
    workspace = "hmac-sha256:" + "1" * 64
    session = "hmac-sha256:" + "2" * 64
    timestamp = Timestamp("2026-09-06T00:00:00.000Z")
    envelope = ObservationEnvelope(
        session_commitment=session,
        event_kind="PostToolUse",
        source_identity="hook:production-writer",
        source=source,
        cursor=ObservationCursor(1, 1, 1, "hmac-sha256:" + "3" * 64, "obs-guard/1"),
        receipt_time=timestamp,
        structural_payload=JsonObject({"tool_name": "shell", "exit_status": 0}),
        content_object_refs=(),
        gap_codes=(),
    )
    database = _open_unfenced_writer(path)
    try:
        initialize_bundle(database, {"task_id": "task_obs", "protocol_version": "0.1"})
        store = SqliteObservationStore(database)
        store.grant_consent(workspace, timestamp, content_capture_profiles=profiles)
        store.bind_session(workspace, session)
        assert (
            asyncio.run(store.ingest(envelope)).disposition is ObservationIngestDisposition.ACCEPTED
        )
        assert (
            asyncio.run(store.ingest(envelope)).disposition
            is ObservationIngestDisposition.DUPLICATE
        )
        assert len(store.list_envelopes(workspace)) == 1
        for statement in (
            "PRAGMA table_info(bundle_meta)",
            "PRAGMA table_info",
            "PRAGMA writable_schema=ON",
        ):
            with pytest.raises(apsw.AuthError):
                database.execute(statement).fetchall()
    finally:
        database.close()

    inspection = open_read_only(path)
    try:
        assert SqliteObservationStore(inspection).content_capture_profiles(workspace) == profiles
        with pytest.raises(apsw.AuthError):
            inspection.execute("PRAGMA table_info(bundle_meta)").fetchall()
        with pytest.raises(apsw.AuthError):
            inspection.execute("DELETE FROM observation_consent")
    finally:
        inspection.close()


def test_read_only_inspection_does_not_promote_write_safety(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "inspection-only.sqlite3"
    observed_paths = _review_private_test_path(monkeypatch, tmp_path, database_path)
    seed = apsw.Connection(str(database_path))
    seed.close()
    database_path.chmod(0o600)

    with pytest.warns(RuntimeWarning, match="sqlite_build_unsupported"):
        inspection = connection_module.open_read_only(database_path)
    try:
        assert inspection.execute("SELECT count(*) FROM sqlite_schema").fetchone() == (0,)
        with pytest.raises(apsw.AuthError):
            inspection.execute("CREATE TABLE forbidden(value TEXT)")
    finally:
        inspection.close()

    with pytest.raises(StorageUnsafeError, match="compile_options_mismatch") as captured:
        _open_unfenced_writer(database_path)
    assert captured.value.reason_code == "compile_options_mismatch"
    assert observed_paths == [tmp_path, database_path, tmp_path, database_path]


def test_read_only_legacy_bundle_allows_structural_consent_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pre-0010 bundles keep structural consent readable through the guarded RO path."""

    database_path = tmp_path / "legacy-observation.sqlite3"
    _review_private_test_path(monkeypatch, tmp_path, database_path)
    _install_exact_test_policy()

    database = _open_unfenced_writer(database_path)
    try:
        # Build a real supported older bundle instead of inventing a native-profile schema.
        with database:
            for migration in BUNDLE_MIGRATIONS[:9]:
                database.execute(migration.ddl.decode("utf-8"))
            database.executemany(
                "INSERT INTO bundle_meta(key, value) VALUES (?, ?)",
                (
                    ("import_schema_version", "1"),
                    ("protocol_version", "0.1"),
                    ("storage_schema_version", "9"),
                    ("task_id", "task_legacy"),
                    ("owner_generation", "1"),
                    ("owner_nonce", "nonce_value_123456"),
                ),
            )
            database.execute(
                "INSERT INTO observation_consent(workspace_commitment, granted_at, revoked_at, paused) "
                "VALUES (?, ?, NULL, 0)",
                ("hmac-sha256:" + "a" * 64, "2026-09-06T00:00:00.000Z"),
            )
        assert database.pragma("user_version") == 9
    finally:
        database.close(force=True)

    inspection = open_read_only(database_path)
    try:
        workspace = "hmac-sha256:" + "a" * 64
        assert SqliteObservationStore(inspection).content_capture_profiles(workspace) == ()
        with pytest.raises(apsw.AuthError):
            inspection.execute("PRAGMA table_info(bundle_meta)").fetchall()
        with pytest.raises(apsw.AuthError):
            inspection.execute("PRAGMA writable_schema=ON")
    finally:
        inspection.close(force=True)
