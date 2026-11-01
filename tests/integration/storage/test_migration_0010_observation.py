"""The binary can reopen the native-content consent schema it initializes."""

from pathlib import Path

import apsw
import pytest

from finishup.adapters.sqlite.connection import StorageUnsafeError, verify_schema_identity
from finishup.adapters.sqlite.migrations import initialize_bundle


def test_fresh_content_consent_bundle_reopens_but_future_schema_is_refused(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "bundle.sqlite3"
    db = apsw.Connection(str(path))
    try:
        initialize_bundle(
            db, {"task_id": "tsk_10000000-0000-4000-8000-000000000001", "protocol_version": "0.1"}
        )
    finally:
        db.close()
    reopened = apsw.Connection(str(path))
    try:
        identity = verify_schema_identity(reopened)
        assert identity.state == "current"
        columns = {row[1] for row in reopened.execute("PRAGMA table_info(observation_consent)")}
        assert "content_capture_profiles_json" in columns
        reopened.execute(f"PRAGMA user_version = {identity.user_version + 1}")
        with pytest.raises(StorageUnsafeError, match="schema_newer_than_binary"):
            verify_schema_identity(reopened)
    finally:
        reopened.close()
