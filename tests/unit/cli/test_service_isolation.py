"""Connection-free isolation proof for the dogfood preflight (issues #518, #567).

The report must prove — with path-identity digests over canonical resolved paths, never raw
paths — which identity roots this exact environment would use, so a parity preflight can reject
shared, ambient, or unprovable FinishUP service/state identity before any launch. Path identity is
not byte content: only the opt-in content lane binds the selected config's bytes, and it records
SHA-256, size, existence, and observation time only.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import cast, get_args

import pytest
from typer.testing import CliRunner

import finishup.cli.app as cli
import finishup.cli.isolation_status as module
from finishup.cli.isolation_status import isolation_report, observe_file_content
from finishup.config.installation import ReportedLifecycle
from finishup.config.models import ConfigError
from finishup.config.paths import (
    ISOLATED_ROOT_ENV,
    LEGACY_ISOLATED_ROOT_ENV,
    IsolationBinding,
    PathSafetyError,
)
from finishup.protocol.canonical import JsonValue
from finishup.protocol.isolation_report import IsolationReportContract
from finishup.protocol.schemas import validate_schema_instance

_PATH_KEYS = (
    "state_path_digest",
    "endpoint_path_digest",
    "storage_path_digest",
    "config_path_digest",
)
_NOW = datetime(2026, 9, 22, 12, 0, 0, 123_000, tzinfo=UTC)
_SECRET = b'[secret]\ntoken = "never-in-a-report"\n'


@pytest.fixture
def private_root() -> Iterator[Path]:
    root = Path(tempfile.mkdtemp(prefix=".yz-isolation-test-", dir=Path.home()))
    root.chmod(0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _scrub_finishup_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in [name for name in os.environ if name.startswith(("FINISHUP_", "YOETZ_"))]:
        monkeypatch.delenv(name, raising=False)


def _expected_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(str(path.resolve(strict=False)).encode("utf-8")).hexdigest()


def _bytes_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _observe(path: Path) -> dict[str, object]:
    return dict(observe_file_content(path, now=lambda: _NOW))


def test_ambient_mode_reports_the_exact_platform_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub_finishup_env(monkeypatch)
    # A hermetic explicit config keeps the probe away from the live user config file.
    monkeypatch.setenv("FINISHUP_CONFIG", str(tmp_path / "missing.toml"))

    report = isolation_report()

    assert report["schema"] == "yoetz.isolation-report/1"
    assert report["mode"] == "ambient"
    assert set(report["path_identity"]) == {*_PATH_KEYS, "executable_path_digest"}
    # Path identity only unless the content lane is requested.
    assert report["config_content"] is None
    validate_schema_instance("isolation-report", "1.0.0", cast(JsonValue, dict(report)))


def test_isolated_mode_reports_every_identity_beneath_the_exact_root(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub_finishup_env(monkeypatch)
    root = private_root / "iso"
    root.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(root))

    report = isolation_report()

    assert report["mode"] == "isolated"
    identity = report["path_identity"]
    assert identity["state_path_digest"] == _expected_digest(root / "state")
    assert identity["endpoint_path_digest"] == _expected_digest(root / "run")
    assert identity["storage_path_digest"] == _expected_digest(root / "data")
    assert identity["config_path_digest"] == _expected_digest(root / "config" / "config.toml")
    # Digest-only privacy boundary: no raw path may appear anywhere in the report.
    assert str(root) not in repr(report)


def test_the_legacy_root_and_config_spellings_select_the_same_identities(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``YOETZ_ISOLATED_ROOT`` and ``YOETZ_CONFIG`` still select their targets (ADR-048)."""

    _scrub_finishup_env(monkeypatch)
    root = private_root / "iso"
    root.mkdir(mode=0o700)
    config = private_root / "legacy.toml"
    monkeypatch.setenv(LEGACY_ISOLATED_ROOT_ENV, str(root))
    monkeypatch.setenv("YOETZ_CONFIG", str(config))

    report = isolation_report()

    assert report["mode"] == "isolated"
    assert report["binding"] == "environment"
    assert report["path_identity"]["state_path_digest"] == _expected_digest(root / "state")
    assert report["path_identity"]["config_path_digest"] == _expected_digest(config)


def test_conflicting_config_spellings_are_unprovable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub_finishup_env(monkeypatch)
    monkeypatch.setenv("FINISHUP_CONFIG", str(tmp_path / "new.toml"))
    monkeypatch.setenv("YOETZ_CONFIG", str(tmp_path / "old.toml"))

    with pytest.raises(ConfigError) as caught:
        isolation_report()
    assert caught.value.reason_code == "config_env_conflict"


def test_conflicting_root_spellings_are_unprovable(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub_finishup_env(monkeypatch)
    for name, leaf in ((ISOLATED_ROOT_ENV, "new"), (LEGACY_ISOLATED_ROOT_ENV, "old")):
        (private_root / leaf).mkdir(mode=0o700)
        monkeypatch.setenv(name, str(private_root / leaf))

    with pytest.raises(PathSafetyError) as caught:
        isolation_report()
    assert caught.value.reason_code == "isolation_root_env_conflict"


def test_two_target_reports_expose_shared_relocated_storage(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact normal target, not platform defaults, supplies the comparison identity."""

    _scrub_finishup_env(monkeypatch)
    relocated = private_root / "relocated-data"
    relocated.mkdir(mode=0o700)
    monkeypatch.setenv("FINISHUP_STORAGE_DATA_DIR", str(relocated))

    normal = isolation_report()

    root = private_root / "iso"
    root.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(root))
    isolated = isolation_report()

    assert normal["mode"] == "ambient"
    assert isolated["mode"] == "isolated"
    assert (
        isolated["path_identity"]["storage_path_digest"]
        == normal["path_identity"]["storage_path_digest"]
    )


def test_unusable_root_is_unprovable_never_ambient(monkeypatch: pytest.MonkeyPatch) -> None:
    _scrub_finishup_env(monkeypatch)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, "relative/never-valid")

    with pytest.raises(PathSafetyError) as caught:
        isolation_report()
    assert caught.value.reason_code == "isolation_root_invalid"


def test_path_stable_config_edit_changes_content_not_path_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The #567 confusion: an in-place edit is invisible to ``config_path_digest``."""

    _scrub_finishup_env(monkeypatch)
    config = tmp_path / "config.toml"
    config.write_bytes(_SECRET)
    monkeypatch.setenv("FINISHUP_CONFIG", str(config))

    before = isolation_report(content=True, now=lambda: _NOW)
    config.write_bytes(_SECRET + b"# edited\n")
    after = isolation_report(content=True, now=lambda: _NOW)

    assert before["path_identity"] == after["path_identity"]
    before_content = before["config_content"]
    after_content = after["config_content"]
    assert before_content is not None and after_content is not None
    assert before_content == {
        "path_digest": _expected_digest(config),
        "presence": "present",
        "content_digest": _bytes_digest(_SECRET),
        "size_bytes": len(_SECRET),
        "observed_at": "2026-09-22T12:00:00.123Z",
    }
    assert before_content["path_digest"] == before["path_identity"]["config_path_digest"]
    assert after_content["content_digest"] != before_content["content_digest"]
    for report in (before, after):
        validate_schema_instance("isolation-report", "1.0.0", cast(JsonValue, dict(report)))
        rendered = json.dumps(report)
        # Privacy-safe rendering: neither the config bytes nor its path are ever published.
        assert "never-in-a-report" not in rendered
        assert str(config) not in rendered


def test_absent_config_is_observed_without_a_byte_digest(tmp_path: Path) -> None:
    observation = _observe(tmp_path / "missing.toml")

    assert observation["presence"] == "absent"
    assert observation["content_digest"] is None
    assert observation["size_bytes"] is None
    assert observation["path_digest"] == _expected_digest(tmp_path / "missing.toml")


def test_empty_file_is_present_with_the_empty_digest(tmp_path: Path) -> None:
    path = tmp_path / "empty.toml"
    path.write_bytes(b"")

    observation = _observe(path)

    assert observation["presence"] == "present"
    assert observation["content_digest"] == _bytes_digest(b"")
    assert observation["size_bytes"] == 0


def test_atomic_replacement_keeps_path_identity_and_binds_the_new_bytes(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(_SECRET)
    first = _observe(path)

    staged = tmp_path / "config.toml.tmp"
    staged.write_bytes(_SECRET)
    os.replace(staged, path)
    identical = _observe(path)

    staged.write_bytes(b"replaced = true\n")
    os.replace(staged, path)
    changed = _observe(path)

    # A new inode with identical bytes is not a content change.
    assert identical == first
    assert changed["path_digest"] == first["path_digest"]
    assert changed["content_digest"] == _bytes_digest(b"replaced = true\n")


def test_symlink_retarget_moves_path_identity_but_not_content(tmp_path: Path) -> None:
    first_target = tmp_path / "a.toml"
    second_target = tmp_path / "b.toml"
    first_target.write_bytes(_SECRET)
    second_target.write_bytes(_SECRET)
    link = tmp_path / "config.toml"
    link.symlink_to(first_target)
    before = _observe(link)

    link.unlink()
    link.symlink_to(second_target)
    moved = _observe(link)

    second_target.write_bytes(b"drift = 1\n")
    drifted = _observe(link)

    assert before["path_digest"] == _expected_digest(first_target)
    assert moved["path_digest"] == _expected_digest(second_target)
    assert moved["content_digest"] == before["content_digest"]
    assert drifted["path_digest"] == moved["path_digest"]
    assert drifted["content_digest"] != moved["content_digest"]


def test_dangling_symlink_is_absent_at_its_target_identity(tmp_path: Path) -> None:
    link = tmp_path / "config.toml"
    link.symlink_to(tmp_path / "gone.toml")

    observation = _observe(link)

    assert observation["presence"] == "absent"
    assert observation["path_digest"] == _expected_digest(tmp_path / "gone.toml")


def test_directory_is_not_regular(tmp_path: Path) -> None:
    observation = _observe(tmp_path)

    assert observation["presence"] == "not_regular"
    assert observation["content_digest"] is None


def test_oversized_file_is_bounded_without_reading_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module, "CONTENT_OBSERVATION_BYTE_LIMIT", 4)
    path = tmp_path / "big.toml"
    path.write_bytes(b"12345")

    observation = _observe(path)

    assert observation["presence"] == "oversized"
    assert observation["size_bytes"] is None


def test_concurrent_change_during_read_is_observed_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A write racing the digest never yields a digest of a mixed state."""

    path = tmp_path / "config.toml"
    path.write_bytes(b"before = 1\n")
    real_read = os.read
    calls = {"count": 0}

    def racing_read(descriptor: int, size: int) -> bytes:
        calls["count"] += 1
        if calls["count"] == 1:
            # Another writer appends while the first read is in flight.
            with path.open("ab") as handle:
                handle.write(b"racing = 2\n")
        return real_read(descriptor, size)

    monkeypatch.setattr(module.os, "read", racing_read)

    observation = _observe(path)

    assert observation["presence"] == "present"
    assert observation["content_digest"] == _bytes_digest(b"before = 1\nracing = 2\n")
    assert observation["size_bytes"] == len(b"before = 1\nracing = 2\n")


def test_file_that_keeps_changing_is_unstable_not_digested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(b"value = 0\n")
    real_read = os.read

    def always_racing(descriptor: int, size: int) -> bytes:
        chunk = real_read(descriptor, size)
        if chunk:
            with path.open("ab") as handle:
                handle.write(b"x")
        return chunk

    monkeypatch.setattr(module.os, "read", always_racing)

    observation = _observe(path)

    assert observation["presence"] == "unstable"
    assert observation["content_digest"] is None
    assert observation["size_bytes"] is None


def test_unreadable_file_reports_unreadable(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root reads mode-000 files")
    path = tmp_path / "config.toml"
    path.write_bytes(_SECRET)
    path.chmod(0o000)
    try:
        observation = _observe(path)
    finally:
        path.chmod(0o600)

    assert observation["presence"] == "unreadable"
    assert observation["content_digest"] is None


def test_cli_content_lane_is_opt_in_and_digest_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub_finishup_env(monkeypatch)
    config = tmp_path / "config.toml"
    config.write_bytes(_SECRET)
    monkeypatch.setenv("FINISHUP_CONFIG", str(config))
    runner = CliRunner()

    plain = runner.invoke(cli.app, ["service", "isolation", "--json"])
    lane = runner.invoke(cli.app, ["service", "isolation", "--json", "--content-digests"])

    assert plain.exit_code == 0, plain.output
    assert lane.exit_code == 0, lane.output
    plain_report = json.loads(plain.stdout)
    lane_report = json.loads(lane.stdout)
    assert plain_report["config_content"] is None
    assert lane_report["config_content"]["content_digest"] == _bytes_digest(_SECRET)
    assert lane_report["path_identity"] == plain_report["path_identity"]
    for output in (plain.stdout, lane.stdout):
        assert "never-in-a-report" not in output
        assert str(config) not in output
    validate_schema_instance("isolation-report", "1.0.0", cast(JsonValue, lane_report))


def test_golden_vector_matches_the_schema_and_contract() -> None:
    root = Path(__file__).parents[3]
    payload = json.loads((root / "fixtures/service/isolation-report.case.json").read_bytes())

    validate_schema_instance("isolation-report", "1.0.0", payload)
    IsolationReportContract.model_validate(payload)


def test_contract_rejects_the_untagged_ambiguous_shape_and_partial_evidence() -> None:
    digest = "sha256:" + "a" * 64
    path_identity = {key: digest for key in (*_PATH_KEYS, "executable_path_digest")}
    base: dict[str, object] = {
        "schema": "yoetz.isolation-report/1",
        "mode": "ambient",
        "binding": "ambient",
        "lifecycle": "permanent",
        "path_identity": path_identity,
        "config_content": None,
    }
    IsolationReportContract.model_validate(base)
    legacy = {key: value for key, value in base.items() if key != "path_identity"}
    legacy["identity"] = {"config_digest": digest}
    with pytest.raises(ValueError):
        IsolationReportContract.model_validate(legacy)
    absent_with_digest = {
        "path_digest": digest,
        "presence": "absent",
        "content_digest": digest,
        "size_bytes": 3,
        "observed_at": "2026-09-22T12:00:00.123Z",
    }
    with pytest.raises(ValueError):
        IsolationReportContract.model_validate({**base, "config_content": absent_with_digest})


def test_contract_literals_track_the_runtime_literals() -> None:
    fields = IsolationReportContract.model_fields
    assert set(get_args(fields["binding"].annotation)) == set(get_args(IsolationBinding.__value__))
    assert set(get_args(fields["lifecycle"].annotation)) == set(
        get_args(ReportedLifecycle.__value__)
    )
