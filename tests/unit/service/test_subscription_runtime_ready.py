"""READY composition treats Codex binding facts as credential presence without spawning."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from finishup.adapters.providers import codex_app_server as runtime_module
from finishup.adapters.providers.codex_app_server import (
    CODEX_APP_SERVER_SCHEMA_SHA256,
    CODEX_EVALUATOR_CAPABILITY_CELL_SHA256,
    CODEX_EVALUATOR_CAPABILITY_PROFILE,
    CODEX_EVALUATOR_CONFIG_SHA256,
    CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
    CodexAppServerProfile,
)
from finishup.config.models import ExternalRuntimeProfileConfig
from finishup.config.write import codex_subscription_runtime
from finishup.service.ready_composition import subscription_runtime_structurally_ready


def _binding(executable: Path, home: Path) -> ExternalRuntimeProfileConfig:
    return codex_subscription_runtime(
        executable_path=str(executable),
        executable_sha256="sha256:27ceb5f9b957b43a519efe4eaa3816a0bffb0a531a2c89af18840c0a3c016a7d",
        runtime_version="0.157.1",
        source_identity="openai-codex-npm-darwin-arm64-0.157.1",
        app_server_schema_sha256=CODEX_APP_SERVER_SCHEMA_SHA256,
        capability_cell_sha256=CODEX_EVALUATOR_CAPABILITY_CELL_SHA256,
        isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
        capability_profile=CODEX_EVALUATOR_CAPABILITY_PROFILE,
        capability_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
        codex_home=str(home),
        model="gpt-5.6-sol",
        reasoning_effort="high",
    )


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (datetime(2026, 9, 26, tzinfo=UTC), True),
        (datetime(2026, 11, 30, tzinfo=UTC), False),
        (datetime(2026, 12, 1, tzinfo=UTC), False),
    ],
)
def test_ready_credential_presence_is_binding_digest_and_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, now: datetime, expected: bool
) -> None:
    launches: list[object] = []

    async def launch(_profile: CodexAppServerProfile) -> object:
        launches.append(_profile)
        raise AssertionError("READY must not spawn a Codex app-server")

    async def account_status(_profile: CodexAppServerProfile) -> object:
        raise AssertionError("READY must not probe account/read")

    def binding_is_valid(_self: CodexAppServerProfile) -> None:
        return None

    monkeypatch.setattr(runtime_module, "_launch", launch)
    monkeypatch.setattr(runtime_module, "codex_account_status", account_status)
    monkeypatch.setattr(CodexAppServerProfile, "verify_local_binding", binding_is_valid)

    binding = _binding(tmp_path / "codex", tmp_path / "home")

    assert subscription_runtime_structurally_ready(binding, now=now) is expected
    assert launches == []
    assert subscription_runtime_structurally_ready(object()) is False


# -- structural readiness memo (#881) ------------------------------------------------------------

_EXE = b"admitted codex bytes"
_HOST = b"admitted code-mode host bytes"


class _Hashes:
    """Stand the synthetic bytes in for the macOS cell digests and record every hash."""

    def __init__(self) -> None:
        self.paths: list[str] = []
        self.threads: set[int] = set()

    def __call__(self, path: Path) -> str:
        import threading

        self.paths.append(path.name)
        self.threads.add(threading.get_ident())
        data = path.read_bytes()
        cell = runtime_module.codex_evaluator_cell_for_platform("darwin", "arm64")
        if data == _EXE:
            return cell.executable_sha256
        if data == _HOST:
            return cell.code_mode_host_sha256
        return "sha256:" + "0" * 64


@pytest.fixture
def retained(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[ExternalRuntimeProfileConfig, _Hashes]:
    monkeypatch.setattr(runtime_module.sys, "platform", "darwin")
    monkeypatch.setattr(runtime_module.platform, "machine", lambda: "arm64")

    def allow_private(_path: Path) -> None:
        return None

    monkeypatch.setattr(runtime_module, "verify_private_local_bundle", allow_private)
    hashes = _Hashes()
    monkeypatch.setattr(runtime_module, "_sha256_file", hashes)
    store = tmp_path / "store"
    store.mkdir()
    executable = store / "codex"
    executable.write_bytes(_EXE)
    host = store / "codex-code-mode-host"
    host.write_bytes(_HOST)
    for path in (executable, host):
        path.chmod(0o500)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    (home / "config.toml").write_bytes(runtime_module.CODEX_EVALUATOR_CONFIG.encode())
    return _binding(executable, home), hashes


_NOW = datetime(2026, 9, 27, tzinfo=UTC)


def _rewrite_keeping_size_and_mtime(path: Path, data: bytes) -> None:
    """Rewrite *path* in place with same-size bytes and its old mtime, so only ctime can tell.

    ctime is the kernel's coarse clock: one tick per jiffy (1 ms on the CI-equivalent box, 4 to
    10 ms elsewhere; fine-grained only since Linux 6.13). The fixture's last ``chmod`` is often
    less than a tick old, so a single rewrite can land on the very ctime the memo fingerprinted
    and the memo, correctly by its inputs, stays cached. Repeat the rewrite until the clock has
    moved past the recorded ctime; the deadline bounds it, nothing sleeps.
    """

    before = path.stat()
    deadline = time.monotonic() + 5.0
    while True:
        path.chmod(0o700)
        path.write_bytes(data)
        path.chmod(0o500)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        after = path.stat()
        if after.st_ctime_ns != before.st_ctime_ns:
            break
        assert time.monotonic() < deadline, "the filesystem clock did not advance"
    assert (after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode) == (
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_mode,
    )


@pytest.mark.anyio
async def test_repeated_structural_readiness_hashes_once_off_the_event_loop(
    retained: tuple[ExternalRuntimeProfileConfig, _Hashes],
) -> None:
    import threading

    from finishup.service.ready_composition import SubscriptionReadinessMemo

    binding, hashes = retained
    memo = SubscriptionReadinessMemo()

    for _ in range(25):
        assert await memo.ready(binding, now=_NOW) is True

    assert sorted(hashes.paths) == ["codex", "codex-code-mode-host"]
    assert threading.get_ident() not in hashes.threads
    # Evidence expiry is still the clock's call on every read, without re-hashing.
    assert await memo.ready(binding, now=datetime(2026, 11, 30, tzinfo=UTC)) is False
    assert len(hashes.paths) == 2


@pytest.mark.anyio
@pytest.mark.parametrize("change", ["replace_host", "rewrite_executable", "touch", "config"])
async def test_a_changed_retained_file_forces_a_rehash(
    retained: tuple[ExternalRuntimeProfileConfig, _Hashes], change: str
) -> None:
    from finishup.service.ready_composition import SubscriptionReadinessMemo

    binding, hashes = retained
    memo = SubscriptionReadinessMemo()
    assert await memo.ready(binding, now=_NOW) is True
    executable = Path(binding.executable_path)
    host = executable.parent / "codex-code-mode-host"
    config = Path(binding.codex_home) / "config.toml"

    expected = True
    if change == "replace_host":
        replacement = executable.parent / "replacement"
        replacement.write_bytes(b"other host bytes")
        replacement.chmod(0o500)
        os.replace(replacement, host)
        expected = False
    elif change == "rewrite_executable":
        _rewrite_keeping_size_and_mtime(executable, _EXE[:-1] + b"!")
        expected = False
    elif change == "touch":
        os.utime(host, ns=(1, 1))
    else:
        config.write_bytes(b"changed = true\n")
        expected = False

    assert await memo.ready(binding, now=_NOW) is expected
    assert len(hashes.paths) > 2


def test_the_launch_fence_still_hashes_both_files_every_time(
    retained: tuple[ExternalRuntimeProfileConfig, _Hashes],
) -> None:
    binding, hashes = retained
    profile = CodexAppServerProfile.from_config(binding)

    for _ in range(3):
        profile.verify_local_binding()

    assert hashes.paths == ["codex", "codex-code-mode-host"] * 3
