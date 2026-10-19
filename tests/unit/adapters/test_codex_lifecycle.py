"""Codex lifecycle mapping store unit tests."""

from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path

import pytest

from finishup.adapters.integrations import codex_lifecycle as codex_lifecycle_module
from finishup.adapters.integrations.codex_lifecycle import (
    MAPPING_VERSION,
    LifecycleMapping,
    acquire_session_lock,
    acquire_workspace_recovery_lock,
    clear_mapping,
    encode_frontier_token,
    is_scoped_child_session_id,
    load_latest_mapping,
    load_mapping,
    load_route_history,
    mapping_from_start_ids,
    scoped_child_session_id,
    store_mapping,
    validate_codex_session_id,
)
from finishup.config.paths import PathSafetyError
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import IdKind, new_id


def _ids() -> tuple[str, str, str, str]:
    return (
        "codex-session-abc123",
        new_id(IdKind.TASK),
        new_id(IdKind.SESSION),
        new_id(IdKind.WRITER),
    )


def test_scoped_child_session_id_is_bounded_and_domain_separated() -> None:
    parent = "codex-parent-abc"
    first = scoped_child_session_id(
        parent,
        host="codex",
        identity="agent-1",
        identity_kind="host",
    )
    assert first == scoped_child_session_id(
        parent,
        host="codex",
        identity="agent-1",
        identity_kind="host",
    )
    assert is_scoped_child_session_id(first)
    assert len(first) <= 128
    assert first != scoped_child_session_id(
        parent,
        host="codex",
        identity="agent-1",
        identity_kind="task",
    )
    assert first != scoped_child_session_id(
        "codex-other-parent",
        host="codex",
        identity="agent-1",
        identity_kind="host",
    )
    assert not is_scoped_child_session_id(parent)
    assert not is_scoped_child_session_id(first[:-1])


@pytest.mark.parametrize(
    ("parent", "host", "identity", "identity_kind"),
    [
        ("parent", "unknown", "agent", "host"),
        ("parent", "codex", "agent", "unknown"),
        ("parent", "codex", "", "host"),
        ("parent", "codex", "agent/unsafe", "host"),
    ],
)
def test_scoped_child_session_id_rejects_unadmitted_inputs(
    parent: str,
    host: str,
    identity: str,
    identity_kind: str,
) -> None:
    with pytest.raises(ProtocolValueError):
        scoped_child_session_id(
            parent,
            host=host,
            identity=identity,
            identity_kind=identity_kind,
        )


def test_mapping_round_trip(tmp_path: Path) -> None:
    codex_session_id, task_id, session_id, writer_id = _ids()
    frontier = encode_frontier_token(sequence="0", head_digest="genesis")
    mapping = mapping_from_start_ids(
        codex_session_id=codex_session_id,
        finishup_task_id=task_id,
        finishup_session_id=session_id,
        finishup_writer_id=writer_id,
        last_frontier=frontier,
    )
    store_mapping(mapping, _state=tmp_path)
    loaded = load_mapping(codex_session_id, _state=tmp_path)
    assert loaded == mapping
    path = tmp_path / "codex-lifecycle" / f"{codex_session_id}.json"
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_rejects_extra_keys_and_wrong_version(tmp_path: Path) -> None:
    codex_session_id, task_id, session_id, writer_id = _ids()
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=codex_session_id,
            finishup_task_id=task_id,
            finishup_session_id=session_id,
            finishup_writer_id=writer_id,
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    path = tmp_path / "codex-lifecycle" / f"{codex_session_id}.json"
    path.write_text(
        json.dumps(
            {
                "mapping_version": MAPPING_VERSION,
                "codex_session_id": codex_session_id,
                "yoetz_task_id": task_id,
                "yoetz_session_id": session_id,
                "yoetz_writer_id": writer_id,
                "last_frontier": None,
                "title": "secret prose",
            }
        ),
        encoding="utf-8",
    )
    assert load_mapping(codex_session_id, _state=tmp_path) is None
    path.write_text(
        json.dumps(
            {
                "mapping_version": 99,
                "codex_session_id": codex_session_id,
                "yoetz_task_id": task_id,
                "yoetz_session_id": session_id,
                "yoetz_writer_id": writer_id,
                "last_frontier": None,
            }
        ),
        encoding="utf-8",
    )
    assert load_mapping(codex_session_id, _state=tmp_path) is None


def test_rejects_oversized_file(tmp_path: Path) -> None:
    codex_session_id = "session-oversize"
    directory = tmp_path / "codex-lifecycle"
    directory.mkdir(parents=True, mode=0o700)
    path = directory / f"{codex_session_id}.json"
    path.write_bytes(b"{" + (b"x" * 5000) + b"}")
    assert load_mapping(codex_session_id, _state=tmp_path) is None


def test_forbidden_codex_session_tokens() -> None:
    with pytest.raises(ProtocolValueError):
        validate_codex_session_id("../escape")
    with pytest.raises(ProtocolValueError):
        validate_codex_session_id("has/slash")
    with pytest.raises(ProtocolValueError):
        validate_codex_session_id("x" * 200)
    with pytest.raises(ProtocolValueError):
        validate_codex_session_id("has space")


def test_store_rejects_bad_ids(tmp_path: Path) -> None:
    with pytest.raises(ProtocolValueError):
        store_mapping(
            LifecycleMapping(
                mapping_version=1,
                codex_session_id="ok-session",
                finishup_task_id="not-a-task",
                finishup_session_id=new_id(IdKind.SESSION),
                finishup_writer_id=new_id(IdKind.WRITER),
                last_frontier=None,
            ),
            _state=tmp_path,
        )


def test_clear_mapping(tmp_path: Path) -> None:
    codex_session_id, task_id, session_id, writer_id = _ids()
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=codex_session_id,
            finishup_task_id=task_id,
            finishup_session_id=session_id,
            finishup_writer_id=writer_id,
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    clear_mapping(codex_session_id, _state=tmp_path)
    assert load_mapping(codex_session_id, _state=tmp_path) is None


def test_route_history_is_task_bound_and_malformed_history_fails_closed(
    tmp_path: Path,
) -> None:
    codex_session_id, task_id, session_id, writer_id = _ids()
    mapping = mapping_from_start_ids(
        codex_session_id=codex_session_id,
        finishup_task_id=task_id,
        finishup_session_id=session_id,
        finishup_writer_id=writer_id,
        last_frontier=None,
    )
    store_mapping(mapping, _state=tmp_path)
    history_path = tmp_path / "codex-lifecycle" / "route-history" / f"{codex_session_id}.json"
    history_path.parent.mkdir(mode=0o700, exist_ok=True)

    history_path.write_bytes(
        canonical_encode(
            {
                "schema": "yoetz.codex-route-history/1",
                "task_id": new_id(IdKind.TASK),
                "routes": ({"session_id": session_id, "writer_id": writer_id},),
                "truncated": False,
            }
        )
        + b"\n"
    )
    # A history file left by a previous task cannot authorize probes for the
    # current task's legacy operation graph.
    history = load_route_history(mapping, _state=tmp_path)
    assert history is not None
    assert history.routes == ()
    assert history.truncated is False

    history_path.write_bytes(b"not-json")
    # A present but corrupt sidecar is different from a missing sidecar: the
    # caller must fail closed instead of silently reminting an old operation.
    assert load_route_history(mapping, _state=tmp_path) is None


def test_route_history_is_bounded_to_the_newest_predecessors(tmp_path: Path) -> None:
    max_route_history = 5
    codex_session_id, task_id, session_id, writer_id = _ids()
    current = mapping_from_start_ids(
        codex_session_id=codex_session_id,
        finishup_task_id=task_id,
        finishup_session_id=session_id,
        finishup_writer_id=writer_id,
        last_frontier=None,
    )
    store_mapping(current, _state=tmp_path)
    predecessor_routes: list[tuple[str, str]] = []
    for _ in range(max_route_history + 1):
        predecessor_routes.append((current.finishup_session_id, current.finishup_writer_id))
        current = mapping_from_start_ids(
            codex_session_id=codex_session_id,
            finishup_task_id=task_id,
            finishup_session_id=new_id(IdKind.SESSION),
            finishup_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        )
        store_mapping(current, _state=tmp_path)

    # The oldest route is deliberately evicted. The result is a truthful
    # bounded suffix, never an unbounded reconstruction of the route graph.
    history = load_route_history(current, _state=tmp_path)
    assert history is not None
    assert history.routes == tuple(predecessor_routes[-max_route_history:])
    assert history.truncated is True


def test_route_history_namespace_cannot_overwrite_a_mapping(tmp_path: Path) -> None:
    codex_session_id, task_id, session_id, writer_id = _ids()
    first = mapping_from_start_ids(
        codex_session_id=codex_session_id,
        finishup_task_id=task_id,
        finishup_session_id=session_id,
        finishup_writer_id=writer_id,
        last_frontier=None,
    )
    successor = mapping_from_start_ids(
        codex_session_id=codex_session_id,
        finishup_task_id=task_id,
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )
    colliding_session = f"{codex_session_id}.history"
    colliding = mapping_from_start_ids(
        codex_session_id=colliding_session,
        finishup_task_id=new_id(IdKind.TASK),
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )

    store_mapping(first, _state=tmp_path)
    store_mapping(successor, _state=tmp_path)
    store_mapping(colliding, _state=tmp_path)

    assert load_mapping(codex_session_id, _state=tmp_path) == successor
    assert load_mapping(colliding_session, _state=tmp_path) == colliding
    history = load_route_history(successor, _state=tmp_path)
    assert history is not None
    assert history.routes == ((first.finishup_session_id, first.finishup_writer_id),)
    assert history.truncated is False


def test_clear_mapping_removes_route_history_sidecar(tmp_path: Path) -> None:
    codex_session_id, task_id, session_id, writer_id = _ids()
    first = mapping_from_start_ids(
        codex_session_id=codex_session_id,
        finishup_task_id=task_id,
        finishup_session_id=session_id,
        finishup_writer_id=writer_id,
        last_frontier=None,
    )
    successor = mapping_from_start_ids(
        codex_session_id=codex_session_id,
        finishup_task_id=task_id,
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )
    store_mapping(first, _state=tmp_path)
    store_mapping(successor, _state=tmp_path)
    history_path = tmp_path / "codex-lifecycle" / "route-history" / f"{codex_session_id}.json"
    assert history_path.is_file()

    clear_mapping(codex_session_id, _state=tmp_path)

    assert load_mapping(codex_session_id, _state=tmp_path) is None
    assert not history_path.exists()
    history = load_route_history(successor, _state=tmp_path)
    assert history is not None
    assert history.routes == ()
    assert history.truncated is False


@pytest.mark.parametrize("failure_stage", ["write", "fsync"])
def test_private_atomic_write_cleans_temporary_on_initial_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    codex_session_id, task_id, session_id, writer_id = _ids()
    mapping = mapping_from_start_ids(
        codex_session_id=codex_session_id,
        finishup_task_id=task_id,
        finishup_session_id=session_id,
        finishup_writer_id=writer_id,
        last_frontier=None,
    )

    if failure_stage == "write":

        def fail_write(_descriptor: int, _payload: memoryview) -> int:
            raise OSError("simulated write failure")

        monkeypatch.setattr(codex_lifecycle_module.os, "write", fail_write)
    else:

        def fail_fsync(_descriptor: int) -> None:
            raise OSError("simulated fsync failure")

        monkeypatch.setattr(codex_lifecycle_module.os, "fsync", fail_fsync)

    with pytest.raises(OSError):
        store_mapping(mapping, _state=tmp_path)

    lifecycle = tmp_path / "codex-lifecycle"
    assert not list(lifecycle.glob(f".{codex_session_id}.json.*.tmp"))
    assert not (lifecycle / f"{codex_session_id}.json").exists()


def test_load_latest_mapping_uses_valid_mapping_write_recency(tmp_path: Path) -> None:
    first_session, first_task, first_finishup_session, first_writer = _ids()
    second_session = "codex-session-def456"
    second = mapping_from_start_ids(
        codex_session_id=second_session,
        finishup_task_id=new_id(IdKind.TASK),
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )
    first = mapping_from_start_ids(
        codex_session_id=first_session,
        finishup_task_id=first_task,
        finishup_session_id=first_finishup_session,
        finishup_writer_id=first_writer,
        last_frontier=None,
    )
    store_mapping(first, _state=tmp_path)
    store_mapping(second, _state=tmp_path)
    directory = tmp_path / "codex-lifecycle"
    os.utime(directory / f"{first_session}.json", ns=(1_000_000_000, 1_000_000_000))
    os.utime(directory / f"{second_session}.json", ns=(2_000_000_000, 2_000_000_000))

    assert load_latest_mapping((first_session, second_session), _state=tmp_path) == second

    (directory / f"{second_session}.json").write_text("invalid", encoding="ascii")
    assert load_latest_mapping((first_session, second_session), _state=tmp_path) == first


def test_session_lock_coalesces_concurrent_acquirers(tmp_path: Path) -> None:
    session_id = "lock-session-1"
    results: list[bool] = []
    barrier = threading.Barrier(2)

    def worker() -> None:
        barrier.wait()
        with acquire_session_lock(session_id, _state=tmp_path, stale_seconds=30.0) as owned:
            results.append(owned)
            if owned:
                # Hold briefly so the other contender observes the lock.
                import time

                time.sleep(0.05)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1
    assert results.count(False) == 1


def test_workspace_recovery_lock_namespace_is_disjoint_from_session_locks(
    tmp_path: Path,
) -> None:
    """A valid host id may contain the old workspace-lock filename prefix."""

    digest = "ab" * 32
    workspace = f"hmac-sha256:{digest}"
    colliding_session = f"workspace-recovery-{digest}"

    # Both locks must be acquirable at once: the workspace reservation lives in
    # a dedicated directory instead of sharing the validated session-id names.
    with acquire_session_lock(colliding_session, _state=tmp_path) as session_owned:
        assert session_owned is True
        with acquire_workspace_recovery_lock(workspace, _state=tmp_path) as workspace_owned:
            assert workspace_owned is True


def test_workspace_recovery_lock_namespace_rejects_symlink(tmp_path: Path) -> None:
    """The dedicated lock directory keeps the lifecycle state symlink-safe."""

    lifecycle = tmp_path / "codex-lifecycle"
    lifecycle.mkdir(parents=True, mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (lifecycle / "workspace-recovery-locks").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PathSafetyError):
        acquire_workspace_recovery_lock(
            f"hmac-sha256:{'cd' * 32}",
            _state=tmp_path,
        )


def test_stale_lock_can_be_broken(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = "stale-lock"
    lock = tmp_path / "codex-lifecycle"
    lock.mkdir(parents=True, mode=0o700)
    path = lock / f".{session_id}.lock"
    path.write_text("4242:1\n", encoding="ascii")
    old = path.stat().st_mtime - 120
    os.utime(path, (old, old))

    def dead(_pid: int, _signal: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(codex_lifecycle_module.os, "kill", dead)
    with acquire_session_lock(session_id, _state=tmp_path, stale_seconds=1.0) as owned:
        assert owned is True


def test_stale_lock_with_live_owner_is_not_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = "live-stale-lock"
    lock = tmp_path / "codex-lifecycle"
    lock.mkdir(parents=True, mode=0o700)
    path = lock / f".{session_id}.lock"
    payload = b"4242:1\n"
    path.write_bytes(payload)
    old = path.stat().st_mtime - 120
    os.utime(path, (old, old))

    def live(_pid: int, _signal: int) -> None:
        return None

    monkeypatch.setattr(codex_lifecycle_module.os, "kill", live)
    with acquire_session_lock(session_id, _state=tmp_path, stale_seconds=1.0) as owned:
        assert owned is False
    assert path.read_bytes() == payload


def test_stale_lock_takeover_is_serialized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = "serialized-stale-lock"
    (tmp_path / "codex-lifecycle").mkdir(parents=True, mode=0o700)
    path = tmp_path / "codex-lifecycle" / f".{session_id}.lock"
    path.write_bytes(b"4242:1\n")
    old = path.stat().st_mtime - 120
    os.utime(path, (old, old))

    def dead(_pid: int, _signal: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(codex_lifecycle_module.os, "kill", dead)
    start = threading.Barrier(2)
    entered = threading.Barrier(2)
    results: list[bool] = []

    def contender() -> None:
        start.wait()
        with acquire_session_lock(session_id, _state=tmp_path, stale_seconds=1.0) as owned:
            results.append(owned)
            entered.wait()

    threads = [threading.Thread(target=contender) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(results) == [False, True]


def test_old_lock_owner_does_not_remove_a_replacement(
    tmp_path: Path,
) -> None:
    session_id = "replacement-lock"
    path = tmp_path / "codex-lifecycle" / f".{session_id}.lock"
    replacement = b"7777:2\n"
    with acquire_session_lock(session_id, _state=tmp_path) as owned:
        assert owned is True
        path.unlink()
        path.write_bytes(replacement)
    assert path.read_bytes() == replacement


def test_pending_mapping_preserves_update_queued_during_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session, task, first_session, first_writer = _ids()
    first = mapping_from_start_ids(
        codex_session_id=session,
        finishup_task_id=task,
        finishup_session_id=first_session,
        finishup_writer_id=first_writer,
        last_frontier=None,
    )
    second = mapping_from_start_ids(
        codex_session_id=session,
        finishup_task_id=task,
        finishup_session_id=new_id(IdKind.SESSION),
        finishup_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )
    original = codex_lifecycle_module.store_mapping

    def interleaved(mapping: LifecycleMapping, *, _state: Path | None = None) -> None:
        original(mapping, _state=_state)
        if mapping == first:
            codex_lifecycle_module.queue_mapping_store(second, _state=_state)

    codex_lifecycle_module.queue_mapping_store(first, _state=tmp_path)
    monkeypatch.setattr(codex_lifecycle_module, "store_mapping", interleaved)
    with acquire_session_lock(session, _state=tmp_path) as owned:
        assert owned
        assert codex_lifecycle_module.apply_pending_mapping(session, _state=tmp_path)
        assert load_mapping(session, _state=tmp_path) == first
        assert codex_lifecycle_module.apply_pending_mapping(session, _state=tmp_path)
        assert load_mapping(session, _state=tmp_path) == second
        assert not codex_lifecycle_module.apply_pending_mapping(session, _state=tmp_path)


def test_new_mapping_does_not_reuse_history_left_by_interrupted_clear(tmp_path: Path) -> None:
    host, task, _, _ = _ids()
    mappings = [
        mapping_from_start_ids(
            codex_session_id=host,
            finishup_task_id=task,
            finishup_session_id=new_id(IdKind.SESSION),
            finishup_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        )
        for _ in range(3)
    ]
    store_mapping(mappings[0], _state=tmp_path)
    store_mapping(mappings[1], _state=tmp_path)
    history = load_route_history(mappings[1], _state=tmp_path)
    assert history is not None and len(history.routes) == 1
    # Simulate a crash between clear_mapping's two unlinks.
    codex_lifecycle_module.mapping_path(host, _state=tmp_path).unlink()
    store_mapping(mappings[2], _state=tmp_path)
    history = load_route_history(mappings[2], _state=tmp_path)
    assert history is not None and history.routes == () and not history.truncated
