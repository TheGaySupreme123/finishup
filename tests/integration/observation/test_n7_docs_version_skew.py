"""A new hook never leaves a ``docs`` row an older running service cannot read (#1106 r2).

The hooks and the running service share one local observation store, and the service's outbox
sweeper and every store read decode each persisted envelope. A build that predates the ``docs``
write scope refuses a row naming it (``invalid_event_value_type``) for the whole workspace, and
the hook connects without superseding such a holder. These cases run real hook payloads through
``handle_observe`` into a real store, then read the store back the way that older build does:
with the ``write_scope`` enum it shipped (the base of #1106, 85d5c2994).
"""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import os
from pathlib import Path

import pytest

import finishup.adapters.integrations.observation_local as observation_local_module
import finishup.domain.observation as observation_module
import finishup.service.write_scope_admission as admission
from builders.codex_replay import Replay, replay_cell, session_start
from finishup import __version__
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import schema_manifest_digest
from finishup.service.lifecycle import SINGLETON_LOCK_NAME

__all__ = ["replay_cell"]

# The real probe, kept before the suite-wide fixture replaces it with "a compatible service".
_REAL_PROBE = admission.docs_write_scope_admitted
# The ``write_scope`` values the build before ``docs`` reads (85d5c2994 ``WRITE_SCOPES``).
_OLDER_WRITE_SCOPES = frozenset(
    {"outside_workspace", "scratch", "yoetz_owned", "notes", "workspace"}
)


def _readme_edits(replay: Replay) -> None:
    session_start(replay, cli_version="0.159.0")
    for index, (tool, tool_input) in enumerate(
        (
            ("Bash", {"command": "printf 'x\\n' > README.md"}),
            ("Write", {"file_path": str(replay.workspace / "README.md"), "content": "x"}),
        )
    ):
        for event in ("PreToolUse", "PostToolUse"):
            fields: dict[str, object] = {
                "tool_name": tool,
                "tool_use_id": f"call_skew_{index}",
                "tool_input": tool_input,
            }
            if event == "PostToolUse":
                fields["tool_response"] = ""
            replay.hook(event, **fields)


def _stored_scopes(replay: Replay) -> list[object]:
    rows = LocalObservationStore(_state=replay.root).list_pending_outbox_rows(replay.commitment)
    return [row.envelope.structural_payload.get("write_scope") for row in rows]


def _read_as_older_build(replay: Replay, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as older:
        older.setitem(observation_module._RUNTIME_FACT_VALUES, "write_scope", _OLDER_WRITE_SCOPES)
        # Another process: nothing this one decoded is cached there.
        older.setattr(
            observation_local_module,
            "_CODEC",
            observation_local_module._EnvelopeCodec(observation_local_module._CODEC_MEMO_ENTRIES),
        )
        store = LocalObservationStore(_state=replay.root)
        store.list_pending_outbox_rows(replay.commitment)
        store.consent_for(replay.commitment)
        store.pending_workspaces()


def test_an_older_service_could_not_read_a_docs_row(
    replay: Replay, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hazard itself: with a service of this build running, the hook records ``docs``, and a
    reader with the older enum refuses the whole workspace."""

    _readme_edits(replay)
    assert "docs" in _stored_scopes(replay)
    with pytest.raises(ProtocolValueError):
        _read_as_older_build(replay, monkeypatch)


def test_without_a_service_that_reads_docs_the_hook_records_the_older_class(
    replay: Replay, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(admission, "docs_write_scope_admitted", lambda: False)
    _readme_edits(replay)
    scopes = _stored_scopes(replay)
    assert "docs" not in scopes
    # The shell write is the older ``workspace``; the edit tool carries no scope at all.
    assert "workspace" in scopes
    assert {scope for scope in scopes if scope is not None} <= _OLDER_WRITE_SCOPES
    _read_as_older_build(replay, monkeypatch)


def _stamp(state: Path, *, digest: str | None, pid: int | None = None) -> None:
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    body: dict[str, object] = {
        "instance_id": "svc_skew",
        "pid": os.getpid() if pid is None else pid,
        "service_version": __version__,
    }
    if digest is not None:
        body["schema_manifest_digest"] = digest
    path = state / SINGLETON_LOCK_NAME
    path.write_bytes(canonical_encode(body) + b"\n")  # type: ignore[arg-type]
    path.chmod(0o600)


def test_the_probe_admits_docs_only_for_a_holder_of_this_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    monkeypatch.setattr("finishup.config.paths.state_dir", lambda: state)
    # No holder: whichever build starts next is unknown, so the older class is recorded.
    assert _REAL_PROBE() is False
    _stamp(state, digest=schema_manifest_digest())
    assert _REAL_PROBE() is True
    # An earlier build of the same version carries another manifest digest.
    _stamp(state, digest="sha256:" + "f" * 64)
    assert _REAL_PROBE() is False
    _stamp(state, digest=None)
    assert _REAL_PROBE() is False
    # A stamp left by a process that is gone names no holder.
    _stamp(state, digest=schema_manifest_digest(), pid=2**31 - 1)
    assert _REAL_PROBE() is False
