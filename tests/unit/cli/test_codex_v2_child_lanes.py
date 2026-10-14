"""Issue #841: Codex multi-agent v2 child callbacks and rollouts resolve one child lane.

v2 gives every thread of one delegation tree the root ``session_id``. A delegated child's own
callbacks therefore carry the parent's session, and its rollout is named by the child's thread.
These rows pin how a callback's own transcript names the child, how a contradiction becomes an
explicit attribution gap, and how ``observe reconcile`` resolves a child rollout to its one
validated lane or refuses with a bounded reason. Inputs are the exact IMP-015 v2 records.
"""

from __future__ import annotations

import base64
import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from builders.codex_rollout import encode_lines, session_meta
from finishup.adapters.integrations.codex_lifecycle import (
    LifecycleMapping,
    load_mapping,
    mapping_from_start_ids,
    scoped_child_session_id,
    store_mapping,
)
from finishup.adapters.integrations.hook_spool import HookSpool
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import observe as observe_cli
from finishup.cli import observe_hooks
from finishup.cli.hook_diagnostics import hook_diagnostic_summary
from finishup.cli.hooks import (
    TRANSCRIPT_CHILD_IDENTITY_CONFLICT,
    bind_start_mapping_outcome,
    handle_post_tool_use,
    with_transcript_child_identity,
)
from finishup.cli.observe_hooks import handle_observe, handle_spool
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.ids import IdKind, new_id
from fixture_loader import build_fixture_loader

_IMP_015 = "imports/codex/rollout-multi-agent-v2-0.153.4.case.json"
_PARENT = "019f8b27-b98e-7061-bbb5-d0b897594de6"
_CHILD = "019f8b27-b98e-7061-bbb5-d0b897594de7"
_OTHER_ROOT = "019f8b27-b98e-7061-bbb5-d0b897594de9"


def _imp_015(variant: str) -> bytes:
    case = cast(dict[str, object], build_fixture_loader().load_json(_IMP_015))
    variants = cast(dict[str, object], cast(dict[str, object], case["input"])["variants"])
    source = cast(dict[str, object], cast(dict[str, object], variants[variant])["source"])
    return base64.b64decode(cast(str, source["bytes_base64"]))


@pytest.fixture
def codex_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "codex-home"
    (home / "sessions" / "2026" / "08" / "22").mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("CODEX_HOME", str(home))
    return home


def _rollout(home: Path, thread: str, content: bytes) -> Path:
    path = home / "sessions" / "2026" / "08" / "22" / f"rollout-2026-08-22T12-00-00-{thread}.jsonl"
    path.write_bytes(content)
    return path


def _mapping(session: str, *, task: str | None = None) -> LifecycleMapping:
    return mapping_from_start_ids(
        codex_session_id=session,
        yoetz_task_id=task or new_id(IdKind.TASK),
        yoetz_session_id=new_id(IdKind.SESSION),
        yoetz_writer_id=new_id(IdKind.WRITER),
        last_frontier=None,
    )


def _child_lane(session: str = _PARENT, child: str = _CHILD) -> str:
    return scoped_child_session_id(session, host="codex", identity=child, identity_kind="host")


def _callback(transcript: Path | None, **extra: JsonValue) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = {
        "hook_event_name": "PreToolUse",
        "session_id": _PARENT,
        "tool_name": "shell",
        "tool_use_id": "child-call",
    }
    if transcript is not None:
        payload["transcript_path"] = str(transcript)
    payload.update(extra)
    return payload


def _short_child_rollout(
    home: Path,
    *,
    parent: str,
    filename_child: str,
    header_child: str,
) -> Path:
    path = (
        home
        / "sessions"
        / "2026"
        / "08"
        / "22"
        / f"rollout-2026-08-22T12-00-00-{filename_child}.jsonl"
    )
    path.write_bytes(
        encode_lines(
            session_meta(
                cli_version="0.153.4",
                history_mode="paginated",
                session_id=parent,
                extra={
                    "id": header_child,
                    "multi_agent_version": "v2",
                    "thread_source": "subagent",
                    "parent_thread_id": parent,
                    "source": {"subagent": {"thread_spawn": {"parent_thread_id": parent}}},
                },
            )
        )
    )
    return path


@pytest.mark.parametrize("child", ["root-child", "root_child"])
def test_transcript_identity_preserves_valid_prefix_ids(codex_home: Path, child: str) -> None:
    parent = "root"
    rollout = _short_child_rollout(
        codex_home,
        parent=parent,
        filename_child=child,
        header_child=child,
    )

    enriched, conflict = with_transcript_child_identity(
        {"session_id": parent, "transcript_path": str(rollout)},
        event_name="PreToolUse",
    )

    assert conflict is None
    assert enriched["subagent_id"] == child


def test_transcript_identity_rejects_a_child_suffix_collision(codex_home: Path) -> None:
    parent = "root"
    payload = {"session_id": parent, "transcript_path": ""}
    rollout = _short_child_rollout(
        codex_home,
        parent=parent,
        filename_child="child-2",
        header_child="child",
    )
    payload["transcript_path"] = str(rollout)

    enriched, conflict = with_transcript_child_identity(payload, event_name="PreToolUse")

    assert (enriched, conflict) == (payload, None)


def test_parent_session_rollout_suffix_remains_an_ordinary_callback(codex_home: Path) -> None:
    path = (
        codex_home
        / "sessions"
        / "2026"
        / "08"
        / "22"
        / "rollout-2026-08-22T12-00-00-root_child.jsonl"
    )
    path.write_bytes(
        encode_lines(
            session_meta(
                cli_version="0.153.4",
                history_mode="paginated",
                session_id="root",
            )
        )
    )
    payload = {"session_id": "root", "transcript_path": str(path)}

    assert with_transcript_child_identity(payload, event_name="PreToolUse") == (payload, None)


# --- A callback's own transcript names the delegated child ------------------------------------


def test_child_transcript_names_the_child_for_a_root_session_callback(codex_home: Path) -> None:
    child_rollout = _rollout(codex_home, _CHILD, _imp_015("child"))

    enriched, conflict = with_transcript_child_identity(
        _callback(child_rollout), event_name="PreToolUse"
    )

    assert conflict is None
    assert enriched["subagent_id"] == _CHILD
    assert {key: value for key, value in enriched.items() if key != "subagent_id"} == _callback(
        child_rollout
    )


@pytest.mark.parametrize("key", ["session_file", "transcript_path"])
def test_both_host_transcript_spellings_are_read(codex_home: Path, key: str) -> None:
    child_rollout = _rollout(codex_home, _CHILD, _imp_015("child"))
    payload = _callback(None, **{key: str(child_rollout)})

    enriched, conflict = with_transcript_child_identity(payload, event_name="PostToolUse")

    assert conflict is None and enriched["subagent_id"] == _CHILD


def test_the_sessions_own_rollout_and_unprovable_files_change_nothing(
    codex_home: Path, tmp_path: Path
) -> None:
    own = _rollout(codex_home, _PARENT, _imp_015("parent"))
    # A foreign transcript whose header declares no delegation proves nothing about a child.
    foreign_user_thread = _rollout(codex_home, _OTHER_ROOT, _imp_015("parent"))
    outside = tmp_path / f"rollout-2026-08-22T12-00-00-{_CHILD}.jsonl"
    outside.write_bytes(_imp_015("child"))
    unterminated = _rollout(codex_home, "019f8b27-b98e-7061-bbb5-d0b897594dea", b'{"type":')
    symlink = codex_home / "sessions" / "2026" / "08" / "22" / f"rollout-link-{_CHILD}.jsonl"
    symlink.symlink_to(_rollout(codex_home, _CHILD, _imp_015("child")))

    for transcript in (own, foreign_user_thread, outside, unterminated, symlink):
        payload = _callback(transcript)
        enriched, conflict = with_transcript_child_identity(payload, event_name="PreToolUse")
        assert (enriched, conflict) == (payload, None), transcript.name
    payload = _callback(None)
    assert with_transcript_child_identity(payload, event_name="PreToolUse") == (payload, None)


@pytest.mark.parametrize(
    "event_name", ["SessionStart", "SessionEnd", "SubagentStart", "SubagentStop"]
)
def test_lifecycle_and_lineage_signals_are_never_reattributed(
    codex_home: Path, event_name: str
) -> None:
    payload = _callback(_rollout(codex_home, _CHILD, _imp_015("child")))

    assert with_transcript_child_identity(payload, event_name=event_name) == (payload, None)


def test_an_agreeing_host_alias_is_kept(codex_home: Path) -> None:
    payload = _callback(_rollout(codex_home, _CHILD, _imp_015("child")), agent_id=_CHILD)

    assert with_transcript_child_identity(payload, event_name="PreToolUse") == (payload, None)


def test_an_already_invalid_host_alias_stays_the_hosts_gap(codex_home: Path) -> None:
    payload = _callback(
        _rollout(codex_home, _CHILD, _imp_015("child")), agent_id="a", subagent_id="b"
    )

    assert with_transcript_child_identity(payload, event_name="PreToolUse") == (payload, None)


@pytest.mark.parametrize("shape", ["contradicting_alias", "identity_invalid", "other_session_tree"])
def test_a_child_transcript_that_cannot_name_this_child_is_an_explicit_gap(
    codex_home: Path, tmp_path: Path, shape: str
) -> None:
    """Known child-shaped input never inherits the root session's own route."""

    if shape == "contradicting_alias":
        payload = _callback(
            _rollout(codex_home, _CHILD, _imp_015("child")), agent_id="another-child"
        )
    elif shape == "identity_invalid":
        # A declared delegated child with no usable distinct identity (IMP-015).
        invalid = _rollout(codex_home, _OTHER_ROOT, _imp_015("child_without_identity"))
        payload = _callback(invalid)
    else:
        payload = {
            **_callback(_rollout(codex_home, _CHILD, _imp_015("child"))),
            "session_id": _OTHER_ROOT,
        }

    enriched, conflict = with_transcript_child_identity(payload, event_name="PreToolUse")

    assert conflict == TRANSCRIPT_CHILD_IDENTITY_CONFLICT
    assert enriched["subagent_id"] == ""
    host_session = cast(str, payload["session_id"])
    store_mapping(_mapping(host_session), _state=tmp_path)
    lane = observe_hooks._resolve_observation_lane(  # pyright: ignore[reportPrivateUsage]
        enriched,
        event_name="PreToolUse",
        source=observe_hooks.ObservationSource.CODEX_HOOK,
        _state=tmp_path,
    )
    assert (lane.effective_session_id, lane.attribution_gap) == (host_session, True)


# --- The derived identity routes the child's attach and evidence -------------------------------


def _attach_result(parent_task: str) -> dict[str, JsonValue]:
    return {
        "ok": True,
        "outcome": "attached",
        "task_id": new_id(IdKind.TASK),
        "session_id": new_id(IdKind.SESSION),
        "writer_id": new_id(IdKind.WRITER),
        "parent_task_id": parent_task,
    }


def test_post_tool_use_binds_the_child_lane_from_the_childs_transcript(
    codex_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``finishup hooks post-tool-use`` is the production binder for the child's attach."""

    parent = _mapping(_PARENT)
    store_mapping(parent, _state=tmp_path)
    result = _attach_result(parent.yoetz_task_id)
    callback = _callback(
        _rollout(codex_home, _CHILD, _imp_015("child")),
        hook_event_name="PostToolUse",
        tool_name="mcp__finishup__start",
        tool_response={"structuredContent": result},
    )
    observed: list[Mapping[str, JsonValue]] = []

    def fake_observe(**kwargs: object) -> int:
        observed.append(json.loads(cast(bytes, kwargs["stdin_bytes"])))
        return 0

    monkeypatch.setattr(observe_hooks, "handle_observe", fake_observe)

    assert (
        handle_post_tool_use(
            stdin_bytes=json.dumps(callback).encode(), stdout=io.BytesIO(), _state=tmp_path
        )
        == 0
    )

    child = load_mapping(_child_lane(), _state=tmp_path)
    assert child is not None
    assert (child.yoetz_task_id, child.yoetz_session_id, child.yoetz_writer_id) == (
        result["task_id"],
        result["session_id"],
        result["writer_id"],
    )
    # The shared root session keeps the parent route; observe receives the host bytes.
    assert load_mapping(_PARENT, _state=tmp_path) == parent
    assert observed == [callback]


def test_without_a_transcript_the_root_session_attach_stays_unbound(tmp_path: Path) -> None:
    parent = _mapping(_PARENT)
    store_mapping(parent, _state=tmp_path)
    callback = _callback(
        None,
        hook_event_name="PostToolUse",
        tool_name="mcp__finishup__start",
        tool_response={"structuredContent": _attach_result(parent.yoetz_task_id)},
    )

    assert bind_start_mapping_outcome(callback, _state=tmp_path) == "start_bind_child_lane_unbound"
    assert load_mapping(_child_lane(), _state=tmp_path) is None


def _observe(payload: Mapping[str, JsonValue], workspace: Path, state: Path) -> None:
    assert (
        handle_observe(
            event_name=None,
            stdin_bytes=json.dumps(payload).encode(),
            stdout=io.BytesIO(),
            workspace=str(workspace),
            _state=state,
            skip_service=True,
        )
        == 0
    )


def _consented(tmp_path: Path) -> tuple[Path, Path, LocalObservationStore, str]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    commitment = store.workspace_commitment(str(workspace.resolve()))
    store.grant_consent(commitment)
    return workspace, state, store, commitment


def test_child_evidence_lands_on_the_child_lane_with_its_own_rollout(
    codex_home: Path, tmp_path: Path
) -> None:
    workspace, state, store, commitment = _consented(tmp_path)
    parent = _mapping(_PARENT)
    store_mapping(parent, _state=state)
    store_mapping(_mapping(_child_lane()), _state=state)
    child_rollout = _rollout(codex_home, _CHILD, _imp_015("child"))

    _observe(
        _callback(child_rollout, hook_event_name="PostToolUse", exit_status=0), workspace, state
    )

    rows = store.list_pending_outbox_rows(commitment)
    assert rows and {row.codex_session_id for row in rows} == {_child_lane()}
    kinds = {row.envelope.event_kind for row in rows}
    # The hook row plus the child's own rollout, whose header is its delegation signal.
    assert {"PostToolUse", "SubagentStart"} <= kinds
    header = next(row.envelope for row in rows if row.envelope.event_kind == "SubagentStart")
    assert header.structural_payload["subagent_id"] == _CHILD
    assert _PARENT not in store.codex_sessions_for_workspace(commitment)


def test_a_contradicted_child_callback_never_reaches_the_parent_lane(
    codex_home: Path, tmp_path: Path
) -> None:
    workspace, state, store, commitment = _consented(tmp_path)
    store_mapping(_mapping(_PARENT), _state=state)
    child_rollout = _rollout(codex_home, _CHILD, _imp_015("child"))

    _observe(_callback(child_rollout, agent_id="another-child"), workspace, state)

    assert store.list_pending_outbox_rows(commitment) == ()
    summary = canonical_encode(hook_diagnostic_summary(_state=state))
    assert TRANSCRIPT_CHILD_IDENTITY_CONFLICT.encode() in summary


def test_legacy_spool_names_the_child_before_the_service_replays_it(
    codex_home: Path, tmp_path: Path
) -> None:
    workspace, state, _store, _commitment = _consented(tmp_path)
    child_rollout = _rollout(codex_home, _CHILD, _imp_015("child"))

    assert (
        handle_spool(
            event_name="PreToolUse",
            stdin_bytes=json.dumps(_callback(child_rollout)).encode(),
            stdout=io.BytesIO(),
            workspace=str(workspace),
            _state=state,
        )
        == 0
    )

    spool = HookSpool(_state=state)
    (pending,) = spool.pending_workspaces()
    with spool.claim(pending, limit=10) as records:
        assert [record.payload.get("subagent_id") for record in records] == [_CHILD]


# --- ``observe reconcile`` of a child's own rollout --------------------------------------------


def _reconcile(path: Path, workspace: Path, state: Path) -> int:
    return observe_cli.reconcile_session_stream(
        session_file=str(path), workspace=str(workspace), json_output=True, _state=state
    )


def test_reconcile_resolves_a_child_rollout_to_its_validated_lane_idempotently(
    codex_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, state, store, commitment = _consented(tmp_path)
    store.bind_codex_session(commitment, _PARENT)
    store_mapping(_mapping(_PARENT), _state=state)
    store_mapping(_mapping(_child_lane()), _state=state)
    child_rollout = _rollout(codex_home, _CHILD, _imp_015("child"))

    assert _reconcile(child_rollout, workspace, state) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["mode"] == "recovery_child_lane"
    assert first["accepted"] == 3
    rows = store.list_pending_outbox_rows(commitment)
    assert {row.codex_session_id for row in rows} == {_child_lane()}
    assert rows[0].envelope.event_kind == "SubagentStart"
    assert _child_lane() in store.codex_sessions_for_workspace(commitment)

    assert _reconcile(child_rollout, workspace, state) == 0
    again = json.loads(capsys.readouterr().out)
    assert (again["mode"], again["accepted"]) == ("recovery_child_lane", 0)
    assert store.list_pending_outbox_rows(commitment) == rows


@pytest.mark.parametrize(
    ("shape", "reason"),
    [
        ("parent_unbound", "child_parent_unmapped"),
        ("parent_unmapped", "child_parent_unmapped"),
        ("parent_bound_elsewhere", "child_parent_unmapped"),
        ("lane_missing", "child_route_missing"),
        ("lane_names_parent_task", "child_route_missing"),
        ("lane_bound_elsewhere", "child_route_ambiguous"),
        ("identity_invalid", "child_identity_invalid"),
    ],
)
def test_reconcile_refuses_an_unprovable_child_rollout_with_a_bounded_reason(
    codex_home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    shape: str,
    reason: str,
) -> None:
    workspace, state, store, commitment = _consented(tmp_path)
    parent = _mapping(_PARENT)
    if shape not in {"parent_unbound", "parent_bound_elsewhere"}:
        store.bind_codex_session(commitment, _PARENT)
    if shape != "parent_unmapped":
        store_mapping(parent, _state=state)
    if shape == "parent_bound_elsewhere":
        other = store.workspace_commitment(str((tmp_path / "other").resolve()))
        store.grant_consent(other)
        store.bind_codex_session(other, _PARENT)
    if shape in {"lane_names_parent_task", "lane_bound_elsewhere"}:
        task = parent.yoetz_task_id if shape == "lane_names_parent_task" else None
        store_mapping(_mapping(_child_lane(), task=task), _state=state)
    if shape == "lane_bound_elsewhere":
        other = store.workspace_commitment(str((tmp_path / "other").resolve()))
        store.grant_consent(other)
        store.bind_codex_session(other, _child_lane())
    variant = "child_without_identity" if shape == "identity_invalid" else "child"
    child_rollout = _rollout(codex_home, _CHILD, _imp_015(variant))
    before = store.codex_sessions_for_workspace(commitment)

    assert _reconcile(child_rollout, workspace, state) == 20

    err = capsys.readouterr().err
    assert err.startswith(f"observation_reconcile_failed:{reason}: ")
    # The bounded reason never echoes a host thread, lane, task, or path.
    for secret in (_PARENT, _CHILD, _child_lane(), parent.yoetz_task_id, str(child_rollout)):
        assert secret not in err
    assert store.list_pending_outbox_rows(commitment) == ()
    assert store.codex_sessions_for_workspace(commitment) == before


def test_reconcile_keeps_mapping_missing_for_an_unmapped_ordinary_rollout(
    codex_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, state, _store, _commitment = _consented(tmp_path)
    parent_rollout = _rollout(codex_home, _PARENT, _imp_015("parent"))

    assert _reconcile(parent_rollout, workspace, state) == 20
    assert capsys.readouterr().err == "observation_reconcile_failed:mapping_missing\n"
