"""Actual native ingress proves selection precedes optional content extraction."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import io
import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from builders.codex_rollout import (
    encode_lines,
    function_call,
    function_call_output,
    session_meta,
)
from yoetz.adapters.integrations.codex_lifecycle import LifecycleMapping, store_mapping
from yoetz.adapters.integrations.codex_session_stream import (
    CodexSessionStreamLocator,
    reconcile_session_stream,
)
from yoetz.adapters.integrations.observation_admission import (
    ROUTINE_SUMMARY_INVALID_GAP,
    AdmissionBuffer,
    build_routine_read_summary,
)
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.application.observation_drain import ObservationOutboxSweeper
from yoetz.application.observation_materialize import materialize_observation_envelope
from yoetz.cli import observe as observe_cli
from yoetz.cli import observe_hooks
from yoetz.cli.hook_diagnostics import hook_diagnostic_summary
from yoetz.cli.observe import _selection_preview_plan
from yoetz.domain.observation import (
    ObservationEnvelope,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationSource,
    ObservationStatusQuery,
)
from yoetz.domain.observation_budget import AdmissionLossCause, ObservationMode
from yoetz.domain.observation_settings import ObservationSelection
from yoetz.domain.values import JsonObject, Timestamp
from yoetz.protocol.canonical import JsonValue, canonical_encode

TASK = "tsk_17607d01-2f55-4b28-82b6-8659242a1267"
SESSION = "ses_6201a23d-a03a-46a5-bda9-d16a7a261ee0"
WRITER = "wri_45c1a9bb-20ac-41ce-9fb9-19394f76e1e1"
HOST = "codex-observation-selection-test"


def setup_store(tmp_path: Path) -> tuple[LocalObservationStore, Path, Path, str, str]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    root = tmp_path / "isolated"
    store = LocalObservationStore(_state=root)
    commitment = store.workspace_commitment(str(workspace.resolve()))
    store.grant_consent(commitment)
    session = store.bind_codex_session(commitment, HOST)
    store_mapping(LifecycleMapping(1, HOST, TASK, SESSION, WRITER, None), _state=root)
    return store, root, workspace, commitment, session


# Every shape a real host post can carry its proven success in. Codex states
# its result under ``tool_response`` and Claude's native post hook may state no
# outcome fact at all, so only the first row is the shape the top-level
# structural copy ever retained (issue #753).
NATIVE_POST_SUCCESS_SHAPES: dict[str, dict[str, JsonValue]] = {
    "native_post_fallback": {},
    "nested_exit_code": {"tool_response": {"exit_code": 0}},
    "nested_is_error": {"tool_response": {"is_error": False}},
    "nested_status": {"tool_response": {"status": "ok"}},
    "top_level_success": {"success": True, "exit_status": 0},
}


def hook(
    root: Path,
    workspace: Path,
    phase: str,
    call: str,
    *,
    success: bool = True,
    event_ordinal: int | None = None,
    outcome: Mapping[str, JsonValue] | None = None,
) -> None:
    payload: dict[str, JsonValue] = {
        "session_id": HOST,
        "hook_event_name": phase,
        "tool_name": "Read",
        "tool_use_id": call,
        "tool_input": {"file_path": "public-example.txt"},
    }
    if phase == "PostToolUse" and outcome is not None:
        payload.update(outcome)
    elif phase == "PostToolUse":
        payload.update(
            success=success,
            exit_status=0 if success else 1,
            tool_response={"text": "public synthetic output"},
        )
    if event_ordinal is not None:
        payload["event_ordinal"] = event_ordinal
    assert (
        observe_hooks.handle_observe(
            event_name=phase,
            stdin_bytes=canonical_encode(payload),
            stdout=io.BytesIO(),
            workspace=str(workspace),
            _state=root,
            skip_service=True,
        )
        == 0
    )


def test_focused_pair_skips_capture_and_delivers_a_bounded_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, root, workspace, commitment, _ = setup_store(tmp_path)
    captures: list[str] = []

    def capture(phase: str, *args: object, **kwargs: object):
        captures.append(phase)
        return (), False

    monkeypatch.setattr(observe_hooks, "_visible_content_chunks", capture)
    hook(root, workspace, "PreToolUse", "read1")
    hook(root, workspace, "PostToolUse", "read1")
    assert captures == []
    assert store.selection_accounting(commitment)["buffered_input_count"] == 2
    # The cursor is the authoritative accepted-input account after selected
    # routine diagnostics are reclaimed from the secondary envelope cache.
    assert store.list_envelopes(commitment) == ()
    assert store.status(ObservationStatusQuery(commitment)).source_coverage[
        ObservationSource.CODEX_HOOK
    ]
    assert store.flush_selected_admission(
        commitment, summary_builder=build_routine_read_summary, force=True
    )
    rows = store.list_pending_outbox_rows(commitment)
    assert len(rows) == 1
    assert rows[0].envelope.event_kind == "RoutineReadSummary"
    assert rows[0].envelope.structural_payload["input_count"] == 2
    batch = materialize_observation_envelope(rows[0].envelope, task_id=TASK)
    assert len(batch.drafts) == 1
    assert "routine_read_detail_omitted" in batch.coverage.known_gaps


def test_negative_read_keeps_original_attempt_outcome_and_capture_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, root, workspace, commitment, _ = setup_store(tmp_path)
    captures: list[str] = []

    def capture(phase: str, *args: object, **kwargs: object):
        captures.append(phase)
        return (), False

    monkeypatch.setattr(observe_hooks, "_visible_content_chunks", capture)
    hook(root, workspace, "PreToolUse", "negative-read")
    hook(root, workspace, "PostToolUse", "negative-read", success=False)
    rows = store.list_pending_outbox_rows(commitment)
    assert [row.envelope.event_kind for row in rows] == ["PreToolUse", "PostToolUse"]
    assert rows[-1].envelope.structural_payload["exit_status"] == 1
    assert rows[-1].envelope.structural_payload["success"] is False
    assert captures == ["PostToolUse"]


def test_detailed_keeps_individual_records_without_increasing_content_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, root, workspace, commitment, session = setup_store(tmp_path)
    authority = store.content_capture_authority(commitment)
    store.set_session_selection(
        commitment, session, ObservationSelection(detail=ObservationMode.DETAILED)
    )
    captures: list[str] = []

    def capture(phase: str, *args: object, **kwargs: object):
        captures.append(phase)
        return (), False

    monkeypatch.setattr(observe_hooks, "_visible_content_chunks", capture)
    hook(root, workspace, "PreToolUse", "detailed-read")
    hook(root, workspace, "PostToolUse", "detailed-read")
    rows = store.list_pending_outbox_rows(commitment)
    assert len(rows) == 2
    assert all(row.envelope.structural_payload["action"] == "routine_read_detailed" for row in rows)
    assert captures == ["PreToolUse", "PostToolUse"]
    assert store.content_capture_authority(commitment) == authority


def test_live_pressure_does_not_invalidate_exact_owner_selection_preview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, root, workspace, commitment, session = setup_store(tmp_path)
    del root, workspace
    selection = ObservationSelection(detail=ObservationMode.DETAILED)
    expiry = Timestamp("2026-09-11T00:00:00.000Z")
    monkeypatch.setattr(store, "_wall_timestamp", lambda: Timestamp("2026-09-10T00:01:00.000Z"))
    first_plan, first_digest = _selection_preview_plan(
        store,
        commitment,
        selection,
        session_commitment=session,
        scope="session",
        expires_at=expiry,
    )
    store.update_capture_backlog(
        commitment,
        450,
        0,
        Timestamp("2026-09-10T00:00:00.000Z"),
        Timestamp("2026-09-10T00:01:00.000Z"),
        route_id="capture-live",
    )
    second_plan, second_digest = _selection_preview_plan(
        store,
        commitment,
        selection,
        session_commitment=session,
        scope="session",
        expires_at=expiry,
    )
    assert first_digest == second_digest
    assert first_plan["pressure_state"] != second_plan["pressure_state"]
    assert first_plan["accounting"] == second_plan["accounting"]


def test_buffered_promotion_retains_native_identity_and_reports_missing_content(
    tmp_path: Path,
) -> None:
    store, root, workspace, commitment, _ = setup_store(tmp_path)
    hook(root, workspace, "PreToolUse", "promoted-read")
    hook(root, workspace, "PostToolUse", "promoted-read")
    buffered = store._load(commitment).admission_buffer.inputs
    original = buffered[-1].envelope
    result = store.promote_buffered_observation(commitment, original.source_identity)
    assert result["outcome"] == "queued_individual"
    assert result["content_availability"] == "not_retained"
    rows = store.list_pending_outbox_rows(commitment)
    assert rows[-1].envelope.source_identity == original.source_identity
    assert rows[-1].envelope.cursor == original.cursor
    assert rows[-1].envelope.structural_payload["action"] == "evidence_linked_read"
    assert (
        store.promote_buffered_observation(commitment, original.source_identity)["reason"]
        == "promotion_window_closed"
    )


def test_loss_history_survives_recovery_without_retargeting_another_task(tmp_path: Path) -> None:
    store, root, workspace, commitment, _ = setup_store(tmp_path)
    hook(root, workspace, "PreToolUse", "original")
    hook(root, workspace, "PostToolUse", "original")
    original = store._load(commitment).admission_buffer.inputs[-1].envelope
    lost = replace(original, source_identity="native:lost-input")
    assert store.record_admission_loss(commitment, lost)
    assert not store.record_admission_loss(commitment, lost)
    assert store.flush_selected_admission(
        commitment, summary_builder=build_routine_read_summary, force=True
    )
    for row in store.list_pending_outbox_rows(commitment):
        assert store.acknowledge_outbox_row(commitment, row)
    reopened = LocalObservationStore(_state=root)
    assert reopened.selection_history_gaps(commitment, original) == ("observation_input_loss",)
    different_task = replace(
        original,
        structural_payload=JsonObject(
            {
                **original.structural_payload,
                "selection_task_id": "tsk_00000000-0000-4000-8000-000000000001",
            }
        ),
    )
    assert reopened.selection_history_gaps(commitment, different_task) == ()
    hook(root, workspace, "PreToolUse", "after-recovery")
    hook(root, workspace, "PostToolUse", "after-recovery")
    assert reopened.flush_selected_admission(
        commitment, summary_builder=build_routine_read_summary, force=True
    )
    rows = reopened.list_pending_outbox_rows(commitment)
    assert rows[-1].envelope.event_kind == "RoutineReadSummary"
    batch = materialize_observation_envelope(rows[-1].envelope, task_id=TASK)
    # The lost input belonged to call "original"; an unrelated later call is
    # not marked by it (tb4n1 B3). The lane's loss is still reported once.
    assert "observation_input_loss" not in batch.coverage.known_gaps
    assert reopened.pending_selection_losses(commitment)


_WIRE_LOSS_RANGE_FIELDS = frozenset(
    {
        "lane",
        "source",
        "session",
        "source_generation",
        "route",
        "first_identity",
        "last_identity",
        "first_position",
        "last_position",
        "count",
        "identity_extent",
    }
)


def _loss_envelope_factory(
    store: LocalObservationStore, root: Path, workspace: Path, commitment: str
):
    """Build routed hook envelopes at chosen positions for distinct host calls."""

    hook(root, workspace, "PreToolUse", "template-call")
    template = store._load(commitment).admission_buffer.inputs[-1].envelope
    assert template.structural_payload.get("selection_task_id") == TASK

    def at(position: int, call: str, *, parent: str | None = None) -> ObservationEnvelope:
        payload: dict[str, JsonValue] = {**template.structural_payload, "tool_call_id": call}
        if parent is not None:
            payload["parent_tool_call_id"] = parent
        return replace(
            template,
            # The identity never spells the host call id, so the persisted
            # state can be checked for a leaked call id below.
            source_identity=f"hook:loss-test-{position}-{sum(map(ord, call))}",
            cursor=replace(template.cursor, event_position=position),
            structural_payload=JsonObject(payload),
        )

    return at


def _state_path(root: Path) -> Path:
    return next((root / "observation" / "workspaces").glob("*.json"))


def test_one_startup_loss_marks_only_inputs_of_the_lost_call(tmp_path: Path) -> None:
    """tb4n1 music-harmony: one refusal at position 8 marked 133 later results."""

    store, root, workspace, commitment, _ = setup_store(tmp_path)
    at = _loss_envelope_factory(store, root, workspace, commitment)
    lost_pre = at(8, "lost-call")
    assert store.record_admission_loss(
        commitment, lost_pre, cause=AdmissionLossCause.CAPTURE_SCOPE_UNKNOWN
    )

    reopened = LocalObservationStore(_state=root)
    loss = ("observation_input_loss",)
    # Every later input of other calls is unaffected by the lost pre.
    for position in range(9, 240):
        assert reopened.selection_history_gaps(commitment, at(position, f"call-{position}")) == ()
    # Its pairing partner and a call it spawned inherit the loss.
    assert reopened.selection_history_gaps(commitment, at(10, "lost-call")) == loss
    assert reopened.selection_history_gaps(commitment, at(11, "child", parent="lost-call")) == loss
    # The lane is still reported to the task once, with its closed cause.
    assert reopened.pending_selection_losses(commitment)
    (cause,) = reopened.selection_loss_causes(commitment)
    assert cause["cause"] == "capture_scope_unknown"
    assert cause["causes"] == {"capture_scope_unknown": 1}
    assert cause["inherit_scope"] == "paired_inputs"
    assert reopened.admission_loss_cause(commitment, lost_pre) is (
        AdmissionLossCause.CAPTURE_SCOPE_UNKNOWN
    )
    # The wire-shaped range is unchanged and no host call id is persisted.
    accounting = reopened.selection_accounting(commitment)
    ranges = cast(tuple[Mapping[str, JsonValue], ...], accounting["loss_ranges"])
    assert set(ranges[0]) == _WIRE_LOSS_RANGE_FIELDS
    assert "lost-call" not in _state_path(root).read_text(encoding="utf-8")


def test_loss_lane_with_too_many_lost_calls_falls_back_to_route_wide(tmp_path: Path) -> None:
    store, root, workspace, commitment, _ = setup_store(tmp_path)
    at = _loss_envelope_factory(store, root, workspace, commitment)
    for index in range(17):
        store.record_admission_loss(
            commitment, at(20 + index, f"lost-{index}"), cause=AdmissionLossCause.QUEUE_BYTES
        )
    (cause,) = store.selection_loss_causes(commitment)
    assert cause["inherit_scope"] == "route"
    assert cause["causes"] == {"queue_bytes": 17}
    assert store.selection_history_gaps(commitment, at(500, "unrelated")) == (
        "observation_input_loss",
    )


@pytest.mark.parametrize(
    "legacy_edit",
    ["details_absent", "details_count_stale", "details_malformed"],
)
def test_legacy_loss_range_keeps_route_wide_inheritance(tmp_path: Path, legacy_edit: str) -> None:
    """A range written before causes existed (or advanced by an older writer)."""

    store, root, workspace, commitment, _ = setup_store(tmp_path)
    at = _loss_envelope_factory(store, root, workspace, commitment)
    store.record_admission_loss(commitment, at(8, "lost-call"))
    path = _state_path(root)
    state = json.loads(path.read_text(encoding="utf-8"))
    assert set(state["selection_loss_ranges"][0]) == _WIRE_LOSS_RANGE_FIELDS
    if legacy_edit == "details_absent":
        state.pop("selection_loss_details")
    elif legacy_edit == "details_count_stale":
        state["selection_loss_ranges"][0]["count"] = 2
    else:
        state["selection_loss_details"][0]["pairings"] = ["not-a-digest"]
    path.write_text(json.dumps(state), encoding="utf-8")

    reopened = LocalObservationStore(_state=root)
    assert reopened.selection_history_gaps(commitment, at(300, "unrelated")) == (
        "observation_input_loss",
    )
    (cause,) = reopened.selection_loss_causes(commitment)
    assert cause["inherit_scope"] == "route"
    if legacy_edit != "details_count_stale":
        assert cause["cause"] == "unknown"
    # A later loss on a legacy lane cannot narrow its earlier history.
    reopened.record_admission_loss(
        commitment, at(301, "second-loss"), cause=AdmissionLossCause.SESSION_FAIR_SHARE
    )
    (cause,) = reopened.selection_loss_causes(commitment)
    assert cause["inherit_scope"] == "route"
    assert cause["cause"] == "session_fair_share"
    assert reopened.selection_history_gaps(commitment, at(302, "unrelated-2")) == (
        "observation_input_loss",
    )


def test_unknown_capture_scope_refusal_records_its_cause_and_diagnostic(
    tmp_path: Path,
) -> None:
    store, root, workspace, commitment, _ = setup_store(tmp_path)
    hook(root, workspace, "PreToolUse", "before")
    store.mark_capture_backlog_scope_unknown(commitment)
    hook(root, workspace, "PreToolUse", "refused-call")
    (cause,) = store.selection_loss_causes(commitment)
    assert cause["cause"] == "capture_scope_unknown"
    assert cause["inherit_scope"] == "paired_inputs"
    reasons = cast(Mapping[str, JsonValue], hook_diagnostic_summary(_state=root)["reasons"])
    assert "outbox_overflow" in reasons
    assert "admission_loss_capture_scope_unknown" in reasons


def test_unconfirmed_capture_reservation_does_not_refuse_native_input(
    tmp_path: Path,
) -> None:
    """tb4n1 music-harmony: a hook ran 28 ms after a 1.4 s reservation hold."""

    store, root, workspace, commitment, _ = setup_store(tmp_path)
    store.bootstrap_capture_reservations(
        commitment,
        {},
        observed_at=Timestamp("2026-09-10T00:00:00.000Z"),
        complete=True,
    )
    store.reserve_capture_ticket(commitment, "sha256:" + "a" * 64, TASK, 4_096)
    assert store._load(commitment).capture_reservations
    hook(root, workspace, "PreToolUse", "during-reservation")
    hook(root, workspace, "PostToolUse", "during-reservation")
    assert store.selection_loss_causes(commitment) == ()
    assert store.selection_accounting(commitment)["unrecoverable_input_count"] == 0
    # An unproven inventory still refuses, and now says why.
    store.mark_capture_backlog_scope_unknown(commitment)
    hook(root, workspace, "PreToolUse", "after-unknown")
    (cause,) = store.selection_loss_causes(commitment)
    assert cause["cause"] == "capture_scope_unknown"


def test_selected_admission_exception_rolls_back_ingest_for_exact_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed selected commit cannot leave a duplicate-only local envelope behind."""

    _store, root, workspace, commitment, _ = setup_store(tmp_path)
    original_commit = LocalObservationStore.commit_selected_admission
    calls = 0

    def fail_once(
        selected_store: LocalObservationStore,
        selected_workspace: str,
        plan: object,
        **kwargs: object,
    ) -> bool:
        nonlocal calls
        if calls == 0:
            calls += 1
            raise RuntimeError("selected_commit_fault")
        return original_commit(  # type: ignore[arg-type]
            selected_store,
            selected_workspace,
            plan,  # type: ignore[arg-type]
            **kwargs,  # type: ignore[arg-type]
        )

    monkeypatch.setattr(LocalObservationStore, "commit_selected_admission", fail_once)
    hook(root, workspace, "PreToolUse", "atomic-retry")
    assert LocalObservationStore(_state=root).list_envelopes(commitment) == ()

    hook(root, workspace, "PreToolUse", "atomic-retry")
    hook(root, workspace, "PostToolUse", "atomic-retry")
    reopened = LocalObservationStore(_state=root)
    assert reopened.list_envelopes(commitment) == ()
    assert len(reopened._load(commitment).admission_buffer.inputs) == 2
    assert reopened.flush_selected_admission(
        commitment, summary_builder=build_routine_read_summary, force=True
    )
    rows = reopened.list_pending_outbox_rows(commitment)
    assert [row.envelope.event_kind for row in rows] == ["RoutineReadSummary"]
    assert rows[0].envelope.structural_payload["input_count"] == 2


@pytest.mark.anyio
async def test_fresh_background_sweeper_delivers_buffer_without_another_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, root, workspace, commitment, _ = setup_store(tmp_path)

    # Keep the four synthetic hook calls within one admission deadline even
    # when the isolated hook subprocess setup is slow on the test host.
    def fixed_wall_now(_store: LocalObservationStore) -> float:
        return 1_000_000.0

    monkeypatch.setattr(LocalObservationStore, "_wall_now", fixed_wall_now)
    # A host retry can replay the same source identity and cursor.  It must be
    # idempotent in both the observed/admitted counters and the buffered pair.
    hook(root, workspace, "PreToolUse", "before-restart", event_ordinal=1)
    hook(root, workspace, "PostToolUse", "before-restart", event_ordinal=2)
    hook(root, workspace, "PreToolUse", "before-restart", event_ordinal=1)
    hook(root, workspace, "PostToolUse", "before-restart", event_ordinal=2)
    assert store.list_pending_outbox_rows(commitment) == ()
    before_sweep = store.selection_accounting(commitment)
    assert before_sweep["observed_count"] == 2
    assert before_sweep["admitted_input_count"] == 2
    assert before_sweep["summarized_input_count"] == 0
    assert before_sweep["delivered_input_count"] == 0
    assert before_sweep["intentionally_omitted_input_count"] == 0
    received: list[ObservationEnvelope] = []

    class Coordinator:
        async def ingest_request(
            self, request: ObservationIngestRequest
        ) -> ObservationIngestResult:
            received.append(request.envelope)
            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED, None, request.envelope.cursor
            )

    reopened = LocalObservationStore(_state=root)
    sweeper = ObservationOutboxSweeper(reopened, Coordinator())
    result = await sweeper.sweep()
    assert result.acknowledged == 1
    assert len(received) == 1
    assert received[0].event_kind == "RoutineReadSummary"
    assert received[0].structural_payload["input_count"] == 2
    assert reopened.selection_accounting(commitment)["buffered_input_count"] == 0
    assert reopened.list_pending_outbox_rows(commitment) == ()
    after_sweep = reopened.selection_accounting(commitment)
    assert after_sweep["observed_count"] == 2
    assert after_sweep["admitted_input_count"] == 2
    assert after_sweep["summarized_input_count"] == 2
    assert after_sweep["delivered_input_count"] == 2
    assert after_sweep["intentionally_omitted_input_count"] == 0

    # A second sweep sees no row and cannot account the same summary twice.
    second = await sweeper.sweep()
    assert second.attempted == 0
    assert reopened.selection_accounting(commitment) == after_sweep
    sweeper.close()


@pytest.mark.parametrize("shape", sorted(NATIVE_POST_SUCCESS_SHAPES))
def test_every_proven_post_shape_buffers_and_flushes_repeatedly(tmp_path: Path, shape: str) -> None:
    """The classifier and the summary builder must agree on one proof (#753).

    The hook classifier proves a routine success from nested result carriers or
    from the native post-hook fallback, while the structural envelope retained
    only top-level outcome fields. Re-deriving proof from that copy refused four
    of these five shapes, and the refused input stayed buffered, so every later
    flush raised again and ingestion stopped for the rest of the session.
    """

    store, root, workspace, commitment, _ = setup_store(tmp_path)
    outcome = NATIVE_POST_SUCCESS_SHAPES[shape]
    hook(root, workspace, "PreToolUse", "shaped-read", outcome=outcome)
    hook(root, workspace, "PostToolUse", "shaped-read", outcome=outcome)
    assert store.selection_accounting(commitment)["buffered_input_count"] == 2

    assert store.flush_selected_admission(
        commitment, summary_builder=build_routine_read_summary, force=True
    )
    rows = store.list_pending_outbox_rows(commitment)
    assert [row.envelope.event_kind for row in rows] == ["RoutineReadSummary"]
    assert rows[0].envelope.structural_payload["input_count"] == 2

    # The second flush is what every later hook and every daemon sweep runs.
    assert store.flush_selected_admission(
        commitment, summary_builder=build_routine_read_summary, force=True
    )
    assert store.selection_accounting(commitment)["buffered_input_count"] == 0
    assert store.summary_refusals(commitment) == ()
    assert ROUTINE_SUMMARY_INVALID_GAP not in store.status(ObservationStatusQuery(commitment)).gaps


def _poison_buffered_post(store: LocalObservationStore, commitment: str) -> ObservationEnvelope:
    """Contradict one buffered success so the summary builder must refuse it."""

    state = store._load(commitment)
    inputs = state.admission_buffer.inputs
    assert [item.kind for item in inputs] == ["success", "success"]
    original = inputs[-1].envelope
    poisoned = replace(
        original,
        structural_payload=JsonObject({**original.structural_payload, "success": False}),
    )
    state.admission_buffer = AdmissionBuffer(
        inputs[:-1] + (replace(inputs[-1], envelope=poisoned),)
    )
    store._save(commitment, state)
    return poisoned


@pytest.mark.anyio
async def test_refused_summary_drains_its_lane_and_ingestion_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A builder refusal is an accounting loss for one lane, never a stall (#753).

    Before this, the refused input was never evicted: the daemon sweep aborted
    its batch once a minute and every later hook raised out of its own
    pre-flush, so nothing from either source reached the ledger again.
    """

    def fixed_wall_now(_store: LocalObservationStore) -> float:
        return 1_000_000.0

    monkeypatch.setattr(LocalObservationStore, "_wall_now", fixed_wall_now)
    store, root, workspace, commitment, _ = setup_store(tmp_path)
    hook(root, workspace, "PreToolUse", "poisoned-read", event_ordinal=1)
    hook(root, workspace, "PostToolUse", "poisoned-read", event_ordinal=2)
    poisoned = _poison_buffered_post(store, commitment)

    # A later hook still ingests, and its own pre-flush drains the refused lane.
    hook(root, workspace, "SessionEnd", "session-end", event_ordinal=3)
    reopened = LocalObservationStore(_state=root)
    rows = reopened.list_pending_outbox_rows(commitment)
    assert [row.envelope.event_kind for row in rows] == [
        "PreToolUse",
        "PostToolUse",
        "SessionEnd",
    ]
    refused = next(row for row in rows if row.envelope.source_identity == poisoned.source_identity)
    assert ROUTINE_SUMMARY_INVALID_GAP in refused.envelope.gap_codes
    assert reopened.selection_accounting(commitment)["buffered_input_count"] == 0

    # The cause is named durably, once, with the refused lane's bounded identity.
    refusals = reopened.summary_refusals(commitment)
    assert len(refusals) == 1
    refusal = refusals[0]
    assert refusal["source_identity"] == rows[0].envelope.source_identity
    assert refusal["event_position"] == rows[0].envelope.cursor.event_position
    assert refusal["input_count"] == 2
    assert refusal["reason"] == "invalid_event_value_type"
    assert ROUTINE_SUMMARY_INVALID_GAP in reopened.status(ObservationStatusQuery(commitment)).gaps

    diagnostics = (root / "observation" / "hook-diagnostics.jsonl").read_text()
    assert ROUTINE_SUMMARY_INVALID_GAP in diagnostics
    assert '"reason":"observe"' not in diagnostics

    # `observe status` names the cause instead of a bare coverage note.
    assert observe_cli.observe_status(workspace=str(workspace), json_output=True, _state=root) == 0
    status_payload = json.loads(capsys.readouterr().out)
    assert status_payload["summary_refusals"] == list(refusals)
    assert ROUTINE_SUMMARY_INVALID_GAP in status_payload["status"]["gaps"]

    # The real background sweep drains the workspace it used to abort, and a
    # later stream-sourced ingest still reaches the same outbox.
    received: list[ObservationEnvelope] = []

    class Coordinator:
        async def ingest_request(
            self, request: ObservationIngestRequest
        ) -> ObservationIngestResult:
            received.append(request.envelope)
            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED, None, request.envelope.cursor
            )

    swept = LocalObservationStore(_state=root)
    sweeper = ObservationOutboxSweeper(swept, Coordinator())
    try:
        result = await sweeper.sweep()
        assert result.acknowledged == 3
        assert [envelope.event_kind for envelope in received] == [
            "PreToolUse",
            "PostToolUse",
            "SessionEnd",
        ]
        assert swept.list_pending_outbox_rows(commitment) == ()

        home = tmp_path / "codex-home"
        (home / "sessions").mkdir(parents=True)
        (home / "sessions" / f"rollout-{HOST}.jsonl").write_bytes(
            encode_lines(
                session_meta(session_id=HOST),
                function_call(name="shell", call_id="stream-read", arguments='{"command":"ls"}'),
                function_call_output(call_id="stream-read", exit_code=0),
            )
        )
        stream = reconcile_session_stream(
            swept,
            workspace_commitment=commitment,
            session_commitment=swept.session_commitment(HOST),
            codex_session_id=HOST,
            locator=CodexSessionStreamLocator(home),
        )
        assert stream["accepted"] == 3
        stream_result = await sweeper.sweep()
        assert stream_result.acknowledged >= 1
        assert [
            envelope.event_kind
            for envelope in received
            if envelope.source is ObservationSource.CODEX_SESSION_STREAM
        ] != []
    finally:
        sweeper.close()


def test_pressure_that_withholds_detail_is_disclosed_on_check_coverage_and_spares_edits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#883 body ask 3: a pressure downgrade never silently thins what a check reviews.

    Optional routine detail withheld under pressure carries its own gap from the envelope, through
    materialized ledger coverage, into the check's folded coverage. Native edit content is never
    optional, so the same pressure still captures it; the check-time change (ADR-031) is read by
    the service at check time and is independent of observation pressure altogether.
    """

    from builders.policy_cases import act, make_case
    from yoetz.domain.observation_budget import PressureEvaluation
    from yoetz.kernel.deterministic_checks import case_coverage

    store, root, workspace, commitment, session = setup_store(tmp_path)
    store.set_session_selection(
        commitment, session, ObservationSelection(detail=ObservationMode.DETAILED)
    )
    original = LocalObservationStore.update_selection_pressure

    def pressured(
        self: LocalObservationStore, workspace_commitment: str, session_commitment: str
    ) -> PressureEvaluation:
        evaluation = original(self, workspace_commitment, session_commitment)
        return replace(evaluation, content_allowed=False)

    captures: list[str] = []

    def capture(phase: str, *args: object, **kwargs: object):
        captures.append(phase)
        return (), False

    monkeypatch.setattr(LocalObservationStore, "update_selection_pressure", pressured)
    monkeypatch.setattr(observe_hooks, "_visible_content_chunks", capture)
    hook(root, workspace, "PreToolUse", "pressured-read")
    hook(root, workspace, "PostToolUse", "pressured-read")

    assert captures == []
    post = store.list_pending_outbox_rows(commitment)[-1].envelope
    assert "optional_observation_detail_omitted" in post.gap_codes
    batch = materialize_observation_envelope(post, task_id=TASK)
    assert "optional_observation_detail_omitted" in batch.coverage.known_gaps
    case = make_case(extra_refs=(act(1),), coverage_overrides={act(1): batch.coverage})
    assert "optional_observation_detail_omitted" in case_coverage(case, semantic=True).known_gaps

    patch = "*** Begin Patch\n*** Update File: app.py\n@@\n-old\n+new\n*** End Patch\n"
    for phase in ("PreToolUse", "PostToolUse"):
        payload: dict[str, JsonValue] = {
            "session_id": HOST,
            "hook_event_name": phase,
            "tool_name": "apply_patch",
            "tool_use_id": "pressured-edit",
            "tool_input": {"command": patch},
        }
        if phase == "PostToolUse":
            payload["tool_response"] = "Exit code: 0\nWall time: 0.1 seconds\nOutput:\nSuccess."
        assert (
            observe_hooks.handle_observe(
                event_name=phase,
                stdin_bytes=canonical_encode(payload),
                stdout=io.BytesIO(),
                workspace=str(workspace),
                _state=root,
                skip_service=True,
            )
            == 0
        )
    assert captures == ["PreToolUse", "PostToolUse"]


@pytest.mark.parametrize(
    ("lost_event", "lost_extra", "scope"),
    [
        (
            "PostToolUse",
            {"tool_name": "Bash", "tool_use_id": "call-1", "exit_status": 0},
            "paired_inputs",
        ),
        # Names no host call: every later input of the lane may depend on it.
        ("UserPromptSubmit", {}, "route"),
        # Names only its spawning call: bounded to that call and its children.
        ("SubagentStart", {"parent_tool_call_id": "spawn-9", "subagent_id": "a1"}, "paired_inputs"),
    ],
)
def test_a_lost_input_without_a_call_id_keeps_route_wide_inheritance(
    tmp_path: Path, lost_event: str, lost_extra: dict[str, JsonValue], scope: str
) -> None:
    """Review of #998: a bounded scope needs a call to bound to, or it under-reports the loss."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "lost-scope")
    lost = observe_hooks.map_hook_payload_to_envelope(
        lost_event,
        {"session_id": "lost-scope", "hook_event_name": lost_event, **lost_extra},
        session_commitment=store.session_commitment("lost-scope"),
        event_ordinal=1,
        key_material=store.key_material(),
        source=ObservationSource.CODEX_HOOK,
    )
    store.record_admission_loss(workspace, lost, cause=AdmissionLossCause.QUEUE_BYTES)
    (lane,) = store.selection_loss_causes(workspace)
    assert lane["inherit_scope"] == scope
    assert lane["cause"] == AdmissionLossCause.QUEUE_BYTES.value
