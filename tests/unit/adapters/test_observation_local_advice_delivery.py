"""Hook-channel advice delivery cadence and dedup identity (#241).

The 2026-08-13 dogfood session received the same ``provider_not_ready``
developer message 29 times, byte-identical, over 24 minutes: the delivery gate
keyed on ``suppression_identity``, which folds in a digest over every retained
envelope and therefore churns on every tool call while the rendered text cannot
change. These tests pin the content-keyed replacement and the standing-advice
cadence.
"""

from __future__ import annotations

import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.observation_local import AdviceDelivery, LocalObservationStore
from finishup.application.observation_advice import (
    ObservationAdviceBuildInput,
    build_observation_advice_snapshot,
)
from finishup.cli.observe_hooks import handle_claude_observe, handle_observe
from finishup.domain.observation import (
    AdviceSnapshot,
    ObservationCursor,
    ObservationEnvelope,
    ObservationLifecycle,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.kernel.policies.observation_advice import ObservationCompositionFact

_TIME = Timestamp("2026-08-13T14:00:00.000Z")
_STANDING = ObservationCompositionFact(
    semantic_configured=True,
    semantic_ready=False,
    provider_factory_ids=("fireworks",),
    connected_provider_ids=(),
)
_READY = ObservationCompositionFact(
    semantic_configured=False,
    semantic_ready=False,
    provider_factory_ids=(),
    connected_provider_ids=(),
)
# Structurally usable configured provider that has not (yet) appeared in the
# lazily-filled connected registry — the shape a fresh per-build fact takes
# right after a successful mapped-session dispatch or before the first one (#265).
_USABLE = ObservationCompositionFact(
    semantic_configured=True,
    semantic_ready=True,
    provider_factory_ids=("fireworks",),
    connected_provider_ids=(),
)


def _envelope(
    commitment: str, identity: str, payload: dict[str, object], *, pos: int
) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=commitment,
        event_kind="PostToolUse",
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=pos * 8,
            event_position=pos,
            last_source_commitment=commitment,
            mapping_version="codex-obs-hook/1.0.0",
        ),
        receipt_time=_TIME,
        structural_payload=JsonObject(payload),
        content_object_refs=(),
        gap_codes=(),
    )


def _snapshot(
    commitment: str,
    *,
    envelopes: int,
    composition: ObservationCompositionFact | None = None,
    payload: dict[str, object] | None = None,
) -> AdviceSnapshot:
    body: dict[str, object] = (
        {"tool_name": "shell", "exit_status": 0} if payload is None else payload
    )
    built = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=tuple(
                _envelope(commitment, f"hook:{index}", body, pos=index)
                for index in range(1, envelopes + 1)
            ),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            composition=composition,
            has_real_observation=True,
        )
    )
    assert built is not None
    return built


def _compose(monkeypatch: pytest.MonkeyPatch, composition: ObservationCompositionFact) -> None:
    """Make the hook's advice refresh composition-aware, as the service side is.

    ``handle_observe`` calls ``refresh_advice`` with no composition fact, so
    without this the standing provider condition — the exact condition that
    stormed — could never be reproduced through the hook path.
    """

    original = LocalObservationStore.refresh_advice

    def patched(self: LocalObservationStore, workspace: str, **kwargs: object) -> object:
        kwargs.setdefault("composition", composition)
        return original(self, workspace, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(LocalObservationStore, "refresh_advice", patched)


def _run(tmp_path: Path, event: str, session: str, **payload: object) -> str:
    """Run one hook and return its additionalContext (empty when none)."""

    out = io.BytesIO()
    body: dict[str, object] = {"session_id": session, "hook_event_name": event, **payload}
    code = handle_observe(
        event_name=event,
        stdin_bytes=json.dumps(body).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    emitted = cast(Mapping[str, object], json.loads(out.getvalue().decode() or "{}"))
    specific = emitted.get("hookSpecificOutput")
    if isinstance(specific, Mapping):
        return str(cast(Mapping[str, object], specific).get("additionalContext") or "")
    if emitted.get("decision") == "block":
        return str(emitted.get("reason") or "")
    return ""


def _post(tmp_path: Path, session: str) -> str:
    """One ordinary successful tool call: the hook that carries standing advice a Stop withheld."""

    return _run(tmp_path, "PostToolUse", session, tool_name="shell", exit_status=0)


def _consented(tmp_path: Path) -> tuple[LocalObservationStore, str]:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    return store, workspace


def test_standing_advice_delivered_once_then_suppressed_across_n_envelope_ingests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#241 headline: 26 hooks, one standing-advice injection, not 26.

    The incident delivered the identical connect_provider text 29 times in one
    session because every new envelope moved the suppression identity.
    """

    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)

    emitted = [_run(tmp_path, "SessionStart", "storm", source="startup")]
    for _ in range(25):
        emitted.append(_run(tmp_path, "PostToolUse", "storm", tool_name="shell", exit_status=0))

    standing = [index for index, text in enumerate(emitted) if "connect_provider" in text]
    assert standing == [0], (
        f"standing advice reached the agent {len(standing)} times across "
        f"{len(emitted)} hooks (indices {standing}); the incident measured 29"
    )


def test_hook_serializes_advice_selection_through_commit_without_workspace_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)
    phases: list[tuple[str, bool]] = []
    original_peek = LocalObservationStore.peek_advice_for_delivery
    original_commit = LocalObservationStore.commit_advice_delivery

    def peek(
        self: LocalObservationStore,
        workspace: str,
        *,
        finishup_session_id: str | None = None,
        allow_standing: bool = True,
        session_commitment: str | None = None,
    ) -> AdviceDelivery | None:
        phases.append(
            ("peek", workspace in self._batch)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        )
        return original_peek(
            self,
            workspace,
            finishup_session_id=finishup_session_id,
            allow_standing=allow_standing,
            session_commitment=session_commitment,
        )

    def commit(
        self: LocalObservationStore,
        workspace: str,
        delivery_identity: str,
        *,
        finishup_session_id: str | None = None,
        session_commitment: str | None = None,
    ) -> None:
        phases.append(
            ("commit", workspace in self._batch)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        )
        original_commit(
            self,
            workspace,
            delivery_identity,
            finishup_session_id=finishup_session_id,
            session_commitment=session_commitment,
        )

    monkeypatch.setattr(LocalObservationStore, "peek_advice_for_delivery", peek)
    monkeypatch.setattr(LocalObservationStore, "commit_advice_delivery", commit)

    assert "connect_provider" in _run(tmp_path, "SessionStart", "serialized", source="startup")
    assert phases == [("peek", False), ("commit", False)]


def test_standing_advice_never_masks_actionable_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cadence-gating a standing item falls through, it does not suppress the snapshot."""

    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)

    _run(tmp_path, "SessionStart", "fall", source="startup")
    delivered = _run(
        tmp_path,
        "PostToolUse",
        "fall",
        tool_name="shell",
        claim_kind="semantic",
        exit_status=0,
    )
    assert "attempt_semantic_dispatch" in delivered
    assert "connect_provider" not in delivered


def test_standing_advice_reaches_the_agent_only_at_session_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SessionStart carries it; a Stop withholds it for exactly one later PostToolUse (#985).

    The per-tool-call channel never carries it on its own. Advice never rides a
    Stop (the Stop channel continues the agent), so a Stop that finds standing
    advice pending marks it, and only the first later PostToolUse carries it.
    That keeps the honest bound: at most once per turn, and only when a
    different text was delivered in between.
    """

    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)

    first = _run(tmp_path, "SessionStart", "cadence", source="startup")
    middles = [
        _run(tmp_path, "PostToolUse", "cadence", tool_name="shell", exit_status=0)
        for _ in range(10)
    ]
    assert "connect_provider" in first
    assert not any("connect_provider" in text for text in middles)

    # A different advice text in between is what re-opens the single slot, and
    # the standing item must be top-ranked again once the work advice clears.
    failed = _run(
        tmp_path, "PostToolUse", "cadence", tool_name="shell", exit_status=1, correlation_id="c1"
    )
    assert "resolve_failed_command" in failed
    _run(tmp_path, "PostToolUse", "cadence", tool_name="shell", exit_status=0, correlation_id="c1")
    assert _run(tmp_path, "Stop", "cadence") == ""
    assert "connect_provider" in _post(tmp_path, "cadence")
    # Carried once: the marker clears on delivery, so the next tool call is quiet again.
    assert "connect_provider" not in _post(tmp_path, "cadence")


def test_usable_provider_receives_no_connect_provider_at_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A structurally usable provider never triggers connect_provider at Stop (#265).

    The hook itself succeeds on every event — ``_run`` asserts exit code 0 — so
    an empty text is an advice-content verdict, not a delivery failure. This is
    the shape of the incident session: AI-powered review dispatch had just succeeded,
    yet the frozen READY snapshot advised reconnecting the provider.
    """

    _consented(tmp_path)
    _compose(monkeypatch, _USABLE)

    started = _run(tmp_path, "SessionStart", "usable", source="startup")
    _run(tmp_path, "PostToolUse", "usable", tool_name="shell", exit_status=0)
    stopped = _run(tmp_path, "Stop", "usable")

    assert "connect_provider" not in started
    assert "connect_provider" not in stopped
    assert stopped == ""


def test_credential_revocation_resurfaces_connect_provider_from_current_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past usability never suppresses advice once current facts say not-ready (#265).

    The advice source is per-build, so a provider that was usable (no advice)
    and is then revoked must be advised again at the next standing boundary.
    """

    _consented(tmp_path)
    _compose(monkeypatch, _USABLE)
    assert _run(tmp_path, "Stop", "revoked") == ""

    _compose(monkeypatch, _STANDING)
    assert _run(tmp_path, "Stop", "revoked") == ""
    assert "connect_provider" in _post(tmp_path, "revoked")


def test_delivered_then_retired_condition_resurfaces_at_the_documented_cadence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Retire-and-return keeps the #241 identity contract, and the honest bound with it (#265).

    A condition that was already delivered, retired on live facts, and then
    returned renders byte-identical text, so within the same session scope it
    stays suppressed exactly like any repeat (#241). The current evidence is
    still in the workspace snapshot, and the next session boundary delivers it.
    A Stop never delivers it (#985); it reaches the first later PostToolUse.
    """

    store, workspace = _consented(tmp_path)
    _compose(monkeypatch, _STANDING)
    assert _run(tmp_path, "Stop", "flap") == ""
    assert "connect_provider" in _post(tmp_path, "flap")

    _compose(monkeypatch, _USABLE)
    assert _run(tmp_path, "Stop", "flap") == ""
    assert _post(tmp_path, "flap") == ""

    _compose(monkeypatch, _STANDING)
    # Same scope, identical text: the #241 dedup holds even across the retire.
    assert _run(tmp_path, "Stop", "flap") == ""
    assert _post(tmp_path, "flap") == ""
    snapshot = store.advice_snapshot_for(workspace)
    assert snapshot is not None
    assert any(item.rule_code == "provider_not_ready" for item in snapshot.ranked_items), (
        "the resurfaced condition must be present as current evidence even while "
        "its delivery is deduplicated"
    )
    # A fresh session scope hears about the still-true condition again.
    assert "connect_provider" in _run(tmp_path, "SessionStart", "flap-next", source="startup")


def test_changed_advice_is_still_delivered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _consented(tmp_path)
    _compose(monkeypatch, _READY)

    _run(tmp_path, "PostToolUse", "changed", tool_name="shell", exit_status=0)
    delivered = _run(
        tmp_path, "PostToolUse", "changed", tool_name="shell", exit_status=1, correlation_id="c1"
    )
    assert "resolve_failed_command" in delivered


def test_repeated_identical_advice_is_delivered_once(tmp_path: Path) -> None:
    store, workspace = _consented(tmp_path)
    first = _snapshot(workspace, envelopes=1, composition=_STANDING)

    store.set_advice_snapshot(workspace, first)
    delivery = store.peek_advice_for_delivery(workspace)
    assert delivery is not None
    store.commit_advice_delivery(workspace, delivery.delivery_identity)
    for grown in (4, 9):
        store.set_advice_snapshot(
            workspace, _snapshot(workspace, envelopes=grown, composition=_STANDING)
        )
        assert store.peek_advice_for_delivery(workspace) is None


def test_peek_alone_never_suppresses_the_next_peek(tmp_path: Path) -> None:
    """The selection is a pure read; only a committed delivery suppresses (#242 review).

    Recording the identity before the hook wrote its stdout meant one broken
    pipe suppressed that advice permanently — strictly worse than a repeat.
    """

    store, workspace = _consented(tmp_path)
    store.set_advice_snapshot(workspace, _snapshot(workspace, envelopes=1, composition=_STANDING))

    first = store.peek_advice_for_delivery(workspace)
    second = store.peek_advice_for_delivery(workspace)
    assert first is not None and second is not None
    assert first.delivery_identity == second.delivery_identity
    state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert state.last_advice_suppression is None

    store.commit_advice_delivery(workspace, first.delivery_identity)
    assert store.peek_advice_for_delivery(workspace) is None


def test_failed_stdout_write_redelivers_the_advice_on_the_next_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hook whose pipe closes mid-write must not lose the advice it selected."""

    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)

    class _BrokenStdout(io.BytesIO):
        def write(self, data: object) -> int:
            del data
            raise BrokenPipeError("pipe closed by host")

    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps({"session_id": "broken", "source": "startup"}).encode(),
        stdout=_BrokenStdout(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    scope = store.session_commitment("broken")
    assert state.last_advice_suppression is None, (
        "a delivery that never reached stdout was recorded as delivered"
    )
    assert (state.session_advice_suppression or {}).get(scope) is None, (
        "a delivery that never reached stdout was recorded as delivered"
    )
    # The undelivered advice is still pending: the Stop withholds it and the next tool call
    # carries it (#985).
    assert _run(tmp_path, "Stop", "broken") == ""
    assert "connect_provider" in _post(tmp_path, "broken")


def test_successful_emit_records_the_delivery_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)

    assert "connect_provider" in _run(tmp_path, "SessionStart", "recorded", source="startup")

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    recorded = (state.session_advice_suppression or {}).get(store.session_commitment("recorded"))
    assert type(recorded) is str and recorded.startswith("deliver-")
    assert "connect_provider" not in _run(tmp_path, "Stop", "recorded")


def test_stop_emits_no_advice_and_carries_standing_advice_to_the_next_tool_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Codex Stop never emits advice (#985), and never hookSpecificOutput (#222).

    Codex Stop rejects hookSpecificOutput as invalid JSON, and a ``decision: block``
    would spend the turn's continuation the closure gate needs. The pending standing
    advice is not consumed: the first later PostToolUse carries it.
    """

    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)
    _run(tmp_path, "SessionStart", "stop-shape", source="startup")
    failed = _run(
        tmp_path,
        "PostToolUse",
        "stop-shape",
        tool_name="shell",
        exit_status=1,
        correlation_id="c1",
    )
    assert "resolve_failed_command" in failed
    _run(
        tmp_path,
        "PostToolUse",
        "stop-shape",
        tool_name="shell",
        exit_status=0,
        correlation_id="c1",
    )

    out = io.BytesIO()
    code = handle_observe(
        event_name="Stop",
        stdin_bytes=json.dumps({"session_id": "stop-shape", "hook_event_name": "Stop"}).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    emitted = json.loads(out.getvalue().decode() or "{}")
    assert "hookSpecificOutput" not in emitted
    assert emitted == {}
    assert "connect_provider" in _post(tmp_path, "stop-shape")


def test_stop_hook_active_does_not_block_or_consume_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Host loop guard: a prior Stop already continued this turn (#222)."""

    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)
    _run(tmp_path, "SessionStart", "loop-guard", source="startup")
    failed = _run(
        tmp_path,
        "PostToolUse",
        "loop-guard",
        tool_name="shell",
        exit_status=1,
        correlation_id="c1",
    )
    assert "resolve_failed_command" in failed
    _run(
        tmp_path,
        "PostToolUse",
        "loop-guard",
        tool_name="shell",
        exit_status=0,
        correlation_id="c1",
    )

    guarded = _run(tmp_path, "Stop", "loop-guard", stop_hook_active=True)
    assert guarded == ""
    assert _run(tmp_path, "Stop", "loop-guard") == ""
    assert "connect_provider" in _post(tmp_path, "loop-guard")


def test_claude_stop_loop_guard_does_not_consume_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)
    session = "claude:loop-guard"
    _run(tmp_path, "SessionStart", session, source="startup")
    assert "resolve_failed_command" in _run(
        tmp_path,
        "PostToolUse",
        session,
        tool_name="shell",
        exit_status=1,
        correlation_id="c1",
    )
    _run(
        tmp_path,
        "PostToolUse",
        session,
        tool_name="shell",
        exit_status=0,
        correlation_id="c1",
    )

    out = io.BytesIO()
    code = handle_claude_observe(
        event_name="Stop",
        stdin_bytes=json.dumps(
            {
                "hook_event_name": "Stop",
                "session_id": "loop-guard",
                "stop_hook_active": True,
            }
        ).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )

    assert code == 0
    assert json.loads(out.getvalue().decode() or "{}") == {}
    assert _run(tmp_path, "Stop", session) == ""
    assert "connect_provider" in _post(tmp_path, session)


def test_session_end_does_not_consume_undeliverable_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SessionEnd stdout is discarded; peek/commit there would lose the advice."""

    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)
    _run(tmp_path, "SessionStart", "teardown", source="startup")
    failed = _run(
        tmp_path,
        "PostToolUse",
        "teardown",
        tool_name="shell",
        exit_status=1,
        correlation_id="c1",
    )
    assert "resolve_failed_command" in failed
    _run(
        tmp_path,
        "PostToolUse",
        "teardown",
        tool_name="shell",
        exit_status=0,
        correlation_id="c1",
    )

    teardown = _run(tmp_path, "SessionEnd", "teardown")
    assert teardown == ""
    assert _run(tmp_path, "Stop", "teardown") == ""
    assert "connect_provider" in _post(tmp_path, "teardown")


def test_a_then_b_then_a_redelivers_a(tmp_path: Path) -> None:
    """Last-delivered is a single value, never a set: a reappearing condition speaks again."""

    store, workspace = _consented(tmp_path)
    session = "ses_00000000-0000-4000-8000-0000000000aa"
    advice_a = _snapshot(workspace, envelopes=1, composition=_STANDING)
    advice_b = _snapshot(
        workspace,
        envelopes=2,
        composition=_READY,
        payload={"tool_name": "shell", "exit_status": 1, "correlation_id": "x"},
    )

    texts: list[str] = []
    persisted: list[str | None] = []
    for snapshot in (advice_a, advice_b, advice_a):
        store.set_session_advice_snapshot(workspace, finishup_session_id=session, snapshot=snapshot)
        delivery = store.peek_advice_for_delivery(workspace, finishup_session_id=session)
        assert delivery is not None
        store.commit_advice_delivery(
            workspace, delivery.delivery_identity, finishup_session_id=session
        )
        texts.append(delivery.text)
        state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        persisted.append((state.session_advice_suppression or {}).get(session))

    assert texts[0] == texts[2] != texts[1]
    assert persisted[0] != persisted[1] and persisted[1] != persisted[2]
    assert persisted[0] == persisted[2]


def _map_session(tmp_path: Path, codex_session: str) -> str:
    from finishup.adapters.integrations.codex_lifecycle import (
        mapping_from_start_ids,
        store_mapping,
    )
    from finishup.protocol.ids import IdKind, new_id

    finishup_session = new_id(IdKind.SESSION)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=codex_session,
            finishup_task_id=new_id(IdKind.TASK),
            finishup_session_id=finishup_session,
            finishup_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    return finishup_session


def test_workspace_snapshot_is_not_a_task_scoped_fallback(tmp_path: Path) -> None:
    """A workspace-wide failed_command snapshot is not current-task advice (#249)."""

    store, workspace = _consented(tmp_path)
    store.set_advice_snapshot(
        workspace,
        _snapshot(
            workspace,
            envelopes=1,
            payload={"tool_name": "shell", "exit_status": 1, "correlation_id": "old"},
        ),
    )
    assert store.peek_advice_for_delivery(workspace) is None
    assert store.peek_advice_for_delivery(workspace, allow_standing=False) is None


def test_unmapped_task_does_not_receive_prior_task_failed_command(
    tmp_path: Path,
) -> None:
    """#249: task B must not inherit task A's resolve_failed_command as current work."""

    _consented(tmp_path)
    first = _run(
        tmp_path,
        "PostToolUse",
        "task-a",
        tool_name="shell",
        exit_status=1,
        correlation_id="a1",
    )
    assert "resolve_failed_command" in first

    later = _run(tmp_path, "PostToolUse", "task-b", tool_name="shell", exit_status=0)
    assert "resolve_failed_command" not in later
    # Task B's post has no correlation id, so it opens a new orphan scope. The
    # standing limitation stays local and does not enter hook context (#974).
    assert later == ""


def test_same_session_failed_command_stays_deliverable(tmp_path: Path) -> None:
    _consented(tmp_path)
    delivered = _run(
        tmp_path,
        "PostToolUse",
        "same-session",
        tool_name="shell",
        exit_status=1,
        correlation_id="s1",
    )
    assert "resolve_failed_command" in delivered


def test_mapped_session_without_own_snapshot_does_not_use_workspace_task_advice(
    tmp_path: Path,
) -> None:
    _consented(tmp_path)
    prior = _run(
        tmp_path,
        "PostToolUse",
        "task-a",
        tool_name="shell",
        exit_status=1,
        correlation_id="old",
    )
    assert "resolve_failed_command" in prior
    _map_session(tmp_path, "mapped-b")

    delivered = _run(tmp_path, "PostToolUse", "mapped-b", tool_name="shell", exit_status=0)
    assert "resolve_failed_command" not in delivered


def test_mapped_session_snapshot_still_delivers_its_own_failed_command(
    tmp_path: Path,
) -> None:
    store, workspace = _consented(tmp_path)
    finishup_session = _map_session(tmp_path, "mapped-own")
    own = _snapshot(
        workspace,
        envelopes=1,
        payload={"tool_name": "shell", "exit_status": 1, "correlation_id": "own"},
    )
    store.set_session_advice_snapshot(workspace, finishup_session_id=finishup_session, snapshot=own)

    delivered = _run(tmp_path, "PostToolUse", "mapped-own", tool_name="shell", exit_status=0)
    assert "resolve_failed_command" in delivered


def test_unmapped_session_start_still_delivers_workspace_standing_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)
    prior = _run(
        tmp_path,
        "PostToolUse",
        "task-a",
        tool_name="shell",
        exit_status=1,
        correlation_id="old",
    )
    assert "resolve_failed_command" in prior

    started = _run(tmp_path, "SessionStart", "fresh-b", source="startup")
    assert "connect_provider" in started
    assert "resolve_failed_command" not in started


def test_unmapped_session_start_joins_attach_advisory_with_standing_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The attach advisory and pending advice share the channel, neither starves the other.

    The advisory is a static bootstrap instruction with no advice content of its own
    (issue #280); standing advice must still reach the agent at the same SessionStart
    (issue #241), so the delivery text is appended after the advisory.
    """

    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)

    started = _run(tmp_path, "SessionStart", "joined", source="startup")
    bootstrap = "call start to attach a task before substantive material work."
    assert "After guidance reads, tool/schema discovery" in started
    assert bootstrap in started
    assert "connect_provider" in started
    assert started.index(bootstrap) < started.index("connect_provider")


def test_delivery_in_task_a_does_not_suppress_same_condition_in_task_b(
    tmp_path: Path,
) -> None:
    _consented(tmp_path)
    first = _run(
        tmp_path,
        "PostToolUse",
        "suppress-a",
        tool_name="shell",
        exit_status=1,
        correlation_id="a1",
    )
    assert "resolve_failed_command" in first
    second = _run(
        tmp_path,
        "PostToolUse",
        "suppress-b",
        tool_name="shell",
        exit_status=1,
        correlation_id="b1",
    )
    assert "resolve_failed_command" in second


def test_withheld_standing_advice_survives_being_outranked_on_the_first_tool_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Stop carry is cleared only once the standing advice is actually delivered (#985).

    When ordinary advice outranks it on the first later PostToolUse, the carry survives to the
    next one; a single-turn Codex exec has no later SessionStart to fall back on.
    """

    _consented(tmp_path)
    _compose(monkeypatch, _STANDING)

    assert "connect_provider" in _run(tmp_path, "SessionStart", "outranked", source="startup")
    failed = _run(
        tmp_path, "PostToolUse", "outranked", tool_name="shell", exit_status=1, correlation_id="c1"
    )
    assert "resolve_failed_command" in failed
    _run(
        tmp_path, "PostToolUse", "outranked", tool_name="shell", exit_status=0, correlation_id="c1"
    )
    assert _run(tmp_path, "Stop", "outranked") == ""
    outranking = _run(
        tmp_path, "PostToolUse", "outranked", tool_name="shell", exit_status=1, correlation_id="c2"
    )
    assert "connect_provider" not in outranking
    later = _run(
        tmp_path, "PostToolUse", "outranked", tool_name="shell", exit_status=0, correlation_id="c2"
    )
    assert "connect_provider" in later
    # Delivered once: the carry clears, so the next tool call is quiet again.
    assert "connect_provider" not in _post(tmp_path, "outranked")
