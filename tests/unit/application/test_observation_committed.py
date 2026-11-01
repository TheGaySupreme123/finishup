"""The one definition of "already committed" the coordinator's three decisions share (#1027)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from finishup.application.observation_committed import (
    action_event_committed,
    committed_event_ids,
    observation_already_committed,
)
from finishup.application.observation_materialize import (
    materialize_observation_envelope,
    observation_event_ids_call_keyed,
)
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp

_SESSION = f"hmac-sha256:{'ef' * 32}"


class _EventLedger:
    def __init__(self, *held: str) -> None:
        self.held = frozenset(held)
        self.reads: list[tuple[str, ...]] = []

    async def committed_event_ids(self, event_ids: tuple[str, ...]) -> frozenset[str]:
        self.reads.append(tuple(event_ids))
        return self.held & frozenset(event_ids)


class _ProjectedLedger(_EventLedger):
    def __init__(self, projected: dict[str, str]) -> None:
        super().__init__()
        self.projected = projected

    async def projected_action_event(self, action: str) -> str | None:
        return self.projected.get(action)


@pytest.mark.anyio
async def test_committed_event_ids_answers_only_for_the_asked_ids() -> None:
    ledger = _EventLedger("evt_a", "evt_b")

    assert await committed_event_ids(ledger, ["evt_a", "evt_c", "evt_a"]) == {"evt_a"}
    assert ledger.reads == [("evt_a", "evt_c")]
    assert await committed_event_ids(ledger, []) == frozenset()
    assert len(ledger.reads) == 1  # an empty question is not a read


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("held", "asked", "expected"),
    [
        (("evt_a", "evt_b"), ("evt_a", "evt_b"), True),
        (("evt_a", "evt_b", "evt_z"), ("evt_a",), True),
        (("evt_a",), ("evt_a", "evt_b"), False),  # a partial overlap is a refusal, not a duplicate
        ((), ("evt_a",), False),
        (("evt_a",), (), False),
    ],
)
async def test_already_committed_needs_every_event_and_at_least_one(
    held: tuple[str, ...], asked: tuple[str, ...], expected: bool
) -> None:
    assert await observation_already_committed(_EventLedger(*held), asked) is expected


@pytest.mark.anyio
async def test_a_ledger_without_the_seam_reports_nothing_committed() -> None:
    """Older in-process ledgers and test doubles keep their pre-#1027 behavior."""

    assert await committed_event_ids(object(), ["evt_a"]) == frozenset()
    assert await observation_already_committed(object(), ["evt_a"]) is False
    assert await action_event_committed(object(), "act_a", "evt_a") is False


@pytest.mark.anyio
async def test_action_event_committed_requires_the_event_that_records_the_action() -> None:
    ledger = _ProjectedLedger({"act_a": "evt_a"})

    assert await action_event_committed(ledger, "act_a", "evt_a") is True
    assert await action_event_committed(ledger, "act_a", "evt_other") is False
    assert await action_event_committed(ledger, "act_missing", "evt_a") is False


def _envelope(
    *,
    kind: str,
    source: ObservationSource = ObservationSource.CODEX_HOOK,
    corr: str | None = "call-1",
    gaps: tuple[str, ...] = (),
    structural: dict[str, object] | None = None,
) -> ObservationEnvelope:
    fields: dict[str, object] = {"tool_name": "shell"}
    if corr is not None:
        fields.update({"tool_call_id": corr, "correlation_id": corr})
    fields.update(structural or {})
    return ObservationEnvelope(
        session_commitment=_SESSION,
        event_kind=kind,
        source_identity=f"{source.value}:{kind}:{corr}",
        source=source,
        cursor=ObservationCursor(1, 0, 1, f"hmac-sha256:{'ab' * 32}", "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject(fields),
        content_object_refs=(),
        gap_codes=gaps,
    )


@pytest.mark.parametrize(
    ("envelope", "expected"),
    [
        # Event ids derived from the host call: a second delivery of the same call is a duplicate.
        (_envelope(kind="PreToolUse"), True),
        (_envelope(kind="PostToolUse", structural={"exit_status": 0}), True),
        (
            _envelope(
                kind="item_completed",
                source=ObservationSource.CODEX_SESSION_STREAM,
                structural={"action": "CommandExecution", "exit_status": 0},
            ),
            True,
        ),
        # Ids derived from the source identity can be reused by another call (#560): a conflict.
        (
            _envelope(
                kind="PostToolUse",
                gaps=(ObservationGapCode.UNPAIRED_EVENT.value,),
                structural={"exit_status": 0},
            ),
            False,
        ),
        (_envelope(kind="PostToolUse", corr=None), False),
        (_envelope(kind="SessionStart"), False),
    ],
)
def test_only_call_keyed_event_ids_may_classify_a_collision_as_a_duplicate(
    envelope: ObservationEnvelope, expected: bool
) -> None:
    assert observation_event_ids_call_keyed(envelope) is expected


def test_the_call_keyed_classification_matches_how_the_materializer_mints_ids() -> None:
    """The same call from the hook and from the stream shares its result event id."""

    task = "tsk_00000000-0000-4000-8000-000000000001"
    hook = _envelope(kind="PostToolUse", structural={"exit_status": 0})
    stream = replace(
        _envelope(
            kind="item_completed",
            source=ObservationSource.CODEX_SESSION_STREAM,
            structural={"action": "CommandExecution", "exit_status": 0},
        ),
        cursor=hook.cursor,
    )

    def result_events(envelope: ObservationEnvelope) -> set[str]:
        batch = materialize_observation_envelope(envelope, task_id=task)
        return {str(item.draft.event_id) for item in batch.drafts if item.role == "result"}

    assert observation_event_ids_call_keyed(hook) and observation_event_ids_call_keyed(stream)
    assert result_events(hook) == result_events(stream) != set()
