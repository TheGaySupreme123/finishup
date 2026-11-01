"""The in-memory repeat guard for id-less ``publish_work`` calls (issue #1084, ADR-050 decision 2).

Each case pins one rule: what is remembered, what refuses, and what forgets. The guard never
mints, resumes or persists anything; it only names the earlier id of an identical id-less call.
"""

from __future__ import annotations

from typing import Any

from finishup.mcp.publish_identity import (
    PUBLISH_REPEAT_WINDOW_SECONDS,
    PublishRepeatGuard,
    publish_body_commitment,
)
from finishup.protocol.ids import IdKind, new_id

_SESSION = "ses_00000000-0000-4000-8000-000000000001"
_WRITER = "wri_00000000-0000-4000-8000-000000000001"
_OTHER = "wri_00000000-0000-4000-8000-000000000002"
_FIRST = "req_00000000-0000-4000-8000-000000000001"
_SECOND = "req_00000000-0000-4000-8000-000000000002"


def _body(statement: str = "Keep it.", writer: str = _WRITER) -> dict[str, Any]:
    return {
        "session_id": _SESSION,
        "writer_id": writer,
        "event_drafts": [{"schema": {"name": "decision_recorded"}, "payload": {"s": statement}}],
    }


def test_an_identical_body_names_the_previous_id_and_nothing_else_does() -> None:
    guard = PublishRepeatGuard()
    guard.record(_body(), _FIRST)
    assert guard.previous_request_id(_body()) == _FIRST
    assert guard.previous_request_id({**_body(), "request_id": _SECOND}) == _FIRST
    assert guard.previous_request_id(_body("Other.")) is None
    assert guard.previous_request_id(_body(writer=_OTHER)) is None


def test_only_the_writers_most_recent_call_is_remembered() -> None:
    guard = PublishRepeatGuard()
    guard.record(_body("A."), _FIRST)
    guard.record(_body("B."), _SECOND)
    assert guard.previous_request_id(_body("A.")) is None
    assert guard.previous_request_id(_body("B.")) == _SECOND


def test_a_certain_rejection_forgets_only_that_call() -> None:
    guard = PublishRepeatGuard()
    guard.record(_body(), _FIRST)
    guard.rejected(_body(), _SECOND)
    assert guard.previous_request_id(_body()) == _FIRST
    guard.rejected(_body(), _FIRST)
    assert guard.previous_request_id(_body()) is None


def test_an_explicit_publish_forgets_only_its_own_writer() -> None:
    guard = PublishRepeatGuard()
    guard.record(_body(), _FIRST)
    guard.explicit(_body(writer=_OTHER))
    assert guard.previous_request_id(_body()) == _FIRST
    guard.explicit(_body())
    assert guard.previous_request_id(_body()) is None


def test_the_window_runs_on_the_injected_monotonic_clock() -> None:
    now = [100.0]
    guard = PublishRepeatGuard(clock=lambda: now[0])
    guard.record(_body(), _FIRST)
    now[0] += PUBLISH_REPEAT_WINDOW_SECONDS
    assert guard.previous_request_id(_body()) == _FIRST
    now[0] += 1
    assert guard.previous_request_id(_body()) is None


def test_the_writer_bound_drops_the_least_recently_recorded_writer() -> None:
    guard = PublishRepeatGuard(limit=3)
    writers = [new_id(IdKind.WRITER) for _ in range(4)]
    for writer in writers:
        guard.record(_body(writer=writer), new_id(IdKind.REQUEST))
    assert guard.previous_request_id(_body(writer=writers[0])) is None
    assert all(guard.previous_request_id(_body(writer=w)) is not None for w in writers[1:])


def test_unscoped_or_uncanonical_bodies_are_not_remembered() -> None:
    guard = PublishRepeatGuard()
    guard.record({**_body(), "session_id": "nope"}, _FIRST)
    assert guard.previous_request_id({**_body(), "session_id": "nope"}) is None
    assert publish_body_commitment({**_body(), "x": 1.5}) is None
    guard.record(_body(), "not-a-request-id")
    assert guard.previous_request_id(_body()) is None
