"""The request identity of a ``publish_work`` call that omits ``request_id`` (ADR-050 decision 2).

Issue #1084 lets an agent leave ``request_id`` out of a publish body. The MCP bridge mints a fresh
``req_`` id for every such call: the bridge's own transport retries (reconnect, the timeout probe
and its replay) reuse it, and every result and error names it. Retrying an unknown outcome means
sending that id. Nothing is derived from the body, and nothing is resumed by content: whether an
identical body is a retry or a new publication is something only the caller knows (review R1 of
PR #1088), and a host cannot verify that a result reached the caller (review N1 of round 2).

What this module adds is a guard, never a guess. It remembers, in this bridge process only, each
writer's previous id-less publish whose outcome could have committed: a commitment over the
canonical body and the id it ran under. An id-less call whose body is identical to that previous
call is refused before anything is sent, naming the earlier id, so the caller chooses explicitly:
send that id to retry it, or a fresh ``request_id`` to publish the same facts again. The record
is replaced by the writer's next id-less publish, dropped by an explicit-id publish of that writer
that could have committed, cleared when the previous call was certainly rejected before any
append, and forgotten after one hour of monotonic time. Dry runs never touch it.

Because the guard lives in memory it cannot be corrupted, short-written, stale after a failed
cleanup, or expired early by a wall-clock step (review N2, N3, N5); another writer's calls never
displace a writer's record below the bound (N4); and an explicit-id call of another writer, or a
dry run, never drops it (N6). Across a bridge restart there is no guard: an identical id-less body
is then a new publication, which the guidance states.
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, cast

from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.ids import IdKind, is_valid_id

__all__ = [
    "PUBLISH_REPEAT_WINDOW_SECONDS",
    "PUBLISH_REPEAT_WRITER_LIMIT",
    "PublishRepeatGuard",
    "publish_body_commitment",
]

_BODY_DOMAIN: Final = b"finishup/publish-call/body/v2\x00"
# One hour of monotonic time: far longer than any retry, short enough that a much later identical
# publication is not refused.
PUBLISH_REPEAT_WINDOW_SECONDS: Final = 3_600.0
# Writers remembered per bridge process. A bridge serves one host session; its agent and the
# delegates it hosts use a handful of writers. Above the bound the least recently recorded writer's
# guard is forgotten, which only means its next identical id-less body is not refused.
PUBLISH_REPEAT_WRITER_LIMIT: Final = 4_096


@dataclass(frozen=True, slots=True)
class _Previous:
    commitment: str
    request_id: str
    at: float


def _scope(arguments: Mapping[str, object]) -> tuple[str, str] | None:
    session, writer = arguments.get("session_id"), arguments.get("writer_id")
    if (
        type(session) is str
        and is_valid_id(IdKind.SESSION, session)
        and type(writer) is str
        and is_valid_id(IdKind.WRITER, writer)
    ):
        return session, writer
    return None


def publish_body_commitment(arguments: Mapping[str, object]) -> str | None:
    """SHA-256 over the canonical body without ``request_id``; ``None`` when it has no form."""

    body = {key: value for key, value in arguments.items() if key != "request_id"}
    if any(type(key) is not str for key in body):
        return None
    try:
        encoded = canonical_encode(cast(JsonValue, body))
    except Exception:  # noqa: BLE001 - a body with no canonical form is simply not guarded
        return None
    return "sha256:" + hashlib.sha256(_BODY_DOMAIN + encoded).hexdigest()


class PublishRepeatGuard:
    """Each writer's previous id-less publish in this bridge process (see the module docstring).

    ``clock`` is a monotonic seconds source (a seam for tests); wall-clock steps never move it.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        window_seconds: float = PUBLISH_REPEAT_WINDOW_SECONDS,
        limit: int = PUBLISH_REPEAT_WRITER_LIMIT,
    ) -> None:
        self._clock = clock
        self._window = window_seconds
        self._limit = limit
        self._previous: OrderedDict[tuple[str, str], _Previous] = OrderedDict()

    def previous_request_id(self, arguments: Mapping[str, object]) -> str | None:
        """The id of this writer's previous id-less call when this body is identical to it."""

        scope = _scope(arguments)
        commitment = publish_body_commitment(arguments)
        if scope is None or commitment is None:
            return None
        previous = self._previous.get(scope)
        if previous is None:
            return None
        if self._clock() - previous.at > self._window:
            del self._previous[scope]
            return None
        return previous.request_id if previous.commitment == commitment else None

    def record(self, arguments: Mapping[str, object], request_id: str) -> None:
        """Remember an id-less call before it is sent; it replaces the writer's previous one."""

        scope = _scope(arguments)
        commitment = publish_body_commitment(arguments)
        if scope is None or commitment is None or not is_valid_id(IdKind.REQUEST, request_id):
            return
        self._previous.pop(scope, None)
        self._previous[scope] = _Previous(commitment, request_id, self._clock())
        while len(self._previous) > self._limit:
            self._previous.popitem(last=False)

    def rejected(self, arguments: Mapping[str, object], request_id: str) -> None:
        """The call recorded under ``request_id`` was certainly rejected before any append."""

        scope = _scope(arguments)
        if scope is None:
            return
        previous = self._previous.get(scope)
        if previous is not None and previous.request_id == request_id:
            del self._previous[scope]

    def explicit(self, arguments: Mapping[str, object]) -> None:
        """This writer sent an explicit-id publish that could have committed: it moved on."""

        scope = _scope(arguments)
        if scope is not None:
            self._previous.pop(scope, None)
