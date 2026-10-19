# Adapted from mini-swe-agent's DefaultAgent (src/minisweagent/agents/default.py at
# 40fa36522015a6bc6cf14411382b662b42083bf1, https://github.com/SWE-agent/mini-swe-agent).
# Its shell environment, model framework, templating and trajectory logging are removed; the
# action is one structured read or the final judgment. Provenance: ADR-006, #1118 unit 2.
#
# MIT License
#
# Copyright (c) 2025 Kilian A. Lieret and Carlos E. Jimenez
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""The reviewer loop: a linear history, one read or the final judgment per turn (#1118 unit 2).

At most three reads, then only the final judgment. One format repair for the whole review; a
second malformed reply, a read after the cap, a revoked binding, a lost lease or the deadline ends
the review incomplete. Every model turn, the repair and every read is a durable job step, reserved
before it runs; a job that already holds steps is not resumed. A failed turn is never retried.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal, Protocol

from finishup.adapters.providers.reviewer_reply import (
    ReviewerReplyInvalid,
    decode_reviewer_reply,
    reviewer_reply_schema,
)
from finishup.adapters.task_input_read import ReadDeadline
from finishup.application.reviewer_broker import ReviewerBroker
from finishup.ports.semantic import Deadline, ReviewStepRefused, SemanticJudgment
from finishup.protocol.canonical import JsonValue, canonical_encode

__all__ = ["ReviewOutcome", "ReviewerLoop", "ReviewerModel", "ReviewerModelError", "Turn"]

# Four normal completions (the first plus one per read) and the one format repair.
MAX_MODEL_TURNS: Final = 5
LOCAL_READ_SECONDS: Final = 5.0
FORMAT_ERROR: Final = (
    "format_error: {code}. Reply with exactly one read action or final_judgment that matches the "
    "schema."
)


@dataclass(frozen=True, slots=True)
class Turn:
    role: Literal["system", "user", "assistant"]
    content: str


class ReviewerModel(Protocol):
    """One structured completion over the whole history; bound to one job, route and deadline."""

    async def complete(
        self, history: Sequence[Turn], schema: dict[str, JsonValue], *, deadline: Deadline
    ) -> JsonValue: ...


class ReviewerModelError(Exception):
    """A failed, refused or uncertain model turn, or a stop; ``code`` is closed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ReviewOutcome:
    """The loop's end. ``citable_refs``/``text_by_ref`` are the packet and read citation union."""

    status: Literal["final", "incomplete"]
    judgment: SemanticJudgment | None
    reason: str | None
    history: tuple[Turn, ...]
    model_turns: int
    citable_refs: frozenset[str]
    text_by_ref: Mapping[str, tuple[str, ...]]


class ReviewerLoop:
    def __init__(
        self,
        model: ReviewerModel,
        broker: ReviewerBroker,
        *,
        instruction: str,
        packet: str,
        deadline: Deadline,
        history_admissible: Callable[[frozenset[str]], Awaitable[bool]],
        final_reserve_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.model, self.broker, self.store = model, broker, broker.store
        self.deadline, self.clock = deadline, clock
        self.instruction, self.packet = instruction, packet
        self.history_admissible = history_admissible
        self.reserve = final_reserve_seconds
        self.messages: list[Turn] = []
        self.n_calls = 0

    async def run(self) -> ReviewOutcome:
        """Query the model and run its one read until the final judgment or an exit."""
        self.messages = [Turn("system", self.instruction), Turn("user", self.packet)]
        repaired = False
        try:
            steps, uncaptured = await self.store.usage()
            if steps:  # no resume in v1: an earlier run of this job ends it
                return self.exit("uncaptured_step" if uncaptured else "interrupted")
            while True:
                self.remaining()
                if self.n_calls >= MAX_MODEL_TURNS:
                    return self.exit("turn_limit")
                # Revocation wins: every binding the history holds is rechecked before each turn.
                if not await self.history_admissible(frozenset(self.broker.history_roots)):
                    return self.exit("authorization_changed")
                reads = self.broker.reads_allowed() and self.remaining() > self.reserve
                self.n_calls = turn = self.n_calls + 1
                await self.store.reserve("turn", turn, b"turn" if reads else b"final")
                self.remaining()
                schema = reviewer_reply_schema(reads_allowed=reads, strict=True)
                parsed = await self.model.complete(
                    tuple(self.messages), schema, deadline=self.deadline
                )
                await self.store.capture("turn", turn, json.dumps(parsed, sort_keys=True).encode())
                self.remaining()  # an answer that arrives after the deadline is not used
                try:
                    reply = decode_reviewer_reply(parsed)
                except ReviewerReplyInvalid as e:
                    if repaired:
                        return self.exit("format_invalid")
                    repaired, note = True, FORMAT_ERROR.format(code=e.code)
                    await self.store.reserve("repair", 1, e.code.encode())
                    await self.store.capture("repair", 1, note.encode())
                    self.messages.append(Turn("user", note))  # the malformed text is not echoed
                    continue
                # The validated reply exactly as the model returned it: a provider holding its own
                # copy of the thread (Codex) checks the history against it (unit 3).
                self.messages.append(Turn("assistant", canonical_encode(parsed).decode()))
                if isinstance(reply, SemanticJudgment):
                    return self.exit(None, reply)
                if not reads:
                    return self.exit("read_limit")  # no observation, no extra budget
                left = self.remaining() - self.reserve
                if left <= 0:
                    return self.exit("deadline")  # the model's turn spent the read's time
                stop_at = self.clock() + min(LOCAL_READ_SECONDS, left)
                observation = await self.broker.execute(reply, lambda: self.clock() >= stop_at)
                self.remaining()
                self.messages.append(Turn("user", observation))
        except ReviewerModelError as e:
            return self.exit(e.code)
        except ReadDeadline:
            return self.exit("deadline")
        except ReviewStepRefused:
            return self.exit("step_refused")

    def remaining(self) -> float:
        """Seconds left; the deadline is checked after every await, never consumed late."""
        now = self.clock()
        if self.deadline.expired(now):
            raise ReviewerModelError("deadline")
        return self.deadline.remaining_seconds(now)

    def exit(self, code: str | None, judgment: SemanticJudgment | None = None) -> ReviewOutcome:
        status: Literal["final", "incomplete"] = "final" if judgment is not None else "incomplete"
        texts = {ref: tuple(texts) for ref, texts in self.broker.text_by_ref.items()}
        refs = frozenset(self.broker.cited_refs)
        return ReviewOutcome(
            status, judgment, code, tuple(self.messages), self.n_calls, refs, texts
        )
