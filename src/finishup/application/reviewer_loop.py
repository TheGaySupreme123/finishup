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

At most three content-bearing reads, five read attempts, then only the final judgment. One format
repair for the whole review, for a completed answer that is not one JSON object or not a valid
reply, or for a read in the final phase of a review that started with reads. Such a review keeps
the full reply schema while a read can still be offered or repaired (#1172: the normal final turn
stays a cache hit), so after its reads end the loop appends ``FINAL_PHASE`` once; the repair turn,
and any final-phase turn after the review's one repair is spent, send the read-free schema, so a
route that enforces it can only return the judgment. A repair note never offers a read when the
next turn is final. A review whose first turn offers no read sends the read-free schema on every
turn and gets no notice. When the next exchange has no room left for the notice (only a first
exchange admitted inside the frame the notices need), the loop leaves it out. A second
malformed reply, a read after the repair or in a review that never offered one (only a route that
does not enforce the schema returns one), a revoked binding, a lost lease or the deadline ends the
review incomplete. Every model turn, the repair and every read is a durable job step, reserved
before it runs; a job that already holds steps is not resumed, except the one first turn that
waited for the owner before anything was sent (``resume_reserved``). A failed turn is never
retried.
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
from finishup.application.reviewer_broker import ReadExchangeFull, ReviewerBroker
from finishup.domain.reviewer_reads import MAX_REVIEWER_EXCHANGES
from finishup.ports.semantic import Deadline, ReviewStepRefused, SemanticJudgment
from finishup.protocol.canonical import JsonValue, canonical_encode

__all__ = ["ReviewOutcome", "ReviewerLoop", "ReviewerModel", "ReviewerModelError", "Turn"]

# Five read attempts, the final judgment and one format repair, on the original deadline.
MAX_MODEL_TURNS: Final = MAX_REVIEWER_EXCHANGES
LOCAL_READ_SECONDS: Final = 5.0
FORMAT_ERROR: Final = (
    "format_error: {code}. Reply with exactly one read action or final_judgment that matches the "
    "schema."
)
# The repair in the final phase never invites a read: none would be executed (#1173).
FINAL_FORMAT_ERROR: Final = (
    "format_error: {code}. No reads remain. Reply with final_judgment only, matching the schema."
)
# A read action returned in the final phase: the wire schema allows it, the controller does not.
FINAL_PHASE_READ: Final = "read_in_final_phase"
FINAL_PHASE: Final = "FinishUP: read allowance or time reserve reached. Return final_judgment now."
# #1242: a read whose exchange has no room is not served. The review asks for the judgment.
READ_NOT_SERVED: Final = "FinishUP: reviewer read not served: no room. Return final_judgment now."


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
    capacity: tuple[int, int] | None = None


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
        resume_reserved: bool = False,
    ) -> None:
        self.model, self.broker, self.store = model, broker, broker.store
        self.deadline, self.clock = deadline, clock
        self.instruction, self.packet = instruction, packet
        self.history_admissible = history_admissible
        self.reserve = final_reserve_seconds
        self.resume_reserved = resume_reserved
        self.messages: list[Turn] = []
        self.n_calls = 0

    async def run(self) -> ReviewOutcome:
        """Query the model and run its one read until the final judgment or an exit."""
        self.messages = [Turn("system", self.instruction), Turn("user", self.packet)]
        repaired = False
        final_phase = False
        read_closed = False
        offered: bool | None = None
        try:
            usage = await self.store.usage()
            # The caller proved the one reserved first turn waited for the owner and sent nothing;
            # it runs once more in that same reservation, never with a refilled budget.
            resumed = self.resume_reserved and usage == (1, 1)
            if usage[0] and not resumed:  # no other resume: an earlier run of this job ends it
                return self.exit("uncaptured_step" if usage[1] else "interrupted")
            while True:
                self.remaining()
                if self.n_calls >= MAX_MODEL_TURNS:
                    return self.exit("turn_limit")
                # Revocation wins: every binding the history holds is rechecked before each turn.
                if not await self.history_admissible(frozenset(self.broker.history_roots)):
                    return self.exit("authorization_changed")
                reads = (
                    not read_closed
                    and self.broker.reads_allowed()
                    and self.remaining() > self.reserve
                )
                if offered is None:
                    # A review that never offers a read (ask-every-time, or a first turn already
                    # inside the final reserve) keeps the read-free schema on every turn.
                    offered = reads
                # The provider caches the schema with the conversation (#1172), so a review that
                # started with reads keeps the full one while a late read can still be repaired.
                # Once its one repair is spent (the repair turn itself included), the final phase
                # sends the read-free schema: one cache miss, never a review ended by a read.
                schema = reviewer_reply_schema(
                    reads_allowed=offered and (reads or not repaired), strict=True
                )
                if offered and not reads and not final_phase:
                    # No room left for the notice (a first exchange admitted inside the frame the
                    # notices need) leaves it out, so it never pushes that exchange over the cap
                    # (#1172). That state is reached only after a malformed first answer, so the
                    # repair note already asks for the judgment and the turn is read-free.
                    if self.broker.notice_fits():
                        self.messages.append(Turn("user", FINAL_PHASE))
                    final_phase = True
                self.n_calls = turn = self.n_calls + 1
                if not (resumed and turn == 1):
                    await self.store.reserve("turn", turn, b"turn" if reads else b"final")
                self.remaining()
                invalid: ReviewerReplyInvalid | None = None
                try:
                    parsed = await self.model.complete(
                        tuple(self.messages), schema, deadline=self.deadline
                    )
                except ReviewerReplyInvalid as e:  # completed, but not one JSON object
                    invalid, parsed = e, None
                captured = {"invalid": invalid.code} if invalid is not None else parsed
                await self.store.capture(
                    "turn", turn, json.dumps(captured, sort_keys=True).encode()
                )
                self.remaining()  # an answer that arrives after the deadline is not used
                try:
                    if invalid is not None:
                        raise invalid
                    reply = decode_reviewer_reply(parsed)
                    if not reads and not isinstance(reply, SemanticJudgment):
                        # A review that started with reads keeps offering them on the wire, so a
                        # read in its final phase is that phase's format error: the one repair
                        # asks for the judgment. A read after the repair executes nothing and ends
                        # it, as does one a route returned against the read-free schema of a
                        # review that never offered one (there, ask-every-time, a repair would
                        # be another exchange needing its own approval).
                        if repaired or not offered:
                            return self.exit("read_limit")
                        raise ReviewerReplyInvalid(FINAL_PHASE_READ)
                except ReviewerReplyInvalid as e:
                    if repaired:
                        return self.exit("format_invalid")
                    # The note matches the next turn: never "a read action" before a final one.
                    reads_next = (
                        reads and self.broker.reads_allowed() and self.remaining() > self.reserve
                    )
                    template = FORMAT_ERROR if reads_next else FINAL_FORMAT_ERROR
                    repaired, note = True, template.format(code=e.code)
                    await self.store.reserve("repair", 1, e.code.encode())
                    await self.store.capture("repair", 1, note.encode())
                    self.messages.append(Turn("user", note))  # the malformed text is not echoed
                    continue
                # The validated reply exactly as the model returned it: a provider holding its own
                # copy of the thread (Codex) checks the history against it (unit 3).
                self.messages.append(Turn("assistant", canonical_encode(parsed).decode()))
                if isinstance(reply, SemanticJudgment):
                    return self.exit(None, reply)
                left = self.remaining() - self.reserve
                if left <= 0:
                    return self.exit("deadline")  # the model's turn spent the read's time
                stop_at = self.clock() + min(LOCAL_READ_SECONDS, left)
                try:
                    observation = await self.broker.execute(
                        reply,
                        lambda: self.clock() >= stop_at,
                        self.messages[-1].content,
                    )
                except ReadExchangeFull as e:
                    # The read action does not fit (#1242). Ask for the judgment. A second
                    # read after that notice still ends the review; nothing was read.
                    if read_closed:
                        return self.exit("case_capacity_exceeded", capacity=e.capacity)
                    read_closed = True
                    final_phase = True
                    self.messages.append(Turn("user", READ_NOT_SERVED))
                    continue
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

    def exit(
        self,
        code: str | None,
        judgment: SemanticJudgment | None = None,
        *,
        capacity: tuple[int, int] | None = None,
    ) -> ReviewOutcome:
        status: Literal["final", "incomplete"] = "final" if judgment is not None else "incomplete"
        texts = {ref: tuple(texts) for ref, texts in self.broker.text_by_ref.items()}
        refs = frozenset(self.broker.cited_refs)
        return ReviewOutcome(
            status, judgment, code, tuple(self.messages), self.n_calls, refs, texts, capacity
        )
