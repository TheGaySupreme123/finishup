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
second malformed reply, a read after the cap, a revoked binding or the deadline ends the review
incomplete. A failed model turn is never retried here.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Final, Literal, Protocol

from finishup.adapters.providers.reviewer_reply import (
    ReviewerReplyInvalid,
    decode_reviewer_reply,
    reviewer_reply_schema,
)
from finishup.application.reviewer_broker import ReviewerBroker
from finishup.ports.semantic import Deadline, SemanticJudgment
from finishup.protocol.canonical import JsonValue, canonical_encode

__all__ = ["ReviewOutcome", "ReviewerLoop", "ReviewerModel", "ReviewerModelError", "Turn"]

# Four normal completions (the first plus one per read) and the one format repair.
MAX_MODEL_TURNS: Final = 5
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
    """A failed, refused or uncertain model turn; ``code`` is closed and the review ends."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _Exit(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ReviewOutcome:
    status: Literal["final", "incomplete"]
    judgment: SemanticJudgment | None
    reason: str | None
    history: tuple[Turn, ...]
    model_turns: int


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
        self.model, self.broker, self.deadline, self.clock = model, broker, deadline, clock
        self.instruction, self.packet = instruction, packet
        self.history_admissible = history_admissible
        self.final_reserve_seconds = final_reserve_seconds
        self.messages: list[Turn] = []
        self.n_calls = 0
        self.repaired = False
        self.reads_offered = False

    def add_messages(self, *messages: Turn) -> None:
        self.messages.extend(messages)

    async def run(self) -> ReviewOutcome:
        """Run step() until the final judgment or an exit."""
        self.messages = []
        self.add_messages(Turn("system", self.instruction), Turn("user", self.packet))
        while True:
            try:
                judgment = await self.step()
            except ReviewerReplyInvalid as e:
                if self.repaired:
                    return self.exit("format_invalid")
                self.repaired = True
                self.add_messages(Turn("user", FORMAT_ERROR.format(code=e.code)))
                continue
            except (_Exit, ReviewerModelError) as e:
                return self.exit(e.code)
            if judgment is not None:
                return ReviewOutcome("final", judgment, None, tuple(self.messages), self.n_calls)

    def exit(self, code: str) -> ReviewOutcome:
        return ReviewOutcome("incomplete", None, code, tuple(self.messages), self.n_calls)

    async def step(self) -> SemanticJudgment | None:
        """Query the model, execute its read."""
        return await self.execute_actions(await self.query())

    async def query(self) -> JsonValue:
        if self.deadline.expired(self.clock()):
            raise _Exit("deadline")
        if self.n_calls >= MAX_MODEL_TURNS:
            raise _Exit("turn_limit")
        # Revocation wins: every binding the history holds is rechecked before each continuation.
        if not await self.history_admissible(frozenset(self.broker.history_roots)):
            raise _Exit("authorization_changed")
        reads = self.broker.reads_allowed() and (
            self.deadline.remaining_seconds(self.clock()) > self.final_reserve_seconds
        )
        self.n_calls += 1
        self.reads_offered = reads
        parsed = await self.model.complete(
            tuple(self.messages),
            reviewer_reply_schema(reads_allowed=reads, strict=True),
            deadline=self.deadline,
        )
        if self.deadline.expired(self.clock()):
            raise _Exit("deadline")  # an answer that arrives after the deadline is not used
        return parsed

    async def execute_actions(self, parsed: JsonValue) -> SemanticJudgment | None:
        """Decode the one reply; run a read and append its observation, or finish."""
        reply = decode_reviewer_reply(parsed)
        # The assistant turn is the validated reply exactly as the model returned it: a provider
        # holding its own copy of the thread (Codex) checks the history against it (unit 3).
        self.add_messages(Turn("assistant", canonical_encode(parsed).decode()))
        if isinstance(reply, SemanticJudgment):
            return reply
        if not self.reads_offered:
            raise _Exit("read_limit")  # no observation, no extra budget
        self.add_messages(Turn("user", await self.broker.execute(reply)))
        return None
