"""What one reviewer conversation did, as one bounded record every surface renders alike (#1118).

The service builds the record from its own durable conversation: the result envelopes its broker
issued and the disclosure receipt of each exchange that carried them. Its wire form holds only
closed tokens, counts, byte sizes, digests, service-issued root aliases (``w1``, ``o1``, ``s1``)
and opaque identities: never a path, an argument or any read text. A file read's ``source`` is a
keyed commitment of its root alias and path within the review job, so two reads of one file share
it and reads of two files do not. Paths stay in the encrypted review response; the check, status,
MCP, CLI, TUI and receipt surfaces render the same lines from the same record.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, cast

__all__ = [
    "MAX_REVIEWER_READS",
    "ReviewerRead",
    "ReviewerRecord",
    "render_reviewer_lines",
    "reviewer_record_from_wire",
]

MAX_REVIEWER_READS: Final = 3
_ACTIONS: Final = frozenset({"read_packet_section", "read_ledger", "read_file"})
_STATUSES: Final = frozenset({"ok", "partial", "unavailable", "denied", "stale"})
_STANDINGS: Final = frozenset(
    {
        "task_transcription",
        "agent_assertion",
        "finishup_record",
        "workspace_content",
        "outside_input_mutable",
        "outside_input_snapshot",
    }
)
_BASELINES: Final = frozenset({"task_start", "admission_time", "check_time", "read_time"})
_TOKEN: Final = re.compile(r"[a-z][a-z0-9_]{0,95}")
_ALIAS: Final = re.compile(r"[a-z][0-9]{1,2}")
_SOURCE: Final = re.compile(r"(?:src_[0-9a-f]{24}|[A-Za-z0-9][A-Za-z0-9._:-]{0,127})")
_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}")
_RECEIPT: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


@dataclass(frozen=True, slots=True)
class ReviewerRead:
    """One read the reviewer asked for and what the service sent back."""

    call: int
    action: str
    status: str
    reason: str | None
    source: str | None
    root: str | None
    standing: str | None
    baseline: str | None
    lines: tuple[int, int] | None
    result_bytes: int
    result_digest: str
    # The privacy receipt of the exchange that first carried this result to the reviewer; None
    # when the conversation ended before any exchange carried it.
    disclosure: str | None

    def __post_init__(self) -> None:
        if (
            type(self.call) is not int
            or not 1 <= self.call <= MAX_REVIEWER_READS
            or self.action not in _ACTIONS
            or self.status not in _STATUSES
            or not _optional(self.reason, _TOKEN)
            or not _optional(self.source, _SOURCE)
            or not _optional(self.root, _ALIAS)
            or (self.standing is not None and self.standing not in _STANDINGS)
            or (self.baseline is not None and self.baseline not in _BASELINES)
            or type(self.result_bytes) is not int
            or not 0 <= self.result_bytes <= 8192
            or not _DIGEST.fullmatch(self.result_digest)
            or not _optional(self.disclosure, _RECEIPT)
        ):
            raise ValueError("reviewer_read_invalid")
        if self.lines is not None and not (
            type(self.lines) is tuple
            and len(self.lines) == 2
            and all(type(n) is int and n >= 1 for n in self.lines)
            and self.lines[0] <= self.lines[1]
        ):
            raise ValueError("reviewer_read_invalid")

    def as_wire(self) -> dict[str, object]:
        return {
            "call": str(self.call),
            "action": self.action,
            "status": self.status,
            "reason": self.reason,
            "source": self.source,
            "root": self.root,
            "standing": self.standing,
            "baseline": self.baseline,
            "lines": None if self.lines is None else [str(n) for n in self.lines],
            "result_bytes": str(self.result_bytes),
            "result_digest": self.result_digest,
            "disclosure": self.disclosure,
        }


@dataclass(frozen=True, slots=True)
class ReviewerRecord:
    """One review conversation: its exchanges, reads, why it ended and its runtime cleanup.

    ``ended`` is ``None`` for a conversation that returned its final judgment, else the closed
    reason the loop stopped. ``cleanup`` is the held provider session's cleanup outcome (a Codex
    thread); ``None`` when the route held nothing between exchanges.
    """

    exchanges: int
    reads: tuple[ReviewerRead, ...]
    ended: str | None
    cleanup: str | None

    def __post_init__(self) -> None:
        if (
            type(self.exchanges) is not int
            or not 0 <= self.exchanges <= 5
            or type(self.reads) is not tuple
            or len(self.reads) > MAX_REVIEWER_READS
            or any(type(read) is not ReviewerRead for read in self.reads)
            or [read.call for read in self.reads] != list(range(1, len(self.reads) + 1))
            or not _optional(self.ended, _TOKEN)
            or not _optional(self.cleanup, _TOKEN)
        ):
            raise ValueError("reviewer_record_invalid")

    def as_wire(self) -> dict[str, object]:
        """Counts are canonical decimal strings, like every other count on the wire."""

        return {
            "exchanges": str(self.exchanges),
            "reads_used": str(len(self.reads)),
            "read_bytes": str(sum(read.result_bytes for read in self.reads)),
            "reads": [read.as_wire() for read in self.reads],
            "ended": self.ended,
            "cleanup": self.cleanup,
        }


def _optional(value: object, pattern: re.Pattern[str]) -> bool:
    return value is None or (type(value) is str and pattern.fullmatch(value) is not None)


def _count(value: object) -> int:
    if type(value) is not str or not value.isdigit() or len(value) > 6:
        raise ValueError("reviewer_record_invalid")
    return int(value)


def reviewer_record_from_wire(value: object) -> ReviewerRecord | None:
    """The record a wire form describes; ``None`` for anything else (an older response)."""

    if not isinstance(value, Mapping):
        return None
    body = cast(Mapping[str, object], value)
    try:
        reads = tuple(
            ReviewerRead(
                call=_count(row["call"]),
                action=cast(str, row["action"]),
                status=cast(str, row["status"]),
                reason=cast(str | None, row["reason"]),
                source=cast(str | None, row["source"]),
                root=cast(str | None, row["root"]),
                standing=cast(str | None, row["standing"]),
                baseline=cast(str | None, row["baseline"]),
                lines=None
                if row["lines"] is None
                else cast(
                    tuple[int, int], tuple(_count(n) for n in cast(Sequence[object], row["lines"]))
                ),
                result_bytes=_count(row["result_bytes"]),
                result_digest=cast(str, row["result_digest"]),
                disclosure=cast(str | None, row["disclosure"]),
            )
            for row in cast(Sequence[Mapping[str, object]], body["reads"])
        )
        record = ReviewerRecord(
            _count(body["exchanges"]),
            reads,
            cast(str | None, body["ended"]),
            cast(str | None, body["cleanup"]),
        )
    except KeyError, TypeError, ValueError:
        return None
    return record


def render_reviewer_lines(record: ReviewerRecord | None) -> tuple[str, ...]:
    """Plain lines for text surfaces: one summary line, then one line per read."""

    if record is None:
        return ()
    used = len(record.reads)
    total = sum(read.result_bytes for read in record.reads)
    head = (
        f"Reviewer reads: {used} of {MAX_REVIEWER_READS}, {total} bytes, "
        f"{record.exchanges} model exchange{'s' if record.exchanges != 1 else ''}"
    )
    if record.ended is not None:
        head += f"; ended early: {record.ended}"
    lines = [head]
    for read in record.reads:
        line = f"- {read.call}. {read.action}: {read.status}"
        if read.reason is not None:
            line += f" {read.reason}"
        where = [part for part in (read.root, read.source) if part is not None]
        if where:
            line += f" [{' '.join(where)}]"
        if read.standing is not None:
            line += f" ({read.standing}, {read.baseline})"
        if read.lines is not None:
            line += f" lines {read.lines[0]}-{read.lines[1]}"
        line += f", {read.result_bytes} bytes"
        line += (
            f", sent under receipt {read.disclosure}"
            if read.disclosure is not None
            else ", not sent"
        )
        lines.append(line)
    return tuple(lines)
