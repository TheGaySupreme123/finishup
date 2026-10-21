"""The reviewer's three reads, bounded and admitted like the packet (#1118 unit 2, ADR-006).

``read_packet_section`` and ``read_ledger`` read records the case builder already rendered into the
frozen review case, including what the bounded packet cut. ``read_file`` reads a line span or one
directory listing beneath a service-issued root alias: the workspace, an owner-admitted outside
root limited to the task-declared paths, or a snapshot of one. A result is fitted into its byte
room first (a listed entry is whole or left for the cursor, never shortened); then each element it
carries is admitted unchanged, and its exact encoding is scanned. Spans, cursors and citable text
come from what was fitted and sent, nothing else. A read that completes past its local stop is
discarded, not used; that is a check after each blocking call, not preemption of one. At most three
reads, 8 KiB each and 24 KiB in all, each reserved durably before it runs and never refunded.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Literal, cast

from finishup.adapters.task_input_read import (
    ReadDeadline,
    clear_cut,
    list_beneath,
    read_text_beneath,
)
from finishup.ports.change_capture import TaskInputSnapshotSet
from finishup.ports.semantic import (
    ReviewStepStore,
    SemanticCase,
    SemanticCaseItem,
    reviewer_message_bytes,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.models import (
    DataCategory,
    ReadFileListArgsModel,
    ReadFileTextArgsModel,
    ReadLedgerArgsModel,
    ReadPacketSectionArgsModel,
    ReviewerActionModel,
    ReviewerFileActionModel,
)

__all__ = ["MAX_READS", "ReadElement", "ReadExchangeFull", "ReadRoot", "ReviewerBroker"]

MAX_READS: Final = 3
MAX_RESULT_BYTES: Final = 8192
MAX_TOTAL_BYTES: Final = 24_576
# Past any envelope without data, as the exchange carries it; below it only the final judgment
# remains.
MIN_ROOM: Final = 1024
# What an ordinary read action adds to its exchange, at most (#1118): offering a read leaves it.
READ_ACTION_ROOM: Final = 1024
_TEXT_BYTES: Final = 6144
_MAX_RECORDS: Final = 8
_PACKET_SECTIONS: Final = {
    "task_statement": {"task_statement"},
    "excerpts": {"excerpt"},
    "deterministic_findings": {"deterministic_summary", "deterministic_detail"},
    "agent_account": {"goal", "obligation", "claim", "decision"},
    "prior_findings": {"prior_finding"},
    "timeline": {"timeline"},
}
# A ledger view matches a rendered record by its case section or its source kind.
_LEDGER_VIEWS: Final = {
    "findings": {"finding", "prior_finding", "deterministic_detail"},
    "observations": {"evidence", "diff"},
    "claims": {"claim"},
    "plan": {"goal"},
    "obligations": {"obligation"},
    "command_output": {"command", "test", "failure"},
}

# What admission sees of a result: each element's category, exact bytes and outside root.
type ReadElement = tuple[DataCategory, bytes, str | None]
type _Selected = (
    tuple[str, list[_Piece], tuple[str, str, int] | None, int] | tuple[str, str] | _WithheldRead
)


@dataclass(frozen=True, slots=True)
class _WithheldRead:
    size: int


class ReadExchangeFull(Exception):
    """The read action alone left its exchange no room for even a result without data (#1118).

    Raised before the read is reserved; nothing is read and that exchange is never sent."""

    def __init__(self, required: int, available: int) -> None:
        super().__init__("reviewer_read_exchange_full")
        self.capacity = (required, available)


@dataclass(frozen=True, slots=True)
class ReadRoot:
    """One ``read_file`` alias the service issued; the model names only ``alias``.

    ``path`` is the directory read beneath; ``input_root`` the owner-admitted outside root it
    binds (E2E-2), with ``declared`` the task-declared paths beneath it. A ``snapshot`` serves the
    files FinishUP kept instead of current ones. ``refuse`` is the service's ignored-path rule.
    """

    alias: str
    path: str
    input_root: str | None = None
    declared: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()
    subject_refs: tuple[str, ...] = ()
    snapshot: TaskInputSnapshotSet | None = None
    refuse: Callable[[str], bool] | None = None


@dataclass(slots=True)
class _Piece:
    """One content-bearing element of a result, ``source[start:end]``; ``end < stop`` is a cut.

    A listed entry (``ref`` its kind) is never cut: it is sent whole or left for the cursor.
    """

    source: bytes
    start: int
    stop: int
    citable: tuple[str, ...]
    prov: dict[str, JsonValue]
    ref: str = ""  # a record's ref, or a listed entry's kind
    line: int | None = None
    root: str | None = None
    category: DataCategory = DataCategory.REPOSITORY_EXCERPT
    truncation_reason: str | None = None
    end: int = field(init=False)

    def __post_init__(self) -> None:
        self.end = self.stop

    @property
    def text(self) -> bytes:
        return self.source[self.start : self.end]


class ReviewerBroker:
    """Executes one validated read per call; the step store holds the durable reservations."""

    def __init__(
        self,
        *,
        job_id: str,
        case: SemanticCase,
        roots: Sequence[ReadRoot],
        store: ReviewStepStore,
        admit: Callable[[tuple[ReadElement, ...], bytes], Awaitable[str | None]],
        packet_refs: frozenset[str] = frozenset(),
        packet_text: Mapping[str, tuple[str, ...]] | None = None,
        max_reads: int = MAX_READS,
        exchange_room: Callable[[], int | None] = lambda: None,
    ) -> None:
        self.store, self._job, self._case, self._admit = store, job_id, case, admit
        # #1118: the bytes the conversation's next exchange may still add under the disclosure
        # cap (``None`` when unbounded). A result is fitted to what is left of it after the read
        # action, measured as the exchange encodes both, escaping included.
        self._exchange_room = exchange_room
        self._max_reads = min(max_reads, MAX_READS)
        # The read bytes this review may still add; the conversation lowers it to fit the channel.
        self.total = MAX_TOTAL_BYTES
        self._roots = {root.alias: root for root in roots}
        self._allowed = frozenset(case.frontier_refs | case.local_check_refs)
        self._cursors: dict[str, tuple[str, str, int]] = {}
        self.calls = self.used = 0
        # Every outside root the conversation holds bytes from; rechecked before each turn.
        self.history_roots: set[str] = set(dict(case.input_roots).values())
        # The citation union: the packet as sent, then every admitted read as sent.
        self.cited_refs = set(packet_refs)
        self.text_by_ref = {ref: list(texts) for ref, texts in (packet_text or {}).items()}

    def reads_allowed(self) -> bool:
        # A read is offered only while its exchange can carry a read action of ordinary size
        # (``READ_ACTION_ROOM``) beside a result without data; a longer action ends the review
        # unsent (``ReadExchangeFull``) rather than outgrow the cap.
        room = self._exchange_room()
        return (
            self.calls < self._max_reads
            and self.total - self.used >= MIN_ROOM
            and (room is None or room >= MIN_ROOM + READ_ACTION_ROOM)
        )

    async def execute(
        self, action: ReviewerActionModel, expired: Callable[[], bool], reply: str = ""
    ) -> str:
        """Reserve the next read, run it, fit and admit it; return the result envelope.

        ``reply`` is the assistant turn that asked for the read, exactly as the conversation
        carries it: the result travels in the same exchange, so it gets only what the reply
        leaves of that exchange's room.
        """

        left = self._exchange_room()
        if left is not None:
            required = reviewer_message_bytes("assistant", reply) + MIN_ROOM
            available = left
            left -= reviewer_message_bytes("assistant", reply)
            if left < MIN_ROOM:
                raise ReadExchangeFull(required, available)
        ordinal = self.calls + 1
        await self.store.reserve("read", ordinal, canonical_encode(action.model_dump(mode="json")))
        self.calls, tool_ref, args = ordinal, f"{self._job}:read:{ordinal}", action.args
        if isinstance(action, ReviewerFileActionModel):
            selected = self._file(action.args, expired, tool_ref)
        elif isinstance(args, ReadLedgerArgsModel):
            selected = self._ledger(args.view, args.refs, args.cursor)
        else:
            selected = self._packet(cast(ReadPacketSectionArgsModel, args))
        if expired():  # completed past its local stop: discarded, never retained or sent
            raise ReadDeadline("reviewer_read_deadline")
        room = min(MAX_RESULT_BYTES, args.max_bytes, self.total - self.used)
        encoded = await self._result(tool_ref, ordinal, selected, room, left)
        self.used += len(encoded)
        await self.store.capture("read", ordinal, encoded)
        return encoded.decode()

    async def _result(
        self,
        tool_ref: str,
        ordinal: int,
        selected: _Selected,
        room: int,
        exchange_left: int | None = None,
    ) -> bytes:
        """Fit the selection into ``room``, admit exactly what fits, and record what was sent.

        With ``exchange_left``, what the result adds to its exchange (``reviewer_message_bytes``)
        must fit that too; an envelope without data always does (``MIN_ROOM``).
        """

        def over_by(encoded: bytes) -> int:
            over = len(encoded) - room
            if exchange_left is None:
                return over
            return max(over, reviewer_message_bytes("user", encoded.decode()) - exchange_left)

        def envelope(
            status: str,
            reason: str | None = None,
            data: JsonValue = None,
            refs: list[str] | None = None,
            cursor: str | None = None,
        ) -> bytes:
            body: dict[str, JsonValue] = {
                "tool_ref": tool_ref,
                "call_index": ordinal,
                "status": status,
                "reason": reason,
                "snapshot_ref": tool_ref if data is not None and file else self._case.case_id,
                "citable_refs": list[JsonValue](refs or ()),
                "truncated": status == "partial",
                "next_cursor": cursor,
                "calls_remaining": MAX_READS - ordinal,
                "data": data,
                "result_digest": canonical_digest(data),
            }
            if reason == "not_in_frozen_case":
                body["continuation"] = (
                    "This frozen lookup does not establish that the item was never recorded. "
                    "Request the needed content in final_judgment.missing_for_assessment with "
                    "the appropriate kind and target_refs; a later check must freeze it."
                )
            encoded, size = b"", 0
            for _ in range(8):  # the length fixed point: the size and the remainder's digits
                body["result_utf8_bytes"] = size
                body["bytes_remaining"] = max(0, self.total - self.used - size)
                encoded = canonical_encode(body)
                if len(encoded) == size:
                    break
                size = len(encoded)
            return encoded

        if isinstance(selected, _WithheldRead):
            file = True
            return envelope("partial", "native_read_limit", {"source_bytes": selected.size})
        if len(selected) == 2:
            return envelope(*selected)
        shape, pieces, page, left = selected
        count, file = len(pieces), pieces[0].prov["root_id"] is not None
        for piece in pieces if shape != "list" else ():  # an even share of the text room first
            share = min(_TEXT_BYTES, room) // count
            piece.end = _clear(piece.source, min(piece.stop, piece.start + share), "head")
        refs, cites, cursor, encoded = list[str](), dict[str, list[str]](), None, b""

        def fitted(pieces: list[_Piece]) -> bytes:
            nonlocal refs, cites, cursor
            more = left > 0 or len(pieces) < count
            reason = next((p.truncation_reason for p in pieces if p.truncation_reason), None)
            cut = more or reason is not None or any(piece.end < piece.stop for piece in pieces)
            data, cites = _data(shape, pieces)
            refs = sorted(cites)[:16]  # the citation is what the result advertises, nothing more
            cursor = f"c{ordinal}" if page is not None and more else None
            return envelope("partial" if cut else "ok", reason, data, refs, cursor)

        while pieces := [piece for piece in pieces if piece.end > piece.start]:
            encoded = fitted(pieces)
            over = over_by(encoded)
            if over <= 0:
                break
            last = pieces[-1]
            if shape == "list" or (len(pieces) > 1 and last.end - last.start <= over + 64):
                pieces.pop()
                continue
            # The longest head of the last piece that fits, measured: escaping makes one text
            # byte cost several result and exchange bytes, so cutting ``over`` text bytes would
            # discard far more than the excess (#1118). An empty head drops the piece.
            fits, short = last.start, last.end
            while short - fits > 1:
                middle = (fits + short) // 2
                last.end = _clear(last.source, middle, "head")
                if last.end > fits and over_by(fitted(pieces)) <= 0:
                    fits = last.end
                else:
                    short = middle
            last.end = fits
        else:
            return envelope("unavailable", "byte_budget")
        elements = tuple((piece.category, piece.text, piece.root) for piece in pieces)
        reason = await self._admit(elements, encoded)
        if reason is not None:
            return envelope("denied", reason)
        if page is not None and cursor is not None:  # resumes at the first entry not sent
            self._cursors[cursor] = (page[0], page[1], page[2] + len(pieces))
        for ref in refs:  # only what the result carries is citable or binds the history
            self.cited_refs.add(ref)
            self.text_by_ref.setdefault(ref, []).extend(cites[ref])
        self.history_roots.update(piece.root for piece in pieces if piece.root is not None)
        return encoded

    def _page(self, selector: str, version: str, cursor: str | None) -> int | tuple[str, str]:
        """The offset a cursor this broker issued names; a forged or rebound one is refused."""

        bound = (selector, version, 0) if cursor is None else self._cursors.get(cursor)
        if bound is None or bound[0] != selector:
            return ("denied", "invalid_request")
        return bound[2] if bound[1] == version else ("stale", "source_changed")

    def _item(self, item: SemanticCaseItem, offset: int) -> _Piece:
        standing = (
            "agent_assertion"
            if item.section in _PACKET_SECTIONS["agent_account"]
            else "finishup_record"
        )
        if item.section == "task_statement":
            standing = "task_transcription"
        prov: dict[str, JsonValue] = {
            "source_ref": item.item_id,
            "root_id": None,
            "baseline": "check_time",
            "standing": standing,
        }
        refs = tuple(r for r in (item.source_ref, *item.linked_subject_refs) if r in self._allowed)
        start, stop = _clear(item.content, offset, "tail"), len(item.content)
        root = dict(self._case.input_roots).get(item.item_id)
        return _Piece(
            item.content, start, stop, refs, prov, item.item_id, None, root, item.category
        )

    def _packet(self, args: ReadPacketSectionArgsModel) -> _Selected:
        item = next((i for i in self._case.items if i.item_id == args.item_ref), None)
        if (
            item
            and item.section in _PACKET_SECTIONS[args.section]
            and args.offset < len(item.content)
        ):
            return ("text", [self._item(item, args.offset)], None, 0)
        return ("unavailable", "not_retained")

    def _ledger(self, view: str, refs: tuple[str, ...], cursor: str | None) -> _Selected:
        kinds, wanted = _LEDGER_VIEWS[view], set(refs)
        matched = [
            i
            for i in self._case.items
            if (i.section in kinds or i.source_kind in kinds)
            and (i.source_ref in wanted or wanted & set(i.linked_subject_refs))
        ]
        selector, version = "\x00".join((view, *sorted(refs))), self._case.case_id
        start = self._page(selector, version, cursor)
        if isinstance(start, tuple):
            return start
        page = matched[start : start + _MAX_RECORDS]
        if not page:
            # A case is a bounded selection, not the entire ledger. Do not consult mutable
            # storage or turn absence from this frozen selection into a claim of non-recording.
            return ("unavailable", "not_in_frozen_case")
        left = len(matched) - start - len(page)
        return ("records", [self._item(i, 0) for i in page], (selector, version, start), left)

    @staticmethod
    def _refused(root: ReadRoot, path: str) -> str | None:
        if root.refuse is not None and root.refuse(path):
            return "forbidden_path"
        inside = any(d == "" or path == d or path.startswith(f"{d}/") for d in root.declared)
        return "outside_scope" if root.declared and not inside else None

    def _file(
        self,
        args: ReadFileTextArgsModel | ReadFileListArgsModel,
        expired: Callable[[], bool],
        tool_ref: str,
    ) -> _Selected:
        root, path = self._roots.get(args.root_id), args.path.removeprefix("./").rstrip("/")
        path = "" if path == "." else path
        if root is None or path.startswith("/") or "\0" in path:
            return ("denied", "forbidden_path")
        if path and any(part[:1] in {"", "."} for part in path.split("/")):
            return ("denied", "forbidden_path")  # hidden, empty or traversing components
        refused = self._refused(root, path)
        if refused is not None:
            return ("denied", refused)
        prefix, snap = root.path.rstrip("/") + "/", root.snapshot
        kept = {
            f.path.removeprefix(prefix): f.text
            for f in (snap.files if snap else ())
            if f.path.startswith(prefix)
        }
        standing = "workspace_content" if root.input_root is None else "outside_input_mutable"
        prov: dict[str, JsonValue] = {
            "source_ref": tool_ref,
            "root_id": root.alias,
            "baseline": snap.boundary if snap else "read_time",
            "standing": "outside_input_snapshot" if snap else standing,
        }
        refs = tuple(r for r in root.subject_refs if r in self._allowed)
        if isinstance(args, ReadFileListArgsModel):
            below = f"{path}/" if path else ""
            if snap is None:
                listing = list_beneath(root.path, path, excluded=root.excluded, expired=expired)
                listed, truncated = listing if listing is not None else ((), False)
            else:
                names = {m[len(below) :].split("/")[0] for m in kept if m.startswith(below)}
                listed = tuple(sorted((n, f"{below}{n}" not in kept) for n in names))
                truncated = False
            children = [(n, d) for n, d in listed or () if not self._refused(root, below + n)]
            selector = f"{root.alias}\x00{path}"
            version = canonical_digest([[[n, d] for n, d in children], truncated])
            start = self._page(selector, version, args.cursor)
            if isinstance(start, tuple):
                return start
            page = children[start : start + args.max_entries]
            if not page:
                if truncated:
                    return ("partial", "inspection_limit")
                return ("unavailable", "not_recorded")
            kinds = [(n.encode(), "directory" if d else "file") for n, d in page]
            pieces = [_Piece(n, 0, len(n), refs, prov, k, None, root.input_root) for n, k in kinds]
            if truncated:
                for piece in pieces:
                    piece.truncation_reason = "inspection_limit"
            return ("list", pieces, (selector, version, start), len(children) - start - len(page))
        if snap is not None:
            read = None if path not in kept else (kept[path], len(kept[path]))
        else:
            read = read_text_beneath(root.path, path, excluded=root.excluded, expired=expired)
        if read is None:
            return ("unavailable", "not_recorded")
        data, size = read
        if size > len(data):
            return _WithheldRead(size)
        starts = [0, *(m.end() for m in re.finditer(b"\n", data))]
        first, last = args.start_line - 1, args.start_line - 1 + args.line_count
        if first >= len(starts) or starts[first] >= len(data):
            return ("unavailable", "byte_budget" if size > len(data) else "not_recorded")
        stop = starts[last] if last < len(starts) else len(data)
        try:
            data[starts[first] : stop].decode()
        except UnicodeDecodeError:
            return ("unavailable", "unsupported_type")
        if b"\0" in data[:8000]:
            return ("unavailable", "unsupported_type")
        piece = _Piece(data, starts[first], stop, refs, prov, "", args.start_line, root.input_root)
        return ("text", [piece], None, 0)


def _data(shape: str, pieces: list[_Piece]) -> tuple[JsonValue, dict[str, list[str]]]:
    """The result ``data`` of exactly the fitted pieces, and the text it sends for each ref."""

    items: list[JsonValue] = []
    cites: dict[str, list[str]] = {}
    for piece in pieces:
        text = piece.text.decode()
        for ref in piece.citable:
            cites.setdefault(ref, []).append(text)
        if shape == "list":
            items.append({"name": text, "kind": piece.ref})
            continue
        lines = None
        if piece.line is not None:
            last = piece.line + text.count("\n") - text.endswith("\n")
            lines = {"start": piece.line, "end_inclusive": last}
        span = {"start": piece.start, "end_exclusive": piece.end}
        item = {"text": text, "provenance": {**piece.prov, "span": span, "line_span": lines}}
        items.append(item if shape == "text" else {"ref": piece.ref, **item})
    if shape == "list":
        unspanned = pieces[0].prov | {"span": None, "line_span": None}
        return {"entries": items, "provenance": unspanned}, cites
    return ({"records": items} if shape == "records" else items[0]), cites


def _clear(content: bytes, at: int, edge: Literal["head", "tail"]) -> int:
    """``at`` moved clear of a credential and onto a UTF-8 boundary: back for a head, on for a tail."""

    at = clear_cut(content, min(at, len(content)), edge)
    while 0 < at < len(content) and content[at] & 0xC0 == 0x80:
        at += -1 if edge == "head" else 1
    return at
