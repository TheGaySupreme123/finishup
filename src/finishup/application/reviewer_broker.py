"""The reviewer's three reads, bounded and admitted like the packet (#1118 unit 2, ADR-006).

``read_packet_section`` and ``read_ledger`` read records the case builder already rendered into the
frozen review case, including what the bounded packet cut. ``read_file`` reads a line span or one
directory listing beneath a service-issued root alias: the workspace, an owner-admitted outside
root limited to the task-declared paths, or a snapshot of one. A result is fitted into its byte
room first; then each element it carries is admitted unchanged, and its exact encoding is scanned.
Spans, cursors and citable text come from what was fitted and sent, nothing else. At most three
reads, 8 KiB each and 24 KiB in all, each reserved durably before it runs and never refunded.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, cast

from finishup.adapters.task_input_read import clear_cut, list_beneath, read_text_beneath
from finishup.ports.change_capture import TaskInputSnapshotSet
from finishup.ports.semantic import ReviewStepStore, SemanticCase, SemanticCaseItem
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

__all__ = ["MAX_READS", "ReadElement", "ReadRoot", "ReviewerBroker"]

MAX_READS: Final = 3
MAX_RESULT_BYTES: Final = 8192
MAX_TOTAL_BYTES: Final = 24_576
MIN_ROOM: Final = 1024  # one whole result envelope; below it only the final judgment remains
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
_AGENT_SECTIONS: Final = frozenset({"goal", "obligation", "claim", "decision"})

# What admission sees of a result: each element's category, exact bytes and outside root.
type ReadElement = tuple[DataCategory, bytes, str | None]
type _Selected = tuple[str, list[_Piece], tuple[str, str, int] | None, int] | tuple[str, str]


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
    """One content-bearing element of a result, ``source[start:end]``; ``end < stop`` is a cut."""

    source: bytes
    start: int
    stop: int
    citable: tuple[str, ...]
    prov: dict[str, JsonValue]
    ref: str = ""  # a record's ref, or a listed entry's kind
    line: int | None = None
    root: str | None = None
    category: DataCategory = DataCategory.REPOSITORY_EXCERPT
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
    ) -> None:
        self.store, self._job, self._case, self._admit = store, job_id, case, admit
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
        return self.calls < MAX_READS and MAX_TOTAL_BYTES - self.used >= MIN_ROOM

    async def execute(self, action: ReviewerActionModel, expired: Callable[[], bool]) -> str:
        """Reserve the next read, run it, fit and admit it; return the result envelope."""

        ordinal = self.calls + 1
        await self.store.reserve("read", ordinal, canonical_encode(action.model_dump(mode="json")))
        self.calls, tool_ref, args = ordinal, f"{self._job}:read:{ordinal}", action.args
        if isinstance(action, ReviewerFileActionModel):
            selected = self._file(action.args, expired, tool_ref)
        elif isinstance(args, ReadLedgerArgsModel):
            selected = self._ledger(args.view, args.refs, args.cursor)
        else:
            selected = self._packet(cast(ReadPacketSectionArgsModel, args))
        room = min(MAX_RESULT_BYTES, args.max_bytes, MAX_TOTAL_BYTES - self.used)
        encoded = await self._result(tool_ref, ordinal, selected, room)
        self.used += len(encoded)
        await self.store.capture("read", ordinal, encoded)
        return encoded.decode()

    async def _result(self, tool_ref: str, ordinal: int, selected: _Selected, room: int) -> bytes:
        """Fit the selection into ``room``, admit exactly what fits, and record what was sent."""

        def envelope(status: str, reason: str | None = None, data: JsonValue = None) -> bytes:
            body: dict[str, JsonValue] = {
                "tool_ref": tool_ref,
                "call_index": ordinal,
                "status": status,
                "reason": reason,
                "snapshot_ref": tool_ref if pieces and pieces[0].prov["root_id"] else case_id,
                "citable_refs": list[JsonValue](refs),
                "truncated": cut,
                "next_cursor": cursor,
                "calls_remaining": MAX_READS - ordinal,
                "data": data,
                "result_digest": canonical_digest(data),
            }
            encoded, size = b"", 0
            for _ in range(8):  # the length fixed point: the size and the remainder's digits
                body["result_utf8_bytes"] = size
                body["bytes_remaining"] = max(0, MAX_TOTAL_BYTES - self.used - size)
                encoded = canonical_encode(body)
                if len(encoded) == size:
                    break
                size = len(encoded)
            return encoded

        case_id, pieces, refs, cut, cursor = (
            self._case.case_id,
            list[_Piece](),
            list[str](),
            False,
            None,
        )
        if len(selected) == 2:
            return envelope(*selected)
        shape, pieces, page, left = selected
        count = len(pieces)
        for piece in pieces:  # an even share of the text room first, then the exact fit
            share = min(_TEXT_BYTES, room) // count
            piece.end = _head(piece.source, min(piece.stop, piece.start + share))
        while pieces := [piece for piece in pieces if piece.end > piece.start]:
            more = left > 0 or len(pieces) < count
            cut = more or any(piece.end < piece.stop for piece in pieces)
            refs = sorted({ref for piece in pieces for ref in piece.citable})[:16]
            if page is not None and more:
                cursor = f"c{ordinal}"
                self._cursors[cursor] = (page[0], page[1], page[2] + len(pieces))
            encoded = envelope("partial" if cut else "ok", None, _data(shape, pieces))
            over = len(encoded) - room
            if over <= 0:
                break
            last = pieces[-1]
            if shape == "list" or (len(pieces) > 1 and last.end - last.start <= over + 64):
                pieces.pop()
            else:
                last.end = _head(last.source, max(last.start, last.end - over - 8))
        else:
            cut, cursor = False, None
            return envelope("unavailable", "byte_budget")
        elements = tuple((piece.category, piece.text, piece.root) for piece in pieces)
        reason = await self._admit(elements, encoded)
        if reason is not None:
            pieces, refs, cut, cursor = [], [], False, None
            return envelope("denied", reason)
        for piece in pieces:  # only what the result carries is citable or binds the history
            for ref in piece.citable:
                self.cited_refs.add(ref)
                self.text_by_ref.setdefault(ref, []).append(piece.text.decode())
            if piece.root is not None:
                self.history_roots.add(piece.root)
        return encoded

    def _page(self, selector: str, version: str, cursor: str | None) -> int | tuple[str, str]:
        """The offset a cursor this broker issued names; a forged or rebound one is refused."""

        bound = (selector, version, 0) if cursor is None else self._cursors.get(cursor)
        if bound is None or bound[0] != selector:
            return ("denied", "invalid_request")
        return bound[2] if bound[1] == version else ("stale", "source_changed")

    def _item(self, item: SemanticCaseItem, offset: int) -> _Piece:
        standing = "agent_assertion" if item.section in _AGENT_SECTIONS else "finishup_record"
        if item.section == "task_statement":
            standing = "task_transcription"
        prov: dict[str, JsonValue] = {
            "source_ref": item.item_id,
            "root_id": None,
            "baseline": "check_time",
            "standing": standing,
        }
        refs = tuple(r for r in (item.source_ref, *item.linked_subject_refs) if r in self._allowed)
        start, stop = _tail(item.content, offset), len(item.content)
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
            return ("unavailable", "not_recorded")
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
                listed = list_beneath(root.path, path, excluded=root.excluded, expired=expired)
            else:
                names = {m[len(below) :].split("/")[0] for m in kept if m.startswith(below)}
                listed = tuple(sorted((n, f"{below}{n}" not in kept) for n in names))
            children = [(n, d) for n, d in listed or () if not self._refused(root, below + n)]
            selector = f"{root.alias}\x00{path}"
            version = canonical_digest([[n, d] for n, d in children])
            start = self._page(selector, version, args.cursor)
            if isinstance(start, tuple):
                return start
            page = children[start : start + args.max_entries]
            if not page:
                return ("unavailable", "not_recorded")
            pieces = [
                _Piece(n.encode(), 0, len(n.encode()), refs, prov, "directory" if d else "file")
                for n, d in page
            ]
            for piece in pieces:
                piece.root = root.input_root
            return ("list", pieces, (selector, version, start), len(children) - start - len(page))
        if snap is not None:
            read = None if path not in kept else (kept[path], len(kept[path]))
        else:
            read = read_text_beneath(root.path, path, excluded=root.excluded, expired=expired)
        if read is None:
            return ("unavailable", "not_recorded")
        data, size = read
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


def _data(shape: str, pieces: list[_Piece]) -> JsonValue:
    """The result ``data`` of exactly the fitted pieces, spans and lines included."""

    def prov(piece: _Piece) -> dict[str, JsonValue]:
        text, lines = piece.text, None
        if piece.line is not None:
            last = piece.line + text.count(b"\n") - text.endswith(b"\n")
            lines = {"start": piece.line, "end_inclusive": last}
        span = {"start": piece.start, "end_exclusive": piece.end}
        return {**piece.prov, "span": span, "line_span": lines}

    if shape == "records":
        records = [{"ref": p.ref, "text": p.text.decode(), "provenance": prov(p)} for p in pieces]
        return {"records": cast(list[JsonValue], records)}
    if shape == "list":
        entries = [{"name": p.text.decode(), "kind": p.ref} for p in pieces]
        unspanned = pieces[0].prov | {"span": None, "line_span": None}
        return {"entries": cast(list[JsonValue], entries), "provenance": unspanned}
    return {"text": pieces[0].text.decode(), "provenance": prov(pieces[0])}


def _head(content: bytes, end: int) -> int:
    """``end`` moved back clear of a credential and onto a UTF-8 sequence boundary."""

    end = clear_cut(content, min(end, len(content)), "head")
    while 0 < end < len(content) and content[end] & 0xC0 == 0x80:
        end -= 1
    return end


def _tail(content: bytes, start: int) -> int:
    """``start`` moved forward clear of a credential and onto a UTF-8 sequence boundary."""

    start = clear_cut(content, min(start, len(content)), "tail")
    while start < len(content) and content[start] & 0xC0 == 0x80:
        start += 1
    return start
