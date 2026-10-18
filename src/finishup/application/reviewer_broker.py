"""The reviewer's three reads, bounded and admitted like the packet (#1118 unit 2, ADR-006).

``read_packet_section`` and ``read_ledger`` read the frozen review case: the records the case
builder already rendered, including items the bounded packet cut. ``read_file`` reads a text span
or one directory listing beneath a service-issued root alias, through the trusted descriptor walk
of ``task_input_read``. Every result goes through the same privacy admission as the packet, keeps
the outside root it was read beneath, and is cut clear of credentials before it is clipped. At
most three reads, 8 KiB per result and 24 KiB in all, counted in the step store and never
refunded. A result is evidence for the model, never an instruction.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Final, Literal, Protocol

from finishup.adapters.task_input_read import clear_cut, list_beneath, read_text_beneath
from finishup.domain.privacy import (
    AuthorizationScope,
    CandidateContext,
    CandidateContextItem,
    EgressChannel,
    ProviderBinding,
)
from finishup.ports.semantic import SemanticCase, SemanticCaseItem
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.models import (
    DataCategory,
    ReadFileListArgsModel,
    ReadFileTextArgsModel,
    ReviewerActionModel,
    ReviewerFileActionModel,
    ReviewerLedgerActionModel,
)

__all__ = ["MemoryStepStore", "ReadRoot", "ReviewerBroker", "ReviewerStepStore", "StepConflict"]

MAX_READS: Final = 3
MAX_RESULT_BYTES: Final = 8192
MAX_TOTAL_BYTES: Final = 24_576
_TARGET_TEXT_BYTES: Final = 6144
_ENVELOPE_ROOM: Final = 1024  # below this no result fits: only the final judgment remains
_LIST_INSPECT: Final = 128
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
_STANDING: Final = {
    "task_statement": "task_transcription",
    "goal": "agent_assertion",
    "obligation": "agent_assertion",
    "claim": "agent_assertion",
    "decision": "agent_assertion",
}


@dataclass(frozen=True, slots=True)
class ReadRoot:
    """One ``read_file`` alias the service issued; the model names only ``alias``.

    A current root reads beneath ``path``: the workspace, or an owner-admitted outside root
    limited to the task-``declared`` files and directories beneath it. A snapshot root reads only
    the members FinishUP captured. ``input_root`` is the owner-admitted root (E2E-2 binding).
    """

    alias: str
    path: str | None = None
    snapshot: Mapping[str, bytes] | None = None
    input_root: str | None = None
    declared: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()
    subject_refs: tuple[str, ...] = ()
    standing: str = "workspace_content"
    baseline: str = "read_time"
    refuse: Callable[[str], bool] | None = None  # e.g. Git-ignored workspace paths


class StepConflict(ValueError):
    """A reserved step asked again with different arguments."""


class ReviewerStepStore(Protocol):
    """Durable step slots of one review job: reserved before a read runs, never refunded."""

    def reserve(self, step_ref: str, commitment: str) -> bytes | None:
        """Reserve ``step_ref``; return the saved result when the same arguments already ran."""
        ...

    def record(self, step_ref: str, result: bytes) -> None: ...

    def usage(self) -> tuple[int, int]:
        """``(steps reserved, result bytes recorded)``."""
        ...


@dataclass(slots=True)
class MemoryStepStore:
    """In-process ``ReviewerStepStore``; a ledger-backed store keeps the same contract."""

    steps: dict[str, tuple[str, bytes | None]] = field(
        default_factory=dict[str, tuple[str, bytes | None]]
    )

    def reserve(self, step_ref: str, commitment: str) -> bytes | None:
        saved = self.steps.setdefault(step_ref, (commitment, None))
        if saved[0] != commitment:
            raise StepConflict("reviewer_step_conflict")
        return saved[1]

    def record(self, step_ref: str, result: bytes) -> None:
        self.steps[step_ref] = (self.steps[step_ref][0], result)

    def usage(self) -> tuple[int, int]:
        return len(self.steps), sum(len(saved or b"") for _c, saved in self.steps.values())


@dataclass(frozen=True, slots=True)
class _Part:
    ref: str
    text: bytes
    category: DataCategory
    citable: tuple[str, ...]
    standing: str = "finishup_record"
    baseline: str = "check_time"
    root: ReadRoot | None = None
    input_root: str | None = None
    span: tuple[int, int] | None = None
    lines: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class _Read:
    status: str
    reason: str | None = None
    parts: tuple[_Part, ...] = ()
    shape: Literal["text", "records", "list"] = "text"
    entries: tuple[tuple[str, bool], ...] = ()
    truncated: bool = False
    next_cursor: str | None = None


class ReviewerBroker:
    """Executes one validated read per call; the budgets live in the step store."""

    def __init__(
        self,
        *,
        job_id: str,
        case: SemanticCase,
        roots: Sequence[ReadRoot],
        store: ReviewerStepStore,
        admit: Callable[[CandidateContext], Awaitable[dict[str, bytes] | str]],
        scope: AuthorizationScope,
        provider_binding: ProviderBinding,
        request_id: str,
    ) -> None:
        self._job, self._case, self._store, self._admit = job_id, case, store, admit
        self._roots = {root.alias: root for root in roots}
        self._scope, self._binding, self._request_id = scope, provider_binding, request_id
        self._allowed = frozenset(case.frontier_refs | case.local_check_refs)
        self._case_roots = dict(case.input_roots)
        # Every outside root the conversation holds bytes from; rechecked before each turn.
        self.history_roots: set[str] = set(self._case_roots.values())
        self.text_by_ref: dict[str, list[str]] = {}

    def reads_allowed(self) -> bool:
        calls, used = self._store.usage()
        return calls < MAX_READS and MAX_TOTAL_BYTES - used >= _ENVELOPE_ROOM

    def citations(
        self, packet_refs: frozenset[str], packet_text: Mapping[str, tuple[str, ...]]
    ) -> tuple[frozenset[str], dict[str, tuple[str, ...]]]:
        """The citation fence over the union of the packet and the admitted read results."""

        merged = {ref: tuple(texts) for ref, texts in packet_text.items()}
        for ref, texts in self.text_by_ref.items():
            merged[ref] = (*merged.get(ref, ()), *texts)
        return packet_refs | frozenset(self.text_by_ref), merged

    async def execute(self, action: ReviewerActionModel) -> str:
        """Reserve the next step, run the read, admit it and return the result envelope."""

        calls, used = self._store.usage()
        ordinal, tool_ref = calls + 1, f"{self._job}:read:{calls + 1}"
        saved = self._store.reserve(tool_ref, canonical_digest(action.model_dump(mode="json")))
        if saved is not None:
            return saved.decode("utf-8")
        # A requested cap below one envelope still gets an envelope; the fitter clips the text.
        room = min(
            MAX_RESULT_BYTES, max(action.args.max_bytes, _ENVELOPE_ROOM), MAX_TOTAL_BYTES - used
        )
        target = min(_TARGET_TEXT_BYTES, room)
        if isinstance(action, ReviewerFileActionModel):
            read = self._file(action.args, target)
        elif isinstance(action, ReviewerLedgerActionModel):
            read = self._ledger(action.args.view, action.args.refs, action.args.cursor, target)
        else:
            args = action.args
            read = self._item(_PACKET_SECTIONS[args.section], args.item_ref, args.offset, target)
        if read.parts:
            read = await self._admitted(read, ordinal)
        result, sent = self._envelope(tool_ref, ordinal, read, room, MAX_TOTAL_BYTES - used)
        # Only what the result actually carries becomes citable or binds the conversation.
        for part in sent:
            for ref in part.citable:
                self.text_by_ref.setdefault(ref, []).append(part.text.decode("utf-8", "replace"))
            if part.input_root is not None:
                self.history_roots.add(part.input_root)
        self._store.record(tool_ref, result)
        return result.decode("utf-8")

    async def _admitted(self, read: _Read, ordinal: int) -> _Read:
        items = tuple(
            CandidateContextItem(
                f"reviewer-read-{ordinal}-{index}",
                part.category,
                self._scope,
                f"/reviewer/read/{ordinal}/{index}",
                part.text,
                input_root=part.input_root,
            )
            for index, part in enumerate(read.parts)
        )
        admitted = await self._admit(
            CandidateContext(
                self._request_id,
                EgressChannel.LLM_INFERENCE,
                None,
                "semantic-review-read",
                self._scope,
                None,
                self._binding,
                items,
            )
        )
        if isinstance(admitted, str):
            return _Read("denied", admitted)
        parts: list[_Part] = []
        for item, part in zip(items, read.parts, strict=True):
            text = admitted.get(item.item_id)
            if text is None or (read.shape == "list" and text != part.text):
                return _Read("denied", "privacy_withheld")
            citable = tuple(ref for ref in part.citable if ref in self._allowed)
            parts.append(replace(part, text=text, citable=citable))
        return replace(read, parts=tuple(parts))

    def _part(self, item: SemanticCaseItem, offset: int, target: int) -> tuple[_Part, bool]:
        text, span, cut = _window(item.content, offset, target)
        part = _Part(
            item.item_id,
            text,
            item.category,
            (item.source_ref, *item.linked_subject_refs),
            _STANDING.get(item.section, "finishup_record"),
            input_root=self._case_roots.get(item.item_id),
            span=span,
        )
        return part, cut

    def _item(self, sections: set[str], ref: str, offset: int, target: int) -> _Read:
        item = next((i for i in self._case.items if i.item_id == ref), None)
        if item is None or item.section not in sections:
            return _Read("unavailable", "not_retained")
        if offset >= len(item.content):
            return _Read("unavailable", "not_retained")
        part, cut = self._part(item, offset, target)
        return _Read("partial" if cut else "ok", parts=(part,), truncated=cut)

    def _ledger(self, view: str, refs: tuple[str, ...], cursor: str | None, target: int) -> _Read:
        kinds, wanted = _LEDGER_VIEWS[view], set(refs)
        matched = [
            i
            for i in self._case.items
            if (i.section in kinds or i.source_kind in kinds)
            and (i.source_ref in wanted or wanted & set(i.linked_subject_refs))
        ]
        start = int(cursor) if cursor is not None and cursor.isdigit() else 0
        page = matched[start : start + _MAX_RECORDS]
        if not page:
            return _Read("unavailable", "not_recorded")
        windows = [self._part(item, 0, target // len(page)) for item in page]
        parts = [part for part, _cut in windows]
        cut = any(cut for _part, cut in windows)
        more = start + len(parts) < len(matched)
        return _Read(
            "partial" if more or cut else "ok",
            parts=tuple(parts),
            shape="records",
            truncated=more or cut,
            next_cursor=str(start + len(parts)) if more else None,
        )

    def _file(self, args: ReadFileTextArgsModel | ReadFileListArgsModel, target: int) -> _Read:
        root, path = self._roots.get(args.root_id), _relative(args.path)
        if root is None or path is None or (root.refuse is not None and root.refuse(path)):
            return _Read("denied", "forbidden_path")
        if root.declared and not any(
            d == "" or path == d or path.startswith(f"{d}/") for d in root.declared
        ):
            return _Read("denied", "outside_scope")

        def part(text: bytes, **where: tuple[int, int]) -> _Part:
            return _Part(
                f"{root.alias}:{path}",
                text,
                DataCategory.REPOSITORY_EXCERPT,
                root.subject_refs,
                root.standing,
                root.baseline,
                root,
                root.input_root,
                **where,
            )

        if isinstance(args, ReadFileListArgsModel):
            listed = _listing(root, path)
            if listed is None:
                return _Read("unavailable", "not_recorded")
            start = int(args.cursor) if args.cursor is not None and args.cursor.isdigit() else 0
            page = listed[start : start + args.max_entries]
            more = start + len(page) < len(listed)
            return _Read(
                "partial" if more else "ok",
                parts=(part("\n".join(name for name, _d in page).encode()),),
                shape="list",
                entries=page,
                truncated=more,
                next_cursor=str(start + len(page)) if more else None,
            )
        if root.snapshot is not None:
            found = root.snapshot.get(path)
            read = None if found is None else (found, len(found))
        else:
            read = read_text_beneath(root.path or "", path, excluded=root.excluded)
        if read is None:
            return _Read("unavailable", "not_recorded")
        data, size = read
        if b"\0" in data[:8000]:
            return _Read("unavailable", "unsupported_type")
        lines = data.splitlines(keepends=True)
        first = args.start_line - 1
        if first >= len(lines):
            return _Read("unavailable", "byte_budget" if size > len(data) else "not_recorded")
        begin = sum(len(line) for line in lines[:first])
        end = begin + sum(len(line) for line in lines[first : first + args.line_count])
        text, span, cut = _window(data[:end], begin, target)
        last = args.start_line + max(0, text.count(b"\n") - (1 if text.endswith(b"\n") else 0))
        return _Read(
            "partial" if cut else "ok",
            parts=(part(text, span=span, lines=(args.start_line, last)),),
            truncated=cut,
        )

    def _envelope(
        self, tool_ref: str, ordinal: int, read: _Read, room: int, left: int
    ) -> tuple[bytes, tuple[_Part, ...]]:
        """The round-1 result envelope clipped to ``room``, and the parts it carries."""

        parts, entries = list(read.parts), list(read.entries)
        clipped = False
        while True:
            body: dict[str, JsonValue] = {
                "tool_ref": tool_ref,
                "call_index": ordinal,
                "status": read.status,
                "reason": read.reason,
                "snapshot_ref": self._case.case_id
                if not parts or parts[0].root is None
                else tool_ref,
                "citable_refs": list[JsonValue](sorted({r for p in parts for r in p.citable})[:16]),
                "truncated": read.truncated or clipped,
                "next_cursor": read.next_cursor,
                "calls_remaining": MAX_READS - ordinal,
                "data": _data(read.shape, parts, entries),
                "result_digest": "",
                "result_utf8_bytes": 0,
                "bytes_remaining": 0,
            }
            body["result_digest"] = canonical_digest(body["data"])
            encoded, size = b"", 0
            for _ in range(8):  # the length fixed point: the digits of the size and remainder
                body["result_utf8_bytes"], body["bytes_remaining"] = size, max(0, left - size)
                encoded = canonical_encode(body)
                if len(encoded) == size:
                    break
                size = len(encoded)
            if size <= room or not (parts or entries) or (len(parts) == 1 and not parts[0].text):
                return encoded, tuple(parts)
            clipped = True
            if read.shape == "list" and entries:
                entries.pop()
            elif len(parts) > 1 and len(parts[-1].text) < 64:
                parts.pop()
            else:
                last = parts[-1].text
                keep = _utf8_floor(
                    last, clear_cut(last, max(0, len(last) - (size - room) - 8), "head")
                )
                parts[-1] = replace(parts[-1], text=last[:keep])


def _prov(part: _Part) -> dict[str, JsonValue]:
    return {
        "source_ref": part.ref[:128],
        "root_id": None if part.root is None else part.root.alias,
        "baseline": part.baseline,
        "standing": part.standing,
        "span": None
        if part.span is None
        else {"start": part.span[0], "end_exclusive": part.span[1]},
        "line_span": None
        if part.lines is None
        else {"start": part.lines[0], "end_inclusive": part.lines[1]},
    }


def _data(shape: str, parts: list[_Part], entries: list[tuple[str, bool]]) -> JsonValue:
    if not parts:
        return None
    if shape == "records":
        return {
            "records": [
                {
                    "ref": p.ref[:128],
                    "text": p.text.decode("utf-8", "replace"),
                    "provenance": _prov(p),
                }
                for p in parts
            ]
        }
    if shape == "list":
        kinds = [{"name": n, "kind": "directory" if d else "file"} for n, d in entries]
        return {"entries": kinds, "provenance": _prov(parts[0])}  # pyright: ignore[reportReturnType]
    return {"text": parts[0].text.decode("utf-8", "replace"), "provenance": _prov(parts[0])}


def _relative(path: str) -> str | None:
    """A root-relative path, ``""`` for the root itself; ``None`` for any escape or hidden name."""

    while path.startswith("./"):
        path = path[2:]
    path = "" if path in {".", ""} else path.rstrip("/")
    parts = path.split("/")
    if path and (
        path.startswith("/")
        or "\0" in path
        or any(p in {"", ".", ".."} or p.startswith(".") for p in parts)
    ):
        return None
    return path


def _listing(root: ReadRoot, path: str) -> tuple[tuple[str, bool], ...] | None:
    if root.snapshot is None:
        return list_beneath(root.path or "", path, excluded=root.excluded, inspect=_LIST_INSPECT)
    prefix = f"{path}/" if path else ""
    names = sorted({m[len(prefix) :].split("/")[0] for m in root.snapshot if m.startswith(prefix)})
    return tuple((n, f"{prefix}{n}" not in root.snapshot) for n in names[:_LIST_INSPECT]) or None


def _window(content: bytes, offset: int, target: int) -> tuple[bytes, tuple[int, int], bool]:
    """``content[offset:]`` up to ``target`` bytes, each cut moved clear of a credential."""

    start = clear_cut(content, min(offset, len(content)), "tail")
    while start < len(content) and content[start] & 0xC0 == 0x80:
        start += 1  # never split a UTF-8 sequence
    end = max(
        start, _utf8_floor(content, clear_cut(content, min(len(content), start + target), "head"))
    )
    return content[start:end], (start, end), end < len(content)


def _utf8_floor(content: bytes, end: int) -> int:
    """``end`` moved back to a UTF-8 sequence boundary."""

    while 0 < end < len(content) and content[end] & 0xC0 == 0x80:
        end -= 1
    return end
