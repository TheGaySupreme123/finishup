"""The reviewer's three reads, bounded and admitted like the packet (#1118 unit 2, ADR-006).

``read_packet_section`` and ``read_ledger`` read records the case builder already rendered into the
frozen review case, including what the bounded packet cut. ``read_file`` reads a line span or one
directory listing beneath a service-issued root alias: the workspace, an owner-admitted outside
root limited to the task-declared paths, or a snapshot of one. A result is fitted into its byte
room first (a listed entry is whole or left for the cursor, never shortened); then each element it
carries is admitted unchanged, and its exact encoding is scanned. Spans, cursors and citable text
come from what was fitted and sent, nothing else. A read that completes past its local stop is
discarded, not used; that is a check after each blocking call, not preemption of one. At most three
content-bearing reads and five attempts, 8 KiB each and 24 KiB in all. Attempts and bytes are
reserved durably and never refunded; refused/empty results do not spend a content read.

The ``t1`` root (issue #1220) serves only the agent's declared tests the packet lists, by their
``dt<n>`` ref: each read re-reads the file and is refused unless its bytes still match the digest
pinned when the check ran; a result is at most 4 KiB and counts against the same allowance.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Literal, cast

from finishup.adapters.reviewer_artifacts import artifact_facts, image_attachment
from finishup.adapters.task_input_read import (
    ReadDeadline,
    clear_cut,
    list_beneath,
    read_declared_test,
    read_text_beneath,
)
from finishup.domain.reviewer_reads import MAX_REVIEWER_READ_ATTEMPTS, MAX_REVIEWER_READS
from finishup.kernel.declared_checks import DECLARED_TEST_READ_BYTES
from finishup.observability.privacy import redact_fully
from finishup.ports.change_capture import TaskInputSnapshotSet
from finishup.ports.semantic import (
    ReviewStepRefused,
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

MAX_READS: Final = MAX_REVIEWER_READS
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

# A refused file selector's correction, by cause (#1173): fixed service text that never echoes
# the refused path and names no concrete path a model could copy as if it existed.
_DISCOVER: Final = (
    " Prefer a path the packet names; a path=. listing that returns names spends a content read."
)
_PATH_CORRECTIONS: Final = {
    "unknown_root": "root_id must be an alias from the catalog's read_file_roots "
    "(allowed_root_ids lists some); no other alias or filesystem root is readable." + _DISCOVER,
    "absolute": "Paths are relative to the root_id alias: drop the filesystem prefix and any "
    "leading / and name the file beneath that root (path=<relative-path>)." + _DISCOVER,
    "component": "Hidden (dot-prefixed), empty or traversing (..) path components, and NUL "
    "bytes, are never readable, under any spelling. Choose another file.",
    "ignored": "The repository's ignore rules exclude this path, or its ignore state could not "
    "be checked; no root serves it. Do not retry it; choose another file or judge without it.",
    "outside_scope": "This root serves only the task-declared paths listed in its catalog "
    "covers. Choose a path from that list.",
    # #1220: the declared-test root names files by ref only, never by filesystem path.
    "declared_test": "This root serves only the packet's declared_tests, by ref: path=dt1 (or "
    "dt2, dt3), mode=text. No listing and no other path.",
}
# #1220: a listed declared test the service could not show; fixed text, never the path.
_DECLARED_TEST_LIMITS: Final = {
    "declared_test_changed": "This declared test's content no longer matches the digest the "
    "packet lists, so it is not visible to this review. Judge without it and say it was not "
    "visible; do not ask the agent to copy it.",
    "declared_test_not_visible": "This declared test is not visible to this review (not "
    "readable as text where it was declared). Judge without it and say it was not visible; do "
    "not ask the agent to copy it.",
}
_NO_ROOT: Final = (
    "No file root is available in this review. Use packet/ledger catalog selectors or "
    "final_judgment.missing_for_assessment for unavailable material; no path correction grants "
    "a root."
)
_NOT_RECORDED: Final = (
    "No readable file, retained snapshot entry, directory entry or requested line was available "
    "through this root. This does not establish that a task record was never recorded. Correct "
    "the relative path/line or list a permitted parent (a listing that returns names spends a "
    "content read); request unavailable content in final_judgment.missing_for_assessment with "
    "the appropriate kind and target_refs; a later check must freeze it."
)
# #1148: a frozen-case miss never claims non-recording. This static text carries no catalog
# metadata, so it stays even when every alternative row is withheld or does not fit.
_FROZEN_MISS: Final = (
    "This frozen lookup does not establish that the item was never recorded. Request unavailable "
    "content via final_judgment.missing_for_assessment (kind, target_refs); a later check must "
    "freeze it."
)
_FROZEN_RETRY: Final = " Or retry a listed item_id/section (offset=0) or source_ref/view."

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

    Raised before the read is reserved; nothing is read. ``verdict_fits`` says the action still
    fits beside the notices every exchange keeps room for, so the loop can leave the read unserved
    and ask for the final judgment in that exchange instead of ending the review (#1242).
    """

    def __init__(self, required: int, available: int, *, verdict_fits: bool = False) -> None:
        super().__init__("reviewer_read_exchange_full")
        self.capacity = (required, available)
        self.verdict_fits = verdict_fits


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
    # #1220: ``(ref, absolute path, pinned digest, criterion ref)`` of each declared test this
    # root serves; a read is citable for its criterion ref when the case lets it be cited.
    pinned: tuple[tuple[str, str, str, str], ...] = ()


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
    image: bytes | None = None
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
        images: bool = False,
    ) -> None:
        self.store, self._job, self._case, self._admit = store, job_id, case, admit
        self._images = images
        # #1118: the bytes the conversation's next exchange may still add under the disclosure
        # cap (``None`` when unbounded). A result is fitted to what is left of it after the read
        # action, measured as the exchange encodes both, escaping included.
        self._exchange_room = exchange_room
        self._max_reads = min(max_reads, MAX_READS)
        self._max_attempts = (
            min(MAX_REVIEWER_READ_ATTEMPTS, self._max_reads + 2) if self._max_reads else 0
        )
        # The read bytes this review may still add; the conversation lowers it to fit the channel.
        self.total = MAX_TOTAL_BYTES
        self._roots = {root.alias: root for root in roots}
        self._allowed = frozenset(case.frontier_refs | case.local_check_refs)
        self._cursors: dict[str, tuple[str, str, int]] = {}
        self.calls = self.used = self.content_reads = 0
        self.read_usage: list[Mapping[str, JsonValue]] = []
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
            self.content_reads < self._max_reads
            and self.calls < self._max_attempts
            and self.total - self.used >= MIN_ROOM
            and (room is None or room >= MIN_ROOM + READ_ACTION_ROOM)
        )

    def notice_fits(self) -> bool:
        """Whether the next exchange still has the room every read leaves for the loop's notices.

        That room is reserved past each fitted read (#1172), so only a first exchange admitted
        inside it, where ceiling planning could not keep its frame, leaves less.
        """

        room = self._exchange_room()
        return room is None or room >= 0

    async def execute(
        self, action: ReviewerActionModel, expired: Callable[[], bool], reply: str = ""
    ) -> str:
        """Reserve the next read, run it, fit and admit it; return the result envelope.

        ``reply`` is the assistant turn that asked for the read, exactly as the conversation
        carries it: the result travels in the same exchange, so it gets only what the reply
        leaves of that exchange's room.
        """

        # The model's completed turn may leave less than READ_ACTION_ROOM. That allowance is
        # only for offering the read; measure this actual action below instead of reapplying it.
        if self.content_reads >= self._max_reads or self.calls >= self._max_attempts:
            raise ReviewStepRefused("review_step_refused")
        left = self._exchange_room()
        if left is not None:
            required = reviewer_message_bytes("assistant", reply) + MIN_ROOM
            available = left
            left -= reviewer_message_bytes("assistant", reply)
            if left < MIN_ROOM:
                raise ReadExchangeFull(required, available, verdict_fits=left >= 0)
        ordinal = self.calls + 1
        await self.store.reserve("read", ordinal, canonical_encode(action.model_dump(mode="json")))
        self.calls, tool_ref, args = ordinal, f"{self._job}:read:{ordinal}", action.args
        usage: dict[str, JsonValue] = {
            "call": ordinal,
            **action.model_dump(mode="json"),
            "status": "unavailable",
            "reason": "outcome_unknown",
        }
        self.read_usage.append(usage)
        if isinstance(action, ReviewerFileActionModel):
            selected = self._file(action.args, expired, tool_ref)
        elif isinstance(args, ReadLedgerArgsModel):
            selected = self._ledger(args.view, args.refs, args.cursor)
        else:
            selected = self._packet(cast(ReadPacketSectionArgsModel, args))
        if expired():  # completed past its local stop: discarded, never retained or sent
            usage["reason"] = "deadline"
            raise ReadDeadline("reviewer_read_deadline")
        room = min(MAX_RESULT_BYTES, args.max_bytes, self.total - self.used)
        if isinstance(action, ReviewerFileActionModel) and self._pinned(action.args.root_id):
            room = min(room, DECLARED_TEST_READ_BYTES)  # #1220: at most 4 KiB per declared read
        # The read itself finished before its local stop (checked above). Admission is local and
        # never ends the review: a result admitted after the stop is still sent, as before #1173,
        # and the next turn's reserve check decides whether another read is offered. Only a
        # refusal's optional correction is dropped when it crosses the stop (``_result``).
        encoded = await self._result(tool_ref, ordinal, selected, room, left, action, expired)
        from finishup.protocol.canonical import strict_json_parse

        result = cast(dict[str, JsonValue], strict_json_parse(encoded))
        usage.update(status=result["status"], reason=result["reason"])
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
        action: ReviewerActionModel | None = None,
        expired: Callable[[], bool] = lambda: False,
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

        file = False
        correction: dict[str, JsonValue] = {}

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
                "calls_remaining": min(
                    self._max_reads - self.content_reads - int(_has_content(data)),
                    self._max_attempts - ordinal,
                ),
                "data": data,
                "result_digest": canonical_digest(data),
            }
            body.update(correction)
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
            status, reason = selected
            correction, elements, static = self._correction(reason, action)
            encoded = envelope(status, reason)
            # Hints are metadata from the frozen catalog, admitted under their own categories
            # and roots. Drop whole rows to fit; never shorten an identity into a wrong selector.
            while over_by(encoded) > 0 and elements:
                elements = elements[:-1]
                cast(list[JsonValue], correction["alternatives"]).pop()
                encoded = envelope(status, reason)
            if correction and (
                (correction.get("alternatives") == [])  # every row dropped to fit
                or over_by(encoded) > 0
                or await self._admit(elements, encoded) is not None
            ):
                # No catalog metadata bypasses the ordinary privacy projection, but the static
                # text carries none: it stays when every row is withheld (#1148), and is itself
                # scanned in the exact envelope it travels in.
                correction, elements = ({} if static == correction else static), ()
                encoded = envelope(status, reason)
                if correction and (
                    over_by(encoded) > 0 or await self._admit((), encoded) is not None
                ):
                    correction = {}
                    encoded = envelope(status, reason)
            if correction and expired():
                # Admitted after the local read stop: send the bare refusal, never a late hint.
                correction, elements = {}, ()
                encoded = envelope(status, reason)
            self.history_roots.update(
                root for _category, _data, root in elements if root is not None
            )
            return encoded
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
            if last.image is not None:
                # An image is atomic. Keep facts when the whole attachment cannot fit.
                last.image = None
                last.truncation_reason = "image_byte_budget"
                continue
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
        elements = tuple(
            (piece.category, data, piece.root)
            for piece in pieces
            for data in (piece.text,) + ((piece.image,) if piece.image is not None else ())
        )
        reason = await self._admit(elements, encoded)
        if reason is not None:
            return envelope("denied", reason)
        if page is not None and cursor is not None:  # resumes at the first entry not sent
            self._cursors[cursor] = (page[0], page[1], page[2] + len(pieces))
        for ref in refs:  # only what the result carries is citable or binds the history
            self.cited_refs.add(ref)
            self.text_by_ref.setdefault(ref, []).extend(cites[ref])
        self.history_roots.update(piece.root for piece in pieces if piece.root is not None)
        self.content_reads += 1
        return encoded

    def _correction(
        self, reason: str, action: ReviewerActionModel | None
    ) -> tuple[dict[str, JsonValue], tuple[ReadElement, ...], dict[str, JsonValue]]:
        """Bounded replacement selectors, never content, the refused path or a filesystem root.

        Returns the correction, the catalog rows it carries for admission, and its static form
        without those rows (#1173).
        """

        if reason in {"forbidden_path", "outside_scope"}:
            args = action.args if isinstance(action, ReviewerFileActionModel) else None
            root = None if args is None else self._roots.get(args.root_id)
            # The workspace first, then the outside roots: never only the outside ones.
            issued = sorted(self._roots, key=lambda a: (self._roots[a].input_root is not None, a))
            aliases = [root.alias] if root is not None else issued[:4]
            if not aliases:
                fixed: dict[str, JsonValue] = {"continuation": _NO_ROOT, "allowed_root_ids": []}
                return fixed, (), fixed
            cause = (
                "declared_test"
                if root is not None and root.pinned
                else "outside_scope"
                if reason == "outside_scope"
                else None
                if args is None
                else _path_refusal(root, _file_path(args.path))
            )
            # The only forbidden_path left after the selector's own shape is the ignore rule.
            fixed = {
                "continuation": _PATH_CORRECTIONS[cause or ("ignored" if root else "unknown_root")],
                "allowed_root_ids": cast(list[JsonValue], aliases),
            }
            return fixed, (), fixed
        if reason == "not_recorded":
            fixed = {"continuation": _NOT_RECORDED}
            return fixed, (), fixed
        if reason in _DECLARED_TEST_LIMITS:
            fixed = {"continuation": _DECLARED_TEST_LIMITS[reason]}
            return fixed, (), fixed
        if reason not in {"not_in_frozen_case", "not_retained"} or action is None:
            return {}, (), {}
        static: dict[str, JsonValue] = {"continuation": _FROZEN_MISS}
        args = action.args
        requested = (
            {args.item_ref}
            if isinstance(args, ReadPacketSectionArgsModel)
            else set(args.refs if isinstance(args, ReadLedgerArgsModel) else ())
        )
        wanted_sections: set[str] = (
            _PACKET_SECTIONS[args.section]
            if isinstance(args, ReadPacketSectionArgsModel)
            else _LEDGER_VIEWS[args.view]
            if isinstance(args, ReadLedgerArgsModel)
            else set[str]()
        )
        candidates = sorted(
            (i for i in self._case.items if i.content),
            key=lambda i: (
                not bool(requested & {i.item_id, i.source_ref, *i.linked_subject_refs}),
                i.section not in wanted_sections and i.source_kind not in wanted_sections,
                i.item_id,
            ),
        )
        alternatives: list[JsonValue] = []
        elements: list[ReadElement] = []
        for item in candidates:
            sections = [name for name, kinds in _PACKET_SECTIONS.items() if item.section in kinds]
            views = [
                name
                for name, kinds in _LEDGER_VIEWS.items()
                if item.section in kinds or item.source_kind in kinds
            ]
            if not sections and not views:
                continue
            row: dict[str, JsonValue] = {
                "item_id": item.item_id,
                "sections": cast(list[JsonValue], sections),
                "views": cast(list[JsonValue], views),
                "source_ref": item.source_ref,
            }
            alternatives.append(row)
            elements.append(
                (
                    item.category,
                    canonical_encode(row),
                    dict(self._case.input_roots).get(item.item_id),
                )
            )
            if len(alternatives) == 2:
                break
        if not alternatives:
            return static, (), static
        return (
            {"continuation": _FROZEN_MISS + _FROZEN_RETRY, "alternatives": alternatives},
            tuple(elements),
            static,
        )

    def _page(self, selector: str, version: str, cursor: str | None) -> int | tuple[str, str]:
        """The offset a cursor this broker issued names; a forged or rebound one is refused."""

        bound = (selector, version, 0) if cursor is None else self._cursors.get(cursor)
        if bound is None or bound[0] != selector:
            return ("denied", "invalid_request")
        return bound[2] if bound[1] == version else ("stale", "source_changed")

    def _item(self, item: SemanticCaseItem, offset: int) -> _Piece | None:
        """One record read from ``offset`` of its redacted text; ``None`` when that cannot be."""

        content = redact_fully(item.content)
        if content is None:
            return None
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
        start, stop = _clear(content, offset, "tail"), len(content)
        root = dict(self._case.input_roots).get(item.item_id)
        return _Piece(content, start, stop, refs, prov, item.item_id, None, root, item.category)

    def _packet(self, args: ReadPacketSectionArgsModel) -> _Selected:
        item = next((i for i in self._case.items if i.item_id == args.item_ref), None)
        if (
            item
            and item.section in _PACKET_SECTIONS[args.section]
            and args.offset < len(item.content)
        ):
            piece = self._item(item, args.offset)
            if piece is None:
                return ("denied", "privacy_withheld")
            if piece.start >= piece.stop:
                return ("unavailable", "not_retained")
            return ("text", [piece], None, 0)
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
        records = [piece for piece in (self._item(i, 0) for i in page) if piece is not None]
        if not records:
            return ("denied", "privacy_withheld")
        return ("records", records, (selector, version, start), left)

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
        root, path = self._roots.get(args.root_id), _file_path(args.path)
        if root is None or _path_refusal(root, path) is not None:
            return ("denied", "forbidden_path")
        if root.pinned:
            return self._declared(root, args, path, expired, tool_ref)
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
        facts = artifact_facts(data)
        if facts is not None:
            image = image_attachment(data, facts) if self._images else None
            facts["image_review"] = (
                "attachment_eligible"
                if image is not None
                else "not_enabled_or_unsupported"
                if not self._images
                else "attachment_limit_or_type"
            )
            rendered = canonical_encode(facts)
            piece = _Piece(
                rendered,
                0,
                len(rendered),
                refs,
                {**prov, "representation": "deterministic_artifact_facts"},
                root=root.input_root,
                image=data if image is not None else None,
            )
            return ("text", [piece], None, 0)
        if b"\0" in data[:8000]:
            return ("unavailable", "unsupported_type")
        # The lines are cut from the whole file redacted first (#1248, P-D4), never from the file
        # itself: a read starting on a value's line would otherwise send the value without the
        # label a line above it, where no scanner of the slice sees it. Redaction keeps every
        # line break, so line numbers still name the file's lines.
        redacted = redact_fully(data)
        if redacted is None:
            return ("denied", "privacy_withheld")
        data = redacted
        starts = [0, *(m.end() for m in re.finditer(b"\n", data))]
        first, last = args.start_line - 1, args.start_line - 1 + args.line_count
        if first >= len(starts) or starts[first] >= len(data):
            return ("unavailable", "byte_budget" if size > len(data) else "not_recorded")
        stop = starts[last] if last < len(starts) else len(data)
        try:
            data[starts[first] : stop].decode()
        except UnicodeDecodeError:
            return ("unavailable", "unsupported_type")
        piece = _Piece(data, starts[first], stop, refs, prov, "", args.start_line, root.input_root)
        return ("text", [piece], None, 0)

    def _pinned(self, alias: str) -> bool:
        root = self._roots.get(alias)
        return root is not None and bool(root.pinned)

    def _declared(
        self,
        root: ReadRoot,
        args: ReadFileTextArgsModel | ReadFileListArgsModel,
        path: str,
        expired: Callable[[], bool],
        tool_ref: str,
    ) -> _Selected:
        """One declared test by ref (#1220): re-read, refused unless still the pinned bytes."""

        entry = next((row for row in root.pinned if row[0] == path), None)
        if isinstance(args, ReadFileListArgsModel) or entry is None:
            return ("denied", "outside_scope")
        _ref, location, digest, criterion = entry
        data = read_declared_test(location, excluded=root.excluded, expired=expired)
        if data is None:
            return ("unavailable", "declared_test_not_visible")
        if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            return ("unavailable", "declared_test_changed")
        # Cut from the redacted test, like every other read (#1248, P-D4).
        redacted = redact_fully(data)
        if redacted is None:
            return ("denied", "privacy_withheld")
        data = redacted
        starts = [0, *(m.end() for m in re.finditer(b"\n", data))]
        first, last = args.start_line - 1, args.start_line - 1 + args.line_count
        if first >= len(starts) or starts[first] >= len(data):
            return ("unavailable", "not_recorded")
        stop = starts[last] if last < len(starts) else len(data)
        prov: dict[str, JsonValue] = {
            "source_ref": tool_ref,
            "root_id": root.alias,
            "baseline": "check_time",
            "standing": "declared_test",
        }
        piece = _Piece(
            data,
            starts[first],
            stop,
            (criterion,) if criterion in self._allowed else (),
            prov,
            "",
            args.start_line,
            None,
            DataCategory.DECLARED_TEST_EXCERPT,
        )
        return ("text", [piece], None, 0)


def _file_path(path: str) -> str:
    """A ``read_file`` path as the broker resolves it; ``.`` is the root itself."""

    path = path.removeprefix("./").rstrip("/")
    return "" if path == "." else path


def _path_refusal(root: ReadRoot | None, path: str) -> str | None:
    """Why a file selector is refused by its shape alone, before any filesystem or ignore probe."""

    if root is None:
        return "unknown_root"
    if path.startswith("/"):
        return "absolute"
    if "\0" in path or (path and any(part[:1] in {"", "."} for part in path.split("/"))):
        return "component"  # hidden, empty or traversing components, or a NUL byte
    return None


def _has_content(data: JsonValue) -> bool:
    return isinstance(data, dict) and bool(
        data.get("text") or data.get("entries") or data.get("records")
    )


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
        item: dict[str, JsonValue] = {
            "text": text,
            "provenance": {**piece.prov, "span": span, "line_span": lines},
        }
        if piece.image is not None:
            facts = artifact_facts(piece.image)
            assert facts is not None
            item["image"] = image_attachment(piece.image, facts)
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
