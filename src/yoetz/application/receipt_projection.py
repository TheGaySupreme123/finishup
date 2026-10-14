"""Agent-context receipt name spans: which repository names a receipt's prose spells.

A receipt's prose is Yoetz-authored, but under ``full_local`` it can spell the names of files the
check found and no participant published (the undeclared-reference names, ADR-035). Those names
are repository-excerpt content, so an agent-facing projection withholds each such name span, and
only that span, unless the requesting writer published that exact name in this session. Owner
views (``local_human_view``) never come here. Nothing in this module reaches the wire.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, cast

from yoetz.application.receipt import ReceiptInternalResult
from yoetz.application.status import published_name_authorship
from yoetz.domain.bounded_text import quoted_path
from yoetz.domain.events import CheckRecordedPayload
from yoetz.domain.privacy import (
    MAX_EGRESS_ITEM_BYTES,
    MAX_RECEIPT_NAME_AUTHORSHIP,
    DataCategory,
    ProjectionItemAuthorship,
)
from yoetz.domain.values import Frontier
from yoetz.kernel.delivered_set import undeclared_reference_rows
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.ledger import ProjectionView
from yoetz.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.models import MAX_PROJECTION_CONTENT_LEAVES, classify_result_leaf

WITHHELD: Final = "(receipt prose withheld: repository_excerpt)"
_NOT_PROSE: Final = frozenset(
    {
        "public_structural",
        DataCategory.BOUNDED_STRUCTURAL_METADATA,
        DataCategory.DECLARED_FILE_TYPE,
    }
)
_SECTION_TITLE: Final = re.compile(r"/document/sections/[0-9]+/title")


@dataclass(frozen=True, slots=True)
class ReceiptExcerpt:
    """One repository name spelled in one receipt prose leaf.

    ``origin`` is the candidate item pointer (``<leaf>/@repository_name/<name index>``), so the
    audit records one decision per name and leaf; ``pointer`` is the real result leaf.
    """

    origin: str
    pointer: str
    path: str
    spellings: tuple[str, ...]


def _strings(value: JsonValue, pointer: str = "") -> dict[str, str]:
    if isinstance(value, Mapping):
        result: dict[str, str] = {}
        for key, child in cast(Mapping[str, JsonValue], value).items():
            result.update(
                _strings(child, pointer + "/" + key.replace("~", "~0").replace("/", "~1"))
            )
        return result
    if type(value) in {tuple, list}:
        result = {}
        for index, child in enumerate(cast(Sequence[JsonValue], value)):
            result.update(_strings(child, f"{pointer}/{index}"))
        return result
    return {pointer: value} if type(value) is str else {}


def _spellings(path: str) -> tuple[str, ...]:
    # The builder spells a name as a bounded quoted path (the shared Stop-gate sentence); a name
    # with a directory may also occur bare, and so may a distinctive basename (one with an
    # extension, such as ``english_ngrams.npz``). A plain word does not count: a file named
    # "Summary" or "1" must not withhold a heading or a count that uses the same word. Case and
    # Unicode spellings are compared exactly: folding them would conflate distinct files on a
    # case-sensitive filesystem, and Yoetz has no per-platform path-equivalence fact here.
    forms = {quoted_path(path)}
    if "/" in path:
        forms.add(path)
    basename = path.rsplit("/", 1)[-1]
    stem, dot, extension = basename.rpartition(".")
    if dot and stem.strip(".") and extension:
        forms.add(basename)
    return tuple(sorted(forms, key=lambda spelling: (-len(spelling), spelling)))


# A harmless spelling of the same repository-relative path: any number of leading ``./``, or an
# absolute path that ends in it. Either prefix is part of the matched token, so the whole path
# token is withheld. A different relative directory (``x/artifacts/a.npz``) never matches.
_SAME_PATH_PREFIX: Final = r"(?:(?:\./)+|/(?:[^\s/\"'`<>|]+/)*)?"
# Inside one pair of quotes or backticks a path may contain spaces
# (``"/Users/u/My Project/a.npz"``); the quotes bound the token, so the absolute prefix there may
# hold any character but a quote, a backtick, a line break or a slash. Unquoted prose has no such
# bound, so an unquoted absolute path through a directory with spaces is not one token there.
_QUOTED_SAME_PATH_PREFIX: Final = r"(?:(?:\./)+|/(?:[^\"'`\n/]+/)*)?"


def _pattern(spellings: Iterable[str]) -> re.Pattern[str]:
    # Longest first, and never inside a longer path-like token: ``a.npz`` does not match within
    # ``data.npz`` or ``x/a.npz.bak``, so unrelated names and prose stay readable.
    ordered = sorted(set(spellings), key=lambda s: (-len(s), s))
    quoted = [s for s in ordered if len(s) >= 2 and s[0] == '"' and s[-1] == '"']
    bare = [s for s in ordered if s not in quoted]
    inner = sorted(
        {*(s[1:-1] for s in quoted), *bare}, key=lambda spelling: (-len(spelling), spelling)
    )
    alternatives: list[str] = [
        # A whole single-, double- or backtick-quoted path token, quotes included.
        r"(?P<quote>[\"'`])"
        + _QUOTED_SAME_PATH_PREFIX
        + "(?:"
        + "|".join(re.escape(spelling) for spelling in inner)
        + r")(?P=quote)"
    ]
    if bare:
        alternatives.append(
            r"(?<![\w./-])"
            + _SAME_PATH_PREFIX
            + "(?:"
            + "|".join(re.escape(spelling) for spelling in bare)
            + r")(?![\w/-]|\.\w)"
        )
    return re.compile("|".join(f"(?:{alternative})" for alternative in alternatives))


async def receipt_excerpts(
    runtime_port: BundleRuntimePort,
    result: ReceiptInternalResult,
) -> tuple[tuple[ReceiptExcerpt, ...], tuple[ProjectionItemAuthorship, ...], Frontier]:
    """The name spans of this receipt and the requesting writer's provenance for each name.

    Names come from every check recorded through the receipt's subject frontier, a superset of
    the applicable check the builder named them from, so a replayed or older stored receipt is
    held to the same rule. Authorship is read at the current head, so redacting the publication
    that spelled a name revokes it here as it does on status.
    """

    runtime = await runtime_port.route(
        RouteCommand(
            result.session_id,
            result.writer_id,
            RouteAccess.PAYLOAD_READ,
            frozenset({RuntimeCapability.PAYLOAD_READ}),
        )
    )
    try:
        names: set[str] = set()
        async for record in runtime.ledger.load_events(
            runtime.session_id, through=result.subject_frontier.sequence
        ):
            payload = getattr(record, "payload", None)
            if type(payload) is CheckRecordedPayload:
                for _obligation, _index, paths, _total in undeclared_reference_rows(
                    payload.deliverable_states
                ):
                    names.update(path for path in paths if path)
        paths = sorted(names, key=str.encode)
        source = result.as_json()
        excerpts: list[ReceiptExcerpt] = []
        if paths:
            spelled = [(path, _spellings(path)) for path in paths]
            patterns = [_pattern(spellings) for _path, spellings in spelled]
            strings = _strings({"document": result.document, "human_text": result.human_text})
            for pointer, text in strings.items():
                if _SECTION_TITLE.fullmatch(pointer):
                    continue
                if classify_result_leaf("receipt", source, pointer) in _NOT_PROSE:
                    continue
                for index, (path, spellings) in enumerate(spelled):
                    if patterns[index].search(text):
                        excerpts.append(
                            ReceiptExcerpt(
                                f"{pointer}/@repository_name/{index}", pointer, path, spellings
                            )
                        )
        head = await runtime.ledger.load_projection(runtime.session_id, ProjectionView.COMPACT)
        frontier = head.frontier if head is not None else result.subject_frontier
        # Past the bound a name simply stays withheld: no provenance never widens anything.
        attributable = [
            (f"/receipt_repository_names/{index}", path)
            for index, path in enumerate(paths)
            if any(item.path == path for item in excerpts)
        ][:MAX_RECEIPT_NAME_AUTHORSHIP]
        authorship = await published_name_authorship(runtime, frontier, attributable)
        return tuple(excerpts), authorship, frontier
    finally:
        await runtime_port.release(runtime)


def withheld_text(
    text: str, excerpts: Sequence[ReceiptExcerpt], *, max_chars: int | None = None
) -> str:
    """Replace only the withheld name spans; titles, counts and other prose stay.

    The token is longer than most names, so a field near its bound could grow past it. The
    result is then cut, visibly and deterministically, to fit both ``max_chars`` (the field's
    wire bound) and the per-item privacy bound. A cut never splits a withheld token, and only
    text already past the withholding is dropped, so nothing withheld can reappear.
    """

    spellings = {spelling for excerpt in excerpts for spelling in excerpt.spellings}
    replaced = _pattern(spellings).sub(lambda _match: WITHHELD, text) if spellings else text
    limit = max(len(text), _MIN_FIELD_CHARS) if max_chars is None else max_chars
    return _bounded(replaced, limit)


# Every receipt prose field this projection rewrites admits at least this many characters
# (section titles, the one smaller field, are never rewritten).
_MIN_FIELD_CHARS: Final = 4_096
HUMAN_TEXT_MAX_CHARS: Final = 32_768


def _fits(text: str, max_chars: int) -> bool:
    return len(text) <= max_chars and len(canonical_encode(text)) <= MAX_EGRESS_ITEM_BYTES


def _bounded(text: str, max_chars: int) -> str:
    if _fits(text, max_chars):
        return text
    low, high = 0, len(text)
    best = ""
    while low <= high:
        middle = (low + high) // 2
        cut = _token_safe_cut(text, middle)
        candidate = text[:cut] + _truncation_marker(len(text) - cut)
        if _fits(candidate, max_chars):
            best = candidate
            low = middle + 1
        else:
            high = middle - 1
    return best or _truncation_marker(len(text))


def _token_safe_cut(text: str, position: int) -> int:
    # A token that straddles ``position`` starts within the token length before it.
    window_start = max(0, position - len(WITHHELD) + 1)
    start = text.find(WITHHELD, window_start, position + len(WITHHELD) - 1)
    if start != -1 and start < position < start + len(WITHHELD):
        return start
    return position


def _truncation_marker(omitted: int) -> str:
    return f" [receipt text truncated after withholding: {omitted} characters not shown]"


def bounded_omitted_pointers(pointers: Sequence[str]) -> tuple[str, ...]:
    """Sorted, unique omitted pointers within the wire bound; never drops an omission.

    Past ``MAX_PROJECTION_CONTENT_LEAVES`` the parent with the most omitted children replaces
    them (and anything else beneath it), until the list fits. A coalesced pointer still covers
    every omission it replaced; the local disclosure audit keeps each individual decision.
    """

    current = set(pointers)
    while len(current) > MAX_PROJECTION_CONTENT_LEAVES:
        groups: dict[str, int] = {}
        for pointer in current:
            parent = pointer.rsplit("/", 1)[0]
            groups[parent] = groups.get(parent, 0) + 1
        parent = min(groups.items(), key=lambda row: (-row[1], row[0].encode()))[0]
        prefix = parent + "/"
        covered = any(parent.startswith(other + "/") for other in current)
        current = {pointer for pointer in current if not pointer.startswith(prefix)}
        if not covered:
            current.add(parent)
    return tuple(sorted(current, key=str.encode))
