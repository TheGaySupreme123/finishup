"""Agent-context receipt name spans: which repository names a receipt's prose spells.

A receipt's prose is FinishUP-authored, but under ``full_local`` it can spell the names of files the
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

from finishup.application.receipt import ReceiptInternalResult
from finishup.application.status import published_name_authorship
from finishup.domain.bounded_text import quoted_path
from finishup.domain.events import CheckRecordedPayload
from finishup.domain.privacy import (
    MAX_EGRESS_ITEM_BYTES,
    MAX_RECEIPT_NAME_AUTHORSHIP,
    DataCategory,
    ProjectionItemAuthorship,
)
from finishup.domain.values import Frontier
from finishup.kernel.delivered_set import undeclared_reference_rows
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.ledger import ProjectionView
from finishup.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import MAX_PROJECTION_CONTENT_LEAVES, classify_result_leaf

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
    # case-sensitive filesystem, and FinishUP has no per-platform path-equivalence fact here.
    # ``./path`` stands for the path behind a mandatory ``./`` or absolute prefix: every name,
    # including a top-level one without an extension (``vocab_table``), is a path when a prefix
    # marks it as one, while the bare word stays readable.
    forms = {quoted_path(path), "./" + path}
    if "/" in path:
        forms.add(path)
    basename = path.rsplit("/", 1)[-1]
    stem, dot, extension = basename.rpartition(".")
    if dot and stem.strip(".") and extension:
        forms.add(basename)
    return tuple(sorted(forms, key=lambda spelling: (-len(spelling), spelling)))


# A harmless spelling of the same repository-relative path. ``./`` (also ``.//`` and ``././``)
# may lead the relative path. An absolute prefix -- ``/``, ``~`` or ``~user``, ``$VAR`` or
# ``${VAR}`` and then ``/``, optionally behind ``file://`` -- may lead any directories (empty and
# ``.`` segments included) and then the name's last component: any absolute path that ends in a
# withheld file's base name counts as that file, which can only withhold more, never less.
# Either prefix is part of the matched token, so the whole path token is withheld. A different
# relative directory (``x/artifacts/a.npz``, ``../repo/a.npz``) never matches.
#
# Every quantifier is bounded, and the directories of an absolute prefix are taken possessively
# (a segment never contains the ``/`` that ends it, and the prefix never gives a segment back),
# so each start costs at most one bounded scan and one alternation: a search stays linear in the
# text however many names there are. Participant prose reaches this pattern on the service event
# loop (#1073 review).
_MAX_PREFIX_SEGMENTS: Final = 64
_MAX_SEGMENT_CHARS: Final = 255
_MAX_DOT_SLASHES: Final = 16
_ROOTS: Final = r"(?:file://)?(?:~[\w.-]{0,64}|\$\w{1,64}|\$\{\w{1,64}\})?/"
_DOT_SLASHES: Final = rf"\./(?:\.?/){{0,{_MAX_DOT_SLASHES}}}"


def _absolute_prefix(segment: str) -> str:
    return rf"{_ROOTS}(?:{segment}{{0,{_MAX_SEGMENT_CHARS}}}+/){{0,{_MAX_PREFIX_SEGMENTS}}}+"


# Unquoted prose has no token bound, so an unquoted segment stops at whitespace, quotes, ``<>|``
# and the list delimiters ``,`` ``;`` and brackets, and at a ``:`` that starts another path
# (``:/``, ``:~``, ``:$``, ``:./``, ``:../``); a ``:`` inside a directory or a URL port
# (``host:8080/``) is kept. An unquoted absolute path through a directory with spaces or those
# characters is not one token there. Stopping at them keeps the possessive prefix from running past
# one path into the next (``/r/a.npz,/r/b.npz``, ``/r/a.npz:~/b``). A name glued to other
# characters and then a ``/`` (``/r/a.npz~/x``, or a list entry that is a bare relative path,
# ``/r/a.npz:rel/x``) is read as a directory of a longer path and not recognised.
_ABSOLUTE_PREFIX: Final = _absolute_prefix(r"(?:[^\s/\"'`<>|,;:()\[\]{}]|:(?![/~$]|\.{1,2}/))")
# Inside one pair of quotes or backticks a path may contain spaces and the other quote characters
# (``"/Volumes/Bob's Mac/a.npz"``); the closing quote bounds the token, so a segment there may hold
# any character but that quote, a line break or a slash.
_QUOTED_ABSOLUTE_PREFIX: Final = _absolute_prefix(r"(?:(?!(?P=quote))[^\n/])")
_EXTRA_SEPARATORS: Final = re.compile(r"/(?:\.?/)+")


def _spelled(name: str) -> str:
    # ``a/b`` also matches ``a//b`` and ``a/./b``: the same path with empty or ``.`` segments.
    return r"/(?:\.?/){0,8}".join(re.escape(segment) for segment in name.split("/"))


def _longest_first(values: Iterable[str]) -> list[str]:
    return sorted({value for value in values if value}, key=lambda value: (-len(value), value))


def _union(names: Iterable[str]) -> str:
    return "(?:" + "|".join(_spelled(name) for name in _longest_first(names)) + ")"


@dataclass(frozen=True, slots=True)
class _Spellings:
    """One set of name spellings, split by the prefix each needs."""

    bare: frozenset[str]  # readable alone: a path with a directory, a basename with an extension
    relative: frozenset[str]  # behind ``./`` or quotes: every relative spelling
    bases: frozenset[str]  # behind an absolute prefix: each name's last component

    @classmethod
    def of(cls, spellings: Iterable[str]) -> _Spellings:
        quoted: set[str] = set()
        prefixed: set[str] = set()
        bare: set[str] = set()
        for spelling in spellings:
            if len(spelling) >= 2 and spelling[0] == '"' and spelling[-1] == '"':
                quoted.add(spelling[1:-1])
            elif spelling.startswith("./"):
                # ``./name`` (from ``_spellings``) counts only behind a prefix or in quotes,
                # so a plain word (``Summary``) without one stays readable.
                if len(spelling) > 2:
                    prefixed.add(spelling[2:])
            elif spelling:
                bare.add(spelling)
        relative = quoted | prefixed | bare
        bases = {name.rsplit("/", 1)[-1] for name in relative}
        return cls(frozenset(bare), frozenset(relative), frozenset(bases))


def _compile(names: _Spellings) -> re.Pattern[str]:
    # Longest first, and never inside a longer path-like token: ``a.npz`` does not match within
    # ``data.npz`` or ``x/a.npz.bak``, so unrelated names and prose stay readable. The groups say
    # which kind of spelling matched, so a match maps back to its names without another search.
    relative = _union(names.relative)
    bases = _union(names.bases)
    alternatives = [
        # A whole single-, double- or backtick-quoted path token, quotes included.
        r"(?P<quote>[\"'`])(?:(?:" + _DOT_SLASHES + ")?(?P<quoted_relative>" + relative + ")"
        "|" + _QUOTED_ABSOLUTE_PREFIX + "(?P<quoted_base>" + bases + r"))(?P=quote)",
        r"(?<![\w./-])(?:"
        + _DOT_SLASHES
        + "(?P<dotted_relative>"
        + relative
        + ")|"
        + _ABSOLUTE_PREFIX
        + "(?P<absolute_base>"
        + bases
        + ")"
        + ("|(?P<bare>" + _union(names.bare) + ")" if names.bare else "")
        + r")(?![\w/-]|\.\w)",
    ]
    return re.compile("|".join(f"(?:{alternative})" for alternative in alternatives))


def _pattern(spellings: Iterable[str]) -> re.Pattern[str]:
    return _compile(_Spellings.of(spellings))


class _NameMatcher:
    """Every name's spans in one pass per text: one union search, then dictionary lookups."""

    def __init__(self, paths: Sequence[str]) -> None:
        self._relative: dict[str, set[str]] = {}
        self._bases: dict[str, set[str]] = {}
        everything: set[str] = set()
        for path in paths:
            spellings = _spellings(path)
            everything.update(spellings)
            names = _Spellings.of(spellings)
            for name in names.relative:
                self._relative.setdefault(name, set()).add(path)
            for base in names.bases:
                self._bases.setdefault(base, set()).add(path)
        self._pattern = _compile(_Spellings.of(everything)) if everything else None

    def paths_in(self, text: str) -> set[str]:
        found: set[str] = set()
        if self._pattern is None:
            return found
        spans = [(0, len(text))]
        while spans:
            start, end = spans.pop()
            for match in self._pattern.finditer(text, start, end):
                for group, index in (
                    ("quoted_relative", self._relative),
                    ("dotted_relative", self._relative),
                    ("bare", self._relative),
                    ("quoted_base", self._bases),
                    ("absolute_base", self._bases),
                ):
                    value = match.group(group) if group in self._pattern.groupindex else None
                    if value is not None:
                        found.update(index.get(_EXTRA_SEPARATORS.sub("/", value), ()))
                if match.group("quote") is not None:
                    # A quoted token may hold several paths (``"/bin/cmp /r/b.npz /r/a.npz"``);
                    # the match names only its last one, so search its interior too. The
                    # interior holds no quote, so this never nests: still linear.
                    spans.append((match.start() + 1, match.end() - 1))
        return found


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
            # One union search per leaf, whatever the number of names (#1073 review).
            matcher = _NameMatcher(paths)
            strings = _strings({"document": result.document, "human_text": result.human_text})
            for pointer, text in strings.items():
                if _SECTION_TITLE.fullmatch(pointer):
                    continue
                if classify_result_leaf("receipt", source, pointer) in _NOT_PROSE:
                    continue
                hits = matcher.paths_in(text)
                if not hits:
                    continue
                for index, (path, spellings) in enumerate(spelled):
                    if path in hits:
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


def bounded_omitted_pointers(
    pointers: Sequence[str], *, limit: int = MAX_PROJECTION_CONTENT_LEAVES
) -> tuple[str, ...]:
    """Sorted, unique omitted pointers within the wire bound; never drops an omission.

    Past ``limit`` (the 512-pointer wire bound unless a delivery page needs fewer) the parent
    with the most omitted children replaces them (and anything else beneath it), until the list
    fits. A coalesced pointer still covers every omission it replaced; the local disclosure audit
    keeps each individual decision. Coalescing stops at top-level fields: the empty pointer is
    not a valid wire pointer.
    """

    current = set(pointers)
    while len(current) > limit:
        groups: dict[str, int] = {}
        for pointer in current:
            parent = pointer.rsplit("/", 1)[0]
            if parent:
                groups[parent] = groups.get(parent, 0) + 1
        if not groups:
            break
        parent = min(groups.items(), key=lambda row: (-row[1], row[0].encode()))[0]
        prefix = parent + "/"
        covered = any(parent.startswith(other + "/") for other in current)
        current = {pointer for pointer in current if not pointer.startswith(prefix)}
        if not covered:
            current.add(parent)
    return tuple(sorted(current, key=str.encode))
