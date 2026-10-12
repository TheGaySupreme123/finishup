"""Closed registry of manifest-verified static MCP guidance resources."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType
from typing import Final, cast

from yoetz.protocol.guidance_uris import GUIDANCE_TOPIC_URIS
from yoetz.version import read_verified_resource

__all__ = [
    "DEFAULT_GUIDANCE_PAGE_SIZE",
    "MAX_GUIDANCE_DOCUMENT_BYTES",
    "MAX_GUIDANCE_PAGE_SIZE",
    "MAX_GUIDANCE_PAGE_COUNT",
    "GUIDANCE_RESOURCES",
    "GUIDANCE_TOPIC_URIS",
    "GuidanceResource",
    "GuidanceResourceAnnotations",
    "GuidanceResourceError",
    "GuidanceAssemblyError",
    "GuidanceResourcePage",
    "GuidancePageAssembler",
    "list_resources",
    "resource_for_uri",
    "read_resource_page",
    "read_resource",
    "resolve_guidance_topic_uri",
]


class GuidanceResourceError(ValueError):
    """A bounded resource-registry failure with no caller-controlled text."""


# A page is deliberately smaller than the observed host response caps. Callers may request a
# smaller page for a stricter host, but they may not ask this read-only route to recreate the
# unbounded document response through one page. The lower bound leaves room for one UTF-8 scalar
# even when a caller chooses the smallest page.
DEFAULT_GUIDANCE_PAGE_SIZE: Final = 4096
MAX_GUIDANCE_PAGE_SIZE: Final = 16_384
MAX_GUIDANCE_DOCUMENT_BYTES: Final = 1_048_576
MAX_GUIDANCE_PAGE_COUNT: Final = 16_384
_MAX_GUIDANCE_PAGE_BYTES: Final = 65_536
_MIN_GUIDANCE_PAGE_SIZE: Final = 4
_GUIDANCE_HEADING: Final = re.compile(r"^(#{1,6}) (.+?)\s*$")


@dataclass(frozen=True, slots=True)
class GuidanceResourceAnnotations:
    """Honest MCP resource annotations: intended audience and relative priority."""

    audience: tuple[str, ...]
    priority: float


@dataclass(frozen=True, slots=True)
class GuidanceResource:
    uri: str
    logical_name: str
    name: str
    title: str
    description: str
    annotations: GuidanceResourceAnnotations
    media_type: str = "text/markdown"
    section_start: int | None = None
    section_end: int | None = None

    @property
    def source_bytes(self) -> bytes:
        """Return the complete verified source document backing this resource."""

        return read_verified_resource(self.logical_name)

    @property
    def bytes(self) -> bytes:
        payload = self.source_bytes
        if self.section_start is None and self.section_end is None:
            return payload
        if (
            self.section_start is None
            or self.section_end is None
            or self.section_start < 0
            or self.section_end < self.section_start
            or self.section_end > len(payload)
        ):
            raise GuidanceResourceError("guidance_topic_range_invalid")
        return payload[self.section_start : self.section_end]

    @property
    def text(self) -> str:
        return self.bytes.decode("utf-8", errors="strict")

    @property
    def size(self) -> int:
        return len(self.bytes)

    @property
    def digest(self) -> str:
        """The current source-byte digest used as the immutable guidance revision."""

        return "sha256:" + hashlib.sha256(self.bytes).hexdigest()

    @property
    def revision(self) -> str:
        """The source revision token.

        Guidance is packaged as verified bytes rather than fetched from a mutable store. Binding
        the revision to those bytes gives a caller one stable freshness check without inventing a
        second version registry.
        """

        return self.digest


@dataclass(frozen=True, slots=True)
class GuidanceResourcePage:
    """One UTF-8-safe, digest-bound page of a registered guidance document."""

    resource: GuidanceResource
    page: int
    page_size: int
    offset: int
    text: str
    byte_count: int
    total_byte_count: int
    page_count: int
    digest: str
    revision: str

    @property
    def complete(self) -> bool:
        return self.page + 1 == self.page_count

    @property
    def next_page(self) -> int | None:
        return None if self.complete else self.page + 1

    @property
    def continuation(self) -> dict[str, object] | None:
        if self.next_page is None:
            return None
        return {
            "uri": self.resource.uri,
            "page": str(self.next_page),
            "page_size": str(self.page_size),
            "revision": self.revision,
            "digest": self.digest,
        }


class GuidanceAssemblyError(ValueError):
    """A bounded host-delivery or reconstruction failure."""


class GuidancePageAssembler:
    """Validate host-visible pages before exposing a reconstructed guidance document.

    A service digest and a final-page ``complete`` flag describe the page the service emitted;
    neither proves that the host delivered every page. This assembler is the consumer-side proof
    boundary: it rejects clipped begin/end markers, duplicate or missing pages, offset gaps,
    revision changes, byte-count mismatches, and a final digest mismatch. Callers can retry the
    exact rejected page, or restart at page zero when the revision changes.
    """

    __slots__ = (
        "_uri",
        "_revision",
        "_digest",
        "_total_byte_count",
        "_page_size",
        "_page_count",
        "_pages",
        "_host_proof_required",
    )

    def __init__(self, *, host_proof_required: bool = True) -> None:
        self._uri: str | None = None
        self._revision: str | None = None
        self._digest: str | None = None
        self._total_byte_count: int | None = None
        self._page_size: int | None = None
        self._page_count: int | None = None
        self._pages: dict[int, tuple[int, int, str, bool]] = {}
        self._host_proof_required = host_proof_required

    @property
    def page_count(self) -> int | None:
        return self._page_count

    @property
    def received_pages(self) -> tuple[int, ...]:
        return tuple(sorted(self._pages))

    def add(self, wire: Mapping[str, object], *, host_text: str | None = None) -> None:
        """Validate and retain one structured page plus its optional host-visible rendering."""

        if wire.get("ok") is not True:
            raise GuidanceAssemblyError("guidance_page_result_not_success")
        required = (
            "uri",
            "document_id",
            "revision",
            "digest",
            "total_byte_count",
            "page",
            "page_size",
            "page_offset",
            "page_byte_count",
            "page_count",
            "complete",
            "text",
        )
        if any(key not in wire for key in required):
            raise GuidanceAssemblyError("guidance_page_metadata_missing")
        uri = wire["uri"]
        document_id = wire["document_id"]
        revision = wire["revision"]
        digest = wire["digest"]
        text = wire["text"]
        if (
            type(uri) is not str
            or type(document_id) is not str
            or uri != document_id
            or type(revision) is not str
            or type(digest) is not str
            or revision != digest
            or type(text) is not str
        ):
            raise GuidanceAssemblyError("guidance_page_identity_invalid")
        try:
            page = _canonical_nonnegative_int(wire["page"])
            page_size = _canonical_nonnegative_int(wire["page_size"])
            offset = _bounded_int(wire["page_offset"], maximum=MAX_GUIDANCE_DOCUMENT_BYTES)
            page_byte_count = _bounded_int(
                wire["page_byte_count"], maximum=_MAX_GUIDANCE_PAGE_BYTES
            )
            total_byte_count = _bounded_int(
                wire["total_byte_count"], maximum=MAX_GUIDANCE_DOCUMENT_BYTES
            )
            page_count = _canonical_positive_int(wire["page_count"])
        except GuidanceAssemblyError:
            raise
        if page_size < _MIN_GUIDANCE_PAGE_SIZE or page_size > MAX_GUIDANCE_PAGE_SIZE:
            raise GuidanceAssemblyError("guidance_page_size_invalid")
        minimum_page_count = max(1, (total_byte_count + page_size - 1) // page_size)
        if page_count < minimum_page_count or page_count > MAX_GUIDANCE_PAGE_COUNT:
            raise GuidanceAssemblyError("guidance_page_count_invalid")
        if page >= page_count:
            raise GuidanceAssemblyError("guidance_page_invalid")
        if page_byte_count != len(text.encode("utf-8")):
            raise GuidanceAssemblyError("guidance_page_byte_count_mismatch")
        if offset + page_byte_count > total_byte_count:
            raise GuidanceAssemblyError("guidance_page_offset_invalid")
        complete = wire["complete"]
        if type(complete) is not bool or complete != (page + 1 == page_count):
            raise GuidanceAssemblyError("guidance_completion_mismatch")
        raw_continuation = wire.get("continuation")
        if complete:
            if raw_continuation is not None:
                raise GuidanceAssemblyError("guidance_completion_continuation_invalid")
        else:
            if not isinstance(raw_continuation, Mapping):
                raise GuidanceAssemblyError("guidance_continuation_missing")
            continuation = cast(Mapping[str, object], raw_continuation)
            if (
                continuation.get("uri") != uri
                or continuation.get("page_size") != str(page_size)
                or continuation.get("revision") != revision
                or continuation.get("digest") != digest
            ):
                raise GuidanceAssemblyError("guidance_continuation_invalid")
            try:
                continuation_page = _canonical_nonnegative_int(continuation.get("page"))
            except GuidanceAssemblyError:
                raise GuidanceAssemblyError("guidance_continuation_invalid") from None
            if continuation_page != page + 1:
                raise GuidanceAssemblyError("guidance_continuation_invalid")
        if self._uri is None:
            self._uri = uri
            self._revision = revision
            self._digest = digest
            self._total_byte_count = total_byte_count
            self._page_size = page_size
            self._page_count = page_count
        elif (
            uri != self._uri
            or revision != self._revision
            or digest != self._digest
            or total_byte_count != self._total_byte_count
            or page_size != self._page_size
            or page_count != self._page_count
        ):
            raise GuidanceAssemblyError("guidance_revision_or_shape_changed")
        if page in self._pages and self._pages[page] != (offset, page_byte_count, text, complete):
            raise GuidanceAssemblyError("guidance_page_duplicate_mismatch")
        if page in self._pages:
            raise GuidanceAssemblyError("guidance_page_duplicate")
        if self._host_proof_required and host_text is None:
            raise GuidanceAssemblyError("guidance_host_delivery_missing")
        if host_text is not None:
            _validate_host_page_rendering(
                host_text,
                uri=uri,
                page=page,
                page_count=page_count,
                offset=offset,
                page_byte_count=page_byte_count,
                total_byte_count=total_byte_count,
                revision=revision,
                digest=digest,
                complete=complete,
                text=text,
            )
        self._pages[page] = (offset, page_byte_count, text, complete)

    def assemble(self) -> str:
        """Return the document only after every page and the final digest validate."""

        if (
            self._page_count is None
            or self._total_byte_count is None
            or self._digest is None
            or len(self._pages) != self._page_count
            or set(self._pages) != set(range(self._page_count))
        ):
            raise GuidanceAssemblyError("guidance_pages_missing")
        ordered = [self._pages[index] for index in range(self._page_count)]
        cursor = 0
        parts: list[str] = []
        for offset, byte_count, text, complete in ordered:
            if offset != cursor:
                raise GuidanceAssemblyError("guidance_page_offset_gap")
            if complete != (offset + byte_count == self._total_byte_count):
                raise GuidanceAssemblyError("guidance_completion_mismatch")
            parts.append(text)
            cursor += byte_count
        if cursor != self._total_byte_count:
            raise GuidanceAssemblyError("guidance_total_byte_count_mismatch")
        assembled = "".join(parts)
        digest = "sha256:" + hashlib.sha256(assembled.encode("utf-8")).hexdigest()
        if digest != self._digest:
            raise GuidanceAssemblyError("guidance_digest_mismatch")
        return assembled


def _canonical_nonnegative_int(value: object) -> int:
    if type(value) is not str or not value.isdigit() or (value != "0" and value.startswith("0")):
        raise GuidanceAssemblyError("guidance_integer_invalid")
    parsed = int(value)
    if parsed > 9_007_199_254_740_991:
        raise GuidanceAssemblyError("guidance_integer_invalid")
    return parsed


def _canonical_positive_int(value: object) -> int:
    parsed = _canonical_nonnegative_int(value)
    if parsed == 0:
        raise GuidanceAssemblyError("guidance_integer_invalid")
    return parsed


def _bounded_int(value: object, *, maximum: int) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise GuidanceAssemblyError("guidance_integer_invalid")
    return value


def _validate_host_page_rendering(
    host_text: str,
    *,
    uri: str,
    page: int,
    page_count: int,
    offset: int,
    page_byte_count: int,
    total_byte_count: int,
    revision: str,
    digest: str,
    complete: bool,
    text: str,
) -> None:
    """Require both sentinels and exact page bytes in a model-visible rendering."""

    begin = (
        f"YOETZ_GUIDANCE_PAGE_BEGIN document={uri} page={page} page_count={page_count} "
        f"offset={offset} bytes={page_byte_count} total_bytes={total_byte_count} "
        f"revision={revision} digest={digest}"
    )
    end = (
        f"YOETZ_GUIDANCE_PAGE_END complete={'yes' if complete else 'no'} "
        f"next_page={'none' if complete else page + 1} revision={revision} digest={digest}"
    )
    if not host_text.startswith(begin):
        raise GuidanceAssemblyError("guidance_host_delivery_incomplete")
    separator = host_text.find("\n", len(begin))
    if separator < 0 or not host_text.endswith(end):
        raise GuidanceAssemblyError("guidance_host_delivery_incomplete")
    delivered_text = host_text[separator + 1 : -(len(end) + 1)]
    if delivered_text != text:
        raise GuidanceAssemblyError("guidance_host_delivery_incomplete")


def _page_boundaries(payload: bytes, page_size: int) -> tuple[int, ...]:
    """Return page starts/ends without ever splitting a UTF-8 scalar value."""

    boundaries = [0]
    cursor = 0
    total = len(payload)
    while cursor < total:
        end = min(cursor + page_size, total)
        # A UTF-8 continuation byte can only appear after the first byte of a scalar. Move the
        # boundary backwards until the slice is decodable. A page size of at least four means the
        # scalar cannot be larger than the requested bound, so this cannot loop forever.
        while end > cursor:
            try:
                payload[cursor:end].decode("utf-8", errors="strict")
                break
            except UnicodeDecodeError:
                end -= 1
        if end == cursor:
            raise GuidanceResourceError("guidance_page_size_too_small")
        boundaries.append(end)
        cursor = end
    # An empty document still has one addressable, complete page. The shipped registry is
    # nonempty today, but keeping this shape explicit makes the helper safe for future resources.
    return tuple(boundaries if total else (0,))


def read_resource_page(
    uri: str,
    *,
    page: int = 0,
    page_size: int = DEFAULT_GUIDANCE_PAGE_SIZE,
    expected_revision: str | None = None,
    expected_digest: str | None = None,
) -> GuidanceResourcePage:
    """Read a bounded page and bind it to the current verified source bytes.

    ``expected_revision`` and ``expected_digest`` are independent caller checks. They currently
    resolve to the same source-byte digest, but keeping both lets the wire contract distinguish
    source freshness from reconstructed-content integrity. A mismatch is fail-closed so a caller
    cannot silently combine pages from different guidance revisions.
    """

    if type(page) is not int or page < 0:
        raise GuidanceResourceError("guidance_page_invalid")
    if (
        type(page_size) is not int
        or not _MIN_GUIDANCE_PAGE_SIZE <= page_size <= MAX_GUIDANCE_PAGE_SIZE
    ):
        raise GuidanceResourceError("guidance_page_size_invalid")
    resource = _resource_for_uri(uri)
    try:
        payload = resource.bytes
    except BaseException:
        raise GuidanceResourceError("guidance_resource_integrity_failed") from None
    total_byte_count = len(payload)
    if total_byte_count > MAX_GUIDANCE_DOCUMENT_BYTES:
        raise GuidanceResourceError("guidance_document_too_large")
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if expected_revision is not None and expected_revision != digest:
        raise GuidanceResourceError("guidance_revision_mismatch")
    if expected_digest is not None and expected_digest != digest:
        raise GuidanceResourceError("guidance_digest_mismatch")
    boundaries = _page_boundaries(payload, page_size)
    page_count = max(1, len(boundaries) - 1)
    if page_count > MAX_GUIDANCE_PAGE_COUNT:
        raise GuidanceResourceError("guidance_page_count_invalid")
    if page >= page_count:
        raise GuidanceResourceError("guidance_page_out_of_range")
    start = boundaries[page]
    end = boundaries[page + 1] if page + 1 < len(boundaries) else start
    text = payload[start:end].decode("utf-8", errors="strict")
    return GuidanceResourcePage(
        resource=resource,
        page=page,
        page_size=page_size,
        offset=start,
        text=text,
        byte_count=end - start,
        total_byte_count=total_byte_count,
        page_count=page_count,
        digest=digest,
        revision=digest,
    )


GUIDANCE_RESOURCES: Final = (
    GuidanceResource(
        uri="yoetz://guidance/agent-instructions.md",
        logical_name="guidance/agent-instructions.md",
        name="agent-instructions.md",
        title="Yoetz agent instructions",
        description=(
            "Read at session start, and re-read if the initialize instructions are not in "
            "context. The non-negotiable floor: when to activate, how often to call each "
            "operation, what is never published, and how honestly to word a conclusion."
        ),
        annotations=GuidanceResourceAnnotations(audience=("assistant",), priority=1.0),
    ),
    GuidanceResource(
        uri="yoetz://guidance/workflow.md",
        logical_name="guidance/workflow.md",
        name="workflow.md",
        title="Yoetz cooperative workflow",
        description=(
            "Read before the first start call. Task identity, material-work cadence, resume and "
            "handoff behavior, and pointers to conditional review, setup, and recovery guidance."
        ),
        annotations=GuidanceResourceAnnotations(audience=("assistant",), priority=0.9),
    ),
    GuidanceResource(
        uri="yoetz://guidance/publication-policy.md",
        logical_name="guidance/publication-policy.md",
        name="publication-policy.md",
        title="Yoetz publication policy",
        description=(
            "Read before the first publish_work call. What is material enough to publish, how "
            "large a batch should be, the sixteen event families, and what is never published."
        ),
        annotations=GuidanceResourceAnnotations(audience=("assistant",), priority=0.8),
    ),
    GuidanceResource(
        uri="yoetz://guidance/coverage-and-receipts.md",
        logical_name="guidance/coverage-and-receipts.md",
        name="coverage-and-receipts.md",
        title="Yoetz coverage and receipts",
        description=(
            "Read before the first check call. The coverage vector, why a recorded finding stays "
            "recorded, when to stop requesting AI-powered review, and how to word a conclusion."
        ),
        annotations=GuidanceResourceAnnotations(audience=("assistant",), priority=0.8),
    ),
    GuidanceResource(
        uri="yoetz://guidance/request-templates.md",
        logical_name="guidance/request-templates.md",
        name="request-templates.md",
        title="Yoetz request templates",
        description=(
            "Read when a host drops schema metadata or after an invalid request, and before setup, "
            "consent, credential/vault operations, import, or recommendation decisions. Complete "
            "copy-ready bodies for all six operations and all nine ordinary publication "
            "families, with explicit placeholder replacement rules."
        ),
        annotations=GuidanceResourceAnnotations(audience=("assistant",), priority=0.7),
    ),
)


_RESOURCE_BY_URI: Final = MappingProxyType(
    {resource.uri: resource for resource in GUIDANCE_RESOURCES}
)
_FOCUSED_TOPIC_FILES: Final = frozenset(
    {
        "startup.md",
        "recovery.md",
        "publication.md",
        "review.md",
        "receipt.md",
        "delegation.md",
        "consent.md",
        "page-delivery.md",
    }
)
_FOCUSED_TOPIC_URIS: Final = frozenset(f"yoetz://guidance/{name}" for name in _FOCUSED_TOPIC_FILES)


def _guidance_anchor(value: str) -> str:
    """Use the stable, human-readable anchor form shared by guidance links and topics."""

    lowered = value.casefold()
    lowered = re.sub(r"[^\w\s-]", "", lowered, flags=re.UNICODE)
    return re.sub(r"[\s_-]+", "-", lowered).strip("-")


def _guidance_headings(text: str) -> tuple[tuple[int, str, int, int], ...]:
    """Return Markdown headings while ignoring fenced code examples."""

    headings: list[tuple[int, str, int, int]] = []
    offset = 0
    fence: str | None = None
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            fence = None if fence == marker else marker if fence is None else fence
        elif fence is None:
            content = line.rstrip("\r\n")
            match = _GUIDANCE_HEADING.fullmatch(content)
            if match is not None:
                headings.append(
                    (len(match.group(1)), match.group(2).strip(), offset, offset + len(line))
                )
        offset += len(line)
    return tuple(headings)


@lru_cache(maxsize=256)
def _topic_resource(uri: str) -> GuidanceResource:
    """Resolve one catalogued heading to a byte-bounded view of its source document."""

    if uri in _FOCUSED_TOPIC_URIS:
        name = uri.rsplit("/", 1)[-1]
        stem = name.removesuffix(".md").replace("-", " ")
        return GuidanceResource(
            uri=uri,
            logical_name=f"guidance/{name}",
            name=name,
            title=f"Yoetz {stem} topic",
            description="Small triggered guidance topic; read it only when its procedure applies.",
            annotations=GuidanceResourceAnnotations(audience=("assistant",), priority=0.7),
        )
    base_uri, separator, anchor = uri.partition("#")
    if not separator or not anchor:
        raise GuidanceResourceError("guidance_resource_uri_unregistered")
    try:
        source = _RESOURCE_BY_URI[base_uri]
    except KeyError:
        raise GuidanceResourceError("guidance_resource_uri_unregistered") from None
    if uri not in GUIDANCE_TOPIC_URIS:
        raise GuidanceResourceError("guidance_resource_uri_unregistered")
    text = source.source_bytes.decode("utf-8", errors="strict")
    headings = _guidance_headings(text)
    seen: dict[str, int] = {}
    selected: tuple[int, int, str] | None = None
    for index, heading in enumerate(headings):
        level, heading_title, heading_start, _heading_end = heading
        slug = _guidance_anchor(heading_title)
        occurrence = seen.get(slug, 0) + 1
        seen[slug] = occurrence
        candidate = slug if occurrence == 1 else f"{slug}-{occurrence}"
        if candidate != anchor:
            continue
        end = len(text)
        for following in headings[index + 1 :]:
            following_level, _following_title, following_start, _following_end = following
            # A document title's topic is its introduction only; otherwise the first H2 would
            # make the title topic the entire long archive. Nested headings stay with their
            # parent procedure, while every heading also receives its own narrower topic.
            if (level == 1 and following_level >= 2) or following_level <= level:
                end = following_start
                break
        selected = (heading_start, end, heading_title)
        break
    if selected is None:
        raise GuidanceResourceError("guidance_resource_uri_unregistered")
    start_char, end_char, title = selected
    start = len(text[:start_char].encode("utf-8"))
    end = len(text[:end_char].encode("utf-8"))
    return GuidanceResource(
        uri=uri,
        logical_name=source.logical_name,
        name=f"{source.name}#{anchor}",
        title=f"{source.title}: {title}",
        description=f"Bounded topic from {source.name}; read this procedure when its trigger applies.",
        annotations=source.annotations,
        media_type=source.media_type,
        section_start=start,
        section_end=end,
    )


# An explicit ``<a id="..."></a>`` target a guidance document writes beside a heading. Several name
# the procedure more briefly than the heading (``attempt-accounting``), so an agent reading the
# text requests them.
_HTML_ANCHOR: Final = re.compile(r'<a id="([a-z0-9][a-z0-9-]{0,127})"></a>', re.ASCII)
_MAX_GUESSED_TOPIC_URI_CHARS: Final = 512


@lru_cache(maxsize=16)
def _document_topic_anchors(document_uri: str) -> tuple[tuple[str, ...], Mapping[str, str]]:
    """One document's catalogued topic anchors, and its explicit anchor ids mapped onto them.

    An explicit anchor maps to the catalogued topic of the heading it sits under, computed with
    the same slug and repeat-suffix rule ``_topic_resource`` reads, so both agree on the section.
    """

    prefix = document_uri + "#"
    catalogued = tuple(uri[len(prefix) :] for uri in GUIDANCE_TOPIC_URIS if uri.startswith(prefix))
    text = _RESOURCE_BY_URI[document_uri].source_bytes.decode("utf-8", errors="strict")
    seen: dict[str, int] = {}
    owners: list[tuple[int, str]] = []
    for _level, title, start, _end in _guidance_headings(text):
        slug = _guidance_anchor(title)
        occurrence = seen.get(slug, 0) + 1
        seen[slug] = occurrence
        owners.append((start, slug if occurrence == 1 else f"{slug}-{occurrence}"))
    aliases: dict[str, str] = {}
    for match in _HTML_ANCHOR.finditer(text):
        owner = None
        for start, anchor in owners:
            if start > match.start():
                break
            owner = anchor
        if owner in catalogued and match.group(1) not in catalogued:
            aliases.setdefault(match.group(1), owner)
    return catalogued, MappingProxyType(aliases)


def resolve_guidance_topic_uri(uri: object) -> str | None:
    """The one catalogued topic a near-miss anchor names, or ``None`` (tb4n4, issue #1049).

    Seven tb4n4 reads guessed an anchor and were refused. For one of the five guidance documents,
    an anchor resolves, in this order and deterministically, when it is:

    1. a catalogued anchor once spelled the shared slug way (``publish_work-decision`` and
       ``Publish-Work-Decision`` are ``publish-work-decision``: case, ``_`` and punctuation fold);
    2. an explicit ``<a id>`` target the document writes under a catalogued heading
       (``attempt-accounting`` is ``requested-items-and-attempt-accounting``);
    3. words that all appear in exactly one catalogued anchor of that document
       (``decision`` is ``publish-work-decision``). Two or more candidates are ambiguous and never
       resolve.

    Anything else, a focused topic or an unknown document returns ``None``, and the caller keeps
    its refusal with the registered alternatives. The URI is never interpreted as a path.
    """

    if type(uri) is not str or len(uri) > _MAX_GUESSED_TOPIC_URI_CHARS:
        return None
    document, separator, anchor = uri.partition("#")
    if not separator or not anchor or document not in _RESOURCE_BY_URI:
        return None
    try:
        catalogued, aliases = _document_topic_anchors(document)
    except ValueError, OSError:
        # An unreadable document resolves nothing; the caller keeps its ordinary refusal.
        return None
    slug = _guidance_anchor(anchor)
    if not slug.isascii() or not slug:
        return None
    if slug in catalogued:
        return f"{document}#{slug}"
    alias = aliases.get(slug)
    if alias is not None:
        return f"{document}#{alias}"
    words = frozenset(slug.split("-"))
    matches = [candidate for candidate in catalogued if words <= frozenset(candidate.split("-"))]
    return f"{document}#{matches[0]}" if len(matches) == 1 else None


def _resource_for_uri(uri: object) -> GuidanceResource:
    if type(uri) is not str:
        raise GuidanceResourceError("guidance_resource_uri_invalid")
    try:
        return _RESOURCE_BY_URI[uri]
    except KeyError:
        return _topic_resource(uri)


def resource_for_uri(uri: object) -> GuidanceResource:
    """Return one registered document or bounded heading topic by its exact URI."""

    return _resource_for_uri(uri)


def list_resources() -> tuple[GuidanceResource, ...]:
    """Return the exact stable registry after verifying every resource member."""

    try:
        for resource in GUIDANCE_RESOURCES:
            resource.bytes
    except GuidanceResourceError:
        raise
    except BaseException:
        raise GuidanceResourceError("guidance_resource_integrity_failed") from None
    return GUIDANCE_RESOURCES


def read_resource(uri: str) -> bytes:
    """Read one exact URI registry key; URI text is never interpreted as a path."""

    resource = _resource_for_uri(uri)
    try:
        return resource.bytes
    except BaseException:
        raise GuidanceResourceError("guidance_resource_integrity_failed") from None
