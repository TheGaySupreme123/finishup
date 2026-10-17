"""FinishUP's own bounded description of a binary task input it never sends whole (issue #1082).

A read-only task input (a spec, a dataset, a source the task names) reaches the review packet as a
text excerpt. A binary input (an image, a PDF, a spreadsheet, a NumPy array, an archive) has no
useful excerpt, so instead of skipping it FinishUP writes a short description of it: the format
its leading bytes declare, its size, a SHA-256 of the bytes read, and the few facts the format
states about itself (dimensions, a page estimate, sheet names and first rows, first paragraphs,
member names, an array's shape). The description is FinishUP's own text, written from at most the
leading bytes the service read; the file itself is never carried.

Every input is untrusted, so the summarizer:

- is pure and deterministic: no network, filesystem, subprocess, or clock, and the same bytes
  always give the same text;
- never raises: a header it cannot parse leaves only the format, size, and digest lines;
- opens an archive only through ``zipfile`` over the bytes in memory, refuses a member whose
  declared size exceeds 2 MiB or whose declared compression ratio exceeds 100:1, reads each member
  with an explicit bound, and reads at most 4 MiB uncompressed from one archive;
- parses an XML part only when it decodes as UTF-8 and carries no ``<!DOCTYPE`` or ``<!ENTITY``,
  and parses the decoded text, so the declaration that was checked is the one parsed;
- quotes text from the file (cell values, paragraphs, member and sheet names) only after replacing
  control and invisible formatting characters, collapsing whitespace, and capping its length;
  quoted rows, paragraphs, and member names are indented two spaces, and every other line starts
  with a ``key:`` FinishUP wrote;
- scans each quoted value whole, before it is normalized or cut, with the shared credential
  scanner, and quotes a flagged value only as ``[REDACTED]`` (a recognized credential) or
  ``[withheld-by-yoetz:possible-credential]`` (one that only looks like a credential): a cut
  value could otherwise keep a fragment too short for any later scan to recognize (PR #1086
  review R1-04; ``summarize_task_input`` reports that a value was withheld);
- caps the facts at ``MAX_INPUT_SUMMARY_BYTES`` and the quoted listing at
  ``MAX_INPUT_SUMMARY_TABLE_BYTES``, keeping whole lines only and ending a cut part with
  ``... (summary cut)``.

``declared_binary_format`` tells the task-input reader which signatures it summarizes even when
their bytes hold no NUL (an all-ASCII PDF), so the summary path is chosen the same way everywhere.
"""

from __future__ import annotations

import hashlib
import io
import itertools
import re
import zipfile
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from typing import Final, Literal
from xml.etree import ElementTree

from finishup.observability.privacy import (
    EGRESS_CREDENTIAL_PLACEHOLDER,
    scan_finding_is_heuristic,
    scan_for_sensitive_content,
)

__all__ = [
    "MAX_INPUT_SUMMARY_BYTES",
    "MAX_INPUT_SUMMARY_TABLE_BYTES",
    "declared_binary_format",
    "summarize_binary_input",
    "summarize_task_input",
]

# The facts part (format, size, digest, header facts) and the quoted listing (rows, paragraphs,
# member names) are capped separately; together they fit one task input's text budget.
MAX_INPUT_SUMMARY_BYTES: Final = 4_096
MAX_INPUT_SUMMARY_TABLE_BYTES: Final = 12_288

_CUT_LINE: Final = "... (summary cut)"
_QUOTE: Final = "  "
# The markers the check-time change and task inputs already use (``_redacted_text``), so the
# reviewer reads a withheld summary value exactly like a redacted line of an input.
_REDACTED_VALUE: Final = "[REDACTED]"
_POSSIBLE_CREDENTIAL_VALUE: Final = EGRESS_CREDENTIAL_PLACEHOLDER.decode("ascii")
# Set by ``summarize_task_input`` for one call: a value was withheld as a possible credential.
_withheld: ContextVar[list[bool] | None] = ContextVar(
    "finishup_input_summary_withheld", default=None
)

_MAX_MEMBER_BYTES: Final = 2 * 1024 * 1024
_MAX_MEMBER_RATIO: Final = 100
_MAX_ARCHIVE_READ_BYTES: Final = 4 * 1024 * 1024

_MAX_SHEET_NAMES: Final = 16
_MAX_SHEET_NAME_CHARS: Final = 64
_MAX_SHEET_TABLES: Final = 4
_MAX_SHEET_ROWS: Final = 20
_MAX_SHEET_COLUMNS: Final = 20
_MAX_CELL_CHARS: Final = 64
_MAX_PARAGRAPHS: Final = 40
_MAX_PARAGRAPH_CHARS: Final = 200
_MAX_MEMBER_NAMES: Final = 32
_MAX_MEMBER_NAME_CHARS: Final = 128
_MAX_DTYPE_CHARS: Final = 64
_MAX_SHAPE_DIMENSIONS: Final = 32
_MAX_JPEG_SEGMENTS: Final = 1_024
_MAX_NPY_HEADER_BYTES: Final = 65_536
_PDF_HEADER_WINDOW: Final = 1_024

_PNG: Final = "PNG image"
_JPEG: Final = "JPEG image"
_GIF: Final = "GIF image"
_BMP: Final = "BMP image"
_WEBP: Final = "WebP image"
_TIFF: Final = "TIFF image"
_PDF: Final = "PDF document"
_XLSX: Final = "XLSX workbook"
_DOCX: Final = "DOCX document"
_ZIP: Final = "ZIP archive"
_NPY: Final = "NumPy array (.npy)"
_GZIP: Final = "gzip data"
_HDF5: Final = "HDF5 data"
_SQLITE: Final = "SQLite database"
_ELF: Final = "ELF executable"
_MACHO: Final = "Mach-O executable"
_PE: Final = "PE executable"
_BINARY: Final = "binary data"

_WORKBOOK: Final = "xl/workbook.xml"
_WORKBOOK_RELATIONSHIPS: Final = "xl/_rels/workbook.xml.rels"
_SHARED_STRINGS: Final = "xl/sharedStrings.xml"
_DOCUMENT: Final = "word/document.xml"
_DOCX_EXTENSIONS: Final = frozenset({".docx", ".docm", ".dotx", ".dotm"})
_XLSX_EXTENSIONS: Final = frozenset({".xlsx", ".xlsm", ".xltx", ".xltm"})

_PNG_COLOR_TYPES: Final[Mapping[int, str]] = {
    0: "grayscale",
    2: "truecolor (RGB)",
    3: "indexed (palette)",
    4: "grayscale with alpha",
    6: "truecolor with alpha (RGBA)",
}
_ELF_MACHINES: Final[Mapping[int, str]] = {
    3: "x86",
    8: "mips",
    20: "powerpc",
    21: "powerpc64",
    40: "arm",
    62: "x86-64",
    183: "aarch64",
    243: "riscv",
}
_BMP_HEADER_SIZES: Final = frozenset({12, 16, 40, 52, 56, 64, 108, 124})
_MACHO_MAGICS: Final = frozenset(
    {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
)
_MACHO_FAT_MAGICS: Final = frozenset({b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"})
_TIFF_ORDERS: Final[Mapping[bytes, str]] = {
    b"II*\x00": "little",
    b"II+\x00": "little",
    b"MM\x00*": "big",
    b"MM\x00+": "big",
}
_HDF5_SIGNATURE: Final = b"\x89HDF\r\n\x1a\n"

# C0 and C1 controls, DEL, and the invisible characters that can hide, reorder, or smuggle text
# (soft hyphen, blank fillers, variation selectors, zero-width characters, bidirectional
# overrides and isolates, line and paragraph separators, the byte-order mark, interlinear
# annotation, Unicode tag characters), plus lone surrogates, which UTF-8 cannot carry.
_UNSAFE_CHARACTERS: Final = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f"
    r"\u200b-\u200f\u2028-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffb"
    r"\ud800-\udfff\U000e0000-\U000e0fff]"
)
_PDF_VERSION: Final = re.compile(rb"%PDF-([0-9]{1,2}\.[0-9]{1,2})")
_PDF_PAGE: Final = re.compile(rb"/Type\s*/Page(?![A-Za-z0-9_.#-])")
_NPY_DESCR: Final = re.compile(r"""['"]descr['"]\s*:\s*(?:'([^']*)'|"([^"]*)"|(\[))""")
_NPY_FORTRAN: Final = re.compile(r"""['"]fortran_order['"]\s*:\s*(True|False)""")
_NPY_SHAPE: Final = re.compile(r"""['"]shape['"]\s*:\s*\(([^()]*)\)""")
_NPY_DIMENSION: Final = re.compile(r"([0-9]{1,20})L?")
_CELL_REFERENCE: Final = re.compile(r"([A-Za-z]{1,3})[0-9]*")
# PDF object structure: a ``%PDF-`` header after other bytes counts as a PDF for dispatch only
# beside it, so a text file that merely mentions ``%PDF-`` stays text.
_PDF_OBJECT: Final = re.compile(rb"[0-9]+\s+[0-9]+\s+obj\b")

type _Element = ElementTree.Element
type _Description = tuple[str, list[str], list[str]]
type _Describer = Callable[[bytes, str], _Description]


def summarize_task_input(name: str, content: bytes, size: int) -> tuple[str, bool]:
    """``summarize_binary_input`` and whether it withheld a quoted value as a possible credential.

    The task-input reader marks such a summary ``redacted``, so the review discloses it like any
    redacted input (PR #1086 review R1-04).
    """

    withheld: list[bool] = []
    token = _withheld.set(withheld)
    try:
        text = summarize_binary_input(name, content, size)
    finally:
        _withheld.reset(token)
    return text, bool(withheld)


def declared_binary_format(content: bytes) -> bool:
    """Whether ``content`` starts with a signature this module summarizes (PR #1086 review R1-08).

    The NUL sniff alone misses a binary or document format whose bytes hold no NUL, such as an
    all-ASCII PDF. Every signature ``_detect`` knows counts at the start of the file; a ``%PDF-``
    header later in the first KiB counts only beside PDF object structure. Never raises.
    """

    try:
        data = bytes(content)
        format_name, _ = _detect(data)
    except Exception:
        return False
    if format_name == _BINARY:
        return False
    if format_name == _PDF and not data.startswith(b"%PDF-"):
        return b"endobj" in data and _PDF_OBJECT.search(data) is not None
    return True


def summarize_binary_input(name: str, content: bytes, size: int) -> str:
    """FinishUP's bounded plain-text description of a binary input; never raises.

    ``name`` is the input's path, used only for its extension as a tiebreak between formats that
    share a signature (a ZIP whose members cannot be read); it is never echoed. ``content`` is the
    leading bytes the service read (at most 1 MiB, possibly the whole file) and ``size`` the file's
    full byte size. The text is one ``key: value`` fact per line, starting with ``format:``,
    ``size:``, and ``sha256:`` (of ``content``, marked when that is only the first bytes), then the
    facts the format states, then any quoted listing indented two spaces. It is at most
    ``MAX_INPUT_SUMMARY_BYTES + MAX_INPUT_SUMMARY_TABLE_BYTES`` bytes of UTF-8, and the same
    arguments always give the same text.
    """

    try:
        data = bytes(content)
        total = max(int(size), len(data))
    except Exception:
        data, total = b"", 0
    digest = hashlib.sha256(data).hexdigest()
    if len(data) < total:
        digest += f" (first {len(data)} bytes)"
    try:
        format_name, facts, table = _describe(data, _extension(name))
    except Exception:
        format_name, facts, table = _BINARY, [], []
    head, head_cut = _bounded(
        [f"format: {format_name}", f"size: {total} bytes", f"sha256: {digest}", *facts],
        MAX_INPUT_SUMMARY_BYTES,
    )
    lines = head if head_cut else head + _bounded(table, MAX_INPUT_SUMMARY_TABLE_BYTES)[0]
    return "".join(f"{line}\n" for line in lines)


def _describe(data: bytes, extension: str) -> _Description:
    """The format the signature declares, with what its describer could read; a describer that
    fails leaves only the format."""

    format_name, describer = _detect(data)
    try:
        return describer(data, extension)
    except Exception:
        return format_name, [], []


def _detect(data: bytes) -> tuple[str, _Describer]:
    """The format by signature (magic bytes) at the start, checked from the most to the least
    specific; a PDF header later in the first KiB is checked last."""

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return _PNG, _png
    if data.startswith(b"\xff\xd8\xff"):
        return _JPEG, _jpeg
    if data[:6] in {b"GIF87a", b"GIF89a"}:
        return _GIF, _gif
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return _WEBP, _webp
    if data[:4] in _TIFF_ORDERS:
        return _TIFF, _tiff
    if data.startswith(b"%PDF-"):
        return _PDF, _pdf
    if data[:4] in {b"PK\x03\x04", b"PK\x05\x06"}:
        return _ZIP, _zip
    if data.startswith(b"\x93NUMPY"):
        return _NPY, _npy
    if data.startswith(b"\x1f\x8b\x08"):
        return _GZIP, _gzip
    if any(data.startswith(_HDF5_SIGNATURE, offset) for offset in (0, 512, 1024, 2048)):
        return _HDF5, _only(_HDF5)
    if data.startswith(b"SQLite format 3\x00"):
        return _SQLITE, _only(_SQLITE)
    if data.startswith(b"\x7fELF"):
        return _ELF, _elf
    if data[:4] in _MACHO_MAGICS or (
        data[:4] in _MACHO_FAT_MAGICS and 0 < (_uint(data, 4, 4, "big") or 0) < 20
    ):
        return _MACHO, _only(_MACHO)
    if _is_pe(data):
        return _PE, _only(_PE)
    if data[:2] == b"BM" and _uint(data, 14, 4, "little") in _BMP_HEADER_SIZES:
        return _BMP, _bmp
    if b"%PDF-" in data[:_PDF_HEADER_WINDOW]:
        return _PDF, _pdf
    return _BINARY, _only(_BINARY)


def _only(format_name: str) -> _Describer:
    def describe(_data: bytes, _extension: str) -> _Description:
        return format_name, [], []

    return describe


def _png(data: bytes, _extension: str) -> _Description:
    facts: list[str] = []
    if data[12:16] == b"IHDR" and len(data) >= 26:
        width, height = _uint(data, 16, 4, "big"), _uint(data, 20, 4, "big")
        color = data[25]
        facts += [
            f"dimensions: {width}x{height}",
            f"bit depth: {data[24]}",
            f"color type: {_PNG_COLOR_TYPES.get(color, f'unknown ({color})')}",
        ]
    return _PNG, facts, []


def _jpeg(data: bytes, _extension: str) -> _Description:
    """Walk the marker segments, at most ``_MAX_JPEG_SEGMENTS``, to the first SOF0/1/2 frame
    header; stop at the scan, the end of the image, or anything that is not a marker."""

    position = 2
    for _ in range(_MAX_JPEG_SEGMENTS):
        while data[position : position + 2] == b"\xff\xff":
            position += 1
        if position + 4 > len(data) or data[position] != 0xFF:
            break
        marker = data[position + 1]
        if marker in {0x01, 0xD8} or 0xD0 <= marker <= 0xD7:
            position += 2
            continue
        if marker in {0xD9, 0xDA}:
            break
        length = _uint(data, position + 2, 2, "big")
        if length is None or length < 2:
            break
        if marker in {0xC0, 0xC1, 0xC2}:
            height = _uint(data, position + 5, 2, "big")
            width = _uint(data, position + 7, 2, "big")
            if height is None or width is None:
                break
            return _JPEG, [f"dimensions: {width}x{height}"], []
        position += 2 + length
    return _JPEG, [], []


def _gif(data: bytes, _extension: str) -> _Description:
    width, height = _uint(data, 6, 2, "little"), _uint(data, 8, 2, "little")
    if width is None or height is None:
        return _GIF, [], []
    return _GIF, [f"dimensions: {width}x{height}"], []


def _bmp(data: bytes, _extension: str) -> _Description:
    if _uint(data, 14, 4, "little") == 12:
        width, height = _uint(data, 18, 2, "little"), _uint(data, 20, 2, "little")
    else:
        width = _uint(data, 18, 4, "little", signed=True)
        height = _uint(data, 22, 4, "little", signed=True)
    if width is None or height is None or width < 0:
        return _BMP, [], []
    return _BMP, [f"dimensions: {width}x{abs(height)}"], []


def _webp(data: bytes, _extension: str) -> _Description:
    chunk = data[12:16]
    width: int | None = None
    height: int | None = None
    if chunk == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
        width = _uint(data, 26, 2, "little")
        height = _uint(data, 28, 2, "little")
        if width is not None and height is not None:
            width, height = width & 0x3FFF, height & 0x3FFF
    elif chunk == b"VP8L" and data[20:21] == b"\x2f":
        bits = _uint(data, 21, 4, "little")
        if bits is not None:
            width, height = (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    elif chunk == b"VP8X":
        width = _uint(data, 24, 3, "little")
        height = _uint(data, 27, 3, "little")
        if width is not None and height is not None:
            width, height = width + 1, height + 1
    if width is None or height is None:
        return _WEBP, [], []
    return _WEBP, [f"dimensions: {width}x{height}"], []


def _tiff(data: bytes, _extension: str) -> _Description:
    return _TIFF, [f"byte order: {_TIFF_ORDERS[data[:4]]}"], []


def _pdf(data: bytes, _extension: str) -> _Description:
    """The header version and a page estimate from uncompressed ``/Type /Page`` objects; pages
    held in compressed object streams are not counted, and no text is extracted."""

    facts: list[str] = []
    version = _PDF_VERSION.search(data, 0, _PDF_HEADER_WINDOW + 16)
    if version is not None:
        facts.append(f"version: {version.group(1).decode('ascii')}")
    pages = len(_PDF_PAGE.findall(data))
    if pages:
        facts.append(f"pages (estimated): {pages}")
    else:
        facts.append("pages (estimated): unknown (no uncompressed page objects found)")
    facts.append("text: not extracted")
    return _PDF, facts, []


def _zip(data: bytes, extension: str) -> _Description:
    """An XLSX workbook or DOCX document by its members, else a plain ZIP archive. An archive
    that cannot be opened from the bytes read (a truncated or corrupt one) is named by its
    extension when that says workbook or document, and its contents are not read."""

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        format_name = (
            _XLSX
            if extension in _XLSX_EXTENSIONS
            else _DOCX
            if extension in _DOCX_EXTENSIONS
            else _ZIP
        )
        return format_name, ["contents: not read (the archive could not be opened)"], []
    with archive:
        names = set(archive.namelist())
        workbook, document = _WORKBOOK in names, _DOCUMENT in names
        if workbook and not (document and extension in _DOCX_EXTENSIONS):
            format_name, describe = _XLSX, _xlsx
        elif document:
            format_name, describe = _DOCX, _docx
        else:
            return _plain_zip(archive)
        try:
            return describe(_MemberReader(archive))
        except Exception:
            return format_name, [], []


def _plain_zip(archive: zipfile.ZipFile) -> _Description:
    members = archive.infolist()
    table = ["member names:"] + [
        _QUOTE + _clean(member.filename, _MAX_MEMBER_NAME_CHARS)
        for member in members[:_MAX_MEMBER_NAMES]
    ]
    if len(members) > _MAX_MEMBER_NAMES:
        table.append(f"more members: {len(members) - _MAX_MEMBER_NAMES}")
    return _ZIP, [f"members: {len(members)}"], table if members else []


def _xlsx(reader: _MemberReader) -> _Description:
    """Sheet names from the workbook, then the first rows of the first sheets, cells resolved
    through the shared strings."""

    sheets = _workbook_sheets(reader)
    if sheets is None:
        return _XLSX, ["sheets: not read"], []
    if not sheets:
        return _XLSX, ["sheets: none"], []
    listed = ", ".join(_clean(name, _MAX_SHEET_NAME_CHARS) for name, _ in sheets[:_MAX_SHEET_NAMES])
    if len(sheets) > _MAX_SHEET_NAMES:
        listed += f", ... ({len(sheets)} sheets)"
    strings = _SharedStrings(reader)
    table: list[str] = []
    for name, part in sheets[:_MAX_SHEET_TABLES]:
        label = f"sheet {_clean(name, _MAX_SHEET_NAME_CHARS)} (first rows):"
        sheet = reader.xml(part)
        if sheet is None:
            table.append(f"{label} not read")
            continue
        rows = _sheet_rows(sheet, strings)
        table.append(label if rows else f"{label} none")
        table += [_QUOTE + row for row in rows]
    return _XLSX, [f"sheets: {listed}"], table


def _workbook_sheets(reader: _MemberReader) -> list[tuple[str, str]] | None:
    """Each sheet's name and part path, through the workbook relationships when they name it,
    else ``xl/worksheets/sheet<n>.xml`` in workbook order; ``None`` when unreadable."""

    workbook = reader.xml(_WORKBOOK)
    if workbook is None:
        return None
    targets = _workbook_targets(reader)
    sheets: list[tuple[str, str]] = []
    for element in workbook.iter():
        if _local(element.tag) != "sheet":
            continue
        relationship = next(
            (
                value
                for key, value in element.attrib.items()
                if key.startswith("{") and _local(key) == "id"
            ),
            None,
        )
        part = targets.get(relationship) if relationship is not None else None
        sheets.append(
            (element.get("name") or "", part or f"xl/worksheets/sheet{len(sheets) + 1}.xml")
        )
    return sheets


def _workbook_targets(reader: _MemberReader) -> dict[str, str]:
    relationships = reader.xml(_WORKBOOK_RELATIONSHIPS)
    targets: dict[str, str] = {}
    if relationships is None:
        return targets
    for element in relationships.iter():
        if _local(element.tag) != "Relationship" or element.get("TargetMode") == "External":
            continue
        identifier, target = element.get("Id"), element.get("Target")
        if identifier and target:
            targets[identifier] = _part_path("xl", target)
    return targets


def _part_path(base: str, target: str) -> str:
    """A relationship target as an archive member name: absolute from the package root, or
    relative to ``base``, with ``.`` and ``..`` resolved without leaving the package."""

    parts = (
        target[1:].split("/") if target.startswith("/") else [*base.split("/"), *target.split("/")]
    )
    resolved: list[str] = []
    for part in parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if resolved:
                resolved.pop()
            continue
        resolved.append(part)
    return "/".join(resolved)


def _sheet_rows(sheet: _Element, strings: _SharedStrings) -> list[str]:
    """The first non-empty rows, cells placed by their column reference (gaps left empty), at
    most ``_MAX_SHEET_COLUMNS`` columns each, trailing empty cells dropped."""

    rows: list[str] = []
    for row in sheet.iter():
        if _local(row.tag) != "row":
            continue
        values: list[str] = []
        column = -1
        for cell in row:
            if _local(cell.tag) != "c":
                continue
            column = _column_index(cell.get("r"), column + 1)
            if column >= _MAX_SHEET_COLUMNS:
                continue
            values += [""] * (column + 1 - len(values))
            values[column] = _cell_value(cell, strings)
        while values and not values[-1]:
            values.pop()
        if values:
            rows.append(" | ".join(values))
            if len(rows) >= _MAX_SHEET_ROWS:
                break
    return rows


def _column_index(reference: str | None, fallback: int) -> int:
    match = _CELL_REFERENCE.fullmatch(reference or "")
    if match is None:
        return fallback
    index = 0
    for letter in match.group(1).upper():
        index = index * 26 + ord(letter) - ord("A") + 1
    return index - 1


def _cell_value(cell: _Element, strings: _SharedStrings) -> str:
    """A cell as written: a shared or inline string resolved, a boolean as TRUE/FALSE, anything
    else (numbers, dates, errors, formula strings) as its stored value."""

    kind = cell.get("t") or "n"
    if kind == "inlineStr":
        inline = next((child for child in cell if _local(child.tag) == "is"), None)
        return "" if inline is None else _clean(_rich_text(inline), _MAX_CELL_CHARS)
    stored = next((child.text or "" for child in cell if _local(child.tag) == "v"), "")
    if kind == "s":
        return strings.get(stored)
    if kind == "b" and stored.strip() in {"0", "1"}:
        return "TRUE" if stored.strip() == "1" else "FALSE"
    return _clean(stored, _MAX_CELL_CHARS)


def _rich_text(item: _Element) -> str:
    """A shared or inline string's text: its ``t`` and its runs' ``t``, not phonetic runs."""

    parts: list[str] = []
    for child in item:
        local = _local(child.tag)
        if local == "t":
            parts.append(child.text or "")
        elif local == "r":
            parts += [run.text or "" for run in child if _local(run.tag) == "t"]
    return "".join(parts)


class _SharedStrings:
    """The workbook's shared strings, read on first use; each is cleaned and capped (and scanned
    whole) only when a quoted cell uses it."""

    def __init__(self, reader: _MemberReader) -> None:
        self._reader = reader
        self._strings: list[str] | None = None
        self._cleaned: dict[int, str] = {}

    def get(self, index: str) -> str:
        if self._strings is None:
            root = self._reader.xml(_SHARED_STRINGS)
            self._strings = (
                []
                if root is None
                else [_rich_text(item) for item in root if _local(item.tag) == "si"]
            )
        try:
            position = int(index)
        except ValueError:
            return ""
        if not 0 <= position < len(self._strings):
            return ""
        if position not in self._cleaned:
            self._cleaned[position] = _clean(self._strings[position], _MAX_CELL_CHARS)
        return self._cleaned[position]


def _docx(reader: _MemberReader) -> _Description:
    document = reader.xml(_DOCUMENT)
    if document is None:
        return _DOCX, ["paragraphs: not read"], []
    paragraphs = _paragraphs(document)
    if not paragraphs:
        return _DOCX, [], ["paragraphs (first text): none"]
    return _DOCX, [], ["paragraphs (first text):"] + [_QUOTE + text for text in paragraphs]


def _paragraphs(document: _Element) -> list[str]:
    """The first non-empty paragraph texts in document order. A paragraph nested in another (a
    text box) keeps its own text, and ``mc:Fallback`` copies of ``mc:Choice`` are skipped."""

    texts: list[list[str]] = []
    stack: list[tuple[_Element, int]] = [(document, -1)]
    while stack:
        element, paragraph = stack.pop()
        local = _local(element.tag)
        if local == "Fallback":
            continue
        if local == "p":
            texts.append([])
            paragraph = len(texts) - 1
        elif paragraph >= 0 and local == "t":
            texts[paragraph].append(element.text or "")
        elif paragraph >= 0 and local in {"tab", "br", "cr"}:
            texts[paragraph].append(" ")
        stack += [(child, paragraph) for child in reversed(list(element))]
    cleaned = (_clean("".join(parts), _MAX_PARAGRAPH_CHARS) for parts in texts)
    return list(itertools.islice((text for text in cleaned if text), _MAX_PARAGRAPHS))


def _npy(data: bytes, _extension: str) -> _Description:
    """The array's dtype, shape, and memory order, matched in the header text with regular
    expressions; the header is never evaluated."""

    major = data[6] if len(data) > 6 else 0
    if major == 1:
        length, start = _uint(data, 8, 2, "little"), 10
    elif major in {2, 3}:
        length, start = _uint(data, 8, 4, "little"), 12
    else:
        return _NPY, [], []
    if length is None:
        return _NPY, [], []
    raw = data[start : start + min(length, _MAX_NPY_HEADER_BYTES)]
    header = raw.decode("utf-8" if major == 3 else "latin-1", errors="replace")
    facts: list[str] = []
    descr = _NPY_DESCR.search(header)
    if descr is not None:
        dtype = "structured" if descr.group(3) else descr.group(1) or descr.group(2) or ""
        if cleaned := _clean(dtype, _MAX_DTYPE_CHARS):
            facts.append(f"dtype: {cleaned}")
    shape = _NPY_SHAPE.search(header)
    if shape is not None:
        dimensions = [part.strip() for part in shape.group(1).split(",") if part.strip()]
        matched = [_NPY_DIMENSION.fullmatch(part) for part in dimensions]
        if len(dimensions) <= _MAX_SHAPE_DIMENSIONS and all(matched):
            sizes = [str(int(match.group(1))) for match in matched if match is not None]
            facts.append(f"shape: ({', '.join(sizes)}{',' if len(sizes) == 1 else ''})")
    fortran = _NPY_FORTRAN.search(header)
    if fortran is not None:
        facts.append(f"fortran order: {'yes' if fortran.group(1) == 'True' else 'no'}")
    return _NPY, facts, []


def _gzip(_data: bytes, _extension: str) -> _Description:
    return _GZIP, ["compressed: yes"], []


def _elf(data: bytes, _extension: str) -> _Description:
    facts: list[str] = []
    word = {1: "32-bit", 2: "64-bit"}.get(data[4] if len(data) > 4 else 0)
    if word is not None:
        facts.append(f"class: {word}")
    order: Literal["little", "big"] | None = (
        "little" if data[5:6] == b"\x01" else "big" if data[5:6] == b"\x02" else None
    )
    machine = None if order is None else _uint(data, 18, 2, order)
    if machine is not None:
        facts.append(f"machine: {_ELF_MACHINES.get(machine, str(machine))}")
    return _ELF, facts, []


def _is_pe(data: bytes) -> bool:
    if data[:2] != b"MZ":
        return False
    offset = _uint(data, 0x3C, 4, "little")
    return offset is not None and data[offset : offset + 4] == b"PE\x00\x00"


class _MemberReader:
    """Reads archive members within the per-member and per-archive bounds.

    A member is refused when its declared size exceeds ``_MAX_MEMBER_BYTES``, its declared size
    exceeds ``_MAX_MEMBER_RATIO`` times its compressed size, or reading it would take the
    archive past ``_MAX_ARCHIVE_READ_BYTES`` (each member is charged its declared size, which
    ``zipfile`` never reads past). The read itself is bounded too, and an XML part is parsed
    only through ``_parse_xml``.
    """

    def __init__(self, archive: zipfile.ZipFile) -> None:
        self._archive = archive
        self._charged = 0

    def read(self, member: str) -> bytes | None:
        try:
            info = self._archive.getinfo(member)
        except KeyError:
            return None
        declared, compressed = info.file_size, info.compress_size
        if (
            not 0 <= declared <= _MAX_MEMBER_BYTES
            or declared > _MAX_MEMBER_RATIO * max(compressed, 0)
            or self._charged + declared > _MAX_ARCHIVE_READ_BYTES
        ):
            return None
        self._charged += declared
        try:
            with self._archive.open(info) as handle:
                content = handle.read(declared + 1)
        except Exception:
            return None
        return content if len(content) <= declared else None

    def xml(self, member: str) -> _Element | None:
        content = self.read(member)
        return None if content is None else _parse_xml(content)


def _parse_xml(content: bytes) -> _Element | None:
    """Parse one XML part, or ``None``: it must decode as UTF-8 and carry no document type or
    entity declaration. The decoded text is what is parsed, so a declared encoding cannot hide
    a declaration from the check."""

    try:
        text = content.decode("utf-8").removeprefix("﻿")
    except UnicodeDecodeError:
        return None
    if "<!DOCTYPE" in text or "<!ENTITY" in text or "\x00" in text:
        return None
    try:
        return ElementTree.fromstring(text)
    except Exception:
        return None


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


def _clean(text: str, limit: int) -> str:
    """Text from the file made safe to quote on one line: control, invisible formatting, and
    surrogate characters become spaces, whitespace runs collapse to one space, and text over
    ``limit`` characters is cut to fit with ``...``.

    The whole value is scanned first, as read and as normalized, before anything is cut: a value
    the shared credential scanner flags is quoted only as a marker (R1-04).
    """

    collapsed = " ".join(_UNSAFE_CHARACTERS.sub(" ", text).split())
    marker = _credential_marker(text, collapsed)
    if marker is not None:
        return marker
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3].rstrip() + "..."


def _credential_marker(*values: str) -> str | None:
    """The marker that replaces a value whose complete text the scanner flags, else ``None``.

    ``[REDACTED]`` for a recognized credential, ``[withheld-by-yoetz:possible-credential]`` for
    a value only the assignment heuristic flags. The owner's possible-credential opt-out does not
    apply here: the summary is FinishUP's own text, and the egress scan still decides what leaves.
    """

    high = heuristic = False
    for value in dict.fromkeys(values):
        for finding in scan_for_sensitive_content(value.encode("utf-8", errors="replace")):
            if scan_finding_is_heuristic(finding):
                heuristic = True
            else:
                high = True
    if not (high or heuristic):
        return None
    sink = _withheld.get()
    if sink is not None:
        sink.append(True)
    return _REDACTED_VALUE if high else _POSSIBLE_CREDENTIAL_VALUE


def _bounded(lines: list[str], limit: int) -> tuple[list[str], bool]:
    """``lines`` if they fit in ``limit`` bytes (each with its newline), else the leading whole
    lines that fit and ``_CUT_LINE``; and whether cut. A line is never cut part way: it may quote
    values from the file, and a part of one could hold an unrecognizable credential fragment."""

    encoded = [line.encode("utf-8", errors="replace") for line in lines]
    if sum(len(item) + 1 for item in encoded) <= limit:
        return [item.decode("utf-8") for item in encoded], False
    room = limit - len(_CUT_LINE) - 1
    kept: list[str] = []
    for item in encoded:
        if len(item) + 1 > room:
            break
        kept.append(item.decode("utf-8"))
        room -= len(item) + 1
    kept.append(_CUT_LINE)
    return kept, True


def _extension(name: str) -> str:
    base = name.replace("\\", "/").rpartition("/")[2]
    stem, dot, suffix = base.rpartition(".")
    return f".{suffix.lower()}" if dot and stem and 0 < len(suffix) <= 8 else ""


def _uint(
    data: bytes,
    offset: int,
    length: int,
    order: Literal["little", "big"],
    *,
    signed: bool = False,
) -> int | None:
    if offset < 0 or offset + length > len(data):
        return None
    return int.from_bytes(data[offset : offset + length], order, signed=signed)
