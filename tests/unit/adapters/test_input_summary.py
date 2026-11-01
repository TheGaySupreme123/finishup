"""FinishUP's bounded description of a binary task input (issue #1082)."""

from __future__ import annotations

import hashlib
import io
import random
import struct
import unicodedata
import zipfile

import pytest

from finishup.adapters.input_summary import (
    MAX_INPUT_SUMMARY_BYTES,
    MAX_INPUT_SUMMARY_TABLE_BYTES,
    summarize_binary_input,
)

_CAP = MAX_INPUT_SUMMARY_BYTES + MAX_INPUT_SUMMARY_TABLE_BYTES
_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_RELATIONSHIPS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PACKAGE = "http://schemas.openxmlformats.org/package/2006/relationships"
_WORD = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_WORKSHEET_TYPE = f"{_RELATIONSHIPS}/worksheet"


def _summary(name: str, data: bytes, size: int | None = None) -> list[str]:
    text = summarize_binary_input(name, data, len(data) if size is None else size)
    assert text.endswith("\n")
    assert len(text.encode("utf-8")) <= _CAP
    return text.splitlines()


def _head(data: bytes, format_name: str) -> list[str]:
    return [
        f"format: {format_name}",
        f"size: {len(data)} bytes",
        f"sha256: {hashlib.sha256(data).hexdigest()}",
    ]


def _archive(members: dict[str, str | bytes], *, stored: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in members.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return buffer.getvalue()


def _declare_size(archive: bytes, member: str, declared: int) -> bytes:
    """Rewrite the central directory's uncompressed size for ``member``."""

    patched = bytearray(archive)
    encoded = member.encode("utf-8")
    position = patched.find(b"PK\x01\x02")
    while position >= 0:
        length = int.from_bytes(patched[position + 28 : position + 30], "little")
        if bytes(patched[position + 46 : position + 46 + length]) == encoded:
            patched[position + 24 : position + 28] = declared.to_bytes(4, "little")
            return bytes(patched)
        position = patched.find(b"PK\x01\x02", position + 4)
    raise AssertionError(member)


def _png() -> bytes:
    header = struct.pack(">IIBBBBB", 640, 480, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + header + b"\0\0\0\0"


def _jpeg() -> bytes:
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 17, 8, 300, 200, 3) + b"\x01\x22\x00" * 3
    return b"\xff\xd8" + app0 + sof0 + b"\xff\xda\x00\x08" + b"\x00" * 6 + b"\xff\xd9"


def _gif() -> bytes:
    return b"GIF89a" + struct.pack("<HH", 32, 16) + b"\x00\x00\x00;"


def _bmp() -> bytes:
    dib = struct.pack("<IiiHHIIiiII", 40, 10, -20, 1, 24, 0, 0, 0, 0, 0, 0)
    return b"BM" + struct.pack("<IHHI", 54 + 600, 0, 0, 54) + dib + b"\x00" * 600


def _webp(chunk: bytes, payload: bytes) -> bytes:
    body = b"WEBP" + chunk + struct.pack("<I", len(payload)) + payload
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _pdf() -> bytes:
    return (
        b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R >> endobj\n"
        b"4 0 obj << /Type/Page/Parent 2 0 R >> endobj\n"
        b"%%EOF\n"
    )


def _npy() -> bytes:
    header = "{'descr': '<f8', 'fortran_order': False, 'shape': (3, 4), }"
    header += " " * (63 - (10 + len(header)) % 64) + "\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header.encode() + b"\0" * 96


def _elf(word: int, order: int, machine: int) -> bytes:
    byte_order = "<" if order == 1 else ">"
    identity = b"\x7fELF" + bytes([word, order, 1, 0]) + b"\x00" * 8
    return identity + struct.pack(f"{byte_order}HH", 2, machine) + b"\x00" * 44


def _workbook_xml(names: list[str]) -> str:
    sheets = "".join(
        f'<sheet name="{name}" sheetId="{index + 1}" r:id="rId{index + 1}"/>'
        for index, name in enumerate(names)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<workbook xmlns="{_MAIN}" xmlns:r="{_RELATIONSHIPS}"><sheets>{sheets}</sheets></workbook>'
    )


def _relationships_xml(targets: list[str]) -> str:
    relationships = "".join(
        f'<Relationship Id="rId{index + 1}" Type="{_WORKSHEET_TYPE}" Target="{target}"/>'
        for index, target in enumerate(targets)
    )
    return f'<Relationships xmlns="{_PACKAGE}">{relationships}</Relationships>'


def _sheet_xml(rows: str, padding: int = 0) -> str:
    return f'<worksheet xmlns="{_MAIN}">{" " * padding}<sheetData>{rows}</sheetData></worksheet>'


def _inline(reference: str, text: str) -> str:
    return f'<c r="{reference}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'


def _column(index: int) -> str:
    letters = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(ord("A") + remainder) + letters
    return letters


def _xlsx() -> bytes:
    shared = (
        f'<sst xmlns="{_MAIN}" count="4" uniqueCount="4">'
        "<si><t>name</t></si><si><t>score</t></si><si><t>alice</t></si>"
        "<si><r><t>rich </t></r><r><t>text</t></r><rPh><t>PHONETIC</t></rPh></si></sst>"
    )
    data = _sheet_xml(
        '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>'
        '<row r="2"><c r="A2" t="s"><v>2</v></c><c r="B2"><v>42.5</v></c></row>'
        '<row r="3">' + _inline("A3", "inline") + '<c r="B3" t="b"><v>1</v></c></row>'
        '<row r="4"><c r="A4" t="s"><v>3</v></c><c r="C4"><v>7</v></c></row>'
        '<row r="5"><c r="A5" s="1"/></row>'
    )
    notes = _sheet_xml('<row r="1"><c r="A1" t="str"><v>formula text</v></c></row>')
    return _archive(
        {
            "[Content_Types].xml": "<Types/>",
            "xl/workbook.xml": _workbook_xml(["Data", "Notes"]),
            "xl/_rels/workbook.xml.rels": _relationships_xml(
                ["worksheets/sheet1.xml", "/xl/worksheets/notes.xml"]
            ),
            "xl/sharedStrings.xml": shared,
            "xl/worksheets/sheet1.xml": data,
            "xl/worksheets/notes.xml": notes,
        }
    )


def _document_xml(body: str) -> str:
    return f'<w:document xmlns:w="{_WORD}"><w:body>{body}</w:body></w:document>'


_DOCX_BODY = (
    "<w:p><w:r><w:t>Hello</w:t></w:r><w:r><w:tab/>"
    '<w:t xml:space="preserve">world   again</w:t></w:r></w:p>'
    "<w:p/>"
    "<w:p><w:r><w:t>Second paragraph</w:t></w:r><w:r><w:delText>deleted</w:delText></w:r></w:p>"
)


def _docx(*, stored: bool = False) -> bytes:
    return _archive(
        {
            "[Content_Types].xml": "<Types/>",
            "word/document.xml": _document_xml(_DOCX_BODY),
        },
        stored=stored,
    )


def _samples() -> dict[str, bytes]:
    return {
        "image.png": _png(),
        "photo.jpg": _jpeg(),
        "anim.gif": _gif(),
        "bitmap.bmp": _bmp(),
        "image.webp": _webp(b"VP8X", b"\x00" * 4 + (1023).to_bytes(3, "little") * 2),
        "doc.pdf": _pdf(),
        "book.xlsx": _xlsx(),
        "letter.docx": _docx(),
        "bundle.zip": _archive({"a.txt": "a", "dir/b.bin": b"\x00\x01"}),
        "array.npy": _npy(),
        "data.gz": b"\x1f\x8b\x08\x00" + b"\x00" * 32,
        "tool": _elf(2, 1, 62),
        "noise.bin": random.Random(1082).randbytes(4096),
    }


def test_png_reports_ihdr_dimensions_depth_and_color_type() -> None:
    data = _png()
    assert _summary("pictures/image.png", data) == [
        *_head(data, "PNG image"),
        "dimensions: 640x480",
        "bit depth: 8",
        "color type: truecolor with alpha (RGBA)",
    ]


def test_jpeg_reports_the_first_frame_header_dimensions() -> None:
    data = _jpeg()
    assert _summary("photo.jpg", data) == [*_head(data, "JPEG image"), "dimensions: 200x300"]


def test_jpeg_without_a_frame_header_reports_only_the_format() -> None:
    data = b"\xff\xd8\xff\xe0\x00\x02\xff\xd9"
    assert _summary("photo.jpg", data) == _head(data, "JPEG image")


def test_gif_and_bmp_report_dimensions() -> None:
    gif, bmp = _gif(), _bmp()
    assert _summary("anim.gif", gif) == [*_head(gif, "GIF image"), "dimensions: 32x16"]
    assert _summary("bitmap.bmp", bmp) == [*_head(bmp, "BMP image"), "dimensions: 10x20"]


@pytest.mark.parametrize(
    ("chunk", "payload", "dimensions"),
    [
        (
            b"VP8X",
            b"\x00" * 4 + (1023).to_bytes(3, "little") + (767).to_bytes(3, "little"),
            "1024x768",
        ),
        (b"VP8L", b"\x2f" + (99 | (49 << 14)).to_bytes(4, "little"), "100x50"),
        (b"VP8 ", b"\x10\x02\x00\x9d\x01\x2a" + struct.pack("<HH", 320, 240), "320x240"),
    ],
)
def test_webp_reports_dimensions_for_each_bitstream(
    chunk: bytes, payload: bytes, dimensions: str
) -> None:
    data = _webp(chunk, payload)
    assert _summary("image.webp", data) == [*_head(data, "WebP image"), f"dimensions: {dimensions}"]


@pytest.mark.parametrize(
    ("data", "format_name", "facts"),
    [
        (b"II*\x00\x08\x00\x00\x00" + b"\x00" * 16, "TIFF image", ["byte order: little"]),
        (b"MM\x00*\x00\x00\x00\x08" + b"\x00" * 16, "TIFF image", ["byte order: big"]),
        (b"\x1f\x8b\x08\x00" + b"\x00" * 16, "gzip data", ["compressed: yes"]),
        (b"\x89HDF\r\n\x1a\n" + b"\x00" * 16, "HDF5 data", []),
        (b"SQLite format 3\x00" + b"\x00" * 84, "SQLite database", []),
        (b"\xcf\xfa\xed\xfe" + b"\x00" * 28, "Mach-O executable", []),
        (
            b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + b"\x00" * 20,
            "PE executable",
            [],
        ),
        (b"MZ" + b"\x00" * 80, "binary data", []),
        (b"", "binary data", []),
    ],
)
def test_signature_only_formats(data: bytes, format_name: str, facts: list[str]) -> None:
    assert _summary("input", data) == [*_head(data, format_name), *facts]


def test_elf_reports_class_and_machine() -> None:
    little, big, unknown = _elf(2, 1, 62), _elf(1, 2, 8), _elf(2, 1, 999)
    assert _summary("tool", little)[3:] == ["class: 64-bit", "machine: x86-64"]
    assert _summary("tool", big)[3:] == ["class: 32-bit", "machine: mips"]
    assert _summary("tool", _elf(2, 1, 183))[3:] == ["class: 64-bit", "machine: aarch64"]
    assert _summary("tool", unknown)[3:] == ["class: 64-bit", "machine: 999"]


def test_pdf_reports_version_and_an_estimated_page_count_without_text() -> None:
    data = _pdf()
    assert _summary("doc.pdf", data) == [
        *_head(data, "PDF document"),
        "version: 1.7",
        "pages (estimated): 2",
        "text: not extracted",
    ]


def test_pdf_without_uncompressed_page_objects_says_the_count_is_unknown() -> None:
    data = b"%PDF-2.0\n1 0 obj << /Type /ObjStm /N 3 >> stream\nxx\nendstream endobj\n"
    assert _summary("doc.pdf", data)[3:] == [
        "version: 2.0",
        "pages (estimated): unknown (no uncompressed page objects found)",
        "text: not extracted",
    ]


def test_xlsx_reports_sheet_names_and_first_rows_through_relationships() -> None:
    data = _xlsx()
    assert _summary("book.xlsx", data) == [
        *_head(data, "XLSX workbook"),
        "sheets: Data, Notes",
        "sheet Data (first rows):",
        "  name | score",
        "  alice | 42.5",
        "  inline | TRUE",
        "  rich text |  | 7",
        "sheet Notes (first rows):",
        "  formula text",
    ]


def test_xlsx_without_relationships_falls_back_to_numbered_sheet_parts() -> None:
    data = _archive(
        {
            "xl/workbook.xml": _workbook_xml(["First", "Second"]),
            "xl/worksheets/sheet1.xml": _sheet_xml('<row r="1">' + _inline("A1", "one") + "</row>"),
            "xl/worksheets/sheet2.xml": _sheet_xml("<row/>"),
        }
    )
    assert _summary("book.xlsx", data)[3:] == [
        "sheets: First, Second",
        "sheet First (first rows):",
        "  one",
        "sheet Second (first rows): none",
    ]


def test_xlsx_shows_at_most_twenty_rows_of_twenty_columns() -> None:
    rows = "".join(
        f'<row r="{row}">'
        + "".join(_inline(f"{_column(column)}{row}", f"r{row}c{column}") for column in range(25))
        + "</row>"
        for row in range(1, 31)
    )
    data = _archive(
        {
            "xl/workbook.xml": _workbook_xml(["Grid"]),
            "xl/_rels/workbook.xml.rels": _relationships_xml(["worksheets/sheet1.xml"]),
            "xl/worksheets/sheet1.xml": _sheet_xml(rows),
        }
    )
    quoted = [line for line in _summary("grid.xlsx", data) if line.startswith("  ")]
    assert len(quoted) == 20
    assert quoted[0] == "  " + " | ".join(f"r1c{column}" for column in range(20))
    assert quoted[-1].startswith("  r20c0 | ")
    assert all(len(line[2:].split(" | ")) == 20 for line in quoted)


def test_docx_reports_the_first_paragraph_texts() -> None:
    data = _docx()
    assert _summary("letter.docx", data) == [
        *_head(data, "DOCX document"),
        "paragraphs (first text):",
        "  Hello world again",
        "  Second paragraph",
    ]


def test_plain_zip_reports_member_count_and_names_in_stored_order() -> None:
    data = _archive({"z.txt": "z", "a.txt": "a", "dir/b.bin": b"\x00\x01"})
    assert _summary("bundle.zip", data) == [
        *_head(data, "ZIP archive"),
        "members: 3",
        "member names:",
        "  z.txt",
        "  a.txt",
        "  dir/b.bin",
    ]


def test_plain_zip_lists_at_most_thirty_two_members() -> None:
    data = _archive({f"member-{index:03d}.txt": "x" for index in range(40)})
    lines = _summary("bundle.zip", data)
    assert lines[3:5] == ["members: 40", "member names:"]
    assert [line for line in lines if line.startswith("  ")] == [
        f"  member-{index:03d}.txt" for index in range(32)
    ]
    assert lines[-1] == "more members: 8"


def test_npy_header_is_parsed_without_evaluation() -> None:
    data = _npy()
    assert _summary("array.npy", data) == [
        *_head(data, "NumPy array (.npy)"),
        "dtype: <f8",
        "shape: (3, 4)",
        "fortran order: no",
    ]


def test_npy_header_that_is_not_a_literal_reports_no_shape() -> None:
    header = "{'descr': [('a', '<i4')], 'fortran_order': True, 'shape': (__import__('os'),), }\n"
    data = b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header.encode()
    assert _summary("array.npy", data)[3:] == ["dtype: structured", "fortran order: yes"]


def test_random_bytes_are_binary_data() -> None:
    data = random.Random(1082).randbytes(4096)
    assert _summary("noise.bin", data) == _head(data, "binary data")


def test_sha256_marks_a_digest_of_only_the_leading_bytes() -> None:
    data = _png()
    lines = _summary("image.png", data[:20], size=1_000)
    assert lines == [
        "format: PNG image",
        "size: 1000 bytes",
        f"sha256: {hashlib.sha256(data[:20]).hexdigest()} (first 20 bytes)",
    ]
    assert _summary("image.png", data)[2] == f"sha256: {hashlib.sha256(data).hexdigest()}"
    assert _summary("image.png", data, size=3)[1] == f"size: {len(data)} bytes"


def test_truncated_or_corrupt_zip_degrades_without_raising() -> None:
    workbook = _xlsx()
    truncated = workbook[: len(workbook) // 2]
    assert _summary("book.xlsx", truncated)[3:] == [
        "contents: not read (the archive could not be opened)"
    ]
    assert _summary("book.xlsx", truncated)[0] == "format: XLSX workbook"
    assert _summary("letter.docx", _docx()[:200])[0] == "format: DOCX document"
    assert _summary("bundle.zip", truncated)[0] == "format: ZIP archive"
    assert _summary("x", b"PK\x03\x04" + b"\xff" * 100)[0] == "format: ZIP archive"


def test_every_prefix_and_corruption_of_every_sample_is_summarized_within_the_cap() -> None:
    for name, data in _samples().items():
        for cut in range(0, len(data), max(len(data) // 97, 1)):
            _summary(name, data[:cut], size=len(data))
        for position in range(0, len(data), max(len(data) // 89, 1)):
            corrupt = bytearray(data)
            corrupt[position] ^= 0xA5
            _summary(name, bytes(corrupt))


def test_xml_part_with_a_document_type_or_entity_is_not_parsed() -> None:
    doctype = _archive(
        {
            "word/document.xml": '<?xml version="1.0"?><!DOCTYPE w:document '
            '[<!ENTITY boom "EXPANDED">]>'
            + _document_xml("<w:p><w:r><w:t>&boom;</w:t></w:r></w:p>")
        }
    )
    lines = _summary("letter.docx", doctype)
    assert lines[3:] == ["paragraphs: not read"]
    assert "EXPANDED" not in "\n".join(lines)
    utf16 = _archive(
        {
            "word/document.xml": _document_xml("<w:p><w:r><w:t>wide</w:t></w:r></w:p>").encode(
                "utf-16"
            )
        }
    )
    assert _summary("letter.docx", utf16)[3:] == ["paragraphs: not read"]


def test_member_declaring_more_than_the_size_limit_is_not_read() -> None:
    stored = _docx(stored=True)
    assert "  Second paragraph" in _summary("letter.docx", stored)
    oversized = _declare_size(stored, "word/document.xml", 3 * 1024 * 1024)
    assert _summary("letter.docx", oversized)[3:] == ["paragraphs: not read"]


def test_member_declaring_more_than_the_compression_ratio_is_not_read() -> None:
    stored = _docx(stored=True)
    actual = len(_document_xml(_DOCX_BODY).encode())
    within = _declare_size(stored, "word/document.xml", actual * 99)
    assert "  Second paragraph" in _summary("letter.docx", within)
    beyond = _declare_size(stored, "word/document.xml", actual * 101)
    assert _summary("letter.docx", beyond)[3:] == ["paragraphs: not read"]


def test_archive_stops_reading_past_the_total_budget() -> None:
    names = ["S1", "S2", "S3", "S4"]
    members: dict[str, str | bytes] = {
        "xl/workbook.xml": _workbook_xml(names),
        "xl/_rels/workbook.xml.rels": _relationships_xml(
            [f"worksheets/sheet{index}.xml" for index in range(1, 5)]
        ),
    }
    for index in range(1, 5):
        rows = '<row r="1">' + _inline("A1", f"value {index}") + "</row>"
        members[f"xl/worksheets/sheet{index}.xml"] = _sheet_xml(rows, padding=20_000)
    data = _archive(members, stored=True)
    for index in range(1, 5):
        data = _declare_size(data, f"xl/worksheets/sheet{index}.xml", 1_536 * 1024)
    assert _summary("book.xlsx", data)[3:] == [
        "sheets: S1, S2, S3, S4",
        "sheet S1 (first rows):",
        "  value 1",
        "sheet S2 (first rows):",
        "  value 2",
        "sheet S3 (first rows): not read",
        "sheet S4 (first rows): not read",
    ]


def test_large_workbook_summary_stays_within_the_cap() -> None:
    generator = random.Random(1082)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789é漢字 "
    names = [f"Sheet{index:02d}-" + "n" * 100 for index in range(40)]
    members: dict[str, str | bytes] = {
        "xl/workbook.xml": _workbook_xml(names),
        "xl/_rels/workbook.xml.rels": _relationships_xml(
            [f"worksheets/sheet{index}.xml" for index in range(1, 5)]
        ),
    }
    for index in range(1, 5):
        rows = "".join(
            f'<row r="{row}">'
            + "".join(
                _inline(
                    f"{_column(column)}{row}",
                    "".join(generator.choice(alphabet) for _ in range(100)),
                )
                for column in range(30)
            )
            + "</row>"
            for row in range(1, 31)
        )
        members[f"xl/worksheets/sheet{index}.xml"] = _sheet_xml(rows)
    data = _archive(members)
    text = summarize_binary_input("book.xlsx", data, len(data))
    assert len(text.encode("utf-8")) <= _CAP
    assert text.endswith("\n... (summary cut)\n")
    lines = text.splitlines()
    sheets = lines[3].removeprefix("sheets: ")
    listed = sheets.removesuffix(", ... (40 sheets)").split(", ")
    assert len(listed) == 16
    assert all(len(name) <= 64 for name in listed)
    table = "".join(f"{line}\n" for line in lines[4:])
    assert len(table.encode("utf-8")) <= MAX_INPUT_SUMMARY_TABLE_BYTES
    for line in lines[4:]:
        if line.startswith("  "):
            cells = line[2:].split(" | ")
            assert len(cells) <= 20
            assert all(len(cell) <= 64 for cell in cells)


def test_quoted_text_carries_no_control_or_invisible_characters() -> None:
    hostile = "a\tb\nc\r\nd\u0085e\x7ff‮g​h\U000e0041i﻿j"
    workbook = _archive(
        {
            "xl/workbook.xml": _workbook_xml(["Bad‮Name"]),
            "xl/worksheets/sheet1.xml": _sheet_xml(
                '<row r="1">' + _inline("A1", hostile) + "</row>"
            ),
        }
    )
    archive = _archive({"evil\x1b[31mname\x07.txt": "x", "nul\x00cut.txt": "y"})
    for name, data in (("book.xlsx", workbook), ("bundle.zip", archive)):
        text = summarize_binary_input(name, data, len(data))
        assert "\x00" not in text
        for character in text.replace("\n", ""):
            assert unicodedata.category(character) not in {"Cc", "Cf", "Cs"}, repr(character)
    lines = _summary("book.xlsx", workbook)
    assert lines[3:] == [
        "sheets: Bad Name",
        "sheet Bad Name (first rows):",
        "  a b c d e f g h i j",
    ]
    assert "  evil [31mname .txt" in _summary("bundle.zip", archive)


def test_summary_is_deterministic_and_never_echoes_the_path() -> None:
    for name, data in _samples().items():
        path = f"private-owner/secret-project/{name}"
        first = summarize_binary_input(path, data, len(data) + 10)
        assert first == summarize_binary_input(path, data, len(data) + 10)
        assert "private-owner" not in first
        assert "secret-project" not in first


# --- PR #1086 review R1-04: every quoted value is scanned whole before it is cut -----------------

_TOKEN = "ghp_" + "B7" * 20
_LEAD = "x" * 44


def _withheld(text: str) -> None:
    """No part of the synthetic credential survives, and the egress scan finds nothing."""

    from finishup.adapters.privacy.local_enforcer import scan_exact_bytes

    assert "ghp_" not in text and "B7B7B7" not in text, text
    assert not scan_exact_bytes(text.encode("utf-8"))


def test_a_credential_cut_short_by_a_cell_cap_is_withheld_whole() -> None:
    """R1-04 probe: a 64-character cell cap kept ``ghp_`` plus 12 characters, which no scan
    recognizes; the complete cell is now scanned first and quoted only as ``[REDACTED]``."""

    from finishup.adapters.input_summary import summarize_task_input
    from finishup.observability.privacy import scan_for_sensitive_content

    cell = f"{_LEAD} {_TOKEN}"
    assert scan_for_sensitive_content(_TOKEN.encode())
    book = _archive(
        {
            "xl/workbook.xml": _workbook_xml(["data"]),
            "xl/worksheets/sheet1.xml": _sheet_xml(
                '<row r="1">' + _inline("A1", cell) + _inline("B1", "kept") + "</row>"
            ),
        }
    )

    text, withheld = summarize_task_input("data.xlsx", book, len(book))

    assert withheld
    _withheld(text)
    assert "  [REDACTED] | kept" in text.splitlines()


def test_shared_strings_sheet_names_paragraphs_and_members_are_scanned_whole() -> None:
    """R1-04: the same rule for every quoted unit: a shared string, a sheet name, a paragraph,
    an archive member name; a value the assignment heuristic flags reads the possible-credential
    marker; and a summary that withheld nothing says so."""

    from finishup.adapters.input_summary import summarize_task_input

    secret_name = f"{_LEAD}{'y' * 20} {_TOKEN}"
    book = _archive(
        {
            "xl/workbook.xml": _workbook_xml([secret_name[:31], "plain"]),
            "xl/sharedStrings.xml": (
                f'<sst xmlns="{_MAIN}"><si><r><t>{_LEAD} </t></r><r><t>{_TOKEN}</t></r></si>'
                '<si><t>password = "a8F3kL9qZx7Pw2Rt"</t></si></sst>'
            ),
            "xl/worksheets/sheet1.xml": _sheet_xml(
                '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>'
            ),
        }
    )
    text, withheld = summarize_task_input("book.xlsx", book, len(book))
    assert withheld
    _withheld(text)
    assert "  [REDACTED] | [withheld-by-finishup:possible-credential]" in text.splitlines()
    assert "a8F3kL9qZx7Pw2Rt" not in text

    paragraph = "word " * 39 + _TOKEN
    letter = _archive(
        {"word/document.xml": _document_xml(f"<w:p><w:r><w:t>{paragraph}</w:t></w:r></w:p>")}
    )
    text, withheld = summarize_task_input("letter.docx", letter, len(letter))
    assert withheld and "  [REDACTED]" in text.splitlines()
    _withheld(text)

    member = "m" * 100 + " " + _TOKEN + ".txt"
    bundle = _archive({member: "a", "plain.txt": "b"})
    text, withheld = summarize_task_input("bundle.zip", bundle, len(bundle))
    assert withheld and "  [REDACTED]" in text.splitlines() and "  plain.txt" in text
    _withheld(text)

    plain, withheld = summarize_task_input("book.xlsx", _xlsx(), len(_xlsx()))
    assert not withheld and plain == summarize_binary_input("book.xlsx", _xlsx(), len(_xlsx()))


def test_a_summary_cut_drops_whole_lines_and_never_splits_a_quoted_value() -> None:
    """R1-04: the listing's byte cap drops the line that does not fit instead of cutting it."""

    rows = "".join(
        f'<row r="{row}">'
        + "".join(
            _inline(f"{_column(column)}{row}", f"r{row}c{column}-" + "v" * 50)
            for column in range(20)
        )
        + "</row>"
        for row in range(1, 21)
    )
    sheets = {f"xl/worksheets/sheet{index}.xml": _sheet_xml(rows) for index in range(1, 5)}
    book = _archive({"xl/workbook.xml": _workbook_xml(["a", "b", "c", "d"]), **sheets})
    text = summarize_binary_input("book.xlsx", book, len(book))
    assert text.endswith("\n... (summary cut)\n")
    quoted = [line for line in text.splitlines() if line.startswith("  ")]
    assert quoted
    # Every quoted row kept is whole: twenty complete cells.
    for line in quoted:
        cells = line[2:].split(" | ")
        assert len(cells) == 20 and all(cell.endswith("v" * 50) for cell in cells), line


def test_a_signature_declares_a_summarized_format_without_a_nul() -> None:
    """R1-08: the task-input reader asks this module which signatures it summarizes."""

    from finishup.adapters.input_summary import declared_binary_format

    assert declared_binary_format(_pdf())
    assert declared_binary_format(_gif()) and declared_binary_format(_png())
    assert declared_binary_format(b"junk\n" + _pdf())
    assert not declared_binary_format(b"Uploads must start with %PDF-1.7; see 1 0 obj docs.\n")
    assert not declared_binary_format(b"id,value\n1,2\n")
    assert not declared_binary_format(b">seq1\nACGT\n")
    assert not declared_binary_format(random.Random(7).randbytes(64).replace(b"%", b"_"))
