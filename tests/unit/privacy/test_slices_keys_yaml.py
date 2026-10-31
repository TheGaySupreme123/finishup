"""Slices from redacted text, private keys through END, YAML block values (#1248 P3, P-D4).

Owner decision P-D4: every slice (a reviewer line or offset read, a check-time change part) is
cut from text that was already redacted, so a slice never carries a value without the label that
made it detectable. A private key is redacted from its BEGIN line through its END line at capture,
persistence, case composition and egress; without its END line the item is withheld. YAML block
values (``key: |``, ``key: >``, or an empty ``key:`` over indented lines) are values. Keys of a
JSON document nested in a JSON string are found to escaping depth three (#1015).

Every secret is synthetic and assembled at runtime so no committed byte has a live-credential or
key-block shape.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.privacy.local_enforcer import scan_exact_bytes_with_confidence
from finishup.application import check_change as check_change_module
from finishup.application import semantic_case as semantic_case_module
from finishup.application.check_change import ChangeCaptureUnavailable
from finishup.application.reviewer_broker import ReadRoot
from finishup.observability.privacy import (
    EGRESS_CREDENTIAL_PLACEHOLDER,
    ScanConfidence,
    heuristic_value_lines,
    prepare_persisted_plaintext,
    redact_before_cut,
    redact_encoded_heuristic_spans,
    redact_fully,
    redact_heuristic_spans,
    redact_high_confidence_content,
    redact_sensitive_content,
    scan_for_sensitive_content,
    semantic_egress_forms,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from unit.application.test_reviewer_loop import (
    _FINAL,  # pyright: ignore[reportPrivateUsage]
    _observations,  # pyright: ignore[reportPrivateUsage]
    _setup,  # pyright: ignore[reportPrivateUsage]
    _text,  # pyright: ignore[reportPrivateUsage]
)

_MARK = EGRESS_CREDENTIAL_PLACEHOLDER.decode()
_DASHES = "-" * 5
# A synthetic key body: base64-alphabet lines, none of which is real key material.
_BODY_LINE = ("Zm9v" + "YmFy" + "+q/Z" + "0123") * 4
# PEM (RSA, EC), OpenSSH and PKCS#8 (plain and encrypted) key blocks.
_LABELS = (
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
)
_PASSWORD = "Qz7" + "-pw-" + "4410x"
_SECOND = "Hq7" + "zKp2" + "xWv9"


def _begin(label: str) -> str:
    return _DASHES + "BEGIN " + label + _DASHES


def _end(label: str) -> str:
    return _DASHES + "END " + label + _DASHES


def _key_lines(label: str, body_lines: int = 4, *, end: bool = True) -> list[str]:
    lines = [_begin(label), *([_BODY_LINE] * body_lines)]
    return [*lines, _end(label)] if end else lines


def _with_key(label: str, prefix: str = "", *, end: bool = True, ending: str = "\n") -> str:
    lines = ["before: 1", *(prefix + line for line in _key_lines(label, end=end)), "after: 2"]
    return ending.join(lines) + ending


def _encode(text: str, depth: int) -> bytes:
    data = text.encode()
    for _ in range(depth):
        data = canonical_encode(data.decode())
    return data


def _decode(data: bytes, depth: int) -> str:
    text = data.decode()
    for _ in range(depth):
        decoded = json.loads(text)
        assert type(decoded) is str
        text = decoded
    return text


def _assert_key_gone(text: str, label: str, original_lines: int) -> None:
    assert _BODY_LINE not in text
    assert _begin(label) not in text and _end(label) not in text
    assert "before: 1" in text and "after: 2" in text
    # The block's line breaks stay, so the text keeps its line count.
    assert text.count("\n") == original_lines


# ---- private keys, BEGIN through END ---------------------------------------------------------


@pytest.mark.parametrize("ending", ("\n", "\r\n"))
@pytest.mark.parametrize("prefix", ("", "+", "    "))
@pytest.mark.parametrize("label", _LABELS)
def test_a_private_key_is_redacted_begin_through_end_at_every_stage(
    label: str, prefix: str, ending: str
) -> None:
    text = _with_key(label, prefix, ending=ending)
    raw = text.encode()
    lines = text.count("\n")

    (finding,) = (f for f in scan_for_sensitive_content(raw) if f.kind == "private_key_marker")
    assert raw[finding.start_offset :].startswith(_begin(label).encode())
    assert raw[: finding.end_offset].endswith(_end(label).encode())

    # Capture.
    captured, changed = redact_high_confidence_content(raw)
    assert changed
    _assert_key_gone(captured.decode(), label, lines)
    # Persistence.
    persisted = prepare_persisted_plaintext(raw)
    assert persisted.persist and persisted.redacted
    _assert_key_gone(persisted.content.decode(), label, lines)
    # Case composition: the cut source and the full redaction every slice is cut from.
    cut_source: Callable[[bytes], bytes] = getattr(semantic_case_module, "_cut_source")
    for composed in (redact_before_cut(raw), redact_fully(raw), cut_source(raw)):
        assert composed is not None
        _assert_key_gone(composed.decode(), label, lines)
    # The check-time change capture.
    redacted_text: Callable[[bytes], tuple[bytes, bool]] = getattr(
        check_change_module, "_redacted_text"
    )
    change, change_redacted = redacted_text(raw)
    assert change_redacted
    _assert_key_gone(change.decode(), label, lines)
    # Egress: the raw item is excluded as key material; the captured item carries no body in any
    # form the minimizer can send.
    assert scan_exact_bytes_with_confidence(raw).high_confidence
    assert not scan_exact_bytes_with_confidence(captured).all_findings
    for form in semantic_egress_forms(captured):
        assert _BODY_LINE.encode() not in form


@pytest.mark.parametrize("depth", (1, 2, 3))
@pytest.mark.parametrize("label", _LABELS)
def test_a_private_key_is_found_whole_at_every_escaping_depth(label: str, depth: int) -> None:
    text = _with_key(label)
    encoded = _encode(text, depth)

    findings = [f for f in scan_for_sensitive_content(encoded) if f.kind == "private_key_marker"]
    assert len(findings) == 1 and findings[0].confidence is ScanConfidence.HIGH
    redacted, changed = redact_high_confidence_content(encoded)
    assert changed
    _assert_key_gone(_decode(redacted, depth), label, text.count("\n"))


def test_a_key_the_64_kib_scan_window_splits_is_found_and_redacted_whole() -> None:
    # The first scan chunk ends at 65,536 and the next starts 4 KiB earlier: a key that begins
    # before that overlap and ends after the chunk is in neither chunk whole.
    lead = "x" * 79 + "\n"
    text = lead * (59_000 // len(lead)) + "\n".join(_key_lines("RSA PRIVATE KEY", 120)) + "\ntail\n"
    raw = text.encode()
    begin = raw.index(_begin("RSA PRIVATE KEY").encode())
    end = raw.index(_end("RSA PRIVATE KEY").encode())
    assert begin < 65_536 - 4_096 and end > 65_536

    (finding,) = (f for f in scan_for_sensitive_content(raw) if f.kind == "private_key_marker")
    assert (finding.start_offset, finding.end_offset) == (
        begin,
        end + len(_end("RSA PRIVATE KEY")),
    )
    for redacted in (
        redact_high_confidence_content(raw)[0],
        prepare_persisted_plaintext(raw).content,
        redact_fully(raw),
    ):
        assert redacted is not None
        assert _BODY_LINE.encode() not in redacted and redacted.endswith(b"\ntail\n")
        assert redacted.count(b"\n") == raw.count(b"\n")


@pytest.mark.parametrize("label", _LABELS)
def test_a_key_without_its_end_line_withholds_the_item(label: str) -> None:
    raw = _with_key(label, end=False).encode()

    assert any(f.kind == "private_key_marker" for f in scan_for_sensitive_content(raw))
    assert redact_high_confidence_content(raw) == (b"", True)
    assert redact_sensitive_content(raw) == (b"", True)
    persisted = prepare_persisted_plaintext(raw)
    assert (persisted.persist, persisted.content) == (False, b"")
    assert redact_before_cut(raw) is None and redact_fully(raw) is None
    cut_source: Callable[[bytes], bytes] = getattr(semantic_case_module, "_cut_source")
    assert _BODY_LINE.encode() not in cut_source(raw)
    redacted_text: Callable[[bytes], tuple[bytes, bool]] = getattr(
        check_change_module, "_redacted_text"
    )
    with pytest.raises(ChangeCaptureUnavailable) as caught:
        redacted_text(raw)
    assert caught.value.reason == "redaction_incomplete"
    # An END line of another label does not close the block.
    mismatched = (_with_key(label, end=False) + _end("DSA PRIVATE KEY") + "\n").encode()
    assert redact_high_confidence_content(mismatched) == (b"", True)


# ---- YAML block values -----------------------------------------------------------------------

_YAML_SHAPES = (
    ("password: |", ("  " + _PASSWORD, "  " + _SECOND)),
    ("password: >", ("  " + _PASSWORD, "  " + _SECOND)),
    ("api_token: |-", ("    " + _PASSWORD,)),
    ("db_secret: >+ # rotated", ("  " + _PASSWORD, "", "  " + _SECOND)),
    ('"private_key": |2', ("  " + _PASSWORD, "  " + _SECOND)),
    # An empty key over a multi-line plain value.
    ("password:", ("  " + _PASSWORD, "  more " + _SECOND)),
)


def _yaml(key: str, values: tuple[str, ...], prefix: str = "", indent: str = "") -> str:
    lines = [
        "db:",
        indent + key,
        *((indent + value) if value else "" for value in values),
        indent + "role: admin",
        "port: 5432",
    ]
    return "".join(f"{prefix}{line}\n" for line in lines)


def _expected_yaml(key: str, values: tuple[str, ...], prefix: str = "", indent: str = "") -> str:
    """The marker after the separator, then one empty line per value line replaced."""

    name = key.split(":")[0]
    if key.endswith(":"):
        # An empty key: the separator spans its line break and the value's indentation.
        separator = "\n" + (
            values[0][: len(values[0]) - len(values[0].lstrip())] if not prefix else ""
        )
        head = f"{prefix}{indent}{name}:{separator}{'' if prefix else indent}{_MARK}\n"
        blank = len(values) - 1
    else:
        head = f"{prefix}{indent}{name}: {_MARK}\n"
        blank = len(values)
    return (
        f"{prefix}db:\n"
        + head
        + "\n" * blank
        + f"{prefix}{indent}role: admin\n{prefix}port: 5432\n"
    )


@pytest.mark.parametrize("indent", ("", "  "))
@pytest.mark.parametrize("prefix", ("", "+"))
@pytest.mark.parametrize(("key", "values"), _YAML_SHAPES)
def test_a_yaml_block_value_is_redacted_and_the_next_key_kept(
    key: str, values: tuple[str, ...], prefix: str, indent: str
) -> None:
    raw = _yaml(key, values, prefix, indent).encode()

    redacted = redact_fully(raw)
    assert redacted is not None
    assert _PASSWORD.encode() not in redacted and _SECOND.encode() not in redacted
    assert redacted.count(b"\n") == raw.count(b"\n")
    assert redacted == _expected_yaml(key, values, prefix, indent).encode()
    # Egress passes, raw and encoded, replace the same lines.
    sanitized, count = redact_heuristic_spans(raw)
    assert count and _PASSWORD.encode() not in sanitized and _SECOND.encode() not in sanitized
    assert sanitized.endswith(f"{prefix}{indent}role: admin\n{prefix}port: 5432\n".encode())
    lines = heuristic_value_lines(raw)
    assert set(range(3, 3 + len([v for v in values if v]))) <= set(lines) or len(values) == 1


@pytest.mark.parametrize("depth", (1, 2, 3))
@pytest.mark.parametrize(("key", "values"), _YAML_SHAPES)
def test_a_yaml_block_value_is_found_at_every_escaping_depth(
    key: str, values: tuple[str, ...], depth: int
) -> None:
    text = _yaml(key, values, indent="  ")
    encoded = _encode(text, depth)

    redacted, count = redact_heuristic_spans(encoded)
    assert count
    decoded = _decode(redacted, depth)
    assert _PASSWORD not in decoded and _SECOND not in decoded
    assert decoded.count("\n") == text.count("\n")
    assert decoded.endswith("  role: admin\nport: 5432\n")
    if depth == 1:
        # The encoded pass of minimization: the item's own JSON-string encoding.
        assert redact_encoded_heuristic_spans(text.encode()) is not None


@pytest.mark.parametrize(
    "text",
    (
        # A nested mapping under a credential-named key is not a value.
        "secret:\n  name: app-db\n  key: password\nnext: 1\n",
        # Source: the name does not open its line.
        "if password:\n    connect(" + "user" + ")\n    retry = 3\n",
    ),
)
def test_what_is_not_a_yaml_block_value(text: str) -> None:
    assert redact_fully(text.encode()) == text.encode()


def test_a_block_of_finishup_markers_is_not_redacted_again() -> None:
    # An already redacted block value converges: its marker lines are not a fresh value.
    text = ("password: |\n  " + _MARK + "\n  " + _MARK + "\nrole: admin\n").encode()
    once = redact_fully(text)
    assert once is not None and once.count(_MARK.encode()) == 3
    assert redact_fully(once) == once


# ---- slices: reviewer line reads and check-time change parts ---------------------------------


def _labelled_file() -> str:
    return (
        "settings:\n"
        f"  password: |\n    {_PASSWORD}\n    {_SECOND}\n"
        "  role: admin\n"
        + "\n".join(_key_lines("OPENSSH PRIVATE KEY"))
        + "\n"
        + f"db_token = '{_PASSWORD}'\n"
        + "done: true\n"
    )


@pytest.mark.anyio
@pytest.mark.parametrize("start", range(1, 14))
async def test_a_line_read_never_sends_a_value_without_its_label(
    tmp_path: Path, start: int
) -> None:
    text = _labelled_file()
    assert start <= text.count("\n")
    (tmp_path / "settings.yaml").write_text(text)
    loop, broker, _model, _ = _setup(
        _text("w1", "settings.yaml", start, 2),
        _FINAL,
        roots=(ReadRoot("w1", str(tmp_path.resolve())),),
    )
    (result,) = _observations((await loop.run()).history)

    assert result["status"] == "ok"
    sent = cast(str, cast(dict[str, JsonValue], result["data"])["text"])
    for secret in (_PASSWORD, _SECOND, _BODY_LINE):
        assert secret not in sent and secret not in json.dumps(result)
    # Line numbers still name the file's lines: the read starts where it was asked to.
    expected_first = (redact_fully(text.encode()) or b"").decode().split("\n")[start - 1]
    assert sent.split("\n")[0] == expected_first
    assert all(_PASSWORD not in "".join(texts) for texts in broker.text_by_ref.values())


@pytest.mark.anyio
async def test_a_declared_test_read_is_cut_from_the_redacted_test(tmp_path: Path) -> None:
    test = tmp_path.resolve() / "tests" / "test_settings.py"
    test.parent.mkdir()
    content = f'FIXTURE = """\npassword: |\n  {_PASSWORD}\n"""\n\n\ndef test_x():\n    pass\n'
    test.write_text(content)
    digest = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
    root = ReadRoot("t1", str(tmp_path.resolve()), pinned=(("dt1", str(test), digest, "clm"),))
    loop, _broker, _model, _ = _setup(_text("t1", "dt1", 3, 2), _FINAL, roots=(root,))
    (result,) = _observations((await loop.run()).history)

    assert result["status"] == "ok"
    sent = cast(str, cast(dict[str, JsonValue], result["data"])["text"])
    assert _PASSWORD not in json.dumps(result)
    assert sent == '\n"""\n'


@pytest.mark.anyio
async def test_a_file_whose_key_has_no_end_line_is_withheld_from_reads(tmp_path: Path) -> None:
    (tmp_path / "id.txt").write_text("\n".join(_key_lines("OPENSSH PRIVATE KEY", end=False)))
    loop, _broker, _model, _ = _setup(
        _text("w1", "id.txt", 2, 1), _FINAL, roots=(ReadRoot("w1", str(tmp_path.resolve())),)
    )
    (result,) = _observations((await loop.run()).history)

    assert (result["status"], result["reason"], result["data"]) == (
        "denied",
        "privacy_withheld",
        None,
    )
    assert _BODY_LINE not in json.dumps(result)


def test_change_parts_are_cut_from_text_redacted_raw_and_encoded() -> None:
    # #1238: this value matches only in the change's JSON-string encoding (the raw quoted value
    # never closes), and a YAML block value spans lines; both are redacted before the #983 split.
    encoded_only = '+password:"' + _PASSWORD + '\\"\n'
    yaml_block = f"+api_token: |\n+  {_SECOND}\n+  {_PASSWORD}\n"
    change = (
        "diff --git a/c.yaml b/c.yaml\n@@ -0,0 +1,6 @@\n"
        + "+x: 1\n" * 40
        + encoded_only
        + "+y: 2\n" * 40
        + yaml_block
        + "+z: 3\n" * 40
    ).encode()
    assert not any(
        _PASSWORD.encode() in change[f.start_offset : f.end_offset]
        for f in scan_for_sensitive_content(change)
        if f.start_offset < change.index(b"+y: 2")
    )

    redacted_text: Callable[[bytes], tuple[bytes, bool]] = getattr(
        check_change_module, "_redacted_text"
    )
    redacted, changed = redacted_text(change)
    assert changed
    assert _PASSWORD.encode() not in redacted and _SECOND.encode() not in redacted
    assert redacted.count(b"\n") == change.count(b"\n")
    chunks: Callable[[bytes, int], tuple[bytes, ...]] = getattr(
        semantic_case_module, "_line_chunks"
    )
    for limit in (256, 300, 400, 512):
        parts = chunks(redacted, limit)
        assert b"".join(parts) == redacted
        assert all(
            _PASSWORD.encode() not in part and _SECOND.encode() not in part for part in parts
        )


# ---- keys of a JSON document nested in a JSON string (#1015) ---------------------------------


def _nested_document(value: str, depth: int) -> bytes:
    document: JsonValue = {"api_token": value, "role": "admin"}
    text = json.dumps(document)
    for _ in range(depth - 1):
        text = json.dumps({"payload": text})
    return text.encode()


@pytest.mark.parametrize("depth", (1, 2, 3))
def test_a_key_is_found_at_every_escaping_depth(depth: int) -> None:
    value = "tok" + "A1b2C3d4" * 3
    data = _nested_document(value, depth)
    quote = b"\\" * (2 ** (depth - 1) - 1) + b'"'
    assert b"api_token" + quote + b": " in data

    findings = [f for f in scan_for_sensitive_content(data) if f.kind == "credential_pattern"]
    assert findings and all(f.confidence is ScanConfidence.HEURISTIC for f in findings)
    redacted, count = redact_heuristic_spans(data)
    assert count == 1 and value.encode() not in redacted
    # The replacement keeps every quote, so each nested document still parses.
    text = redacted.decode()
    for _ in range(depth - 1):
        text = cast(str, json.loads(text)["payload"])
    assert json.loads(text) == {"api_token": _MARK, "role": "admin"}


@pytest.mark.parametrize("depth", (1, 2, 3))
def test_a_marker_quoted_at_any_depth_is_not_a_fresh_value(depth: int) -> None:
    for marker in ("[REDACTED]", _MARK):
        assert scan_for_sensitive_content(_nested_document(marker, depth)) == ()
