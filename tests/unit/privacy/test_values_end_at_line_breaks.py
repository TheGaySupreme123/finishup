"""Values end at line breaks, and no redaction pass deletes past its match (#1248 P2, #1138).

Owner decision P-D3: an unquoted value ends at a raw line break or at a JSON-encoded one at any
escaping depth, and no pass, raw or encoded, removes bytes outside its own match. Under the
2026-10-06 rule an encoded tab ends it too, exactly as a raw tab does. Before this, a
value read from encoded text ran through the encoded newline, so the redaction that replaced it
also deleted the lines that followed (``DB_PASSWORD=...`` then ``DB_USER=...`` lost
``DB_USER``). Every stage that runs these passes is exercised here: capture and persistence, the
check-time change, the cut source of case composition, egress minimization (raw and encoded
passes) and the gateway's final scans of the reviewer conversation.

Secrets are synthetic and assembled at runtime so no committed byte has a live-credential shape.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from tests.unit.privacy.test_local_enforcer import (
    _minimize_all,  # pyright: ignore[reportPrivateUsage]
    _two_excerpt_semantic_candidate,  # pyright: ignore[reportPrivateUsage]
)

from finishup.adapters.privacy import gateway as gateway_module
from finishup.adapters.privacy.local_enforcer import (
    LocalPrivacyEnforcer,
    scan_exact_bytes_with_confidence,
)
from finishup.application import check_change as check_change_module
from finishup.application import semantic_case as semantic_case_module
from finishup.domain.privacy import CredentialHeuristic
from finishup.observability.privacy import (
    EGRESS_CREDENTIAL_PLACEHOLDER,
    ScanConfidence,
    prepare_persisted_plaintext,
    redact_before_cut,
    redact_encoded_heuristic_spans,
    redact_heuristic_spans,
    redact_high_confidence_content,
    redact_sensitive_content,
    scan_for_sensitive_content,
    semantic_egress_forms,
)
from finishup.ports.semantic import encode_reviewer_exchange
from finishup.protocol.canonical import canonical_encode

_MARK = EGRESS_CREDENTIAL_PLACEHOLDER.decode()
_REDACTED = "[REDACTED]"
# Synthetic, built at runtime: a human-chosen password and a GitHub-token-shaped value.
_PASSWORD = "Qz7" + "-pw-" + "4410x"
_TOKEN = "gh" + "p_" + "A1b2C3d4" * 4

_ENDINGS = ("\n", "\r\n")
# What follows the assignment: a column-0 key, an indented YAML key, a diff ``+`` line, a diff
# context line, and a blank line before the next key.
_FOLLOWING = ("DB_USER=app", "  role: admin", "+DB_USER=app", " DB_USER=app", "")
# What follows the value on its own line: nothing, or a tab and more text (a raw tab, a JSON
# ``\t`` once encoded), which ends the value as whitespace does.
_SAME_LINE = ("", "\t# rotated", "\tDB_PORT=5432")


def _text(first: str, following: str, ending: str) -> str:
    return f"{first}{ending}{following}{ending}DB_HOST=db{ending}"


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


@pytest.mark.parametrize("depth", (0, 1, 2, 3))
@pytest.mark.parametrize("ending", _ENDINGS)
@pytest.mark.parametrize("following", _FOLLOWING)
@pytest.mark.parametrize("same_line", _SAME_LINE)
def test_db_password_keeps_its_following_line_raw_and_encoded(
    depth: int, ending: str, following: str, same_line: str
) -> None:
    text = _text(f"DB_PASSWORD={_PASSWORD}{same_line}", following, ending)
    encoded = _encode(text, depth)

    findings = scan_for_sensitive_content(encoded)
    assert findings
    for finding in findings:
        matched = encoded[finding.start_offset : finding.end_offset]
        assert b"DB_USER" not in matched and b"role" not in matched and b"DB_HOST" not in matched
        assert b"rotated" not in matched and b"DB_PORT" not in matched

    redacted, count = redact_heuristic_spans(encoded)
    assert count == 1
    assert _decode(redacted, depth) == _text(f"DB_PASSWORD={_MARK}{same_line}", following, ending)


@pytest.mark.parametrize("ending", _ENDINGS)
@pytest.mark.parametrize("following", _FOLLOWING)
@pytest.mark.parametrize("same_line", _SAME_LINE)
def test_every_egress_pass_keeps_the_following_line(
    ending: str, following: str, same_line: str
) -> None:
    raw = _text(f"DB_PASSWORD={_PASSWORD}{same_line}", following, ending).encode()
    expected_mark = _text(f"DB_PASSWORD={_MARK}{same_line}", following, ending).encode()
    expected_redacted = _text(f"DB_PASSWORD={_REDACTED}{same_line}", following, ending).encode()

    assert redact_sensitive_content(raw) == (expected_redacted, True)
    assert redact_sensitive_content(raw, heuristic_marker=EGRESS_CREDENTIAL_PLACEHOLDER) == (
        expected_mark,
        True,
    )
    # The encoded pass (minimization's second pass, ``local_enforcer`` round loop).
    assert redact_encoded_heuristic_spans(raw) == (expected_mark, 1)
    # Case composition redacts before any cut (``semantic_case`` ``redact_before_cut``).
    assert redact_before_cut(raw) == expected_mark
    cut_source: Callable[[bytes], bytes] = getattr(semantic_case_module, "_cut_source")
    assert cut_source(raw) == expected_mark
    # Every form the minimizer can send keeps the following line.
    forms = semantic_egress_forms(raw)
    assert forms[1:] and all(form == expected_mark for form in forms[1:])
    # The check-time change's raw-only passes (``check_change._redacted_text``).
    redacted_text: Callable[[bytes], tuple[bytes, bool]] = getattr(
        check_change_module, "_redacted_text"
    )
    assert redacted_text(raw) == (expected_mark, True)


@pytest.mark.parametrize("depth", (0, 1, 2, 3))
@pytest.mark.parametrize("ending", _ENDINGS)
@pytest.mark.parametrize("following", _FOLLOWING)
@pytest.mark.parametrize("same_line", _SAME_LINE)
def test_capture_redaction_keeps_the_following_line(
    depth: int, ending: str, following: str, same_line: str
) -> None:
    """Capture and persistence redact only high-confidence spans, and only those bytes."""

    text = _text(f"  GITHUB_TOKEN={_TOKEN}{same_line}", following, ending)
    encoded = _encode(text, depth)
    expected = _text(f"  GITHUB_TOKEN={_REDACTED}{same_line}", following, ending)

    redacted, changed = redact_high_confidence_content(encoded)
    assert changed
    assert _decode(redacted, depth) == expected
    persisted = prepare_persisted_plaintext(encoded)
    assert persisted.persist and persisted.redacted
    assert _decode(persisted.content, depth) == expected


def _high_confidence_shapes() -> tuple[str, ...]:
    pem_label = "-" * 5 + "BEGIN " + "RSA PRIVATE KEY" + "-" * 5
    return (
        "sk" + "-" + "a1B2" * 6,
        "gh" + "p_" + "A1b2C3d4" * 3,
        "github" + "_pat_" + "A1b2C3d4" * 3,
        "xo" + "xb-" + "1234567890-" * 2,
        "AK" + "IA" + "ABCDEFGH23456789",
        "postgres://" + "app:" + _PASSWORD + "@db.internal",
        pem_label,
    )


@pytest.mark.parametrize("depth", (0, 1, 2, 3))
@pytest.mark.parametrize("shape", _high_confidence_shapes())
def test_high_confidence_detections_still_fire_beside_a_following_line(
    depth: int, shape: str
) -> None:
    text = _text(f"  value {shape}", "  role: admin", "\n")
    encoded = _encode(text, depth)

    assert any(
        finding.confidence is ScanConfidence.HIGH for finding in scan_for_sensitive_content(encoded)
    )
    redacted, changed = redact_high_confidence_content(encoded)
    assert changed
    decoded = _decode(redacted, depth)
    assert shape not in decoded
    assert decoded.endswith("\n  role: admin\nDB_HOST=db\n")


@pytest.mark.parametrize(
    "value",
    (
        "C:" + "\\" + "Data" + "\\" + "x9-pw",  # Windows-style backslashes
        "Ab12" + "\\" + "vZZtail9",  # a literal backslash-v is not a line break or tab
        "pw9" + "\\",  # a trailing literal backslash just before the line break
        "pw9" + "\\" * 2 + "q",
        "pw9" + "\\" + "N" + "\\" + "R" + "\\" + "Tx",  # not JSON escapes, whatever the case flag
    ),
)
@pytest.mark.parametrize("depth", (0, 1, 2, 3))
def test_backslashes_that_are_not_a_line_break_or_tab_stay_in_the_value(
    depth: int, value: str
) -> None:
    text = _text(f"  password: {value}", "  role: admin", "\n")
    redacted, count = redact_heuristic_spans(_encode(text, depth))
    assert count == 1
    assert _decode(redacted, depth) == _text(f"  password: {_MARK}", "  role: admin", "\n")


@pytest.mark.parametrize("depth", (0, 1, 2, 3))
@pytest.mark.parametrize("escape", ("\\n", "\\r", "\\t"))
def test_literal_backslash_n_in_a_value_ends_it_so_its_tail_is_kept_by_design(
    depth: int, escape: str
) -> None:
    """The accepted cost of P-D3: a secret containing a literal backslash-n is partly redacted.

    The scanner cannot tell a literal backslash-n, backslash-r or backslash-t from an encoded line
    break or tab, so the value ends there; the bytes after it are not part of the match and are
    kept, never deleted.
    """

    value_head, value_tail = "head9", "tail9x"
    text = _text(f"  password: {value_head}{escape}{value_tail}", "  role: admin", "\n")
    redacted, count = redact_heuristic_spans(_encode(text, depth))
    assert count == 1
    assert _decode(redacted, depth) == _text(
        f"  password: {_MARK}{escape}{value_tail}", "  role: admin", "\n"
    )


def test_a_match_cut_at_a_scan_chunk_edge_is_replaced_whole() -> None:
    """A value found cut short in one scan chunk and whole in the next leaves no tail."""

    lead = b"x" * (65_536 - 20)
    data = lead + b" password=" + b"a1" * 20 + b"\nnext=1\n"
    redacted, count = redact_heuristic_spans(data)
    assert count >= 1
    assert redacted == lead + b" password=" + EGRESS_CREDENTIAL_PLACEHOLDER + b"\nnext=1\n"


def test_a_token_running_past_the_value_bound_is_replaced_whole() -> None:
    """A credential that starts inside a bounded assignment value and ends past it leaves no tail."""

    token = "gh" + "p_" + "Ab3" * 10
    data = ("password=" + "-" * 505 + token + "\nnext=1\n").encode()
    redacted, changed = redact_sensitive_content(data)
    assert changed
    assert redacted == b"password=[REDACTED]\nnext=1\n"


def _gateway_scan_is_clean(body: bytes) -> bool:
    final_scan = getattr(gateway_module, "_final_scan")
    return final_scan(LocalPrivacyEnforcer(), body, CredentialHeuristic.ENFORCED) == ()


@pytest.mark.parametrize("ending", _ENDINGS)
@pytest.mark.parametrize("following", ("DB_USER=app", "  role: admin", "+DB_USER=app"))
@pytest.mark.parametrize("same_line", _SAME_LINE)
@pytest.mark.parametrize("raw_pass_misses", (False, True))
def test_minimized_item_keeps_its_following_line_through_the_reviewer_conversation(
    monkeypatch: pytest.MonkeyPatch,
    ending: str,
    following: str,
    same_line: str,
    raw_pass_misses: bool,
) -> None:
    """Minimization (raw pass, then the encoded pass) and the gateway scans of the conversation.

    With ``same_line`` the placeholder is followed by an encoded tab in the packet and by a
    doubly encoded one in the reviewer conversation; neither re-matches.
    """

    import finishup.adapters.privacy.local_enforcer as enforcer_module

    if raw_pass_misses:
        # Force the encoded pass: the first (raw) pass reports nothing, as when a value only
        # becomes visible in the packet's JSON encoding.
        real = enforcer_module.redact_heuristic_spans
        calls = {"count": 0}

        def first_pass_misses(data: bytes) -> tuple[bytes, int]:
            calls["count"] += 1
            return (data, 0) if calls["count"] == 1 else real(data)

        monkeypatch.setattr(enforcer_module, "redact_heuristic_spans", first_pass_misses)
    item = _text(f"DB_PASSWORD={_PASSWORD}{same_line}", following, ending)
    minimized = _minimize_all(_two_excerpt_semantic_candidate(b"clean evidence", item.encode()))

    assert minimized.forbidden_findings == () and minimized.heuristic_findings == ()
    assert minimized.withheld_item_ids == ()
    packet = minimized.prepared_bytes
    assert _PASSWORD.encode() not in packet
    expected = _text(f"DB_PASSWORD={_MARK}{same_line}", following, ending)
    assert canonical_encode(expected)[1:-1] in packet

    # The reviewer conversation nests the packet one JSON level deeper; a resumed or wrapped
    # conversation nests it again. The gateway's final-body and local-sink scans see it clean.
    exchange = encode_reviewer_exchange(
        (("system", "Review the packet."), ("user", packet.decode()))
    )
    wrapped = canonical_encode({"content": exchange.decode()})
    for body in (packet, exchange, wrapped):
        assert not scan_exact_bytes_with_confidence(body).heuristic
        assert _gateway_scan_is_clean(body)


# Owner decision (#1248 P2): for ``KEY=value`` an empty value ends at the line break. The next
# line is not its value and is scanned on its own, so it is kept when clean and caught by its own
# key or pattern when not. (YAML ``key:`` with the value indented below is P3's block detection.)
_BASE_URL = "OPENAI_BASE_URL=" + "https://" + "api.example.com/v1"


@pytest.mark.parametrize("depth", (0, 1, 2, 3))
@pytest.mark.parametrize("ending", _ENDINGS)
@pytest.mark.parametrize("separator", ("=", " = ", "=\t"))
def test_an_empty_value_does_not_take_the_next_line(
    depth: int, ending: str, separator: str
) -> None:
    text = _text(f"OPENAI_API_KEY{separator}", _BASE_URL, ending)
    encoded = _encode(text, depth)

    assert scan_for_sensitive_content(encoded) == ()
    assert redact_heuristic_spans(encoded) == (encoded, 0)
    assert redact_sensitive_content(encoded) == (encoded, False)
    if depth == 0:
        assert redact_before_cut(encoded) == encoded
        assert semantic_egress_forms(encoded) == (encoded,)


@pytest.mark.parametrize("depth", (0, 1, 2, 3))
@pytest.mark.parametrize("ending", _ENDINGS)
def test_a_secret_on_the_line_after_an_empty_value_is_still_redacted(
    depth: int, ending: str
) -> None:
    secret = "sk" + "-" + "a1B2" * 6
    text = _text("OPENAI_API_KEY=", f"API_KEY={secret}", ending)
    encoded = _encode(text, depth)

    redacted, changed = redact_sensitive_content(encoded)
    assert changed
    assert _decode(redacted, depth) == _text("OPENAI_API_KEY=", f"API_KEY={_REDACTED}", ending)
    captured, _ = redact_high_confidence_content(encoded)
    assert _decode(captured, depth) == _text("OPENAI_API_KEY=", f"API_KEY={_REDACTED}", ending)


@pytest.mark.parametrize("ending", _ENDINGS)
def test_a_credential_like_value_after_an_empty_value_is_caught_by_its_own_key(
    ending: str,
) -> None:
    raw = _text("OPENAI_API_KEY=", f"API_KEY={_PASSWORD}", ending).encode()
    expected = _text("OPENAI_API_KEY=", f"API_KEY={_MARK}", ending).encode()

    assert redact_heuristic_spans(raw) == (expected, 1)
    assert redact_before_cut(raw) == expected
    assert semantic_egress_forms(raw)[1:] == (expected,)
