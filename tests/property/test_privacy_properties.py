"""Privacy/redaction property checks for ``finishup.observability.privacy``.

Searches the privacy diagnostic helpers (never the policy/gateway machinery, which have their own
dedicated suites) for accidental leakage, instability, or reversible redaction.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import json
import re
import string

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from finishup.observability.privacy import (
    EGRESS_CREDENTIAL_PLACEHOLDER,
    PrivacyFenceError,
    assert_plaintext_safe,
    prepare_persisted_plaintext,
    redact_before_cut,
    redact_diagnostic_record,
    redact_diagnostic_value,
    redact_encoded_heuristic_spans,
    redact_heuristic_spans,
    redact_high_confidence_content,
    redact_sensitive_content,
    scan_for_sensitive_content,
    semantic_egress_forms,
    session_id_hash,
)
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.ids import IdKind, validate_id

_ALWAYS_OMITTED_FIELDS = (
    "message",
    "exception",
    "traceback",
    "stack",
    "path",
    "filename",
    "url",
    "command",
    "argv",
    "prompt",
    "payload",
    "body",
    "response",
    "sql",
    "parameters",
    "credential",
    "authorization",
    "environment",
)
_KNOWN_TOKEN_FIELDS = ("level", "component", "operation", "outcome")


class _StaticMacKey:
    """A deterministic, injected ``MacKeyHandle`` stand-in; it is never a raw key/bytes value."""

    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        self._secret = secret

    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac_module.new(self._secret, domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


_KEY = _StaticMacKey(b"k" * 32)
_OTHER_KEY = _StaticMacKey(b"j" * 32)


def _session_ids() -> st.SearchStrategy[str]:
    return st.uuids(version=4).map(lambda value: f"ses_{value}")


def _sensitive_texts() -> st.SearchStrategy[str]:
    return st.text(min_size=1, max_size=256).filter(lambda value: "\x00" not in value)


@given(_session_ids())
def test_session_hash_never_equals_plain_id(session_id: str) -> None:
    validate_id(IdKind.SESSION, session_id)  # precondition: only valid session IDs are hashed

    hashed = session_id_hash(session_id, _KEY)

    assert hashed != session_id
    assert session_id not in hashed
    assert hashed.startswith("hmac-sha256:")
    # Deterministic: hashing the same ID under the same key always yields the same commitment.
    assert session_id_hash(session_id, _KEY) == hashed


@given(_session_ids(), _session_ids())
def test_session_hash_is_domain_separated_by_key_and_input(first: str, second: str) -> None:
    assume(first != second)

    same_key = session_id_hash(first, _KEY), session_id_hash(second, _KEY)
    assert same_key[0] != same_key[1]

    cross_key = session_id_hash(first, _KEY), session_id_hash(first, _OTHER_KEY)
    assert cross_key[0] != cross_key[1]


@given(st.sampled_from(_ALWAYS_OMITTED_FIELDS), _sensitive_texts())
def test_redaction_removes_always_omitted_fields_entirely(field: str, secret: str) -> None:
    record = {field: secret, "component": "gateway"}

    redacted = redact_diagnostic_record(record)

    assert field not in redacted
    # The structural shell survives (a known, well-formed sibling field remains), while the
    # omitted field contributes nothing else to the output.
    assert redacted == {"component": "gateway"}


@given(st.sampled_from(_KNOWN_TOKEN_FIELDS), _sensitive_texts())
def test_redaction_preserves_structure_but_removes_sensitive_text(field: str, secret: str) -> None:
    # "unavailable" is the sanitizer's own sentinel; excluding it keeps the two branches below
    # (legitimate pass-through vs. rejection) unambiguous.
    assume(secret != "unavailable")
    record = {field: secret, "unknown_free_text_field": secret}

    redacted = redact_diagnostic_record(record)

    # An unrecognized field is dropped outright: its structural shell (the key) does not survive.
    assert "unknown_free_text_field" not in redacted
    # A known field is preserved structurally (the key survives) even when its value is rejected.
    assert field in redacted
    value = redacted[field]
    if value != "unavailable":
        assert value == secret
    assert set(redacted) == {field}


@given(_sensitive_texts())
def test_redaction_is_deterministic(secret: str) -> None:
    record = {"operation": secret, "message": secret}

    first = redact_diagnostic_record(record)
    second = redact_diagnostic_record(record)

    assert first == second


@given(st.binary(min_size=1, max_size=64), st.binary(min_size=0, max_size=256))
def test_canary_patterns_stay_testable(canary: bytes, noise: bytes) -> None:
    haystack = noise + canary + noise

    findings = scan_for_sensitive_content(haystack, canaries=(canary,))

    assert any(
        finding.kind == "canary" and haystack[finding.start_offset : finding.end_offset] == canary
        for finding in findings
    )
    # Deterministic: scanning the same bytes twice reports the same findings.
    assert scan_for_sensitive_content(haystack, canaries=(canary,)) == findings

    with pytest.raises(PrivacyFenceError):
        assert_plaintext_safe(haystack, "property_test_surface", canaries=(canary,))


@given(st.binary(min_size=0, max_size=64))
def test_canary_absence_is_not_a_false_positive(clean: bytes) -> None:
    assume(b"BEGIN" not in clean and b"sk-" not in clean)

    findings = scan_for_sensitive_content(clean, canaries=())

    assert findings == ()
    assert_plaintext_safe(clean, "property_test_surface", canaries=())  # must not raise


def test_redact_diagnostic_value_never_echoes_an_unknown_field() -> None:
    assert redact_diagnostic_value("totally_unknown_field", "super-secret-value") is None
    assert redact_diagnostic_value("message", "super-secret-value") is None


# #1248 P2 (owner decision P-D3): values end at line breaks, and at tabs (the 2026-10-06 rule),
# raw or JSON-encoded, and no redaction pass removes a byte outside its own match. Each generated
# text is lines of benign settings and credential-like assignments, some with a tab and more text
# after the value; after any pass, at any JSON escaping depth up to three, every line break and
# every benign line is intact, and an assignment line is either untouched or keeps its name,
# separator and post-tab text with exactly one fixed marker where its whole value was.

_SECRET_NAMES = ("DB_PASSWORD", "api_key", "client_secret", "password", "AWS_SECRET_ACCESS_KEY")
_BENIGN_NAMES = ("user", "host", "port", "role", "mode", "DB_NAME")
_LINE_PREFIXES = ("", "  ", "    ", "+", "-", " ")
_SEPARATORS = ("=", ": ", " = ")
_MARKERS = (EGRESS_CREDENTIAL_PLACEHOLDER.decode(), "[REDACTED]")
_AFTER_VALUE = ("", "\t", "\t# note", "\tport=5432")
# Value bytes include backslashes; a backslash run before ``n``/``r``/``t`` is excluded because
# the value deliberately ends there (the accepted P-D3 cost, covered by a unit test).
_VALUE_ALPHABET = string.ascii_letters + string.digits + "-_./:!%^&*+~?#\\"
_VALUE_END_ESCAPE = re.compile(r"\\+[nrt]")


@st.composite
def _secret_value(draw: st.DrawFn) -> str:
    head = draw(st.sampled_from(string.ascii_letters))
    body = draw(st.text(alphabet=_VALUE_ALPHABET, min_size=4, max_size=40))
    value = head + body + "9"
    assume(_VALUE_END_ESCAPE.search(value) is None)
    return value


@st.composite
def _setting_line(draw: st.DrawFn) -> tuple[str, tuple[str, str] | None]:
    """``(line, kept)``: the bytes around the value a pass may replace; ``None`` when benign."""

    kind = draw(st.sampled_from(("secret", "benign", "blank", "comment")))
    if kind == "blank":
        return "", None
    if kind == "comment":
        return "# note", None
    prefix = draw(st.sampled_from(_LINE_PREFIXES))
    separator = draw(st.sampled_from(_SEPARATORS))
    if kind == "benign":
        name = draw(st.sampled_from(_BENIGN_NAMES))
        value = draw(
            st.text(
                alphabet=string.ascii_lowercase + string.digits + "-._/", min_size=1, max_size=12
            )
        )
        return prefix + name + separator + value, None
    name = draw(st.sampled_from(_SECRET_NAMES))
    after = draw(st.sampled_from(_AFTER_VALUE))
    head = prefix + name + separator
    return head + draw(_secret_value()) + after, (head, after)


def _nest(text: str, depth: int) -> bytes:
    data = text.encode()
    for _ in range(depth):
        data = canonical_encode(data.decode())
    return data


def _unnest(data: bytes, depth: int) -> str:
    text = data.decode()
    for _ in range(depth):
        decoded = json.loads(text)
        assert type(decoded) is str
        text = decoded
    return text


def _assert_only_values_replaced(
    lines: list[tuple[str, tuple[str, str] | None]], ending: str, output: str
) -> None:
    out_lines = output.split(ending)
    assert len(out_lines) == len(lines) + 1 and out_lines[-1] == ""
    for (line, kept), out in zip(lines, out_lines, strict=False):
        if kept is None:
            assert out == line
        else:
            head, after = kept
            assert out == line or out in {head + marker + after for marker in _MARKERS}


@given(
    st.lists(_setting_line(), min_size=1, max_size=8),
    st.sampled_from(("\n", "\r\n")),
    st.integers(min_value=0, max_value=3),
)
def test_no_redaction_pass_removes_bytes_past_its_match(
    lines: list[tuple[str, tuple[str, str] | None]], ending: str, depth: int
) -> None:
    text = "".join(line + ending for line, _ in lines)
    nested = _nest(text, depth)

    for redacted in (
        redact_heuristic_spans(nested)[0],
        redact_sensitive_content(nested)[0],
        redact_sensitive_content(nested, heuristic_marker=EGRESS_CREDENTIAL_PLACEHOLDER)[0],
        redact_high_confidence_content(nested)[0],
        prepare_persisted_plaintext(nested).content,
    ):
        _assert_only_values_replaced(lines, ending, _unnest(redacted, depth))

    if depth:
        return
    # The item-text passes of egress minimization and case composition.
    encoded_pass = redact_encoded_heuristic_spans(nested)
    cut_source = redact_before_cut(nested)
    for output in (
        *semantic_egress_forms(nested),
        *(() if encoded_pass is None else (encoded_pass[0],)),
        *(() if cut_source is None else (cut_source,)),
    ):
        _assert_only_values_replaced(lines, ending, output.decode())
