"""Privacy/redaction property checks for ``finishup.observability.privacy``.

Searches the privacy diagnostic helpers (never the policy/gateway machinery, which have their own
dedicated suites) for accidental leakage, instability, or reversible redaction.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from finishup.observability.privacy import (
    PrivacyFenceError,
    assert_plaintext_safe,
    redact_diagnostic_record,
    redact_diagnostic_value,
    scan_for_sensitive_content,
    session_id_hash,
)
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
