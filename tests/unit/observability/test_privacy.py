from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import pytest

import yoetz.observability.privacy as privacy_module
from yoetz.observability.privacy import (
    EGRESS_CREDENTIAL_PLACEHOLDER,
    PRIVACY_REQUEST_BODY_DOMAIN,
    SESSION_HASH_DOMAIN,
    DiagnosticRedactionProfile,
    PersistenceScanResult,
    PrivacyFenceError,
    ScanConfidence,
    Sensitivity,
    assert_plaintext_safe,
    build_diagnostic_manifest,
    prepare_persisted_plaintext,
    privacy_request_commitment,
    redact_diagnostic_record,
    redact_diagnostic_value,
    redact_heuristic_spans,
    redact_high_confidence_content,
    redact_sensitive_content,
    scan_for_sensitive_content,
    session_id_hash,
)
from yoetz.ports.keys import MacKeyHandle
from yoetz.protocol.canonical import canonical_encode

_SESSION_ID = "ses_11111111-1111-4111-8111-111111111111"
_REQUEST_ID = "req_22222222-2222-4222-8222-222222222222"
_CORRELATION_ID = "err_33333333-3333-4333-8333-333333333333"
_CANARY = b"unique-binary-canary-\x00-credential"


def _pem_begin_marker(label: bytes) -> bytes:
    return b"-" * 5 + b"BEGIN " + label + b"-" * 5


@dataclass(frozen=True, slots=True)
class _PurposeMac:
    key: bytes
    domain: bytes

    def mac(self, domain: bytes, message: bytes) -> str:
        if domain != self.domain:
            raise ValueError("mac_domain_forbidden")
        digest = hmac.new(self.key, domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


def _mac(key: bytes, domain: bytes) -> MacKeyHandle:
    return _PurposeMac(key=key, domain=domain)


def test_session_id_hash_is_separate_from_plain_id() -> None:
    key = b"installation-one-log-key-32byte"
    handle = _mac(key, SESSION_HASH_DOMAIN)
    actual = session_id_hash(_SESSION_ID, handle)
    expected = hmac.new(
        key,
        SESSION_HASH_DOMAIN + _SESSION_ID.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    assert actual == f"hmac-sha256:{expected}"
    assert _SESSION_ID not in actual
    assert actual == session_id_hash(_SESSION_ID, handle)
    assert actual != session_id_hash(
        _SESSION_ID,
        _mac(b"installation-two-log-key-32byte", SESSION_HASH_DOMAIN),
    )


class _HostileText:
    def __str__(self) -> str:
        raise AssertionError("hostile text stringified")

    def __repr__(self) -> str:
        raise AssertionError("hostile text represented")


def test_redaction_helpers_strip_sensitive_text() -> None:
    record = redact_diagnostic_record(
        {
            "request_id": _REQUEST_ID,
            "correlation_id": _CORRELATION_ID,
            "duration_ms": 12,
            "outcome": "completed",
            "payload": "private task text",
            "path": "/private/repository/name",
            "credential": "sk-example",
            "message": _HostileText(),
            "unknown": _HostileText(),
        }
    )
    assert record == {
        "request_id": _REQUEST_ID,
        "correlation_id": _CORRELATION_ID,
        "duration_ms": 12,
        "outcome": "completed",
    }
    assert redact_diagnostic_value("component", _HostileText()) == "unavailable"
    assert redact_diagnostic_value("payload", _HostileText()) is None


def test_canary_checks_are_detectable() -> None:
    data = b"prefix" + _CANARY + b"suffix"
    findings = scan_for_sensitive_content(data, canaries=(_CANARY,))
    assert len(findings) == 1
    assert findings[0].kind == "canary"
    assert findings[0].start_offset == 6
    assert findings[0].end_offset == 6 + len(_CANARY)
    assert findings[0].severity is Sensitivity.SECRET
    with pytest.raises(PrivacyFenceError) as caught:
        assert_plaintext_safe(data, "/secret/path", canaries=(_CANARY,))
    assert caught.value.reason_code == "plaintext_canary_detected"
    assert caught.value.surface == "unsafe_surface"
    assert _CANARY.decode("utf-8") not in str(caught.value)


def test_canary_spanning_scan_chunk_boundary_is_detected() -> None:
    prefix = b"x" * (65_536 - len(_CANARY) // 2)
    data = prefix + _CANARY + b"suffix"
    finding = scan_for_sensitive_content(data, canaries=(_CANARY,))[0]
    assert finding.start_offset == len(prefix)
    assert finding.end_offset == len(prefix) + len(_CANARY)


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (_pem_begin_marker(b"OPENSSH PRIVATE KEY"), "private_key_marker"),
        (b"OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456", "credential_pattern"),
        (b"https://" + b"user:password@" + b"example.invalid/resource", "credential_pattern"),
        (b"github_pat_abcdefghijklmnopqrstuvwxyz123456", "credential_pattern"),
        (b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "credential_pattern"),
        (b"AZURE_CLIENT_SECRET=abc123secretvalue0001", "credential_pattern"),
        (b"GITHUB_TOKEN=notakeybutlongenoughvalue", "credential_pattern"),
        (b"NPM_TOKEN=npm_notarealtokenvalue12", "credential_pattern"),
    ],
)
def test_sensitive_scanner_positive_patterns(data: bytes, kind: str) -> None:
    assert any(finding.kind == kind for finding in scan_for_sensitive_content(data))


@pytest.mark.parametrize(
    "data",
    [
        b"https://example.invalid/resource",
        b"api_key=",
        b"random structural identifier sk-short",
        b"sha256:" + b"a" * 64,
        b"\xff\xfe\x80 ordinary invalid utf8 bytes",
        b"AWS_ACCESS_KEY_ID=not-an-akia-identifier",
        b"TOKEN_COUNT=12",
        b"MAX_TOKEN=4096",
        b"SECRETARY=Alice",
        b"tokenize=falsehood",
    ],
)
def test_sensitive_scanner_negative_patterns(data: bytes) -> None:
    assert scan_for_sensitive_content(data) == ()


def test_assignment_heuristic_preserves_source_expressions_but_withholds_quoted_lookalikes() -> (
    None
):
    for source in (
        b"const token = parser.getToken();",
        b"const token = nextToken(parser)",
        b"let token = lexer.next();",
        b"+const token = parser.getToken();",
        b"parser.token = Token.EOF",
        b"token: Token.ConstKeyword",
        b"+token: Token.ConstKeyword",
        b"-token: Token.ConstKeyword",
    ):
        assert scan_for_sensitive_content(source) == ()

    # A quoted literal stays a literal even when it reads like source. Parentheses cannot occur
    # in opaque ``*token`` material (issue #982), so the lookalike uses a dotted literal here; a
    # password-family value keeps every punctuation shape.
    for lookalike in (b"TOKEN='nextToken.parser'", b"PASSWORD='nextToken(parser)'"):
        quoted = scan_for_sensitive_content(lookalike)
        assert len(quoted) == 1
        assert quoted[0].confidence is ScanConfidence.HEURISTIC


def test_python_attribute_assignment_uses_syntax_proof_only() -> None:
    assert scan_for_sensitive_content(b"def parse(node):\n    token = node.token\n") == ()
    malformed = scan_for_sensitive_content(b"token = node.token\nnot valid python ???")
    assert len(malformed) == 1
    assert malformed[0].confidence is ScanConfidence.HEURISTIC


_PLACEHOLDER = EGRESS_CREDENTIAL_PLACEHOLDER.decode("ascii")


def test_python_precision_does_not_exempt_generic_dotted_or_literal_values() -> None:
    for source in (
        b"TOKEN=opaque.value",
        b"token = 'node.token'",
        b"+token = node.token",
    ):
        findings = scan_for_sensitive_content(source)
        assert len(findings) == 1
        assert findings[0].confidence is ScanConfidence.HEURISTIC


@pytest.mark.parametrize(
    "source",
    [
        b"const token = parser.token;",  # JavaScript/TypeScript member without a safe enum proof
        b"var token = parser.token",  # Go-like declaration
        b"let token = parser.token;",  # Rust-like binding
        b"Token token = parser.token;",  # Java-like declaration
        b"token = node.token",  # Python without an enclosing function
        b"TOKEN=opaque.value",  # configuration/prose
        b'{"token":"node.token"}',  # quoted structured history
    ],
)
def test_unproven_cross_language_member_assignments_stay_heuristic(source: bytes) -> None:
    findings = scan_for_sensitive_content(source)
    assert len(findings) == 1
    assert findings[0].confidence is ScanConfidence.HEURISTIC


def test_high_confidence_controls_remain_high_across_source_contexts() -> None:
    for source in (
        b"def parse(node):\n    token = node.token\n    value = 'ghp_abcdefghijklmnopqrstuvwxyz123456'\n",
        b"const token = '-----BEGIN PRIVATE KEY-----';",
    ):
        findings = scan_for_sensitive_content(source)
        assert findings
        assert any(finding.confidence is ScanConfidence.HIGH for finding in findings)


def test_python_context_parse_failure_stays_heuristic(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_parse(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RecursionError("bounded parser failure")

    monkeypatch.setattr(privacy_module.ast, "parse", fail_parse)
    findings = scan_for_sensitive_content(b"def parse(node):\n    token = node.token\n")
    assert len(findings) == 1
    assert findings[0].confidence is ScanConfidence.HEURISTIC


def test_heuristic_json_assignment_redaction_keeps_structured_payload_valid() -> None:
    secret = b"bounded-but-suspicious-value"
    payload = (
        b'{"event_id":"evt_1","payload":{"auth_token":"'
        + secret
        + b'","config":"TOKEN=opaque.value"}}'
    )
    redacted, count = redact_heuristic_spans(payload)
    assert count == 2
    assert secret not in redacted
    assert json.loads(redacted) == {
        "event_id": "evt_1",
        "payload": {
            "auth_token": _PLACEHOLDER,
            # The value is redacted and the assignment name kept: the JSON member's ``:`` before
            # the string is a boundary byte, not the assignment separator (issue #976).
            "config": "TOKEN=" + _PLACEHOLDER,
        },
    }
    assert scan_for_sensitive_content(redacted) == ()


@pytest.mark.parametrize("value", ["bounded secret words", 'bounded\\"value'])
def test_quoted_assignment_redaction_consumes_complete_json_string(value: str) -> None:
    payload = json.dumps({"auth_token": value}, separators=(",", ":")).encode("utf-8")

    redacted, count = redact_heuristic_spans(payload)
    assert count == 1
    assert value.encode("utf-8") not in redacted
    assert json.loads(redacted) == {"auth_token": _PLACEHOLDER}
    assert scan_for_sensitive_content(redacted) == ()

    # Issue #982: a heuristic-only match is kept as captured in the encrypted local store; the
    # egress redaction above is what keeps it from leaving the machine.
    persisted = prepare_persisted_plaintext(payload)
    assert persisted == PersistenceScanResult(True, payload, False, ())


@pytest.mark.parametrize(
    "data",
    [
        b"TOKEN=opaque.value",
        b"TOKEN=Token.EOF",
        b"TOKEN: Token.EOF",
    ],
)
def test_ambiguous_unquoted_assignments_remain_heuristic(data: bytes) -> None:
    findings = scan_for_sensitive_content(data)
    assert len(findings) == 1
    assert findings[0].confidence is ScanConfidence.HEURISTIC


@pytest.mark.parametrize("data", [b"+TOKEN: opaque.value", b"-TOKEN: opaque.value"])
def test_diff_property_with_ambiguous_value_remains_heuristic(data: bytes) -> None:
    findings = scan_for_sensitive_content(data)
    assert len(findings) == 1
    assert findings[0].confidence is ScanConfidence.HEURISTIC


@pytest.mark.parametrize(
    "payload",
    [
        {
            "tool_name": "apply_patch",
            "tool_input": {"patch": "*** Begin Patch\\n+const token = parser.getToken();"},
        },
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Edit",
            "tool_input": {"new_string": "const token = parser.getToken();"},
        },
        {
            "hook_event_name": "postToolUse",
            "tool_name": "cursor_file_edit",
            "tool_input": {"newText": "+const token = parser.getToken();"},
        },
    ],
)
def test_json_encoded_host_edit_payloads_keep_source_assignments(
    payload: dict[str, object],
) -> None:
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    assert scan_for_sensitive_content(encoded) == ()


def test_heuristic_scan_saturation_is_bounded_without_exposing_matches() -> None:
    data = b"\n".join([b"TOKEN=suspiciousvalue"] * 128)
    findings = scan_for_sensitive_content(data)
    assert len(findings) == 128
    assert all(finding.confidence is ScanConfidence.HEURISTIC for finding in findings)


def test_prepare_persisted_plaintext_redacts_without_retaining_match() -> None:
    secret = b"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"
    data = b"export OPENAI_API_KEY=" + secret + b"\n"
    result = prepare_persisted_plaintext(data)
    assert result.persist is True
    assert result.redacted is True
    assert result.finding_kinds == ("credential_pattern",)
    assert b"[REDACTED]" in result.content
    assert secret not in result.content


def test_prepare_persisted_plaintext_keeps_heuristic_only_matches_raw() -> None:
    """Issue #982: capture keeps heuristic-only matches; egress redacts them."""

    data = b"export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    assert scan_for_sensitive_content(data)
    assert prepare_persisted_plaintext(data) == PersistenceScanResult(True, data, False, ())
    egress, count = redact_heuristic_spans(data)
    assert count == 1
    assert b"wJalrXUtnFEMI" not in egress


def test_prepare_persisted_plaintext_redacts_only_high_confidence_spans_in_mixed_content() -> None:
    high = b"ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    data = b"api_token = 'a8F3kL9qZ2xV7mN4'\nGH=" + high + b"\n"
    result = prepare_persisted_plaintext(data)
    assert result.persist is True
    assert result.redacted is True
    assert result.finding_kinds == ("credential_pattern",)
    assert high not in result.content
    assert b"api_token = 'a8F3kL9qZ2xV7mN4'" in result.content


def test_prepare_persisted_plaintext_withholds_canary_and_scanner_failure() -> None:
    canary = b"unique-binary-canary-\x00-credential"
    withheld = prepare_persisted_plaintext(b"prefix" + canary + b"suffix", canaries=(canary,))
    assert withheld == PersistenceScanResult(False, b"", True, ("canary",))
    failed = prepare_persisted_plaintext(canary, canaries=(b"",))
    assert failed.persist is False
    assert failed.content == b""
    assert failed.redacted is True


def test_prepare_persisted_plaintext_withholds_at_finding_capacity() -> None:
    secret = b"OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"
    saturated = prepare_persisted_plaintext(b"\n".join([secret] * 128))

    assert saturated == PersistenceScanResult(False, b"", True, ("credential_pattern",))


def test_heuristic_saturation_does_not_withhold_capture() -> None:
    """High-confidence detectors run first, so a cap reached by heuristics loses no high match."""

    secret = b"AWS_SECRET_ACCESS_KEY=not-a-real-but-sensitive-value"
    data = b"\n".join([secret] * 128)
    assert len(scan_for_sensitive_content(data)) == 128
    assert prepare_persisted_plaintext(data) == PersistenceScanResult(True, data, False, ())

    high = b"GH=ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    mixed = b"\n".join([high] + [secret] * 200)
    result = prepare_persisted_plaintext(mixed)
    assert result.persist is True
    assert result.redacted is True
    assert b"ghp_" not in result.content
    assert result.content.count(b"not-a-real-but-sensitive-value") == 200


def test_redact_high_confidence_content_flags_only_changed_bytes() -> None:
    heuristic_only = b'self.api_key = "Zx81Kq0Lm2Pq9Rs7"\n'
    assert redact_high_confidence_content(heuristic_only) == (heuristic_only, False)
    assert redact_high_confidence_content(b"plain text") == (b"plain text", False)
    redacted, changed = redact_high_confidence_content(
        b"key=sk-abcdefghijklmnopqrstuvwxyz123456 and " + heuristic_only
    )
    assert changed is True
    assert b"sk-abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert heuristic_only in redacted


def test_privacy_helpers_are_deterministic() -> None:
    record = {
        "engine_version": "0.1.0",
        "sqlite_compile_options_ok": True,
        "operation_count": 9,
        "session_id_hash": "hmac-sha256:" + "a" * 64,
    }
    first = build_diagnostic_manifest(DiagnosticRedactionProfile.SUPPORT, record)
    second = build_diagnostic_manifest(DiagnosticRedactionProfile.SUPPORT, record)
    assert first == second
    assert first["session_id_hash"] == record["session_id_hash"]
    assert "session_id_hash" not in build_diagnostic_manifest(
        DiagnosticRedactionProfile.MINIMAL,
        record,
    )
    with pytest.raises(PrivacyFenceError, match="credential_pattern_detected"):
        build_diagnostic_manifest(
            DiagnosticRedactionProfile.RELEASE_PROBE,
            {"capability_probe_id": "sk-abcdefghijklmnopqrstuvwxyz123456"},
        )


def test_mac_helpers_require_exact_purpose_and_domain() -> None:
    log = _mac(b"log-key-32-byte-purpose-binding!", SESSION_HASH_DOMAIN)
    audit = _mac(b"audit-key-32-byte-purpose-bind", PRIVACY_REQUEST_BODY_DOMAIN)
    assert session_id_hash(_SESSION_ID, log).startswith("hmac-sha256:")
    assert privacy_request_commitment(b"{}", audit).startswith("hmac-sha256:")
    with pytest.raises(ValueError, match="mac_domain_forbidden"):
        session_id_hash(_SESSION_ID, audit)
    with pytest.raises(ValueError, match="mac_domain_forbidden"):
        privacy_request_commitment(b"{}", log)
    with pytest.raises(TypeError, match="raw_mac_key_forbidden"):
        session_id_hash(_SESSION_ID, b"raw-key")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="raw_mac_key_forbidden"):
        privacy_request_commitment(b"{}", bytearray(b"raw-key"))  # type: ignore[arg-type]


def test_request_commitment_covers_final_body_only() -> None:
    key = b"privacy-audit-body-key-32-bytes!"
    handle = _mac(key, PRIVACY_REQUEST_BODY_DOMAIN)
    body = b'{"input":"bounded final body"}'
    expected = hmac.new(
        key,
        PRIVACY_REQUEST_BODY_DOMAIN + body,
        hashlib.sha256,
    ).hexdigest()
    assert privacy_request_commitment(body, handle) == f"hmac-sha256:{expected}"
    assert privacy_request_commitment(body + b"!", handle) != f"hmac-sha256:{expected}"


@pytest.mark.parametrize(
    "line",
    (
        b"API_TOKEN=abcdefgh12345678\n",
        b'x_token = "abcdefgh12345678"\n',
    ),
)
def test_redacted_line_stays_clean_after_json_encoding(line: bytes) -> None:
    """TB4 tb4f1 (issue #976): Yoetz's own marker must not re-match once JSON-escaped.

    The prepared review packet is canonical JSON, so ``[REDACTED]\\n`` used to read as a fresh
    token assignment value and the egress rescan blocked the whole packet.
    """

    redacted, count = redact_heuristic_spans(line)
    assert count == 1
    encoded = canonical_encode({"content": redacted.decode("utf-8")})
    assert scan_for_sensitive_content(encoded) == ()
    # Redacting the encoded form again is a fixed point.
    assert redact_heuristic_spans(encoded) == (encoded, 0)


@pytest.mark.parametrize(
    ("encoded", "secret"),
    (
        (b'{"c":"API_TOKEN=abcdefgh12345678\\n"}', b"abcdefgh12345678"),
        (b'{"c":"auth_token:\\n  zzqqrrtt9988\\n"}', b"zzqqrrtt9988"),
        (b'{"k":"password=\\"s3cretvalue\\""}', b"s3cretvalue"),
    ),
)
def test_json_encoded_assignment_is_still_detected_and_redacted(
    encoded: bytes, secret: bytes
) -> None:
    findings = scan_for_sensitive_content(encoded)
    assert findings
    assert all(finding.confidence is ScanConfidence.HEURISTIC for finding in findings)
    redacted, count = redact_heuristic_spans(encoded)
    assert count == 1
    assert secret not in redacted
    json.loads(redacted)


@pytest.mark.parametrize(
    ("data", "secret"),
    (
        (b"password=Ab12\\tZZtail9", b"ZZtail9"),
        (b"password=C:\\temp\\new", b"new"),
        (json.dumps({"c": "password=ab\\ntail"}).encode(), b"tail"),
        (json.dumps({"c": 'password="ab\\"cd efgh"'}).encode(), b"efgh"),
    ),
)
def test_encoded_escapes_never_shorten_a_redacted_value(data: bytes, secret: bytes) -> None:
    """A literal backslash escape inside a value stays inside the redacted span (issue #976)."""

    redacted, changed = redact_sensitive_content(data)
    assert changed
    assert secret not in redacted


# Issue #982: shapes taken from real tb4n1 captures (sglang, vllm, batched-eval, freight, fin-saccr,
# rs-archive, data-anonymization and nextjs attempts) where the assignment heuristic fired on
# ordinary source code or tool output and redacted local evidence for nothing.
@pytest.mark.parametrize(
    "source",
    [
        b'        self.bot_token = "<|tool_call_start|>"\n',
        b'        self.eot_token = "<|tool_call_end|>"\n',
        b'        self.bot_token = "["\n',
        b'        self.bot_token = "<tool_call>"\n',
        b'        self.eot_token = "\\n</tool_call>"\n',
        b'        self.bot_token = "[TOOL_CALLS] ["\n',
        b'        self.bot_token = "<|start|>assistant<|channel|>commentary"\n',
        b'        self.bot_token = "<\xef\xbd\x9ctool\xe2\x96\x81calls\xe2\x96\x81begin\xef\xbd\x9c>"\n',
        b'    tokenizer.pad_token = "<pad>"\n',
        b'    "self.bot_token = \\"<tool_call>\\"\\n"',  # the same line inside JSON tool output
        b"    tool_call_start_token: str\n",
        b"    previous_token: int\n",
        b"def detect(self, text: str, bot_token: str) -> None:\n",
        b"        if token == self.eot_token:\n",
        b"    while (token := next(stream)) is not None:\n",
        b"    token = self.id_to_token[int(token_id)]\n",
        b"    token = tokenizer.decode(token_id)\n",
        b'    token = os.environ.get("HF_TOKEN")\n',
        b"    self.token = functools.lru_cache(maxsize=2048)(self._token)\n",
        b"    previous_token=self.bos_id,\n",
        b"        self.tool_call_start_token = TOOL_CALL_START\n",
        b"        had_end_token = self.eot_token\n",
        b"    compute(logits, per_token=True)\n",
        b"        found_token = False\n",
        b"{'mean_logprob_per_token': -4.722294041641461, 'mean_token': None}\n",
        b"for char in token:\n            node = x\n",
        b"        if self.unk_token:\n            return None\n",
        b"Use `yoetz status`; the finding token: `work_open_findings` is open.\n",
        b"session_token: mask_secret\n",
        b"rules:\n  mask_secret:\n    anonymizer: sha256\n",
        b"OPENAI_API_KEY=\nOPENAI_BASE_URL=\nPAGER=cat\n",
        b"api_key: Optional[str] = None\n",
        b'api_key = "<your-api-key>"\n',
        b"AI_GATEWAY_API_KEY=gw_...\n",
    ],
)
def test_tb4n1_source_false_positives_are_not_credentials(source: bytes) -> None:
    assert scan_for_sensitive_content(source) == ()
    assert redact_heuristic_spans(source) == (source, 0)


@pytest.mark.parametrize(
    "source",
    [
        b'api_token = "a8F3kL9qZ2xV7mN4"\n',
        b"GITHUB_TOKEN=abcd1234efgh5678\n",
        b'password: "hunter2hunter2"\n',
        b'        self.api_key = "Zx81Kq0Lm2Pq9Rs7"\n',
        b'{"token":"AbC123xyz789Qwe"}',
        b'{"env":"GITHUB_TOKEN=abcd1234efgh5678\\nPATH=/usr/bin"}',
        b"access_token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl\n",
        b"PASSWORD=admin\n",
        b"password='p@ss(w0rd) with spaces'\n",
        b"SECRET_KEY = 'correct horse battery staple'\n",
        b"self.session_token = 'merge_sess_00002_post'\n",
        b"card_token: tok_live_00149999_49981\n",
        b'{"c":"auth_token:\\n  zzqqrrtt9988\\n"}',
    ],
)
def test_narrowed_heuristic_still_matches_plausible_secrets(source: bytes) -> None:
    findings = scan_for_sensitive_content(source)
    assert findings
    assert all(finding.confidence is ScanConfidence.HEURISTIC for finding in findings)
    redacted, count = redact_heuristic_spans(source)
    assert count >= 1
    assert redacted != source


@pytest.mark.parametrize(
    "source",
    [
        b"key = 'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789'\n",
        b"token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'\n",
        b"AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
        b"postgres://admin:hunter2@db.internal/app\n",
        b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
    ],
)
def test_high_confidence_detectors_are_unchanged_by_narrowing(source: bytes) -> None:
    findings = scan_for_sensitive_content(source)
    assert any(finding.confidence is ScanConfidence.HIGH for finding in findings)
    assert prepare_persisted_plaintext(source).redacted is True
