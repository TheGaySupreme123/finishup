"""Deterministic privacy fences for plaintext diagnostic surfaces."""

from __future__ import annotations

import ast
import bisect
import hashlib
import json
import re
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Final

from finishup.domain.values import parse_rfc3339_millis, validate_commitment
from finishup.ports.keys import MacKeyHandle
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "PRIVACY_REQUEST_BODY_DOMAIN",
    "SESSION_HASH_DOMAIN",
    "EGRESS_CREDENTIAL_PLACEHOLDER",
    "DiagnosticRedactionProfile",
    "PersistenceScanResult",
    "PrivacyFenceError",
    "ScanConfidence",
    "ScanFinding",
    "Sensitivity",
    "assert_plaintext_safe",
    "build_diagnostic_manifest",
    "heuristic_value_lines",
    "prepare_persisted_plaintext",
    "privacy_request_commitment",
    "redact_before_cut",
    "redact_diagnostic_record",
    "redact_diagnostic_value",
    "redact_encoded_heuristic_spans",
    "redact_fully",
    "redact_heuristic_spans",
    "redact_high_confidence_content",
    "redact_sensitive_content",
    "scan_for_sensitive_content",
    "scan_finding_is_heuristic",
    "semantic_disclosed_bytes",
    "semantic_egress_forms",
    "semantic_egress_transforms",
    "session_id_hash",
]

SESSION_HASH_DOMAIN: Final = b"yoetz/session-log-id/v1\x00"
PRIVACY_REQUEST_BODY_DOMAIN: Final = b"yoetz/privacy-egress-request/v1\x00"

_MAX_SCAN_FINDINGS: Final = 128
_PERSISTED_REDACTION_MARKER: Final = b"[REDACTED]"
# Egress-only replacement for a credential-like value (issue #982, owner decision B2): the value,
# and only the value, is replaced in place so the reviewer still sees the rest of the line, item
# and file, and is told why the value is missing. The text is fixed; it carries no source bytes.
# It has no whitespace, so an unquoted value (``TOKEN=...``) is replaced by one scanner-exempt
# unquoted value rather than by text whose first word would re-match as a fresh assignment.
EGRESS_CREDENTIAL_PLACEHOLDER: Final = b"[withheld-by-yoetz:possible-credential]"
_EXEMPT_REPLACEMENT_MARKERS: Final = frozenset(
    {_PERSISTED_REDACTION_MARKER, EGRESS_CREDENTIAL_PLACEHOLDER}
)
_MAX_CANARIES: Final = 64
_MAX_CANARY_BYTES: Final = 4_096
_SCAN_CHUNK_BYTES: Final = 65_536
_SCAN_OVERLAP_BYTES: Final = 4_096
_MAX_STRUCTURAL_TEXT_BYTES: Final = 128
_MAX_SAFE_INTEGER: Final = 2**53 - 1

_TOKEN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$", re.ASCII)
# One FinishUP-owned source location, nothing else: a dotted module path under ``finishup`` and a
# line number. Deliberately cannot express a filesystem path, a symbol, or any runtime value, so
# the field carries where our own code failed and can carry nothing about the caller's data.
# Records written before the rename name the package ``yoetz``; the durable diagnostics ring
# re-validates them on read, so the legacy package name stays accepted (ADR-048).
_ORIGIN = re.compile(
    r"^(?:finishup|yoetz)(?:\.[a-z_][a-z0-9_]{0,63}){0,8}:[0-9]{1,6}"
    r"(?:#[A-Za-z_][A-Za-z0-9_]{0,63})?$",
    re.ASCII,
)
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._/+:-]{0,127}$", re.ASCII)
_HASH = re.compile(r"^(?:hmac-)?sha256:[0-9a-f]{64}$", re.ASCII)


# A private key is matched from its BEGIN line through the END line of the same label (#1248,
# owner decision P-D4): PEM (``RSA``, ``EC``, ``DSA``), PKCS#8 (plain and ``ENCRYPTED``), OpenSSH
# and PGP key blocks. Both lines are literal at every JSON escaping depth, so the block is found
# whole in a diff, an indented string or an encoded packet alike. The patterns are written with
# ``-{5}`` so the publication-boundary scanner does not read detector constants as key material
# (PRIV-CRED-001).
_PRIVATE_KEY_BEGIN: Final = re.compile(
    rb"-{5}BEGIN (?P<label>(?:[A-Z0-9]{1,16} ){0,2}PRIVATE KEY(?: BLOCK)?)-{5}"
)
# How far past its BEGIN line a key block may end. The largest real keys (16384-bit RSA, PGP
# blocks with subkeys) stay well inside it, escaped at depth three included. A BEGIN line with no
# matching END inside it is an unterminated key: its finding runs to the end of the data, and the
# passes that hold whole items withhold the item.
_MAX_PRIVATE_KEY_BLOCK_BYTES: Final = 65_536
_CREDENTIAL_PATTERNS: Final = (
    re.compile(rb"(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,256}(?![A-Za-z0-9_-])"),
    re.compile(rb"(?<![A-Za-z0-9])(?:ghp_|gho_|ghu_|ghs_)[A-Za-z0-9]{20,256}"),
    re.compile(rb"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,256}"),
    re.compile(rb"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{20,256}"),
    re.compile(rb"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])"),
)
_URI_PASSWORD = re.compile(rb"[A-Za-z][A-Za-z0-9+.-]{0,31}://[^\s/:@]{1,128}:[^\s/@]{1,256}@")
# Assignment values are bounded but may be quoted JSON/Python strings.  Keep the complete quoted
# span, including whitespace and escaped quotes, so redaction cannot leave a suffix behind or
# remove the closing quote and corrupt an otherwise valid structured payload.
# A JSON string escape for a line break or tab (``\\n``, ``\\r``, ``\\t``) is whitespace in the
# text it encodes. Prepared review packets are canonical JSON, so the separator may span one, and
# the exact-marker exemption ignores trailing ones; otherwise FinishUP's own ``[REDACTED]`` marker
# followed by an encoded newline re-matches as a fresh assignment after encoding and blocks the
# whole packet (TB4 tb4f1, issue #976).
_ENCODED_SPACE = rb"(?:\s|\\[nrt])"
# The assignment separator. After ``=`` the value starts on the same line: an empty ``KEY=`` value
# ends at the line break, raw or encoded, so the next line is never read as its value and is
# scanned on its own (#1248, owner decision). After ``:`` the separator may still span a line
# break; a YAML value indented on the following lines is P3's block-value detection.
_SAME_LINE_SPACE = rb"(?:[ \t\f\v]|\\(?-i:t))"
_SEPARATOR = rb"(?:=" + _SAME_LINE_SPACE + rb"*|:" + _ENCODED_SPACE + rb"*)"
# Values end where the text they encode has whitespace (#1248, owner decision P-D3 on top of the
# 2026-10-06 rule, ADR-009). An unquoted value ends at raw whitespace and at a JSON-encoded line
# break or tab at any escaping depth, exactly as it ends at a raw one: the run of ``w``
# backslashes before ``n``, ``r`` or ``t`` (``w`` is 1 in a review packet, 2 in the reviewer
# conversation that nests the packet, 4 one level deeper). At depth ``d`` a literal backslash is
# ``2w`` backslashes, so a run of ``k`` backslashes before that letter is ``k - w`` literal ones
# and then the escape, where ``w`` is the largest power of two dividing ``k``. Those literal
# backslashes stay value bytes at depths 1 to 6, as does every backslash run of up to 64 that is
# not such an escape (``C:<backslash>Data``). Deeper or longer, the value conservatively ends at
# the run. Without this an encoded value ran through the rest of the line's encoding into the
# following lines, and the redaction that replaced the value deleted those lines with it
# (``DB_PASSWORD=...`` then ``DB_USER=...`` lost ``DB_USER``; #1138). The accepted cost: a value
# that itself contains a literal backslash-n, backslash-r or backslash-t ends there, so only its
# first part is matched and redacted.
_MAX_VALUE_BACKSLASH_RUN: Final = 64
# The escape letters that end an unquoted value: an encoded line break or tab. Case-sensitive even
# inside the ``(?i)`` assignment patterns: ``\N``, ``\R`` and ``\T`` are not JSON escapes.
_VALUE_END_ESCAPE_LETTER = rb"(?-i:[nrt])"
# The escape letters of a line break, which no value spans, quoted or not.
_LINE_BREAK_ESCAPE_LETTER = rb"(?-i:[nr])"
_UNQUOTED_VALUE_CHAR = (
    rb"(?:[^\s\\,'\";}{]"
    # A whole backslash run that is not an encoded line break or tab.
    + b"|\\\\{1,%d}(?!\\\\|%s)" % (_MAX_VALUE_BACKSLASH_RUN, _VALUE_END_ESCAPE_LETTER)
    # The literal backslashes before an encoded line break or tab of width ``w``.
    + b"".join(
        b"|(?:\\\\{%d}){1,%d}(?=\\\\{%d}%s)"
        % (2 * width, _MAX_VALUE_BACKSLASH_RUN // (2 * width), width, _VALUE_END_ESCAPE_LETTER)
        for width in (1, 2, 4, 8, 16, 32)
    )
    + rb")"
)
# A quoted value inside an encoded JSON string: ``\"...\"``. Inside it an encoded escaped quote
# (three backslashes and a quote) and an encoded backslash (two) are part of the value. Like the
# raw quoted value, it never spans a line break of the text it encodes (an encoded ``\n``/``\r``).
# A JSON document nested as a string inside another one (#1015) quotes its values with three
# backslashes, and one level deeper with seven: the quote of escaping depth ``d`` is ``2**d - 1``
# backslashes and ``"``. Inside such a value an escaped quote is ``2w + 1`` backslashes, a literal
# backslash ``w + 1``, and any other escape (``\n``, ``\t``, ``\u``) ``(w + 1) / 2`` before its
# letter; an encoded line break ends the value as it does at depth one.
_QUOTE_WIDTHS: Final = (1, 3, 7)


def _deep_escaped_quoted_value(width: int) -> bytes:
    half = (width + 1) // 2
    return (
        b'\\\\{%d}"(?:\\\\{%d}"|\\\\{%d}|\\\\{%d}(?![\\\\"]|%s)|[^\\\\"\\r\\n]){1,512}\\\\{%d}"'
        % (width, 2 * width + 1, width + 1, half, _LINE_BREAK_ESCAPE_LETTER, width)
    )


_ESCAPED_QUOTED_VALUE = (
    rb"(?:"
    + b"|".join(_deep_escaped_quoted_value(width) for width in reversed(_QUOTE_WIDTHS[1:]))
    + rb'|\\"(?:\\\\\\"|\\\\\\\\|(?!\\"|\\'
    + _LINE_BREAK_ESCAPE_LETTER
    + rb')[^\r\n]){1,512}\\")'
)
# The opening quote of a quoted assignment value: ``'``, ``"`` or an escaped ``"`` of depth 1-3.
_VALUE_QUOTE: Final = re.compile(rb"['\"]|\\{7}\"|\\{3}\"|\\\"")
_JSON_STRING_TOKEN: Final = re.compile(rb'"(?:[^"\\]|\\.)*"')
_JSON_STRING_ESCAPE: Final = re.compile(
    rb"\\(?:u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)"
)
# Python/JS string-literal prefixes (``b"..."``, ``r'...'``, ``f"..."``) belong to the quoted value.
_STRING_PREFIX_RE: Final = rb"(?:[bBrRuUfF]{1,2}(?=[\"']))?"
_STRING_PREFIX: Final = re.compile(rb"[bBrRuUfF]{1,2}(?=[\"'])")
_ASSIGNMENT_VALUE = (
    rb"(?:" + _STRING_PREFIX_RE + rb"\"(?:\\.|[^\"\\\r\n]){1,512}\""
    rb"|" + _STRING_PREFIX_RE + rb"'(?:\\.|[^'\\\r\n]){1,512}'"
    rb"|" + _ESCAPED_QUOTED_VALUE + rb"|" + _UNQUOTED_VALUE_CHAR + rb"{1,512})"
)
# Compound names such as AWS_SECRET_ACCESS_KEY and AZURE_CLIENT_SECRET keep the
# secret token as one underscore/hyphen component, not the entire identifier.
# The key's closing quote may be escaped to depth three (``\\\"`` closes a key of a JSON
# document nested in a JSON string, #1015), like the quoted value after it.
_SECRET_ASSIGNMENT = re.compile(
    rb"(?i)(?:^|[^A-Za-z0-9_])['\"]?"
    rb"(?:[A-Za-z][A-Za-z0-9]{0,63}[_-])*"
    rb"(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key|secret)"
    rb"(?:[_-][A-Za-z][A-Za-z0-9]{0,63})*"
    rb"(?:\\{0,7}['\"])?\s*" + _SEPARATOR + _ASSIGNMENT_VALUE
)
# `*_TOKEN` only as the final identifier component. The value must contain a
# non-digit and be at least eight bytes so MAX_TOKEN=4096 and TOKEN_COUNT=12
# are not treated as secrets.
_TOKEN_ASSIGNMENT = re.compile(
    rb"(?i)(?:^|[^A-Za-z0-9_])['\"]?"
    rb"(?:[A-Za-z][A-Za-z0-9]{0,63}[_-])*token"
    rb"(?:\\{0,7}['\"])?\s*" + _SEPARATOR + rb"(?="
    rb"(?:" + _STRING_PREFIX_RE + rb"\"(?:\\.|[^\"\\\r\n]){1,512}\""
    rb"|" + _STRING_PREFIX_RE + rb"'(?:\\.|[^'\\\r\n]){1,512}'"
    rb"|"
    + _ESCAPED_QUOTED_VALUE
    + rb"|"
    + _UNQUOTED_VALUE_CHAR
    + rb"{0,511}[A-Za-z_/=+-]))"
    + _ASSIGNMENT_VALUE
)
# A typed declaration (``password: str = "hunter2"``, ``api_token: Final = "..."``) puts a type
# between the name and ``=``; the plain heuristics stop at the ``:`` and read the type as the value.
# Only a quoted value is considered, and the finding span is the quoted value alone, so redaction
# keeps the name, the annotation and the ``=``.
_ANNOTATED_ASSIGNMENT = re.compile(
    rb"(?i)(?:^|[^A-Za-z0-9_])"
    rb"(?P<name>(?:[A-Za-z][A-Za-z0-9]{0,63}[_-])*"
    rb"(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key|secret|token)"
    rb"(?:[_-][A-Za-z][A-Za-z0-9]{0,63})*)"
    rb"[ \t]*:[ \t]*[A-Za-z_][A-Za-z0-9_.\[\], |]{0,64}?[ \t]*"
    rb"(?P<assign>=[ \t]*(?P<value>"
    + _STRING_PREFIX_RE
    + rb"\"(?:\\.|[^\"\\\r\n]){1,512}\"|"
    + _STRING_PREFIX_RE
    + rb"'(?:\\.|[^'\\\r\n]){1,512}'))"
)
# Assignment heuristics remain conservative: ordinary parser/member/call expressions should not
# turn a whole review into a credential refusal, but a bare dotted value is ambiguous without
# source syntax. These filters run on bounded matches and never retain or log the value inspected.
_SOURCE_DECLARATION = re.compile(
    rb"(?ix)(?:^|[\s{;(+\-'\"])"
    rb"(?:export\s+)?(?:const|let|var)\s+"
    rb"[A-Za-z_][A-Za-z0-9_]*\s*$"
)
_CODE_LIKE_CALL_VALUE = re.compile(
    rb"(?ix)^(?:(?:[A-Za-z_][A-Za-z0-9_]*\.)?"
    rb"(?:getToken|nextToken|next)|[A-Za-z_][A-Za-z0-9_]*token)"
    rb"\([^()]{0,256}\)$"
)
_CODE_LIKE_ENUM_VALUE = re.compile(rb"^(?:[A-Z][A-Za-z0-9_]*\.)+[A-Z][A-Za-z0-9_]*$")
_TOKEN_LIKE_ASSIGNMENT_NAME = re.compile(rb"(?i)^(?:[A-Za-z][A-Za-z0-9]{0,63}[_-])?token$")
# Issue #982: values that cannot be credential material. Real tb4n1 captures showed the assignment
# heuristics firing on ordinary source (``self.bot_token = "<|tool_call_start|>"``, ``bot_token:
# str``, ``token = data[i]``, ``token == ...``), which redacted local evidence for nothing. Each
# rule below inspects only the bounded match and never retains or logs the value.
# A ``*token`` value is opaque material: base64/base64url/JWT/hex/URL-safe bytes, never
# whitespace, brackets, braces, parentheses, pipes, quotes or backticks.
_TOKEN_VALUE_CHARS: Final = re.compile(rb"^[A-Za-z0-9._~+/=:@%!#$&*?^-]+$")
_MIN_TOKEN_VALUE_BYTES: Final = 8
# Characters that make an unquoted ``*token`` value a source expression or markup, not a credential.
_UNQUOTED_CODE_CHARS: Final = re.compile(rb"[()\[\]<>|`]")
# Password/secret/API-key values are human-chosen and may hold any punctuation, so for them only a
# real source shape is skipped: a call or subscript on a name (``get_secret(``, ``secrets[i]``) or
# a pipe operator (``|>``).
_SECRET_CODE_SHAPE: Final = re.compile(rb"^[A-Za-z_][A-Za-z0-9_.]*[(\[]|\|>")
_NUMERIC_VALUE: Final = re.compile(rb"^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$")
# Language literals and type annotations (``password: str``, ``per_token=True``).
_NON_CREDENTIAL_WORDS: Final = frozenset(
    {
        b"None",
        b"True",
        b"False",
        b"null",
        b"nil",
        b"true",
        b"false",
        b"undefined",
        b"str",
        b"int",
        b"bool",
        b"bytes",
        b"float",
        b"object",
        b"Any",
        b"string",
        b"number",
        b"boolean",
        b"Optional",
        b"SecretStr",
        b"Final",
        b"ClassVar",
    }
)
# ``self.bos_id``, ``this.token`` and ``cls.prefix`` name an attribute; they are never a value.
_RECEIVER_ATTRIBUTE_VALUE: Final = re.compile(rb"^(?:self|this|cls)(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
# A digit-free snake/constant identifier (``TOOL_CALL_START``, ``normal_text``) is a source name;
# random credential material of eight or more bytes practically always carries a digit. Dotted
# values such as ``opaque.value`` stay ambiguous and keep matching.
_DIGITLESS_IDENTIFIER_VALUE: Final = re.compile(rb"^[A-Za-z]+(?:_[A-Za-z]+)+$")
# Documentation placeholders: ``"<your-api-key>"``, ``"${API_KEY}"``, ``"{{ token }}"``, ``gw_...``.
_PLACEHOLDER_VALUE: Final = re.compile(
    rb"^(?:<[^<>]{1,256}>|\$\{[^{}]{1,256}\}|\{\{[^{}]{1,256}\}\}|.{0,256}(?:\.\.\.|\xe2\x80\xa6))$",
    re.DOTALL,
)
# Each shape needs a placeholder cue so an all-letter password (``"<Password>"``, ``"Secret..."``)
# keeps matching: a ``-``/``_``-joined or all-caps name or the word ``your`` inside ``<>``, a
# ``${NAME}`` reference, a ``{{ name }}`` template, or a vendor prefix ending in ``_``/``-``
# before an ellipsis (``gw_...``).
_SECRET_PLACEHOLDER_VALUE: Final = re.compile(
    rb"^(?:<(?:[A-Za-z]{1,32}[_-][A-Za-z_ -]{1,64}|[A-Z_]{2,64}|(?i:your)[A-Za-z_ -]{0,60})>"
    rb"|\$\{[A-Za-z_]{1,64}\}|\{\{[ A-Za-z_.]{1,64}\}\}"
    rb"|(?:[A-Za-z]{1,6}[_-])?(?:\.\.\.|\xe2\x80\xa6))$"
)
_LINE_BREAK_SEPARATOR: Final = re.compile(rb"[\r\n]|\\[nr]")
# After a line break, ``NEXT_KEY=`` or ``nested:`` is the next key, not this key's value.
_NEXT_KEY_VALUE: Final = re.compile(rb"^[A-Za-z_][A-Za-z0-9_.-]*[:=]$")
_ENCODED_ESCAPE: Final = re.compile(rb"\\")

_LOG_FIELDS: Final = frozenset(
    {
        "codex_event_wire_bytes",
        "codex_event_control_count",
        "codex_event_control_bytes",
        "codex_event_telemetry_count",
        "codex_event_telemetry_bytes",
        "codex_event_delta_count",
        "codex_event_delta_bytes",
        "codex_event_intermediate_count",
        "codex_event_intermediate_bytes",
        # #1172: per-exchange prompt-cache telemetry (provider-reported token counts and one
        # closed miss label, never content).
        "reviewer_exchange_index",
        "reviewer_model_requests",
        "reviewer_input_tokens",
        "reviewer_cached_input_tokens",
        "reviewer_cache_write_input_tokens",
        "reviewer_output_tokens",
        "reviewer_prefix_tokens",
        "reviewer_prefix_cached_tokens",
        "reviewer_cache_miss",
        "timestamp",
        "level",
        "component",
        "operation",
        "correlation_id",
        "session_id_hash",
        "request_id",
        "duration_ms",
        "outcome",
        "reason",
        "reason_code",
        "phase",
        "origin",
        "engine_version",
        "policy_version",
        "sqlite_source_id_hash",
        # Bounded structural accounting for one AI-powered review: what the reviewer returned and
        # what became of it. Counts and one closed conclusion token only — never challenge text.
        "semantic_conclusion",
        "semantic_challenges_returned",
        "semantic_candidates_accepted",
        "semantic_challenges_rejected",
        "semantic_rejected_hidden_source_claim",
        "semantic_rejected_local_rule_owned",
        "semantic_rejected_ref_not_carried",
        "semantic_rejected_ref_outside_case",
        "semantic_rejected_routine_completeness",
        "semantic_rejected_snippet_invalid",
        "semantic_rejected_subject_refs_over_limit",
        "semantic_rejected_yoetz_process_state",
        "semantic_challenges_advisory",
        "semantic_agent_criteria",
        "semantic_review_refs_reduced",
        "semantic_review_snippets_rejected",
        "semantic_restatements_suppressed",
        "semantic_prior_rulings_set_aside",
        "semantic_rulings_disputed_after_rebuttal",
        "semantic_findings_selected",
        "semantic_findings_suppressed",
        # #1241 D9: the verification rerun question, per check.
        "rerun_questions_asked",
        "rerun_questions_answered",
        "rerun_answers_reviewer_agreed",
        "rerun_answers_reviewer_disagreed",
        "reruns_after_answer",
        "reruns_after_answer_changed",
        "semantic_follow_up_round",
        "semantic_follow_up_items",
        "semantic_follow_up_refs_added",
        "semantic_follow_up_parts_added",
        "semantic_capture_parts_resolved",
        "semantic_diff_parts_resolved",
        "semantic_excerpts_selected",
        "semantic_diff_excerpts_selected",
        "semantic_excerpt_bytes_selected",
        "semantic_excerpt_count_approved",
        "semantic_excerpt_byte_approved",
        "semantic_excerpt_count_limit",
        "semantic_excerpt_count_cut_for_case_bound",
        "semantic_excerpt_byte_limit",
        "semantic_excerpt_ceiling_rounds",
        # #1245 (D22): which sections ceiling planning dropped, and the agent-account rows kept
        # (integers only, never content).
        "semantic_section_dropped_goal",
        "semantic_section_dropped_obligations",
        "semantic_section_dropped_claims",
        "semantic_section_dropped_timeline",
        "semantic_obligation_rows_selected",
        "semantic_claim_rows_selected",
        # #1118: a capacity refusal's rendered disclosure size and the limit it
        # exceeded (integers only, never content).
        "semantic_disclosure_attempted_bytes",
        "semantic_disclosure_limit_bytes",
        "semantic_disclosure_attempted_tokens",
        "semantic_disclosure_limit_tokens",
        "semantic_excerpt_attempted_bytes",
        "semantic_excerpt_limit_bytes",
        "semantic_excerpt_attempted_excerpts",
        "semantic_excerpt_limit_excerpts",
        "semantic_excerpt_total_attempted_bytes",
        "semantic_excerpt_total_limit_bytes",
        # #1230: excerpts a disclosure-time fit left out (integers only).
        "semantic_excerpts_unselected_at_disclosure",
        # #1242: the first exchange could not keep the frame later exchanges grow into.
        "semantic_first_exchange_frame_unkept",
        "semantic_first_exchange_frame_unplanned",
        "semantic_check_change_parts_selected",
        "semantic_edit_evidence_in_case",
        # Issue #1102: task-input pilot counters (integers only, never a path).
        "semantic_task_input_candidates",
        "semantic_task_input_excerpts_selected",
        "semantic_task_input_listings",
        "semantic_task_input_outside_candidates",
        "semantic_task_inputs_outside_not_admitted",
        "semantic_task_inputs_read",
        # Closed control-plane identity of an abandoned response write (tb4n2 NEW-8): the wire
        # method enum value and the handshake client kind, never a body or a peer identity.
        "control_method",
        "client_kind",
    }
)
_MANIFEST_FIELDS: Final = frozenset(
    {
        "schema_version",
        "redaction_profile",
        "package_version",
        "protocol_version",
        "control_protocol_version",
        "engine_version",
        "policy_version",
        "projection_version",
        "privacy_policy_schema_version",
        "egress_receipt_schema_version",
        "platform_identity",
        "runtime_identity",
        "sqlite_version",
        "sqlite_source_id_hash",
        "sqlite_compile_options_ok",
        "startup_check_outcome",
        "startup_reason_code",
        "operation_count",
        "duration_bucket_ms",
        "terminal_outcome_count",
        "session_id_hash",
        "capability_probe_id",
    }
)
_KNOWN_FIELDS: Final = _LOG_FIELDS | _MANIFEST_FIELDS
_ALWAYS_OMITTED: Final = frozenset(
    {
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
    }
)
_TOKEN_FIELDS: Final = frozenset(
    {
        "level",
        "component",
        "operation",
        "outcome",
        "reason",
        "reason_code",
        "phase",
        "redaction_profile",
        "startup_check_outcome",
        "startup_reason_code",
        "capability_probe_id",
        "semantic_conclusion",
        "control_method",
        "client_kind",
        # #1172: the closed per-exchange prompt-cache miss label.
        "reviewer_cache_miss",
    }
)
_VERSION_FIELDS: Final = frozenset(
    {
        "schema_version",
        "package_version",
        "protocol_version",
        "control_protocol_version",
        "engine_version",
        "policy_version",
        "projection_version",
        "privacy_policy_schema_version",
        "egress_receipt_schema_version",
        "platform_identity",
        "runtime_identity",
        "sqlite_version",
    }
)
_INTEGER_FIELDS: Final = frozenset(
    {
        "codex_event_wire_bytes",
        "codex_event_control_count",
        "codex_event_control_bytes",
        "codex_event_telemetry_count",
        "codex_event_telemetry_bytes",
        "codex_event_delta_count",
        "codex_event_delta_bytes",
        "codex_event_intermediate_count",
        "codex_event_intermediate_bytes",
        # #1172: per-exchange prompt-cache token counts.
        "reviewer_exchange_index",
        "reviewer_model_requests",
        "reviewer_input_tokens",
        "reviewer_cached_input_tokens",
        "reviewer_cache_write_input_tokens",
        "reviewer_output_tokens",
        "reviewer_prefix_tokens",
        "reviewer_prefix_cached_tokens",
        "duration_ms",
        "operation_count",
        "duration_bucket_ms",
        "terminal_outcome_count",
        "semantic_challenges_returned",
        "semantic_candidates_accepted",
        "semantic_challenges_rejected",
        "semantic_rejected_hidden_source_claim",
        "semantic_rejected_local_rule_owned",
        "semantic_rejected_ref_not_carried",
        "semantic_rejected_ref_outside_case",
        "semantic_rejected_routine_completeness",
        "semantic_rejected_snippet_invalid",
        "semantic_rejected_subject_refs_over_limit",
        "semantic_rejected_yoetz_process_state",
        "semantic_challenges_advisory",
        "semantic_agent_criteria",
        "semantic_review_refs_reduced",
        "semantic_review_snippets_rejected",
        "semantic_restatements_suppressed",
        "semantic_prior_rulings_set_aside",
        "semantic_rulings_disputed_after_rebuttal",
        "semantic_findings_selected",
        "semantic_findings_suppressed",
        # #1241 D9: the verification rerun question, per check.
        "rerun_questions_asked",
        "rerun_questions_answered",
        "rerun_answers_reviewer_agreed",
        "rerun_answers_reviewer_disagreed",
        "reruns_after_answer",
        "reruns_after_answer_changed",
        "semantic_follow_up_round",
        "semantic_follow_up_items",
        "semantic_follow_up_refs_added",
        "semantic_follow_up_parts_added",
        "semantic_capture_parts_resolved",
        "semantic_diff_parts_resolved",
        "semantic_excerpts_selected",
        "semantic_diff_excerpts_selected",
        "semantic_excerpt_bytes_selected",
        "semantic_excerpt_count_approved",
        "semantic_excerpt_byte_approved",
        "semantic_excerpt_count_limit",
        "semantic_excerpt_count_cut_for_case_bound",
        "semantic_excerpt_byte_limit",
        "semantic_excerpt_ceiling_rounds",
        # #1245 (D22): which sections ceiling planning dropped, and the agent-account rows kept
        # (integers only, never content).
        "semantic_section_dropped_goal",
        "semantic_section_dropped_obligations",
        "semantic_section_dropped_claims",
        "semantic_section_dropped_timeline",
        "semantic_obligation_rows_selected",
        "semantic_claim_rows_selected",
        # #1118: a capacity refusal's rendered disclosure size and the limit it
        # exceeded (integers only, never content).
        "semantic_disclosure_attempted_bytes",
        "semantic_disclosure_limit_bytes",
        "semantic_disclosure_attempted_tokens",
        "semantic_disclosure_limit_tokens",
        "semantic_excerpt_attempted_bytes",
        "semantic_excerpt_limit_bytes",
        "semantic_excerpt_attempted_excerpts",
        "semantic_excerpt_limit_excerpts",
        "semantic_excerpt_total_attempted_bytes",
        "semantic_excerpt_total_limit_bytes",
        # #1230: excerpts a disclosure-time fit left out (integers only).
        "semantic_excerpts_unselected_at_disclosure",
        # #1242: the first exchange could not keep the frame later exchanges grow into.
        "semantic_first_exchange_frame_unkept",
        "semantic_first_exchange_frame_unplanned",
        "semantic_check_change_parts_selected",
        "semantic_edit_evidence_in_case",
        # Issue #1102: task-input pilot counters (integers only, never a path).
        "semantic_task_input_candidates",
        "semantic_task_input_excerpts_selected",
        "semantic_task_input_listings",
        "semantic_task_input_outside_candidates",
        "semantic_task_inputs_outside_not_admitted",
        "semantic_task_inputs_read",
    }
)
_BOOLEAN_FIELDS: Final = frozenset({"sqlite_compile_options_ok"})

_omitted_field_count = 0


class Sensitivity(str, Enum):  # noqa: UP042 - frozen diagnostic vocabulary
    PUBLIC_STRUCTURAL = "public_structural"
    LOCAL_IDENTIFIER = "local_identifier"
    USER_CONTENT = "user_content"
    SECRET = "secret"
    KEY_MATERIAL = "key_material"


class ScanConfidence(str, Enum):  # noqa: UP042 - local scanner classification
    """Confidence class for a sensitive-content match.

    ``ScanFinding.kind`` stays backward-compatible for persisted diagnostic manifests. Egress uses
    this separate field to withhold heuristic-only items while continuing to block concrete
    credentials.
    """

    HIGH = "high"
    HEURISTIC = "heuristic"


@dataclass(frozen=True, slots=True)
class ScanFinding:
    """One bounded sensitive-content match, without retaining matched bytes."""

    kind: str
    start_offset: int
    end_offset: int
    severity: Sensitivity
    confidence: ScanConfidence = ScanConfidence.HIGH

    def __post_init__(self) -> None:
        if self.kind not in {"canary", "credential_pattern", "private_key_marker"}:
            raise ValueError("scan_finding_kind_invalid")
        if (
            type(self.start_offset) is not int
            or type(self.end_offset) is not int
            or not 0 <= self.start_offset < self.end_offset
        ):
            raise ValueError("scan_finding_offset_invalid")
        if type(self.severity) is not Sensitivity:
            raise TypeError("scan_finding_severity_invalid")
        if type(self.confidence) is not ScanConfidence:
            raise TypeError("scan_finding_confidence_invalid")


def scan_finding_is_heuristic(finding: ScanFinding) -> bool:
    """Return whether a finding came from a low-confidence assignment heuristic."""

    if type(finding) is not ScanFinding:
        raise TypeError("scan_finding_invalid")
    return finding.confidence is ScanConfidence.HEURISTIC


class DiagnosticRedactionProfile(str, Enum):  # noqa: UP042 - frozen profile vocabulary
    MINIMAL = "minimal"
    SUPPORT = "support"
    RELEASE_PROBE = "release_probe"


class PrivacyFenceError(Exception):
    """A bounded privacy failure which never echoes the matched input."""

    __slots__ = ("reason_code", "surface")

    reason_code: str
    surface: str

    def __init__(self, reason_code: str, surface: str) -> None:
        if type(reason_code) is not str or _TOKEN.fullmatch(reason_code) is None:
            raise ValueError("privacy_reason_invalid")
        safe_surface = (
            surface if type(surface) is str and _TOKEN.fullmatch(surface) else "unsafe_surface"
        )
        self.reason_code = reason_code
        self.surface = safe_surface
        super().__init__(f"{reason_code}:{safe_surface}")


def _append_finding(
    findings: list[ScanFinding],
    seen: set[tuple[str, int, int]],
    kind: str,
    start: int,
    end: int,
    severity: Sensitivity,
    confidence: ScanConfidence = ScanConfidence.HIGH,
) -> None:
    identity = (kind, start, end)
    if identity not in seen and len(findings) < _MAX_SCAN_FINDINGS:
        seen.add(identity)
        findings.append(ScanFinding(kind, start, end, severity, confidence))


def _python_attribute_assignment_spans(data: bytes) -> tuple[tuple[int, int], ...]:
    """Return spans proven to be Python ``token = object.member`` assignments.

    The assignment scanner sees bytes from prose, structured history, diffs, and source files.
    Syntactically valid Python is necessary but insufficient: the assignment must sit inside a
    real function scope and the RHS must be the matching ``.token`` member. Calls, generic
    dotted values, literals, uppercase configuration names, mixed-language text, and malformed
    source remain heuristic findings.
    """

    if len(data) > _SCAN_CHUNK_BYTES:
        return ()
    try:
        source = data.decode("utf-8")
        tree = ast.parse(source, mode="exec")
    except (RecursionError, UnicodeDecodeError, SyntaxError, ValueError):
        return ()
    lines = source.splitlines(keepends=True)
    line_offsets: list[int] = []
    offset = 0
    for line in lines:
        line_offsets.append(offset)
        offset += len(line.encode("utf-8"))

    def node_span(node: ast.AST) -> tuple[int, int] | None:
        lineno = getattr(node, "lineno", None)
        col_offset = getattr(node, "col_offset", None)
        end_lineno = getattr(node, "end_lineno", None)
        end_col_offset = getattr(node, "end_col_offset", None)
        if not all(
            type(value) is int for value in (lineno, col_offset, end_lineno, end_col_offset)
        ):
            return None
        assert isinstance(lineno, int)
        assert isinstance(col_offset, int)
        assert isinstance(end_lineno, int)
        assert isinstance(end_col_offset, int)
        if not 1 <= lineno <= len(line_offsets) or not 1 <= end_lineno <= len(line_offsets):
            return None
        start = line_offsets[lineno - 1] + col_offset
        end = line_offsets[end_lineno - 1] + end_col_offset
        return (start, end) if 0 <= start < end <= len(data) else None

    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def has_enclosing_scope(node: ast.AST) -> bool:
        current = parents.get(node)
        while current is not None:
            if isinstance(current, (ast.AsyncFunctionDef, ast.FunctionDef)):
                return True
            current = parents.get(current)
        return False

    spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Attribute):
            continue
        if (
            not has_enclosing_scope(node)
            or not isinstance(node.value.value, ast.Name)
            or node.value.attr != "token"
            or not all(
                isinstance(target, ast.Name) and target.id == "token" for target in node.targets
            )
        ):
            continue
        span = node_span(node)
        if span is not None:
            spans.append(span)
    return tuple(sorted(set(spans)))


_ASSIGNMENT_SEPARATOR: Final = re.compile(rb"[:=]" + _ENCODED_SPACE + rb"*")
_ASSIGNMENT_NAME_START: Final = re.compile(rb"[A-Za-z]")


def _without_string_prefix(value: bytes) -> bytes:
    """Drop a string-literal prefix (``b``, ``r``, ``f``, ``rb``...) that opens a quoted value."""

    prefix = _STRING_PREFIX.match(value)
    return value if prefix is None else value[prefix.end() :]


def _value_quote(value: bytes) -> bytes:
    """The quote that opens ``value``: ``'``, ``"``, an escaped ``"`` of depth 1-3, or nothing."""

    quote = _VALUE_QUOTE.match(value)
    return b"" if quote is None else quote.group(0)


def _quoted_inner(value: bytes, quote: bytes) -> bytes:
    """``value`` without its opening ``quote`` and, when it closes with it, its closing one."""

    if value.endswith(quote) and len(value) >= 2 * len(quote):
        return value[len(quote) : -len(quote)]
    return value[len(quote) :]


def _assignment_separator(raw: bytes) -> re.Match[bytes] | None:
    """The ``:``/``=`` that separates an assignment match's name from its value.

    The match may begin with one boundary byte before the name, which can itself be ``:`` or
    ``=`` (a JSON member such as ``"c":"API_TOKEN=..."``). Searching from the name keeps that
    boundary from being read as the separator, which would turn the whole name into the value and
    defeat the exact-marker exemption.
    """

    name = _ASSIGNMENT_NAME_START.search(raw)
    return _ASSIGNMENT_SEPARATOR.search(raw, 0 if name is None else name.start())


@dataclass(slots=True)
class _JsonStringIndex:
    """Scan-local, lazy string spans and decodes shared by all marker occurrences."""

    data: bytes
    spans: tuple[tuple[int, int], ...] | None = None
    ends: tuple[int, ...] = ()
    decoded: dict[int, _DecodedJsonString | None] = field(
        default_factory=lambda: dict[int, _DecodedJsonString | None]()
    )

    def decode_at(self, offset: int) -> tuple[_JsonStringIndex, int] | None:
        if self.spans is None:
            self.spans = tuple(match.span() for match in _JSON_STRING_TOKEN.finditer(self.data))
            self.ends = tuple(end for _, end in self.spans)
        index = bisect.bisect_right(self.ends, offset)
        if index == len(self.spans) or self.spans[index][0] >= offset:
            return None
        start, end = self.spans[index]
        if index not in self.decoded:
            self.decoded[index] = _decode_json_string(self.data[start:end])
        decoded = self.decoded[index]
        if decoded is None:
            return None
        relative = offset - start
        escape_index = bisect.bisect_right(decoded.escape_ends, relative)
        if escape_index < len(decoded.escape_starts) and (
            decoded.escape_starts[escape_index] < relative
        ):
            return None
        return decoded.context, relative - 1 - decoded.shrink[escape_index]


@dataclass(frozen=True, slots=True)
class _DecodedJsonString:
    context: _JsonStringIndex
    escape_starts: tuple[int, ...]
    escape_ends: tuple[int, ...]
    shrink: tuple[int, ...]


def _decode_json_string(token: bytes) -> _DecodedJsonString | None:
    try:
        # Validate the complete string once, including UTF-8 and surrogate pairs, before any
        # occurrence can be exempted. The escape map replaces repeated growing-prefix decodes.
        data = json.loads(token).encode("utf-8")
        starts: list[int] = []
        ends: list[int] = []
        shrink = [0]
        for escape in _JSON_STRING_ESCAPE.finditer(token):
            raw = escape.group()
            size = 1
            if raw[1:2] == b"u":
                size = 4 if len(raw) == 12 else len(chr(int(raw[2:], 16)).encode("utf-8"))
            starts.append(escape.start())
            ends.append(escape.end())
            shrink.append(shrink[-1] + len(raw) - size)
        return _DecodedJsonString(_JsonStringIndex(data), tuple(starts), tuple(ends), tuple(shrink))
    except (ValueError, UnicodeError):
        return None


def _assignment_value_is_code(
    match: re.Match[bytes],
    *,
    preceding: bytes = b"",
    following: bytes = b"",
    json_strings: _JsonStringIndex | None = None,
    absolute_start: int | None = None,
    python_attribute_spans: tuple[tuple[int, int], ...] = (),
) -> bool:
    """Recognize source expressions only when the assignment syntax proves source context."""

    raw = match.group(0)
    separator = _assignment_separator(raw)
    if separator is None:
        return False
    value = _without_string_prefix(raw[separator.end() :])
    # These are FinishUP's own bounded replacement markers. They carry no secret bytes, so allowing
    # the scanner to classify a marker as a fresh assignment would make every structured redaction
    # fail its final scan. Only the exact markers are exempt; any suffix remains heuristic.
    quote = _value_quote(value)
    marker_value = _quoted_inner(value, quote) if quote else value
    encoded_context = (
        None
        if json_strings is None or absolute_start is None
        else (json_strings, absolute_start + raw.index(marker_value))
    )
    if _is_replacement_marker(marker_value, following=following, encoded_context=encoded_context):
        return True
    # Quoted values are literals even when their text resembles source code. Keep them in the
    # heuristic class so a value such as ``TOKEN='nextToken(parser)'`` is still withheld.
    if value.startswith((b"'", b'"')):
        return False
    # Unified diffs carry added/removed source lines as ``+token: ...``/``-token: ...``.
    # The marker is transport syntax, not part of the object property name; retain it in the
    # surrounding context check while removing it from the token-like-name test.  This narrow
    # normalization still leaves ``+TOKEN=opaque.value`` heuristic because only the explicit
    # source-expression branches below can return True.
    lhs = raw[: separator.start()].strip(b" \t\r\n'\"")
    lhs = lhs.lstrip(b"+-").strip()
    lhs_name = lhs.rsplit(b".", 1)[-1].strip()
    if _TOKEN_LIKE_ASSIGNMENT_NAME.fullmatch(lhs_name) is None:
        return False
    if absolute_start is not None:
        absolute_end = absolute_start + len(raw)
        for start, end in python_attribute_spans:
            if absolute_end > end or absolute_start > start:
                continue
            prefix = raw[: start - absolute_start]
            if not prefix.strip(b" \t\r\n"):
                return True
    source_context = (preceding[-512:] + raw[: separator.start()])[-1024:]
    declared = _SOURCE_DECLARATION.search(source_context) is not None
    if _CODE_LIKE_CALL_VALUE.fullmatch(value) is not None:
        # A declaration is the evidence that ``token = nextToken(parser)`` is source code. A
        # bare ``TOKEN=opaque.value`` or ``token=getToken()`` remains a heuristic match.
        return declared
    if _CODE_LIKE_ENUM_VALUE.fullmatch(value) is not None:
        # Member assignment (``parser.token = Token.EOF``) and an object property (``token:
        # Token.ConstKeyword``) carry their own source evidence. A bare equals assignment does
        # not, even if the RHS happens to look like an enum.
        return (
            lhs.startswith(b".")
            or declared
            or (separator.group(0).startswith(b":") and lhs_name == b"token")
        )
    return False


def _is_replacement_marker(
    value: bytes, *, following: bytes, encoded_context: tuple[_JsonStringIndex, int] | None
) -> bool:
    """Match only a fixed marker and its JSON framing, at the rendered encoding depth.

    At each encoding a newline's backslashes double, while the closing quote has one fewer
    backslash. Checking both counts keeps a literal backslash suffix (possibly secret content)
    distinct from encoded whitespace. The assignment match is already bounded to 512 bytes.
    """

    closing_slashes = len(value) - len(value.rstrip(b"\\"))
    width = closing_slashes + 1
    if closing_slashes and (following[:1] != b'"' or width & (width - 1)):
        return False
    for marker in _EXEMPT_REPLACEMENT_MARKERS:
        if not value.startswith(marker):
            continue
        suffix = value[len(marker) : len(value) - closing_slashes if closing_slashes else None]
        encoded_space = b"\\" * width
        while suffix.startswith(encoded_space) and suffix[width : width + 1] in (b"n", b"r", b"t"):
            suffix = suffix[width + 1 :]
        if not suffix and (not closing_slashes or _marker_has_json_framing(encoded_context, width)):
            return True
    return False


def _marker_has_json_framing(context: tuple[_JsonStringIndex, int] | None, width: int) -> bool:
    """Prove the nesting, rather than mistaking a literal escaped quote for JSON framing."""

    if context is None:
        return False
    strings, offset = context
    while width > 1:
        nested = strings.decode_at(offset)
        if nested is None:
            return False
        strings, offset = nested
        width //= 2
    return True


def _assignment_value_cannot_be_credential(match: re.Match[bytes], *, token_family: bool) -> bool:
    """Reject assignment matches whose value cannot be credential material (issue #982).

    The rules are deliberately narrow and value-shaped. Comparisons and walrus operators are not
    assignments; an unquoted value on the next line belongs to a nested key, not this one; source
    expressions, language literals, type names and documentation placeholders carry no secret.
    ``*token`` values additionally have to look like opaque token material of at least eight
    bytes. Password/secret/API-key values keep every other shape, including short ones and ones
    with punctuation, because human-chosen passwords legitimately take those forms.
    """

    raw = match.group(0)
    separator = _assignment_separator(raw)
    if separator is None:
        return False
    value = _without_string_prefix(raw[separator.end() :])
    if not value or value.startswith(b"="):
        # ``token == other``, ``token := next(it)``: a comparison or walrus, not an assignment.
        return True
    quote = _value_quote(value)
    if quote:
        quoted = True
        inner = _quoted_inner(value, quote)
    else:
        quoted = False
        # An unquoted value read from encoded text runs through escapes such as ``\n``; classify
        # only the part before the first escape. The match span itself is unchanged.
        escape = _ENCODED_ESCAPE.search(value)
        inner = value if escape is None else value[: escape.start()]
        if not inner:
            return True
        if (
            _LINE_BREAK_SEPARATOR.search(separator.group(0)) is not None
            and _NEXT_KEY_VALUE.fullmatch(inner) is not None
        ):
            # An empty ``OPENAI_API_KEY=`` followed by ``OPENAI_BASE_URL=`` on the next line, or
            # a YAML ``mask_secret:`` whose next line opens a nested ``anonymizer:`` mapping.
            return True
        if any(
            inner.startswith(marker) and inner != marker for marker in _EXEMPT_REPLACEMENT_MARKERS
        ):
            # ``TOKEN=[withheld-by-yoetz:possible-credential]realsecret``: a marker with a suffix
            # is not FinishUP's own replacement; the suffix may be secret material.
            return False
        code_shape = (
            _UNQUOTED_CODE_CHARS.search(inner) if token_family else _SECRET_CODE_SHAPE.search(inner)
        )
        if code_shape is not None:
            return True
        if inner in _NON_CREDENTIAL_WORDS or _RECEIVER_ATTRIBUTE_VALUE.fullmatch(inner):
            return True
        if token_family and _NUMERIC_VALUE.fullmatch(inner) is not None:
            return True
    if not token_family:
        # Opaque-material shapes are judged for ``*token`` values only. A password/secret/API-key
        # value is skipped only when it is an obvious documentation placeholder that carries no
        # digit: ``"<your-api-key>"``, ``"${MY_PASSWORD}"``, ``gw_...``. ``"<s3cr3tP4ss>"`` and
        # ``"Summer2024..."`` keep matching.
        return _SECRET_PLACEHOLDER_VALUE.fullmatch(inner) is not None
    if _PLACEHOLDER_VALUE.fullmatch(inner) is not None:
        return True
    if len(inner) < _MIN_TOKEN_VALUE_BYTES or _TOKEN_VALUE_CHARS.fullmatch(inner) is None:
        return True
    return not quoted and _DIGITLESS_IDENTIFIER_VALUE.fullmatch(inner) is not None


# A line break of the text, raw or JSON-encoded at any escaping depth (#1248, P-D3): ``\r\n``,
# ``\r``, ``\n``, or a backslash run before ``r`` or ``n`` (with ``\r\n`` as one break). Literal
# backslashes the run may start with stay part of the break: no value byte follows them.
_LINE_BREAK: Final = re.compile(rb"\r\n|\r|\n|\\{1,64}(?-i:r)(?:\\{1,64}(?-i:n))?|\\{1,64}(?-i:n)")
# The private key END line that closes a BEGIN line of ``label``.
_PRIVATE_KEY_END_PREFIX: Final = b"-" * 5 + b"END "


def _private_key_blocks(data: bytes) -> Iterator[tuple[int, int, bool]]:
    """Each private key block in ``data``: its BEGIN line's start, its END line's end, and whether
    it has one (#1248, P-D4).

    The block is searched in the whole of ``data``, never per scan chunk, so a key the 64 KiB scan
    window would split is still found whole. Without an END line of the same label within
    ``_MAX_PRIVATE_KEY_BLOCK_BYTES`` the block runs to the end of ``data`` and is unterminated.
    """

    offset = 0
    while (begin := _PRIVATE_KEY_BEGIN.search(data, offset)) is not None:
        end_line = _PRIVATE_KEY_END_PREFIX + begin.group("label") + b"-" * 5
        found = data.find(
            end_line, begin.end(), begin.start() + _MAX_PRIVATE_KEY_BLOCK_BYTES + len(end_line)
        )
        if found < 0:
            yield begin.start(), len(data), False
            return
        yield begin.start(), found + len(end_line), True
        offset = found + len(end_line)


def _unterminated_private_key(data: bytes, findings: tuple[ScanFinding, ...]) -> bool:
    """Whether a private key finding in ``data`` has no END line (P-D4: the item is withheld)."""

    for finding in findings:
        if finding.kind != "private_key_marker":
            continue
        begin = _PRIVATE_KEY_BEGIN.match(data, finding.start_offset)
        end_line = _PRIVATE_KEY_END_PREFIX + (b"" if begin is None else begin.group("label"))
        if not data[: finding.end_offset].endswith(end_line + b"-" * 5):
            return True
    return False


# YAML block values (#1248, P-D4): a credential-named key whose value is a block scalar
# (``password: |`` or ``>``, with optional chomping/indentation indicators) or is left empty for
# the lines below (``password:``), with the value on the following lines indented deeper than the
# key. Without this only the indicator was matched and the value lines went out as written. The
# key must open its line (after an optional diff ``+``/``-``/`` `` and indentation, a ``- ``
# sequence entry, or a quote), so ``if password:`` in source is not a key. Lines are found at raw
# and JSON-encoded line breaks alike.
_YAML_BLOCK_KEY: Final = re.compile(
    rb"(?i)(?:(?<![A-Za-z0-9_])|(?<=\\(?-i:[nrt])))"
    rb"(?P<name>(?:[A-Za-z][A-Za-z0-9]{0,63}[_-])*"
    rb"(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key|secret"
    rb"|token)"
    rb"(?:[_-][A-Za-z][A-Za-z0-9]{0,63})*)"
    rb"(?:\\{0,7}['\"])?[ \t]*:"
    rb"(?P<indicator>[ \t]*[|>](?:[1-9][+-]?|[+-][1-9]?)?)?"
    rb"(?:[ \t]+#[^\r\n\\]*)?[ \t]*"
    rb"(?=\r|\n|\\{1,64}(?-i:[nr]))"
)
# What may precede a YAML key on its line: a diff marker, indentation (raw or an encoded tab), a
# sequence entry dash, and the key's opening quote. A line starts after a raw or encoded line
# break, or after the quote that opens an encoded string.
_YAML_KEY_LINE_LEAD: Final = re.compile(
    rb"[+\- ]?(?:[ \t]|\\{1,64}(?-i:t))*(?:-[ \t]+)?(?:\\{0,7}['\"])?"
)
_YAML_INDENT: Final = re.compile(rb"(?:[ \t]|\\{1,64}(?-i:t))*")
# A first value line that opens a nested mapping (``nested:`` or ``nested: value``) or is a
# comment: then the key holds a mapping or nothing, not a value.
_YAML_NESTED_KEY: Final = re.compile(
    rb"(?:#|(?:\\{0,7}['\"])?[A-Za-z0-9_.-]+(?:\\{0,7}['\"])?[ \t]*:(?:[ \t]|\\|$))"
)
_YAML_KEY_LEAD_BYTES: Final = 256


def _yaml_indent(line: bytes) -> tuple[int, bytes]:
    """A line's indentation width, after one diff marker, and the text after it."""

    body = line[1:] if line[:1] in (b"+", b"-", b" ") else line
    indent = _YAML_INDENT.match(body)
    width = 0 if indent is None else indent.end()
    rest = body[width:]
    # An encoded tab counts as one column, like a raw one.
    columns = width - sum(len(run) for run in re.findall(rb"\\+(?=t)", body[:width]))
    return columns, rest


def _yaml_key_line_lead(data: bytes, name_start: int) -> bytes | None:
    """What precedes the key starting at ``name_start`` on its line, or ``None`` when that is more
    than a key's lead (the name does not open its line)."""

    window_start = max(0, name_start - _YAML_KEY_LEAD_BYTES)
    window = data[window_start:name_start]
    line_start = max(
        window.rfind(b"\n") + 1,
        window.rfind(b"\r") + 1,
        *(found + 2 for found in (window.rfind(b"\\n"), window.rfind(b"\\r")) if found >= 0),
    )
    if line_start == 0 and window_start > 0:
        return None
    lead = window[line_start:]
    if _YAML_KEY_LINE_LEAD.fullmatch(lead) is not None:
        return lead
    quote = window.rfind(b'"', line_start)
    if quote >= 0 and window[quote - 1 : quote] != b"\\":
        # The first line of an encoded string starts after its opening quote.
        lead = window[quote + 1 :]
        if _YAML_KEY_LINE_LEAD.fullmatch(lead) is not None:
            return lead
    return None


def _yaml_block_values(data: bytes) -> Iterator[tuple[int, int]]:
    """Each YAML block value under a credential-named key: from the key to the value's end.

    The span starts at the key's name, so a replacement keeps the name and separator and replaces
    the value lines whole (``_replace_sensitive_spans``). A block of FinishUP's own markers only
    (an already redacted value) is not a value.
    """

    offset = 0
    while (key := _YAML_BLOCK_KEY.search(data, offset)) is not None:
        offset = key.end()
        lead = _yaml_key_line_lead(data, key.start("name"))
        if lead is None:
            # Not a key opening its line; a shorter name may start later in this one
            # (``\\ndb_password:`` read from its ``n``).
            offset = key.start("name") + 1
            continue
        key_columns, _rest = _yaml_indent(lead)
        indicator = key.group("indicator") is not None
        cursor = key.end()
        value_end: int | None = None
        contents: list[bytes] = []
        while cursor < len(data):
            line_break = _LINE_BREAK.match(data, cursor)
            if line_break is None:
                break
            line_start = line_break.end()
            following = _LINE_BREAK.search(data, line_start)
            line_end = len(data) if following is None else following.start()
            columns, content = _yaml_indent(data[line_start:line_end])
            if content.strip(b" \t"):
                if columns > key_columns:
                    if not contents and not indicator and _YAML_NESTED_KEY.match(content):
                        break
                elif not (indicator and not contents and not _YAML_NESTED_KEY.match(content)):
                    break
                contents.append(content.strip(b" \t"))
                value_end = line_end
                if columns <= key_columns:
                    # A block indicator over a line that is not indented: that line was meant
                    # as the value. Only it is taken; the next line is not the block's.
                    break
            cursor = line_end
        if (
            value_end is None
            # One plain line under an empty key is the ordinary assignment heuristic's value
            # (``password:`` then ``  value``), judged by its value rules.
            or (not indicator and len(contents) == 1)
            or all(content in _EXEMPT_REPLACEMENT_MARKERS for content in contents)
        ):
            continue
        yield key.start("name"), value_end
        offset = value_end


def _line_breaks_of(region: bytes, *, encoded: bool = True) -> bytes:
    """The line breaks ``region`` holds, in order and nothing else; raw ones only unless
    ``encoded`` (inside a quoted literal a backslash-n is the value's own escape, not a line)."""

    return b"".join(
        match.group(0)
        for match in _LINE_BREAK.finditer(region)
        if encoded or match.group(0)[:1] != b"\\"
    )


def _scan_chunks(data: bytes) -> Iterator[tuple[int, bytes]]:
    if len(data) <= _SCAN_CHUNK_BYTES:
        yield 0, data
        return
    start = 0
    while start < len(data):
        end = min(len(data), start + _SCAN_CHUNK_BYTES)
        yield start, data[start:end]
        if end == len(data):
            break
        start = end - _SCAN_OVERLAP_BYTES


def scan_for_sensitive_content(
    data: bytes,
    *,
    canaries: tuple[bytes, ...] = (),
) -> tuple[ScanFinding, ...]:
    """Return bounded structural findings for known plaintext-sensitive patterns."""

    if type(data) is not bytes:
        raise TypeError("scan_data_not_bytes")
    if type(canaries) is not tuple or len(canaries) > _MAX_CANARIES:
        raise PrivacyFenceError("scanner_input_invalid", "sensitive_content_scan")
    if any(
        type(canary) is not bytes or not canary or len(canary) > _MAX_CANARY_BYTES
        for canary in canaries
    ):
        raise PrivacyFenceError("scanner_input_invalid", "sensitive_content_scan")

    findings: list[ScanFinding] = []
    seen: set[tuple[str, int, int]] = set()
    python_attribute_spans = _python_attribute_assignment_spans(data)
    json_strings = _JsonStringIndex(data)

    for canary in canaries:
        for chunk_start, chunk in _scan_chunks(data):
            offset = 0
            while len(findings) < _MAX_SCAN_FINDINGS:
                found = chunk.find(canary, offset)
                if found < 0:
                    break
                absolute = chunk_start + found
                _append_finding(
                    findings,
                    seen,
                    "canary",
                    absolute,
                    absolute + len(canary),
                    Sensitivity.SECRET,
                )
                offset = found + max(1, len(canary))

    # The whole key block, BEGIN through END, searched across scan chunks (#1248, P-D4).
    for block_start, block_end, _terminated in _private_key_blocks(data):
        if len(findings) >= _MAX_SCAN_FINDINGS:
            break
        _append_finding(
            findings,
            seen,
            "private_key_marker",
            block_start,
            block_end,
            Sensitivity.KEY_MATERIAL,
        )

    for pattern in (*_CREDENTIAL_PATTERNS, _URI_PASSWORD):
        for chunk_start, chunk in _scan_chunks(data):
            for match in pattern.finditer(chunk):
                _append_finding(
                    findings,
                    seen,
                    "credential_pattern",
                    chunk_start + match.start(),
                    chunk_start + match.end(),
                    Sensitivity.SECRET,
                    ScanConfidence.HIGH,
                )
                if len(findings) >= _MAX_SCAN_FINDINGS:
                    break

    for pattern in (_SECRET_ASSIGNMENT, _TOKEN_ASSIGNMENT):
        for chunk_start, chunk in _scan_chunks(data):
            for match in pattern.finditer(chunk):
                # ``parser.getToken()``, ``nextToken(parser)`` and ``Token.EOF`` are ordinary
                # source expressions. The assignment heuristic must not classify them as secret
                # material merely because the left side is named ``token`` or ``secret``.
                absolute_start = chunk_start + match.start()
                if _assignment_value_is_code(
                    match,
                    preceding=data[max(0, absolute_start - 1024) : absolute_start],
                    following=data[chunk_start + match.end() : chunk_start + match.end() + 1],
                    json_strings=json_strings,
                    absolute_start=absolute_start,
                    python_attribute_spans=python_attribute_spans,
                ) or _assignment_value_cannot_be_credential(
                    match, token_family=pattern is _TOKEN_ASSIGNMENT
                ):
                    continue
                _append_finding(
                    findings,
                    seen,
                    "credential_pattern",
                    chunk_start + match.start(),
                    chunk_start + match.end(),
                    Sensitivity.SECRET,
                    ScanConfidence.HEURISTIC,
                )
                if len(findings) >= _MAX_SCAN_FINDINGS:
                    break

    for chunk_start, chunk in _scan_chunks(data):
        for match in _ANNOTATED_ASSIGNMENT.finditer(chunk):
            if len(findings) >= _MAX_SCAN_FINDINGS:
                break
            name = match.group("name")
            assign = match.group("assign")
            # Judge the value exactly as the plain heuristic would judge ``name = value``.
            synthetic = b" " + name + b" " + assign
            token_family = _TOKEN_LIKE_ASSIGNMENT_NAME.fullmatch(name) is not None or (
                _SECRET_ASSIGNMENT.match(synthetic) is None
            )
            plain = (_TOKEN_ASSIGNMENT if token_family else _SECRET_ASSIGNMENT).match(synthetic)
            if plain is None or _assignment_value_cannot_be_credential(
                plain, token_family=token_family
            ):
                continue
            _append_finding(
                findings,
                seen,
                "credential_pattern",
                chunk_start + match.start("value"),
                chunk_start + match.end("value"),
                Sensitivity.SECRET,
                ScanConfidence.HEURISTIC,
            )

    # YAML block values span lines, so they are found in the whole of ``data`` (#1248, P-D4).
    for value_start, value_end in _yaml_block_values(data):
        if len(findings) >= _MAX_SCAN_FINDINGS:
            break
        _append_finding(
            findings,
            seen,
            "credential_pattern",
            value_start,
            value_end,
            Sensitivity.SECRET,
            ScanConfidence.HEURISTIC,
        )

    findings.sort(key=lambda finding: (finding.start_offset, finding.end_offset, finding.kind))
    return tuple(findings)


def assert_plaintext_safe(
    data: bytes,
    surface: str,
    *,
    canaries: tuple[bytes, ...] = (),
) -> None:
    """Fail closed when known sensitive content is present on a plaintext surface."""

    findings = scan_for_sensitive_content(data, canaries=canaries)
    if not findings:
        return
    first = findings[0]
    reason = {
        "canary": "plaintext_canary_detected",
        "credential_pattern": "credential_pattern_detected",
        "private_key_marker": "private_key_marker_detected",
    }[first.kind]
    raise PrivacyFenceError(reason, surface)


def _overlapping_finding_groups(
    findings: tuple[ScanFinding, ...],
) -> Iterator[tuple[ScanFinding, int, bool]]:
    """Group findings whose spans overlap; yield each group's lead, its end, and whether it is high.

    The lead is the earliest-starting, then longest, finding: its name and separator are kept.
    The group ends where its last member ends. A later finding that starts inside an earlier one
    but ends beyond it (a value cut short at a scan-chunk edge and found whole in the next chunk,
    or a token running past the 512-byte assignment bound) therefore joins that replacement, so no
    pass keeps the tail of a match, and none removes a byte outside the union of its matches.
    """

    ordered = sorted(findings, key=lambda finding: (finding.start_offset, -finding.end_offset))
    index = 0
    while index < len(ordered):
        lead = ordered[index]
        end = lead.end_offset
        high = lead.confidence is not ScanConfidence.HEURISTIC
        index += 1
        while index < len(ordered) and ordered[index].start_offset < end:
            end = max(end, ordered[index].end_offset)
            high = high or ordered[index].confidence is not ScanConfidence.HEURISTIC
            index += 1
        yield lead, end, high


def _replace_sensitive_spans(
    data: bytes,
    findings: tuple[ScanFinding, ...],
    *,
    marker: bytes = _PERSISTED_REDACTION_MARKER,
    heuristic_marker: bytes | None = None,
) -> bytes:
    """Replace each finding's span; a heuristic one with ``heuristic_marker`` when given.

    Only bytes inside a match are replaced: an assignment keeps its name, separator and quotes,
    and overlapping matches are replaced once, as their union. A heuristic span that overlaps a
    high-confidence finding (``TOKEN = 'ghp_...'``: the assignment and the token shape) holds a
    detected credential, so it keeps ``marker``. A replaced span that crosses lines (a private key
    block, a YAML block value) keeps every line break it held, raw or encoded, after its marker
    and nothing else of those lines (#1248, P-D4): the text keeps its line count, so a line read
    or a line number taken from the redacted text still names the same line.
    """

    if heuristic_marker is not None and heuristic_marker not in _EXEMPT_REPLACEMENT_MARKERS:
        # Only an exact exempt marker converges: any other text could re-match as an assignment.
        raise ValueError("redaction_marker_invalid")
    pieces: list[bytes] = []
    cursor = 0
    for lead, group_end, group_high in _overlapping_finding_groups(findings):
        span_marker = (
            heuristic_marker if heuristic_marker is not None and not group_high else marker
        )
        pieces.append(data[cursor : lead.start_offset])
        raw = data[lead.start_offset : lead.end_offset]
        # A key block holds base64 ``=`` and PEM ``Proc-Type:`` headers, never a label to keep.
        separator = None if lead.kind == "private_key_marker" else _assignment_separator(raw)
        prefix = b"" if separator is None else raw[: separator.start()].lower()
        if separator is not None and (
            lead.confidence is ScanConfidence.HEURISTIC
            or re.search(rb"(?:token|secret|password|passwd|api|key|auth)", prefix)
        ):
            value = data[lead.start_offset + separator.end() : group_end]
            literal_prefix = _STRING_PREFIX.match(value)
            string_prefix = b"" if literal_prefix is None else literal_prefix.group(0)
            value = value[len(string_prefix) :]
            opening_quote = _value_quote(value)
            closing_quote = (
                opening_quote
                if opening_quote
                and value.endswith(opening_quote)
                and len(value) >= 2 * len(opening_quote)
                else b""
            )
            inner = value[len(opening_quote) : len(value) - len(closing_quote)]
            pieces.append(
                raw[: separator.end()]
                + string_prefix
                + opening_quote
                + span_marker
                + _line_breaks_of(inner, encoded=not opening_quote)
                + closing_quote
            )
        else:
            pieces.append(span_marker + _line_breaks_of(data[lead.start_offset : group_end]))
        cursor = group_end
    pieces.append(data[cursor:])
    return b"".join(pieces)


@dataclass(frozen=True, slots=True)
class PersistenceScanResult:
    """Fail-closed scan outcome for bytes about to be encrypted at rest.

    ``persist`` is false when the payload must be withheld entirely. Matched
    secret bytes are never retained: redacted content substitutes ``[REDACTED]``,
    and withheld results carry empty content plus finding kinds only.
    """

    persist: bool
    content: bytes
    redacted: bool
    finding_kinds: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.persist) is not bool or type(self.redacted) is not bool:
            raise TypeError("persistence_scan_flag_invalid")
        if type(self.content) is not bytes:
            raise TypeError("persistence_scan_content_invalid")
        if type(self.finding_kinds) is not tuple:
            raise TypeError("persistence_scan_kinds_invalid")
        if any(
            type(kind) is not str
            or kind not in {"canary", "credential_pattern", "private_key_marker"}
            for kind in self.finding_kinds
        ):
            raise ValueError("persistence_scan_kind_invalid")
        if not self.persist and self.content:
            raise ValueError("persistence_scan_withheld_must_be_empty")


def _high_confidence_findings(findings: tuple[ScanFinding, ...]) -> tuple[ScanFinding, ...]:
    return tuple(finding for finding in findings if finding.confidence is ScanConfidence.HIGH)


def prepare_persisted_plaintext(
    data: bytes,
    *,
    canaries: tuple[bytes, ...] = (),
) -> PersistenceScanResult:
    """Classify bytes before encoding or encrypted persistence.

    High-confidence secret spans (known credential shapes, private-key markers, URI passwords)
    are redacted in memory. A canary match or scanner failure withholds the payload so original
    bytes never reach an object. Heuristic-only assignment matches are kept as captured (issue
    #982): they live only in the encrypted local store, local and deterministic checks may read
    them, and every egress path re-scans and replaces them before anything leaves the machine.
    ``redacted`` is true only when bytes were actually replaced.
    """

    if type(data) is not bytes:
        return PersistenceScanResult(False, b"", True, ())
    try:
        findings = scan_for_sensitive_content(data, canaries=canaries)
    except (PrivacyFenceError, TypeError, ValueError):
        return PersistenceScanResult(False, b"", True, ())
    high = _high_confidence_findings(findings)
    kinds = tuple(dict.fromkeys(finding.kind for finding in high))
    if any(finding.kind == "canary" for finding in high):
        return PersistenceScanResult(False, b"", True, kinds)
    # The public scanner deliberately caps structural findings. High-confidence detectors run
    # before the heuristics, so a cap reached by heuristic findings still leaves the complete
    # high-confidence set. A cap reached by high-confidence findings alone does not prove there
    # is no later match, so encrypted persistence withholds instead of redacting a prefix.
    if len(high) >= _MAX_SCAN_FINDINGS:
        return PersistenceScanResult(False, b"", True, kinds)
    # A private key BEGIN line without its END: no bound on the key body, so the item is withheld
    # (#1248, P-D4).
    if _unterminated_private_key(data, high):
        return PersistenceScanResult(False, b"", True, kinds)
    if not high:
        return PersistenceScanResult(True, data, False, ())
    redacted = _replace_sensitive_spans(data, high)
    return PersistenceScanResult(True, redacted, redacted != data, kinds)


def redact_sensitive_content(
    data: bytes, *, heuristic_marker: bytes | None = None
) -> tuple[bytes, bool]:
    """Replace every detected credential/key span without retaining the match.

    This includes heuristic-only assignment matches. It is for content that is about to be
    disclosed; capture and at-rest paths use ``redact_high_confidence_content``. Every span reads
    ``[REDACTED]`` unless ``heuristic_marker`` is given: then a heuristic-only span reads that
    marker instead, which must be one of FinishUP's exact replacement markers
    (``EGRESS_CREDENTIAL_PLACEHOLDER``) so a further pass never re-matches it. The check-time
    change uses it so a reviewer is told the value may be a credential FinishUP withheld (tb4n5),
    never left to read ``password=[REDACTED]`` as source code. A private key BEGIN line without
    its END withholds the whole text: the result is empty (#1248, P-D4).
    """

    findings = scan_for_sensitive_content(data)
    if not findings:
        return data, False
    if _unterminated_private_key(data, findings):
        return b"", True
    return _replace_sensitive_spans(data, findings, heuristic_marker=heuristic_marker), True


def redact_high_confidence_content(data: bytes) -> tuple[bytes, bool]:
    """Capture-time redaction: replace only high-confidence credential/key spans.

    Heuristic-only assignment matches stay as captured (issue #982); they are redacted at egress
    by ``redact_heuristic_spans`` and the final-body scan. The flag is true only when bytes were
    actually replaced. Callers that persist the result still pass it through
    ``prepare_persisted_plaintext``, which re-scans and withholds on canary or saturation. A
    private key is replaced from its BEGIN line through its END line; without an END line the
    whole text is withheld and the result is empty, flagged as redacted (#1248, P-D4).
    """

    if type(data) is not bytes:
        raise TypeError("redaction_data_not_bytes")
    high = _high_confidence_findings(scan_for_sensitive_content(data))
    if not high:
        return data, False
    if _unterminated_private_key(data, high):
        return b"", True
    redacted = _replace_sensitive_spans(data, high)
    return redacted, redacted != data


def redact_heuristic_spans(data: bytes) -> tuple[bytes, int]:
    """Replace only low-confidence assignment spans and return the bounded span count.

    Heuristic findings are never evidence that a byte is safe to disclose.  This helper is for
    sinks that have already established that the candidate contains no high-confidence finding:
    it preserves the surrounding item while ensuring the suspicious span cannot reach a local or
    external disclosure sink.  Only the value is replaced, by ``EGRESS_CREDENTIAL_PLACEHOLDER``,
    which tells the reader the value may be a credential and was withheld.  Callers still run the
    ordinary final-body scan afterwards.
    """

    if type(data) is not bytes:
        raise TypeError("redaction_data_not_bytes")
    findings = scan_for_sensitive_content(data)
    heuristic = tuple(
        finding for finding in findings if finding.confidence is ScanConfidence.HEURISTIC
    )
    if not heuristic:
        return data, 0
    return (
        _replace_sensitive_spans(data, heuristic, marker=EGRESS_CREDENTIAL_PLACEHOLDER),
        len(heuristic),
    )


def redact_encoded_heuristic_spans(
    content: bytes,
    *,
    redact: Callable[[bytes], tuple[bytes, int]] = redact_heuristic_spans,
) -> tuple[bytes, int] | None:
    """Replace heuristic values as they appear in the item's JSON-string encoding.

    The raw-text pass cannot see an assignment that only exists in the encoded form (for example
    ``token = \\"...\\"`` inside an embedded JSON document). This pass redacts on the exact
    encoding the review packet carries, decodes the result back to the item's text, and returns
    it only when both forms then scan clean. ``None`` means the caller must withhold the whole
    item. ``redact`` is the value pass the caller applies to raw text, so both passes agree. No
    scanned bytes are retained.
    """

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None
    encoded = canonical_encode(text)
    sanitized_encoded, span_count = redact(encoded)
    if span_count == 0:
        return None
    try:
        decoded = strict_json_parse(sanitized_encoded)
    except (TypeError, ValueError, UnicodeDecodeError):
        return None
    if type(decoded) is not str:
        return None
    sanitized = decoded.encode("utf-8")
    if any(scan_for_sensitive_content(form) for form in (sanitized, canonical_encode(decoded))):
        return None
    return sanitized, span_count


def semantic_egress_forms(content: bytes) -> tuple[bytes, ...]:
    """Every text the semantic-review minimizer can carry for one item's ``content`` (#1230).

    Egress minimization may send an item as written (no finding, or the owner turned the
    credential heuristic off), with its credential-like values replaced
    (``redact_heuristic_spans``), or with the values replaced in its JSON-string encoding
    (``redact_encoded_heuristic_spans``, on either of the first two). A replacement is the fixed
    ``EGRESS_CREDENTIAL_PLACEHOLDER``, which is longer than a short value, so an item can grow
    between composition and disclosure. The forms are distinct and in that order; the first is
    always ``content``. Nothing is retained.
    """

    if type(content) is not bytes:
        raise TypeError("redaction_data_not_bytes")
    forms: dict[bytes, None] = {content: None}
    replaced, span_count = redact_heuristic_spans(content)
    if span_count:
        forms[replaced] = None
    for base in tuple(forms):
        encoded = redact_encoded_heuristic_spans(base)
        if encoded is not None:
            forms[encoded[0]] = None
    return tuple(forms)


_MAX_CUT_REDACTION_PASSES: Final = 8


def redact_before_cut(content: bytes) -> bytes | None:
    """``content`` with every detected credential-like value replaced, for a cut to follow (#1230).

    A cut can keep a value and drop the label that made it detectable (``password = "..."``
    cut after ``= ``), and a scanner reading the cut text no longer sees it. So the whole text
    is redacted first, as egress would disclose it, and only then cut: concrete shapes read
    ``[REDACTED]``, values that only look like credentials read the egress placeholder, in the
    text and in its JSON-string encoding, pass after pass until a pass finds nothing (bounded;
    the egress scan still checks whatever is sent). Content without a finding is returned
    unchanged, so a clean cut stays placeable in its source. ``None`` when the pass bound is
    reached while a pass still finds a value (each scan reports a bounded number of findings):
    the text cannot be redacted in full, so no cut may be taken from it (fail closed, as capture's
    ``redaction_incomplete``). Nothing is retained.
    """

    if type(content) is not bytes:
        raise TypeError("redaction_data_not_bytes")
    return redact_fully(content, max_passes=_MAX_CUT_REDACTION_PASSES)


def redact_fully(content: bytes, *, max_passes: int = _MAX_CUT_REDACTION_PASSES) -> bytes | None:
    """``content`` redacted raw and in its JSON-string encoding until a pass finds nothing.

    The one redaction every slice is cut from (#1248, P-D4): case composition's cuts, the
    reviewer's line and offset reads, and the check-time change before its #983 parts. Concrete
    shapes read ``[REDACTED]``, values that only look like credentials read the egress
    placeholder, and every line break is kept, so line numbers still hold. ``None`` when the
    text cannot be redacted in full: the pass bound is reached, or a private key has no END line.
    Nothing is retained.
    """

    if type(content) is not bytes:
        raise TypeError("redaction_data_not_bytes")
    text = content
    for _pass in range(max_passes):
        findings = scan_for_sensitive_content(text)
        if findings:
            if _unterminated_private_key(text, findings):
                return None
            text = _replace_sensitive_spans(
                text, findings, heuristic_marker=EGRESS_CREDENTIAL_PLACEHOLDER
            )
            continue
        encoded = redact_encoded_heuristic_spans(text)
        if encoded is None:
            return text
        text = encoded[0]
    return None


# Bounded memo of ``semantic_egress_forms`` sizes, keyed by the content's SHA-256 digest so no
# content is retained: composition, ceiling planning and their rebuilds measure the same excerpt
# text many times, and each measure costs two scans.
_DISCLOSED_SIZE_CACHE: Final[OrderedDict[str, tuple[int, bool]]] = OrderedDict()
_DISCLOSED_SIZE_CACHE_LOCK: Final = threading.Lock()
_DISCLOSED_SIZE_CACHE_ENTRIES: Final = 4_096


def _semantic_disclosed_size(content: bytes) -> tuple[int, bool]:
    if type(content) is not bytes:
        raise TypeError("redaction_data_not_bytes")
    key = hashlib.sha256(content).hexdigest()
    with _DISCLOSED_SIZE_CACHE_LOCK:
        cached = _DISCLOSED_SIZE_CACHE.get(key)
        if cached is not None:
            _DISCLOSED_SIZE_CACHE.move_to_end(key)
            return cached
    forms = semantic_egress_forms(content)
    measured = (max(len(form) for form in forms), len(forms) > 1)
    with _DISCLOSED_SIZE_CACHE_LOCK:
        _DISCLOSED_SIZE_CACHE[key] = measured
        _DISCLOSED_SIZE_CACHE.move_to_end(key)
        while len(_DISCLOSED_SIZE_CACHE) > _DISCLOSED_SIZE_CACHE_ENTRIES:
            _DISCLOSED_SIZE_CACHE.popitem(last=False)
    return measured


def semantic_disclosed_bytes(content: bytes) -> int:
    """The most UTF-8 bytes one review item's ``content`` can occupy once disclosed (#1230).

    This is the one measure composition and disclosure share: egress reads an excerpt's size as
    the ``content_bytes`` of its minimized row, which is the length of one of
    ``semantic_egress_forms(content)``; this is the largest of them. Content without a
    credential-like value measures exactly ``len(content)``.
    """

    return _semantic_disclosed_size(content)[0]


def semantic_egress_transforms(content: bytes) -> bool:
    """Whether egress minimization may carry ``content`` in a form other than as written."""

    return _semantic_disclosed_size(content)[1]


def _json_string_newline_offsets(data: bytes) -> list[int]:
    """Offsets of the ``\\n`` escapes in one canonical JSON string encoding, in order."""

    offsets: list[int] = []
    index = 0
    length = len(data)
    while index < length:
        if data[index] == 0x5C and index + 1 < length:
            escape = data[index + 1]
            if escape == 0x6E:
                offsets.append(index)
            index += 6 if escape == 0x75 else 2
            continue
        index += 1
    return offsets


def heuristic_value_lines(
    data: bytes, *, json_string: bool = False, limit: int = 32
) -> tuple[int, ...]:
    """1-based lines of the values ``redact_heuristic_spans`` replaces in ``data`` (PL2-1).

    ``json_string=True`` reads ``data`` as the canonical JSON string encoding of a text and
    reports lines of that decoded text. Replacement never removes a line break (a value that
    spans lines, a YAML block value, keeps its breaks), so the lines also hold for the original
    item text. Only sorted unique line
    numbers are returned, at most ``limit``; no matched bytes or offsets are retained.
    """

    if type(data) is not bytes:
        raise TypeError("redaction_data_not_bytes")
    heuristic = tuple(
        finding
        for finding in scan_for_sensitive_content(data)
        if finding.confidence is ScanConfidence.HEURISTIC
    )
    if not heuristic:
        return ()
    newline_offsets = _json_string_newline_offsets(data) if json_string else None

    def line_of(offset: int) -> int:
        if newline_offsets is None:
            return data.count(b"\n", 0, offset) + 1
        return bisect.bisect_left(newline_offsets, offset) + 1

    lines: set[int] = set()
    # Grouped as ``_replace_sensitive_spans`` groups them: a YAML block value overlaps the plain
    # match of its first line, and the replacement covers every line the group runs over.
    for lead, group_end, _high in _overlapping_finding_groups(heuristic):
        separator = _assignment_separator(data[lead.start_offset : lead.end_offset])
        value_start = lead.start_offset + (0 if separator is None else separator.end())
        lines.update(range(line_of(value_start), line_of(max(value_start, group_end - 1)) + 1))
    return tuple(sorted(lines))[: max(0, limit)]


def _safe_mac(handle: MacKeyHandle, domain: bytes, message: bytes) -> str:
    if isinstance(handle, bytes | bytearray | memoryview):
        raise TypeError("raw_mac_key_forbidden")
    try:
        result = handle.mac(domain, message)
    except AttributeError as exc:
        raise TypeError("mac_handle_required") from exc
    return validate_commitment(result)


def session_id_hash(session_id: str, log_mac: MacKeyHandle) -> str:
    """Return an installation-local opaque session correlation label."""

    validated = validate_id(IdKind.SESSION, session_id)
    return _safe_mac(log_mac, SESSION_HASH_DOMAIN, validated.encode("ascii"))


def privacy_request_commitment(final_request_body: bytes, audit_mac: MacKeyHandle) -> str:
    """Commit to the exact final provider/application body before transport metadata."""

    if type(final_request_body) is not bytes:
        raise TypeError("request_body_not_bytes")
    return _safe_mac(audit_mac, PRIVACY_REQUEST_BODY_DOMAIN, final_request_body)


def _bounded_token(value: object, pattern: re.Pattern[str]) -> str:
    if (
        type(value) is not str
        or len(value.encode("utf-8")) > _MAX_STRUCTURAL_TEXT_BYTES
        or pattern.fullmatch(value) is None
    ):
        return "unavailable"
    return value


def redact_diagnostic_value(name: str, value: object) -> JsonValue:
    """Convert one known structural diagnostic field without generic stringification."""

    if type(name) is not str or name in _ALWAYS_OMITTED or name not in _KNOWN_FIELDS:
        return None
    try:
        if name == "timestamp":
            if type(value) is not str:
                return "unavailable"
            parse_rfc3339_millis(value)
            return value
        if name == "request_id":
            return validate_id(IdKind.REQUEST, value)
        if name == "correlation_id":
            return validate_id(IdKind.CORRELATION, value)
        if name in {"session_id_hash", "sqlite_source_id_hash"}:
            return value if type(value) is str and _HASH.fullmatch(value) else "unavailable"
        if name == "origin":
            return value if type(value) is str and _ORIGIN.fullmatch(value) else "unavailable"
        if name in _TOKEN_FIELDS:
            return _bounded_token(value, _TOKEN)
        if name in _VERSION_FIELDS:
            return _bounded_token(value, _VERSION)
        if name in _INTEGER_FIELDS:
            return (
                value if type(value) is int and 0 <= value <= _MAX_SAFE_INTEGER else "unavailable"
            )
        if name in _BOOLEAN_FIELDS:
            return value if type(value) is bool else "unavailable"
    except BaseException:
        return "unavailable"
    return None


def redact_diagnostic_record(record: Mapping[str, object]) -> dict[str, JsonValue]:
    """Drop unknown fields and retain only bounded structural diagnostic values."""

    global _omitted_field_count
    output: dict[str, JsonValue] = {}
    try:
        keys = tuple(record.keys())
    except BaseException:
        return output
    for key in keys:
        if type(key) is not str or key not in _KNOWN_FIELDS or key in _ALWAYS_OMITTED:
            _omitted_field_count += 1
            continue
        try:
            output[key] = redact_diagnostic_value(key, record[key])
        except BaseException:
            output[key] = "unavailable"
    return output


def build_diagnostic_manifest(
    profile: DiagnosticRedactionProfile,
    structural_inputs: Mapping[str, object],
) -> dict[str, JsonValue]:
    """Build the sole bounded plaintext diagnostic-manifest shape."""

    if type(profile) is not DiagnosticRedactionProfile:
        raise TypeError("diagnostic_profile_invalid")
    redacted = redact_diagnostic_record(structural_inputs)
    if profile is DiagnosticRedactionProfile.MINIMAL:
        redacted.pop("session_id_hash", None)
        redacted.pop("capability_probe_id", None)
    elif profile is DiagnosticRedactionProfile.SUPPORT:
        redacted.pop("capability_probe_id", None)
    else:
        redacted.pop("session_id_hash", None)
    redacted["schema_version"] = "yoetz-diagnostic-manifest/1"
    redacted["redaction_profile"] = profile.value
    assert_plaintext_safe(canonical_encode(redacted), "diagnostic_manifest")
    return redacted
