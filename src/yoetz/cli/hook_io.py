"""Leaf hook IO helpers: stdin payload, stdout JSON, stderr line, context output.

Deliberately imports no Yoetz modules beyond ``yoetz.protocol``. ``yoetz.cli.hooks``
re-exports these names unchanged; the split exists so a hook process does not
pay for ``service.client`` → ``control_protocol`` → ``protocol.schemas`` →
jsonschema just to write one JSON object to stdout (#242).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import BinaryIO, Final, cast

from yoetz.domain.bounded_text import clip_to_limit
from yoetz.protocol.canonical import (
    MAX_JSON_DEPTH,
    JsonValue,
    canonical_encode,
    ensure_canonical_value,
    strict_json_parse,
)
from yoetz.protocol.errors import ProtocolValueError

__all__ = [
    "ADDITIONAL_CONTEXT_EVENTS",
    "CLAUDE_ADDITIONAL_CONTEXT_EVENTS",
    "MAX_HOOK_SKIM_BYTES",
    "MAX_HOOK_STDIN_BYTES",
    "MAX_OBSERVED_IMAGES",
    "OBSERVED_IMAGES_KEY",
    "OBSERVED_IMAGE_MEDIA_TYPES",
    "STOP_CONTROL_EVENTS",
    "CursorOversizedPayloadError",
    "OversizedHookPayloadError",
    "claude_context_output",
    "claude_permission_denied_output",
    "context_output",
    "image_header_facts",
    "observed_image_facts",
    "cursor_context_output",
    "read_cursor_hook_ingress",
    "read_cursor_hook_payload",
    "read_hook_ingress",
    "read_hook_payload",
    "stderr_line",
    "strip_hook_media",
    "stdout_json",
]

# The one hook ingress bound, shared by every host reader here and by
# ``yoetz.cli.hooks``. A second copy of this number drifted from this one
# silently, and both sides must move together for the documented 1 MiB cap to
# stay a single fact (issue #667). It was 256 KiB until tb4n1 (B5): Yoetz's own
# ``closure_prepare`` replies (300 KB-1 MB), image views, and large command
# outputs outgrew it, so their PostToolUse rows were lost and the matching
# pre-events were left unpaired. Captured content stays separately bounded by
# the content budget in ``observe_hooks``; a large output is truncated content,
# not a dropped event.
MAX_HOOK_STDIN_BYTES: Final = 1_048_576
# Complete-document skim for one hook body that outgrew the trusted parse, on
# every host. A larger body is refused unread; a complete body inside this cap is
# parsed with the same safety rules, its image bytes are dropped, and it is kept
# whole when that brings it under the trusted cap. Otherwise it is reduced to a
# closed structural identity with no content.
MAX_HOOK_SKIM_BYTES: Final = 8_388_608
# An inline media string shorter than this is not worth replacing (a tiny icon
# keeps its bytes; it can never move an event across the ingress cap).
_MIN_MEDIA_STRING_CHARS: Final = 256
_MEDIA_BLOCK_TYPES: Final = frozenset(
    {"image", "input_image", "output_image", "image_url", "audio", "input_audio"}
)
_MEDIA_MIME_KEYS: Final = ("mimeType", "mime_type", "media_type", "mediaType")
_MEDIA_MIME_PREFIXES: Final = ("image/", "audio/", "video/")
_MEDIA_PLACEHOLDER: Final = "[media bytes omitted by Yoetz]"
# Parse cost of the skim grows with the number of JSON containers and elements, not
# with bytes: an 8 MiB body of ``[{},{},...]`` took 12.6 s and 418 MB to skim, while a
# real ``closure_prepare`` reply carries about 30 structural tokens per KB (tb4n1: at
# most 30,228 in a 1 MB reply) and a base64 image almost none. A body whose
# ``{``, ``[`` and ``,`` count outside strings exceeds this budget is refused before
# the parse as ``payload_too_large``; the count itself is two C-speed passes.
_MAX_SKIM_STRUCTURE_TOKENS: Final = 262_144
# An unterminated string consumes to the end of input, so a malformed body cannot make
# the match restart at every quote (quadratic time; found in review of #999).
_JSON_STRING_TOKEN: Final = re.compile(rb'"[^"\\]*(?:\\.[^"\\]*)*(?:"|\\?\Z)')
# Yoetz's own cap on the advice text a hook hands a host. It is NOT a documented host limit
# (tb4n3 RC-2: no host document available to this repository states one for Codex, Claude Code or
# Cursor), it is the conservative bound every renderer and the Stop gate compose against. Text
# over it used to be cut mid-word with nothing to say so; it now ends with a visible marker.
_MAX_CONTEXT_CHARS: Final = 2_000
_CONTEXT_CUT_MARKER: Final = " [Yoetz text cut at 2000 characters; read status or the receipt]"


def _bounded_context(text: str) -> str:
    """Bound hook advice text; a cut ends with a marker so the agent can tell it is partial."""

    return clip_to_limit(text, _MAX_CONTEXT_CHARS, marker=_CONTEXT_CUT_MARKER, ascii_only=False)


_MAX_CURSOR_IDENTITY_STRING_BYTES: Final = 8_192
_MAX_CURSOR_IDENTITY_DEPTH: Final = 6
_MAX_CURSOR_IDENTITY_ITEMS: Final = 32
_CURSOR_IDENTITY_STRINGS: Final = frozenset(
    {
        "action",
        "claim_kind",
        "conversation_id",
        "cursor_version",
        "decision",
        "failure_type",
        "filePath",
        "file_path",
        "generation_id",
        "hook_event_name",
        "id",
        "mapping_hint",
        "model",
        "model_id",
        "outcome",
        "path",
        "permission_decision",
        "permission_kind",
        "result_status",
        "session_id",
        "source",
        "status",
        "target_file",
        "tool_call_id",
        "tool_name",
        "tool_use_id",
        "value",
    }
)
_CURSOR_IDENTITY_BOOLS: Final = frozenset(
    {
        "canceled",
        "cancelled",
        "denied",
        "failed",
        "interrupted",
        "isCanceled",
        "isError",
        "isInterrupted",
        "is_cancelled",
        "is_denied",
        "is_error",
        "is_interrupt",
        "is_interrupted",
        "ok",
        "permission_denied",
        "success",
    }
)
_CURSOR_IDENTITY_INTS: Final = frozenset(
    {
        "duration",
        "exitCode",
        "exitStatus",
        "exit_code",
        "exit_status",
    }
)
_CURSOR_IDENTITY_OBJECTS: Final = frozenset(
    {
        "data",
        "result",
        "result_json",
        "structuredContent",
        "structured_content",
        "tool_input",
        "tool_output",
        "tool_response",
    }
)
# Codex and Claude Code name their session, lineage, and outcome fields with
# keys Cursor does not use. Every addition is an identifier, a locator, or a
# closed flag the full-size path already reads; command text, prompts, file
# bodies, and tool results stay out.
_HOOK_IDENTITY_STRINGS: Final = _CURSOR_IDENTITY_STRINGS | frozenset(
    {
        "agent_id",
        "agent_thread_id",
        "agent_transcript_path",
        "agent_type",
        "claude_code_version",
        "cwd",
        "mcp_server_name",
        "parent_tool_call_id",
        "permission_mode",
        "session_file",
        "subagent_id",
        "transcript_path",
        "turn_id",
    }
)
_HOOK_IDENTITY_BOOLS: Final = _CURSOR_IDENTITY_BOOLS | frozenset(
    {"isImage", "run_in_background", "stop_hook_active"}
)
_HOOK_IDENTITY_INTS: Final = _CURSOR_IDENTITY_INTS | frozenset({"duration_ms"})


@dataclass(frozen=True, slots=True)
class _IdentityAllowlist:
    """The closed key sets one host's oversized-body identity view may keep."""

    strings: frozenset[str]
    bools: frozenset[str]
    ints: frozenset[str]
    objects: frozenset[str]


_CURSOR_IDENTITY: Final = _IdentityAllowlist(
    _CURSOR_IDENTITY_STRINGS,
    _CURSOR_IDENTITY_BOOLS,
    _CURSOR_IDENTITY_INTS,
    _CURSOR_IDENTITY_OBJECTS,
)
_HOOK_IDENTITY: Final = _IdentityAllowlist(
    _HOOK_IDENTITY_STRINGS,
    _HOOK_IDENTITY_BOOLS,
    _HOOK_IDENTITY_INTS,
    _CURSOR_IDENTITY_OBJECTS,
)
_MAX_STDERR_CHARS: Final = 200
_MAX_SAFE_INTEGER: Final = 2**53 - 1
# Codex events whose output schema admits hookSpecificOutput.additionalContext.
ADDITIONAL_CONTEXT_EVENTS: Final = frozenset(
    {
        "PostToolUse",
        "PreToolUse",
        "SessionStart",
        "SubagentStart",
        "UserPromptSubmit",
    }
)
# Codex Stop / SubagentStop admit only the common output fields plus
# decision/reason. The current hooks reference (learn.chatgpt.com/docs/hooks,
# re-read 2026-08-28 for #420) still lists no hookSpecificOutput for either
# event, and a build that received one marked the hook Failed with "invalid
# stop hook JSON output" (#222). Per that reference, `decision: block` does not
# reject the turn: Codex continues with `reason` as a new continuation prompt,
# so `stop_hook_active` plus delivery identity remain the loop guard.
STOP_CONTROL_EVENTS: Final = frozenset({"Stop", "SubagentStop"})
# Claude Code events whose output schema admits hookSpecificOutput.additionalContext.
# Unlike Codex, Claude Code documents Stop / SubagentStop `additionalContext` as
# non-error feedback (code.claude.com/docs/en/hooks, re-read 2026-08-28): the
# conversation continues so the model can act on it, but it is shown as hook
# feedback rather than the `decision: block` hook error.
CLAUDE_ADDITIONAL_CONTEXT_EVENTS: Final = frozenset(
    {
        "PostToolUse",
        "PostToolUseFailure",
        "PreToolUse",
        "SessionStart",
        "Stop",
        "SubagentStart",
        "SubagentStop",
        "UserPromptSubmit",
    }
)


def stderr_line(message: str) -> None:
    text = message.replace("\n", " ").replace("\r", " ")[:_MAX_STDERR_CHARS]
    try:
        sys.stderr.write(text + "\n")
        sys.stderr.flush()
    except OSError:
        pass


def stdout_json(value: JsonValue, stream: BinaryIO | None = None) -> bool:
    out = sys.stdout.buffer if stream is None else stream
    try:
        out.write(canonical_encode(value) + b"\n")
        out.flush()
        return True
    except BrokenPipeError, OSError, ValueError:
        return False


def context_output(event_name: str, additional_context: str) -> dict[str, JsonValue]:
    """Return the Codex-valid stdout object for one event's advice text.

    SessionStart / PostToolUse / UserPromptSubmit inject model-visible
    ``additionalContext``. Stop / SubagentStop have no such field: the only
    way to reach the model is ``decision: block`` plus ``reason``. Every other
    event, including SessionEnd (stdout discarded), emits ``{}``.
    """

    text = additional_context.strip()
    if not text:
        return {}
    text = _bounded_context(text)
    if event_name in STOP_CONTROL_EVENTS:
        return {"decision": "block", "reason": text}
    if event_name in ADDITIONAL_CONTEXT_EVENTS:
        return {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "additionalContext": text,
            }
        }
    return {}


def claude_context_output(event_name: str, additional_context: str) -> dict[str, JsonValue]:
    """Return the Claude Code-valid stdout object for one event's advice text.

    Every supported advice-bearing event, including Stop / SubagentStop, injects
    ``hookSpecificOutput.additionalContext``. At Stop / SubagentStop that is
    Claude Code's documented non-error feedback channel: it continues through
    the same loop protections as ``decision: block`` but is labelled as feedback
    instead of an error. SessionEnd and every undocumented event emit ``{}``.
    """

    text = additional_context.strip()
    if not text:
        return {}
    text = _bounded_context(text)
    if event_name in CLAUDE_ADDITIONAL_CONTEXT_EVENTS:
        return {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "additionalContext": text,
            }
        }
    return {}


def claude_permission_denied_output(system_message: str, *, retry: bool) -> dict[str, JsonValue]:
    """Render only fields supported by Claude's PermissionDenied event.

    The user sees systemMessage; the model receives the host's retry cue only. Unlike
    several other hook events, PermissionDenied does not accept additionalContext
    (Claude Code 2.1.281 schema and docs checked 2026-09-26).
    """

    shown = _bounded_context(system_message.strip())
    if not shown:
        return {}
    return {
        "hookSpecificOutput": {"hookEventName": "PermissionDenied", "retry": retry},
        "systemMessage": shown,
    }


def cursor_context_output(
    raw_event: str,
    text: str,
    *,
    allow_stop_followup: bool = False,
) -> dict[str, JsonValue]:
    """Return the Cursor-native stdout object for one raw hook event.

    Cursor's output contract is independent from the Codex hook contract:
    ``sessionStart`` and successful ``postToolUse`` accept
    ``additional_context``, while ``stop`` can optionally submit a
    ``followup_message``.  Stop follow-ups are disabled by default because
    Cursor treats them as a new user message.  ``postToolUseFailure`` and the
    other advice-less Cursor events emit ``{}``. Passive ``preToolUse``
    observation returns ``permission: allow`` to avoid an invalid permission
    response; native MCP admission remains separate.
    """

    # A passive pre-tool observer must explicitly pass the hook's permission
    # boundary. Cursor rejects an empty/invalid permission response. Native
    # MCP admission remains a separate beforeMCPExecution/host decision.
    if raw_event == "preToolUse":
        return {"permission": "allow"}
    bounded = text.strip()
    if not bounded:
        return {}
    bounded = _bounded_context(bounded)
    if raw_event in {"sessionStart", "postToolUse"}:
        return {"additional_context": bounded}
    if raw_event == "stop" and allow_stop_followup:
        return {"followup_message": bounded}
    return {}


def read_hook_payload(raw: bytes | None = None) -> Mapping[str, JsonValue]:
    """Read a bounded Codex hook JSON object from stdin (or supplied bytes)."""

    data = sys.stdin.buffer.read(MAX_HOOK_STDIN_BYTES + 1) if raw is None else raw
    # Size is decided before the body is inspected, so an oversized event and an
    # empty or malformed one shared one reason and the caller could not tell an
    # ordinary edit that outgrew the cap from a host that sent nothing (#667).
    # Only cap-plus-one bytes are ever read, so the exact size stays unknown by
    # construction: the bound itself is the whole fact.
    if len(data) > MAX_HOOK_STDIN_BYTES:
        raise ProtocolValueError("payload_too_large")
    if not data:
        raise ProtocolValueError("invalid_event_value_type")
    parsed = strict_json_parse(data)
    if not isinstance(parsed, Mapping):
        raise ProtocolValueError("unsupported_json_type")
    return cast(Mapping[str, JsonValue], parsed)


def _parse_cursor_integer(literal: str) -> int:
    """Parse a Cursor host integer with the same safe bound as canonical JSON."""

    if literal == "-0":
        raise ProtocolValueError("float_forbidden")
    try:
        value = int(literal)
    except ValueError as exc:
        raise ProtocolValueError("integer_out_of_safe_range") from exc
    if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
        raise ProtocolValueError("integer_out_of_safe_range")
    return value


def _reject_cursor_constant(_: str) -> object:
    raise ProtocolValueError("float_forbidden")


def _normalize_cursor_duration(value: Decimal) -> int:
    """Truncate one finite, nonnegative Cursor duration to canonical milliseconds."""

    if not value.is_finite() or value < 0 or (value.is_zero() and value.is_signed()):
        raise ProtocolValueError("invalid_duration")
    if value > _MAX_SAFE_INTEGER:
        raise ProtocolValueError("integer_out_of_safe_range")
    return int(value)


def _normalize_cursor_value(value: object, *, key: str | None, depth: int) -> JsonValue:
    """Convert Cursor floats without admitting them to the canonical payload.

    The host may place ordinary decimal numbers in discarded vendor fields such
    as tool metadata. Those values remain transient and are replaced with
    ``null``; only the top-level duration is retained after normalization.
    """

    if isinstance(value, Decimal):
        if key == "duration" and depth == 1:
            return _normalize_cursor_duration(value)
        if depth == 0:
            raise ProtocolValueError("float_forbidden")
        return None
    if value is None or type(value) in {bool, int, str}:
        return cast(JsonValue, value)
    if type(value) is list:
        if depth >= MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        return [
            _normalize_cursor_value(item, key=None, depth=depth + 1)
            for item in cast(list[object], value)
        ]
    if type(value) is dict:
        if depth >= MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        normalized: dict[str, JsonValue] = {}
        for child_key, item in cast(dict[object, object], value).items():
            if type(child_key) is not str:
                raise ProtocolValueError("object_key_not_string")
            normalized[child_key] = _normalize_cursor_value(
                item,
                key=child_key,
                depth=depth + 1,
            )
        return normalized
    raise ProtocolValueError("unsupported_json_type")


class CursorOversizedPayloadError(Exception):
    """A Cursor body above the trusted cap was not reduced to a structural identity.

    ``payload_too_large`` is reserved for the pure cap refusal. This error is the
    skim path: the complete body fit the skim cap, and a safety check refused it.
    The reason is the same protocol code the full parser would have raised.
    """

    def __init__(self, reason_code: str) -> None:
        if type(reason_code) is not str or not reason_code:
            raise ValueError("unregistered_protocol_reason_code")
        self.reason_code = reason_code
        super().__init__(reason_code)


class _IdentityDrop:
    """Marker for a host value the identity view must not retain."""


_IDENTITY_DROP: Final = _IdentityDrop()


def _read_cursor_bytes(raw: bytes | None, limit: int) -> bytes:
    data = sys.stdin.buffer.read(limit) if raw is None else raw
    if type(data) is bytearray:
        data = bytes(data)
    elif type(data) is not bytes:
        raise ProtocolValueError("input_not_bytes")
    return data


def _parse_cursor_hook_document(data: bytes) -> Mapping[str, JsonValue]:
    """Parse one complete Cursor hook body with the vendor-decimal rules.

    Callers decide the byte cap before this runs. An empty body, a NUL, invalid
    UTF-8, a duplicate key, or truncated JSON raises and returns nothing.
    """

    if not data:
        raise ProtocolValueError("invalid_event_value_type")
    if b"\x00" in data:
        raise ProtocolValueError("nul_byte_forbidden")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolValueError("invalid_utf8") from exc
    if text.startswith("\ufeff"):
        raise ProtocolValueError("byte_order_mark_forbidden")

    def _decode_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = dict(pairs)
        if len(result) != len(pairs):
            raise ProtocolValueError("duplicate_object_key")
        return result

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_decode_object_pairs,
            parse_float=Decimal,
            parse_int=_parse_cursor_integer,
            parse_constant=_reject_cursor_constant,
        )
    except json.JSONDecodeError as exc:
        raise ProtocolValueError("malformed_json") from exc
    except RecursionError as exc:
        raise ProtocolValueError("nesting_too_deep") from exc
    except InvalidOperation as exc:
        raise ProtocolValueError("float_forbidden") from exc

    normalized = _normalize_cursor_value(parsed, key=None, depth=0)
    ensure_canonical_value(normalized)
    if not isinstance(normalized, Mapping):
        raise ProtocolValueError("unsupported_json_type")
    return cast(Mapping[str, JsonValue], normalized)


def _bounded_identity_string(value: object) -> str | None:
    if type(value) is not str or not value:
        return None
    if len(value.encode("utf-8")) > _MAX_CURSOR_IDENTITY_STRING_BYTES:
        return None
    return value


def _cursor_identity_field(
    key: str, value: object, *, depth: int, allow: _IdentityAllowlist = _CURSOR_IDENTITY
) -> JsonValue | _IdentityDrop:
    """Copy one allowlisted identity field, dropping every other host value."""

    if key == "workspace_roots":
        # A present root list the view cannot keep becomes ``null``, which the
        # workspace resolver refuses. Dropping the key would let it fall back
        # to a less trusted locator that a full-size body never reaches.
        if type(value) is not list:
            return None
        roots = cast(list[object], value)
        if len(roots) > _MAX_CURSOR_IDENTITY_ITEMS:
            return None
        kept_roots: list[JsonValue] = []
        for item in roots:
            text = _bounded_identity_string(item)
            if text is None:
                return None
            kept_roots.append(text)
        return kept_roots
    if key == "error":
        # Outcome parsing reads only whether ``error`` is set. Keep that bit,
        # never the host's error text.
        return True if value not in (None, False, "") else _IDENTITY_DROP
    if key == "model_params":
        if type(value) is not list:
            return _IDENTITY_DROP
        items = cast(list[object], value)
        if len(items) > _MAX_CURSOR_IDENTITY_ITEMS:
            return _IDENTITY_DROP
        kept_items: list[JsonValue] = []
        for item in items:
            if type(item) is not dict or depth >= _MAX_CURSOR_IDENTITY_DEPTH:
                continue
            reduced = _cursor_identity_object(
                cast(dict[str, JsonValue], item), depth=depth + 1, allow=allow
            )
            if reduced:
                kept_items.append(reduced)
        return kept_items
    if key in allow.objects and type(value) is dict:
        if depth >= _MAX_CURSOR_IDENTITY_DEPTH:
            return _IDENTITY_DROP
        reduced = _cursor_identity_object(
            cast(dict[str, JsonValue], value), depth=depth + 1, allow=allow
        )
        if not reduced:
            return _IDENTITY_DROP
        return reduced
    if key in allow.bools and type(value) is bool:
        return value
    if key in allow.ints and type(value) is int and not isinstance(value, bool):
        return value
    if key in allow.strings:
        text = _bounded_identity_string(value)
        if text is None:
            return _IDENTITY_DROP
        return text
    return _IDENTITY_DROP


def _cursor_identity_object(
    value: Mapping[str, JsonValue], *, depth: int, allow: _IdentityAllowlist = _CURSOR_IDENTITY
) -> dict[str, JsonValue]:
    kept: dict[str, JsonValue] = {}
    for key, item in value.items():
        if type(key) is not str:
            continue
        copied = _cursor_identity_field(key, item, depth=depth, allow=allow)
        if isinstance(copied, _IdentityDrop):
            continue
        kept[key] = copied
    return kept


def read_cursor_hook_payload(raw: bytes | None = None) -> Mapping[str, JsonValue]:
    """Read Cursor's bounded host JSON, normalizing its decimal duration field.

    Cursor reports MCP hook durations as fractional milliseconds. That vendor shape
    is admitted only here; canonical ledger and all other host parsers remain
    float-free. Unknown or nested numeric floats are replaced with ``null`` before
    structural filtering, while all host-controlled values are still discarded
    by the caller.

    This pure parser refuses a body over ``MAX_HOOK_STDIN_BYTES`` before any
    inspection. Replay of a captured oversized hook stays a size refusal.
    """

    data = _read_cursor_bytes(raw, MAX_HOOK_STDIN_BYTES + 1)
    # Same split as the Codex reader, and for the same reason: this branch runs
    # before the NUL scan, the UTF-8 decode, and the JSON parse, so without it
    # every oversized Cursor write is reported as a malformed envelope (#667).
    if len(data) > MAX_HOOK_STDIN_BYTES:
        raise ProtocolValueError("payload_too_large")
    return _parse_cursor_hook_document(data)


def read_cursor_hook_ingress(raw: bytes | None = None) -> tuple[Mapping[str, JsonValue], bool]:
    """Read one Cursor hook for observation, skimming a complete oversized body.

    Returns ``(payload, content_omitted)``. A body at or under the trusted cap
    is the full parse and ``content_omitted`` is false. A complete body above
    that cap and at or under ``MAX_HOOK_SKIM_BYTES`` is parsed with the same
    safety rules and returned as the identity view, with ``content_omitted``
    true. A body over the skim cap raises ``payload_too_large`` before the NUL
    scan, the decode, and the parse. A complete oversized body that fails those
    checks raises ``CursorOversizedPayloadError`` and yields no payload.
    """

    data = _read_cursor_bytes(raw, MAX_HOOK_SKIM_BYTES + 1)
    if len(data) > MAX_HOOK_SKIM_BYTES:
        raise ProtocolValueError("payload_too_large")
    if len(data) > MAX_HOOK_STDIN_BYTES:
        if not _skim_structure_within_budget(data):
            raise ProtocolValueError("payload_too_large")
        try:
            parsed = _parse_cursor_hook_document(data)
        except ProtocolValueError as exc:
            raise CursorOversizedPayloadError(exc.reason_code) from exc
        return _reduce_oversized_document(parsed, _CURSOR_IDENTITY)
    return _with_observed_images(_parse_cursor_hook_document(data)), False


class OversizedHookPayloadError(Exception):
    """A Codex or Claude Code body above the trusted cap failed the skim's safety checks.

    The Cursor sibling is ``CursorOversizedPayloadError``; the meaning is the same. The body fit
    the skim cap and was complete, yet the parse refused it, so it yields no payload at all.
    """

    def __init__(self, reason_code: str) -> None:
        if type(reason_code) is not str or not reason_code:
            raise ValueError("unregistered_protocol_reason_code")
        self.reason_code = reason_code
        super().__init__(reason_code)


def _skim_structure_within_budget(data: bytes) -> bool:
    """Whether one oversized body's structure is cheap enough to parse in a hook.

    String bodies are removed first (an unterminated string runs to the end of the body,
    which the parse then refuses), so text and base64 never spend the budget and the
    count stays linear in the body size.
    """

    structural = _JSON_STRING_TOKEN.sub(b'""', data)
    tokens = structural.count(b"{") + structural.count(b"[") + structural.count(b",")
    return tokens <= _MAX_SKIM_STRUCTURE_TOKENS


def _media_block(value: Mapping[str, JsonValue]) -> bool:
    kind = value.get("type")
    if type(kind) is str and kind in _MEDIA_BLOCK_TYPES:
        return True
    for key in _MEDIA_MIME_KEYS:
        mime = value.get(key)
        if type(mime) is str and mime.lower().startswith(_MEDIA_MIME_PREFIXES):
            return True
    return False


def _inline_media_string(value: str) -> bool:
    if len(value) < _MIN_MEDIA_STRING_CHARS or not value.startswith("data:"):
        return False
    header = value[:200].lower()
    return ";base64," in header and header[5:].startswith(_MEDIA_MIME_PREFIXES)


def _strip_media(value: JsonValue, *, in_media: bool) -> tuple[JsonValue, int]:
    if type(value) is str:
        if (in_media and len(value) >= _MIN_MEDIA_STRING_CHARS) or _inline_media_string(value):
            return _MEDIA_PLACEHOLDER, 1
        return value, 0
    if isinstance(value, Mapping):
        mapping = cast(Mapping[str, JsonValue], value)
        nested = in_media or _media_block(mapping)
        result: dict[str, JsonValue] = {}
        total = 0
        for key, item in mapping.items():
            result[key], count = _strip_media(item, in_media=nested)
            total += count
        return (result, total) if total else (value, 0)
    if isinstance(value, list):
        items: list[JsonValue] = []
        total = 0
        for item in cast(list[JsonValue], value):
            stripped, count = _strip_media(item, in_media=in_media)
            items.append(stripped)
            total += count
        return (items, total) if total else (value, 0)
    return value, 0


def strip_hook_media(payload: Mapping[str, JsonValue]) -> tuple[Mapping[str, JsonValue], int]:
    """Replace inline image, audio, and video bytes with a fixed placeholder.

    Returns ``(payload, omitted)``. Media is an image-typed content block (MCP ``image``,
    Responses ``input_image``, Claude ``image`` with its ``source`` or ``file``), any object that
    declares an ``image/``, ``audio/`` or ``video/`` media type, or a ``data:`` URL of one of those
    types anywhere. Inside a media block every long string is bytes, not text; outside one only a
    media ``data:`` URL is. The payload is returned unchanged (same object) when nothing matched.
    Text, numbers, and structure are never altered, and the placeholder names no host value.
    """

    stripped, omitted = _strip_media(cast(JsonValue, payload), in_media=False)
    return cast(Mapping[str, JsonValue], stripped), omitted


# --- Image tool results as digest-only facts (P3-2, issue #1013) ---------------------------------
# A hook that sees an image tool result records what the agent looked at, never the pixels: the
# SHA-256 of the decoded image bytes, their count, a closed media type sniffed from the bytes, and
# pixel dimensions read from the header alone. The service materializes each as digest-only
# evidence linked to the call. The key is reserved: a host value under it is always discarded.
OBSERVED_IMAGES_KEY: Final = "observed_images"
MAX_OBSERVED_IMAGES: Final = 8
OBSERVED_IMAGE_MEDIA_TYPES: Final = (
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/unknown",
    "image/webp",
)
MAX_OBSERVED_IMAGE_DIMENSION: Final = 2_147_483_647
_IMAGE_BLOCK_TYPES: Final = frozenset({"image", "input_image", "output_image", "image_url"})
_PNG_SIGNATURE: Final = b"\x89PNG\r\n\x1a\n"
# JPEG start-of-frame markers that carry the frame size (DHT C4, JPG C8, DAC CC excluded).
_JPEG_SOF_MARKERS: Final = frozenset(
    {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
)
_MAX_JPEG_SEGMENTS: Final = 4_096


def _image_block(value: Mapping[str, JsonValue]) -> bool:
    kind = value.get("type")
    if type(kind) is str and kind in _IMAGE_BLOCK_TYPES:
        return True
    for key in _MEDIA_MIME_KEYS:
        mime = value.get(key)
        if type(mime) is str and mime.lower().startswith("image/"):
            return True
    return False


# A base64 image string inside an image block. Shorter strings are labels ("high", "png"), and
# even the smallest real image encodes to more than this.
_MIN_IMAGE_STRING_CHARS: Final = 32


def _inline_image_string(value: str) -> bool:
    header = value[:200].lower()
    return header.startswith("data:image/") and ";base64," in header


def _image_strings(value: JsonValue, *, in_image: bool, found: list[str]) -> None:
    if len(found) >= MAX_OBSERVED_IMAGES:
        return
    if type(value) is str:
        if (in_image and len(value) >= _MIN_IMAGE_STRING_CHARS) or _inline_image_string(value):
            found.append(value)
        return
    if isinstance(value, Mapping):
        mapping = cast(Mapping[str, JsonValue], value)
        nested = in_image or _image_block(mapping)
        for key, item in mapping.items():
            if key == OBSERVED_IMAGES_KEY:
                continue
            _image_strings(item, in_image=nested, found=found)
        return
    if isinstance(value, list):
        for item in cast(list[JsonValue], value):
            _image_strings(item, in_image=in_image, found=found)


def _decode_image_string(value: str) -> bytes | None:
    body = value
    if value.startswith("data:"):
        header, separator, body = value.partition(",")
        if not separator or ";base64" not in header.lower():
            return None
    compact = "".join(body.split())
    try:
        decoded = base64.b64decode(compact, validate=True)
    except binascii.Error, ValueError:
        return None
    return decoded or None


def _be16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def _le(data: bytes, offset: int, width: int) -> int:
    return int.from_bytes(data[offset : offset + width], "little")


def _jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    index = 2
    for _ in range(_MAX_JPEG_SEGMENTS):
        if index + 4 > len(data) or data[index] != 0xFF:
            return None
        marker = data[index + 1]
        if marker == 0xFF:
            index += 1
            continue
        if marker in {0x01, 0xD8} or 0xD0 <= marker <= 0xD7:
            index += 2
            continue
        if marker in {0xD9, 0xDA}:
            return None
        length = _be16(data, index + 2)
        if length < 2:
            return None
        if marker in _JPEG_SOF_MARKERS:
            if index + 9 > len(data):
                return None
            return _be16(data, index + 7), _be16(data, index + 5)
        index += 2 + length
    return None


def image_header_facts(data: bytes) -> tuple[str, int | None, int | None]:
    """Return ``(media_type, width, height)`` read from an image header only.

    The media type is sniffed from the bytes, never taken from the host's label. PNG ``IHDR``,
    JPEG ``SOFn`` (bounded segment walk), GIF logical screen, and WebP ``VP8``/``VP8L``/``VP8X``
    are read; anything else, or a header too short or naming a zero size, is ``image/unknown``
    with no dimensions. No pixel data is decoded.
    """

    size: tuple[int, int] | None = None
    media = "image/unknown"
    if data[:8] == _PNG_SIGNATURE and data[12:16] == b"IHDR" and len(data) >= 24:
        media = "image/png"
        size = (int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big"))
    elif data[:3] == b"\xff\xd8\xff":
        media, size = "image/jpeg", _jpeg_dimensions(data)
    elif data[:6] in {b"GIF87a", b"GIF89a"} and len(data) >= 10:
        media, size = "image/gif", (_le(data, 6, 2), _le(data, 8, 2))
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        media = "image/webp"
        chunk = data[12:16]
        if chunk == b"VP8 " and len(data) >= 30 and data[23:26] == b"\x9d\x01\x2a":
            size = (_le(data, 26, 2) & 0x3FFF, _le(data, 28, 2) & 0x3FFF)
        elif chunk == b"VP8L" and len(data) >= 25 and data[20] == 0x2F:
            bits = _le(data, 21, 4)
            size = ((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1)
        elif chunk == b"VP8X" and len(data) >= 30:
            size = (_le(data, 24, 3) + 1, _le(data, 27, 3) + 1)
    if size is None or not all(1 <= side <= MAX_OBSERVED_IMAGE_DIMENSION for side in size):
        return "image/unknown", None, None
    return media, size[0], size[1]


def observed_image_facts(payload: Mapping[str, JsonValue]) -> list[JsonValue]:
    """Digest-only facts for at most ``MAX_OBSERVED_IMAGES`` images in one hook payload.

    An image is a decodable base64 string inside an image block (MCP and Claude ``image``,
    Responses ``input_image``, an object declaring an ``image/`` media type) or an image ``data:``
    URL anywhere. A string that does not decode is not an image Yoetz can attest and is skipped.
    """

    found: list[str] = []
    _image_strings(cast(JsonValue, payload), in_image=False, found=found)
    facts: list[JsonValue] = []
    for text in found:
        decoded = _decode_image_string(text)
        if decoded is None:
            continue
        media, width, height = image_header_facts(decoded)
        fact: dict[str, JsonValue] = {
            "byte_count": len(decoded),
            "content_digest": "sha256:" + hashlib.sha256(decoded).hexdigest(),
            "media_type": media,
        }
        if width is not None and height is not None:
            fact["width"] = width
            fact["height"] = height
        facts.append(fact)
    return facts


def _with_observed_images(
    payload: Mapping[str, JsonValue], source: Mapping[str, JsonValue] | None = None
) -> Mapping[str, JsonValue]:
    """Replace any host value under the reserved key with facts computed here."""

    facts = observed_image_facts(payload if source is None else source)
    if OBSERVED_IMAGES_KEY not in payload and not facts:
        return payload
    result = {key: value for key, value in payload.items() if key != OBSERVED_IMAGES_KEY}
    if facts:
        result[OBSERVED_IMAGES_KEY] = facts
    return result


def _reduce_oversized_document(
    parsed: Mapping[str, JsonValue], allow: _IdentityAllowlist
) -> tuple[Mapping[str, JsonValue], bool]:
    """Keep an oversized body whole once its media is gone, else reduce it to identity.

    An image view or a screenshot is almost all base64. Without its media bytes it usually fits
    the trusted cap, and then it is exactly the event a smaller body would have been: structure,
    outcome, and text content all kept. Anything still over the cap keeps only the closed
    identity view, and the caller records that its content was omitted.
    """

    stripped, omitted = strip_hook_media(parsed)
    if omitted:
        try:
            if len(canonical_encode(cast(JsonValue, stripped))) <= MAX_HOOK_STDIN_BYTES:
                return _with_observed_images(stripped, parsed), False
        except ProtocolValueError, TypeError, ValueError:
            pass
    identity = _cursor_identity_object(parsed, depth=0, allow=allow)
    return _with_observed_images(identity, parsed), True


def read_hook_ingress(raw: bytes | None = None) -> tuple[Mapping[str, JsonValue], bool]:
    """Read one Codex or Claude Code hook for observation, skimming an oversized body.

    Returns ``(payload, content_omitted)``, with the same contract as the Cursor reader. A body at
    or under ``MAX_HOOK_STDIN_BYTES`` is exactly :func:`read_hook_payload`. A complete body above
    it and at or under ``MAX_HOOK_SKIM_BYTES`` is parsed with the vendor-number rules (a nested
    fractional number becomes ``null``; nothing else is relaxed). Its media bytes are dropped; if
    that brings it under the trusted cap it is returned whole with ``content_omitted`` false,
    otherwise as the closed identity view with ``content_omitted`` true: file contents, edits,
    prompts, command text, and every other non-identity value are absent, and a string over the
    locator bound is omitted rather than clipped. A body over the skim cap
    raises ``payload_too_large`` unread, and so does one whose JSON structure (``{``, ``[`` and
    ``,`` outside strings) exceeds the skim budget, before any parse. A complete oversized body
    that fails the parse raises
    ``OversizedHookPayloadError`` and yields no payload.
    """

    data = _read_cursor_bytes(raw, MAX_HOOK_SKIM_BYTES + 1)
    if len(data) > MAX_HOOK_SKIM_BYTES:
        raise ProtocolValueError("payload_too_large")
    if len(data) <= MAX_HOOK_STDIN_BYTES:
        return _with_observed_images(read_hook_payload(data)), False
    if not _skim_structure_within_budget(data):
        raise ProtocolValueError("payload_too_large")
    try:
        parsed = _parse_cursor_hook_document(data)
    except ProtocolValueError as exc:
        raise OversizedHookPayloadError(exc.reason_code) from exc
    return _reduce_oversized_document(parsed, _HOOK_IDENTITY)
