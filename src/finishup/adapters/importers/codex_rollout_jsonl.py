"""Bounded parser for exact Codex session-rollout JSONL profiles.

The ``codex exec --json`` grammar lives in ``codex_jsonl.py`` and is a different
surface. This module admits ``rollout-*.jsonl`` lines of the form
``{"timestamp","ordinal"?,"type","payload"}``.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal, NoReturn, cast

from finishup.adapters.importers.codex_jsonl import (
    CodexCapabilityProfile,
    CodexParsedRecord,
    CodexParseResult,
    CodexSourceLine,
)
from finishup.adapters.integrations.codex_capability_cells import CODEX_ROLLOUT_HISTORY_MODES
from finishup.domain.values import JsonObject, JsonValue, freeze_json
from finishup.observability.privacy import redact_high_confidence_content
from finishup.ports.importer import ImportLineStatus
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "CODEX_ROLLOUT_COMPATIBLE_PROFILE_ID",
    "CODEX_ROLLOUT_MAPPING_VERSION",
    "COMPATIBLE_ROLLOUT_PROFILE",
    "ROLLOUT_MAX_LINE_BYTES",
    "SUPPORTED_ROLLOUT_PROFILES",
    "RolloutAdmissionProvenance",
    "admission_profile_for_rollout_version",
    "parse_codex_rollout_jsonl",
    "parse_codex_rollout_jsonl_from_offset",
    "profile_for_rollout_id",
    "profile_for_rollout_version",
    "rollout_admission_provenance",
    "split_codex_rollout_jsonl_chunk",
]

CODEX_ROLLOUT_MAPPING_VERSION: Final = "codex-rollout-jsonl/1.0.0"
_MAX_SOURCE_BYTES: Final = 4_194_304
_MAX_LINE_BYTES: Final = 1_048_576
_MAX_LINES: Final = 20_000
_MAX_JSON_DEPTH: Final = 64
# Every exact profile shares the same byte/line bounds (``CodexCapabilityProfile`` pins them), so
# chunking a stream whose header has not admitted a profile yet is still bounded.
ROLLOUT_MAX_LINE_BYTES: Final = _MAX_LINE_BYTES

# One vocabulary per exact Codex release, each locked by its own constructed fixtures
# (``fixtures/imports/codex/rollout-*-<cli_version>.case.json``). An exact profile is
# certification evidence. A header naming any other release is admitted under the structural
# ``compatible`` profile below (issue #656): the host version is diagnostic provenance, the
# wrapper/item vocabulary is what decides whether a line is understood, and a shape outside that
# vocabulary stays a bounded per-line gap instead of disabling the whole stream.
_WRAPPER_TYPES_0_148_0: Final = (
    "compacted",
    "event_msg",
    "inter_agent_communication",
    "inter_agent_communication_metadata",
    "realtime_item",
    "response_item",
    "security_risk_score",
    "session_meta",
    "turn_context",
    "world_state",
)
_ITEM_TYPES_0_148_0: Final = (
    "agent_message",
    "agent_reasoning",
    "compaction",
    "context_compaction",
    "custom_tool_call",
    "custom_tool_call_output",
    "function_call",
    "function_call_output",
    "item_completed",
    "local_shell_call",
    "message",
    "reasoning",
    "user_message",
    "web_search_call",
)
_WRAPPER_TYPES_0_150_1: Final = (
    "compacted",
    "event_msg",
    "inter_agent_communication_metadata",
    "response_item",
    "session_meta",
    "turn_context",
    "world_state",
)
# ``event_msg`` payload types, ``response_item`` payload types, and the PascalCase
# ``event_msg.item_completed.item.type`` family are one closed set: a nested item type must be
# admitted here before the wrapper line maps, so an unknown inner item is never masked.
_ITEM_TYPES_0_150_1: Final = (
    "AgentMessage",
    "CollabAgentToolCall",
    "CommandExecution",
    "ContextCompaction",
    "FileChange",
    "McpToolCall",
    "Reasoning",
    "SubAgentActivity",
    "UserMessage",
    "agent_message",
    "custom_tool_call",
    "custom_tool_call_output",
    "function_call",
    "function_call_output",
    "item_completed",
    "message",
    "reasoning",
    "task_complete",
    "task_started",
    "thread_settings_applied",
    "token_count",
    "turn_aborted",
)


def _profile_digest(
    cli_version: str,
    profile_id: str,
    wrapper_types: tuple[str, ...],
    item_types: tuple[str, ...],
) -> str:
    return canonical_digest(
        {
            "cli_version": cli_version,
            "item_types": item_types,
            "history_modes": CODEX_ROLLOUT_HISTORY_MODES,
            "max_line_bytes": _MAX_LINE_BYTES,
            "max_lines": _MAX_LINES,
            "max_source_bytes": _MAX_SOURCE_BYTES,
            "profile_id": profile_id,
            "wrapper_types": wrapper_types,
        }
    )


def _exact_profile(
    cli_version: str,
    wrapper_types: tuple[str, ...],
    item_types: tuple[str, ...],
) -> CodexCapabilityProfile:
    profile_id = f"codex-rollout-jsonl/{cli_version}/v1"
    return CodexCapabilityProfile(
        cli_version,
        profile_id,
        _profile_digest(cli_version, profile_id, wrapper_types, item_types),
        wrapper_types,
        item_types,
    )


_BASELINE_PROFILE = _exact_profile("0.148.0", _WRAPPER_TYPES_0_148_0, _ITEM_TYPES_0_148_0)
_PROFILE_0_150_1 = _exact_profile("0.150.1", _WRAPPER_TYPES_0_150_1, _ITEM_TYPES_0_150_1)
# Exact, fixture-proven profiles keyed by ``cli_version``. This mapping is certification: the
# dogfood parity gate and ``CODEX_ROLLOUT_PARSER_PROOFS`` mirror exactly these keys.
SUPPORTED_ROLLOUT_PROFILES: Final[Mapping[str, CodexCapabilityProfile]] = MappingProxyType(
    {
        _BASELINE_PROFILE.cli_version: _BASELINE_PROFILE,
        _PROFILE_0_150_1.cli_version: _PROFILE_0_150_1,
    }
)
# The structural compatibility profile (issue #656). Its ``cli_version`` is the literal token
# ``compatible`` — it never names a release — and its vocabulary is the union of every exact
# profile plus the structurally ignored families below, so a header naming an unproven release
# parses the wrappers and items FinishUP already understands while everything else stays a bounded
# ``unsupported_event`` gap.
CODEX_ROLLOUT_COMPATIBLE_VERSION_TOKEN: Final = "compatible"
CODEX_ROLLOUT_COMPATIBLE_PROFILE_ID: Final = "codex-rollout-jsonl/compatible/v1"
# Wrapper families that only the compatibility profile admits (issue #754). ``token_usage_record``
# is per-turn accounting telemetry a real Codex 0.153.4 multi-agent v2 transcript emits on every
# turn (fixture IMP-015). FinishUP reads no structural field from it, so admitting the family turns
# a per-line coverage gap into a bounded ignored line. It stays out of every exact profile: no
# certified release has been proven to emit it.
_COMPATIBLE_ONLY_WRAPPER_TYPES: Final = ("token_usage_record",)
_COMPATIBLE_WRAPPER_TYPES: Final = tuple(
    sorted(
        {
            wrapper
            for profile in SUPPORTED_ROLLOUT_PROFILES.values()
            for wrapper in profile.wrapper_types
        }
        | set(_COMPATIBLE_ONLY_WRAPPER_TYPES),
        key=str.encode,
    )
)
# Item families only the compatibility profile admits, on the same terms (issue #1041).
# ``HookPrompt`` is the ``event_msg.item_completed`` item a Codex 0.159.3 rollout writes when a
# Stop hook continues the turn with a prompt (FinishUP's own closure gate text). FinishUP reads no
# structural field from it: it names no tool call and pairs with nothing, so it is bookkeeping,
# not an ``unsupported_event`` gap on every gated attempt.
_COMPATIBLE_ONLY_ITEM_TYPES: Final = ("HookPrompt",)
_COMPATIBLE_ITEM_TYPES: Final = tuple(
    sorted(
        {item for profile in SUPPORTED_ROLLOUT_PROFILES.values() for item in profile.item_types}
        | set(_COMPATIBLE_ONLY_ITEM_TYPES),
        key=str.encode,
    )
)
COMPATIBLE_ROLLOUT_PROFILE: Final = CodexCapabilityProfile(
    CODEX_ROLLOUT_COMPATIBLE_VERSION_TOKEN,
    CODEX_ROLLOUT_COMPATIBLE_PROFILE_ID,
    _profile_digest(
        CODEX_ROLLOUT_COMPATIBLE_VERSION_TOKEN,
        CODEX_ROLLOUT_COMPATIBLE_PROFILE_ID,
        _COMPATIBLE_WRAPPER_TYPES,
        _COMPATIBLE_ITEM_TYPES,
    ),
    _COMPATIBLE_WRAPPER_TYPES,
    _COMPATIBLE_ITEM_TYPES,
)
_PROFILES_BY_ID: Final[Mapping[str, CodexCapabilityProfile]] = MappingProxyType(
    {
        **{profile.profile_id: profile for profile in SUPPORTED_ROLLOUT_PROFILES.values()},
        COMPATIBLE_ROLLOUT_PROFILE.profile_id: COMPATIBLE_ROLLOUT_PROFILE,
    }
)
_ADMISSIBLE_PROFILES: Final = frozenset(_PROFILES_BY_ID.values())

type RolloutAdmissionProvenance = Literal["exact", "structural"]


def admission_profile_for_rollout_version(
    version: str,
) -> tuple[CodexCapabilityProfile, RolloutAdmissionProvenance]:
    """Select the profile a session header admits under, with its provenance.

    An exactly proven ``cli_version`` selects its certified profile (``exact``). Any other ASCII
    version selects the structural compatibility profile (``structural``): the release is not
    certified, the version is recorded only as diagnostic provenance, and lines are understood
    or refused by their shape alone.
    """

    if type(version) is not str or not version.isascii():
        raise ValueError("unsupported_codex_profile")
    exact = SUPPORTED_ROLLOUT_PROFILES.get(version)
    if exact is not None:
        return exact, "exact"
    return COMPATIBLE_ROLLOUT_PROFILE, "structural"


def rollout_admission_provenance(
    profile: CodexCapabilityProfile,
) -> RolloutAdmissionProvenance:
    """Name whether *profile* is an exact certification or the structural compatibility profile."""

    if type(profile) is not CodexCapabilityProfile or profile not in _ADMISSIBLE_PROFILES:
        raise ValueError("unsupported_codex_profile")
    return "structural" if profile == COMPATIBLE_ROLLOUT_PROFILE else "exact"


def profile_for_rollout_version(version: str) -> CodexCapabilityProfile:
    """Return one exact rollout profile; never infer a version range."""

    if type(version) is not str or not version.isascii():
        raise ValueError("unsupported_codex_profile")
    try:
        return SUPPORTED_ROLLOUT_PROFILES[version]
    except KeyError as exc:
        raise ValueError("unsupported_codex_profile") from exc


def profile_for_rollout_id(profile_id: str) -> CodexCapabilityProfile:
    """Return the profile a persisted ``profile_id`` names (exact or compatible), or fail closed."""

    if type(profile_id) is not str or not profile_id.isascii():
        raise ValueError("unsupported_codex_profile")
    try:
        return _PROFILES_BY_ID[profile_id]
    except KeyError as exc:
        raise ValueError("unsupported_codex_profile") from exc


def _check_profile(profile: CodexCapabilityProfile | None) -> None:
    if profile is None:
        return
    if type(profile) is not CodexCapabilityProfile or profile not in _ADMISSIBLE_PROFILES:
        raise ValueError("unsupported_codex_profile")


def split_codex_rollout_jsonl_chunk(
    source: bytes,
    profile: CodexCapabilityProfile | None,
    *,
    start_ordinal: int = 1,
) -> tuple[CodexSourceLine, ...]:
    """Split a byte chunk into source lines with chunk-relative byte offsets.

    ``profile`` may be ``None`` before the session header has admitted one; every exact profile
    shares the same bounds, so splitting is identical either way.
    """

    if type(start_ordinal) is not int or start_ordinal < 1:
        raise ValueError("codex_source_invalid")
    _check_profile(profile)
    bounds = _BASELINE_PROFILE if profile is None else profile
    if type(source) is not bytes:
        raise ValueError("codex_source_invalid")
    if len(source) > bounds.max_source_bytes:
        raise ValueError("import_source_limit_exceeded")
    if not source:
        return ()
    lines: list[CodexSourceLine] = []
    start = 0
    ordinal = start_ordinal
    while start < len(source):
        newline = source.find(b"\n", start)
        terminated = newline >= 0
        end = newline + 1 if terminated else len(source)
        if ordinal > bounds.max_lines:
            raise ValueError("import_line_limit_exceeded")
        content_end = end - 1 if terminated else end
        content = bytes(source[start:content_end])
        if content.endswith(b"\r"):
            content = content[:-1]
        lines.append(CodexSourceLine(ordinal, start, end, content, terminated))
        ordinal += 1
        start = end
    return tuple(lines)


def parse_codex_rollout_jsonl(
    source: bytes,
    profile: CodexCapabilityProfile | None,
    *,
    require_admission: bool = True,
) -> CodexParseResult:
    """Split and validate exact rollout bytes without IO or source-bearing diagnostics."""

    return parse_codex_rollout_jsonl_from_offset(
        source, profile, start_ordinal=1, require_admission=require_admission
    )


def parse_codex_rollout_jsonl_from_offset(
    source: bytes,
    profile: CodexCapabilityProfile | None,
    *,
    start_ordinal: int = 1,
    require_admission: bool = False,
) -> CodexParseResult:
    """Parse a rollout JSONL chunk. Unterminated tails are retained by callers.

    With an explicit ``profile`` the session header must select exactly that profile. With
    ``profile=None`` (only valid when admission is required) the header selects the profile: an
    exactly proven ``cli_version`` selects its certified profile, any other version selects the
    structural compatibility profile. The result's ``profile`` is the admitted one and stays
    ``None`` when the chunk admitted nothing, which now means a structurally unsupported header
    (not ``session_meta``, a non-object payload, a non-string version, or an unknown
    ``history_mode``) rather than an unlisted release.
    """

    _check_profile(profile)
    if type(require_admission) is not bool:
        raise ValueError("codex_source_invalid")
    if profile is None and not require_admission:
        raise ValueError("unsupported_codex_profile")
    lines = split_codex_rollout_jsonl_chunk(source, profile, start_ordinal=start_ordinal)
    records: list[CodexParsedRecord] = []
    statuses: list[ImportLineStatus] = []
    reasons: list[str | None] = []
    stream_gaps: set[str] = set()
    admitted = not require_admission
    refused = False
    for line in lines:
        if refused:
            statuses.append(ImportLineStatus.UNSUPPORTED)
            reasons.append("unsupported_codex_profile")
            continue
        if len(line.content) > _MAX_LINE_BYTES:
            statuses.append(ImportLineStatus.OVERSIZED)
            reasons.append("line_oversized")
            if not admitted:
                refused = True
                stream_gaps.add("unsupported_codex_profile")
            continue
        try:
            value = _redact_json_tree(_parse_json_line(line.content))
        except (TypeError, ValueError, UnicodeError):
            statuses.append(ImportLineStatus.MALFORMED)
            reason = "malformed_line"
            if line.ordinal == lines[-1].ordinal and not line.terminated:
                reason = "truncated_final_line"
                stream_gaps.add(reason)
            reasons.append(reason)
            if not admitted and line.terminated:
                refused = True
                stream_gaps.add("unsupported_codex_profile")
            continue
        if not admitted:
            selected, admission_reason = _admit_session_meta(value, profile)
            if selected is None:
                refused = True
                stream_gaps.add("unsupported_codex_profile")
                statuses.append(ImportLineStatus.UNSUPPORTED)
                reasons.append(admission_reason)
                continue
            admitted = True
            profile = selected
        assert profile is not None
        status, item_type, reason = _validate_wrapper(value, profile)
        statuses.append(status)
        reasons.append(reason)
        wrapper_type = value.get("type")
        if status is ImportLineStatus.MAPPED and type(wrapper_type) is str:
            try:
                frozen = freeze_json(cast(JsonValue, value))
            except ProtocolValueError:
                statuses[-1] = ImportLineStatus.UNSUPPORTED
                reasons[-1] = "json_profile_unsupported"
                continue
            if type(frozen) is not JsonObject:
                statuses[-1] = ImportLineStatus.UNSUPPORTED
                reasons[-1] = "json_profile_unsupported"
                continue
            records.append(
                CodexParsedRecord(
                    line.ordinal,
                    line.byte_start,
                    line.byte_end,
                    wrapper_type,
                    item_type,
                    frozen,
                )
            )
    if lines and not lines[-1].terminated:
        stream_gaps.add("final_newline_absent")
    return CodexParseResult(
        profile if admitted else None,
        lines,
        tuple(records),
        tuple(statuses),
        tuple(reasons),
        tuple(sorted(stream_gaps, key=str.encode)),
    )


def _reject_constant(_: str) -> NoReturn:
    raise ValueError("nonfinite_number")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_object_key")
        result[key] = value
    return result


def _validate_json_tree(value: object, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("nesting_too_deep")
    if type(value) is str:
        value.encode("utf-8", errors="strict")
    elif type(value) is float:
        if not math.isfinite(value):
            raise ValueError("nonfinite_number")
    elif type(value) is list:
        for item in cast(list[object], value):
            _validate_json_tree(item, depth + 1)
    elif type(value) is dict:
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str:
                raise ValueError("json_object_invalid")
            key.encode("utf-8", errors="strict")
            _validate_json_tree(item, depth + 1)
    elif value is not None and type(value) not in {bool, int}:
        raise ValueError("json_value_invalid")


def _parse_json_line(content: bytes) -> dict[str, object]:
    if not content or b"\x00" in content or content.startswith(b"\xef\xbb\xbf"):
        raise ValueError("malformed_json")
    try:
        text = content.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("malformed_json") from exc
    _validate_json_tree(parsed)
    if type(parsed) is not dict:
        raise ValueError("top_level_not_object")
    return cast(dict[str, object], parsed)


def _redact_json_tree(value: dict[str, object]) -> dict[str, object]:
    """Redact high-confidence secrets in decoded JSON strings and drop unrepresentable numbers.

    Heuristic-only assignment matches are kept (issue #982); egress redacts them.

    Tree shape stays intact: strings are redacted in place and a fractional number becomes
    ``null`` in the same position. The canonical value model has no float (``float_forbidden``),
    and Codex 0.153.4 added fractional leaves to ordinary rows — ``rate_limits.*.used_percent``
    on ``token_count`` and ``internal_chat_message_metadata_passthrough.create_time`` on every
    ``response_item`` (issue #754). Before this normalization one such leaf refused the whole
    line as ``json_profile_unsupported``, which cost 40 of the 50 unsupported rows in the
    observed v2 run. No structural field FinishUP maps is ever a float — identifiers are tokens and
    ``exit_code`` is an integer — so the mapped record loses nothing structural, and the line's
    own commitment is still taken over its raw bytes.
    """

    def redact(item: object, depth: int = 0) -> object:
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("nesting_too_deep")
        if type(item) is str:
            redacted, _detected = redact_high_confidence_content(
                item.encode("utf-8", errors="strict")
            )
            return redacted.decode("utf-8", errors="strict")
        if type(item) is float:
            return None
        if type(item) is list:
            return [redact(child, depth + 1) for child in cast(list[object], item)]
        if type(item) is dict:
            result: dict[str, object] = {}
            for key, child in cast(dict[str, object], item).items():
                redacted_key = cast(str, redact(key, depth + 1))
                if redacted_key in result:
                    raise ValueError("duplicate_object_key")
                result[redacted_key] = redact(child, depth + 1)
            return result
        return item

    redacted = redact(value)
    if type(redacted) is not dict:
        raise ValueError("top_level_not_object")
    result = cast(dict[str, object], redacted)
    _validate_json_tree(result)
    return result


def _admit_session_meta(
    value: dict[str, object], profile: CodexCapabilityProfile | None
) -> tuple[CodexCapabilityProfile | None, str]:
    """Select the profile the header admits under, or refuse structurally.

    The structural constraints are the gate: a ``session_meta`` wrapper, an object payload, a
    string ASCII ``cli_version``, and a known ``history_mode``. The version then only chooses
    between an exact certified profile and the structural compatibility profile; it is never a
    reason to refuse (issue #656). An explicit ``profile`` refuses a header that selects a
    different profile, so a caller pinned to one exact release still cannot parse another.
    """

    if value.get("type") != "session_meta":
        return None, "unsupported_codex_profile"
    payload = value.get("payload")
    if type(payload) is not dict:
        return None, "unsupported_codex_profile"
    cli_version = cast(dict[str, object], payload).get("cli_version")
    if type(cli_version) is not str or not cli_version.isascii():
        return None, "unsupported_codex_profile"
    admitted, _provenance = admission_profile_for_rollout_version(cli_version)
    if profile is not None and admitted != profile:
        return None, "unsupported_codex_profile"
    history_mode = cast(dict[str, object], payload).get("history_mode")
    if type(history_mode) is not str or history_mode not in CODEX_ROLLOUT_HISTORY_MODES:
        return None, "unsupported_codex_profile"
    return admitted, "session_meta"


def _item_types_of(value: dict[str, object]) -> tuple[str | None, tuple[str, ...]]:
    payload = value.get("payload")
    if type(payload) is not dict:
        return None, ()
    body = cast(dict[str, object], payload)
    payload_type = body.get("type")
    inner = body.get("item")
    inner_type: object = None
    if type(inner) is dict:
        inner_type = cast(dict[str, object], inner).get("type")
    candidates = tuple(
        candidate for candidate in (payload_type, inner_type) if type(candidate) is str
    )
    selected = inner_type if type(inner_type) is str else payload_type
    return (selected if type(selected) is str else None), candidates


def _validate_wrapper(
    value: dict[str, object], profile: CodexCapabilityProfile
) -> tuple[ImportLineStatus, str | None, str | None]:
    wrapper_type = value.get("type")
    if type(wrapper_type) is not str:
        return ImportLineStatus.UNSUPPORTED, None, "wrapper_shape_unsupported"
    if wrapper_type not in profile.wrapper_types:
        return ImportLineStatus.UNKNOWN, None, "unknown_wrapper_type"
    payload = value.get("payload")
    if type(payload) is not dict:
        return ImportLineStatus.UNSUPPORTED, None, "wrapper_shape_unsupported"
    if "timestamp" in value and type(value.get("timestamp")) is not str:
        return ImportLineStatus.UNSUPPORTED, None, "wrapper_shape_unsupported"
    if "ordinal" in value and type(value.get("ordinal")) is not int:
        return ImportLineStatus.UNSUPPORTED, None, "wrapper_shape_unsupported"
    item_type, semantic_types = _item_types_of(value)
    for semantic_type in semantic_types:
        if semantic_type not in profile.item_types:
            return ImportLineStatus.UNKNOWN, semantic_type, "unknown_item_type"
    return ImportLineStatus.MAPPED, item_type, None
