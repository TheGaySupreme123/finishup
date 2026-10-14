"""Pure, bounded parser and conservative mapper for exact Codex JSONL profiles."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Final, Literal, NoReturn, cast

from yoetz.adapters.importers._codex_jsonl_types import (
    CODEX_JSONL_MAPPING_VERSION,
    INT64_MAX,
    INT64_MIN,
    ITEM_TYPES,
    MAPPED_ITEM_TYPES,
    MAX_ARGV_BYTES,
    MAX_ARGV_ITEMS,
    MAX_JSON_DEPTH,
    REDACTED_ARG,
    SUPPORTED_CODEX_PROFILES,
    WRAPPER_TYPES,
    CodexCapabilityProfile,
    CodexParsedRecord,
    CodexParseResult,
    CodexSourceLine,
)
from yoetz.domain.events import (
    MAX_TEXT_BYTES,
    ActionKind,
    ActionRecordedPayload,
    EventDraft,
    EventPayload,
    EventSchema,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.values import (
    JsonObject,
    Timestamp,
    action_id,
    event_id,
    freeze_json,
    object_id,
    result_id,
)
from yoetz.domain.values import (
    JsonValue as DomainJsonValue,
)
from yoetz.ports.importer import (
    ImportEventCandidate,
    ImportGap,
    ImportLineOutcome,
    ImportLineStatus,
)
from yoetz.ports.objects import ObjectKind, ObjectRef
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    Coverage,
    PublicationChannel,
)
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.ids import IdKind, validate_id

__all__ = [
    "CODEX_JSONL_MAPPING_VERSION",
    "CODEX_OPAQUE_SCHEMA",
    "SUPPORTED_CODEX_PROFILES",
    "CodexCandidateTemplate",
    "CodexCapabilityProfile",
    "CodexMappingContext",
    "CodexMappingTemplate",
    "CodexMaterializationIds",
    "CodexParsedRecord",
    "CodexParseResult",
    "CodexPreparedMapping",
    "CodexSourceLine",
    "SanitizedCodexArgv",
    "materialize_codex_mapping",
    "parse_codex_jsonl",
    "parse_codex_jsonl_from_offset",
    "plan_codex_mapping",
    "profile_for_codex_version",
    "sanitize_codex_argv",
    "split_codex_jsonl_chunk",
]

CODEX_OPAQUE_SCHEMA: Final = EventSchema("codex_jsonl_observation", "1.0.0")


@dataclass(frozen=True, slots=True)
class CodexMappingContext:
    source_object: ObjectRef
    source_commitment: str
    captured_at: Timestamp
    profile: CodexCapabilityProfile
    mapping_version: str
    coverage: Coverage

    def __post_init__(self) -> None:
        if (
            type(self.source_object) is not ObjectRef
            or self.source_object.metadata.kind is not ObjectKind.IMPORT_SOURCE
            or self.source_object.commitment != self.source_commitment
            or type(self.captured_at) is not Timestamp
            or type(self.profile) is not CodexCapabilityProfile
            or self.mapping_version != CODEX_JSONL_MAPPING_VERSION
            or type(self.coverage) is not Coverage
            or self.coverage.publication_channels != (PublicationChannel.CODEX_JSONL_IMPORT,)
            or self.coverage.authorship_assurance > AuthorshipAssurance.HARNESS_OBSERVED
            or self.coverage.artifact_observation > ArtifactObservation.IMPORT_OBSERVED
        ):
            raise ValueError("codex_mapping_context_invalid")


type _TemplateKind = Literal["action", "result", "opaque"]


@dataclass(frozen=True, slots=True, repr=False)
class CodexCandidateTemplate:
    local_key: str
    logical_key: str | None
    kind: _TemplateKind
    source_line_ordinal: int
    byte_start: int
    byte_end: int
    source_category: str
    target_schema: EventSchema
    payload: JsonObject
    causal_parent_keys: tuple[str, ...]
    gap_codes: tuple[str, ...]

    def __repr__(self) -> str:
        return "CodexCandidateTemplate(<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class CodexMappingTemplate:
    context: CodexMappingContext
    line_outcomes: tuple[ImportLineOutcome, ...]
    candidates: tuple[CodexCandidateTemplate, ...]
    gaps: tuple[ImportGap, ...]
    report_facts: JsonObject


@dataclass(frozen=True, slots=True)
class CodexMaterializationIds:
    event_ids: Mapping[str, str]
    logical_ids: Mapping[str, str]
    plan_object: ObjectRef

    def __post_init__(self) -> None:
        if (
            type(self.plan_object) is not ObjectRef
            or self.plan_object.metadata.kind is not ObjectKind.IMPORT_PLAN
        ):
            raise ValueError("codex_materialization_ids_invalid")
        events = _copy_string_mapping(self.event_ids, IdKind.EVENT)
        logical: dict[str, str] = {}
        for key, value in self.logical_ids.items():
            if type(key) is not str or type(value) is not str:
                raise ValueError("codex_materialization_ids_invalid")
            if value.startswith("act_"):
                validate_id(IdKind.ACTION, value)
            elif value.startswith("res_"):
                validate_id(IdKind.RESULT, value)
            else:
                raise ValueError("codex_materialization_ids_invalid")
            logical[key] = value
        object.__setattr__(self, "event_ids", MappingProxyType(events))
        object.__setattr__(self, "logical_ids", MappingProxyType(logical))


@dataclass(frozen=True, slots=True, repr=False)
class CodexPreparedMapping:
    line_outcomes: tuple[ImportLineOutcome, ...]
    event_drafts: tuple[EventDraft, ...]
    candidates: tuple[ImportEventCandidate, ...]
    gaps: tuple[ImportGap, ...]
    report_facts: JsonObject

    def __repr__(self) -> str:
        return "CodexPreparedMapping(<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True, repr=False)
class SanitizedCodexArgv:
    argv: tuple[str, ...]
    omission_codes: tuple[str, ...]

    def __repr__(self) -> str:
        return "SanitizedCodexArgv(<redacted>)"

    __str__ = __repr__


def _copy_string_mapping(source: Mapping[str, str], kind: IdKind) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in source.items():
        if type(key) is not str or type(value) is not str or key in result:
            raise ValueError("codex_materialization_ids_invalid")
        result[key] = validate_id(kind, value)
    return result


def profile_for_codex_version(version: str) -> CodexCapabilityProfile:
    """Return one exact capability profile; never infer a version range."""

    if type(version) is not str or not version.isascii():
        raise ValueError("unsupported_codex_profile")
    try:
        return SUPPORTED_CODEX_PROFILES[version]
    except KeyError as exc:
        raise ValueError("unsupported_codex_profile") from exc


def _split_lines(source: bytes, profile: CodexCapabilityProfile) -> tuple[CodexSourceLine, ...]:
    return _split_lines_from(source, profile, start_ordinal=1)


def split_codex_jsonl_chunk(
    source: bytes,
    profile: CodexCapabilityProfile,
    *,
    start_ordinal: int = 1,
) -> tuple[CodexSourceLine, ...]:
    """Split a byte chunk into source lines with chunk-relative byte offsets.

    Partial (unterminated) final lines are returned so callers can hold them across reads.
    Absolute file positions are owned by the session-stream cursor, not these lines.
    """

    if type(start_ordinal) is not int or start_ordinal < 1:
        raise ValueError("codex_source_invalid")
    if (
        type(profile) is not CodexCapabilityProfile
        or SUPPORTED_CODEX_PROFILES.get(profile.cli_version) != profile
    ):
        raise ValueError("unsupported_codex_profile")
    return _split_lines_from(source, profile, start_ordinal=start_ordinal)


def _split_lines_from(
    source: bytes, profile: CodexCapabilityProfile, *, start_ordinal: int
) -> tuple[CodexSourceLine, ...]:
    if type(source) is not bytes:
        raise ValueError("codex_source_invalid")
    if len(source) > profile.max_source_bytes:
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
        if ordinal > profile.max_lines:
            raise ValueError("import_line_limit_exceeded")
        content_end = end - 1 if terminated else end
        content = bytes(source[start:content_end])
        if content.endswith(b"\r"):
            content = content[:-1]
        lines.append(CodexSourceLine(ordinal, start, end, content, terminated))
        ordinal += 1
        start = end
    return tuple(lines)


def parse_codex_jsonl_from_offset(
    source: bytes,
    profile: CodexCapabilityProfile,
    *,
    start_ordinal: int = 1,
) -> CodexParseResult:
    """Parse a JSONL chunk using the same mapping rules as ``parse_codex_jsonl``.

    Unterminated trailing lines are marked so incremental readers can retain them
    without inventing events. Byte positions are chunk-relative.
    """

    if (
        type(profile) is not CodexCapabilityProfile
        or SUPPORTED_CODEX_PROFILES.get(profile.cli_version) != profile
    ):
        raise ValueError("unsupported_codex_profile")
    lines = split_codex_jsonl_chunk(source, profile, start_ordinal=start_ordinal)
    records: list[CodexParsedRecord] = []
    statuses: list[ImportLineStatus] = []
    reasons: list[str | None] = []
    stream_gaps: set[str] = set()
    for line in lines:
        if len(line.content) > profile.max_line_bytes:
            statuses.append(ImportLineStatus.OVERSIZED)
            reasons.append("line_oversized")
            continue
        try:
            value = _parse_json_line(line.content)
        except TypeError, ValueError, UnicodeError:
            statuses.append(ImportLineStatus.MALFORMED)
            reason = "malformed_line"
            if line.ordinal == lines[-1].ordinal and not line.terminated:
                reason = "truncated_final_line"
                stream_gaps.add(reason)
            reasons.append(reason)
            continue
        status, item_type, reason = _validate_wrapper(value)
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
        profile,
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
    if depth > MAX_JSON_DEPTH:
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


def _keys(value: Mapping[str, object], expected: frozenset[str]) -> bool:
    return frozenset(value) == expected


def _text(value: object) -> bool:
    return type(value) is str


def _int64(value: object) -> bool:
    return type(value) is int and INT64_MIN <= value <= INT64_MAX


def _json_value(value: object) -> bool:
    try:
        _validate_json_tree(value)
    except TypeError, ValueError, UnicodeError:
        return False
    return True


def _validate_item(item: object) -> tuple[bool, str | None]:
    if type(item) is not dict:
        return False, None
    row = cast(dict[str, object], item)
    item_id = row.get("id")
    item_type = row.get("type")
    if not _text(item_id) or not _text(item_type):
        return False, None
    category = cast(str, item_type)
    if category not in ITEM_TYPES:
        return False, category
    if category in {"agent_message", "reasoning", "error"}:
        return _keys(
            row, frozenset({"id", "type", "text" if category != "error" else "message"})
        ) and _text(row.get("text" if category != "error" else "message")), category
    if category == "command_execution":
        valid = (
            _keys(
                row,
                frozenset({"id", "type", "command", "aggregated_output", "exit_code", "status"}),
            )
            and _text(row.get("command"))
            and _text(row.get("aggregated_output"))
            and (row.get("exit_code") is None or _int64(row.get("exit_code")))
            and row.get("status") in {"in_progress", "completed", "failed", "declined"}
        )
        return valid, category
    if category == "file_change":
        changes = row.get("changes")
        valid_changes = type(changes) is list and all(
            type(change) is dict
            and _keys(cast(dict[str, object], change), frozenset({"path", "kind"}))
            and _text(cast(dict[str, object], change).get("path"))
            and cast(dict[str, object], change).get("kind") in {"add", "delete", "update"}
            for change in cast(list[object], changes or [])
        )
        return (
            _keys(row, frozenset({"id", "type", "changes", "status"}))
            and valid_changes
            and row.get("status") in {"in_progress", "completed", "failed"},
            category,
        )
    if category == "mcp_tool_call":
        error = row.get("error")
        result = row.get("result")
        valid_error = error is None or (
            type(error) is dict
            and _keys(cast(dict[str, object], error), frozenset({"message"}))
            and _text(cast(dict[str, object], error).get("message"))
        )
        valid_result = result is None or (
            type(result) is dict
            and frozenset(cast(dict[str, object], result)).issubset(
                {"content", "_meta", "structured_content"}
            )
            and "content" in cast(dict[str, object], result)
            and type(cast(dict[str, object], result).get("content")) is list
            and _json_value(cast(object, result))
        )
        return (
            _keys(
                row,
                frozenset(
                    {"id", "type", "server", "tool", "arguments", "result", "error", "status"}
                ),
            )
            and _text(row.get("server"))
            and _text(row.get("tool"))
            and _json_value(row.get("arguments"))
            and valid_result
            and valid_error
            and row.get("status") in {"in_progress", "completed", "failed"},
            category,
        )
    if category == "collab_tool_call":
        receivers = row.get("receiver_thread_ids")
        return (
            _keys(
                row,
                frozenset(
                    {
                        "id",
                        "type",
                        "tool",
                        "sender_thread_id",
                        "receiver_thread_ids",
                        "prompt",
                        "agents_states",
                        "status",
                    }
                ),
            )
            and row.get("tool") in {"spawn_agent", "send_input", "wait", "close_agent"}
            and _text(row.get("sender_thread_id"))
            and type(receivers) is list
            and all(_text(value) for value in cast(list[object], receivers or []))
            and (row.get("prompt") is None or _text(row.get("prompt")))
            and type(row.get("agents_states")) is dict
            and _json_value(cast(object, row.get("agents_states")))
            and row.get("status") in {"in_progress", "completed", "failed"},
            category,
        )
    if category == "web_search":
        return (
            _keys(row, frozenset({"id", "type", "query", "action"}))
            and _text(row.get("query"))
            and _json_value(row.get("action")),
            category,
        )
    items = row.get("items")
    return (
        _keys(row, frozenset({"id", "type", "items"}))
        and type(items) is list
        and all(
            type(entry) is dict
            and _keys(cast(dict[str, object], entry), frozenset({"text", "completed"}))
            and _text(cast(dict[str, object], entry).get("text"))
            and type(cast(dict[str, object], entry).get("completed")) is bool
            for entry in cast(list[object], items or [])
        ),
        category,
    )


def _validate_wrapper(value: dict[str, object]) -> tuple[ImportLineStatus, str | None, str | None]:
    wrapper_type = value.get("type")
    if type(wrapper_type) is not str:
        return ImportLineStatus.UNSUPPORTED, None, "wrapper_shape_unsupported"
    if wrapper_type not in WRAPPER_TYPES:
        return ImportLineStatus.UNKNOWN, None, "unknown_wrapper_type"
    if wrapper_type == "thread.started":
        valid = _keys(value, frozenset({"type", "thread_id"})) and _text(value.get("thread_id"))
    elif wrapper_type == "turn.started":
        valid = _keys(value, frozenset({"type"}))
    elif wrapper_type == "turn.completed":
        usage = value.get("usage")
        valid = (
            _keys(value, frozenset({"type", "usage"}))
            and type(usage) is dict
            and _keys(
                cast(dict[str, object], usage),
                frozenset(
                    {
                        "input_tokens",
                        "cached_input_tokens",
                        "output_tokens",
                        "reasoning_output_tokens",
                    }
                ),
            )
            and all(_int64(item) for item in cast(dict[str, object], usage).values())
        )
    elif wrapper_type == "turn.failed":
        error = value.get("error")
        valid = (
            _keys(value, frozenset({"type", "error"}))
            and type(error) is dict
            and _keys(cast(dict[str, object], error), frozenset({"message"}))
            and _text(cast(dict[str, object], error).get("message"))
        )
    elif wrapper_type == "error":
        valid = _keys(value, frozenset({"type", "message"})) and _text(value.get("message"))
    else:
        valid = _keys(value, frozenset({"type", "item"}))
        if not valid:
            return ImportLineStatus.UNSUPPORTED, None, "wrapper_shape_unsupported"
        valid, item_type = _validate_item(value.get("item"))
        if not valid:
            reason = (
                "unknown_item_type" if item_type not in ITEM_TYPES else "item_shape_unsupported"
            )
            status = (
                ImportLineStatus.UNKNOWN
                if item_type not in ITEM_TYPES
                else ImportLineStatus.UNSUPPORTED
            )
            return status, item_type, reason
        return ImportLineStatus.MAPPED, item_type, None
    if not valid:
        return ImportLineStatus.UNSUPPORTED, None, "wrapper_shape_unsupported"
    return ImportLineStatus.MAPPED, None, None


def parse_codex_jsonl(source: bytes, profile: CodexCapabilityProfile) -> CodexParseResult:
    """Split and validate exact bytes without IO or source-bearing diagnostics."""

    if (
        type(profile) is not CodexCapabilityProfile
        or SUPPORTED_CODEX_PROFILES.get(profile.cli_version) != profile
    ):
        raise ValueError("unsupported_codex_profile")
    lines = _split_lines(source, profile)
    records: list[CodexParsedRecord] = []
    statuses: list[ImportLineStatus] = []
    reasons: list[str | None] = []
    stream_gaps: set[str] = set()
    for line in lines:
        if len(line.content) > profile.max_line_bytes:
            statuses.append(ImportLineStatus.OVERSIZED)
            reasons.append("line_oversized")
            continue
        try:
            value = _parse_json_line(line.content)
        except TypeError, ValueError, UnicodeError:
            statuses.append(ImportLineStatus.MALFORMED)
            reason = "malformed_line"
            if line.ordinal == len(lines) and not line.terminated:
                reason = "truncated_final_line"
                stream_gaps.add(reason)
            reasons.append(reason)
            continue
        status, item_type, reason = _validate_wrapper(value)
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
        profile,
        lines,
        tuple(records),
        tuple(statuses),
        tuple(reasons),
        tuple(sorted(stream_gaps, key=str.encode)),
    )


def _object(value: object) -> JsonObject:
    frozen = freeze_json(value)
    if type(frozen) is not JsonObject:
        raise ValueError("codex_mapping_value_invalid")
    return frozen


def _mapping_coverage(context: CodexMappingContext, gaps: Sequence[str]) -> Coverage:
    baseline = context.coverage
    return replace(
        baseline,
        authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
        artifact_observation=ArtifactObservation.IMPORT_OBSERVED,
        known_gaps=tuple(sorted(set((*baseline.known_gaps, *gaps)), key=str.encode)),
    )


def _record_item(record: CodexParsedRecord) -> JsonObject:
    item = record.value["item"]
    if type(item) is not JsonObject:
        raise ValueError("codex_mapping_value_invalid")
    return item


def _item_id(record: CodexParsedRecord) -> str:
    value = _record_item(record)["id"]
    if type(value) is not str:
        raise ValueError("codex_mapping_value_invalid")
    return value


def _item_identity(record: CodexParsedRecord) -> JsonValue:
    item = _record_item(record)
    item_type = record.item_type
    if item_type == "command_execution":
        return (item["type"], item["command"])
    if item_type == "file_change":
        return (item["type"], item["changes"])
    if item_type == "mcp_tool_call":
        return (item["type"], item["server"], item["tool"], item["arguments"])
    if item_type == "collab_tool_call":
        return (
            item["type"],
            item["tool"],
            item["sender_thread_id"],
            item["receiver_thread_ids"],
            item["prompt"],
        )
    if item_type == "web_search":
        return (item["type"], item["id"], item["query"])
    return (item["type"],)


def _coherent_group(records: Sequence[CodexParsedRecord]) -> bool:
    if not records:
        return False
    item_type = records[0].item_type
    identity = _item_identity(records[0])
    previous_rank = -1
    terminal = False
    ranks = {"item.started": 0, "item.updated": 1, "item.completed": 2}
    for record in records:
        rank = ranks[record.wrapper_type]
        if (
            record.item_type != item_type
            or _item_identity(record) != identity
            or terminal
            or rank < previous_rank
        ):
            return False
        terminal = rank == 2
        previous_rank = rank
    return True


def _opaque_template(
    context: CodexMappingContext,
    line: CodexSourceLine,
    *,
    category: str | None,
    status: ImportLineStatus,
    gap_code: str,
) -> CodexCandidateTemplate:
    local_key = f"line-{line.ordinal:06d}/opaque"
    payload = _object(
        {
            "byte_end": line.byte_end,
            "byte_start": line.byte_start,
            "gap_codes": (gap_code,),
            "line_ordinal": line.ordinal,
            "mapping_version": context.mapping_version,
            "profile_id": context.profile.profile_id,
            "source_category": category,
            "source_object_id": context.source_object.object_id,
            "status": status.value,
        }
    )
    return CodexCandidateTemplate(
        local_key,
        None,
        "opaque",
        line.ordinal,
        line.byte_start,
        line.byte_end,
        category or "opaque",
        CODEX_OPAQUE_SCHEMA,
        payload,
        (),
        (gap_code,),
    )


def _action_template(
    record: CodexParsedRecord,
) -> tuple[CodexCandidateTemplate, CodexCandidateTemplate | None]:
    item = _record_item(record)
    ordinal = record.line_ordinal
    base = f"line-{ordinal:06d}"
    action_key = f"{base}/action"
    action_id_key = f"{base}/action-id"
    item_type = cast(str, record.item_type)
    gaps = {"source_timestamp_unavailable"}
    action_kind = ActionKind.OTHER
    description = "Imported Codex tool activity."
    command: str | None = None
    attempted: tuple[str, ...] = ()
    if item_type == "command_execution":
        action_kind = ActionKind.COMMAND
        description = "Imported Codex command execution."
        command = cast(str, item["command"])
    elif item_type == "file_change":
        action_kind = ActionKind.EDIT
        description = "Imported Codex file change."
        changes = cast(tuple[JsonValue, ...], item["changes"])
        attempted = tuple(cast(str, cast(JsonObject, change)["path"]) for change in changes)
        gaps.add("file_content_not_captured")
    elif item_type == "web_search":
        action_kind = ActionKind.RESEARCH
        description = "Imported Codex web search."
        attempted = (cast(str, item["query"]),)
        gaps.add("web_results_not_captured")
    elif item_type == "mcp_tool_call":
        description = "Imported Codex MCP tool call."
        attempted = (f"{item['server']}/{item['tool']}",)
    elif item_type == "collab_tool_call":
        description = "Imported Codex collaboration tool call."
    action_payload = _object(
        {
            "action_kind": action_kind.value,
            "attempted_items": attempted,
            "command": command,
            "description": description,
            "logical_id_key": action_id_key,
        }
    )
    action = CodexCandidateTemplate(
        action_key,
        action_id_key,
        "action",
        ordinal,
        record.byte_start,
        record.byte_end,
        item_type,
        EventSchema("action_recorded", "1.0.0"),
        action_payload,
        (),
        tuple(sorted(gaps, key=str.encode)),
    )

    status = item.get("status")
    terminal = record.wrapper_type == "item.completed" or status in {
        "completed",
        "failed",
        "declined",
    }
    if not terminal:
        return action, None
    result_key = f"{base}/result"
    result_id_key = f"{base}/result-id"
    outcome = ResultOutcome.UNKNOWN
    exit_status: int | None = None
    summary: str | None = None
    result_gaps = set(gaps)
    if item_type == "command_execution":
        exit_value = item["exit_code"]
        exit_status = cast(int | None, exit_value)
        if status == "completed" and exit_status == 0:
            outcome = ResultOutcome.SUCCESS
        elif status == "failed" or (exit_status is not None and exit_status != 0):
            outcome = ResultOutcome.FAILURE
        else:
            result_gaps.add("command_outcome_incomplete")
        if status == "declined":
            result_gaps.add("command_declined_not_executed")
        output = cast(str, item["aggregated_output"])
        if len(output.encode("utf-8")) <= MAX_TEXT_BYTES:
            summary = output
        else:
            result_gaps.add("source_text_not_represented")
    elif status == "completed" or item_type == "web_search":
        outcome = ResultOutcome.SUCCESS
    elif status == "failed":
        outcome = ResultOutcome.FAILURE
    else:
        result_gaps.add("result_outcome_incomplete")
    result_payload = _object(
        {
            "action_id_key": action_id_key,
            "exit_status": exit_status,
            "logical_id_key": result_id_key,
            "outcome": outcome.value,
            "summary": summary,
        }
    )
    result = CodexCandidateTemplate(
        result_key,
        result_id_key,
        "result",
        ordinal,
        record.byte_start,
        record.byte_end,
        item_type,
        EventSchema("result_recorded", "1.0.0"),
        result_payload,
        (action_key,),
        tuple(sorted(result_gaps, key=str.encode)),
    )
    return action, result


def plan_codex_mapping(
    parsed: CodexParseResult,
    context: CodexMappingContext,
) -> CodexMappingTemplate:
    """Fold validated records into source-linked candidate templates and explicit gaps."""

    if parsed.profile != context.profile:
        raise ValueError("codex_mapping_profile_mismatch")
    records_by_line = {record.line_ordinal: record for record in parsed.records}
    groups: dict[str, list[CodexParsedRecord]] = {}
    group_for_line: dict[int, str] = {}
    for record in parsed.records:
        if record.item_type is None:
            continue
        source_id = _item_id(record)
        groups.setdefault(source_id, []).append(record)
        group_for_line[record.line_ordinal] = source_id

    candidates: list[CodexCandidateTemplate] = []
    line_candidate_indexes: dict[int, tuple[int, ...]] = {}
    emitted_groups: set[str] = set()
    for line, status, reason in zip(
        parsed.lines, parsed.statuses, parsed.reason_codes, strict=True
    ):
        record = records_by_line.get(line.ordinal)
        group_key = group_for_line.get(line.ordinal)
        if group_key is not None:
            if group_key in emitted_groups:
                continue
            emitted_groups.add(group_key)
            group = groups[group_key]
            if not _coherent_group(group) or group[0].item_type not in MAPPED_ITEM_TYPES:
                gap = (
                    "item_transition_invalid"
                    if not _coherent_group(group)
                    else "source_category_not_mapped"
                )
                indexes: list[int] = []
                for member in group:
                    source_line = parsed.lines[member.line_ordinal - 1]
                    indexes.append(len(candidates))
                    candidates.append(
                        _opaque_template(
                            context,
                            source_line,
                            category=member.item_type,
                            status=ImportLineStatus.UNSUPPORTED,
                            gap_code=gap,
                        )
                    )
                    line_candidate_indexes[member.line_ordinal] = (indexes[-1],)
                continue
            action, result = _action_template(group[-1])
            first_index = len(candidates)
            candidates.append(action)
            indexes = [first_index]
            if result is not None:
                candidates.append(result)
                indexes.append(first_index + 1)
            for member in group:
                line_candidate_indexes[member.line_ordinal] = tuple(indexes)
            continue
        if record is not None:
            gap = "source_category_not_mapped"
            index = len(candidates)
            candidates.append(
                _opaque_template(
                    context,
                    line,
                    category=record.wrapper_type,
                    status=ImportLineStatus.UNSUPPORTED,
                    gap_code=gap,
                )
            )
            line_candidate_indexes[line.ordinal] = (index,)
            continue
        gap = reason or "source_line_unmapped"
        index = len(candidates)
        candidates.append(
            _opaque_template(
                context,
                line,
                category=None,
                status=status,
                gap_code=gap,
            )
        )
        line_candidate_indexes[line.ordinal] = (index,)

    outcomes: list[ImportLineOutcome] = []
    gaps: list[ImportGap] = []
    for line, status, reason in zip(
        parsed.lines, parsed.statuses, parsed.reason_codes, strict=True
    ):
        candidate_indexes = line_candidate_indexes[line.ordinal]
        mapped = all(candidates[index].kind != "opaque" for index in candidate_indexes)
        line_gap = None if mapped else (reason or candidates[candidate_indexes[0]].gap_codes[0])
        source_category = None
        record = records_by_line.get(line.ordinal)
        if record is not None:
            source_category = record.item_type or record.wrapper_type
        outcomes.append(
            ImportLineOutcome(
                line.ordinal,
                line.byte_start,
                line.byte_end,
                (
                    ImportLineStatus.MAPPED
                    if mapped
                    else (
                        status
                        if status is not ImportLineStatus.MAPPED
                        else ImportLineStatus.UNSUPPORTED
                    )
                ),
                source_category,
                candidate_indexes,
                line_gap,
            )
        )
    for candidate in candidates:
        for code in candidate.gap_codes:
            gaps.append(
                ImportGap(
                    code,
                    context.source_object.object_id,
                    candidate.source_line_ordinal,
                    candidate.byte_start,
                    candidate.byte_end,
                    _mapping_coverage(context, (code,)),
                )
            )
    malformed = sum(status is ImportLineStatus.MALFORMED for status in parsed.statuses)
    unknown = sum(
        status
        in {ImportLineStatus.UNKNOWN, ImportLineStatus.UNSUPPORTED, ImportLineStatus.OVERSIZED}
        for status in parsed.statuses
    )
    report_facts = _object(
        {
            "candidate_count": len(candidates),
            "gap_count": len(gaps),
            "line_count": len(parsed.lines),
            "malformed_count": malformed,
            "mapping_version": context.mapping_version,
            "profile_id": context.profile.profile_id,
            "unknown_count": unknown,
        }
    )
    return CodexMappingTemplate(
        context,
        tuple(outcomes),
        tuple(candidates),
        tuple(gaps),
        report_facts,
    )


def _payload_value(payload: JsonObject, key: str, expected: type[object]) -> object:
    value = payload[key]
    if type(value) is not expected:
        raise ValueError("codex_materialization_payload_invalid")
    return value


def materialize_codex_mapping(
    template: CodexMappingTemplate,
    ids: CodexMaterializationIds,
) -> CodexPreparedMapping:
    """Resolve exactly allocated IDs into deterministic drafts and port candidates."""

    if type(template) is not CodexMappingTemplate or type(ids) is not CodexMaterializationIds:
        raise ValueError("codex_materialization_ids_invalid")
    expected_events = {candidate.local_key for candidate in template.candidates}
    expected_logical = {
        candidate.logical_key
        for candidate in template.candidates
        if candidate.logical_key is not None
    }
    if set(ids.event_ids) != expected_events or set(ids.logical_ids) != expected_logical:
        raise ValueError("codex_materialization_ids_invalid")
    if len(set(ids.event_ids.values())) != len(ids.event_ids) or len(
        set(ids.logical_ids.values())
    ) != len(ids.logical_ids):
        raise ValueError("codex_materialization_ids_invalid")

    drafts: list[EventDraft] = []
    port_candidates: list[ImportEventCandidate] = []
    for index, candidate in enumerate(template.candidates):
        event = event_id(ids.event_ids[candidate.local_key])
        parents = tuple(event_id(ids.event_ids[key]) for key in candidate.causal_parent_keys)
        logical_ids: tuple[str, ...] = ()
        intended_refs: tuple[str, ...] = ()
        if candidate.kind == "opaque":
            payload: object = candidate.payload
        elif candidate.kind == "action":
            assert candidate.logical_key is not None
            logical = action_id(ids.logical_ids[candidate.logical_key])
            logical_ids = (str(logical),)
            attempted_raw = candidate.payload["attempted_items"]
            if type(attempted_raw) is not tuple or any(
                type(value) is not str for value in attempted_raw
            ):
                raise ValueError("codex_materialization_payload_invalid")
            command = candidate.payload["command"]
            if command is not None and type(command) is not str:
                raise ValueError("codex_materialization_payload_invalid")
            payload = ActionRecordedPayload(
                logical,
                ActionKind(cast(str, _payload_value(candidate.payload, "action_kind", str))),
                cast(str, _payload_value(candidate.payload, "description", str)),
                command=command,
                attempted_items=cast(tuple[str, ...], attempted_raw),
            )
        else:
            assert candidate.logical_key is not None
            logical = result_id(ids.logical_ids[candidate.logical_key])
            action_key = cast(str, _payload_value(candidate.payload, "action_id_key", str))
            action = action_id(ids.logical_ids[action_key])
            logical_ids = tuple(sorted((str(action), str(logical)), key=str.encode))
            intended_refs = (str(action),)
            exit_status = candidate.payload["exit_status"]
            summary = candidate.payload["summary"]
            if exit_status is not None and type(exit_status) is not int:
                raise ValueError("codex_materialization_payload_invalid")
            if summary is not None and type(summary) is not str:
                raise ValueError("codex_materialization_payload_invalid")
            payload = ResultRecordedPayload(
                logical,
                action,
                ResultOutcome(cast(str, _payload_value(candidate.payload, "outcome", str))),
                exit_status=exit_status,
                summary=summary,
            )
        draft = EventDraft(
            event,
            candidate.target_schema,
            template.context.captured_at,
            parents,
            cast(EventPayload | DomainJsonValue, payload),
            (object_id(template.context.source_object.object_id),),
            (),
        )
        coverage = _mapping_coverage(template.context, candidate.gap_codes)
        drafts.append(draft)
        port_candidates.append(
            ImportEventCandidate(
                index,
                event,
                logical_ids,
                candidate.source_line_ordinal,
                candidate.byte_start,
                candidate.byte_end,
                candidate.target_schema,
                candidate.source_category,
                intended_refs,
                coverage,
                ids.plan_object,
            )
        )
    return CodexPreparedMapping(
        template.line_outcomes,
        tuple(drafts),
        tuple(port_candidates),
        template.gaps,
        template.report_facts,
    )


_BOOLEAN_FLAGS: Final = frozenset(
    {
        "--ephemeral",
        "--ignore-rules",
        "--ignore-user-config",
        "--json",
        "--skip-git-repo-check",
    }
)
_VALUE_OPTIONS: Final = frozenset(
    {
        "--add-dir",
        "--cd",
        "--config",
        "--disable",
        "--enable",
        "--image",
        "--model",
        "--output-last-message",
        "--output-schema",
        "--profile",
        "-C",
        "-c",
    }
)
_ENUM_OPTIONS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "--color": frozenset({"always", "auto", "never"}),
        "--sandbox": frozenset({"danger-full-access", "read-only", "workspace-write"}),
    }
)


def _validated_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, str | bytes | bytearray):
        raise ValueError("codex_argv_invalid")
    values = tuple(argv)
    if len(values) > MAX_ARGV_ITEMS:
        raise ValueError("codex_argv_limit_exceeded")
    total = 0
    for value in values:
        if type(value) is not str or "\x00" in value:
            raise ValueError("codex_argv_invalid")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError("codex_argv_invalid") from exc
        total += len(encoded)
        if total > MAX_ARGV_BYTES:
            raise ValueError("codex_argv_limit_exceeded")
    return values


def sanitize_codex_argv(argv: Sequence[str]) -> SanitizedCodexArgv:
    """Allowlist command-shape metadata while replacing every content-bearing value."""

    values = _validated_argv(argv)
    output: list[str] = []
    omissions: set[str] = set()
    index = 0
    while index < len(values):
        value = values[index]
        if value in {"exec", "resume", "review"}:
            output.append(value)
        elif value in _BOOLEAN_FLAGS:
            output.append(value)
        elif value in _ENUM_OPTIONS:
            output.append(value)
            if index + 1 < len(values) and values[index + 1] in _ENUM_OPTIONS[value]:
                index += 1
                output.append(values[index])
            else:
                output.append(REDACTED_ARG)
                omissions.add("argv_enum_value_removed")
        elif any(value.startswith(f"{option}=") for option in (*_VALUE_OPTIONS, *_ENUM_OPTIONS)):
            option, supplied = value.split("=", 1)
            if option in _ENUM_OPTIONS and supplied in _ENUM_OPTIONS[option]:
                output.append(value)
            else:
                output.extend((option, REDACTED_ARG))
                omissions.add("argv_value_removed")
        elif value in _VALUE_OPTIONS:
            output.append(value)
            if index + 1 < len(values):
                index += 1
            output.append(REDACTED_ARG)
            omissions.add("argv_value_removed")
        elif value.startswith("-"):
            option = value.split("=", 1)[0]
            output.extend((option, REDACTED_ARG))
            omissions.add("argv_unknown_option_removed")
        else:
            output.append(REDACTED_ARG)
            omissions.add("argv_positional_removed")
        index += 1
    return SanitizedCodexArgv(tuple(output), tuple(sorted(omissions, key=str.encode)))


# Older callers and serialized values resolve these types through the public facade.
for _public_name in __all__:
    _public_value = globals().get(_public_name)
    if isinstance(_public_value, type) and _public_value.__module__ == __name__:
        _public_value.__module__ = "yoetz.adapters.importers.codex_jsonl"
