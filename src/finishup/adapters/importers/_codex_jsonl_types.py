"""Shared parser values and exact profiles, independent of ledger materialization."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from finishup.domain.values import JsonObject
from finishup.ports.importer import ImportLineStatus
from finishup.protocol.canonical import canonical_digest

CODEX_JSONL_MAPPING_VERSION: Final = "codex-jsonl/1.0.0"

_MAX_SOURCE_BYTES: Final = 4_194_304
_MAX_LINE_BYTES: Final = 1_048_576
_MAX_LINES: Final = 20_000
MAX_ARGV_ITEMS: Final = 256
MAX_ARGV_BYTES: Final = 65_536
MAX_JSON_DEPTH: Final = 64
INT64_MIN: Final = -(2**63)
INT64_MAX: Final = 2**63 - 1
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$", re.ASCII)
REDACTED_ARG: Final = "<redacted>"

WRAPPER_TYPES: Final = (
    "error",
    "item.completed",
    "item.started",
    "item.updated",
    "thread.started",
    "turn.completed",
    "turn.failed",
    "turn.started",
)
ITEM_TYPES: Final = (
    "agent_message",
    "collab_tool_call",
    "command_execution",
    "error",
    "file_change",
    "mcp_tool_call",
    "reasoning",
    "todo_list",
    "web_search",
)
MAPPED_ITEM_TYPES: Final = frozenset(
    {"collab_tool_call", "command_execution", "file_change", "mcp_tool_call", "web_search"}
)


def _profile_digest() -> str:
    return canonical_digest(
        {
            "cli_version": "0.139.0",
            "item_types": ITEM_TYPES,
            "max_line_bytes": _MAX_LINE_BYTES,
            "max_lines": _MAX_LINES,
            "max_source_bytes": _MAX_SOURCE_BYTES,
            "profile_id": "codex-exec-jsonl/0.139.0/v1",
            "wrapper_types": WRAPPER_TYPES,
        }
    )


@dataclass(frozen=True, slots=True)
class CodexCapabilityProfile:
    cli_version: str
    profile_id: str
    contract_digest: str
    wrapper_types: tuple[str, ...]
    item_types: tuple[str, ...]
    max_source_bytes: int = _MAX_SOURCE_BYTES
    max_line_bytes: int = _MAX_LINE_BYTES
    max_lines: int = _MAX_LINES

    def __post_init__(self) -> None:
        if (
            type(self.cli_version) is not str
            or type(self.profile_id) is not str
            or _TOKEN.fullmatch(self.profile_id) is None
            or type(self.contract_digest) is not str
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.contract_digest)
            or type(self.wrapper_types) is not tuple
            or type(self.item_types) is not tuple
            or self.wrapper_types != tuple(sorted(set(self.wrapper_types), key=str.encode))
            or self.item_types != tuple(sorted(set(self.item_types), key=str.encode))
            or self.max_source_bytes != _MAX_SOURCE_BYTES
            or self.max_line_bytes != _MAX_LINE_BYTES
            or self.max_lines != _MAX_LINES
        ):
            raise ValueError("codex_profile_invalid")


_BASELINE_PROFILE = CodexCapabilityProfile(
    "0.139.0",
    "codex-exec-jsonl/0.139.0/v1",
    _profile_digest(),
    WRAPPER_TYPES,
    ITEM_TYPES,
)
SUPPORTED_CODEX_PROFILES: Final[Mapping[str, CodexCapabilityProfile]] = MappingProxyType(
    {_BASELINE_PROFILE.cli_version: _BASELINE_PROFILE}
)


@dataclass(frozen=True, slots=True, repr=False)
class CodexSourceLine:
    ordinal: int
    byte_start: int
    byte_end: int
    content: bytes
    terminated: bool

    def __post_init__(self) -> None:
        if (
            type(self.ordinal) is not int
            or not 1 <= self.ordinal <= _MAX_LINES
            or type(self.byte_start) is not int
            or type(self.byte_end) is not int
            or not 0 <= self.byte_start < self.byte_end <= _MAX_SOURCE_BYTES
            or type(self.content) is not bytes
            or type(self.terminated) is not bool
        ):
            raise ValueError("codex_source_line_invalid")

    def __repr__(self) -> str:
        return "CodexSourceLine(<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True, repr=False)
class CodexParsedRecord:
    line_ordinal: int
    byte_start: int
    byte_end: int
    wrapper_type: str
    item_type: str | None
    value: JsonObject

    def __post_init__(self) -> None:
        if (
            type(self.line_ordinal) is not int
            or not 1 <= self.line_ordinal <= _MAX_LINES
            or type(self.byte_start) is not int
            or type(self.byte_end) is not int
            or not 0 <= self.byte_start < self.byte_end <= _MAX_SOURCE_BYTES
            or type(self.wrapper_type) is not str
            or (self.item_type is not None and type(self.item_type) is not str)
            or type(self.value) is not JsonObject
        ):
            raise ValueError("codex_parsed_record_invalid")

    def __repr__(self) -> str:
        return "CodexParsedRecord(<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class CodexParseResult:
    # The exact profile that admitted this source, or ``None`` when a header-selected parse
    # admitted nothing (the rollout stream reader refuses such a chunk durably).
    profile: CodexCapabilityProfile | None
    lines: tuple[CodexSourceLine, ...]
    records: tuple[CodexParsedRecord, ...]
    statuses: tuple[ImportLineStatus, ...]
    reason_codes: tuple[str | None, ...]
    stream_gaps: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            (self.profile is not None and type(self.profile) is not CodexCapabilityProfile)
            or type(self.lines) is not tuple
            or type(self.records) is not tuple
            or type(self.statuses) is not tuple
            or type(self.reason_codes) is not tuple
            or len(self.lines) != len(self.statuses)
            or len(self.lines) != len(self.reason_codes)
            or any(type(line) is not CodexSourceLine for line in self.lines)
            or any(type(record) is not CodexParsedRecord for record in self.records)
            or any(type(status) is not ImportLineStatus for status in self.statuses)
            or any(reason is not None and type(reason) is not str for reason in self.reason_codes)
            or self.stream_gaps != tuple(sorted(set(self.stream_gaps), key=str.encode))
        ):
            raise ValueError("codex_parse_result_invalid")


# Preserve the original public class identity for older serialized test/import values.
for _public_type in (CodexCapabilityProfile, CodexSourceLine, CodexParsedRecord, CodexParseResult):
    _public_type.__module__ = "finishup.adapters.importers.codex_jsonl"
