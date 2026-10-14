"""Codex JSONL API with ledger mapping loaded only when an importer requests it."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from yoetz.adapters.importers._codex_jsonl_types import (
    CODEX_JSONL_MAPPING_VERSION,
    SUPPORTED_CODEX_PROFILES,
    CodexCapabilityProfile,
    CodexParsedRecord,
    CodexParseResult,
    CodexSourceLine,
)

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

if TYPE_CHECKING:
    from yoetz.adapters.importers._codex_jsonl_impl import (
        CODEX_OPAQUE_SCHEMA,
        CodexCandidateTemplate,
        CodexMappingContext,
        CodexMappingTemplate,
        CodexMaterializationIds,
        CodexPreparedMapping,
        SanitizedCodexArgv,
        materialize_codex_mapping,
        parse_codex_jsonl,
        parse_codex_jsonl_from_offset,
        plan_codex_mapping,
        profile_for_codex_version,
        sanitize_codex_argv,
        split_codex_jsonl_chunk,
    )


def __getattr__(name: str) -> object:
    if name.startswith("__"):
        raise AttributeError(name)
    implementation = import_module("yoetz.adapters.importers._codex_jsonl_impl")
    value: object = getattr(implementation, name)
    globals()[name] = value
    return value
