"""Exact-profile, bounded Codex JSONL parser and mapper tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from builders import ids
from finishup.adapters.importers.codex_jsonl import (
    CODEX_JSONL_MAPPING_VERSION,
    CodexMappingContext,
    CodexMaterializationIds,
    materialize_codex_mapping,
    parse_codex_jsonl,
    plan_codex_mapping,
    profile_for_codex_version,
    sanitize_codex_argv,
)
from finishup.domain.values import Timestamp
from finishup.ports.importer import ImportLineStatus
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from finishup.protocol.coverage import (
    AuthorshipAssurance,
    PublicationChannel,
    coverage_for_channel,
)


def _object(kind: ObjectKind, seed: str, size: int) -> ObjectRef:
    return ObjectRef(
        ids.object_id(seed),
        size,
        f"hmac-sha256:{'1' * 64}",
        f"sha256:{'2' * 64}",
        "yoetz-object/1",
        "slot-1",
        ObjectMetadata(
            kind,
            "application/x-ndjson" if kind is ObjectKind.IMPORT_SOURCE else "application/json",
            ids.task_id("codex-task"),
            datetime(2026, 7, 19, 12, tzinfo=UTC),
        ),
    )


def _context(source: ObjectRef) -> CodexMappingContext:
    return CodexMappingContext(
        source,
        source.commitment,
        Timestamp("2026-07-19T12:00:00.000Z"),
        profile_for_codex_version("0.139.0"),
        CODEX_JSONL_MAPPING_VERSION,
        coverage_for_channel(PublicationChannel.CODEX_JSONL_IMPORT),
    )


def test_exact_profile_and_physical_line_contract() -> None:
    profile = profile_for_codex_version("0.139.0")
    with pytest.raises(ValueError, match="unsupported_codex_profile"):
        profile_for_codex_version("0.144.5")

    source = (
        b'{"type":"thread.started","thread_id":"thread-canary"}\r\n'
        b'{"type":"turn.started"}\n'
        b'{"type":"turn.completed","usage":{"input_tokens":1,'
        b'"cached_input_tokens":0,"output_tokens":2,"reasoning_output_tokens":0}}'
    )
    parsed = parse_codex_jsonl(source, profile)
    assert tuple((line.byte_start, line.byte_end) for line in parsed.lines) == (
        (0, 55),
        (55, 79),
        (79, len(source)),
    )
    assert parsed.statuses == (ImportLineStatus.MAPPED,) * 3
    assert parsed.stream_gaps == ("final_newline_absent",)
    assert "thread-canary" not in repr(parsed.records[0])


def test_malformed_unknown_unsupported_and_truncated_are_data_outcomes() -> None:
    source = (
        b'{"type":"future.event","secret":"unknown-canary"}\n'
        b'{"type":"turn.started","extra":true}\n'
        b'{"type":"turn.started","type":"turn.started"}\n'
        b'{"type":"item.completed","item":'
    )
    parsed = parse_codex_jsonl(source, profile_for_codex_version("0.139.0"))
    assert parsed.statuses == (
        ImportLineStatus.UNKNOWN,
        ImportLineStatus.UNSUPPORTED,
        ImportLineStatus.MALFORMED,
        ImportLineStatus.MALFORMED,
    )
    assert parsed.reason_codes == (
        "unknown_wrapper_type",
        "wrapper_shape_unsupported",
        "malformed_line",
        "truncated_final_line",
    )
    assert parsed.stream_gaps == ("final_newline_absent", "truncated_final_line")
    assert "unknown-canary" not in repr(parsed)


def test_command_mapping_materializes_stable_import_candidates_without_leakage() -> None:
    source_bytes = (
        b'{"type":"thread.started","thread_id":"source-thread"}\n'
        b'{"type":"turn.started"}\n'
        b'{"type":"item.completed","item":{"id":"source-item","type":'
        b'"command_execution","command":"secret-command-canary","aggregated_output":'
        b'"secret-output-canary","exit_code":0,"status":"completed"}}\n'
    )
    source = _object(ObjectKind.IMPORT_SOURCE, "source", len(source_bytes))
    parsed = parse_codex_jsonl(source_bytes, profile_for_codex_version("0.139.0"))
    template = plan_codex_mapping(parsed, _context(source))
    assert len(template.candidates) == 4  # lifecycle opaque rows plus action/result
    assert "secret-command-canary" not in repr(template.candidates[-2])

    event_ids = {
        candidate.local_key: ids.event_id(f"codex-event-{index}")
        for index, candidate in enumerate(template.candidates)
    }
    logical_ids = {
        candidate.logical_key: (
            ids.action_id("codex-action")
            if candidate.kind == "action"
            else ids.result_id("codex-result")
        )
        for candidate in template.candidates
        if candidate.logical_key is not None
    }
    prepared = materialize_codex_mapping(
        template,
        CodexMaterializationIds(
            event_ids,
            logical_ids,
            _object(ObjectKind.IMPORT_PLAN, "plan", 10),
        ),
    )
    assert tuple(draft.schema.name for draft in prepared.event_drafts) == (
        "codex_jsonl_observation",
        "codex_jsonl_observation",
        "action_recorded",
        "result_recorded",
    )
    assert prepared.event_drafts[-1].causal_parents == (prepared.event_drafts[-2].event_id,)
    assert all(
        candidate.coverage.publication_channels == (PublicationChannel.CODEX_JSONL_IMPORT,)
        and candidate.coverage.authorship_assurance is AuthorshipAssurance.HARNESS_OBSERVED
        for candidate in prepared.candidates
    )
    assert "secret-command-canary" not in repr(prepared)
    assert "secret-output-canary" not in repr(prepared)


def test_caps_and_argv_allowlist_fail_closed() -> None:
    profile = profile_for_codex_version("0.139.0")
    with pytest.raises(ValueError, match="import_source_limit_exceeded"):
        parse_codex_jsonl(b"x" * (profile.max_source_bytes + 1), profile)

    narrowed = replace(profile, max_line_bytes=profile.max_line_bytes)
    assert narrowed == profile
    sanitized = sanitize_codex_argv(
        ("codex", "exec", "--json", "--model", "secret-model", "secret prompt")
    )
    assert sanitized.argv == (
        "<redacted>",
        "exec",
        "--json",
        "--model",
        "<redacted>",
        "<redacted>",
    )
    assert sanitized.omission_codes == ("argv_positional_removed", "argv_value_removed")
    assert "secret-model" not in repr(sanitized)
    assert "secret prompt" not in repr(sanitized)
