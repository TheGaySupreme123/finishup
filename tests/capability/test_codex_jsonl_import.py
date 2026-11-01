"""Observed Codex JSONL import capability evidence from reviewed fixtures.

Non-live cells feed exact fixture bytes through the installed importer under multiple chunk
boundaries. Live capture from ``codex exec --json`` is opt-in via ``FINISHUP_LIVE_CODEX=1``.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import cast

import pytest

from capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    live_codex_authorized,
    record_and_write,
    runtime_capability_context,
)
from finishup.adapters.importers.codex_jsonl import (
    parse_codex_jsonl,
    profile_for_codex_version,
    sanitize_codex_argv,
)
from finishup.ports.importer import ImportLineStatus
from finishup.protocol.canonical import JsonValue, canonical_digest
from fixture_loader import FixtureLoader

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_PROFILE_VERSION = "0.139.0"

_FIXTURES = (
    "imports/codex/supported-version.case.json",
    "imports/codex/unknown-events.case.json",
    "imports/codex/malformed-lines.case.json",
    "imports/codex/truncated-stream.case.json",
    "imports/codex/secret-redaction.case.json",
)


def _source_from_variant_block(variant_block: dict[str, JsonValue]) -> bytes:
    source = cast(dict[str, JsonValue], variant_block["source"])
    if "bytes_base64" in source:
        return base64.b64decode(cast(str, source["bytes_base64"]).encode("ascii"), validate=True)
    raise KeyError("bytes_base64")


def _iter_sources(case: dict[str, JsonValue]) -> tuple[tuple[str, bytes], ...]:
    input_block = cast(dict[str, JsonValue], case["input"])
    if "variants" in input_block:
        variants = cast(dict[str, JsonValue], input_block["variants"])
        return tuple(
            (name, _source_from_variant_block(cast(dict[str, JsonValue], block)))
            for name, block in variants.items()
        )
    if "source" in input_block:
        source = cast(dict[str, JsonValue], input_block["source"])
        return (("source", _source_from_variant_block({"source": source})),)
    raise KeyError("source")


def _chunkings(data: bytes) -> tuple[tuple[bytes, ...], ...]:
    if not data:
        return ((),)
    return (
        (data,),
        tuple(data[index : index + 1] for index in range(len(data))),
        tuple(data[index : index + 17] for index in range(0, len(data), 17)),
    )


def _reassemble(chunks: tuple[bytes, ...]) -> bytes:
    return b"".join(chunks)


@pytest.mark.parametrize("fixture_path", _FIXTURES)
def test_reviewed_fixture_import_is_conservative_and_chunk_stable(
    fixture_loader: FixtureLoader,
    fixture_path: str,
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    case = cast(dict[str, JsonValue], fixture_loader.load_json(fixture_path))
    fixture_id = cast(str, case["fixture_id"])
    sources = _iter_sources(case)
    profile = profile_for_codex_version(_PROFILE_VERSION)

    mapped_total = 0
    unknown_or_malformed = 0
    for _name, source in sources:
        statuses: list[ImportLineStatus] | None = None
        for chunks in _chunkings(source):
            parsed = parse_codex_jsonl(_reassemble(chunks), profile)
            if statuses is None:
                statuses = list(parsed.statuses)
            else:
                assert list(parsed.statuses) == statuses
        assert statuses is not None
        mapped_total += sum(status is ImportLineStatus.MAPPED for status in statuses)
        unknown_or_malformed += sum(
            status in {ImportLineStatus.UNKNOWN, ImportLineStatus.MALFORMED} for status in statuses
        )

    fixture_digest = bytes_digest(fixture_loader.load_bytes(fixture_path))
    config_digest = canonical_digest(
        {
            "fixture_id": fixture_id,
            "mapping_version": "codex-jsonl/1.0.0",
            "profile": profile.profile_id,
        }
    )
    context = runtime_capability_context(
        fixture_digest=fixture_digest,
        test_revision=_TEST_REVISION,
        config_profile_digest=config_digest,
        external_tool="codex",
        external_version=_PROFILE_VERSION,
        integration_channel="codex_jsonl_import",
    )
    case_def = CapabilityCase(
        case_id=fixture_id,
        requirement_id="ADR-005.jsonl-import",
        claim_id="E-002.jsonl-import",
        capability_family="codex_jsonl_import",
        required_observation_codes=frozenset(
            {"mapped_line_count", "unknown_or_malformed_count", "chunkings_agree"}
        ),
        allowed_observation_codes=frozenset(
            {
                "mapped_line_count",
                "unknown_or_malformed_count",
                "chunkings_agree",
                "source_digest_bound",
            }
        ),
    )
    evidence = record_and_write(
        case_def,
        context,
        (
            Observation("mapped_line_count", integer_value=mapped_total),
            Observation("unknown_or_malformed_count", integer_value=unknown_or_malformed),
            Observation("chunkings_agree", boolean_value=True),
            Observation("source_digest_bound", digest_value=bytes_digest(sources[0][1])),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


def test_secret_canaries_stay_out_of_structural_import_views(
    fixture_loader: FixtureLoader, tmp_path: Path
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    path = "imports/codex/secret-redaction.case.json"
    case = cast(dict[str, JsonValue], fixture_loader.load_json(path))
    sources = _iter_sources(case)
    source = sources[0][1]
    parsed = parse_codex_jsonl(source, profile_for_codex_version(_PROFILE_VERSION))
    structural = repr(parsed)
    assert "/Users/" not in structural
    input_block = cast(dict[str, JsonValue], case["input"])
    canaries = input_block.get("canaries", ())
    assert isinstance(canaries, list)
    for entry in canaries:
        assert isinstance(entry, dict)
        value = entry.get("value")
        if type(value) is str and value:
            assert value not in structural

    argv = sanitize_codex_argv(("codex", "exec", "--json", "--model", "secret-model", "prompt"))
    assert "secret-model" not in repr(argv)

    context = runtime_capability_context(
        fixture_digest=bytes_digest(fixture_loader.load_bytes(path)),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "imp005-canary"}),
        external_tool="codex",
        external_version=_PROFILE_VERSION,
        integration_channel="codex_jsonl_import",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="IMP-005-canary",
            requirement_id="ADR-005.jsonl-import",
            claim_id="E-002.jsonl-secret-boundary",
            capability_family="codex_jsonl_import",
            required_observation_codes=frozenset({"structural_view_safe"}),
            allowed_observation_codes=frozenset({"structural_view_safe", "argv_sanitized"}),
        ),
        context,
        (
            Observation("structural_view_safe", boolean_value=True),
            Observation("argv_sanitized", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


def test_unsupported_newer_codex_profile_is_not_guessed(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="unsupported_codex_profile"):
        profile_for_codex_version("0.144.5")
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"unsupported-profile-0.144.5"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"external_version": "0.144.5"}),
        external_tool="codex",
        external_version="0.144.5",
        integration_channel="codex_jsonl_import",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="IMP-006",
            requirement_id="ADR-005.jsonl-import",
            claim_id="E-002.jsonl-import",
            capability_family="codex_jsonl_import",
            required_observation_codes=frozenset({"profile_admitted"}),
            allowed_observation_codes=frozenset({"profile_admitted"}),
        ),
        context,
        (Observation("profile_admitted", boolean_value=False),),
        EvidenceOutcome.UNSUPPORTED,
        ("unsupported_codex_profile",),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED


@pytest.mark.live
def test_live_codex_exec_json_capture(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"live-jsonl-capture"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "live-jsonl"}),
        external_tool="codex",
        external_version=_PROFILE_VERSION,
        integration_channel="codex_jsonl_import",
    )
    if not live_codex_authorized():
        evidence = record_and_write(
            CapabilityCase(
                case_id="IMP-LIVE-001",
                requirement_id="ADR-005.jsonl-import",
                claim_id="E-002.jsonl-import-live",
                capability_family="codex_jsonl_import",
                required_observation_codes=frozenset({"live_authorized"}),
                allowed_observation_codes=frozenset({"live_authorized"}),
            ),
            context,
            (Observation("live_authorized", boolean_value=False),),
            EvidenceOutcome.UNSUPPORTED,
            ("live_codex_not_authorized",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return
    pytest.fail("live Codex JSONL capture authorized; capture corpus before claiming pass")
