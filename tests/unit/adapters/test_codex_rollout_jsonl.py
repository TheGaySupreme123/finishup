"""Exact-profile Codex rollout JSONL parser tests."""

from __future__ import annotations

import base64
import json
from typing import cast

import pytest

from builders.codex_rollout import (
    encode_lines,
    function_call,
    function_call_output,
    item_completed,
    response_item,
    session_meta,
)
from fixture_loader import FixtureLoader, build_fixture_loader
from yoetz.adapters.importers.codex_jsonl import profile_for_codex_version
from yoetz.adapters.importers.codex_rollout_jsonl import (
    CODEX_ROLLOUT_COMPATIBLE_PROFILE_ID,
    COMPATIBLE_ROLLOUT_PROFILE,
    SUPPORTED_ROLLOUT_PROFILES,
    admission_profile_for_rollout_version,
    parse_codex_rollout_jsonl,
    parse_codex_rollout_jsonl_from_offset,
    profile_for_rollout_id,
    profile_for_rollout_version,
    rollout_admission_provenance,
)
from yoetz.adapters.integrations.codex_capability_cells import (
    CODEX_ROLLOUT_CLI_VERSION,
    CODEX_ROLLOUT_COMPATIBLE_EVIDENCE_CASE_IDS,
    CODEX_ROLLOUT_EVIDENCE_CASE_IDS,
    CODEX_ROLLOUT_IMPORTER_PROFILE_ID,
    CODEX_ROLLOUT_PARSER_PROOFS,
    CODEX_ROLLOUT_UNSUPPORTED_EVIDENCE_CASE_IDS,
    codex_version_manifest_profiles,
    rollout_parser_proof,
)
from yoetz.adapters.integrations.codex_skill import CODEX_HARNESS_PROFILE
from yoetz.ports.importer import ImportLineStatus
from yoetz.protocol.canonical import JsonValue

_CANARY_SECRET = "sk-proj-CANARYLEGACYTOKEN0001"
# Every 0.150.1 fixture value carries this prefix; none of it may survive into records.
_CANARY_0150 = "CANARY_0150_"


def _loader() -> FixtureLoader:
    return build_fixture_loader()


def _variant_bytes(path: str, variant: str) -> bytes:
    case = cast(dict[str, JsonValue], _loader().load_json(path))
    variants = cast(dict[str, JsonValue], cast(dict[str, JsonValue], case["input"])["variants"])
    source_block = cast(dict[str, JsonValue], variants[variant])["source"]
    return base64.b64decode(
        cast(str, cast(dict[str, JsonValue], source_block)["bytes_base64"]).encode("ascii"),
        validate=True,
    )


def _expected(path: str, variant: str) -> dict[str, JsonValue]:
    case = cast(dict[str, JsonValue], _loader().load_json(path))
    expected_block = cast(dict[str, JsonValue], case["expected"])
    return cast(
        dict[str, JsonValue], cast(dict[str, JsonValue], expected_block["variants"])[variant]
    )


def test_rollout_profile_is_exact_and_distinct_from_exec() -> None:
    profile = profile_for_rollout_version("0.148.0")
    assert profile.profile_id == CODEX_ROLLOUT_IMPORTER_PROFILE_ID
    with pytest.raises(ValueError, match="unsupported_codex_profile"):
        profile_for_rollout_version("0.139.0")
    with pytest.raises(ValueError, match="unsupported_codex_profile"):
        profile_for_rollout_version("0.149.1")
    exec_profile = profile_for_codex_version("0.139.0")
    assert exec_profile.profile_id != profile.profile_id


def test_legacy_and_paginated_fixtures_map_without_unknown_lines() -> None:
    loader = _loader()
    profile = profile_for_rollout_version("0.148.0")
    for path in (
        "imports/codex/rollout-legacy-0.148.0.case.json",
        "imports/codex/rollout-paginated-0.148.0.case.json",
    ):
        case = cast(dict[str, JsonValue], loader.load_json(path))
        variants = cast(dict[str, JsonValue], cast(dict[str, JsonValue], case["input"])["variants"])
        expected_block = cast(dict[str, JsonValue], case["expected"])
        expected_variants = cast(dict[str, JsonValue], expected_block["variants"])
        for name, variant in variants.items():
            source_block = cast(dict[str, JsonValue], variant)["source"]
            raw = base64.b64decode(
                cast(str, cast(dict[str, JsonValue], source_block)["bytes_base64"]).encode("ascii"),
                validate=True,
            )
            parsed = parse_codex_rollout_jsonl(raw, profile, require_admission=True)
            unknown = sum(status is ImportLineStatus.UNKNOWN for status in parsed.statuses)
            assert unknown == 0
            assert parsed.records
            expected = cast(dict[str, JsonValue], expected_variants[name])
            assert unknown == expected["unknown_count"]
            dumped = json.dumps(
                [dict(record.value) for record in parsed.records],
                default=str,
            )
            assert _CANARY_SECRET not in dumped


def test_truncated_fixture_holds_final_line() -> None:
    loader = _loader()
    case = cast(
        dict[str, JsonValue], loader.load_json("imports/codex/rollout-truncated-0.148.0.case.json")
    )
    variants = cast(dict[str, JsonValue], cast(dict[str, JsonValue], case["input"])["variants"])
    source_block = cast(dict[str, JsonValue], variants["unterminated"])["source"]
    raw = base64.b64decode(
        cast(str, cast(dict[str, JsonValue], source_block)["bytes_base64"]).encode("ascii"),
        validate=True,
    )
    parsed = parse_codex_rollout_jsonl(
        raw, profile_for_rollout_version("0.148.0"), require_admission=True
    )
    assert "final_newline_absent" in parsed.stream_gaps
    assert parsed.lines[-1].terminated is False


def test_compressed_fixture_is_not_jsonl() -> None:
    loader = _loader()
    case = cast(
        dict[str, JsonValue], loader.load_json("imports/codex/rollout-zst-0.148.0.case.json")
    )
    variants = cast(dict[str, JsonValue], cast(dict[str, JsonValue], case["input"])["variants"])
    source_block = cast(dict[str, JsonValue], variants["compressed"])["source"]
    raw = base64.b64decode(
        cast(str, cast(dict[str, JsonValue], source_block)["bytes_base64"]).encode("ascii"),
        validate=True,
    )
    assert raw.startswith(b"\x28\xb5\x2f\xfd")
    parsed = parse_codex_rollout_jsonl(raw, profile_for_rollout_version("0.148.0"))
    assert parsed.records == ()
    assert all(status is ImportLineStatus.MALFORMED for status in parsed.statuses)


def test_redaction_canary_is_stripped_from_records() -> None:
    profile = profile_for_rollout_version("0.148.0")
    source = encode_lines(
        session_meta(),
        response_item(
            {
                "content": [{"text": f"token {_CANARY_SECRET}", "type": "output_text"}],
                "role": "assistant",
                "type": "message",
            }
        ),
        function_call(
            name="mcp__yoetz__status",
            call_id="call_yoetz_1",
            arguments='{"request_id":"req_canary"}',
        ),
        function_call_output(call_id="call_yoetz_1", output="ok"),
    )
    parsed = parse_codex_rollout_jsonl(source, profile, require_admission=True)
    assert all(status is not ImportLineStatus.UNKNOWN for status in parsed.statuses)
    tools = [record.item_type for record in parsed.records]
    assert "function_call" in tools
    assert _CANARY_SECRET not in repr(parsed.records)


def test_secret_assignment_in_valid_output_preserves_json_structure() -> None:
    profile = profile_for_rollout_version("0.148.0")
    source = encode_lines(
        session_meta(),
        function_call(name="shell", call_id="call_secret_output"),
        function_call_output(
            call_id="call_secret_output",
            output=f"api_key={_CANARY_SECRET}",
        ),
    )

    parsed = parse_codex_rollout_jsonl(source, profile, require_admission=True)

    assert parsed.statuses == (
        ImportLineStatus.MAPPED,
        ImportLineStatus.MAPPED,
        ImportLineStatus.MAPPED,
    )
    output = next(record for record in parsed.records if record.item_type == "function_call_output")
    dumped = json.dumps(dict(output.value), default=str)
    assert _CANARY_SECRET not in dumped
    assert "[REDACTED]" in dumped


def test_heuristic_only_assignment_in_output_is_kept() -> None:
    """Issue #982: only high-confidence shapes are redacted at import; egress redacts the rest."""

    profile = profile_for_rollout_version("0.148.0")
    output_text = 'self.bot_token = "<tool_call>"\napi_token = "a8F3kL9qZ2xV7mN4"'
    source = encode_lines(
        session_meta(),
        function_call(name="shell", call_id="call_heuristic_output"),
        function_call_output(call_id="call_heuristic_output", output=output_text),
    )

    parsed = parse_codex_rollout_jsonl(source, profile, require_admission=True)

    output = next(record for record in parsed.records if record.item_type == "function_call_output")
    payload = cast(dict[str, JsonValue], output.value["payload"])
    assert payload["output"] == output_text


def test_wrong_cli_version_is_unsupported_format() -> None:
    """A caller pinned to one exact profile still refuses a header that selects another."""

    profile = profile_for_rollout_version("0.148.0")
    source = encode_lines(
        session_meta(cli_version="0.149.1"),
        function_call(name="shell", call_id="x"),
    )
    parsed = parse_codex_rollout_jsonl(source, profile, require_admission=True)
    assert parsed.records == ()
    assert parsed.stream_gaps == ("unsupported_codex_profile",)
    assert all(status is ImportLineStatus.UNSUPPORTED for status in parsed.statuses)


@pytest.mark.parametrize("history_mode", ["future", None, 1])
def test_unknown_or_invalid_history_mode_is_unsupported_format(history_mode: object) -> None:
    profile = profile_for_rollout_version("0.148.0")
    meta = session_meta()
    payload = cast(dict[str, object], meta["payload"])
    if history_mode is None:
        payload.pop("history_mode")
    else:
        payload["history_mode"] = history_mode
    source = encode_lines(meta, function_call(name="shell", call_id="x"))

    parsed = parse_codex_rollout_jsonl(source, profile, require_admission=True)

    assert parsed.records == ()
    assert parsed.stream_gaps == ("unsupported_codex_profile",)
    assert all(status is ImportLineStatus.UNSUPPORTED for status in parsed.statuses)


def test_unknown_item_type_is_not_mapped_as_clean_coverage() -> None:
    parsed = parse_codex_rollout_jsonl(
        encode_lines(session_meta(), response_item({"type": "future_tool_result"})),
        profile_for_rollout_version("0.148.0"),
        require_admission=True,
    )
    assert ImportLineStatus.UNKNOWN in parsed.statuses
    assert "unknown_item_type" in parsed.reason_codes
    assert all(record.item_type != "future_tool_result" for record in parsed.records)


@pytest.mark.parametrize(
    ("outer_type", "inner_type"),
    [
        ("future_outer_result", "function_call_output"),
        ("item_completed", "future_inner_result"),
    ],
)
def test_unknown_semantic_type_cannot_be_masked_by_nested_item(
    outer_type: str,
    inner_type: str,
) -> None:
    parsed = parse_codex_rollout_jsonl(
        encode_lines(
            session_meta(),
            response_item(
                {
                    "item": {"call_id": "masked", "type": inner_type},
                    "type": outer_type,
                }
            ),
        ),
        profile_for_rollout_version("0.148.0"),
        require_admission=True,
    )

    assert parsed.statuses[-1] is ImportLineStatus.UNKNOWN
    assert parsed.reason_codes[-1] == "unknown_item_type"
    assert len(parsed.records) == 1


def test_exec_jsonl_is_unsupported_codex_profile() -> None:
    profile = profile_for_rollout_version("0.148.0")
    source = (
        b'{"type":"item.completed","item":{"id":"i1","type":"command_execution",'
        b'"command":"echo","aggregated_output":"ok","exit_code":0,"status":"completed"}}\n'
    )
    parsed = parse_codex_rollout_jsonl(source, profile, require_admission=True)
    assert parsed.records == ()
    assert "unsupported_codex_profile" in parsed.stream_gaps
    assert all(status is ImportLineStatus.UNSUPPORTED for status in parsed.statuses)


def test_rollout_fixture_cell_does_not_promote_harness_support() -> None:
    assert CODEX_HARNESS_PROFILE.capability_profile_ids == ()
    assert CODEX_HARNESS_PROFILE.supported_versions == ()
    assert dict(CODEX_HARNESS_PROFILE.hooks_by_capability_profile) == {}
    assert codex_version_manifest_profiles() == ()
    assert CODEX_ROLLOUT_CLI_VERSION == "0.148.0"
    assert CODEX_ROLLOUT_EVIDENCE_CASE_IDS == ("IMP-006", "IMP-007", "IMP-008", "IMP-009")
    assert [proof.cli_version for proof in CODEX_ROLLOUT_PARSER_PROOFS] == ["0.148.0", "0.150.1"]
    assert all(proof.host_support == "unproven" for proof in CODEX_ROLLOUT_PARSER_PROOFS)
    current_proof = rollout_parser_proof("0.150.1")
    assert current_proof is not None
    assert current_proof.evidence_case_ids == ("IMP-011", "IMP-012")
    assert rollout_parser_proof("0.149.1") is None
    assert rollout_parser_proof("0.152.1") is None
    assert rollout_parser_proof("0.153.4") is None
    assert CODEX_ROLLOUT_UNSUPPORTED_EVIDENCE_CASE_IDS == ("IMP-013",)
    assert CODEX_ROLLOUT_COMPATIBLE_EVIDENCE_CASE_IDS == ("IMP-014", "IMP-015")


def test_parser_proofs_and_supported_profiles_name_the_same_exact_versions() -> None:
    proven = {proof.cli_version: proof.profile_id for proof in CODEX_ROLLOUT_PARSER_PROOFS}
    supported = {
        version: profile.profile_id for version, profile in SUPPORTED_ROLLOUT_PROFILES.items()
    }
    assert proven == supported
    for version, profile in SUPPORTED_ROLLOUT_PROFILES.items():
        assert profile.cli_version == version
        assert profile.profile_id == f"codex-rollout-jsonl/{version}/v1"
        assert profile_for_rollout_id(profile.profile_id) is profile
    with pytest.raises(ValueError, match="unsupported_codex_profile"):
        profile_for_rollout_id("codex-rollout-jsonl/0.152.1/v1")
    # Two exact releases are two distinct grammars, not one aliased contract.
    baseline = SUPPORTED_ROLLOUT_PROFILES["0.148.0"]
    current = SUPPORTED_ROLLOUT_PROFILES["0.150.1"]
    assert baseline.contract_digest != current.contract_digest
    # Neither vocabulary contains the other, so semver aliasing in either direction would
    # misclassify real lines.
    assert set(current.item_types) - set(baseline.item_types)
    assert set(baseline.item_types) - set(current.item_types)
    assert set(current.wrapper_types) != set(baseline.wrapper_types)


_PAGINATED_0150 = "imports/codex/rollout-paginated-0.150.1.case.json"
_TRUNCATED_0150 = "imports/codex/rollout-truncated-0.150.1.case.json"
_UNSUPPORTED_0152 = "imports/codex/rollout-unsupported-0.152.1.case.json"


def test_0_150_1_fixture_proves_profile_vocabulary_in_both_directions() -> None:
    profile = profile_for_rollout_version("0.150.1")
    raw = _variant_bytes(_PAGINATED_0150, "paginated")
    expected = _expected(_PAGINATED_0150, "paginated")

    parsed = parse_codex_rollout_jsonl(raw, profile, require_admission=True)

    assert parsed.profile is profile
    assert parsed.stream_gaps == ()
    assert all(status is ImportLineStatus.MAPPED for status in parsed.statuses)
    assert (
        sum(status is ImportLineStatus.UNKNOWN for status in parsed.statuses)
        == expected["unknown_count"]
    )
    # Every admitted wrapper and item type is exercised by the fixture, and the fixture uses
    # nothing outside the profile: the fixture and the profile lock each other.
    wrappers = {record.wrapper_type for record in parsed.records}
    items = {record.item_type for record in parsed.records if record.item_type is not None}
    inner = {
        cast(str, cast(dict[str, object], record.value["payload"]).get("type"))
        for record in parsed.records
        if record.wrapper_type == "event_msg"
    }
    assert wrappers == set(profile.wrapper_types) == set(cast(list[str], expected["wrapper_types"]))
    assert items | inner == set(profile.item_types) == set(cast(list[str], expected["item_types"]))
    meta = cast(dict[str, object], parsed.records[0].value["payload"])
    assert meta["history_mode"] == expected["history_mode"]
    assert all(record.line_ordinal == index + 1 for index, record in enumerate(parsed.records))


def test_0_150_1_fixture_secret_canary_is_redacted_from_records() -> None:
    """Parser records are redacted for secrets only; content stays out at the envelope layer.

    ``test_codex_session_stream`` proves the hidden reasoning, prompt, and message canaries in
    this fixture never reach an observation envelope.
    """

    raw = _variant_bytes(_PAGINATED_0150, "paginated")
    assert _CANARY_0150.encode() in raw
    assert _CANARY_SECRET.encode() in raw

    parsed = parse_codex_rollout_jsonl(raw, None, require_admission=True)

    dumped = json.dumps([dict(record.value) for record in parsed.records], default=str)
    assert _CANARY_SECRET not in dumped
    assert _CANARY_SECRET not in repr(parsed.records)
    assert "[REDACTED]" in dumped
    # Structural identity survives redaction so pairing and dedup still work.
    tool_call = next(record for record in parsed.records if record.item_type == "function_call")
    assert cast(dict[str, object], tool_call.value["payload"])["call_id"] == "call_yoetz_1"


def test_0_150_1_truncated_fixture_holds_live_partial_tail() -> None:
    raw = _variant_bytes(_TRUNCATED_0150, "unterminated")
    parsed = parse_codex_rollout_jsonl(raw, None, require_admission=True)
    assert parsed.profile is profile_for_rollout_version("0.150.1")
    assert "final_newline_absent" in parsed.stream_gaps
    assert parsed.lines[-1].terminated is False
    assert parsed.statuses[0] is ImportLineStatus.MAPPED


def test_unsupported_0_152_1_fixture_is_refused_not_aliased() -> None:
    """IMP-013 now proves structural refusal: its header names an unknown history_mode, so no
    profile (exact or compatible) admits it and the release label plays no part."""

    raw = _variant_bytes(_UNSUPPORTED_0152, "future")
    expected = _expected(_UNSUPPORTED_0152, "future")
    assert b'"history_mode":"streamed"' in raw
    for profile in (None, *SUPPORTED_ROLLOUT_PROFILES.values(), COMPATIBLE_ROLLOUT_PROFILE):
        parsed = parse_codex_rollout_jsonl(raw, profile, require_admission=True)
        assert parsed.profile is None
        assert parsed.records == ()
        assert list(parsed.stream_gaps) == expected["stream_gaps"]
        assert all(status is ImportLineStatus.UNSUPPORTED for status in parsed.statuses)
        assert len(parsed.statuses) == 3


def test_header_selects_exact_profile_without_inference() -> None:
    """An exact release selects its certified profile; every other release selects the
    structural compatibility profile with ``structural`` provenance, never a neighbour's exact
    profile (issue #656)."""

    for version in ("0.148.0", "0.150.1"):
        parsed = parse_codex_rollout_jsonl(
            encode_lines(
                session_meta(cli_version=version, history_mode="paginated", ordinal=1),
                function_call(name="shell", call_id="x", ordinal=2),
            ),
            None,
            require_admission=True,
        )
        assert parsed.profile is SUPPORTED_ROLLOUT_PROFILES[version]
        assert parsed.profile is not None
        assert rollout_admission_provenance(parsed.profile) == "exact"
        assert parsed.stream_gaps == ()
    for version in ("0.149.1", "0.150.0", "0.150.2", "0.152.1", "0.153.4", "0.148", "99.0.0"):
        parsed = parse_codex_rollout_jsonl(
            encode_lines(
                session_meta(cli_version=version), function_call(name="shell", call_id="x")
            ),
            None,
            require_admission=True,
        )
        assert parsed.profile is COMPATIBLE_ROLLOUT_PROFILE
        assert parsed.profile is not None
        assert rollout_admission_provenance(parsed.profile) == "structural"
        assert parsed.profile not in SUPPORTED_ROLLOUT_PROFILES.values()
        assert parsed.stream_gaps == ()
        assert all(status is ImportLineStatus.MAPPED for status in parsed.statuses)
    assert admission_profile_for_rollout_version("0.150.1") == (
        SUPPORTED_ROLLOUT_PROFILES["0.150.1"],
        "exact",
    )
    assert admission_profile_for_rollout_version("0.153.4") == (
        COMPATIBLE_ROLLOUT_PROFILE,
        "structural",
    )
    with pytest.raises(ValueError, match="unsupported_codex_profile"):
        admission_profile_for_rollout_version("0.153.4\u00e9")


def test_compatible_profile_is_the_union_and_not_a_certified_version() -> None:
    assert COMPATIBLE_ROLLOUT_PROFILE.cli_version == "compatible"
    assert COMPATIBLE_ROLLOUT_PROFILE.profile_id == CODEX_ROLLOUT_COMPATIBLE_PROFILE_ID
    assert profile_for_rollout_id(CODEX_ROLLOUT_COMPATIBLE_PROFILE_ID) is (
        COMPATIBLE_ROLLOUT_PROFILE
    )
    with pytest.raises(ValueError, match="unsupported_codex_profile"):
        profile_for_rollout_version("compatible")
    union_wrappers = {
        wrapper for p in SUPPORTED_ROLLOUT_PROFILES.values() for wrapper in p.wrapper_types
    }
    union_items = {item for p in SUPPORTED_ROLLOUT_PROFILES.values() for item in p.item_types}
    # The compatibility vocabulary is the union plus the families admitted as structurally
    # ignored from a real transcript (issue #754). Neither addition reaches an exact profile.
    assert set(COMPATIBLE_ROLLOUT_PROFILE.wrapper_types) == union_wrappers | {"token_usage_record"}
    assert set(COMPATIBLE_ROLLOUT_PROFILE.item_types) == union_items | {"HookPrompt"}
    assert all(
        "token_usage_record" not in p.wrapper_types for p in SUPPORTED_ROLLOUT_PROFILES.values()
    )
    assert all("HookPrompt" not in p.item_types for p in SUPPORTED_ROLLOUT_PROFILES.values())
    # Certification surfaces never grow because the compatibility profile exists.
    assert "compatible" not in SUPPORTED_ROLLOUT_PROFILES
    assert rollout_parser_proof("compatible") is None
    assert rollout_parser_proof("0.153.4") is None


_COMPATIBLE_0153 = "imports/codex/rollout-compatible-0.153.4.case.json"


@pytest.mark.parametrize(
    "variant", ["relabeled", "additive", "unknown_event", "incompatible_known", "truncated"]
)
def test_compatible_0_153_4_fixture_matrix_matches_expectations(variant: str) -> None:
    """Issue #656 differential matrix: the version label alone never disables the stream, unknown
    or malformed lines stay bounded per-line gaps, and independent known lines keep mapping.
    Constructed from the 0.150.1 grammar; no real 0.153.4 transcript was available."""

    raw = _variant_bytes(_COMPATIBLE_0153, variant)
    expected = _expected(_COMPATIBLE_0153, variant)

    parsed = parse_codex_rollout_jsonl(raw, None, require_admission=True)

    assert parsed.profile is COMPATIBLE_ROLLOUT_PROFILE
    assert parsed.profile is not None
    assert rollout_admission_provenance(parsed.profile) == expected["provenance"]
    assert list(parsed.stream_gaps) == expected["stream_gaps"]
    assert (
        sum(status is ImportLineStatus.UNKNOWN for status in parsed.statuses)
        == expected["unknown_count"]
    )
    assert (
        sum(status is ImportLineStatus.UNSUPPORTED for status in parsed.statuses)
        == expected["unsupported_count"]
    )
    reason_codes = sorted({code for code in parsed.reason_codes if code is not None})
    assert reason_codes == expected.get("reason_codes", [])
    meta = cast(dict[str, object], parsed.records[0].value["payload"])
    assert meta["cli_version"] == "0.153.4"
    assert parsed.statuses[0] is ImportLineStatus.MAPPED


_MULTI_AGENT_V2_0153 = "imports/codex/rollout-multi-agent-v2-0.153.4.case.json"


@pytest.mark.parametrize("variant", ["parent", "child", "child_without_identity"])
def test_multi_agent_v2_families_are_understood(variant: str) -> None:
    """Issue #754: every record family a real 0.153.4 multi-agent v2 run emits is understood.

    ``token_usage_record`` is admitted as a structurally ignored family and the fractional leaves
    0.153.4 added to ``agent_message`` and ``token_count`` no longer refuse their lines, so no
    line of a v2 rollout is left an unknown or unsupported per-line gap.
    """

    raw = _variant_bytes(_MULTI_AGENT_V2_0153, variant)
    expected = _expected(_MULTI_AGENT_V2_0153, variant)

    parsed = parse_codex_rollout_jsonl(raw, None, require_admission=True)

    assert parsed.profile is COMPATIBLE_ROLLOUT_PROFILE
    assert parsed.profile is not None
    assert rollout_admission_provenance(parsed.profile) == expected["provenance"]
    assert list(parsed.stream_gaps) == expected["stream_gaps"]
    assert (
        sum(status is ImportLineStatus.UNKNOWN for status in parsed.statuses)
        == expected["unknown_count"]
    )
    assert (
        sum(status is ImportLineStatus.UNSUPPORTED for status in parsed.statuses)
        == expected["unsupported_count"]
    )
    assert [code for code in parsed.reason_codes if code is not None] == []
    assert len(parsed.records) == len(parsed.statuses)


def test_fractional_leaves_are_normalized_instead_of_refusing_the_line() -> None:
    """A float has no canonical value, so the leaf becomes null and the line still maps."""

    raw = _variant_bytes(_MULTI_AGENT_V2_0153, "parent")
    parsed = parse_codex_rollout_jsonl(raw, None, require_admission=True)

    message = next(record for record in parsed.records if record.item_type == "agent_message")
    payload = cast(dict[str, object], message.value["payload"])
    passthrough = cast(dict[str, object], payload["internal_chat_message_metadata_passthrough"])
    assert "create_time" in passthrough
    assert passthrough["create_time"] is None
    assert passthrough["turn_id"] == "turn_1"
    # Author and recipient survive as ordinary payload strings; they are agent-definition
    # paths, not delegation identities, so no structural mapping consumes them.
    assert payload["author"] == "/root/canary_review"


def test_relabeled_release_maps_every_line_the_exact_profile_maps() -> None:
    """Changing only the header version keeps every event of the supported structure."""

    exact = parse_codex_rollout_jsonl(
        _variant_bytes(_PAGINATED_0150, "paginated"), None, require_admission=True
    )
    relabeled = parse_codex_rollout_jsonl(
        _variant_bytes(_COMPATIBLE_0153, "relabeled"), None, require_admission=True
    )
    assert exact.profile is SUPPORTED_ROLLOUT_PROFILES["0.150.1"]
    assert relabeled.profile is COMPATIBLE_ROLLOUT_PROFILE
    assert relabeled.statuses == exact.statuses
    assert [(r.wrapper_type, r.item_type) for r in relabeled.records] == [
        (r.wrapper_type, r.item_type) for r in exact.records
    ]


def test_additive_fields_do_not_break_or_promote_compatible_lines() -> None:
    parsed = parse_codex_rollout_jsonl(
        _variant_bytes(_COMPATIBLE_0153, "additive"), None, require_admission=True
    )
    assert all(status is ImportLineStatus.MAPPED for status in parsed.statuses)
    # The additive fields survive into parser records (the parser is structural, not a content
    # filter); ``test_codex_session_stream`` proves they never reach an observation envelope.
    assert any("x_future_wrapper_field" in record.value for record in parsed.records)


def test_incompatible_known_wrapper_is_bounded_and_invents_no_outcome() -> None:
    parsed = parse_codex_rollout_jsonl(
        _variant_bytes(_COMPATIBLE_0153, "incompatible_known"), None, require_admission=True
    )
    assert parsed.statuses == (
        ImportLineStatus.MAPPED,
        ImportLineStatus.UNSUPPORTED,
        ImportLineStatus.UNSUPPORTED,
        ImportLineStatus.MAPPED,
    )
    assert parsed.reason_codes[1:3] == ("wrapper_shape_unsupported",) * 2
    # No record is minted for the incompatible lines, so nothing downstream can pair or
    # conclude from them; the later known call still maps on its own.
    assert [record.line_ordinal for record in parsed.records] == [1, 4]
    assert parsed.records[-1].item_type == "function_call"


def test_structurally_refused_header_is_refused_under_every_profile() -> None:
    """Refusal is structural: an unknown history_mode refuses regardless of version, and so does
    a header naming an exact release when the caller pinned a different profile."""

    for version in ("0.148.0", "0.150.1", "0.153.4"):
        parsed = parse_codex_rollout_jsonl(
            encode_lines(
                session_meta(cli_version=version, history_mode="streamed"),
                function_call(name="shell", call_id="x"),
            ),
            None,
            require_admission=True,
        )
        assert parsed.profile is None
        assert parsed.stream_gaps == ("unsupported_codex_profile",)
    pinned = parse_codex_rollout_jsonl(
        encode_lines(session_meta(cli_version="0.153.4"), function_call(name="shell", call_id="x")),
        profile_for_rollout_version("0.150.1"),
        require_admission=True,
    )
    assert pinned.profile is None
    assert pinned.stream_gaps == ("unsupported_codex_profile",)
    compatible_pinned = parse_codex_rollout_jsonl(
        encode_lines(session_meta(cli_version="0.153.4"), function_call(name="shell", call_id="x")),
        COMPATIBLE_ROLLOUT_PROFILE,
        require_admission=True,
    )
    assert compatible_pinned.profile is COMPATIBLE_ROLLOUT_PROFILE


def test_explicit_profile_refuses_the_other_supported_release() -> None:
    for held, header in (("0.148.0", "0.150.1"), ("0.150.1", "0.148.0")):
        parsed = parse_codex_rollout_jsonl(
            encode_lines(
                session_meta(cli_version=header), function_call(name="shell", call_id="x")
            ),
            profile_for_rollout_version(held),
            require_admission=True,
        )
        assert parsed.profile is None
        assert parsed.records == ()
        assert parsed.stream_gaps == ("unsupported_codex_profile",)


def test_profile_less_parse_requires_admission() -> None:
    with pytest.raises(ValueError, match="unsupported_codex_profile"):
        parse_codex_rollout_jsonl_from_offset(b"", None, start_ordinal=1, require_admission=False)


def test_0_150_1_item_completed_is_only_admitted_for_its_profile() -> None:
    row = item_completed({"id": "item_1", "type": "AgentMessage"}, ordinal=2)
    current = parse_codex_rollout_jsonl(
        encode_lines(session_meta(cli_version="0.150.1", history_mode="paginated", ordinal=1), row),
        None,
        require_admission=True,
    )
    assert current.statuses == (ImportLineStatus.MAPPED, ImportLineStatus.MAPPED)
    assert current.records[-1].item_type == "AgentMessage"

    baseline = parse_codex_rollout_jsonl(
        encode_lines(session_meta(cli_version="0.148.0", history_mode="paginated", ordinal=1), row),
        None,
        require_admission=True,
    )
    assert baseline.statuses[-1] is ImportLineStatus.UNKNOWN
    assert baseline.reason_codes[-1] == "unknown_item_type"


def test_unknown_shapes_under_0_150_1_stay_bounded_unknown() -> None:
    parsed = parse_codex_rollout_jsonl(
        encode_lines(
            session_meta(cli_version="0.150.1", history_mode="paginated", ordinal=1),
            {
                "ordinal": 2,
                "payload": {"tokens": 1},
                "timestamp": "t",
                "type": "token_usage_record",
            },
            item_completed({"id": "item_2", "type": "FutureItem"}, ordinal=3),
            function_call(name="shell", call_id="after", ordinal=4),
        ),
        None,
        require_admission=True,
    )
    assert parsed.statuses == (
        ImportLineStatus.MAPPED,
        ImportLineStatus.UNKNOWN,
        ImportLineStatus.UNKNOWN,
        ImportLineStatus.MAPPED,
    )
    assert parsed.reason_codes[1:3] == ("unknown_wrapper_type", "unknown_item_type")
    assert [record.item_type for record in parsed.records] == [None, "function_call"]


def test_compatible_fractional_metadata_preserves_the_mapped_message() -> None:
    row = response_item(
        {
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "ok"}],
            "internal_chat_message_metadata_passthrough": {"create_time": 123.5},
        },
        ordinal=2,
    )
    parsed = parse_codex_rollout_jsonl(
        encode_lines(session_meta(cli_version="0.153.4", history_mode="paginated", ordinal=1), row),
        None,
        require_admission=True,
    )
    assert parsed.statuses == (ImportLineStatus.MAPPED, ImportLineStatus.MAPPED)
    payload = cast(dict[str, object], parsed.records[-1].value["payload"])
    metadata = cast(dict[str, object], payload["internal_chat_message_metadata_passthrough"])
    assert metadata["create_time"] is None
    assert payload["role"] == "assistant"


def test_compatible_token_usage_telemetry_is_known_without_promoting_an_exact_cell() -> None:
    parsed = parse_codex_rollout_jsonl(
        encode_lines(
            session_meta(cli_version="0.153.4", history_mode="paginated", ordinal=1),
            {"type": "token_usage_record", "timestamp": "t", "payload": {"tokens": 1}},
        ),
        None,
        require_admission=True,
    )
    assert parsed.profile is COMPATIBLE_ROLLOUT_PROFILE
    assert all(reason is None for reason in parsed.reason_codes)
    assert all(
        "token_usage_record" not in p.wrapper_types for p in SUPPORTED_ROLLOUT_PROFILES.values()
    )


def _hook_prompt(ordinal: int) -> dict[str, object]:
    """The item a Codex 0.159.3 rollout writes when a Stop hook continues the turn (#1041)."""

    return item_completed(
        {
            "fragments": [{"hook_run_id": "stop-1", "text": "CANARY_HOOK_PROMPT_TEXT"}],
            "id": "item_hook_prompt_1",
            "type": "HookPrompt",
        },
        ordinal=ordinal,
    )


def test_compatible_hook_prompt_is_bookkeeping_without_promoting_an_exact_cell() -> None:
    """Yoetz's own Stop-gate prompt row maps on the compatibility profile only (#1041)."""

    compatible = parse_codex_rollout_jsonl(
        encode_lines(
            session_meta(cli_version="0.159.3", history_mode="paginated", ordinal=1),
            _hook_prompt(2),
        ),
        None,
        require_admission=True,
    )
    assert compatible.profile is COMPATIBLE_ROLLOUT_PROFILE
    assert compatible.statuses == (ImportLineStatus.MAPPED, ImportLineStatus.MAPPED)
    assert [record.item_type for record in compatible.records] == [None, "HookPrompt"]
    exact = parse_codex_rollout_jsonl(
        encode_lines(
            session_meta(cli_version="0.150.1", history_mode="paginated", ordinal=1),
            _hook_prompt(2),
        ),
        None,
        require_admission=True,
    )
    assert exact.statuses[1] is ImportLineStatus.UNKNOWN
    assert exact.reason_codes[1] == "unknown_item_type"
