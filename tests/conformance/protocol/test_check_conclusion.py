"""Canonical check outcomes preserve legacy bytes and cannot turn unassessable into proof."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from finishup.domain.events import CheckRecordedPayload, EventSchema, decode_payload, encode_payload
from finishup.domain.values import freeze_json
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance


def _vectors() -> list[dict[str, Any]]:
    path = (
        Path(__file__).resolve().parents[3] / "fixtures/canonical/check-conclusion-1.3.0.case.json"
    )
    return json.loads(path.read_bytes())["input"]["vectors"]


def test_golden_check_outcomes_round_trip_through_schema_and_domain() -> None:
    for vector in _vectors():
        version, wire = vector["schema_version"], vector["payload"]
        validate_schema_instance("check-recorded", version, wire)
        payload = decode_payload(EventSchema("check_recorded", version), wire)
        assert type(payload) is CheckRecordedPayload
        assert payload.semantic_conclusion == wire.get("semantic_conclusion")
        included = wire.get("semantic_included_refs")
        assert payload.semantic_included_refs == (None if included is None else tuple(included))
        encoded = encode_payload(payload)
        assert canonical_encode(encoded).hex() == vector["canonical_hex"]
        assert canonical_digest(encoded) == vector["digest"]


def test_conclusion_is_not_admitted_on_legacy_version_or_absent_on_new_version() -> None:
    current = _vectors()[1]["payload"]
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("check_recorded", "1.2.0"), current)
    missing = {key: value for key, value in current.items() if key != "semantic_conclusion"}
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(missing))
    for value in ("completed", "", 1):
        with pytest.raises(ProtocolValueError):
            decode_payload(
                EventSchema("check_recorded", "1.3.0"),
                freeze_json({**current, "semantic_conclusion": value}),
            )


def test_rulings_and_named_missing_items_share_one_check_version() -> None:
    """Issues #905 and #907 extend the unreleased ``check_recorded`` 1.3.0 in place."""

    missing_only: dict[str, Any] = next(
        vector["payload"]
        for vector in _vectors()
        if vector["schema_version"] == "1.3.0" and "missing_for_assessment" in vector["payload"]
    )
    rulings: list[dict[str, Any]] = [
        {
            "cited_refs": [],
            "finding_id": "fnd_30000000-0000-4000-8000-000000000001",
            "verdict": "unassessable",
        }
    ]
    both: dict[str, Any] = {**missing_only, "prior_finding_verdicts": rulings}
    validate_schema_instance("check-recorded", "1.3.0", both)
    payload = decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(both))
    assert type(payload) is CheckRecordedPayload
    assert payload.prior_finding_verdicts and payload.missing_for_assessment
    # Named missing items belong only to an insufficient_packet conclusion, in schema and domain.
    other: dict[str, Any] = {**both, "semantic_conclusion": "no_material_discrepancy"}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("check-recorded", "1.3.0", other)
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(other))
    # Rulings alone may accompany any completed conclusion.
    ruled: dict[str, Any] = {
        key: value for key, value in other.items() if key != "missing_for_assessment"
    }
    validate_schema_instance("check-recorded", "1.3.0", ruled)
    decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(ruled))
    # Neither field is ever carried by the released 1.2.0 payload.
    for extended in (both, ruled, missing_only):
        legacy = {key: value for key, value in extended.items() if key != "semantic_conclusion"}
        with pytest.raises(ProtocolValueError):
            decode_payload(EventSchema("check_recorded", "1.2.0"), freeze_json(legacy))


def test_check_change_files_ride_only_a_recorded_conclusion_and_stay_closed() -> None:
    """ADR-031 (#883): keyed shown-file commitments, never paths, only beside a conclusion."""

    # ADR-031's vector: found by content, since #907 appends its own 1.3.0 vector as well.
    vector = next(item for item in _vectors() if "check_change_files" in item["payload"])
    wire = vector["payload"]
    payload = decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(wire))
    assert type(payload) is CheckRecordedPayload
    assert payload.check_change_files is not None
    assert payload.check_change_files.fully_shown == tuple(
        wire["check_change_files"]["fully_shown"]
    )
    assert {
        item.commitment: (
            item.shown_bytes,
            item.redactions,
            item.section_admitted,
            item.clean_bytes,
        )
        for item in payload.check_change_files.partially_shown
    } == {
        item["commitment"]: (
            item["shown_bytes"],
            item["redactions"],
            item["section_admitted"],
            item["clean_bytes"],
        )
        for item in wire["check_change_files"]["partially_shown"]
    }
    files = wire["check_change_files"]
    without_conclusion = {key: value for key, value in wire.items() if key != "semantic_conclusion"}
    invalid = [
        (EventSchema("check_recorded", "1.2.0"), without_conclusion),
        (
            EventSchema("check_recorded", "1.3.0"),
            {
                **wire,
                "check_change_files": {
                    **files,
                    "partially_shown": [
                        {
                            "clean_bytes": 1,
                            "commitment": files["fully_shown"][0],
                            "redactions": 0,
                            "section_admitted": False,
                            "shown_bytes": 1,
                        }
                    ],
                },
            },
        ),
        (
            EventSchema("check_recorded", "1.3.0"),
            {
                **wire,
                "check_change_files": {
                    **files,
                    "partially_shown": [{**files["partially_shown"][0], "shown_bytes": -1}],
                },
            },
        ),
        (
            EventSchema("check_recorded", "1.3.0"),
            {
                **wire,
                "check_change_files": {
                    **files,
                    # A clean prefix longer than what was shown.
                    "partially_shown": [{**files["partially_shown"][0], "clean_bytes": 2_000}],
                },
            },
        ),
        (
            EventSchema("check_recorded", "1.3.0"),
            {
                **wire,
                "check_change_files": {
                    **files,
                    "partially_shown": [
                        {
                            key: value
                            for key, value in files["partially_shown"][0].items()
                            if key != "redactions"
                        }
                    ],
                },
            },
        ),
        (
            EventSchema("check_recorded", "1.3.0"),
            {
                **wire,
                "check_change_files": {
                    **files,
                    "partially_shown": [files["partially_shown"][0]["commitment"]],
                },
            },
        ),
        (
            EventSchema("check_recorded", "1.3.0"),
            {**wire, "check_change_files": {**files, "fully_shown": ["src/app.py"]}},
        ),
        (
            EventSchema("check_recorded", "1.3.0"),
            {**wire, "check_change_files": {**files, "extra": 1}},
        ),
    ]
    for schema, candidate in invalid:
        with pytest.raises(ProtocolValueError):
            decode_payload(schema, freeze_json(candidate))
    # A record past its file bound keeps the files it holds: every entry is still true.
    bounded = {**wire, "check_change_files": {**files, "complete": False}}
    validate_schema_instance("check-recorded", "1.3.0", bounded)
    decoded = decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(bounded))
    assert type(decoded) is CheckRecordedPayload and decoded.check_change_files is not None
    assert decoded.check_change_files.complete is False
    assert decoded.check_change_files.fully_shown == tuple(files["fully_shown"])


def test_partial_files_carry_a_view_commitment_and_legacy_rows_still_decode() -> None:
    """R945-02: the golden vector binds each partial view; a row without it stays readable."""

    wire = next(item for item in _vectors() if "check_change_files" in item["payload"])["payload"]
    partial = wire["check_change_files"]["partially_shown"][0]
    assert partial["view_commitment"].startswith("hmac-sha256:")
    payload = decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(wire))
    assert type(payload) is CheckRecordedPayload and payload.check_change_files is not None
    assert (
        payload.check_change_files.partially_shown[0].view_commitment
        == (partial["view_commitment"])
    )
    legacy_partial = {key: value for key, value in partial.items() if key != "view_commitment"}
    legacy = {
        **wire,
        "check_change_files": {**wire["check_change_files"], "partially_shown": [legacy_partial]},
    }
    validate_schema_instance("check-recorded", "1.3.0", freeze_json(legacy))
    decoded = decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(legacy))
    assert type(decoded) is CheckRecordedPayload and decoded.check_change_files is not None
    assert decoded.check_change_files.has_unverified_views()
    for bad in ("", "sha256:" + "0" * 64, 1):
        bad_wire = {
            **wire,
            "check_change_files": {
                **wire["check_change_files"],
                "partially_shown": [{**partial, "view_commitment": bad}],
            },
        }
        with pytest.raises((ProtocolValueError, ValueError)):
            decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(bad_wire))


def test_included_references_bind_to_a_reduced_recorded_conclusion() -> None:
    """Issue #904: only a reduced review with a recorded conclusion carries included references."""

    [reduced] = [
        item["payload"] for item in _vectors() if "semantic_included_refs" in item["payload"]
    ]
    refs: list[str] = list(reduced["semantic_included_refs"])
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("check_recorded", "1.2.0"), freeze_json(reduced))
    unreduced: dict[str, Any] = {
        **reduced,
        "coverage": {**reduced["coverage"], "known_gaps": ["content_unselected"]},
    }
    empty: list[str] = []
    invalid_payloads: list[dict[str, Any]] = [
        unreduced,
        {**reduced, "semantic_included_refs": empty},
        {**reduced, "semantic_included_refs": list(reversed(refs))},
        {**reduced, "semantic_included_refs": ["not-a-ref"]},
    ]
    for invalid in invalid_payloads:
        with pytest.raises(ProtocolValueError):
            decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(invalid))
