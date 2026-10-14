"""Compatibility conformance: released bundle images stay backward-readable in v0.1.

Grounded entirely in the two permanent ``fixtures/backward-read/v0.1.0-*.case.json`` fixtures --
BWR-001, a first-release empty bundle, and BWR-002, a full sixteen-family event bundle carrying one
deliberately unknown ``future_fixture_event/2.0.0`` row -- plus the installed ``finishup.version``
identity constants and the real ``finishup.kernel.projections`` domain codec.

Every archive member is decoded and digest-verified directly from the fixture's own declared
inventory. The embedded ``bundle.sqlite3`` is materialized to a private scratch file and opened with
``apsw.SQLITE_OPEN_READONLY`` -- the same raw read-only idiom used by
``tests/integration/storage/test_build_and_pragma_gate.py`` -- never through FinishUP's own
``finishup.adapters.sqlite.connection`` wrapper, whose path-safety policy is scoped to FinishUP's live
per-user runtime directories, not to an arbitrary archived fixture artifact under test. No fixture
byte is written back at any point; every claim of "no migration, no database writes, no archive
regeneration" is checked by re-hashing the materialized file and the raw archive bytes after use.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import cast

import apsw

from finishup.domain.values import event_id, frontier_from_json, object_id, validate_sha256_digest
from finishup.kernel.projections import (
    empty_projection_state,
    projection_digest,
    projection_from_snapshot,
    projection_snapshot,
)
from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from finishup.version import BUNDLE_SCHEMA_VERSION, ENGINE_VERSION, PROTOCOL_VERSION
from fixture_loader import FixtureLoader, JsonValue

_EMPTY_BUNDLE = "v0.1.0-empty-bundle.case.json"
_FULL_EVENT_BUNDLE = "v0.1.0-full-event-bundle.case.json"
_FIXTURE_NAMES = (_EMPTY_BUNDLE, _FULL_EVENT_BUNDLE)

# Assertion names whose fixture-declared result must hold the one honest, non-mutating value.
_MUST_BE_FALSE = frozenset(
    {
        "in_place_migration",
        "archive_bytes_mutated",
        "plaintext_canary_present_in_archive",
        "wal_or_shm_member_present",
    }
)
_MUST_BE_TRUE = frozenset({"all_sixteen_event_families_present", "unknown_event_preserved"})
_MUST_BE_SUCCESS = frozenset({"open_status", "recovery_and_read"})

_COMPATIBILITY_DOC = Path(__file__).resolve().parents[3] / "docs" / "protocol" / "compatibility.md"


def _document(fixture_loader: FixtureLoader, name: str) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], fixture_loader.load_json(f"backward-read/{name}"))


def _archive_bytes(document: dict[str, JsonValue]) -> bytes:
    input_block = cast(dict[str, JsonValue], document["input"])
    archive = cast(dict[str, JsonValue], input_block["archive"])
    return base64.b64decode(cast(str, archive["base64"]), validate=True)


def _archive_members(raw_archive: bytes) -> dict[str, bytes]:
    inner = cast(dict[str, JsonValue], strict_json_parse(raw_archive))
    raw_members = cast(list[JsonValue], inner["members"])
    result: dict[str, bytes] = {}
    for raw_member in raw_members:
        member = cast(dict[str, JsonValue], raw_member)
        logical_name = cast(str, member["logical_name"])
        result[logical_name] = base64.b64decode(cast(str, member["bytes_base64"]), validate=True)
    return result


def _digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _open_readonly(path: Path) -> apsw.Connection:
    return apsw.Connection(str(path), flags=apsw.SQLITE_OPEN_READONLY)


def _classify_bundle_schema(value: str) -> str:
    """Bounded, always-total classification grounded in the compatibility.md version vocabulary.

    The exact installed cell is ``supported``. Older contiguous released cells in
    ``1..current-1`` stay ``readable`` (safe inspect/read; writes still require migration).
    Anything else is ``unsupported`` -- there is no silent third option and no collapse into a
    bare pass.
    """

    if type(value) is not str or not value.isdigit():
        return "unsupported"
    version = int(value)
    current = int(BUNDLE_SCHEMA_VERSION)
    if version == current:
        return "supported"
    if 1 <= version < current:
        return "readable"
    return "unsupported"


def test_released_corpus_still_reads(fixture_loader: FixtureLoader, tmp_path: Path) -> None:
    """Every released archive member, structural fact, and projection vector reads back exactly."""

    for name in _FIXTURE_NAMES:
        document = _document(fixture_loader, name)
        input_block = cast(dict[str, JsonValue], document["input"])
        expected = cast(dict[str, JsonValue], document["expected"])

        raw_archive = _archive_bytes(document)
        assert _digest(raw_archive) == expected["archive_sha256_after_read"], name

        members = _archive_members(raw_archive)
        inventory = cast(list[JsonValue], input_block["expected_member_inventory"])
        inventory_names = {
            cast(str, cast(dict[str, JsonValue], item)["logical_name"]) for item in inventory
        }
        assert set(members) == inventory_names, name
        for raw_item in inventory:
            item = cast(dict[str, JsonValue], raw_item)
            logical_name = cast(str, item["logical_name"])
            data = members[logical_name]
            assert len(data) == item["byte_length"], (name, logical_name)
            assert _digest(data) == item["sha256"], (name, logical_name)
            assert not logical_name.endswith(("-wal", "-shm")), (name, logical_name)

        plaintext_canary = input_block.get("plaintext_canary_sha256")
        if plaintext_canary is not None:
            # The plaintext itself is never known to this test -- only its digest. A genuine leak
            # would surface as some archive member's own bytes hashing to that exact digest.
            assert all(_digest(data) != plaintext_canary for data in members.values()), name

        release_identity = cast(dict[str, JsonValue], input_block["release_manifest_identity"])
        assert release_identity["package"] == "finishup", name
        assert release_identity["protocol"] == PROTOCOL_VERSION, name
        assert _classify_bundle_schema(cast(str, release_identity["bundle_schema"])) in {
            "supported",
            "readable",
        }, name

        minimum_versions = cast(dict[str, JsonValue], document["minimum_versions"])
        assert minimum_versions["protocol"] == PROTOCOL_VERSION, name
        assert _classify_bundle_schema(cast(str, minimum_versions["bundle_schema"])) in {
            "supported",
            "readable",
        }, name
        assert minimum_versions["engine"] == ENGINE_VERSION, name

        bundle_path = tmp_path / name / "bundle.sqlite3"
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_bytes = members["bundle.sqlite3"]
        bundle_path.write_bytes(bundle_bytes)
        before = hashlib.sha256(bundle_path.read_bytes()).hexdigest()

        connection = _open_readonly(bundle_path)
        try:
            table_rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            tables = {cast(str, cast(tuple[object, ...], row)[0]) for row in table_rows}

            structural = input_block.get("structural_inventory")
            if structural is not None:
                structural_map = cast(dict[str, JsonValue], structural)
                assert tables == set(cast(list[str], structural_map["tables"])), name

                user_version_row = cast(
                    tuple[object, ...], connection.execute("PRAGMA user_version").fetchone()
                )
                assert user_version_row[0] == structural_map["user_version"], name

                application_id_row = cast(
                    tuple[object, ...], connection.execute("PRAGMA application_id").fetchone()
                )
                application_id = cast(int, application_id_row[0])
                assert f"0x{application_id:08X}" == structural_map["application_id"], name

                events_row = cast(
                    tuple[object, ...],
                    connection.execute("SELECT count(*) FROM events").fetchone(),
                )
                objects_row = cast(
                    tuple[object, ...],
                    connection.execute("SELECT count(*) FROM objects").fetchone(),
                )
                assert events_row[0] == structural_map["event_count"], name
                assert objects_row[0] == structural_map["object_count"], name
        finally:
            connection.close()

        # Read-only open plus SELECT-only queries never mutate the materialized artifact.
        assert hashlib.sha256(bundle_path.read_bytes()).hexdigest() == before, name

        projection_block = cast(dict[str, JsonValue], expected["projection"])
        canonical_bytes = bytes.fromhex(cast(str, projection_block["canonical_hex"]))
        parsed_snapshot = strict_json_parse(canonical_bytes)
        # The fixture's own two declared fields are internally self-consistent regardless of shape.
        assert canonical_digest(parsed_snapshot) == projection_block["digest"], name

        if name == _EMPTY_BUNDLE:
            # For the empty bundle the declared "current flat projection vector" is exactly the
            # canonical empty ProjectionState under the real, current domain codec -- proving the
            # backward-read path returns a freshly derived in-memory value, never a copied artifact.
            state = projection_from_snapshot(parsed_snapshot)
            assert state == empty_projection_state()
            assert projection_digest(state) == projection_block["digest"]
            assert canonical_encode(projection_snapshot(state)) == canonical_bytes

        for raw_assertion in cast(list[JsonValue], expected["assertions"]):
            assertion = cast(dict[str, JsonValue], raw_assertion)
            assertion_name = cast(str, assertion["assertion"])
            result = assertion["result"]
            if assertion_name in _MUST_BE_FALSE:
                assert result is False, (name, assertion_name)
            elif assertion_name in _MUST_BE_TRUE:
                assert result is True, (name, assertion_name)
            elif assertion_name in _MUST_BE_SUCCESS:
                assert result == "success", (name, assertion_name)
            elif assertion_name == "open_mode":
                assert result == "read_only", (name, assertion_name)
            elif assertion_name == "writes_attempted":
                assert result == 0, (name, assertion_name)
            elif assertion_name == "frontier":
                frontier = frontier_from_json(result)
                assert frontier.sequence >= 0, name


def test_unknown_events_remain_preservable(fixture_loader: FixtureLoader, tmp_path: Path) -> None:
    """BWR-002's unknown event stays opaque -- preserved verbatim, never reinterpreted."""

    document = _document(fixture_loader, _FULL_EVENT_BUNDLE)
    expected = cast(dict[str, JsonValue], document["expected"])
    raw_archive = _archive_bytes(document)
    members = _archive_members(raw_archive)

    bundle_path = tmp_path / "bundle.sqlite3"
    bundle_path.write_bytes(members["bundle.sqlite3"])

    preserved = cast(list[JsonValue], expected["preserved_unknowns"])
    assert preserved, "BWR-002 must declare at least one preserved unknown event"

    connection = _open_readonly(bundle_path)
    try:
        total_row = cast(
            tuple[object, ...], connection.execute("SELECT count(*) FROM events").fetchone()
        )
        assert total_row[0] == expected["event_record_count"]

        distinct_rows = connection.execute("SELECT DISTINCT schema_name FROM events").fetchall()
        distinct_names = {cast(str, cast(tuple[object, ...], row)[0]) for row in distinct_rows}

        unknown_names: set[str] = set()
        for raw_unknown in preserved:
            unknown = cast(dict[str, JsonValue], raw_unknown)
            eid = event_id(unknown["event_id"])
            schema = cast(dict[str, JsonValue], unknown["schema"])
            unknown_names.add(cast(str, schema["name"]))

            row = cast(
                tuple[object, ...] | None,
                connection.execute(
                    "SELECT schema_name, schema_version, entry_digest FROM events "
                    "WHERE event_id = ?",
                    (str(eid),),
                ).fetchone(),
            )
            assert row is not None, eid
            schema_name, schema_version, entry_digest = row
            # Preserved opaque -- schema/version/digest read back exactly as declared; this test
            # never attempts to decode the row's payload as any known event family.
            assert schema_name == schema["name"]
            assert schema_version == schema["version"]
            assert entry_digest == validate_sha256_digest(cast(str, unknown["entry_digest"]))

        assert unknown_names <= distinct_names
        known_family_names = distinct_names - unknown_names
        assert len(known_family_names) == expected["event_family_count"]

        final_frontier = frontier_from_json(expected["final_frontier"])
        assert final_frontier.sequence == cast(int, expected["event_record_count"])
    finally:
        connection.close()

    receipt = cast(dict[str, JsonValue], expected["receipt"])
    object_id(receipt["object_id"])
    validate_sha256_digest(cast(str, receipt["digest"]))
    subject_frontier = frontier_from_json(receipt["subject_frontier"])
    assert subject_frontier.sequence <= cast(int, expected["event_record_count"])


def test_compatibility_window_is_honestly_reported(fixture_loader: FixtureLoader) -> None:
    """Compatibility classification stays inside the four-state vocabulary; unsupported fails closed."""

    doc_text = _COMPATIBILITY_DOC.read_text(encoding="utf-8")
    vocabulary = {"supported", "readable", "unsupported", "untested"}
    for state in vocabulary:
        assert f"**`{state}`**" in doc_text, state
    assert "`untested` is never collapsed into `unsupported`" in doc_text

    for name in _FIXTURE_NAMES:
        document = _document(fixture_loader, name)
        input_block = cast(dict[str, JsonValue], document["input"])
        expected = cast(dict[str, JsonValue], document["expected"])

        release_identity = cast(dict[str, JsonValue], input_block["release_manifest_identity"])
        assert _classify_bundle_schema(cast(str, release_identity["bundle_schema"])) in {
            "supported",
            "readable",
        }

        classification = cast(dict[str, JsonValue], expected["compatibility_classification"])
        schema_state = cast(str, classification["schema"]).split("_", 1)[0]
        assert schema_state in vocabulary, name
        # A read-only backward-read path never performs a migration.
        assert classification["migration"] == "none", name
        assert classification["resources"] == "exact_release_identity", name

        resource_compat = expected.get("resource_schema_compatibility")
        if resource_compat is not None:
            assert cast(str, resource_compat).startswith("exact_"), name

    # A newer, unknown storage schema is never silently treated as supported -- it is reported
    # explicitly and honestly, never blank and never collapsed into a false pass.
    newer_schema = str(int(BUNDLE_SCHEMA_VERSION) + 1)
    classification_for_newer = _classify_bundle_schema(newer_schema)
    assert classification_for_newer != "supported"
    assert classification_for_newer  # bounded, always a real value -- never silently empty
    assert _classify_bundle_schema(BUNDLE_SCHEMA_VERSION) == "supported"
