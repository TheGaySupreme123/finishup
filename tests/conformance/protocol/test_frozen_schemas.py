from __future__ import annotations

import hashlib
import importlib
import importlib.resources as resources
import importlib.util
import json
from collections.abc import Iterator, Mapping
from importlib.resources.abc import Traversable
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, cast
from urllib.parse import urldefrag, urlparse

import pytest

from finishup.protocol.canonical import canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError

_REPO_ROOT = Path(__file__).resolve().parents[3]
_ROOT_SCHEMA_DIR = _REPO_ROOT / "schemas"
_PACKAGE_SCHEMA_DIR = resources.files("finishup").joinpath("resources").joinpath("schemas")
_MANIFEST_PATH = "manifest.json"
_SCHEMA_NAMESPACE = "https://schemas.yoetz.dev/0.1/"
_EXPECTED_SCHEMA_MANIFEST_SCHEMA = "yoetz.schema-manifest/1.0.0"
_EXPECTED_SCHEMA_MANIFEST_VERSION = "1.0.0"
# +1 each: the review-packet-row 2.0.0 provider contract (robust lane row contract).
# ADR-049: +1 member, decision-recorded 1.1.0 (an event schema, not a request/result version).
_EXPECTED_MEMBER_COUNT = 233  # #1119: additive host-connection batch report
_EXPECTED_REQUEST_RESULT_VERSION_COUNT = 55
_EXPECTED_EVENT_VERSION_COUNT = 29


def _schema_module() -> Any:
    if importlib.util.find_spec("finishup.protocol.schemas") is None:
        pytest.skip("finishup.protocol.schemas not implemented yet")
    return importlib.import_module("finishup.protocol.schemas")


def _collect_traversable_files(root: Traversable, prefix: str = "") -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for child in root.iterdir():
        rel = f"{prefix}{child.name}"
        if child.is_file():
            result[rel] = child.read_bytes()
        else:
            result.update(_collect_traversable_files(child, f"{rel}/"))
    return result


def _load_manifest_bytes(root: Path) -> bytes:
    return (root / _MANIFEST_PATH).read_bytes()


def _load_manifest(value: bytes) -> dict[str, Any]:
    parsed = strict_json_parse(value)
    if not isinstance(parsed, dict):
        raise AssertionError("manifest_root_not_object")
    return parsed


def _schema_files_from_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    members = manifest.get("members")
    if not isinstance(members, list):
        raise AssertionError("manifest_members_not_list")
    return cast(list[dict[str, Any]], members)


def _assert_manifest_member_shape(member: dict[str, Any]) -> None:
    expected_keys = {
        "$id",
        "artifact_role",
        "byte_length",
        "media_type",
        "owning_model",
        "path",
        "schema_kind",
        "schema_version",
        "sha256",
    }
    if set(member) != expected_keys:
        raise AssertionError(f"unexpected_manifest_member_keys:{sorted(member)}")
    if type(member["path"]) is not str or not member["path"]:
        raise AssertionError("schema_path_invalid")
    if type(member["schema_version"]) is not str or not member["schema_version"]:
        raise AssertionError("schema_version_invalid")
    if type(member["$id"]) is not str or not member["$id"].startswith(_SCHEMA_NAMESPACE):
        raise AssertionError("schema_id_invalid")
    if type(member["media_type"]) is not str or member["media_type"] != "application/schema+json":
        raise AssertionError("schema_media_type_invalid")
    if type(member["byte_length"]) is not int or member["byte_length"] < 0:
        raise AssertionError("schema_byte_length_invalid")
    if type(member["sha256"]) is not str or not member["sha256"].startswith("sha256:"):
        raise AssertionError("schema_digest_invalid")


def _schema_name_version(member: dict[str, Any]) -> tuple[str, str]:
    path = PurePosixPath(member["path"])
    stem = path.name.removesuffix(".schema.json")
    schema_version = member["schema_version"]
    if not stem.endswith(f"-{schema_version}"):
        raise AssertionError("schema_version_suffix_mismatch")
    schema_name = stem[: -(len(schema_version) + 1)]
    return schema_name, schema_version


def _walk_refs(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in cast(dict[Any, Any], node).items():
            if key == "$ref" and type(value) is str:
                yield value
            yield from _walk_refs(value)
    elif isinstance(node, list | tuple):
        for item in cast(list[Any] | tuple[Any, ...], node):
            yield from _walk_refs(item)


def _assert_reference_closed(schema_text: bytes, member_ids: set[str]) -> None:
    parsed = strict_json_parse(schema_text)
    if not isinstance(parsed, dict):
        raise AssertionError("schema_document_not_object")
    for ref in _walk_refs(parsed):
        parsed_ref = urlparse(ref)
        if (
            parsed_ref.fragment
            and not parsed_ref.scheme
            and not parsed_ref.netloc
            and parsed_ref.path == ""
        ):
            continue
        if parsed_ref.query:
            raise AssertionError("schema_reference_query_forbidden")
        if parsed_ref.scheme != "https" or parsed_ref.netloc != "schemas.yoetz.dev":
            raise AssertionError("schema_reference_not_local")
        if not parsed_ref.path.startswith("/0.1/"):
            raise AssertionError("schema_reference_not_namespaced")
        if urldefrag(ref)[0] not in member_ids:
            raise AssertionError("schema_reference_unresolved")


def _assert_public_json_frozen(value: Any) -> None:
    if isinstance(value, MappingProxyType):
        for item in cast(Mapping[Any, Any], value).values():
            _assert_public_json_frozen(item)
        return
    if isinstance(value, tuple):
        for item in cast(tuple[Any, ...], value):
            _assert_public_json_frozen(item)
        return
    if value is None or type(value) in {bool, int, str}:
        return
    raise AssertionError(f"mutable_schema_value:{type(value).__name__}")


def test_schema_registry_is_complete() -> None:
    manifest_bytes = _load_manifest_bytes(_ROOT_SCHEMA_DIR)
    manifest = _load_manifest(manifest_bytes)
    members = _schema_files_from_manifest(manifest)

    assert manifest["manifest_schema"] == _EXPECTED_SCHEMA_MANIFEST_SCHEMA
    assert manifest["manifest_version"] == _EXPECTED_SCHEMA_MANIFEST_VERSION
    assert len(members) == _EXPECTED_MEMBER_COUNT

    paths = [member["path"] for member in members]
    assert paths == sorted(paths, key=lambda item: item.encode("ascii"))
    assert len(paths) == len(set(paths))
    assert len({member["$id"] for member in members}) == len(members)
    for member in members:
        path = member["path"]
        expected = (
            "7.0.0"
            if path
            in {
                "consent/catalog-7.0.0.schema.json",
                "consent/pending-agent-7.0.0.schema.json",
                "consent/prepare-result-7.0.0.schema.json",
                "consent/review-result-7.0.0.schema.json",
                "consent/status-7.0.0.schema.json",
            }
            else "6.0.0"
            if path
            in {
                "consent/catalog-6.0.0.schema.json",
                "consent/pending-agent-6.0.0.schema.json",
                "consent/prepare-result-6.0.0.schema.json",
                "consent/review-result-6.0.0.schema.json",
                "consent/status-6.0.0.schema.json",
            }
            else "5.0.0"
            if path
            in {
                "consent/catalog-5.0.0.schema.json",
                "consent/pending-agent-5.0.0.schema.json",
                "consent/prepare-result-5.0.0.schema.json",
                "consent/review-result-5.0.0.schema.json",
                "consent/status-5.0.0.schema.json",
            }
            else "4.0.0"
            if path
            in {
                "consent/catalog-4.0.0.schema.json",
                "consent/pending-agent-4.0.0.schema.json",
                "consent/prepare-result-4.0.0.schema.json",
                "consent/review-result-4.0.0.schema.json",
                "consent/status-4.0.0.schema.json",
            }
            else "3.0.0"
            if path
            in {
                "consent/catalog-3.0.0.schema.json",
                "consent/pending-agent-3.0.0.schema.json",
                "consent/prepare-result-3.0.0.schema.json",
                "consent/review-result-3.0.0.schema.json",
                "consent/status-3.0.0.schema.json",
            }
            else "2.9.0"
            if path.endswith("-2.9.0.schema.json")
            else "2.8.0"
            if path.endswith("-2.8.0.schema.json")
            else "2.7.0"
            if path.endswith("-2.7.0.schema.json")
            else "2.6.1"
            if path.endswith("-2.6.1.schema.json")
            else "2.6.0"
            if path.endswith("-2.6.0.schema.json")
            else "2.5.0"
            if path.endswith("-2.5.0.schema.json")
            else "2.4.0"
            if path.endswith("-2.4.0.schema.json")
            else "2.3.0"
            if path.endswith("-2.3.0.schema.json")
            else "2.2.3"
            if path.endswith("-2.2.3.schema.json")
            else "2.2.4"
            if path.endswith("-2.2.4.schema.json")
            else "2.2.2"
            if path.endswith("-2.2.2.schema.json")
            else "2.2.1"
            if path.endswith("-2.2.1.schema.json")
            else "2.2.0"
            if path.endswith("-2.2.0.schema.json")
            else "2.1.0"
            if path.endswith("-2.1.0.schema.json")
            else "2.0.0"
            if (
                path.startswith("consent/")
                and path != "consent/chat-user-attestation-1.0.0.schema.json"
            )
            or path.endswith("-2.0.0.schema.json")
            else "1.5.0"
            if path.endswith("-1.5.0.schema.json")
            else "1.4.0"
            if path.endswith("-1.4.0.schema.json")
            else "1.3.0"
            if path
            in {
                "config/yoetz-config-1.3.0.schema.json",
                "events/finding-recorded-1.3.0.schema.json",
                "events/check-recorded-1.3.0.schema.json",
                "findings/finding-1.3.0.schema.json",
                "operations/check-result-1.3.0.schema.json",
                "operations/receipt-result-1.3.0.schema.json",
                "receipts/receipt-document-1.3.0.schema.json",
                "operations/status-result-1.3.0.schema.json",
            }
            else "1.2.0"
            if path
            in {
                "config/yoetz-config-1.2.0.schema.json",
                "events/event-draft-1.2.0.schema.json",
                "events/evidence-recorded-1.2.0.schema.json",
                "events/finding-recorded-1.2.0.schema.json",
                "events/check-recorded-1.2.0.schema.json",
                "privacy/outbound-case-1.2.0.schema.json",
                "findings/semantic-provenance-1.2.0.schema.json",
                "events/opaque-unknown-event-draft-1.2.0.schema.json",
                "events/session-opened-1.2.0.schema.json",
                "events/session-resumed-1.2.0.schema.json",
                "findings/finding-1.2.0.schema.json",
                "findings/provider-judgment-1.2.0.schema.json",
                "operations/check-result-1.2.0.schema.json",
                "operations/publish-work-request-1.2.0.schema.json",
                "operations/receipt-result-1.2.0.schema.json",
                "operations/status-request-1.2.0.schema.json",
                "operations/status-result-1.2.0.schema.json",
                "privacy/outbound-case-1.2.0.schema.json",
                "privacy/privacy-policy-1.2.0.schema.json",
                "receipts/receipt-document-1.2.0.schema.json",
            }
            else (
                "1.3.0"
                if path == "operations/status-result-1.3.0.schema.json"
                else "1.2.0"
                if path == "operations/status-result-1.2.0.schema.json"
                else "1.1.0"
                if path
                in {
                    "config/yoetz-config-1.1.0.schema.json",
                    "events/check-recorded-1.1.0.schema.json",
                    "findings/runtime-attempt-evidence-1.1.0.schema.json",
                    "events/claim-recorded-1.1.0.schema.json",
                    "events/event-draft-1.1.0.schema.json",
                    "events/evidence-recorded-1.1.0.schema.json",
                    "events/finding-recorded-1.1.0.schema.json",
                    "events/opaque-unknown-event-draft-1.1.0.schema.json",
                    "events/plan-published-1.1.0.schema.json",
                    "events/plan-revised-1.1.0.schema.json",
                    "events/obligation-published-1.1.0.schema.json",
                    "events/decision-recorded-1.1.0.schema.json",
                    "events/session-opened-1.1.0.schema.json",
                    "events/session-resumed-1.1.0.schema.json",
                    "findings/finding-1.1.0.schema.json",
                    "findings/provider-judgment-1.1.0.schema.json",
                    "findings/semantic-provenance-1.1.0.schema.json",
                    "operations/check-request-1.1.0.schema.json",
                    "operations/check-result-1.1.0.schema.json",
                    "operations/publish-work-request-1.1.0.schema.json",
                    "operations/receipt-result-1.1.0.schema.json",
                    "operations/status-request-1.1.0.schema.json",
                    "operations/status-result-1.1.0.schema.json",
                    "operations/start-request-1.1.0.schema.json",
                    "operations/start-result-1.1.0.schema.json",
                    "privacy/egress-receipt-1.1.0.schema.json",
                    "privacy/outbound-case-1.1.0.schema.json",
                    "findings/provider-judgment-1.1.0.schema.json",
                    "events/response-recorded-1.1.0.schema.json",
                    "events/obligation-published-1.1.0.schema.json",
                    "operations/respond-request-1.1.0.schema.json",
                    "operations/respond-result-1.1.0.schema.json",
                    "operations/publish-work-result-1.1.0.schema.json",
                    "operations/read-guidance-request-1.1.0.schema.json",
                    "operations/read-guidance-result-1.1.0.schema.json",
                    "privacy/privacy-policy-1.1.0.schema.json",
                    "receipts/receipt-document-1.1.0.schema.json",
                }
                else "1.0.0"
            )
        )
        assert member["schema_version"] == expected
    for member in members:
        _assert_manifest_member_shape(member)
    assert canonical_encode(manifest) == manifest_bytes


def test_schema_root_and_package_resources_are_byte_identical() -> None:
    root_files: dict[str, bytes] = {}
    for child in _ROOT_SCHEMA_DIR.iterdir():
        if child.is_file():
            root_files[child.name] = child.read_bytes()
        elif child.is_dir():
            for grandchild in child.rglob("*"):
                if grandchild.is_file():
                    root_files[str(grandchild.relative_to(_ROOT_SCHEMA_DIR)).replace("\\", "/")] = (
                        grandchild.read_bytes()
                    )

    package_files = _collect_traversable_files(_PACKAGE_SCHEMA_DIR)

    assert set(root_files) == set(package_files)
    for rel_path, root_bytes in root_files.items():
        package_bytes = package_files[rel_path]
        assert root_bytes == package_bytes


def test_schema_documents_are_reference_closed() -> None:
    manifest = _load_manifest(_load_manifest_bytes(_ROOT_SCHEMA_DIR))
    member_paths = {member["path"] for member in _schema_files_from_manifest(manifest)}
    member_ids = {member["$id"] for member in _schema_files_from_manifest(manifest)}

    for rel_path in member_paths:
        _assert_reference_closed((_ROOT_SCHEMA_DIR / rel_path).read_bytes(), member_ids)


def test_observation_capture_provenance_is_additive_only() -> None:
    evidence_1_1 = _load_manifest(
        (_ROOT_SCHEMA_DIR / "events/evidence-recorded-1.1.0.schema.json").read_bytes()
    )
    evidence_1_2 = _load_manifest(
        (_ROOT_SCHEMA_DIR / "events/evidence-recorded-1.2.0.schema.json").read_bytes()
    )
    old_provenance = evidence_1_1["$defs"]["evidence_digest_provenance"]["enum"]
    new_provenance = evidence_1_2["$defs"]["evidence_digest_provenance"]["enum"]
    assert "observation_captured" not in old_provenance
    assert "observation_captured" in new_provenance

    outbound_1_0 = _load_manifest(
        (_ROOT_SCHEMA_DIR / "privacy/outbound-case-1.0.0.schema.json").read_bytes()
    )
    outbound_1_1 = _load_manifest(
        (_ROOT_SCHEMA_DIR / "privacy/outbound-case-1.1.0.schema.json").read_bytes()
    )
    old_outbound = outbound_1_0["$defs"]["targeted_excerpt"]["properties"]["digest_provenance"][
        "properties"
    ]["provenance"]["enum"]
    new_outbound = outbound_1_1["$defs"]["targeted_excerpt"]["properties"]["digest_provenance"][
        "properties"
    ]["provenance"]["enum"]
    assert "observation_captured" not in old_outbound
    assert "observation_captured" in new_outbound

    event_draft_1_0 = _load_manifest(
        (_ROOT_SCHEMA_DIR / "events/event-draft-1.0.0.schema.json").read_bytes()
    )
    event_draft_1_1 = _load_manifest(
        (_ROOT_SCHEMA_DIR / "events/event-draft-1.1.0.schema.json").read_bytes()
    )
    old_event_draft_text = json.dumps(event_draft_1_0)
    new_event_draft_text = json.dumps(event_draft_1_1)
    assert "evidence-recorded-1.2.0.schema.json" not in old_event_draft_text
    assert "opaque-unknown-event-draft-1.1.0.schema.json" not in old_event_draft_text
    assert "evidence-recorded-1.2.0.schema.json" in new_event_draft_text
    assert "opaque-unknown-event-draft-1.1.0.schema.json" in new_event_draft_text

    opaque_1_0 = _load_manifest(
        (_ROOT_SCHEMA_DIR / "events/opaque-unknown-event-draft-1.0.0.schema.json").read_bytes()
    )
    opaque_1_1 = _load_manifest(
        (_ROOT_SCHEMA_DIR / "events/opaque-unknown-event-draft-1.1.0.schema.json").read_bytes()
    )
    assert '"1.2.0"' not in json.dumps(opaque_1_0)
    assert '"1.2.0"' in json.dumps(opaque_1_1)


# The released 2.1.0 version report is frozen: `scripts/generate_schemas.py` reloads its bytes
# from disk instead of re-deriving them, so an accidental revert of the file would be re-pinned
# into `schemas/manifest.json` without any generator or digest check noticing. These are the exact
# released cardinalities and versions; only the live 2.2.0 report tracks the current inventory.
_FROZEN_VERSION_MANIFEST_2_1_COUNTS: Mapping[str, str] = MappingProxyType(
    {
        "canonical_vectors": "10",
        "guidance_resources": "5",
        "migrations": "11",
        "runtime_config_resources": "1",
        "runtime_support_resources": "1",
        "schema_resources": "120",
        "skill_resources": "12",
        "total": "160",
    }
)
_FROZEN_VERSION_MANIFEST_2_1_EVENTS: Mapping[str, str] = MappingProxyType(
    {
        "check_recorded": "1.1.0",
        "claim_recorded": "1.0.0",
        "evidence_recorded": "1.2.0",
        "finding_recorded": "1.1.0",
        "session_opened": "1.1.0",
        "session_resumed": "1.1.0",
    }
)
_FROZEN_VERSION_MANIFEST_2_1_REQUESTS: Mapping[str, str] = MappingProxyType(
    {
        "catalog": "5.0.0",
        "outbound-case": "1.1.0",
        "pending-agent": "5.0.0",
        "prepare-result": "5.0.0",
        "publish-work-request": "1.0.0",
        "review-result": "5.0.0",
        "status": "5.0.0",
    }
)


def _version_manifest_document(version: str) -> dict[str, Any]:
    return _load_manifest(
        (_ROOT_SCHEMA_DIR / f"version/version-manifest-{version}.schema.json").read_bytes()
    )


def _version_manifest_consts(document: dict[str, Any], definition: str) -> dict[str, str]:
    properties = cast(dict[str, dict[str, str]], document["$defs"][definition]["properties"])
    return {name: entry["const"] for name, entry in properties.items()}


def test_released_version_manifest_2_1_stays_frozen_at_its_released_snapshot() -> None:
    document = _version_manifest_document("2.1.0")

    assert document["properties"]["schema_version"]["const"] == "2.1.0"
    counts = _version_manifest_consts(document, "resource_counts")
    assert counts == dict(_FROZEN_VERSION_MANIFEST_2_1_COUNTS)
    total = int(counts["total"])
    resources_property = cast(dict[str, Any], document["properties"]["resources"])
    assert resources_property["maxItems"] == total
    assert resources_property["oneOf"] == [
        {"maxItems": 0},
        {"maxItems": total, "minItems": total},
    ]
    events = _version_manifest_consts(document, "event_schema_versions")
    for name, version in _FROZEN_VERSION_MANIFEST_2_1_EVENTS.items():
        assert events[name] == version
    requests = _version_manifest_consts(document, "request_result_schema_versions")
    for name, version in _FROZEN_VERSION_MANIFEST_2_1_REQUESTS.items():
        assert requests[name] == version

    root_bytes = (_ROOT_SCHEMA_DIR / "version/version-manifest-2.1.0.schema.json").read_bytes()
    packaged = _PACKAGE_SCHEMA_DIR.joinpath("version/version-manifest-2.1.0.schema.json")
    assert root_bytes == packaged.read_bytes()


def test_released_version_manifest_2_2_retains_the_0_2_2_inventory() -> None:
    document = _version_manifest_document("2.2.0")

    assert document["properties"]["schema_version"]["const"] == "2.2.0"
    assert int(_version_manifest_consts(document, "resource_counts")["total"]) == 199
    assert (
        _version_manifest_consts(document, "request_result_schema_versions")["control-result"]
        == "2.6.0"
    )


def test_released_version_manifest_2_2_1_retains_the_0_2_3_inventory() -> None:
    document = _version_manifest_document("2.2.1")
    assert document["properties"]["schema_version"]["const"] == "2.2.1"
    assert int(_version_manifest_consts(document, "resource_counts")["total"]) == 202
    assert "host-connection" not in _version_manifest_consts(
        document, "request_result_schema_versions"
    )


def test_live_version_manifest_2_3_tracks_the_current_inventory() -> None:
    from finishup.version import REVIEWED_RESOURCE_COUNT

    document = _version_manifest_document("2.3.0")

    assert document["properties"]["schema_version"]["const"] == "2.3.0"
    counts = _version_manifest_consts(document, "resource_counts")
    assert int(counts["total"]) == REVIEWED_RESOURCE_COUNT
    assert sum(int(count) for name, count in counts.items() if name != "total") == int(
        counts["total"]
    )
    assert int(counts["schema_resources"]) > int(
        _FROZEN_VERSION_MANIFEST_2_1_COUNTS["schema_resources"]
    )
    events = _version_manifest_consts(document, "event_schema_versions")
    assert events["claim_recorded"] == "1.1.0"
    requests = _version_manifest_consts(document, "request_result_schema_versions")
    # The task-statement contracts (issue #908).
    assert requests["publish-work-request"] == "1.2.0"
    assert requests["start-request"] == "1.1.0"
    assert requests["privacy-policy"] == "1.2.0"
    assert events["session_opened"] == "1.2.0"


def test_released_version_manifest_2_2_2_retains_the_0_2_4_inventory() -> None:
    document = _version_manifest_document("2.2.2")
    assert document["properties"]["schema_version"]["const"] == "2.2.2"
    assert int(_version_manifest_consts(document, "resource_counts")["total"]) == 204
    requests = _version_manifest_consts(document, "request_result_schema_versions")
    assert requests["host-connection"] == "1.0.0"
    assert requests["control-result"] == "2.6.1"
    assert "setup-status" not in requests


def test_released_version_manifest_2_2_3_retains_the_0_2_5_inventory() -> None:
    document = _version_manifest_document("2.2.3")
    assert document["properties"]["schema_version"]["const"] == "2.2.3"
    assert int(_version_manifest_consts(document, "resource_counts")["total"]) == 206


def test_version_manifest_2_2_4_retains_the_0_2_line_setup_inventory() -> None:
    document = _version_manifest_document("2.2.4")
    assert document["properties"]["schema_version"]["const"] == "2.2.4"
    assert int(_version_manifest_consts(document, "resource_counts")["total"]) == 208
    requests = _version_manifest_consts(document, "request_result_schema_versions")
    assert requests["setup-readiness"] == "1.0.0"
    assert requests["setup-status"] == "2.0.0"
    assert "session-health" not in requests


def test_schema_documents_are_frozen_when_catalog_available() -> None:
    schemas = _schema_module()
    catalog = schemas.load_schema_catalog()
    manifest = _load_manifest(_load_manifest_bytes(_ROOT_SCHEMA_DIR))
    members = _schema_files_from_manifest(manifest)

    assert len(catalog.documents) == _EXPECTED_MEMBER_COUNT
    assert catalog.manifest_version == _EXPECTED_SCHEMA_MANIFEST_VERSION
    assert (
        catalog.manifest_digest
        == f"sha256:{hashlib.sha256(_load_manifest_bytes(_ROOT_SCHEMA_DIR)).hexdigest()}"
    )
    assert len(catalog.request_result_versions) == _EXPECTED_REQUEST_RESULT_VERSION_COUNT
    assert len(catalog.event_schema_versions) == _EXPECTED_EVENT_VERSION_COUNT

    by_path = dict(catalog.by_path)
    by_id = dict(catalog.by_id)
    by_name_version = dict(catalog.by_name_version)

    for member in members:
        schema_name, schema_version = _schema_name_version(member)
        doc = by_path[member["path"]]
        assert by_id[member["$id"]] is doc
        assert by_name_version[(schema_name, schema_version)] is doc
        assert doc.schema_id == member["$id"]
        assert doc.schema_version == schema_version
        assert doc.relative_path == member["path"]
        assert doc.schema_bytes == (_ROOT_SCHEMA_DIR / member["path"]).read_bytes()
        assert canonical_encode(doc.json_schema) == doc.schema_bytes
        _assert_public_json_frozen(doc.json_schema)

    assert isinstance(catalog.by_path, MappingProxyType)
    assert isinstance(catalog.by_id, MappingProxyType)
    assert isinstance(catalog.by_name_version, MappingProxyType)


def test_schema_uris_and_versions_are_stable() -> None:
    schemas = _schema_module()
    catalog = schemas.load_schema_catalog()
    manifest = _load_manifest(_load_manifest_bytes(_ROOT_SCHEMA_DIR))

    for member in _schema_files_from_manifest(manifest):
        schema_name, schema_version = _schema_name_version(member)
        assert schemas.schema_path_for(schema_name, schema_version) == member["path"]
        assert schemas.schema_uri(schema_name, schema_version) == member["$id"]
        assert schemas.schema_document_for(schema_name, schema_version).schema_id == member["$id"]

    assert schemas.request_result_schema_versions(catalog) == catalog.request_result_versions
    assert schemas.event_schema_versions(catalog) == catalog.event_schema_versions


def test_every_packaged_member_is_a_valid_draft_2020_12_schema() -> None:
    """The build-time invariant behind the #210 runtime fast path.

    ``load_schema_catalog`` no longer meta-validates members whose bytes match
    the packaged manifest digest, so this test is where meta-validity of the
    packaged catalog is enforced. If it is deleted, nothing checks it anywhere.
    """

    from jsonschema import Draft202012Validator

    manifest = _load_manifest(_load_manifest_bytes(_ROOT_SCHEMA_DIR))
    members = _schema_files_from_manifest(manifest)
    assert len(members) == _EXPECTED_MEMBER_COUNT
    for member in members:
        data = (_ROOT_SCHEMA_DIR / member["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == member["sha256"].removeprefix("sha256:")
        parsed = strict_json_parse(data)
        assert canonical_encode(parsed) == data, f"not canonical: {member['path']}"
        Draft202012Validator.check_schema(cast(dict[str, Any], parsed))


def test_manifest_digest_is_available_without_building_the_catalog() -> None:
    """#210: handshakes hash the manifest without paying for the catalog."""

    schemas = _schema_module()
    schemas.schema_manifest_digest.cache_clear()
    schemas._load_catalog_state.cache_clear()
    digest = schemas.schema_manifest_digest()
    assert digest == f"sha256:{hashlib.sha256(_load_manifest_bytes(_ROOT_SCHEMA_DIR)).hexdigest()}"
    assert schemas._load_catalog_state.cache_info().misses == 0, (
        "schema_manifest_digest built the full catalog; the handshake fast path is gone"
    )
    assert digest == schemas.load_schema_catalog().manifest_digest


def test_schema_instance_validation_stays_local_when_catalog_available() -> None:
    schemas = _schema_module()
    try:
        schemas.validate_schema_instance("public-error", "1.0.0", {})
    except ProtocolValueError as exc:
        assert exc.reason_code == "schema_instance_invalid"
    else:
        raise AssertionError("schema_instance_invalid_not_raised")
