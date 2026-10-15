"""Synchronize the frozen wire-schema additions owned by ADR-018.

The public operation models intentionally differ from several internal dataclasses, so these
reviewed schemas cannot be replaced by an unmodified Pydantic introspection result. This script
applies the four bounded wire changes and refreshes their schema-manifest byte identities.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import cast

from finishup.protocol.canonical import JsonValue, canonical_encode

_ROUTE_PROFILE_SCHEMA: dict[str, JsonValue] = {
    "enum": ["policy", "strict"],
    "type": "string",
}
_TARGETS = (
    "events/check-recorded-1.0.0.schema.json",
    "operations/check-result-1.0.0.schema.json",
    "operations/status-result-1.0.0.schema.json",
    "service/control-request-1.0.0.schema.json",
)


def _load(path: Path) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], json.loads(path.read_bytes()))


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise RuntimeError("mcp_route_schema_shape_changed")
    return value


def _array(value: JsonValue) -> list[JsonValue]:
    if not isinstance(value, list):
        raise RuntimeError("mcp_route_schema_shape_changed")
    return value


def _insert_enum(enum: list[JsonValue]) -> None:
    if "route_semantic_ceiling" in enum:
        return
    try:
        index = enum.index("coordinator_failure")
    except ValueError as exc:
        raise RuntimeError("semantic_reason_registry_changed") from exc
    enum.insert(index, "route_semantic_ceiling")


def _insert_binding(one_of: list[JsonValue]) -> None:
    for branch in one_of:
        properties = _object(_object(branch).get("properties", {}))
        reason = _object(properties.get("semantic_reason", {})).get("const")
        status = _object(properties.get("semantic_status", {})).get("const")
        if reason == "route_semantic_ceiling":
            if status != "blocked_by_policy":
                raise RuntimeError("route_semantic_binding_changed")
            return
    for index, branch in enumerate(one_of):
        properties = _object(_object(branch).get("properties", {}))
        reason = _object(properties.get("semantic_reason", {})).get("const")
        status = _object(properties.get("semantic_status", {})).get("const")
        if reason == "scope_not_authorized" and status == "blocked_by_policy":
            addition = copy.deepcopy(_object(branch))
            addition_properties = _object(addition["properties"])
            _object(addition_properties["semantic_reason"])["const"] = "route_semantic_ceiling"
            one_of.insert(index + 1, addition)
            return
    raise RuntimeError("blocked_policy_binding_missing")


def _sync_check_recorded(document: dict[str, JsonValue]) -> None:
    properties = _object(document["properties"])
    _insert_enum(_array(_object(properties["semantic_reason"])["enum"]))
    definitions = _object(document["$defs"])
    _insert_binding(_array(_object(definitions["semantic_binding"])["oneOf"]))


def _sync_check_result(document: dict[str, JsonValue]) -> None:
    definitions = _object(document["$defs"])
    success = _object(definitions["success"])
    properties = _object(success["properties"])
    _insert_enum(_array(_object(properties["semantic_reason"])["enum"]))
    _insert_binding(_array(_object(definitions["semantic_binding"])["oneOf"]))


def _sync_status_result(document: dict[str, JsonValue]) -> None:
    definitions = _object(document["$defs"])
    version_slice = _object(definitions["version_slice"])
    properties = _object(version_slice["properties"])
    existing = properties.get("route_profile")
    if existing is not None and existing != _ROUTE_PROFILE_SCHEMA:
        raise RuntimeError("status_route_profile_schema_changed")
    properties["route_profile"] = copy.deepcopy(_ROUTE_PROFILE_SCHEMA)


def _sync_control_request(document: dict[str, JsonValue]) -> None:
    updated: set[str] = set()
    for raw_branch in _array(document["oneOf"]):
        branch = _object(raw_branch)
        properties = _object(branch.get("properties", {}))
        method = _object(properties.get("method", {})).get("const")
        if method not in {"check", "status"}:
            continue
        existing = properties.get("route_profile")
        if existing is not None and existing != _ROUTE_PROFILE_SCHEMA:
            raise RuntimeError("control_route_profile_schema_changed")
        properties["route_profile"] = copy.deepcopy(_ROUTE_PROFILE_SCHEMA)
        updated.add(method)
    if updated != {"check", "status"}:
        raise RuntimeError("control_route_profile_methods_missing")


def _update_schema_manifest(root: Path) -> None:
    manifest_path = root / "manifest.json"
    manifest = _load(manifest_path)
    members = _array(manifest["members"])
    by_path = {cast(str, _object(member)["path"]): _object(member) for member in members}
    for relative_path in _TARGETS:
        member = by_path.get(relative_path)
        if member is None:
            raise RuntimeError("schema_manifest_member_missing")
        payload = (root / relative_path).read_bytes()
        member["byte_length"] = len(payload)
        member["sha256"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    manifest_path.write_bytes(canonical_encode(cast(JsonValue, manifest)))


def main() -> None:
    root = Path(__file__).resolve().parent.parent / "schemas"
    synchronizers = {
        _TARGETS[0]: _sync_check_recorded,
        _TARGETS[1]: _sync_check_result,
        _TARGETS[2]: _sync_status_result,
        _TARGETS[3]: _sync_control_request,
    }
    for relative_path, synchronize in synchronizers.items():
        path = root / relative_path
        document = _load(path)
        synchronize(document)
        path.write_bytes(canonical_encode(cast(JsonValue, document)))
    _update_schema_manifest(root)
    print("sync_mcp_route_profile_schemas: WROTE (4 schemas, schema manifest)")


if __name__ == "__main__":
    main()
