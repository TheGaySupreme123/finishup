#!/usr/bin/env python3
"""Synchronize the hand-authored same-request CHECK continuation schemas for issue 141."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Final, cast

from finishup.protocol.canonical import canonical_encode

_ROOT: Final = Path(__file__).resolve().parents[1]
_TARGETS: Final = (
    "operations/check-result-1.0.0.schema.json",
    "operations/status-result-1.0.0.schema.json",
)


def _repository_grant_branch(base: dict[str, Any]) -> dict[str, Any]:
    branch = copy.deepcopy(base)
    properties = cast(dict[str, Any], branch["properties"])
    properties["kind"] = {"const": "repository_privacy_setup"}
    properties["command"] = {
        "items": {"maxLength": 256, "minLength": 1, "type": "string"},
        "maxItems": 2,
        "minItems": 2,
        "prefixItems": [{"const": "yoetz"}, {"const": "--privacy"}],
        "type": "array",
    }
    properties.pop("pending_id", None)
    properties.pop("expires_at", None)
    branch["required"] = ["kind", "command", "replay_request_id", "instruction"]
    return branch


def _continuation_schema(document: dict[str, Any]) -> dict[str, Any]:
    definitions = cast(dict[str, Any], document["$defs"])
    current = cast(dict[str, Any], definitions["continuation"])
    branches = current.get("oneOf")
    disclosure = (
        copy.deepcopy(cast(list[dict[str, Any]], branches)[0])
        if isinstance(branches, list)
        else copy.deepcopy(current)
    )
    if cast(dict[str, Any], disclosure["properties"])["kind"] != {
        "const": "privacy_disclosure_decision"
    }:
        raise RuntimeError("check_continuation_disclosure_shape_changed")
    disclosure_properties = cast(dict[str, Any], disclosure["properties"])
    disclosure_properties["command"] = {
        "items": False,
        "maxItems": 4,
        "minItems": 4,
        "prefixItems": [
            {"const": "yoetz"},
            {"const": "privacy"},
            {"const": "decide-disclosure"},
            copy.deepcopy(disclosure_properties["pending_id"]),
        ],
        "type": "array",
    }
    return {"oneOf": [disclosure, _repository_grant_branch(disclosure)]}


def _expected_documents() -> dict[Path, bytes]:
    documents: dict[Path, bytes] = {}
    for relative in _TARGETS:
        path = _ROOT / "schemas" / relative
        document = cast(dict[str, Any], json.loads(path.read_bytes()))
        cast(dict[str, Any], document["$defs"])["continuation"] = _continuation_schema(document)
        documents[path] = canonical_encode(document)
    return documents


def _sync_manifest(documents: dict[Path, bytes], *, write: bool) -> bool:
    path = _ROOT / "schemas" / "manifest.json"
    manifest = cast(dict[str, Any], json.loads(path.read_bytes()))
    members = cast(list[dict[str, Any]], manifest["members"])
    by_path = {cast(str, member["path"]): member for member in members}
    changed = False
    for schema_path, payload in documents.items():
        relative = schema_path.relative_to(_ROOT / "schemas").as_posix()
        member = by_path.get(relative)
        if member is None:
            raise RuntimeError("schema_manifest_member_missing")
        expected = {
            "byte_length": len(payload),
            "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        }
        if any(member.get(key) != value for key, value in expected.items()):
            changed = True
            if write:
                member.update(expected)
    if write and changed:
        path.write_bytes(canonical_encode(manifest))
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    documents = _expected_documents()
    mismatches = [path for path, payload in documents.items() if path.read_bytes() != payload]
    manifest_changed = _sync_manifest(documents, write=args.write)
    if args.write:
        for path, payload in documents.items():
            path.write_bytes(payload)
        # Compute manifest against the bytes now installed, including first-run schema changes.
        _sync_manifest(documents, write=True)
        print("sync_check_continuation_schemas: WROTE (2 schemas, schema manifest)")
        return 0
    if mismatches or manifest_changed:
        for path in mismatches:
            print(f"check continuation schema stale: {path.relative_to(_ROOT)}")
        if manifest_changed:
            print("check continuation schema stale: schemas/manifest.json")
        return 1
    print("sync_check_continuation_schemas: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
