"""Converge the reviewed pre-dispatch capacity reason in public AI-powered review bindings."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import cast

from finishup.protocol.canonical import JsonValue, canonical_encode


def _sync(value: JsonValue) -> None:
    if isinstance(value, list):
        for item in value:
            _sync(item)
    elif isinstance(value, dict):
        enum = value.get("enum")
        if isinstance(enum, list) and "coordinator_failure" in enum:
            if "case_capacity_exceeded" not in enum:
                enum.insert(enum.index("coordinator_failure"), "case_capacity_exceeded")
        branches = value.get("oneOf")
        if isinstance(branches, list):
            for existing in branches:
                if isinstance(existing, dict):
                    properties = existing.get("properties")
                    if isinstance(properties, dict) and properties.get("semantic_reason") == {
                        "const": "case_capacity_exceeded"
                    }:
                        properties["semantic_provenance"] = {"type": "null"}
            additions: list[JsonValue] = []
            for branch in branches:
                if not isinstance(branch, dict):
                    continue
                props = branch.get("properties")
                if not isinstance(props, dict):
                    continue
                reason = props.get("semantic_reason")
                if reason == {"const": "coordinator_failure"}:
                    addition = cast(
                        JsonValue,
                        json.loads(
                            json.dumps(copy.deepcopy(branch)).replace(
                                '"coordinator_failure"', '"case_capacity_exceeded"'
                            )
                        ),
                    )
                    assert isinstance(addition, dict)
                    properties = addition["properties"]
                    assert isinstance(properties, dict)
                    properties["semantic_provenance"] = {"type": "null"}
                    if addition not in branches:
                        additions.append(addition)
            branches.extend(additions)
        for item in value.values():
            _sync(item)


def main() -> None:
    root = Path(__file__).resolve().parent.parent / "schemas"
    changed = 0
    # These are additive contracts. Never traverse released 1.0 schemas: their
    # exact bytes remain frozen even when the runtime admits a new reason.
    for relative_path in (
        "events/check-recorded-1.2.0.schema.json",
        "events/check-recorded-1.3.0.schema.json",
        "findings/semantic-provenance-1.2.0.schema.json",
        "operations/check-result-1.2.0.schema.json",
    ):
        path = root / relative_path
        original = path.read_bytes()
        document = cast(JsonValue, json.loads(original))
        _sync(document)
        updated = canonical_encode(document)
        if updated != original:
            path.write_bytes(updated)
            changed += 1
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for member in manifest["members"]:
        data = (root / member["path"]).read_bytes()
        member["byte_length"] = len(data)
        member["sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()
    manifest_path.write_bytes(canonical_encode(cast(JsonValue, manifest)))
    print(f"sync_semantic_capacity_schemas: WROTE ({changed} schemas)")


if __name__ == "__main__":
    main()
