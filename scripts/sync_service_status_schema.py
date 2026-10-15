"""Synchronize service-status reasons and their runtime-support digest dependency."""

from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path
from typing import cast

from verify_resource_manifest import build_manifest, collect_source_entries, load_inventory_config

from finishup.ports.control import _SERVICE_STATE_REASON_VALUES
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode


def _load(path: Path) -> dict[str, JsonValue]:
    """Load one canonical JSON object from disk."""

    return cast(dict[str, JsonValue], json.loads(path.read_bytes()))


def _write(path: Path, document: dict[str, JsonValue]) -> None:
    """Write one canonical JSON object without incidental formatting drift."""

    path.write_bytes(canonical_encode(document))


def _sync_runtime_support(root: Path) -> None:
    """Refresh the runtime-support digest after schema resource changes."""

    inventory = load_inventory_config()
    resources = collect_source_entries(inventory, repo_root=root)
    generated_manifest = _load_bytes(build_manifest(inventory, resources))
    resource_set_digest = cast(str, generated_manifest["resource_set_digest"])

    support_path = root / "support/runtime-support.json"
    support = _load(support_path)
    support["release_version"] = tomllib.loads((root / "pyproject.toml").read_text())["project"][
        "version"
    ]
    support["resource_set_digest"] = resource_set_digest
    without_digest = {key: value for key, value in support.items() if key != "manifest_digest"}
    support["manifest_digest"] = canonical_digest(without_digest)
    support_path.write_bytes(canonical_encode(support) + b"\n")


def _load_bytes(value: bytes) -> dict[str, JsonValue]:
    """Decode one generated canonical JSON object."""

    return cast(dict[str, JsonValue], json.loads(value))


def main() -> None:
    """Synchronize the service-status schema and all owned digest dependencies."""

    root = Path(__file__).resolve().parent.parent
    status_path = root / "schemas/service/service-status-1.0.0.schema.json"
    status = _load(status_path)
    status_properties = cast(dict[str, JsonValue], status["properties"])
    state_reason = cast(dict[str, JsonValue], status_properties["state_reason"])
    state_reason["enum"] = cast(JsonValue, list(_SERVICE_STATE_REASON_VALUES))
    _write(status_path, status)

    status_bytes = status_path.read_bytes()
    manifest_path = root / "schemas/manifest.json"
    manifest = _load(manifest_path)
    members = cast(list[JsonValue], manifest["members"])
    for raw_member in members:
        member = cast(dict[str, JsonValue], raw_member)
        if member.get("path") == "service/service-status-1.0.0.schema.json":
            member["byte_length"] = len(status_bytes)
            member["sha256"] = "sha256:" + hashlib.sha256(status_bytes).hexdigest()
            break
    else:
        raise RuntimeError("service_status_manifest_member_missing")
    _write(manifest_path, manifest)
    _sync_runtime_support(root)

    print("sync_service_status_schema: WROTE (1 schema, schema manifest, runtime support)")


if __name__ == "__main__":
    main()
