"""Own only the canonical CTL-250 native-capture fixture and its manifest member."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse

_FIXTURE_RELATIVE = Path("fixtures/canonical/control-native-capture-2.5.case.json")
_FIXTURE_MANIFEST_PATH = "canonical/control-native-capture-2.5.case.json"
_MANIFEST_RELATIVE = Path("fixtures/manifest.json")
_FIXTURE_ID = "CTL-250"
_FIXTURE_MEDIA_TYPE = "application/vnd.yoetz.fixture-case+json"
_COMMITMENT = "hmac-sha256:" + "1" * 64
_SERVICE_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000001"


def _request(
    *, host: str, rpc_suffix: str, source: str, profile: str | None, mapping: str
) -> dict[str, Any]:
    source_identity = f"hook:{host}-control-schema-250"
    body: dict[str, Any] = {
        "capture_only": True,
        "codex_session_id": f"{host}:control-schema-250",
        "content_chunks": [
            {
                "content_b64": "Y2FwdHVyZQ==",
                "content_kind": "tool_input",
                "correlation_identity": f"{source_identity}:tool-input",
                "media_type": "text/plain",
                "part_count": 1,
                "part_index": 0,
                "redacted": False,
                "source_commitment": _COMMITMENT,
            }
        ],
        "envelope": {
            "content_object_refs": [],
            "cursor": {
                "byte_position": 0,
                "event_position": 1,
                "last_source_commitment": _COMMITMENT,
                "mapping_version": mapping,
                "source_generation": 1,
            },
            "event_kind": "PostToolUse",
            "gap_codes": [],
            "receipt_time": "2026-09-06T12:00:00.000Z",
            "session_commitment": _COMMITMENT,
            "source": source,
            "source_identity": source_identity,
            "structural_payload": {"tool_name": "Bash"},
        },
    }
    if profile is not None:
        body["content_capture_profile"] = profile
    return {
        "body": body,
        "kind": "call",
        "method": "observation_ingest",
        "protocol_version": "1.0",
        "rpc_id": f"rpc_00000000-0000-4000-8000-0000000000{rpc_suffix}",
        "service_generation": "1",
        "service_instance_id": _SERVICE_INSTANCE_ID,
    }


def _fixture_document() -> dict[str, Any]:
    vectors = (
        (
            "claude-native-capture",
            _request(
                host="claude",
                rpc_suffix="10",
                source="claude_hook",
                profile="claude-code-ordinary-observation-v1",
                mapping="claude-code-hooks-ordinary-v2",
            ),
            "claude_hook",
            "claude-code-ordinary-observation-v1",
        ),
        (
            "cursor-native-capture",
            _request(
                host="cursor",
                rpc_suffix="11",
                source="cursor_hook",
                profile="cursor-ordinary-observation-v1",
                mapping="cursor-hooks-ordinary-v1",
            ),
            "cursor_hook",
            "cursor-ordinary-observation-v1",
        ),
        (
            "codex-native-capture",
            _request(
                host="codex",
                rpc_suffix="12",
                source="codex_hook",
                profile=None,
                mapping="codex-obs-hook/1.0.0",
            ),
            "codex_hook",
            None,
        ),
    )
    expected: list[dict[str, Any]] = []
    for vector_id, request, source, profile in vectors:
        encoded = canonical_encode(request)
        expected_result: dict[str, Any] = {
            "capture_only": True,
            "protocol_version": "1.0",
            "schema_name": "control-request",
            "schema_validation": "valid",
            "schema_version": "2.5.0",
            "service_result": {
                "advanced_cursor": None,
                "disposition": "rejected",
                "reason": "content_capture_pending",
            },
            "source": source,
        }
        if profile is not None:
            expected_result["content_capture_profile"] = profile
        expected.append(
            {
                "canonical_byte_length": len(encoded),
                "canonical_hex": encoded.hex(),
                "canonical_sha256": canonical_digest(request),
                "expected_result": expected_result,
                "request_identity": {
                    "method": "observation_ingest",
                    "rpc_id": request["rpc_id"],
                    "service_generation": "1",
                    "service_instance_id": _SERVICE_INSTANCE_ID,
                },
                "vector_id": vector_id,
            }
        )
    return {
        "controls": {
            "clock": "fixture_supplied",
            "external_io": "forbidden",
            "network": "forbidden",
            "randomness": "fixture_supplied",
        },
        "expected": {
            "outer_protocol_version": "1.0",
            "schema_version": "2.5.0",
            "vector_count": 3,
            "vectors": expected,
        },
        "fixture_id": _FIXTURE_ID,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {
            "vectors": [
                {"request": request, "vector_id": vector_id} for vector_id, request, _, _ in vectors
            ]
        },
        "minimum_versions": {
            "control_schema": "2.5.0",
            "fixture_contract": "1.0.0",
            "protocol": "1.0",
        },
        "owns_requirements": ["CONTROL-2.5:native-observation-handoff", "ISSUE-616:main-repair"],
        "purpose": (
            "Freeze canonical Claude, Cursor, and profileless Codex native capture requests "
            "admitted by the additive 2.5 control schema, including their request identities, "
            "valid schema results, and content-pending ingest outcomes."
        ),
    }


def _manifest_bytes(path: Path, fixture_bytes: bytes, *, allow_owned_update: bool = False) -> bytes:
    parsed = strict_json_parse(path.read_bytes())
    if not isinstance(parsed, dict) or set(parsed) != {
        "manifest_schema",
        "manifest_version",
        "members",
    }:
        raise ValueError("fixture_manifest_shape_invalid")
    members = parsed["members"]
    if not isinstance(members, list):
        raise ValueError("fixture_manifest_members_invalid")
    previous = [cast(dict[str, Any], item) for item in members]
    if previous != sorted(previous, key=lambda item: str(item["path"]).encode("ascii")):
        raise ValueError("fixture_manifest_order_invalid")
    member = {
        "byte_length": len(fixture_bytes),
        "fixture_id": _FIXTURE_ID,
        "media_type": _FIXTURE_MEDIA_TYPE,
        "path": _FIXTURE_MANIFEST_PATH,
        "sha256": hashlib.sha256(fixture_bytes).hexdigest(),
    }
    existing = [item for item in previous if item["path"] == _FIXTURE_MANIFEST_PATH]
    if len(existing) > 1:
        raise ValueError("fixture_manifest_duplicate_path")
    if existing and existing[0] != member and not allow_owned_update:
        raise ValueError("fixture_manifest_owned_member_changed")
    if any(
        item["fixture_id"] == _FIXTURE_ID and item["path"] != _FIXTURE_MANIFEST_PATH
        for item in previous
    ):
        raise ValueError("fixture_manifest_id_already_owned")
    updated_members = (
        [member if item["path"] == _FIXTURE_MANIFEST_PATH else item for item in previous]
        if existing
        else sorted([*previous, member], key=lambda item: str(item["path"]).encode("ascii"))
    )
    if [item for item in updated_members if item["path"] != _FIXTURE_MANIFEST_PATH] != [
        item for item in previous if item["path"] != _FIXTURE_MANIFEST_PATH
    ]:
        raise ValueError("fixture_manifest_existing_member_changed")
    updated = cast(dict[str, Any], dict(parsed))
    updated["members"] = updated_members
    return json.dumps(updated).encode("utf-8") + b"\n"


def _expected(root: Path, *, allow_owned_update: bool = False) -> tuple[bytes, bytes]:
    fixture_bytes = canonical_encode(_fixture_document())
    return fixture_bytes, _manifest_bytes(
        root / _MANIFEST_RELATIVE,
        fixture_bytes,
        allow_owned_update=allow_owned_update,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.check == args.write:
        parser.error("choose exactly one of --check or --write")
    root = args.repo_root.resolve()
    fixture_bytes, manifest_bytes = _expected(root, allow_owned_update=args.write)
    fixture_path = root / _FIXTURE_RELATIVE
    manifest_path = root / _MANIFEST_RELATIVE
    if args.check:
        if not fixture_path.is_file() or fixture_path.read_bytes() != fixture_bytes:
            print("control capture fixture stale")
            return 1
        if not manifest_path.is_file() or manifest_path.read_bytes() != manifest_bytes:
            print("fixture manifest stale")
            return 1
        print("control capture fixture and manifest are current")
        return 0
    if fixture_path.exists() and fixture_path.read_bytes() != fixture_bytes and not args.write:
        raise SystemExit("control capture fixture has unexpected existing bytes")
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_bytes(fixture_bytes)
    manifest_path.write_bytes(manifest_bytes)
    print("wrote CTL-250 fixture and its single manifest member")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
