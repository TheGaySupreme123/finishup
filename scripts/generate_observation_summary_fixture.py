"""Write the canonical routine-read summary fixture and its manifest member."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from finishup.adapters.integrations.observation_admission import build_routine_read_summary
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationSource,
    observation_envelope_to_json,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse

_FIXTURE_RELATIVE = Path("fixtures/observations/routine-read-summary.case.json")
_FIXTURE_MANIFEST_PATH = "observations/routine-read-summary.case.json"
_MANIFEST_RELATIVE = Path("fixtures/manifest.json")
_FIXTURE_ID = "OBS-002"
_FIXTURE_MEDIA_TYPE = "application/vnd.yoetz.fixture-case+json"
_SESSION_COMMITMENT = "hmac-sha256:" + "a" * 64
_CURSOR_COMMITMENT = "hmac-sha256:" + "b" * 64
_FENCE = "sha256:" + "c" * 64
_AUTHORITY_GENERATION = "sha256:" + "d" * 64
_SUBJECT_STATE = "sha256:" + "e" * 64
_TASK = "tsk_00000000-0000-4000-8000-000000000001"
_SELECTION_SESSION = "ses_00000000-0000-4000-8000-000000000002"
_WRITER = "wri_00000000-0000-4000-8000-000000000003"
_GAPS = ("content_unselected", "observation_input_loss")


def _envelope(position: int, event_kind: str) -> ObservationEnvelope:
    structural: dict[str, Any] = {
        "action": "routine_read",
        "tool_name": "Read",
        "tool_call_id": "fixture-read-1",
        "selection_task_id": _TASK,
        "selection_session_id": _SELECTION_SESSION,
        "selection_writer_id": _WRITER,
        "selection_authority_generation": _AUTHORITY_GENERATION,
        "subject_state_digest": _SUBJECT_STATE,
    }
    if event_kind == "PostToolUse":
        structural["success"] = True
        structural["exit_status"] = 0
    return ObservationEnvelope(
        session_commitment=_SESSION_COMMITMENT,
        event_kind=event_kind,
        source_identity=f"native:fixture-read-1-{event_kind.casefold()}",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=position * 10,
            event_position=position,
            last_source_commitment=_CURSOR_COMMITMENT,
            mapping_version="codex-obs-hook/1.0.0",
        ),
        receipt_time=Timestamp(f"2026-09-10T00:00:0{position}.000Z"),
        structural_payload=JsonObject(structural),
        content_object_refs=(),
        gap_codes=_GAPS,
    )


def _fixture_document() -> dict[str, Any]:
    pre = _envelope(1, "PreToolUse")
    post = _envelope(2, "PostToolUse")
    summary = build_routine_read_summary((pre, post), _FENCE)
    summary_wire = observation_envelope_to_json(summary)
    encoded = canonical_encode(summary_wire)
    return {
        "controls": {
            "clock": "fixture_supplied",
            "external_io": "forbidden",
            "network": "forbidden",
            "randomness": "fixture_supplied",
        },
        "expected": {
            "member_digest": summary.structural_payload["member_digest"],
            "summary_canonical_hex": encoded.hex(),
            "summary_canonical_sha256": canonical_digest(summary_wire),
            "summary_envelope": summary_wire,
            "summary_identity": summary.source_identity,
        },
        "fixture_id": _FIXTURE_ID,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {
            "envelopes": (observation_envelope_to_json(pre), observation_envelope_to_json(post)),
            "fence": _FENCE,
        },
        "minimum_versions": {
            "fixture_contract": "1.0.0",
            "observation_summary": "1.0.0",
            "protocol": "1.0",
        },
        "owns_requirements": ["ISSUE-687/routine-read-selection-summary", "ADR-029"],
        "purpose": (
            "Freeze the bounded structural identity, member digest, and canonical bytes for a "
            "successful routine-read summary without retaining host content."
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
            print("observation summary fixture stale")
            return 1
        if not manifest_path.is_file() or manifest_path.read_bytes() != manifest_bytes:
            print("fixture manifest stale")
            return 1
        print("observation summary fixture and manifest are current")
        return 0
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_bytes(fixture_bytes)
    manifest_path.write_bytes(manifest_bytes)
    print("wrote OBS-002 routine-read summary fixture and manifest member")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
