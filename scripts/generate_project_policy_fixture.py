"""Own the CTL-270 project policy-denial wire vector and its manifest entry."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from finishup.protocol.canonical import canonical_digest, canonical_encode

_PATH = "canonical/control-project-policy-2.7.case.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    frame = {
        "protocol_version": "1.0",
        "rpc_id": "rpc_00000000-0000-4000-8000-000000000001",
        "service_instance_id": "svc_00000000-0000-4000-8000-000000000001",
        "service_generation": "1",
        "method": "project",
        "outcome": "error",
        "body": {"code": "coordination_source_policy_denied", "retryable": False},
    }
    encoded = canonical_encode(frame)
    fixture = canonical_encode(
        {
            "fixture_id": "CTL-270",
            "fixture_schema": "yoetz.fixture-case/1.0.0",
            "fixture_version": "1.0.0",
            "controls": {
                "clock": "fixture_supplied",
                "external_io": "forbidden",
                "network": "forbidden",
                "randomness": "fixture_supplied",
            },
            "minimum_versions": {
                "control_schema": "2.7.0",
                "fixture_contract": "1.0.0",
                "protocol": "1.0",
            },
            "owns_requirements": ["ISSUE-502:source-policy-refusal", "ADR-027"],
            "purpose": "Distinguish source policy refusal from missing workspace consent on control 2.7.",
            "input": {"frame": frame},
            "expected": {
                "canonical_hex": encoded.hex(),
                "canonical_byte_length": len(encoded),
                "canonical_sha256": canonical_digest(frame),
            },
        }
    )
    manifest_path = root / "fixtures/manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    member = {
        "byte_length": len(fixture),
        "fixture_id": "CTL-270",
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "path": _PATH,
        "sha256": hashlib.sha256(fixture).hexdigest(),
    }
    others = [item for item in manifest["members"] if item["path"] != _PATH]
    if any(item["fixture_id"] == "CTL-270" for item in others):
        raise ValueError("fixture_id_already_owned")
    manifest["members"] = sorted([*others, member], key=lambda item: item["path"].encode())
    expected_manifest = json.dumps(manifest).encode() + b"\n"
    fixture_path = root / "fixtures" / _PATH
    if args.write:
        fixture_path.write_bytes(fixture)
        manifest_path.write_bytes(expected_manifest)
        return 0
    return int(
        not fixture_path.exists()
        or fixture_path.read_bytes() != fixture
        or manifest_path.read_bytes() != expected_manifest
    )


if __name__ == "__main__":
    raise SystemExit(main())
