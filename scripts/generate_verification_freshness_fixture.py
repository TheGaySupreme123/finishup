"""Own the #1143 observation-wire vectors and their single fixture-manifest member."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from finishup.domain.workspace_effect import workspace_path_identity
from finishup.protocol.canonical import canonical_digest, canonical_encode

_PATH = "observations/verification-freshness.case.json"
_ID = "FRESH-1143"


def expected(root: Path) -> tuple[bytes, bytes]:
    baseline = json.loads(
        (root / "fixtures/canonical/control-native-capture-2.5.case.json").read_bytes()
    )
    template = baseline["input"]["vectors"][0]["request"]
    identity = workspace_path_identity(b"f" * 32, "source.py")
    vectors: list[dict[str, Any]] = []
    for index, (name, effect, entries, valid) in enumerate(
        (
            ("input-changed", "changed", [identity], True),
            ("byte-identical", "unchanged", [], True),
            ("unknown-comparison", "unavailable", None, True),
            ("duplicate-identities", "changed", [identity, identity], False),
            ("invalid-identity", "changed", ["source.py"], False),
        )
    ):
        request = json.loads(json.dumps(template))
        request["rpc_id"] = f"rpc_00000000-0000-4000-8000-{114300 + index:012d}"
        structural: dict[str, Any] = request["body"]["envelope"]["structural_payload"]
        structural["workspace_effect"] = effect
        if entries is not None:
            structural["workspace_changed_entries"] = entries
        encoded = canonical_encode(request)
        vectors.append(
            {
                "name": name,
                "request": request,
                "valid": valid,
                "canonical_sha256": canonical_digest(request),
                "byte_length": len(encoded),
            }
        )
    document: dict[str, Any] = {
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "fixture_id": _ID,
        "controls": {"network": "forbidden", "randomness": "fixture_supplied"},
        "minimum_versions": {"control_schema": "2.9.0"},
        "purpose": "Pin bounded keyed change identities; unknown is omitted and raw paths are refused.",
        "owns_requirements": ["ISSUE-1143", "ADR-042"],
        "input": {"vectors": vectors},
    }
    body = canonical_encode(document)
    manifest = json.loads((root / "fixtures/manifest.json").read_bytes())
    member = {
        "path": _PATH,
        "fixture_id": _ID,
        "byte_length": len(body),
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "sha256": hashlib.sha256(body).hexdigest(),
    }
    manifest["members"] = sorted(
        [item for item in manifest["members"] if item["path"] != _PATH] + [member],
        key=lambda item: item["path"],
    )
    return body, json.dumps(manifest).encode() + b"\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose --write or --check")
    root = Path(__file__).resolve().parents[1]
    body, manifest = expected(root)
    targets = ((root / "fixtures" / _PATH, body), (root / "fixtures/manifest.json", manifest))
    if args.write:
        for path, data in targets:
            path.write_bytes(data)
    elif any(not path.is_file() or path.read_bytes() != data for path, data in targets):
        print("verification freshness fixture: STALE")
        return 1
    print("verification freshness fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
