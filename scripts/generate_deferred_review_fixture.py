"""Golden vectors for the pre-edit deferral reason on check-result 1.5.0.

1.4.0 still admits ``not_requested`` / ``deterministic_mode`` and refuses
``deferred_before_first_edit``. 1.5.0 admits both. The payloads are the two
reason pairs; the conformance test merges each onto a complete check result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Final, cast

from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_PATH: Final = "canonical/deferred-before-first-edit-1.5.0.case.json"
_FIXTURE_ID: Final = "CAN-021"


def _vectors() -> tuple[dict[str, JsonValue], ...]:
    cases: tuple[tuple[str, dict[str, JsonValue], bool], ...] = (
        (
            "not_requested_deferred_before_first_edit",
            {
                "semantic_reason": "deferred_before_first_edit",
                "semantic_status": "not_requested",
            },
            True,
        ),
        (
            "not_requested_deterministic_mode",
            {
                "semantic_reason": "deterministic_mode",
                "semantic_status": "not_requested",
            },
            True,
        ),
    )
    vectors: list[dict[str, JsonValue]] = []
    for vector_id, payload, admitted in cases:
        vectors.append(
            {
                "admitted": admitted,
                "canonical_hex": canonical_encode(payload).hex(),
                "digest": canonical_digest(payload),
                "payload": payload,
                "surface": "check_result",
                "vector_id": vector_id,
            }
        )
    return tuple(vectors)


def document() -> dict[str, JsonValue]:
    return {
        "controls": {
            "clock": "fixture_supplied",
            "external_io": "forbidden",
            "network": "forbidden",
            "randomness": "forbidden",
        },
        "fixture_id": _FIXTURE_ID,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {"vectors": list(_vectors())},
        "minimum_versions": {
            "check_result_schema": "1.5.0",
            "engine": "0.1.0",
            "protocol": "0.1",
        },
        "owns_requirements": ["ADR-040:deferred-before-first-edit"],
        "purpose": (
            "Freeze the pre-edit deferral reason pair. check-result 1.5.0 admits "
            "not_requested/deferred_before_first_edit and still admits "
            "not_requested/deterministic_mode. check-result 1.4.0 admits only the latter."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    data = canonical_encode(cast(JsonValue, document()))
    target = root / "fixtures" / _PATH
    manifest_path = root / "fixtures/manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    unrelated = [item for item in manifest["members"] if item["path"] != _PATH]
    if any(item["fixture_id"] == _FIXTURE_ID for item in unrelated):
        raise ValueError("fixture_identity_conflict")
    member = {
        "byte_length": len(data),
        "fixture_id": _FIXTURE_ID,
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "path": _PATH,
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if args.check:
        if (
            not target.is_file()
            or target.read_bytes() != data
            or [item for item in manifest["members"] if item["path"] == _PATH] != [member]
        ):
            raise ValueError("deferred_review_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("deferred review fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
