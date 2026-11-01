"""Generate canonical check `await_observations` / `observations_awaited` vectors (issue #1012)."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Final, cast

from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_PATH: Final = "canonical/check-observations-awaited-1.4.0.case.json"
_FIXTURE_ID: Final = "CAN-016"


def _vectors() -> tuple[dict[str, JsonValue], ...]:
    # (vector_id, surface, payload, admitted)
    cases: tuple[tuple[str, str, dict[str, JsonValue], bool], ...] = (
        ("request_await_true", "check_request", {"await_observations": True}, True),
        ("request_await_false", "check_request", {"await_observations": False}, True),
        ("request_await_string", "check_request", {"await_observations": "true"}, False),
        (
            "result_complete",
            "check_result",
            {"observations_awaited": {"pending_count": "0", "state": "complete"}},
            True,
        ),
        (
            "result_bounded_timeout",
            "check_result",
            {"observations_awaited": {"pending_count": "3", "state": "bounded_timeout"}},
            True,
        ),
        (
            "result_unavailable",
            "check_result",
            {"observations_awaited": {"pending_count": "0", "state": "unavailable"}},
            True,
        ),
        (
            "result_complete_with_pending",
            "check_result",
            {"observations_awaited": {"pending_count": "2", "state": "complete"}},
            False,
        ),
        (
            "result_timeout_without_pending",
            "check_result",
            {"observations_awaited": {"pending_count": "0", "state": "bounded_timeout"}},
            False,
        ),
        (
            "result_unknown_state",
            "check_result",
            {"observations_awaited": {"pending_count": "0", "state": "skipped"}},
            False,
        ),
        (
            "result_extra_member",
            "check_result",
            {
                "observations_awaited": {
                    "pending_count": "0",
                    "rows": "0",
                    "state": "complete",
                }
            },
            False,
        ),
    )
    vectors: list[dict[str, JsonValue]] = []
    for vector_id, surface, payload, admitted in cases:
        vectors.append(
            {
                "vector_id": vector_id,
                "surface": surface,
                "admitted": admitted,
                "payload": payload,
                "canonical_hex": canonical_encode(payload).hex(),
                "digest": canonical_digest(payload),
            }
        )
    return tuple(vectors)


def document() -> dict[str, JsonValue]:
    return {
        "fixture_id": _FIXTURE_ID,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "minimum_versions": {
            "check_request_schema": "1.1.0",
            "check_result_schema": "1.4.0",
            "engine": "0.1.0",
            "protocol": "0.1",
        },
        "owns_requirements": ["ISSUE-1012:check-await-observations"],
        "purpose": (
            "Freeze the optional check request flag await_observations and the closed result "
            "member observations_awaited: admitted states with their count rule, and rejected "
            "shapes."
        ),
        "controls": {
            "clock": "fixture_supplied",
            "external_io": "forbidden",
            "network": "forbidden",
            "randomness": "forbidden",
        },
        "input": {"vectors": list(_vectors())},
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
        "fixture_id": _FIXTURE_ID,
        "path": _PATH,
        "byte_length": len(data),
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if args.check:
        if (
            not target.is_file()
            or target.read_bytes() != data
            or [item for item in manifest["members"] if item["path"] == _PATH] != [member]
        ):
            raise ValueError("check_observations_awaited_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("check observations-awaited fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
