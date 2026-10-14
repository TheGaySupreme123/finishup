"""Generate canonical check-totals accounting vectors for issue #971."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Final, cast

from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_PATH: Final = "canonical/check-totals-1.4.0.case.json"
_FIXTURE_ID: Final = "CAN-015"


def _totals(
    *,
    obligations: tuple[str, str, str, str, str, str],
    requested_items: tuple[str, str],
    commands: tuple[str, str, str, str, str, str],
    evidence: dict[str, str],
    findings: tuple[str, str, str, str],
    test_edits: tuple[str, str, str, str, str, str, str, str],
) -> dict[str, JsonValue]:
    return {
        "obligations": {
            key: value
            for key, value in zip(
                (
                    "declared",
                    "resolved",
                    "open",
                    "unreadable",
                    "with_evidence",
                    "scope_known",
                ),
                obligations,
                strict=True,
            )
        },
        "requested_items": {
            key: value
            for key, value in zip(("attempted", "unattempted"), requested_items, strict=True)
        },
        "commands": {
            key: value
            for key, value in zip(
                (
                    "observed",
                    "failed",
                    "unknown",
                    "live_failed",
                    "retired_by_rerun",
                    "disclosed_not_rerun_green",
                ),
                commands,
                strict=True,
            )
        },
        "evidence": evidence,
        "findings": {
            key: value
            for key, value in zip(
                ("returned", "actionable_returned", "coverage_only_returned", "suppressed"),
                findings,
                strict=True,
            )
        },
        "test_edits": {
            key: value
            for key, value in zip(
                (
                    "examined",
                    "baseline_known",
                    "modified",
                    "renamed",
                    "deleted",
                    "skipped",
                    "unjustified",
                    "unknown",
                ),
                test_edits,
                strict=True,
            )
        },
    }


def _vectors() -> tuple[dict[str, JsonValue], ...]:
    common_evidence = {
        "content_digest": "0",
        "independently_reproduced": "0",
        "immutable_snapshot": "0",
        "metadata_only": "0",
        "mutable_reference": "0",
    }
    cases = (
        (
            "clean_scoped",
            _totals(
                obligations=("2", "2", "0", "0", "2", "1"),
                requested_items=("2", "0"),
                commands=("2", "0", "0", "0", "0", "0"),
                evidence={**common_evidence, "immutable_snapshot": "2"},
                findings=("0", "0", "0", "0"),
                test_edits=("0", "0", "0", "0", "0", "0", "0", "0"),
            ),
            "no_issue_detected",
        ),
        (
            "insufficient",
            _totals(
                obligations=("2", "0", "1", "1", "0", "1"),
                requested_items=("0", "1"),
                commands=("1", "0", "1", "0", "0", "0"),
                evidence=common_evidence,
                findings=("0", "0", "0", "0"),
                test_edits=("0", "0", "0", "0", "0", "0", "0", "0"),
            ),
            "insufficient_coverage",
        ),
        (
            "findings",
            _totals(
                obligations=("1", "1", "0", "0", "1", "1"),
                requested_items=("0", "0"),
                commands=("0", "0", "0", "0", "0", "0"),
                evidence={**common_evidence, "immutable_snapshot": "1"},
                findings=("2", "1", "1", "3"),
                test_edits=("0", "0", "0", "0", "0", "0", "0", "0"),
            ),
            "action_required",
        ),
        (
            "livefailure",
            _totals(
                obligations=("0", "0", "0", "0", "0", "1"),
                requested_items=("0", "0"),
                commands=("1", "1", "0", "1", "0", "0"),
                evidence=common_evidence,
                findings=("1", "1", "0", "0"),
                test_edits=("0", "0", "0", "0", "0", "0", "0", "0"),
            ),
            "action_required",
        ),
    )
    vectors: list[dict[str, JsonValue]] = []
    for vector_id, totals, verdict in cases:
        payload: dict[str, JsonValue] = {"totals": totals, "verdict": verdict}
        encoded = canonical_encode(payload)
        vectors.append(
            {
                "vector_id": vector_id,
                "payload": payload,
                "canonical_hex": encoded.hex(),
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
            "engine": "0.1.0",
            "protocol": "0.1",
            "status_result_schema": "1.4.0",
        },
        "owns_requirements": ["ISSUE-971:check-totals"],
        "purpose": (
            "Freeze four structural accounting cases: a clean current scope, incomplete scope, "
            "returned findings, and a live observed failure with an omission finding."
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
            raise ValueError("check_totals_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("check totals fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
