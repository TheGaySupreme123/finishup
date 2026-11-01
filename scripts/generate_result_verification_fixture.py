"""Own the optional result-recorded 1.1.0 verification manifest golden vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Final

from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_PATH: Final = "canonical/result-verification-1.1.0.case.json"
_FIXTURE_ID: Final = "CAN-023"


def document() -> dict[str, JsonValue]:
    base: dict[str, JsonValue] = {
        "result_id": "res_00000000-0000-4000-8000-000000001170",
        "action_id": "act_00000000-0000-4000-8000-000000001170",
        "outcome": "success",
    }
    manifest: dict[str, JsonValue] = {
        "criterion_quote": "Keep known failing cases visible",
        "data_source": "independent",
        "cases": 7,
        "failing": 1,
        "worst": "absolute error 0.25",
        "tuned_on_these_cases": False,
        "test_file": "checks/check_cases.py",
        "results_file": "checks/results.json",
        "report_digest": "sha256:" + "a" * 64,
    }
    cases: tuple[tuple[str, dict[str, JsonValue], bool, bool], ...] = (
        ("legacy_without_manifest", base, True, True),
        ("independent_with_failure", {**base, "verification": manifest}, False, True),
        ("all_cases_fail", {**base, "verification": {**manifest, "failing": 7}}, False, True),
        (
            "zero_cases",
            {**base, "verification": {**manifest, "cases": 0, "failing": 0}},
            False,
            True,
        ),
        (
            "failing_exceeds_cases",
            {**base, "verification": {**manifest, "failing": 8}},
            False,
            False,
        ),
        ("boolean_count", {**base, "verification": {**manifest, "cases": True}}, False, False),
        (
            "blank_quote",
            {**base, "verification": {**manifest, "criterion_quote": "  "}},
            False,
            False,
        ),
        ("null_manifest", {**base, "verification": None}, False, False),
        # Issue #1226: a test file alone declares the test; a report binds to it only with both
        # results_file and report_digest.
        (
            "test_file_alone",
            {
                **base,
                "verification": {
                    key: value
                    for key, value in manifest.items()
                    if key not in {"results_file", "report_digest"}
                },
            },
            False,
            True,
        ),
        (
            "results_file_without_digest",
            {
                **base,
                "verification": {
                    key: value for key, value in manifest.items() if key != "report_digest"
                },
            },
            False,
            False,
        ),
        (
            "report_without_test_file",
            {
                **base,
                "verification": {
                    key: value for key, value in manifest.items() if key != "test_file"
                },
            },
            False,
            False,
        ),
    )
    return {
        "fixture_id": _FIXTURE_ID,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "minimum_versions": {
            "engine": "0.1.0",
            "protocol": "0.1",
            "result_recorded_schema": "1.1.0",
        },
        "owns_requirements": [
            "issue-1170:optional-test-manifest",
            "issue-1226:test-file-alone",
        ],
        "purpose": "Freeze optional agent-declared result verification without changing the released result shape.",
        "controls": {
            "clock": "fixture_supplied",
            "external_io": "forbidden",
            "network": "forbidden",
            "randomness": "forbidden",
        },
        "input": {
            "vectors": [
                {
                    "vector_id": name,
                    "payload": payload,
                    "admitted_1_0": old,
                    "admitted_1_1": new,
                    "canonical_hex": canonical_encode(payload).hex(),
                    "digest": canonical_digest(payload),
                }
                for name, payload, old, new in cases
            ]
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    data = canonical_encode(document())
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
            raise ValueError("result_verification_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("result verification fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
