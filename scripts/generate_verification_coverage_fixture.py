"""Own the bounded advisory verification-coverage status golden vector (#1170)."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final, cast

from finishup.domain.values import action_id, result_id
from finishup.domain.verification_coverage import (
    VerificationCoverage,
    VerificationCriterion,
    VerificationWitness,
    verification_coverage_to_json,
    verification_coverage_wire_lines,
)
from finishup.protocol.canonical import JsonValue, canonical_encode

_PATH: Final = "canonical/verification-coverage-1.4.0.case.json"
_FIXTURE_ID: Final = "CAN-024"


def document() -> dict[str, JsonValue]:
    root = Path(__file__).resolve().parents[1]
    base = json.loads(
        (root / "fixtures/canonical/status-check-admission-1.4.0.case.json").read_bytes()
    )
    status = base["input"]["results"]["capture_refused"]
    coverage = VerificationCoverage(
        (
            VerificationCriterion(
                "Every case must meet the bound",
                "task_statement",
                ("failing_cases", "own_or_tuned_only"),
                (
                    VerificationWitness(
                        result_id("res_00000000-0000-4000-8000-000000001170"),
                        action_id("act_00000000-0000-4000-8000-000000001170"),
                        "own_generated",
                        100,
                        6,
                        True,
                        "105.61 mm",
                    ),
                ),
                unresolved_failing_runs=1,
            ),
            VerificationCriterion("Write the labels", "obligation", ("no_test",)),
        )
    )
    declared = verification_coverage_to_json(coverage)
    status["view"] = "coverage"
    status["page"] = {"verification_coverage": declared, "next_cursor": None}
    return {
        "fixture_id": _FIXTURE_ID,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "minimum_versions": {"protocol": "0.1", "status_result_schema": "1.4.0"},
        "owns_requirements": ["issue-1170:advisory-verification-coverage"],
        "purpose": "Keep known failures and an untested output visible without certifying correctness.",
        "controls": {
            "clock": "fixture_supplied",
            "external_io": "forbidden",
            "network": "forbidden",
            "randomness": "forbidden",
        },
        "input": {"status_result": status},
        "expected": {
            "coverage_lines": list(
                verification_coverage_wire_lines(cast(dict[str, object], declared))
            )
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
    manifest = cast(dict[str, Any], json.loads(manifest_path.read_bytes()))
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
            raise ValueError("verification_coverage_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("verification coverage fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
