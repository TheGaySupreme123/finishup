"""Generate the owned check-conclusion vectors without modifying earlier fixture members."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from finishup.domain.events import EventSchema, decode_payload, encode_payload
from finishup.domain.values import freeze_json
from finishup.protocol.canonical import canonical_digest, canonical_encode

_RELATIVE = "canonical/check-conclusion-1.3.0.case.json"
_ID = "CHK-001"


def document(root: Path) -> dict[str, Any]:
    source = json.loads((root / "fixtures/receipts/semantic-advisory.case.json").read_bytes())
    shared = source["input"]["shared_current_check"]
    provenance = source["expected"]["variants"]["success_after_durable_receipt"][
        "semantic_provenance"
    ]
    coverage = dict(shared["coverage"])
    coverage["check_types"] = ["deterministic", "semantic_model_derived"]
    coverage["ledger_freshness"] = "partial"
    coverage["known_gaps"] = ["content_unselected"]
    base: dict[str, Any] = {
        "mode": "semantic_required",
        "policies": [{"policy_id": "work-integrity", "policy_version": "0.1.0"}],
        "scope": {"claim_ids": [], "obligation_ids": []},
        "policy_executions": [
            {
                "policy_id": "work-integrity",
                "policy_version": "0.1.0",
                "outcome": "run",
                "reason": "completed",
            }
        ],
        "subject_frontier": shared["frontier"],
        "verdict": "insufficient_coverage",
        "returned_finding_ids": [],
        "suppressed_count": 0,
        "coverage": coverage,
        "semantic_status": "succeeded",
        "semantic_reason": "semantic_completed",
        "engine_version": "0.1.0",
        "projection_version": "yoetz/0.1.0",
        "semantic_provenance": provenance,
    }
    reduced = dict(base)
    reduced["coverage"] = {
        **coverage,
        "known_gaps": ["content_unselected", "semantic_reference_scope_reduced"],
    }
    # Issue #904: a reduced packet records the frontier references it included.
    reduced["semantic_included_refs"] = [
        "evd_00000000-0000-4000-8000-000000000904",
        "evt_00000000-0000-4000-8000-000000000904",
        "obl_00000000-0000-4000-8000-000000000904",
    ]
    vectors: list[dict[str, Any]] = []
    # ADR-031 (#883) appends one vector: a completed review that carried a check-time change
    # records keyed commitments to the files it was shown. Earlier vectors keep their bytes.
    check_change_files = {
        "complete": True,
        "fully_shown": ["hmac-sha256:" + "1" * 64, "hmac-sha256:" + "2" * 64],
        "partially_shown": [
            {
                "clean_bytes": 67,
                "commitment": "hmac-sha256:" + "3" * 64,
                "redactions": 1,
                "section_admitted": True,
                "shown_bytes": 1024,
                "view_commitment": "hmac-sha256:" + "4" * 64,
            }
        ],
    }
    for conclusion, source, files in [
        (None, base, None),
        ("no_material_discrepancy", base, None),
        ("challenges_returned", base, None),
        ("insufficient_packet", base, None),
        ("no_material_discrepancy", base, check_change_files),
        # Issue #904 appends a reduced-scope review that recorded what its packet included.
        ("no_material_discrepancy", reduced, None),
    ]:
        version = "1.2.0" if conclusion is None else "1.3.0"
        wire = dict(source)
        if conclusion is not None:
            wire["semantic_conclusion"] = conclusion
        if files is not None:
            wire["check_change_files"] = files
        payload = decode_payload(EventSchema("check_recorded", version), freeze_json(wire))
        encoded = encode_payload(payload)
        vectors.append(
            {
                "schema_version": version,
                "payload": wire,
                "canonical_hex": canonical_encode(encoded).hex(),
                "digest": canonical_digest(encoded),
            }
        )
    # Issue #907: an unassessable review that named what it needed, on the same (unreleased)
    # 1.3.0 payload with the optional list. Structural fields only.
    missing_coverage = dict(coverage)
    missing_coverage["known_gaps"] = [
        "content_unselected",
        "semantic_missing_agent_suppliable",
        "semantic_missing_structurally_unavailable",
        "semantic_packet_insufficient",
    ]
    missing: dict[str, Any] = {
        **base,
        "coverage": missing_coverage,
        "semantic_conclusion": "insufficient_packet",
        # Canonical (kind, target_refs) order, as the domain payload requires.
        "missing_for_assessment": [
            {
                "availability": "structurally_unavailable_on_this_host",
                "kind": "command_identity",
                "target_refs": [],
            },
            {
                "availability": "agent_suppliable",
                "kind": "current_diff_for_path",
                "target_refs": ["evd_20000000-0000-4000-8000-000000000011"],
            },
        ],
    }
    payload = decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(missing))
    encoded = encode_payload(payload)
    vectors.append(
        {
            "schema_version": "1.3.0",
            "payload": missing,
            "canonical_hex": canonical_encode(encoded).hex(),
            "digest": canonical_digest(encoded),
        }
    )
    return {
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "fixture_id": _ID,
        "purpose": (
            "Distinguish legacy unknown review outcomes from recorded conclusions, and record "
            "a reduced review packet's included references."
        ),
        "minimum_versions": {"fixture_contract": "1.0.0", "protocol": "1.0"},
        "owns_requirements": [
            "ISSUE-884/check-conclusion",
            "ISSUE-904/reduced-scope-included-refs",
            "ISSUE-907/missing-for-assessment",
        ],
        "controls": {
            "clock": "fixture_supplied",
            "ids": "fixture_supplied",
            "network": "forbidden",
            "external_io": "forbidden",
            "randomness": "forbidden",
        },
        "input": {"vectors": vectors},
        "expected": {"legacy_conclusion": None},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose --write or --check")
    root = Path(__file__).resolve().parents[1]
    data = canonical_encode(document(root))
    target = root / "fixtures" / _RELATIVE
    manifest_path = root / "fixtures/manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    unrelated = [member for member in manifest["members"] if member["path"] != _RELATIVE]
    if any(member["fixture_id"] == _ID for member in unrelated):
        raise ValueError("fixture_identity_conflict")
    member = {
        "fixture_id": _ID,
        "path": _RELATIVE,
        "byte_length": len(data),
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    existing = [item for item in manifest["members"] if item["path"] == _RELATIVE]
    if args.check:
        if not target.is_file() or target.read_bytes() != data or existing != [member]:
            raise ValueError("check_conclusion_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("check conclusion fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
