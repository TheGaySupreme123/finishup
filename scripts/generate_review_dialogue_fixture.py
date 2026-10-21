"""Generate the owned review-dialogue vectors without modifying earlier fixture members.

Issue #905 records what the reviewer asked for on each AI-powered finding, the earlier finding a
re-raise names, and the reviewer's per-finding rulings on a check. The vectors pin the exact bytes
of the optional fields on the (unreleased) 1.3.0 events beside rows without them, so a row written
by an earlier 0.3 build keeps its recorded bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from finishup.domain.events import EventSchema, decode_payload, encode_payload
from finishup.domain.values import freeze_json
from finishup.protocol.canonical import canonical_digest, canonical_encode

_RELATIVE = "canonical/review-dialogue-1.3.0.case.json"
_ID = "DLG-001"
_OBLIGATION = "obl_828ab204-0000-4000-8000-000000000001"
_FIRST = "fnd_fb333698-0000-4000-8000-000000000001"
_RESTATED = "fnd_97289e6b-0000-4000-8000-000000000002"


def _finding(
    root: Path, finding_id: str, summary: str, detail: str, refs: list[str]
) -> dict[str, Any]:
    source = json.loads((root / "fixtures/receipts/semantic-advisory.case.json").read_bytes())
    shared = source["input"]["shared_current_check"]
    provenance = source["expected"]["variants"]["success_after_durable_receipt"][
        "semantic_provenance"
    ]
    coverage = dict(shared["coverage"])
    coverage["check_types"] = ["deterministic", "semantic_model_derived"]
    return {
        "finding_id": finding_id,
        "kind": "completion_with_open_obligations",
        "origin": "semantic_model_derived",
        "priority": 1,
        "summary": summary,
        "detail": detail,
        "subject_refs": sorted(refs),
        "policy_id": "work-integrity",
        "policy_version": "0.1.0",
        "subject_frontier": shared["frontier"],
        "coverage": coverage,
        "provenance": provenance,
    }


def _check(root: Path) -> dict[str, Any]:
    source = json.loads((root / "fixtures/receipts/semantic-advisory.case.json").read_bytes())
    shared = source["input"]["shared_current_check"]
    provenance = source["expected"]["variants"]["success_after_durable_receipt"][
        "semantic_provenance"
    ]
    coverage = dict(shared["coverage"])
    coverage["check_types"] = ["deterministic", "semantic_model_derived"]
    coverage["ledger_freshness"] = "partial"
    coverage["known_gaps"] = ["semantic_packet_insufficient"]
    return {
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
        "semantic_conclusion": "no_material_discrepancy",
    }


def _first_privacy_projection(value: object) -> dict[str, Any]:
    """Reuse a reviewed privacy projection instead of inventing one."""

    if isinstance(value, dict):
        source = cast(dict[str, Any], value)
        found = source.get("privacy_projection")
        if isinstance(found, dict):
            return cast(dict[str, Any], found)
        children: list[object] = list(source.values())
    elif isinstance(value, list):
        children = list(cast(list[object], value))
    else:
        return {}
    for item in children:
        nested = _first_privacy_projection(item)
        if nested:
            return nested
    return {}


def document(root: Path) -> dict[str, Any]:
    # numba-stencil-boundary-modes (DeepSWE v2): one environment-blocked obligation raised, then
    # restated under a new id. The earlier row has no dialogue fields; the restatement records the
    # challenge fields and names the earlier finding it restates.
    legacy = _finding(
        root,
        _FIRST,
        "Completion claim includes an open llvmlite 0.46.0 verification obligation.",
        "Please make one concrete attempt to satisfy the open obligation.",
        [_OBLIGATION],
    )
    restated = _finding(
        root,
        _RESTATED,
        "Completion claim does not satisfy the open required-version verification obligation.",
        "Make one concrete authorized attempt to obtain llvmlite 0.46.0, then run the tests.",
        [_OBLIGATION],
    )
    restated["challenge"] = {
        "alternative_interpretation": "The package index may be unreachable from this sandbox.",
        "discrepancy": "The claim is complete while the llvmlite 0.46.0 obligation is open.",
        "requested_next_step": "act",
        "uncertainty": "The recorded install failure may already be the authorized attempt.",
    }
    restated["relates_to"] = [_FIRST]
    link_only = dict(restated)
    link_only.pop("challenge")
    # kea-atomic-signal-selectors: the recheck after the repair rules the repaired finding fixed
    # (citing the regression result recorded after it) even though the packet as a whole was
    # insufficient, and cannot assess a sibling. A check without rulings keeps its earlier bytes.
    check = _check(root)
    ruled = dict(check)
    ruled["semantic_conclusion"] = "insufficient_packet"
    ruled["prior_finding_verdicts"] = [
        {"cited_refs": [], "finding_id": _RESTATED, "verdict": "unassessable"},
        {
            "cited_refs": ["res_866db2dd-0000-4000-8000-000000000003"],
            "finding_id": _FIRST,
            "verdict": "fixed",
        },
    ]
    # numba fnd_01c5aaf7: the agent answers that it will not do the environment-blocked item.
    # Only this terminal disposition rides response_recorded 1.1.0; a rejection keeps 1.0.0 bytes.
    frontier = check["subject_frontier"]
    not_done: dict[str, Any] = {
        "finding_id": _RESTATED,
        "finding_frontier": frontier,
        "disposition": "acknowledged_not_done",
        "reason": "llvmlite 0.46.0 is not installable in this sandbox; out of scope here.",
        "evidence_refs": [],
    }
    rejected: dict[str, Any] = {
        "finding_id": _FIRST,
        "finding_frontier": frontier,
        "disposition": "rejected",
        "reason": "The task statement excludes the llvmlite upgrade.",
        "evidence_refs": [],
    }
    # Issue #984: the agent repaired the first finding, FinishUP could not prove it, and the agent
    # verified it itself, citing its own recorded result. Rides response_recorded 1.1.0 too.
    self_verified: dict[str, Any] = {
        "finding_id": _FIRST,
        "finding_frontier": frontier,
        "disposition": "self_verified",
        "reason": "Re-ran the Map-key regression myself after the packet could not show it.",
        "evidence_refs": ["res_866db2dd-0000-4000-8000-000000000003"],
    }
    # Issue #996 (numba, as above): the restatement was minted as a new finding anyway; the agent
    # links it to the earlier finding it already answered instead of answering it again.
    duplicate: dict[str, Any] = {
        "finding_id": _RESTATED,
        "finding_frontier": frontier,
        "disposition": "duplicate_of",
        "evidence_refs": [],
        "duplicate_of_finding_id": _FIRST,
    }
    vectors: list[dict[str, Any]] = []
    for family, version, wire in (
        ("finding_recorded", "1.3.0", legacy),
        ("finding_recorded", "1.3.0", restated),
        ("finding_recorded", "1.3.0", link_only),
        ("check_recorded", "1.3.0", check),
        ("check_recorded", "1.3.0", ruled),
        ("response_recorded", "1.0.0", rejected),
        ("response_recorded", "1.1.0", not_done),
        ("response_recorded", "1.1.0", self_verified),
        ("response_recorded", "1.1.0", duplicate),
    ):
        payload = decode_payload(EventSchema(family, version), freeze_json(wire))
        encoded = encode_payload(payload)
        vectors.append(
            {
                "family": family,
                "schema_version": version,
                "payload": wire,
                "canonical_hex": canonical_encode(encoded).hex(),
                "digest": canonical_digest(encoded),
            }
        )
    request: dict[str, Any] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_01c5aaf7-0000-4000-8000-000000000001",
        "session_id": "ses_01c5aaf7-0000-4000-8000-000000000001",
        "writer_id": "wri_01c5aaf7-0000-4000-8000-000000000001",
        "expected_frontier": frontier,
        "finding_id": _RESTATED,
        "finding_frontier": frontier,
        "disposition": "acknowledged_not_done",
        "reason": not_done["reason"],
        "actor": {"actor_id": "harness:dialogue", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
    }
    status = json.loads(
        (root / "fixtures/canonical/status-check-admission-1.4.0.case.json").read_bytes()
    )
    projection = _first_privacy_projection(status)
    result: dict[str, Any] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request["request_id"],
        "ok": True,
        "task_id": "tsk_01c5aaf7-0000-4000-8000-000000000001",
        "session_id": request["session_id"],
        "writer_id": request["writer_id"],
        "subject_frontier": frontier,
        "result_frontier": frontier,
        "accepted_event": {
            "event_id": "evt_01c5aaf7-0000-4000-8000-000000000001",
            "writer_sequence": "3",
            "ingestion_sequence": frontier["sequence"],
            "accepted_at": "2026-09-30T12:00:00.000Z",
            "entry_digest": frontier["head_digest"],
        },
        "response": {
            "response_event_id": "evt_01c5aaf7-0000-4000-8000-000000000001",
            "finding_id": _RESTATED,
            "finding_frontier": frontier,
            "disposition": "acknowledged_not_done",
            "reason": not_done["reason"],
            "evidence": [],
        },
        "coverage": check["coverage"],
        "warning_codes": [],
        "versions": {
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "yoetz/0.1.0",
            "policy_packs": ["research-evidence/0.1.0", "work-integrity/0.1.0"],
        },
        "privacy_projection": projection,
    }
    operations: list[dict[str, Any]] = [
        {"schema": "respond-request", "schema_version": "1.1.0", "payload": request},
        {"schema": "respond-result", "schema_version": "1.1.0", "payload": result},
        {
            "schema": "respond-request",
            "schema_version": "1.1.0",
            "payload": {
                **request,
                "request_id": "req_01c5aaf7-0000-4000-8000-000000000002",
                "finding_id": _FIRST,
                "disposition": "self_verified",
                "reason": self_verified["reason"],
                "evidence_refs": self_verified["evidence_refs"],
            },
        },
        {
            "schema": "respond-request",
            "schema_version": "1.1.0",
            "payload": {
                **{key: value for key, value in request.items() if key != "reason"},
                "request_id": "req_01c5aaf7-0000-4000-8000-000000000003",
                "finding_id": _RESTATED,
                "disposition": "duplicate_of",
                "duplicate_of_finding_id": _FIRST,
            },
        },
    ]
    # #1146: pin the new kind on finding/event 1.4.0 without changing the historical vectors.
    decision = _finding(
        root,
        "fnd_97289e6b-0000-4000-8000-000000000003",
        "Decision needed: deferred loading versus immediate content.",
        "You decide; record your choice and reason with respond acknowledged or rejected.",
        [_OBLIGATION],
    )
    decision.update(
        kind="decision_needed",
        priority=3,
        policy_id="research-evidence",
        challenge={
            "discrepancy": "Immediate content avoids a delay after the initial render.",
            "alternative_interpretation": "Deferred loading improves the measured initial render.",
            "requested_next_step": "answer_question",
            "uncertainty": "Does the task forbid deferred loading?",
        },
    )
    decision_bytes = canonical_encode(
        encode_payload(
            decode_payload(EventSchema("finding_recorded", "1.4.0"), freeze_json(decision))
        )
    )
    return {
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "fixture_id": _ID,
        "purpose": (
            "Pin the additive review-dialogue event bytes beside unchanged legacy rows, and the "
            "terminal acknowledged_not_done and self_verified responses and the duplicate_of link "
            "on their 1.1.0 event and respond wire."
        ),
        "minimum_versions": {"fixture_contract": "1.0.0", "protocol": "1.0"},
        "owns_requirements": ["ISSUE-905/review-dialogue"],
        "controls": {
            "clock": "fixture_supplied",
            "ids": "fixture_supplied",
            "network": "forbidden",
            "external_io": "forbidden",
            "randomness": "forbidden",
        },
        "input": {
            "vectors": vectors,
            "operations": operations,
            "decision_needed": {
                "payload": decision,
                "canonical_hex": decision_bytes.hex(),
                "digest": canonical_digest(decision),
                "schema_version": "1.4.0",
            },
        },
        "expected": {"legacy_challenge": None},
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
            raise ValueError("review_dialogue_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("review dialogue fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
