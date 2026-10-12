"""Generate canonical `mode: inspect` request and inspection-branch vectors (issue #1048)."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Final, cast

from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_PATH: Final = "canonical/check-inspection-1.4.0.case.json"
_FIXTURE_ID: Final = "CAN-017"
_OBLIGATION: Final = "obl_00000000-0000-4000-8000-0000000000e1"
_OPEN_OBLIGATION: Final = "obl_00000000-0000-4000-8000-0000000000e2"
_FINDING: Final = "fnd_00000000-0000-4000-8000-0000000000e3"
_RESULT: Final = "res_00000000-0000-4000-8000-0000000000e4"
_EVENT: Final = "evt_00000000-0000-4000-8000-0000000000e5"
_COMMITMENT: Final = "hmac-sha256:" + "e6" * 32


def inspection_body() -> dict[str, JsonValue]:
    """One complete inspection branch without its privacy projection (added by the reader)."""

    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-0000000000e7",
        "ok": True,
        "state": "inspected",
        "task_id": "tsk_00000000-0000-4000-8000-0000000000e8",
        "session_id": "ses_00000000-0000-4000-8000-0000000000e9",
        "writer_id": "wri_00000000-0000-4000-8000-0000000000ea",
        "subject_frontier": {"sequence": "12", "head_digest": "sha256:" + "eb" * 32},
        "remaining": {
            "readiness": "action_required",
            "predicted_conclusion": "insufficient_coverage",
            "agent_actionable": ["obligations_open"],
            "standing_limitations": ["semantic_review_not_requested"],
            "obligations": [
                {
                    "obligation_id": _OPEN_OBLIGATION,
                    "closure_class": "agent_work",
                    "closure_basis": "open",
                    "missing": [
                        {
                            "kind": "requested_item_not_attempted",
                            "owner": "agent",
                            "item_indexes": ["0"],
                        },
                        {
                            "kind": "command_run_not_observed",
                            "owner": "yoetz",
                            "item_indexes": ["1"],
                        },
                        {"kind": "resolution_evidence_not_cited", "owner": "agent"},
                    ],
                }
            ],
            "obligation_count": "1",
            "findings": [
                {
                    "finding_id": _FINDING,
                    "closure_class": "agent_work",
                    "closure_basis": "open_unanswered",
                }
            ],
            "finding_count": "1",
        },
        "observed_since_check": {
            "last_check_frontier": "9",
            "actions": [
                {
                    "event_id": _EVENT,
                    "ledger_sequence": "11",
                    "action_kind": "command",
                    "material_class": "other",
                    "tool_name": "Bash",
                    "write_scope": "workspace",
                    "outcome": "failure",
                    "exit_status": 1,
                    "command_commitment": _COMMITMENT,
                }
            ],
            "action_count": "1",
        },
        "evidence_alignment": {
            "basis": "recorded_links",
            "obligations": [
                {
                    "obligation_id": _OBLIGATION,
                    "alignment": "evidence_off_declared_items",
                    "declared_items": [
                        {"index": "0", "item_kind": "file"},
                        {"index": "1", "item_kind": "command"},
                    ],
                    "sources": [
                        {
                            "ref": _RESULT,
                            "origin": "observed",
                            "command_commitment": _COMMITMENT,
                            "outcome": "success",
                            "named_item_indexes": [],
                        }
                    ],
                }
            ],
            "obligation_count": "1",
            "off_declared_count": "1",
        },
    }


def _with(path: tuple[str | int, ...], value: JsonValue) -> dict[str, JsonValue]:
    """A copy of the admitted body with one leaf replaced (the path alternates keys/indexes)."""

    body = copy.deepcopy(inspection_body())
    node: object = body
    for key in path[:-1]:
        node = (
            cast(dict[str, object], node)[key]
            if isinstance(key, str)
            else cast(list[object], node)[key]
        )
    last = path[-1]
    if isinstance(last, str):
        cast(dict[str, object], node)[last] = value
    else:
        cast(list[object], node)[last] = value
    return body


def _vectors() -> tuple[dict[str, JsonValue], ...]:
    uncounted = inspection_body()
    del cast(dict[str, JsonValue], uncounted["evidence_alignment"])["obligation_count"]
    # (vector_id, surface, payload, schema_admitted, admitted)
    cases: tuple[tuple[str, str, dict[str, JsonValue], bool, bool], ...] = (
        ("request_inspect", "check_request", {"mode": "inspect"}, True, True),
        (
            "request_inspect_await",
            "check_request",
            {"mode": "inspect", "await_observations": True},
            True,
            True,
        ),
        # The refusal of a minting check's options lives in the request model, not the schema
        # (a root conditional lowers the advertised check input on observed hosts, ADR-047).
        (
            "request_inspect_final_review",
            "check_request",
            {"mode": "inspect", "final_review": True},
            True,
            False,
        ),
        (
            "request_inspect_scope",
            "check_request",
            {"mode": "inspect", "scope": {"claim_ids": [], "obligation_ids": []}},
            True,
            False,
        ),
        ("request_unknown_mode", "check_request", {"mode": "inspection"}, False, False),
        ("result_inspection", "check_result", inspection_body(), True, True),
        (
            "result_inspection_with_verdict",
            "check_result",
            {**inspection_body(), "verdict": "no_issue_detected"},
            False,
            False,
        ),
        (
            "result_inspection_unknown_missing_kind",
            "check_result",
            _with(("remaining", "obligations", 0, "missing", 2, "kind"), "evidence_weak"),
            False,
            False,
        ),
        (
            "result_inspection_lists_own_call",
            "check_result",
            _with(("observed_since_check", "actions", 0, "material_class"), "yoetz_own_call"),
            False,
            False,
        ),
        (
            "result_inspection_unknown_alignment",
            "check_result",
            _with(("evidence_alignment", "obligations", 0, "alignment"), "matches"),
            False,
            False,
        ),
        # A bounded alignment list without its count could read as complete (review of #1048).
        (
            "result_inspection_alignment_uncounted",
            "check_result",
            uncounted,
            False,
            False,
        ),
    )
    vectors: list[dict[str, JsonValue]] = []
    for vector_id, surface, payload, schema_admitted, admitted in cases:
        vectors.append(
            {
                "vector_id": vector_id,
                "surface": surface,
                "schema_admitted": schema_admitted,
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
        "owns_requirements": ["ISSUE-1048:check-inspection"],
        "purpose": (
            "Freeze the read-only check mode inspect: the admitted request, the options refused "
            "beside it by the request model, and the closed inspection result branch with "
            "rejected shapes."
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
            raise ValueError("check_inspection_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("check inspection fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
