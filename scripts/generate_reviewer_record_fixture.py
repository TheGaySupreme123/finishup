"""Golden vectors for the reviewer conversation record on check-recorded and check-result 1.6.0.

#1118: the optional ``reviewer`` record is new in check-recorded 1.6.0 and on the check-result
1.6.0 success branch. The earlier versions stay closed and refuse it. Each payload is one record's
exact wire form; the conformance test places it on a complete event and check result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Final, cast

from finishup.application.result_delivery import page_result
from finishup.mcp.summaries import render_check_review_delivery
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_PATH: Final = "canonical/check-reviewer-record-1.6.0.case.json"
_FIXTURE_ID: Final = "CHK-160"
_DIGEST: Final = "sha256:" + "a" * 64


def _result_delivery_vector() -> dict[str, JsonValue]:
    source: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "ok": True,
        "state": "complete",
        "request_id": "req_00000000-0000-4000-8000-000000000001",
        "task_id": "tsk_00000000-0000-4000-8000-000000000002",
        "session_id": "ses_00000000-0000-4000-8000-000000000003",
        "result_frontier": {"sequence": "42", "head_digest": _DIGEST},
        "verdict": "action_required",
        "agent_next": "Read the complete uncertainty before choosing an action.",
        "review_summary": "Read the complete finding before deciding.",
        "findings": [
            {
                "finding_id": "fnd_00000000-0000-4000-8000-000000000005",
                "challenge": {
                    "discrepancy": 'An alternative remains: "עברית 😀". ' * 80,
                    "requested_next_step": "answer_question",
                    "alternative_interpretation": "The supplied reference may be intentional.",
                    "uncertainty": "Verify its authority before changing it.",
                },
            }
        ],
    }
    page = page_result(
        source,
        key=b"fixture-delivery-key-not-a-secret",
        method="check",
        selector={"request_id": source["request_id"]},
        writer_id="wri_00000000-0000-4000-8000-000000000004",
        sink="agent_context",
    )
    # Cursor authentication is round-tripped separately. Normalize this opaque value so the
    # golden presentation bytes do not depend on a platform's compression-library version.
    page["next_cursor"] = "fixture.cursor"
    return {
        "source": source,
        "payload": page,
        "canonical_hex": canonical_encode(page).hex(),
        "digest": canonical_digest(page),
        "cursor_normalization": "fixture.cursor",
        "schema": "operations/check-result-1.7.0.schema.json",
    }


def _vectors() -> tuple[dict[str, JsonValue], ...]:
    read: dict[str, JsonValue] = {
        "action": "read_file",
        "baseline": "read_time",
        "call": "1",
        "disclosure": "egr_00000000-0000-4000-8000-000000000001",
        "lines": ["1", "12"],
        "reason": None,
        "result_bytes": "705",
        "result_digest": _DIGEST,
        "root": "w1",
        "source": "src_" + "0" * 24,
        "standing": "workspace_content",
        "status": "ok",
    }
    cases: tuple[tuple[str, dict[str, JsonValue]], ...] = (
        (
            "final_after_one_file_read",
            {
                "cleanup": "terminated",
                "ended": None,
                "exchanges": "2",
                "read_bytes": "705",
                "reads": [read],
                "reads_used": "1",
            },
        ),
        (
            "incomplete_without_reads",
            {
                "cleanup": None,
                "ended": "format_invalid",
                "exchanges": "2",
                "read_bytes": "0",
                "reads": [],
                "reads_used": "0",
            },
        ),
    )
    return tuple(
        {
            "admitted_versions": ["1.6.0"],
            "canonical_hex": canonical_encode(payload).hex(),
            "digest": canonical_digest(payload),
            "payload": payload,
            "refused_versions": ["1.4.0", "1.5.0"],
            "surface": "check_reviewer_record",
            "vector_id": vector_id,
        }
        for vector_id, payload in cases
    )


def document() -> dict[str, JsonValue]:
    delivery_source: dict[str, JsonValue] = {
        "review_summary": "The supplied reference may be intentional.",
        "findings": [
            {
                "finding_id": "fnd_00000000-0000-4000-8000-000000000001",
                "challenge": {
                    "discrepancy": "The two references disagree.",
                    "requested_next_step": "act",
                    "alternative_interpretation": "Keep the task-supplied reference.",
                    "uncertainty": "The authoritative reference is ambiguous.",
                },
            }
        ],
    }
    delivery = render_check_review_delivery(delivery_source)
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
        "input": {
            "vectors": list(_vectors()),
            "review_delivery": {
                "source": delivery_source,
                "text": delivery,
                "canonical_hex": canonical_encode(delivery).hex(),
                "digest": canonical_digest(delivery),
            },
            "result_delivery": _result_delivery_vector(),
            "stopped_review": {
                "semantic_status": "unavailable",
                "semantic_reason": "round_limit_unassessable",
            },
        },
        "minimum_versions": {
            "check_recorded_schema": "1.6.0",
            "check_result_schema": "1.6.0",
            "engine": "0.1.0",
            "protocol": "0.1",
        },
        "owns_requirements": [
            "ADR-006:reviewer-record",
            "ADR-040:requested-review-stopped",
            "ISSUE-1139:bounded-review-delivery",
        ],
        "purpose": (
            "Freeze the reviewer conversation record. check-recorded 1.6.0 and the check-result "
            "1.6.0 success admit it; check-recorded 1.4.0/1.5.0 and check-result 1.5.0 refuse it."
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
            raise ValueError("reviewer_record_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("reviewer record fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
