"""Generate canonical #1084 vectors: server-filled publish results and brief, labelled status.

The vectors freeze the unreleased in-place additions of ADR-050 on the public wire:

* ``publish-work-result`` 1.1.0: ``server_filled`` on a sparse success, a dry run and the reduced
  ``accepted_projection_unavailable`` success, with the shapes it refuses (a service-filled
  ``request_id``, overlapping or unsorted groups, and the retired ``replay_notice``);
* ``status-result`` 1.4.0: the ``detail: brief`` body with ``closure_state``, the
  ``occurred_at_source: service_clock`` history label, and the shapes they refuse.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Final, cast

from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_PATH: Final = "canonical/server-filled-brief-status-1.4.0.case.json"
_FIXTURE_ID: Final = "CAN-022"
_HEAD: Final = "sha256:" + "b1" * 32
_NEXT: Final = "sha256:" + "b2" * 32
_FILLED: Final[list[JsonValue]] = [
    "artifact_refs",
    "causal_parents",
    "event_id",
    "evidence_refs",
    "occurred_at",
]
_COVERAGE: Final[dict[str, JsonValue]] = {
    "publication_channels": ["cooperative_mcp"],
    "authorship_assurance": "self_asserted",
    "artifact_observation": "published_only",
    "evidence_immutability": "metadata_only",
    "ledger_freshness": "current",
    "check_types": ["none"],
    "known_gaps": [],
}
_PRIVACY_PROJECTION: Final[dict[str, JsonValue]] = {
    "sink": "agent_context",
    "local_disclosure_receipt_id": "egr_00000000-0000-4000-8000-0000000000b3",
    "policy_id": "pvy_00000000-0000-4000-8000-0000000000b4",
    "policy_version": "1",
    "policy_digest": "sha256:" + "b5" * 32,
    "included_categories": [],
    "blocked_categories": [],
    "omitted_pointers": [],
    "projection_commitment": "hmac-sha256:" + "b6" * 32,
}
_IDENTITY: Final[dict[str, JsonValue]] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-0000000000b7",
    "ok": True,
    "task_id": "tsk_00000000-0000-4000-8000-0000000000b8",
    "session_id": "ses_00000000-0000-4000-8000-0000000000b9",
    "writer_id": "wri_00000000-0000-4000-8000-0000000000ba",
}


def _event(number: int) -> str:
    return f"evt_00000000-0000-4000-8000-{number:012x}"


def _filled(*groups: tuple[list[JsonValue], list[JsonValue]]) -> dict[str, JsonValue]:
    return {
        "request": ["expected_frontier"],
        "drafts": [{"fields": fields, "indexes": indexes} for fields, indexes in groups],
    }


def _accepted(number: int) -> dict[str, JsonValue]:
    return {
        "event_id": _event(number),
        "schema_name": "decision_recorded",
        "schema_version": "1.1.0",
        "writer_sequence": str(number + 1),
        "ingestion_sequence": str(number + 1),
        "accepted_at": "2026-10-17T12:00:00.000Z",
        "predecessor_digest": _HEAD,
        "entry_digest": _NEXT,
        "projection_status": "projected",
    }


def publish_success(filled: dict[str, JsonValue] | None) -> dict[str, JsonValue]:
    """A sparse two-draft publish success; ``filled`` is its ``server_filled`` record."""

    body: dict[str, JsonValue] = {
        **_IDENTITY,
        "outcome": "accepted",
        "subject_frontier": {"sequence": "1", "head_digest": _HEAD},
        "result_frontier": {"sequence": "3", "head_digest": _NEXT},
        "accepted_events": [_accepted(1), _accepted(2)],
        "warning_codes": [],
        "coverage": copy.deepcopy(_COVERAGE),
        "gaps": [],
        "versions": {
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "0.1.0",
            "policy_packs": ["research-evidence/0.2.0", "work-integrity/0.3.0"],
        },
        "privacy_projection": copy.deepcopy(_PRIVACY_PROJECTION),
    }
    if filled is not None:
        body["server_filled"] = filled
    return body


def publish_dry_run() -> dict[str, JsonValue]:
    """The same batch previewed: nothing appended, the same names filled."""

    return {
        **_IDENTITY,
        "outcome": "dry_run",
        "evidential": False,
        "subject_frontier": {"sequence": "1", "head_digest": _HEAD},
        "result_frontier": {"sequence": "1", "head_digest": _HEAD},
        "would_accept": [
            {
                "event_id": _event(number),
                "schema_name": "decision_recorded",
                "schema_version": "1.1.0",
                "causal_parents": [],
                "artifact_refs": [],
                "evidence_refs": [],
            }
            for number in (1, 2)
        ],
        "coverage": copy.deepcopy(_COVERAGE),
        "gaps": [],
        "server_filled": _filled((_FILLED, ["0", "1"])),
    }


def publish_reduced() -> dict[str, JsonValue]:
    """A replayed operation whose full response could not be built keeps its provenance."""

    return {
        **_IDENTITY,
        "response_completeness": "accepted_projection_unavailable",
        "reason_code": "response_projection_failed",
        "correlation_id": "err_00000000-0000-4000-8000-0000000000bb",
        "outcome": "replayed",
        "subject_frontier": {"sequence": "1", "head_digest": _HEAD},
        "result_frontier": {"sequence": "3", "head_digest": _NEXT},
        "accepted_events": [
            {
                "event_id": _event(number),
                "entry_digest": _NEXT,
                "ingestion_sequence": str(number + 1),
            }
            for number in (1, 2)
        ],
        "server_filled": _filled((_FILLED, ["0", "1"])),
    }


def _history_item(number: int, source: str | None) -> dict[str, JsonValue]:
    item: dict[str, JsonValue] = {
        "event_id": _event(number),
        "schema_name": "decision_recorded",
        "schema_version": "1.1.0",
        "actor_id": "harness:fixture",
        "publication_channel": "cooperative_mcp",
        "ingestion_sequence": str(number + 1),
        "occurred_at": "2026-10-17T12:00:00.000Z",
        "accepted_at": "2026-10-17T12:00:00.000Z",
        "occurred_at_consistency": "within_forward_skew_allowance",
        "projection_status": "projected",
        "summary_code": "decision_recorded",
    }
    if source is not None:
        item["occurred_at_source"] = source
    return item


def status_brief(view: str, page: dict[str, JsonValue], **extra: JsonValue) -> dict[str, JsonValue]:
    """A ``detail: brief`` non-compact status body with its closure state."""

    body: dict[str, JsonValue] = {
        **_IDENTITY,
        "detail": "brief",
        "view": view,
        "result_frontier": {"sequence": "3", "head_digest": _NEXT},
        "page": page,
        "gaps": [],
        "closure_state": {
            "state": "action_required",
            "blocking_conditions": ["obligations_open"],
            "agent_actionable": ["obligations_open", "check_not_recorded"],
        },
        "privacy_projection": copy.deepcopy(_PRIVACY_PROJECTION),
    }
    body.update(extra)
    return body


def _history_page(*items: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {"items": list(items), "next_cursor": None}


def _vectors() -> tuple[dict[str, JsonValue], ...]:
    overlapping = publish_success(_filled((_FILLED, ["0"]), (["occurred_at"], ["0"])))
    unsorted = publish_success(_filled((_FILLED, ["1", "0"])))
    request_id_filled = publish_success(_filled((_FILLED, ["0", "1"])))
    request_id_filled["server_filled"] = {
        "request": ["expected_frontier", "request_id"],
        "drafts": [{"fields": _FILLED, "indexes": ["0", "1"]}],
    }
    retired_notice = publish_success(_filled((_FILLED, ["0", "1"])))
    retired_notice["replay_notice"] = {"notice": "unresolved_call_resumed", "text": "replayed"}
    reduced_without = publish_reduced()
    del reduced_without["server_filled"]
    coverage_on_brief_page = status_brief(
        "history", _history_page(), coverage=copy.deepcopy(_COVERAGE)
    )
    missing_state = status_brief("history", _history_page())
    del missing_state["closure_state"]
    # (vector_id, schema, payload, schema_admitted, admitted)
    cases: tuple[tuple[str, str, dict[str, JsonValue], bool, bool], ...] = (
        (
            "publish_sparse_success_filled",
            "publish-work-result",
            publish_success(_filled((_FILLED, ["0", "1"]))),
            True,
            True,
        ),
        (
            "publish_mixed_groups_by_first_index",
            "publish-work-result",
            publish_success(
                _filled((_FILLED, ["0"]), (["artifact_refs", "causal_parents", "event_id"], ["1"]))
            ),
            True,
            True,
        ),
        (
            "publish_complete_body_no_record",
            "publish-work-result",
            publish_success(None),
            True,
            True,
        ),
        ("publish_dry_run_filled", "publish-work-result", publish_dry_run(), True, True),
        ("publish_reduced_replay_filled", "publish-work-result", publish_reduced(), True, True),
        ("publish_reduced_without_record", "publish-work-result", reduced_without, True, True),
        (
            "rejected_service_filled_request_id",
            "publish-work-result",
            request_id_filled,
            False,
            False,
        ),
        ("rejected_retired_replay_notice", "publish-work-result", retired_notice, False, False),
        ("rejected_overlapping_groups", "publish-work-result", overlapping, True, False),
        ("rejected_unsorted_indexes", "publish-work-result", unsorted, True, False),
        (
            "status_brief_history_service_clock_label",
            "status-result",
            status_brief(
                "history", _history_page(_history_item(1, "service_clock"), _history_item(2, None))
            ),
            True,
            True,
        ),
        (
            "rejected_unknown_time_source",
            "status-result",
            status_brief("history", _history_page(_history_item(1, "caller"))),
            False,
            False,
        ),
        (
            "rejected_brief_page_with_coverage",
            "status-result",
            coverage_on_brief_page,
            False,
            False,
        ),
        ("rejected_brief_page_without_closure_state", "status-result", missing_state, False, False),
    )
    vectors: list[dict[str, JsonValue]] = []
    for vector_id, schema, payload, schema_admitted, admitted in cases:
        vectors.append(
            {
                "vector_id": vector_id,
                "schema": schema,
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
            "engine": "0.1.0",
            "protocol": "0.1",
            "publish_work_result_schema": "1.1.0",
            "status_result_schema": "1.4.0",
        },
        "owns_requirements": ["ISSUE-1084:server-filled-provenance", "ISSUE-1084:brief-status"],
        "purpose": (
            "Freeze the ADR-050 wire additions: server_filled on sparse, dry-run and reduced "
            "publish results, the brief status body with closure_state, the service-clock "
            "occurred_at_source history label, and the shapes each refuses (a service-filled "
            "request_id and the retired replay_notice included)."
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
            raise ValueError("publish_server_filled_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("publish server-filled and brief status fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
