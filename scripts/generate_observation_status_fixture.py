"""Write the canonical observation-status selection wire fixtures and manifest members.

CTL-260 freezes the additive 2.6 selection-runtime projection; CTL-290 freezes the 2.9
configurable-capacity projection (custom queue count, capacity labels, effective budget).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from finishup.domain.observation_budget import (
    BUDGET_VALIDATION_STATUS,
    STATE_DOCUMENT_CEILING_BYTES,
    BudgetLimits,
    BudgetUsage,
    ObservationCapacity,
    ObservationMode,
    evaluate_pressure,
    no_cap_support,
)
from finishup.domain.observation_settings import (
    EFFECTIVE_BUDGET_SCHEMA,
    ObservationSelectionRuntimeStatus,
    observation_selection_runtime_status_to_json,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse

_MANIFEST_RELATIVE = Path("fixtures/manifest.json")
# Frozen fixtures pin the policy string they shipped with; the live
# ``BUDGET_POLICY_VERSION`` may advance without rewriting historical wire cases.
_CTL_290_BUDGET_POLICY_VERSION = "observation-budget-v2-provisional"
_FIXTURE_MEDIA_TYPE = "application/vnd.yoetz.fixture-case+json"
_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000001"
_RPC_ID = "rpc_00000000-0000-4000-8000-000000000002"
_REQUEST_ID = "req_00000000-0000-4000-8000-000000000003"
_COMMITMENT = "hmac-sha256:" + "1" * 64
_DIGEST = "sha256:" + "2" * 64


def _runtime_status_26() -> dict[str, Any]:
    return {
        "selected_mode": "detailed",
        "effective_mode": "focused",
        "selected_capacity": 2048,
        "effective_capacity": 2048,
        "selection_origin": "session",
        "selection_expires_at": "2026-09-10T01:00:00.000Z",
        "pressure_state": "rising",
        "pressure_transition_identity": _DIGEST,
        "content_allowed": True,
        "admission_allowed": True,
        "queue_count": 2,
        "queue_bytes": 1024,
        "state_bytes": 4096,
        "oldest_pending_age_ms": 250,
        "pending_attempts": 1,
        "pending_lifecycle_count": 0,
        "capture_backlog": {
            "capture_backlog_scope": "partial",
            "route_count": 1,
            "count": 1,
            "byte_count": 512,
            "oldest_receipt_time": "2026-09-10T00:00:00.000Z",
            "observed_at": "2026-09-10T00:00:01.000Z",
            "reservation_count": 0,
            "reserved_byte_count": 0,
            "reservation_unknown": False,
            "routes": {
                "tsk_00000000-0000-4000-8000-000000000004": {
                    "count": 1,
                    "byte_count": 512,
                    "oldest_receipt_time": "2026-09-10T00:00:00.000Z",
                    "observed_at": "2026-09-10T00:00:01.000Z",
                    "reservation_count": 0,
                    "reservation_unknown": False,
                }
            },
        },
        "protected_count_reserve": 512,
        "protected_bytes_reserve": 131072,
        "session_fair_share": 512,
        "session_fair_share_bytes": 524288,
        "accounting": {
            "observed_count": 4,
            "accounting_scope": "locally_ingested_since_selection_upgrade",
            "admitted_input_count": 3,
            "delivered_input_count": 2,
            "summarized_input_count": 1,
            "intentionally_omitted_input_count": 1,
            "check_selection": "reported_by_each_check",
            "summary_record_count": 1,
            "buffered_input_count": 1,
            "pending_attempt_count": 1,
            "buffered_successful_call_count": 1,
            "unrecoverable_input_count": 0,
            "loss_identity_commitment": None,
            "loss_ranges": [],
            "loss_identity_list_complete": False,
            "selection_epoch": 3,
        },
        "session_commitment": _COMMITMENT,
        "policy_version": "observation-budget-v1-provisional",
        "validation_status": "not_validated",
    }


def _frame(selection_runtime: dict[str, Any]) -> dict[str, Any]:
    return {
        "body": {
            "request_id": _REQUEST_ID,
            "schema_version": "1.0.0",
            "status": {
                "lifecycle": "active",
                "workspace_commitment": _COMMITMENT,
                "source_coverage": {
                    "claude_hook": True,
                    "codex_hook": True,
                    "codex_session_stream": False,
                    "cursor_hook": False,
                },
                "last_observation_receipt_time": "2026-09-10T00:00:01.000Z",
                "lag_events": 0,
                "gaps": [],
                "unsupported_events": [],
                "advice_frontier": None,
                "selection_runtime": selection_runtime,
            },
        },
        "method": "observation_status",
        "outcome": "ok",
        "protocol_version": "1.0",
        "rpc_id": _RPC_ID,
        "service_generation": "1",
        "service_instance_id": _INSTANCE_ID,
    }


def _fixture_document_26() -> dict[str, Any]:
    frame = _frame(_runtime_status_26())
    encoded = canonical_encode(frame)
    return {
        "controls": {
            "clock": "fixture_supplied",
            "external_io": "forbidden",
            "network": "forbidden",
            "randomness": "fixture_supplied",
        },
        "expected": {
            "canonical_byte_length": len(encoded),
            "canonical_hex": encoded.hex(),
            "canonical_sha256": canonical_digest(frame),
            "new_schema_version": "2.6.0",
            "old_schema_version": "2.5.0",
            "selection_runtime_present": True,
        },
        "fixture_id": _CTL_260.fixture_id,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {"frame": frame},
        "minimum_versions": {
            "control_schema": "2.6.0",
            "fixture_contract": "1.0.0",
            "protocol": "1.0",
        },
        "owns_requirements": ["ISSUE-687:selection-runtime-status", "ADR-029"],
        "purpose": (
            "Freeze the bounded structural selection-runtime projection on the additive 2.6 "
            "observation-status result wire while proving the frozen 2.5 wire rejects it."
        ),
    }


_CUSTOM_QUEUE_COUNT = 1024
_EXPIRES_AT_29 = "2026-09-24T01:00:00.000Z"


def _plain(value: JsonObject) -> dict[str, Any]:
    """Return the domain JSON value as plain dictionaries in canonical key order."""

    return cast(dict[str, Any], strict_json_parse(canonical_encode(value)))


def _runtime_status_29() -> dict[str, Any]:
    """Build the 2.9 custom-capacity projection through the real domain builders.

    The effective budget uses the same record shape the local observation store
    assembles for a session-scoped read, and the pressure fields come from the
    domain pressure evaluation over exactly the usage reported beside them.
    """

    capacity = ObservationCapacity(_CUSTOM_QUEUE_COUNT)
    limits = BudgetLimits.for_capacity(capacity)
    template = _runtime_status_26()
    capture = cast(dict[str, Any], template["capture_backlog"])
    usage = BudgetUsage(
        queue_count=600,
        queue_bytes=262_144,
        state_bytes=524_288,
        oldest_pending_age_ms=250,
        pending_attempts=1,
        capture_tickets=int(capture["count"]),
        capture_bytes=int(capture["byte_count"]),
        session_queue_count=128,
        session_queue_bytes=65_536,
    )
    evaluation = evaluate_pressure(usage, ObservationMode.DETAILED, None, 0, limits=limits)
    effective_budget = JsonObject(
        {
            "schema": EFFECTIVE_BUDGET_SCHEMA,
            # CTL-290 is frozen at the policy version current when 2.9 shipped.
            "budget_policy_version": _CTL_290_BUDGET_POLICY_VERSION,
            "validation_status": BUDGET_VALIDATION_STATUS,
            "scope": "session",
            "selected_queue_count": capacity.queue_count,
            "selected_capacity_label": capacity.label,
            "effective_queue_count": capacity.queue_count,
            "effective_capacity_label": capacity.label,
            "effective_reason": "selected",
            "limits": {
                "queue_count": limits.queue_count,
                "queue_bytes": limits.queue_bytes,
                "state_bytes": limits.state_bytes,
                "pending_attempts": limits.pending_attempts,
                "capture_tickets": limits.capture_tickets,
                "capture_bytes": limits.capture_bytes,
                "protected_count": limits.protected_count,
                "protected_bytes": limits.protected_bytes,
                "session_fair_share": limits.session_fair_share,
                "session_fair_share_bytes": limits.session_fair_share_bytes,
                "max_pending_age_ms": limits.max_pending_age_ms,
                "state_document_ceiling_bytes": STATE_DOCUMENT_CEILING_BYTES,
            },
            "limiting_dimension": evaluation.dimension.value,
            "utilization_bps": evaluation.utilization_bps,
            "no_cap": no_cap_support(),
        }
    )
    status = ObservationSelectionRuntimeStatus(
        selected_mode=ObservationMode.DETAILED,
        effective_mode=evaluation.effective_mode,
        selected_capacity=capacity,
        effective_capacity=capacity,
        selection_origin="session",
        selection_expires_at=Timestamp(_EXPIRES_AT_29),
        pressure_state=evaluation.state,
        pressure_transition_identity=evaluation.transition_identity,
        content_allowed=evaluation.content_allowed,
        admission_allowed=evaluation.admission_allowed,
        queue_count=usage.queue_count,
        queue_bytes=usage.queue_bytes,
        state_bytes=usage.state_bytes,
        oldest_pending_age_ms=usage.oldest_pending_age_ms,
        pending_attempts=usage.pending_attempts,
        pending_lifecycle_count=0,
        capture_backlog=JsonObject(capture),
        protected_count_reserve=limits.protected_count,
        protected_bytes_reserve=limits.protected_bytes,
        session_fair_share=limits.session_fair_share,
        session_fair_share_bytes=limits.session_fair_share_bytes,
        accounting=JsonObject(cast(dict[str, Any], template["accounting"])),
        session_commitment=_COMMITMENT,
        effective_budget=effective_budget,
        policy_version=_CTL_290_BUDGET_POLICY_VERSION,
    )
    return _plain(observation_selection_runtime_status_to_json(status))


def _fixture_document_29() -> dict[str, Any]:
    frame = _frame(_runtime_status_29())
    encoded = canonical_encode(frame)
    return {
        "controls": {
            "clock": "fixture_supplied",
            "external_io": "forbidden",
            "network": "forbidden",
            "randomness": "fixture_supplied",
        },
        "expected": {
            "canonical_byte_length": len(encoded),
            "canonical_hex": encoded.hex(),
            "canonical_sha256": canonical_digest(frame),
            "new_schema_version": "2.9.0",
            "old_schema_version": "2.8.0",
            "selection_runtime_present": True,
        },
        "fixture_id": _CTL_290.fixture_id,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {"frame": frame},
        "minimum_versions": {
            "control_schema": "2.9.0",
            "fixture_contract": "1.0.0",
            "protocol": "1.0",
        },
        "owns_requirements": ["ISSUE-828:configurable-capacity", "ADR-029"],
        "purpose": (
            "Freeze a custom-capacity selection with its capacity labels and effective budget "
            "on the 2.9 observation-status result wire while proving the 2.8 wire rejects it."
        ),
    }


@dataclass(frozen=True, slots=True)
class _Case:
    fixture_id: str
    manifest_path: str
    build: Callable[[], dict[str, Any]]

    @property
    def relative(self) -> Path:
        return Path("fixtures") / self.manifest_path


_CTL_260 = _Case(
    "CTL-260", "canonical/control-observation-status-2.6.case.json", _fixture_document_26
)
_CTL_290 = _Case(
    "CTL-290", "canonical/control-observation-status-2.9.case.json", _fixture_document_29
)
_CASES = (_CTL_260, _CTL_290)


def _upsert_member(
    previous: list[dict[str, Any]],
    case: _Case,
    fixture_bytes: bytes,
    *,
    allow_owned_update: bool,
) -> list[dict[str, Any]]:
    member = {
        "byte_length": len(fixture_bytes),
        "fixture_id": case.fixture_id,
        "media_type": _FIXTURE_MEDIA_TYPE,
        "path": case.manifest_path,
        "sha256": hashlib.sha256(fixture_bytes).hexdigest(),
    }
    existing = [item for item in previous if item["path"] == case.manifest_path]
    if len(existing) > 1:
        raise ValueError("fixture_manifest_duplicate_path")
    if existing and existing[0] != member and not allow_owned_update:
        raise ValueError("fixture_manifest_owned_member_changed")
    if any(
        item["fixture_id"] == case.fixture_id and item["path"] != case.manifest_path
        for item in previous
    ):
        raise ValueError("fixture_manifest_id_already_owned")
    updated_members = (
        [member if item["path"] == case.manifest_path else item for item in previous]
        if existing
        else sorted([*previous, member], key=lambda item: str(item["path"]).encode("ascii"))
    )
    if [item for item in updated_members if item["path"] != case.manifest_path] != [
        item for item in previous if item["path"] != case.manifest_path
    ]:
        raise ValueError("fixture_manifest_existing_member_changed")
    return updated_members


def _manifest_bytes(
    path: Path,
    fixtures: tuple[tuple[_Case, bytes], ...],
    *,
    allow_owned_update: bool,
) -> bytes:
    parsed = strict_json_parse(path.read_bytes())
    if not isinstance(parsed, dict) or set(parsed) != {
        "manifest_schema",
        "manifest_version",
        "members",
    }:
        raise ValueError("fixture_manifest_shape_invalid")
    members = parsed["members"]
    if not isinstance(members, list):
        raise ValueError("fixture_manifest_members_invalid")
    previous = [cast(dict[str, Any], item) for item in members]
    if previous != sorted(previous, key=lambda item: str(item["path"]).encode("ascii")):
        raise ValueError("fixture_manifest_order_invalid")
    for case, fixture_bytes in fixtures:
        previous = _upsert_member(
            previous, case, fixture_bytes, allow_owned_update=allow_owned_update
        )
    updated = cast(dict[str, Any], dict(parsed))
    updated["members"] = previous
    return json.dumps(updated).encode("utf-8") + b"\n"


def _expected(
    root: Path, *, allow_owned_update: bool
) -> tuple[tuple[tuple[_Case, bytes], ...], bytes]:
    fixtures = tuple((case, canonical_encode(case.build())) for case in _CASES)
    manifest_bytes = _manifest_bytes(
        root / _MANIFEST_RELATIVE,
        fixtures,
        allow_owned_update=allow_owned_update,
    )
    return fixtures, manifest_bytes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.check == args.write:
        parser.error("choose exactly one of --check or --write")
    root = args.repo_root.resolve()
    fixtures, manifest_bytes = _expected(root, allow_owned_update=args.write)
    manifest_path = root / _MANIFEST_RELATIVE
    if args.check:
        for case, fixture_bytes in fixtures:
            fixture_path = root / case.relative
            if not fixture_path.is_file() or fixture_path.read_bytes() != fixture_bytes:
                print(f"observation status fixture {case.fixture_id} stale")
                return 1
        if not manifest_path.is_file() or manifest_path.read_bytes() != manifest_bytes:
            print("fixture manifest stale")
            return 1
        print("observation status fixtures and manifest are current")
        return 0
    for case, fixture_bytes in fixtures:
        fixture_path = root / case.relative
        fixture_path.parent.mkdir(parents=True, exist_ok=True)
        fixture_path.write_bytes(fixture_bytes)
    manifest_path.write_bytes(manifest_bytes)
    ids = ", ".join(case.fixture_id for case, _ in fixtures)
    print(f"wrote {ids} observation status fixtures and manifest members")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
