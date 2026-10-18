"""Generate the canonical ``agent_next`` vectors of check-result 1.5.0 (issue #1107, W6).

Each vector freezes one ``overall_next`` and ``missing_for_assessment`` pair and the bounded
``agent_next`` lead the service composes from them, so a change to the closed sentences, their
order or their shrink rule is a reviewed fixture change rather than a silent drift.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Final, cast

from finishup.domain.review_input_render import MAX_AGENT_NEXT_BYTES, render_agent_next
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_PATH: Final = "canonical/check-agent-next-1.5.0.case.json"
_FIXTURE_ID: Final = "AGN-001"


def _ref(prefix: str, number: int) -> str:
    return f"{prefix}_10000000-0000-4000-8000-{number:012x}"


def _item(kind: str, availability: str, *refs: str) -> dict[str, JsonValue]:
    return {"availability": availability, "kind": kind, "target_refs": list(refs)}


def _next(
    action: str, status: str, *refs: str, predicted: str | None = None
) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {"action": action, "status": status, "target_refs": list(refs)}
    if predicted is not None:
        value["predicted_conclusion"] = predicted
    return value


def _cases() -> tuple[tuple[str, dict[str, JsonValue], list[JsonValue], bool], ...]:
    run = _ref("res", 2)
    worst_kinds = (
        "verification_output",
        "current_diff_for_path",
        "command_identity",
        "other",
        "plan_or_claim_text",
        "task_statement",
        "prior_finding_context",
        "verification_output",
    )
    worst: list[JsonValue] = [
        _item(kind, "agent_suppliable", *(_ref("res", 16 * index + ref) for ref in range(4)))
        for index, kind in enumerate(worst_kinds)
    ]
    worst_targets = [
        ref
        for item in worst
        for ref in cast(list[str], cast(dict[str, JsonValue], item)["target_refs"])
    ]
    return (
        (
            "supply_one_item_with_a_finishup_limit",
            _next(
                "supply_missing_input", "action_required", run, predicted="insufficient_coverage"
            ),
            [
                _item("verification_output", "agent_suppliable", run),
                _item("other", "yoetz_limit_packet_room", _ref("evd", 3)),
            ],
            False,
        ),
        (
            "supply_worst_case_shrinks_to_the_bound",
            _next("supply_missing_input", "action_required", *worst_targets[:64]),
            worst,
            False,
        ),
        (
            "work_open_findings_with_a_limitation_request",
            _next("work_open_findings", "action_required", _ref("fnd", 7), _ref("fnd", 8)),
            [],
            True,
        ),
        (
            "receipt_with_limitations",
            _next("request_receipt", "ready_with_limitations", predicted="insufficient_coverage"),
            [],
            False,
        ),
    )


def _vectors() -> tuple[dict[str, JsonValue], ...]:
    vectors: list[dict[str, JsonValue]] = []
    for vector_id, overall_next, missing, limitation_requests in _cases():
        agent_next = render_agent_next(
            overall_next, missing, limitation_requests=limitation_requests
        )
        if not agent_next or len(agent_next.encode("ascii")) > MAX_AGENT_NEXT_BYTES:
            raise ValueError("agent_next_fixture_invalid")
        payload: dict[str, JsonValue] = {
            "agent_next": agent_next,
            "limitation_requests": limitation_requests,
            "missing_for_assessment": missing,
            "overall_next": overall_next,
        }
        vectors.append(
            {
                "vector_id": vector_id,
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
            "check_result_schema": "1.5.0",
            "engine": "0.1.0",
            "protocol": "0.1",
        },
        "owns_requirements": ["ISSUE-1107:check-agent-next"],
        "purpose": (
            "Freeze the bounded agent_next lead of a check result: one agent-suppliable item "
            "beside a FinishUP limit, the worst case shrunk to the 2,048-byte bound, open "
            "findings with a limitation request, and a receipt with limitations."
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
            raise ValueError("review_result_delivery_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("review result delivery fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
