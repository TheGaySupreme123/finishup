"""Generate the canonical W6 review-result-delivery vectors (issue #1107).

``AGN-001`` freezes ``overall_next`` and ``missing_for_assessment`` pairs and the bounded
``agent_next`` lead the service composes from them (check-result 1.5.0), so a change to the closed
sentences, their order or their shrink rule is a reviewed fixture change rather than a silent
drift. ``AGN-002`` freezes one status-result 1.4.0 operation page of a finished
``insufficient_packet`` check with its ``check_outcome`` (verdict, lead, next action, missing
items, frontier) and the CLI and MCP renderings of that page.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, cast

from finishup.cli.render import render_human_status
from finishup.domain.review_input_render import MAX_AGENT_NEXT_BYTES, render_agent_next
from finishup.domain.values import freeze_json
from finishup.mcp.summaries import render_safe_compact_summary
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.models import StatusResultModel, StatusSuccessModel, public_model_to_wire
from finishup.protocol.schemas import validate_schema_instance

_PATH: Final = "canonical/check-agent-next-1.5.0.case.json"
_FIXTURE_ID: Final = "AGN-001"
_STATUS_PATH: Final = "canonical/status-check-outcome-1.4.0.case.json"
_STATUS_FIXTURE_ID: Final = "AGN-002"
# A reviewed status-result 1.4.0 operation page whose envelope the outcome page reuses.
_STATUS_BASE: Final = "canonical/status-check-admission-1.4.0.case.json"


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


def status_document(root: Path) -> dict[str, JsonValue]:
    """The finished-check operation page (``AGN-002``), on a reviewed status envelope."""

    base = json.loads((root / "fixtures" / _STATUS_BASE).read_bytes())
    result = cast(dict[str, JsonValue], copy.deepcopy(base["input"]["results"]["acquiring"]))
    _vector_id, overall_next, missing, limitation_requests = _cases()[0]
    agent_next = render_agent_next(overall_next, missing, limitation_requests=limitation_requests)
    page = cast(dict[str, JsonValue], result["page"])
    page.pop("admission")
    page.update(
        found=True,
        state="complete",
        operation_kind="check",
        check_outcome={
            "verdict": "insufficient_coverage",
            "agent_next": agent_next,
            "overall_next": overall_next,
            "missing_for_assessment": missing,
            "semantic_status": "succeeded",
            "semantic_reason": "semantic_completed",
            "semantic_conclusion": "insufficient_packet",
            "result_frontier": result["result_frontier"],
        },
    )
    validate_schema_instance("status-result", "1.4.0", freeze_json(result))
    model = StatusResultModel.model_validate(result)
    if public_model_to_wire(model) != result or not isinstance(model.root, StatusSuccessModel):
        raise ValueError("status_check_outcome_fixture_invalid")
    lines = render_human_status(model.root).splitlines()
    # The outcome block: from its first line up to the page's gap line.
    start = next(index for index, line in enumerate(lines) if line.startswith("Check outcome:"))
    end = next(
        (index for index, line in enumerate(lines) if index > start and line.startswith("Gaps:")),
        len(lines),
    )
    return {
        "fixture_id": _STATUS_FIXTURE_ID,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "minimum_versions": {
            "engine": "0.1.0",
            "protocol": "0.1",
            "status_result_schema": "1.4.0",
        },
        "owns_requirements": ["ISSUE-1107:status-check-outcome"],
        "purpose": (
            "Freeze the status view=operation page of a finished insufficient_packet check: its "
            "check_outcome carries the same verdict, agent_next, overall_next, missing items and "
            "result frontier a same-id replay returns, and the CLI and MCP renderings of it."
        ),
        "controls": {
            "clock": "fixture_supplied",
            "external_io": "forbidden",
            "network": "forbidden",
            "randomness": "forbidden",
        },
        "input": {"result": result},
        "expected": {
            "text_lines": cast(list[JsonValue], lines[start:end]),
            "mcp_summary": render_safe_compact_summary(cast(JsonValue, result)),
            "canonical_hex": canonical_encode(result).hex(),
            "digest": canonical_digest(result),
        },
    }


def _member(fixture_id: str, path: str, data: bytes) -> dict[str, Any]:
    return {
        "fixture_id": fixture_id,
        "path": path,
        "byte_length": len(data),
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    builders: tuple[tuple[str, str, Callable[[], dict[str, JsonValue]]], ...] = (
        (_FIXTURE_ID, _PATH, document),
        (_STATUS_FIXTURE_ID, _STATUS_PATH, lambda: status_document(root)),
    )
    manifest_path = root / "fixtures/manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    paths = {path for _id, path, _build in builders}
    unrelated = [item for item in manifest["members"] if item["path"] not in paths]
    ids = {fixture_id for fixture_id, _path, _build in builders}
    if any(item["fixture_id"] in ids for item in unrelated):
        raise ValueError("fixture_identity_conflict")
    outputs = [
        (path, data, _member(fixture_id, path, data))
        for fixture_id, path, build in builders
        for data in (canonical_encode(cast(JsonValue, build())),)
    ]
    if args.check:
        for path, data, member in outputs:
            target = root / "fixtures" / path
            if (
                not target.is_file()
                or target.read_bytes() != data
                or [item for item in manifest["members"] if item["path"] == path] != [member]
            ):
                raise ValueError("review_result_delivery_fixture_stale")
    else:
        manifest["members"] = sorted(
            [*unrelated, *(member for _path, _data, member in outputs)],
            key=lambda item: item["path"],
        )
        for path, data, _member_row in outputs:
            (root / "fixtures" / path).write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("review result delivery fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
