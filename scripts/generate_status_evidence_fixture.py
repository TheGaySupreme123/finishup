"""Own the CAN-013 evidence read-back golden vector and its manifest entry (issue #914).

The vector freezes one agent-context ``status view=evidence`` exchange at status request 1.2.0 and
status result 1.4.0, both unreleased on the 0.3 line and extended in place: a
``filter.author=mine`` request, the page it returns (the requester's own rows readable), an
unfiltered page mixing the requester's rows with a host-observed capture whose prose stays
omitted, and the text and MCP renderings that must agree with both.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Final, cast

from finishup.cli.render import render_human_status
from finishup.mcp.summaries import render_safe_compact_summary
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import StatusRequestModel, StatusResultModel, StatusSuccessModel

_PATH: Final = "canonical/status-evidence-author-1.4.0.case.json"
_FIXTURE_ID: Final = "CAN-013"
_HEAD: Final = {
    "head_digest": "sha256:4f1d8a02c3a2b8a4a9e1f7c1d5a6b3e2c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5",
    "sequence": "21",
}
_OMITTED: Final = {
    "category": "evidence_excerpt",
    "omitted": True,
    "reason": "local_disclosure_not_authorized",
}


def _id(prefix: str, seed: int) -> str:
    return f"{prefix}_00000000-0000-4000-8000-{seed:012d}"


def _own_rows() -> list[dict[str, JsonValue]]:
    return [
        {
            "available": True,
            "captured_object_id": None,
            "content_digest": "sha256:" + "a1" * 32,
            "description": (
                "Commit de58a86 source diff (22,099 bytes). Bounded changed-code excerpt: "
                "_date_property emits Z for UTC and TZID for named local time."
            ),
            "evidence_id": _id("evd", 914001),
            "freshness": "current",
            "publication_channel": "cooperative_mcp",
            "reference": "git show de58a86",
            "strength": "content_digest",
            "subject_state": None,
        },
        {
            "available": True,
            "captured_object_id": None,
            "content_digest": "sha256:" + "b2" * 32,
            "description": "pytest tests -q: 2036 passed, 47 skipped, 16 xfailed in 1.94s.",
            "evidence_id": _id("evd", 914002),
            "freshness": "current",
            "publication_channel": "cooperative_mcp",
            "reference": "pytest tests -q",
            "strength": "content_digest",
            "subject_state": None,
        },
    ]


def _captured_row() -> dict[str, JsonValue]:
    return {
        "available": True,
        "captured_object_id": _id("obj", 914003),
        "content_digest": "sha256:" + "c3" * 32,
        "description": dict(_OMITTED),
        "evidence_id": _id("evd", 914000),
        "freshness": "partial",
        "publication_channel": "hook_observed",
        "reference": dict(_OMITTED),
        "strength": "immutable_snapshot",
        "subject_state": None,
    }


def _request(filter_value: JsonValue) -> dict[str, JsonValue]:
    request: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _id("req", 914010),
        "session_id": _id("ses", 914011),
        "writer_id": _id("wri", 914012),
        "view": "evidence",
        "limit": "100",
        "actor": {"actor_id": "codex", "actor_type": "logical_agent"},
        "client": {"kind": "cooperative_agent", "version": "1.0", "integration": "cooperative_mcp"},
    }
    if filter_value is not None:
        request["filter"] = filter_value
    return request


def _result(items: list[dict[str, JsonValue]], *, omitted: list[str]) -> dict[str, JsonValue]:
    categories: list[JsonValue] = ["evidence_excerpt"]
    return {
        "closure_readiness": {
            "blocking_conditions": ["obligations_open"],
            "declared_obligation_count": "1",
            "no_obligations_reason": None,
            "open_obligation_count": "1",
            "receipt_blocking_finding_count": "0",
            "unanswered_finding_count": "0",
        },
        "coverage": {
            "artifact_observation": "content_captured",
            "authorship_assurance": "self_asserted",
            "check_types": ["deterministic"],
            "evidence_immutability": "content_digest",
            "known_gaps": [],
            "ledger_freshness": "current",
            "publication_channels": ["cooperative_mcp", "hook_observed"],
        },
        "gaps": [],
        "head_frontier": dict(_HEAD),
        "import_status": {
            "pending_count": "0",
            "phase": None,
            "report_evidence_id": None,
            "source_identity_digest": None,
            "terminal_count": "0",
        },
        "ok": True,
        "page": {"items": cast(JsonValue, items), "next_cursor": None},
        "privacy_projection": {
            "blocked_categories": categories if omitted else [],
            "included_categories": categories,
            "local_disclosure_receipt_id": _id("egr", 914020),
            "omitted_pointers": cast(JsonValue, omitted),
            "policy_digest": "sha256:" + "77" * 32,
            "policy_id": _id("pvy", 914021),
            "policy_version": "1",
            "projection_commitment": "hmac-sha256:" + "2e" * 32,
            "sink": "agent_context",
        },
        "projection_lag": "0",
        "projection_version": "0.1.0",
        "protocol_version": "0.1",
        "rebuild_state": "current",
        "request_id": _id("req", 914010),
        "requested_frontier": dict(_HEAD),
        "result_frontier": dict(_HEAD),
        "schema_version": "1.0.0",
        "session_id": _id("ses", 914011),
        "subject_frontier": dict(_HEAD),
        "task_id": _id("tsk", 914013),
        "view": "evidence",
        "writer_id": _id("wri", 914012),
    }


def build_fixture() -> dict[str, JsonValue]:
    """Build the vector; every expected rendering comes from the shipped renderers."""

    own = _own_rows()
    requests = {
        "mine": _request({"author": "mine"}),
        "unfiltered": _request(None),
    }
    results = {
        "mine": _result(own, omitted=[]),
        "unfiltered": _result(
            [_captured_row(), *own],
            omitted=["/page/items/0/description", "/page/items/0/reference"],
        ),
    }
    expected_summaries: dict[str, JsonValue] = {}
    expected_lines: dict[str, JsonValue] = {}
    for case, result in results.items():
        StatusRequestModel.model_validate(requests[case])
        success = StatusResultModel.model_validate(result).root
        assert isinstance(success, StatusSuccessModel)
        expected_summaries[case] = render_safe_compact_summary(cast(JsonValue, result))
        expected_lines[case] = cast(JsonValue, render_human_status(success).splitlines())
    return {
        "fixture_id": _FIXTURE_ID,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "owns_requirements": [
            "INTERFACES:DisclosureProvenance",
            "ISSUE-914:evidence-author-filter",
        ],
        "minimum_versions": {
            "engine": "0.1.0",
            "protocol": "0.1",
            "status_request_schema": "1.2.0",
            "status_result_schema": "1.4.0",
        },
        "purpose": (
            "Freeze the evidence author filter, the per-row publication channel, the requester's "
            "own readable rows beside an omitted host capture, and the text and MCP renderings."
        ),
        "input": {"requests": requests, "results": results},
        "expected": {
            "human_lines": expected_lines,
            "mcp_summaries": expected_summaries,
            "own_evidence_ids": [cast(str, row["evidence_id"]) for row in own],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    fixture = canonical_encode(cast(JsonValue, build_fixture()))
    manifest_path = root / "fixtures/manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    member = {
        "byte_length": len(fixture),
        "fixture_id": _FIXTURE_ID,
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "path": _PATH,
        "sha256": hashlib.sha256(fixture).hexdigest(),
    }
    others = [item for item in manifest["members"] if item["path"] != _PATH]
    if any(item["fixture_id"] == _FIXTURE_ID for item in others):
        raise ValueError("fixture_id_already_owned")
    manifest["members"] = sorted([*others, member], key=lambda item: str(item["path"]).encode())
    expected_manifest = json.dumps(manifest).encode() + b"\n"
    fixture_path = root / "fixtures" / _PATH
    if args.write:
        fixture_path.write_bytes(fixture)
        manifest_path.write_bytes(expected_manifest)
        return 0
    return int(
        not fixture_path.exists()
        or fixture_path.read_bytes() != fixture
        or manifest_path.read_bytes() != expected_manifest
    )


if __name__ == "__main__":
    raise SystemExit(main())
