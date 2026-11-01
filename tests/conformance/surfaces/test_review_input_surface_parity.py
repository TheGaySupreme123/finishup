"""Check, MCP, and terminal-facing projections share review-input metadata wording."""

from __future__ import annotations

import pytest

from finishup.cli.render import render_human_check
from finishup.mcp.server import _result_text  # pyright: ignore[reportPrivateUsage]
from finishup.mcp.summaries import MAX_SUMMARY_BYTES, render_safe_compact_summary
from finishup.protocol.models import (
    CheckMissingItemModel,
    CheckSuccessModel,
    CoverageModel,
    ReviewInputManifestModel,
)

_DIGEST = "sha256:" + "b" * 64


def _section(status: str, *, digest: str | None = _DIGEST) -> dict[str, object]:
    return {
        "status": status,
        "source_refs": ["evt_00000000-0000-4000-8000-000000000001"],
        "item_ids": ["item-1"],
        "omitted_refs": [],
        "omission_reasons": [],
        "revision": 4,
        "content_digest": digest,
        "content_bytes": 96,
    }


def _manifest() -> dict[str, object]:
    return {
        "schema": "yoetz.review-input-manifest/1",
        "specification": _section("withheld", digest=None),
        "current_diff": _section("complete"),
        "caller_evidence": _section("partial"),
        "latest_verification": _section("missing", digest=None),
        "prior_finding_context": _section("not_selected", digest=None),
        "phase": "provider_bound",
        "missing_inputs": [],
        "selected_item_count": 2,
        "selected_excerpt_bytes": 192,
        "omitted_item_count": 1,
    }


@pytest.mark.parametrize(
    ("kind", "refs"),
    (
        ("verification_output", ("res_00000000-0000-4000-8000-000000000002",)),
        ("other", ()),
    ),
)
def test_check_cli_and_mcp_share_bounded_manifest_and_missing_projection(
    kind: str, refs: tuple[str, ...]
) -> None:
    manifest = _manifest()
    result = CheckSuccessModel.model_construct(
        verdict="insufficient_coverage",
        semantic_status="succeeded",
        semantic_reason="semantic_completed",
        semantic_provenance=None,
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(
            known_gaps=("semantic_packet_insufficient", "semantic_review_context_withheld")
        ),
        children=None,
        advisory_notes=(),
        missing_for_assessment=(
            CheckMissingItemModel.model_validate(
                {
                    "kind": kind,
                    "target_refs": refs,
                    "availability": "agent_suppliable",
                }
            ),
        ),
        finding_checklist=None,
        review_input_manifest=ReviewInputManifestModel.model_validate(manifest),
    )

    cli = render_human_check(result)
    assert "Review input manifest: provider_bound" in cli
    assert "- specification: withheld" in cli
    assert "Missing for assessment" in cli
    assert "agent_suppliable" in cli

    wire: dict[str, object] = {
        "ok": True,
        "verdict": "insufficient_coverage",
        "findings": [],
        "suppressed_count": "0",
        "semantic_status": "succeeded",
        "semantic_reason": "semantic_completed",
        "review_input_manifest": manifest,
        "missing_for_assessment": [
            {
                "kind": kind,
                "target_refs": list(refs),
                "availability": "agent_suppliable",
            }
        ],
        "result_frontier": {"sequence": "7", "head_digest": _DIGEST},
    }
    mcp = _result_text(wire)
    assert "Review input manifest: provider_bound" in mcp
    assert "specification: withheld" in mcp
    assert "overall next: supply_missing_input" in mcp
    for ref in refs:
        assert ref in mcp
    if not refs:
        remedy = "Publish new evidence answering the request; if a target is named"
        assert remedy in cli and remedy in mcp
    assert len(render_safe_compact_summary(wire).encode("ascii")) <= MAX_SUMMARY_BYTES
