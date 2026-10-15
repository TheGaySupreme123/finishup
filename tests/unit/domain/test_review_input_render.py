"""Shared public projections for the bounded review-input manifest."""

from __future__ import annotations

from finishup.domain.review_input_render import (
    FINISHUP_LIMIT_MISSING_TEXT,
    MISSING_SUPPLY_SENTENCE,
    has_agent_suppliable_missing,
    render_missing_for_assessment_lines,
    render_missing_for_assessment_next,
    render_review_input_manifest_compact,
    render_review_input_manifest_compat_line,
    render_review_input_manifest_coverage_note,
    render_review_input_manifest_lines,
)

_DIGEST = "sha256:" + "a" * 64


def _section(status: str, *, digest: str | None = _DIGEST) -> dict[str, object]:
    return {
        "status": status,
        "source_refs": ["evt_00000000-0000-4000-8000-000000000001"],
        "item_ids": ["item-1"],
        "omitted_refs": [],
        "omission_reasons": [],
        "revision": 7,
        "content_digest": digest,
        "content_bytes": 123,
    }


def _manifest(*, specification_status: str = "complete") -> dict[str, object]:
    return {
        "schema": "yoetz.review-input-manifest/1",
        "specification": _section(specification_status),
        "current_diff": _section("partial"),
        "caller_evidence": _section("missing", digest=None),
        "latest_verification": _section("complete"),
        "prior_finding_context": _section("not_selected", digest=None),
        "phase": "provider_bound",
        "missing_inputs": [
            {
                "kind": "verification_output",
                "status": "pending",
                "target_refs": ["res_00000000-0000-4000-8000-000000000002"],
                "supplied_refs": [],
            }
        ],
        "selected_item_count": 3,
        "selected_excerpt_bytes": 246,
        "omitted_item_count": 2,
    }


def test_manifest_renderer_keeps_distinct_statement_state_and_digests() -> None:
    lines = render_review_input_manifest_lines(_manifest(specification_status="title_only"))

    assert lines[0] == (
        "Review input manifest: provider_bound; selected items 3; "
        "selected excerpt bytes 246; omitted items 2."
    )
    assert any(line.startswith("- specification: title_only;") for line in lines)
    assert any(_DIGEST in line for line in lines)
    assert any("Manifest missing inputs: verification_output=pending" in line for line in lines)
    assert "Provider-bound review input: specification complete" in (
        render_review_input_manifest_compat_line(_manifest())
    )
    assert "provider_bound" in render_review_input_manifest_compact(_manifest())


def test_manifest_renderer_reports_the_true_omission_total_beside_the_listed_cap() -> None:
    # Issue #976 (tb4n1 D11): the listed count saturates at 64; the total does not.
    manifest = _manifest()
    manifest["omitted_item_count"] = 64
    manifest["omitted_item_total"] = 173

    lines = render_review_input_manifest_lines(manifest)

    assert lines[0].endswith("; omitted items 173 (64 listed).")
    assert "omitted items 173 (64 listed)" in render_review_input_manifest_compact(manifest)
    manifest["omitted_item_total"] = 64
    assert render_review_input_manifest_lines(manifest)[0].endswith("; omitted items 64.")
    # An older manifest without the total keeps its listed count; a malformed total is ignored.
    manifest["omitted_item_total"] = "many"
    assert render_review_input_manifest_lines(manifest)[0].endswith("; omitted items 64.")


def test_manifest_renderer_rejects_untrusted_or_incomplete_shapes() -> None:
    assert render_review_input_manifest_lines({"schema": "other"}) == ()
    malformed = _manifest()
    malformed["selected_item_count"] = "3"
    assert render_review_input_manifest_lines(malformed) == ()


def test_receipt_note_lists_missing_availability_without_content() -> None:
    note = render_review_input_manifest_coverage_note(
        _manifest(),
        [
            {
                "kind": "task_statement",
                "target_refs": ["clm_00000000-0000-4000-8000-000000000003"],
                "availability": "agent_suppliable",
            }
        ],
    )

    assert note is not None
    assert "Review input coverage (metadata only):" in note
    assert "specification: complete" in note
    assert "task_statement (1 target refs): agent_suppliable" in note
    assert len(note.encode("utf-8")) <= 4096


def test_missing_renderer_preserves_refs_for_cli_and_mcp_surfaces() -> None:
    lines = render_missing_for_assessment_lines(
        [
            {
                "kind": "current_diff_for_path",
                "target_refs": ["evd_00000000-0000-4000-8000-000000000004"],
                "availability": "structurally_unavailable_on_this_host",
            }
        ]
    )

    assert lines == (
        "Missing for assessment (the reviewer could not assess the packet):",
        "- current_diff_for_path (evd_00000000-0000-4000-8000-000000000004): "
        "structurally_unavailable_on_this_host",
    )


def test_missing_renderer_prioritizes_agent_suppliable_input_over_a_receipt() -> None:
    items = [
        {
            "kind": "verification_output",
            "target_refs": ["res_00000000-0000-4000-8000-000000000002"],
            "availability": "agent_suppliable",
        }
    ]

    assert has_agent_suppliable_missing(items)
    assert render_missing_for_assessment_next(items) == "Overall next: " + MISSING_SUPPLY_SENTENCE
    lines = render_missing_for_assessment_lines(items)
    assert lines[-1] == render_missing_for_assessment_next(items)
    assert "result_recorded of that target whose summary is the command output" in lines[1]


def test_finishup_limit_items_are_named_as_finishup_limits_never_agent_work() -> None:
    """tb4n1 D1/F2 (#983): an unshowable item tells the agent to self-verify, never to reshape."""

    items = [
        {
            "kind": "other",
            "target_refs": ["evd_00000000-0000-4000-8000-000000000002"],
            "availability": "yoetz_limit_unsupported_data_type",
        }
    ]
    assert not has_agent_suppliable_missing(items)
    assert render_missing_for_assessment_next(items) == ""
    lines = render_missing_for_assessment_lines(items)
    assert (
        "- other (evd_00000000-0000-4000-8000-000000000002): yoetz_limit_unsupported_data_type"
        in lines
    )
    assert lines[-1] == FINISHUP_LIMIT_MISSING_TEXT
    assert "never a blocker" in FINISHUP_LIMIT_MISSING_TEXT
    assert "git-add" in FINISHUP_LIMIT_MISSING_TEXT


def test_recorded_manifest_accepts_the_omission_total_and_refuses_a_smaller_one() -> None:
    import pytest

    from finishup.domain.events import (
        _review_input_manifest_from_json,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.protocol.errors import ProtocolValueError

    manifest = _manifest()
    manifest["omitted_item_count"] = 64
    manifest["omitted_item_total"] = 173
    frozen = _review_input_manifest_from_json(manifest)  # pyright: ignore[reportArgumentType]
    assert frozen is not None and frozen["omitted_item_total"] == 173
    del manifest["omitted_item_total"]
    assert _review_input_manifest_from_json(manifest) is not None  # pyright: ignore[reportArgumentType]
    for invalid in (63, "173", None):
        manifest["omitted_item_total"] = invalid
        with pytest.raises(ProtocolValueError):
            _review_input_manifest_from_json(manifest)  # pyright: ignore[reportArgumentType]
