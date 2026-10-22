from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, is_dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.domain.findings import (
    CheckVerdict,
    CostFields,
    SamplingParams,
    SemanticDispatchKind,
    SemanticFailureClass,
    SemanticProvenance,
    TokenUsage,
)
from finishup.domain.receipts import (
    SEMANTIC_REDACTED_VALUES_AGENT_LINE,
    ReceiptConclusion,
    ReceiptDocument,
    ReceiptRedactionCategory,
    ReceiptRedactionReason,
    ReceiptSectionKey,
    receipt_document_from_json,
    receipt_document_to_json,
    receipt_weakest_coverage,
    render_receipt_compact,
    render_receipt_human,
    unresolved_findings_for_render,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import SemanticReason, SemanticStatus

_RECEIPT_FIXTURES = Path(__file__).parents[3] / "fixtures" / "receipts"


def _fixture_variants() -> tuple[tuple[str, str, dict[str, Any], str, str], ...]:
    result: list[tuple[str, str, dict[str, Any], str, str]] = []
    for path in sorted(_RECEIPT_FIXTURES.glob("*.case.json")):
        case = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
        variants = cast(dict[str, dict[str, Any]], case["expected"]["variants"])
        for name, expected in sorted(variants.items()):
            if "receipt_document" not in expected:
                continue
            result.append(
                (
                    path.name,
                    name,
                    cast(dict[str, Any], expected["receipt_document"]),
                    cast(str, expected["compact_markdown"]),
                    cast(str, expected["canonical_receipt_digest"]),
                )
            )
    return tuple(result)


_VARIANTS = _fixture_variants()


def _variant(file_name: str, variant_name: str) -> dict[str, Any]:
    for candidate_file, candidate_name, document, _, _ in _VARIANTS:
        if candidate_file == file_name and candidate_name == variant_name:
            return deepcopy(document)
    raise AssertionError(f"unknown fixture variant: {file_name}/{variant_name}")


def _rendered_with_current_product_name(expected: str) -> str:
    """The fixtures record pre-rename receipts and their pre-rename rendering (ADR-048).

    The stored receipt document is unchanged and still loads; only the product name the renderer
    prints is the current one.
    """

    return expected.replace("Yoetz receipt at frontier ", "FinishUP receipt at frontier ", 1)


def test_receipt_package_name_admits_the_current_and_the_legacy_distribution() -> None:
    """Receipts issued before the rename name ``yoetz``; new ones name ``finishup`` (ADR-048)."""

    legacy = _variant("deterministic-current.case.json", "current_complete")
    assert legacy["versions"]["package_name"] == "yoetz"
    current = deepcopy(legacy)
    current["versions"]["package_name"] = "finishup"
    for wire in (legacy, current):
        document = receipt_document_from_json(wire)
        assert receipt_document_to_json(document) == wire
        assert render_receipt_compact(document).startswith("FinishUP receipt at frontier 12:")
    other = deepcopy(legacy)
    other["versions"]["package_name"] = "other"
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(other)
    _assert_reason(exc_info, "invalid_receipt_version_slice")


def _assert_reason(exc_info: pytest.ExceptionInfo[ProtocolValueError], reason: str) -> None:
    assert exc_info.value.reason_code == reason
    assert exc_info.value.args == (reason,)


@pytest.mark.parametrize(
    ("file_name", "variant_name", "wire", "_compact", "expected_digest"),
    _VARIANTS,
    ids=[f"{file_name}:{variant_name}" for file_name, variant_name, *_ in _VARIANTS],
)
def test_receipt_document_exact_codec_and_digest(
    file_name: str,
    variant_name: str,
    wire: dict[str, Any],
    _compact: str,
    expected_digest: str,
) -> None:
    del file_name, variant_name
    document = receipt_document_from_json(wire)
    encoded = receipt_document_to_json(document)
    assert canonical_encode(cast(JsonValue, encoded)) == canonical_encode(cast(JsonValue, wire))
    assert canonical_digest(cast(JsonValue, encoded)) == expected_digest
    assert receipt_document_from_json(encoded) == document


@pytest.mark.parametrize(
    ("file_name", "variant_name", "wire", "expected", "_digest"),
    _VARIANTS,
    ids=[f"{file_name}:{variant_name}" for file_name, variant_name, *_ in _VARIANTS],
)
def test_render_receipt_compact_never_outruns_evidence(
    file_name: str,
    variant_name: str,
    wire: dict[str, Any],
    expected: str,
    _digest: str,
) -> None:
    del file_name, variant_name
    rendered = render_receipt_compact(receipt_document_from_json(wire))
    assert rendered == _rendered_with_current_product_name(expected)
    assert "\n" not in rendered
    assert len(rendered) <= 32_768
    assert "fully verified" not in rendered.lower()
    assert "all work is complete" not in rendered.lower()


@pytest.mark.parametrize(
    "missing_key",
    ("receipt_id", "task_id", "session_id", "generated_at", "subject_frontier", "versions"),
)
def test_receipt_document_requires_frontier_and_versions(missing_key: str) -> None:
    wire = _variant("deterministic-current.case.json", "current_complete")
    del wire[missing_key]
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(wire)
    _assert_reason(exc_info, "receipt_json_shape_invalid")


def test_receipt_document_is_frozen_and_exactly_shaped() -> None:
    document = receipt_document_from_json(
        _variant("deterministic-current.case.json", "current_complete")
    )
    expected_fields = (
        "schema_version",
        "receipt_id",
        "task_id",
        "session_id",
        "generated_at",
        "subject_frontier",
        "conclusion",
        "suppressed_finding_count",
        "versions",
        "coverage",
        "findings",
        "obligations",
        "responses",
        "claim_refs",
        "evidence_refs",
        "gaps",
        "redactions",
        "sections",
        "children",
        "semantic_provenance",
        "semantic_status",
        "semantic_reason",
        "acknowledged_not_done_finding_ids",
        "rejection_accepted_finding_ids",
        "self_verified_finding_ids",
        "disproved_self_verified_finding_ids",
        "disputed_after_rebuttal_finding_ids",
        "duplicate_finding_links",
        "semantic_withheld_items",
        "semantic_redacted_values",
        "disclosed_assumptions",
        "acknowledged_not_done_obligation_ids",
        "premise_disputed_finding_ids",
        "limitation_disclosed_finding_ids",
        "conclusion_basis",
        "correctness_advisory_counts",
        "verification_coverage",  # #1170: the optional agent-declared coverage projection
    )
    assert is_dataclass(document)
    assert ReceiptDocument.__slots__ == expected_fields
    assert tuple(item.name for item in fields(document)) == expected_fields
    with pytest.raises(FrozenInstanceError):
        setattr(document, "suppressed_finding_count", 1)


def test_receipt_withheld_items_round_trip_and_human_projection() -> None:
    wire = _variant("deterministic-current.case.json", "current_complete")
    wire["semantic_withheld_items"] = [
        {"item_id": "excerpt-heuristic", "reason": "never_send_heuristic"}
    ]

    document = receipt_document_from_json(wire)
    encoded = receipt_document_to_json(document)
    assert encoded["semantic_withheld_items"] == wire["semantic_withheld_items"]
    assert receipt_document_from_json(encoded) == document
    rendered = render_receipt_human(document, markdown=False)
    assert "excerpt-heuristic" in rendered
    assert "never_send_heuristic" in rendered
    assert "item text was not sent or echoed" in rendered


def test_receipt_redacted_values_round_trip_and_render_refs_lines_and_agent_line() -> None:
    """PL2-1 (issue #982): refs and line numbers only, plus the fixed agent line once."""

    wire = _variant("deterministic-current.case.json", "current_complete")
    wire["semantic_withheld_items"] = [
        {"item_id": "excerpt-withheld", "reason": "never_send_heuristic"}
    ]
    wire["semantic_redacted_values"] = [
        {
            "disposition": "value_replaced",
            "item_id": "excerpt-replaced",
            "lines": [2, 9],
            "source_ref": "evd_10000000-0000-4000-8000-000000000021",
        },
        {"disposition": "item_withheld", "item_id": "excerpt-withheld", "lines": [4]},
    ]
    document = receipt_document_from_json(wire)
    encoded = receipt_document_to_json(document)
    assert encoded["semantic_redacted_values"] == wire["semantic_redacted_values"]
    assert receipt_document_from_json(encoded) == document
    for markdown in (True, False):
        rendered = render_receipt_human(document, markdown=markdown)
        assert (
            "evd_10000000-0000-4000-8000-000000000021 (item excerpt-replaced): value replaced, "
            "lines 2, 9"
        ) in rendered
        assert "excerpt-withheld: item withheld, line 4" in rendered
        assert rendered.count(SEMANTIC_REDACTED_VALUES_AGENT_LINE) == 1
        assert rendered.isascii()


def test_receipt_rejects_redacted_values_that_carry_more_than_structure() -> None:
    wire = _variant("deterministic-current.case.json", "current_complete")
    wire["semantic_redacted_values"] = [
        {"disposition": "value_replaced", "item_id": "x", "lines": [1], "value": "secret"}
    ]
    with pytest.raises(ProtocolValueError):
        receipt_document_from_json(wire)
    wire["semantic_redacted_values"] = [
        {"disposition": "value_replaced", "item_id": "x", "lines": [1], "source_ref": "a/b.py"}
    ]
    with pytest.raises(ProtocolValueError):
        receipt_document_from_json(wire)


def test_historical_receipt_omits_withheld_items() -> None:
    wire = _variant("deterministic-current.case.json", "current_complete")
    document = receipt_document_from_json(wire)
    assert document.semantic_withheld_items == ()
    assert "semantic_withheld_items" not in receipt_document_to_json(document)
    assert document.semantic_redacted_values == ()
    assert "semantic_redacted_values" not in receipt_document_to_json(document)
    assert SEMANTIC_REDACTED_VALUES_AGENT_LINE not in render_receipt_human(document, markdown=True)


def test_children_use_receipt_document_1_3_artifact_and_keep_inner_version() -> None:
    """The additive artifact carries children while the inner document version stays 1.0.0."""

    wire = _variant("deterministic-current.case.json", "current_complete")
    versions = cast(dict[str, Any], wire["versions"])
    schema_versions = cast(list[dict[str, str]], versions["schema_versions"])
    for entry in schema_versions:
        if entry["schema_id"] == "receipts/receipt-document":
            entry["schema_version"] = "1.3.0"
    wire["children"] = {"children": []}

    document = receipt_document_from_json(wire)
    assert document.schema_version == "1.0.0"
    assert receipt_document_to_json(document) == wire


def _terminal_artifact(conclusion: str) -> dict[str, Any]:
    wire = _variant("unresolved-findings.case.json", "mixed_open_responses")
    versions = cast(dict[str, Any], wire["versions"])
    for entry in cast(list[dict[str, str]], versions["schema_versions"]):
        if entry["schema_id"] == "receipts/receipt-document":
            entry["schema_version"] = "1.3.0"
    wire["children"] = {"children": []}
    wire["conclusion"] = conclusion
    return wire


def test_self_verified_ids_get_their_own_section_and_never_read_clean() -> None:
    """Issue #984 (ADR-034): the agent's own verification is disclosed, never a clean receipt."""

    wire = _terminal_artifact("insufficient_coverage")
    findings = cast(list[dict[str, Any]], wire["findings"])
    finding = cast(str, findings[0]["finding_id"])
    wire["self_verified_finding_ids"] = [finding]
    document = receipt_document_from_json(wire)
    assert document.self_verified_finding_ids == (finding,)
    encoded = receipt_document_to_json(document)
    assert encoded["self_verified_finding_ids"] == [finding]
    assert receipt_document_from_json(encoded) == document
    for markdown in (True, False):
        rendered = render_receipt_human(document, markdown=markdown)
        assert (
            "Self-verified by the agent; FinishUP could not independently prove the outcome"
            in rendered
        )
        assert f"- {finding}" in rendered
    assert finding not in {item.finding_id for item in unresolved_findings_for_render(document)}

    wire["disproved_self_verified_finding_ids"] = [finding]
    disproved = receipt_document_from_json(wire)
    assert receipt_document_from_json(receipt_document_to_json(disproved)) == disproved
    for markdown in (True, False):
        text = render_receipt_human(disproved, markdown=markdown)
        assert "Concerns the agent reports disproved" in text
        assert "reports that they do not hold" in text
        assert "The agent repaired these" not in text

    clean = _terminal_artifact("no_unresolved_deterministic_findings")
    clean["self_verified_finding_ids"] = [finding]
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(clean)
    _assert_reason(exc_info, "invalid_receipt_conclusion")


def test_stopped_review_receipt_preserves_the_requested_review_outcome() -> None:
    wire = _terminal_artifact("insufficient_coverage")
    wire["semantic_status"] = "unavailable"
    wire["semantic_reason"] = "round_limit_unassessable"
    wire.pop("semantic_provenance", None)
    document = receipt_document_from_json(wire)
    assert receipt_document_to_json(document)["semantic_reason"] == "round_limit_unassessable"
    for markdown in (True, False):
        text = render_receipt_human(document, markdown=markdown)
        assert "unavailable / round_limit_unassessable" in text
        assert "Requested review stopped" in text
    assert "round_limit_unassessable" in render_receipt_compact(document)
    for mutation in (
        {"semantic_status": "not_requested"},
        {"semantic_reason": "deterministic_mode"},
    ):
        with pytest.raises(ProtocolValueError):
            receipt_document_from_json({**wire, **mutation})


def test_disputed_after_rebuttal_ids_get_their_own_section_and_never_read_clean() -> None:
    """Issue #1020 (ADR-040): a standing reviewer disagreement is disclosed, never clean."""

    wire = _terminal_artifact("insufficient_coverage")
    findings = cast(list[dict[str, Any]], wire["findings"])
    finding = cast(str, findings[0]["finding_id"])
    wire["disputed_after_rebuttal_finding_ids"] = [finding]
    document = receipt_document_from_json(wire)
    assert document.disputed_after_rebuttal_finding_ids == (finding,)
    encoded = receipt_document_to_json(document)
    assert encoded["disputed_after_rebuttal_finding_ids"] == [finding]
    assert receipt_document_from_json(encoded) == document
    for markdown in (True, False):
        rendered = render_receipt_human(document, markdown=markdown)
        assert "Disputed after rebuttal" in rendered
        assert "The reviewer and the agent disagree" in rendered
        assert f"- {finding}" in rendered
    assert finding not in {item.finding_id for item in unresolved_findings_for_render(document)}

    clean = _terminal_artifact("no_unresolved_deterministic_findings")
    clean["disputed_after_rebuttal_finding_ids"] = [finding]
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(clean)
    _assert_reason(exc_info, "invalid_receipt_conclusion")
    # A finding is in at most one terminal section.
    both = _terminal_artifact("insufficient_coverage")
    both["disputed_after_rebuttal_finding_ids"] = [finding]
    both["self_verified_finding_ids"] = [finding]
    with pytest.raises(ProtocolValueError):
        receipt_document_from_json(both)


def test_disclosed_assumptions_round_trip_with_ids_and_kind_only() -> None:
    """Issue #995: disclosures are ids and a closed kind only, on the 1.3.0 artifact."""

    obligation = "obl_00000000-0000-4000-8000-000000000001"
    decision = "evt_00000000-0000-4000-8000-000000000009"
    wire = _terminal_artifact("insufficient_coverage")
    wire["disclosed_assumptions"] = [
        {"obligation_id": obligation, "kind": "assumption", "decision_event_id": decision},
        {"obligation_id": obligation, "kind": "verification_limit", "decision_event_id": decision},
    ]
    document = receipt_document_from_json(wire)
    assert [item.kind for item in document.disclosed_assumptions] == [
        "assumption",
        "verification_limit",
    ]
    encoded = receipt_document_to_json(document)
    assert encoded["disclosed_assumptions"] == wire["disclosed_assumptions"]
    assert receipt_document_from_json(encoded) == document
    for markdown in (True, False):
        rendered = render_receipt_human(document, markdown=markdown)
        assert "Assumptions and verification limits the agent disclosed" in rendered
        assert f"- {obligation}: verification_limit (decision {decision})" in rendered

    bad_kind = _terminal_artifact("insufficient_coverage")
    bad_kind["disclosed_assumptions"] = [
        {"obligation_id": obligation, "kind": "blocker", "decision_event_id": decision}
    ]
    with pytest.raises(ProtocolValueError):
        receipt_document_from_json(bad_kind)
    prose = _terminal_artifact("insufficient_coverage")
    prose["disclosed_assumptions"] = [
        {
            "obligation_id": obligation,
            "kind": "assumption",
            "decision_event_id": decision,
            "rationale": "never copied",
        }
    ]
    with pytest.raises(ProtocolValueError):
        receipt_document_from_json(prose)
    empty = _terminal_artifact("insufficient_coverage")
    empty["disclosed_assumptions"] = []
    with pytest.raises(ProtocolValueError):
        receipt_document_from_json(empty)
    legacy = _variant("deterministic-current.case.json", "current_complete")
    legacy["disclosed_assumptions"] = [
        {"obligation_id": obligation, "kind": "assumption", "decision_event_id": decision}
    ]
    with pytest.raises(ProtocolValueError):
        receipt_document_from_json(legacy)


def test_acknowledged_obligations_get_their_own_section_and_never_read_clean() -> None:
    """Issue #997 (ADR-032 slice C): an obligation the agent will not do is disclosed by id."""

    obligation = "obl_00000000-0000-4000-8000-000000000003"
    wire = _terminal_artifact("insufficient_coverage")
    wire["acknowledged_not_done_obligation_ids"] = [obligation]
    document = receipt_document_from_json(wire)
    assert document.acknowledged_not_done_obligation_ids == (obligation,)
    encoded = receipt_document_to_json(document)
    assert encoded["acknowledged_not_done_obligation_ids"] == [obligation]
    assert receipt_document_from_json(encoded) == document
    for markdown in (True, False):
        rendered = render_receipt_human(document, markdown=markdown)
        assert "Obligations acknowledged as not done" in rendered
        assert f"- {obligation}" in rendered

    clean = _terminal_artifact("no_unresolved_deterministic_findings")
    clean["acknowledged_not_done_obligation_ids"] = [obligation]
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(clean)
    _assert_reason(exc_info, "invalid_receipt_conclusion")
    legacy = _variant("deterministic-current.case.json", "current_complete")
    legacy["acknowledged_not_done_obligation_ids"] = [obligation]
    with pytest.raises(ProtocolValueError):
        receipt_document_from_json(legacy)


def test_premise_disputed_findings_are_a_subset_with_their_own_section() -> None:
    """Issue #984 (D7a): acknowledged findings the review says the task requires."""

    wire = _terminal_artifact("unresolved_findings_remain")
    finding = cast(str, cast(list[dict[str, Any]], wire["findings"])[0]["finding_id"])
    wire["acknowledged_not_done_finding_ids"] = [finding]
    wire["premise_disputed_finding_ids"] = [finding]
    document = receipt_document_from_json(wire)
    assert document.premise_disputed_finding_ids == (finding,)
    assert receipt_document_from_json(receipt_document_to_json(document)) == document
    for markdown in (True, False):
        rendered = render_receipt_human(document, markdown=markdown)
        assert "Not done although the review says the task requires it" in rendered
    unacknowledged = _terminal_artifact("unresolved_findings_remain")
    unacknowledged["premise_disputed_finding_ids"] = [finding]
    with pytest.raises(ProtocolValueError):
        receipt_document_from_json(unacknowledged)


def test_children_are_rejected_under_the_legacy_receipt_artifact() -> None:
    wire = _variant("deterministic-current.case.json", "current_complete")
    wire["children"] = {"children": []}
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(wire)
    _assert_reason(exc_info, "invalid_receipt_document")


def test_receipt_conclusion_vocab_is_conservative() -> None:
    assert {value.value for value in ReceiptConclusion} == {
        "no_unresolved_deterministic_findings",
        "unresolved_findings_remain",
        "insufficient_coverage",
    }
    assert all(
        "verified" not in value.value and value.value != "pass" for value in ReceiptConclusion
    )


def test_verdict_conclusion_correspondence_is_exhaustive() -> None:
    fixed = {
        CheckVerdict.ACTION_REQUIRED: ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN,
        CheckVerdict.NO_ISSUE_DETECTED: ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS,
        CheckVerdict.INSUFFICIENT_COVERAGE: ReceiptConclusion.INSUFFICIENT_COVERAGE,
    }
    incomplete = {
        False: ReceiptConclusion.INSUFFICIENT_COVERAGE,
        True: ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN,
    }
    assert set(fixed) | {CheckVerdict.INCOMPLETE_CHECK} == set(CheckVerdict)
    assert incomplete[False] is ReceiptConclusion.INSUFFICIENT_COVERAGE
    assert incomplete[True] is ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN


def test_suppressed_latest_check_cannot_claim_clear() -> None:
    wire = _variant("deterministic-current.case.json", "current_complete")
    wire["suppressed_finding_count"] = 1
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(wire)
    _assert_reason(exc_info, "invalid_receipt_document")

    wire["conclusion"] = "insufficient_coverage"
    document = receipt_document_from_json(wire)
    assert document.suppressed_finding_count == 1
    assert document.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE


def test_receipt_weakest_coverage_matches_supports() -> None:
    wire = _variant("semantic-advisory.case.json", "success_after_durable_receipt")
    document = receipt_document_from_json(wire)
    assert receipt_weakest_coverage(document) == document.coverage

    finding = cast(list[dict[str, Any]], wire["findings"])[0]
    finding_coverage = cast(dict[str, Any], finding["coverage"])
    finding_coverage["artifact_observation"] = "published_only"
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(wire)
    _assert_reason(exc_info, "receipt_coverage_mismatch")


def test_resolved_history_is_carried_without_bounding_document_coverage() -> None:
    """Issue #912: only current rows bound the coverage; summary-listed resolved rows do not."""

    wire = _variant("semantic-advisory.case.json", "success_after_durable_receipt")
    finding = cast(list[dict[str, Any]], wire["findings"])[0]
    cast(dict[str, Any], finding["coverage"])["artifact_observation"] = "published_only"
    sections = cast(list[dict[str, Any]], wire["sections"])
    summary = next(section for section in sections if section["key"] == "summary")
    summary["items"] = [finding["finding_id"]]

    document = receipt_document_from_json(wire)
    assert receipt_weakest_coverage(document) == document.coverage
    assert tuple(item.finding_id for item in document.findings) == (finding["finding_id"],)
    # The same weaker row without the resolved-history marker is a current row again.
    summary["items"] = []
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(wire)
    _assert_reason(exc_info, "receipt_coverage_mismatch")


def test_section_order_and_redaction_notes_are_stable() -> None:
    wire = _variant("redacted-gap.case.json", "redacted_object")
    document = receipt_document_from_json(wire)
    assert tuple(section.key for section in document.sections) == (
        ReceiptSectionKey.SUMMARY,
        ReceiptSectionKey.LIMITATIONS_AND_COVERAGE,
        ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY,
    )
    assert len(document.redactions) == 1
    assert document.redactions[0].category is ReceiptRedactionCategory.EVIDENCE_CONTENT
    assert document.redactions[0].reason is ReceiptRedactionReason.SOURCE_REDACTED
    assert document.redactions[0].count == 1
    assert (
        cast(list[dict[str, Any]], receipt_document_to_json(document)["redactions"])[0]["count"]
        == "1"
    )

    sections = cast(list[dict[str, Any]], wire["sections"])
    sections[0], sections[1] = sections[1], sections[0]
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(wire)
    _assert_reason(exc_info, "invalid_receipt_section_order")


@pytest.mark.parametrize(
    ("refs", "reason"),
    (
        (
            [
                "res_40000000-0000-4000-8000-000000000007",
                "evd_40000000-0000-4000-8000-000000000005",
            ],
            "unsorted_set_field",
        ),
        (
            [
                "evd_40000000-0000-4000-8000-000000000005",
                "evd_40000000-0000-4000-8000-000000000005",
            ],
            "duplicate_set_member",
        ),
        (["act_40000000-0000-4000-8000-000000000007"], "invalid_receipt_response"),
    ),
)
def test_receipt_response_rejects_invalid_evidence_result_sets(
    refs: list[str], reason: str
) -> None:
    wire = _variant("waiver-expiry.case.json", "active_exact_scope")
    response = cast(list[dict[str, Any]], wire["responses"])[0]
    response["evidence_refs"] = refs
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(wire)
    _assert_reason(exc_info, reason)


def test_receipt_response_preserves_evidence_and_result_refs() -> None:
    wire = _variant("waiver-expiry.case.json", "active_exact_scope")
    refs = [
        "evd_40000000-0000-4000-8000-000000000005",
        "res_40000000-0000-4000-8000-000000000007",
    ]
    response = cast(list[dict[str, Any]], wire["responses"])[0]
    response["evidence_refs"] = refs
    document = receipt_document_from_json(wire)
    assert list(document.responses[0].evidence_refs) == refs
    encoded_responses = cast(list[dict[str, Any]], receipt_document_to_json(document)["responses"])
    assert encoded_responses[0]["evidence_refs"] == refs


def test_receipt_section_items_are_required_and_exact() -> None:
    wire = _variant("deterministic-current.case.json", "current_complete")
    section = cast(list[dict[str, Any]], wire["sections"])[0]
    del section["items"]
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(wire)
    _assert_reason(exc_info, "invalid_receipt_section")

    wire = _variant("deterministic-current.case.json", "current_complete")
    document = receipt_document_from_json(wire)
    assert document.sections[0].items == ()
    encoded_sections = cast(list[dict[str, Any]], receipt_document_to_json(document)["sections"])
    assert "items" in encoded_sections[0]
    assert encoded_sections[0]["items"] == []


def test_every_explicit_gap_occurs_in_coverage_summary() -> None:
    wire = _variant("redacted-gap.case.json", "locked_key")
    coverage = cast(dict[str, Any], wire["coverage"])
    coverage["known_gaps"] = []
    with pytest.raises(ProtocolValueError) as exc_info:
        receipt_document_from_json(wire)
    _assert_reason(exc_info, "receipt_gap_not_in_coverage")


def test_semantic_review_not_configured_receipt_states_not_run() -> None:
    """Requirement: receipt with AI-powered evaluator not configured discloses not-run."""

    from finishup.domain.receipts import (
        OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
        SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
    )

    wire = _variant("deterministic-current.case.json", "current_complete")
    wire["conclusion"] = "insufficient_coverage"
    coverage = cast(dict[str, Any], wire["coverage"])
    coverage["known_gaps"] = [SEMANTIC_REVIEW_NOT_CONFIGURED_GAP]
    coverage["ledger_freshness"] = "partial"
    wire["gaps"] = [{"code": SEMANTIC_REVIEW_NOT_CONFIGURED_GAP, "subject_refs": []}]
    for section in cast(list[dict[str, Any]], wire["sections"]):
        if section["key"] == "limitations_and_coverage":
            section["body"] = (
                "AI-powered relevance review was not run. "
                f"Coverage is limited by: {SEMANTIC_REVIEW_NOT_CONFIGURED_GAP}."
            )
            section["items"] = [SEMANTIC_REVIEW_NOT_CONFIGURED_GAP]
        if section["key"] == "summary":
            section["body"] = "Coverage is insufficient at frontier 7."
    document = receipt_document_from_json(wire)
    assert SEMANTIC_REVIEW_NOT_CONFIGURED_GAP in {gap.code for gap in document.gaps}
    assert OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP not in {gap.code for gap in document.gaps}
    rendered = render_receipt_compact(document)
    assert "AI-powered relevance review was not run" in rendered
    assert "optional AI-powered review was blocked" not in rendered
    assert "coverage is insufficient" in rendered
    assert "no unresolved local issue was found in the published record" not in rendered


def test_semantic_relevance_review_not_run_gap_shares_not_run_wording() -> None:
    """Evaluator failure/timeout uses the same truthful not-run disclosure family."""

    from finishup.domain.receipts import SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP

    wire = _variant("deterministic-current.case.json", "current_complete")
    wire["conclusion"] = "insufficient_coverage"
    coverage = cast(dict[str, Any], wire["coverage"])
    coverage["known_gaps"] = [SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP]
    coverage["ledger_freshness"] = "partial"
    wire["gaps"] = [{"code": SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP, "subject_refs": []}]
    for section in cast(list[dict[str, Any]], wire["sections"]):
        if section["key"] == "limitations_and_coverage":
            section["body"] = (
                "AI-powered relevance review was not run. "
                f"Coverage is limited by: {SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP}."
            )
            section["items"] = [SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP]
        if section["key"] == "summary":
            section["body"] = "Coverage is insufficient at frontier 7."
    rendered = render_receipt_compact(receipt_document_from_json(wire))
    assert "AI-powered relevance review was not run" in rendered


def test_compact_receipt_names_a_pre_edit_deferral() -> None:
    """A not-requested receipt that also carries the deferral gap uses the deferral sentence."""

    from finishup.domain.receipts import (
        DEFERRED_BEFORE_FIRST_EDIT_TEXT,
        SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP,
        SEMANTIC_REVIEW_NOT_REQUESTED_GAP,
    )

    gaps = sorted(
        (
            SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP,
            SEMANTIC_REVIEW_NOT_REQUESTED_GAP,
        )
    )

    def rendered(conclusion: str) -> str:
        wire = _variant("deterministic-current.case.json", "current_complete")
        wire["conclusion"] = conclusion
        coverage = cast(dict[str, Any], wire["coverage"])
        coverage["known_gaps"] = gaps
        coverage["ledger_freshness"] = "partial"
        wire["gaps"] = [{"code": code, "subject_refs": []} for code in gaps]
        for section in cast(list[dict[str, Any]], wire["sections"]):
            if section["key"] == "limitations_and_coverage":
                section["body"] = (
                    f"{DEFERRED_BEFORE_FIRST_EDIT_TEXT} Coverage is limited by: "
                    + ", ".join(gaps)
                    + "."
                )
                section["items"] = list(gaps)
            if section["key"] == "summary":
                section["body"] = "Coverage is insufficient at frontier 7."
        return render_receipt_compact(receipt_document_from_json(wire))

    for conclusion in (
        "insufficient_coverage",
        "unresolved_findings_remain",
        "no_unresolved_deterministic_findings",
    ):
        text = rendered(conclusion)
        assert DEFERRED_BEFORE_FIRST_EDIT_TEXT in text
        assert "AI-powered relevance review was not run" not in text


def test_semantic_review_not_run_never_hides_unresolved_findings() -> None:
    """An AI-powered gap must not turn an unresolved local receipt into a clean claim."""

    from finishup.domain.receipts import SEMANTIC_REVIEW_NOT_CONFIGURED_GAP

    wire = _variant("deterministic-current.case.json", "current_complete")
    wire["conclusion"] = "unresolved_findings_remain"
    coverage = cast(dict[str, Any], wire["coverage"])
    coverage["known_gaps"] = [SEMANTIC_REVIEW_NOT_CONFIGURED_GAP]
    coverage["ledger_freshness"] = "partial"
    wire["gaps"] = [{"code": SEMANTIC_REVIEW_NOT_CONFIGURED_GAP, "subject_refs": []}]
    document = receipt_document_from_json(wire)

    rendered = render_receipt_compact(document)

    assert "unresolved finding" in rendered
    assert "AI-powered relevance review was not run" in rendered
    assert "no unresolved local issue" not in rendered
    assert "blocked before dispatch" not in rendered


def test_render_receipt_human_projects_sections_and_advisory_count() -> None:
    """#437/#429: markdown/text human_text carries sections, not a compact one-liner."""

    from finishup.domain.findings import FindingKind, FindingOrigin

    wire = _variant("unresolved-findings.case.json", "mixed_open_responses")
    wire["sections"][0]["coverage_note"] = "Coverage note"
    document = receipt_document_from_json(wire)
    markdown = render_receipt_human(document, markdown=True)
    text = render_receipt_human(document, markdown=False)
    assert "## Limitations" in markdown
    assert "Limitations" in text
    assert "\n" in markdown
    assert document.sections[0].body in markdown
    assert document.sections[0].body in text
    assert f"- {document.sections[1].items[0]}" in markdown
    assert f"- {document.sections[1].items[0]}" in text
    assert "Coverage note" in markdown
    assert "Coverage note" in text
    assert "do not by themselves select unresolved_findings_remain" not in markdown
    assert all(
        finding.kind is not FindingKind.LEDGER_STALE_OR_INCOMPLETE for finding in document.findings
    )
    assert FindingOrigin.DETERMINISTIC in {finding.origin for finding in document.findings}

    advisory = receipt_document_from_json(
        _variant("semantic-advisory.case.json", "success_after_durable_receipt")
    )
    advisory_text = render_receipt_human(advisory, markdown=True)
    assert "## Limitations" in advisory_text
    assert "AI-powered review completed" in advisory_text
    # material_limitation_omitted is actionable, so no extra coverage-limitation appendix.
    assert "do not by themselves select unresolved_findings_remain" not in advisory_text

    stale = _variant("unresolved-findings.case.json", "mixed_open_responses")
    stale["findings"][0]["kind"] = "ledger_stale_or_incomplete"
    stale["findings"][0]["priority"] = 3
    stale_document = receipt_document_from_json(stale)
    stale_text = render_receipt_human(stale_document, markdown=True)
    assert "do not by themselves select unresolved_findings_remain" in stale_text


def test_render_receipt_human_marks_bounded_truncation() -> None:
    """#437: the wire bound cannot silently erase later receipt sections.

    tb4n3 RC-2 (A7): the cut is by section. A 32 KiB first section is shortened, the marker names
    it, and every later section keeps its heading and its content.
    """

    wire = _variant("unresolved-findings.case.json", "mixed_open_responses")
    wire["sections"][0]["body"] = "x" * 32_768
    document = receipt_document_from_json(wire)

    rendered = render_receipt_human(document, markdown=True)

    assert len(rendered) <= 32_768
    assert "truncated at 32768 characters" in rendered
    assert "shortened sections: Summary" in rendered
    assert rendered.endswith("holds every section in full.]")
    for section in document.sections[1:]:
        assert f"## {section.title}" in rendered
        assert section.body[:60] in rendered


def test_registration_drift_compact_names_policy_recovery() -> None:
    """Issue #537 slice C: applied-policy-serving-strict names the recovery compactly."""

    # The drift variant is built in memory on the ceiling-only fixture rather than
    # stored as a second golden vector: the coverage schema's `known_gaps` pattern
    # (`^[a-z][a-z0-9_]{0,127}$`) is open, so the new gap code needs no schema bump,
    # and the ceiling-only fixture plus this augmentation cover both wordings.
    from finishup.domain.receipts import OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP

    wire = _variant("semantic-advisory.case.json", "predispatch_policy_block")
    coverage = cast(dict[str, Any], wire["coverage"])
    coverage["known_gaps"] = sorted(
        [*coverage["known_gaps"], OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP]
    )
    wire["gaps"] = [
        *wire["gaps"],
        {"code": OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP, "subject_refs": []},
    ]
    rendered = render_receipt_compact(receipt_document_from_json(wire))
    assert (
        "blocked by the strict route ceiling while the last install applied the policy route"
        in rendered
    )
    # The disagreement is the claim; whether the strict route was intended is the owner's
    # to say, so the recovery is offered as a conditional rather than asserted.
    assert "If this strict route was not intended" in rendered
    assert "finishup integrate codex mcp install --route-profile policy" in rendered
    assert "start a fresh Codex process" in rendered
    assert "No provider attempt or AI-powered finding was recorded." in rendered


def test_render_receipt_human_projects_registry_recovery_from_provenance() -> None:
    document = receipt_document_from_json(
        _variant("deterministic-current.case.json", "current_complete")
    )
    digest = "sha256:" + "c" * 64
    uuid = "00000000-0000-4000-8000-000000000001"
    provenance = SemanticProvenance(
        provider="openai",
        endpoint_profile_id="review.default",
        endpoint_profile_version="1.0.0",
        model="gpt-5.4",
        sdk_version="2.46.0",
        prompt_digest=digest,
        schema_digest=digest,
        policy_digest=digest,
        privacy_policy_digest=digest,
        sampling_params=SamplingParams(
            max_output_tokens=2_048,
            temperature="0.20",
            top_p="1.0",
            seed=7,
        ),
        latency_ms=321,
        semantic_attempt_id="att_" + uuid,
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_" + "00000000-0000-4000-8000-000000000002",
        status=SemanticStatus.UNAVAILABLE,
        reason=SemanticReason.TRANSPORT_UNAVAILABLE,
        provider_request_id="request:abc-123",
        token_usage=TokenUsage(input_tokens=12, output_tokens=7, total_tokens=19),
        cost_fields=CostFields(
            currency="USD",
            input_microunits=12,
            output_microunits=14,
            total_microunits=26,
        ),
        failure_class=SemanticFailureClass.AUTHENTICATION,
        egress_authorization_id="aut_" + "00000000-0000-4000-8000-000000000003",
        request_commitment="hmac-sha256:" + "d" * 64,
    )
    rendered = render_receipt_human(
        replace(document, semantic_provenance=provenance), markdown=True
    )
    assert "## Recovery" in rendered
    assert "Continuation: semantic_credential_rejected" in rendered
    compact = render_receipt_compact(replace(document, semantic_provenance=provenance))
    assert "Continuation:" not in compact


def test_genuine_strict_ceiling_compact_keeps_terminal_wording() -> None:
    """Without the drift gap the blocked compact sentence keeps today's wording exactly."""

    wire = _variant("semantic-advisory.case.json", "predispatch_policy_block")
    rendered = render_receipt_compact(receipt_document_from_json(wire))
    assert rendered == (
        "FinishUP receipt at frontier 22: coverage is insufficient because optional AI-powered "
        "review was blocked before dispatch by network-egress policy. No provider attempt "
        "or AI-powered finding was recorded."
    )


def test_duplicate_links_round_trip_by_ids_and_render_in_their_own_section() -> None:
    """Issue #996: holding ``duplicate_of`` links, ids only, on the 1.3.0 artifact."""

    wire = _terminal_artifact("unresolved_findings_remain")
    findings = cast(list[dict[str, Any]], wire["findings"])
    duplicate = cast(str, findings[0]["finding_id"])
    earlier = "fnd_00000000-0000-4000-8000-000000000996"
    wire["duplicate_finding_links"] = [
        {"finding_id": duplicate, "duplicate_of_finding_id": earlier}
    ]
    document = receipt_document_from_json(wire)
    assert [
        (item.finding_id, item.duplicate_of_finding_id) for item in document.duplicate_finding_links
    ] == [(duplicate, earlier)]
    encoded = receipt_document_to_json(document)
    assert encoded["duplicate_finding_links"] == wire["duplicate_finding_links"]
    assert receipt_document_from_json(encoded) == document
    for markdown, heading in ((True, "## Linked duplicates"), (False, "Linked duplicates")):
        rendered = render_receipt_human(document, markdown=markdown)
        assert heading in rendered
        assert f"- {duplicate} duplicates {earlier}" in rendered
        assert "never resolves a finding by itself" in rendered
    # The link never settles the row: it stays among the unresolved findings it reads as.
    assert duplicate in {item.finding_id for item in unresolved_findings_for_render(document)}

    for bad in (
        [{"finding_id": duplicate, "duplicate_of_finding_id": duplicate}],  # itself
        [{"finding_id": earlier, "duplicate_of_finding_id": duplicate}],  # not carried
        [{"finding_id": duplicate, "duplicate_of_finding_id": earlier, "reason": "x"}],  # prose
        [],  # present only when non-empty
    ):
        broken = deepcopy(wire)
        broken["duplicate_finding_links"] = bad
        with pytest.raises(ProtocolValueError):
            receipt_document_from_json(broken)
    legacy = _variant("unresolved-findings.case.json", "mixed_open_responses")
    legacy["duplicate_finding_links"] = wire["duplicate_finding_links"]
    with pytest.raises(ProtocolValueError):
        receipt_document_from_json(legacy)
