"""Image and binary files in the review packet (TB4 tb4n1 D6; issues #983 and #1004).

The packet is text: no pixels or binary bytes ever travel. A row that records such a file is
carried as a short notice that the file exists and was not sent, citing its evidence id, and an
agent's text rendering of a binary deliverable is labelled as the agent's rendering, never as
the file itself. Both are plain text inside existing excerpt rows, so the manifest discloses them
through the caller-evidence section without a new wire field.
"""

from __future__ import annotations

from dataclasses import replace

from builders.policy_cases import (
    clm,
    evd,
    evidence_record,
    make_case,
)
from yoetz.application.semantic_case import MAX_BINARY_NOTICES, build_semantic_case
from yoetz.domain.events import (
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceKind,
    EvidenceRecordedPayload,
)
from yoetz.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from yoetz.domain.values import timestamp_from_string
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.ports.semantic import SemanticCase
from yoetz.protocol.coverage import EvidenceImmutability

_NOW = timestamp_from_string("2026-10-07T12:00:00.000Z")
_IMAGE_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def _observed_image(number: int) -> EvidenceRecordedPayload:
    """The L3 P3-2 row a hook writes for an image tool result: a digest, never pixels."""

    return EvidenceRecordedPayload(
        evd(number),
        EvidenceKind.ARTIFACT,
        EvidenceImmutability.CONTENT_DIGEST,
        _NOW,
        content_digest="sha256:" + "d" * 64,
        description=(
            "Observed image tool result image/png 800x600 (5120 bytes); "
            "pixels were not captured or sent"
        ),
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.ARTIFACT_BYTES,
            content_availability=EvidenceContentAvailability.DIGEST_ONLY,
            byte_count=5120,
            provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
        ),
    )


def _artifact(number: int, path: str, description: str | None = None) -> EvidenceRecordedPayload:
    return EvidenceRecordedPayload(
        evd(number),
        EvidenceKind.ARTIFACT,
        EvidenceImmutability.METADATA_ONLY,
        _NOW,
        reference=path,
        description=description,
    )


def _rendering(number: int, path: str, text: str) -> EvidenceRecordedPayload:
    return EvidenceRecordedPayload(
        evd(number),
        EvidenceKind.COMMAND_OUTPUT,
        EvidenceImmutability.METADATA_ONLY,
        _NOW,
        reference=path,
        description=text,
    )


def _build(case: DeterministicCase, selection: ReviewSelectionPolicy | None = None) -> SemanticCase:
    profile = ReviewContextProfile.EXPANDED if selection is None else ReviewContextProfile.CUSTOM
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=selection or ReviewSelectionPolicy.for_profile(profile),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )


def _texts(case: SemanticCase) -> dict[str, str]:
    return {
        item.source_ref: item.content.decode("utf-8")
        for item in case.items
        if item.section == "excerpt"
    }


def _case(*rows: EvidenceRecordedPayload) -> DeterministicCase:
    return make_case(
        evidence={
            row.evidence_id: evidence_record(row, 10 + index) for index, row in enumerate(rows)
        },
        extra_refs=(*(row.evidence_id for row in rows), clm(1)),
    )


def test_an_observed_image_is_a_notice_that_cites_its_evidence_and_sends_no_pixels() -> None:
    case = _build(_case(_observed_image(7)))

    text = _texts(case)[str(evd(7))]
    assert text.startswith(
        f"[Yoetz: an image or binary file exists and was not sent (evidence {evd(7)}); "
        "its content is not assessable from this packet]\n"
    )
    assert "Observed image tool result image/png 800x600" in text
    for item in case.items:
        assert _IMAGE_BYTES not in item.content
        assert b"\x89PNG" not in item.content
    # The manifest discloses the row through the caller-evidence section.
    manifest = case.packet.input_manifest
    assert manifest is not None
    assert str(evd(7)) in manifest.caller_evidence.source_refs
    assert f"excerpt-{evd(7)}" in manifest.caller_evidence.selected_item_ids


def test_a_recorded_binary_deliverable_is_a_notice_naming_its_path() -> None:
    case = _build(
        _case(
            _artifact(5, "out/schematic.PNG", "The rendered schematic."),
            _artifact(6, "model.FCStd"),
        )
    )

    texts = _texts(case)
    assert texts[str(evd(5))] == (
        f"[Yoetz: an image or binary file at out/schematic.PNG exists and was not sent "
        f"(evidence {evd(5)}); its content is not assessable from this packet]\n"
        "The rendered schematic."
    )
    assert texts[str(evd(6))].startswith(
        "[Yoetz: an image or binary file at model.FCStd exists and was not sent"
    )


def test_agent_rendered_text_of_a_binary_is_labelled_as_the_agents_rendering() -> None:
    """PL5-2 (#1004): pdftotext output recorded with the PDF's path as its reference."""

    rendered = "INVOICE 2026-0042\nTotal due: 1,240.00 EUR\n"
    case = _build(
        _case(
            _artifact(5, "out/invoice.pdf"),
            _rendering(6, "out/invoice.pdf", rendered),
        )
    )

    texts = _texts(case)
    assert texts[str(evd(6))] == (
        f"[Yoetz: agent-rendered text of out/invoice.pdf (evidence {evd(6)}); "
        "the binary file itself is not sent]\n" + rendered
    )
    assert texts[str(evd(5))].startswith("[Yoetz: an image or binary file at out/invoice.pdf")


def test_text_files_and_urls_are_never_labelled() -> None:
    case = _build(
        _case(
            _artifact(5, "src/app.py", "The patched module."),
            _rendering(6, "https://example.org/spec.pdf", "Section 4 says ..."),
        )
    )

    texts = _texts(case)
    assert texts[str(evd(5))] == "The patched module."
    assert texts[str(evd(6))] == "Section 4 says ..."


def test_notices_are_reserved_room_and_bounded() -> None:
    """Older notices outrank newer general output; past the bound they compete as usual."""

    narrow = replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED), max_excerpts=4
    )
    older_notices = [_artifact(number, f"img/{number}.png") for number in range(1, 4)]
    newer_output = [_rendering(number, f"log/{number}.txt", "ok") for number in range(4, 10)]
    case = _build(_case(*older_notices, *newer_output), narrow)
    carried = {item.source_ref for item in case.items if item.section == "excerpt"}
    assert {str(evd(number)) for number in range(1, 4)} <= carried

    count = MAX_BINARY_NOTICES + 4
    many = _build(
        _case(*(_artifact(number, f"img/{number}.png") for number in range(1, count + 1))),
        replace(narrow, max_excerpts=MAX_BINARY_NOTICES),
    )
    carried = {item.source_ref for item in many.items if item.section == "excerpt"}
    assert carried == {str(evd(number)) for number in range(count, count - MAX_BINARY_NOTICES, -1)}
    texts = _texts(many)
    assert all(len(text.encode("utf-8")) < 512 for text in texts.values())
