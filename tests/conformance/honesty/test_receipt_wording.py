"""Honesty conformance: receipts and their rendered text never overclaim beyond frozen evidence.

Every case in the reviewed ``fixtures/receipts/*.case.json`` corpus that carries a
``receipt_document`` is decoded through the real domain codec (``receipt_document_from_json``),
rendered through the real compact renderer (``render_receipt_compact``), and checked against the
fixture's own frozen expectations: the exact compact sentence, the absence of every
``forbidden_claims``/``forbidden_content`` phrase, and an explicit limitations surface whenever
coverage carries a live gap or the document carries a redaction. A gap a later check cleared
(``historical``, issue #1017) stays visible in its own rendered section instead. Variants without a
``receipt_document`` (rejected malformed inputs) must render no wording at all.
"""

from __future__ import annotations

from typing import cast

import pytest

from fixture_loader import FixtureLoader, JsonValue
from yoetz.domain.receipts import (
    ReceiptConclusion,
    ReceiptDocument,
    ReceiptSectionKey,
    historical_gap_line,
    historical_receipt_gaps,
    live_receipt_gap_codes,
    receipt_document_from_json,
    receipt_weakest_coverage,
    render_receipt_compact,
    render_receipt_human,
)
from yoetz.domain.values import freeze_json

_RECEIPT_FIXTURE_PATHS = (
    "receipts/deterministic-current.case.json",
    "receipts/semantic-advisory.case.json",
    "receipts/unresolved-findings.case.json",
    "receipts/waiver-expiry.case.json",
    "receipts/imported-partial.case.json",
    "receipts/redacted-gap.case.json",
)


def _variants(fixture_loader: FixtureLoader, path: str) -> dict[str, dict[str, object]]:
    document = cast(dict[str, object], fixture_loader.load_json(path))
    expected = cast(dict[str, object], document["expected"])
    variants = cast(dict[str, object], expected["variants"])
    return {name: cast(dict[str, object], value) for name, value in variants.items()}


def _iter_receipt_variants(
    fixture_loader: FixtureLoader,
) -> list[tuple[str, str, dict[str, object]]]:
    rows: list[tuple[str, str, dict[str, object]]] = []
    for path in _RECEIPT_FIXTURE_PATHS:
        for name, variant in _variants(fixture_loader, path).items():
            rows.append((path, name, variant))
    return rows


def _decode(variant: dict[str, object]) -> ReceiptDocument:
    raw = cast(JsonValue, variant["receipt_document"])
    return receipt_document_from_json(freeze_json(raw))


_NEGATION_CUES = ("not ", "never ", "n't ", "no ")


def _forbidden_phrase_is_asserted_positively(haystack: str, phrase: str) -> bool:
    """Return True only if *phrase* appears as an unqualified claim, not honestly negated.

    A conservative honest sentence such as "this is not proof of correctness" legitimately
    contains the substring "proof of correctness"; what a fixture's ``forbidden_claims`` actually
    forbids is asserting that phrase *positively*. This scans every occurrence and only flags one
    that is not immediately preceded by a negation cue.
    """

    lowered_haystack = haystack.lower()
    lowered_phrase = phrase.lower()
    start = 0
    while True:
        index = lowered_haystack.find(lowered_phrase, start)
        if index == -1:
            return False
        window = lowered_haystack[max(0, index - 16) : index]
        if not any(cue in window for cue in _NEGATION_CUES):
            return True
        start = index + 1


def test_conclusion_vocabulary_is_not_upgraded(fixture_loader: FixtureLoader) -> None:
    """The closed conclusion vocabulary contains only conservative outcomes, never a proof claim."""

    assert {member.value for member in ReceiptConclusion} == {
        "no_unresolved_deterministic_findings",
        "unresolved_findings_remain",
        "insufficient_coverage",
    }
    banned_tokens = ("verified", "proven", "proof", "guarantee", "certain", "complete")
    for member in ReceiptConclusion:
        lowered = member.value.lower()
        for token in banned_tokens:
            assert token not in lowered, (member, token)

    for path, name, variant in _iter_receipt_variants(fixture_loader):
        if "receipt_document" not in variant:
            continue
        document = _decode(variant)
        raw_document = cast(dict[str, object], variant["receipt_document"])
        assert document.conclusion.value == raw_document["conclusion"], (path, name)
        # A document whose known coverage still carries a live gap can never claim the strongest
        # (no-unresolved-deterministic-findings) conclusion without proof that nothing is missing.
        # A gap a later check cleared is history and never bounds it (issue #1017).
        if live_receipt_gap_codes(document):
            assert (
                document.conclusion is not ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
            ), (
                path,
                name,
            )


def test_rendered_text_is_no_stronger_than_document(fixture_loader: FixtureLoader) -> None:
    """The compact render matches the frozen fixture sentence and never uses a forbidden phrase."""

    exercised_rendered = False
    for path, name, variant in _iter_receipt_variants(fixture_loader):
        if "receipt_document" not in variant:
            # Rejected/malformed inputs never reach a receipt and therefore never render wording.
            assert variant.get("compact_markdown") is None, (path, name)
            continue

        document = _decode(variant)
        rendered = render_receipt_compact(document)
        expected_compact = variant.get("compact_markdown")
        if expected_compact is not None:
            assert rendered == expected_compact, (path, name)
            exercised_rendered = True

        haystacks = [rendered, *(section.body for section in document.sections)]
        for key in ("forbidden_claims", "forbidden_content"):
            forbidden = variant.get(key)
            if not forbidden:
                continue
            for phrase in cast(list[str], forbidden):
                for haystack in haystacks:
                    assert not _forbidden_phrase_is_asserted_positively(haystack, phrase), (
                        path,
                        name,
                        key,
                        phrase,
                        haystack,
                    )

    assert exercised_rendered, "no receipt fixture variant exercised the compact renderer"


def test_limitations_and_redactions_are_spelled_out(fixture_loader: FixtureLoader) -> None:
    """Weak coverage and redactions are always visible in the limitations section, never hidden."""

    for path, name, variant in _iter_receipt_variants(fixture_loader):
        if "receipt_document" not in variant:
            continue
        document = _decode(variant)

        # The document's declared coverage is always at least as weak as folding in every finding;
        # the receipt cannot claim stronger coverage than its own carried evidence supports.
        assert receipt_weakest_coverage(document) == document.coverage, (path, name)

        limitations = next(
            (
                section
                for section in document.sections
                if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
            ),
            None,
        )
        assert limitations is not None, (path, name)

        for gap_code in live_receipt_gap_codes(document):
            assert gap_code in limitations.body or gap_code in limitations.items, (
                path,
                name,
                gap_code,
            )
        # A historical gap is never listed as a current limitation, and is always rendered in
        # its own section in both human formats (issue #1017).
        for gap in historical_receipt_gaps(document):
            assert gap.code not in limitations.items, (path, name, gap.code)
            for markdown in (True, False):
                rendered = render_receipt_human(document, markdown=markdown)
                assert historical_gap_line(gap, markdown=markdown) in rendered, (path, name)
        if document.redactions:
            assert "redact" in limitations.body.lower() or document.coverage.known_gaps, (
                path,
                name,
            )

        # A document is never silently more visible than it claims: any recorded redaction count
        # is strictly positive (redactions never no-op).
        for redaction in document.redactions:
            assert redaction.count > 0, (path, name, redaction)


@pytest.mark.parametrize("path", _RECEIPT_FIXTURE_PATHS)
def test_every_receipt_fixture_file_is_reviewed_and_reachable(
    fixture_loader: FixtureLoader, path: str
) -> None:
    """Guard against a silently empty or unreachable receipt fixture undermining the suite."""

    variants = _variants(fixture_loader, path)
    assert variants, path
