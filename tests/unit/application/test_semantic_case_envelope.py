"""Envelope bounding for AI-powered review cases large enough to exercise it (dogfood run 2026-07-30).

The production failure was a 44 KiB structural envelope against a 16 KiB bound whose compaction
ladder could not reach it: the "last resort" truncated the item catalog to 64 rows, and a
``SemanticCase`` already admits at most 64 items. Nothing in the suite built a case big enough to
run that code, so four PRs shipped over it.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import cast

import pytest

from builders.large_semantic_cases import large_case
from yoetz.application import semantic_case as semantic_case_module
from yoetz.application.check import (
    CheckScope,
    allocate_findings,
    prior_finding_ids,
    run_deterministic_policies,
)
from yoetz.application.semantic_case import (
    REVIEW_PACKET_ITEM_ID,
    SemanticCaseTooLarge,
    bounded_case_envelope,
    build_semantic_case,
    semantic_case_to_candidate_context,
    semantic_case_to_prepared_payload,
)
from yoetz.domain.findings import Finding
from yoetz.domain.privacy import (
    MAX_EGRESS_ENVELOPE_BYTES,
    AuthorizationScope,
    AuthorizationScopeKind,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.ports.semantic import SemanticCase
from yoetz.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from yoetz.protocol.ids import IdKind, new_id

_SCOPE = AuthorizationScope(
    AuthorizationScopeKind.TASK,
    "ins_10000000-0000-4000-8000-000000000001",
    "hmac-sha256:" + "a" * 64,
    "tsk_10000000-0000-4000-8000-000000000001",
)
_BINDING = ProviderBinding("fireworks", "test-model", "chat-completions", "1", "external")


class _Ids:
    def new(self, kind: IdKind) -> str:
        return new_id(kind)


def _findings_for(case: DeterministicCase) -> tuple[Finding, ...]:
    assessments, _ = run_deterministic_policies(
        case,
        CheckScope((), ()),
        ("research-evidence/0.2.0", "work-integrity/0.3.0"),
    )
    return allocate_findings(
        _Ids(),
        tuple(item.candidate for item in assessments),
        prior_finding_ids(case.projection),
    )


def _semantic(profile: ReviewContextProfile, **kwargs: int) -> SemanticCase:
    case = large_case(**kwargs)
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=_findings_for(case),
        review_context_profile=profile,
        review_selection=ReviewSelectionPolicy.for_profile(profile),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )


def _parsed(envelope: bytes) -> Mapping[str, JsonValue]:
    document = strict_json_parse(envelope)
    assert isinstance(document, Mapping)
    return cast(Mapping[str, JsonValue], document)


def _original_reduction_states(case: SemanticCase) -> Iterator[bytes]:
    """The original greedy row-removal sequence, independent of the search algorithm."""
    module = semantic_case_module
    envelope = module._case_envelope_json(case)  # pyright: ignore[reportPrivateUsage]
    counts = {
        "assessment_links_stripped_count": 0,
        "catalog_dropped_count": 0,
        "change_observations_dropped_count": 0,
        "deterministic_assessments_dropped_count": 0,
        "omissions_dropped_count": 0,
        "targeted_excerpts_dropped_count": 0,
    }

    def encoded() -> bytes:
        module._set_selection_accounting(envelope, counts)  # pyright: ignore[reportPrivateUsage]
        return canonical_encode(envelope)

    yield encoded()
    counts["assessment_links_stripped_count"] += module._strip_assessment_links(envelope)  # pyright: ignore[reportPrivateUsage]
    yield encoded()
    packet = cast(dict[str, JsonValue], envelope["review_packet"])
    for key in (
        "change_observations",
        "targeted_excerpts",
        "omissions",
        "deterministic_assessments",
    ):
        values = packet.get(key)
        if type(values) is not list:
            continue
        rows = cast(list[JsonValue], values)
        while rows:
            rows = rows[:-1]
            packet[key] = rows
            counts[f"{key}_dropped_count"] += 1
            yield encoded()
    while module._drop_catalog_row(envelope):  # pyright: ignore[reportPrivateUsage]
        counts["catalog_dropped_count"] += 1
        yield encoded()


@pytest.mark.parametrize(
    "profile",
    [
        ReviewContextProfile.STRUCTURAL,
        ReviewContextProfile.GOAL_AWARE,
        ReviewContextProfile.ASSISTED,
        ReviewContextProfile.EXPANDED,
    ],
)
def test_bounding_matches_original_bytes_at_reduction_boundaries(
    monkeypatch: pytest.MonkeyPatch, profile: ReviewContextProfile
) -> None:
    case = _semantic(profile)
    states = tuple(_original_reduction_states(case))
    indices = {
        0,
        1,
        2,
        9,
        10,
        11,
        len(states) // 3,
        2 * len(states) // 3,
        len(states) - 2,
        len(states) - 1,
    }
    bounds = {
        len(states[index]) + delta
        for index in indices
        if index < len(states)
        for delta in (-1, 0, 1)
    }
    for bound in sorted(bounds):
        monkeypatch.setattr(semantic_case_module, "MAX_EGRESS_ENVELOPE_BYTES", bound)
        expected = next((state for state in states if len(state) <= bound), None)
        if expected is None:
            with pytest.raises(SemanticCaseTooLarge, match="semantic_case_envelope_too_large"):
                bounded_case_envelope(case)
        else:
            assert bounded_case_envelope(case) == expected


def test_packet_search_avoids_full_encode_per_removed_row(monkeypatch: pytest.MonkeyPatch) -> None:
    case = _semantic(ReviewContextProfile.EXPANDED)
    source = semantic_case_module._case_envelope_json(case)  # pyright: ignore[reportPrivateUsage]
    packet = cast(dict[str, JsonValue], source["review_packet"])
    packet["change_observations"] = [{"note": "synthetic" * 100} for _ in range(64)]

    def envelope_for(_case: SemanticCase) -> dict[str, JsonValue]:
        return source

    monkeypatch.setattr(semantic_case_module, "_case_envelope_json", envelope_for)
    states = tuple(_original_reduction_states(case))
    # The independent oracle mutated its private envelope; supply a fresh copy for production.
    source = cast(dict[str, JsonValue], strict_json_parse(states[0]))
    bound = len(states[34])
    expected = next(state for state in states if len(state) <= bound)
    monkeypatch.setattr(semantic_case_module, "MAX_EGRESS_ENVELOPE_BYTES", bound)
    calls = 0

    def counting_encode(value: JsonValue) -> bytes:
        nonlocal calls
        calls += 1
        return canonical_encode(value)

    monkeypatch.setattr(semantic_case_module, "canonical_encode", counting_encode)
    assert bounded_case_envelope(case) == expected
    assert calls <= 10


@pytest.mark.parametrize(
    "profile",
    [
        ReviewContextProfile.STRUCTURAL,
        ReviewContextProfile.GOAL_AWARE,
        ReviewContextProfile.ASSISTED,
        ReviewContextProfile.EXPANDED,
    ],
)
def test_large_case_envelope_is_bounded_for_every_profile(profile: ReviewContextProfile) -> None:
    """The case that killed the dogfood run now builds — on every profile, including the widest.

    Raising the review profile to disclose more used to make failure *more* likely, because the
    extra excerpts and id arrays grew the same over-tight envelope.
    """

    envelope = bounded_case_envelope(_semantic(profile))
    assert len(envelope) <= MAX_EGRESS_ENVELOPE_BYTES


def test_large_case_reproduces_the_production_envelope_size() -> None:
    """Pin that the builder really does produce a case of the failing magnitude."""

    envelope = bounded_case_envelope(_semantic(ReviewContextProfile.EXPANDED))
    # The old bound was 16 KiB. If this ever drops below it the builder has stopped reproducing
    # the shape that broke production and these tests would pass vacuously.
    assert len(envelope) > 16_384


def test_bounding_is_deterministic() -> None:
    """Two builds of one case must produce byte-identical envelopes.

    The envelope is digest-bound and replayed across attempts, so any nondeterminism here would
    change the provider payload for the same ``case_digest``.
    """

    semantic = _semantic(ReviewContextProfile.EXPANDED)
    assert bounded_case_envelope(semantic) == bounded_case_envelope(semantic)


def test_unbounded_case_reports_no_minimization() -> None:
    """A case that fits is never marked as minimized."""

    envelope = _parsed(bounded_case_envelope(_semantic(ReviewContextProfile.STRUCTURAL)))
    accounting = envelope["selection_accounting"]
    assert isinstance(accounting, Mapping)
    assert cast(Mapping[str, JsonValue], accounting)["catalog_dropped_count"] == "0"
    assert cast(Mapping[str, JsonValue], accounting)["reason"] == "not_minimized"


def test_non_catalog_reduction_is_reported_as_minimization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing assessment links must be visible even when no catalog row is dropped."""

    import yoetz.application.semantic_case as module

    semantic = _semantic(ReviewContextProfile.EXPANDED)
    original = bounded_case_envelope(semantic)
    monkeypatch.setattr(module, "MAX_EGRESS_ENVELOPE_BYTES", len(original) - 1)
    envelope = bounded_case_envelope(semantic)

    assert len(envelope) <= len(original) - 1
    accounting = cast(Mapping[str, JsonValue], _parsed(envelope)["selection_accounting"])
    assert int(cast(str, accounting["assessment_links_stripped_count"])) > 0
    assert accounting["catalog_dropped_count"] == "0"
    assert accounting["reason"] == "size_minimized"


def test_minimization_terminates_and_is_accounted_under_a_tiny_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under extreme pressure the reducer terminates and says what it dropped.

    The old ladder had a fixed three stages and simply raised when they were not enough. This
    asserts the property that matters: the result fits, and every catalog row it removed is
    counted rather than silently vanishing.
    """

    import yoetz.application.semantic_case as module

    monkeypatch.setattr(module, "MAX_EGRESS_ENVELOPE_BYTES", 8_192)
    semantic = _semantic(ReviewContextProfile.EXPANDED)
    envelope = bounded_case_envelope(semantic)

    assert len(envelope) <= 8_192
    document = _parsed(envelope)
    accounting = cast(Mapping[str, JsonValue], document["selection_accounting"])
    dropped = int(cast(str, accounting["catalog_dropped_count"]))
    assert dropped > 0
    assert accounting["reason"] == "size_minimized"
    catalog = document["item_catalog"]
    assert isinstance(catalog, list)
    assert dropped + len(cast(list[object], catalog)) == len(semantic.items)


def test_minimization_never_leaves_a_dangling_item_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No packet id may reference an item the catalog no longer carries."""

    import yoetz.application.semantic_case as module

    monkeypatch.setattr(module, "MAX_EGRESS_ENVELOPE_BYTES", 8_192)
    document = _parsed(bounded_case_envelope(_semantic(ReviewContextProfile.EXPANDED)))

    catalog = cast(list[object], document["item_catalog"])
    catalogued = {
        cast(str, cast(Mapping[str, JsonValue], row)["item_id"])
        for row in catalog
        if isinstance(row, Mapping)
    }
    packet = cast(Mapping[str, JsonValue], document["review_packet"])
    for key in (
        "goal_item_ids",
        "obligation_item_ids",
        "claim_item_ids",
        "decision_item_ids",
        "timeline_item_ids",
    ):
        for item_id in cast(list[object], packet[key]):
            assert item_id in catalogued, f"{key} references an uncatalogued item"
    for row in cast(list[object], packet["targeted_excerpts"]):
        assert isinstance(row, Mapping)
        assert cast(Mapping[str, JsonValue], row)["excerpt_item_id"] in catalogued


def test_candidate_context_offers_only_catalogued_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Content whose catalog row was dropped must not be offered for authorization.

    Offering it would get it privacy-approved and then silently discarded during assembly, so the
    packet would claim coverage of material the provider never saw.
    """

    import yoetz.application.semantic_case as module

    monkeypatch.setattr(module, "MAX_EGRESS_ENVELOPE_BYTES", 8_192)
    semantic = _semantic(ReviewContextProfile.EXPANDED)
    candidate = semantic_case_to_candidate_context(
        semantic,
        request_id="req_10000000-0000-4000-8000-000000000001",
        scope=_SCOPE,
        provider_binding=_BINDING,
    )

    envelope_item = next(item for item in candidate.items if item.item_id == REVIEW_PACKET_ITEM_ID)
    catalogued = {
        cast(str, cast(Mapping[str, JsonValue], row)["item_id"])
        for row in cast(list[object], _parsed(envelope_item.plaintext)["item_catalog"])
        if isinstance(row, Mapping)
    }
    offered = {item.item_id for item in candidate.items} - {REVIEW_PACKET_ITEM_ID}
    assert offered == catalogued
    assert len(offered) < len(semantic.items)


def test_prepared_payload_matches_the_authorized_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The provider document must describe exactly what privacy was asked to approve."""

    import yoetz.application.semantic_case as module

    monkeypatch.setattr(module, "MAX_EGRESS_ENVELOPE_BYTES", 8_192)
    semantic = _semantic(ReviewContextProfile.EXPANDED)
    candidate = semantic_case_to_candidate_context(
        semantic,
        request_id="req_10000000-0000-4000-8000-000000000001",
        scope=_SCOPE,
        provider_binding=_BINDING,
    )
    approved = {item.item_id for item in candidate.items}
    document = _parsed(semantic_case_to_prepared_payload(semantic, approved))

    carried = {
        cast(str, cast(Mapping[str, JsonValue], row)["item_id"])
        for row in cast(list[object], document["items"])
        if isinstance(row, Mapping)
    }
    assert carried == approved - {REVIEW_PACKET_ITEM_ID}
    packet = cast(Mapping[str, JsonValue], document["review_packet"])
    for raw in cast(list[object], packet["deterministic_assessments"]):
        assert isinstance(raw, Mapping)
        row = cast(Mapping[str, JsonValue], raw)
        for key in ("summary_item_id", "detail_item_id"):
            linked = row.get(key)
            if linked is not None:
                assert linked in carried
    accounting = cast(Mapping[str, JsonValue], document["selection_accounting"])
    assert int(cast(str, accounting["catalog_dropped_count"])) > 0
    # Nothing was approved that the document could not carry.
    assert accounting["uncatalogued_approved_count"] == "0"


def test_irreducible_core_raises_a_typed_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """When even the core cannot fit, the caller gets a typed terminal, not a bare ValueError.

    ``SemanticCaseTooLarge`` is what lets the coordinator record an honest terminal outcome
    instead of treating the case as an unexpected coordinator fault.
    """

    import yoetz.application.semantic_case as module

    monkeypatch.setattr(module, "MAX_EGRESS_ENVELOPE_BYTES", 1)
    with pytest.raises(SemanticCaseTooLarge):
        bounded_case_envelope(_semantic(ReviewContextProfile.STRUCTURAL))


def test_non_ascii_ledger_content_still_builds_a_case() -> None:
    """An em dash must not stop the AI-powered review.

    ``canonical_encode`` emits UTF-8 without escaping non-ASCII, but the case builder decoded it
    as ASCII. One curly quote, em dash or accented character anywhere in a plan, obligation or
    claim therefore raised UnicodeDecodeError while building the case, which the coordinator
    surfaced as ``coordinator_failure`` with no AI-powered review at all. A live dogfood run hit
    this within minutes; agents write these characters constantly.
    """

    case = large_case(obligation_count=3, claim_count=2, evidence_count=2)
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=_findings_for(case),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )
    assert bounded_case_envelope(semantic)


@pytest.mark.parametrize(
    "text",
    [
        "plan — with an em dash",
        "the user’s curly apostrophe",
        "café; naïve; résumé",
        "ship it 🚀",
    ],
)
def test_bounded_json_round_trips_non_ascii(text: str) -> None:
    """Every character class an agent realistically writes must survive encoding."""

    from yoetz.application import semantic_case as module

    value = {"text": text}
    encoded, fit = module._bounded_json(value)  # pyright: ignore[reportPrivateUsage]
    assert fit == "whole"
    assert text in encoded
    assert text in module._structural_json(value)  # pyright: ignore[reportPrivateUsage]
