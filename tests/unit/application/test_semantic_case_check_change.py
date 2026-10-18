"""The service-captured check-time change in the pure case builder (ADR-031, issue #883)."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from builders.policy_cases import (
    clm,
    evd,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
)
from finishup.application.semantic_case import (
    CHECK_TIME_CHANGE_ITEM_PREFIX,
    CapturedContentScope,
    CapturedSemanticContent,
    CheckTimeChange,
    CheckTimeChangeShownFile,
    build_semantic_case,
    check_time_change_bytes_carried,
    check_time_change_parts_carried,
    check_time_change_sections_carried,
    check_time_change_shown_files,
    check_time_change_shown_record,
    semantic_case_to_prepared_payload,
)
from finishup.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,
    CHECK_TIME_CHANGE_REDACTED_GAP,
    CHECK_TIME_CHANGE_TRUNCATED_GAP,
    CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
)
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.ports.change_capture import (
    CHECK_CHANGE_MEDIA_TYPE,
    ChangeBaseKind,
    CheckChangeCapture,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from finishup.ports.semantic import SemanticCase
from finishup.protocol.canonical import strict_json_parse
from finishup.protocol.coverage import LedgerFreshness
from unit.application.test_semantic_case import (
    _captured_case_values,  # pyright: ignore[reportPrivateUsage]
    _case_with_material,  # pyright: ignore[reportPrivateUsage]
)

_TASK = "tsk_10000000-0000-4000-8000-000000000001"


def _change(
    text: bytes = b"diff --git a/selectors.ts b/selectors.ts\n+kea-repair-marker\n",
    *,
    base: ChangeBaseKind = "task_start",
    truncated: bool = False,
    redacted: bool = False,
    object_suffix: str = "901",
) -> CheckTimeChange:
    return CheckTimeChange(
        ObjectRef(
            object_id=f"obj_00000000-0000-4000-8000-000000000{object_suffix}",
            plaintext_size=len(text) + 100,
            commitment="hmac-sha256:" + "9" * 64,
            envelope_digest="sha256:" + "a" * 64,
            encryption_format="yoetz-object/1",
            key_slot="task",
            metadata=ObjectMetadata(
                ObjectKind.CHANGE_CAPTURE,
                CHECK_CHANGE_MEDIA_TYPE,
                _TASK,
                datetime(2026, 9, 29, tzinfo=UTC),
            ),
        ),
        CheckChangeCapture(
            base=base,
            text=text,
            tracked_files=1,
            untracked_files=0,
            omitted_files=1 if truncated else 0,
            truncated=truncated,
            redacted=redacted,
        ),
    )


def _build(
    case: DeterministicCase,
    profile: ReviewContextProfile = ReviewContextProfile.EXPANDED,
    *,
    change: CheckTimeChange | None = None,
    unavailable: bool = False,
    selection: ReviewSelectionPolicy | None = None,
    captured: Sequence[CapturedSemanticContent] = (),
    scope: CapturedContentScope | None = None,
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=profile,
        # The 1.1.0 presets (16 Expanded excerpts): these cases pin the ADR-031 reservation and
        # backfill arithmetic, which the 1.2.0 Expanded count of 64 (#907 Phase 1b) would change.
        review_selection=selection
        or ReviewSelectionPolicy.for_profile(profile, preset_version="1.1.0"),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=captured,
        captured_content_scope=scope,
        check_time_change=change,
        check_time_change_unavailable=unavailable,
    )


def _change_items(case: SemanticCase) -> list[str]:
    return [
        item.excerpt_item_id
        for item in case.packet.targeted_excerpts
        if item.excerpt_item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    ]


def _large_change(parts: int) -> bytes:
    line = b"+" + b"x" * 99 + b"\n"
    return line * (40 * parts)


def test_change_is_the_first_excerpt_linked_to_claims_and_obligations() -> None:
    case = _case_with_material(with_evidence=True)

    semantic = _build(case, change=_change())

    first = semantic.packet.targeted_excerpts[0]
    assert first.excerpt_item_id == f"{CHECK_TIME_CHANGE_ITEM_PREFIX}001"
    assert first.source_kind == "diff"
    assert first.linked_subject_refs == (str(clm(1)), str(obl(1)))
    item = next(item for item in semantic.items if item.item_id == first.excerpt_item_id)
    content = item.content.decode("utf-8")
    assert content.startswith("[FinishUP check-time change, part 1 of 1]\n")
    assert "+kea-repair-marker" in content
    assert not {
        CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,
        CHECK_TIME_CHANGE_TRUNCATED_GAP,
        CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
    } & set(semantic.packet.coverage.known_gaps)
    # The provider document lists items in section and recorded order (#907); the change is the
    # first excerpt row it carries.
    prepared = strict_json_parse(
        semantic_case_to_prepared_payload(semantic, {item.item_id for item in semantic.items})
    )
    assert isinstance(prepared, dict)
    rows = cast(list[dict[str, object]], prepared["items"])
    excerpt_rows = [row for row in rows if row.get("section") == "excerpt"]
    assert excerpt_rows[0]["item_id"] == first.excerpt_item_id


def test_reserved_share_holds_against_competing_captures_and_backfills_free_room() -> None:
    # Issue #983 deliberately replaced the 4 KiB parts (16 slots, 15 parts) this case locked: a
    # part is now one 16 KiB excerpt, and the parts the reservation could not hold take the room
    # ahead of unreserved tool output, which still gets the bytes left after them.
    case, captured, scope = _captured_case_values(b"competing-tool-output-marker")
    change = _change(_large_change(40))

    semantic = _build(case, change=change, captured=(captured,), scope=scope)

    change_ids = _change_items(semantic)
    excerpt_ids = [item.excerpt_item_id for item in semantic.packet.targeted_excerpts]
    # Four 16 KiB parts are the reserved half of the 128 KiB budget, four more take the room the
    # unreserved capture would otherwise have taken, and the capture still fits what is left.
    assert (
        excerpt_ids[:8]
        == change_ids
        == [f"{CHECK_TIME_CHANGE_ITEM_PREFIX}{index:03d}" for index in range(1, 9)]
    )
    assert excerpt_ids[8:] == [f"excerpt-{evd(1)}"]
    assert all(
        16_000 < item.content_bytes <= 16_384 for item in semantic.packet.targeted_excerpts[:8]
    )
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP in semantic.packet.coverage.known_gaps
    assert semantic.packet.coverage.ledger_freshness is LedgerFreshness.PARTIAL
    last = next(item for item in semantic.items if item.item_id == change_ids[-1])
    assert last.content.startswith(b"[FinishUP check-time change, part 8 of 10]")


def test_small_change_leaves_its_unused_reservation_to_other_excerpts() -> None:
    case, captured, scope = _captured_case_values(b"competing-tool-output-marker")

    semantic = _build(case, change=_change(), captured=(captured,), scope=scope)

    assert [item.excerpt_item_id for item in semantic.packet.targeted_excerpts] == [
        f"{CHECK_TIME_CHANGE_ITEM_PREFIX}001",
        f"excerpt-{evd(1)}",
    ]
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP not in semantic.packet.coverage.known_gaps


@pytest.mark.parametrize(
    ("change", "gap"),
    (
        (_change(base="head"), CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP),
        (_change(truncated=True), CHECK_TIME_CHANGE_TRUNCATED_GAP),
        (_change(redacted=True), CHECK_TIME_CHANGE_REDACTED_GAP),
    ),
)
def test_capture_limits_are_disclosed_on_packet_coverage(change: CheckTimeChange, gap: str) -> None:
    semantic = _build(_case_with_material(), change=change)

    assert gap in semantic.packet.coverage.known_gaps
    assert semantic.packet.coverage.ledger_freshness is LedgerFreshness.PARTIAL
    assert _change_items(semantic)


def test_unavailable_capture_is_disclosed_without_any_item() -> None:
    semantic = _build(_case_with_material(), unavailable=True)

    assert CHECK_TIME_CHANGE_UNAVAILABLE_GAP in semantic.packet.coverage.known_gaps
    assert not _change_items(semantic)


def test_change_without_a_linkable_subject_is_disclosed_unavailable() -> None:
    semantic = _build(make_case(), change=_change())

    assert CHECK_TIME_CHANGE_UNAVAILABLE_GAP in semantic.packet.coverage.known_gaps
    assert "check_time_change_unavailable_no_linked_subject" in (
        semantic.packet.coverage.known_gaps
    )
    assert not _change_items(semantic)


def test_plan_is_the_fallback_link_when_no_claim_or_obligation_exists() -> None:
    plan = plan_record(PlanPublishedPayload(1, "Repair selectors", ()), 1)
    case = make_case(plans={1: plan}, extra_refs=(plan.source_event_id,))

    semantic = _build(case, change=_change())

    assert semantic.packet.targeted_excerpts[0].linked_subject_refs == (str(plan.source_event_id),)


@pytest.mark.parametrize(
    "profile", (ReviewContextProfile.STRUCTURAL, ReviewContextProfile.GOAL_AWARE)
)
def test_recipe_without_diff_excerpts_carries_nothing_and_reports_nothing(
    profile: ReviewContextProfile,
) -> None:
    case = _case_with_material()
    baseline = _build(case, profile)

    for semantic in (
        _build(case, profile, change=_change()),
        _build(case, profile, unavailable=True),
    ):
        assert not _change_items(semantic)
        assert semantic.packet.coverage == baseline.packet.coverage
        assert semantic.case_digest == baseline.case_digest


def test_custom_recipe_without_the_diff_kind_carries_nothing() -> None:
    expanded = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    selection = replace(
        expanded, excerpt_kinds=tuple(kind for kind in expanded.excerpt_kinds if kind != "diff")
    )
    case = _case_with_material()

    semantic = _build(case, ReviewContextProfile.CUSTOM, change=_change(), selection=selection)

    assert not _change_items(semantic)
    assert CHECK_TIME_CHANGE_UNAVAILABLE_GAP not in semantic.packet.coverage.known_gaps


def test_case_digest_binds_the_change_and_is_unchanged_without_one() -> None:
    case = _case_with_material()
    without = _build(case)

    first = _build(case, change=_change(b"+first\n"))
    second = _build(case, change=_change(b"+second\n"))

    assert without.case_digest != first.case_digest != second.case_digest
    assert _build(case, change=_change(b"+first\n")).case_digest == first.case_digest
    assert _build(case).case_digest == without.case_digest


def test_parts_split_on_lines_and_stay_within_one_item() -> None:
    text = b"".join(f"+line {index:05d} {'y' * 40}\n".encode() for index in range(1_200))

    semantic = _build(_case_with_material(), change=_change(text))

    items = [
        item for item in semantic.items if item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    ]
    assert len(items) > 1
    joined = b""
    for index, item in enumerate(items, start=1):
        # One excerpt's bound (issue #983), no longer the 4 KiB structural prose bound.
        assert item.content_bytes <= 16_384
        header, _, body = item.content.partition(b"\n")
        assert header == f"[FinishUP check-time change, part {index} of {len(items)}]".encode()
        assert body.endswith(b"\n")
        joined += body
    assert joined == text


def test_obligation_only_case_links_the_change_to_the_obligation() -> None:
    obligation = obligation_record(
        ObligationPublishedPayload(obl(1), "Repair", "tests pass", ObligationStatus.OPEN), 1
    )
    claim = record(ClaimRecordedPayload(clm(2), ClaimKind.MATERIAL, "Working", ()), 2)
    case = make_case(
        obligations={obl(1): obligation},
        claims={clm(2): claim},
        extra_refs=(obl(1), clm(2)),
    )

    semantic = _build(case, change=_change())

    assert semantic.packet.targeted_excerpts[0].linked_subject_refs == (str(clm(2)), str(obl(1)))


def test_value_rejects_objects_that_are_not_check_change_captures() -> None:
    valid = _change()
    wrong_kind = replace(
        valid.object_ref,
        metadata=replace(valid.object_ref.metadata, kind=ObjectKind.CAPTURED_CONTENT),
    )
    with pytest.raises(ValueError, match="semantic_case_check_change_invalid"):
        CheckTimeChange(wrong_kind, valid.capture)
    with pytest.raises(ValueError, match="semantic_case_check_change_invalid"):
        _build(_case_with_material(), change=valid, unavailable=True)


def _section(path: str, lines: int, *, fill: str = "x") -> bytes:
    head = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1,{lines} @@\n"
    return head.encode() + b"".join(f"+{fill * 60} {index}\n".encode() for index in range(lines))


def test_shown_files_follow_the_admitted_parts_and_redaction() -> None:
    """Whole, cut at the packet boundary, redacted, and never reached (ADR-031 resolution)."""

    header = b"FinishUP check-time change: header\nFiles:\n  M listed-only.ts\nEnd of header.\n"
    text = (
        header
        + _section("whole.ts", 3)
        + _section("redacted.ts", 2).replace(b"x" * 60, b"[REDACTED]" + b"x" * 50, 1)
        # Larger than the whole 128 KiB excerpt budget now that a part is 16 KiB (issue #983).
        + _section("cut.ts", 2_100)
        + _section("never.ts", 200)
    )
    change = _change(text)
    case = _build(_case_with_material(), change=change)
    admitted = len(_change_items(case))
    shown_bytes = sum(len(chunk) for chunk in _check_time_change_chunks(text)[:admitted])
    assert check_time_change_bytes_carried(case) == shown_bytes

    files = check_time_change_shown_files(change.capture, shown_bytes)

    whole_len = len(_section("whole.ts", 3))
    redacted_len = len(_section("redacted.ts", 2))
    cut_start = len(header) + whole_len + redacted_len
    redacted_marker = text.index(b"[REDACTED]") - (len(header) + whole_len)
    assert [
        (
            file.identity.decode(),
            file.whole,
            file.shown_bytes,
            file.redactions,
            file.section_admitted,
            file.clean_bytes,
        )
        for file in files
    ][:3] == [
        ("diff --git a/whole.ts b/whole.ts", True, whole_len, 0, True, whole_len),
        # Wholly admitted but redacted: everything shown counts, and so does the span.
        (
            "diff --git a/redacted.ts b/redacted.ts",
            False,
            redacted_len,
            1,
            True,
            redacted_marker,
        ),
        (
            "diff --git a/cut.ts b/cut.ts",
            False,
            shown_bytes - cut_start,
            0,
            False,
            shown_bytes - cut_start,
        ),
    ]
    assert all(b"never.ts" not in identity for identity, *_ in files)
    assert all(b"listed-only" not in identity for identity, *_ in files)
    # With every part admitted the whole unredacted change is fully shown.
    everything = check_time_change_shown_files(change.capture, len(text))
    assert {identity: whole for identity, whole, *_ in everything}[
        b"diff --git a/never.ts b/never.ts"
    ] is True
    assert check_time_change_shown_files(change.capture, 0) == ()


def test_many_changed_files_record_only_the_few_the_packet_showed() -> None:
    """More than 128 changed files: only shown files count toward the record bound."""

    header = b"FinishUP check-time change: header\nEnd of header.\n"
    text = header + b"".join(_section(f"generated/{index:03d}.ts", 20) for index in range(140))
    change = _change(text)
    case = _build(_case_with_material(), change=change)

    files = check_time_change_shown_files(change.capture, check_time_change_bytes_carried(case))

    assert 0 < len(files) < 128
    assert sum(whole for _, whole, *_ in files) == len(files) - 1  # one straddles the edge


def _check_time_change_chunks(text: bytes) -> tuple[bytes, ...]:
    from finishup.application import semantic_case as module

    selection = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    chunks = getattr(module, "_check_time_change_chunks")
    limit = getattr(module, "_check_time_change_part_limit")(selection)
    return cast(tuple[bytes, ...], chunks(text, limit))


def _tight_custom_selection() -> ReviewSelectionPolicy:
    """A legal custom recipe whose half-byte share (3000) is smaller than one 4 KiB part."""

    expanded = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    return replace(expanded, max_excerpts=4, max_excerpt_bytes=4_096, max_total_excerpt_bytes=6_000)


@pytest.mark.parametrize("parts", (1, 3))
def test_reservation_admits_one_whole_part_even_when_half_the_bytes_is_smaller(
    parts: int,
) -> None:
    # R945-01: the reserved share must hold at least one part, or an ordinary excerpt consumes
    # the budget first and a captured change is reported unavailable.
    line = b"+" + b"z" * 99 + b"\n"
    text = line * (39 * parts)
    case, captured, scope = _captured_case_values(b"competing-output " + b"q" * 3_880)
    selection = _tight_custom_selection()

    semantic = _build(
        case,
        ReviewContextProfile.CUSTOM,
        change=_change(text),
        selection=selection,
        captured=(captured,),
        scope=scope,
    )

    change_ids = _change_items(semantic)
    assert change_ids, "a captured change that fits the recipe must reach the packet"
    assert semantic.packet.targeted_excerpts[0].excerpt_item_id == change_ids[0]
    gaps = set(semantic.packet.coverage.known_gaps)
    assert CHECK_TIME_CHANGE_UNAVAILABLE_GAP not in gaps
    assert (CHECK_TIME_CHANGE_TRUNCATED_GAP in gaps) is (parts > 1)
    used = sum(item.content_bytes for item in semantic.packet.targeted_excerpts)
    assert used <= selection.max_total_excerpt_bytes


def test_parts_never_exceed_a_total_excerpt_budget_smaller_than_one_excerpt() -> None:
    expanded = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    selection = replace(
        expanded, max_excerpts=4, max_excerpt_bytes=16_384, max_total_excerpt_bytes=1_500
    )

    semantic = _build(
        _case_with_material(),
        ReviewContextProfile.CUSTOM,
        change=_change(_large_change(1)),
        selection=selection,
    )

    change_ids = _change_items(semantic)
    assert change_ids
    assert CHECK_TIME_CHANGE_UNAVAILABLE_GAP not in semantic.packet.coverage.known_gaps
    used = sum(item.content_bytes for item in semantic.packet.targeted_excerpts)
    assert used <= selection.max_total_excerpt_bytes


def test_parts_carried_are_counted_from_the_bounded_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # R945-06: the shown-file record must describe what the provider-facing envelope carries,
    # not the case before envelope minimization dropped catalog rows.
    import finishup.application.semantic_case as semantic_case_module

    # Seven 16 KiB parts (issue #983; the case locked twelve 4 KiB parts before).
    semantic = _build(_case_with_material(), change=_change(_large_change(28)))
    admitted = len(_change_items(semantic))
    assert admitted == 7
    assert check_time_change_parts_carried(semantic) == admitted
    assert check_time_change_parts_carried(semantic, withheld_categories=("claim_text",)) == 7

    # Primary material leads the case (n7 RC7, #1108), so bounding drops the timeline and the
    # agent's account before any change part: the cap is small enough to reach the parts.
    monkeypatch.setattr(semantic_case_module, "MAX_EGRESS_ENVELOPE_BYTES", 6_000)
    carried = check_time_change_parts_carried(semantic)
    assert 0 < carried < admitted
    envelope = strict_json_parse(semantic_case_module.bounded_case_envelope(semantic))
    assert isinstance(envelope, dict)
    catalog = {
        cast(dict[str, object], row)["item_id"]
        for row in cast(list[object], envelope["item_catalog"])
    }
    # Every non-excerpt row went before the first change part did.
    sections = {item.item_id: item.section for item in semantic.items}
    assert {sections[cast(str, item_id)] for item_id in catalog} == {"excerpt"}
    assert {f"{CHECK_TIME_CHANGE_ITEM_PREFIX}{index:03d}" for index in range(1, carried + 1)} <= (
        catalog
    )
    assert f"{CHECK_TIME_CHANGE_ITEM_PREFIX}{carried + 1:03d}" not in catalog


def test_parts_carried_is_zero_when_the_channel_withholds_repository_excerpts() -> None:
    semantic = _build(_case_with_material(), change=_change())

    assert check_time_change_parts_carried(semantic) == 1
    assert (
        check_time_change_parts_carried(semantic, withheld_categories=("repository_excerpt",)) == 0
    )


@pytest.mark.parametrize(
    "reason", ("unsafe_root", "unsupported_repository", "changed_during_capture", "git_failed")
)
def test_unavailable_reason_is_disclosed_beside_the_generic_code_and_bound_to_the_case(
    reason: str,
) -> None:
    case = _case_with_material()
    generic = _build(case, unavailable=True)

    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        check_time_change_unavailable=True,
        check_time_change_unavailable_reason=reason,
    )

    gaps = set(semantic.packet.coverage.known_gaps)
    assert {CHECK_TIME_CHANGE_UNAVAILABLE_GAP, f"check_time_change_unavailable_{reason}"} <= gaps
    assert semantic.case_digest != generic.case_digest


def test_every_adapter_reason_has_a_closed_sentence() -> None:
    from finishup.domain.receipts import (
        CHECK_TIME_CHANGE_UNAVAILABLE_REASONS,
        check_time_change_gap_sentence,
        check_time_change_unavailable_reason_gap,
    )
    from finishup.ports.change_capture import CHANGE_CAPTURE_UNAVAILABLE_REASONS

    assert CHANGE_CAPTURE_UNAVAILABLE_REASONS <= set(CHECK_TIME_CHANGE_UNAVAILABLE_REASONS)
    for reason in CHECK_TIME_CHANGE_UNAVAILABLE_REASONS:
        sentence = check_time_change_gap_sentence(check_time_change_unavailable_reason_gap(reason))
        assert sentence is not None and sentence.isascii() and sentence.endswith(".")
    assert check_time_change_gap_sentence(CHECK_TIME_CHANGE_UNAVAILABLE_GAP) is None
    with pytest.raises(ValueError):
        check_time_change_unavailable_reason_gap("not_a_reason")


def _view_of(text: bytes) -> CheckTimeChangeShownFile:
    change = _change(text).capture
    (file,) = check_time_change_shown_files(change, len(text))
    return file


_SECTION = (
    b"diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
    b"@@ -1,3 +1,3 @@ def handler():\n"
    b" keep = 1\n-token = [REDACTED]\n+value = 2\n"
    b"@@ -20,2 +20,2 @@ def other():\n"
    b"-old = 3\n+new = 4\n"
)


def test_view_binds_where_redactions_and_hunks_lie_not_only_their_counts() -> None:
    """R945-02: equal lengths and counts, different positions, different views."""

    base = _view_of(_SECTION)
    moved_marker = _view_of(
        _SECTION.replace(b"-token = [REDACTED]\n+value = 2\n", b"-token = 1\n+value = [REDACTED]\n")
    )
    moved_hunk = _view_of(_SECTION.replace(b"@@ -20,2 +20,2 @@", b"@@ -40,2 +40,2 @@"))

    assert base.redactions == moved_marker.redactions == 1
    assert base.shown_bytes == moved_marker.shown_bytes == moved_hunk.shown_bytes
    assert base.view != moved_marker.view
    assert base.view != moved_hunk.view
    assert _view_of(_SECTION).view == base.view
    assert b"token" not in base.view and b"value" not in base.view  # structure, not lines


def test_the_possible_credential_placeholder_counts_as_a_redaction_like_redacted() -> None:
    """tb4n5: capture-time redaction marks a look-alike value with the placeholder; the shown-file
    record must still see a withheld span, so the file is never ``whole`` and its view binds it.
    A change holding ``[REDACTED]`` only (stored before the placeholder) keeps its exact view."""

    placeholder = _SECTION.replace(b"[REDACTED]", b"[withheld-by-yoetz:possible-credential]")
    both = placeholder.replace(b"+new = 4\n", b"+new = [REDACTED]\n")

    legacy = _view_of(_SECTION)
    marked = _view_of(placeholder)
    mixed = _view_of(both)

    assert not marked.whole and marked.redactions == 1
    assert marked.clean_bytes == placeholder.index(b"[withheld-by-yoetz")
    assert not mixed.whole and mixed.redactions == 2
    assert mixed.clean_bytes == marked.clean_bytes
    assert len({legacy.view, marked.view, mixed.view}) == 3
    # The pre-existing record is byte-for-byte what it was: one [REDACTED] at the same offset.
    assert legacy.redactions == 1 and legacy.clean_bytes == _SECTION.index(b"[REDACTED]")
    # A placeholder cut by the packet edge still counts: part of the withheld span was shown.
    edge = placeholder.index(b"[withheld-by-yoetz") + 5
    (cut,) = check_time_change_shown_files(_change(placeholder).capture, edge)
    assert cut.redactions == 1 and cut.clean_bytes == edge - 5


@pytest.mark.anyio
async def test_partial_files_record_a_keyed_view_commitment_never_the_view() -> None:
    from finishup.application.check_change import check_change_shown_files

    commitments: list[bytes] = []

    class _Objects:
        async def commitment_for(self, data: bytes, kind: object) -> str:
            commitments.append(data)
            return "hmac-sha256:" + hashlib.sha256(data).hexdigest()

    class _Runtime:
        objects = _Objects()

    change = _change(_SECTION)
    change = CheckTimeChange(
        change.object_ref, replace(change.capture, base_commit="a" * 40, redacted=True)
    )

    files = await check_change_shown_files(cast(Any, _Runtime()), change, len(_SECTION))

    (partial,) = files.partially_shown
    assert partial.view_commitment is not None
    assert partial.view_commitment != partial.commitment
    assert any(data.startswith(b"yoetz/check-change-shown-view/v1\x00") for data in commitments)


def test_shown_file_views_come_from_exactly_the_carried_envelope_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R945-02/R945-06: views and accounting share one source, the parts the envelope kept."""

    import finishup.application.semantic_case as semantic_case_module

    text = b"".join(
        _SECTION.replace(b"app.py", f"app{index:03d}.py".encode()) for index in range(300)
    )
    change = _change(text)
    semantic = _build(_case_with_material(), change=change)
    # The agent's rows and the timeline yield first (#1108), so this cap reaches the change parts.
    monkeypatch.setattr(semantic_case_module, "MAX_EGRESS_ENVELOPE_BYTES", 6_000)
    carried = check_time_change_parts_carried(semantic)
    assert 0 < carried < len(_change_items(semantic))
    envelope = strict_json_parse(semantic_case_module.bounded_case_envelope(semantic))
    assert isinstance(envelope, dict)
    catalog = {
        cast(dict[str, object], row)["item_id"]
        for row in cast(list[object], envelope["item_catalog"])
    }
    carried_text = b"".join(
        item.content.partition(b"\n")[2]
        for item in sorted(semantic.items, key=lambda item: item.item_id)
        if item.item_id in catalog and item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    )

    shown = check_time_change_shown_files(change.capture, check_time_change_bytes_carried(semantic))

    assert carried_text == text[: len(carried_text)]
    assert sum(file.shown_bytes for file in shown) == len(carried_text)


# --- Issue #983: larger parts and the room the reserved excerpt classes leave -------------------


def _cracker_change(table_rows: int = 900) -> bytes:
    """One new ~140 KiB source file with an embedded numeric table (the tb4n1 cracker.py shape)."""

    head = (
        b"FinishUP check-time change: header\nFiles:\n  A cracker.py untracked\nEnd of header.\n"
        b"diff --git a/cracker.py b/cracker.py\nnew file mode 100644\n--- /dev/null\n"
        b"+++ b/cracker.py\n@@ -0,0 +1,2400 @@\n"
    )
    code = b"".join(
        f"+def step_{index}(state):\n+    return (state * {index} + 7) % 97\n".encode()
        for index in range(300)
    )
    table = (
        b"+TABLE = [\n"
        + b"".join(
            (
                "+    " + ", ".join(str((row * column) % 1000) for column in range(24)) + ",\n"
            ).encode()
            for row in range(table_rows)
        )
        + b"+]\n"
    )
    tail = b"".join(
        f"+def solve_{index}(key):\n+    return TABLE[key % {index + 1}]\n".encode()
        for index in range(300)
    )
    return head + code + table + tail


def _ledger_build(
    change: CheckTimeChange,
    *,
    ceiling: int | None = 262_144,
    outputs: int = 30,
    findings: Any = None,
    selection: ReviewSelectionPolicy | None = None,
) -> tuple[SemanticCase, Any]:
    from unit.application.test_semantic_case_selection import (
        _ledger,  # pyright: ignore[reportPrivateUsage]
    )

    ledger = _ledger(
        "codex",
        outputs=outputs,
        output_text=lambda index: f"output {index}\n" + "tool output line\n" * 300,
        findings=findings,
    )
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=ledger.case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=selection
        or ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=ledger.captured,
        captured_content_scope=ledger.scope,
        check_time_change=change,
        prepared_byte_ceiling=ceiling,
    )
    return semantic, ledger


def test_a_single_large_source_file_reaches_the_reviewer_in_few_large_parts() -> None:
    """The tb4n1 shape: a ~140 KiB deliverable beside a busy ledger, under the Expanded preset.

    With 4 KiB parts and only the reserved half of the budget it reached the reviewer as 16 parts
    of about 63 KiB in all. It now travels as at most eight 16 KiB parts carrying most of the
    whole 128 KiB excerpt budget, and the prepared document still plans below the channel ceiling.
    """

    text = _cracker_change()
    assert 135_000 < len(text) < 150_000

    semantic, _ = _ledger_build(_change(text))

    change_items = [
        item for item in semantic.items if item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    ]
    carried = sum(item.content_bytes for item in change_items)
    assert len(change_items) <= 8
    assert all(item.content_bytes <= 16_384 for item in change_items)
    assert carried >= 110_000
    assert change_items[0].content.startswith(b"[FinishUP check-time change, part 1 of 9]\n")
    # Parts are whole lines of the change, so the table rows the reviewer sees are never split.
    joined = b"".join(item.content.partition(b"\n")[2] for item in change_items)
    assert text.startswith(joined) and joined.endswith(b"\n")
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP in semantic.packet.coverage.known_gaps
    prepared = semantic_case_to_prepared_payload(
        semantic, {item.item_id for item in semantic.items}
    )
    assert len(prepared) <= 262_144 - 4_096


def test_leftover_parts_rank_after_reserved_excerpts_and_before_older_hunks_and_output() -> None:
    semantic, ledger = _ledger_build(_change(_large_change(40)))

    by_id = {item.item_id: item for item in semantic.items}
    newest = {str(ref) for ref in ledger.newest_edit_for_path.values()}
    outputs = {str(ref) for ref in ledger.outputs}
    order: list[str] = []
    for excerpt in semantic.packet.targeted_excerpts:
        item = by_id[excerpt.excerpt_item_id]
        if excerpt.excerpt_item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX):
            order.append("change")
        elif item.source_ref in newest:
            order.append("newest_edit")
        elif item.superseded_by and item.source_kind == "diff":
            order.append("older_edit")
        elif item.source_ref in outputs:
            order.append("output")
        else:
            order.append("other")
    change_positions = [index for index, kind in enumerate(order) if kind == "change"]
    assert change_positions[:4] == [0, 1, 2, 3]  # the reserved half of 128 KiB
    leftover = change_positions[4:]
    assert leftover, "the parts the reservation could not hold take the next room"
    # Every newest captured edit precedes the leftover parts; older hunks and output follow them.
    assert max(index for index, kind in enumerate(order) if kind == "newest_edit") < leftover[0]
    assert (
        min(index for index, kind in enumerate(order) if kind in {"older_edit", "output"})
        > leftover[-1]
    )


def test_a_planned_case_narrows_general_output_before_the_change() -> None:
    # A narrower owner ceiling: the planner drops the 5 KiB tool outputs, not the change's parts.
    roomy, ledger = _ledger_build(_change(_large_change(40)))
    narrow, _ = _ledger_build(_change(_large_change(40)), ceiling=200_000)

    outputs = {str(ref) for ref in ledger.outputs}
    assert any(item.source_ref in outputs for item in roomy.items if item.section == "excerpt")
    assert not any(item.source_ref in outputs for item in narrow.items if item.section == "excerpt")
    assert len(_change_items(narrow)) >= 5
    assert "content_unselected" in narrow.packet.coverage.known_gaps
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP in narrow.packet.coverage.known_gaps


def _open_prior_findings() -> dict[Any, Any]:
    from builders.policy_cases import finding_record, fnd
    from finishup.application.semantic_case import MAX_PRIOR_FINDINGS
    from unit.application.test_semantic_case_prior_findings import (
        _CHALLENGE,  # pyright: ignore[reportPrivateUsage]
        _semantic,  # pyright: ignore[reportPrivateUsage]
    )

    return {
        fnd(number): finding_record(_semantic(number, challenge=_CHALLENGE), 80 + number)
        for number in range(1, MAX_PRIOR_FINDINGS + 1)
    }


def _assert_change_leads_and_is_accounted(semantic: SemanticCase, text: bytes) -> int:
    change_items = sorted(
        (item for item in semantic.items if item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)),
        key=lambda item: item.item_id,
    )
    assert change_items, "the change under review must keep at least its leading part"
    assert semantic.packet.targeted_excerpts[0].excerpt_item_id == change_items[0].item_id
    gaps = set(semantic.packet.coverage.known_gaps)
    assert CHECK_TIME_CHANGE_UNAVAILABLE_GAP not in gaps
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP in gaps
    joined = b"".join(item.content.partition(b"\n")[2] for item in change_items)
    assert text.startswith(joined)
    carried = check_time_change_bytes_carried(semantic)
    assert carried == len(joined)
    (shown,) = check_time_change_shown_files(_change(text).capture, carried)
    assert shown.shown_bytes == carried - text.index(b"diff --git")
    assert not shown.section_admitted
    return len(change_items)


@pytest.mark.parametrize("ceiling", (262_144, 220_000, 200_000, 170_000, 162_000))
def test_the_change_keeps_its_leading_part_beside_sixteen_prior_findings(ceiling: int) -> None:
    """tb4n1 (issue #983): a narrowed case dropped every 16 KiB part while small excerpts stayed.

    Sixteen open reviewer findings with full prose and a ~140 KiB single-file change: at every
    ceiling the change's first part (cut to the room when a whole part does not fit) reaches the
    reviewer ahead of every recorded excerpt, and the shown-file record counts exactly its bytes.
    """

    text = _cracker_change()
    semantic, _ = _ledger_build(_change(text), ceiling=ceiling, findings=_open_prior_findings())

    assert len(semantic.packet.prior_finding_refs) == 16
    _assert_change_leads_and_is_accounted(semantic, text)
    prepared = semantic_case_to_prepared_payload(
        semantic, {item.item_id for item in semantic.items}
    )
    assert len(prepared) <= ceiling


def test_a_tight_case_cuts_the_first_part_to_the_room_and_says_so() -> None:
    text = _cracker_change()
    # About 4 KiB of room is left above the fixed material: less than one whole part. (The planner
    # searches excerpt budgets in 1 KiB steps, so a ceiling within about 2 KiB of the fixed
    # material can land on no part at all; FinishUP's labels are 3 bytes longer than Yoetz's were.)
    semantic, _ = _ledger_build(_change(text), ceiling=162_000, findings=_open_prior_findings())

    (first,) = [
        item for item in semantic.items if item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    ]
    assert first.content.startswith(
        b"[FinishUP check-time change, part 1 of 9, cut to the packet's room]\n"
    )
    assert first.content_bytes < 16_384
    assert _assert_change_leads_and_is_accounted(semantic, text) == 1


@pytest.mark.parametrize("limit", (200_000, 170_000, 162_000))
def test_the_channel_ceiling_planner_keeps_the_change_and_its_accounting(limit: int) -> None:
    """The service planner narrows the selection itself; the change still leads (issue #983)."""

    from finishup.service.semantic_ceiling import plan_under_channel_ceiling

    text = _cracker_change()
    findings = _open_prior_findings()
    approved = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)

    def rebuild(selection: ReviewSelectionPolicy) -> SemanticCase:
        return _ledger_build(_change(text), ceiling=None, findings=findings, selection=selection)[0]

    planned, _, rounds = plan_under_channel_ceiling(rebuild(approved), approved, limit, rebuild)

    assert rounds > 1
    _assert_change_leads_and_is_accounted(planned, text)


def _diff_file(path: str, lines: tuple[bytes, ...]) -> bytes:
    head = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n".encode()
    return head + b"".join(lines)


def _tight_decision_selection(total: int) -> ReviewSelectionPolicy:
    expanded = ReviewSelectionPolicy.for_profile(
        ReviewContextProfile.EXPANDED, preset_version="1.1.0"
    )
    return replace(expanded, max_excerpts=4, max_excerpt_bytes=4_096, max_total_excerpt_bytes=total)


def test_a_tight_change_shows_the_decision_section_ahead_of_boilerplate() -> None:
    """Issue #1079: when the change does not fit, keep the branch and the rule it implements."""

    header = b"FinishUP check-time change: header\nFiles:\nEnd of header.\n"
    license_file = _diff_file(
        "LICENSE",
        (b"+# Copyright 2020 the authors\n", b"+# SPDX-License-Identifier: MIT\n")
        + tuple(b"+# license notice line\n" for _ in range(400)),
    )
    decision = _diff_file(
        "src/rule.py",
        (b"+# reject a non-positive amount\n", b"+if value > 0:\n", b"+    return value\n"),
    )
    text = header + license_file + decision
    decision_at = text.index(b"diff --git a/src/rule.py")
    # Room for the decision section and its labels, not for a 256-byte boilerplate chunk.
    selection = _tight_decision_selection(700)
    semantic = _build(
        _case_with_material(),
        ReviewContextProfile.CUSTOM,
        change=_change(text),
        selection=selection,
    )

    parts = [
        item for item in semantic.items if item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    ]
    assert parts
    body = b"".join(item.content for item in parts)
    assert b"if value > 0:" in body
    assert b"return value" in body
    assert b"reject a non-positive amount" in body
    assert b"Copyright 2020" not in body
    assert b"decision-changing sections are shown ahead of boilerplate" in parts[0].content
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP in semantic.packet.coverage.known_gaps
    assert sum(item.content_bytes for item in semantic.packet.targeted_excerpts) <= 700

    leading = check_time_change_bytes_carried(semantic)
    served = check_time_change_sections_carried(semantic)
    assert leading == 0
    assert (decision_at, decision_at + len(decision)) in served
    files, representable = check_time_change_shown_record(_change(text).capture, leading, served)
    assert representable
    identities = {file.identity for file in files}
    assert b"diff --git a/src/rule.py b/src/rule.py" in identities
    assert all(b"LICENSE" not in identity for identity in identities)
    (shown,) = files
    assert shown.whole and shown.section_admitted
    assert (
        check_time_change_sections_carried(semantic, withheld_categories=("repository_excerpt",))
        == ()
    )
    assert (
        check_time_change_bytes_carried(semantic, withheld_categories=("repository_excerpt",)) == 0
    )


def test_a_change_that_fits_keeps_its_leading_prefix() -> None:
    header = b"FinishUP check-time change: header\nEnd of header.\n"
    license_file = _diff_file("LICENSE", (b"+# Copyright 2020\n",))
    decision = _diff_file("src/rule.py", (b"+if value > 0:\n", b"+    return value\n"))
    text = header + license_file + decision

    semantic = _build(_case_with_material(), change=_change(text))

    first = next(
        item for item in semantic.items if item.item_id == f"{CHECK_TIME_CHANGE_ITEM_PREFIX}001"
    )
    assert b"decision-changing sections" not in first.content
    body = first.content.split(b"\n", 1)[1]
    assert text.startswith(body)
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP not in semantic.packet.coverage.known_gaps


@pytest.mark.parametrize(
    "prefix", (b"+import module\n", b"+# generated boilerplate\n", b"+// license notice\n")
)
@pytest.mark.parametrize("path", ("src/rule.py", "src/règle.py"))
@pytest.mark.parametrize("separate_hunk", (False, True))
def test_a_tight_single_file_selects_the_decision_interval(
    prefix: bytes, path: str, separate_hunk: bool
) -> None:
    text = b"FinishUP check-time change: header\nEnd of header.\n" + _diff_file(
        path,
        (prefix,) * 400
        + ((b"@@ -600,2 +1000,3 @@\n",) if separate_hunk else ())
        + (b"+# reject non-positive values\n", b"+if value > 0:\n", b"+    return value\n"),
    )
    semantic = _build(
        _case_with_material(),
        ReviewContextProfile.CUSTOM,
        change=_change(text),
        selection=_tight_decision_selection(700),
    )
    parts = [
        item for item in semantic.items if item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    ]
    body = b"".join(item.content for item in parts)
    assert b"if value > 0:" in body and b"return value" in body
    assert b"reject non-positive values" in body
    assert f"diff --git a/{path} b/{path}".encode() in body
    assert b"[FinishUP hunk: @@" in body
    assert b"skipped file intervals" in body
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP in semantic.packet.coverage.known_gaps
    assert sum(item.content_bytes for item in semantic.packet.targeted_excerpts) <= 700
    leading = check_time_change_bytes_carried(semantic)
    served = check_time_change_sections_carried(semantic)
    assert leading == 0 and served
    decision_at = text.index(b"+if value > 0:")
    assert any(low <= decision_at < high for low, high in served)
    files, representable = check_time_change_shown_record(_change(text).capture, leading, served)
    assert representable and len(files) == 1
    shown = files[0]
    assert not shown.whole and not shown.section_admitted
    assert shown.clean_bytes == 0
    assert shown.shown_bytes == sum(high - low for low, high in served)
    assert shown.view.startswith(b"yoetz/check-change-interval-view/v1\x00")
    # A different interval cannot authorize the same repair view.
    other, _ = check_time_change_shown_record(
        _change(text).capture, 0, ((served[0][0] - 1, served[0][1]),)
    )
    assert other[0].view != shown.view
    # Copied context is part of the shown view too, even outside the selected interval.
    old_header, new_header = (
        (b"@@ -600,2 +1000,3 @@", b"@@ -601,2 +1001,3 @@")
        if separate_hunk
        else (b"@@ -1 +1 @@", b"@@ -2 +2 @@")
    )
    relabeled, _ = check_time_change_shown_record(
        _change(text.replace(old_header, new_header)).capture, leading, served
    )
    assert relabeled[0].view != shown.view
    assert (
        check_time_change_sections_carried(semantic, withheld_categories=("repository_excerpt",))
        == ()
    )


def test_cut_interior_hunk_header_counts_only_the_bytes_that_reached_the_packet() -> None:
    from finishup.application.semantic_case import (
        _check_time_change_cut_part,  # pyright: ignore[reportPrivateUsage]
        _check_time_change_label_body,  # pyright: ignore[reportPrivateUsage]
        _check_time_change_offer,  # pyright: ignore[reportPrivateUsage]
    )

    text = _diff_file(
        "src/règle.py",
        (b"+import module\n",) * 400
        + (b"+if value > 0:\n", b"+    return value\n")
        + (b"+detail = '" + b"x" * 150 + b"'\n",) * 5,
    )
    parts, offsets = _check_time_change_offer(text, _tight_decision_selection(1800))
    result = _check_time_change_cut_part(parts[0], 1, len(parts), 700)
    assert result is not None and result[1]
    part = result[0].encode()
    assert b"cut to the packet's room" in part
    assert b"if value > 0:" in part and b"return value" in part
    match = re.search(rb"selected original bytes (\d+):(\d+)", part)
    assert match is not None
    _labels, body = _check_time_change_label_body(result[0])
    assert int(match[1]) == offsets[0]
    assert text[int(match[1]) : int(match[2])] == body.encode()
    assert len(part) <= 700


def test_other_code_ranks_after_a_decision_and_ahead_of_a_license() -> None:
    header = b"FinishUP check-time change: header\nEnd of header.\n"
    license_file = _diff_file(
        "LICENSE",
        tuple(b"+# Copyright notice\n" for _ in range(300)),
    )
    helper = _diff_file("src/total.py", (b"+total = left + right\n",))
    decision = _diff_file("src/rule.py", (b"+if ready:\n", b"+    return total\n"))
    text = header + license_file + helper + decision
    # Just above the decision part (labels included) and below that part plus the helper.
    selection = _tight_decision_selection(420)
    semantic = _build(
        _case_with_material(),
        ReviewContextProfile.CUSTOM,
        change=_change(text),
        selection=selection,
    )

    body = b"".join(
        item.content
        for item in semantic.items
        if item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    )
    assert b"if ready:" in body and b"return total" in body
    assert b"total = left + right" not in body
    assert b"Copyright notice" not in body


def test_a_decision_that_names_a_license_outranks_an_assignment() -> None:
    """A line matching ``_DECISION_LINE`` ranks first even when it contains ``license``.

    With one excerpt, the decision file is the part offered and the preference note is true:
    the assignment beside it is the section left out.
    """

    header = b"FinishUP check-time change: header\nEnd of header.\n"
    assignment = _diff_file(
        "src/total.py",
        tuple(b"+total = left + right\n" for _ in range(200)),
    )
    decision = _diff_file("src/gate.py", (b"+if not self.has_license:\n",))
    text = header + assignment + decision
    selection = replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED, preset_version="1.1.0"),
        max_excerpts=1,
        max_excerpt_bytes=4_096,
        max_total_excerpt_bytes=8_192,
    )
    semantic = _build(
        _case_with_material(),
        ReviewContextProfile.CUSTOM,
        change=_change(text),
        selection=selection,
    )

    parts = [
        item for item in semantic.items if item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX)
    ]
    assert len(parts) == 1
    body = parts[0].content
    assert b"if not self.has_license:" in body
    assert b"total = left + right" not in body
    assert b"decision-changing sections are shown ahead of boilerplate" in body
    assert CHECK_TIME_CHANGE_TRUNCATED_GAP in semantic.packet.coverage.known_gaps


def test_a_structural_recipe_does_not_send_the_decision_section() -> None:
    header = b"FinishUP check-time change: header\nEnd of header.\n"
    text = header + _diff_file("src/rule.py", (b"+if value > 0:\n", b"+    return value\n"))
    selection = ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL)

    semantic = _build(
        _case_with_material(),
        ReviewContextProfile.CUSTOM,
        change=_change(text),
        selection=selection,
    )

    assert not any(
        item.item_id.startswith(CHECK_TIME_CHANGE_ITEM_PREFIX) for item in semantic.items
    )
    assert b"if value > 0:" not in b"".join(item.content for item in semantic.items)


def test_captured_edits_the_change_already_carries_whole_yield_to_the_latest_verification() -> None:
    """Issue #1082: hook-captured hunks of files the check-time change already shows whole are
    the same code again. They rank as older edits superseded by the change, so the latest
    verification output takes their room first; they are still offered after it."""

    from unit.application.test_semantic_case_selection import (
        _PATHS,  # pyright: ignore[reportPrivateUsage]
    )

    text = b"".join(
        f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n+fixed\n".encode()
        for path in _PATHS
    )
    semantic, ledger = _ledger_build(_change(text), ceiling=None, outputs=4)

    by_id = {item.item_id: item for item in semantic.items}
    order = [ref.excerpt_item_id for ref in semantic.packet.targeted_excerpts]
    newest = {str(ref) for ref in ledger.newest_edit_for_path.values()}
    edit_items = [
        item for item in semantic.items if item.section == "excerpt" and item.source_ref in newest
    ]
    assert edit_items, "the captured edits are still offered"
    assert all(item.superseded_by == ("check-time-change",) for item in edit_items)
    assert all(item.latest_for is None for item in edit_items)
    latest_pytest = str(ledger.verification["pytest"][-1])
    verification = next(
        item_id
        for item_id, item in by_id.items()
        if item.section == "excerpt" and item.source_ref == latest_pytest
    )
    first_edit = min(order.index(item.item_id) for item in edit_items)
    assert order.index(verification) < first_edit

    # A change that carries only some of a file's sections leaves its captured edits current.
    partial, ledger = _ledger_build(_change(text.split(b"diff --git a/lib/")[0]), ceiling=None)
    lib_refs = {
        str(ref) for path, ref in ledger.newest_edit_for_path.items() if path.startswith("lib/")
    }
    lib_edits = [
        item for item in partial.items if item.section == "excerpt" and item.source_ref in lib_refs
    ]
    assert lib_edits and all(item.superseded_by != ("check-time-change",) for item in lib_edits)
