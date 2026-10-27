"""#1230: composition sizes every excerpt as disclosure will measure it.

In TB4 rv16 a task input composed at exactly the 16,384-byte per-excerpt bound reached egress
18 bytes over it: minimization replaced a short credential-like value with the longer fixed
placeholder, and egress measures the minimized row. Composition and egress now share one measure
(``semantic_disclosed_bytes``), so a composed case never exceeds a per-excerpt bound, the excerpt
total or the planned exchange once its values are replaced.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import cast

from finishup.application import semantic_case as composer
from finishup.application.egress import (
    _excerpt_limit_capacity,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.receipts import SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP
from finishup.observability.privacy import (
    EGRESS_CREDENTIAL_PLACEHOLDER,
    semantic_disclosed_bytes,
    semantic_egress_forms,
)
from finishup.ports.change_capture import MAX_TASK_INPUT_TEXT_BYTES, TaskInputFile
from finishup.ports.semantic import SemanticCase
from finishup.service.semantic_ceiling import planned_exchange_size
from unit.application.test_semantic_case_packet_completeness import (
    _change,  # pyright: ignore[reportPrivateUsage]
    _react_case,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _candidate,  # pyright: ignore[reportPrivateUsage]
    _minimize_everything,  # pyright: ignore[reportPrivateUsage]
)

_SELECTION = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
_CAP = _SELECTION.max_excerpt_bytes
# A seven-byte value the egress heuristic replaces with the 39-byte placeholder: +32 bytes.
_PLANTED = b'password = "hunter2"\n'
_GROWTH = len(EGRESS_CREDENTIAL_PLACEHOLDER) - len(b"hunter2")
_FILLER = b"Requirement line: reject bad input and keep the tail verdict.\n"


def _build(
    *,
    diff: bytes = b"diff --git a/form.py b/form.py\n+return value is not None\n",
    inputs: tuple[TaskInputFile, ...] = (),
    selection: ReviewSelectionPolicy = _SELECTION,
) -> SemanticCase:
    return composer.build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=_react_case(),
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.CUSTOM,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        check_time_change=_change(diff, inputs=inputs),
        workspace_root="/app",
    )


def _rows(prepared: bytes) -> dict[str, dict[str, object]]:
    packet = cast(dict[str, object], json.loads(prepared))
    return {
        cast(str, row["item_id"]): row
        for row in cast(list[dict[str, object]], packet["items"])
        if row["section"] == "excerpt"
    }


def test_the_shared_measure_counts_the_placeholder_growth() -> None:
    text = b"intro\n" + _PLANTED + b"outro\n"
    forms = semantic_egress_forms(text)
    assert forms[0] == text
    assert any(EGRESS_CREDENTIAL_PLACEHOLDER in form for form in forms[1:])
    assert semantic_disclosed_bytes(text) == len(text) + _GROWTH
    clean = b"no credential-like value here\n"
    assert semantic_egress_forms(clean) == (clean,)
    assert semantic_disclosed_bytes(clean) == len(clean)


def test_a_task_input_clipped_to_the_cap_still_fits_once_its_value_is_replaced() -> None:
    """The rv16 shape: a large task input head/tail-clipped to the per-excerpt bound."""

    body = b"SPEC HEAD\n" + _PLANTED + _FILLER * (_CAP // len(_FILLER))
    spec = body[: MAX_TASK_INPUT_TEXT_BYTES - len(b"SPEC TAIL\n")] + b"SPEC TAIL\n"
    # The reader kept the file's first 16 KiB; its label then puts the excerpt over the bound.
    case = _build(inputs=(TaskInputFile("DESIGN.md", spec, 2 * len(spec)),))
    item = next(item for item in case.items if item.item_id == "task-input-01")
    assert b"SPEC HEAD" in item.content and b"SPEC TAIL" in item.content
    # The cut is taken from the input redacted in full, so the value is replaced before any
    # byte is dropped, and composition's own measure is the disclosed one.
    assert b"hunter2" not in item.content
    assert EGRESS_CREDENTIAL_PLACEHOLDER in item.content
    assert semantic_disclosed_bytes(item.content) <= _CAP
    assert item.content_bytes <= _CAP
    # A cut of redacted text has no exact place in the input: never read as shown whole.
    assert item.item_id in case.unplaced_item_ids
    minimized = _minimize_everything(_candidate(case))
    row = _rows(minimized.prepared_bytes)["task-input-01"]
    assert b"hunter2" not in minimized.prepared_bytes
    assert EGRESS_CREDENTIAL_PLACEHOLDER.decode() in cast(str, row["content"])
    assert cast(int, row["content_bytes"]) <= _CAP
    # Before #1230 the row measured _CAP + _GROWTH and egress refused the whole review.
    assert _excerpt_limit_capacity(minimized.prepared_bytes, _SELECTION) is None


def test_a_change_part_near_the_cap_is_cut_so_its_disclosed_form_fits() -> None:
    """Written within the bound, the part would outgrow it once its value is replaced."""

    head = b"diff --git a/src/archive.rs b/src/archive.rs\n+    " + _PLANTED
    line = b"+    archive.push_entry(entry_index, &buffer[offset..offset + chunk]);\n"
    diff = head + line * ((_CAP - 200 - len(head)) // len(line))
    diff += b"+" + b"x" * (_CAP - 60 - len(diff)) + b"\n"
    case = _build(diff=diff)
    part_id = f"{composer.CHECK_TIME_CHANGE_ITEM_PREFIX}001"
    part = next(item for item in case.items if item.item_id == part_id)
    assert semantic_disclosed_bytes(part.content) <= _CAP
    # The extra cut is marked in the text and disclosed like any clip to the item bound.
    assert b"bytes elided here" in part.content
    assert SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP in case.packet.coverage.known_gaps
    manifest = case.packet.input_manifest
    assert manifest is not None
    assert "truncated_payload" in manifest.current_diff.omission_reasons
    minimized = _minimize_everything(_candidate(case))
    assert cast(int, _rows(minimized.prepared_bytes)[part_id]["content_bytes"]) <= _CAP
    assert _excerpt_limit_capacity(minimized.prepared_bytes, _SELECTION) is None


def test_the_excerpt_total_is_kept_as_disclosure_will_measure_it() -> None:
    """Change parts fill the excerpt total as written; replaced values would push it over.

    Measured as written this case composes 12,247 of 12,288 bytes and discloses 13,879.
    """

    total = 12_288
    selection = replace(_SELECTION, max_excerpt_bytes=4_096, max_total_excerpt_bytes=total)
    line = b"+    retries = compute_retries(attempt, budget, policy)  # keep going\n"
    diff = (
        b"diff --git a/app/settings.py b/app/settings.py\n" + (b"+    " + _PLANTED + line * 3) * 60
    )
    case = _build(diff=diff, selection=selection)
    excerpts = [item for item in case.items if item.section == "excerpt"]
    # Several parts hold a value, as written or already replaced by a cut (#1230).
    assert (
        sum(
            1
            for item in excerpts
            if b"hunter2" in item.content or EGRESS_CREDENTIAL_PLACEHOLDER in item.content
        )
        > 1
    )
    assert sum(semantic_disclosed_bytes(item.content) for item in excerpts) <= total
    minimized = _minimize_everything(_candidate(case))
    sizes = [cast(int, row["content_bytes"]) for row in _rows(minimized.prepared_bytes).values()]
    assert sum(sizes) <= total
    assert max(sizes) <= selection.max_excerpt_bytes
    assert _excerpt_limit_capacity(minimized.prepared_bytes, selection) is None


def test_the_planned_exchange_is_the_payload_as_disclosed() -> None:
    case = _build(diff=b"diff --git a/config.py b/config.py\n+" + _PLANTED)
    payloads = composer.semantic_case_to_disclosed_payloads(
        case, {item.item_id for item in case.items}
    )
    assert len(payloads) == 2
    as_written, disclosed = payloads
    assert b"hunter2" in as_written and b"hunter2" not in disclosed
    # The disclosed shape also carries the row's ``redacted`` transformation, so it is larger.
    assert len(disclosed) > len(as_written)
    assert planned_exchange_size(case, None, len) == len(disclosed)
    minimized = _minimize_everything(_candidate(case))
    assert len(minimized.prepared_bytes) <= len(disclosed)


# Codex review round 1, P1: a cut keeping ``hunter2`` but dropping its ``password =`` label.
_LABEL_CUT_INPUT = b"HEAD\n" + b"a" * 8_000 + b"\n" + _PLANTED + b"b" * 3_980 + b"\nTAIL\n"
# Fragments of the value a cut through it could keep; the filler holds none of them.
_VALUE_FRAGMENTS = (b"hunter2", b"hunt", b"unte", b"nter", b"ter2")


def test_a_cut_never_keeps_a_value_whose_label_it_dropped() -> None:
    """Every cut edge around the value: label dropped, value split, value whole in the tail."""

    limits = range(7_900, 8_200)
    # The edge is real: cut as written, some of these keep the value and lose its label.
    exposed = [
        limit
        for limit in limits
        if b"hunter2"
        in (cut := composer._head_tail_kept_clean(_LABEL_CUT_INPUT, limit)[0].encode())  # pyright: ignore[reportPrivateUsage]
        and b"password" not in cut
    ]
    assert exposed
    for limit in limits:
        cut = composer._head_tail(_LABEL_CUT_INPUT, limit).encode()  # pyright: ignore[reportPrivateUsage]
        fitted = composer.fit_disclosed_excerpt(_LABEL_CUT_INPUT, limit)
        for text in (cut, fitted or b""):
            assert not any(fragment in text for fragment in _VALUE_FRAGMENTS), limit
        assert fitted is not None and semantic_disclosed_bytes(fitted) <= limit


def test_the_label_cut_reproduction_composes_without_the_value() -> None:
    selection = replace(_SELECTION, max_excerpt_bytes=8_086)
    case = _build(
        inputs=(TaskInputFile("DESIGN.md", _LABEL_CUT_INPUT, len(_LABEL_CUT_INPUT)),),
        selection=selection,
    )
    item = next(item for item in case.items if item.item_id == "task-input-01")
    assert b"HEAD" in item.content and b"TAIL" in item.content
    assert not any(fragment in item.content for fragment in _VALUE_FRAGMENTS)
    assert semantic_disclosed_bytes(item.content) <= 8_086
    minimized = _minimize_everything(_candidate(case))
    assert minimized.forbidden_findings == () and minimized.heuristic_findings == ()
    assert not any(fragment in minimized.prepared_bytes for fragment in _VALUE_FRAGMENTS)
    # Finding 2: the cut input is sent but never counted as showing its source whole, so an
    # in-check follow-up may still offer the rest.
    assert item.item_id in case.unplaced_item_ids
    disclosure = composer.review_packet_disclosure_result(minimized.prepared_bytes)
    assert disclosure.failure is None and disclosure.disclosure is not None
    manifest = disclosure.disclosure.provider_input_manifest
    sent = composer.sent_excerpt_content_refs(case, manifest)
    assert sent is not None
    assert not composer.excerpt_content_refs((item,)) <= sent
