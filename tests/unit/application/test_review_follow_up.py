"""In-check follow-up: Yoetz answers the reviewer's own request from its records (issue #1047).

The reviewer named content it needed (``missing_for_assessment``) that Yoetz holds but the packet
did not carry. The planner decides what Yoetz may add, the case builder ranks those excerpts first
within a bounded share, and the input manifest says, on every surface, which round this is and
what was added. Without a follow-up nothing about the packet changes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any, cast

import pytest

from builders.policy_cases import (
    act,
    clm,
    evd,
    evidence_record,
    evt,
    make_case,
    record,
    res,
)
from yoetz.application.missing_for_assessment import (
    ReviewFollowUp,
    ReviewFollowUpItem,
    excerpt_span_whole,
    plan_review_follow_up,
    review_missing_for_assessment,
)
from yoetz.application.semantic_case import (
    CHECK_TIME_SECTION_ITEM_PREFIX,
    CapturedContentScope,
    CapturedSemanticContent,
    CheckTimeChange,
    assemble_filtered_review_packet,
    bounded_case_envelope,
    build_semantic_case,
    captured_edit_paths,
    check_time_change_bytes_carried,
    check_time_change_sections_carried,
    check_time_change_shown_record,
    current_section_parts,
    excerpt_content_refs,
    follow_up_byte_budget,
    follow_up_new_parts,
    review_input_manifest_to_json,
    review_packet_disclosure_result,
    semantic_case_packet_view,
    sent_excerpt_content_refs,
    sent_excerpt_parts,
    withheld_excerpt_content_refs,
)
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    MissingForAssessmentItem,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.observation import ObservationContentKind
from yoetz.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from yoetz.domain.review_input_render import (
    render_review_input_manifest_compact,
    render_review_input_manifest_lines,
)
from yoetz.domain.values import EvidenceId, freeze_json, object_id, timestamp_from_string
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.kernel.projections import EvidenceProjectionRecord
from yoetz.ports.semantic import MissingForAssessment, SemanticCase, SemanticJudgment
from yoetz.protocol.canonical import JsonValue, strict_json_parse
from yoetz.protocol.coverage import EvidenceImmutability
from yoetz.protocol.models import MAX_REVIEW_FOLLOW_UP_ROUNDS, DataCategory

_WHEN = timestamp_from_string("2026-10-12T00:00:00.000Z")


def _verification_case(filler: int) -> tuple[DeterministicCase, tuple[EvidenceId, ...]]:
    """Three runs of one test command beside ``filler`` newer output rows.

    The latest run (a pass) and the failure before it are reserved; the first failing run is
    superseded, so a 16-excerpt packet cuts its output for room: the shape a reviewer asks
    ``verification_output`` for when it wants to see how the work first failed.
    """

    outcomes = (ResultOutcome.FAILURE, ResultOutcome.FAILURE, ResultOutcome.SUCCESS)
    actions = {
        act(run): record(
            ActionRecordedPayload(
                act(run), ActionKind.COMMAND, "Run the suite", command="pytest -q tests/test_api.py"
            ),
            run * 3 - 1,
        )
        for run in (1, 2, 3)
    }
    results = {
        res(run): record(
            ResultRecordedPayload(
                res(run),
                act(run),
                outcome,
                summary="1 failed" if outcome is ResultOutcome.FAILURE else "12 passed",
                evidence_refs=(evd(run),),
            ),
            run * 3,
        )
        for run, outcome in zip((1, 2, 3), outcomes, strict=True)
    }
    evidence = {
        evd(run): evidence_record(
            EvidenceRecordedPayload(
                evd(run),
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                _WHEN,
                description=(
                    _FIRST_FAILURE if run == 1 else f"run {run}: {results[res(run)].payload}"
                ),
            ),
            run * 3 + 1,
        )
        for run in (1, 2, 3)
    }
    refs = tuple(evd(number) for number in range(4, filler + 4))
    evidence.update(
        {
            ref: evidence_record(
                EvidenceRecordedPayload(
                    ref,
                    EvidenceKind.TEST_RESULT,
                    EvidenceImmutability.METADATA_ONLY,
                    _WHEN,
                    description=f"other suite {number}: 12 passed",
                ),
                number + 20,
            )
            for number, ref in enumerate(refs, start=1)
        }
    )
    supported = (evd(1), evd(2), evd(3), *refs)
    # One claim cites at most 64 refs; later claims cite the rest.
    claims = {
        clm(index + 1): record(
            ClaimRecordedPayload(
                clm(index + 1),
                ClaimKind.COMPLETION,
                "Lookups repaired",
                supported[start : start + 60],
            ),
            99 + index,
        )
        for index, start in enumerate(range(0, len(supported), 60))
    }
    case = make_case(
        actions=actions,
        results=results,
        evidence=evidence,
        claims=claims,
        extra_refs=tuple(claims),
    )
    return case, refs


_FIRST_FAILURE = "FAILED tests/test_api.py::test_lookup - KeyError: 'id'\n" * 8


def _selection(max_excerpts: int = 16) -> ReviewSelectionPolicy:
    return replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED), max_excerpts=max_excerpts
    )


def _build(
    case: DeterministicCase,
    *,
    follow_up: ReviewFollowUp | None = None,
    selection: ReviewSelectionPolicy | None = None,
    captured_content: Sequence[CapturedSemanticContent] = (),
    captured_content_scope: CapturedContentScope | None = None,
    check_time_change: CheckTimeChange | None = None,
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=selection or _selection(),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        follow_up=follow_up,
        captured_content=captured_content,
        captured_content_scope=captured_content_scope,
        check_time_change=check_time_change,
    )


def _excerpt_refs(semantic: SemanticCase) -> frozenset[str]:
    return frozenset(item.source_ref for item in semantic.items if item.section == "excerpt")


def _requested(kind: str, *targets: str, availability: str = "yoetz_limit_packet_room"):
    return MissingForAssessmentItem(kind=kind, target_refs=targets, availability=availability)


# --- The planner: what Yoetz may answer, and when it stops -------------------------------------


def test_a_run_request_resolves_to_the_run_its_output_and_its_command() -> None:
    case, _refs = _verification_case(20)
    first = _build(case)
    shown = _excerpt_refs(first)
    assert str(evd(1)) not in shown

    follow_up = plan_review_follow_up(
        case.projection,
        frozenset(str(ref) for ref in case.allowed_ids),
        (_requested("verification_output", str(res(1)), availability="agent_suppliable"),),
        previous=None,
        shown_refs=shown,
    )

    assert follow_up is not None
    assert follow_up.round == 1
    assert follow_up.shown_refs == shown
    assert follow_up.added_refs == frozenset()
    (item,) = follow_up.items
    assert (item.kind, item.target_refs) == ("verification_output", (str(res(1)),))
    assert item.source_refs == {str(res(1)), str(act(1)), str(evd(1))}


def test_an_event_target_names_the_rows_it_recorded() -> None:
    case, _refs = _verification_case(20)
    # The result was recorded by evt(3) (``record`` numbers each row's event).
    follow_up = plan_review_follow_up(
        case.projection,
        frozenset(str(ref) for ref in case.allowed_ids),
        (_requested("verification_output", str(evt(3))),),
        previous=None,
        shown_refs=frozenset(),
    )
    assert follow_up is not None
    assert {str(res(1)), str(evd(1)), str(act(1))} <= follow_up.items[0].source_refs


@pytest.mark.parametrize(
    "item",
    [
        # Kinds Yoetz never answers itself: they stay the agent's, exactly as before.
        _requested("task_statement", str(clm(1)), availability="agent_suppliable"),
        _requested("plan_or_claim_text", str(clm(1)), availability="agent_suppliable"),
        _requested("other", str(res(1)), availability="agent_suppliable"),
        # Content the packet may never carry is never re-sent.
        _requested(
            "verification_output", str(res(1)), availability="structurally_unavailable_on_this_host"
        ),
        _requested(
            "verification_output", str(res(1)), availability="yoetz_limit_unsupported_data_type"
        ),
        # An item naming no target cannot be bound to a recorded row.
        _requested("verification_output", availability="agent_suppliable"),
    ],
)
def test_requests_yoetz_cannot_answer_leave_the_check_unchanged(
    item: MissingForAssessmentItem,
) -> None:
    case, _refs = _verification_case(20)
    assert (
        plan_review_follow_up(
            case.projection,
            frozenset(str(ref) for ref in case.allowed_ids),
            (item,),
            previous=None,
            shown_refs=frozenset(),
        )
        is None
    )


def test_no_round_runs_when_everything_requested_was_already_shown_or_unknown() -> None:
    case, _refs = _verification_case(20)
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    request = (_requested("verification_output", str(res(1))),)
    everything = frozenset({str(res(1)), str(act(1)), str(evd(1))})
    assert (
        plan_review_follow_up(
            case.projection, allowed, request, previous=None, shown_refs=everything
        )
        is None
    )
    # The first packet could not be read: nothing can be called added, so nothing is sent.
    assert (
        plan_review_follow_up(case.projection, allowed, request, previous=None, shown_refs=None)
        is None
    )


def test_rounds_accumulate_in_request_order_and_stop_at_the_bound() -> None:
    case, _refs = _verification_case(20)
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    first = plan_review_follow_up(
        case.projection,
        allowed,
        (_requested("verification_output", str(res(1))),),
        previous=None,
        shown_refs=frozenset(),
    )
    assert first is not None
    after_first = replace(first, added_refs=frozenset({str(evd(1))}))
    second = plan_review_follow_up(
        case.projection,
        allowed,
        (
            _requested("verification_output", str(res(1))),
            _requested("command_identity", str(act(1))),
        ),
        previous=after_first,
        shown_refs=frozenset({"ignored"}),
    )
    assert second is not None
    assert second.round == 2
    # The earlier item keeps its place; the first packet's shown set and the added refs carry.
    assert [(item.kind, item.target_refs) for item in second.items] == [
        ("verification_output", (str(res(1)),)),
        ("command_identity", (str(act(1)),)),
    ]
    assert second.shown_refs == frozenset()
    assert second.added_refs == frozenset({str(evd(1))})
    last = replace(second, round=MAX_REVIEW_FOLLOW_UP_ROUNDS)
    assert (
        plan_review_follow_up(
            case.projection,
            allowed,
            (_requested("verification_output", str(res(1))),),
            previous=last,
            shown_refs=frozenset(),
        )
        is None
    )


def test_a_repeated_request_with_nothing_left_to_add_ends_the_follow_up() -> None:
    case, _refs = _verification_case(20)
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    first = plan_review_follow_up(
        case.projection,
        allowed,
        (_requested("verification_output", str(res(1))),),
        previous=None,
        shown_refs=frozenset({str(act(1)), str(res(1))}),
    )
    assert first is not None
    added = replace(first, added_refs=frozenset({str(evd(1))}))
    assert (
        plan_review_follow_up(
            case.projection,
            allowed,
            (_requested("verification_output", str(res(1))),),
            previous=added,
            shown_refs=None,
        )
        is None
    )


# --- The packet: requested excerpts first, within a bounded share ------------------------------


def _follow_up(case: DeterministicCase, shown: frozenset[str]) -> ReviewFollowUp:
    follow_up = plan_review_follow_up(
        case.projection,
        frozenset(str(ref) for ref in case.allowed_ids),
        (_requested("verification_output", str(res(1))),),
        previous=None,
        shown_refs=shown,
    )
    assert follow_up is not None
    return follow_up


def test_the_follow_up_packet_carries_the_requested_output_and_says_so() -> None:
    case, _refs = _verification_case(20)
    first = _build(case)
    shown = _excerpt_refs(first)
    follow_up = _follow_up(case, shown)

    again = _build(case, follow_up=follow_up)

    carried = _excerpt_refs(again)
    assert str(evd(1)) in carried
    assert follow_up.added_by(carried) >= {str(evd(1))}
    # The requested excerpt took the room of the lowest-ranked one; the count stays approved.
    assert len([item for item in again.items if item.section == "excerpt"]) == 16
    assert again.case_digest != first.case_digest
    manifest = again.packet.input_manifest
    assert manifest is not None
    assert manifest.follow_up_round == 1
    (row,) = manifest.missing_inputs
    assert (row.kind, row.target_refs, row.status) == (
        "verification_output",
        (str(res(1)),),
        "supplied",
    )
    assert str(evd(1)) in row.supplied_refs
    encoded = review_input_manifest_to_json(manifest)
    assert encoded["follow_up_round"] == 1


def test_without_a_follow_up_the_packet_is_built_exactly_as_before() -> None:
    case, _refs = _verification_case(20)
    first = _build(case)
    manifest = first.packet.input_manifest
    assert manifest is not None
    assert manifest.follow_up_round is None
    assert "follow_up_round" not in review_input_manifest_to_json(manifest)
    assert _build(case).case_digest == first.case_digest


def test_requested_excerpts_rank_first_only_within_half_the_excerpt_budget() -> None:
    """The share bounds each requested part. This output is one part (head and tail of a
    recorded description, never split), so a share smaller than it ranks none of it first; a
    source split into parts has its next parts ranked first instead (tb4n5, see
    ``test_a_partly_shown_capture_adds_its_next_parts_never_the_one_shown``)."""

    case, _refs = _verification_case(20)
    first = _build(case)
    follow_up = _follow_up(case, _excerpt_refs(first))
    output_bytes = len(_FIRST_FAILURE.encode("utf-8"))
    # A budget whose half cannot hold the requested output leaves it at its ordinary rank.
    tight = replace(_selection(), max_total_excerpt_bytes=2 * output_bytes - 2)
    assert follow_up_byte_budget(tight) < output_bytes
    narrowed = _build(case, follow_up=follow_up, selection=tight)
    assert str(evd(1)) not in _excerpt_refs(narrowed)
    manifest = narrowed.packet.input_manifest
    assert manifest is not None
    (row,) = manifest.missing_inputs
    # The run's short rows (its command and failure summary) still fit the share; its long
    # output does not, and the row never names what the packet did not carry.
    assert row.supplied_refs == (str(act(1)), str(res(1)))
    roomy = replace(_selection(), max_total_excerpt_bytes=2 * output_bytes)
    assert str(evd(1)) in _excerpt_refs(_build(case, follow_up=follow_up, selection=roomy))


def test_the_provider_bound_manifest_keeps_the_round_and_only_what_was_sent() -> None:
    case, _refs = _verification_case(20)
    follow_up = _follow_up(case, _excerpt_refs(_build(case)))
    again = _build(case, follow_up=follow_up)
    envelope = strict_json_parse(bounded_case_envelope(again))
    assert isinstance(envelope, dict)
    content_by_id = {item.item_id: item.content for item in again.items}
    every = frozenset(content_by_id)
    sent = assemble_filtered_review_packet(
        envelope, content_by_id=content_by_id, included_item_ids=every
    )
    provider = _provider_manifest(sent)
    assert provider["follow_up_round"] == 1
    assert provider["missing_inputs"] == [
        {
            "kind": "verification_output",
            "status": "supplied",
            "supplied_refs": sorted((str(act(1)), str(evd(1)), str(res(1))), key=str.encode),
            "target_refs": [str(res(1))],
        }
    ]
    assert review_packet_disclosure_result(sent).disclosure is not None
    # Privacy withheld every added excerpt: the row says nothing was supplied.
    added = {str(act(1)), str(evd(1)), str(res(1))}
    withheld = frozenset(
        item.item_id
        for item in again.items
        if item.section == "excerpt" and item.source_ref in added
    )
    held = assemble_filtered_review_packet(
        envelope,
        content_by_id=content_by_id,
        included_item_ids=every - withheld,
        withheld_item_ids=withheld,
    )
    held_manifest = _provider_manifest(held)
    assert held_manifest["follow_up_round"] == 1
    rows = held_manifest["missing_inputs"]
    assert isinstance(rows, list)
    assert [row["status"] for row in rows if isinstance(row, dict)] == ["unavailable"]


def _provider_manifest(prepared: bytes) -> dict[str, JsonValue]:
    document = strict_json_parse(prepared)
    assert isinstance(document, dict)
    packet = document["review_packet"]
    assert isinstance(packet, dict)
    manifest = packet["provider_input_manifest"]
    assert isinstance(manifest, dict)
    return manifest


def _send(semantic: SemanticCase) -> bytes:
    """The exact packet a provider receives when privacy approves every item."""

    envelope = strict_json_parse(bounded_case_envelope(semantic))
    assert isinstance(envelope, dict)
    content_by_id = {item.item_id: item.content for item in semantic.items}
    return assemble_filtered_review_packet(
        envelope, content_by_id=content_by_id, included_item_ids=frozenset(content_by_id)
    )


def _captured_group_case(
    newer: int, *, claims: int = 1
) -> tuple[DeterministicCase, tuple[CapturedSemanticContent, ...], CapturedContentScope]:
    """A two-part captured output (lead ``evd(20)``, part ``evd(21)``) and ``newer`` later runs.

    The parts are one excerpt keyed by the lead; the newer outputs outrank it, so a packet with
    room for ``newer`` excerpts omits the group. ``claims`` claims each cite every row, so each
    part stays in the packet's citable frontier.
    """

    from unit.application.test_semantic_case import (
        _captured_case_values,  # pyright: ignore[reportPrivateUsage]
    )

    base, captured, scope = _captured_case_values()
    template = base.projection.evidence[evd(1)].payload
    assert template is not None and template.digest_binding is not None
    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    parts: list[CapturedSemanticContent] = []
    for index, (ref, content) in enumerate(((evd(20), b"part-a\n"), (evd(21), b"part-b\n"))):
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        captured_object = object_id(f"obj_00000000-0000-4000-8000-00000000030{index + 2}")
        envelope_digest = "sha256:" + str(5 + index) * 64
        evidence[ref] = evidence_record(
            replace(
                template,
                evidence_id=ref,
                captured_object_id=captured_object,
                content_digest=digest,
                description=f"Observation-captured tool output bytes part={index + 1}/2",
                digest_binding=replace(template.digest_binding, byte_count=len(content)),
            ),
            20 + index,
        )
        parts.append(
            replace(
                captured,
                object_ref=replace(
                    captured.object_ref, object_id=captured_object, envelope_digest=envelope_digest
                ),
                manifest=replace(
                    captured.manifest,
                    object_id=captured_object,
                    envelope_digest=envelope_digest,
                    part_index=index,
                    part_count=2,
                    content_digest=digest,
                    content_bytes=len(content),
                ),
                content=content,
            )
        )
    for number in range(newer):
        ref = evd(30 + number)
        evidence[ref] = evidence_record(
            EvidenceRecordedPayload(
                ref,
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                _WHEN,
                description=f"other suite {number}: 12 passed",
            ),
            30 + number,
        )
    citing = {
        clm(number): record(
            ClaimRecordedPayload(
                clm(number), ClaimKind.COMPLETION, "Output captured", tuple(evidence)
            ),
            80 + number,
        )
        for number in range(1, claims + 1)
    }
    case = make_case(evidence=evidence, claims=citing, extra_refs=(*evidence, *citing))
    phase = scope.phase_bindings[0][1]
    scope = replace(scope, phase_bindings=((str(evd(20)), phase), (str(evd(21)), phase)))
    return case, tuple(parts), scope


def test_a_request_for_a_later_part_of_an_omitted_captured_group_is_answered() -> None:
    """A reviewer may name any part of a captured group; the group's excerpt carries it (#1047).

    The group travels as one excerpt keyed by its lead evidence, so counting only excerpt sources
    found nothing added for a request naming the second part: the round was never sent.
    """

    case, captured, scope = _captured_group_case(newer=4)
    selection = _selection(max_excerpts=4)
    first = _build(
        case, selection=selection, captured_content=captured, captured_content_scope=scope
    )
    assert f"excerpt-{evd(20)}" not in {item.item_id for item in first.items}
    assert str(evd(21)) in semantic_case_packet_view(first).citable_refs
    shown = sent_excerpt_content_refs(first, _provider_manifest(_send(first)))
    assert shown is not None and str(evd(21)) not in shown
    follow_up = plan_review_follow_up(
        case.projection,
        frozenset(str(ref) for ref in case.allowed_ids),
        (_requested("verification_output", str(evd(21))),),
        previous=None,
        shown_refs=shown,
    )
    assert follow_up is not None
    assert follow_up.items[0].source_refs == {str(evd(21))}

    again = _build(
        case,
        follow_up=follow_up,
        selection=selection,
        captured_content=captured,
        captured_content_scope=scope,
    )

    (group,) = (item for item in again.items if item.item_id == f"excerpt-{evd(20)}")
    assert group.source_ref == str(evd(20))
    assert str(evd(21)) in group.linked_subject_refs
    # What the composition compares before dispatch, and what the sent packet then showed.
    assert follow_up.added_by(excerpt_content_refs(again.items)) == {str(evd(21))}
    sent = _provider_manifest(_send(again))
    assert follow_up.added_by(sent_excerpt_content_refs(again, sent) or ()) == {str(evd(21))}
    manifest = again.packet.input_manifest
    assert manifest is not None
    (row,) = manifest.missing_inputs
    assert (row.status, row.supplied_refs) == ("supplied", (str(evd(21)),))
    assert sent["missing_inputs"] == [
        {
            "kind": "verification_output",
            "status": "supplied",
            "supplied_refs": [str(evd(21))],
            "target_refs": [str(evd(21))],
        }
    ]
    # A linked claim or event is not part of the group: only its ``evd_`` parts count.
    assert excerpt_content_refs((group,)) == {str(evd(20)), str(evd(21))}


@pytest.mark.parametrize("claims", [1, 15])
def test_every_part_of_a_group_is_linked_even_when_citing_claims_fill_the_bound(
    claims: int,
) -> None:
    """An excerpt links at most 16 refs; a capture's own parts come before linking claims.

    The parts are what the group's bytes hold and how a request naming any of them is matched
    (#1047). A list that fits is every linked ref in byte order, exactly as before; past the
    bound, the claims that sort before ``evd_`` no longer push the parts out.
    """

    case, captured, scope = _captured_group_case(newer=0, claims=claims)
    semantic = _build(case, captured_content=captured, captured_content_scope=scope)
    (group,) = (item for item in semantic.items if item.item_id == f"excerpt-{evd(20)}")
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    citing = sorted((str(clm(number)) for number in range(1, claims + 1)), key=str.encode)
    every = {str(evd(20)), str(evd(21)), str(evt(20)), str(evt(21)), *citing} & allowed
    if len(every) <= 16:
        assert group.linked_subject_refs == tuple(sorted(every, key=str.encode))
    else:
        assert group.linked_subject_refs == tuple(
            sorted((str(evd(20)), str(evd(21)), *citing[:14]), key=str.encode)
        )
    assert excerpt_content_refs((group,)) == {str(evd(20)), str(evd(21))}
    sent = _provider_manifest(_send(semantic))
    shown = sent_excerpt_content_refs(semantic, sent)
    assert shown is not None and str(evd(21)) in shown
    # Shown whole: the group's one excerpt part was sent, so nothing of it is left to add and a
    # request naming the second part sends no round (tb4n5: judged per part, not per ref).
    shown_parts = sent_excerpt_parts(semantic, sent)
    assert shown_parts is not None
    ((group_part,),) = [[key for key in shown_parts if key.startswith(f"{evd(20)}#")]]
    assert group_part.startswith(f"{evd(20)}#0-")
    assert (
        plan_review_follow_up(
            case.projection,
            allowed,
            (_requested("verification_output", str(evd(21))),),
            previous=None,
            shown_refs=shown,
            shown_parts=shown_parts,
        )
        is None
    )


def test_an_ordinary_excerpt_keeps_its_first_sixteen_links_in_byte_order() -> None:
    """Only a captured group's parts take priority within the bound; nothing else changes.

    A plain evidence excerpt's own ref is already its source, so it never displaces a claim that
    links it: with 16 claims citing ``evd(30)`` the excerpt links exactly those 16 claims.
    """

    case, captured, scope = _captured_group_case(newer=1, claims=16)
    semantic = _build(case, captured_content=captured, captured_content_scope=scope)
    (plain,) = (item for item in semantic.items if item.item_id == f"excerpt-{evd(30)}")
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    every = {str(evd(30)), str(evt(30)), *(str(clm(number)) for number in range(1, 17))}
    assert plain.linked_subject_refs == tuple(sorted(every & allowed, key=str.encode)[:16])


def test_a_ref_a_sent_packet_withheld_under_a_privacy_rule_never_justifies_a_round() -> None:
    """Privacy withholds the same row from every packet of the check, so it is not sent again."""

    case, _refs = _verification_case(20)
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    request = (_requested("verification_output", str(res(1))),)
    shown = frozenset({str(res(1)), str(act(1))})
    held = frozenset({str(evd(1))})
    assert (
        plan_review_follow_up(
            case.projection,
            allowed,
            request,
            previous=None,
            shown_refs=shown,
            privacy_withheld_refs=held,
        )
        is None
    )
    # Withheld for room (no privacy rule), the output is still Yoetz's to send.
    room = plan_review_follow_up(case.projection, allowed, request, previous=None, shown_refs=shown)
    assert room is not None and room.added_refs == frozenset()
    # A later round's packet withheld it under a privacy rule: no further round is sent for it.
    assert (
        plan_review_follow_up(
            case.projection,
            allowed,
            request,
            previous=room,
            shown_refs=None,
            privacy_withheld_refs=held | {str(evd(9))},
        )
        is None
    )

    # A captured group withheld whole: its omission row names only the lead evidence, yet the
    # rule withheld every part with it, so naming the second part reads like naming the lead.
    group_case, captured, scope = _captured_group_case(newer=0)
    first = _build(group_case, captured_content=captured, captured_content_scope=scope)
    group = f"excerpt-{evd(20)}"
    envelope = strict_json_parse(bounded_case_envelope(first))
    assert isinstance(envelope, dict)
    offered = {item.item_id: item.content for item in first.items if item.item_id != group}
    disclosure = review_packet_disclosure_result(
        assemble_filtered_review_packet(
            envelope,
            content_by_id=offered,
            included_item_ids=frozenset(offered),
            withheld_item_ids=frozenset({group}),
        )
    ).disclosure
    assert disclosure is not None and disclosure.privacy_withheld == {str(evd(20))}
    shown = sent_excerpt_content_refs(first, disclosure.provider_input_manifest)
    assert shown is not None and not {str(evd(20)), str(evd(21))} & shown
    withheld = withheld_excerpt_content_refs(first, disclosure.privacy_withheld)
    assert withheld == {str(evd(20)), str(evd(21))}
    # The check classifies either request as the same privacy limit.
    citable = semantic_case_packet_view(first).citable_refs
    for target in (str(evd(20)), str(evd(21))):
        assert target in citable
        classified = review_missing_for_assessment(
            group_case,
            (),
            SemanticJudgment(
                "insufficient_packet",
                (),
                missing_for_assessment=(
                    MissingForAssessment("verification_output", (target,), "The output."),
                ),
            ),
            unsuppliable_kinds=frozenset(),
            citable_refs=citable,
            privacy_withheld_refs=withheld,
        )
        assert [item.availability for item in classified.items] == [
            "structurally_unavailable_on_this_host"
        ]
    for target in (str(evd(20)), str(evd(21))):
        assert (
            plan_review_follow_up(
                group_case.projection,
                frozenset(str(ref) for ref in group_case.allowed_ids),
                (_requested("verification_output", target, availability="agent_suppliable"),),
                previous=None,
                shown_refs=shown,
                privacy_withheld_refs=withheld,
            )
            is None
        )


def test_a_follow_up_value_is_bounded() -> None:
    item = ReviewFollowUpItem("verification_output", (str(res(1)),), frozenset({str(evd(1))}))
    with pytest.raises(ValueError):
        ReviewFollowUp(0, (item,), frozenset())
    with pytest.raises(ValueError):
        ReviewFollowUp(MAX_REVIEW_FOLLOW_UP_ROUNDS + 1, (item,), frozenset())
    with pytest.raises(ValueError):
        ReviewFollowUp(1, (), frozenset())
    with pytest.raises(ValueError):
        ReviewFollowUpItem("other", (str(res(1)),), frozenset({str(evd(1))}))


# --- Every surface reads the round from the recorded manifest ---------------------------------


def _manifest_json(follow_up_round: int | None) -> dict[str, JsonValue]:
    case, _refs = _verification_case(20)
    first = _build(case)
    built = (
        first
        if follow_up_round is None
        else _build(case, follow_up=replace(_follow_up(case, _excerpt_refs(first)), round=2))
    )
    manifest = built.packet.input_manifest
    assert manifest is not None
    return {**review_input_manifest_to_json(manifest), "phase": "provider_bound"}


def test_receipt_cli_and_mcp_lines_name_the_round_and_what_was_added() -> None:
    lines = render_review_input_manifest_lines(_manifest_json(2))
    assert "follow-up round 2 of 3" in lines[0]
    assert any(
        line.startswith("Review follow-up (the reviewer's request in this check")
        and "verification_output=supplied; targets 1; supplied 3" in line
        for line in lines
    )
    assert "follow-up round 2 of 3" in render_review_input_manifest_compact(_manifest_json(2))
    plain = render_review_input_manifest_lines(_manifest_json(None))
    assert not any("follow-up" in line for line in plain)


def test_the_recorded_check_event_admits_only_a_bounded_round() -> None:
    case, _refs = _verification_case(20)
    first = _build(case)
    follow_up = _follow_up(case, _excerpt_refs(first))
    manifest = _build(case, follow_up=follow_up).packet.input_manifest
    assert manifest is not None
    from yoetz.domain import events as events_module

    decode = events_module._review_input_manifest_from_json  # pyright: ignore[reportPrivateUsage]
    body = review_input_manifest_to_json(manifest)
    assert decode(freeze_json(body)) is not None
    for invalid in (0, MAX_REVIEW_FOLLOW_UP_ROUNDS + 1, "1"):
        with pytest.raises(ValueError):
            decode(freeze_json({**body, "follow_up_round": invalid}))


# --- tb4n5: per part, the current section of a stale edit, and requests with no rows ----------

_PART = 4_096


def _split_capture_case() -> tuple[
    DeterministicCase, tuple[CapturedSemanticContent, ...], CapturedContentScope
]:
    """One captured edit (``evd(1)``) of about 18 KB: five 4 KiB parts under ``_small_parts``."""

    from unit.application.test_semantic_case import (
        _captured_case_values,  # pyright: ignore[reportPrivateUsage]
    )

    content = b"*** Begin Patch\n*** Add File: src/lib/store.ts\n" + b"".join(
        b"+export const s%05d = %05d;\n" % (row, row) for row in range(600)
    )
    case, captured, scope = _captured_case_values(content)
    captured = replace(
        captured,
        manifest=replace(captured.manifest, content_kind=ObservationContentKind.WORKSPACE_DIFF),
    )
    return case, (captured,), scope


def _small_parts() -> ReviewSelectionPolicy:
    """4 KiB excerpts within 16 KiB: the follow-up share (half) holds two parts."""

    return replace(_selection(), max_excerpt_bytes=_PART, max_total_excerpt_bytes=4 * _PART)


def _send_except(semantic: SemanticCase, room_cut: frozenset[str]) -> dict[str, JsonValue]:
    """The provider-bound manifest of a packet whose envelope bounding cut ``room_cut``."""

    envelope = strict_json_parse(bounded_case_envelope(semantic))
    assert isinstance(envelope, dict)
    catalog = envelope["item_catalog"]
    assert isinstance(catalog, list)
    envelope["item_catalog"] = [
        row for row in catalog if not (isinstance(row, dict) and row.get("item_id") in room_cut)
    ]
    content = {
        item.item_id: item.content for item in semantic.items if item.item_id not in room_cut
    }
    return _provider_manifest(
        assemble_filtered_review_packet(
            envelope, content_by_id=content, included_item_ids=frozenset(content)
        )
    )


def _part_id(number: int) -> str:
    return f"excerpt-{evd(1)}-part-{number:02d}"


def test_a_partly_shown_capture_adds_its_next_parts_never_the_one_shown() -> None:
    """tb4n5 react-lead-form: the first packet carried part 1 of the requested edit, so the
    per-ref rule called it shown and no round could ever add its other parts."""

    case, captured, scope = _split_capture_case()
    selection = _small_parts()
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    first = _build(
        case, selection=selection, captured_content=captured, captured_content_scope=scope
    )
    parts = dict(first.excerpt_parts)
    assert [item_id for item_id in parts if item_id.startswith(f"excerpt-{evd(1)}-part-")] == [
        _part_id(number) for number in (1, 2, 3, 4)
    ]
    # Room left the provider only the first part.
    sent = _send_except(first, frozenset({_part_id(2), _part_id(3), _part_id(4)}))
    shown = sent_excerpt_content_refs(first, sent)
    shown_parts = sent_excerpt_parts(first, sent)
    assert shown is not None and shown_parts is not None
    assert str(evd(1)) not in shown  # shown only in part
    assert parts[_part_id(1)] in shown_parts and parts[_part_id(2)] not in shown_parts
    request = (_requested("current_diff_for_path", str(evd(1))),)

    follow_up = plan_review_follow_up(
        case.projection,
        allowed,
        request,
        previous=None,
        shown_refs=shown,
        shown_parts=shown_parts,
    )

    assert follow_up is not None and follow_up.shown_parts == shown_parts
    again = _build(
        case,
        follow_up=follow_up,
        selection=selection,
        captured_content=captured,
        captured_content_scope=scope,
    )
    order = [ref.excerpt_item_id for ref in again.packet.targeted_excerpts]
    # The next two parts fill the share (8 KiB), ahead of the part the first packet showed.
    assert order[:2] == [_part_id(2), _part_id(3)]
    again_parts = dict(again.excerpt_parts)
    new = follow_up_new_parts(again, follow_up)
    assert {again_parts[_part_id(2)], again_parts[_part_id(3)]} <= new
    assert again_parts[_part_id(1)] not in new
    manifest = again.packet.input_manifest
    assert manifest is not None
    (row,) = manifest.missing_inputs
    assert (row.status, row.supplied_refs) == ("supplied", (str(evd(1)),))

    # Round 2: what round 1 sent keeps its place; nothing new fits the share, so the same parts
    # are never sent again and the request stays unanswered (the fifth part never fits).
    round_one = sent_excerpt_parts(again, _provider_manifest(_send(again)))
    assert round_one is not None
    after = replace(follow_up, added_parts=follow_up.unseen(round_one))
    assert after.added_parts == {again_parts[_part_id(number)] for number in (2, 3, 4)}
    second = plan_review_follow_up(
        case.projection, allowed, request, previous=after, shown_refs=None
    )
    assert second is not None and second.round == 2
    repeat = _build(
        case,
        follow_up=second,
        selection=selection,
        captured_content=captured,
        captured_content_scope=scope,
    )
    assert [ref.excerpt_item_id for ref in repeat.packet.targeted_excerpts][:2] == [
        _part_id(2),
        _part_id(3),
    ]
    assert follow_up_new_parts(repeat, second) == frozenset()


def test_a_privacy_withheld_part_is_never_served_again() -> None:
    case, captured, scope = _split_capture_case()
    selection = _small_parts()
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    first = _build(
        case, selection=selection, captured_content=captured, captured_content_scope=scope
    )
    sent = _send_except(first, frozenset({_part_id(2), _part_id(3), _part_id(4)}))
    request = (_requested("current_diff_for_path", str(evd(1))),)
    # A privacy rule withheld the capture from a sent packet: that rule holds for every packet.
    assert (
        plan_review_follow_up(
            case.projection,
            allowed,
            request,
            previous=None,
            shown_refs=sent_excerpt_content_refs(first, sent),
            shown_parts=sent_excerpt_parts(first, sent),
            privacy_withheld_refs=frozenset({str(evd(1))}),
        )
        is None
    )
    # A round that would carry only a category the channel withholds is never sent either.
    follow_up = plan_review_follow_up(
        case.projection,
        allowed,
        request,
        previous=None,
        shown_refs=sent_excerpt_content_refs(first, sent),
        shown_parts=sent_excerpt_parts(first, sent),
    )
    assert follow_up is not None
    again = _build(
        case,
        follow_up=follow_up,
        selection=selection,
        captured_content=captured,
        captured_content_scope=scope,
    )
    assert follow_up_new_parts(again, follow_up)
    assert not follow_up_new_parts(
        again, follow_up, withheld_categories=(DataCategory.EVIDENCE_EXCERPT.value,)
    )


_LEAD = "src/lib/leadStore.ts"


def _change_section(path: str, rows: int, marker: str) -> bytes:
    lines = "".join(f"+export const v{row:04d} = {row};\n" for row in range(rows))
    return (
        f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n"
        f"@@ -0,0 +1,{rows + 1} @@\n+// {marker}\n{lines}"
    ).encode()


def _stale_edit_case(
    *, lead_first: bool = False
) -> tuple[
    DeterministicCase, tuple[CapturedSemanticContent, ...], CapturedContentScope, CheckTimeChange
]:
    """A hook-captured edit that first added ``leadStore.ts`` (edited again since), and a
    check-time change of about 157 KB whose current ``leadStore.ts`` section lies past what one
    packet carries, unless ``lead_first``."""

    from unit.application.test_semantic_case import (
        _captured_case_values,  # pyright: ignore[reportPrivateUsage]
    )
    from unit.application.test_semantic_case_packet_completeness import (
        _change,  # pyright: ignore[reportPrivateUsage]
    )

    content = (
        f"*** Begin Patch\n*** Add File: {_LEAD}\n+// STALE_LEAD_STORE_MARKER\n*** End Patch\n"
    ).encode()
    case, captured, scope = _captured_case_values(content)
    captured = replace(
        captured,
        manifest=replace(captured.manifest, content_kind=ObservationContentKind.WORKSPACE_DIFF),
    )
    fillers = [
        _change_section(f"src/f{index:02d}.ts", 500, f"FILLER_{index}") for index in range(10)
    ]
    lead = _change_section(_LEAD, 200, "CURRENT_LEAD_STORE_MARKER")
    body = b"".join([lead, *fillers] if lead_first else [*fillers, lead])
    header = (
        b"Yoetz check-time change: captured by the Yoetz service when this check ran; the "
        b"agent did not supply it.\nEnd of header. The unified diff follows.\n"
    )
    return case, (captured,), scope, _change(header + body)


def _section_parts(
    case: DeterministicCase,
    captured: tuple[CapturedSemanticContent, ...],
    scope: CapturedContentScope,
    change: CheckTimeChange,
) -> Mapping[str, frozenset[str]]:
    """What a current-diff follow-up could serve, as the composition computes it."""

    return current_section_parts(
        change.capture, captured_edit_paths(case, captured, scope), workspace_root=None
    )


def test_a_stale_edit_request_is_answered_with_the_current_section_from_the_change() -> None:
    """tb4n5 react-lead-form: ``current_diff_for_path`` named the stale apply_patch that first
    added ``leadStore.ts``; only the frozen change held the current file."""

    case, captured, scope, change = _stale_edit_case()
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    section_parts = _section_parts(case, captured, scope, change)
    text = change.capture.text
    start = text.index(f"diff --git a/{_LEAD}".encode())
    lead_key = f"check-time-change#{start}-{len(text)}/{len(text)}"
    assert section_parts == {str(evd(1)): frozenset({lead_key})}
    first = _build(
        case, captured_content=captured, captured_content_scope=scope, check_time_change=change
    )
    first_sent = _provider_manifest(_send(first))
    shown = sent_excerpt_content_refs(first, first_sent)
    shown_parts = sent_excerpt_parts(first, first_sent)
    assert shown is not None and shown_parts is not None
    assert str(evd(1)) in shown  # the stale edit itself was shown whole
    assert b"CURRENT_LEAD_STORE_MARKER" not in _send(first)
    request = (_requested("current_diff_for_path", str(evd(1))),)

    follow_up = plan_review_follow_up(
        case.projection,
        allowed,
        request,
        previous=None,
        shown_refs=shown,
        shown_parts=shown_parts,
        section_parts=section_parts,
    )

    assert follow_up is not None
    again = _build(
        case,
        follow_up=follow_up,
        captured_content=captured,
        captured_content_scope=scope,
        check_time_change=change,
    )
    (section,) = (
        item for item in again.items if item.item_id.startswith(CHECK_TIME_SECTION_ITEM_PREFIX)
    )
    assert section.item_id == f"{CHECK_TIME_SECTION_ITEM_PREFIX}011"
    assert section.category is DataCategory.REPOSITORY_EXCERPT
    assert section.linked_subject_refs == (str(evd(1)),)
    marker, body = section.content.split(b"\n", 1)
    assert marker.startswith(b"[Yoetz check-time change, the current state of a file a requested")
    # Cut from the frozen change: exactly that section's bytes, placed in the change text.
    assert body == text[start:] and b"CURRENT_LEAD_STORE_MARKER" in body
    assert follow_up_new_parts(again, follow_up) == {lead_key}
    assert b"CURRENT_LEAD_STORE_MARKER" in _send(again)
    manifest = again.packet.input_manifest
    assert manifest is not None
    (row,) = manifest.missing_inputs
    assert (row.status, row.supplied_refs) == ("supplied", (str(evd(1)),))
    sent_again = _provider_manifest(_send(again))
    assert [entry["status"] for entry in cast(Any, sent_again["missing_inputs"])] == ["supplied"]
    # The change's own leading parts still come first.
    assert again.packet.targeted_excerpts[0].excerpt_item_id == "change-check-time-001"

    # Served once: nothing more is owed for that path, so no later round is even planned.
    round_one = sent_excerpt_parts(again, sent_again)
    assert round_one is not None
    after = replace(follow_up, added_parts=follow_up.unseen(round_one))
    assert (
        plan_review_follow_up(
            case.projection,
            allowed,
            request,
            previous=after,
            shown_refs=None,
            section_parts=section_parts,
        )
        is None
    )
    # A round that had to be built anyway keeps the section in place and never counts it new.
    repeat = _build(
        case,
        follow_up=replace(after, round=2),
        captured_content=captured,
        captured_content_scope=scope,
        check_time_change=change,
    )
    assert any(item.item_id == section.item_id for item in repeat.items)
    assert follow_up_new_parts(repeat, replace(after, round=2)) == frozenset()


def test_a_current_section_the_first_packet_carried_plans_no_round() -> None:
    """Checker P3 (tb4n5 fix review): the planner asks per requested path, so a section the
    first packet already carried never costs a rebuild just to find nothing new."""

    case, captured, scope, change = _stale_edit_case(lead_first=True)
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    first = _build(
        case, captured_content=captured, captured_content_scope=scope, check_time_change=change
    )
    first_sent = _provider_manifest(_send(first))
    assert b"CURRENT_LEAD_STORE_MARKER" in _send(first)
    shown_parts = sent_excerpt_parts(first, first_sent)
    assert shown_parts is not None
    # Other bytes of the change are still unseen; the requested path's are not.
    change_keys = [key for key in shown_parts if key.startswith("check-time-change#")]
    assert change_keys and not excerpt_span_whole(change_keys[0], change_keys)

    assert (
        plan_review_follow_up(
            case.projection,
            allowed,
            (_requested("current_diff_for_path", str(evd(1))),),
            previous=None,
            shown_refs=sent_excerpt_content_refs(first, first_sent),
            shown_parts=shown_parts,
            section_parts=_section_parts(case, captured, scope, change),
        )
        is None
    )


def test_a_served_current_section_is_part_of_the_raising_inventory() -> None:
    """Checker P1 (tb4n5 fix review): the follow-up packet showed the current ``leadStore.ts``
    through ``change-section-011``, but the shown-file record counted only the change's leading
    bytes and called itself complete, so a repair that never showed that file could clear a
    finding raised on it. The served section now joins the record; a repair lacking the file is
    not covered."""

    case, captured, scope, change = _stale_edit_case()
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    first = _build(
        case, captured_content=captured, captured_content_scope=scope, check_time_change=change
    )
    first_sent = _provider_manifest(_send(first))
    follow_up = plan_review_follow_up(
        case.projection,
        allowed,
        (_requested("current_diff_for_path", str(evd(1))),),
        previous=None,
        shown_refs=sent_excerpt_content_refs(first, first_sent),
        shown_parts=sent_excerpt_parts(first, first_sent),
        section_parts=_section_parts(case, captured, scope, change),
    )
    assert follow_up is not None
    again = _build(
        case,
        follow_up=follow_up,
        captured_content=captured,
        captured_content_scope=scope,
        check_time_change=change,
    )
    text = change.capture.text
    start = text.index(f"diff --git a/{_LEAD}".encode())
    carried = check_time_change_bytes_carried(again)
    assert carried < start  # the leading bytes stop before the file
    served = check_time_change_sections_carried(again)
    assert served == ((start, len(text)),)
    # A channel that withholds repository excerpts carries no section at all.
    assert (
        check_time_change_sections_carried(
            again, withheld_categories=(DataCategory.REPOSITORY_EXCERPT.value,)
        )
        == ()
    )

    leading_only, _ = check_time_change_shown_record(change.capture, carried)
    files, representable = check_time_change_shown_record(change.capture, carried, served)

    lead_identity = f"diff --git a/{_LEAD} b/{_LEAD}".encode()
    assert representable
    assert lead_identity not in {file.identity for file in leading_only}
    (lead,) = (file for file in files if file.identity == lead_identity)
    assert lead.whole and lead.section_admitted and lead.shown_bytes == len(text) - start
    assert [file for file in files if file.identity != lead_identity] == list(leading_only)
    # A gap inside what a file showed has no truthful view: left out, record incomplete.
    gapped = ((start + 200, len(text)),)
    holes, ok = check_time_change_shown_record(change.capture, carried, gapped)
    assert not ok and lead_identity not in {file.identity for file in holes}


@pytest.mark.anyio
async def test_a_repair_that_never_showed_the_served_file_does_not_cover_the_raising_review() -> (
    None
):
    from yoetz.application.check_change import check_change_shown_files

    class _Objects:
        async def commitment_for(self, data: bytes, kind: object) -> str:
            del kind
            return "hmac-sha256:" + hashlib.sha256(data).hexdigest()

    class _Runtime:
        objects = _Objects()

    _case, _captured, _scope, change = _stale_edit_case()
    change = CheckTimeChange(change.object_ref, replace(change.capture, base_commit="a" * 40))
    text = change.capture.text
    start = text.index(f"diff --git a/{_LEAD}".encode())
    carried = start - 10  # the leading bytes stop inside the file before leadStore.ts
    runtime = cast(Any, _Runtime())

    raised = await check_change_shown_files(runtime, change, carried, ((start, len(text)),))
    repair = await check_change_shown_files(runtime, change, carried)
    whole = await check_change_shown_files(runtime, change, len(text))
    gapped = await check_change_shown_files(runtime, change, carried, ((start + 200, len(text)),))

    assert raised.complete and repair.complete
    assert not repair.covers(raised)  # the repair never showed leadStore.ts
    assert whole.covers(raised)
    # Unrepresentable: incomplete, so no repair can claim to cover what that review saw.
    assert not gapped.complete and not whole.covers(gapped)


def test_a_request_naming_only_rows_yoetz_does_not_hold_plans_no_round() -> None:
    """tb4n5 react-lead-form 19:35:05: a request naming an obligation and the event that carried
    the task statement (no action, result or evidence row) rebuilt the case to send nothing."""

    case, _refs = _verification_case(20)
    targets = (str(evt(500)), "obl_00000000-0000-4000-8000-000000000099")
    allowed = frozenset(str(ref) for ref in case.allowed_ids) | frozenset(targets)

    assert (
        plan_review_follow_up(
            case.projection,
            allowed,
            (_requested("verification_output", *targets, availability="agent_suppliable"),),
            previous=None,
            shown_refs=frozenset(),
        )
        is None
    )
    # A target that names a recorded run still resolves to the run's rows only.
    follow_up = plan_review_follow_up(
        case.projection,
        allowed,
        (_requested("verification_output", *sorted((str(res(1)), *targets))),),
        previous=None,
        shown_refs=frozenset(),
    )
    assert follow_up is not None
    assert follow_up.items[0].source_refs == {str(res(1)), str(act(1)), str(evd(1))}


def test_parts_compare_by_byte_interval_so_a_different_split_never_counts_twice() -> None:
    """A narrowed case may split one source differently; the bytes, not part numbers, decide."""

    from yoetz.application.missing_for_assessment import (
        excerpt_span_covered,
        excerpt_span_key,
        excerpt_span_whole,
    )

    ref = str(evd(1))
    sent = [excerpt_span_key(ref, 0, 4_096, 12_000), excerpt_span_key(ref, 4_096, 8_192, 12_000)]
    assert excerpt_span_covered(excerpt_span_key(ref, 1_000, 8_000, 12_000), sent)
    assert not excerpt_span_covered(excerpt_span_key(ref, 6_000, 9_000, 12_000), sent)
    assert not excerpt_span_whole(sent[0], sent)
    assert excerpt_span_whole(sent[0], [*sent, excerpt_span_key(ref, 8_000, 12_000, 12_000)])
    # Another source, or the same ref over a different text length, is never the same bytes.
    assert not excerpt_span_covered(excerpt_span_key(str(evd(2)), 0, 10, 12_000), sent)
    assert not excerpt_span_covered(excerpt_span_key(ref, 0, 10, 13_000), sent)
    with pytest.raises(ValueError):
        excerpt_span_key(ref, 5, 5, 10)
    follow_up = ReviewFollowUp(
        1,
        (ReviewFollowUpItem("current_diff_for_path", (ref,), frozenset({ref})),),
        frozenset(),
        shown_parts=frozenset(sent[:1]),
        added_parts=frozenset(sent[1:]),
    )
    assert follow_up.unseen([*sent, excerpt_span_key(ref, 8_192, 12_000, 12_000)]) == {
        excerpt_span_key(ref, 8_192, 12_000, 12_000)
    }


# --- Checker P2: a part's identity is its bytes in the source, whatever the selection ---------


def test_a_narrowed_selection_keeps_the_identity_of_a_byte_identical_part() -> None:
    """The same 4 KiB first part keeps its key when a narrowed case allows fewer parts, so a
    follow-up built under the narrower selection never counts the part already shown as new."""

    case, captured, scope = _split_capture_case()
    wide = _small_parts()
    narrow = replace(wide, max_excerpts=2)
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    first = _build(case, selection=wide, captured_content=captured, captured_content_scope=scope)
    narrowed = _build(
        case, selection=narrow, captured_content=captured, captured_content_scope=scope
    )
    wide_parts = dict(first.excerpt_parts)
    narrow_parts = dict(narrowed.excerpt_parts)
    assert wide_parts[_part_id(1)] == narrow_parts[_part_id(1)]
    total = int(wide_parts[_part_id(1)].rsplit("/", 1)[1])
    assert total == len(captured[0].content)  # the capture's own length, not the selection's
    sent = _send_except(first, frozenset({_part_id(2), _part_id(3), _part_id(4)}))
    follow_up = plan_review_follow_up(
        case.projection,
        allowed,
        (_requested("current_diff_for_path", str(evd(1))),),
        previous=None,
        shown_refs=sent_excerpt_content_refs(first, sent),
        shown_parts=sent_excerpt_parts(first, sent),
    )
    assert follow_up is not None

    again = _build(
        case,
        follow_up=follow_up,
        selection=narrow,
        captured_content=captured,
        captured_content_scope=scope,
    )

    again_parts = dict(again.excerpt_parts)
    new = follow_up_new_parts(again, follow_up)
    assert wide_parts[_part_id(1)] not in new
    assert again_parts[_part_id(2)] in new


def test_a_head_and_tail_clip_holds_two_intervals_never_the_whole_source() -> None:
    """An 8,000-byte output clipped to 1 KiB keeps its head and its tail; the elided middle is
    never credited, so the source is not shown whole and stays answerable."""

    from yoetz.application import semantic_case as semantic_case_module

    output = "".join(f"line {row:05d} of the long run\n" for row in range(300))[:8_000]
    case = make_case(
        evidence={
            evd(1): evidence_record(
                EvidenceRecordedPayload(
                    evd(1),
                    EvidenceKind.TEST_RESULT,
                    EvidenceImmutability.METADATA_ONLY,
                    _WHEN,
                    description=output,
                ),
                2,
            )
        },
        claims={
            clm(1): record(
                ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "The run passed", (evd(1),)),
                3,
            )
        },
        extra_refs=(clm(1),),
    )
    selection = replace(_selection(), max_excerpt_bytes=1_024)
    semantic = _build(case, selection=selection)
    keys = [key for item_id, key in semantic.excerpt_parts if item_id == f"excerpt-{evd(1)}"]
    assert len(keys) == 2
    head, tail = sorted(keys, key=lambda key: int(key.split("#")[1].split("-")[0]))
    assert head.startswith(f"{evd(1)}#0-") and head.endswith("/8000")
    assert tail.endswith("-8000/8000")
    sent = _provider_manifest(_send(semantic))
    shown = sent_excerpt_content_refs(semantic, sent)
    assert shown is not None and str(evd(1)) not in shown
    assert set(keys) <= (sent_excerpt_parts(semantic, sent) or frozenset())
    # The helper's intervals are exactly the bytes the clip kept.
    raw = output.encode()
    kept_fn = getattr(semantic_case_module, "_head_tail_kept")
    text, kept = kept_fn(raw, 1_024)
    (low_h, high_h), (low_t, high_t) = kept
    assert low_h == 0 and text.encode().startswith(raw[:high_h])
    assert high_t == len(raw) and text.encode().endswith(raw[low_t:])
    assert high_h < low_t


def test_admission_that_drops_every_new_part_leaves_the_request_pending_and_sends_nothing() -> None:
    """Checker P3 (tb4n5 fix review): the first packet sent part 1; the follow-up composed parts
    2 to 4, and admission dropped all three but kept part 1. ``supplied`` was ref-based, so the
    provider manifest still said supplied, and the gate counted the composed case. Both now count
    only marked parts that admission kept."""

    case, captured, scope = _split_capture_case()
    selection = _small_parts()
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    first = _build(
        case, selection=selection, captured_content=captured, captured_content_scope=scope
    )
    sent = _send_except(first, frozenset({_part_id(2), _part_id(3), _part_id(4)}))
    follow_up = plan_review_follow_up(
        case.projection,
        allowed,
        (_requested("current_diff_for_path", str(evd(1))),),
        previous=None,
        shown_refs=sent_excerpt_content_refs(first, sent),
        shown_parts=sent_excerpt_parts(first, sent),
    )
    assert follow_up is not None
    again = _build(
        case,
        follow_up=follow_up,
        selection=selection,
        captured_content=captured,
        captured_content_scope=scope,
    )
    new_ids = frozenset({_part_id(2), _part_id(3), _part_id(4)})
    assert again.follow_up_supplied_item_ids == new_ids

    # Admission keeps every row but the new parts: the old part 1 still travels.
    envelope = strict_json_parse(bounded_case_envelope(again))
    assert isinstance(envelope, dict)
    catalog = envelope["item_catalog"]
    assert isinstance(catalog, list)
    envelope["item_catalog"] = [
        row for row in catalog if not (isinstance(row, dict) and row.get("item_id") in new_ids)
    ]
    content = {item.item_id: item.content for item in again.items if item.item_id not in new_ids}
    prepared = assemble_filtered_review_packet(
        envelope, content_by_id=content, included_item_ids=frozenset(content)
    )
    result = review_packet_disclosure_result(prepared)
    assert result.failure is None and result.disclosure is not None
    provider = result.disclosure.provider_input_manifest
    assert provider is not None
    assert _part_id(1) in cast(Any, provider["current_diff"])["item_ids"]
    ((row),) = cast(Any, provider["missing_inputs"])
    assert (row["kind"], row["status"], tuple(row["supplied_refs"])) == (
        "current_diff_for_path",
        "pending",
        (),
    )
    # Composed alone, the round would add parts; counted over what admission keeps, nothing.
    assert follow_up_new_parts(again, follow_up)
    kept = frozenset(item.item_id for item in again.items) - new_ids
    assert follow_up_new_parts(again, follow_up, carried_item_ids=kept) == frozenset()
    # With the new parts kept, the same packet says supplied and the reader agrees.
    full = review_packet_disclosure_result(_send(again))
    assert full.failure is None and full.disclosure is not None
    assert full.disclosure.provider_input_manifest is not None
    assert [
        entry["status"]
        for entry in cast(Any, full.disclosure.provider_input_manifest["missing_inputs"])
    ] == ["supplied"]
