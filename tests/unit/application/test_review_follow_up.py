"""In-check follow-up: Yoetz answers the reviewer's own request from its records (issue #1047).

The reviewer named content it needed (``missing_for_assessment``) that Yoetz holds but the packet
did not carry. The planner decides what Yoetz may add, the case builder ranks those excerpts first
within a bounded share, and the input manifest says, on every surface, which round this is and
what was added. Without a follow-up nothing about the packet changes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import replace

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
    plan_review_follow_up,
    review_missing_for_assessment,
)
from yoetz.application.semantic_case import (
    CapturedContentScope,
    CapturedSemanticContent,
    assemble_filtered_review_packet,
    bounded_case_envelope,
    build_semantic_case,
    excerpt_content_refs,
    follow_up_byte_budget,
    review_input_manifest_to_json,
    review_packet_disclosure_result,
    semantic_case_packet_view,
    sent_excerpt_content_refs,
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
from yoetz.protocol.models import MAX_REVIEW_FOLLOW_UP_ROUNDS

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
    assert [row["status"] for row in rows if isinstance(row, dict)] == ["pending"]


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
    shown = sent_excerpt_content_refs(semantic, _provider_manifest(_send(semantic)))
    assert shown is not None and str(evd(21)) in shown
    # Shown already: a request naming the second part sends no round.
    assert (
        plan_review_follow_up(
            case.projection,
            allowed,
            (_requested("verification_output", str(evd(21))),),
            previous=None,
            shown_refs=shown,
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
