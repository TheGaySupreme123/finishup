"""#1230: a packet over an approved bound at disclosure leaves out excerpts and is reviewed.

Composition sizes excerpts as disclosure measures them, so these cases reach the bound another
way: the owner narrowed the excerpt limits after the case was composed, or the reviewer exchange
has less room than planned. Disclosure never cuts an excerpt: it leaves out the lowest-ranked ones
whole, never the check-time change, and refuses what that cannot fit. Each case runs the
production ``LocalPrivacyEnforcer`` and the privacy coordinator up to the stored proposal;
nothing is dispatched.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

import pytest

import finishup.application.egress as egress
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.application.egress import (
    PrivacyCoordinator,
    ReviewerExchangeFrame,
    ReviewerHistory,
    SemanticEgressBlocked,
)
from finishup.application.semantic_case import (
    CHECK_TIME_CHANGE_ITEM_PREFIX,
    excerpt_content_refs,
    review_packet_disclosure_result,
    sent_excerpt_content_refs,
    sent_excerpt_parts,
)
from finishup.domain.privacy import (
    EgressChannel,
    PrivacyPolicy,
    PrivacyReason,
    ReviewContextProfile,
)
from finishup.domain.review_input_render import render_review_input_manifest_lines
from finishup.domain.reviewer_context import ReviewerExchangeBudget
from finishup.ports.change_capture import TaskInputFile
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.privacy import (
    DisclosureProposalRequest,
    HumanAuthorityCapability,
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyPolicyStorePort,
)
from finishup.ports.semantic import (
    Deadline,
    SemanticCase,
    encode_reviewer_exchange,
    reviewer_packet_bytes,
)
from unit.application.test_egress_origin_operation import (
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _Gateway,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_semantic_case_disclosed_size import (
    _build,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _Audit,  # pyright: ignore[reportPrivateUsage]
    _candidate,  # pyright: ignore[reportPrivateUsage]
)

_PLANTED = b'password = "hunter2"\n'
_FILLER = b"Requirement line: reject bad input and keep the tail verdict.\n"
_CHANGE_PART = f"{CHECK_TIME_CHANGE_ITEM_PREFIX}001"
_TASK_INPUT = "task-input-01"
# The codex review round 1 reproduction: a cut at 8,086 bytes that keeps the value's line tail
# and drops its ``password =`` label.
_LABEL_CUT_INPUT = b"HEAD\n" + b"a" * 8_000 + b"\n" + _PLANTED + b"b" * 3_980 + b"\nTAIL\n"
_LABEL_CUT_BOUND = 8_086


def _spec_case(spec: bytes | None = None) -> SemanticCase:
    """A change plus a whole task input (12 KB by default) with a credential in it."""

    if spec is None:
        spec = b"SPEC HEAD\n" + _PLANTED + _FILLER * (12_000 // len(_FILLER)) + b"SPEC TAIL\n"
    return _build(inputs=(TaskInputFile("DESIGN.md", spec, len(spec)),))


def _policy(**selection: int) -> PrivacyPolicy:
    policy = _Store()._policy  # pyright: ignore[reportPrivateUsage]
    return replace(
        policy,
        review_context_profile=ReviewContextProfile.CUSTOM,
        review_selection=replace(policy.review_selection, **selection),
        # Room for the whole composed case: the bounds under test are the ones narrowed below.
        channel_policies=tuple(
            replace(channel, max_tokens=65_536)
            if channel.channel is EgressChannel.LLM_INFERENCE
            else channel
            for channel in policy.channel_policies
        ),
    )


def _render(packet: bytes) -> bytes:
    return encode_reviewer_exchange((("system", "review the packet"), ("user", packet.decode())))


async def _coordinate(
    case: SemanticCase,
    policy: PrivacyPolicy,
    monkeypatch: pytest.MonkeyPatch,
    *,
    budget: ReviewerExchangeBudget | None = None,
    history: ReviewerHistory | None = None,
) -> tuple[object, _Audit, list[dict[str, object]]]:
    store = _Store()
    store._policy = policy  # pyright: ignore[reportPrivateUsage]
    audit = _Audit()
    events: list[dict[str, object]] = []

    def record(**kwargs: object) -> str:
        events.append(kwargs)
        return ""

    monkeypatch.setattr(egress, "record_bounded_counts_without_raising", record)
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, store),
        LocalPrivacyEnforcer(),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, _Gateway()),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=HumanAuthorityCapability(
            "established_passphrase", "sha256:" + "8" * 64, 1, "passphrase", 1, True
        ),
    )
    result = await coordinator.evaluate_semantic(
        _candidate(case),
        Deadline(datetime(2026, 10, 8, 17, 8, tzinfo=UTC), 61.0),
        exchange=ReviewerExchangeFrame(
            "application/vnd.finishup.reviewer-final+json",
            _render,
            history=history,
            budget=budget,
        ),
    )
    return result, audit, events


async def _evaluate(
    case: SemanticCase,
    policy: PrivacyPolicy,
    monkeypatch: pytest.MonkeyPatch,
    *,
    budget: ReviewerExchangeBudget | None = None,
    history: ReviewerHistory | None = None,
) -> tuple[DisclosureProposalRequest, bytes, list[dict[str, object]]]:
    result, audit, events = await _coordinate(
        case, policy, monkeypatch, budget=budget, history=history
    )
    # The fake audit stops right after the proposal is stored: the packet was admitted.
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.AUDIT_FAILED
    assert result.capacity is None
    (proposal,) = audit.prepared
    packet = reviewer_packet_bytes(proposal.minimized.prepared_bytes)
    assert packet is not None
    return proposal, packet, events


def _excerpt_rows(packet: bytes) -> dict[str, dict[str, object]]:
    document = cast(dict[str, object], json.loads(packet))
    return {
        cast(str, row["item_id"]): row
        for row in cast(list[dict[str, object]], document["items"])
        if row["section"] == "excerpt"
    }


def _provider_manifest(packet: bytes) -> dict[str, object]:
    """The provider-bound manifest, checked to re-derive from the sent packet alone."""

    result = review_packet_disclosure_result(packet)
    assert result.failure is None and result.disclosure is not None
    assert result.disclosure.provider_input_manifest is not None
    document = cast(dict[str, object], json.loads(packet))
    return cast(
        dict[str, object],
        cast(dict[str, object], document["review_packet"])["provider_input_manifest"],
    )


def _omissions(packet: bytes) -> set[tuple[str, str]]:
    document = cast(dict[str, object], json.loads(packet))
    rows = cast(
        list[dict[str, str]], cast(dict[str, object], document["review_packet"])["omissions"]
    )
    return {(row["subject_ref"], row["reason"]) for row in rows}


def _fitted(events: list[dict[str, object]]) -> dict[str, object]:
    (event,) = [e for e in events if e["operation"] == "semantic_disclosure_capacity_fitted"]
    return event


def _assert_task_input_not_selected(packet: bytes, roomy: bytes) -> None:
    """The task input's own section names it not selected, by identity, never as withheld."""

    composed = cast(dict[str, object], _provider_manifest(roomy)["caller_evidence"])
    assert _TASK_INPUT in cast(list[str], composed["item_ids"])
    section = cast(dict[str, object], _provider_manifest(packet)["caller_evidence"])
    assert section["item_ids"] == []
    assert section["status"] == "not_selected"
    assert "not_selected" in cast(list[str], section["omission_reasons"])
    assert "withheld_by_policy" not in cast(list[str], section["omission_reasons"])
    assert "task-input" in cast(list[str], section["omitted_refs"])
    # Every surface renders the manifest through the same lines: none says "withheld" for it.
    lines = render_review_input_manifest_lines(_provider_manifest(packet))
    (line,) = [line for line in lines if "caller_evidence" in line]
    assert "not_selected" in line and "withheld" not in line
    # Every row the fit adds reads room, and the left-out input adds none naming a linked claim
    # or obligation (those were not left out).
    added = _omissions(packet) - _omissions(roomy)
    assert {reason for _subject, reason in added} <= {"not_selected"}
    linked = set(
        next(item for item in _spec_case().items if item.item_id == _TASK_INPUT).linked_subject_refs
    )
    assert not {subject for subject, _reason in added} & linked


@pytest.mark.anyio
async def test_an_excerpt_over_a_narrowed_per_excerpt_bound_is_left_out_whole(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _spec_case()
    composed = next(item for item in case.items if item.item_id == _TASK_INPUT)
    assert composed.content_bytes > 8_192
    _, roomy, _ = await _evaluate(case, _policy(), monkeypatch)
    proposal, packet, events = await _evaluate(case, _policy(max_excerpt_bytes=8_192), monkeypatch)
    rows = _excerpt_rows(packet)
    # Never cut at disclosure: the over-bound input is not sent at all; the change still is.
    assert _TASK_INPUT not in rows and _CHANGE_PART in rows
    assert _TASK_INPUT not in proposal.minimized.included_item_ids
    assert proposal.minimized.withheld_item_ids == ()
    assert b"hunter2" not in proposal.minimized.prepared_bytes
    assert all(cast(int, row["content_bytes"]) <= 8_192 for row in rows.values())
    _assert_task_input_not_selected(packet, roomy)
    # Finding 2: what an in-check follow-up reads as shown comes from what was sent. The roomy
    # packet showed the input whole; the fitted one showed none of it, so a follow-up may add it.
    input_refs = excerpt_content_refs((composed,))
    roomy_sent = sent_excerpt_content_refs(case, _provider_manifest(roomy))
    sent = sent_excerpt_content_refs(case, _provider_manifest(packet))
    assert roomy_sent is not None and sent is not None
    assert input_refs <= roomy_sent and not input_refs <= sent
    # Only parts of what was sent are carried: the left-out input contributes none.
    assert sent_excerpt_parts(case, _provider_manifest(packet)) == frozenset(
        key for item_id, key in case.excerpt_parts if item_id in rows
    )
    fitted = _fitted(events)
    assert fitted["outcome"] == "fitted"
    assert fitted["counts"] == {"semantic_excerpts_unselected_at_disclosure": 1}


@pytest.mark.anyio
async def test_a_label_cut_never_exposes_its_value_at_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Codex review round 1, P1: a cut keeping ``hunter2`` without its ``password =`` label."""

    case = _spec_case(_LABEL_CUT_INPUT)
    composed = next(item for item in case.items if item.item_id == _TASK_INPUT)
    assert composed.content_bytes > _LABEL_CUT_BOUND
    _, roomy, _ = await _evaluate(case, _policy(), monkeypatch)
    proposal, packet, _ = await _evaluate(
        case, _policy(max_excerpt_bytes=_LABEL_CUT_BOUND), monkeypatch
    )
    assert b"hunter2" not in proposal.minimized.prepared_bytes
    assert _TASK_INPUT not in _excerpt_rows(packet)
    _assert_task_input_not_selected(packet, roomy)


@pytest.mark.anyio
async def test_excerpts_beyond_a_narrowed_count_leave_out_the_lowest_ranked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _spec_case()
    order = [ref.excerpt_item_id for ref in case.packet.targeted_excerpts]
    assert order[0] == _CHANGE_PART and _TASK_INPUT in order
    _, roomy, _ = await _evaluate(case, _policy(), monkeypatch)
    left_out = [item_id for item_id in _excerpt_rows(roomy) if item_id != _CHANGE_PART]
    assert _TASK_INPUT in left_out
    proposal, packet, events = await _evaluate(case, _policy(max_excerpts=1), monkeypatch)
    # The service's own change ranks first and is kept; every lower-ranked excerpt is left out.
    assert list(_excerpt_rows(packet)) == [_CHANGE_PART]
    assert proposal.minimized.withheld_item_ids == ()
    # Each left-out excerpt with an own subject is a ``not_selected`` omission: room, never a
    # privacy withholding, even the task input whose value egress would have replaced.
    added = _omissions(packet) - _omissions(roomy)
    assert {reason for _subject, reason in added} <= {"not_selected"}
    _assert_task_input_not_selected(packet, roomy)
    assert _fitted(events)["counts"] == {
        "semantic_excerpts_unselected_at_disclosure": len(left_out)
    }


@pytest.mark.anyio
async def test_an_exchange_over_its_budget_leaves_out_excerpts_to_fit_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _spec_case()
    roomy, _, _ = await _evaluate(case, _policy(), monkeypatch)
    limit = roomy.minimized.byte_count - 4_000
    proposal, packet, events = await _evaluate(
        case, _policy(), monkeypatch, budget=ReviewerExchangeBudget(limit)
    )
    assert proposal.minimized.byte_count <= limit
    rows = _excerpt_rows(packet)
    assert _CHANGE_PART in rows and _TASK_INPUT not in rows
    assert b"hunter2" not in proposal.minimized.prepared_bytes
    fitted = _fitted(events)
    assert fitted["outcome"] == "fitted"
    assert cast(dict[str, int], fitted["counts"])["semantic_excerpts_unselected_at_disclosure"] >= 1


@pytest.mark.anyio
async def test_a_change_over_a_narrowed_bound_is_refused_never_cut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The change under review is never left out or cut, so no fit can trade it away."""

    change = next(item for item in _spec_case().items if item.item_id == _CHANGE_PART)
    result, audit, events = await _coordinate(
        _spec_case(), _policy(max_excerpt_bytes=change.content_bytes - 1), monkeypatch
    )
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.POLICY_DENIED
    assert result.capacity is not None and result.capacity_scope == "excerpt"
    assert audit.prepared == []
    assert not [e for e in events if e["operation"] == "semantic_disclosure_capacity_fitted"]


@pytest.mark.anyio
async def test_a_later_exchange_replays_the_first_exchanges_fit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every exchange re-admits the packet and must extend the last one byte for byte."""

    case = _spec_case()
    roomy, roomy_packet, _ = await _evaluate(case, _policy(), monkeypatch)
    limit = roomy.minimized.byte_count - 4_000
    history = ReviewerHistory()
    _, first, events = await _evaluate(
        case, _policy(), monkeypatch, budget=ReviewerExchangeBudget(limit), history=history
    )
    assert first != roomy_packet
    assert history.policy is not None and history.capacity_left_out
    assert len([e for e in events if e["operation"] == "semantic_disclosure_capacity_fitted"]) == 1
    # A later exchange has room again (say a smaller read result): the packet is still the one
    # the first exchange sent, not refitted and not restored.
    _, later, later_events = await _evaluate(case, _policy(), monkeypatch, history=history)
    assert later == first
    assert not [e for e in later_events if e["operation"] == "semantic_disclosure_capacity_fitted"]


def test_the_fit_plan_never_leaves_out_the_change_or_a_served_change_section() -> None:
    """The shown-file record counts both, composed before disclosure, so neither is shed."""

    section = "change-section-001-part-01"
    packet = json.dumps(
        {
            "items": [
                {"section": "excerpt", "item_id": _CHANGE_PART, "content_bytes": 4_000},
                {"section": "excerpt", "item_id": section, "content_bytes": 3_000},
                {"section": "excerpt", "item_id": _TASK_INPUT, "content_bytes": 2_000},
            ]
        }
    ).encode()
    plan = egress._capacity_fit_plan  # pyright: ignore[reportPrivateUsage]
    overage = egress._CapacityOverage  # pyright: ignore[reportPrivateUsage]
    # Room for two excerpts: the lowest-ranked one that is neither is left out.
    assert plan(packet, overage((), 1, 0), frozenset()) == frozenset({_TASK_INPUT})
    # More bytes than the others hold: nothing can fit without the change's sections.
    assert plan(packet, overage((), 0, 2_500), frozenset()) is None
    # A served section over the per-excerpt bound is refused whole, never cut or left out.
    assert plan(packet, overage((section,), 0, 0), frozenset()) is None
