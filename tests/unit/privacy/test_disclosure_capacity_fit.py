"""#1230: a packet over an approved bound at disclosure is shrunk and reviewed, not refused.

Composition sizes excerpts as disclosure measures them, so these cases reach the bound another
way: the owner narrowed the excerpt limits after the case was composed, or the reviewer exchange
has less room than planned. Each runs the production ``LocalPrivacyEnforcer`` and the privacy
coordinator up to the stored proposal; nothing is dispatched.
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
    review_packet_disclosure_result,
)
from finishup.domain.privacy import (
    EgressChannel,
    PrivacyPolicy,
    PrivacyReason,
    ReviewContextProfile,
)
from finishup.domain.reviewer_context import ReviewerExchangeBudget
from finishup.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER
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


def _spec_case() -> SemanticCase:
    """A change plus a whole 12 KB task input with a credential near its head."""

    body = b"SPEC HEAD\n" + _PLANTED + _FILLER * (12_000 // len(_FILLER))
    spec = body + b"SPEC TAIL\n"
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


async def _evaluate(
    case: SemanticCase,
    policy: PrivacyPolicy,
    monkeypatch: pytest.MonkeyPatch,
    *,
    budget: ReviewerExchangeBudget | None = None,
    history: ReviewerHistory | None = None,
) -> tuple[DisclosureProposalRequest, bytes, list[dict[str, object]]]:
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


def _manifest_sections(packet: bytes) -> dict[str, dict[str, object]]:
    """The provider-bound manifest, checked to re-derive from the sent packet alone."""

    result = review_packet_disclosure_result(packet)
    assert result.failure is None and result.disclosure is not None
    assert result.disclosure.provider_input_manifest is not None
    document = cast(dict[str, object], json.loads(packet))
    manifest = cast(
        dict[str, object],
        cast(dict[str, object], document["review_packet"])["provider_input_manifest"],
    )
    return {
        name: cast(dict[str, object], section)
        for name, section in manifest.items()
        if isinstance(section, dict)
    }


def _omissions(packet: bytes) -> set[tuple[str, str]]:
    document = cast(dict[str, object], json.loads(packet))
    rows = cast(
        list[dict[str, str]], cast(dict[str, object], document["review_packet"])["omissions"]
    )
    return {(row["subject_ref"], row["reason"]) for row in rows}


def _fitted(events: list[dict[str, object]]) -> dict[str, object]:
    (event,) = [e for e in events if e["operation"] == "semantic_disclosure_capacity_fitted"]
    return event


@pytest.mark.anyio
async def test_an_excerpt_over_a_narrowed_per_excerpt_bound_is_cut_to_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _spec_case()
    composed = next(item for item in case.items if item.item_id == "task-input-01")
    assert composed.content_bytes > 8_192
    _, roomy, _ = await _evaluate(case, _policy(), monkeypatch)
    (whole,) = [
        section
        for section in _manifest_sections(roomy).values()
        if "task-input-01" in cast(list[str], section["item_ids"])
    ]
    assert "truncated_payload" not in cast(list[str], whole["omission_reasons"])
    proposal, packet, events = await _evaluate(case, _policy(max_excerpt_bytes=8_192), monkeypatch)
    rows = _excerpt_rows(packet)
    row = rows["task-input-01"]
    content = cast(str, row["content"])
    # Cut to the bound with the ordinary marker, head and tail kept, the value still replaced.
    assert cast(int, row["content_bytes"]) <= 8_192
    assert "bytes elided here; head and tail kept" in content
    assert "SPEC HEAD" in content and "SPEC TAIL" in content
    assert EGRESS_CREDENTIAL_PLACEHOLDER.decode() in content
    assert b"hunter2" not in proposal.minimized.prepared_bytes
    assert all(cast(int, item["content_bytes"]) <= 8_192 for item in rows.values())
    assert (
        egress._excerpt_limit_capacity(  # pyright: ignore[reportPrivateUsage]
            packet, _policy(max_excerpt_bytes=8_192).review_selection
        )
        is None
    )
    # The cut is disclosed in the provider-bound manifest section that carries the input.
    (section,) = [
        section
        for section in _manifest_sections(packet).values()
        if "task-input-01" in cast(list[str], section["item_ids"])
    ]
    assert section["status"] == "partial"
    assert "truncated_payload" in cast(list[str], section["omission_reasons"])
    fitted = _fitted(events)
    assert fitted["outcome"] == "fitted"
    assert fitted["counts"] == {
        "semantic_excerpts_cut_at_disclosure": 1,
        "semantic_excerpts_unselected_at_disclosure": 0,
    }


@pytest.mark.anyio
async def test_excerpts_beyond_a_narrowed_count_leave_out_the_lowest_ranked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _spec_case()
    order = [ref.excerpt_item_id for ref in case.packet.targeted_excerpts]
    assert order[0] == _CHANGE_PART and "task-input-01" in order
    proposal, packet, events = await _evaluate(case, _policy(max_excerpts=1), monkeypatch)
    # The service's own change ranks first and is kept; every lower-ranked excerpt is left out.
    assert list(_excerpt_rows(packet)) == [_CHANGE_PART]
    assert "task-input-01" not in proposal.minimized.included_item_ids
    _, roomy, _ = await _evaluate(case, _policy(), monkeypatch)
    left_out = [item_id for item_id in _excerpt_rows(roomy) if item_id != _CHANGE_PART]
    assert "task-input-01" in left_out
    added = _omissions(packet) - _omissions(roomy)
    # Each excerpt left out is a ``not_selected`` omission: room, never a privacy withholding,
    # even the task input whose credential-like value egress would otherwise have replaced.
    assert added and {reason for _subject, reason in added} == {"not_selected"}
    assert proposal.minimized.withheld_item_ids == ()
    sections = _manifest_sections(packet)
    assert any(
        "not_selected" in cast(list[str], section["omission_reasons"])
        for section in sections.values()
    )
    assert _fitted(events)["counts"] == {
        "semantic_excerpts_cut_at_disclosure": 0,
        "semantic_excerpts_unselected_at_disclosure": len(left_out),
    }


@pytest.mark.anyio
async def test_an_exchange_over_its_budget_is_shrunk_to_fit_it(
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
    # The change under review is still carried.
    assert _CHANGE_PART in rows
    assert b"hunter2" not in proposal.minimized.prepared_bytes
    fitted = _fitted(events)
    assert fitted["outcome"] == "fitted"
    counts = cast(dict[str, int], fitted["counts"])
    assert (
        counts["semantic_excerpts_cut_at_disclosure"]
        + counts["semantic_excerpts_unselected_at_disclosure"]
        >= 1
    )


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
    assert history.policy is not None and history.capacity_fit is not None
    assert len([e for e in events if e["operation"] == "semantic_disclosure_capacity_fitted"]) == 1
    # A later exchange has room again (say a smaller read result): the packet is still the one
    # the first exchange sent, not refitted and not restored.
    _, later, later_events = await _evaluate(case, _policy(), monkeypatch, history=history)
    assert later == first
    assert not [e for e in later_events if e["operation"] == "semantic_disclosure_capacity_fitted"]
