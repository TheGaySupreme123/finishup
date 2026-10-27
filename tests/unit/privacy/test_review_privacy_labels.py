"""#1138/#1142: real transformed packets and rendered exchanges, with no provider or service."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from typing import Literal, cast

import pytest

import finishup.application.egress as egress
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.application.egress import (
    PrivacyCoordinator,
    ReviewerExchangeFrame,
    SemanticEgressBlocked,
)
from finishup.application.semantic_case import review_packet_disclosure_result
from finishup.domain.privacy import (
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyReason,
    ReviewContextProfile,
)
from finishup.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.privacy import (
    HumanAuthorityCapability,
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyPolicyStorePort,
)
from finishup.ports.semantic import Deadline, encode_reviewer_exchange, reviewer_packet_bytes
from unit.application.test_egress_origin_operation import (
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _Gateway,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _Audit,  # pyright: ignore[reportPrivateUsage]
    _candidate,  # pyright: ignore[reportPrivateUsage]
    _minimize_everything,  # pyright: ignore[reportPrivateUsage]
    _semantic_case,  # pyright: ignore[reportPrivateUsage]
)

_DIFF = b"diff --git a/config.py b/config.py\n+retries=3\n+password=hunter2\n"


def _render(packet: bytes, *, secret: bool = False) -> bytes:
    instruction = "review the packet" + (" sk-" + "a1" * 20 if secret else "")
    return encode_reviewer_exchange((("system", instruction), ("user", packet.decode())))


async def _evaluate(
    *, policy: PrivacyPolicy | None = None, secret_in_frame: bool = False
) -> tuple[object, _Audit]:
    store = _Store()
    if policy is not None:
        store._policy = policy  # pyright: ignore[reportPrivateUsage]
    audit = _Audit()
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
        _candidate(_semantic_case(_DIFF, with_aws_key=False)),
        Deadline(datetime(2026, 10, 8, 17, 8, tzinfo=UTC), 61.0),
        exchange=ReviewerExchangeFrame(
            "application/vnd.finishup.reviewer-final+json",
            lambda packet: _render(packet, secret=secret_in_frame),
        ),
    )
    return result, audit


@pytest.mark.anyio
async def test_a_replaced_value_reaches_preparation_through_the_final_exchange_scan() -> None:
    result, audit = await _evaluate()
    # The audit stops at preparation; no gateway or provider is invoked.
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.AUDIT_FAILED
    (proposal,) = audit.prepared
    assert EGRESS_CREDENTIAL_PLACEHOLDER in proposal.minimized.prepared_bytes
    assert b"hunter2" not in proposal.minimized.prepared_bytes
    assert b"retries=3" in proposal.minimized.prepared_bytes
    assert proposal.minimized.redacted_span_count == 1


@pytest.mark.anyio
async def test_a_real_credential_in_the_rendered_frame_still_refuses_the_whole_review() -> None:
    result, audit = await _evaluate(secret_in_frame=True)
    assert isinstance(result, SemanticEgressBlocked)
    assert (result.outcome, result.reason) == (
        PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
        PrivacyReason.NEVER_SEND_DETECTED,
    )
    assert audit.prepared == []
    (receipt,) = audit.receipts
    assert receipt.counts.final_bytes == 0
    assert not receipt.secret_scan.passed


@pytest.mark.anyio
@pytest.mark.parametrize("bound", ("excerpt", "excerpt_total"))
async def test_replacement_growth_is_cut_to_the_approved_bound_and_the_review_continues(
    bound: Literal["excerpt", "excerpt_total"], monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1230: an excerpt a replaced value grows past an approved bound is cut, not refused.

    The case is handed to egress as composed (the #1142 boundary: it fits exactly as written),
    so only disclosure-time recovery stands between it and a ``case_capacity_exceeded`` failure.
    """

    case = _semantic_case(_DIFF, with_aws_key=False)
    selected = sum(item.content_bytes for item in case.items if item.section == "excerpt")
    packet = json.loads(_minimize_everything(_candidate(case)).prepared_bytes)
    rows = [item for item in packet["items"] if item["section"] == "excerpt"]
    assert len(rows) == 1
    transformed = len(rows[0]["content"].encode("utf-8"))
    assert transformed == rows[0]["content_bytes"]
    assert transformed == selected + len(EGRESS_CREDENTIAL_PLACEHOLDER) - len(b"hunter2")
    policy = _Store()._policy  # pyright: ignore[reportPrivateUsage]
    selection = replace(
        policy.review_selection,
        max_excerpt_bytes=selected if bound == "excerpt" else 16_384,
        max_total_excerpt_bytes=selected if bound == "excerpt_total" else 131_072,
    )
    policy = replace(
        policy, review_context_profile=ReviewContextProfile.CUSTOM, review_selection=selection
    )
    events: list[dict[str, object]] = []

    def record(**kwargs: object) -> str:
        events.append(kwargs)
        return ""

    monkeypatch.setattr(egress, "record_bounded_counts_without_raising", record)
    result, audit = await _evaluate(policy=policy)
    # The fake audit stops right after preparation: the cut packet was admitted for dispatch.
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.AUDIT_FAILED
    assert result.capacity is None
    (proposal,) = audit.prepared
    sent = reviewer_packet_bytes(proposal.minimized.prepared_bytes)
    assert sent is not None
    (row,) = [item for item in json.loads(sent)["items"] if item["section"] == "excerpt"]
    # The approved bound is respected and the value is never sent. A bound this small keeps the
    # part's head only (too small for an elision marker), which here ends before the value.
    assert row["content_bytes"] <= selected
    assert row["content_bytes"] == len(row["content"].encode("utf-8"))
    assert row["content"].startswith("[FinishUP check-time change")
    assert b"hunter2" not in proposal.minimized.prepared_bytes
    # The cut is disclosed in the provider-bound review input manifest, re-derived from the
    # sent packet alone.
    disclosure = review_packet_disclosure_result(sent)
    assert disclosure.failure is None
    manifest = cast(dict[str, object], disclosure.disclosure.provider_input_manifest)  # type: ignore[union-attr]
    current_diff = cast(dict[str, object], manifest["current_diff"])
    assert current_diff["status"] == "partial"
    assert "truncated_payload" in cast(list[str], current_diff["omission_reasons"])
    (fitted,) = [e for e in events if e["operation"] == "semantic_disclosure_capacity_fitted"]
    assert fitted["outcome"] == "fitted"
    assert fitted["counts"] == {
        "semantic_excerpts_cut_at_disclosure": 1,
        "semantic_excerpts_unselected_at_disclosure": 0,
    }
