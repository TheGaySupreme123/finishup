"""#1138/#1142: real transformed packets and rendered exchanges, with no provider or service."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from typing import Literal, cast

import pytest

import finishup.service.ready_composition as composition
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.application.egress import (
    PrivacyCoordinator,
    ReviewerExchangeFrame,
    SemanticEgressBlocked,
)
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
from finishup.ports.semantic import Deadline, encode_reviewer_exchange
from finishup.protocol.models import SemanticReason, SemanticStatus
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
async def test_replacement_growth_refuses_with_the_exact_transformed_excerpt_size(
    bound: Literal["excerpt", "excerpt_total"], monkeypatch: pytest.MonkeyPatch
) -> None:
    # #1230: the only excerpt is the check-time change, which disclosure never leaves out or
    # cuts, so a packet over its bound because of it is still refused whole.
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

    monkeypatch.setattr(composition, "record_bounded_counts_without_raising", record)
    result, audit = await _evaluate(policy=policy)
    assert isinstance(result, SemanticEgressBlocked)
    assert result.capacity == (transformed, selected)
    assert result.capacity_scope == bound
    assert result.capacity_unit == "bytes"
    assert audit.prepared == []
    assert audit.receipts[0].counts.final_bytes == 0
    final = composition._map_egress_to_final(  # pyright: ignore[reportPrivateUsage]
        result, attempt_id="sma_00000000-0000-4000-8000-000000000001"
    )
    assert (final.status, final.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )
    assert events[0]["counts"] == {
        f"semantic_{bound}_attempted_bytes": transformed,
        f"semantic_{bound}_limit_bytes": selected,
    }
