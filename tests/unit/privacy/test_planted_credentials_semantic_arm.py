"""Planted credentials through the real semantic case and egress enforcer (tb4n2 A7, P1-14).

B2 value-level redaction (issue #982), PL2-1 redacted-value locations and the #979 manifest alias
never ran on real data in tb4n2: no attempt carried a credential-like value. These cases build the
packet the AI-powered review would send from a planted workspace change, run it through the
production ``LocalPrivacyEnforcer`` and the privacy coordinator (no service, no network), and
assert what the reviewer would receive.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast

import pytest

from builders.privacy_policies import INSTALLATION_ID, minimal_external_policy
from builders.privacy_widenings import llm_channel
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.application.egress import PrivacyCoordinator, SemanticEgressBlocked
from finishup.application.semantic_case import (
    CHECK_TIME_CHANGE_ITEM_PREFIX,
    build_semantic_case,
    review_packet_disclosure_result,
    semantic_case_to_candidate_context,
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    EgressOriginOperation,
    EgressReceipt,
    PrivacyDecision,
    PrivacyOutcome,
    PrivacyReason,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.domain.receipts import (
    SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
    SEMANTIC_REVIEW_VALUE_REDACTED_GAP,
)
from finishup.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.privacy import (
    DisclosureProposalRequest,
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    MinimizedDisclosure,
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyAuditReservation,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
)
from finishup.ports.semantic import Deadline, SemanticCase
from finishup.protocol.canonical import strict_json_parse
from finishup.protocol.redacted_values import SemanticRedactedValue
from finishup.service.ready_composition import (
    _egress_case_content_gaps,  # pyright: ignore[reportPrivateUsage]
    _provider_manifest_has_redaction,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_egress_origin_operation import (
    _COMMITMENT,  # pyright: ignore[reportPrivateUsage]
    _TASK,  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _Gateway,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_semantic_case import (
    _captured_case_values,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_semantic_case_check_change import (
    _change,  # pyright: ignore[reportPrivateUsage]
)

# A heuristic-only credential: an assignment to a token-named attribute with a high-entropy value
# of no known provider shape. A real-looking AWS access key id is a high-confidence shape.
_BOT_TOKEN = b"x9Fq2LmZ7vRt4KpW8sYd3NcB6hJe1QaU"
_AWS_KEY = b"AK" + b"IAQ3EGRL7X2VNTWB5D"
_BOT_LINE = b'+        self.bot_token = "' + _BOT_TOKEN + b'"\n'
_DELIVERABLE_DIFF = (
    b"diff --git a/bot/client.py b/bot/client.py\n"
    b"+class Client:\n"
    b"+    def __init__(self):\n" + _BOT_LINE + b"+        self.retries = 3\n"
)
_REQUEST = "req_40000000-0000-4000-8000-000000000101"


def _semantic_case(diff: bytes, *, with_aws_key: bool) -> SemanticCase:
    frozen, captured, scope = _captured_case_values(b'AWS_ACCESS_KEY_ID = "' + _AWS_KEY + b'"\n')
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=frozen,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=(captured,) if with_aws_key else (),
        captured_content_scope=scope if with_aws_key else None,
        check_time_change=_change(diff),
        final_review=True,
    )


def _candidate(case: SemanticCase) -> CandidateContext:
    binding = llm_channel(minimal_external_policy()).provider_binding
    assert binding is not None
    return semantic_case_to_candidate_context(
        case,
        request_id=_REQUEST,
        scope=AuthorizationScope(AuthorizationScopeKind.TASK, INSTALLATION_ID, _COMMITMENT, _TASK),
        provider_binding=binding,
    )


class _Audit:
    """Records the proposal the coordinator would persist, then stops before any dispatch."""

    def __init__(self) -> None:
        self.receipts: list[EgressReceipt] = []
        self.prepared: list[DisclosureProposalRequest] = []

    async def reserve(self, subject: object) -> PrivacyAuditReservation:
        return PrivacyAuditReservation(
            cast(str, getattr(subject, "privacy_proposal_id")),
            cast(str, getattr(subject, "request_id")),
            "sha256:" + "7" * 64,
            "reserved",
            1,
            datetime(2026, 10, 8, tzinfo=UTC),
        )

    async def complete_decision(self, proposal_id: str, receipt: object) -> None:
        del proposal_id
        assert type(receipt) is EgressReceipt
        self.receipts.append(receipt)

    async def prepare_disclosure_proposal(self, request: DisclosureProposalRequest) -> object:
        self.prepared.append(request)
        raise RuntimeError("stop_before_dispatch")


async def _evaluate(candidate: CandidateContext) -> tuple[object, _Audit]:
    audit = _Audit()
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, _Store()),
        cast(PrivacyClassifierPort, LocalPrivacyEnforcer()),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, _Gateway()),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=HumanAuthorityCapability(
            "established_passphrase", "sha256:" + "8" * 64, 1, "passphrase", 1, True
        ),
    )
    result = await coordinator.evaluate_semantic(
        candidate, Deadline(datetime(2026, 10, 8, 17, 8, tzinfo=UTC), 61.0)
    )
    return result, audit


def _minimize_everything(candidate: CandidateContext) -> MinimizedDisclosure:
    """The enforcer alone, every item approved: what the packet bytes would be."""

    enforcer = LocalPrivacyEnforcer()
    store = _Store()
    policy = store._policy  # pyright: ignore[reportPrivateUsage]
    classified = enforcer.classify(
        candidate, EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    )
    approve = tuple(sorted(item.candidate.item_id for item in classified.items))
    return enforcer.minimize_and_scan(
        classified, PrivacyDecision(approve, (), PrivacyOutcome.COMPLETED, None)
    )


def _assert_value_redacted_packet(minimized: MinimizedDisclosure, item_id: str) -> None:
    prepared = minimized.prepared_bytes
    # The heuristic value is replaced in place; the rest of the line and the item are kept.
    assert _BOT_TOKEN not in prepared
    assert b'self.bot_token = \\"' + EGRESS_CREDENTIAL_PLACEHOLDER in prepared
    assert b"self.retries = 3" in prepared
    assert item_id in minimized.included_item_ids
    assert minimized.withheld_item_ids == ()
    assert minimized.redacted_span_count >= 1
    assert minimized.heuristic_findings == ()
    assert minimized.forbidden_findings == ()
    # PL2-1: the item and the 1-based line of the replaced value, never the value.
    (located,) = minimized.redacted_values
    assert located == SemanticRedactedValue(
        item_id, "value_replaced", located.lines, "check-time-change"
    )
    assert located.lines and all(line >= 1 for line in located.lines)
    assert _BOT_TOKEN not in repr(minimized.redacted_values).encode()
    # The check gap is the review-scoped one, never the capture-time `content_redacted`.
    gaps = _egress_case_content_gaps(
        SimpleNamespace(
            redacted_span_count=minimized.redacted_span_count,
            withheld_item_ids=minimized.withheld_item_ids,
        )
    )
    assert gaps == (SEMANTIC_REVIEW_VALUE_REDACTED_GAP,)
    assert "content_redacted" not in gaps
    assert SEMANTIC_REVIEW_ITEM_WITHHELD_GAP not in gaps
    # #979: the provider-bound manifest of the closing review still decodes as final.
    disclosure = review_packet_disclosure_result(prepared)
    assert disclosure.failure is None
    packet = cast(dict[str, object], strict_json_parse(prepared))
    review_packet = cast(dict[str, object], packet["review_packet"])
    manifest = cast(dict[str, object], review_packet["provider_input_manifest"])
    assert manifest["review_phase"] == "final"
    # The recovery path re-derives the value-redaction gap from this manifest alone.
    assert _provider_manifest_has_redaction(manifest)


def test_heuristic_token_in_a_deliverable_is_value_redacted_not_withheld() -> None:
    case = _semantic_case(_DELIVERABLE_DIFF, with_aws_key=False)
    item_id = f"{CHECK_TIME_CHANGE_ITEM_PREFIX}001"
    assert any(item.item_id == item_id for item in case.items)
    _assert_value_redacted_packet(_minimize_everything(_candidate(case)), item_id)


@pytest.mark.anyio
async def test_coordinator_prepares_the_value_redacted_packet_for_dispatch() -> None:
    case = _semantic_case(_DELIVERABLE_DIFF, with_aws_key=False)
    result, audit = await _evaluate(_candidate(case))
    # The fake audit stops right after the proposal; no provider is reachable from this test.
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.AUDIT_FAILED
    (proposal,) = audit.prepared
    _assert_value_redacted_packet(proposal.minimized, f"{CHECK_TIME_CHANGE_ITEM_PREFIX}001")


@pytest.mark.anyio
async def test_a_real_looking_aws_key_is_never_sent_and_blocks_the_review() -> None:
    """A high-confidence key fails the whole case closed: nothing is prepared or sent.

    The heuristic token in the same case does not change that; the receipt names the check.
    """

    case = _semantic_case(_DELIVERABLE_DIFF, with_aws_key=True)
    candidate = _candidate(case)
    assert any(_AWS_KEY in item.plaintext for item in candidate.items)
    result, audit = await _evaluate(candidate)
    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.BLOCKED_FORBIDDEN_DATA
    assert result.reason is PrivacyReason.NEVER_SEND_DETECTED
    assert audit.prepared == []
    (receipt,) = audit.receipts
    assert receipt.origin_operation is EgressOriginOperation.SEMANTIC_CHECK
    assert receipt.counts.final_bytes == 0
    # Even the enforcer alone never carries the key into packet bytes.
    minimized = _minimize_everything(candidate)
    assert _AWS_KEY not in minimized.prepared_bytes
    assert _AWS_KEY not in repr(minimized.redacted_values).encode()


def test_replay_n1_rs_archive_change_part_five_is_value_redacted_not_withheld() -> None:
    """n1 rs-archive S withheld ``change-check-time-005`` on five receipts (never_send_heuristic).

    The original bytes are not exportable (vault-only), so this synthesizes a large Rust change
    whose fifth 16 KiB part carries a credential-like assignment. Under B2 the value is replaced
    in place and the part stays in the review.
    """

    filler = b"+    archive.push_entry(entry_index, &buffer[offset..offset + chunk]);\n"
    head = b"diff --git a/src/archive.rs b/src/archive.rs\n"
    before = filler * ((4 * 16_384 + 2_000) // len(filler))
    planted = b'+    let api_token = "' + _BOT_TOKEN + b'";\n'
    after = filler * 40
    case = _semantic_case(head + before + planted + after, with_aws_key=False)
    item_id = f"{CHECK_TIME_CHANGE_ITEM_PREFIX}005"
    part = next(item for item in case.items if item.item_id == item_id)
    assert _BOT_TOKEN in part.content
    minimized = _minimize_everything(_candidate(case))
    assert _BOT_TOKEN not in minimized.prepared_bytes
    assert b'let api_token = \\"' + EGRESS_CREDENTIAL_PLACEHOLDER in minimized.prepared_bytes
    assert item_id in minimized.included_item_ids
    assert minimized.withheld_item_ids == ()
    (located,) = minimized.redacted_values
    assert (located.item_id, located.disposition) == (item_id, "value_replaced")
    assert located.lines
    assert review_packet_disclosure_result(minimized.prepared_bytes).failure is None
