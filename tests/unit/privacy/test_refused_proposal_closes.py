"""#1066: a proposal refused at the final permission check closes at once as blocked.

tb4n5: when the coordinator refused an egress request after its disclosure proposal was prepared
(a policy switch during preparation, a narrowed limit, a changed case), the proposal stayed
``reserved`` until its authorization timeout, and ``privacy pending`` listed it as a decision the
owner could take although nothing could or would be sent. It now closes immediately with a
blocked receipt naming the refusal, on both audit stores, and replays as that refusal.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
from typing import cast

import pytest

from finishup.adapters.memory.privacy import MemoryPrivacyAudit, MemoryPrivacyCatalogState
from finishup.adapters.privacy.catalog import CatalogPrivacyAudit
from finishup.application.egress import (
    SemanticEgressBlocked,
    _refused_proposal_receipt,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import (
    DisclosureProposal,
    EgressReceipt,
    PrivacyOutcome,
    PrivacyReason,
    ReceiptCapacity,
)
from finishup.ports.ids import IdPort
from finishup.ports.privacy import (
    EffectivePrivacyPolicy,
    NetworkEgressReceiptView,
    PrivacyAuditPort,
    PrivacyReceiptAudience,
    PrivacyReceiptView,
)
from finishup.protocol.ids import IdKind
from unit.application import test_semantic_authorization_resume as resume
from unit.privacy import test_catalog_audit as catalog_test

_CATALOG_NOW = catalog_test._NOW  # pyright: ignore[reportPrivateUsage]
_REQUEST = resume._REQUEST  # pyright: ignore[reportPrivateUsage]
_CASE_DIGEST = resume._CASE_DIGEST  # pyright: ignore[reportPrivateUsage]
_RECEIPT_IDS = iter(f"egr_66000000-0000-4000-8000-{n:012d}" for n in range(1, 100))


class _Ids:
    def new(self, kind: IdKind) -> str:
        assert kind is IdKind.EGRESS_RECEIPT
        return next(_RECEIPT_IDS)


def _blocked(
    proposal_id: str,
    request_id: str,
    outcome: PrivacyOutcome = PrivacyOutcome.BLOCKED_BY_POLICY,
    reason: PrivacyReason = PrivacyReason.SCOPE_MISMATCH,
    **kwargs: object,
) -> SemanticEgressBlocked:
    return SemanticEgressBlocked(
        request_id,
        outcome,
        reason,
        privacy_proposal_id=proposal_id,
        **kwargs,  # pyright: ignore[reportArgumentType]
    )


def _stores() -> tuple[CatalogPrivacyAudit, MemoryPrivacyAudit]:
    db = catalog_test._database()  # pyright: ignore[reportPrivateUsage]
    catalog_test._insert_task_route(db)  # pyright: ignore[reportPrivateUsage]
    sqlite = CatalogPrivacyAudit(
        db,
        catalog_test._Objects(),  # pyright: ignore[reportPrivateUsage, reportArgumentType]
        catalog_test._Key(),  # pyright: ignore[reportPrivateUsage, reportArgumentType]
        catalog_test._Clock(),  # pyright: ignore[reportPrivateUsage, reportArgumentType]
    )
    memory = MemoryPrivacyAudit(
        MemoryPrivacyCatalogState(
            routes={catalog_test._TASK: catalog_test._ROUTE_DIGEST}  # pyright: ignore[reportPrivateUsage]
        ),
        catalog_test._Objects(),  # pyright: ignore[reportPrivateUsage, reportArgumentType]
        catalog_test._Key(),  # pyright: ignore[reportPrivateUsage, reportArgumentType]
        catalog_test._Clock(),  # pyright: ignore[reportPrivateUsage, reportArgumentType]
    )
    return sqlite, memory


def _effective() -> EffectivePrivacyPolicy:
    policy = catalog_test._policy()  # pyright: ignore[reportPrivateUsage]
    return EffectivePrivacyPolicy(policy, 1, policy.policy_digest)


async def _pending(audit: object) -> tuple[str, ...]:
    page = await cast(PrivacyAuditPort, audit).list_pending_disclosures(
        PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
    )
    return tuple(entry.pending_id for entry in page.pending)


def test_both_stores_close_a_refused_proposal_once_and_stop_listing_it() -> None:
    async def run(audit: CatalogPrivacyAudit | MemoryPrivacyAudit) -> None:
        request = catalog_test._external_disclosure_request()  # pyright: ignore[reportPrivateUsage]
        prepared = await audit.prepare_disclosure_proposal(request)
        proposal = prepared.proposal
        assert await _pending(audit) == (proposal.privacy_proposal_id,)
        refusal = _blocked(
            proposal.privacy_proposal_id,
            proposal.request_id,
            reason=PrivacyReason.POLICY_DENIED,
            capacity=(131_074, 131_072),
            capacity_unit="bytes",
            capacity_scope="excerpt_total",
        )
        receipt = _refused_proposal_receipt(
            proposal,
            _effective(),
            refusal,
            _CATALOG_NOW,
            cast(IdPort, _Ids()),  # pyright: ignore[reportPrivateUsage]
        )
        assert await audit.close_refused_disclosure(proposal.privacy_proposal_id, receipt)
        # Gone from pending at once, and the receipt says blocked, with the reason, sent nothing.
        assert await _pending(audit) == ()
        view = await audit.get_receipt(
            receipt.receipt_id, PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
        )
        assert isinstance(view, NetworkEgressReceiptView)
        stored = view.receipt
        assert (stored.outcome, stored.safe_failure_reason) == (
            PrivacyOutcome.BLOCKED_BY_POLICY,
            PrivacyReason.POLICY_DENIED,
        )
        assert stored.capacity_exceeded == ReceiptCapacity(
            "excerpt_total", "bytes", 131_074, 131_072
        )
        assert stored.counts.final_bytes == 0 and stored.dispatch_id is None
        # Once only: the closed proposal does not move again.
        again = replace(receipt, receipt_id=next(_RECEIPT_IDS))
        assert not await audit.close_refused_disclosure(proposal.privacy_proposal_id, again)

    for audit in _stores():
        asyncio.run(run(audit))


def test_an_authorized_proposal_is_never_closed_as_refused() -> None:
    async def run() -> None:
        sqlite, _memory = _stores()
        request = catalog_test._external_disclosure_request()  # pyright: ignore[reportPrivateUsage]
        prepared = await sqlite.prepare_disclosure_proposal(request)
        proposal = prepared.proposal
        await sqlite.authorize(
            proposal.privacy_proposal_id,
            proposal.prepared_case_digest,
            _CATALOG_NOW,  # pyright: ignore[reportPrivateUsage]
        )
        receipt = _refused_proposal_receipt(
            proposal,
            _effective(),
            _blocked(proposal.privacy_proposal_id, proposal.request_id),
            _CATALOG_NOW,  # pyright: ignore[reportPrivateUsage]
            cast(IdPort, _Ids()),
        )
        assert not await sqlite.close_refused_disclosure(proposal.privacy_proposal_id, receipt)

    asyncio.run(run())


class _ClosingAudit(resume._Audit):  # pyright: ignore[reportPrivateUsage]
    def __init__(self, status: str, proposal: DisclosureProposal) -> None:
        super().__init__(status, proposal)
        self.closed: list[EgressReceipt] = []

    async def close_refused_disclosure(self, proposal_id: str, receipt: EgressReceipt) -> bool:
        assert proposal_id == resume._PROPOSAL  # pyright: ignore[reportPrivateUsage]
        self.closed.append(receipt)
        return True

    async def get_receipt(
        self, receipt_id: str, audience: PrivacyReceiptAudience
    ) -> PrivacyReceiptView | None:
        del audience
        for receipt in self.closed:
            if receipt.receipt_id == receipt_id:
                return NetworkEgressReceiptView("network_egress", receipt)
        return None


def _coordinator(status: str, proposal: DisclosureProposal) -> tuple[object, _ClosingAudit]:
    coordinator = resume._coordinator(  # pyright: ignore[reportPrivateUsage]
        status,
        expires_at=resume._NOW + timedelta(minutes=5),  # pyright: ignore[reportPrivateUsage]
        proposal=proposal,
    )
    audit = _ClosingAudit(status, proposal)
    object.__setattr__(coordinator, "_audit", audit)
    return coordinator, audit


@pytest.mark.anyio
async def test_a_proposal_whose_policy_changed_closes_at_the_final_check() -> None:
    proposal = replace(
        resume._proposal(expires_at=resume._NOW + timedelta(minutes=5)),  # pyright: ignore[reportPrivateUsage]
        policy_digest="sha256:" + "e" * 64,
    )
    coordinator, audit = _coordinator("approved", proposal)
    result = await coordinator.resume(  # type: ignore[attr-defined]
        _REQUEST,
        _CASE_DIGEST,
        resume._deadline(),  # pyright: ignore[reportPrivateUsage]
    )
    assert isinstance(result, SemanticEgressBlocked)
    assert (result.outcome, result.reason) == (
        PrivacyOutcome.BLOCKED_BY_POLICY,
        PrivacyReason.POLICY_DENIED,
    )
    (receipt,) = audit.closed
    assert result.receipt_id == receipt.receipt_id
    assert receipt.counts.final_bytes == 0
    assert receipt.policy.policy_digest == "sha256:" + "e" * 64


@pytest.mark.anyio
async def test_a_timed_out_check_keeps_a_valid_approval_usable() -> None:
    class _Late(resume._Clock):  # pyright: ignore[reportPrivateUsage]
        def monotonic_seconds(self) -> float:
            return 10_000.0

    proposal = resume._proposal(expires_at=resume._NOW + timedelta(minutes=5))  # pyright: ignore[reportPrivateUsage]
    coordinator, audit = _coordinator("approved", proposal)
    object.__setattr__(coordinator, "_clock", _Late())
    result = await coordinator.resume(  # type: ignore[attr-defined]
        _REQUEST,
        _CASE_DIGEST,
        resume._deadline(),  # pyright: ignore[reportPrivateUsage]
    )
    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.TIMEOUT
    assert audit.closed == []


@pytest.mark.anyio
async def test_a_closed_proposal_replays_as_the_refusal_it_recorded() -> None:
    proposal = resume._proposal(expires_at=resume._NOW + timedelta(minutes=5))  # pyright: ignore[reportPrivateUsage]
    coordinator, audit = _coordinator("decision_completed", proposal)
    refusal = _blocked(
        proposal.privacy_proposal_id,
        proposal.request_id,
        reason=PrivacyReason.POLICY_DENIED,
        capacity=(70_000, 65_536),
        capacity_unit="tokens",
    )
    receipt = _refused_proposal_receipt(
        proposal,
        resume._effective(),  # pyright: ignore[reportPrivateUsage]
        refusal,
        resume._NOW,  # pyright: ignore[reportPrivateUsage]
        cast(IdPort, _Ids()),
    )
    audit.closed.append(receipt)

    async def load(request_id: str, subject_digest: str) -> object:
        del request_id, subject_digest
        from finishup.ports.privacy import PrivacyAuditReservation, PrivacyAuditState

        reservation = PrivacyAuditReservation(
            resume._PROPOSAL,  # pyright: ignore[reportPrivateUsage]
            _REQUEST,
            _CASE_DIGEST,
            "decision_completed",
            2,
            resume._NOW,  # pyright: ignore[reportPrivateUsage]
        )
        return PrivacyAuditState(reservation, "decision_completed", receipt_id=receipt.receipt_id)

    object.__setattr__(audit, "load", load)
    object.__setattr__(audit, "load_disclosure_attempt", load)
    result = await coordinator.resume(  # type: ignore[attr-defined]
        _REQUEST,
        _CASE_DIGEST,
        resume._deadline(),  # pyright: ignore[reportPrivateUsage]
    )
    assert isinstance(result, SemanticEgressBlocked)
    assert (result.outcome, result.reason, result.receipt_id) == (
        PrivacyOutcome.BLOCKED_BY_POLICY,
        PrivacyReason.POLICY_DENIED,
        receipt.receipt_id,
    )
    assert result.capacity == (70_000, 65_536) and result.capacity_unit == "tokens"


@pytest.mark.anyio
async def test_an_approved_proposal_refused_at_the_dispatch_fence_closes_at_once() -> None:
    proposal = resume._proposal(expires_at=resume._NOW + timedelta(minutes=5))  # pyright: ignore[reportPrivateUsage]
    coordinator, audit = _coordinator("approved", proposal)
    result = await coordinator.resume(  # type: ignore[attr-defined]
        _REQUEST,
        _CASE_DIGEST,
        resume._deadline(),  # pyright: ignore[reportPrivateUsage]
        dispatch_guard=lambda: False,
    )
    assert isinstance(result, SemanticEgressBlocked)
    assert (result.outcome, result.reason) == (
        PrivacyOutcome.BLOCKED_BY_POLICY,
        PrivacyReason.SCOPE_MISMATCH,
    )
    (receipt,) = audit.closed
    assert result.receipt_id == receipt.receipt_id
    assert receipt.safe_failure_reason is PrivacyReason.SCOPE_MISMATCH
