"""#1066: a proposal refused at the final permission check closes at once as blocked.

tb4n5: when the coordinator refused an egress request after its disclosure proposal was prepared
(a policy switch during preparation, a narrowed limit, a changed case), the proposal stayed
``reserved`` until its authorization timeout, and ``privacy pending`` listed it as a decision the
owner could take although nothing could or would be sent. It now closes immediately with a
blocked receipt naming the refusal, on both audit stores, and replays as that refusal.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
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
    AuthorizationScope,
    CredentialHeuristic,
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
    RepositoryPrivacyAuthority,
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


@pytest.mark.anyio
async def test_a_refused_receipt_keeps_the_heuristic_the_case_was_scanned_under() -> None:
    # The owner had the possible-credential filter off when the case was prepared (#982), and
    # turns it back on as the request reaches the dispatch fence. The receipt describes the
    # prepared case's scan, so it keeps the opt-out every other blocked receipt states.
    base = resume._effective()  # pyright: ignore[reportPrivateUsage]
    prepared = EffectivePrivacyPolicy(
        replace(base.policy, credential_heuristic=CredentialHeuristic.DISABLED),
        base.generation,
        base.effective_digest,
    )
    proposal = resume._proposal(expires_at=resume._NOW + timedelta(minutes=5))  # pyright: ignore[reportPrivateUsage]
    coordinator, audit = _coordinator("approved", proposal)
    policies = cast(
        resume._Policies,  # pyright: ignore[reportPrivateUsage]
        coordinator._policies,  # type: ignore[attr-defined]
    )
    policies.effective = prepared

    def fence() -> bool:
        policies.effective = EffectivePrivacyPolicy(
            base.policy, base.generation + 1, "sha256:" + "f" * 64
        )
        return False

    result = await coordinator.resume(  # type: ignore[attr-defined]
        _REQUEST,
        _CASE_DIGEST,
        resume._deadline(),  # pyright: ignore[reportPrivateUsage]
        dispatch_guard=fence,
    )
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.SCOPE_MISMATCH
    (receipt,) = audit.closed
    assert result.receipt_id == receipt.receipt_id
    assert receipt.secret_scan.credential_heuristic is CredentialHeuristic.DISABLED
    assert receipt.policy.policy_digest == base.effective_digest


async def _resume_with_authority(read: int, failure: str) -> tuple[object, _ClosingAudit, int]:
    """Resume an approved proposal whose ``read``-th repository-authority read fails.

    The first read activates the authority on resume; the second rechecks it at dispatch.
    ``failure`` is ``raises`` (a catalog hiccup) or ``lost`` (the authority no longer holds).
    """

    proposal = resume._proposal(expires_at=resume._NOW + timedelta(minutes=5))  # pyright: ignore[reportPrivateUsage]
    coordinator, audit = _coordinator("approved", proposal)
    policies = cast(
        resume._Policies,  # pyright: ignore[reportPrivateUsage]
        coordinator._policies,  # type: ignore[attr-defined]
    )
    held = policies.repository_authority
    reads = 0

    async def authority(scope: AuthorizationScope) -> RepositoryPrivacyAuthority:
        nonlocal reads
        reads += 1
        failing = reads == read
        if failing and failure == "raises":
            raise OSError("catalog busy")
        # Lost on resume: the grant was withdrawn. Lost at dispatch: the authority changed.
        policies.granted = not (failing and read == 1)
        current = await held(scope)
        if failing and read == 2:
            return replace(current, authority_digest="sha256:" + "9" * 64)
        return current

    object.__setattr__(policies, "repository_authority", authority)
    result = cast(
        object,
        await coordinator.resume(  # type: ignore[attr-defined]
            _REQUEST,
            _CASE_DIGEST,
            resume._deadline(),  # pyright: ignore[reportPrivateUsage]
        ),
    )
    return result, audit, reads


@pytest.mark.anyio
@pytest.mark.parametrize("read", (1, 2), ids=("on_resume", "at_dispatch"))
async def test_an_authority_read_that_raises_leaves_an_approved_proposal_open(read: int) -> None:
    """A one-off catalog failure decides nothing: the owner's approval is not closed."""

    result, audit, reads = await _resume_with_authority(read, "raises")
    assert reads == read
    assert isinstance(result, SemanticEgressBlocked)
    # The caller still gets the same refusal; only the proposal is left as it was.
    assert (result.outcome, result.reason, result.receipt_id) == (
        PrivacyOutcome.BLOCKED_BY_POLICY,
        PrivacyReason.SCOPE_MISMATCH,
        None,
    )
    assert result.transient
    assert audit.closed == []


@pytest.mark.anyio
@pytest.mark.parametrize("read", (1, 2), ids=("on_resume", "at_dispatch"))
async def test_an_authority_no_longer_held_still_closes_the_proposal(read: int) -> None:
    result, audit, reads = await _resume_with_authority(read, "lost")
    assert reads == read
    assert isinstance(result, SemanticEgressBlocked)
    assert (result.outcome, result.reason) == (
        PrivacyOutcome.BLOCKED_BY_POLICY,
        PrivacyReason.SCOPE_MISMATCH,
    )
    assert not result.transient
    (receipt,) = audit.closed
    assert result.receipt_id == receipt.receipt_id


async def _raising_guard() -> bool:
    raise OSError("observation store busy")


def _raising_sync_guard() -> bool:
    raise OSError("observation store busy")


@pytest.mark.anyio
@pytest.mark.parametrize("guard", (_raising_sync_guard, _raising_guard), ids=("sync", "async"))
async def test_a_fence_guard_that_raises_leaves_an_approved_proposal_open(
    guard: Callable[[], Awaitable[bool] | bool],
) -> None:
    proposal = resume._proposal(expires_at=resume._NOW + timedelta(minutes=5))  # pyright: ignore[reportPrivateUsage]
    coordinator, audit = _coordinator("approved", proposal)
    result = await coordinator.resume(  # type: ignore[attr-defined]
        _REQUEST,
        _CASE_DIGEST,
        resume._deadline(),  # pyright: ignore[reportPrivateUsage]
        dispatch_guard=guard,
    )
    assert isinstance(result, SemanticEgressBlocked)
    assert (result.outcome, result.reason, result.receipt_id) == (
        PrivacyOutcome.BLOCKED_BY_POLICY,
        PrivacyReason.SCOPE_MISMATCH,
        None,
    )
    assert result.transient
    assert audit.closed == []
    # A definitive refusal at the same fence still closes it at once.
    coordinator, audit = _coordinator("approved", proposal)
    refused = await coordinator.resume(  # type: ignore[attr-defined]
        _REQUEST,
        _CASE_DIGEST,
        resume._deadline(),  # pyright: ignore[reportPrivateUsage]
        dispatch_guard=lambda: False,
    )
    assert isinstance(refused, SemanticEgressBlocked) and not refused.transient
    (receipt,) = audit.closed
    assert refused.receipt_id == receipt.receipt_id


def test_only_a_scope_refusal_can_be_transient() -> None:
    with pytest.raises(ValueError, match="semantic_transient_refusal_invalid"):
        _blocked(_REQUEST, _REQUEST, reason=PrivacyReason.POLICY_DENIED, transient=True)
    with pytest.raises(ValueError, match="semantic_transient_refusal_invalid"):
        _blocked(
            _REQUEST,
            _REQUEST,
            PrivacyOutcome.APPROVAL_EXPIRED,
            PrivacyReason.AUTHORIZATION_EXPIRED,
            transient=True,
        )
