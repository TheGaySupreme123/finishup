"""Every network egress receipt names the closed operation that asked for it (tb4n2 N-5).

n2 recorded recurring ``blocked_by_policy`` / ``insufficient_approved_context`` semantic-review
receipts on one ``bounded_structural_metadata`` item that could not be traced to an operation.
The producer is the background observation-advice supervisor (#619): its single advice packet is
not a review-packet envelope, so the semantic-review assembly fails closed. The receipt now says
``observation_advice``.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from typing import cast

import pytest

from builders.privacy_policies import INSTALLATION_ID, minimal_external_policy
from builders.privacy_widenings import llm_channel, with_llm
from yoetz.adapters.privacy.catalog import (
    _network_receipt_from_bytes,  # pyright: ignore[reportPrivateUsage]
    _receipt_bytes,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from yoetz.application.egress import PrivacyCoordinator, SemanticEgressBlocked
from yoetz.application.privacy_control import encode_privacy_receipt_view
from yoetz.domain.privacy import (
    OBSERVATION_ADVICE_PACKET_ITEM_ID,
    REVIEW_PACKET_ITEM_ID,
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    CandidateContextItem,
    ConsentSource,
    EgressChannel,
    EgressOriginOperation,
    EgressReceipt,
    PrivacyOutcome,
    PrivacyReason,
    ProviderBinding,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptSecretScanStage,
    ReceiptTransformations,
    egress_origin_operation,
)
from yoetz.domain.values import JsonObject, freeze_json
from yoetz.ports.clock import ClockPort
from yoetz.ports.ids import IdPort
from yoetz.ports.privacy import (
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    NetworkEgressReceiptView,
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyAuditReservation,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
)
from yoetz.ports.semantic import Deadline
from yoetz.protocol.ids import IdKind
from yoetz.protocol.models import DataCategory
from yoetz.service.client import (
    PrivacyReceiptFound,
    _receipt_get_from_wire,  # pyright: ignore[reportPrivateUsage]
)

_NOW = datetime(2026, 10, 8, 17, 7, tzinfo=UTC)
_REQUEST = "req_40000000-0000-4000-8000-000000000001"
_TASK = "tsk_40000000-0000-4000-8000-000000000002"
_RECEIPT = "egr_40000000-0000-4000-8000-000000000003"
_PROPOSAL = "ppr_40000000-0000-4000-8000-000000000004"
_POLICY = "pvy_40000000-0000-4000-8000-000000000005"
_DIGEST = "sha256:" + "7" * 64
_COMMITMENT = "hmac-sha256:" + "a" * 64


def test_origin_is_derived_from_purpose_and_reserved_item_ids() -> None:
    assert (
        egress_origin_operation("semantic-review", [REVIEW_PACKET_ITEM_ID, "excerpt-1"])
        is EgressOriginOperation.SEMANTIC_CHECK
    )
    assert (
        egress_origin_operation("semantic-review", [OBSERVATION_ADVICE_PACKET_ITEM_ID])
        is EgressOriginOperation.OBSERVATION_ADVICE
    )
    assert (
        egress_origin_operation("credential-probe", ["credential-probe"])
        is EgressOriginOperation.CREDENTIAL_PROBE
    )
    assert egress_origin_operation("semantic-review", ["item-1"]) is None
    assert egress_origin_operation("client_result_projection", [REVIEW_PACKET_ITEM_ID]) is None


def _receipt(origin: EgressOriginOperation | None) -> EgressReceipt:
    return EgressReceipt(
        "1.1.0",
        _RECEIPT,
        _REQUEST,
        _PROPOSAL,
        EgressChannel.LLM_INFERENCE,
        PrivacyOutcome.BLOCKED_BY_POLICY,
        _NOW,
        AuthorizationScope(AuthorizationScopeKind.TASK, INSTALLATION_ID, _COMMITMENT, _TASK),
        "semantic-review",
        ProviderBinding("openai-codex", "gpt-6", "codex-subscription", "1.0.0", "external"),
        ReceiptPolicyBinding(_POLICY, 1, _DIGEST, _DIGEST),
        ConsentSource.NONE,
        (),
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        ReceiptCounts(1, 0, 1, 0, 1, 494, 0, None, None),
        ReceiptTransformations(0, 0, 1),
        ReceiptSecretScan("scanner-v3", _DIGEST, 0, True, ReceiptSecretScanStage.PREPARED_CASE),
        PrivacyReason.INSUFFICIENT_APPROVED_CONTEXT,
        1,
        origin_operation=origin,
    )


def test_receipt_without_an_origin_keeps_its_stored_bytes() -> None:
    stored = _receipt_bytes(_receipt(None))
    assert b"origin_operation" not in stored
    assert _network_receipt_from_bytes(stored).origin_operation is None


def test_receipt_origin_round_trips_storage_wire_and_schema() -> None:
    receipt = _receipt(EgressOriginOperation.OBSERVATION_ADVICE)
    stored = _receipt_bytes(receipt)
    assert b'"origin_operation":"observation_advice"' in stored
    assert _network_receipt_from_bytes(stored) == receipt

    wire = encode_privacy_receipt_view(NetworkEgressReceiptView("network_egress", receipt))
    body = cast(dict[str, object], wire["receipt"])
    assert body["origin_operation"] == "observation_advice"
    view = NetworkEgressReceiptView("network_egress", receipt)
    decoded = _receipt_get_from_wire(
        cast(
            JsonObject,
            freeze_json({"schema_version": "1.0.0", "outcome": "found", "receipt": wire}),
        )
    )
    assert isinstance(decoded, PrivacyReceiptFound)
    assert decoded.receipt == view

    document = json.loads(
        files("yoetz.resources")
        .joinpath("schemas/privacy/egress-receipt-1.1.0.schema.json")
        .read_bytes()
    )
    assert document["properties"]["origin_operation"] == {
        "enum": ["credential_probe", "observation_advice", "semantic_check"],
        "type": "string",
    }


def test_legacy_receipt_version_cannot_carry_an_origin() -> None:
    with pytest.raises(ValueError):
        replace(
            _receipt(EgressOriginOperation.SEMANTIC_CHECK),
            schema_version="1.0.0",
            secret_scan=ReceiptSecretScan(
                "scanner-v3", _DIGEST, 0, True, ReceiptSecretScanStage.LEGACY_UNKNOWN
            ),
        )


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 1.0


class _Ids:
    def __init__(self) -> None:
        self._n = 0

    def new(self, kind: IdKind) -> str:
        self._n += 1
        prefix = {IdKind.PRIVACY_PROPOSAL: "ppr", IdKind.EGRESS_RECEIPT: "egr"}.get(kind, "ppr")
        return f"{prefix}_40000000-0000-4000-8000-{self._n + 100:012d}"


class _Store:
    def __init__(self) -> None:
        self._policy = with_llm(minimal_external_policy())

    async def effective_policy(self, scope: AuthorizationScope) -> EffectivePrivacyPolicy:
        del scope
        return EffectivePrivacyPolicy(self._policy, 1, self._policy.policy_digest)

    async def repository_authority(self, scope: AuthorizationScope) -> object:
        from types import SimpleNamespace

        return SimpleNamespace(
            effective=await self.effective_policy(scope),
            grant_state="granted",
            repository_privacy_commitment=_COMMITMENT,
            authority_digest="sha256:" + "9" * 64,
        )


class _Audit:
    def __init__(self) -> None:
        self.receipts: list[EgressReceipt] = []

    async def reserve(self, subject: object) -> PrivacyAuditReservation:
        return PrivacyAuditReservation(
            cast(str, getattr(subject, "privacy_proposal_id", _PROPOSAL)),
            cast(str, getattr(subject, "request_id", _REQUEST)),
            _DIGEST,
            "reserved",
            1,
            _NOW,
        )

    async def complete_decision(self, proposal_id: str, receipt: object) -> None:
        del proposal_id
        assert type(receipt) is EgressReceipt
        self.receipts.append(receipt)


class _Gateway:
    async def reconcile_repository_policy(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        return object()

    async def close(self) -> None:
        return None


@pytest.mark.anyio
async def test_blocked_advice_dispatch_receipt_names_observation_advice() -> None:
    """Replays the n2 vpp S shape: one advice packet, blocked as insufficient context."""

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
    scope = AuthorizationScope(AuthorizationScopeKind.TASK, INSTALLATION_ID, _COMMITMENT, _TASK)
    binding = llm_channel(minimal_external_policy()).provider_binding
    assert binding is not None
    packet = json.dumps({"gaps": ["unpaired_event"], "schema": "observation-advice/1"}).encode()
    candidate = CandidateContext(
        _REQUEST,
        EgressChannel.LLM_INFERENCE,
        None,
        "semantic-review",
        scope,
        _DIGEST,
        binding,
        (
            CandidateContextItem(
                OBSERVATION_ADVICE_PACKET_ITEM_ID,
                DataCategory.BOUNDED_STRUCTURAL_METADATA,
                scope,
                "/observation-advice",
                packet,
            ),
        ),
    )
    deadline = Deadline(_NOW + timedelta(minutes=1), 61.0)
    result = await coordinator.evaluate_semantic(candidate, deadline)
    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.BLOCKED_BY_POLICY
    assert result.reason is PrivacyReason.INSUFFICIENT_APPROVED_CONTEXT
    (receipt,) = audit.receipts
    assert receipt.origin_operation is EgressOriginOperation.OBSERVATION_ADVICE


@pytest.mark.anyio
async def test_malformed_advice_does_not_claim_category_denial() -> None:
    audit = _Audit()
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, _Store()),
        cast(PrivacyClassifierPort, LocalPrivacyEnforcer()),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, _Gateway()),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=HumanAuthorityCapability(
            "established_passphrase",
            "sha256:" + "8" * 64,
            1,
            "passphrase",
            1,
            True,
        ),
    )
    scope = AuthorizationScope(AuthorizationScopeKind.TASK, INSTALLATION_ID, _COMMITMENT, _TASK)
    binding = llm_channel(minimal_external_policy()).provider_binding
    assert binding is not None
    candidate = CandidateContext(
        _REQUEST,
        EgressChannel.LLM_INFERENCE,
        None,
        "semantic-review",
        scope,
        _DIGEST,
        binding,
        (
            CandidateContextItem(
                OBSERVATION_ADVICE_PACKET_ITEM_ID,
                DataCategory.BOUNDED_STRUCTURAL_METADATA,
                scope,
                "/observation-advice",
                b"{}",
            ),
        ),
    )
    result = await coordinator.evaluate_semantic(candidate, Deadline(_NOW, 61.0))
    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason is PrivacyReason.INSUFFICIENT_APPROVED_CONTEXT
    (receipt,) = audit.receipts
    assert receipt.blocked_categories == ()
    assert receipt.counts.blocked_items == 0
    assert receipt.counts.approved_items == 1
