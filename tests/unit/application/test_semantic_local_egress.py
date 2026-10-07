from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast

import pytest

import yoetz.service.ready_composition as ready_composition
from builders.privacy_policies import local_only_policy
from yoetz.adapters.providers.fake import scripted_success
from yoetz.application.egress import (
    PrivacyCoordinator,
    SemanticEgressBlocked,
    SemanticEgressSuccess,
)
from yoetz.domain.findings import SemanticDispatchKind
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    ConsentSource,
    DataClass,
    DisclosureProposal,
    EgressChannel,
    LocalDisclosureReceipt,
    LocalDisclosureSink,
    PrivacyOutcome,
    PrivacyReason,
    ProviderBinding,
)
from yoetz.domain.receipts import (
    SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP,
)
from yoetz.ports.clock import ClockPort
from yoetz.ports.privacy import (
    EffectivePrivacyPolicy,
    MinimizedDisclosure,
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
)
from yoetz.ports.semantic import Deadline, SemanticJudgment, SemanticResultSuccess
from yoetz.protocol.models import DataCategory, SemanticReason, SemanticStatus

_NOW = datetime(2026, 7, 26, tzinfo=UTC)
_REQUEST = "req_30000000-0000-4000-8000-000000000001"
_TASK = "tsk_30000000-0000-4000-8000-000000000002"
_PROPOSAL = "ppr_30000000-0000-4000-8000-000000000003"
_CASE_DIGEST = "sha256:" + "c" * 64
_SUBJECT_DIGEST = "sha256:" + "d" * 64
_ITEM_DIGEST = "sha256:" + "e" * 64


class _Clock:
    def __init__(self, *, monotonic: float = 1.0) -> None:
        self.monotonic = monotonic

    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return self.monotonic


class _Audit:
    def __init__(self, *, persist: bool) -> None:
        self.persist = persist
        self.receipt: LocalDisclosureReceipt | None = None
        self.authorize_calls = 0

    async def authorize(self, *args: object) -> object:
        self.authorize_calls += 1
        raise AssertionError("on-device AI-powered review dispatch must not mint network authority")

    async def complete_local_disclosure(
        self, reservation_id: str, receipt: LocalDisclosureReceipt
    ) -> None:
        assert reservation_id == _PROPOSAL
        if not self.persist:
            raise RuntimeError("receipt_write_failed")
        self.receipt = receipt

    async def load(self, request_id: str, subject_digest: str) -> object | None:
        assert (request_id, subject_digest) == (_REQUEST, _SUBJECT_DIGEST)
        if self.receipt is None:
            return None
        return SimpleNamespace(receipt_id=self.receipt.receipt_id)


class _Gateway:
    def __init__(self) -> None:
        self.result = scripted_success(SemanticJudgment("no_material_discrepancy", ())).result
        self.calls = 0
        self.payloads: list[bytes] = []

    async def dispatch_local_semantic(self, case: object, deadline: Deadline) -> object:
        self.payloads.append(cast(bytes, getattr(case, "payload")))
        del deadline
        self.calls += 1
        return self.result


def _binding() -> ProviderBinding:
    return ProviderBinding(
        "local-test",
        "local/test-model",
        "local-af-unix",
        "1.0.0",
        "local_af_unix",
    )


def _scope() -> AuthorizationScope:
    return AuthorizationScope(
        AuthorizationScopeKind.TASK,
        "ins_30000000-0000-4000-8000-000000000004",
        "hmac-sha256:" + "f" * 64,
        _TASK,
    )


def _effective(binding: ProviderBinding) -> EffectivePrivacyPolicy:
    policy = replace(
        local_only_policy(),
        local_model_enabled=True,
        local_model_binding=binding,
        local_model_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        local_model_data_classes=(DataClass.PUBLIC_STRUCTURAL,),
    )
    return EffectivePrivacyPolicy(policy, 1, policy.policy_digest)


def _candidate(binding: ProviderBinding) -> CandidateContext:
    return CandidateContext(
        _REQUEST,
        EgressChannel.LLM_INFERENCE,
        None,
        "semantic-review",
        _scope(),
        _SUBJECT_DIGEST,
        binding,
        (),
    )


def _proposal(
    binding: ProviderBinding,
    *,
    expires_at: datetime = _NOW + timedelta(minutes=1),
) -> DisclosureProposal:
    return DisclosureProposal(
        _PROPOSAL,
        _REQUEST,
        _TASK,
        (_ITEM_DIGEST,),
        b"{}",
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (),
        (),
        _CASE_DIGEST,
        None,
        LocalDisclosureSink.LOCAL_MODEL,
        "semantic-review",
        _scope(),
        1,
        local_only_policy().policy_digest,
        2,
        1,
        expires_at,
        "hmac-sha256:" + "a" * 64,
    )


def _minimized() -> MinimizedDisclosure:
    return MinimizedDisclosure(
        b"{}",
        ("case-packet",),
        (_ITEM_DIGEST,),
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (),
        (),
        2,
        1,
        _CASE_DIGEST,
        "semantic-local-test-v1",
        "sha256:" + "b" * 64,
        (),
    )


async def _dispatch(
    *,
    persist: bool,
    dispatch_guard: Callable[[], Awaitable[bool] | bool] | None = None,
    proposal_expires_at: datetime = _NOW + timedelta(minutes=1),
    deadline: Deadline = Deadline(_NOW + timedelta(minutes=1), 60.0),
    monotonic: float = 1.0,
    prepared_bytes: bytes | None = None,
    withheld_item_ids: tuple[str, ...] = (),
) -> tuple[object, _Audit, _Gateway]:
    binding = _binding()
    audit = _Audit(persist=persist)
    gateway = _Gateway()
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, object()),
        cast(PrivacyClassifierPort, object()),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, gateway),
        cast(ClockPort, _Clock(monotonic=monotonic)),
        ready_composition.IdPort(),
    )
    coordinator._semantic_dispatch_guard = dispatch_guard  # pyright: ignore[reportPrivateUsage]
    selected_bytes = b"{}" if prepared_bytes is None else prepared_bytes
    minimized = replace(
        _minimized(),
        prepared_bytes=selected_bytes,
        byte_count=len(selected_bytes),
        case_digest="sha256:" + hashlib.sha256(selected_bytes).hexdigest(),
        withheld_item_ids=withheld_item_ids,
    )
    proposal = replace(
        _proposal(binding, expires_at=proposal_expires_at),
        prepared_bytes=selected_bytes,
        prepared_case_digest=minimized.case_digest,
    )
    result = await coordinator._dispatch_approved(  # pyright: ignore[reportPrivateUsage]
        _candidate(binding),
        _effective(binding),
        proposal,
        minimized,
        ConsentSource.BASELINE_POLICY,
        deadline,
        subject_digest=_SUBJECT_DIGEST,
    )
    return result, audit, gateway


@pytest.mark.anyio
async def test_withheld_notice_allows_a_safe_replacement_on_the_next_check() -> None:
    """The next review dispatch uses the caller's replacement packet, not stale withheld bytes."""

    first_payload = b'{"items":[{"item_id":"clean"}]}'
    first, first_audit, first_gateway = await _dispatch(
        persist=True,
        prepared_bytes=first_payload,
        withheld_item_ids=("excerpt-heuristic",),
    )
    assert isinstance(first, SemanticEgressSuccess)
    assert first.withheld_item_ids == ("excerpt-heuristic",)
    assert first_gateway.payloads == [first_payload]
    assert b"auth_token" not in first_gateway.payloads[0]
    assert first_audit.receipt is not None
    assert first_audit.receipt.withheld_item_ids == ("excerpt-heuristic",)

    replacement_payload = b'{"items":[{"item_id":"excerpt-replacement","content":"safe context"}]}'
    second, second_audit, second_gateway = await _dispatch(
        persist=True,
        prepared_bytes=replacement_payload,
    )
    assert isinstance(second, SemanticEgressSuccess)
    assert second.withheld_item_ids == ()
    assert second_gateway.payloads == [replacement_payload]
    assert b"excerpt-replacement" in second_gateway.payloads[0]
    assert second_audit.receipt is not None
    assert second_audit.receipt.withheld_item_ids == ()


def test_egress_results_enforce_the_shared_opaque_item_id_shape() -> None:
    with pytest.raises(ValueError, match="semantic_withheld_item_ids_invalid"):
        SemanticEgressBlocked(
            _REQUEST,
            PrivacyOutcome.BLOCKED_BY_POLICY,
            PrivacyReason.POLICY_DENIED,
            withheld_item_ids=("has whitespace",),
        )


@pytest.mark.anyio
async def test_local_semantic_success_persists_receipt_and_finalizes_local_provenance() -> None:
    result, audit, _gateway = await _dispatch(persist=True)

    assert isinstance(result, SemanticEgressSuccess)
    assert result.authorization_id is None
    assert result.dispatch_kind is SemanticDispatchKind.LOCAL_MODEL
    assert result.request_commitment is None
    assert audit.authorize_calls == 0
    assert audit.receipt is not None
    assert audit.receipt.sink is LocalDisclosureSink.LOCAL_MODEL
    assert audit.receipt.outcome is PrivacyOutcome.COMPLETED
    final = ready_composition._map_egress_to_final(  # pyright: ignore[reportPrivateUsage]
        result, ready_composition.IdPort()
    )
    assert final.status is SemanticStatus.SUCCEEDED
    assert final.provenance is not None
    assert final.provenance.dispatch_kind is SemanticDispatchKind.LOCAL_MODEL
    assert final.provenance.privacy_receipt_id == audit.receipt.receipt_id
    assert final.provenance.local_disclosure_reservation_id == _PROPOSAL
    assert final.provenance.egress_authorization_id is None
    assert final.provenance.request_commitment is None
    redacted_final = ready_composition._map_egress_to_final(  # pyright: ignore[reportPrivateUsage]
        replace(result, redacted_span_count=2), ready_composition.IdPort()
    )
    assert redacted_final.case_content_gaps == ("semantic_review_value_redacted",)


@pytest.mark.anyio
async def test_semantic_success_names_only_content_the_exact_prepared_packet_carried() -> None:
    """Issue #904: the check may credit only what the sent (bounded, minimized) packet carried.

    A reference counts as the source of a carried content item. A reference named only by an
    omission row, or by a structural item beside its own omission, does not.
    """

    from builders.policy_cases import act, evt, make_case, record, res
    from yoetz.domain.events import ResultOutcome, ResultRecordedPayload
    from yoetz.protocol.canonical import JsonValue, canonical_encode

    shown = "evd_30000000-0000-4000-8000-000000000011"
    withheld = "evd_30000000-0000-4000-8000-000000000012"
    clipped = "evt_30000000-0000-4000-8000-000000000013"
    recorded_by = str(evt(7))
    packet = canonical_encode(
        cast(
            JsonValue,
            {
                "schema": "yoetz.review-packet-case/2",
                "frontier_refs": sorted([shown, withheld, clipped, recorded_by]),
                "items": [
                    {
                        "item_id": "excerpt-a",
                        "source_ref": shown,
                        "linked_subject_refs": [withheld],
                    },
                    {"item_id": "history-b", "source_ref": clipped, "linked_subject_refs": []},
                    {
                        "item_id": "history-c",
                        "source_ref": recorded_by,
                        "category": "command_metadata",
                        "linked_subject_refs": [recorded_by],
                        # The item's own content carries the recording event's payload.
                        "content": canonical_encode(
                            cast(
                                JsonValue,
                                {"event_id": recorded_by, "payload": {"outcome": "success"}},
                            )
                        ).decode("utf-8"),
                    },
                ],
                "review_packet": {
                    "omissions": [
                        {"subject_ref": withheld, "category": "evidence_excerpt", "reason": "x"},
                        {"subject_ref": clipped, "category": "timeline", "reason": "x"},
                    ]
                },
            },
        )
    )
    result, _audit, _gateway = await _dispatch(persist=True, prepared_bytes=packet)

    assert isinstance(result, SemanticEgressSuccess)
    assert result.disclosure is not None
    assert result.disclosure.carried == frozenset({shown, recorded_by})
    assert result.disclosure.withheld == frozenset({withheld, clipped})
    assert result.disclosure.payload_events == frozenset({recorded_by})
    assert result.provider_input_manifest_failure == SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP
    final = ready_composition._map_egress_to_final(  # pyright: ignore[reportPrivateUsage]
        result, ready_composition.IdPort()
    )
    assert final.case_included_refs == frozenset({shown, recorded_by})
    # With the frozen projection, the result that event recorded counts as sent too.
    projection = make_case(
        results={res(1): record(ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS, 0), 7)}
    ).projection
    expanded = ready_composition._map_egress_to_final(  # pyright: ignore[reportPrivateUsage]
        result, ready_composition.IdPort(), projection=projection
    )
    assert expanded.case_included_refs == frozenset({shown, recorded_by, str(res(1))})
    # A document that is not a readable review packet proves nothing about what it carried.
    opaque, _audit, _gateway = await _dispatch(persist=True)
    assert isinstance(opaque, SemanticEgressSuccess)
    assert opaque.disclosure is None
    assert opaque.provider_input_manifest_failure == SEMANTIC_PROVIDER_INPUT_MANIFEST_INVALID_GAP


def test_success_boundary_rejects_unclassified_provider_manifest_failures() -> None:
    with pytest.raises(ValueError, match="provider_input_manifest_failure_invalid"):
        SemanticEgressSuccess(
            _REQUEST,
            _PROPOSAL,
            None,
            SemanticDispatchKind.LOCAL_MODEL,
            cast(
                SemanticResultSuccess,
                scripted_success(SemanticJudgment("no_material_discrepancy", ())).result,
            ),
            _CASE_DIGEST,
            provider_input_manifest_failure="provider_text",
        )


@pytest.mark.anyio
async def test_local_semantic_success_fails_closed_when_receipt_is_not_durable() -> None:
    result, audit, _gateway = await _dispatch(persist=False)

    assert isinstance(result, SemanticEgressSuccess)
    assert audit.authorize_calls == 0
    final = ready_composition._map_egress_to_final(  # pyright: ignore[reportPrivateUsage]
        result, ready_composition.IdPort()
    )
    assert final.status is SemanticStatus.UNAVAILABLE
    assert final.reason is SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN
    assert final.provenance is None


@pytest.mark.anyio
async def test_external_semantic_success_still_requires_authority_and_request_commitment() -> None:
    local, _audit, _gateway = await _dispatch(persist=True)
    assert isinstance(local, SemanticEgressSuccess)
    external = replace(
        local,
        authorization_id="aut_30000000-0000-4000-8000-000000000005",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        request_commitment="hmac-sha256:" + "6" * 64,
    )

    final = ready_composition._map_egress_to_final(  # pyright: ignore[reportPrivateUsage]
        external, ready_composition.IdPort()
    )
    assert final.status is SemanticStatus.SUCCEEDED
    assert final.provenance is not None
    assert final.provenance.dispatch_kind is SemanticDispatchKind.EXTERNAL
    assert final.provenance.egress_authorization_id == external.authorization_id
    assert final.provenance.request_commitment == external.request_commitment
    assert final.provenance.local_disclosure_reservation_id is None

    unbound = ready_composition._map_egress_to_final(  # pyright: ignore[reportPrivateUsage]
        replace(external, request_commitment=None), ready_composition.IdPort()
    )
    assert unbound.status is SemanticStatus.UNAVAILABLE
    assert unbound.reason is SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN
    assert unbound.provenance is None


@pytest.mark.anyio
async def test_local_semantic_rechecks_content_fence_before_provider_call() -> None:
    result, audit, gateway = await _dispatch(persist=True, dispatch_guard=lambda: False)

    assert isinstance(result, SemanticEgressBlocked)
    assert result.reason.value == "scope_mismatch"
    assert audit.receipt is None
    assert gateway.calls == 0


@pytest.mark.anyio
async def test_expired_execution_deadline_is_timeout_before_dispatch() -> None:
    result, audit, gateway = await _dispatch(
        persist=True,
        deadline=Deadline(_NOW + timedelta(minutes=1), 1.0),
        monotonic=1.0,
    )

    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.TIMEOUT
    assert result.reason is PrivacyReason.DEADLINE_EXPIRED
    assert audit.receipt is None
    assert gateway.calls == 0


@pytest.mark.anyio
async def test_expired_proposal_remains_approval_expiry_with_live_deadline() -> None:
    result, audit, gateway = await _dispatch(
        persist=True,
        proposal_expires_at=_NOW - timedelta(seconds=1),
        deadline=Deadline(_NOW + timedelta(minutes=1), 60.0),
        monotonic=1.0,
    )

    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.APPROVAL_EXPIRED
    assert result.reason is PrivacyReason.AUTHORIZATION_EXPIRED
    assert audit.receipt is None
    assert gateway.calls == 0
