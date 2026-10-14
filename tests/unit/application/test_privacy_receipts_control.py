"""Privacy receipt get/list are reachable over ordinary control and round-trip the client wire.

Issue #730: both methods existed in the port, the application, the client, and the CLI, but the
service handler map never registered them, so every ``yoetz privacy receipts`` call was answered
``method_forbidden`` and rendered as ``invalid_request``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import pytest

from yoetz.application.privacy_control import (
    build_privacy_support_handlers,
    encode_privacy_receipt_view,
)
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ConsentSource,
    DataCategory,
    EgressChannel,
    EgressReceipt,
    LocalDisclosureReceipt,
    LocalDisclosureSink,
    PrivacyOutcome,
    PrivacyReason,
    ProviderBinding,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptSecretScanStage,
    ReceiptTransformations,
    RequestCommitment,
)
from yoetz.domain.values import JsonObject, freeze_json
from yoetz.ports.control import ControlError, ControlMethod
from yoetz.ports.privacy import (
    LocalDisclosureReceiptView,
    NetworkEgressReceiptView,
    PrivacyAuditUnreadable,
    PrivacyReceiptAudience,
    PrivacyReceiptCursorInvalid,
    PrivacyReceiptPage,
    PrivacyReceiptQuery,
    PrivacyReceiptView,
)
from yoetz.service.client import (
    ListPrivacyReceiptsRequest,
    PrivacyReceiptFilters,
    PrivacyReceiptFound,
    _receipt_get_from_wire,  # pyright: ignore[reportPrivateUsage]
    _receipt_page_from_wire,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_NOW = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
_INSTALLATION = "ins_70000000-0000-4000-8000-000000000001"
_REQUEST = "req_70000000-0000-4000-8000-000000000002"
_PROPOSAL = "ppr_70000000-0000-4000-8000-000000000003"
_POLICY = "pvy_70000000-0000-4000-8000-000000000004"
_RECEIPT = "egr_70000000-0000-4000-8000-000000000005"
_RECEIPT_2 = "egr_70000000-0000-4000-8000-000000000006"
_AUTHORIZATION = "aut_70000000-0000-4000-8000-000000000007"
_DISPATCH = "dsp_70000000-0000-4000-8000-000000000008"
_TASK = "tsk_70000000-0000-4000-8000-000000000009"
_DIGEST = f"sha256:{'7' * 64}"
_COMMITMENT = f"hmac-sha256:{'8' * 64}"


class _Audit:
    def __init__(self, *views: PrivacyReceiptView) -> None:
        self.views = views
        self.queries: list[PrivacyReceiptQuery] = []
        self.lookups: list[str] = []
        self.audiences: list[PrivacyReceiptAudience] = []
        self.next_cursor: str | None = None
        self.failure: BaseException | None = None
        self.undecodable: tuple[int, tuple[str, ...]] = (0, ())

    async def list_receipts(
        self, query: PrivacyReceiptQuery, audience: PrivacyReceiptAudience
    ) -> PrivacyReceiptPage:
        self.queries.append(query)
        self.audiences.append(audience)
        if query.cursor == "mismatch":
            raise PrivacyReceiptCursorInvalid("privacy_receipt_cursor_query_mismatch")
        if self.failure is not None:
            raise self.failure
        return PrivacyReceiptPage(11, self.views, self.next_cursor, *self.undecodable)

    async def get_receipt(
        self, receipt_id: str, audience: PrivacyReceiptAudience
    ) -> PrivacyReceiptView | None:
        self.lookups.append(receipt_id)
        self.audiences.append(audience)
        if self.failure is not None:
            raise self.failure
        return next((view for view in self.views if view.receipt.receipt_id == receipt_id), None)


class _App:
    def __init__(self, audit: _Audit) -> None:
        self.audit = audit


def _handlers(*views: PrivacyReceiptView) -> tuple[dict[ControlMethod, Any], _Audit]:
    audit = _Audit(*views)
    handlers = build_privacy_support_handlers(_App(audit))  # type: ignore[arg-type]
    return dict(handlers), audit


def _policy() -> ReceiptPolicyBinding:
    return ReceiptPolicyBinding(_POLICY, 3, _DIGEST, _DIGEST)


def _local_view(receipt_id: str = _RECEIPT, finished_at: datetime = _NOW) -> PrivacyReceiptView:
    return LocalDisclosureReceiptView(
        "local_disclosure",
        LocalDisclosureReceipt(
            "1.0.0",
            receipt_id,
            _REQUEST,
            _PROPOSAL,
            LocalDisclosureSink.LOCAL_HUMAN_VIEW,
            PrivacyOutcome.COMPLETED,
            finished_at,
            AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION),
            "client_result_projection",
            _policy(),
            ConsentSource.BASELINE_POLICY,
            (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
            (),
            ReceiptCounts(3, 2, 1, 2, 1, 40, 20, 5, None),
            ReceiptTransformations(1, 0, 1),
            ReceiptSecretScan(
                "scanner-v1", _DIGEST, 0, True, ReceiptSecretScanStage.LEGACY_UNKNOWN
            ),
            None,
            1,
        ),
    )


def _network_view() -> PrivacyReceiptView:
    """A completed subscription review: the receipt kind a real AI-powered check records."""

    return NetworkEgressReceiptView(
        "network_egress",
        EgressReceipt(
            "1.0.0",
            _RECEIPT_2,
            _REQUEST,
            _PROPOSAL,
            EgressChannel.LLM_INFERENCE,
            PrivacyOutcome.COMPLETED,
            _NOW,
            AuthorizationScope(AuthorizationScopeKind.TASK, _INSTALLATION, _COMMITMENT, _TASK),
            "semantic-review",
            ProviderBinding("openai-codex", "gpt-5.6", "codex-subscription", "1.0.0", "external"),
            _policy(),
            ConsentSource.SCOPED_LOCAL_HUMAN,
            (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
            (),
            ReceiptCounts(4, 4, 0, 4, 0, 900, 900, None, 1200),
            ReceiptTransformations(0, 0, 0),
            ReceiptSecretScan(
                "scanner-v1", _DIGEST, 0, True, ReceiptSecretScanStage.LEGACY_UNKNOWN
            ),
            None,
            1,
            authorization_id=_AUTHORIZATION,
            dispatch_id=_DISPATCH,
            dispatch_started_at=_NOW,
            request_commitment=RequestCommitment(
                "hmac-sha256/yoetz-privacy-egress-request-v1", _COMMITMENT
            ),
        ),
    )


def _wire(value: JsonObject) -> JsonObject:
    """What the daemon hands the client: the same body after a canonical freeze."""

    return cast(JsonObject, freeze_json(value))


def test_both_receipt_methods_are_registered_support_handlers() -> None:
    handlers, _ = _handlers()

    assert ControlMethod.PRIVACY_RECEIPTS_GET in handlers
    assert ControlMethod.PRIVACY_RECEIPTS_LIST in handlers


@pytest.mark.parametrize("view", [_local_view(), _network_view()], ids=["local", "network"])
async def test_get_returns_the_receipt_in_the_shape_the_client_decodes(
    view: PrivacyReceiptView,
) -> None:
    handlers, audit = _handlers(view)

    body = await handlers[ControlMethod.PRIVACY_RECEIPTS_GET](
        {"schema_version": "1.0.0", "receipt_id": view.receipt.receipt_id}
    )

    assert body["outcome"] == "found"
    decoded = _receipt_get_from_wire(_wire(body))
    assert isinstance(decoded, PrivacyReceiptFound)
    assert decoded.receipt == view
    assert audit.lookups == [view.receipt.receipt_id]
    assert audit.audiences == [PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL]


async def test_get_of_an_unknown_receipt_is_not_found_not_an_error() -> None:
    handlers, _ = _handlers(_local_view())

    body = await handlers[ControlMethod.PRIVACY_RECEIPTS_GET](
        {"schema_version": "1.0.0", "receipt_id": _RECEIPT_2}
    )

    assert dict(body) == {"schema_version": "1.0.0", "outcome": "not_found"}


@pytest.mark.parametrize(
    "request_body",
    [
        {},
        {"schema_version": "1.0.0"},
        {"schema_version": "2.0.0", "receipt_id": _RECEIPT},
        {"schema_version": "1.0.0", "receipt_id": "not-a-receipt-id"},
        {"schema_version": "1.0.0", "receipt_id": _REQUEST},
        {"schema_version": "1.0.0", "receipt_id": _RECEIPT, "extra": True},
        "text",
    ],
)
async def test_get_rejects_malformed_bodies_before_touching_the_audit(
    request_body: object,
) -> None:
    handlers, audit = _handlers(_local_view())

    with pytest.raises(ControlError) as raised:
        await handlers[ControlMethod.PRIVACY_RECEIPTS_GET](request_body)

    assert raised.value.reason == "invalid_request"
    assert audit.lookups == []


async def test_list_returns_the_page_in_the_shape_the_client_decodes() -> None:
    first = _local_view()
    second = _network_view()
    handlers, audit = _handlers(second, first)
    audit.next_cursor = "AAAA"

    body = await handlers[ControlMethod.PRIVACY_RECEIPTS_LIST](
        dict(ListPrivacyReceiptsRequest()._wire())  # pyright: ignore[reportPrivateUsage]
    )

    page = _receipt_page_from_wire(_wire(body))
    assert page == PrivacyReceiptPage(11, (second, first), "AAAA")
    assert audit.queries == [PrivacyReceiptQuery(limit=50)]
    assert audit.audiences == [PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL]


async def test_list_without_a_next_page_omits_the_cursor() -> None:
    handlers, _ = _handlers()

    body = await handlers[ControlMethod.PRIVACY_RECEIPTS_LIST](
        {"schema_version": "1.0.0", "filters": {}, "page_size": 50}
    )

    assert dict(body) == {"schema_version": "1.0.0", "snapshot_generation": "11", "receipts": ()}


async def test_list_decodes_every_client_filter_into_the_port_query() -> None:
    handlers, audit = _handlers()
    request = ListPrivacyReceiptsRequest(
        PrivacyReceiptFilters(
            outcome=PrivacyOutcome.COMPLETED,
            channel=EgressChannel.LLM_INFERENCE,
            sink=LocalDisclosureSink.AGENT_CONTEXT,
            provider_id="openai-codex",
            endpoint_profile_id="codex-subscription",
            policy_version=3,
            scope_kind=AuthorizationScopeKind.TASK,
            finished_from=datetime(2026, 9, 1, tzinfo=UTC),
            finished_through=_NOW,
        ),
        page_size=7,
        cursor="AAAA",
    )

    await handlers[ControlMethod.PRIVACY_RECEIPTS_LIST](
        dict(request._wire())  # pyright: ignore[reportPrivateUsage]
    )

    assert audit.queries == [
        PrivacyReceiptQuery(
            outcome=PrivacyOutcome.COMPLETED,
            channel=EgressChannel.LLM_INFERENCE,
            local_sink=LocalDisclosureSink.AGENT_CONTEXT,
            provider_id="openai-codex",
            endpoint_profile_id="codex-subscription",
            policy_version=3,
            scope_kind=AuthorizationScopeKind.TASK,
            finished_at_from=datetime(2026, 9, 1, tzinfo=UTC),
            finished_at_through=_NOW,
            limit=7,
            cursor="AAAA",
        )
    ]


@pytest.mark.parametrize(
    "request_body",
    [
        {},
        {"schema_version": "2.0.0", "filters": {}, "page_size": 50},
        {"schema_version": "1.0.0", "filters": {}, "page_size": 0},
        {"schema_version": "1.0.0", "filters": {}, "page_size": 101},
        {"schema_version": "1.0.0", "filters": {}, "page_size": True},
        {"schema_version": "1.0.0", "filters": {}, "page_size": 50, "cursor": ""},
        {"schema_version": "1.0.0", "filters": {}, "page_size": 50, "cursor": "not base64!"},
        {"schema_version": "1.0.0", "filters": [], "page_size": 50},
        {"schema_version": "1.0.0", "filters": {"outcome": "won"}, "page_size": 50},
        {"schema_version": "1.0.0", "filters": {"channel": "email"}, "page_size": 50},
        {"schema_version": "1.0.0", "filters": {"policy_version": 3}, "page_size": 50},
        {"schema_version": "1.0.0", "filters": {"policy_version": "0"}, "page_size": 50},
        {"schema_version": "1.0.0", "filters": {"policy_version": "03"}, "page_size": 50},
        {"schema_version": "1.0.0", "filters": {"finished_from": "yesterday"}, "page_size": 50},
        {"schema_version": "1.0.0", "filters": {"provider_id": ""}, "page_size": 50},
        {"schema_version": "1.0.0", "filters": {"outcom": "completed"}, "page_size": 50},
        {"schema_version": "1.0.0", "filters": {}, "page_size": 50, "receipt_id": _RECEIPT},
        {
            "schema_version": "1.0.0",
            "filters": {
                "finished_from": "2026-09-13T12:00:00.000Z",
                "finished_through": "2026-09-01T00:00:00.000Z",
            },
            "page_size": 50,
        },
    ],
)
async def test_list_rejects_malformed_bodies_before_touching_the_audit(
    request_body: object,
) -> None:
    handlers, audit = _handlers()

    with pytest.raises(ControlError) as raised:
        await handlers[ControlMethod.PRIVACY_RECEIPTS_LIST](request_body)

    assert raised.value.reason == "invalid_request"
    assert audit.queries == []


async def test_a_cursor_from_another_query_is_a_caller_error_not_a_crash() -> None:
    handlers, _ = _handlers()

    with pytest.raises(ControlError) as raised:
        await handlers[ControlMethod.PRIVACY_RECEIPTS_LIST](
            {"schema_version": "1.0.0", "filters": {}, "page_size": 50, "cursor": "mismatch"}
        )

    assert raised.value.reason == "invalid_request"
    assert raised.value.retryable is False


@pytest.mark.parametrize(
    "reason",
    [
        "privacy_audit_page_invariant_violated",
        "privacy_audit_generation_unavailable",
        "privacy_audit_local_row_undecodable",
    ],
)
async def test_a_store_failure_is_named_and_never_the_callers_invalid_request(
    reason: str,
) -> None:
    """Issue #921: the store's fault used to reach the operator as ``invalid_request``."""

    handlers, audit = _handlers(_local_view())
    audit.failure = PrivacyAuditUnreadable(reason)

    with pytest.raises(ControlError) as listed:
        await handlers[ControlMethod.PRIVACY_RECEIPTS_LIST](
            {"schema_version": "1.0.0", "filters": {}, "page_size": 100}
        )
    with pytest.raises(ControlError) as fetched:
        await handlers[ControlMethod.PRIVACY_RECEIPTS_GET](
            {"schema_version": "1.0.0", "receipt_id": _RECEIPT}
        )

    for raised in (listed, fetched):
        assert raised.value.reason == "privacy_audit_unreadable"
        assert raised.value.retryable is False
        assert raised.value.correlation_id is not None


async def test_an_unclassified_failure_is_not_folded_into_invalid_request() -> None:
    """Only a caller's own mistake is ``invalid_request``; anything unexpected keeps its type so
    the daemon records it as ``read_projection_failed`` with a diagnostic."""

    handlers, audit = _handlers(_local_view())
    audit.failure = ValueError("privacy_audit_something_unforeseen")

    with pytest.raises(ValueError, match="privacy_audit_something_unforeseen"):
        await handlers[ControlMethod.PRIVACY_RECEIPTS_LIST](
            {"schema_version": "1.0.0", "filters": {}, "page_size": 100}
        )


async def test_a_partial_page_carries_its_count_and_ids_through_the_client() -> None:
    skipped = "egr_70000000-0000-4000-8000-00000000000a"
    handlers, audit = _handlers(_network_view(), _local_view())
    audit.undecodable = (2, (skipped,))

    body = await handlers[ControlMethod.PRIVACY_RECEIPTS_LIST](
        {"schema_version": "1.0.0", "filters": {}, "page_size": 100}
    )

    assert body["undecodable_count"] == "2"
    assert body["undecodable_receipt_ids"] == (skipped,)
    page = _receipt_page_from_wire(_wire(body))
    assert page == PrivacyReceiptPage(11, (_network_view(), _local_view()), None, 2, (skipped,))


async def test_a_complete_page_keeps_its_exact_prior_shape() -> None:
    handlers, _ = _handlers(_local_view())

    body = await handlers[ControlMethod.PRIVACY_RECEIPTS_LIST](
        {"schema_version": "1.0.0", "filters": {}, "page_size": 100}
    )

    assert set(body) == {"schema_version", "snapshot_generation", "receipts"}


def test_optional_receipt_fields_are_absent_not_null() -> None:
    """The receipt schema forbids ``null``; an absent field is how "no value" is spelled."""

    local = cast(dict[str, Any], dict(encode_privacy_receipt_view(_local_view()))["receipt"])
    network = cast(dict[str, Any], dict(encode_privacy_receipt_view(_network_view()))["receipt"])

    assert "safe_failure_reason" not in local
    assert "request_body_bytes" not in local["counts"]
    assert local["counts"]["estimated_input_tokens"] == "5"
    assert "estimated_input_tokens" not in network["counts"]
    assert network["counts"]["request_body_bytes"] == "1200"
    assert network["scope"] == {
        "kind": "task",
        "installation_id": _INSTALLATION,
        "workspace_ref_commitment": _COMMITMENT,
        "task_id": _TASK,
    }
    assert local["scope"] == {"kind": "machine", "installation_id": _INSTALLATION}
    assert local["policy"]["version"] == "3"
    assert None not in _leaves(local) and None not in _leaves(network)


def test_a_blocked_receipt_carries_its_reason() -> None:
    blocked = LocalDisclosureReceiptView(
        "local_disclosure",
        LocalDisclosureReceipt(
            "1.0.0",
            _RECEIPT,
            _REQUEST,
            _PROPOSAL,
            LocalDisclosureSink.LOCAL_HUMAN_VIEW,
            PrivacyOutcome.BLOCKED_BY_POLICY,
            _NOW,
            AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION),
            "client_result_projection",
            _policy(),
            ConsentSource.NONE,
            (),
            (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
            ReceiptCounts(1, 0, 1, 0, 1, 1, 0),
            ReceiptTransformations(0, 0, 1),
            ReceiptSecretScan(
                "scanner-v1", _DIGEST, 0, True, ReceiptSecretScanStage.LEGACY_UNKNOWN
            ),
            PrivacyReason.POLICY_DENIED,
            1,
        ),
    )

    wrapper = encode_privacy_receipt_view(blocked)
    encoded = cast(dict[str, Any], dict(wrapper)["receipt"])

    assert encoded["safe_failure_reason"] == "policy_denied"
    decoded = _receipt_get_from_wire(
        _wire(JsonObject({"schema_version": "1.0.0", "outcome": "found", "receipt": wrapper}))
    )
    assert isinstance(decoded, PrivacyReceiptFound)
    assert decoded.receipt == blocked


def _leaves(value: object) -> list[object]:
    if isinstance(value, dict):
        return [leaf for item in cast(dict[str, object], value).values() for leaf in _leaves(item)]
    if isinstance(value, (list, tuple)):
        return [leaf for item in cast(list[object], value) for leaf in _leaves(item)]
    return [value]
