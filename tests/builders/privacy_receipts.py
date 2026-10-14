"""Real privacy receipt views, shared by the CLI rendering and wire-schema regressions.

Issues #731 and #732 were both missed because every test built its receipts inline: the CLI
rendering path never saw a decoded ``datetime`` and the control wire never saw the product's own
local-disclosure purpose.  One builder keeps those two surfaces on the same values.
"""

from __future__ import annotations

from datetime import UTC, datetime

from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ConsentSource,
    DataCategory,
    EgressChannel,
    EgressReceipt,
    LocalDisclosureReceipt,
    LocalDisclosureSink,
    PrivacyOutcome,
    ProviderBinding,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptTransformations,
    RequestCommitment,
)
from finishup.ports.privacy import (
    LocalDisclosureReceiptView,
    NetworkEgressReceiptView,
    PrivacyReceiptView,
)

__all__ = [
    "AUTHORIZATION_ID",
    "DISPATCH_ID",
    "INSTALLATION_ID",
    "LOCAL_RECEIPT_ID",
    "LOCAL_RECEIPT_PURPOSE",
    "NETWORK_RECEIPT_ID",
    "NETWORK_RECEIPT_PURPOSE",
    "NOW",
    "PROPOSAL_ID",
    "REQUEST_ID",
    "local_receipt_view",
    "network_receipt_view",
]

NOW = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
INSTALLATION_ID = "ins_70000000-0000-4000-8000-000000000001"
REQUEST_ID = "req_70000000-0000-4000-8000-000000000002"
PROPOSAL_ID = "ppr_70000000-0000-4000-8000-000000000003"
POLICY_ID = "pvy_70000000-0000-4000-8000-000000000004"
LOCAL_RECEIPT_ID = "egr_70000000-0000-4000-8000-000000000005"
NETWORK_RECEIPT_ID = "egr_70000000-0000-4000-8000-000000000006"
AUTHORIZATION_ID = "aut_70000000-0000-4000-8000-000000000007"
DISPATCH_ID = "dsp_70000000-0000-4000-8000-000000000008"
TASK_ID = "tsk_70000000-0000-4000-8000-000000000009"
DIGEST = f"sha256:{'7' * 64}"
COMMITMENT = f"hmac-sha256:{'8' * 64}"

# The product's own local-disclosure purpose, recorded in ``application/service.py`` and
# constrained by the ``agent_projection`` CHECK in ``migrations/catalog/0001.sql``.
LOCAL_RECEIPT_PURPOSE = "client_result_projection"
NETWORK_RECEIPT_PURPOSE = "semantic-review"


def _policy() -> ReceiptPolicyBinding:
    return ReceiptPolicyBinding(POLICY_ID, 3, DIGEST, DIGEST)


def local_receipt_view(
    receipt_id: str = LOCAL_RECEIPT_ID,
    finished_at: datetime = NOW,
    purpose: str = LOCAL_RECEIPT_PURPOSE,
) -> PrivacyReceiptView:
    """An agent-projection local disclosure: the receipt every ordinary workflow call records."""

    return LocalDisclosureReceiptView(
        "local_disclosure",
        LocalDisclosureReceipt(
            "1.0.0",
            receipt_id,
            REQUEST_ID,
            PROPOSAL_ID,
            LocalDisclosureSink.LOCAL_HUMAN_VIEW,
            PrivacyOutcome.COMPLETED,
            finished_at,
            AuthorizationScope(AuthorizationScopeKind.MACHINE, INSTALLATION_ID),
            purpose,
            _policy(),
            ConsentSource.BASELINE_POLICY,
            (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
            (),
            ReceiptCounts(3, 2, 1, 2, 1, 40, 20, 5, None),
            ReceiptTransformations(1, 0, 1),
            ReceiptSecretScan("scanner-v1", DIGEST, 0, True),
            None,
            1,
        ),
    )


def network_receipt_view(
    receipt_id: str = NETWORK_RECEIPT_ID,
    finished_at: datetime = NOW,
) -> PrivacyReceiptView:
    """A completed subscription review: the receipt kind a real semantic check records."""

    return NetworkEgressReceiptView(
        "network_egress",
        EgressReceipt(
            "1.0.0",
            receipt_id,
            REQUEST_ID,
            PROPOSAL_ID,
            EgressChannel.LLM_INFERENCE,
            PrivacyOutcome.COMPLETED,
            finished_at,
            AuthorizationScope(AuthorizationScopeKind.TASK, INSTALLATION_ID, COMMITMENT, TASK_ID),
            NETWORK_RECEIPT_PURPOSE,
            ProviderBinding("openai-codex", "gpt-5.6", "codex-subscription", "1.0.0", "external"),
            _policy(),
            ConsentSource.SCOPED_LOCAL_HUMAN,
            (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
            (),
            ReceiptCounts(4, 4, 0, 4, 0, 900, 900, None, 1200),
            ReceiptTransformations(0, 0, 0),
            ReceiptSecretScan("scanner-v1", DIGEST, 0, True),
            None,
            1,
            authorization_id=AUTHORIZATION_ID,
            dispatch_id=DISPATCH_ID,
            dispatch_started_at=finished_at,
            request_commitment=RequestCommitment(
                "hmac-sha256/yoetz-privacy-egress-request-v1", COMMITMENT
            ),
        ),
    )
