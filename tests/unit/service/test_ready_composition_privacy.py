"""Privacy refusal mapping keeps a typed rendered-body block actionable."""

from __future__ import annotations

from yoetz.application.egress import SemanticEgressProviderOutcome
from yoetz.domain.findings import SamplingParams, SemanticDispatchKind, SemanticFailureClass
from yoetz.ports.semantic import ProviderAttemptProvenance, SemanticResultUnavailable
from yoetz.protocol.models import SemanticReason, SemanticStatus
from yoetz.service.ready_composition import (  # pyright: ignore[reportPrivateUsage]
    _map_egress_to_final,  # pyright: ignore[reportPrivateUsage]
)

_DIGEST = "sha256:" + "a" * 64


def test_typed_rendered_body_privacy_refusal_maps_to_privacy_recovery() -> None:
    provenance = ProviderAttemptProvenance(
        provider="provider",
        endpoint_profile_id="endpoint",
        endpoint_profile_version="1.0.0",
        model="model",
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest="sha256:" + "0" * 64,
        privacy_policy_digest="sha256:" + "0" * 64,
        sampling_params=SamplingParams(1),
        latency_ms=0,
        status=SemanticStatus.UNAVAILABLE,
        failure_class=SemanticFailureClass.RESPONSE_CONTENT,
    )
    result = SemanticEgressProviderOutcome(
        request_id="req_00000000-0000-4000-8000-000000000001",
        privacy_proposal_id="ppr_00000000-0000-4000-8000-000000000001",
        authorization_id=None,
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        result=SemanticResultUnavailable(provenance),
        case_digest=_DIGEST,
    )

    mapped = _map_egress_to_final(  # pyright: ignore[reportPrivateUsage]
        result,
        attempt_id="sma_00000000-0000-4000-8000-000000000001",
    )

    assert mapped.status is SemanticStatus.BLOCKED_FORBIDDEN_DATA
    assert mapped.reason is SemanticReason.NEVER_SEND_DETECTED
    assert mapped.provenance is None
