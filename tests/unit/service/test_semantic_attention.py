"""Attempt-derived attention for standing provider advice (#819)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from finishup.application.egress import (
    SemanticEgressAttemptUnknown,
    SemanticEgressProviderOutcome,
    SemanticEgressSuccess,
)
from finishup.domain.findings import (
    RuntimeAttemptEvidence,
    SamplingParams,
    SemanticDispatchKind,
    SemanticFailureClass,
)
from finishup.domain.privacy import ProviderBinding
from finishup.ports.semantic import (
    ProviderAttemptProvenance,
    SemanticJudgment,
    SemanticResultInvalid,
    SemanticResultRefused,
    SemanticResultSuccess,
    SemanticResultTimeout,
    SemanticResultUnavailable,
)
from finishup.protocol.models import SemanticStatus
from finishup.service.semantic_attention import (
    SemanticAttentionTracker,
    semantic_attention_for_outcome,
)

_DIGEST = "sha256:" + "a" * 64
_CODEX = ProviderBinding(
    "openai-codex", "gpt-5.6-luna", "codex-chatgpt-subscription", "1.0.0", "external"
)
_API = ProviderBinding("openai", "gpt-5.6-sol", "openai-responses", "1.0.0", "external")


def _runtime(stage: str | None) -> RuntimeAttemptEvidence:
    return RuntimeAttemptEvidence(
        credential_authority="external_runtime_oauth",
        runtime_version="0.150.1",
        runtime_source_identity="openai-codex-npm-linux-x64-0.150.1",
        executable_sha256=_DIGEST,
        app_server_schema_sha256=_DIGEST,
        capability_cell_sha256=_DIGEST,
        capability_profile="codex-evaluator/0.150.1/v2",
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        launcher_sha256=_DIGEST,
        isolated_config_sha256=_DIGEST,
        disclosed_case_sha256=_DIGEST,
        instruction_sha256=_DIGEST,
        output_schema_sha256=_DIGEST,
        selection_sha256=_DIGEST,
        upstream_body_observability="unavailable",
        auth_mode=None,
        plan_type=None,
        reasoning_effort="high",
        thread_id=None,
        turn_id=None,
        final_output_sha256=None,
        case_disclosed=False,
        turn_acknowledged=False,
        process_cleanup="terminated",
        failure_stage=stage,
    )


def _provenance(
    binding: ProviderBinding,
    status: SemanticStatus,
    failure_class: SemanticFailureClass | None = None,
    runtime: RuntimeAttemptEvidence | None = None,
) -> ProviderAttemptProvenance:
    return ProviderAttemptProvenance(
        provider=binding.provider_id,
        endpoint_profile_id=binding.endpoint_profile_id,
        endpoint_profile_version=binding.endpoint_profile_version,
        model=binding.model_id,
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        status=status,
        failure_class=failure_class,
        runtime_evidence=runtime,
    )


def _outcome(result: object) -> SemanticEgressProviderOutcome:
    return SemanticEgressProviderOutcome(
        request_id="req-1",
        privacy_proposal_id="ppr-1",
        authorization_id=None,
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        result=result,  # type: ignore[arg-type]
        case_digest=_DIGEST,
    )


def _unavailable(
    binding: ProviderBinding,
    failure_class: SemanticFailureClass,
    stage: str | None = None,
    *,
    runtime: bool = True,
) -> SemanticEgressProviderOutcome:
    evidence = _runtime(stage) if runtime else None
    return _outcome(
        SemanticResultUnavailable(
            _provenance(binding, SemanticStatus.UNAVAILABLE, failure_class, evidence)
        )
    )


def _success(binding: ProviderBinding) -> SemanticEgressSuccess:
    return SemanticEgressSuccess(
        request_id="req-1",
        privacy_proposal_id="ppr-1",
        authorization_id=None,
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        result=SemanticResultSuccess(
            SemanticJudgment("no_material_discrepancy", ()),
            _provenance(binding, SemanticStatus.SUCCEEDED),
        ),
        case_digest=_DIGEST,
    )


@pytest.mark.parametrize(
    ("result", "expected"),
    (
        (
            _unavailable(_CODEX, SemanticFailureClass.AUTHENTICATION, "login_required"),
            "sign_in_required",
        ),
        # A ChatGPT token rejected mid-turn (HTTP 401) is still a Codex sign-in problem.
        (
            _unavailable(_CODEX, SemanticFailureClass.AUTHENTICATION, "turn_failed"),
            "sign_in_required",
        ),
        (
            _unavailable(_CODEX, SemanticFailureClass.UNSUPPORTED_PROFILE, "model_unavailable"),
            "model_unavailable",
        ),
        (
            _unavailable(
                _CODEX, SemanticFailureClass.UNSUPPORTED_PROFILE, "capability_evidence_stale"
            ),
            "runtime_update_required",
        ),
        (
            _unavailable(_API, SemanticFailureClass.AUTHENTICATION, runtime=False),
            "credential_rejected",
        ),
        (_unavailable(_API, SemanticFailureClass.AUTHORIZATION, runtime=False), "access_denied"),
        (
            _unavailable(_API, SemanticFailureClass.QUOTA_EXHAUSTED, runtime=False),
            "quota_exhausted",
        ),
    ),
)
def test_user_repairable_failures_name_one_closed_cause(result: object, expected: str) -> None:
    assert semantic_attention_for_outcome(result) == expected


@pytest.mark.parametrize(
    "failure_class",
    (
        SemanticFailureClass.RATE_LIMITED,
        SemanticFailureClass.TRANSPORT,
        SemanticFailureClass.TIMEOUT,
        SemanticFailureClass.PROVIDER_OUTAGE,
        SemanticFailureClass.UNSUPPORTED_PROFILE,
    ),
)
def test_transient_or_unclassified_failures_say_nothing(
    failure_class: SemanticFailureClass,
) -> None:
    assert semantic_attention_for_outcome(_unavailable(_API, failure_class, runtime=False)) is None
    assert (
        semantic_attention_for_outcome(_unavailable(_CODEX, failure_class, "launch_failed")) is None
    )


def test_answers_clear_and_non_answers_leave_attention_alone() -> None:
    assert semantic_attention_for_outcome(_success(_CODEX)) == "clear"
    invalid = SemanticResultInvalid(
        _provenance(_CODEX, SemanticStatus.INVALID, SemanticFailureClass.RESPONSE_SCHEMA), 12
    )
    refused = SemanticResultRefused(_provenance(_CODEX, SemanticStatus.REFUSED))
    timeout = SemanticResultTimeout(
        _provenance(_CODEX, SemanticStatus.TIMEOUT, SemanticFailureClass.TIMEOUT)
    )
    assert semantic_attention_for_outcome(_outcome(invalid)) == "clear"
    assert semantic_attention_for_outcome(_outcome(refused)) == "clear"
    assert semantic_attention_for_outcome(_outcome(timeout)) is None
    assert semantic_attention_for_outcome(SemanticEgressAttemptUnknown("req-1", "ppr-1")) is None
    assert semantic_attention_for_outcome(object()) is None


def test_tracker_records_clears_and_prefers_the_primary() -> None:
    tracker = SemanticAttentionTracker((_CODEX, _API))
    assert tracker.current(_CODEX, _API) is None

    tracker.record(_API, _unavailable(_API, SemanticFailureClass.QUOTA_EXHAUSTED, runtime=False))
    assert tracker.current(_CODEX, _API) == ("quota_exhausted", "openai")

    tracker.record(
        _CODEX, _unavailable(_CODEX, SemanticFailureClass.AUTHENTICATION, "login_required")
    )
    assert tracker.current(_CODEX, _API) == ("sign_in_required", "openai-codex")

    # A transient after the sign-in failure proves nothing about the sign-in.
    tracker.record(_CODEX, _unavailable(_CODEX, SemanticFailureClass.TRANSPORT, "transport_failed"))
    assert tracker.current(_CODEX, _API) == ("sign_in_required", "openai-codex")

    tracker.record(_CODEX, _success(_CODEX))
    assert tracker.current(_CODEX, _API) == ("quota_exhausted", "openai")
    tracker.record(_API, _success(_API))
    assert tracker.current(_CODEX, _API) is None


def test_tracker_ignores_unconfigured_bindings_and_never_raises() -> None:
    tracker = SemanticAttentionTracker((_CODEX, None))
    stranger = replace(_API, provider_id="stranger")
    tracker.record(stranger, _unavailable(stranger, SemanticFailureClass.QUOTA_EXHAUSTED))
    tracker.record("not-a-binding", _success(_CODEX))
    tracker.record(_CODEX, object())
    assert tracker.current(_CODEX, stranger) is None
