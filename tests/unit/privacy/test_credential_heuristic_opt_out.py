"""Owner opt-out for the low-confidence credential heuristic (issue #982).

The heuristic stays enforced by default and for every policy written before the field existed;
turning it off is a widening that needs the trusted decision, turning it back on is a tightening;
high-confidence detectors always block, whatever the setting.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from finishup.adapters.privacy.catalog import (
    _json,  # pyright: ignore[reportPrivateUsage]
    _local_receipt_from_bytes,  # pyright: ignore[reportPrivateUsage]
    _receipt_bytes,  # pyright: ignore[reportPrivateUsage]
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.adapters.privacy.gateway import _final_scan  # pyright: ignore[reportPrivateUsage]
from finishup.adapters.privacy.local_enforcer import (
    LocalPrivacyEnforcer,
    scan_exact_bytes,
)
from finishup.application.check import (
    FinalSemanticEvaluation,
    _credential_heuristic_gaps,  # pyright: ignore[reportPrivateUsage]
)
from finishup.application.egress import (
    _resume_scan_is_clean,  # pyright: ignore[reportPrivateUsage]
)
from finishup.application.privacy_control import encode_privacy_receipt_view
from finishup.application.privacy_policy import (
    _policy_for_scope,  # pyright: ignore[reportPrivateUsage]
    is_privacy_tightening,
    privacy_policy_changes,
)
from finishup.config.privacy_desired import (
    load_privacy_desired_canonical,
    render_privacy_desired_toml,
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    CandidateContextItem,
    ChannelPolicy,
    ConsentSource,
    CredentialHeuristic,
    DataClass,
    EgressChannel,
    ForbiddenDataKind,
    LocalDisclosureReceipt,
    LocalDisclosureSink,
    PrivacyDecision,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyProfile,
    ProviderBinding,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptSecretScanStage,
    ReceiptTransformations,
    ReviewContextProfile,
    ReviewSelectionPolicy,
    external_review_credential_heuristic,
)
from finishup.domain.receipts import SEMANTIC_REVIEW_CREDENTIAL_HEURISTIC_DISABLED_GAP
from finishup.kernel.closure_readiness import GAP_CLASSIFICATION, GapClass
from finishup.kernel.finding_resolution import (
    _DETERMINISTIC_PROOF_TOLERATED_GAPS,  # pyright: ignore[reportPrivateUsage]
    _SEMANTIC_PROOF_TOLERATED_GAPS,  # pyright: ignore[reportPrivateUsage]
)
from finishup.ports.privacy import EffectivePrivacyPolicy, LocalDisclosureReceiptView
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.models import DataCategory, SemanticReason, SemanticStatus
from finishup.protocol.schemas import validate_schema_instance

_INSTALLATION = "ins_10000000-0000-4000-8000-000000000001"
_TASK = "tsk_10000000-0000-4000-8000-000000000002"
_REQUEST = "req_10000000-0000-4000-8000-000000000003"
_POLICY_ID = "pvy_10000000-0000-4000-8000-000000000004"
_RECEIPT_ID = "egr_10000000-0000-4000-8000-000000000005"
_PROPOSAL_ID = "ppr_10000000-0000-4000-8000-000000000006"
_WORKSPACE = f"hmac-sha256:{'1' * 64}"
_DIGEST = f"sha256:{'2' * 64}"
_NOW = datetime(2026, 10, 7, tzinfo=UTC)
# Heuristic-only: an assignment the low-confidence detector flags, no known credential shape.
_HEURISTIC = b"auth_token: 'bounded-but-suspicious-value-9'"
# High-confidence: a known credential shape.
_CONCRETE = b"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456"
_PRIVATE_KEY = b"-----BEGIN " + b"RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD\n"


def _machine() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION)


def _task_scope() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.TASK, _INSTALLATION, _WORKSPACE, _TASK)


def _off(channel: EgressChannel) -> ChannelPolicy:
    return ChannelPolicy(
        channel, False, (), (), None, (), AuthorizationScopeKind.MACHINE, False, 0, 0, 0
    )


def _policy(
    setting: CredentialHeuristic = CredentialHeuristic.ENFORCED,
    *,
    scope: AuthorizationScope | None = None,
) -> PrivacyPolicy:
    return PrivacyPolicy(
        policy_id=_POLICY_ID,
        version=1,
        policy_digest=_DIGEST,
        profile=PrivacyProfile.LOCAL_ONLY,
        review_context_profile=ReviewContextProfile.STRUCTURAL,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        require_current_provider_data_use_evidence=False,
        network_egress_permitted=False,
        effective_scope=_machine() if scope is None else scope,
        channel_policies=tuple(
            _off(channel) for channel in sorted(EgressChannel, key=lambda c: c.value)
        ),
        local_model_enabled=False,
        local_model_binding=None,
        local_model_categories=(),
        local_model_data_classes=(),
        agent_context_categories=(DataCategory.FINDING_SUMMARY,),
        agent_context_data_classes=(DataClass.ORDINARY_USER_CONTENT, DataClass.PUBLIC_STRUCTURAL),
        trusted_human_control_categories=tuple(DataCategory),
        trusted_human_control_data_classes=(
            DataClass.ORDINARY_USER_CONTENT,
            DataClass.PUBLIC_STRUCTURAL,
        ),
        created_at=_NOW,
        credential_heuristic=setting,
    )


# -- policy field, codecs and digests ------------------------------------------------------------


def test_default_is_enforced_and_never_encoded_so_existing_bytes_and_digests_hold() -> None:
    policy = _policy()
    assert policy.credential_heuristic is CredentialHeuristic.ENFORCED
    wire = encode_privacy_policy_json(policy)
    assert "credential_heuristic" not in wire
    assert wire["schema_version"] == "1.1.0"
    domain = cast(dict[str, JsonValue], _json(policy))
    assert "credential_heuristic" not in domain
    # A policy row written before the field existed decodes as enforced, byte for byte.
    assert decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, domain))) == policy
    assert decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire))) == policy
    # Pinned from the code before the field existed: candidate identity, wire bytes, catalog row
    # bytes and the meet composition digest are all unchanged for an enforced policy.
    scoped = _policy_for_scope(policy, _machine(), policy_id=_POLICY_ID, version=2, supersedes=None)
    assert scoped.policy_digest == (
        "sha256:103dedbdbc856f91f6251694d45b3bb8b7ba93d5aba2114b0b5b566831016073"
    )
    assert canonical_digest(cast(JsonValue, wire)) == (
        "sha256:5d9ea2ac3e44dc247378360a78cc50c8f1624a827145c7686a0c3cd0f4463196"
    )
    assert canonical_digest(cast(JsonValue, domain)) == (
        "sha256:683aaf3dd183a0e503ae6afca95d27bb02b87fb47d03bc6ca638137b0794bff5"
    )
    assert policy.meet(policy).policy_digest == (
        "sha256:c2908a5343311cad8dd17c0938f558d19637ca1ab9aab3f4bfd9a521a5668ac9"
    )


def test_disabled_round_trips_at_wire_1_2_0_and_validates_against_the_schema() -> None:
    policy = _policy(CredentialHeuristic.DISABLED)
    wire = encode_privacy_policy_json(policy)
    assert wire["credential_heuristic"] == "disabled"
    assert wire["schema_version"] == "1.2.0"
    validate_schema_instance("privacy-policy", "1.2.0", cast(JsonValue, wire))
    assert decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire))) == policy
    domain = canonical_encode(_json(policy))
    assert decode_privacy_policy_canonical(domain) == policy
    # Digests differ: the opt-out is part of the approved identity.
    enforced = _policy_for_scope(
        _policy(), _machine(), policy_id=_POLICY_ID, version=2, supersedes=None
    )
    disabled = _policy_for_scope(
        policy, _machine(), policy_id=_POLICY_ID, version=2, supersedes=None
    )
    assert enforced.policy_digest != disabled.policy_digest


def test_older_wire_versions_cannot_carry_the_opt_out() -> None:
    wire = dict(encode_privacy_policy_json(_policy(CredentialHeuristic.DISABLED)))
    wire["schema_version"] = "1.1.0"
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire)))
    garbage = dict(encode_privacy_policy_json(_policy(CredentialHeuristic.DISABLED)))
    garbage["credential_heuristic"] = "off"
    with pytest.raises(ValueError):
        decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, garbage)))


def test_desired_state_toml_carries_the_opt_out_and_omits_the_default(tmp_path: Path) -> None:
    for setting in CredentialHeuristic:
        policy = _policy(setting)
        path = tmp_path / f"{setting.value}.toml"
        path.write_text(render_privacy_desired_toml(policy), encoding="utf-8")
        assert ("credential_heuristic" in path.read_text(encoding="utf-8")) is (
            setting is CredentialHeuristic.DISABLED
        )
        assert decode_privacy_policy_canonical(load_privacy_desired_canonical(path)) == policy


def test_disabling_is_a_widening_and_reenabling_is_a_tightening() -> None:
    enforced = _policy()
    disabled = _policy(CredentialHeuristic.DISABLED)
    widening = privacy_policy_changes(enforced, disabled)
    assert [(c.area, c.field, c.widens) for c in widening] == [
        ("global", "credential_heuristic", True)
    ]
    assert not is_privacy_tightening(enforced, disabled)
    narrowing = privacy_policy_changes(disabled, enforced)
    assert [(c.area, c.field, c.widens) for c in narrowing] == [
        ("global", "credential_heuristic", False)
    ]
    assert is_privacy_tightening(disabled, enforced)


def _workspace() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.WORKSPACE, _INSTALLATION, _WORKSPACE)


def test_the_repository_grant_decides_and_the_machine_value_is_only_a_default() -> None:
    """Owner decision 2026-10-07: a repository is off only where its own grant says off."""

    off, on = CredentialHeuristic.DISABLED, CredentialHeuristic.ENFORCED
    machine_on, machine_off = _policy(on), _policy(off)
    grant_on, grant_off = _policy(on, scope=_workspace()), _policy(off, scope=_workspace())
    assert machine_on.meet(grant_off).credential_heuristic is off
    assert machine_off.meet(grant_on).credential_heuristic is on
    assert machine_off.meet(grant_off).credential_heuristic is off
    assert grant_off.meet(machine_on).credential_heuristic is off
    # Narrower rows (task, request) can only keep the filter on.
    task_on = _policy(on, scope=_task_scope())
    assert machine_on.meet(grant_off).meet(task_on).credential_heuristic is on
    assert machine_off.meet(machine_on).credential_heuristic is on
    # An all-default composition keeps its pinned digest.
    assert machine_on.meet(machine_on).policy_digest != machine_off.meet(machine_off).policy_digest


# -- enforcement -----------------------------------------------------------------------------------


_EXTERNAL = ProviderBinding("openai", "gpt-5", "openai-responses", "1.0.0", "external")
_LOCAL_MODEL = ProviderBinding("ollama", "qwen", "local-model", "1.0.0", "local_af_unix")


def _candidate(
    *payloads: bytes,
    sink: LocalDisclosureSink | None = None,
    binding: ProviderBinding | None = _EXTERNAL,
) -> CandidateContext:
    """An external AI-reviewer disclosure by default; ``sink`` makes it a local output."""

    return CandidateContext(
        request_id=_REQUEST,
        channel=None if sink is not None else EgressChannel.LLM_INFERENCE,
        local_sink=sink,
        purpose="privacy-test",
        scope=_task_scope(),
        subject_digest=_DIGEST,
        provider_binding=None if sink is not None else binding,
        items=tuple(
            CandidateContextItem(
                f"item-{index}",
                DataCategory.EVIDENCE_EXCERPT,
                _task_scope(),
                f"finding:item-{index}",
                payload,
            )
            for index, payload in enumerate(payloads)
        ),
    )


def _effective(setting: CredentialHeuristic) -> EffectivePrivacyPolicy:
    return EffectivePrivacyPolicy(_policy(setting, scope=_task_scope()), 1, _DIGEST)


def _minimize(candidate: CandidateContext, setting: CredentialHeuristic):  # noqa: ANN202
    enforcer = LocalPrivacyEnforcer()
    classified = enforcer.classify(candidate, _effective(setting))
    decision = PrivacyDecision(
        tuple(item.candidate.item_id for item in classified.items),
        (),
        PrivacyOutcome.COMPLETED,
        None,
    )
    return classified, enforcer.minimize_and_scan(classified, decision)


def test_enforced_default_still_replaces_the_heuristic_value() -> None:
    classified, minimized = _minimize(_candidate(_HEURISTIC), CredentialHeuristic.ENFORCED)
    assert classified.credential_heuristic is CredentialHeuristic.ENFORCED
    assert classified.items[0].heuristic_findings == (ForbiddenDataKind.API_CREDENTIAL,)
    assert minimized.redacted_span_count == 1
    assert b"bounded-but-suspicious-value-9" not in minimized.prepared_bytes


def test_disabled_heuristic_sends_the_value_and_reports_no_heuristic_finding() -> None:
    classified, minimized = _minimize(_candidate(_HEURISTIC), CredentialHeuristic.DISABLED)
    assert classified.credential_heuristic is CredentialHeuristic.DISABLED
    assert classified.items[0].heuristic_findings == ()
    assert classified.items[0].forbidden_findings == ()
    assert minimized.heuristic_findings == ()
    assert minimized.forbidden_findings == ()
    assert minimized.withheld_item_ids == ()
    assert minimized.redacted_span_count == 0
    assert minimized.included_item_ids == ("item-0",)


@pytest.mark.parametrize(
    "sink",
    (
        LocalDisclosureSink.AGENT_CONTEXT,
        LocalDisclosureSink.LOCAL_HUMAN_VIEW,
        LocalDisclosureSink.TRUSTED_HUMAN_CONTROL,
    ),
)
def test_local_outputs_keep_the_heuristic_when_the_owner_disabled_it(
    sink: LocalDisclosureSink,
) -> None:
    """Owner decision 2026-10-07: the opt-out reaches only the external AI reviewer."""

    classified, minimized = _minimize(
        _candidate(_HEURISTIC, sink=sink), CredentialHeuristic.DISABLED
    )
    assert classified.credential_heuristic is CredentialHeuristic.ENFORCED
    assert classified.items[0].heuristic_findings == (ForbiddenDataKind.API_CREDENTIAL,)
    assert minimized.redacted_span_count == 1
    assert b"bounded-but-suspicious-value-9" not in minimized.prepared_bytes


def test_local_model_review_keeps_the_heuristic_when_the_owner_disabled_it() -> None:
    classified, minimized = _minimize(
        _candidate(_HEURISTIC, binding=_LOCAL_MODEL), CredentialHeuristic.DISABLED
    )
    assert classified.credential_heuristic is CredentialHeuristic.ENFORCED
    assert classified.items[0].heuristic_findings == (ForbiddenDataKind.API_CREDENTIAL,)
    assert b"bounded-but-suspicious-value-9" not in minimized.prepared_bytes


def test_the_disclosure_setting_follows_only_external_review() -> None:
    disabled = _policy(CredentialHeuristic.DISABLED)
    off = CredentialHeuristic.DISABLED
    on = CredentialHeuristic.ENFORCED
    assert external_review_credential_heuristic(disabled, _EXTERNAL) is off
    assert external_review_credential_heuristic(disabled, _LOCAL_MODEL) is on
    assert external_review_credential_heuristic(disabled, None) is on
    sink = LocalDisclosureSink.AGENT_CONTEXT
    assert external_review_credential_heuristic(disabled, _EXTERNAL, local_sink=sink) is on
    assert external_review_credential_heuristic(_policy(), _EXTERNAL) is on


@pytest.mark.parametrize("concrete", (_CONCRETE, _PRIVATE_KEY))
def test_high_confidence_detectors_still_block_with_the_heuristic_disabled(
    concrete: bytes,
) -> None:
    classified, minimized = _minimize(
        _candidate(_HEURISTIC, concrete), CredentialHeuristic.DISABLED
    )
    assert classified.items[1].forbidden_findings
    assert classified.items[1].data_class is DataClass.SECRET_OR_CRYPTOGRAPHIC
    assert "item-1" not in minimized.included_item_ids


def test_final_scans_ignore_only_the_heuristic_class_when_disabled() -> None:
    disabled = CredentialHeuristic.DISABLED
    assert scan_exact_bytes(_HEURISTIC) == (ForbiddenDataKind.API_CREDENTIAL,)
    assert scan_exact_bytes(_HEURISTIC, credential_heuristic=disabled) == ()
    assert scan_exact_bytes(_CONCRETE, credential_heuristic=disabled) == (
        ForbiddenDataKind.API_CREDENTIAL,
    )
    # Saturation is a high-confidence class: it still fails closed.
    crowded = b"\n".join([b"TOKEN=suspiciousvalue1"] * 128)
    assert scan_exact_bytes(crowded, credential_heuristic=disabled)
    enforcer = LocalPrivacyEnforcer()
    assert _resume_scan_is_clean(enforcer, _HEURISTIC) == (ForbiddenDataKind.API_CREDENTIAL,)
    assert _resume_scan_is_clean(enforcer, _HEURISTIC, disabled) == ()
    assert _resume_scan_is_clean(enforcer, _CONCRETE, disabled)
    assert _final_scan(enforcer, _HEURISTIC, CredentialHeuristic.ENFORCED)
    assert _final_scan(enforcer, _HEURISTIC, disabled) == ()
    assert _final_scan(enforcer, _PRIVATE_KEY, disabled)


def test_gateway_keeps_the_historical_call_shape_for_the_default() -> None:
    calls: list[dict[str, object]] = []

    class _Recorder:
        def scan_exact_bytes(self, data: bytes, **kwargs: object) -> tuple[ForbiddenDataKind, ...]:
            del data
            calls.append(kwargs)
            return ()

    recorder = cast(LocalPrivacyEnforcer, _Recorder())
    _final_scan(recorder, b"x", CredentialHeuristic.ENFORCED)
    _final_scan(recorder, b"x", CredentialHeuristic.DISABLED)
    assert calls == [{}, {"credential_heuristic": CredentialHeuristic.DISABLED}]


# -- receipts --------------------------------------------------------------------------------------


def _receipt(setting: CredentialHeuristic) -> LocalDisclosureReceipt:
    return LocalDisclosureReceipt(
        "1.1.0",
        _RECEIPT_ID,
        _REQUEST,
        _PROPOSAL_ID,
        LocalDisclosureSink.LOCAL_MODEL,
        PrivacyOutcome.COMPLETED,
        _NOW,
        _machine(),
        "semantic-review",
        ReceiptPolicyBinding(_POLICY_ID, 1, _DIGEST, _DIGEST),
        ConsentSource.BASELINE_POLICY,
        (DataCategory.EVIDENCE_EXCERPT,),
        (),
        ReceiptCounts(1, 1, 0, 1, 0, 10, 10, 3, None),
        ReceiptTransformations(0, 0, 0),
        ReceiptSecretScan(
            "observability-sensitive-content-v3",
            _DIGEST,
            0,
            True,
            ReceiptSecretScanStage.RENDERED_BODY,
            credential_heuristic=setting,
        ),
        None,
        1,
    )


def test_disclosure_receipt_records_the_setting_used_and_omits_the_default() -> None:
    enforced = _receipt(CredentialHeuristic.ENFORCED)
    disabled = _receipt(CredentialHeuristic.DISABLED)
    assert b"credential_heuristic" not in _receipt_bytes(enforced)
    assert b'"credential_heuristic":"disabled"' in _receipt_bytes(disabled)
    assert _local_receipt_from_bytes(_receipt_bytes(disabled)) == disabled
    assert _local_receipt_from_bytes(_receipt_bytes(enforced)) == enforced
    wire = encode_privacy_receipt_view(LocalDisclosureReceiptView("local_disclosure", disabled))
    receipt_wire = cast(dict[str, JsonValue], wire["receipt"])
    scan = cast(dict[str, JsonValue], receipt_wire["secret_scan"])
    assert scan["credential_heuristic"] == "disabled"
    plain = encode_privacy_receipt_view(LocalDisclosureReceiptView("local_disclosure", enforced))
    plain_scan = cast(
        dict[str, JsonValue], cast(dict[str, JsonValue], plain["receipt"])["secret_scan"]
    )
    assert "credential_heuristic" not in plain_scan


def test_legacy_receipt_version_cannot_carry_the_opt_out() -> None:
    with pytest.raises(ValueError):
        replace(_receipt(CredentialHeuristic.DISABLED), schema_version="1.0.0")


def test_egress_receipt_schema_admits_the_recorded_setting() -> None:
    import json
    from importlib.resources import files

    document = json.loads(
        files("finishup.resources")
        .joinpath("schemas/privacy/egress-receipt-1.1.0.schema.json")
        .read_bytes()
    )
    scan_properties = document["$defs"]["secret_scan"]["properties"]
    assert scan_properties["credential_heuristic"] == {"const": "disabled", "type": "string"}


# -- coverage gap ----------------------------------------------------------------------------------


def _evaluation(
    status: SemanticStatus, *, disabled: bool, sent: bool = False
) -> FinalSemanticEvaluation:
    # Only the fields the gap rule reads; a real SUCCEEDED evaluation also carries provenance.
    return cast(
        FinalSemanticEvaluation,
        SimpleNamespace(
            status=status,
            credential_heuristic_disabled=disabled,
            provider_input_manifest=object() if sent else None,
        ),
    )


def test_review_that_ran_with_the_heuristic_disabled_discloses_a_gap() -> None:
    gap = {SEMANTIC_REVIEW_CREDENTIAL_HEURISTIC_DISABLED_GAP}
    assert _credential_heuristic_gaps(_evaluation(SemanticStatus.SUCCEEDED, disabled=True)) == gap
    assert (
        _credential_heuristic_gaps(_evaluation(SemanticStatus.SUCCEEDED, disabled=False)) == set()
    )
    # The packet crossed the boundary even though the answer was not usable.
    assert (
        _credential_heuristic_gaps(_evaluation(SemanticStatus.INVALID, disabled=True, sent=True))
        == gap
    )
    # Nothing was sent: nothing to disclose.
    assert _credential_heuristic_gaps(_evaluation(SemanticStatus.FAILED, disabled=True)) == set()
    # The field defaults off on a real evaluation.
    plain = FinalSemanticEvaluation(SemanticStatus.FAILED, SemanticReason.COORDINATOR_FAILURE)
    assert plain.credential_heuristic_disabled is False


def test_the_gap_is_an_owner_disclosure_never_agent_work() -> None:
    gap = SEMANTIC_REVIEW_CREDENTIAL_HEURISTIC_DISABLED_GAP
    assert GAP_CLASSIFICATION[gap] is GapClass.STANDING_LIMITATION
    assert gap in _DETERMINISTIC_PROOF_TOLERATED_GAPS
    assert gap in _SEMANTIC_PROOF_TOLERATED_GAPS
