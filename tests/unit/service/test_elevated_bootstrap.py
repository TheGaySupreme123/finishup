"""Trusted-review pending and catalog contract (ADR-015/016)."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, get_ident
from typing import Any, cast
from unittest.mock import patch

import pytest
from tests.builders.privacy_policies import (
    INSTALLATION_ID,
    local_only_policy,
    minimal_external_policy,
)

import finishup.service.elevated_bootstrap as elevated_bootstrap
from finishup.cli.privacy_setup import build_candidate_policy, recipe_answers
from finishup.domain.privacy import AuthorizationScope, AuthorizationScopeKind, ProviderBinding
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.schemas import validate_schema_instance
from finishup.service.elevated_bootstrap import (
    ElevatedBootstrapError,
    PendingElevatedConsent,
    catalog_payload,
    claim_pending_for_review,
    clear_pending,
    complete_review,
    grant_target_digest,
    load_pending,
    prepare_pending,
    projection_for_status,
    repository_grant_binding,
    status_payload,
)

_TARGET = canonical_digest({"expected_mode": "uninitialized", "kind": "empty_vault"})
_REPOSITORY_COMMITMENT = "hmac-sha256:" + ("c" * 64)
_AUTHORITY_DIGEST = "sha256:" + ("d" * 64)
_BINDING = {
    "endpoint_profile_id": "ep_fireworks",
    "endpoint_profile_version": "1",
    "model_id": "accounts/fireworks/models/minimax-m3",
    "provider_id": "fireworks",
    "purpose": "semantic-review",
    "purpose_digest": canonical_digest({"purpose": "semantic-review"}),
    "scope_digest": "sha256:" + ("b" * 64),
}
_AGENT_FORBIDDEN = {
    "approve_command",
    "confirmation_phrase",
    "credential_fd",
    "passphrase_fd",
    "reauth_fd",
    "secret_fds",
}


def _grant_binding(recipe: str = "assisted_review") -> dict[str, Any]:
    current = replace(
        local_only_policy(),
        effective_scope=AuthorizationScope(
            AuthorizationScopeKind.WORKSPACE,
            INSTALLATION_ID,
            _REPOSITORY_COMMITMENT,
        ),
    )
    external = ProviderBinding(
        "fireworks",
        "accounts/fireworks/models/minimax-m3",
        "fireworks-responses",
        "1.0.0",
        "external",
    )
    candidate = build_candidate_policy(
        current,
        recipe_answers(cast(Any, recipe), current, external),
        now=datetime(2026, 9, 3, tzinfo=UTC),
    )
    return cast(
        dict[str, Any],
        repository_grant_binding(
            recipe=cast(Any, recipe),
            repository_privacy_commitment=_REPOSITORY_COMMITMENT,
            authority_digest=_AUTHORITY_DIGEST,
            current_policy=current,
            candidate_policy=candidate,
        ),
    )


def _assert_agent_safe(value: object) -> None:
    rendered = json.dumps(value, sort_keys=True)
    for forbidden in _AGENT_FORBIDDEN:
        assert forbidden not in rendered


def test_catalog_is_review_only_and_agent_safe() -> None:
    catalog = cast(dict[str, Any], catalog_payload())
    assert catalog["schema"] == "yoetz.consent.catalog/7"
    assert "mcp.start" in catalog["default_safe"]
    assert catalog["rules"]["no_standing_yolo"] is True
    assert catalog["rules"]["independent_user_presence_required_for_agent_chat"] is False
    assert catalog["rules"]["trusted_console_is_not_authority"] is True
    assert catalog["rules"]["agent_selected_initialization_secret_forbidden"] is True
    assert catalog["rules"]["agent_attested_current_chat_instruction_permitted"] is True
    assert catalog["rules"]["agent_attestation_is_independent_proof"] is False
    assert catalog["rules"]["compromised_agent_can_forge_attestation"] is True
    assert catalog["rules"]["explicit_current_user_outcome_controls_supported_choice"] is True
    assert catalog["rules"]["recommendations_are_advisory"] is True
    assert catalog["rules"]["technical_authority_and_safety_boundaries_remain_enforced"] is True
    by_name = {item["operation"]: item for item in catalog["operations"]}
    assert by_name["vault_initialize"]["implemented"] is True
    assert by_name["vault_initialize"]["agent_chat_authorize_allowed"] is True
    assert by_name["vault_passphrase_rotate"]["implemented"] is True
    assert by_name["vault_passphrase_rotate"]["risk_class"] == "secret_reauth"
    assert by_name["vault_passphrase_rotate"]["agent_chat_authorize_allowed"] is True
    assert by_name["provider_credential_rotate"]["implemented"] is True
    assert by_name["provider_credential_set"]["agent_chat_authorize_allowed"] is True
    assert by_name["repository_privacy_grant"]["requires_grant_binding"] is True
    assert by_name["repository_privacy_grant"]["agent_chat_authorize_allowed"] is True
    assert by_name["import_publication"]["implemented"] is True
    assert by_name["import_publication"]["risk_class"] == "review_only"
    assert by_name["import_publication"]["agent_chat_authorize_allowed"] is True
    assert by_name["import_publication"]["prepare_hint"].startswith("finishup import")
    assert by_name["backup_execute"]["implemented"] is False
    assert by_name["backup_execute"]["risk_class"] == "review_only"
    assert by_name["plugin_artifact_apply"]["implemented"] is True
    assert by_name["plugin_artifact_apply"]["risk_class"] == "review_only"
    assert by_name["plugin_artifact_apply"]["agent_chat_authorize_allowed"] is False
    _assert_agent_safe(catalog)


def test_prepare_projection_contains_only_agent_safe_review_fields(tmp_path: Path) -> None:
    pending = prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
    projection = cast(dict[str, Any], projection_for_status(pending))

    assert set(projection) == {
        "danger_digest",
        "danger_text",
        "expires_at_unix",
        "import_publication_preview",
        "operation",
        "pending_id",
        "repository_privacy_recipe",
        "repository_privacy_preview",
        "authorize_command",
        "review_command",
        "risk_class",
        "schema",
        "target_digest",
    }
    assert projection["schema"] == "yoetz.consent.pending-agent/6"
    assert projection["review_command"] == ["finishup", "consent", "review"]
    assert projection["authorize_command"] == ["finishup", "consent", "authorize"]
    assert projection["repository_privacy_recipe"] is None
    assert projection["repository_privacy_preview"] is None
    assert projection["import_publication_preview"] is None
    assert pending.expires_at_unix - pending.created_at_unix == 15 * 60
    stored = json.loads(
        (tmp_path / "elevated-bootstrap" / "elevated-bootstrap-pending.json").read_text()
    )
    assert stored["schema"] == "yoetz.elevated-bootstrap.pending/4"
    _assert_agent_safe(projection)
    _assert_agent_safe(stored)


def test_review_claim_is_single_shot_for_approval_and_duplicate(tmp_path: Path) -> None:
    prepared = prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
    claimed = claim_pending_for_review(_state=tmp_path)
    assert claimed == prepared
    assert load_pending(_state=tmp_path) is None

    with pytest.raises(ElevatedBootstrapError) as duplicate:
        claim_pending_for_review(_state=tmp_path)
    assert duplicate.value.reason == "pending_absent"

    complete_review(claimed, outcome="approved", _state=tmp_path)
    with pytest.raises(ElevatedBootstrapError) as reused:
        complete_review(claimed, outcome="approved", _state=tmp_path)
    assert reused.value.reason == "pending_absent"


def test_expected_review_claim_cannot_consume_a_replacement(tmp_path: Path) -> None:
    displayed = prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
    clear_pending(_state=tmp_path)
    replacement = prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)

    with pytest.raises(ElevatedBootstrapError) as mismatch:
        claim_pending_for_review(expected_pending=displayed, _state=tmp_path)

    assert mismatch.value.reason == "pending_tampered"
    assert load_pending(_state=tmp_path) == replacement
    assert not (tmp_path / "elevated-bootstrap" / "elevated-bootstrap-reviewing.json").exists()


@pytest.mark.parametrize("outcome", ["denied", "cancelled", "failed"])
def test_review_consumes_denial_cancellation_and_failure(tmp_path: Path, outcome: str) -> None:
    prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
    claimed = claim_pending_for_review(_state=tmp_path)
    complete_review(claimed, outcome=outcome, _state=tmp_path)
    assert load_pending(_state=tmp_path) is None


def test_concurrent_review_has_one_winner(tmp_path: Path) -> None:
    prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)

    def claim() -> tuple[str, object]:
        try:
            return "ok", claim_pending_for_review(_state=tmp_path)
        except ElevatedBootstrapError as exc:
            return "error", exc.reason

    def claim_index(_index: int) -> tuple[str, object]:
        return claim()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(claim_index, range(2)))

    winners = [value for status, value in outcomes if status == "ok"]
    losers = [value for status, value in outcomes if status == "error"]
    assert len(winners) == 1
    assert losers[0] in {"pending_absent", "review_in_progress"}
    complete_review(cast(Any, winners[0]), outcome="cancelled", _state=tmp_path)


def test_concurrent_loser_cannot_consume_atomic_review_claim(tmp_path: Path) -> None:
    prepared = prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
    pending = tmp_path / "elevated-bootstrap" / "elevated-bootstrap-pending.json"
    reviewing = tmp_path / "elevated-bootstrap" / "elevated-bootstrap-reviewing.json"
    claim_published = Event()
    release_winner = Event()
    real_link = os.link

    def pause_winner_after_atomic_claim(source: Any, claim: Any) -> None:
        real_link(source, claim)
        claim_published.set()
        assert release_winner.wait(timeout=5), "winner was not released"

    def claim() -> tuple[str, object]:
        try:
            return "ok", claim_pending_for_review(_state=tmp_path)
        except ElevatedBootstrapError as exc:
            return "error", exc.reason

    with patch(
        "finishup.service.elevated_bootstrap.os.link",
        side_effect=pause_winner_after_atomic_claim,
    ):
        with ThreadPoolExecutor(max_workers=2) as pool:
            winner_future = pool.submit(claim)
            assert claim_published.wait(timeout=5), "winner did not publish its review marker"
            loser_future = pool.submit(claim)
            assert not loser_future.done(), "loser bypassed the winner's state lock"
            assert pending.is_file(), "winner removed the public name before claiming"
            assert reviewing.is_file(), "winner did not publish the review marker"
            release_winner.set()
            winner = winner_future.result(timeout=5)
            loser = loser_future.result(timeout=5)

    assert loser == ("error", "pending_absent")
    assert winner == ("ok", prepared)
    assert not pending.exists()
    assert reviewing.is_file()
    complete_review(prepared, outcome="cancelled", _state=tmp_path)


def test_public_name_cleanup_cannot_revoke_atomic_review_claim(tmp_path: Path) -> None:
    prepared = prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
    pending = tmp_path / "elevated-bootstrap" / "elevated-bootstrap-pending.json"
    reviewing = tmp_path / "elevated-bootstrap" / "elevated-bootstrap-reviewing.json"
    real_link = os.link

    def remove_public_name_after_atomic_claim(source: Any, claim: Any) -> None:
        real_link(source, claim)
        Path(source).unlink()

    with patch(
        "finishup.service.elevated_bootstrap.os.link",
        side_effect=remove_public_name_after_atomic_claim,
    ):
        claimed = claim_pending_for_review(_state=tmp_path)

    assert claimed == prepared
    assert not pending.exists()
    assert reviewing.is_file()
    complete_review(claimed, outcome="cancelled", _state=tmp_path)


def test_expiry_reprepare_cannot_replace_claimed_record(
    tmp_path: Path,
) -> None:
    """The claim transition serializes expiry cleanup and replacement preparation (#344)."""

    claim_loaded = Event()
    release_claim = Event()
    replacement_started = Event()
    claim_thread_id: list[int | None] = [None]

    def clock() -> float:
        if claim_thread_id[0] == get_ident():
            return 1_899 if not release_claim.is_set() else 1_901
        return 1_000 if claim_thread_id[0] is None else 1_901

    real_load = elevated_bootstrap._load_pending_path  # pyright: ignore[reportPrivateUsage]

    def pause_claim_load(
        path: Path,
        *,
        _state: Path | None,
        expire: bool,
    ) -> object:
        loaded = real_load(path, _state=_state, expire=expire)
        if (
            claim_thread_id[0] == get_ident()
            and expire
            and path.name == "elevated-bootstrap-pending.json"
            and loaded is not None
        ):
            claim_loaded.set()
            assert release_claim.wait(timeout=5), "claim did not release its state lock"
        return loaded

    def claim() -> tuple[str, object]:
        claim_thread_id[0] = get_ident()
        try:
            return "ok", claim_pending_for_review(_state=tmp_path)
        except ElevatedBootstrapError as exc:
            return "error", exc.reason

    def reprepare() -> tuple[str, object]:
        replacement_started.set()
        try:
            return "ok", prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
        except ElevatedBootstrapError as exc:
            return "error", exc.reason

    with (
        patch("finishup.service.elevated_bootstrap.time.time", side_effect=clock),
        patch(
            "finishup.service.elevated_bootstrap._load_pending_path",
            side_effect=pause_claim_load,
        ),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        prepared = prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
        claim_future = pool.submit(claim)
        assert claim_loaded.wait(timeout=5), "claim did not load the original pending record"
        replacement_future = pool.submit(reprepare)
        assert replacement_started.wait(timeout=5), "replacement did not start"
        assert not replacement_future.done(), "replacement bypassed the claim state lock"
        release_claim.set()
        claim_result = claim_future.result(timeout=5)
        replacement_result = replacement_future.result(timeout=5)
        replacement_present = load_pending(_state=tmp_path)

    assert claim_result == ("error", "pending_expired")
    assert replacement_result[0] == "ok"
    replacement = cast(PendingElevatedConsent, replacement_result[1])
    assert replacement != prepared
    assert replacement_present == replacement


def test_interrupted_review_marker_blocks_reuse_and_new_prepare(tmp_path: Path) -> None:
    prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
    claimed = claim_pending_for_review(_state=tmp_path)
    assert load_pending(_state=tmp_path) is None
    with pytest.raises(ElevatedBootstrapError) as duplicate:
        claim_pending_for_review(_state=tmp_path)
    assert duplicate.value.reason == "pending_absent"
    with pytest.raises(ElevatedBootstrapError) as replacement:
        prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
    assert replacement.value.reason == "review_in_progress"
    complete_review(claimed, outcome="failed", _state=tmp_path)


@pytest.mark.parametrize("version", ["1", "2", "3"])
def test_legacy_pending_record_is_invalidated_not_migrated(tmp_path: Path, version: str) -> None:
    root = tmp_path / "elevated-bootstrap"
    root.mkdir(mode=0o700)
    path = root / "elevated-bootstrap-pending.json"
    path.write_text(
        json.dumps(
            {
                "schema": f"finishup.elevated-bootstrap.pending/{version}",
                "confirmation_phrase": "reusable value",
            }
        )
    )

    with pytest.raises(ElevatedBootstrapError) as exc:
        load_pending(_state=tmp_path)
    assert exc.value.reason == "legacy_pending_invalidated"
    assert not path.exists()
    audit = (root / "elevated-bootstrap-audit.jsonl").read_text()
    assert "legacy_pending_invalidated" in audit
    assert "reusable value" not in audit


@pytest.mark.parametrize("version", ["1", "2", "3"])
def test_legacy_claim_marker_remains_owned_and_blocks_replacement(
    tmp_path: Path, version: str
) -> None:
    """Upgrade never steals a possibly live pre-upgrade review claim."""

    root = tmp_path / "elevated-bootstrap"
    root.mkdir(mode=0o700)
    marker = root / "elevated-bootstrap-reviewing.json"
    marker.write_text(
        json.dumps(
            {
                "schema": f"finishup.elevated-bootstrap.pending/{version}",
                "pending_id": "possibly-live-owner",
            }
        )
    )

    assert load_pending(_state=tmp_path) is None
    with pytest.raises(ElevatedBootstrapError) as replacement:
        prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
    assert replacement.value.reason == "review_in_progress"
    assert marker.is_file()
    assert not (root / "elevated-bootstrap-audit.jsonl").exists()


def test_expiry_consumes_before_review(tmp_path: Path) -> None:
    with patch("finishup.service.elevated_bootstrap.time.time", return_value=1_000):
        prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
    with patch("finishup.service.elevated_bootstrap.time.time", return_value=1_901):
        with pytest.raises(ElevatedBootstrapError) as exc:
            claim_pending_for_review(_state=tmp_path)
    assert exc.value.reason == "pending_absent"
    assert load_pending(_state=tmp_path) is None


def test_tampered_digest_or_operation_is_rejected_before_claim(tmp_path: Path) -> None:
    prepare_pending("vault_initialize", target_digest=_TARGET, _state=tmp_path)
    path = tmp_path / "elevated-bootstrap" / "elevated-bootstrap-pending.json"
    payload = json.loads(path.read_text())
    payload["danger_digest"] = "sha256:" + ("0" * 64)
    path.write_text(json.dumps(payload))
    with pytest.raises(ElevatedBootstrapError) as digest:
        claim_pending_for_review(_state=tmp_path)
    assert digest.value.reason == "pending_tampered"

    payload["operation"] = "provider_credential_set"
    path.write_text(json.dumps(payload))
    with pytest.raises(ElevatedBootstrapError) as operation:
        claim_pending_for_review(_state=tmp_path)
    assert operation.value.reason in {"pending_corrupt", "pending_tampered"}


def test_prepare_provider_binding_rules(tmp_path: Path) -> None:
    with pytest.raises(ElevatedBootstrapError) as missing:
        prepare_pending("provider_credential_set", target_digest=_TARGET, _state=tmp_path)
    assert missing.value.reason == "provider_binding_required"
    with pytest.raises(ElevatedBootstrapError) as forbidden:
        prepare_pending(
            "vault_initialize",
            target_digest=_TARGET,
            provider_binding=_BINDING,
            _state=tmp_path,
        )
    assert forbidden.value.reason == "provider_binding_forbidden"
    with pytest.raises(ElevatedBootstrapError) as incomplete:
        prepare_pending(
            "provider_credential_set",
            target_digest=_TARGET,
            provider_binding={"provider_id": "x"},
            _state=tmp_path,
        )
    assert incomplete.value.reason == "provider_binding_invalid"


def test_prepare_grant_binding_rules(tmp_path: Path) -> None:
    grant = _grant_binding()
    with pytest.raises(ElevatedBootstrapError) as missing:
        prepare_pending(
            "repository_privacy_grant",
            target_digest=grant_target_digest(grant),
            _state=tmp_path,
        )
    assert missing.value.reason == "grant_binding_required"
    with pytest.raises(ElevatedBootstrapError) as forbidden:
        prepare_pending(
            "vault_initialize",
            target_digest=_TARGET,
            grant_binding=grant,
            _state=tmp_path,
        )
    assert forbidden.value.reason == "grant_binding_forbidden"
    for invalid in (
        {**grant, "schema": "wrong"},
        {**grant, "preview": {**grant["preview"], "recipe": "custom"}},
        {**grant, "preview": {**grant["preview"], "diff_digest": "sha256:" + "0" * 64}},
        {**grant, "candidate_policy": grant["current_policy"]},
    ):
        with pytest.raises(ElevatedBootstrapError) as malformed:
            prepare_pending(
                "repository_privacy_grant",
                target_digest=grant_target_digest(grant),
                grant_binding=invalid,
                _state=tmp_path,
            )
        assert malformed.value.reason == "grant_binding_invalid"


def test_repository_grant_is_repository_bound(tmp_path: Path) -> None:
    grant = _grant_binding("expanded_review")
    pending = prepare_pending(
        "repository_privacy_grant",
        target_digest=grant_target_digest(grant),
        grant_binding=grant,
        _state=tmp_path,
    )
    assert pending.grant_binding == grant
    grant_projection = cast(dict[str, Any], projection_for_status(pending))
    assert grant_projection["repository_privacy_recipe"] == "expanded_review"
    assert grant_projection["repository_privacy_preview"]["recipe"] == "expanded_review"
    assert grant_projection["repository_privacy_preview"]["changes"]
    assert grant_projection["authorize_command"] == ["finishup", "consent", "authorize"]
    assert load_pending(_state=tmp_path) == pending
    assert (
        grant_target_digest(
            {
                **grant,
                "preview": {
                    **grant["preview"],
                    "authority_digest": "sha256:" + ("e" * 64),
                },
            }
        )
        != pending.target_digest
    )


@pytest.mark.parametrize(
    "recipe", ["expanded_review", "assisted_review", "metadata_only", "private"]
)
def test_every_named_recipe_has_one_exact_previewed_grant_binding(recipe: str) -> None:
    grant = _grant_binding(recipe)
    preview = grant["preview"]
    assert isinstance(preview, dict)
    assert preview["recipe"] == recipe
    assert preview["repository_privacy_commitment"] == _REPOSITORY_COMMITMENT
    assert preview["authority_digest"] == _AUTHORITY_DIGEST
    assert grant_target_digest(grant).startswith("sha256:")


def test_preview_names_provider_binding_even_when_the_route_does_not_change() -> None:
    current = replace(
        minimal_external_policy(),
        effective_scope=AuthorizationScope(
            AuthorizationScopeKind.WORKSPACE,
            INSTALLATION_ID,
            _REPOSITORY_COMMITMENT,
        ),
    )
    external = next(
        channel.provider_binding
        for channel in current.channel_policies
        if channel.provider_binding is not None
    )
    assert external is not None
    candidate = build_candidate_policy(
        current,
        recipe_answers("expanded_review", current, external),
        now=datetime(2026, 9, 3, tzinfo=UTC),
    )
    grant = repository_grant_binding(
        recipe="expanded_review",
        repository_privacy_commitment=_REPOSITORY_COMMITMENT,
        authority_digest=_AUTHORITY_DIGEST,
        current_policy=current,
        candidate_policy=candidate,
    )
    preview = cast(dict[str, Any], grant["preview"])
    assert preview["candidate_provider_binding"]["model_id"] == external.model_id
    assert not any(
        change["area"] == "channel" and change["field"] == "provider"
        for change in preview["changes"]
    )


def test_first_repository_grant_binds_machine_baseline_to_repository_target() -> None:
    current = local_only_policy()
    external = ProviderBinding(
        "fireworks",
        "accounts/fireworks/models/minimax-m3",
        "fireworks-responses",
        "1.0.0",
        "external",
    )
    candidate = build_candidate_policy(
        current,
        recipe_answers("expanded_review", current, external),
        now=datetime(2026, 9, 3, tzinfo=UTC),
    )
    grant = repository_grant_binding(
        recipe="expanded_review",
        repository_privacy_commitment=_REPOSITORY_COMMITMENT,
        authority_digest=_AUTHORITY_DIGEST,
        current_policy=current,
        candidate_policy=candidate,
    )
    preview = cast(dict[str, Any], grant["preview"])
    assert current.effective_scope.kind is AuthorizationScopeKind.MACHINE
    assert candidate.effective_scope.kind is AuthorizationScopeKind.MACHINE
    assert preview["repository_privacy_commitment"] == _REPOSITORY_COMMITMENT
    assert grant_target_digest(grant).startswith("sha256:")


def test_provider_binding_preserves_repository_commitment(tmp_path: Path) -> None:
    provider = {**_BINDING, "repository_privacy_commitment": _REPOSITORY_COMMITMENT}
    provider_pending = prepare_pending(
        "provider_credential_set",
        target_digest=_TARGET,
        provider_binding=provider,
        _state=tmp_path,
    )
    assert provider_pending.provider_binding == provider


def test_target_digest_and_unimplemented_operations_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ElevatedBootstrapError) as digest:
        prepare_pending("vault_initialize", target_digest="sha256:not-hex", _state=tmp_path)
    assert digest.value.reason == "target_digest_invalid"
    with pytest.raises(ElevatedBootstrapError) as unimplemented:
        prepare_pending(
            "privacy_policy_widen",
            target_digest=canonical_digest({"pending": "x"}),
            _state=tmp_path,
        )
    assert unimplemented.value.reason == "operation_not_implemented"


def test_status_contains_nullable_pending_and_catalog(tmp_path: Path) -> None:
    empty = cast(dict[str, Any], status_payload(_state=tmp_path))
    assert empty["schema"] == "yoetz.elevated-bootstrap.status/7"
    assert empty["pending"] is None
    assert empty["consent_catalog"]["schema"] == "yoetz.consent.catalog/7"
    _assert_agent_safe(empty)
    validate_schema_instance("status", "7.0.0", empty)

    prepare_pending(
        "provider_credential_set", target_digest=_TARGET, provider_binding=_BINDING, _state=tmp_path
    )
    prepared = cast(dict[str, Any], status_payload(_state=tmp_path))
    assert prepared["pending"]["operation"] == "provider_credential_set"
    assert prepared["pending"]["authorize_command"] == ["finishup", "consent", "authorize"]
    assert prepared["pending"]["schema"] == "yoetz.consent.pending-agent/7"
    assert prepared["pending"]["coordination_binding"] is None
    _assert_agent_safe(prepared)
    validate_schema_instance("catalog", "7.0.0", prepared["consent_catalog"])
    validate_schema_instance("pending-agent", "7.0.0", prepared["pending"])
    validate_schema_instance("status", "7.0.0", prepared)
