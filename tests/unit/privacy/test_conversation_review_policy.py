"""The owner's conversation setting in the privacy policy (ADR-049)."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest
from tests.unit.privacy.test_credential_heuristic_opt_out import (
    _INSTALLATION,  # pyright: ignore[reportPrivateUsage]
    _WORKSPACE,  # pyright: ignore[reportPrivateUsage]
    _policy,  # pyright: ignore[reportPrivateUsage]
    _task_scope,  # pyright: ignore[reportPrivateUsage]
)

from finishup.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.domain.privacy import AuthorizationScope, AuthorizationScopeKind, ConversationReview
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.schemas import validate_schema_instance


def _workspace() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.WORKSPACE, _INSTALLATION, _WORKSPACE)


def test_an_unset_setting_is_never_encoded_and_reads_as_released() -> None:
    policy = _policy()
    assert policy.conversation_review is None
    wire = encode_privacy_policy_json(policy)
    assert "conversation_review" not in wire
    assert decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire))) == policy
    # Inference off: nothing may be sent, so tasks are local.
    assert policy.effective_conversation_review is ConversationReview.LOCAL_ONLY


@pytest.mark.parametrize("setting", list(ConversationReview))
def test_every_setting_round_trips_at_wire_1_2_0(setting: ConversationReview) -> None:
    policy = replace(_policy(), conversation_review=setting)
    wire = encode_privacy_policy_json(policy)
    assert wire["schema_version"] == "1.2.0"
    assert wire["conversation_review"] == setting.value
    validate_schema_instance("privacy-policy", "1.2.0", cast(JsonValue, wire))
    assert decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire))) == policy
    assert policy.effective_conversation_review is setting


def test_older_wire_versions_cannot_carry_the_setting() -> None:
    wire = dict(
        encode_privacy_policy_json(
            replace(_policy(), conversation_review=ConversationReview.LOCAL_ONLY)
        )
    )
    wire["schema_version"] = "1.1.0"
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire)))
    wire["schema_version"] = "1.2.0"
    wire["conversation_review"] = "sometimes"
    with pytest.raises(ValueError):
        decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire)))


def test_the_repository_row_decides_and_narrower_rows_keep_the_stricter_setting() -> None:
    opt_in, local_only = ConversationReview.LOCAL_AGENT_OPT_IN, ConversationReview.LOCAL_ONLY
    machine = replace(_policy(), conversation_review=local_only)
    grant = replace(_policy(scope=_workspace()), conversation_review=opt_in)
    assert machine.meet(grant).conversation_review is opt_in
    assert grant.meet(machine).conversation_review is opt_in
    # A repository without its own setting inherits the installation default.
    assert machine.meet(_policy(scope=_workspace())).conversation_review is local_only
    # Any other composition keeps the setting that needs more of the owner.
    task = replace(_policy(scope=_task_scope()), conversation_review=local_only)
    assert machine.meet(grant).meet(task).conversation_review is local_only
    # Unset on both sides stays unset, so the released reading applies to the composition.
    assert _policy().meet(_policy(scope=_workspace())).conversation_review is None
    # The composed setting is part of the composition's identity; an unset one adds nothing.
    unset = _policy().meet(_policy(scope=_workspace()))
    assert machine.meet(grant).policy_digest != unset.policy_digest
