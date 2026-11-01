"""The trusted client must accept the preview for the exact target the service bound.

Issue #169: the client kept its own copy of the target serialization, which silently
dropped ``repository_privacy_commitment`` after the service digest gained it, so every
provider-credential ceremony failed closed with ``preview_invalid``. These tests pin the
real boundary: the binding digest is computed exactly the way the service's prepare
effect computes it (``target.target_digest()``), the opened envelope round-trips the
wire codec, and only then does the client verify it.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from finishup.cli.unlock import (
    HumanCeremonyCliError,
    _verify_preview,  # pyright: ignore[reportPrivateUsage]
)
from finishup.service.confidential_client import HumanControlSession
from finishup.service.confidential_protocol import (
    DecisionRequiredPhase,
    HumanCeremonyBinding,
    HumanCeremonyKind,
    InstallationRecoveryPreview,
    InstallationRecoveryTarget,
    ProviderCredentialRotatePreview,
    ProviderCredentialSetPreview,
    ProviderCredentialTarget,
    SecretIngressBinding,
    SecretRequiredPhase,
    ServerOpenedEnvelope,
    decode_human_frame,
    encode_human_frame,
)

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000001"
_DIGEST_A = "sha256:" + "a" * 64
_PURPOSE_DIGEST = "sha256:df4c93f6d19a44d9b8b6c8eae62a0cf3203cde00f35fb220c42ec2a02d5ee8c1"
_REPOSITORY = "hmac-sha256:" + "b" * 64


def _target(*, repository_bound: bool) -> ProviderCredentialTarget:
    unbound = ProviderCredentialTarget(
        action="set",
        provider_id="fireworks",
        model_id="accounts/fireworks/models/minimax-m3",
        endpoint_profile_id="fireworks-responses",
        endpoint_profile_version="1.0.0",
        purpose="semantic-review",
        scope_digest=_DIGEST_A,
        purpose_digest=_PURPOSE_DIGEST,
    )
    if not repository_bound:
        return unbound
    return replace(unbound, repository_privacy_commitment=_REPOSITORY)


def _opened_session(target: ProviderCredentialTarget) -> HumanControlSession:
    # The binding digest is derived the same way the daemon's prepare effect derives it, and
    # the whole opened envelope crosses the real wire codec before the client sees it.
    binding = HumanCeremonyBinding(
        binding_version=1,
        ceremony_id="1" * 64,
        connection_nonce="0" * 64,
        ceremony_kind=HumanCeremonyKind.PROVIDER_CREDENTIAL_SET,
        service_instance_id=_SERVICE_ID,
        service_generation=3,
        vault_generation=4,
        policy_generation=None,
        target_digest=target.target_digest(),
        expires_at_monotonic_ms=60_000,
    )
    phase = SecretRequiredPhase(
        SecretIngressBinding(
            binding_version=1,
            ceremony_id="1" * 64,
            secret_challenge="2" * 64,
            purpose=__import__(
                "finishup.service.confidential_protocol", fromlist=["ConfidentialSecretPurpose"]
            ).ConfidentialSecretPurpose.PROVIDER_CREDENTIAL,
            service_instance_id=_SERVICE_ID,
            service_generation=3,
            vault_generation=4,
            policy_generation=None,
            target_digest=target.target_digest(),
            expires_at_monotonic_ms=60_000,
        )
    )
    opened = ServerOpenedEnvelope(
        ceremony_id="1" * 64,
        step=1,
        binding=binding,
        preview=ProviderCredentialSetPreview(target),
        phase=phase,
    )
    round_tripped = decode_human_frame(encode_human_frame(opened))
    assert type(round_tripped) is ServerOpenedEnvelope
    return cast(HumanControlSession, SimpleNamespace(opened=round_tripped))


@pytest.mark.parametrize("repository_bound", [False, True])
def test_client_accepts_the_preview_for_the_service_bound_target(
    repository_bound: bool,
) -> None:
    target = _target(repository_bound=repository_bound)
    session = _opened_session(target)

    preview = _verify_preview(HumanCeremonyKind.PROVIDER_CREDENTIAL_SET, target, session)

    assert type(preview) is ProviderCredentialSetPreview
    assert preview.target == target


def test_client_rejects_a_preview_for_a_different_repository_binding() -> None:
    bound = _target(repository_bound=True)
    session = _opened_session(bound)

    with pytest.raises(HumanCeremonyCliError, match="preview_invalid"):
        _verify_preview(
            HumanCeremonyKind.PROVIDER_CREDENTIAL_SET,
            _target(repository_bound=False),
            session,
        )


def test_client_rejects_a_preview_whose_kind_does_not_match() -> None:
    target = _target(repository_bound=True)
    session = _opened_session(target)

    rotate = replace(target, action="rotate")
    rotate_session = cast(
        HumanControlSession,
        SimpleNamespace(
            opened=replace(
                cast(SimpleNamespace, session).opened,
                preview=ProviderCredentialRotatePreview(rotate),
            )
        ),
    )
    with pytest.raises(HumanCeremonyCliError, match="preview_invalid"):
        _verify_preview(HumanCeremonyKind.PROVIDER_CREDENTIAL_SET, target, rotate_session)


_REQUEST_ID = "req_00000000-0000-4000-8000-000000000002"


def _recovery_target(generation: int = 1) -> InstallationRecoveryTarget:
    unbound = InstallationRecoveryTarget(
        operation="provision",
        request_id=_REQUEST_ID,
        confirmed_plan_digest=_DIGEST_A,
        recovery_generation=generation,
        set_mode="compact",
        secret_kind="generated_code",
        target_envelope="preserve",
    )
    return replace(unbound, confirmed_plan_digest=unbound.plan_digest())


def _recovery_session(
    target: InstallationRecoveryTarget,
    *,
    server_plan_digest: str,
) -> HumanControlSession:
    binding = HumanCeremonyBinding(
        binding_version=1,
        ceremony_id="1" * 64,
        connection_nonce="0" * 64,
        ceremony_kind=HumanCeremonyKind.INSTALLATION_RECOVERY,
        service_instance_id=_SERVICE_ID,
        service_generation=3,
        vault_generation=4,
        policy_generation=None,
        # The service binds the ceremony to whatever plan it decided to preview.
        target_digest=server_plan_digest,
        expires_at_monotonic_ms=60_000,
    )
    opened = ServerOpenedEnvelope(
        ceremony_id="1" * 64,
        step=1,
        binding=binding,
        preview=InstallationRecoveryPreview(
            operation=target.operation,
            request_id=target.request_id,
            confirmed_plan_digest=server_plan_digest,
            recovery_generation=target.recovery_generation,
            set_mode=target.set_mode,
            secret_kind=target.secret_kind,
            target_envelope=target.target_envelope,
            item_count=1,
            total_bytes=0,
            native_prompt_available=False,
        ),
        phase=DecisionRequiredPhase(),
    )
    round_tripped = decode_human_frame(encode_human_frame(opened))
    assert type(round_tripped) is ServerOpenedEnvelope
    return cast(HumanControlSession, SimpleNamespace(opened=round_tripped))


def test_client_accepts_a_recovery_preview_bound_to_its_own_plan() -> None:
    target = _recovery_target()
    session = _recovery_session(target, server_plan_digest=target.confirmed_plan_digest)

    preview = _verify_preview(HumanCeremonyKind.INSTALLATION_RECOVERY, target, session)

    assert type(preview) is InstallationRecoveryPreview
    assert preview.confirmed_plan_digest == target.confirmed_plan_digest


def test_client_rejects_a_recovery_preview_bound_to_a_server_chosen_plan() -> None:
    """Comparing the preview only against the binding proves nothing: both come from the service.

    A service that previews and binds a different plan than the one this client asked for is
    internally consistent, so the client must also anchor the comparison to its own target.
    """

    target = _recovery_target()
    elsewhere = _recovery_target(generation=2)
    assert elsewhere.confirmed_plan_digest != target.confirmed_plan_digest
    session = _recovery_session(target, server_plan_digest=elsewhere.confirmed_plan_digest)

    with pytest.raises(HumanCeremonyCliError, match="preview_invalid"):
        _verify_preview(HumanCeremonyKind.INSTALLATION_RECOVERY, target, session)


@pytest.mark.anyio
async def test_remove_requires_the_foreground_terminal_even_with_supplied_reauthentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.cli import unlock

    opened: list[bool] = []

    class Client:
        async def close(self) -> None:
            return None

    class Terminal:
        def __enter__(self) -> None:
            opened.append(True)
            raise HumanCeremonyCliError("trusted_console_required")

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(unlock, "HumanControlClient", Client)
    monkeypatch.setattr(unlock, "_ForegroundTerminal", Terminal)
    target = replace(_target(repository_bound=False), action="remove")
    secret = bytearray(b"scoped-test-reauthentication")
    with pytest.raises(HumanCeremonyCliError, match="trusted_console_required"):
        await unlock.remove_provider_credential(target, secret)
    assert opened == [True]
    assert secret == bytearray(len(secret))
