"""r3 F1: the owner-view ceremony reauthenticates, then mints exactly one grant.

Drives the real ``HumanControlService`` and the production daemon effects
(``_LockedHumanEffects``) with the human-control test doubles.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.secret_memory import HumanAuthorizationProof, SecretPurpose
from finishup.service.confidential_protocol import (
    AuthorizationRequiredPhase,
    ClientActionEnvelope,
    ClientOpenEnvelope,
    ConfidentialSecretPurpose,
    HumanCeremonyKind,
    OwnerReceiptViewPreview,
    OwnerReceiptViewResult,
    OwnerReceiptViewTarget,
    SecretRequiredPhase,
    SelectAuthorizationSourceAction,
    ServerPhaseEnvelope,
    ServerResultEnvelope,
)
from finishup.service.daemon import _LockedHumanEffects
from finishup.service.human_control import HumanControlError
from finishup.service.owner_view import (
    OwnerViewGrants,
    owner_receipt_view_target,
    owner_receipt_view_target_digest,
)
from integration.service.test_human_control import _Effects, _Presence, _service

pytestmark = pytest.mark.anyio

_TARGET = owner_receipt_view_target(
    SimpleNamespace(
        task_id="tsk_00000000-0000-4000-8000-0000000000c1",
        session_id="ses_00000000-0000-4000-8000-0000000000c2",
        request_id="req_00000000-0000-4000-8000-0000000000c3",
        format="markdown",
        include="full",
        redaction_profile="full_local",
    ),
    "e" * 64,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _VaultView:
    """The daemon effects read ``mode.value``; the human-control doubles store a string."""

    def __init__(self, vault: Any) -> None:
        self._vault = vault

    @property
    def mode(self) -> Any:
        return SimpleNamespace(value=self._vault.mode)

    @property
    def ready(self) -> bool:
        return cast(bool, self._vault.ready)

    @property
    def generation(self) -> int:
        return cast(int, self._vault.generation)


class _OwnerEffects(_Effects):
    def __init__(self) -> None:
        super().__init__()
        self.locked: _LockedHumanEffects | None = None

    async def prepare(self, request: ClientOpenEnvelope) -> Any:
        if request.ceremony_kind is HumanCeremonyKind.OWNER_RECEIPT_VIEW:
            assert self.locked is not None
            return await self.locked.prepare(request)
        return await super().prepare(request)

    async def authorize_owner_receipt_view(
        self,
        target: OwnerReceiptViewTarget,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> OwnerReceiptViewResult:
        assert self.locked is not None
        return await self.locked.authorize_owner_receipt_view(target, proof, now_monotonic)


def _owner_service(
    tmp_path: Path, mode: str, handles: list[Any], presence: _Presence | None = None
) -> tuple[Any, OwnerViewGrants, str]:
    effects = _OwnerEffects()
    service, _clock, lifecycle, vault, _ = _service(
        tmp_path, mode=mode, ready=True, handles=handles, presence=presence, effects=effects
    )
    grants = OwnerViewGrants()
    # The owner's own receipt command holds this admitted control connection.
    admission = grants.admit("e" * 64)
    effects.locked = _LockedHumanEffects(
        cast(Any, lifecycle),
        cast(Any, _VaultView(vault)),
        cast(Any, None),
        owner_view_grants=grants,
    )
    return service, grants, admission


async def test_passphrase_reauthentication_mints_one_grant_for_the_exact_target(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    reauth = memory.capture(
        SecretPurpose.PRIVACY_REAUTHENTICATION, bytearray(b"correct horse battery staple")
    )
    service, grants, admission = _owner_service(tmp_path, "passphrase", [reauth])
    opened = await service.open_ceremony(
        ClientOpenEnvelope("7" * 64, HumanCeremonyKind.OWNER_RECEIPT_VIEW, _TARGET)
    )
    digest = owner_receipt_view_target_digest(_TARGET)
    assert type(opened.preview) is OwnerReceiptViewPreview
    assert opened.preview.task_id == _TARGET.task_id
    assert opened.binding.target_digest == digest
    assert type(opened.phase) is AuthorizationRequiredPhase
    assert opened.phase.available_sources == ("secret_reauthentication",)
    # Nothing is granted before the owner reauthenticates.
    assert grants._grants == {}
    phase = await service.submit_action(
        ClientActionEnvelope(
            opened.ceremony_id, 2, SelectAuthorizationSourceAction("secret_reauthentication")
        )
    )
    assert type(phase) is ServerPhaseEnvelope
    assert cast(SecretRequiredPhase, phase.phase).binding.purpose is (
        ConfidentialSecretPurpose.PRIVACY_REAUTHENTICATION
    )
    result = await service.secret_completed(opened.ceremony_id)
    assert type(result) is ServerResultEnvelope
    assert type(result.result) is OwnerReceiptViewResult
    assert result.result.target_digest == digest
    assert grants.consume(admission, digest) is True
    assert grants.consume(admission, digest) is False
    memory.close()


async def test_without_presence_or_a_passphrase_vault_the_view_fails_closed(
    tmp_path: Path,
) -> None:
    """Keyring vault with no presence adapter: the production default refuses at open."""

    service, grants, admission = _owner_service(tmp_path, "os_keyring", [])
    with pytest.raises(HumanControlError) as raised:
        await service.open_ceremony(
            ClientOpenEnvelope("8" * 64, HumanCeremonyKind.OWNER_RECEIPT_VIEW, _TARGET)
        )
    assert raised.value.reason == "reauthentication_unavailable"
    assert grants.consume(admission, owner_receipt_view_target_digest(_TARGET)) is False


async def test_os_presence_alone_can_authorize_the_view(tmp_path: Path) -> None:
    presence = _Presence()
    service, grants, admission = _owner_service(tmp_path, "os_keyring", [], presence=presence)
    opened = await service.open_ceremony(
        ClientOpenEnvelope("9" * 64, HumanCeremonyKind.OWNER_RECEIPT_VIEW, _TARGET)
    )
    assert type(opened.phase) is AuthorizationRequiredPhase
    result = await service.submit_action(
        ClientActionEnvelope(
            opened.ceremony_id, 2, SelectAuthorizationSourceAction("os_user_presence")
        )
    )
    assert type(result) is ServerResultEnvelope
    assert presence.attestation.used
    assert presence.last_challenge is not None
    assert presence.last_challenge.target_digest == owner_receipt_view_target_digest(_TARGET)
    assert grants.consume(admission, owner_receipt_view_target_digest(_TARGET)) is True


async def test_a_ceremony_for_a_connection_that_is_gone_mints_nothing(tmp_path: Path) -> None:
    """R3-F1: the grant must belong to a live admitted connection, or there is no grant."""

    memory = LocalSecretMemory()
    reauth = memory.capture(
        SecretPurpose.PRIVACY_REAUTHENTICATION, bytearray(b"correct horse battery staple")
    )
    service, grants, _admission = _owner_service(tmp_path, "passphrase", [reauth])
    grants.clear()  # the command's control connection closed before the owner confirmed
    opened = await service.open_ceremony(
        ClientOpenEnvelope("6" * 64, HumanCeremonyKind.OWNER_RECEIPT_VIEW, _TARGET)
    )
    await service.submit_action(
        ClientActionEnvelope(
            opened.ceremony_id, 2, SelectAuthorizationSourceAction("secret_reauthentication")
        )
    )
    with pytest.raises(HumanControlError) as raised:
        await service.secret_completed(opened.ceremony_id)
    assert raised.value.reason == "target_invalid"
    memory.close()
