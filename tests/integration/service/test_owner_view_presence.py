"""#1073 2.C: OS user presence (macOS LocalAuthentication) opens the owner receipt view.

These drive the real ``HumanControlService``, the real ``UnlockCoordinator``, the production
daemon effects (``_LockedHumanEffects``) and the real ``MacOSLocalAuthenticationPresence``
adapter with the same scope the packaged daemon composes. Only the ``osascript`` helper is a stub
runner, because a Touch ID prompt needs a person at a Mac; that check is the documented manual
step in the integration runbooks.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import time
from collections.abc import Buffer, Mapping, Sequence
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, cast

import pytest

import yoetz.service.daemon as daemon_module
from integration.service.test_daemon_clients import _Listener
from integration.service.test_human_control import _Effects, _Presence, _service
from integration.service.test_owner_receipt_view import _TARGET, _OwnerEffects, _VaultView
from yoetz.adapters.keys import macos_user_presence
from yoetz.adapters.keys.macos_user_presence import (
    OWNER_VIEW_PRESENCE_PURPOSES,
    OWNER_VIEW_PRESENCE_VAULT_MODES,
    MacOSLocalAuthenticationPresence,
)
from yoetz.adapters.keys.secret_memory import LocalSecretMemory
from yoetz.config.models import YoetzConfig
from yoetz.ports.secret_memory import SecretPurpose, presence_confirmation_code
from yoetz.protocol.canonical import canonical_digest
from yoetz.service.confidential_protocol import (
    AuthorizationRequiredPhase,
    ClientActionEnvelope,
    ClientOpenEnvelope,
    EmptyVaultTarget,
    HumanCeremonyKind,
    KeyringRetryResult,
    OwnerReceiptViewResult,
    ProviderCredentialTarget,
    RetryAction,
    SelectAuthorizationSourceAction,
    ServerCloseEnvelope,
    ServerResultEnvelope,
    encode_human_frame,
)
from yoetz.service.daemon import _LockedHumanEffects
from yoetz.service.human_control import HumanControlError, HumanControlService, PresenceScope
from yoetz.service.owner_view import OwnerViewGrants, owner_receipt_view_target_digest

pytestmark = pytest.mark.anyio

_SCOPE = PresenceScope(OWNER_VIEW_PRESENCE_PURPOSES, OWNER_VIEW_PRESENCE_VAULT_MODES)
_DIGEST = owner_receipt_view_target_digest(_TARGET)
_PRESENCE = SelectAuthorizationSourceAction("os_user_presence")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _Runner:
    """Stands in for ``/usr/bin/osascript``; optionally holds the prompt open until released."""

    stdout: bytes = b"approved\n"
    hold: bool = False
    calls: list[tuple[str, ...]] = field(default_factory=lambda: [])
    started: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    cancelled: bool = False

    async def __call__(
        self, argv: Sequence[str], stdin: bytes, env: Mapping[str, str], timeout: float
    ) -> tuple[int, bytes]:
        del stdin, env, timeout
        self.calls.append(tuple(argv))
        self.started.set()
        if self.hold:
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                self.cancelled = True
                raise
        return 0, self.stdout


def _owner(
    tmp_path: Path, mode: str, runner: _Runner, *, handles: list[Any] | None = None
) -> tuple[HumanControlService, OwnerViewGrants, str, Any, Any]:
    presence = MacOSLocalAuthenticationPresence(
        runner=runner, platform=lambda: "darwin", helper_present=lambda: True
    )
    effects = _OwnerEffects()
    service, clock, lifecycle, vault, _ = _service(
        tmp_path,
        mode=mode,
        ready=True,
        handles=handles or [],
        presence=cast(_Presence, presence),
        effects=effects,
    )
    # The packaged daemon's scope (daemon._production_composition).
    service._user_presence_scope = _SCOPE
    grants = OwnerViewGrants()
    admission = grants.admit("e" * 64)
    effects.locked = _LockedHumanEffects(
        cast(Any, lifecycle),
        cast(Any, _VaultView(vault)),
        cast(Any, None),
        owner_view_grants=grants,
    )
    return service, grants, admission, clock, vault


async def _open(service: HumanControlService, nonce: str = "7") -> Any:
    return await service.open_ceremony(
        ClientOpenEnvelope(nonce * 64, HumanCeremonyKind.OWNER_RECEIPT_VIEW, _TARGET)
    )


async def test_touch_id_opens_the_owner_view_on_a_keychain_vault(tmp_path: Path) -> None:
    runner = _Runner()
    service, grants, admission, _, _ = _owner(tmp_path, "os_keyring", runner)

    opened = await _open(service)
    assert type(opened.phase) is AuthorizationRequiredPhase
    assert opened.phase.available_sources == ("os_user_presence",)
    assert runner.calls == []  # nothing prompts before the owner's command selects it
    result = await service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))

    assert type(result) is ServerResultEnvelope
    assert result.result == OwnerReceiptViewResult("authorized", _DIGEST, 60)
    (argv,) = runner.calls
    # The dialog names the same code the owner's terminal shows for this exact request.
    assert f"(confirmation code {presence_confirmation_code(_DIGEST)})" in argv[4]
    assert grants.consume(admission, _DIGEST) is True
    assert grants.consume(admission, _DIGEST) is False
    # The ceremony is over: replaying its action finds nothing to act on.
    with pytest.raises(HumanControlError, match="replay"):
        await service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))


@pytest.mark.parametrize(
    ("stdout", "reason"),
    [
        (b"cancelled\n", "presence_refused"),
        (b"failed\n", "presence_refused"),
        (b"timeout\n", "presence_timeout"),
        (b"unavailable\n", "presence_unavailable"),
        (b"approved\napproved\n", "presence_unavailable"),
        (b"APPROVED\n", "presence_unavailable"),
    ],
)
async def test_a_refused_or_garbled_prompt_grants_nothing(
    tmp_path: Path, stdout: bytes, reason: str
) -> None:
    runner = _Runner(stdout=stdout)
    service, grants, admission, _, _ = _owner(tmp_path, "os_keyring", runner)
    opened = await _open(service)

    with pytest.raises(HumanControlError) as raised:
        await service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))

    assert raised.value.reason == reason
    assert grants.consume(admission, _DIGEST) is False
    # The refusal consumed the ceremony; the owner can simply ask again.
    assert service._active is None
    await _open(service, "8")


async def test_a_keychain_passphrase_vault_offers_touch_id_beside_its_passphrase(
    tmp_path: Path,
) -> None:
    """Setup's system-keychain choice is a passphrase vault whose passphrase was generated and
    kept in the Keychain: its owner never saw it, so presence is what lets them in. A passphrase
    the owner knows stays offered beside it."""

    memory = LocalSecretMemory()
    reauth = memory.capture(
        SecretPurpose.PRIVACY_REAUTHENTICATION, bytearray(b"correct horse battery staple")
    )
    runner = _Runner()
    service, grants, admission, _, _ = _owner(tmp_path, "passphrase", runner, handles=[reauth])

    opened = await _open(service)
    assert type(opened.phase) is AuthorizationRequiredPhase
    assert opened.phase.available_sources == ("os_user_presence", "secret_reauthentication")
    result = await service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
    assert type(result) is ServerResultEnvelope
    assert len(runner.calls) == 1
    assert grants.consume(admission, _DIGEST) is True

    reopened = await _open(service, "8")
    await service.submit_action(
        ClientActionEnvelope(
            reopened.ceremony_id, 2, SelectAuthorizationSourceAction("secret_reauthentication")
        )
    )
    passphrase_result = await service.secret_completed(reopened.ceremony_id)
    assert type(passphrase_result) is ServerResultEnvelope
    assert len(runner.calls) == 1  # the passphrase path never prompts
    assert grants.consume(admission, _DIGEST) is True
    assert grants.consume(admission, _DIGEST) is False
    memory.close()


async def test_presence_never_stands_in_for_another_reauthentication(tmp_path: Path) -> None:
    runner = _Runner()
    service, _, _, _, _ = _owner(tmp_path, "os_keyring", runner)
    purpose = "semantic-review"
    credential = ProviderCredentialTarget(
        "set",
        "openai",
        "gpt-5",
        "responses",
        "1",
        purpose,
        "sha256:" + "0" * 64,
        canonical_digest({"purpose": purpose}),
    )
    # A keychain vault has no passphrase, and the provider is scoped to the owner view only, so
    # a provider-credential ceremony has no authorization source at all.
    with pytest.raises(HumanControlError, match="reauthentication_unavailable"):
        await service.open_ceremony(
            ClientOpenEnvelope("3" * 64, HumanCeremonyKind.PROVIDER_CREDENTIAL_SET, credential)
        )
    assert runner.calls == []


async def test_keyring_retry_never_receives_the_scoped_capability(tmp_path: Path) -> None:
    runner = _Runner()
    presence = MacOSLocalAuthenticationPresence(
        runner=runner, platform=lambda: "darwin", helper_present=lambda: True
    )
    service, _, lifecycle, vault, _ = _service(
        tmp_path,
        mode="os_keyring",
        ready=False,
        handles=[],
        presence=cast(_Presence, presence),
        effects=_Effects(),
    )
    service._user_presence_scope = _SCOPE
    del lifecycle
    opened = await service.open_ceremony(
        ClientOpenEnvelope(
            "4" * 64, HumanCeremonyKind.KEYRING_RETRY, EmptyVaultTarget(expected_mode="os_keyring")
        )
    )
    result = await service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, RetryAction()))
    assert type(result) is ServerResultEnvelope
    assert type(result.result) is KeyringRetryResult
    # The test vault becomes ready only when handed a capability; the scope withholds it.
    assert vault.ready is False
    assert runner.calls == []


async def test_without_a_provider_the_keychain_view_fails_closed(tmp_path: Path) -> None:
    """Linux and WSL compose no provider; a client naming presence asserts nothing."""

    effects = _OwnerEffects()
    service, _, lifecycle, vault, _ = _service(
        tmp_path, mode="os_keyring", ready=True, handles=[], presence=None, effects=effects
    )
    grants = OwnerViewGrants()
    admission = grants.admit("e" * 64)
    effects.locked = _LockedHumanEffects(
        cast(Any, lifecycle),
        cast(Any, _VaultView(vault)),
        cast(Any, None),
        owner_view_grants=grants,
    )
    with pytest.raises(HumanControlError, match="reauthentication_unavailable"):
        await _open(service)
    assert grants.consume(admission, _DIGEST) is False
    # The wire action names a source and nothing else: there is no field for a client to
    # carry a presence result.
    assert {item.name for item in fields(SelectAuthorizationSourceAction)} == {"source", "kind"}


async def test_close_during_the_prompt_stops_it_without_waiting(tmp_path: Path) -> None:
    runner = _Runner(hold=True)
    service, grants, admission, _, _ = _owner(tmp_path, "os_keyring", runner)
    opened = await _open(service)
    action = asyncio.create_task(
        service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
    )
    await asyncio.wait_for(runner.started.wait(), 5.0)

    await asyncio.wait_for(service.close(), 5.0)

    with pytest.raises(HumanControlError, match="cancelled"):
        await asyncio.wait_for(action, 5.0)
    assert runner.cancelled
    assert grants.consume(admission, _DIGEST) is False


async def test_cancel_during_the_prompt_ends_it_and_grants_nothing(tmp_path: Path) -> None:
    runner = _Runner(hold=True)
    service, grants, admission, _, _ = _owner(tmp_path, "os_keyring", runner)
    opened = await _open(service)
    action = asyncio.create_task(
        service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
    )
    await asyncio.wait_for(runner.started.wait(), 5.0)

    closed = await asyncio.wait_for(service.cancel(opened.ceremony_id), 5.0)

    assert type(closed) is ServerCloseEnvelope
    with pytest.raises(HumanControlError, match="cancelled"):
        await asyncio.wait_for(action, 5.0)
    assert runner.cancelled
    assert grants.consume(admission, _DIGEST) is False


async def test_a_second_action_cannot_ride_on_a_pending_prompt(tmp_path: Path) -> None:
    runner = _Runner(hold=True)
    service, grants, admission, _, _ = _owner(tmp_path, "os_keyring", runner)
    opened = await _open(service)
    first = asyncio.create_task(
        service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
    )
    await asyncio.wait_for(runner.started.wait(), 5.0)

    for action in (_PRESENCE, SelectAuthorizationSourceAction("secret_reauthentication")):
        with pytest.raises(HumanControlError, match="phase_invalid"):
            await service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, action))
    # Another connection cannot open a ceremony while this one is live, and is told so plainly
    # rather than that the vault is locked (#1073 review P2-2).
    with pytest.raises(HumanControlError, match="ceremony_busy"):
        await _open(service, "9")

    runner.release.set()
    result = await asyncio.wait_for(first, 5.0)
    assert type(result) is ServerResultEnvelope
    assert len(runner.calls) == 1
    assert grants.consume(admission, _DIGEST) is True
    assert grants.consume(admission, _DIGEST) is False


async def test_an_approval_after_the_ceremony_expired_mints_nothing(tmp_path: Path) -> None:
    runner = _Runner(hold=True)
    service, grants, admission, clock, _ = _owner(tmp_path, "os_keyring", runner)
    opened = await _open(service)
    action = asyncio.create_task(
        service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
    )
    await asyncio.wait_for(runner.started.wait(), 5.0)
    clock.monotonic += 301.0
    runner.release.set()

    with pytest.raises(HumanControlError, match="binding_expired"):
        await asyncio.wait_for(action, 5.0)
    assert grants.consume(admission, _DIGEST) is False


async def test_a_terminal_that_disappears_during_the_prompt_cancels_it(tmp_path: Path) -> None:
    """The daemon's human-control handler ends the prompt when its ceremony client goes away."""

    runner = _Runner(hold=True)
    service, grants, admission, _, _ = _owner(tmp_path, "os_keyring", runner)
    frames = bytearray(
        encode_human_frame(
            ClientOpenEnvelope("7" * 64, HumanCeremonyKind.OWNER_RECEIPT_VIEW, _TARGET)
        )
    )
    sent: list[bytes] = []

    class _Stream:
        closed = False

        @property
        def peer_identity(self) -> object:
            return object()

        async def receive(self, max_bytes: int) -> bytes:
            if not frames:
                # The terminal goes away only once the OS prompt is up.
                await runner.started.wait()
                return b""
            size = min(max_bytes, len(frames))
            chunk = bytes(frames[:size])
            del frames[:size]
            return chunk

        async def send_all(self, data: Buffer) -> None:
            sent.append(bytes(data))
            if len(sent) == 1:
                active = service._active
                assert active is not None
                ceremony_id = active.binding.ceremony_id
                frames.extend(encode_human_frame(ClientActionEnvelope(ceremony_id, 2, _PRESENCE)))

        async def aclose(self) -> None:
            _Stream.closed = True

    handler = daemon_module._HumanConnectionServer(service)
    await asyncio.wait_for(handler(cast(Any, _Stream())), 5.0)

    assert runner.cancelled
    assert service._active is None
    assert _Stream.closed
    assert grants.consume(admission, _DIGEST) is False


async def test_the_packaged_daemon_composes_one_scoped_provider_on_macos_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def compose(root: Path) -> Any:
        metadata = root / "state"
        paths = daemon_module._ProductionPaths(
            root / "data",
            metadata / "service-generation.json",
            metadata / "unlock-throttle.json",
            metadata / "service.lock",
            metadata,
        )

        async def bind() -> _Listener:
            return _Listener()

        binders = daemon_module._ListenerBinders(cast(Any, bind), cast(Any, bind), cast(Any, bind))
        return await daemon_module._production_composition(
            _config=YoetzConfig(), _paths=paths, _binders=binders
        )

    async def close(composition: Any) -> None:
        daemon = daemon_module.ServiceDaemon(_composition=composition)
        await daemon.start()
        await daemon.close()

    monkeypatch.setattr(macos_user_presence, "_current_platform", lambda: "darwin")
    mac = await compose(tmp_path / "mac")
    human = mac.human_control_service
    assert type(human._user_presence) is MacOSLocalAuthenticationPresence
    # The vault consumes exactly the attestations human control obtained from that provider.
    assert mac.vault._user_presence_port is human._user_presence
    assert human._user_presence_scope == _SCOPE
    await close(mac)

    monkeypatch.setattr(macos_user_presence, "_current_platform", lambda: "linux")
    linux = await compose(tmp_path / "linux")
    assert linux.human_control_service._user_presence is None
    assert linux.vault._user_presence_port is None
    await close(linux)


async def test_tearing_down_the_connection_during_the_prompt_ends_it(tmp_path: Path) -> None:
    runner = _Runner(hold=True)
    service, grants, admission, _, _ = _owner(tmp_path, "os_keyring", runner)
    frames = bytearray(
        encode_human_frame(
            ClientOpenEnvelope("7" * 64, HumanCeremonyKind.OWNER_RECEIPT_VIEW, _TARGET)
        )
    )
    idle = asyncio.Event()

    class _Stream:
        @property
        def peer_identity(self) -> object:
            return object()

        async def receive(self, max_bytes: int) -> bytes:
            if not frames:
                await idle.wait()  # the terminal stays connected and silent
                return b""
            size = min(max_bytes, len(frames))
            chunk = bytes(frames[:size])
            del frames[:size]
            return chunk

        async def send_all(self, data: Buffer) -> None:
            del data
            active = service._active
            if active is not None and not frames:
                frames.extend(
                    encode_human_frame(
                        ClientActionEnvelope(active.binding.ceremony_id, 2, _PRESENCE)
                    )
                )

        async def aclose(self) -> None:
            idle.set()

    handler = asyncio.create_task(
        daemon_module._HumanConnectionServer(service)(cast(Any, _Stream()))
    )
    await asyncio.wait_for(runner.started.wait(), 5.0)
    handler.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(handler, 5.0)
    await asyncio.wait_for(service.close(), 5.0)
    assert runner.cancelled
    assert grants.consume(admission, _DIGEST) is False


async def test_prompts_that_do_not_approve_back_off_before_the_next_one(tmp_path: Path) -> None:
    """#1073 review P3: a caller cannot re-raise system dialogs without limit."""

    from yoetz.service.human_control import PRESENCE_BACKOFF_SECONDS

    runner = _Runner(stdout=b"cancelled\n")
    service, grants, admission, clock, _ = _owner(tmp_path, "os_keyring", runner)

    async def attempt(nonce: str) -> str:
        opened = await _open(service, nonce)
        try:
            await service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
        except HumanControlError as error:
            return error.reason
        return "authorized"

    assert await attempt("1") == "presence_refused"
    assert len(runner.calls) == 1
    # Within the first delay no dialog is raised at all.
    assert await attempt("2") == "reauthentication_rate_limited"
    assert len(runner.calls) == 1
    clock.monotonic += PRESENCE_BACKOFF_SECONDS[0]
    assert await attempt("3") == "presence_refused"
    assert len(runner.calls) == 2
    # The second miss waits longer.
    clock.monotonic += PRESENCE_BACKOFF_SECONDS[0]
    assert await attempt("4") == "reauthentication_rate_limited"
    clock.monotonic += PRESENCE_BACKOFF_SECONDS[1]
    runner.stdout = b"approved\n"
    assert await attempt("5") == "authorized"
    assert grants.consume(admission, _DIGEST) is True
    # An approval resets the schedule.
    runner.stdout = b"timeout\n"
    assert await attempt("6") == "presence_timeout"
    clock.monotonic += PRESENCE_BACKOFF_SECONDS[0]
    assert await attempt("7") == "presence_timeout"
    assert len(runner.calls) == 5


async def test_a_prompt_cancelled_while_it_is_up_counts_as_a_miss(tmp_path: Path) -> None:
    from yoetz.service.human_control import PRESENCE_MIN_SHOWN_SECONDS

    runner = _Runner(hold=True)
    service, _grants, _admission, clock, _ = _owner(tmp_path, "os_keyring", runner)
    opened = await _open(service)
    action = asyncio.create_task(
        service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
    )
    await asyncio.wait_for(runner.started.wait(), 5.0)
    clock.monotonic += PRESENCE_MIN_SHOWN_SECONDS  # the dialog was up long enough to be seen
    await service.cancel(opened.ceremony_id)
    with pytest.raises(HumanControlError, match="cancelled"):
        await asyncio.wait_for(action, 5.0)
    reopened = await _open(service, "8")
    with pytest.raises(HumanControlError, match="reauthentication_rate_limited"):
        await service.submit_action(ClientActionEnvelope(reopened.ceremony_id, 2, _PRESENCE))
    assert len(runner.calls) == 1


def test_a_throttled_passphrase_is_not_reported_as_a_locked_vault() -> None:
    from yoetz.service.unlock import UnlockError

    mapped = HumanControlService._map_error(UnlockError("unlock_rate_limited"))
    assert mapped == "reauthentication_rate_limited"


class _End:
    """One end of an in-memory duplex standing in for the human-control socket."""

    def __init__(self) -> None:
        self.peer: _End | None = None
        self.peer_identity = object()
        self._buffer = bytearray()
        self._eof = False
        self._ready = asyncio.Condition()

    async def _feed(self, data: bytes) -> None:
        async with self._ready:
            self._buffer.extend(data)
            self._ready.notify_all()

    async def _end(self) -> None:
        async with self._ready:
            self._eof = True
            self._ready.notify_all()

    async def receive(self, max_bytes: int) -> bytes:
        async with self._ready:
            while not self._buffer and not self._eof:
                await self._ready.wait()
            chunk = bytes(self._buffer[:max_bytes])
            del self._buffer[:max_bytes]
            return chunk

    async def send_all(self, data: Buffer) -> None:
        assert self.peer is not None
        await self.peer._feed(bytes(data))

    async def shutdown_write(self) -> None:
        assert self.peer is not None
        await self.peer._end()

    async def aclose(self) -> None:
        await self._end()
        if self.peer is not None:
            await self.peer._end()


def _real_client(service: HumanControlService) -> tuple[Any, list[asyncio.Task[None]]]:
    from yoetz.service.confidential_client import HumanControlClient

    servers: list[asyncio.Task[None]] = []
    handler = daemon_module._HumanConnectionServer(service)

    async def connect_human() -> Any:
        client_end, server_end = _End(), _End()
        client_end.peer, server_end.peer = server_end, client_end
        servers.append(asyncio.create_task(handler(cast(Any, server_end))))
        return client_end

    async def connect_secret() -> Any:
        raise AssertionError("the presence path sends no secret")

    factory = getattr(HumanControlClient, "_with_connectors")
    return factory(connect_human, connect_secret, timeout_seconds=5.0), servers


async def test_the_real_ceremony_client_drives_presence_end_to_end(tmp_path: Path) -> None:
    """#1073 review: the presence flow through HumanControlClient and the daemon handler."""

    from yoetz.service.confidential_client import ConfidentialClientError

    runner = _Runner(stdout=b"unavailable\n")
    service, grants, admission, clock, _ = _owner(tmp_path, "os_keyring", runner)
    # The client checks the binding's expiry against the real monotonic clock.
    clock.monotonic = time.monotonic()
    client, servers = _real_client(service)

    # No dialog could be shown: a typed refusal, and the ceremony is free again at once.
    session = await client.open(HumanCeremonyKind.OWNER_RECEIPT_VIEW, _TARGET)
    assert session.opened.phase == AuthorizationRequiredPhase(("os_user_presence",))
    await session.send_action(_PRESENCE)
    with pytest.raises(ConfidentialClientError) as unavailable:
        await session.wait_phase_or_result()
    assert unavailable.value.reason == "presence_unavailable"

    runner.stdout = b"approved\n"
    session = await client.open(HumanCeremonyKind.OWNER_RECEIPT_VIEW, _TARGET)
    await session.send_action(_PRESENCE)
    result = await session.wait_phase_or_result()
    assert result == OwnerReceiptViewResult("authorized", _DIGEST, 60)
    assert grants.consume(admission, _DIGEST) is True

    # Cancelled from the terminal while the dialog is up: the dialog ends, nothing is granted.
    runner.hold = True
    runner.started.clear()
    session = await client.open(HumanCeremonyKind.OWNER_RECEIPT_VIEW, _TARGET)
    await session.send_action(_PRESENCE)
    await asyncio.wait_for(runner.started.wait(), 5.0)
    await asyncio.wait_for(session.cancel(), 5.0)
    await asyncio.wait_for(asyncio.gather(*servers), 5.0)
    assert runner.cancelled
    assert service._active is None
    assert grants.consume(admission, _DIGEST) is False
    await client.close()


async def test_a_prompt_cancelled_at_once_cannot_lock_the_owner_out(tmp_path: Path) -> None:
    """#1073 review rounds 2-3: a quick open-and-cancel loop neither escalates the owner's wait
    (no lockout without a visible dialog) nor raises dialogs faster than one per first step."""

    from yoetz.service.human_control import PRESENCE_BACKOFF_SECONDS

    runner = _Runner(hold=True)
    service, grants, admission, clock, _ = _owner(tmp_path, "os_keyring", runner)
    for nonce, retry_nonce in (("1", "a"), ("2", "b"), ("3", "c"), ("4", "d")):
        runner.started.clear()
        opened = await _open(service, nonce)
        action = asyncio.create_task(
            service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
        )
        await asyncio.wait_for(runner.started.wait(), 5.0)
        await service.cancel(opened.ceremony_id)
        with pytest.raises(HumanControlError, match="cancelled"):
            await asyncio.wait_for(action, 5.0)
        # Spaced: an immediate retry raises no dialog.
        retry = await _open(service, retry_nonce)
        with pytest.raises(HumanControlError, match="reauthentication_rate_limited"):
            await service.submit_action(ClientActionEnvelope(retry.ceremony_id, 2, _PRESENCE))
        clock.monotonic += PRESENCE_BACKOFF_SECONDS[0]
    assert len(runner.calls) == 4
    # Never escalated: the owner waits at most the first step, not a growing backoff.
    assert service._presence_misses == 0
    runner.hold = False
    opened = await _open(service, "5")
    result = await service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
    assert type(result) is ServerResultEnvelope
    assert grants.consume(admission, _DIGEST) is True


async def test_the_backoff_decays_after_ten_quiet_minutes(tmp_path: Path) -> None:
    from yoetz.service.human_control import PRESENCE_BACKOFF_SECONDS, PRESENCE_MISS_DECAY_SECONDS

    runner = _Runner(stdout=b"cancelled\n")
    service, _grants, _admission, clock, _ = _owner(tmp_path, "os_keyring", runner)
    for nonce in ("1", "2", "3"):
        opened = await _open(service, nonce)
        with pytest.raises(HumanControlError, match="presence_refused"):
            await service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
        clock.monotonic += PRESENCE_BACKOFF_SECONDS[-1]
    assert service._presence_misses == 3
    clock.monotonic += PRESENCE_MISS_DECAY_SECONDS
    opened = await _open(service, "4")
    with pytest.raises(HumanControlError, match="presence_refused"):
        await service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
    # The quiet period reset the count, so this miss waits the first delay, not the fourth.
    assert service._presence_misses == 1
    assert service._presence_backoff_until == clock.monotonic + PRESENCE_BACKOFF_SECONDS[0]


async def test_a_silent_ceremony_past_its_expiry_does_not_hold_the_slot(tmp_path: Path) -> None:
    """#1073 review round 2: a client that opens and goes quiet cannot keep others busy."""

    runner = _Runner()
    service, grants, admission, clock, _ = _owner(tmp_path, "os_keyring", runner)
    await _open(service, "1")  # opened, then silent; its connection stays up
    with pytest.raises(HumanControlError, match="ceremony_busy"):
        await _open(service, "2")
    clock.monotonic += 301.0  # past the five-minute binding expiry
    opened = await _open(service, "3")
    result = await service.submit_action(ClientActionEnvelope(opened.ceremony_id, 2, _PRESENCE))
    assert type(result) is ServerResultEnvelope
    assert grants.consume(admission, _DIGEST) is True
