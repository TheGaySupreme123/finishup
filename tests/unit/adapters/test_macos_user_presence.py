"""Service-side macOS LocalAuthentication presence (ADR-016 decision 4, owner receipt view).

A stub helper runner stands in for ``/usr/bin/osascript`` everywhere except the POSIX runner
tests, which drive the real subprocess runner against ``/bin/sh`` and ``/bin/sleep`` to prove the
deadline and cancellation kill and reap the helper. A real Touch ID prompt needs a person at a
Mac; that check is the documented manual step in the integration runbooks.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import os
import signal
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

import pytest

from finishup.adapters.keys import macos_user_presence
from finishup.adapters.keys.macos_user_presence import (
    OWNER_VIEW_PRESENCE_PURPOSES,
    MacOSLocalAuthenticationPresence,
    run_presence_helper,
    select_service_user_presence,
)
from finishup.ports.secret_memory import (
    UserPresenceAttestation,
    UserPresenceChallenge,
    UserPresenceError,
    presence_confirmation_code,
)

pytestmark = pytest.mark.anyio

_TARGET = "sha256:" + "ab12cd34" + "0" * 56


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _challenge(purpose: str = "owner_receipt_view", target: str = _TARGET) -> UserPresenceChallenge:
    return UserPresenceChallenge(
        purpose=purpose,
        ceremony_digest="sha256:" + "c" * 64,
        target_digest=target,
        display_summary_digest=target,
        service_generation=7,
        vault_generation=3,
        policy_generation=None,
        expires_at_monotonic=400.0,
    )


@dataclass
class _Runner:
    returncode: int = 0
    stdout: bytes = b"approved\n"
    raises: BaseException | None = None
    calls: list[tuple[tuple[str, ...], bytes, dict[str, str], float]] = field(
        default_factory=lambda: []
    )

    async def __call__(
        self, argv: Sequence[str], stdin: bytes, env: Mapping[str, str], timeout: float
    ) -> tuple[int, bytes]:
        self.calls.append((tuple(argv), stdin, dict(env), timeout))
        if self.raises is not None:
            raise self.raises
        return self.returncode, self.stdout


@dataclass
class _Clock:
    now: float = 100.0

    def __call__(self) -> float:
        return self.now


def _adapter(
    runner: _Runner, *, platform: str = "darwin", clock: _Clock | None = None
) -> MacOSLocalAuthenticationPresence:
    return MacOSLocalAuthenticationPresence(
        runner=runner,
        platform=lambda: platform,
        monotonic=clock or _Clock(),
        helper_present=lambda: True,
    )


async def test_approval_runs_the_fixed_helper_and_yields_a_one_use_attestation() -> None:
    runner = _Runner()
    presence = _adapter(runner)
    challenge = _challenge()

    attestation = await presence.assert_presence(challenge)

    (call,) = runner.calls
    argv, stdin, env, timeout = call
    # Absolute, SIP-protected executable; no shell; the program arrives on stdin.
    assert argv[:4] == ("/usr/bin/osascript", "-l", "JavaScript", "-")
    assert len(argv) == 5
    assert os.path.isabs(argv[0])
    # The only variable text is the hex confirmation code derived from the target digest.
    assert argv[4] == (
        "show your full FinishUP receipt, including repository names hidden from your agents "
        "(confirmation code ab12-cd34). Cancel unless you just asked for it in your own terminal."
    )
    assert env == {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    assert timeout == 75.0
    script = stdin.decode("utf-8")
    assert "ObjC.import('LocalAuthentication');" in script
    assert "$.LAPolicyDeviceOwnerAuthentication" in script
    assert "touchIDAuthenticationAllowableReuseDuration = 0" in script
    assert "Date.now() + 60000" in script
    assert "context.invalidate;" in script
    assert "{" not in argv[4] and "$(" not in argv[4]

    presence.consume(attestation, challenge)
    with pytest.raises(UserPresenceError) as replay:
        presence.consume(attestation, challenge)
    assert replay.value.reason == "failed"


@pytest.mark.parametrize(
    ("stdout", "reason"),
    [
        (b"cancelled\n", "cancelled"),
        (b"failed\n", "failed"),
        (b"unavailable\n", "unavailable"),
        (b"timeout\n", "timeout"),
        (b"timeout", "timeout"),
    ],
)
async def test_each_refusal_is_typed(stdout: bytes, reason: str) -> None:
    presence = _adapter(_Runner(stdout=stdout))
    with pytest.raises(UserPresenceError) as raised:
        await presence.assert_presence(_challenge())
    assert raised.value.reason == reason


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (1, b"approved\n"),
        (0, b"Approved\n"),
        (0, b"approved \n"),
        (0, b" approved\n"),
        (0, b"approved\n\n"),
        (0, b"approved\napproved\n"),
        (0, b"\x00approved\n"),
        (0, b"approvedx\n"),
        (0, b"invalid\n"),
        (0, b""),
        (0, b"approved" * 20),
        (-9, b""),
    ],
)
async def test_a_garbled_or_failed_helper_result_is_never_success(
    returncode: int, stdout: bytes
) -> None:
    presence = _adapter(_Runner(returncode=returncode, stdout=stdout))
    with pytest.raises(UserPresenceError) as raised:
        await presence.assert_presence(_challenge())
    assert raised.value.reason == "unavailable"
    assert presence._issued == {}


async def test_helper_deadline_and_launch_failures_are_typed() -> None:
    timed_out = _adapter(_Runner(raises=TimeoutError()))
    with pytest.raises(UserPresenceError) as timeout:
        await timed_out.assert_presence(_challenge())
    assert timeout.value.reason == "timeout"

    missing = _adapter(_Runner(raises=FileNotFoundError()))
    with pytest.raises(UserPresenceError) as unavailable:
        await missing.assert_presence(_challenge())
    assert unavailable.value.reason == "unavailable"


async def test_a_purpose_outside_the_scope_never_starts_a_prompt() -> None:
    runner = _Runner()
    presence = _adapter(runner)
    for purpose in ("provider_credential_set", "privacy_policy_widen", "vault_passphrase_rotate"):
        with pytest.raises(UserPresenceError) as raised:
            await presence.assert_presence(_challenge(purpose))
        assert raised.value.reason == "unavailable"
    assert runner.calls == []
    with pytest.raises(ValueError, match="presence_purposes_invalid"):
        MacOSLocalAuthenticationPresence(purposes=frozenset({"provider_credential_set"}))


async def test_off_macos_or_without_the_helper_nothing_is_offered_or_started() -> None:
    runner = _Runner()
    linux = _adapter(runner, platform="linux")
    assert linux.capability().available == "unavailable"
    with pytest.raises(UserPresenceError) as raised:
        await linux.assert_presence(_challenge())
    assert raised.value.reason == "unavailable"

    no_helper = MacOSLocalAuthenticationPresence(
        runner=runner, platform=lambda: "darwin", helper_present=lambda: False
    )
    capability = no_helper.capability()
    assert {
        capability.available,
        capability.os_authenticated_prompt,
        capability.trusted_action_binding,
        capability.one_use_attestation,
    } == {"unavailable"}
    with pytest.raises(UserPresenceError):
        await no_helper.assert_presence(_challenge())
    assert runner.calls == []


async def test_capability_on_macos_is_active_but_matches_no_release_cell() -> None:
    capability = _adapter(_Runner()).capability()
    assert {
        capability.available,
        capability.os_authenticated_prompt,
        capability.trusted_action_binding,
        capability.one_use_attestation,
    } == {"active"}
    # Keyring first-install authority needs a qualified runtime-support row; this adapter
    # deliberately names none.
    assert capability.release_cell == "unqualified"
    assert capability.adapter_id == "finishup.presence.macos-local-authentication"


async def test_an_attestation_is_bound_to_its_exact_challenge_and_expires() -> None:
    clock = _Clock()
    presence = _adapter(_Runner(), clock=clock)
    challenge = _challenge()

    other_target = await presence.assert_presence(challenge)
    with pytest.raises(UserPresenceError):
        presence.consume(other_target, _challenge(target="sha256:" + "f" * 64))

    other_generation = await presence.assert_presence(challenge)
    with pytest.raises(UserPresenceError):
        presence.consume(other_generation, replace(challenge, vault_generation=4))

    stale = await presence.assert_presence(challenge)
    clock.now += 30.0
    with pytest.raises(UserPresenceError) as expired:
        presence.consume(stale, challenge)
    assert expired.value.reason == "timeout"


async def test_a_client_made_object_is_not_an_attestation() -> None:
    presence = _adapter(_Runner())
    challenge = _challenge()
    await presence.assert_presence(challenge)

    class _Forged:
        _token = "0" * 32

    for forged in (_Forged(), object(), True, "approved"):
        with pytest.raises(UserPresenceError):
            presence.consume(forged, challenge)  # pyright: ignore[reportArgumentType]


async def test_close_withdraws_issued_attestations_and_stops_prompting() -> None:
    runner = _Runner()
    presence = _adapter(runner)
    challenge = _challenge()
    attestation = await presence.assert_presence(challenge)
    presence.close()
    with pytest.raises(UserPresenceError):
        presence.consume(attestation, challenge)
    with pytest.raises(UserPresenceError):
        await presence.assert_presence(challenge)
    assert len(runner.calls) == 1


def test_confirmation_code_is_hex_from_the_target_digest_only() -> None:
    assert presence_confirmation_code(_TARGET) == "ab12-cd34"
    with pytest.raises(ValueError):
        presence_confirmation_code("ab12cd34")


def test_selection_is_macos_only(monkeypatch: pytest.MonkeyPatch) -> None:
    darwin = select_service_user_presence("darwin")
    assert type(darwin) is MacOSLocalAuthenticationPresence
    assert darwin.purposes == OWNER_VIEW_PRESENCE_PURPOSES
    for platform in ("linux", "win32", "cygwin", "freebsd14"):
        assert select_service_user_presence(platform) is None

    monkeypatch.setattr(macos_user_presence, "_current_platform", lambda: "darwin")
    assert type(select_service_user_presence()) is MacOSLocalAuthenticationPresence
    monkeypatch.setattr(macos_user_presence, "_current_platform", lambda: "linux")
    assert select_service_user_presence() is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX helper processes only")
async def test_the_real_runner_returns_exit_status_and_bounded_output() -> None:
    returncode, stdout = await run_presence_helper(
        ("/bin/sh", "-c", "cat; printf approved"), b"", {"PATH": "/usr/bin:/bin"}, 10.0
    )
    assert (returncode, stdout) == (0, b"approved")
    returncode, stdout = await run_presence_helper(
        ("/bin/sh", "-c", "head -c 4096 /dev/zero"), b"", {"PATH": "/usr/bin:/bin"}, 10.0
    )
    assert returncode == 0 and len(stdout) == 65
    with pytest.raises(UserPresenceError):
        await run_presence_helper(("sh", "-c", "true"), b"", {}, 1.0)


def _capture_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[asyncio.subprocess.Process], asyncio.Event]:
    processes: list[asyncio.subprocess.Process] = []
    started = asyncio.Event()
    spawn = asyncio.create_subprocess_exec

    async def capture(*args: object, **kwargs: object) -> asyncio.subprocess.Process:
        process = await spawn(*args, **kwargs)  # pyright: ignore[reportArgumentType]
        processes.append(process)
        started.set()
        return process

    monkeypatch.setattr(macos_user_presence.asyncio, "create_subprocess_exec", capture)
    return processes, started


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX helper processes only")
async def test_the_real_runner_kills_and_reaps_the_helper_at_its_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processes, _started = _capture_processes(monkeypatch)
    with pytest.raises(TimeoutError):
        await run_presence_helper(
            ("/bin/sh", "-c", "exec /bin/sleep 30"), b"", {"PATH": "/usr/bin:/bin"}, 0.3
        )
    (process,) = processes
    # Killed and reaped before the deadline error surfaced, not left to finish its sleep.
    assert process.returncode == -signal.SIGKILL


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX helper processes only")
async def test_the_real_runner_kills_the_helper_when_the_ceremony_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processes, started = _capture_processes(monkeypatch)
    task = asyncio.create_task(
        run_presence_helper(
            ("/bin/sh", "-c", "exec /bin/sleep 30"), b"", {"PATH": "/usr/bin:/bin"}, 60.0
        )
    )
    await asyncio.wait_for(started.wait(), 10.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    (process,) = processes
    assert process.returncode == -signal.SIGKILL


async def test_attestation_is_opaque_and_not_serializable() -> None:
    import pickle

    presence = _adapter(_Runner())
    attestation: UserPresenceAttestation = await presence.assert_presence(_challenge())
    assert "approved" not in repr(attestation)
    with pytest.raises(TypeError):
        pickle.dumps(attestation)


async def test_an_approval_nobody_consumed_is_dropped_at_the_next_prompt() -> None:
    clock = _Clock()
    presence = _adapter(_Runner(), clock=clock)
    challenge = _challenge()
    abandoned = await presence.assert_presence(challenge)
    clock.now += 31.0
    fresh = await presence.assert_presence(challenge)
    assert list(presence._issued) == [fresh]
    with pytest.raises(UserPresenceError):
        presence.consume(abandoned, challenge)
    presence.consume(fresh, challenge)
