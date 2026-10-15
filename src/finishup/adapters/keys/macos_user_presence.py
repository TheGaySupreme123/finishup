"""macOS LocalAuthentication user presence for the service's human-control reauthentication.

This is the service-wide ``UserPresencePort`` the packaged daemon composes on macOS (ADR-016
decision 4, ADR-009 owner receipt view). The *service* process runs the check: it starts the
SIP-protected ``/usr/bin/osascript`` with a fixed JavaScript-for-Automation program that asks
Apple LocalAuthentication for ``LAPolicyDeviceOwnerAuthentication`` (Touch ID or the device
password) in a fresh context with authentication reuse disabled. No client, CLI, terminal or
agent can assert presence: a client only names the source it asks for, and only the exact
``approved`` token from this helper, for this exact challenge, yields an attestation that the
vault consumes once.

The adapter is purpose-scoped. It prompts only for the reauthentication purposes it has fixed
prompt text for (today ``owner_receipt_view``); any other challenge is ``unavailable`` without
starting a helper. Every non-approval is a typed :class:`UserPresenceError`; an unreadable,
garbled or nonzero helper result is never success.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import suppress
from types import MappingProxyType
from typing import Final, Literal

from finishup.ports.secret_memory import (
    UserPresenceAttestation,
    UserPresenceCapability,
    UserPresenceChallenge,
    UserPresenceError,
    presence_confirmation_code,
)

__all__ = [
    "LOCAL_AUTHENTICATION_PROMPT_SECONDS",
    "OWNER_VIEW_PRESENCE_PURPOSES",
    "OWNER_VIEW_PRESENCE_VAULT_MODES",
    "MacOSLocalAuthenticationPresence",
    "run_presence_helper",
    "select_service_user_presence",
]

type _Outcome = Literal["approved", "cancelled", "failed", "unavailable", "timeout"]
type HelperRunner = Callable[
    [Sequence[str], bytes, Mapping[str, str], float], Awaitable[tuple[int, bytes]]
]

_OSASCRIPT: Final = "/usr/bin/osascript"
_LOCAL_AUTHENTICATION_FRAMEWORK: Final = "/System/Library/Frameworks/LocalAuthentication.framework"
# The helper's own prompt deadline. The service kills the helper a little later if it has not
# exited, so a wedged ``osascript`` can never hold the ceremony past this bound.
LOCAL_AUTHENTICATION_PROMPT_SECONDS: Final = 60
_HELPER_DEADLINE_SECONDS: Final = float(LOCAL_AUTHENTICATION_PROMPT_SECONDS + 15)
# An attestation is consumed by the vault immediately after the prompt; it is never a window.
_ATTESTATION_SECONDS: Final = 30.0
_MAX_HELPER_OUTPUT: Final = 64
_HELPER_ENVIRONMENT: Final[Mapping[str, str]] = MappingProxyType(
    {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
)

# The only reauthentication purposes this adapter may prompt for, and the vault modes on which
# the service offers it. Both ready vault modes qualify: a system-keychain install's vault
# passphrase is generated and kept in the Keychain, so its owner never learned it, and on a vault
# with a passphrase the owner chose, that passphrase stays offered beside the dialog (ADR-009).
OWNER_VIEW_PRESENCE_PURPOSES: Final = frozenset({"owner_receipt_view"})
OWNER_VIEW_PRESENCE_VAULT_MODES: Final = frozenset({"os_keyring", "passphrase"})

# Fixed prompt text per purpose. The only variable part is the confirmation code, which is hex
# derived from the service-computed target digest; nothing user-controlled reaches the dialog.
_PROMPT_REASONS: Final = {
    "owner_receipt_view": (
        "show your full FinishUP receipt, including repository names hidden from your agents "
        "(confirmation code {code}). Cancel unless you just asked for it in your own terminal."
    ),
}

_JXA_LOCAL_AUTHENTICATION: Final = rf"""
ObjC.import('Foundation');
ObjC.import('LocalAuthentication');

function run(argv) {{
    if (argv.length !== 1) {{
        return 'invalid';
    }}
    const context = $.LAContext.alloc.init;
    context.touchIDAuthenticationAllowableReuseDuration = 0;
    const policy = $.LAPolicyDeviceOwnerAuthentication;
    const error = Ref();
    if (!ObjC.unwrap(context.canEvaluatePolicyError(policy, error))) {{
        return 'unavailable';
    }}

    let completed = false;
    let outcome = 'failed';
    context.evaluatePolicyLocalizedReasonReply(policy, $(argv[0]), function(success, replyError) {{
        // LocalAuthentication's success boolean is authoritative; the error code only sorts a
        // refusal. Reading it can fail on some JXA builds, which leaves the refusal as 'failed'.
        if (Boolean(success)) {{
            outcome = 'approved';
        }} else {{
            let code = 0;
            try {{
                code = Number(replyError.code);
            }} catch (ignored) {{
                code = 0;
            }}
            if (code === -2 || code === -4 || code === -9) {{
                outcome = 'cancelled';
            }} else if (
                code === -5 || code === -6 || code === -7 || code === -10 || code === -11
                || code === -1004
            ) {{
                outcome = 'unavailable';
            }} else {{
                outcome = 'failed';
            }}
        }}
        completed = true;
    }});

    const deadline = Date.now() + {LOCAL_AUTHENTICATION_PROMPT_SECONDS * 1000};
    while (!completed && Date.now() < deadline) {{
        $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.05));
    }}
    if (!completed) {{
        context.invalidate;
        return 'timeout';
    }}
    return outcome;
}}
""".lstrip()

_HELPER_RESULTS: Final[Mapping[bytes, _Outcome]] = {
    b"approved": "approved",
    b"cancelled": "cancelled",
    b"failed": "failed",
    b"unavailable": "unavailable",
    b"timeout": "timeout",
}

_HELPER_DIGEST: Final = (
    "sha256:"
    + hashlib.sha256(
        b"\x00".join(
            (
                _OSASCRIPT.encode(),
                _JXA_LOCAL_AUTHENTICATION.encode(),
                repr(sorted(_PROMPT_REASONS.items())).encode(),
            )
        )
    ).hexdigest()
)


def _current_platform() -> str:
    return sys.platform


async def run_presence_helper(
    argv: Sequence[str], stdin: bytes, env: Mapping[str, str], timeout: float
) -> tuple[int, bytes]:
    """Run one fixed helper with no shell; kill and reap it on deadline or cancellation."""

    if not argv or not os.path.isabs(argv[0]):
        raise UserPresenceError("unavailable")
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=dict(env),
        cwd="/",
        close_fds=True,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(stdin), timeout)
    except BaseException:
        if process.returncode is None:
            with suppress(ProcessLookupError):
                process.kill()
            with suppress(BaseException):
                await asyncio.wait_for(asyncio.shield(process.wait()), 5.0)
        raise
    return (process.returncode if process.returncode is not None else -1), stdout[
        : _MAX_HELPER_OUTPUT + 1
    ]


class _LocalAuthenticationAttestation:
    """Opaque, identity-compared, one-use proof that one exact challenge was approved."""

    __slots__ = ("_token",)

    def __init__(self) -> None:
        self._token = secrets.token_hex(16)

    def __repr__(self) -> str:
        return "<LocalAuthenticationAttestation>"

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("user_presence_attestation_not_serializable")


class MacOSLocalAuthenticationPresence:
    """Service-side Touch ID / device-password presence for scoped reauthentication purposes."""

    # Frozen legacy identifier (ADR-048): presence adapter ids share the `yoetz.` namespace with the
    # released keyring and capability names that protocol 0.1 keeps.
    adapter_id: Final = "yoetz.presence.macos-local-authentication"
    profile_id: Final = "device-owner-authentication/1"

    def __init__(
        self,
        *,
        purposes: frozenset[str] = OWNER_VIEW_PRESENCE_PURPOSES,
        runner: HelperRunner | None = None,
        platform: Callable[[], str] = _current_platform,
        monotonic: Callable[[], float] = time.monotonic,
        helper_present: Callable[[], bool] | None = None,
    ) -> None:
        unknown = purposes - frozenset(_PROMPT_REASONS)
        if type(purposes) is not frozenset or not purposes or unknown:
            raise ValueError("presence_purposes_invalid")
        self._purposes = purposes
        self._runner: HelperRunner = run_presence_helper if runner is None else runner
        self._platform = platform
        self._monotonic = monotonic
        self._helper_present = _helper_present if helper_present is None else helper_present
        self._issued: dict[
            _LocalAuthenticationAttestation, tuple[UserPresenceChallenge, float]
        ] = {}
        self._prompt = asyncio.Lock()
        self._closed = False

    @property
    def purposes(self) -> frozenset[str]:
        return self._purposes

    def capability(self) -> UserPresenceCapability:
        state: Literal["active", "unavailable"] = "active" if self._usable() else "unavailable"
        return UserPresenceCapability(
            candidate_artifact_digest=_HELPER_DIGEST,
            # No runtime-support ``user_presence_cells`` row names this adapter, so it can never
            # satisfy keyring first-install authority; it serves only its scoped purposes.
            release_cell="unqualified",
            adapter_id=self.adapter_id,
            profile_id=self.profile_id,
            os_authentication_primitive="LocalAuthentication.LAPolicyDeviceOwnerAuthentication",
            os_authenticated_prompt=state,
            trusted_action_binding=state,
            one_use_attestation=state,
            available=state,
            capability_evidence_digest=_HELPER_DIGEST,
        )

    async def assert_presence(self, challenge: UserPresenceChallenge) -> UserPresenceAttestation:
        if type(challenge) is not UserPresenceChallenge:
            raise UserPresenceError("unavailable")
        template = _PROMPT_REASONS.get(challenge.purpose)
        if template is None or challenge.purpose not in self._purposes or not self._usable():
            raise UserPresenceError("unavailable")
        reason = template.format(code=presence_confirmation_code(challenge.target_digest))
        async with self._prompt:
            if self._closed:
                raise UserPresenceError("unavailable")
            try:
                returncode, stdout = await self._runner(
                    (_OSASCRIPT, "-l", "JavaScript", "-", reason),
                    _JXA_LOCAL_AUTHENTICATION.encode("utf-8"),
                    _HELPER_ENVIRONMENT,
                    _HELPER_DEADLINE_SECONDS,
                )
            except TimeoutError as exc:
                raise UserPresenceError("timeout") from exc
            except UserPresenceError:
                raise
            except (OSError, ValueError, NotImplementedError, subprocess.SubprocessError) as exc:
                raise UserPresenceError("unavailable") from exc
            outcome = _parse_helper_result(returncode, stdout)
            if outcome != "approved":
                raise UserPresenceError(outcome)
            if self._closed:
                raise UserPresenceError("unavailable")
            now = self._monotonic()
            for stale in [
                key
                for key, (_bound, issued_at) in self._issued.items()
                if not 0.0 <= now - issued_at < _ATTESTATION_SECONDS
            ]:
                del self._issued[stale]  # approved, then never consumed (ceremony ended)
            attestation = _LocalAuthenticationAttestation()
            self._issued[attestation] = (challenge, self._monotonic())
            return attestation

    def consume(
        self, attestation: UserPresenceAttestation, challenge: UserPresenceChallenge
    ) -> None:
        if type(attestation) is not _LocalAuthenticationAttestation:
            raise UserPresenceError("failed")
        issued = self._issued.pop(attestation, None)
        if issued is None or self._closed:
            raise UserPresenceError("failed")
        bound, issued_at = issued
        if bound != challenge:
            raise UserPresenceError("failed")
        elapsed = self._monotonic() - issued_at
        if not 0.0 <= elapsed < _ATTESTATION_SECONDS:
            raise UserPresenceError("timeout")

    def close(self) -> None:
        self._closed = True
        self._issued.clear()

    def _usable(self) -> bool:
        if self._closed or self._platform() != "darwin":
            return False
        try:
            return self._helper_present()
        except OSError:
            return False


def _helper_present() -> bool:
    return os.path.isfile(_OSASCRIPT) and os.path.isdir(_LOCAL_AUTHENTICATION_FRAMEWORK)


def _parse_helper_result(returncode: int, stdout: bytes) -> _Outcome:
    """Exactly one known token, optionally newline-terminated; anything else is unavailable."""

    if returncode != 0 or type(stdout) is not bytes or len(stdout) > _MAX_HELPER_OUTPUT:
        return "unavailable"
    token = stdout[:-1] if stdout.endswith(b"\n") else stdout
    return _HELPER_RESULTS.get(token, "unavailable")


def select_service_user_presence(
    platform: str | None = None,
) -> MacOSLocalAuthenticationPresence | None:
    """The service-wide presence provider for ``platform`` (default: this interpreter's).

    macOS gets the LocalAuthentication adapter. Linux, WSL 2 and every other platform get none,
    so the human-control ceremony keeps its fail-closed continuation there.
    """

    selected = _current_platform() if platform is None else platform
    if selected != "darwin":
        return None
    if platform is None:
        return MacOSLocalAuthenticationPresence()
    return MacOSLocalAuthenticationPresence(platform=lambda: selected)
