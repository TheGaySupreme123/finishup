"""Linux PAM re-authentication authority for one exact plugin-artifact review.

This is the Linux sibling of ``MacOSArtifactUserPresence`` and is exactly as narrow: it proves
that the invoking account's operating-system password was re-entered for the already validated,
digest-bound ``plugin_artifact_apply`` pending consumed by ``ElevatedPortableArtifactReview``.

The password travels only through the ADR-008/ADR-015 trusted foreground console
(``/dev/tty`` with matching-terminal and foreground-process-group checks) and is verified by
Linux-PAM through the fixed ``login`` service. The console is the ingress, never the authority:
a terminal, pseudo-terminal, or same-UID process that cannot produce the account password proves
nothing. The same cell serves a Linux distribution running under WSL 2, which has no
LocalAuthentication, usually no display-bound polkit agent, and often no logind session, but does
ship PAM and the account password chosen at first launch.
"""

from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import sys
from collections.abc import Callable
from io import BufferedReader
from types import TracebackType
from typing import Final, Protocol, Self, cast

from finishup.cli.trusted_console import TrustedForegroundConsole
from finishup.ports.plugin_artifacts import ArtifactAuthority

__all__ = [
    "PAM_SERVICE",
    "ArtifactPasswordAuthenticator",
    "LinuxArtifactUserPresence",
    "LinuxPamAuthenticator",
    "PresenceConsole",
    "invoking_account",
]

PAM_SERVICE: Final = "login"
_PAM_LIBRARY: Final = "libpam.so.0"
_TIMEOUT_SECONDS: Final = 130
_PASSWORD_MAX_BYTES: Final = 1024
_ACCOUNT_MAX_LENGTH: Final = 256

_PAM_SUCCESS: Final = 0
_PAM_CONV_ERR: Final = 19
_PAM_TTY: Final = 3
_PAM_DISALLOW_NULL_AUTHTOK: Final = 0x1
_PAM_PROMPT_ECHO_OFF: Final = 1
_PAM_ERROR_MSG: Final = 3
_PAM_TEXT_INFO: Final = 4

_UNAVAILABLE: Final = "human_authority_unavailable"


class ArtifactPasswordAuthenticator(Protocol):
    """Verify the account password produced by ``read_password`` against the operating system."""

    def authenticate(self, account: str, read_password: Callable[[], bytearray]) -> bool: ...


class PresenceConsole(Protocol):
    """The slice of ``TrustedForegroundConsole`` this ceremony uses."""

    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
        /,
    ) -> None: ...

    def write(self, value: str, /) -> None: ...

    def read_secret(self, prompt: str, maximum: int, /) -> bytearray: ...


class _Deadline(BaseException):
    """Raised by the SIGALRM handler when the bounded ceremony overruns."""


def _overwrite(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


class PamMessage(ctypes.Structure):
    msg_style: int
    msg: bytes | None
    _fields_ = (("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p))


class PamResponse(ctypes.Structure):
    resp: int | None
    resp_retcode: int
    _fields_ = (("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int))


# Linux-PAM passes ``const struct pam_message **`` (an array of pointers) and expects
# ``struct pam_response **`` to receive one ``calloc``-ed array that PAM later frees.
_CONVERSATION: Final = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
)


class _PamConv(ctypes.Structure):
    _fields_ = (("conv", _CONVERSATION), ("appdata_ptr", ctypes.c_void_p))


class ConversationState:
    """Outcome record shared between ``converse`` and the ``pam_authenticate`` caller."""

    __slots__ = ("failed", "prompted")

    def __init__(self) -> None:
        self.failed = False
        self.prompted = 0


class ResponseAllocator:
    """``calloc``/``free`` wrapper for the response memory PAM takes ownership of."""

    __slots__ = ("_libc",)

    def __init__(self, libc: ctypes.CDLL) -> None:
        self._libc = libc
        self._libc.calloc.restype = ctypes.c_void_p
        self._libc.calloc.argtypes = (ctypes.c_size_t, ctypes.c_size_t)
        self._libc.free.restype = None
        self._libc.free.argtypes = (ctypes.c_void_p,)

    def block(self, count: int) -> int:
        address = self._libc.calloc(count, ctypes.sizeof(PamResponse))
        if not address:
            raise MemoryError
        return int(address)

    def string(self, secret: bytearray) -> int:
        """Copy ``secret`` into a NUL-terminated ``calloc`` buffer, then zero ``secret``."""

        try:
            address = self._libc.calloc(len(secret) + 1, 1)
            if not address:
                raise MemoryError
            source = (ctypes.c_char * len(secret)).from_buffer(secret)
            try:
                ctypes.memmove(address, source, len(secret))
            finally:
                del source
            return int(address)
        finally:
            _overwrite(secret)

    def release(self, block: int, count: int) -> None:
        responses = ctypes.cast(block, ctypes.POINTER(PamResponse))
        for index in range(count):
            buffer = responses[index].resp
            if buffer:
                ctypes.memset(buffer, 0, len(ctypes.string_at(buffer)))
                self._libc.free(buffer)
        self._libc.free(block)


def converse(
    allocator: ResponseAllocator,
    state: ConversationState,
    read_password: Callable[[], bytearray],
    count: int,
    messages_address: int | None,
    responses_address: int | None,
) -> int:
    """Answer exactly one hidden password prompt; every other conversation fails closed."""

    block = 0
    try:
        if count <= 0 or not messages_address or not responses_address:
            raise RuntimeError(_UNAVAILABLE)
        messages = ctypes.cast(messages_address, ctypes.POINTER(ctypes.POINTER(PamMessage)))
        block = allocator.block(count)
        answers = ctypes.cast(block, ctypes.POINTER(PamResponse))
        for index in range(count):
            style = messages[index].contents.msg_style
            if style in {_PAM_ERROR_MSG, _PAM_TEXT_INFO}:
                # Operating-system text is never reflected to the operator.
                continue
            if style != _PAM_PROMPT_ECHO_OFF or state.prompted:
                raise RuntimeError(_UNAVAILABLE)
            state.prompted += 1
            answers[index].resp = allocator.string(read_password())
            answers[index].resp_retcode = 0
        ctypes.cast(responses_address, ctypes.POINTER(ctypes.c_void_p))[0] = block
        return _PAM_SUCCESS
    except BaseException:
        # A Python exception cannot cross the C boundary; record it and let PAM fail.
        state.failed = True
        if block:
            allocator.release(block, count)
        return _PAM_CONV_ERR


class LinuxPamAuthenticator:
    """``libpam.so.0`` binding: one ``pam_authenticate`` plus ``pam_acct_mgmt`` for one account."""

    __slots__ = ("_allocator", "_libpam")

    def __init__(self) -> None:
        # ``pam_unix`` cannot read ``/etc/shadow`` from an unprivileged process, so it verifies
        # through the setuid ``unix_chkpwd`` helper, which only accepts the invoking user's own
        # account. That restriction is the property this cell relies on.
        self._libpam = ctypes.CDLL(_PAM_LIBRARY)
        self._allocator = ResponseAllocator(ctypes.CDLL(None))
        self._libpam.pam_start.restype = ctypes.c_int
        self._libpam.pam_start.argtypes = (
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(_PamConv),
            ctypes.POINTER(ctypes.c_void_p),
        )
        self._libpam.pam_set_item.restype = ctypes.c_int
        self._libpam.pam_set_item.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p)
        self._libpam.pam_authenticate.restype = ctypes.c_int
        self._libpam.pam_authenticate.argtypes = (ctypes.c_void_p, ctypes.c_int)
        self._libpam.pam_acct_mgmt.restype = ctypes.c_int
        self._libpam.pam_acct_mgmt.argtypes = (ctypes.c_void_p, ctypes.c_int)
        self._libpam.pam_end.restype = ctypes.c_int
        self._libpam.pam_end.argtypes = (ctypes.c_void_p, ctypes.c_int)

    def authenticate(self, account: str, read_password: Callable[[], bytearray]) -> bool:
        state = ConversationState()

        def conversation(
            count: int, messages: int | None, responses: int | None, _appdata: int | None
        ) -> int:
            return converse(self._allocator, state, read_password, count, messages, responses)

        callback = _CONVERSATION(conversation)
        conv = _PamConv(callback, None)
        handle = ctypes.c_void_p()
        status = int(
            self._libpam.pam_start(
                PAM_SERVICE.encode("ascii"),
                account.encode("ascii"),
                ctypes.byref(conv),
                ctypes.byref(handle),
            )
        )
        if status != _PAM_SUCCESS:
            return False
        try:
            if self._libpam.pam_set_item(handle, _PAM_TTY, b"/dev/tty") != _PAM_SUCCESS:
                return False
            status = int(self._libpam.pam_authenticate(handle, _PAM_DISALLOW_NULL_AUTHTOK))
            if status != _PAM_SUCCESS or state.failed or state.prompted != 1:
                return False
            status = int(self._libpam.pam_acct_mgmt(handle, 0))
            return status == _PAM_SUCCESS and not state.failed
        finally:
            self._libpam.pam_end(handle, status)
            del callback


class IsolatedPamAuthenticator:
    """Keep native PAM off the console process so its deadline can always stop the attempt."""

    def authenticate(self, account: str, read_password: Callable[[], bytearray]) -> bool:
        secret = read_password()
        try:
            if not secret or len(secret) > _PASSWORD_MAX_BYTES or 0 in secret:
                return False
            # The password crosses only an anonymous pipe, never argv, environment, or a file.
            # Isolated Python ignores the working directory and PYTHONPATH for imports. The
            # worker cannot reflect PAM text or ask another console prompt.
            with subprocess.Popen(  # noqa: S603 - fixed interpreter/worker, no shell
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "from finishup.adapters.integrations.linux_artifact_presence import pam_worker; "
                    "raise SystemExit(pam_worker())",
                    account,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ) as process:
                try:
                    # CPython's binary communicate accepts the buffer protocol; retain the
                    # wipeable bytearray instead of making an immutable password copy.
                    process.communicate(input=secret, timeout=_TIMEOUT_SECONDS)  # pyright: ignore[reportArgumentType]
                    return process.returncode == 0
                finally:
                    # Also runs when the whole-ceremony alarm interrupts communicate. Kill only
                    # the worker we spawned, before Popen.__exit__ waits for it.
                    if process.poll() is None:
                        process.kill()
                    process.wait()
        finally:
            _overwrite(secret)


def pam_worker() -> int:
    """Private fixed worker entrypoint; expose only a successful/failed exit status."""

    secret = bytearray(_PASSWORD_MAX_BYTES + 1)
    used = 0
    try:
        if sys.platform != "linux" or len(sys.argv) != 2 or sys.argv[1] != invoking_account():
            return 1
        while used < len(secret):
            with memoryview(secret)[used:] as target:
                count = cast(BufferedReader, sys.stdin.buffer).readinto(target)
            if not count:
                break
            used += count
        if not 0 < used <= _PASSWORD_MAX_BYTES or 0 in memoryview(secret)[:used]:
            return 1
        del secret[used:]
        return 0 if LinuxPamAuthenticator().authenticate(sys.argv[1], lambda: secret) else 1
    except BaseException:
        return 1
    finally:
        _overwrite(secret)


def invoking_account() -> str:
    """Name of the real-UID account, the only one ``unix_chkpwd`` will verify."""

    import pwd

    name = pwd.getpwuid(os.getuid()).pw_name
    if (
        not name
        or len(name) > _ACCOUNT_MAX_LENGTH
        or not name.isascii()
        or not name.isprintable()
        or " " in name
    ):
        raise RuntimeError(_UNAVAILABLE)
    return name


class LinuxArtifactUserPresence:
    """Re-authenticate the invoking account through PAM for one exact pending artifact action."""

    __slots__ = ("_authenticator", "_console")

    def __init__(
        self,
        *,
        _authenticator: ArtifactPasswordAuthenticator | None = None,
        _console: Callable[[], PresenceConsole] | None = None,
    ) -> None:
        self._authenticator = _authenticator
        self._console = TrustedForegroundConsole if _console is None else _console

    def verify_artifact_review(self, authority: ArtifactAuthority) -> None:
        if (
            sys.platform != "linux"
            or type(authority) is not ArtifactAuthority
            or authority.channel != "review_only"
            or authority.review_id is None
        ):
            raise RuntimeError(_UNAVAILABLE)

        def expire(_signum: int, _frame: object) -> None:
            raise _Deadline

        try:
            account = invoking_account()
            # Only the main thread may own SIGALRM; anything else is not the operator's CLI.
            previous = signal.signal(signal.SIGALRM, expire)
        except Exception as exc:
            raise RuntimeError(_UNAVAILABLE) from exc
        approved = False
        try:
            signal.setitimer(signal.ITIMER_REAL, _TIMEOUT_SECONDS)
            authenticator = (
                IsolatedPamAuthenticator() if self._authenticator is None else self._authenticator
            )
            with self._console() as console:
                console.write(
                    "FinishUP plugin_artifact_apply review\n"
                    f"  preview digest: {authority.target_digest}\n"
                    f"  pending review: {authority.review_id}\n"
                    f"Re-enter the operating-system password for account {account} to approve "
                    "this one action. Press Ctrl-C to cancel; nothing changes until it is "
                    "accepted.\n"
                )

                def read_password() -> bytearray:
                    return console.read_secret(f"Password for {account}: ", _PASSWORD_MAX_BYTES)

                approved = authenticator.authenticate(account, read_password)
                console.write("\n")
        except BaseException as exc:
            # Cancellation, EOF, deadline, missing PAM, console loss: all fail closed.
            raise RuntimeError(_UNAVAILABLE) from exc
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL if previous is None else previous)
        if approved is not True:
            raise RuntimeError(_UNAVAILABLE)
