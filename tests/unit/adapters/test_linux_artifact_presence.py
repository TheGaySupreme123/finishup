from __future__ import annotations

import ctypes
import io
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace, TracebackType
from typing import Self

import pytest

from finishup.adapters.integrations import linux_artifact_presence as module
from finishup.adapters.integrations.linux_artifact_presence import (
    ConversationState,
    IsolatedPamAuthenticator,
    LinuxArtifactUserPresence,
    PamMessage,
    PamResponse,
    ResponseAllocator,
    converse,
)
from finishup.cli.trusted_console import TrustedConsoleError
from finishup.ports.plugin_artifacts import ArtifactAuthority

_DIGEST = "sha256:" + "a" * 64
_REVIEW_ID = "b" * 64
_MODULE = "finishup.adapters.integrations.linux_artifact_presence"


def _authority() -> ArtifactAuthority:
    return ArtifactAuthority("review_only", _DIGEST, _REVIEW_ID)


class _Console:
    """Scripted stand-in for the verified foreground console."""

    def __init__(
        self,
        *,
        secret: bytes | None = b"correct horse",
        open_error: str | None = None,
        read_error: str | None = None,
    ) -> None:
        self.secret = secret
        self.open_error = open_error
        self.read_error = read_error
        self.written: list[str] = []
        self.prompts: list[str] = []
        self.opened = 0
        self.closed = 0

    def __call__(self) -> Self:
        return self

    def __enter__(self) -> Self:
        if self.open_error is not None:
            raise TrustedConsoleError(self.open_error)
        self.opened += 1
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.closed += 1

    def write(self, value: str) -> None:
        self.written.append(value)

    def read_secret(self, prompt: str, maximum: int) -> bytearray:
        self.prompts.append(prompt)
        assert maximum > 0
        if self.read_error is not None:
            raise TrustedConsoleError(self.read_error)
        assert self.secret is not None
        return bytearray(self.secret)


class _Authenticator:
    """Scripted operating-system verifier that consumes the console password like PAM."""

    def __init__(self, expected: bytes, *, error: BaseException | None = None) -> None:
        self.expected = expected
        self.error = error
        self.accounts: list[str] = []
        self.results: list[bool] = []

    def authenticate(self, account: str, read_password: Callable[[], bytearray]) -> bool:
        self.accounts.append(account)
        if self.error is not None:
            raise self.error
        secret = read_password()
        try:
            result = bytes(secret) == self.expected
        finally:
            for index in range(len(secret)):
                secret[index] = 0
        self.results.append(result)
        return result


@pytest.fixture
def linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(f"{_MODULE}.sys.platform", "linux")
    monkeypatch.setattr(f"{_MODULE}.invoking_account", lambda: "operator")


def _previous_alarm() -> object:
    return signal.getsignal(signal.SIGALRM)


def test_linux_presence_reauthenticates_the_invoking_account_through_the_console(
    linux: None,
) -> None:
    console = _Console()
    authenticator = _Authenticator(b"correct horse")
    before = _previous_alarm()

    LinuxArtifactUserPresence(
        _authenticator=authenticator, _console=console
    ).verify_artifact_review(_authority())

    assert authenticator.accounts == ["operator"]
    assert authenticator.results == [True]
    assert console.opened == 1 and console.closed == 1
    banner = "".join(console.written)
    assert "plugin_artifact_apply" in banner
    assert _DIGEST in banner
    assert _REVIEW_ID in banner
    assert "operator" in banner
    assert console.prompts == ["Password for operator: "]
    assert signal.getsignal(signal.SIGALRM) is before
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_linux_presence_wrong_password_fails_closed(linux: None) -> None:
    console = _Console(secret=b"wrong")
    authenticator = _Authenticator(b"correct horse")

    with pytest.raises(RuntimeError, match="human_authority_unavailable"):
        LinuxArtifactUserPresence(
            _authenticator=authenticator, _console=console
        ).verify_artifact_review(_authority())
    assert authenticator.results == [False]


@pytest.mark.parametrize("reason", ["cancelled", "eof", "empty_input", "interrupted"])
def test_linux_presence_console_cancellation_fails_closed(linux: None, reason: str) -> None:
    console = _Console(read_error=reason)
    authenticator = _Authenticator(b"correct horse")

    with pytest.raises(RuntimeError, match="human_authority_unavailable"):
        LinuxArtifactUserPresence(
            _authenticator=authenticator, _console=console
        ).verify_artifact_review(_authority())
    assert authenticator.results == []
    assert console.closed == 1


def test_linux_presence_requires_the_trusted_foreground_console(linux: None) -> None:
    console = _Console(open_error="trusted_console_required")
    authenticator = _Authenticator(b"correct horse")

    with pytest.raises(RuntimeError, match="human_authority_unavailable"):
        LinuxArtifactUserPresence(
            _authenticator=authenticator, _console=console
        ).verify_artifact_review(_authority())
    assert authenticator.accounts == []


@pytest.mark.parametrize(
    "error", [OSError("libpam.so.0: cannot open shared object file"), RuntimeError("pam_start")]
)
def test_linux_presence_unavailable_pam_fails_closed(linux: None, error: BaseException) -> None:
    console = _Console()
    authenticator = _Authenticator(b"correct horse", error=error)

    with pytest.raises(RuntimeError, match="human_authority_unavailable") as caught:
        LinuxArtifactUserPresence(
            _authenticator=authenticator, _console=console
        ).verify_artifact_review(_authority())
    assert caught.value.__cause__ is error


def test_linux_presence_deadline_fails_closed_and_restores_the_alarm(
    linux: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    console = _Console()
    before = _previous_alarm()

    class _Stalled:
        def authenticate(self, account: str, read_password: Callable[[], bytearray]) -> bool:
            # Deliver the actual alarm without waiting for wall time to infer the outcome.
            signal.raise_signal(signal.SIGALRM)
            return True

    started = time.monotonic()
    with pytest.raises(RuntimeError, match="human_authority_unavailable"):
        LinuxArtifactUserPresence(
            _authenticator=_Stalled(), _console=console
        ).verify_artifact_review(_authority())
    assert time.monotonic() - started < 4
    assert signal.getsignal(signal.SIGALRM) is before
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_linux_presence_refuses_off_linux_before_opening_the_console(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(f"{_MODULE}.sys.platform", "darwin")
    console = _Console()
    authenticator = _Authenticator(b"correct horse")

    with pytest.raises(RuntimeError, match="human_authority_unavailable"):
        LinuxArtifactUserPresence(
            _authenticator=authenticator, _console=console
        ).verify_artifact_review(_authority())
    assert console.opened == 0
    assert authenticator.accounts == []


def test_linux_presence_refuses_setup_composition_authority(linux: None) -> None:
    console = _Console()
    authenticator = _Authenticator(b"correct horse")

    with pytest.raises(RuntimeError, match="human_authority_unavailable"):
        LinuxArtifactUserPresence(
            _authenticator=authenticator, _console=console
        ).verify_artifact_review(ArtifactAuthority("setup_composition", _DIGEST))
    assert console.opened == 0


@pytest.mark.parametrize("name", ["", "with space", "non\x00printable", "ünïcode", "x" * 257])
def test_linux_presence_rejects_an_unusable_account_name(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    class _Entry:
        pw_name = name

    def getpwuid(_uid: int) -> _Entry:
        return _Entry()

    monkeypatch.setattr(f"{_MODULE}.sys.platform", "linux")
    monkeypatch.setattr("pwd.getpwuid", getpwuid)
    console = _Console()

    with pytest.raises(RuntimeError, match="human_authority_unavailable"):
        LinuxArtifactUserPresence(
            _authenticator=_Authenticator(b"x"), _console=console
        ).verify_artifact_review(_authority())
    assert console.opened == 0


def _messages(*styles: int):  # noqa: ANN202 - inferred ctypes array type
    keep = [PamMessage(style, b"Password: ") for style in styles]
    array = (ctypes.POINTER(PamMessage) * len(keep))(*(ctypes.pointer(item) for item in keep))
    return array, keep


def test_pam_conversation_answers_exactly_one_hidden_prompt_and_owns_the_memory() -> None:
    allocator = ResponseAllocator(ctypes.CDLL(None))
    state = ConversationState()
    secret = bytearray(b"correct horse")
    messages, _keep = _messages(4, 1, 3)
    out = ctypes.c_void_p()

    result = converse(
        allocator,
        state,
        lambda: secret,
        3,
        ctypes.addressof(messages),
        ctypes.addressof(out),
    )

    assert result == 0
    assert state.prompted == 1 and state.failed is False
    assert bytes(secret) == b"\x00" * len(b"correct horse")
    assert out.value
    answers = ctypes.cast(out.value, ctypes.POINTER(PamResponse))
    assert answers[0].resp is None and answers[2].resp is None
    assert answers[1].resp is not None
    assert ctypes.string_at(answers[1].resp) == b"correct horse"
    assert answers[1].resp_retcode == 0
    allocator.release(out.value, 3)


@pytest.mark.parametrize(
    ("styles", "count"),
    [((2,), 1), ((1, 1), 2), ((99,), 1), ((), 0)],
)
def test_pam_conversation_refuses_echoed_repeated_or_unknown_prompts(
    styles: tuple[int, ...], count: int
) -> None:
    allocator = ResponseAllocator(ctypes.CDLL(None))
    state = ConversationState()
    reads = 0

    def read_password() -> bytearray:
        nonlocal reads
        reads += 1
        return bytearray(b"secret")

    messages, _keep = _messages(*styles) if styles else _messages(1)
    out = ctypes.c_void_p()

    result = converse(
        allocator, state, read_password, count, ctypes.addressof(messages), ctypes.addressof(out)
    )

    assert result == 19
    assert state.failed is True
    assert out.value is None
    assert reads <= 1


def test_pam_conversation_records_console_failure_without_crossing_into_c() -> None:
    allocator = ResponseAllocator(ctypes.CDLL(None))
    state = ConversationState()

    def read_password() -> bytearray:
        raise TrustedConsoleError("cancelled")

    messages, _keep = _messages(1)
    out = ctypes.c_void_p()

    assert (
        converse(
            allocator, state, read_password, 1, ctypes.addressof(messages), ctypes.addressof(out)
        )
        == 19
    )
    assert state.failed is True
    assert out.value is None


def _libpam_available() -> bool:
    try:
        ctypes.CDLL("libpam.so.0")
    except OSError:
        return False
    return True


@pytest.mark.skipif(not _libpam_available(), reason="Linux-PAM is not installed on this host")
def test_real_pam_rejects_a_wrong_password_for_the_invoking_account() -> None:
    account = module.invoking_account()
    prompts = 0

    def read_password() -> bytearray:
        nonlocal prompts
        prompts += 1
        return bytearray(b"not-the-account-password-" + str(time.time_ns()).encode())

    assert IsolatedPamAuthenticator().authenticate(account, read_password) is False
    assert prompts <= 1


@pytest.mark.parametrize("returncode", [0, 1])
def test_isolated_pam_uses_only_a_pipe_for_the_secret(
    monkeypatch: pytest.MonkeyPatch, returncode: int
) -> None:
    secret = bytearray(b"test-password")

    class Worker:
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            self.returncode = returncode
            assert all("test-password" not in arg for arg in argv)
            assert argv[-1] == "operator"
            assert argv[1:3] == ["-I", "-c"]
            assert kwargs["stdin"] == subprocess.PIPE
            assert kwargs["stdout"] == subprocess.DEVNULL
            assert kwargs["stderr"] == subprocess.DEVNULL

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def communicate(self, *, input: bytearray, timeout: float) -> None:
            assert input is secret
            assert timeout == 130

        def poll(self) -> int:
            return self.returncode

        def wait(self) -> int:
            return self.returncode

    monkeypatch.setattr(module.subprocess, "Popen", Worker)
    assert IsolatedPamAuthenticator().authenticate("operator", lambda: secret) is (returncode == 0)
    assert secret == bytearray(len(b"test-password"))


@pytest.mark.parametrize("error", [subprocess.TimeoutExpired("worker", 130), KeyboardInterrupt()])
def test_isolated_pam_kills_and_reaps_worker_on_timeout_or_cancellation(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    secret = bytearray(b"test-password")
    cleanup: list[str] = []

    class Worker:
        returncode = None

        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            assert cleanup == ["kill", "wait"]

        def communicate(self, **kwargs: object) -> None:
            raise error

        def poll(self) -> None:
            return None

        def kill(self) -> None:
            cleanup.append("kill")

        def wait(self) -> int:
            cleanup.append("wait")
            return -9

    monkeypatch.setattr(module.subprocess, "Popen", Worker)
    with pytest.raises(type(error)):
        IsolatedPamAuthenticator().authenticate("operator", lambda: secret)
    assert cleanup == ["kill", "wait"]
    assert secret == bytearray(len(b"test-password"))


@pytest.mark.parametrize("raw", [b"", b"secret\x00suffix", b"x" * 1025])
def test_isolated_pam_refuses_unrepresentable_passwords_before_launch(
    monkeypatch: pytest.MonkeyPatch, raw: bytes
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("invalid password must not reach PAM")

    monkeypatch.setattr(module.subprocess, "Popen", forbidden)
    secret = bytearray(raw)
    assert IsolatedPamAuthenticator().authenticate("operator", lambda: secret) is False
    assert secret == bytearray(len(raw))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX PAM worker lifecycle")
def test_stalled_worker_is_actually_terminated_and_reaped(monkeypatch: pytest.MonkeyPatch) -> None:
    real_popen = subprocess.Popen
    children: list[subprocess.Popen[bytes]] = []

    def spawn(argv: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
        child = real_popen(
            [sys.executable, "-c", "import signal; signal.pause()"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        children.append(child)
        return child

    monkeypatch.setattr(module.subprocess, "Popen", spawn)
    monkeypatch.setattr(module, "_TIMEOUT_SECONDS", 0.1)
    secret = bytearray(b"synthetic-test-password")
    with pytest.raises(subprocess.TimeoutExpired):
        IsolatedPamAuthenticator().authenticate("operator", lambda: secret)
    assert len(children) == 1
    assert children[0].returncode is not None
    assert children[0].returncode < 0
    assert secret == bytearray(len(b"synthetic-test-password"))


@pytest.mark.parametrize("raw", [b"synthetic-password", b"", b"x" * 1025, b"prefix\x00suffix"])
def test_pam_worker_bounds_pipe_ingress_and_wipes_it(
    linux: None, monkeypatch: pytest.MonkeyPatch, raw: bytes
) -> None:
    observed: list[bytearray] = []

    class Pam:
        def authenticate(self, account: str, read_password: Callable[[], bytearray]) -> bool:
            assert account == "operator"
            secret = read_password()
            assert secret == b"synthetic-password"
            observed.append(secret)
            return True

    monkeypatch.setattr(module.sys, "argv", ["-c", "operator"])
    monkeypatch.setattr(module.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.setattr(module, "LinuxPamAuthenticator", Pam)
    expected = raw == b"synthetic-password"
    assert module.pam_worker() == (0 if expected else 1)
    assert bool(observed) is expected
    assert all(value == bytearray(len(value)) for value in observed)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX PAM worker lifecycle")
def test_pam_worker_does_not_import_workspace_or_pythonpath_modules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = tmp_path / "imported"
    (tmp_path / "finishup.py").write_text(
        "from pathlib import Path; Path(" + repr(str(marker)) + ").touch()\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    # The account is deliberately not the invoking account, so no real authentication runs.
    assert (
        IsolatedPamAuthenticator().authenticate(
            "not-the-invoking-account", lambda: bytearray(b"synthetic-password")
        )
        is False
    )
    assert not marker.exists()
