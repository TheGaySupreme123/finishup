"""Portable trusted foreground-console boundary."""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import pytest

from finishup.cli import trusted_console
from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole


@pytest.mark.skipif(os.name == "nt", reason="POSIX terminal checks are unavailable")
def test_posix_redirected_stdin_fails_before_open() -> None:
    adapter = trusted_console._PosixConsoleAdapter()  # pyright: ignore[reportPrivateUsage]
    with (
        patch("finishup.cli.trusted_console.os.isatty", return_value=False),
        patch("finishup.cli.trusted_console.os.open") as opened,
    ):
        with pytest.raises(TrustedConsoleError) as exc:
            adapter.open()
    assert exc.value.reason == "trusted_console_required"
    opened.assert_not_called()


@pytest.mark.skipif(os.name == "nt", reason="foreground-pgrp checks are POSIX-only")
def test_posix_background_or_mismatched_terminal_fails_and_closes() -> None:
    adapter = trusted_console._PosixConsoleAdapter()  # pyright: ignore[reportPrivateUsage]
    terminal = SimpleNamespace(st_rdev=10)
    with (
        patch("finishup.cli.trusted_console.os.isatty", return_value=True),
        patch("finishup.cli.trusted_console.os.open", return_value=9),
        patch("finishup.cli.trusted_console.os.fstat", return_value=terminal),
        patch("finishup.cli.trusted_console.os.tcgetpgrp", return_value=777),
        patch("finishup.cli.trusted_console.os.getpgrp", return_value=778),
        patch("finishup.cli.trusted_console.os.close") as closed,
    ):
        with pytest.raises(TrustedConsoleError) as exc:
            adapter.open()
    assert exc.value.reason == "trusted_console_required"
    closed.assert_called_once_with(9)


@pytest.mark.skipif(os.name == "nt", reason="POSIX terminal checks are unavailable")
def test_posix_ambiguous_terminal_error_is_bounded_and_closes() -> None:
    adapter = trusted_console._PosixConsoleAdapter()  # pyright: ignore[reportPrivateUsage]
    with (
        patch("finishup.cli.trusted_console.os.isatty", return_value=True),
        patch("finishup.cli.trusted_console.os.open", return_value=9),
        patch("finishup.cli.trusted_console.os.fstat", side_effect=OSError("private detail")),
        patch("finishup.cli.trusted_console.os.close") as closed,
    ):
        with pytest.raises(TrustedConsoleError) as exc:
            adapter.open()
    assert exc.value.reason == "trusted_console_required"
    closed.assert_called_once_with(9)


@pytest.mark.skipif(os.name == "nt", reason="POSIX terminal checks are unavailable")
def test_posix_empty_line_is_rejected() -> None:
    adapter = trusted_console._PosixConsoleAdapter()  # pyright: ignore[reportPrivateUsage]
    adapter._fd = 9  # pyright: ignore[reportPrivateUsage]

    def newline(_fd: int, buffers: list[memoryview]) -> int:
        buffers[0][0] = 10
        return 1

    with (
        patch("finishup.cli.trusted_console._PosixConsoleAdapter.write"),
        patch("finishup.cli.trusted_console.os.readv", side_effect=newline),
    ):
        with pytest.raises(TrustedConsoleError) as exc:
            adapter.read_line("Secret: ", 64, hidden=False)
    assert exc.value.reason == "empty_input"


@pytest.mark.skipif(os.name == "nt", reason="POSIX terminal checks are unavailable")
def test_posix_eof_is_distinct_from_empty_input() -> None:
    adapter = trusted_console._PosixConsoleAdapter()  # pyright: ignore[reportPrivateUsage]
    adapter._fd = 9  # pyright: ignore[reportPrivateUsage]

    with (
        patch("finishup.cli.trusted_console._PosixConsoleAdapter.write"),
        patch("finishup.cli.trusted_console.os.readv", return_value=0),
    ):
        with pytest.raises(TrustedConsoleError) as exc:
            adapter.read_line("Secret: ", 64, hidden=False)
    assert exc.value.reason == "eof"


@pytest.mark.skipif(os.name == "nt", reason="POSIX terminal checks are unavailable")
def test_posix_hidden_input_renders_live_masks_and_erases_on_backspace() -> None:
    import termios

    adapter = trusted_console._PosixConsoleAdapter()  # pyright: ignore[reportPrivateUsage]
    adapter._fd = 9  # pyright: ignore[reportPrivateUsage]
    incoming = iter(b"abc\x7fd\n")
    writes: list[str] = []
    attributes: list[int | list[bytes]] = [
        0,
        0,
        0,
        termios.ECHO | termios.ICANON,
        0,
        0,
        [],
    ]

    def read_one(_fd: int, buffers: list[memoryview]) -> int:
        buffers[0][0] = next(incoming)
        return 1

    with (
        patch("finishup.cli.trusted_console._PosixConsoleAdapter.write", side_effect=writes.append),
        patch("finishup.cli.trusted_console.os.readv", side_effect=read_one),
        patch("termios.tcgetattr", return_value=attributes),
        patch("termios.tcsetattr") as set_attributes,
    ):
        secret = adapter.read_line("Secret: ", 64, hidden=True)

    assert secret == bytearray(b"abd")
    assert writes == ["Secret: ", "*", "*", "*", "\b \b", "*", "\n"]
    changed = set_attributes.call_args_list[0].args[2]
    assert cast(int, changed[3]) & (termios.ECHO | termios.ICANON) == 0
    assert set_attributes.call_args_list[-1].args[2] is attributes


class _WindowsApi:
    def __init__(
        self,
        *,
        standard_console: bool = True,
        input_console: bool = True,
        output_console: bool = True,
        attached: bool = True,
    ) -> None:
        self.standard_console = standard_console
        self.input_console = input_console
        self.output_console = output_console
        self.attached = attached
        self.closed: list[int] = []
        self.hidden_reads: list[bool] = []
        self.writes: list[str] = []
        self.secret_writes: list[bytes] = []

    def open_input(self) -> int:
        return 101

    def open_output(self) -> int:
        return 202

    def is_console(self, handle: int) -> bool:
        return self.input_console if handle == 101 else self.output_console

    def standard_handles_are_console(self) -> bool:
        return self.standard_console

    def attached_process_ids(self) -> tuple[int, ...]:
        return (os.getpid(),) if self.attached else (os.getpid() + 1,)

    def write(self, handle: int, value: str) -> None:
        del handle
        self.writes.append(value)

    def write_secret(self, handle: int, value: memoryview) -> None:
        del handle
        self.secret_writes.append(bytes(value))

    def read_line(
        self, input_handle: int, output_handle: int, maximum: int, *, hidden: bool
    ) -> bytearray:
        del input_handle, maximum
        self.hidden_reads.append(hidden)
        if hidden:
            self.write(output_handle, "******")
        return bytearray(b"secret")

    def close(self, handle: int) -> None:
        self.closed.append(handle)


@pytest.mark.parametrize(
    ("overrides", "opened"),
    [
        ({"standard_console": False}, False),
        ({"input_console": False}, True),
        ({"output_console": False}, True),
        ({"attached": False}, True),
    ],
)
def test_windows_invalid_or_redirected_console_fails_closed(
    overrides: dict[str, bool],
    opened: bool,
) -> None:
    api = _WindowsApi(**overrides)
    adapter = trusted_console._WindowsConsoleAdapter(api)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(TrustedConsoleError) as exc:
        adapter.open()
    assert exc.value.reason == "trusted_console_required"
    assert bool(api.closed) is opened


def test_windows_reads_secrets_with_masked_feedback_through_console_api() -> None:
    api = _WindowsApi()
    adapter = trusted_console._WindowsConsoleAdapter(api)  # pyright: ignore[reportPrivateUsage]
    adapter.open()
    try:
        secret = adapter.read_line("Secret: ", 64, hidden=True)
    finally:
        adapter.close()
    assert secret == bytearray(b"secret")
    assert api.hidden_reads == [True]
    assert api.writes == ["Secret: ", "******", "\n"]
    assert api.closed == [202, 101]


def test_windows_writes_generated_code_through_mutable_secret_api() -> None:
    api = _WindowsApi()
    adapter = trusted_console._WindowsConsoleAdapter(api)  # pyright: ignore[reportPrivateUsage]
    source = bytearray(b"YRK1-TEST")
    adapter.open()
    try:
        view = memoryview(source)
        try:
            adapter.write_secret(view)
        finally:
            view.release()
    finally:
        adapter.close()
    source[:] = b"\x00" * len(source)
    assert api.secret_writes == [b"YRK1-TEST"]
    assert source == bytearray(b"\x00" * len(source))


def test_windows_empty_input_is_distinct_and_bounded() -> None:
    api = _WindowsApi()
    api.read_line = lambda *_args, **_kwargs: bytearray()  # type: ignore[method-assign]
    adapter = trusted_console._WindowsConsoleAdapter(api)  # pyright: ignore[reportPrivateUsage]
    adapter.open()
    try:
        with pytest.raises(TrustedConsoleError) as exc:
            adapter.read_line("Secret: ", 64, hidden=True)
    finally:
        adapter.close()
    assert exc.value.reason == "empty_input"


def test_windows_eof_reason_is_not_collapsed() -> None:
    api = _WindowsApi()

    def eof(*_args: object, **_kwargs: object) -> bytearray:
        raise TrustedConsoleError("eof")

    api.read_line = eof  # type: ignore[method-assign]
    adapter = trusted_console._WindowsConsoleAdapter(api)  # pyright: ignore[reportPrivateUsage]
    adapter.open()
    try:
        with pytest.raises(TrustedConsoleError) as exc:
            adapter.read_line("Secret: ", 64, hidden=True)
    finally:
        adapter.close()
    assert exc.value.reason == "eof"


def test_windows_ambiguous_console_error_is_bounded() -> None:
    api = _WindowsApi()

    def fail() -> bool:
        raise RuntimeError("private detail")

    api.standard_handles_are_console = fail
    adapter = trusted_console._WindowsConsoleAdapter(api)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(TrustedConsoleError) as exc:
        adapter.open()
    assert exc.value.reason == "trusted_console_required"
    assert api.closed == []


def test_public_boundary_uses_platform_adapter_without_injection() -> None:
    fake = _WindowsApi()
    adapter = trusted_console._WindowsConsoleAdapter(fake)  # pyright: ignore[reportPrivateUsage]
    with patch("finishup.cli.trusted_console._new_adapter", return_value=adapter):
        with TrustedForegroundConsole() as console:
            assert console.read_secret("Secret: ", 64) == bytearray(b"secret")


def test_windows_ctypes_adapter_refuses_non_windows_host() -> None:
    if os.name == "nt":
        pytest.skip("non-Windows refusal is not applicable")
    with pytest.raises(TrustedConsoleError) as exc:
        trusted_console._CtypesWindowsConsoleApi()  # pyright: ignore[reportPrivateUsage]
    assert exc.value.reason == "trusted_console_required"
