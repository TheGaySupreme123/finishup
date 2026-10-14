from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

import finishup.cli.bootstrap as bootstrap
import finishup.cli.entry as entry
import finishup.cli.observe_hooks as observe_hooks
import finishup.config.paths as paths
import finishup.service.client as client_module
from finishup.ports.control import ServiceState, ServiceStatus


@pytest.fixture
def isolated_cli_modules() -> Iterator[None]:
    """Temporarily remove the full Typer graph without poisoning later test imports.

    The fast path must prove that ``finishup.cli.app`` is absent while it connects.  Restoring both
    ``sys.modules`` and the package attributes matters because another test may already hold a
    function imported from the original module; leaving a newly re-imported module attached to the
    package makes string-based monkeypatching target a different module instance.
    """

    package = sys.modules["finishup.cli"]
    module_names = ("finishup.cli.app", "finishup.cli.project")
    sentinel = object()
    saved_modules: dict[str, ModuleType | None] = {
        name: sys.modules.get(name) for name in module_names
    }
    saved_attributes: dict[str, object] = {
        name.rsplit(".", 1)[-1]: getattr(package, name.rsplit(".", 1)[-1], sentinel)
        for name in module_names
    }
    for name in module_names:
        sys.modules.pop(name, None)
        attribute = name.rsplit(".", 1)[-1]
        if hasattr(package, attribute):
            delattr(package, attribute)
    try:
        yield
    finally:
        for name, module in saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
        for attribute, value in saved_attributes.items():
            if value is sentinel:
                if hasattr(package, attribute):
                    delattr(package, attribute)
            else:
                setattr(package, attribute, value)


def test_cursor_pretool_import_or_handler_failure_stays_fail_open(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(**_kwargs: object) -> int:
        raise RuntimeError("private failure")

    monkeypatch.setattr(observe_hooks, "handle_cursor_observe", fail)
    assert entry._cursor_observe_fast_path(["--event", "preToolUse"]) == 0  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert capsys.readouterr().out == '{"permission":"allow"}\n'


def test_cursor_pretool_inner_handler_failure_is_emitted_once(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(**_kwargs: object) -> int:
        raise RuntimeError("private failure")

    monkeypatch.setattr(observe_hooks, "_handle_cursor_observe", fail)
    assert (
        entry._cursor_observe_fast_path(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            ["--event", "preToolUse"]
        )
        == 0
    )
    assert capsys.readouterr().out == '{"permission":"allow"}\n'


def test_observe_fast_path_propagates_handler_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exit_seven(**_kwargs: object) -> int:
        return 7

    monkeypatch.setattr(observe_hooks, "handle_observe", exit_seven)

    assert (
        entry._observe_fast_path(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            ["--event", "PostToolUse"]
        )
        == 7
    )


def test_observe_fast_path_degrades_handler_failure_to_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(**_kwargs: object) -> int:
        raise RuntimeError("boom")

    monkeypatch.setattr(observe_hooks, "handle_observe", fail)

    assert (
        entry._observe_fast_path(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            ["--event", "PostToolUse"]
        )
        == 0
    )


def test_service_status_fast_path_falls_through_for_help_and_unknown_options() -> None:
    assert (
        entry._service_status_fast_path(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            ["--help"]
        )
        is None
    )
    assert (
        entry._service_status_fast_path(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            ["--json", "--json"]
        )
        is None
    )


def test_service_status_fast_path_connects_before_loading_full_cli(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    isolated_cli_modules: None,
) -> None:
    del isolated_cli_modules
    closed = False
    status = ServiceStatus(
        protocol_version="1.0",
        service_version="0.1.0",
        service_instance_id="svc_00000000-0000-4000-8000-000000000001",
        service_generation="1",
        state=ServiceState.LOCKED,
        state_reason="vault_uninitialized",
        vault_mode="uninitialized",
        capabilities=("workflow",),
        session_monitor="unavailable",
    )

    class FakeClient:
        async def service_status(self) -> ServiceStatus:
            return status

        async def close(self) -> None:
            nonlocal closed
            closed = True

    async def connect(*_args: object, **_kwargs: object) -> FakeClient:
        assert "finishup.cli.app" not in sys.modules
        return FakeClient()

    monkeypatch.setattr(client_module, "connect_service", connect)

    assert (
        entry._service_status_fast_path(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            ["--json"]
        )
        == 0
    )
    assert closed
    assert "finishup.cli.app" not in sys.modules
    assert "finishup.cli.project" not in sys.modules
    payload = json.loads(capsys.readouterr().out)
    assert payload["service_version"] == "0.1.0"
    assert payload["state"] == "locked"


def test_service_status_fast_path_preserves_silent_service_guidance(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    isolated_cli_modules: None,
) -> None:
    del isolated_cli_modules
    root = tmp_path

    def state_dir(**_kwargs: object) -> Path:
        return root

    monkeypatch.setattr(paths, "state_dir", state_dir)

    async def refuse(*_args: object, **_kwargs: object) -> object:
        raise client_module._AcceptedServiceUnresponsive()  # pyright: ignore[reportPrivateUsage]

    monkeypatch.setattr(client_module, "connect_service", refuse)

    assert (
        entry._service_status_fast_path([])  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        == 20
    )
    assert "finishup.cli.app" not in sys.modules
    assert "finishup.cli.project" not in sys.modules
    captured = capsys.readouterr()
    assert "did not answer within 5 seconds" in captured.err
    assert "Do not run 'finishup service run'" in captured.err


def test_service_status_fast_path_bounds_rendering_failure_without_retry(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = 0

    class FakeClient:
        async def service_status(self) -> ServiceStatus:
            return ServiceStatus(
                protocol_version="1.0",
                service_version="0.1.0",
                service_instance_id="svc_00000000-0000-4000-8000-000000000001",
                service_generation="1",
                state=ServiceState.LOCKED,
                state_reason="vault_uninitialized",
                vault_mode="uninitialized",
                capabilities=(),
                session_monitor="unavailable",
            )

        async def close(self) -> None:
            return None

    async def connect(*_args: object, **_kwargs: object) -> FakeClient:
        nonlocal calls
        calls += 1
        return FakeClient()

    def broken_pipe(*_args: object, **_kwargs: object) -> None:
        raise BrokenPipeError

    monkeypatch.setattr(client_module, "connect_service", connect)
    monkeypatch.setattr(bootstrap, "human_or_json", broken_pipe)

    assert (
        entry._service_status_fast_path(["--json"])  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        == 70
    )
    assert calls == 1
    assert capsys.readouterr().err == "internal_error: the command could not be completed\n"


def test_claude_observe_fast_path_forwards_profile_and_entry_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_handler(**kwargs: object) -> int:
        captured.update(kwargs)
        return 7

    monkeypatch.setattr(entry, "_ENTRY_MONOTONIC", 12.5)
    monkeypatch.setattr(observe_hooks, "handle_claude_observe", fake_handler)

    assert (
        entry._claude_observe_fast_path(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            [
                "--workspace",
                "/project",
                "--event",
                "PostToolUse",
                "--observation-profile",
                "claude-code-ordinary-observation-v1",
            ]
        )
        == 7
    )
    assert captured == {
        "event_name": "PostToolUse",
        "workspace": "/project",
        "observation_profile": "claude-code-ordinary-observation-v1",
        "_entry_monotonic": 12.5,
    }


def test_cursor_observe_fast_path_forwards_profile_and_entry_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_handler(**kwargs: object) -> int:
        captured.update(kwargs)
        return 3

    monkeypatch.setattr(entry, "_ENTRY_MONOTONIC", 8.25)
    monkeypatch.setattr(observe_hooks, "handle_cursor_observe", fake_handler)

    assert (
        entry._cursor_observe_fast_path(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            [
                "--event",
                "postToolUse",
                "--workspace",
                ".",
                "--observation-profile",
                "cursor-ordinary-observation-v1",
            ]
        )
        == 3
    )
    assert captured == {
        "event_name": "postToolUse",
        "workspace": ".",
        "observation_profile": "cursor-ordinary-observation-v1",
        "_entry_monotonic": 8.25,
    }


@pytest.mark.parametrize(
    "arguments",
    [
        ["--event", "PostToolUse", "--event", "Stop"],
        ["--event", "PostToolUse", "--unknown", "value"],
        ["--event"],
        ["--help"],
    ],
)
def test_claude_fast_path_falls_through_for_non_exact_arguments(arguments: list[str]) -> None:
    assert (
        entry._claude_observe_fast_path(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            arguments
        )
        is None
    )


def test_main_dispatches_claude_before_loading_full_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["finishup", "hooks", "claude-observe", "--event", "Stop"])

    def fast_path(_arguments: list[str]) -> int:
        return 9

    monkeypatch.setattr(entry, "_claude_observe_fast_path", fast_path)

    with pytest.raises(SystemExit) as caught:
        entry.main()

    assert caught.value.code == 9


def test_native_windows_refuses_stateful_commands_with_a_bounded_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = entry._unsupported_platform_exit(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        ["setup", "status", "--json"], os_name="nt"
    )

    assert code == 20
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("unsupported_platform: ")
    assert "WSL 2" in captured.err
    assert "install-and-first-run.md#windows" in captured.err
    assert "internal_error" not in captured.err


@pytest.mark.parametrize(
    "arguments",
    [
        ["version"],
        ["version", "--json"],
        ["--version"],
        ["--help"],
        ["setup", "--help"],
        ["-h"],
    ],
)
def test_native_windows_still_answers_version_and_help(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        entry._unsupported_platform_exit(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            arguments, os_name="nt"
        )
        is None
    )
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("arguments", [[], ["setup", "status"], ["service", "run"]])
def test_posix_never_hits_the_platform_refusal(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        entry._unsupported_platform_exit(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            arguments, os_name="posix"
        )
        is None
    )
    assert capsys.readouterr().err == ""


def test_main_refuses_before_loading_the_full_cli_on_native_windows(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["finishup", "privacy", "show"])
    monkeypatch.setattr(entry.os, "name", "nt")

    def never() -> None:
        raise AssertionError("full CLI must not load on native Windows")

    monkeypatch.setattr(entry, "_run_full_cli", never)

    with pytest.raises(SystemExit) as caught:
        entry.main()

    assert caught.value.code == 20
    assert capsys.readouterr().err.startswith("unsupported_platform: ")


def test_main_falls_through_to_the_full_cli_on_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["finishup", "privacy", "show"])
    monkeypatch.setattr(entry.os, "name", "posix")
    calls: list[str] = []
    monkeypatch.setattr(entry, "_run_full_cli", lambda: calls.append("cli"))

    entry.main()

    assert calls == ["cli"]


def test_runtime_isolation_failure_does_not_emit_a_hook_allow(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from finishup.adapters import release_runtime

    def refuse(_arguments: list[str]) -> None:
        raise release_runtime.ReleaseRuntimeError("release_runtime_busy")

    monkeypatch.setattr(release_runtime, "enter_release_runtime", refuse)
    monkeypatch.setattr(
        sys, "argv", ["finishup", "hooks", "cursor-observe", "--event", "preToolUse"]
    )
    with pytest.raises(SystemExit) as error:
        entry.main()
    assert error.value.code == 20
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "package update is running" in captured.err


def test_runtime_cleanup_does_not_take_its_own_serving_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.adapters import release_runtime

    def unexpected(_arguments: list[str]) -> None:
        raise AssertionError("cleanup must not lease its own generation")

    monkeypatch.setattr(release_runtime, "enter_release_runtime", unexpected)
    monkeypatch.setattr(entry, "_run_full_cli", lambda: None)
    monkeypatch.setattr(sys, "argv", ["finishup", "upgrade", "--prune-runtimes"])
    entry.main()


@pytest.mark.parametrize(
    "os_errno, reason", [(13, "permission_denied"), (2, "file_missing"), (9999, "os_error")]
)
def test_runtime_os_failure_has_bounded_reason_without_private_text(
    os_errno: int, reason: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from finishup.adapters import release_runtime

    def refuse(_arguments: list[str]) -> None:
        raise OSError(os_errno, "PRIVATE_ERROR_CANARY", "PRIVATE_PATH_CANARY")

    monkeypatch.setattr(release_runtime, "enter_release_runtime", refuse)
    monkeypatch.setattr(sys, "argv", ["finishup", "service", "run"])
    with pytest.raises(SystemExit) as error:
        entry.main()
    assert error.value.code == 20
    captured = capsys.readouterr()
    assert captured.out == ""
    assert (
        captured.err
        == f"release_runtime_unavailable: {reason}; retry from the installed launcher.\n"
    )
    assert "PRIVATE" not in captured.err


@pytest.mark.parametrize("phase", ["snapshot", "lease", "exec"])
def test_runtime_io_phase_excludes_source_exception_text(
    phase: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from typing import Literal, cast

    from finishup.adapters import release_runtime

    def refuse(_arguments: list[str]) -> None:
        raise release_runtime.ReleaseRuntimeIOError(
            PermissionError(13, "PRIVATE_ERROR", "PRIVATE_PATH"),
            cast(Literal["snapshot", "lease", "exec"], phase),
        )

    monkeypatch.setattr(release_runtime, "enter_release_runtime", refuse)
    monkeypatch.setattr(sys, "argv", ["finishup", "service", "run"])
    with pytest.raises(SystemExit):
        entry.main()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"{phase}_permission_denied" in captured.err
    assert "PRIVATE" not in captured.err
