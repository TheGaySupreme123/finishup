"""Console entry point that fast-paths bounded commands past the typer graph.

Loading ``finishup.cli.app`` costs a substantial typer/pydantic/protocol-schema import that a Codex
hook never uses (#242). Only exact hook commands and the ordinary ``service status`` forms are
fast-pathed; everything else falls through to the full CLI unchanged, so usage errors and
``--help`` stay byte-identical.
"""

from __future__ import annotations

import errno
import os
import sys
import time
from collections.abc import Callable
from typing import Final

# Sampled before any finishup module resolves, so the hook can measure the import
# term it otherwise cannot see. Interpreter start itself is not portably
# measurable and is documented (~20 ms), never guessed.
_ENTRY_MONOTONIC: Final = time.monotonic()

__all__ = ["LEGACY_ALIAS_NOTICE", "UNSUPPORTED_PLATFORM_MESSAGE", "main"]

# FinishUP is POSIX-only: the service listens on an owner-only AF_UNIX socket, and every path,
# vault, and lock check compares ``st_uid`` against ``os.geteuid()``. On native Windows the path
# probe raised ``AttributeError`` inside the catch-all and every stateful command printed
# ``internal_error`` (issue #709). Refusing here names the real condition and the way out.
_NATIVE_WINDOWS: Final = "nt"
_PLATFORM_EXEMPT_COMMANDS: Final = frozenset({"version"})
_PLATFORM_EXEMPT_FLAGS: Final = frozenset({"--help", "-h", "--version"})
# ``service_unavailable`` exits 20 in ``finishup.cli.exits``: no FinishUP service can ever be reached
# from this process, so the exit matches the public code an absent service already carries.
_UNSUPPORTED_PLATFORM_EXIT: Final = 20
UNSUPPORTED_PLATFORM_MESSAGE: Final = (
    "unsupported_platform: FinishUP runs on macOS and Linux; native Windows is not supported.\n"
    "On Windows, install and run FinishUP inside WSL 2 (Ubuntu). Setup guide:\n"
    "  https://github.com/TheGaySupreme123/finishup/blob/main/docs/usage/install-and-first-run.md#windows"
)

# The deprecated ``yoetz`` alias (ADR-048) names its replacement once per interactive run. It is
# never printed where a machine reads the streams: hooks, MCP and service processes, ``--json``,
# or ``--version``, whose bare stdout released ``yoetz upgrade`` code parses.
LEGACY_ALIAS_NOTICE: Final = (
    "notice: 'yoetz' is now 'finishup'. For this release any finishup command also works as "
    "'yoetz' with the same subcommand, and 'yoetz upgrade' shows how to move; the alias will be "
    "removed in a later release. See "
    "https://github.com/TheGaySupreme123/finishup/blob/main/docs/usage/upgrading.md#upgrading-from-yoetz"
)
_LEGACY_ALIAS_QUIET_FLAGS: Final = frozenset({"--json", "--version"})


def _legacy_alias_notice(arguments: list[str]) -> None:
    """Print the alias deprecation notice to an interactive stderr only (ADR-048)."""

    if any(token in _LEGACY_ALIAS_QUIET_FLAGS for token in arguments):
        return
    if arguments[:1] == ["hooks"] or arguments[:2] in (["mcp", "serve"], ["service", "run"]):
        return
    from finishup.adapters.integrations.launcher import invoked_through_legacy_alias

    if not invoked_through_legacy_alias():
        return
    try:
        if sys.stderr is None or not sys.stderr.isatty():
            return
        sys.stderr.write(LEGACY_ALIAS_NOTICE + "\n")
        sys.stderr.flush()
    except OSError, ValueError:
        pass


def _service_status_fast_path(arguments: list[str]) -> int | None:
    """Connect before loading the full Typer command graph for exact status invocations."""

    if arguments not in ([], ["--json"]):
        return None

    import asyncio

    from finishup.cli.bootstrap import connect_cli_service, control_failure, human_or_json, stderr
    from finishup.ports.control import ControlError

    json_output = arguments == ["--json"]

    async def _request() -> object:
        client = await connect_cli_service()
        try:
            return await client.service_status()
        finally:
            await client.close()

    def _render(callback: Callable[[], object]) -> int:
        from typer import Exit as TyperExit

        try:
            result = callback()
        except TyperExit as error:
            return int(error.exit_code or 0)
        except KeyboardInterrupt:
            stderr("cancelled")
            return 130
        except Exception:
            stderr("internal_error: the command could not be completed")
            return 70
        return result if type(result) is int else 0

    try:
        status = asyncio.run(_request())
    except ControlError as error:
        return _render(lambda error=error: control_failure(error, json_output=json_output))
    except KeyboardInterrupt:
        stderr("cancelled")
        return 130
    except Exception:
        stderr("internal_error: the command could not be completed")
        return 70

    code = _render(lambda: human_or_json(status, json_output=json_output))
    if code == 0 and not json_output:
        from finishup.cli.service_installation import report_installation_naming

        # A Yoetz-era install used in place is named on stderr; stdout is unchanged (ADR-048).
        report_installation_naming(stderr)
    return code


def _observe_fast_path(arguments: list[str]) -> int | None:
    """Run ``hooks observe`` directly, or return None to fall through to typer.

    Any unrecognised token — ``--help``, an unknown flag, a repeated or
    value-less option, a missing ``--event`` — returns None. A mis-sniff would
    turn a user-facing usage error into a silent exit 0.
    """

    event: str | None = None
    workspace: str | None = None
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if index + 1 >= len(arguments):
            return None
        value = arguments[index + 1]
        if value.startswith("-"):
            return None
        if token == "--event" and event is None:
            event = value
        elif token == "--workspace" and workspace is None:
            workspace = value
        else:
            return None
        index += 2
    if event is None:
        return None
    try:
        from finishup.cli.observe_hooks import handle_codex_observe

        return handle_codex_observe(
            event_name=event,
            workspace=workspace,
            _entry_monotonic=_ENTRY_MONOTONIC,
        )
    except BaseException:
        # Same contract as the typer command: a hook never fails its host.
        try:
            from finishup.cli.hook_io import stdout_json

            stdout_json({})
        except BaseException:
            pass
    return 0


def _spool_fast_path(arguments: list[str]) -> int | None:
    """Run the legacy synchronous spool writer without loading typer."""

    event: str | None = None
    workspace: str | None = None
    index = 0
    while index < len(arguments):
        if index + 1 >= len(arguments):
            return None
        token, value = arguments[index], arguments[index + 1]
        if value.startswith("-"):
            return None
        if token == "--event" and event is None:
            event = value
        elif token == "--workspace" and workspace is None:
            workspace = value
        else:
            return None
        index += 2
    if event is None or workspace is None:
        return None
    try:
        from finishup.cli.observe_hooks import handle_spool

        return handle_spool(
            event_name=event,
            workspace=workspace,
            _entry_monotonic=_ENTRY_MONOTONIC,
        )
    except BaseException:
        try:
            from finishup.cli.hook_io import stdout_json

            stdout_json({})
        except BaseException:
            pass
    return 0


def _cursor_observe_fast_path(arguments: list[str]) -> int | None:
    """Run ``hooks cursor-observe`` without loading typer."""

    event: str | None = None
    workspace: str | None = None
    observation_profile: str | None = None
    index = 0
    while index < len(arguments):
        if index + 1 >= len(arguments):
            return None
        token, value = arguments[index], arguments[index + 1]
        if value.startswith("-"):
            return None
        if token == "--event" and event is None:
            event = value
        elif token == "--workspace" and workspace is None:
            workspace = value
        elif token == "--observation-profile" and observation_profile is None:
            observation_profile = value
        else:
            return None
        index += 2
    if event is None:
        return None
    try:
        from finishup.cli.observe_hooks import handle_cursor_observe

        return handle_cursor_observe(
            event_name=event,
            workspace=workspace,
            observation_profile=observation_profile,
            _entry_monotonic=_ENTRY_MONOTONIC,
        )
    except BaseException:
        try:
            from finishup.cli.hook_io import cursor_context_output, stdout_json

            stdout_json(cursor_context_output(event, ""))
        except BaseException:
            pass
    return 0


def _claude_observe_fast_path(arguments: list[str]) -> int | None:
    """Run ``hooks claude-observe`` without loading the full Typer graph.

    Claude's ordinary native profile fires for every generic tool event.  The
    command therefore must stay on the same lightweight path as the Codex and
    Cursor ingress commands; falling through to ``cli.app`` makes a fresh hook
    process spend most of its host timeout importing unused command modules.
    """

    event: str | None = None
    workspace: str | None = None
    observation_profile: str | None = None
    index = 0
    while index < len(arguments):
        if index + 1 >= len(arguments):
            return None
        token, value = arguments[index], arguments[index + 1]
        if value.startswith("-"):
            return None
        if token == "--event" and event is None:
            event = value
        elif token == "--workspace" and workspace is None:
            workspace = value
        elif token == "--observation-profile" and observation_profile is None:
            observation_profile = value
        else:
            return None
        index += 2
    if event is None:
        return None
    try:
        from finishup.cli.observe_hooks import handle_claude_observe

        return handle_claude_observe(
            event_name=event,
            workspace=workspace,
            observation_profile=observation_profile,
            _entry_monotonic=_ENTRY_MONOTONIC,
        )
    except BaseException:
        try:
            from finishup.cli.hook_io import stdout_json

            stdout_json({})
        except BaseException:
            pass
    return 0


def _unsupported_platform_exit(arguments: list[str], *, os_name: str | None = None) -> int | None:
    """Return the bounded exit for native Windows, or None where FinishUP can run.

    ``version``, ``--version``, and ``--help`` stay available so a user or agent can still see what
    was installed; everything else would only reach ``internal_error``.
    """

    if (os.name if os_name is None else os_name) != _NATIVE_WINDOWS:
        return None
    if arguments and arguments[0] in _PLATFORM_EXEMPT_COMMANDS:
        return None
    if any(token in _PLATFORM_EXEMPT_FLAGS for token in arguments):
        return None
    try:
        sys.stderr.write(UNSUPPORTED_PLATFORM_MESSAGE + "\n")
        sys.stderr.flush()
    except OSError:
        pass
    return _UNSUPPORTED_PLATFORM_EXIT


def _run_full_cli() -> None:
    """Load the typer graph and dispatch; split out so tests can prove it never loads on Windows."""

    from finishup.cli.app import main as app_main

    app_main()


def main() -> None:
    """Installed console entry point."""

    argv = sys.argv[1:]
    # The static cue has its own bounded resource fallback and must survive unavailable state
    # or installation runtime setup. It never serves work, asserts readiness or decides access.
    if (
        len(argv) == 4
        and argv[:3] == ["hooks", "startup-context", "--host"]
        and argv[3] in {"claude", "cursor"}
    ):
        from finishup.cli.startup_context import handle_startup_context

        raise SystemExit(handle_startup_context(host="claude" if argv[3] == "claude" else "cursor"))
    if (
        os.name != "nt"
        and (
            argv[:2] in (["mcp", "serve"], ["service", "run"])
            or argv[:1] in (["hooks"], ["upgrade"])
        )
        and not any(token in {"--help", "-h"} for token in argv)
        and "--prune-runtimes" not in argv
    ):
        from finishup.adapters.release_runtime import (
            ReleaseRuntimeError,
            ReleaseRuntimeIOError,
            enter_release_runtime,
        )

        try:
            enter_release_runtime(argv)
        except ReleaseRuntimeError as error:
            message = {
                "release_runtime_busy": "A package update is running. Retry after it finishes.",
                "release_runtime_changed_retry": "The package changed during startup. Retry from the installed launcher.",
                "release_runtime_external_link": "This runtime links to editable or external package files. Use a regular installed FinishUP package.",
            }.get(
                str(error),
                "The retained runtime could not be verified. Repair this FinishUP installation.",
            )
            sys.stderr.write(f"release_runtime_unavailable: {message}\n")
            raise SystemExit(20) from None
        except OSError as error:
            # Closed OS categories only: exception text and filenames may contain private paths.
            reason = {
                errno.EACCES: "permission_denied",
                errno.EPERM: "operation_not_permitted",
                errno.ENOENT: "file_missing",
                errno.ENAMETOOLONG: "path_too_long",
                errno.EMFILE: "process_file_limit",
                errno.ENFILE: "system_file_limit",
                errno.ENOSPC: "storage_full",
                errno.ELOOP: "symlink_loop",
                errno.ENOEXEC: "executable_format",
                errno.ETXTBSY: "executable_busy",
            }.get(error.errno or 0, "os_error")
            phase = f"{error.phase}_" if isinstance(error, ReleaseRuntimeIOError) else ""
            sys.stderr.write(
                f"release_runtime_unavailable: {phase}{reason}; retry from the installed launcher.\n"
            )
            raise SystemExit(20) from None
    if (
        len(argv) == 6
        and argv[:3] == ["hooks", "startup-gate", "--host"]
        and argv[3] in {"claude", "cursor"}
        and argv[4] == "--event"
    ):
        from finishup.cli.startup_gate import handle_startup_gate

        raise SystemExit(
            handle_startup_gate(host="claude" if argv[3] == "claude" else "cursor", event=argv[5])
        )
    if len(argv) >= 2 and argv[0] == "hooks" and argv[1] == "observe":
        code = _observe_fast_path(argv[2:])
        if code is not None:
            raise SystemExit(code)
    if len(argv) >= 2 and argv[0] == "hooks" and argv[1] == "cursor-observe":
        code = _cursor_observe_fast_path(argv[2:])
        if code is not None:
            raise SystemExit(code)
    if len(argv) >= 2 and argv[0] == "hooks" and argv[1] == "claude-observe":
        code = _claude_observe_fast_path(argv[2:])
        if code is not None:
            raise SystemExit(code)
    if len(argv) >= 2 and argv[0] == "hooks" and argv[1] == "spool":
        code = _spool_fast_path(argv[2:])
        if code is not None:
            raise SystemExit(code)
    # After the release-runtime handoff, so a re-executed process prints the notice only once.
    _legacy_alias_notice(argv)
    code = _unsupported_platform_exit(argv)
    if code is not None:
        raise SystemExit(code)
    if len(argv) >= 2 and argv[0] == "service" and argv[1] == "status":
        code = _service_status_fast_path(argv[2:])
        if code is not None:
            raise SystemExit(code)
    _run_full_cli()
