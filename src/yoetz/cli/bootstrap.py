"""Lightweight CLI bootstrap, rendering, and control-error helpers.

The console entry point uses this module for the exact ``service status`` forms before loading
the full Typer command graph.  The ordinary CLI imports the same helpers so the fast path and the
regular path share workspace binding, output conversion, and public error wording.
"""

from __future__ import annotations

import dataclasses
import os
import sys
from collections.abc import Callable, Mapping
from datetime import datetime
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

import typer
from pydantic import BaseModel

from yoetz.cli.exits import exit_code_for
from yoetz.domain.coordination import CoordinationErrorCode
from yoetz.domain.values import format_rfc3339_millis
from yoetz.ports.control import (
    ControlClientKind,
    ControlError,
    ProjectionRenderMode,
    WorkspaceLocator,
)
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.errors import SERVICE_STARTUP_PHASES, PublicErrorCode
from yoetz.service.control_protocol import public_error_code_for_control_reason

if TYPE_CHECKING:
    from yoetz.service.client import ServiceClient
    from yoetz.service.startup_failure import StartupFailure

__all__ = [
    "WORKSPACE_LOCATOR_DEFAULT",
    "connect_cli_service",
    "control_failure",
    "human_or_json",
    "plain_json",
    "resolve_cli_workspace_locator",
    "spawned_startup_failure_line",
    "stderr",
    "stdout_json",
]


class _WorkspaceLocatorDefault:
    __slots__ = ()


WORKSPACE_LOCATOR_DEFAULT: Final = _WorkspaceLocatorDefault()

_COORDINATION_CONTROL_GUIDANCE: Final[Mapping[str, str]] = MappingProxyType(
    {
        "coordination_invalid": "correct the project command fields and retry",
        "project_not_found": "choose an existing project and retry",
        "project_dissolved": "choose an active project and retry",
        "implicit_project_requires_opt_out": (
            "run `yoetz project opt-out` for the repository before retrying"
        ),
        "general_project_membership_conflict": (
            "unlink the task from its current general project before linking another"
        ),
        "project_member_not_found": "refresh project status and choose an active member",
        "selector_conflict": (
            "provide selectors that identify the same task; if project status cannot choose "
            "because one task matches more than one general project, unlink one membership "
            "or dissolve one project, then retry"
        ),
        "coordination_consent_required": (
            "obtain current source-workspace consent before retrying"
        ),
        "coordination_source_policy_denied": (
            "review the source task's coordination disclosure policy; workspace consent alone "
            "does not authorize this flow"
        ),
        "coordination_grant_required": "obtain the current project grant before retrying",
        "coordination_generation_revoked": (
            "refresh project status and grant, then retry with the current generation"
        ),
        "coordination_generation_mismatch": (
            "refresh project status and retry with the current generation"
        ),
        "cross_repository_lineage_requires_grant": (
            "obtain a cross-repository project grant before retrying"
        ),
        "project_member_already_unbound": "refresh project status; the member is already unlinked",
    }
)
_COORDINATION_CONTROL_ERROR_REASONS: Final[frozenset[str]] = frozenset(
    code.value for code in CoordinationErrorCode
)


async def connect_cli_service(
    client_kind: ControlClientKind = ControlClientKind.CLI,
    *,
    workspace_locator: WorkspaceLocator | None | _WorkspaceLocatorDefault = (
        WORKSPACE_LOCATOR_DEFAULT
    ),
    projection_render_mode: ProjectionRenderMode = ProjectionRenderMode.MACHINE_READABLE,
    output_is_controlling_tty: bool = False,
) -> ServiceClient:
    """Connect to the ordinary fixed service endpoint with the CLI's binding defaults."""

    locator = resolve_cli_workspace_locator(workspace_locator)
    from yoetz.service.client import connect_service

    return await connect_service(
        client_kind,
        workspace_locator=locator,
        projection_render_mode=projection_render_mode,
        output_is_controlling_tty=output_is_controlling_tty,
    )


def resolve_cli_workspace_locator(
    workspace_locator: WorkspaceLocator | None | _WorkspaceLocatorDefault = (
        WORKSPACE_LOCATOR_DEFAULT
    ),
) -> WorkspaceLocator | None:
    """Resolve the ordinary CLI workspace binding without choosing a connector."""

    return (
        WorkspaceLocator(os.fspath(Path.cwd().resolve(strict=True)))
        if workspace_locator is WORKSPACE_LOCATOR_DEFAULT
        else cast(WorkspaceLocator | None, workspace_locator)
    )


def _safe_write(stream: object, data: bytes) -> None:
    if not hasattr(stream, "write") or not hasattr(stream, "flush"):
        raise TypeError("cli_output_stream_invalid")
    try:
        cast(Callable[[bytes], object], getattr(stream, "write"))(data)
        cast(Callable[[], object], getattr(stream, "flush"))()
    except BrokenPipeError:
        raise typer.Exit(70) from None


def stdout_json(value: JsonValue) -> None:
    """Write one canonical JSON value to stdout."""

    _safe_write(sys.stdout.buffer, canonical_encode(value) + b"\n")


def stderr(message: str) -> None:
    """Write one bounded diagnostic to stderr."""

    try:
        typer.echo(message, err=True)
    except BrokenPipeError:
        pass


def plain_json(value: object) -> JsonValue:
    """Convert the supported CLI result values without exposing object reprs."""

    if value is None or type(value) in {bool, int, str}:
        return cast(JsonValue, value)
    if isinstance(value, Enum):
        return cast(JsonValue, value.value)
    if type(value) is datetime:
        # Privacy receipts and other control results carry real ``datetime`` fields
        # (``finished_at``, ``dispatch_started_at``).  They render as the one canonical
        # timestamp the wire already uses; a naive or non-UTC value stays a typed refusal
        # rather than an invented rendering (issue #731).
        return format_rfc3339_millis(value)
    if isinstance(value, BaseModel):
        return cast(JsonValue, value.model_dump(mode="json", by_alias=True, exclude_none=False))
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return plain_json(dataclasses.asdict(value))
    if isinstance(value, Mapping):
        source = cast(Mapping[object, object], value)
        return {str(key): plain_json(item) for key, item in source.items()}
    if isinstance(value, (list, tuple)):
        sequence = cast(list[object] | tuple[object, ...], value)
        return [plain_json(item) for item in sequence]
    if isinstance(value, (set, frozenset)):
        members = cast(set[object] | frozenset[object], value)
        return [plain_json(item) for item in sorted(members, key=str)]
    raise TypeError("cli_result_not_json")


def human_or_json(
    value: object,
    *,
    json_output: bool,
    stdout_writer: Callable[[JsonValue], None] = stdout_json,
    plain_json_converter: Callable[[object], JsonValue] = plain_json,
) -> None:
    """Render a CLI result using the same machine/terminal split as the full app."""

    converted = plain_json_converter(value)
    if json_output or not sys.stdout.isatty():
        stdout_writer(converted)
    else:
        typer.echo(canonical_encode(converted).decode("utf-8"))


def _singleton_holder_pid() -> int | None:
    try:
        from yoetz.config.paths import state_dir
        from yoetz.service.lifecycle import SINGLETON_LOCK_NAME, probe_singleton_holder

        return probe_singleton_holder(state_dir() / SINGLETON_LOCK_NAME)
    except Exception:
        return None


def _with_holder_pid(line: str) -> str:
    holder = _singleton_holder_pid()
    return line if holder is None else f"{line} (holder pid {holder})"


def _with_holder_identity(line: str) -> str:
    try:
        from yoetz.config.paths import state_dir
        from yoetz.service.lifecycle import SINGLETON_LOCK_NAME, probe_singleton_holder_identity

        holder = probe_singleton_holder_identity(state_dir() / SINGLETON_LOCK_NAME)
    except Exception:
        holder = None
    if holder is None:
        return line
    version = holder.service_version or "unknown"
    digest = holder.schema_manifest_digest or "unknown"
    return f"{line} (holder pid {holder.pid}, service version {version}, schema manifest {digest})"


def _holder_predates_this_package() -> bool:
    """True when the stamped holder runs an older package: an in-place update awaiting reopen."""

    try:
        from yoetz.service.client import holder_version_order, service_holder_identity

        holder = service_holder_identity()
        return holder is not None and holder_version_order(holder.service_version) == "older"
    except Exception:
        return False


def _with_correlation(line: str, error: ControlError) -> str:
    if error.correlation_id is None:
        return line
    head, separator, rest = line.partition("\n")
    return f"{head}; correlation_id {error.correlation_id}{separator}{rest}"


def _holder_identity_json() -> dict[str, JsonValue] | None:
    try:
        from yoetz.config.paths import state_dir
        from yoetz.service.lifecycle import SINGLETON_LOCK_NAME, probe_singleton_holder_identity

        holder = probe_singleton_holder_identity(state_dir() / SINGLETON_LOCK_NAME)
    except Exception:
        return None
    if holder is None:
        return None
    body: dict[str, JsonValue] = {"pid": holder.pid}
    if holder.service_version is not None:
        body["service_version"] = holder.service_version
    if holder.schema_manifest_digest is not None:
        body["schema_manifest_digest"] = holder.schema_manifest_digest
    return body


def _bind_handshake_correlation(error: ControlError) -> ControlError:
    if error.reason not in {"service_incompatible", "protocol_mismatch"}:
        return error
    if error.correlation_id is not None:
        return error
    from yoetz.observability.logging import record_public_error_without_raising

    correlation_id = record_public_error_without_raising(
        component="cli.service",
        operation="control_handshake",
        reason=error.reason,
    )
    return ControlError(
        error.reason,
        retryable=error.retryable,
        accepted_state=error.accepted_state or None,
        correlation_id=correlation_id,
    )


PRIVACY_AUDIT_UNREADABLE_SUMMARY: Final = (
    "privacy_audit_unreadable: the request was valid, but the local privacy audit holds a "
    "receipt that could not be read back"
)


def _privacy_audit_unreadable_failure(
    error: ControlError,
    code: PublicErrorCode,
    *,
    json_output: bool,
    stderr_writer: Callable[[str], None],
    stdout_writer: Callable[[JsonValue], None],
) -> int:
    """Name a store-side receipt failure as exactly that, with its typed continuation (#921).

    Before this, the store's condition reached the operator as the generic
    ``invalid_request: the local request could not be completed`` -- a caller error for a request
    that had nothing wrong with it, and no reason to act on.
    """

    from yoetz.cli.render import recovery_directive_json, render_recovery_directive_lines
    from yoetz.protocol.recovery import continuation_for_reason, directive_for

    directive = directive_for(continuation_for_reason(error.reason))
    lines = [PRIVACY_AUDIT_UNREADABLE_SUMMARY]
    if directive is not None:
        lines.extend(render_recovery_directive_lines(directive))
    stderr_writer(_with_correlation("\n".join(lines), error))
    if json_output:
        payload: dict[str, JsonValue] = {
            "ok": False,
            "public_code": code.value,
            "reason": error.reason,
            "retryable": error.retryable,
        }
        if error.correlation_id is not None:
            payload["correlation_id"] = error.correlation_id
        if directive is not None:
            payload["recovery"] = recovery_directive_json(directive)
        stdout_writer(payload)
    return exit_code_for(code)


def _spawned_startup_failure(error: BaseException) -> StartupFailure | None:
    """The recorded failure of a service this command started on demand, or None.

    On-demand start raises ``service_unavailable`` with ``phase`` set to the spawned service's
    startup stage and ``correlation_id`` to its record (#1040); no other error carries one.
    """

    if (
        not isinstance(error, ControlError)
        or error.reason != "service_unavailable"
        or error.phase not in SERVICE_STARTUP_PHASES
    ):
        return None
    from yoetz.service.startup_failure import spawned_startup_failure

    return spawned_startup_failure(error.phase, error.correlation_id)


def _spawned_startup_failure_line(startup: StartupFailure) -> str:
    return (
        f"service_unavailable: the local service exited while starting "
        f"({startup.describe()}); correlation_id {startup.correlation_id}; read it with "
        f"'yoetz service diagnostics --correlation-id {startup.correlation_id}'"
    )


def spawned_startup_failure_line(error: BaseException) -> str | None:
    """The ``control_failure`` line for a service this command started that exited while starting.

    For a command that keeps its own result shape and exit code when the service is unreachable
    (setup, observation drain) instead of rendering ``control_failure``, so it names the same
    stage, exception class and correlation id. None for any other error.
    """

    startup = _spawned_startup_failure(error)
    return None if startup is None else _spawned_startup_failure_line(startup)


def control_failure(
    error: ControlError,
    *,
    json_output: bool = False,
    operation: str | None = None,
    check_mode: object = None,
    stderr_writer: Callable[[str], None] = stderr,
    stdout_writer: Callable[[JsonValue], None] = stdout_json,
) -> int:
    """Render the shared public control-error taxonomy without loading ``cli.app``.

    ``check_mode`` is a ``check`` request's ``mode``: one that records nothing (ADR-047,
    ``inspect``) times out as a read, never as a write that may have committed.
    """

    error = _bind_handshake_correlation(error)
    code = public_error_code_for_control_reason(error.reason)
    if error.reason == "request_timeout" and operation is not None:
        from yoetz.cli.render import render_recovery_directive_lines
        from yoetz.protocol.recovery import (
            continuation_for_reason,
            directive_for,
            timeout_operation_kind,
        )

        kind = timeout_operation_kind(operation, check_mode=check_mode)
        directive = directive_for(continuation_for_reason("request_timeout", operation_kind=kind))
        lines = [
            f"{code.value.lower()}: request_timeout: the local {operation} request did not answer "
            "within its deadline"
        ]
        if directive is not None:
            lines.extend(render_recovery_directive_lines(directive))
        stderr_writer(_with_correlation("\n".join(lines), error))
        return exit_code_for(code)
    if error.reason in _COORDINATION_CONTROL_ERROR_REASONS:
        from yoetz.cli.render import recovery_directive_json, render_recovery_directive_lines
        from yoetz.protocol.recovery import continuation_for_reason, directive_for

        remedy = _COORDINATION_CONTROL_GUIDANCE[error.reason]
        # A coordination reason code maps to a registered directive like any protocol reason;
        # the remedy names the condition, the directive the recovery rule (ADR-030, #741).
        coordination_directive = directive_for(continuation_for_reason(error.reason))
        lines = [f"{error.reason}: {remedy}"]
        if coordination_directive is not None:
            lines.extend(render_recovery_directive_lines(coordination_directive))
        stderr_writer("\n".join(lines))
        if json_output:
            payload: dict[str, JsonValue] = {
                "ok": False,
                "public_code": code.value,
                "reason": error.reason,
                "retryable": error.retryable,
            }
            if error.correlation_id is not None:
                payload["correlation_id"] = error.correlation_id
            if coordination_directive is not None:
                payload["recovery"] = recovery_directive_json(coordination_directive)
            stdout_writer(payload)
        return exit_code_for(code)
    if error.reason == "privacy_audit_unreadable":
        return _privacy_audit_unreadable_failure(
            error,
            code,
            json_output=json_output,
            stderr_writer=stderr_writer,
            stdout_writer=stdout_writer,
        )
    if error.reason in {"service_incompatible", "protocol_mismatch"}:
        if _holder_predates_this_package():
            summary = (
                f"{error.reason}: Yoetz was updated, and the running local service is still the "
                "previous version, serving sessions opened before the update. Reopen your agent "
                "app or start a new session to switch automatically, or run "
                "'yoetz service restart' on a local terminal to switch now, then retry"
            )
        else:
            summary = (
                f"{error.reason}: the running local service was started by a different Yoetz "
                "installation than this command and rejected its handshake. Run "
                "'yoetz service restart' on a local terminal to replace it with this "
                "installation's service, then retry"
            )
        guidance = _with_correlation(_with_holder_identity(summary), error)
        stderr_writer(guidance)
        if json_output:
            payload = {
                "ok": False,
                "public_code": code.value,
                "reason": error.reason,
                "retryable": error.retryable,
            }
            if error.correlation_id is not None:
                payload["correlation_id"] = error.correlation_id
            holder = _holder_identity_json()
            if holder is not None:
                payload["holder"] = holder
            stdout_writer(payload)
        return exit_code_for(code)
    from yoetz.service.client import accepted_but_unresponsive

    startup = _spawned_startup_failure(error)
    if startup is not None:
        # The service this command started exited during startup (#1040): name the stage and
        # exception class instead of telling the operator to start a service that cannot start.
        stderr_writer(_spawned_startup_failure_line(startup))
        if json_output:
            payload = {
                "ok": False,
                "public_code": code.value,
                "reason": "service_start_failed",
                "phase": startup.stage,
                "retryable": False,
                "correlation_id": startup.correlation_id,
            }
            stdout_writer(payload)
        return exit_code_for(code)
    if code is PublicErrorCode.SERVICE_UNAVAILABLE and accepted_but_unresponsive(error):
        stderr_writer(
            _with_holder_pid(
                "service_unavailable: a local service is listening but did not answer within "
                "5 seconds; it may still be starting or may be wedged. Wait and retry "
                "'yoetz service status'. Do not run 'yoetz service run' -- it will refuse "
                "while that process holds the singleton; stop it with 'yoetz service stop' "
                "instead"
            )
        )
        return exit_code_for(code)
    guidance = {
        PublicErrorCode.VAULT_LOCKED: (
            "vault_locked: run `yoetz service unlock` on a local terminal "
            "(uses the platform credential store when setup provisioned auto-unlock); "
            "if auto-unlock is stale, run `yoetz service auto-unlock repair`; "
            "if ordinary unlock authority may be lost, run `yoetz service recovery status`; "
            "if uninitialized with no TTY, prepare `vault_initialize`, then "
            "`yoetz consent review` on a trusted console"
        ),
        PublicErrorCode.SERVICE_UNAVAILABLE: (
            "service_unavailable: run 'yoetz service run' under your selected user supervisor"
        ),
    }.get(code, f"{code.value.lower()}: the local request could not be completed")
    stderr_writer(guidance)
    return exit_code_for(code)
