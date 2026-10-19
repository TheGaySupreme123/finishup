"""Thin command-line client for the persistent local FinishUP service."""

from __future__ import annotations

import contextlib
import dataclasses
import importlib
import os
import sys
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Any, BinaryIO, Final, Literal, Protocol, cast

import anyio
import typer
from pydantic import BaseModel, ValidationError

from finishup import __version__
from finishup.cli.agent_start import AGENT_START_HANDOFF
from finishup.cli.bootstrap import (
    control_failure as _shared_control_failure,
)
from finishup.cli.bootstrap import (
    human_or_json as _shared_human_or_json,
)
from finishup.cli.bootstrap import (
    plain_json as _shared_plain_json,
)
from finishup.cli.bootstrap import resolve_cli_workspace_locator
from finishup.cli.bootstrap import (
    stderr as _shared_stderr,
)
from finishup.cli.bootstrap import (
    stdout_json as _shared_stdout_json,
)
from finishup.cli.exits import (
    exit_code_for,
    lifecycle_public_code,
    remediation_message,
)
from finishup.cli.project import project_app
from finishup.cli.render import (
    bounded_failure_line,
    ceremony_refusal_line,
    render_error_recovery_lines,
    render_human_awaiting_human,
    render_human_check,
    render_human_error,
    render_human_inspection,
    render_human_receipt,
    render_human_status,
    render_local_recovery_lines,
)
from finishup.domain.values import JsonObject
from finishup.legacy_names import RENAME_NOTE
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    ProjectionRenderMode,
    WorkspaceLocator,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError, PublicErrorCode
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    MAX_TASK_STATEMENT_BYTES,
    CheckAwaitingHumanModel,
    CheckInspectionModel,
    CheckRequest,
    CheckResult,
    CheckSuccessModel,
    OperationFailureModel,
    PublishWorkRequest,
    PublishWorkResult,
    ReceiptRequest,
    ReceiptResult,
    ReceiptSuccessModel,
    RespondRequest,
    RespondResult,
    StartRequest,
    StartResult,
    StatusRequest,
    StatusResult,
    StatusSuccessModel,
    public_model_to_wire,
)
from finishup.protocol.schemas import schema_document_for
from finishup.service.client import ServiceClient, connect_service
from finishup.version import ResourceIntegrityError

if TYPE_CHECKING:
    # Runtime resolution is deliberately lazy: the client/service trust boundary pins
    # cli.app's import graph to the ordinary service client, and finishup.service.lifecycle
    # is service-composition side (see tests/packaging/test_service_boundary_imports.py).
    from finishup.service.lifecycle import LifecycleError

__all__ = [
    "app",
    "build_service_client",
    "control_failure",
    "main",
    "run_async",
    "support_methods_carrying_schema_version",
    "usage_failure",
    "with_body_schema_version",
]

_MAX_INPUT_BYTES: Final = 1_048_576
_INPUT = Annotated[
    str | None,
    typer.Option("--input", help="Strict JSON request path, or - for stdin."),
]
_INLINE = Annotated[
    str | None,
    typer.Option("--request", help="Inline strict JSON request."),
]
_JSON = Annotated[bool, typer.Option("--json", help="Emit canonical JSON.")]
_DEADLINE = Annotated[
    int | None,
    typer.Option("--deadline-ms", min=1, max=86_400_000),
]


class _MutableBinaryReader(Protocol):
    def readinto(self, buffer: memoryview) -> int | None: ...


app = typer.Typer(
    name="finishup",
    help=f"Local-first evidence ledger and review engine. {RENAME_NOTE} https://finishup.dev",
    epilog=AGENT_START_HANDOFF,
    no_args_is_help=False,
    invoke_without_command=True,
    pretty_exceptions_enable=False,
    add_completion=False,
)
mcp_app = typer.Typer(help="Run protocol bridges.", no_args_is_help=True)
state_app = typer.Typer(help="Capture bounded local structural state.", no_args_is_help=True)
integrate_app = typer.Typer(help="Manage explicit harness integrations.", no_args_is_help=True)
integrate_skill_app = typer.Typer(help="Manage the FinishUP harness skill.", no_args_is_help=True)
integrate_mcp_app = typer.Typer(
    help="Manage the FinishUP MCP server registration.", no_args_is_help=True
)
integrate_project_mcp_app = typer.Typer(
    help="Manage Cursor's project-scoped FinishUP MCP registration.", no_args_is_help=True
)
integrate_plugin_app = typer.Typer(
    help=(
        "Manage an explicit host plugin artifact. Claude Code supports the full lifecycle plus "
        "export; Cursor supports preview, install, status, and remove; Codex supports only "
        "preview, status, and remove (Codex activation stays in `finishup setup run`)."
    ),
    no_args_is_help=True,
)
integrate_admission_app = typer.Typer(
    help=(
        "Let a host's automatic tool-call reviewer admit the owner-authorized AI-powered check "
        "(project-scoped, previewed, digest-bound, reversible)."
    ),
    no_args_is_help=True,
)
setup_app = typer.Typer(help="Guided first-run harness and provider setup.", no_args_is_help=True)
service_app = typer.Typer(help="Manage the foreground local service.", no_args_is_help=True)
instance_app = typer.Typer(
    help=(
        "Create, inspect, and dispose independent FinishUP instances (persistent development "
        "instances and disposable test snapshots with their own root, service, and vault)."
    ),
    no_args_is_help=True,
)
auto_unlock_app = typer.Typer(
    help="Inspect or repair restart-safe passphrase unlock.", no_args_is_help=True
)
recovery_app = typer.Typer(
    help="Provision or use installation-vault recovery without exposing secrets to agents.",
    no_args_is_help=True,
)
provider_app = typer.Typer(help="Manage provider setup.", no_args_is_help=True)
codex_subscription_app = typer.Typer(
    help="Manage the exact Codex-owned ChatGPT subscription evaluator.", no_args_is_help=True
)
codex_evaluator_runtime_app = typer.Typer(
    help=(
        "Inspect, retain, or remove FinishUP's verified private copy of the evaluator runtime, kept "
        "apart from your everyday Codex installation."
    ),
    no_args_is_help=True,
)
credential_app = typer.Typer(
    help="Provision credentials through a trusted ceremony.", no_args_is_help=True
)
fallback_app = typer.Typer(
    help=(
        "Manage the primary/fallback pairing of the two bound AI-powered review endpoints "
        "(Codex subscription and API provider)."
    ),
    no_args_is_help=True,
)
privacy_app = typer.Typer(help="Inspect and configure local privacy policy.", no_args_is_help=True)
privacy_receipts_app = typer.Typer(
    help="Inspect bounded structural privacy receipts.", no_args_is_help=True
)
backup_app = typer.Typer(help="Preview or execute a backup.", no_args_is_help=True)
restore_app = typer.Typer(help="Preview or execute a restore.", no_args_is_help=True)
migrate_app = typer.Typer(help="Preview or execute a migration.", no_args_is_help=True)
elevated_app = typer.Typer(
    help=(
        "Human-review consent for non-default actions (ADR-015/016). "
        "Authority and secrets stay inside a verified foreground-console review."
    ),
    no_args_is_help=True,
)
hooks_app = typer.Typer(
    help="Local harness lifecycle hook commands (activation, correlation, re-ground, observe).",
    no_args_is_help=True,
)
observe_app = typer.Typer(
    help="Live Codex observation consent and status (local control; not MCP).",
    no_args_is_help=True,
)
observe_checks_app = typer.Typer(
    help="Preview and manage exact-digest approved workspace checks.",
    no_args_is_help=True,
)
recommend_app = typer.Typer(
    help="Review and explicitly decide recommended defaults.", no_args_is_help=True
)

app.add_typer(recommend_app, name="recommend")
app.add_typer(mcp_app, name="mcp")
app.add_typer(state_app, name="state")
app.add_typer(integrate_app, name="integrate")
integrate_app.add_typer(integrate_skill_app, name="skill")
integrate_app.add_typer(integrate_mcp_app, name="mcp")
integrate_app.add_typer(integrate_project_mcp_app, name="project-mcp")
integrate_app.add_typer(integrate_plugin_app, name="plugin")
integrate_app.add_typer(integrate_admission_app, name="admission")
app.add_typer(setup_app, name="setup")
app.add_typer(service_app, name="service")
app.add_typer(instance_app, name="instance")
service_app.add_typer(auto_unlock_app, name="auto-unlock")
service_app.add_typer(recovery_app, name="recovery")
app.add_typer(provider_app, name="provider")
provider_app.add_typer(credential_app, name="credential")
provider_app.add_typer(codex_subscription_app, name="codex-subscription")
codex_subscription_app.add_typer(codex_evaluator_runtime_app, name="runtime")
provider_app.add_typer(fallback_app, name="fallback")
app.add_typer(privacy_app, name="privacy")
privacy_app.add_typer(privacy_receipts_app, name="receipts")
app.add_typer(backup_app, name="backup")
app.add_typer(restore_app, name="restore")
app.add_typer(migrate_app, name="migrate")
app.add_typer(elevated_app, name="elevated-bootstrap")
app.add_typer(elevated_app, name="consent")
app.add_typer(hooks_app, name="hooks")
app.add_typer(observe_app, name="observe")
observe_app.add_typer(observe_checks_app, name="checks")
app.add_typer(project_app, name="project")


def _recommend_operation(name: str) -> Callable[..., None]:
    # Keep recommendation composition outside the ordinary CLI import graph. Use the builtin
    # importer here so tests may independently fence the adapter import performed by recommend.py.
    module = __import__("finishup.cli.recommend", fromlist=[name])
    return cast(Callable[..., None], getattr(module, name))


@recommend_app.command("list")
def recommend_list_cmd(
    json_output: _JSON = False,
    codex_path: Annotated[
        Path | None,
        typer.Option(
            "--codex-path",
            help="Exact Codex executable to inspect; activation status stays unknown without it.",
        ),
    ] = None,
    codex_home: Annotated[
        Path | None,
        typer.Option("--codex-home", help="Exact Codex home expected from that executable."),
    ] = None,
) -> None:
    """Refresh at this heavy touchpoint and list cached pending recommendations."""

    _recommend_operation("recommend_list")(
        json_output=json_output,
        codex_path=codex_path,
        codex_home=codex_home,
    )


@recommend_app.command("accept")
def recommend_accept_cmd(
    recommendation_id: Annotated[str, typer.Argument(help="Exact recommendation id.")],
    release_version: Annotated[
        str | None, typer.Option("--release-version", help="Exact advertised package release.")
    ] = None,
    codex_path: Annotated[
        Path | None,
        typer.Option(
            "--codex-path",
            help="Exact Codex executable whose activation is being approved.",
        ),
    ] = None,
    codex_home: Annotated[
        Path | None,
        typer.Option("--codex-home", help="Exact Codex home to preview and update."),
    ] = None,
) -> None:
    """Explicitly approve and apply one currently recommended action."""

    _recommend_operation("recommend_accept")(
        recommendation_id,
        release_version=release_version,
        codex_path=codex_path,
        codex_home=codex_home,
    )


@recommend_app.command("decline")
def recommend_decline_cmd(
    recommendation_id: Annotated[str, typer.Argument(help="Exact recommendation id.")],
    release_version: Annotated[
        str | None, typer.Option("--release-version", help="Exact advertised package release.")
    ] = None,
    codex_path: Annotated[
        Path | None,
        typer.Option(
            "--codex-path",
            help="Exact Codex executable used to refresh activation advice.",
        ),
    ] = None,
    codex_home: Annotated[
        Path | None,
        typer.Option(
            "--codex-home", help="Exact Codex home used when refreshing activation advice."
        ),
    ] = None,
) -> None:
    """Remember an explicit decline for the cached recommendation target."""

    _recommend_operation("recommend_decline")(
        recommendation_id,
        release_version=release_version,
        codex_path=codex_path,
        codex_home=codex_home,
    )


@app.command("upgrade")
def upgrade_cmd(
    host: Annotated[
        list[str] | None,
        typer.Option(
            "--host", help="Existing host: codex, claude, cursor; repeat for multiple hosts."
        ),
    ] = None,
    accept: Annotated[
        bool,
        typer.Option(
            "--accept",
            help="Run only the fixed uv package upgrade now; open sessions keep working and "
            "switch to the new version when they are reopened.",
        ),
    ] = False,
    prune_runtimes: Annotated[
        bool,
        typer.Option(
            "--prune-runtimes",
            help="Remove unused retained runtimes without stopping active sessions.",
        ),
    ] = False,
    writers_stopped: Annotated[
        bool,
        typer.Option(
            "--writers-stopped",
            hidden=True,
            help="Accepted for compatibility; stopping hosts and the service is no longer required.",
        ),
    ] = False,
    project_root: Annotated[
        str | None,
        typer.Option("--project-root", help="Exact existing project-root; never inferred."),
    ] = None,
    codex_path: Annotated[
        str | None, typer.Option("--codex-path", help="Exact existing codex-path; never inferred.")
    ] = None,
    codex_home: Annotated[
        str | None, typer.Option("--codex-home", help="Exact existing codex-home; never inferred.")
    ] = None,
    claude_path: Annotated[
        str | None,
        typer.Option("--claude-path", help="Exact existing claude-path; never inferred."),
    ] = None,
    claude_config_root: Annotated[
        str | None,
        typer.Option(
            "--claude-config-root", help="Exact existing claude-config-root; never inferred."
        ),
    ] = None,
    cache_root: Annotated[
        str | None, typer.Option("--cache-root", help="Exact existing cache-root; never inferred.")
    ] = None,
    marketplace_root: Annotated[
        str | None,
        typer.Option("--marketplace-root", help="Exact existing marketplace-root; never inferred."),
    ] = None,
    cursor_config_root: Annotated[
        str | None,
        typer.Option(
            "--cursor-config-root", help="Exact existing cursor-config-root; never inferred."
        ),
    ] = None,
    mcp_ownership: Annotated[
        str | None,
        typer.Option("--mcp-ownership", help="Exact existing mcp-ownership; never inferred."),
    ] = None,
    route_profile: Annotated[
        str | None,
        typer.Option("--route-profile", help="Exact existing route-profile; never inferred."),
    ] = None,
    observation_profile: Annotated[
        str | None,
        typer.Option(
            "--observation-profile", help="Exact existing observation-profile; never inferred."
        ),
    ] = None,
) -> None:
    """Plan a complete upgrade while preserving settings; optionally replace this uv tool."""
    del writers_stopped  # Older guidance passed it; the package step no longer needs quiescence.
    module = importlib.import_module("finishup.cli.upgrade")
    operation = cast(Callable[..., int], module.run_upgrade)
    options = {
        "project-root": project_root,
        "codex-path": codex_path,
        "codex-home": codex_home,
        "claude-path": claude_path,
        "claude-config-root": claude_config_root,
        "cache-root": cache_root,
        "marketplace-root": marketplace_root,
        "cursor-config-root": cursor_config_root,
        "mcp-ownership": mcp_ownership,
        "route-profile": route_profile,
        "observation-profile": observation_profile,
    }
    _finish(
        operation(
            hosts=host,
            options={key: value for key, value in options.items() if value is not None},
            accept=accept,
            prune_runtimes=prune_runtimes,
        )
    )


def run_async[T](operation: Callable[[], Awaitable[T]]) -> T:
    """Own exactly one event-loop bridge for a CLI operation."""

    return anyio.run(operation)


class _WorkspaceLocatorDefault:
    __slots__ = ()


_WORKSPACE_LOCATOR_DEFAULT: Final = _WorkspaceLocatorDefault()


async def build_service_client(
    client_kind: ControlClientKind = ControlClientKind.CLI,
    *,
    workspace_locator: WorkspaceLocator | None | _WorkspaceLocatorDefault = (
        _WORKSPACE_LOCATOR_DEFAULT
    ),
    projection_render_mode: ProjectionRenderMode = ProjectionRenderMode.MACHINE_READABLE,
    output_is_controlling_tty: bool = False,
) -> ServiceClient:
    """Connect to the fixed same-user service endpoint; never spawn one.

    Ordinary CLI work is repository-bound by default. Passing ``None`` explicitly remains the
    narrow escape hatch for callers whose operation genuinely has no workspace authority.
    """

    locator = (
        resolve_cli_workspace_locator()
        if workspace_locator is _WORKSPACE_LOCATOR_DEFAULT
        else resolve_cli_workspace_locator(cast(WorkspaceLocator | None, workspace_locator))
    )
    return await connect_service(
        client_kind,
        workspace_locator=locator,
        projection_render_mode=projection_render_mode,
        output_is_controlling_tty=output_is_controlling_tty,
    )


def _bounded_input(input_path: str | None, inline: str | None) -> JsonValue:
    if (input_path is None) == (inline is None):
        raise ProtocolValueError("invalid_event_value_type")
    if inline is not None:
        raw = inline.encode("utf-8")
    elif input_path == "-":
        raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    else:
        if input_path is None:
            raise ProtocolValueError("invalid_event_value_type")
        with Path(input_path).open("rb") as stream:
            raw = stream.read(_MAX_INPUT_BYTES + 1)
    if not raw or len(raw) > _MAX_INPUT_BYTES:
        raise ProtocolValueError("invalid_event_value_type")
    return strict_json_parse(raw)


def _request_model(
    model_type: type[BaseModel], input_path: str | None, inline: str | None
) -> BaseModel:
    return model_type.model_validate(_bounded_input(input_path, inline))


def _json_object(input_path: str | None, inline: str | None) -> JsonObject:
    parsed = _bounded_input(input_path, inline)
    if not isinstance(parsed, Mapping):
        raise ProtocolValueError("unsupported_json_type")
    return JsonObject(parsed)


def _safe_write(stream: BinaryIO, data: bytes) -> None:
    try:
        stream.write(data)
        stream.flush()
    except BrokenPipeError:
        raise typer.Exit(70) from None


def _stdout_json(value: JsonValue) -> None:
    _shared_stdout_json(value)


def _stderr(message: str) -> None:
    _shared_stderr(message)


def _plain_json(value: object) -> JsonValue:
    return _shared_plain_json(value)


def _human_or_json(value: object, *, json_output: bool) -> None:
    _shared_human_or_json(
        value,
        json_output=json_output,
        stdout_writer=_stdout_json,
        plain_json_converter=_plain_json,
    )


def _usage_failure() -> int:
    _stderr("invalid_request: the command input is invalid")
    return 2


def usage_failure() -> int:
    """Return the standard CLI exit code for invalid command usage."""

    return _usage_failure()


def _machine_scope_request_or_none() -> JsonObject | None:
    """Build the machine-scope privacy body locally, or emit one bounded diagnostic.

    Machine-scope construction is a local read of the configured installation bundle. When it
    fails, the bounded reason and its remediation are reported here and ``None`` is returned so
    the caller stops before any service request is sent (issue #517).
    """

    from finishup.cli.provider_status import MachineScopeError, machine_scope_request

    try:
        return machine_scope_request()
    except MachineScopeError as error:
        _stderr(f"machine_scope_unavailable: {error.reason}: {error.remediation}")
        return None


def _bounded_failure_line(reason: str, *, prefix: str | None = None) -> str:
    """Render one bounded token with its remediation and its recovery directive.

    One shape for every human-rendered CLI refusal, shared with ``menu``, ``instance``, and
    ``observe`` so a lifecycle refusal the MCP bridge would explain is explained here too
    (issue #741).
    """

    return bounded_failure_line(reason, prefix=prefix)


def _codex_subscription_cli_failure(error: BaseException) -> None:
    from finishup.cli.codex_subscription import (
        subscription_failure_reason,
        subscription_remediation,
    )

    reason = subscription_failure_reason(error)
    rendered = _bounded_failure_line(reason, prefix="codex_subscription")
    guidance = subscription_remediation(reason)
    if guidance is not None and remediation_message(reason) is None:
        # Evaluator-runtime tokens carry their next step beside the subscription commands (#855).
        head, separator, directives = rendered.partition("\n")
        rendered = f"{head}: {guidance}{separator}{directives}"
    _stderr(rendered)


async def _codex_subscription_mutate[T](operation: Callable[[], Awaitable[T]]) -> T:
    """Apply a subscription mutation, then recompose so a running service cannot keep the old cell."""

    from finishup.cli.setup import restart_service_for_semantic_composition

    result = await operation()
    await restart_service_for_semantic_composition()
    return result


async def _noop_subscription_recompose() -> None:
    return None


def _elevated_failure(error: Exception) -> int:
    """Report one bounded elevated-bootstrap failure with its exact next step."""

    reason = getattr(error, "reason", "failed")
    _stderr(
        _bounded_failure_line(
            reason if type(reason) is str else "failed", prefix="elevated_bootstrap"
        )
    )
    if reason in {
        "ceremony_service_unavailable",
        "provider_binding_required",
        "repository_privacy_scope_unavailable",
    }:
        from finishup.cli.setup_readiness import continuation

        recipe = "review" if reason == "provider_binding_required" else "local"
        _stderr(
            "Next: "
            + continuation(
                ["setup", "status", "--next", "--operation", recipe],
                project=Path.cwd(),
            )
        )
    return 2


def _singleton_holder_pid() -> int | None:
    """Best-effort advisory pid of the process holding the service singleton, else None.

    Never takes the lock: even a shared flock conflicts with a daemon still acquiring its
    exclusive one, so a diagnostic could make a legitimate start fail.
    """

    try:
        from finishup.config.paths import state_dir
        from finishup.service.lifecycle import SINGLETON_LOCK_NAME, probe_singleton_holder

        return probe_singleton_holder(state_dir() / SINGLETON_LOCK_NAME)
    except Exception:
        return None


def _annotate_first_line(text: str, suffix: str) -> str:
    """Append a bounded annotation to the token line, ahead of any directive lines beneath it."""

    head, separator, rest = text.partition("\n")
    return f"{head}{suffix}{separator}{rest}"


def _with_holder_pid(line: str) -> str:
    holder = _singleton_holder_pid()
    return line if holder is None else _annotate_first_line(line, f" (holder pid {holder})")


def _lifecycle_exit_code(error: BaseException) -> int | None:
    """Exit code for a bounded lifecycle refusal, or None for anything else.

    A ``LifecycleError`` can only arrive from a command that already composed the daemon,
    so its module is resolved through ``sys.modules`` rather than imported: the catch-all
    must not pull service-composition modules into cli.app's pinned import graph.
    """

    lifecycle = sys.modules.get("finishup.service.lifecycle")
    if lifecycle is None:
        return None
    if not isinstance(error, lifecycle.LifecycleError):
        return None
    return _lifecycle_failure(cast("LifecycleError", error))


def _lifecycle_failure(error: LifecycleError) -> int:
    """Report a bounded lifecycle refusal as the operating condition it names."""

    code = lifecycle_public_code(error.reason)
    if code is None:
        _stderr("internal_error: the command could not be completed")
        return exit_code_for(PublicErrorCode.INTERNAL_ERROR)
    _stderr(_with_holder_pid(_bounded_failure_line(error.reason)))
    return exit_code_for(code)


def _control_failure(
    error: ControlError,
    *,
    json_output: bool = False,
    operation: str | None = None,
    check_mode: object = None,
) -> int:
    return _shared_control_failure(
        error,
        json_output=json_output,
        operation=operation,
        check_mode=check_mode,
        stderr_writer=_stderr,
        stdout_writer=_stdout_json,
    )


def control_failure(
    error: ControlError, *, json_output: bool = False, operation: str | None = None
) -> int:
    """Render a control-channel failure using the shared CLI taxonomy."""

    return _control_failure(error, json_output=json_output, operation=operation)


type WorkflowRequest = (
    StartRequest
    | PublishWorkRequest
    | CheckRequest
    | RespondRequest
    | StatusRequest
    | ReceiptRequest
)
type WorkflowResult = (
    StartResult | PublishWorkResult | CheckResult | RespondResult | StatusResult | ReceiptResult
)


def _read_task_statement_file(path: str) -> str:
    """Read the user's request verbatim for ``start.task_statement`` (issue #908).

    The file is UTF-8 text, never parsed or trimmed: the agent transcribes the request and the
    reviewer receives exactly those words.
    """

    if path == "-":
        raw = sys.stdin.buffer.read(MAX_TASK_STATEMENT_BYTES + 1)
    else:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_TASK_STATEMENT_BYTES + 1)
    if not raw:
        raise ProtocolValueError("invalid_event_value_type")
    if len(raw) > MAX_TASK_STATEMENT_BYTES:
        # Too long, not mistyped: name the bound (tb4n3 A13).
        raise ProtocolValueError("event_text_out_of_bounds")
    return raw.decode("utf-8", errors="strict")


def _publish_work_request(
    input_path: str | None, inline: str | None
) -> tuple[BaseModel, str | None]:
    """Parse one ``publish-work`` body, minting its request id when it omits one.

    Issue #1084 (ADR-050 decision 2), the bridge's contract: the identity is never derived from
    the body. A body without ``request_id`` is validated under a provisional id and then sent
    under a fresh one; the minted id is returned so the caller can name it before sending (a dry
    run's id is not returned: a preview consumes no identity). Re-running the identical command
    is a new publication; retrying means sending the named id.
    """

    parsed = _bounded_input(input_path, inline)
    if not isinstance(parsed, Mapping) or "request_id" in parsed:
        return PublishWorkRequest.model_validate(parsed), None
    request_id = new_id(IdKind.REQUEST)
    request = PublishWorkRequest.model_validate(
        {**cast(Mapping[str, JsonValue], parsed), "request_id": request_id}
    )
    return request, None if request.dry_run is True else request_id


def _start_request_model(
    input_path: str | None, inline: str | None, task_statement_file: str | None
) -> BaseModel:
    if task_statement_file is None:
        return _request_model(StartRequest, input_path, inline)
    # One source per field: two stdin readers, or a request that already carries a statement,
    # is ambiguous rather than something to merge.
    if task_statement_file == "-" and input_path == "-":
        raise ProtocolValueError("invalid_event_value_type")
    parsed = _bounded_input(input_path, inline)
    if not isinstance(parsed, Mapping) or "task_statement" in parsed:
        raise ProtocolValueError("invalid_event_value_type")
    return StartRequest.model_validate(
        {
            **cast(Mapping[str, JsonValue], parsed),
            "task_statement": _read_task_statement_file(task_statement_file),
        }
    )


async def _call_workflow(
    method: str,
    request_type: type[BaseModel],
    input_path: str | None,
    inline: str | None,
    json_output: bool,
    deadline_ms: int | None,
    *,
    task_statement_file: str | None = None,
    await_observations: bool = False,
    owner_view: bool = False,
    use_passphrase: bool = False,
) -> int:
    # ADR-047: a ``check`` whose mode records nothing (``inspect``) fails as a read.
    check_mode: object = None
    # Issue #1084: the request id this command minted for an id-less publish, and whether a
    # workflow result came back (so an output failure afterwards is not called a usage error).
    minted: str | None = None
    completed_request_id: str | None = None
    try:
        if method == "start":
            request = cast(
                WorkflowRequest, _start_request_model(input_path, inline, task_statement_file)
            )
        elif await_observations:
            # ``finishup check --await-observations`` sets the optional request field (issue #1012);
            # a request that already carries it keeps its own value.
            parsed = _bounded_input(input_path, inline)
            if not isinstance(parsed, Mapping):
                raise ProtocolValueError("unsupported_json_type")
            request = cast(
                WorkflowRequest,
                request_type.model_validate({"await_observations": True, **parsed}),
            )
        elif method == "publish_work":
            parsed_request, minted = _publish_work_request(input_path, inline)
            request = cast(WorkflowRequest, parsed_request)
        else:
            request = cast(WorkflowRequest, _request_model(request_type, input_path, inline))
        if type(request) is CheckRequest:
            check_mode = request.mode
        # Every result is the agent-facing projection (ADR-009 round 3): a terminal is not
        # proof that the owner is reading. ``--owner-view`` asks the service for the full
        # receipt, which it grants only after the owner reauthenticates for this exact request.
        if (owner_view or use_passphrase) and type(request) is not ReceiptRequest:
            raise ProtocolValueError("unsupported_json_type")
        if use_passphrase and not owner_view:
            raise ProtocolValueError("unsupported_json_type")
        if minted is not None:
            # Named before anything is sent, so the id survives a lost or unwritable result.
            _stderr(
                f"request_id {minted}: minted by FinishUP for this publish-work; send it as "
                "request_id to retry this call (re-running the command publishes again)"
            )
        client = await build_service_client()
        try:
            if owner_view:
                refused = await _authorize_owner_receipt_view(
                    client, cast(ReceiptRequest, request), use_passphrase=use_passphrase
                )
                if refused is not None:
                    return refused
            call = getattr(client, method)
            result = cast(WorkflowResult, await call(request, deadline_ms=deadline_ms))
        finally:
            await client.close()
        if method in {"start", "publish_work", "check", "respond", "receipt"}:
            completed_request_id = cast(str, getattr(request, "request_id", "")) or None
        wire = public_model_to_wire(result)
        branch = result.root
        if json_output or not sys.stdout.isatty():
            _stdout_json(wire)
            if isinstance(branch, OperationFailureModel):
                # stdout is the frozen wire failure result and admits no extra field, so the
                # directive this renderer resolves from the token goes to stderr (ADR-030, #741).
                recovery = render_error_recovery_lines(branch.error.safe_details)
                if recovery:
                    _stderr("\n".join(recovery))
        elif isinstance(branch, OperationFailureModel):
            _stderr(render_human_error(branch.error))
        elif isinstance(branch, CheckSuccessModel):
            typer.echo(render_human_check(branch))
        elif isinstance(branch, CheckAwaitingHumanModel):
            typer.echo(render_human_awaiting_human(branch))
        elif isinstance(branch, CheckInspectionModel):
            typer.echo(render_human_inspection(branch))
        elif isinstance(branch, StatusSuccessModel):
            typer.echo(render_human_status(branch))
        elif isinstance(branch, ReceiptSuccessModel):
            typer.echo(render_human_receipt(branch))
        else:
            typer.echo(canonical_encode(wire).decode("utf-8"))
        if isinstance(branch, OperationFailureModel):
            return exit_code_for(branch.error.code)
        return 0
    except OSError:
        if completed_request_id is not None:
            # Review N1 of PR #1088 round 2: the service answered (a write may have committed)
            # and only writing that answer failed. That is not a usage error.
            with contextlib.suppress(Exception):
                _stderr(
                    "result_output_failed: the call completed but its result could not be "
                    f"written; read status view=operation for request_id {completed_request_id}"
                )
            return exit_code_for(PublicErrorCode.INTERNAL_ERROR)
        return _usage_failure()
    except (ProtocolValueError, ValidationError, ValueError):
        return _usage_failure()
    except ControlError as error:
        return _control_failure(error, operation=method, check_mode=check_mode)


def _finish(code: int) -> None:
    if code:
        raise typer.Exit(code)


def _hooks_operation(name: str) -> Callable[..., int]:
    module = importlib.import_module("finishup.cli.hooks")
    return cast(Callable[..., int], getattr(module, name))


@hooks_app.command("user-prompt-submit")
def hooks_user_prompt_submit(
    workspace: Annotated[
        str | None,
        typer.Option(
            "--workspace",
            help=(
                "Project workspace path (use '.' for the Codex session cwd). Only its "
                "private commitment is retained."
            ),
        ),
    ] = None,
) -> None:
    """Inject the materiality/activation cue for UserPromptSubmit."""

    _finish(_hooks_operation("handle_user_prompt_submit")(workspace=workspace))


@hooks_app.command("post-tool-use")
def hooks_post_tool_use() -> None:
    """Correlate a successful FinishUP start tool call for PostToolUse."""

    _finish(_hooks_operation("handle_post_tool_use")())


@hooks_app.command("session-start")
def hooks_session_start(
    workspace: Annotated[
        str | None,
        typer.Option(
            "--workspace",
            help=(
                "Project workspace path for the resume/compact status read (defaults to the "
                "hook's working directory). Only its private commitment is retained."
            ),
        ),
    ] = None,
) -> None:
    """Re-ground after SessionStart resume/compact; clear removes mapping."""

    _finish(_hooks_operation("handle_session_start")(workspace=workspace))


@hooks_app.command("observe")
def hooks_observe(
    event: Annotated[str, typer.Option("--event", help="Codex hook event name.")],
    workspace: Annotated[
        str | None,
        typer.Option(
            "--workspace",
            help=(
                "Project workspace path (use '.' for cwd). Resolved locally; only the "
                "private commitment is retained—never logged or persisted as plaintext."
            ),
        ),
    ] = None,
) -> None:
    """Unified bounded observation ingress for Codex lifecycle hooks."""

    try:
        module = importlib.import_module("finishup.cli.observe_hooks")
        handler = cast(Callable[..., int], getattr(module, "handle_codex_observe"))
        handler(event_name=event, workspace=workspace)
    except BaseException:
        try:
            _stdout_json({})
        except BaseException:
            pass


@hooks_app.command("startup-context")
def hooks_startup_context(
    host: Annotated[Literal["claude", "cursor"], typer.Option("--host")],
) -> None:
    """Emit static native startup guidance without observation or service access."""

    from finishup.cli.startup_context import handle_startup_context

    handle_startup_context(host=host)


@hooks_app.command("startup-gate")
def hooks_startup_gate(
    host: Annotated[Literal["claude", "cursor"], typer.Option("--host")],
    event: Annotated[str, typer.Option("--event")],
) -> None:
    """Run the owner-selected native required-startup hook."""

    from finishup.cli.startup_gate import handle_startup_gate

    handle_startup_gate(host=host, event=event)


@hooks_app.command("cursor-observe")
def hooks_cursor_observe(
    event: Annotated[str, typer.Option("--event", help="Cursor hook event name.")],
    workspace: Annotated[
        str | None,
        typer.Option(
            "--workspace",
            help=(
                "Cursor workspace path (use '.' for cwd). Only its private commitment "
                "is retained; hook content is structurally minimized."
            ),
        ),
    ] = None,
    observation_profile: Annotated[
        str | None,
        typer.Option(
            "--observation-profile",
            help="Exact profile emitted by the rendered native Cursor artifact.",
        ),
    ] = None,
) -> None:
    """Privacy-minimized, fail-open observation ingress for local Cursor hooks."""

    try:
        module = importlib.import_module("finishup.cli.observe_hooks")
        handler = cast(Callable[..., int], getattr(module, "handle_cursor_observe"))
        handler(
            event_name=event,
            workspace=workspace,
            observation_profile=observation_profile,
        )
    except BaseException:
        try:
            from finishup.cli.hook_io import cursor_context_output

            _stdout_json(cursor_context_output(event, ""))
        except BaseException:
            pass


@hooks_app.command("claude-observe")
def hooks_claude_observe(
    event: Annotated[str, typer.Option("--event", help="Claude hook event name.")],
    workspace: Annotated[
        str | None,
        typer.Option(
            "--workspace",
            help=(
                "Claude project path (normally ${CLAUDE_PROJECT_DIR}). Only its private "
                "commitment is retained; hook content is structurally minimized."
            ),
        ),
    ] = None,
    observation_profile: Annotated[
        str | None,
        typer.Option(
            "--observation-profile",
            help="Exact profile emitted by the rendered native Claude artifact.",
        ),
    ] = None,
) -> None:
    """Privacy-minimized, fail-open observation ingress for Claude Code hooks."""

    try:
        module = importlib.import_module("finishup.cli.observe_hooks")
        handler = cast(Callable[..., int], getattr(module, "handle_claude_observe"))
        handler(
            event_name=event,
            workspace=workspace,
            observation_profile=observation_profile,
        )
    except BaseException:
        try:
            _stdout_json({})
        except BaseException:
            pass


@hooks_app.command("spool")
def hooks_spool(
    event: Annotated[str, typer.Option("--event", help="Codex hook event name.")],
    workspace: Annotated[str, typer.Option("--workspace", help="Project workspace path.")],
) -> None:
    """Append a legacy synchronous hook observation for service-side forwarding."""

    try:
        module = importlib.import_module("finishup.cli.observe_hooks")
        handler = cast(Callable[..., int], getattr(module, "handle_spool"))
        handler(event_name=event, workspace=workspace)
    except BaseException:
        try:
            _stdout_json({})
        except BaseException:
            pass


def _observe_operation(name: str) -> Callable[..., int]:
    module = importlib.import_module("finishup.cli.observe")
    return cast(Callable[..., int], getattr(module, name))


@observe_app.command("status")
def observe_status_cmd(
    workspace: Annotated[
        str | None, typer.Option("--workspace", help="Workspace path (commitment only stored).")
    ] = None,
    codex_path: Annotated[
        Path | None,
        typer.Option(
            "--codex-path",
            help="Exact Codex executable to inspect; requires --codex-home.",
        ),
    ] = None,
    codex_home: Annotated[
        Path | None,
        typer.Option(
            "--codex-home",
            help="Expected Codex home/cache; requires --codex-path.",
        ),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show observation consent and lifecycle status for a workspace."""

    if (codex_path is None) != (codex_home is None):
        raise typer.BadParameter("--codex-path and --codex-home must be provided together")
    _finish(
        _observe_operation("observe_status")(
            workspace=workspace,
            codex_path=codex_path,
            codex_home=codex_home,
            json_output=json_output,
        )
    )


@observe_app.command("drain")
def observe_drain_cmd(
    workspace: Annotated[
        str | None,
        typer.Option(
            "--workspace",
            help="Restrict delivery to one workspace; default drains all pending commitments.",
        ),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Deliver pending structural observations and summarize exact routing outcomes."""

    _finish(_observe_operation("drain_observation")(workspace=workspace, json_output=json_output))


@observe_app.command("reclaim")
def observe_reclaim_cmd(
    workspace: Annotated[
        str,
        typer.Option("--workspace", help="Workspace path (commitment only stored)."),
    ],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Drop quarantined observation detail, recording the drop in eviction evidence.

    Destructive like grant/pause/revoke, so the workspace is explicit — no cwd default.
    """

    _finish(_observe_operation("reclaim_observation")(workspace=workspace, json_output=json_output))


@observe_app.command("grant")
def observe_grant_cmd(
    workspace: Annotated[str, typer.Option("--workspace", help="Workspace path to consent.")],
) -> None:
    """One-time observation consent; stores a private workspace commitment only."""

    _finish(_observe_operation("grant_observation")(workspace=workspace))


@observe_app.command("content-enable")
def observe_content_enable_cmd(
    workspace: Annotated[str, typer.Option("--workspace", help="Workspace path to consent.")],
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            help=(
                "Versioned native-host content profile; use the exact profile emitted by the "
                "host integration renderer."
            ),
        ),
    ],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Enable one versioned native-host content capture arm."""

    _finish(
        _observe_operation("enable_observation_content")(
            workspace=workspace, profile=profile, json_output=json_output
        )
    )


@observe_app.command("content-disable")
def observe_content_disable_cmd(
    workspace: Annotated[str, typer.Option("--workspace")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", help="Disable one profile; omit to disable all profiles."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Disable one native-host content arm or all native-host content capture."""

    _finish(
        _observe_operation("disable_observation_content")(
            workspace=workspace, profile=profile, json_output=json_output
        )
    )


@observe_app.command("content-status")
def observe_content_status_cmd(
    workspace: Annotated[str, typer.Option("--workspace")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show exact native-host content arms and their active state."""

    _finish(
        _observe_operation("observation_content_status")(
            workspace=workspace, json_output=json_output
        )
    )


_CAPACITY_HELP = (
    "standard (recommended, 512), larger (2048), largest (8192), custom (with --queue-count "
    "64..8192), or none (no FinishUP cap; reports why it is unavailable)"
)
_QUEUE_COUNT_HELP = "Custom queue count from 64 to 8192 rows; only with --capacity custom."


@observe_app.command("selection-status")
def observe_selection_status_cmd(
    workspace: Annotated[str, typer.Option("--workspace")],
    session_id: Annotated[
        str | None,
        typer.Option(
            "--session-id",
            help="Optional current host session token; status stores only its commitment.",
        ),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show selected/effective observation detail and capacity."""

    _finish(
        _observe_operation("observation_selection_status")(
            workspace=workspace,
            session_id=session_id,
            json_output=json_output,
        )
    )


@observe_app.command("selection-preview")
def observe_selection_preview_cmd(
    workspace: Annotated[str, typer.Option("--workspace")],
    detail: Annotated[
        str,
        typer.Option("--detail", help="focused or detailed"),
    ],
    capacity: Annotated[
        str,
        typer.Option("--capacity", help=_CAPACITY_HELP),
    ],
    queue_count: Annotated[
        int | None,
        typer.Option("--queue-count", help=_QUEUE_COUNT_HELP),
    ] = None,
    session_id: Annotated[str | None, typer.Option("--session-id")] = None,
    persist: Annotated[
        bool,
        typer.Option(
            "--persist",
            help="Preview an explicit workspace default instead of a session override.",
        ),
    ] = False,
    expires_at: Annotated[
        str | None,
        typer.Option("--expires-at", help="RFC3339 UTC expiry (optional)."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Preview a detail/capacity choice before owner apply."""

    _finish(
        _observe_operation("observation_selection_preview")(
            workspace=workspace,
            detail=detail,
            capacity=capacity,
            queue_count=queue_count,
            session_id=session_id,
            persist=persist,
            expires_at=expires_at,
            json_output=json_output,
        )
    )


@observe_app.command("selection-apply")
def observe_selection_apply_cmd(
    workspace: Annotated[str, typer.Option("--workspace")],
    detail: Annotated[str, typer.Option("--detail", help="focused or detailed")],
    capacity: Annotated[
        str,
        typer.Option("--capacity", help=_CAPACITY_HELP),
    ],
    queue_count: Annotated[
        int | None,
        typer.Option("--queue-count", help=_QUEUE_COUNT_HELP),
    ] = None,
    session_id: Annotated[str | None, typer.Option("--session-id")] = None,
    persist: Annotated[
        bool,
        typer.Option(
            "--persist",
            help="Persist for the workspace; without it the setting is session-scoped.",
        ),
    ] = False,
    expires_at: Annotated[
        str | None,
        typer.Option("--expires-at", help="RFC3339 UTC expiry (optional)."),
    ] = None,
    accept: Annotated[
        bool,
        typer.Option(
            "--accept",
            help="Accept the exact selection preview shown by --preview-digest.",
        ),
    ] = False,
    preview_digest: Annotated[
        str | None,
        typer.Option("--preview-digest", help="Exact digest returned by selection-preview."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Apply an exact owner-selected detail/capacity preview."""

    _finish(
        _observe_operation("set_observation_selection")(
            workspace=workspace,
            detail=detail,
            capacity=capacity,
            queue_count=queue_count,
            session_id=session_id,
            persist=persist,
            expires_at=expires_at,
            accept=accept,
            preview_digest=preview_digest,
            json_output=json_output,
        )
    )


@observe_app.command("selection-revoke")
def observe_selection_revoke_cmd(
    workspace: Annotated[str, typer.Option("--workspace")],
    session_id: Annotated[str | None, typer.Option("--session-id")] = None,
    persist: Annotated[
        bool,
        typer.Option("--persist", help="Revoke the persisted workspace default."),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Revoke a session/workspace selection and restore the safe fallback."""

    _finish(
        _observe_operation("revoke_observation_selection")(
            workspace=workspace,
            session_id=session_id,
            persist=persist,
            json_output=json_output,
        )
    )


@observe_app.command("protect-read")
def observe_protect_read_cmd(
    workspace: Annotated[str, typer.Option("--workspace")],
    session_id: Annotated[str, typer.Option("--session-id")],
    reference: Annotated[
        str,
        typer.Option(
            "--reference",
            help="Existing obligation, claim, finding, or verification reference.",
        ),
    ],
    count: Annotated[int, typer.Option("--count", min=1, max=32)] = 1,
    expires_at: Annotated[
        str | None,
        typer.Option("--expires-at", help="RFC3339 UTC expiry (optional)."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Protect the next bounded session reads within existing authority."""

    _finish(
        _observe_operation("protect_observation_read")(
            workspace=workspace,
            session_id=session_id,
            reference=reference,
            count=count,
            expires_at=expires_at,
            json_output=json_output,
        )
    )


@observe_app.command("promote")
def observe_promote_cmd(
    workspace: Annotated[str, typer.Option("--workspace")],
    source_identity: Annotated[
        str,
        typer.Option(
            "--source-identity",
            help="Exact retained observation source identity to promote.",
        ),
    ],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Promote a still-retained observation identity without new capture."""

    _finish(
        _observe_operation("promote_observation")(
            workspace=workspace,
            source_identity=source_identity,
            json_output=json_output,
        )
    )


@observe_app.command("pause")
def observe_pause_cmd(
    workspace: Annotated[str, typer.Option("--workspace")],
) -> None:
    """Pause new observation ingest while retaining consent and evidence."""

    _finish(_observe_operation("pause_observation")(workspace=workspace))


@observe_app.command("resume")
def observe_resume_cmd(
    workspace: Annotated[str, typer.Option("--workspace")],
) -> None:
    """Resume observation ingest after pause."""

    _finish(_observe_operation("resume_observation")(workspace=workspace))


@observe_app.command("revoke")
def observe_revoke_cmd(
    workspace: Annotated[str, typer.Option("--workspace")],
) -> None:
    """Stop new ingest permanently; retained evidence is kept."""

    _finish(_observe_operation("revoke_observation")(workspace=workspace))


@observe_app.command("reconcile")
def observe_reconcile_cmd(
    session_file: Annotated[str, typer.Option("--session-file", help="Codex session JSONL path.")],
    workspace: Annotated[str | None, typer.Option("--workspace")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Advance the session-stream cursor for a consented workspace."""

    _finish(
        _observe_operation("reconcile_session_stream")(
            session_file=session_file,
            workspace=workspace,
            json_output=json_output,
        )
    )


@observe_checks_app.command("preview")
def observe_checks_preview_cmd(
    workspace: Annotated[str | None, typer.Option("--workspace")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show exact policy bytes digest and proposed argv without activating it."""

    _finish(
        _observe_operation("observe_checks_preview")(workspace=workspace, json_output=json_output)
    )


@observe_checks_app.command("trust")
def observe_checks_trust_cmd(
    policy_digest: Annotated[str, typer.Option("--policy-digest")],
    workspace: Annotated[str | None, typer.Option("--workspace")] = None,
) -> None:
    """Trust only the exact raw policy digest currently present."""

    _finish(
        _observe_operation("observe_checks_trust")(workspace=workspace, policy_digest=policy_digest)
    )


@observe_checks_app.command("status")
def observe_checks_status_cmd(
    workspace: Annotated[str | None, typer.Option("--workspace")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show whether the current exact policy digest is trusted."""

    _finish(
        _observe_operation("observe_checks_status")(workspace=workspace, json_output=json_output)
    )


@observe_checks_app.command("revoke")
def observe_checks_revoke_cmd(
    workspace: Annotated[str | None, typer.Option("--workspace")] = None,
) -> None:
    """Revoke workspace check-policy activation."""

    _finish(_observe_operation("observe_checks_revoke")(workspace=workspace))


@observe_checks_app.command("run")
def observe_checks_run_cmd(
    workspace: Annotated[str | None, typer.Option("--workspace")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run exact trusted argv under the enforcing sandbox."""

    _finish(_observe_operation("observe_checks_run")(workspace=workspace, json_output=json_output))


_OWNER_VIEW_REFUSALS: Final = MappingProxyType(
    {
        "presence_unavailable": (
            "owner_view_unavailable: FinishUP cannot confirm it is you on this installation. The "
            "vault has no passphrase, and no operating-system confirmation could be shown: "
            "Touch ID or your login password needs macOS and a FinishUP service running in your "
            "desktop session (one started over SSH is expected not to show it), and Linux and "
            "WSL have none yet. "
            "The full receipt stays closed and nothing changed. Without --owner-view you get "
            "the receipt your agents get, with repository names withheld; to see what your "
            "change created, run 'git status --short' in your repository."
        ),
        "passphrase_in_credential_store": (
            "owner_view_unavailable: no system confirmation dialog can be shown here, and this "
            "vault's passphrase may be kept in the system credential store, or the store could "
            "not be read (FinishUP setup's system keychain choice generates one you were never "
            "shown), so FinishUP does not ask you to type it. Nothing was shown and nothing "
            "changed. If you chose that passphrase yourself, run the command again with "
            "--use-passphrase. To see what your change created, run 'git status --short' in "
            "your repository."
        ),
        "passphrase_unavailable": (
            "owner_view_unavailable: this vault has no passphrase to confirm with, so "
            "--use-passphrase cannot be used here. Run the command without it. Nothing changed."
        ),
        "ceremony_busy": (
            "owner_view_busy: another confirmation is already open on this computer, perhaps "
            "one an agent started, so this one did not start. If a system dialog is on screen, "
            "it is not for this command: cancel it, never approve it. If nothing is on screen, "
            "'finishup service restart' ends the other confirmation. Then run the command again. "
            "Nothing was shown and nothing changed."
        ),
        "passphrase_rate_limited": (
            "owner_view_refused: too many wrong passphrases, so FinishUP waits before accepting "
            "another (30 seconds after the third, growing to five minutes). Restarting the "
            "service does not clear this wait. Wait, then run the command again. Nothing was "
            "shown and nothing changed."
        ),
        "reauthentication_rate_limited": (
            "owner_view_refused: recent confirmations did not succeed, so FinishUP waits before "
            "asking again (5 seconds, growing to five minutes after repeated misses). Another "
            "program may have caused this; 'finishup service restart' clears the wait, and "
            "--use-passphrase confirms with a vault passphrase you chose. Nothing was shown and "
            "nothing changed."
        ),
        "presence_refused": (
            "owner_view_refused: the operating-system confirmation was cancelled or did not "
            "confirm it is you. Nothing was shown and nothing changed; run the command again "
            "to retry."
        ),
        "presence_timeout": (
            "owner_view_refused: the operating-system confirmation was not answered within "
            "a minute, so it closed. Nothing was shown and nothing changed; run the command "
            "again when you can answer it."
        ),
        "state_forbidden": (
            "owner_view_unavailable: the vault is locked or not set up. Run 'finishup service "
            "unlock' in your terminal, then ask again. Nothing changed."
        ),
        "trusted_console_required": (
            "owner_view_requires_terminal: the full receipt asks you to confirm it is you (Touch "
            "ID or your login password on a Mac, otherwise your vault passphrase) from a "
            "foreground terminal, and this command has none. Run 'finishup receipt --owner-view' "
            "yourself in your own terminal. Nothing changed."
        ),
        "target_invalid": (
            "owner_view_refused: this command's connection to FinishUP closed before the "
            "confirmation finished, so nothing can be shown. Run the command again. Nothing "
            "changed."
        ),
        "secret_rejected": (
            "owner_view_refused: the passphrase did not match. Nothing was shown and nothing "
            "changed; run the command again to retry."
        ),
    }
)


async def _authorize_owner_receipt_view(
    client: object, request: ReceiptRequest, *, use_passphrase: bool = False
) -> int | None:
    """Run the owner-view ceremony for this request on this connection; None when granted."""

    from finishup.cli.unlock import (
        HumanCeremonyCliError,
        authorize_owner_receipt_view,
        owner_view_confirmation_code,
    )
    from finishup.service.confidential_client import ConfidentialClientError

    target_for = getattr(client, "owner_receipt_view_target", None)
    if target_for is None:
        _stderr(_OWNER_VIEW_REFUSALS["presence_unavailable"])
        return exit_code_for(PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED)
    target = target_for(request)
    try:
        await authorize_owner_receipt_view(target, use_passphrase=use_passphrase)
    except (ConfidentialClientError, HumanCeremonyCliError) as error:
        reason = error.reason
        key = "presence_unavailable" if reason == "reauthentication_unavailable" else reason
        line = _OWNER_VIEW_REFUSALS.get(key)
        if line is not None:
            _stderr(line)
            if key == "ceremony_busy":
                # The code a dialog for this command would show; any other code is not ours.
                _stderr(
                    "This command's confirmation code would be "
                    f"{owner_view_confirmation_code(target)}."
                )
            return exit_code_for(PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED)
        failure = _trusted_exception_failure(error)
        return failure if failure is not None else _usage_failure()
    return None


def _workflow_command(method: str, request_type: type[BaseModel]) -> Callable[..., None]:
    def command(
        input_path: _INPUT = None,
        request: _INLINE = None,
        json_output: _JSON = False,
        deadline_ms: _DEADLINE = None,
    ) -> None:
        _finish(
            run_async(
                lambda: _call_workflow(
                    method, request_type, input_path, request, json_output, deadline_ms
                )
            )
        )

    return command


_TASK_STATEMENT_FILE = Annotated[
    str | None,
    typer.Option(
        "--task-statement-file",
        help=(
            "UTF-8 file (or - for stdin) holding the user's request verbatim; recorded as "
            "task_statement."
        ),
    ),
]


@app.command("start")
def start_command(
    input_path: _INPUT = None,
    request: _INLINE = None,
    task_statement_file: _TASK_STATEMENT_FILE = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
) -> None:
    _finish(
        run_async(
            lambda: _call_workflow(
                "start",
                StartRequest,
                input_path,
                request,
                json_output,
                deadline_ms,
                task_statement_file=task_statement_file,
            )
        )
    )


app.command("publish-work")(_workflow_command("publish_work", PublishWorkRequest))


@app.command("check")
def check_command(
    input_path: _INPUT = None,
    request: _INLINE = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
    await_observations: Annotated[
        bool,
        typer.Option(
            "--await-observations",
            help=(
                "Before checking, wait up to about 3 seconds for this task's hook observations "
                "that are still being delivered; the result reports whether they all arrived."
            ),
        ),
    ] = False,
) -> None:
    _finish(
        run_async(
            lambda: _call_workflow(
                "check",
                CheckRequest,
                input_path,
                request,
                json_output,
                deadline_ms,
                await_observations=await_observations,
            )
        )
    )


app.command("respond")(_workflow_command("respond", RespondRequest))
app.command("status")(_workflow_command("status", StatusRequest))


@app.command("receipt")
def receipt_command(
    input_path: _INPUT = None,
    request: _INLINE = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
    owner_view: Annotated[
        bool,
        typer.Option(
            "--owner-view",
            help=(
                "Show the full receipt, including repository names your agents do not see. "
                "You confirm it is you (on macOS Touch ID or your login password, otherwise "
                "your vault passphrase) from a foreground terminal, for this one request on "
                "this command's own connection; nothing else changes."
            ),
        ),
    ] = False,
    use_passphrase: Annotated[
        bool,
        typer.Option(
            "--use-passphrase",
            help=(
                "With --owner-view: confirm with your vault passphrase instead of a system "
                "dialog, for example when you are connected over SSH and the dialog would appear "
                "on the Mac's own screen. You type it at a hidden prompt, never on the command "
                "line."
            ),
        ),
    ] = False,
) -> None:
    _finish(
        run_async(
            lambda: _call_workflow(
                "receipt",
                ReceiptRequest,
                input_path,
                request,
                json_output,
                deadline_ms,
                owner_view=owner_view,
                use_passphrase=use_passphrase,
            )
        )
    )


@app.command("closure-prepare")
def closure_prepare_command(
    session_id: Annotated[str, typer.Option("--session-id")],
    writer_id: Annotated[str, typer.Option("--writer-id")],
    input_path: _INPUT = None,
    output_path: Annotated[
        Path | None,
        typer.Option(
            "--output",
            help=(
                "Save the complete result to this file (owner-only, replaced whole) and print "
                "a short summary instead; query the file rather than preparing again."
            ),
        ),
    ] = None,
) -> None:
    """Read closure inventory or prepare one explicitly selected phase; never publish."""

    from finishup.cli.closure import (
        PREPARATION_REMEDIATIONS,
        Selection,
        prepare_closure,
        write_prepared_output,
    )

    async def prepare() -> None:
        selection = (
            Selection()
            if input_path is None
            else cast(Selection, _request_model(Selection, input_path, None))
        )
        client = await build_service_client()
        try:
            result = await prepare_closure(client.status, session_id, writer_id, selection)
        finally:
            await client.close()
        if output_path is None:
            _stdout_json(result)
        else:
            _stdout_json(write_prepared_output(result, output_path))

    try:
        run_async(prepare)
    except (OSError, ProtocolValueError, ValidationError):
        _finish(_usage_failure())
    except ValueError as error:
        reason = str(error)
        remediation = PREPARATION_REMEDIATIONS.get(reason)
        if remediation is None:
            _finish(_usage_failure())
        else:
            _stderr(f"{reason}: {remediation}")
            _finish(2)
    except ControlError as error:
        _finish(_control_failure(error))


@app.command("closure-schema")
def closure_schema_command() -> None:
    """Print the closed selection-input schema for closure-prepare."""

    from finishup.cli.closure import Selection

    _stdout_json(cast(JsonValue, Selection.model_json_schema()))


@cache
def support_methods_carrying_schema_version() -> frozenset[str]:
    """Support methods whose frozen request body declares the const ``schema_version`` field.

    Derived from the frozen control-request schema rather than listed here, so a method added or
    changed there cannot leave this behind.
    """

    document = schema_document_for("control-request", "1.0.0").json_schema
    # The catalog hands back frozen values, so JSON arrays arrive as tuples rather than lists.
    branches = document.get("oneOf")
    if not isinstance(branches, Sequence) or type(branches) is str:
        return frozenset()  # pragma: no cover - the frozen schema is a oneOf of calls
    definitions = document.get("$defs")
    defs: Mapping[str, JsonValue] = (
        cast(Mapping[str, JsonValue], definitions) if isinstance(definitions, Mapping) else {}
    )
    methods: set[str] = set()
    for raw in cast(Sequence[JsonValue], branches):
        if not isinstance(raw, Mapping):
            continue
        properties = cast(Mapping[str, JsonValue], raw).get("properties")
        if not isinstance(properties, Mapping):
            continue
        fields = cast(Mapping[str, JsonValue], properties)
        method_node = fields.get("method")
        body_node = fields.get("body")
        if not isinstance(method_node, Mapping) or not isinstance(body_node, Mapping):
            continue
        name = cast(Mapping[str, JsonValue], method_node).get("const")
        reference = cast(Mapping[str, JsonValue], body_node).get("$ref")
        if type(name) is not str or type(reference) is not str:
            continue
        body = defs.get(reference.removeprefix("#/$defs/"))
        if not isinstance(body, Mapping):
            continue
        required = cast(Mapping[str, JsonValue], body).get("required")
        if isinstance(required, Sequence) and "schema_version" in required:
            methods.add(name)
    return frozenset(methods)


def with_body_schema_version(method: str, request: JsonObject) -> JsonObject:
    """Fill in ``schema_version`` when the method's body requires it and the input omitted it.

    The field is a ``const``: there is exactly one value the frozen schema accepts, so an input
    file without it is unambiguous rather than incomplete. Omitting it used to fail frame encoding
    before the request left the process, and the caller saw only a closed ``invalid_request`` that
    named no field. An input that supplies its own value is passed through untouched and still
    validated, so a wrong version is still rejected rather than silently corrected.
    """

    if method not in support_methods_carrying_schema_version() or "schema_version" in request:
        return request
    return JsonObject({**dict(request), "schema_version": "1.0.0"})


async def _call_support(
    method: str,
    input_path: str | None,
    inline: str | None,
    json_output: bool,
    deadline_ms: int | None,
) -> int:
    try:
        if input_path is None and inline is None and method == "privacy_get_effective":
            scoped = _machine_scope_request_or_none()
            if scoped is None:
                return 2
            request = scoped
        else:
            request = _json_object(input_path, inline)
            if method == "privacy_get_effective" and len(request) == 0:
                scoped = _machine_scope_request_or_none()
                if scoped is None:
                    return 2
                request = scoped
        # Every support body passes through here, whichever branch built it, so the normalization
        # is one step rather than a property of one path.
        request = with_body_schema_version(method, request)
        client = await build_service_client()
        try:
            result = await getattr(client, method)(request, deadline_ms=deadline_ms)
        finally:
            await client.close()
        _human_or_json(result, json_output=json_output)
        if method == "privacy_get_effective" and not json_output and sys.stdout.isatty():
            plain = _plain_json(result)
            for line in (
                _effective_task_statement_line(plain),
                _effective_excerpt_limits_line(plain),
                _effective_credential_heuristic_line(plain),
            ):
                if line is not None:
                    typer.echo(line)
        return 0
    except (OSError, ProtocolValueError, ValidationError, ValueError):
        return _usage_failure()
    except ControlError as error:
        return _control_failure(error)


def _effective_credential_heuristic_line(value: JsonValue) -> str | None:
    """Say plainly when the owner turned the possible-credential filter off (issue #982).

    ``None`` for the default and for any document that is not the expected shape.
    """

    try:
        policy = cast(Mapping[str, JsonValue], cast(Mapping[str, JsonValue], value)["policy"])
    except (KeyError, TypeError):
        return None
    if policy.get("credential_heuristic") != "disabled":
        return None
    scope = policy.get("effective_scope")
    kind = cast(Mapping[str, JsonValue], scope).get("kind") if isinstance(scope, Mapping) else None
    if kind == "machine":
        # The default ``privacy show`` reads the installation row: it is the default a new
        # repository grant starts from, not what any granted repository applies (owner decision).
        return (
            "Possible-credential filter, installation default: off. New repository grants start "
            "with the external reviewer's filter off; a repository with a grant follows its own "
            "grant ('finishup status' shows it). Restore the default with "
            "'finishup privacy credential-heuristic enable --machine-default'."
        )
    return (
        "Possible-credential filter for this repository: off. Values that only look like "
        "passwords or tokens may be sent to the external AI reviewer as written; local outputs "
        "keep the filter, and known credential shapes, private keys and URL passwords are still "
        "withheld. Turn it back on with 'finishup privacy credential-heuristic enable'."
    )


def _effective_task_statement_line(value: JsonValue) -> str | None:
    """Say plainly whether the effective policy sends the task statement (issue #908).

    Read from the structural policy document only; ``None`` when its shape is not the expected
    effective-policy body, so the terminal never guesses.
    """

    from finishup.domain.task_statement import task_statement_disclosure_text

    try:
        policy = cast(Mapping[str, JsonValue], cast(Mapping[str, JsonValue], value)["policy"])
        selection = cast(Mapping[str, JsonValue], policy["review_selection"])
        sections = cast(list[JsonValue], selection["sections"])
        llm = next(
            cast(Mapping[str, JsonValue], row)
            for row in cast(list[JsonValue], policy["channel_policies"])
            if cast(Mapping[str, JsonValue], row)["channel"] == "llm_inference"
        )
        categories = cast(list[JsonValue], llm["allowed_categories"])
        text = task_statement_disclosure_text(
            section_selected="task_statement" in sections,
            channel_sends_task_description=llm["enabled"] is True
            and "task_description" in categories,
            # A named recipe without the section is the preset approved before it existed. Read
            # from the selection itself: the wire version also moves for other fields (#982).
            predates_section="task_statement" not in sections
            and policy["review_context_profile"] in {"goal_aware", "assisted", "expanded"},
        )
    except (KeyError, StopIteration, TypeError):
        return None
    return "Task statement: " + text


def _effective_excerpt_limits_line(value: JsonValue) -> str | None:
    """The approved excerpt limits beside the current recipe's (issue #907 Phase 1b).

    ``None`` when the body is not a readable effective-policy document, so the terminal never
    guesses.
    """

    from finishup.adapters.privacy.catalog import decode_privacy_policy_canonical
    from finishup.cli.privacy_setup import policy_excerpt_limits_disclosure
    from finishup.protocol.canonical import canonical_encode

    try:
        policy = decode_privacy_policy_canonical(
            canonical_encode(cast(Mapping[str, JsonValue], value)["policy"])
        )
    except (KeyError, TypeError, ValueError):
        return None
    return "Excerpt limits: " + policy_excerpt_limits_disclosure(policy)


def _support_command(method: str) -> Callable[..., None]:
    def command(
        input_path: _INPUT = None,
        request: _INLINE = None,
        json_output: _JSON = False,
        deadline_ms: _DEADLINE = None,
    ) -> None:
        _finish(
            run_async(lambda: _call_support(method, input_path, request, json_output, deadline_ms))
        )

    return command


app.command("import")(_support_command("import_codex_jsonl"))
app.command("review")(_support_command("review"))
backup_app.command("preview")(_support_command("backup_preview"))
backup_app.command("execute")(_support_command("backup_execute"))
restore_app.command("preview")(_support_command("restore_preview"))
restore_app.command("execute")(_support_command("restore_execute"))
migrate_app.command("preview")(_support_command("migrate_preview"))
migrate_app.command("execute")(_support_command("migrate_execute"))
privacy_app.command("show")(_support_command("privacy_get_effective"))
privacy_app.command("propose")(_support_command("privacy_propose_policy"))
privacy_app.command("tighten")(_support_command("privacy_tighten_policy"))


async def _run_privacy_setup_command() -> int:
    from finishup.cli.privacy_setup import run_privacy_setup
    from finishup.cli.unlock import HumanCeremonyCliError

    try:
        report = await run_privacy_setup(
            recipe_hint="assisted_review",
            offer_recommended=True,
            # ADR-049 review round 3: where agent opt-in needs a reviewing recipe, list them.
            ai_review_add_on_when_hybrid=True,
        )
    except ControlError as error:
        return _control_failure(error)
    except (HumanCeremonyCliError, OSError, ValueError) as error:
        reason = getattr(error, "reason", None)
        typer.echo(
            f"privacy_setup_failed: {reason if type(reason) is str else 'privacy_setup_failed'}",
            err=True,
        )
        return 20
    if report.outcome == "failed":
        typer.echo(f"privacy_setup_failed: {report.reason or 'invalid'}", err=True)
        return 20
    _human_or_json(report, json_output=False)
    return 0


@privacy_app.command("setup")
def privacy_setup() -> None:
    """Review privacy choices and apply them through the trusted local ceremony."""

    _finish(run_async(_run_privacy_setup_command))


async def _run_credential_heuristic_command(
    action: str, json_output: bool, machine_default: bool = False
) -> int:
    from finishup.cli.privacy_setup import run_credential_heuristic_change
    from finishup.cli.provider_status import MachineScopeError
    from finishup.cli.unlock import HumanCeremonyCliError
    from finishup.domain.privacy import CredentialHeuristic

    setting = CredentialHeuristic.DISABLED if action == "disable" else CredentialHeuristic.ENFORCED
    try:
        report = await run_credential_heuristic_change(setting, machine_default=machine_default)
    except ControlError as error:
        return _control_failure(error, json_output=json_output)
    except MachineScopeError as error:
        _stderr(f"machine_scope_unavailable: {error.reason}: {error.remediation}")
        return 2
    except (HumanCeremonyCliError, OSError, ValueError) as error:
        reason = getattr(error, "reason", None)
        typer.echo(
            f"privacy_credential_heuristic_failed: "
            f"{reason if type(reason) is str else 'privacy_credential_heuristic_failed'}",
            err=True,
        )
        return 20
    if report.outcome == "failed":
        typer.echo(f"privacy_credential_heuristic_failed: {report.reason or 'invalid'}", err=True)
        return 20
    if report.reason == "repository_privacy_grant_missing" and not json_output:
        typer.echo(
            "This repository has no privacy grant, so nothing reaches the external reviewer "
            "here and there is no repository setting to turn back on. A new grant starts from "
            "the installation default; to turn that default back on, run "
            "'finishup privacy credential-heuristic enable --machine-default'.",
            err=True,
        )
    _human_or_json(
        {
            "credential_heuristic": setting.value,
            "scope": "machine_default" if machine_default else "repository",
            "outcome": report.outcome,
            **({"proposal_id": report.proposal_id} if report.proposal_id is not None else {}),
            **({"reason": report.reason} if report.reason is not None else {}),
        },
        json_output=json_output,
    )
    return 0 if report.outcome in {"configured", "unchanged"} else 20


_CONVERSATION_SETTINGS: Final = {
    "agent-opt-in": "local_agent_opt_in",
    "owner-approval": "local_owner_approval",
    "local-only": "local_only",
    "ai-powered": "ai_powered",
}


async def _run_conversation_review_command(setting_name: str, json_output: bool) -> int:
    from finishup.cli.privacy_setup import run_conversation_review_change
    from finishup.cli.unlock import HumanCeremonyCliError
    from finishup.domain.privacy import ConversationReview

    token = _CONVERSATION_SETTINGS.get(setting_name)
    if token is None:
        typer.echo(
            "privacy_conversations_invalid: choose agent-opt-in, owner-approval, local-only, "
            "or ai-powered",
            err=True,
        )
        return 2
    setting = ConversationReview(token)
    try:
        report = await run_conversation_review_change(setting)
    except ControlError as error:
        return _control_failure(error, json_output=json_output)
    except (HumanCeremonyCliError, OSError, ValueError) as error:
        reason = getattr(error, "reason", None)
        typer.echo(
            "privacy_conversations_failed: "
            f"{reason if type(reason) is str else 'privacy_conversations_failed'}",
            err=True,
        )
        return 20
    if report.outcome == "failed":
        typer.echo(f"privacy_conversations_failed: {report.reason or 'invalid'}", err=True)
        if report.reason == "local_terminal_required":
            # `finishup --privacy` sets up a grant; name it only where that is what is missing.
            grant_needed = (
                report.grant_state != "granted" and setting is not ConversationReview.LOCAL_ONLY
            )
            typer.echo(
                "This needs your approval in a local terminal: run this command there"
                + (
                    ", or 'finishup --privacy' to set up this repository's privacy policy."
                    if grant_needed
                    else "."
                ),
                err=True,
            )
        return 20
    if report.reason == "repository_privacy_grant_missing" and not json_output:
        typer.echo(
            "This repository has no privacy policy of its own yet, so no work is sent for "
            "AI-powered review here. Nothing changed; run this command in a local terminal to "
            "record the setting.",
            err=True,
        )
    _human_or_json(
        {
            "conversation_review": setting.value,
            "scope": "repository",
            "outcome": report.outcome,
            **({"proposal_id": report.proposal_id} if report.proposal_id is not None else {}),
            **({"reason": report.reason} if report.reason is not None else {}),
        },
        json_output=json_output,
    )
    return 0 if report.outcome in {"configured", "unchanged"} else 20


privacy_conversations_app = typer.Typer(
    help=(
        "Choose how this repository's tasks use AI-powered review. Every task starts "
        "with FinishUP's local checks unless you choose ai-powered. Moving toward local checks "
        "or your approval applies at once; anything that needs less of you applies only after "
        "the trusted local approval on this terminal, and never sends more than the "
        "repository's privacy policy allows."
    ),
    no_args_is_help=True,
)
privacy_app.add_typer(privacy_conversations_app, name="conversations")


@privacy_conversations_app.command("agent-opt-in")
def privacy_conversations_agent_opt_in(json_output: _JSON = False) -> None:
    """Recommended: tasks start local; your agent can turn on AI-powered review when it helps."""

    _finish(run_async(lambda: _run_conversation_review_command("agent-opt-in", json_output)))


@privacy_conversations_app.command("owner-approval")
def privacy_conversations_owner_approval(json_output: _JSON = False) -> None:
    """Tasks start local; each review an agent turns on waits for your approval."""

    _finish(run_async(lambda: _run_conversation_review_command("owner-approval", json_output)))


@privacy_conversations_app.command("local-only")
def privacy_conversations_local_only(json_output: _JSON = False) -> None:
    """Every task runs local checks only; agents may not turn on AI-powered review."""

    _finish(run_async(lambda: _run_conversation_review_command("local-only", json_output)))


@privacy_conversations_app.command("ai-powered")
def privacy_conversations_ai_powered(json_output: _JSON = False) -> None:
    """Every task runs with AI-powered review (the behaviour before this setting existed)."""

    _finish(run_async(lambda: _run_conversation_review_command("ai-powered", json_output)))


@privacy_conversations_app.command("status")
def privacy_conversations_status(json_output: _JSON = False) -> None:
    """Show this repository's setting (read-only)."""

    _finish(run_async(lambda: _run_conversation_review_status(json_output)))


async def _run_conversation_review_status(json_output: bool) -> int:
    from finishup.cli.privacy_setup import get_privacy_setup_snapshot
    from finishup.cli.render import conversation_setting_text

    try:
        snapshot = await get_privacy_setup_snapshot(Path.cwd())
    except ControlError as error:
        return _control_failure(error, json_output=json_output)
    except (OSError, ValueError):
        typer.echo("privacy_conversations_failed: privacy_setup_unreadable", err=True)
        return 20
    policy = snapshot.composed_policy
    effective = policy.effective_conversation_review.value
    if not json_output:
        typer.echo(
            conversation_setting_text(
                effective,
                explicit=policy.conversation_review is not None,
                grant_missing=snapshot.grant_state == "missing",
                migration_pending=snapshot.migration_state
                in {"legacy_route_available", "first_repository_available"},
            )
        )
        return 0
    _human_or_json(
        {
            "conversation_review": effective,
            "explicit": policy.conversation_review is not None,
            "scope": "repository",
            "grant_state": snapshot.grant_state,
        },
        json_output=json_output,
    )
    return 0


async def _run_input_root_command(action: str, value: str, json_output: bool) -> int:
    """Admit or remove an outside-workspace input root for this repository (issue #1082)."""

    from finishup.cli.privacy_setup import run_input_root_change
    from finishup.cli.unlock import HumanCeremonyCliError

    try:
        report = await run_input_root_change("add" if action == "add" else "remove", value)
    except ControlError as error:
        return _control_failure(error, json_output=json_output)
    except (HumanCeremonyCliError, OSError, ValueError) as error:
        reason = getattr(error, "reason", None)
        typer.echo(
            f"privacy_input_roots_failed: {reason if type(reason) is str else 'invalid'}",
            err=True,
        )
        return 20
    if report.outcome == "failed":
        typer.echo(f"privacy_input_roots_failed: {report.reason or 'invalid'}", err=True)
        if report.reason == "input_root_invalid":
            typer.echo(
                "Name an existing directory by its absolute path, with no link on the way. The "
                "filesystem root, hidden directories and system trees such as /etc are refused.",
                err=True,
            )
        elif report.reason == "local_terminal_required":
            typer.echo(
                "Admitting a directory needs your approval in a local terminal: run this "
                "command there.",
                err=True,
            )
        return 20
    if report.reason == "repository_privacy_grant_missing" and not json_output:
        typer.echo(
            "This repository has no privacy policy of its own yet, so nothing is sent for "
            "AI-powered review here. Nothing changed; run 'finishup --privacy' first.",
            err=True,
        )
    _human_or_json(
        {
            "action": action,
            "scope": "repository",
            "outcome": report.outcome,
            **({"proposal_id": report.proposal_id} if report.proposal_id is not None else {}),
            **({"reason": report.reason} if report.reason is not None else {}),
        },
        json_output=json_output,
    )
    return 0 if report.outcome in {"configured", "unchanged"} else 20


async def _run_input_roots_status(json_output: bool) -> int:
    from finishup.cli.privacy_setup import get_privacy_setup_snapshot

    try:
        snapshot = await get_privacy_setup_snapshot(Path.cwd())
    except ControlError as error:
        return _control_failure(error, json_output=json_output)
    except (OSError, ValueError):
        typer.echo("privacy_input_roots_failed: privacy_setup_unreadable", err=True)
        return 20
    roots = list(snapshot.composed_policy.admitted_input_roots)
    if not json_output:
        if not roots:
            typer.echo(
                "No directory outside the workspace is admitted for this repository's reviews."
            )
        else:
            typer.echo(
                "Files the task names beneath these directories may reach this repository's "
                "AI-powered review packets as read-only task inputs:"
            )
            for root in roots:
                typer.echo(f"  {root}")
        return 0
    _human_or_json(
        {
            "admitted_input_roots": cast(JsonValue, roots),
            "scope": "repository",
            "grant_state": snapshot.grant_state,
        },
        json_output=json_output,
    )
    return 0


privacy_input_roots_app = typer.Typer(
    help=(
        "Admit directories outside the workspace (for example a shared specification or dataset "
        "folder) whose files the task names, so AI-powered review can read them as read-only "
        "task inputs. Admitting applies only after the trusted local approval on this terminal; "
        "removing applies at once. Nothing is sent unless this repository's privacy policy "
        "already sends repository excerpts."
    ),
    no_args_is_help=True,
)
privacy_app.add_typer(privacy_input_roots_app, name="input-roots")
_ROOT_PATH = Annotated[str, typer.Argument(help="Absolute path of an existing directory.")]


@privacy_input_roots_app.command("add")
def privacy_input_roots_add(path: _ROOT_PATH, json_output: _JSON = False) -> None:
    """Admit one directory for this repository (trusted local approval required)."""

    _finish(run_async(lambda: _run_input_root_command("add", path, json_output)))


@privacy_input_roots_app.command("remove")
def privacy_input_roots_remove(path: _ROOT_PATH, json_output: _JSON = False) -> None:
    """Stop admitting one directory for this repository (applies at once)."""

    _finish(run_async(lambda: _run_input_root_command("remove", path, json_output)))


@privacy_input_roots_app.command("status")
def privacy_input_roots_status(json_output: _JSON = False) -> None:
    """Show the directories this repository admits (read-only)."""

    _finish(run_async(lambda: _run_input_roots_status(json_output)))


privacy_credential_heuristic_app = typer.Typer(
    help=(
        "Turn the possible-credential filter for the external AI reviewer off or back on for "
        "this repository (owner opt-out). Local outputs always keep it; known credential shapes, "
        "private keys and URL passwords are always withheld."
    ),
    no_args_is_help=True,
)
privacy_app.add_typer(privacy_credential_heuristic_app, name="credential-heuristic")
_MACHINE_DEFAULT = Annotated[
    bool,
    typer.Option(
        "--machine-default",
        help="Change the installation-wide default that repositories without a grant inherit.",
    ),
]


@privacy_credential_heuristic_app.command("disable")
def privacy_credential_heuristic_disable(
    machine_default: _MACHINE_DEFAULT = False, json_output: _JSON = False
) -> None:
    """Stop withholding, from the external reviewer, values that only look like credentials.

    Applies to this repository's privacy grant (or, without one, the grant you create now) only
    after the trusted local approval on this terminal.
    """

    _finish(
        run_async(
            lambda: _run_credential_heuristic_command("disable", json_output, machine_default)
        )
    )


@privacy_credential_heuristic_app.command("enable")
def privacy_credential_heuristic_enable(
    machine_default: _MACHINE_DEFAULT = False, json_output: _JSON = False
) -> None:
    """Withhold values that look like credentials again for this repository (applies now)."""

    _finish(
        run_async(lambda: _run_credential_heuristic_command("enable", json_output, machine_default))
    )


async def _service_call(method: str, json_output: bool) -> int:
    try:
        client = await build_service_client()
        try:
            result = await getattr(client, method)()
        finally:
            await client.close()
        _human_or_json(result, json_output=json_output)
        if method == "service_status" and not json_output:
            from finishup.cli.service_installation import report_installation_naming

            # A Yoetz-era install used in place is named on stderr; stdout is unchanged (ADR-048).
            report_installation_naming(_stderr)
        return 0
    except ControlError as error:
        return _control_failure(error, json_output=json_output)


def _service_command(method: str) -> Callable[..., None]:
    def command(json_output: _JSON = False) -> None:
        _finish(run_async(lambda: _service_call(method, json_output)))

    return command


service_app.command("status")(_service_command("service_status"))
service_app.command("lock")(_service_command("lock"))
service_app.command("stop")(_service_command("stop"))


async def _service_restart(json_output: bool) -> int:
    """Replace the running service, compatible or not, with one of this installation.

    A compatible holder is stopped through its ordinary control method; an incompatible holder
    (another installation's service that rejects this CLI's hello) is asked to stop through the
    same bounded-shutdown signal on-demand startup uses, and so is a holder that rejects the
    hello while its stamp carries no identity field, which only this explicit restart may
    replace. The successor is then started on demand and its status reported.
    """

    from finishup.service.client import (
        connect_service_on_demand,
        handshake_failure,
        supersede_incompatible_service,
        wait_for_singleton_release,
    )

    deadline = time.monotonic() + 30.0
    holder_pid = _singleton_holder_pid()
    try:
        try:
            client = await build_service_client(workspace_locator=None)
        except ControlError as error:
            if error.reason in {"service_incompatible", "protocol_mismatch"}:
                # An explicit human restart may also replace a newer holder (a rollback) and a
                # holder stamped without any identity field.
                if not await supersede_incompatible_service(
                    deadline=deadline, replace_newer=True, replace_legacy=True
                ):
                    return _control_failure(error, json_output=json_output)
            elif handshake_failure(error) is not None:
                # A holder that closed this hello is replaced here only when its stamp carries
                # no identity field at all (an older FinishUP, or a compatible service whose stamp
                # lost its identity): this explicit restart is the one path allowed to replace
                # such a holder. One stamped with this installation's identity, or partly
                # readable, cannot be asked to stop over the handshake and is never signalled.
                if not await supersede_incompatible_service(
                    deadline=deadline, replace_newer=True, replace_legacy=True
                ):
                    return _control_failure(error, json_output=json_output)
            elif error.reason != "service_unavailable":
                return _control_failure(error, json_output=json_output)
        else:
            try:
                await client.stop()
            finally:
                await client.close()
        if holder_pid is not None and not await wait_for_singleton_release(
            holder_pid, deadline=deadline
        ):
            _stderr(
                _with_holder_pid(
                    "service_unavailable: the previous service did not release the singleton "
                    "within 30 seconds; wait and retry 'finishup service restart'"
                )
            )
            return exit_code_for(PublicErrorCode.SERVICE_UNAVAILABLE)
        successor = await connect_service_on_demand(
            ControlClientKind.CLI,
            workspace_locator=None,
            timeout_seconds=max(0.1, min(30.0, deadline - time.monotonic())),
            supersede_incompatible=False,
        )
        try:
            status = await successor.service_status()
        finally:
            await successor.close()
    except ControlError as error:
        return _control_failure(error, json_output=json_output)
    _human_or_json(status, json_output=json_output)
    return 0


@service_app.command("restart")
def service_restart(json_output: _JSON = False) -> None:
    """Stop the running service (even one from another installation) and start this one."""

    _finish(run_async(lambda: _service_restart(json_output)))


@service_app.command("run")
def service_run(
    startup_correlation_id: Annotated[
        str | None,
        typer.Option(
            "--startup-correlation-id",
            hidden=True,
            help="Internal: the err_… id the spawning process looks a startup failure up under.",
        ),
    ] = None,
) -> None:
    """Run the persistent service in the foreground."""

    if startup_correlation_id is not None:
        from finishup.protocol.ids import IdKind, validate_id

        try:
            validate_id(IdKind.CORRELATION, startup_correlation_id)
        except (TypeError, ValueError):
            _finish(_usage_failure())
    # Import-light: it must record a failure to import the daemon itself (#1040).
    from finishup.service.startup_failure import ServiceStartupError, record_startup_failure

    try:
        from finishup.service.daemon import main as daemon_main
    except ModuleNotFoundError as error:
        # A passphrase vault is part of the supported base installation.  The
        # daemon imports its Argon2 implementation while composing the vault,
        # so recognize only that exact absent module here rather than turning
        # an arbitrary broken import into an operator-facing dependency claim.
        if error.name != "cryptography.hazmat.primitives.kdf.argon2":
            failure = record_startup_failure(
                error, stage="import", correlation_id=startup_correlation_id
            )
            _stderr(failure.line())
            raise typer.Exit(exit_code_for(PublicErrorCode.INTERNAL_ERROR)) from None
        record_startup_failure(
            error,
            stage="import",
            correlation_id=startup_correlation_id,
            reason_code="passphrase_kdf_unavailable",
        )
        _stderr(
            "passphrase_kdf_unavailable: reinstall this FinishUP package before starting "
            "a passphrase vault"
        )
        raise typer.Exit(exit_code_for(PublicErrorCode.SERVICE_UNAVAILABLE)) from None
    except Exception as error:
        # A module that cannot load here (a native extension built for a newer C library) is
        # named by stage and exception class, never a bare internal_error.
        failure = record_startup_failure(
            error, stage="import", correlation_id=startup_correlation_id
        )
        _stderr(failure.line())
        raise typer.Exit(exit_code_for(PublicErrorCode.INTERNAL_ERROR)) from None

    # Free at this point: the daemon import above already composed the lifecycle module.
    from finishup.config.installation import InstanceIdentityError
    from finishup.config.models import ConfigError
    from finishup.config.paths import PathSafetyError
    from finishup.service.lifecycle import LifecycleError

    try:
        daemon_main(startup_correlation_id=startup_correlation_id)
    except ServiceStartupError as error:
        # Already recorded under the printed correlation id with its stage, exception class and
        # finishup origin; the harness that captures this stream gets the reason, not a bare token.
        _stderr(error.failure.line())
        _finish(exit_code_for(PublicErrorCode.INTERNAL_ERROR))
    except LifecycleError as error:
        _finish(_lifecycle_failure(error))
    except (InstanceIdentityError, PathSafetyError) as error:
        # An instance whose identity, pin, root, or lifetime cannot be trusted is refused before
        # the singleton is taken (issue #604); name the condition, never a traceback.
        _finish(_instance_failure(error))
    except ConfigError as error:
        # The same refusal every other command gives a configuration it cannot load.
        _stderr(f"invalid_request: {error.reason_code}")
        _finish(2)


@service_app.command("isolation")
def service_isolation(
    json_output: _JSON = False,
    content_digests: Annotated[
        bool,
        typer.Option(
            "--content-digests",
            help=(
                "Also observe the selected config file's bytes as SHA-256, size, existence, and "
                "observation time (never its content)."
            ),
        ),
    ] = False,
) -> None:
    """Report the resolved identity roots and isolation mode without connecting to a service.

    Digest-only output (``yoetz.isolation-report/1``): each root is a path-identity digest over
    its canonical resolved path, which does not change when the file's bytes change. With
    ``--content-digests`` the selected config also gets a bounded byte-content observation. The
    dogfood parity preflight compares one report from the exact normal target with another from
    the isolated launch environment; platform defaults cannot stand in for a relocated target.
    """

    from finishup.cli.isolation_status import isolation_report
    from finishup.config.installation import InstanceIdentityError
    from finishup.config.models import ConfigError
    from finishup.config.paths import PathSafetyError

    try:
        report = isolation_report(content=content_digests)
    except PathSafetyError as error:
        _stderr(f"isolation_invalid: {error.reason_code}")
        _finish(2)
    except ConfigError as error:
        _stderr(f"isolation_unprovable: {error.reason_code}")
        _finish(2)
    except InstanceIdentityError as error:
        _stderr(f"isolation_unprovable: {error.reason}")
        _finish(2)
    else:
        _human_or_json(cast(JsonValue, dict(report)), json_output=json_output)
        _finish(0)


def _instance_failure(error: BaseException) -> int:
    """Report a bounded instance-identity or isolation-root refusal (issue #604)."""

    from finishup.cli.exits import INSTANCE_PUBLIC_CODES
    from finishup.cli.instance import instance_failure_line
    from finishup.config.installation import InstanceIdentityError
    from finishup.config.paths import PathSafetyError

    if isinstance(error, InstanceIdentityError):
        reason = error.reason
    elif isinstance(error, PathSafetyError):
        reason = error.reason_code
    else:
        _stderr("internal_error: the command could not be completed")
        return exit_code_for(PublicErrorCode.INTERNAL_ERROR)
    _stderr(instance_failure_line(error))
    return exit_code_for(INSTANCE_PUBLIC_CODES.get(reason, PublicErrorCode.STORAGE_UNSAFE))


def _run_instance_operation(operation: Callable[[], object], *, json_output: bool) -> None:
    from finishup.config.installation import InstanceIdentityError
    from finishup.config.paths import PathSafetyError

    try:
        result = operation()
    except (InstanceIdentityError, PathSafetyError) as error:
        _finish(_instance_failure(error))
    else:
        _human_or_json(cast(JsonValue, result), json_output=json_output)
        _finish(0)


_INSTANCE_ROOT_OPTION = Annotated[
    Path,
    typer.Option(
        "--root",
        help="Absolute isolated root the instance owns (created by 'create', removed by 'dispose').",
    ),
]


@instance_app.command("create")
def instance_create(
    root: _INSTANCE_ROOT_OPTION,
    lifecycle: Annotated[
        Literal["persistent", "disposable"],
        typer.Option(
            "--lifecycle",
            help="persistent: a kept development instance; disposable: a bounded test snapshot.",
        ),
    ],
    source_ref: Annotated[
        str | None,
        typer.Option(
            "--source-ref", help="Exact 40/64-hex source revision the runtime was built from."
        ),
    ] = None,
    source_state: Annotated[
        Literal["clean", "modified", "unknown"],
        typer.Option("--source-state", help="Whether that revision's tree was clean when built."),
    ] = "unknown",
    package_digest: Annotated[
        str | None,
        typer.Option("--package-digest", help="sha256:<hex> of the installed wheel, when known."),
    ] = None,
    expires_in: Annotated[
        float | None,
        typer.Option("--expires-in", help="Hours until a disposable instance stops serving."),
    ] = None,
    expires_at: Annotated[
        str | None,
        typer.Option("--expires-at", help="RFC 3339 UTC millisecond time the instance expires."),
    ] = None,
    bind_runtime: Annotated[
        bool,
        typer.Option(
            "--bind-runtime",
            help=(
                "Pin this runtime (its virtual environment) to the root so it resolves the root "
                "even without FINISHUP_ISOLATED_ROOT."
            ),
        ),
    ] = False,
    json_output: _JSON = False,
) -> None:
    """Create an isolated instance root with a sealed identity; connection-free."""

    from datetime import UTC, datetime

    from finishup.cli.instance import create_instance, parse_expiry

    def operation() -> object:
        now = datetime.now(UTC)
        return create_instance(
            root=root,
            lifecycle=lifecycle,
            now=now,
            expires_at=parse_expiry(now=now, expires_in_hours=expires_in, expires_at=expires_at),
            source_ref=source_ref,
            source_state=source_state,
            package_digest=package_digest,
            bind_runtime=bind_runtime,
        )

    _run_instance_operation(operation, json_output=json_output)


@instance_app.command("status")
def instance_status_command(json_output: _JSON = False) -> None:
    """Report this runtime's instance (mode, binding, lifecycle, provenance); digest-only."""

    from finishup.cli.instance import instance_status

    _run_instance_operation(instance_status, json_output=json_output)


@instance_app.command("dispose")
def instance_dispose(
    root: _INSTANCE_ROOT_OPTION,
    retain_logs: Annotated[
        Path | None,
        typer.Option(
            "--retain-logs",
            help="Directory that receives a copy of the instance's log files before removal.",
        ),
    ] = None,
    no_stop: Annotated[
        bool,
        typer.Option(
            "--no-stop",
            help="Refuse instead of stopping a service that still holds the root's singleton.",
        ),
    ] = False,
    json_output: _JSON = False,
) -> None:
    """Remove one persistent or disposable instance root; repeated calls are a no-op."""

    from finishup.cli.instance import dispose_instance

    _run_instance_operation(
        lambda: dispose_instance(root=root, retain_logs=retain_logs, stop_service=not no_stop),
        json_output=json_output,
    )


@service_app.command("diagnostics")
def service_diagnostics(
    correlation_id: Annotated[
        str | None,
        typer.Option(
            "--correlation-id",
            help="Exact err_… correlation id from a public error or reduced accept envelope.",
        ),
    ] = None,
    request_id: Annotated[
        str | None,
        typer.Option("--request-id", help="Exact check request ID for joined failure stages."),
    ] = None,
    json_output: _JSON = False,
) -> None:
    """Resolve one durable owner-only diagnostic record by correlation id."""

    try:
        from finishup.observability.diagnostics import lookup_diagnostic_records
        from finishup.protocol.ids import IdKind, validate_id

        if correlation_id is not None:
            validate_id(IdKind.CORRELATION, correlation_id)
        records = lookup_diagnostic_records(correlation_id, request_id=request_id)
        output = cast(
            JsonValue,
            {
                "correlation_id": correlation_id,
                **({"request_id": request_id} if request_id is not None else {}),
                "count": len(records),
                "records": [dict(item) for item in records],
            },
        )
        _human_or_json(output, json_output=json_output)
        _finish(0 if records else 1)
    except (OSError, TypeError, ValueError):
        _finish(_usage_failure())


@mcp_app.command("serve")
def mcp_serve(
    semantic: Annotated[
        Literal["on", "off"],
        typer.Option(
            "--semantic",
            help="AI-powered review route posture: on follows policy; off fixes a process-lifetime ceiling.",
        ),
    ] = "on",
    host: Annotated[
        Literal["generic", "codex", "claude", "cursor"],
        typer.Option(
            "--host",
            help="MCP serving identity for the exact local host; generic leaves host unknown.",
        ),
    ] = "generic",
    project_root: Annotated[
        Path | None,
        typer.Option(
            "--project-root",
            help=("Cursor only: exact project containing the approved MCP registration."),
        ),
    ] = None,
    project_binding: Annotated[
        Literal["mcp-roots", "registered-project"],
        typer.Option(
            "--project-binding",
            help="Cursor binding: desktop host roots, or explicit registered project for Agent CLI.",
        ),
    ] = "mcp-roots",
) -> None:
    """Run the MCP stdio bridge."""

    module = importlib.import_module("finishup.mcp.server")
    mcp_main = cast(Callable[..., None], getattr(module, "main"))
    mcp_main(
        semantic=semantic, host=host, project_root=project_root, project_binding=project_binding
    )


@state_app.command("capture")
def state_capture(
    workspace: Annotated[Path, typer.Option("--workspace", exists=True, file_okay=False)],
    json_output: _JSON = False,
) -> None:
    """Capture content-withholding Git structural state."""

    try:
        from finishup.adapters.git_subject_state import GitSubjectStateAdapter, open_local_workspace
        from finishup.ports.subject_state import (
            SubjectStateCaptureCommand,
            SubjectStateFormat,
        )

        handle = open_local_workspace(workspace)
        result = GitSubjectStateAdapter().capture(
            SubjectStateCaptureCommand(handle, SubjectStateFormat.GIT_STRUCTURAL_V1)
        )
        state = result.subject_state
        output: JsonValue = {
            "bytes_hashed": result.bytes_hashed,
            "files_hashed": result.files_hashed,
            "format": result.format.value,
            "limitations": [item.value for item in result.limitations],
            "limit_detail": [
                {"bound": item.bound.value, "observed": item.observed, "limit": item.limit}
                for item in result.limit_detail
            ],
            "status": result.status.value,
            "tree_digest": state.tree_digest if state is not None else None,
            "diff_digest": state.diff_digest if state is not None else None,
        }
        _human_or_json(output, json_output=json_output)
    except ValueError as error:
        from finishup.adapters.git_version import GIT_VERSION_UNSUPPORTED
        from finishup.ports.subject_state import SubjectStateLimitation

        reason = str(error)
        if reason in {item.value for item in SubjectStateLimitation} or (
            reason == GIT_VERSION_UNSUPPORTED
        ):
            _stderr(_bounded_failure_line(reason))
            _finish(exit_code_for(PublicErrorCode.INVALID_REQUEST))
        _finish(_usage_failure())
    except OSError:
        _finish(_usage_failure())


async def _integration(action: str, harness: str, json_output: bool) -> int:
    if harness != "codex":
        return _usage_failure()
    request = JsonObject({"action": action, "harness": harness, "kind": "skill"})
    method = "integration_preview" if action == "preview" else "integration_execute"
    try:
        client = await build_service_client()
        try:
            result = await getattr(client, method)(request)
        finally:
            await client.close()
        _human_or_json(result, json_output=json_output)
        return 0
    except ControlError as error:
        return _control_failure(error)


@integrate_app.callback()
def integrate_root(
    context: typer.Context,
    harness: Annotated[str, typer.Argument(help="Exact harness ID (claude, codex, or cursor).")],
) -> None:
    context.obj = harness


def _integration_command(action: str) -> Callable[..., None]:
    def command(
        context: typer.Context,
        json_output: _JSON = False,
    ) -> None:
        harness = cast(str, context.find_root().find_object(str) or context.obj)
        _finish(run_async(lambda: _integration(action, harness, json_output)))

    return command


for _action in ("preview", "install", "status", "remove"):
    integrate_skill_app.command(_action)(_integration_command(_action))


_CODEX_PATH = Annotated[
    str | None,
    typer.Option("--codex-path", help="Exact codex executable to configure."),
]
_ACCEPT = Annotated[
    bool,
    typer.Option("--accept", help="Explicitly accept the previewed change."),
]
_ROUTE_PROFILE = Annotated[
    str | None,
    typer.Option(
        "--route-profile",
        help=(
            "Exact MCP route profile to register (strict or policy). Without it, an "
            "existing finishup-owned registration keeps its current route."
        ),
    ),
]


def _validated_route_profile(route_profile: str | None) -> str | None:
    if route_profile is not None and route_profile not in {"strict", "policy"}:
        raise typer.BadParameter("--route-profile must be 'strict' or 'policy'")
    return route_profile


def _setup_operation(name: str) -> Callable[..., Awaitable[int]]:
    module = importlib.import_module("finishup.cli.setup")
    return cast(Callable[..., Awaitable[int]], getattr(module, name))


def _integration_mcp_command(action: str) -> Callable[..., None]:
    def command(
        context: typer.Context,
        codex_path: _CODEX_PATH = None,
        codex_home: Annotated[Path | None, typer.Option("--codex-home")] = None,
        accept: _ACCEPT = False,
        preview_digest: Annotated[
            str | None,
            typer.Option("--preview-digest", help="Exact preview digest to bind."),
        ] = None,
        route_profile: _ROUTE_PROFILE = None,
        project_root: Annotated[
            Path | None,
            typer.Option(
                "--project-root",
                help=(
                    "Trusted project whose Codex host-admission entry a strict registration "
                    "or a removal also revokes."
                ),
            ),
        ] = None,
        json_output: _JSON = False,
    ) -> None:
        harness = cast(str, context.find_root().find_object(str) or context.obj)
        chosen_route = _validated_route_profile(route_profile)
        operation = _setup_operation("integrate_mcp")
        _finish(
            run_async(
                lambda: operation(
                    action,
                    harness,
                    codex_path=codex_path,
                    codex_home=codex_home,
                    accept=accept,
                    preview_digest=preview_digest,
                    json_output=json_output,
                    route_profile=chosen_route,
                    project_root=project_root,
                )
            )
        )

    return command


for _mcp_action in ("preview", "preview-remove", "install", "status", "remove"):
    integrate_mcp_app.command(_mcp_action)(_integration_mcp_command(_mcp_action))


def _cursor_project_mcp_command(action: str) -> Callable[..., None]:
    def command(
        context: typer.Context,
        project_root: Annotated[
            Path,
            typer.Option(
                "--project-root", help="Exact trusted project containing .cursor/mcp.json."
            ),
        ],
        cursor_config_root: Annotated[
            Path,
            typer.Option("--cursor-config-root", help="Exact Cursor user configuration root."),
        ],
        route_profile: _ROUTE_PROFILE = None,
        accept: _ACCEPT = False,
        preview_digest: Annotated[
            str | None,
            typer.Option("--preview-digest", help="Exact reviewed project MCP preview digest."),
        ] = None,
        project_binding: Annotated[
            Literal["mcp-roots", "registered-project"] | None,
            typer.Option(
                "--project-binding",
                help="Explicit Agent CLI binding; omitted preserves an owned entry, otherwise uses desktop roots.",
            ),
        ] = None,
        json_output: _JSON = False,
    ) -> None:
        harness = cast(str, context.find_root().find_object(str) or context.obj)
        module = importlib.import_module("finishup.cli.cursor_project_mcp")
        operation = cast(Callable[..., int], getattr(module, "run_cursor_project_mcp_command"))
        _finish(
            operation(
                action,
                harness,
                project_root=project_root,
                cursor_config_root=cursor_config_root,
                route_profile=_validated_route_profile(route_profile),
                accept=accept,
                preview_digest=preview_digest,
                json_output=json_output,
                project_binding=project_binding,
            )
        )

    return command


for _project_mcp_action in ("preview", "preview-remove", "install", "status", "remove"):
    integrate_project_mcp_app.command(_project_mcp_action)(
        _cursor_project_mcp_command(_project_mcp_action)
    )


# The per-host plugin command surface (issue #465). Codex activation is the
# digest-bound setup/recommendation ceremony (ADR-012), so its standalone
# lifecycle is removal-shaped; Cursor has no update/enable/disable states; the
# export carrier is Claude-specific. Every dispatcher fails closed on its own,
# but the gate here refuses before any dispatch, binary discovery, or mutation
# with an error that names the supported actions, and the help text below
# marks each command's hosts so `--help` never advertises a dead command.
_PLUGIN_HOSTS: Final = ("claude", "codex", "cursor")
_PLUGIN_COMMAND_HOSTS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "preview": frozenset({"claude", "codex", "cursor"}),
        "install": frozenset({"claude", "cursor"}),
        "update": frozenset({"claude"}),
        "enable": frozenset({"claude"}),
        "disable": frozenset({"claude"}),
        "status": frozenset({"claude", "codex", "cursor"}),
        "remove": frozenset({"claude", "codex", "cursor"}),
        "export": frozenset({"claude"}),
    }
)
_PLUGIN_HOST_LABELS: Final[Mapping[str, str]] = MappingProxyType(
    {"claude": "Claude Code", "codex": "Codex", "cursor": "Cursor"}
)
_PLUGIN_COMMAND_SUMMARY: Final[Mapping[str, str]] = MappingProxyType(
    {
        "preview": "Render the exact plan and digest for a plugin change",
        "install": "Apply a previewed plugin install",
        "update": "Apply a previewed plugin update",
        "enable": "Apply a previewed plugin enable",
        "disable": "Apply a previewed plugin disable",
        "status": "Report the installed plugin state",
        "remove": "Apply a previewed plugin removal",
        "export": "Render a development plugin directory for `claude --plugin-dir`",
    }
)


def plugin_commands_for_host(harness: str) -> tuple[str, ...]:
    """Return the plugin commands one host supports, in registration order."""

    return tuple(name for name, hosts in _PLUGIN_COMMAND_HOSTS.items() if harness in hosts)


def _plugin_command_help(command_name: str) -> str:
    hosts = ", ".join(
        _PLUGIN_HOST_LABELS[host]
        for host in _PLUGIN_HOSTS
        if host in _PLUGIN_COMMAND_HOSTS[command_name]
    )
    unsupported = ", ".join(
        _PLUGIN_HOST_LABELS[host]
        for host in _PLUGIN_HOSTS
        if host not in _PLUGIN_COMMAND_HOSTS[command_name]
    )
    text = f"{_PLUGIN_COMMAND_SUMMARY[command_name]} ({hosts})."
    if unsupported:
        text += f" Not supported for {unsupported}."
    return text


def _refuse_unsupported_plugin_command(harness: str, command_name: str) -> None:
    supported = ",".join(plugin_commands_for_host(harness))
    sys.stderr.write(f"{harness}_plugin_command_unsupported:{command_name} supported={supported}\n")
    _finish(2)


def _host_plugin_command(command_name: str) -> Callable[..., None]:
    def command(
        context: typer.Context,
        cursor_config_root: Annotated[
            Path | None,
            typer.Option(
                "--cursor-config-root",
                help="Exact isolated Cursor ~/.cursor configuration root.",
            ),
        ] = None,
        claude_path: Annotated[
            Path | None,
            typer.Option("--claude-path", help="Exact Claude Code executable."),
        ] = None,
        claude_config_root: Annotated[
            Path | None,
            typer.Option("--claude-config-root", help="Exact isolated Claude config root."),
        ] = None,
        cache_root: Annotated[
            Path | None,
            typer.Option("--cache-root", help="Exact Claude plugin cache root."),
        ] = None,
        marketplace_root: Annotated[
            Path | None,
            typer.Option("--marketplace-root", help="Exact managed private marketplace root."),
        ] = None,
        output_root: Annotated[
            Path | None,
            typer.Option(
                "--output-root",
                help="export only: not-yet-existing directory for a claude --plugin-dir root.",
            ),
        ] = None,
        development_enabled: Annotated[
            bool,
            typer.Option(
                "--development-enabled",
                help="export only: render defaultEnabled:true so --plugin-dir loads it.",
            ),
        ] = False,
        project_root: Annotated[
            Path | None,
            typer.Option("--project-root", help="Exact trusted project for MCP source checks."),
        ] = None,
        format_name: Annotated[str, typer.Option("--format", help="portable or native")] = "native",
        observation_profile: Annotated[
            str,
            typer.Option(
                "--observation-profile",
                help="structural or ordinary native hooks; content capture requires separate consent.",
            ),
        ] = "structural",
        startup_mode: Annotated[
            str | None,
            typer.Option(
                "--startup-mode",
                help="optional or required; defaults to the owned installed mode, or optional for a new install.",
            ),
        ] = None,
        ownership_name: Annotated[
            str,
            typer.Option("--mcp-ownership", help="external-registration or plugin-managed"),
        ] = "external-registration",
        route_profile: Annotated[
            str | None,
            typer.Option("--route-profile", help="strict or policy for plugin-managed MCP."),
        ] = None,
        requested_action: Annotated[
            str | None,
            typer.Option(
                "--action",
                help=(
                    "Preview action. Claude Code: install/update/enable/disable/remove. "
                    "Cursor: install/replace/remove. Not used for Codex (removal only)."
                ),
            ),
        ] = None,
        request_value: Annotated[
            str | None,
            typer.Option("--request-id", help="Exact request ID returned by preview."),
        ] = None,
        preview_digest: Annotated[
            str | None,
            typer.Option("--preview-digest", help="Exact digest returned by preview."),
        ] = None,
        codex_path: _CODEX_PATH = None,
        codex_home: Annotated[
            Path | None,
            typer.Option("--codex-home", help="Exact Codex home to bind plugin removal to."),
        ] = None,
        purge_cache: Annotated[
            bool,
            typer.Option(
                "--purge-cache",
                help="Also delete other digest-matched finishup cache versions.",
            ),
        ] = False,
        accept: _ACCEPT = False,
        json_output: _JSON = False,
    ) -> None:
        harness = cast(str, context.find_root().find_object(str) or context.obj)
        if harness in _PLUGIN_HOSTS and harness not in _PLUGIN_COMMAND_HOSTS[command_name]:
            _refuse_unsupported_plugin_command(harness, command_name)
            return
        if startup_mode not in {None, "optional", "required"}:
            raise typer.BadParameter("--startup-mode must be optional or required")
        if startup_mode == "required" and (harness == "codex" or format_name != "native"):
            raise typer.BadParameter("required startup needs native Claude or Cursor hooks")
        if observation_profile not in {"structural", "ordinary"}:
            raise typer.BadParameter("--observation-profile must be structural or ordinary")
        if observation_profile == "ordinary" and (harness == "codex" or format_name != "native"):
            raise typer.BadParameter("ordinary observation requires native Claude or Cursor")
        if harness == "codex":
            module = importlib.import_module("finishup.cli.codex_plugin")
            operation = cast(Callable[..., int], getattr(module, "run_codex_plugin_command"))
            _finish(
                operation(
                    command_name,
                    harness=harness,
                    project_root=project_root,
                    codex_path=codex_path,
                    codex_home=codex_home,
                    purge_cache=purge_cache,
                    preview_digest=preview_digest,
                    accept=accept,
                    json_output=json_output,
                )
            )
            return
        if harness == "cursor":
            if cursor_config_root is None:
                sys.stderr.write("cursor_config_root_required\n")
                _finish(2)
                return
            module = importlib.import_module("finishup.cli.cursor_integration")
            operation = cast(Callable[..., int], getattr(module, "run_cursor_plugin_command"))
            arguments = {
                "harness": harness,
                "cursor_config_root": cursor_config_root,
                "project_root": project_root,
                "format_name": format_name,
                "observation_profile": observation_profile,
                "startup_mode": startup_mode,
                "ownership_name": ownership_name,
                "route_profile": route_profile,
                "requested_action": requested_action,
                "request_value": request_value,
                "preview_digest": preview_digest,
                "accept": accept,
                "json_output": json_output,
            }
        elif harness == "claude" and command_name == "export":
            if output_root is None:
                raise typer.BadParameter("--output-root is required for claude plugin export")
            module = importlib.import_module("finishup.cli.claude_code_integration")
            export = cast(Callable[..., int], getattr(module, "run_claude_code_plugin_export"))
            _finish(
                export(
                    output_root=output_root,
                    ownership_name=ownership_name,
                    route_profile=route_profile,
                    development_enabled=development_enabled,
                    observation_profile=observation_profile,
                    startup_mode=startup_mode or "optional",
                    json_output=json_output,
                )
            )
            return
        elif harness == "claude":
            if any(
                value is None
                for value in (
                    claude_path,
                    claude_config_root,
                    cache_root,
                    marketplace_root,
                    project_root,
                )
            ):
                raise typer.BadParameter(
                    "--claude-path, --claude-config-root, --cache-root, "
                    "--marketplace-root, and --project-root are required for claude"
                )
            module = importlib.import_module("finishup.cli.claude_code_integration")
            operation = cast(Callable[..., int], getattr(module, "run_claude_code_plugin_command"))
            arguments = {
                "harness": harness,
                "claude_path": claude_path,
                "claude_config_root": claude_config_root,
                "cache_root": cache_root,
                "marketplace_root": marketplace_root,
                "project_root": project_root,
                "format_name": format_name,
                "observation_profile": observation_profile,
                "startup_mode": startup_mode,
                "ownership_name": ownership_name,
                "route_profile": route_profile,
                "requested_action": requested_action,
                "request_value": request_value,
                "preview_digest": preview_digest,
                "accept": accept,
                "json_output": json_output,
            }
        else:
            raise typer.BadParameter("plugin lifecycle is available for claude, codex, or cursor")
        _finish(
            operation(
                command_name,
                **arguments,
            )
        )

    return command


for _plugin_action in _PLUGIN_COMMAND_HOSTS:
    integrate_plugin_app.command(_plugin_action, help=_plugin_command_help(_plugin_action))(
        _host_plugin_command(_plugin_action)
    )


def _host_admission_command(command_name: str) -> Callable[..., None]:
    def command(
        context: typer.Context,
        project_root: Annotated[
            Path,
            typer.Option("--project-root", help="Exact trusted project whose host files to edit."),
        ],
        requested_action: Annotated[
            str | None,
            typer.Option("--action", help="preview only: grant (default) or revoke."),
        ] = None,
        codex_path: Annotated[
            Path | None,
            typer.Option("--codex-path", help="Exact Codex executable to inspect."),
        ] = None,
        codex_home: Annotated[
            Path | None,
            typer.Option("--codex-home", help="Exact Codex home to inspect."),
        ] = None,
        checkpoint: Annotated[
            bool,
            typer.Option(
                "--checkpoint",
                help=(
                    "Claude Code only: write the permissions.ask human checkpoint instead of "
                    "permissions.allow."
                ),
            ),
        ] = False,
        claude_path: Annotated[
            Path | None,
            typer.Option("--claude-path", help="Exact Claude Code executable (route check)."),
        ] = None,
        claude_config_root: Annotated[
            Path | None,
            typer.Option("--claude-config-root", help="Exact isolated Claude config root."),
        ] = None,
        cache_root: Annotated[
            Path | None,
            typer.Option("--cache-root", help="Exact Claude plugin cache root."),
        ] = None,
        marketplace_root: Annotated[
            Path | None,
            typer.Option("--marketplace-root", help="Exact managed private marketplace root."),
        ] = None,
        cursor_config_root: Annotated[
            Path | None,
            typer.Option(
                "--cursor-config-root",
                help="Exact isolated Cursor ~/.cursor configuration root (route check).",
            ),
        ] = None,
        ownership_name: Annotated[
            str,
            typer.Option("--mcp-ownership", help="external-registration or plugin-managed"),
        ] = "external-registration",
        route_profile: Annotated[
            str | None,
            typer.Option("--route-profile", help="strict or policy for plugin-managed MCP."),
        ] = None,
        preview_digest: Annotated[
            str | None,
            typer.Option("--preview-digest", help="Exact digest returned by preview."),
        ] = None,
        accept: _ACCEPT = False,
        json_output: _JSON = False,
    ) -> None:
        harness = cast(str, context.find_root().find_object(str) or context.obj)
        module = importlib.import_module("finishup.cli.host_admission")
        operation = cast(
            Callable[..., Awaitable[int]], getattr(module, "run_host_admission_command")
        )
        _finish(
            run_async(
                lambda: operation(
                    command_name,
                    harness=harness,
                    project_root=project_root,
                    action_name=requested_action,
                    codex_path=codex_path,
                    codex_home=codex_home,
                    accept=accept,
                    preview_digest=preview_digest,
                    checkpoint=checkpoint,
                    json_output=json_output,
                    claude_path=claude_path,
                    claude_config_root=claude_config_root,
                    cache_root=cache_root,
                    marketplace_root=marketplace_root,
                    cursor_config_root=cursor_config_root,
                    ownership_name=ownership_name,
                    route_name=_validated_route_profile(route_profile),
                )
            )
        )

    return command


for _admission_action in ("status", "preview", "grant", "revoke"):
    integrate_admission_app.command(_admission_action)(_host_admission_command(_admission_action))


def _setup_targets(
    hosts: list[str] | None,
    paths: list[Path] | None,
    roots: list[Path] | None,
) -> tuple[
    str | tuple[str, ...] | None, Path | tuple[Path, ...] | None, Path | tuple[Path, ...] | None
]:
    if hosts and (len(hosts) > 1 or hosts == ["all"]):
        return tuple(hosts), tuple(paths or ()), tuple(roots or ())
    if (paths and len(paths) != 1) or (roots and len(roots) != 1):
        raise typer.BadParameter("Supply one --host-path and --host-config-root per --host")
    return hosts[0] if hosts else None, paths[0] if paths else None, roots[0] if roots else None


@setup_app.command("run")
def setup_run(
    non_interactive: Annotated[
        bool,
        typer.Option(
            "--non-interactive", help="Never ask setup questions; apply only an accepted preview."
        ),
    ] = False,
    codex_path: _CODEX_PATH = None,
    codex_home: Annotated[
        Path | None,
        typer.Option("--codex-home", help="Exact Codex home to bind activation to."),
    ] = None,
    accept: _ACCEPT = False,
    route_profile: _ROUTE_PROFILE = None,
    json_output: _JSON = False,
    host: Annotated[
        list[str] | None,
        typer.Option("--host", help="Agent to connect; repeat to choose several, or use all."),
    ] = None,
    host_path: Annotated[
        list[Path] | None, typer.Option("--host-path", help="Executable for each --host, in order.")
    ] = None,
    host_config_root: Annotated[
        list[Path] | None,
        typer.Option("--host-config-root", help="Configuration for each --host, in order."),
    ] = None,
    project: Annotated[Path | None, typer.Option("--project", help="Project to connect.")] = None,
    request_value: Annotated[
        str | None,
        typer.Option("--request-id", help="Request identity returned by the connection preview."),
    ] = None,
    preview_digest: Annotated[
        str | None, typer.Option("--preview-digest", help="Exact connection plan to accept.")
    ] = None,
    batch: Annotated[bool, typer.Option("--batch", hidden=True)] = False,
) -> None:
    """Run the guided first-run setup wizard."""

    if codex_home is not None and codex_path is None:
        raise typer.BadParameter("--codex-home requires --codex-path")
    chosen_route = _validated_route_profile(route_profile)
    selected_host, selected_path, selected_root = _setup_targets(host, host_path, host_config_root)
    if batch and isinstance(selected_host, str):
        selected_host = (selected_host,)
        selected_path = () if selected_path is None else (cast(Path, selected_path),)
        selected_root = () if selected_root is None else (cast(Path, selected_root),)

    operation = _setup_operation("run_setup_wizard")
    _finish(
        run_async(
            lambda: operation(
                non_interactive=non_interactive,
                codex_path=codex_path,
                codex_home=codex_home,
                accept=accept,
                json_output=json_output,
                route_profile=chosen_route,
                host=selected_host,
                host_path=selected_path,
                host_config_root=selected_root,
                project=project,
                request_value=request_value,
                preview_digest=preview_digest,
            )
        )
    )


@setup_app.command("disconnect")
def setup_disconnect(
    host: Annotated[
        list[str], typer.Option("--host", help="Agent to disconnect; repeat or use all.")
    ],
    host_path: Annotated[list[Path] | None, typer.Option("--host-path")] = None,
    host_config_root: Annotated[list[Path] | None, typer.Option("--host-config-root")] = None,
    codex_home: Annotated[Path | None, typer.Option("--codex-home")] = None,
    codex_path: _CODEX_PATH = None,
    project: Annotated[Path | None, typer.Option("--project")] = None,
    request_value: Annotated[str | None, typer.Option("--request-id")] = None,
    preview_digest: Annotated[str | None, typer.Option("--preview-digest")] = None,
    accept: _ACCEPT = False,
    non_interactive: Annotated[bool, typer.Option("--non-interactive")] = False,
    route_profile: _ROUTE_PROFILE = None,
    json_output: _JSON = False,
    remove_shared: Annotated[
        bool,
        typer.Option(
            "--remove-shared",
            help=(
                "Also remove the FinishUP pieces this agent configuration shares with other "
                "connected projects (they stop using FinishUP; the preview names them). Without "
                "it, a disconnect keeps the shared pieces while another project FinishUP knows "
                "of may still use them."
            ),
        ),
    ] = False,
    batch: Annotated[bool, typer.Option("--batch", hidden=True)] = False,
) -> None:
    """Preview and remove the selected integration, preserving FinishUP data."""
    from finishup.cli.host_connection import run_host_connection

    selected, executable, config_root = _setup_targets(host, host_path, host_config_root)
    if batch and isinstance(selected, str):
        selected = (selected,)
        executable = () if executable is None else (cast(Path, executable),)
        config_root = () if config_root is None else (cast(Path, config_root),)
    if isinstance(selected, tuple):
        if codex_home is not None or codex_path is not None:
            raise typer.BadParameter("Use --host-path and --host-config-root for each batch member")
        from finishup.cli.host_batch import run_host_batch

        _finish(
            run_async(
                lambda: run_host_batch(
                    hosts=selected,
                    executables=executable if isinstance(executable, tuple) else (),
                    config_roots=config_root if isinstance(config_root, tuple) else (),
                    project=(project or Path.cwd()).expanduser().resolve(),
                    action="disconnect",
                    route=cast(
                        Literal["strict", "policy"] | None, _validated_route_profile(route_profile)
                    ),
                    accept=accept,
                    interactive=not non_interactive and not json_output and sys.stdin.isatty(),
                    request_value=request_value,
                    preview_digest=preview_digest,
                    json_output=json_output,
                    remove_shared=remove_shared,
                )
            )
        )
        return
    assert isinstance(selected, str)
    if codex_home is not None or codex_path is not None:
        if selected != "codex" or executable is not None or config_root is not None:
            raise typer.BadParameter("Codex options cannot be combined with other host targets")
        executable = None if codex_path is None else Path(codex_path)
        config_root = codex_home

    _finish(
        run_host_connection(
            host=selected,
            executable=cast(Path | None, executable),
            config_root=cast(Path | None, config_root),
            project=(project or Path.cwd()).expanduser().resolve(),
            action="disconnect",
            # Without --route-profile, a Codex home keeps its registered review mode.
            route=cast(Literal["strict", "policy"] | None, _validated_route_profile(route_profile)),
            accept=accept,
            interactive=not non_interactive and sys.stdin.isatty(),
            request_value=request_value,
            preview_digest=preview_digest,
            json_output=json_output,
            remove_shared=remove_shared,
        )
    )


@setup_app.command("vault")
def setup_vault(
    passphrase: Annotated[
        bool,
        typer.Option(
            "--passphrase",
            help=(
                "For a new vault, choose your own passphrase instead of a generated one kept "
                "in the system keychain or a private file. You type it after every restart."
            ),
        ),
    ] = False,
) -> None:
    """Initialize or unlock storage in a trusted terminal, without provider setup."""
    operation = _setup_operation("run_vault_setup")
    _finish(run_async(lambda: operation(passphrase=passphrase)))


@setup_app.command("status")
def setup_status(
    json_output: _JSON = False,
    next_step: Annotated[bool, typer.Option("--next")] = False,
    operation: Annotated[
        str, typer.Option("--operation", help="local, review or connection")
    ] = "local",
    codex_home: Annotated[Path | None, typer.Option("--codex-home")] = None,
    codex_path: _CODEX_PATH = None,
    host: Annotated[list[str] | None, typer.Option("--host")] = None,
    host_path: Annotated[list[Path] | None, typer.Option("--host-path")] = None,
    host_config_root: Annotated[list[Path] | None, typer.Option("--host-config-root")] = None,
    project: Annotated[Path | None, typer.Option("--project")] = None,
    route_profile: _ROUTE_PROFILE = None,
) -> None:
    """Show read-only setup posture without mutating anything."""

    if operation not in {"local", "review", "connection"}:
        raise typer.BadParameter("--operation must be local, review or connection")
    selected, executable, config_root = _setup_targets(host, host_path, host_config_root)
    if isinstance(selected, tuple):
        if next_step or codex_home is not None or codex_path is not None:
            raise typer.BadParameter(
                "Batch status uses --host-path/--host-config-root; --next needs one host"
            )
        from finishup.cli.host_batch import run_host_batch

        _finish(
            run_async(
                lambda: run_host_batch(
                    hosts=selected,
                    executables=executable if isinstance(executable, tuple) else (),
                    config_roots=config_root if isinstance(config_root, tuple) else (),
                    project=(project or Path.cwd()).expanduser().resolve(),
                    route=cast(
                        Literal["strict", "policy"] | None, _validated_route_profile(route_profile)
                    ),
                    json_output=json_output,
                    status_only=True,
                )
            )
        )
        return
    # Keep the single-host and local-status paths on their released report contracts.
    host_value = selected
    host_executable = cast(Path | None, executable)
    host_root = cast(Path | None, config_root)
    if codex_home is not None or codex_path is not None:
        if (
            host_value not in {None, "codex"}
            or host_root is not None
            or host_executable is not None
        ):
            raise typer.BadParameter("Codex options cannot be combined with other host targets")
        host_value, host_root = "codex", codex_home
        host_executable = None if codex_path is None else Path(codex_path)
    if next_step:
        from finishup.cli.setup_readiness import setup_next

        _finish(
            setup_next(
                operation=cast(Literal["local", "review", "connection"], operation),
                host=host_value,
                executable=host_executable,
                config_root=host_root,
                project=(project or Path.cwd()).expanduser().resolve(),
                # Review needs the AI-powered route; otherwise a Codex home keeps its mode.
                route=cast(
                    Literal["strict", "policy"] | None,
                    _validated_route_profile(route_profile)
                    or ("policy" if operation == "review" else None),
                ),
                json_output=json_output,
            )
        )
        return
    if host_value is not None:
        from finishup.cli.host_connection import run_host_connection

        _finish(
            run_host_connection(
                host=host_value,
                executable=host_executable,
                config_root=host_root,
                project=(project or Path.cwd()).expanduser().resolve(),
                # Without --route-profile, a Codex home keeps its registered review mode.
                route=cast(
                    Literal["strict", "policy"] | None, _validated_route_profile(route_profile)
                ),
                json_output=json_output,
                status_only=True,
            )
        )
        return
    status_operation = _setup_operation("setup_status")
    _finish(run_async(lambda: status_operation(json_output=json_output)))


async def _trusted_call(operation: Callable[[], Awaitable[object]], json_output: bool) -> int:
    try:
        result = await operation()
        _human_or_json(result, json_output=json_output)
        return 0
    except (OSError, ProtocolValueError, ValueError):
        return _usage_failure()
    except Exception as error:
        failure = _trusted_exception_failure(error)
        if failure is not None:
            return failure
        raise


def _recovery_store_read[T](operation: Callable[[], T]) -> tuple[T | None, int | None]:
    """Run one local recovery-store read behind a bounded public CLI outcome."""

    try:
        return operation(), None
    except (OSError, ProtocolValueError, RuntimeError, ValueError):
        _stderr("storage_corrupt: the installation recovery set could not be read")
        return None, exit_code_for(PublicErrorCode.STORAGE_CORRUPT)


def _trusted_exception_failure(error: Exception) -> int | None:
    """Map trusted-ceremony failures to bounded public CLI outcomes."""

    unlock_module = importlib.import_module("finishup.cli.unlock")
    client_module = importlib.import_module("finishup.service.confidential_client")
    ceremony_error = cast(type[Exception], getattr(unlock_module, "HumanCeremonyCliError"))
    client_error = cast(type[Exception], getattr(client_module, "ConfidentialClientError"))
    if isinstance(error, ceremony_error):
        reason = cast(str, getattr(error, "reason"))
        if reason in {"cancelled", "interrupted"}:
            _stderr("cancelled")
            return exit_code_for("cancelled")
        if reason in {"preview_invalid", "result_invalid"}:
            _stderr("internal_error: the confidential ceremony could not be completed")
            return exit_code_for(PublicErrorCode.INTERNAL_ERROR)
        # A ceremony that could not find a console it owns is not malformed input. Reporting it
        # as invalid_request sent operators looking for a bad flag they never typed.
        line = _bounded_failure_line(reason)
        if line != reason:
            _stderr(line)
            return exit_code_for(PublicErrorCode.INVALID_REQUEST)
        return _usage_failure()
    if isinstance(error, client_error):
        reason = cast(str, getattr(error, "reason"))
        if reason == "cancelled":
            _stderr("cancelled")
            return exit_code_for("cancelled")
        ceremony_refusal = ceremony_refusal_line(reason)
        if ceremony_refusal is not None:
            _stderr(ceremony_refusal)
            return exit_code_for(PublicErrorCode.INVALID_REQUEST)
        _stderr("service_unavailable: the confidential ceremony could not be completed")
        return exit_code_for(PublicErrorCode.SERVICE_UNAVAILABLE)
    return None


def _unlock_operation(name: str) -> Callable[[], Awaitable[object]]:
    module = importlib.import_module("finishup.cli.unlock")
    return cast(Callable[[], Awaitable[object]], getattr(module, name))


@service_app.command("unlock")
def service_unlock(json_output: _JSON = False) -> None:
    _finish(run_async(lambda: _service_unlock(json_output)))


async def _service_unlock(json_output: bool) -> int:
    try:
        client = await build_service_client()
        try:
            status = await client.service_status()
        finally:
            await client.close()
    except ControlError as error:
        return _control_failure(error)
    if status.vault_mode == "os_keyring":
        return await _trusted_call(_unlock_operation("retry_keyring"), json_output)
    if status.vault_mode == "passphrase":
        return await _trusted_call(_unlock_operation("unlock_vault"), json_output)
    _stderr(
        "vault_locked: the vault is uninitialized; run "
        "'finishup service initialize-passphrase' from a local terminal"
    )
    return exit_code_for(PublicErrorCode.VAULT_LOCKED)


def _auto_unlock_store() -> Any:
    """Build the store for the same environment-selected bundle as the daemon."""

    from finishup.adapters.keys.os_keyring import AutoUnlockPassphraseStore
    from finishup.config.load import load_config
    from finishup.config.paths import bundle_root

    config = load_config({}, os.environ, None)
    return AutoUnlockPassphraseStore(bundle_root(_data_dir=config.storage.data_dir))


@auto_unlock_app.command("status")
def service_auto_unlock_status(json_output: _JSON = False) -> None:
    """Report scoped restart-unlock state without exposing credential material."""

    _finish(run_async(lambda: _service_auto_unlock_status(json_output)))


async def _service_auto_unlock_status(json_output: bool) -> int:
    """Compose platform-entry and live-service evidence into one bounded report.

    The per-slot report distinguishes a genuinely pre-existing active entry, a same-attempt
    staged or orphaned initialization entry, an established active entry, and an invalid entry
    (#511) without exposing credential material.
    """

    store = _auto_unlock_store()
    secret, reason = store.load_with_reason()
    if secret is not None:
        for index in range(len(secret)):
            secret[index] = 0
    slots = store.slot_report()
    service_state: str | None = None
    service_reason: str | None = None
    vault_mode: str | None = None
    try:
        client = await build_service_client()
        try:
            status = await client.service_status()
            service_state = status.state.value
            service_reason = status.state_reason
            vault_mode = status.vault_mode
        finally:
            await client.close()
    except ControlError as error:
        service_state = error.reason
        service_reason = error.reason
    staged_initialization = slots.get("staged_initialization")
    if service_reason == "auto_unlock_rejected":
        state = "rejected"
    elif service_reason == "auto_unlock_stale":
        state = "stale"
    elif staged_initialization == "present":
        # A staged-initialization entry exists only because an authorized initialization
        # attempt has not been reconciled. With a provably uninitialized vault it is an
        # orphan repair can discard; otherwise restart reconciliation resolves it by proof.
        state = (
            "initialization_orphaned"
            if vault_mode == "uninitialized"
            else "initialization_unreconciled"
        )
    elif reason == "none":
        # An active entry beside an uninitialized vault predates initialization and is never
        # adopted; it must be removed out of band before initialization can proceed.
        state = "pre_existing_unadoptable" if vault_mode == "uninitialized" else "provisioned"
    elif reason == "auto_unlock_absent":
        state = "absent"
    elif reason == "auto_unlock_backend_unavailable":
        state = "backend_unsupported"
    else:
        state = "rejected"
    if state in {"stale", "absent", "rejected", "initialization_orphaned"}:
        next_command: str | None = "finishup service auto-unlock repair"
    elif state == "initialization_unreconciled":
        next_command = "finishup service restart"
    else:
        next_command = None
    report: JsonValue = {
        # Frozen legacy identifier (ADR-048): machine-readable report tag agents parse.
        "schema": "yoetz.auto-unlock-status/2",
        "state": state,
        "custody": store.custody,
        "slots": dict(slots),
        "service_state": service_state,
        "service_state_reason": service_reason,
        "vault_mode": vault_mode,
        "next_command": next_command,
    }
    _human_or_json(report, json_output=json_output)
    return 0 if state == "provisioned" else 20


@auto_unlock_app.command("repair")
def service_auto_unlock_repair(json_output: _JSON = False) -> None:
    """Repair restart unlock after proving the current vault passphrase."""

    _finish(run_async(lambda: _service_auto_unlock_repair(json_output)))


@auto_unlock_app.command("enable")
def service_auto_unlock_enable(json_output: _JSON = False) -> None:
    """Enable restart-safe unlock for an existing passphrase vault."""

    _finish(run_async(lambda: _service_auto_unlock_repair(json_output)))


async def _service_auto_unlock_repair(json_output: bool) -> int:
    """Prove, persist, and wipe one bundle-scoped passphrase."""

    from finishup.adapters.keys.os_keyring import OSKeyringError
    from finishup.cli.unlock import read_vault_passphrase_for_auto_unlock, unlock_vault

    try:
        client = await build_service_client()
        try:
            status = await client.service_status()
        finally:
            await client.close()
    except ControlError as error:
        return _control_failure(error)
    if status.vault_mode == "uninitialized":
        # An orphan left by a failed initialization attempt (#511) is removed with verified
        # read-back, but only under the bundle-scoped guard with the vault state re-proven
        # while it is held: no initializer can stage, commit, or promote while the guard is
        # taken, so the status cannot go stale between the read and the delete. Active entries
        # are never deleted by this command.
        orphan_store = _auto_unlock_store()
        if orphan_store.slot_report().get("staged_initialization") == "present":
            try:
                with orphan_store.staged_initialization_guard():
                    try:
                        client = await build_service_client()
                        try:
                            proven = await client.service_status()
                        finally:
                            await client.close()
                    except ControlError as error:
                        return _control_failure(error)
                    if proven.state.value != "locked" or proven.vault_mode != "uninitialized":
                        _stderr(
                            "auto_unlock_repair_unproven: the vault state changed; rerun "
                            "'finishup service auto-unlock status'"
                        )
                        return 20
                    if orphan_store.slot_report().get("staged_initialization") == "present":
                        orphan_store.discard_staged_initialization()
            except OSKeyringError as error:
                _stderr(f"auto_unlock_{error.reason}")
                return 20
            report = {
                # Frozen legacy identifier (ADR-048): machine-readable report tag agents parse.
                "schema": "yoetz.auto-unlock-repair/1",
                "outcome": "initialization_orphan_cleared",
                "service_state": status.state.value,
                "next_command": "finishup consent prepare vault_initialize",
            }
            _human_or_json(cast(JsonValue, report), json_output=json_output)
            return 0
    if status.vault_mode != "passphrase":
        _stderr("auto_unlock_unavailable: the vault is not in passphrase mode")
        return 20
    if status.state.value != "locked":
        _stderr("auto_unlock_repair_requires_locked_service: run 'finishup service lock' and retry")
        return 20

    try:
        passphrase = read_vault_passphrase_for_auto_unlock()
        try:
            result = await unlock_vault(bytearray(passphrase))
            if result.state != "ready":
                _stderr("vault_locked: the passphrase did not unlock the vault")
                return exit_code_for(PublicErrorCode.VAULT_LOCKED)
            store = _auto_unlock_store()
            store.save(passphrase)
            custody = store.custody
        finally:
            for index in range(len(passphrase)):
                passphrase[index] = 0
    except OSKeyringError as error:
        _stderr(f"auto_unlock_{error.reason}")
        return 20
    except Exception as error:
        failure = _trusted_exception_failure(error)
        if failure is not None:
            return failure
        raise
    report: JsonValue = {
        # Frozen legacy identifier (ADR-048): machine-readable report tag agents parse.
        "schema": "yoetz.auto-unlock-repair/1",
        "outcome": "repaired",
        "service_state": "ready",
        # Issue #1119: where the passphrase now lives (owner_file keeps it in a file only this
        # account can read, which programs running as this account can also read).
        "custody": custody,
        "next_command": "finishup service auto-unlock status",
    }
    _human_or_json(report, json_output=json_output)
    return 0


def _installation_recovery_store() -> Any:
    from finishup.config.load import load_config
    from finishup.config.paths import bundle_root
    from finishup.service.installation_recovery import InstallationRecoverySetStore

    config = load_config({}, os.environ, None)
    return InstallationRecoverySetStore(bundle_root(_data_dir=config.storage.data_dir))


def _installation_recovery_target(
    *,
    operation: Literal["provision", "rotate", "revoke", "restore"],
    recovery_generation: int,
    set_mode: Literal["compact", "self_contained"],
    secret_kind: Literal["generated_code", "argon2id_passphrase"],
) -> object:
    from finishup.service.confidential_protocol import InstallationRecoveryTarget

    target_envelope: Literal["preserve", "passphrase"] = (
        "preserve" if operation == "provision" else "passphrase"
    )
    provisional = InstallationRecoveryTarget(
        operation,
        new_id(IdKind.REQUEST),
        "sha256:" + "0" * 64,
        recovery_generation,
        set_mode,
        secret_kind,
        target_envelope,
    )
    return dataclasses.replace(provisional, confirmed_plan_digest=provisional.plan_digest())


@recovery_app.command("status")
def service_recovery_status(json_output: _JSON = False) -> None:
    """Report only bounded structural recovery state and an exact trusted next command."""

    _finish(run_async(lambda: _service_recovery_status(json_output)))


async def _service_recovery_status(json_output: bool) -> int:
    from finishup.config.load import load_config
    from finishup.config.paths import bundle_root

    config = load_config({}, os.environ, None)
    root = bundle_root(_data_dir=config.storage.data_dir)
    service_state: str | None = None
    service_reason: str | None = None
    vault_mode: str | None = None
    try:
        client = await build_service_client()
        try:
            live = await client.service_status()
            service_state = live.state.value
            service_reason = live.state_reason
            vault_mode = live.vault_mode
        finally:
            await client.close()
    except ControlError:
        pass
    status = _installation_recovery_store().status(
        installation_exists=(root / "installation-state.json").exists(),
        vault_ready=service_state == "ready",
        ordinary_unlock_available=(
            vault_mode in {"os_keyring", "passphrase"}
            and service_reason
            not in {
                "auto_unlock_rejected",
                "auto_unlock_stale",
                "keyring_unavailable",
                "unlock_failed",
            }
        ),
        auto_unlock_repairable=service_reason in {"auto_unlock_rejected", "auto_unlock_stale"},
    )
    report: JsonValue = {
        # Frozen legacy identifier (ADR-048): machine-readable report tag agents parse.
        "schema": "yoetz.installation-recovery-status/1",
        "state": status.state.value,
        "reason": status.reason,
        "active_generation": status.active_generation,
        "available_modes": list(status.available_modes),
        "continuation_id": status.continuation_id,
        "next_command": status.next_command,
        "service_state": service_state,
    }
    _human_or_json(report, json_output=json_output)
    return 0


@recovery_app.command("import")
def service_recovery_import(json_output: _JSON = False) -> None:
    """Import an archive chosen on the trusted console; the daemon must be stopped."""

    module = importlib.import_module("finishup.cli.unlock")
    operation = cast(Callable[[], Awaitable[object]], module.import_installation_recovery_set)
    _finish(run_async(lambda: _trusted_call(operation, json_output)))


@recovery_app.command("export")
def service_recovery_export(json_output: _JSON = False) -> None:
    """Export the active set to a create-only path selected on the trusted console."""

    _finish(run_async(lambda: _service_recovery_export(json_output)))


async def _service_recovery_export(json_output: bool) -> int:
    store, failure = _recovery_store_read(_installation_recovery_store)
    if failure is not None:
        return failure
    assert store is not None
    status, failure = _recovery_store_read(
        lambda: store.status(
            installation_exists=True,
            vault_ready=True,
            ordinary_unlock_available=True,
            auto_unlock_repairable=False,
        )
    )
    if failure is not None:
        return failure
    assert status is not None
    generation = status.active_generation
    if generation is None or status.reason == "recovery_material_revoked":
        _stderr("recovery_not_provisioned")
        return 20
    module = importlib.import_module("finishup.cli.unlock")
    operation = cast(Callable[[int], Awaitable[object]], module.export_installation_recovery_set)
    return await _trusted_call(lambda: operation(generation), json_output)


@recovery_app.command("provision")
def service_recovery_provision(
    mode: Annotated[str, typer.Option("--mode", help="compact or self-contained.")] = "compact",
    secret_kind: Annotated[
        str,
        typer.Option("--secret-kind", help="generated-code or argon2id-passphrase."),
    ] = "generated-code",
    json_output: _JSON = False,
) -> None:
    """Provision recovery while ready; the secret is generated or entered on the trusted console."""

    _finish(run_async(lambda: _service_recovery_provision(mode, secret_kind, json_output)))


async def _service_recovery_provision(mode: str, secret_kind: str, json_output: bool) -> int:
    return await _service_recovery_create("provision", mode, secret_kind, json_output)


async def _service_recovery_create(
    operation_name: Literal["provision", "rotate"],
    mode: str,
    secret_kind: str,
    json_output: bool,
) -> int:
    normalized_mode = mode.replace("-", "_")
    normalized_secret = secret_kind.replace("-", "_")
    if normalized_mode not in {"compact", "self_contained"} or normalized_secret not in {
        "generated_code",
        "argon2id_passphrase",
    }:
        return _usage_failure()
    store, failure = _recovery_store_read(_installation_recovery_store)
    if failure is not None:
        return failure
    assert store is not None
    current, failure = _recovery_store_read(
        lambda: store.status(
            installation_exists=True,
            vault_ready=True,
            ordinary_unlock_available=True,
            auto_unlock_repairable=False,
        )
    )
    if failure is not None:
        return failure
    assert current is not None
    generation = 1 if current.active_generation is None else current.active_generation + 1
    if operation_name == "provision" and current.active_generation is not None:
        _stderr("recovery_already_provisioned: run 'finishup service recovery rotate'")
        return 20
    if operation_name == "rotate" and current.active_generation is None:
        _stderr("recovery_not_provisioned: run 'finishup service recovery provision'")
        return 20
    target = _installation_recovery_target(
        operation=operation_name,
        recovery_generation=generation,
        set_mode=cast(Literal["compact", "self_contained"], normalized_mode),
        secret_kind=cast(Literal["generated_code", "argon2id_passphrase"], normalized_secret),
    )
    module = importlib.import_module("finishup.cli.unlock")
    operation = cast(Callable[[object], Awaitable[object]], module.provision_installation_recovery)
    return await _trusted_call(lambda: operation(target), json_output)


@recovery_app.command("rotate")
def service_recovery_rotate(
    mode: Annotated[str, typer.Option("--mode", help="compact or self-contained.")] = "compact",
    secret_kind: Annotated[
        str,
        typer.Option("--secret-kind", help="generated-code or argon2id-passphrase."),
    ] = "generated-code",
    json_output: _JSON = False,
) -> None:
    """Replace the active recovery generation after local reauthentication."""

    _finish(run_async(lambda: _service_recovery_create("rotate", mode, secret_kind, json_output)))


@recovery_app.command("revoke")
def service_recovery_revoke(json_output: _JSON = False) -> None:
    """Withdraw the active managed recovery generation after local reauthentication."""

    _finish(run_async(lambda: _service_recovery_revoke(json_output)))


async def _service_recovery_revoke(json_output: bool) -> int:
    store, failure = _recovery_store_read(_installation_recovery_store)
    if failure is not None:
        return failure
    assert store is not None
    status, failure = _recovery_store_read(
        lambda: store.status(
            installation_exists=True,
            vault_ready=True,
            ordinary_unlock_available=True,
            auto_unlock_repairable=False,
        )
    )
    if failure is not None:
        return failure
    assert status is not None
    generation = status.active_generation
    if generation is None:
        _stderr("recovery_not_provisioned")
        return 20
    if status.reason == "recovery_material_revoked":
        _stderr("recovery_already_revoked: run 'finishup service recovery rotate'")
        return 20
    metadata, failure = _recovery_store_read(lambda: store.metadata(generation))
    if failure is not None:
        return failure
    assert metadata is not None
    target = _installation_recovery_target(
        operation="revoke",
        recovery_generation=generation,
        set_mode=cast(Literal["compact", "self_contained"], metadata.mode.value),
        secret_kind=cast(
            Literal["generated_code", "argon2id_passphrase"], metadata.secret_kind.value
        ),
    )
    module = importlib.import_module("finishup.cli.unlock")
    operation = cast(Callable[[object], Awaitable[object]], module.revoke_installation_recovery)
    return await _trusted_call(lambda: operation(target), json_output)


@recovery_app.command("restore")
def service_recovery_restore(json_output: _JSON = False) -> None:
    """Recover the active managed generation and choose a new passphrase locally."""

    _finish(run_async(lambda: _service_recovery_restore(json_output)))


async def _service_recovery_restore(json_output: bool) -> int:
    store, failure = _recovery_store_read(_installation_recovery_store)
    if failure is not None:
        return failure
    assert store is not None
    status, failure = _recovery_store_read(
        lambda: store.status(
            installation_exists=True,
            vault_ready=False,
            ordinary_unlock_available=False,
            auto_unlock_repairable=False,
        )
    )
    if failure is not None:
        return failure
    assert status is not None
    generation = status.active_generation
    if generation is None:
        _stderr("recovery_material_required: no provisioned managed recovery generation")
        return exit_code_for(PublicErrorCode.VAULT_LOCKED)
    metadata, failure = _recovery_store_read(lambda: store.metadata(generation))
    if failure is not None:
        return failure
    assert metadata is not None
    target = _installation_recovery_target(
        operation="restore",
        recovery_generation=generation,
        set_mode=cast(Literal["compact", "self_contained"], metadata.mode.value),
        secret_kind=cast(
            Literal["generated_code", "argon2id_passphrase"], metadata.secret_kind.value
        ),
    )
    module = importlib.import_module("finishup.cli.unlock")
    operation = cast(Callable[[object], Awaitable[object]], module.restore_installation_recovery)
    return await _trusted_call(lambda: operation(target), json_output)


@service_app.command("initialize-passphrase")
def service_initialize_passphrase(json_output: _JSON = False) -> None:
    _finish(
        run_async(
            lambda: _trusted_call(_unlock_operation("initialize_passphrase_vault"), json_output)
        )
    )


@service_app.command("rotate-passphrase")
def service_rotate_passphrase(json_output: _JSON = False) -> None:
    """Reauthenticate and replace the vault passphrase from the trusted terminal."""

    _finish(
        run_async(lambda: _trusted_call(_unlock_operation("rotate_vault_passphrase"), json_output))
    )


def _idle_relock_target(raw: str) -> int | str:
    if raw == "disabled":
        return raw
    if not raw.isascii() or not raw.isdecimal() or (len(raw) > 1 and raw.startswith("0")):
        raise ValueError("idle_relock_target_invalid")
    value = int(raw)
    if not 60 <= value <= 86_400:
        raise ValueError("idle_relock_target_invalid")
    return value


@service_app.command("idle-relock")
def service_idle_relock(
    target: Annotated[str, typer.Argument(help="60..86400 or disabled.")],
    json_output: _JSON = False,
) -> None:
    try:
        parsed = _idle_relock_target(target)
    except ValueError:
        _finish(_usage_failure())
        return
    module = importlib.import_module("finishup.cli.unlock")
    operation = cast(
        Callable[[int | str], Awaitable[object]], getattr(module, "change_idle_relock_policy")
    )
    _finish(run_async(lambda: _trusted_call(lambda: operation(parsed), json_output)))


async def _provider_credential_target(
    action: str,
    *,
    provider_id: str | None,
    model_id: str | None,
    endpoint_profile_id: str | None,
    endpoint_profile_version: str | None,
    purpose: str | None,
    scope_digest: str | None,
    purpose_digest: str | None,
) -> tuple[object | None, str | None]:
    """Resolve the installed provider identity and privacy binding; explicit flags still win."""

    if (
        provider_id is None
        or model_id is None
        or endpoint_profile_id is None
        or endpoint_profile_version is None
    ):
        config_load = importlib.import_module("finishup.config.load")
        provider = cast(Callable[..., Any], config_load.load_config)({}, {}, None).provider
        if provider is None:
            return None, "provider_not_configured"
        provider_id = provider.provider_id if provider_id is None else provider_id
        model_id = provider.model if model_id is None else model_id
        endpoint_profile_id = (
            provider.endpoint_profile_id if endpoint_profile_id is None else endpoint_profile_id
        )
        endpoint_profile_version = (
            provider.endpoint_profile_version
            if endpoint_profile_version is None
            else endpoint_profile_version
        )
    # The stored-credential purpose and its digests are derived facts of the profile, not caller
    # input; requiring them forced operators into product internals just to paste a key.
    if purpose is None or scope_digest is None or purpose_digest is None:
        vault_module = importlib.import_module("finishup.service.vault")
        binding = cast(Callable[..., Any], vault_module.provider_credential_profile_binding)(
            provider_id, model_id, endpoint_profile_id, endpoint_profile_version
        )
        purpose = cast(str, binding.purpose) if purpose is None else purpose
        scope_digest = (
            cast(str, binding.authorization_scope_digest) if scope_digest is None else scope_digest
        )
        purpose_digest = (
            cast(str, binding.purpose_digest) if purpose_digest is None else purpose_digest
        )
    privacy = importlib.import_module("finishup.cli.privacy_setup")
    try:
        snapshot = await cast(Callable[[], Awaitable[Any]], privacy.get_privacy_setup_snapshot)()
        commitment = cast(Mapping[str, object], snapshot.bound_scope).get(
            "workspace_ref_commitment"
        )
    except Exception:
        commitment = None
    if type(commitment) is not str:
        return None, "repository_privacy_scope_unavailable"
    protocol = importlib.import_module("finishup.service.confidential_protocol")
    target_type = cast(Callable[..., object], getattr(protocol, "ProviderCredentialTarget"))
    return (
        target_type(
            action=action,
            provider_id=provider_id,
            model_id=model_id,
            endpoint_profile_id=endpoint_profile_id,
            endpoint_profile_version=endpoint_profile_version,
            purpose=purpose,
            scope_digest=scope_digest,
            purpose_digest=purpose_digest,
            repository_privacy_commitment=commitment,
        ),
        None,
    )


def _provider_credential_command(action: str) -> Callable[..., None]:
    def command(
        provider_id: Annotated[str | None, typer.Option("--provider-id")] = None,
        model_id: Annotated[str | None, typer.Option("--model-id")] = None,
        endpoint_profile_id: Annotated[str | None, typer.Option("--endpoint-profile-id")] = None,
        endpoint_profile_version: Annotated[
            str | None, typer.Option("--endpoint-profile-version")
        ] = None,
        purpose: Annotated[str | None, typer.Option("--purpose")] = None,
        scope_digest: Annotated[str | None, typer.Option("--scope-digest")] = None,
        purpose_digest: Annotated[str | None, typer.Option("--purpose-digest")] = None,
        json_output: _JSON = False,
    ) -> None:
        async def run() -> int:
            target, reason = await _provider_credential_target(
                action,
                provider_id=provider_id,
                model_id=model_id,
                endpoint_profile_id=endpoint_profile_id,
                endpoint_profile_version=endpoint_profile_version,
                purpose=purpose,
                scope_digest=scope_digest,
                purpose_digest=purpose_digest,
            )
            if target is None:
                _stderr(_bounded_failure_line(reason or "provider_credential_invalid"))
                return exit_code_for(PublicErrorCode.INVALID_REQUEST)
            unlock_module = importlib.import_module("finishup.cli.unlock")
            function_name = (
                "set_provider_credential" if action == "set" else "rotate_provider_credential"
            )
            operation = cast(
                Callable[..., Awaitable[object]], getattr(unlock_module, function_name)
            )
            # A Keychain-provisioned passphrase vault is ready without the human ever knowing its
            # generated passphrase; without this the ceremony asks for a secret they never saw.
            reauthentication = cast(
                Callable[[], bytearray | None],
                getattr(unlock_module, "load_auto_unlock_reauthentication"),
            )()
            return await _trusted_call(
                lambda: operation(target, None, reauthentication), json_output
            )

        try:
            _finish(run_async(run))
        except (ProtocolValueError, ValueError):
            _finish(_usage_failure())

    return command


credential_app.command("set")(_provider_credential_command("set"))
credential_app.command("rotate")(_provider_credential_command("rotate"))


@codex_subscription_app.command("setup")
def provider_codex_subscription_setup(
    executable: Annotated[
        Path | None,
        typer.Option(
            "--executable",
            help=(
                "Codex CLI/native executable to check and bind. Defaults to the newest Codex at "
                "or above the evaluator minimum among FinishUP's retained copies, the existing "
                "binding, and discovered installations, falling back to older ones that pass."
            ),
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            help=(
                "Exact Codex model id. A new binding is offered gpt-6.1-sol, or gpt-6-luna when "
                "the admitted Codex does not list it; an existing binding keeps its model when "
                "omitted."
            ),
        ),
    ] = None,
    reasoning_effort: Annotated[
        str | None,
        typer.Option(
            "--reasoning-effort",
            help=(
                "Final review effort; medium for a new binding, otherwise preserves its current "
                "choice."
            ),
        ),
    ] = None,
    routine_reasoning_effort: Annotated[
        str | None,
        typer.Option(
            "--routine-reasoning-effort",
            help=(
                "Exact reasoning effort for routine checkpoint reviews. Defaults to medium for "
                "a new binding and preserves an existing binding's routine choice when omitted."
            ),
        ),
    ] = None,
    codex_home: Annotated[
        Path | None,
        typer.Option("--codex-home", help="Dedicated owner-private evaluator CODEX_HOME."),
    ] = None,
    device_code: Annotated[
        bool, typer.Option("--device-code", help="Use Codex's documented device-code flow.")
    ] = False,
    open_browser: Annotated[
        bool, typer.Option("--open-browser/--no-open-browser", help="Open Codex's returned URL.")
    ] = True,
    switch_account: Annotated[
        bool,
        typer.Option(
            "--switch-account",
            help="Log out the dedicated home and sign in again, even if it is already signed in.",
        ),
    ] = False,
    accept: Annotated[
        bool,
        typer.Option("--accept", help="Explicitly accept the displayed destination/terms notice."),
    ] = False,
    as_fallback: Annotated[
        bool,
        typer.Option(
            "--as-fallback",
            help=(
                "Keep the bound API provider as the primary and bind this runtime as the "
                "fallback that serves only after the primary cannot."
            ),
        ),
    ] = False,
    json_output: _JSON = False,
) -> None:
    """Capability-check the newest Codex, prove or obtain its login, then bind it."""

    from finishup.adapters.providers.codex_app_server import (
        CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
        CODEX_EVALUATOR_RUNTIME_FLOOR,
    )
    from finishup.adapters.providers.codex_evaluator_runtime import managed_runtime_path
    from finishup.cli.codex_subscription import (
        CODEX_SUBSCRIPTION_FALLBACK_MODEL,
        codex_subscription_model_is_suggested,
        codex_subscription_setup,
        default_codex_evaluator_executable,
        default_codex_home,
        default_codex_subscription_model,
        default_codex_subscription_reasoning_effort,
        default_codex_subscription_routine_effort,
        resolve_codex_executable,
        runtime_bundle,
    )

    try:
        shown_executable = (
            default_codex_evaluator_executable() if executable is None else executable
        )
        if shown_executable is None:
            raise ValueError("codex_evaluator_runtime_unavailable")
        resolved = resolve_codex_executable(shown_executable)
        destination = default_codex_home() if codex_home is None else codex_home
        selected_model = default_codex_subscription_model() if model is None else model
        # Setup's own suggestion for a new binding may fall back when Codex does not list it;
        # an explicit --model or an existing binding's model is never substituted.
        model_is_suggestion = (
            model is None
            and selected_model != CODEX_SUBSCRIPTION_FALLBACK_MODEL
            and codex_subscription_model_is_suggested()
        )
        selected_routine = (
            default_codex_subscription_routine_effort()
            if routine_reasoning_effort is None
            else routine_reasoning_effort
        )
        selected_effort = (
            default_codex_subscription_reasoning_effort()
            if reasoning_effort is None
            else reasoning_effort
        )
        typer.echo("Codex with ChatGPT subscription")
        typer.echo(f"  runtime source: {resolved.native}")
        typer.echo(
            f"  Codex version: {resolved.version} (minimum {CODEX_EVALUATOR_RUNTIME_FLOOR}), "
            "capability-checked before it is bound"
            + (
                "; an older installed release is used if this one fails the check"
                if executable is None
                else ""
            )
        )
        typer.echo(
            f"  bound runtime: {managed_runtime_path(runtime_bundle(), resolved.source_identity)} "
            "(FinishUP's private copy; a later Codex update is adopted on the next repair)"
        )
        typer.echo(f"  source: {resolved.source_identity}")
        typer.echo(f"  evidence expires: {CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT}")
        typer.echo(f"  dedicated CODEX_HOME: {destination}")
        typer.echo(
            f"  model: {selected_model}"
            + (
                f" (suggested; {CODEX_SUBSCRIPTION_FALLBACK_MODEL} if this Codex does not list it)"
                if model_is_suggestion
                else ""
            )
        )
        typer.echo(
            f"  reasoning: final {selected_effort} / routine "
            + (
                f"{selected_effort} (legacy single effort kept)"
                if selected_routine is None
                else selected_routine
            )
        )
        typer.echo("  destination: OpenAI through Codex-managed ChatGPT authentication")
        typer.echo("  data-use posture: unknown; your ChatGPT plan and terms apply")
        typer.echo("  FinishUP sends only a privacy-approved case; Codex owns the upstream body.")
        typer.echo("  disconnect: finishup provider codex-subscription disconnect")
        typer.echo("  rollback only: finishup provider codex-subscription rollback")
        if as_fallback:
            typer.echo("  role: fallback behind the bound API provider (primary)")
            typer.echo("  remove pairing: finishup provider fallback remove")
        if switch_account:
            typer.echo("  existing sign-in: logged out first, then a new Codex sign-in")
        else:
            typer.echo(
                "  existing sign-in: reused when Codex reports the home already signed in;"
                " pass --switch-account to sign in again"
            )
        if not accept:
            if not (sys.stdin.isatty() and sys.stdout.isatty()) or not typer.confirm(
                "Continue to Codex sign-in?", default=False
            ):
                _finish(20)
                return
        payload = run_async(
            lambda: _codex_subscription_mutate(
                lambda: codex_subscription_setup(
                    executable=executable,
                    codex_home=destination,
                    model=selected_model,
                    reasoning_effort=selected_effort,
                    routine_reasoning_effort=selected_routine,
                    login_mode="device_code" if device_code else "browser",
                    open_browser=open_browser,
                    switch_account=switch_account,
                    as_fallback=as_fallback,
                    model_is_suggestion=model_is_suggestion,
                )
            )
        )
        _human_or_json(cast(Mapping[str, JsonValue], payload), json_output=json_output)
        _finish(0)
    except (OSError, TimeoutError, ValueError) as error:
        _codex_subscription_cli_failure(error)
        _finish(20)


@codex_subscription_app.command("status")
def provider_codex_subscription_status(json_output: _JSON = False) -> None:
    """Read bound runtime, login, plan, model, and cleanup state without task content."""

    from finishup.cli.codex_subscription import codex_subscription_status

    try:
        payload = run_async(codex_subscription_status)
        _human_or_json(cast(Mapping[str, JsonValue], payload), json_output=json_output)
        _finish(0 if payload.get("model_available") is True else 20)
    except (OSError, TimeoutError, ValueError) as error:
        _codex_subscription_cli_failure(error)
        _finish(20)


@codex_subscription_app.command("disconnect")
def provider_codex_subscription_disconnect(
    accept: Annotated[
        bool, typer.Option("--accept", help="Confirm logout of only the dedicated Codex home.")
    ] = False,
    json_output: _JSON = False,
) -> None:
    """Ask Codex to log out its dedicated home, confirm it, then remove the binding."""

    from finishup.cli.codex_subscription import codex_subscription_disconnect

    if not accept and (
        not (sys.stdin.isatty() and sys.stdout.isatty())
        or not typer.confirm(
            "Log out the dedicated evaluator home and remove its binding?", default=False
        )
    ):
        _finish(20)
        return
    try:
        payload = run_async(lambda: _codex_subscription_mutate(codex_subscription_disconnect))
        _human_or_json(cast(Mapping[str, JsonValue], payload), json_output=json_output)
        _finish(0)
    except (OSError, TimeoutError, ValueError) as error:
        _codex_subscription_cli_failure(error)
        _finish(20)


@codex_subscription_app.command("rollback")
def provider_codex_subscription_rollback(json_output: _JSON = False) -> None:
    """Remove only the FinishUP binding; preserve the Codex installation and dedicated home."""

    from finishup.cli.codex_subscription import codex_subscription_rollback

    try:
        payload = codex_subscription_rollback()

        async def recompose() -> None:
            await _codex_subscription_mutate(_noop_subscription_recompose)

        run_async(recompose)
        _human_or_json(payload, json_output=json_output)
        _finish(0)
    except (OSError, ValueError) as error:
        _codex_subscription_cli_failure(error)
        _finish(20)


def _confirm_or_refuse(accept: bool, question: str) -> bool:
    """An explicit ``--accept``, or a yes from an interactive terminal; never an implied yes."""

    if accept:
        return True
    return sys.stdin.isatty() and sys.stdout.isatty() and typer.confirm(question, default=False)


@codex_subscription_app.command("repair")
def provider_codex_subscription_repair(
    executable: Annotated[
        Path | None,
        typer.Option(
            "--executable",
            help=(
                "Codex CLI/native executable to check and bind instead of the newest eligible "
                "installation. It must pass the capability check."
            ),
        ),
    ] = None,
    accept: Annotated[
        bool, typer.Option("--accept", help="Confirm the displayed rebinding without a prompt.")
    ] = False,
    json_output: _JSON = False,
) -> None:
    """Rebind to the newest Codex that passes the capability check; keep login and choices.

    Model, reasoning effort, timeout, retries, dedicated home, endpoint role, and privacy grants
    are preserved. The existing sign-in is reused only when Codex reports the dedicated home
    signed in with the exact model; repair never opens a sign-in or switches accounts.
    """

    from finishup.cli.codex_subscription import (
        codex_subscription_repair,
        codex_subscription_repair_plan,
    )

    try:
        plan = codex_subscription_repair_plan(executable=executable)
        candidates = cast(list[Mapping[str, object]], plan["candidates"])
        if not json_output:
            typer.echo("Repair the Codex subscription evaluator binding")
            typer.echo(f"  current state: {plan['state_before']}")
            typer.echo(
                f"  Codex: {plan['runtime_version_before']} -> {plan['runtime_version_after']} "
                f"from {plan['source_path']} ({plan['source']})"
            )
            typer.echo(
                f"  bound runtime: {plan['executable_path_after']} (FinishUP's private copy; a "
                "later Codex update is adopted on the next repair)"
            )
            typer.echo(
                f"  capability profile: {plan['capability_profile_before']} -> "
                f"{plan['capability_profile_after']}"
            )
            typer.echo(
                "  capability check: runs before anything is written; fallbacks if it fails: "
                + (", ".join(str(item["runtime_version"]) for item in candidates[1:]) or "none")
            )
            typer.echo(
                "  preserved: model, reasoning effort, timeout, retries, dedicated home, "
                "endpoint role, and privacy grants"
            )
            typer.echo(
                "  sign-in: reused only if Codex reports this home signed in; repair never signs "
                "in, logs out, or switches accounts"
            )
        if not _confirm_or_refuse(accept, "Apply this repair?"):
            _finish(20)
            return
        payload = run_async(
            lambda: _codex_subscription_mutate(
                lambda: codex_subscription_repair(executable=executable)
            )
        )
        _human_or_json(cast(Mapping[str, JsonValue], payload), json_output=json_output)
        _finish(0)
    except (OSError, TimeoutError, ValueError) as error:
        _codex_subscription_cli_failure(error)
        _finish(20)


@codex_evaluator_runtime_app.command("status")
def provider_codex_evaluator_runtime_status(json_output: _JSON = False) -> None:
    """Report the retained runtime and the binding's structural state without starting Codex."""

    from finishup.cli.codex_subscription import codex_evaluator_runtime_status

    try:
        payload = codex_evaluator_runtime_status()
        _human_or_json(payload, json_output=json_output)
        binding = payload.get("binding")
        ready = binding is None or cast(Mapping[str, object], binding).get("state") == "ready"
        _finish(0 if ready else 20)
    except (OSError, ValueError) as error:
        _codex_subscription_cli_failure(error)
        _finish(20)


@codex_evaluator_runtime_app.command("install")
def provider_codex_evaluator_runtime_install(
    source: Annotated[
        Path | None,
        typer.Option(
            "--from",
            help="Codex CLI/native executable to retain and capability-check.",
        ),
    ] = None,
    download: Annotated[
        bool,
        typer.Option(
            "--download",
            help=(
                "Allow downloading the newest stable Codex with your npm when no eligible local "
                "Codex exists."
            ),
        ),
    ] = False,
    npm: Annotated[
        Path | None, typer.Option("--npm", help="Absolute npm executable to download with.")
    ] = None,
    accept: Annotated[
        bool, typer.Option("--accept", help="Confirm the displayed retention without a prompt.")
    ] = False,
    json_output: _JSON = False,
) -> None:
    """Keep a capability-checked private copy of the newest Codex; never edits the binding."""

    from finishup.cli.codex_subscription import (
        codex_evaluator_runtime_install,
        codex_evaluator_runtime_install_plan,
        describe_runtime_download,
    )

    try:
        plan = codex_evaluator_runtime_install_plan(source=source, download=download)
        if not json_output:
            typer.echo("Retain the Codex subscription evaluator runtime")
            if plan["download"] is True:
                typer.echo("  source: download")
                for line in describe_runtime_download():
                    typer.echo(f"  {line}")
            else:
                typer.echo(f"  source: {plan['source_path']} ({plan['source']})")
            typer.echo(
                f"  runtime: Codex {plan['runtime_version']} (minimum {plan['runtime_floor']})"
            )
            if plan["managed_runtime_path"] is not None:
                typer.echo(f"  retained at: {plan['managed_runtime_path']}")
                typer.echo(f"  current copy: {plan['managed_runtime_state']}")
            typer.echo(
                "  the copy is capability-checked without any sign-in or task content before "
                "it is kept as admitted"
            )
            typer.echo("  the binding is not changed; run repair or setup to bind this copy")
        question = (
            "Download and retain the evaluator runtime?"
            if plan["download"] is True
            else "Retain this evaluator runtime?"
        )
        if not _confirm_or_refuse(accept, question):
            _finish(20)
            return
        payload = run_async(
            lambda: codex_evaluator_runtime_install(source=source, npm=npm, download=download)
        )
        _human_or_json(payload, json_output=json_output)
        _finish(0)
    except (OSError, TimeoutError, ValueError) as error:
        _codex_subscription_cli_failure(error)
        _finish(20)


@codex_evaluator_runtime_app.command("remove")
def provider_codex_evaluator_runtime_remove(
    accept: Annotated[
        bool, typer.Option("--accept", help="Confirm removal of the unreferenced retained copies.")
    ] = False,
    json_output: _JSON = False,
) -> None:
    """Delete FinishUP's retained runtime copies the binding does not use; never the bound one."""

    from finishup.cli.codex_subscription import codex_evaluator_runtime_remove

    if not _confirm_or_refuse(
        accept,
        "Remove FinishUP's retained evaluator runtime copies the binding does not use (not your "
        "Codex installation)?",
    ):
        _finish(20)
        return
    try:
        payload = codex_evaluator_runtime_remove()
        _human_or_json(payload, json_output=json_output)
        _finish(0)
    except (OSError, ValueError) as error:
        _codex_subscription_cli_failure(error)
        _finish(20)


@provider_app.command("status")
def provider_status(
    json_output: _JSON = False,
    codex_home: Annotated[Path | None, typer.Option("--codex-home")] = None,
    codex_path: _CODEX_PATH = None,
) -> None:
    """Report whether external AI-powered review is structurally ready to dispatch."""

    from finishup.cli.provider_status import run_provider_status

    _finish(
        run_async(
            lambda: run_provider_status(
                json_output=json_output, codex_home=codex_home, codex_path=codex_path
            )
        )
    )


def _semantic_fallback_payload(path: Path, config: object) -> dict[str, JsonValue]:
    from finishup.config.models import (
        FinishUpConfig,
        fallback_external_endpoint,
        primary_external_endpoint,
    )

    assert type(config) is FinishUpConfig
    primary = primary_external_endpoint(config)
    fallback = fallback_external_endpoint(config)
    return {
        "config_path": str(path),
        "profile": config.profile,
        "primary": (None if config.semantic_fallback is None else config.semantic_fallback.primary),
        "primary_endpoint": (
            None
            if primary is None
            else {
                "provider_id": primary.provider_id,
                "model": primary.model,
                "endpoint_profile_id": primary.endpoint_profile_id,
                "endpoint_profile_version": primary.endpoint_profile_version,
            }
        ),
        "fallback_endpoint": (
            None
            if fallback is None
            else {
                "provider_id": fallback.provider_id,
                "model": fallback.model,
                "endpoint_profile_id": fallback.endpoint_profile_id,
                "endpoint_profile_version": fallback.endpoint_profile_version,
            }
        ),
    }


@fallback_app.command("remove")
def provider_fallback_remove(json_output: _JSON = False) -> None:
    """Drop the fallback endpoint and its selector; the primary keeps serving alone."""

    from finishup.cli.provider_binding import remove_semantic_fallback
    from finishup.config.models import ConfigError

    try:
        path, config = remove_semantic_fallback()
    except ConfigError as error:
        typer.echo(f"invalid_request: {error.reason_code}", err=True)
        _finish(2)
        return
    _human_or_json(_semantic_fallback_payload(path, config), json_output=json_output)
    typer.echo(
        "next: the privacy policy still names the removed endpoint until you re-run "
        "'finishup privacy setup'; review the resulting policy changes there",
        err=True,
    )
    _finish(0)


@fallback_app.command("primary")
def provider_fallback_primary(
    primary: Annotated[
        str,
        typer.Argument(
            help="Which bound endpoint serves first: api_provider or codex_subscription."
        ),
    ],
    json_output: _JSON = False,
) -> None:
    """Swap which of the two bound endpoints is the primary; both stay bound and approved."""

    from finishup.cli.provider_binding import set_semantic_fallback_primary
    from finishup.config.models import ConfigError

    if primary not in {"api_provider", "codex_subscription"}:
        _finish(_usage_failure())
        return
    try:
        path, config = set_semantic_fallback_primary(
            cast(Literal["api_provider", "codex_subscription"], primary)
        )
    except ConfigError as error:
        typer.echo(f"invalid_request: {error.reason_code}", err=True)
        _finish(2)
        return
    _human_or_json(_semantic_fallback_payload(path, config), json_output=json_output)
    _finish(0)


@provider_app.command("catalog")
def provider_catalog(json_output: _JSON = False) -> None:
    """List the installed reviewed presets and their suggested model IDs without network access."""

    from finishup.config.write import PROVIDER_PRESETS

    presets = [
        {
            "preset": name,
            "provider_id": preset.provider_id,
            "endpoint_profile_id": preset.endpoint_profile_id,
            "endpoint_profile_version": preset.endpoint_profile_version,
            "suggested_models": list(preset.suggested_models),
            "custom_model_id_supported": True,
        }
        for name, preset in PROVIDER_PRESETS.items()
    ]
    _human_or_json(
        {
            # Frozen legacy identifier (ADR-048): machine-readable report tag agents parse.
            "schema": "yoetz.provider-catalog/1",
            "presets": presets,
            "limitations": [
                "catalog_support_is_not_account_entitlement",
                "catalog_support_is_not_live_provider_proof",
            ],
        },
        json_output=json_output,
    )


@provider_app.command("endpoint")
def provider_endpoint(
    official: Annotated[
        bool, typer.Option("--official", help="Bind the bundled Official OpenAI Responses profile.")
    ] = False,
    grok: Annotated[
        bool,
        typer.Option("--grok", help="Bind the bundled Grok / xAI Chat Completions profile."),
    ] = False,
    fireworks: Annotated[
        bool,
        typer.Option(
            "--fireworks",
            help="Bind the reviewed Fireworks Responses profile.",
        ),
    ] = False,
    provider_name: Annotated[
        str | None,
        typer.Option(
            "--provider",
            help=(
                "Reviewed preset: openai, fireworks, anthropic, gemini, openrouter, grok, "
                "or vercel-ai-gateway."
            ),
        ),
    ] = None,
    https_origin: Annotated[
        str | None,
        typer.Option(
            "--https-origin",
            help="Owner-declared HTTPS origin (https://host[:port] only).",
        ),
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="Model identifier.")] = None,
    interactive: Annotated[
        bool, typer.Option("--interactive/--no-interactive", help="Prompt on a TTY.")
    ] = True,
    as_fallback: Annotated[
        bool,
        typer.Option(
            "--as-fallback",
            help=(
                "Keep the bound Codex subscription as the primary and bind this provider as "
                "the fallback that serves only after the primary cannot."
            ),
        ),
    ] = False,
    json_output: _JSON = False,
) -> None:
    """Write a nonsecret reviewed provider or owner-declared binding to config.toml."""

    from finishup.cli.provider_binding import (
        ProviderEndpointChoice,
        apply_provider_endpoint_choice,
        prompt_provider_endpoint_binding,
        prompt_provider_model,
    )
    from finishup.config.models import ConfigError
    from finishup.config.write import provider_preset

    try:
        if (
            interactive
            and not official
            and not fireworks
            and not grok
            and provider_name is None
            and https_origin is None
            and model is None
        ):
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                _finish(_usage_failure())
                return
            selected = prompt_provider_endpoint_binding()
            if selected == "codex_subscription":
                typer.echo("next: finishup provider codex-subscription setup")
            _finish(0)
            return
        if (
            (official and (fireworks or grok))
            or (fireworks and grok)
            or (
                provider_name is not None
                and (official or fireworks or grok or https_origin is not None)
            )
            or ((official or fireworks or grok) and https_origin is not None)
        ):
            _finish(_usage_failure())
            return
        choice: ProviderEndpointChoice
        if provider_name is not None:
            choice = cast(ProviderEndpointChoice, provider_preset(provider_name).choice)
        elif official:
            choice = "official_openai"
        elif fireworks:
            choice = "fireworks"
        elif grok:
            choice = "grok"
        elif https_origin is not None:
            choice = "owner_declared"
        else:
            _finish(_usage_failure())
            return
        if model is None:
            if not interactive or not (sys.stdin.isatty() and sys.stdout.isatty()):
                _finish(_usage_failure())
                return
            if choice == "owner_declared":
                model = typer.prompt("Model id", show_default=False).strip()
            else:
                model = prompt_provider_model(choice)
            if not model:
                _finish(_usage_failure())
                return
        if choice == "owner_declared":
            path, provider = apply_provider_endpoint_choice(
                "owner_declared", model=model, https_origin=https_origin, as_fallback=as_fallback
            )
        else:
            path, provider = apply_provider_endpoint_choice(
                choice, model=model, as_fallback=as_fallback
            )
        payload = {
            "config_path": str(path),
            "endpoint_profile_id": provider.endpoint_profile_id,
            "endpoint_profile_version": provider.endpoint_profile_version,
            "model": provider.model,
            "provider_id": provider.provider_id,
            "endpoint_role": "fallback" if as_fallback else "primary",
        }
        if provider.owner_declared_endpoint is not None:
            payload["https_origin"] = provider.owner_declared_endpoint.https_origin
        _human_or_json(payload, json_output=json_output)
        _finish(0)
    except ConfigError as error:
        typer.echo(f"invalid_request: {error.reason_code}", err=True)
        _finish(2)


@privacy_app.command("export-desired")
def privacy_export_desired(
    output: Annotated[Path, typer.Option("--output", help="Destination TOML path.")],
    json_output: _JSON = False,
) -> None:
    """Export effective nonsecret privacy policy as desired-state TOML (never secrets)."""

    async def _run() -> int:
        from finishup.adapters.privacy.catalog import decode_privacy_policy_canonical
        from finishup.config.privacy_desired import write_privacy_desired_toml

        # Machine scope is a local construction; resolve it before connecting so a broken
        # installation marker stops here without any service request (issue #517).
        scoped = _machine_scope_request_or_none()
        if scoped is None:
            return 2
        try:
            client = await build_service_client()
            try:
                effective = await client.privacy_get_effective(scoped)
            finally:
                await client.close()
        except ControlError as error:
            return _control_failure(error)
        plain = _plain_json(effective)
        if type(plain) is not dict or "policy" not in plain:
            return _usage_failure()
        try:
            policy = decode_privacy_policy_canonical(
                canonical_encode(cast(JsonValue, plain["policy"]))
            )
        except Exception:
            return _usage_failure()
        path = write_privacy_desired_toml(policy, output)
        _human_or_json(
            # Frozen legacy identifier (ADR-048): machine-readable report tag agents parse.
            {"path": str(path), "schema": "yoetz.privacy-desired/1"},
            json_output=json_output,
        )
        return 0

    _finish(run_async(_run))


@privacy_app.command("apply-desired")
def privacy_apply_desired(
    input_path: Annotated[Path, typer.Option("--input", help="Desired-state TOML path.")],
    json_output: _JSON = False,
) -> None:
    """Classify privacy desired-state TOML: tighten may proceed via gates; widen never silent."""

    async def _run() -> int:
        from finishup.adapters.privacy.catalog import decode_privacy_policy_canonical
        from finishup.application.privacy_policy import is_privacy_tightening
        from finishup.config.models import ConfigError
        from finishup.config.privacy_desired import load_privacy_desired_canonical

        try:
            candidate = decode_privacy_policy_canonical(load_privacy_desired_canonical(input_path))
        except ConfigError as error:
            typer.echo(f"invalid_request: {error.reason_code}", err=True)
            return 2
        # Machine scope is a local construction; resolve it before connecting so a broken
        # installation marker stops here without any service request (issue #517).
        scoped = _machine_scope_request_or_none()
        if scoped is None:
            return 2
        try:
            client = await build_service_client()
            try:
                effective = await client.privacy_get_effective(scoped)
            finally:
                await client.close()
        except ControlError as error:
            return _control_failure(error)
        plain = _plain_json(effective)
        if type(plain) is not dict or "policy" not in plain:
            return _usage_failure()
        try:
            current = decode_privacy_policy_canonical(
                canonical_encode(cast(JsonValue, plain["policy"]))
            )
        except Exception:
            return _usage_failure()
        if current == candidate:
            _human_or_json({"outcome": "equivalent"}, json_output=json_output)
            return 0
        try:
            tightening = is_privacy_tightening(current, candidate)
        except (TypeError, ValueError):
            # Classification is the gate. If it cannot run, this is not a tighten, and the
            # command must not fall through to the widen message as if it had decided.
            return _usage_failure()
        if tightening:
            _human_or_json(
                {
                    "next": "finishup privacy tighten",
                    "note": "desired-state is a tighten; apply via the existing tighten gate",
                    "outcome": "tighten",
                },
                json_output=json_output,
            )
            return 0
        typer.echo(
            "widening_requires_decide: editing desired-state TOML cannot silently widen egress; "
            "run 'finishup privacy propose' then 'finishup privacy decide-policy'.",
            err=True,
        )
        _human_or_json(
            {
                "next": "finishup privacy propose → finishup privacy decide-policy",
                "outcome": "widen",
            },
            json_output=json_output,
        )
        return 2

    _finish(run_async(_run))


def _privacy_decision_command(kind: str) -> Callable[..., None]:
    def command(
        pending_id: Annotated[str, typer.Argument(help="Exact pending privacy decision ID.")],
        json_output: _JSON = False,
    ) -> None:
        module = importlib.import_module("finishup.cli.privacy_control")
        operation = cast(Callable[[str], Awaitable[object]], getattr(module, f"decide_{kind}"))

        async def run_decision() -> object:
            if kind != "policy":
                return await operation(pending_id)
            passphrase = _auto_unlock_store().load()
            if passphrase is None:
                return await operation(pending_id)
            auto_operation = cast(
                Callable[[str, bytearray], Awaitable[object]],
                getattr(module, "decide_policy_with_local_reauthentication"),
            )
            return await auto_operation(pending_id, passphrase)

        _finish(run_async(lambda: _trusted_call(run_decision, json_output)))

    return command


privacy_app.command("decide-policy")(_privacy_decision_command("policy"))
privacy_app.command("decide-disclosure")(_privacy_decision_command("disclosure"))


async def _privacy_pending(json_output: bool) -> int:
    try:
        client = await build_service_client()
        try:
            result = await client.privacy_pending_list()
        finally:
            await client.close()
    except (ProtocolValueError, ValueError):
        return _usage_failure()
    except ControlError as error:
        return _control_failure(error)
    if json_output:
        _human_or_json(result, json_output=True)
        return 0
    # Canonical JSON freezes arrays to tuples, so a list-only check would silently report
    # "nothing waiting" for every populated answer.
    pending = result.get("pending")
    rows: tuple[object, ...] = tuple(pending) if isinstance(pending, list | tuple) else ()
    if not rows:
        typer.echo("No disclosure decision is waiting.")
        return 0
    typer.echo("Disclosure decisions waiting for you:")
    empty: Mapping[str, object] = {}
    for row in rows:
        entry = cast("Mapping[str, object]", row) if isinstance(row, Mapping) else empty
        typer.echo(f"  {entry.get('pending_id')}  expires {entry.get('expires_at')}")
    typer.echo("")
    typer.echo("Decide one with 'finishup privacy decide-disclosure <pending_id>'.")
    return 0


@privacy_app.command("pending")
def privacy_pending(json_output: _JSON = False) -> None:
    """List disclosure decisions awaiting a local human.

    `decide-disclosure` needs an exact id, which normally arrives in a check result. When that
    is lost -- a closed terminal, an agent that did not relay it -- this is how the ceremony is
    found again. It names the waiting decisions and nothing about what they would disclose.
    """

    _finish(run_async(lambda: _privacy_pending(json_output)))


def _partial_receipt_page_lines(undecodable_count: int, receipt_ids: tuple[str, ...]) -> str:
    """Say that a receipt page is partial, how partial, and which receipts to look at (#921).

    Only the count and structural receipt ids are printed; nothing a skipped row stored is.
    """

    from finishup.cli.render import render_recovery_directive_lines
    from finishup.protocol.recovery import continuation_for_reason, directive_for

    named = f": {', '.join(receipt_ids)}" if receipt_ids else ""
    lines = [
        f"privacy_audit_unreadable: this page is partial; {undecodable_count} stored "
        f"receipt(s) could not be read back and were skipped{named}"
    ]
    directive = directive_for(continuation_for_reason("privacy_audit_unreadable"))
    if directive is not None:
        lines.extend(render_recovery_directive_lines(directive))
    return "\n".join(lines)


def _receipt_not_sent_lines(views: Iterable[object]) -> tuple[str, ...]:
    """Label classification-only approvals on network receipts whose dispatch never started.

    A refused request can still carry ``approved_categories`` and ``counts.approved_items``: they
    record what classification approved, not what left the machine (#1019). The released receipt
    shape cannot carry a new field, so the human rendering says so beside it. Only structural
    receipt ids and closed outcome values are printed.
    """

    from finishup.ports.privacy import NetworkEgressReceiptView

    lines: list[str] = []
    for view in views:
        if type(view) is not NetworkEgressReceiptView:
            continue
        receipt = view.receipt
        if receipt.dispatch_id is not None or not (
            receipt.approved_categories or receipt.counts.approved_items
        ):
            continue
        lines.append(
            f"not sent: privacy receipt {receipt.receipt_id} ({receipt.outcome.value}) never "
            "reached a provider; its approved_categories and counts.approved_items are "
            "classification results, not data sent"
        )
    return tuple(lines)


async def _privacy_receipts_list(page_size: int, cursor: str | None, json_output: bool) -> int:
    from finishup.service.client import ListPrivacyReceiptsRequest

    try:
        request = ListPrivacyReceiptsRequest(page_size=page_size, cursor=cursor)
        client = await build_service_client()
        try:
            result = await client.privacy_receipts_list(request)
        finally:
            await client.close()
    except (ProtocolValueError, ValueError):
        return _usage_failure()
    except ControlError as error:
        return _control_failure(error, json_output=json_output)
    _human_or_json(result, json_output=json_output)
    if not json_output:
        for line in _receipt_not_sent_lines(result.receipts):
            _stderr(line)
    if result.undecodable_count:
        # A partial page is printed in full -- every receipt that could be read -- and then exits
        # non-zero, so a script can never mistake it for a complete listing.
        _stderr(
            _partial_receipt_page_lines(result.undecodable_count, result.undecodable_receipt_ids)
        )
        return exit_code_for(PublicErrorCode.STORAGE_CORRUPT)
    return 0


@privacy_receipts_app.command("list")
def privacy_receipts_list(
    page_size: Annotated[int, typer.Option("--page-size", min=1, max=100)] = 50,
    cursor: Annotated[str | None, typer.Option("--cursor")] = None,
    json_output: _JSON = False,
) -> None:
    _finish(run_async(lambda: _privacy_receipts_list(page_size, cursor, json_output)))


async def _privacy_receipts_get(receipt_id: str, json_output: bool) -> int:
    from finishup.service.client import GetPrivacyReceiptRequest, PrivacyReceiptFound

    try:
        request = GetPrivacyReceiptRequest(receipt_id)
        client = await build_service_client()
        try:
            result = await client.privacy_receipts_get(request)
        finally:
            await client.close()
    except (ProtocolValueError, ValueError):
        return _usage_failure()
    except ControlError as error:
        return _control_failure(error, json_output=json_output)
    _human_or_json(result, json_output=json_output)
    if not json_output and isinstance(result, PrivacyReceiptFound):
        for line in _receipt_not_sent_lines((result.receipt,)):
            _stderr(line)
    return 0


@privacy_receipts_app.command("get")
def privacy_receipts_get(
    receipt_id: Annotated[str, typer.Argument(help="Exact privacy receipt ID.")],
    json_output: _JSON = False,
) -> None:
    _finish(run_async(lambda: _privacy_receipts_get(receipt_id, json_output)))


@app.command("menu")
def menu_command() -> None:
    """Open the interactive FinishUP interface for setup, connections, privacy, and service."""

    if _open_tui(first_run=False):
        return
    module = importlib.import_module("finishup.cli.menu")
    operation = cast(Callable[[], int], getattr(module, "run_menu"))
    _finish(operation())


@app.command("version")
def version_command(
    json_output: _JSON = False,
    resources: Annotated[
        bool,
        typer.Option("--resources", help="Enumerate every reviewed installed resource identity."),
    ] = False,
) -> None:
    """Show installed public package/runtime identity."""

    if not json_output:
        typer.echo(__version__)
        return
    try:
        package = importlib.import_module("finishup")
        module = importlib.import_module("finishup.version")
        builder = cast(Callable[[], object], getattr(package, "get_version_manifest"))
        serializer = cast(
            Callable[..., bytes],
            getattr(module, "version_manifest_json"),
        )
        _safe_write(sys.stdout.buffer, serializer(builder(), include_resources=resources) + b"\n")
    except ResourceIntegrityError as error:
        detail = f" {error.detail}" if error.detail else ""
        _stderr(f"version: FAIL ({error.reason}){detail}")
        remediation = remediation_message(error.reason)
        if remediation is not None:
            _stderr(f"version: remediation: {remediation}")
        for line in render_local_recovery_lines(error.reason):
            _stderr(f"version: {line}")
        raise typer.Exit(1) from None
    except ImportError:
        _stdout_json({"package_name": "finishup", "package_version": __version__})


@app.callback()
def root(
    context: typer.Context,
    version: Annotated[
        bool,
        typer.Option("--version", is_eager=True, help="Show the installed package version."),
    ] = False,
    set_provider: Annotated[
        bool,
        typer.Option(
            "--set",
            help="Set up the LLM model and API key through the secure local wizard.",
        ),
    ] = False,
    privacy: Annotated[
        bool,
        typer.Option(
            "--privacy",
            help="Review or change the privacy policy through the trusted local wizard.",
        ),
    ] = False,
    fireworks: Annotated[
        bool,
        typer.Option("--fireworks", help="Use the bundled Fireworks Responses profile."),
    ] = False,
    grok: Annotated[
        bool,
        typer.Option("--grok", help="Use the bundled Grok / xAI Chat Completions profile."),
    ] = False,
    provider_name: Annotated[
        str | None,
        typer.Option(
            "--provider",
            help="Reviewed provider preset used with --set.",
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="Provider model identifier used with --set."),
    ] = None,
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit(0)
    if privacy:
        if context.invoked_subcommand is not None:
            raise typer.BadParameter("--privacy cannot be combined with a subcommand")
        if set_provider or grok or fireworks or provider_name is not None or model is not None:
            raise typer.BadParameter("--privacy cannot be combined with provider setup options")
        _finish(run_async(_run_privacy_setup_command))
        return
    if set_provider:
        if context.invoked_subcommand is not None:
            raise typer.BadParameter("--set cannot be combined with a subcommand")
        if (fireworks or grok) and provider_name is not None:
            raise typer.BadParameter("provider shortcuts and --provider are mutually exclusive")
        if fireworks and grok:
            raise typer.BadParameter("--fireworks and --grok are mutually exclusive")
        operation = _setup_operation("run_provider_setup")
        arguments: dict[str, object] = {
            "fireworks": fireworks,
            "model": model,
        }
        if provider_name is not None:
            arguments["provider"] = provider_name
        if grok:
            arguments["grok"] = True
        _finish(run_async(lambda: operation(**arguments)))
        return
    if grok or fireworks or provider_name is not None or model is not None:
        raise typer.BadParameter("--fireworks, --grok, --provider, and --model require --set")
    if context.invoked_subcommand is not None:
        return
    # Bare invocation (ADR-017, amending ADR-013): a human at a real terminal gets
    # the full-screen interface, with first run folded into it as its opening
    # steps rather than a separate wizard. When the terminal UI is unavailable or
    # declined we fall back to the ADR-013 prompt-loop menu, and every non-TTY,
    # piped, CI, or `--help` invocation keeps the historical help text.
    module = importlib.import_module("finishup.cli.setup")
    offer = cast(Callable[[], bool], getattr(module, "should_offer_first_run"))
    first_run = offer()
    if _open_tui(first_run=first_run):
        return
    if first_run:
        operation = _setup_operation("run_setup_wizard")
        _finish(
            run_async(
                lambda: operation(
                    non_interactive=False,
                    codex_path=None,
                    codex_home=None,
                    accept=False,
                    json_output=False,
                )
            )
        )
    menu_module = importlib.import_module("finishup.cli.menu")
    available = cast(Callable[[], bool], getattr(menu_module, "menu_available"))
    if available():
        run_menu = cast(Callable[[], int], getattr(menu_module, "run_menu"))
        _finish(run_menu())
        return
    typer.echo(context.get_help())
    typer.echo(
        "Get started: run 'finishup' in your own terminal to walk setup interactively.\n"
        + AGENT_START_HANDOFF
    )
    raise typer.Exit(0)


def _open_tui(*, first_run: bool) -> bool:
    """Open the full-screen interface when this really is a human terminal.

    Returns ``False`` — having emitted nothing — whenever the caller should keep
    the historical behaviour instead: automation, a pipe, an opt-out, or an
    installation whose optional rendering dependency is absent.
    """

    tui = importlib.import_module("finishup.tui")
    available = cast(Callable[[], bool], getattr(tui, "tui_available"))
    supported = cast(Callable[[], bool], getattr(tui, "tui_supported"))
    if not available() or not supported():
        return False
    runner = cast(Callable[..., int], getattr(tui, "run_tui"))
    unavailable = cast(int, getattr(tui, "TUI_UNAVAILABLE"))
    code = runner(first_run=first_run)
    if code == unavailable:
        return False
    _finish(code)
    return True


def main() -> None:
    """Installed console entry point with bounded exception handling."""

    try:
        app(prog_name="finishup")
    except KeyboardInterrupt:
        _stderr("cancelled")
        raise SystemExit(130) from None
    except Exception as error:
        # Defence in depth for the same defect the ``service run`` arm fixes: no command may
        # ever leak a bounded lifecycle refusal as internal_error again (#237).
        lifecycle_exit = _lifecycle_exit_code(error)
        if lifecycle_exit is not None:
            raise SystemExit(lifecycle_exit) from None
        _stderr("internal_error: the command could not be completed")
        raise SystemExit(70) from None


@elevated_app.command("status")
def elevated_status(json_output: _JSON = True) -> None:
    """Show pending consent status plus the non-default operation catalog."""

    module = importlib.import_module("finishup.cli.elevated")
    payload = cast(Callable[[], object], getattr(module, "status_elevated"))()
    _human_or_json(payload, json_output=json_output)


@elevated_app.command("catalog")
def elevated_catalog(json_output: _JSON = True) -> None:
    """List default-safe vs consent-required operations for agents."""

    module = importlib.import_module("finishup.cli.elevated")
    payload = cast(Callable[[], object], getattr(module, "catalog_elevated"))()
    _human_or_json(payload, json_output=json_output)


@elevated_app.command("prepare")
def elevated_prepare(
    operation: Annotated[
        str,
        typer.Argument(help="Consent catalog operation name (see `catalog`)."),
    ],
    provider_id: Annotated[str | None, typer.Option("--provider-id")] = None,
    model_id: Annotated[str | None, typer.Option("--model-id")] = None,
    endpoint_profile_id: Annotated[str | None, typer.Option("--endpoint-profile-id")] = None,
    endpoint_profile_version: Annotated[
        str | None, typer.Option("--endpoint-profile-version")
    ] = None,
    purpose: Annotated[str | None, typer.Option("--purpose")] = None,
    scope_digest: Annotated[str | None, typer.Option("--scope-digest")] = None,
    purpose_digest: Annotated[str | None, typer.Option("--purpose-digest")] = None,
    recipe: Annotated[
        str | None,
        typer.Option(
            "--recipe",
            help="Exact repository privacy recipe for repository_privacy_grant.",
        ),
    ] = None,
    project_id: Annotated[
        str | None,
        typer.Option("--project-id", help="Exact project id for project coordination grant."),
    ] = None,
    membership_generation: Annotated[
        int | None,
        typer.Option("--membership-generation", min=1),
    ] = None,
    audit_record_id: Annotated[
        str | None,
        typer.Option("--audit-record-id", help="Exact project grant audit event id."),
    ] = None,
    target_digest: Annotated[
        str | None,
        typer.Option("--target-digest", help="Exact plan/preview digest when required."),
    ] = None,
    json_output: _JSON = True,
) -> None:
    """Create a pending consent challenge (no secrets)."""

    module = importlib.import_module("finishup.cli.elevated")
    errors = importlib.import_module("finishup.service.elevated_bootstrap")
    elevated_error = cast(type[Exception], getattr(errors, "ElevatedBootstrapError"))
    prepare = cast(Callable[..., object], getattr(module, "prepare_elevated"))
    binding: dict[str, str] | None = None
    grant: dict[str, JsonValue] | None = None
    coordination: dict[str, JsonValue] | None = None
    if operation in {"provider_credential_set", "provider_credential_rotate"}:
        required = {
            "provider_id": provider_id,
            "model_id": model_id,
            "endpoint_profile_id": endpoint_profile_id,
            "endpoint_profile_version": endpoint_profile_version,
        }
        if any(value is None or value == "" for value in required.values()):
            _finish(_usage_failure())
        # The stored-credential purpose and its digests are derived facts of the profile, not
        # caller input; requiring them forced agents into product internals just to prepare.
        # Explicit values remain accepted so an unusual binding can still be named exactly.
        if purpose is None or purpose == "" or scope_digest is None or purpose_digest is None:
            vault_module = importlib.import_module("finishup.service.vault")
            profile_binding = cast(
                Callable[..., object], getattr(vault_module, "provider_credential_profile_binding")
            )(
                cast(str, provider_id),
                cast(str, model_id),
                cast(str, endpoint_profile_id),
                cast(str, endpoint_profile_version),
            )
            derived_purpose = cast(str, getattr(profile_binding, "purpose"))
            if purpose is not None and purpose != "" and purpose != derived_purpose:
                _finish(_usage_failure())
            purpose = derived_purpose
            if scope_digest is None:
                scope_digest = cast(str, getattr(profile_binding, "authorization_scope_digest"))
            if purpose_digest is None:
                purpose_digest = cast(str, getattr(profile_binding, "purpose_digest"))
        binding = {
            **{key: cast(str, value) for key, value in required.items()},
            "purpose": purpose,
            "scope_digest": scope_digest,
            "purpose_digest": purpose_digest,
        }

        async def _provider_scope_binding() -> int:
            privacy = importlib.import_module("finishup.cli.privacy_setup")
            try:
                snapshot = await cast(
                    Callable[..., Awaitable[object]], privacy.get_privacy_setup_snapshot
                )()
                bound = cast(Mapping[str, object], getattr(snapshot, "bound_scope"))
                commitment = bound.get("workspace_ref_commitment")
            except Exception as exc:
                raise elevated_error("repository_privacy_scope_unavailable") from exc
            if type(commitment) is not str:
                raise elevated_error("repository_privacy_scope_unavailable")
            binding["repository_privacy_commitment"] = commitment
            return 0

        try:
            code = run_async(_provider_scope_binding)
        except elevated_error as exc:
            _elevated_failure(exc)
            raise SystemExit(2) from None
        if code != 0:
            raise SystemExit(2)
    if operation == "repository_privacy_grant":
        if recipe is None or recipe == "":
            _finish(_usage_failure())

        async def _grant_binding() -> int:
            nonlocal grant
            from datetime import UTC, datetime

            from finishup.config.models import ConfigError

            privacy = importlib.import_module("finishup.cli.privacy_setup")
            try:
                snapshot = await cast(
                    Callable[..., Awaitable[object]], privacy.get_privacy_setup_snapshot
                )()
                bound = cast(Mapping[str, object], getattr(snapshot, "bound_scope"))
                commitment = bound.get("workspace_ref_commitment")
                authority_digest = getattr(snapshot, "authority_digest", None)
            except Exception as exc:
                raise elevated_error("repository_privacy_scope_unavailable") from exc
            if type(commitment) is not str or type(authority_digest) is not str:
                raise elevated_error("repository_privacy_scope_unavailable")
            try:
                external, _local = cast(
                    Callable[[], tuple[object | None, object | None]],
                    getattr(privacy, "configured_bindings"),
                )()
                current = getattr(snapshot, "composed_policy")
                answers = cast(Callable[..., object], getattr(privacy, "recipe_answers"))(
                    cast(str, recipe), current, external
                )
                # ADR-049 review round 2: a repository's first grant starts its conversation
                # setting where the conversation question would, not on the installation row.
                candidate = cast(Callable[..., object], getattr(privacy, "build_candidate_policy"))(
                    current,
                    answers,
                    now=datetime.now(UTC),
                    first_grant=getattr(snapshot, "grant_state", None) == "missing",
                )
                binding_builder = cast(
                    Callable[..., dict[str, JsonValue]],
                    getattr(errors, "repository_grant_binding"),
                )
                grant = binding_builder(
                    recipe=cast(str, recipe),
                    repository_privacy_commitment=commitment,
                    authority_digest=authority_digest,
                    current_policy=current,
                    candidate_policy=candidate,
                )
            except elevated_error:
                raise
            except privacy.ProviderBindingRequiredError:
                raise elevated_error("provider_binding_required") from None
            except (ConfigError, KeyError, TypeError, ValueError) as exc:
                raise elevated_error("grant_binding_invalid") from exc
            return 0

        try:
            code = run_async(_grant_binding)
        except elevated_error as exc:
            _elevated_failure(exc)
            raise SystemExit(2) from None
        if code != 0 or grant is None:
            raise SystemExit(2)
    if operation == "project_coordination_grant":
        if project_id is None or membership_generation is None or audit_record_id is None:
            _finish(_usage_failure())
        try:
            coordination_builder = cast(
                Callable[..., dict[str, JsonValue]],
                getattr(errors, "project_coordination_grant_binding"),
            )
            coordination = coordination_builder(
                project_id=project_id,
                membership_generation=membership_generation,
                audit_record_id=audit_record_id,
            )
        except elevated_error as exc:
            _elevated_failure(exc)
            raise SystemExit(2) from None
    try:
        payload = prepare(
            operation,
            provider_binding=binding,
            grant_binding=grant,
            coordination_binding=coordination,
            target_digest=target_digest,
        )
    except elevated_error as exc:
        _elevated_failure(exc)
        raise SystemExit(2) from None
    _human_or_json(payload, json_output=json_output)


@elevated_app.command("review")
def elevated_review(
    json_output: _JSON = True,
) -> None:
    """Review one pending action on a verified foreground console."""

    module = importlib.import_module("finishup.cli.elevated")
    errors = importlib.import_module("finishup.service.elevated_bootstrap")
    elevated_error = cast(type[Exception], getattr(errors, "ElevatedBootstrapError"))
    review = cast(Callable[[], Awaitable[object]], getattr(module, "review_elevated"))

    async def _run() -> int:
        try:
            payload = await review()
        except elevated_error as exc:
            return _elevated_failure(exc)
        _human_or_json(payload, json_output=json_output)
        return 0

    _finish(run_async(_run))


def _read_bounded_stdin_secret(maximum: int) -> bytearray:
    """Read one pipe-delimited secret directly into mutable storage."""

    if type(maximum) is not int or maximum <= 0:
        raise ValueError("provider_credential_invalid")
    storage = bytearray(maximum + 1)
    used = 0
    try:
        stream = cast(_MutableBinaryReader, sys.stdin.buffer)
        while used < len(storage):
            view = memoryview(storage)[used:]
            try:
                count = stream.readinto(view)
            finally:
                view.release()
            if count is None or count <= 0:
                break
            used += count
        if used > maximum:
            raise ValueError("provider_credential_invalid")
        if used > 0 and storage[used - 1] == 10:
            used -= 1
        if used == 0 or any(storage[index] in {0, 10, 13} for index in range(used)):
            raise ValueError("provider_credential_invalid")
        del storage[used:]
        return storage
    except BaseException:
        for index in range(len(storage)):
            storage[index] = 0
        raise


@elevated_app.command("authorize")
def elevated_authorize(
    pending_id: Annotated[str, typer.Option("--pending-id")],
    operation: Annotated[str, typer.Option("--operation")],
    danger_digest: Annotated[str, typer.Option("--danger-digest")],
    target_digest: Annotated[str, typer.Option("--target-digest")],
    client_kind: Annotated[str, typer.Option("--client-kind")],
    decision: Annotated[str, typer.Option("--decision", help="approve or deny")],
    warning_acknowledged: Annotated[
        bool,
        typer.Option(
            "--warning-acknowledged/--warning-not-acknowledged",
            help="Required true for credential-bearing approve.",
        ),
    ] = False,
    provider_credential_stdin: Annotated[
        bool,
        typer.Option(
            "--provider-credential-stdin",
            help="Read one provider credential from stdin (never echoed).",
        ),
    ] = False,
    json_output: _JSON = True,
) -> None:
    """Relay one explicit current-chat instruction for an exact prepared consent (#164)."""

    module = importlib.import_module("finishup.cli.elevated")
    errors = importlib.import_module("finishup.service.elevated_bootstrap")
    elevated_error = cast(type[Exception], getattr(errors, "ElevatedBootstrapError"))
    authorize = cast(Callable[..., Awaitable[object]], getattr(module, "authorize_elevated"))
    if decision not in {"approve", "deny"}:
        _finish(_usage_failure())
    if provider_credential_stdin and decision != "approve":
        _finish(_usage_failure())

    async def _run() -> int:
        secret: bytearray | None = None
        try:
            if provider_credential_stdin:
                try:
                    secret = _read_bounded_stdin_secret(8192)
                except (OSError, ValueError):
                    _stderr(
                        _bounded_failure_line(
                            "provider_credential_invalid", prefix="elevated_bootstrap"
                        )
                    )
                    return 2
            payload = await authorize(
                {
                    # Frozen legacy identifier (ADR-048): attestation tag the service validates.
                    "schema": "yoetz.chat-user-attestation/1",
                    "channel": "agent_attested_chat_instruction",
                    "client_kind": client_kind,
                    "instruction_source": "explicit_current_chat_user",
                    "pending_id": pending_id,
                    "operation": operation,
                    "danger_digest": danger_digest,
                    "target_digest": target_digest,
                    "warning_acknowledged": warning_acknowledged,
                    "decision": decision,
                },
                provider_credential=secret,
            )
        except elevated_error as exc:
            return _elevated_failure(exc)
        except Exception:
            _stderr("elevated_bootstrap: authorize_failed")
            return 2
        finally:
            if secret is not None:
                unlock = importlib.import_module("finishup.cli.unlock")
                cast(Callable[[bytearray], None], unlock.overwrite_secret_buffer)(secret)
        _human_or_json(payload, json_output=json_output)
        return 0

    _finish(run_async(_run))
