"""CLI-only project lifecycle commands.

The daemon remains the authority for project writes.  These commands send one structural
``operation`` envelope over the authenticated control channel; they never reach into SQLite or
create a local project shortcut.  Project titles and descriptions are sent only to the service's
encrypted object path and responses contain object references.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import Annotated, Protocol, cast

import typer

from finishup import __version__
from finishup.domain.values import JsonObject, JsonValue
from finishup.ports.control import ControlError, ProjectionRenderMode
from finishup.protocol.ids import IdKind, new_id, validate_id
from finishup.protocol.models import (
    StatusRequest,
    StatusResultModel,
    StatusSuccessModel,
    public_model_to_wire,
)

__all__ = ["project_app"]


project_app = typer.Typer(
    help="Manage CLI-only general and implicit projects.", no_args_is_help=True
)

_JSON = Annotated[bool, typer.Option("--json", help="Emit canonical JSON.")]
_DEADLINE = Annotated[
    int | None,
    typer.Option("--deadline-ms", min=1, max=86_400_000),
]
_REQUEST_ID = Annotated[
    str | None,
    typer.Option(
        "--request-id",
        help="Stable request id for retrying a timed-out or lost-response mutation.",
    ),
]


class _ProjectClient(Protocol):
    async def project(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject: ...

    async def status(self, request: StatusRequest, *, deadline_ms: int | None = None) -> object: ...


def _emit(value: Mapping[str, JsonValue], *, json_output: bool) -> None:
    if json_output:
        sys.stdout.write(json.dumps(dict(value), ensure_ascii=False, separators=(",", ":")))
        sys.stdout.write("\n")
        return
    if value.get("view") in {"project", "lineage"}:
        from finishup.cli.render import render_human_status

        result = StatusResultModel.model_validate(dict(value)).root
        if isinstance(result, StatusSuccessModel):
            # STATUS has already applied source/recipient policy and its typed content omissions.
            # Reuse the same renderer as workflow status and TUI so no project facts disappear.
            typer.echo(render_human_status(result))
            return
    # Human project output stays structural.  The service may add policy-approved disclosed text
    # in a future renderer, but this command never treats a title/description field as safe merely
    # because it arrived in a control response.
    project = value.get("project")
    if project is None and value.get("view") == "project":
        # ``finishup project status`` uses the canonical STATUS result.  Its page is the same
        # structural project descriptor that the workflow status command returns.
        project = value.get("page")
    if isinstance(project, Mapping):
        project_id = project.get("project_id", "")
        kind = project.get("kind", "")
        generation = project.get("membership_generation", "")
        typer.echo(f"project {project_id} ({kind}) generation {generation}")
        coverage = project.get("coverage")
        if isinstance(coverage, list | tuple):
            for row in coverage:
                if isinstance(row, Mapping):
                    typer.echo(
                        f"coverage {row.get('task_id', 'unknown')}: "
                        f"{row.get('coverage', 'unavailable')} ({row.get('gap_code', 'unknown')})"
                    )
    else:
        typer.echo(json.dumps(dict(value), ensure_ascii=False, sort_keys=True))


async def _invoke(
    body: Mapping[str, object], *, deadline_ms: int | None, json_output: bool
) -> JsonObject:
    # Import lazily so importing ``finishup.cli.project`` does not pull lifecycle/service composition
    # into the ordinary command registration path.
    from finishup.cli.app import build_service_client

    human_terminal = not json_output and sys.stdout.isatty()
    client = await build_service_client(
        projection_render_mode=(
            ProjectionRenderMode.HUMAN_READABLE
            if human_terminal
            else ProjectionRenderMode.MACHINE_READABLE
        ),
        output_is_controlling_tty=human_terminal,
    )
    try:
        # The project support body is a closed control-protocol envelope.  Keep the CLI command
        # builders focused on user-facing fields while binding the protocol version at this one
        # service-client boundary.
        body_values = dict(cast(Mapping[str, JsonValue], body))
        # One invocation owns one stable mutation identity.  A caller that must retry after the
        # process exits can pass --request-id and receive the same durable response later.
        if body_values.get("request_id") is None:
            body_values["request_id"] = new_id(IdKind.REQUEST)
        request = JsonObject({"schema_version": "1.0.0", **body_values})
        return await cast(_ProjectClient, client).project(request, deadline_ms=deadline_ms)
    finally:
        await client.close()


async def _invoke_status(
    body: Mapping[str, object],
    *,
    session_id: str,
    writer_id: str,
    deadline_ms: int | None,
    json_output: bool,
) -> JsonObject:
    from finishup.cli.app import build_service_client

    human_terminal = not json_output and sys.stdout.isatty()
    client = await build_service_client(
        projection_render_mode=(
            ProjectionRenderMode.HUMAN_READABLE
            if human_terminal
            else ProjectionRenderMode.MACHINE_READABLE
        ),
        output_is_controlling_tty=human_terminal,
    )
    try:
        request_body: dict[str, object] = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": new_id(IdKind.REQUEST),
            "actor": {"actor_id": "yoetz:project-cli", "actor_type": "harness"},
            "client": {
                "kind": "yoetz_cli",
                "version": __version__,
                "integration": "local_cli",
            },
            "session_id": session_id,
            "writer_id": writer_id,
            "view": "project",
            "limit": "100",
        }
        request_body.update({key: value for key, value in body.items() if value is not None})
        request = StatusRequest.model_validate(request_body)
        result = await cast(_ProjectClient, client).status(request, deadline_ms=deadline_ms)
        return JsonObject(public_model_to_wire(result))
    finally:
        await client.close()


def _run(body: Mapping[str, object], *, json_output: bool, deadline_ms: int | None) -> None:
    from finishup.cli.app import run_async

    # Mint before opening the service connection so a timeout or lost response can surface the
    # exact identity needed for a later ``--request-id`` retry.  The body is local to this CLI
    # process; an explicit caller value remains unchanged.
    request_body = dict(body)
    if request_body.get("request_id") is None:
        request_body["request_id"] = new_id(IdKind.REQUEST)
    request_id = request_body.get("request_id")
    try:
        # Validate before connection failures can echo the retry token to a human terminal.
        # A caller-supplied string is not trusted terminal output until it is a canonical ID.
        if type(request_id) is not str:
            raise ValueError("project_request_id_invalid")
        validate_id(IdKind.REQUEST, request_id)
        result = run_async(
            lambda: _invoke(request_body, deadline_ms=deadline_ms, json_output=json_output)
        )
        _emit(result, json_output=json_output)
    except Exception as error:
        # The existing app owns the full control-error rendering and exit taxonomy.  Delegate to
        # it without making project commands a second service client implementation.
        from finishup.cli.app import control_failure, usage_failure

        if isinstance(error, ControlError):
            if error.retryable and type(request_id) is str:
                typer.echo(
                    f"request_id {request_id} retained; retry with --request-id {request_id}",
                    err=True,
                )
            raise typer.Exit(control_failure(error, json_output=json_output))
        raise typer.Exit(usage_failure())


def _run_status(
    body: Mapping[str, object],
    *,
    session_id: str,
    writer_id: str,
    json_output: bool,
    deadline_ms: int | None,
) -> None:
    from finishup.cli.app import run_async

    try:
        result = run_async(
            lambda: _invoke_status(
                body,
                session_id=session_id,
                writer_id=writer_id,
                deadline_ms=deadline_ms,
                json_output=json_output,
            )
        )
        _emit(result, json_output=json_output)
    except Exception as error:
        from finishup.cli.app import control_failure, usage_failure

        if isinstance(error, ControlError):
            raise typer.Exit(control_failure(error, json_output=json_output))
        raise typer.Exit(usage_failure())


@project_app.command("create")
def project_create(
    title: Annotated[str, typer.Argument(help="Human title; encrypted by the service.")],
    owner_task_id: Annotated[
        str,
        typer.Option(
            "--owner-task-id",
            help="Task that authorizes the encrypted project text; its current route is used.",
        ),
    ],
    description: Annotated[
        str | None,
        typer.Option("--description", help="Optional encrypted description."),
    ] = None,
    auto_grouping: Annotated[
        bool,
        typer.Option("--auto-grouping/--no-auto-grouping"),
    ] = False,
    request_id: _REQUEST_ID = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
) -> None:
    _run(
        {
            "operation": "create",
            "title": title,
            "description": description,
            "owner_task_id": owner_task_id,
            "auto_grouping": auto_grouping,
            "request_id": request_id,
        },
        json_output=json_output,
        deadline_ms=deadline_ms,
    )


@project_app.command("link")
def project_link(
    project_id: Annotated[str, typer.Option("--project-id")],
    member_kind: Annotated[str, typer.Option("--member-kind")],
    member_commitment_or_id: Annotated[str, typer.Option("--member")],
    source_workspace_commitment: Annotated[
        str | None, typer.Option("--source-workspace-commitment")
    ] = None,
    member_repository_commitment: Annotated[
        str | None, typer.Option("--member-repository-commitment")
    ] = None,
    expected_generation: Annotated[int | None, typer.Option("--expected-generation", min=1)] = None,
    request_id: _REQUEST_ID = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
) -> None:
    _run(
        {
            "operation": "link",
            "project_id": project_id,
            "member_kind": member_kind,
            "member_commitment_or_id": member_commitment_or_id,
            "source_workspace_commitment": source_workspace_commitment,
            "member_repository_commitment": member_repository_commitment,
            "expected_generation": expected_generation,
            "request_id": request_id,
        },
        json_output=json_output,
        deadline_ms=deadline_ms,
    )


@project_app.command("unlink")
def project_unlink(
    project_id: Annotated[str, typer.Option("--project-id")],
    member_kind: Annotated[str, typer.Option("--member-kind")],
    member_commitment_or_id: Annotated[str, typer.Option("--member")],
    expected_generation: Annotated[int | None, typer.Option("--expected-generation", min=1)] = None,
    request_id: _REQUEST_ID = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
) -> None:
    _run(
        {
            "operation": "unlink",
            "project_id": project_id,
            "member_kind": member_kind,
            "member_commitment_or_id": member_commitment_or_id,
            "expected_generation": expected_generation,
            "request_id": request_id,
        },
        json_output=json_output,
        deadline_ms=deadline_ms,
    )


@project_app.command("amend")
def project_amend(
    project_id: Annotated[str, typer.Option("--project-id")],
    owner_task_id: Annotated[
        str,
        typer.Option(
            "--owner-task-id",
            help="Task that authorizes the encrypted project text; its current route is used.",
        ),
    ],
    title: Annotated[str | None, typer.Option("--title")] = None,
    description: Annotated[str | None, typer.Option("--description")] = None,
    request_id: _REQUEST_ID = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
) -> None:
    _run(
        {
            "operation": "amend",
            "project_id": project_id,
            "title": title,
            "description": description,
            "owner_task_id": owner_task_id,
            "request_id": request_id,
        },
        json_output=json_output,
        deadline_ms=deadline_ms,
    )


@project_app.command("dissolve")
def project_dissolve(
    project_id: Annotated[str, typer.Option("--project-id")],
    expected_generation: Annotated[int | None, typer.Option("--expected-generation", min=1)] = None,
    request_id: _REQUEST_ID = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
) -> None:
    _run(
        {
            "operation": "dissolve",
            "project_id": project_id,
            "expected_generation": expected_generation,
            "request_id": request_id,
        },
        json_output=json_output,
        deadline_ms=deadline_ms,
    )


def _project_opt(
    operation: str,
    repository_commitment: str,
    json_output: bool,
    deadline_ms: int | None,
    request_id: str | None,
) -> None:
    _run(
        {
            "operation": operation,
            "repository_commitment": repository_commitment,
            "request_id": request_id,
        },
        json_output=json_output,
        deadline_ms=deadline_ms,
    )


@project_app.command("opt-out")
def project_opt_out(
    repository_commitment: Annotated[str, typer.Option("--repository-commitment")],
    request_id: _REQUEST_ID = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
) -> None:
    _project_opt("opt_out", repository_commitment, json_output, deadline_ms, request_id)


@project_app.command("opt-in")
def project_opt_in(
    repository_commitment: Annotated[str, typer.Option("--repository-commitment")],
    request_id: _REQUEST_ID = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
) -> None:
    _project_opt("opt_in", repository_commitment, json_output, deadline_ms, request_id)


@project_app.command("grant")
def project_grant(
    project_id: Annotated[str, typer.Option("--project-id")],
    membership_generation: Annotated[int, typer.Option("--membership-generation", min=1)],
    audit_record_id: Annotated[str | None, typer.Option("--audit-record-id")] = None,
    request_id: _REQUEST_ID = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
) -> None:
    _run(
        {
            "operation": "grant",
            "project_id": project_id,
            "membership_generation": membership_generation,
            "audit_record_id": audit_record_id,
            "request_id": request_id,
        },
        json_output=json_output,
        deadline_ms=deadline_ms,
    )


@project_app.command("revoke")
def project_revoke(
    project_id: Annotated[str, typer.Option("--project-id")],
    membership_generation: Annotated[int, typer.Option("--membership-generation", min=1)],
    audit_record_id: Annotated[str | None, typer.Option("--audit-record-id")] = None,
    request_id: _REQUEST_ID = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
) -> None:
    _run(
        {
            "operation": "revoke",
            "project_id": project_id,
            "membership_generation": membership_generation,
            "audit_record_id": audit_record_id,
            "request_id": request_id,
        },
        json_output=json_output,
        deadline_ms=deadline_ms,
    )


@project_app.command("status")
def project_status(
    session_id: Annotated[
        str,
        typer.Option(
            "--session-id",
            help="Exact FinishUP session bound to the selected task; never inferred or resumed.",
        ),
    ],
    writer_id: Annotated[
        str,
        typer.Option(
            "--writer-id",
            help="Exact writer bound to the selected session.",
        ),
    ],
    task_id: Annotated[
        str | None,
        typer.Option("--task-id", help="Optional task selector for the canonical project view."),
    ] = None,
    project_id: Annotated[str | None, typer.Option("--project-id")] = None,
    json_output: _JSON = False,
    deadline_ms: _DEADLINE = None,
) -> None:
    if project_id is None and task_id is None:
        raise typer.BadParameter("one of --project-id or --task-id is required")
    if project_id is not None and task_id is not None:
        raise typer.BadParameter("--project-id and --task-id are mutually exclusive")
    _run_status(
        {
            "project_id": project_id,
            "task_id": task_id,
        },
        session_id=session_id,
        writer_id=writer_id,
        json_output=json_output,
        deadline_ms=deadline_ms,
    )
