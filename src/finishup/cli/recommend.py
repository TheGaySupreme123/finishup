"""Explicit owner decisions for cached recommended-default advisories."""

from __future__ import annotations

import importlib
import json
import os
import shlex
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Final, cast

import anyio
import typer

from finishup.adapters.integrations.codex_session_stream import resolve_codex_home
from finishup.application.package_update import PACKAGE_UPDATE_UPGRADE_COMMAND
from finishup.application.recommendations import (
    RecommendationContext,
    RecommendationState,
    RecommendationStoreError,
    RecommendationTarget,
    codex_activation_recommendation_target,
    decline_cached_recommendation,
    evaluate_recommendation_context,
    recommendation_by_id,
    record_recommendation_decision,
    refresh_pending,
)
from finishup.config.load import load_config
from finishup.config.models import ConfigError, FinishUpConfig
from finishup.config.paths import config_file_path
from finishup.config.write import write_config_toml_if_unchanged
from finishup.ports.integrations import IntegrationError, IntegrationScope, IntegrationTarget

__all__ = ["recommend_app"]

_JSON = Annotated[bool, typer.Option("--json", help="Emit structural JSON.")]
_ACTIVATION_MODULE: Final = "finishup.adapters.integrations.codex_marketplace"

recommend_app = typer.Typer(
    help="Review and explicitly decide recommended defaults.", no_args_is_help=True
)


class _RecommendationCliError(Exception):
    reason_code: str

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _load_current_config(path: Path | None = None) -> FinishUpConfig:
    selected = config_file_path() if path is None else path
    if not selected.is_file():
        return FinishUpConfig()
    return load_config({}, {}, selected)


def _integration_target(path: Path) -> IntegrationTarget:
    return IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, os.fspath(path.resolve(strict=True)))


def _selected_codex_home(explicit: Path | str | None) -> Path:
    isolated = any(
        type(os.environ.get(name)) is str and bool(os.environ.get(name, "").strip())
        for name in ("CODEX_HOME", "CODEX_TESTING_HOME")
    )
    if explicit is None and not isolated:
        raise _RecommendationCliError("activation_home_ambiguous")
    return resolve_codex_home(explicit).resolve(strict=False)


def _target_from_preview(preview: object) -> RecommendationTarget:
    executable_path = getattr(preview, "executable_path", None)
    executable_digest = getattr(preview, "executable_digest", None)
    codex_version = getattr(preview, "codex_version", None)
    codex_home = getattr(preview, "codex_home", None)
    preview_digest = getattr(preview, "preview_digest", None)
    plugin_install_digest = getattr(preview, "plugin_install_digest", None)
    if (
        not isinstance(executable_path, Path)
        or type(executable_digest) is not str
        or type(codex_version) is not str
        or not isinstance(codex_home, Path)
        or type(preview_digest) is not str
        or type(plugin_install_digest) is not str
    ):
        raise _RecommendationCliError("activation_preview_invalid")
    try:
        return codex_activation_recommendation_target(
            executable_path=executable_path,
            executable_digest=executable_digest,
            codex_version=codex_version,
            codex_home=codex_home,
            activation_preview_digest=preview_digest,
            plugin_install_digest=plugin_install_digest,
        )
    except (OSError, ValueError) as exc:
        raise _RecommendationCliError("activation_preview_invalid") from exc


def _activation_context(
    target: Path,
    *,
    executable_path: Path | str | None = None,
    codex_home: Path | str | None = None,
) -> tuple[str | None, RecommendationTarget | None]:
    if executable_path is None:
        return None, None
    try:
        module = importlib.import_module(_ACTIVATION_MODULE)
        selected_home = _selected_codex_home(codex_home)
        inspection = module.inspect_activation(
            _integration_target(target),
            executable_path=os.fspath(executable_path),
            codex_home=selected_home,
        )
    except (
        _RecommendationCliError,
        AttributeError,
        ImportError,
        IntegrationError,
        OSError,
        TypeError,
        ValueError,
    ):
        return None, None
    state = getattr(inspection, "state", None)
    value = getattr(state, "value", state)
    if type(value) is not str:
        return None, None
    if value != "installed_not_activated":
        return value, None
    try:
        preview = module.preview_activation(
            _integration_target(target),
            executable_path=os.fspath(executable_path),
            codex_home=selected_home,
        )
        recommendation_target = _target_from_preview(preview)
    except (
        _RecommendationCliError,
        AttributeError,
        ImportError,
        IntegrationError,
        OSError,
        TypeError,
        ValueError,
    ):
        # The inspected state remains authoritative. A non-previewable modified/ambiguous target
        # is not actionable recommendation advice and must clear any stale cached prompt.
        return value, None
    return value, recommendation_target


async def _current_context(
    *,
    config_path: Path | None = None,
    activation_target: Path | None = None,
    codex_path: Path | str | None = None,
    codex_home: Path | str | None = None,
) -> RecommendationContext:
    config = _load_current_config(config_path)
    target = Path.cwd() if activation_target is None else activation_target
    activation_state, activation_decision_target = _activation_context(
        target, executable_path=codex_path, codex_home=codex_home
    )
    # Phase 2 supplies the durable privacy-policy posture. Until then this remains deliberately
    # no-egress and cannot manufacture package-update advice from an unauthorized network call.
    return await evaluate_recommendation_context(
        observation_enabled=config.observation.enabled,
        codex_activation_state=activation_state,
        codex_activation_target=activation_decision_target,
        allow_network=False,
    )


def _state_payload(state: RecommendationState) -> dict[str, object]:
    return {
        "schema": state.schema,
        "last_evaluated_version": state.last_evaluated_version,
        "pending_package_version": state.pending_package_version,
        "pending": [
            {
                "id": item.id,
                "kind": item.kind,
                "summary": item.summary,
                "title": item.title,
            }
            for recommendation_id in state.pending
            if (item := recommendation_by_id(recommendation_id)) is not None
        ],
        "decisions": {
            key: {
                "decision": row.decision,
                "decided_at": row.decided_at.isoformat(),
                "version": row.version,
                "release_version": row.release_version,
                "recommendation_id": row.recommendation_id or key,
                "target_digest": None if row.target is None else row.target.target_digest,
            }
            for key, row in sorted(state.decisions.items())
        },
        "pending_targets": {
            key: target.target_digest for key, target in sorted(state.pending_targets.items())
        },
    }


def _render_state(state: RecommendationState, *, json_output: bool) -> None:
    payload = _state_payload(state)
    if json_output:
        typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return
    if not state.pending:
        typer.echo("No recommended changes are pending.")
        return
    typer.echo("Recommended changes awaiting your decision:")
    for recommendation_id in state.pending:
        item = recommendation_by_id(recommendation_id)
        if item is None:
            continue
        typer.echo(f"  {item.id}: {item.title}")
        typer.echo(f"    {item.summary}")
        if (target := state.pending_targets.get(item.id)) is not None:
            typer.echo(f"    Target digest: {target.target_digest}")
        suffix = (
            f" --release-version {state.pending_package_version}"
            if recommendation_id == "package-update" and state.pending_package_version
            else ""
        )
        typer.echo(
            f"    Accept: finishup recommend accept {item.id}{suffix}  |  "
            f"Decline: finishup recommend decline {item.id}{suffix}"
        )


async def _refresh_for_cli(
    *, codex_path: Path | None = None, codex_home: Path | None = None
) -> RecommendationState:
    async def context() -> RecommendationContext:
        return await _current_context(codex_path=codex_path, codex_home=codex_home)

    # Exact-target list is also the recovery touchpoint: it must re-evaluate even when a
    # historical same-version decision left the global pending cache empty (#463).
    return await refresh_pending(context_factory=context, force=True)


@recommend_app.command("list")
def recommend_list(
    json_output: _JSON = False,
    codex_path: Annotated[
        Path | None,
        typer.Option(
            "--codex-path",
            help=(
                "Exact Codex executable to inspect. Activation status stays unknown unless "
                "--codex-home is also passed (or CODEX_HOME/CODEX_TESTING_HOME is set)."
            ),
        ),
    ] = None,
    codex_home: Annotated[
        Path | None,
        typer.Option("--codex-home", help="Exact Codex home expected from that executable."),
    ] = None,
) -> None:
    """Refresh at this heavy touchpoint and list cached pending recommendations."""

    try:
        state = anyio.run(lambda: _refresh_for_cli(codex_path=codex_path, codex_home=codex_home))
    except RecommendationStoreError as exc:
        typer.echo(f"recommendation_error: {exc.reason_code}", err=True)
        raise typer.Exit(2) from exc
    except ConfigError as exc:
        typer.echo(f"invalid_request: {exc.reason_code}", err=True)
        raise typer.Exit(2) from exc
    _render_state(state, json_output=json_output)


def _apply_observation_enabled(*, path: Path | None) -> str:
    target = config_file_path() if path is None else path
    try:
        expected = target.read_bytes()
    except FileNotFoundError:
        expected = None
    except OSError as exc:
        raise _RecommendationCliError("config_read_failed") from exc
    current = _load_current_config(target)
    if current.observation.enabled:
        return "already enabled in [observation]"
    updated = current.model_copy(
        update={"observation": current.observation.model_copy(update={"enabled": True})}
    )
    typer.echo("Exact config change:")
    typer.echo("  [observation] enabled = false -> true")
    try:
        written = write_config_toml_if_unchanged(updated, expected_bytes=expected, path=target)
    except ConfigError as exc:
        if exc.reason_code == "config_preimage_mismatch":
            raise _RecommendationCliError("config_preview_stale") from exc
        raise
    return (
        f"wrote [observation] enabled = true to {written}; "
        "restart the FinishUP service so the running composition loads this setting"
    )


def _preview_text(preview: object) -> tuple[str, str]:
    digest = getattr(preview, "preview_digest", None)
    if type(digest) is not str or not digest:
        raise _RecommendationCliError("activation_preview_invalid")
    details: list[str] = []
    for name in (
        "marketplace_json",
        "marketplace_bytes",
        "marketplace_payload",
        "config_toml_block",
        "toml_block",
    ):
        value = getattr(preview, name, None)
        if isinstance(value, bytes):
            try:
                details.append(value.decode("utf-8"))
            except UnicodeError as exc:
                raise _RecommendationCliError("activation_preview_invalid") from exc
        elif type(value) is str and value:
            details.append(value)
    if not details:
        details.append(repr(preview))
    return digest, "\n".join(details)


def _command_text(executable: Path, command: object) -> str:
    if type(command) is not tuple:
        raise _RecommendationCliError("activation_preview_invalid")
    parts: list[str] = []
    for item in cast(tuple[object, ...], command):
        if type(item) is not str:
            raise _RecommendationCliError("activation_preview_invalid")
        parts.append(item)
    return shlex.join((os.fspath(executable), *parts))


def _environment_lines(environment: object) -> tuple[str, ...]:
    if type(environment) is not tuple:
        raise _RecommendationCliError("activation_preview_invalid")
    lines: list[str] = []
    names: set[str] = set()
    for raw in cast(tuple[object, ...], environment):
        if type(raw) is not tuple:
            raise _RecommendationCliError("activation_preview_invalid")
        row = cast(tuple[object, ...], raw)
        if len(row) != 2:
            raise _RecommendationCliError("activation_preview_invalid")
        name, value = row
        if type(name) is not str or type(value) is not str or name in names:
            raise _RecommendationCliError("activation_preview_invalid")
        names.add(name)
        lines.append(f"{name}={value}")
    if names != {"CODEX_HOME", "CODEX_TESTING_HOME"}:
        raise _RecommendationCliError("activation_preview_invalid")
    return tuple(lines)


def _apply_codex_activation(
    *,
    target: Path,
    executable_path: Path,
    codex_home: Path,
    record_approval: Callable[[RecommendationTarget], None] | None = None,
) -> tuple[str, RecommendationTarget]:
    try:
        module = importlib.import_module(_ACTIVATION_MODULE)
        integration_target = _integration_target(target)
        selected_home = _selected_codex_home(codex_home)
        preview = module.preview_activation(
            integration_target,
            executable_path=os.fspath(executable_path),
            codex_home=selected_home,
        )
        recommendation_target = _target_from_preview(preview)
        digest, exact_change = _preview_text(preview)
        preview_home = getattr(preview, "codex_home", None)
        if not isinstance(preview_home, Path) or preview_home != selected_home:
            raise _RecommendationCliError("activation_preview_invalid")
        preview_executable = getattr(preview, "executable_path", None)
        executable_digest = getattr(preview, "executable_digest", None)
        codex_version = getattr(preview, "codex_version", None)
        install_path = getattr(preview, "plugin_install_path", None)
        source_digest = getattr(preview, "plugin_source_digest", None)
        install_digest = getattr(preview, "plugin_install_digest", None)
        marketplace_preimage = getattr(preview, "marketplace_preimage_digest", None)
        config_preimage = getattr(preview, "config_preimage_digest", None)
        cache_mutation = getattr(preview, "cache_mutation_planned", None)
        probe_environment = getattr(preview, "probe_environment", None)
        activation_environment = _environment_lines(
            getattr(preview, "activation_environment", None)
        )
        inspection = getattr(preview, "inspection", None)
        inventory_verified = getattr(inspection, "inventory_verified", None)
        if (
            not isinstance(preview_executable, Path)
            or type(executable_digest) is not str
            or not executable_digest
            or type(codex_version) is not str
            or not codex_version
            or not isinstance(install_path, Path)
            or type(source_digest) is not str
            or not source_digest
            or type(install_digest) is not str
            or not install_digest
            or type(marketplace_preimage) is not str
            or not marketplace_preimage
            or type(config_preimage) is not str
            or not config_preimage
            or type(cache_mutation) is not bool
            or probe_environment != "temporary_owner_private_home"
            or type(inventory_verified) is not bool
        ):
            raise _RecommendationCliError("activation_preview_invalid")
        probe = _command_text(preview_executable, getattr(preview, "probe_command", None))
        inventory = _command_text(preview_executable, getattr(preview, "inventory_command", None))
        install = _command_text(preview_executable, getattr(preview, "install_command", None))
        typer.echo(f"Codex executable: {preview_executable}")
        typer.echo(f"Codex executable digest: {executable_digest}")
        typer.echo(f"Codex version: {codex_version}")
        typer.echo(f"Codex home: {preview_home}")
        typer.echo(f"Codex config target: {preview_home / 'config.toml'}")
        typer.echo(f"Exact plugin install target: {install_path}")
        typer.echo(f"Plugin source digest: {source_digest}")
        typer.echo(f"Plugin install digest: {install_digest}")
        typer.echo(f"Marketplace preimage digest: {marketplace_preimage}")
        typer.echo(f"Config preimage digest: {config_preimage}")
        typer.echo(f"Plugin cache mutation planned: {'yes' if cache_mutation else 'no'}")
        typer.echo(f"Probe argv: {probe}")
        typer.echo(f"Probe environment: {probe_environment}")
        typer.echo(
            "Canonical plugin inventory verified before consent: "
            f"{'yes' if inventory_verified else 'no (verification occurs during approved apply)'}"
        )
        typer.echo(f"Inventory argv: {inventory}")
        typer.echo(f"Install argv: {install}")
        typer.echo("Inventory/install environment overrides:")
        for line in activation_environment:
            typer.echo(f"  {line}")
        typer.echo("Exact activation change:")
        typer.echo(exact_change.rstrip())
        typer.echo(f"preview digest: {digest}")
        if not typer.confirm("Apply exactly this digest-bound activation change?", default=False):
            raise _RecommendationCliError("activation_not_approved")
        if record_approval is not None:
            # The accepted decision is authority, not a success claim. Persist it before mutation
            # so a full bounded store cannot leave an applied change with no decision record.
            record_approval(recommendation_target)
        module.apply_activation(
            integration_target,
            approved_digest=digest,
            executable_path=os.fspath(executable_path),
            codex_home=selected_home,
        )
    except _RecommendationCliError:
        raise
    except (
        AttributeError,
        ImportError,
        IntegrationError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise _RecommendationCliError("activation_unavailable") from exc
    return (
        (
            f"applied exact activation preview {digest}; "
            "start a fresh Codex process/session to load the plugin and hooks"
        ),
        recommendation_target,
    )


def _apply_recommendation(
    recommendation_id: str,
    *,
    codex_path: Path | None = None,
    codex_home: Path | None = None,
    record_activation_approval: Callable[[RecommendationTarget], None] | None = None,
) -> tuple[str, RecommendationTarget | None]:
    if recommendation_id == "observation-enabled":
        return _apply_observation_enabled(path=None), None
    if recommendation_id == "codex-plugin-activation":
        if codex_path is None:
            raise _RecommendationCliError("activation_codex_path_required")
        if codex_home is None:
            raise _RecommendationCliError("activation_codex_home_required")
        return _apply_codex_activation(
            target=Path.cwd(),
            executable_path=codex_path,
            codex_home=codex_home,
            record_approval=record_activation_approval,
        )
    if recommendation_id == "package-update":
        return f"run: finishup upgrade (package command: {PACKAGE_UPDATE_UPGRADE_COMMAND})", None
    raise _RecommendationCliError("recommendation_unknown")


@recommend_app.command("accept")
def recommend_accept(
    recommendation_id: Annotated[str, typer.Argument(help="Exact recommendation id.")],
    release_version: Annotated[
        str | None, typer.Option("--release-version", help="Exact advertised package release.")
    ] = None,
    codex_path: Annotated[
        Path | None,
        typer.Option(
            "--codex-path",
            help="Exact Codex executable whose digest, version, home, and plugin commands are approved.",
        ),
    ] = None,
    codex_home: Annotated[
        Path | None,
        typer.Option(
            "--codex-home",
            help="Exact Codex home to preview and update; otherwise the isolated runtime environment is resolved.",
        ),
    ] = None,
) -> None:
    """Explicitly approve and apply one currently recommended action."""

    if recommendation_by_id(recommendation_id) is None:
        typer.echo("invalid_request: recommendation_unknown", err=True)
        raise typer.Exit(2)
    if recommendation_id == "codex-plugin-activation" and codex_path is None:
        typer.echo("recommendation_error: activation_codex_path_required", err=True)
        raise typer.Exit(2)
    if recommendation_id == "codex-plugin-activation" and codex_home is None:
        typer.echo("recommendation_error: activation_codex_home_required", err=True)
        raise typer.Exit(2)
    activation_decision_recorded = False
    try:

        async def refresh_exact() -> RecommendationState:
            async def context() -> RecommendationContext:
                return await _current_context(codex_path=codex_path, codex_home=codex_home)

            return await refresh_pending(context_factory=context, force=True)

        current = anyio.run(refresh_exact)
        if recommendation_id not in current.pending:
            raise _RecommendationCliError("recommendation_not_pending")
        if release_version is not None and (
            recommendation_id != "package-update"
            or release_version != current.pending_package_version
        ):
            raise _RecommendationCliError("recommendation_release_changed")

        # The command itself is the approval. Re-preview at this point binds activation to fresh
        # bytes; activation additionally confirms that displayed digest before it mutates trust.
        def record_activation(target: RecommendationTarget) -> None:
            nonlocal activation_decision_recorded
            record_recommendation_decision("codex-plugin-activation", "accepted", target=target)
            activation_decision_recorded = True

        outcome, decision_target = _apply_recommendation(
            recommendation_id,
            codex_path=codex_path,
            codex_home=codex_home,
            record_activation_approval=(
                record_activation if recommendation_id == "codex-plugin-activation" else None
            ),
        )
        if not activation_decision_recorded:
            # Non-activation recommendations still record after applying. Their fixed global keys
            # cannot exhaust the bounded target history; preserve the existing partial-apply report.
            try:
                record_recommendation_decision(
                    recommendation_id,
                    "accepted",
                    target=decision_target,
                    release_version=(
                        current.pending_package_version
                        if recommendation_id == "package-update"
                        else None
                    ),
                )
            except RecommendationStoreError as exc:
                typer.echo(f"applied {recommendation_id}: {outcome}")
                typer.echo(
                    f"recommendation_error: {exc.reason_code} "
                    "(the change above was applied, but the decision could not be recorded)",
                    err=True,
                )
                raise typer.Exit(2) from exc
    except RecommendationStoreError as exc:
        typer.echo(f"recommendation_error: {exc.reason_code}", err=True)
        raise typer.Exit(2) from exc
    except ConfigError as exc:
        typer.echo(f"invalid_request: {exc.reason_code}", err=True)
        raise typer.Exit(2) from exc
    except ValueError as exc:
        typer.echo(f"recommendation_error: {exc}", err=True)
        raise typer.Exit(2) from exc
    except _RecommendationCliError as exc:
        if activation_decision_recorded:
            typer.echo(
                "activation decision recorded; the activation apply did not complete",
                err=True,
            )
        typer.echo(f"recommendation_error: {exc.reason_code}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"accepted {recommendation_id}: {outcome}")


@recommend_app.command("decline")
def recommend_decline(
    recommendation_id: Annotated[str, typer.Argument(help="Exact recommendation id.")],
    release_version: Annotated[
        str | None, typer.Option("--release-version", help="Exact advertised package release.")
    ] = None,
    codex_path: Annotated[
        Path | None,
        typer.Option(
            "--codex-path",
            help="Accepted for compatibility; decline binds the cached exact target.",
        ),
    ] = None,
    codex_home: Annotated[
        Path | None,
        typer.Option(
            "--codex-home",
            help="Accepted for compatibility; decline binds the cached exact target.",
        ),
    ] = None,
) -> None:
    """Remember an explicit decline for the cached recommendation target."""

    # Decline consumes no Codex authority, so these selectors are deliberately inert. The cached
    # pending target already contains the digest-only identity that was shown by list/the hook.
    del codex_path, codex_home
    if recommendation_by_id(recommendation_id) is None:
        typer.echo("invalid_request: recommendation_unknown", err=True)
        raise typer.Exit(2)
    # Decline is a pure durable memory write against the already-cached pending advice.
    # It must never require per-kind authority (an exact Codex path/home, network posture)
    # or force a fresh evaluation: the hook-advertised `finishup recommend decline <id>` line
    # has to be honorable exactly as printed.
    try:
        decided = decline_cached_recommendation(recommendation_id, release_version=release_version)
    except RecommendationStoreError as exc:
        typer.echo(f"recommendation_error: {exc.reason_code}", err=True)
        raise typer.Exit(2) from exc
    except ValueError as exc:
        typer.echo(f"recommendation_error: {exc}", err=True)
        raise typer.Exit(2) from exc
    if recommendation_id == "codex-plugin-activation":
        typer.echo(f"declined {recommendation_id} for this exact target and activation digest")
    elif (
        recommendation_id == "package-update"
        and decided.decisions[recommendation_id].release_version
    ):
        typer.echo("declined this release; later releases may be recommended")
    else:
        typer.echo(f"declined {recommendation_id}; this recommendation will not be shown again")
