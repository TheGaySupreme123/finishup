"""Explicit local Codex plugin/marketplace removal commands."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final, cast

from yoetz.adapters.integrations.codex_discovery import discover_codex_binaries
from yoetz.adapters.integrations.codex_marketplace import (
    RemovalPreview,
    apply_removal,
    inspect_activation,
    preview_removal,
    skill_tree_state,
)
from yoetz.cli.host_admission import admission_cleanup_preview, reverse_sweep
from yoetz.cli.setup import (
    _choose_binary,  # pyright: ignore[reportPrivateUsage]
    _UsageExit,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.ports.integrations import (
    IntegrationError,
    IntegrationScope,
    IntegrationTarget,
)
from yoetz.protocol.canonical import JsonValue, canonical_encode

__all__ = ["CODEX_PLUGIN_COMMANDS", "run_codex_plugin_command"]

# Codex activation is the digest-bound setup/recommendation ceremony (ADR-012);
# the standalone plugin surface is inspection and removal only (issue #465).
CODEX_PLUGIN_COMMANDS: Final = ("preview", "status", "remove")
# Generic lifecycle commands the shared `integrate <host> plugin` group
# registers for other hosts; refused here by name before binary discovery.
_UNSUPPORTED_GENERIC_COMMANDS: Final = frozenset(
    {"install", "update", "enable", "disable", "export"}
)


def _emit(value: dict[str, object], *, json_output: bool) -> None:
    if json_output:
        sys.stdout.buffer.write(canonical_encode(cast(JsonValue, value)) + b"\n")
        return
    for key, item in value.items():
        rendered = (
            canonical_encode(cast(JsonValue, item)).decode("utf-8")
            if isinstance(item, (dict, list, tuple))
            else str(item)
        )
        sys.stdout.write(f"{key}: {rendered}\n")


def _target(project_root: Path | None) -> IntegrationTarget:
    root = Path.cwd() if project_root is None else project_root
    if not root.is_absolute():
        root = Path.cwd() / root
    # Preserve the lexical path so the adapter can reject a symlinked project
    # root instead of silently authorizing its resolved target.
    return IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, os.fspath(root.absolute()))


def _preview_body(preview: RemovalPreview) -> dict[str, object]:
    return {
        "action": preview.outcome.value,
        "cache_preimages": [
            {"digest": digest, "version": version} for version, digest in preview.cache_digests
        ],
        "cache_versions": list(preview.cache_versions),
        "codex_version": preview.codex_version,
        "config_preimage_digest": preview.config_preimage_digest,
        "config_toml_block": preview.config_toml_block,
        "inventory_command": list(preview.inventory_command),
        "marketplace_json_planned": preview.marketplace_json_planned,
        "marketplace_preimage_digest": preview.marketplace_preimage_digest,
        "marketplace_remove_command": list(preview.marketplace_remove_command),
        "marketplace_remove_planned": preview.marketplace_remove_planned,
        "plugin_remove_command": list(preview.plugin_remove_command),
        "plugin_remove_planned": preview.plugin_remove_planned,
        "preview_digest": preview.preview_digest,
        "purge_cache": preview.purge_cache,
        # `detach` (#1058): other connected projects keep the home's shared pieces.
        "rebind_to": preview.rebind_to,
        "shared_with": list(preview.shared_with),
        "skill_tree": preview.skill_tree_state,
        "state_before": preview.inspection.state.value,
    }


def run_codex_plugin_command(
    command: str,
    *,
    harness: str,
    project_root: Path | None,
    codex_path: str | None,
    codex_home: Path | None,
    purge_cache: bool,
    preview_digest: str | None,
    accept: bool,
    json_output: bool,
) -> int:
    """Run one path-explicit Codex marketplace removal without ambient home inference."""

    if harness == "codex" and command in _UNSUPPORTED_GENERIC_COMMANDS:
        sys.stderr.write(
            f"codex_plugin_command_unsupported:{command} "
            f"supported={','.join(CODEX_PLUGIN_COMMANDS)}\n"
        )
        return 2
    if harness != "codex" or command not in CODEX_PLUGIN_COMMANDS:
        sys.stderr.write("codex_plugin_command_invalid\n")
        return 2
    if codex_home is None and command != "status":
        sys.stderr.write("codex_home_required\n")
        return 2
    from yoetz.adapters.integrations.codex_session_stream import resolve_codex_home

    codex_home = resolve_codex_home(codex_home).absolute()
    binaries = discover_codex_binaries()
    try:
        chosen = _choose_binary(binaries, codex_path=codex_path, interactive=False)
    except _UsageExit as failure:
        return failure.code
    if chosen is None:
        sys.stderr.write("codex_executable_unresolved\n")
        return 2
    target = _target(project_root)
    executable = chosen.executable_path
    try:
        if command == "status":
            inspection = inspect_activation(
                target, executable_path=executable, codex_home=codex_home
            )
            _emit(
                {
                    "inspected_codex_home": str(codex_home),
                    "skill_tree": skill_tree_state(target),
                    "state": inspection.state.value,
                },
                json_output=json_output,
            )
            return 0
        if command == "preview":
            preview = preview_removal(
                target,
                executable_path=executable,
                codex_home=codex_home,
                purge_cache=purge_cache,
            )
            _emit(
                {
                    **_preview_body(preview),
                    # Removal is a reverse transition for the project's Codex host-admission
                    # entry (issue #467); disclose what the sweep would touch.
                    "admission_cleanup": admission_cleanup_preview(
                        "codex", Path(target.project_root)
                    ),
                },
                json_output=json_output,
            )
            return 0
        if not accept or preview_digest is None:
            sys.stderr.write("codex_plugin_exact_preview_acceptance_required\n")
            return 3
        result = apply_removal(
            target,
            approved_digest=preview_digest,
            executable_path=executable,
            codex_home=codex_home,
            purge_cache=purge_cache,
        )
    except IntegrationError as error:
        details = dict(error.safe_details)
        conflict = details.get("conflict")
        sys.stderr.write(
            f"codex_plugin_{error.reason.value}"
            + (f":{conflict}" if type(conflict) is str else "")
            + "\n"
        )
        return 20 if error.reason.value not in {"remove_refused", "preview_stale"} else 2
    _emit(
        {
            "admission_cleanup": reverse_sweep("codex", Path(target.project_root)),
            "outcome": result.outcome.value,
            "purge_cache": result.purge_cache,
            "skill_tree": result.skill_tree_state,
            "state_after": result.inspection.state.value,
        },
        json_output=json_output,
    )
    return 0
