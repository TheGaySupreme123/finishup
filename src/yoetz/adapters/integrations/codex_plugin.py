"""Codex plugin bundle renderer, installer, and hook-presence inspection."""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final, cast

from packaging.version import InvalidVersion, Version

from yoetz import __version__
from yoetz.adapters.integrations.codex_skill import (
    SkillResourceSource,
    load_packaged_skill_members,
    load_packaged_skill_source,
    validated_managed_parent,
)
from yoetz.domain.values import JsonValue as DomainJsonValue
from yoetz.ports.harness_mcp import MCP_SERVE_COMMAND, MCP_SERVER_NAME
from yoetz.ports.integrations import (
    HarnessId,
    IntegrationError,
    IntegrationReason,
    IntegrationScope,
    IntegrationState,
    IntegrationTarget,
)
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from yoetz.protocol.errors import ProtocolValueError

__all__ = [
    "PLUGIN_ROOT",
    "PluginHookPresence",
    "PluginInspection",
    "codex_supports_async_hooks",
    "inspect_plugin",
    "install_plugin",
    "plugin_tree_matches_marker",
    "render_plugin_install_tree",
    "render_plugin_tree",
]

_ADAPTER_VERSION: Final = "codex-plugin/0.1.0"
_MARKER_NAME: Final = ".yoetz-plugin-install.json"
_MARKER_SCHEMA: Final = "yoetz.codex-plugin-install/1"
_PLUGIN_ROOT: Final = ".agents/plugins/yoetz"
PLUGIN_ROOT: Final = _PLUGIN_ROOT
_SOURCE_FILE_LIMIT: Final = 262_144
# openai/codex#37533 first shipped in this prerelease. Unknown or malformed
# versions deliberately stay on the slower synchronous path: dropping an
# observation handler is worse than adding bounded hook latency.
_ASYNC_HOOKS_MIN_VERSION: Final = Version("0.148.0-alpha.6")


class PluginHookPresence(str, Enum):  # noqa: UP042 - exact structural enum
    ABSENT = "absent"
    INSTALLED_UNTRUSTED_UNKNOWN = "installed_untrusted_unknown"
    INSTALLED = "installed"


@dataclass(frozen=True, slots=True, repr=False)
class PluginInspection:
    """Read-only plugin/hook presence classification.

    Codex hook trust is never inferred from filesystem presence alone.
    """

    presence: PluginHookPresence
    trust_observable: bool
    installed_digest: str | None
    notes: tuple[str, ...]

    @property
    def state(self) -> IntegrationState:
        return {
            PluginHookPresence.ABSENT: IntegrationState.ABSENT,
            PluginHookPresence.INSTALLED_UNTRUSTED_UNKNOWN: IntegrationState.MODIFIED,
            PluginHookPresence.INSTALLED: IntegrationState.INSTALLED_EXACT,
        }[self.presence]

    def __repr__(self) -> str:
        return (
            "PluginInspection("
            f"presence={self.presence.value!r}, trust_observable={self.trust_observable!r}, "
            f"installed_digest={self.installed_digest!r})"
        )


def _error(
    reason: IntegrationReason, details: Mapping[str, DomainJsonValue] | None = None
) -> IntegrationError:
    return IntegrationError(reason, {} if details is None else details)


def _sha(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def codex_supports_async_hooks(codex_version: str | None) -> bool:
    """Return whether one exact Codex version can register async command hooks.

    This is a narrow host-capability check, not the exact-version evidence table
    used by JSONL import. It fails closed because unsupported hosts discard, rather
    than synchronously downgrade, most handlers carrying ``"async": true``.
    """

    if type(codex_version) is not str or len(codex_version) > 128:
        return False
    try:
        parsed = Version(codex_version)
        return len(parsed.release) == 3 and parsed >= _ASYNC_HOOKS_MIN_VERSION
    except InvalidVersion:
        return False


def _hooks_json(*, codex_version: str | None = None) -> bytes:
    async_hooks = codex_supports_async_hooks(codex_version)

    def _command(
        event: str, *, command: str, timeout: int, status: str, run_async: bool = False
    ) -> dict[str, JsonValue]:
        handler: dict[str, JsonValue] = {
            "type": "command",
            "command": command,
            "timeout": timeout,
            "statusMessage": status,
        }
        if run_async and async_hooks:
            handler["async"] = True
        return {"hooks": [handler]}

    # Project-scoped observe binds cwd ('.') via local resolve + consent commitment.
    #
    # Execution-mode split (#209, #271): handlers that only ingest and always emit
    # {} use async only when the exact probed host can register async command
    # hooks. Older stable hosts discard such handlers instead of downgrading them,
    # so unknown and unsupported versions keep the bounded synchronous form.
    # Handlers that return additionalContext (SessionStart advice/attach,
    # PostToolUse advice) or a Stop ``decision: block`` stay synchronous with a
    # timeout the handler can actually meet; Codex's own default would be 600s,
    # so 10s here is still a deliberate bound, not a relaxation. PreToolUse is
    # synchronous as well: its pairing identity must be committed before Codex
    # can deliver the matching PostToolUse, otherwise built-in MCP-resource calls
    # can be recorded as orphaned despite healthy observation (#974). SessionEnd
    # is host-clamped to 3s max, discards stdout, and is downgraded to sync (with
    # a per-session warning) if declared async, so it keeps its own explicit 3.
    observe = "yoetz hooks observe --workspace . --event"
    legacy_spool = "yoetz hooks spool --workspace . --event"
    ingress = observe if async_hooks else legacy_spool
    observe_timeout = 10
    session_end_timeout = 3
    body: dict[str, JsonValue] = {
        "description": (
            "Yoetz Codex lifecycle hooks: observation ingress, activation cue, "
            "start correlation, and re-ground."
        ),
        "hooks": {
            "SessionStart": [
                {
                    "matcher": "resume|compact",
                    "hooks": [
                        {
                            "type": "command",
                            # `--workspace .` names the hook cwd explicitly; the host
                            # payload's cwd still outranks it for the status probe (#659).
                            "command": "yoetz hooks session-start --workspace .",
                            "timeout": 15,
                            "statusMessage": "Yoetz re-ground",
                        }
                    ],
                },
                _command(
                    "SessionStart",
                    command=f"{observe} SessionStart",
                    timeout=observe_timeout,
                    status="Yoetz observe SessionStart",
                ),
            ],
            "SessionEnd": [
                _command(
                    "SessionEnd",
                    command=f"{observe} SessionEnd",
                    timeout=session_end_timeout,
                    status="Yoetz observe SessionEnd",
                )
            ],
            "Stop": [
                _command(
                    "Stop",
                    command=f"{observe} Stop",
                    timeout=observe_timeout,
                    status="Yoetz observe Stop",
                )
            ],
            "UserPromptSubmit": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "yoetz hooks user-prompt-submit --workspace .",
                            "timeout": 10,
                            "statusMessage": "Yoetz intake cue",
                        }
                    ]
                }
            ],
            "PreToolUse": [
                _command(
                    "PreToolUse",
                    command=f"{ingress} PreToolUse",
                    timeout=observe_timeout,
                    status="Yoetz observe PreToolUse",
                )
            ],
            "PostToolUse": [
                {
                    "matcher": "^mcp__yoetz__start$",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "yoetz hooks post-tool-use",
                            "timeout": 10,
                            "statusMessage": "Yoetz start correlation",
                        }
                    ],
                },
                _command(
                    "PostToolUse",
                    command=f"{ingress} PostToolUse",
                    timeout=observe_timeout,
                    status="Yoetz observe PostToolUse",
                ),
            ],
            "PermissionRequest": [
                _command(
                    "PermissionRequest",
                    command=f"{ingress} PermissionRequest",
                    timeout=observe_timeout,
                    status="Yoetz observe PermissionRequest",
                    run_async=True,
                )
            ],
            "PreCompact": [
                _command(
                    "PreCompact",
                    command=f"{observe} PreCompact",
                    timeout=observe_timeout,
                    status="Yoetz observe PreCompact",
                    run_async=True,
                )
            ],
            "PostCompact": [
                _command(
                    "PostCompact",
                    command=f"{observe} PostCompact",
                    timeout=observe_timeout,
                    status="Yoetz observe PostCompact",
                    run_async=True,
                )
            ],
            "SubagentStart": [
                _command(
                    "SubagentStart",
                    command=f"{observe} SubagentStart",
                    timeout=observe_timeout,
                    status="Yoetz observe SubagentStart",
                    run_async=True,
                )
            ],
            "SubagentStop": [
                _command(
                    "SubagentStop",
                    command=f"{observe} SubagentStop",
                    timeout=observe_timeout,
                    status="Yoetz observe SubagentStop",
                    run_async=True,
                )
            ],
        },
    }
    return canonical_encode(body) + b"\n"


def _plugin_json() -> bytes:
    body: dict[str, JsonValue] = {
        "name": "yoetz",
        "version": __version__,
        "description": (
            "Yoetz local work ledger plugin: skill, MCP server, and lifecycle hooks. "
            "Automatic activation is not claimed without exact-host capability evidence."
        ),
        "skills": "./skills/",
        "mcpServers": "./.mcp.json",
        "hooks": "./hooks/hooks.json",
    }
    return canonical_encode(body) + b"\n"


def _mcp_json() -> bytes:
    body: dict[str, JsonValue] = {
        "mcpServers": {
            MCP_SERVER_NAME: {
                "command": MCP_SERVE_COMMAND[0],
                "args": list(MCP_SERVE_COMMAND[1:]),
            }
        }
    }
    return canonical_encode(body) + b"\n"


def render_plugin_tree(
    *,
    resource_source: SkillResourceSource | None = None,
    codex_version: str | None = None,
) -> dict[str, bytes]:
    """Render the plugin file tree as an in-memory path → bytes mapping."""

    skill_members = load_packaged_skill_members(resource_source)
    members: dict[str, bytes] = {
        ".codex-plugin/plugin.json": _plugin_json(),
        "hooks/hooks.json": _hooks_json(codex_version=codex_version),
        ".mcp.json": _mcp_json(),
    }
    for relative_path, data in skill_members.items():
        members[f"skills/yoetz/{relative_path}"] = data
    return members


def render_plugin_install_tree(
    *,
    resource_source: SkillResourceSource | None = None,
    codex_version: str | None = None,
) -> dict[str, bytes]:
    """Render the complete installed tree, including the deterministic ownership marker."""

    members = render_plugin_tree(
        resource_source=resource_source,
        codex_version=codex_version,
    )
    return {**members, _MARKER_NAME: _build_marker(members)}


def _validated_project(target: IntegrationTarget) -> Path:
    if (
        type(target) is not IntegrationTarget
        or target.scope is not IntegrationScope.TRUSTED_PROJECT
    ):
        raise _error(IntegrationReason.TARGET_UNTRUSTED)
    root = Path(target.project_root)
    if not root.is_absolute():
        root = Path.cwd() / root
    if root == Path(root.anchor) or root == Path.home() or root.is_symlink() or not root.is_dir():
        raise _error(IntegrationReason.TARGET_UNTRUSTED)
    try:
        stat = root.stat()
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    if hasattr(os, "geteuid") and stat.st_uid != os.geteuid():
        raise _error(IntegrationReason.TARGET_UNSAFE)
    if stat.st_mode & 0o022:
        raise _error(IntegrationReason.TARGET_UNSAFE)
    return root


def _validated_plugin_parent(root: Path, *, create: bool) -> Path:
    """Resolve the managed parent without following project-local symlink ancestors."""

    return validated_managed_parent(root, (".agents", "plugins"), create=create)


def plugin_tree_matches_marker(members: Mapping[str, bytes]) -> bool:
    """True when a file tree byte-matches its own valid Yoetz install marker.

    ADR-023 treats a marker-identified, internally consistent tree as a prior
    yoetz-managed render that whole-directory replacement may refresh. Anything
    else — a foreign tree, a missing or inconsistent marker, or a modified
    member — is not replaceable through this classification.
    """

    marker_raw = members.get(_MARKER_NAME)
    if marker_raw is None or len(marker_raw) > _SOURCE_FILE_LIMIT:
        return False
    try:
        parsed = strict_json_parse(marker_raw)
    except ProtocolValueError:
        return False
    if not isinstance(parsed, Mapping):
        return False
    marker = cast(Mapping[str, object], parsed)
    if marker.get("schema") != _MARKER_SCHEMA:
        return False
    body = {name: value for name, value in marker.items() if name != "marker_digest"}
    if marker.get("marker_digest") != canonical_digest(cast(JsonValue, body)):
        return False
    rows = marker.get("managed_files")
    if type(rows) is not list:
        return False
    inventory: dict[str, tuple[str, int]] = {}
    for raw_row in cast(list[object], rows):
        if not isinstance(raw_row, Mapping):
            return False
        row = cast(Mapping[str, object], raw_row)
        relative_path = row.get("relative_path")
        digest = row.get("sha256")
        size = row.get("size")
        if type(relative_path) is not str or type(digest) is not str or type(size) is not int:
            return False
        if relative_path in inventory or relative_path == _MARKER_NAME:
            return False
        inventory[relative_path] = (digest, size)
    actual = {
        path: (_sha(data), len(data)) for path, data in members.items() if path != _MARKER_NAME
    }
    return inventory == actual


def _is_prior_managed_render(destination: Path) -> bool:
    """True when the installed tree is exactly one marker-consistent prior render."""

    members: dict[str, bytes] = {}
    try:
        for candidate in destination.rglob("*"):
            if candidate.is_symlink():
                return False
            if candidate.is_dir():
                continue
            if not candidate.is_file():
                return False
            data = candidate.read_bytes()
            if len(data) > _SOURCE_FILE_LIMIT:
                return False
            members[candidate.relative_to(destination).as_posix()] = data
    except OSError:
        return False
    return plugin_tree_matches_marker(members)


def _build_marker(members: Mapping[str, bytes]) -> bytes:
    managed = [
        {
            "relative_path": path,
            "sha256": _sha(data),
            "size": len(data),
        }
        for path, data in sorted(members.items(), key=lambda item: item[0].encode("ascii"))
    ]
    body: dict[str, JsonValue] = {
        "adapter_version": _ADAPTER_VERSION,
        "harness_id": HarnessId.CODEX.value,
        "managed_files": cast(JsonValue, managed),
        "schema": _MARKER_SCHEMA,
        "scope": IntegrationScope.TRUSTED_PROJECT.value,
        "yoetz_version": __version__,
    }
    body["marker_digest"] = canonical_digest(body)
    return canonical_encode(body) + b"\n"


def _write_tree(stage: Path, members: Mapping[str, bytes], marker: bytes) -> None:
    stage.mkdir(mode=0o700)
    for relative_path, data in members.items():
        if len(data) > _SOURCE_FILE_LIMIT:
            raise _error(IntegrationReason.SOURCE_INVALID)
        destination = stage / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            written = 0
            while written < len(data):
                written += os.write(fd, data[written:])
            os.fsync(fd)
        finally:
            os.close(fd)
    marker_path = stage / _MARKER_NAME
    marker_path.write_bytes(marker)
    with marker_path.open("rb") as handle:
        os.fsync(handle.fileno())


def install_plugin(
    target: IntegrationTarget,
    *,
    replace_modified: bool = False,
    resource_source: SkillResourceSource | None = None,
    allow_untested: bool = False,
    codex_version: str | None = None,
) -> PluginInspection:
    """Install the rendered plugin tree under the trusted-project plugin root.

    By default refuse when the packaged Codex tested set is empty (no supported profile
    yet). Observation setup may pass ``allow_untested=True`` to install hooks while still
    reporting that automatic activation is untested. Refuses to overwrite user-modified
    managed files unless ``replace_modified`` is true.
    """

    source = load_packaged_skill_source(resource_source)
    if not source.harness_tested_set and not allow_untested:
        raise _error(IntegrationReason.VERSION_INCOMPATIBLE)
    root = _validated_project(target)
    parent = _validated_plugin_parent(root, create=True)
    destination = parent / "yoetz"
    members = render_plugin_tree(
        resource_source=resource_source,
        codex_version=codex_version,
    )
    marker = _build_marker(members)
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise _error(IntegrationReason.TARGET_UNSAFE)
        # A destination that byte-matches its own valid install marker is a prior
        # yoetz-managed render (for example the async-variant hooks form, or an
        # older guidance render), not an owner edit: ADR-023 whole-directory
        # replacement may refresh it without ``replace_modified``. The check is
        # lazy so an already-exact tree never pays for it.
        prior_render: bool | None = None

        def _replaceable_prior_render() -> bool:
            nonlocal prior_render
            if prior_render is None:
                prior_render = _is_prior_managed_render(destination)
            return prior_render

        for relative_path, expected in members.items():
            path = destination / relative_path
            if not path.exists():
                continue
            if path.is_symlink() or not path.is_file():
                raise _error(IntegrationReason.TARGET_UNSAFE)
            current = path.read_bytes()
            if current != expected and not replace_modified and not _replaceable_prior_render():
                raise _error(
                    IntegrationReason.MODIFIED_COPY,
                    {"relative_path": relative_path, "replace_modified": True},
                )
        existing_marker = destination / _MARKER_NAME
        if (
            existing_marker.is_file()
            and existing_marker.read_bytes() != marker
            and not replace_modified
            and not _replaceable_prior_render()
        ):
            raise _error(
                IntegrationReason.MODIFIED_COPY,
                {"relative_path": _MARKER_NAME, "replace_modified": True},
            )
    stage = parent / f".yoetz.plugin-stage-{os.urandom(6).hex()}"
    rollback = parent / f".yoetz.plugin-rollback-{os.urandom(6).hex()}"
    destination_moved = False
    try:
        _write_tree(stage, members, marker)
        if destination.exists():
            os.replace(destination, rollback)
            destination_moved = True
        os.replace(stage, destination)
        if rollback.exists():
            shutil.rmtree(rollback)
    except IntegrationError:
        raise
    except OSError as exc:
        if destination_moved and rollback.exists():
            try:
                if destination.exists():
                    shutil.rmtree(destination)
                os.replace(rollback, destination)
            except OSError:
                pass
        raise _error(IntegrationReason.WRITE_FAILED) from exc
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
    return inspect_plugin(
        target,
        resource_source=resource_source,
        codex_version=codex_version,
    )


def inspect_plugin(
    target: IntegrationTarget,
    *,
    resource_source: SkillResourceSource | None = None,
    codex_version: str | None = None,
) -> PluginInspection:
    """Classify plugin/hook presence without inferring Codex trust from files."""

    trust_note = "codex_hook_trust_not_observable_from_installation_state"
    try:
        root = _validated_project(target)
    except IntegrationError:
        return PluginInspection(
            PluginHookPresence.ABSENT,
            False,
            None,
            (trust_note,),
        )
    try:
        parent = _validated_plugin_parent(root, create=False)
    except IntegrationError:
        return PluginInspection(
            PluginHookPresence.INSTALLED_UNTRUSTED_UNKNOWN,
            False,
            None,
            (trust_note, "destination_unsafe"),
        )
    destination = parent / "yoetz"
    if not destination.exists():
        return PluginInspection(PluginHookPresence.ABSENT, False, None, (trust_note,))
    if destination.is_symlink() or not destination.is_dir():
        return PluginInspection(
            PluginHookPresence.INSTALLED_UNTRUSTED_UNKNOWN,
            False,
            None,
            (trust_note, "destination_unsafe"),
        )
    members = render_plugin_tree(
        resource_source=resource_source,
        codex_version=codex_version,
    )
    expected_marker = _build_marker(members)
    marker_path = destination / _MARKER_NAME
    marker_valid = marker_path.is_file() and marker_path.read_bytes() == expected_marker
    exact = marker_valid
    for relative_path, expected in members.items():
        path = destination / relative_path
        if not path.is_file() or path.is_symlink() or path.read_bytes() != expected:
            exact = False
            break
    digest = canonical_digest(
        {
            "files": [
                {"path": path, "digest": _sha((destination / path).read_bytes())}
                for path in sorted(members)
                if (destination / path).is_file()
            ],
            "marker_valid": marker_valid,
        }
    )
    if exact:
        return PluginInspection(
            PluginHookPresence.INSTALLED,
            False,
            digest,
            (trust_note,),
        )
    return PluginInspection(
        PluginHookPresence.INSTALLED_UNTRUSTED_UNKNOWN,
        False,
        digest,
        (trust_note,),
    )


def parse_hooks_json(raw: bytes) -> Mapping[str, JsonValue]:
    """Strict-parse hooks.json for tests and status helpers."""

    if len(raw) > _SOURCE_FILE_LIMIT:
        raise ProtocolValueError("unsupported_json_type")
    parsed = strict_json_parse(raw)
    if not isinstance(parsed, Mapping):
        raise ProtocolValueError("unsupported_json_type")
    return cast(Mapping[str, JsonValue], parsed)
