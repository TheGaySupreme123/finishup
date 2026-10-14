"""Consent-gated Codex marketplace registration and plugin activation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final, Literal, Never, cast

from yoetz import __version__
from yoetz.adapters.integrations.codex_plugin import (
    PluginHookPresence,
    inspect_plugin,
    plugin_tree_matches_marker,
    render_plugin_install_tree,
)
from yoetz.adapters.integrations.codex_session_stream import resolve_codex_home
from yoetz.adapters.integrations.codex_skill import (
    inspect_destination,
    load_packaged_skill_source,
)
from yoetz.adapters.integrations.host_projects import (
    ConnectedProjects,
    HostProjectsError,
    duplicate_of,
    live_projects,
    load_connected_projects,
    same_directory,
    write_connected_projects,
)
from yoetz.adapters.integrations.toml_tables import (
    append_table_block,
    exact_table_span,
    strip_exact_table,
)
from yoetz.ports.integrations import (
    IntegrationError,
    IntegrationReason,
    IntegrationScope,
    IntegrationTarget,
)
from yoetz.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from yoetz.protocol.errors import ProtocolValueError

try:
    import fcntl
except ImportError:  # pragma: no cover - supported Codex plugin hosts are POSIX
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "ActivationInspection",
    "ActivationPreview",
    "ActivationState",
    "RemovalOutcome",
    "RemovalPreview",
    "RemovalResult",
    "apply_activation",
    "apply_removal",
    "connected_projects",
    "inspect_activation",
    "preview_activation",
    "preview_removal",
    "project_registered_elsewhere",
    "resolve_codex_home_for_binary",
    "skill_tree_state",
]

_MARKETPLACE_NAME: Final = "yoetz"
_PLUGIN_ID: Final = "yoetz@yoetz"
_MARKETPLACE_RELATIVE_PATH: Final = ".agents/plugins/marketplace.json"
_PLUGIN_RELATIVE_PATH: Final = "./.agents/plugins/yoetz"
_MAX_MARKETPLACE_BYTES: Final = 262_144
_MAX_CONFIG_BYTES: Final = 1_048_576
_MAX_VERSION_BYTES: Final = 4_096
_VERSION_TIMEOUT_SECONDS: Final = 5.0
_PLUGIN_ADD_TIMEOUT_SECONDS: Final = 30.0
_MAX_PLUGIN_OUTPUT_BYTES: Final = 262_144
_MAX_EXECUTABLE_BYTES: Final = 256 * 1024 * 1024
_MAX_MANAGED_CACHE_FILES: Final = 64
_MAX_MANAGED_CACHE_ENTRIES: Final = 256
_MAX_MANAGED_CACHE_DEPTH: Final = 16
_MAX_MANAGED_CACHE_RELATIVE_PATH_BYTES: Final = 4_096
_MAX_MANAGED_CACHE_MEMBER_BYTES: Final = 262_144
_MAX_MANAGED_CACHE_TREE_BYTES: Final = 4 * 1024 * 1024
_ACTIVATION_LOCK: Final = ".yoetz-marketplace-activation.lock"
_PLUGIN_ADD_COMMAND: Final = ("plugin", "add", _PLUGIN_ID, "--json")
_PLUGIN_LIST_COMMAND: Final = ("plugin", "list", "--marketplace", _MARKETPLACE_NAME, "--json")
_PLUGIN_REMOVE_COMMAND: Final = ("plugin", "remove", _PLUGIN_ID, "--json")
_MARKETPLACE_REMOVE_COMMAND: Final = (
    "plugin",
    "marketplace",
    "remove",
    _MARKETPLACE_NAME,
    "--json",
)
_PLUGIN_TABLE: Final = f'[plugins."{_PLUGIN_ID}"]\nenabled = true\n'
_VERSION_RE: Final = re.compile(
    r"\b(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\b", re.ASCII
)


class ActivationState(str, Enum):  # noqa: UP042 - exact structural enum
    ACTIVE = "active"
    INSTALLED_NOT_ACTIVATED = "installed_not_activated"
    NOT_INSTALLED = "not_installed"
    FOREIGN = "foreign"


@dataclass(frozen=True, slots=True)
class ActivationInspection:
    """Read-only classification of Codex marketplace and plugin activation state."""

    marketplace_registered: bool
    plugin_enabled: bool
    state: ActivationState
    plugin_cached: bool = False
    inventory_verified: bool = True


@dataclass(frozen=True, slots=True)
class ActivationPreview:
    """Exact activation bytes shown before the owner approves mutation."""

    marketplace_bytes: bytes
    config_toml_block: str
    preview_digest: str
    inspection: ActivationInspection
    plugin_source_digest: str
    codex_home: Path
    plugin_install_path: Path
    plugin_install_digest: str
    executable_path: Path
    executable_digest: str
    codex_version: str
    probe_command: tuple[str, ...]
    inventory_command: tuple[str, ...]
    install_command: tuple[str, ...]
    probe_environment: str
    activation_environment: tuple[tuple[str, str], ...]
    marketplace_preimage_digest: str
    config_preimage_digest: str
    cache_mutation_planned: bool


class RemovalOutcome(str, Enum):  # noqa: UP042 - exact structural enum
    REMOVE = "remove"
    ALREADY_ABSENT = "already_absent"
    # Other connected projects still use the Codex home's shared plugin, marketplace binding,
    # and MCP registration: only this project's pieces go (#1058).
    DETACH = "detach"


@dataclass(frozen=True, slots=True)
class RemovalPreview:
    """Exact removal bytes shown before the owner approves mutation."""

    preview_digest: str
    inspection: ActivationInspection
    outcome: RemovalOutcome
    purge_cache: bool
    plugin_remove_planned: bool
    marketplace_remove_planned: bool
    marketplace_json_planned: bool
    cache_versions: tuple[str, ...]
    cache_digests: tuple[tuple[str, str], ...]
    skill_tree_state: str
    executable_path: Path
    executable_digest: str
    codex_version: str
    codex_home: Path
    probe_command: tuple[str, ...]
    inventory_command: tuple[str, ...]
    plugin_remove_command: tuple[str, ...]
    marketplace_remove_command: tuple[str, ...]
    probe_environment: str
    activation_environment: tuple[tuple[str, str], ...]
    marketplace_preimage_digest: str
    config_preimage_digest: str
    config_toml_block: str
    # Projects that keep the home's shared Yoetz pieces after a ``DETACH`` (#1058).
    shared_with: tuple[str, ...] = ()
    # The connected project the home's marketplace binding moves to, when it named this one.
    rebind_to: str | None = None


@dataclass(frozen=True, slots=True)
class RemovalResult:
    """Verified post-removal classification for one approved preview."""

    outcome: RemovalOutcome
    inspection: ActivationInspection
    skill_tree_state: str
    purge_cache: bool


@dataclass(frozen=True, slots=True)
class _ActivationPlan:
    preview: ActivationPreview
    marketplace_before: bytes | None
    config_before: bytes | None
    config_after: bytes
    cache_members: Mapping[str, bytes]
    cache_before: str | None
    binary: _CodexBinaryProbe
    projects_before: ConnectedProjects
    projects_after: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _CodexBinaryProbe:
    executable_path: Path
    executable_digest: str
    codex_version: str
    codex_home: Path


@dataclass(frozen=True, slots=True)
class _BoundedCommandOutput:
    returncode: int
    stdout: bytes


class _CommandOutputLimit(Exception):
    pass


def _error(
    reason: IntegrationReason,
    details: Mapping[str, str] | None = None,
) -> IntegrationError:
    return IntegrationError(reason, {} if details is None else dict(details))


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                total += len(chunk)
                if total > _MAX_EXECUTABLE_BYTES:
                    raise _error(IntegrationReason.SOURCE_INVALID)
                digest.update(chunk)
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    return f"sha256:{digest.hexdigest()}"


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1.0)


def _run_bounded_command(
    argv: tuple[str, ...],
    *,
    env: Mapping[str, str],
    timeout: float,
    stdout_limit: int,
) -> _BoundedCommandOutput:
    """Run fixed argv while enforcing the stdout bound during capture.

    Stderr is drained but never retained. This prevents a selected host binary
    from turning the post-parse size check into unbounded process memory.
    """

    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    try:
        process = subprocess.Popen(  # noqa: S603 - exact selected executable, no shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=dict(env),
            close_fds=True,
            # User-scope plugin commands run from the selected Codex home so a broken
            # trusted-project `.codex` layer in the invoking directory cannot fail them.
            cwd=_neutral_cwd(env),
        )
        if process.stdout is None or process.stderr is None:
            raise OSError("missing_subprocess_pipe")
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                raise subprocess.TimeoutExpired(argv, timeout)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(argv, timeout)
            for key, _mask in events:
                try:
                    chunk = os.read(key.fd, 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.fileobj is process.stdout:
                    if len(stdout) + len(chunk) > stdout_limit:
                        raise _CommandOutputLimit
                    stdout.extend(chunk)
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(argv, timeout) from None
        return _BoundedCommandOutput(process.returncode, bytes(stdout))
    except BaseException:
        if process is not None:
            _terminate_process(process)
        raise
    finally:
        selector.close()
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


def _neutral_cwd(env: Mapping[str, str]) -> str | None:
    home = env.get("CODEX_HOME")
    return home if home and Path(home).is_dir() else None


def _command_output(
    argv: tuple[str, ...],
    *,
    env: Mapping[str, str],
    timeout: float,
    stdout_limit: int,
    _run: Callable[..., subprocess.CompletedProcess[bytes]],
) -> _BoundedCommandOutput:
    if _run is subprocess.run:
        return _run_bounded_command(
            argv,
            env=env,
            timeout=timeout,
            stdout_limit=stdout_limit,
        )
    completed = _run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
        shell=False,
        env=dict(env),
    )
    raw = completed.stdout[: stdout_limit + 1]
    if len(raw) > stdout_limit:
        raise _CommandOutputLimit
    return _BoundedCommandOutput(completed.returncode, raw)


def _probe_codex_binary(
    executable_path: str,
    *,
    codex_home: Path | str | None = None,
    _run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> _CodexBinaryProbe:
    """Bind an exact executable/version to one explicitly controlled Codex home."""

    if (
        type(executable_path) is not str
        or not executable_path
        or len(executable_path) > 4_096
        or any(ord(char) < 32 or ord(char) == 127 for char in executable_path)
    ):
        raise _error(IntegrationReason.TARGET_UNSAFE)
    executable = Path(executable_path)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise _error(IntegrationReason.TARGET_UNSAFE)
    try:
        resolved_executable = executable.resolve(strict=True)
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    executable_digest = _sha_file(resolved_executable)
    home = resolve_codex_home_for_binary(executable_path, codex_home=codex_home)
    try:
        with tempfile.TemporaryDirectory(prefix="yoetz-codex-version-") as temporary:
            probe_home = Path(temporary)
            probe_home.chmod(0o700)
            completed = _command_output(
                (str(executable), "--version"),
                env=_codex_environment(probe_home),
                timeout=_VERSION_TIMEOUT_SECONDS,
                stdout_limit=_MAX_VERSION_BYTES,
                _run=_run,
            )
    except (OSError, subprocess.SubprocessError, _CommandOutputLimit) as exc:
        raise _error(IntegrationReason.SOURCE_INVALID) from exc
    raw = completed.stdout
    if completed.returncode != 0 or not raw:
        raise _error(IntegrationReason.SOURCE_INVALID)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _error(IntegrationReason.SOURCE_INVALID) from exc
    match = _VERSION_RE.search(text)
    if match is None:
        raise _error(IntegrationReason.SOURCE_INVALID)
    return _CodexBinaryProbe(
        executable.absolute(),
        executable_digest,
        match.group(1),
        home,
    )


def resolve_codex_home_for_binary(
    executable_path: str,
    *,
    codex_home: Path | str | None = None,
    _run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> Path:
    """Select the home that activation will force for the exact executable.

    This performs no subprocess or network probe. Every later Codex command receives both home
    variables set to this value, so wrappers cannot redirect the approved mutation target.
    """

    del _run
    del executable_path
    if codex_home is None:
        raise _error(IntegrationReason.TARGET_UNTRUSTED)
    return _codex_root(codex_home)


def _codex_environment(home: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment["CODEX_HOME"] = str(home)
    environment["CODEX_TESTING_HOME"] = str(home)
    return environment


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
    resolved = root.resolve()
    if root.absolute() != resolved:
        raise _error(IntegrationReason.TARGET_UNSAFE)
    return resolved


def _owned_not_writable(path: Path, *, directory: bool) -> None:
    try:
        facts = path.lstat()
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    if path.is_symlink() or (not path.is_dir() if directory else not path.is_file()):
        raise _error(IntegrationReason.TARGET_UNSAFE)
    if hasattr(os, "geteuid") and facts.st_uid != os.geteuid():
        raise _error(IntegrationReason.TARGET_UNSAFE)
    if facts.st_mode & 0o022:
        raise _error(IntegrationReason.TARGET_UNSAFE)


def _validate_descendant_ancestors(root: Path, relative_parent: Path) -> None:
    current = root
    for part in relative_parent.parts:
        current /= part
        if not current.exists() and not current.is_symlink():
            return
        _owned_not_writable(current, directory=True)


def _codex_root(codex_home: Path | str | None) -> Path:
    root = resolve_codex_home(codex_home)
    if not root.is_absolute() or root == Path(root.anchor) or root == Path.home():
        raise _error(IntegrationReason.TARGET_UNSAFE)
    if not root.exists() and not root.is_symlink():
        raise _error(IntegrationReason.TARGET_UNTRUSTED)
    _owned_not_writable(root, directory=True)
    resolved = root.resolve()
    if root.absolute() != resolved:
        raise _error(IntegrationReason.TARGET_UNSAFE)
    return resolved


def _marketplace_document() -> dict[str, JsonValue]:
    return {
        "name": _MARKETPLACE_NAME,
        "plugins": [
            {
                "name": "yoetz",
                "source": {"source": "local", "path": _PLUGIN_RELATIVE_PATH},
            }
        ],
    }


def _load_marketplace(path: Path) -> tuple[bytes, Mapping[str, object]] | None:
    if path.is_symlink():
        raise _error(IntegrationReason.TARGET_UNSAFE)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    if not raw or len(raw) > _MAX_MARKETPLACE_BYTES:
        raise _error(IntegrationReason.SOURCE_INVALID)
    _owned_not_writable(path, directory=False)
    try:
        parsed = strict_json_parse(raw)
    except Exception as exc:
        raise _error(IntegrationReason.SOURCE_INVALID) from exc
    if not isinstance(parsed, Mapping):
        raise _error(IntegrationReason.SOURCE_INVALID)
    return raw, cast(Mapping[str, object], parsed)


def _expected_source() -> dict[str, str]:
    return {"source": "local", "path": _PLUGIN_RELATIVE_PATH}


def _classify_manifest(document: Mapping[str, object] | None) -> tuple[bool, bool]:
    """Return ``(registered, foreign)`` for one marketplace document."""

    if document is None:
        return False, False
    if document.get("name") != _MARKETPLACE_NAME:
        return False, True
    plugins = document.get("plugins")
    if type(plugins) is not list:
        return False, True
    registered = False
    for raw in cast(list[object], plugins):
        if not isinstance(raw, Mapping):
            return False, True
        row = cast(Mapping[str, object], raw)
        if row.get("name") != "yoetz":
            continue
        if registered or row.get("source") != _expected_source():
            return False, True
        registered = True
    return registered, False


def _personal_manifest_conflicts(document: Mapping[str, object] | None) -> bool:
    """A different personal marketplace is harmless unless it also claims ``yoetz``."""

    if document is None:
        return False
    if document.get("name") == _MARKETPLACE_NAME:
        return True
    plugins = document.get("plugins")
    if type(plugins) is not list:
        return False
    for raw in cast(list[object], plugins):
        if isinstance(raw, Mapping) and cast(Mapping[str, object], raw).get("name") == "yoetz":
            return True
    return False


def _load_config(path: Path) -> tuple[bytes, Mapping[str, object]]:
    if path.is_symlink():
        raise _error(IntegrationReason.TARGET_UNSAFE)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return b"", {}
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    if len(raw) > _MAX_CONFIG_BYTES:
        raise _error(IntegrationReason.SOURCE_INVALID)
    _owned_not_writable(path, directory=False)
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise _error(IntegrationReason.SOURCE_INVALID) from exc
    return raw, cast(Mapping[str, object], parsed)


def _table(root: Mapping[str, object], name: str) -> Mapping[str, object] | None:
    value = root.get(name)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise _error(IntegrationReason.DESTINATION_CONFLICT)
    return cast(Mapping[str, object], value)


def _config_state(config: Mapping[str, object], project: Path) -> tuple[bool, bool, bool]:
    """Return ``(marketplace_configured, plugin_enabled, foreign)``.

    A binding to another connected project that still serves the exact Yoetz manifest is the
    home's shared marketplace, not a foreign one (#1058).
    """

    relation, _source = _marketplace_relation(config, project)
    configured = relation in {"self", "shared"}
    if relation in {"foreign", "duplicate"}:
        return False, False, True

    plugins = _table(config, "plugins")
    plugin = None if plugins is None else plugins.get(_PLUGIN_ID)
    enabled = False
    if plugin is not None:
        if not isinstance(plugin, Mapping):
            return configured, False, True
        row = cast(Mapping[str, object], plugin)
        flag = row.get("enabled")
        if type(flag) is not bool:
            return configured, False, True
        enabled = flag
    return configured, enabled, False


# How the home's one ``[marketplaces.yoetz]`` binding relates to the project in question (#1058):
# ``self`` names it; ``shared`` names another project that still serves the exact Yoetz manifest;
# ``missing`` names a project whose directory or manifest is gone (Codex then fails every plugin
# command in the home); ``duplicate`` names this same directory under another path; ``foreign``
# is anything else.
type _Relation = Literal["absent", "self", "shared", "missing", "duplicate", "foreign"]


def _anchor_manifest_state(anchor: Path) -> Literal["serves", "missing", "foreign"]:
    try:
        if anchor.is_symlink() or not anchor.is_dir() or anchor.resolve() != anchor:
            return "foreign" if os.path.lexists(anchor) else "missing"
        manifest = anchor / _MARKETPLACE_RELATIVE_PATH
        if not os.path.lexists(manifest):
            return "missing"
        snapshot = _load_marketplace(manifest)
    except IntegrationError, OSError:
        return "foreign"
    registered, foreign = _classify_manifest(None if snapshot is None else snapshot[1])
    source = anchor / _PLUGIN_RELATIVE_PATH.removeprefix("./")
    if registered and not foreign and source.is_dir() and not source.is_symlink():
        return "serves"
    return "foreign"


def _marketplace_relation(config: Mapping[str, object], project: Path) -> tuple[_Relation, str]:
    marketplaces = _table(config, "marketplaces")
    marketplace = None if marketplaces is None else marketplaces.get(_MARKETPLACE_NAME)
    if marketplace is None:
        return "absent", ""
    if not isinstance(marketplace, Mapping):
        return "foreign", ""
    row = cast(Mapping[str, object], marketplace)
    source = row.get("source")
    if row.get("source_type") != "local" or type(source) is not str:
        return "foreign", ""
    if source == str(project):
        return "self", source
    anchor = Path(source)
    if not anchor.is_absolute():
        return "foreign", source
    if same_directory(anchor, project):
        return "duplicate", source
    state = _anchor_manifest_state(anchor)
    if state == "serves":
        return "shared", source
    return ("missing" if state == "missing" else "foreign"), source


def _anchor(config: Mapping[str, object], project: Path) -> Path:
    """The project whose manifest Codex resolves the shared marketplace from."""

    relation, source = _marketplace_relation(config, project)
    return Path(source) if relation in {"self", "shared"} else project


def _load_projects(home: Path) -> ConnectedProjects:
    try:
        return load_connected_projects(home)
    except HostProjectsError as exc:
        raise _error(IntegrationReason.SOURCE_INVALID, {"conflict": "connected_projects"}) from exc


def _write_projects(snapshot: ConnectedProjects, projects: tuple[str, ...]) -> None:
    try:
        write_connected_projects(snapshot, projects)
    except HostProjectsError as exc:
        raise _error(
            IntegrationReason.PREVIEW_STALE
            if exc.reason == "registry_stale"
            else IntegrationReason.WRITE_FAILED
        ) from exc


def _refuse_duplicate(project: Path, relation: _Relation, members: tuple[str, ...]) -> None:
    if relation == "duplicate" or duplicate_of(project, members) is not None:
        raise _error(IntegrationReason.PROJECT_CONNECTED_VIA_OTHER_PATH)


def _member(project: Path, relation: _Relation, members: tuple[str, ...]) -> bool:
    """Whether this project connected to the home, as opposed to only seeing its shared plugin.

    A home written before #1058 has no record; its one bound project is its one member.
    """

    return relation == "self" or (relation == "shared" and str(project) in members)


def connected_projects(codex_home: Path | str | None) -> tuple[str, ...]:
    """The projects connected to this Codex home through its shared Yoetz pieces (status)."""

    home = _codex_root(codex_home)
    projects = set(_load_projects(home).projects)
    _raw, config = _load_config(home / "config.toml")
    marketplaces = _table(config, "marketplaces")
    marketplace = None if marketplaces is None else marketplaces.get(_MARKETPLACE_NAME)
    if isinstance(marketplace, Mapping):
        source = cast(Mapping[str, object], marketplace).get("source")
        if type(source) is str and Path(source).is_absolute():
            projects.add(source)
    return tuple(sorted(projects))


def project_registered_elsewhere(codex_home: Path | str | None, project: Path) -> str | None:
    """The recorded path that names ``project``'s directory differently, if any (refusal text)."""

    try:
        return duplicate_of(project, connected_projects(codex_home))
    except IntegrationError:
        return None


def _rebind_marketplace(raw: bytes, old: str, new: Path) -> bytes:
    """Point the exact Yoetz marketplace table at another connected project, in place."""

    old_table = _expected_marketplace_table(Path(old))
    span = exact_table_span(raw, old_table)
    if span is None:
        raise _error(IntegrationReason.DESTINATION_CONFLICT, {"conflict": "config_marketplace"})
    start, _end = span
    rebound = (
        raw[:start]
        + _expected_marketplace_table(new).encode()
        + raw[start + len(old_table.encode()) :]
    )
    try:
        tomllib.loads(rebound.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise _error(IntegrationReason.DESTINATION_CONFLICT) from exc
    return rebound


def _paths(
    target: IntegrationTarget, codex_home: Path | str | None
) -> tuple[Path, Path, Path, Path]:
    project = _validated_project(target)
    _validate_descendant_ancestors(project, Path(".agents/plugins"))
    home = _codex_root(codex_home)
    _validate_descendant_ancestors(home, Path("plugins/cache/yoetz/yoetz"))
    _validate_descendant_ancestors(home, Path(".agents/plugins"))
    return (
        project,
        home,
        project / _MARKETPLACE_RELATIVE_PATH,
        home / "config.toml",
    )


def _cache_root(home: Path) -> Path:
    return home / "plugins" / "cache" / _MARKETPLACE_NAME / "yoetz"


def _cache_root_has_entries(home: Path) -> bool:
    relative_root = Path("plugins/cache/yoetz/yoetz")
    try:
        root_fd = _open_anchored_directory(
            home,
            relative_root,
            missing_reason=IntegrationReason.PREVIEW_STALE,
        )
    except IntegrationError as exc:
        if exc.reason is IntegrationReason.PREVIEW_STALE:
            return False
        raise
    try:
        return bool(_bounded_directory_names(root_fd))
    finally:
        os.close(root_fd)


def _cache_version_path(root: Path, version: str) -> Path:
    if _VERSION_RE.fullmatch(version) is None:
        raise _error(IntegrationReason.SOURCE_INVALID)
    return root / version


def _plugin_source_presence(target: IntegrationTarget, *, codex_version: str) -> PluginHookPresence:
    """Classify source presence independently of host-variant byte parity.

    ``INSTALLED`` when either current renderer variant matches. ``ABSENT`` only
    when both variants report absence. Any other byte-present tree, including a
    modified or untrusted copy that Codex may still be serving, is
    ``INSTALLED_UNTRUSTED_UNKNOWN`` so status never collapses it to
    ``not_installed`` (#347).
    """

    seen = tuple(
        inspect_plugin(target, codex_version=variant).presence for variant in (None, codex_version)
    )
    if PluginHookPresence.INSTALLED in seen:
        return PluginHookPresence.INSTALLED
    if all(presence is PluginHookPresence.ABSENT for presence in seen):
        return PluginHookPresence.ABSENT
    return PluginHookPresence.INSTALLED_UNTRUSTED_UNKNOWN


def _plugin_source_installed(target: IntegrationTarget, *, codex_version: str) -> bool:
    """True when the project tree is byte-exactly one current managed renderer variant.

    The committed project tree deliberately carries the canonical (async-free)
    render (``codex_version=None``); the host-specific form belongs only to the
    activation cache. Either byte-exact form counts as an installed source, so a
    canonical source on an async-capable host never reads as ``not_installed``.
    Apply fences keep using this exact-variant check; status uses
    ``_plugin_source_presence`` so a modified tree is not reported absent.
    """

    return (
        _plugin_source_presence(target, codex_version=codex_version) is PluginHookPresence.INSTALLED
    )


def _read_managed_tree(root: Path) -> dict[str, bytes]:
    """Read one managed tree through the shared bounded, no-follow descriptor walker."""

    if root.is_symlink():
        raise _error(IntegrationReason.TARGET_UNSAFE)
    try:
        descriptor = os.open(root, _directory_open_flags())
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    try:
        _owned_stat_not_writable(os.fstat(descriptor), directory=True)
        return _read_managed_tree_fd(descriptor)
    finally:
        os.close(descriptor)


def _source_cache_members(target: IntegrationTarget, *, codex_version: str) -> dict[str, bytes]:
    project = _validated_project(target)
    source = project / ".agents/plugins/yoetz"
    expected = render_plugin_install_tree(codex_version=codex_version)
    inspection = inspect_plugin(target, codex_version=codex_version)
    if inspection.presence is PluginHookPresence.ABSENT:
        return expected
    if inspection.presence is not PluginHookPresence.INSTALLED:
        # Setup previews activation before it replaces a previously managed tree.
        # Admit any byte-exact prior yoetz-managed render here (the canonical
        # committed source, the other renderer variant, or an older marker-bound
        # render), then bind the preview to the intended version-specific bytes.
        # Apply still requires an exact current renderer variant at its first
        # source fence before any mutation.
        if plugin_tree_matches_marker(_read_managed_tree(source)):
            return expected
        raise _error(IntegrationReason.PARTIAL_INSTALL)
    actual_paths: set[str] = set()
    for candidate in source.rglob("*"):
        if candidate.is_symlink():
            raise _error(IntegrationReason.TARGET_UNSAFE)
        relative = candidate.relative_to(source).as_posix()
        if candidate.is_dir():
            _owned_not_writable(candidate, directory=True)
        elif candidate.is_file():
            _owned_not_writable(candidate, directory=False)
            actual_paths.add(relative)
        else:
            raise _error(IntegrationReason.TARGET_UNSAFE)
    if actual_paths != set(expected):
        raise _error(IntegrationReason.DESTINATION_CONFLICT)
    members: dict[str, bytes] = {}
    for relative_path in expected:
        path = source / relative_path
        current = source
        for part in Path(relative_path).parts:
            current /= part
            if current.is_symlink():
                raise _error(IntegrationReason.TARGET_UNSAFE)
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise _error(IntegrationReason.TARGET_UNSAFE) from exc
        _owned_not_writable(path, directory=False)
        if payload != expected[relative_path]:
            raise _error(IntegrationReason.PARTIAL_INSTALL)
        members[relative_path] = payload
    return members


def _members_digest(members: Mapping[str, bytes]) -> str:
    rows = [
        {"path": path, "digest": _sha(payload), "size": len(payload)}
        for path, payload in sorted(members.items())
    ]
    return _sha(canonical_encode(cast(JsonValue, {"managed_files": rows})))


def _installed_cache_digest(path: Path, expected_members: Mapping[str, bytes]) -> str | None:
    """Digest the installed cache tree when it is yoetz-managed, else refuse.

    ``None`` means absent. A tree byte-identical to ``expected_members`` is the
    current render. A tree that instead byte-matches its own valid install marker
    (schema ``yoetz.codex-plugin-install/1``) is a *prior* yoetz-managed render:
    preview binds its digest as ``cache_before`` and apply may atomically replace
    the whole directory (#388). Foreign, marker-inconsistent, or otherwise
    modified trees stay ``destination_conflict``.
    """

    if path.is_symlink():
        raise _error(IntegrationReason.TARGET_UNSAFE)
    if not path.exists():
        return None
    _owned_not_writable(path, directory=True)
    actual = _read_managed_tree(path)
    if actual != dict(expected_members) and not plugin_tree_matches_marker(actual):
        raise _error(IntegrationReason.DESTINATION_CONFLICT)
    return _members_digest(actual)


def _installed_cache_digest_anchored(
    home: Path,
    version: str,
    expected_members: Mapping[str, bytes],
) -> str | None:
    """Digest one cache version without following a replaced home ancestor."""

    if _VERSION_RE.fullmatch(version) is None:
        raise _error(IntegrationReason.SOURCE_INVALID)
    try:
        root_fd = _open_anchored_directory(
            home,
            Path("plugins/cache/yoetz/yoetz"),
            missing_reason=IntegrationReason.PREVIEW_STALE,
        )
    except IntegrationError as exc:
        if exc.reason is IntegrationReason.PREVIEW_STALE:
            return None
        raise
    try:
        opened = _open_managed_cache_digest_at(
            root_fd,
            version,
            expected_members,
            mismatch_reason=IntegrationReason.DESTINATION_CONFLICT,
        )
        if opened is None:
            return None
        descriptor, digest, _approved_members = opened
        os.close(descriptor)
        return digest
    finally:
        os.close(root_fd)


def _run_json_command(
    binary: _CodexBinaryProbe,
    command: tuple[str, ...],
    *,
    _run: Callable[..., subprocess.CompletedProcess[bytes]],
    timeout: float,
) -> Mapping[str, object]:
    try:
        completed = _command_output(
            (str(binary.executable_path), *command),
            env=_codex_environment(binary.codex_home),
            timeout=timeout,
            stdout_limit=_MAX_PLUGIN_OUTPUT_BYTES,
            _run=_run,
        )
    except (OSError, subprocess.SubprocessError, _CommandOutputLimit) as exc:
        raise _error(IntegrationReason.WRITE_FAILED) from exc
    raw = completed.stdout
    if completed.returncode != 0 or not raw:
        raise _error(IntegrationReason.WRITE_FAILED)
    try:
        parsed = strict_json_parse(raw)
    except ProtocolValueError as exc:
        raise _error(IntegrationReason.SOURCE_INVALID) from exc
    if not isinstance(parsed, Mapping):
        raise _error(IntegrationReason.SOURCE_INVALID)
    return cast(Mapping[str, object], parsed)


def _plugin_inventory(
    binary: _CodexBinaryProbe,
    anchor: Path,
    *,
    _run: Callable[..., subprocess.CompletedProcess[bytes]],
) -> tuple[bool, str | None]:
    """Return exact Yoetz installed state/version from canonical Codex inventory.

    ``anchor`` is the project the home's marketplace binding names: with several connected
    projects it is one of them, not necessarily the project being inspected (#1058).
    """

    document = _run_json_command(
        binary,
        _PLUGIN_LIST_COMMAND,
        _run=_run,
        timeout=_VERSION_TIMEOUT_SECONDS,
    )
    matches: list[Mapping[str, object]] = []
    for field in ("installed", "available"):
        raw_rows = document.get(field, [])
        if type(raw_rows) is not list:
            raise _error(IntegrationReason.SOURCE_INVALID)
        for raw in cast(list[object], raw_rows):
            if not isinstance(raw, Mapping):
                raise _error(IntegrationReason.SOURCE_INVALID)
            row = cast(Mapping[str, object], raw)
            if row.get("pluginId") == _PLUGIN_ID:
                matches.append(row)
    if not matches:
        return False, None
    if len(matches) != 1:
        raise _error(IntegrationReason.DESTINATION_CONFLICT)
    row = matches[0]
    expected_source = {"source": "local", "path": str(anchor / ".agents/plugins/yoetz")}
    expected_marketplace = {"sourceType": "local", "source": str(anchor)}
    if row.get("source") != expected_source or row.get("marketplaceSource") != expected_marketplace:
        raise _error(IntegrationReason.DESTINATION_CONFLICT)
    installed = row.get("installed")
    enabled = row.get("enabled")
    version = row.get("version")
    if type(installed) is not bool or type(enabled) is not bool:
        raise _error(IntegrationReason.SOURCE_INVALID)
    if version is not None and (type(version) is not str or _VERSION_RE.fullmatch(version) is None):
        raise _error(IntegrationReason.SOURCE_INVALID)
    if installed and (enabled is not True or type(version) is not str):
        raise _error(IntegrationReason.DESTINATION_CONFLICT)
    return installed, version


def inspect_activation(
    target: IntegrationTarget,
    *,
    executable_path: str,
    codex_home: Path | str | None = None,
    _run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    _canonical_inventory: bool = True,
) -> ActivationInspection:
    """Inspect installation, repository registration, and selected Codex-home activation."""

    binary = _probe_codex_binary(executable_path, codex_home=codex_home, _run=_run)
    if codex_home is not None and _codex_root(codex_home) != binary.codex_home:
        raise _error(IntegrationReason.PREVIEW_STALE)
    project, home, marketplace_path, config_path = _paths(target, binary.codex_home)
    # The committed project tree carries the canonical render; judging ``installed``
    # against the host-specific render alone would keep an async-capable host at
    # ``not_installed`` forever (#387). A byte-present modified tree is still
    # installed for status (#347): ``not_installed`` is absence only.
    presence = _plugin_source_presence(target, codex_version=binary.codex_version)
    installed = presence is not PluginHookPresence.ABSENT
    exact_source = presence is PluginHookPresence.INSTALLED
    plugin_cached = False
    cache_foreign = False
    _raw, config = _load_config(config_path)
    relation, _source = _marketplace_relation(config, project)
    if exact_source and relation != "missing":
        # A missing binding makes Codex fail every plugin command in the home; the inventory
        # cannot be read until activation rebinds it, so the plugin reads as not cached.
        try:
            cache_members = _source_cache_members(target, codex_version=binary.codex_version)
            local_digest = _installed_cache_digest_anchored(home, __version__, cache_members)
            if _canonical_inventory:
                inventory_installed, version = _plugin_inventory(
                    binary, _anchor(config, project), _run=_run
                )
                if inventory_installed:
                    assert version is not None
                    plugin_cached = _installed_cache_digest_anchored(
                        home, version, cache_members
                    ) == _members_digest(cache_members)
                elif _cache_root_has_entries(home):
                    cache_foreign = True
            elif local_digest is not None:
                # Preview is mutation-free: a canonical inventory command is reserved for apply.
                plugin_cached = False
            elif _cache_root_has_entries(home):
                cache_foreign = True
        except IntegrationError as exc:
            if exc.reason in {
                IntegrationReason.DESTINATION_CONFLICT,
                IntegrationReason.TARGET_UNSAFE,
            }:
                cache_foreign = True
            else:
                raise
    repo_snapshot = _load_marketplace(marketplace_path)
    repo_document = None if repo_snapshot is None else repo_snapshot[1]
    repo_registered, repo_foreign = _classify_manifest(repo_document)

    # A same-named personal marketplace entry is ambiguous with the repository-scoped source.
    personal_path = home / _MARKETPLACE_RELATIVE_PATH
    personal_document = None
    if personal_path != marketplace_path:
        personal_snapshot = _load_marketplace(personal_path)
        personal_document = None if personal_snapshot is None else personal_snapshot[1]
    config_registered, plugin_enabled, config_foreign = _config_state(config, project)
    try:
        members = _load_projects(home).projects
        record_foreign = False
    except IntegrationError:
        members, record_foreign = (), True
    foreign = (
        repo_foreign
        or _personal_manifest_conflicts(personal_document)
        or config_foreign
        or cache_foreign
        or record_foreign
    )
    # Another project's binding serves this project's sessions too, but this project is only
    # connected once its own setup recorded it (#1058).
    marketplace_registered = (
        repo_registered and config_registered and _member(project, relation, members)
    )
    if foreign:
        state = ActivationState.FOREIGN
    elif not installed:
        state = ActivationState.NOT_INSTALLED
    elif marketplace_registered and plugin_enabled and plugin_cached:
        state = ActivationState.ACTIVE
    else:
        state = ActivationState.INSTALLED_NOT_ACTIVATED
    return ActivationInspection(
        marketplace_registered,
        plugin_enabled,
        state,
        plugin_cached,
        _canonical_inventory,
    )


def _merged_marketplace_bytes(existing: Mapping[str, object] | None) -> bytes:
    if existing is None:
        document: dict[str, object] = dict(_marketplace_document())
    else:
        _registered, foreign = _classify_manifest(existing)
        if foreign:
            raise _error(IntegrationReason.DESTINATION_CONFLICT)
        document = dict(existing)
        raw_plugins = document.get("plugins", [])
        assert type(raw_plugins) is list
        plugins = [
            dict(cast(Mapping[str, object], item)) for item in cast(list[object], raw_plugins)
        ]
        if not any(item.get("name") == "yoetz" for item in plugins):
            plugins.append({"name": "yoetz", "source": _expected_source()})
        document["name"] = _MARKETPLACE_NAME
        document["plugins"] = plugins
    return canonical_encode(cast(JsonValue, document)) + b"\n"


def _toml_string(value: str) -> str:
    # ``ensure_ascii=False`` keeps non-BMP characters literal (valid in TOML basic
    # strings) instead of surrogate-pair ``\uXXXX`` escapes (invalid TOML), while
    # JSON still escapes quote, backslash, and C0 controls as TOML-valid escapes.
    # DEL is the one TOML-forbidden literal JSON leaves unescaped.
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def _activation_block(project: Path, config: Mapping[str, object]) -> str:
    relation, _source = _marketplace_relation(config, project)
    if relation == "duplicate":
        raise _error(IntegrationReason.PROJECT_CONNECTED_VIA_OTHER_PATH)
    configured, enabled, foreign = _config_state(config, project)
    if foreign:
        raise _error(IntegrationReason.DESTINATION_CONFLICT)
    plugins = _table(config, "plugins")
    if plugins is not None and _PLUGIN_ID in plugins and not enabled:
        # The owner-authored table cannot be appended a second time and this adapter never
        # rewrites user TOML. The owner must remove the disabled table before a new preview.
        raise _error(IntegrationReason.DESTINATION_CONFLICT)
    blocks: list[str] = []
    if not configured:
        blocks.append(
            f'[marketplaces.yoetz]\nsource_type = "local"\nsource = {_toml_string(str(project))}\n'
        )
    if not enabled:
        blocks.append(f'[plugins."{_PLUGIN_ID}"]\nenabled = true\n')
    return "\n".join(blocks)


def _sha(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _plugin_source_digest(*, codex_version: str) -> str:
    rows = [
        {"path": path, "digest": _sha(payload), "size": len(payload)}
        for path, payload in sorted(render_plugin_install_tree(codex_version=codex_version).items())
    ]
    return _sha(canonical_encode(cast(JsonValue, {"managed_files": rows})))


def _activation_plan(
    target: IntegrationTarget,
    *,
    executable_path: str,
    codex_home: Path | str | None = None,
    _run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> _ActivationPlan:
    binary = _probe_codex_binary(executable_path, codex_home=codex_home, _run=_run)
    if codex_home is not None and _codex_root(codex_home) != binary.codex_home:
        raise _error(IntegrationReason.PREVIEW_STALE)
    project, home, marketplace_path, config_path = _paths(target, binary.codex_home)
    inspection = inspect_activation(
        target,
        executable_path=executable_path,
        codex_home=home,
        _run=_run,
        _canonical_inventory=False,
    )
    config_bytes, config = _load_config(config_path)
    relation, source = _marketplace_relation(config, project)
    projects_before = _load_projects(home)
    # The same directory under a second path would give one project two registrations that
    # disagree about every later disconnect; name that before any generic conflict (#1058).
    _refuse_duplicate(project, relation, projects_before.projects)
    if inspection.state is ActivationState.FOREIGN:
        raise _error(IntegrationReason.DESTINATION_CONFLICT)
    marketplace_snapshot = _load_marketplace(marketplace_path)
    marketplace_before = None if marketplace_snapshot is None else marketplace_snapshot[0]
    marketplace_document = None if marketplace_snapshot is None else marketplace_snapshot[1]
    marketplace_bytes = _merged_marketplace_bytes(marketplace_document)
    config_before = config_bytes if config_path.exists() else None
    projects_after = projects_before.with_project(project)
    if relation == "shared":
        # A home bound before #1058 has no record; its bound project stays connected.
        projects_after = tuple(sorted({*projects_after, source}))
    block = _activation_block(project, config)
    plugin_source_digest = _plugin_source_digest(codex_version=binary.codex_version)
    cache_members = _source_cache_members(target, codex_version=binary.codex_version)
    plugin_install_digest = _members_digest(cache_members)
    plugin_cache_root = _cache_root(home)
    plugin_install_path = _cache_version_path(plugin_cache_root, __version__)
    cache_before = _installed_cache_digest_anchored(home, __version__, cache_members)
    digest_body = (
        b"yoetz.codex-marketplace-activation/2\0"
        + str(home).encode("utf-8")
        + b"\0"
        + _sha(b"" if marketplace_before is None else marketplace_before).encode()
        + b"\0"
        + (b"present:" if config_before is not None else b"absent:")
        + _sha(config_bytes).encode()
        + b"\0"
        + marketplace_bytes
        + b"\0"
        + block.encode("utf-8")
        + b"\0"
        + plugin_source_digest.encode("ascii")
        + b"\0"
        + str(plugin_install_path).encode("utf-8")
        + b"\0"
        + (b"absent" if cache_before is None else cache_before.encode("ascii"))
        + b"\0"
        + plugin_install_digest.encode("ascii")
        + b"\0"
        + str(binary.executable_path).encode("utf-8")
        + b"\0"
        + binary.executable_digest.encode("ascii")
        + b"\0"
        + binary.codex_version.encode("ascii")
        + b"\0"
        + canonical_encode(["--version"])
        + b"\0"
        + b"temporary_owner_private_home"
        + b"\0"
        + canonical_encode(
            {
                "CODEX_HOME": str(home),
                "CODEX_TESTING_HOME": str(home),
            }
        )
        + b"\0"
        + canonical_encode(list(_PLUGIN_LIST_COMMAND))
        + b"\0"
        + canonical_encode(list(_PLUGIN_ADD_COMMAND))
        + b"\0"
        + _sha(b"" if projects_before.raw is None else projects_before.raw).encode()
        + b"\0"
        + canonical_encode(list(projects_after))
    )
    preview = ActivationPreview(
        marketplace_bytes,
        block,
        _sha(digest_body),
        inspection,
        plugin_source_digest,
        home,
        plugin_install_path,
        plugin_install_digest,
        binary.executable_path,
        binary.executable_digest,
        binary.codex_version,
        ("--version",),
        _PLUGIN_LIST_COMMAND,
        _PLUGIN_ADD_COMMAND,
        "temporary_owner_private_home",
        (("CODEX_HOME", str(home)), ("CODEX_TESTING_HOME", str(home))),
        _sha(b"" if marketplace_before is None else marketplace_before),
        _sha(config_bytes),
        cache_before != plugin_install_digest,
    )
    config_after = _activated_config_bytes(config_bytes, config, project)
    return _ActivationPlan(
        preview,
        marketplace_before,
        config_before,
        config_after,
        cache_members,
        cache_before,
        binary,
        projects_before,
        projects_after,
    )


def preview_activation(
    target: IntegrationTarget,
    *,
    executable_path: str,
    codex_home: Path | str | None = None,
    _run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> ActivationPreview:
    """Return the exact proposed marketplace document, TOML block, and stale-safe digest."""

    return _activation_plan(
        target,
        executable_path=executable_path,
        codex_home=codex_home,
        _run=_run,
    ).preview


def _safe_parent(path: Path) -> None:
    ancestors: list[Path] = []
    current = path
    while not current.exists():
        ancestors.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise _error(IntegrationReason.TARGET_UNSAFE)
    for directory in reversed(ancestors):
        try:
            directory.mkdir(mode=0o700)
        except OSError as exc:
            raise _error(IntegrationReason.WRITE_FAILED) from exc
    if path.is_symlink() or not path.is_dir():
        raise _error(IntegrationReason.TARGET_UNSAFE)


def _atomic_write(path: Path, payload: bytes) -> None:
    _safe_parent(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise _error(IntegrationReason.WRITE_FAILED) from exc


def _open_or_create_private_directory(root_fd: int, relative: Path) -> int:
    current_fd = os.dup(root_fd)
    try:
        for part in relative.parts:
            if part in {"", ".", ".."}:
                raise _error(IntegrationReason.TARGET_UNSAFE)
            try:
                os.mkdir(part, mode=0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            except OSError as exc:
                raise _error(IntegrationReason.WRITE_FAILED) from exc
            try:
                child_fd = os.open(part, _directory_open_flags(), dir_fd=current_fd)
            except OSError as exc:
                raise _error(IntegrationReason.WRITE_FAILED) from exc
            try:
                _owned_stat_not_writable(os.fstat(child_fd), directory=True)
            except BaseException:
                os.close(child_fd)
                raise
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _remove_private_tree_contents_fd(directory_fd: int, *, depth: int = 0) -> None:
    """Remove a freshly created private staging tree without following links."""

    if depth > _MAX_MANAGED_CACHE_DEPTH:
        raise _error(IntegrationReason.WRITE_FAILED)
    try:
        names = _bounded_directory_names(directory_fd)
    except IntegrationError as exc:
        raise _error(IntegrationReason.WRITE_FAILED) from exc
    for name in names:
        try:
            facts = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(facts.st_mode):
                child_fd = os.open(name, _directory_open_flags(), dir_fd=directory_fd)
                try:
                    _remove_private_tree_contents_fd(child_fd, depth=depth + 1)
                finally:
                    os.close(child_fd)
                os.rmdir(name, dir_fd=directory_fd)
            elif stat.S_ISREG(facts.st_mode):
                os.unlink(name, dir_fd=directory_fd)
            else:
                raise _error(IntegrationReason.WRITE_FAILED)
        except IntegrationError:
            raise
        except OSError as exc:
            raise _error(IntegrationReason.WRITE_FAILED) from exc


def _replace_cache_tree(
    path: Path,
    members: Mapping[str, bytes],
    *,
    anchor_root: Path | None = None,
) -> None:
    """Atomically replace one managed cache directory with freshly rendered members."""

    if anchor_root is not None:
        _replace_cache_tree_anchored(path, members, anchor_root=anchor_root)
        return

    parent = path.parent
    _safe_parent(parent)
    stage = parent / f".yoetz-cache-stage-{os.urandom(6).hex()}"
    rollback = parent / f".yoetz-cache-rollback-{os.urandom(6).hex()}"
    destination_moved = False
    try:
        stage.mkdir(mode=0o700)
        for relative_path, payload in members.items():
            destination = stage / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                written = 0
                while written < len(payload):
                    written += os.write(descriptor, payload[written:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if path.exists():
            os.replace(path, rollback)
            destination_moved = True
        os.replace(stage, path)
        if rollback.exists():
            shutil.rmtree(rollback)
    except OSError as exc:
        if destination_moved and rollback.exists():
            try:
                if path.exists():
                    shutil.rmtree(path)
                os.replace(rollback, path)
            except OSError:
                pass
        raise _error(IntegrationReason.WRITE_FAILED) from exc
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def _replace_cache_tree_anchored(
    path: Path,
    members: Mapping[str, bytes],
    *,
    anchor_root: Path,
) -> None:
    """Replace a managed cache tree through a no-follow selected-home descriptor."""

    if path.name in {"", ".", ".."} or "/" in path.name:
        raise _error(IntegrationReason.TARGET_UNSAFE)
    try:
        relative_parent = path.parent.relative_to(anchor_root)
    except ValueError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    parent_fd = _open_anchored_directory(anchor_root, relative_parent)
    stage = f".yoetz-cache-stage-{os.urandom(6).hex()}"
    rollback = f".yoetz-cache-rollback-{os.urandom(6).hex()}"
    stage_fd: int | None = None
    old_fd: int | None = None
    old_members: dict[str, bytes] | None = None
    stage_present = False
    rollback_present = False
    destination_installed = False
    failure: Exception | None = None
    try:
        try:
            os.mkdir(stage, mode=0o700, dir_fd=parent_fd)
            stage_present = True
            stage_fd = os.open(stage, _directory_open_flags(), dir_fd=parent_fd)
            _owned_stat_not_writable(os.fstat(stage_fd), directory=True)
            for relative_path, payload in sorted(members.items()):
                relative = Path(relative_path)
                if relative.is_absolute() or any(
                    part in {"", ".", ".."} for part in relative.parts
                ):
                    raise _error(IntegrationReason.SOURCE_INVALID)
                directory_fd = _open_or_create_private_directory(stage_fd, relative.parent)
                try:
                    descriptor = os.open(
                        relative.name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=directory_fd,
                    )
                    try:
                        written = 0
                        while written < len(payload):
                            written += os.write(descriptor, payload[written:])
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                finally:
                    os.close(directory_fd)

            try:
                before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                before = None
            except OSError as exc:
                raise _error(IntegrationReason.WRITE_FAILED) from exc
            if before is not None:
                _owned_stat_not_writable(before, directory=True)
                old_fd = os.open(path.name, _directory_open_flags(), dir_fd=parent_fd)
                _owned_stat_not_writable(os.fstat(old_fd), directory=True)
                old_members = _read_managed_tree_fd(old_fd)
                os.rename(
                    path.name,
                    rollback,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                rollback_present = True
            os.rename(stage, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            stage_present = False
            destination_installed = True
            if rollback_present:
                assert old_fd is not None and old_members is not None
                _remove_validated_directory(parent_fd, rollback, old_fd, old_members)
                rollback_present = False
        except IntegrationError:
            raise
        except OSError as exc:
            raise _error(IntegrationReason.WRITE_FAILED) from exc
    except Exception as exc:
        failure = exc
        if rollback_present and not destination_installed:
            try:
                os.rename(
                    rollback,
                    path.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                rollback_present = False
            except OSError:
                failure = _error(IntegrationReason.WRITE_FAILED)
    finally:
        if stage_present and stage_fd is not None:
            try:
                _remove_private_tree_contents_fd(stage_fd)
                os.rmdir(stage, dir_fd=parent_fd)
            except IntegrationError as exc:
                failure = exc
        if old_fd is not None:
            os.close(old_fd)
        if stage_fd is not None:
            os.close(stage_fd)
        os.close(parent_fd)
    if failure is not None:
        if isinstance(failure, IntegrationError):
            raise failure
        raise _error(IntegrationReason.WRITE_FAILED) from failure


def _current_bytes(path: Path) -> bytes | None:
    if path.is_symlink():
        raise _error(IntegrationReason.TARGET_UNSAFE)
    try:
        payload = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    _owned_not_writable(path, directory=False)
    return payload


def _assert_snapshot(path: Path, expected: bytes | None) -> None:
    if _current_bytes(path) != expected:
        raise _error(IntegrationReason.PREVIEW_STALE)


class _ActivationLock:
    def __init__(self, target: IntegrationTarget, codex_home: Path | str | None) -> None:
        self._target = target
        self._codex_home = codex_home
        self._descriptor: int | None = None

    def __enter__(self) -> None:
        _validated_project(self._target)
        home = _codex_root(self._codex_home)
        _safe_parent(home)
        path = home / _ACTIVATION_LOCK
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(path, flags, 0o600)
            os.fchmod(descriptor, 0o600)
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise _error(IntegrationReason.TARGET_UNSAFE) from exc
        assert descriptor is not None
        self._descriptor = descriptor

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is not None:
            os.close(descriptor)


def _assert_plugin_source(
    target: IntegrationTarget,
    expected_digest: str,
    expected_members: Mapping[str, bytes],
    *,
    codex_version: str,
) -> None:
    if _plugin_source_digest(codex_version=codex_version) != expected_digest:
        raise _error(IntegrationReason.PREVIEW_STALE)
    if not _plugin_source_installed(target, codex_version=codex_version):
        raise _error(IntegrationReason.PARTIAL_INSTALL)
    if _source_cache_members(target, codex_version=codex_version) != dict(expected_members):
        raise _error(IntegrationReason.PREVIEW_STALE)


def _assert_binary_probe(
    expected: _CodexBinaryProbe,
    *,
    _run: Callable[..., subprocess.CompletedProcess[bytes]],
) -> None:
    current = _probe_codex_binary(
        str(expected.executable_path), codex_home=expected.codex_home, _run=_run
    )
    if current != expected:
        raise _error(IntegrationReason.PREVIEW_STALE)


def _validate_add_result(
    result: Mapping[str, object],
    preview: ActivationPreview,
) -> Path:
    if (
        result.get("pluginId") != _PLUGIN_ID
        or result.get("name") != "yoetz"
        or result.get("marketplaceName") != _MARKETPLACE_NAME
        or result.get("version") != __version__
    ):
        raise _error(IntegrationReason.WRITE_FAILED)
    installed_raw = result.get("installedPath")
    if type(installed_raw) is not str:
        raise _error(IntegrationReason.WRITE_FAILED)
    installed = Path(installed_raw)
    expected = preview.plugin_install_path
    if not installed.is_absolute() or installed != expected:
        raise _error(IntegrationReason.DESTINATION_CONFLICT)
    return installed


def _activated_config_bytes(raw: bytes, config: Mapping[str, object], project: Path) -> bytes:
    relation, source = _marketplace_relation(config, project)
    if relation == "duplicate":
        raise _error(IntegrationReason.PROJECT_CONNECTED_VIA_OTHER_PATH)
    configured, enabled, foreign = _config_state(config, project)
    if foreign:
        raise _error(IntegrationReason.DESTINATION_CONFLICT)
    if configured and enabled:
        return raw
    if relation == "missing":
        # The binding names a project whose manifest is gone, so Codex already fails every plugin
        # command in this home: move the exact Yoetz table to this project instead of adding a
        # second one (#1058).
        raw = _rebind_marketplace(raw, source, project)
        config = cast(Mapping[str, object], tomllib.loads(raw.decode("utf-8")))
    merged = append_table_block(raw, _activation_block(project, config))
    try:
        tomllib.loads(merged.decode("utf-8"))
    except tomllib.TOMLDecodeError as exc:
        # Legal owner TOML such as inline ``marketplaces = {}`` makes the appended
        # table headers re-declarations; refuse at plan time instead of writing a
        # config Codex itself can no longer parse.
        raise _error(IntegrationReason.DESTINATION_CONFLICT) from exc
    return merged


def apply_activation(
    target: IntegrationTarget,
    *,
    approved_digest: str,
    executable_path: str,
    codex_home: Path | str | None = None,
    _run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> ActivationInspection:
    """Apply one exact approved preview, refusing stale or foreign state."""

    binary = _probe_codex_binary(executable_path, codex_home=codex_home, _run=_run)
    if codex_home is not None and _codex_root(codex_home) != binary.codex_home:
        raise _error(IntegrationReason.PREVIEW_STALE)
    with _ActivationLock(target, binary.codex_home):
        plan = _activation_plan(
            target,
            executable_path=executable_path,
            codex_home=codex_home,
            _run=_run,
        )
        preview = plan.preview
        if approved_digest != preview.preview_digest:
            raise _error(IntegrationReason.PREVIEW_STALE)
        _assert_plugin_source(
            target,
            preview.plugin_source_digest,
            plan.cache_members,
            codex_version=plan.binary.codex_version,
        )
        project, _home, marketplace_path, config_path = _paths(target, binary.codex_home)
        marketplace_changed = plan.marketplace_before != preview.marketplace_bytes
        config_changed = plan.config_before != plan.config_after
        if marketplace_changed:
            _assert_plugin_source(
                target,
                preview.plugin_source_digest,
                plan.cache_members,
                codex_version=plan.binary.codex_version,
            )
            _assert_snapshot(marketplace_path, plan.marketplace_before)
            _atomic_write(marketplace_path, preview.marketplace_bytes)
        try:
            if config_changed:
                _assert_plugin_source(
                    target,
                    preview.plugin_source_digest,
                    plan.cache_members,
                    codex_version=plan.binary.codex_version,
                )
                _assert_snapshot(config_path, plan.config_before)
                _atomic_write(config_path, plan.config_after)
            _raw_after, config_after = _load_config(config_path)
            inventory_installed, inventory_version = _plugin_inventory(
                plan.binary, _anchor(config_after, project), _run=_run
            )
            if inventory_installed:
                if inventory_version != __version__ or plan.cache_before is None:
                    raise _error(IntegrationReason.DESTINATION_CONFLICT)
                if plan.cache_before != preview.plugin_install_digest:
                    # Same-version refresh (#388): the approved preview bound the
                    # marker-identified prior render's digest as ``cache_before``.
                    # Replace only those exact bytes; anything else is stale.
                    if (
                        _installed_cache_digest_anchored(
                            binary.codex_home, __version__, plan.cache_members
                        )
                        != plan.cache_before
                    ):
                        raise _error(IntegrationReason.PREVIEW_STALE)
                    _replace_cache_tree(
                        preview.plugin_install_path,
                        plan.cache_members,
                        anchor_root=binary.codex_home,
                    )
                    if (
                        _installed_cache_digest_anchored(
                            binary.codex_home, __version__, plan.cache_members
                        )
                        != preview.plugin_install_digest
                    ):
                        raise _error(IntegrationReason.WRITE_FAILED)
            elif plan.cache_before is not None:
                raise _error(IntegrationReason.DESTINATION_CONFLICT)
            else:
                _assert_plugin_source(
                    target,
                    preview.plugin_source_digest,
                    plan.cache_members,
                    codex_version=plan.binary.codex_version,
                )
                _assert_binary_probe(plan.binary, _run=_run)
                add_result = _run_json_command(
                    plan.binary,
                    preview.install_command,
                    _run=_run,
                    timeout=_PLUGIN_ADD_TIMEOUT_SECONDS,
                )
                cache_created = _validate_add_result(add_result, preview)
                if (
                    _installed_cache_digest_anchored(
                        binary.codex_home, __version__, plan.cache_members
                    )
                    != preview.plugin_install_digest
                ):
                    # ``plugin add`` copies the canonical project source; the
                    # host-specific render belongs to the cache layer (#387).
                    # Seed the exact previewed install bytes over the copied
                    # marker-identified tree.
                    _replace_cache_tree(
                        cache_created,
                        plan.cache_members,
                        anchor_root=binary.codex_home,
                    )
                    if (
                        _installed_cache_digest_anchored(
                            binary.codex_home, __version__, plan.cache_members
                        )
                        != preview.plugin_install_digest
                    ):
                        raise _error(IntegrationReason.WRITE_FAILED)
            _assert_snapshot(config_path, plan.config_after)
            _assert_snapshot(marketplace_path, preview.marketplace_bytes)
            _assert_plugin_source(
                target,
                preview.plugin_source_digest,
                plan.cache_members,
                codex_version=plan.binary.codex_version,
            )
            # Record this project last: the home's shared pieces now serve it (#1058).
            _write_projects(plan.projects_before, plan.projects_after)
        except IntegrationError:
            # Preserve already-approved partial state for an honest retry. Pathname
            # verify-then-rollback cannot exclude a non-cooperating concurrent replacement.
            raise
        inspection = inspect_activation(
            target,
            executable_path=executable_path,
            codex_home=binary.codex_home,
            _run=_run,
        )
        if inspection.state is not ActivationState.ACTIVE:
            raise _error(IntegrationReason.WRITE_FAILED)
    return inspection


@dataclass(frozen=True, slots=True)
class _RemovalPlan:
    preview: RemovalPreview
    marketplace_before: bytes | None
    config_before: bytes | None
    config_after: bytes
    cache_members: Mapping[str, bytes]
    cache_digests: tuple[tuple[str, str], ...]
    binary: _CodexBinaryProbe
    projects_before: ConnectedProjects
    projects_after: tuple[str, ...]
    # The path the home's Yoetz tables name for this project (itself, or an alias of its
    # directory that this removal also clears).
    owned: Path


def _refuse_conflict(candidate: str) -> Never:
    raise _error(IntegrationReason.REMOVE_REFUSED, {"conflict": candidate})


def _expected_marketplace_table(project: Path) -> str:
    return f'[marketplaces.yoetz]\nsource_type = "local"\nsource = {_toml_string(str(project))}\n'


def _canonical_marketplace_bytes() -> bytes:
    return canonical_encode(cast(JsonValue, _marketplace_document())) + b"\n"


def skill_tree_state(target: IntegrationTarget) -> str:
    """Return the packaged skill destination state used by preview, apply, and CLI status."""

    return inspect_destination(target, load_packaged_skill_source()).state.value


def _config_table_plan(
    raw: bytes, config: Mapping[str, object], project: Path
) -> tuple[bool, bool, bytes]:
    """Return ``(plugin_table_owned, marketplace_table_owned, config_after)``.

    A same-named table that is not byte-identical to the yoetz render is a
    conflict, never a candidate for whole-table removal.
    """

    _configured, _enabled, foreign = _config_state(config, project)
    if foreign:
        marketplaces = _table(config, "marketplaces")
        marketplace = None if marketplaces is None else marketplaces.get(_MARKETPLACE_NAME)
        if marketplace is not None:
            _refuse_conflict("config_marketplace")
        _refuse_conflict("config_plugin")
    plugins = _table(config, "plugins")
    plugin = None if plugins is None else plugins.get(_PLUGIN_ID)
    plugin_present = plugin is not None
    plugin_owned = (
        isinstance(plugin, Mapping)
        and dict(cast(Mapping[str, object], plugin)) == {"enabled": True}
        and exact_table_span(raw, _PLUGIN_TABLE) is not None
    )
    if plugin_present and not plugin_owned:
        _refuse_conflict("config_plugin")
    marketplace_table = _expected_marketplace_table(project)
    marketplaces = _table(config, "marketplaces")
    marketplace = None if marketplaces is None else marketplaces.get(_MARKETPLACE_NAME)
    marketplace_present = marketplace is not None
    marketplace_owned = (
        isinstance(marketplace, Mapping)
        and dict(cast(Mapping[str, object], marketplace))
        == {"source_type": "local", "source": str(project)}
        and exact_table_span(raw, marketplace_table) is not None
    )
    if marketplace_present and not marketplace_owned:
        _refuse_conflict("config_marketplace")
    after = raw
    if plugin_owned:
        after = strip_exact_table(after, _PLUGIN_TABLE)
    if marketplace_owned:
        after = strip_exact_table(after, marketplace_table)
    if after != raw:
        try:
            parsed = tomllib.loads(after.decode("utf-8") if after else "")
        except (UnicodeError, tomllib.TOMLDecodeError) as exc:
            raise _error(IntegrationReason.WRITE_FAILED) from exc
        remaining_configured, remaining_enabled, remaining_foreign = _config_state(
            cast(Mapping[str, object], parsed), project
        )
        if remaining_configured or remaining_enabled or remaining_foreign:
            raise _error(IntegrationReason.WRITE_FAILED)
    return plugin_owned, marketplace_owned, after


def _marketplace_json_owned(path: Path) -> bool:
    snapshot = _load_marketplace(path)
    if snapshot is None:
        return False
    raw, document = snapshot
    registered, foreign = _classify_manifest(document)
    if foreign or (registered and raw != _canonical_marketplace_bytes()):
        _refuse_conflict("repository_marketplace")
    return raw == _canonical_marketplace_bytes()


def _managed_cache_versions(
    root: Path,
    expected: Mapping[str, bytes],
    *,
    include_all_managed: bool,
    anchor_root: Path | None = None,
) -> tuple[tuple[str, str], ...]:
    """List yoetz-managed version dirs that this removal may delete.

    Foreign or unexpected members refuse. Other-version managed trees require
    ``--purge-cache`` so default removal cannot delete extra version dirs.
    """

    if anchor_root is not None:
        try:
            relative_root = root.relative_to(anchor_root)
        except ValueError as exc:
            raise _error(IntegrationReason.TARGET_UNSAFE) from exc
        try:
            root_fd = _open_anchored_directory(
                anchor_root,
                relative_root,
                missing_reason=IntegrationReason.PREVIEW_STALE,
            )
        except IntegrationError as exc:
            if exc.reason is IntegrationReason.PREVIEW_STALE:
                return ()
            raise
        try:
            names = _bounded_directory_names(root_fd)
            versions: list[tuple[str, str]] = []
            for name in names:
                if _VERSION_RE.fullmatch(name) is None:
                    _refuse_conflict("cache")
                try:
                    opened = _open_managed_cache_digest_at(
                        root_fd,
                        name,
                        expected,
                        mismatch_reason=IntegrationReason.DESTINATION_CONFLICT,
                    )
                except IntegrationError as exc:
                    if exc.reason is IntegrationReason.DESTINATION_CONFLICT:
                        _refuse_conflict("cache")
                    raise
                if opened is None:
                    _refuse_conflict("cache")
                descriptor, digest, _approved_members = opened
                os.close(descriptor)
                if name == __version__ or include_all_managed:
                    versions.append((name, digest))
                else:
                    _refuse_conflict("cache")
            return tuple(versions)
        finally:
            os.close(root_fd)

    if not root.exists():
        return ()
    if root.is_symlink() or not root.is_dir():
        raise _error(IntegrationReason.TARGET_UNSAFE)
    versions: list[tuple[str, str]] = []
    children: list[Path] = []
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if type(entry.name) is not str or entry.name in {"", ".", ".."}:
                    raise _error(IntegrationReason.TARGET_UNSAFE)
                children.append(root / entry.name)
                if len(children) > _MAX_MANAGED_CACHE_ENTRIES:
                    raise _error(IntegrationReason.PREVIEW_STALE)
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    children.sort(key=lambda path: os.fsencode(path.name))
    if not children:
        return ()
    for child in children:
        if child.is_symlink():
            raise _error(IntegrationReason.TARGET_UNSAFE)
        if not child.is_dir() or _VERSION_RE.fullmatch(child.name) is None:
            _refuse_conflict("cache")
        try:
            digest = _installed_cache_digest(child, expected)
        except IntegrationError as exc:
            if exc.reason is IntegrationReason.DESTINATION_CONFLICT:
                _refuse_conflict("cache")
            raise
        if digest is None:
            _refuse_conflict("cache")
        if child.name == __version__ or include_all_managed:
            versions.append((child.name, digest))
        else:
            _refuse_conflict("cache")
    return tuple(versions)


def _inventory_owned(
    binary: _CodexBinaryProbe,
    project: Path,
    *,
    _run: Callable[..., subprocess.CompletedProcess[bytes]],
) -> bool:
    try:
        installed, _version = _plugin_inventory(binary, project, _run=_run)
    except IntegrationError as exc:
        if exc.reason is IntegrationReason.DESTINATION_CONFLICT:
            _refuse_conflict("inventory")
        raise
    return installed


def _removed_tables_block(plugin_owned: bool, marketplace_owned: bool, project: Path) -> str:
    blocks: list[str] = []
    if marketplace_owned:
        blocks.append(_expected_marketplace_table(project))
    if plugin_owned:
        blocks.append(_PLUGIN_TABLE)
    return "\n".join(blocks)


def _removal_plan(
    target: IntegrationTarget,
    *,
    executable_path: str,
    codex_home: Path | str | None = None,
    purge_cache: bool = False,
    _run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> _RemovalPlan:
    binary = _probe_codex_binary(executable_path, codex_home=codex_home, _run=_run)
    if codex_home is not None and _codex_root(codex_home) != binary.codex_home:
        raise _error(IntegrationReason.PREVIEW_STALE)
    project, home, marketplace_path, config_path = _paths(target, binary.codex_home)
    personal_path = home / _MARKETPLACE_RELATIVE_PATH
    if personal_path != marketplace_path:
        personal_snapshot = _load_marketplace(personal_path)
        personal_document = None if personal_snapshot is None else personal_snapshot[1]
        if _personal_manifest_conflicts(personal_document):
            _refuse_conflict("personal_marketplace")
    marketplace_json_planned = _marketplace_json_owned(marketplace_path)
    marketplace_snapshot = _load_marketplace(marketplace_path)
    marketplace_before = None if marketplace_snapshot is None else marketplace_snapshot[0]
    config_bytes, config = _load_config(config_path)
    config_before = config_bytes if config_path.exists() else None
    relation, source = _marketplace_relation(config, project)
    # Disconnecting a project also removes an entry that names its directory under another path
    # (a symlink, a case variant, the path before a move): that entry is this same project, and
    # removing it is the way out of a ``project_connected_via_other_path`` refusal (#1058).
    owned = Path(source) if relation == "duplicate" else project
    projects_before = _load_projects(home)
    # Other connected projects that can still anchor the home's shared marketplace (#1058).
    candidates = {*projects_before.projects, *((source,) if relation == "shared" else ())}
    remaining = tuple(
        candidate
        for candidate in live_projects(candidates, excluding=project)
        if _anchor_manifest_state(Path(candidate)) == "serves"
    )
    detach = bool(remaining) and relation in {"self", "shared", "duplicate"}
    rebind_to = remaining[0] if detach and relation in {"self", "duplicate"} else None
    cache_members = render_plugin_install_tree(codex_version=binary.codex_version)
    if detach:
        # The shared plugin, its cache, its enable table, and the user-level MCP registration
        # keep serving the remaining projects; only this project's pieces go.
        plugin_table_owned = marketplace_table_owned = inventory_owned = False
        config_after = (
            config_bytes
            if rebind_to is None
            else _rebind_marketplace(config_bytes, source, Path(rebind_to))
        )
        cache_digests: tuple[tuple[str, str], ...] = ()
        projects_after = tuple(
            item
            for item in projects_before.without_project(project)
            if not same_directory(Path(item), project)
        )
    else:
        plugin_table_owned, marketplace_table_owned, config_after = _config_table_plan(
            config_bytes, config, owned
        )
        _validate_descendant_ancestors(home, Path("plugins/cache/yoetz/yoetz"))
        cache_digests = _managed_cache_versions(
            _cache_root(home),
            cache_members,
            include_all_managed=purge_cache,
            anchor_root=home,
        )
        if cache_digests:
            _require_safe_cache_removal_primitives()
        inventory_owned = _inventory_owned(binary, owned, _run=_run)
        # The last connected project's removal leaves no record behind.
        projects_after = ()
    cache_versions = tuple(version for version, _digest in cache_digests)
    inspection = inspect_activation(
        target,
        executable_path=executable_path,
        codex_home=home,
        _run=_run,
    )
    record_changes = projects_before.raw is not None and (
        not projects_after or projects_after != projects_before.projects
    )
    planned = (
        inventory_owned
        or plugin_table_owned
        or marketplace_table_owned
        or marketplace_json_planned
        or bool(cache_versions)
        or record_changes
        or config_after != config_bytes
    )
    outcome = (
        RemovalOutcome.ALREADY_ABSENT
        if not planned
        else RemovalOutcome.DETACH
        if detach
        else RemovalOutcome.REMOVE
    )
    digest_body = (
        b"yoetz.codex-marketplace-removal/1\0"
        + str(project).encode("utf-8")
        + b"\0"
        + str(home).encode("utf-8")
        + b"\0"
        + (b"1" if purge_cache else b"0")
        + b"\0"
        + _sha(b"" if marketplace_before is None else marketplace_before).encode()
        + b"\0"
        + (b"present:" if config_before is not None else b"absent:")
        + _sha(config_bytes).encode()
        + b"\0"
        + (b"1" if inventory_owned else b"0")
        + b"\0"
        + (b"1" if plugin_table_owned else b"0")
        + b"\0"
        + (b"1" if marketplace_table_owned else b"0")
        + b"\0"
        + (b"1" if marketplace_json_planned else b"0")
        + b"\0"
        + canonical_encode(
            [{"version": version, "digest": digest} for version, digest in cache_digests]
        )
        + b"\0"
        + str(binary.executable_path).encode("utf-8")
        + b"\0"
        + binary.executable_digest.encode("ascii")
        + b"\0"
        + binary.codex_version.encode("ascii")
        + b"\0"
        + canonical_encode(["--version"])
        + b"\0"
        + b"temporary_owner_private_home"
        + b"\0"
        + canonical_encode(
            {
                "CODEX_HOME": str(home),
                "CODEX_TESTING_HOME": str(home),
            }
        )
        + b"\0"
        + canonical_encode(list(_PLUGIN_LIST_COMMAND))
        + b"\0"
        + canonical_encode(list(_PLUGIN_REMOVE_COMMAND))
        + b"\0"
        + canonical_encode(list(_MARKETPLACE_REMOVE_COMMAND))
        + b"\0"
        + _sha(b"" if projects_before.raw is None else projects_before.raw).encode()
        + b"\0"
        + canonical_encode(
            {
                "detach": detach,
                "projects_after": list(projects_after),
                "rebind_to": rebind_to,
                "shared_with": list(remaining) if detach else [],
            }
        )
    )
    preview = RemovalPreview(
        _sha(digest_body),
        inspection,
        outcome,
        purge_cache,
        inventory_owned,
        marketplace_table_owned,
        marketplace_json_planned,
        cache_versions,
        cache_digests,
        skill_tree_state(target),
        binary.executable_path,
        binary.executable_digest,
        binary.codex_version,
        home,
        ("--version",),
        _PLUGIN_LIST_COMMAND,
        _PLUGIN_REMOVE_COMMAND,
        _MARKETPLACE_REMOVE_COMMAND,
        "temporary_owner_private_home",
        (("CODEX_HOME", str(home)), ("CODEX_TESTING_HOME", str(home))),
        _sha(b"" if marketplace_before is None else marketplace_before),
        _sha(config_bytes),
        _removed_tables_block(plugin_table_owned, marketplace_table_owned, owned),
        remaining if detach else (),
        rebind_to,
    )
    return _RemovalPlan(
        preview,
        marketplace_before,
        config_before,
        config_after if planned else config_bytes,
        cache_members,
        cache_digests,
        binary,
        projects_before,
        projects_after,
        owned,
    )


def preview_removal(
    target: IntegrationTarget,
    *,
    executable_path: str,
    codex_home: Path | str | None = None,
    purge_cache: bool = False,
    _run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> RemovalPreview:
    """Return the exact proposed removal plan and stale-safe digest."""

    return _removal_plan(
        target,
        executable_path=executable_path,
        codex_home=codex_home,
        purge_cache=purge_cache,
        _run=_run,
    ).preview


def _owned_stat_not_writable(facts: os.stat_result, *, directory: bool) -> None:
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(facts.st_mode):
        raise _error(IntegrationReason.TARGET_UNSAFE)
    if hasattr(os, "geteuid") and facts.st_uid != os.geteuid():
        raise _error(IntegrationReason.TARGET_UNSAFE)
    if facts.st_mode & 0o022:
        raise _error(IntegrationReason.TARGET_UNSAFE)


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_anchored_directory(
    anchor_root: Path,
    relative_directory: Path,
    *,
    missing_reason: IntegrationReason = IntegrationReason.TARGET_UNSAFE,
) -> int:
    """Open one descendant directory without following any path component.

    The returned descriptor is derived from the selected project/home descriptor,
    so swapping an intermediate pathname cannot redirect a later mutation outside
    that authority root.
    """

    if relative_directory.is_absolute() or any(
        part in {"", ".."} for part in relative_directory.parts
    ):
        raise _error(IntegrationReason.TARGET_UNSAFE)
    try:
        current_fd = os.open(anchor_root, _directory_open_flags())
    except FileNotFoundError as exc:
        raise _error(missing_reason) from exc
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    try:
        _owned_stat_not_writable(os.fstat(current_fd), directory=True)
        for part in relative_directory.parts:
            try:
                child_fd = os.open(part, _directory_open_flags(), dir_fd=current_fd)
            except FileNotFoundError as exc:
                raise _error(missing_reason) from exc
            except OSError as exc:
                raise _error(IntegrationReason.TARGET_UNSAFE) from exc
            try:
                _owned_stat_not_writable(os.fstat(child_fd), directory=True)
            except BaseException:
                os.close(child_fd)
                raise
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _require_safe_cache_removal_primitives() -> None:
    required = (os.open, os.rename, os.stat)
    if (
        not getattr(os, "O_NOFOLLOW", 0)
        or any(function not in os.supports_dir_fd for function in required)
        or not getattr(shutil.rmtree, "avoids_symlink_attacks", False)
    ):
        raise _error(IntegrationReason.TARGET_UNSAFE)


def _require_safe_file_removal_primitives() -> None:
    _require_safe_cache_removal_primitives()
    if os.link not in os.supports_dir_fd or os.link not in os.supports_follow_symlinks:
        raise _error(IntegrationReason.TARGET_UNSAFE)


def _bounded_directory_names(directory_fd: int) -> list[str]:
    names: list[str] = []
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                name = entry.name
                if type(name) is not str or name in {"", ".", ".."} or "/" in name:
                    raise _error(IntegrationReason.TARGET_UNSAFE)
                names.append(name)
                if len(names) > _MAX_MANAGED_CACHE_ENTRIES:
                    raise _error(IntegrationReason.PREVIEW_STALE)
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    return sorted(names, key=lambda name: os.fsencode(name))


def _read_managed_tree_fd(root_fd: int) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    file_count = 0
    entry_count = 0
    total_bytes = 0

    def walk(directory_fd: int, prefix: str, depth: int) -> None:
        nonlocal entry_count, file_count, total_bytes
        if depth > _MAX_MANAGED_CACHE_DEPTH:
            raise _error(IntegrationReason.PREVIEW_STALE)
        names = _bounded_directory_names(directory_fd)
        if prefix and not names:
            # The marker/member digest models files, so an empty directory is
            # otherwise invisible at preview but appears during exact deletion.
            raise _error(IntegrationReason.DESTINATION_CONFLICT)
        for name in names:
            entry_count += 1
            if entry_count > _MAX_MANAGED_CACHE_ENTRIES:
                raise _error(IntegrationReason.PREVIEW_STALE)
            relative = name if not prefix else f"{prefix}/{name}"
            if len(os.fsencode(relative)) > _MAX_MANAGED_CACHE_RELATIVE_PATH_BYTES:
                raise _error(IntegrationReason.PREVIEW_STALE)
            try:
                facts = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise _error(IntegrationReason.TARGET_UNSAFE) from exc
            if stat.S_ISDIR(facts.st_mode):
                _owned_stat_not_writable(facts, directory=True)
                try:
                    child_fd = os.open(name, _directory_open_flags(), dir_fd=directory_fd)
                except OSError as exc:
                    raise _error(IntegrationReason.TARGET_UNSAFE) from exc
                try:
                    _owned_stat_not_writable(os.fstat(child_fd), directory=True)
                    walk(child_fd, relative, depth + 1)
                finally:
                    os.close(child_fd)
                continue
            _owned_stat_not_writable(facts, directory=False)
            file_count += 1
            if file_count > _MAX_MANAGED_CACHE_FILES:
                raise _error(IntegrationReason.PREVIEW_STALE)
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(name, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise _error(IntegrationReason.TARGET_UNSAFE) from exc
            try:
                opened_facts = os.fstat(descriptor)
                _owned_stat_not_writable(opened_facts, directory=False)
                if (
                    opened_facts.st_size < 0
                    or opened_facts.st_size > _MAX_MANAGED_CACHE_MEMBER_BYTES
                    or total_bytes + opened_facts.st_size > _MAX_MANAGED_CACHE_TREE_BYTES
                ):
                    raise _error(IntegrationReason.PREVIEW_STALE)
                chunks: list[bytes] = []
                file_bytes = 0
                while chunk := os.read(descriptor, 64 * 1024):
                    file_bytes += len(chunk)
                    if (
                        file_bytes > _MAX_MANAGED_CACHE_MEMBER_BYTES
                        or total_bytes + file_bytes > _MAX_MANAGED_CACHE_TREE_BYTES
                    ):
                        raise _error(IntegrationReason.PREVIEW_STALE)
                    chunks.append(chunk)
                final_facts = os.fstat(descriptor)
                _owned_stat_not_writable(final_facts, directory=False)
                if final_facts.st_size != file_bytes:
                    raise _error(IntegrationReason.PREVIEW_STALE)
                total_bytes += file_bytes
                members[relative] = b"".join(chunks)
            except OSError as exc:
                raise _error(IntegrationReason.TARGET_UNSAFE) from exc
            finally:
                os.close(descriptor)

    walk(root_fd, "", 1)
    return members


def _open_managed_cache_digest_at(
    root_fd: int,
    name: str,
    expected_members: Mapping[str, bytes],
    *,
    mismatch_reason: IntegrationReason = IntegrationReason.PREVIEW_STALE,
) -> tuple[int, str, Mapping[str, bytes]] | None:
    """Open and validate one managed cache tree, retaining its exact directory inode."""

    try:
        descriptor = os.open(name, _directory_open_flags(), dir_fd=root_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    try:
        _owned_stat_not_writable(os.fstat(descriptor), directory=True)
        actual = _read_managed_tree_fd(descriptor)
        if actual != dict(expected_members) and not plugin_tree_matches_marker(actual):
            raise _error(mismatch_reason)
        return descriptor, _members_digest(actual), actual
    except BaseException:
        os.close(descriptor)
        raise


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _expected_child_names(approved_members: Mapping[str, bytes], prefix: str) -> set[str]:
    stem = "" if not prefix else f"{prefix}/"
    children: set[str] = set()
    for relative in approved_members:
        if not relative.startswith(stem):
            continue
        suffix = relative[len(stem) :]
        if suffix:
            children.add(suffix.split("/", maxsplit=1)[0])
    return children


def _read_exact_member(
    descriptor: int,
    expected: bytes,
    *,
    mismatch_reason: IntegrationReason = IntegrationReason.PREVIEW_STALE,
) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(64 * 1024, len(expected) + 1 - total)):
            total += len(chunk)
            if total > len(expected):
                raise _error(mismatch_reason)
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise _error(IntegrationReason.WRITE_FAILED) from exc


def _restore_quarantined_file(
    parent_fd: int,
    name: str,
    quarantine: str,
    quarantined_facts: os.stat_result,
) -> None:
    """Restore one preserved quarantine inode when the approved name is still absent."""

    try:
        current = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise _error(IntegrationReason.WRITE_FAILED) from exc
    if not _same_inode(quarantined_facts, current):
        raise _error(IntegrationReason.WRITE_FAILED)
    # ``link`` is the portable no-clobber primitive here: it fails with EEXIST instead of
    # overwriting a foreign file that appears while restoration is in progress.
    try:
        os.link(
            quarantine,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        restored = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise _error(IntegrationReason.WRITE_FAILED) from exc
    if not _same_inode(quarantined_facts, restored):
        raise _error(IntegrationReason.WRITE_FAILED)
    try:
        current = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_inode(quarantined_facts, current):
            raise _error(IntegrationReason.WRITE_FAILED)
        os.unlink(quarantine, dir_fd=parent_fd)
    except OSError as exc:
        raise _error(IntegrationReason.WRITE_FAILED) from exc


def _remove_exact_managed_file(
    path: Path,
    expected: bytes,
    *,
    mismatch_reason: IntegrationReason,
    anchor_root: Path | None = None,
) -> None:
    """Quarantine and unlink only the exact descriptor-bound approved file inode."""

    if path.name in {"", ".", ".."} or "/" in path.name:
        raise _error(IntegrationReason.TARGET_UNSAFE)
    _require_safe_file_removal_primitives()
    if anchor_root is None:
        try:
            parent_fd = os.open(path.parent, _directory_open_flags())
        except OSError as exc:
            raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    else:
        try:
            relative_parent = path.parent.relative_to(anchor_root)
        except ValueError as exc:
            raise _error(IntegrationReason.TARGET_UNSAFE) from exc
        parent_fd = _open_anchored_directory(anchor_root, relative_parent)
    descriptor: int | None = None
    try:
        _owned_stat_not_writable(os.fstat(parent_fd), directory=True)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        except FileNotFoundError as exc:
            raise _error(mismatch_reason) from exc
        except OSError as exc:
            raise _error(IntegrationReason.TARGET_UNSAFE) from exc
        opened = os.fstat(descriptor)
        _owned_stat_not_writable(opened, directory=False)
        if (
            opened.st_size != len(expected)
            or _read_exact_member(
                descriptor,
                expected,
                mismatch_reason=mismatch_reason,
            )
            != expected
        ):
            raise _error(mismatch_reason)
        try:
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise _error(mismatch_reason) from exc
        if not _same_inode(opened, current):
            raise _error(mismatch_reason)

        quarantine = f".yoetz-file-remove-{os.urandom(8).hex()}"
        try:
            os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise _error(IntegrationReason.WRITE_FAILED) from exc
        else:
            raise _error(IntegrationReason.WRITE_FAILED)
        try:
            os.rename(
                path.name,
                quarantine,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            quarantined = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise _error(IntegrationReason.WRITE_FAILED) from exc
        if not _same_inode(opened, quarantined):
            _restore_quarantined_file(parent_fd, path.name, quarantine, quarantined)
            raise _error(IntegrationReason.WRITE_FAILED)
        if (
            _read_exact_member(
                descriptor,
                expected,
                mismatch_reason=IntegrationReason.WRITE_FAILED,
            )
            != expected
        ):
            _restore_quarantined_file(parent_fd, path.name, quarantine, quarantined)
            raise _error(IntegrationReason.WRITE_FAILED)
        try:
            final = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise _error(IntegrationReason.WRITE_FAILED) from exc
        if not _same_inode(opened, final):
            raise _error(IntegrationReason.WRITE_FAILED)
        try:
            os.unlink(quarantine, dir_fd=parent_fd)
        except OSError as exc:
            raise _error(IntegrationReason.WRITE_FAILED) from exc
        if (
            _read_exact_member(
                descriptor,
                expected,
                mismatch_reason=IntegrationReason.WRITE_FAILED,
            )
            != expected
        ):
            raise _error(IntegrationReason.WRITE_FAILED)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def _remove_managed_tree_contents_fd(
    directory_fd: int,
    approved_members: Mapping[str, bytes],
    *,
    prefix: str = "",
    mutation_state: list[bool],
) -> None:
    """Delete only names and bytes from the exact approved descriptor-bound snapshot."""

    names = _bounded_directory_names(directory_fd)
    if set(names) != _expected_child_names(approved_members, prefix):
        raise _error(IntegrationReason.PREVIEW_STALE)
    for name in names:
        if type(name) is not str or name in {"", ".", ".."} or "/" in name:
            raise _error(IntegrationReason.TARGET_UNSAFE)
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise _error(IntegrationReason.PREVIEW_STALE) from exc
        relative = name if not prefix else f"{prefix}/{name}"
        expected_payload = approved_members.get(relative)
        has_descendants = any(path.startswith(f"{relative}/") for path in approved_members)
        if stat.S_ISDIR(before.st_mode):
            if expected_payload is not None or not has_descendants:
                raise _error(IntegrationReason.PREVIEW_STALE)
            _owned_stat_not_writable(before, directory=True)
            try:
                child_fd = os.open(name, _directory_open_flags(), dir_fd=directory_fd)
            except OSError as exc:
                raise _error(IntegrationReason.PREVIEW_STALE) from exc
            try:
                opened = os.fstat(child_fd)
                _owned_stat_not_writable(opened, directory=True)
                if not _same_inode(before, opened):
                    raise _error(IntegrationReason.PREVIEW_STALE)
                _remove_managed_tree_contents_fd(
                    child_fd,
                    approved_members,
                    prefix=relative,
                    mutation_state=mutation_state,
                )
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not _same_inode(opened, current):
                    raise _error(IntegrationReason.PREVIEW_STALE)
                os.rmdir(name, dir_fd=directory_fd)
                mutation_state[0] = True
            except OSError as exc:
                raise _error(IntegrationReason.WRITE_FAILED) from exc
            finally:
                os.close(child_fd)
            continue
        if expected_payload is None or has_descendants:
            raise _error(IntegrationReason.PREVIEW_STALE)
        _owned_stat_not_writable(before, directory=False)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            member_fd = os.open(name, flags, dir_fd=directory_fd)
        except OSError as exc:
            raise _error(IntegrationReason.PREVIEW_STALE) from exc
        try:
            opened = os.fstat(member_fd)
            _owned_stat_not_writable(opened, directory=False)
            if not _same_inode(before, opened):
                raise _error(IntegrationReason.PREVIEW_STALE)
            if opened.st_size != len(expected_payload):
                raise _error(IntegrationReason.PREVIEW_STALE)
            if _read_exact_member(member_fd, expected_payload) != expected_payload:
                raise _error(IntegrationReason.PREVIEW_STALE)
            final_before_unlink = os.fstat(member_fd)
            if final_before_unlink.st_size != len(expected_payload):
                raise _error(IntegrationReason.PREVIEW_STALE)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not _same_inode(final_before_unlink, current):
                raise _error(IntegrationReason.PREVIEW_STALE)
            os.unlink(name, dir_fd=directory_fd)
            mutation_state[0] = True
            # The unlink has committed. Detect a last-window write through another retained
            # descriptor and report partial mutation instead of claiming a stale preimage.
            if (
                _read_exact_member(
                    member_fd,
                    expected_payload,
                    mismatch_reason=IntegrationReason.WRITE_FAILED,
                )
                != expected_payload
            ):
                raise _error(IntegrationReason.WRITE_FAILED)
        except OSError as exc:
            raise _error(IntegrationReason.WRITE_FAILED) from exc
        finally:
            os.close(member_fd)


def _remove_validated_directory(
    root_fd: int,
    name: str,
    descriptor: int,
    approved_members: Mapping[str, bytes],
) -> None:
    """Remove only the approved tree through its retained descriptor and exact member snapshot."""

    validated = os.fstat(descriptor)
    try:
        current_before = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except OSError as exc:
        raise _error(IntegrationReason.PREVIEW_STALE) from exc
    if not _same_inode(validated, current_before):
        raise _error(IntegrationReason.PREVIEW_STALE)
    if _read_managed_tree_fd(descriptor) != dict(approved_members):
        raise _error(IntegrationReason.PREVIEW_STALE)
    mutation_state = [False]
    try:
        _remove_managed_tree_contents_fd(
            descriptor,
            approved_members,
            mutation_state=mutation_state,
        )
    except IntegrationError as exc:
        # Recursive deletion may already have unlinked an earlier approved member. Once that
        # phase begins, an observable race is a partial write failure, not a stale preimage.
        if mutation_state[0] and exc.reason is not IntegrationReason.WRITE_FAILED:
            raise _error(IntegrationReason.WRITE_FAILED) from exc
        raise
    try:
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except OSError as exc:
        raise _error(IntegrationReason.WRITE_FAILED) from exc
    if not _same_inode(validated, current):
        raise _error(IntegrationReason.WRITE_FAILED)
    try:
        os.rmdir(name, dir_fd=root_fd)
    except OSError as exc:
        raise _error(IntegrationReason.WRITE_FAILED) from exc


def _delete_managed_cache_versions(
    root: Path,
    cache_digests: tuple[tuple[str, str], ...],
    expected_members: Mapping[str, bytes],
    *,
    anchor_root: Path | None = None,
    missing_ok_after_prior_mutation: bool = False,
) -> bool:
    if not cache_digests:
        return False
    _require_safe_cache_removal_primitives()
    if anchor_root is None:
        try:
            root_fd = os.open(root, _directory_open_flags())
        except FileNotFoundError as exc:
            raise _error(IntegrationReason.PREVIEW_STALE) from exc
        except OSError as exc:
            raise _error(IntegrationReason.TARGET_UNSAFE) from exc
    else:
        try:
            relative_root = root.relative_to(anchor_root)
        except ValueError as exc:
            raise _error(IntegrationReason.TARGET_UNSAFE) from exc
        try:
            root_fd = _open_anchored_directory(
                anchor_root,
                relative_root,
                missing_reason=IntegrationReason.PREVIEW_STALE,
            )
        except IntegrationError as exc:
            if missing_ok_after_prior_mutation and exc.reason is IntegrationReason.PREVIEW_STALE:
                return True
            raise
    try:
        _owned_stat_not_writable(os.fstat(root_fd), directory=True)
        cache_mutation_started = False
        for version, expected_digest in cache_digests:
            try:
                opened = _open_managed_cache_digest_at(root_fd, version, expected_members)
            except IntegrationError as exc:
                if cache_mutation_started:
                    raise _error(IntegrationReason.WRITE_FAILED) from exc
                raise
            if opened is None:
                continue
            version_fd, current_digest, approved_members = opened
            if current_digest != expected_digest:
                os.close(version_fd)
                if cache_mutation_started:
                    raise _error(IntegrationReason.WRITE_FAILED)
                raise _error(IntegrationReason.PREVIEW_STALE)
            quarantine = f".yoetz-cache-remove-{os.urandom(8).hex()}"
            try:
                os.rename(
                    version,
                    quarantine,
                    src_dir_fd=root_fd,
                    dst_dir_fd=root_fd,
                )
            except OSError as exc:
                os.close(version_fd)
                raise _error(IntegrationReason.WRITE_FAILED) from exc
            cache_mutation_started = True
            try:
                try:
                    current = os.stat(quarantine, dir_fd=root_fd, follow_symlinks=False)
                except OSError as exc:
                    raise _error(IntegrationReason.WRITE_FAILED) from exc
                if not _same_inode(os.fstat(version_fd), current):
                    raise _error(IntegrationReason.WRITE_FAILED)
                try:
                    _remove_validated_directory(
                        root_fd,
                        quarantine,
                        version_fd,
                        approved_members,
                    )
                except IntegrationError as exc:
                    if exc.reason is IntegrationReason.WRITE_FAILED:
                        raise
                    # No member was deleted: restore the exact retained inode when the original
                    # version name is still absent. `_remove_validated_directory` converts every
                    # error after its first unlink to WRITE_FAILED, so every other reason is an
                    # initial-validation failure eligible for this recovery. A failed restore is
                    # itself an outcome-unknown write.
                    try:
                        quarantine_current = os.stat(
                            quarantine,
                            dir_fd=root_fd,
                            follow_symlinks=False,
                        )
                    except OSError as stat_exc:
                        raise _error(IntegrationReason.WRITE_FAILED) from stat_exc
                    if not _same_inode(os.fstat(version_fd), quarantine_current):
                        raise _error(IntegrationReason.WRITE_FAILED) from exc
                    try:
                        os.stat(version, dir_fd=root_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        try:
                            os.rename(
                                quarantine,
                                version,
                                src_dir_fd=root_fd,
                                dst_dir_fd=root_fd,
                            )
                        except OSError as restore_exc:
                            raise _error(IntegrationReason.WRITE_FAILED) from restore_exc
                    except OSError as restore_exc:
                        raise _error(IntegrationReason.WRITE_FAILED) from restore_exc
                    else:
                        raise _error(IntegrationReason.WRITE_FAILED) from exc
                    raise _error(IntegrationReason.WRITE_FAILED) from exc
            finally:
                os.close(version_fd)
        try:
            remaining = _bounded_directory_names(root_fd)
        except IntegrationError as exc:
            if cache_mutation_started:
                raise _error(IntegrationReason.WRITE_FAILED) from exc
            raise
        if remaining:
            raise _error(IntegrationReason.WRITE_FAILED)
        return cache_mutation_started
    finally:
        os.close(root_fd)


def _assert_yoetz_tables_absent(config_path: Path, project: Path) -> None:
    raw, config = _load_config(config_path)
    configured, enabled, foreign = _config_state(config, project)
    if configured or enabled or foreign:
        raise _error(IntegrationReason.WRITE_FAILED)
    del raw


def apply_removal(
    target: IntegrationTarget,
    *,
    approved_digest: str,
    executable_path: str,
    codex_home: Path | str | None = None,
    purge_cache: bool = False,
    _run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> RemovalResult:
    """Apply one exact approved removal preview, refusing stale or foreign state."""

    binary = _probe_codex_binary(executable_path, codex_home=codex_home, _run=_run)
    if codex_home is not None and _codex_root(codex_home) != binary.codex_home:
        raise _error(IntegrationReason.PREVIEW_STALE)
    with _ActivationLock(target, binary.codex_home):
        plan = _removal_plan(
            target,
            executable_path=executable_path,
            codex_home=codex_home,
            purge_cache=purge_cache,
            _run=_run,
        )
        preview = plan.preview
        if approved_digest != preview.preview_digest:
            raise _error(IntegrationReason.PREVIEW_STALE)
        project, home, marketplace_path, config_path = _paths(target, binary.codex_home)
        if preview.outcome is RemovalOutcome.ALREADY_ABSENT:
            inspection = inspect_activation(
                target,
                executable_path=executable_path,
                codex_home=home,
                _run=_run,
            )
            if inspection.state is ActivationState.ACTIVE:
                raise _error(IntegrationReason.WRITE_FAILED)
            if inspection.state is ActivationState.FOREIGN:
                _refuse_conflict("cache")
            return RemovalResult(
                RemovalOutcome.ALREADY_ABSENT,
                inspection,
                preview.skill_tree_state,
                purge_cache,
            )
        _assert_snapshot(marketplace_path, plan.marketplace_before)
        _assert_snapshot(config_path, plan.config_before)
        _assert_binary_probe(plan.binary, _run=_run)
        if preview.outcome is RemovalOutcome.DETACH:
            return _apply_detach(
                target,
                plan,
                executable_path=executable_path,
                paths=(project, home, marketplace_path, config_path),
                _run=_run,
            )
        mutation_started = False
        if preview.plugin_remove_planned:
            mutation_started = True
            try:
                _run_json_command(
                    plan.binary,
                    preview.plugin_remove_command,
                    _run=_run,
                    timeout=_PLUGIN_ADD_TIMEOUT_SECONDS,
                )
            except Exception as exc:
                if (
                    isinstance(exc, IntegrationError)
                    and exc.reason is IntegrationReason.WRITE_FAILED
                ):
                    raise
                raise _error(IntegrationReason.WRITE_FAILED) from exc
        if preview.marketplace_remove_planned:
            mutation_started = True
            try:
                _run_json_command(
                    plan.binary,
                    preview.marketplace_remove_command,
                    _run=_run,
                    timeout=_PLUGIN_ADD_TIMEOUT_SECONDS,
                )
            except Exception as exc:
                if (
                    isinstance(exc, IntegrationError)
                    and exc.reason is IntegrationReason.WRITE_FAILED
                ):
                    raise
                raise _error(IntegrationReason.WRITE_FAILED) from exc
        try:
            current_config = _current_bytes(config_path)
        except IntegrationError as exc:
            if mutation_started and exc.reason is not IntegrationReason.WRITE_FAILED:
                raise _error(IntegrationReason.WRITE_FAILED) from exc
            raise
        if current_config is None:
            current_config = b""
        try:
            parsed_config = tomllib.loads(current_config.decode("utf-8") if current_config else "")
        except (UnicodeError, tomllib.TOMLDecodeError) as exc:
            if mutation_started:
                raise _error(IntegrationReason.WRITE_FAILED) from exc
            raise _error(IntegrationReason.SOURCE_INVALID) from exc
        try:
            _, _, stripped = _config_table_plan(
                current_config,
                cast(Mapping[str, object], parsed_config),
                plan.owned,
            )
        except IntegrationError as exc:
            if mutation_started:
                # A conflict discovered after the host removal subprocesses have already
                # mutated state is a partial-apply failure, not a pre-mutation refusal/staleness.
                conflict = exc.safe_details.get("conflict")
                details = {"conflict": conflict} if type(conflict) is str else None
                raise _error(IntegrationReason.WRITE_FAILED, details) from exc
            raise
        if stripped != current_config:
            if plan.config_before is None and not stripped:
                if config_path.exists():
                    try:
                        _remove_exact_managed_file(
                            config_path,
                            current_config,
                            mismatch_reason=(
                                IntegrationReason.WRITE_FAILED
                                if mutation_started
                                else IntegrationReason.PREVIEW_STALE
                            ),
                            anchor_root=home,
                        )
                    except IntegrationError as exc:
                        if mutation_started and exc.reason is not IntegrationReason.WRITE_FAILED:
                            raise _error(IntegrationReason.WRITE_FAILED) from exc
                        raise
                    mutation_started = True
            else:
                _atomic_write(config_path, stripped)
                mutation_started = True
        if preview.marketplace_json_planned:
            try:
                _remove_exact_managed_file(
                    marketplace_path,
                    _canonical_marketplace_bytes(),
                    mismatch_reason=(
                        IntegrationReason.WRITE_FAILED
                        if mutation_started
                        else IntegrationReason.PREVIEW_STALE
                    ),
                    anchor_root=project,
                )
            except IntegrationError as exc:
                if mutation_started or exc.reason is IntegrationReason.WRITE_FAILED:
                    raise _error(
                        IntegrationReason.WRITE_FAILED,
                        {"conflict": "repository_marketplace"},
                    ) from exc
                raise
            mutation_started = True
        try:
            cache_mutated = _delete_managed_cache_versions(
                _cache_root(home),
                plan.cache_digests,
                plan.cache_members,
                anchor_root=home,
                missing_ok_after_prior_mutation=mutation_started,
            )
        except IntegrationError as exc:
            if mutation_started and exc.reason is not IntegrationReason.WRITE_FAILED:
                raise _error(IntegrationReason.WRITE_FAILED, {"conflict": "cache"}) from exc
            raise
        mutation_started = mutation_started or cache_mutated
        try:
            installed, _version = _plugin_inventory(plan.binary, project, _run=_run)
            if installed:
                raise _error(IntegrationReason.WRITE_FAILED)
            _assert_yoetz_tables_absent(config_path, project)
            if preview.marketplace_json_planned and marketplace_path.exists():
                raise _error(IntegrationReason.WRITE_FAILED)
            inspection = inspect_activation(
                target,
                executable_path=executable_path,
                codex_home=home,
                _run=_run,
            )
            if inspection.state is ActivationState.ACTIVE:
                raise _error(IntegrationReason.WRITE_FAILED)
            if inspection.state is ActivationState.FOREIGN:
                raise _error(IntegrationReason.WRITE_FAILED)
            skill_state = skill_tree_state(target)
            if skill_state != preview.skill_tree_state:
                raise _error(IntegrationReason.WRITE_FAILED)
            _write_projects(plan.projects_before, plan.projects_after)
        except IntegrationError as exc:
            if mutation_started and exc.reason is not IntegrationReason.WRITE_FAILED:
                conflict = exc.safe_details.get("conflict")
                details = {"conflict": conflict} if type(conflict) is str else None
                raise _error(IntegrationReason.WRITE_FAILED, details) from exc
            raise
    return RemovalResult(RemovalOutcome.REMOVE, inspection, skill_state, purge_cache)


def _apply_detach(
    target: IntegrationTarget,
    plan: _RemovalPlan,
    *,
    executable_path: str,
    paths: tuple[Path, Path, Path, Path],
    _run: Callable[..., subprocess.CompletedProcess[bytes]],
) -> RemovalResult:
    """Remove one project's pieces while other connected projects keep the shared ones (#1058).

    The caller holds the activation lock and already fenced the approved snapshots. The order
    keeps Codex loadable at every step: the binding moves to a remaining project before this
    project's manifest goes, and the record changes last.
    """

    preview = plan.preview
    project, home, marketplace_path, config_path = paths
    mutation_started = False
    try:
        if plan.config_after != (plan.config_before or b""):
            _atomic_write(config_path, plan.config_after)
            mutation_started = True
        if preview.marketplace_json_planned:
            _remove_exact_managed_file(
                marketplace_path,
                _canonical_marketplace_bytes(),
                mismatch_reason=(
                    IntegrationReason.WRITE_FAILED
                    if mutation_started
                    else IntegrationReason.PREVIEW_STALE
                ),
                anchor_root=project,
            )
            mutation_started = True
        _write_projects(plan.projects_before, plan.projects_after)
        mutation_started = True
        inspection = inspect_activation(
            target, executable_path=executable_path, codex_home=home, _run=_run
        )
        if inspection.state in {ActivationState.ACTIVE, ActivationState.FOREIGN}:
            raise _error(IntegrationReason.WRITE_FAILED)
        skill_state = skill_tree_state(target)
        if skill_state != preview.skill_tree_state:
            raise _error(IntegrationReason.WRITE_FAILED)
    except IntegrationError as exc:
        if mutation_started and exc.reason is not IntegrationReason.WRITE_FAILED:
            raise _error(IntegrationReason.WRITE_FAILED) from exc
        raise
    return RemovalResult(RemovalOutcome.DETACH, inspection, skill_state, preview.purge_cache)
