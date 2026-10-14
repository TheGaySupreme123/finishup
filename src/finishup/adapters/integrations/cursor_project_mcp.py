"""Digest-bound, explicit Cursor project MCP configuration lifecycle.

Cursor supplies project roots for project-managed servers. This adapter owns only the exact
``finishup`` entry; it never infers repository authority from a working directory or hook record.

Entries written before the rename sit under the legacy ``yoetz`` key and may carry only the
legacy ``YOETZ_ISOLATED_ROOT`` spelling (ADR-048). An owned legacy entry reads as owned but
outdated; install migrates it in the same preview (write ``finishup``, drop ``yoetz``) and remove
takes both keys. A legacy entry FinishUP cannot prove is its own is reported and never touched.
A FinishUP server elsewhere -- the user configuration or either plugin tree, under either key --
is an external source this adapter reports and never edits, exactly as before the rename.
New entries carry the root under both spellings while the deprecated ``yoetz`` alias ships, so an
older launcher that only reads the legacy name still isolates.
"""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from finishup.adapters.integrations.launcher import valid_launcher
from finishup.adapters.integrations.legacy_launchers import launcher_aliases, recorded_launcher
from finishup.config.foreign_write import project_root_admitted, writable_by_others
from finishup.config.paths import ISOLATED_ROOT_ENV, LEGACY_ISOLATED_ROOT_ENV
from finishup.legacy_names import LAUNCHER_NAMES, LEGACY_MCP_SERVER_NAME, MCP_SERVER_NAME
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)

type Route = Literal["policy", "strict"]
# Owned legacy-key state (ADR-048), with the token vocabulary of ``ports.harness_mcp``.
type LegacyRegistration = Literal["none", "legacy_only", "duplicate", "foreign"]

_MAX_BYTES = 262144
_CURSOR_PROJECT_SELECTOR = "${workspaceFolder}"
# Frozen legacy identifier (ADR-048): the Cursor plugin install marker, read only for the launcher
# a pre-rename native install recorded under its frozen ``yoetz_launcher`` key.
_PLUGIN_MARKER_NAME = ".yoetz-cursor-plugin-install.json"
_PLUGIN_DIRECTORIES = ("finishup", "yoetz")
# Where each inspected configuration document comes from, in ``_Inspection.raws`` order: the
# project file, the user file, the renamed plugin tree, and the Yoetz-era plugin tree (ADR-048).
_SOURCE_NAMES = ("project", "user", "plugin", "plugin")
_REASONS = frozenset(
    {
        "cursor_project_mcp_target_unsafe",
        "cursor_project_mcp_config_invalid",
        "cursor_project_mcp_foreign_present",
        "cursor_project_mcp_multiple_sources",
        "cursor_project_mcp_external_source",
        "cursor_project_mcp_preview_stale",
        "cursor_project_mcp_preview_required",
        "cursor_project_mcp_command_invalid",
        "cursor_project_mcp_launcher_invalid",
        "cursor_project_mcp_write_failed",
        "cursor_project_mcp_platform_unsupported",
    }
)


class CursorProjectMcpError(ValueError):
    """A closed reason token, never host configuration or operating-system error text."""

    def __init__(self, reason: str) -> None:
        self.reason = reason if reason in _REASONS else "cursor_project_mcp_config_invalid"
        super().__init__(self.reason)


@dataclass(frozen=True, slots=True)
class CursorProjectMcpTarget:
    project_root: Path
    cursor_config_root: Path
    project_binding: Literal["mcp-roots", "registered-project"] | None = None


@dataclass(frozen=True, slots=True)
class CursorProjectMcpRegistrationSnapshot:
    """Stable identity of the project registration used by a running Cursor bridge."""

    project_identity: tuple[int, int]
    config_directory_identity: tuple[int, int]
    config_identity: tuple[int, int, int, int, int]
    config_digest: str


def _fail(reason: str) -> CursorProjectMcpError:
    return CursorProjectMcpError("cursor_project_mcp_" + reason)


def _path(path: object) -> None:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise _fail("target_unsafe")
    text = str(path)
    if len(text) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise _fail("target_unsafe")


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _owned(info: os.stat_result) -> None:
    if info.st_uid != os.geteuid() or writable_by_others(info):
        raise _fail("target_unsafe")


def _project(info: os.stat_result) -> None:
    """The project root itself: the running user's, or a root-owned one others cannot replace."""
    if not project_root_admitted(info):
        raise _fail("target_unsafe")


@contextmanager
def _directory(
    path: Path, *, optional: bool = False, project: bool = False
) -> Generator[int | None]:
    """Walk absolute components through pinned descriptors, rejecting every symlink."""
    _path(path)
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise _fail("platform_unsupported")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                )
            except FileNotFoundError:
                if optional:
                    yield None
                    return
                raise _fail("target_unsafe") from None
            os.close(descriptor)
            descriptor = child
        (_project if project else _owned)(os.fstat(descriptor))
        yield descriptor
    except OSError:
        raise _fail("target_unsafe") from None
    finally:
        os.close(descriptor)


def _open_directory_at(parent: int, name: str) -> int | None:
    """Open one pinned child directory, preserving a genuinely absent child."""

    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    except FileNotFoundError:
        return None
    except OSError:
        raise _fail("target_unsafe") from None
    try:
        _owned(os.fstat(descriptor))
        return descriptor
    except CursorProjectMcpError:
        os.close(descriptor)
        raise
    except OSError:
        os.close(descriptor)
        raise _fail("target_unsafe") from None


def _read_at(parent: int, name: str) -> bytes | None:
    observed = _read_at_with_identity(parent, name)
    return None if observed is None else observed[0]


def _read_at_with_identity(
    parent: int, name: str
) -> tuple[bytes, tuple[int, int, int, int, int]] | None:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        return None
    except OSError:
        raise _fail("target_unsafe") from None
    try:
        before = os.fstat(descriptor)
        _owned(before)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise _fail("target_unsafe")
        if before.st_size > _MAX_BYTES:
            raise _fail("config_invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(_MAX_BYTES + 1)
        after = os.fstat(descriptor)
        before_stamp = (*_identity(before), before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        after_stamp = (*_identity(after), after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if (
            before_stamp != after_stamp
            or len(raw) != after.st_size
            or len(raw) > _MAX_BYTES
            or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _identity(after)
        ):
            raise _fail("preview_stale")
        return raw, after_stamp
    except OSError:
        raise _fail("target_unsafe") from None
    finally:
        os.close(descriptor)


def _read(path: Path) -> bytes | None:
    with _directory(path.parent, optional=True) as parent:
        return None if parent is None else _read_at(parent, path.name)


def _directory_identity(path: Path, *, optional: bool = False) -> tuple[int, int] | None:
    """Capture one safe directory identity, preserving an explicitly absent directory."""

    with _directory(path, optional=optional) as descriptor:
        return None if descriptor is None else _identity(os.fstat(descriptor))


def _file_identity(path: Path) -> tuple[int, int, int, int, int] | None:
    """Capture one stable, owner-checked config-file identity without following links."""

    with _directory(path.parent, optional=True) as parent:
        return None if parent is None else _file_identity_at(parent, path.name)


def _file_identity_at(parent: int, name: str) -> tuple[int, int, int, int, int] | None:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent,
        )
    except FileNotFoundError:
        return None
    except OSError:
        raise _fail("target_unsafe") from None
    try:
        facts = os.fstat(descriptor)
        _owned(facts)
        if not stat.S_ISREG(facts.st_mode) or facts.st_nlink != 1:
            raise _fail("target_unsafe")
        return facts.st_dev, facts.st_ino, facts.st_size, facts.st_mtime_ns, facts.st_ctime_ns
    finally:
        os.close(descriptor)


def _canonical_identity(value: tuple[int, ...]) -> list[str]:
    """Encode filesystem identity numbers as bounded canonical text.

    ``st_ino`` and nanosecond timestamps can exceed the protocol's JSON-safe integer range.
    They are used only for local comparison, while the public target digest needs a stable
    canonical representation, so stringify each value before hashing.
    """

    return [str(item) for item in value]


def inspect_project_mcp_registration(
    project_root: Path,
    *,
    launcher: tuple[str, ...],
    route_profile: Route,
    isolation_root: str | None,
    project_binding: Literal["mcp-roots", "registered-project"] = "mcp-roots",
) -> CursorProjectMcpRegistrationSnapshot:
    """Verify the exact project entry and capture its non-content identity for a live bridge.

    This narrow read path deliberately inspects only the opened project's ``.cursor/mcp.json``.
    It keeps the configured project directory separate from its canonical Git repository root;
    the latter is resolved by the MCP bridge's roots/list binding.
    """

    if route_profile not in {"policy", "strict"}:
        raise _fail("command_invalid")
    # Validates the request in its established order before any alias is derived.
    _expected(
        launcher,
        isolation_root,
        route_profile,
        project_root=project_root,
        project_binding=project_binding,
    )
    accepted: list[dict[str, JsonValue]] = []
    # The renamed launcher or its deprecated alias, under any isolation-root spelling (ADR-048).
    for alias in _launcher_aliases(launcher):
        forms = [
            _expected(
                alias,
                isolation_root,
                route_profile,
                project_root=project_root,
                project_binding=project_binding,
            )
        ]
        if project_binding == "mcp-roots":
            forms.append(_expected(alias, isolation_root, route_profile))
        accepted.extend(form for base in forms for form in _environment_forms(base))
    with _directory(project_root, project=True) as project_descriptor:
        assert project_descriptor is not None
        project_identity = _identity(os.fstat(project_descriptor))
    config = project_root / ".cursor" / "mcp.json"
    with _directory(config.parent) as config_directory:
        assert config_directory is not None
        config_directory_identity = _identity(os.fstat(config_directory))
        observed = _read_at_with_identity(config_directory, config.name)
        if observed is None:
            raise _fail("config_invalid")
        raw, config_identity = observed
        document = _document(raw)
        # Either key may hold the entry that launched this bridge (ADR-048).
        if not any(
            _present(document, name) and _entry(document, name) in accepted
            for name in (MCP_SERVER_NAME, LEGACY_MCP_SERVER_NAME)
        ):
            raise _fail("foreign_present")
        if _identity(os.fstat(config_directory)) != config_directory_identity:
            raise _fail("preview_stale")
    with _directory(config.parent) as current_config_directory:
        assert current_config_directory is not None
        if _identity(os.fstat(current_config_directory)) != config_directory_identity:
            raise _fail("preview_stale")
    with _directory(project_root, project=True) as current_project_directory:
        assert current_project_directory is not None
        if _identity(os.fstat(current_project_directory)) != project_identity:
            raise _fail("preview_stale")
    return CursorProjectMcpRegistrationSnapshot(
        project_identity,
        config_directory_identity,
        config_identity,
        _digest(raw),
    )


def _document(raw: bytes | None) -> dict[str, JsonValue]:
    if raw is None:
        return {}
    try:
        parsed = strict_json_parse(raw)
        if not isinstance(parsed, Mapping):
            raise _fail("config_invalid")
        document = dict(parsed)
        if "mcpServers" in document and not isinstance(document["mcpServers"], Mapping):
            raise _fail("config_invalid")
        return document
    except TypeError, ValueError:
        raise _fail("config_invalid") from None


def _entry(document: Mapping[str, JsonValue], name: str = MCP_SERVER_NAME) -> JsonValue:
    servers = document.get("mcpServers", {})
    assert isinstance(servers, Mapping)
    # Null is a same-name foreign entry, not absence.
    return servers.get(name)


def _present(document: Mapping[str, JsonValue], name: str = MCP_SERVER_NAME) -> bool:
    servers = document.get("mcpServers", {})
    assert isinstance(servers, Mapping)
    return name in servers


def _environment_forms(entry: dict[str, JsonValue]) -> tuple[dict[str, JsonValue], ...]:
    """Every isolation-root spelling an owned entry may carry (ADR-048).

    A rendered isolated entry names the root under both spellings. An entry with only the new
    name, or only the legacy ``YOETZ_ISOLATED_ROOT`` an earlier release wrote, binds the same
    root. Two spellings with different values never match: no form here carries them.
    """

    environment = entry.get("env")
    if not isinstance(environment, Mapping):
        return (entry,)
    root = cast(Mapping[str, JsonValue], environment)[ISOLATED_ROOT_ENV]
    return (
        entry,
        {**entry, "env": {ISOLATED_ROOT_ENV: root}},
        {**entry, "env": {LEGACY_ISOLATED_ROOT_ENV: root}},
    )


def _launcher_aliases(launcher: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    """The launcher and the deprecated alias of the same installation (ADR-048)."""

    if not valid_launcher(launcher):
        raise _fail("launcher_invalid")
    return launcher_aliases(launcher)


def recorded_cursor_launchers(cursor_config_root: Path) -> tuple[tuple[str, ...], ...]:
    """Launchers the native Cursor plugin markers recorded, under either plugin name (ADR-048).

    A project entry rendered by an earlier install names the launcher of that installation,
    which an upgrade may have moved. The plugin marker written in the same guided connection
    records it under the frozen ``yoetz_launcher`` key; a self-consistent marker whose launcher
    names a FinishUP launcher is the ownership proof. Unreadable markers prove nothing.
    """

    recorded: list[tuple[str, ...]] = []
    for directory in _PLUGIN_DIRECTORIES:
        path = cursor_config_root / "plugins" / "local" / directory / _PLUGIN_MARKER_NAME
        try:
            raw = _read(path)
            marker = None if raw is None else strict_json_parse(raw)
        except CursorProjectMcpError, TypeError, ValueError:
            continue
        if not isinstance(marker, Mapping):
            continue
        body = {key: value for key, value in marker.items() if key != "marker_digest"}
        if marker.get("marker_digest") != canonical_digest(body):
            continue
        # Frozen legacy identifier (ADR-048): the marker key every release writes.
        launcher = recorded_launcher(marker.get("yoetz_launcher"))
        if launcher is not None and launcher not in recorded:
            recorded.append(launcher)
    return tuple(recorded)


def _expected(
    launcher: tuple[str, ...],
    root: str | None,
    route: Route,
    *,
    project_selector: bool = True,
    project_root: Path | None = None,
    project_binding: Literal["mcp-roots", "registered-project"] = "mcp-roots",
) -> dict[str, JsonValue]:
    if project_binding not in {"mcp-roots", "registered-project"} or (
        project_binding == "registered-project" and (project_root is None or not project_selector)
    ):
        raise _fail("command_invalid")
    if not valid_launcher(launcher):
        raise _fail("launcher_invalid")
    if root is not None:
        if type(root) is not str or str(Path(root)) != root or "\x00" in root:
            raise _fail("target_unsafe")
        with _directory(Path(root)):
            pass
    args: list[JsonValue] = [*launcher[1:], "mcp", "serve", "--host", "cursor"]
    if project_selector:
        if project_root is not None:
            _path(project_root)
        args.extend(
            (
                "--project-root",
                _CURSOR_PROJECT_SELECTOR if project_root is None else str(project_root),
            )
        )
    if project_binding == "registered-project":
        args.extend(("--project-binding", project_binding))
    if route == "strict":
        args.extend(("--semantic", "off"))
    entry: dict[str, JsonValue] = {"type": "stdio", "command": launcher[0], "args": args}
    if root is not None:
        # Both spellings with one value while the deprecated ``yoetz`` alias ships (ADR-048).
        entry["env"] = {ISOLATED_ROOT_ENV: root, LEGACY_ISOLATED_ROOT_ENV: root}
    return entry


def _digest(raw: bytes | None) -> str:
    return (
        canonical_digest({"absent": True})
        if raw is None
        else "sha256:" + hashlib.sha256(raw).hexdigest()
    )


@dataclass(frozen=True, slots=True)
class _Inspection:
    raws: tuple[bytes | None, ...]
    project_identity: tuple[int, int]
    project_config_directory_identity: tuple[int, int] | None
    config_identities: tuple[tuple[int, int, int, int, int] | None, ...]
    config_identity_digest: str
    document: dict[str, JsonValue]
    target_identity: str
    state: str
    source: str
    route: Route | None
    project_binding: Literal["mcp-roots", "registered-project"] | None
    legacy_registration: LegacyRegistration = "none"
    # Whether the project file's own legacy ``yoetz`` key is FinishUP's: the only legacy entry
    # this adapter migrates or removes (ADR-048).
    project_legacy_owned: bool = False


def _owned_forms(
    launchers: tuple[tuple[str, ...], ...], root: str | None, project_root: Path
) -> dict[Route, list[tuple[dict[str, JsonValue], Literal["mcp-roots", "registered-project"]]]]:
    """Every entry shape FinishUP wrote for this project, per route, with its project binding."""

    forms: dict[
        Route, list[tuple[dict[str, JsonValue], Literal["mcp-roots", "registered-project"]]]
    ] = {"policy": [], "strict": []}
    for launcher in launchers:
        for route in ("policy", "strict"):
            bases: tuple[
                tuple[dict[str, JsonValue], Literal["mcp-roots", "registered-project"]], ...
            ] = (
                (_expected(launcher, root, route, project_root=project_root), "mcp-roots"),
                (
                    _expected(
                        launcher,
                        root,
                        route,
                        project_root=project_root,
                        project_binding="registered-project",
                    ),
                    "registered-project",
                ),
                (_expected(launcher, root, route), "mcp-roots"),
                # Entries written before the explicit project selector remain safe to recognize
                # as FinishUP's own project source so the next preview can upgrade them in place.
                # They never get emitted again, and foreign/user/plugin sources remain untouched.
                (_expected(launcher, root, route, project_selector=False), "mcp-roots"),
            )
            forms[route].extend(
                (form, binding) for base, binding in bases for form in _environment_forms(base)
            )
    return forms


def _classify(
    entry: JsonValue,
    forms: Mapping[
        Route, list[tuple[dict[str, JsonValue], Literal["mcp-roots", "registered-project"]]]
    ],
) -> tuple[Route, Literal["mcp-roots", "registered-project"]] | None:
    for route in ("policy", "strict"):
        for form, binding in forms[route]:
            if entry == form:
                return route, binding
    return None


def _launches_finishup(entry: JsonValue, launchers: tuple[tuple[str, ...], ...]) -> bool:
    """Whether a user or plugin entry serves FinishUP's MCP through a provable launcher.

    Those sources are never this adapter's to edit, so their exact shape does not matter: an
    entry that runs ``mcp serve`` through a bare ``finishup``/``yoetz`` script or one of
    ``launchers`` is a FinishUP server registered elsewhere (ADR-048). Anything else under the
    legacy key no longer shares FinishUP's name.
    """

    if not isinstance(entry, Mapping):
        return False
    typed = cast(Mapping[str, JsonValue], entry)
    command = typed.get("command")
    raw_args = typed.get("args")
    if type(command) is not str or not isinstance(raw_args, list):
        return False
    args = tuple(cast(list[JsonValue], raw_args))
    prefixes = [launcher[1:] for launcher in launchers if launcher[0] == command]
    if command in LAUNCHER_NAMES:
        prefixes.append(())
    return any(
        args[: len(prefix)] == prefix and args[len(prefix) : len(prefix) + 2] == ("mcp", "serve")
        for prefix in prefixes
    )


def _inspect(
    target: CursorProjectMcpTarget,
    launcher: tuple[str, ...],
    root: str | None,
    known_launchers: tuple[tuple[str, ...], ...] = (),
) -> _Inspection:
    # Validates the launcher and root before any filesystem read.
    _expected(launcher, root, "policy", project_root=target.project_root)
    identities: list[JsonValue] = []
    project_identity: tuple[int, int] | None = None
    for path in (target.project_root, target.cursor_config_root):
        # The project root is judged by the project rule, as on the write path; the Cursor
        # configuration root stays the running user's own.
        with _directory(
            path,
            optional=path == target.cursor_config_root,
            project=path == target.project_root,
        ) as descriptor:
            if descriptor is None:
                identities.append([str(path), None])
                continue
            identity = _identity(os.fstat(descriptor))
            identities.append([str(path), *_canonical_identity(identity)])
            if path == target.project_root:
                project_identity = identity
    assert project_identity is not None
    project_config_directory_identity = _directory_identity(
        target.project_root / ".cursor", optional=True
    )
    paths = (
        target.project_root / ".cursor" / "mcp.json",
        target.cursor_config_root / "mcp.json",
        # The Yoetz-era plugin tree serves FinishUP until it is migrated (ADR-048).
        *(
            target.cursor_config_root / "plugins" / "local" / directory / "mcp.json"
            for directory in _PLUGIN_DIRECTORIES
        ),
    )
    raws = tuple(_read(path) for path in paths)
    config_identities = tuple(_file_identity(path) for path in paths)
    config_identity_values: list[JsonValue] = [
        None
        if project_config_directory_identity is None
        else cast(JsonValue, _canonical_identity(project_config_directory_identity))
    ]
    config_identity_values.extend(
        None if item is None else cast(JsonValue, _canonical_identity(item))
        for item in config_identities
    )
    config_identity_digest = canonical_digest(config_identity_values)
    documents = tuple(_document(raw) for raw in raws)
    launchers = tuple(
        dict.fromkeys(
            (
                *_launcher_aliases(launcher),
                *recorded_cursor_launchers(target.cursor_config_root),
                *(item for item in known_launchers if recorded_launcher(list(item)) is not None),
            )
        )
    )
    forms = _owned_forms(launchers, root, target.project_root)

    def elsewhere(document: Mapping[str, JsonValue]) -> bool:
        # A user or plugin source serves FinishUP under the new key (whatever it holds, as
        # before the rename) or under the legacy key through a provable launcher (ADR-048).
        return _present(document) or (
            _present(document, LEGACY_MCP_SERVER_NAME)
            and _launches_finishup(_entry(document, LEGACY_MCP_SERVER_NAME), launchers)
        )

    # The legacy ``yoetz`` key across every source (ADR-048). Only the project file's is this
    # adapter's to migrate; an owned one elsewhere is reported through the external state below.
    legacy_classified: tuple[Route, Literal["mcp-roots", "registered-project"]] | None = None
    if _present(documents[0], LEGACY_MCP_SERVER_NAME):
        legacy_classified = _classify(_entry(documents[0], LEGACY_MCP_SERVER_NAME), forms)
    # The project file serves FinishUP under the new key, or under the legacy key through an
    # owned route: both count as a project source, as the same entry did before the rename.
    present = [
        index
        for index, document in enumerate(documents)
        if (
            _present(document) or legacy_classified is not None
            if index == 0
            else elsewhere(document)
        )
    ]
    source = _SOURCE_NAMES[present[0]] if len(present) == 1 else "none"
    route: Route | None = None
    binding: Literal["mcp-roots", "registered-project"] | None = None
    if not present:
        state = "absent"
    elif len(present) > 1:
        state = "multiple_sources"
    elif source != "project":
        state = "external_source"
    else:
        # A project file holding only an owned legacy entry is owned but outdated (ADR-048).
        classified = (
            _classify(_entry(documents[0]), forms) if _present(documents[0]) else legacy_classified
        )
        # Frozen legacy identifier (ADR-048): ``yoetz_owned`` is the released state wire value.
        state = "foreign_present" if classified is None else "yoetz_owned"
        if classified is not None:
            route, binding = classified
    legacy_present = any(_present(document, LEGACY_MCP_SERVER_NAME) for document in documents)
    legacy_owned = legacy_classified is not None or any(
        _present(document, LEGACY_MCP_SERVER_NAME)
        and _launches_finishup(_entry(document, LEGACY_MCP_SERVER_NAME), launchers)
        for document in documents[1:]
    )
    current = (
        _present(documents[0]) and _classify(_entry(documents[0]), forms) is not None
    ) or any(_present(document) for document in documents[1:])
    legacy: LegacyRegistration = (
        "none"
        if not legacy_present
        else "foreign"
        if not legacy_owned
        else "duplicate"
        if current
        else "legacy_only"
    )
    return _Inspection(
        raws,
        project_identity,
        project_config_directory_identity,
        config_identities,
        config_identity_digest,
        documents[0],
        canonical_digest(identities),
        state,
        source,
        route,
        binding,
        legacy,
        legacy_classified is not None,
    )


def _legacy_warnings(legacy: LegacyRegistration) -> list[JsonValue]:
    if legacy in {"legacy_only", "duplicate"}:
        return ["legacy_registration_owned"]
    return ["legacy_registration_foreign"] if legacy == "foreign" else []


def status_cursor_project_mcp(
    target: CursorProjectMcpTarget,
    *,
    launcher: tuple[str, ...],
    isolation_root: str | None,
    known_launchers: tuple[tuple[str, ...], ...] = (),
) -> dict[str, JsonValue]:
    """Read the project registration; ``known_launchers`` adds marker-recorded proofs."""

    observed = _inspect(target, launcher, isolation_root, known_launchers)
    return {
        "ok": True,
        "state": observed.state,
        "source": observed.source,
        "route_profile": observed.route,
        "project_binding": observed.project_binding,
        "legacy_registration": observed.legacy_registration,
        "target_identity": observed.target_identity,
        "host_trust": "unknown",
        "runtime_binding": "unobserved",
    }


def _plan(
    target: CursorProjectMcpTarget,
    action: str,
    launcher: tuple[str, ...],
    route_profile: Route | None,
    isolation_root: str | None,
    known_launchers: tuple[tuple[str, ...], ...] = (),
) -> tuple[dict[str, JsonValue], _Inspection, bytes | None]:
    if action not in {"install", "remove"} or route_profile not in {None, "policy", "strict"}:
        raise _fail("command_invalid")
    if target.project_binding not in {None, "mcp-roots", "registered-project"}:
        raise _fail("command_invalid")
    observed = _inspect(target, launcher, isolation_root, known_launchers)
    remove_legacy_beside_foreign = (
        action == "remove" and observed.state == "foreign_present" and observed.project_legacy_owned
    )
    if observed.state not in {"absent", "yoetz_owned"} and not remove_legacy_beside_foreign:
        raise _fail(observed.state)
    route = route_profile or observed.route or "policy"
    binding = target.project_binding or observed.project_binding or "mcp-roots"
    document = dict(observed.document)
    servers = dict(cast(Mapping[str, JsonValue], document.get("mcpServers", {})))
    replacement = observed.raws[0]
    mutation = "noop"
    legacy_owned = observed.project_legacy_owned
    if action == "remove":
        if observed.state == "yoetz_owned" or remove_legacy_beside_foreign:
            # Remove takes owned entries under both keys (ADR-048).
            if observed.state == "yoetz_owned":
                servers.pop(MCP_SERVER_NAME, None)
            if legacy_owned:
                del servers[LEGACY_MCP_SERVER_NAME]
            mutation = "unregister"
    else:
        entry = _expected(
            launcher,
            isolation_root,
            route,
            project_root=target.project_root,
            project_binding=binding,
        )
        if legacy_owned:
            # Migrate the owned legacy entry in this same preview (ADR-048).
            del servers[LEGACY_MCP_SERVER_NAME]
            mutation = "reregister"
        if servers.get(MCP_SERVER_NAME) != entry:
            servers[MCP_SERVER_NAME] = entry
            mutation = "register" if observed.state == "absent" else "reregister"
    if mutation != "noop":
        document["mcpServers"] = servers
        replacement = canonical_encode(document) + b"\n"
        if len(replacement) > _MAX_BYTES:
            raise _fail("config_invalid")
    body: dict[str, JsonValue] = {
        "ok": True,
        "action": mutation,
        "operation": action,
        "state_before": observed.state,
        "source": observed.source,
        "route_profile": route if action == "install" else observed.route,
        "project_binding": binding if action == "install" else observed.project_binding,
        "project_root": str(target.project_root),
        "target_identity": observed.target_identity,
        "config_identity_digest": observed.config_identity_digest,
        "launcher": list(launcher),
        "isolated_root": isolation_root,
        "config_digest_before": _digest(observed.raws[0]),
        "config_digest_after": _digest(replacement),
        "source_digests": [_digest(raw) for raw in observed.raws],
        "legacy_registration": observed.legacy_registration,
        "warnings": [
            "host_config_not_compare_and_swap",
            "host_restart_required",
            *_legacy_warnings(observed.legacy_registration),
            *(["foreign_entry_present"] if remove_legacy_beside_foreign else []),
        ],
    }
    body["preview_digest"] = canonical_digest(body)
    return body, observed, replacement


def preview_cursor_project_mcp(
    target: CursorProjectMcpTarget,
    *,
    action: str,
    launcher: tuple[str, ...],
    route_profile: Route | None,
    isolation_root: str | None,
    known_launchers: tuple[tuple[str, ...], ...] = (),
) -> dict[str, JsonValue]:
    """Plan one install or remove.

    ``known_launchers`` are marker-recorded launchers a caller captured before a step that may
    migrate the marker away (ADR-048); they are accepted only when they name a FinishUP
    launcher, and the same tuple must reach the matching apply.
    """

    return _plan(target, action, launcher, route_profile, isolation_root, known_launchers)[0]


def _write(
    target: CursorProjectMcpTarget,
    before: bytes | None,
    after: bytes,
    *,
    project_identity: tuple[int, int],
    project_config_directory_identity: tuple[int, int] | None,
) -> None:
    """Pinned-parent atomic replacement with a final preimage check; no host-wide CAS claim."""
    with _directory(target.project_root, project=True) as root:
        assert root is not None
        if _identity(os.fstat(root)) != project_identity:
            raise _fail("preview_stale")
        descriptor: int | None = _open_directory_at(root, ".cursor")
        if descriptor is None:
            if project_config_directory_identity is not None:
                raise _fail("preview_stale")
            try:
                os.mkdir(".cursor", 0o700, dir_fd=root)
            except FileExistsError:
                raise _fail("preview_stale") from None
            except OSError:
                raise _fail("target_unsafe") from None
            descriptor = _open_directory_at(root, ".cursor")
            if descriptor is None:
                raise _fail("preview_stale")
        elif project_config_directory_identity is None or (
            _identity(os.fstat(descriptor)) != project_config_directory_identity
        ):
            os.close(descriptor)
            raise _fail("preview_stale")
        temporary: str | None = ".finishup-mcp-" + uuid.uuid4().hex
        try:
            _owned(os.fstat(descriptor))
            if _read_at(descriptor, "mcp.json") != before:
                raise _fail("preview_stale")
            output = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=descriptor,
            )
            with os.fdopen(output, "wb") as stream:
                stream.write(after)
                stream.flush()
                os.fsync(stream.fileno())
            with _directory(target.project_root / ".cursor") as current:
                assert current is not None
                if (
                    _identity(os.fstat(root)) != project_identity
                    or _identity(os.fstat(descriptor)) != _identity(os.fstat(current))
                    or _read_at(descriptor, "mcp.json") != before
                ):
                    raise _fail("preview_stale")
                os.replace(temporary, "mcp.json", src_dir_fd=descriptor, dst_dir_fd=descriptor)
                os.fsync(descriptor)
        finally:
            try:
                os.unlink(temporary, dir_fd=descriptor)
            except FileNotFoundError:
                pass
            os.close(descriptor)


def apply_cursor_project_mcp(
    target: CursorProjectMcpTarget,
    *,
    action: str,
    launcher: tuple[str, ...],
    route_profile: Route | None,
    isolation_root: str | None,
    preview_digest: str,
    accept: bool,
    known_launchers: tuple[tuple[str, ...], ...] = (),
) -> dict[str, JsonValue]:
    if accept is not True:
        raise _fail("preview_required")
    body, observed, replacement = _plan(
        target, action, launcher, route_profile, isolation_root, known_launchers
    )
    if preview_digest != body["preview_digest"]:
        raise _fail("preview_stale")
    if body["action"] != "noop":
        assert replacement is not None
        # Recheck every known source immediately before the project-file effect.
        if _inspect(target, launcher, isolation_root, known_launchers) != observed:
            raise _fail("preview_stale")
        try:
            _write(
                target,
                observed.raws[0],
                replacement,
                project_identity=observed.project_identity,
                project_config_directory_identity=observed.project_config_directory_identity,
            )
        except OSError:
            raise _fail("write_failed") from None
    try:
        after = _inspect(target, launcher, isolation_root, known_launchers)
    except CursorProjectMcpError:
        raise _fail("write_failed") from None
    expected_state = (
        "foreign_present"
        if action == "remove" and observed.state == "foreign_present"
        else "absent"
        if action == "remove"
        else "yoetz_owned"
    )
    if (
        after.raws[0] != replacement
        or after.state != expected_state
        # A migrated or removed legacy entry must be gone; a foreign one stays untouched.
        or (body["action"] != "noop" and after.project_legacy_owned)
        or after.target_identity != observed.target_identity
        or (
            action == "install"
            and (
                after.source != "project"
                or after.route != body["route_profile"]
                or after.project_binding != body["project_binding"]
            )
        )
    ):
        raise _fail("write_failed")
    return {
        **body,
        "state_after": after.state,
        "host_trust": "unknown",
        "runtime_binding": "unobserved",
    }
