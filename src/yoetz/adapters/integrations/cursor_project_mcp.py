"""Digest-bound, explicit Cursor project MCP configuration lifecycle.

Cursor supplies project roots for project-managed servers. This adapter owns only the exact
``yoetz`` entry; it never infers repository authority from a working directory or hook record.
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

from yoetz.adapters.integrations.launcher import valid_launcher
from yoetz.config.foreign_write import writable_by_others
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)

type Route = Literal["policy", "strict"]

_MAX_BYTES = 262144
_CURSOR_PROJECT_SELECTOR = "${workspaceFolder}"
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


@contextmanager
def _directory(path: Path, *, optional: bool = False) -> Generator[int | None]:
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
        _owned(os.fstat(descriptor))
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
    expected = _expected(
        launcher,
        isolation_root,
        route_profile,
        project_root=project_root,
        project_binding=project_binding,
    )
    legacy_selector = _expected(launcher, isolation_root, route_profile)
    with _directory(project_root) as project_descriptor:
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
        if not _present(document) or _entry(document) not in (
            (expected, legacy_selector) if project_binding == "mcp-roots" else (expected,)
        ):
            raise _fail("foreign_present")
        if _identity(os.fstat(config_directory)) != config_directory_identity:
            raise _fail("preview_stale")
    with _directory(config.parent) as current_config_directory:
        assert current_config_directory is not None
        if _identity(os.fstat(current_config_directory)) != config_directory_identity:
            raise _fail("preview_stale")
    with _directory(project_root) as current_project_directory:
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


def _entry(document: Mapping[str, JsonValue]) -> JsonValue:
    servers = document.get("mcpServers", {})
    assert isinstance(servers, Mapping)
    # Null is a same-name foreign entry, not absence.
    return servers.get("yoetz")


def _present(document: Mapping[str, JsonValue]) -> bool:
    servers = document.get("mcpServers", {})
    assert isinstance(servers, Mapping)
    return "yoetz" in servers


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
        entry["env"] = {"YOETZ_ISOLATED_ROOT": root}
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


def _inspect(
    target: CursorProjectMcpTarget, launcher: tuple[str, ...], root: str | None
) -> _Inspection:
    policy = _expected(launcher, root, "policy", project_root=target.project_root)
    strict = _expected(launcher, root, "strict", project_root=target.project_root)
    cli_policy = _expected(
        launcher,
        root,
        "policy",
        project_root=target.project_root,
        project_binding="registered-project",
    )
    cli_strict = _expected(
        launcher,
        root,
        "strict",
        project_root=target.project_root,
        project_binding="registered-project",
    )
    placeholder_policy = _expected(launcher, root, "policy")
    placeholder_strict = _expected(launcher, root, "strict")
    # Entries written before the explicit project selector remain safe to recognize as Yoetz's
    # own project source so the next preview can upgrade them in place.  They never get emitted
    # again, and foreign/user/plugin sources remain untouched.
    legacy_policy = _expected(launcher, root, "policy", project_selector=False)
    legacy_strict = _expected(launcher, root, "strict", project_selector=False)
    identities: list[JsonValue] = []
    project_identity: tuple[int, int] | None = None
    for path in (target.project_root, target.cursor_config_root):
        with _directory(path, optional=path == target.cursor_config_root) as descriptor:
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
    raws = tuple(
        _read(path)
        for path in (
            target.project_root / ".cursor" / "mcp.json",
            target.cursor_config_root / "mcp.json",
            target.cursor_config_root / "plugins" / "local" / "yoetz" / "mcp.json",
        )
    )
    config_identities = tuple(
        _file_identity(path)
        for path in (
            target.project_root / ".cursor" / "mcp.json",
            target.cursor_config_root / "mcp.json",
            target.cursor_config_root / "plugins" / "local" / "yoetz" / "mcp.json",
        )
    )
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
    present = [i for i, document in enumerate(documents) if _present(document)]
    source = ("project", "user", "plugin")[present[0]] if len(present) == 1 else "none"
    route: Route | None = None
    binding: Literal["mcp-roots", "registered-project"] | None = None
    if not present:
        state = "absent"
    elif len(present) > 1:
        state = "multiple_sources"
    elif source != "project":
        state = "external_source"
    else:
        entry = _entry(documents[0])
        route = (
            "policy"
            if entry in (policy, placeholder_policy, legacy_policy, cli_policy)
            else "strict"
            if entry in (strict, placeholder_strict, legacy_strict, cli_strict)
            else None
        )
        state = "yoetz_owned" if route is not None else "foreign_present"
        if route is not None:
            binding = "registered-project" if entry in (cli_policy, cli_strict) else "mcp-roots"
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
    )


def status_cursor_project_mcp(
    target: CursorProjectMcpTarget,
    *,
    launcher: tuple[str, ...],
    isolation_root: str | None,
) -> dict[str, JsonValue]:
    observed = _inspect(target, launcher, isolation_root)
    return {
        "ok": True,
        "state": observed.state,
        "source": observed.source,
        "route_profile": observed.route,
        "project_binding": observed.project_binding,
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
) -> tuple[dict[str, JsonValue], _Inspection, bytes | None]:
    if action not in {"install", "remove"} or route_profile not in {None, "policy", "strict"}:
        raise _fail("command_invalid")
    if target.project_binding not in {None, "mcp-roots", "registered-project"}:
        raise _fail("command_invalid")
    observed = _inspect(target, launcher, isolation_root)
    if observed.state not in {"absent", "yoetz_owned"}:
        raise _fail(observed.state)
    route = route_profile or observed.route or "policy"
    binding = target.project_binding or observed.project_binding or "mcp-roots"
    document = dict(observed.document)
    servers = dict(cast(Mapping[str, JsonValue], document.get("mcpServers", {})))
    replacement = observed.raws[0]
    mutation = "noop"
    if action == "remove":
        if observed.state == "yoetz_owned":
            del servers["yoetz"]
            mutation = "unregister"
    else:
        entry = _expected(
            launcher,
            isolation_root,
            route,
            project_root=target.project_root,
            project_binding=binding,
        )
        if servers.get("yoetz") != entry:
            servers["yoetz"] = entry
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
        "warnings": ["host_config_not_compare_and_swap", "host_restart_required"],
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
) -> dict[str, JsonValue]:
    return _plan(target, action, launcher, route_profile, isolation_root)[0]


def _write(
    target: CursorProjectMcpTarget,
    before: bytes | None,
    after: bytes,
    *,
    project_identity: tuple[int, int],
    project_config_directory_identity: tuple[int, int] | None,
) -> None:
    """Pinned-parent atomic replacement with a final preimage check; no host-wide CAS claim."""
    with _directory(target.project_root) as root:
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
        temporary: str | None = ".yoetz-mcp-" + uuid.uuid4().hex
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
) -> dict[str, JsonValue]:
    if accept is not True:
        raise _fail("preview_required")
    body, observed, replacement = _plan(target, action, launcher, route_profile, isolation_root)
    if preview_digest != body["preview_digest"]:
        raise _fail("preview_stale")
    if body["action"] != "noop":
        assert replacement is not None
        # Recheck every known source immediately before the project-file effect.
        if _inspect(target, launcher, isolation_root) != observed:
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
        after = _inspect(target, launcher, isolation_root)
    except CursorProjectMcpError:
        raise _fail("write_failed") from None
    expected_state = "absent" if action == "remove" else "yoetz_owned"
    if (
        after.raws[0] != replacement
        or after.state != expected_state
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
