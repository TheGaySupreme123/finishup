"""Host auto-review admission for the owner-authorized AI-powered ``check`` (issue #467).

Claude Code auto mode, Codex ``approvals_reviewer = "auto_review"``, and Cursor Auto-review each
route FinishUP's policy-route ``check`` through a model reviewer that refuses "data to a destination
the user did not name". The owner *did* name it, in the trusted ``finishup --privacy`` ceremony, but
nothing about that grant is visible to a host reviewer. This adapter writes each host's own
project-scoped admission entry for exactly ``check`` so the host's rule layer admits the call
before its reviewer runs — the mirror image of the ADR-018 strict ceiling: the owner's trusted
decision, never the agent and never a self-approving hook, tells the host to admit the call.

Rules shared by every host surface:

- Only ``check`` is admitted by this adapter. The other operations have local or read-only
  effects, but host invocation policies remain independent and may hold them.
- An entry is recognized by exact bytes. A wider rule (a server-wide allow, a wildcard, a Codex
  server-level default) or a deny rule for the same tool is ``foreign``: reported, never edited,
  and never a reason to write beside it.
- An unreadable, oversized, symlinked, or unparseable host file is ``unknown``, never ``absent``.
- Grant is previewed and digest-bound, and the digest binds the exact host file bytes it read.
- Revoke and sweep remove only the exact entries FinishUP writes and nothing else in the file.
- Grant writes only the ``finishup`` server-name forms. The exact entries Yoetz 0.1-0.2 wrote
  for the legacy ``yoetz`` server name are reported (``legacy_entries``) and never written: a
  stale one would admit a later, unrelated server that takes the old name (ADR-048). Revoke and
  sweep remove them with the FinishUP forms. Grant removes them too, without touching the
  FinishUP grant, once the caller observed that no FinishUP registration still serves the old
  name; it refuses while the host serves FinishUP only under that name, because a ``finishup``
  entry would then admit nothing.
- Admission is host tool-call authorization. It does not prove dispatch, widen FinishUP policy, or
  bypass any privacy, disclosure, credential, or dispatch gate.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Final, Literal, cast

from finishup.config.foreign_write import (
    project_root_admitted,
    superuser_owned,
    writable_by_others,
)
from finishup.protocol.canonical import (
    JsonValue,
    ProtocolValueError,
    canonical_digest,
    strict_json_parse,
)

from .toml_tables import append_table_block, exact_table_span, strip_exact_table

__all__ = [
    "ADMISSION_HOSTS",
    "CLAUDE_CHECK_TOOL_NAME",
    "CLAUDE_EXTERNAL_CHECK_TOOL_NAME",
    "CLAUDE_PLUGIN_CHECK_TOOL_NAME",
    "CODEX_EXTERNAL_ADMISSION_TABLE",
    "CODEX_LEGACY_PLUGIN_ADMISSION_HEADER",
    "CODEX_PLUGIN_ADMISSION_TABLE",
    "CURSOR_CLI_EXTERNAL_ENTRY",
    "CURSOR_CLI_PLUGIN_ENTRY",
    "CURSOR_IDE_ENTRY",
    "HostAdmissionAction",
    "HostAdmissionEntry",
    "HostAdmissionError",
    "HostAdmissionHost",
    "HostAdmissionObservation",
    "HostAdmissionPreview",
    "HostAdmissionReason",
    "HostAdmissionResult",
    "HostAdmissionState",
    "HostAdmissionSweep",
    "LegacyNameUse",
    "McpOwnerForm",
    "admission_surfaces",
    "apply_host_admission",
    "observe_host_admission",
    "preview_host_admission",
    "sweep_host_admission",
]

type HostAdmissionHost = Literal["claude", "codex", "cursor"]
type McpOwnerForm = Literal["external", "plugin"]
# How the host uses the legacy ``yoetz`` server name, as the caller observed it (ADR-048):
# ``serving`` (FinishUP is served only under it), ``shared`` (a FinishUP-owned registration or
# install still uses it beside the ``finishup`` one), ``unused`` (nothing FinishUP owns does).
type LegacyNameUse = Literal["serving", "shared", "unused"]
_LEGACY_NAME_USES: Final = frozenset({"serving", "shared", "unused"})

ADMISSION_HOSTS: Final[tuple[HostAdmissionHost, ...]] = ("claude", "codex", "cursor")

# Claude Code: `permissions.allow` resolves before the auto-mode classifier and is honored from
# `.claude/settings.local.json` at the repository root. Allow rules take a literal
# `mcp__<server>__` prefix. A normal registration uses the configured key `finishup`; a plugin-owned
# server is scoped by Claude as `plugin_finishup_finishup`.
CLAUDE_EXTERNAL_CHECK_TOOL_NAME: Final = "mcp__finishup__check"
CLAUDE_PLUGIN_CHECK_TOOL_NAME: Final = "mcp__plugin_finishup_finishup__check"
# Compatibility name retained for the plugin-rendered hook and older callers.
CLAUDE_CHECK_TOOL_NAME: Final = CLAUDE_PLUGIN_CHECK_TOOL_NAME
_CLAUDE_CHECK_TOOL_NAMES: Final = frozenset(
    {CLAUDE_EXTERNAL_CHECK_TOOL_NAME, CLAUDE_PLUGIN_CHECK_TOOL_NAME}
)
_CLAUDE_SURFACE: Final = ".claude/settings.local.json"
_CLAUDE_WIDER_RULES: Final = frozenset(
    {
        "mcp__finishup",
        "mcp__finishup__*",
        "mcp__finishup__check*",
        "mcp__plugin_finishup_finishup",
        "mcp__plugin_finishup_finishup__*",
        "mcp__plugin_finishup_finishup__check*",
    }
)

# Codex: under `approval_mode = auto` a policy-route `check` (`openWorldHint: true`) always needs
# approval, and `approvals_reviewer = "auto_review"` sends it to the guardian. A per-tool
# `approval_mode = "approve"` means the reviewer is never invoked for that tool. Project-scoped
# `.codex/config.toml` layers are loaded only for trusted projects and `mcp_servers` is not on
# the project-layer denylist (openai/codex `loader/mod.rs`, read 2026-08-30).
_CODEX_SURFACE: Final = ".codex/config.toml"
CODEX_EXTERNAL_ADMISSION_TABLE: Final = (
    '[mcp_servers.finishup.tools.check]\napproval_mode = "approve"\n'
)
CODEX_PLUGIN_ADMISSION_TABLE: Final = (
    '[plugins."finishup@finishup".mcp_servers.finishup.tools.check]\napproval_mode = "approve"\n'
)

# Cursor: `mcpAllowlist` in `<workspace>/.cursor/permissions.json` admits `server:tool` without
# human review under Auto-review (server name = the `mcp.json` key). The Agent CLI reads
# `permissions.allow` from `<project>/.cursor/cli.json` and names a plugin-bundled server
# `plugin-<plugin>-<server>` (live-verified 2026-08-29, issue #468 cell).
_CURSOR_IDE_SURFACE: Final = ".cursor/permissions.json"
_CURSOR_CLI_SURFACE: Final = ".cursor/cli.json"
CURSOR_IDE_ENTRY: Final = "finishup:check"
CURSOR_CLI_EXTERNAL_ENTRY: Final = "Mcp(finishup:check)"
CURSOR_CLI_PLUGIN_ENTRY: Final = "Mcp(plugin-finishup-finishup:check)"
_CURSOR_IDE_WIDER: Final = frozenset({"finishup:*", "*:check", "*:*", "plugin-finishup-finishup:*"})
_CURSOR_CLI_WIDER: Final = frozenset(
    {"Mcp(finishup:*)", "Mcp(*:check)", "Mcp(*:*)", "Mcp(plugin-finishup-finishup:*)"}
)

# Frozen legacy identifier (ADR-048): the exact admission entries Yoetz 0.1-0.2 wrote for the
# legacy ``yoetz`` server name, per host. Recognized and removed; never written.
_CLAUDE_LEGACY_ENTRIES: Final = frozenset({"mcp__yoetz__check", "mcp__plugin_yoetz_yoetz__check"})
_CODEX_LEGACY_TABLES: Final = (
    '[mcp_servers.yoetz.tools.check]\napproval_mode = "approve"\n',
    '[plugins."yoetz@yoetz".mcp_servers.yoetz.tools.check]\napproval_mode = "approve"\n',
)
# The legacy entry that admits the Yoetz-era plugin's ``check``, as ``legacy_entries`` names it.
CODEX_LEGACY_PLUGIN_ADMISSION_HEADER: Final = _CODEX_LEGACY_TABLES[1].splitlines()[0]
_CURSOR_IDE_LEGACY_ENTRIES: Final = frozenset({"yoetz:check"})
_CURSOR_CLI_LEGACY_ENTRIES: Final = frozenset({"Mcp(yoetz:check)", "Mcp(plugin-yoetz-yoetz:check)"})

_MAX_FILE_BYTES: Final = 262_144
# Frozen legacy identifier (ADR-048): the preview tag family keeps its namespace.
_PREVIEW_SCHEMA: Final = "yoetz.host-admission-preview/1"


class HostAdmissionState(str, Enum):  # noqa: UP042 - exact public token
    ABSENT = "absent"
    PRESENT = "present"
    # Only for a host with more than one surface: some, not all, carry the entry.
    PARTIAL = "partial"
    FOREIGN = "foreign"
    UNKNOWN = "unknown"


class HostAdmissionAction(str, Enum):  # noqa: UP042 - exact public token
    GRANT = "grant"
    REVOKE = "revoke"
    NOOP = "noop"


class HostAdmissionReason(str, Enum):  # noqa: UP042 - exact public token
    CONFIRMATION_REQUIRED = "confirmation_required"
    PREVIEW_STALE = "preview_stale"
    FOREIGN_ENTRY_PRESENT = "foreign_entry_present"
    ENTRY_UNREADABLE = "entry_unreadable"
    ROUTE_NOT_POLICY = "route_not_policy"
    ROUTE_UNOBSERVED = "route_unobserved"
    CODEX_BINARY_INCONSISTENT = "codex_binary_inconsistent"
    GRANT_NOT_PERMITTING = "grant_not_permitting"
    GRANT_UNVERIFIABLE = "grant_unverifiable"
    # The host serves FinishUP only under the legacy ``yoetz`` name; integrate migrates it first.
    LEGACY_REGISTRATION_ACTIVE = "legacy_registration_active"
    OWNER_REQUIRED = "owner_required"
    TARGET_UNSAFE = "target_unsafe"
    WRITE_FAILED = "write_failed"
    HOST_INVALID = "host_invalid"


class HostAdmissionError(Exception):
    """Typed refusal; never carries file contents or paths."""

    def __init__(self, reason: HostAdmissionReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class HostAdmissionEntry:
    """One host surface: the exact entry FinishUP recognizes there and what was observed."""

    surface: str
    state: HostAdmissionState
    entry: str
    detail: str | None = None
    file_digest: str | None = None
    # Exact pre-rename entries for the legacy ``yoetz`` server name still on this surface
    # (ADR-048). FinishUP never needs them; revoke and sweep remove them.
    legacy_entries: tuple[str, ...] = ()

    def as_json(self) -> dict[str, JsonValue]:
        body: dict[str, JsonValue] = {
            "detail": self.detail,
            "entry": self.entry,
            "file_digest": self.file_digest,
            "state": self.state.value,
            "surface": self.surface,
        }
        if self.legacy_entries:
            body["legacy_entries"] = list(self.legacy_entries)
        return body


@dataclass(frozen=True, slots=True)
class HostAdmissionObservation:
    host: HostAdmissionHost
    state: HostAdmissionState
    entries: tuple[HostAdmissionEntry, ...]

    @property
    def observed(self) -> bool:
        return self.state is not HostAdmissionState.UNKNOWN

    @property
    def legacy_entries_present(self) -> bool:
        """A stale pre-rename admission for the legacy ``yoetz`` server name remains (ADR-048)."""

        return any(entry.legacy_entries for entry in self.entries)

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "entries": [entry.as_json() for entry in self.entries],
            "host": self.host,
            "legacy_entries_present": self.legacy_entries_present,
            "observed": self.observed,
            "state": self.state.value,
        }


@dataclass(frozen=True, slots=True)
class HostAdmissionPreview:
    host: HostAdmissionHost
    action: HostAdmissionAction
    state_before: HostAdmissionState
    entries: tuple[HostAdmissionEntry, ...]
    route_profile: str | None
    grant_permits: bool | None
    owner: McpOwnerForm | None
    checkpoint: bool
    preview_digest: str
    warnings: tuple[str, ...]
    _requested_action: HostAdmissionAction = field(repr=False, compare=False)
    files_after: Mapping[str, bytes] = field(repr=False, compare=False)
    legacy_name: LegacyNameUse | None = None

    @property
    def requested_action(self) -> HostAdmissionAction:
        """The requested transition retained when the public effective action is ``noop``."""

        return self._requested_action

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "action": self.action.value,
            "checkpoint": self.checkpoint,
            "entries": [entry.as_json() for entry in self.entries],
            "grant_permits": self.grant_permits,
            "host": self.host,
            "owner": self.owner,
            "preview_digest": self.preview_digest,
            "route_profile": self.route_profile,
            "state_before": self.state_before.value,
            "surfaces_changed": cast(list[JsonValue], sorted(self.files_after)),
            "warnings": cast(list[JsonValue], list(self.warnings)),
        }


@dataclass(frozen=True, slots=True)
class HostAdmissionResult:
    host: HostAdmissionHost
    action: HostAdmissionAction
    state_before: HostAdmissionState
    state_after: HostAdmissionState
    surfaces_changed: tuple[str, ...]

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "action": self.action.value,
            "host": self.host,
            "state_after": self.state_after.value,
            "state_before": self.state_before.value,
            "surfaces_changed": list(self.surfaces_changed),
        }


@dataclass(frozen=True, slots=True)
class HostAdmissionSweep:
    """Outcome of one reverse transition on one host."""

    host: HostAdmissionHost
    outcome: Literal["removed", "absent", "retained_foreign", "unknown", "write_failed"]
    surfaces_changed: tuple[str, ...] = ()

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "host": self.host,
            "outcome": self.outcome,
            "surfaces_changed": list(self.surfaces_changed),
        }


def admission_surfaces(host: HostAdmissionHost) -> tuple[str, ...]:
    """Project-relative host files this adapter may read and edit for ``host``."""

    if host == "claude":
        return (_CLAUDE_SURFACE,)
    if host == "codex":
        return (_CODEX_SURFACE,)
    if host == "cursor":
        return (_CURSOR_IDE_SURFACE, _CURSOR_CLI_SURFACE)
    raise HostAdmissionError(HostAdmissionReason.HOST_INVALID)


# --- file reading -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Read:
    raw: bytes | None
    problem: str | None

    @property
    def digest(self) -> str | None:
        if self.raw is None:
            return None
        return f"sha256:{hashlib.sha256(self.raw).hexdigest()}"


def _validated_root(project_root: Path) -> Path:
    """The project root, judged by the shared project-root rule (ADR-007, 2026-10-14).

    That is the running user's own directory no other account can write or, for a non-root
    user, a root-owned one that no other account can write or that is sticky. A link, a
    non-directory and any other owner are refused.
    """

    if not project_root.is_absolute():
        raise HostAdmissionError(HostAdmissionReason.TARGET_UNSAFE)
    try:
        facts = project_root.lstat()
    except OSError as exc:
        raise HostAdmissionError(HostAdmissionReason.TARGET_UNSAFE) from exc
    if not project_root_admitted(facts):
        raise HostAdmissionError(HostAdmissionReason.TARGET_UNSAFE)
    return project_root


_DIRECTORY_FLAGS: Final = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_READ_FLAGS: Final = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


def _host_folder_readable(facts: os.stat_result) -> bool:
    """Whether a host folder's contents can be read as this user's admission.

    The running user's own folder no other account can write, or one root made that no other
    account can write (a committed ``.claude`` in an image built as root): root is already trusted
    with everything the user runs. A folder another non-root account made, or one others can
    write (a sticky project root lets any account create ``.claude`` first), is not.
    """

    if writable_by_others(facts):
        return False
    return not hasattr(os, "geteuid") or facts.st_uid == os.geteuid() or superuser_owned(facts)


def _host_folder_writable(facts: os.stat_result) -> bool:
    """Whether FinishUP may write into a host folder: only the running user's own, unshared."""

    if writable_by_others(facts):
        return False
    return not hasattr(os, "geteuid") or facts.st_uid == os.geteuid()


def _read_at(folder: int, name: str) -> _Read:
    """Read one bounded regular file in a pinned folder without following a link.

    Host configuration writers do not share a lock with FinishUP. Retaining one descriptor and
    comparing its before/after metadata prevents a replace or in-place write during this read from
    being accepted as a coherent preimage. Apply performs another read immediately before its
    mutation; the remaining final syscall window is disclosed separately.
    """

    try:
        descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=folder)
    except FileNotFoundError:
        return _Read(None, None)
    except OSError as exc:
        return _Read(None, "file_symlink" if exc.errno == errno.ELOOP else "file_unreadable")
    try:
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if stat.S_ISLNK(before.st_mode):
                return _Read(None, "file_symlink")
            if not stat.S_ISREG(before.st_mode):
                return _Read(None, "file_not_regular")
            if before.st_size > _MAX_FILE_BYTES:
                return _Read(None, "file_too_large")
            raw = handle.read(_MAX_FILE_BYTES + 1)
            after = os.fstat(handle.fileno())
        if len(raw) > _MAX_FILE_BYTES:
            return _Read(None, "file_too_large")
        before_snapshot = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_snapshot = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_snapshot != after_snapshot or len(raw) != after.st_size:
            return _Read(None, "file_unreadable")
        return _Read(raw, None)
    except OSError:
        return _Read(None, "file_unreadable")


def _open_folder(path: Path) -> int | None:
    """Pin one existing host folder by descriptor without following a link; None when absent."""

    try:
        return os.open(path, _DIRECTORY_FLAGS)
    except FileNotFoundError:
        return None


def _read(path: Path) -> _Read:
    """Read ``<root>/<host folder>/<file>`` through the pinned host folder.

    A linked folder is ``file_symlink``, as is a linked file. A folder whose contents cannot be
    read as this user's admission (``_host_folder_readable``) is ``folder_not_owned``, so status
    never reports an admission another account could have written.
    """

    try:
        folder = _open_folder(path.parent)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            try:
                linked = path.parent.is_symlink()
            except OSError:
                linked = False
            return _Read(None, "file_symlink" if linked else "file_unreadable")
        return _Read(None, "file_unreadable")
    if folder is None:
        return _Read(None, None)
    try:
        if not _host_folder_readable(os.fstat(folder)):
            return _Read(None, "folder_not_owned")
        return _read_at(folder, path.name)
    except OSError:
        return _Read(None, "file_unreadable")
    finally:
        os.close(folder)


def _unknown(surface: str, entry: str, problem: str) -> HostAdmissionEntry:
    return HostAdmissionEntry(surface, HostAdmissionState.UNKNOWN, entry, problem, None)


# --- JSON list surfaces (Claude, Cursor) -------------------------------------------------


def _json_object(read: _Read) -> tuple[dict[str, JsonValue] | None, str | None]:
    """Parse a host JSON file to a mutable object, or name why it cannot be trusted."""

    if read.problem is not None:
        return None, read.problem
    if read.raw is None:
        return {}, None
    try:
        parsed = strict_json_parse(read.raw)
    except ProtocolValueError:
        return None, "file_invalid"
    if not isinstance(parsed, Mapping):
        return None, "shape_invalid"
    return dict(cast(Mapping[str, JsonValue], parsed)), None


def _string_list(container: Mapping[str, JsonValue], key: str) -> tuple[list[str] | None, bool]:
    """Return ``(list, shape_ok)``; an absent key is an empty list."""

    if key not in container:
        return [], True
    value = container[key]
    if not isinstance(value, list) or not all(type(item) is str for item in value):
        return None, False
    return [cast(str, item) for item in value], True


def _observe_string_list_surface(
    *,
    surface: str,
    read: _Read,
    container_key: str | None,
    allow_key: str,
    deny_key: str | None,
    ask_key: str | None,
    entries: frozenset[str],
    wider: frozenset[str],
    case_insensitive: bool,
    legacy: frozenset[str] = frozenset(),
) -> HostAdmissionEntry:
    """Classify one JSON allow-list surface against the exact FinishUP entries.

    Exact ``legacy`` entries in the allow or ask list are reported beside the classification;
    they never change it, because they admit a different server name (ADR-048).
    """

    expected = sorted(entries)[0]
    parsed, problem = _json_object(read)
    if parsed is None:
        return _unknown(surface, expected, problem or "file_unreadable")
    container: Mapping[str, JsonValue] = parsed
    if container_key is not None:
        if container_key not in parsed:
            nested = {}
        else:
            nested = parsed[container_key]
        if not isinstance(nested, Mapping):
            return _unknown(surface, expected, "shape_invalid")
        container = cast(Mapping[str, JsonValue], nested)

    def fold(value: str) -> str:
        return value.casefold() if case_insensitive else value

    folded_entries = {fold(item) for item in entries}
    folded_wider = {fold(item) for item in wider}
    allow, allow_ok = _string_list(container, allow_key)
    if not allow_ok or allow is None:
        return _unknown(surface, expected, "shape_invalid")
    deny: list[str] = []
    if deny_key is not None:
        deny_value, deny_ok = _string_list(container, deny_key)
        if not deny_ok or deny_value is None:
            return _unknown(surface, expected, "shape_invalid")
        deny = deny_value
    ask: list[str] = []
    if ask_key is not None:
        ask_value, ask_ok = _string_list(container, ask_key)
        if not ask_ok or ask_value is None:
            return _unknown(surface, expected, "shape_invalid")
        ask = ask_value
    digest = read.digest
    folded_legacy = {fold(item) for item in legacy}
    legacy_present = tuple(sorted({item for item in (*allow, *ask) if fold(item) in folded_legacy}))

    def classified(state: HostAdmissionState, entry: str, detail: str | None) -> HostAdmissionEntry:
        return HostAdmissionEntry(surface, state, entry, detail, digest, legacy_present)

    if any(fold(item) in folded_entries or fold(item) in folded_wider for item in deny):
        return classified(HostAdmissionState.FOREIGN, expected, "deny_rule_present")
    if any(fold(item) in folded_wider for item in (*allow, *ask)):
        return classified(HostAdmissionState.FOREIGN, expected, "wider_rule_present")
    present_allow = [item for item in allow if fold(item) in folded_entries]
    present_ask = [item for item in ask if fold(item) in folded_entries]
    if {fold(item) for item in present_allow} & {fold(item) for item in present_ask}:
        return classified(HostAdmissionState.FOREIGN, expected, "allow_and_ask_present")
    if present_allow:
        return classified(HostAdmissionState.PRESENT, present_allow[0], "allow")
    if present_ask:
        return classified(HostAdmissionState.PRESENT, present_ask[0], "ask")
    return classified(HostAdmissionState.ABSENT, expected, None)


def _json_with_list_entry(
    read: _Read,
    *,
    container_key: str | None,
    list_key: str,
    entry: str,
    add: bool,
    remove_entries: frozenset[str] = frozenset(),
    case_insensitive: bool = False,
) -> bytes | None:
    """Return the file bytes with ``entry`` added to or removed from one list, else ``None``.

    ``None`` means no byte would change. Every other key, and the order of every other list
    member, is preserved. The file is re-encoded with two-space indentation, the shape the hosts
    themselves write.
    """

    parsed, problem = _json_object(read)
    if parsed is None or problem is not None:
        raise HostAdmissionError(HostAdmissionReason.ENTRY_UNREADABLE)
    container: dict[str, JsonValue] = parsed
    if container_key is not None:
        if container_key not in parsed:
            nested = {}
            parsed[container_key] = nested
        else:
            nested = parsed[container_key]
        if not isinstance(nested, dict):
            raise HostAdmissionError(HostAdmissionReason.ENTRY_UNREADABLE)
        container = nested
    current, ok = _string_list(container, list_key)
    if not ok or current is None:
        raise HostAdmissionError(HostAdmissionReason.ENTRY_UNREADABLE)

    def fold(value: str) -> str:
        return value.casefold() if case_insensitive else value

    if add:
        if any(fold(item) == fold(entry) for item in current):
            return None
        container[list_key] = cast(list[JsonValue], [*current, entry])
    else:
        targets = {fold(item) for item in remove_entries or {entry}}
        kept = [item for item in current if fold(item) not in targets]
        if len(kept) == len(current):
            return None
        if kept:
            container[list_key] = cast(list[JsonValue], kept)
        else:
            del container[list_key]
        if container_key is not None and not container:
            del parsed[container_key]
        if not parsed:
            # Nothing but the FinishUP entry was ever in this file; removal restores "no file".
            return b""
    return (json.dumps(parsed, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


# --- Codex TOML surface -------------------------------------------------------------------


def _table_get(table: object, key: str) -> object | None:
    if not isinstance(table, Mapping):
        return None
    return cast(Mapping[str, object], table).get(key)


def _toml_path(root: Mapping[str, object], *keys: str) -> object | None:
    current: object | None = root
    for key in keys:
        current = _table_get(current, key)
        if current is None:
            return None
    return current


def _observe_codex(read: _Read, owner: McpOwnerForm | None) -> HostAdmissionEntry:
    surface = _CODEX_SURFACE
    expected = _codex_table(owner)
    if read.problem is not None:
        return _unknown(surface, expected, read.problem)
    if read.raw is None:
        return HostAdmissionEntry(surface, HostAdmissionState.ABSENT, expected, None, None)
    try:
        parsed = tomllib.loads(read.raw.decode("utf-8"))
    except UnicodeError, tomllib.TOMLDecodeError:
        return _unknown(surface, expected, "file_invalid")
    digest = read.digest
    legacy = _codex_legacy_tables(read.raw, parsed)

    def classified(state: HostAdmissionState, detail: str | None) -> HostAdmissionEntry:
        return HostAdmissionEntry(surface, state, expected, detail, digest, legacy)

    forms: dict[McpOwnerForm, tuple[str, tuple[str, ...]]] = {
        "external": (CODEX_EXTERNAL_ADMISSION_TABLE, ("mcp_servers", "finishup")),
        "plugin": (
            CODEX_PLUGIN_ADMISSION_TABLE,
            ("plugins", "finishup@finishup", "mcp_servers", "finishup"),
        ),
    }
    present: list[McpOwnerForm] = []
    for form, (table, server_keys) in forms.items():
        server = _toml_path(parsed, *server_keys)
        if server is None:
            continue
        if not isinstance(server, Mapping):
            return classified(HostAdmissionState.FOREIGN, "entry_not_exact")
        server_map = cast(Mapping[str, object], server)
        if server_map.get("default_tools_approval_mode") is not None:
            # A server-wide default admits every tool; wider than FinishUP ever writes.
            return classified(HostAdmissionState.FOREIGN, "server_default_present")
        check = _toml_path(server_map, "tools", "check")
        if check is None:
            continue
        if not isinstance(check, Mapping) or exact_table_span(read.raw, table) is None:
            return classified(HostAdmissionState.FOREIGN, "entry_not_exact")
        present.append(form)
    if not present:
        return classified(HostAdmissionState.ABSENT, None)
    if owner is not None and owner not in present:
        # An exact table for the inactive owner is FinishUP-shaped but does not admit the active
        # route. Report the applicable entry absent so grant appends the owner-selected form.
        return classified(HostAdmissionState.ABSENT, f"inactive_{present[0]}_entry_present")
    detail = "both" if len(present) == 2 else present[0]
    return classified(HostAdmissionState.PRESENT, detail)


def _codex_legacy_tables(raw: bytes, parsed: Mapping[str, object]) -> tuple[str, ...]:
    """Exact legacy ``yoetz`` admission tables on the Codex surface, by header (ADR-048)."""

    found: list[str] = []
    for table, keys in zip(
        _CODEX_LEGACY_TABLES,
        (
            ("mcp_servers", "yoetz", "tools", "check"),
            ("plugins", "yoetz@yoetz", "mcp_servers", "yoetz", "tools", "check"),
        ),
        strict=True,
    ):
        check = _toml_path(parsed, *keys)
        if (
            isinstance(check, Mapping)
            and dict(cast(Mapping[str, object], check)) == {"approval_mode": "approve"}
            and exact_table_span(raw, table) is not None
        ):
            found.append(table.splitlines()[0])
    return tuple(sorted(found))


def _codex_table(owner: McpOwnerForm | None) -> str:
    return CODEX_PLUGIN_ADMISSION_TABLE if owner == "plugin" else CODEX_EXTERNAL_ADMISSION_TABLE


def _codex_after(read: _Read, *, add: bool, owner: McpOwnerForm | None) -> bytes | None:
    if read.problem is not None:
        raise HostAdmissionError(HostAdmissionReason.ENTRY_UNREADABLE)
    raw = read.raw or b""
    if add:
        table = _codex_table(owner)
        if exact_table_span(raw, table) is not None:
            return None
        merged = append_table_block(raw, table)
        try:
            tomllib.loads(merged.decode("utf-8"))
        except (UnicodeError, tomllib.TOMLDecodeError) as exc:
            # Legal owner TOML (an inline ``mcp_servers = {}``) can make the appended header a
            # re-declaration; refuse at plan time rather than write a file Codex cannot parse.
            raise HostAdmissionError(HostAdmissionReason.FOREIGN_ENTRY_PRESENT) from exc
        return merged
    after = raw
    tables = (
        (_codex_table(owner),)
        if owner is not None
        else (CODEX_EXTERNAL_ADMISSION_TABLE, CODEX_PLUGIN_ADMISSION_TABLE)
    )
    for table in tables:
        after = strip_exact_table(after, table)
    if owner is None:
        # An ownership-independent revoke also takes the exact legacy tables (ADR-048).
        for table in _CODEX_LEGACY_TABLES:
            after = strip_exact_table(after, table)
    return None if after == raw else after


# --- observation --------------------------------------------------------------------------


def _aggregate(entries: Sequence[HostAdmissionEntry]) -> HostAdmissionState:
    states = [entry.state for entry in entries]
    if any(state is HostAdmissionState.UNKNOWN for state in states):
        return HostAdmissionState.UNKNOWN
    if any(state is HostAdmissionState.FOREIGN for state in states):
        return HostAdmissionState.FOREIGN
    if all(state is HostAdmissionState.PRESENT for state in states):
        return HostAdmissionState.PRESENT
    if all(state is HostAdmissionState.ABSENT for state in states):
        return HostAdmissionState.ABSENT
    return HostAdmissionState.PARTIAL


def _cursor_cli_entries(owner: McpOwnerForm | None) -> frozenset[str]:
    if owner == "external":
        return frozenset({CURSOR_CLI_EXTERNAL_ENTRY})
    if owner == "plugin":
        return frozenset({CURSOR_CLI_PLUGIN_ENTRY})
    return frozenset({CURSOR_CLI_EXTERNAL_ENTRY, CURSOR_CLI_PLUGIN_ENTRY})


def _claude_check_entries(owner: McpOwnerForm | None) -> frozenset[str]:
    if owner == "external":
        return frozenset({CLAUDE_EXTERNAL_CHECK_TOOL_NAME})
    if owner == "plugin":
        return frozenset({CLAUDE_PLUGIN_CHECK_TOOL_NAME})
    return _CLAUDE_CHECK_TOOL_NAMES


def _observe_entries(
    host: HostAdmissionHost, root: Path, owner: McpOwnerForm | None
) -> tuple[HostAdmissionEntry, ...]:
    if host == "claude":
        return (
            _observe_string_list_surface(
                surface=_CLAUDE_SURFACE,
                read=_read(root / _CLAUDE_SURFACE),
                container_key="permissions",
                allow_key="allow",
                deny_key="deny",
                ask_key="ask",
                entries=_claude_check_entries(owner),
                wider=_CLAUDE_WIDER_RULES,
                case_insensitive=False,
                legacy=_CLAUDE_LEGACY_ENTRIES,
            ),
        )
    if host == "codex":
        return (_observe_codex(_read(root / _CODEX_SURFACE), owner),)
    if host == "cursor":
        return (
            _observe_string_list_surface(
                surface=_CURSOR_IDE_SURFACE,
                read=_read(root / _CURSOR_IDE_SURFACE),
                container_key=None,
                allow_key="mcpAllowlist",
                deny_key=None,
                ask_key=None,
                entries=frozenset({CURSOR_IDE_ENTRY}),
                wider=_CURSOR_IDE_WIDER,
                case_insensitive=True,
                legacy=_CURSOR_IDE_LEGACY_ENTRIES,
            ),
            _observe_string_list_surface(
                surface=_CURSOR_CLI_SURFACE,
                read=_read(root / _CURSOR_CLI_SURFACE),
                container_key="permissions",
                allow_key="allow",
                deny_key="deny",
                ask_key=None,
                entries=_cursor_cli_entries(owner),
                wider=_CURSOR_CLI_WIDER,
                case_insensitive=False,
                legacy=_CURSOR_CLI_LEGACY_ENTRIES,
            ),
        )
    raise HostAdmissionError(HostAdmissionReason.HOST_INVALID)


def observe_host_admission(
    host: HostAdmissionHost,
    project_root: Path,
    *,
    owner: McpOwnerForm | None = None,
) -> HostAdmissionObservation:
    """Read every admission surface of ``host`` under ``project_root`` without mutating."""

    root = _validated_root(project_root)
    entries = _observe_entries(host, root, owner)
    return HostAdmissionObservation(host, _aggregate(entries), entries)


# --- preview ------------------------------------------------------------------------------


def _files_after(
    host: HostAdmissionHost,
    root: Path,
    action: HostAdmissionAction,
    owner: McpOwnerForm | None,
    *,
    checkpoint: bool,
    entries: Sequence[HostAdmissionEntry],
    retire_legacy: bool = False,
) -> dict[str, bytes]:
    add = action is HostAdmissionAction.GRANT
    changed: dict[str, bytes] = {}
    by_surface = {entry.surface: entry for entry in entries}

    def editable(surface: str) -> bool:
        # Revoke touches only a surface that carries an exact FinishUP entry (or, on an otherwise
        # absent surface, an exact legacy one, ADR-048); grant touches only an absent one —
        # except the Claude allow<->ask mode change below, and a surface whose exact legacy
        # entries a grant retires. A foreign or unknown surface is never edited.
        entry = by_surface[surface]
        if add:
            return entry.state is HostAdmissionState.ABSENT or (
                retire_legacy
                and entry.state is HostAdmissionState.PRESENT
                and bool(entry.legacy_entries)
            )
        return entry.state is HostAdmissionState.PRESENT or (
            entry.state is HostAdmissionState.ABSENT and bool(entry.legacy_entries)
        )

    def retired(
        surface: str,
        after: bytes | None,
        *,
        container_key: str | None,
        list_keys: tuple[str, ...],
        legacy: frozenset[str],
        case_insensitive: bool = False,
    ) -> bytes | None:
        """Strip the exact legacy entries a grant retires from one JSON surface (ADR-048)."""

        if not (retire_legacy and by_surface[surface].legacy_entries):
            return after
        current = _read(root / surface) if after is None else _Read(after or None, None)
        result = after
        for list_key in list_keys:
            stripped = _json_with_list_entry(
                current,
                container_key=container_key,
                list_key=list_key,
                entry=sorted(legacy)[0],
                add=False,
                remove_entries=legacy,
                case_insensitive=case_insensitive,
            )
            if stripped is not None:
                result = stripped
                current = _Read(stripped or None, None)
        return result

    if host == "claude":
        # A grant whose exact entry already sits in the other Claude list is a mode change
        # (`allow` <-> `ask`), not a no-op: leaving the other mode in place would silently keep
        # the behavior the owner just asked to change. Only the requested mode already set stays
        # a no-op. The observation reports `foreign` when both lists carry the entry, so a
        # present entry names exactly one current mode in its detail.
        current = by_surface[_CLAUDE_SURFACE]
        requested_mode = "ask" if checkpoint else "allow"
        mode_change = (
            add
            and current.state is HostAdmissionState.PRESENT
            and current.detail in {"allow", "ask"}
            and current.detail != requested_mode
        )
        if editable(_CLAUDE_SURFACE) or mode_change:
            claude_entries = _claude_check_entries(owner)
            before = _read(root / _CLAUDE_SURFACE)
            if add:
                source = before
                if mode_change:
                    removed = _json_with_list_entry(
                        before,
                        container_key="permissions",
                        list_key="allow" if requested_mode == "ask" else "ask",
                        entry=sorted(claude_entries)[0],
                        add=False,
                        remove_entries=claude_entries,
                    )
                    if removed is not None:
                        # Emptied-to-no-file removal reads as an absent file for the re-add.
                        source = _Read(None if removed == b"" else removed, None)
                after = _json_with_list_entry(
                    source,
                    container_key="permissions",
                    list_key=requested_mode,
                    entry=sorted(claude_entries)[0],
                    add=True,
                    remove_entries=claude_entries,
                )
                after = retired(
                    _CLAUDE_SURFACE,
                    after,
                    container_key="permissions",
                    list_keys=("allow", "ask"),
                    legacy=_CLAUDE_LEGACY_ENTRIES,
                )
            else:
                # Revoke takes the exact legacy spellings with the FinishUP ones (ADR-048).
                claude_entries = claude_entries | _CLAUDE_LEGACY_ENTRIES
                after_allow = _json_with_list_entry(
                    before,
                    container_key="permissions",
                    list_key="allow",
                    entry=sorted(claude_entries)[0],
                    add=False,
                    remove_entries=claude_entries,
                )
                if after_allow == b"":
                    after = after_allow
                else:
                    after_allow_read = before if after_allow is None else _Read(after_allow, None)
                    after_ask = _json_with_list_entry(
                        after_allow_read,
                        container_key="permissions",
                        list_key="ask",
                        entry=sorted(claude_entries)[0],
                        add=False,
                        remove_entries=claude_entries,
                    )
                    after = after_ask if after_ask is not None else after_allow
            if after is not None:
                changed[_CLAUDE_SURFACE] = after
    elif host == "codex":
        if editable(_CODEX_SURFACE):
            before = _read(root / _CODEX_SURFACE)
            after = _codex_after(before, add=add, owner=owner)
            if add and retire_legacy and by_surface[_CODEX_SURFACE].legacy_entries:
                # The grant retires the exact legacy tables (ADR-048).
                stripped = after if after is not None else (before.raw or b"")
                for table in _CODEX_LEGACY_TABLES:
                    stripped = strip_exact_table(stripped, table)
                if stripped != (before.raw or b""):
                    after = stripped
            if after is not None:
                changed[_CODEX_SURFACE] = after
    elif host == "cursor":
        if editable(_CURSOR_IDE_SURFACE):
            after = _json_with_list_entry(
                _read(root / _CURSOR_IDE_SURFACE),
                container_key=None,
                list_key="mcpAllowlist",
                entry=CURSOR_IDE_ENTRY,
                add=add,
                remove_entries=frozenset({CURSOR_IDE_ENTRY}) | _CURSOR_IDE_LEGACY_ENTRIES,
                case_insensitive=True,
            )
            if add:
                after = retired(
                    _CURSOR_IDE_SURFACE,
                    after,
                    container_key=None,
                    list_keys=("mcpAllowlist",),
                    legacy=_CURSOR_IDE_LEGACY_ENTRIES,
                    case_insensitive=True,
                )
            if after is not None:
                changed[_CURSOR_IDE_SURFACE] = after
        if editable(_CURSOR_CLI_SURFACE):
            cli_entries = _cursor_cli_entries(owner)
            if not add:
                cli_entries = cli_entries | _CURSOR_CLI_LEGACY_ENTRIES
            after = _json_with_list_entry(
                _read(root / _CURSOR_CLI_SURFACE),
                container_key="permissions",
                list_key="allow",
                entry=sorted(cli_entries)[0],
                add=add,
                remove_entries=cli_entries,
            )
            if add:
                after = retired(
                    _CURSOR_CLI_SURFACE,
                    after,
                    container_key="permissions",
                    list_keys=("allow",),
                    legacy=_CURSOR_CLI_LEGACY_ENTRIES,
                )
            if after is not None:
                changed[_CURSOR_CLI_SURFACE] = after
    return changed


def _preview_digest(
    host: HostAdmissionHost,
    action: HostAdmissionAction,
    entries: Sequence[HostAdmissionEntry],
    owner: McpOwnerForm | None,
    *,
    checkpoint: bool,
    files_after: Mapping[str, bytes],
    legacy_name: LegacyNameUse | None = None,
) -> str:
    body: dict[str, JsonValue] = {
        "action": action.value,
        "checkpoint": checkpoint,
        "entries_before": [entry.as_json() for entry in entries],
        "files_after": {
            surface: f"sha256:{hashlib.sha256(data).hexdigest()}"
            for surface, data in sorted(files_after.items())
        },
        "host": host,
        "owner": owner,
        "schema": _PREVIEW_SCHEMA,
    }
    if legacy_name is not None:
        # The observed legacy-name use decides whether a grant retires legacy entries (ADR-048).
        body["legacy_name"] = legacy_name
    return canonical_digest(body)


def preview_host_admission(
    host: HostAdmissionHost,
    project_root: Path,
    action: HostAdmissionAction,
    *,
    route_profile: str | None,
    grant_permits: bool | None,
    owner: McpOwnerForm | None = None,
    checkpoint: bool = False,
    legacy_name: LegacyNameUse | None = None,
) -> HostAdmissionPreview:
    """Plan one grant or revoke and bind it to the exact bytes it read and would write.

    ``route_profile``, ``grant_permits`` and ``legacy_name`` are the caller's *observed* facts
    (``None`` means unread). A grant is refused unless the route is ``policy`` and the repository
    grant permits external review; a revoke needs neither, because the way out must always stay
    open. A grant is also refused while the host serves FinishUP only under the legacy ``yoetz``
    name, and it retires the exact legacy entries once ``legacy_name`` is ``unused``; an unread
    or still-used legacy name leaves them in place (ADR-048).
    """

    if action is HostAdmissionAction.NOOP:
        raise HostAdmissionError(HostAdmissionReason.HOST_INVALID)
    if legacy_name is not None and legacy_name not in _LEGACY_NAME_USES:
        raise HostAdmissionError(HostAdmissionReason.HOST_INVALID)
    root = _validated_root(project_root)
    # Revoke is ownership-independent: its job is to remove every exact FinishUP admission form,
    # including one left behind by an earlier route-owner transition.
    effective_owner = owner if action is HostAdmissionAction.GRANT else None
    if action is HostAdmissionAction.GRANT:
        if route_profile is None:
            raise HostAdmissionError(HostAdmissionReason.ROUTE_UNOBSERVED)
        if route_profile != "policy":
            raise HostAdmissionError(HostAdmissionReason.ROUTE_NOT_POLICY)
        if grant_permits is None:
            raise HostAdmissionError(HostAdmissionReason.GRANT_UNVERIFIABLE)
        if grant_permits is not True:
            raise HostAdmissionError(HostAdmissionReason.GRANT_NOT_PERMITTING)
        if effective_owner is None:
            raise HostAdmissionError(HostAdmissionReason.OWNER_REQUIRED)
        if checkpoint and host != "claude":
            raise HostAdmissionError(HostAdmissionReason.HOST_INVALID)
        if legacy_name == "serving":
            # A ``finishup`` entry would admit nothing the host routes (ADR-048).
            raise HostAdmissionError(HostAdmissionReason.LEGACY_REGISTRATION_ACTIVE)
    else:
        # Revoke removes every exact form regardless; the observed use cannot change it.
        legacy_name = None
    retire_legacy = action is HostAdmissionAction.GRANT and legacy_name == "unused"
    entries = _observe_entries(host, root, effective_owner)
    state_before = _aggregate(entries)
    warnings: list[str] = []
    if state_before is HostAdmissionState.UNKNOWN:
        raise HostAdmissionError(HostAdmissionReason.ENTRY_UNREADABLE)
    if action is HostAdmissionAction.GRANT and state_before is HostAdmissionState.FOREIGN:
        raise HostAdmissionError(HostAdmissionReason.FOREIGN_ENTRY_PRESENT)
    if state_before is HostAdmissionState.FOREIGN:
        warnings.append("foreign_entry_retained")
    files_after = _files_after(
        host,
        root,
        action,
        effective_owner,
        checkpoint=checkpoint,
        entries=entries,
        retire_legacy=retire_legacy,
    )
    # Only a surface this preview would change needs a folder FinishUP may write: a revoke with
    # nothing to remove stays a no-op beside a host folder root committed to the image.
    for surface in files_after:
        _require_writable_host_folder((root / surface).parent)
    effective = action if files_after else HostAdmissionAction.NOOP
    if effective is not HostAdmissionAction.NOOP:
        warnings.append("host_config_not_compare_and_swap")
    if host == "codex" and effective is HostAdmissionAction.GRANT:
        warnings.append("codex_project_layer_requires_trusted_project")
    if host == "claude" and effective is HostAdmissionAction.GRANT:
        warnings.append("claude_local_settings_held_until_trusted_when_tracked")
    if (effective is HostAdmissionAction.REVOKE or retire_legacy) and any(
        entry.legacy_entries and entry.surface in files_after for entry in entries
    ):
        warnings.append("legacy_entries_removed")
    elif (
        action is HostAdmissionAction.GRANT
        and not retire_legacy
        and any(entry.legacy_entries for entry in entries)
    ):
        warnings.append("legacy_entries_retained")
    digest = _preview_digest(
        host,
        action,
        entries,
        effective_owner,
        checkpoint=checkpoint,
        files_after=files_after,
        legacy_name=legacy_name,
    )
    return HostAdmissionPreview(
        host,
        effective,
        state_before,
        entries,
        route_profile,
        grant_permits,
        effective_owner,
        checkpoint,
        digest,
        tuple(warnings),
        action,
        files_after,
        legacy_name,
    )


# --- apply --------------------------------------------------------------------------------


def _require_writable_host_folder(folder: Path) -> None:
    """Refuse a host folder FinishUP may not write: a link, a non-directory, or not the user's own.

    An absent folder passes; FinishUP creates it owner-only, pinned by descriptor.
    """

    try:
        descriptor = _open_folder(folder)
    except OSError as exc:
        raise HostAdmissionError(HostAdmissionReason.TARGET_UNSAFE) from exc
    if descriptor is None:
        return
    try:
        if not _host_folder_writable(os.fstat(descriptor)):
            raise HostAdmissionError(HostAdmissionReason.TARGET_UNSAFE)
    finally:
        os.close(descriptor)


def _pinned_host_folder(path: Path, *, create: bool) -> int | None:
    """Pin ``<root>/<host folder>`` by descriptor for a write or removal of ``path``.

    The project root is opened without following a link and judged by the project-root rule; the
    host folder is opened (or created owner-only) relative to it, without following a link, and
    must be the running user's own and not writable by another account. Every later step uses
    this descriptor, so swapping the folder for a link or another account's folder after the
    check cannot redirect the write.
    """

    folder = path.parent
    try:
        root = os.open(folder.parent, _DIRECTORY_FLAGS)
    except OSError as exc:
        raise HostAdmissionError(HostAdmissionReason.TARGET_UNSAFE) from exc
    try:
        if not project_root_admitted(os.fstat(root)):
            raise HostAdmissionError(HostAdmissionReason.TARGET_UNSAFE)
        try:
            descriptor = os.open(folder.name, _DIRECTORY_FLAGS, dir_fd=root)
        except FileNotFoundError:
            if not create:
                return None
            try:
                os.mkdir(folder.name, 0o700, dir_fd=root)
                descriptor = os.open(folder.name, _DIRECTORY_FLAGS, dir_fd=root)
            except OSError as exc:
                raise HostAdmissionError(HostAdmissionReason.WRITE_FAILED) from exc
        except OSError as exc:
            raise HostAdmissionError(HostAdmissionReason.TARGET_UNSAFE) from exc
    finally:
        os.close(root)
    try:
        if not _host_folder_writable(os.fstat(descriptor)):
            raise HostAdmissionError(HostAdmissionReason.TARGET_UNSAFE)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _require_expected_at(folder: int, name: str, expected_digest: str | None) -> None:
    """Refuse when the pinned file is not the exact byte preimage used by the fresh preview."""

    current = _read_at(folder, name)
    if current.problem is not None or current.digest != expected_digest:
        raise HostAdmissionError(HostAdmissionReason.PREVIEW_STALE)


def _write_private(folder: int, name: str, payload: bytes, *, expected_digest: str | None) -> None:
    temporary = f".{name}.{os.urandom(8).hex()}.tmp"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=folder,
        )
    except OSError as exc:
        raise HostAdmissionError(HostAdmissionReason.WRITE_FAILED) from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # Re-read after staging, immediately before replacement. A non-cooperating same-UID writer
        # can still win the final syscall window; the preview warning and runbook disclose that
        # host limitation instead of claiming a compare-and-swap primitive POSIX does not provide.
        _require_expected_at(folder, name, expected_digest)
        os.replace(temporary, name, src_dir_fd=folder, dst_dir_fd=folder)
    except BaseException as exc:
        try:
            os.unlink(temporary, dir_fd=folder)
        except OSError:
            pass
        if isinstance(exc, OSError):
            raise HostAdmissionError(HostAdmissionReason.WRITE_FAILED) from exc
        raise


def _delete_or_write(path: Path, payload: bytes, *, expected_digest: str | None) -> None:
    """Write or remove ``<root>/<host folder>/<file>`` through the pinned host folder."""

    folder = _pinned_host_folder(path, create=payload != b"")
    if folder is None:
        # Nothing to remove, and the preview saw no file either, or the folder vanished.
        if expected_digest is not None:
            raise HostAdmissionError(HostAdmissionReason.PREVIEW_STALE)
        return
    try:
        _require_expected_at(folder, path.name, expected_digest)
        if payload == b"":
            # A host file emptied by removal reverts to "no file", the state before grant.
            try:
                os.unlink(path.name, dir_fd=folder)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise HostAdmissionError(HostAdmissionReason.WRITE_FAILED) from exc
            return
        _write_private(folder, path.name, payload, expected_digest=expected_digest)
    finally:
        os.close(folder)


def apply_host_admission(
    preview: HostAdmissionPreview,
    project_root: Path,
    *,
    accepted_preview_digest: str,
) -> HostAdmissionResult:
    """Recompute the preview, refuse on any drift, then write only the previewed surfaces."""

    if accepted_preview_digest != preview.preview_digest:
        raise HostAdmissionError(HostAdmissionReason.PREVIEW_STALE)
    fresh = preview_host_admission(
        preview.host,
        project_root,
        preview.requested_action,
        route_profile=preview.route_profile,
        grant_permits=preview.grant_permits,
        owner=preview.owner,
        checkpoint=preview.checkpoint,
        legacy_name=preview.legacy_name,
    )
    if fresh.preview_digest != accepted_preview_digest:
        raise HostAdmissionError(HostAdmissionReason.PREVIEW_STALE)
    if fresh.action is HostAdmissionAction.NOOP:
        # A second read keeps a no-op from reporting success after its accepted state changed in
        # the gap between the fresh preview and this return.
        final = preview_host_admission(
            preview.host,
            project_root,
            preview.requested_action,
            route_profile=preview.route_profile,
            grant_permits=preview.grant_permits,
            owner=preview.owner,
            checkpoint=preview.checkpoint,
            legacy_name=preview.legacy_name,
        )
        if final.preview_digest != accepted_preview_digest:
            raise HostAdmissionError(HostAdmissionReason.PREVIEW_STALE)
        return HostAdmissionResult(
            preview.host, HostAdmissionAction.NOOP, fresh.state_before, final.state_before, ()
        )
    root = _validated_root(project_root)
    expected_by_surface = {entry.surface: entry.file_digest for entry in fresh.entries}
    mutation_started = False
    for surface, payload in sorted(fresh.files_after.items()):
        try:
            _delete_or_write(
                root / surface,
                payload,
                expected_digest=expected_by_surface[surface],
            )
        except HostAdmissionError as error:
            if mutation_started and error.reason in {
                HostAdmissionReason.PREVIEW_STALE,
                HostAdmissionReason.TARGET_UNSAFE,
            }:
                raise HostAdmissionError(HostAdmissionReason.WRITE_FAILED) from error
            raise
        mutation_started = True
    try:
        after = observe_host_admission(preview.host, root, owner=preview.owner)
    except HostAdmissionError as error:
        raise HostAdmissionError(HostAdmissionReason.WRITE_FAILED) from error
    expected_state = (
        HostAdmissionState.PRESENT
        if preview.requested_action is HostAdmissionAction.GRANT
        else HostAdmissionState.ABSENT
    )
    if after.state is not expected_state:
        raise HostAdmissionError(HostAdmissionReason.WRITE_FAILED)
    retiring = (
        preview.requested_action is HostAdmissionAction.REVOKE or preview.legacy_name == "unused"
    )
    if retiring and any(
        entry.legacy_entries and entry.surface in fresh.files_after for entry in after.entries
    ):
        raise HostAdmissionError(HostAdmissionReason.WRITE_FAILED)
    return HostAdmissionResult(
        preview.host,
        fresh.action,
        fresh.state_before,
        after.state,
        tuple(sorted(fresh.files_after)),
    )


# --- reverse transitions ------------------------------------------------------------------


def sweep_host_admission(
    project_root: Path,
    hosts: Sequence[HostAdmissionHost] = ADMISSION_HOSTS,
) -> tuple[HostAdmissionSweep, ...]:
    """Remove exactly the entries FinishUP writes, for every listed host, and report each outcome.

    Used by the reverse transitions (grant revoke, strict re-registration, host uninstall) that
    already carry their own digest-bound authority. Foreign entries are retained and reported;
    an unreadable surface is reported as ``unknown`` and left alone.
    """

    outcomes: list[HostAdmissionSweep] = []
    for host in hosts:
        try:
            preview = preview_host_admission(
                host,
                project_root,
                HostAdmissionAction.REVOKE,
                route_profile=None,
                grant_permits=None,
                owner=None,
            )
        except HostAdmissionError as error:
            outcomes.append(
                HostAdmissionSweep(
                    host,
                    "unknown"
                    if error.reason is HostAdmissionReason.ENTRY_UNREADABLE
                    else "write_failed",
                )
            )
            continue
        if not preview.files_after:
            outcomes.append(
                HostAdmissionSweep(
                    host,
                    "retained_foreign"
                    if preview.state_before is HostAdmissionState.FOREIGN
                    else "absent",
                )
            )
            continue
        try:
            result = apply_host_admission(
                preview, project_root, accepted_preview_digest=preview.preview_digest
            )
        except HostAdmissionError:
            outcomes.append(HostAdmissionSweep(host, "write_failed"))
            continue
        outcomes.append(HostAdmissionSweep(host, "removed", result.surfaces_changed))
    return tuple(outcomes)
