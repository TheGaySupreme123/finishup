"""Platform-native paths and the private-local bundle safety gate."""

from __future__ import annotations

import ctypes
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, cast

from platformdirs import PlatformDirs

from finishup.config.env import EnvNameConflictError, env_names, read_env
from finishup.config.foreign_write import writable_by_others
from finishup.legacy_names import APP_NAME, LEGACY_APP_NAME

__all__ = [
    "ISOLATED_ROOT_ENV",
    "ISOLATED_ROOT_ENV_NAMES",
    "LEGACY_ISOLATED_ROOT_ENV",
    "RUNTIME_PIN_NAME",
    "RUNTIME_PIN_SCHEMA",
    "SERVERS_DIR_NAME",
    "SERVER_SELECTION_NAME",
    "SERVER_SELECTION_SCHEMA",
    "SERVER_TARGET_FILE_NAME",
    "InstallationNaming",
    "IsolationBinding",
    "PathSafetyError",
    "RuntimePin",
    "active_root",
    "ambient_installation_dirs",
    "ambient_registry_dirs",
    "bundle_root",
    "cache_dir",
    "catalog_path",
    "config_file_path",
    "ensure_owner_only_dir",
    "existing_owner_only_dir",
    "installation_naming",
    "isolated_root",
    "isolated_root_variable",
    "isolation_binding",
    "log_dir",
    "read_runtime_pin",
    "reset_selection_memo",
    "runtime_dir",
    "selection_override",
    "runtime_pin_path",
    "service_generation_path",
    "setup_marker_path",
    "state_dir",
    "task_bundle_dir",
    "unlock_throttle_path",
    "verify_private_local_bundle",
]

_ISOLATED_ROOT_SUFFIX: Final = "ISOLATED_ROOT"
# ``FINISHUP_ISOLATED_ROOT`` and its legacy ``YOETZ_ISOLATED_ROOT`` spelling (ADR-048). Children
# this runtime spawns receive both with one value, so an older launcher still isolates (#604).
ISOLATED_ROOT_ENV_NAMES: Final = env_names(_ISOLATED_ROOT_SUFFIX)
ISOLATED_ROOT_ENV: Final = ISOLATED_ROOT_ENV_NAMES[0]
LEGACY_ISOLATED_ROOT_ENV: Final = ISOLATED_ROOT_ENV_NAMES[1]
# Files that mark an existing ambient installation under one platform-directory application name
# (ADR-048): the storage catalog and vault (the keyring auto-unlock account is bound to the data
# directory's absolute path), the user config file, and the service singleton lock an older
# running service still holds. Caches, logs, and runtime endpoints are not anchors.
_INSTALLATION_ANCHORS: Final = (
    ("data", "catalog.sqlite3"),
    ("data", "vault"),
    ("config", "config.toml"),
    ("state", "service.lock"),
)
# A runtime pin lives inside the snapshot's own virtual environment (``sys.prefix``), next to the
# interpreter that every launcher, hook, and MCP bridge of that snapshot resolves. It binds the
# executable to one isolated root so a dropped environment cannot select the ambient install
# (issue #604). ``config/installation.py`` writes and removes it; this module only reads it.
# Frozen legacy identifier (ADR-048): retained older runtimes and release snapshots read this pin
# by name and schema; a missed pin would silently fall back to the everyday install (#604).
RUNTIME_PIN_NAME: Final = "yoetz-instance-pin.json"
RUNTIME_PIN_SCHEMA: Final = "yoetz.runtime-instance-pin/1"
_MAX_RUNTIME_PIN_BYTES: Final = 4_096
_INSTALLATION_ID: Final = re.compile(
    r"^ins_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.ASCII
)
# The owner-only server selection (ADR-051): the lowest-precedence root source, below the
# isolation variable and the runtime pin. It lives in the ambient config directory and names one
# target root beneath ``<ambient state dir>/servers/``; ``finishup.client.targets`` writes it, and
# this module only reads it (``json`` and ``os`` only, so a hook pays nothing more).
SERVER_SELECTION_NAME: Final = "server-selection.json"
SERVER_SELECTION_SCHEMA: Final = "yoetz.server-selection/1"
SERVERS_DIR_NAME: Final = "servers"
SERVER_TARGET_FILE_NAME: Final = "target.json"
_MAX_SELECTION_BYTES: Final = 1_024
# ``finishup.client.targets`` owns the record; these bound the service's own minimal read of it.
_MAX_TARGET_RECORD_BYTES: Final = 8_192
_SERVER_TARGET_KINDS: Final = frozenset({"local", "local_port", "ssh", "https"})
_TARGET_ID: Final = re.compile(r"^t_[0-9a-f]{8}$", re.ASCII)
type IsolationBinding = Literal[
    "ambient", "environment", "runtime_pin", "environment_and_pin", "selection"
]
# Which platform-directory application name the ambient roots use (ADR-048): ``finishup`` for a
# new installation, ``legacy_yoetz`` for one first installed as Yoetz and adopted in place.
type InstallationNaming = Literal["finishup", "legacy_yoetz"]
type _NamingSelection = Literal["finishup", "legacy_yoetz", "ambiguous"]
_PRIVATE_DIR_MODE: Final = 0o700
_VCS_MARKERS: Final = frozenset({".git", ".hg", ".svn", ".jj"})
# ``9p`` (WSL 2 Windows drives and other virtio-9p shares), ``drvfs`` (WSL 1 Windows drives), and
# ``virtiofs`` (VM shared folders, including newer WSL and Docker/Lima mounts) all proxy file
# operations across a VM or host boundary. FinishUP has not certified their locking and crash
# durability, so they are refused like a network share (issue #723): use the guest's own disk.
_NETWORK_FILESYSTEMS_LINUX: Final = frozenset(
    {
        "9p",
        "afs",
        "ceph",
        "cifs",
        "davfs",
        "drvfs",
        "fuse.rclone",
        "fuse.sshfs",
        "glusterfs",
        "nfs",
        "nfs4",
        "smb3",
        "smbfs",
        "sshfs",
        "virtiofs",
    }
)
_NETWORK_FILESYSTEMS_MACOS: Final = frozenset({"acfs", "afpfs", "nfs", "smbfs", "webdav"})
_LINUX_SYNC_COMPONENTS: Final = frozenset(
    {"Google Drive", "GoogleDrive", "Insync", "Nextcloud", "OneDrive", "Sync", "ownCloud"}
)
_SYNC_METADATA_NAMES: Final = frozenset({".dropbox", ".dropbox.cache", ".stfolder", ".sync"})
_PATH_SAFETY_REASONS: Final = frozenset(
    {
        "installation_root_ambiguous",
        "isolation_root_conflict",
        "isolation_root_env_conflict",
        "isolation_root_invalid",
        "path_contains_symlink",
        "path_in_repository",
        "path_in_sync_folder",
        "path_not_owned",
        "path_on_network_filesystem",
        "path_shared_temp",
        "permissions_too_broad",
        "runtime_pin_invalid",
    }
)


class PathSafetyError(Exception):
    """A bounded path-safety failure suitable for STORAGE_UNSAFE mapping."""

    reason_code: str

    def __init__(self, reason_code: str) -> None:
        if type(reason_code) is not str or reason_code not in _PATH_SAFETY_REASONS:
            raise ValueError("path_safety_reason_invalid")
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class _PathProbe:
    """Private injection seam for deterministic path-classifier tests."""

    platform: str
    effective_uid: int
    home: Path
    shared_temp: Path
    fixed_shared_temps: tuple[Path, ...]
    platform_dirs: PlatformDirs
    mount_table: Callable[[], str]
    macos_fstype: Callable[[Path], str | None]
    diagnostic: Callable[[str], None]
    runtime_prefix: Path = field(default_factory=lambda: Path(sys.prefix))
    # The ambient application-name selection ``platform_dirs`` was built for (ADR-048).
    installation_naming: _NamingSelection = "finishup"


@dataclass(frozen=True, slots=True)
class RuntimePin:
    """The exact root and installation identity a runtime prefix is bound to."""

    isolated_root: Path
    installation_id: str


def _ignore_diagnostic(_reason_code: str) -> None:
    return None


def _read_mount_table() -> str:
    return Path("/proc/mounts").read_text(encoding="utf-8")


class _DarwinStatFs(ctypes.Structure):
    # Darwin's public struct statfs layout. This branch is never selected on Linux.
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_reserved", ctypes.c_uint32 * 8),
    ]


def _darwin_fstype(path: Path) -> str | None:
    if sys.platform != "darwin":
        return None
    libc = ctypes.CDLL(None, use_errno=True)
    statfs = libc.statfs
    statfs.argtypes = [ctypes.c_char_p, ctypes.POINTER(_DarwinStatFs)]
    statfs.restype = ctypes.c_int
    result = _DarwinStatFs()
    if statfs(os.fsencode(path), ctypes.byref(result)) != 0:
        return None
    return bytes(result.f_fstypename).split(b"\0", 1)[0].decode("ascii", errors="strict")


def _platform_dirs(app_name: str) -> PlatformDirs:
    return PlatformDirs(appname=app_name, appauthor=False, roaming=False)


def _anchor_present(path: Path) -> bool:
    try:
        path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        # An anchor that cannot be examined is not proven absent.
        return True
    return True


def _has_installation_anchor(dirs: PlatformDirs) -> bool:
    roots = {
        "data": Path(dirs.user_data_dir),
        "config": Path(dirs.user_config_dir),
        "state": Path(dirs.user_state_dir),
    }
    return any(_anchor_present(roots[root] / name) for root, name in _INSTALLATION_ANCHORS)


def _select_installation_naming(current: PlatformDirs, legacy: PlatformDirs) -> _NamingSelection:
    """Choose one application name for every ambient root (ADR-048).

    An installation first made as Yoetz keeps its directories in place: a legacy anchor with no
    FinishUP anchor selects the legacy name for all roots, so the vault, the keyring auto-unlock
    binding, and an older service's singleton lock stay where they are. Nothing is moved, copied,
    or linked. A FinishUP anchor, or no anchor at all, selects ``finishup``. Anchors under both
    names are ambiguous: the caller fails closed rather than choosing one installation.
    """

    current_present = _has_installation_anchor(current)
    legacy_present = _has_installation_anchor(legacy)
    if current_present and legacy_present:
        return "ambiguous"
    return "legacy_yoetz" if legacy_present else "finishup"


def _default_probe() -> _PathProbe:
    current = _platform_dirs(APP_NAME)
    legacy = _platform_dirs(LEGACY_APP_NAME)
    naming = _select_installation_naming(current, legacy)
    dirs = legacy if naming == "legacy_yoetz" else current
    effective_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    return _PathProbe(
        platform=sys.platform,
        effective_uid=effective_uid,
        home=Path.home(),
        shared_temp=Path(tempfile.gettempdir()),
        fixed_shared_temps=(Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")),
        platform_dirs=dirs,
        mount_table=_read_mount_table,
        macos_fstype=_darwin_fstype,
        diagnostic=_ignore_diagnostic,
        installation_naming=naming,
    )


def _probe_or_default(probe: _PathProbe | None) -> _PathProbe:
    return _default_probe() if probe is None else probe


def _ambient_dirs(probe: _PathProbe) -> PlatformDirs:
    if probe.installation_naming == "ambiguous":
        raise PathSafetyError("installation_root_ambiguous")
    return probe.platform_dirs


def installation_naming(*, _probe: _PathProbe | None = None) -> InstallationNaming:
    """Name which application name the ambient platform roots use, as a closed token (ADR-048).

    ``legacy_yoetz`` means an installation first made as Yoetz is used in place. An isolated root
    never uses the ambient roots, so this answer does not describe it. Raises
    ``installation_root_ambiguous`` when installations exist under both names.
    """

    probe = _probe_or_default(_probe)
    _ambient_dirs(probe)
    return "legacy_yoetz" if probe.installation_naming == "legacy_yoetz" else "finishup"


def isolated_root_variable() -> str | None:
    """Return the raw isolation-root variable under either spelling (ADR-048), unvalidated.

    Raises ``isolation_root_env_conflict`` when ``FINISHUP_ISOLATED_ROOT`` and the legacy
    ``YOETZ_ISOLATED_ROOT`` are both set to different values. That is an environment mistake, not
    a disagreement between a root and a runtime pin (``isolation_root_conflict``), so it has its
    own token and a non-destructive remedy.
    """

    try:
        return read_env(_ISOLATED_ROOT_SUFFIX)
    except EnvNameConflictError:
        # Both spellings name different roots (ADR-048): refuse rather than choose either.
        raise PathSafetyError("isolation_root_env_conflict") from None


def runtime_pin_path(*, _probe: _PathProbe | None = None) -> Path:
    """Return the fixed pin location inside this process's runtime prefix."""

    return _probe_or_default(_probe).runtime_prefix / RUNTIME_PIN_NAME


def read_runtime_pin(*, _probe: _PathProbe | None = None) -> RuntimePin | None:
    """Return the runtime pin bound into this prefix, ``None`` when absent, or fail closed.

    A pin that exists but is a symlink, foreign-owned, group/world-writable, oversized, or not
    exactly the reviewed shape is ``runtime_pin_invalid``: a pin anyone else could have written
    is a way to redirect one installation to another, so it is refused rather than ignored.
    """

    probe = _probe_or_default(_probe)
    path = runtime_pin_path(_probe=probe)
    try:
        facts = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PathSafetyError("runtime_pin_invalid") from exc
    if (
        not stat.S_ISREG(facts.st_mode)
        or (hasattr(facts, "st_uid") and facts.st_uid != probe.effective_uid)
        or writable_by_others(facts)
        or facts.st_size > _MAX_RUNTIME_PIN_BYTES
    ):
        raise PathSafetyError("runtime_pin_invalid")
    try:
        parsed: object = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise PathSafetyError("runtime_pin_invalid") from exc
    if not isinstance(parsed, dict):
        raise PathSafetyError("runtime_pin_invalid")
    fields = cast(dict[object, object], parsed)
    if set(fields) != {"schema", "isolated_root", "installation_id"} or (
        fields.get("schema") != RUNTIME_PIN_SCHEMA
    ):
        raise PathSafetyError("runtime_pin_invalid")
    root = fields.get("isolated_root")
    installation_id = fields.get("installation_id")
    if (
        type(root) is not str
        or not root
        or not Path(root).is_absolute()
        or type(installation_id) is not str
        or not _INSTALLATION_ID.match(installation_id)
    ):
        raise PathSafetyError("runtime_pin_invalid")
    return RuntimePin(Path(root), installation_id)


def _validated_isolated_root(raw: str, probe: _PathProbe) -> Path:
    if not raw:
        raise PathSafetyError("isolation_root_invalid")
    root = Path(raw)
    if not root.is_absolute():
        raise PathSafetyError("isolation_root_invalid")
    verify_private_local_bundle(root, _probe=probe)
    try:
        facts = root.lstat()
    except OSError as exc:
        raise PathSafetyError("isolation_root_invalid") from exc
    if not stat.S_ISDIR(facts.st_mode):
        raise PathSafetyError("isolation_root_invalid")
    return root


def isolated_root(*, _probe: _PathProbe | None = None) -> Path | None:
    """Return the validated exact-target isolation root, or ``None`` in ambient mode.

    ``FINISHUP_ISOLATED_ROOT`` is the one supported isolation contract (issue #518): when it is
    set, every identity root — config, storage bundle, state directory (service lock and
    generation), runtime endpoint directory, cache, and logs — derives from this single root, so
    an isolated runtime can never share the ambient platform singleton. Validation fails closed:
    a set-but-unusable root raises instead of falling back to the ambient platform directories.
    The root must already exist as an absolute, owner-only, symlink-free private directory
    outside shared temp, repositories, and sync folders.

    A runtime pin (issue #604) is the second, executable-bound source of the same root: when the
    variable is unset, a pinned runtime resolves the pinned root under the same validation, so a
    host or hook that drops the environment still reaches the snapshot's own state and never the
    everyday singleton. When both are present they must name the same root;
    ``isolation_root_conflict`` fails closed instead of choosing either.

    The legacy ``YOETZ_ISOLATED_ROOT`` spelling is read when ``FINISHUP_ISOLATED_ROOT`` is unset
    (ADR-048); both set to different roots is ``isolation_root_env_conflict``.
    """

    probe = _probe_or_default(_probe)
    raw = isolated_root_variable()
    pin = read_runtime_pin(_probe=probe)
    if raw is None and pin is None:
        return None
    if raw is not None:
        root = _validated_isolated_root(raw, probe)
        if pin is not None and pin.isolated_root != root:
            raise PathSafetyError("isolation_root_conflict")
        return root
    assert pin is not None
    return _validated_isolated_root(str(pin.isolated_root), probe)


# Per-process memo of the selected target root, keyed by the selection file path. The MCP bridge
# reads the selection once per process, so it never switches servers mid-session; a hook is a
# fresh process and follows a new selection at once.
_SELECTION_MEMO: dict[str, Path | None] = {}


def reset_selection_memo() -> None:
    """Forget the memoized selection (``finishup server use`` and tests call this)."""

    _SELECTION_MEMO.clear()


# Set once by ``finishup service run --ambient-root``: this process never reads the selection.
_selection_ignored: bool = False


def ignore_server_selection() -> None:
    """Resolve the server selection as absent for the rest of this process (ADR-051).

    A client whose own root is the everyday installation starts its service with
    ``finishup service run --ambient-root``, which calls this before anything resolves a path. The
    service then serves the everyday installation its spawner uses, never a target that a
    selection written after the spawner resolved its root names. The isolation variable and the
    runtime pin still outrank this, exactly as they outrank the selection; nothing undoes it
    within the process, and ``reset_selection_memo`` leaves it in force.
    """

    global _selection_ignored
    _selection_ignored = True


def ambient_registry_dirs(*, _probe: _PathProbe | None = None) -> tuple[Path, Path]:
    """Return ``(ambient config dir, ambient state dir)``, where the server registry lives.

    These are the everyday installation's platform directories, independent of any isolation
    root or selection: target roots live beneath ``<state>/servers/`` and the selection file in
    ``<config>``. Raises ``installation_root_ambiguous`` like every other ambient path.
    """

    dirs = _ambient_dirs(_probe_or_default(_probe))
    return Path(dirs.user_config_dir), Path(dirs.user_state_dir)


def ambient_installation_dirs() -> tuple[Path, ...]:
    """Every platform directory the everyday installation may use, under both names (ADR-048).

    The data, configuration, cache, state, log and runtime directories of the ambient
    installation as ``finishup`` and as the legacy ``yoetz``, whatever root this process uses and
    whether or not they exist. Nothing is read, validated or created: the answer only names
    directories a caller keeps reads out of (the workspace agent's own-directory fence, ADR-051),
    so a selected or isolated root never makes the everyday installation readable.
    """

    found: list[Path] = []
    for app_name in (APP_NAME, LEGACY_APP_NAME):
        dirs = _platform_dirs(app_name)
        found.extend(
            Path(directory)
            for directory in (
                dirs.user_data_dir,
                dirs.user_config_dir,
                dirs.user_cache_dir,
                dirs.user_state_dir,
                dirs.user_log_dir,
                dirs.user_runtime_dir,
            )
        )
    return tuple(dict.fromkeys(found))


def _read_selection(path: Path, probe: _PathProbe) -> str | None:
    """Return the selected target id, ``None`` when no selection file exists, or fail closed."""

    try:
        facts = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        raise PathSafetyError("isolation_root_invalid") from exc
    if (
        not stat.S_ISREG(facts.st_mode)
        or (hasattr(facts, "st_uid") and facts.st_uid != probe.effective_uid)
        or stat.S_IMODE(facts.st_mode) & 0o077
        or facts.st_size > _MAX_SELECTION_BYTES
    ):
        raise PathSafetyError("isolation_root_invalid")
    try:
        parsed: object = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise PathSafetyError("isolation_root_invalid") from exc
    if not isinstance(parsed, dict):
        raise PathSafetyError("isolation_root_invalid")
    fields = cast(dict[object, object], parsed)
    target_id = fields.get("target_id")
    if (
        set(fields) != {"schema", "target_id"}
        or fields.get("schema") != SERVER_SELECTION_SCHEMA
        or type(target_id) is not str
        or not _TARGET_ID.match(target_id)
    ):
        raise PathSafetyError("isolation_root_invalid")
    return target_id


def _selected_root(probe: _PathProbe) -> Path | None:
    """Return the validated root the owner-only selection file names, memoized per process.

    No selection file means the ambient installation, exactly as before. A selection that is
    malformed, foreign-owned, or names a missing or unsafe root fails closed with
    ``isolation_root_invalid`` (or the root's own path-safety reason); it never falls back to the
    everyday service silently. Ambiguous ambient naming reads no selection: every ambient path
    already fails closed with ``installation_root_ambiguous`` there.
    """

    if probe.installation_naming == "ambiguous" or _selection_ignored:
        return None
    dirs = probe.platform_dirs
    path = Path(dirs.user_config_dir) / SERVER_SELECTION_NAME
    key = str(path)
    if key in _SELECTION_MEMO:
        return _SELECTION_MEMO[key]
    target_id = _read_selection(path, probe)
    root: Path | None = None
    if target_id is not None:
        root = _validated_isolated_root(
            str(Path(dirs.user_state_dir) / SERVERS_DIR_NAME / target_id), probe
        )
        try:
            marker = (root / SERVER_TARGET_FILE_NAME).lstat()
        except OSError as exc:
            raise PathSafetyError("isolation_root_invalid") from exc
        if not stat.S_ISREG(marker.st_mode):
            raise PathSafetyError("isolation_root_invalid")
    _SELECTION_MEMO[key] = root
    return root


def server_target_kind(root: Path, *, _probe: _PathProbe | None = None) -> str | None:
    """The kind the server target record in ``root`` names; ``None`` when ``root`` holds none.

    The service's own minimal check (ADR-051): it may not import the client's target registry
    (``finishup.client.targets`` validates the whole record), yet must never run in a remote
    target's root. Only an owner-only regular file holding a JSON object whose ``kind`` is one of
    the closed target kinds is answered; anything else fails closed with
    ``isolation_root_invalid``, and the caller treats that as possibly remote.
    """

    probe = _probe_or_default(_probe)
    path = root / SERVER_TARGET_FILE_NAME
    try:
        facts = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        raise PathSafetyError("isolation_root_invalid") from exc
    if (
        not stat.S_ISREG(facts.st_mode)
        or (hasattr(facts, "st_uid") and facts.st_uid != probe.effective_uid)
        or stat.S_IMODE(facts.st_mode) & 0o077
        or facts.st_size > _MAX_TARGET_RECORD_BYTES
    ):
        raise PathSafetyError("isolation_root_invalid")
    try:
        parsed: object = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise PathSafetyError("isolation_root_invalid") from exc
    kind = cast(dict[object, object], parsed).get("kind") if isinstance(parsed, dict) else None
    if type(kind) is not str or kind not in _SERVER_TARGET_KINDS:
        raise PathSafetyError("isolation_root_invalid")
    return kind


@contextmanager
def selection_override(root: Path | None, *, _probe: _PathProbe | None = None) -> Generator[None]:
    """Resolve the selection as ``root`` (``None``: the everyday install) inside this block.

    ``finishup server`` uses this to start, stop, or probe one named target from a process whose
    own selection names another; the block ends with the previous answer restored. It changes
    nothing on disk and never outranks the isolation variable or the runtime pin. ``root`` must
    be a validated target root.
    """

    probe = _probe_or_default(_probe)
    key = str(Path(probe.platform_dirs.user_config_dir) / SERVER_SELECTION_NAME)
    missing = object()
    previous: object = _SELECTION_MEMO.get(key, missing)
    _SELECTION_MEMO[key] = root
    try:
        yield
    finally:
        if previous is missing:
            _SELECTION_MEMO.pop(key, None)
        else:
            _SELECTION_MEMO[key] = cast(Path | None, previous)


def active_root(*, _probe: _PathProbe | None = None) -> Path | None:
    """Return the root this process uses, or ``None`` for the everyday ambient installation.

    Precedence (ADR-051 amending ADR-026/ADR-028): ``FINISHUP_ISOLATED_ROOT`` (or its legacy
    spelling), then the runtime pin — both through ``isolated_root()``, unchanged — then the
    owner-only server selection, then ambient. A pinned test instance therefore never sees the
    selection. Every identity root (config, bundle, state, runtime endpoints, cache, logs) derives
    from this answer; ``isolated_root()`` keeps meaning "explicitly isolated" for the call sites
    that stamp registrations and launch lines, so a selection is never written into a host.
    """

    probe = _probe_or_default(_probe)
    explicit = isolated_root(_probe=probe)
    if explicit is not None:
        return explicit
    return _selected_root(probe)


def isolation_binding(*, _probe: _PathProbe | None = None) -> IsolationBinding:
    """Name which source selected the root, after validating it."""

    probe = _probe_or_default(_probe)
    if isolated_root(_probe=probe) is None:
        return "ambient" if _selected_root(probe) is None else "selection"
    from_environment = isolated_root_variable() is not None
    from_pin = read_runtime_pin(_probe=probe) is not None
    if from_environment and from_pin:
        return "environment_and_pin"
    return "environment" if from_environment else "runtime_pin"


def bundle_root(*, _data_dir: Path | None = None, _probe: _PathProbe | None = None) -> Path:
    """Return the default bundle root or a safety-verified explicit override."""

    probe = _probe_or_default(_probe)
    if _data_dir is None:
        isolated = active_root(_probe=probe)
        if isolated is not None:
            return isolated / "data"
        return Path(_ambient_dirs(probe).user_data_dir)
    verify_private_local_bundle(_data_dir, _probe=probe)
    return _data_dir


def catalog_path(*, _data_dir: Path | None = None, _probe: _PathProbe | None = None) -> Path:
    """Return the catalog database path inside the selected bundle root."""

    return bundle_root(_data_dir=_data_dir, _probe=_probe) / "catalog.sqlite3"


def task_bundle_dir(
    task_id: str, *, _data_dir: Path | None = None, _probe: _PathProbe | None = None
) -> Path:
    """Return the task bundle directory for an already validated task ID."""

    return bundle_root(_data_dir=_data_dir, _probe=_probe) / "tasks" / task_id


def config_file_path(*, _probe: _PathProbe | None = None) -> Path:
    """Return the sole default user configuration file path."""

    probe = _probe_or_default(_probe)
    isolated = active_root(_probe=probe)
    if isolated is not None:
        return isolated / "config" / "config.toml"
    return Path(_ambient_dirs(probe).user_config_dir) / "config.toml"


def cache_dir(*, _probe: _PathProbe | None = None) -> Path:
    """Return the platform-native or isolated user cache directory."""

    probe = _probe_or_default(_probe)
    isolated = active_root(_probe=probe)
    if isolated is not None:
        return isolated / "cache"
    return Path(_ambient_dirs(probe).user_cache_dir)


def state_dir(*, _probe: _PathProbe | None = None) -> Path:
    """Return the platform-native or isolated user state directory."""

    probe = _probe_or_default(_probe)
    isolated = active_root(_probe=probe)
    if isolated is not None:
        return isolated / "state"
    return Path(_ambient_dirs(probe).user_state_dir)


def log_dir(*, _probe: _PathProbe | None = None) -> Path:
    """Return the platform-native or isolated user log directory."""

    probe = _probe_or_default(_probe)
    isolated = active_root(_probe=probe)
    if isolated is not None:
        return isolated / "log"
    return Path(_ambient_dirs(probe).user_log_dir)


def runtime_dir(*, _probe: _PathProbe | None = None) -> Path:
    """Return the platform-native or isolated runtime endpoint directory.

    The service control, secret-ingress, and human-control endpoints bind beneath this
    directory, so deriving it from the isolation root is what makes an isolated runtime unable
    to reach — or be reached by — the ambient service singleton.
    """

    probe = _probe_or_default(_probe)
    isolated = active_root(_probe=probe)
    if isolated is not None:
        return isolated / "run"
    return Path(_ambient_dirs(probe).user_runtime_path)


def service_generation_path(*, _probe: _PathProbe | None = None) -> Path:
    """Return the fixed locked-state service-generation metadata path."""

    root = state_dir(_probe=_probe)
    verify_private_local_bundle(root, _probe=_probe)
    ensure_owner_only_dir(root)
    verify_private_local_bundle(root, _probe=_probe)
    return root / "service-generation.json"


def setup_marker_path(*, _probe: _PathProbe | None = None) -> Path:
    """Return the fixed first-run setup-wizard completion marker path."""

    root = state_dir(_probe=_probe)
    verify_private_local_bundle(root, _probe=_probe)
    ensure_owner_only_dir(root)
    verify_private_local_bundle(root, _probe=_probe)
    return root / "setup-wizard.json"


def unlock_throttle_path(*, _probe: _PathProbe | None = None) -> Path:
    """Return the fixed passphrase-throttle metadata path."""

    root = state_dir(_probe=_probe)
    verify_private_local_bundle(root, _probe=_probe)
    ensure_owner_only_dir(root)
    verify_private_local_bundle(root, _probe=_probe)
    return root / "unlock-throttle.json"


def _absolute_without_resolving(path: Path) -> Path:
    return path if path.is_absolute() else Path.cwd() / path


def _existing_ancestor(path: Path) -> Path:
    candidate = path
    while not candidate.exists():
        parent = candidate.parent
        if parent == candidate:
            return candidate
        candidate = parent
    return candidate


def _ancestors_inclusive(path: Path) -> tuple[Path, ...]:
    return (path, *path.parents)


def _is_beneath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _reject_symlink_components(path: Path) -> None:
    absolute = _absolute_without_resolving(path)
    parts = absolute.parts
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise PathSafetyError("path_contains_symlink") from exc
        if stat.S_ISLNK(mode):
            raise PathSafetyError("path_contains_symlink")


def _check_owner_and_mode(path: Path, probe: _PathProbe) -> None:
    if not path.exists():
        return
    try:
        facts = path.stat()
    except OSError:
        probe.diagnostic("path_posix_facts_unavailable")
        return
    if hasattr(facts, "st_uid") and facts.st_uid != probe.effective_uid:
        raise PathSafetyError("path_not_owned")
    try:
        mode = stat.S_IMODE(facts.st_mode)
    except (AttributeError, TypeError, ValueError):
        probe.diagnostic("path_mode_unavailable")
        return
    if mode & 0o077:
        raise PathSafetyError("permissions_too_broad")


def _check_shared_temp(path: Path, probe: _PathProbe) -> None:
    for root in probe.fixed_shared_temps:
        try:
            resolved_root = root.resolve(strict=False)
        except OSError:
            resolved_root = root
        if _is_beneath(path, resolved_root):
            raise PathSafetyError("path_shared_temp")

    try:
        shared_temp = probe.shared_temp.resolve(strict=False)
        temp_mode = stat.S_IMODE(shared_temp.stat().st_mode)
    except OSError:
        probe.diagnostic("shared_temp_probe_failed")
        return
    if temp_mode & 0o077 and _is_beneath(path, shared_temp):
        raise PathSafetyError("path_shared_temp")


def _check_repository(path: Path) -> None:
    for ancestor in _ancestors_inclusive(path):
        if any((ancestor / marker).exists() for marker in _VCS_MARKERS):
            raise PathSafetyError("path_in_repository")


def _contains_component(path: Path, name: str) -> bool:
    return name in path.parts


def _check_sync_folder(path: Path, probe: _PathProbe) -> None:
    ancestors = _ancestors_inclusive(path)
    if _contains_component(path, "Dropbox"):
        raise PathSafetyError("path_in_sync_folder")
    if any(
        (ancestor / marker).exists() for ancestor in ancestors for marker in _SYNC_METADATA_NAMES
    ):
        raise PathSafetyError("path_in_sync_folder")

    if probe.platform == "darwin":
        mobile_documents = probe.home / "Library" / "Mobile Documents"
        cloud_storage = probe.home / "Library" / "CloudStorage"
        if _is_beneath(path, mobile_documents):
            raise PathSafetyError("path_in_sync_folder")
        if any(ancestor.name.endswith(".icloud") for ancestor in ancestors):
            raise PathSafetyError("path_in_sync_folder")
        if _is_beneath(path, cloud_storage) and path != cloud_storage:
            raise PathSafetyError("path_in_sync_folder")

    if probe.platform.startswith("linux"):
        for index, component in enumerate(path.parts):
            if component not in _LINUX_SYNC_COMPONENTS:
                continue
            component_path = Path(*path.parts[: index + 1])
            parent = component_path.parent
            if any((parent / marker).exists() for marker in _SYNC_METADATA_NAMES):
                raise PathSafetyError("path_in_sync_folder")


def _decode_mount_field(value: str) -> str:
    result = value
    for escaped, literal in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        result = result.replace(escaped, literal)
    return result


def _linux_mount_fstype(path: Path, mount_table: str) -> str | None:
    matches: list[tuple[int, str]] = []
    for line in mount_table.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        mount_point = Path(_decode_mount_field(fields[1]))
        try:
            resolved_mount = mount_point.resolve(strict=False)
        except OSError:
            resolved_mount = mount_point
        if _is_beneath(path, resolved_mount):
            matches.append((len(resolved_mount.parts), fields[2]))
    if not matches:
        return None
    return max(matches, key=lambda item: item[0])[1]


def _check_network_filesystem(path: Path, probe: _PathProbe) -> None:
    stat_target = _existing_ancestor(path)
    if probe.platform.startswith("linux"):
        try:
            os.statvfs(stat_target)
            mount_table = probe.mount_table()
            filesystem = _linux_mount_fstype(path, mount_table)
        except Exception:
            probe.diagnostic("network_filesystem_probe_failed")
            return
        if filesystem in _NETWORK_FILESYSTEMS_LINUX:
            raise PathSafetyError("path_on_network_filesystem")
        return

    if probe.platform == "darwin":
        try:
            filesystem = probe.macos_fstype(stat_target)
        except Exception:
            probe.diagnostic("network_filesystem_probe_failed")
            return
        if filesystem is None:
            probe.diagnostic("network_filesystem_probe_failed")
        elif filesystem in _NETWORK_FILESYSTEMS_MACOS:
            raise PathSafetyError("path_on_network_filesystem")


def _record_location_diagnostic(path: Path, probe: _PathProbe) -> None:
    approved_roots = (
        Path(probe.platform_dirs.user_data_dir),
        Path(probe.platform_dirs.user_config_dir),
        Path(probe.platform_dirs.user_cache_dir),
        Path(probe.platform_dirs.user_state_dir),
        Path(probe.platform_dirs.user_log_dir),
    )
    try:
        approved = tuple(root.resolve(strict=False) for root in approved_roots)
    except OSError:
        probe.diagnostic("approved_path_probe_failed")
        return
    if not _is_beneath(path, probe.home) and not any(_is_beneath(path, root) for root in approved):
        probe.diagnostic("path_outside_user_home")


def verify_private_local_bundle(path: Path, *, _probe: _PathProbe | None = None) -> None:
    """Verify a bundle path without creating or modifying it.

    Checks execute in the contractually fixed order and stop at the first
    reason-coded unsafe condition.
    """

    probe = _probe_or_default(_probe)
    _reject_symlink_components(path)
    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        raise PathSafetyError("path_contains_symlink") from exc
    _check_owner_and_mode(resolved, probe)
    _check_shared_temp(resolved, probe)
    _check_repository(resolved)
    _check_sync_folder(resolved, probe)
    _check_network_filesystem(resolved, probe)
    _record_location_diagnostic(resolved, probe)


def ensure_owner_only_dir(path: Path) -> None:
    """Create an owner-only directory if absent, then verify owner and mode."""

    _reject_symlink_components(path)
    missing: list[Path] = []
    candidate = path
    while not candidate.exists():
        missing.append(candidate)
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
    try:
        for directory in reversed(missing):
            directory.mkdir(mode=_PRIVATE_DIR_MODE)
            created = directory.lstat()
            if stat.S_IMODE(created.st_mode) != _PRIVATE_DIR_MODE:
                raise PathSafetyError("permissions_too_broad")
        facts = path.lstat()
    except PathSafetyError:
        raise
    except OSError as exc:
        raise PathSafetyError("permissions_too_broad") from exc
    _check_private_dir(facts)


def existing_owner_only_dir(path: Path) -> bool:
    """Verify an owner-only directory without creating anything; False when it is absent.

    The read-side twin of ``ensure_owner_only_dir``: a status read must not create the state it
    reports on, but an existing directory still has to pass the same symlink, owner and mode checks.
    """

    _reject_symlink_components(path)
    try:
        facts = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise PathSafetyError("permissions_too_broad") from exc
    _check_private_dir(facts)
    return True


def _check_private_dir(facts: os.stat_result) -> None:
    if stat.S_ISLNK(facts.st_mode) or not stat.S_ISDIR(facts.st_mode):
        raise PathSafetyError("path_contains_symlink")
    effective_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if hasattr(facts, "st_uid") and facts.st_uid != effective_uid:
        raise PathSafetyError("path_not_owned")
    if stat.S_IMODE(facts.st_mode) != _PRIVATE_DIR_MODE:
        raise PathSafetyError("permissions_too_broad")
