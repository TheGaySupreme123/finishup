"""What a server on another machine may read here outside a project (ADR-051 decision 5).

A FinishUP server on another machine reads nothing on this computer by itself: the workspace
agent (``finishup.client.workspace_agent``) answers its bounded calls. Inside the claimed worktree
the agent reads under the existing fences. Outside it, each server target has an **outside-read
mode**, this client's own fact, as approved-check trust is (ADR-051 decisions 5 and 12): it is
never sent to the server, and nothing the server sends changes it. Every remote kind
(``local_port``, ``ssh``, ``https``) offers the same two modes, with the same behaviour:

* ``local``: the agent answers the server's outside reads as a FinishUP service on this computer
  would answer them. The server's own admitted-root policy chooses the roots, and the adapters'
  own fences and the agent's protected directories still hold; the folders of this record also
  admit the task inputs beneath them (below), and no other read asks them.
* ``listed``: the agent reads outside the worktree only beneath a folder this computer's owner
  listed for that target with ``finishup server folders add``; anything else is refused.

In both modes a listed folder also admits the task inputs beneath it for that target's
claim-bound sessions, even where the server's own input-root policy names no root there
(maintainer decision, 2026-11-07): in ``local`` mode beside the server's own roots, in ``listed``
mode alone.

The owner chooses the mode when adding the target (``finishup server add``, on the trusted
console, or ``--outside-reads``), and ``finishup server folders mode NAME local|listed`` changes
it. There is no default per kind. An HTTPS target at an official FinishUP endpoint
(``OFFICIAL_ENDPOINT_HOSTS``, matched by exact hostname, and only while it trusts the system
certificate store) is not asked and is ``local`` while its owner has recorded no mode. Any other
target with no mode recorded is ``listed`` (``not_chosen``), and a record that cannot be read is
``listed`` with no folder: both fail closed.

The record is ``<target root>/config/folders.json`` (``yoetz.server-folders/1``): an owner-only
regular file of canonical JSON with exactly ``schema``, ``target_id`` (the root's own id) and
``folders`` (sorted, unique, at most ``MAX_FOLDERS``), and ``mode`` when the owner chose one. Each
folder is an absolute path an owner could admit as an input root (``admitted_input_root_valid``)
that is neither the home directory nor one that holds it. Only a remote target has such a record;
removing the target removes it with its root. Every failure is a closed reason, never a path.
Standard library and lean shared modules only.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import os
import posixpath
import secrets
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal, cast
from urllib.parse import urlsplit

from finishup.config.paths import PathSafetyError, ensure_owner_only_dir
from finishup.domain.privacy import admitted_input_root_valid
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

if TYPE_CHECKING:
    from finishup.client.targets import ServerTarget

__all__ = [
    "FOLDERS_FILE_NAME",
    "FOLDERS_SCHEMA",
    "MAX_FOLDERS",
    "OFFICIAL_ENDPOINT_HOSTS",
    "OUTSIDE_READ_MODES",
    "OUTSIDE_READ_MODE_LINES",
    "OUTSIDE_READ_QUESTION",
    "ClearOutcome",
    "FolderError",
    "FolderRecord",
    "OutsideReadMode",
    "OutsideReadSource",
    "OutsideReads",
    "add_folder",
    "clear_folders",
    "folder_admissible",
    "folder_covers",
    "folder_holds_home",
    "folders_path",
    "mode_of",
    "official_address",
    "official_endpoint",
    "outside_reads_of",
    "outside_reads_reader",
    "read_folders",
    "read_record",
    "remove_folder",
    "set_mode",
]

FOLDERS_SCHEMA: Final = "yoetz.server-folders/1"
FOLDERS_FILE_NAME: Final = "folders.json"
# Well above the eight input roots one repository's policy may admit: one server target serves
# every project this computer works on.
MAX_FOLDERS: Final = 32
_MAX_RECORD_BYTES: Final = 16_384
_FIELDS: Final = frozenset({"schema", "target_id", "folders"})
_FIELDS_WITH_MODE: Final = _FIELDS | {"mode"}
_REASONS: Final = frozenset(
    {
        "folder_invalid",
        "folder_limit",
        "folders_record_invalid",
        "folders_record_unsafe",
        "outside_read_mode_invalid",
    }
)

# ``local``: outside reads are answered as a FinishUP service on this computer answers them.
# ``listed``: only beneath a folder the owner listed for the target here.
type OutsideReadMode = Literal["local", "listed"]
# Where a target's mode came from: the owner (at 'server add', or 'server folders mode'); with no
# mode recorded, an official FinishUP endpoint ('local') or no choice yet ('listed'); or a record
# that cannot be read, which is 'listed' with no folder.
type OutsideReadSource = Literal["owner", "official_endpoint", "not_chosen", "unreadable"]
OUTSIDE_READ_MODES: Final[tuple[OutsideReadMode, ...]] = ("listed", "local")

# What the owner is asked at 'server add' (the trusted console) and in the terminal interface's
# '/server' add flow, then one plain line per mode. Fixed text, the same for every remote kind.
OUTSIDE_READ_QUESTION: Final = "What may this server read outside your projects on this computer?"
OUTSIDE_READ_MODE_LINES: Final[Mapping[OutsideReadMode, str]] = MappingProxyType(
    {
        "local": (
            "what FinishUP on this computer would read there; choose it for a server you trust "
            "as you trust this computer"
        ),
        "listed": (
            "only folders you list for it with 'finishup server folders add'; nothing else there"
        ),
    }
)

# Hostnames of official FinishUP endpoints, whose HTTPS targets are 'local' without being asked,
# as FinishUP on this computer would read. Reviewed by the maintainer, who adds each exact,
# lowercase hostname here when an official hosted endpoint exists. Empty today: none exists yet.
# A target matches only by its exact hostname, and only while it trusts the system certificate
# store: one added with --ca-file or --tls-pin never counts as official by its hostname alone.
OFFICIAL_ENDPOINT_HOSTS: Final[frozenset[str]] = frozenset()


class FolderError(Exception):
    """A bounded failure of the folders record; ``reason`` is a closed token, never a path."""

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("folder_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class FolderRecord:
    """What one target's record holds: its listed folders, and the mode its owner chose (None:
    none recorded, so ``listed``, or ``local`` for an official FinishUP endpoint)."""

    folders: tuple[str, ...] = ()
    mode: OutsideReadMode | None = None


@dataclass(frozen=True, slots=True)
class OutsideReads:
    """What the server of one target may read outside the claimed worktree, read now.

    In both modes ``folders`` admit the task inputs beneath them, whatever the server's own policy
    admits (ADR-051 decision 5, amended 2026-11-07); in ``listed`` mode they are all it reads.
    """

    mode: OutsideReadMode
    folders: tuple[str, ...] = ()
    source: OutsideReadSource = "not_chosen"


# An agent bound to no record, and a record that cannot be read: 'listed' with no folder.
_LISTED_NOTHING: Final = OutsideReads("listed", (), "unreadable")

type ClearOutcome = Literal["absent", "cleared", "reset_to_listed"]


def official_address(
    kind: str, base_url: str | None, *, ca_file: str | None, tls_pin: str | None
) -> bool:
    """Whether a target of ``kind`` at ``base_url`` is an official FinishUP endpoint.

    Only an ``https`` target whose exact hostname is in ``OFFICIAL_ENDPOINT_HOSTS`` and that
    trusts the system certificate store: one with its own ``ca_file`` or ``tls_pin`` never counts
    by hostname. ``server add`` asks this before the target exists, to skip the mode question.
    """

    if kind != "https" or base_url is None or ca_file is not None or tls_pin is not None:
        return False
    try:
        host = urlsplit(base_url).hostname
    except ValueError:
        return False
    return host is not None and host in OFFICIAL_ENDPOINT_HOSTS


def official_endpoint(record: ServerTarget) -> bool:
    """Whether ``record`` is an HTTPS target at an official FinishUP endpoint
    (``official_address``)."""

    return official_address(
        record.kind, record.base_url, ca_file=record.ca_file, tls_pin=record.tls_pin
    )


def mode_of(record: ServerTarget, found: FolderRecord) -> tuple[OutsideReadMode, OutsideReadSource]:
    """The mode ``record`` is in given its readable record ``found``, and where it came from.

    The owner's recorded choice; else ``local`` for an official FinishUP endpoint; else
    ``listed``, the fail-closed value of a target whose owner has not chosen (every kind alike).
    """

    if found.mode is not None:
        return found.mode, "owner"
    if official_endpoint(record):
        return "local", "official_endpoint"
    return "listed", "not_chosen"


def folders_path(root: Path) -> Path:
    """``<target root>/config/folders.json``."""

    return root / "config" / FOLDERS_FILE_NAME


def folder_covers(path: str, folders: Sequence[str]) -> bool:
    """Whether absolute, normalized ``path`` is one of ``folders`` or lies beneath one.

    Exact spelling: a differently cased or linked spelling of an admitted folder is not covered,
    so the comparison errs toward refusing.
    """

    return any(path == folder or path.startswith(folder.rstrip("/") + "/") for folder in folders)


def folder_holds_home(folder: str, *, home: str | None = None) -> bool:
    """Whether ``folder`` is the home directory or one of its ancestors, by spelling.

    Such a folder would open the home directory's private trees (``Library``, dot folders) to a
    read beneath it, which the outside read's own home rule leaves to a root at the home
    directory itself; it is never admitted for a server here. The filesystem root holds every
    home directory and is refused by the input-root rule already.
    """

    base = posixpath.normpath(home if home is not None else os.path.expanduser("~"))
    if not base.startswith("/"):
        return True  # no usable home: refuse rather than guess
    return folder == base or base.startswith(folder.rstrip("/") + "/")


def _well_formed(folder: object) -> bool:
    return (
        type(folder) is str
        and admitted_input_root_valid(folder)
        and posixpath.normpath(folder) == folder
    )


def _identity(path: str) -> tuple[int, int] | None:
    try:
        facts = os.stat(path)
    except OSError:
        return None
    return facts.st_dev, facts.st_ino


def _holds_home_by_identity(folder: str) -> bool:
    """Whether ``folder`` is the home directory or an ancestor of it under another spelling
    (another case on a case-insensitive volume, a bind mount); unexaminable counts as holding."""

    found = _identity(folder)
    if found is None:
        return True
    current = posixpath.normpath(os.path.expanduser("~"))
    while current not in {"", "/"}:
        if _identity(current) == found:
            return True
        current = posixpath.dirname(current)
    return False


def folder_admissible(folder: str) -> bool:
    """Whether the owner may admit ``folder`` for a server: the input-root shape in normal form,
    neither the home directory nor a folder that holds it (by spelling or by identity), and not
    in the home directory's private trees.

    ``add_folder`` applies this rule under the registry lock; ``server folders add`` asks it
    first too, so the owner is never asked to consent to a folder that would then be refused.
    """

    from finishup.adapters.home_project_reads import home_private_location

    return (
        _well_formed(folder)
        and not folder_holds_home(folder)
        and not _holds_home_by_identity(folder)
        and not home_private_location(folder)
    )


def _decode(encoded: bytes, target_id: str) -> FolderRecord:
    try:
        if not encoded.endswith(b"\n"):
            raise ValueError("trailer")
        value = strict_json_parse(encoded[:-1])
    except ValueError:
        raise FolderError("folders_record_invalid") from None
    if type(value) is not dict:
        raise FolderError("folders_record_invalid")
    source = cast(dict[str, JsonValue], value)
    folders = source.get("folders")
    mode = source.get("mode")
    if (
        frozenset(source) not in (_FIELDS, _FIELDS_WITH_MODE)
        or source.get("schema") != FOLDERS_SCHEMA
        or source.get("target_id") != target_id
        or type(folders) is not list
        or ("mode" in source and mode not in OUTSIDE_READ_MODES)
    ):
        raise FolderError("folders_record_invalid")
    items = cast(list[object], folders)
    if len(items) > MAX_FOLDERS or not all(_well_formed(item) for item in items):
        raise FolderError("folders_record_invalid")
    ordered = tuple(sorted(set(cast(list[str], items)), key=str.encode))
    record = FolderRecord(ordered, cast(OutsideReadMode | None, mode))
    if list(ordered) != items or _encode(target_id, record) != encoded:
        raise FolderError("folders_record_invalid")
    return record


def _encode(target_id: str, record: FolderRecord) -> bytes:
    document: dict[str, JsonValue] = {
        "schema": FOLDERS_SCHEMA,
        "target_id": target_id,
        "folders": list(record.folders),
    }
    if record.mode is not None:
        document["mode"] = record.mode
    return canonical_encode(document) + b"\n"


def _read_owner_only(path: Path) -> bytes | None:
    """The bytes of an owner-only regular file; ``None`` when absent; fail closed otherwise."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise FolderError("folders_record_unsafe") from None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_RECORD_BYTES
        ):
            raise FolderError("folders_record_unsafe")
        chunks: list[bytes] = []
        remaining = _MAX_RECORD_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        raise FolderError("folders_record_unsafe") from None
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if len(data) > _MAX_RECORD_BYTES:
        raise FolderError("folders_record_unsafe")
    return data


def _write(root: Path, target_id: str, record: FolderRecord) -> None:
    """Atomically replace the record (owner-only temporary file, fsync, rename)."""

    path = folders_path(root)
    try:
        ensure_owner_only_dir(path.parent)
    except PathSafetyError:
        raise FolderError("folders_record_unsafe") from None
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    encoded = _encode(target_id, record)
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short_write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise FolderError("folders_record_unsafe") from None


def read_record(root: Path, target_id: str) -> FolderRecord:
    """The record of the target at ``root``: its listed folders and the mode its owner set.

    No record is ``FolderRecord()``: no folder listed, no mode set. Raises ``FolderError``
    (``folders_record_unsafe`` or ``folders_record_invalid``) for a record that is not
    owner-only, a link, too large, malformed, or another target's.
    """

    encoded = _read_owner_only(folders_path(root))
    if encoded is None:
        return FolderRecord()
    return _decode(encoded, target_id)


def read_folders(root: Path, target_id: str) -> tuple[str, ...]:
    """The folders the owner listed for the target at ``root``; ``()`` when none were.

    Raises as ``read_record`` does.
    """

    return read_record(root, target_id).folders


def add_folder(root: Path, target_id: str, folder: str) -> bool:
    """List ``folder`` for the target at ``root``; False when it already was. The mode is kept.

    ``folder`` is already canonical (the caller applied the input-root rule on the trusted
    console). A damaged record is refused, never replaced: ``clear_folders`` is its way out.
    Callers hold ``targets.registry_lock()``.
    """

    if not folder_admissible(folder):
        raise FolderError("folder_invalid")
    current = read_record(root, target_id)
    if folder in current.folders:
        return False
    if len(current.folders) >= MAX_FOLDERS:
        raise FolderError("folder_limit")
    folders = tuple(sorted({*current.folders, folder}, key=str.encode))
    _write(root, target_id, FolderRecord(folders, current.mode))
    return True


def remove_folder(root: Path, target_id: str, folder: str) -> bool:
    """Stop listing ``folder`` (compared in normal form); False when it was not listed. The mode
    is kept."""

    wanted = posixpath.normpath(folder) if folder else folder
    current = read_record(root, target_id)
    if wanted not in current.folders:
        return False
    folders = tuple(item for item in current.folders if item != wanted)
    _write(root, target_id, FolderRecord(folders, current.mode))
    return True


def set_mode(root: Path, target_id: str, mode: OutsideReadMode) -> bool:
    """Record ``mode`` as the owner's choice for the target at ``root``; False when it already
    was. The listed folders are kept.

    A recorded mode is the owner's own: ``server add`` records the answer to its question (or
    ``--outside-reads``), and ``finishup server folders mode`` changes it. A recorded ``local``
    widens what the server reads, so callers record it only after the owner typed the target's
    name on the trusted console, an official endpoint's included, whose ``local`` would otherwise
    follow the reviewed list of official hosts. A damaged record is refused, never replaced:
    ``clear_folders`` is its way out. Callers hold ``targets.registry_lock()``.
    """

    if mode not in OUTSIDE_READ_MODES:
        raise FolderError("outside_read_mode_invalid")
    current = read_record(root, target_id)
    if current.mode == mode:
        return False
    _write(root, target_id, FolderRecord(current.folders, mode))
    return True


def clear_folders(root: Path, target_id: str) -> ClearOutcome:
    """Stop listing every folder for the target at ``root``; the way back from a damaged record.

    ``absent`` when there was nothing to clear. ``cleared`` when a readable record listed a
    folder: none is listed now, and the mode its owner set, if any, is kept. ``reset_to_listed``
    when the record could not be read: it is replaced by one that lists nothing in ``listed``
    mode, the state a record that cannot be read already stood for, so clearing it never widens
    what the server may read (an official endpoint's included); the owner chooses ``local``
    again with ``set_mode``. A link is replaced itself, never its target; anything but
    a file or a link is refused. Callers hold ``targets.registry_lock()``.
    """

    path = folders_path(root)
    try:
        facts = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return "absent"
    except OSError:
        raise FolderError("folders_record_unsafe") from None
    if not (stat.S_ISREG(facts.st_mode) or stat.S_ISLNK(facts.st_mode)):
        raise FolderError("folders_record_unsafe")
    try:
        current = read_record(root, target_id)
    except FolderError:
        current = None
    if current is not None:
        if not current.folders:
            return "absent"
        _write(root, target_id, FolderRecord((), current.mode))
        return "cleared"
    # Replaced in one rename, which replaces a link itself and never its target: there is no
    # moment without a record, when an official endpoint's 'local' could apply.
    _write(root, target_id, FolderRecord((), "listed"))
    return "reset_to_listed"


def outside_reads_of(root: Path, record: ServerTarget) -> OutsideReads:
    """What the server of the remote target ``record`` (whose root is ``root``) may read outside
    the claimed worktree on this computer, read now.

    Never raises: a record that cannot be read, or is another target's, is ``listed`` with no
    folder. With no mode recorded it is ``listed``, or ``local`` for an official endpoint
    (``mode_of``). A folder that holds the home directory is never listed here; one recorded
    under another home directory than this process's is left out rather than read.
    """

    try:
        found = read_record(root, record.target_id)
    except Exception:  # noqa: BLE001 - an unreadable record is 'listed' with no folder
        return _LISTED_NOTHING
    folders = tuple(folder for folder in found.folders if not folder_holds_home(folder))
    mode, source = mode_of(record, found)
    return OutsideReads(mode, folders, source)


def _read_nothing() -> OutsideReads:
    return _LISTED_NOTHING


def _salt_matches(recorded: str | None, claim_salt: bytes) -> bool:
    try:
        salt = base64.b64decode(recorded or "", validate=True)
    except (TypeError, ValueError, binascii.Error):
        return False
    return bool(salt) and hmac.compare_digest(salt, claim_salt)


def outside_reads_reader(
    root: Path | None = None, *, claim_salt: bytes | None = None
) -> Callable[[], OutsideReads]:
    """A reader of what one remote target's server may read outside the worktree, bound to that
    target now.

    The workspace agent of a connection is built with one; it reads the record on every outside
    read, in the agent's worker thread, so a change of mode or folders takes effect at the next
    call. The target is fixed here, when the agent is built: ``root``, or the root this process
    uses now, which is taken only with ``claim_salt`` (the salt the connection's claim was made
    under) and only when it is the target whose salt that is, since this process's selection may
    name another server. A later change of this process's selection (``server use``, or another
    target probed under ``selection_override``) therefore never makes the agent read another
    target's record. Neither ``root`` nor ``claim_salt``, a root that is not a remote target, a
    target record that cannot be read and a salt that does not match all bind a reader that
    answers ``listed`` with no folder, whatever mode any target is in. Never raises.
    """

    from finishup.client.targets import read_target
    from finishup.config.paths import active_root

    if root is None and claim_salt is None:
        return _read_nothing  # the selection alone never says which server the agent serves
    try:
        where = active_root() if root is None else root
        record = None if where is None else read_target(where)
    except Exception:  # noqa: BLE001 - an unreadable target reads nothing outside (fail closed)
        return _read_nothing
    if (
        where is None
        or record is None
        or not record.is_remote
        or (claim_salt is not None and not _salt_matches(record.claim_salt, claim_salt))
    ):
        return _read_nothing
    bound_root, bound = where, record
    return lambda: outside_reads_of(bound_root, bound)
