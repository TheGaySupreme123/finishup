"""Retained virtual environments for running releases, independent of package replacement.

Installed bridges, services, hooks and upgrade commands enter these copies. The stable installation remains
owned by its package manager. Snapshots contain runtime files, never application state or a vault.
The manager lock serializes creation, supported upgrades and pruning; a shared process lease keeps
an in-use generation out of pruning. No environment variable can select or bypass a generation.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import importlib.util
import json
import marshal
import os
import py_compile
import re
import shutil
import stat
import sys
import tempfile
import time
import types
import warnings
from collections.abc import Generator, Mapping
from pathlib import Path
from typing import Final, Literal, cast

from yoetz.config.foreign_write import foreign_write

_MARKER: Final = "yoetz-release-runtime.json"
_SCHEMA: Final = "yoetz.release-runtime/1"
_LEASE: Final = ".in-use"
_STAGING: Final = ".creation.json"
_KEY: Final = re.compile(r"[0-9a-f]{64}\Z")
_PIN: Final = "yoetz-instance-pin.json"
# Part of every generation key. A generation built by an earlier layout (no bytecode, or
# bytecode reused from a timestamp pyc) never matches, so the next start builds a complete one
# and prunes the old one once unused.
_LAYOUT: Final = b"yoetz.release-runtime-layout/3:unchecked-hash-bytecode\x00"
NOT_OWNED_TOKEN: Final = "release_runtime_not_owned"
# Kept open for the lifetime of this process; intentionally not inherited by unrelated children.
_process_lease: int | None = None
_original_interpreter: str | None = None


class ReleaseRuntimeError(ValueError):
    """A bounded refusal, never an installation path or package-manager output."""

    def __init__(
        self, token: str, *, area: Literal["environment", "interpreter"] | None = None
    ) -> None:
        super().__init__(token)
        # Which tree another account can write: the installed environment, or the base
        # interpreter its ``bin/python`` resolves to. A closed label, never a path.
        self.area = area


def _refuse_foreign_write(
    facts: os.stat_result, *, area: Literal["environment", "interpreter"]
) -> None:
    """Refuse a runtime object another account can write; the owner's private group is fine."""

    kind = foreign_write(facts)
    if kind is not None:
        raise ReleaseRuntimeError(f"release_runtime_{kind}_writable", area=area)


class ReleaseRuntimeIOError(OSError):
    """A closed operation label plus errno; never retains an exception message or path."""

    def __init__(
        self,
        error: OSError,
        phase: Literal[
            "snapshot",
            "snapshot_copy",
            "snapshot_compile",
            "snapshot_seal",
            "snapshot_publish",
            "lease",
            "exec",
        ],
    ) -> None:
        super().__init__(error.errno, "release_runtime_io")
        self.phase = phase


def _private_directory(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ReleaseRuntimeError("release_runtime_unsafe")


def _manager(prefix: Path) -> Path:
    if not prefix.is_absolute() or prefix.is_symlink():
        raise ReleaseRuntimeError("release_runtime_unsafe")
    return prefix.parent / f".{prefix.name}-releases"


def retained_runtime_directory(prefix: Path) -> Path:
    """Where the generations of the installation at ``prefix`` live: its private sibling."""

    return _manager(prefix)


def _another_account_owns(path: Path) -> bool:
    try:
        return path.stat().st_uid != os.geteuid()
    except OSError:
        return False


def _manager_directory(root: Path) -> None:
    """Create (when absent) and verify the manager directory this account serves from.

    The generations a process runs from must be this account's own, so the directory holding
    them must be too. An installation another account made (root, in a container image whose
    agent runs as a non-root ``USER``) therefore cannot serve this account: an existing
    directory owned by another account, or none and a parent this account cannot create it in,
    is ``release_runtime_not_owned`` rather than the generic ``release_runtime_unsafe`` or a
    bare permission error. The ownership requirement itself is unchanged.
    """

    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EPERM, errno.EROFS} and _another_account_owns(
            root.parent
        ):
            raise ReleaseRuntimeError(NOT_OWNED_TOKEN) from None
        raise
    info = root.lstat()
    if stat.S_ISDIR(info.st_mode) and info.st_uid != os.geteuid():
        raise ReleaseRuntimeError(NOT_OWNED_TOKEN)
    _private_directory(root)


def _manager_refusal(root: Path) -> ReleaseRuntimeError | None:
    """Read-only twin of ``_manager_directory``: the refusal it would raise, creating nothing."""

    try:
        info = root.lstat()
    except FileNotFoundError:
        parent = root.parent
        writable = os.access(
            parent, os.W_OK | os.X_OK, effective_ids=os.access in os.supports_effective_ids
        )
        if _another_account_owns(parent) and not writable:
            return ReleaseRuntimeError(NOT_OWNED_TOKEN)
        return None
    if stat.S_ISDIR(info.st_mode) and info.st_uid != os.geteuid():
        return ReleaseRuntimeError(NOT_OWNED_TOKEN)
    return None


def _open_lock(path: Path) -> int:
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        os.close(fd)
        raise ReleaseRuntimeError("release_runtime_unsafe")
    return fd


@contextlib.contextmanager
def release_update_lock(prefix: Path, *, timeout: float = 10.0) -> Generator[Path]:
    """Fence snapshots against the supported package replacement and cleanup paths."""

    root = _manager(prefix)
    _manager_directory(root)
    fd = _open_lock(root / ".lock")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ReleaseRuntimeError("release_runtime_busy") from None
                time.sleep(min(0.025, max(0.0, deadline - time.monotonic())))
        yield root
    finally:
        os.close(fd)


def _read_regular(path: Path, *, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ReleaseRuntimeError("release_runtime_unsafe")
        _refuse_foreign_write(info, area="environment")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            result = stream.read(limit + 1)
        if len(result) > limit:
            raise ReleaseRuntimeError("release_runtime_unsafe")
        return result
    finally:
        os.close(fd)


def _release_key(prefix: Path) -> str:
    """Installed RECORDs select a generation; no version-only cache aliases two artifacts."""

    records = sorted(prefix.glob("lib/python*/site-packages/*.dist-info/RECORD"))
    if not records or not (prefix / "pyvenv.cfg").is_file():
        raise ReleaseRuntimeError("release_runtime_unsupported")
    digest = hashlib.sha256(_LAYOUT)
    paths = [prefix / "pyvenv.cfg", *records]
    if (prefix / _PIN).exists():
        paths.append(prefix / _PIN)
    for path in paths:
        relative = path.relative_to(prefix).as_posix().encode()
        data = _read_regular(path, limit=8_388_608)
        digest.update(len(relative).to_bytes(8, "big") + relative)
        digest.update(len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def _refuse_foreign_interpreter_chain(link: Path) -> None:
    """Whoever can write the interpreter or its directories can swap it between runs."""

    target = link.resolve(strict=True)
    for item in (target, target.parent, target.parent.parent):
        _refuse_foreign_write(item.stat(), area="interpreter")


def _revalidate_interpreter_links(generation: Path) -> None:
    """Re-check the external interpreter a retained generation links to, at every reuse.

    A generation copies the environment but links its base interpreter, which stays outside the
    sealed tree. Group membership or modes can change after the copy was made, so the same
    foreign-write rule is applied again before any process enters the generation.
    """

    try:
        entries = list((generation / "bin").iterdir())
    except OSError as error:
        raise ReleaseRuntimeIOError(error, "snapshot") from None
    for entry in entries:
        if entry.is_symlink():
            try:
                _refuse_foreign_interpreter_chain(entry)
            except OSError as error:
                raise ReleaseRuntimeIOError(error, "snapshot") from None


def _members(prefix: Path) -> tuple[tuple[Path, tuple[int, int, int, int]], ...]:
    """Enumerate only the environment, refusing mutable external package links."""

    members: list[tuple[Path, tuple[int, int, int, int]]] = []
    # Another account able to write the prefix itself could swap a whole subtree.
    _refuse_foreign_write(prefix.lstat(), area="environment")
    roots = [prefix / "bin", prefix / "lib", prefix / "pyvenv.cfg"]
    roots.extend(prefix / name for name in ("include", "share") if (prefix / name).exists())
    if (prefix / _PIN).exists():
        roots.append(prefix / _PIN)
    pending = roots[:]
    while pending:
        path = pending.pop()
        info = path.lstat()
        relative = path.relative_to(prefix)
        if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}:
            continue
        area: Literal["environment", "interpreter"] = "environment"
        if stat.S_ISLNK(info.st_mode):
            # Python executables are normally links to the package-manager/system interpreter.
            # Retain the resolved base-interpreter path; a copied ELF interpreter may have
            # origin-relative libpython linkage. Package replacement does not change the base.
            if relative.parts[0] != "bin" or not re.fullmatch(r"python(?:3(?:\.\d+)?)?", path.name):
                raise ReleaseRuntimeError("release_runtime_external_link")
            info = path.stat()
            area = "interpreter"
            _refuse_foreign_interpreter_chain(path)
        _refuse_foreign_write(info, area=area)
        if stat.S_ISDIR(info.st_mode):
            pending.extend(path.iterdir())
        elif stat.S_ISREG(info.st_mode):
            if path.suffix == ".egg-link":
                raise ReleaseRuntimeError("release_runtime_external_link")
            if path.suffix == ".pth":
                for line in path.read_text().splitlines():
                    if not line or line.startswith(("#", "import ", "import\t")):
                        continue
                    if not (path.parent / line).resolve().is_relative_to(prefix.resolve()):
                        raise ReleaseRuntimeError("release_runtime_external_link")
            if path.name == "direct_url.json":
                direct: object = json.loads(path.read_bytes())
                if isinstance(direct, dict) and cast(dict[str, object], direct).get("dir_info") == {
                    "editable": True
                }:
                    raise ReleaseRuntimeError("release_runtime_external_link")
            members.append((relative, (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)))
        else:
            raise ReleaseRuntimeError("release_runtime_unsafe")
    return tuple(sorted(members))


def _marker(prefix: Path) -> dict[str, str] | None:
    path = prefix / _MARKER
    if not path.exists() and not path.is_symlink():
        return None
    try:
        value: object = json.loads(_read_regular(path, limit=4096))
    except OSError, ValueError:
        raise ReleaseRuntimeError("release_runtime_invalid") from None
    if not isinstance(value, dict):
        raise ReleaseRuntimeError("release_runtime_invalid")
    fields = cast(dict[str, object], value)
    if set(fields) != {"schema", "origin", "key"}:
        raise ReleaseRuntimeError("release_runtime_invalid")
    schema, origin, key = fields["schema"], fields["origin"], fields["key"]
    if (
        schema != _SCHEMA
        or not isinstance(origin, str)
        or not Path(origin).is_absolute()
        or not isinstance(key, str)
        or not _KEY.fullmatch(key)
        or prefix != _manager(Path(origin)) / key
    ):
        raise ReleaseRuntimeError("release_runtime_invalid")
    return {"schema": _SCHEMA, "origin": origin, "key": key}


def _prepare_locked(prefix: Path, root: Path) -> Path:
    _discard_abandoned_copies(root)
    key = _release_key(prefix)
    target = root / key
    if target.exists() or target.is_symlink():
        _private_directory(target)
        if target.stat().st_mode & 0o222:
            raise ReleaseRuntimeError("release_runtime_incomplete")
        marker = _marker(target)
        if marker is None or marker["origin"] != str(prefix):
            raise ReleaseRuntimeError("release_runtime_invalid")
        _revalidate_interpreter_links(target)
        return target
    before = _members(prefix)
    temporary = Path(tempfile.mkdtemp(prefix=".creating-", dir=root))
    try:
        (temporary / _STAGING).write_text(
            json.dumps({"schema": _SCHEMA, "origin": str(prefix), "key": key})
        )
        (temporary / _STAGING).chmod(0o600)
        for relative, _facts in before:
            source, destination = prefix / relative, temporary / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            # copyfile creates independent bytes even if uv installed from a hard-linked cache.
            if source.is_symlink():
                destination.symlink_to(source.resolve(strict=True))
            else:
                try:
                    shutil.copyfile(source, destination, follow_symlinks=False)
                    destination.chmod(0o700 if os.access(source, os.X_OK) else 0o600)
                except OSError as error:
                    raise ReleaseRuntimeIOError(error, "snapshot_copy") from None
        if before != _members(prefix) or key != _release_key(prefix):
            raise ReleaseRuntimeError("release_runtime_changed_retry")
        (temporary / _MARKER).write_text(
            json.dumps({"schema": _SCHEMA, "origin": str(prefix), "key": key}, sort_keys=True)
            + "\n"
        )
        (temporary / _MARKER).chmod(0o600)
        try:
            _compile_bytecode(prefix, temporary, target)
        except OSError as error:
            raise ReleaseRuntimeIOError(error, "snapshot_compile") from None
        lease = _open_lock(temporary / _LEASE)
        os.close(lease)
        try:
            for path in temporary.rglob("*"):
                if path.is_file() and not path.is_symlink() and path.name != _LEASE:
                    path.chmod(0o500 if os.access(path, os.X_OK) else 0o400)
            for path in sorted(temporary.rglob("*"), reverse=True):
                if path.is_dir():
                    path.chmod(0o500)
        except OSError as error:
            raise ReleaseRuntimeIOError(error, "snapshot_seal") from None
        try:
            # macOS may require a writable source directory for rename. Keep only the
            # private staging root writable until publication, under the manager lock.
            # Consumers cannot acquire that lock or a lease until sealing completes.
            temporary.rename(target)
            try:
                target.chmod(0o500)
            except OSError:
                # This call created the unpublished/unleased generation. Remove it rather
                # than leave a writable root that a later prepare could mistake for ready.
                _remove_copy(target)
                raise
        except OSError as error:
            raise ReleaseRuntimeIOError(error, "snapshot_publish") from None
        return target
    finally:
        if temporary.exists():
            _remove_copy(temporary)


def _compile_bytecode(prefix: Path, staging: Path, published: Path) -> None:
    """Write unchecked-hash bytecode beside every copied module before the tree is sealed.

    A sealed generation is read-only, so an interpreter could never cache what it compiles and
    every serving start (service, bridge, each hook) would recompile the whole package: seconds
    on a slow filesystem, enough to miss a host's hook or handshake deadline. Unchecked-hash
    pycs never consult source mtimes, which the copy does not preserve; the generation is
    immutable, so nothing can make them stale. ``__pycache__`` is fixed (never
    ``sys.pycache_prefix``) and the optimization level is 0, as the ``-I`` bootstrap loads it.

    Hash-based bytecode the installation already holds (checked or unchecked, PEP 552) is reused
    when its embedded source hash matches the copied source and no other account can write it:
    only the flags are rewritten, which costs a hash instead of a compile. Timestamp bytecode
    (the default of ``uv tool install --compile-bytecode`` and of an ordinary run) cannot prove
    the source bytes, so it is compiled fresh. Everything else is compiled with the published file name. A module this
    interpreter cannot compile (a file meant for another Python) still compiles at import.
    """

    tag: object = getattr(sys.implementation, "cache_tag", None)
    if type(tag) is not str:
        return  # An implementation that disables bytecode caching.
    # A dependency's SyntaxWarning must not reach a hook's stderr.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        _compile_sources(prefix, staging, published, tag)


# 1980-01-01: any non-empty SOURCE_DATE_EPOCH makes py_compile, and so uv's --compile-bytecode,
# write checked-hash pycs, which a generation can verify and reuse; the value itself is only
# read by build backends, and zip archives cannot hold earlier timestamps.
HASH_BYTECODE_EPOCH: Final = "315532800"


def hash_bytecode_environment(base: Mapping[str, str]) -> dict[str, str]:
    """``base`` for one owned install child, so its compiled bytecode is checked-hash.

    Set only in the child's environment, never in this process. An epoch the caller already
    exports is kept; any non-empty value selects checked-hash bytecode.
    """

    environment = dict(base)
    if not environment.get("SOURCE_DATE_EPOCH"):
        environment["SOURCE_DATE_EPOCH"] = HASH_BYTECODE_EPOCH
    return environment


def _reusable_bytecode(installed: Path, source: bytes) -> bytes | None:
    """The installed pyc as an unchecked-hash pyc of ``source``, or None when not provably it."""

    try:
        fd = os.open(installed, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        facts = os.fstat(fd)
        if not stat.S_ISREG(facts.st_mode) or facts.st_size > 67_108_864:
            return None
        if foreign_write(facts) is not None or foreign_write(installed.parent.lstat()):
            return None
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read()
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) < 16 or data[:4] != importlib.util.MAGIC_NUMBER:
        return None
    # Only a hash-based pyc (PEP 552: checked 0b11 or unchecked 0b01) names the source bytes it
    # was compiled from. A timestamp pyc proves a whole-second mtime and a size, which an edit
    # within the same second at equal length keeps, so it is never reused: it is compiled fresh.
    flags = int.from_bytes(data[4:8], "little")
    if flags not in {0b01, 0b11}:
        return None
    source_hash = importlib.util.source_hash(source)
    if data[8:16] != source_hash:
        return None
    # The hash vouches for the header only; a truncated or corrupt payload is compiled instead.
    try:
        code: object = marshal.loads(data[16:])
    except EOFError, ValueError, TypeError:
        return None
    if type(code) is not types.CodeType:
        return None
    return data[:4] + (0b1).to_bytes(4, "little") + source_hash + data[16:]


def _compile_sources(prefix: Path, staging: Path, published: Path, tag: str) -> None:
    for source in sorted(staging.joinpath("lib").rglob("*.py")):
        if source.is_symlink() or not source.is_file():
            continue
        relative = source.relative_to(staging)
        cache = source.parent / "__pycache__"
        cache.mkdir(mode=0o700, exist_ok=True)
        name = f"{source.stem}.{tag}.pyc"
        origin = prefix / relative
        reused = _reusable_bytecode(origin.parent / "__pycache__" / name, source.read_bytes())
        if reused is not None:
            fd = os.open(cache / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(reused)
            continue
        try:
            py_compile.compile(
                str(source),
                cfile=str(cache / name),
                dfile=str(published / relative),
                doraise=True,
                optimize=0,
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            )
        except py_compile.PyCompileError:
            continue


def prepare_release_runtime(prefix: Path) -> Path:
    """Create/reuse a complete generation without exposing a partial copy."""

    with release_update_lock(prefix) as root:
        return _prepare_locked(prefix, root)


def _remove_copy(path: Path) -> None:
    """Make only this owned copy's directories writable for bounded removal."""

    path.chmod(0o700)
    for member in path.rglob("*"):
        if member.is_dir() and not member.is_symlink():
            member.chmod(0o700)
    shutil.rmtree(path)


def _discard_abandoned_copies(root: Path) -> None:
    # The exclusive manager lock proves no constructor is active. A creation marker, not a
    # directory-name guess, authorizes removing a copy abandoned by a crashed constructor.
    for path in root.iterdir():
        if not re.fullmatch(r"\.creating-[a-z0-9_]{8}", path.name):
            continue
        try:
            _private_directory(path)
            value: object = json.loads(_read_regular(path / _STAGING, limit=4096))
            if not isinstance(value, dict):
                continue
            fields = cast(dict[str, object], value)
            origin, key = fields.get("origin"), fields.get("key")
            if (
                set(fields) != {"schema", "origin", "key"}
                or fields.get("schema") != _SCHEMA
                or type(origin) is not str
                or not Path(origin).is_absolute()
                or _manager(Path(origin)) != root
                or type(key) is not str
                or not _KEY.fullmatch(key)
            ):
                continue
        except OSError, ValueError:
            continue
        _remove_copy(path)


def prune_release_runtimes(prefix: Path, *, wait_seconds: float = 0.0) -> tuple[int, int]:
    """Remove only our unused completed generations; never signal a running process."""

    with release_update_lock(prefix) as root:
        return _prune_locked(root, wait_seconds=wait_seconds)


def _prune_locked(
    root: Path, *, keep: Path | None = None, wait_seconds: float = 0.0
) -> tuple[int, int]:
    _discard_abandoned_copies(root)
    removed = retained = 0
    deadline = time.monotonic() + max(0.0, wait_seconds)
    for path in sorted(root.iterdir()):
        if not _KEY.fullmatch(path.name) or path == keep:
            continue
        _private_directory(path)
        if _marker(path) is None:
            raise ReleaseRuntimeError("release_runtime_invalid")
        fd = _open_lock(path / _LEASE)
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        retained += 1
                        break
                    # Disposal observes the lease, not a guessed shutdown delay: a daemon can
                    # release its singleton just before interpreter teardown closes its lease.
                    time.sleep(min(0.025, remaining))
                    continue
                _remove_copy(path)
                removed += 1
                break
        finally:
            os.close(fd)
    return removed, retained


def adopt_release_lease(descriptor: int, interpreter: str) -> None:
    """Adopt the descriptor carried by our fixed exec bootstrap, never an environment selector."""

    global _process_lease, _original_interpreter
    prefix = Path(sys.prefix)
    if _marker(prefix) is None or not os.path.samestat(
        os.fstat(descriptor), (prefix / _LEASE).stat()
    ):
        raise ReleaseRuntimeError("release_runtime_invalid")
    os.set_inheritable(descriptor, False)
    _process_lease = descriptor
    _original_interpreter = interpreter


def original_module_launcher(argv0: Path) -> tuple[str, ...] | None:
    """Retain a python -m host registration across the internal runtime handoff."""

    marker = _marker(Path(sys.prefix))
    if marker is None or _original_interpreter is None:
        return None
    origin = Path(marker["origin"])
    if (
        argv0.name == "__main__.py"
        and argv0.parent.name == "yoetz"
        and argv0.is_relative_to(origin)
    ):
        return (str(Path(_original_interpreter).resolve()), "-m", "yoetz")
    return None


def installation_prefix() -> Path:
    """The package-manager prefix, distinct from a retained process runtime."""

    prefix = Path(sys.prefix)
    marker = _marker(prefix)
    return prefix if marker is None else Path(marker["origin"])


FOREIGN_WRITE_TOKENS: Final = frozenset(
    {"release_runtime_group_writable", "release_runtime_world_writable"}
)
# Refusals the installation cannot outgrow by retrying: each surface names the token and its
# repair instead of the generic "could not be verified".
OWNERSHIP_TOKENS: Final = FOREIGN_WRITE_TOKENS | {NOT_OWNED_TOKEN}


def installed_runtime_refusal() -> ReleaseRuntimeError | None:
    """Read-only: the ownership refusal a serving process of this install would hit.

    That is another account able to write the runtime, or a runtime another account installed
    (``release_runtime_not_owned``). ``None`` for a source checkout, a runtime that verifies, or
    any other condition (those are reported where the runtime is entered). Never takes the
    manager lock or creates a copy.
    """

    try:
        prefix = Path(sys.prefix)
        marker = _marker(prefix)
        if marker is not None:
            prefix = Path(marker["origin"])
        elif sys.prefix == sys.base_prefix or not Path(__file__).resolve().is_relative_to(
            prefix.resolve()
        ):
            return None
        # Serving checks the manager directory first, so the probe does too.
        refusal = _manager_refusal(_manager(prefix))
        if refusal is not None:
            return refusal
        _release_key(prefix)
        _members(prefix)
    except ReleaseRuntimeError as error:
        return error if str(error) in OWNERSHIP_TOKENS else None
    except OSError, ValueError:
        return None
    return None


def enter_release_runtime(arguments: list[str]) -> None:
    """Re-exec installed serving processes before loading the CLI/bridge/service graph.

    Source checkouts remain ordinary development runtimes and cannot use package replacement.
    The original argv is retained for exact native host registration comparisons. The runtime
    lease travels across exec; the child checks its marker and keeps that descriptor for life.
    """

    global _process_lease
    prefix = Path(sys.prefix)
    marker = _marker(prefix)
    if marker is not None:
        # A process started inside a generation (a service spawned by a retained bridge) hands
        # off here; the linked interpreter is re-checked exactly as on reuse.
        _revalidate_interpreter_links(prefix)
        if _process_lease is None:
            # The launching process already holds the shared lease across exec. Opening another
            # lease also protects services subsequently spawned from this generation.
            with release_update_lock(Path(marker["origin"])):
                _process_lease = _open_lock(prefix / _LEASE)
                fcntl.flock(_process_lease, fcntl.LOCK_SH)
        return
    package = Path(__file__).resolve()
    if sys.prefix == sys.base_prefix or not package.is_relative_to(prefix.resolve()):
        return
    with release_update_lock(prefix) as root:
        try:
            target = _prepare_locked(prefix, root)
        except ReleaseRuntimeIOError:
            raise
        except OSError as error:
            raise ReleaseRuntimeIOError(error, "snapshot") from None
        fd = _open_lock(target / _LEASE)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            os.set_inheritable(fd, True)
        except OSError as error:
            os.close(fd)
            raise ReleaseRuntimeIOError(error, "lease") from None
        try:
            with contextlib.suppress(OSError, ReleaseRuntimeError):
                _prune_locked(root, keep=target)
            python = target / "bin/python"
            # Fixed bootstrap, no path interpolation and no shell. -I excludes ambient Python
            # search paths; sys.argv preserves the installation's original host identity.
            bootstrap = (
                "import sys; from yoetz.adapters.release_runtime import adopt_release_lease; "
                "adopt_release_lease(int(sys.argv[1]), sys.argv[2]); sys.argv = sys.argv[3:]; "
                "from yoetz.cli.entry import main; main()"
            )
            os.execv(
                str(python),
                [
                    str(python),
                    "-I",
                    "-c",
                    bootstrap,
                    str(fd),
                    sys.executable,
                    sys.argv[0],
                    *arguments,
                ],
            )
        finally:
            os.close(fd)
