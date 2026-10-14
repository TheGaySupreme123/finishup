"""Retained virtual environments for running releases, independent of package replacement.

Installed bridges, services, hooks and upgrade commands enter these copies. The stable installation remains
owned by its package manager. Snapshots contain runtime files, never application state or a vault.
The manager lock serializes creation, supported upgrades and pruning; a shared process lease keeps
an in-use generation out of pruning. No environment variable can select or bypass a generation.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Generator
from pathlib import Path
from typing import Final, Literal, cast

_MARKER: Final = "yoetz-release-runtime.json"
_SCHEMA: Final = "yoetz.release-runtime/1"
_LEASE: Final = ".in-use"
_STAGING: Final = ".creation.json"
_KEY: Final = re.compile(r"[0-9a-f]{64}\Z")
_PIN: Final = "yoetz-instance-pin.json"
# Kept open for the lifetime of this process; intentionally not inherited by unrelated children.
_process_lease: int | None = None
_original_interpreter: str | None = None


class ReleaseRuntimeError(ValueError):
    """A bounded refusal, never an installation path or package-manager output."""


class ReleaseRuntimeIOError(OSError):
    """A closed operation label plus errno; never retains an exception message or path."""

    def __init__(
        self,
        error: OSError,
        phase: Literal[
            "snapshot", "snapshot_copy", "snapshot_seal", "snapshot_publish", "lease", "exec"
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
    _private_directory(root, create=True)
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
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_mode & 0o022:
            raise ReleaseRuntimeError("release_runtime_unsafe")
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
    digest = hashlib.sha256()
    paths = [prefix / "pyvenv.cfg", *records]
    if (prefix / _PIN).exists():
        paths.append(prefix / _PIN)
    for path in paths:
        relative = path.relative_to(prefix).as_posix().encode()
        data = _read_regular(path, limit=8_388_608)
        digest.update(len(relative).to_bytes(8, "big") + relative)
        digest.update(len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def _members(prefix: Path) -> tuple[tuple[Path, tuple[int, int, int, int]], ...]:
    """Enumerate only the environment, refusing mutable external package links."""

    members: list[tuple[Path, tuple[int, int, int, int]]] = []
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
        if stat.S_ISLNK(info.st_mode):
            # Python executables are normally links to the package-manager/system interpreter.
            # Retain the resolved base-interpreter path; a copied ELF interpreter may have
            # origin-relative libpython linkage. Package replacement does not change the base.
            if relative.parts[0] != "bin" or not re.fullmatch(r"python(?:3(?:\.\d+)?)?", path.name):
                raise ReleaseRuntimeError("release_runtime_external_link")
            info = path.stat()
        if info.st_mode & 0o022:
            raise ReleaseRuntimeError("release_runtime_unsafe")
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
        and argv0.parent.name == "finishup"
        and argv0.is_relative_to(origin)
    ):
        return (str(Path(_original_interpreter).resolve()), "-m", "finishup")
    return None


def installation_prefix() -> Path:
    """The package-manager prefix, distinct from a retained process runtime."""

    prefix = Path(sys.prefix)
    marker = _marker(prefix)
    return prefix if marker is None else Path(marker["origin"])


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
                "import sys; from finishup.adapters.release_runtime import adopt_release_lease; "
                "adopt_release_lease(int(sys.argv[1]), sys.argv[2]); sys.argv = sys.argv[3:]; "
                "from finishup.cli.entry import main; main()"
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
