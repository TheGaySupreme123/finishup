"""FinishUP-managed Codex evaluator runtime and structural binding diagnosis (issue #855).

The subscription evaluator admits exactly one reviewed native Codex executable per platform cell
(ADR-006). Binding that cell to an ordinary host installation couples AI-powered review to the
host's package manager: a routine Codex update replaces the bytes at the bound path and every later
check refuses before dispatch. This module keeps the *evaluator runtime* separate from the *host
installation*:

* a verified copy of the admitted native executable, and of the ``codex-code-mode-host`` helper it
  starts from beside itself, lives in an owner-private directory under the FinishUP data bundle,
  content-bound to the cell's pinned digests, so host updates cannot replace it;
* the copy is made only from bytes that hash to that pinned digest — from a selected local
  executable or from an explicitly authorized package-manager download — and is re-verified on
  every launch by the unchanged ``verify_local_binding`` fence;
* :func:`diagnose_codex_binding` classifies a persisted binding into one closed structural token
  without starting a process or reading any credential, so status surfaces can name the exact
  repair instead of an opaque credential-unavailable outcome.

Nothing here widens admission: an executable whose bytes are not the pinned digest is never
retained, bound, or launched.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, Literal

from finishup.adapters.providers.codex_app_server import (
    CODEX_CODE_MODE_HOST_NAME,
    CODEX_EVALUATOR_CONFIG,
    CODEX_EVALUATOR_RUNTIME_VERSION,
    CodexAppServerProfile,
    CodexEvaluatorCell,
    codex_code_mode_host_path,
    codex_evaluator_cell_for_platform,
)
from finishup.config.models import ExternalRuntimeProfileConfig
from finishup.config.paths import (
    PathSafetyError,
    ensure_owner_only_dir,
    verify_private_local_bundle,
)

__all__ = [
    "CODEX_BINDING_STATES",
    "CodexBindingDiagnosis",
    "ManagedRuntimeState",
    "diagnose_codex_binding",
    "host_codex_evaluator_cell",
    "inspect_managed_code_mode_host",
    "inspect_managed_runtime",
    "managed_code_mode_host_path",
    "managed_runtime_path",
    "managed_runtime_root",
    "provision_codex_runtime",
    "remove_managed_runtime",
    "retain_codex_runtime",
    "runtime_mutation_lock",
]

_STORE_PARTS: Final = ("external-runtimes", "codex-evaluator")
_EXECUTABLE_NAME: Final = "codex"
_RETAINED_NAMES: Final = frozenset({_EXECUTABLE_NAME, CODEX_CODE_MODE_HOST_NAME})
_RETAINED_MODE: Final = 0o500
# The admitted native executables are tens of MiB; the bound only stops an unbounded copy.
_MAX_EXECUTABLE_BYTES: Final = 1024 * 1024 * 1024
_CHUNK_BYTES: Final = 1024 * 1024
_NPM_TIMEOUT_SECONDS: Final = 600.0
_CODEX_NPM_PACKAGE: Final = "@openai/codex"

# ``incomplete``: the retained executable verifies but its code-mode host is absent (a store
# written before the host joined the cell). ``verified`` requires both files.
type ManagedRuntimeState = Literal[
    "absent", "verified", "incomplete", "changed", "invalid", "unsafe"
]
type CapabilityState = Literal[
    "current", "profile_outdated", "unsupported", "platform_unsupported", "evidence_stale"
]
type ExecutableState = Literal[
    "admitted", "changed", "missing", "invalid", "unreadable", "not_checked"
]
type HomeState = Literal[
    "ready", "missing", "unsafe", "config_missing", "config_changed", "unreadable", "not_checked"
]

# Every primary token ``diagnose_codex_binding`` can return, in precedence order. ``ready`` is the
# only state in which ``verify_local_binding`` accepts the binding.
CODEX_BINDING_STATES: Final = (
    "codex_runtime_platform_unsupported",
    "codex_runtime_binding_invalid",
    "codex_runtime_capability_evidence_stale",
    "codex_runtime_capability_unsupported",
    "codex_runtime_executable_missing",
    "codex_runtime_executable_invalid",
    "codex_runtime_executable_changed",
    "codex_runtime_profile_outdated",
    "codex_home_missing",
    "codex_home_unsafe",
    "codex_runtime_config_missing",
    "codex_runtime_config_changed",
    "codex_runtime_unavailable",
    "ready",
)


def host_codex_evaluator_cell() -> CodexEvaluatorCell:
    """The reviewed cell for the running interpreter's platform, or a closed refusal."""

    host_os = "linux" if sys.platform.startswith("linux") else sys.platform
    return codex_evaluator_cell_for_platform(host_os, platform.machine())


def managed_runtime_root(bundle: Path) -> Path:
    """Owner-private directory holding every retained evaluator runtime of one data bundle."""

    return bundle.joinpath(*_STORE_PARTS)


def managed_runtime_path(bundle: Path, cell: CodexEvaluatorCell) -> Path:
    """The one stable path the retained runtime for ``cell`` is bound at."""

    return managed_runtime_root(bundle) / cell.source_identity / _EXECUTABLE_NAME


def managed_code_mode_host_path(bundle: Path, cell: CodexEvaluatorCell) -> Path:
    """The retained code-mode host, beside the retained executable where Codex looks for it."""

    return codex_code_mode_host_path(managed_runtime_path(bundle, cell))


@contextmanager
def runtime_mutation_lock(bundle: Path) -> Generator[None]:
    """Fence retention/removal and the complete setup or repair binding transaction.

    Contention refuses immediately, including while another command awaits a login probe.
    The lock file is never unlinked, so concurrent openers always fence the same inode.
    """

    root = managed_runtime_root(bundle)
    descriptor: int | None = None
    try:
        try:
            ensure_owner_only_dir(root)
            verify_private_local_bundle(root)
            descriptor = os.open(
                root / ".mutation.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            facts = os.fstat(descriptor)
            if (
                not stat.S_ISREG(facts.st_mode)
                or facts.st_uid != os.geteuid()
                or stat.S_IMODE(facts.st_mode) & 0o077
            ):
                raise ValueError("codex_evaluator_runtime_store_unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("codex_evaluator_runtime_busy") from None
        except PathSafetyError as error:
            raise ValueError("codex_evaluator_runtime_store_unsafe") from error
        except OSError as error:
            raise ValueError("codex_evaluator_runtime_store_unavailable") from error
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _open_regular(path: Path) -> tuple[int, os.stat_result]:
    """Open one regular file without following a final symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        facts = os.fstat(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, facts


def _digest_descriptor(descriptor: int, sink: Callable[[bytes], object] | None = None) -> str:
    digest = hashlib.sha256()
    total = 0
    while chunk := os.read(descriptor, _CHUNK_BYTES):
        total += len(chunk)
        if total > _MAX_EXECUTABLE_BYTES:
            raise ValueError("codex_runtime_executable_invalid")
        digest.update(chunk)
        if sink is not None:
            sink(chunk)
    return "sha256:" + digest.hexdigest()


def _file_digest(path: Path) -> str:
    descriptor, facts = _open_regular(path)
    try:
        if not stat.S_ISREG(facts.st_mode):
            raise ValueError("codex_runtime_executable_invalid")
        return _digest_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _store_directory(bundle: Path, cell: CodexEvaluatorCell, *, create: bool) -> Path:
    directory = managed_runtime_root(bundle) / cell.source_identity
    try:
        if create:
            ensure_owner_only_dir(directory)
        verify_private_local_bundle(directory)
    except PathSafetyError as error:
        raise ValueError("codex_evaluator_runtime_store_unsafe") from error
    return directory


def _inspect_store_file(
    bundle: Path, cell: CodexEvaluatorCell, name: str, expected: str
) -> ManagedRuntimeState:
    directory = managed_runtime_root(bundle) / cell.source_identity
    try:
        directory.lstat()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unsafe"
    try:
        verify_private_local_bundle(directory)
    except PathSafetyError, OSError:
        return "unsafe"
    target = directory / name
    try:
        facts = target.lstat()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "invalid"
    if not stat.S_ISREG(facts.st_mode) or not facts.st_mode & stat.S_IXUSR:
        return "invalid"
    try:
        digest = _file_digest(target)
    except OSError, ValueError:
        return "invalid"
    return "verified" if digest == expected else "changed"


def inspect_managed_code_mode_host(bundle: Path, cell: CodexEvaluatorCell) -> ManagedRuntimeState:
    """Classify only the retained code-mode host; nothing is created, repaired, or launched."""

    return _inspect_store_file(bundle, cell, CODEX_CODE_MODE_HOST_NAME, cell.code_mode_host_sha256)


def inspect_managed_runtime(bundle: Path, cell: CodexEvaluatorCell) -> ManagedRuntimeState:
    """Classify the retained runtime without creating, repairing, or launching anything.

    ``verified`` means both the executable and its code-mode host hold the cell's pinned bytes.
    """

    executable = _inspect_store_file(bundle, cell, _EXECUTABLE_NAME, cell.executable_sha256)
    if executable != "verified":
        return executable
    host = inspect_managed_code_mode_host(bundle, cell)
    return "incomplete" if host == "absent" else host


def _open_source(path: Path, *, missing_token: str) -> tuple[int, os.stat_result]:
    try:
        descriptor, facts = _open_regular(path)
    except FileNotFoundError as error:
        raise ValueError(missing_token) from error
    except OSError as error:
        raise ValueError("codex_runtime_executable_invalid") from error
    if not stat.S_ISREG(facts.st_mode) or facts.st_size > _MAX_EXECUTABLE_BYTES:
        os.close(descriptor)
        raise ValueError("codex_runtime_executable_invalid")
    return descriptor, facts


def _copy_verified(descriptor: int, directory: Path, name: str, expected: str) -> None:
    """Hash while copying; atomically commit ``name`` only when the bytes equal ``expected``."""

    temporary: Path | None = None
    try:
        handle, temporary_name = tempfile.mkstemp(prefix=".retain-", dir=directory)
        temporary = Path(temporary_name)
        with os.fdopen(handle, "wb") as output:
            digest = _digest_descriptor(descriptor, output.write)
            output.flush()
            os.fsync(output.fileno())
        if digest != expected:
            raise ValueError("codex_runtime_capability_unsupported")
        os.chmod(temporary, _RETAINED_MODE)
        os.replace(temporary, directory / name)
        temporary = None
    except OSError as error:
        raise ValueError("codex_evaluator_runtime_store_unavailable") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def retain_codex_runtime(source: Path, *, bundle: Path, cell: CodexEvaluatorCell) -> Path:
    """Copy the admitted executable and its code-mode host into the owner-private store.

    ``source`` is the admitted native executable; its code-mode host is taken only from beside
    it, where Codex itself looks. Each copy is hashed while it is written, so bytes that changed
    after the caller's own digest check are never retained. A file that already verifies is
    reused without rewriting it, which keeps setup and repair idempotent, never disturbs an
    in-flight evaluator process, and completes a store retained before the host joined the cell.
    Both sources are opened before anything is written. The returned bound path is the
    executable; the store reports ``verified`` only when both files hold the pinned bytes.
    """

    directory = _store_directory(bundle, cell, create=True)
    target = directory / _EXECUTABLE_NAME
    if inspect_managed_runtime(bundle, cell) == "verified":
        return target
    files = (
        (source, _EXECUTABLE_NAME, cell.executable_sha256, "codex_runtime_not_found"),
        (
            codex_code_mode_host_path(source),
            CODEX_CODE_MODE_HOST_NAME,
            cell.code_mode_host_sha256,
            "codex_runtime_code_mode_host_missing",
        ),
    )
    opened: list[tuple[int, str, str]] = []
    try:
        for path, name, expected, missing_token in files:
            if _inspect_store_file(bundle, cell, name, expected) == "verified":
                continue
            descriptor, _facts = _open_source(path, missing_token=missing_token)
            opened.append((descriptor, name, expected))
        for descriptor, name, expected in opened:
            _copy_verified(descriptor, directory, name, expected)
        _fsync_directory(directory)
    finally:
        for descriptor, _name, _expected in opened:
            os.close(descriptor)
    if inspect_managed_runtime(bundle, cell) != "verified":
        raise ValueError("codex_evaluator_runtime_store_unavailable")
    return target


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def remove_managed_runtime(bundle: Path, cell: CodexEvaluatorCell) -> bool:
    """Delete the retained runtime (executable and code-mode host) for ``cell``.

    Returns whether anything was removed.

    The caller owns the in-use check. An unsafe store is refused rather than cleaned, and nothing
    outside the cell's own store directory is touched.
    """

    directory = managed_runtime_root(bundle) / cell.source_identity
    try:
        directory.lstat()
    except FileNotFoundError:
        return False
    _store_directory(bundle, cell, create=False)
    removed = False
    try:
        for entry in directory.iterdir():
            if entry.name in _RETAINED_NAMES or entry.name.startswith(".retain-"):
                if entry.is_dir() and not entry.is_symlink():
                    raise ValueError("codex_evaluator_runtime_store_unsafe")
                entry.unlink()
                removed = True
        directory.rmdir()
    except FileNotFoundError:
        pass
    except OSError as error:
        if removed:
            return True
        raise ValueError("codex_evaluator_runtime_store_unavailable") from error
    _fsync_directory(directory.parent)
    return removed


type NpmRunner = Callable[[Sequence[str], Path], int]


def _run_npm(argv: Sequence[str], cwd: Path) -> int:
    """Run one package-manager command; never capture or forward its output into tokens."""

    completed = subprocess.run(  # noqa: S603 - fixed argv authorized by the operator
        tuple(argv),
        check=False,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=_NPM_TIMEOUT_SECONDS,
    )
    return completed.returncode


def provision_codex_runtime(
    *,
    bundle: Path,
    cell: CodexEvaluatorCell,
    runtime_version: str,
    npm: Path,
    resolve_wrapper: Callable[[Path], Path],
    runner: NpmRunner | None = None,
) -> Path:
    """Download the admitted release with the operator's npm, then retain only its verified bytes.

    The package is installed with lifecycle scripts disabled into a fresh owner-private staging
    prefix inside the store; ``resolve_wrapper`` applies the exact wrapper/native manifest and
    digest checks to the result. Only the resolved native executable is retained; the staging
    prefix is always removed, so a failed or interrupted download leaves no bound state.
    """

    if not npm.is_absolute():
        raise ValueError("codex_evaluator_runtime_package_manager_unavailable")
    root = managed_runtime_root(bundle)
    try:
        ensure_owner_only_dir(root)
        verify_private_local_bundle(root)
    except PathSafetyError as error:
        raise ValueError("codex_evaluator_runtime_store_unsafe") from error
    staging = Path(tempfile.mkdtemp(prefix=".provision-", dir=root))
    try:
        os.chmod(staging, 0o700)
        argv = (
            str(npm),
            "install",
            "--prefix",
            str(staging),
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--no-package-lock",
            f"{_CODEX_NPM_PACKAGE}@{runtime_version}",
        )
        try:
            returncode = (_run_npm if runner is None else runner)(argv, staging)
        except subprocess.TimeoutExpired, TimeoutError:
            raise ValueError("codex_evaluator_runtime_download_timeout") from None
        except OSError:
            raise ValueError("codex_evaluator_runtime_package_manager_unavailable") from None
        if returncode != 0:
            raise ValueError("codex_evaluator_runtime_download_failed")
        wrapper = next(
            (
                candidate
                for candidate in (
                    staging / "node_modules" / "@openai" / "codex" / "bin" / "codex.js",
                    staging / "lib" / "node_modules" / "@openai" / "codex" / "bin" / "codex.js",
                )
                if candidate.is_file()
            ),
            None,
        )
        if wrapper is None:
            raise ValueError("codex_runtime_not_found")
        return retain_codex_runtime(resolve_wrapper(wrapper), bundle=bundle, cell=cell)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


@dataclass(frozen=True, slots=True)
class CodexBindingDiagnosis:
    """Closed structural facts about one persisted subscription binding.

    ``state`` is the single primary token (see :data:`CODEX_BINDING_STATES`); the three axes keep
    independent facts visible, so an outdated capability identity cannot hide replaced bytes.
    """

    state: str
    capability: CapabilityState
    executable: ExecutableState
    home: HomeState
    # The bound executable's sibling code-mode host. Its faults select the same
    # ``codex_runtime_executable_*`` states (the continuation is the same repair); this axis says
    # which file it was.
    code_mode_host: ExecutableState = "not_checked"

    @property
    def ready(self) -> bool:
        return self.state == "ready"


def _capability_state(
    config: ExternalRuntimeProfileConfig, cell: CodexEvaluatorCell, now: datetime | None
) -> CapabilityState:
    if now is not None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("codex_runtime_capability_time_invalid")
        if now >= datetime.fromisoformat(cell.capability_evidence_expires_at):
            return "evidence_stale"
    runtime_matches = (
        config.source_identity == cell.source_identity
        and config.executable_sha256 == cell.executable_sha256
        and config.runtime_version == CODEX_EVALUATOR_RUNTIME_VERSION
        and config.app_server_schema_sha256 == cell.app_server_schema_sha256
        and config.isolated_config_sha256 == cell.isolated_config_sha256
    )
    if not runtime_matches:
        return "unsupported"
    if (
        config.capability_profile != cell.capability_profile
        or config.capability_cell_sha256 != cell.capability_cell_sha256
        or config.capability_evidence_expires_at != cell.capability_evidence_expires_at
    ):
        return "profile_outdated"
    return "current"


def _executable_state(path: Path, expected: str) -> ExecutableState:
    try:
        facts = path.stat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unreadable"
    if not stat.S_ISREG(facts.st_mode) or not facts.st_mode & stat.S_IXUSR:
        return "invalid"
    try:
        # ``verify_local_binding`` follows the bound path; so does this read.
        digest = _file_digest(path.resolve(strict=True))
    except FileNotFoundError:
        return "missing"
    except ValueError:
        return "invalid"
    except OSError:
        return "unreadable"
    return "admitted" if digest == expected else "changed"


def _home_state(home: Path) -> HomeState:
    try:
        home.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unreadable"
    try:
        verify_private_local_bundle(home)
    except PathSafetyError:
        return "unsafe"
    except OSError:
        return "unreadable"
    try:
        current = (home / "config.toml").read_bytes()
    except FileNotFoundError:
        return "config_missing"
    except OSError:
        return "unreadable"
    return "ready" if current == CODEX_EVALUATOR_CONFIG.encode() else "config_changed"


_EXECUTABLE_TOKENS: Final[dict[ExecutableState, str]] = {
    "missing": "codex_runtime_executable_missing",
    "invalid": "codex_runtime_executable_invalid",
    "changed": "codex_runtime_executable_changed",
    "unreadable": "codex_runtime_unavailable",
}
_HOME_TOKENS: Final[dict[HomeState, str]] = {
    "missing": "codex_home_missing",
    "unsafe": "codex_home_unsafe",
    "config_missing": "codex_runtime_config_missing",
    "config_changed": "codex_runtime_config_changed",
    "unreadable": "codex_runtime_unavailable",
}


def diagnose_codex_binding(
    config: ExternalRuntimeProfileConfig, *, now: datetime | None = None
) -> CodexBindingDiagnosis:
    """Classify one binding by local structure only: no process, login, or credential read.

    ``ready`` is returned only after the unchanged launch fence (``verify_local_binding``) also
    accepts the binding, so this function can never report a binding usable that a dispatch would
    refuse. A timezone-aware ``now`` adds the capability-evidence expiry check dispatch applies.
    """

    if type(config) is not ExternalRuntimeProfileConfig:
        return CodexBindingDiagnosis(
            "codex_runtime_binding_invalid", "unsupported", "not_checked", "not_checked"
        )
    executable_path = Path(config.executable_path)
    home_path = Path(config.codex_home)
    if not executable_path.is_absolute() or not home_path.is_absolute():
        return CodexBindingDiagnosis(
            "codex_runtime_binding_invalid", "unsupported", "not_checked", "not_checked"
        )
    home = _home_state(home_path)
    try:
        selected = host_codex_evaluator_cell()
    except ValueError:
        return CodexBindingDiagnosis(
            "codex_runtime_platform_unsupported", "platform_unsupported", "not_checked", home
        )
    capability = _capability_state(config, selected, now)
    executable = _executable_state(executable_path, selected.executable_sha256)
    host = _executable_state(
        codex_code_mode_host_path(executable_path), selected.code_mode_host_sha256
    )
    runtime_files = executable if executable != "admitted" else host
    if capability == "evidence_stale":
        state = "codex_runtime_capability_evidence_stale"
    elif capability == "unsupported":
        state = "codex_runtime_capability_unsupported"
    elif runtime_files in _EXECUTABLE_TOKENS:
        state = _EXECUTABLE_TOKENS[runtime_files]
    elif capability == "profile_outdated":
        state = "codex_runtime_profile_outdated"
    elif home in _HOME_TOKENS:
        state = _HOME_TOKENS[home]
    else:
        state = _confirm_launch_fence(config)
    return CodexBindingDiagnosis(state, capability, executable, home, host)


def _confirm_launch_fence(config: ExternalRuntimeProfileConfig) -> str:
    """Re-run the authoritative launch-time check; any refusal keeps the binding not ready."""

    try:
        CodexAppServerProfile.from_config(config).verify_local_binding()
    except PathSafetyError:
        return "codex_home_unsafe"
    except FileNotFoundError:
        return "codex_runtime_executable_missing"
    except ValueError as error:
        token = str(error)
        return token if token in CODEX_BINDING_STATES else "codex_runtime_binding_invalid"
    except TypeError:
        return "codex_runtime_binding_invalid"
    except OSError:
        return "codex_runtime_unavailable"
    return "ready"
