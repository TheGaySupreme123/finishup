"""FinishUP-managed Codex evaluator runtimes, capability checks, and binding diagnosis.

The subscription evaluator runs the newest installed Codex release at or above the floor that
passes a capability check (ADR-006 capability amendment). Binding it to an ordinary host
installation would couple AI-powered review to the host's package manager: a routine update would
replace the bytes at the bound path after they were checked. This module keeps the *evaluator
runtime* separate from the *host installation*:

* each checked release is retained as a private copy of its native executable and the
  ``codex-code-mode-host`` helper beside it, under
  ``<bundle>/external-runtimes/codex-evaluator/<source identity>/``, with the
  :class:`~finishup.adapters.providers.codex_capability.CodexCapabilityRecord` that admitted it;
* :func:`check_codex_capability` runs the schema-subset check and the zero-inference app-server
  probe against the retained bytes themselves, so what was checked is what launches;
* the launch fence (``verify_local_binding``) re-hashes both files against the committed record
  before every child, and :func:`diagnose_codex_binding` classifies a persisted binding into one
  closed structural token without starting a process or reading any credential.

A newer everyday Codex is adopted by the next ``setup`` or ``repair``; earlier retained releases
stay as fallbacks until ``runtime remove`` deletes them.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Awaitable, Callable, Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, Literal

from finishup.adapters.providers.codex_app_server import (
    CODEX_CODE_MODE_HOST_NAME,
    CODEX_EVALUATOR_CONFIG,
    CODEX_EVALUATOR_CONFIG_SHA256,
    CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
    CodexAppServerProfile,
    codex_capability_probe,
    codex_code_mode_host_path,
    prepare_codex_home,
)
from finishup.adapters.providers.codex_capability import (
    CODEX_CAPABILITY_RECORD_NAME,
    CODEX_EVALUATOR_CAPABILITY_PROFILE,
    CodexCapabilityRecord,
    CodexPlatform,
    SubprocessRunner,
    check_app_server_schema,
    codex_source_identity,
    codex_version_key,
    generate_app_server_schema,
    host_codex_platform,
    parse_codex_source_identity,
    read_capability_record,
    require_admitted_version,
    validate_capability_binding,
    write_capability_record,
)
from finishup.adapters.providers.data_use_catalog import data_use_record_for_endpoint
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
    "RetainedRuntime",
    "check_codex_capability",
    "diagnose_codex_binding",
    "host_codex_platform",
    "inspect_managed_runtime",
    "is_managed_runtime_path",
    "managed_code_mode_host_path",
    "managed_runtime_dir",
    "managed_runtime_path",
    "managed_runtime_root",
    "provision_codex_runtime",
    "remove_managed_runtime",
    "retain_codex_runtime",
    "retained_runtimes",
    "runtime_mutation_lock",
]

_STORE_PARTS: Final = ("external-runtimes", "codex-evaluator")
_EXECUTABLE_NAME: Final = "codex"
_RETAINED_NAMES: Final = frozenset(
    {_EXECUTABLE_NAME, CODEX_CODE_MODE_HOST_NAME, CODEX_CAPABILITY_RECORD_NAME}
)
_RETAINED_MODE: Final = 0o500
# The native executables are tens of MiB; the bound only stops an unbounded copy.
_MAX_EXECUTABLE_BYTES: Final = 1024 * 1024 * 1024
_CHUNK_BYTES: Final = 1024 * 1024
_NPM_TIMEOUT_SECONDS: Final = 600.0
_CODEX_NPM_PACKAGE: Final = "@openai/codex"
# The thread the capability probe starts names a model only so Codex can echo it back; nothing is
# sampled, so any id works. The dedicated home's own model is checked by the readiness probe.
_PROBE_MODEL: Final = "gpt-6-luna"

# ``incomplete``: the executable is retained but its code-mode host is absent. ``unchecked``: both
# files are retained but no current capability record vouches for them yet. ``verified`` requires
# both files and a current record whose digests they still match.
type ManagedRuntimeState = Literal[
    "absent", "verified", "incomplete", "unchecked", "changed", "invalid", "unsafe"
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
    "codex_runtime_version_unsupported",
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


def managed_runtime_root(bundle: Path) -> Path:
    """Owner-private directory holding every retained evaluator runtime of one data bundle."""

    return bundle.joinpath(*_STORE_PARTS)


def managed_runtime_dir(bundle: Path, source_identity: str) -> Path:
    """The directory one retained release lives in, named for its source identity."""

    if parse_codex_source_identity(source_identity) is None:
        raise ValueError("codex_runtime_binding_invalid")
    return managed_runtime_root(bundle) / source_identity


def managed_runtime_path(bundle: Path, source_identity: str) -> Path:
    """The one stable path the retained runtime for ``source_identity`` is bound at."""

    return managed_runtime_dir(bundle, source_identity) / _EXECUTABLE_NAME


def managed_code_mode_host_path(bundle: Path, source_identity: str) -> Path:
    """The retained code-mode host, beside the retained executable where Codex looks for it."""

    return codex_code_mode_host_path(managed_runtime_path(bundle, source_identity))


def is_managed_runtime_path(bundle: Path, executable: Path) -> bool:
    """Whether ``executable`` is a retained runtime of this bundle (by location, not bytes)."""

    return (
        executable.name == _EXECUTABLE_NAME
        and executable.parent.parent == managed_runtime_root(bundle)
        and parse_codex_source_identity(executable.parent.name) is not None
    )


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


def _store_directory(bundle: Path, source_identity: str, *, create: bool) -> Path:
    directory = managed_runtime_dir(bundle, source_identity)
    try:
        if create:
            ensure_owner_only_dir(directory)
        verify_private_local_bundle(directory)
    except PathSafetyError as error:
        raise ValueError("codex_evaluator_runtime_store_unsafe") from error
    return directory


def _store_file_state(directory: Path, name: str) -> Literal["present", "absent", "invalid"]:
    try:
        facts = (directory / name).lstat()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "invalid"
    if not stat.S_ISREG(facts.st_mode) or not facts.st_mode & stat.S_IXUSR:
        return "invalid"
    return "present"


def inspect_managed_runtime(bundle: Path, source_identity: str) -> ManagedRuntimeState:
    """Classify one retained release without creating, repairing, or launching anything."""

    try:
        directory = managed_runtime_dir(bundle, source_identity)
    except ValueError:
        return "invalid"
    try:
        directory.lstat()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unsafe"
    try:
        verify_private_local_bundle(directory)
    except (PathSafetyError, OSError):
        return "unsafe"
    executable = _store_file_state(directory, _EXECUTABLE_NAME)
    if executable != "present":
        return executable
    host = _store_file_state(directory, CODEX_CODE_MODE_HOST_NAME)
    if host == "absent":
        return "incomplete"
    if host != "present":
        return host
    try:
        record = read_capability_record(directory)
    except FileNotFoundError:
        return "unchecked"
    except ValueError:
        return "invalid"
    if not record.current or record.source_identity != source_identity:
        return "unchecked"
    try:
        executable_digest = _file_digest(directory / _EXECUTABLE_NAME)
        host_digest = _file_digest(directory / CODEX_CODE_MODE_HOST_NAME)
    except (OSError, ValueError):
        return "invalid"
    if (executable_digest, host_digest) != (
        record.executable_sha256,
        record.code_mode_host_sha256,
    ):
        return "changed"
    return "verified"


@dataclass(frozen=True, slots=True)
class RetainedRuntime:
    """One retained release of the host platform, as found in the store (not yet re-checked)."""

    source_identity: str
    runtime_version: str
    path: Path


def retained_runtimes(bundle: Path, platform: CodexPlatform) -> tuple[RetainedRuntime, ...]:
    """Every retained release of ``platform`` whose executable is present, newest first."""

    root = managed_runtime_root(bundle)
    try:
        entries = tuple(root.iterdir())
    except OSError:
        return ()
    found: list[RetainedRuntime] = []
    for entry in entries:
        parsed = parse_codex_source_identity(entry.name)
        if parsed is None or parsed[0] != platform:
            continue
        if _store_file_state(entry, _EXECUTABLE_NAME) != "present":
            continue
        found.append(RetainedRuntime(entry.name, parsed[1], entry / _EXECUTABLE_NAME))
    found.sort(key=lambda item: codex_version_key(item.runtime_version) or (0, 0, 0), reverse=True)
    return tuple(found)


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


def _stage_copy(descriptor: int, directory: Path) -> tuple[Path, str]:
    """Hash while copying into a private temporary file; nothing is committed yet."""

    temporary: Path | None = None
    try:
        handle, temporary_name = tempfile.mkstemp(prefix=".retain-", dir=directory)
        temporary = Path(temporary_name)
        with os.fdopen(handle, "wb") as output:
            digest = _digest_descriptor(descriptor, output.write)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, _RETAINED_MODE)
    except OSError as error:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise ValueError("codex_evaluator_runtime_store_unavailable") from error
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return temporary, digest


def _existing_digest(path: Path) -> str | None:
    try:
        return _file_digest(path)
    except (OSError, ValueError):
        return None


def retain_codex_runtime(source: Path, *, bundle: Path, source_identity: str) -> Path:
    """Copy one native executable and its code-mode host into the owner-private store.

    ``source`` is the native executable; its code-mode host is taken only from beside it, where
    Codex itself looks. Both are opened before anything is written and hashed while copied. A
    store file already holding the same bytes is kept as-is (same inode), which keeps setup,
    repair and install idempotent and never disturbs an in-flight evaluator process. When either
    file changes, the capability record is removed first, so a record never vouches for bytes it
    did not check. The returned bound path is the executable; it is not admitted until a
    capability check commits a new record.
    """

    directory = _store_directory(bundle, source_identity, create=True)
    sources = (
        (source, _EXECUTABLE_NAME, "codex_runtime_not_found"),
        (
            codex_code_mode_host_path(source),
            CODEX_CODE_MODE_HOST_NAME,
            "codex_runtime_code_mode_host_missing",
        ),
    )
    opened: list[tuple[int, str]] = []
    staged: list[tuple[Path, str]] = []
    try:
        for path, name, missing_token in sources:
            descriptor, _facts = _open_source(path, missing_token=missing_token)
            opened.append((descriptor, name))
        changed: list[tuple[Path, str]] = []
        for descriptor, name in opened:
            temporary, digest = _stage_copy(descriptor, directory)
            staged.append((temporary, name))
            if _existing_digest(directory / name) != digest:
                changed.append((temporary, name))
        if changed:
            try:
                (directory / CODEX_CAPABILITY_RECORD_NAME).unlink(missing_ok=True)
                for temporary, name in changed:
                    os.replace(temporary, directory / name)
            except OSError as error:
                raise ValueError("codex_evaluator_runtime_store_unavailable") from error
            _fsync_directory(directory)
    finally:
        for descriptor, _name in opened:
            os.close(descriptor)
        for temporary, _name in staged:
            temporary.unlink(missing_ok=True)
    if inspect_managed_runtime(bundle, source_identity) not in {"verified", "unchecked"}:
        raise ValueError("codex_evaluator_runtime_store_unavailable")
    return directory / _EXECUTABLE_NAME


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


def remove_managed_runtime(bundle: Path, source_identity: str) -> bool:
    """Delete one retained release (executable, code-mode host, and record).

    Returns whether anything was removed. The caller owns the in-use check. An unsafe store is
    refused rather than cleaned, and nothing outside the release's own directory is touched.
    """

    directory = managed_runtime_dir(bundle, source_identity)
    try:
        directory.lstat()
    except FileNotFoundError:
        return False
    _store_directory(bundle, source_identity, create=False)
    removed = False
    try:
        for entry in directory.iterdir():
            if entry.name in _RETAINED_NAMES or entry.name.startswith((".retain-", ".record-")):
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
    platform: CodexPlatform,
    npm: Path,
    resolve_wrapper: Callable[[Path], tuple[Path, str]],
    runner: NpmRunner | None = None,
) -> tuple[Path, str]:
    """Download the newest stable Codex with the operator's npm and retain only its native files.

    The package is installed with lifecycle scripts disabled into a fresh owner-private staging
    prefix inside the store; ``resolve_wrapper`` applies the wrapper/native manifest checks and
    returns the native executable and its release. Only the native executable and its code-mode
    host are retained; the staging prefix is always removed. Returns the retained path and
    release; the copy is admitted only after a capability check commits its record.
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
            f"{_CODEX_NPM_PACKAGE}@latest",
        )
        try:
            returncode = (_run_npm if runner is None else runner)(argv, staging)
        except (subprocess.TimeoutExpired, TimeoutError):
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
        native, version = resolve_wrapper(wrapper)
        identity = codex_source_identity(platform, version)
        return retain_codex_runtime(native, bundle=bundle, source_identity=identity), version
    finally:
        shutil.rmtree(staging, ignore_errors=True)


type CapabilityProbe = Callable[[CodexAppServerProfile], Awaitable[None]]


def _regular_executable(path: Path, *, missing_token: str) -> None:
    try:
        facts = path.lstat()
    except FileNotFoundError as error:
        raise ValueError(missing_token) from error
    except OSError as error:
        raise ValueError("codex_runtime_unavailable") from error
    if not stat.S_ISREG(facts.st_mode) or not facts.st_mode & stat.S_IXUSR:
        raise ValueError("codex_runtime_executable_invalid")


async def check_codex_capability(
    executable: Path,
    *,
    runtime_version: str,
    platform: CodexPlatform,
    scratch_parent: Path,
    probe: CapabilityProbe | None = None,
    runner: SubprocessRunner | None = None,
) -> CodexCapabilityRecord:
    """Run the capability check against one retained runtime; return the record it earned.

    In order, with the first failure as one closed token: the release is a stable version at or
    above the floor; the executable and its code-mode host are regular owner-executable files;
    the app-server schema the binary generates carries the reviewed subset; and a zero-inference
    app-server session under a scratch home (never a real one) passes
    :func:`~finishup.adapters.providers.codex_app_server.codex_capability_probe`. The scratch
    directory is always removed. Nothing is committed here; the caller writes the record.
    """

    require_admitted_version(runtime_version)
    identity = codex_source_identity(platform, runtime_version)
    _regular_executable(executable, missing_token="codex_runtime_not_found")
    host = codex_code_mode_host_path(executable)
    _regular_executable(host, missing_token="codex_runtime_code_mode_host_missing")
    try:
        executable_digest = _file_digest(executable)
        host_digest = _file_digest(host)
    except OSError as error:
        raise ValueError("codex_runtime_unavailable") from error
    subset_digest = check_app_server_schema(
        generate_app_server_schema(executable, scratch_parent=scratch_parent, runner=runner)
    )
    record = CodexCapabilityRecord(
        runtime_version=runtime_version,
        source_identity=identity,
        platform_os=platform.os,
        platform_architecture=platform.architecture,
        executable_sha256=executable_digest,
        code_mode_host_sha256=host_digest,
        app_server_schema_sha256=subset_digest,
        isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
    )
    try:
        scratch = Path(tempfile.mkdtemp(prefix=".probe-", dir=scratch_parent))
        os.chmod(scratch, 0o700)
    except OSError as error:
        raise ValueError("codex_evaluator_runtime_store_unavailable") from error
    try:
        home = scratch / "home"
        prepare_codex_home(home)
        profile = CodexAppServerProfile(
            provider_id="openai-codex",
            endpoint_profile_id="codex-chatgpt-subscription",
            endpoint_profile_version="1.0.0",
            executable_path=executable,
            executable_sha256=executable_digest,
            runtime_version=runtime_version,
            source_identity=identity,
            app_server_schema_sha256=subset_digest,
            capability_cell_sha256=record.digest,
            capability_profile=CODEX_EVALUATOR_CAPABILITY_PROFILE,
            capability_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
            codex_home=home,
            isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
            model=_PROBE_MODEL,
            reasoning_effort="low",
            timeout_seconds=30,
            data_use_profile=data_use_record_for_endpoint("codex-chatgpt-subscription").profile,
            capability_record=record,
        )
        await (codex_capability_probe if probe is None else probe)(profile)
    except PathSafetyError as error:
        raise ValueError("codex_evaluator_runtime_store_unsafe") from error
    except FileNotFoundError as error:
        raise ValueError("codex_runtime_not_found") from error
    except OSError as error:
        raise ValueError("codex_runtime_unavailable") from error
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return record


def commit_capability_record(bundle: Path, record: CodexCapabilityRecord) -> Path:
    """Commit ``record`` beside its retained release, after re-checking the bytes still match."""

    directory = _store_directory(bundle, record.source_identity, create=False)
    try:
        current = (
            _file_digest(directory / _EXECUTABLE_NAME),
            _file_digest(directory / CODEX_CODE_MODE_HOST_NAME),
        )
    except OSError as error:
        raise ValueError("codex_evaluator_runtime_store_unavailable") from error
    if current != (record.executable_sha256, record.code_mode_host_sha256):
        raise ValueError("codex_runtime_executable_changed")
    write_capability_record(directory, record)
    _fsync_directory(directory)
    return directory / _EXECUTABLE_NAME


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
    config: ExternalRuntimeProfileConfig, platform: CodexPlatform, now: datetime | None
) -> tuple[CapabilityState, str | None]:
    if now is not None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("codex_runtime_capability_time_invalid")
        if now >= datetime.fromisoformat(CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT):
            return "evidence_stale", None
    try:
        bound = validate_capability_binding(
            source_identity=config.source_identity,
            executable_sha256=config.executable_sha256,
            runtime_version=config.runtime_version,
            app_server_schema_sha256=config.app_server_schema_sha256,
            capability_cell_sha256=config.capability_cell_sha256,
            capability_profile=config.capability_profile,
            capability_evidence_expires_at=config.capability_evidence_expires_at,
            isolated_config_sha256=config.isolated_config_sha256,
            expected_isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
            expected_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
        )
    except ValueError as error:
        token = str(error)
        if token == "codex_runtime_profile_outdated":
            return "profile_outdated", None
        return "unsupported", token
    if bound != platform:
        return "unsupported", "codex_runtime_capability_unsupported"
    return "current", None


def _executable_state(path: Path, expected: str | None) -> ExecutableState:
    """Classify one bound file; ``expected=None`` checks only that it is an owner executable."""

    try:
        facts = path.stat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unreadable"
    if not stat.S_ISREG(facts.st_mode) or not facts.st_mode & stat.S_IXUSR:
        return "invalid"
    if expected is None:
        return "admitted"
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


def _bound_record_host_digest(
    config: ExternalRuntimeProfileConfig, executable: ExecutableState
) -> tuple[ExecutableState, str | None]:
    """(record-adjusted executable state, the code-mode host digest the record pins)."""

    try:
        record = read_capability_record(Path(config.executable_path).parent)
    except FileNotFoundError:
        return ("missing" if executable == "admitted" else executable), None
    except ValueError:
        return ("changed" if executable == "admitted" else executable), None
    if (
        not record.current
        or record.digest != config.capability_cell_sha256
        or record.executable_sha256 != config.executable_sha256
        or record.runtime_version != config.runtime_version
        or record.source_identity != config.source_identity
        or record.app_server_schema_sha256 != config.app_server_schema_sha256
    ):
        return ("changed" if executable == "admitted" else executable), None
    return executable, record.code_mode_host_sha256


def diagnose_codex_binding(
    config: ExternalRuntimeProfileConfig, *, now: datetime | None = None
) -> CodexBindingDiagnosis:
    """Classify one binding by local structure only: no process, login, or credential read.

    ``ready`` is returned only after the unchanged launch fence (``verify_local_binding``) also
    accepts the binding, so this function can never report a binding usable that a dispatch would
    refuse. A timezone-aware ``now`` adds the capability-evidence expiry check dispatch applies.
    A binding written under an earlier contract (an exact pinned cell) is ``profile_outdated``;
    its bytes are still compared with the digest it names, so replaced bytes stay visible.
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
        platform = host_codex_platform()
    except ValueError:
        return CodexBindingDiagnosis(
            "codex_runtime_platform_unsupported", "platform_unsupported", "not_checked", home
        )
    capability, unsupported_token = _capability_state(config, platform, now)
    executable = _executable_state(executable_path, config.executable_sha256)
    host_expected: str | None = None
    if capability == "current":
        executable, host_expected = _bound_record_host_digest(config, executable)
    host = _executable_state(codex_code_mode_host_path(executable_path), host_expected)
    runtime_files = executable if executable != "admitted" else host
    if capability == "evidence_stale":
        state = "codex_runtime_capability_evidence_stale"
    elif capability == "unsupported":
        state = unsupported_token or "codex_runtime_capability_unsupported"
    elif runtime_files in _EXECUTABLE_TOKENS:
        state = _EXECUTABLE_TOKENS[runtime_files]
    elif capability == "profile_outdated":
        state = "codex_runtime_profile_outdated"
    elif home in _HOME_TOKENS:
        state = _HOME_TOKENS[home]
    else:
        state = _confirm_launch_fence(config)
    if state not in CODEX_BINDING_STATES:
        state = "codex_runtime_binding_invalid"
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
