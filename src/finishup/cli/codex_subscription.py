"""Guided Codex-owned ChatGPT login for the capability-checked subscription evaluator.

The evaluator uses the newest installed Codex release at or above the floor that passes the
capability check (ADR-006 capability amendment). ``setup`` and ``repair`` gather the eligible
installations (FinishUP's retained copies, the existing binding, and discovered everyday Codex
installs), try them newest first, and bind the first one that passes the check and lists the
configured model for the dedicated home. Updating Codex is enough: the next ``repair`` or
``setup`` adopts the newer release without a FinishUP release.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
import webbrowser
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

import typer

from finishup.adapters.providers.codex_app_server import (
    CODEX_CODE_MODE_HOST_NAME,
    CODEX_EVALUATOR_CAPABILITY_PROFILE,
    CODEX_EVALUATOR_CONFIG_SHA256,
    CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
    CODEX_EVALUATOR_RUNTIME_FLOOR,
    CodexAppServerProfile,
    CodexLoginChallenge,
    CodexRuntimeStatus,
    codex_account_status,
    codex_code_mode_host_path,
    codex_login,
    codex_logout,
    prepare_codex_home,
)
from finishup.adapters.providers.codex_capability import (
    CODEX_PROBE_CLEANUP_UNCONFIRMED,
    CodexCapabilityRecord,
    CodexPlatform,
    codex_cli_version,
    codex_source_identity,
    codex_version_key,
    read_capability_record,
    require_admitted_version,
)
from finishup.adapters.providers.codex_evaluator_runtime import (
    CodexBindingDiagnosis,
    check_codex_capability,
    commit_capability_record,
    diagnose_codex_binding,
    host_codex_platform,
    inspect_managed_runtime,
    is_managed_runtime_path,
    managed_runtime_path,
    managed_runtime_root,
    provision_codex_runtime,
    remove_managed_runtime,
    retain_codex_runtime,
    retained_runtimes,
    runtime_mutation_lock,
)
from finishup.config.load import environment_config_path, load_config
from finishup.config.models import (
    CODEX_ROUTINE_REASONING_EFFORT_DEFAULT,
    ConfigError,
    ExternalRuntimeProfileConfig,
    FinishUpConfig,
)
from finishup.config.paths import PathSafetyError, bundle_root, config_file_path
from finishup.config.write import (
    cleared_external_runtime_config,
    codex_subscription_runtime,
    config_write_snapshot,
    external_runtime_binding_config,
    preflight_config_write,
    write_config_toml_if_unchanged,
)
from finishup.protocol.canonical import JsonValue, strict_json_parse

__all__ = [
    "BINDING_CONTINUATIONS",
    "RUNTIME_REBINDABLE_STATES",
    "EvaluatorCandidate",
    "ResolvedCodex",
    "binding_continuation",
    "codex_evaluator_runtime_install",
    "codex_evaluator_runtime_install_plan",
    "codex_evaluator_runtime_remove",
    "codex_evaluator_runtime_status",
    "codex_subscription_preview",
    "codex_subscription_disconnect",
    "codex_subscription_repair",
    "codex_subscription_repair_plan",
    "codex_subscription_rollback",
    "codex_subscription_setup",
    "codex_subscription_status",
    "default_codex_evaluator_executable",
    "setup_executable_selection",
    "default_codex_home",
    "default_codex_subscription_model",
    "default_codex_subscription_routine_effort",
    "default_codex_subscription_reasoning_effort",
    "describe_runtime_download",
    "diagnose_bound_runtime",
    "evaluator_candidates",
    "prompt_codex_subscription_setup",
    "resolve_codex_executable",
    "runtime_bundle",
    "select_codex_evaluator_executable",
    "subscription_failure_line",
    "subscription_failure_reason",
    "subscription_remediation",
]

_CODEX_PACKAGE_NAME: Final = "@openai/codex"
_CODEX_PACKAGE_JSON_MAX_BYTES: Final = 64 * 1024
_SUPPORTED_REASONING: Final = frozenset({"low", "medium", "high", "xhigh", "max", "ultra"})
_DEFAULT_CODEX_SUBSCRIPTION_MODEL: Final = "gpt-6-luna"
_DEFAULT_CODEX_SUBSCRIPTION_REASONING: Final = "high"
_CLOSED_FAILURE_TOKEN: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _bounded_config_operation[T](operation: Callable[[], T]) -> T:
    """Run one local config step; surface a ``ConfigError`` as its closed reason token.

    Every subscription surface (CLI commands, terminal menu, TUI runtime) already maps
    ``ValueError`` through :func:`subscription_failure_reason`; a raw ``ConfigError`` escaping
    any of them was masked as a generic ``internal_error`` exit (#520).
    """

    try:
        return operation()
    except ConfigError as error:
        raise ValueError(error.reason_code) from error


def subscription_failure_reason(error: BaseException) -> str:
    """Map subscription CLI failures to one closed token; never echo native OS text."""

    if isinstance(error, ConfigError):
        return error.reason_code
    if isinstance(error, FileNotFoundError):
        return "codex_runtime_not_found"
    if isinstance(error, TimeoutError):
        return "codex_subscription_timeout"
    if isinstance(error, OSError):
        return "codex_runtime_unavailable"
    if isinstance(error, ValueError):
        token = str(error)
        if _CLOSED_FAILURE_TOKEN.fullmatch(token) is not None:
            return token
    return "codex_subscription_failed"


_REPAIR_COMMAND: Final = "'finishup provider codex-subscription repair'"
_INSTALL_COMMAND: Final = "'finishup provider codex-subscription runtime install'"
_UPDATE_CODEX: Final = "update Codex (for example 'npm install -g @openai/codex@latest')"
_RECHECK: Final = "it checks the newest installed Codex and keeps the sign-in, model, and settings"
# Next steps for the evaluator-runtime tokens (#855). They are kept beside the subscription
# commands, not in the shared CLI remediation table, because every reason in that table must also
# carry a registered recovery directive; these are rendered only by subscription surfaces.
_SUBSCRIPTION_REMEDIATIONS: Final[Mapping[str, str]] = {
    "codex_runtime_executable_changed": (
        "the bound evaluator runtime, its code-mode host, or its capability record no longer "
        f"matches what passed FinishUP's capability check; run {_REPAIR_COMMAND} — {_RECHECK}"
    ),
    "codex_runtime_executable_missing": (
        "the bound evaluator runtime, its code-mode host, or its capability record is gone; run "
        f"{_REPAIR_COMMAND} — {_RECHECK}"
    ),
    "codex_runtime_executable_invalid": (
        "the bound evaluator executable or its code-mode host is not a regular owner-executable "
        f"file; run {_REPAIR_COMMAND}"
    ),
    "codex_runtime_code_mode_host_missing": (
        f"the selected Codex has no {CODEX_CODE_MODE_HOST_NAME} beside its native executable, "
        "which the evaluator runtime needs; select the npm package's bin/codex.js, or run "
        f"{_INSTALL_COMMAND} --download"
    ),
    "codex_runtime_profile_outdated": (
        "this FinishUP release admits Codex by capability check instead of the exact build this "
        f"binding names; review and run {_REPAIR_COMMAND} — {_RECHECK}"
    ),
    "codex_runtime_capability_unsupported": (
        "the selected Codex did not pass FinishUP's capability check; "
        f"{_UPDATE_CODEX} and run {_REPAIR_COMMAND}, or run {_INSTALL_COMMAND} --download"
    ),
    "codex_runtime_version_unsupported": (
        "the selected Codex is not a stable release at or above "
        f"{CODEX_EVALUATOR_RUNTIME_FLOOR}, the oldest the evaluator admits; {_UPDATE_CODEX}, "
        "then run setup or repair"
    ),
    "codex_runtime_version_unknown": (
        "the selected Codex did not report its version ('codex --version'); select the npm "
        "package's bin/codex.js or its native codex executable"
    ),
    "codex_runtime_version_mismatch": (
        "the Codex runtime reported a different release than the one being checked or bound; "
        f"run {_REPAIR_COMMAND}"
    ),
    "codex_runtime_protocol_incompatible": (
        "the selected Codex no longer carries an app-server method or field the evaluator reads, "
        "so it is not admitted; an earlier admitted runtime is used when one exists — run "
        f"{_REPAIR_COMMAND}, or upgrade FinishUP (see 'finishup upgrade --help')"
    ),
    "codex_runtime_protocol_unavailable": (
        "the selected Codex could not describe its app-server protocol "
        "('codex app-server generate-json-schema'); select another Codex installation"
    ),
    "codex_sandbox_unavailable_unreviewed_runtime": (
        "this Codex release reports that its Linux sandbox cannot create user namespaces here, "
        "or that no system bubblewrap is installed. FinishUP accepts that only from Codex releases "
        "it has reviewed, and this one is not reviewed, so it is not admitted. Install a "
        "reviewed release (for example 'npm install -g @openai/codex@0.162.1'), or run where "
        "bubblewrap is installed and unprivileged user namespaces are allowed (not gVisor or a "
        f"restrictive container seccomp profile), then run {_REPAIR_COMMAND}"
    ),
    "codex_app_server_predisclosure_event_forbidden": (
        "the selected Codex sent an event FinishUP does not admit before any review content exists, "
        "such as an unreviewed configuration or sandbox warning; it is not admitted — fix that, "
        f"then run {_REPAIR_COMMAND}"
    ),
    "codex_app_server_remote_control_not_disabled": (
        "the selected Codex reported remote control as not disabled before any review content "
        "exists; it is not admitted"
    ),
    "codex_thread_isolation_unproven": (
        "the selected Codex did not prove a read-only, network-off, ephemeral review thread; it "
        "is not admitted"
    ),
    "codex_capability_probe_timeout": (
        "the selected Codex did not answer the capability check in time; retry, or select "
        "another Codex installation"
    ),
    CODEX_PROBE_CLEANUP_UNCONFIRMED: (
        "FinishUP could not confirm that every Codex process it started to check a Codex "
        "installation has exited, so it stopped without trying another installation and changed "
        "nothing; inspect running processes, stop any leftover Codex check you own, then retry"
    ),
    "codex_model_unavailable": (
        "Codex reports the dedicated home signed in, but no admitted Codex lists the model with "
        f"the configured reasoning efforts; {_UPDATE_CODEX} and retry, choose another --model, "
        "or pass --switch-account to sign in with another ChatGPT account"
    ),
    "codex_runtime_not_found": (
        "the selected Codex executable or its platform package was not found; pass the exact "
        f"path, or run {_INSTALL_COMMAND} --download"
    ),
    "codex_evaluator_runtime_unavailable": (
        f"no Codex {CODEX_EVALUATOR_RUNTIME_FLOOR} or newer was found; install Codex (for "
        f"example 'npm install -g @openai/codex') or run {_INSTALL_COMMAND} --download, then "
        "retry"
    ),
    "codex_evaluator_runtime_store_unsafe": (
        "FinishUP's evaluator runtime store must be an owner-only (0700), non-symlinked local "
        "directory inside the FinishUP data directory; restore that, then retry"
    ),
    "codex_evaluator_runtime_store_unavailable": (
        "the retained runtime copy could not be written or verified; check free space and "
        "permissions of the FinishUP data directory, then retry"
    ),
    "codex_evaluator_runtime_busy": (
        "another evaluator setup, repair, install, or removal is running; wait for it to finish, "
        "then retry this command"
    ),
    "codex_evaluator_runtime_in_use": (
        "the current binding uses the only retained runtime; run 'finishup provider "
        "codex-subscription disconnect' or 'rollback' first, then remove it"
    ),
    "codex_evaluator_runtime_download_failed": (
        "npm could not install the newest Codex release (its output is not captured); check "
        "your npm registry and network settings, then retry, or retain a local copy with --from"
    ),
    "codex_evaluator_runtime_download_timeout": (
        "the npm download did not finish within 10 minutes; retry, or retain a local copy with "
        "--from"
    ),
    "codex_evaluator_runtime_package_manager_unavailable": (
        "npm was not found or could not run; install Node.js and npm, pass --npm <absolute "
        "path>, or retain a local copy with --from"
    ),
    "codex_subscription_login_required": (
        "Codex reports the dedicated home is not signed in with the exact model; run "
        "'finishup provider codex-subscription setup' to sign in (it binds FinishUP's retained runtime)"
    ),
    "codex_home_missing": (
        "the dedicated evaluator home, and Codex's sign-in inside it, is gone; run "
        "'finishup provider codex-subscription setup' to sign in again"
    ),
    "codex_home_unsafe": (
        "the dedicated evaluator home must be an owner-only (0700), non-symlinked local "
        f"directory; restore that, then run {_REPAIR_COMMAND}"
    ),
    "codex_runtime_config_missing": (
        f"the dedicated home's FinishUP-owned config.toml is missing; run {_REPAIR_COMMAND} to "
        "restore it"
    ),
    "codex_runtime_config_changed": (
        "the dedicated home's config.toml differs from the FinishUP-owned isolated config; restore "
        f"it or remove only that file, then run {_REPAIR_COMMAND} (FinishUP never overwrites it)"
    ),
    "codex_runtime_capability_evidence_stale": (
        "the reviewed evaluator evidence has expired; upgrade FinishUP to a release that renews it "
        "(see 'finishup upgrade --help')"
    ),
    "codex_runtime_platform_unsupported": (
        "the evaluator supports macOS arm64 and Linux x86_64 only, so the binding cannot run "
        "here; 'finishup provider codex-subscription rollback' removes it"
    ),
    "codex_runtime_binding_invalid": (
        "the stored binding is malformed; run 'finishup provider codex-subscription setup'"
    ),
    "codex_runtime_unavailable": (
        "the evaluator runtime or its dedicated home could not be read; inspect "
        "'finishup provider codex-subscription runtime status', then retry"
    ),
}


def subscription_remediation(reason: str) -> str | None:
    """The subscription-specific next step for one bounded token, or ``None``."""

    return _SUBSCRIPTION_REMEDIATIONS.get(reason)


def subscription_failure_line(error: BaseException) -> str:
    """One bounded ``codex_subscription: <token>[: <next step>]`` line; never native text."""

    from finishup.cli.exits import remediation_message

    reason = subscription_failure_reason(error)
    remediation = remediation_message(reason) or subscription_remediation(reason)
    head = f"codex_subscription: {reason}"
    return head if remediation is None else f"{head}: {remediation}"


def _runtime_path(path: Path, *, missing_token: str) -> Path:
    """Resolve one path selected by the caller without widening its search scope."""

    try:
        return path.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError(missing_token) from error
    except (OSError, RuntimeError) as error:
        raise ValueError("codex_runtime_unavailable") from error


def _package_json(package_root: Path) -> Mapping[str, JsonValue]:
    """Read one bounded npm manifest and convert all parse failures to safe tokens."""

    path = package_root / "package.json"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise ValueError("codex_runtime_not_found") from error
    except OSError as error:
        raise ValueError("codex_runtime_capability_unsupported") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > _CODEX_PACKAGE_JSON_MAX_BYTES
        ):
            raise ValueError("codex_runtime_capability_unsupported")
        chunks: list[bytes] = []
        remaining = _CODEX_PACKAGE_JSON_MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError as error:
        raise ValueError("codex_runtime_capability_unsupported") from error
    finally:
        os.close(descriptor)
    if not raw or len(raw) > _CODEX_PACKAGE_JSON_MAX_BYTES:
        raise ValueError("codex_runtime_capability_unsupported")
    try:
        document = strict_json_parse(raw)
    except (ValueError, RecursionError) as error:
        raise ValueError("codex_runtime_capability_unsupported") from error
    if not isinstance(document, Mapping):
        raise ValueError("codex_runtime_capability_unsupported")
    return cast(Mapping[str, JsonValue], document)


def _validate_codex_wrapper_manifest(
    document: Mapping[str, JsonValue], platform: CodexPlatform
) -> str:
    """Validate the wrapper metadata and return the release it names."""

    if document.get("name") != _CODEX_PACKAGE_NAME:
        raise ValueError("codex_runtime_capability_unsupported")
    version = document.get("version")
    if type(version) is not str:
        raise ValueError("codex_runtime_capability_unsupported")
    require_admitted_version(version)
    binary_map = document.get("bin")
    if not isinstance(binary_map, Mapping) or binary_map.get("codex") != "bin/codex.js":
        raise ValueError("codex_runtime_capability_unsupported")
    optional_dependencies = document.get("optionalDependencies")
    if not isinstance(optional_dependencies, Mapping) or optional_dependencies.get(
        f"@openai/{platform.native_package_directory}"
    ) != platform.native_package_spec(version):
        raise ValueError("codex_runtime_capability_unsupported")
    return version


def _validate_codex_native_manifest(
    document: Mapping[str, JsonValue], platform: CodexPlatform, version: str
) -> None:
    """Validate the native package identity and platform selectors for one release."""

    if document.get("name") != _CODEX_PACKAGE_NAME:
        raise ValueError("codex_runtime_capability_unsupported")
    if document.get("version") != platform.native_package_version(version):
        raise ValueError("codex_runtime_capability_unsupported")
    if document.get("os") != [platform.os] or document.get("cpu") != [platform.npm_cpu]:
        raise ValueError("codex_runtime_capability_unsupported")


def _package_candidate_present(path: Path) -> bool:
    """Return presence without following an absent/broken candidate into a parent search."""

    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ValueError("codex_runtime_unavailable") from error


def _reject_symlinked_package_root(path: Path) -> None:
    """Keep package identity bound to the selected layout, including same-parent aliases."""

    try:
        if stat.S_ISLNK(path.lstat().st_mode):
            raise ValueError("codex_runtime_capability_unsupported")
    except FileNotFoundError as error:
        raise ValueError("codex_runtime_not_found") from error
    except OSError as error:
        raise ValueError("codex_runtime_unavailable") from error


def _resolve_codex_package_layout(wrapper: Path, platform: CodexPlatform) -> tuple[Path, str]:
    """Resolve a selected npm wrapper to its nested or npm-prefix native executable and release.

    The only allowed package roots are the optional dependency nested below the selected wrapper
    and its direct hoisted sibling. The nested candidate wins deterministically; a present but
    malformed nested package is terminal and never causes an unbounded parent/PATH search.
    """

    package_root = wrapper.parent.parent
    if package_root == Path(package_root.anchor):
        raise ValueError("codex_runtime_capability_unsupported")
    version = _validate_codex_wrapper_manifest(_package_json(package_root), platform)

    nested = package_root / "node_modules" / "@openai" / platform.native_package_directory
    hoisted = package_root.parent / platform.native_package_directory
    if _package_candidate_present(nested):
        _reject_symlinked_package_root(nested)
        expected_parent = nested.parent
        allowed_parent = _runtime_path(nested.parent, missing_token="codex_runtime_not_found")
        native_root = _runtime_path(nested, missing_token="codex_runtime_not_found")
    elif _package_candidate_present(hoisted):
        _reject_symlinked_package_root(hoisted)
        expected_parent = hoisted.parent
        allowed_parent = _runtime_path(hoisted.parent, missing_token="codex_runtime_not_found")
        native_root = _runtime_path(hoisted, missing_token="codex_runtime_not_found")
    else:
        raise ValueError("codex_runtime_not_found")
    if (
        allowed_parent != expected_parent
        or native_root.parent != allowed_parent
        or not native_root.is_dir()
    ):
        raise ValueError("codex_runtime_capability_unsupported")
    _validate_codex_native_manifest(_package_json(native_root), platform, version)
    native = _runtime_path(
        native_root / platform.native_executable_relative,
        missing_token="codex_runtime_not_found",
    )
    try:
        native.relative_to(native_root)
    except ValueError as error:
        raise ValueError("codex_runtime_capability_unsupported") from error
    return native, version


def _codex_cli_version(native: Path) -> str:
    """``codex --version`` of one native executable, under a throwaway scratch home."""

    return codex_cli_version(native, scratch_parent=Path(tempfile.gettempdir()))


@dataclass(frozen=True, slots=True)
class ResolvedCodex:
    """One selected Codex resolved to its native executable, release and platform."""

    native: Path
    version: str
    platform: CodexPlatform

    @property
    def source_identity(self) -> str:
        return codex_source_identity(self.platform, self.version)


def resolve_codex_executable(selected: Path) -> ResolvedCodex:
    """Resolve one selected npm wrapper or native executable; nothing else is searched.

    The release comes from the npm manifests for a wrapper, or from ``codex --version`` for a
    native executable; it must be a stable release at or above the floor, and the code-mode host
    must sit beside the native executable. Admission itself is the later capability check.
    """

    platform = host_codex_platform()
    resolved = _runtime_path(selected.expanduser(), missing_token="codex_runtime_not_found")
    version: str | None = None
    if resolved.name == "codex.js" and resolved.parent.name == "bin":
        resolved, version = _resolve_codex_package_layout(resolved, platform)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("codex_runtime_executable_invalid")
    if version is None:
        version = _codex_cli_version(resolved)
    require_admitted_version(version)
    _verify_code_mode_host(resolved)
    return ResolvedCodex(resolved, version, platform)


def _verify_code_mode_host(native: Path) -> Path:
    """Require Codex's code-mode host beside the resolved native executable (#874).

    Every supported layout (nested or hoisted npm package, or the native path itself) places it
    in the native executable's own directory, where Codex starts it; nothing else is searched.
    """

    host = codex_code_mode_host_path(native)
    try:
        facts = host.lstat()
    except FileNotFoundError as error:
        raise ValueError("codex_runtime_code_mode_host_missing") from error
    except OSError as error:
        raise ValueError("codex_runtime_unavailable") from error
    if not stat.S_ISREG(facts.st_mode) or not facts.st_mode & stat.S_IXUSR:
        raise ValueError("codex_runtime_executable_invalid")
    return host


def default_codex_home() -> Path:
    """The dedicated sign-in home a new binding is offered.

    This is where Codex keeps the evaluator's ChatGPT login, not the runtime copy (that lives under
    ``external-runtimes/codex-evaluator/<source identity>``). Its historical directory name is kept
    stable across admitted runtime versions so a home signed in before a runtime change is offered
    again, and reused, after a rollback followed by setup.
    """

    config = _bounded_config_operation(lambda: load_config({}, os.environ, None))
    if config.external_runtime is not None:
        return Path(config.external_runtime.codex_home)
    return bundle_root(_data_dir=config.storage.data_dir) / "external-runtimes" / "codex-0.150.1"


def runtime_bundle() -> Path:
    """The data bundle whose owner-private store holds the retained evaluator runtimes.

    It is resolved exactly like the service's own bundle and the default dedicated home
    (configuration file, environment, and isolation root), so an isolated or test instance never
    retains into, or binds, another instance's runtime.
    """

    config = _bounded_config_operation(lambda: load_config({}, os.environ, None))
    try:
        return bundle_root(_data_dir=config.storage.data_dir)
    except PathSafetyError as error:
        raise ValueError("codex_evaluator_runtime_store_unsafe") from error


type EvaluatorRuntimeSource = Literal["selected", "managed", "binding", "discovered"]
# On equal releases the copy FinishUP already retains wins, so no bytes are copied again.
_SOURCE_PREFERENCE: Final[Mapping[str, int]] = {
    "selected": 0,
    "managed": 0,
    "binding": 1,
    "discovered": 2,
}


@dataclass(frozen=True, slots=True)
class EvaluatorCandidate:
    """One eligible installation: a stable release at or above the floor, not yet checked."""

    source: EvaluatorRuntimeSource
    path: Path
    version: str


def _sorted_candidates(found: list[EvaluatorCandidate]) -> tuple[EvaluatorCandidate, ...]:
    best: dict[str, EvaluatorCandidate] = {}
    for candidate in found:
        current = best.get(candidate.version)
        if current is None or (
            _SOURCE_PREFERENCE[candidate.source] < _SOURCE_PREFERENCE[current.source]
        ):
            best[candidate.version] = candidate
    return tuple(
        sorted(
            best.values(),
            key=lambda item: codex_version_key(item.version) or (0, 0, 0),
            reverse=True,
        )
    )


def _stop_on_unconfirmed_cleanup(error: BaseException) -> None:
    """Re-raise a version probe whose process group was not confirmed gone; skip anything else."""

    if isinstance(error, ValueError) and str(error) == CODEX_PROBE_CLEANUP_UNCONFIRMED:
        raise error


def evaluator_candidates(
    config: FinishUpConfig, *, executable: Path | None = None
) -> tuple[EvaluatorCandidate, ...]:
    """Every eligible evaluator runtime, newest release first; nothing is checked or copied.

    An explicit ``executable`` is the only candidate. Otherwise: FinishUP's retained releases, the
    existing binding's executable when it is a host installation, and every discovered everyday
    Codex install. One candidate is kept per release (the retained copy first). An installation
    below the floor, a prerelease, or one that cannot be resolved is never offered.
    """

    platform = host_codex_platform()
    if executable is not None:
        resolved = resolve_codex_executable(executable)
        return (EvaluatorCandidate("selected", resolved.native, resolved.version),)
    found: list[EvaluatorCandidate] = []
    try:
        bundle: Path | None = runtime_bundle()
    except ValueError:
        bundle = None
    if bundle is not None:
        for retained in retained_runtimes(bundle, platform):
            state = inspect_managed_runtime(bundle, retained.source_identity)
            if state not in {"verified", "unchecked", "changed"}:
                continue
            try:
                require_admitted_version(retained.runtime_version)
            except ValueError:
                continue
            found.append(EvaluatorCandidate("managed", retained.path, retained.runtime_version))
    binding = config.external_runtime
    if binding is not None and not (
        bundle is not None and is_managed_runtime_path(bundle, Path(binding.executable_path))
    ):
        try:
            resolved = resolve_codex_executable(Path(binding.executable_path))
        except (OSError, ValueError) as error:  # fmt: skip
            _stop_on_unconfirmed_cleanup(error)
        else:
            found.append(EvaluatorCandidate("binding", resolved.native, resolved.version))
    from finishup.adapters.integrations.codex_discovery import discover_codex_binaries

    for binary in discover_codex_binaries():
        try:
            resolved = resolve_codex_executable(Path(binary.executable_path))
        except (OSError, ValueError) as error:  # fmt: skip
            _stop_on_unconfirmed_cleanup(error)
            continue
        found.append(EvaluatorCandidate("discovered", resolved.native, resolved.version))
    return _sorted_candidates(found)


def select_codex_evaluator_executable(
    config: FinishUpConfig,
) -> tuple[EvaluatorRuntimeSource, Path] | None:
    """The newest eligible evaluator runtime, or ``None`` when there is none.

    This is the first of :func:`evaluator_candidates`; setup and repair fall back to the next
    candidate when it does not pass the capability check.
    """

    try:
        candidates = evaluator_candidates(config)
    except ValueError:
        return None
    if not candidates:
        return None
    return candidates[0].source, candidates[0].path


def default_codex_evaluator_executable(path: Path | None = None) -> Path | None:
    """The eligible evaluator runtime setup offers by default, or ``None`` when none exists."""

    selected = select_codex_evaluator_executable(_base_config(path))
    return None if selected is None else selected[1]


def setup_executable_selection(entered: str | Path | None, offered: Path | None) -> Path | None:
    """The ``executable`` an interactive setup passes on: ``None`` unless the owner pinned one.

    Accepting the offered default (or leaving the field blank) keeps newest-first discovery with
    fallback, so a newest release that fails the capability check or readiness falls back to the
    previous good one. Only an explicitly typed, different path pins setup to that one runtime.
    """

    if entered is None:
        return None
    text = str(entered).strip()
    if not text:
        return None
    chosen = Path(text).expanduser()
    if offered is not None and chosen == offered.expanduser():
        return None
    return chosen


def diagnose_bound_runtime(binding: ExternalRuntimeProfileConfig) -> CodexBindingDiagnosis:
    """Structural diagnosis of one binding at the current time; never starts Codex."""

    return diagnose_codex_binding(binding, now=datetime.now(UTC))


def _validate_choices(
    *, codex_home: Path, model: str, reasoning_effort: str, routine_reasoning_effort: str | None
) -> None:
    if not codex_home.is_absolute():
        raise ValueError("codex_home_invalid")
    if not model or reasoning_effort not in _SUPPORTED_REASONING:
        raise ValueError("codex_runtime_model_invalid")
    if routine_reasoning_effort is not None and routine_reasoning_effort not in (
        _SUPPORTED_REASONING
    ):
        raise ValueError("codex_runtime_model_invalid")


def codex_subscription_preview(
    *,
    executable: Path,
    codex_home: Path,
    model: str,
    reasoning_effort: str,
    routine_reasoning_effort: str | None = None,
) -> dict[str, JsonValue]:
    """Resolve the selected runtime and show the nonsecret binding without any side effect.

    ``reasoning_effort`` is the final-profile effort. ``routine_reasoning_effort=None`` means the
    routine profile keeps that single effort (the legacy binding shape). The capability check
    runs at setup, against FinishUP's retained copy, before anything is bound.
    """

    resolved = resolve_codex_executable(executable)
    _validate_choices(
        codex_home=codex_home,
        model=model,
        reasoning_effort=reasoning_effort,
        routine_reasoning_effort=routine_reasoning_effort,
    )
    host = codex_code_mode_host_path(resolved.native)
    return {
        "schema": "yoetz.codex-subscription-preview/2",
        "credential_authority": "external_runtime_oauth",
        "runtime_version": resolved.version,
        "runtime_floor": CODEX_EVALUATOR_RUNTIME_FLOOR,
        "runtime_source_identity": resolved.source_identity,
        "executable_path": str(resolved.native),
        "executable_sha256": _sha256_file(resolved.native),
        "code_mode_host_path": str(host),
        "code_mode_host_sha256": _sha256_file(host),
        "capability_profile": CODEX_EVALUATOR_CAPABILITY_PROFILE,
        "capability_check": "runs at setup before binding; a newer failing Codex falls back",
        "capability_evidence_expires_at": CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
        "isolated_config_sha256": CODEX_EVALUATOR_CONFIG_SHA256,
        "codex_home": str(codex_home),
        "model": model,
        "reasoning_effort": reasoning_effort,
        "routine_reasoning_effort": (
            reasoning_effort if routine_reasoning_effort is None else routine_reasoning_effort
        ),
        "destination": "OpenAI through Codex-managed ChatGPT authentication",
        "data_use_posture": "unknown",
        "upstream_body_observability": "unavailable",
        "disconnect_command": "finishup provider codex-subscription disconnect",
        "rollback_command": "finishup provider codex-subscription rollback",
    }


def _base_config(path: Path | None) -> FinishUpConfig:
    """Load the exact target config through the canonical loader; fail as one closed token.

    Strict validation of raw TOML rejected valid files whose ``storage.data_dir`` string the
    canonical loader converts to ``Path`` before model validation (#520). Loading through
    :func:`finishup.config.load.load_config` keeps one rule: a file the service accepts is a file
    every subscription lifecycle command accepts. Sources stay file-only (no environment or
    override leaves) so a write base never persists ambient environment state.
    """

    target = _target_config_path(path)
    return _bounded_config_operation(lambda: load_config({}, {}, target))


def default_codex_subscription_model(path: Path | None = None) -> str:
    """Return the new-binding recommendation or preserve an existing binding's model."""

    config = _base_config(path)
    if config.external_runtime is not None:
        return config.external_runtime.model
    return _DEFAULT_CODEX_SUBSCRIPTION_MODEL


def default_codex_subscription_routine_effort(path: Path | None = None) -> str | None:
    """Return the routine effort setup applies when no explicit choice is given.

    A new binding receives the bounded recommendation. An existing binding keeps its own routine
    choice, and a legacy binding without one keeps its single effort (``None``): re-running setup
    never silently lowers a persisted choice.
    """

    config = _base_config(path)
    if config.external_runtime is not None:
        return config.external_runtime.routine_reasoning_effort
    return CODEX_ROUTINE_REASONING_EFFORT_DEFAULT


def default_codex_subscription_reasoning_effort(path: Path | None = None) -> str:
    """Preserve the existing final effort, or recommend the new-binding default (#855)."""

    config = _base_config(path)
    if config.external_runtime is not None:
        return config.external_runtime.reasoning_effort
    return _DEFAULT_CODEX_SUBSCRIPTION_REASONING


def _config_snapshot(path: Path) -> tuple[FinishUpConfig, bytes | None]:
    """Load the write base and exact preimage as one locked operation."""

    return _bounded_config_operation(lambda: config_write_snapshot(path))


def _target_config_path(path: Path | None) -> Path:
    if path is not None:
        return path
    selected = environment_config_path()
    return selected if selected is not None else config_file_path()


def _binding(
    *,
    record: CodexCapabilityRecord,
    executable: Path,
    codex_home: Path,
    model: str,
    reasoning_effort: str,
    routine_reasoning_effort: str | None = None,
    existing: ExternalRuntimeProfileConfig | None = None,
) -> ExternalRuntimeProfileConfig:
    """Construct the nonsecret binding for one checked runtime without creating any state.

    The runtime identity fields come from the capability record the retained ``executable``
    earned; output limits, timeout and retry budgets are configuration-only choices with no setup
    prompt, and an existing binding preserves all of them during a rebind (#855).
    """

    _validate_choices(
        codex_home=codex_home,
        model=model,
        reasoning_effort=reasoning_effort,
        routine_reasoning_effort=routine_reasoning_effort,
    )
    return codex_subscription_runtime(
        executable_path=str(executable),
        executable_sha256=record.executable_sha256,
        runtime_version=record.runtime_version,
        source_identity=record.source_identity,
        app_server_schema_sha256=record.app_server_schema_sha256,
        capability_cell_sha256=record.digest,
        isolated_config_sha256=record.isolated_config_sha256,
        capability_profile=record.capability_profile,
        capability_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
        codex_home=str(codex_home),
        model=model,
        reasoning_effort=reasoning_effort,
        routine_reasoning_effort=routine_reasoning_effort,
        **(
            {}
            if existing is None
            else {
                "routine_output_limit": existing.routine_output_limit,
                "final_output_limit": existing.final_output_limit,
                "timeout_seconds": existing.timeout_seconds,
                "max_retries": existing.max_retries,
            }
        ),
    )


def _provisional_record(candidate: EvaluatorCandidate) -> CodexCapabilityRecord:
    """A shape-only record used to prove the configuration write before any side effect."""

    platform = host_codex_platform()
    placeholder = "sha256:" + "0" * 64
    return CodexCapabilityRecord(
        runtime_version=candidate.version,
        source_identity=codex_source_identity(platform, candidate.version),
        platform_os=platform.os,
        platform_architecture=platform.architecture,
        executable_sha256=placeholder,
        code_mode_host_sha256=placeholder,
        app_server_schema_sha256=placeholder,
        isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
    )


def _profile(binding: ExternalRuntimeProfileConfig) -> CodexAppServerProfile:
    return CodexAppServerProfile.from_config(binding)


@dataclass(frozen=True, slots=True)
class _Checked:
    """One candidate that passed the capability check, retained with its committed record."""

    candidate: EvaluatorCandidate
    retained: Path
    record: CodexCapabilityRecord


# Store faults are not a property of one candidate; they stop the whole adoption.
_STORE_FAULTS: Final = frozenset(
    {
        "codex_evaluator_runtime_busy",
        "codex_evaluator_runtime_store_unsafe",
        "codex_evaluator_runtime_store_unavailable",
        "codex_runtime_platform_unsupported",
        # A candidate process group that may still be running stops selection outright: no
        # further candidate is launched beside it, and nothing is bound.
        CODEX_PROBE_CLEANUP_UNCONFIRMED,
    }
)


async def _check_candidate(candidate: EvaluatorCandidate, *, bundle: Path) -> _Checked:
    """Retain one candidate, run the capability check on the retained bytes, commit the record."""

    platform = host_codex_platform()
    identity = codex_source_identity(platform, candidate.version)
    retained = retain_codex_runtime(candidate.path, bundle=bundle, source_identity=identity)
    record = await check_codex_capability(
        retained,
        runtime_version=candidate.version,
        platform=platform,
        scratch_parent=managed_runtime_root(bundle),
    )
    commit_capability_record(bundle, record)
    return _Checked(candidate, retained, record)


type _Readiness = Callable[[ExternalRuntimeProfileConfig], Awaitable[CodexRuntimeStatus]]


@dataclass(frozen=True, slots=True)
class _Adopted:
    checked: _Checked
    binding: ExternalRuntimeProfileConfig
    status: CodexRuntimeStatus | None
    # Closed tokens of the newer candidates that were tried first and not adopted.
    passed_over: tuple[str, ...]


async def _adopt_runtime(
    candidates: tuple[EvaluatorCandidate, ...],
    *,
    bundle: Path,
    make_binding: Callable[[Path, CodexCapabilityRecord], ExternalRuntimeProfileConfig],
    readiness: _Readiness | None,
) -> _Adopted:
    """Bind the newest candidate that passes the check and, given a home, lists the model.

    Candidates are tried newest first. A candidate that fails the capability check, or whose
    readiness probe reports the dedicated home signed in without the configured model and
    efforts, is passed over for the next one: a newer Codex that regresses falls back to the
    previous good release. A home Codex reports as not signed in stops the search there (sign-in
    belongs to the home, not the runtime). An unconfirmed cleanup of any check or readiness
    process (``codex_capability_probe_cleanup_unconfirmed``), like a store fault, stops the
    search at once instead of falling back to an older candidate.
    Nothing is written to the configuration here.
    """

    passed_over: list[str] = []
    for candidate in candidates:
        try:
            checked = await _check_candidate(candidate, bundle=bundle)
        except ValueError as error:
            token = subscription_failure_reason(error)
            if token in _STORE_FAULTS:
                raise
            passed_over.append(token)
            continue
        except (OSError, TimeoutError) as error:  # fmt: skip
            passed_over.append(subscription_failure_reason(error))
            continue
        binding = make_binding(checked.retained, checked.record)
        if readiness is None:
            return _Adopted(checked, binding, None, tuple(passed_over))
        try:
            status = await readiness(binding)
        except (OSError, TimeoutError, ValueError) as error:  # fmt: skip
            token = subscription_failure_reason(error)
            if token == CODEX_PROBE_CLEANUP_UNCONFIRMED:
                raise
            passed_over.append(token)
            continue
        if status.cleanup == "failed":
            raise ValueError("codex_subscription_readiness_unproven")
        if status.runtime_ready and status.auth_mode == "chatgpt" and not status.model_available:
            passed_over.append("codex_model_unavailable")
            continue
        return _Adopted(checked, binding, status, tuple(passed_over))
    if "codex_model_unavailable" in passed_over:
        raise ValueError("codex_model_unavailable")
    raise ValueError(passed_over[0] if passed_over else "codex_evaluator_runtime_unavailable")


# Structural states another admitted runtime resolves: the bound bytes or capability identity are
# wrong, while the dedicated home (and the login Codex keeps in it) is intact.
RUNTIME_REBINDABLE_STATES: Final = frozenset(
    {
        "codex_runtime_capability_unsupported",
        "codex_runtime_version_unsupported",
        "codex_runtime_executable_missing",
        "codex_runtime_executable_invalid",
        "codex_runtime_executable_changed",
        "codex_runtime_profile_outdated",
    }
)
# Dedicated-home faults no runtime can fix. They are checked on their own axis, so a replaced
# executable (the primary state) can never mask a missing home or a modified isolated config.
_HOME_REFUSALS: Final[Mapping[str, str]] = {
    "missing": "codex_home_missing",
    "unsafe": "codex_home_unsafe",
    "config_missing": "codex_runtime_config_missing",
    "config_changed": "codex_runtime_config_changed",
    "unreadable": "codex_runtime_unavailable",
}


def _refuse_home_fault(
    diagnosis: CodexBindingDiagnosis, *, restorable: frozenset[str] = frozenset()
) -> None:
    refusal = _HOME_REFUSALS.get(diagnosis.home)
    if refusal is not None and diagnosis.home not in restorable:
        raise ValueError(refusal)


def _rebinder(
    existing: ExternalRuntimeProfileConfig,
) -> Callable[[Path, CodexCapabilityRecord], ExternalRuntimeProfileConfig]:
    """Build ``existing`` with only its runtime identity replaced by one checked runtime."""

    def make(retained: Path, record: CodexCapabilityRecord) -> ExternalRuntimeProfileConfig:
        validated = _binding(
            record=record,
            executable=retained,
            codex_home=Path(existing.codex_home),
            model=existing.model,
            reasoning_effort=existing.reasoning_effort,
            existing=existing,
        )
        return existing.model_copy(
            update={name: getattr(validated, name) for name in _IDENTITY_FIELDS}
        )

    return make


async def _operational_binding(
    binding: ExternalRuntimeProfileConfig, config: FinishUpConfig
) -> ExternalRuntimeProfileConfig:
    """The binding to launch for a reverse operation on the same dedicated home.

    A stranded binding (replaced executable, outdated capability identity) must still be able to
    ask Codex to log its dedicated home out; the newest runtime that passes the capability check
    is used in memory for that one probe. Nothing is persisted, and home or config faults still
    fail closed.
    """

    diagnosis = diagnose_bound_runtime(binding)
    if diagnosis.ready:
        return binding
    _refuse_home_fault(diagnosis)
    if diagnosis.state not in RUNTIME_REBINDABLE_STATES:
        raise ValueError(diagnosis.state)
    with runtime_mutation_lock(runtime_bundle()):
        candidates = evaluator_candidates(config)
        if not candidates:
            raise ValueError(diagnosis.state)
        adopted = await _adopt_runtime(
            candidates, bundle=runtime_bundle(), make_binding=_rebinder(binding), readiness=None
        )
    return adopted.binding


# The compatibility-critical fields a rebind takes from the capability record and retained copy.
# Every other field of an existing binding (model, efforts, budgets, home, and any field a later
# release adds) is carried over unchanged, so a rebind can never silently reset an owner choice.
_IDENTITY_FIELDS: Final = (
    "executable_path",
    "executable_sha256",
    "runtime_version",
    "source_identity",
    "app_server_schema_sha256",
    "capability_cell_sha256",
    "isolated_config_sha256",
    "capability_profile",
    "capability_evidence_expires_at",
)


def _already_ready(status: CodexRuntimeStatus) -> bool:
    """Codex proved a ChatGPT login and the exact model/reasoning cell for this home."""

    return status.runtime_ready and status.auth_mode == "chatgpt" and status.model_available


def _bound_code_mode_host_sha256(binding: ExternalRuntimeProfileConfig) -> str | None:
    """The host digest the binding's capability record pins, or ``None`` when unreadable."""

    try:
        record = read_capability_record(Path(binding.executable_path).parent)
    except (OSError, ValueError):  # fmt: skip
        return None
    if record.digest != binding.capability_cell_sha256:
        return None
    return record.code_mode_host_sha256


def _safe_status(
    binding: ExternalRuntimeProfileConfig, status: CodexRuntimeStatus
) -> dict[str, JsonValue]:
    return {
        "schema": "yoetz.codex-subscription-status/1",
        "credential_authority": binding.credential_authority,
        "runtime_version": binding.runtime_version,
        "runtime_source_identity": binding.source_identity,
        "executable_path": binding.executable_path,
        "executable_sha256": binding.executable_sha256,
        "code_mode_host_path": str(codex_code_mode_host_path(Path(binding.executable_path))),
        "code_mode_host_sha256": _bound_code_mode_host_sha256(binding),
        "app_server_schema_sha256": binding.app_server_schema_sha256,
        "capability_cell_sha256": binding.capability_cell_sha256,
        "capability_profile": binding.capability_profile,
        "capability_evidence_expires_at": binding.capability_evidence_expires_at,
        "isolated_config_sha256": binding.isolated_config_sha256,
        "codex_home": binding.codex_home,
        "model": binding.model,
        "reasoning_effort": binding.reasoning_effort,
        "review_budgets": cast(JsonValue, binding.review_budget_facts()),
        "runtime_ready": status.runtime_ready,
        "auth_mode": status.auth_mode,
        "plan_type": status.plan_type,
        "model_available": status.model_available,
        "process_cleanup": status.cleanup,
        # Codex reported that its Linux sandbox cannot create user namespaces, or that no system
        # bubblewrap is installed so the sandbox is unverified (ADR-006, 2026-10-14). The
        # evaluator exposes no tool that sandbox would confine; the reason is disclosed.
        "codex_sandbox_unavailable": status.sandbox_unavailable,
        "codex_sandbox_unavailable_reason": status.sandbox_unavailable_reason,
        "upstream_body_observability": "unavailable",
    }


async def codex_subscription_setup(
    *,
    executable: Path | None,
    codex_home: Path,
    model: str,
    reasoning_effort: str,
    login_mode: Literal["browser", "device_code"],
    open_browser: bool,
    switch_account: bool,
    config_path: Path | None = None,
    as_fallback: bool = False,
    routine_reasoning_effort: str | None = None,
) -> dict[str, JsonValue]:
    """Check and bind the newest admitted runtime, prove or obtain Codex login, then persist it.

    ``as_fallback`` keeps the already-bound API provider as the primary and declares this
    runtime as its fallback (issue #582); it never replaces that binding.

    Every deterministic local requirement — eligible candidates, the canonical target
    configuration, and a render-validated, lock-probed write of the binding's shape — is proven
    before any store, home or Codex side effect, so a configuration failure can never follow login
    side effects (#520).

    The runtime is adopted by capability (ADR-006): candidates are tried newest first; each is
    retained in the FinishUP-managed store, checked there, and then probed against the dedicated
    home (``account/read`` with ``refreshToken: false`` and ``model/list``). A home Codex already
    reports as signed in with the model available is bound without a new ``account/login/start``
    challenge (#534); a signed-in home whose model no admitted runtime lists fails as
    ``codex_model_unavailable`` without opening a sign-in. FinishUP never reads or copies
    ``auth.json``: readiness is only what Codex answers. ``switch_account`` logs the home out
    and signs in again. ``executable`` selects one installation instead of the candidate search.
    An existing binding's timeout and retry budgets are preserved.
    """

    with runtime_mutation_lock(runtime_bundle()):
        target = _target_config_path(config_path)
        base, expected_bytes = _config_snapshot(target)
        # ``None`` defers to the same rule the setup screens display: keep an existing binding's
        # routine choice (including a legacy single effort) or recommend the bounded default.
        selected_routine = (
            routine_reasoning_effort
            if routine_reasoning_effort is not None
            else (
                CODEX_ROUTINE_REASONING_EFFORT_DEFAULT
                if base.external_runtime is None
                else base.external_runtime.routine_reasoning_effort
            )
        )
        _validate_choices(
            codex_home=codex_home,
            model=model,
            reasoning_effort=reasoning_effort,
            routine_reasoning_effort=selected_routine,
        )
        candidates = evaluator_candidates(base, executable=executable)
        if not candidates:
            raise ValueError("codex_evaluator_runtime_unavailable")
        bundle = runtime_bundle()

        def make_binding(
            retained: Path, record: CodexCapabilityRecord
        ) -> ExternalRuntimeProfileConfig:
            return _binding(
                record=record,
                executable=retained,
                codex_home=codex_home,
                model=model,
                reasoning_effort=reasoning_effort,
                routine_reasoning_effort=selected_routine,
                existing=base.external_runtime,
            )

        provisional = make_binding(
            managed_runtime_path(bundle, _provisional_record(candidates[0]).source_identity),
            _provisional_record(candidates[0]),
        )
        _bounded_config_operation(
            lambda: preflight_config_write(
                external_runtime_binding_config(provisional, base=base, as_fallback=as_fallback),
                target,
                expected_bytes=expected_bytes,
            )
        )
        prepare_codex_home(codex_home)

        async def readiness(binding: ExternalRuntimeProfileConfig) -> CodexRuntimeStatus:
            return await codex_account_status(_profile(binding))

        adopted = await _adopt_runtime(
            candidates,
            bundle=bundle,
            make_binding=make_binding,
            readiness=None if switch_account else readiness,
        )
        binding = adopted.binding
        profile = _profile(binding)
        login_reused = False
        status = adopted.status
        if switch_account:
            logout_status = await codex_logout(profile)
            if logout_status.cleanup == "failed":
                raise ValueError("codex_logout_unconfirmed")
        elif status is not None and _already_ready(status):
            login_reused = True
            typer.echo("")
            typer.echo(
                "Codex reports this dedicated home is already signed in with the exact model "
                "available; reusing it without a new sign-in."
            )
        if not login_reused:

            def present(challenge: CodexLoginChallenge) -> None:
                typer.echo("")
                typer.echo(
                    "Codex owns this ChatGPT sign-in. FinishUP does not receive the credentials."
                )
                typer.echo(f"Open: {challenge.url}")
                if challenge.user_code is not None:
                    typer.echo(f"One-time code: {challenge.user_code}")
                if open_browser and challenge.mode == "browser":
                    if not webbrowser.open(challenge.url):
                        raise ValueError("codex_login_browser_unavailable")

            status = await codex_login(profile, mode=login_mode, present_challenge=present)
            if not _already_ready(status) or status.cleanup == "failed":
                raise ValueError("codex_subscription_readiness_unproven")
        assert status is not None
        selected_config = external_runtime_binding_config(
            binding, base=base, as_fallback=as_fallback
        )
        _bounded_config_operation(
            lambda: write_config_toml_if_unchanged(
                selected_config,
                expected_bytes=expected_bytes,
                path=target,
            )
        )
        result = _safe_status(binding, status)
        result["login_reused"] = login_reused
        # An existing pairing keeps its selector, so report the role the written config holds.
        result["endpoint_role"] = _endpoint_role(selected_config)
        result["runtime_retained_from"] = str(adopted.checked.candidate.path)
        result["runtime_source"] = adopted.checked.candidate.source
        result["runtimes_passed_over"] = list(adopted.passed_over)
        return result


async def _prompt_evaluator_executable() -> tuple[Path, Path | None]:
    """Offer only an eligible evaluator runtime; offer the managed download when none exists.

    Discovery order is host inventory, not evaluator eligibility (#855): an unusable discovered
    binary is never presented as the ready default. Returns (entered, offered default).
    """

    selected = default_codex_evaluator_executable()
    if selected is None:
        typer.echo("")
        typer.echo(
            f"No Codex {CODEX_EVALUATOR_RUNTIME_FLOOR} or newer was found. FinishUP can download "
            "the newest Codex into its own private copy; your everyday Codex is not changed."
        )
        for line in describe_runtime_download():
            typer.echo(f"  {line}")
        if typer.confirm("Download the evaluator runtime now?", default=False):
            installed = await codex_evaluator_runtime_install(source=None, npm=None, download=True)
            selected = Path(cast(str, installed["managed_runtime_path"]))
    entered = Path(
        typer.prompt(
            "Codex evaluator executable",
            default=None if selected is None else str(selected),
            show_default=selected is not None,
        )
    ).expanduser()
    return entered, selected


async def prompt_codex_subscription_setup() -> dict[str, JsonValue]:
    """Run the shared terminal setup screen used by first-run and prompt-loop menus."""

    executable, offered = await _prompt_evaluator_executable()
    codex_home = Path(
        typer.prompt("Dedicated evaluator CODEX_HOME", default=str(default_codex_home()))
    ).expanduser()
    model = typer.prompt("Exact model", default=default_codex_subscription_model()).strip()
    reasoning_effort = typer.prompt(
        "Final review reasoning effort", default=default_codex_subscription_reasoning_effort()
    ).strip()
    routine_default = default_codex_subscription_routine_effort()
    routine_reasoning_effort = typer.prompt(
        "Routine checkpoint reasoning effort",
        default=reasoning_effort if routine_default is None else routine_default,
    ).strip()
    login_choice = typer.prompt("Login method (browser/device_code)", default="browser").strip()
    if login_choice not in {"browser", "device_code"}:
        raise ValueError("codex_login_method_invalid")
    preview = codex_subscription_preview(
        executable=executable,
        codex_home=codex_home,
        model=model,
        reasoning_effort=reasoning_effort,
        routine_reasoning_effort=routine_reasoning_effort,
    )
    typer.echo("")
    typer.echo("Codex with ChatGPT subscription")
    typer.echo(f"  runtime source: {preview['executable_path']}")
    typer.echo(
        f"  Codex version: {preview['runtime_version']} (minimum {preview['runtime_floor']})"
    )
    typer.echo(
        f"  bound runtime: {managed_runtime_path(runtime_bundle(), cast(str, preview['runtime_source_identity']))}"
        " (FinishUP's private copy; updating your everyday Codex leaves it unchanged until the next"
        " repair adopts the newer release)"
    )
    typer.echo(f"  executable_sha256: {preview['executable_sha256']}")
    typer.echo(f"  code-mode host sha256: {preview['code_mode_host_sha256']}")
    typer.echo(f"  capability check: {preview['capability_profile']}, before binding")
    typer.echo(f"  evidence expires: {preview['capability_evidence_expires_at']}")
    typer.echo(f"  dedicated CODEX_HOME: {preview['codex_home']}")
    typer.echo(f"  model: {model}")
    typer.echo(f"  reasoning: final {reasoning_effort} / routine {routine_reasoning_effort}")
    typer.echo("  destination: OpenAI through Codex-managed ChatGPT authentication")
    typer.echo("  data-use posture: unknown; your ChatGPT plan and terms apply")
    typer.echo("  FinishUP receives no OAuth credential and cannot observe the upstream body")
    typer.echo(f"  disconnect: {preview['disconnect_command']}")
    typer.echo(f"  rollback only: {preview['rollback_command']}")
    typer.echo("  a dedicated home Codex already reports signed in is reused without a new sign-in")
    if not typer.confirm("Continue to Codex sign-in?", default=False):
        raise ValueError("cancelled")
    switch_account = typer.confirm(
        "Log out the dedicated home first and sign in again (switch ChatGPT account)?",
        default=False,
    )
    return await codex_subscription_setup(
        # The accepted default keeps newest-first discovery with fallback; a typed path pins.
        executable=setup_executable_selection(executable, offered),
        codex_home=codex_home,
        model=model,
        reasoning_effort=reasoning_effort,
        routine_reasoning_effort=routine_reasoning_effort,
        login_mode=cast(Literal["browser", "device_code"], login_choice),
        open_browser=login_choice == "browser",
        switch_account=switch_account,
    )


def _endpoint_role(config: FinishUpConfig) -> Literal["primary", "fallback"]:
    pairing = config.semantic_fallback
    return "fallback" if pairing is not None and pairing.primary == "api_provider" else "primary"


async def codex_subscription_status(*, config_path: Path | None = None) -> dict[str, JsonValue]:
    """Report login/model readiness; a structurally unusable binding fails first, precisely.

    The structural diagnosis runs before any Codex process, so a replaced executable, an outdated
    capability identity, or a changed isolated config is named exactly instead of surfacing as a
    generic launch or credential failure (#855).
    """

    config = _base_config(config_path)
    binding = config.external_runtime
    if binding is None:
        raise ValueError("codex_subscription_not_configured")
    diagnosis = diagnose_bound_runtime(binding)
    if not diagnosis.ready:
        raise ValueError(diagnosis.state)
    return _safe_status(binding, await codex_account_status(_profile(binding)))


async def codex_subscription_disconnect(*, config_path: Path | None = None) -> dict[str, JsonValue]:
    """Prove the cleared config persists, confirm Codex logout, then remove only the binding.

    The removal write is render-validated and lock-probed before Codex logs the dedicated home
    out, so a local persistence failure cannot strand a logged-out home behind a binding that
    still claims to be active.
    """

    target = _target_config_path(config_path)
    config, expected_bytes = _config_snapshot(target)
    binding = config.external_runtime
    if binding is None:
        raise ValueError("codex_subscription_not_configured")
    _bounded_config_operation(
        lambda: preflight_config_write(
            cleared_external_runtime_config(config),
            target,
            expected_bytes=expected_bytes,
        )
    )
    status = await codex_logout(_profile(await _operational_binding(binding, config)))
    if status.cleanup == "failed":
        raise ValueError("codex_logout_unconfirmed")
    written = _bounded_config_operation(
        lambda: write_config_toml_if_unchanged(
            cleared_external_runtime_config(config),
            expected_bytes=expected_bytes,
            path=target,
        )
    )
    result = _safe_status(binding, status)
    result["binding_removed"] = True
    result["config_path"] = str(written)
    return result


def codex_subscription_rollback(*, config_path: Path | None = None) -> dict[str, JsonValue]:
    """Remove only the nonsecret binding; preserve the dedicated home and Codex install."""

    target = _target_config_path(config_path)
    config, expected_bytes = _config_snapshot(target)
    home = None if config.external_runtime is None else config.external_runtime.codex_home
    written = _bounded_config_operation(
        lambda: write_config_toml_if_unchanged(
            cleared_external_runtime_config(config),
            expected_bytes=expected_bytes,
            path=target,
        )
    )
    return {
        "schema": "yoetz.codex-subscription-rollback/1",
        "binding_removed": config.external_runtime is not None,
        "config_path": str(written),
        "codex_home_preserved": home,
        "codex_installation_preserved": True,
        # The retained evaluator runtimes are a separate resource with their own removal command.
        "evaluator_runtime_preserved": True,
    }


_REPAIR: Final = "finishup provider codex-subscription repair"
_SETUP: Final = "finishup provider codex-subscription setup"
_ROLLBACK: Final = "finishup provider codex-subscription rollback"
_RUNTIME_STATUS: Final = "finishup provider codex-subscription runtime status"
_RUNTIME_INSTALL: Final = "finishup provider codex-subscription runtime install"
_RUNTIME_REMOVE: Final = "finishup provider codex-subscription runtime remove"

# One executable continuation per structural state (#855). What to fix by hand first, where that
# is needed, is the token's operator remediation.
BINDING_CONTINUATIONS: Final[Mapping[str, str]] = {
    "codex_runtime_platform_unsupported": _ROLLBACK,
    "codex_runtime_binding_invalid": _SETUP,
    "codex_runtime_capability_evidence_stale": "finishup upgrade --help",
    "codex_runtime_capability_unsupported": _REPAIR,
    "codex_runtime_version_unsupported": _REPAIR,
    "codex_runtime_executable_missing": _REPAIR,
    "codex_runtime_executable_invalid": _REPAIR,
    "codex_runtime_executable_changed": _REPAIR,
    "codex_runtime_profile_outdated": _REPAIR,
    "codex_home_missing": _SETUP,
    "codex_home_unsafe": _REPAIR,
    "codex_runtime_config_missing": _REPAIR,
    "codex_runtime_config_changed": _REPAIR,
    "codex_runtime_unavailable": _RUNTIME_STATUS,
}

# Primary states ``repair`` resolves itself. Home faults are refused first on their own axis
# (``_refuse_home_fault``): repair never loosens permissions, overwrites a modified isolated
# config, or creates a new home; it only restores a missing FinishUP-owned config.
_REPAIRABLE_STATES: Final = RUNTIME_REBINDABLE_STATES | {"codex_runtime_config_missing", "ready"}
# Fixed by the endpoint profile itself, so never an owner choice to report.
_PROFILE_FIELDS: Final = frozenset(
    {"provider_id", "endpoint_profile_id", "endpoint_profile_version", "credential_authority"}
)

type InstallSource = Literal["selected", "managed", "binding", "discovered", "download"]


def binding_continuation(state: str) -> str | None:
    """The executable next step for one structural state; ``None`` when ready."""

    return BINDING_CONTINUATIONS.get(state)


def describe_runtime_download() -> tuple[str, ...]:
    """Plain-language implications shown before any download consent."""

    return (
        "package: @openai/codex@latest (the newest stable Codex) through your own npm and "
        "registry settings, with install scripts disabled",
        "only the native executable and its code-mode host are kept, in an owner-private FinishUP "
        "directory, and only after they pass the capability check; the rest of the download is "
        "deleted",
        "the capability check runs that Codex without any sign-in, task content, or model request",
        "your everyday Codex installation, settings, and sign-ins are not changed",
        "no task content, credential, or account data is sent",
        f"remove later: {_RUNTIME_REMOVE}",
    )


def _retained_report(bundle: Path, platform: CodexPlatform) -> list[JsonValue]:
    report: list[JsonValue] = []
    for retained in retained_runtimes(bundle, platform):
        state = inspect_managed_runtime(bundle, retained.source_identity)
        try:
            record: CodexCapabilityRecord | None = read_capability_record(retained.path.parent)
        except (OSError, ValueError):  # fmt: skip
            record = None
        report.append(
            {
                "source_identity": retained.source_identity,
                "runtime_version": retained.runtime_version,
                "path": str(retained.path),
                "state": state,
                "code_mode_host_path": str(codex_code_mode_host_path(retained.path)),
                "executable_sha256": None if record is None else record.executable_sha256,
                "code_mode_host_sha256": None if record is None else record.code_mode_host_sha256,
                "capability_profile": None if record is None else record.capability_profile,
            }
        )
    return report


def codex_evaluator_runtime_status(*, config_path: Path | None = None) -> dict[str, JsonValue]:
    """Read-only structural report; starts no Codex process and reads no credential."""

    config = _base_config(config_path)
    try:
        platform: CodexPlatform | None = host_codex_platform()
    except ValueError:
        platform = None
    bundle: Path | None = None
    retained: list[JsonValue] = []
    store_state: str | None = None
    if platform is not None:
        try:
            bundle = runtime_bundle()
        except ValueError:
            store_state = "unsafe"
        else:
            retained = _retained_report(bundle, platform)
            store_state = "present" if retained else "absent"
    binding = config.external_runtime
    binding_report: dict[str, JsonValue] | None = None
    next_command: str | None = None
    if binding is not None:
        diagnosis = diagnose_bound_runtime(binding)
        next_command = binding_continuation(diagnosis.state)
        uses_managed: bool | None = (
            None
            if bundle is None
            else is_managed_runtime_path(bundle, Path(binding.executable_path))
        )
        if next_command is None and uses_managed is False and platform is not None:
            # Ready, but still bound to a host installation its package manager can replace.
            next_command = _REPAIR
        binding_report = {
            "state": diagnosis.state,
            "capability": diagnosis.capability,
            "executable": diagnosis.executable,
            "code_mode_host": diagnosis.code_mode_host,
            "home": diagnosis.home,
            "executable_path": binding.executable_path,
            "code_mode_host_path": str(codex_code_mode_host_path(Path(binding.executable_path))),
            "uses_managed_runtime": uses_managed,
            "capability_profile": binding.capability_profile,
            "runtime_version": binding.runtime_version,
            "codex_home": binding.codex_home,
            "endpoint_role": _endpoint_role(config),
        }
    elif platform is not None and not any(
        cast(Mapping[str, object], item).get("state") == "verified" for item in retained
    ):
        next_command = _RUNTIME_INSTALL
    return {
        "schema": "yoetz.codex-evaluator-runtime-status/2",
        "platform": None if platform is None else platform.npm_suffix,
        "runtime_floor": CODEX_EVALUATOR_RUNTIME_FLOOR,
        "capability_profile": CODEX_EVALUATOR_CAPABILITY_PROFILE,
        "store": store_state,
        "retained_runtimes": retained,
        "binding": binding_report,
        "login_checked": False,
        "next_command": next_command,
    }


def _install_source(
    config: FinishUpConfig, source: Path | None, *, download: bool
) -> tuple[InstallSource, EvaluatorCandidate | None]:
    candidates = evaluator_candidates(config, executable=source)
    if candidates:
        return candidates[0].source, candidates[0]
    if download:
        return "download", None
    raise ValueError("codex_evaluator_runtime_unavailable")


def codex_evaluator_runtime_install_plan(
    *, source: Path | None, download: bool, config_path: Path | None = None
) -> dict[str, JsonValue]:
    """Say which runtime would be retained and checked, and from where, before any side effect."""

    platform = host_codex_platform()
    config = _base_config(config_path)
    bundle = runtime_bundle()
    kind, candidate = _install_source(config, source, download=download)
    identity = None if candidate is None else codex_source_identity(platform, candidate.version)
    return {
        "schema": "yoetz.codex-evaluator-runtime-install-plan/2",
        "source": kind,
        "source_path": None if candidate is None else str(candidate.path),
        "runtime_version": "latest" if candidate is None else candidate.version,
        "runtime_floor": CODEX_EVALUATOR_RUNTIME_FLOOR,
        "managed_runtime_path": (
            None if identity is None else str(managed_runtime_path(bundle, identity))
        ),
        "managed_runtime_state": (
            None if identity is None else inspect_managed_runtime(bundle, identity)
        ),
        "download": kind == "download",
    }


def _which_npm() -> Path:
    found = shutil.which("npm")
    if found is None:
        raise ValueError("codex_evaluator_runtime_package_manager_unavailable")
    return Path(found).absolute()


def _resolve_downloaded_wrapper(wrapper: Path) -> tuple[Path, str]:
    resolved = resolve_codex_executable(wrapper)
    return resolved.native, resolved.version


async def codex_evaluator_runtime_install(
    *,
    source: Path | None,
    npm: Path | None,
    download: bool,
    config_path: Path | None = None,
) -> dict[str, JsonValue]:
    """Retain and capability-check the newest eligible runtime; download only when authorized.

    A local source (or the newest eligible installation) is retained and checked. A download
    installs ``@openai/codex@latest`` into an owner-private staging prefix with scripts disabled
    and keeps only the native executable and its code-mode host. The check commits the capability
    record. Neither path edits the binding.
    """

    with runtime_mutation_lock(runtime_bundle()):
        platform = host_codex_platform()
        config = _base_config(config_path)
        bundle = runtime_bundle()
        kind, candidate = _install_source(config, source, download=download)
        if candidate is None:
            retained, version = provision_codex_runtime(
                bundle=bundle,
                platform=platform,
                npm=_which_npm() if npm is None else npm,
                resolve_wrapper=_resolve_downloaded_wrapper,
            )
            candidate = EvaluatorCandidate("managed", retained, version)
        checked = await _check_candidate(candidate, bundle=bundle)
        return {
            "schema": "yoetz.codex-evaluator-runtime-install/2",
            "source": kind,
            "managed_runtime_path": str(checked.retained),
            "managed_runtime_state": inspect_managed_runtime(
                bundle, checked.record.source_identity
            ),
            "runtime_version": checked.record.runtime_version,
            "executable_sha256": checked.record.executable_sha256,
            "code_mode_host_path": str(codex_code_mode_host_path(checked.retained)),
            "code_mode_host_sha256": checked.record.code_mode_host_sha256,
            "capability_cell_sha256": checked.record.digest,
            "capability_profile": checked.record.capability_profile,
            "binding_changed": False,
            "host_installation_changed": False,
            "next_command": _SETUP if config.external_runtime is None else _REPAIR,
        }


def codex_evaluator_runtime_remove(*, config_path: Path | None = None) -> dict[str, JsonValue]:
    """Delete every retained runtime the binding does not use; the binding and home stay.

    The release a binding uses is never removed; when it is the only retained runtime, removal is
    refused as ``codex_evaluator_runtime_in_use``.
    """

    with runtime_mutation_lock(runtime_bundle()):
        platform = host_codex_platform()
        config = _base_config(config_path)
        bundle = runtime_bundle()
        bound = None if config.external_runtime is None else config.external_runtime.executable_path
        retained = retained_runtimes(bundle, platform)
        removable = [item for item in retained if str(item.path) != bound]
        if retained and not removable:
            raise ValueError("codex_evaluator_runtime_in_use")
        removed: list[JsonValue] = []
        for item in removable:
            if remove_managed_runtime(bundle, item.source_identity):
                removed.append(str(item.path))
        return {
            "schema": "yoetz.codex-evaluator-runtime-remove/2",
            "removed_runtimes": removed,
            "removed": bool(removed),
            "kept_runtime_path": bound if bound in {str(item.path) for item in retained} else None,
            "binding_changed": False,
            "codex_home_preserved": True,
            "host_installation_changed": False,
        }


def _repair_candidates(
    config: FinishUpConfig, executable: Path | None
) -> tuple[ExternalRuntimeProfileConfig, str, tuple[EvaluatorCandidate, ...]]:
    """(existing binding, state before, candidates newest first) with no side effect."""

    existing = config.external_runtime
    if existing is None:
        raise ValueError("codex_subscription_not_configured")
    diagnosis = diagnose_bound_runtime(existing)
    # Only the FinishUP-owned isolated config may be restored; every other home fault is the
    # owner's to fix first, and a new home would not carry the existing sign-in anyway.
    _refuse_home_fault(diagnosis, restorable=frozenset({"config_missing"}))
    if diagnosis.state not in _REPAIRABLE_STATES:
        raise ValueError(diagnosis.state)
    candidates = evaluator_candidates(config, executable=executable)
    if not candidates:
        raise ValueError("codex_evaluator_runtime_unavailable")
    return existing, diagnosis.state, candidates


def _changed_fields(
    before: ExternalRuntimeProfileConfig, after: ExternalRuntimeProfileConfig
) -> list[JsonValue]:
    """Every field the rebind changed, identity fields first; owner choices never appear."""

    names = (
        *_IDENTITY_FIELDS,
        *(name for name in type(before).model_fields if name not in _IDENTITY_FIELDS),
    )
    return [name for name in names if getattr(before, name) != getattr(after, name)]


def codex_subscription_repair_plan(
    *, config_path: Path | None = None, executable: Path | None = None
) -> dict[str, JsonValue]:
    """Show what repair would try; no store, home, config, or Codex side effect.

    The candidate list is newest first; repair binds the first one that passes the capability
    check and lists the model for the dedicated home, so the exact identity fields are known
    only after that check.
    """

    existing, state, candidates = _repair_candidates(_base_config(config_path), executable)
    first = candidates[0]
    platform = host_codex_platform()
    identity = codex_source_identity(platform, first.version)
    return {
        "schema": "yoetz.codex-subscription-repair-plan/2",
        "state_before": state,
        "source": first.source,
        "source_path": str(first.path),
        "runtime_version_before": existing.runtime_version,
        "runtime_version_after": first.version,
        "candidates": [
            {"source": item.source, "path": str(item.path), "runtime_version": item.version}
            for item in candidates
        ],
        "capability_profile_before": existing.capability_profile,
        "capability_profile_after": CODEX_EVALUATOR_CAPABILITY_PROFILE,
        "executable_path_after": str(managed_runtime_path(runtime_bundle(), identity)),
        "capability_check": "runs on each candidate, newest first, before anything is written",
        # Every owner choice the binding carries, whatever this release names them.
        "preserved": {
            name: getattr(existing, name)
            for name in type(existing).model_fields
            if name not in _IDENTITY_FIELDS and name not in _PROFILE_FIELDS
        },
    }


async def codex_subscription_repair(
    *, config_path: Path | None = None, executable: Path | None = None
) -> dict[str, JsonValue]:
    """Rebind to the newest runtime that passes the capability check, preserving every choice.

    Order mirrors setup: the write is render-validated and lock-probed first, the dedicated home's
    FinishUP-owned config is restored only when absent, then candidates are retained, checked and
    probed newest first. Codex's own ``account/read``/``model/list`` probe must report the existing
    login usable before the binding is written against the exact preimage. A home that is not
    signed in fails with ``codex_subscription_login_required`` and nothing is written. Repair
    never starts a sign-in, logs out, or switches accounts; privacy grants are not part of the
    binding and do not move.
    """

    with runtime_mutation_lock(runtime_bundle()):
        target = _target_config_path(config_path)
        base, expected_bytes = _config_snapshot(target)
        existing, state, candidates = _repair_candidates(base, executable)
        bundle = runtime_bundle()
        make_binding = _rebinder(existing)
        provisional = make_binding(
            managed_runtime_path(bundle, _provisional_record(candidates[0]).source_identity),
            _provisional_record(candidates[0]),
        )
        _bounded_config_operation(
            lambda: preflight_config_write(
                external_runtime_binding_config(provisional, base=base),
                target,
                expected_bytes=expected_bytes,
            )
        )
        prepare_codex_home(Path(existing.codex_home))

        async def readiness(binding: ExternalRuntimeProfileConfig) -> CodexRuntimeStatus:
            return await codex_account_status(_profile(binding))

        adopted = await _adopt_runtime(
            candidates, bundle=bundle, make_binding=make_binding, readiness=readiness
        )
        repaired = adopted.binding
        status = adopted.status
        assert status is not None
        if not _already_ready(status):
            raise ValueError("codex_subscription_login_required")
        selected_config = external_runtime_binding_config(repaired, base=base)
        written = _bounded_config_operation(
            lambda: write_config_toml_if_unchanged(
                selected_config, expected_bytes=expected_bytes, path=target
            )
        )
        result = _safe_status(repaired, status)
        result.update(
            {
                "state_before": state,
                "source": adopted.checked.candidate.source,
                "runtime_retained_from": str(adopted.checked.candidate.path),
                "runtimes_passed_over": list(adopted.passed_over),
                "changed_fields": _changed_fields(existing, repaired),
                "login_reused": True,
                "endpoint_role": _endpoint_role(selected_config),
                "config_path": str(written),
            }
        )
        return result
