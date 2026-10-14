"""Guided Codex-owned ChatGPT login for the exact subscription evaluator cell."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import stat
import sys
import webbrowser
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

import typer

from finishup.adapters.providers.codex_app_server import (
    CODEX_CODE_MODE_HOST_NAME,
    CODEX_EVALUATOR_RUNTIME_VERSION,
    CodexAppServerProfile,
    CodexEvaluatorCell,
    CodexLoginChallenge,
    CodexRuntimeStatus,
    codex_account_status,
    codex_code_mode_host_path,
    codex_evaluator_cell_for_binding,
    codex_evaluator_cell_for_platform,
    codex_login,
    codex_logout,
    codex_model_listed,
    prepare_codex_home,
)
from finishup.adapters.providers.codex_evaluator_runtime import (
    CodexBindingDiagnosis,
    diagnose_codex_binding,
    host_codex_evaluator_cell,
    inspect_managed_code_mode_host,
    inspect_managed_runtime,
    managed_code_mode_host_path,
    managed_runtime_path,
    provision_codex_runtime,
    remove_managed_runtime,
    retain_codex_runtime,
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
    "admitted_native_executable",
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
    "default_codex_home",
    "default_codex_subscription_model",
    "codex_subscription_model_is_suggested",
    "CODEX_SUBSCRIPTION_FALLBACK_MODEL",
    "CODEX_SUBSCRIPTION_SUGGESTED_MODEL",
    "default_codex_subscription_routine_effort",
    "default_codex_subscription_reasoning_effort",
    "describe_runtime_download",
    "diagnose_bound_runtime",
    "prompt_codex_subscription_setup",
    "resolve_supported_codex_executable",
    "runtime_bundle",
    "select_codex_evaluator_executable",
    "subscription_failure_line",
    "subscription_failure_reason",
    "subscription_remediation",
]

_CODEX_PACKAGE_NAME: Final = "@openai/codex"
_CODEX_PACKAGE_JSON_MAX_BYTES: Final = 64 * 1024
_SUPPORTED_REASONING: Final = frozenset({"low", "medium", "high", "xhigh", "max", "ultra"})
# New bindings are offered gpt-6.1-sol at medium final effort. The admitted Codex must list it in
# its own model/list; when it does not (Codex 0.157.1's catalog predates it), setup binds the
# fallback, says so, and never substitutes for a model the owner typed or an existing binding.
CODEX_SUBSCRIPTION_SUGGESTED_MODEL: Final = "gpt-6.1-sol"
CODEX_SUBSCRIPTION_FALLBACK_MODEL: Final = "gpt-6-luna"
_DEFAULT_CODEX_SUBSCRIPTION_MODEL: Final = CODEX_SUBSCRIPTION_SUGGESTED_MODEL
_DEFAULT_CODEX_SUBSCRIPTION_REASONING: Final = "medium"
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
# Next steps for the evaluator-runtime tokens (#855). They are kept beside the subscription
# commands, not in the shared CLI remediation table, because every reason in that table must also
# carry a registered recovery directive; these are rendered only by subscription surfaces.
_SUBSCRIPTION_REMEDIATIONS: Final[Mapping[str, str]] = {
    "codex_runtime_executable_changed": (
        "the bound evaluator executable or its code-mode host no longer holds the admitted Codex "
        f"bytes (a Codex update usually replaced it); run {_REPAIR_COMMAND} to bind FinishUP's "
        "retained copy — the sign-in, model, and settings are kept"
    ),
    "codex_runtime_executable_missing": (
        "the bound evaluator executable or its code-mode host is gone; run "
        f"{_REPAIR_COMMAND} to bind FinishUP's retained copy — the sign-in, model, and settings are "
        "kept"
    ),
    "codex_runtime_executable_invalid": (
        "the bound evaluator executable or its code-mode host is not a regular owner-executable "
        f"file; run {_REPAIR_COMMAND}"
    ),
    "codex_runtime_code_mode_host_missing": (
        f"the selected Codex has no {CODEX_CODE_MODE_HOST_NAME} beside its native executable, "
        "which the admitted evaluator runtime needs; select the npm package's bin/codex.js, or "
        f"run {_INSTALL_COMMAND} --download"
    ),
    "codex_runtime_profile_outdated": (
        "this FinishUP release uses a newer reviewed capability identity for the same Codex runtime; "
        f"review and run {_REPAIR_COMMAND} — the sign-in, model, and settings are kept"
    ),
    "codex_runtime_capability_unsupported": (
        f"the Codex executable is not the admitted evaluator runtime (Codex "
        f"{CODEX_EVALUATOR_RUNTIME_VERSION} with the reviewed digest); your everyday Codex can "
        f"stay on any version — run {_INSTALL_COMMAND} --download to keep a verified copy, then "
        "setup or repair"
    ),
    "codex_runtime_not_found": (
        "the selected Codex executable or its platform package was not found; pass the exact "
        f"path, or run {_INSTALL_COMMAND} --download"
    ),
    "codex_evaluator_runtime_unavailable": (
        f"no Codex {CODEX_EVALUATOR_RUNTIME_VERSION} evaluator runtime was found; run "
        f"{_INSTALL_COMMAND} --download (or --from <path> for a local copy), then retry"
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
        "the current binding uses this retained runtime; run 'finishup provider codex-subscription "
        "disconnect' or 'rollback' first, then remove it"
    ),
    "codex_evaluator_runtime_download_failed": (
        "npm could not install the admitted Codex release (its output is not captured); check "
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
    "codex_model_unavailable": (
        "the admitted Codex does not list the selected model with the selected reasoning efforts "
        "for this sign-in; rerun 'finishup provider codex-subscription setup --model <id>' with a "
        f"model Codex lists ({CODEX_SUBSCRIPTION_FALLBACK_MODEL} works on Codex "
        f"{CODEX_EVALUATOR_RUNTIME_VERSION})"
    ),
    "codex_reasoning_effort_unavailable": (
        "the admitted Codex lists the selected model but not with the selected reasoning effort; "
        "rerun 'finishup provider codex-subscription setup' with --reasoning-effort and "
        "--routine-reasoning-effort values Codex lists for it (medium is widely listed)"
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
        "this platform has no reviewed evaluator cell, so the binding cannot run here; "
        "'finishup provider codex-subscription rollback' removes it"
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
    document: Mapping[str, JsonValue], cell: CodexEvaluatorCell
) -> None:
    """Validate the exact wrapper metadata for the closed evaluator cell."""

    if document.get("name") != _CODEX_PACKAGE_NAME:
        raise ValueError("codex_runtime_capability_unsupported")
    if document.get("version") != CODEX_EVALUATOR_RUNTIME_VERSION:
        raise ValueError("codex_runtime_capability_unsupported")
    binary_map = document.get("bin")
    if not isinstance(binary_map, Mapping) or binary_map.get("codex") != "bin/codex.js":
        raise ValueError("codex_runtime_capability_unsupported")
    optional_dependencies = document.get("optionalDependencies")
    if (
        not isinstance(optional_dependencies, Mapping)
        or optional_dependencies.get(f"@openai/{cell.native_package_directory}")
        != cell.native_package_spec
    ):
        raise ValueError("codex_runtime_capability_unsupported")


def _validate_codex_native_manifest(
    document: Mapping[str, JsonValue], cell: CodexEvaluatorCell
) -> None:
    """Validate the exact native package identity and platform selectors."""

    if document.get("name") != _CODEX_PACKAGE_NAME:
        raise ValueError("codex_runtime_capability_unsupported")
    if document.get("version") != cell.native_package_version:
        raise ValueError("codex_runtime_capability_unsupported")
    expected_cpu = "arm64" if cell.platform_architecture == "arm64" else "x64"
    if document.get("os") != [cell.platform_os] or document.get("cpu") != [expected_cpu]:
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


def _resolve_codex_package_layout(selected: Path, cell: CodexEvaluatorCell | None = None) -> Path:
    """Resolve a selected wrapper to its exact nested or npm-prefix native executable.

    The only allowed package roots are the optional dependency nested below the selected wrapper
    and its direct hoisted sibling. The nested candidate wins deterministically; a present but
    malformed nested package is terminal and never causes an unbounded parent/PATH search.
    """

    wrapper = _runtime_path(selected.expanduser(), missing_token="codex_runtime_not_found")
    selected_cell = cell or codex_evaluator_cell_for_platform(sys.platform, platform.machine())
    if wrapper.name != "codex.js" or wrapper.parent.name != "bin":
        return wrapper
    package_root = wrapper.parent.parent
    if package_root == Path(package_root.anchor):
        raise ValueError("codex_runtime_capability_unsupported")
    _validate_codex_wrapper_manifest(_package_json(package_root), selected_cell)

    nested = package_root / "node_modules" / "@openai" / selected_cell.native_package_directory
    hoisted = package_root.parent / selected_cell.native_package_directory
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
    _validate_codex_native_manifest(_package_json(native_root), selected_cell)
    native = _runtime_path(
        native_root / selected_cell.native_executable_relative,
        missing_token="codex_runtime_not_found",
    )
    try:
        native.relative_to(native_root)
    except ValueError as error:
        raise ValueError("codex_runtime_capability_unsupported") from error
    return native


def resolve_supported_codex_executable(selected: Path) -> tuple[Path, str, str]:
    """Resolve only the selected npm distribution to its exact native executable."""

    cell = codex_evaluator_cell_for_platform(sys.platform, platform.machine())
    resolved = _runtime_path(selected.expanduser(), missing_token="codex_runtime_not_found")
    if resolved.name == "codex.js" and resolved.parent.name == "bin":
        resolved = _resolve_codex_package_layout(resolved, cell)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("codex_runtime_executable_invalid")
    digest = _sha256_file(resolved)
    if digest != cell.executable_sha256:
        raise ValueError("codex_runtime_capability_unsupported")
    _verify_code_mode_host(resolved, cell)
    return resolved, digest, cell.source_identity


def _verify_code_mode_host(native: Path, cell: CodexEvaluatorCell) -> Path:
    """Require the admitted code-mode host beside the resolved native executable (#874).

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
    if _sha256_file(host) != cell.code_mode_host_sha256:
        raise ValueError("codex_runtime_capability_unsupported")
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
    """The data bundle whose owner-private store holds the retained evaluator runtime.

    It is resolved exactly like the service's own bundle and the default dedicated home
    (configuration file, environment, and isolation root), so an isolated or test instance never
    retains into, or binds, another instance's runtime.
    """

    config = _bounded_config_operation(lambda: load_config({}, os.environ, None))
    try:
        return bundle_root(_data_dir=config.storage.data_dir)
    except PathSafetyError as error:
        raise ValueError("codex_evaluator_runtime_store_unsafe") from error


def admitted_native_executable(selected: Path) -> Path | None:
    """Return the admitted native executable behind ``selected``, or ``None`` when it is not one.

    Eligibility is the exact capability-cell identity (layout, platform, and pinned digest), never
    a path name, version string, or discovery order.
    """

    try:
        native, digest, source_identity = resolve_supported_codex_executable(selected)
        cell = codex_evaluator_cell_for_platform(sys.platform, platform.machine())
    except OSError, ValueError:
        return None
    if digest != cell.executable_sha256 or source_identity != cell.source_identity:
        return None
    return native


type EvaluatorRuntimeSource = Literal["managed", "binding", "discovered"]


def select_codex_evaluator_executable(
    config: FinishUpConfig,
) -> tuple[EvaluatorRuntimeSource, Path] | None:
    """Select the evaluator runtime by eligibility and ownership, never by lexical path order.

    Preference: the FinishUP-managed retained runtime, then the existing binding's executable when it
    still holds the admitted bytes, then the first discovered host installation that resolves to
    the admitted cell. A discovered binary that is not the admitted cell is never offered.
    """

    try:
        cell = codex_evaluator_cell_for_platform(sys.platform, platform.machine())
    except ValueError:
        return None
    try:
        bundle = runtime_bundle()
    except ValueError:
        bundle = None
    if bundle is not None and inspect_managed_runtime(bundle, cell) == "verified":
        return "managed", managed_runtime_path(bundle, cell)
    if config.external_runtime is not None:
        bound = admitted_native_executable(Path(config.external_runtime.executable_path))
        if bound is not None:
            return "binding", bound
    from finishup.adapters.integrations.codex_discovery import discover_codex_binaries

    for binary in discover_codex_binaries():
        if admitted_native_executable(Path(binary.executable_path)) is not None:
            return "discovered", Path(binary.executable_path)
    return None


def default_codex_evaluator_executable(path: Path | None = None) -> Path | None:
    """The eligible evaluator runtime setup offers by default, or ``None`` when none exists."""

    selected = select_codex_evaluator_executable(_base_config(path))
    return None if selected is None else selected[1]


def diagnose_bound_runtime(binding: ExternalRuntimeProfileConfig) -> CodexBindingDiagnosis:
    """Structural diagnosis of one binding at the current time; never starts Codex."""

    return diagnose_codex_binding(binding, now=datetime.now(UTC))


def codex_subscription_preview(
    *,
    executable: Path,
    codex_home: Path,
    model: str,
    reasoning_effort: str,
    routine_reasoning_effort: str | None = None,
) -> dict[str, JsonValue]:
    """Resolve and validate the exact nonsecret cell without creating a home or logging in.

    ``reasoning_effort`` is the final-profile effort. ``routine_reasoning_effort=None`` means the
    routine profile keeps that single effort (the legacy binding shape).
    """

    native, digest, source_identity = resolve_supported_codex_executable(executable)
    cell = codex_evaluator_cell_for_platform(sys.platform, platform.machine())
    if source_identity != cell.source_identity or digest != cell.executable_sha256:
        raise ValueError("codex_runtime_capability_unsupported")
    if not codex_home.is_absolute():
        raise ValueError("codex_home_invalid")
    if not model or reasoning_effort not in _SUPPORTED_REASONING:
        raise ValueError("codex_runtime_model_invalid")
    if routine_reasoning_effort is not None and routine_reasoning_effort not in (
        _SUPPORTED_REASONING
    ):
        raise ValueError("codex_runtime_model_invalid")
    return {
        "schema": "yoetz.codex-subscription-preview/1",
        "credential_authority": "external_runtime_oauth",
        "runtime_version": CODEX_EVALUATOR_RUNTIME_VERSION,
        "runtime_source_identity": source_identity,
        "executable_path": str(native),
        "executable_sha256": digest,
        "code_mode_host_path": str(codex_code_mode_host_path(native)),
        "code_mode_host_sha256": cell.code_mode_host_sha256,
        "app_server_schema_sha256": cell.app_server_schema_sha256,
        "capability_cell_sha256": cell.capability_cell_sha256,
        "capability_profile": cell.capability_profile,
        "capability_evidence_expires_at": cell.capability_evidence_expires_at,
        "isolated_config_sha256": cell.isolated_config_sha256,
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


def codex_subscription_model_is_suggested(path: Path | None = None) -> bool:
    """True when no binding exists, so the model on offer is setup's own suggestion."""

    return _base_config(path).external_runtime is None


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
    executable: Path,
    codex_home: Path,
    model: str,
    reasoning_effort: str,
    routine_reasoning_effort: str | None = None,
    existing: ExternalRuntimeProfileConfig | None = None,
) -> ExternalRuntimeProfileConfig:
    """Validate and construct the exact nonsecret binding without creating any state.

    Output limits, timeout and retry budgets are configuration-only choices with no setup
    prompt; an existing binding preserves all of them during a rebind (#855).
    """

    preview = codex_subscription_preview(
        executable=executable,
        codex_home=codex_home,
        model=model,
        reasoning_effort=reasoning_effort,
        routine_reasoning_effort=routine_reasoning_effort,
    )
    return codex_subscription_runtime(
        executable_path=cast(str, preview["executable_path"]),
        executable_sha256=cast(str, preview["executable_sha256"]),
        runtime_version=CODEX_EVALUATOR_RUNTIME_VERSION,
        source_identity=cast(str, preview["runtime_source_identity"]),
        app_server_schema_sha256=cast(str, preview["app_server_schema_sha256"]),
        capability_cell_sha256=cast(str, preview["capability_cell_sha256"]),
        isolated_config_sha256=cast(str, preview["isolated_config_sha256"]),
        capability_profile=cast(str, preview["capability_profile"]),
        capability_evidence_expires_at=cast(
            Literal["2026-11-30T00:00:00Z"], preview["capability_evidence_expires_at"]
        ),
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


def _retained_binding(
    binding: ExternalRuntimeProfileConfig, *, bundle: Path
) -> ExternalRuntimeProfileConfig:
    """The same validated binding, pointed at the FinishUP-managed copy of its admitted runtime.

    Only the path changes: the digest, cell identity, and every other field are the ones the
    selected executable was just validated against, and the launch fence re-verifies the copy.
    """

    cell = codex_evaluator_cell_for_platform(sys.platform, platform.machine())
    return binding.model_copy(update={"executable_path": str(managed_runtime_path(bundle, cell))})


def _retain_binding_runtime(
    binding: ExternalRuntimeProfileConfig, *, source: Path, bundle: Path
) -> None:
    """Retain the admitted bytes behind ``source`` at the path ``binding`` is bound to."""

    cell = codex_evaluator_cell_for_platform(sys.platform, platform.machine())
    retained = retain_codex_runtime(source, bundle=bundle, cell=cell)
    if str(retained) != binding.executable_path:
        raise ValueError("codex_evaluator_runtime_store_unavailable")


def _profile(binding: ExternalRuntimeProfileConfig) -> CodexAppServerProfile:
    return CodexAppServerProfile.from_config(binding)


# Structural states another admitted runtime resolves: the bound bytes or capability identity are
# wrong, while the dedicated home (and the login Codex keeps in it) is intact.
RUNTIME_REBINDABLE_STATES: Final = frozenset(
    {
        "codex_runtime_capability_unsupported",
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


def _operational_binding(
    binding: ExternalRuntimeProfileConfig, config: FinishUpConfig
) -> ExternalRuntimeProfileConfig:
    """The binding to launch for a reverse operation on the same dedicated home.

    A stranded binding (replaced executable, outdated capability identity) must still be able to
    ask Codex to log its dedicated home out; the eligible admitted runtime is used in memory for
    that one probe. Nothing is persisted, and home or config faults still fail closed.
    """

    diagnosis = diagnose_bound_runtime(binding)
    if diagnosis.ready:
        return binding
    _refuse_home_fault(diagnosis)
    if diagnosis.state not in RUNTIME_REBINDABLE_STATES:
        raise ValueError(diagnosis.state)
    selected = select_codex_evaluator_executable(config)
    if selected is None:
        raise ValueError(diagnosis.state)
    return _rebound(binding, selected[1])


# The compatibility-critical fields a rebind takes from the admitted cell and selected executable.
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


def _rebound(
    existing: ExternalRuntimeProfileConfig, executable: Path
) -> ExternalRuntimeProfileConfig:
    """``existing`` with only its runtime identity replaced by the validated admitted cell."""

    validated = _binding(
        executable=executable,
        codex_home=Path(existing.codex_home),
        model=existing.model,
        reasoning_effort=existing.reasoning_effort,
        existing=existing,
    )
    return existing.model_copy(update={name: getattr(validated, name) for name in _IDENTITY_FIELDS})


def _already_ready(status: CodexRuntimeStatus) -> bool:
    """Codex proved a ChatGPT login and the exact model/reasoning cell for this home."""

    return status.runtime_ready and status.auth_mode == "chatgpt" and status.model_available


def _bound_code_mode_host_sha256(binding: ExternalRuntimeProfileConfig) -> str | None:
    """The host digest the binding's exact cell pins, or ``None`` for an unadmitted binding."""

    try:
        return codex_evaluator_cell_for_binding(
            source_identity=binding.source_identity,
            executable_sha256=binding.executable_sha256,
            runtime_version=binding.runtime_version,
            app_server_schema_sha256=binding.app_server_schema_sha256,
            capability_cell_sha256=binding.capability_cell_sha256,
            capability_profile=binding.capability_profile,
            capability_evidence_expires_at=binding.capability_evidence_expires_at,
            isolated_config_sha256=binding.isolated_config_sha256,
        ).code_mode_host_sha256
    except ValueError:
        return None


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
    model_is_suggestion: bool = False,
) -> dict[str, JsonValue]:
    """Validate the binding and its persistence, prove or obtain Codex login, then persist it.

    ``model_is_suggestion`` marks ``model`` as setup's own suggestion for a new binding rather than
    the owner's explicit choice. Only then, when the admitted Codex's ``model/list`` does not offer
    the suggested model with the selected efforts, setup binds
    :data:`CODEX_SUBSCRIPTION_FALLBACK_MODEL` instead, announces it, and reports
    ``model_fallback_from``. An explicit model or an existing binding is never substituted.

    ``as_fallback`` keeps the already-bound API provider as the primary and declares this
    runtime as its fallback (issue #582); it never replaces that binding.

    Every deterministic local requirement — the exact runtime cell, the canonical target
    configuration, and a render-validated, lock-probed write of the staged binding — is proven
    before any Codex process starts, so a configuration failure can never follow login side
    effects (#520).

    Login is Codex-owned state that lives once per dedicated home. Unless the caller asked to
    switch accounts, the same structural probe ``status`` uses (app-server ``account/read`` with
    ``refreshToken: false`` and ``model/list``) runs first; a home Codex already reports as
    signed in with the exact model cell available is bound without a new ``account/login/start``
    challenge (#534). FinishUP still never reads or copies ``auth.json``: readiness is only ever what
    Codex itself answers. ``switch_account`` remains the explicit override that logs the home out
    and signs in again.

    The evaluator runtime is kept separate from the host installation (#855): the admitted bytes
    behind ``executable`` are retained in the FinishUP-managed owner-private store and the binding
    points at that copy, so a later host Codex update cannot strand the binding. ``executable``
    ``None`` selects the eligible runtime (see :func:`select_codex_evaluator_executable`). An
    existing binding's timeout and retry budgets are preserved.
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
        if executable is None:
            selected = select_codex_evaluator_executable(base)
            if selected is None:
                raise ValueError("codex_evaluator_runtime_unavailable")
            executable = selected[1]
        validated = _binding(
            executable=executable,
            codex_home=codex_home,
            model=model,
            reasoning_effort=reasoning_effort,
            routine_reasoning_effort=selected_routine,
            existing=base.external_runtime,
        )
        bundle = runtime_bundle()
        binding = _retained_binding(validated, bundle=bundle)
        _bounded_config_operation(
            lambda: preflight_config_write(
                external_runtime_binding_config(binding, base=base, as_fallback=as_fallback),
                target,
                expected_bytes=expected_bytes,
            )
        )
        _retain_binding_runtime(binding, source=Path(validated.executable_path), bundle=bundle)
        prepare_codex_home(codex_home)
        model_fallback_from: str | None = None
        if (
            model_is_suggestion
            and base.external_runtime is None
            and model != CODEX_SUBSCRIPTION_FALLBACK_MODEL
            and not await codex_model_listed(_profile(binding))
        ):
            fallback = _retained_binding(
                _binding(
                    executable=executable,
                    codex_home=codex_home,
                    model=CODEX_SUBSCRIPTION_FALLBACK_MODEL,
                    reasoning_effort=reasoning_effort,
                    routine_reasoning_effort=selected_routine,
                    existing=base.external_runtime,
                ),
                bundle=bundle,
            )
            if await codex_model_listed(_profile(fallback)):
                _bounded_config_operation(
                    lambda: preflight_config_write(
                        external_runtime_binding_config(
                            fallback, base=base, as_fallback=as_fallback
                        ),
                        target,
                        expected_bytes=expected_bytes,
                    )
                )
                model_fallback_from = model
                binding = fallback
                typer.echo("")
                typer.echo(
                    f"Codex {binding.runtime_version} does not list the suggested model {model} "
                    f"with these reasoning efforts; using {CODEX_SUBSCRIPTION_FALLBACK_MODEL} "
                    "instead. After an upgrade that admits a newer Codex, rerun setup with "
                    f"--model {model} to switch."
                )
        profile = _profile(binding)
        login_reused = False
        if switch_account:
            logout_status = await codex_logout(profile)
            if logout_status.cleanup == "failed":
                raise ValueError("codex_logout_unconfirmed")
            status: CodexRuntimeStatus | None = None
        else:
            status = await codex_account_status(profile)
            if status.cleanup == "failed":
                raise ValueError("codex_subscription_readiness_unproven")
            if _already_ready(status):
                login_reused = True
                typer.echo("")
                typer.echo(
                    "Codex reports this dedicated home is already signed in with the exact model "
                    "available; reusing it without a new sign-in."
                )
            else:
                status = None

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

        if status is None:
            status = await codex_login(profile, mode=login_mode, present_challenge=present)
            if not _already_ready(status) or status.cleanup == "failed":
                raise ValueError("codex_subscription_readiness_unproven")
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
        if model_fallback_from is not None:
            result["model_fallback_from"] = model_fallback_from
        # An existing pairing keeps its selector, so report the role the written config holds.
        result["endpoint_role"] = _endpoint_role(selected_config)
        result["runtime_retained_from"] = validated.executable_path
        return result


def _prompt_evaluator_executable() -> Path:
    """Offer only an eligible evaluator runtime; offer the managed download when none exists.

    Discovery order is host inventory, not evaluator eligibility (#855): an unusable discovered
    binary is never presented as the ready default.
    """

    selected = default_codex_evaluator_executable()
    if selected is None:
        typer.echo("")
        typer.echo(
            f"No Codex {CODEX_EVALUATOR_RUNTIME_VERSION} evaluator runtime was found. Your "
            "everyday Codex can stay on any version: FinishUP keeps its own verified copy."
        )
        for line in describe_runtime_download():
            typer.echo(f"  {line}")
        if typer.confirm("Download the evaluator runtime now?", default=False):
            installed = codex_evaluator_runtime_install(source=None, npm=None, download=True)
            selected = Path(cast(str, installed["managed_runtime_path"]))
    return Path(
        typer.prompt(
            "Codex evaluator executable",
            default=None if selected is None else str(selected),
            show_default=selected is not None,
        )
    ).expanduser()


async def prompt_codex_subscription_setup() -> dict[str, JsonValue]:
    """Run the shared terminal setup screen used by first-run and prompt-loop menus."""

    executable = _prompt_evaluator_executable()
    codex_home = Path(
        typer.prompt("Dedicated evaluator CODEX_HOME", default=str(default_codex_home()))
    ).expanduser()
    suggested_model = default_codex_subscription_model()
    new_binding = codex_subscription_model_is_suggested()
    if new_binding:
        typer.echo(
            f"Suggested model: {suggested_model} at medium reasoning. If this Codex does not list "
            f"it, setup uses {CODEX_SUBSCRIPTION_FALLBACK_MODEL} and tells you. Press Enter to "
            "accept, or type another exact Codex model id."
        )
    model = typer.prompt("Exact model", default=suggested_model).strip()
    typer.echo(
        "Reasoning effort: final reviews run when the agent claims it is done; routine "
        "checkpoints run along the way. Higher effort is slower and uses more of your plan."
    )
    reasoning_effort = typer.prompt(
        "Final review reasoning effort", default=default_codex_subscription_reasoning_effort()
    ).strip()
    routine_default = default_codex_subscription_routine_effort()
    routine_reasoning_effort = typer.prompt(
        "Routine checkpoint reasoning effort",
        default=reasoning_effort if routine_default is None else routine_default,
    ).strip()
    login_choice = typer.prompt(
        "Sign-in method: browser opens a page here; device_code shows a code for another device "
        "(browser/device_code)",
        default="browser",
    ).strip()
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
        f"  bound runtime: {managed_runtime_path(runtime_bundle(), host_codex_evaluator_cell())}"
        " (FinishUP's verified private copy; updating your everyday Codex leaves it unchanged)"
    )
    typer.echo(f"  executable_sha256: {preview['executable_sha256']}")
    typer.echo(f"  code-mode host sha256: {preview['code_mode_host_sha256']}")
    typer.echo(f"  Codex version: {preview['runtime_version']}")
    typer.echo(f"  capability cell: {preview['capability_cell_sha256']}")
    typer.echo(f"  cell evidence expires: {preview['capability_evidence_expires_at']}")
    typer.echo(f"  dedicated CODEX_HOME: {preview['codex_home']}")
    model_is_suggestion = new_binding and model == suggested_model
    typer.echo(
        f"  model: {model}"
        + (
            f" (suggested; {CODEX_SUBSCRIPTION_FALLBACK_MODEL} if this Codex does not list it)"
            if model_is_suggestion and model != CODEX_SUBSCRIPTION_FALLBACK_MODEL
            else ""
        )
    )
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
        executable=executable,
        codex_home=codex_home,
        model=model,
        reasoning_effort=reasoning_effort,
        routine_reasoning_effort=routine_reasoning_effort,
        login_mode=cast(Literal["browser", "device_code"], login_choice),
        open_browser=login_choice == "browser",
        switch_account=switch_account,
        model_is_suggestion=model_is_suggestion,
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
    status = await codex_logout(_profile(_operational_binding(binding, config)))
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
        # The retained evaluator runtime is a separate resource with its own removal command.
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
        f"package: @openai/codex@{CODEX_EVALUATOR_RUNTIME_VERSION} through your own npm and "
        "registry settings, with install scripts disabled",
        "only the native executable and its code-mode host matching the reviewed evaluator "
        "SHA-256 values are kept, in an owner-private FinishUP directory; the rest of the download "
        "is deleted",
        "your everyday Codex installation, settings, and sign-ins are not changed",
        "no task content, credential, or account data is sent",
        f"remove later: {_RUNTIME_REMOVE}",
    )


def codex_evaluator_runtime_status(*, config_path: Path | None = None) -> dict[str, JsonValue]:
    """Read-only structural report; starts no Codex process and reads no credential."""

    config = _base_config(config_path)
    managed_path: str | None = None
    managed_state: str | None = None
    host_path: str | None = None
    host_state: str | None = None
    try:
        cell = host_codex_evaluator_cell()
    except ValueError:
        cell = None
    if cell is not None:
        try:
            bundle = runtime_bundle()
        except ValueError:
            managed_state = "unsafe"
            host_state = "unsafe"
        else:
            managed_path = str(managed_runtime_path(bundle, cell))
            managed_state = inspect_managed_runtime(bundle, cell)
            host_path = str(managed_code_mode_host_path(bundle, cell))
            host_state = inspect_managed_code_mode_host(bundle, cell)
    binding = config.external_runtime
    binding_report: dict[str, JsonValue] | None = None
    next_command: str | None = None
    if binding is not None:
        diagnosis = diagnose_bound_runtime(binding)
        next_command = binding_continuation(diagnosis.state)
        uses_managed = managed_path is not None and binding.executable_path == managed_path
        if next_command is None and not uses_managed and cell is not None:
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
    elif cell is not None and managed_state != "verified":
        next_command = _RUNTIME_INSTALL
    return {
        "schema": "yoetz.codex-evaluator-runtime-status/1",
        "platform_cell": None if cell is None else cell.source_identity,
        "admitted_runtime_version": CODEX_EVALUATOR_RUNTIME_VERSION,
        "managed_runtime": {
            "path": managed_path,
            "state": managed_state,
            "code_mode_host": {
                "path": host_path,
                "state": host_state,
                "sha256": None if cell is None else cell.code_mode_host_sha256,
            },
        },
        "binding": binding_report,
        "login_checked": False,
        "next_command": next_command,
    }


def _install_source(
    config: FinishUpConfig, source: Path | None, *, download: bool
) -> tuple[InstallSource, Path | None]:
    if source is not None:
        return "selected", source
    selected = select_codex_evaluator_executable(config)
    if selected is not None:
        return selected
    if download:
        return "download", None
    raise ValueError("codex_evaluator_runtime_unavailable")


def codex_evaluator_runtime_install_plan(
    *, source: Path | None, download: bool, config_path: Path | None = None
) -> dict[str, JsonValue]:
    """Say which admitted bytes would be retained, and from where, before any side effect."""

    cell = host_codex_evaluator_cell()
    config = _base_config(config_path)
    bundle = runtime_bundle()
    kind, selected = _install_source(config, source, download=download)
    if selected is not None and admitted_native_executable(selected) is None:
        raise ValueError("codex_runtime_capability_unsupported")
    return {
        "schema": "yoetz.codex-evaluator-runtime-install-plan/1",
        "source": kind,
        "source_path": None if selected is None else str(selected),
        "runtime_version": CODEX_EVALUATOR_RUNTIME_VERSION,
        "executable_sha256": cell.executable_sha256,
        "code_mode_host_sha256": cell.code_mode_host_sha256,
        "managed_runtime_path": str(managed_runtime_path(bundle, cell)),
        "managed_runtime_state": inspect_managed_runtime(bundle, cell),
        "download": kind == "download",
    }


def _which_npm() -> Path:
    found = shutil.which("npm")
    if found is None:
        raise ValueError("codex_evaluator_runtime_package_manager_unavailable")
    return Path(found).absolute()


def codex_evaluator_runtime_install(
    *,
    source: Path | None,
    npm: Path | None,
    download: bool,
    config_path: Path | None = None,
) -> dict[str, JsonValue]:
    """Retain the admitted runtime; download it with npm only when ``download`` authorizes it.

    A local source is retained only when it resolves to the admitted cell. A download installs the
    exact admitted release into an owner-private staging prefix with scripts disabled and keeps
    only the native executable that hashes to the pinned digest. Neither path edits the binding.
    """

    with runtime_mutation_lock(runtime_bundle()):
        cell = host_codex_evaluator_cell()
        config = _base_config(config_path)
        bundle = runtime_bundle()
        kind, selected = _install_source(config, source, download=download)
        if selected is None:
            retained = provision_codex_runtime(
                bundle=bundle,
                cell=cell,
                runtime_version=CODEX_EVALUATOR_RUNTIME_VERSION,
                npm=_which_npm() if npm is None else npm,
                resolve_wrapper=lambda wrapper: resolve_supported_codex_executable(wrapper)[0],
            )
        else:
            native = admitted_native_executable(selected)
            if native is None:
                raise ValueError("codex_runtime_capability_unsupported")
            retained = retain_codex_runtime(native, bundle=bundle, cell=cell)
        return {
            "schema": "yoetz.codex-evaluator-runtime-install/1",
            "source": kind,
            "managed_runtime_path": str(retained),
            "managed_runtime_state": inspect_managed_runtime(bundle, cell),
            "runtime_version": CODEX_EVALUATOR_RUNTIME_VERSION,
            "executable_sha256": cell.executable_sha256,
            "code_mode_host_path": str(managed_code_mode_host_path(bundle, cell)),
            "code_mode_host_sha256": cell.code_mode_host_sha256,
            "binding_changed": False,
            "host_installation_changed": False,
            "next_command": _SETUP if config.external_runtime is None else _REPAIR,
        }


def codex_evaluator_runtime_remove(*, config_path: Path | None = None) -> dict[str, JsonValue]:
    """Delete only an unreferenced retained runtime; the binding and home are untouched."""

    with runtime_mutation_lock(runtime_bundle()):
        cell = host_codex_evaluator_cell()
        config = _base_config(config_path)
        bundle = runtime_bundle()
        managed = str(managed_runtime_path(bundle, cell))
        if (
            config.external_runtime is not None
            and config.external_runtime.executable_path == managed
        ):
            raise ValueError("codex_evaluator_runtime_in_use")
        removed = remove_managed_runtime(bundle, cell)
        return {
            "schema": "yoetz.codex-evaluator-runtime-remove/1",
            "managed_runtime_path": managed,
            "removed": removed,
            "binding_changed": False,
            "codex_home_preserved": True,
            "host_installation_changed": False,
        }


def _repair_target(
    config: FinishUpConfig, executable: Path | None
) -> tuple[ExternalRuntimeProfileConfig, ExternalRuntimeProfileConfig, str, str, Path]:
    """(existing, repaired, state before, source kind, retained source) with no side effect."""

    existing = config.external_runtime
    if existing is None:
        raise ValueError("codex_subscription_not_configured")
    diagnosis = diagnose_bound_runtime(existing)
    # Only the FinishUP-owned isolated config may be restored; every other home fault is the
    # owner's to fix first, and a new home would not carry the existing sign-in anyway.
    _refuse_home_fault(diagnosis, restorable=frozenset({"config_missing"}))
    if diagnosis.state not in _REPAIRABLE_STATES:
        raise ValueError(diagnosis.state)
    if executable is not None:
        kind, source = "selected", executable
    else:
        selected = select_codex_evaluator_executable(config)
        if selected is None:
            raise ValueError("codex_evaluator_runtime_unavailable")
        kind, source = selected
    validated = _rebound(existing, source)
    repaired = _retained_binding(validated, bundle=runtime_bundle())
    return existing, repaired, diagnosis.state, kind, Path(validated.executable_path)


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
    """Show exactly what repair would change; no store, home, config, or Codex side effect."""

    existing, repaired, state, kind, source = _repair_target(_base_config(config_path), executable)
    return {
        "schema": "yoetz.codex-subscription-repair-plan/1",
        "state_before": state,
        "source": kind,
        "source_path": str(source),
        "changed_fields": _changed_fields(existing, repaired),
        "capability_profile_before": existing.capability_profile,
        "capability_profile_after": repaired.capability_profile,
        "executable_path_after": repaired.executable_path,
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
    """Rebind to the current admitted cell and retained runtime, preserving every choice.

    Order mirrors setup: the write is render-validated and lock-probed first, the runtime is
    retained, the dedicated home's FinishUP-owned config is restored only when absent, then Codex's
    own ``account/read``/``model/list`` probe must report the existing login usable before the
    binding is written against the exact preimage. A home that is not signed in fails with
    ``codex_subscription_login_required`` and nothing is written. Repair never starts a sign-in,
    logs out, or switches accounts; privacy grants are not part of the binding and do not move.
    """

    with runtime_mutation_lock(runtime_bundle()):
        target = _target_config_path(config_path)
        base, expected_bytes = _config_snapshot(target)
        existing, repaired, state, kind, source = _repair_target(base, executable)
        selected_config = external_runtime_binding_config(repaired, base=base)
        _bounded_config_operation(
            lambda: preflight_config_write(selected_config, target, expected_bytes=expected_bytes)
        )
        _retain_binding_runtime(repaired, source=source, bundle=runtime_bundle())
        prepare_codex_home(Path(repaired.codex_home))
        status = await codex_account_status(_profile(repaired))
        if status.cleanup == "failed":
            raise ValueError("codex_subscription_readiness_unproven")
        if not _already_ready(status):
            raise ValueError("codex_subscription_login_required")
        written = _bounded_config_operation(
            lambda: write_config_toml_if_unchanged(
                selected_config, expected_bytes=expected_bytes, path=target
            )
        )
        result = _safe_status(repaired, status)
        result.update(
            {
                "state_before": state,
                "source": kind,
                "changed_fields": _changed_fields(existing, repaired),
                "login_reused": True,
                "endpoint_role": _endpoint_role(selected_config),
                "config_path": str(written),
            }
        )
        return result
