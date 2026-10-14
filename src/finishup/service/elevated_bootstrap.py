"""Human-review consent for non-default actions (ADR-015 / ADR-016).

Pending consent is owner-only file state. Console input never substitutes for OS user presence.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, NoReturn, cast

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows uses msvcrt below
    fcntl = None  # type: ignore[assignment]
try:
    import msvcrt
except ImportError:  # pragma: no cover - POSIX uses fcntl above
    msvcrt = None  # type: ignore[assignment]

from finishup.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.application.privacy_policy import privacy_policy_changes
from finishup.config.paths import ensure_owner_only_dir, state_dir
from finishup.domain.privacy import (
    AuthorizationScopeKind,
    EgressChannel,
    PrivacyPolicy,
    PrivacyProfile,
    ReviewContextProfile,
)
from finishup.domain.values import ProtocolValueError, validate_commitment, validate_sha256_digest
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    parse_canonical_integer_string,
)
from finishup.protocol.consent import (
    CONSENT_PENDING_TTL_SECONDS,
    AgentSafePendingModel,
    ConsentCatalogModel,
    ConsentStatusModel,
    ImportPublicationPreviewModel,
    PrivacyPolicyChangeModel,
    RepositoryPrivacyGrantPreviewModel,
    RepositoryPrivacyProviderBindingModel,
    RepositoryPrivacyRecipe,
)
from finishup.protocol.ids import IdKind, validate_id
from finishup.service.confidential_protocol import ProviderCredentialTarget

__all__ = [
    "CONSENT_OPERATIONS",
    "ConsentOperationSpec",
    "ElevatedBootstrapError",
    "ElevatedOperation",
    "PendingElevatedConsent",
    "ImportPublicationAuthorization",
    "ProjectCoordinationAuthorization",
    "RiskClass",
    "catalog_payload",
    "claim_pending_for_review",
    "clear_pending",
    "complete_review",
    "grant_target_digest",
    "repository_grant_binding",
    "consume_import_publication_authorization",
    "load_import_publication_authorization",
    "load_project_coordination_audit_record_id",
    "load_pending",
    "operation_spec",
    "prepare_pending",
    "projection_for_status",
    "record_import_publication_authorization",
    "record_project_coordination_authorization",
    "load_project_coordination_authorization",
    "consume_project_coordination_authorization",
    "project_coordination_grant_binding",
    "project_coordination_target_digest",
    "status_payload",
]

RiskClass = Literal[
    "default_safe",
    "secret_ingress",
    "secret_reauth",
    "review_only",
    "privacy_widen",
]

ElevatedOperation = Literal[
    "vault_initialize",
    "vault_passphrase_rotate",
    "provider_credential_set",
    "provider_credential_rotate",
    "repository_privacy_grant",
    "import_publication",
    "idle_relock_disable",
    "privacy_policy_widen",
    "backup_execute",
    "restore_execute",
    "migrate_execute",
    "skill_install",
    "plugin_artifact_apply",
    "harness_mcp_register",
    "project_coordination_grant",
]

_SCHEMA: Final = "yoetz.elevated-bootstrap.pending/4"
_LEGACY_SCHEMAS: Final = frozenset(
    {
        "yoetz.elevated-bootstrap.pending/1",
        "yoetz.elevated-bootstrap.pending/2",
        "yoetz.elevated-bootstrap.pending/3",
    }
)
_TTL_SECONDS: Final = CONSENT_PENDING_TTL_SECONDS
_PENDING_NAME: Final = "elevated-bootstrap-pending.json"
_REVIEW_NAME: Final = "elevated-bootstrap-reviewing.json"
_REVIEW_LOCK_NAME: Final = ".elevated-bootstrap.lock"
_AUDIT_NAME: Final = "elevated-bootstrap-audit.jsonl"
_IMPORT_AUTHORIZATION_NAME: Final = "import-publication-authorization.json"
_PROJECT_COORDINATION_AUTHORIZATION_NAME: Final = "project-coordination-authorization.json"
_FORBIDDEN: Final = ("mcp", "argv", "env", "stdin", "config", "transcript")
_PROVIDER_BINDING_KEYS: Final = (
    "provider_id",
    "model_id",
    "endpoint_profile_id",
    "endpoint_profile_version",
    "purpose",
    "scope_digest",
    "purpose_digest",
)
_PROVIDER_REPOSITORY_KEY: Final = "repository_privacy_commitment"
_PROVIDER_BINDING_OPTIONAL_KEYS: Final = frozenset({_PROVIDER_REPOSITORY_KEY})
_GRANT_BINDING_KEYS: Final = ("schema", "preview", "current_policy", "candidate_policy")
_GRANT_RECIPES: Final[frozenset[RepositoryPrivacyRecipe]] = frozenset(
    {"assisted_review", "expanded_review", "private", "metadata_only"}
)
_COORDINATION_BINDING_SCHEMA: Final = "yoetz.project-coordination-grant-binding/1"
_COORDINATION_BINDING_KEYS: Final = (
    "schema",
    "project_id",
    "membership_generation",
    "action",
    "audit_record_id",
)


@dataclass(frozen=True, slots=True)
class ConsentOperationSpec:
    """One catalogued non-default (or default-safe reference) operation."""

    operation: str
    risk_class: RiskClass
    summary: str
    danger_text: str
    requires_provider_binding: bool
    requires_grant_binding: bool
    requires_target_digest_arg: bool
    implemented: bool
    agent_chat_authorize_allowed: bool


CONSENT_OPERATIONS: Final[tuple[ConsentOperationSpec, ...]] = (
    ConsentOperationSpec(
        operation="vault_initialize",
        risk_class="secret_ingress",
        summary="Create the local vault passphrase (cloud/no-TTY).",
        danger_text=(
            "DANGER — vault initialize. Creates this installation's encrypted vault and stores a "
            "helper-generated auto-unlock secret in the scoped platform credential store. Review "
            "may use independent action-bound OS user presence or an explicit current-chat "
            "instruction relayed by an allowlisted first-party agent. The helper generates and "
            "submits the secret locally; neither the agent nor chat may supply or receive it."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=False,
        implemented=True,
        agent_chat_authorize_allowed=True,
    ),
    ConsentOperationSpec(
        operation="vault_passphrase_rotate",
        risk_class="secret_reauth",
        summary="Rotate the passphrase vault with a helper-generated local secret.",
        danger_text=(
            "DANGER — vault passphrase rotate. Reauthenticates the ready vault and atomically "
            "replaces its passphrase envelope. After an explicit current-chat instruction, the "
            "trusted helper stages a random replacement in the scoped platform credential store "
            "and submits both secrets locally. Neither the agent nor chat may supply or receive "
            "either secret. A staged entry is retained across an ambiguous interruption so "
            "service restart can reconcile it safely."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=False,
        implemented=True,
        agent_chat_authorize_allowed=True,
    ),
    ConsentOperationSpec(
        operation="provider_credential_set",
        risk_class="secret_ingress",
        summary="Store an LLM API credential in the vault.",
        danger_text=(
            "DANGER — provider credential set. Stores an API credential in the local vault for the "
            "exact provider binding. Ordinary chat may retain or expose the value — prefer a "
            "confidential input surface or a limited/rotatable credential, or run "
            "`finishup consent review` locally. After one clear warning and an explicit current-chat "
            "instruction, the agent may attest and complete this exact action without a second "
            "terminal. FinishUP cannot independently authenticate the chat provenance."
        ),
        requires_provider_binding=True,
        requires_grant_binding=False,
        requires_target_digest_arg=False,
        implemented=True,
        agent_chat_authorize_allowed=True,
    ),
    ConsentOperationSpec(
        operation="provider_credential_rotate",
        risk_class="secret_ingress",
        summary="Rotate a stored LLM API credential.",
        danger_text=(
            "DANGER — provider credential rotate. Replaces a stored API credential for the exact "
            "provider binding. Ordinary chat may retain or expose the value — prefer confidential "
            "input or a limited/rotatable credential, or run `finishup consent review` locally. "
            "After one clear warning and an explicit current-chat instruction, the agent may "
            "attest and complete this exact action without a second terminal. FinishUP cannot "
            "independently authenticate the chat provenance."
        ),
        requires_provider_binding=True,
        requires_grant_binding=False,
        requires_target_digest_arg=False,
        implemented=True,
        agent_chat_authorize_allowed=True,
    ),
    ConsentOperationSpec(
        operation="repository_privacy_grant",
        risk_class="privacy_widen",
        summary="Grant one exact previewed repository privacy recipe.",
        danger_text=(
            "DANGER — repository privacy grant. Widens or sets external-review permission for one "
            "exact repository recipe and the complete before/after policy diff shown in the "
            "prepared preview. After one warning, an agent attesting an explicit current-chat "
            "instruction may complete only that expiring target. FinishUP cannot independently "
            "authenticate that provenance; the stronger local path remains `finishup --privacy`."
        ),
        requires_provider_binding=False,
        requires_grant_binding=True,
        requires_target_digest_arg=False,
        implemented=True,
        agent_chat_authorize_allowed=True,
    ),
    ConsentOperationSpec(
        operation="project_coordination_grant",
        risk_class="privacy_widen",
        summary="Grant bounded local coordination for one project generation.",
        danger_text=(
            "DANGER — project coordination grant. Allows bounded local disclosure for the exact "
            "project membership generation and audit record shown in this request. It does not "
            "authorize external semantic dispatch, attach, resume, or task selection. The grant "
            "expires if it is not consumed by that exact project operation."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=False,
        implemented=True,
        agent_chat_authorize_allowed=True,
    ),
    ConsentOperationSpec(
        operation="import_publication",
        risk_class="review_only",
        summary="Publish one exact bounded Codex JSONL import plan.",
        danger_text=(
            "DANGER — Codex JSONL import publication. Publishes only the prepared bounded plan "
            "shown below into the exact local task/session. Reasoning remains excluded, excerpt "
            "and source limits remain enforced, and this does not authorize reviewer egress. "
            "Authorization is one-use and any source, target, profile, or plan change invalidates it."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=False,
        implemented=True,
        agent_chat_authorize_allowed=True,
    ),
    ConsentOperationSpec(
        operation="idle_relock_disable",
        risk_class="secret_reauth",
        summary="Disable idle vault relock (weakens locked-session protection).",
        danger_text=(
            "DANGER — disable idle relock. Weakens automatic vault locking. Approve only from the "
            "verified foreground console after reviewing the exact change."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=False,
        implemented=False,
        agent_chat_authorize_allowed=False,
    ),
    ConsentOperationSpec(
        operation="privacy_policy_widen",
        risk_class="privacy_widen",
        summary="Widen standing privacy/egress policy.",
        danger_text=(
            "DANGER — privacy policy widen. Allows broader disclosure to agents or providers. "
            "Confirm the exact policy digest only if you intend this widening. Prefer "
            "`repository_privacy_grant` for exact recipe grants from chat."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=True,
        implemented=False,
        agent_chat_authorize_allowed=False,
    ),
    ConsentOperationSpec(
        operation="backup_execute",
        risk_class="review_only",
        summary="Execute a backup plan (irreversible artifact write).",
        danger_text=(
            "DANGER — backup execute. Writes a durable backup for the exact plan digest. Approve "
            "only from the verified foreground console after reviewing the preview."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=True,
        # Catalogued for ADR-016; prepare refuses until owning CLIs consume a durable grant.
        implemented=False,
        agent_chat_authorize_allowed=False,
    ),
    ConsentOperationSpec(
        operation="restore_execute",
        risk_class="review_only",
        summary="Execute a restore plan (may switch active route).",
        danger_text=(
            "DANGER — restore execute. May replace or switch local ledger state for the exact plan "
            "digest. Confirm only if you reviewed the preview. Recovery secrets never go in chat."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=True,
        implemented=False,
        agent_chat_authorize_allowed=False,
    ),
    ConsentOperationSpec(
        operation="migrate_execute",
        risk_class="review_only",
        summary="Execute a storage migration plan.",
        danger_text=(
            "DANGER — migrate execute. Changes on-disk storage layout for the exact plan digest. "
            "Confirm only if you reviewed the preview and backup preflight."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=True,
        implemented=False,
        agent_chat_authorize_allowed=False,
    ),
    ConsentOperationSpec(
        operation="skill_install",
        risk_class="review_only",
        summary="Install or replace a harness skill bundle.",
        danger_text=(
            "DANGER — skill install/replace. Changes agent guidance files for the exact preview "
            "digest. Confirm only if you reviewed the file list and digests."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=True,
        implemented=False,
        agent_chat_authorize_allowed=False,
    ),
    ConsentOperationSpec(
        operation="plugin_artifact_apply",
        risk_class="review_only",
        summary="Install, replace, or remove one portable plugin artifact.",
        danger_text=(
            "DANGER — portable plugin artifact apply. Replaces or removes the exact managed "
            "plugin tree bound to the preview digest. Confirm only after reviewing its format, "
            "target identity, current-state digest, and complete future inventory."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=True,
        implemented=True,
        agent_chat_authorize_allowed=False,
    ),
    ConsentOperationSpec(
        operation="harness_mcp_register",
        risk_class="review_only",
        summary="Register FinishUP as an MCP server in a harness config.",
        danger_text=(
            "DANGER — harness MCP registration. Mutates harness config for the exact preview "
            "digest. Confirm only if you reviewed the binary path and serve command."
        ),
        requires_provider_binding=False,
        requires_grant_binding=False,
        requires_target_digest_arg=True,
        implemented=False,
        agent_chat_authorize_allowed=False,
    ),
)

_OPS: Final[dict[str, ConsentOperationSpec]] = {spec.operation: spec for spec in CONSENT_OPERATIONS}


class ElevatedBootstrapError(Exception):
    """Bounded elevated-bootstrap failure with a stable reason token."""

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or not reason:
            raise TypeError("elevated_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class PendingElevatedConsent:
    """One active elevated consent pending record."""

    pending_id: str
    operation: ElevatedOperation
    risk_class: RiskClass
    danger_text: str
    danger_digest: str
    created_at_unix: int
    expires_at_unix: int
    target_digest: str
    provider_binding: Mapping[str, str] | None
    grant_binding: Mapping[str, JsonValue] | None = None
    import_publication_preview: Mapping[str, JsonValue] | None = None
    coordination_binding: Mapping[str, JsonValue] | None = None

    def as_json(self) -> dict[str, JsonValue]:
        payload: dict[str, JsonValue] = {
            "schema": _SCHEMA,
            "pending_id": self.pending_id,
            "state": "pending",
            "operation": self.operation,
            "risk_class": self.risk_class,
            "danger_text": self.danger_text,
            "danger_digest": self.danger_digest,
            "created_at_unix": self.created_at_unix,
            "expires_at_unix": self.expires_at_unix,
            "target_digest": self.target_digest,
        }
        if self.provider_binding is not None:
            payload["provider_binding"] = dict(self.provider_binding)
        if self.grant_binding is not None:
            payload["grant_binding"] = dict(self.grant_binding)
        if self.import_publication_preview is not None:
            payload["import_publication_preview"] = dict(self.import_publication_preview)
        if self.coordination_binding is not None:
            payload["coordination_binding"] = dict(self.coordination_binding)
        return payload


@dataclass(frozen=True, slots=True)
class ImportPublicationAuthorization:
    """Owner-only, exact, non-bearer handoff from consent to the importer."""

    pending_id: str
    danger_digest: str
    target_digest: str
    expires_at_unix: int

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "schema": "yoetz.import-publication-authorization/1",
            "pending_id": self.pending_id,
            "danger_digest": self.danger_digest,
            "target_digest": self.target_digest,
            "expires_at_unix": self.expires_at_unix,
        }


@dataclass(frozen=True, slots=True)
class ProjectCoordinationAuthorization:
    """One-use owner-only proof for one exact project-generation grant.

    This is deliberately a narrow handoff from the existing elevated consent ceremony to the
    project application.  It is not a bearer token: the application recomputes the binding from
    its live project generation and audit record, then consumes this record under the same lock.
    """

    pending_id: str
    danger_digest: str
    target_digest: str
    project_id: str
    membership_generation: int
    action: Literal["grant"]
    audit_record_id: str
    expires_at_unix: int

    def __post_init__(self) -> None:
        try:
            if type(self.pending_id) is not str or len(self.pending_id) != 64:
                raise ValueError("project_coordination_authorization_invalid")
            if any(character not in "0123456789abcdef" for character in self.pending_id):
                raise ValueError("project_coordination_authorization_invalid")
            validate_sha256_digest(self.danger_digest)
            validate_sha256_digest(self.target_digest)
            validate_id(IdKind.PROJECT, self.project_id)
            if (
                type(self.membership_generation) is not int
                or not 1 <= self.membership_generation <= 2**53 - 1
            ):
                raise ValueError("project_coordination_authorization_invalid")
            if self.action != "grant":
                raise ValueError("project_coordination_authorization_invalid")
            validate_id(IdKind.EVENT, self.audit_record_id)
            if type(self.expires_at_unix) is not int or self.expires_at_unix <= 0:
                raise ValueError("project_coordination_authorization_invalid")
        except (TypeError, ValueError, ProtocolValueError) as exc:
            raise ValueError("project_coordination_authorization_invalid") from exc

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "schema": "yoetz.project-coordination-authorization/1",
            "pending_id": self.pending_id,
            "danger_digest": self.danger_digest,
            "target_digest": self.target_digest,
            "project_id": self.project_id,
            "membership_generation": str(self.membership_generation),
            "action": self.action,
            "audit_record_id": self.audit_record_id,
            "expires_at_unix": self.expires_at_unix,
        }


def operation_spec(operation: str) -> ConsentOperationSpec:
    try:
        return _OPS[operation]
    except KeyError as exc:
        raise ElevatedBootstrapError("operation_invalid") from exc


def elevated_dir(*, _state: Path | None = None) -> Path:
    root = state_dir() if _state is None else _state
    path = root / "elevated-bootstrap"
    ensure_owner_only_dir(path)
    return path


def pending_path(*, _state: Path | None = None) -> Path:
    return elevated_dir(_state=_state) / _PENDING_NAME


def review_path(*, _state: Path | None = None) -> Path:
    return elevated_dir(_state=_state) / _REVIEW_NAME


def _import_authorization_path(*, _state: Path | None = None) -> Path:
    return elevated_dir(_state=_state) / _IMPORT_AUTHORIZATION_NAME


def _project_coordination_authorization_path(*, _state: Path | None = None) -> Path:
    return elevated_dir(_state=_state) / _PROJECT_COORDINATION_AUTHORIZATION_NAME


class _PendingStateLock:
    """Owner-only advisory lock spanning every pending-state transition."""

    def __init__(self, state: Path | None) -> None:
        self._path = elevated_dir(_state=state) / _REVIEW_LOCK_NAME
        self._descriptor: int | None = None

    def __enter__(self) -> None:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            try:
                existing = self._path.lstat()
            except FileNotFoundError:
                existing = None
            if existing is not None and stat.S_ISLNK(existing.st_mode):
                raise OSError("pending_lock_unsafe")
            descriptor = os.open(self._path, flags, 0o600)
            facts = os.fstat(descriptor)
            effective_uid = (
                os.geteuid()
                if hasattr(os, "geteuid")
                else os.getuid()
                if hasattr(os, "getuid")
                else None
            )
            if not stat.S_ISREG(facts.st_mode) or (
                effective_uid is not None
                and hasattr(facts, "st_uid")
                and facts.st_uid != effective_uid
            ):
                raise OSError("pending_lock_unsafe")
            fchmod = getattr(os, "fchmod", None)
            if fchmod is not None:
                fchmod(descriptor, 0o600)
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            elif msvcrt is not None:
                self._acquire_windows(descriptor)
            else:
                raise OSError("pending_lock_unsupported")
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise ElevatedBootstrapError("pending_lock_failed") from exc
        self._descriptor = descriptor

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is not None:
            try:
                if fcntl is None and msvcrt is not None:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    windows_msvcrt = cast(Any, msvcrt)
                    windows_msvcrt.locking(descriptor, windows_msvcrt.LK_UNLCK, 1)
            finally:
                os.close(descriptor)

    @staticmethod
    def _acquire_windows(descriptor: int) -> None:
        if msvcrt is None:  # pragma: no cover - guarded by __enter__
            raise OSError("pending_lock_unsupported")
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        windows_msvcrt = cast(Any, msvcrt)
        while True:
            try:
                windows_msvcrt.locking(descriptor, windows_msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                time.sleep(0.05)


def audit_path(*, _state: Path | None = None) -> Path:
    return elevated_dir(_state=_state) / _AUDIT_NAME


def _danger_digest(
    *,
    operation: str,
    risk_class: str,
    danger_text: str,
    target_digest: str,
    pending_id: str,
    expires_at_unix: int,
    provider_binding: Mapping[str, str] | None,
    grant_binding: Mapping[str, JsonValue] | None = None,
    import_publication_preview: Mapping[str, JsonValue] | None = None,
    coordination_binding: Mapping[str, JsonValue] | None = None,
) -> str:
    body: dict[str, JsonValue] = {
        "danger_text": danger_text,
        "expires_at_unix": expires_at_unix,
        "operation": operation,
        "pending_id": pending_id,
        "risk_class": risk_class,
        "schema": "yoetz.elevated-bootstrap.danger/2",
        "target_digest": target_digest,
    }
    if provider_binding is not None:
        body["provider_binding"] = dict(provider_binding)
    if grant_binding is not None:
        body["grant_binding"] = dict(grant_binding)
    if import_publication_preview is not None:
        body["import_publication_preview"] = dict(import_publication_preview)
    if coordination_binding is not None:
        body["coordination_binding"] = dict(coordination_binding)
    return canonical_digest(body)


def prepare_pending(
    operation: ElevatedOperation,
    *,
    target_digest: str,
    provider_binding: Mapping[str, str] | None = None,
    grant_binding: Mapping[str, JsonValue] | None = None,
    import_publication_preview: Mapping[str, JsonValue] | None = None,
    coordination_binding: Mapping[str, JsonValue] | None = None,
    _state: Path | None = None,
) -> PendingElevatedConsent:
    spec = operation_spec(operation)
    if not spec.implemented:
        raise ElevatedBootstrapError("operation_not_implemented")
    if spec.requires_provider_binding and provider_binding is None:
        raise ElevatedBootstrapError("provider_binding_required")
    if not spec.requires_provider_binding and provider_binding is not None:
        raise ElevatedBootstrapError("provider_binding_forbidden")
    if spec.requires_grant_binding and grant_binding is None:
        raise ElevatedBootstrapError("grant_binding_required")
    if not spec.requires_grant_binding and grant_binding is not None:
        raise ElevatedBootstrapError("grant_binding_forbidden")
    if operation == "import_publication":
        if import_publication_preview is None:
            raise ElevatedBootstrapError("import_publication_preview_required")
        try:
            preview_model = ImportPublicationPreviewModel.model_validate(
                dict(import_publication_preview)
            )
        except (TypeError, ValueError) as exc:
            raise ElevatedBootstrapError("import_publication_preview_invalid") from exc
        preview = cast(
            dict[str, JsonValue],
            preview_model.model_dump(mode="json", by_alias=True),
        )
        if preview_model.authorization_target_digest != target_digest:
            raise ElevatedBootstrapError("import_publication_preview_invalid")
    elif import_publication_preview is not None:
        raise ElevatedBootstrapError("import_publication_preview_forbidden")
    else:
        preview = None
    if operation == "project_coordination_grant":
        if coordination_binding is None:
            raise ElevatedBootstrapError("coordination_binding_required")
        coordination = _validated_coordination_binding(coordination_binding)
    elif coordination_binding is not None:
        raise ElevatedBootstrapError("coordination_binding_forbidden")
    else:
        coordination = None
    binding = (
        _validated_provider_binding(provider_binding) if provider_binding is not None else None
    )
    grant = _validated_grant_binding(grant_binding) if grant_binding is not None else None
    try:
        validated_digest = validate_sha256_digest(target_digest)
    except ProtocolValueError as exc:
        raise ElevatedBootstrapError("target_digest_invalid") from exc
    if operation == "project_coordination_grant":
        if not _exact_match(
            validated_digest,
            project_coordination_target_digest(cast(Mapping[str, JsonValue], coordination)),
        ):
            raise ElevatedBootstrapError("coordination_binding_invalid")
    with _PendingStateLock(_state):
        if (
            operation == "import_publication"
            and _load_import_authorization_unlocked(_state=_state) is not None
        ):
            raise ElevatedBootstrapError("import_publication_authorization_active")
        if (
            operation == "project_coordination_grant"
            and _load_project_coordination_authorization_unlocked(_state=_state) is not None
        ):
            raise ElevatedBootstrapError("project_coordination_authorization_active")
        if review_path(_state=_state).is_file():
            raise ElevatedBootstrapError("review_in_progress")
        existing = _load_pending_unlocked(_state=_state)
        if existing is not None and existing.expires_at_unix > int(time.time()):
            raise ElevatedBootstrapError("pending_already_active")
        now = int(time.time())
        pending_id = secrets.token_hex(32)
        text = spec.danger_text
        expires = now + _TTL_SECONDS
        digest = _danger_digest(
            operation=operation,
            risk_class=spec.risk_class,
            danger_text=text,
            target_digest=validated_digest,
            pending_id=pending_id,
            expires_at_unix=expires,
            provider_binding=binding,
            grant_binding=grant,
            import_publication_preview=preview,
            coordination_binding=coordination,
        )
        pending = PendingElevatedConsent(
            pending_id=pending_id,
            operation=operation,
            risk_class=spec.risk_class,
            danger_text=text,
            danger_digest=digest,
            created_at_unix=now,
            expires_at_unix=expires,
            target_digest=validated_digest,
            provider_binding=binding,
            grant_binding=grant,
            import_publication_preview=preview,
            coordination_binding=coordination,
        )
        _write_pending(pending, _state=_state)
        _audit(
            {
                "event": "prepare",
                "operation": operation,
                "risk_class": spec.risk_class,
                "pending_id": pending_id,
                "danger_digest": digest,
                "expires_at_unix": expires,
            },
            _state=_state,
        )
    return pending


def _validated_coordination_binding(
    binding: Mapping[str, JsonValue],
) -> dict[str, JsonValue]:
    """Validate the exact project-generation grant binding used by consent.

    The binding contains identities and a generation only.  It deliberately contains no project
    title, description, path, task content, or caller supplied authority label.
    """

    if set(binding) != set(_COORDINATION_BINDING_KEYS):
        raise ElevatedBootstrapError("coordination_binding_invalid")
    if binding.get("schema") != _COORDINATION_BINDING_SCHEMA:
        raise ElevatedBootstrapError("coordination_binding_invalid")
    project_value = binding.get("project_id")
    audit_value = binding.get("audit_record_id")
    generation_value = binding.get("membership_generation")
    if type(project_value) is not str or type(audit_value) is not str:
        raise ElevatedBootstrapError("coordination_binding_invalid")
    try:
        project = validate_id(IdKind.PROJECT, project_value)
        audit_record_id = validate_id(IdKind.EVENT, audit_value)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise ElevatedBootstrapError("coordination_binding_invalid") from exc
    if type(generation_value) is not str:
        raise ElevatedBootstrapError("coordination_binding_invalid")
    try:
        generation = parse_canonical_integer_string(generation_value)
    except (TypeError, ValueError) as exc:
        raise ElevatedBootstrapError("coordination_binding_invalid") from exc
    if generation <= 0 or generation > 2**53 - 1:
        raise ElevatedBootstrapError("coordination_binding_invalid")
    if binding.get("action") != "grant":
        raise ElevatedBootstrapError("coordination_binding_invalid")
    return {
        "schema": _COORDINATION_BINDING_SCHEMA,
        "project_id": project,
        "membership_generation": str(generation),
        "action": "grant",
        "audit_record_id": audit_record_id,
    }


def project_coordination_grant_binding(
    *,
    project_id: str,
    membership_generation: int,
    audit_record_id: str,
) -> dict[str, JsonValue]:
    """Build one exact, canonical binding for a local project coordination grant."""

    if type(membership_generation) is not int:
        raise ElevatedBootstrapError("coordination_binding_invalid")
    return _validated_coordination_binding(
        {
            "schema": _COORDINATION_BINDING_SCHEMA,
            "project_id": project_id,
            "membership_generation": str(membership_generation),
            "action": "grant",
            "audit_record_id": audit_record_id,
        }
    )


def project_coordination_target_digest(
    binding: Mapping[str, JsonValue],
) -> str:
    """Return the target digest bound to one project coordination grant."""

    normalized = _validated_coordination_binding(binding)
    return canonical_digest({"kind": "project_coordination_grant", "binding": normalized})


def _validated_provider_binding(binding: Mapping[str, str]) -> dict[str, str]:
    keys = set(binding)
    required = set(_PROVIDER_BINDING_KEYS)
    if keys != required and keys != required | _PROVIDER_BINDING_OPTIONAL_KEYS:
        raise ElevatedBootstrapError("provider_binding_invalid")
    normalized: dict[str, str] = {}
    for key in _PROVIDER_BINDING_KEYS:
        value = binding[key]
        if type(value) is not str or not value:
            raise ElevatedBootstrapError("provider_binding_invalid")
        if key in {"scope_digest", "purpose_digest"}:
            try:
                normalized[key] = validate_sha256_digest(value)
            except ProtocolValueError as exc:
                raise ElevatedBootstrapError("provider_binding_invalid") from exc
        else:
            normalized[key] = value
    if _PROVIDER_REPOSITORY_KEY in binding:
        try:
            normalized[_PROVIDER_REPOSITORY_KEY] = validate_commitment(
                binding[_PROVIDER_REPOSITORY_KEY]
            )
        except ProtocolValueError as exc:
            raise ElevatedBootstrapError("provider_binding_invalid") from exc
    try:
        ProviderCredentialTarget(
            action="set",
            provider_id=normalized["provider_id"],
            model_id=normalized["model_id"],
            endpoint_profile_id=normalized["endpoint_profile_id"],
            endpoint_profile_version=normalized["endpoint_profile_version"],
            purpose=normalized["purpose"],
            scope_digest=normalized["scope_digest"],
            purpose_digest=normalized["purpose_digest"],
            repository_privacy_commitment=normalized.get(_PROVIDER_REPOSITORY_KEY),
        )
    except (TypeError, ValueError) as exc:
        raise ElevatedBootstrapError("provider_binding_invalid") from exc
    return normalized


def repository_grant_binding(
    *,
    recipe: RepositoryPrivacyRecipe,
    repository_privacy_commitment: str,
    authority_digest: str,
    current_policy: PrivacyPolicy,
    candidate_policy: PrivacyPolicy,
) -> dict[str, JsonValue]:
    """Build the exact, agent-reviewable binding for one named repository recipe."""

    if recipe not in _GRANT_RECIPES or not _candidate_matches_grant_recipe(
        recipe, candidate_policy
    ):
        raise ElevatedBootstrapError("grant_binding_invalid")
    changes = tuple(
        PrivacyPolicyChangeModel.from_domain(change)
        for change in privacy_policy_changes(current_policy, candidate_policy)
    )
    change_payload: list[JsonValue] = [
        cast(JsonValue, change.model_dump(mode="json")) for change in changes
    ]
    llm = next(
        channel
        for channel in candidate_policy.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    preview = RepositoryPrivacyGrantPreviewModel(
        schema="yoetz.repository-privacy-grant-preview/1",
        recipe=recipe,
        repository_privacy_commitment=repository_privacy_commitment,
        authority_digest=authority_digest,
        current_policy_digest=current_policy.policy_digest,
        candidate_policy_digest=candidate_policy.policy_digest,
        diff_digest=canonical_digest(change_payload),
        candidate_profile=candidate_policy.profile.value,
        candidate_review_context=cast(
            Literal["structural", "assisted", "expanded"],
            candidate_policy.review_context_profile.value,
        ),
        candidate_provider_binding=(
            None
            if llm.provider_binding is None
            else RepositoryPrivacyProviderBindingModel.from_domain(llm.provider_binding)
        ),
        changes=changes,
    )
    return _validated_grant_binding(
        {
            "schema": "yoetz.repository-privacy-grant-binding/2",
            "preview": cast(JsonValue, preview.model_dump(mode="json", by_alias=True)),
            "current_policy": cast(JsonValue, encode_privacy_policy_json(current_policy)),
            "candidate_policy": cast(JsonValue, encode_privacy_policy_json(candidate_policy)),
        }
    )


def _candidate_matches_grant_recipe(
    recipe: RepositoryPrivacyRecipe, candidate: PrivacyPolicy
) -> bool:
    llm = next(
        channel
        for channel in candidate.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    if recipe == "private":
        return (
            candidate.profile is PrivacyProfile.LOCAL_ONLY
            and candidate.review_context_profile is ReviewContextProfile.STRUCTURAL
            and not llm.enabled
        )
    if recipe == "metadata_only":
        return (
            candidate.profile is PrivacyProfile.CONFIRM_EVERY_REQUEST
            and candidate.review_context_profile is ReviewContextProfile.STRUCTURAL
            and llm.enabled
            and llm.preview_required
        )
    if recipe == "assisted_review":
        return (
            candidate.profile in {PrivacyProfile.MINIMAL_EXTERNAL, PrivacyProfile.TRUSTED_PROVIDER}
            and candidate.review_context_profile is ReviewContextProfile.ASSISTED
            and llm.enabled
            and not llm.preview_required
        )
    return (
        candidate.profile is PrivacyProfile.TRUSTED_PROVIDER
        and candidate.review_context_profile is ReviewContextProfile.EXPANDED
        and llm.enabled
        and not llm.preview_required
    )


def _validated_grant_binding(binding: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    if set(binding) != set(_GRANT_BINDING_KEYS):
        raise ElevatedBootstrapError("grant_binding_invalid")
    if binding["schema"] != "yoetz.repository-privacy-grant-binding/2":
        raise ElevatedBootstrapError("grant_binding_invalid")
    preview_raw = binding["preview"]
    current_raw = binding["current_policy"]
    candidate_raw = binding["candidate_policy"]
    if not isinstance(preview_raw, Mapping):
        raise ElevatedBootstrapError("grant_binding_invalid")
    try:
        preview = RepositoryPrivacyGrantPreviewModel.model_validate(dict(preview_raw))
        if preview.recipe not in _GRANT_RECIPES:
            raise ValueError("grant_recipe_invalid")
        current = decode_privacy_policy_canonical(canonical_encode(current_raw))
        candidate = decode_privacy_policy_canonical(canonical_encode(candidate_raw))
        llm = next(
            channel
            for channel in candidate.channel_policies
            if channel.channel is EgressChannel.LLM_INFERENCE
        )
        if (
            not _candidate_matches_grant_recipe(preview.recipe, candidate)
            or current.policy_digest != preview.current_policy_digest
            or candidate.policy_digest != preview.candidate_policy_digest
            or candidate.profile.value != preview.candidate_profile
            or candidate.review_context_profile.value != preview.candidate_review_context
            or llm.provider_binding
            != (
                None
                if preview.candidate_provider_binding is None
                else preview.candidate_provider_binding.to_domain()
            )
            or candidate.policy_id != current.policy_id
            or candidate.version != current.version + 1
            or candidate.supersedes_policy_digest != current.policy_digest
        ):
            raise ValueError("grant_policy_binding_invalid")
        expected_changes = privacy_policy_changes(current, candidate)
        if tuple(change.to_domain() for change in preview.changes) != expected_changes:
            raise ValueError("grant_diff_invalid")
        if current.effective_scope != candidate.effective_scope:
            raise ValueError("grant_scope_invalid")
        for policy in (current, candidate):
            scope = policy.effective_scope
            if scope.kind is AuthorizationScopeKind.MACHINE:
                continue
            if scope.kind is not AuthorizationScopeKind.WORKSPACE:
                raise ValueError("grant_scope_invalid")
            if scope.workspace_ref_commitment != preview.repository_privacy_commitment:
                raise ValueError("grant_scope_invalid")
    except (TypeError, ValueError, ProtocolValueError) as exc:
        raise ElevatedBootstrapError("grant_binding_invalid") from exc
    return {
        "schema": "yoetz.repository-privacy-grant-binding/2",
        "preview": cast(JsonValue, preview.model_dump(mode="json", by_alias=True)),
        "current_policy": cast(JsonValue, encode_privacy_policy_json(current)),
        "candidate_policy": cast(JsonValue, encode_privacy_policy_json(candidate)),
    }


def grant_target_digest(grant_binding: Mapping[str, JsonValue]) -> str:
    """Canonical target digest for one exact repository privacy grant."""

    binding = _validated_grant_binding(grant_binding)
    return canonical_digest({"kind": "repository_privacy_grant", "binding": binding})


def _require_int(value: object) -> int:
    if type(value) is not int or isinstance(value, bool):
        raise ElevatedBootstrapError("pending_corrupt")
    return value


def _require_str(value: object) -> str:
    if type(value) is not str or not value:
        raise ElevatedBootstrapError("pending_corrupt")
    return value


def _validated_pending_id(value: object) -> str:
    pending_id = _require_str(value)
    if len(pending_id) != 64 or any(
        character not in "0123456789abcdef" for character in pending_id
    ):
        raise ElevatedBootstrapError("pending_corrupt")
    return pending_id


def _invalidate_legacy(path: Path, *, _state: Path | None) -> NoReturn:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise ElevatedBootstrapError("pending_clear_failed") from exc
    _audit({"event": "legacy_pending_invalidated"}, _state=_state)
    raise ElevatedBootstrapError("legacy_pending_invalidated")


def _load_pending_path(
    path: Path,
    *,
    _state: Path | None,
    expire: bool,
) -> PendingElevatedConsent | None:
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ElevatedBootstrapError("pending_corrupt") from exc
    if not isinstance(raw, dict):
        raise ElevatedBootstrapError("pending_corrupt")
    source = cast(dict[str, object], raw)
    if source.get("schema") in _LEGACY_SCHEMAS:
        _invalidate_legacy(path, _state=_state)
    try:
        if source.get("schema") != _SCHEMA:
            raise ElevatedBootstrapError("pending_corrupt")
        expected_keys = {
            "created_at_unix",
            "danger_digest",
            "danger_text",
            "expires_at_unix",
            "operation",
            "pending_id",
            "risk_class",
            "schema",
            "state",
            "target_digest",
        }
        if "provider_binding" in source:
            expected_keys.add("provider_binding")
        if "grant_binding" in source:
            expected_keys.add("grant_binding")
        if "import_publication_preview" in source:
            expected_keys.add("import_publication_preview")
        if "coordination_binding" in source:
            expected_keys.add("coordination_binding")
        if set(source) != expected_keys or source.get("state") != "pending":
            raise ElevatedBootstrapError("pending_corrupt")
        operation = _require_str(source["operation"])
        if operation not in _OPS:
            raise ElevatedBootstrapError("pending_corrupt")
        spec = _OPS[operation]
        binding_raw = source.get("provider_binding")
        binding: dict[str, str] | None
        if binding_raw is None:
            binding = None
        elif isinstance(binding_raw, dict) and all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in cast(dict[object, object], binding_raw).items()
        ):
            try:
                binding = _validated_provider_binding(
                    {str(k): str(v) for k, v in cast(dict[object, object], binding_raw).items()}
                )
            except ElevatedBootstrapError as exc:
                raise ElevatedBootstrapError("pending_corrupt") from exc
        else:
            raise ElevatedBootstrapError("pending_corrupt")
        grant_raw = source.get("grant_binding")
        grant: dict[str, JsonValue] | None
        if grant_raw is None:
            grant = None
        elif isinstance(grant_raw, dict) and all(
            isinstance(key, str) for key in cast(dict[object, object], grant_raw)
        ):
            try:
                grant = _validated_grant_binding(cast(dict[str, JsonValue], grant_raw))
            except ElevatedBootstrapError as exc:
                raise ElevatedBootstrapError("pending_corrupt") from exc
        else:
            raise ElevatedBootstrapError("pending_corrupt")
        if spec.requires_provider_binding and binding is None:
            raise ElevatedBootstrapError("pending_corrupt")
        if not spec.requires_provider_binding and binding is not None:
            raise ElevatedBootstrapError("pending_corrupt")
        if spec.requires_grant_binding and grant is None:
            raise ElevatedBootstrapError("pending_corrupt")
        if not spec.requires_grant_binding and grant is not None:
            raise ElevatedBootstrapError("pending_corrupt")
        preview_raw = source.get("import_publication_preview")
        preview: dict[str, JsonValue] | None
        if preview_raw is None:
            preview = None
        elif isinstance(preview_raw, dict):
            try:
                preview_model = ImportPublicationPreviewModel.model_validate(preview_raw)
            except (TypeError, ValueError) as exc:
                raise ElevatedBootstrapError("pending_corrupt") from exc
            preview = cast(
                dict[str, JsonValue], preview_model.model_dump(mode="json", by_alias=True)
            )
        else:
            raise ElevatedBootstrapError("pending_corrupt")
        if operation == "import_publication":
            if preview is None or preview["authorization_target_digest"] != source["target_digest"]:
                raise ElevatedBootstrapError("pending_corrupt")
        elif preview is not None:
            raise ElevatedBootstrapError("pending_corrupt")
        coordination_raw = source.get("coordination_binding")
        coordination: dict[str, JsonValue] | None
        if coordination_raw is None:
            coordination = None
        elif isinstance(coordination_raw, dict) and all(
            isinstance(key, str) for key in cast(dict[object, object], coordination_raw)
        ):
            try:
                coordination = _validated_coordination_binding(
                    cast(dict[str, JsonValue], coordination_raw)
                )
            except ElevatedBootstrapError as exc:
                raise ElevatedBootstrapError("pending_corrupt") from exc
        else:
            raise ElevatedBootstrapError("pending_corrupt")
        if (operation == "project_coordination_grant") != (coordination is not None):
            raise ElevatedBootstrapError("pending_corrupt")
        risk = _require_str(source["risk_class"])
        danger_text = _require_str(source["danger_text"])
        if risk != spec.risk_class or danger_text != spec.danger_text:
            raise ElevatedBootstrapError("pending_tampered")
        target_digest = validate_sha256_digest(_require_str(source["target_digest"]))
        danger_digest = validate_sha256_digest(_require_str(source["danger_digest"]))
        if operation == "project_coordination_grant":
            if coordination is None or not _exact_match(
                target_digest, project_coordination_target_digest(coordination)
            ):
                raise ElevatedBootstrapError("pending_tampered")
        created_at = _require_int(source["created_at_unix"])
        expires_at = _require_int(source["expires_at_unix"])
        if created_at <= 0 or expires_at - created_at != _TTL_SECONDS:
            raise ElevatedBootstrapError("pending_tampered")
        pending = PendingElevatedConsent(
            pending_id=_validated_pending_id(source["pending_id"]),
            operation=operation,  # type: ignore[arg-type]
            risk_class=risk,  # type: ignore[arg-type]
            danger_text=danger_text,
            danger_digest=danger_digest,
            created_at_unix=created_at,
            expires_at_unix=expires_at,
            target_digest=target_digest,
            provider_binding=binding,
            grant_binding=grant,
            import_publication_preview=preview,
            coordination_binding=coordination,
        )
    except ElevatedBootstrapError:
        raise
    except (KeyError, TypeError, ValueError, ProtocolValueError) as exc:
        raise ElevatedBootstrapError("pending_corrupt") from exc
    expected = _danger_digest(
        operation=pending.operation,
        risk_class=pending.risk_class,
        danger_text=pending.danger_text,
        target_digest=pending.target_digest,
        pending_id=pending.pending_id,
        expires_at_unix=pending.expires_at_unix,
        provider_binding=pending.provider_binding,
        grant_binding=pending.grant_binding,
        import_publication_preview=pending.import_publication_preview,
        coordination_binding=pending.coordination_binding,
    )
    if not _exact_match(expected, pending.danger_digest):
        raise ElevatedBootstrapError("pending_tampered")
    if expire and pending.expires_at_unix <= int(time.time()):
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise ElevatedBootstrapError("pending_clear_failed") from exc
        _audit(
            {"event": "expire", "pending_id": pending.pending_id, "operation": pending.operation},
            _state=_state,
        )
        return None
    return pending


def _load_pending_unlocked(*, _state: Path | None = None) -> PendingElevatedConsent | None:
    claim = review_path(_state=_state)
    path = pending_path(_state=_state)
    if claim.is_file():
        # Creating the hard-link marker is the atomic ownership transition. A reader that
        # observes it is a loser and must not mutate either name: the winning claimant owns
        # removal of the public pending name, and an interrupted winner deliberately leaves
        # the private marker in place to block reuse.
        return None
    return _load_pending_path(path, _state=_state, expire=True)


def load_pending(*, _state: Path | None = None) -> PendingElevatedConsent | None:
    with _PendingStateLock(_state):
        return _load_pending_unlocked(_state=_state)


def clear_pending(*, _state: Path | None = None) -> None:
    with _PendingStateLock(_state):
        path = pending_path(_state=_state)
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise ElevatedBootstrapError("pending_clear_failed") from exc


def _load_import_authorization_unlocked(
    *, _state: Path | None = None, expire: bool = True
) -> ImportPublicationAuthorization | None:
    path = _import_authorization_path(_state=_state)
    if not path.is_file():
        return None
    try:
        decoded = json.loads(path.read_bytes().decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ElevatedBootstrapError("import_publication_authorization_corrupt")
        raw = cast(dict[str, object], decoded)
        if set(raw) != {
            "schema",
            "pending_id",
            "danger_digest",
            "target_digest",
            "expires_at_unix",
        }:
            raise ElevatedBootstrapError("import_publication_authorization_corrupt")
        if raw.get("schema") != "yoetz.import-publication-authorization/1":
            raise ElevatedBootstrapError("import_publication_authorization_corrupt")
        authorization = ImportPublicationAuthorization(
            pending_id=_validated_pending_id(raw["pending_id"]),
            danger_digest=validate_sha256_digest(_require_str(raw["danger_digest"])),
            target_digest=validate_sha256_digest(_require_str(raw["target_digest"])),
            expires_at_unix=_require_int(raw["expires_at_unix"]),
        )
    except ElevatedBootstrapError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ElevatedBootstrapError("import_publication_authorization_corrupt") from exc
    if authorization.expires_at_unix <= int(time.time()):
        if expire:
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                raise ElevatedBootstrapError(
                    "import_publication_authorization_clear_failed"
                ) from exc
            _audit(
                {
                    "event": "import_publication_authorization_expired",
                    "target_digest": authorization.target_digest,
                },
                _state=_state,
            )
        return None
    return authorization


def load_import_publication_authorization(
    target_digest: str, *, _state: Path | None = None
) -> ImportPublicationAuthorization | None:
    """Load only an exact unexpired internal grant; no token is returned to callers."""

    try:
        expected = validate_sha256_digest(target_digest)
    except ProtocolValueError as exc:
        raise ElevatedBootstrapError("target_digest_invalid") from exc
    with _PendingStateLock(_state):
        authorization = _load_import_authorization_unlocked(_state=_state)
        if authorization is None or not _exact_match(authorization.target_digest, expected):
            return None
        return authorization


def record_import_publication_authorization(
    pending: PendingElevatedConsent, *, _state: Path | None = None
) -> ImportPublicationAuthorization:
    """Record the one exact owner-only handoff after an approved consent decision."""

    if (
        type(pending) is not PendingElevatedConsent
        or pending.operation != "import_publication"
        or pending.import_publication_preview is None
    ):
        raise ElevatedBootstrapError("import_publication_preview_required")
    authorization = ImportPublicationAuthorization(
        pending.pending_id,
        pending.danger_digest,
        pending.target_digest,
        pending.expires_at_unix,
    )
    with _PendingStateLock(_state):
        existing = _load_import_authorization_unlocked(_state=_state)
        if existing is not None and existing != authorization:
            raise ElevatedBootstrapError("import_publication_authorization_active")
        path = _import_authorization_path(_state=_state)
        payload = canonical_encode(authorization.as_json())
        tmp = path.with_suffix(".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(tmp, flags, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        _audit(
            {
                "event": "import_publication_authorized",
                "pending_id": pending.pending_id,
                "target_digest": pending.target_digest,
            },
            _state=_state,
        )
    return authorization


def consume_import_publication_authorization(
    authorization: ImportPublicationAuthorization, *, _state: Path | None = None
) -> None:
    """Consume the exact handoff only after terminal import completion."""

    if type(authorization) is not ImportPublicationAuthorization:
        raise TypeError("import_publication_authorization_invalid")
    with _PendingStateLock(_state):
        observed = _load_import_authorization_unlocked(_state=_state, expire=False)
        if observed is None or observed != authorization:
            raise ElevatedBootstrapError("import_publication_authorization_mismatch")
        try:
            _import_authorization_path(_state=_state).unlink()
        except OSError as exc:
            raise ElevatedBootstrapError("import_publication_authorization_clear_failed") from exc
        _audit(
            {
                "event": "import_publication_authorization_consumed",
                "target_digest": authorization.target_digest,
            },
            _state=_state,
        )


def _load_project_coordination_authorization_unlocked(
    *, _state: Path | None = None, expire: bool = True
) -> ProjectCoordinationAuthorization | None:
    path = _project_coordination_authorization_path(_state=_state)
    if not path.is_file():
        return None
    try:
        decoded = json.loads(path.read_bytes().decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ElevatedBootstrapError("project_coordination_authorization_corrupt")
        raw = cast(dict[str, object], decoded)
        expected_keys = {
            "schema",
            "pending_id",
            "danger_digest",
            "target_digest",
            "project_id",
            "membership_generation",
            "action",
            "audit_record_id",
            "expires_at_unix",
        }
        if (
            set(raw) != expected_keys
            or raw.get("schema") != "yoetz.project-coordination-authorization/1"
        ):
            raise ElevatedBootstrapError("project_coordination_authorization_corrupt")
        binding = _validated_coordination_binding(
            cast(
                dict[str, JsonValue],
                {
                    "schema": _COORDINATION_BINDING_SCHEMA,
                    "project_id": raw["project_id"],
                    "membership_generation": raw["membership_generation"],
                    "action": raw["action"],
                    "audit_record_id": raw["audit_record_id"],
                },
            )
        )
        authorization = ProjectCoordinationAuthorization(
            pending_id=_validated_pending_id(raw["pending_id"]),
            danger_digest=validate_sha256_digest(_require_str(raw["danger_digest"])),
            target_digest=validate_sha256_digest(_require_str(raw["target_digest"])),
            project_id=cast(str, binding["project_id"]),
            membership_generation=parse_canonical_integer_string(
                cast(str, binding["membership_generation"])
            ),
            action="grant",
            audit_record_id=cast(str, binding["audit_record_id"]),
            expires_at_unix=_require_int(raw["expires_at_unix"]),
        )
        expected_target = project_coordination_target_digest(binding)
        if not _exact_match(authorization.target_digest, expected_target):
            raise ElevatedBootstrapError("project_coordination_authorization_corrupt")
    except ElevatedBootstrapError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        ProtocolValueError,
    ) as exc:
        raise ElevatedBootstrapError("project_coordination_authorization_corrupt") from exc
    if authorization.expires_at_unix <= int(time.time()):
        if expire:
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                raise ElevatedBootstrapError(
                    "project_coordination_authorization_clear_failed"
                ) from exc
            _audit(
                {
                    "event": "project_coordination_authorization_expired",
                    "target_digest": authorization.target_digest,
                },
                _state=_state,
            )
        return None
    return authorization


def load_project_coordination_authorization(
    *,
    project_id: str,
    membership_generation: int,
    audit_record_id: str,
    _state: Path | None = None,
) -> ProjectCoordinationAuthorization | None:
    """Load a project grant only when every live binding field matches exactly."""

    try:
        binding = project_coordination_grant_binding(
            project_id=project_id,
            membership_generation=membership_generation,
            audit_record_id=audit_record_id,
        )
    except ElevatedBootstrapError:
        raise
    expected = project_coordination_target_digest(binding)
    with _PendingStateLock(_state):
        authorization = _load_project_coordination_authorization_unlocked(_state=_state)
        if authorization is None or not _exact_match(authorization.target_digest, expected):
            return None
        return authorization


def load_project_coordination_audit_record_id(
    *,
    project_id: str,
    membership_generation: int,
    _state: Path | None = None,
) -> str | None:
    """Recover the stable audit identity for a pending or approved project grant.

    A grant command may omit ``audit_record_id`` on its first attempt.  The authority mints that
    identity into the owner-only pending binding, so a retry can recover the same challenge after
    the command response was lost.  This returns only the validated event identity and never
    returns consent material.
    """

    if type(membership_generation) is not int:
        raise ElevatedBootstrapError("coordination_binding_invalid")
    try:
        validated_project = validate_id(IdKind.PROJECT, project_id)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise ElevatedBootstrapError("coordination_binding_invalid") from exc
    if not 1 <= membership_generation <= 2**53 - 1:
        raise ElevatedBootstrapError("coordination_binding_invalid")
    with _PendingStateLock(_state):
        authorization = _load_project_coordination_authorization_unlocked(_state=_state)
        if (
            authorization is not None
            and authorization.project_id == validated_project
            and authorization.membership_generation == membership_generation
        ):
            return authorization.audit_record_id
        # A review claim deliberately blocks ordinary reads.  The approved artifact above is the
        # only retry identity that is safe to expose while a human review owns the claim.
        if review_path(_state=_state).is_file():
            return None
        pending = _load_pending_unlocked(_state=_state)
        if pending is None or pending.operation != "project_coordination_grant":
            return None
        binding = pending.coordination_binding
        if binding is None:
            return None
        if (
            binding.get("project_id") == validated_project
            and binding.get("membership_generation") == str(membership_generation)
            and binding.get("action") == "grant"
        ):
            audit_record_id = binding.get("audit_record_id")
            return audit_record_id if type(audit_record_id) is str else None
        return None


def record_project_coordination_authorization(
    pending: PendingElevatedConsent, *, _state: Path | None = None
) -> ProjectCoordinationAuthorization:
    """Persist the one exact project-generation handoff after consent approval."""

    if (
        type(pending) is not PendingElevatedConsent
        or pending.operation != "project_coordination_grant"
        or pending.coordination_binding is None
    ):
        raise ElevatedBootstrapError("coordination_binding_required")
    binding = _validated_coordination_binding(pending.coordination_binding)
    expected_target = project_coordination_target_digest(binding)
    if not _exact_match(pending.target_digest, expected_target):
        raise ElevatedBootstrapError("coordination_binding_invalid")
    authorization = ProjectCoordinationAuthorization(
        pending_id=pending.pending_id,
        danger_digest=pending.danger_digest,
        target_digest=pending.target_digest,
        project_id=cast(str, binding["project_id"]),
        membership_generation=parse_canonical_integer_string(
            cast(str, binding["membership_generation"])
        ),
        action="grant",
        audit_record_id=cast(str, binding["audit_record_id"]),
        expires_at_unix=pending.expires_at_unix,
    )
    with _PendingStateLock(_state):
        existing = _load_project_coordination_authorization_unlocked(_state=_state)
        if existing is not None and existing != authorization:
            raise ElevatedBootstrapError("project_coordination_authorization_active")
        path = _project_coordination_authorization_path(_state=_state)
        ensure_owner_only_dir(path.parent)
        payload = canonical_encode(authorization.as_json())
        # A unique sibling avoids treating a crash-left temporary file as a live
        # authorization and keeps retries safe after an interrupted write.
        tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(tmp, flags, 0o600)
            try:
                os.write(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(tmp, path)
        except BaseException:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        os.chmod(path, 0o600)
        _audit(
            {
                "event": "project_coordination_authorized",
                "pending_id": pending.pending_id,
                "target_digest": pending.target_digest,
            },
            _state=_state,
        )
    return authorization


def consume_project_coordination_authorization(
    authorization: ProjectCoordinationAuthorization, *, _state: Path | None = None
) -> None:
    """Consume an exact project grant handoff under the owner-only consent lock."""

    if type(authorization) is not ProjectCoordinationAuthorization:
        raise TypeError("project_coordination_authorization_invalid")
    with _PendingStateLock(_state):
        observed = _load_project_coordination_authorization_unlocked(_state=_state, expire=False)
        if observed is None or observed != authorization:
            raise ElevatedBootstrapError("project_coordination_authorization_mismatch")
        try:
            _project_coordination_authorization_path(_state=_state).unlink()
        except OSError as exc:
            raise ElevatedBootstrapError("project_coordination_authorization_clear_failed") from exc
        _audit(
            {
                "event": "project_coordination_authorization_consumed",
                "target_digest": authorization.target_digest,
            },
            _state=_state,
        )


def _exact_match(left: str, right: str) -> bool:
    if type(left) is not str or type(right) is not str or len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def claim_pending_for_review(
    *,
    for_console: bool = False,
    expected_pending: PendingElevatedConsent | None = None,
    _state: Path | None = None,
) -> PendingElevatedConsent:
    """Atomically consume one pending request for a verified-console review.

    ``for_console`` refuses operations that need chat authority before any mutation.
    ``expected_pending`` binds a delayed console decision to the record that was displayed.  The
    comparison runs under the same state lock as the hard-link claim, so a request prepared after
    the displayed one expires cannot be consumed by the earlier prompt.
    """

    with _PendingStateLock(_state):
        pending = _load_pending_unlocked(_state=_state)
        if pending is None:
            raise ElevatedBootstrapError("pending_absent")
        if expected_pending is not None and pending != expected_pending:
            raise ElevatedBootstrapError("pending_tampered")
        if not operation_spec(pending.operation).implemented:
            raise ElevatedBootstrapError("operation_not_implemented")
        if for_console and pending.operation == "project_coordination_grant":
            raise ElevatedBootstrapError("project_coordination_grant_requires_chat_authority")
        source = pending_path(_state=_state)
        claim = review_path(_state=_state)
        try:
            os.link(source, claim)
        except FileExistsError as exc:
            raise ElevatedBootstrapError("review_in_progress") from exc
        except FileNotFoundError as exc:
            raise ElevatedBootstrapError("pending_absent") from exc
        except OSError as exc:
            raise ElevatedBootstrapError("pending_claim_failed") from exc
        try:
            source.unlink()
        except FileNotFoundError:
            # The hard link already made this caller the winner. Concurrent cancellation or
            # cleanup of the public name cannot revoke ownership of the private review marker.
            pass
        except OSError as exc:
            try:
                claim.unlink(missing_ok=True)
            except OSError:
                pass
            raise ElevatedBootstrapError("pending_claim_failed") from exc
        claimed = _load_pending_path(claim, _state=_state, expire=False)
        if claimed is None or claimed != pending:
            try:
                claim.unlink(missing_ok=True)
            except OSError:
                pass
            raise ElevatedBootstrapError("pending_tampered")
        if claimed.expires_at_unix <= int(time.time()):
            _complete_review_unlocked(claimed, outcome="expired", _state=_state)
            raise ElevatedBootstrapError("pending_expired")
        _audit(
            {
                "event": "review_claimed",
                "pending_id": pending.pending_id,
                "operation": pending.operation,
                "risk_class": pending.risk_class,
                "danger_digest": pending.danger_digest,
            },
            _state=_state,
        )
        return claimed


_FAILURE_REASON_CHARACTERS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")


def _validated_failure_reason(outcome: str, failure_reason: str | None) -> str | None:
    if failure_reason is None:
        return None
    if outcome != "failed":
        raise ElevatedBootstrapError("review_outcome_invalid")
    if (
        type(failure_reason) is not str
        or not 0 < len(failure_reason) <= 128
        or any(character not in _FAILURE_REASON_CHARACTERS for character in failure_reason)
    ):
        raise ElevatedBootstrapError("failure_reason_invalid")
    return failure_reason


def _complete_review_unlocked(
    pending: PendingElevatedConsent,
    *,
    outcome: str,
    failure_reason: str | None = None,
    _state: Path | None = None,
) -> None:
    """Consume the claimed request exactly once for approval, denial, cancellation, or expiry."""

    if type(pending) is not PendingElevatedConsent:
        raise TypeError("pending_review_invalid")
    if outcome not in {"approved", "cancelled", "denied", "expired", "failed"}:
        raise ElevatedBootstrapError("review_outcome_invalid")
    reason = _validated_failure_reason(outcome, failure_reason)
    claim = review_path(_state=_state)
    claimed = _load_pending_path(claim, _state=_state, expire=False)
    if claimed is None:
        raise ElevatedBootstrapError("pending_absent")
    if claimed != pending:
        raise ElevatedBootstrapError("pending_tampered")
    try:
        claim.unlink()
    except OSError as exc:
        raise ElevatedBootstrapError("pending_clear_failed") from exc
    event: dict[str, JsonValue] = {
        "event": "review_consumed",
        "pending_id": pending.pending_id,
        "operation": pending.operation,
        "outcome": outcome,
    }
    if reason is not None:
        event["failure_reason"] = reason
    _audit(event, _state=_state)


def complete_review(
    pending: PendingElevatedConsent,
    *,
    outcome: str,
    failure_reason: str | None = None,
    _state: Path | None = None,
) -> None:
    """Consume the claimed request exactly once for approval, denial, cancellation, or expiry."""

    with _PendingStateLock(_state):
        _complete_review_unlocked(
            pending, outcome=outcome, failure_reason=failure_reason, _state=_state
        )


def projection_for_status(
    pending: PendingElevatedConsent | None,
    *,
    _version: Literal["6", "7"] | None = None,
) -> dict[str, JsonValue] | None:
    """Versioned agent-safe projection with exact bounded recovery/authorization guidance."""

    if pending is None:
        return None
    version = _version
    if version is None:
        version = "7" if pending.coordination_binding is not None else "6"
    if version == "6" and pending.coordination_binding is not None:
        raise ElevatedBootstrapError("coordination_binding_requires_pending_v7")
    grant_preview = (
        None
        if pending.grant_binding is None
        else RepositoryPrivacyGrantPreviewModel.model_validate(
            cast(Mapping[str, JsonValue], pending.grant_binding["preview"])
        )
    )
    model_values: dict[str, object] = {
        "schema": f"finishup.consent.pending-agent/{version}",
        "operation": pending.operation,
        "risk_class": pending.risk_class,
        "pending_id": pending.pending_id,
        "danger_digest": pending.danger_digest,
        "danger_text": pending.danger_text,
        "expires_at_unix": pending.expires_at_unix,
        "target_digest": pending.target_digest,
        "repository_privacy_recipe": None if grant_preview is None else grant_preview.recipe,
        "repository_privacy_preview": grant_preview,
        "import_publication_preview": (
            None
            if pending.import_publication_preview is None
            else ImportPublicationPreviewModel.model_validate(
                dict(pending.import_publication_preview)
            )
        ),
        "review_command": ("finishup", "consent", "review"),
        "authorize_command": (
            ("finishup", "consent", "authorize")
            if operation_spec(pending.operation).agent_chat_authorize_allowed
            else None
        ),
    }
    if version == "7":
        model_values["coordination_binding"] = (
            None if pending.coordination_binding is None else dict(pending.coordination_binding)
        )
    elif pending.coordination_binding is not None:
        model_values["coordination_binding"] = dict(pending.coordination_binding)
    model = AgentSafePendingModel.model_validate(model_values)
    return cast(dict[str, JsonValue], model.model_dump(mode="json", by_alias=True))


def catalog_payload() -> dict[str, JsonValue]:
    """Agent-facing catalog of default-safe vs consent-required operations."""

    operations: list[JsonValue] = []
    for spec in CONSENT_OPERATIONS:
        hint = (
            "finishup import --request <bounded-json>"
            if spec.operation == "import_publication"
            else f"finishup consent prepare {spec.operation}"
        )
        if spec.requires_target_digest_arg:
            hint += " --target-digest <sha256:...>"
        if spec.requires_grant_binding:
            hint += " --recipe <expanded_review|assisted_review|private|metadata_only>"
        if spec.operation == "project_coordination_grant":
            hint += (
                " --project-id <prj_...> --membership-generation <positive-integer>"
                " --audit-record-id <evt_...>"
            )
        # Only the profile identity is caller input; the purpose, its digests, and the repository
        # privacy commitment are derived by prepare. Naming them here sent agents hunting for
        # internals they cannot know.
        if spec.requires_provider_binding:
            hint += (
                " --provider-id <id> --model-id <id> --endpoint-profile-id <id>"
                " --endpoint-profile-version <version>"
            )
        operations.append(
            {
                "operation": spec.operation,
                "risk_class": spec.risk_class,
                "summary": spec.summary,
                "implemented": spec.implemented,
                "requires_provider_binding": spec.requires_provider_binding,
                "requires_grant_binding": spec.requires_grant_binding,
                "requires_target_digest_arg": spec.requires_target_digest_arg,
                "agent_chat_authorize_allowed": spec.agent_chat_authorize_allowed,
                "prepare_hint": hint,
            }
        )
    model = ConsentCatalogModel.model_validate(
        {
            "schema": "yoetz.consent.catalog/7",
            "default_safe": [
                "mcp.start",
                "mcp.publish_work",
                "mcp.check",
                "mcp.respond",
                "mcp.status",
                "mcp.receipt",
                "privacy.tighten",
            ],
            "rules": {
                "forbidden_secret_channels": [
                    channel for channel in _FORBIDDEN if channel != "stdin"
                ],
                "no_standing_yolo": True,
                "path_safety_not_waivable_by_consent": True,
                "independent_user_presence_required_for_agent_chat": False,
                "trusted_console_is_not_authority": True,
                "one_pending_at_a_time": True,
                "approval_arguments_forbidden": True,
                "agent_selected_initialization_secret_forbidden": True,
                "authorized_one_shot_stdin_permitted": True,
                "agent_attested_current_chat_instruction_permitted": True,
                "agent_attestation_is_independent_proof": False,
                "compromised_agent_can_forge_attestation": True,
                "explicit_current_user_outcome_controls_supported_choice": True,
                "recommendations_are_advisory": True,
                "technical_authority_and_safety_boundaries_remain_enforced": True,
            },
            "operations": operations,
        }
    )
    return cast(dict[str, JsonValue], model.model_dump(mode="json", by_alias=True))


def status_payload(*, _state: Path | None = None) -> dict[str, JsonValue]:
    model = ConsentStatusModel.model_validate(
        {
            "schema": "yoetz.elevated-bootstrap.status/7",
            "pending": projection_for_status(load_pending(_state=_state), _version="7"),
            "consent_catalog": catalog_payload(),
        }
    )
    return cast(dict[str, JsonValue], model.model_dump(mode="json", by_alias=True))


def _write_pending(pending: PendingElevatedConsent, *, _state: Path | None) -> None:
    path = pending_path(_state=_state)
    ensure_owner_only_dir(path.parent)
    payload = canonical_encode(pending.as_json())
    tmp = path.with_suffix(".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def _audit(event: Mapping[str, JsonValue], *, _state: Path | None) -> None:
    path = audit_path(_state=_state)
    ensure_owner_only_dir(path.parent)
    line = canonical_encode({**dict(event), "at_unix": int(time.time())}) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)
