"""Stable process exits for public Yoetz outcomes."""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, Literal

from yoetz.protocol.errors import PublicErrorCode

__all__ = [
    "CEREMONY_REFUSAL_MESSAGES",
    "CONFIG_CONSTRAINT_REASONS",
    "INSTANCE_PUBLIC_CODES",
    "LIFECYCLE_PUBLIC_CODES",
    "LOCAL_REASONS",
    "PUBLIC_EXIT_CODES",
    "REMEDIATION_MESSAGES",
    "VAULT_RESULT_REASON_PREFIX",
    "ceremony_refusal_message",
    "exit_code_for",
    "lifecycle_public_code",
    "remediation_message",
]

PUBLIC_EXIT_CODES: Final = MappingProxyType(
    {
        PublicErrorCode.INVALID_REQUEST: 2,
        PublicErrorCode.PROTOCOL_VERSION_UNSUPPORTED: 20,
        PublicErrorCode.SESSION_NOT_FOUND: 10,
        PublicErrorCode.SESSION_CONFLICT: 10,
        PublicErrorCode.IDEMPOTENCY_CONFLICT: 10,
        PublicErrorCode.REQUEST_IDENTITY_CONFLICT: 10,
        PublicErrorCode.OPERATION_PENDING: 11,
        PublicErrorCode.FRONTIER_CONFLICT: 10,
        PublicErrorCode.EVENT_INVALID: 2,
        PublicErrorCode.LIMIT_EXCEEDED: 2,
        PublicErrorCode.BUNDLE_BUSY: 20,
        PublicErrorCode.STORAGE_UNSAFE: 20,
        PublicErrorCode.STORAGE_CORRUPT: 40,
        PublicErrorCode.MIGRATION_REQUIRED: 20,
        PublicErrorCode.SERVICE_UNAVAILABLE: 20,
        PublicErrorCode.VAULT_LOCKED: 20,
        PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED: 20,
        PublicErrorCode.PROVIDER_UNAVAILABLE: 30,
        PublicErrorCode.PROVIDER_REFUSED: 30,
        PublicErrorCode.PROVIDER_TIMEOUT: 30,
        PublicErrorCode.SEMANTIC_RESULT_INVALID: 30,
        PublicErrorCode.CANCELLED: 130,
        PublicErrorCode.INTERNAL_ERROR: 70,
    }
)

if set(PUBLIC_EXIT_CODES) != set(PublicErrorCode):
    raise RuntimeError("public_exit_codes_not_exhaustive")


def exit_code_for(outcome: PublicErrorCode | Literal["success", "cancelled"]) -> int:
    """Return the approved shell exit for an exact public outcome."""

    if outcome == "success":
        return 0
    if outcome == "cancelled":
        return 130
    if type(outcome) is not PublicErrorCode:
        raise TypeError("public_outcome_invalid")
    return PUBLIC_EXIT_CODES[outcome]


# Each closed lifecycle reason names a true operating condition. Collapsing them into
# internal_error told an operator the service had died when it was alive and holding its
# singleton, and sent the whole incident down the wrong diagnostic path (#237).
# ``BUNDLE_BUSY`` is the only member of the frozen public enum whose meaning is "a resource is
# already held by another owner"; it exits 20, like every other entry here.
# ``invalid_transition`` is deliberately absent: it is a genuine internal defect and stays
# INTERNAL_ERROR / 70.
LIFECYCLE_PUBLIC_CODES: Final = MappingProxyType(
    {
        "service_already_running": PublicErrorCode.BUNDLE_BUSY,
        "service_draining": PublicErrorCode.SERVICE_UNAVAILABLE,
        "vault_locked": PublicErrorCode.VAULT_LOCKED,
        "session_monitor_unavailable": PublicErrorCode.SERVICE_UNAVAILABLE,
        "human_authorization_required": PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED,
        "human_authorization_stale": PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED,
    }
)


def lifecycle_public_code(reason: str) -> PublicErrorCode | None:
    """Return the public outcome for a bounded lifecycle reason, or None when unmapped."""

    return LIFECYCLE_PUBLIC_CODES.get(reason)


# Instance-identity and isolation-root refusals (issue #604). A usage-shaped refusal (the operator
# named a root that cannot be created or disposed) exits 2; a runtime whose identity, pin, or root
# cannot be trusted exits 20 as an unsafe-storage condition; an owned service still holding the
# root's singleton is a busy resource, like ``service_already_running``.
INSTANCE_PUBLIC_CODES: Final = MappingProxyType(
    {
        "instance_absent": PublicErrorCode.INVALID_REQUEST,
        "instance_exists": PublicErrorCode.INVALID_REQUEST,
        "instance_expiry_invalid": PublicErrorCode.INVALID_REQUEST,
        "instance_not_disposable": PublicErrorCode.INVALID_REQUEST,
        "instance_root_invalid": PublicErrorCode.INVALID_REQUEST,
        "instance_root_too_long": PublicErrorCode.INVALID_REQUEST,
        "instance_expired": PublicErrorCode.SERVICE_UNAVAILABLE,
        "instance_identity_invalid": PublicErrorCode.STORAGE_UNSAFE,
        "instance_lifecycle_requires_isolated_root": PublicErrorCode.STORAGE_UNSAFE,
        "installation_identity_mismatch": PublicErrorCode.STORAGE_UNSAFE,
        "isolation_root_conflict": PublicErrorCode.STORAGE_UNSAFE,
        "runtime_pin_conflict": PublicErrorCode.STORAGE_UNSAFE,
        "runtime_pin_invalid": PublicErrorCode.STORAGE_UNSAFE,
        "runtime_pin_unwritable": PublicErrorCode.STORAGE_UNSAFE,
        "instance_service_running": PublicErrorCode.BUNDLE_BUSY,
    }
)


# A confidential ceremony the service answered and *declined* is not an unavailable service.
# Reporting every refusal as service_unavailable sent operators to restart a healthy daemon and
# hid the one fact that told them what to do next.
CEREMONY_REFUSAL_MESSAGES: Final = MappingProxyType(
    {
        "pending_unavailable": (
            "pending_unavailable: that pending decision no longer exists or has expired; "
            "run the check again to get a current one"
        ),
        "pending_not_actionable": (
            "pending_not_actionable: that pending decision cannot be decided as prepared, "
            "usually because the policy changed after it was created; run the check again"
        ),
        "ceremony_unsupported": (
            "ceremony_unsupported: this installation cannot run that confidential ceremony"
        ),
        "kind_forbidden": (
            "kind_forbidden: that ceremony is not permitted for this target in the current "
            "vault mode"
        ),
        "ceremony_busy": (
            "ceremony_busy: another confirmation is already open on this computer, so this one "
            "did not start. Finish it where it was started, and cancel any system dialog you did "
            "not start yourself; if nothing is on screen, 'yoetz service restart' ends it. Then "
            "run the command again"
        ),
        "reauthentication_rate_limited": (
            "reauthentication_rate_limited: recent confirmations did not succeed, so Yoetz waits "
            "before asking again; wait up to five minutes, then run the command again"
        ),
        "state_forbidden": (
            "state_forbidden: the vault must be unlocked before this ceremony; "
            "run 'yoetz service unlock', or 'yoetz service recovery status' if ordinary "
            "unlock authority may be lost"
        ),
        # Covers both a malformed paste and a provider that refused the key. Either way nothing
        # durable should look "configured" when the credential cannot be used.
        "secret_rejected": (
            "secret_rejected: that credential was not accepted, so nothing was saved. "
            "Check the key is complete, current, and belongs to the configured provider, "
            "then run 'yoetz provider credential set' again"
        ),
    }
)


def ceremony_refusal_message(reason: str) -> str | None:
    """Return the operator-facing line for a structural ceremony refusal, or None."""

    return CEREMONY_REFUSAL_MESSAGES.get(reason)


# Bounded elevated-bootstrap and human-ceremony tokens are stable contract, but a bare token on
# stderr tells an operator nothing about what to do next. These are the remediation halves; the
# caller keeps printing the token so existing machine-readable expectations stay intact.
REMEDIATION_MESSAGES: Final = MappingProxyType(
    {
        "support_resource_set_mismatch": (
            "the runtime support document describes a different resource set; in a source "
            "checkout run 'python scripts/sync_resource_ripple.py --write', which owns that "
            "regeneration order"
        ),
        "support_digest_mismatch": (
            "support/runtime-support.json is not self-consistent; in a source checkout run "
            "'python scripts/sync_resource_ripple.py --write' to rebuild its digests"
        ),
        "resource_digest_mismatch": (
            "an installed resource does not match the reviewed manifest; reinstall Yoetz from a "
            "verified artifact, or regenerate the resource manifest in a source checkout"
        ),
        "manifest_digest_mismatch": (
            "the installed resource manifest is not self-consistent; reinstall Yoetz from a "
            "verified artifact, or in a source checkout run "
            "'python scripts/sync_resource_ripple.py --write'"
        ),
        "resource_missing": (
            "a reviewed installed resource is absent; reinstall Yoetz from a verified artifact"
        ),
        "resource_counts_invalid": (
            "the compiled resource counts do not match the reviewed manifest; after an "
            "intentional inventory change, update REVIEWED_RESOURCE_COUNT and run "
            "'python scripts/sync_resource_ripple.py --write' in a source checkout"
        ),
        "trusted_console_required": (
            "this ceremony needs a foreground terminal Yoetz owns (stdin and stderr on the same "
            "tty, in the foreground process group). From an agent session run "
            "'yoetz consent prepare <operation>' then 'yoetz consent authorize' instead"
        ),
        "human_authority_unavailable": (
            "no verified foreground console was found for this review; run "
            "'yoetz consent review' directly on a local terminal"
        ),
        "chat_user_attestation_invalid": (
            "the relayed attestation was not accepted; --client-kind must name an allowlisted "
            "first-party client (currently 'codex')"
        ),
        "chat_user_target_mismatch": (
            "the supplied pending id or digests do not match the pending decision; the pending "
            "record is stale, or prepare and authorize ran from different working directories. "
            "Run 'yoetz consent prepare' again and pass its exact digests"
        ),
        "chat_user_warning_required": (
            "a credential-bearing approve requires --warning-acknowledged after showing the "
            "danger text to the person instructing you"
        ),
        "chat_user_reauthentication_unavailable": (
            "this installation has no keyring auto-unlock secret, so this action requires "
            "reauthentication on a local terminal; use 'yoetz --privacy' for repository "
            "privacy, 'yoetz provider credential set' for a provider credential, or "
            "'yoetz service rotate-passphrase' for passphrase rotation"
        ),
        "repository_privacy_scope_unavailable": (
            "this repository is not bound to privacy authority yet; run 'yoetz --privacy' "
            "(or prepare and authorize 'repository_privacy_grant') with the service running"
        ),
        "provider_credential_required": (
            "this operation stores a provider credential; pipe exactly one into "
            "'yoetz consent authorize --provider-credential-stdin'"
        ),
        "provider_credential_invalid": (
            "the piped credential must be 1..8192 bytes with no NUL, carriage return, or newline"
        ),
        "ceremony_service_unavailable": (
            "the selected service is unavailable; run 'yoetz service restart', then inspect "
            "'yoetz consent status' and retry the same pending decision if it is still valid. "
            "An approval already claimed before service loss stays consumed"
        ),
        "provider_binding_required": (
            "this review recipe needs a configured provider; run 'yoetz --set' "
            "before preparing the repository grant again. Local-only setup needs no provider"
        ),
        "provider_not_configured": (
            "no provider and model are configured for this installation; run 'yoetz --set' first"
        ),
        "unsafe_root": (
            "the workspace or Git metadata has a symlinked, foreign-owned, writable, or otherwise "
            "unsafe ancestor; pass the fully resolved path to a repository owned by the current user"
        ),
        "git_config_limit_exceeded": (
            "the repository's .git/config exceeds the bounded 1 MiB safety scan; remove stale local "
            "branch configuration or use a fresh clone"
        ),
        "git_version_unsupported": (
            "the system Git (the first 'git' in /bin or /usr/bin) is older than 2.25, the oldest "
            "Git Yoetz supports; install Git 2.25 or later there, then retry"
        ),
        "pending_expired": (
            "that pending decision expired before it was authorized; run "
            "'yoetz consent prepare <operation>' again"
        ),
        "pending_already_active": (
            "another pending decision is already active; authorize or deny it with "
            "'yoetz consent authorize', or wait for it to expire"
        ),
        "service_already_running": (
            "another local service process already holds the singleton lock, so a second one "
            "cannot start. Inspect it with 'yoetz service status'; if it stays unresponsive, "
            "stop it with 'yoetz service stop' or end the holding process, then start again"
        ),
        "service_draining": (
            "the local service is shutting down; wait for it to exit, then start it again"
        ),
        "storage_unsafe": (
            "the local Yoetz observation store has an unsafe file or path shape; repair its "
            "owner-only files, permissions, or symlinks and retry"
        ),
        "storage_unavailable": (
            "the local Yoetz observation store could not be opened or locked from this process; "
            "make the owner-only state directory accessible and writable from the supported host "
            "surface, then retry"
        ),
        "result_invalid": (
            "the operation produced a result the consent schema does not admit, so the "
            "approval was recorded as failed and nothing was approved; run "
            "'yoetz consent prepare <operation>' again, and report a defect if this recurs"
        ),
        # Canonical config-loading tokens surfaced by provider lifecycle commands (#520). Each
        # names the failing condition without echoing file content or private paths.
        "config_toml_invalid": (
            "the selected Yoetz config file is not valid TOML; fix the syntax error and retry"
        ),
        "config_value_invalid": (
            "a value in the selected Yoetz config file (or a YOETZ_ override) is outside the "
            "reviewed configuration model; correct it and retry"
        ),
        "unknown_config_key": (
            "the selected Yoetz config file names a key the reviewed configuration model does "
            "not admit; remove or correct that key and retry"
        ),
        "config_file_unreadable": (
            "the selected Yoetz config file exists but could not be read; check its permissions "
            "and retry"
        ),
        "config_file_too_large": (
            "the selected Yoetz config file exceeds the bounded 64 KiB limit; remove unrelated "
            "content and retry"
        ),
        "config_schema_unsupported": (
            "the selected Yoetz config file declares a schema_version this installation does "
            'not support; set schema_version = "1" or upgrade Yoetz'
        ),
        "config_preimage_mismatch": (
            "the selected Yoetz config changed while the Codex authentication operation was in "
            "progress; review the current file, then retry the same setup or disconnect command"
        ),
        "durability_unsupported": (
            "the selected storage durability mode is unsupported; choose the documented durable "
            "SQLite mode in config.toml and retry"
        ),
        "secret_in_config": (
            "the selected Yoetz config file contains a secret-named key; config.toml is "
            "nonsecret — provision credentials with 'yoetz provider credential set' instead"
        ),
        "secret_env_forbidden": (
            "a secret-named YOETZ_ environment variable is set; Yoetz never reads secrets from "
            "the environment — unset it and provision credentials with "
            "'yoetz provider credential set'"
        ),
        "unknown_config_env_var": (
            "an unrecognized YOETZ_-prefixed environment variable is set; unset it or use a "
            "documented configuration variable"
        ),
        "repository_privacy_grant_unconfirmed": (
            "the grant decision was submitted but its outcome could not be confirmed over the "
            "confidential channel, so it may already be effective; check 'yoetz provider status' "
            "for the repository grant state before preparing a new consent — do not assume it "
            "failed"
        ),
        "workspace_unresolvable": (
            "the --workspace locator is empty, missing, symlinked, foreign-owned, or otherwise "
            "unsafe; pass the resolved path of a directory owned by the current user (host hooks "
            "render it from CLAUDE_PROJECT_DIR or CURSOR_PROJECT_DIR, so check that variable "
            "when a hook reports this)"
        ),
        # Instance identity and runtime pin (issue #604).
        "instance_identity_invalid": (
            "the instance-identity marker in this root's state directory is malformed, "
            "foreign-owned, or not owner-only; dispose the instance with "
            "'yoetz instance dispose --root <root>' and create it again"
        ),
        "instance_expired": (
            "this disposable instance is past its recorded expiry and will not serve; dispose it "
            "with 'yoetz instance dispose --root <root>' and create a fresh one"
        ),
        "instance_lifecycle_requires_isolated_root": (
            "a persistent or disposable instance marker was found in ambient state; a labeled "
            "instance only runs under its own YOETZ_ISOLATED_ROOT or runtime pin"
        ),
        "installation_identity_mismatch": (
            "the runtime pin, the instance-identity marker, and the service generation record do "
            "not name one installation; the runtime was re-pointed or the root was replaced. "
            "Dispose and recreate the instance, or remove the stale pin from the runtime"
        ),
        "isolation_root_conflict": (
            "YOETZ_ISOLATED_ROOT names a different root than this runtime's pin; unset the "
            "variable to use the pinned root, or run the runtime that belongs to that root"
        ),
        "runtime_pin_invalid": (
            "this runtime's yoetz-instance-pin.json is unreadable, foreign-owned, writable by "
            "others, or malformed; remove it or recreate the instance with --bind-runtime"
        ),
        "runtime_pin_conflict": (
            "this runtime is already pinned to another root; dispose that instance from this "
            "runtime or provision a separate runtime for the new root"
        ),
        "runtime_pin_unwritable": (
            "this runtime's environment directory cannot be written by the current user (it was "
            "installed by another account, or its disk is read-only or full), so the runtime was "
            "not pinned and no instance was kept; install Yoetz as the account that will run it, "
            "or fix that directory, then run the same command again"
        ),
        "path_on_network_filesystem": (
            "the Yoetz state directory is on a network or cross-machine filesystem (NFS, SMB, "
            "9p, drvfs, virtiofs, sshfs, ...), where SQLite locking is unsafe; keep state on a "
            "local disk. Inside WSL, that means the Linux filesystem (your WSL home), never a "
            "Windows drive under /mnt/<letter>; unset YOETZ_ISOLATED_ROOT or point it at a "
            "local path, then retry"
        ),
        "instance_root_invalid": (
            "the instance root must be an absolute path whose parent exists, owned by the "
            "current user, outside shared temp, repositories, sync folders, and the home root, "
            "and either absent or an empty directory"
        ),
        "instance_root_too_long": (
            "the instance root is too long for the Unix control sockets that bind beneath it; "
            "choose a shorter path such as ~/.yz-<tag>/state"
        ),
        "instance_expiry_invalid": (
            "--expires-in/--expires-at must name a future time within 30 days and applies only "
            "to a disposable instance"
        ),
        "instance_exists": (
            "that root already carries an instance-identity marker; dispose it first or choose "
            "another root"
        ),
        "instance_not_disposable": (
            "that root carries no persistent or disposable instance marker, so this command will "
            "not remove it; the everyday (permanent) install and unlabeled ADR-026 roots are "
            "never disposed by 'yoetz instance dispose'"
        ),
        "instance_service_running": (
            "a service still holds that root's singleton and did not release it within the "
            "bounded stop window; stop it with that runtime's 'yoetz service stop', then retry"
        ),
    }
)


# Profile and field constraints the configuration model refuses as a family: one remediation
# answers all of them, and the token names which constraint was violated. Held as a named
# constant rather than inline so the coverage ratchet below can range over it.
CONFIG_CONSTRAINT_REASONS: Final[frozenset[str]] = frozenset(
    {
        "external_profile_forbids_local_model",
        "external_runtime_forbids_local_model",
        "external_runtime_forbids_provider",
        "external_runtime_required_for_semantic",
        "https_origin_invalid",
        "local_model_locator_forbidden",
        "max_findings_out_of_range",
        "owner_declared_endpoint_forbidden",
        "owner_declared_endpoint_required",
        "payload_logging_forbidden",
        "privacy_bootstrap_unsafe",
        "provider_required_for_semantic",
        "release_probe_not_a_user_profile",
        "strict_local_forbids_provider",
        "test_fake_forbids_local_model",
        "test_fake_forbids_provider",
    }
)

# The one generated local family. Every ``vault_result_<condition>`` names an exact service
# condition, and they share one remediation and one recovery directive.
VAULT_RESULT_REASON_PREFIX: Final = "vault_result_"


def remediation_message(reason: str) -> str | None:
    """Return the next-step half of an operator-facing line for a bounded token, or None."""

    message = REMEDIATION_MESSAGES.get(reason)
    if message is None and reason in CONFIG_CONSTRAINT_REASONS:
        return (
            "the selected Yoetz configuration violates the named profile or field constraint; "
            "correct that profile/section in config.toml, then retry"
        )
    if message is None and reason.startswith(VAULT_RESULT_REASON_PREFIX):
        # One remediation for the whole family: the token names the exact service condition,
        # and the consent approval was consumed as failed, never recorded as approved.
        return (
            "the vault ceremony finished without reaching its exact successful state, so the "
            "approval was recorded as failed; inspect 'yoetz service status', resolve the "
            "named condition, then run 'yoetz consent prepare <operation>' and authorize again"
        )
    return message


# Every bounded reason this module can put in front of an operator. ``REMEDIATION_MESSAGES`` and
# ``CEREMONY_REFUSAL_MESSAGES`` hold the per-reason remedy; the public-code tables hold reasons
# that reach an operator through an exit code with no remedy of their own. The ratchet below
# ranges over the union, so widening any of them is what trips the gate.
LOCAL_REASONS: Final[frozenset[str]] = frozenset(
    set(REMEDIATION_MESSAGES)
    | set(CEREMONY_REFUSAL_MESSAGES)
    | set(LIFECYCLE_PUBLIC_CODES)
    | set(INSTANCE_PUBLIC_CODES)
    | CONFIG_CONSTRAINT_REASONS
)


def _check_local_reason_coverage() -> None:
    """Fail at import when a local CLI reason has nothing to tell an agent to do (issue #741).

    The mirror of the protocol-side ratchet in ``yoetz.protocol.recovery``, applied to the second,
    disjoint reason vocabulary this module owns. Before ADR-030 reached the CLI, forty of these
    reasons carried a remediation sentence and no typed directive, so the same condition that got
    a directive over MCP got none in a shell. A reason is answered when it resolves through
    ``continuation_for_local_reason``, or when it is also a protocol reason code whose disposition
    was already recorded on that side -- ``service_draining`` is the one member in that state, and
    its directive is owned by a later sub-issue of #739.
    """

    from yoetz.protocol.recovery import local_reason_has_disposition

    for reason in LOCAL_REASONS:
        if not local_reason_has_disposition(reason):
            raise RuntimeError("local_reason_without_recovery_disposition")
    if not local_reason_has_disposition(f"{VAULT_RESULT_REASON_PREFIX}keyring_unavailable"):
        raise RuntimeError("local_reason_without_recovery_disposition")


_check_local_reason_coverage()
