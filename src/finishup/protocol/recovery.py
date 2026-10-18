"""Frozen recovery directives for typed public-error continuations.

Every value in this module is repository-authored text keyed by a typed token. Nothing here is
derived from a caller, a payload, a path, a provider, or model output, so a directive can be
rendered on any agent-facing surface without widening the egress boundary that
``CONTRIBUTING.md`` locks: "Nothing user-controlled ... appears in ... errors, or MCP text
summaries."

The point of the indirection is that the *token* travels and the *text* does not. A renderer
reconstructs the directive locally from the token, so the wire shape stays exactly as narrow as it
was before this module existed, and no ``safe_details`` key or ``public-error`` schema version was
added to carry prose (issue #739).

Directives restate what ``guidance/workflow.md`` already rules, in the one place an agent is
guaranteed to look: the error it just hit. When a rule changes, both move together — the
import-time gate below holds the vocabulary closed, and the guidance anchors are checked against
the registered resource set by ``finishup.mcp.resources``.

A directive is an instruction, never a prediction. "Repeat the read with a new request_id" is
admissible because the error proves the read did not commit. "This will fix it" is not: the error
cannot substantiate an outcome, and coverage-bounded language forbids claiming one.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from finishup.protocol.errors import (
    ADMITTED_CLAIM_REVISION_INVARIANTS,
    ADMITTED_CONTINUATION_TOKENS,
    PROTOCOL_REASON_CODES,
    REASON_CODE_CONTINUATIONS,
)

__all__ = [
    "CLAIM_REVISION_CORRECTIONS",
    "CONTINUATION_TOKENS",
    "LOCAL_REASON_CONTINUATION_PREFIXES",
    "READ_ONLY_CHECK_MODES",
    "REASON_CODE_DIRECTIVE_EXEMPTIONS",
    "REASON_REMEDIES",
    "RECOVERY_DIRECTIVES",
    "RecoveryDirective",
    "TimeoutOperationKind",
    "WRITE_OPERATIONS",
    "continuation_for_local_reason",
    "continuation_for_reason",
    "continuation_for_semantic_outcome",
    "correction_for_invariant",
    "covered_reason_codes",
    "directive_for",
    "local_reason_has_disposition",
    "timeout_operation_kind",
]

# The three ways a local request can time out, which is the one distinction a reason code alone
# cannot carry (issue #669): a read proves nothing committed, a write leaves the outcome unknown but
# recoverable through the operation view, and a ``start`` leaves it unknown *without* the session
# and writer ids that view requires.
type TimeoutOperationKind = Literal["read", "write", "start"]

# The workflow operations that append to the ledger. Shared by the MCP bridge and the CLI so both
# classify a timed-out operation the same way; ``status`` is the one read.
WRITE_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"start", "publish_work", "check", "respond", "receipt"}
)
# The ``check`` modes that record nothing (ADR-047: ``inspect``). A check in one of them is a read
# like ``status``: the daemon, the MCP bridge and the CLI all classify it so, and a lost answer is
# repeated under a new request_id, never replayed as a write that may have committed.
READ_ONLY_CHECK_MODES: Final[frozenset[str]] = frozenset({"inspect"})

# Bounds chosen against the original 512-byte ASCII ceiling in ``finishup.mcp.summaries`` (4,096 since
# ADR-043): an error identity clause plus a reason/location clause plus a directive plus a guidance
# pointer has to fit, with the identity never the part that gets dropped. They stay as chosen so a
# tight bound still holds a whole directive.
_MAX_DIRECTIVE_BYTES: Final = 232
_MAX_NUDGE_BYTES: Final = 128
_MAX_REMEDY_BYTES: Final = 420
# A directive is new output, so it names the current scheme only; a legacy ``yoetz://`` URI is
# accepted where a caller reads guidance, never emitted here (ADR-048).
_GUIDANCE_URI_PATTERN: Final = re.compile(
    r"^finishup://guidance/[a-z][a-z0-9-]*\.md(?:#[a-z0-9][a-z0-9-]*)?$", re.ASCII
)
_TOKEN_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)


@dataclass(frozen=True, slots=True)
class RecoveryDirective:
    """One frozen continuation: what happened, what to do next, and where the rule is written."""

    token: str
    directive: str
    guidance_uri: str | None = None
    nudge: str | None = None


_WORKFLOW_ERRORS: Final = "finishup://guidance/workflow.md#errors-and-continuations"
_WORKFLOW_RECOVERY: Final = "finishup://guidance/workflow.md#recovery-decision-table-02"
_TEMPLATES_SETUP: Final = "finishup://guidance/request-templates.md#setup-and-consent"
_PUBLICATION_SETS: Final = "finishup://guidance/publication-policy.md#set-valued-reference-lists"
_SEMANTIC_COVERAGE: Final = (
    "finishup://guidance/coverage-and-receipts.md#check-mode-and-ai-powered-review-coverage"
)
_PUBLICATION_RECOVERY: Final = (
    "finishup://guidance/publication-policy.md#operation-specific-recovery-and-templates"
)
_PUBLICATION_SERVICE_FILLED: Final = (
    "finishup://guidance/publication-policy.md#service-filled-values"
)

_DIRECTIVES: Final = (
    RecoveryDirective(
        token="start_busy_same_identity",
        directive=(
            "The start reservation is retained and its lease was released. Replay the exact "
            "start body and request_id once; no session or writer IDs are needed. If contention "
            "persists, retain the request and report the unresolved start."
        ),
        guidance_uri=_WORKFLOW_RECOVERY,
        nudge="Do not create a replacement task to escape contention.",
    ),
    RecoveryDirective(
        token="start_pending_same_identity",
        directive=(
            "Start still has a live lease. Wait up to 60 seconds, then replay the exact start "
            "body and request_id once. Do not invent session or writer IDs. If still pending, "
            "retain the request and report the unresolved start."
        ),
        guidance_uri=_WORKFLOW_RECOVERY,
        nudge="A pending start does not prove failure.",
    ),
    # --- timeout family (issue #669) -------------------------------------------------------
    RecoveryDirective(
        token="read_timeout_new_identity",
        directive=(
            "This read timed out and requested no write, so nothing committed. Repeat the same "
            "read intent with a NEW request_id, preserving view, filter, cursor, and limit. "
            "Reusing a timed-out read identity is rejected."
        ),
        guidance_uri=_WORKFLOW_RECOVERY,
        nudge="An unreadable response is not proof a record is absent.",
    ),
    RecoveryDirective(
        token="write_timeout_same_identity",
        directive=(
            "This write timed out and MAY already have committed. Read status view=operation with "
            "filter.operation_request_id set to this exact request_id, then replay the same body "
            "once only when state=absent."
        ),
        guidance_uri=_WORKFLOW_RECOVERY,
        nudge="Do not mint a fresh request_id, task, or sibling to escape an ambiguous write.",
    ),
    RecoveryDirective(
        token="start_timeout_same_identity",
        directive=(
            "This start timed out and MAY already have committed. A lost start returns no session "
            "or writer id, so do not query operation status: replay the exact same start body once "
            "with this same request_id."
        ),
        guidance_uri=_WORKFLOW_RECOVERY,
        nudge="The start idempotency path returns the stored result or a typed boundary.",
    ),
    RecoveryDirective(
        token="service_replacement_exhausted",
        directive=(
            "An incompatible local service holder could not be superseded within the automatic "
            "budget. Run the exact authorized restart for this instance, then replay this request "
            "under its original identity rules."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
        nudge="Never run service lifecycle commands an error did not name.",
    ),
    # --- setup and consent (issues #512, #740) ---------------------------------------------
    RecoveryDirective(
        token="vault_initialization_required",
        directive=(
            "The vault is uninitialized: a continuation, not a terminal error. Run the carried "
            "prepare command, show its danger text to the user, and wait for their exact "
            "decision. Replay this request once after setup reports ready."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="FinishUP stores the secret locally; never request or transmit recovery material.",
    ),
    RecoveryDirective(
        token="consent_ceremony_required",
        directive=(
            "This operation needs a human decision that has not been made. Follow the carried "
            "prepare and review commands, then replay this exact request once after the ceremony "
            "reports a terminal decision."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="Denial and expiry are answers; do not re-prepare to obtain a different one.",
    ),
    # --- authoring repairs (issues #266, #579) ----------------------------------------------
    RecoveryDirective(
        token="field_ownership_repair",
        directive=(
            "A field was sent under an event family that does not own it. Move the field to its "
            "owning family rather than deleting it; deleting it silently discards the record it "
            "carried."
        ),
        guidance_uri=_PUBLICATION_RECOVERY,
    ),
    RecoveryDirective(
        token="sorted_set_required",
        directive=(
            "A set-valued reference list must be ASCII-sorted and duplicate-free on the wire. "
            "Sort the named list and resubmit; the order is part of the canonical form, not a "
            "presentation choice."
        ),
        guidance_uri=_PUBLICATION_SETS,
    ),
    RecoveryDirective(
        token="input_correction_new_identity",
        directive=(
            "FinishUP rejected this request body before any write, so retryable=false covers only "
            "this exact body. Correct the named field and submit the corrected body once under a "
            "NEW request_id; do not resend it unchanged."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
        nudge="A rejected body is not an ambiguous write; do not mint a task or sibling to escape it.",
    ),
    RecoveryDirective(
        token="recovery_check_then_correct",
        directive=(
            "This body was rejected before any write, but whether an earlier request under this "
            "request_id already committed could not be checked. Read status view=operation for it "
            "once the service answers, then correct under a NEW request_id."
        ),
        guidance_uri=_WORKFLOW_RECOVERY,
        nudge="Do not resubmit until the original request_id has a known outcome.",
    ),
    # --- ledger and session state (issues #308, #326) ---------------------------------------
    RecoveryDirective(
        token="frontier_refresh_required",
        directive=(
            "The expected frontier no longer matches the ledger, so this write was not applied. "
            "Read status for the current frontier, set expected_frontier from it, and retry "
            "idempotently with this same request_id."
        ),
        guidance_uri=_PUBLICATION_RECOVERY,
        nudge="A frontier conflict means the ledger moved, not that your content was wrong.",
    ),
    # tb4n5 (#1048): a batch that sent no frontier is not a conflict. Every write already returned
    # one, and the first plan uses the frontier start returned, so no status read is needed.
    RecoveryDirective(
        token="frontier_held_required",
        directive=(
            "Null expected_frontier: nothing written. Omit it (guarded at admission) or send the "
            "one you hold: start returned it for a first plan, else your last accepted write's "
            "result_frontier. Retry with this same request_id."
        ),
        guidance_uri=_PUBLICATION_RECOVERY,
        nudge="Read status for a frontier only when you hold none.",
    ),
    # Issue #1084 (ADR-050 decision 2): an id-less publish never resumes an earlier call by its
    # content. An identical id-less resend of the writer's previous, possibly committed call is
    # refused so the caller decides what it is. A result the caller saw succeed is recorded, so a
    # deliberate repeat changes the body or sends a new id; only an unseen outcome is retried.
    RecoveryDirective(
        token="publish_identity_choice",
        directive=(
            "Nothing was sent: this body repeats your previous id-less publish_work. If you saw "
            "it succeed, it is recorded; to publish again, change the body or send a fresh "
            "request_id. Otherwise retry it: send replay_request_id as request_id."
        ),
        guidance_uri=_PUBLICATION_SERVICE_FILLED,
        nudge=(
            "A fresh request_id is req_ plus a new lowercase UUIDv4. An id-less resend is never "
            "a retry."
        ),
    ),
    RecoveryDirective(
        token="session_rebind_required",
        directive=(
            "This session is not usable for the request. Re-attach with an exact held session_id, "
            "or start with mode=create_or_attach using the canonical workspace and external ref "
            "pair. Inspect status before continuing."
        ),
        guidance_uri=_WORKFLOW_RECOVERY,
        nudge="A fresh conversation is not automatically a new task.",
    ),
    RecoveryDirective(
        token="operation_pending_inspect",
        directive=(
            "A prior operation under this identity is still pending. Read status view=operation "
            "once with the exact filter.operation_request_id, and replay only on an exact typed "
            "continuation whose approval has completed."
        ),
        guidance_uri=_WORKFLOW_RECOVERY,
        nudge="Retain and report a pending or quarantined boundary; do not claim completion.",
    ),
    # A check refused before admission has no operation to inspect: status reads it as absent
    # with an ``admission`` stage, so the exact replay is the whole recovery (issue #838).
    RecoveryDirective(
        token="check_admission_same_identity",
        directive=(
            "The check was not admitted, so nothing is recorded under this request_id. Wait "
            "retry_after_ms, then replay the exact check body and request_id. After three "
            "refusals, retain it and report the check as not admitted."
        ),
        guidance_uri=_WORKFLOW_RECOVERY,
        nudge="Do not mint a new request_id, task, or check mode to escape an admission barrier.",
    ),
    # --- local installation state (issues #220, #237) ---------------------------------------
    RecoveryDirective(
        token="service_holder_busy",
        directive=(
            "A local service is already running and holding this instance's singleton. It is "
            "alive, not failed. Query its status before any lifecycle action, and never match a "
            "process by path or name to stop it."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
    ),
    RecoveryDirective(
        token="resource_integrity_repair",
        directive=(
            "An installed resource does not match the reviewed manifest, so FinishUP refused to read "
            "it. Reinstall from a verified artifact; in a source checkout regenerate through the "
            "owning resource script."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
        nudge="Do not hand-edit a generated resource to clear this.",
    ),
    RecoveryDirective(
        token="storage_root_unsafe",
        directive=(
            "The workspace or its Git metadata has an unsafe ancestor: a symlink, a foreign owner, "
            "or a writable parent. Pass a fully resolved path to a repository owned by the current "
            "user."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
    ),
    # The 0.3 lineage/project reasons are explicit dispositions, never ratchet exemptions.
    RecoveryDirective(
        token="lineage_attach_review",
        directive="The child attach capability is unusable. Ask the authorized parent to inspect the delegation and its existing child before issuing a replacement handle. Do not create a second child to bypass a used or revoked handle.",
        guidance_uri=_WORKFLOW_ERRORS,
    ),
    RecoveryDirective(
        token="coordination_authority_review",
        directive="This route lacks authority for this action. Inspect the exact task or project grant and its source-workspace scope. Use the supported consent review only with explicit owner approval; do not widen authority or retry blindly.",
        guidance_uri=_WORKFLOW_ERRORS,
    ),
    RecoveryDirective(
        token="lineage_operation_recovery",
        directive="Keep the original request_id and body. Recover the operation using the route ids you already hold; if a start returned no ids, use its exact same-request recovery. Do not create a new task or identity to escape a pending write.",
        guidance_uri=_WORKFLOW_ERRORS,
    ),
    RecoveryDirective(
        token="lineage_successor_task",
        directive="This task's work is terminal: it cannot be resumed or delegate. Keep a held session for its status, checks, and receipts. For new work, start one successor with mode=create, a new external_ref, and a handoff naming the predecessor.",
        guidance_uri=_WORKFLOW_ERRORS,
        nudge="The predecessor keeps its history and receipts; never report them as completed work.",
    ),
    RecoveryDirective(
        token="lineage_terminal_review",
        directive="The task, project, or operation is terminal or quarantined. Stop this mutation and present the recorded state for maintainer review. Do not reopen, replace, or clear durable state to bypass the refusal.",
        guidance_uri=_WORKFLOW_ERRORS,
    ),
    RecoveryDirective(
        token="lineage_service_review",
        directive="The lineage or coordination service cannot serve this route. Retain the exact request identity, inspect bounded service diagnostics, and report the unavailable boundary. Run only a repair explicitly named for this instance.",
        guidance_uri=_WORKFLOW_ERRORS,
    ),
    RecoveryDirective(
        token="lineage_state_refresh",
        directive="Inspect current task lineage and project membership through an authorized route. Reconcile the named state conflict before another mutation, and recover any earlier write under its original request identity.",
        guidance_uri=_WORKFLOW_ERRORS,
    ),
    RecoveryDirective(
        token="cursor_project_preview_review",
        directive="Inspect the Cursor project MCP configuration with the supported preview command. Correct the reported route or command mismatch before applying the reviewed configuration; do not replace foreign configuration blindly.",
        guidance_uri=_WORKFLOW_ERRORS,
    ),
    RecoveryDirective(
        token="lineage_integrity_review",
        directive="A lineage value or stored result failed its contract. Inspect the current schema and bounded diagnostic for this operation. Correct caller-authored fields only; stop and report invalid stored state instead of rewriting it.",
        guidance_uri=_WORKFLOW_ERRORS,
    ),
    RecoveryDirective(
        # Issue #842: a superseded project generation can never be admitted again, so the
        # authority review above would send the caller after authority that cannot exist.
        token="coordination_superseded_recheck",
        directive=(
            "This detection's project generation was superseded and cannot be reauthorized. Run "
            "check to record it as history; if the overlap still applies, declare against the "
            "current detection named in coordination advice."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
        nudge="Do not request consent or a grant to revive the old generation.",
    ),
    RecoveryDirective(
        token="coordination_policy_review",
        directive="The source-workspace policy denies coordination. This is not a missing consent grant. Keep the denial in place and ask the policy owner to review the configured restriction; another grant or repeated request does not override it.",
        guidance_uri=_WORKFLOW_ERRORS,
    ),
    # --- local CLI reasons (issue #741) -----------------------------------------------------
    # These tokens are reached only through ``continuation_for_local_reason``: the reasons that
    # map to them are raised by CLI adapters and never become a public error envelope. They are
    # registered here, beside the protocol continuations, so one edit moves every surface and the
    # ratchet in ``finishup.cli.exits`` can require a disposition for every local reason too.
    RecoveryDirective(
        token="ceremony_refusal_terminal",
        directive=(
            "The service answered this confidential ceremony and declined it, so it is healthy "
            "and a restart changes nothing. Report the refusal with its exact token and ask the "
            "vault owner to review the policy that produced it."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="A refusal is an answer; re-running the ceremony does not obtain a different one.",
    ),
    RecoveryDirective(
        token="ceremony_in_progress",
        directive=(
            "Another confirmation is open on this computer, so nothing changed. Do not approve, "
            "cancel or restart anything yourself: report that a confirmation is already open and "
            "let the owner decide. Retry once only when the owner asks."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="A confirmation someone else opened is never yours to approve or end.",
    ),
    RecoveryDirective(
        token="ceremony_retry_after_wait",
        directive=(
            "Recent confirmations did not succeed, so the service waits before asking again; it "
            "is healthy and nothing changed. Wait up to five minutes, then retry once. Retrying "
            "sooner gets the same answer."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="Agents must not loop on this; report it and let the owner retry.",
    ),
    RecoveryDirective(
        token="vault_unlock_required",
        directive=(
            "The vault must be unlocked before this ceremony can run, and nothing was changed. "
            "Unlock it on a trusted local terminal, then replay this request once; when ordinary "
            "unlock authority may be lost, read recovery status first."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="FinishUP stores the secret locally; never request or transmit recovery material.",
    ),
    RecoveryDirective(
        token="pending_decision_refresh",
        directive=(
            "That pending decision no longer exists, has expired, or cannot be decided as "
            "prepared, so nothing was decided. Prepare a fresh decision from the same working "
            "directory, pass its exact digests, and decide that one."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="A stale pending id is never revived; absence and expiry are reported alike.",
    ),
    RecoveryDirective(
        token="pending_decision_in_flight",
        directive=(
            "Another pending decision is already active for this installation, so a second one "
            "was not prepared. Authorize or deny the existing decision, or wait for it to expire, "
            "before preparing another."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="Do not prepare a second decision to obtain a different answer.",
    ),
    RecoveryDirective(
        token="consent_relay_correction",
        directive=(
            "This relayed approval was refused before anything was stored. Correct the named "
            "relay condition, such as an allowlisted client kind or acknowledged danger text, and "
            "authorize once; otherwise run the ceremony on a local terminal."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="Show the danger text to the person instructing you before acknowledging it.",
    ),
    RecoveryDirective(
        token="provider_setup_required",
        directive=(
            "No usable provider credential is configured for this installation, so nothing was "
            "stored. Supply exactly one complete, current credential for the configured provider "
            "through the documented setup command, then run this again."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="FinishUP stores the credential locally; never echo, log, or transmit it.",
    ),
    # --- provider / AI-powered review outcomes (issue #742) --------------------------------
    # Each directive restates the coverage guidance for its outcome class: which outcomes were
    # already retried in the job, whether one more job is allowed, and that a required review is
    # reported as unmet rather than downgraded to local-only.
    RecoveryDirective(
        token="semantic_response_invalid",
        directive=(
            "The provider answered, but not with a usable review, and asking again will not "
            "change that. For optional review, run a local-only check and disclose the gap. For "
            "required review, report the requirement as unmet."
        ),
        guidance_uri=_SEMANTIC_COVERAGE,
        nudge="A classified invalid answer is not a finding and carries no provider text.",
    ),
    RecoveryDirective(
        token="semantic_response_truncated",
        directive=(
            "The provider answer was cut short or overlong, and the one in-job repair was spent "
            "or not admitted. Do not spend a second job on it. For optional review, run a "
            "local-only check; for required review, report it as unmet."
        ),
        guidance_uri=_SEMANTIC_COVERAGE,
        nudge="Disclose the recorded semantic_status and semantic_reason as a gap, not a finding.",
    ),
    RecoveryDirective(
        token="semantic_credential_rejected",
        directive=(
            "The provider rejected the bound credential, so this job neither retried nor switched "
            "endpoints. Ask the owner to run the documented provider credential setup, then run "
            "one new check under a NEW request_id."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="Do not echo, log, or transmit the credential, and do not resend this check.",
    ),
    RecoveryDirective(
        token="semantic_capacity_exceeded",
        directive=(
            "No usable review ran. For case_capacity_exceeded no provider attempt was made: narrow "
            "the claim or obligation scope. For provider_quota_exhausted, wait for quota. Then run "
            "one new check under a NEW request_id."
        ),
        guidance_uri=_SEMANTIC_COVERAGE,
        nudge="Do not resend the same case expecting a larger admitted bound.",
    ),
    RecoveryDirective(
        token="semantic_timeout",
        directive=(
            "The provider timed out and this job already spent its retry budget. For optional "
            "review, run at most one new check under a NEW request_id, then go local-only and "
            "disclose the gap. Report a required review as unmet."
        ),
        guidance_uri=_SEMANTIC_COVERAGE,
        nudge="A timeout is a coverage gap, not a diagnosis of the work under review.",
    ),
    RecoveryDirective(
        token="semantic_refused",
        directive=(
            "The provider refused the review. Do not resend this check. For optional review, run "
            "a local-only check and disclose the recorded semantic_status and semantic_reason. "
            "For required review, report the requirement as unmet."
        ),
        guidance_uri=_SEMANTIC_COVERAGE,
        nudge="A refusal is terminal inside the job; a fresh request is a fresh gamble.",
    ),
    RecoveryDirective(
        token="semantic_rate_limited",
        directive=(
            "The provider rate-limited this job after it spent its retry budget. Wait; for "
            "optional review, run at most one new check under a NEW request_id, then go "
            "local-only and disclose the gap. Report a required review as unmet."
        ),
        guidance_uri=_SEMANTIC_COVERAGE,
        nudge="The recorded reason names the retry outcome, not a diagnosis of the work.",
    ),
    RecoveryDirective(
        token="semantic_transport_retry",
        directive=(
            "The provider transport failed after this job spent its retry budget. For optional "
            "review, run at most one new check under a NEW request_id, then go local-only and "
            "disclose the gap. Report a required review as unmet."
        ),
        guidance_uri=_SEMANTIC_COVERAGE,
        nudge="Do not treat a transport gap as proof the work under review is wrong.",
    ),
    RecoveryDirective(
        token="semantic_no_judgment",
        directive=(
            "This job ended without a judgment; the reason names how it ended, not why. For "
            "optional review, run at most one new check under a NEW request_id, then go "
            "local-only and disclose the gap. Report a required review as unmet."
        ),
        guidance_uri=_SEMANTIC_COVERAGE,
        nudge="Never present retry_budget_exhausted or outcome_unknown as a diagnosis.",
    ),
    RecoveryDirective(
        token="semantic_coordinator_review",
        directive=(
            "A fault inside FinishUP stopped the review. Inspect service diagnostics for this "
            "check request_id. Null provenance does not prove that no provider call occurred."
        ),
        guidance_uri=_SEMANTIC_COVERAGE,
        nudge="This names a FinishUP fault, never a finding about the work under review.",
    ),
    RecoveryDirective(
        token="semantic_privacy_blocked",
        directive=(
            "Blocked before dispatch; never resend this case. Supply a safe replacement to rescan, "
            "then check once under a NEW request_id. Else, for optional review, a "
            "local-only check may stand with the gap; required review is unmet."
        ),
        guidance_uri=_SEMANTIC_COVERAGE,
        nudge="Never reuse the blocked bytes or case identity.",
    ),
    RecoveryDirective(
        token="consent_outcome_unconfirmed",
        directive=(
            "The decision was submitted but its outcome could not be confirmed, so it may already "
            "be effective. Read the recorded grant state through the documented status command "
            "before preparing another consent."
        ),
        guidance_uri=_WORKFLOW_RECOVERY,
        nudge="An unreadable response is not proof a decision was not recorded.",
    ),
    RecoveryDirective(
        token="ceremony_result_invalid",
        directive=(
            "The ceremony finished without reaching its exact successful state, so the approval "
            "was recorded as failed and nothing was approved. Resolve the named service "
            "condition, then prepare and authorize again."
        ),
        guidance_uri=_TEMPLATES_SETUP,
        nudge="A failed approval is not a partial one; nothing durable was stored.",
    ),
    RecoveryDirective(
        token="config_correction_required",
        directive=(
            "FinishUP refused the selected configuration before doing any work, so nothing changed. "
            "Correct the named file, key, profile, or environment variable so it matches the "
            "reviewed configuration model, then run this command again."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
        nudge="config.toml is nonsecret; provision credentials through the credential command.",
    ),
    RecoveryDirective(
        token="instance_identity_repair",
        directive=(
            "This runtime, its pin, and the root's instance marker do not name one trusted "
            "installation. Inspect the named root and pin, then dispose and recreate the "
            "instance, or run the runtime that belongs to that root."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
        nudge="Never point a runtime at a second root, or hand-edit a pin, to get past this.",
    ),
    RecoveryDirective(
        token="instance_request_correction",
        directive=(
            "The instance root or expiry named on this command cannot be used as asked, and "
            "nothing was created or removed. Name a root and expiry the documented instance rules "
            "admit, then run the command again."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
        nudge="The everyday permanent install is never disposed by an instance command.",
    ),
    RecoveryDirective(
        token="capacity_request_correction",
        directive=(
            "The requested observation capacity is not supported for this dimension, and nothing "
            "was changed. Ask the owner to choose a supported finite capacity, preview it, and "
            "apply only that exact accepted preview."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
        nudge="Never describe a finite capacity as uncapped or unlimited.",
    ),
    RecoveryDirective(
        token="local_state_repair",
        directive=(
            "FinishUP could not safely open local state, so nothing was read or written. Repair the "
            "named owner-only path, permission, or size condition and keep state on a local disk, "
            "then run this command again."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
        nudge="Do not move state onto a network or shared filesystem to clear this.",
    ),
    RecoveryDirective(
        token="system_git_upgrade_required",
        directive=(
            "The system Git where FinishUP runs is older than 2.25, the oldest Git FinishUP supports, "
            "so the repository was not read. Ask the owner to install Git 2.25 or later as the "
            "system Git, then run this command again."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
        nudge=(
            "FinishUP uses only the system Git; a newer Git elsewhere on PATH does not change this. "
            "Do not restart the service for it."
        ),
    ),
    RecoveryDirective(
        token="privacy_audit_review",
        directive=(
            "The request was valid; a stored privacy receipt could not be read back. Run "
            "'finishup privacy receipts get <receipt id>' for each reported id, and keep the "
            "correlation_id for 'finishup service diagnostics'."
        ),
        nudge="Report the unreadable receipt; never delete or rewrite audit records to clear it.",
    ),
    RecoveryDirective(
        token="local_service_unavailable",
        directive=(
            "The local service could not serve this request, so no work was recorded. Inspect its "
            "status, let a draining or restarting service settle, then run this command again "
            "under its original request identity."
        ),
        guidance_uri=_WORKFLOW_ERRORS,
        nudge="Never match a FinishUP process by name or path to stop it.",
    ),
)

RECOVERY_DIRECTIVES: Final[Mapping[str, RecoveryDirective]] = MappingProxyType(
    {entry.token: entry for entry in _DIRECTIVES}
)

CONTINUATION_TOKENS: Final[frozenset[str]] = frozenset(RECOVERY_DIRECTIVES)


# Protocol reason codes whose recovery is fully determined by the reason alone. The map itself is
# held literally in ``finishup.protocol.errors`` (a dependency root that cannot import this module),
# because that is where every ``PublicOperationError`` attaches the token at construction; this
# module owns the directive each value stands for and checks the two against each other below.
_REASON_CONTINUATIONS: Final[Mapping[str, str]] = REASON_CODE_CONTINUATIONS

# Reasons the reason code alone cannot resolve, because the correct recovery genuinely differs by
# operation kind. Resolved in ``continuation_for_reason``; held here so the ratchet counts them as
# answered rather than missing.
_OPERATION_DEPENDENT_REASONS: Final[frozenset[str]] = frozenset({"request_timeout"})

# A second, disjoint vocabulary. Lifecycle, instance, and ceremony reasons are raised by the CLI
# and service adapters (``finishup.cli.exits``), never by the protocol validator, so they are not
# members of ``PROTOCOL_REASON_CODES`` and the ratchet below does not range over them. Keeping
# them apart is the point: mixing the namespaces is what let three CLI reasons masquerade as
# protocol reasons while this registry was being written.
_LOCAL_REASON_CONTINUATIONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        # Configuration the loader refused before any work (issues #520, #741).
        "config_file_too_large": "config_correction_required",
        "config_file_unreadable": "config_correction_required",
        "config_preimage_mismatch": "config_correction_required",
        "config_schema_unsupported": "config_correction_required",
        "config_toml_invalid": "config_correction_required",
        "config_value_invalid": "config_correction_required",
        "durability_unsupported": "config_correction_required",
        "external_profile_forbids_local_model": "config_correction_required",
        "external_runtime_forbids_local_model": "config_correction_required",
        "external_runtime_forbids_provider": "config_correction_required",
        "external_runtime_required_for_semantic": "config_correction_required",
        "https_origin_invalid": "config_correction_required",
        "local_model_locator_forbidden": "config_correction_required",
        "max_findings_out_of_range": "config_correction_required",
        "owner_declared_endpoint_forbidden": "config_correction_required",
        "owner_declared_endpoint_required": "config_correction_required",
        "payload_logging_forbidden": "config_correction_required",
        "privacy_bootstrap_unsafe": "config_correction_required",
        "provider_required_for_semantic": "config_correction_required",
        "release_probe_not_a_user_profile": "config_correction_required",
        "secret_env_forbidden": "config_correction_required",
        "secret_in_config": "config_correction_required",
        "strict_local_forbids_provider": "config_correction_required",
        "test_fake_forbids_local_model": "config_correction_required",
        "test_fake_forbids_provider": "config_correction_required",
        "unknown_config_env_var": "config_correction_required",
        "unknown_config_key": "config_correction_required",
        # A FINISHUP_ variable and its legacy YOETZ_ spelling disagree (ADR-048).
        "config_env_conflict": "config_correction_required",
        # Human ceremony and consent (issues #147, #489, #519).
        # Another ceremony is open (#1073): never approve it; finish or cancel it, then retry.
        "ceremony_busy": "ceremony_in_progress",
        # Recent confirmations did not succeed (#1073): wait up to five minutes, retry once.
        "reauthentication_rate_limited": "ceremony_retry_after_wait",
        "ceremony_service_unavailable": "local_service_unavailable",
        "ceremony_unsupported": "ceremony_refusal_terminal",
        "chat_user_attestation_invalid": "consent_relay_correction",
        "chat_user_reauthentication_unavailable": "consent_relay_correction",
        "chat_user_target_mismatch": "pending_decision_refresh",
        "chat_user_warning_required": "consent_relay_correction",
        "human_authority_unavailable": "consent_ceremony_required",
        "human_authorization_required": "consent_ceremony_required",
        "human_authorization_stale": "consent_ceremony_required",
        "kind_forbidden": "ceremony_refusal_terminal",
        "pending_already_active": "pending_decision_in_flight",
        "pending_expired": "consent_ceremony_required",
        "pending_not_actionable": "pending_decision_refresh",
        "pending_unavailable": "pending_decision_refresh",
        "repository_privacy_grant_unconfirmed": "consent_outcome_unconfirmed",
        "repository_privacy_scope_unavailable": "consent_ceremony_required",
        "result_invalid": "ceremony_result_invalid",
        "state_forbidden": "vault_unlock_required",
        "trusted_console_required": "consent_ceremony_required",
        "vault_locked": "vault_unlock_required",
        # Provider credentials (issue #520).
        "provider_binding_required": "provider_setup_required",
        "provider_credential_invalid": "provider_setup_required",
        "provider_credential_required": "provider_setup_required",
        "provider_not_configured": "provider_setup_required",
        "secret_rejected": "provider_setup_required",
        # Installed resource integrity.
        "manifest_digest_mismatch": "resource_integrity_repair",
        "resource_counts_invalid": "resource_integrity_repair",
        "resource_digest_mismatch": "resource_integrity_repair",
        "resource_missing": "resource_integrity_repair",
        "support_digest_mismatch": "resource_integrity_repair",
        "support_resource_set_mismatch": "resource_integrity_repair",
        # Instance identity, isolation roots, and runtime pins (issue #604).
        "installation_identity_mismatch": "instance_identity_repair",
        "instance_absent": "instance_request_correction",
        "instance_exists": "instance_request_correction",
        "instance_expired": "instance_identity_repair",
        "instance_expiry_invalid": "instance_request_correction",
        "instance_identity_invalid": "instance_identity_repair",
        "instance_lifecycle_requires_isolated_root": "instance_identity_repair",
        "instance_not_disposable": "instance_request_correction",
        "instance_root_invalid": "instance_request_correction",
        "instance_root_too_long": "instance_request_correction",
        "instance_service_running": "service_holder_busy",
        "isolation_root_conflict": "instance_identity_repair",
        # The two isolation-root spellings disagree (ADR-048): an environment correction, never
        # an instance repair.
        "isolation_root_env_conflict": "config_correction_required",
        "isolation_root_invalid": "config_correction_required",
        "runtime_pin_conflict": "instance_identity_repair",
        "runtime_pin_invalid": "instance_identity_repair",
        "runtime_pin_unwritable": "local_state_repair",
        # Local storage, workspace, and service lifecycle (issues #237, #428).
        "git_config_limit_exceeded": "local_state_repair",
        "git_version_unsupported": "system_git_upgrade_required",
        # Ambient roots under both the FinishUP and the legacy Yoetz names (ADR-048).
        "installation_root_ambiguous": "local_state_repair",
        "path_contains_symlink": "local_state_repair",
        "path_in_repository": "local_state_repair",
        "path_in_sync_folder": "local_state_repair",
        "path_not_owned": "local_state_repair",
        "path_on_network_filesystem": "local_state_repair",
        "path_shared_temp": "local_state_repair",
        "permissions_too_broad": "local_state_repair",
        "service_already_running": "service_holder_busy",
        "session_monitor_unavailable": "local_service_unavailable",
        "storage_unavailable": "local_state_repair",
        "storage_unsafe": "local_state_repair",
        "unsafe_root": "storage_root_unsafe",
        "workspace_unresolvable": "storage_root_unsafe",
        # Observation capacity owner choices (issue #828).
        "capacity_no_cap_unsupported": "capacity_request_correction",
    }
)

# The one bounded local family whose members are generated rather than enumerated. Every
# ``vault_result_<condition>`` projection reports the same fact -- the ceremony finished outside
# its exact successful state and the approval was consumed as failed -- so one directive answers
# the family, exactly as ``finishup.cli.exits`` gives it one remediation.
LOCAL_REASON_CONTINUATION_PREFIXES: Final[tuple[tuple[str, str], ...]] = (
    ("vault_result_", "ceremony_result_invalid"),
)

# The ratchet's escape hatch (issue #739). A reason code here has been examined and found to need
# no directive beyond its own name: it is an internal invariant an agent cannot act on, or a
# structural validation reason whose field pointer and authoring hint already say what to fix.
# Membership is a decision, not a default — the gate in ``finishup.protocol.errors`` fails the build
# when a newly registered reason code appears in neither this set nor the mapping above, so a new
# reason code cannot land with nothing to say.
REASON_CODE_DIRECTIVE_EXEMPTIONS: Final[frozenset[str]] = frozenset(
    {
        # Internal contention labels do not prove that a first-start lease was released.
        # The start application emits the stronger start_* tokens only after that proof.
        "catalog_busy",
        "catalog_maintenance_busy",
        "runtime_rebind_busy",
        # Validation reasons: the field pointer plus the schema-derived authoring hint already
        # name the exact repair, and a generic directive would bury it.
        "accepted_record_shape_invalid",
        "actor_id_malformed",
        "actor_id_not_generated",
        "byte_order_mark_forbidden",
        "claim_revision_invalid",
        "claim_revision_mismatch",
        "commitment_only_object_kind",
        "duplicate_object_key",
        "empty_check_types",
        "empty_publication_channels",
        "empty_subject_state",
        "event_integer_out_of_range",
        "event_text_out_of_bounds",
        "evidence_digest_availability_invalid",
        "evidence_digest_binding_invalid",
        "evidence_digest_binding_required",
        "evidence_digest_provenance_invalid",
        "evidence_digest_subject_incompatible",
        "evidence_strength_unsupported",
        "finding_json_shape_invalid",
        "finding_priority_mismatch",
        "float_forbidden",
        "id_malformed_uuid",
        "id_not_ascii",
        "id_uuid_not_version_4",
        "id_uuid_wrong_variant",
        "id_wrong_length",
        "id_wrong_prefix",
        "id_wrong_type",
        "import_report_invalid",
        "input_not_bytes",
        "integer_out_of_safe_range",
        "integer_out_of_sqlite_range",
        "invalid_actor_type",
        "invalid_approved_check",
        "invalid_approved_check_policy",
        "invalid_chain",
        "invalid_check_types",
        "invalid_commitment",
        "invalid_cost_fields",
        "invalid_coverage_value",
        "invalid_digest",
        "invalid_duration",
        "invalid_event_enum",
        "invalid_event_schema",
        "invalid_event_value_type",
        "invalid_finding_kind",
        "invalid_finding_origin",
        "invalid_finding_policy_identity",
        "invalid_finding_provenance",
        "invalid_finding_subject_refs",
        "invalid_frontier",
        "invalid_json_pointer",
        "invalid_known_gap",
        "invalid_payload_ref",
        "invalid_projection_locator",
        "invalid_publication_channels",
        "invalid_ranked_findings",
        "invalid_receipt_conclusion",
        "invalid_receipt_document",
        "invalid_receipt_gap",
        "invalid_receipt_obligation",
        "invalid_receipt_redaction",
        "invalid_receipt_response",
        "invalid_receipt_section",
        "invalid_receipt_section_order",
        "invalid_receipt_version_slice",
        "invalid_runtime_attempt_evidence",
        "invalid_sampling_params",
        "invalid_semantic_dispatch_kind",
        "invalid_semantic_failure_class",
        "invalid_semantic_fallback_origin",
        "invalid_semantic_outcome_type",
        "invalid_semantic_provenance",
        "invalid_semantic_status_reason_pair",
        "invalid_subject_state",
        "invalid_timestamp",
        "invalid_token_usage",
        "invalid_utf8",
        "lone_surrogate",
        "malformed_json",
        "missing_payload_field",
        "nesting_too_deep",
        "no_obligations_reason_conflict",
        "noncanonical_integer_string",
        "nul_byte_forbidden",
        "object_key_not_string",
        "obligation_change_invalid",
        "obligation_resolution_invalid",
        "obligation_resolution_mismatch",
        "payload_redaction_mismatch",
        "receipt_coverage_mismatch",
        "receipt_gap_not_in_coverage",
        "receipt_json_shape_invalid",
        "redaction_target_required",
        "ref_mirror_mismatch",
        # Issue #977: the message names the requested item and the exact repair.
        "requested_command_placeholder",
        "response_fields_invalid",
        "runtime_attempt_evidence_json_shape_invalid",
        "semantic_provenance_json_shape_invalid",
        "set_member_not_ascii",
        "timestamp_not_utc",
        "timestamp_out_of_range",
        "timestamp_submillisecond_precision",
        "timestamp_timezone_missing",
        "unknown_payload_field",
        "unsupported_json_type",
        "unsupported_payload_type",
        # Issue #905: a response to a terminal finding records nothing. The finding is done; there
        # is nothing to retry or correct, and a directive would invite a loop.
        "finding_terminal",
        # Internal invariants and defects. An agent cannot act on these; the correlation_id is the
        # recovery path, and inventing a directive would imply a repair that does not exist.
        "internal_error",
        "entry_digest_mismatch",
        "event_family_not_admitted",
        # These producer boundaries do not establish a yielded start lease. The start
        # application maps definite, fenced lease yield to the exact-start continuation.
        "catalog_busy",
        "catalog_maintenance_busy",
        "runtime_rebind_busy",
        "engine_family_wrong_author",
        "frame_invalid",
        "frame_too_large",
        "ledger_assigned_field_in_request_identity",
        "method_forbidden",
        "not_an_accepted_envelope",
        # A host handed one hook ingress more bytes than the fixed stdin cap admits, and
        # the handler did not retain a structural row. The agent cannot shrink what the
        # host already wrote. Cursor may instead retain identity under payload_content_omitted
        # when the complete body fits the skim cap; this reason is the no-row refusal
        # (issue #667).
        "payload_too_large",
        "peer_untrusted",
        "provider_attempt_provenance_is_not_final",
        "public_error_invalid_correlation_id",
        "public_error_invalid_message",
        "public_error_missing_correlation_id",
        "read_projection_failed",
        "response_projection_failed",
        "unknown_event_schema",
        # Schema catalog integrity. Reported through resource_integrity_repair when it reaches an
        # agent surface; the remaining members are build-time integrity checks that never do.
        "schema_artifact_role_invalid",
        "schema_artifact_role_mismatch",
        "schema_bytes_invalid",
        "schema_catalog_incomplete",
        "schema_draft_unsupported",
        "schema_duplicate_identity",
        "schema_id_mismatch",
        "schema_instance_invalid",
        "schema_kind_mismatch",
        "schema_manifest_duplicate_path",
        "schema_manifest_invalid",
        "schema_manifest_member_mismatch",
        "schema_manifest_missing",
        "schema_name_invalid",
        "schema_not_found",
        "schema_path_unsafe",
        "schema_reference_unresolved",
        "schema_version_mismatch",
        # Remaining #739 families whose directives still depend on decisions not yet made
        # (observation-drain, privacy projection, and service-holder identity). Provider
        # and AI-powered review outcomes are classified through
        # ``continuation_for_semantic_outcome`` (issue #742) rather than this list.
        # Listed explicitly so the ratchet records them as pending, not as answered.
        "accepted_but_unresponsive",
        "dependency_changed",
        "import_publication_authority_required",
        "receipt_json_projection_blocked",
        "ownership_contended",
        "plan_version_conflict",
        "privacy_projection_unavailable",
        "privacy_receipt_not_durable",
        "protocol_mismatch",
        "repository_identity_mismatch",
        "repository_identity_required",
        "request_identity_conflict",
        "service_draining",
        "service_generation_changed",
        "service_incompatible",
        "service_unavailable",
        "workspace_task_exists",
        # tb4n3 RC-2 (#1025). Typed INTERNAL_ERROR stages: each names where the bridge or the
        # service failed so the failure is never a bare "internal error". The remedy for each
        # reaches the text channel through ``REASON_REMEDIES`` below rather than a continuation.
        "bridge_error_mapping_failed",
        "bridge_invoke_failed",
        "bridge_result_validate_failed",
        "bridge_result_wire_failed",
        "bridge_request_validation_failed",
        "check_pipeline_failed",
        "closure_prepare_failed",
        "import_publication_failed",
        "maintenance_state_unverified",
        "start_state_inconsistent",
        # #1040: a spawned service exited during startup; `phase` names its stage and the
        # correlation_id resolves its exception class and origin.
        "service_start_failed",
        # #1040 follow-up: a running service whose stamp names no other installation closed a
        # hello without answering. The service recorded why; a system Git below the minimum is
        # named through the explicit `system_git_upgrade_required` continuation as well.
        "service_handshake_failed",
        # Closure-preparation selection reasons: the reason names the selection to correct and
        # the fixed remedy sentence in ``finishup.domain.closure.PREPARATION_REMEDIATIONS`` reaches
        # the text channel beside it (tb4n3 formal-crypto S).
        "closure_attempt_selection_required",
        "closure_claim_decision_required",
        "closure_command_revision_required",
        "closure_draft_invalid",
        "closure_evidence_unavailable",
        "closure_inventory_limit",
        "closure_item_omitted",
        "closure_item_unknown",
        "closure_obligation_content_unavailable",
        "closure_obligation_not_open",
        "closure_obligation_unknown",
        "closure_pagination_invalid",
        "closure_resolution_decision_required",
        "closure_result_too_large",
        "closure_snapshot_unavailable",
        "closure_response_decision_required",
        "closure_result_unavailable",
        "closure_source_unknown",
        "closure_status_unavailable",
        "closure_unattempted_items",
    }
)


# Per-reason remedy sentences for the typed INTERNAL_ERROR stages (tb4n3 RC-2). Like a directive
# these are repository text selected by a closed reason token and never derived from a caller;
# unlike a directive they restate no guidance rule, they say what is known about the failure and
# what the agent can safely do next. Each is bounded so the error identity, the reason and the
# remedy fit the bounded text channel together.
REASON_REMEDIES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "bridge_request_validation_failed": (
            "The bridge's own request validator failed before anything reached the service; "
            "nothing was recorded. Send the same call once more, then report the correlation_id."
        ),
        "bridge_invoke_failed": (
            "The bridge failed while calling the local service. A write (start, publish_work, "
            "check other than an inspection, respond, receipt) may or may not be recorded: replay the same request_id "
            "(never a new one); replay is idempotent and returns the stored result when the "
            "write committed. A read changed nothing: repeat it. Report the correlation_id."
        ),
        "bridge_error_mapping_failed": (
            "The service reported a failure that the bridge could not translate, so its code is "
            "not shown. If you hold session and writer ids, read status view=compact before "
            "repeating the call; a start that returned no ids is replayed once under the same "
            "request_id. Report the correlation_id."
        ),
        "bridge_result_wire_failed": (
            "The bridge could not serialize this call's result. A write (start, publish_work, "
            "check other than an inspection, respond, receipt) is recorded: replaying its request_id fails the same way, "
            "so read status view=operation and view=compact, and never resend it under a new "
            "request_id. A read or dry run changed nothing: repeat it. Report the correlation_id."
        ),
        "bridge_result_validate_failed": (
            "This call's result did not match its response schema. A write (start, publish_work, "
            "check other than an inspection, respond, receipt) is recorded: replaying its request_id fails the same way, "
            "so read status view=operation and view=compact, and never resend it under a new "
            "request_id. A read or dry run changed nothing: repeat it. Report the correlation_id."
        ),
        # n7 RC3b (#1103): the one respond field-rule reason, so a host that renders only the
        # bounded text (Claude Code) gets the rule, not just the token. ``respond`` reuses this
        # sentence in its refusal message, which a host reading the structured body sees.
        "response_fields_invalid": (
            "The answer breaks a field rule of its disposition: acknowledged_not_done, "
            "provenance_disputed, rejected, reopened, self_verified and waived need a reason; "
            "self_verified needs evidence_refs; only waived takes waiver_scope (required) and "
            "waiver_expiry; duplicate_of needs a duplicate_of_finding_id naming another finding."
        ),
        "response_projection_failed": (
            "The operation is recorded, but its response could not be shaped. Replay the same "
            "request_id once to load the stored result; if that replay also fails, stop "
            "replaying: read status view=operation for the committed outcome and view=compact "
            "for the frontier, and never send the work again under a new request_id."
        ),
        "read_projection_failed": (
            "The read changed nothing; its response could not be shaped. Repeat it with a new "
            "request_id, or read status view=versions for the authoritative frontier."
        ),
        "check_pipeline_failed": (
            "The check hit an internal failure and may not have produced a verdict. Replay the "
            "same request_id once: a check that committed returns its stored verdict. If the "
            "replay fails the same way, run check again under a new request_id. Report the "
            "correlation_id."
        ),
        "closure_prepare_failed": (
            "Closure preparation failed unexpectedly and recorded nothing. Read status "
            "view=compact for the frontier, publish the change yourself with publish_work, and "
            "report the correlation_id."
        ),
        "import_publication_failed": (
            "The import's publication did not return an accepted result, so it may or may not "
            "be recorded. Read status view=compact before repeating the import, and report the "
            "correlation_id."
        ),
        "maintenance_state_unverified": (
            "Maintenance could not verify its own state and changed nothing. Preview the plan "
            "again, and report the correlation_id if it recurs."
        ),
        "internal_error": (
            "The bridge failed while building its own error, so nothing more specific is known. "
            "A write may or may not be recorded: replay the same request_id (never a new one). "
            "Report the correlation_id."
        ),
        "start_state_inconsistent": (
            "The start state recorded for this request is inconsistent. Do not start a "
            "replacement task to escape it: read status for the task you meant to attach to, "
            "and report the correlation_id."
        ),
        "service_start_failed": (
            "The local FinishUP service exited while starting, so it is not running and nothing "
            "was recorded; retrying fails the same way until the cause is repaired. Give the "
            "user the correlation_id: 'finishup service diagnostics --correlation-id' with it names "
            "the failing stage and exception class. Do not run service lifecycle commands."
        ),
        "service_handshake_failed": (
            "The local FinishUP service closed the connection while setting it up and answered "
            "nothing, so nothing was recorded. Its stamp does not show another installation, so "
            "it was not replaced. It recorded why: ask the user to run 'finishup service "
            "diagnostics' on a local terminal. Do not run service lifecycle commands for this."
        ),
    }
)


# One corrective phrase per claim-revision invariant. These are directive text reconstructed from a
# typed token, exactly like a continuation directive, so they live beside them rather than inside
# one renderer: before ADR-030 they were reachable only from the MCP text projector, and the CLI
# rendered no correction at all for the same rejection.
CLAIM_REVISION_CORRECTIONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "claim_id_must_be_fresh": "use a fresh claim_id",
        "claim_kind_must_match": "match claim_kind with every superseded claim",
        "completion_scope_must_be_explicit": (
            "set obligation_refs explicitly to the intended obligation ids, or [] for intentional "
            "empty scope; repair an accepted empty-scope claim with a fresh claim_id and its "
            "actual id in supersedes_claim_refs"
        ),
        "empty_scope_must_not_support_obligations": (
            "declare intended obligation ids in obligation_refs; supporting_refs does not declare "
            "scope; for intentional empty scope use [] and remove obligation support; repair an "
            "accepted claim with a fresh claim_id and its actual id in supersedes_claim_refs"
        ),
        "limitation_refs_complete": (
            "include every relevant partial or failed result in limitation_refs"
        ),
        "limitation_refs_must_be_relevant_non_success_results": (
            "keep only relevant non-success results in limitation_refs"
        ),
        "replacement_must_change_effective_claim": (
            "change the replacement's effective claim meaning"
        ),
        "replacement_must_not_dispute": "do not combine supersedes_claim_refs with disputes_refs",
        "scope_overlap_required": (
            "overlap obligation scope with every nonempty superseded claim (a replacement a "
            "plan_revised supersession recorded counts); an empty-scope target "
            "may be explicitly replaced with empty or populated obligation_refs"
        ),
        "supporting_refs_must_exclude_limitations": (
            "keep non-success result ids in limitation_refs rather than supporting_refs"
        ),
        "superseded_claim_must_be_effective": "supersede only an effective claim",
        "superseded_claim_must_exist": "name an existing claim in supersedes_claim_refs",
    }
)


def correction_for_invariant(invariant: object) -> str | None:
    """Return the frozen corrective phrase for a claim-revision invariant, or None."""

    if type(invariant) is not str:
        return None
    return CLAIM_REVISION_CORRECTIONS.get(invariant)


def directive_for(token: object) -> RecoveryDirective | None:
    """Return the frozen directive for a continuation token, or None when unregistered."""

    if type(token) is not str:
        return None
    return RECOVERY_DIRECTIVES.get(token)


_TIMEOUT_CONTINUATIONS: Final[Mapping[TimeoutOperationKind, str]] = MappingProxyType(
    {
        "read": "read_timeout_new_identity",
        "write": "write_timeout_same_identity",
        "start": "start_timeout_same_identity",
    }
)


def timeout_operation_kind(
    operation: object,
    *,
    write_operations: frozenset[str] = WRITE_OPERATIONS,
    check_mode: object = None,
) -> TimeoutOperationKind | None:
    """Classify a timed-out operation name, or None when the name is not a known operation.

    ``start`` is a write whose lost response carries no route ids, so it is its own kind: the
    generic write recovery ("read status view=operation") is an instruction a first start cannot
    follow, and the shipped guidance has always excepted it (replay the exact start once).
    ``check_mode`` is the request's ``mode``: a ``check`` in a ``READ_ONLY_CHECK_MODES`` mode
    records nothing, so it is a read (ADR-047).
    """

    if type(operation) is not str:
        return None
    if operation == "start":
        return "start"
    if operation == "check" and type(check_mode) is str and check_mode in READ_ONLY_CHECK_MODES:
        return "read"
    if operation in write_operations:
        return "write"
    return "read"


# Adapter-boundary failure classes that distinguish a rejected credential from a
# generic transport gap. These tokens are resolved at render time from recorded
# provenance; they are not public SemanticReason values and do not bump frozen
# check-result schemas (issue #742).
_FAILURE_CLASS_CONTINUATIONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "authentication": "semantic_credential_rejected",
        "authorization": "semantic_credential_rejected",
    }
)

# Public SemanticReason values that reach an agent-facing check, receipt, or
# status surface after a provider outcome. Predispatch configuration and policy outcomes
# (``not_configured``, ``credential_unavailable``, ``blocked_by_policy``, ...) carry no
# directive: the coverage guidance says to take that first answer, and a setup prompt on
# every check of an installation without a provider would be noise, not recovery.
_SEMANTIC_REASON_CONTINUATIONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "response_schema_invalid": "semantic_response_invalid",
        "semantic_judgment_rejected": "semantic_response_invalid",
        "response_content_invalid": "semantic_response_truncated",
        "case_capacity_exceeded": "semantic_capacity_exceeded",
        "provider_quota_exhausted": "semantic_capacity_exceeded",
        "provider_timeout": "semantic_timeout",
        "provider_refused": "semantic_refused",
        "provider_rate_limited": "semantic_rate_limited",
        "transport_unavailable": "semantic_transport_retry",
        "retry_budget_exhausted": "semantic_no_judgment",
        "outcome_unknown": "semantic_no_judgment",
        "coordinator_failure": "semantic_coordinator_review",
        "never_send_detected": "semantic_privacy_blocked",
        "classification_uncertain": "semantic_privacy_blocked",
    }
)


def continuation_for_semantic_outcome(
    status: object = None,
    reason: object = None,
    *,
    failure_class: object = None,
) -> str | None:
    """Return the recovery token for a recorded AI-powered review outcome.

    Classification happens at the adapter boundary into closed failure-class
    tokens; this lookup never reads provider or caller text. A rejected
    credential is distinguished from transport failure by ``failure_class``,
    not by finding count or raw provider output (issue #742).
    """

    del status  # Status is accepted for call-site symmetry; the reason pair is closed.
    class_token = None
    if failure_class is not None:
        class_value = getattr(failure_class, "value", failure_class)
        if type(class_value) is str:
            class_token = _FAILURE_CLASS_CONTINUATIONS.get(class_value)
    if class_token is not None:
        return class_token
    reason_value = getattr(reason, "value", reason)
    if type(reason_value) is not str:
        return None
    return _SEMANTIC_REASON_CONTINUATIONS.get(reason_value)


def continuation_for_reason(
    reason_code: object, *, operation_kind: TimeoutOperationKind | None = None
) -> str | None:
    """Return the continuation token for a typed reason, or None when none is registered.

    ``operation_kind`` resolves the one reason whose recovery genuinely differs by operation
    kind: a timed-out read proves nothing committed, a timed-out write leaves the outcome unknown
    and must be recovered under its original identity, and a timed-out ``start`` must be replayed
    outright because the operation view needs ids it never returned (issue #669). When the caller
    cannot say which it was, no directive travels rather than the wrong one.
    """

    if type(reason_code) is not str:
        return None
    if reason_code == "request_timeout":
        if operation_kind is None:
            return None
        return _TIMEOUT_CONTINUATIONS[operation_kind]
    return _REASON_CONTINUATIONS.get(reason_code)


def continuation_for_local_reason(reason: object) -> str | None:
    """Return the continuation token for a CLI lifecycle, instance, or ceremony reason.

    Disjoint from ``continuation_for_reason``: these reasons are raised by local adapters and are
    not protocol reason codes. Callers hold one vocabulary or the other, never both.
    """

    if type(reason) is not str:
        return None
    token = _LOCAL_REASON_CONTINUATIONS.get(reason)
    if token is not None:
        return token
    for prefix, prefixed_token in LOCAL_REASON_CONTINUATION_PREFIXES:
        if reason.startswith(prefix) and len(reason) > len(prefix):
            return prefixed_token
    return None


def local_reason_has_disposition(reason: object) -> bool:
    """Return whether a CLI reason resolves to a directive in either vocabulary.

    The ratchet in ``finishup.cli.exits`` uses this: a local reason is answered when it maps to a
    local directive, or when it is also a protocol reason code whose disposition -- a directive or
    a recorded exemption -- was already decided on the protocol side. Nothing else counts, so a
    new CLI reason cannot land with nothing for an agent to do.
    """

    if type(reason) is not str:
        return False
    if continuation_for_local_reason(reason) is not None:
        return True
    if reason not in PROTOCOL_REASON_CODES:
        return False
    return (
        continuation_for_reason(reason) is not None
        or reason in _OPERATION_DEPENDENT_REASONS
        or reason in REASON_CODE_DIRECTIVE_EXEMPTIONS
    )


def covered_reason_codes() -> frozenset[str]:
    """Return every protocol reason code the ratchet counts as answered.

    A reason is answered when it maps to a directive, resolves to one through the operation kind,
    or carries an explicit exemption. ``finishup.protocol.errors`` compares this against the full
    reason-code vocabulary at import time, so a newly registered reason code cannot land with
    nothing to say.
    """

    return frozenset(
        set(_REASON_CONTINUATIONS) | _OPERATION_DEPENDENT_REASONS | REASON_CODE_DIRECTIVE_EXEMPTIONS
    )


def _check_registry() -> None:
    """Hold the registry to its own bounds at import time."""

    for token, entry in RECOVERY_DIRECTIVES.items():
        if _TOKEN_PATTERN.fullmatch(token) is None or entry.token != token:
            raise RuntimeError("recovery_directive_token_invalid")
        for text, bound in (
            (entry.directive, _MAX_DIRECTIVE_BYTES),
            (entry.nudge, _MAX_NUDGE_BYTES),
        ):
            if text is None:
                continue
            try:
                encoded = text.encode("ascii", errors="strict")
            except UnicodeEncodeError as exc:
                raise RuntimeError("recovery_directive_not_ascii") from exc
            if not 1 <= len(encoded) <= bound:
                raise RuntimeError("recovery_directive_out_of_bounds")
            if any(ord(character) <= 0x1F or ord(character) == 0x7F for character in text):
                raise RuntimeError("recovery_directive_control_character")
        if entry.guidance_uri is not None and (
            _GUIDANCE_URI_PATTERN.fullmatch(entry.guidance_uri) is None
        ):
            raise RuntimeError("recovery_directive_guidance_uri_invalid")
    mapped_tokens = (
        set(_REASON_CONTINUATIONS.values())
        | set(_LOCAL_REASON_CONTINUATIONS.values())
        | {token for _, token in LOCAL_REASON_CONTINUATION_PREFIXES}
        | set(_SEMANTIC_REASON_CONTINUATIONS.values())
        | set(_FAILURE_CLASS_CONTINUATIONS.values())
    )
    if mapped_tokens - CONTINUATION_TOKENS:
        raise RuntimeError("recovery_reason_maps_to_unregistered_token")
    if set(_REASON_CONTINUATIONS) & REASON_CODE_DIRECTIVE_EXEMPTIONS:
        raise RuntimeError("recovery_reason_both_mapped_and_exempt")
    if _OPERATION_DEPENDENT_REASONS & (
        set(_REASON_CONTINUATIONS) | REASON_CODE_DIRECTIVE_EXEMPTIONS
    ):
        raise RuntimeError("recovery_reason_both_operation_dependent_and_fixed")
    # The two reason vocabularies are disjoint by construction. An overlap means a local adapter
    # reason was mistaken for a protocol reason code, which is how three CLI lifecycle reasons
    # were nearly registered as protocol reasons while this module was written.
    if set(_LOCAL_REASON_CONTINUATIONS) & PROTOCOL_REASON_CODES:
        raise RuntimeError("recovery_local_reason_collides_with_protocol_reason")
    for prefix, _ in LOCAL_REASON_CONTINUATION_PREFIXES:
        if _TOKEN_PATTERN.fullmatch(prefix.rstrip("_")) is None:
            raise RuntimeError("recovery_local_reason_prefix_invalid")
        if any(reason.startswith(prefix) for reason in PROTOCOL_REASON_CODES):
            raise RuntimeError("recovery_local_reason_collides_with_protocol_reason")
    # ``finishup.protocol.errors`` is a dependency root and cannot import this module, so it holds
    # the admitted token set literally. Locking the two here means a token can never be admitted
    # onto the wire without a directive behind it, nor a directive exist for a token the
    # normalizer would strip.
    if CONTINUATION_TOKENS != ADMITTED_CONTINUATION_TOKENS:
        raise RuntimeError("recovery_tokens_disagree_with_safe_detail_admission")
    # Every admitted invariant must have a correction, and no correction may name an invariant the
    # normalizer would strip. An invariant without one would reach an agent as a bare token.
    if frozenset(CLAIM_REVISION_CORRECTIONS) != ADMITTED_CLAIM_REVISION_INVARIANTS:
        raise RuntimeError("claim_revision_corrections_disagree_with_admitted_invariants")
    # Coverage ratchet (issue #739). Every reason code must resolve to a directive or carry an
    # explicit exemption, so a newly registered reason can never reach an agent as a bare token
    # with nothing to do about it. Widening the reason vocabulary without deciding what an agent
    # should do is exactly the regression this gate exists to fail on.
    for remedy_reason, remedy in REASON_REMEDIES.items():
        if remedy_reason not in PROTOCOL_REASON_CODES:
            raise RuntimeError("recovery_remedy_for_unregistered_reason_code")
        if not remedy.isascii() or not 1 <= len(remedy) <= _MAX_REMEDY_BYTES:
            raise RuntimeError("recovery_remedy_out_of_bounds")
    if PROTOCOL_REASON_CODES - covered_reason_codes():
        raise RuntimeError("protocol_reason_code_without_recovery_disposition")
    if covered_reason_codes() - PROTOCOL_REASON_CODES:
        raise RuntimeError("recovery_disposition_for_unregistered_reason_code")


_check_registry()
