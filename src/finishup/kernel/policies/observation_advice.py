"""Local observation-advice policy pack over live observation envelopes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from finishup.domain.advice_actions import STANDING_MACHINE_ACTIONS as STANDING_MACHINE_ACTIONS
from finishup.domain.events import ResultOutcome
from finishup.domain.findings import FINDING_KIND_TRAITS, FindingKind
from finishup.domain.observation import (
    ObservationEnvelope,
    ObservationGapCode,
    ObservationLifecycle,
)
from finishup.kernel.observed_failures import (
    ObservedFailureState,
    ObservedRun,
    classify_observed_runs,
)
from finishup.protocol.canonical import JsonValue, canonical_digest

__all__ = [
    "SEMANTIC_ATTENTION_TOKENS",
    "STANDING_MACHINE_ACTIONS",
    "OBSERVATION_ADVICE_FACT_CODES",
    "OBSERVATION_ADVICE_POLICY_ID",
    "OBSERVATION_ADVICE_POLICY_VERSION",
    "ObservationAdviceCandidate",
    "ObservationAdviceContext",
    "ObservationCheckFact",
    "ObservationCompositionFact",
    "ObservationInspectFact",
    "advice_candidate_digest",
    "evidence_basis_digest",
    "observation_advice_findings",
]

OBSERVATION_ADVICE_POLICY_ID: Final = "observation-advice"
OBSERVATION_ADVICE_POLICY_VERSION: Final = "0.1.8"

OBSERVATION_ADVICE_FACT_CODES: Final = frozenset(
    {
        "failed_command_unresolved",
        "edit_after_successful_check",
        "completion_without_verification",
        "static_test_for_live_claim",
        "subagent_finding_unaddressed",
        "change_outside_plan",
        "observation_gap_or_stale",
        "provider_not_ready",
        "semantic_sign_in_required",
        "semantic_provider_attention",
        "semantic_claim_without_attempt",
        # Runtime facts the hook classified at the host boundary (#977). Advice only: they are
        # recorded history the receipt discloses through the matching standing task-fact gap.
        "install_into_yoetz_runtime",
        "install_into_private_env",
        "write_outside_workspace",
    }
)

# Closed, nonsecret reasons the last terminal AI-powered review attempt of a configured
# provider stopped for a cause only the user can repair (#819). The service derives them from
# the attempt's closed failure class and runtime failure stage, never from provider text.
SEMANTIC_ATTENTION_TOKENS: Final = frozenset(
    {
        "sign_in_required",
        "credential_rejected",
        "access_denied",
        "quota_exhausted",
        "model_unavailable",
        "runtime_update_required",
    }
)

type AdviceNextAction = Literal[
    "resolve_failed_command",
    "rerun_approved_check",
    "provide_verification",
    "disclose_limitation",
    "address_subagent_finding",
    "revise_plan_scope",
    "refresh_observation",
    "connect_provider",
    "renew_provider_sign_in",
    "repair_semantic_provider",
    "update_yoetz",
    "attempt_semantic_dispatch",
    "reground_status",
]

_EDIT_TOOLS: Final = frozenset(
    {
        "apply_patch",
        "ApplyPatch",
        "write_file",
        "edit_file",
        "MultiEdit",
        "Write",
        "Edit",
        "shell_write",
    }
)
# Dedicated verification tools: the tool identity itself names a check, so a
# successful result is typed check evidence rather than an inference from a
# command line.  Generic host shells are deliberately absent (#681).
_VERIFICATION_TOOLS: Final = frozenset(
    {
        "test",
        "pytest",
        "cargo_test",
        "npm_test",
        "uv_run_pytest",
    }
)
# Generic host shells.  A successful envelope here proves only that the host
# tool returned; it never proves that a verification check ran.
# Cursor's ordinary profile reports its shell tool as ``Shell`` (#909).  Codex hooks name a
# shell call ``Bash`` (including code-mode ``tools.exec_command``) and its direct tools
# ``exec_command``/``local_shell``; each now states its exit status (#910), so each is a
# command whose failure the unresolved-command rule reads.  A session-stream
# ``command_execution`` row is deliberately absent: advice must not name one run twice.
_SHELL_TOOLS: Final = frozenset({"shell", "Shell", "Bash", "bash", "exec_command", "local_shell"})
# Tools whose envelopes carry command outcomes at all, used by the failed and
# unresolved-command rules, which reason about outcomes rather than checks.
_COMMAND_TOOLS: Final = _VERIFICATION_TOOLS | _SHELL_TOOLS
# Service-owned routine-read markers.  ADR-022 decision 10 keeps routine reads
# a separate class that is never promoted to a check.
_ROUTINE_READ_ACTIONS: Final = frozenset(
    {
        "routine_read",
        "routine_read_detailed",
        "routine_read_summary",
    }
)
_STATIC_CHECK_HINTS: Final = frozenset(
    {
        "pytest",
        "unittest",
        "static",
        "typecheck",
        "pyright",
        "mypy",
        "ruff",
    }
)
_LIVE_CLAIM_HINTS: Final = frozenset(
    {
        "live",
        "wire",
        "network",
        "http",
        "mcp",
        "socket",
        "dispatch",
        "provider",
    }
)


@dataclass(frozen=True, slots=True)
class ObservationCheckFact:
    approval_commitment: str
    subject_state_digest: str
    status: str
    cursor_event_position: int
    is_current: bool = True

    def __post_init__(self) -> None:
        if (
            type(self.approval_commitment) is not str
            or not self.approval_commitment.startswith("sha256:")
            or type(self.subject_state_digest) is not str
            or not self.subject_state_digest.startswith("sha256:")
            or type(self.status) is not str
            or not self.status
            or type(self.cursor_event_position) is not int
            or self.cursor_event_position < 0
            or type(self.is_current) is not bool
        ):
            raise ValueError("observation_advice_invalid")


@dataclass(frozen=True, slots=True)
class ObservationInspectFact:
    selection_digest: str
    relative_paths: tuple[str, ...]
    changed_paths_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ObservationCompositionFact:
    # semantic_ready is the structural usability of the configured AI-powered review
    # path — endpoint bound, factory available, configured credential present.
    # It claims nothing about repository-scoped dispatch authority, which is
    # resolved per check (#265). semantic_configured is the operator's effective intent to
    # use external AI-powered review — review not disabled, an endpoint bound, and the
    # machine privacy policy admitting LLM-inference egress — so a private or intentionally
    # unbound install is never told to connect or repair a provider (#844).
    semantic_configured: bool
    semantic_ready: bool
    provider_factory_ids: tuple[str, ...]
    connected_provider_ids: tuple[str, ...]
    # The last terminal attempt's user-repairable cause (SEMANTIC_ATTENTION_TOKENS) and the
    # provider id it concerns. Structural readiness cannot see an expired Codex login or an
    # exhausted plan; only a real attempt can, and a later successful attempt clears it (#819).
    semantic_attention: str | None = None
    semantic_attention_provider: str | None = None

    def __post_init__(self) -> None:
        if self.semantic_attention is not None and (
            self.semantic_attention not in SEMANTIC_ATTENTION_TOKENS
        ):
            raise ValueError("observation_advice_invalid")


@dataclass(frozen=True, slots=True)
class ObservationAdviceContext:
    envelopes: tuple[ObservationEnvelope, ...]
    lifecycle: ObservationLifecycle
    gaps: tuple[str, ...]
    lineage_refs: tuple[tuple[str, str], ...] = ()
    check_facts: tuple[ObservationCheckFact, ...] = ()
    inspect_fact: ObservationInspectFact | None = None
    composition: ObservationCompositionFact | None = None
    plan_path_digests: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ObservationAdviceCandidate:
    kind: FindingKind
    rule_code: str
    next_action: AdviceNextAction
    evidence_refs: tuple[str, ...]
    priority: int
    detail_token: str

    def __post_init__(self) -> None:
        if type(self.kind) is not FindingKind:
            raise ValueError("observation_advice_invalid")
        if self.rule_code not in OBSERVATION_ADVICE_FACT_CODES:
            raise ValueError("observation_advice_invalid")
        expected, _ = FINDING_KIND_TRAITS[self.kind]
        if self.priority != expected:
            raise ValueError("observation_advice_invalid")


# Structural payload fields the rules below read, named once so a rule and its
# accessor cannot drift apart.
_FIELD_TOOL_NAME: Final = "tool_name"
_FIELD_EXIT_STATUS: Final = "exit_status"
_FIELD_SUCCESS: Final = "success"
_FIELD_CLAIM_KIND: Final = "claim_kind"
_FIELD_RESULT_STATUS: Final = "result_status"
_FIELD_CHANGED_PATHS_DIGEST: Final = "changed_paths_digest"
_FIELD_MAPPING_HINT: Final = "mapping_hint"
_FIELD_SUBAGENT_ID: Final = "subagent_id"
_FIELD_ACTION: Final = "action"
_FIELD_ATTEMPT: Final = "attempt"
_FIELD_DENIED: Final = "denied"
_FIELD_COMMAND_COMMITMENT: Final = "command_commitment"
# The post-phase event kinds that report a completed tool call (Cursor's is mapped to the first).
_POST_TOOL_EVENT_KINDS: Final = frozenset({"PostToolUse", "postToolUse"})
# Read only as correlation keys.
_FIELD_CORRELATION_ID: Final = "correlation_id"
_FIELD_TOOL_CALL_ID: Final = "tool_call_id"
_ORIGINATING_TOOL_ACTIONS: Final = frozenset({"function_call", "custom_tool_call"})

type _ToolCorrelationKey = tuple[str, str, int, str]


def _ascii(value: str) -> bytes:
    return value.encode("ascii", errors="strict")


def _tool(envelope: ObservationEnvelope) -> str | None:
    value = envelope.structural_payload.get(_FIELD_TOOL_NAME)
    return value if type(value) is str else None


def _exit_status(envelope: ObservationEnvelope) -> int | None:
    value = envelope.structural_payload.get(_FIELD_EXIT_STATUS)
    return value if type(value) is int else None


def _success(envelope: ObservationEnvelope) -> bool | None:
    value = envelope.structural_payload.get(_FIELD_SUCCESS)
    return value if type(value) is bool else None


def _claim_kind(envelope: ObservationEnvelope) -> str | None:
    value = envelope.structural_payload.get(_FIELD_CLAIM_KIND)
    return value if type(value) is str else None


def _result_status(envelope: ObservationEnvelope) -> str | None:
    value = envelope.structural_payload.get(_FIELD_RESULT_STATUS)
    return value if type(value) is str else None


def _denied(envelope: ObservationEnvelope) -> bool:
    return envelope.structural_payload.get(_FIELD_DENIED) is True


def _command_commitment(envelope: ObservationEnvelope) -> str | None:
    value = envelope.structural_payload.get(_FIELD_COMMAND_COMMITMENT)
    return value if type(value) is str and value.startswith("hmac-sha256:") else None


def _changed_paths_digest(envelope: ObservationEnvelope) -> str | None:
    value = envelope.structural_payload.get(_FIELD_CHANGED_PATHS_DIGEST)
    return value if type(value) is str else None


def _mapping_hint(envelope: ObservationEnvelope) -> str | None:
    value = envelope.structural_payload.get(_FIELD_MAPPING_HINT)
    return value if type(value) is str else None


def _subagent_id(envelope: ObservationEnvelope) -> str | None:
    value = envelope.structural_payload.get(_FIELD_SUBAGENT_ID)
    return value if type(value) is str else None


def _envelope_ref(envelope: ObservationEnvelope) -> str:
    return envelope.source_identity


def _tool_correlation_key(envelope: ObservationEnvelope) -> _ToolCorrelationKey | None:
    """Return a source/session/generation-fenced key for one tool stream."""

    payload = envelope.structural_payload
    raw_key = (
        payload.get(_FIELD_CORRELATION_ID)
        or payload.get(_FIELD_TOOL_CALL_ID)
        or envelope.source_identity
    )
    if type(raw_key) is not str:
        return None
    return (
        envelope.source.value,
        envelope.session_commitment,
        envelope.cursor.source_generation,
        raw_key,
    )


def _tool_resolution(
    envelopes: Sequence[ObservationEnvelope],
) -> tuple[dict[_ToolCorrelationKey, str], dict[_ToolCorrelationKey, str]]:
    """Index originating and fallback tool names without crossing observation boundaries."""

    originating: dict[_ToolCorrelationKey, str] = {}
    fallback: dict[_ToolCorrelationKey, str] = {}
    for envelope in envelopes:
        key = _tool_correlation_key(envelope)
        tool = _tool(envelope)
        if key is None or tool is None:
            continue
        if envelope.structural_payload.get(_FIELD_ACTION) in _ORIGINATING_TOOL_ACTIONS:
            originating[key] = tool
        else:
            fallback.setdefault(key, tool)
    return originating, fallback


def _resolved_tool(
    envelope: ObservationEnvelope,
    originating: Mapping[_ToolCorrelationKey, str],
    fallback: Mapping[_ToolCorrelationKey, str],
) -> tuple[str | None, _ToolCorrelationKey | None]:
    """Resolve a tool name, giving a same-key originating call precedence."""

    key = _tool_correlation_key(envelope)
    if key is None:
        return None, None
    origin = originating.get(key)
    if origin is not None:
        return origin, key
    return _tool(envelope) or fallback.get(key), key


def _is_routine_read(envelope: ObservationEnvelope) -> bool:
    """Return whether the service classified this envelope as a routine read."""

    action = envelope.structural_payload.get(_FIELD_ACTION)
    return type(action) is str and action in _ROUTINE_READ_ACTIONS


def _observed_check_success(envelope: ObservationEnvelope, tool: str | None) -> bool:
    """Return whether one envelope is typed evidence that a check passed.

    A successful generic shell envelope proves that the host tool returned,
    not that the command verified anything, and a routine read is a separate
    class that is never promoted to a check (ADR-022 decision 10, #681).  Only
    a dedicated verification tool reporting an explicit success qualifies; a
    pre-event remains an attempt until its successful post-event arrives.
    """

    if tool is None or tool not in _VERIFICATION_TOOLS:
        return False
    if _is_routine_read(envelope) or envelope.event_kind in {"PreToolUse", "preToolUse"}:
        return False
    return _exit_status(envelope) == 0 or _success(envelope) is True


def _is_edit_envelope(envelope: ObservationEnvelope, tool: str | None) -> bool:
    """Return whether one envelope is structural evidence of a state edit."""

    if tool is not None and tool in _EDIT_TOOLS:
        return True
    # Also treat apply_patch action writes.
    action = envelope.structural_payload.get(_FIELD_ACTION)
    return action in {"write", "edit", "delete"} or _changed_paths_digest(envelope) is not None


def _candidate(
    kind: FindingKind,
    rule_code: str,
    next_action: AdviceNextAction,
    refs: Sequence[str],
    detail_token: str,
) -> ObservationAdviceCandidate:
    priority, _ = FINDING_KIND_TRAITS[kind]
    ordered = tuple(sorted(set(refs), key=_ascii))
    return ObservationAdviceCandidate(
        kind=kind,
        rule_code=rule_code,
        next_action=next_action,
        evidence_refs=ordered,
        priority=priority,
        detail_token=detail_token,
    )


def _failed_commands(envelopes: Sequence[ObservationEnvelope]) -> list[ObservationAdviceCandidate]:
    """Report a failed command only while it is still live (#909).

    A failure clears when the same host call later reports success (its correlation key), or when
    a later run of the same command identity reports a success, failure, or partial outcome (the
    keyed ``command_commitment`` the hook computed, never command text; only the latest limiting
    run is judged). An unknown outcome cannot certify repair. An edit changes the state under test
    but proves no covering rerun. This is the shared supersession rule the local packs and
    claim-revision invariant apply, so advice cannot keep a failure the packs already treat as
    history. An envelope without a commitment keeps its disclosure duty until it is explicitly
    acknowledged.
    """

    results: list[ObservationAdviceCandidate] = []
    unresolved: dict[_ToolCorrelationKey, tuple[str, ObservationEnvelope]] = {}
    runs: list[ObservedRun] = []
    originating_tools, fallback_tools = _tool_resolution(envelopes)
    for position, envelope in enumerate(envelopes):
        tool, key = _resolved_tool(envelope, originating_tools, fallback_tools)
        if key is None:
            continue
        if envelope.event_kind in {"PreToolUse", "preToolUse"}:
            continue
        exit_status = _exit_status(envelope)
        success = _success(envelope)
        failed = (exit_status is not None and exit_status != 0) or success is False
        passed = not failed and (exit_status == 0 or success is True)
        ref = str(position)
        runner_class = envelope.structural_payload.get("runner_class")
        if tool is not None and tool in _COMMAND_TOOLS:
            if runner_class == "exploration":
                # Known read/exploration failures are not verification commands. Keep unknown
                # command classes on the ordinary advice path (#972).
                continue
            identity = _command_commitment(envelope)
            if failed:
                unresolved[key] = (ref, envelope)
                runs.append(ObservedRun(ref, position, ResultOutcome.FAILURE, identity))
            elif passed:
                unresolved.pop(key, None)
                runs.append(ObservedRun(ref, position, ResultOutcome.SUCCESS, identity))
            elif identity is not None and envelope.event_kind in _POST_TOOL_EVENT_KINDS:
                # Preserve the unknown observation for ordering, but it cannot certify or retire
                # the earlier failure. Only a later success, failure, or partial result is a
                # qualifying same-command rerun.
                runs.append(ObservedRun(ref, position, ResultOutcome.UNKNOWN, identity))
        elif (
            envelope.event_kind in _POST_TOOL_EVENT_KINDS
            and _is_edit_envelope(envelope, tool)
            and passed
            and not _denied(envelope)
        ):
            # Only a post-event with a stated success is a completed edit, exactly as the packs
            # read the ledger result; a permission request, a denied or failed edit, and an edit
            # whose outcome the host did not state are no proof the workspace changed.
            runs.append(ObservedRun(ref, position, ResultOutcome.SUCCESS, edit=True))
    states = classify_observed_runs(runs)
    for key, (ref, envelope) in unresolved.items():
        if states.get(ref) is not ObservedFailureState.LIVE:
            continue
        cause_digest = canonical_digest(
            {
                "correlation_key": key,
                "source_identity": envelope.source_identity,
            }
        )
        results.append(
            _candidate(
                FindingKind.FAILED_WORK_OMITTED,
                "failed_command_unresolved",
                "resolve_failed_command",
                (_envelope_ref(envelope),),
                f"failed:{cause_digest.removeprefix('sha256:')}",
            )
        )
    return results


def _edits_after_check(
    envelopes: Sequence[ObservationEnvelope],
    checks: Sequence[ObservationCheckFact],
) -> list[ObservationAdviceCandidate]:
    # The verification baseline moves only on typed check evidence: a current
    # passed approved-check fact, or a dedicated verification tool reporting an
    # explicit success.  An arbitrary successful shell command and any routine
    # read leave the baseline where it is, so a routine read neither invents a
    # baseline nor carries one past a later edit (#681).
    originating_tools, fallback_tools = _tool_resolution(envelopes)
    last_success_pos: int | None = None
    for envelope in envelopes:
        tool, _key = _resolved_tool(envelope, originating_tools, fallback_tools)
        if _observed_check_success(envelope, tool):
            last_success_pos = envelope.cursor.event_position
    for check in checks:
        if check.status == "passed" and check.is_current:
            last_success_pos = max(last_success_pos or 0, check.cursor_event_position)
    if last_success_pos is None:
        return []
    # One logical host edit is observed twice on paired profiles: a PreToolUse
    # attempt and a PostToolUse result.  Group the observed phases by the
    # source/session/generation-fenced call key so the stale-verification
    # condition keeps one identity per logical edit (#680).  A post-only
    # profile (current Cursor) still yields one group per envelope through the
    # ``source_identity`` fallback in ``_tool_correlation_key``, and two
    # distinct calls — or the same call id across a source, session, or
    # generation boundary — remain separate keys.
    grouped: dict[_ToolCorrelationKey, list[ObservationEnvelope]] = {}
    for envelope in envelopes:
        tool, key = _resolved_tool(envelope, originating_tools, fallback_tools)
        if key is None or not _is_edit_envelope(envelope, tool):
            continue
        grouped.setdefault(key, []).append(envelope)
    results: list[ObservationAdviceCandidate] = []
    for key, phases in grouped.items():
        if not any(phase.cursor.event_position > last_success_pos for phase in phases):
            continue
        # The call key identifies the condition; the phase refs prove it.
        cause_digest = canonical_digest({"correlation_key": key})
        results.append(
            _candidate(
                FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
                "edit_after_successful_check",
                "rerun_approved_check",
                tuple(_envelope_ref(phase) for phase in phases),
                f"edit-after-check:{cause_digest.removeprefix('sha256:')}",
            )
        )
    return results


def _completion_without_verification(
    envelopes: Sequence[ObservationEnvelope],
    checks: Sequence[ObservationCheckFact],
) -> list[ObservationAdviceCandidate]:
    completion_refs: list[str] = []
    for envelope in envelopes:
        claim = _claim_kind(envelope)
        # ``result_status`` describes the outcome of a host/tool event.  It is
        # not an authored statement that the agent's work is complete.  Native
        # Codex completion events commonly carry ``result_status=completed``
        # while retaining no completion claim at all; treating every such row
        # as a claim both raised false advice and accumulated unbounded refs.
        if claim in {"completion", "done", "finished"}:
            completion_refs.append(_envelope_ref(envelope))
    if not completion_refs:
        return []
    has_pass = any(check.status == "passed" and check.is_current for check in checks)
    originating_tools, fallback_tools = _tool_resolution(envelopes)
    # Only typed check evidence supports a completion claim.  A successful
    # arbitrary shell command, and a routine read in particular, leaves the
    # claim unverified (#681).
    has_obs_pass = any(
        _observed_check_success(
            envelope, _resolved_tool(envelope, originating_tools, fallback_tools)[0]
        )
        for envelope in envelopes
    )
    if has_pass or has_obs_pass:
        return []
    return [
        _candidate(
            FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
            "completion_without_verification",
            "provide_verification",
            completion_refs,
            "completion-unverified",
        )
    ]


def _static_for_live(envelopes: Sequence[ObservationEnvelope]) -> list[ObservationAdviceCandidate]:
    live_claims: list[str] = []
    static_support: list[str] = []
    for envelope in envelopes:
        claim = (_claim_kind(envelope) or "").lower()
        hint = (_mapping_hint(envelope) or "").lower()
        tool = (_tool(envelope) or "").lower()
        blob = f"{claim}:{hint}:{tool}"
        if any(token in blob for token in _LIVE_CLAIM_HINTS):
            live_claims.append(_envelope_ref(envelope))
        if (
            any(token in blob for token in _STATIC_CHECK_HINTS)
            and not _is_routine_read(envelope)
            and (_exit_status(envelope) == 0 or _success(envelope) is True)
        ):
            static_support.append(_envelope_ref(envelope))
    if (
        live_claims
        and static_support
        # A live-labelled success suppresses the limitation only when it is
        # typed check evidence; an arbitrary successful shell command is not
        # live verification (#681).
        and not any(
            "live" in ((_mapping_hint(envelope) or "").lower())
            and _observed_check_success(envelope, _tool(envelope))
            for envelope in envelopes
        )
    ):
        # Heuristic: live/wire claim present, only static verification observed.
        return [
            _candidate(
                FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
                "static_test_for_live_claim",
                "disclose_limitation",
                live_claims + static_support,
                "static-for-live",
            )
        ]
    return []


def _subagent_unaddressed(
    envelopes: Sequence[ObservationEnvelope],
    lineage_refs: Sequence[tuple[str, str]] = (),
) -> list[ObservationAdviceCandidate]:
    findings: dict[str, ObservationEnvelope] = {}
    addressed: set[str] = set()
    authorized_refs = dict(lineage_refs)
    for envelope in envelopes:
        sub = _subagent_id(envelope)
        if envelope.event_kind == "SubagentStop" and sub is not None:
            if (
                _result_status(envelope) in {"finding", "failed", "issue"}
                or _success(envelope) is False
            ):
                findings[sub] = envelope
        if sub is not None and envelope.event_kind in {"PostToolUse", "UserPromptSubmit"}:
            if _result_status(envelope) in {"resolved", "addressed", "fixed"}:
                addressed.add(sub)
        # Parent claim acknowledging the subagent id also counts.
        claim = _claim_kind(envelope)
        if claim is not None and sub is not None and claim in {"resolved", "addressed"}:
            addressed.add(sub)
    results: list[ObservationAdviceCandidate] = []
    for sub, envelope in findings.items():
        if sub not in addressed:
            ref = _envelope_ref(envelope)
            authorized_ref = authorized_refs.get(ref)
            evidence_refs = (ref,) if authorized_ref is None else (authorized_ref, ref)
            results.append(
                _candidate(
                    FindingKind.FAILED_WORK_OMITTED,
                    "subagent_finding_unaddressed",
                    "address_subagent_finding",
                    evidence_refs,
                    f"subagent:{sub[:48]}",
                )
            )
    return results


def _outside_plan(
    envelopes: Sequence[ObservationEnvelope],
    inspect: ObservationInspectFact | None,
    plan_path_digests: Sequence[str],
) -> list[ObservationAdviceCandidate]:
    if not plan_path_digests:
        return []
    plan_set = set(plan_path_digests)
    change_refs: list[str] = []
    for envelope in envelopes:
        digest = _changed_paths_digest(envelope)
        if digest is not None and digest not in plan_set:
            change_refs.append(_envelope_ref(envelope))
    if inspect is not None and inspect.changed_paths_digest is not None:
        if inspect.changed_paths_digest not in plan_set:
            change_refs.append(inspect.selection_digest)
    if not change_refs:
        return []
    return [
        _candidate(
            FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
            "change_outside_plan",
            "revise_plan_scope",
            change_refs,
            "outside-plan",
        )
    ]


# Observation conditions that still raise the ``refresh_observation`` advisory.
# Source lag, a stale cursor, an unavailable service and a locked vault recover
# while the session continues (reconcile, drain, restart, unlock), and the
# advisory clears when they do. Unsupported rollout records remain disclosed
# operator coverage, but cannot be repaired by an agent refresh (#974).
_ADVISED_OBSERVATION_GAPS: Final = frozenset(
    {
        ObservationGapCode.SOURCE_LAG.value,
        ObservationGapCode.CURSOR_STALE.value,
        ObservationGapCode.SERVICE_UNAVAILABLE.value,
        ObservationGapCode.VAULT_LOCKED.value,
    }
)


def _observation_gaps(
    lifecycle: ObservationLifecycle,
    gaps: Sequence[str],
    envelopes: Sequence[ObservationEnvelope],
) -> list[ObservationAdviceCandidate]:
    # ``unpaired_event`` is a standing record, not a stale feed (#917): a lost
    # pairing stays disclosed on status, check coverage and the receipt for the
    # rest of the session, and no drain or wait can clear it. It is announced
    # once per new orphan scope instead, so it never raises this advisory.
    present = sorted({gap for gap in gaps if gap in _ADVISED_OBSERVATION_GAPS}, key=str.encode)
    if not present:
        # A lifecycle state can be degraded/stale because of a standing coverage record, a
        # bounded drain backlog, or an empty/unmapped observation path.  Those facts remain in
        # operator status and receipts; without a named recoverable cause they must never become
        # agent-facing ``refresh_observation`` advice (#974).
        return []
    # Name the live cause. Refs are sorted, and ``cause:`` sorts before every
    # observation source identity, so the hook's single evidence reference
    # names it rather than a rolling envelope.
    causes = [f"cause:{gap}" for gap in present]
    refs = [*causes, *(_envelope_ref(item) for item in envelopes[-3:])]
    return [
        _candidate(
            FindingKind.LEDGER_STALE_OR_INCOMPLETE,
            "observation_gap_or_stale",
            "refresh_observation",
            refs,
            "observation-gap",
        )
    ]


def _provider_not_ready(
    composition: ObservationCompositionFact | None,
) -> list[ObservationAdviceCandidate]:
    # connect_provider is a standing machine action, so it must rest on facts
    # that establish the operator has something to connect: AI-powered review wanted
    # but the configured path is structurally unusable. Absence from the
    # connected registry is not such a fact — activation is lazy and
    # repository-scoped, re-established automatically on dispatch (#265) —
    # so registry lag only names evidence, it never triggers the advice. Without effective
    # review intent there is nothing to connect; check reports that coverage gap itself (#844).
    if composition is None:
        return []
    if not composition.semantic_configured or composition.semantic_ready:
        return []
    configured = set(composition.provider_factory_ids)
    connected = set(composition.connected_provider_ids)
    missing = configured - connected
    return [
        _candidate(
            FindingKind.MATERIAL_LIMITATION_OMITTED,
            "provider_not_ready",
            "connect_provider",
            tuple(sorted(missing or {"semantic:not_ready"}, key=_ascii)),
            "provider-not-ready",
        )
    ]


_ATTENTION_NEXT_ACTIONS: Final[Mapping[str, AdviceNextAction]] = {
    "sign_in_required": "renew_provider_sign_in",
    "credential_rejected": "repair_semantic_provider",
    "access_denied": "repair_semantic_provider",
    "quota_exhausted": "repair_semantic_provider",
    "model_unavailable": "repair_semantic_provider",
    "runtime_update_required": "update_yoetz",
}


def _semantic_attention(
    composition: ObservationCompositionFact | None,
) -> list[ObservationAdviceCandidate]:
    # A standing machine condition like provider_not_ready, but resting on the last real
    # attempt instead of structure: the path is usable on paper, yet its last terminal attempt
    # stopped for a cause only the user can repair (#819). A structurally unusable path is
    # provider_not_ready's to report, so the two never compete for the same standing slot.
    if composition is None or composition.semantic_attention is None:
        return []
    if not composition.semantic_configured or not composition.semantic_ready:
        return []
    token = composition.semantic_attention
    refs = [f"semantic:{token}"]
    if composition.semantic_attention_provider:
        refs.append(composition.semantic_attention_provider)
    return [
        _candidate(
            FindingKind.MATERIAL_LIMITATION_OMITTED,
            "semantic_sign_in_required"
            if token == "sign_in_required"
            else "semantic_provider_attention",
            _ATTENTION_NEXT_ACTIONS[token],
            tuple(refs),
            f"semantic-attention:{token}",
        )
    ]


def _semantic_without_attempt(
    envelopes: Sequence[ObservationEnvelope],
) -> list[ObservationAdviceCandidate]:
    claims: list[str] = []
    attempts: list[str] = []
    for envelope in envelopes:
        claim = (_claim_kind(envelope) or "").lower()
        hint = (_mapping_hint(envelope) or "").lower()
        if "semantic" in claim or "live-dispatch" in claim or "live_dispatch" in claim:
            claims.append(_envelope_ref(envelope))
        if "semantic" in hint or envelope.structural_payload.get(_FIELD_ATTEMPT) is not None:
            if "semantic" in hint or claim in {"semantic_attempt", "dispatch_attempt"}:
                attempts.append(_envelope_ref(envelope))
        action = envelope.structural_payload.get(_FIELD_ACTION)
        if type(action) is str and action in {"semantic_dispatch", "live_dispatch"}:
            attempts.append(_envelope_ref(envelope))
    if claims and not attempts:
        return [
            _candidate(
                FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
                "semantic_claim_without_attempt",
                "attempt_semantic_dispatch",
                claims,
                "semantic-unattempted",
            )
        ]
    return []


_RUNTIME_ADVICE_RULES: Final = (
    ("install_target", "yoetz_runtime", "install_into_yoetz_runtime"),
    ("install_target", "private_env", "install_into_private_env"),
    ("write_scope", "outside_workspace", "write_outside_workspace"),
)


def _runtime_facts(envelopes: Sequence[ObservationEnvelope]) -> list[ObservationAdviceCandidate]:
    """One advisory per runtime fact the hook classified (#977), named at its first occurrence.

    The detail token is the rule itself, so each fact is delivered once per session condition;
    the evidence references accumulate but never mint a new identity.
    """

    refs: dict[str, list[str]] = {}
    for envelope in envelopes:
        payload = envelope.structural_payload
        for field, value, rule in _RUNTIME_ADVICE_RULES:
            if payload.get(field) == value:
                refs.setdefault(rule, []).append(_envelope_ref(envelope))
    return [
        _candidate(
            FindingKind.MATERIAL_LIMITATION_OMITTED,
            rule,
            "disclose_limitation",
            tuple(items[:16]),
            f"runtime:{rule}",
        )
        for rule, items in sorted(refs.items())
    ]


def observation_advice_findings(
    context: ObservationAdviceContext,
) -> tuple[ObservationAdviceCandidate, ...]:
    """Emit ranked observation-advice candidates from envelopes and optional facts."""

    if type(context) is not ObservationAdviceContext:
        raise ValueError("observation_advice_invalid")
    envelopes = context.envelopes
    collected: list[ObservationAdviceCandidate] = []
    collected.extend(_failed_commands(envelopes))
    collected.extend(_edits_after_check(envelopes, context.check_facts))
    collected.extend(_completion_without_verification(envelopes, context.check_facts))
    collected.extend(_static_for_live(envelopes))
    collected.extend(_subagent_unaddressed(envelopes, context.lineage_refs))
    collected.extend(_outside_plan(envelopes, context.inspect_fact, context.plan_path_digests))
    collected.extend(_observation_gaps(context.lifecycle, context.gaps, envelopes))
    collected.extend(_provider_not_ready(context.composition))
    collected.extend(_semantic_attention(context.composition))
    collected.extend(_semantic_without_attempt(envelopes))
    collected.extend(_runtime_facts(envelopes))

    # Deduplicate by rule_code + detail_token; keep first occurrence.
    seen: set[tuple[str, str]] = set()
    unique: list[ObservationAdviceCandidate] = []
    for item in collected:
        key = (item.rule_code, item.detail_token)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    ordered = tuple(
        sorted(
            unique,
            key=lambda item: (
                item.priority,
                _ascii(item.rule_code),
                _ascii(item.detail_token),
            ),
        )
    )
    return ordered


def evidence_basis_digest(
    candidates: Sequence[ObservationAdviceCandidate],
    envelopes: Sequence[ObservationEnvelope],
    *,
    extra: Mapping[str, JsonValue] | None = None,
) -> str:
    """Digest the exact evidence frontier used for an advice snapshot."""

    payload: dict[str, JsonValue] = {
        "policy": f"{OBSERVATION_ADVICE_POLICY_ID}/{OBSERVATION_ADVICE_POLICY_VERSION}",
        "candidates": tuple(
            {
                "kind": item.kind.value,
                "rule_code": item.rule_code,
                "evidence_refs": item.evidence_refs,
                "detail_token": item.detail_token,
            }
            for item in candidates
        ),
        "envelope_identities": tuple(item.source_identity for item in envelopes),
    }
    if extra:
        payload["extra"] = dict(sorted(extra.items(), key=lambda pair: pair[0].encode("ascii")))
    return canonical_digest(payload)


def advice_candidate_digest(candidate: ObservationAdviceCandidate) -> str:
    """Return the stable identity of one advice condition.

    Evidence references prove the condition but do not identify it. Several
    rules intentionally retain rolling or accumulating reference windows, so
    including them here would mint a new finding for every routine envelope.
    ``detail_token`` carries the rule-specific cause when multiple independent
    instances of one rule must remain distinct.
    """

    if type(candidate) is not ObservationAdviceCandidate:
        raise ValueError("observation_advice_invalid")
    return canonical_digest(
        {
            "policy": f"{OBSERVATION_ADVICE_POLICY_ID}/{OBSERVATION_ADVICE_POLICY_VERSION}",
            "kind": candidate.kind.value,
            "rule_code": candidate.rule_code,
            "detail_token": candidate.detail_token,
        }
    )
