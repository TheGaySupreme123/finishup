"""One shared reading of hook-observed failed runs at a completion claim (#909).

A completion claim must disclose failed work that is still *live* when it is made. For a result
the harness observed (a hook-observed tool call), a later qualifying run can make an earlier
failure history instead of an omission:

* **Supersession.** A later hook-observed run of the *same command identity* succeeded, or ran
  again with another limiting outcome (failure or partial): only a run with a recorded outcome
  can replace the earlier disclosure duty. An unknown outcome does not certify repair. The
  identity is the installation-keyed ``hmac-sha256:`` command commitment the hook computes and
  materialization stores as ``omitted:<commitment>`` in the action's ``command`` field; the raw
  command text never reaches the ledger. Any other command, and any unkeyed or structural
  placeholder, supersedes nothing.
* **No edit inference.** A workspace edit changes the state being verified, but it does not prove
  that a failed validation was repaired or passed. A failed run therefore stays live until a
  later qualifying run of the same keyed command identity (or an explicit claim acknowledgement)
  resolves its disclosure duty. Legacy rows without a command identity
  (``omitted:structural``) never fall back to "every failure is live" supersession.

Only service-stamped hook observations take part on either side: a cooperative result keeps its
exact ADR-025 disclosure duty, and a cooperative "success" or "edit" can never retire a hook
failure. A superseded or legacy historical failure is not deleted or hidden: the receipt counts it
once as history, and naming it in ``limitation_refs`` stays accepted.

The work-integrity and research-evidence packs, the claim-revision replay invariant, the receipt
builder and the observation-advice rule all read this module, so no two of them can disagree
about which observed failure is still live.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final, cast

from yoetz.domain.events import (
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    LedgerRecord,
    ResultOutcome,
    ResultRecordedPayload,
    is_observation_authored,
)
from yoetz.domain.values import ActionId, EventId, ResultId, event_id
from yoetz.kernel.projections import ProjectionRecord, ProjectionState
from yoetz.protocol.coverage import Coverage, PublicationChannel

__all__ = [
    "COMMAND_IDENTITY_PREFIX",
    "NON_COUNTING_WRITE_TOKENS",
    "observed_edit_counts",
    "ObservedFailureState",
    "ObservedRun",
    "ObservedRunFacts",
    "classify_observed_runs",
    "command_identity",
    "command_segment_identities",
    "observed_command_field",
    "is_observed_run_record",
    "observed_event_ids_from_coverage",
    "observed_event_ids_from_records",
    "observed_failure_states",
    "observed_failure_states_from_records",
    "observed_action_description",
    "observed_action_is_exploratory",
    "observed_action_runner_class",
    "observed_action_runtime_tokens",
    "observed_action_tool",
    "INSTALL_TARGET_CLASSES",
    "RUNTIME_SUFFIX_TOKENS",
    "observed_run_facts",
]

# Hook materialization writes a command action's ``command`` as ``omitted:<digest>``; only an
# installation-keyed commitment is an identity. ``omitted:structural`` carries none.
COMMAND_IDENTITY_PREFIX: Final = "omitted:"
_COMMITMENT_PATTERN: Final = re.compile(r"\Ahmac-sha256:[0-9a-f]{64}\Z", re.ASCII)
# A compound, wrapped, prefixed or redirected observed command also carries, after its identity,
# the closed composition token and the sorted keyed commitments to its simple commands (#977):
# ``omitted:<identity> <composition> <segment> <segment> ...``. Commitments only, never text.
_SEGMENT_COMPOSITIONS: Final = frozenset({"single", "and_chain", "masked"})
_MAX_SEGMENT_IDENTITIES: Final = 32
_FAILED_OUTCOMES: Final = frozenset({ResultOutcome.FAILURE, ResultOutcome.PARTIAL})
_OBSERVED_RUN_FAMILIES: Final = frozenset({"action_recorded", "result_recorded"})
# Hook materialization appends the host tool name to an observed action's description in this
# closed form; the results view reads it back only from service-stamped observed actions.
_TOOL_SUFFIX_RE: Final = re.compile(r" \(tool ([A-Za-z0-9][A-Za-z0-9._:/+-]{0,127})\)\Z", re.ASCII)
_TOOL_TOKEN_RE: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}\Z", re.ASCII)
_RUNNER_SUFFIX_RE: Final = re.compile(
    r" \(runner (exploration|test|build|lint|typecheck|vcs|other|compound)\)\Z", re.ASCII
)
_RUNNER_CLASSES: Final = frozenset(
    {"exploration", "test", "build", "lint", "typecheck", "vcs", "other", "compound"}
)
# Hook-derived runtime facts (#977), appended after the runner suffix in this closed order:
# where a package install resolved its interpreter, an edit outside the workspace root, and the
# effective user the hook process ran as. Closed tokens only; never a path or command text.
INSTALL_TARGET_CLASSES: Final = frozenset(
    {"yoetz_runtime", "workspace_env", "private_env", "system", "unresolved"}
)
_RUNTIME_SUFFIX_RE: Final = re.compile(
    r" \((install (?:yoetz_runtime|workspace_env|private_env|system|unresolved)"
    r"|write (?:outside_workspace|scratch|yoetz_owned)|user (?:root|non_root))\)\Z",
    re.ASCII,
)
RUNTIME_SUFFIX_TOKENS: Final = frozenset(
    {f"install {name}" for name in INSTALL_TARGET_CLASSES}
    | {
        "write outside_workspace",
        "write scratch",
        "write yoetz_owned",
        "user root",
        "user non_root",
    }
)
# Edit runtime tokens that name a write which changes nothing under test (ADR-042, tb4n2 R4):
# every path the edit named was scratch (temp roots outside the workspace) or Yoetz's own material.
NON_COUNTING_WRITE_TOKENS: Final = frozenset({"write scratch", "write yoetz_owned"})


class ObservedFailureState(str, Enum):  # noqa: UP042 - stable closed token
    """Whether one hook-observed failure still needs disclosure at a point in the ledger."""

    LIVE = "live"
    SUPERSEDED = "superseded"
    RERUN = "rerun"
    HISTORICAL = "historical"


@dataclass(frozen=True, slots=True)
class ObservedRun:
    """One hook-observed tool result, reduced to the facts the supersession rule reads.

    ``position`` orders runs (ledger ingestion sequence, or envelope order for advice). ``edit``
    marks an edit tool call for callers that need to retain that structural fact. Edits never
    supersede a failed validation: only a qualifying rerun of the same keyed command identity can
    establish that the earlier failure has been rerun or passed.
    """

    ref: str
    position: int
    outcome: ResultOutcome
    identity: str | None = None
    edit: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.ref) is not str
            or not self.ref
            or type(self.position) is not int
            or type(self.outcome) is not ResultOutcome
            or (self.identity is not None and _COMMITMENT_PATTERN.fullmatch(self.identity) is None)
            or type(self.edit) is not bool
        ):
            raise ValueError("observed_run_invalid")


def command_identity(command: object) -> str | None:
    """Return the keyed command commitment an observed action carries, or ``None``.

    Only ``omitted:hmac-sha256:<hex>`` is an identity, optionally followed by the segment suffix
    ``observed_command_field`` writes. Plain ``sha256`` digests are dictionary-guessable for
    short commands and are never produced as identities, and ``omitted:structural`` (every row
    recorded before command commitments existed) has none.
    """

    if type(command) is not str or not command.startswith(COMMAND_IDENTITY_PREFIX):
        return None
    value = command.removeprefix(COMMAND_IDENTITY_PREFIX).split(" ", 1)[0]
    return value if _COMMITMENT_PATTERN.fullmatch(value) is not None else None


def command_segment_identities(command: object) -> tuple[frozenset[str], str] | None:
    """The segment commitments and composition an observed command carries, or ``None``.

    ``None`` for a simple command (its whole identity is its only one), a legacy row, or a
    suffix that is not exactly the closed form: a malformed suffix never widens a match.
    """

    if command_identity(command) is None:
        return None
    parts = cast(str, command).split(" ")
    if len(parts) < 3 or parts[1] not in _SEGMENT_COMPOSITIONS:
        return None
    segments = parts[2:]
    if len(segments) > _MAX_SEGMENT_IDENTITIES or any(
        _COMMITMENT_PATTERN.fullmatch(item) is None for item in segments
    ):
        return None
    return frozenset(segments), parts[1]


def observed_command_field(
    commitment: str, segments: tuple[str, ...] | None = None, composition: str | None = None
) -> str:
    """The ``command`` field of an observed command action for one keyed identity.

    Without valid segments this is exactly ``omitted:<commitment>``, byte for byte what every
    earlier ledger recorded, so simple commands keep their historical form.
    """

    base = f"{COMMAND_IDENTITY_PREFIX}{commitment}"
    if (
        _COMMITMENT_PATTERN.fullmatch(commitment) is None
        or not segments
        or composition not in _SEGMENT_COMPOSITIONS
        or len(segments) > _MAX_SEGMENT_IDENTITIES
        or any(_COMMITMENT_PATTERN.fullmatch(item) is None for item in segments)
    ):
        return base
    return " ".join((base, composition, *sorted(set(segments))))


def classify_observed_runs(runs: Iterable[ObservedRun]) -> Mapping[str, ObservedFailureState]:
    """Classify every failed or partial run against the runs that follow it.

    One backward pass. Only the latest *limiting* run of a command identity can be live: a failure
    is ``SUPERSEDED`` when a later run with the same identity succeeded, else ``RERUN`` when a
    later failure or partial run with the same identity follows it (that later run is the one
    judged), else ``LIVE``. A later failure of the same identity is a new failure in its own
    right; it never revives an earlier superseded one. Edits or other workspace-state changes do
    not retire a failure because neither proves that the failed validation was covered. The caller
    bounds ``runs`` to what precedes the point being judged.
    """

    ordered = sorted(runs, key=lambda run: run.position, reverse=True)
    if len({run.position for run in ordered}) != len(ordered):
        raise ValueError("observed_run_invalid")
    passed_after: set[str] = set()
    ran_after: set[str] = set()
    states: dict[str, ObservedFailureState] = {}
    for run in ordered:
        if run.outcome in _FAILED_OUTCOMES:
            if run.identity is not None and run.identity in passed_after:
                states[run.ref] = ObservedFailureState.SUPERSEDED
            elif run.identity is not None and run.identity in ran_after:
                states[run.ref] = ObservedFailureState.RERUN
            else:
                states[run.ref] = ObservedFailureState.LIVE
        if run.identity is not None and (
            run.outcome in _FAILED_OUTCOMES or run.outcome is ResultOutcome.SUCCESS
        ):
            ran_after.add(run.identity)
            if run.outcome is ResultOutcome.SUCCESS:
                passed_after.add(run.identity)
    return MappingProxyType(states)


def is_observed_run_record(record: LedgerRecord) -> bool:
    """A service-stamped hook-observed action or result record (ADR-022 decision 2)."""

    return (
        type(record) is AcceptedEvent
        and record.schema.name in _OBSERVED_RUN_FAMILIES
        and record.publication_channel is PublicationChannel.HOOK_OBSERVED
        and is_observation_authored(record)
    )


def observed_event_ids_from_records(records: Iterable[LedgerRecord]) -> frozenset[EventId]:
    """The hook-observed action and result events of one accepted prefix."""

    return frozenset(record.event_id for record in records if is_observed_run_record(record))


def observed_event_ids_from_coverage[Ref: str](
    coverage_by_ref: Mapping[Ref, Coverage],
) -> frozenset[EventId]:
    """Source events whose service-derived coverage names the hook-observed channel.

    ADR-022 decision 2 keeps ``hook_observed`` unselectable by cooperative requests, so this is
    the same provenance test the research-evidence outcome narrowing already applies.
    """

    return frozenset(
        event_id(ref)
        for ref, coverage in coverage_by_ref.items()
        if ref.startswith("evt_")
        and PublicationChannel.HOOK_OBSERVED in set(coverage.publication_channels)
    )


def _projection_runs(
    results: Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]],
    actions: Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]],
    observed: frozenset[EventId],
    through: int,
) -> tuple[ObservedRun, ...]:
    runs: list[ObservedRun] = []
    for result_ref, record in results.items():
        payload = record.payload
        if (
            payload is None
            or record.source_frontier > through
            or record.source_event_id not in observed
        ):
            continue
        identity: str | None = None
        edit = False
        action = actions.get(payload.action_id)
        if action is not None and action.payload is not None and action.source_event_id in observed:
            if action.payload.action_kind is ActionKind.COMMAND:
                identity = command_identity(action.payload.command)
            elif action.payload.action_kind is ActionKind.EDIT:
                edit = True
        runs.append(
            ObservedRun(
                ref=str(result_ref),
                position=record.source_frontier,
                outcome=payload.outcome,
                identity=identity,
                edit=edit,
            )
        )
    return tuple(runs)


def observed_failure_states_from_records(
    results: Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]],
    actions: Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]],
    observed_event_ids: frozenset[EventId],
    *,
    through: int,
) -> Mapping[ResultId, ObservedFailureState]:
    """Classify each hook-observed failed or partial result recorded no later than ``through``.

    ``observed_event_ids`` are the source events the caller established as service-stamped
    hook observations. A result absent from the returned mapping is not hook-observed and keeps
    its ordinary disclosure duty. The replay reducer calls this form directly with the maps it is
    folding, so admission and the policies read one rule.
    """

    if type(observed_event_ids) is not frozenset:
        raise ValueError("observed_run_invalid")
    if type(through) is not int or through < 0:
        raise ValueError("observed_run_invalid")
    states = classify_observed_runs(_projection_runs(results, actions, observed_event_ids, through))
    return MappingProxyType({ResultId(ref): state for ref, state in states.items()})


def observed_failure_states(
    projection: ProjectionState,
    observed_event_ids: frozenset[EventId],
    *,
    through: int,
) -> Mapping[ResultId, ObservedFailureState]:
    """Classify the hook-observed failures of one projection up to ``through``."""

    if type(projection) is not ProjectionState:
        raise ValueError("observed_run_invalid")
    return observed_failure_states_from_records(
        projection.results, projection.actions, observed_event_ids, through=through
    )


def observed_action_description(
    base: str,
    tool: str | None,
    runner_class: str | None = None,
    *,
    install_target: str | None = None,
    write_outside_workspace: bool = False,
    effective_user: str | None = None,
    write_scope: str | None = None,
) -> str:
    """Append bounded host facts to an observed action description, when known.

    The suffix order is fixed (tool, runner, install, write, user) so each reader can strip the
    later suffixes before parsing an earlier one. Every value is a closed token.
    """

    result = base
    if tool is not None and _TOOL_TOKEN_RE.fullmatch(tool) is not None:
        result = f"{result} (tool {tool})"
    if runner_class in _RUNNER_CLASSES:
        result = f"{result} (runner {runner_class})"
    if install_target in INSTALL_TARGET_CLASSES:
        result = f"{result} (install {install_target})"
    if write_outside_workspace is True or write_scope == "outside_workspace":
        result = f"{result} (write outside_workspace)"
    elif write_scope in {"scratch", "yoetz_owned"}:
        result = f"{result} (write {write_scope})"
    if effective_user in {"root", "non_root"}:
        result = f"{result} (user {effective_user})"
    return result


def _split_runtime_suffixes(description: str) -> tuple[str, frozenset[str]]:
    tokens: set[str] = set()
    remaining = description
    for _ in range(3):
        match = _RUNTIME_SUFFIX_RE.search(remaining)
        if match is None:
            break
        tokens.add(match.group(1))
        remaining = remaining[: match.start()]
    return remaining, frozenset(tokens)


def observed_action_runtime_tokens(description: str) -> frozenset[str]:
    """Read back the closed runtime suffixes (``install <class>``, ``write outside_workspace``,
    ``user root|non_root``) ``observed_action_description`` wrote."""

    return _split_runtime_suffixes(description)[1]


def observed_edit_counts(description: str) -> bool:
    """Whether an observed edit can change the work under test (ADR-042, tb4n2 R4).

    ``False`` only for an edit whose every path was scratch (temp roots outside the workspace) or Yoetz's own
    material (``write scratch`` / ``write yoetz_owned``): it never makes an earlier verification
    stale and is not acting on the task. Deliverable, workspace and real outside-workspace edits,
    and every edit recorded before the class existed, count.
    """

    return not (observed_action_runtime_tokens(description) & NON_COUNTING_WRITE_TOKENS)


def observed_action_tool(description: str) -> str | None:
    """Read back the tool name ``observed_action_description`` wrote, or ``None``."""

    # Runner and runtime suffixes are appended after the tool suffix. Strip those bounded
    # suffixes before applying the anchored tool parser so adding them cannot break lookup.
    without_runtime, _tokens = _split_runtime_suffixes(description)
    without_runner = _RUNNER_SUFFIX_RE.sub("", without_runtime)
    match = _TOOL_SUFFIX_RE.search(without_runner)
    return None if match is None else match.group(1)


def observed_action_runner_class(description: str) -> str | None:
    """Read the bounded command class derived at the host boundary, or ``None``."""

    without_runtime, _tokens = _split_runtime_suffixes(description)
    match = _RUNNER_SUFFIX_RE.search(without_runtime)
    return None if match is None else match.group(1)


def observed_action_is_exploratory(action: ActionRecordedPayload) -> bool:
    """Return true only for a service-derived command classified as a safe exploration."""

    return (
        action.action_kind is ActionKind.COMMAND
        and observed_action_runner_class(action.description) == "exploration"
    )


@dataclass(frozen=True, slots=True)
class ObservedRunFacts:
    """What the results view shows so an agent can recognize its own observed run.

    Structural only: the 1-based occurrence among hook-observed results in ledger order, the host
    tool name, the keyed command commitment, and the recorded exit status. Never command text.
    The runner class (test, typecheck, build, lint, vcs, other) is #910's to add here.
    """

    occurrence: int
    tool_name: str | None
    command_commitment: str | None
    exit_status: int | None


def observed_run_facts(
    projection: ProjectionState,
    observed_event_ids: frozenset[EventId],
) -> Mapping[ResultId, ObservedRunFacts]:
    """Index every readable hook-observed result by its structural run facts."""

    if type(projection) is not ProjectionState or type(observed_event_ids) is not frozenset:
        raise ValueError("observed_run_invalid")
    ordered = sorted(
        (
            (record.source_frontier, result_ref, record)
            for result_ref, record in projection.results.items()
            if record.payload is not None and record.source_event_id in observed_event_ids
        ),
        key=lambda item: item[0],
    )
    facts: dict[ResultId, ObservedRunFacts] = {}
    for occurrence, (_frontier, result_ref, record) in enumerate(ordered, 1):
        payload = record.payload
        assert payload is not None
        tool: str | None = None
        commitment: str | None = None
        action = projection.actions.get(payload.action_id)
        if (
            action is not None
            and action.payload is not None
            and action.source_event_id in (observed_event_ids)
        ):
            tool = observed_action_tool(action.payload.description)
            if action.payload.action_kind is ActionKind.COMMAND:
                commitment = command_identity(action.payload.command)
        facts[result_ref] = ObservedRunFacts(occurrence, tool, commitment, payload.exit_status)
    return MappingProxyType(facts)
