"""Input-aware freshness from recorded declarations and trusted workspace comparisons (#1143).

An input declaration is evidence of what the agent says the check reads, not a syscall trace.
A change the trusted comparison placed (keyed path identities) is judged against the recorded
inputs: a changed input is stale and named, outputs and disjoint changes are quiet, and an
unrecorded dependency or opaque directory asks for a decision. A counting change FinishUP cannot
place (a host edit-tool edit, a shell write without a trusted comparison, an unavailable or
incomplete comparison) may have edited a deliverable source, which is an input, so it keeps the
verification stale (controller decision under the #1143 direction, ADR-042). No command-text
heuristic proves a read.
Every input scope is per verification: a requested input applies to the runs of the command its
obligation requests, and a per-run declaration applies to that one run.
"""

from __future__ import annotations

import json
import posixpath
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

from finishup.domain.bounded_text import quoted_path
from finishup.domain.events import (
    ActionKind,
    ClaimRecordedPayloadV1_1,
    EvidenceRecordedPayload,
    LedgerRecord,
    RequestedItemKind,
    RequestedItemRole,
    ResultOutcome,
    is_observation_authored,
)
from finishup.domain.values import ActionId, EventId, ResultId, event_id, result_id
from finishup.domain.workspace_effect import (
    path_beyond_workspace_fingerprint,
    workspace_effect_from_annotation,
    workspace_effect_from_result_summary,
    workspace_entries_from_summary,
    workspace_write_scopes_from_summary,
)
from finishup.kernel.observed_failures import (
    command_identity,
    observed_action_runner_class,
    observed_action_tool,
    observed_edit_counts,
    observed_shell_write_counts,
    observed_write_stales_verification,
)
from finishup.kernel.projections import ProjectionState
from finishup.protocol.canonical import JsonValue

if TYPE_CHECKING:
    from finishup.kernel.deterministic_checks import DeterministicCase

INPUTS_REFERENCE = "finishup-verification-inputs/v1:"
RERUN_QUESTION = "verification_rerun_question"
# A disclosure, never agent work: freshness held only because the caller asserted that its
# per-run input declaration is complete, and a later change fell outside that declaration.
CALLER_ASSERTED_INPUTS = "verification_inputs_caller_asserted"
FRESHNESS_FACT = "verification_freshness_question"

# How the affected verification's inputs are known; persisted with the frozen case so every
# rendering states the same basis after recovery.
FRESHNESS_BASES: Final = frozenset({"undeclared", "requested", "declared", "complete"})
_MAX_LABEL_BYTES: Final = 1_024
# Agent-published evidence references are only name candidates for keyed identities; bound them.
_MAX_NAME_CANDIDATES: Final = 512


@dataclass(frozen=True, slots=True)
class VerificationFreshness:
    """One retained verification run and the later changes that bear on it.

    ``state`` is ``stale`` (a recorded input changed, or a counting change FinishUP cannot place),
    ``unknown`` (a placed change may touch an input FinishUP cannot rule out) or ``current``. A ``current`` row exists only to disclose that
    a later change was set aside on the caller's complete-declaration assertion. ``basis`` names
    how the run's inputs are known and ``label`` is the requested command it matched, if any.
    ``set_aside`` says that a later change was set aside on that assertion; it is derived with
    the row and not persisted (a frozen ``current`` row implies it).
    """

    run_ref: ResultId
    state: str
    changes: tuple[str, ...]
    change_refs: tuple[EventId, ...]
    basis: str = "undeclared"
    label: str | None = None
    set_aside: bool = field(default=False, compare=False)

    def __post_init__(self) -> None:
        result_id(self.run_ref)
        if (
            self.state not in {"current", "stale", "unknown"}
            or self.basis not in FRESHNESS_BASES
            or len(self.changes) > 16
            or len(self.change_refs) > 16
        ):
            raise ValueError("verification_freshness_invalid")
        if any(type(text) is not str or len(text.encode("utf-8")) > 2048 for text in self.changes):
            raise ValueError("verification_freshness_invalid")
        if type(self.changes) is not tuple or type(self.change_refs) is not tuple:
            raise ValueError("verification_freshness_invalid")
        if self.label is not None and (
            type(self.label) is not str
            or not self.label
            or len(self.label.encode("utf-8")) > _MAX_LABEL_BYTES
        ):
            raise ValueError("verification_freshness_invalid")
        if self.change_refs != tuple(sorted(set(self.change_refs), key=str.encode)):
            raise ValueError("verification_freshness_invalid")
        if self.state == "current" and (self.basis != "complete" or not self.change_refs):
            raise ValueError("verification_freshness_invalid")
        if type(self.set_aside) is not bool or self.set_aside and self.basis != "complete":
            raise ValueError("verification_freshness_invalid")
        for ref in self.change_refs:
            event_id(ref)

    @property
    def caller_asserted(self) -> bool:
        """Freshness set a later change aside only on the caller's complete declaration.

        A change the record cannot place (an unnamed host edit) is asked about, not set aside, so
        a complete declaration alone never raises the disclosure. A stale run already demands a
        rerun, so it discloses nothing more.
        """

        return self.state == "current" or self.set_aside and self.state != "stale"

    def to_json(self) -> list[JsonValue]:
        return cast(
            list[JsonValue],
            [
                self.run_ref,
                self.state,
                list(self.changes),
                list(self.change_refs),
                self.basis,
                self.label,
            ],
        )


@dataclass(slots=True)
class _InputScope:
    """What one obligation, or one per-run declaration, says a verification reads."""

    inputs: set[str] = field(default_factory=lambda: set[str]())
    directories: set[str] = field(default_factory=lambda: set[str]())
    unobservable: bool = False


def _within(name: str, directory: str) -> bool:
    return directory in {"", "."} or name == directory or name.startswith(directory + "/")


def _may_hold_input(
    identities: tuple[str, ...] | None,
    names: dict[str, str],
    directories: set[str],
    unobservable: bool,
) -> bool:
    """Whether a later change may have touched an input the record cannot rule out.

    An input the comparison cannot see (outside the workspace or beyond the fingerprint) may have
    changed with any write. A requested directory input can be ruled out only for changed paths
    the record names and that lie outside it.
    """

    if unobservable:
        return True
    if not directories:
        return False
    return identities is None or any(
        (name := names.get(identity)) is None
        or any(_within(name, directory) for directory in directories)
        for identity in identities
    )


# What is known about a later change that carries no keyed path identity: its kind and, for a
# host edit-tool edit, the bounded tool token the hook recorded.
_Unplaced = tuple[str, str | None]
_NOOP_UNOBSERVABLE: Final[_Unplaced] = ("noop_unobservable", None)
_UNPLACED_TEXT: Final[Mapping[str, str]] = MappingProxyType(
    {
        "edit": "later edit(s) through a host edit tool{tools}; edit tools record no file path",
        "command": (
            "later command(s) wrote workspace files without a trusted workspace comparison, so"
            " no file path is recorded"
        ),
        "comparison_unavailable": (
            "later call(s) had no available workspace comparison, so no file path is recorded"
        ),
        "comparison_incomplete": (
            "later call(s) had an incomplete workspace comparison (too many changed paths, a"
            " replaced workspace root or an older record), so no file path is recorded"
        ),
        "noop_unobservable": (
            "later rewrite(s) left the compared workspace unchanged, but a verification input"
            " lies outside what the comparison covers"
        ),
    }
)
_MAX_TOOLS_NAMED: Final = 3


def _unplaced_action(kind: ActionKind, description: str) -> _Unplaced:
    if kind is ActionKind.EDIT:
        return ("edit", observed_action_tool(description))
    return ("command", None)


def _count_unplaced(counts: dict[str, tuple[int, frozenset[str]]], unplaced: _Unplaced) -> None:
    count, tools = counts.get(unplaced[0], (0, frozenset[str]()))
    counts[unplaced[0]] = (count + 1, tools | ({unplaced[1]} if unplaced[1] else set[str]()))


def _unplaced_summaries(counts: Mapping[str, tuple[int, frozenset[str]]]) -> list[str]:
    """One sentence per kind of change FinishUP cannot place, never claiming what it touched."""

    lines: list[str] = []
    for kind in _UNPLACED_TEXT:
        if kind not in counts:
            continue
        count, tools = counts[kind]
        named = sorted(tools)[:_MAX_TOOLS_NAMED]
        listed = (
            ""
            if not named
            else " ("
            + ", ".join(quoted_path(tool) for tool in named)
            + (f" and {len(tools) - len(named)} more" if len(tools) > len(named) else "")
            + ")"
        )
        lines.append(
            f"{count} {_UNPLACED_TEXT[kind].format(tools=listed)}; FinishUP cannot tell whether"
            " that touched this verification's inputs"
        )
    return lines


# Finding text is bounded at 8 192 characters; leave room for the template and subjects.
_MAX_FRESHNESS_DETAIL_CHARS: Final = 7_600
FRESHNESS_DETAIL_MARKER: Final = " Recorded verification and later changes:"
_FRESHNESS_BASIS_TEXT: Final[Mapping[str, str]] = MappingProxyType(
    {
        "undeclared": (
            "no usable input declaration is recorded for it, so FinishUP cannot tell which files"
            " it read"
        ),
        "requested": "its inputs are known only from the task's requested input files",
        "declared": "its inputs come from the caller's partial input declaration",
        "complete": (
            "its inputs come from the caller-asserted complete input declaration; FinishUP did"
            " not observe which files it read"
        ),
    }
)
_STALE_FACTS: Final = frozenset({"planned_verification_stale", "edited_after_last_verification"})


def freshness_rows_for(
    case: DeterministicCase, subject_refs: Iterable[str], known_gaps: Iterable[str]
) -> list[VerificationFreshness]:
    """The freshness rows a local ledger-stale finding is about (#1143).

    A row whose run the finding names, or a stale row when the finding carries a stale fact.
    """

    subjects = set(subject_refs)
    stale_fact = bool(set(known_gaps) & _STALE_FACTS)
    return [
        row
        for row in case.verification_freshness or ()
        if row.state != "current"
        and (
            case.projection.results[row.run_ref].source_event_id in subjects
            or row.state == "stale"
            and stale_fact
        )
    ]


def freshness_detail(
    rows: Iterable[VerificationFreshness], used: int = 0, *, named: bool = True
) -> str:
    """The bounded freshness suffix of a finding detail (``FRESHNESS_DETAIL_MARKER`` first).

    ``named`` renders the requested command and the changed paths the record names, for the
    local agent. The review packet uses ``named=False``: the requested command and those paths
    come from obligation and evidence text, so they leave only through their own privacy
    categories, never as finding prose; it counts them instead (#1167 review finding 10).
    ``used`` is the length of the detail the suffix extends.
    """

    rows = list(rows)
    detail = FRESHNESS_DETAIL_MARKER
    for row in rows[:4]:
        label = (
            ""
            if row.label is None or not named
            else f" (requested command {quoted_path(row.label)})"
        )
        changes = list(row.changes)
        if not named:
            # Named lines start with the quoted path; count lines never do.
            hidden = sum(1 for text in changes if text.startswith('"'))
            changes = [text for text in changes if not text.startswith('"')]
            if hidden:
                changes.insert(
                    0,
                    f"{hidden} named change(s) withheld here; the obligation and evidence items"
                    " carry their paths where the privacy policy allows",
                )
        listed = "; ".join(changes[:4])
        more = f"; {len(changes) - 4} more" if len(changes) > 4 else ""
        sentence = (
            f" verification {row.run_ref}{label}: {_FRESHNESS_BASIS_TEXT[row.basis]}."
            f" Later changes: {listed}{more}."
        )
        if used + len(detail) + len(sentence) > _MAX_FRESHNESS_DETAIL_CHARS:
            break
        detail += sentence
    if len(rows) > 4 and used + len(detail) + 64 <= _MAX_FRESHNESS_DETAIL_CHARS:
        detail += f" {len(rows) - 4} more verification(s) omitted."
    return detail


def name_free_finding_detail(
    detail: str,
    case: DeterministicCase,
    subject_refs: Iterable[str],
    known_gaps: Iterable[str],
) -> str:
    """``detail`` with its freshness suffix re-rendered without names, for the review packet."""

    head, marker, _named = detail.partition(FRESHNESS_DETAIL_MARKER)
    if not marker:
        return detail
    rows = freshness_rows_for(case, subject_refs, known_gaps)
    return head + freshness_detail(rows, len(head), named=False) if rows else head


def verification_freshness(
    projection: ProjectionState,
    records: Iterable[LedgerRecord],
) -> tuple[VerificationFreshness, ...]:
    # Local import breaks the task_facts -> freshness -> task_facts cycle.
    from finishup.kernel.task_facts import (
        PlannedCommand,
        effective_obligations,
        non_counting_edits_exempt,
        observed_event_ids_from_records,
        observed_run_from_command,
        planned_match,
        requested_planned_command,
        requested_verification_run_events,
        stale_exempt_write_tokens,
        task_workspace_root,
        verification_path_identity,
        verification_unchanged_actions,
    )

    prefix = tuple(records)
    observed = observed_event_ids_from_records(prefix)
    requested_runs = requested_verification_run_events(projection, prefix)
    root = task_workspace_root(prefix)
    # Scoped per run below: only a run with an input the comparison cannot see refuses the proof.
    unchanged: frozenset[ActionId] = verification_unchanged_actions(
        projection, prefix, per_verification=True
    )
    exempt = non_counting_edits_exempt(projection)
    stale_exempt = stale_exempt_write_tokens(projection)

    def relative(value: str) -> str | None:
        path = posixpath.normpath(value.replace("\\", "/"))
        if path.startswith("/"):
            # POSIX keeps a leading "//"; normalize it exactly as the no-op proof's input check.
            path = "/" + path.lstrip("/")
            if root is None or not path.startswith(root.rstrip("/") + "/"):
                return None
            path = path[len(root.rstrip("/")) + 1 :]
        return None if path == ".." or path.startswith("../") else path

    names: dict[str, str] = {}
    # Requested inputs are scoped through their obligation: they belong to the runs of the
    # command that obligation requests. An obligation that requests no command names task-level
    # inputs; they apply to every run whose own complete declaration does not say otherwise.
    command_scopes: list[tuple[tuple[tuple[str, PlannedCommand], ...], _InputScope]] = []
    unscoped = _InputScope()
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        scope = _InputScope()
        for item in payload.requested_items:
            if item.item_kind not in {RequestedItemKind.FILE, RequestedItemKind.DIRECTORY}:
                continue
            directory = item.item_kind is RequestedItemKind.DIRECTORY
            path = relative(item.value)
            if item.role is RequestedItemRole.INPUT:
                if path is None or path_beyond_workspace_fingerprint(
                    item.value, directory=directory, workspace_root=root
                ):
                    # The comparison cannot see this input change at all.
                    scope.unobservable = True
                elif directory:
                    # The comparison sees its changes, but a keyed identity cannot be mapped to
                    # directory membership unless the changed path is named in the record.
                    scope.directories.add(path)
            if directory:
                continue
            identity = None if path is None else verification_path_identity(path)
            if identity is not None and path is not None:
                names[identity] = path
                if item.role is RequestedItemRole.INPUT:
                    scope.inputs.add(identity)
        commands = tuple(
            (item.value, command)
            for item in payload.requested_items
            if item.item_kind is RequestedItemKind.COMMAND
            and (command := requested_planned_command(item.value)) is not None
        )
        if commands:
            command_scopes.append((commands, scope))
        else:
            unscoped.directories |= scope.directories
            unscoped.unobservable |= scope.unobservable

    # Manifest evidence refers to ONE actual observed run, so a rerun needs its own declaration.
    # Unknown fields, malformed/truncated payloads and conflicting declarations never grant
    # completeness. They fall back to asking. Declarations are disclosed as agent assertions.
    manifests: dict[str, list[tuple[_InputScope, set[str], bool]]] = {}
    manifest_counts: dict[str, int] = {}
    candidates: list[tuple[int, str]] = []
    for row in projection.evidence.values():
        payload = row.payload
        if payload is None or not payload.reference:
            continue
        if not payload.reference.startswith(INPUTS_REFERENCE):
            if row.source_event_id not in observed and len(payload.reference.encode()) <= 1024:
                candidates.append((row.source_frontier, payload.reference))
            continue
        target = payload.reference[len(INPUTS_REFERENCE) :]
        manifest_counts[target] = manifest_counts.get(target, 0) + 1
        try:
            raw: object = json.loads(payload.description or "")
            data = cast(dict[str, object], raw) if type(raw) is dict else {}
            if type(data) is not dict or set(data) != {"inputs", "outputs", "complete"}:
                continue
            if type(data["complete"]) is not bool:
                continue
            declared = _InputScope()
            outputs: set[str] = set()
            complete = data["complete"]
            for field_name in ("inputs", "outputs"):
                values = data[field_name]
                if type(values) is not list or len(cast(list[object], values)) > 128:
                    raise ValueError
                for value in cast(list[object], values):
                    if type(value) is not str or len(value.encode("utf-8")) > 1024:
                        raise ValueError
                    path = relative(value)
                    if (
                        path is not None
                        and (value.endswith("/") or path == ".")
                        and not path_beyond_workspace_fingerprint(
                            value, directory=True, workspace_root=root
                        )
                    ):
                        # A directory (named with a trailing slash): FinishUP cannot tell which
                        # of its files a change touched, so the declaration is partial and a
                        # change it may hold asks (#1167 review). A bare name reads as a file.
                        complete = False
                        if field_name == "inputs":
                            declared.directories.add(path)
                        continue
                    identity = None if path is None else verification_path_identity(path)
                    if (
                        identity is None
                        or field_name == "inputs"
                        and path_beyond_workspace_fingerprint(value, workspace_root=root)
                    ):
                        complete = False
                        if field_name == "inputs":
                            declared.unobservable = True
                    if identity is None or path is None:
                        continue
                    names[identity] = path
                    (declared.inputs if field_name == "inputs" else outputs).add(identity)
            if not declared.inputs and not declared.unobservable and not declared.directories:
                # A complete list naming no input is no evidence of what the check reads; it
                # never lets a later change pass as unrelated (#1167 review).
                complete = False
            manifests.setdefault(target, []).append((declared, outputs, complete))
        except (ValueError, TypeError):
            continue

    actions = {row.source_event_id: key for key, row in projection.actions.items()}
    annotations: dict[str, list[str]] = {}
    annotation_events: dict[EventId, set[EventId]] = {}
    positions = {record.event_id: record.ledger.ingestion_sequence for record in prefix}
    for record in prefix:
        if (
            not is_observation_authored(record)
            or type(record.payload) is not EvidenceRecordedPayload
        ):
            continue
        if workspace_effect_from_annotation(record.payload.description) is None:
            continue
        parents = {actions[parent] for parent in record.causal_parents if parent in actions}
        if len(parents) == 1 and record.payload.description is not None:
            parent_action = next(iter(parents))
            annotations.setdefault(parent_action, []).append(record.payload.description)
            action_event = projection.actions[parent_action].source_event_id
            annotation_events.setdefault(action_event, set()).add(record.event_id)

    # One change per host call at its result frontier, never the late annotation's frontier.
    # A trusted byte-identical shell write is kept as a no-op change: only a run with an input the
    # workspace comparison cannot see refuses the workspace-only proof.
    # (position, change event, keyed identities or None, exempt class, trusted no-op, what is
    # known about a change without identities: its kind and, for an edit tool, the tool name).
    changes: list[tuple[int, EventId, tuple[str, ...] | None, bool, bool, _Unplaced]] = []
    own_changes: dict[EventId, tuple[str, ...] | None] = {}
    completed: set[str] = set()
    runs: list[tuple[ResultId, int, EventId]] = []
    first_positions: dict[str, int] = {}
    run_scopes: dict[ResultId, tuple[_InputScope, str | None]] = {}
    for ref, row in sorted(projection.results.items(), key=lambda item: item[1].source_frontier):
        result = row.payload
        if result is None or row.source_event_id not in observed:
            continue
        action = projection.actions.get(result.action_id)
        if action is None or action.payload is None or action.source_event_id not in observed:
            continue
        completed.add(result.action_id)
        position = first_positions.setdefault(result.action_id, row.source_frontier)
        if action.payload.action_kind is ActionKind.COMMAND and (
            action.source_event_id in (requested_runs or ())
            or observed_action_runner_class(action.payload.description)
            in {"test", "lint", "typecheck", "build"}
        ):
            runs.append((ref, position, action.source_event_id))
            observed_run = observed_run_from_command(action.payload.command)
            matched = _InputScope()
            label: str | None = None
            for commands, scope in command_scopes:
                values = [
                    value
                    for value, command in commands
                    if observed_run is not None and planned_match(observed_run, command) is not None
                ]
                if not values:
                    continue
                label = label or values[0]
                matched.inputs |= scope.inputs
                matched.directories |= scope.directories
                matched.unobservable |= scope.unobservable
            run_scopes[ref] = (matched, label)
        descriptions = [result.summary or "", *annotations.get(result.action_id, ())]
        effects = [
            workspace_effect_from_result_summary(descriptions[0]),
            *(workspace_effect_from_annotation(text) for text in descriptions[1:]),
        ]
        entries: set[str] = set()
        comparison_known = False
        comparison_unknown = False
        exempt_change = True
        for text, effect in zip(descriptions, effects, strict=True):
            if effect == "changed":
                identities = workspace_entries_from_summary(text)
                comparison_unknown |= identities is None
                entries.update(identities or ())
                comparison_known = True
                scopes = workspace_write_scopes_from_summary(text)
                exempt_change &= scopes is not None and all(
                    f"write {scope}" in exempt | stale_exempt for scope in scopes
                )
            elif effect == "unavailable":
                comparison_unknown = True
                exempt_change = False
        if comparison_known or comparison_unknown:
            identities = None if comparison_unknown else tuple(sorted(entries))
            own_changes[action.source_event_id] = identities
            changes.append(
                (
                    position,
                    action.source_event_id,
                    identities,
                    exempt_change,
                    False,
                    _Unplaced(
                        "comparison_unavailable"
                        if any(effect == "unavailable" for effect in effects)
                        else "comparison_incomplete"
                    ),
                )
            )
        else:
            description = action.payload.description
            writes = (
                action.payload.action_kind is ActionKind.EDIT
                and result.outcome is not ResultOutcome.FAILURE
                or observed_shell_write_counts(description, exempt)
            )
            if writes and observed_edit_counts(description, exempt):
                changes.append(
                    (
                        position,
                        action.source_event_id,
                        None,
                        not observed_write_stales_verification(description, stale_exempt),
                        result.action_id in unchanged,
                        _unplaced_action(action.payload.action_kind, description),
                    )
                )
    for ref, row in projection.actions.items():
        payload = row.payload
        if payload is None or ref in completed or row.source_event_id not in observed:
            continue
        if payload.action_kind is ActionKind.EDIT or observed_shell_write_counts(
            payload.description, exempt
        ):
            if observed_edit_counts(payload.description, exempt):
                changes.append(
                    (
                        row.source_frontier,
                        row.source_event_id,
                        None,
                        not observed_write_stales_verification(payload.description, stale_exempt),
                        False,
                        _unplaced_action(payload.action_kind, payload.description),
                    )
                )

    # An agent-published evidence reference can name a changed path only through an exact keyed
    # identity match. Hash the bounded, latest candidates only when an unnamed identity exists.
    if any(
        identity not in names
        for _, _, identities, _, _, _ in changes
        for identity in identities or ()
    ):
        for _, reference in sorted(candidates)[-_MAX_NAME_CANDIDATES:]:
            if "://" in reference:
                continue
            path = relative(reference)
            identity = None if path is None else verification_path_identity(path)
            if identity is not None and path is not None:
                names.setdefault(identity, path)

    # Repeated runs of the same command do not grow the derived packet quadratically. Keep
    # the latest run and any older run the account still cites; history itself is retained.
    cited: set[str] = set()
    for row in projection.claims.values():
        if row.payload is not None:
            cited.update(row.payload.supporting_refs)
            if type(row.payload) is ClaimRecordedPayloadV1_1:
                cited.update(row.payload.limitation_refs)
    for row in projection.obligations.values():
        if row.payload is not None:
            cited.update(row.payload.resolution_evidence_refs)
    for row in projection.responses.values():
        if row.payload is not None:
            cited.update(row.payload.evidence_refs)
    latest: dict[str, tuple[int, int, ResultId]] = {}
    for run_ref, run_position, _ in runs:
        result = projection.results[run_ref].payload
        assert result is not None
        action = projection.actions[result.action_id].payload
        assert action is not None
        identity = command_identity(action.command) or run_ref
        choice = (run_position, projection.results[run_ref].source_frontier, run_ref)
        if identity not in latest or choice > latest[identity]:
            latest[identity] = choice
        if cited.intersection(result.evidence_refs):
            cited.add(run_ref)
    retained = {choice[2] for choice in latest.values()} | cited
    output: list[VerificationFreshness] = []
    for run_ref, position, run_event in runs:
        if run_ref not in retained:
            continue
        matched, label = run_scopes.get(run_ref, (_InputScope(), None))
        known_inputs = set(matched.inputs)
        outputs: set[str] = set()
        declarations = manifests.get(run_ref, [])
        declared = manifest_counts.get(run_ref) == 1 and len(declarations) == 1
        complete = declared and declarations[0][2]
        unobservable = matched.unobservable
        directories = set(matched.directories)
        if declared:
            declared_scope, declared_outputs, _ = declarations[0]
            known_inputs |= declared_scope.inputs
            outputs |= declared_outputs
            unobservable |= declared_scope.unobservable
            directories |= declared_scope.directories
        if not complete:
            # Task-level inputs no command scopes: a complete per-run declaration is the
            # caller's statement of what this run reads; any other run may read them.
            directories |= unscoped.directories
            unobservable |= unscoped.unobservable
        # An output exemption covers only bytes the verification itself produced: the run's own
        # trusted comparison changed that path. A declared output the run never wrote (such as a
        # pre-existing source file) does not make its later edits unrelated.
        produced = (outputs & set(own_changes.get(run_event) or ())) - known_inputs
        basis = (
            "complete"
            if complete
            else "declared"
            if declared
            else "requested"
            if matched.inputs or matched.directories or matched.unobservable
            else "undeclared"
        )

        stale_names: set[str] = set()
        unknown_names: set[str] = set()
        unknown_unnamed: set[str] = set()
        asserted_names: set[str] = set()
        asserted_unnamed: set[str] = set()
        unplaced_stale: dict[str, tuple[int, frozenset[str]]] = {}
        unplaced_unknown: dict[str, tuple[int, frozenset[str]]] = {}
        opaque_reason = False
        refs: set[EventId] = set()
        state = "current"
        for changed_at, event, identities, exempt_change, noop, unplaced in changes:
            if changed_at <= position or (noop and not unobservable):
                continue
            hits = set(identities or ()) & known_inputs
            if hits:
                state = "stale"
                stale_names.update(names[identity] for identity in hits)
            elif identities is None and not exempt_change:
                # FinishUP cannot place this change: it has no trusted keyed identity set (a host
                # edit-tool edit, a shell write without a trusted comparison, an unavailable or
                # incomplete comparison, or a no-op proof that cannot cover an input outside the
                # comparison). It may be a deliverable-source edit, which is an input, so the
                # verification stays stale as before #1143; the summary says what is known.
                state = "stale"
                _count_unplaced(unplaced_stale, _NOOP_UNOBSERVABLE if noop else unplaced)
            else:
                opaque = _may_hold_input(identities, names, directories, unobservable)
                if not opaque and (
                    exempt_change
                    and (not known_inputs or identities is not None)
                    or identities is not None
                    and set(identities) <= produced
                ):
                    continue
                if not opaque and identities is not None and complete:
                    for identity in identities:
                        if identity in names:
                            asserted_names.add(names[identity])
                        else:
                            asserted_unnamed.add(identity)
                else:
                    if state != "stale":
                        state = "unknown"
                    opaque_reason |= opaque
                    for identity in identities or ():
                        if identity in names:
                            unknown_names.add(names[identity])
                        else:
                            unknown_unnamed.add(identity)
                    if identities is None:
                        _count_unplaced(unplaced_unknown, _NOOP_UNOBSERVABLE if noop else unplaced)
            refs.add(event)
            refs.update(annotation_events.get(event, ()))
        if not refs:
            continue
        summaries = [
            *(
                f"{quoted_path(name)} changed: a recorded verification input"
                for name in sorted(stale_names)
            ),
            *_unplaced_summaries(unplaced_stale),
            *(f"{quoted_path(name)} added, removed or modified" for name in sorted(unknown_names)),
            *(
                [
                    f"{len(unknown_unnamed)} changed workspace path(s) not named anywhere in the"
                    " task record (only keyed identities were observed)"
                ]
                if unknown_unnamed
                else []
            ),
            *_unplaced_summaries(unplaced_unknown),
            *(
                [
                    (
                        "a verification input lies outside what the workspace comparison covers"
                        if unobservable
                        else "a requested input directory may contain the changed path"
                    )
                ]
                if opaque_reason
                else []
            ),
            *(
                f"{quoted_path(name)} changed outside the caller-asserted complete input list"
                for name in sorted(asserted_names)
            ),
            *(
                [
                    f"{len(asserted_unnamed)} unnamed changed path(s) outside the caller-asserted"
                    " complete input list"
                ]
                if asserted_unnamed
                else []
            ),
        ]
        if len(summaries) > 16:
            summaries = [*summaries[:15], f"{len(summaries) - 15} more change summaries omitted"]
        output.append(
            VerificationFreshness(
                run_ref,
                state,
                tuple(summaries),
                tuple(
                    sorted(
                        sorted(refs, key=lambda ref: positions.get(ref, 0))[-16:],
                        key=str.encode,
                    )
                ),
                basis,
                label if label is None or len(label.encode("utf-8")) <= _MAX_LABEL_BYTES else None,
                bool(asserted_names or asserted_unnamed),
            )
        )
    return tuple(output)
