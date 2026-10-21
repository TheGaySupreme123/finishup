"""Input-aware freshness from recorded declarations and trusted workspace comparisons (#1143).

An input declaration is evidence of what the agent says the check reads, not a syscall trace.
Unrecorded dependencies, missing comparisons, opaque directories and old observations ask for a
decision instead of asserting that a rerun is required. No command-text heuristic proves a read.
Every input scope is per verification: a requested input applies to the runs of the command its
obligation requests, and a per-run declaration applies to that one run.
"""

from __future__ import annotations

import json
import posixpath
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Final, cast

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
    observed_edit_counts,
    observed_shell_write_counts,
    observed_write_stales_verification,
)
from finishup.kernel.projections import ProjectionState
from finishup.protocol.canonical import JsonValue

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

    ``state`` is ``stale`` (a recorded input changed), ``unknown`` (a later change may touch an
    input FinishUP cannot rule out) or ``current``. A ``current`` row exists only to disclose that
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
    unchanged: frozenset[ActionId] = verification_unchanged_actions(projection, prefix)
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
            if not declared.inputs and not declared.unobservable:
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
    changes: list[tuple[int, EventId, tuple[str, ...] | None, bool, bool]] = []
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
            changes.append((position, action.source_event_id, identities, exempt_change, False))
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
                    )
                )

    # An agent-published evidence reference can name a changed path only through an exact keyed
    # identity match. Hash the bounded, latest candidates only when an unnamed identity exists.
    if any(
        identity not in names for _, _, identities, _, _ in changes for identity in identities or ()
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
        unobserved = False
        noop_unobservable = False
        opaque_reason = False
        refs: set[EventId] = set()
        state = "current"
        for changed_at, event, identities, exempt_change, noop in changes:
            if changed_at <= position or (noop and not unobservable):
                continue
            hits = set(identities or ()) & known_inputs
            if hits:
                state = "stale"
                stale_names.update(names[identity] for identity in hits)
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
                        if noop:
                            noop_unobservable = True
                        else:
                            unobserved = True
            refs.add(event)
            refs.update(annotation_events.get(event, ()))
        if not refs:
            continue
        summaries = [
            *(
                f"{quoted_path(name)} changed: a recorded verification input"
                for name in sorted(stale_names)
            ),
            *(f"{quoted_path(name)} added, removed or modified" for name in sorted(unknown_names)),
            *(
                [
                    f"{len(unknown_unnamed)} changed workspace path(s) not named anywhere in the"
                    " task record (only keyed identities were observed)"
                ]
                if unknown_unnamed
                else []
            ),
            *(
                ["paths unavailable: a later workspace change was not fully observed"]
                if unobserved
                else []
            ),
            *(
                [
                    "the workspace comparison saw no change, but a verification input lies outside"
                    " what it compares"
                ]
                if noop_unobservable
                else []
            ),
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
