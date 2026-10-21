"""Input-aware freshness from recorded declarations and trusted workspace comparisons (#1143).

An input declaration is evidence of what the agent says the check reads, not a syscall trace.
Unrecorded dependencies, missing comparisons, opaque directories and old observations ask for a
decision instead of asserting that a rerun is required. No command-text heuristic proves a read.
"""

from __future__ import annotations

import json
import posixpath
from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

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
FRESHNESS_FACT = "verification_freshness_question"


@dataclass(frozen=True, slots=True)
class VerificationFreshness:
    run_ref: ResultId
    state: str
    changes: tuple[str, ...]
    change_refs: tuple[EventId, ...]

    def __post_init__(self) -> None:
        result_id(self.run_ref)
        if (
            self.state not in {"current", "stale", "unknown"}
            or len(self.changes) > 16
            or len(self.change_refs) > 16
        ):
            raise ValueError("verification_freshness_invalid")
        if any(type(text) is not str or len(text.encode("utf-8")) > 2048 for text in self.changes):
            raise ValueError("verification_freshness_invalid")
        if type(self.changes) is not tuple or type(self.change_refs) is not tuple:
            raise ValueError("verification_freshness_invalid")
        if self.change_refs != tuple(sorted(set(self.change_refs), key=str.encode)):
            raise ValueError("verification_freshness_invalid")
        for ref in self.change_refs:
            event_id(ref)

    def to_json(self) -> list[JsonValue]:
        return cast(
            list[JsonValue], [self.run_ref, self.state, list(self.changes), list(self.change_refs)]
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
            if root is None or not path.startswith(root.rstrip("/") + "/"):
                return None
            path = path[len(root.rstrip("/")) + 1 :]
        return None if path == ".." or path.startswith("../") else path

    names: dict[str, str] = {}
    command_scopes: list[tuple[tuple[PlannedCommand, ...], set[str]]] = []
    run_inputs: dict[ResultId, set[str]] = {}
    opaque_inputs = False
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        scoped_inputs: set[str] = set()
        for item in payload.requested_items:
            if item.item_kind not in {RequestedItemKind.FILE, RequestedItemKind.DIRECTORY}:
                continue
            path = relative(item.value)
            if item.role is RequestedItemRole.INPUT:
                opaque_inputs |= path is None or path_beyond_workspace_fingerprint(
                    item.value,
                    directory=item.item_kind is RequestedItemKind.DIRECTORY,
                    workspace_root=root,
                )
                if item.item_kind is RequestedItemKind.DIRECTORY:
                    opaque_inputs = True
            if item.item_kind is RequestedItemKind.DIRECTORY:
                continue
            identity = None if path is None else verification_path_identity(path)
            if identity is not None:
                names[identity] = path  # type: ignore[assignment]
                if item.role is RequestedItemRole.INPUT:
                    scoped_inputs.add(identity)
        commands = tuple(
            command
            for item in payload.requested_items
            if item.item_kind is RequestedItemKind.COMMAND
            and (command := requested_planned_command(item.value)) is not None
        )
        if commands:
            command_scopes.append((commands, scoped_inputs))

    # Manifest evidence refers to ONE actual observed run, so a rerun needs its own declaration.
    # Unknown fields, malformed/truncated payloads and conflicting declarations never grant
    # completeness. They fall back to asking. Declarations are disclosed as agent assertions.
    manifests: dict[str, list[tuple[set[str], set[str], bool]]] = {}
    manifest_counts: dict[str, int] = {}
    opaque_manifest_input = False
    for row in projection.evidence.values():
        payload = row.payload
        if (
            payload is None
            or not payload.reference
            or not payload.reference.startswith(INPUTS_REFERENCE)
        ):
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
            groups: list[set[str]] = []
            complete = data["complete"]
            for field in ("inputs", "outputs"):
                values = data[field]
                if type(values) is not list or len(cast(list[object], values)) > 128:
                    raise ValueError
                group: set[str] = set()
                for value in cast(list[object], values):
                    if type(value) is not str or len(value.encode("utf-8")) > 1024:
                        raise ValueError
                    path = relative(value)
                    identity = None if path is None else verification_path_identity(path)
                    if (
                        identity is None
                        or field == "inputs"
                        and path_beyond_workspace_fingerprint(value, workspace_root=root)
                    ):
                        complete = False
                        if field == "inputs":
                            opaque_manifest_input = True
                    if identity is None:
                        continue
                    else:
                        names[identity] = path  # type: ignore[assignment]
                        group.add(identity)
                groups.append(group)
            manifests.setdefault(payload.reference[len(INPUTS_REFERENCE) :], []).append(
                (groups[0], groups[1], complete)
            )
        except (ValueError, TypeError):
            continue

    if opaque_manifest_input:
        # Like requested inputs outside the walk, a per-run opaque input cannot borrow the
        # workspace-only no-op exemption. Missing scope asks; it never asserts a changed input.
        unchanged = frozenset()

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
    changes: list[tuple[int, EventId, tuple[str, ...] | None, bool]] = []
    completed: set[str] = set()
    runs: list[tuple[ResultId, int]] = []
    first_positions: dict[str, int] = {}
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
            runs.append((ref, position))
            observed_run = observed_run_from_command(action.payload.command)
            run_inputs[ref] = set().union(
                *(
                    scoped
                    for commands, scoped in command_scopes
                    if observed_run is not None
                    and any(
                        planned_match(observed_run, command) is not None for command in commands
                    )
                )
            )
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
            changes.append(
                (
                    position,
                    action.source_event_id,
                    None if comparison_unknown else tuple(sorted(entries)),
                    exempt_change,
                )
            )
        elif result.action_id not in unchanged:
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
                    )
                )

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
    for run_ref, run_position in runs:
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
    for run_ref, position in runs:
        if run_ref not in retained:
            continue
        known_inputs = set(run_inputs.get(run_ref, ()))
        outputs: set[str] = set()
        declarations = manifests.get(run_ref, [])
        complete = (
            not opaque_inputs
            and manifest_counts.get(run_ref) == 1
            and len(declarations) == 1
            and declarations[0][2]
        )
        for declared_inputs, declared_outputs, _ in declarations:
            if manifest_counts.get(run_ref) == 1:
                known_inputs.update(declared_inputs)
                outputs.update(declared_outputs)
        summaries: list[str] = []
        refs: set[EventId] = set()
        state = "current"
        for changed_at, event, identities, exempt_change in changes:
            if changed_at <= position:
                continue
            hits = set(identities or ()) & known_inputs
            if hits:
                state = "stale"
                summaries.extend(
                    f"{names[identity]}: verification input changed" for identity in sorted(hits)
                )
            elif (
                exempt_change
                and not opaque_inputs
                and (not known_inputs or identities is not None)
                or (
                    identities is not None
                    and (complete or not opaque_inputs and set(identities) <= outputs)
                )
            ):
                continue
            else:
                if state != "stale":
                    state = "unknown"
                summaries.extend(
                    f"{names.get(identity, 'path unavailable')}: added, removed or modified"
                    for identity in identities or ()
                )
                if identities is None:
                    summaries.append("paths unavailable: workspace change not fully observed")
            refs.add(event)
            refs.update(annotation_events.get(event, ()))
        if refs:
            unique_summaries = list(dict.fromkeys(summaries))
            if state == "stale":
                unique_summaries.sort(key=lambda text: "verification input changed" not in text)
            if len(unique_summaries) > 16:
                unique_summaries = unique_summaries[:15] + [
                    f"{len(unique_summaries) - 15} more change summaries omitted"
                ]
            output.append(
                VerificationFreshness(
                    run_ref,
                    state,
                    tuple(unique_summaries),
                    tuple(
                        sorted(
                            sorted(refs, key=lambda ref: positions.get(ref, 0))[-16:],
                            key=str.encode,
                        )
                    ),
                )
            )
    return tuple(output)
