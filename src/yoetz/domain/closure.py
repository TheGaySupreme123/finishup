"""Shared read-only closure preparation over the privacy-projected status boundary."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import cast

from pydantic import ValidationError

from yoetz import __version__
from yoetz.domain.events import (
    OBLIGATION_SCHEMA_VERSION,
    EventSchema,
    ObligationPublishedPayload,
    decode_payload,
    obligation_schema_version,
)
from yoetz.domain.values import freeze_json
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    ClosureSelectionModel,
    PublishWorkRequest,
    ReceiptRequest,
    RespondRequest,
    StatusRequest,
    StatusResult,
    StatusSuccessModel,
    public_model_to_wire,
)
from yoetz.protocol.readiness_text import predicted_receipt_variants

__all__ = ["PREPARATION_REMEDIATIONS", "Selection", "prepare_closure", "recheck_note"]

PREPARATION_REMEDIATIONS = {
    "closure_status_unavailable": "Read status for this session and writer before preparing again.",
    "closure_snapshot_unavailable": "A complete pinned snapshot was unavailable. Read status and restart inventory.",
    "closure_pagination_invalid": "The cursor repeated. Keep the original query identity and inspect status.",
    "closure_inventory_limit": "The bounded inventory is incomplete; use paginated status without assuming closure.",
    "closure_result_too_large": "The complete inventory exceeds the MCP response bound. Select the ids you need from status pages and call closure_prepare with phase attempt, respond, resolve, claim or receipt (those responses carry only the selected rows), or use the CLI closure-prepare --output path; do not claim closure from an incomplete response.",
    "closure_obligation_unknown": "Select an obligation ID from the returned inventory.",
    "closure_evidence_unavailable": "Select available evidence ids (evd_) from the inventory in evidence_refs; result ids (res_) go in result_ids. Otherwise retain the missing-evidence limitation.",
    "closure_result_unavailable": "The selected result payload is unavailable; inspect results and retain its limitation.",
    "closure_attempt_selection_required": "Select one obligation, exact requested-item indexes, and an explicit action description.",
    "closure_item_unknown": "Select requested-item indexes from the current obligation.",
    "closure_item_omitted": "The requested value is withheld; do not reconstruct it or claim it was attempted.",
    "closure_command_revision_required": "Correct the attempt assertion or record the replacement command through a plan/obligation revision with rationale.",
    "closure_source_unknown": "Use a returned history event ID; do not invent observation provenance.",
    "closure_response_decision_required": "Select a finding and explicitly provide its disposition and reason. A receipt has different fields.",
    "closure_resolution_decision_required": "Select the obligations you assessed and their actual evidence or results.",
    "closure_obligation_not_open": "Remove the non-open obligation from the resolution selection.",
    "closure_unattempted_items": "Account for genuine attempts or revise the obligation; do not copy unchecked requested items.",
    "closure_obligation_content_unavailable": "The obligation's meaning fields are withheld; do not recreate them to resolve it.",
    "closure_claim_decision_required": "Supply the bounded completion assertion and explicitly select its obligations and support.",
    "closure_draft_invalid": "The prepared draft did not validate; nothing was recorded. Publish the change yourself with publish_work (obligation_published/1.1.0 accepts every obligation) and report this preparation failure.",
    "closure_output_unwritable": "Nothing was saved. Choose a writable file path in an existing directory and prepare again.",
    "closure_output_not_durable": "The file was replaced, but its directory could not be flushed to disk, so a crash may lose it. Prepare again, saving to a local disk.",
}

Selection = ClosureSelectionModel


def _base(
    session_id: str,
    writer_id: str,
    *,
    client_kind: str = "yoetz_cli",
    integration: str = "local_cli",
) -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "session_id": session_id,
        "writer_id": writer_id,
        "actor": {"actor_id": "harness:closure-composer", "actor_type": "harness"},
        "client": {"kind": client_kind, "version": __version__, "integration": integration},
    }


_RECHECK_PHRASES = {
    "acceptance": "the acceptance criteria of your resolved obligations",
    "acknowledgement": "obligations you recorded as not done",
    "blocker": "a blocker you recorded",
    "premise": "findings you acknowledged that the review says the task requires",
}


def recheck_note(readiness: object) -> str | None:
    """One sentence naming the re-checks the Stop gate will ask once (tb4n3 RC-8).

    ``closure_readiness.rechecks`` is the list status, this preparation and the Stop gate all
    read, so a preparation that says "nothing further" never precedes a gate for an item it did
    not name. ``None`` when the readiness announces none (or an older service sent no list).
    """

    raw = getattr(readiness, "rechecks", None)
    if not isinstance(raw, (tuple, list)):
        return None
    kinds: list[str] = []
    for entry in tuple(cast(tuple[object, ...], raw)):
        kind: object = (
            cast(dict[str, object], entry).get("kind")
            if isinstance(entry, dict)
            else getattr(entry, "kind", None)
        )
        if type(kind) is str and kind in _RECHECK_PHRASES and kind not in kinds:
            kinds.append(kind)
    if not kinds:
        return None
    named = "; ".join(_RECHECK_PHRASES[kind] for kind in kinds)
    return (
        "At Stop you will be asked once to re-read: "
        f"{named}. closure_readiness.rechecks lists each with its key."
    )


def scope_inventory_to_selection(
    inventory: dict[str, list[dict[str, JsonValue]]], selection: ClosureSelectionModel
) -> dict[str, JsonValue]:
    """Keep only the inventory rows a phase's selection names, and say what was left out.

    A draft phase already validated its selection against the whole pinned inventory, so echoing
    every row again only costs response bytes: at a long-run frontier (about 1,430 events) the
    full echo exceeded the MCP frame bound and the agent lost the draft it had just earned
    (tb4n3 formal-crypto S). ``scope`` records the per-view totals and how many rows are kept.
    """

    selected_findings: set[str] = set() if selection.finding_id is None else {selection.finding_id}
    wanted: dict[str, tuple[str, set[str]]] = {
        "obligations": ("obligation_id", set(selection.obligation_ids)),
        "results": ("result_id", set(selection.result_ids)),
        "evidence": ("evidence_id", set(selection.evidence_refs)),
        "findings": ("finding_id", selected_findings),
        "history": ("event_id", set(selection.observed_event_ids)),
    }
    scoped: dict[str, JsonValue] = {}
    totals: dict[str, JsonValue] = {}
    kept: dict[str, JsonValue] = {}
    for view, rows in inventory.items():
        key, ids = wanted[view]
        chosen = [
            row for row in rows if isinstance(row.get(key), str) and cast(str, row.get(key)) in ids
        ]
        scoped[view] = cast(JsonValue, chosen)
        totals[view] = str(len(rows))
        kept[view] = str(len(chosen))
    scoped["scope"] = {
        "mode": "selected_rows",
        "totals": totals,
        "kept": kept,
        "note": (
            "Only rows named by this selection are included. Read the status views, or prepare "
            "phase inventory, for every row."
        ),
    }
    return scoped


async def prepare_closure(
    status: Callable[[StatusRequest], Awaitable[StatusResult]],
    session_id: str,
    writer_id: str,
    selection: ClosureSelectionModel,
    *,
    client_kind: str = "yoetz_cli",
    integration: str = "local_cli",
    scope_to_selection: bool = False,
) -> dict[str, JsonValue]:
    """Pin and exhaust every input view, then produce at most one non-evidential request.

    ``scope_to_selection`` limits a draft phase's echoed inventory to the selected rows (the MCP
    path; the CLI keeps the complete inventory for its local ``--output`` file). Validation always
    runs against the complete pinned inventory.
    """

    base = _base(
        session_id,
        writer_id,
        client_kind=client_kind,
        integration=integration,
    )
    compact_request = StatusRequest.model_validate(
        {
            **base,
            "view": "compact",
            "limit": "10",
            "at_frontier": None,
            "cursor": None,
        }
    )
    compact = (await status(compact_request)).root
    if not isinstance(compact, StatusSuccessModel):
        raise ValueError("closure_status_unavailable")
    frontier = compact.subject_frontier.model_dump(mode="json")
    inventory: dict[str, list[dict[str, JsonValue]]] = {}
    for view in ("obligations", "results", "evidence", "findings", "history"):
        cursor = None
        seen: set[str] = set()
        items: list[dict[str, JsonValue]] = []
        for _ in range(100):
            query: dict[str, object] = {
                **base,
                "request_id": new_id(IdKind.REQUEST),
                "view": view,
                "limit": "100",
                "at_frontier": frontier["sequence"],
                "cursor": cursor,
            }
            if view in {"obligations", "findings"}:
                query["filter"] = {"include_resolved": True}
            elif view == "evidence":
                query["filter"] = {"include_unavailable": True}
            wrapped = await status(StatusRequest.model_validate(query))
            result = wrapped.root
            if (
                not isinstance(result, StatusSuccessModel)
                or result.subject_frontier != compact.subject_frontier
            ):
                raise ValueError("closure_snapshot_unavailable")
            wire = public_model_to_wire(wrapped)
            page = cast(dict[str, JsonValue], wire["page"])
            items.extend(cast(list[dict[str, JsonValue]], page["items"]))
            cursor = cast(str | None, page["next_cursor"])
            if cursor is None:
                break
            if cursor in seen:
                raise ValueError("closure_pagination_invalid")
            seen.add(cursor)
        else:
            raise ValueError("closure_inventory_limit")
        inventory[view] = items
    output: dict[str, JsonValue] = {
        "preparatory_only": True,
        "frontier": cast(JsonValue, frontier),
        "closure_readiness": cast(
            JsonValue, compact.closure_readiness.model_dump(mode="json", exclude_unset=True)
        ),
        "inventory": cast(JsonValue, inventory),
        "request": None,
        "notes": [
            "Nothing was published or judged. Review one phase and explicitly submit its request.",
            "After a committed write, prepare the next phase from its new frontier.",
            "Evidence availability is per item and each row names its publication_channel. "
            "Select IDs you published or captures a recorded result links to the claim.",
            "Requested-item accounting is asserted; command_attempts separately reports observed reconciliation.",
            "GitHub workflow evidence uses the API run id, never run_number; this tool does not manufacture it.",
        ],
    }
    announced = recheck_note(compact.closure_readiness)
    if announced is not None:
        cast(list[str], output["notes"]).append(announced)
    # The same predicted receipt conclusion every surface prints (owner decision Q1), appended
    # after the notes above and never edited into them.
    readiness_state = getattr(compact.closure_readiness, "state", None)
    predicted = predicted_receipt_variants(
        getattr(compact.closure_readiness, "predicted_receipt", None),
        state=readiness_state if type(readiness_state) is str else "ready",
    )
    if predicted:
        cast(list[str], output["notes"]).append(predicted[0])
    if selection.phase == "inventory":
        return output
    obligations = {cast(str, item["obligation_id"]): item for item in inventory["obligations"]}
    results = {cast(str, item["result_id"]): item for item in inventory["results"]}
    evidence = {cast(str, item["evidence_id"]): item for item in inventory["evidence"]}
    findings = {cast(str, item["finding_id"]): item for item in inventory["findings"]}
    for key in selection.obligation_ids:
        if key not in obligations:
            raise ValueError("closure_obligation_unknown")
    for key in selection.evidence_refs:
        if key not in evidence or evidence[key]["available"] is not True:
            raise ValueError("closure_evidence_unavailable")
    for key in selection.result_ids:
        if key not in results or results[key]["payload_available"] is not True:
            raise ValueError("closure_result_unavailable")
    request: dict[str, object] = {
        **base,
        "request_id": new_id(IdKind.REQUEST),
        "expected_frontier": frontier,
    }
    operation = "publish_work"
    drafts: list[dict[str, object]] = []

    def draft(name: str, payload: dict[str, object], *, version: str = "1.0.0") -> None:
        drafts.append(
            {
                "event_id": new_id(IdKind.EVENT),
                "schema": {"name": name, "version": version},
                "occurred_at": datetime.now(UTC)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z"),
                "causal_parents": sorted(set(selection.observed_event_ids))
                if name == "action_recorded"
                else [],
                "payload": payload,
                "artifact_refs": [],
                "evidence_refs": [],
            }
        )

    if selection.phase == "attempt":
        if (
            len(selection.obligation_ids) != 1
            or not selection.requested_item_indexes
            or not selection.description
        ):
            raise ValueError("closure_attempt_selection_required")
        obligation = obligations[selection.obligation_ids[0]]
        requested = cast(list[dict[str, JsonValue]], obligation["requested_items"])
        if any(index >= len(requested) for index in selection.requested_item_indexes):
            raise ValueError("closure_item_unknown")
        values = [requested[index]["value"] for index in selection.requested_item_indexes]
        if any(not isinstance(value, str) for value in values):
            raise ValueError("closure_item_omitted")
        for index in selection.requested_item_indexes:
            item = requested[index]
            if item["item_kind"] == "command" and (
                selection.action_kind != "command" or selection.command != item["value"]
            ):
                raise ValueError("closure_command_revision_required")
        history_ids = {cast(str, row["event_id"]) for row in inventory["history"]}
        if any(key not in history_ids for key in selection.observed_event_ids):
            raise ValueError("closure_source_unknown")
        payload: dict[str, object] = {
            "action_id": new_id(IdKind.ACTION),
            "action_kind": selection.action_kind,
            "description": selection.description,
            "attempted_items": sorted(set(cast(list[str], values))),
            "obligation_refs": list(selection.obligation_ids),
        }
        if selection.command is not None:
            payload["command"] = selection.command
        draft("action_recorded", payload)
    elif selection.phase == "respond":
        if (
            selection.finding_id not in findings
            or selection.disposition is None
            or not selection.reason
        ):
            raise ValueError("closure_response_decision_required")
        # The fully read snapshot contains the finding: bind the result frontier, never its tested input.
        request.update(
            {
                "finding_id": selection.finding_id,
                "finding_frontier": frontier,
                "disposition": selection.disposition,
                "reason": selection.reason,
                "evidence_refs": sorted(set((*selection.evidence_refs, *selection.result_ids))),
            }
        )
        if selection.disposition == "waived":
            request["waiver_scope"] = "finding_only"
        operation = "respond"
    elif selection.phase == "resolve":
        if not selection.obligation_ids or not (selection.evidence_refs or selection.result_ids):
            raise ValueError("closure_resolution_decision_required")
        for key in selection.obligation_ids:
            row = obligations[key]
            # acknowledged_not_done (#1002) is not resolved and may still be resolved.
            if row["status"] == "resolved":
                raise ValueError("closure_obligation_not_open")
            if row["unattempted_items"]:
                raise ValueError("closure_unattempted_items")
            if any(
                item["relation"] == "asserted_observed_mismatch"
                for item in cast(list[dict[str, JsonValue]], row.get("command_attempts", []))
            ):
                raise ValueError("closure_command_revision_required")
            if any(
                not isinstance(row[name], str) for name in ("description", "evidence_expectation")
            ):
                raise ValueError("closure_obligation_content_unavailable")
            payload = {
                name: row[name]
                for name in (
                    "obligation_id",
                    "description",
                    "evidence_expectation",
                    "source_refs",
                    "requested_items",
                )
            }
            if row.get("acceptance_criteria") is not None:
                payload["acceptance_criteria"] = row["acceptance_criteria"]
            payload.update(
                {
                    "status": "resolved",
                    "resolution_evidence_refs": sorted(
                        set((*selection.evidence_refs, *selection.result_ids))
                    ),
                }
            )
            # One version rule for every obligation draft (issue #1023): a role, directory item
            # or acknowledgement needs 1.1.0; a plain obligation keeps its 1.0.0 bytes.
            draft("obligation_published", payload, version=_obligation_draft_version(payload))
    elif selection.phase == "claim":
        if not selection.description or not selection.obligation_ids:
            raise ValueError("closure_claim_decision_required")
        support = list(selection.evidence_refs)
        limits: list[str] = []
        for key in selection.result_ids:
            (support if results[key]["outcome"] == "success" else limits).append(key)
        draft(
            "claim_recorded",
            {
                "claim_id": new_id(IdKind.CLAIM),
                "claim_kind": "completion",
                "statement": selection.description,
                "obligation_refs": sorted(set(selection.obligation_ids)),
                "supporting_refs": sorted(set(support)),
                "limitation_refs": sorted(set(limits)),
                "supersedes_claim_refs": sorted(set(selection.supersedes_claim_refs)),
            },
            version="1.1.0",
        )
    elif selection.phase == "receipt":
        operation = "receipt"
        request.update(
            {
                "task_id": compact.task_id,
                "format": selection.format,
                "include": "standard",
                "redaction_profile": "default_local_export",
            }
        )
    try:
        if operation == "publish_work":
            request.update({"event_drafts": drafts, "dry_run": True})
            validated = public_model_to_wire(PublishWorkRequest.model_validate(request))
        elif operation == "respond":
            validated = public_model_to_wire(RespondRequest.model_validate(request))
        else:
            validated = public_model_to_wire(ReceiptRequest.model_validate(request))
    except ValidationError as exc:
        # A draft this composer built that its own request model refuses is a preparation
        # defect, never an internal error the agent cannot act on (tb4n2 retro S, N2-2).
        raise ValueError("closure_draft_invalid") from exc
    output["operation"] = operation
    output["request"] = validated
    recovery = StatusRequest.model_validate(
        {
            **_base(
                session_id,
                writer_id,
                client_kind=client_kind,
                integration=integration,
            ),
            "view": "operation",
            "limit": "10",
            "at_frontier": None,
            "cursor": None,
            "filter": {"operation_request_id": request["request_id"]},
        }
    )
    output["recovery_request"] = public_model_to_wire(recovery)
    output["recovery"] = (
        "After timeout, inspect this operation: absent permits replay; pending keeps the same request; committed uses its stored result. Never regenerate the request identity."
    )
    if scope_to_selection:
        output["inventory"] = scope_inventory_to_selection(inventory, selection)
    return output


def _obligation_draft_version(payload: dict[str, object]) -> str:
    """The ``obligation_published`` version for a resolve draft, by the shared rule.

    The payload is read with the 1.1.0 codec (a superset), then ``obligation_schema_version``
    picks 1.1.0 only for a payload that needs it. A payload the codec refuses is a draft defect.
    """

    try:
        decoded = decode_payload(
            EventSchema("obligation_published", OBLIGATION_SCHEMA_VERSION),
            freeze_json(cast(JsonValue, payload)),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("closure_draft_invalid") from exc
    if type(decoded) is not ObligationPublishedPayload:
        raise ValueError("closure_draft_invalid")
    return obligation_schema_version(decoded)
