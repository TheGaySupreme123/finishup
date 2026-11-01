"""Selector-only read usage in encrypted attempt responses and owner-local metrics (#1173).

These rows are private payload, never structural accounting or public result leaves. Metrics
callers must already hold the owner's unlocked object store; this module opens no authority lane.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from finishup.adapters.providers.reviewer_reply import ReviewerReplyInvalid, decode_reviewer_reply
from finishup.domain.reviewer_reads import MAX_REVIEWER_READ_ATTEMPTS
from finishup.ports.ledger import SemanticAttemptRecord
from finishup.ports.objects import ObjectKind, ObjectStorePort
from finishup.ports.semantic import SemanticJudgment
from finishup.protocol.canonical import JsonValue, strict_json_parse

_FIELDS = frozenset({"call", "action", "args", "status", "reason"})
_REASONS = frozenset(
    {
        "forbidden_path",
        "outside_scope",
        "not_recorded",
        "unsupported_type",
        "invalid_request",
        "source_changed",
        "not_in_frozen_case",
        "not_retained",
        "byte_budget",
        "inspection_limit",
        "native_read_limit",
        "privacy_withheld",
        "authorization_changed",
        "outcome_unknown",
        "deadline",
    }
)


def read_usage_from_wire(value: object) -> tuple[Mapping[str, JsonValue], ...] | None:
    """Validate selector-only rows; missing older telemetry stays unknown, never invented."""
    if not isinstance(value, (list, tuple)):
        return None
    supplied = cast(Sequence[object], value)
    if len(supplied) > MAX_REVIEWER_READ_ATTEMPTS:
        return None
    rows: list[Mapping[str, JsonValue]] = []
    for ordinal, raw in enumerate(supplied, 1):
        if not isinstance(raw, dict) or frozenset(cast(dict[str, object], raw)) != _FIELDS:
            return None
        row = cast(dict[str, JsonValue], raw)
        if type(row["call"]) is not int or row["call"] != ordinal:
            return None
        if row["status"] not in ("ok", "partial", "unavailable", "denied", "stale"):
            return None
        reason = row["reason"]
        if reason is not None and (not isinstance(reason, str) or reason not in _REASONS):
            return None
        try:
            action = decode_reviewer_reply(
                {"reply": {"action": row["action"], "args": row["args"]}}
            )
        except ReviewerReplyInvalid:
            return None
        if isinstance(action, SemanticJudgment):
            return None
        rows.append(
            {
                "call": ordinal,
                **action.model_dump(mode="json"),
                "status": row["status"],
                "reason": reason,
            }
        )
    return tuple(rows)


async def export_reviewer_read_metrics(
    attempts: Sequence[SemanticAttemptRecord], objects: ObjectStorePort
) -> dict[str, JsonValue]:
    """Join every physical attempt to its private selector/result usage for owner-local metrics.

    No packet, judgment, read content, hint or provider text enters the export. Missing or invalid
    response objects yield null usage. An older export cannot retroactively recover selectors.
    """
    rows: list[JsonValue] = []
    for attempt in sorted(attempts, key=lambda a: a.attempt_ordinal):
        usage = None
        ref = attempt.result_object_ref
        if ref is not None and ref.metadata.kind is ObjectKind.SEMANTIC_RESPONSE:
            try:
                resolved = await objects.resolve_verified(ref.object_id, ref.envelope_digest)
                payload = b"".join([chunk async for chunk in objects.open_verified(resolved)])
                body = strict_json_parse(payload)
                if (
                    isinstance(body, dict)
                    and body.get("schema") == "yoetz.semantic-response/1"
                    and body.get("attempt_id") == attempt.attempt_id
                ):
                    usage = read_usage_from_wire(body.get("reviewer_read_usage"))
            except (KeyError, OSError, TypeError, ValueError):
                pass
        rows.append(
            {
                "attempt_id": attempt.attempt_id,
                "attempt_ordinal": attempt.attempt_ordinal,
                "reviewer_reads": None if usage is None else [dict(row) for row in usage],
            }
        )
    return {"attempt_usages": rows}
