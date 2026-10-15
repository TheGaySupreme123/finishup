"""Pure capacity-change disclosure shared by every owner surface (#828).

A larger observation capacity costs local disk, memory, and CPU; a request for
no FinishUP cap is not supported by the structural queue in this storage
revision.  :func:`capacity_change_disclosure` builds one deterministic record
of closed tokens and integers for a proposed change, and
:func:`render_capacity_disclosure_lines` is the single human wording used by
the CLI and the terminal interface.  Neither function performs I/O, and no
user-controlled text is ever carried into the record or the rendered lines:
every command names the ``<workspace>`` and ``<session-id>`` placeholders
rather than echoing a caller's argument.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final, Literal, TypeGuard, cast

from finishup.domain.observation_budget import (
    BUDGET_VALIDATION_STATUS,
    STANDARD_CAPACITY,
    STATE_DOCUMENT_CEILING_BYTES,
    STRUCTURAL_QUEUE_DIMENSION,
    BudgetLimits,
    CapacityRequest,
    ObservationCapacity,
    ObservationMode,
    no_cap_support,
)
from finishup.domain.values import JsonObject
from finishup.legacy_names import LAUNCHER_NAME

__all__ = [
    "CAPACITY_DISCLOSURE_SCHEMA",
    "SESSION_PLACEHOLDER",
    "WORKSPACE_PLACEHOLDER",
    "CapacityChange",
    "CapacityScope",
    "canonical_safe_command",
    "capacity_change_disclosure",
    "is_closed_token",
    "is_safe_command",
    "render_capacity_disclosure_lines",
    "scope_flag",
]

# Frozen legacy identifier (ADR-048): the stored disclosure record tag.
CAPACITY_DISCLOSURE_SCHEMA: Final = "yoetz.capacity-change-disclosure/1"

type CapacityScope = Literal["session", "workspace"]
type CapacityChange = Literal["increase", "decrease", "unchanged", "unsupported"]

_CONSEQUENCES: Final[dict[CapacityChange, tuple[str, ...]]] = {
    "increase": (
        "disk_use",
        "memory_use",
        "cpu_work",
        "host_slowdown_possible",
        "workspace_aggregate_raised",
    ),
    "decrease": ("future_admission_only", "accepted_records_drain"),
    "unchanged": (),
    "unsupported": ("state_document_ceiling",),
}
_AUTHORITY_UNCHANGED: Final = ("content", "privacy", "provider", "credential", "network")
_ORIGINS: Final = frozenset({"session", "workspace", "configured", "default"})
_LABELS: Final = frozenset({"standard", "larger", "largest", "custom"})
WORKSPACE_PLACEHOLDER: Final = "<workspace>"
SESSION_PLACEHOLDER: Final = "<session-id>"
_PREVIEW_DIGEST_PLACEHOLDER: Final = "<preview-digest>"
# Command arguments are relayed verbatim to owners and agents.  Only bounded
# placeholders and plain identifier/path characters are allowed, and the first
# character can never be ``-``, so an argument cannot read as a flag; anything
# else falls back to the placeholder instead of echoing caller text.
_SAFE_ARGUMENT: Final = re.compile(r"^[A-Za-z0-9_.~/<][A-Za-z0-9_.:/~<>@+-]{0,255}$", re.ASCII)
# A record written before the rename names the legacy launcher, so either head is safe; it is
# rendered with the current launcher (ADR-048).
_SAFE_COMMAND: Final = re.compile(r"^(finishup|yoetz) ([A-Za-z0-9_.:/~<>@+ -]{1,1024})$", re.ASCII)
# A compound command joins its steps with `` then `` (``lower_command``), and a record written
# before the rename names the legacy launcher at the head of every step (ADR-048).
_LEGACY_STEP_HEAD: Final = re.compile(r"(?<= then )yoetz(?= )", re.ASCII)
_TOKEN: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
_KIB: Final = 1024
_MIB: Final = 1024 * 1024


class _DisclosureError(ValueError):
    def __init__(self) -> None:
        super().__init__("capacity_disclosure_invalid")


def is_safe_command(text: object) -> TypeGuard[str]:
    """Return whether ``text`` is a ``finishup`` command built only from safe characters.

    The legacy ``yoetz`` head of a record written before the rename is accepted too (ADR-048).
    """

    return type(text) is str and _SAFE_COMMAND.fullmatch(text) is not None


def canonical_safe_command(text: object) -> str | None:
    """Return a safe command spelled with the current launcher, or ``None`` when unsafe.

    A legacy ``yoetz`` head is rewritten to ``finishup`` so owner-facing text never points at
    the pre-rename launcher (ADR-048). That holds for every step of a compound command, whose
    later steps follow the `` then `` joiner; the arguments are already closed-shape and kept.
    """

    if type(text) is not str:
        return None
    match = _SAFE_COMMAND.fullmatch(text)
    if match is None:
        return None
    return f"{LAUNCHER_NAME} {_LEGACY_STEP_HEAD.sub(LAUNCHER_NAME, match.group(2))}"


def is_closed_token(text: object) -> TypeGuard[str]:
    """Return whether ``text`` is a closed lower-snake token safe to echo."""

    return type(text) is str and _TOKEN.fullmatch(text) is not None


def scope_flag(scope: CapacityScope, session_argument: str | None = None) -> str:
    """Return the command flag for ``scope``: ``--persist`` or ``--session-id <id>``.

    ``session_argument`` is used only when it is a safe argument; otherwise,
    and by default, the ``<session-id>`` placeholder is named.
    """

    if scope == "workspace":
        return "--persist"
    session = (
        session_argument
        if type(session_argument) is str and _SAFE_ARGUMENT.fullmatch(session_argument)
        else SESSION_PLACEHOLDER
    )
    return f"--session-id {session}"


def _capacity_record(capacity: ObservationCapacity) -> JsonObject:
    limits = BudgetLimits.for_capacity(capacity)
    return JsonObject(
        {
            "queue_count": capacity.queue_count,
            "label": capacity.label,
            "queue_bytes_limit": limits.queue_bytes,
            "state_bytes_limit": limits.state_bytes,
        }
    )


def capacity_change_disclosure(
    *,
    current: ObservationCapacity,
    current_origin: str,
    requested: CapacityRequest,
    scope: Literal["session", "workspace"],
    detail: ObservationMode = ObservationMode.FOCUSED,
) -> JsonObject:
    """Return the deterministic disclosure record for one capacity request.

    ``current`` is the capacity currently selected at ``scope`` (with its
    resolution ``current_origin``), ``detail`` the detail mode the lowering
    command must preserve.  A ``no_cap`` request yields ``change`` =
    ``unsupported`` with ``requested`` = ``None``.
    """

    if type(current) is not ObservationCapacity:
        raise _DisclosureError()
    if type(requested) is not CapacityRequest:
        raise _DisclosureError()
    if current_origin not in _ORIGINS:
        raise _DisclosureError()
    if scope not in ("session", "workspace"):
        raise _DisclosureError()
    mode = ObservationMode.from_value(detail)
    workspace = WORKSPACE_PLACEHOLDER
    flag = scope_flag(scope)

    change: CapacityChange
    target = requested.capacity
    if target is None:
        change = "unsupported"
    elif target.queue_count > current.queue_count:
        change = "increase"
    elif target.queue_count < current.queue_count:
        change = "decrease"
    else:
        change = "unchanged"
    fair_share_limits = BudgetLimits.for_capacity(current if target is None else target)
    # "Lower it later" must undo an increase, so it restores the current
    # capacity; every other change points back at the recommended default.
    restore = current if change == "increase" else STANDARD_CAPACITY
    restore_arguments = (
        f"--capacity {restore.label}"
        if restore.profile is not None
        else f"--capacity custom --queue-count {restore.queue_count}"
    )
    selection_arguments = (
        f"--workspace {workspace} --detail {mode.value} {restore_arguments} {flag}"
    )
    lower_command = (
        f"finishup observe selection-preview {selection_arguments} then "
        f"finishup observe selection-apply {selection_arguments} "
        f"--accept --preview-digest {_PREVIEW_DIGEST_PLACEHOLDER}"
    )
    return JsonObject(
        {
            "schema": CAPACITY_DISCLOSURE_SCHEMA,
            "dimension": STRUCTURAL_QUEUE_DIMENSION,
            "scope": scope,
            "change": change,
            "current_origin": current_origin,
            "current": _capacity_record(current),
            "requested": None if target is None else _capacity_record(target),
            "consequences": _CONSEQUENCES[change],
            "remaining_limits": {
                "pending_attempts": fair_share_limits.pending_attempts,
                "capture_tickets": fair_share_limits.capture_tickets,
                "capture_bytes": fair_share_limits.capture_bytes,
                "state_document_ceiling_bytes": STATE_DOCUMENT_CEILING_BYTES,
                "session_fair_share": fair_share_limits.session_fair_share,
                "max_pending_age_ms": fair_share_limits.max_pending_age_ms,
            },
            "no_cap": no_cap_support(),
            "authority_unchanged": _AUTHORITY_UNCHANGED,
            "lower_command": lower_command,
            "revoke_command": (f"finishup observe selection-revoke --workspace {workspace} {flag}"),
            "pause_command": f"finishup observe pause --workspace {workspace}",
            "resume_command": f"finishup observe resume --workspace {workspace}",
            "validation_status": BUDGET_VALIDATION_STATUS,
        }
    )


def _human_bytes(value: int) -> str:
    """Render a byte count as B, KiB, or MiB with at most one decimal."""

    if value < _KIB:
        return f"{value} B"
    unit, name = (_MIB, "MiB") if value >= _MIB else (_KIB, "KiB")
    tenths = (value * 10 + unit // 2) // unit
    whole, fraction = divmod(tenths, 10)
    return f"{whole:,}{'' if fraction == 0 else f'.{fraction}'} {name}"


def _int(source: Mapping[str, object], key: str) -> int:
    value = source.get(key)
    if type(value) is not int or value < 0:
        raise _DisclosureError()
    return value


def _mapping(source: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = source.get(key)
    if not isinstance(value, Mapping):
        raise _DisclosureError()
    return cast(Mapping[str, object], value)


def _command(source: Mapping[str, object], key: str) -> str:
    command = canonical_safe_command(source.get(key))
    if command is None:
        raise _DisclosureError()
    return command


def _capacity_line_parts(record: Mapping[str, object]) -> tuple[int, str, int, int]:
    label = record.get("label")
    if type(label) is not str or label not in _LABELS:
        raise _DisclosureError()
    return (
        _int(record, "queue_count"),
        label,
        _int(record, "queue_bytes_limit"),
        _int(record, "state_bytes_limit"),
    )


def render_capacity_disclosure_lines(disclosure: Mapping[str, object]) -> tuple[str, ...]:
    """Return the one human wording for a capacity-change disclosure record.

    Every value is re-validated as a closed token, a non-negative integer, or
    a command built from safe arguments, so a record decoded from elsewhere
    cannot inject text into owner-facing output.
    """

    raw = cast(object, disclosure)
    if not isinstance(raw, Mapping):
        raise _DisclosureError()
    source = cast(Mapping[str, object], raw)
    if source.get("schema") != CAPACITY_DISCLOSURE_SCHEMA:
        raise _DisclosureError()
    change = source.get("change")
    scope = source.get("scope")
    if change not in _CONSEQUENCES or scope not in ("session", "workspace"):
        raise _DisclosureError()
    no_cap = _mapping(source, "no_cap")
    ceiling = _human_bytes(_int(no_cap, "state_document_ceiling_bytes"))
    largest = _int(no_cap, "largest_supported_queue_count")
    if change == "unsupported":
        return (
            "No FinishUP cap is not available for the structural queue in this revision: "
            f"the local state document has a {ceiling} safety ceiling. "
            f"The largest supported finite capacity is {largest:,} rows "
            f"(--capacity largest or --capacity custom --queue-count {largest}).",
        )
    current_count, current_label, current_queue, _current_state = _capacity_line_parts(
        _mapping(source, "current")
    )
    requested_count, _requested_label, requested_queue, requested_state = _capacity_line_parts(
        _mapping(source, "requested")
    )
    if change == "unchanged":
        return (
            f"Capacity is unchanged: this {scope} already selects "
            f"{current_count:,} rows ({current_label}).",
        )
    remaining = _mapping(source, "remaining_limits")
    scope_line = (
        f"Scope: this {scope}. Queue: {current_count:,} → {requested_count:,} rows "
        f"({_human_bytes(current_queue)} → {_human_bytes(requested_queue)} queue bytes; "
        f"state document up to {_human_bytes(requested_state)})."
    )
    limited_line = (
        f"Still limited: {_int(remaining, 'pending_attempts'):,} pending pairs, "
        f"{_int(remaining, 'capture_tickets'):,} capture tickets / "
        f"{_human_bytes(_int(remaining, 'capture_bytes'))}, "
        f"{_human_bytes(_int(remaining, 'state_document_ceiling_bytes'))} state document; "
        "content, privacy and provider authority are unchanged."
    )
    validation = source.get("validation_status")
    if not is_closed_token(validation):
        raise _DisclosureError()
    validation_line = f"Performance validation is provisional ({validation})."
    if change == "decrease":
        return (
            "Lowering affects future admission only; accepted records drain and are not deleted.",
            scope_line,
            limited_line,
            validation_line,
        )
    return (
        "Larger local retention can increase disk use, memory use and CPU work, "
        "and may slow FinishUP or other apps.",
        scope_line,
        "The shared workspace queue follows the largest active selection, so this can raise "
        "the queue and state-document bounds for every session in the workspace.",
        limited_line,
        f"Lower it later with: {_command(source, 'lower_command')}. "
        f"Pause new observation ingest with: {_command(source, 'pause_command')}.",
        f"Resume with: {_command(source, 'resume_command')}.",
        validation_line,
    )
