"""What the reviewer read, as a structural summary every surface renders alike (#1118 unit 4).

The reviewer loop's history holds each read as an assistant action followed by the service's
result envelope. This module keeps only closed tokens, counts, byte sizes and the service-issued
root aliases (``w1``, ``o1``, ``s1``): never a path, a ``source_ref``, an argument or any read text.
Check, status, MCP, TUI and receipt surfaces render the same lines from the same summary.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Final, cast

__all__ = ["MAX_REVIEWER_READS", "render_reviewer_reads_lines", "summarize_reviewer_reads"]

MAX_REVIEWER_READS: Final = 3
_MAX_RESULT_BYTES: Final = 8192
_MAX_SOURCES: Final = 8
_ACTIONS: Final = frozenset({"read_packet_section", "read_ledger", "read_file"})
_STATUSES: Final = frozenset(
    {"ok", "partial", "unavailable", "denied", "stale", "budget_exhausted"}
)
_REASONS: Final = frozenset(
    {
        "not_retained",
        "not_recorded",
        "unsupported_type",
        "outside_scope",
        "privacy_withheld",
        "forbidden_path",
        "source_changed",
        "authorization_changed",
        "byte_budget",
        "invalid_request",
    }
)
_STANDINGS: Final = frozenset(
    {
        "task_transcription",
        "agent_assertion",
        "host_observation",
        "finishup_record",
        "workspace_content",
        "outside_input_mutable",
        "outside_input_snapshot",
    }
)
_BASELINES: Final = frozenset(
    {"task_start", "admission_time", "check_time", "read_time", "unknown"}
)
# A service-issued alias names a root; anything else (a path, a model-chosen name) is dropped.
_ALIAS: Final = re.compile(r"[a-z][0-9]{1,2}")


def _json(text: object) -> Mapping[str, object] | None:
    if type(text) is not str:
        return None
    try:
        value: object = json.loads(text)
    except ValueError:
        return None
    return cast(Mapping[str, object], value) if isinstance(value, dict) else None


def _source(provenance: object) -> dict[str, str] | None:
    if not isinstance(provenance, Mapping):
        return None
    fields = cast(Mapping[str, object], provenance)
    standing, baseline, root = fields.get("standing"), fields.get("baseline"), fields.get("root_id")
    if standing not in _STANDINGS or baseline not in _BASELINES:
        return None
    source = {"standing": cast(str, standing), "baseline": cast(str, baseline)}
    if type(root) is str and _ALIAS.fullmatch(root):
        source["root"] = root
    return source


def _sources(data: object) -> list[dict[str, str]]:
    if not isinstance(data, Mapping):
        return []
    body = cast(Mapping[str, object], data)
    records = body.get("records")
    provenances: Iterable[object] = (
        (
            cast(Mapping[str, object], row).get("provenance")
            for row in cast(Sequence[object], records)
            if isinstance(row, Mapping)
        )
        if isinstance(records, list)
        else (body.get("provenance"),)
    )
    found: list[dict[str, str]] = []
    for provenance in provenances:
        source = _source(provenance)
        if source is not None and source not in found:
            found.append(source)
    return found[:_MAX_SOURCES]


def summarize_reviewer_reads(turns: Iterable[tuple[str, str]]) -> dict[str, object] | None:
    """The structural read summary of one reviewer history of ``(role, content)`` turns.

    A read is an assistant turn naming one of the three actions followed by a user turn holding
    its result envelope. Malformed or unrecognized turns are skipped, never guessed at. ``None``
    when the history holds no read (a zero-read review renders nothing new).
    """

    history = list(turns)
    reads: list[dict[str, object]] = []
    for (role, content), (next_role, observation) in zip(history, history[1:], strict=False):
        action = _json(content) if role == "assistant" else None
        envelope = _json(observation) if next_role == "user" else None
        if action is None or envelope is None or action.get("action") not in _ACTIONS:
            continue
        ordinal, status, size = (
            envelope.get("call_index"),
            envelope.get("status"),
            envelope.get("result_utf8_bytes"),
        )
        if (
            type(ordinal) is not int
            or not 1 <= ordinal <= MAX_REVIEWER_READS
            or status not in _STATUSES
            or type(size) is not int
            or not 0 <= size <= _MAX_RESULT_BYTES
            or any(read["ordinal"] == ordinal for read in reads)
        ):
            continue
        read: dict[str, object] = {
            "ordinal": ordinal,
            "action": action["action"],
            "status": status,
            "result_bytes": size,
            "truncated": envelope.get("truncated") is True,
            "sources": _sources(envelope.get("data")),
        }
        if envelope.get("reason") in _REASONS:
            read["reason"] = envelope["reason"]
        reads.append(read)
    if not reads:
        return None
    return {
        "reads_used": len(reads),
        "result_bytes": sum(cast(int, read["result_bytes"]) for read in reads),
        "reads": reads,
    }


def _source_text(source: Mapping[str, object]) -> str:
    where = source.get("root", "record")
    return f"{where} ({source.get('standing')}, {source.get('baseline')})"


def render_reviewer_reads_lines(summary: object) -> tuple[str, ...]:
    """The fixed-wording lines for one read summary; empty for none or a malformed one."""

    if not isinstance(summary, Mapping):
        return ()
    body = cast(Mapping[str, object], summary)
    reads, used, total = body.get("reads"), body.get("reads_used"), body.get("result_bytes")
    if not isinstance(reads, list) or type(used) is not int or type(total) is not int:
        return ()
    lines = [
        f"Reviewer reads: {used} of {MAX_REVIEWER_READS}, {total} result bytes "
        "(what was read is named by root alias and standing, never by path)."
    ]
    for raw in cast(Sequence[object], reads):
        if not isinstance(raw, Mapping):
            continue
        read = cast(Mapping[str, object], raw)
        reason = f" {read['reason']}" if "reason" in read else ""
        clipped = ", clipped" if read.get("truncated") is True else ""
        raw_sources = read.get("sources")
        sources = (
            [
                _source_text(cast(Mapping[str, object], s))
                for s in cast(Sequence[object], raw_sources)
                if isinstance(s, Mapping)
            ]
            if isinstance(raw_sources, list)
            else []
        )
        what = "; " + ", ".join(sources) if sources else ""
        lines.append(
            f"- {read.get('ordinal')}. {read.get('action')}: {read.get('status')}{reason}, "
            f"{read.get('result_bytes')} bytes{clipped}{what}"
        )
    return tuple(lines)
