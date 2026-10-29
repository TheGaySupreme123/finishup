"""One semantic review job run as the reviewer conversation (#1118, ADR-006).

Every admitted semantic review job runs ``ReviewerLoop`` over the route's completion adapter. Each
exchange is an ordinary privacy-coordinator dispatch: the case items are classified, minimized and
scanned as for the old one-shot packet, the approved packet is placed in the conversation, and the
exact conversation bytes are admitted, consumed under the root and policy fence, and sent. Read
results were admitted by the broker before they joined the conversation. The steps are the job's
durable step store; the terminal result is one ordinary egress result, so the existing judgment
fence, recovery and receipts apply to it unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Final, cast

from finishup.adapters.providers.reviewer_reply import REVIEWER_LOOP_INSTRUCTION
from finishup.adapters.reviewer_artifacts import image_api
from finishup.application.egress import (
    PrivacyCoordinator,
    ReviewerExchangeFrame,
    ReviewerHistory,
    SemanticEgressAwaitingHuman,
    SemanticEgressBlocked,
    SemanticEgressProviderOutcome,
    SemanticEgressReply,
    SemanticEgressResult,
)
from finishup.application.reviewer_broker import (
    MAX_READS,
    MAX_TOTAL_BYTES,
    ReadRoot,
    ReviewerBroker,
)
from finishup.application.reviewer_exchange import ReviewerExchangeModel
from finishup.application.reviewer_loop import (
    FINAL_FORMAT_ERROR,
    FINAL_PHASE,
    FORMAT_ERROR,
    ReviewerLoop,
    ReviewerModelError,
    ReviewOutcome,
)
from finishup.application.reviewer_telemetry import read_usage_from_wire
from finishup.domain.findings import SemanticFailureClass
from finishup.domain.privacy import (
    AuthorizationScope,
    CandidateContext,
    PrivacyOutcome,
    PrivacyReason,
    ProviderBinding,
)
from finishup.domain.reviewer_context import ReviewerExchangeBudget
from finishup.domain.reviewer_reads import ReviewerRead, ReviewerRecord
from finishup.observability.logging import record_bounded_counts_without_raising
from finishup.ports.semantic import (
    Deadline,
    ReviewerSession,
    ReviewStepStore,
    SemanticCase,
    SemanticResult,
    SemanticResultInvalid,
    SemanticResultSuccess,
    SemanticResultTimeout,
    SemanticResultUnavailable,
    decode_reviewer_exchange,
    encode_reviewer_exchange,
    reviewer_exchange_tokens,
    reviewer_message_bytes,
    reviewer_message_tokens,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import SemanticStatus

__all__ = [
    "PACKET_TURN",
    "ReviewerRun",
    "reviewer_catalog",
    "reviewer_first_exchange",
    "run_reviewer",
]

# The loop's packet turn; each exchange replaces it with the packet that exchange's admission
# approved, followed by the read catalog.
PACKET_TURN: Final = "[FinishUP review packet]"
_INVALID_ENDINGS: Final = frozenset({"format_invalid", "read_limit", "turn_limit"})
_SOURCE_DOMAIN: Final = b"finishup/reviewer-read-source/v1\x00"
# The one format-repair notice a conversation may still add after any exchange (its codes are the
# service's own short names); every read leaves this room so that exchange fits the cap (#1118).
# The final phase's repair notice has its own wording (#1173); the room is the longer of the two.
_REPAIR_NOTES: Final = tuple(t.format(code="x" * 64) for t in (FORMAT_ERROR, FINAL_FORMAT_ERROR))
_REPAIR_NOTE_BYTES: Final = max(reviewer_message_bytes("user", note) for note in _REPAIR_NOTES)
_REPAIR_NOTE_TOKENS: Final = max(reviewer_message_tokens(note) for note in _REPAIR_NOTES)
_FINAL_NOTE_BYTES: Final = reviewer_message_bytes("user", FINAL_PHASE)
_FINAL_NOTE_TOKENS: Final = reviewer_message_tokens(FINAL_PHASE)


@dataclass(frozen=True, slots=True)
class ReviewerRun:
    """The conversation's terminal egress result and its record.

    ``citable_refs``/``text_by_ref`` are what the reads sent (the packet's own come from its
    disclosure); ``paths`` names each file read's root alias and path, kept only in the encrypted
    review response.
    """

    result: SemanticEgressResult
    record: ReviewerRecord
    citable_refs: frozenset[str]
    text_by_ref: Mapping[str, tuple[str, ...]]
    paths: Mapping[int, str]
    read_usage: tuple[Mapping[str, JsonValue], ...] = ()


def reviewer_catalog(roots: Sequence[ReadRoot], reads: int) -> str:
    """What the reviewer may read, beside the packet: root aliases and what each covers."""

    rows: list[dict[str, object]] = []
    for root in roots:
        row: dict[str, object] = {"root_id": root.alias}
        if root.pinned:
            # #1220: the declared tests the packet lists, by ref; never a filesystem path.
            row["standing"], row["baseline"] = "declared_test", "check_time"
            row["covers"] = [ref for ref, *_rest in root.pinned]
        elif root.snapshot is not None:
            prefix = root.path.rstrip("/") + "/"
            row["standing"], row["baseline"] = "outside_input_snapshot", root.snapshot.boundary
            row["covers"] = sorted(
                f.path.removeprefix(prefix)
                for f in root.snapshot.files
                if f.path.startswith(prefix)
            )
        elif root.input_root is not None:
            row["standing"], row["baseline"] = "outside_input_mutable", "read_time"
            row["covers"] = sorted(root.declared)
        else:
            row["standing"], row["baseline"] = "workspace_content", "read_time"
            row["covers"] = "the task workspace"
        rows.append(row)
    body = {"reviewer_catalog": {"reads_allowed": reads, "read_file_roots": rows}}
    return canonical_encode(cast(dict[str, object], body)).decode()  # pyright: ignore[reportArgumentType]


def reviewer_first_exchange(packet: bytes, catalog: str) -> bytes:
    """The exact first exchange that carries ``packet``: the loop instruction, the packet as a JSON
    string and the read catalog. Ceiling planning measures it, so escaping is counted (#1118)."""

    return encode_reviewer_exchange(
        (("system", REVIEWER_LOOP_INSTRUCTION), ("user", packet.decode()), ("user", catalog))
    )


async def run_reviewer(
    privacy: PrivacyCoordinator,
    *,
    job_id: str,
    case: SemanticCase,
    roots: Sequence[ReadRoot],
    steps: ReviewStepStore,
    binding: ProviderBinding,
    scope: AuthorizationScope,
    deadline: Deadline,
    first_request_id: str,
    new_request_id: Callable[[], str],
    candidate_for: Callable[[str], CandidateContext],
    dispatch_guard: Callable[[], Awaitable[bool]] | None,
    resume_pending: str | None,
    clock: Callable[[], float],
    source_commitment: Callable[[bytes], Awaitable[str]],
    reads: int = MAX_READS,
    exchange_budget: ReviewerExchangeBudget | None = None,
) -> ReviewerRun:
    """Run the review conversation for one job attempt and return its terminal result.

    ``reads`` is how many reads the review offers: none where every exchange asks the owner first,
    since each further exchange would need its own approval. ``resume_pending`` names the proposal
    of a first exchange that waited for the owner before anything was sent: that exchange is
    resumed once, in the turn it already reserved, by its exact prepared identity.
    ``exchange_budget`` is what one exchange may carry (#1118): its bytes and, on a route sized to
    its model's context, its estimated model tokens. Each read result gets only what the last
    exchange sent leaves of both, measured as the next exchange will encode the read action and
    the result, less the room a format-repair notice may still need. A message adds at most as
    many estimated tokens as encoded bytes, so token room is granted as that many bytes.
    ``source_commitment`` is the installation's keyed object commitment; a file read's opaque
    source id is derived from it, so the id cannot be recomputed from a guessed path.
    """

    retained = ReviewerHistory()
    sent: list[tuple[int, int]] = []

    def exchange_room() -> int | None:
        if exchange_budget is None or not sent:
            return None
        size, tokens = sent[-1]
        room = exchange_budget.byte_limit - size - _REPAIR_NOTE_BYTES - _FINAL_NOTE_BYTES
        if exchange_budget.token_limit is not None:
            room = min(
                room,
                exchange_budget.token_limit - tokens - _REPAIR_NOTE_TOKENS - _FINAL_NOTE_TOKENS,
            )
        return room

    broker = ReviewerBroker(
        job_id=job_id,
        case=case,
        roots=roots,
        store=steps,
        admit=lambda elements, envelope: privacy.admit_reviewer_read(
            first_request_id, scope, binding, elements, envelope, retained
        ),
        max_reads=reads,
        exchange_room=exchange_room,
        images=(
            binding.transport != "local_af_unix"
            and image_api(binding.endpoint_profile_id) is not None
            and await privacy.reviewer_images_allowed(scope, binding)
        ),
    )
    catalog = reviewer_catalog(roots, reads)
    results: list[SemanticEgressResult] = []
    # Read call -> the exchange (index into ``results``) that first carried its result, recorded
    # when that exchange was sent; a result no sent exchange carried has no disclosure.
    carried: dict[int, int] = {}

    async def dispatch(payload: bytes, media_type: str, limit: Deadline) -> SemanticResult:
        history = decode_reviewer_exchange(payload)
        calls = [call for role, text in history[2:] if (call := _read_call(role, text))]

        def render(packet: bytes) -> bytes:
            rendered = encode_reviewer_exchange(
                (history[0], ("user", packet.decode()), ("user", catalog), *history[2:])
            )
            sent.append((len(rendered), reviewer_exchange_tokens(rendered)))
            return rendered

        roots_held = tuple(sorted(broker.history_roots, key=str.encode))
        frame = ReviewerExchangeFrame(media_type, render, roots_held, retained, exchange_budget)
        if not results and resume_pending is not None:
            result = await privacy.resume_reviewer_exchange(
                first_request_id,
                resume_pending,
                limit,
                dispatch_guard=dispatch_guard,
                exchange=frame,
            )
        else:
            rid = first_request_id if not results else new_request_id()
            result = await privacy.evaluate_semantic(
                candidate_for(rid), limit, dispatch_guard=dispatch_guard, exchange=frame
            )
        results.append(result)
        if _receipt(result) is not None:
            for call in calls:
                carried.setdefault(call, len(results) - 1)
        room = exchange_room()
        if room is not None:  # what the next exchanges may still add under the cap
            broker.total = min(MAX_TOTAL_BYTES, broker.used + max(0, room))
        if type(result) is SemanticEgressReply or type(result) is SemanticEgressProviderOutcome:
            return result.result
        raise ReviewerModelError("reviewer_exchange_not_sent")

    async def admissible(held: frozenset[str]) -> bool:
        return await privacy.reviewer_history_current(scope, binding, held, retained)

    session = ReviewerSession(job_id, deadline)
    async with ReviewerExchangeModel(binding, dispatch, session) as model:
        loop = ReviewerLoop(
            model,
            broker,
            instruction=REVIEWER_LOOP_INSTRUCTION,
            packet=PACKET_TURN,
            deadline=deadline,
            history_admissible=admissible,
            clock=clock,
            resume_reserved=resume_pending is not None,
        )
        outcome = await loop.run()
        cleanup = await session.aclose()
    if cleanup == "failed" and outcome.status == "final":
        outcome = replace(outcome, status="incomplete", judgment=None, reason="cleanup_unconfirmed")
    record, paths = _record(outcome, results, carried, cleanup)
    for usage in broker.read_usage:
        record_bounded_counts_without_raising(
            component="reviewer_reads",
            operation=f"reviewer_{usage['action']}",
            outcome=cast(str, usage["reason"] or usage["status"]),
            request_id=first_request_id,
            counts={"operation_count": usage["call"]},
        )
    sources: dict[int, str] = {}
    for call, path in paths.items():
        keyed = await source_commitment(_SOURCE_DOMAIN + f"{job_id}\x00{path}".encode())
        sources[call] = "src_" + keyed.rpartition(":")[2][:24]
    record = replace(
        record,
        reads=tuple(
            replace(read, source=sources[read.call]) if read.call in sources else read
            for read in record.reads
        ),
    )
    return ReviewerRun(
        _terminal(outcome, results, first_request_id, cleanup),
        record,
        outcome.citable_refs,
        outcome.text_by_ref,
        paths,
        read_usage_from_wire(broker.read_usage) or (),
    )


def _terminal(
    outcome: ReviewOutcome,
    results: list[SemanticEgressResult],
    request_id: str,
    cleanup: str | None,
) -> SemanticEgressResult:
    """One egress result for the whole conversation, without inventing an AI judgment."""

    last = results[-1] if results else None
    if outcome.reason == "case_capacity_exceeded" and outcome.capacity is not None:
        return SemanticEgressBlocked(
            request_id,
            PrivacyOutcome.BLOCKED_BY_POLICY,
            PrivacyReason.POLICY_DENIED,
            capacity=outcome.capacity,
        )
    if type(last) is SemanticEgressReply:
        provenance = last.result.provenance
        evidence = provenance.runtime_evidence
        if evidence is not None and cleanup is not None:
            # The held session's actual cleanup, never the in-session "retained" of a turn.
            provenance = replace(
                provenance, runtime_evidence=replace(evidence, process_cleanup=cleanup)
            )
        if cleanup == "failed":
            evidence = provenance.runtime_evidence
            if evidence is not None:
                evidence = replace(evidence, failure_stage="cleanup_unconfirmed")
            return last.outcome(
                SemanticResultUnavailable(
                    replace(
                        provenance,
                        status=SemanticStatus.UNAVAILABLE,
                        failure_class=SemanticFailureClass.TRANSPORT,
                        runtime_evidence=evidence,
                    )
                )
            )
        if outcome.status == "final" and outcome.judgment is not None:
            return last.success(SemanticResultSuccess(outcome.judgment, provenance))
        if outcome.reason == "deadline":
            return last.outcome(
                SemanticResultTimeout(replace(provenance, status=SemanticStatus.TIMEOUT))
            )
        if outcome.reason in _INVALID_ENDINGS or (outcome.reason or "").startswith("reviewer_"):
            raw = len(json.dumps(last.result.reply).encode())
            return last.outcome(
                SemanticResultInvalid(replace(provenance, status=SemanticStatus.INVALID), raw)
            )
    elif last is not None and not (type(last) is SemanticEgressAwaitingHuman and len(results) > 1):
        # The exchange's own outcome ended the review: blocked, awaiting the owner on the first
        # exchange, or a provider failure. It maps exactly as a one-shot review's would.
        return last
    if outcome.reason == "deadline":
        return SemanticEgressBlocked(
            request_id, PrivacyOutcome.TIMEOUT, PrivacyReason.DEADLINE_EXPIRED
        )
    if outcome.reason == "authorization_changed" or type(last) is SemanticEgressAwaitingHuman:
        return SemanticEgressBlocked(
            request_id, PrivacyOutcome.BLOCKED_BY_POLICY, PrivacyReason.POLICY_DENIED
        )
    # A lost lease, an earlier run of this job, or an uncaptured step: whether anything more was
    # sent is not known, and the conversation is not resumed.
    return SemanticEgressBlocked(
        request_id, PrivacyOutcome.TRANSPORT_FAILED, PrivacyReason.OUTCOME_UNKNOWN
    )


def _record(
    outcome: ReviewOutcome,
    results: list[SemanticEgressResult],
    carried: Mapping[int, int],
    cleanup: str | None,
) -> tuple[ReviewerRecord, dict[int, str]]:
    """The bounded record of what the conversation read, built from its own service envelopes."""

    reads: list[ReviewerRead] = []
    paths: dict[int, str] = {}
    turns = outcome.history
    for index, turn in enumerate(turns[:-1]):
        nxt = turns[index + 1]
        if turn.role != "assistant" or nxt.role != "user":
            continue
        reply = json.loads(turn.content)["reply"]
        if "action" not in reply:
            continue
        envelope = json.loads(nxt.content)
        call = cast(int, envelope["call_index"])
        data = envelope.get("data")
        prov = _provenance(data)
        args = cast(dict[str, object], reply["args"])
        source = cast(str | None, None if prov is None else prov.get("source_ref"))
        if reply["action"] == "read_file":
            # Its opaque source id is the keyed commitment ``run_reviewer`` derives from this.
            alias, path = cast(str, args["root_id"]), cast(str, args["path"])
            paths[call] = f"{alias}:{path}"
            source = None
        line_span = None if prov is None else prov.get("line_span")
        lines = (
            None
            if not isinstance(line_span, dict)
            else (cast(int, line_span["start"]), cast(int, line_span["end_inclusive"]))
        )
        carrier = results[carried[call]] if call in carried else None
        reads.append(
            ReviewerRead(
                call=call,
                action=cast(str, reply["action"]),
                status=cast(str, envelope["status"]),
                reason=cast(str | None, envelope["reason"]),
                source=source,
                root=cast(str | None, None if prov is None else prov.get("root_id")),
                standing=cast(str | None, None if prov is None else prov.get("standing")),
                baseline=cast(str | None, None if prov is None else prov.get("baseline")),
                lines=lines,
                result_bytes=cast(int, envelope["result_utf8_bytes"]),
                result_digest=cast(str, envelope["result_digest"]),
                disclosure=_receipt(carrier),
            )
        )
    ended = None if outcome.status == "final" else outcome.reason
    # #1138: an exchange refused before dispatch was never sent; count only those that were.
    sent = sum(
        type(result) is SemanticEgressReply or type(result) is SemanticEgressProviderOutcome
        for result in results
    )
    return ReviewerRecord(sent, tuple(reads), ended, cleanup), paths


def _read_call(role: str, text: str) -> int | None:
    """The call index of a read result envelope in the history, else ``None``."""

    if role != "user" or not text.startswith('{"'):
        return None
    try:
        envelope = json.loads(text)
    except ValueError:
        return None
    if not isinstance(envelope, dict):
        return None
    body = cast(dict[str, object], envelope)
    call = body.get("call_index")
    return call if type(call) is int and "tool_ref" in body else None


def _provenance(data: object) -> dict[str, object] | None:
    """The first provenance a result's data carries (a record set's first record)."""

    if not isinstance(data, dict):
        return None
    body = cast(dict[str, object], data)
    records = body.get("records")
    if isinstance(records, list) and records:
        body = cast(dict[str, object], cast(list[object], records)[0])
    prov = body.get("provenance")
    return cast(dict[str, object], prov) if isinstance(prov, dict) else None


def _receipt(result: SemanticEgressResult | None) -> str | None:
    if type(result) is SemanticEgressReply:
        return cast(str | None, result.fields["privacy_receipt_id"])
    if type(result) is SemanticEgressProviderOutcome:
        return result.privacy_receipt_id
    return None
