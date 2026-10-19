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
from finishup.application.reviewer_loop import ReviewerLoop, ReviewerModelError, ReviewOutcome
from finishup.domain.privacy import (
    AuthorizationScope,
    CandidateContext,
    PrivacyOutcome,
    PrivacyReason,
    ProviderBinding,
)
from finishup.domain.reviewer_reads import ReviewerRead, ReviewerRecord
from finishup.ports.semantic import (
    Deadline,
    ReviewerSession,
    ReviewStepStore,
    SemanticCase,
    SemanticResult,
    SemanticResultInvalid,
    SemanticResultSuccess,
    SemanticResultTimeout,
    decode_reviewer_exchange,
    encode_reviewer_exchange,
)
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.models import SemanticStatus

__all__ = ["PACKET_TURN", "ReviewerRun", "reviewer_catalog", "run_reviewer"]

# The loop's packet turn; each exchange replaces it with the packet that exchange's admission
# approved, followed by the read catalog.
PACKET_TURN: Final = "[FinishUP review packet]"
_INVALID_ENDINGS: Final = frozenset({"format_invalid", "read_limit", "turn_limit"})
_SOURCE_DOMAIN: Final = b"finishup/reviewer-read-source/v1\x00"


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


def reviewer_catalog(roots: Sequence[ReadRoot], reads: int) -> str:
    """What the reviewer may read, beside the packet: root aliases and what each covers."""

    rows: list[dict[str, object]] = []
    for root in roots:
        row: dict[str, object] = {"root_id": root.alias}
        if root.snapshot is not None:
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
    read_room: Callable[[int], int] = lambda _sent: MAX_TOTAL_BYTES,
) -> ReviewerRun:
    """Run the review conversation for one job attempt and return its terminal result.

    ``reads`` is how many reads the review offers: none where every exchange asks the owner first,
    since each further exchange would need its own approval. ``resume_pending`` names the proposal
    of a first exchange that waited for the owner before anything was sent: that exchange is
    resumed once, in the turn it already reserved, by its exact prepared identity. ``read_room``
    says how many read bytes the channel ceiling leaves after a conversation of that many bytes.
    ``source_commitment`` is the installation's keyed object commitment; a file read's opaque
    source id is derived from it, so the id cannot be recomputed from a guessed path.
    """

    retained = ReviewerHistory()
    broker = ReviewerBroker(
        job_id=job_id,
        case=case,
        roots=roots,
        store=steps,
        admit=lambda elements, envelope: privacy.admit_reviewer_read(
            first_request_id, scope, binding, elements, envelope, retained
        ),
        max_reads=reads,
    )
    catalog = reviewer_catalog(roots, reads)
    results: list[SemanticEgressResult] = []
    sent: list[int] = []
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
            sent.append(len(rendered))
            return rendered

        roots_held = tuple(sorted(broker.history_roots, key=str.encode))
        frame = ReviewerExchangeFrame(media_type, render, roots_held, retained)
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
        if sent:  # what the next exchanges may still add under the channel ceiling
            broker.total = min(MAX_TOTAL_BYTES, broker.used + read_room(sent[-1]))
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
    record, paths = _record(outcome, results, carried, cleanup)
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
    )


def _terminal(
    outcome: ReviewOutcome,
    results: list[SemanticEgressResult],
    request_id: str,
    cleanup: str | None,
) -> SemanticEgressResult:
    """One egress result for the whole conversation, without inventing an AI judgment."""

    last = results[-1] if results else None
    if type(last) is SemanticEgressReply:
        provenance = last.result.provenance
        evidence = provenance.runtime_evidence
        if evidence is not None and cleanup is not None:
            # The held session's actual cleanup, never the in-session "retained" of a turn.
            provenance = replace(
                provenance, runtime_evidence=replace(evidence, process_cleanup=cleanup)
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
    return ReviewerRecord(len(results), tuple(reads), ended, cleanup), paths


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
