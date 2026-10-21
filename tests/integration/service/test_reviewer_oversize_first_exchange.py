"""#1118: a large but legal case plans its reviewer conversation under the disclosure cap.

A benchmark smoke ended four reviews ``coordinator_failure`` at ``finishup.ports.privacy:529``: the
packet fit the planner's estimate (the ceiling less 8 KiB, less a fifth for escaping), but the first
exchange (the loop instruction, the packet as a JSON string, the read catalog) came to more than the
262,144 bytes one ``MinimizedDisclosure`` may carry, whether the excerpts were diff parts or
captured output alone under the excerpt budget. Building that disclosure raised inside the privacy
coordinator.

These tests drive the real service evaluator, composition, ceiling planning, privacy coordinator
and reviewer conversation over a durable job, with the real setup ceilings. Only the provider is
scripted; no model, network or credential is used.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.cli.privacy_setup as privacy_setup_module
import finishup.service.ready_composition as ready_composition_module
from builders.privacy_policies import minimal_external_policy
from finishup.adapters.privacy.local_enforcer import estimated_token_count
from finishup.application.reviewer_loop import FINAL_TURN
from finishup.application.reviewer_run import reviewer_first_exchange
from finishup.application.semantic_case import (
    check_time_change_bytes_carried,
    check_time_change_floor_bytes_carried,
    final_diff_floor,
)
from finishup.domain.events import EvidenceKind
from finishup.domain.privacy import (
    EgressChannel,
    PrivacyPolicy,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.domain.reviewer_context import (
    MAX_SIZED_EXCHANGE_BYTES,
    UNSIZED_EXCHANGE_BYTES,
    ReviewerExchangeBudget,
)
from finishup.ports.semantic import (
    ReviewerMessage,
    SemanticResultReply,
    encode_reviewer_exchange,
    reviewer_exchange_tokens,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.models import SemanticReason, SemanticStatus
from finishup.service.semantic_ceiling import REVIEWER_FRAME_BYTES, reviewer_exchange_budget
from integration.service.test_reviewer_conversation_composition import (
    _BINDING,  # pyright: ignore[reportPrivateUsage]
    _FINAL,  # pyright: ignore[reportPrivateUsage]
    _read_file,  # pyright: ignore[reportPrivateUsage]
    _run,  # pyright: ignore[reportPrivateUsage]
    frozen_request,
)
from unit.application.test_semantic_case_packet_completeness import (
    _change,  # pyright: ignore[reportPrivateUsage]
    _react_case,  # pyright: ignore[reportPrivateUsage]
    _with_evidence,  # pyright: ignore[reportPrivateUsage]
)

# The setup's LLM channel ceilings (``cli/privacy_setup._CASE_MAX_BYTES``/``_CASE_MAX_TOKENS``).
_CEILING = 256 * 1024
# The ceilings a fresh ``--privacy`` setup writes (#1118): 524,288 bytes and 131,072 tokens.
_SETUP_CEILINGS = (
    privacy_setup_module._CASE_MAX_BYTES,  # pyright: ignore[reportPrivateUsage]
    privacy_setup_module._CASE_MAX_TOKENS,  # pyright: ignore[reportPrivateUsage]
)


def _code_diff(files: int, lines: int) -> bytes:
    """Ordinary Python edits whose quotes and backslashes JSON escapes twice in the conversation."""

    out: list[bytes] = []
    for index in range(files):
        out.append(f"diff --git a/pkg/mod{index}.py b/pkg/mod{index}.py\n".encode())
        for line in range(lines):
            out.append(
                (
                    f'+    row = {{"id": "{index}-{line}", "path": "C:\\\\data\\\\{line}", '
                    f'"label": "say \\"ok\\""}}\n'
                ).encode()
            )
    return b"".join(out)


@pytest.mark.anyio
async def test_read_action_capacity_maps_through_the_service_without_schema_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #1135: force the boundary independently of changes to the first-packet planner. The real
    # broker refuses this valid action before I/O, and the real service must map that refusal.
    from finishup.application.reviewer_broker import ReviewerBroker

    execute = ReviewerBroker.execute

    async def nearly_full(self: Any, *args: Any, **kwargs: Any) -> str:
        self._exchange_room = lambda: 2048  # pyright: ignore[reportPrivateUsage]
        return await execute(self, *args, **kwargs)

    monkeypatch.setattr(ReviewerBroker, "execute", nearly_full)
    path = "\\" * 509
    result, gateway, runtime = await _run(
        tmp_path, monkeypatch, _read_file(path), policy=_expanded_policy()
    )
    assert (result.status, result.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )
    assert result.judgment is None and len(gateway.exchanges) == 1
    assert result.reviewer is not None and result.reviewer.ended == "case_capacity_exceeded"
    assert result.reviewer.reads == ()
    job = await runtime.ledger.load_semantic_job(runtime.writer_id or "", frozen_request())
    assert job is not None and job.terminal_code is SemanticReason.CASE_CAPACITY_EXCEEDED
    assert await cast(Any, runtime.ledger).review_step_usage(job.job_id) == (1, 0)


def _decision_first_diff(files: int, lines: int, pad: int) -> bytes:
    """Quoted Python edits with a decision past each file's opening rows.

    Too large for the excerpt budget, this change is offered decision sections first (#983), so
    its leading parts start inside the change, not at its first byte: the shape of the benchmark
    change whose reviews were refused.
    """

    extra = ', "w": "\\"y\\" C:\\\\z"' * pad
    out: list[bytes] = []
    for index in range(files):
        out.append(
            (
                f"diff --git a/pkg/m{index}.py b/pkg/m{index}.py\n--- a/pkg/m{index}.py\n"
                f"+++ b/pkg/m{index}.py\n@@ -1,1 +1,{lines} @@\n"
            ).encode()
        )
        for line in range(lines):
            if line % 12 == 11:
                out.append(f'+    if row["k{line}"] == "v\\"{line}\\"":\n'.encode())
            else:
                out.append(
                    f'+    row = {{"id": "{index}-{line}", "q": "\\"x\\""{extra}}}\n'.encode()
                )
    return b"".join(out)


def _tool_output(outputs: int) -> tuple[tuple[EvidenceKind, str], ...]:
    """Agent-published command output, JSON log lines: excerpts with no diff part at all."""

    line = '{"level": "info", "msg": "row \\"%d\\" ok", "path": "C:\\\\run\\\\%d"}\n'
    return tuple(
        (EvidenceKind.COMMAND_OUTPUT, "".join(line % (i, n) for n in range(110))[:8000])
        for i in range(outputs)
    )


def _expanded_policy() -> PrivacyPolicy:
    base = minimal_external_policy()
    channels = tuple(
        replace(channel, max_bytes=_CEILING, max_tokens=estimated_token_count(_CEILING))
        if channel.channel is EgressChannel.LLM_INFERENCE
        else channel
        for channel in base.channel_policies
    )
    return replace(
        base,
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        channel_policies=channels,
    )


def _composed(
    monkeypatch: pytest.MonkeyPatch, *, diff: bytes | None, outputs: int = 0
) -> list[Any]:
    """Compose the real case over a linked work record with a check-time change of ``diff`` (none
    when ``None``) and ``outputs`` captured command outputs; return each case built."""

    real = ready_composition_module.build_semantic_case
    frozen = _with_evidence(_react_case(), *_tool_output(outputs)) if outputs else _react_case()
    built: list[Any] = []

    def build(**kwargs: Any) -> Any:  # noqa: ANN401
        change = None if diff is None else _change(diff)
        options: dict[str, Any] = {**kwargs, "frozen_case": frozen, "check_time_change": change}
        case = real(**options)
        built.append(case)
        return case

    monkeypatch.setattr(ready_composition_module, "build_semantic_case", build)
    return built


def _encoded(history: tuple[tuple[str, str], ...]) -> bytes:
    return encode_reviewer_exchange(cast(tuple[ReviewerMessage, ...], history))


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("diff", "outputs"),
    (
        # Eight diff parts of quoted code fill the 131,072-byte excerpt budget.
        (_code_diff(files=8, lines=400), 0),
        # No diff part: captured JSON tool output alone, under the excerpt budget.
        (None, 16),
    ),
    ids=("diff_parts", "captured_output_only"),
)
async def test_a_case_filling_the_excerpt_budget_is_reviewed_within_the_disclosure_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, diff: bytes | None, outputs: int
) -> None:
    built = _composed(monkeypatch, diff=diff, outputs=outputs)
    result, gateway, _runtime = await _run(tmp_path, monkeypatch, _FINAL, policy=_expanded_policy())
    # Not a coordinator failure: the review ran and concluded.
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    ((_media, history),) = gateway.exchanges
    # The exact first exchange the provider received fits the cap one disclosure carries.
    assert len(_encoded(history)) <= UNSIZED_EXCHANGE_BYTES
    # Planning measured these same bytes: the renderer it uses is the one the exchange was sent in.
    assert reviewer_first_exchange(history[1][1].encode(), history[2][1]) == _encoded(history)
    # The full selection did not fit, so planning narrowed it and the packet says so.
    approved, planned = built[0], built[-1]
    assert sum(i.content_bytes for i in planned.items if i.section == "excerpt") < sum(
        i.content_bytes for i in approved.items if i.section == "excerpt"
    )
    packet = json.loads(history[1][1])
    assert "content_unselected" in packet["review_packet"]["coverage"]["known_gaps"]


@pytest.mark.anyio
async def test_an_exchange_over_the_disclosure_cap_is_refused_typed_and_never_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the rendered conversation still outgrows the cap, nothing is sent and the review ends
    as the case's capacity (#1118 owner decision), never as a coordinator failure and never as a
    network denial: egress was allowed. The receipt still records ``blocked_by_policy`` /
    ``policy_denied`` with nothing sent, the job ends on that reason, and a bounded diagnostic
    carries the attempted size and the cap."""

    import finishup.application.reviewer_run as reviewer_run_module
    from finishup.adapters.memory.privacy import MemoryPrivacyAudit

    receipts: list[Any] = []
    complete = MemoryPrivacyAudit.complete_decision

    async def capture(self: MemoryPrivacyAudit, proposal_id: str, receipt: Any) -> None:  # noqa: ANN401
        receipts.append(receipt)
        await complete(self, proposal_id, receipt)

    monkeypatch.setattr(MemoryPrivacyAudit, "complete_decision", capture)
    events: list[dict[str, Any]] = []
    record = ready_composition_module.record_bounded_counts_without_raising

    def counted(**kwargs: Any) -> str:  # noqa: ANN401
        events.append(kwargs)
        return record(**kwargs)

    monkeypatch.setattr(ready_composition_module, "record_bounded_counts_without_raising", counted)

    _composed(monkeypatch, diff=_code_diff(files=1, lines=20))
    real_catalog = reviewer_run_module.reviewer_catalog

    def oversize_catalog(roots: Any, reads: int) -> str:  # noqa: ANN401
        body = json.loads(real_catalog(roots, reads))
        body["reviewer_catalog"]["padding"] = "x" * UNSIZED_EXCHANGE_BYTES
        return json.dumps(body)

    monkeypatch.setattr(reviewer_run_module, "reviewer_catalog", oversize_catalog)
    result, gateway, runtime = await _run(tmp_path, monkeypatch, _FINAL, policy=_expanded_policy())
    assert gateway.exchanges == []
    assert (result.status, result.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )
    assert result.provenance is None
    (receipt,) = receipts
    assert (receipt.outcome.value, receipt.safe_failure_reason.value) == (
        "blocked_by_policy",
        "policy_denied",
    )
    assert receipt.counts.final_bytes == 0
    (event,) = [e for e in events if e["operation"] == "semantic_disclosure_capacity_exceeded"]
    attempted = event["counts"]["semantic_disclosure_attempted_bytes"]
    assert attempted > UNSIZED_EXCHANGE_BYTES
    assert event["counts"]["semantic_disclosure_limit_bytes"] == UNSIZED_EXCHANGE_BYTES
    job = await runtime.ledger.load_semantic_job(runtime.writer_id or "", frozen_request())
    assert job is not None and job.terminal_code is SemanticReason.CASE_CAPACITY_EXCEEDED


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("files", "lines", "pad", "outputs"),
    (
        # A narrowed case fits at the first planned budget (the a1 refusal: two planning rounds).
        (40, 24, 10, 35),
        # The first planned budget is still over; the second fits (the a2 refusal: three rounds).
        (24, 36, 12, 35),
    ),
    ids=("two_rounds", "three_rounds"),
)
async def test_a_decision_first_change_is_narrowed_under_the_cap_not_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    files: int,
    lines: int,
    pad: int,
    outputs: int,
) -> None:
    """#1118: two benchmark reviews ended ``blocked_by_policy`` / ``network_egress_denied`` in the
    coordinator's cap check on their first exchange, before any model turn. Their change did not
    fit, so it was offered decision sections first; ceiling planning then compared the diff
    floor (change bytes of the leading parts) with the contiguous run from the change's first
    byte, which such parts never start at: 0. Every narrowed candidate failed the floor and the
    over-ceiling case was returned whole."""

    built = _composed(monkeypatch, diff=_decision_first_diff(files, lines, pad), outputs=outputs)
    result, gateway, _runtime = await _run(tmp_path, monkeypatch, _FINAL, policy=_expanded_policy())
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    ((_media, history),) = gateway.exchanges
    assert len(_encoded(history)) <= _CEILING - REVIEWER_FRAME_BYTES
    approved, planned = built[0], built[-1]
    # Why the old comparison refused every narrowing: the leading parts never start at byte 0.
    assert check_time_change_bytes_carried(approved) == 0
    # The narrowed case still carries the change floor the approved selection protected.
    floor = final_diff_floor(
        approved,
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        _CEILING - REVIEWER_FRAME_BYTES,
    )
    assert check_time_change_floor_bytes_carried(planned) >= floor > 0
    assert sum(i.content_bytes for i in planned.items if i.section == "excerpt") < sum(
        i.content_bytes for i in approved.items if i.section == "excerpt"
    )
    packet = json.loads(history[1][1])
    assert "content_unselected" in packet["review_packet"]["coverage"]["known_gaps"]


def _file_read(path: str, write: Callable[[], None]) -> Callable[..., object]:
    """A reviewer reply that asks for 200 lines of ``path``; ``write`` puts the file in place."""

    def reply(_case: object, provenance: Any) -> object:  # noqa: ANN401
        write()
        action = _read_file(path)
        cast(dict[str, dict[str, JsonValue]], action["reply"])["args"]["line_count"] = 200
        return SemanticResultReply(action, provenance)

    return reply


def _legacy_read_exchange(
    first: tuple[tuple[str, str], ...],
    second: tuple[tuple[str, str], ...],
    source: str,
) -> bytes:
    """Reproduce the old raw-byte fitter, proving the fixture still exposes its overflow.

    Both fixtures are ASCII. Measure the actual escaped action, result and history so changes
    to reviewer wording cannot silently turn this into a non-boundary read.
    """

    total = max(0, (_CEILING - len(_encoded(first)) - 2048) * 4 // 5)
    room = min(8192, total)
    body = json.loads(second[-1][1])
    head = min(6144, room, len(source))
    while head:
        text = source[:head]
        data = body["data"]
        data["text"] = text
        data["provenance"]["span"]["end_exclusive"] = head
        data["provenance"]["line_span"]["end_inclusive"] = (
            1 + text.count("\n") - text.endswith("\n")
        )
        body["result_digest"] = canonical_digest(data)
        encoded, size = b"", 0
        for _ in range(8):
            body["result_utf8_bytes"] = size
            body["bytes_remaining"] = max(0, total - size)
            encoded = canonical_encode(body)
            if len(encoded) == size:
                break
            size = len(encoded)
        over = len(encoded) - room
        if over <= 0:
            return _encoded((*second[:-1], ("user", encoded.decode())))
        head = max(0, head - over - 8)
    raise AssertionError("fixture does not retain a legacy read")


@pytest.mark.anyio
async def test_every_later_exchange_fits_the_cap_beside_a_long_read_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1118: the read room was estimated from the last exchange ((cap - sent - 2048) * 4/5 raw
    result bytes), but the read action and its result travel as JSON strings in the next
    exchange, escaping and all. A long escaped path beside a quoted result outgrew the cap, and
    the coordinator refused the whole review on its second exchange. Each result now gets only
    what the exact next exchange leaves."""

    _composed(monkeypatch, diff=_decision_first_diff(32, 24, 12), outputs=16)
    # A legal 507-character path whose characters JSON escapes as \u00XX, twice in the exchange.
    parts = ("\x01" * 250, "\x02" * 250)
    path = "/".join((*parts, "rows.py"))

    line = '{"id": %d, "m": "\\"a\\" b", "p": "C:\\\\x"}\n'
    source = "".join(line % n for n in range(300))

    def write() -> None:
        folder = tmp_path / "work" / parts[0] / parts[1]
        folder.mkdir(parents=True)
        (folder / "rows.py").write_text(source)

    result, gateway, _runtime = await _run(
        tmp_path, monkeypatch, _file_read(path, write), _FINAL, policy=_expanded_policy()
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    first, second = (history for _media, history in gateway.exchanges)
    assert len(_legacy_read_exchange(first, second, source)) > UNSIZED_EXCHANGE_BYTES
    assert len(_encoded(second)) <= UNSIZED_EXCHANGE_BYTES
    # The result was fitted to that room, not dropped: it still carries the file's head.
    observation = json.loads(second[-1][1])
    assert observation["status"] == "partial" and '\\"a\\" b' in observation["data"]["text"]


@pytest.mark.anyio
async def test_an_escaping_heavy_read_keeps_the_longest_head_that_fits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1118: a result over its room was cut by the excess in result bytes, but each quote costs
    two result bytes, so a quoted file lost twice what it had to, or arrived with no data at
    all. It now keeps the longest head that fits, measured."""

    def write() -> None:
        (tmp_path / "work" / "quotes.py").write_text(('x = "' + '\\"' * 40 + '"\n') * 200)

    result, gateway, _runtime = await _run(
        tmp_path, monkeypatch, _file_read("quotes.py", write), _FINAL, policy=_expanded_policy()
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    observation = gateway.exchanges[-1][1][-1][1]
    body = json.loads(observation)
    assert body["status"] == "partial" and body["data"] is not None
    # Within a line-free head of the 8 KiB result room, not a quarter of it.
    assert len(observation.encode()) > 8192 - 128


@pytest.mark.anyio
async def test_a_backslash_read_after_a_full_first_exchange_fits_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1118 verifier V4: a first exchange of 253,597 bytes, under the planned target, left a
    read room of (262,144 - 253,597 - 2,048) * 4/5 = 5,199 bytes. Backslash lines escape again
    in the conversation, so the 5,100-byte result went out as 9,210 bytes, and the second
    exchange reached 263,010, over the cap: the review was refused after its first exchange."""

    _composed(monkeypatch, diff=_code_diff(8, 203), outputs=0)

    source = ("\\" * 100 + "\n") * 150

    def read(_case: object, provenance: Any) -> object:  # noqa: ANN401
        (tmp_path / "work" / "calc.py").write_text(source)
        action = _read_file("calc.py")
        cast(dict[str, dict[str, JsonValue]], action["reply"])["args"]["line_count"] = 32
        return SemanticResultReply(action, provenance)

    result, gateway, _runtime = await _run(
        tmp_path, monkeypatch, read, _FINAL, policy=_expanded_policy()
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    first, second = (history for _media, history in gateway.exchanges)
    assert len(_legacy_read_exchange(first, second, source[: 32 * 101])) > UNSIZED_EXCHANGE_BYTES
    assert len(_encoded(second)) <= UNSIZED_EXCHANGE_BYTES
    assert json.loads(second[-1][1])["data"] is not None  # fitted, not dropped


@pytest.mark.anyio
async def test_the_no_reads_left_notice_fits_beside_a_read_that_filled_its_room(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1172: the reply schema no longer narrows after the last read, so the loop appends its one
    no-reads-left notice instead. Every read leaves room for it beside the one format repair: after
    a third read that filled what a near-cap conversation left, the exchange carrying the notice,
    and the repair after it, still fit the cap, under the same reply schema throughout."""

    _composed(monkeypatch, diff=_code_diff(8, 203), outputs=0)

    def read(lines: int) -> Callable[..., object]:
        def reply(_case: object, provenance: Any) -> object:  # noqa: ANN401
            (tmp_path / "work" / "calc.py").write_text(("\\" * 100 + "\n") * 150)
            action = _read_file("calc.py")
            cast(dict[str, dict[str, JsonValue]], action["reply"])["args"]["line_count"] = lines
            return SemanticResultReply(action, provenance)

        return reply

    rejected: dict[str, JsonValue] = {"reply": {}}  # the decoder refuses it: one repair
    result, gateway, _runtime = await _run(
        tmp_path,
        monkeypatch,
        read(1),
        read(1),
        read(150),
        rejected,
        _FINAL,
        policy=_expanded_policy(),
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    exchanges = [history for _media, history in gateway.exchanges]
    assert len(exchanges) == 5 and exchanges[3][-1] == ("user", FINAL_TURN)
    assert exchanges[4][-2:][0] == ("user", FINAL_TURN)
    assert exchanges[4][-1][1].startswith("format_error: action_invalid.")
    assert json.loads(exchanges[3][-2][1])["status"] == "partial"  # the read filled its room
    for history in exchanges:
        assert len(_encoded(history)) <= UNSIZED_EXCHANGE_BYTES
    assert len(_encoded(exchanges[-1])) > UNSIZED_EXCHANGE_BYTES - 1024  # a real boundary
    assert {media for media, _history in gateway.exchanges} == {
        "application/vnd.finishup.reviewer-turn+json"
    }


# #1118 token budget: the Codex subscription route running the pinned reviewer model is sized to
# that model's context; every other route keeps the 262,144-byte exchange bound.
_CODEX = ProviderBinding(
    "openai-codex", "gpt-6.1-sol", "codex-chatgpt-subscription", "1.0.0", "external"
)


def _policy_for(binding: ProviderBinding, max_bytes: int, max_tokens: int) -> PrivacyPolicy:
    base = _expanded_policy()
    channels = tuple(
        replace(channel, provider_binding=binding, max_bytes=max_bytes, max_tokens=max_tokens)
        if channel.channel is EgressChannel.LLM_INFERENCE
        else channel
        for channel in base.channel_policies
    )
    return replace(base, channel_policies=channels)


def _sized_budget() -> ReviewerExchangeBudget:
    budget = reviewer_exchange_budget(_policy_for(_CODEX, 0, 0), (_CODEX,))
    assert budget is not None and budget.first_token_limit is not None
    return budget


def test_the_benchmark_route_budget_is_the_model_context_less_its_reserves() -> None:
    budget = _sized_budget()
    assert budget == ReviewerExchangeBudget(MAX_SIZED_EXCHANGE_BYTES, 169_144, 152_760)
    # The ceilings setup writes leave the sized route its whole budget.
    assert _SETUP_CEILINGS == (MAX_SIZED_EXCHANGE_BYTES, 131_072)
    setup = reviewer_exchange_budget(_policy_for(_CODEX, *_SETUP_CEILINGS), (_CODEX,))
    assert setup == budget
    # An owner's lower ceilings (the old setup values, 256 KiB and 65,536 estimated tokens) bind
    # before the model does, in bytes or in tokens.
    owner = reviewer_exchange_budget(_policy_for(_CODEX, _CEILING, 65_536), (_CODEX,))
    assert owner == ReviewerExchangeBudget(_CEILING, 169_144, 152_760)
    tokens = reviewer_exchange_budget(_policy_for(_CODEX, _CEILING * 2, 40_000), (_CODEX,))
    assert tokens == ReviewerExchangeBudget(160_000, 169_144, 152_760)
    # Any route FinishUP cannot size keeps the bound it always had: unset ceilings, or the raised
    # ceilings setup writes, never widen it.
    for ceilings in ((0, 0), _SETUP_CEILINGS):
        unsized = reviewer_exchange_budget(_policy_for(_BINDING, *ceilings), (_BINDING,))
        assert unsized == ReviewerExchangeBudget(UNSIZED_EXCHANGE_BYTES)
    # With a fallback destination the narrower one binds.
    both = reviewer_exchange_budget(_policy_for(_CODEX, 0, 0), (_CODEX, _BINDING))
    assert both == ReviewerExchangeBudget(UNSIZED_EXCHANGE_BYTES)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("diff", "outputs"),
    ((_code_diff(files=8, lines=400), 0), (None, 16)),
    ids=("diff_parts", "captured_output_only"),
)
@pytest.mark.parametrize("ceilings", ((0, 0), _SETUP_CEILINGS), ids=("unset", "setup_written"))
async def test_a_sized_route_carries_the_whole_selection_the_byte_cap_trimmed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    diff: bytes | None,
    outputs: int,
    ceilings: tuple[int, int],
) -> None:
    """The cases the 262,144-byte cap narrowed (``test_a_case_filling_the_excerpt_budget...``)
    now reach the reviewer whole on the sized route, under unset ceilings and under the ones a
    fresh setup writes, and still fit its context."""

    built = _composed(monkeypatch, diff=diff, outputs=outputs)
    policy = _policy_for(_CODEX, *ceilings)
    result, gateway, _runtime = await _run(
        tmp_path, monkeypatch, _FINAL, policy=policy, primary=_CODEX
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    ((_media, history),) = gateway.exchanges
    sent = _encoded(history)
    budget = _sized_budget()
    assert len(sent) > UNSIZED_EXCHANGE_BYTES  # more than the old cap could carry
    assert len(sent) <= budget.byte_limit - REVIEWER_FRAME_BYTES
    assert reviewer_exchange_tokens(sent) <= budget.first_token_limit  # type: ignore[operator]
    # Nothing was narrowed: the planned case is the approved one.
    assert len(built) == 1
    packet = json.loads(history[1][1])
    assert "content_unselected" not in packet["review_packet"]["coverage"]["known_gaps"]


@pytest.mark.anyio
async def test_the_owner_ceiling_still_binds_on_a_sized_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An owner's lower 256 KiB / 65,536-token ceiling (the pre-#1118 setup values) is the
    owner's, not the model's: it is kept."""

    built = _composed(monkeypatch, diff=_code_diff(files=8, lines=400))
    policy = _policy_for(_CODEX, _CEILING, 65_536)
    result, gateway, _runtime = await _run(
        tmp_path, monkeypatch, _FINAL, policy=policy, primary=_CODEX
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    ((_media, history),) = gateway.exchanges
    assert len(_encoded(history)) <= _CEILING - REVIEWER_FRAME_BYTES
    assert len(built) > 1  # narrowed under the owner's ceiling


@pytest.mark.anyio
@pytest.mark.parametrize("ceilings", ((0, 0), _SETUP_CEILINGS), ids=("unset", "setup_written"))
async def test_an_unsized_route_with_unset_ceilings_keeps_the_old_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ceilings: tuple[int, int]
) -> None:
    _composed(monkeypatch, diff=_code_diff(files=8, lines=400))
    policy = _policy_for(_BINDING, *ceilings)
    result, gateway, _runtime = await _run(tmp_path, monkeypatch, _FINAL, policy=policy)
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    ((_media, history),) = gateway.exchanges
    assert len(_encoded(history)) <= UNSIZED_EXCHANGE_BYTES - REVIEWER_FRAME_BYTES


@pytest.mark.anyio
async def test_every_later_exchange_stays_within_the_token_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read after a first exchange planned up to the token budget is fitted to what the next
    exchange's tokens and bytes leave."""

    _composed(monkeypatch, diff=_decision_first_diff(40, 24, 12), outputs=35)

    def write() -> None:
        line = '{"id": %d, "m": "\\"a\\" b", "p": "C:\\\\x"}\n'
        (tmp_path / "work" / "rows.py").write_text("".join(line % n for n in range(300)))

    policy = _policy_for(_CODEX, 0, 0)
    result, gateway, _runtime = await _run(
        tmp_path, monkeypatch, _file_read("rows.py", write), _FINAL, policy=policy, primary=_CODEX
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    budget = _sized_budget()
    exchanges = [_encoded(history) for _media, history in gateway.exchanges]
    assert len(exchanges) == 2
    assert len(exchanges[0]) > UNSIZED_EXCHANGE_BYTES  # a first exchange the old cap refused
    assert reviewer_exchange_tokens(exchanges[0]) <= budget.first_token_limit  # type: ignore[operator]
    for sent in exchanges:
        assert len(sent) <= budget.byte_limit
        assert reviewer_exchange_tokens(sent) <= budget.token_limit  # type: ignore[operator]


@pytest.mark.anyio
async def test_an_exchange_over_the_token_budget_is_refused_and_never_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under the byte bound but over the model-token budget (non-ASCII text, one token per byte):
    nothing is sent and the review ends blocked by policy, never sent to overflow the context."""

    import finishup.application.reviewer_run as reviewer_run_module

    events: list[dict[str, Any]] = []
    record = ready_composition_module.record_bounded_counts_without_raising

    def counted(**kwargs: Any) -> str:  # noqa: ANN401
        events.append(kwargs)
        return record(**kwargs)

    monkeypatch.setattr(ready_composition_module, "record_bounded_counts_without_raising", counted)
    _composed(monkeypatch, diff=_code_diff(files=1, lines=20))
    real_catalog = reviewer_run_module.reviewer_catalog

    def heavy_catalog(roots: Any, reads: int) -> str:  # noqa: ANN401
        body = json.loads(real_catalog(roots, reads))
        body["reviewer_catalog"]["padding"] = "\u00e9" * 100_000  # 200,000 bytes and tokens
        return json.dumps(body, ensure_ascii=False)

    monkeypatch.setattr(reviewer_run_module, "reviewer_catalog", heavy_catalog)
    policy = _policy_for(_CODEX, 0, 0)
    result, gateway, _runtime = await _run(
        tmp_path, monkeypatch, _FINAL, policy=policy, primary=_CODEX
    )
    assert gateway.exchanges == []
    assert (result.status, result.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )
    (event,) = [e for e in events if e["operation"] == "semantic_disclosure_capacity_exceeded"]
    # Reported in the unit it exceeded: estimated tokens, under the byte bound.
    assert event["counts"]["semantic_disclosure_limit_tokens"] == 169_144
    assert event["counts"]["semantic_disclosure_attempted_tokens"] > 169_144
