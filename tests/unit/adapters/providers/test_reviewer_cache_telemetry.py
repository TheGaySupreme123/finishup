"""Every reviewer exchange records its prompt-cache share and labels a miss (#1172).

The Codex runtime and the API transports are scripted; the evaluators, the reviewer session and
the diagnostics fence are the real ones. Records carry provider token counts, one closed label
and the review's first request id, never content.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from builders.codex_capability import profile_for, record_for
from finishup.adapters.providers import codex_app_server as codex
from finishup.adapters.providers import reviewer_cache_telemetry as telemetry
from finishup.domain.privacy import ProviderBinding
from finishup.domain.reviewer_cache import ExchangeCacheUsage
from finishup.observability.diagnostics import lookup_diagnostic_records
from finishup.ports.secret_memory import ProviderAttemptAuthBinding
from finishup.ports.semantic import (
    CURRENT_REVIEWER_SESSION,
    ExternalRuntimeAuthority,
    ReviewerMessage,
    ReviewerSession,
    SemanticResult,
    SemanticResultReply,
    reviewer_exchange,
)
from finishup.protocol.canonical import canonical_digest
from unit.adapters.providers.test_reviewer_completions import (
    _ACTION,  # pyright: ignore[reportPrivateUsage]
    _DEADLINE,  # pyright: ignore[reportPrivateUsage]
    _DIGEST,  # pyright: ignore[reportPrivateUsage]
    _FINAL,  # pyright: ignore[reportPrivateUsage]
    _FIRST,  # pyright: ignore[reportPrivateUsage]
    _SCHEMAS,  # pyright: ignore[reportPrivateUsage]
    _SECOND,  # pyright: ignore[reportPrivateUsage]
    _api_evaluate,  # pyright: ignore[reportPrivateUsage]
    _Capture,  # pyright: ignore[reportPrivateUsage]
    _case,  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _CodexRuntime,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_REQUESTS = tuple(f"req_73000000-0000-4000-8000-00000000000{n}" for n in range(1, 6))
_THIRD: tuple[ReviewerMessage, ...] = (*_SECOND, ("assistant", _ACTION), ("user", "observation2"))
type _Usage = tuple[int, int, int]  # input, cached input, output


def _breakdown(usage: _Usage) -> dict[str, int]:
    return {
        "inputTokens": usage[0],
        "cachedInputTokens": usage[1],
        "cacheWriteInputTokens": 0,
        "outputTokens": usage[2],
        "reasoningOutputTokens": 0,
        "totalTokens": usage[0] + usage[2],
    }


class _UsageRuntime(_CodexRuntime):
    """The scripted app-server, plus the cumulative usage snapshots each turn reports.

    ``turns`` lists, per ``turn/start``, the model requests that turn makes as ``last``
    breakdowns; the runtime keeps the thread's cumulative total the way Codex does. ``None`` is
    a snapshot the evaluator refuses as malformed.
    """

    def __init__(self, answers: list[str], turns: list[list[_Usage | None]]) -> None:
        super().__init__(profile_for(record_for(b"c", b"h", version="0.162.1")), answers)
        self.turns, self.total = turns, (0, 0, 0)
        self.tail: list[dict[str, object]] = []

    async def request(self, rid: int, method: str, params: object, timeout: float) -> object:
        result = await super().request(rid, method, params, timeout)
        if method == "turn/start":
            turn = cast(dict[str, Any], result)["turn"]["id"]
            snapshots: list[dict[str, object]] = []
            for last in self.turns.pop(0):
                if last is None:
                    usage: dict[str, object] = {"last": {}, "total": _breakdown(self.total)}
                else:
                    self.total = (
                        self.total[0] + last[0],
                        self.total[1] + last[1],
                        self.total[2] + last[2],
                    )
                    usage = {"last": _breakdown(last), "total": _breakdown(self.total)}
                params = {"threadId": "thr1", "turnId": turn, "tokenUsage": usage}
                notice: dict[str, object] = {
                    "method": "thread/tokenUsage/updated",
                    "params": params,
                }
                snapshots += [notice, notice]  # a repeated snapshot is not another request
            self.events[-1:-1] = [*snapshots, *self.tail]
        return result


async def _exchange(
    monkeypatch: pytest.MonkeyPatch,
    runtime: _CodexRuntime,
    session: ReviewerSession | None,
    history: tuple[ReviewerMessage, ...],
    request_id: str,
    mode: str = "turn",
) -> SemanticResult:
    async def launch(profile: object) -> _CodexRuntime:
        return runtime

    async def cleanup(value: object) -> str:
        return "terminated"

    monkeypatch.setattr(codex, "_launch", launch)
    monkeypatch.setattr(codex, "_cleanup", cleanup)
    binding = ProviderBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0", "external"
    )
    case = replace(_case(history, binding, mode), request_id=request_id)
    digest = "sha256:" + __import__("hashlib").sha256(case.payload).hexdigest()
    auth = ProviderAttemptAuthBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0",
        "semantic-review", _DIGEST, canonical_digest({"purpose": "semantic-review"}),
        "dsp_73000000-0000-4000-8000-000000000001", digest, 1, 30.0,
    )  # fmt: skip
    authority = ExternalRuntimeAuthority(
        auth.dispatch_id, digest, "hmac-sha256:" + "a" * 64, 1, 30.0
    )
    evaluator = codex.CodexAppServerEvaluator(
        runtime.profile, auth, authority, _Clock(), None, reply_schemas=_SCHEMAS
    )
    token = CURRENT_REVIEWER_SESSION.set(session)
    try:
        return await evaluator.evaluate(case, _DEADLINE)
    finally:
        CURRENT_REVIEWER_SESSION.reset(token)


@pytest.fixture
def records(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    seen: list[dict[str, object]] = []

    def record(**fields: object) -> str:
        seen.append(fields)
        return "err_73000000-0000-4000-8000-000000000001"

    monkeypatch.setattr(telemetry, "record_bounded_counts_without_raising", record)
    return seen


def _miss(record: dict[str, object]) -> object:
    return cast(dict[str, object], record["counts"]).get("reviewer_cache_miss")


async def test_codex_records_every_exchange_of_its_thread_under_the_review_request(
    monkeypatch: pytest.MonkeyPatch, records: list[dict[str, object]]
) -> None:
    runtime = _UsageRuntime(
        [_ACTION, _ACTION, _FINAL],
        [[(90_000, 0, 50)], [(92_000, 89_984, 50)], [(95_000, 0, 50)]],
    )
    session = ReviewerSession("review-a", _DEADLINE)
    first = await _exchange(monkeypatch, runtime, session, _FIRST, _REQUESTS[0])
    second = await _exchange(monkeypatch, runtime, session, _SECOND, _REQUESTS[1])
    # Today's final-only reply schema changes what every turn sends beside its messages.
    third = await _exchange(monkeypatch, runtime, session, _THIRD, _REQUESTS[2], "final")
    assert all(type(result) is SemanticResultReply for result in (first, second, third))
    await session.aclose()
    # Recording reads only what the runtime already reported: no request or round trip is added
    # (the second ``account/read`` is the existing pre-disclosure barrier).
    assert [method for method, _ in runtime.requests] == [
        "initialize",
        "account/read",
        "model/list",
        "thread/start",
        "account/read",
        "turn/start",
        "turn/start",
        "turn/start",
    ]

    assert [(r["component"], r["operation"], r["outcome"]) for r in records] == [
        ("codex_app_server", "exchange_cache", "completed")
    ] * 3
    # Every exchange names the review's first provider request: the attempt's row.
    assert {r["request_id"] for r in records} == {_REQUESTS[0]}
    assert [r["counts"] for r in records] == [
        {
            "reviewer_exchange_index": 1,
            "reviewer_model_requests": 1,
            "reviewer_input_tokens": 90_000,
            "reviewer_cached_input_tokens": 0,
            "reviewer_output_tokens": 50,
            "reviewer_prefix_cached_tokens": 0,
            "reviewer_prefix_tokens": 0,
            "reviewer_cache_write_input_tokens": 0,
            "reviewer_cache_miss": "first_turn",
        },
        {
            "reviewer_exchange_index": 2,
            "reviewer_model_requests": 1,
            "reviewer_input_tokens": 92_000,
            "reviewer_cached_input_tokens": 89_984,
            "reviewer_output_tokens": 50,
            "reviewer_prefix_cached_tokens": 89_984,
            "reviewer_prefix_tokens": 90_000,
            "reviewer_cache_write_input_tokens": 0,
            "reviewer_cache_miss": "none",
        },
        {
            "reviewer_exchange_index": 3,
            "reviewer_model_requests": 1,
            "reviewer_input_tokens": 95_000,
            "reviewer_cached_input_tokens": 0,
            "reviewer_output_tokens": 50,
            "reviewer_prefix_cached_tokens": 0,
            "reviewer_prefix_tokens": 92_000,
            "reviewer_cache_write_input_tokens": 0,
            "reviewer_cache_miss": "schema_or_settings_change",
        },
    ]


async def test_a_turn_of_several_requests_names_its_first_requests_reuse(
    monkeypatch: pytest.MonkeyPatch, records: list[dict[str, object]]
) -> None:
    # The second turn makes two model requests (say, an interim message then the answer).
    runtime = _UsageRuntime(
        [_ACTION, _FINAL], [[(90_000, 0, 50)], [(92_000, 0, 50), (93_000, 91_904, 60)]]
    )
    session = ReviewerSession("review-a", _DEADLINE)
    await _exchange(monkeypatch, runtime, session, _FIRST, _REQUESTS[0])
    await _exchange(monkeypatch, runtime, session, _SECOND, _REQUESTS[1])
    await session.aclose()
    counts = cast(dict[str, object], records[-1]["counts"])
    assert counts["reviewer_model_requests"] == 2
    assert counts["reviewer_input_tokens"] == 185_000
    assert counts["reviewer_cached_input_tokens"] == 91_904
    # Its first request reused nothing of the 90,000-token prefix: the turn is an unexplained miss
    # even though its second request was served from the cache.
    assert counts["reviewer_prefix_cached_tokens"] == 0
    assert counts["reviewer_cache_miss"] == "unexplained"


async def test_a_format_repair_that_missed_the_cache_is_a_retry(
    monkeypatch: pytest.MonkeyPatch, records: list[dict[str, object]]
) -> None:
    runtime = _UsageRuntime(["not json", _FINAL], [[(90_000, 0, 50)], [(90_100, 0, 40)]])
    session = ReviewerSession("review-a", _DEADLINE)
    await _exchange(monkeypatch, runtime, session, _FIRST, _REQUESTS[0])
    repair: tuple[ReviewerMessage, ...] = (*_FIRST, ("user", "format_error: output_not_json."))
    result = await _exchange(monkeypatch, runtime, session, repair, _REQUESTS[1])
    assert type(result) is SemanticResultReply
    await session.aclose()
    assert [_miss(r) for r in records] == ["first_turn", "retry"]


async def test_a_refused_compaction_is_still_recorded_and_labelled(
    monkeypatch: pytest.MonkeyPatch, records: list[dict[str, object]]
) -> None:
    runtime = _UsageRuntime([_ACTION], [[(240_000, 0, 50)]])
    runtime.tail = [{"method": "thread/compacted", "params": {}}]
    session = ReviewerSession("review-a", _DEADLINE)
    result = await _exchange(monkeypatch, runtime, session, _FIRST, _REQUESTS[0])
    assert type(result) is not SemanticResultReply  # the reviewer still refuses compaction
    await session.aclose()
    assert [(r["outcome"], _miss(r)) for r in records] == [("incomplete", "compaction")]


async def test_a_turn_after_a_silent_one_records_its_own_request_and_names_the_next_miss(
    monkeypatch: pytest.MonkeyPatch, records: list[dict[str, object]]
) -> None:
    # The first turn's request is never reported, so the thread's later totals include it.
    runtime = _UsageRuntime(
        [_ACTION, _ACTION, _FINAL], [[], [(92_000, 89_984, 50)], [(95_000, 0, 50)]]
    )
    session = ReviewerSession("review-a", _DEADLINE)
    await _exchange(monkeypatch, runtime, session, _FIRST, _REQUESTS[0])
    runtime.total = (90_000, 0, 50)
    await _exchange(monkeypatch, runtime, session, _SECOND, _REQUESTS[1])
    # The last turn changes what it sends beside its messages and reuses nothing.
    result = await _exchange(monkeypatch, runtime, session, _THIRD, _REQUESTS[2], "final")
    assert type(result) is SemanticResultReply
    await session.aclose()
    second, third = (cast(dict[str, object], r["counts"]) for r in records)
    # Turn 2 starts at its first snapshot's total less that request's own ``last``: it records
    # its own request, never the thread's 182,000, and has no known prefix to label against.
    assert second == {
        "reviewer_exchange_index": 2,
        "reviewer_model_requests": 1,
        "reviewer_input_tokens": 92_000,
        "reviewer_cached_input_tokens": 89_984,
        "reviewer_output_tokens": 50,
        "reviewer_prefix_cached_tokens": 89_984,
        "reviewer_cache_write_input_tokens": 0,
    }
    # That request is the prefix turn 3 could reuse, so turn 3's miss is still named.
    assert (third["reviewer_prefix_tokens"], third["reviewer_cache_miss"]) == (
        92_000,
        "schema_or_settings_change",
    )


async def test_a_turn_after_a_middle_turn_without_usage_never_claims_the_threads_usage(
    monkeypatch: pytest.MonkeyPatch, records: list[dict[str, object]]
) -> None:
    # Turn 2's request is in the thread's total but never reported, so turn 3's start is unknown.
    runtime = _UsageRuntime(
        [_ACTION, _ACTION, _FINAL], [[(90_000, 0, 50)], [], [(95_000, 92_032, 50)]]
    )
    session = ReviewerSession("review-a", _DEADLINE)
    await _exchange(monkeypatch, runtime, session, _FIRST, _REQUESTS[0])
    await _exchange(monkeypatch, runtime, session, _SECOND, _REQUESTS[1])
    runtime.total = (182_000, 89_984, 100)
    result = await _exchange(monkeypatch, runtime, session, _THIRD, _REQUESTS[2])
    assert type(result) is SemanticResultReply
    await session.aclose()
    # Turn 3 records its own 95,000 tokens, not the 187,000 the thread grew by since turn 1, and
    # no label: turn 2 left no known prefix.
    assert [
        (counts["reviewer_exchange_index"], counts["reviewer_input_tokens"], _miss(record))
        for record in records
        for counts in (cast(dict[str, object], record["counts"]),)
    ] == [(1, 90_000, "first_turn"), (3, 95_000, None)]


async def test_a_turn_that_had_a_snapshot_refused_records_no_counts(
    monkeypatch: pytest.MonkeyPatch, records: list[dict[str, object]]
) -> None:
    runtime = _UsageRuntime([_ACTION, _FINAL], [[(90_000, 0, 50)], [(92_000, 89_984, 50), None]])
    session = ReviewerSession("review-a", _DEADLINE)
    await _exchange(monkeypatch, runtime, session, _FIRST, _REQUESTS[0])
    result = await _exchange(monkeypatch, runtime, session, _SECOND, _REQUESTS[1])
    assert type(result) is SemanticResultReply  # usage is telemetry: the answer still counts
    await session.aclose()
    # The refused snapshot may have reported another request, so turn 2's counts are unknown.
    assert [cast(dict[str, object], r["counts"])["reviewer_exchange_index"] for r in records] == [1]


async def test_a_compaction_before_any_usage_is_still_labelled(
    monkeypatch: pytest.MonkeyPatch, records: list[dict[str, object]]
) -> None:
    runtime = _UsageRuntime([_ACTION, _FINAL], [[(90_000, 0, 50)], []])
    session = ReviewerSession("review-a", _DEADLINE)
    await _exchange(monkeypatch, runtime, session, _FIRST, _REQUESTS[0])
    runtime.tail = [{"method": "thread/compacted", "params": {}}]
    result = await _exchange(monkeypatch, runtime, session, _SECOND, _REQUESTS[1])
    assert type(result) is not SemanticResultReply  # the reviewer still refuses compaction
    await session.aclose()
    assert [(r["outcome"], r["counts"]) for r in records][1:] == [
        ("incomplete", {"reviewer_exchange_index": 2, "reviewer_cache_miss": "compaction"})
    ]


async def test_telemetry_that_fails_never_changes_the_exchange(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(**_fields: object) -> str:
        raise RuntimeError("diagnostics sink unavailable")

    monkeypatch.setattr(telemetry, "record_bounded_counts_without_raising", broken)
    runtime = _UsageRuntime([_FINAL], [[(90_000, 0, 50)]])
    session = ReviewerSession("review-a", _DEADLINE)
    result = await _exchange(monkeypatch, runtime, session, _FIRST, _REQUESTS[0])
    assert type(result) is SemanticResultReply
    await session.aclose()


class _UsageCapture(_Capture):
    """The in-memory API provider, answering with the usage each request reports.

    The input details report what was read from the cache and what was written to it (the rest of
    the input); a Chat Completions answer whose cached count is ``None`` has no details at all.
    """

    def __init__(self, route: str, usages: list[tuple[int, int | None, int]]) -> None:
        super().__init__(route)
        self.usages = usages

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await super().handle_async_request(request)
        payload = cast(dict[str, object], __import__("json").loads(response.content))
        used, cached, output = self.usages.pop(0)
        details = (
            None
            if cached is None
            else {"cached_tokens": cached, "cache_write_tokens": used - cached}
        )
        payload["usage"] = (
            {
                "input_tokens": used,
                "input_tokens_details": details,
                "output_tokens": output,
                "output_tokens_details": {"reasoning_tokens": 0},
                "total_tokens": used + output,
            }
            if self.route == "responses"
            else {
                "prompt_tokens": used,
                "completion_tokens": output,
                "total_tokens": used + output,
            }
            | ({} if details is None else {"prompt_tokens_details": details})
        )
        return httpx.Response(200, request=request, json=payload)


@pytest.mark.parametrize(
    ("route", "component"),
    [("responses", "openai_responses"), ("chat", "openai_chat_completions")],
)
async def test_api_routes_record_each_exchange_from_the_reported_usage(
    records: list[dict[str, object]], route: str, component: str
) -> None:
    session = ReviewerSession("review-a", _DEADLINE)
    token = CURRENT_REVIEWER_SESSION.set(session)
    try:
        for history, usage in ((_FIRST, (2_000, 0, 30)), (_SECOND, (2_200, 1_920, 30))):
            capture = _UsageCapture(route, [usage])
            result, *_rest = await _api_evaluate(route, history, capture, _Clock())
            assert type(result) is SemanticResultReply
    finally:
        CURRENT_REVIEWER_SESSION.reset(token)
    assert [(r["component"], r["operation"], _miss(r)) for r in records] == [
        (component, "exchange_cache", "first_turn"),
        (component, "exchange_cache", "none"),
    ]
    first, second = (cast(dict[str, object], r["counts"]) for r in records)
    assert (second["reviewer_prefix_tokens"], second["reviewer_prefix_cached_tokens"]) == (
        2_000,
        1_920,
    )
    # Both APIs report cache writes in their input details (Responses always), so both record them.
    assert [counts["reviewer_cache_write_input_tokens"] for counts in (first, second)] == [
        2_000,
        280,
    ]


async def test_a_chat_answer_without_a_cached_count_still_records_and_leaves_its_prefix(
    records: list[dict[str, object]],
) -> None:
    session = ReviewerSession("review-a", _DEADLINE)
    token = CURRENT_REVIEWER_SESSION.set(session)
    try:
        for history, usage in ((_FIRST, (2_000, None, 30)), (_SECOND, (2_200, 1_920, 30))):
            result, *_rest = await _api_evaluate(
                "chat", history, _UsageCapture("chat", [usage]), _Clock()
            )
            assert type(result) is SemanticResultReply
    finally:
        CURRENT_REVIEWER_SESSION.reset(token)
    first, second = (cast(dict[str, object], r["counts"]) for r in records)
    # The SDK types ``prompt_tokens_details`` as optional: an unreported cached count is left out,
    # never recorded as zero, and the request's input is still the next exchange's prefix.
    assert first == {
        "reviewer_exchange_index": 1,
        "reviewer_model_requests": 1,
        "reviewer_input_tokens": 2_000,
        "reviewer_output_tokens": 30,
        "reviewer_prefix_tokens": 0,
        "reviewer_cache_miss": "first_turn",
    }
    assert (second["reviewer_prefix_tokens"], second["reviewer_cache_miss"]) == (2_000, "none")


async def test_an_api_answer_without_usage_records_nothing(
    records: list[dict[str, object]],
) -> None:
    result, *_rest = await _api_evaluate("responses", _FIRST, _Capture("responses"), _Clock())
    assert type(result) is SemanticResultReply and records == []


def test_a_record_reaches_the_owner_ring_through_the_field_fence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    case = _case(_SECOND, ProviderBinding("p", "m", "e", "1.0.0", "external"))
    exchange = reviewer_exchange(case.media_type, case.payload, _SCHEMAS)
    session = ReviewerSession("review-a", _DEADLINE)
    session.cache.exchanges, session.cache.messages = 1, 2
    session.cache.request_id, session.cache.settings = _REQUESTS[0], canonical_digest({"s": 1})
    session.cache.prefix_tokens = 90_000
    telemetry.record_exchange_cache(
        component="codex_app_server",
        request_id=_REQUESTS[1],
        session=session,
        exchange=exchange,
        settings={"s": 1},
        usage=ExchangeCacheUsage(92_000, 0, 50, 1, 0, 92_000, cache_write_input_tokens=0),
        completed=True,
    )
    (found,) = lookup_diagnostic_records(request_id=_REQUESTS[0], root=tmp_path)
    assert found["operation"] == "exchange_cache" and found["reason"] == "completed"
    assert {name: found[name] for name in found if name.startswith("reviewer_")} == {
        "reviewer_exchange_index": 2,
        "reviewer_model_requests": 1,
        "reviewer_input_tokens": 92_000,
        "reviewer_cached_input_tokens": 0,
        "reviewer_cache_write_input_tokens": 0,
        "reviewer_output_tokens": 50,
        "reviewer_prefix_tokens": 90_000,
        "reviewer_prefix_cached_tokens": 0,
        "reviewer_cache_miss": "unexplained",
    }
    assert "observation" not in diagnostics.diagnostic_log_path(root=tmp_path).read_text()


def test_the_miss_label_passes_the_token_fence_and_nothing_else_does(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.observability.diagnostics as diagnostics
    from finishup.observability.logging import record_bounded_counts_without_raising

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    correlation = record_bounded_counts_without_raising(
        component="codex_app_server",
        operation="exchange_cache",
        outcome="completed",
        counts={"reviewer_cache_miss": "/home/user/PRIVATE", "reviewer_input_tokens": "PRIVATE"},
    )
    (found,) = lookup_diagnostic_records(correlation, root=tmp_path)
    assert found["reviewer_cache_miss"] == "unavailable"
    assert found["reviewer_input_tokens"] == "unavailable"
    assert "PRIVATE" not in diagnostics.diagnostic_log_path(root=tmp_path).read_text()
