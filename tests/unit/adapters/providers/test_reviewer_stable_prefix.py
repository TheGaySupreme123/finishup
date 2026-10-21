"""One reply schema per review keeps the reviewer's prompt prefix byte-stable (#1172).

A simulated three-read review runs the real loop, reviewer facade and evaluators over a scripted
Codex app-server and the stateless Responses rendering. What each turn sends beside its new
messages never changes and each turn only appends, so the provider can serve all the earlier
context from its prompt cache; announcing the final turn adds no model turn.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from builders.policy_cases import clm
from finishup.adapters.providers import reviewer_cache_telemetry as telemetry
from finishup.adapters.providers.openai_responses import OpenAIProfile, normalize_response
from finishup.adapters.providers.openai_responses import render_case as render_responses
from finishup.application.reviewer_exchange import REVIEWER_REPLY_SCHEMAS, ReviewerExchangeModel
from finishup.application.reviewer_loop import FINAL_TURN, ReviewerLoop, ReviewOutcome
from finishup.domain.privacy import ProviderBinding
from finishup.ports.semantic import (
    REVIEWER_EXCHANGE_MEDIA_TYPES,
    Deadline,
    ReviewerMessage,
    ReviewerSession,
    SemanticResult,
    SemanticResultUnavailable,
    decode_reviewer_exchange,
    reviewer_exchange,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from unit.adapters.providers.test_reviewer_cache_telemetry import (
    _exchange,  # pyright: ignore[reportPrivateUsage]
    _UsageRuntime,  # pyright: ignore[reportPrivateUsage]
)
from unit.adapters.providers.test_reviewer_completions import (
    _DEADLINE,  # pyright: ignore[reportPrivateUsage]
    _DIGEST,  # pyright: ignore[reportPrivateUsage]
    _FINAL,  # pyright: ignore[reportPrivateUsage]
    _FIRST,  # pyright: ignore[reportPrivateUsage]
    _api_binding,  # pyright: ignore[reportPrivateUsage]
    _api_profile,  # pyright: ignore[reportPrivateUsage]
    _case,  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _NoSteps,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_READ = canonical_encode(
    {
        "reply": {
            "action": "read_ledger",
            "args": {"cursor": None, "max_bytes": None, "refs": [str(clm(1))], "view": "claims"},
        }
    }
).decode()


class _ThreeReads:
    """A broker offering three reads, each answered with a fixed result envelope."""

    store = _NoSteps()
    history_roots = ()
    cited_refs: frozenset[str] = frozenset()
    text_by_ref: dict[str, list[str]] = {}

    def __init__(self) -> None:
        self.calls = 0

    def reads_allowed(self) -> bool:
        return self.calls < 3

    async def execute(self, action: object, expired: object, reply: str = "") -> str:
        self.calls += 1
        return canonical_encode({"call_index": self.calls, "status": "ok"}).decode()


async def _review(
    binding: ProviderBinding,
    dispatch: Any,
    session: ReviewerSession,  # noqa: ANN401
) -> ReviewOutcome:
    async def admissible(_roots: frozenset[str]) -> bool:
        return True

    async with ReviewerExchangeModel(binding, dispatch, session) as model:
        return await ReviewerLoop(
            model,
            cast(Any, _ThreeReads()),
            instruction="Review it.",
            packet="packet",
            deadline=_DEADLINE,
            history_admissible=admissible,
            final_reserve_seconds=1.0,  # the scripted 30-second deadline leaves time to read
            clock=_Clock().monotonic_seconds,
        ).run()


async def test_a_three_read_codex_review_keeps_every_turns_settings_byte_identical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    labels: list[object] = []

    def record(**fields: object) -> str:
        labels.append(cast(dict[str, object], fields["counts"]).get("reviewer_cache_miss"))
        return "err_74000000-0000-4000-8000-000000000001"

    monkeypatch.setattr(telemetry, "record_bounded_counts_without_raising", record)
    runtime = _UsageRuntime(
        [_READ, _READ, _READ, _FINAL],
        [
            [(90_000, 0, 50)],
            [(92_000, 89_984, 50)],
            [(94_000, 91_904, 50)],
            [(96_000, 93_952, 50)],
        ],
    )
    session = ReviewerSession("review-a", _DEADLINE)
    binding = ProviderBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0", "external"
    )
    media: list[str] = []
    requests = iter(f"req_74000000-0000-4000-8000-00000000000{n}" for n in range(1, 9))

    async def dispatch(payload: bytes, media_type: str, deadline: Deadline) -> SemanticResult:
        media.append(media_type)
        mode = "turn" if media_type == REVIEWER_EXCHANGE_MEDIA_TYPES["turn"] else "final"
        history = decode_reviewer_exchange(payload)
        return await _exchange(
            monkeypatch, runtime, session, history, next(requests), mode, REVIEWER_REPLY_SCHEMAS
        )

    outcome = await _review(binding, dispatch, session)
    assert (outcome.status, outcome.model_turns) == ("final", 4), outcome.reason

    turns = [params for method, params in runtime.requests if method == "turn/start"]
    beside = {
        canonical_encode(
            cast(JsonValue, {k: v for k, v in turn.items() if k not in {"input", "threadId"}})
        )
        for turn in turns
    }
    # The schema, model, effort and every other setting are the same bytes on all four turns.
    assert len(turns) == 4 and len(beside) == 1
    assert set(media) == {REVIEWER_EXCHANGE_MEDIA_TYPES["turn"]}
    # Each turn sends only what is new: the packet, each read result, and the last result with
    # the no-reads-left notice as a separate input.
    inputs = [[item["text"] for item in cast(list[dict[str, str]], t["input"])] for t in turns]
    assert inputs[0] == ["packet"]
    assert [len(texts) for texts in inputs[1:]] == [1, 1, 2] and inputs[3][1] == FINAL_TURN
    # With the schema stable, no turn after the first misses the cache.
    assert labels == ["first_turn", "none", "none", "none"]


async def test_codex_refuses_a_continuation_that_rewrites_what_the_thread_holds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _UsageRuntime([_READ, _FINAL], [[(90_000, 0, 50)], [(92_000, 0, 50)]])
    session = ReviewerSession("review-a", _DEADLINE)
    request = "req_74000000-0000-4000-8000-000000000011"
    await _exchange(monkeypatch, runtime, session, _FIRST, request)
    runtime.requests.clear()
    rewritten: tuple[ReviewerMessage, ...] = (
        ("system", "Review it."),
        ("user", "another packet"),
        ("assistant", _READ),
        ("user", "observation"),
        ("user", FINAL_TURN),
    )
    result = await _exchange(monkeypatch, runtime, session, rewritten, request)
    assert type(result) is SemanticResultUnavailable and runtime.requests == []
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.failure_stage == "case_invalid"
    await session.aclose()


async def test_responses_bodies_keep_one_schema_and_extend_the_previous_input() -> None:
    profile = _api_profile("responses")
    assert isinstance(profile, OpenAIProfile)
    binding = _api_binding(profile)
    answers = [_READ, _READ, _READ, _FINAL]
    bodies: list[dict[str, JsonValue]] = []

    async def dispatch(payload: bytes, media_type: str, deadline: Deadline) -> SemanticResult:
        mode = "turn" if media_type == REVIEWER_EXCHANGE_MEDIA_TYPES["turn"] else "final"
        case = _case(decode_reviewer_exchange(payload), binding, mode)
        rendered = render_responses(case, REVIEWER_REPLY_SCHEMAS)
        bodies.append(cast(dict[str, JsonValue], strict_json_parse(rendered.body)))
        response = type(
            "R", (), {"output_text": answers.pop(0), "status": "completed", "id": "resp"}
        )()
        exchange = reviewer_exchange(media_type, payload, REVIEWER_REPLY_SCHEMAS)
        return normalize_response(
            response, profile, policy_digest=_DIGEST, latency_ms=1, exchange=exchange
        )

    outcome = await _review(binding, dispatch, ReviewerSession("review-a", _DEADLINE))
    assert (outcome.status, outcome.model_turns) == ("final", 4), outcome.reason
    beside = {canonical_digest({k: v for k, v in body.items() if k != "input"}) for body in bodies}
    assert len(beside) == 1  # one schema, model, output limit and storage opt-out throughout
    inputs = [cast(list[JsonValue], body["input"]) for body in bodies]
    for before, after in zip(inputs, inputs[1:], strict=False):
        assert after[: len(before)] == before  # everything sent before, unchanged and first
    assert cast(dict[str, JsonValue], inputs[-1][-1]) == {"content": FINAL_TURN, "role": "user"}
