"""Reviewer-loop completions on every route (#1118 unit 3): scripted transports only."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import deque
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import httpx
import jsonschema
import pytest

from builders.codex_capability import profile_for, record_for
from finishup.adapters.privacy import gateway
from finishup.adapters.providers import codex_app_server as codex
from finishup.adapters.providers.local_model import (
    LOCAL_REVIEWER_COMPLETION_PROTOCOL,
    LocalModelEndpointProfile,
    LocalModelEvaluator,
)
from finishup.adapters.providers.openai_chat_completions import (
    ChatCompletionsEvaluator,
    ChatCompletionsProfile,
)
from finishup.adapters.providers.openai_chat_completions import render_case as render_chat
from finishup.adapters.providers.openai_responses import (
    OneAttemptCredentialTransport,
    OpenAIProfile,
    OpenAIResponsesEvaluator,
    normalize_response,
    owner_declared_data_use_profile,
)
from finishup.adapters.providers.openai_responses import render_case as render_responses
from finishup.adapters.providers.reviewer_reply import (
    ReviewerReplyInvalid,
    decode_reviewer_reply,
    reviewer_reply_schema,
)
from finishup.application.reviewer_exchange import REVIEWER_REPLY_SCHEMAS, ReviewerExchangeModel
from finishup.application.reviewer_loop import (
    ReviewerLoop,
    ReviewerModelError,
    ReviewOutcome,
    Turn,
)
from finishup.domain.privacy import (
    ApprovedLocalDisclosureCase,
    ApprovedOutboundCase,
    DataCategory,
    LocalDisclosureSink,
    PrivacyOutcome,
    ProviderBinding,
)
from finishup.ports.secret_memory import ProviderAttemptAuthBinding
from finishup.ports.semantic import (
    CURRENT_REVIEWER_SESSION,
    REVIEWER_EXCHANGE_MEDIA_TYPES,
    Deadline,
    ExternalRuntimeAuthority,
    ReviewerMessage,
    ReviewerReplySchemas,
    ReviewerSession,
    SemanticResult,
    SemanticResultInvalid,
    SemanticResultLate,
    SemanticResultReply,
    SemanticResultSuccess,
    SemanticResultTimeout,
    SemanticResultUnavailable,
    decode_reviewer_exchange,
    encode_reviewer_exchange,
    reviewer_exchange,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)

pytestmark = pytest.mark.anyio

_NOW = datetime(2026, 10, 19, tzinfo=UTC)
_DIGEST = "sha256:" + "c" * 64
_SCHEMAS = ReviewerReplySchemas(
    turn={"type": "object", "properties": {"reply": {"anyOf": [{"type": "object"}]}}},
    final={"type": "object", "properties": {"reply": {"type": "object"}}},
)
_ACTION = '{"reply":{"action":"read_ledger","args":{"refs":["evt_1"],"view":"claims"}}}'
_FINAL = (
    '{"reply":{"final_judgment":{"conclusion":"no_material_discrepancy","prior_finding_verdicts":[],'
    '"review_summary":"The supplied packet was reviewed.","reviewer_challenges":[],"verified":[]}}}'
)
_DEADLINE = Deadline(_NOW + timedelta(seconds=30), 30.0)
_JUDGMENT = _FINAL[len('{"reply":{"final_judgment":') : -2]
_FIRST: tuple[ReviewerMessage, ...] = (("system", "Review it."), ("user", "packet"))
_SECOND: tuple[ReviewerMessage, ...] = (*_FIRST, ("assistant", _ACTION), ("user", "observation"))


_PAYLOAD = encode_reviewer_exchange(_FIRST)


def _case(history: tuple[ReviewerMessage, ...], binding: ProviderBinding, mode: str = "turn"):
    payload = encode_reviewer_exchange(history)
    return ApprovedOutboundCase(
        "cas_70000000-0000-4000-8000-000000000001",
        "req_70000000-0000-4000-8000-000000000001",
        payload,
        REVIEWER_EXCHANGE_MEDIA_TYPES["turn" if mode == "turn" else "final"],
        "finishup-reviewer-exchange-1.0.0",
        ("reviewer-exchange",),
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (),
        len(payload),
        8,
        binding,
        "semantic-review",
        "aut_70000000-0000-4000-8000-000000000001",
        _DIGEST,
        _DIGEST,
    )


def test_exchange_payload_is_the_closed_alternating_history() -> None:
    payload = encode_reviewer_exchange(_SECOND)
    assert decode_reviewer_exchange(payload) == _SECOND
    # The loop's format-repair notice follows a user turn; the malformed reply is never echoed.
    assert len(decode_reviewer_exchange(encode_reviewer_exchange((*_FIRST, ("user", "r"))))) == 3
    bad_histories: list[tuple[ReviewerMessage, ...]] = [
        _FIRST[:1],
        (*_FIRST, ("assistant", _ACTION)),
        (("user", "x"), ("user", "y")),
        (*_SECOND[:3], ("assistant", _ACTION), ("user", "y")),
    ]
    for bad in bad_histories:
        with pytest.raises(ValueError, match="reviewer_exchange_invalid"):
            encode_reviewer_exchange(bad)


def test_responses_exchange_sends_history_verbatim_with_schema_and_no_tools() -> None:
    binding = ProviderBinding("fireworks", "m", "fireworks-responses", "1.0.0", "external")
    first, second = _case(_FIRST, binding), _case(_SECOND, binding, "final")
    bodies = [render_responses(case, _SCHEMAS) for case in (first, second)]
    for case, rendered, schema in zip((first, second), bodies, (_SCHEMAS.turn, _SCHEMAS.final)):
        body = cast(dict[str, JsonValue], strict_json_parse(rendered.body))
        assert case.payload in rendered.body  # the gateway's verbatim-body invariant
        assert cast(dict[str, JsonValue], body["text"])["format"] == {
            "type": "json_schema",
            "name": "finishup_reviewer_reply",
            "strict": True,
            "schema": schema,
        }
        assert body["store"] is False and "tools" not in body
    # Each exchange is its own exact body, so each needs its own one-use transport.
    assert bodies[0].body_sha256 != bodies[1].body_sha256
    with pytest.raises(ValueError, match="reviewer_schema_unavailable"):
        render_responses(first)


def test_responses_reply_is_parsed_not_decoded_and_non_objects_are_invalid() -> None:
    profile = OpenAIProfile(
        provider_id="fireworks",
        model="m",
        endpoint_profile_id="fireworks-responses",
        endpoint_profile_version="1.0.0",
        timeout_seconds=60,
        supports_structured_outputs=True,
        data_use_profile=owner_declared_data_use_profile(
            reviewed_at=_NOW, expires_at=_NOW + timedelta(days=30), evidence_digest=_DIGEST
        ),
        host="api.fireworks.ai",
        base_path_prefix="/inference/v1",
    )

    def response(text: str) -> object:
        return type("R", (), {"output_text": text, "status": "completed", "id": "resp_1"})()

    exchange = reviewer_exchange(REVIEWER_EXCHANGE_MEDIA_TYPES["turn"], _PAYLOAD, _SCHEMAS)
    result = normalize_response(
        response(_ACTION), profile, policy_digest=_DIGEST, latency_ms=1, exchange=exchange
    )
    assert type(result) is SemanticResultReply and result.reply == strict_json_parse(
        _ACTION.encode()
    )
    assert gateway._result_outcome(result) == (  # pyright: ignore[reportPrivateUsage]
        PrivacyOutcome.COMPLETED,
        None,
    )
    invalid = normalize_response(
        response("[1]"), profile, policy_digest=_DIGEST, latency_ms=1, exchange=exchange
    )
    assert type(invalid) is SemanticResultInvalid


@pytest.mark.parametrize("enforcement", ["provider_enforced", "prompt_only"])
def test_chat_exchange_uses_plain_messages_and_refuses_prompt_only(enforcement: str) -> None:
    profile = ChatCompletionsProfile(
        provider_id="openrouter",
        model="m",
        endpoint_profile_id="openrouter-openai-chat-completions",
        endpoint_profile_version="1.0.0",
        timeout_seconds=60,
        structured_output_enforcement=enforcement,  # pyright: ignore[reportArgumentType]
        data_use_profile=owner_declared_data_use_profile(
            reviewed_at=_NOW, expires_at=_NOW + timedelta(days=30), evidence_digest=_DIGEST
        ),
        host="openrouter.ai",
        base_path_prefix="/api/v1",
    )
    case = _case(
        _SECOND,
        ProviderBinding("openrouter", "m", profile.endpoint_profile_id, "1.0.0", "external"),
    )
    if enforcement == "prompt_only":
        with pytest.raises(ValueError, match="chat_completions_reviewer_schema_unavailable"):
            render_chat(case, profile, _SCHEMAS)
        return
    rendered = render_chat(case, profile, _SCHEMAS)
    body = cast(dict[str, JsonValue], strict_json_parse(rendered.body))
    assert case.payload in rendered.body
    assert [m["role"] for m in cast(list[dict[str, str]], body["messages"])] == [
        "system",
        "user",
        "assistant",
        "user",
    ]
    assert "tools" not in body and "functions" not in body


class _Socket:
    service_generation = 1
    profile_digest = _DIGEST

    def __init__(self, answer: bytes) -> None:
        self.sent: list[bytes] = []
        self.answer = answer

    async def send(self, payload: bytes) -> None:
        self.sent.append(payload)

    async def receive(self, max_bytes: int) -> bytes:
        return self.answer

    def close(self) -> None:
        return None


class _Clock:
    def __init__(self) -> None:
        self.monotonic = 1.0

    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return self.monotonic


@pytest.mark.parametrize("protocol", [LOCAL_REVIEWER_COMPLETION_PROTOCOL, "1.0.0"])
async def test_local_exchange_needs_the_versioned_completion_contract(protocol: str) -> None:
    profile = LocalModelEndpointProfile(
        "local-test", "1.0.0", "local-test-endpoint", "1.0.0", "local-model", protocol, "1.2.0",
        30, "local-test-service", 0, 0, 0o600, _DIGEST, _DIGEST,
    )  # fmt: skip
    socket = _Socket(_FINAL.encode())
    binding = ProviderBinding(
        "local", "local-model", "local-test-endpoint", "1.0.0", "local_af_unix"
    )
    payload = encode_reviewer_exchange(_FIRST)
    case = ApprovedLocalDisclosureCase(
        "cas_70000000-0000-4000-8000-000000000002", "req_70000000-0000-4000-8000-000000000002",
        "ppr_70000000-0000-4000-8000-000000000002", payload, REVIEWER_EXCHANGE_MEDIA_TYPES["final"],
        ("reviewer-exchange",), (), (), len(payload), 8, LocalDisclosureSink.LOCAL_MODEL, binding,
        "semantic-review", _DIGEST, _DIGEST,
    )  # fmt: skip
    evaluator = LocalModelEvaluator(profile, socket, _Clock(), reply_schemas=_SCHEMAS)
    result = await evaluator.evaluate(case, _DEADLINE)
    if protocol != LOCAL_REVIEWER_COMPLETION_PROTOCOL:
        assert type(result) is SemanticResultUnavailable and socket.sent == []
        return
    assert type(result) is SemanticResultReply
    frame = cast(dict[str, JsonValue], strict_json_parse(socket.sent[0]))
    assert frame["protocol"] == protocol and frame["reply_schema"] == _SCHEMAS.final
    assert payload in socket.sent[0]
    assert result.provenance.schema_digest == canonical_digest(_SCHEMAS.final)


class _CodexRuntime:
    """A scripted app-server: one reply per ``turn/start``, in order."""

    def __init__(self, profile: codex.CodexAppServerProfile, answers: list[str]) -> None:
        self.profile = profile
        self.workdir = Path("/private/empty-attempt")
        self.pending_notifications: deque[dict[str, object]] = deque()
        self.answers = answers
        self.requests: list[tuple[str, dict[str, object]]] = []
        self.events: list[dict[str, object]] = []
        self.extra_event: dict[str, object] | None = None

    async def send(self, value: dict[str, object]) -> None:
        return None

    async def request(self, rid: int, method: str, params: object, timeout: float) -> object:
        self.requests.append((method, cast(dict[str, object], params or {})))
        if method == "initialize":
            agent = f"x/{self.profile.runtime_version} (Mac)"
            return {"codexHome": str(self.profile.codex_home), "userAgent": agent}
        if method == "account/read":
            return {"account": {"type": "chatgpt", "planType": "plus"}}
        if method == "model/list":
            efforts = [{"reasoningEffort": "high"}]
            return {"data": [{"id": self.profile.model, "supportedReasoningEfforts": efforts}]}
        if method == "thread/start":
            cwd = str(self.workdir)
            return {
                "thread": {"id": "thr1", "ephemeral": True, "path": None, "cwd": cwd},
                "cwd": cwd, "model": self.profile.model, "modelProvider": "openai",
                "sandbox": {"type": "readOnly", "networkAccess": False}, "instructionSources": [],
            }  # fmt: skip
        if method == "turn/start":
            turn = f"turn{len(self.answers)}"
            item = {"type": "agentMessage", "phase": "final_answer", "text": self.answers.pop(0)}
            done = {"threadId": "thr1", "turn": {"id": turn, "status": "completed", "error": None}}
            self.events = [{"method": "item/completed", "params": {"item": item}}]
            if self.extra_event is not None:
                self.events.insert(0, self.extra_event)
            self.events.append({"method": "turn/completed", "params": done})
            return {"turn": {"id": turn, "status": "inProgress"}}
        return {}

    async def read(self, timeout: float) -> dict[str, object]:
        return self.events.pop(0)


async def _codex_exchange(
    monkeypatch: pytest.MonkeyPatch,
    runtime: _CodexRuntime,
    session: ReviewerSession | None,
    history: tuple[ReviewerMessage, ...],
    cleanups: list[object],
    clock: _Clock | None = None,
) -> SemanticResult:
    async def launch(profile: object) -> _CodexRuntime:
        return runtime

    async def cleanup(value: object) -> str:
        cleanups.append(value)
        return "terminated"

    monkeypatch.setattr(codex, "_launch", launch)
    monkeypatch.setattr(codex, "_cleanup", cleanup)
    binding = ProviderBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0", "external"
    )
    case = _case(history, binding)
    digest = "sha256:" + __import__("hashlib").sha256(case.payload).hexdigest()
    auth = ProviderAttemptAuthBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0",
        "semantic-review", _DIGEST, canonical_digest({"purpose": "semantic-review"}), "dsp_70000000-0000-4000-8000-000000000001", digest,
        1, 30.0,
    )  # fmt: skip
    authority = ExternalRuntimeAuthority(
        auth.dispatch_id, digest, "hmac-sha256:" + "a" * 64, 1, 30.0
    )
    evaluator = codex.CodexAppServerEvaluator(
        runtime.profile, auth, authority, clock or _Clock(), None, reply_schemas=_SCHEMAS
    )
    token = CURRENT_REVIEWER_SESSION.set(session)
    try:
        return await evaluator.evaluate(case, _DEADLINE)
    finally:
        CURRENT_REVIEWER_SESSION.reset(token)


@pytest.mark.parametrize("version", sorted(codex.REVIEWER_LOOP_REVIEWED_RELEASES))
async def test_codex_keeps_one_thread_sends_only_new_input_and_cleans_up_at_the_end(
    monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version=version)), [_ACTION, _FINAL])
    session = ReviewerSession("review-a", _DEADLINE)
    cleanups: list[object] = []

    first = await _codex_exchange(monkeypatch, runtime, session, _FIRST, cleanups)
    assert type(first) is SemanticResultReply and first.reply == strict_json_parse(_ACTION.encode())
    assert first.provenance.runtime_evidence is not None
    assert first.provenance.runtime_evidence.process_cleanup == "retained" and cleanups == []
    init = dict(runtime.requests)["initialize"]
    assert cast(dict[str, object], init["capabilities"])["experimentalApi"] is True
    thread = dict(runtime.requests)["thread/start"]
    assert thread["environments"] == [] and thread["baseInstructions"] == "Review it."
    assert "dynamicTools" not in thread

    runtime.requests.clear()
    second = await _codex_exchange(monkeypatch, runtime, session, _SECOND, cleanups)
    assert type(second) is SemanticResultReply and second.reply == strict_json_parse(
        _FINAL.encode()
    )
    # The same thread: no launch, no new thread, only the observation, the schema every turn.
    assert [method for method, _ in runtime.requests] == ["turn/start"]
    turn = runtime.requests[0][1]
    assert turn["input"] == [{"type": "text", "text": "observation"}]
    assert turn["threadId"] == "thr1" and turn["outputSchema"] == _SCHEMAS.turn
    # The review's session, not the adapter, ends the thread: on every exit of the review.
    assert cleanups == []
    assert await session.aclose() == "terminated" and cleanups == [runtime]


async def test_codex_continuation_without_its_session_fails_before_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version="0.162.1")), [_FINAL])
    session = ReviewerSession("review-a", _DEADLINE)
    result = await _codex_exchange(monkeypatch, runtime, session, _SECOND, [])
    assert type(result) is SemanticResultUnavailable and runtime.requests == []
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and not evidence.case_disclosed
    assert evidence.failure_stage == "case_invalid"


@pytest.mark.parametrize(
    ("suffix", "accepted"),
    [
        pytest.param((("user", "observation"), ("user", "final phase")), True, id="result+notice"),
        pytest.param((), False, id="nothing-new"),
        pytest.param(tuple(("user", f"m{n}") for n in range(3)), False, id="three-new"),
    ],
)
async def test_codex_continuation_takes_at_most_two_new_user_messages(
    monkeypatch: pytest.MonkeyPatch, suffix: tuple[ReviewerMessage, ...], accepted: bool
) -> None:
    """#1173: the final-phase notice follows the last read result, two new user messages on the
    held thread; anything else that does not extend the thread is still refused before sending."""

    runtime = _CodexRuntime(
        profile_for(record_for(b"c", b"h", version="0.162.1")), [_ACTION, _FINAL, _FINAL]
    )
    session = ReviewerSession("review-a", _DEADLINE)
    cleanups: list[object] = []
    await _codex_exchange(monkeypatch, runtime, session, _FIRST, cleanups)
    # The answer the thread holds, then the suffix; and a history that rewrote the packet.
    held: tuple[ReviewerMessage, ...] = (*_FIRST, ("assistant", _ACTION))
    rewritten: tuple[ReviewerMessage, ...] = (
        ("system", "Review it."),
        ("user", "another packet"),
        *held[2:],
        *suffix,
    )
    cases: list[tuple[tuple[ReviewerMessage, ...], bool]] = (
        [((*held, *suffix), accepted), (rewritten, False)] if suffix else [(_FIRST, False)]
    )
    for history, ok in cases:
        runtime.requests.clear()
        result = await _codex_exchange(monkeypatch, runtime, session, history, cleanups)
        if ok:
            assert type(result) is SemanticResultReply
            (turn,) = [params for method, params in runtime.requests if method == "turn/start"]
            assert turn["input"] == [{"type": "text", "text": t} for _, t in suffix]
            await session.aclose()
            return
        assert type(result) is SemanticResultUnavailable and runtime.requests == []
        evidence = result.provenance.runtime_evidence
        assert evidence is not None and evidence.failure_stage == "case_invalid"
    await session.aclose()


async def test_codex_first_turn_carries_the_packet_and_the_read_catalog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The service's first exchange is the packet then the catalog: both open the one thread."""

    runtime = _CodexRuntime(
        profile_for(record_for(b"c", b"h", version="0.162.1")), [_ACTION, _FINAL]
    )
    session = ReviewerSession("review-a", _DEADLINE)
    first: tuple[ReviewerMessage, ...] = (*_FIRST, ("user", "catalog"))
    cleanups: list[object] = []

    opened = await _codex_exchange(monkeypatch, runtime, session, first, cleanups)
    assert type(opened) is SemanticResultReply
    turn = dict(runtime.requests)["turn/start"]
    assert turn["input"] == [
        {"type": "text", "text": "packet"},
        {"type": "text", "text": "catalog"},
    ]

    runtime.requests.clear()
    nxt: tuple[ReviewerMessage, ...] = (*first, ("assistant", _ACTION), ("user", "observation"))
    second = await _codex_exchange(monkeypatch, runtime, session, nxt, cleanups)
    assert type(second) is SemanticResultReply
    assert [method for method, _ in runtime.requests] == ["turn/start"]
    assert runtime.requests[0][1]["input"] == [{"type": "text", "text": "observation"}]
    assert await session.aclose() == "terminated" and cleanups == [runtime]


@pytest.mark.parametrize(
    ("event", "stage"),
    [
        ({"method": "item/started", "params": {"item": {"type": "plan"}}}, "event_forbidden"),
        (
            {"method": "item/started", "params": {"item": {"type": "contextCompaction"}}},
            "event_forbidden",
        ),
        ({"method": "thread/compacted", "params": {}}, "event_forbidden"),
        (
            {"id": 9, "method": "item/tool/requestUserInput", "params": {}},
            "tool_request_forbidden",
        ),
        ({"method": "warning", "params": {"message": "m", "threadId": "thr1"}}, "runtime_warning"),
    ],
)
async def test_codex_reviewer_turn_aborts_on_utility_compaction_request_or_warning(
    monkeypatch: pytest.MonkeyPatch, event: dict[str, object], stage: str
) -> None:
    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version="0.162.1")), [_ACTION])
    runtime.extra_event = event
    session = ReviewerSession("review-a", _DEADLINE)
    cleanups: list[object] = []
    result = await _codex_exchange(monkeypatch, runtime, session, _FIRST, cleanups)
    assert type(result) is not SemanticResultReply and cleanups == [runtime]
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.failure_stage == stage


def test_the_reviewer_loop_is_reviewed_only_for_source_verified_releases() -> None:
    assert codex.REVIEWER_LOOP_REVIEWED_RELEASES == frozenset({"0.162.1", "0.164.0"})


@pytest.mark.parametrize("version", ["0.159.0", "0.163.0"])
async def test_codex_reviewer_loop_refuses_an_unreviewed_release_before_launch(
    monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version=version)), [_ACTION])
    session = ReviewerSession("review-a", _DEADLINE)
    result = await _codex_exchange(monkeypatch, runtime, session, _FIRST, [])
    assert type(result) is SemanticResultUnavailable and runtime.requests == []


async def test_closing_the_session_cleans_up_a_retained_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version="0.162.1")), [_ACTION])
    session = ReviewerSession("review-a", _DEADLINE)
    cleanups: list[object] = []
    await _codex_exchange(monkeypatch, runtime, session, _FIRST, cleanups)
    await session.aclose()
    assert cleanups == [runtime] and session.held is None
    # A closed session admits no further exchange: nothing is launched or sent.
    runtime.requests.clear()
    late = await _codex_exchange(monkeypatch, runtime, session, _SECOND, cleanups)
    assert type(late) is SemanticResultUnavailable and runtime.requests == []


async def test_facade_refuses_a_reply_from_another_route() -> None:
    binding = ProviderBinding(
        "openai-codex", "m", "codex-chatgpt-subscription", "1.0.0", "external"
    )
    seen: list[str] = []

    async def dispatch(payload: bytes, media_type: str, deadline: Deadline) -> SemanticResult:
        seen.append(media_type)
        reply = normalize_response(
            type("R", (), {"output_text": _FINAL, "status": "completed", "id": "r"})(),
            OpenAIProfile(
                provider_id="openai",
                model="gpt",
                endpoint_profile_id="openai-responses",
                endpoint_profile_version="1.0.0",
                timeout_seconds=60,
                supports_structured_outputs=True,
                data_use_profile=owner_declared_data_use_profile(
                    reviewed_at=_NOW, expires_at=_NOW + timedelta(days=30), evidence_digest=_DIGEST
                ),
            ),  # fmt: skip
            policy_digest=_DIGEST,
            latency_ms=1,
            exchange=reviewer_exchange(media_type, payload, _SCHEMAS),
        )
        return reply

    model = ReviewerExchangeModel(binding, dispatch, ReviewerSession("review-a", _DEADLINE))
    deadline = _DEADLINE
    turns = [Turn(role, text) for role, text in _FIRST]
    final_schema = reviewer_reply_schema(reads_allowed=False, strict=True)
    with pytest.raises(ReviewerModelError, match="reviewer_exchange_route_mismatch"):
        await model.complete(turns, final_schema, deadline=deadline)
    assert seen == [REVIEWER_EXCHANGE_MEDIA_TYPES["final"]]
    same = replace(
        model, binding=replace(binding, endpoint_profile_id="openai-responses", model_id="gpt")
    )
    assert await same.complete(turns, final_schema, deadline=deadline) == strict_json_parse(
        _FINAL.encode()
    )
    with pytest.raises(ReviewerModelError, match="reviewer_schema_unknown"):
        await same.complete(turns, {"type": "object"}, deadline=deadline)


async def test_codex_keeps_a_malformed_turn_for_the_one_format_repair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _CodexRuntime(
        profile_for(record_for(b"c", b"h", version="0.162.1")), ["not json", _FINAL]
    )
    session = ReviewerSession("review-a", _DEADLINE)
    cleanups: list[object] = []
    first = await _codex_exchange(monkeypatch, runtime, session, _FIRST, cleanups)
    assert type(first) is SemanticResultInvalid and cleanups == []
    runtime.requests.clear()
    repair: tuple[ReviewerMessage, ...] = (*_FIRST, ("user", "format_error: output_not_json."))
    second = await _codex_exchange(monkeypatch, runtime, session, repair, cleanups)
    assert type(second) is SemanticResultReply and cleanups == []
    assert [method for method, _ in runtime.requests] == ["turn/start"]


async def test_v1_codex_empty_answer_keeps_its_thread_for_the_one_repair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1118 V1: an empty final answer is judged after ``turn/completed``, so it is retained."""

    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version="0.162.1")), ["", _FINAL])
    session = ReviewerSession("review-a", _DEADLINE)
    cleanups: list[object] = []
    first = await _codex_exchange(monkeypatch, runtime, session, _FIRST, cleanups)
    evidence = first.provenance.runtime_evidence
    assert type(first) is SemanticResultInvalid and evidence is not None
    assert (evidence.failure_stage, evidence.process_cleanup) == ("output_empty", "retained")
    assert cleanups == []
    runtime.requests.clear()
    repair: tuple[ReviewerMessage, ...] = (*_FIRST, ("user", "format_error: output_not_json."))
    second = await _codex_exchange(monkeypatch, runtime, session, repair, cleanups)
    assert type(second) is SemanticResultReply
    assert runtime.requests == [("turn/start", runtime.requests[0][1])]
    assert runtime.requests[0][1]["input"] == [
        {"type": "text", "text": "format_error: output_not_json."}
    ]
    await session.aclose()


async def test_v1_codex_review_never_reopens_a_lost_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1118 V1: once a review's thread is gone, no history reopens it or resends the packet."""

    runtime = _CodexRuntime(
        profile_for(record_for(b"c", b"h", version="0.162.1")), [_FINAL, _FINAL]
    )
    runtime.extra_event = {"method": "warning", "params": {"message": "x"}}
    session = ReviewerSession("review-a", _DEADLINE)
    cleanups: list[object] = []
    first = await _codex_exchange(monkeypatch, runtime, session, _FIRST, cleanups)
    assert type(first) is not SemanticResultReply and cleanups == [runtime]
    runtime.requests.clear()
    runtime.extra_event = None
    # A user-only repair history looks like an opening; it must not open a second thread.
    repair: tuple[ReviewerMessage, ...] = (*_FIRST, ("user", "format_error: output_not_json."))
    second = await _codex_exchange(monkeypatch, runtime, session, repair, cleanups)
    evidence = second.provenance.runtime_evidence
    assert type(second) is SemanticResultUnavailable and runtime.requests == []
    assert evidence is not None and not evidence.case_disclosed
    assert evidence.failure_stage == "case_invalid"


async def test_v1_facade_ends_the_review_when_a_malformed_answer_lost_its_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1118 V1: a malformed answer earns a repair only while its Codex thread is retained."""

    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version="0.162.1")), [""])
    session = ReviewerSession("review-a", _DEADLINE)
    retained = await _codex_exchange(monkeypatch, runtime, session, _FIRST, [])
    evidence = retained.provenance.runtime_evidence
    assert type(retained) is SemanticResultInvalid and evidence is not None
    lost = SemanticResultInvalid(
        replace(
            retained.provenance,
            runtime_evidence=replace(evidence, process_cleanup="terminated"),
        ),
        retained.raw_size,
    )
    binding = ProviderBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0", "external"
    )
    turns = [Turn(role, text) for role, text in _FIRST]
    for result, raised in ((retained, ReviewerReplyInvalid), (lost, ReviewerModelError)):

        async def dispatch(
            payload: bytes, media_type: str, deadline: Deadline, result: SemanticResult = result
        ) -> SemanticResult:
            return result

        model = ReviewerExchangeModel(binding, dispatch, session)
        with pytest.raises(raised):
            await model.complete(turns, REVIEWER_REPLY_SCHEMAS.turn, deadline=_DEADLINE)
    await session.aclose()


async def test_v2_codex_model_verification_notification_is_discarded_unread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1118 V2: 0.162.1 ``model/verification`` is account bookkeeping, not a forbidden event."""

    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version="0.162.1")), [_FINAL])
    runtime.extra_event = {
        "method": "model/verification",
        "params": {"threadId": "thr1", "turnId": "turn1", "verifications": ["canary"]},
    }
    session = ReviewerSession("review-a", _DEADLINE)
    result = await _codex_exchange(monkeypatch, runtime, session, _FIRST, [])
    evidence = result.provenance.runtime_evidence
    assert type(result) is SemanticResultReply, evidence
    assert evidence is not None and evidence.failure_stage is None
    assert "canary" not in repr(result)
    await session.aclose()


# -- review round 1 regressions (R1-R6) ------------------------------------------------------------


def _api_profile(route: str) -> OpenAIProfile | ChatCompletionsProfile:
    data_use = owner_declared_data_use_profile(
        reviewed_at=_NOW, expires_at=_NOW + timedelta(days=30), evidence_digest=_DIGEST
    )
    if route == "responses":
        return OpenAIProfile(
            provider_id="fireworks", model="m", endpoint_profile_id="fireworks-responses",
            endpoint_profile_version="1.0.0", timeout_seconds=60, data_use_profile=data_use,
            host="api.fireworks.ai", base_path_prefix="/inference/v1",
            supports_structured_outputs=True,
        )  # fmt: skip
    return ChatCompletionsProfile(
        provider_id="openrouter", model="m", endpoint_profile_id="openrouter-openai-chat-completions",
        endpoint_profile_version="1.0.0", timeout_seconds=60, data_use_profile=data_use,
        host="openrouter.ai", base_path_prefix="/api/v1",
        structured_output_enforcement="provider_enforced",
    )  # fmt: skip


def _api_binding(profile: OpenAIProfile | ChatCompletionsProfile) -> ProviderBinding:
    return ProviderBinding(
        profile.provider_id, profile.model, profile.endpoint_profile_id, "1.0.0", "external"
    )


class _Capture(httpx.AsyncBaseTransport):
    """An in-memory provider: records each request body; may advance the clock or fail."""

    def __init__(
        self, route: str, clock: _Clock | None = None, fail: bool = False, judgment: bool = False
    ) -> None:
        self.route, self.clock, self.fail = route, clock, fail
        self.text = _JUDGMENT if judgment else _FINAL
        self.bodies: list[bytes] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(await request.aread())
        if self.clock is not None:
            self.clock.monotonic = 31.0  # the answer arrives after the deadline
        if self.fail:
            raise httpx.ReadTimeout("scripted timeout")
        message = {"type": "message", "content": [{"type": "output_text", "text": self.text}]}
        reply = {"role": "assistant", "content": self.text}
        choice = {"index": 0, "finish_reason": "stop", "message": reply}
        payload = (
            {"id": "resp_1", "status": "completed", "output": [message]}
            if self.route == "responses"
            else {"id": "chatcmpl_1", "choices": [choice]}
        )
        return httpx.Response(200, request=request, json=payload)


class _Credential:
    def __init__(self) -> None:
        self.calls = 0

    async def authorize_attempt(self, binding: object, callback: Any) -> object:
        self.calls += 1
        return await callback.inject_and_start(memoryview(b"nonsecret-review-fixture"))


async def _api_evaluate(
    route: str, history: tuple[ReviewerMessage, ...] | None, capture: _Capture, clock: _Clock
) -> tuple[SemanticResult, bytes, _Credential, OneAttemptCredentialTransport]:
    """One exchange (``None``: a one-shot case) through the real pinned SDK, offline."""

    profile = _api_profile(route)
    case = _case(_FIRST if history is None else history, _api_binding(profile))
    if history is None:
        case = replace(case, payload=b'{"case":1}', media_type="application/json", byte_count=10)
    rendered = (
        render_responses(case, REVIEWER_REPLY_SCHEMAS)
        if isinstance(profile, OpenAIProfile)
        else render_chat(case, profile, REVIEWER_REPLY_SCHEMAS)
    )
    credential = _Credential()
    binding = ProviderAttemptAuthBinding(
        profile.provider_id, profile.model, profile.endpoint_profile_id, "1.0.0",
        "semantic-review", _DIGEST, canonical_digest({"purpose": "semantic-review"}),
        "dsp_70000000-0000-4000-8000-000000000001", rendered.body_sha256, 1, 30.0,
    )  # fmt: skip
    transport = OneAttemptCredentialTransport(
        rendered=rendered, credential=cast(Any, credential), binding=binding,
        host=profile.host, port=profile.port, path=profile.path,
    )  # fmt: skip
    inner = cast(Any, transport)
    await inner._inner.aclose()
    inner._inner = capture  # only the network hop is replaced; the exact-body guard stays
    evaluator = (
        OpenAIResponsesEvaluator(profile, transport, clock, reply_schemas=REVIEWER_REPLY_SCHEMAS)
        if isinstance(profile, OpenAIProfile)
        else ChatCompletionsEvaluator(
            profile, transport, clock, reply_schemas=REVIEWER_REPLY_SCHEMAS
        )
    )
    return await evaluator.evaluate(case, _DEADLINE), rendered.body, credential, transport


@pytest.mark.parametrize("route", ["responses", "chat"])
@pytest.mark.parametrize("history", [_FIRST, _SECOND, None], ids=["initial", "next", "one-shot"])
async def test_r1_real_sdk_sends_the_audited_body_once(
    route: str, history: tuple[ReviewerMessage, ...] | None
) -> None:
    capture = _Capture(route, judgment=history is None)
    result, body, credential, transport = await _api_evaluate(route, history, capture, _Clock())
    assert type(result) is (SemanticResultSuccess if history is None else SemanticResultReply)
    assert credential.calls == 1 and capture.bodies == [body]
    with pytest.raises(RuntimeError, match="already_consumed"):
        await transport.handle_async_request(httpx.Request("POST", "https://x/y", content=body))


async def test_r2_identical_reviews_keep_their_own_threads(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = profile_for(record_for(b"c", b"h", version="0.162.1"))
    a, b = _CodexRuntime(profile, [_ACTION, _FINAL]), _CodexRuntime(profile, [_ACTION, _FINAL])
    review_a, review_b = (
        ReviewerSession("review-a", _DEADLINE),
        ReviewerSession("review-b", _DEADLINE),
    )
    cleanups: list[object] = []
    await _codex_exchange(monkeypatch, a, review_a, _FIRST, cleanups)
    await _codex_exchange(monkeypatch, b, review_b, _FIRST, cleanups)
    a.requests.clear()
    b.requests.clear()
    result = await _codex_exchange(monkeypatch, a, review_a, _SECOND, cleanups)
    assert type(result) is SemanticResultReply
    assert [method for method, _ in a.requests] == ["turn/start"] and b.requests == []
    await review_a.aclose()
    await review_b.aclose()
    assert cleanups == [a, b]


async def test_r3_close_drains_an_inflight_turn_and_retains_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered, release = asyncio.Event(), asyncio.Event()

    class _Held(_CodexRuntime):
        async def read(self, timeout: float) -> dict[str, object]:
            entered.set()
            await release.wait()
            return await super().read(timeout)

    runtime = _Held(profile_for(record_for(b"c", b"h", version="0.162.1")), [_ACTION])
    session = ReviewerSession("review-a", _DEADLINE)
    cleanups: list[object] = []
    turn = asyncio.create_task(_codex_exchange(monkeypatch, runtime, session, _FIRST, cleanups))
    await asyncio.wait_for(entered.wait(), 5)
    observed: list[int] = []

    async def close() -> None:
        await session.aclose()
        observed.append(len(cleanups))  # cleanup is done when close returns

    closing = asyncio.create_task(close())
    release.set()
    result = await turn
    await closing
    assert cleanups == [runtime] and observed == [1] and session.held is None
    assert result.provenance.runtime_evidence is not None
    assert result.provenance.runtime_evidence.process_cleanup == "terminated"


@pytest.mark.parametrize("route", ["responses", "chat"])
async def test_r4_api_answer_after_the_deadline_is_late(route: str) -> None:
    clock = _Clock()
    result, *_ = await _api_evaluate(route, _FIRST, _Capture(route, clock), clock)
    assert type(result) is SemanticResultLate


def _local(protocol: str = LOCAL_REVIEWER_COMPLETION_PROTOCOL) -> LocalModelEndpointProfile:
    return LocalModelEndpointProfile(
        "local-test", "1.0.0", "local-test-endpoint", "1.0.0", "local-model", protocol, "1.2.0",
        30, "local-test-service", 0, 0, 0o600, _DIGEST, _DIGEST,
    )  # fmt: skip


def _local_case() -> ApprovedLocalDisclosureCase:
    binding = ProviderBinding(
        "local", "local-model", "local-test-endpoint", "1.0.0", "local_af_unix"
    )
    return ApprovedLocalDisclosureCase(
        "cas_70000000-0000-4000-8000-000000000003", "req_70000000-0000-4000-8000-000000000003",
        "ppr_70000000-0000-4000-8000-000000000003", _PAYLOAD, REVIEWER_EXCHANGE_MEDIA_TYPES["turn"],
        ("reviewer-exchange",), (), (), len(_PAYLOAD), 8, LocalDisclosureSink.LOCAL_MODEL, binding,
        "semantic-review", _DIGEST, _DIGEST,
    )  # fmt: skip


async def test_r4_local_answer_after_the_deadline_is_not_used() -> None:
    clock = _Clock()

    class _Late(_Socket):
        async def receive(self, max_bytes: int) -> bytes:
            clock.monotonic = 31.0
            return self.answer

    evaluator = LocalModelEvaluator(_local(), _Late(_FINAL.encode()), clock, reply_schemas=_SCHEMAS)
    result = await evaluator.evaluate(_local_case(), _DEADLINE)
    assert type(result) is SemanticResultTimeout
    assert result.provenance.schema_digest == canonical_digest(_SCHEMAS.turn)


async def test_r4_local_receive_ends_at_the_original_deadline() -> None:
    class _RealClock(_Clock):
        def monotonic_seconds(self) -> float:
            return time.monotonic()

    class _Silent(_Socket):
        async def receive(self, max_bytes: int) -> bytes:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    evaluator = LocalModelEvaluator(_local(), _Silent(b""), _RealClock(), reply_schemas=_SCHEMAS)
    deadline = Deadline(_NOW + timedelta(seconds=0.05), time.monotonic() + 0.05)
    # The outer bound only keeps a regression from hanging the suite; the result is observed.
    result = await asyncio.wait_for(evaluator.evaluate(_local_case(), deadline), 5)
    assert type(result) is SemanticResultTimeout


async def test_r4_codex_answer_after_the_deadline_is_not_a_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()

    class _Late(_CodexRuntime):
        async def read(self, timeout: float) -> dict[str, object]:
            message = await super().read(timeout)
            if message.get("method") == "turn/completed":
                clock.monotonic = 31.0
            return message

    runtime = _Late(profile_for(record_for(b"c", b"h", version="0.162.1")), [_FINAL])
    session = ReviewerSession("review-a", _DEADLINE)
    cleanups: list[object] = []
    result = await _codex_exchange(monkeypatch, runtime, session, _FIRST, cleanups, clock)
    assert type(result) is not SemanticResultReply and session.held is None
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.failure_stage == "deadline_expired"
    assert cleanups == [runtime]


class _NoSteps:
    async def reserve(self, kind: str, ordinal: int, selector: bytes) -> None:
        return None

    async def capture(self, kind: str, ordinal: int, result: bytes) -> None:
        return None

    async def usage(self) -> tuple[int, int]:
        return 0, 0


class _NoReads:
    history_roots = ()
    store = _NoSteps()
    cited_refs: frozenset[str] = frozenset()
    text_by_ref: dict[str, list[str]] = {}

    def reads_allowed(self) -> bool:
        return False


async def _loop(dispatch: Any, clock: _Clock) -> ReviewOutcome:
    profile = _api_profile("responses")
    model = ReviewerExchangeModel(
        _api_binding(profile), dispatch, ReviewerSession("review-a", _DEADLINE)
    )

    async def admissible(roots: frozenset[str]) -> bool:
        return True

    async with model:
        return await ReviewerLoop(
            model, cast(Any, _NoReads()), instruction="Review it.", packet="packet",
            deadline=_DEADLINE, history_admissible=admissible, clock=clock.monotonic_seconds,
        ).run()  # fmt: skip


async def test_r4_loop_does_not_accept_a_final_after_the_deadline() -> None:
    profile, clock = _api_profile("responses"), _Clock()
    assert isinstance(profile, OpenAIProfile)

    async def dispatch(payload: bytes, media_type: str, deadline: Deadline) -> SemanticResult:
        clock.monotonic = 31.0
        response = type("R", (), {"output_text": _FINAL, "status": "completed", "id": "r"})()
        exchange = reviewer_exchange(media_type, payload, REVIEWER_REPLY_SCHEMAS)
        return normalize_response(
            response, profile, policy_digest=_DIGEST, latency_ms=1, exchange=exchange
        )

    outcome = await _loop(dispatch, clock)
    assert outcome.status == "incomplete" and outcome.reason == "deadline"


async def test_r5_truncated_answer_ends_without_another_inference() -> None:
    profile, seen = _api_profile("responses"), list[bytes]()
    assert isinstance(profile, OpenAIProfile)

    async def dispatch(payload: bytes, media_type: str, deadline: Deadline) -> SemanticResult:
        seen.append(payload)
        details = type("D", (), {"reason": "max_output_tokens"})()
        fields = {"output_text": "", "status": "incomplete", "id": "r1"}
        response = type("R", (), {**fields, "incomplete_details": details})()
        exchange = reviewer_exchange(media_type, payload, REVIEWER_REPLY_SCHEMAS)
        return normalize_response(
            response, profile, policy_digest=_DIGEST, latency_ms=1, exchange=exchange
        )

    outcome = await _loop(dispatch, _Clock())
    assert outcome.status == "incomplete" and len(seen) == 1
    assert outcome.reason == "reviewer_exchange_response_content"


async def test_r5_codex_output_limit_gets_no_format_repair(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version="0.162.1")), [_FINAL])
    usage = {
        "inputTokens": 1, "cachedInputTokens": 0, "cacheWriteInputTokens": 0,
        "outputTokens": 999_999, "reasoningOutputTokens": 0, "totalTokens": 1_000_000,
    }  # fmt: skip
    params = {"threadId": "thr1", "turnId": "turn1", "tokenUsage": {"last": usage, "total": usage}}
    runtime.extra_event = {"method": "thread/tokenUsage/updated", "params": params}
    session = ReviewerSession("review-a", _DEADLINE)
    result = await _codex_exchange(monkeypatch, runtime, session, _FIRST, [])
    assert type(result) is SemanticResultInvalid

    async def dispatch(payload: bytes, media_type: str, deadline: Deadline) -> SemanticResult:
        return result

    binding = ProviderBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0", "external"
    )
    model = ReviewerExchangeModel(binding, dispatch, session)
    turns = [Turn(role, text) for role, text in _FIRST]
    with pytest.raises(ReviewerModelError, match="reviewer_exchange_output_oversize"):
        await model.complete(turns, REVIEWER_REPLY_SCHEMAS.turn, deadline=_DEADLINE)
    await session.aclose()


@pytest.mark.parametrize("route", ["responses", "chat"])
@pytest.mark.parametrize("mode", ["turn", "final"])
def test_r6_rendered_digests_name_the_exchange(route: str, mode: str) -> None:
    profile = _api_profile(route)
    case = _case(_FIRST, _api_binding(profile), mode)
    if isinstance(profile, OpenAIProfile):
        rendered = render_responses(case, REVIEWER_REPLY_SCHEMAS)
        sent = cast(Any, strict_json_parse(rendered.body))["text"]["format"]["schema"]
    else:
        rendered = render_chat(case, profile, REVIEWER_REPLY_SCHEMAS)
        sent = cast(Any, strict_json_parse(rendered.body))["response_format"]["json_schema"]
        sent = sent["schema"]
    assert rendered.schema_digest == canonical_digest(sent)
    assert rendered.prompt_digest == "sha256:" + hashlib.sha256(b"Review it.").hexdigest()


@pytest.mark.parametrize("route", ["responses", "chat"])
async def test_r6_early_failures_name_the_exchange(route: str) -> None:
    result, *_ = await _api_evaluate(route, _FIRST, _Capture(route, fail=True), _Clock())
    assert type(result) is not SemanticResultReply
    assert result.provenance.schema_digest == canonical_digest(REVIEWER_REPLY_SCHEMAS.turn)


async def test_r3_review_exit_closes_the_thread_when_admission_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version="0.162.1")), [_ACTION])
    cleanups: list[object] = []

    async def dispatch(payload: bytes, media_type: str, deadline: Deadline) -> SemanticResult:
        history = decode_reviewer_exchange(payload)
        session = CURRENT_REVIEWER_SESSION.get()  # the facade binds its review's session
        return await _codex_exchange(monkeypatch, runtime, session, history, cleanups)

    class _Reads(_NoReads):
        def reads_allowed(self) -> bool:
            return True

        async def execute(self, action: object) -> str:
            return "observation"

    admissions = iter([True, False])  # policy tightens before the continuation

    async def admissible(roots: frozenset[str]) -> bool:
        return next(admissions)

    binding = ProviderBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0", "external"
    )
    async with ReviewerExchangeModel(
        binding, dispatch, ReviewerSession("review-a", _DEADLINE)
    ) as model:
        outcome = await ReviewerLoop(
            model, cast(Any, _Reads()), instruction="Review it.", packet="packet",
            deadline=_DEADLINE, history_admissible=admissible, clock=_Clock().monotonic_seconds,
            final_reserve_seconds=0.0,
        ).run()  # fmt: skip
        assert outcome.reason == "authorization_changed" and cleanups == []
    assert cleanups == [runtime]


# -- review round 2 regressions (F1-F3) ------------------------------------------------------------


async def test_f1_codex_reply_the_decoder_rejects_still_gets_its_one_repair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Schema-valid on the provider wire (uniqueItems is not in the strict form), decoder-invalid.
    bad = {"reply": {"action": "read_ledger", "args": {
        "refs": ["evt_1", "evt_1"], "view": "claims", "cursor": None, "max_bytes": 8192,
    }}}  # fmt: skip
    wire = codex._codex_output_schema(cast(Any, REVIEWER_REPLY_SCHEMAS.turn))  # pyright: ignore[reportPrivateUsage]
    jsonschema.validate(bad, cast(Any, wire))
    with pytest.raises(ReviewerReplyInvalid):
        decode_reviewer_reply(cast(JsonValue, bad))
    runtime = _CodexRuntime(
        profile_for(record_for(b"c", b"h", version="0.162.1")),
        [canonical_encode(cast(JsonValue, bad)).decode(), _FINAL],
    )
    cleanups: list[object] = []

    async def dispatch(payload: bytes, media_type: str, deadline: Deadline) -> SemanticResult:
        history = decode_reviewer_exchange(payload)
        return await _codex_exchange(
            monkeypatch, runtime, CURRENT_REVIEWER_SESSION.get(), history, cleanups
        )

    class _Reads(_NoReads):
        def reads_allowed(self) -> bool:
            return True

        async def execute(self, action: object) -> str:
            raise AssertionError("an invalid action never executes")

    async def admissible(roots: frozenset[str]) -> bool:
        return True

    binding = ProviderBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0", "external"
    )
    async with ReviewerExchangeModel(
        binding, dispatch, ReviewerSession("review-a", _DEADLINE)
    ) as model:
        outcome = await ReviewerLoop(
            model, cast(Any, _Reads()), instruction="Review it.", packet="packet",
            deadline=_DEADLINE, history_admissible=admissible, clock=_Clock().monotonic_seconds,
            final_reserve_seconds=0.0,
        ).run()  # fmt: skip
    turns = [params for method, params in runtime.requests if method == "turn/start"]
    assert outcome.status == "final" and len(turns) == 2 and cleanups == [runtime]
    # The loop's history never carries the rejected action; Codex's thread already holds it.
    assert all(turn.role != "assistant" or "evt_1" not in turn.content for turn in outcome.history)


async def test_f2_codex_send_that_never_drains_ends_at_the_deadline_and_close_returns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered, release = asyncio.Event(), asyncio.Event()

    class _Stdin:  # a runtime that stops reading stdin at the turn
        message: Any = None

        def write(self, payload: bytes) -> None:
            self.message = strict_json_parse(payload.rstrip(b"\n"))

        async def drain(self) -> None:
            if self.message.get("method") == "turn/start":
                entered.set()
                await release.wait()

    real = cast(Any, codex)._CodexProcess  # the real send/request code, only stdin scripted

    class _Blocked(_CodexRuntime):
        process: Any = None

        async def send(self, value: dict[str, object]) -> None:
            await real.send(self, value)

        async def request(self, rid: int, method: str, params: object, timeout: float) -> object:
            if method != "turn/start":
                return await super().request(rid, method, params, timeout)
            return await real.request(self, rid, method, params, timeout)

    class _RealClock(_Clock):
        def monotonic_seconds(self) -> float:
            return time.monotonic()

    runtime = _Blocked(profile_for(record_for(b"c", b"h", version="0.162.1")), [_FINAL])
    runtime.process = type("P", (), {"stdin": _Stdin()})()
    cleanups: list[object] = []

    async def launch(profile: object) -> _CodexRuntime:
        return runtime

    async def cleanup(value: object) -> str:
        cleanups.append(value)
        return "terminated"

    monkeypatch.setattr(codex, "_launch", launch)
    monkeypatch.setattr(codex, "_cleanup", cleanup)
    deadline = Deadline(_NOW + timedelta(seconds=0.05), time.monotonic() + 0.05)
    session = ReviewerSession("review-a", deadline)
    binding = ProviderBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0", "external"
    )
    case = _case(_FIRST, binding)
    digest = "sha256:" + hashlib.sha256(case.payload).hexdigest()
    auth = ProviderAttemptAuthBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0",
        "semantic-review", _DIGEST, canonical_digest({"purpose": "semantic-review"}),
        "dsp_70000000-0000-4000-8000-000000000001", digest, 1, deadline.monotonic_deadline,
    )  # fmt: skip
    authority = ExternalRuntimeAuthority(
        auth.dispatch_id, digest, "hmac-sha256:" + "a" * 64, 1, deadline.monotonic_deadline
    )
    evaluator = codex.CodexAppServerEvaluator(
        runtime.profile, auth, authority, _RealClock(), None, reply_schemas=_SCHEMAS
    )

    async def evaluate() -> SemanticResult:
        token = CURRENT_REVIEWER_SESSION.set(session)
        try:
            return await evaluator.evaluate(case, deadline)
        finally:
            CURRENT_REVIEWER_SESSION.reset(token)

    turn = asyncio.create_task(evaluate())
    await asyncio.wait_for(entered.wait(), 5)
    closing = asyncio.create_task(session.aclose())
    try:
        # The outer bound only keeps a regression from hanging the suite; results are observed.
        result = await asyncio.wait_for(turn, 5)
        assert await asyncio.wait_for(closing, 5) is None
    finally:
        release.set()
    assert type(result) is SemanticResultTimeout and session.held is None
    assert cleanups == [runtime]
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.case_disclosed and not evidence.turn_acknowledged


async def test_f2_codex_initialize_and_its_notification_share_the_original_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The initialize reply arrives at 0.3 s of a 0.4 s budget, then the runtime stops reading the
    # initialized notification: cleanup must start at the original deadline, not a fresh budget.
    sent, release = asyncio.Event(), asyncio.Event()
    started: list[float] = []

    class _Slow(_CodexRuntime):
        async def request(self, rid: int, method: str, params: object, timeout: float) -> object:
            if method == "initialize":
                await release.wait()
            return await super().request(rid, method, params, timeout)

        async def send(self, value: dict[str, object]) -> None:
            if value.get("method") == "initialized":
                sent.set()
                await asyncio.Event().wait()

    class _RealClock(_Clock):
        def monotonic_seconds(self) -> float:
            return time.monotonic()

    runtime = _Slow(profile_for(record_for(b"c", b"h", version="0.162.1")), [_FINAL])

    async def launch(profile: object) -> _CodexRuntime:
        return runtime

    async def cleanup(value: object) -> str:
        started.append(time.monotonic())
        return "terminated"

    monkeypatch.setattr(codex, "_launch", launch)
    monkeypatch.setattr(codex, "_cleanup", cleanup)
    start = time.monotonic()
    deadline = Deadline(_NOW + timedelta(seconds=0.4), start + 0.4)
    session = ReviewerSession("review-a", deadline)
    binding = ProviderBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0", "external"
    )
    case = _case(_FIRST, binding)
    digest = "sha256:" + hashlib.sha256(case.payload).hexdigest()
    auth = ProviderAttemptAuthBinding(
        "openai-codex", runtime.profile.model, "codex-chatgpt-subscription", "1.0.0",
        "semantic-review", _DIGEST, canonical_digest({"purpose": "semantic-review"}),
        "dsp_70000000-0000-4000-8000-000000000001", digest, 1, deadline.monotonic_deadline,
    )  # fmt: skip
    authority = ExternalRuntimeAuthority(
        auth.dispatch_id, digest, "hmac-sha256:" + "a" * 64, 1, deadline.monotonic_deadline
    )
    evaluator = codex.CodexAppServerEvaluator(
        runtime.profile, auth, authority, _RealClock(), None, reply_schemas=_SCHEMAS
    )

    async def evaluate() -> SemanticResult:
        token = CURRENT_REVIEWER_SESSION.set(session)
        try:
            return await evaluator.evaluate(case, deadline)
        finally:
            CURRENT_REVIEWER_SESSION.reset(token)

    handle = asyncio.get_running_loop().call_later(0.3, release.set)
    task = asyncio.create_task(evaluate())
    try:
        # The outer bounds only keep a regression from hanging the suite; results are observed.
        await asyncio.wait_for(sent.wait(), 5)
        closing = asyncio.create_task(session.aclose())
        result = await asyncio.wait_for(task, 5)
        assert await asyncio.wait_for(closing, 5) is None
    finally:
        handle.cancel()
    assert type(result) is SemanticResultTimeout and session.held is None
    assert started and started[0] <= deadline.monotonic_deadline + 0.1


async def test_f2_cancelled_codex_turn_is_cleaned_up_not_retained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = asyncio.Event()

    class _Stalled(_CodexRuntime):
        async def read(self, timeout: float) -> dict[str, object]:
            entered.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    runtime = _Stalled(profile_for(record_for(b"c", b"h", version="0.162.1")), [_ACTION])
    session = ReviewerSession("review-a", _DEADLINE)
    cleanups: list[object] = []
    turn = asyncio.create_task(_codex_exchange(monkeypatch, runtime, session, _FIRST, cleanups))
    await asyncio.wait_for(entered.wait(), 5)
    turn.cancel()
    with pytest.raises(asyncio.CancelledError):
        await turn
    assert session.held is None and cleanups == [runtime]


async def test_f3_failed_responses_generation_ends_without_another_inference() -> None:
    seen: list[bytes] = []

    class _Failed(_Capture):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            self.bodies.append(await request.aread())
            error = {"code": "server_error", "message": "scripted fixture"}
            payload: dict[str, object] = {"id": "resp_1", "status": "failed", "error": error}
            payload["output"] = []
            return httpx.Response(200, request=request, json=payload)

    async def dispatch(payload: bytes, media_type: str, deadline: Deadline) -> SemanticResult:
        seen.append(payload)
        capture = _Failed("responses") if len(seen) == 1 else _Capture("responses")
        history = decode_reviewer_exchange(payload)
        result, *_ = await _api_evaluate("responses", history, capture, _Clock())
        return result

    outcome = await _loop(dispatch, _Clock())
    assert outcome.status == "incomplete" and len(seen) == 1
    assert outcome.reason == "reviewer_exchange_unavailable"
