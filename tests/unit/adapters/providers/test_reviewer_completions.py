"""Reviewer-loop completions on every route (#1118 unit 3): scripted transports only."""

from __future__ import annotations

from collections import deque
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from builders.codex_capability import profile_for, record_for
from finishup.adapters.privacy import gateway
from finishup.adapters.providers import codex_app_server as codex
from finishup.adapters.providers.local_model import (
    LOCAL_REVIEWER_COMPLETION_PROTOCOL,
    LocalModelEndpointProfile,
    LocalModelEvaluator,
)
from finishup.adapters.providers.openai_chat_completions import ChatCompletionsProfile
from finishup.adapters.providers.openai_chat_completions import render_case as render_chat
from finishup.adapters.providers.openai_responses import (
    OpenAIProfile,
    normalize_response,
    owner_declared_data_use_profile,
)
from finishup.adapters.providers.openai_responses import render_case as render_responses
from finishup.application.reviewer_exchange import REVIEWER_REPLY_SCHEMAS, ReviewerExchangeModel
from finishup.application.reviewer_loop import ReviewerModelError, Turn
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
    REVIEWER_EXCHANGE_MEDIA_TYPES,
    Deadline,
    ExternalRuntimeAuthority,
    ReviewerMessage,
    ReviewerReplySchemas,
    SemanticResult,
    SemanticResultInvalid,
    SemanticResultReply,
    SemanticResultUnavailable,
    decode_reviewer_exchange,
    encode_reviewer_exchange,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, strict_json_parse

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
_FIRST: tuple[ReviewerMessage, ...] = (("system", "Review it."), ("user", "packet"))
_SECOND: tuple[ReviewerMessage, ...] = (*_FIRST, ("assistant", _ACTION), ("user", "observation"))


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
    with pytest.raises(ValueError, match="openai_reviewer_schema_unavailable"):
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

    result = normalize_response(
        response(_ACTION), profile, policy_digest=_DIGEST, latency_ms=1, reviewer=True
    )
    assert type(result) is SemanticResultReply and result.text == _ACTION
    assert gateway._result_outcome(result) == (  # pyright: ignore[reportPrivateUsage]
        PrivacyOutcome.COMPLETED,
        None,
    )
    invalid = normalize_response(
        response("[1]"), profile, policy_digest=_DIGEST, latency_ms=1, reviewer=True
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
    result = await evaluator.evaluate(case, Deadline(_NOW + timedelta(seconds=30), 30.0))
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
            return {"codexHome": str(self.profile.codex_home), "userAgent": "x/0.162.1 (Mac)"}
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
    sessions: object,
    history: tuple[ReviewerMessage, ...],
    cleanups: list[object],
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
        runtime.profile, auth, authority, _Clock(), None, reply_schemas=_SCHEMAS,
        sessions=cast(codex._ReviewerSessions, sessions),  # pyright: ignore[reportPrivateUsage]
    )  # fmt: skip
    return await evaluator.evaluate(case, Deadline(_NOW + timedelta(seconds=30), 30.0))


async def test_codex_keeps_one_thread_sends_only_new_input_and_cleans_up_at_the_end(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _CodexRuntime(
        profile_for(record_for(b"c", b"h", version="0.162.1")), [_ACTION, _FINAL]
    )
    sessions = codex._ReviewerSessions()  # pyright: ignore[reportPrivateUsage]
    cleanups: list[object] = []

    first = await _codex_exchange(monkeypatch, runtime, sessions, _FIRST, cleanups)
    assert type(first) is SemanticResultReply and first.text == _ACTION
    assert first.provenance.runtime_evidence is not None
    assert first.provenance.runtime_evidence.process_cleanup == "retained" and cleanups == []
    init = dict(runtime.requests)["initialize"]
    assert cast(dict[str, object], init["capabilities"])["experimentalApi"] is True
    thread = dict(runtime.requests)["thread/start"]
    assert thread["environments"] == [] and thread["baseInstructions"] == "Review it."
    assert "dynamicTools" not in thread

    runtime.requests.clear()
    second = await _codex_exchange(monkeypatch, runtime, sessions, _SECOND, cleanups)
    assert type(second) is SemanticResultReply and second.text == _FINAL
    # The same thread: no launch, no new thread, only the observation, the schema every turn.
    assert [method for method, _ in runtime.requests] == ["turn/start"]
    turn = runtime.requests[0][1]
    assert turn["input"] == [{"type": "text", "text": "observation"}]
    assert turn["threadId"] == "thr1" and turn["outputSchema"] == _SCHEMAS.turn
    assert cleanups == [runtime]


async def test_codex_continuation_without_its_session_fails_before_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version="0.162.1")), [_FINAL])
    sessions = codex._ReviewerSessions()  # pyright: ignore[reportPrivateUsage]
    result = await _codex_exchange(monkeypatch, runtime, sessions, _SECOND, [])
    assert type(result) is SemanticResultUnavailable and runtime.requests == []
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and not evidence.case_disclosed
    assert evidence.failure_stage == "case_invalid"


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
    sessions = codex._ReviewerSessions()  # pyright: ignore[reportPrivateUsage]
    cleanups: list[object] = []
    result = await _codex_exchange(monkeypatch, runtime, sessions, _FIRST, cleanups)
    assert type(result) is not SemanticResultReply and cleanups == [runtime]
    evidence = result.provenance.runtime_evidence
    assert evidence is not None and evidence.failure_stage == stage


async def test_codex_reviewer_loop_refuses_an_unreviewed_release_before_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version="0.159.0")), [_ACTION])
    sessions = codex._ReviewerSessions()  # pyright: ignore[reportPrivateUsage]
    result = await _codex_exchange(monkeypatch, runtime, sessions, _FIRST, [])
    assert type(result) is SemanticResultUnavailable and runtime.requests == []


async def test_closing_the_sessions_cleans_up_a_retained_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _CodexRuntime(profile_for(record_for(b"c", b"h", version="0.162.1")), [_ACTION])
    sessions = codex._ReviewerSessions()  # pyright: ignore[reportPrivateUsage]
    cleanups: list[object] = []
    await _codex_exchange(monkeypatch, runtime, sessions, _FIRST, cleanups)
    await sessions.aclose()
    assert cleanups == [runtime]


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
            reviewer=True,
        )
        return reply

    model = ReviewerExchangeModel(binding, dispatch)
    deadline = Deadline(_NOW + timedelta(seconds=30), 30.0)
    turns = [Turn(role, text) for role, text in _FIRST]
    final_schema = REVIEWER_REPLY_SCHEMAS.final
    with pytest.raises(ReviewerModelError, match="reviewer_exchange_route_mismatch"):
        await model.complete(turns, final_schema, deadline=deadline)
    assert seen == [REVIEWER_EXCHANGE_MEDIA_TYPES["final"]]
    same = ReviewerExchangeModel(
        replace(binding, endpoint_profile_id="openai-responses", model_id="gpt"), dispatch
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
    sessions = codex._ReviewerSessions()  # pyright: ignore[reportPrivateUsage]
    cleanups: list[object] = []
    first = await _codex_exchange(monkeypatch, runtime, sessions, _FIRST, cleanups)
    assert type(first) is SemanticResultInvalid and cleanups == []
    runtime.requests.clear()
    repair: tuple[ReviewerMessage, ...] = (*_FIRST, ("user", "format_error: output_not_json."))
    second = await _codex_exchange(monkeypatch, runtime, sessions, repair, cleanups)
    assert type(second) is SemanticResultReply and cleanups == [runtime]
    assert [method for method, _ in runtime.requests] == ["turn/start"]
