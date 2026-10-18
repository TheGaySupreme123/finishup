"""The reviewer loop, its reply contract and its broker (#1118 unit 2), with a scripted model."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator

from builders.privacy_policies import INSTALLATION_ID, minimal_external_policy
from builders.privacy_widenings import with_llm
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.adapters.providers.reviewer_reply import (
    REVIEWER_LOOP_INSTRUCTION,
    ReviewerReplyInvalid,
    decode_reviewer_reply,
    reviewer_reply_schema,
)
from finishup.application.egress import PrivacyCoordinator, reviewer_history_admissible
from finishup.application.reviewer_broker import (
    MemoryStepStore,
    ReadRoot,
    ReviewerBroker,
    StepConflict,
)
from finishup.application.reviewer_loop import ReviewerLoop, ReviewerModelError, Turn
from finishup.domain.privacy import AuthorizationScope, AuthorizationScopeKind, PrivacyPolicy
from finishup.ports.privacy import (
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
)
from finishup.ports.semantic import Deadline, SemanticJudgment
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import ReadLedgerArgsModel, ReviewerLedgerActionModel
from unit.application.test_egress_origin_operation import (
    _COMMITMENT,  # pyright: ignore[reportPrivateUsage]
    _TASK,  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _DELIVERABLE_DIFF,  # pyright: ignore[reportPrivateUsage]
    _semantic_case,  # pyright: ignore[reportPrivateUsage]
)

_REPO = Path(__file__).resolve().parents[3]
_CLM = "clm_10000000-0000-4000-8000-000000000001"
_SCOPE = AuthorizationScope(AuthorizationScopeKind.TASK, INSTALLATION_ID, _COMMITMENT, _TASK)
_FINAL: dict[str, JsonValue] = {
    "reply": {
        "final_judgment": {
            "conclusion": "no_material_discrepancy",
            "review_summary": "Checked the retry count in the diff.",
            "verified": [
                {
                    "requirement_or_claim": "Retries are three",
                    "verdict": "supported",
                    "cited_refs": [_CLM],
                    "snippet": "self.retries = 3",
                }
            ],
            "reviewer_challenges": [],
            "prior_finding_verdicts": [],
        }
    }
}


def _read(tool: str, **args: JsonValue) -> dict[str, JsonValue]:
    return {"reply": {"action": tool, "args": args}}


_PACKET_READ = _read("read_packet_section", section="agent_account", item_ref="goal-1", offset=0)
_LEDGER_READ = _read("read_ledger", view="claims", refs=[_CLM], cursor=None, max_bytes=None)


class _Script:
    def __init__(self, *replies: JsonValue | Exception) -> None:
        self.replies = list(replies)
        self.calls: list[tuple[tuple[Turn, ...], dict[str, JsonValue]]] = []

    async def complete(
        self, history: Sequence[Turn], schema: dict[str, JsonValue], *, deadline: Deadline
    ) -> JsonValue:
        del deadline
        self.calls.append((tuple(history), schema))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def _coordinator(policy: PrivacyPolicy) -> PrivacyCoordinator:
    store = _Store()
    store._policy = policy  # pyright: ignore[reportPrivateUsage]
    return PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, store),
        cast(PrivacyClassifierPort, LocalPrivacyEnforcer()),
        cast(PrivacyAuditPort, object()),
        cast(OutboundGatewayPort, object()),
        _Clock(),
        _Ids(),
    )


def _setup(
    *replies: JsonValue | Exception,
    roots: Sequence[ReadRoot] = (),
    policy: PrivacyPolicy | None = None,
    expired: bool = False,
) -> tuple[ReviewerLoop, ReviewerBroker, _Script, list[PrivacyPolicy]]:
    current = [policy or with_llm(minimal_external_policy())]
    coordinator = _coordinator(current[0])
    binding = next(c for c in current[0].channel_policies if c.provider_binding).provider_binding
    assert binding is not None

    async def admit(candidate: object) -> dict[str, bytes] | str:
        coordinator._policies._policy = current[0]  # type: ignore[attr-defined]  # pyright: ignore
        return await coordinator.admit_reviewer_read(candidate)  # type: ignore[arg-type]

    async def admissible(held: frozenset[str]) -> bool:
        return reviewer_history_admissible(current[0], binding, AuthorizationScopeKind.TASK, held)

    broker = ReviewerBroker(
        job_id="sjb_1",
        case=_semantic_case(_DELIVERABLE_DIFF, with_aws_key=False),
        roots=roots,
        store=MemoryStepStore(),
        admit=admit,
        scope=_SCOPE,
        provider_binding=binding,
        request_id="req_40000000-0000-4000-8000-000000000101",
    )
    model = _Script(*replies)
    deadline = Deadline(
        datetime(2026, 10, 19, tzinfo=UTC) + timedelta(minutes=5), 0.0 if expired else 600.0
    )
    loop = ReviewerLoop(
        model,
        broker,
        instruction=REVIEWER_LOOP_INSTRUCTION,
        packet="{}",
        deadline=deadline,
        history_admissible=admissible,
        clock=lambda: 1.0,
    )
    return loop, broker, model, current


def _observations(model: _Script) -> list[dict[str, JsonValue]]:
    history = model.calls[-1][0]
    return [json.loads(t.content) for t in history[2:] if t.role == "user" and t.content[0] == "{"]


# The reply contract


def test_reply_schema_has_four_disjoint_branches_and_a_final_only_form() -> None:
    full = reviewer_reply_schema(reads_allowed=True)
    reply = cast(dict[str, dict[str, list[dict[str, str]]]], full["properties"])["reply"]
    branches = reply["anyOf"]
    assert [b["$ref"].rsplit("/", 1)[1] for b in branches] == [
        "ReviewerPacketAction",
        "ReviewerLedgerAction",
        "ReviewerFileAction",
        "FinalReply",
    ]
    final_only = reviewer_reply_schema(reads_allowed=False, strict=True)
    assert final_only["properties"] == {"reply": {"anyOf": [{"$ref": "#/$defs/FinalReply"}]}}
    for schema in (full, final_only, reviewer_reply_schema(reads_allowed=True, strict=True)):
        Draft202012Validator.check_schema(schema)
    frozen = json.loads((_REPO / "schemas/findings/reviewer-reply-1.0.0.schema.json").read_text())
    assert {k: v for k, v in frozen.items() if k not in {"$id", "$schema", "title"}} == full
    Draft202012Validator(full).validate(_FINAL)  # pyright: ignore[reportUnknownMemberType]
    strict = reviewer_reply_schema(reads_allowed=True, strict=True)
    assert "allOf" not in json.dumps(strict)
    # Strict nulls stand for the defaulted fields.
    Draft202012Validator(strict).validate(_LEDGER_READ)  # pyright: ignore[reportUnknownMemberType]


@pytest.mark.parametrize(
    "reply",
    [
        {"reply": {**_LEDGER_READ["reply"], "extra": 1}},  # type: ignore[dict-item]
        {"reply": {**_LEDGER_READ["reply"], **_FINAL["reply"]}},  # type: ignore[dict-item]
        {"reply": [_LEDGER_READ["reply"], _PACKET_READ["reply"]]},
        {"reply": _LEDGER_READ["reply"], "thought": "x"},
        _read("read_file", root_id="w1", path="a", mode="text", start_line=0, line_count=1),
        _read("read_ledger", view="claims", refs=[_CLM, _CLM], cursor=None),
        {"reply": {"final_judgment": {"conclusion": "no_material_discrepancy"}}},
    ],
)
def test_decoder_refuses_anything_but_one_valid_reply(reply: JsonValue) -> None:
    with pytest.raises(ReviewerReplyInvalid):
        decode_reviewer_reply(reply)


def test_decoder_reads_strict_nulls_as_defaults() -> None:
    action = decode_reviewer_reply(_LEDGER_READ)
    assert action == ReviewerLedgerActionModel(
        action="read_ledger", args=ReadLedgerArgsModel(view="claims", refs=(_CLM,), cursor=None)
    )
    assert isinstance(decode_reviewer_reply(_FINAL), SemanticJudgment)


def test_instruction_leads_with_the_goal_and_drops_packet_only_rules() -> None:
    assert REVIEWER_LOOP_INSTRUCTION.startswith("## Goal\nVerify the agent's work")
    assert "Review only the supplied packet." not in REVIEWER_LOOP_INSTRUCTION
    assert "fetch more context" not in REVIEWER_LOOP_INSTRUCTION
    assert "At most 3 reads" in REVIEWER_LOOP_INSTRUCTION


# The loop


@pytest.mark.anyio
async def test_no_read_review_is_one_completion() -> None:
    loop, _broker, model, _ = _setup(_FINAL)
    outcome = await loop.run()
    assert (outcome.status, outcome.model_turns, len(model.calls)) == ("final", 1, 1)
    history, schema = model.calls[0]
    assert [t.role for t in history] == ["system", "user"]
    assert schema == reviewer_reply_schema(reads_allowed=True, strict=True)


@pytest.mark.anyio
async def test_reads_append_observations_then_only_final_is_offered() -> None:
    loop, _broker, model, _ = _setup(_PACKET_READ, _LEDGER_READ, _LEDGER_READ, _FINAL)
    outcome = await loop.run()
    assert outcome.status == "final" and outcome.model_turns == 4
    first, second, third = _observations(model)
    assert first["status"] == "ok" and first["call_index"] == 1
    assert "evt_10000000-0000-4000-8000-000000000001" in cast(list[str], first["citable_refs"])
    assert second["data"]["records"][0]["ref"].startswith("claim-")  # type: ignore[index]
    assert third["calls_remaining"] == 0
    assert model.calls[-1][1] == reviewer_reply_schema(reads_allowed=False, strict=True)
    for sent in (first, second, third):
        assert sent["result_utf8_bytes"] == len(canonical_encode(sent)) <= 8192


@pytest.mark.anyio
async def test_a_read_after_the_cap_executes_nothing_and_ends_incomplete() -> None:
    loop, broker, model, _ = _setup(_LEDGER_READ, _LEDGER_READ, _LEDGER_READ, _LEDGER_READ)
    outcome = await loop.run()
    assert (outcome.status, outcome.reason) == ("incomplete", "read_limit")
    assert len(_observations(model)) == 3 and broker.reads_allowed() is False


@pytest.mark.anyio
async def test_one_format_repair_per_review() -> None:
    loop, _broker, model, _ = _setup({"reply": {}}, _LEDGER_READ, {"bad": 1})
    outcome = await loop.run()
    assert (outcome.status, outcome.reason) == ("incomplete", "format_invalid")
    assert model.calls[1][0][-1].content.startswith("format_error: action_invalid.")
    assert "bad" not in "".join(t.content for t in outcome.history)  # malformed text not echoed
    repaired, _b, _m, _ = _setup("not json", _FINAL)
    assert (await repaired.run()).status == "final"


@pytest.mark.anyio
async def test_deadline_model_failure_and_removed_roots_end_incomplete(tmp_path: Path) -> None:
    loop, _b, model, _ = _setup(_FINAL, expired=True)
    assert ((await loop.run()).reason, model.calls) == ("deadline", [])
    loop, _b, _m, _ = _setup(ReviewerModelError("outcome_unknown"))
    assert (await loop.run()).reason == "outcome_unknown"
    (tmp_path / "shared").mkdir()
    (tmp_path / "shared" / "spec.md").write_text("GT_ZERO\n")
    root = str((tmp_path / "shared").resolve())
    policy = replace(with_llm(minimal_external_policy()), admitted_input_roots=(root,))
    alias = ReadRoot("o1", path=root, input_root=root, standing="outside_input_mutable")
    read = _read("read_file", root_id="o1", path="spec.md", mode="text", start_line=1, line_count=5)
    # Removed after the read: the conversation holding its bytes never continues.
    loop, broker, model, current = _setup(read, _FINAL, roots=(alias,), policy=policy)
    check = loop.history_admissible

    async def owner_removes_root(held: frozenset[str]) -> bool:
        if held:
            current[0] = replace(policy, admitted_input_roots=())
        return await check(held)

    loop.history_admissible = owner_removes_root
    outcome = await loop.run()
    assert (outcome.status, outcome.reason) == ("incomplete", "authorization_changed")
    assert len(model.calls) == 1 and root in broker.history_roots
    # Removed before the read: the read is refused and spends its slot.
    loop, broker, model, current = _setup(read, _FINAL, roots=(alias,), policy=policy)
    current[0] = replace(policy, admitted_input_roots=())
    assert (await loop.run()).status == "final"
    (refused,) = _observations(model)
    assert (refused["status"], refused["reason"], refused["data"]) == (
        "denied",
        "authorization_changed",
        None,
    )
    assert "GT_ZERO" not in json.dumps(refused) and root not in broker.history_roots


# The broker


@pytest.mark.anyio
async def test_file_reads_stay_in_scope_and_are_admitted_like_the_packet(tmp_path: Path) -> None:
    work = tmp_path / "work"
    (work / "src").mkdir(parents=True)
    (work / "src" / "a.py").write_text("".join(f"line {n} {'x' * 60}\n" for n in range(1, 400)))
    (work / "src" / "key.py").write_text('KEY = "AKIAQ3EGRL7X2VNTWB5D"\n')
    (work / ".env").write_text("SECRET=1\n")
    (work / "linked.py").symlink_to(work / "src" / "a.py")
    w1 = ReadRoot("w1", path=str(work.resolve()), subject_refs=(_CLM,))
    shared = tmp_path / "shared"
    (shared / "specs").mkdir(parents=True)
    (shared / "customer").mkdir()
    (shared / "specs" / "s.md").write_text("spec\n")
    root = str(shared.resolve())
    o1 = ReadRoot("o1", path=root, input_root=root, declared=("specs",))
    policy = replace(with_llm(minimal_external_policy()), admitted_input_roots=(root,))

    def text(root_id: str, path: str, start: int = 1, count: int = 200) -> JsonValue:
        return _read(
            "read_file", root_id=root_id, path=path, mode="text", start_line=start, line_count=count
        )

    loop, broker, model, _ = _setup(
        text("w1", "./src/a.py", 10, 200),
        text("w1", "../work/src/a.py"),
        text("w1", ".env"),
        _FINAL,
        roots=(w1, o1),
        policy=policy,
    )
    await loop.run()
    span, escape, hidden = _observations(model)
    assert span["status"] == "partial" and span["data"]["text"].startswith("line 10 x")  # type: ignore[index]
    assert cast(int, span["result_utf8_bytes"]) <= 8192 and span["truncated"] is True
    assert (escape["reason"], hidden["reason"]) == ("forbidden_path", "forbidden_path")
    assert hidden["data"] is None and hidden["citable_refs"] == []
    refs, text_by_ref = broker.citations(frozenset(), {})
    # The fence holds exactly the clipped text the reviewer was sent, nothing cut from it.
    assert refs == {_CLM} and text_by_ref[_CLM] == (span["data"]["text"],)  # type: ignore[index]

    loop, broker, model, _ = _setup(
        text("w1", "linked.py"),
        text("w1", "src/key.py"),
        _read("read_file", root_id="o1", path="customer", mode="list", cursor=None),
        _FINAL,
        roots=(w1, o1),
        policy=policy,
    )
    await loop.run()
    link, key, sibling = _observations(model)
    assert link["reason"] == "not_recorded"
    assert key["status"] == "denied" and key["reason"] == "privacy_withheld"
    assert "AKIA" not in json.dumps(key)
    assert sibling["reason"] == "outside_scope"


@pytest.mark.anyio
async def test_listing_snapshots_budgets_and_step_replay(tmp_path: Path) -> None:
    snap = ReadRoot(
        "s1",
        snapshot={"specs/a.md": b"x" * 20_000, "specs/b/c.md": b"c"},
        baseline="task_start",
        standing="outside_input_snapshot",
    )
    listing = _read(
        "read_file", root_id="s1", path="specs", mode="list", cursor=None, max_entries=1
    )
    big = _read(
        "read_file", root_id="s1", path="specs/a.md", mode="text", start_line=1, line_count=1
    )
    loop, _broker, model, _ = _setup(listing, big, big, _FINAL, roots=(snap,))
    await loop.run()
    listed, first, second = _observations(model)
    assert listed["data"]["entries"] == [{"name": "a.md", "kind": "file"}]  # type: ignore[index]
    assert listed["next_cursor"] == "1"
    assert first["data"]["provenance"]["baseline"] == "task_start"  # type: ignore[index]
    total = sum(cast(int, o["result_utf8_bytes"]) for o in (listed, first, second))
    assert total <= 24_576 and second["bytes_remaining"] == 24_576 - total
    store = MemoryStepStore()
    assert store.reserve("sjb_1:read:1", "sha256:a") is None
    store.record("sjb_1:read:1", b"{}")
    assert store.reserve("sjb_1:read:1", "sha256:a") == b"{}"
    with pytest.raises(StepConflict):
        store.reserve("sjb_1:read:1", "sha256:b")


# #1118 unit 4: delivery of what the reviewer read


def test_the_loop_instruction_drops_the_packet_follow_up_rules() -> None:
    assert "follow_up_round" not in REVIEWER_LOOP_INSTRUCTION
    assert "list it again only if you cite" not in REVIEWER_LOOP_INSTRUCTION
    assert "Read what you need first" in REVIEWER_LOOP_INSTRUCTION


@pytest.mark.anyio
async def test_a_real_loop_history_summarizes_by_alias_and_standing_never_path(
    tmp_path: Path,
) -> None:
    from finishup.domain.reviewer_reads import (
        render_reviewer_reads_lines,
        summarize_reviewer_reads,
    )

    work = tmp_path / "work"
    (work / "src").mkdir(parents=True)
    (work / "src" / "private_name.py").write_text("VALUE = 1\n")
    w1 = ReadRoot("w1", path=str(work.resolve()), subject_refs=(_CLM,))
    loop, _broker, _model, _ = _setup(
        _read(
            "read_file",
            root_id="w1",
            path="src/private_name.py",
            mode="text",
            start_line=1,
            line_count=5,
        ),
        _read("read_file", root_id="w1", path=".env", mode="text", start_line=1, line_count=5),
        _FINAL,
        roots=(w1,),
    )
    outcome = await loop.run()
    summary = summarize_reviewer_reads((turn.role, turn.content) for turn in outcome.history)
    assert summary is not None and summary["reads_used"] == 2
    lines = render_reviewer_reads_lines(summary)
    assert lines[0].startswith("Reviewer reads: 2 of 3,")
    assert "read_file: ok" in lines[1] and "w1 (workspace_content, read_time)" in lines[1]
    assert lines[2].startswith("- 2. read_file: denied forbidden_path")
    rendered = json.dumps(summary) + "\n".join(lines)
    assert "private_name" not in rendered and "VALUE" not in rendered and ".env" not in rendered
