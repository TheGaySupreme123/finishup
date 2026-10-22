"""The reviewer loop, its reply contract and its broker (#1118 unit 2), with a scripted model.

The round-1 review's probes (B1, M1-M6, m1, m2) are regression tests here, asserting the fix.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator

from builders.policy_cases import clm, make_case
from builders.privacy_policies import INSTALLATION_ID, minimal_external_policy
from builders.privacy_widenings import with_llm
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer, scan_exact_bytes
from finishup.adapters.providers.reviewer_reply import (
    REVIEWER_LOOP_INSTRUCTION,
    ReviewerReplyInvalid,
    decode_reviewer_reply,
    reviewer_reply_schema,
)
from finishup.adapters.task_input_read import (
    MAX_TASK_INPUT_READ_BYTES,
    ReadDeadline,
    list_beneath,
    read_text_beneath,
)
from finishup.application.check import validate_semantic_judgment
from finishup.application.egress import PrivacyCoordinator, reviewer_history_admissible
from finishup.application.reviewer_broker import ReadElement, ReadRoot, ReviewerBroker
from finishup.application.reviewer_loop import ReviewerLoop, ReviewerModelError, Turn
from finishup.application.reviewer_telemetry import read_usage_from_wire
from finishup.domain.privacy import AuthorizationScope, AuthorizationScopeKind, PrivacyPolicy
from finishup.ports.change_capture import SnapshotFile, TaskInputSnapshotSet
from finishup.ports.privacy import (
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
)
from finishup.ports.semantic import (
    Deadline,
    ReviewStepKind,
    ReviewStepRefused,
    SemanticCase,
    SemanticJudgment,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import ReadLedgerArgsModel, ReviewerLedgerActionModel
from unit.application.test_egress_origin_operation import (
    _COMMITMENT,  # pyright: ignore[reportPrivateUsage]
    _TASK,  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_semantic_post_validation import (
    _provenance,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _DELIVERABLE_DIFF,  # pyright: ignore[reportPrivateUsage]
    _semantic_case,  # pyright: ignore[reportPrivateUsage]
)

_REPO = Path(__file__).resolve().parents[3]
_CLM = str(clm(1))
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


def _text(
    root_id: str, path: str, start: int = 1, count: int = 200, **more: JsonValue
) -> JsonValue:
    return _read(
        "read_file",
        root_id=root_id,
        path=path,
        mode="text",
        start_line=start,
        line_count=count,
        **more,
    )


_PACKET_READ = _read("read_packet_section", section="agent_account", item_ref="goal-1", offset=0)
_LEDGER_READ = _read("read_ledger", view="claims", refs=[_CLM], cursor=None, max_bytes=None)

type _Reply = JsonValue | Exception | Callable[[tuple[Turn, ...]], JsonValue]


class _Script:
    def __init__(self, *replies: _Reply) -> None:
        self.replies = list(replies)
        self.calls: list[tuple[tuple[Turn, ...], dict[str, JsonValue]]] = []
        self.after: Callable[[], None] | None = None

    async def complete(
        self, history: Sequence[Turn], schema: dict[str, JsonValue], *, deadline: Deadline
    ) -> JsonValue:
        del deadline
        self.calls.append((tuple(history), schema))
        reply = self.replies.pop(0)
        if self.after is not None:
            self.after()
        if isinstance(reply, Exception):
            raise reply
        return reply(tuple(history)) if callable(reply) else reply


class _Steps:
    """The step store contract in memory; the SQLite store is tested with its migration."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, int], tuple[bytes, bytes | None]] = {}

    async def reserve(self, kind: ReviewStepKind, ordinal: int, selector: bytes) -> None:
        if (kind, ordinal) in self.rows:
            raise ReviewStepRefused("review_step_refused")
        self.rows[(kind, ordinal)] = (selector, None)

    async def capture(self, kind: ReviewStepKind, ordinal: int, result: bytes) -> None:
        selector, saved = self.rows[(kind, ordinal)]
        if saved is not None:
            raise ReviewStepRefused("review_step_refused")
        self.rows[(kind, ordinal)] = (selector, result)

    async def usage(self) -> tuple[int, int]:
        return len(self.rows), sum(saved is None for _s, saved in self.rows.values())


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
    *replies: _Reply,
    roots: Sequence[ReadRoot] = (),
    policy: PrivacyPolicy | None = None,
    expired: bool = False,
    steps: _Steps | None = None,
    case: SemanticCase | None = None,
) -> tuple[ReviewerLoop, ReviewerBroker, _Script, list[PrivacyPolicy]]:
    current = [policy or with_llm(minimal_external_policy())]
    coordinator = _coordinator(current[0])
    binding = next(c for c in current[0].channel_policies if c.provider_binding).provider_binding
    assert binding is not None

    async def admit(elements: tuple[ReadElement, ...], envelope: bytes) -> str | None:
        coordinator._policies._policy = current[0]  # type: ignore[attr-defined]  # pyright: ignore
        request = "req_40000000-0000-4000-8000-000000000101"
        return await coordinator.admit_reviewer_read(request, _SCOPE, binding, elements, envelope)

    async def admissible(held: frozenset[str]) -> bool:
        return reviewer_history_admissible(current[0], binding, AuthorizationScopeKind.TASK, held)

    broker = ReviewerBroker(
        job_id="sjb_1",
        case=case or _semantic_case(_DELIVERABLE_DIFF, with_aws_key=False),
        roots=roots,
        store=steps or _Steps(),
        admit=admit,
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


def _observations(history: Sequence[Turn]) -> list[dict[str, JsonValue]]:
    return [json.loads(t.content) for t in history[2:] if t.role == "user" and t.content[0] == "{"]


@pytest.mark.anyio
async def test_a_frozen_ledger_miss_never_claims_the_item_was_not_recorded() -> None:
    from builders.policy_cases import obl
    from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
    from unit.application.test_semantic_case_prior_findings import (
        _build,  # pyright: ignore[reportPrivateUsage]
        _numba_case,  # pyright: ignore[reportPrivateUsage]
    )

    selection = replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
        sections=("deterministic_assessments",),
    )
    case = _build(_numba_case(), selection=selection)
    assert str(obl(1)) in case.frontier_refs  # recorded, but excluded by the frozen selection
    loop, broker, _, _ = _setup(
        _read("read_ledger", view="obligations", refs=[str(obl(1))], max_bytes=1024),
        _read("read_ledger", view="obligations", refs=[str(obl(999))], max_bytes=1024),
        _FINAL,
        case=case,
    )
    for result in _observations((await loop.run()).history):
        assert result["reason"] == "not_in_frozen_case"
        assert result["data"] is None and result["citable_refs"] == []
        assert "missing_for_assessment" in cast(str, result["continuation"])
        assert "target_refs" in cast(str, result["continuation"])
        assert cast(int, result["result_utf8_bytes"]) <= 1024
    assert not broker.cited_refs


def _data(result: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], result["data"])


@pytest.mark.anyio
@pytest.mark.parametrize(
    "suffix",
    [b"ordinary text", b"postgres:" + b"//alice:" + b"synthetic-password@db/name", "é".encode()],
)
async def test_a_native_read_over_the_physical_limit_withholds_every_byte(
    tmp_path: Path, suffix: bytes
) -> None:
    # #1134: even a credential or UTF-8 sequence split at the 1 MiB boundary is never exposed.
    cut = MAX_TASK_INPUT_READ_BYTES
    prefix = b"x\n" * ((cut - 20) // 2)
    data = prefix + suffix * 20
    (tmp_path / "large.txt").write_bytes(data)
    root = str(tmp_path.resolve())
    assert read_text_beneath(root, "large.txt", excluded=(), expired=lambda: False) == (
        b"",
        len(data),
    )
    loop, broker, _model, _ = _setup(
        _text("w1", "large.txt", len(prefix) // 2 + 1), _FINAL, roots=(ReadRoot("w1", root),)
    )
    (result,) = _observations((await loop.run()).history)
    assert (result["status"], result["reason"], result["truncated"]) == (
        "partial",
        "native_read_limit",
        True,
    )
    assert result["data"] == {"source_bytes": len(data)}
    assert result["citable_refs"] == [] and result["next_cursor"] is None
    assert not broker.text_by_ref


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("count", "hidden", "truncated"),
    [(32, False, False), (128, False, False), (129, False, True), (1000, True, True)],
)
async def test_native_directory_inspection_exhaustion_is_explicit(
    tmp_path: Path, count: int, hidden: bool, truncated: bool
) -> None:
    for i in range(count):
        (tmp_path / f"{'.' if hidden else ''}file{i:04}.txt").write_text("x")
    listing = list_beneath(str(tmp_path.resolve()), "", excluded=(), expired=lambda: False)
    assert listing is not None and listing[1] is truncated
    action = _read("read_file", root_id="w1", path=".", mode="list", cursor=None)
    loop, _broker, _model, _ = _setup(
        action, _FINAL, roots=(ReadRoot("w1", str(tmp_path.resolve())),)
    )
    (result,) = _observations((await loop.run()).history)
    assert result["truncated"] is (truncated or count > 32)
    assert result["reason"] == ("inspection_limit" if truncated else None)
    assert result["status"] == ("partial" if truncated or count > 32 else "ok")
    if hidden:
        assert result["data"] is None and result["next_cursor"] is None


@pytest.mark.anyio
async def test_a_large_valid_action_ends_as_capacity_before_reserving_a_read() -> None:
    # Escaping can make a valid action exceed the ordinary action allowance.
    loop, broker, model, _ = _setup(_text("w1", "\\" * 509))
    broker._exchange_room = lambda: 2048  # pyright: ignore[reportPrivateUsage]
    outcome = await loop.run()
    assert outcome.reason == "case_capacity_exceeded" and outcome.judgment is None
    assert outcome.capacity is not None and outcome.capacity[0] > outcome.capacity[1]
    assert broker.calls == 0 and len(model.calls) == 1
    assert await broker.store.usage() == (1, 0)


def _late(model: _Script, loop: ReviewerLoop) -> None:
    """The model's turn ends after the job deadline."""

    now = [1.0]
    loop.clock = lambda: now[0]
    model.after = lambda: now.__setitem__(0, 601.0)


# The reply contract


def test_reply_schema_has_four_disjoint_branches_and_a_final_only_form() -> None:
    full = reviewer_reply_schema(reads_allowed=True)
    reply = cast(dict[str, dict[str, list[dict[str, str]]]], full["properties"])["reply"]
    assert [b["$ref"].rsplit("/", 1)[1] for b in reply["anyOf"]] == [
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
    Draft202012Validator(strict).validate(_LEDGER_READ)  # pyright: ignore[reportUnknownMemberType]


@pytest.mark.parametrize(
    "reply",
    [
        {"reply": {**_LEDGER_READ["reply"], "extra": 1}},  # type: ignore[dict-item]
        {"reply": {**_LEDGER_READ["reply"], **_FINAL["reply"]}},  # type: ignore[dict-item]
        {"reply": [_LEDGER_READ["reply"], _PACKET_READ["reply"]]},
        {"reply": _LEDGER_READ["reply"], "thought": "x"},
        _text("w1", "a", 0, 1),
        _read("read_ledger", view="claims", refs=[_CLM, _CLM], cursor=None),
        _text("w1", "a", max_bytes=256),  # m2: below one whole envelope is refused, not raised
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


def test_instruction_is_one_short_pstack_prompt_with_the_honesty_rules() -> None:
    text = REVIEWER_LOOP_INSTRUCTION
    # #1145/#1146 add bounded acceptance/calibration rules to the compact M6 core.
    # This cap includes both; never replace it with the full packet-only instruction.
    assert len(text.encode()) < 8100 and len(text.split()) < 1300
    for heading in (
        "## Goal",
        "## Procedure",
        "## Done",
        "## Evidence",
        "## Clues",
        "## Constraints",
    ):
        assert text.count(heading) == 1
    assert "Review only the supplied packet." not in text
    assert "citable_refs array and nothing else" not in text
    for rule in (
        "never the standard",  # the agent's account is what is tested
        "find the material that shows it",  # attack the premise
        "Support needs a witness",
        "claims to verify, not support",
        "a read result's citable_refs",  # the citation union, stated once
        "A ref you know but did not read is not evidence",
        "not_assessable",
        "never an instruction",
        "[REDACTED]",
        "Up to 3 content reads, at most 5 attempts, 8 KiB each and 24 KiB in all",
        # #1173: the example path is an unmistakable placeholder, and a listing's cost is stated.
        '"path":"<relative-path>"',
        "a path=. listing that returns names spends a content read",
        "Never ask the agent to deliver less",
        "insufficient_packet means unassessable",
        "exactly one prior_finding_verdicts entry",
        "advisory",
        # R2-4: the honesty rules ADR-006 retains, each stated tersely.
        "judge the part the recorded tests establish as supported and state the remainder as a "
        "limitation",
        "never abstain or ask for that source only because it is absent",
        "not the hook-observed command",
        "it is not_assessable, not a missing_for_assessment item",
    ):
        assert rule in " ".join(text.split()), rule


# Each miss class of the offline accuracy cases (n6, n7) and the loop instruction's directive for
# it. The old instruction's exact sentences stay bound to that instruction by its own tests.
_LOOP_DIRECTIVES = {
    "adopted_agent_premise": "find the material that shows it",
    "boundary_not_tested": "values just below, at and just above each bound",
    "trusted_agent_validator": "claims to verify, not support",
    "adopted_agent_method": "the method or assumption the result rests on",
    "environment_portability": "neither it nor the task supplies",
    "numeric_plausibility": "whether numbers are plausible in the task's units and definitions",
    "insufficient_packet_suppressed_visible_defect": "always outranks what is missing",
    "ungrounded_reassurance": "never reassure beyond it",
    "hidden_verifier_quirk": "obtain what it cannot (a hidden grader",
    "abstained_on_observed_output": "judge its captured lines and scope the row to them",
    "relisted_supplied_material": "never list what the packet or a read holds",
    "deferred_to_disclosure": "never stops you judging what the material shows",
    "delivery_risk_on_correct_work": "An input or service the task supplies is no risk",
}
_ACCURACY_CASES = [
    case
    for name in ("n6_cases.json", "n7_cases.json")
    for case in json.loads((_REPO / "tests/fixtures/reviewer_accuracy" / name).read_text("utf-8"))[
        "cases"
    ]
]


@pytest.mark.parametrize("case", _ACCURACY_CASES, ids=lambda case: case["case"])
def test_each_offline_accuracy_case_is_bound_to_the_loop_instruction(
    case: dict[str, JsonValue],
) -> None:
    text = " ".join(REVIEWER_LOOP_INSTRUCTION.split())
    for miss in (case["miss"], *cast(list[str], case["secondary"])):
        assert _LOOP_DIRECTIVES[cast(str, miss)] in text, miss
    assert cast(str, case["case"]) not in text.casefold()


# The loop


@pytest.mark.anyio
async def test_no_read_review_is_one_completion() -> None:
    steps = _Steps()
    loop, _broker, model, _ = _setup(_FINAL, steps=steps)
    outcome = await loop.run()
    assert (outcome.status, outcome.model_turns, len(model.calls)) == ("final", 1, 1)
    history, schema = model.calls[0]
    assert [t.role for t in history] == ["system", "user"]
    assert schema == reviewer_reply_schema(reads_allowed=True, strict=True)
    assert list(steps.rows) == [("turn", 1)] and steps.rows[("turn", 1)][1] is not None


@pytest.mark.anyio
async def test_reads_append_observations_then_only_final_is_offered() -> None:
    steps = _Steps()
    loop, _broker, model, _ = _setup(_PACKET_READ, _LEDGER_READ, _LEDGER_READ, _FINAL, steps=steps)
    outcome = await loop.run()
    assert outcome.status == "final" and outcome.model_turns == 4
    first, second, third = _observations(outcome.history)
    assert first["status"] in {"ok", "partial"} and first["call_index"] == 1
    assert "evt_10000000-0000-4000-8000-000000000001" in cast(list[str], first["citable_refs"])
    records = cast(list[dict[str, str]], _data(second)["records"])
    assert records[0]["ref"].startswith("claim-")
    assert third["calls_remaining"] == 0
    assert model.calls[-1][1] == reviewer_reply_schema(reads_allowed=False, strict=True)
    for sent in (first, second, third):
        assert sent["result_utf8_bytes"] == len(canonical_encode(sent)) <= 8192
        assert sent["status"] != "ok" or sent["truncated"] is False  # m1
    # M4: every turn and read is a durable step, each captured with the exact sent bytes.
    assert sorted(steps.rows) == [
        *(("read", n) for n in (1, 2, 3)),
        *(("turn", n) for n in range(1, 5)),
    ]
    assert steps.rows[("read", 2)][1] == canonical_encode(second)


@pytest.mark.anyio
async def test_a_read_in_the_final_phase_gets_the_one_repair_asking_for_the_judgment() -> None:
    # #1173: the wire schema still offers reads after the cap (#1172), so a schema-valid read
    # there is the final phase's format error, never an INVALID review without a judgment.
    steps = _Steps()
    reads = (_LEDGER_READ,) * 4
    loop, broker, model, _ = _setup(*reads, _FINAL, steps=steps)
    outcome = await loop.run()
    assert (outcome.status, outcome.reason, outcome.model_turns) == ("final", None, 5)
    assert len(_observations(outcome.history)) == broker.calls == 3  # the late read never ran
    repair = model.calls[-1][0][-1].content
    assert repair.startswith("format_error: read_in_final_phase.") and "read action" not in repair
    assert "final_judgment only" in repair
    assert ("repair", 1) in steps.rows and ("read", 4) not in steps.rows
    # The late read is not echoed: the result, the final-phase notice, the repair, the judgment.
    assert [t.role for t in outcome.history[-4:]] == ["user", "user", "user", "assistant"]
    # A read after that repair executes nothing and ends the review; no second repair.
    loop, broker, model, _ = _setup(*reads, _LEDGER_READ)
    outcome = await loop.run()
    assert (outcome.status, outcome.reason, outcome.model_turns) == ("incomplete", "read_limit", 5)
    assert broker.calls == 3 and broker.reads_allowed() is False


@pytest.mark.anyio
async def test_one_format_repair_per_review() -> None:
    steps = _Steps()
    loop, _broker, model, _ = _setup({"reply": {}}, _LEDGER_READ, {"bad": 1}, steps=steps)
    outcome = await loop.run()
    assert (outcome.status, outcome.reason) == ("incomplete", "format_invalid")
    assert model.calls[1][0][-1].content.startswith("format_error: action_invalid.")
    assert "bad" not in "".join(t.content for t in outcome.history)  # malformed text not echoed
    assert ("repair", 1) in steps.rows
    repaired, _b, _m, _ = _setup("not json", _FINAL)
    assert (await repaired.run()).status == "final"


@pytest.mark.anyio
async def test_a_job_with_earlier_steps_is_not_resumed() -> None:
    steps = _Steps()
    await steps.reserve("read", 1, b"{}")
    loop, _broker, model, _ = _setup(_FINAL, steps=steps)
    assert ((await loop.run()).reason, model.calls) == ("uncaptured_step", [])
    await steps.capture("read", 1, b"{}")
    loop, _broker, model, _ = _setup(_FINAL, steps=steps)
    assert ((await loop.run()).reason, model.calls) == ("interrupted", [])


@pytest.mark.anyio
async def test_late_model_turns_are_not_used() -> None:
    # M1: a final answer that arrives after the deadline is not accepted.
    loop, _broker, model, _ = _setup(_FINAL)
    _late(model, loop)
    outcome = await loop.run()
    assert (outcome.status, outcome.reason) == ("incomplete", "deadline")
    # M1: nor is a read the late turn asked for reserved or run.
    steps = _Steps()
    loop, broker, model, _ = _setup(_LEDGER_READ, steps=steps)
    _late(model, loop)
    assert (await loop.run()).reason == "deadline"
    assert broker.calls == 0 and ("read", 1) not in steps.rows


@pytest.mark.anyio
async def test_a_local_read_past_its_time_ends_the_review(tmp_path: Path) -> None:
    # M1: the reader checks the local read budget inside its read and listing loops.
    (tmp_path / "a.txt").write_text("x\n")
    loop, broker, _model, _ = _setup(
        _text("w1", "a.txt"), _FINAL, roots=(ReadRoot("w1", str(tmp_path.resolve())),)
    )
    for action in (
        _text("w1", "a.txt"),
        _read("read_file", root_id="w1", path=".", mode="list", cursor=None),
    ):
        decoded = decode_reviewer_reply(action)
        assert not isinstance(decoded, SemanticJudgment)
        with pytest.raises(ReadDeadline):
            await broker.execute(decoded, lambda: True)
    broker.calls = 0
    broker.store = loop.store = _Steps()

    async def slow(_action: object, expired: Callable[[], bool], reply: str = "") -> str:
        del expired, reply
        raise ReadDeadline("reviewer_read_deadline")

    broker.execute = slow  # type: ignore[method-assign]
    outcome = await loop.run()
    assert (outcome.status, outcome.reason) == ("incomplete", "deadline")


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
    alias = ReadRoot("o1", root, input_root=root)
    read = _text("o1", "spec.md", 1, 5)
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
    outcome = await loop.run()
    (refused,) = _observations(outcome.history)
    assert (outcome.status, refused["status"], refused["reason"], refused["data"]) == (
        "final",
        "denied",
        "authorization_changed",
        None,
    )
    assert "GT_ZERO" not in json.dumps(refused) and root not in broker.history_roots


@pytest.mark.anyio
async def test_citations_are_the_sent_union_and_feed_the_existing_fence() -> None:
    # M2: the outcome carries the packet+reads union, and check's own fence enforces it.
    def final_quoting_the_read(history: tuple[Turn, ...]) -> JsonValue:
        (result,) = _observations(history)
        text = cast(list[dict[str, str]], _data(result)["records"])[0]["text"]
        final = deepcopy(_FINAL)
        row = cast(dict[str, list[dict[str, JsonValue]]], final["reply"])["final_judgment"]
        row["verified"][0]["snippet"] = text[:40]  # type: ignore[index]
        return final

    loop, _broker, _model, _ = _setup(_LEDGER_READ, final_quoting_the_read)
    outcome = await loop.run()
    case = make_case(extra_refs=(clm(1),))
    assert outcome.judgment is not None and _CLM in outcome.citable_refs

    def fenced(judgment: SemanticJudgment) -> tuple[int, int, int]:
        review = validate_semantic_judgment(
            case,
            (),
            judgment,
            _provenance(),
            expected_frontier=case.frontier,
            citable_refs=outcome.citable_refs,
            provider_input_text_by_ref=outcome.text_by_ref,
        )
        return len(review.verified), review.snippets_rejected, review.refs_reduced

    assert fenced(outcome.judgment) == (1, 0, 0)
    unseen = deepcopy(_FINAL)
    row = cast(dict[str, list[dict[str, JsonValue]]], unseen["reply"])["final_judgment"]
    row["verified"][0]["snippet"] = "THIS QUOTE WAS NEVER SENT"  # type: ignore[index]
    unseen_judgment = decode_reviewer_reply(unseen)
    assert isinstance(unseen_judgment, SemanticJudgment)
    assert fenced(unseen_judgment) == (0, 1, 0)


# The broker


@pytest.mark.anyio
async def test_file_reads_stay_in_scope_and_are_admitted_like_the_packet(tmp_path: Path) -> None:
    work = tmp_path / "work"
    (work / "src").mkdir(parents=True)
    (work / "src" / "a.py").write_text("".join(f"line {n} {'x' * 60}\n" for n in range(1, 400)))
    (work / "src" / "key.py").write_text('KEY = "AKIAQ3EGRL7X2VNTWB5D"\n')
    (work / ".env").write_text("SECRET=1\n")
    (work / "linked.py").symlink_to(work / "src" / "a.py")
    w1 = ReadRoot("w1", str(work.resolve()), subject_refs=(_CLM,))
    shared = tmp_path / "shared"
    (shared / "specs").mkdir(parents=True)
    (shared / "customer").mkdir()
    (shared / "specs" / "s.md").write_text("spec\n")
    root = str(shared.resolve())
    o1 = ReadRoot("o1", root, input_root=root, declared=("specs",))
    policy = replace(with_llm(minimal_external_policy()), admitted_input_roots=(root,))
    loop, broker, _model, _ = _setup(
        _text("w1", "./src/a.py", 10, 200),
        _text("w1", "../work/src/a.py"),
        _text("w1", ".env"),
        _FINAL,
        roots=(w1, o1),
        policy=policy,
    )
    span, escape, hidden = _observations((await loop.run()).history)
    text = cast(str, _data(span)["text"])
    assert span["status"] == "partial" and text.startswith("line 10 x")
    assert cast(int, span["result_utf8_bytes"]) <= 8192 and span["truncated"] is True
    assert (escape["reason"], hidden["reason"]) == ("forbidden_path", "forbidden_path")
    assert hidden["data"] is None and hidden["citable_refs"] == []
    # The fence holds exactly the fitted text the reviewer was sent, nothing cut from it.
    assert broker.text_by_ref[_CLM] == [text]

    loop, broker, _model, _ = _setup(
        _text("w1", "linked.py"),
        _text("w1", "src/key.py"),
        _read("read_file", root_id="o1", path="customer", mode="list", cursor=None),
        _FINAL,
        roots=(w1, o1),
        policy=policy,
    )
    link, key, sibling = _observations((await loop.run()).history)
    assert link["reason"] == "not_recorded"
    assert key["status"] == "denied" and key["reason"] == "privacy_withheld"
    assert "AKIA" not in json.dumps(key)
    assert sibling["reason"] == "outside_scope"


@pytest.mark.anyio
async def test_no_label_or_name_carries_what_admission_did_not_scan(tmp_path: Path) -> None:
    # B1: a secret-shaped file name never reaches the result: the path is not echoed, and a
    # listing's names are admitted items scanned with the whole encoded result.
    name = "AKIAQ3EGRL7X2VNTWB5D.py"  # synthetic known scanner fixture, not a credential
    (tmp_path / name).write_text("ordinary content\n")
    (tmp_path / "ok.py").write_text("x\n")
    loop, _broker, _model, _ = _setup(
        _text("w1", name, 1, 1),
        _read("read_file", root_id="w1", path=".", mode="list", cursor=None),
        _FINAL,
        roots=(ReadRoot("w1", str(tmp_path.resolve())),),
    )
    for result in _observations((await loop.run()).history):
        encoded = canonical_encode(result)
        assert name.encode() not in encoded and not scan_exact_bytes(encoded)
        assert result["status"] in {"ok", "denied"}


@pytest.mark.anyio
async def test_listing_filters_every_child_and_cites_only_what_it_sent(tmp_path: Path) -> None:
    # M3: the refuse rule and the declared scope apply to each child, not only the directory.
    (tmp_path / "ordinary.txt").write_text("a")
    (tmp_path / "ignored.txt").write_text("b")
    (tmp_path / "shared.txt").write_text("c")
    (tmp_path / "shared.txt").chmod(0o666)  # another account may write it: untrusted
    root = ReadRoot("w1", str(tmp_path.resolve()), refuse=lambda p: p == "ignored.txt")
    listing = _read("read_file", root_id="w1", path=".", mode="list", cursor=None)
    loop, _broker, _model, _ = _setup(listing, _FINAL, roots=(root,))
    (result,) = _observations((await loop.run()).history)
    assert cast(list[JsonValue], _data(result)["entries"]) == [
        {"name": "ordinary.txt", "kind": "file"}
    ]
    # M2/m1: entries the envelope could not carry are neither citable nor skipped by the cursor.
    names = [f"{i:02d}-{'x' * 180}.txt" for i in range(25)]
    (tmp_path / "specs").mkdir()
    for n in names:
        (tmp_path / "specs" / n).write_text("t")
    s1 = ReadRoot("s1", str(tmp_path.resolve()), subject_refs=(_CLM,))
    page = _read("read_file", root_id="s1", path="specs", mode="list", cursor=None, max_bytes=1024)

    def next_page(history: tuple[Turn, ...]) -> JsonValue:
        cursor = _observations(history)[0]["next_cursor"]
        return _read("read_file", root_id="s1", path="specs", mode="list", cursor=cursor)

    loop, broker, _model, _ = _setup(page, next_page, _FINAL, roots=(s1,))
    first, second = _observations((await loop.run()).history)
    sent = [cast(str, e["name"]) for e in cast(list[dict[str, JsonValue]], _data(first)["entries"])]
    assert 0 < len(sent) < 25 and first["status"] == "partial" and first["next_cursor"] is not None
    assert broker.text_by_ref[_CLM][: len(sent)] == sent
    assert not any(n in "".join(broker.text_by_ref[_CLM][: len(sent)]) for n in names[len(sent) :])
    following = cast(list[dict[str, JsonValue]], _data(second)["entries"])
    assert following[0]["name"] == names[len(sent)]  # the cursor resumes at the first unsent
    prov = cast(dict[str, JsonValue], _data(first)["provenance"])
    assert (prov["baseline"], prov["standing"], prov["root_id"]) == (
        "read_time",
        "workspace_content",
        "s1",
    )


@pytest.mark.anyio
async def test_fitted_spans_and_lines_describe_exactly_the_sent_text(tmp_path: Path) -> None:
    # m1: escaping-heavy text is cut again to fit; its span and lines follow the cut.
    (tmp_path / "a.txt").write_text(('"' * 99 + "\n") * 100)
    loop, _broker, _model, _ = _setup(
        _text("w1", "a.txt", 1, 100), _FINAL, roots=(ReadRoot("w1", str(tmp_path.resolve())),)
    )
    (result,) = _observations((await loop.run()).history)
    data = _data(result)
    text = cast(str, data["text"]).encode()
    prov = cast(dict[str, dict[str, int]], data["provenance"])
    assert prov["span"]["end_exclusive"] - prov["span"]["start"] == len(text)
    assert prov["line_span"]["end_inclusive"] == 1 + text.count(b"\n") - text.endswith(b"\n")
    assert result["status"] == "partial" and result["truncated"] is True
    # A span within the room is exactly the requested lines, nothing after them.
    loop, _broker, _model, _ = _setup(
        _text("w1", "a.txt", 2, 1), _FINAL, roots=(ReadRoot("w1", str(tmp_path.resolve())),)
    )
    (one,) = _observations((await loop.run()).history)
    assert (_data(one)["text"], one["status"]) == ('"' * 99 + "\n", "ok")
    one_prov = cast(dict[str, dict[str, int]], _data(one)["provenance"])
    assert one_prov["line_span"] == {"start": 2, "end_inclusive": 2}


@pytest.mark.anyio
async def test_cursors_are_bound_to_their_read_and_source() -> None:
    # M5: a forged, Unicode or rebound cursor is refused with a fixed reason, never restarted.
    loop, _broker, _model, _ = _setup(
        _read("read_ledger", view="claims", refs=[_CLM], cursor="forged-unbound-cursor"),
        _read("read_ledger", view="claims", refs=[_CLM], cursor="²"),
        _FINAL,
    )
    outcome = await loop.run()
    for result in _observations(outcome.history):
        assert (result["status"], result["reason"], result["data"]) == (
            "denied",
            "invalid_request",
            None,
        )
    assert outcome.status == "final"


@pytest.mark.anyio
async def test_byte_totals_never_exceed_the_review_allowance() -> None:
    snapshot = TaskInputSnapshotSet(
        "admission_time",
        (SnapshotFile("/srv/shared/specs/a.md", "/srv/shared", b"x" * 20_000, 20_000),),
    )
    s1 = ReadRoot("s1", "/srv/shared", input_root="/srv/shared", snapshot=snapshot)
    policy = replace(with_llm(minimal_external_policy()), admitted_input_roots=("/srv/shared",))
    big = _text("s1", "specs/a.md", 1, 1)
    loop, _broker, _model, _ = _setup(big, big, big, _FINAL, roots=(s1,), policy=policy)
    results = _observations((await loop.run()).history)
    total = sum(cast(int, r["result_utf8_bytes"]) for r in results)
    assert total <= 24_576 and results[-1]["bytes_remaining"] == 24_576 - total
    prov = cast(dict[str, JsonValue], _data(results[0])["provenance"])
    assert prov["baseline"] == "admission_time" and prov["source_ref"] == "sjb_1:read:1"


# Review round 2 (R2-2, R2-3, R2-5, R2-6): each probe asserting a defect now asserts the fix.


@pytest.mark.anyio
async def test_a_listing_sends_whole_names_and_resumes_at_the_first_omitted(
    tmp_path: Path,
) -> None:
    # R2-3: entries are indivisible; a name is never shortened into one that does not exist.
    names = [f"{i:02d}-{'x' * 180}.txt" for i in range(25)]
    for name in names:
        (tmp_path / name).write_text("t")
    root = ReadRoot("w1", str(tmp_path.resolve()), subject_refs=(_CLM,))
    page = _read("read_file", root_id="w1", path=".", mode="list", cursor=None, max_bytes=1024)

    def next_page(history: tuple[Turn, ...]) -> JsonValue:
        cursor = _observations(history)[0]["next_cursor"]
        return _read("read_file", root_id="w1", path=".", mode="list", cursor=cursor)

    loop, broker, _model, _ = _setup(page, next_page, _FINAL, roots=(root,))
    first, second = _observations((await loop.run()).history)
    sent = [e["name"] for e in cast(list[dict[str, str]], _data(first)["entries"])]
    assert sent == names[: len(sent)] and 0 < len(sent) < 25
    assert cast(int, first["result_utf8_bytes"]) <= 1024 and first["status"] == "partial"
    following = [e["name"] for e in cast(list[dict[str, str]], _data(second)["entries"])]
    assert following[0] == names[len(sent)] and set(following) <= set(names)
    assert broker.text_by_ref[_CLM] == sent + following


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["text", "list"])
async def test_a_read_that_completes_past_its_local_stop_is_discarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    # R2-2: the last chunk or the listing's completion crosses the 5-second stop. The result is
    # not used; this is a check after the blocking call returns, not preemption of it.
    import finishup.adapters.task_input_read as reader
    import finishup.application.reviewer_broker as broker_module

    (tmp_path / "a.txt").write_text("ordinary text")
    action = (
        _text("w1", "a.txt", 1, 1)
        if mode == "text"
        else _read("read_file", root_id="w1", path=".", mode="list", cursor=None)
    )
    steps = _Steps()
    loop, broker, _model, _ = _setup(
        action, _FINAL, roots=(ReadRoot("w1", str(tmp_path.resolve())),), steps=steps
    )
    now = [1.0]
    loop.clock = lambda: now[0]
    target = (reader.os, "read") if mode == "text" else (broker_module, "list_beneath")
    original = getattr(*target)

    def slow(*args: object, **kwargs: object) -> object:
        value = original(*args, **kwargs)
        now[0] = 7.0  # the local stop is 1 + 5; the job deadline is far away
        return value

    monkeypatch.setattr(*target, slow)
    outcome = await loop.run()
    assert (outcome.status, outcome.reason, _observations(outcome.history)) == (
        "incomplete",
        "deadline",
        [],
    )
    assert steps.rows[("read", 1)][1] is None and "ordinary" not in str(broker.text_by_ref)


@pytest.mark.anyio
async def test_citations_follow_the_advertised_refs_and_the_fallback_fits(
    tmp_path: Path,
) -> None:
    # R2-5: twenty refs bound to one file; the result advertises 16 and only those are citable.
    # R2-6: when no data fits, the fallback carries no refs and stays within max_bytes.
    (tmp_path / "a.txt").write_text("ordinary text")
    refs = tuple(f"clm_00000000-0000-4000-8000-{i:012d}" for i in range(1, 21))
    root = ReadRoot("w1", str(tmp_path.resolve()), subject_refs=refs)
    for budget in (8192, 1024):
        read = _text("w1", "a.txt", 1, 1, max_bytes=budget)
        loop, broker, _model, _ = _setup(read, _FINAL, roots=(root,))
        case = replace(broker._case, frontier_refs=broker._case.frontier_refs | frozenset(refs))  # pyright: ignore[reportPrivateUsage]
        loop.broker = ReviewerBroker(
            job_id="sjb_1",
            case=case,
            roots=(root,),
            store=broker.store,
            admit=broker._admit,  # pyright: ignore[reportPrivateUsage]
        )
        outcome = await loop.run()
        (result,) = _observations(outcome.history)
        advertised = set(cast(list[str], result["citable_refs"]))
        assert outcome.citable_refs == advertised == set(outcome.text_by_ref)
        assert cast(int, result["result_utf8_bytes"]) <= budget
        if budget == 8192:
            assert len(advertised) == 16 and result["status"] == "ok"
        else:
            assert (result["status"], result["reason"], result["data"]) == (
                "unavailable",
                "byte_budget",
                None,
            )
            assert advertised == set() and result["next_cursor"] is None


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["file", "packet", "ledger"])
async def test_a_wrong_selector_recovers_without_spending_a_content_read(
    tmp_path: Path, kind: str
) -> None:
    (tmp_path / "calc.py").write_text("selector_recovery_witness\n")
    root = ReadRoot("w1", str(tmp_path.resolve()))
    wrong = {
        "file": _text("w1", "/absolute/calc.py", max_bytes=1024),
        "packet": _read(
            "read_packet_section", section="agent_account", item_ref=_CLM, offset=0, max_bytes=1024
        ),
        "ledger": _read("read_ledger", view="claims", refs=["goal-1"], cursor=None, max_bytes=1024),
    }[kind]

    def correct(history: tuple[Turn, ...]) -> JsonValue:
        result = _observations(history)[-1]
        assert result["status"] in {"unavailable", "denied"}
        assert result["calls_remaining"] == 3
        assert result["result_utf8_bytes"] == len(canonical_encode(result)) <= 1024
        if kind == "file":
            assert result["allowed_root_ids"] == ["w1"]
            assert "relative" in cast(str, result["continuation"])
            return _text("w1", "calc.py")
        row = cast(list[dict[str, JsonValue]], result["alternatives"])[0]
        if kind == "packet":
            return _read(
                "read_packet_section",
                section=cast(list[str], row["sections"])[0],
                item_ref=row["item_id"],
                offset=0,
            )
        return _read(
            "read_ledger",
            view=cast(list[str], row["views"])[0],
            refs=[row["source_ref"]],
            cursor=None,
        )

    loop, broker, model, _ = _setup(
        wrong, correct, _LEDGER_READ, _LEDGER_READ, _FINAL, roots=[root]
    )
    broker._job = "job_00000000-0000-4000-8000-000000000001"  # pyright: ignore[reportPrivateUsage]
    outcome = await loop.run()
    assert outcome.status == "final" and outcome.model_turns == 5
    assert broker.calls == 4 and broker.content_reads == 3
    results = _observations(outcome.history)
    assert all(r["status"] in {"ok", "partial"} for r in results[1:])
    assert results[-1]["calls_remaining"] == 0
    assert "final_judgment now" in model.calls[-1][0][-1].content
    usage = read_usage_from_wire(broker.read_usage)
    assert usage is not None and len(usage) == 4
    assert "selector_recovery_witness" not in json.dumps(usage)
    assert all(set(row) == {"call", "action", "args", "status", "reason"} for row in usage)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("root_id", "path", "reason", "cause", "aliases"),
    [
        ("w1", "/abs/secret.txt", "forbidden_path", "drop the filesystem prefix", ["w1"]),
        ("w1", "secret.txt", "forbidden_path", "ignore rules exclude this path", ["w1"]),
        ("w1", ".env", "forbidden_path", "Hidden (dot-prefixed)", ["w1"]),
        ("w1", "../w/calc.py", "forbidden_path", "traversing (..)", ["w1"]),
        ("zz", "calc.py", "forbidden_path", "must be one of allowed_root_ids", ["o1", "w1"]),
        ("o1", "customer/notes.md", "outside_scope", "task-declared paths", ["o1"]),
    ],
)
async def test_each_refused_path_gets_its_own_correction_without_echoing_it(
    tmp_path: Path, root_id: str, path: str, reason: str, cause: str, aliases: list[str]
) -> None:
    # #1173: an ignored or hidden relative path is not told to "use a relative path", and
    # outside_scope gets a correction too; none repeats the refused path or a copyable example.
    work, shared = tmp_path / "w", tmp_path / "shared"
    (shared / "specs").mkdir(parents=True)
    work.mkdir()
    (work / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    root = str(shared.resolve())
    roots = (
        ReadRoot("w1", str(work.resolve()), refuse=lambda name: name == "secret.txt"),
        ReadRoot("o1", root, input_root=root, declared=("specs",)),
    )
    policy = replace(with_llm(minimal_external_policy()), admitted_input_roots=(root,))
    action = _text(root_id, path, max_bytes=1024)
    loop, broker, _, _ = _setup(action, _FINAL, roots=roots, policy=policy)
    (result,) = _observations((await loop.run()).history)
    assert (result["status"], result["reason"], result["data"]) == ("denied", reason, None)
    assert result["allowed_root_ids"] == aliases and result["calls_remaining"] == 3
    continuation = cast(str, result["continuation"])
    assert cause in continuation
    if cause in {"ignore rules exclude this path", "Hidden (dot-prefixed)", "traversing (..)"}:
        assert "relative to the root_id" not in continuation  # no absolute-path advice
    encoded = canonical_encode(result).decode()
    for echoed in (path, path.rsplit("/", 1)[-1], "src/main.py"):
        assert echoed not in encoded
    assert broker.content_reads == 0


@pytest.mark.anyio
async def test_five_empty_attempts_and_one_repair_are_a_hard_no_loop_bound() -> None:
    wrong = _read("read_ledger", view="claims", refs=["unknown"], cursor=None)
    loop, broker, model, _ = _setup({}, *([wrong] * 5), _FINAL)
    outcome = await loop.run()
    assert outcome.status == "final" and len(model.calls) == outcome.model_turns == 7
    assert broker.calls == 5 and broker.content_reads == 0 and not broker.reads_allowed()
    assert [r["calls_remaining"] for r in _observations(outcome.history)] == [3, 3, 2, 1, 0]
    # Every failed attempt remains durably spent; another run cannot refill the allowance.
    assert (await loop.run()).reason == "interrupted"
    assert len(model.calls) == 7


@pytest.mark.anyio
async def test_a_sixth_failed_read_is_refused_without_an_observation() -> None:
    wrong = _text("w1", "/wrong")
    # The sixth read gets the final phase's one repair; a seventh ends the review.
    loop, broker, model, _ = _setup(*([wrong] * 7))
    outcome = await loop.run()
    assert outcome.reason == "read_limit" and outcome.model_turns == len(model.calls) == 7
    assert len(_observations(outcome.history)) == broker.calls == 5
    assert model.calls[-1][0][-1].content.startswith("format_error: read_in_final_phase.")


@pytest.mark.anyio
async def test_empty_native_refusals_do_not_count_as_content_reads(tmp_path: Path) -> None:
    (tmp_path / "empty.txt").write_text("")
    (tmp_path / "oversize.txt").write_bytes(b"x" * (MAX_TASK_INPUT_READ_BYTES + 1))
    loop, broker, _, _ = _setup(
        _text("w1", "empty.txt", max_bytes=1024),
        _text("w1", "oversize.txt"),
        _FINAL,
        roots=[ReadRoot("w1", str(tmp_path.resolve()))],
    )
    outcome = await loop.run()
    empty, oversize = _observations(outcome.history)
    assert empty["reason"] == "not_recorded" and "never recorded" in cast(
        str, empty["continuation"]
    )
    assert "missing_for_assessment" in cast(str, empty["continuation"])
    assert oversize["reason"] == "native_read_limit"
    assert broker.calls == 2 and broker.content_reads == 0


@pytest.mark.anyio
@pytest.mark.parametrize("static_admitted", [True, False])
async def test_correction_metadata_is_admitted_and_never_contains_item_content(
    static_admitted: bool,
) -> None:
    loop, broker, _, _ = _setup(
        _read("read_packet_section", section="agent_account", item_ref="wrong", offset=0), _FINAL
    )
    admitted: list[tuple[tuple[ReadElement, ...], bytes]] = []

    async def withhold_rows(elements: tuple[ReadElement, ...], envelope: bytes) -> str | None:
        admitted.append((elements, envelope))
        assert b"self.retries" not in envelope
        return "privacy_withheld" if elements or not static_admitted else None

    broker._admit = withhold_rows  # pyright: ignore[reportPrivateUsage]
    result = _observations((await loop.run()).history)[0]
    (rows, with_rows), (none, static) = admitted
    assert rows and b'"alternatives"' in with_rows and none == ()
    assert "alternatives" not in result and result["data"] is None
    assert not broker.cited_refs and broker.content_reads == 0
    if static_admitted:
        # #1173: withholding the catalog rows keeps the static #1148 continuation, which is
        # itself scanned in the exact envelope that is sent.
        assert canonical_encode(result) == static
        continuation = cast(str, result["continuation"])
        assert "does not establish that the item was never recorded" in continuation
        assert "missing_for_assessment" in continuation and "retry a listed" not in continuation
    else:
        assert "continuation" not in result


@pytest.mark.anyio
async def test_retry_attempts_share_the_original_deadline_and_final_reserve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop, broker, model, _ = _setup(_text("w1", "/wrong"), _FINAL)
    now = [1.0]
    loop.clock = lambda: now[0]
    # The first reply leaves one second for the local read, then the next turn is final.
    model.after = lambda: now.__setitem__(0, 569.0 if len(model.calls) == 1 else 570.0)
    capture = broker.store.capture

    async def advance(kind: ReviewStepKind, ordinal: int, result: bytes) -> None:
        await capture(kind, ordinal, result)
        if kind == "read":
            now[0] = 570.0

    monkeypatch.setattr(broker.store, "capture", advance)
    outcome = await loop.run()
    assert outcome.status == "final" and len(model.calls) == 2 and broker.calls == 1
    assert "final_judgment now" in model.calls[-1][0][-1].content


@pytest.mark.anyio
async def test_a_correction_admitted_after_the_local_stop_is_not_sent() -> None:
    loop, broker, model, _ = _setup(_text("w1", "/wrong"))
    now = [1.0]
    loop.clock = lambda: now[0]

    async def late(_elements: tuple[ReadElement, ...], _envelope: bytes) -> None:
        now[0] = 6.0

    broker._admit = late  # pyright: ignore[reportPrivateUsage]
    outcome = await loop.run()
    assert outcome.reason == "deadline" and len(model.calls) == 1
    assert _observations(outcome.history) == []
    assert broker.read_usage[0]["reason"] == "deadline"


def test_the_provider_wire_schema_is_identical_in_both_phases() -> None:
    from finishup.adapters.providers.reviewer_reply import REVIEWER_REPLY_SCHEMAS

    assert REVIEWER_REPLY_SCHEMAS.turn == REVIEWER_REPLY_SCHEMAS.final
