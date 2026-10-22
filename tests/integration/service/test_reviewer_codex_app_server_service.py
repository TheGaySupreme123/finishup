"""#1118: one review through the ready service to the real Codex evaluator and a fake app-server.

The benchmark smoke ran the Codex subscription route and every review failed before anything was
sent (``case_invalid``, ``codex_reviewer_session_unknown``): the service's first exchange carries
the packet *and* the read catalog as two user messages, and the evaluator only opened a thread
for a two-message history. The other service reviewer tests replace ``build_evaluator`` on the
Responses route, so no test ran the service's own exchange bytes through
``CodexAppServerEvaluator``. Here nothing on that path is scripted except the app-server process:
the real composition builds ``CodexAppServerExternalFactory`` from the configured runtime binding,
the real gateway renders, admits and consumes each exchange, and the real evaluator drives a
JSONL app-server child through its own request, read and process-group cleanup code.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from builders.codex_capability import binding_for, retained_runtime, write_home
from builders.fake_codex_app_server import launcher
from builders.multi_agent import INSTALLATION_ID, multi_agent_service
from builders.privacy_policies import minimal_external_policy
from builders.privacy_widenings import with_llm
from builders.projection_workflow import ProjectionCase, project_case
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.providers import codex_app_server as codex
from finishup.adapters.providers import reviewer_cache_telemetry as telemetry
from finishup.adapters.providers.codex_app_server import codex_binding_from_config
from finishup.adapters.providers.codex_capability import host_codex_platform
from finishup.adapters.providers.reviewer_reply import REVIEWER_LOOP_INSTRUCTION
from finishup.adapters.repository_identity import resolve_repository_privacy_context
from finishup.application.privacy_policy import (
    DecidePrivacyPolicyRequest,
    PolicyDecisionRequired,
    ProposePrivacyPolicyRequest,
    decide_privacy_policy,
    privacy_propose_policy,
)
from finishup.application.reviewer_loop import FINAL_PHASE
from finishup.config.models import FinishUpConfig
from finishup.domain.privacy import AuthorizationScope, AuthorizationScopeKind, PrivacyPolicy
from finishup.ports.control import ControlMethod, WorkspaceLocator
from finishup.ports.keys import MacKeyPurpose
from finishup.ports.privacy import (
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    HumanPolicyDecision,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    SemanticReason,
    SemanticStatus,
    StartRequest,
)

pytestmark = pytest.mark.anyio

_STATEMENT = "Make add(a, b) in calc.py return the sum of a and b, and keep test_calc.py passing."
_READ: dict[str, JsonValue] = {
    "reply": {
        "action": "read_file",
        "args": {
            "root_id": "w1",
            "path": "calc.py",
            "mode": "text",
            "start_line": 1,
            "line_count": 40,
        },
    }
}
_FINAL: dict[str, JsonValue] = {
    "reply": {
        "final_judgment": {
            "conclusion": "no_material_discrepancy",
            "review_summary": "Read calc.py: add returns a + b.",
            "verified": [],
            "reviewer_challenges": [],
            "prior_finding_verdicts": [],
        }
    }
}


@pytest.fixture(autouse=True)
def work_has_begun(monkeypatch: pytest.MonkeyPatch) -> None:
    """The review runs as if the first edit were recorded (no pre-edit deferral)."""

    import finishup.application.check as check_module

    def edited(*_args: object) -> bool:
        return True

    monkeypatch.setattr(check_module, "material_edit_recorded", edited)


async def _widen(service: object, commitment: str, policy: PrivacyPolicy) -> None:
    """The owner's trusted step: widen this repository's policy to the Codex route."""

    app, clock, vault = (getattr(service, name) for name in ("app", "clock", "vault"))
    policy_app = app.privacy.policy_application
    scope = AuthorizationScope(AuthorizationScopeKind.WORKSPACE, INSTALLATION_ID, commitment)
    authority = await policy_app.policy_store.repository_authority(scope)
    candidate = replace(policy, effective_scope=scope, created_at=clock.now_utc())
    proposed = await privacy_propose_policy(
        policy_app,
        ProposePrivacyPolicyRequest(
            authority.effective.effective_digest, candidate, authority.authority_digest, scope
        ),
    )
    assert isinstance(proposed, PolicyDecisionRequired)
    await decide_privacy_policy(
        policy_app,
        DecidePrivacyPolicyRequest(
            proposed.prepared,
            HumanPolicyDecision(
                proposed.prepared.prepared_digest, True, clock.now_utc(), "hmac-sha256:" + "8" * 64
            ),
            HumanAuthorityCapability(
                "established_passphrase",
                "sha256:" + "9" * 64,
                1,
                str(getattr(vault.mode, "value", vault.mode)),
                vault.generation,
                True,
            ),
        ),
    )


async def _review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answers: list[str]
) -> tuple[Any, list[dict[str, Any]], Mapping[str, JsonValue]]:
    """One semantic check through the ready service; the checked result, wire and MCP wire."""

    tmp_path.chmod(0o700)
    executable, record = retained_runtime(
        tmp_path / "bundle", version="0.162.1", platform=host_codex_platform()
    )
    home = write_home(tmp_path / "codex-home")
    runtime = binding_for(record, executable, home, reasoning_effort="medium")
    script, log = tmp_path / "app-server-script.json", tmp_path / "app-server-wire.jsonl"
    script.write_text(
        json.dumps(
            {
                "codex_home": str(home),
                "version": "0.162.1",
                "model": runtime.model,
                "efforts": ["low", "medium", "high", "xhigh"],
                "answers": answers,
            }
        )
    )
    # Only the child process is fake: launch it as Codex would be launched, then let the real
    # ``_CodexProcess`` and ``_cleanup`` talk to it and end its process group.
    monkeypatch.setattr(codex, "_launch", launcher(script, log))

    workspace = (tmp_path / "work").resolve()
    workspace.mkdir()
    (workspace / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    for argv in (
        ("init", "-q", "-b", "main"),
        ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "."),
        ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "base"),
    ):
        subprocess.run(("git", *argv), cwd=workspace, check=True, capture_output=True)

    binding = codex_binding_from_config(runtime)
    policy = with_llm(minimal_external_policy(), provider_binding=binding, max_tokens=65_536)
    config = FinishUpConfig(profile="codex-subscription", external_runtime=runtime)
    async with multi_agent_service(tmp_path / "state", config=config) as service:
        policy_store = service.app.privacy.policy_application.policy_store  # type: ignore[union-attr]
        original_effective_policy = policy_store.effective_policy
        task_policy = [EffectivePrivacyPolicy(policy, 2, policy.policy_digest)]
        task_scopes: list[AuthorizationScope] = []

        async def effective_policy(_store: object, scope: AuthorizationScope) -> object:
            if scope.kind is AuthorizationScopeKind.TASK:
                task_scopes.append(scope)
                return task_policy[-1]
            return await original_effective_policy(scope)

        monkeypatch.setattr(type(policy_store), "effective_policy", effective_policy)
        lookup = service.vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
        repository = await resolve_repository_privacy_context(
            WorkspaceLocator(str(workspace)), lookup
        )
        observations = LocalObservationStore(_state=service.root / "state")
        observations.grant_consent(observations.workspace_commitment(str(workspace)))
        common: dict[str, JsonValue] = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "actor": {"actor_id": "harness:reviewer-codex", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.3.0",
                "integration": "cooperative_mcp",
            },
        }
        started = await service.app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": new_id(IdKind.REQUEST),
                    "mode": "create",
                    "task_title": "Reviewer conversation on Codex",
                    "workspace_ref": str(workspace),
                    "external_ref": "reviewer-codex",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=repository,
        )
        check_body: dict[str, JsonValue] = {
            **common,
            "request_id": new_id(IdKind.REQUEST),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": started.frontier.model_dump(mode="json"),
            "mode": "semantic_required",
            "max_findings": "3",
            "policy_packs": ["work-integrity/0.3.0"],
        }

        async def check() -> Any:
            return await service.app.check(
                CheckRequest.model_validate(check_body), repository_privacy_context=repository
            )

        assert getattr(await check(), "state") == "awaiting_input"
        await service.app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **common,
                    "request_id": new_id(IdKind.REQUEST),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": started.frontier.model_dump(mode="json"),
                    "event_drafts": [
                        {
                            "event_id": new_id(IdKind.EVENT),
                            "schema": {"name": "plan_published", "version": "1.1.0"},
                            "occurred_at": "2026-10-19T12:00:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "plan_version": 1,
                                "summary": "Fix add.",
                                "obligation_refs": [],
                                "task_statement": _STATEMENT,
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                    ],
                }
            ),
            repository_privacy_context=repository,
        )
        await _widen(service, repository.commitment, policy)
        authority = await policy_store.repository_authority(task_scopes[-1])
        task_policy.append(authority.effective)

        checked = await check()
        wire = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        mcp_wire: Mapping[str, JsonValue] = {}
        if type(checked).__name__ == "CheckCommitResult":
            mcp_wire = await project_case(
                service.app, ProjectionCase("check", ControlMethod.CHECK, check_body, checked), 7300
            )
        return checked, wire, mcp_wire


def _encoded(*replies: dict[str, JsonValue]) -> list[str]:
    return [canonical_encode(reply).decode() for reply in replies]


async def test_a_service_review_runs_on_one_codex_thread_through_the_real_evaluator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_records: list[dict[str, Any]] = []

    def record(**fields: Any) -> str:
        cache_records.append(fields)
        return new_id(IdKind.CORRELATION)

    monkeypatch.setattr(telemetry, "record_bounded_counts_without_raising", record)
    checked, wire, mcp_wire = await _review(tmp_path, monkeypatch, _encoded(_READ, _FINAL))
    # Before the fix no child was ever launched: the case failed as ``case_invalid``.
    methods = [request["method"] for request in wire]
    assert type(checked).__name__ == "CheckCommitResult", (checked, methods)
    provenance = getattr(checked, "semantic_provenance", None)
    assert getattr(checked, "semantic_status") is SemanticStatus.SUCCEEDED, provenance
    # One launch and one thread for the whole conversation, environment access disabled.
    assert methods.count("initialize") == 1 and methods.count("thread/start") == 1
    thread = next(request["params"] for request in wire if request["method"] == "thread/start")
    assert thread["environments"] == []
    assert thread["baseInstructions"] == REVIEWER_LOOP_INSTRUCTION
    turns = [request["params"] for request in wire if request["method"] == "turn/start"]
    assert len(turns) == 2 and {turn["threadId"] for turn in turns} == {"thr-fake"}
    # The first turn carries both admitted user messages: the packet, then the read catalog.
    first_input = cast(list[dict[str, str]], turns[0]["input"])
    assert len(first_input) == 2 and "reviewer_catalog" in first_input[1]["text"]
    assert "reviewer_catalog" not in first_input[0]["text"]
    # The continuation sends only the new read result, with the reply schema every turn.
    (observation,) = cast(list[dict[str, str]], turns[1]["input"])
    assert "return a + b" in json.loads(observation["text"])["data"]["text"]
    assert all(turn["outputSchema"] for turn in turns)

    reviewer = cast(dict[str, JsonValue], mcp_wire["reviewer"])
    assert (reviewer["exchanges"], reviewer["reads_used"]) == ("2", "1")
    evidence = cast(dict[str, JsonValue], mcp_wire["semantic_provenance"])["runtime_evidence"]
    # The session's own close ended the process group after the last turn.
    assert cast(dict[str, JsonValue], evidence)["process_cleanup"] == "terminated"
    # The replayed 0.162.1 wire (``thread/settings/updated`` before the first ack, reasoning,
    # deltas, moderation metadata, usage) is admitted without any stage (#1118).
    assert "failure_stage" not in cast(dict[str, JsonValue], evidence)
    # #1172: each exchange recorded its own usage, both under the review's first request id.
    assert [(r["operation"], r["counts"]["reviewer_exchange_index"]) for r in cache_records] == [
        ("exchange_cache", 1),
        ("exchange_cache", 2),
    ]
    assert len({r["request_id"] for r in cache_records}) == 1
    assert [r["counts"]["reviewer_cache_miss"] for r in cache_records] == ["first_turn", "none"]
    assert [r["counts"]["reviewer_input_tokens"] for r in cache_records] == [2_000, 2_400]
    # The second turn reused its whole 2,000-token prefix but the last partial cache block.
    assert (
        cache_records[1]["counts"]["reviewer_prefix_tokens"],
        cache_records[1]["counts"]["reviewer_prefix_cached_tokens"],
    ) == (2_000, 1_920)


async def test_failed_final_held_session_cleanup_withholds_the_judgment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #1137: actually clean up the fake child, then simulate unconfirmed group termination.
    close = codex._cleanup  # pyright: ignore[reportPrivateUsage]
    closed: list[str] = []

    async def failed(runtime: Any) -> str:
        closed.append(await close(runtime))
        return "failed"

    monkeypatch.setattr(codex, "_cleanup", failed)
    checked, wire, mcp_wire = await _review(tmp_path, monkeypatch, _encoded(_READ, _FINAL))
    assert closed and all(result in {"terminated", "killed"} for result in closed)
    assert getattr(checked, "semantic_status") is SemanticStatus.UNAVAILABLE
    assert getattr(checked, "semantic_reason") is SemanticReason.OUTCOME_UNKNOWN
    provenance = cast(dict[str, JsonValue], mcp_wire["semantic_provenance"])
    assert provenance["failure_class"] == "transport"
    evidence = cast(dict[str, JsonValue], provenance["runtime_evidence"])
    assert (evidence["process_cleanup"], evidence["failure_stage"]) == (
        "failed",
        "cleanup_unconfirmed",
    )
    reviewer = cast(dict[str, JsonValue], mcp_wire["reviewer"])
    assert reviewer["ended"] == "cleanup_unconfirmed" and reviewer["cleanup"] == "failed"
    assert [m["method"] for m in wire].count("thread/start") == 1
    assert [m["method"] for m in wire].count("turn/start") == 2
    assert mcp_wire.get("review_summary") is None


_MALFORMED = "not json"
_REJECTED = '{"reply":{"action":"not_an_action","args":{}}}'


@pytest.mark.parametrize(
    ("answers", "repair_turn"),
    [
        pytest.param(["", *_encoded(_FINAL)], 1, id="empty-opening"),
        pytest.param([*_encoded(_READ), "", *_encoded(_FINAL)], 2, id="read-empty"),
        pytest.param([*_encoded(_READ), _MALFORMED, *_encoded(_FINAL)], 2, id="read-malformed"),
        pytest.param([*_encoded(_READ), _REJECTED, *_encoded(_FINAL)], 2, id="read-rejected"),
        pytest.param([_MALFORMED, *_encoded(_READ, _FINAL)], 1, id="malformed-then-read"),
    ],
)
async def test_every_repair_continues_on_the_held_codex_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answers: list[str], repair_turn: int
) -> None:
    """#1118 V1: an empty, malformed or rejected answer is repaired on the same thread.

    Before the fix an empty answer raised before its ``turn/completed``, so the runtime was not
    retained: on the opening the repair reopened a second thread and resent the packet, and after
    a read the repair history was refused as ``case_invalid``. Every shape now runs one launch,
    one thread, the opening's two inputs once, and exactly one new input on every later turn.
    """

    checked, wire, _ = await _review(tmp_path, monkeypatch, answers)
    methods = [request["method"] for request in wire]
    provenance = getattr(checked, "semantic_provenance", None)
    assert getattr(checked, "semantic_status") is SemanticStatus.SUCCEEDED, (provenance, methods)
    assert methods.count("initialize") == 1 and methods.count("thread/start") == 1
    turns = [request["params"] for request in wire if request["method"] == "turn/start"]
    assert len(turns) == len(answers) and {turn["threadId"] for turn in turns} == {"thr-fake"}
    assert len(cast(list[object], turns[0]["input"])) == 2
    assert all(len(cast(list[object], turn["input"])) == 1 for turn in turns[1:])
    # The turn after the bad answer carries only the loop's repair notice.
    (repair,) = cast(list[dict[str, str]], turns[repair_turn]["input"])
    assert repair["text"].startswith("format_error")


@pytest.mark.parametrize(
    "answers",
    [
        pytest.param(_encoded(_READ, _READ, _READ, _FINAL), id="cap-then-judgment"),
        pytest.param(_encoded(_READ, _READ, _READ, _READ, _FINAL), id="final-phase-read-repaired"),
    ],
)
async def test_the_final_phase_continues_on_the_held_codex_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answers: list[str]
) -> None:
    """#1173: after the third read the final-phase notice follows that read's result, two new
    user messages on the held thread. Before the fix the Codex guard accepted exactly one, so
    every review that reached the read cap ended unavailable with no judgment."""

    checked, wire, mcp_wire = await _review(tmp_path, monkeypatch, answers)
    methods = [request["method"] for request in wire]
    provenance = getattr(checked, "semantic_provenance", None)
    assert getattr(checked, "semantic_status") is SemanticStatus.SUCCEEDED, (provenance, methods)
    assert methods.count("initialize") == 1 and methods.count("thread/start") == 1
    turns = [request["params"] for request in wire if request["method"] == "turn/start"]
    assert len(turns) == len(answers) and {turn["threadId"] for turn in turns} == {"thr-fake"}
    inputs = [[item["text"] for item in cast(list[dict[str, str]], t["input"])] for t in turns]
    assert [len(texts) for texts in inputs[1:4]] == [1, 1, 2] and inputs[3][1] == FINAL_PHASE
    assert json.loads(inputs[3][0])["call_index"] == 3
    if len(turns) == 5:  # the late read executes nothing; its one repair asks for the judgment
        (repair,) = inputs[4]
        assert repair.startswith("format_error: read_in_final_phase.")
    reviewer = cast(dict[str, JsonValue], mcp_wire["reviewer"])
    assert (reviewer["exchanges"], reviewer["reads_used"]) == (str(len(answers)), "3")


@pytest.mark.parametrize(
    "answers",
    [
        pytest.param(_encoded(_READ, _READ, _READ, _READ, _FINAL), id="always-reads"),
        pytest.param([_MALFORMED, *_encoded(_READ, _READ, _READ, _FINAL)], id="malformed"),
    ],
)
async def test_codex_gets_the_read_free_schema_once_the_repair_is_spent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answers: list[str]
) -> None:
    """#1173 round 2: Codex enforces ``outputSchema``. The read-offering turns keep one schema
    (cache hits); once the review's one repair is spent, the final turn sends the read-free
    schema, so the model can only return the judgment there."""

    checked, wire, _mcp = await _review(tmp_path, monkeypatch, answers)
    assert getattr(checked, "semantic_status") is SemanticStatus.SUCCEEDED
    turns = [request["params"] for request in wire if request["method"] == "turn/start"]
    schemas = [json.dumps(turn["outputSchema"], sort_keys=True) for turn in turns]
    assert len(turns) == 5 and len(set(schemas[:4])) == 1 and schemas[4] != schemas[0]
    branches = [
        len(cast(dict[str, Any], turn["outputSchema"])["properties"]["reply"]["anyOf"])
        for turn in turns
    ]
    assert branches == [4, 4, 4, 4, 1]  # three read actions and the judgment, then only it
