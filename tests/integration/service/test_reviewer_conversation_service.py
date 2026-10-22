"""#1118: one full review through the ready service, with only the provider scripted.

The real service composition admits the check, runs the reviewer conversation through the real
privacy coordinator, catalog audit, outbound gateway and Responses request renderer, and commits
the check. Only ``build_evaluator`` is replaced: the scripted provider reads each exchange as the
route adapter would and answers with the next structured reply (three reads, then the final
judgment). The check result, its CLI text, its MCP text and the receipt then show what was read.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import finishup.service.ready_composition as ready_composition
from builders.multi_agent import INSTALLATION_ID, multi_agent_service
from builders.privacy_policies import minimal_external_policy
from builders.privacy_widenings import with_llm
from builders.projection_workflow import ProjectionCase, project_case
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.providers.openai_responses_factory import OpenAIResponsesExternalFactory
from finishup.adapters.providers.reviewer_reply import REVIEWER_REPLY_SCHEMAS
from finishup.adapters.repository_identity import resolve_repository_privacy_context
from finishup.application.egress import PrivacyCoordinator
from finishup.application.privacy_policy import (
    DecidePrivacyPolicyRequest,
    PolicyDecisionRequired,
    ProposePrivacyPolicyRequest,
    decide_privacy_policy,
    privacy_propose_policy,
)
from finishup.application.reviewer_loop import FINAL_PHASE
from finishup.application.service import ClientProjectionContext, ProjectionRenderMode
from finishup.cli.render import render_human_check
from finishup.config.models import FinishUpConfig
from finishup.config.write import fireworks_provider
from finishup.domain.findings import SamplingParams
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ConsentSource,
    EgressChannel,
    HumanPrivacyDecision,
    PrivacyPolicy,
    ProviderBinding,
)
from finishup.domain.receipts import receipt_document_from_json, render_receipt_human
from finishup.domain.reviewer_reads import reviewer_record_from_wire
from finishup.kernel.receipt_builder import REVIEWER_ADVISORY_LABEL
from finishup.mcp.summaries import render_check_reviewer_output
from finishup.ports.control import ControlClientKind, ControlMethod, WorkspaceLocator
from finishup.ports.keys import MacKeyPurpose
from finishup.ports.privacy import (
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    HumanPolicyDecision,
)
from finishup.ports.secret_memory import HumanAuthorizationProof, SecretPurpose
from finishup.ports.semantic import (
    ProviderAttemptProvenance,
    SemanticResultReply,
    reviewer_exchange,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    CheckRequest,
    CheckResultModel,
    CheckSuccessModel,
    DataCategory,
    PublishWorkRequest,
    ReceiptRequest,
    SemanticStatus,
    StartRequest,
)
from finishup.service.vault import provider_credential_profile_binding

pytestmark = pytest.mark.anyio

_ROOMY = with_llm(minimal_external_policy(), max_tokens=65_536)
_STATEMENT = "Make add(a, b) in calc.py return the sum of a and b, and keep test_calc.py passing."


@pytest.fixture(autouse=True)
def work_has_begun(monkeypatch: pytest.MonkeyPatch) -> None:
    """The review runs as if the first edit were recorded (no pre-edit deferral)."""

    import finishup.application.check as check_module

    def edited(*_args: object) -> bool:
        return True

    monkeypatch.setattr(check_module, "material_edit_recorded", edited)


def _read_file(path: str) -> dict[str, JsonValue]:
    args: dict[str, JsonValue] = {
        "root_id": "w1",
        "path": path,
        "mode": "text",
        "start_line": 1,
        "line_count": 40,
    }
    return {"reply": {"action": "read_file", "args": args}}


_REPLIES: tuple[dict[str, JsonValue], ...] = (
    _read_file("calc.py"),
    _read_file("test_calc.py"),
    {
        "reply": {
            "action": "read_file",
            "args": {"root_id": "w1", "path": ".", "mode": "list", "cursor": None},
        }
    },
    {
        "reply": {
            "final_judgment": {
                "conclusion": "no_material_discrepancy",
                "review_summary": (
                    "Read calc.py and test_calc.py: add returns a + b and the test asserts "
                    "add(2, 3) == 5."
                ),
                "verified": [],
                "reviewer_challenges": [],
                "prior_finding_verdicts": [],
            }
        }
    },
)


@dataclass
class _Review:
    """One prepared review in a running ready service; ``check`` runs the reviewed check."""

    service: Any
    started: Any
    repository: Any
    common: dict[str, JsonValue]
    check_body: dict[str, JsonValue]
    exchanges: list[tuple[str, tuple[tuple[str, str], ...]]]
    payloads: list[bytes]
    # The task-scope policy the harness serves; a test may narrow it mid-review.
    task_policy: list[EffectivePrivacyPolicy]

    async def check(self) -> Any:
        return await self.service.app.check(
            CheckRequest.model_validate(self.check_body),
            repository_privacy_context=self.repository,
        )


@asynccontextmanager
async def _reviewing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replies: tuple[dict[str, JsonValue], ...] = _REPLIES,
    *,
    policy: PrivacyPolicy = _ROOMY,
    timeout_seconds: int = 60,
) -> AsyncGenerator[_Review]:
    """A ready service, a git workspace, a task with its statement and a connected provider."""

    workspace = (tmp_path / "work").resolve()
    workspace.mkdir()
    (workspace / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (workspace / "test_calc.py").write_text(
        "from calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n"
    )
    for argv in (
        ("init", "-q", "-b", "main"),
        ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "."),
        ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "base"),
    ):
        subprocess.run(("git", *argv), cwd=workspace, check=True, capture_output=True)
    provider = fireworks_provider(
        model="accounts/fireworks/models/minimax-m3", timeout_seconds=timeout_seconds
    )
    exchanges: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    payloads: list[bytes] = []
    queued = list(replies)

    def build_evaluator(
        _factory: OpenAIResponsesExternalFactory,
        binding: ProviderBinding,
        _credential: object,
        _request_commitment: object,
    ) -> object:
        async def evaluate(case: object, _deadline: object) -> SemanticResultReply:
            media_type, payload = getattr(case, "media_type"), getattr(case, "payload")
            exchange = reviewer_exchange(media_type, payload, REVIEWER_REPLY_SCHEMAS)
            assert exchange is not None, "every review dispatch is a reviewer exchange"
            exchanges.append((media_type, exchange.history))
            payloads.append(payload)
            provenance = ProviderAttemptProvenance(
                provider=binding.provider_id,
                endpoint_profile_id=binding.endpoint_profile_id,
                endpoint_profile_version=binding.endpoint_profile_version,
                model=binding.model_id,
                sdk_version="scripted-1.0.0",
                prompt_digest=exchange.prompt_digest,
                schema_digest=exchange.schema_digest,
                policy_digest=minimal_external_policy().policy_digest,
                privacy_policy_digest=minimal_external_policy().policy_digest,
                sampling_params=SamplingParams(128),
                latency_ms=1,
                status=SemanticStatus.SUCCEEDED,
                provider_request_id=f"scripted-{len(exchanges)}",
                request_commitment="hmac-sha256:" + "7" * 64,
            )
            return SemanticResultReply(queued.pop(0), provenance)

        return SimpleNamespace(evaluate=evaluate)

    monkeypatch.setattr(OpenAIResponsesExternalFactory, "build_evaluator", build_evaluator)
    config = FinishUpConfig(profile="local-openai", provider=provider)
    async with multi_agent_service(tmp_path / "state", config=config) as service:
        policy_store = service.app.privacy.policy_application.policy_store  # type: ignore[union-attr]
        original_effective_policy = policy_store.effective_policy
        # A ceiling with room for the packet and three reads: the minimal profile's 4,096 tokens
        # leave this conversation room for one read, and the reviewer is then offered none.
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
        LocalObservationStore(_state=service.root / "state").grant_consent(
            LocalObservationStore(_state=service.root / "state").workspace_commitment(
                str(workspace)
            )
        )
        common: dict[str, JsonValue] = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "actor": {"actor_id": "harness:reviewer-dogfood", "actor_type": "harness"},
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
                    "task_title": "Reviewer conversation dogfood",
                    "workspace_ref": str(workspace),
                    "external_ref": "reviewer-dogfood",
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
        review = _Review(
            service, started, repository, common, check_body, exchanges, payloads, task_policy
        )
        # Without a statement the check waits for one; the same request then resumes the review.
        first = await review.check()
        assert getattr(first, "state") == "awaiting_input"
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
                                "summary": "Fix add and keep its test passing.",
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
        await _widen_and_connect(service, INSTALLATION_ID, repository.commitment, provider, policy)
        # From here the task sees exactly the repository policy the owner just approved, as the
        # service does: reads, exchanges and a resumed approval all name the one policy.
        authority = await policy_store.repository_authority(task_scopes[-1])
        task_policy.append(authority.effective)
        yield review


def _narrow(effective: EffectivePrivacyPolicy, category: DataCategory) -> EffectivePrivacyPolicy:
    """``effective`` with ``category`` removed from the reviewer channel, as a new generation."""

    channels = tuple(
        replace(c, allowed_categories=tuple(x for x in c.allowed_categories if x is not category))
        if c.channel is EgressChannel.LLM_INFERENCE
        else c
        for c in effective.policy.channel_policies
    )
    narrowed = replace(
        effective.policy,
        channel_policies=channels,
        version=effective.policy.version + 1,
        policy_digest="sha256:" + "7" * 64,
    )
    return EffectivePrivacyPolicy(narrowed, effective.generation + 1, narrowed.policy_digest)


async def test_one_review_reads_three_times_then_concludes_on_every_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _reviewing(tmp_path, monkeypatch) as review:
        service, started, common = review.service, review.started, review.common
        check_body, exchanges, repository = review.check_body, review.exchanges, review.repository
        checked = await review.check()
        assert type(checked).__name__ == "CheckCommitResult", checked
        assert getattr(checked, "semantic_status") is SemanticStatus.SUCCEEDED

        # Four exchanges, each admitted on its own; the packet and read catalog lead every one.
        # The last ends with the final-phase notice after the third result (#1173).
        assert [len(history) for _, history in exchanges] == [3, 5, 7, 10]
        last = exchanges[-1][1]
        assert last[-1] == ("user", FINAL_PHASE)
        assert "reviewer_catalog" in last[2][1]
        first_read, second_read, listing = (json.loads(last[i][1]) for i in (4, 6, 8))
        assert first_read["status"] == "ok" and "return a + b" in first_read["data"]["text"]
        assert "assert add(2, 3) == 5" in second_read["data"]["text"]
        listed = {entry["name"] for entry in listing["data"]["entries"]}
        assert {"calc.py", "test_calc.py"} <= listed and ".git" not in listed

        mcp_wire = await project_case(
            service.app, ProjectionCase("check", ControlMethod.CHECK, check_body, checked), 7100
        )
        cli_wire = await project_case(
            service.app,
            ProjectionCase("check", ControlMethod.CHECK, check_body, checked),
            7110,
            context=ClientProjectionContext(
                ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, False
            ),
        )
        reviewer = cast(Mapping[str, JsonValue], mcp_wire["reviewer"])
        assert (reviewer["exchanges"], reviewer["reads_used"], reviewer["ended"]) == (
            "4",
            "3",
            None,
        )
        cli_model = CheckResultModel.model_validate(cli_wire).root
        assert isinstance(cli_model, CheckSuccessModel)
        cli_text = render_human_check(cli_model)
        mcp_text = render_check_reviewer_output(mcp_wire)
        for text in (cli_text, mcp_text):
            assert "Reviewer reads: 3 of 3" in text
            assert "read_file: ok [w1 src_" in text
            assert "calc.py" not in text.split("Reviewer summary")[0]
        # The default agent-context policy withholds reviewer prose from this view; the CLI says
        # so instead of dropping the line. The structural read record is never withheld.
        assert "Reviewer summary (advisory): " in cli_text

        receipt = await service.app.receipt(
            ReceiptRequest.model_validate(
                {
                    **common,
                    "request_id": new_id(IdKind.REQUEST),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": dict(
                        getattr(checked, "result_frontier").as_wire().items()
                    ),
                    "task_id": started.task_id,
                    "format": "json",
                    "redaction_profile": "full_local",
                    "include": "full",
                }
            ),
            repository_privacy_context=repository,
        )
        document = receipt_document_from_json(getattr(receipt, "document"))
        text = render_receipt_human(document, markdown=False)
        markdown = render_receipt_human(document, markdown=True)
        for rendered in (text, markdown, canonical_encode(getattr(receipt, "document")).decode()):
            assert "Reviewer reads: 3 of 3" in rendered
            # The structural read record names no path; the owner's full_local receipt carries
            # the reviewer's own summary as one fenced advisory item.
            reads_line = next(line for line in rendered.split(". ") if "Reviewer reads" in line)
            assert "calc.py" not in reads_line
            assert REVIEWER_ADVISORY_LABEL + "Read calc.py and test_calc.py" in rendered
        # The agent's view of the same owner receipt goes through the result-boundary privacy
        # projection: under this policy reviewer prose is withheld there, and says so.
        markdown_body: dict[str, JsonValue] = {
            **common,
            "request_id": new_id(IdKind.REQUEST),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": dict(getattr(checked, "result_frontier").as_wire().items()),
            "task_id": started.task_id,
            "format": "markdown",
            "redaction_profile": "full_local",
            "include": "full",
        }
        owner_markdown = await service.app.receipt(
            ReceiptRequest.model_validate(markdown_body), repository_privacy_context=repository
        )
        assert REVIEWER_ADVISORY_LABEL in getattr(owner_markdown, "human_text")
        agent_view = await project_case(
            service.app,
            ProjectionCase("receipt", ControlMethod.RECEIPT, markdown_body, owner_markdown),
            7120,
        )
        assert agent_view["human_text"] == {
            "omitted": True,
            "category": "finding_summary",
            "reason": agent_view["human_text"]["reason"],  # type: ignore[index]
        }
        assert "/human_text" in agent_view["privacy_projection"]["omitted_pointers"]  # type: ignore[index]
        print("\n--- CLI text ---\n" + cli_text)
        print("\n--- MCP reviewer text ---\n" + mcp_text)
        print("\n--- receipt text (version and policy identity) ---")
        print("\n".join(line for line in text.splitlines() if "Reviewer reads" in line))


async def _widen_and_connect(
    service: object,
    installation_id: str,
    commitment: str,
    provider: object,
    policy: PrivacyPolicy = _ROOMY,
) -> None:
    """The owner's trusted steps: widen this repository's policy and store a provider key."""

    app = getattr(service, "app")
    clock = getattr(service, "clock")
    vault = getattr(service, "vault")
    policy_app = app.privacy.policy_application
    repository_scope = AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE, installation_id, commitment
    )
    authority = await policy_app.policy_store.repository_authority(repository_scope)
    candidate = replace(policy, effective_scope=repository_scope, created_at=clock.now_utc())
    proposed = await privacy_propose_policy(
        policy_app,
        ProposePrivacyPolicyRequest(
            authority.effective.effective_digest,
            candidate,
            authority.authority_digest,
            repository_scope,
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
    binding = provider_credential_profile_binding(
        getattr(provider, "provider_id"),
        getattr(provider, "model"),
        getattr(provider, "endpoint_profile_id"),
        getattr(provider, "endpoint_profile_version"),
    )
    credential = getattr(service, "memory").capture(
        SecretPurpose.PROVIDER_CREDENTIAL, bytearray(b"reviewer-dogfood-provider-token")
    )
    await vault.store_provider_credential(
        "set",
        binding,
        credential,
        HumanAuthorizationProof(
            "reviewer-dogfood-provider-credential",
            "provider_credential_set",
            binding.target_digest("set"),
            1,
            vault.generation,
            None,
            1.0,
            60.0,
        ),
        2.0,
    )


_FINAL_REPLY = _REPLIES[-1]
# Ask-every-time: every reviewer exchange waits for the owner's decision on its exact bytes.
_ASK = replace(
    _ROOMY,
    channel_policies=tuple(
        replace(c, preview_required=True) if c.channel is EgressChannel.LLM_INFERENCE else c
        for c in _ROOMY.channel_policies
    ),
)


async def _tighten_repository(review: _Review, category: DataCategory) -> None:
    """The owner's own tightening of this repository's grant: ``category`` no longer leaves."""

    policy_app = review.service.app.privacy.policy_application
    scope = AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE, INSTALLATION_ID, review.repository.commitment
    )
    authority = await policy_app.policy_store.repository_authority(scope)
    current = authority.effective
    tightened = await privacy_propose_policy(
        policy_app,
        ProposePrivacyPolicyRequest(
            current.effective_digest,
            replace(
                _narrow(current, category).policy,
                effective_scope=scope,
                created_at=review.service.clock.now_utc(),
            ),
            authority.authority_digest,
            scope,
        ),
    )
    assert not isinstance(tightened, PolicyDecisionRequired), "a tightening needs no decision"
    after = await policy_app.policy_store.repository_authority(scope)
    assert after.effective.generation > current.generation


async def test_a_tightened_repository_category_ends_the_review_before_a_read_is_resent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R1: the gateway never resends a read whose category the owner has since withdrawn."""

    replies = (_read_file("calc.py"), _read_file("test_calc.py"), _FINAL_REPLY)
    async with _reviewing(tmp_path, monkeypatch, replies) as review:
        admit = PrivacyCoordinator.admit_reviewer_read
        tightened: list[int] = []

        async def admit_then_tighten(self: PrivacyCoordinator, *args: Any, **kwargs: Any) -> object:
            reason = await admit(self, *args, **kwargs)
            if reason is None and not tightened:
                # The read result is admitted; before the next exchange the owner tightens the
                # real repository policy (a new generation the gateway's registry follows).
                await _tighten_repository(review, DataCategory.REPOSITORY_EXCERPT)
                tightened.append(len(review.payloads))
            return reason

        monkeypatch.setattr(PrivacyCoordinator, "admit_reviewer_read", admit_then_tighten)
        checked = await review.check()
    assert tightened == [1]
    # Only the first exchange left: the read result of calc.py was never sent.
    assert len(review.payloads) == 1
    assert getattr(checked, "semantic_status") is SemanticStatus.BLOCKED_BY_POLICY
    record = reviewer_record_from_wire(getattr(checked, "reviewer", None))
    assert record is not None and record.ended == "reviewer_exchange_not_sent"
    assert record.exchanges == 2 and record.reads[0].disclosure is None


async def test_a_narrowed_task_policy_ends_the_conversation_before_its_next_turn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R1: a retained read's category, rechecked before each turn, ends the review honestly."""

    replies = (_read_file("calc.py"), _FINAL_REPLY)
    async with _reviewing(tmp_path, monkeypatch, replies) as review:
        admit = PrivacyCoordinator.admit_reviewer_read

        async def admit_then_narrow(self: PrivacyCoordinator, *args: Any, **kwargs: Any) -> object:
            reason = await admit(self, *args, **kwargs)
            if reason is None:
                review.task_policy.append(
                    _narrow(review.task_policy[-1], DataCategory.REPOSITORY_EXCERPT)
                )
            return reason

        monkeypatch.setattr(PrivacyCoordinator, "admit_reviewer_read", admit_then_narrow)
        checked = await review.check()
    assert len(review.payloads) == 1  # the read result was never sent
    assert getattr(checked, "semantic_status") is SemanticStatus.BLOCKED_BY_POLICY
    record = reviewer_record_from_wire(getattr(checked, "reviewer", None))
    assert record is not None and record.ended == "authorization_changed"
    assert record.exchanges == 1 and record.reads[0].disclosure is None


def _capture_evaluations(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    """Every run of the service's admitted-job evaluator, so a test can re-enter one."""

    runs: list[tuple[Any, ...]] = []
    factory = ready_composition._privacy_gated_semantic_evaluator  # pyright: ignore[reportPrivateUsage]

    def tracking(*args: Any, **kwargs: Any) -> Any:
        evaluate = factory(*args, **kwargs)

        async def run(*call: Any, **named: Any) -> Any:
            result = await evaluate(*call, **named)
            runs.append((evaluate, call, named, result))
            return result

        return run

    monkeypatch.setattr(ready_composition, "_privacy_gated_semantic_evaluator", tracking)
    return runs


async def _reenter(runs: list[tuple[Any, ...]]) -> Any:
    """Re-enter the waiting job's evaluator under the lease its wait renewed.

    A same-request ``check`` cannot do this yet: the waiting operation's lease is bounded by the
    job's own deadline, so the public replay is ``operation_pending`` until that deadline passes.
    """

    evaluate, call, named, waiting = runs[-1]
    frozen = replace(call[0], lease=waiting.operation_lease)
    result = await evaluate(frozen, *call[1:], **named)
    runs.append((evaluate, (frozen, *call[1:]), named, result))
    return result


async def _owner_decides(review: _Review, *, approved: bool | None) -> Any:
    """Run the check to its disclosure wait and record the owner's decision on that proposal."""

    waiting = await review.check()
    assert type(waiting).__name__ == "CheckAwaitingHuman", waiting
    continuation = getattr(waiting, "continuation")
    assert continuation.kind == "privacy_disclosure_decision"
    assert review.payloads == []  # nothing is sent before the owner decides
    audit = review.service.app.privacy._audit  # pyright: ignore[reportPrivateUsage]
    proposal = await audit.load_disclosure_proposal(continuation.pending_id)
    assert proposal is not None, "the exact prepared conversation the owner is shown"
    if approved is not None:
        await audit.record_human_decision(
            proposal.privacy_proposal_id,
            HumanPrivacyDecision(
                proposal.proposal_commitment,
                approved,
                ConsentSource.PER_REQUEST_LOCAL_HUMAN,
                review.service.clock.now_utc(),
                proposal.expires_at if approved else None,
                proposal.prepared_case_digest,
                "hmac-sha256:" + "9" * 64,
            ),
        )
    return proposal


async def test_an_approved_first_exchange_resumes_once_and_concludes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2: ask-every-time; the owner approves the exact first exchange; it is sent once."""

    runs = _capture_evaluations(monkeypatch)
    async with _reviewing(tmp_path, monkeypatch, (_FINAL_REPLY,), policy=_ASK) as review:
        # Re-entered before any decision, the job still waits on the same proposal: nothing is
        # sent and no replacement proposal is minted.
        proposal = await _owner_decides(review, approved=None)
        still = await _reenter(runs)
        assert still.status is SemanticStatus.AWAITING_HUMAN
        assert still.continuation.pending_id == proposal.privacy_proposal_id
        assert review.payloads == []
        await _owner_decides_on(review, proposal, approved=True)
        resumed = await _reenter(runs)
        assert resumed.status is SemanticStatus.SUCCEEDED, (resumed.status, resumed.reason)
        # Exactly the approved bytes, once, under the reviewer's final-only media type and with
        # no reads offered: each further exchange would need its own approval.
        assert review.payloads == [proposal.prepared_bytes]
        assert [media for media, _ in review.exchanges] == [
            "application/vnd.finishup.reviewer-final+json"
        ]
        assert '"reads_allowed":0' in review.exchanges[0][1][2][1]
        assert resumed.reviewer is not None
        assert (resumed.reviewer.exchanges, resumed.reviewer.reads) == (1, ())
        assert resumed.reviewer.ended is None
        # The same job entered again recovers its durable result: nothing more is sent.
        await _reenter(runs)
        assert len(review.payloads) == 1


async def test_an_approved_first_exchange_that_asks_for_a_read_ends_without_another_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1173: the wire schema offers reads even when the review offers none, but ask-every-time
    must not turn a read into a repair: that would be a second exchange needing its own
    approval, which nothing resumes. The read ends the review on the one approved exchange."""

    runs = _capture_evaluations(monkeypatch)
    replies = (_read_file("calc.py"), _FINAL_REPLY)
    async with _reviewing(tmp_path, monkeypatch, replies, policy=_ASK) as review:
        proposal = await _owner_decides(review, approved=True)
        resumed = await _reenter(runs)
        assert resumed.status is SemanticStatus.INVALID, (resumed.status, resumed.reason)
        assert review.payloads == [proposal.prepared_bytes]  # nothing sent but the approved bytes
        assert resumed.reviewer is not None
        assert (resumed.reviewer.exchanges, resumed.reviewer.reads) == (1, ())
        assert resumed.reviewer.ended == "read_limit"


async def _owner_decides_on(review: _Review, proposal: Any, *, approved: bool) -> None:
    audit = review.service.app.privacy._audit  # pyright: ignore[reportPrivateUsage]
    await audit.record_human_decision(
        proposal.privacy_proposal_id,
        HumanPrivacyDecision(
            proposal.proposal_commitment,
            approved,
            ConsentSource.PER_REQUEST_LOCAL_HUMAN,
            review.service.clock.now_utc(),
            proposal.expires_at if approved else None,
            proposal.prepared_case_digest,
            "hmac-sha256:" + "9" * 64,
        ),
    )


async def test_a_denied_first_exchange_sends_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs = _capture_evaluations(monkeypatch)
    async with _reviewing(tmp_path, monkeypatch, (_FINAL_REPLY,), policy=_ASK) as review:
        await _owner_decides(review, approved=False)
        denied = await _reenter(runs)
        assert denied.status is SemanticStatus.HUMAN_DENIED, (denied.status, denied.reason)
        assert review.payloads == []


async def test_an_expired_approval_sends_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs = _capture_evaluations(monkeypatch)
    # The proposal expires after 60 s; the job's own deadline is longer.
    ask = replace(
        _ASK,
        channel_policies=tuple(
            replace(c, authorization_ttl_seconds=60)
            if c.channel is EgressChannel.LLM_INFERENCE
            else c
            for c in _ASK.channel_policies
        ),
    )
    async with _reviewing(
        tmp_path, monkeypatch, (_FINAL_REPLY,), policy=ask, timeout_seconds=300
    ) as review:
        proposal = await _owner_decides(review, approved=None)
        review.service.clock.advance(seconds=61)
        assert review.service.clock.now_utc() > proposal.expires_at
        expired = await _reenter(runs)
        assert expired.status is SemanticStatus.APPROVAL_EXPIRED, (expired.status, expired.reason)
        assert review.payloads == []
