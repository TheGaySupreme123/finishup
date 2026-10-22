"""#1118: an admitted semantic review job runs the reviewer conversation through the service.

The real ``_privacy_gated_semantic_evaluator`` drives the real privacy coordinator (classifier,
minimizer, scan, disclosure audit, consume authority) over a durable SQLite job. Only the provider
behind the gateway is scripted: it decodes each exchange exactly as a route adapter does and
answers with the next scripted structured reply. No model, network or credential is used.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import finishup.service.ready_composition as ready_composition_module
from builders.ledger_adapters import FixedClock, append_command, sqlite_adapter
from builders.privacy_policies import minimal_external_policy
from builders.privacy_widenings import with_llm
from finishup.adapters.memory.privacy import MemoryPrivacyAudit, MemoryPrivacyCatalogState
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.adapters.providers.reviewer_reply import REVIEWER_REPLY_SCHEMAS
from finishup.application.check import FinalSemanticEvaluation
from finishup.application.egress import PrivacyCoordinator
from finishup.domain.findings import SamplingParams
from finishup.domain.privacy import (
    ApprovedOutboundCase,
    ConsentSource,
    EgressAuthorization,
    EgressChannel,
    PrivacyPolicy,
    ProviderBinding,
)
from finishup.domain.reviewer_reads import render_reviewer_lines
from finishup.ports.privacy import (
    DisclosureProposalRequest,
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    PreparedDisclosureReservation,
)
from finishup.ports.runtime import TaskRuntime
from finishup.ports.semantic import (
    Deadline,
    ProviderAttemptProvenance,
    SemanticResultReply,
    reviewer_exchange,
)
from finishup.ports.start_catalog import StartCatalogPort
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import SemanticStatus
from integration.service import test_semantic_non_dispatch as non_dispatch

_BINDING = next(
    c.provider_binding for c in minimal_external_policy().channel_policies if c.provider_binding
)
_FINAL: dict[str, JsonValue] = {
    "reply": {
        "final_judgment": {
            "conclusion": "no_material_discrepancy",
            "review_summary": "Read the source and the recorded claim; nothing contradicts them.",
            "verified": [],
            "reviewer_challenges": [],
            "prior_finding_verdicts": [],
        }
    }
}


# The full five-attempt path needs channel room for its whole history and instruction; tests
# of it pass this policy. The fixture default stays the minimal policy (4,096 tokens).
_ROOMY = with_llm(minimal_external_policy(), max_tokens=16_384)


def _read_file(path: str) -> dict[str, JsonValue]:
    args: dict[str, JsonValue] = {
        "root_id": "w1",
        "path": path,
        "mode": "text",
        "start_line": 1,
        "line_count": 20,
    }
    return {"reply": {"action": "read_file", "args": args}}


class _Key:
    def mac(self, domain: bytes, message: bytes) -> str:
        import hashlib
        import hmac

        return "hmac-sha256:" + hmac.new(b"k" * 32, domain + message, hashlib.sha256).hexdigest()


class _Audit(MemoryPrivacyAudit):
    """The memory disclosure audit, plus the network authority the catalog audit mints."""

    __slots__ = ("requests",)

    def __init__(self, *args: object) -> None:
        super().__init__(*args)  # pyright: ignore[reportArgumentType]
        self.requests: dict[str, DisclosureProposalRequest] = {}

    async def prepare_disclosure_proposal(
        self, request: DisclosureProposalRequest
    ) -> PreparedDisclosureReservation:
        self.requests[request.privacy_proposal_id] = request
        return await super().prepare_disclosure_proposal(request)

    async def load(self, request_id: str, subject_digest: str) -> Any:  # noqa: ANN401
        # The receipt the real gateway's consume writes for each sent exchange.
        del subject_digest
        if not any(r.request_id == request_id for r in self.requests.values()):
            return None
        return SimpleNamespace(receipt_id="egr_" + request_id.removeprefix("req_"))

    async def authorize(
        self, reservation_id: str, approved_case_digest: str, now: datetime
    ) -> EgressAuthorization:
        request = self.requests[reservation_id]
        assert request.provider_binding is not None
        return EgressAuthorization(
            new_id(IdKind.EGRESS_AUTHORIZATION),
            reservation_id,
            approved_case_digest,
            EgressChannel.LLM_INFERENCE,
            request.provider_binding,
            request.purpose,
            request.scope,
            request.policy_version,
            request.policy_digest,
            request.max_bytes,
            request.max_tokens,
            ConsentSource.BASELINE_POLICY,
            now,
            now + timedelta(seconds=60),
            1,
        )


class _ScriptedGateway:
    """The provider behind the real gateway contract: one scripted reply per exchange."""

    def __init__(self, *replies: dict[str, JsonValue] | Callable[..., object]) -> None:
        # A reply, or a callable of (case, provenance) that returns the provider's result.
        self.replies = list(replies)
        self.exchanges: list[tuple[str, tuple[tuple[str, str], ...]]] = []
        self.bindings: list[ProviderBinding] = []

    async def reconcile_repository_policy(self, *args: object, **kwargs: object) -> None:
        return None

    async def dispatch_external_semantic(
        self, case: ApprovedOutboundCase, authorization: EgressAuthorization, deadline: Deadline
    ) -> object:
        del authorization, deadline
        exchange = reviewer_exchange(case.media_type, case.payload, REVIEWER_REPLY_SCHEMAS)
        assert exchange is not None, "every review dispatch is a reviewer exchange"
        self.exchanges.append((case.media_type, exchange.history))
        binding = case.provider_binding
        self.bindings.append(binding)
        provenance = ProviderAttemptProvenance(
            provider=binding.provider_id,
            endpoint_profile_id=binding.endpoint_profile_id,
            endpoint_profile_version=binding.endpoint_profile_version,
            model=binding.model_id,
            sdk_version="0.0.0",
            prompt_digest=exchange.prompt_digest,
            schema_digest=exchange.schema_digest,
            policy_digest=case.policy_digest,
            privacy_policy_digest=case.policy_digest,
            sampling_params=SamplingParams(128),
            latency_ms=1,
            status=SemanticStatus.SUCCEEDED,
            request_commitment="hmac-sha256:" + "6" * 64,
        )
        reply = self.replies.pop(0)
        if callable(reply):
            return reply(case, provenance)
        return SemanticResultReply(reply, provenance)

    async def close(self) -> None:
        return None


class _Probe:
    """Git's ignore answer for the workspace: only ``secret.txt`` is ignored."""

    def probe_requested_paths(self, workspace: str, values: tuple[str, ...]) -> tuple[object, ...]:
        del workspace
        return tuple(SimpleNamespace(ignored=value == "secret.txt") for value in values)


async def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *replies: dict[str, JsonValue] | Callable[..., object],
    policy: PrivacyPolicy | None = None,
    primary: ProviderBinding | None = _BINDING,
    **evaluator_options: object,
) -> tuple[FinalSemanticEvaluation, _ScriptedGateway, TaskRuntime]:
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    (work / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (work / "secret.txt").write_text("not for review\n")

    async def workspace_root(_runtime: object) -> str:
        return str(work.resolve())

    monkeypatch.setattr(ready_composition_module, "_workspace_root_for_runtime", workspace_root)
    command = append_command()
    adapter = sqlite_adapter(command)
    frozen, runtime = await non_dispatch._durable_semantic_case(adapter)  # pyright: ignore[reportPrivateUsage]
    policy = policy or minimal_external_policy()
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    store = non_dispatch._PolicyStore(effective, repository_granted=True)  # pyright: ignore[reportPrivateUsage]
    gateway = _ScriptedGateway(*replies)
    clock = FixedClock()
    route = non_dispatch._route_for(runtime.task_id, runtime.session_id)  # pyright: ignore[reportPrivateUsage]
    state = MemoryPrivacyCatalogState()
    state.routes[runtime.task_id] = route.route_identity_digest
    audit = _Audit(state, runtime.objects, _Key(), clock)
    human = HumanAuthorityCapability(
        "established_passphrase", "sha256:" + "9" * 64, 1, "unlocked", 1, True
    )
    coordinator = PrivacyCoordinator(
        store,  # pyright: ignore[reportArgumentType]
        LocalPrivacyEnforcer(),
        audit,  # pyright: ignore[reportArgumentType]
        gateway,  # pyright: ignore[reportArgumentType]
        clock,
        ready_composition_module.IdPort(),
        human_authority=human,
    )
    coordinator._policy_app = SimpleNamespace(policy_store=store)  # type: ignore[assignment]  # pyright: ignore

    async def resolve_provider() -> ProviderBinding | None:
        return primary

    factory = cast(
        Callable[..., Callable[..., Awaitable[FinalSemanticEvaluation]]],
        getattr(ready_composition_module, "_privacy_gated_semantic_evaluator"),
    )
    evaluator = factory(
        coordinator,
        clock,
        non_dispatch._INSTALLATION,  # pyright: ignore[reportPrivateUsage]
        resolve_provider,
        cast(
            StartCatalogPort,
            non_dispatch._Catalog(route),  # pyright: ignore[reportPrivateUsage]
        ),
        ready_composition_module.IdPort(),
        change_capture=_Probe(),
        **evaluator_options,
    )
    return await evaluator(frozen, (), runtime), gateway, runtime


@pytest.mark.anyio
async def test_a_review_job_runs_reads_then_the_final_judgment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, gateway, runtime = await _run(
        tmp_path, monkeypatch, _read_file("calc.py"), _read_file("secret.txt"), _FINAL
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    assert result.judgment is not None and result.judgment.conclusion == "no_material_discrepancy"
    # Three exchanges, each its own admission; reads only on turns, the packet sent every time.
    assert [media for media, _ in gateway.exchanges] == [
        "application/vnd.finishup.reviewer-turn+json"
    ] * 3
    first, _, last = (history for _, history in gateway.exchanges)
    assert [role for role, _ in first] == ["system", "user", "user"]
    assert json.loads(first[1][1])["schema"] and "reviewer_catalog" in first[2][1]
    assert last[:3] == first
    observation = json.loads(last[4][1])
    assert observation["status"] == "ok" and "return a + b" in observation["data"]["text"]
    denied = json.loads(last[6][1])
    assert (denied["status"], denied["reason"], denied["data"]) == (
        "denied",
        "forbidden_path",
        None,
    )
    # The service-owned record: opaque per-source identities, receipts, no path or text.
    record = result.reviewer
    assert record is not None and record.exchanges == 3 and record.ended is None
    one, two = record.reads
    assert (one.status, one.root, one.standing, one.lines) == (
        "ok",
        "w1",
        "workspace_content",
        (1, 2),
    )
    assert one.source != two.source and one.disclosure is not None
    assert two.reason == "forbidden_path"
    rendered = json.dumps(record.as_wire()) + "\n".join(render_reviewer_lines(record))
    assert "calc.py" not in rendered and "secret" not in rendered and "a + b" not in rendered
    assert dict(result.reviewer_paths or {}) == {1: "w1:calc.py", 2: "w1:secret.txt"}
    # The job's durable steps: three turns and two reads, all captured.
    job = await runtime.ledger.load_semantic_job(runtime.writer_id or "", frozen_request())
    assert job is not None
    steps = await cast(Any, runtime.ledger).review_step_usage(job.job_id)
    assert steps == (5, 0)


@pytest.mark.anyio
async def test_a_fourth_read_gets_the_final_phase_repair_before_any_read_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #1173: a review that started with reads keeps that schema on every turn (#1172), so a
    # schema-valid fourth read is the final phase's format error: the one repair asks for the
    # judgment and the review succeeds.
    reads = [_read_file("calc.py")] * 4
    result, gateway, runtime = await _run(tmp_path, monkeypatch, *reads, _FINAL, policy=_ROOMY)
    assert result.status is SemanticStatus.SUCCEEDED and result.judgment is not None
    turn = "application/vnd.finishup.reviewer-turn+json"
    assert [media for media, _ in gateway.exchanges] == [turn] * 5
    notice, repair = (history[-1][1] for _, history in gateway.exchanges[3:])
    assert notice.startswith("FinishUP: read allowance")
    assert repair.startswith("format_error: read_in_final_phase.") and "read action" not in repair
    assert result.reviewer is not None and result.reviewer.ended is None
    assert len(result.reviewer.reads) == 3 and result.reviewer.exchanges == 5
    job = await runtime.ledger.load_semantic_job(runtime.writer_id or "", frozen_request())
    assert job is not None  # five turns, three reads and the repair, every one captured
    assert await cast(Any, runtime.ledger).review_step_usage(job.job_id) == (9, 0)


@pytest.mark.anyio
async def test_a_read_after_the_final_phase_repair_ends_the_review_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    replies = [_read_file("calc.py")] * 5
    result, gateway, _runtime = await _run(tmp_path, monkeypatch, *replies, policy=_ROOMY)
    assert result.status is SemanticStatus.INVALID and result.judgment is None
    assert len(gateway.exchanges) == 5
    assert gateway.exchanges[-1][0] == "application/vnd.finishup.reviewer-turn+json"
    assert result.reviewer is not None and result.reviewer.ended == "read_limit"
    assert len(result.reviewer.reads) == 3


def frozen_request() -> str:
    return cast(str, non_dispatch._REQUEST)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("refused", "content_reads"),
    [pytest.param(0, 2, id="three-reads"), pytest.param(1, 1, id="refusal-then-two-reads")],
)
async def test_the_smallest_channel_limits_leave_room_for_fewer_content_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refused: int, content_reads: int
) -> None:
    """#1173 trade-off (ADR-006): at the minimal policy's 4,096 tokens the longer instruction and
    the final-phase notice room leave two content reads, not three; a refusal's bytes still
    count. The review still concludes: the read it can no longer afford takes the repair."""

    reads = [_read_file("calc.py")] * (3 - refused)
    replies = [*([_read_file("/absolute/calc.py")] * refused), *reads]
    result, gateway, _runtime = await _run(tmp_path, monkeypatch, *replies, _FINAL)
    assert result.status is SemanticStatus.SUCCEEDED and result.reviewer is not None
    assert result.reviewer.as_wire()["reads_used"] == str(content_reads)
    assert len(result.reviewer.reads) == refused + content_reads
    assert gateway.exchanges[-1][1][-1][1].startswith("format_error: read_in_final_phase.")
