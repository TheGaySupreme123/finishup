"""Closure readiness as a checklist through the real application (issue #913, ADR-032).

The DeepSWE v2 shapes replayed here are real Codex ledger shapes: a cooperative plan, obligation,
evidence and completion claim beside hook rows materialized by the production Codex mapping from
``PostToolUse`` envelopes. Those rows carry Codex's standing gaps (``host_outcome_unavailable``
because the host stated no outcome, ``unpaired_event`` for a post without its pre, and
``content_unselected``), and a local-only check adds ``semantic_review_not_requested``.

* Example 2 (bandit B): finished work with only standing limitations reads
  ``ready_with_limitations`` on every surface while the check verdict and the receipt conclusion
  stay ``insufficient_coverage``.
* Example 4 (kgateway B): ``work_closed`` is not a material change, so readiness does not ask for
  an identical recheck; a real material change still does.
* Open work, unanswered findings and actionable gap codes stay agent-actionable, and the
  ``semantic_review_not_requested`` route rule applies when the verification policy requires
  AI-powered review.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Literal, cast

import pytest

import integration.application.test_respond_status_receipt as workflow
import yoetz.application.status as status_module
from builders.ledger_adapters import MemoryObjects
from builders.start_application import protocol_id, start_request
from yoetz.adapters.memory.ledger import MemoryLedgerAdapter
from yoetz.application.check import CheckCommitResult
from yoetz.application.observation_materialize import (
    materialize_observation_envelope,
    observation_author,
)
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.service import Application, VerificationPolicy
from yoetz.application.start import StartInternalResult
from yoetz.application.status import StatusInternalResult
from yoetz.cli.render import render_human_status
from yoetz.domain.events import EVIDENCE_SCHEMA_VERSION, media_type_for
from yoetz.domain.observation import ObservationCursor, ObservationEnvelope, ObservationSource
from yoetz.domain.values import Frontier, JsonObject, Timestamp
from yoetz.mcp.summaries import summary_for_status
from yoetz.ports.ledger import (
    AppendCommand,
    AppendEntry,
    LedgerPort,
    OperationKind,
    ProjectionPage,
    ProjectionQuery,
)
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.models import (
    CheckRequest,
    FrontierModel,
    PublishWorkRequest,
    ReceiptRequest,
    StatusRequest,
    StatusResultModel,
    StatusSuccessModel,
)
from yoetz.protocol.readiness_text import readiness_directive

pytestmark = pytest.mark.anyio

_APPROVED = (
    "Nothing further to do. {n} standing limitation(s) and {m} acknowledged item(s) will be "
    "disclosed on the receipt. Request the receipt."
)
_CODEX_STANDING = {
    "content_unselected",
    "host_outcome_unavailable",
    "semantic_review_not_requested",
    "unpaired_event",
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Session:
    """One task driven through the public operations, tracking the current frontier."""

    def __init__(self, app: Application, runtime: object, started: StartInternalResult) -> None:
        self.app = app
        self.runtime = runtime
        self.started = started
        self.frontier: Frontier | FrontierModel = started.frontier
        self.serial = 0

    def next(self, prefix: str) -> str:
        self.serial += 1
        return protocol_id(prefix, 913_000 + self.serial)

    def draft(self, name: str, payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
        version = {
            "claim_recorded": "1.1.0",
            "evidence_recorded": EVIDENCE_SCHEMA_VERSION,
        }.get(name, "1.0.0")
        return {
            "event_id": self.next("evt_"),
            "schema": {"name": name, "version": version},
            "occurred_at": "2026-09-28T12:00:00.000Z",
            "causal_parents": [],
            "artifact_refs": [],
            "evidence_refs": [],
            "payload": payload,
        }

    async def publish(self, *drafts: dict[str, JsonValue]) -> PublishWorkInternalResult:
        result = await self.app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **workflow._request_base(self.next("req_")),  # pyright: ignore[reportPrivateUsage]
                    "session_id": self.started.session_id,
                    "writer_id": self.started.writer_id,
                    "expected_frontier": workflow._frontier(self.frontier),  # pyright: ignore[reportPrivateUsage]
                    "event_drafts": list(drafts),
                }
            )
        )
        assert type(result) is PublishWorkInternalResult
        self.frontier = result.result_frontier
        return result

    async def check(self) -> CheckCommitResult:
        result = await self.app.check(
            CheckRequest.model_validate(
                {
                    **workflow._request_base(self.next("req_")),  # pyright: ignore[reportPrivateUsage]
                    "session_id": self.started.session_id,
                    "writer_id": self.started.writer_id,
                    "expected_frontier": workflow._frontier(self.frontier),  # pyright: ignore[reportPrivateUsage]
                    "mode": "deterministic_only",
                    "max_findings": "10",
                }
            )
        )
        assert type(result) is CheckCommitResult
        self.frontier = result.result_frontier
        return result

    def status_request(self, view: str = "compact") -> StatusRequest:
        request: dict[str, JsonValue] = {
            **workflow._request_base(self.next("req_")),  # pyright: ignore[reportPrivateUsage]
            "session_id": self.started.session_id,
            "writer_id": self.started.writer_id,
            "view": view,
            "limit": "10",
        }
        if view == "findings":
            request["filter"] = {"include_resolved": True}
        return StatusRequest.model_validate(request)

    async def status(
        self,
        view: str = "compact",
        *,
        route_profile: Literal["policy", "strict"] | None = None,
    ) -> StatusInternalResult:
        return await self.app.status(self.status_request(view), route_profile=route_profile)

    async def receipt(self) -> str:
        receipt = await self.app.receipt(
            ReceiptRequest.model_validate(
                {
                    **workflow._request_base(self.next("req_")),  # pyright: ignore[reportPrivateUsage]
                    "task_id": self.started.task_id,
                    "session_id": self.started.session_id,
                    "writer_id": self.started.writer_id,
                    "expected_frontier": workflow._frontier(self.frontier),  # pyright: ignore[reportPrivateUsage]
                    "format": "json",
                    "include": "standard",
                    "redaction_profile": "full_local",
                }
            )
        )
        self.frontier = receipt.result_frontier
        return str(receipt.conclusion)

    async def codex_post_tool_use(self, *, paired: bool) -> None:
        """Append what the production Codex mapping materializes for one ``PostToolUse``.

        A paired post names its tool call, so it becomes an action and a result; Codex states no
        outcome, so the result carries ``host_outcome_unavailable``. An unpaired post becomes
        metadata-only evidence carrying ``unpaired_event``.
        """

        ordinal = self.serial + 1
        call = f"call-{ordinal}"
        structural: dict[str, JsonValue] = {"tool_name": "shell"}
        if paired:
            structural.update(tool_call_id=call, correlation_id=call)
        envelope = ObservationEnvelope(
            session_commitment="hmac-sha256:" + "91" * 32,
            event_kind="PostToolUse",
            source_identity=f"hook:post:{call}",
            source=ObservationSource.CODEX_HOOK,
            cursor=ObservationCursor(
                1, 0, ordinal, "hmac-sha256:" + "ab" * 32, "codex-obs-hook/1.0.0"
            ),
            receipt_time=Timestamp("2026-09-28T12:00:00.000Z"),
            structural_payload=JsonObject(structural),
            content_object_refs=(),
            gap_codes=("content_unselected",) if paired else ("unpaired_event",),
        )
        batch = materialize_observation_envelope(envelope, task_id=self.started.task_id)
        assert batch.skip_reason is None and batch.drafts
        resources = cast(
            dict[str, tuple[LedgerPort, MemoryObjects]],
            cast(Any, self.runtime).resources,
        )
        ledger, objects = next(iter(resources.values()))
        now = self.app.clock.now_utc()
        entries: list[AppendEntry] = []
        for item in batch.drafts:
            metadata = ObjectMetadata(
                ObjectKind.EVENT_PAYLOAD,
                media_type_for(item.draft.schema.name),
                self.started.task_id,
                now,
            )
            staged = await objects.stage(
                ObjectSource(data=item.payload_bytes, declared_size=len(item.payload_bytes)),
                metadata,
            )
            ref = await objects.finalize(staged)
            entries.append(
                AppendEntry(
                    item.draft,
                    observation_author(),
                    ref,
                    ref.commitment,
                    metadata.media_type,
                    ref.plaintext_size,
                    batch.channel,
                    batch.coverage,
                    item.projection_status,
                )
            )
        appended = await ledger.append_batch(
            AppendCommand(
                self.started.task_id,
                self.started.session_id,
                self.started.writer_id,
                self.next("req_"),
                OperationKind.PUBLISH_WORK,
                "sha256:" + "7" * 64,
                int(self.frontier.sequence),
                tuple(entries),
                None,
            )
        )
        self.frontier = appended.result_frontier


async def _bandit_b(
    ledger_backend: Literal["memory", "sqlite"],
    *,
    semantic: Literal["disabled", "required"] = "disabled",
) -> tuple[_Session, CheckCommitResult]:
    """Finished work: one obligation resolved with evidence and claimed, Codex hook rows, check."""

    app, runtime, _ = workflow._build_app(  # pyright: ignore[reportPrivateUsage]
        seed_offset=913, ledger_backend=ledger_backend
    )
    if semantic == "required":
        app = replace(app, verification_policy=VerificationPolicy(semantic="required"))
    started = await app.start(start_request(913_500, title="Interprocedural taint checks"))
    session = _Session(app, runtime, started)
    obligation = session.next("obl_")
    evidence = session.next("evd_")
    open_obligation: dict[str, JsonValue] = {
        "obligation_id": obligation,
        "description": "Add interprocedural taint checks.",
        "evidence_expectation": "The focused test run passes.",
        "status": "open",
    }
    await session.publish(
        session.draft(
            "plan_published",
            {"plan_version": 1, "summary": "Taint checks", "obligation_refs": [obligation]},
        ),
        session.draft("obligation_published", open_obligation),
    )
    await session.codex_post_tool_use(paired=True)
    await session.codex_post_tool_use(paired=False)
    await session.publish(
        session.draft(
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-09-28T12:00:00.000Z",
                "description": "The focused test run passed.",
            },
        ),
        session.draft(
            "obligation_published",
            {**open_obligation, "status": "resolved", "resolution_evidence_refs": [evidence]},
        ),
        session.draft(
            "claim_recorded",
            {
                "claim_id": session.next("clm_"),
                "claim_kind": "completion",
                "statement": "Interprocedural taint checks are complete.",
                "obligation_refs": [obligation],
                "supporting_refs": [evidence],
                "limitation_refs": [],
                "supersedes_claim_refs": [],
            },
        ),
    )
    checked = await session.check()
    return session, checked


def public_status(status: StatusInternalResult) -> StatusResultModel:
    """Project the internal result to the public result a control client receives."""

    body: dict[str, JsonValue] = {
        **status.as_json(),
        "privacy_projection": {
            "sink": "local_human_view",
            "local_disclosure_receipt_id": protocol_id("egr_", 913_900),
            "policy_id": protocol_id("pvy_", 913_901),
            "policy_version": "1",
            "policy_digest": "sha256:" + "a" * 64,
            "included_categories": [],
            "blocked_categories": [],
            "omitted_pointers": [],
            "projection_commitment": "hmac-sha256:" + "b" * 64,
        },
    }
    return StatusResultModel.model_validate(body)


def _wire(status: StatusInternalResult) -> StatusSuccessModel:
    """Project the internal result to the public model the CLI and TUI render."""

    parsed = public_status(status).root
    assert type(parsed) is StatusSuccessModel
    return parsed


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_bandit_b_reads_ready_with_limitations_and_keeps_its_verdict(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    session, checked = await _bandit_b(ledger_backend)
    # No verdict change: a local-only check with standing gaps stays insufficient_coverage.
    assert checked.findings == ()
    assert checked.verdict.value == "insufficient_coverage"
    assert _CODEX_STANDING <= set(checked.coverage.known_gaps)

    status = await session.status()
    readiness = status.closure_readiness
    assert readiness.agent_actionable is not None and readiness.standing_limitations is not None
    assert readiness.state == "ready_with_limitations"
    assert readiness.agent_actionable == ()
    assert _CODEX_STANDING <= set(readiness.standing_limitations)
    assert readiness.acknowledged_not_done == ()
    # The conclusion stays bounded: gaps are still named as bounding it, and still disclosed.
    assert readiness.blocking_conditions == ("coverage_gaps_declared",)
    assert _CODEX_STANDING <= set(status.coverage.known_gaps)

    # MCP text: the owner-approved stop sentence, with the limitations named.
    sentence = _APPROVED.format(n=len(readiness.standing_limitations), m=0)
    summary = summary_for_status(status.as_json())
    assert "Closure: ready_with_limitations." in summary
    assert sentence in summary
    assert "host_outcome_unavailable" in summary
    assert "check" not in summary.split("Closure:", 1)[1].lower().replace("checks", "")
    # CLI and TUI (which renders the same lines) say the same thing.
    rendered = render_human_status(_wire(status)).splitlines()
    assert "Closure: ready_with_limitations" in rendered
    assert sentence in rendered
    assert any(line.startswith("Standing limitations: ") for line in rendered)

    # One coverage definition (Example 1): every view at one frontier reports the task coverage
    # and gaps the compact view reports, and the same checklist, so none reads cleaner.
    for view in ("findings", "results", "evidence", "history", "obligations"):
        other = await session.status(view)
        assert other.closure_readiness == readiness
        assert other.coverage == status.coverage
        assert other.gaps == status.gaps
        other_summary = summary_for_status(other.as_json())
        assert f"freshness: {status.coverage.ledger_freshness.value};" in other_summary
        assert f"reported gaps: {len(status.gaps)}." in other_summary

    # Honesty: the receipt conclusion is unchanged.
    assert await session.receipt() == "insufficient_coverage"


class _OwnedWorkLifecycle:
    """The two lineage calls an owned ``work_closed`` publication makes, accepted as-is."""

    def __init__(self) -> None:
        self.closed: list[str] = []
        self.store = self

    async def get_task(self, _task_id: str) -> None:
        return None

    async def validate_owned_work_transition(self, *_args: object, **_kwargs: object) -> None:
        return None

    async def close_work(self, *, session_id: str, task_id: str | None = None) -> None:
        self.closed.append(session_id)


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_work_closed_does_not_ask_for_an_identical_recheck(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    session, _ = await _bandit_b(ledger_backend)
    lifecycle = _OwnedWorkLifecycle()
    session.app = replace(session.app, lineage=cast(Any, lifecycle))
    await session.publish(session.draft("work_closed", {}))
    assert lifecycle.closed == [session.started.session_id]
    after_close = await session.status()
    assert after_close.closure_readiness.state == "ready_with_limitations"
    assert after_close.closure_readiness.agent_actionable == ()

    # A real material change after the check is the one recheck readiness asks for.
    await session.publish(
        session.draft(
            "evidence_recorded",
            {
                "evidence_id": session.next("evd_"),
                "evidence_kind": "other",
                "strength": "metadata_only",
                "description": "A later note.",
                "observed_at": "2026-09-28T12:05:00.000Z",
            },
        )
    )
    changed = await session.status()
    assert changed.closure_readiness.state == "action_required"
    assert changed.closure_readiness.agent_actionable is not None
    assert "check_not_applicable" in changed.closure_readiness.agent_actionable
    assert "Closure: action_required." in summary_for_status(changed.as_json())


async def test_open_work_and_actionable_gaps_stay_agent_actionable() -> None:
    app, runtime, _ = workflow._build_app(seed_offset=914)  # pyright: ignore[reportPrivateUsage]
    started = await app.start(start_request(913_700, title="Open work"))
    session = _Session(app, runtime, started)
    obligations: list[JsonValue] = [session.next("obl_"), session.next("obl_")]
    await session.publish(
        session.draft(
            "plan_published",
            {"plan_version": 1, "summary": "Two items", "obligation_refs": obligations},
        ),
        *(
            session.draft(
                "obligation_published",
                {
                    "obligation_id": key,
                    "description": "Synthetic work",
                    "evidence_expectation": "Evidence",
                    "status": "open",
                },
            )
            for key in obligations
        ),
    )
    await session.codex_post_tool_use(paired=True)
    no_check = await session.status()
    assert no_check.closure_readiness.agent_actionable is not None
    assert no_check.closure_readiness.state == "action_required"
    assert no_check.closure_readiness.agent_actionable[:1] == ("obligations_open",)
    assert "check_not_recorded" in no_check.closure_readiness.agent_actionable
    # No recorded form acknowledges an obligation yet (#913 slice C): the group stays empty.
    assert no_check.closure_readiness.acknowledged_not_done == ()
    assert no_check.closure_readiness.acknowledged_not_done_count == "0"

    evidence = session.next("evd_")
    await session.publish(
        session.draft(
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "other",
                "strength": "metadata_only",
                "description": "Evidence for the first item.",
                "observed_at": "2026-09-28T12:00:00.000Z",
            },
        ),
        session.draft(
            "obligation_published",
            {
                "obligation_id": obligations[0],
                "description": "Synthetic work",
                "evidence_expectation": "Evidence",
                "status": "resolved",
                "resolution_evidence_refs": [evidence],
            },
        ),
        session.draft(
            "claim_recorded",
            {
                "claim_id": session.next("clm_"),
                "claim_kind": "completion",
                "statement": "The first item is complete.",
                "obligation_refs": [obligations[0]],
                "supporting_refs": [evidence],
                "limitation_refs": [],
                "supersedes_claim_refs": [],
            },
        ),
    )
    await session.check()
    partial = await session.status()
    readiness = partial.closure_readiness
    assert readiness.agent_actionable is not None and readiness.standing_limitations is not None
    assert readiness.state == "action_required"
    assert "obligations_open" in readiness.agent_actionable
    # A plan item the completion claim omits is the agent's to repair, never a limitation.
    assert "completion_plan_not_claimed" in readiness.agent_actionable
    assert "completion_plan_not_claimed" not in readiness.standing_limitations
    assert readiness_directive("action_required") in render_human_status(_wire(partial))


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_required_ai_review_keeps_the_local_only_gap_actionable(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    session, checked = await _bandit_b(ledger_backend, semantic="required")
    assert "semantic_review_not_requested" in checked.coverage.known_gaps
    status = await session.status()
    readiness = status.closure_readiness
    assert readiness.standing_limitations is not None
    assert readiness.state == "action_required"
    assert readiness.agent_actionable == ("semantic_review_not_requested",)
    assert "semantic_review_not_requested" not in readiness.standing_limitations


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_a_strict_route_never_asks_for_an_ai_review_it_cannot_dispatch(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """PR #937 review F1: a strict MCP process has no AI-powered review capability (ADR-018).

    With the repository policy requiring AI-powered review, the missing review is a route-side
    limitation the owner lifts by serving the policy route, never an action the agent can take
    from this process; asking for it recreated the unchanged-state recheck loop of issue #913.
    """

    session, checked = await _bandit_b(ledger_backend, semantic="required")
    assert "semantic_review_not_requested" in checked.coverage.known_gaps
    status = await session.status(route_profile="strict")
    readiness = status.closure_readiness
    assert readiness.agent_actionable is not None and readiness.standing_limitations is not None
    assert readiness.state == "ready_with_limitations"
    assert readiness.agent_actionable == ()
    assert "semantic_review_not_requested" in readiness.standing_limitations
    # Still bounded and still disclosed: the gap stays in coverage and in the conditions.
    assert readiness.blocking_conditions == ("coverage_gaps_declared",)
    assert "semantic_review_not_requested" in status.coverage.known_gaps
    sentence = _APPROVED.format(n=len(readiness.standing_limitations), m=0)
    summary = summary_for_status(status.as_json())
    assert "Closure: ready_with_limitations." in summary
    assert sentence in summary
    rendered = render_human_status(_wire(status)).splitlines()
    assert "Closure: ready_with_limitations" in rendered
    assert sentence in rendered
    for view in ("findings", "results", "evidence", "history", "obligations"):
        other = await session.status(view, route_profile="strict")
        assert other.closure_readiness == readiness
    # The same ledger read by a caller that can dispatch AI-powered review still owes it.
    policy = await session.status(route_profile="policy")
    assert policy.closure_readiness.state == "action_required"
    assert policy.closure_readiness.agent_actionable == ("semantic_review_not_requested",)
    # Honesty: the receipt conclusion is unchanged.
    assert await session.receipt() == "insufficient_coverage"


@pytest.mark.parametrize("ledger_backend", ("memory", "sqlite"))
async def test_a_check_still_in_flight_is_never_nothing_further_to_do(
    ledger_backend: Literal["memory", "sqlite"],
) -> None:
    """A second check holding the frontier keeps readiness actionable until its result lands."""

    session, _ = await _bandit_b(ledger_backend)
    assert (await session.status()).closure_readiness.state == "ready_with_limitations"
    resources = cast(
        dict[str, tuple[LedgerPort, MemoryObjects]], cast(Any, session.runtime).resources
    )
    ledger, _objects = next(iter(resources.values()))
    request_id = session.next("req_")
    frozen = await ledger.freeze_case(
        session.started.session_id,
        session.started.writer_id,
        int(session.frontier.sequence),
        request_id,
        "sha256:" + "8" * 64,
    )
    assert type(frozen) is not CheckCommitResult
    assert await ledger.has_active_frozen_case(session.started.session_id)

    pending = await session.status()
    readiness = pending.closure_readiness
    assert readiness.state == "action_required"
    assert readiness.agent_actionable == ("check_in_progress",)
    summary = summary_for_status(pending.as_json())
    assert "Nothing further to do" not in summary
    assert "Agent-actionable: check_in_progress." in summary
    operation = await session.app.status(
        StatusRequest.model_validate(
            {
                **workflow._request_base(session.next("req_")),  # pyright: ignore[reportPrivateUsage]
                "session_id": session.started.session_id,
                "writer_id": session.started.writer_id,
                "view": "operation",
                "limit": "1",
                "filter": {"operation_request_id": request_id},
            }
        )
    )
    operation_summary = summary_for_status(operation.as_json())
    assert "operation state: pending" in operation_summary
    assert "Nothing further to do" not in operation_summary
    assert operation.closure_readiness.state == "action_required"


async def test_missing_readiness_facts_read_as_unknown_never_as_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defence in depth: an adapter that derives no facts cannot manufacture a stop state."""

    session, _ = await _bandit_b("memory")
    original = MemoryLedgerAdapter.query_projection

    async def without_facts(self: MemoryLedgerAdapter, query: ProjectionQuery) -> ProjectionPage:
        return replace(await original(self, query), readiness_facts=None)

    monkeypatch.setattr(MemoryLedgerAdapter, "query_projection", without_facts)
    status = await session.status()
    assert status.closure_readiness.state == "unknown"
    assert status.closure_readiness.blocking_conditions == ("readiness_unknown",)
    assert "Nothing further to do" not in summary_for_status(status.as_json())


@pytest.mark.parametrize("token", ("lineage_child_read_gap", "lineage_child_provenance_restricted"))
async def test_a_live_lineage_blocker_is_never_promised_as_a_receipt_disclosure(
    monkeypatch: pytest.MonkeyPatch, token: str
) -> None:
    """Status compares children live; the receipt folds recorded lineage only (Greptile P1).

    A standing-class lineage token that no recorded evaluation carries yet must not read as a
    limitation "disclosed on the receipt": it stays agent-actionable until it is recorded.
    """

    session, _ = await _bandit_b("memory")

    async def live_gaps(*_args: object) -> tuple[tuple[str, ...], bool]:
        return (token,), False

    monkeypatch.setattr(status_module, "_lineage_readiness_gaps", live_gaps)
    status = await session.status()
    readiness = status.closure_readiness
    assert readiness.agent_actionable is not None and readiness.standing_limitations is not None
    assert readiness.state == "action_required"
    assert token in readiness.agent_actionable
    assert token not in readiness.standing_limitations
    assert "Nothing further to do" not in summary_for_status(status.as_json())
    # The receipt at this frontier indeed does not carry the live token.
    receipt = await session.app.receipt(
        ReceiptRequest.model_validate(
            {
                **workflow._request_base(session.next("req_")),  # pyright: ignore[reportPrivateUsage]
                "task_id": session.started.task_id,
                "session_id": session.started.session_id,
                "writer_id": session.started.writer_id,
                "expected_frontier": workflow._frontier(session.frontier),  # pyright: ignore[reportPrivateUsage]
                "format": "json",
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )
    assert token not in receipt.coverage.known_gaps


async def test_a_child_with_self_verified_findings_is_a_standing_status_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #984/#996 (S2): an accepted child's self-verified findings keep the parent receipt
    at best insufficient_coverage, so parent status never reads plainly ready."""

    session, _ = await _bandit_b("memory")

    async def self_verified_child(*_args: object) -> tuple[tuple[str, ...], bool]:
        return (), True

    monkeypatch.setattr(status_module, "_lineage_readiness_gaps", self_verified_child)
    readiness = (await session.status()).closure_readiness
    assert readiness.standing_limitations is not None
    assert "finding_self_verified" in readiness.standing_limitations
    assert readiness.state != "ready"
    assert readiness.agent_actionable is not None
    assert "finding_self_verified" not in readiness.agent_actionable
