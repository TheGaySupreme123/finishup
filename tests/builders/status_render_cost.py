"""A synthetic Codex-shaped task ledger for the status render-cost harness (issue #916).

The DeepSWE v2 run measured ``status`` pages at ~0.5 s fixed plus ~18 ms per returned row, and
``closure-prepare`` at 16-55 s, on ledgers of roughly 1,000 events of which about 70% were
hook-observed. This builder reproduces that shape without a service: a real ready ``Application``
over the memory ledger, the real privacy coordinator and local enforcer seeded with the shipped
default policy, and a SQLite privacy catalog (``migrations/catalog``) so every projection writes
the same local-disclosure receipt row, HMAC commitments included, that the daemon writes.

Each hook-observed tool call becomes an action/result/evidence triple appended under the
observation author on the ``hook_observed`` channel, the shape the Codex hook materialization
produces. The cooperative agent publishes the plan, one obligation, and its own actions, results
and evidence. Two rows carry a never-send credential shape so that the per-pointer omission
reasons mix ``never_send_redacted`` with ``local_disclosure_not_authorized``: one hook-observed
evidence description (another writer's row) and one agent-published evidence reference (a
self-authored row).

Everything is deterministic (fixed clock, counter ids, fixed HMAC key), so the rendered pages and
receipts are byte-stable across runs and machines.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Final, cast

import apsw

from builders.ledger_adapters import MemoryObjects
from builders.projection_workflow import (
    build_projection_application,
    frontier_json,
    request_base,
)
from builders.start_application import protocol_id, start_request
from finishup.adapters.memory.ledger import MemoryLedgerAdapter
from finishup.adapters.privacy.catalog import CatalogPrivacyAudit, CatalogPrivacyPolicyStore
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.adapters.sqlite.migrations import initialize_catalog
from finishup.application.egress import PrivacyCoordinator
from finishup.application.observation_materialize import observation_author
from finishup.application.service import (
    Application,
    ClientProjectionContext,
    ControlProjectionBinding,
    ProjectionRenderMode,
)
from finishup.application.start import StartInternalResult
from finishup.application.status import StatusInternalResult
from finishup.domain.events import (
    EVIDENCE_SCHEMA_VERSION,
    ActionKind,
    ActionRecordedPayload,
    EventDraft,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    encode_payload,
    media_type_for,
)
from finishup.domain.privacy import PrivacyPolicy
from finishup.domain.values import (
    Frontier,
    action_id,
    event_id,
    evidence_id,
    format_rfc3339_millis,
    result_id,
    timestamp_from_datetime,
)
from finishup.ports.control import ControlClientKind, ControlMethod
from finishup.ports.ledger import AppendCommand, AppendEntry, CheckCommitResult, OperationKind
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource, ObjectStorePort
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.coverage import (
    EvidenceImmutability,
    PublicationChannel,
    coverage_for_channel,
)
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    StatusRequest,
    StatusResult,
)

__all__ = [
    "CLOSURE_VIEWS",
    "NEVER_SEND_TOKEN",
    "CodexStatusLedger",
    "build_codex_status_ledger",
]

# The five views ``closure-prepare`` exhausts, in its order.
CLOSURE_VIEWS: Final = ("obligations", "results", "evidence", "findings", "history")

# Matches the shared observability scanner's ``sk-`` credential pattern, so the never-send scan
# records a finding on the rows that carry it.
NEVER_SEND_TOKEN: Final = "sk-" + "synthetic0916Token0916Abc"

_CURSOR_KEY: Final = b"status-render-cost-cursor-key-32b"
_HOOK_BATCH: Final = 30
_AGENT_BATCH: Final = 60
_HOOK_SECRET_CALL: Final = 7
_AGENT_SECRET_ROW: Final = 3

type _HookRow = tuple[
    str,
    ActionRecordedPayload | ResultRecordedPayload | EvidenceRecordedPayload,
    tuple[int, ...],
]


class _AuditKey:
    """A fixed HMAC key so catalog commitments are byte-stable across runs."""

    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac.new(b"\x16" * 32, domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


class _Gateway:
    async def close(self) -> None:
        return None


@dataclass(frozen=True, slots=True)
class CodexStatusLedger:
    """A ready application over one synthetic Codex-shaped task, pinned at ``head``."""

    app: Application
    started: StartInternalResult
    head: Frontier
    catalog: apsw.Connection
    hook_calls: int
    agent_rows: int

    def status_body(
        self,
        view: str,
        seed: int,
        *,
        cursor: str | None = None,
        limit: str = "100",
    ) -> dict[str, JsonValue]:
        """One MCP ``status`` request body pinned at the ledger head, filtered as closure is."""

        body: dict[str, JsonValue] = {
            **request_base(protocol_id("req_", seed)),
            "session_id": self.started.session_id,
            "writer_id": self.started.writer_id,
            "view": view,
            "limit": limit,
            "at_frontier": str(self.head.sequence),
        }
        if cursor is not None:
            body["cursor"] = cursor
        if view in {"obligations", "findings"}:
            body["filter"] = {"include_resolved": True}
        elif view == "evidence":
            body["filter"] = {"include_unavailable": True}
        return body

    async def project_status(self, body: Mapping[str, JsonValue], seed: int) -> StatusResult:
        """Run ``status`` and the daemon's exact post-commit projection for an MCP bridge.

        Returns the projected public model the daemon frames, before any wire dump.
        """

        internal = await self.app.status(StatusRequest.model_validate(body))
        return await self.project(body, internal, seed)

    async def project(
        self, body: Mapping[str, JsonValue], internal: StatusInternalResult, seed: int
    ) -> StatusResult:
        """The daemon's post-commit projection of one ``status`` result for an MCP bridge.

        The frame carries the request body as the daemon's does. These closure-shaped reads send
        no ``delivery=paged`` (#1139), so, like the bridge's own closure reads, they are not paged.
        """

        facts = await self.app.projection_binding_facts(ControlMethod.STATUS, body, internal)
        rpc_id = protocol_id("rpc_", seed)
        service_instance_id = protocol_id("svc_", seed + 1)
        binding = ControlProjectionBinding(
            rpc_id,
            ControlMethod.STATUS,
            service_instance_id,
            1,
            facts.original_request_id,
            facts.route_identity_digest,
            canonical_encode(
                {
                    "rpc_id": rpc_id,
                    "method": ControlMethod.STATUS.value,
                    "service_instance_id": service_instance_id,
                    "service_generation": "1",
                    "body": dict(body),
                }
            ),
        )
        projected = await self.app.project_result_for_client(
            ClientProjectionContext(
                ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
            ),
            binding,
            internal,
        )
        assert type(projected) is StatusResult
        return projected

    def receipt_rows(self) -> tuple[tuple[str, bytes, bytes], ...]:
        """Every durable agent-projection audit row: request id, audit subject, receipt."""

        rows = self.catalog.execute(
            """SELECT request_id, subject_structural_canonical, receipt_canonical
               FROM privacy_audit_records
               WHERE subject_kind = 'agent_projection'
               ORDER BY proposal_id"""
        ).fetchall()
        return tuple(
            (cast(str, request), cast(bytes, subject), cast(bytes, receipt))
            for request, subject, receipt in rows
        )


def _hook_rows(call: int, seed: int, now: datetime) -> tuple[_HookRow, ...]:
    """One Codex hook-observed tool call: the action, its observed result, output evidence."""

    action = action_id(protocol_id("act_", seed))
    outcome = ResultOutcome.FAILURE if call % 9 == 4 else ResultOutcome.SUCCESS
    exit_status = 1 if outcome is ResultOutcome.FAILURE else 0
    description = f"Observed command output exit={exit_status}"
    if call == _HOOK_SECRET_CALL:
        description = f"{description} {NEVER_SEND_TOKEN}"
    return (
        (
            "action_recorded",
            ActionRecordedPayload(
                action,
                ActionKind.COMMAND,
                "Observed command via Codex hook",
                command=f"omitted:sha256:{hashlib.sha256(str(call).encode()).hexdigest()}",
            ),
            (),
        ),
        (
            "result_recorded",
            ResultRecordedPayload(
                result_id(protocol_id("res_", seed + 1)),
                action,
                outcome,
                exit_status=exit_status,
                summary=f"Observed result status={outcome.value}",
            ),
            (0,),
        ),
        (
            "evidence_recorded",
            EvidenceRecordedPayload(
                evidence_id(protocol_id("evd_", seed + 2)),
                EvidenceKind.OTHER,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_datetime(now),
                description=description,
                reference=f"codex-hook:exec_command:call_{call:05d}",
            ),
            (1,),
        ),
    )


async def _append_hook_calls(
    ledger: MemoryLedgerAdapter,
    objects: MemoryObjects,
    started: StartInternalResult,
    head: Frontier,
    calls: range,
    *,
    now: datetime,
    request_seed: int,
) -> Frontier:
    """Append hook-observed rows exactly as the observation drain commits them."""

    channel = PublicationChannel.HOOK_OBSERVED
    occurred_at = timestamp_from_datetime(now)
    entries: list[AppendEntry] = []
    for call in calls:
        seed = 1_000_000 + call * 10
        rows = _hook_rows(call, seed, now)
        event_ids = tuple(protocol_id("evt_", seed + 5 + offset) for offset in range(len(rows)))
        for offset, (name, payload, parents) in enumerate(rows):
            encoded = canonical_encode(encode_payload(payload))
            metadata = ObjectMetadata(
                ObjectKind.EVENT_PAYLOAD, media_type_for(name), started.task_id, now
            )
            staged = await objects.stage(
                ObjectSource(data=encoded, declared_size=len(encoded)), metadata
            )
            ref = await objects.finalize(staged)
            schema_version = EVIDENCE_SCHEMA_VERSION if name == "evidence_recorded" else "1.0.0"
            entries.append(
                AppendEntry(
                    EventDraft(
                        event_id(event_ids[offset]),
                        EventSchema(name, schema_version),
                        occurred_at,
                        tuple(event_id(event_ids[parent]) for parent in parents),
                        payload,
                        (),
                        (),
                    ),
                    observation_author(),
                    ref,
                    ref.commitment,
                    metadata.media_type,
                    ref.plaintext_size,
                    channel,
                    coverage_for_channel(channel),
                    "projected",
                )
            )
    result = await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", request_seed),
            OperationKind.PUBLISH_WORK,
            "sha256:" + "6" * 64,
            head.sequence,
            tuple(entries),
            None,
        )
    )
    return result.result_frontier


def _draft(number: int, name: str, payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "event_id": protocol_id("evt_", number),
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-07-19T12:00:00.000Z",
        "causal_parents": [],
        "payload": payload,
        "artifact_refs": [],
        "evidence_refs": [],
    }


def _agent_drafts(first: int, count: int, obligation: str) -> list[JsonValue]:
    """Agent-authored actions, results and evidence, one of each per row."""

    drafts: list[JsonValue] = []
    for row in range(first, first + count):
        seed = 2_000_000 + row * 10
        action = protocol_id("act_", seed)
        reference = f"tests/test_module_{row:03d}.py::test_case"
        if row == _AGENT_SECRET_ROW:
            reference = f"{reference} {NEVER_SEND_TOKEN}"
        drafts.extend(
            (
                _draft(
                    seed + 5,
                    "action_recorded",
                    {
                        "action_id": action,
                        "action_kind": "command",
                        "command": f"pytest tests/test_module_{row:03d}.py",
                        "description": f"Ran the focused test module {row:03d}.",
                        "obligation_refs": [obligation],
                    },
                ),
                _draft(
                    seed + 6,
                    "result_recorded",
                    {
                        "result_id": protocol_id("res_", seed + 1),
                        "action_id": action,
                        "outcome": "success",
                        "summary": f"Test module {row:03d} passed.",
                    },
                ),
                _draft(
                    seed + 7,
                    "evidence_recorded",
                    {
                        "evidence_id": protocol_id("evd_", seed + 2),
                        "evidence_kind": "test_result",
                        "strength": "metadata_only",
                        "observed_at": "2026-07-19T12:00:00.000Z",
                        "description": f"Focused test module {row:03d} passed.",
                        "reference": reference,
                    },
                ),
            )
        )
    return drafts


async def _catalog_privacy(
    app: Application, policy: PrivacyPolicy
) -> tuple[PrivacyCoordinator, apsw.Connection]:
    """The SQLite privacy catalog the service uses, seeded with the same default policy."""

    db = apsw.Connection(":memory:")
    initialize_catalog(db)
    policies = CatalogPrivacyPolicyStore(db, app.clock)
    await policies.seed_if_absent(policy)
    audit = CatalogPrivacyAudit(
        db,
        cast(ObjectStorePort, MemoryObjects(app.ids)),  # pyright: ignore[reportArgumentType]
        _AuditKey(),  # pyright: ignore[reportArgumentType]
        app.clock,
    )
    coordinator = PrivacyCoordinator(
        policies,
        LocalPrivacyEnforcer(),
        audit,
        _Gateway(),  # pyright: ignore[reportArgumentType]
        app.clock,
        app.ids,
    )
    return coordinator, db


async def build_codex_status_ledger(
    hook_calls: int = 230, agent_rows: int = 100, *, seed: int = 9160
) -> CodexStatusLedger:
    """Build one task of ``3 * (hook_calls + agent_rows) + 3`` events plus one local check.

    The defaults give the benchmark's shape: ~1,000 events, ~70% of them hook-observed, and
    330 evidence rows (four 100-row evidence pages).
    """

    app, policy = await build_projection_application(seed=seed)
    privacy, catalog = await _catalog_privacy(app, policy)
    app = replace(app, privacy=privacy, status_cursor_key=_CURSOR_KEY)
    started = await app.start(start_request(seed + 1, title="Synthetic Codex session"))
    stamp = format_rfc3339_millis(app.clock.now_utc())
    # The catalog keys every task-scoped audit row to its route, as START records it in service.
    catalog.execute(
        """INSERT INTO task_routes (
               task_id, workspace_ref_commitment, external_ref_commitment, active_session_id,
               bundle_relpath, route_generation, active_route_identity_digest, state,
               quarantine_code, created_at, updated_at
           ) VALUES (?, NULL, NULL, ?, ?, 1, ?, 'active', NULL, ?, ?)""",
        (
            started.task_id,
            started.session_id,
            f"tasks/{started.task_id}",
            "sha256:" + "5" * 64,
            stamp,
            stamp,
        ),
    )
    ledger, objects = next(iter(app.runtime.resources.values()))  # type: ignore[attr-defined]
    now = app.clock.now_utc()
    obligation = protocol_id("obl_", seed + 2)
    frontier: JsonValue = frontier_json(started.frontier)
    number = seed * 10

    async def publish(drafts: list[JsonValue]) -> Frontier:
        nonlocal frontier, number
        number += 1
        published = await app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **request_base(protocol_id("req_", number)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": frontier,
                    "event_drafts": drafts,
                }
            )
        )
        head = cast(Frontier, published.result_frontier)  # type: ignore[union-attr]
        frontier = frontier_json(head)
        return head

    head = await publish(
        [
            _draft(
                seed + 3,
                "plan_published",
                {
                    "plan_version": 1,
                    "summary": "Fix the parser and prove it with focused tests.",
                    "obligation_refs": [obligation],
                },
            ),
            _draft(
                seed + 4,
                "obligation_published",
                {
                    "obligation_id": obligation,
                    "description": "Run the focused parser tests.",
                    "evidence_expectation": "Observed passing test results.",
                    "status": "open",
                    "requested_items": [{"item_kind": "command", "value": "pytest tests"}],
                },
            ),
        ]
    )
    hook_done = 0
    agent_done = 0
    batch = 0
    # Interleave hook drains with agent publications, as a live session does.
    while hook_done < hook_calls or agent_done < agent_rows:
        if hook_done < hook_calls:
            upto = min(hook_calls, hook_done + _HOOK_BATCH)
            head = await _append_hook_calls(
                cast(MemoryLedgerAdapter, ledger),
                cast(MemoryObjects, objects),
                started,
                head,
                range(hook_done, upto),
                now=now,
                request_seed=seed * 100 + batch,
            )
            frontier = frontier_json(head)
            hook_done = upto
        if agent_done < agent_rows and (hook_done >= hook_calls or batch % 2 == 1):
            count = min(agent_rows - agent_done, _AGENT_BATCH // 3)
            head = await publish(_agent_drafts(agent_done, count, obligation))
            agent_done += count
        batch += 1
    # An unsupported completion claim over the still-open obligation, then a local check, so the
    # findings view has real rows as it does when an agent prepares closure.
    head = await publish(
        [
            _draft(
                seed + 5,
                "claim_recorded",
                {
                    "claim_id": protocol_id("clm_", seed + 6),
                    "claim_kind": "completion",
                    "statement": "The parser fix is complete.",
                    "supporting_refs": [obligation],
                    "obligation_refs": [obligation],
                },
            )
        ]
    )
    number += 1
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **request_base(protocol_id("req_", number)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier,
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    assert checked.findings, "the synthetic session must yield at least one finding"
    head = checked.result_frontier
    return CodexStatusLedger(app, started, head, catalog, hook_calls, agent_rows)
