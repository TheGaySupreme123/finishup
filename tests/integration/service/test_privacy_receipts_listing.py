"""``privacy receipts list`` over the real local control socket (issue #921).

The DeepSWE v2 export ran ``yoetz privacy receipts list --page-size 100 --json`` after each
session and got ``invalid_request: the local request could not be completed`` in 39 of 58
isolated installs -- every install whose audit held about 45 receipts or more, which is every
install where AI-powered review sent data off the machine. The page itself was valid. The frame
carrying it was not readable: the control reader asked the authenticated Unix stream for the
whole remaining frame in one ``receive``, the stream refuses any single receive above 64 KiB, and
the refusal surfaced as ``frame_invalid`` -- the caller's ``invalid_request`` -- with no service
diagnostic, because the service had answered correctly.

These cases run the real daemon, the real ready application and privacy catalog, a real bound
control listener and the real client, so a page crosses exactly the boundary that failed. Receipts
come from the production writers: projected control reads, the coordinator's own pre-dispatch
path, and the catalog's disclosure, egress and projection writers with receipts shaped the way
the application writes them. Nothing here touches a user installation: the service root is a
private owner-only directory and ``YOETZ_ISOLATED_ROOT`` points there.
"""

from __future__ import annotations

import asyncio
import io
import json
from collections.abc import AsyncIterator, Callable
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

import yoetz.cli.app as cli_app
from builders.multi_agent import private_service_root
from integration.service.test_consent_vault_initialize_composition import (
    runtime_directory,  # noqa: F401  # pyright: ignore[reportUnusedImport]
)
from integration.service.test_ready_composition import (
    _Diagnostics,  # pyright: ignore[reportPrivateUsage]
    _GenerationStore,  # pyright: ignore[reportPrivateUsage]
    _Paths,  # pyright: ignore[reportPrivateUsage]
    _sqlite_policy,  # noqa: F401  # pyright: ignore[reportUnusedImport, reportPrivateUsage]
)
from yoetz.adapters.control.unix_socket import bind_control_listener
from yoetz.adapters.keys.encrypted_vault import EncryptedVaultStore
from yoetz.adapters.keys.secret_memory import LocalSecretMemory
from yoetz.adapters.privacy.catalog import CatalogPrivacyAudit
from yoetz.application.egress import SemanticEgressBlocked
from yoetz.application.privacy_control import encode_privacy_receipt_page
from yoetz.application.service import Application
from yoetz.config.models import YoetzConfig
from yoetz.domain.privacy import (
    MAX_RECEIPT_FINAL_BYTES,
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    CandidateContextItem,
    ConsentSource,
    EgressChannel,
    EgressReceipt,
    LocalDisclosureReceipt,
    LocalDisclosureSink,
    PreDispatchAuditDecision,
    PrivacyOutcome,
    PrivacyReason,
    ProviderBinding,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptTransformations,
    RequestCommitment,
)
from yoetz.domain.values import JsonObject
from yoetz.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    RepositoryPrivacyContext,
    ServiceState,
)
from yoetz.ports.privacy import (
    AgentProjectionRequest,
    DisclosureProposalRequest,
    MinimizedDisclosure,
    PrivacyReceiptPage,
)
from yoetz.ports.secret_memory import SecretPurpose
from yoetz.ports.semantic import Deadline
from yoetz.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import DataCategory, StartRequest
from yoetz.service.client import (
    GetPrivacyReceiptRequest,
    ListPrivacyReceiptsRequest,
    PrivacyReceiptFilters,
    ServiceClient,
    connect_service,
)
from yoetz.service.control_protocol import MAX_CONTROL_RECEIVE_CHUNK_BYTES
from yoetz.service.daemon import ServiceComposition, ServiceDaemon
from yoetz.service.lifecycle import ServiceLifecycle
from yoetz.service.ready_composition import build_ready_application_factory
from yoetz.service.vault import VaultMode, VaultService

pytestmark = pytest.mark.anyio

_INSTALLATION_ID = "ins_92100000-0000-4000-8000-000000000001"
_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000002"
_DIGEST = "sha256:" + "9" * 64
_WORKSPACE = "hmac-sha256:" + "4" * 64
_PASSPHRASE = b"synthetic listing vault only"
_NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
# The review destination arm C of the benchmark used: the local Codex-subscription evaluator.
_CODEX_SUBSCRIPTION = ProviderBinding(
    "openai-codex", "gpt-6-luna", "codex-subscription", "1.0.0", "external"
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Clock:
    """The service's wall clock, pinned so receipt timestamps (and their ties) are exact."""

    def __init__(self) -> None:
        self.instant = _NOW

    def now_utc(self) -> datetime:
        return self.instant

    def monotonic_seconds(self) -> float:
        return 1.0


@dataclass
class _Service:
    daemon: ServiceDaemon
    clock: _Clock
    root: Path

    @property
    def application(self) -> Application:
        application = self.daemon._application  # pyright: ignore[reportPrivateUsage]
        assert isinstance(application, Application)
        return application

    @property
    def audit(self) -> CatalogPrivacyAudit:
        policy_application = self.application.privacy.policy_application
        assert policy_application is not None
        audit = policy_application.audit
        assert type(audit) is CatalogPrivacyAudit
        return audit

    async def dispatch(
        self,
        method: ControlMethod,
        body: object,
        *,
        client_kind: ControlClientKind = ControlClientKind.CLI,
        repository: RepositoryPrivacyContext | None = None,
    ) -> Any:
        instance = self.daemon.composition.lifecycle.instance
        request = ControlCallRequest(
            kind="call",
            protocol_version="1.0",
            rpc_id=new_id(IdKind.CONTROL_RPC),
            service_instance_id=instance.instance_id,
            service_generation=str(instance.generation),
            method=method,
            body=body,  # pyright: ignore[reportArgumentType]
        )
        if repository is None:
            return await self.daemon.dispatch(client_kind, request)
        return await self.daemon.dispatch(
            client_kind, request, repository_privacy_context=repository
        )


@pytest.fixture
async def service(
    runtime_directory: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[_Service]:
    del runtime_directory  # binds the control socket in a short private directory
    with private_service_root() as root:
        monkeypatch.setenv("YOETZ_ISOLATED_ROOT", str(root))
        clock = _Clock()
        memory = LocalSecretMemory()
        lifecycle = ServiceLifecycle(
            clock,
            generation_store=_GenerationStore(),
            process_start_identity_commitment="sha256:" + "4" * 64,
            instance_id=_INSTANCE_ID,
        )
        vault = VaultService(
            installation_id=_INSTALLATION_ID,
            service_generation=1,
            mode=VaultMode.UNINITIALIZED,
            secret_memory=memory,
            clock=clock,
            vault_store_factory=lambda: EncryptedVaultStore(root / "vault"),
            pristine_state_digest="sha256:" + "5" * 64,
        )
        await vault.initialize_passphrase(
            memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(_PASSPHRASE)),
            "sha256:" + "6" * 64,
        )
        await vault.lock()
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=YoetzConfig(),
            paths=_Paths(root),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        daemon = ServiceDaemon(
            _composition=ServiceComposition(
                lifecycle=lifecycle,
                control_listener=await bind_control_listener(),  # pyright: ignore[reportArgumentType]
                secret_ingress_listener=None,
                human_control_listener=None,
                human_control_service=None,
                session_monitor=None,
                vault=vault,
                ready_application_factory=factory,  # pyright: ignore[reportArgumentType]
                secret_memory=memory,
                diagnostics=_Diagnostics(),
            )
        )
        serving: asyncio.Task[None] | None = None
        try:
            await daemon.start()
            await lifecycle.transition(ServiceState.UNLOCKING)
            await vault.unlock(memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(_PASSPHRASE)))
            await daemon.activate_ready_application(1, vault.generation)
            serving = asyncio.create_task(daemon.serve())
            yield _Service(daemon, clock, root)
        finally:
            await daemon.stop()
            if serving is not None:
                await asyncio.wait_for(serving, 10)
            await daemon.close()


def _machine_scope() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID)


def _task_scope(task_id: str) -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.TASK, _INSTALLATION_ID, _WORKSPACE, task_id)


def _policy_binding(scope: AuthorizationScope) -> ReceiptPolicyBinding:
    return ReceiptPolicyBinding(
        new_id(IdKind.PRIVACY_POLICY), 1, _DIGEST, canonical_digest({"scope": scope.kind.value})
    )


def _projection_receipt(
    finished_at: datetime,
    *,
    sink: LocalDisclosureSink = LocalDisclosureSink.AGENT_CONTEXT,
    withheld: bool = False,
    final_bytes: int = 74,
) -> LocalDisclosureReceipt:
    """A client-result projection receipt as ``PrivacyCoordinator._local_receipt`` builds it.

    ``withheld`` is the shape a status page with one never-send match and one unauthorized
    excerpt records: those items are omitted, counted, and the scan reports its match.
    """

    scope = _machine_scope()
    if withheld:
        counts = ReceiptCounts(5, 3, 2, 3, 2, 900, final_bytes, 150, None)
        transformations = ReceiptTransformations(2, 0, 2)
        scan = ReceiptSecretScan("observability-sensitive-content-v1", _DIGEST, 1, False)
        approved: tuple[DataCategory, ...] = (DataCategory.BOUNDED_STRUCTURAL_METADATA,)
        blocked: tuple[DataCategory, ...] = (DataCategory.REPOSITORY_EXCERPT,)
    else:
        counts = ReceiptCounts(0, 0, 0, 0, 0, 0, final_bytes, 0, None)
        transformations = ReceiptTransformations(0, 0, 0)
        scan = ReceiptSecretScan("observability-sensitive-content-v1", _DIGEST, 0, True)
        approved = ()
        blocked = ()
    # Current writers mint 1.1.0, which carries the explicit scan stage; a stage-less 1.0.0 row
    # deliberately reads back as ``legacy_unknown`` rather than a clean prepared scan.
    return LocalDisclosureReceipt(
        "1.1.0",
        new_id(IdKind.EGRESS_RECEIPT),
        new_id(IdKind.REQUEST),
        new_id(IdKind.PRIVACY_PROPOSAL),
        sink,
        PrivacyOutcome.COMPLETED,
        finished_at,
        scope,
        "client_result_projection",
        _policy_binding(scope),
        ConsentSource.BASELINE_POLICY,
        approved,
        blocked,
        counts,
        transformations,
        scan,
        None,
        1,
    )


async def _store_projection(audit: CatalogPrivacyAudit, receipt: LocalDisclosureReceipt) -> None:
    """Write through the catalog writer every agent/CLI result projection uses."""

    empty = canonical_encode({})
    await audit.complete_agent_projection(
        AgentProjectionRequest(
            receipt.privacy_proposal_id,
            receipt.request_id,
            new_id(IdKind.CONTROL_RPC),
            "status",
            _INSTANCE_ID,
            1,
            None,
            empty,
            receipt.scope,
            None,
            None,
            receipt.policy.policy_id,
            1,
            1,
            _DIGEST,
            receipt.sink,
            (),
            empty,
            empty,
            (),
            0,
            0,
            0,
            receipt.finished_at,
        ),
        receipt,
    )


async def _store_projections(
    audit: CatalogPrivacyAudit, count: int, *, newest: datetime, per_millisecond: int = 3
) -> list[LocalDisclosureReceipt]:
    """Write ``count`` projection receipts, ``per_millisecond`` sharing each timestamp.

    Shared timestamps are what a closure-prepare run produces when it pages several status views
    back to back; the page order must break those ties by receipt id exactly as SQL does.
    """

    receipts: list[LocalDisclosureReceipt] = []
    for index in range(count):
        finished = newest - timedelta(milliseconds=index // per_millisecond)
        sink = (
            LocalDisclosureSink.LOCAL_HUMAN_VIEW
            if index % 19 == 0
            else LocalDisclosureSink.AGENT_CONTEXT
        )
        receipt = _projection_receipt(finished, sink=sink, withheld=index % 7 == 0)
        await _store_projection(audit, receipt)
        receipts.append(receipt)
    return receipts


async def _projected_reads(service: _Service, count: int) -> list[str]:
    """Real projected control reads: each one records its own local-disclosure receipt."""

    receipt_ids: list[str] = []
    for _ in range(count):
        result = await service.dispatch(
            ControlMethod.PRIVACY_GET_SETUP,
            JsonObject({"schema_version": "2.0.0"}),
            repository=RepositoryPrivacyContext(_WORKSPACE, "git_common_root"),
        )
        assert result.outcome == "ok", result.body
        body = cast(dict[str, Any], dict(result.body))
        receipt_ids.append(cast(str, body["privacy_projection"]["local_disclosure_receipt_id"]))
    return receipt_ids


async def _start_task(service: _Service) -> str:
    result = await service.dispatch(
        ControlMethod.START,
        StartRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": new_id(IdKind.REQUEST),
                "mode": "create",
                "task_title": "Audit the privacy receipts listing",
                "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
                "client": {
                    "kind": "cooperative_agent",
                    "version": "0.1.0",
                    "integration": "cooperative_mcp",
                },
                "requested_view": "compact",
            }
        ),
        client_kind=ControlClientKind.MCP_BRIDGE,
    )
    assert result.outcome == "ok", result.body
    return cast(str, result.body.root.task_id)


async def _store_completed_review(
    audit: CatalogPrivacyAudit, task_id: str, finished_at: datetime
) -> EgressReceipt:
    """A completed review dispatch: prepared, authorized, consumed, then receipted."""

    payload = canonical_encode({"schema": "yoetz.semantic-review/1", "excerpts": ["a", "b"]})
    scope = _task_scope(task_id)
    minimized = MinimizedDisclosure(
        payload,
        ("item-1",),
        (_DIGEST,),
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (),
        (("minimized_items", 0),),
        len(payload),
        16,
        _DIGEST,
        "observability-sensitive-content-v1",
        _DIGEST,
        (),
    )
    request_id = new_id(IdKind.REQUEST)
    policy_id = new_id(IdKind.PRIVACY_POLICY)
    prepared = await audit.prepare_disclosure_proposal(
        DisclosureProposalRequest(
            new_id(IdKind.PRIVACY_PROPOSAL),
            request_id,
            task_id,
            minimized,
            _CODEX_SUBSCRIPTION,
            None,
            "semantic-review",
            scope,
            policy_id,
            1,
            1,
            _DIGEST,
            len(payload),
            16,
            finished_at + timedelta(minutes=1),
        )
    )
    authorization = await audit.authorize(
        prepared.proposal.privacy_proposal_id, prepared.proposal.prepared_case_digest, finished_at
    )
    dispatch_id = new_id(IdKind.EGRESS_DISPATCH)
    await audit.consume(authorization.authorization_id, dispatch_id, finished_at)
    receipt = EgressReceipt(
        "1.0.0",
        new_id(IdKind.EGRESS_RECEIPT),
        request_id,
        authorization.privacy_proposal_id,
        EgressChannel.LLM_INFERENCE,
        PrivacyOutcome.COMPLETED,
        finished_at,
        authorization.scope,
        authorization.purpose,
        _CODEX_SUBSCRIPTION,
        ReceiptPolicyBinding(policy_id, authorization.policy_version, _DIGEST, _DIGEST),
        authorization.consent_source,
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (),
        ReceiptCounts(1, 1, 0, 1, 0, len(payload), len(payload), 16, len(payload) + 512),
        ReceiptTransformations(0, 0, 0),
        ReceiptSecretScan("observability-sensitive-content-v1", _DIGEST, 0, True),
        None,
        1,
        authorization_id=authorization.authorization_id,
        dispatch_id=dispatch_id,
        dispatch_started_at=finished_at - timedelta(seconds=20),
        request_commitment=RequestCommitment(
            "hmac-sha256/yoetz-privacy-egress-request-v1", _WORKSPACE
        ),
    )
    await audit.complete_egress(dispatch_id, receipt)
    return receipt


async def _store_forbidden_block(
    audit: CatalogPrivacyAudit, task_id: str, finished_at: datetime
) -> EgressReceipt:
    """A review blocked whole by the never-send scanner, as ``_complete_semantic_predispatch``."""

    scope = _task_scope(task_id)
    proposal_id = new_id(IdKind.PRIVACY_PROPOSAL)
    request_id = new_id(IdKind.REQUEST)
    policy_id = new_id(IdKind.PRIVACY_POLICY)
    reservation = await audit.reserve(
        PreDispatchAuditDecision(
            proposal_id,
            request_id,
            EgressChannel.LLM_INFERENCE,
            None,
            "semantic-review",
            scope,
            policy_id,
            1,
            _DIGEST,
            canonical_digest({"binding": _CODEX_SUBSCRIPTION.provider_id}),
            (DataCategory.BOUNDED_STRUCTURAL_METADATA, DataCategory.REPOSITORY_EXCERPT),
            4,
            4,
            (),
            finished_at,
            canonical_digest({"outcome": "blocked_forbidden_data", "request_id": request_id}),
            PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
            PrivacyReason.NEVER_SEND_DETECTED,
        )
    )
    receipt = EgressReceipt(
        "1.0.0",
        new_id(IdKind.EGRESS_RECEIPT),
        request_id,
        proposal_id,
        EgressChannel.LLM_INFERENCE,
        PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
        finished_at,
        scope,
        "semantic-review",
        _CODEX_SUBSCRIPTION,
        ReceiptPolicyBinding(policy_id, 1, _DIGEST, _DIGEST),
        ConsentSource.NONE,
        (),
        (DataCategory.BOUNDED_STRUCTURAL_METADATA, DataCategory.REPOSITORY_EXCERPT),
        ReceiptCounts(4, 0, 4, 0, 4, 48_000, 0, None, None),
        ReceiptTransformations(0, 0, 4),
        ReceiptSecretScan("observability-sensitive-content-v1", f"sha256:{'0' * 64}", 0, True),
        PrivacyReason.NEVER_SEND_DETECTED,
        1,
    )
    await audit.complete_decision(reservation.privacy_proposal_id, receipt)
    return receipt


async def _coordinator_policy_block(service: _Service) -> str:
    """Ask the real coordinator for a review this installation never granted.

    With no repository grant the coordinator refuses before dispatch and records the
    ``blocked_by_policy`` receipt itself -- the writer the benchmark's arm B used.
    """

    scope = _machine_scope()
    result = await service.application.privacy.evaluate_semantic(
        CandidateContext(
            request_id=new_id(IdKind.REQUEST),
            channel=EgressChannel.LLM_INFERENCE,
            local_sink=None,
            purpose="semantic-review",
            scope=scope,
            subject_digest=_DIGEST,
            provider_binding=_CODEX_SUBSCRIPTION,
            items=(
                CandidateContextItem(
                    "excerpt-1",
                    DataCategory.REPOSITORY_EXCERPT,
                    scope,
                    "/excerpts/0",
                    b"def rfc5545_interop(): ...",
                ),
            ),
        ),
        Deadline(service.clock.now_utc() + timedelta(minutes=5), 10_000.0),
    )
    assert type(result) is SemanticEgressBlocked
    assert result.outcome is PrivacyOutcome.BLOCKED_BY_POLICY
    assert result.receipt_id is not None
    return result.receipt_id


async def _client() -> ServiceClient:
    return await connect_service(ControlClientKind.CLI)


async def _list_every_page(page_size: int | None) -> tuple[list[str], list[PrivacyReceiptPage]]:
    client = await _client()
    pages: list[PrivacyReceiptPage] = []
    try:
        cursor: str | None = None
        while True:
            request = (
                ListPrivacyReceiptsRequest(cursor=cursor)
                if page_size is None
                else ListPrivacyReceiptsRequest(page_size=page_size, cursor=cursor)
            )
            page = await client.privacy_receipts_list(request)
            pages.append(page)
            cursor = page.next_cursor
            if cursor is None:
                break
    finally:
        await client.close()
    return [view.receipt.receipt_id for page in pages for view in page.receipts], pages


def _newest_first(receipts: list[tuple[datetime, str]]) -> list[str]:
    return [receipt_id for _, receipt_id in sorted(receipts, reverse=True)]


async def _cli(
    monkeypatch: pytest.MonkeyPatch, coroutine: Callable[[], Any]
) -> tuple[int, str, str]:
    async def build_service_client(*_args: object, **_kwargs: object) -> ServiceClient:
        return await _client()

    monkeypatch.setattr(cli_app, "build_service_client", build_service_client)
    stdout, stderr = io.StringIO(), io.StringIO()

    def write_json(value: object) -> None:
        stdout.write(canonical_encode(cast(Any, value)).decode("utf-8") + "\n")

    monkeypatch.setattr(cli_app, "_stdout_json", write_json)
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = await coroutine()
    return cast(int, code), stdout.getvalue(), stderr.getvalue()


async def test_a_page_past_one_64_kib_receive_lists_over_the_real_socket(
    service: _Service,
) -> None:
    """The benchmark shape: a page of about 45 ordinary receipts, and nothing else wrong.

    Before the fix this raised ``ControlError('frame_invalid')`` -- printed as
    ``invalid_request`` -- for every page whose frame exceeded one 64 KiB receive.
    """

    projected = await _projected_reads(service, 3)
    stored = await _store_projections(service.audit, 60, newest=_NOW - timedelta(minutes=1))

    client = await _client()
    try:
        page = await client.privacy_receipts_list(ListPrivacyReceiptsRequest(page_size=100))
    finally:
        await client.close()

    assert len(page.receipts) == 63
    assert page.undecodable_count == 0
    assert page.next_cursor is None
    listed = {view.receipt.receipt_id for view in page.receipts}
    assert listed == set(projected) | {receipt.receipt_id for receipt in stored}
    assert len(canonical_encode(encode_privacy_receipt_page(page))) > (
        MAX_CONTROL_RECEIVE_CHUNK_BYTES
    )


async def test_150_receipts_page_newest_first_without_duplicates_or_gaps(
    service: _Service,
) -> None:
    """Golden ordering across cursor pages, at ``--page-size 100`` and at the default size."""

    projected = await _projected_reads(service, 2)
    stored = await _store_projections(service.audit, 150, newest=_NOW - timedelta(minutes=1))
    expected = _newest_first(
        [(_NOW, receipt_id) for receipt_id in projected]
        + [(receipt.finished_at, receipt.receipt_id) for receipt in stored]
    )

    for page_size, page_count in ((100, 2), (None, 4)):
        listed, pages = await _list_every_page(page_size)

        assert listed == expected
        assert len(listed) == len(set(listed)) == 152
        assert len(pages) == page_count
        assert all(page.undecodable_count == 0 for page in pages)
        assert len({page.snapshot_generation for page in pages}) == 1


async def test_a_mixed_review_page_lists_every_kind_and_outcome(
    service: _Service, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Local projections, a withheld projection, a completed review, a scanner block and a
    policy block all list together -- the page arm C of the benchmark could never read."""

    task_id = await _start_task(service)
    policy_block = await _coordinator_policy_block(service)
    completed = await _store_completed_review(service.audit, task_id, _NOW - timedelta(seconds=5))
    forbidden = await _store_forbidden_block(service.audit, task_id, _NOW - timedelta(seconds=4))
    withheld = _projection_receipt(_NOW - timedelta(seconds=3), withheld=True)
    await _store_projection(service.audit, withheld)
    ceiling = _projection_receipt(_NOW - timedelta(seconds=2), final_bytes=MAX_RECEIPT_FINAL_BYTES)
    await _store_projection(service.audit, ceiling)
    await _store_projections(service.audit, 50, newest=_NOW - timedelta(minutes=1))

    code, stdout, stderr = await _cli(
        monkeypatch,
        lambda: cli_app._privacy_receipts_list(100, None, True),  # pyright: ignore[reportPrivateUsage]
    )

    assert (code, stderr) == (0, "")
    document = json.loads(stdout)
    by_id = {item["receipt"]["receipt_id"]: item for item in document["receipts"]}
    assert document["undecodable_count"] == 0
    assert document["undecodable_receipt_ids"] == []
    assert by_id[completed.receipt_id]["kind"] == "network_egress"
    assert by_id[completed.receipt_id]["receipt"]["outcome"] == "completed"
    assert by_id[completed.receipt_id]["receipt"]["destination"]["endpoint_profile_id"] == (
        "codex-subscription"
    )
    assert by_id[forbidden.receipt_id]["receipt"]["outcome"] == "blocked_forbidden_data"
    assert by_id[forbidden.receipt_id]["receipt"]["safe_failure_reason"] == "never_send_detected"
    assert by_id[policy_block]["kind"] == "network_egress"
    assert by_id[policy_block]["receipt"]["outcome"] == "blocked_by_policy"
    assert by_id[withheld.receipt_id]["receipt"]["counts"]["removed_items"] == 2
    assert by_id[withheld.receipt_id]["receipt"]["secret_scan"]["passed"] is False
    assert by_id[ceiling.receipt_id]["receipt"]["counts"]["final_bytes"] == MAX_RECEIPT_FINAL_BYTES
    # The five above, the fifty ordinary projections, and the start call's own projection.
    assert len(document["receipts"]) == 56
    assert sum(item["kind"] == "network_egress" for item in document["receipts"]) == 3
    timestamps = [
        (item["receipt"]["finished_at"], item["receipt"]["receipt_id"])
        for item in document["receipts"]
    ]
    assert timestamps == sorted(timestamps, reverse=True)


def _stored_receipt_json(audit: CatalogPrivacyAudit, receipt_id: str) -> dict[str, Any]:
    row = audit._db.execute(  # pyright: ignore[reportPrivateUsage]
        "SELECT receipt_canonical FROM privacy_audit_records WHERE receipt_id = ?",
        (receipt_id,),
    ).fetchone()
    assert row is not None
    return cast(dict[str, Any], strict_json_parse(cast(bytes, row[0])))


def _overwrite_stored_receipt(audit: CatalogPrivacyAudit, receipt_id: str, data: bytes) -> None:
    audit._db.execute(  # pyright: ignore[reportPrivateUsage]
        "UPDATE privacy_audit_records SET receipt_canonical = ? WHERE receipt_id = ?",
        (data, receipt_id),
    )


async def test_an_unreadable_row_is_skipped_counted_named_and_recorded(
    service: _Service, monkeypatch: pytest.MonkeyPatch
) -> None:
    stored = await _store_projections(service.audit, 60, newest=_NOW - timedelta(minutes=1))
    garbled, oversized = stored[10], stored[20]
    _overwrite_stored_receipt(service.audit, garbled.receipt_id, b"{not a receipt")
    # The shape an older build could store: a final_bytes above the published 262,144 bound.
    older = _stored_receipt_json(service.audit, oversized.receipt_id)
    older["counts"]["final_bytes"] = MAX_RECEIPT_FINAL_BYTES + 37_856
    _overwrite_stored_receipt(service.audit, oversized.receipt_id, canonical_encode(older))

    listed, pages = await _list_every_page(25)

    assert len(listed) == 58
    assert garbled.receipt_id not in listed and oversized.receipt_id not in listed
    assert sum(page.undecodable_count for page in pages) == 2
    assert [receipt_id for page in pages for receipt_id in page.undecodable_receipt_ids] == [
        garbled.receipt_id,
        oversized.receipt_id,
    ]
    # Skipped rows still advance the cursor: no page repeats or loses a readable receipt.
    assert listed == [
        receipt.receipt_id
        for receipt in sorted(stored, key=lambda item: (item.finished_at, item.receipt_id))[::-1]
        if receipt.receipt_id not in {garbled.receipt_id, oversized.receipt_id}
    ]
    from yoetz.observability.diagnostics import lookup_diagnostic_records

    records = lookup_diagnostic_records(request_id=garbled.request_id)
    assert [(record["operation"], record["reason"]) for record in records] == [
        ("privacy_receipts_list_row_skipped", "privacy_audit_local_row_undecodable")
    ]
    assert "not a receipt" not in json.dumps(records)

    code, stdout, stderr = await _cli(
        monkeypatch,
        lambda: cli_app._privacy_receipts_list(100, None, True),  # pyright: ignore[reportPrivateUsage]
    )

    document = json.loads(stdout)
    assert code == 40
    assert len(document["receipts"]) == 58
    assert document["undecodable_count"] == 2
    assert document["undecodable_receipt_ids"] == [garbled.receipt_id, oversized.receipt_id]
    assert stderr.startswith(
        "privacy_audit_unreadable: this page is partial; 2 stored receipt(s) could not be read "
        f"back and were skipped: {garbled.receipt_id}, {oversized.receipt_id}\n"
    )
    assert "Continuation: privacy_audit_review" in stderr
    assert "invalid_request" not in stderr


async def test_get_of_an_unreadable_row_names_the_store_not_the_caller(
    service: _Service, monkeypatch: pytest.MonkeyPatch
) -> None:
    stored = await _store_projections(service.audit, 2, newest=_NOW - timedelta(minutes=1))
    _overwrite_stored_receipt(service.audit, stored[0].receipt_id, b"[]")

    client = await _client()
    try:
        with pytest.raises(ControlError) as raised:
            await client.privacy_receipts_get(GetPrivacyReceiptRequest(stored[0].receipt_id))
        readable = await client.privacy_receipts_get(GetPrivacyReceiptRequest(stored[1].receipt_id))
    finally:
        await client.close()

    assert raised.value.reason == "privacy_audit_unreadable"
    assert raised.value.retryable is False
    assert raised.value.correlation_id is not None
    assert getattr(readable, "receipt").receipt == stored[1]

    code, stdout, stderr = await _cli(
        monkeypatch,
        lambda: cli_app._privacy_receipts_get(stored[0].receipt_id, True),  # pyright: ignore[reportPrivateUsage]
    )

    assert code == 40
    payload = json.loads(stdout)
    assert payload["reason"] == "privacy_audit_unreadable"
    assert payload["public_code"] == "STORAGE_CORRUPT"
    assert payload["recovery"]["continuation"] == "privacy_audit_review"
    assert stderr.startswith("privacy_audit_unreadable: the request was valid")
    assert f"correlation_id {payload['correlation_id']}" in stderr


async def test_a_malformed_cursor_is_still_the_callers_invalid_request(service: _Service) -> None:
    await _store_projections(service.audit, 3, newest=_NOW - timedelta(minutes=1))
    client = await _client()
    try:
        first = await client.privacy_receipts_list(ListPrivacyReceiptsRequest(page_size=1))
        assert first.next_cursor is not None
        forged = first.next_cursor[:-4] + ("AAAA" if first.next_cursor[-4:] != "AAAA" else "BBBB")
        with pytest.raises(ControlError) as raised:
            await client.privacy_receipts_list(
                ListPrivacyReceiptsRequest(page_size=1, cursor=forged)
            )
        with pytest.raises(ControlError) as other_query:
            await client.privacy_receipts_list(
                ListPrivacyReceiptsRequest(
                    PrivacyReceiptFilters(sink=LocalDisclosureSink.AGENT_CONTEXT),
                    page_size=1,
                    cursor=first.next_cursor,
                )
            )
    finally:
        await client.close()

    assert raised.value.reason == "invalid_request"
    assert other_query.value.reason == "invalid_request"
