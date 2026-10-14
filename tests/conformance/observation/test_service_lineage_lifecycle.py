"""Fresh and restart lifecycle checks for live multi-agent state.

The existing lineage scenarios exercise one ready composition.  These rows deliberately close
and reopen that composition around durable parent, child, and sibling state so the public
selectors, pending delegation operation, task cursors, and receipt dependencies are checked
against a new service generation.
"""

from __future__ import annotations

import subprocess
from collections.abc import AsyncGenerator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

import yoetz.application.start as start_module
from builders.multi_agent import ScenarioClock, private_service_root
from yoetz.adapters.keys.encrypted_vault import EncryptedVaultStore
from yoetz.adapters.keys.secret_memory import LocalSecretMemory
from yoetz.adapters.keys.vault_passphrase import VaultRootEnvelope
from yoetz.application.service import Application
from yoetz.application.status import StatusInternalResult
from yoetz.config.models import YoetzConfig
from yoetz.domain.coordination import WorkState
from yoetz.ports.control import RepositoryPrivacyContext, ServiceState
from yoetz.ports.ledger import CheckCommitResult
from yoetz.ports.secret_memory import SecretPurpose
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    StartRequest,
    StatusLineagePageModel,
    StatusRequest,
)
from yoetz.service.lifecycle import ServiceLifecycle
from yoetz.service.ready_composition import build_ready_application_factory
from yoetz.service.vault import VaultMode, VaultService

pytestmark = pytest.mark.anyio

_INSTALLATION_ID = "ins_59000000-0000-4000-8000-000000000001"
_INSTANCE_ID = "svc_59000000-0000-4000-8000-000000000002"
_PASSPHRASE = b"synthetic lifecycle conformance vault"
_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Generations:
    def __init__(self) -> None:
        self.current = 0

    def advance(self, instance_id: str) -> int:
        assert instance_id == _INSTANCE_ID
        self.current += 1
        return self.current


@dataclass(frozen=True)
class _Paths:
    bundle: Path

    @property
    def state(self) -> Path:
        return self.bundle / "state"


class _Diagnostics:
    def record(self, result: object) -> None:
        del result


@dataclass
class _Running:
    app: Application
    clock: ScenarioClock
    lifecycle: ServiceLifecycle
    vault: VaultService
    memory: LocalSecretMemory
    generation: int


class _RestartableReadyInstallation:
    """One isolated installation that can create a second real READY composition."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.clock = ScenarioClock()
        self.generations = _Generations()
        self.running: _Running | None = None
        self._root_envelope: VaultRootEnvelope | None = None

    async def open(self) -> _Running:
        if self.running is not None:
            raise AssertionError("ready installation already open")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root.chmod(0o700)
        memory = LocalSecretMemory()
        lifecycle = ServiceLifecycle(
            self.clock,
            generation_store=self.generations,
            process_start_identity_commitment="sha256:" + "a" * 64,
            instance_id=_INSTANCE_ID,
            singleton_lock_path=self.root / "service.lock",
        )
        await lifecycle.acquire_singleton()
        await lifecycle.transition(ServiceState.LOCKED)
        if self._root_envelope is None:
            vault = VaultService(
                installation_id=_INSTALLATION_ID,
                service_generation=1,
                mode=VaultMode.UNINITIALIZED,
                secret_memory=memory,
                clock=self.clock,
                vault_store_factory=lambda: EncryptedVaultStore(self.root / "vault"),
                pristine_state_digest="sha256:" + "b" * 64,
            )
            await vault.initialize_passphrase(
                memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(_PASSPHRASE)),
                "sha256:" + "c" * 64,
            )
            self._root_envelope = cast(VaultRootEnvelope, getattr(vault, "_root_envelope"))
        else:
            vault = VaultService(
                installation_id=_INSTALLATION_ID,
                service_generation=lifecycle.instance.generation,
                mode=VaultMode.PASSPHRASE,
                secret_memory=memory,
                clock=self.clock,
                vault_store_factory=lambda: EncryptedVaultStore(self.root / "vault"),
                root_envelope=self._root_envelope,
            )
            await vault.unlock(memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(_PASSPHRASE)))
        service_generation = lifecycle.instance.generation
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=YoetzConfig(),
            paths=_Paths(self.root),
            clock=self.clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await factory(service_generation, vault.generation)
        await lifecycle.transition(ServiceState.UNLOCKING)
        await lifecycle.transition(ServiceState.READY, vault_generation=vault.generation)
        self.running = _Running(app, self.clock, lifecycle, vault, memory, service_generation)
        return self.running

    async def close(self) -> None:
        current = self.running
        if current is None:
            return
        self._root_envelope = cast(VaultRootEnvelope, getattr(current.vault, "_root_envelope"))
        self.running = None
        await current.app.close()
        await current.vault.close()
        current.memory.close()
        await current.lifecycle.close()

    async def restart(self) -> _Running:
        await self.close()
        return await self.open()


@asynccontextmanager
async def _installation(root: Path) -> AsyncGenerator[_RestartableReadyInstallation]:
    del root  # pytest's basetemp is shared /tmp; the synthetic installation needs a private root.
    with private_service_root() as private_root:
        installation = _RestartableReadyInstallation(private_root)
        await installation.open()
        try:
            yield installation
        finally:
            await installation.close()


def _identity(actor: str = "harness:lifecycle") -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": actor, "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _workspace(root: Path) -> Path:
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
    return root.resolve()


async def _status(
    app: Application,
    task: object,
    *,
    view: str = "compact",
    limit: str = "10",
) -> StatusInternalResult:
    result = await app.status(
        StatusRequest.model_validate(
            {
                **_identity(),
                "session_id": getattr(task, "session_id"),
                "writer_id": getattr(task, "writer_id"),
                "view": view,
                "limit": limit,
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, StatusInternalResult)
    return result


def _frontier(value: object) -> Mapping[str, object]:
    as_wire = getattr(value, "as_wire", None)
    if callable(as_wire):
        return dict(cast(Mapping[str, object], as_wire()).items())
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return cast(Mapping[str, object], model_dump(mode="json"))
    raise AssertionError("frontier is not serializable")


async def _publish(
    app: Application,
    task: object,
    drafts: Sequence[Mapping[str, object]],
) -> object:
    status = await _status(app, task)
    result = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": getattr(task, "session_id"),
                "writer_id": getattr(task, "writer_id"),
                "expected_frontier": _frontier(getattr(status, "head_frontier")),
                "event_drafts": tuple(dict(draft) for draft in drafts),
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    return result


async def _check(app: Application, task: object) -> CheckCommitResult:
    status = await _status(app, task)
    result = await app.check(
        CheckRequest.model_validate(
            {
                **_identity(),
                "session_id": getattr(task, "session_id"),
                "writer_id": getattr(task, "writer_id"),
                "expected_frontier": _frontier(getattr(status, "head_frontier")),
                "mode": "deterministic_only",
                "max_findings": "10",
                "policy_packs": ["research-evidence/0.2.0", "work-integrity/0.3.0"],
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, CheckCommitResult)
    return result


async def _receipt(
    app: Application,
    task: object,
    checked: CheckCommitResult,
    *,
    request_id: str | None = None,
) -> object:
    identity = _identity()
    if request_id is not None:
        identity["request_id"] = request_id
    return await app.receipt(
        ReceiptRequest.model_validate(
            {
                **identity,
                "task_id": getattr(task, "task_id"),
                "session_id": getattr(task, "session_id"),
                "writer_id": getattr(task, "writer_id"),
                "expected_frontier": _frontier(checked.result_frontier),
                "format": "json",
                "include": "standard",
                "redaction_profile": "default_local_export",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def test_fresh_ready_service_preserves_siblings_and_lineage_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new READY generation keeps public task selectors and recorded child dependencies."""

    workspace = _workspace(tmp_path / "workspace")
    async with _installation(tmp_path / "installation") as installation:
        first = cast(_Running, installation.running)
        parent = await first.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Lifecycle parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "lifecycle-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        sibling = await first.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Lifecycle sibling",
                    "workspace_ref": str(workspace),
                    "external_ref": "lifecycle-sibling",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert parent.task_id != sibling.task_id
        sibling_check = await _check(first.app, sibling)
        sibling_receipt_id = new_id(IdKind.REQUEST)
        sibling_receipt = await _receipt(
            first.app,
            sibling,
            sibling_check,
            request_id=sibling_receipt_id,
        )

        request = StartRequest.model_validate(
            {
                **_identity(),
                "mode": "delegate",
                "task_title": "Lifecycle child",
                "session_id": parent.session_id,
                "requested_view": "compact",
            }
        )
        original = start_module._append_delegation_event  # pyright: ignore[reportPrivateUsage]

        async def fail_after_child_bundle(_app: object, _operation: object) -> None:
            raise RuntimeError("simulated_restart_after_child_bundle")

        monkeypatch.setattr(start_module, "_append_delegation_event", fail_after_child_bundle)
        with pytest.raises(RuntimeError, match="simulated_restart_after_child_bundle"):
            await first.app.start(request, repository_privacy_context=_REPOSITORY)
        monkeypatch.setattr(start_module, "_append_delegation_event", original)

        lineage = first.app.lineage
        assert lineage is not None
        pending = await lineage.store.get_operation(request.request_id)
        assert pending is not None
        assert pending.state.value == "pending"
        assert pending.child_task_id is not None
        pending_child_id = pending.child_task_id

        before = await _status(first.app, parent, view="lineage")
        assert isinstance(before.page, StatusLineagePageModel)
        assert before.task_id == parent.task_id
        assert before.page.parent_task_id is None

        second = await installation.restart()
        assert second.generation == first.generation + 1
        await second.app.recover_lineage()
        reopened_lineage = second.app.lineage
        assert reopened_lineage is not None
        recovered = await reopened_lineage.store.get_operation(request.request_id)
        assert recovered is not None
        assert recovered.state.value == "complete"

        replay = await second.app.start(request, repository_privacy_context=_REPOSITORY)
        assert replay.task_id == pending_child_id
        handle = await reopened_lineage.store.get_handle(recovered.handle_digest)
        assert handle is not None
        attached = await second.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "attach",
                    "task_title": "Lifecycle child",
                    "attach_handle": {
                        "handle": handle.value,
                        "child_task_id": handle.task_id,
                        "expires_at": handle.expires_at.isoformat(timespec="milliseconds").replace(
                            "+00:00", "Z"
                        ),
                    },
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert attached.task_id == pending_child_id
        replay = attached

        # The parent and both independent task sessions remain valid selectors in the new
        # generation, and the child relationship is still visible through the public lineage view.
        parent_after = await _status(second.app, parent, view="lineage")
        sibling_after = await _status(second.app, sibling)
        child_after = await _status(second.app, replay)
        assert parent_after.task_id == parent.task_id
        assert sibling_after.task_id == sibling.task_id
        assert child_after.task_id == replay.task_id
        assert isinstance(parent_after.page, StatusLineagePageModel)
        assert tuple(item.task_id for item in parent_after.page.children) == (replay.task_id,)
        assert parent_after.page.children[0].work_state == WorkState.OPEN.value

        child_closed = await _publish(
            second.app,
            replay,
            (
                {
                    "event_id": new_id(IdKind.EVENT),
                    "schema": {"name": "work_closed", "version": "1.0.0"},
                    "occurred_at": "2026-09-05T12:00:00.000Z",
                    "causal_parents": [],
                    "payload": {},
                    "artifact_refs": [],
                    "evidence_refs": [],
                },
            ),
        )
        assert getattr(child_closed, "task_id") == replay.task_id
        child_check = await _check(second.app, replay)
        await _receipt(second.app, replay, child_check)
        assert second.app.observation_sweep is not None
        await second.app.observation_sweep()
        parent_check = await _check(second.app, parent)
        parent_receipt = await _receipt(second.app, parent, parent_check)
        assert getattr(parent_receipt, "document") is not None
        assert getattr(parent_receipt, "task_id") == parent.task_id

        # A sibling receipt minted before restart remains byte-identical when requested through
        # the old session/writer selector after restart.
        sibling_replayed = await _receipt(
            second.app,
            sibling,
            sibling_check,
            request_id=sibling_receipt_id,
        )
        assert getattr(sibling_replayed, "receipt_digest") == getattr(
            sibling_receipt, "receipt_digest"
        )
