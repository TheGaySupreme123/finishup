"""Isolated production composition for the named multi-agent conformance scenarios.

The vault, catalog, encrypted objects, task ledgers and runtime routing are real. Only the
clock and singleton generation store are deterministic; no user service or user data is used.
"""

from __future__ import annotations

import inspect
import shutil
import tempfile
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from finishup.adapters.keys.encrypted_vault import EncryptedVaultStore
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.application.service import Application
from finishup.config.models import FinishUpConfig
from finishup.ports.control import ServiceState
from finishup.ports.diagnostics import StartupCheckResult
from finishup.ports.secret_memory import SecretPurpose
from finishup.service.lifecycle import ServiceLifecycle
from finishup.service.ready_composition import build_ready_application_factory
from finishup.service.vault import VaultMode, VaultService

INSTALLATION_ID = "ins_58000000-0000-4000-8000-000000000001"
INSTANCE_ID = "svc_58000000-0000-4000-8000-000000000001"
_PASSPHRASE = b"synthetic conformance vault only"


@dataclass
class ScenarioClock:
    instant: datetime = datetime(2026, 9, 5, 12, tzinfo=UTC)
    elapsed: float = 1.0

    def now_utc(self) -> datetime:
        return self.instant

    def monotonic_seconds(self) -> float:
        return self.elapsed

    def advance(self, *, seconds: int) -> None:
        self.instant += timedelta(seconds=seconds)
        self.elapsed += seconds


class _Generations:
    def __init__(self) -> None:
        self.current = 0

    def advance(self, instance_id: str) -> int:
        assert instance_id == INSTANCE_ID
        self.current += 1
        return self.current


@dataclass(frozen=True)
class _Paths:
    bundle: Path

    @property
    def state(self) -> Path:
        return self.bundle / "state"


class _Diagnostics:
    def record(self, result: StartupCheckResult) -> None:
        assert isinstance(result, StartupCheckResult)


def _empty_retired_memories() -> list[LocalSecretMemory]:
    return []


async def _close_all(resources: tuple[Callable[[], object], ...]) -> None:
    """Attempt every owned close in order, then propagate the first failure."""

    failures: list[BaseException] = []
    for close in resources:
        try:
            result = close()
            if inspect.isawaitable(result):
                await cast(Awaitable[object], result)
        except BaseException as exc:
            failures.append(exc)
    if failures:
        raise failures[0]


@dataclass
class MultiAgentService:
    app: Application
    clock: ScenarioClock
    vault: VaultService
    lifecycle: ServiceLifecycle
    root: Path
    memory: LocalSecretMemory
    config: FinishUpConfig
    retired_memories: list[LocalSecretMemory] = field(
        default_factory=_empty_retired_memories, repr=False
    )


@contextmanager
def private_service_root() -> Generator[Path]:
    """Yield a short owner-only service root outside shared pytest temp space.

    Linux CI places ``tmp_path`` below shared ``/tmp``, which production validation rejects.
    Keep the synthetic vault/catalog/state tree in a namespaced home-cache directory instead.
    """

    base = (Path.home() / ".cache" / "finishup-conformance").resolve()
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    base.chmod(0o700)
    root = Path(tempfile.mkdtemp(prefix="yz-", dir=base))
    root.chmod(0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=False)


@asynccontextmanager
async def multi_agent_service(
    root: Path, *, config: FinishUpConfig | None = None
) -> AsyncGenerator[MultiAgentService]:
    del root  # callers retain pytest labels; private service data cannot live below shared /tmp.
    with private_service_root() as root:
        clock = ScenarioClock()
        memory = LocalSecretMemory()
        lifecycle = ServiceLifecycle(
            clock,
            generation_store=_Generations(),
            process_start_identity_commitment="sha256:" + "a" * 64,
            instance_id=INSTANCE_ID,
            singleton_lock_path=root / "service.lock",
        )
        vault: VaultService | None = None
        app: Application | None = None
        service: MultiAgentService | None = None
        try:
            await lifecycle.acquire_singleton()
            await lifecycle.transition(ServiceState.LOCKED)
            vault = VaultService(
                installation_id=INSTALLATION_ID,
                service_generation=1,
                mode=VaultMode.UNINITIALIZED,
                secret_memory=memory,
                clock=clock,
                vault_store_factory=lambda: EncryptedVaultStore(root / "vault"),
                pristine_state_digest="sha256:" + "b" * 64,
            )
            selected_config = config or FinishUpConfig()
            initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(_PASSPHRASE))
            await vault.initialize_passphrase(initialize, "sha256:" + "c" * 64)
            assert vault is not None
            factory = build_ready_application_factory(
                lifecycle=lifecycle,
                vault=vault,
                config=selected_config,
                paths=_Paths(root),
                clock=clock,
                secret_memory=memory,
                diagnostics=_Diagnostics(),
            )
            app = await factory(1, vault.generation)
            service = MultiAgentService(app, clock, vault, lifecycle, root, memory, selected_config)
            yield service
        finally:
            # Tests may replace ``service.app`` while exercising a relock/reopen.  Close the
            # current yielded application so its runtime entries (and importer writer threads)
            # cannot outlive the private installation; retain the captured app as the setup-failure
            # fallback before the service wrapper exists.
            current_app = service.app if service is not None else app
            memories = (
                (*service.retired_memories, service.memory) if service is not None else (memory,)
            )
            resources: list[Callable[[], object]] = []
            if current_app is not None:
                resources.append(current_app.close)
            if vault is not None:
                resources.append(vault.close)
            resources.extend(retained.close for retained in memories)
            resources.append(lifecycle.close)
            await _close_all(tuple(resources))


async def relock_and_reopen_multi_agent_service(service: MultiAgentService) -> None:
    """Recompose READY around the same encrypted fixture installation."""

    await service.app.close()
    await service.vault.lock()
    service.retired_memories.append(service.memory)
    memory = LocalSecretMemory()
    try:
        await service.vault.unlock(
            memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(_PASSPHRASE))
        )
        factory = build_ready_application_factory(
            lifecycle=service.lifecycle,
            vault=service.vault,
            config=service.config,
            paths=_Paths(service.root),
            clock=service.clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        service.app = await factory(1, service.vault.generation)
        service.memory = memory
    except BaseException:
        memory.close()
        raise
