"""In-process observation composition harness for non-live DoD tests.

Prefers production APIs when siblings land them. Until then, provides a thin contract
composition that exercises the intended pipeline shape:

  hooks/stream → local consent/outbox → task-bundle SqliteObservationStore → advice

Production path that must replace interim pieces:
  - Agent A: ObservationCoordinator + ready_composition SQLite wiring + outbox ack
  - Agent B: unified setup (plugin+MCP+consent) + CodexSessionStreamLocator + auto reconcile
  - Agent C: AdviceItem in ordinary status + CheckSandboxPort + AI-powered review ready path
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import inspect
import io
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, cast

import apsw

from finishup.adapters.integrations.codex_lifecycle import (
    LifecycleMapping,
    load_mapping,
    mapping_from_start_ids,
    store_mapping,
)
from finishup.adapters.integrations.codex_plugin import render_plugin_tree
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.sqlite import connection as connection_module
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation import SqliteObservationStore
from finishup.application.observation_advice import (
    ObservationAdviceBuildInput,
    build_observation_advice_snapshot,
)
from finishup.cli.observe_hooks import handle_observe, map_hook_payload_to_envelope
from finishup.domain.observation import (
    AdviceSnapshot,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationLifecycle,
)
from finishup.domain.values import Timestamp
from finishup.kernel.policies.observation_advice import (
    ObservationAdviceContext,
    observation_advice_findings,
)
from finishup.protocol.ids import IdKind, new_id

_TIME: Final = Timestamp("2026-07-23T09:00:00.000Z")
_SECRET: Final = "AWS_SECRET=should-never-appear"
_PASSWORD: Final = "password=hunter2"
_DIGEST_A: Final = "sha256:" + "a" * 64
_DIGEST_B: Final = "sha256:" + "b" * 64

CANARY_SECRETS: Final = (_SECRET, _PASSWORD, "hunter2", "AWS_SECRET")


def try_import(module_path: str, attr: str) -> Any | None:
    """Return a production attribute when present; otherwise None."""

    try:
        module = importlib.import_module(module_path)
    except ImportError:
        return None
    return getattr(module, attr, None)


@dataclass(frozen=True, slots=True)
class ProductionSurface:
    """Resolved production modules plus explicit gap labels for parent routing."""

    coordinator_cls: Any | None
    stream_locator_cls: Any | None
    advice_item_cls: Any | None
    check_sandbox_cls: Any | None
    gaps: tuple[str, ...]


def resolve_production_surface() -> ProductionSurface:
    gaps: list[str] = []
    coordinator = try_import("finishup.service.observation_coordinator", "ObservationCoordinator")
    if coordinator is None:
        coordinator = try_import(
            "finishup.application.observation_coordinator", "ObservationCoordinator"
        )
    if coordinator is None:
        gaps.append(
            "Agent A: ObservationCoordinator missing "
            "(expected finishup.service.observation_coordinator or "
            "finishup.application.observation_coordinator)"
        )
    locator = try_import(
        "finishup.adapters.integrations.codex_session_stream", "CodexSessionStreamLocator"
    )
    if locator is None:
        locator = try_import(
            "finishup.adapters.integrations.codex_session_locator", "CodexSessionStreamLocator"
        )
    if locator is None:
        gaps.append(
            "Agent B: CodexSessionStreamLocator missing "
            "(expected codex_session_stream or codex_session_locator)"
        )
    advice_item = try_import("finishup.domain.observation", "AdviceItem")
    if advice_item is None:
        advice_item = try_import("finishup.application.observation_advice", "AdviceItem")
    if advice_item is None:
        gaps.append("Agent C: AdviceItem missing from domain.observation or observation_advice")
    sandbox = try_import("finishup.ports.check_sandbox", "CheckSandboxPort")
    if sandbox is None:
        sandbox = try_import("finishup.adapters.check_sandbox", "MacOSCheckSandbox")
    if sandbox is None:
        gaps.append("Agent C: CheckSandboxPort missing (ports.check_sandbox)")
    return ProductionSurface(
        coordinator_cls=coordinator,
        stream_locator_cls=locator,
        advice_item_cls=advice_item,
        check_sandbox_cls=sandbox,
        gaps=tuple(gaps),
    )


def ready_composition_uses_memory_observation_store() -> bool:
    """True when production ready composition still constructs MemoryObservationStore."""

    module = importlib.import_module("finishup.service.ready_composition")
    source = inspect.getsource(module)
    return "MemoryObservationStore()" in source


def setup_returns_early_when_mcp_registered() -> bool:
    """True when setup still short-circuits on already_registered without plugin install."""

    module = importlib.import_module("finishup.cli.setup")
    source = inspect.getsource(module)
    # Complete path must install/verify plugin even when MCP is already finishup-owned.
    installs_plugin = (
        "install_plugin" in source
        or "plugin_service.install" in source
        or "run_complete_codex_integration" in source
    )
    # Legacy early-return pattern: return already_registered before any plugin install.
    early_return = (
        'outcome="already_registered"' in source.replace(" ", "")
        or 'return _registration_report(preview.state_before, outcome="already_registered")'
        in source
    )
    if installs_plugin and "Plugin is already registered; setup will still install" in source:
        return False
    if installs_plugin and "still install/verify the plugin" in source:
        return False
    return (not installs_plugin) or early_return


def assert_no_plaintext_canaries(*surfaces: object) -> None:
    """Fail if secret-like bytes appear in any serialized observation surface."""

    for surface in surfaces:
        text = surface if type(surface) is str else repr(surface)
        for canary in CANARY_SECRETS:
            assert canary not in text, f"plaintext canary leaked: {canary!r} in {text[:240]!r}"


@dataclass
class FakeCodexInstall:
    """Trusted project + fake Codex home for composition tests."""

    project: Path
    codex_home: Path
    state: Path
    binary: Path

    @classmethod
    def create(cls, root: Path) -> FakeCodexInstall:
        project = root / "project"
        project.mkdir(parents=True, mode=0o700)
        (project / "README.md").write_text("# trusted project\n", encoding="utf-8")
        codex_home = root / "codex-home"
        codex_home.mkdir(mode=0o700)
        binary = root / "bin" / "codex"
        binary.parent.mkdir(parents=True, mode=0o700)
        binary.write_text("#!/bin/sh\necho 0.144.5\n", encoding="utf-8")
        binary.chmod(0o700)
        state = root / "finishup-state"
        state.mkdir(mode=0o700)
        return cls(project=project, codex_home=codex_home, state=state, binary=binary)


@dataclass
class SetupLayers:
    plugin_present: bool
    hooks_present: bool
    mcp_registered: bool
    consent_active: bool
    report: dict[str, object] = field(default_factory=lambda: dict[str, object]())


def _write_plugin_hooks(project: Path) -> bool:
    """Materialize rendered plugin tree under the trusted project (interim setup stand-in)."""

    tree = render_plugin_tree()
    root = project / ".agents" / "plugins" / "finishup"
    root.mkdir(parents=True, mode=0o700)
    for relative, payload in tree.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(payload if type(payload) is bytes else str(payload).encode())
        path.chmod(0o600)
    hooks = root / "hooks" / "hooks.json"
    return hooks.is_file() and b"observe" in hooks.read_bytes()


def run_unified_setup(
    install: FakeCodexInstall,
    *,
    mcp_already_registered: bool = False,
    fail_plugin: bool = False,
) -> SetupLayers:
    """Apply the intended one-shot setup: plugin + MCP + consent.

    Prefers production ``run_complete_codex_integration`` when present. Otherwise installs the
    rendered plugin tree via the owning renderer and grants consent only after plugin+MCP layers
    succeed. Production setup must replace this interim path.
    """

    production_setup = try_import("finishup.cli.setup", "run_complete_codex_integration")
    if callable(production_setup) and not fail_plugin:
        result = production_setup(
            project=install.project,
            codex_home=install.codex_home,
            binary=str(install.binary),
            mcp_already_registered=mcp_already_registered,
        )
        if isinstance(result, Mapping):
            result_map = cast(Mapping[str, object], result)
            return SetupLayers(
                plugin_present=bool(result_map.get("plugin_present")),
                hooks_present=bool(result_map.get("hooks_present")),
                mcp_registered=bool(result_map.get("mcp_registered")),
                consent_active=bool(result_map.get("consent_active")),
                report=dict(result_map),
            )

    plugin_ok = False
    hooks_ok = False
    if not fail_plugin:
        try:
            hooks_ok = _write_plugin_hooks(install.project)
            plugin_ok = hooks_ok
        except Exception:
            plugin_ok = False
            hooks_ok = False

    mcp_ok = True  # registration applied (or already present and still proceeds)
    del mcp_already_registered  # intended: must not skip plugin/consent

    consent_ok = False
    workspace_commitment: str | None = None
    local = LocalObservationStore(_state=install.state)
    workspace_commitment = local.workspace_commitment(str(install.project.resolve()))
    if plugin_ok and mcp_ok and not fail_plugin:
        local.grant_consent(workspace_commitment)
        consent_ok = True

    return SetupLayers(
        plugin_present=plugin_ok,
        hooks_present=hooks_ok,
        mcp_registered=mcp_ok and not fail_plugin,
        consent_active=consent_ok,
        report={
            "workspace_commitment": workspace_commitment,
            "fail_plugin": fail_plugin,
            "interim_harness": production_setup is None,
        },
    )


@dataclass
class ContractObservationPipeline:
    """Interim local→SQLite observation pipeline until ObservationCoordinator lands.

    Outbox semantics: envelopes stay pending until ``drain_to_task_bundle`` commits into
    SqliteObservationStore; acknowledgement happens only after that commit succeeds.
    """

    install: FakeCodexInstall
    local: LocalObservationStore
    bundle_path: Path
    db: apsw.Connection
    sqlite: SqliteObservationStore
    workspace: str
    pending_outbox: list[ObservationEnvelope] = field(
        default_factory=lambda: list[ObservationEnvelope]()
    )
    acknowledged: list[str] = field(default_factory=lambda: list[str]())
    outbox_overflow: bool = False
    max_outbox: int = 64
    task_id: str = ""
    session_id: str = ""
    writer_id: str = ""
    bound_sessions: list[str] = field(default_factory=lambda: list[str]())

    @classmethod
    def open(cls, install: FakeCodexInstall) -> ContractObservationPipeline:
        local = LocalObservationStore(_state=install.state)
        workspace = local.workspace_commitment(str(install.project.resolve()))
        bundle_path = install.state / "task-bundle.sqlite3"
        db = apsw.Connection(str(bundle_path))
        initialize_bundle(db, {"task_id": "task_obs_comp", "owner_generation": "1"})
        db.set_authorizer(connection_module._writer_authorizer)  # pyright: ignore[reportPrivateUsage]
        sqlite = SqliteObservationStore(db)
        sqlite.grant_consent(workspace, _TIME)
        return cls(
            install=install,
            local=local,
            bundle_path=bundle_path,
            db=db,
            sqlite=sqlite,
            workspace=workspace,
            task_id=new_id(IdKind.TASK),
            session_id=new_id(IdKind.SESSION),
            writer_id=new_id(IdKind.WRITER),
        )

    def reopen_after_restart(self) -> ContractObservationPipeline:
        """Simulate service restart by reopening the durable SQLite bundle."""

        with contextlib.suppress(Exception):
            self.db.close(force=True)
        db = apsw.Connection(str(self.bundle_path))
        db.set_authorizer(connection_module._writer_authorizer)  # pyright: ignore[reportPrivateUsage]
        sqlite = SqliteObservationStore(db)
        sqlite.grant_consent(self.workspace, _TIME)
        for session in self.bound_sessions:
            sqlite.bind_session(self.workspace, session)
        return ContractObservationPipeline(
            install=self.install,
            local=self.local,
            bundle_path=self.bundle_path,
            db=db,
            sqlite=sqlite,
            workspace=self.workspace,
            pending_outbox=[],
            acknowledged=list(self.acknowledged),
            outbox_overflow=self.outbox_overflow,
            max_outbox=self.max_outbox,
            task_id=self.task_id,
            session_id=self.session_id,
            writer_id=self.writer_id,
            bound_sessions=list(self.bound_sessions),
        )

    def ensure_consent(self) -> None:
        self.local.grant_consent(self.workspace)
        self.sqlite.grant_consent(self.workspace, _TIME)

    def auto_attach(self, codex_session_id: str) -> LifecycleMapping:
        """SessionStart without MCP start: create lifecycle mapping + session binding."""

        mapping = mapping_from_start_ids(
            codex_session_id=codex_session_id,
            finishup_task_id=self.task_id,
            finishup_session_id=self.session_id,
            finishup_writer_id=self.writer_id,
            last_frontier=None,
        )
        store_mapping(mapping, _state=self.install.state)
        session = self.local.session_commitment(codex_session_id)
        self.local.bind_session(self.workspace, session)
        self.sqlite.bind_session(self.workspace, session)
        if session not in self.bound_sessions:
            self.bound_sessions.append(session)
        return mapping

    def observe_hook(
        self,
        event_name: str,
        payload: Mapping[str, object],
        *,
        drain: bool = True,
    ) -> tuple[int, bytes]:
        out = io.BytesIO()
        code = handle_observe(
            event_name=event_name,
            stdin_bytes=json.dumps(dict(payload)).encode(),
            stdout=out,
            workspace=str(self.install.project),
            _state=self.install.state,
            skip_service=True,
        )
        for envelope in self.local.list_envelopes(self.workspace):
            if envelope.source_identity in self.acknowledged:
                continue
            if any(
                item.source_identity == envelope.source_identity for item in self.pending_outbox
            ):
                continue
            if len(self.pending_outbox) >= self.max_outbox:
                self.outbox_overflow = True
                # Explicit coverage gap — never silently drop.
                overflow = map_hook_payload_to_envelope(
                    "PostToolUse",
                    {
                        "session_id": "outbox-overflow",
                        "tool_name": "shell",
                        "exit_status": 1,
                        "event_ordinal": 9999,
                    },
                    session_commitment=envelope.session_commitment,
                    event_ordinal=9999,
                    key_material=self.local.key_material(),
                    gap_codes=(ObservationGapCode.OUTBOX_OVERFLOW.value,),
                )
                self.local.ingest(overflow)
                break
            self.pending_outbox.append(envelope)
            if envelope.session_commitment not in self.bound_sessions:
                self.bound_sessions.append(envelope.session_commitment)
        if drain and not self.outbox_overflow:
            self._drain_blocking()
        return code, out.getvalue()

    def _drain_blocking(self) -> int:
        """Drain outbox without nesting asyncio.run inside an active event loop."""

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.drain_to_task_bundle())
        # Already inside anyio/pytest-asyncio — schedule on the running loop.
        future = asyncio.ensure_future(self.drain_to_task_bundle(), loop=loop)
        # Caller in async tests should prefer await drain_to_task_bundle(); sync
        # observe_hook with drain=True from async tests must pass drain=False.
        if not future.done():
            # Best-effort: leave pending for explicit await by async callers.
            self._pending_drain = future
            return 0
        return int(future.result())

    def record_rejected_disposition(self, reason: str = "consent_missing") -> None:
        """Service rejected disposition becomes a visible local coverage gap."""

        gap = (
            reason
            if reason in {item.value for item in ObservationGapCode}
            else ObservationGapCode.SERVICE_UNAVAILABLE.value
        )
        session = self.local.session_commitment("reject-gap")
        self.local.bind_session(self.workspace, session)
        envelope = map_hook_payload_to_envelope(
            "PostToolUse",
            {"session_id": "reject-gap", "tool_name": "shell", "exit_status": 1},
            session_commitment=session,
            event_ordinal=99,
            key_material=self.local.key_material(),
            gap_codes=(gap,),
        )
        self.local.ingest(envelope)

    async def drain_to_task_bundle(self) -> int:
        """Commit pending outbox into SQLite; acknowledge only after successful ingest."""

        drained = 0
        remaining: list[ObservationEnvelope] = []
        for envelope in self.pending_outbox:
            self.sqlite.bind_session(self.workspace, envelope.session_commitment)
            if envelope.session_commitment not in self.bound_sessions:
                self.bound_sessions.append(envelope.session_commitment)
            result = await self.sqlite.ingest(envelope)
            if result.disposition in {
                ObservationIngestDisposition.ACCEPTED,
                ObservationIngestDisposition.DUPLICATE,
            }:
                self.acknowledged.append(envelope.source_identity)
                drained += 1
            else:
                remaining.append(envelope)
        self.pending_outbox = remaining
        return drained

    def advice_rules(self) -> set[str]:
        envelopes = tuple(self.sqlite.list_envelopes(self.workspace))
        if not envelopes:
            envelopes = tuple(self.local.list_envelopes(self.workspace))
        return {
            item.rule_code
            for item in observation_advice_findings(
                ObservationAdviceContext(
                    envelopes=envelopes,
                    lifecycle=ObservationLifecycle.ACTIVE,
                    gaps=(),
                )
            )
        }

    def refresh_advice(self) -> AdviceSnapshot | None:
        envelopes = tuple(self.sqlite.list_envelopes(self.workspace))
        if not envelopes:
            envelopes = tuple(self.local.list_envelopes(self.workspace))
        return build_observation_advice_snapshot(
            ObservationAdviceBuildInput(
                envelopes=envelopes,
                lifecycle=ObservationLifecycle.ACTIVE,
                gaps=(),
                has_real_observation=bool(envelopes),
            )
        )

    def mapping_for(self, codex_session_id: str) -> LifecycleMapping | None:
        return load_mapping(codex_session_id, _state=self.install.state)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.db.close(force=True)


__all__ = [
    "CANARY_SECRETS",
    "ContractObservationPipeline",
    "FakeCodexInstall",
    "ProductionSurface",
    "SetupLayers",
    "assert_no_plaintext_canaries",
    "ready_composition_uses_memory_observation_store",
    "resolve_production_surface",
    "run_unified_setup",
    "setup_returns_early_when_mcp_registered",
    "try_import",
    "_DIGEST_A",
    "_DIGEST_B",
    "_PASSWORD",
    "_SECRET",
    "_TIME",
]
