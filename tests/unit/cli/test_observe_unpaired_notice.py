"""The sticky ``unpaired_event`` record stays disclosed without a recurring advisory (#917).

Real Codex hook ingress records a paired-profile orphan post. The durable gap
stays on status after drain and after a restart, the ``refresh_observation``
advisory is reserved for conditions that can recover in session, and the orphan
record remains operator-visible without entering hook context (#974).
"""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path
from typing import Any, cast

import pytest

from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.application.observation_drain import ObservationOutboxSweeper
from yoetz.cli import observe_hooks
from yoetz.domain.observation import (
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationLifecycle,
    ObservationSource,
    ObservationStatusQuery,
)
from yoetz.kernel.policies.observation_advice import (
    ObservationAdviceContext,
    observation_advice_findings,
)
from yoetz.protocol.canonical import canonical_encode

HOST = "019f9b27-orphan-scope-host"


class _Cell:
    def __init__(self, tmp_path: Path) -> None:
        self.workspace = tmp_path / "workspace"
        self.workspace.mkdir()
        self.root = tmp_path / "isolated"
        store = LocalObservationStore(_state=self.root)
        self.commitment = store.workspace_commitment(str(self.workspace.resolve()))
        store.grant_consent(self.commitment)
        self.session = store.bind_codex_session(self.commitment, HOST)

    def store(self) -> LocalObservationStore:
        # Every hook is its own process; a fresh store object is also a restart.
        return LocalObservationStore(_state=self.root)

    def hook(self, event: str, **fields: Any) -> str:
        out = io.BytesIO()
        payload: dict[str, Any] = {
            "cwd": str(self.workspace),
            "hook_event_name": event,
            "session_id": HOST,
            **fields,
        }
        assert (
            observe_hooks.handle_observe(
                event_name=event,
                stdin_bytes=canonical_encode(payload),
                stdout=out,
                workspace=str(self.workspace),
                _state=self.root,
                skip_service=True,
            )
            == 0
        )
        body = cast(dict[str, Any], json.loads(out.getvalue() or b"{}"))
        output = cast(dict[str, Any], body.get("hookSpecificOutput") or {})
        return cast(str, output.get("additionalContext") or "")

    def orphan_post(self, call: str) -> str:
        return self.hook(
            "PostToolUse",
            tool_name="Bash",
            tool_use_id=call,
            tool_input={"command": "npm run test-type"},
            tool_response=json.dumps({"chunk_id": "d74c6f", "exit_code": 2, "output": "TS2322"}),
        )

    def drain(self) -> None:
        class _Coordinator:
            async def ingest_request(
                self, request: ObservationIngestRequest
            ) -> ObservationIngestResult:
                return ObservationIngestResult(
                    ObservationIngestDisposition.ACCEPTED, None, request.envelope.cursor
                )

        sweeper = ObservationOutboxSweeper(self.store(), _Coordinator())
        try:
            asyncio.run(sweeper.sweep())
        finally:
            sweeper.close()

    def advisory_refs(self) -> tuple[str, ...] | None:
        store = self.store()
        status = store.status(ObservationStatusQuery(self.commitment))
        candidates = observation_advice_findings(
            ObservationAdviceContext(
                envelopes=store.list_envelopes(self.commitment),
                lifecycle=status.lifecycle,
                gaps=status.gaps,
            )
        )
        gap = [item for item in candidates if item.rule_code == "observation_gap_or_stale"]
        return None if not gap else gap[0].evidence_refs


def test_orphan_scope_stays_operator_visible_without_agent_advisory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex-home"))
    cell = _Cell(tmp_path)
    cell.hook("SessionStart", source="startup")

    first = cell.orphan_post("call_orphan_1")
    assert "Yoetz notice (no response needed)" not in first
    assert "Observation coverage is incomplete or stale" not in first
    # Repeated orphans in the same scope, and a restarted store, remain silent.
    assert "Yoetz notice (no response needed)" not in cell.orphan_post("call_orphan_2")
    assert "Yoetz notice (no response needed)" not in cell.orphan_post("call_orphan_3")

    cell.drain()
    store = cell.store()
    status = store.status(ObservationStatusQuery(cell.commitment))
    assert ObservationGapCode.UNPAIRED_EVENT.value in status.gaps
    # Drain is healthy: the standing record alone is not stale acquisition.
    assert status.lifecycle is ObservationLifecycle.ACTIVE
    assert cell.advisory_refs() is None
    # The bounded local notice remains available to operators, but is never consumed by a hook.
    assert store.peek_unpaired_notice(cell.commitment, cell.session) is not None

    # A real transient condition still advises, names its cause first...
    store.note_coverage_gap(cell.commitment, ObservationGapCode.SERVICE_UNAVAILABLE.value)
    refs = cell.advisory_refs()
    assert refs is not None
    assert refs[0] == "cause:service_unavailable"
    assert "cause:unpaired_event" not in refs
    assert (
        ObservationGapCode.SERVICE_UNAVAILABLE.value
        in store.status(ObservationStatusQuery(cell.commitment)).gaps
    )

    # ...and clears once a delivery proves the service is reachable again.
    hook_context = cell.hook(
        "PreToolUse",
        tool_name="Bash",
        tool_use_id="call_paired",
        tool_input={"command": "npm run test-type"},
    )
    assert "Yoetz notice (no response needed)" not in hook_context
    assert "refresh_observation" not in hook_context
    assert "Observation coverage is incomplete or stale" not in hook_context
    cell.drain()
    assert cell.advisory_refs() is None
    status = cell.store().status(ObservationStatusQuery(cell.commitment))
    assert ObservationGapCode.UNPAIRED_EVENT.value in status.gaps


def test_each_new_orphan_scope_gets_its_own_notice(tmp_path: Path) -> None:
    cell = _Cell(tmp_path)
    store = cell.store()

    def orphan(generation: int, identity: str) -> None:
        cell.store().note_unpaired_event(
            cell.commitment,
            source=ObservationSource.CODEX_HOOK,
            session_commitment=cell.session,
            source_generation=generation,
            source_identity=identity,
        )

    orphan(1, "hook:orphan-a")
    orphan(1, "hook:orphan-b")
    notice = store.peek_unpaired_notice(cell.commitment, cell.session)
    assert notice is not None and notice.source_generation == 1
    store.commit_unpaired_notice_delivery(cell.commitment, notice.lane)
    # Delivered stays delivered across a restart; a repeated commit is a no-op.
    cell.store().commit_unpaired_notice_delivery(cell.commitment, notice.lane)
    assert cell.store().peek_unpaired_notice(cell.commitment, cell.session) is None

    # A later scope (a new source generation) is a new, separate notice.
    orphan(2, "hook:orphan-c")
    later = cell.store().peek_unpaired_notice(cell.commitment, cell.session)
    assert later is not None
    assert later.source_generation == 2 and later.lane != notice.lane
    # Another session's notice is never delivered into this one.
    assert cell.store().peek_unpaired_notice(cell.commitment, "hmac-sha256:" + "0" * 64) is None
    # The aggregate gap stays on the durable record for every scope.
    status = cell.store().status(ObservationStatusQuery(cell.commitment))
    assert ObservationGapCode.UNPAIRED_EVENT.value in status.gaps
