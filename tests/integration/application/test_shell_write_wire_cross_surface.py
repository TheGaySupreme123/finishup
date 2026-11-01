"""A shell write the hook records reaches every surface through the control wire (#1039).

tb4n4 D: the hook classifies a shell command that writes a workspace file as ``write_scope:
workspace`` (ADR-045), but control-request 2.9.0 admitted only three scopes, so the client refused
the frame on every drain pass (439 ``control_frame_invalid`` rejections in 31 of 60 attempts) and
the edit that should make the final check stale never reached the ledger.

Each case starts at the real host hook (Codex, Claude Code, Cursor) recording a shell command in
its local outbox, sends every pending row the way the drain does (domain serializer, the client's
validating frame encoder, the service's frame parser), materializes the received envelope as the
coordinator does, and appends it after a check. Every surface that reads the check's applicability
then answers the same: a workspace write makes the check no longer current; a notes write or a
scratch write does not (the command still bounds the conclusion with the earlier-frontier note, as
any command FinishUP cannot classify does; ADR-040).
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, cast

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.domain.events import EventPayload
from finishup.domain.observation import (
    ObservationEnvelope,
    ObservationIngestRequest,
    observation_ingest_request_from_json,
    observation_ingest_request_to_json,
)
from finishup.domain.values import JsonObject
from finishup.ports.control import ControlCallRequest, ControlMethod
from finishup.protocol.coverage import LedgerFreshness
from finishup.service.control_protocol import (
    decode_control_frame,
    encode_control_frame,
    parse_control_request,
)
from integration.application import test_tb4n3_own_calls_cross_surface as surfaces_of
from integration.observation.test_failure_supersession_hosts import (
    _claude_bash,
    _codex_exec,
    _cursor_shell,
    _host,
)

pytestmark = pytest.mark.anyio

type _Host = Literal["codex", "claude", "cursor"]

_NOT_APPLICABLE = "check_not_applicable"
_HOST_TOOL = {"codex": "Bash", "claude": "Bash", "cursor": "Shell"}
# The command and the closed token the hook gives it: an edit of a workspace file, the agent's own
# notes, and a temporary file outside the workspace (scratch, which a shell write never names).
_WRITES: dict[str, tuple[str, str | None]] = {
    "workspace": ("printf 'print(1)\\n' > solve.py", "workspace"),
    "notes": ("printf 'tried x\\n' >> NOTES.md", "notes"),
    "scratch": ("printf 'x' > /tmp/yz-1039-scratch.txt", None),
}


def _record_shell_write(
    tmp_path: Path, host: _Host, command: str
) -> tuple[ObservationEnvelope, ...]:
    """Run one shell call through the real host hook; return its pending outbox rows' envelopes
    after each crossed the control wire exactly as the drain sends it."""

    emit, _ledger = _host(tmp_path, host)
    if host == "codex":
        _codex_exec(emit, "call-1039", command, exit_code=0)
    elif host == "claude":
        _claude_bash(emit, "toolu-1039", command, failed=False)
    else:
        _cursor_shell(emit, "cursor-1039", command, exit_code=0)
    store = LocalObservationStore(_state=tmp_path / "state")
    rows = store.list_pending_outbox_rows(store.workspace_commitment(str(tmp_path.resolve())))
    assert rows
    received: list[ObservationEnvelope] = []
    for row in rows:
        request = ObservationIngestRequest(
            codex_session_id=row.codex_session_id, envelope=row.envelope
        )
        frame = encode_control_frame(
            ControlCallRequest(
                kind="call",
                protocol_version="1.0",
                rpc_id="rpc_00000000-0000-4000-8000-000000001039",
                service_instance_id="svc_00000000-0000-4000-8000-000000001039",
                service_generation="1",
                method=ControlMethod.OBSERVATION_INGEST,
                body=observation_ingest_request_to_json(request),
            )
        )
        parsed = parse_control_request(decode_control_frame(frame))
        assert isinstance(parsed, ControlCallRequest)
        received.append(
            observation_ingest_request_from_json(cast(JsonObject, parsed.body)).envelope
        )
    return tuple(received)


async def _surfaces_after(
    tmp_path: Path, host: _Host, write: str, backend: Literal["memory", "sqlite"]
) -> tuple[dict[str, Any], Any]:
    command, scope = _WRITES[write]
    envelopes = _record_shell_write(tmp_path, host, command)
    post = envelopes[-1]
    assert post.structural_payload.get("write_scope") == scope

    app, runtime, _ = surfaces_of.h._build_app(seed_offset=70, ledger_backend=backend)
    started, checked = await surfaces_of._checked(app, runtime, backend)
    items: list[tuple[str, EventPayload]] = []
    for envelope in envelopes:
        batch = materialize_observation_envelope(envelope, task_id=started.task_id)
        for item in batch.drafts:
            if item.draft.schema.name in {"action_recorded", "result_recorded"}:
                assert item.draft.schema.version == "1.0.0"
                items.append((item.draft.schema.name, cast(EventPayload, item.draft.payload)))
    assert any(name == "action_recorded" for name, _ in items)
    appended = await surfaces_of._append_observed(
        app,
        runtime,
        started,
        tuple(items),
        seed=10_390,
        expected_frontier=checked.result_frontier.sequence,
    )
    return (
        await surfaces_of._surfaces(app, runtime, started, appended.result_frontier, 10_490),
        checked,
    )


@pytest.mark.parametrize("backend", ("memory", "sqlite"))
@pytest.mark.parametrize("host", ("codex", "claude", "cursor"))
async def test_a_workspace_shell_write_after_the_check_makes_it_no_longer_current(
    tmp_path: Path, host: _Host, backend: Literal["memory", "sqlite"]
) -> None:
    surfaces, checked = await _surfaces_after(tmp_path, host, "workspace", backend)

    assert _NOT_APPLICABLE in surfaces["capacity"]
    assert surfaces["compact"].freshness == LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE.value
    readiness = surfaces["status"].closure_readiness
    assert _NOT_APPLICABLE in readiness.agent_actionable
    cause = readiness.check_cause
    assert cause is not None
    assert (cause.effect, cause.material_class, cause.tool) == (
        "superseded",
        "edit_or_write",
        _HOST_TOOL[host],
    )
    assert cause.check_subject_frontier == str(checked.subject_frontier.sequence)
    cli, mcp = surfaces_of._readiness_text(surfaces["status"])
    assert f"Why {_NOT_APPLICABLE}" in cli
    assert mcp and mcp.strip() in cli
    for fmt, receipt in surfaces["receipts"].items():
        assert _NOT_APPLICABLE in receipt.coverage.known_gaps, fmt
        assert receipt.conclusion == "insufficient_coverage", fmt
        body = surfaces_of._limitations(receipt)
        assert "no longer covers frontier" in body, fmt
        assert f"ledger record {cause.ledger_sequence}, {cause.event_id}" in body, fmt


@pytest.mark.parametrize("write", ("notes", "scratch"))
@pytest.mark.parametrize("host", ("codex", "claude", "cursor"))
async def test_a_notes_or_scratch_shell_write_leaves_the_check_current(
    tmp_path: Path, host: _Host, write: str
) -> None:
    surfaces, _checked = await _surfaces_after(tmp_path, host, write, "memory")

    assert _NOT_APPLICABLE not in surfaces["capacity"]
    assert surfaces["compact"].freshness != LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE.value
    readiness = surfaces["status"].closure_readiness
    assert _NOT_APPLICABLE not in readiness.agent_actionable
    assert readiness.check_cause is None or readiness.check_cause.effect == "bounds_conclusion"
    for fmt, receipt in surfaces["receipts"].items():
        assert _NOT_APPLICABLE not in receipt.coverage.known_gaps, fmt
        assert "no longer covers frontier" not in surfaces_of._limitations(receipt), fmt
