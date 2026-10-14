"""Required startup is scope-bound and preserves native approval and recovery."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest

from finishup.adapters.integrations.startup_gate import GateScope, GateStore
from finishup.cli import startup_gate as startup_gate_module
from finishup.cli.startup_gate import bootstrap_tool, gate_output, handle_startup_gate
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id


class Host:
    def __init__(
        self,
        root: Path,
        host: Literal["claude", "cursor"],
        *,
        server: str = "finishup",
        plugin: bool = False,
    ):
        self.host: Literal["claude", "cursor"] = host
        # The server spelling the host names FinishUP's tools by: the current one, or the legacy
        # one a 0.1-0.2.5 registration still carries (ADR-048); standalone or plugin-bundled.
        self.tool_prefix = f"mcp__plugin_{server}_{server}__" if plugin else f"mcp__{server}__"
        self.server_key = f"plugin-{server}-{server}" if plugin else server
        self.root = root.resolve()
        self.workspace = self.root / "project"
        self.workspace.mkdir()
        self.state = self.root / "state"
        self.session = "native-session"
        self.store = GateStore(host, self.session, str(self.workspace), root=self.state)
        self.route = (new_id(IdKind.TASK), new_id(IdKind.SESSION), new_id(IdKind.WRITER))
        self.ready = True
        self.probes = 0
        self.boundary("start")

    def boundary(self, kind: str) -> None:
        event = (
            {"start": "SessionStart", "prompt": "UserPromptSubmit", "end": "SessionEnd"}
            if self.host == "claude"
            else {"start": "sessionStart", "prompt": "beforeSubmitPrompt", "end": "sessionEnd"}
        )[kind]
        self.call(event)

    def call(self, event: str, **values: JsonValue) -> dict[str, JsonValue]:
        payload: dict[str, JsonValue] = {
            "session_id": self.session,
            "conversation_id": self.session,
            "cwd": str(self.workspace),
            "workspace_roots": [str(self.workspace)],
            **values,
        }
        out = io.BytesIO()

        def probe(_scope: GateScope, _workspace: str) -> bool:
            self.probes += 1
            return self.ready

        assert (
            handle_startup_gate(
                host=self.host,
                event=event,
                stdin_bytes=json.dumps(payload).encode(),
                stdout=out,
                _state=self.state,
                probe=probe,
            )
            == 0
        )
        return json.loads(out.getvalue())

    def pre(self, tool: str, request: dict[str, JsonValue]) -> dict[str, JsonValue]:
        return self.call(
            "PreToolUse" if self.host == "claude" else "beforeMCPExecution",
            tool_name=f"{self.tool_prefix}{tool}" if self.host == "claude" else tool,
            mcp_server_name=self.server_key,
            tool_input=request,
        )

    def post(self, tool: str, request: dict[str, JsonValue], result: dict[str, JsonValue]) -> None:
        self.call(
            "PostToolUse" if self.host == "claude" else "afterMCPExecution",
            tool_name=f"{self.tool_prefix}{tool}" if self.host == "claude" else tool,
            mcp_server_name=self.server_key,
            tool_input=request,
            **(
                {"tool_response": {"structuredContent": result}}
                if self.host == "claude"
                else {"result_json": json.dumps({"structuredContent": result})}
            ),
        )

    def start(self) -> None:
        request: dict[str, JsonValue] = {"request_id": new_id(IdKind.REQUEST)}
        self.pre("start", request)
        self.post(
            "start",
            request,
            {
                "request_id": request["request_id"],
                "ok": True,
                "task_id": self.route[0],
                "session_id": self.route[1],
                "writer_id": self.route[2],
            },
        )

    def publication(
        self,
        *,
        plan: bool = True,
        obligation: str | None = None,
        refs: list[str] | None = None,
        version: int = 1,
    ) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
        obligation = new_id(IdKind.OBLIGATION) if obligation is None else obligation
        refs = [obligation] if refs is None else refs
        drafts: list[JsonValue] = []
        if plan:
            drafts.append(
                {
                    "event_id": new_id(IdKind.EVENT),
                    "schema": {"name": "plan_published"},
                    "payload": {"plan_version": version, "obligation_refs": list(refs)},
                }
            )
        drafts.append(
            {
                "event_id": new_id(IdKind.EVENT),
                "schema": {"name": "obligation_published"},
                "payload": {
                    "obligation_id": obligation,
                    "status": "open",
                    "description": "private prose never persisted",
                },
            }
        )
        request: dict[str, JsonValue] = {
            "request_id": new_id(IdKind.REQUEST),
            "session_id": self.route[1],
            "writer_id": self.route[2],
            "event_drafts": drafts,
        }
        accepted: list[JsonValue] = []
        for draft in drafts:
            assert isinstance(draft, dict)
            schema = draft["schema"]
            assert isinstance(schema, dict)
            accepted.append(
                {
                    "event_id": draft["event_id"],
                    "schema_name": schema["name"],
                    "accepted_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
                }
            )
        result: dict[str, JsonValue] = {
            "request_id": request["request_id"],
            "ok": True,
            "outcome": "accepted",
            "task_id": self.route[0],
            "session_id": self.route[1],
            "writer_id": self.route[2],
            "accepted_events": accepted,
        }
        return request, result

    def publish(self, **options: object) -> None:
        assert not options
        request, result = self.publication()
        self.pre("publish_work", request)
        self.post("publish_work", request, result)

    def denied(self, tool: str = "Read") -> bool:
        response = self.call(
            "PreToolUse" if self.host == "claude" else "preToolUse",
            tool_name=tool,
            tool_input={"file_path": "private-prose"},
        )
        if self.host == "cursor":
            return response.get("permission") == "deny"
        return "hookSpecificOutput" in response


@pytest.fixture(params=["claude", "cursor"])
def host(tmp_path: Path, request: pytest.FixtureRequest) -> Host:
    name = request.param
    assert name in {"claude", "cursor"}
    return Host(tmp_path, "claude" if name == "claude" else "cursor")


def test_probe_uses_an_isolated_child_import_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: dict[str, object] = {}

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls["command"] = command
        calls.update(kwargs)
        return subprocess.CompletedProcess(command, 0, b'{"ready": true}', b"")

    monkeypatch.setattr("finishup.cli.startup_gate.subprocess.run", run)
    assert startup_gate_module._probe(GateScope.fresh(), str(tmp_path))  # pyright: ignore[reportPrivateUsage]
    assert calls["command"] == [sys.executable, "-I", "-m", "finishup.cli.startup_gate_probe"]
    assert calls["cwd"] == os.path.sep
    environment = calls["env"]
    assert isinstance(environment, dict)
    assert "PYTHONPATH" not in environment
    assert "PYTHONSTARTUP" not in environment


def test_workflow_allowlist_tracks_the_canonical_registry() -> None:
    from finishup.ports.integrations import FINISHUP_WORKFLOW_TOOL_NAMES

    assert startup_gate_module._WORKFLOW == frozenset(  # pyright: ignore[reportPrivateUsage]
        FINISHUP_WORKFLOW_TOOL_NAMES
    )


def test_investigation_and_delegation_denied_until_accepted_current_plan(host: Host) -> None:
    assert host.denied("Read") and host.denied("Agent") and host.denied("Task")
    host.start()
    assert host.denied()
    host.publish()
    assert not host.denied()
    assert host.probes == 1
    assert "private prose" not in host.store.path.read_text()


def test_old_mapping_and_stored_ready_flag_do_not_open_gate(host: Host) -> None:
    host.store.path.write_text('{"ready":true}')
    assert host.denied()


def test_new_scope_requires_fresh_plan_and_keeps_route(host: Host) -> None:
    host.start()
    host.publish()
    host.boundary("prompt")
    scope = host.store.read()
    assert scope is not None and scope.route == host.route
    assert host.denied()
    req, res = host.publication(version=2, refs=scope.plan_refs, obligation=scope.plan_refs[0])
    host.pre("publish_work", req)
    host.post("publish_work", req, res)
    assert not host.denied()


def test_new_session_boundary_requires_start_and_can_bind_new_task(host: Host) -> None:
    host.start()
    host.publish()
    host.boundary("start")
    old = host.store.read()
    assert old is not None and old.needs_start
    req, res = host.publication(version=2, refs=old.plan_refs, obligation=old.plan_refs[0])
    host.pre("publish_work", req)
    host.post("publish_work", req, res)
    assert host.denied()
    host.route = (new_id(IdKind.TASK), new_id(IdKind.SESSION), new_id(IdKind.WRITER))
    host.start()
    host.publish()
    assert not host.denied()


def test_idempotent_old_plan_replay_cannot_renew_scope(host: Host) -> None:
    host.start()
    req, res = host.publication()
    host.pre("publish_work", req)
    host.post("publish_work", req, res)
    host.boundary("prompt")
    scope = host.store.read()
    assert scope is not None
    scope.began_at = "2000-01-01T00:00:00.000+00:00"  # Even a backward wall clock cannot renew it.
    with host.store.locked():
        host.store.write(scope)
    host.pre("publish_work", req)
    host.post("publish_work", req, res)
    assert host.denied()


@pytest.mark.parametrize("outcome", ["failure", "dry_run", "wrong_route", "stale"])
def test_unaccepted_or_stale_plan_cannot_open_gate(host: Host, outcome: str) -> None:
    host.start()
    req, res = host.publication()
    if outcome == "failure":
        res.update(ok=False, error={"code": "INVALID_REQUEST"})
    elif outcome == "dry_run":
        res["outcome"] = "dry_run"
    elif outcome == "wrong_route":
        res["session_id"] = new_id(IdKind.SESSION)
    else:
        rows = res["accepted_events"]
        assert isinstance(rows, list)
        for row in rows:
            assert isinstance(row, dict)
            row["accepted_at"] = "2020-01-01T00:00:00.000Z"
    host.pre("publish_work", req)
    host.post("publish_work", req, res)
    assert host.denied()


def test_new_obligation_outside_effective_plan_closes_gate(host: Host) -> None:
    host.start()
    host.publish()
    req, res = host.publication(plan=False)
    host.pre("publish_work", req)
    host.post("publish_work", req, res)
    assert host.denied()
    scope = host.store.read()
    assert scope is not None
    req, res = host.publication(
        version=2, refs=scope.required_refs, obligation=scope.required_refs[0]
    )
    host.pre("publish_work", req)
    host.post("publish_work", req, res)
    assert not host.denied()


def test_live_probe_failure_denies_but_bootstrap_remains_available(host: Host) -> None:
    host.start()
    host.publish()
    host.ready = False
    assert host.denied()
    for tool in ("read_guidance", "status", "check", "respond", "receipt"):
        response = host.pre(tool, {})
        assert response == ({} if host.host == "claude" else {"permission": "ask"})


def test_pending_start_ticket_capacity_does_not_brick_bootstrap(host: Host) -> None:
    request_ids: list[str] = []
    for _ in range(32):
        request_id = new_id(IdKind.REQUEST)
        request_ids.append(request_id)
        response = host.pre("start", {"request_id": request_id})
        assert response == ({} if host.host == "claude" else {"permission": "ask"})

    blocked_request = new_id(IdKind.REQUEST)
    blocked = host.pre("start", {"request_id": blocked_request})
    if host.host == "claude":
        details = blocked.get("hookSpecificOutput")
        assert isinstance(details, dict)
        assert details.get("permissionDecision") == "deny"
        reason = details.get("permissionDecisionReason")
        assert isinstance(reason, str) and "pending_operation_capacity" in reason
    else:
        assert blocked["permission"] == "deny"
        assert blocked["user_message"] == "FinishUP startup: pending_operation_capacity."

    # The exact request identity remains the supported recovery path at capacity.
    retry = host.pre("start", {"request_id": request_ids[0]})
    assert retry == ({} if host.host == "claude" else {"permission": "ask"})

    scope = host.store.read()
    assert scope is not None
    assert len(scope.pending) == 32
    assert set(request_ids) == set(scope.pending)
    assert blocked_request not in scope.pending
    assert host.denied()


def test_reset_persistence_failure_invalidates_the_previous_candidate(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    host.start()
    host.publish()
    scope = host.store.read()
    assert scope is not None and scope.candidate

    def fail_write(_store: GateStore, _scope: GateScope) -> None:
        raise OSError("simulated reset write failure")

    monkeypatch.setattr(GateStore, "write", fail_write)
    host.boundary("prompt")
    assert host.store.path.exists()
    assert host.store.read() is None
    assert host.store.invalidation_path.exists()
    monkeypatch.undo()
    host.store.write(GateScope.fresh(scope))
    assert host.store.read() is None
    host.boundary("prompt")
    assert not host.store.invalidation_path.exists()
    assert host.denied()


def test_successful_reset_after_failure_preserves_pending_request_identity(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    host.start()
    request: dict[str, JsonValue] = {"request_id": new_id(IdKind.REQUEST)}
    host.pre("start", request)
    before = host.store.read()
    assert before is not None and request["request_id"] in before.pending

    def fail_write(_store: GateStore, _scope: GateScope) -> None:
        raise OSError("simulated reset write failure")

    monkeypatch.setattr(GateStore, "write", fail_write)
    host.boundary("prompt")
    assert host.store.read() is None
    assert host.store.invalidation_path.exists()

    blocked_request: dict[str, JsonValue] = {"request_id": new_id(IdKind.REQUEST)}
    blocked = host.pre("start", blocked_request)
    if host.host == "claude":
        details = blocked.get("hookSpecificOutput")
        assert isinstance(details, dict)
        reason = details.get("permissionDecisionReason")
        assert isinstance(reason, str) and "scope_reset_required" in reason
    else:
        assert blocked["permission"] == "deny"
        assert blocked["user_message"] == "FinishUP startup: scope_reset_required."
    with host.store.locked():
        preserved = host.store.read_for_reset()
    assert preserved is not None and request["request_id"] in preserved.pending
    assert blocked_request["request_id"] not in preserved.pending

    monkeypatch.undo()
    host.boundary("prompt")
    after = host.store.read()
    assert after is not None
    assert after.route == before.route
    assert request["request_id"] in after.pending
    assert after.plan_generation is None
    assert not host.store.invalidation_path.exists()


def test_lock_contention_denies_tracked_bootstrap_writes_without_mutating_scope(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    host.start()
    host.publish()
    before = host.store.read()
    assert before is not None and before.candidate

    def busy_locked(_store: GateStore):
        raise BlockingIOError("simulated contention")

    monkeypatch.setattr(GateStore, "locked", busy_locked)
    start_request: dict[str, JsonValue] = {"request_id": new_id(IdKind.REQUEST)}
    publish_request, _result = host.publication()
    for tool, request in (("start", start_request), ("publish_work", publish_request)):
        response = host.pre(tool, request)
        if host.host == "claude":
            details = response.get("hookSpecificOutput")
            assert isinstance(details, dict)
            assert details.get("permissionDecision") == "deny"
        else:
            assert response["permission"] == "deny"

    after = host.store.read()
    assert after is not None and after == before
    assert start_request["request_id"] not in after.pending
    assert publish_request["request_id"] not in after.pending


def test_unknown_error_code_keeps_pending_ticket_and_closes_gate(host: Host) -> None:
    host.start()
    request, result = host.publication()
    host.pre("publish_work", request)
    result.update(ok=False, error={"code": "UNKNOWN_ERROR"})
    host.post("publish_work", request, result)
    scope = host.store.read()
    assert scope is not None and request["request_id"] in scope.pending
    assert host.denied()


@pytest.mark.parametrize(
    "error_code",
    [
        "IDEMPOTENCY_CONFLICT",
        "REQUEST_IDENTITY_CONFLICT",
    ],
)
def test_identity_conflict_keeps_original_pending_ticket(host: Host, error_code: str) -> None:
    host.start()
    host.publish()
    request, result = host.publication(version=2)
    host.pre("publish_work", request)
    before = host.store.read()
    assert before is not None

    result.update(ok=False, error={"code": error_code})
    host.post("publish_work", request, result)

    after = host.store.read()
    assert after is not None
    rid = request["request_id"]
    assert isinstance(rid, str)
    assert after.pending.get(rid) == "publish_work"
    assert after.pending_refs.get(rid) == before.pending_refs.get(rid)
    assert host.denied()


def test_mismatched_same_request_retry_preserves_original_ticket(host: Host) -> None:
    host.start()
    host.publish()
    request, result = host.publication(version=2)
    host.pre("publish_work", request)
    before = host.store.read()
    assert before is not None
    rid = request["request_id"]
    assert isinstance(rid, str)

    blocked = host.pre("start", {"request_id": rid})
    if host.host == "claude":
        details = blocked.get("hookSpecificOutput")
        assert isinstance(details, dict)
        assert details.get("permissionDecision") == "deny"
        reason = details.get("permissionDecisionReason")
        assert isinstance(reason, str) and "request_identity_conflict" in reason
    else:
        assert blocked["permission"] == "deny"
        assert blocked["user_message"] == "FinishUP startup: request_identity_conflict."

    after_retry = host.store.read()
    assert after_retry is not None
    assert after_retry.pending.get(rid) == "publish_work"
    assert after_retry.pending_refs.get(rid) == before.pending_refs.get(rid)

    result.update(ok=False, error={"code": "REQUEST_IDENTITY_CONFLICT"})
    host.post("publish_work", request, result)
    after_conflict = host.store.read()
    assert after_conflict is not None
    assert after_conflict.pending.get(rid) == "publish_work"
    assert after_conflict.pending_refs.get(rid) == before.pending_refs.get(rid)
    assert host.denied()


@pytest.mark.parametrize(
    "invalid_context",
    [
        {"session_id": "", "conversation_id": ""},
        {"cwd": None, "workspace_roots": []},
    ],
)
def test_tracked_bootstrap_fails_closed_on_missing_identity_or_workspace(
    host: Host, invalid_context: dict[str, JsonValue]
) -> None:
    start_response = host.call(
        "PreToolUse" if host.host == "claude" else "beforeMCPExecution",
        tool_name="mcp__finishup__start" if host.host == "claude" else "start",
        mcp_server_name="finishup",
        tool_input={"request_id": new_id(IdKind.REQUEST)},
        **invalid_context,
    )
    if host.host == "claude":
        details = start_response.get("hookSpecificOutput")
        assert isinstance(details, dict)
        assert details.get("permissionDecision") == "deny"
    else:
        assert start_response["permission"] == "deny"

    guidance_response = host.call(
        "PreToolUse" if host.host == "claude" else "beforeMCPExecution",
        tool_name="ReadMcpResource",
        mcp_server_name="finishup",
        tool_input={"uri": "finishup://guidance/workflow.md"},
        **invalid_context,
    )
    assert guidance_response == ({} if host.host == "claude" else {"permission": "ask"})


def test_reset_marker_failure_uses_prompt_boundary_block(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    host.start()
    host.publish()

    def fail_write(_store: GateStore, _scope: GateScope) -> None:
        raise OSError("simulated reset write failure")

    def fail_invalidate(_store: GateStore) -> bool:
        return False

    monkeypatch.setattr(GateStore, "write", fail_write)
    monkeypatch.setattr(GateStore, "invalidate", fail_invalidate)
    response = host.call("UserPromptSubmit" if host.host == "claude" else "beforeSubmitPrompt")
    if host.host == "claude":
        assert response["decision"] == "block"
        reason = response.get("reason")
        assert isinstance(reason, str) and "could not safely advance" in reason
    else:
        assert response["continue"] is False
        message = response.get("user_message")
        assert isinstance(message, str) and "could not safely advance" in message

    session_response = host.call("SessionStart" if host.host == "claude" else "sessionStart")
    if host.host == "claude":
        assert "decision" not in session_response
        details = session_response.get("hookSpecificOutput")
        assert isinstance(details, dict)
        context = details.get("additionalContext")
    else:
        assert "continue" not in session_response
        context = session_response.get("additional_context")
    assert isinstance(context, str) and "cannot block the first prompt" in context


def test_corrupt_gate_state_does_not_deadlock_bootstrap(host: Host) -> None:
    host.store.path.write_bytes(b"broken")
    assert host.denied()
    assert host.pre("read_guidance", {}) == ({} if host.host == "claude" else {"permission": "ask"})


def test_lost_publication_recovers_without_replaying_complete_write(host: Host) -> None:
    host.start()
    req, _res = host.publication()
    host.pre("publish_work", req)
    host.boundary("prompt")
    assert host.denied()
    host.post(
        "status",
        {},
        {
            "ok": True,
            "view": "operation",
            "task_id": host.route[0],
            "session_id": host.route[1],
            "writer_id": host.route[2],
            "page": {"operation_request_id": req["request_id"], "state": "complete"},
        },
    )
    scope = host.store.read()
    assert scope is not None and not scope.pending and scope.required_refs
    assert host.denied()
    new_req, result = host.publication(
        version=2, refs=scope.required_refs, obligation=scope.required_refs[0]
    )
    host.pre("publish_work", new_req)
    host.post("publish_work", new_req, result)
    assert not host.denied()


def test_concurrent_scope_change_during_probe_denies(host: Host) -> None:
    host.start()
    host.publish()

    def change_scope(scope: GateScope, _workspace: str) -> bool:
        with host.store.locked():
            host.store.write(GateScope.fresh(scope))
        return True

    out = io.BytesIO()
    handle_startup_gate(
        host=host.host,
        event="PreToolUse" if host.host == "claude" else "preToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": host.session,
                "conversation_id": host.session,
                "cwd": str(host.workspace),
                "workspace_roots": [str(host.workspace)],
                "tool_name": "Read",
            }
        ).encode(),
        stdout=out,
        _state=host.state,
        probe=change_scope,
    )
    assert "deny" in out.getvalue().decode()


def test_native_permission_boundaries() -> None:
    assert gate_output("claude", "PreToolUse", True, "ready") == {}
    assert gate_output("cursor", "beforeMCPExecution", True, "ready") == {"permission": "ask"}
    assert gate_output("cursor", "preToolUse", False, "missing")["permission"] == "deny"


def test_recovery_is_exact_launcher_and_never_a_compound_shell_command() -> None:
    command = f"{sys.prefix}/bin/finishup service restart"
    for suffix, allowed in (
        ("", True),
        ("; touch x", False),
        (" | cat", False),
        (" $(touch x)", False),
    ):
        assert (
            bootstrap_tool(
                {"tool_name": "Bash", "tool_input": {"command": command + suffix}},
                "claude",
                "PreToolUse",
            )
            is allowed
        )
    assert not bootstrap_tool(
        {"tool_name": "Bash", "tool_input": {"command": "/foreign/finishup service restart"}},
        "claude",
        "PreToolUse",
    )


def test_foreign_cursor_workflow_name_cannot_bypass_gate(tmp_path: Path) -> None:
    host = Host(tmp_path, "cursor")
    result = host.call(
        "beforeMCPExecution", tool_name="start", mcp_server_name="foreign", tool_input={}
    )
    assert result["permission"] == "deny"


def test_session_end_preserves_unknown_request(host: Host) -> None:
    request: dict[str, JsonValue] = {"request_id": new_id(IdKind.REQUEST)}
    host.pre("start", request)
    host.boundary("end")
    scope = host.store.read()
    assert scope is not None and request["request_id"] in scope.pending
    assert host.denied()


# A host registered by 0.1-0.2.5 names the server ``yoetz`` (ADR-048); the gate reads those
# spellings exactly as the current ones, standalone and plugin-bundled.
@pytest.mark.parametrize("host_name", ["claude", "cursor"])
@pytest.mark.parametrize(
    ("server", "plugin"),
    [("finishup", False), ("finishup", True), ("yoetz", False), ("yoetz", True)],
    ids=["current", "current-plugin", "legacy", "legacy-plugin"],
)
def test_either_server_spelling_starts_and_opens_the_gate(
    tmp_path: Path, host_name: Literal["claude", "cursor"], server: str, plugin: bool
) -> None:
    host = Host(tmp_path, host_name, server=server, plugin=plugin)
    assert host.denied()
    host.start()
    assert host.denied()
    host.publish()
    assert not host.denied()


@pytest.mark.parametrize("host_name", ["claude", "cursor"])
def test_start_and_publication_under_different_server_spellings_share_one_scope(
    tmp_path: Path, host_name: Literal["claude", "cursor"]
) -> None:
    """During an upgrade both registrations can be present: one scope tracks both spellings."""

    host = Host(tmp_path, host_name, server="yoetz")
    host.start()
    host.tool_prefix, host.server_key = "mcp__finishup__", "finishup"
    host.publish()
    assert not host.denied()


@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        ("mcp__finishup__start", "start"),
        ("mcp__yoetz__start", "start"),
        ("mcp__plugin_yoetz_yoetz__publish_work", "publish_work"),
        ("mcp__plugin_finishup_finishup__check", "check"),
        ("mcp__yoetz__closure_prepare", None),
        ("mcp__yoetzx__start", None),
        ("mcp__plugin_yoetz_finishup__start", None),
    ],
)
def test_workflow_tool_reads_both_scoped_server_spellings(tool: str, expected: str | None) -> None:
    payload: dict[str, JsonValue] = {"tool_name": tool}
    assert startup_gate_module.workflow_tool(payload, "claude", "PreToolUse") == expected


@pytest.mark.parametrize(
    ("server", "expected"),
    [
        ("finishup", "start"),
        ("plugin-finishup-finishup", "start"),
        ("yoetz", "start"),
        ("plugin-yoetz-yoetz", "start"),
        ("plugin-yoetz-finishup", None),
        ("yoetzx", None),
    ],
)
def test_cursor_workflow_tool_reads_both_server_keys(server: str, expected: str | None) -> None:
    payload: dict[str, JsonValue] = {"tool_name": "start", "mcp_server_name": server}
    assert startup_gate_module.workflow_tool(payload, "cursor", "beforeMCPExecution") == expected


@pytest.mark.parametrize("scheme", ["finishup", "yoetz"])
@pytest.mark.parametrize("name", ["agent-instructions", "workflow", "request-templates"])
def test_bootstrap_guidance_reads_are_admitted_under_either_scheme(scheme: str, name: str) -> None:
    """Installed 0.1-0.2.5 guidance and skills still name ``yoetz://`` (ADR-048)."""

    payload: dict[str, JsonValue] = {
        "tool_name": "ReadMcpResource",
        "tool_input": {"uri": f"{scheme}://guidance/{name}.md"},
    }
    assert bootstrap_tool(payload, "claude", "PreToolUse")


@pytest.mark.parametrize(
    "uri",
    [
        "yoetz://guidance/unknown.md",
        "yoetzx://guidance/workflow.md",
        "yoetz://guidance/workflow.md#when-to-use-yoetz",
        "finishup://guidance/workflow.md#anchor",
    ],
)
def test_bootstrap_guidance_admission_stays_a_closed_set(uri: str) -> None:
    payload: dict[str, JsonValue] = {"tool_name": "ReadMcpResource", "tool_input": {"uri": uri}}
    assert not bootstrap_tool(payload, "claude", "PreToolUse")


@pytest.mark.parametrize(
    ("skill", "allowed"),
    [
        ("finishup", True),
        ("finishup:finishup", True),
        ("yoetz", True),
        ("yoetz:yoetz", True),
        ("yoetz:finishup", False),
        ("other", False),
    ],
)
def test_bootstrap_skill_reads_both_skill_ids(skill: str, allowed: bool) -> None:
    payload: dict[str, JsonValue] = {"tool_name": "Skill", "tool_input": {"skill": skill}}
    assert bootstrap_tool(payload, "claude", "PreToolUse") is allowed


@pytest.mark.parametrize("launcher", ["finishup", "yoetz"])
def test_recovery_admits_this_runtimes_launcher_or_its_legacy_alias(launcher: str) -> None:
    """The deprecated ``yoetz`` alias ships beside ``finishup`` for one release (ADR-048)."""

    command = f"{sys.prefix}/bin/{launcher} service restart"
    payload: dict[str, JsonValue] = {"tool_name": "Bash", "tool_input": {"command": command}}
    assert bootstrap_tool(payload, "claude", "PreToolUse")
    for foreign in (f"/foreign/{launcher}", f"{sys.prefix}/bin/{launcher}x"):
        payload = {"tool_name": "Bash", "tool_input": {"command": f"{foreign} service restart"}}
        assert not bootstrap_tool(payload, "claude", "PreToolUse")


def test_bare_legacy_launcher_resolves_through_path_to_this_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved: list[str] = []

    def which(name: str) -> str | None:
        resolved.append(name)
        return f"{sys.prefix}/bin/{name}" if name == "yoetz" else None

    monkeypatch.setattr("finishup.cli.startup_gate.shutil.which", which)
    payload: dict[str, JsonValue] = {
        "tool_name": "Bash",
        "tool_input": {"command": "yoetz service status"},
    }
    assert bootstrap_tool(payload, "claude", "PreToolUse")
    assert resolved == ["yoetz"]
    payload = {"tool_name": "Bash", "tool_input": {"command": "yoetzx service status"}}
    assert not bootstrap_tool(payload, "claude", "PreToolUse")
